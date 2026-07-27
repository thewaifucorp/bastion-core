//! Subscription credential lifecycle — the state machine around
//! [`bastion_types::provider_auth`]'s contracts (BPLIFE-01..05).
//!
//! An API key does not have a lifecycle: it works until the operator removes
//! it. A subscription does — it expires, refreshes, gets revoked upstream,
//! hits a rate limit, and can be refreshed concurrently by two callers at
//! once. That mechanism is identical for every connector, so it lives here
//! once, deterministic and testable, instead of being re-invented (differently
//! each time) inside each one.
//!
//! ## Division of labor
//!
//! - **This module** coordinates: it decides whether a call may proceed, who
//!   performs a refresh when several callers want one, which state a failure
//!   maps to, and how long a cooldown lasts.
//! - **The host** persists: [`CredentialStateStore`] is a port, and its
//!   `compare_and_swap` is what makes an interrupted update safe. Nothing here
//!   writes a file, opens a database, or touches a secret store.
//! - **The connector** talks to the vendor: [`ProviderCredentialRefresher`] is
//!   the other port — one method to exchange a refresh token, one to revoke.
//!   It never sees the state machine.
//!
//! [`Clock`] and [`BackoffPolicy`] are injected for the same reason: every
//! timing rule in here has to be assertable without sleeping in a test.
//!
//! ## Single-flight (BPLIFE-01)
//!
//! N concurrent refreshes of the SAME [`ProviderAuthRef`] produce exactly one
//! upstream call, and every caller receives that one result. This is not an
//! optimization: OAuth refresh tokens are commonly single-use, so a second
//! concurrent exchange does not merely waste quota — it invalidates the token
//! the first exchange just rotated, and the credential ends up unusable
//! through no fault of the user. Different refs never block each other.
//!
//! ## What deliberately never happens here
//!
//! - **No fallback.** A failure for one reference never causes an attempt with
//!   another reference, another profile, or another provider (BPLIFE-04). This
//!   module has no way to enumerate other credentials.
//! - **No unbounded retry.** A permanent failure lands in
//!   [`ProviderAuthState::ReauthRequired`] or `Revoked`, which no amount of
//!   waiting clears.
//! - **No secret in observability.** Every log line here carries the opaque
//!   reference, the transition, the instant and a
//!   [`ProviderAuthError`] — never material, never a length, never an upstream
//!   body (BPLIFE-05).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bastion_types::provider_auth::{
    ProviderAuthError, ProviderAuthRef, ProviderAuthState, ResolvedProviderCredential,
};
use tokio::sync::{broadcast, Mutex};

/// Injected time source. Every deadline in this module is computed from it, so
/// a test can prove a cooldown's exact expiry without sleeping.
pub trait Clock: Send + Sync {
    /// Nanoseconds since the Unix epoch — the same convention the rest of the
    /// kernel's timestamps use.
    fn now_nanos(&self) -> i64;
}

/// Wall-clock implementation for production.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_nanos(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64
    }
}

/// How long to wait after a transient failure, given how many consecutive
/// transient failures this credential has already had.
///
/// `attempt` starts at 1 for the first failure. An implementation must be
/// pure: the same `attempt` always yields the same duration, so a cooldown
/// deadline is reproducible from persisted state alone.
pub trait BackoffPolicy: Send + Sync {
    fn cooldown_nanos(&self, attempt: u32) -> i64;
}

/// Doubling backoff, capped. `base * 2^(attempt-1)`, never above `max`.
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    pub base_nanos: i64,
    pub max_nanos: i64,
}

impl ExponentialBackoff {
    /// 1s base, 5min cap — sane for a token endpoint, and the shape a
    /// deployment overrides rather than patches.
    pub fn new_default() -> Self {
        Self {
            base_nanos: 1_000_000_000,
            max_nanos: 300_000_000_000,
        }
    }
}

impl BackoffPolicy for ExponentialBackoff {
    fn cooldown_nanos(&self, attempt: u32) -> i64 {
        let shift = attempt.saturating_sub(1).min(32);
        let multiplier = 1_i64 << shift.min(62);
        self.base_nanos
            .saturating_mul(multiplier)
            .min(self.max_nanos)
            .max(0)
    }
}

/// What the host persists for one credential: the state plus the two fields
/// the state machine needs to be reconstructible after a restart.
///
/// `attempt` is the count of CONSECUTIVE transient failures, reset by any
/// success. It lives here rather than in memory so a daemon restart does not
/// hand a flapping credential a fresh 1-second backoff forever.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialLifecycleRecord {
    pub state: ProviderAuthState,
    pub attempt: u32,
    /// When this record was written, per the injected [`Clock`].
    pub observed_at: i64,
}

impl CredentialLifecycleRecord {
    pub fn ready(observed_at: i64) -> Self {
        Self {
            state: ProviderAuthState::Ready,
            attempt: 0,
            observed_at,
        }
    }
}

/// Host-owned persistence for [`CredentialLifecycleRecord`] (BPLIFE-03).
///
/// `compare_and_swap` is the whole point of the port: it must be atomic, and
/// it must reject the write when the stored record is not `expected`. That is
/// what makes a process crashing mid-transition safe — the next process reads
/// either the old record or the new one, never a torn one, and a transition
/// computed from stale state is refused rather than applied.
///
/// Implementations carry no secret material: the credential itself lives
/// wherever the host's secret backend puts it, reachable through
/// [`ProviderCredentialRefresher`], never through this trait.
#[async_trait]
pub trait CredentialStateStore: Send + Sync {
    /// Current record, or `None` when this reference has never been written.
    async fn load(
        &self,
        reference: &ProviderAuthRef,
    ) -> anyhow::Result<Option<CredentialLifecycleRecord>>;

    /// Atomically replace `expected` with `next`. Returns `false` — NOT an
    /// error — when the stored value is not `expected`; a losing racer is a
    /// normal outcome, not a failure.
    async fn compare_and_swap(
        &self,
        reference: &ProviderAuthRef,
        expected: Option<&CredentialLifecycleRecord>,
        next: &CredentialLifecycleRecord,
    ) -> anyhow::Result<bool>;

    /// Forget this reference entirely. Only ever called for the reference
    /// asked about (BPLIFE-04).
    async fn delete(&self, reference: &ProviderAuthRef) -> anyhow::Result<()>;
}

/// The connector half: whatever actually speaks to the vendor.
///
/// Split from the state machine so a connector implements two straight-line
/// HTTP calls and inherits single-flight, backoff, state transitions and
/// persistence for free — and so those behaviors are tested once, here,
/// against a fake instead of once per vendor against a live account.
#[async_trait]
pub trait ProviderCredentialRefresher: Send + Sync {
    /// Exchange whatever durable material this reference has for usable
    /// credentials. Errors must be mapped onto [`ProviderAuthError`]; a
    /// connector never invents an error string (BPAUTH-05).
    async fn refresh(
        &self,
        reference: &ProviderAuthRef,
    ) -> Result<ResolvedProviderCredential, ProviderAuthError>;

    /// Tell the vendor this credential is withdrawn, where the vendor supports
    /// it. Returning `Ok(())` when the vendor offers no revocation endpoint is
    /// correct: local state still becomes `Revoked`.
    async fn revoke(&self, reference: &ProviderAuthRef) -> Result<(), ProviderAuthError>;
}

/// Result of a refresh attempt, shared with every caller that joined it.
type RefreshOutcome = Result<ResolvedProviderCredential, ProviderAuthError>;

/// Coordinates refresh/revoke for every provider credential in the process.
///
/// One instance per host. Cloneable handles are not needed: wrap it in an
/// `Arc` and share that, so the in-flight map is genuinely shared (two
/// instances would each run their own refresh and defeat BPLIFE-01).
pub struct ProviderCredentialLifecycle {
    store: Arc<dyn CredentialStateStore>,
    refresher: Arc<dyn ProviderCredentialRefresher>,
    clock: Arc<dyn Clock>,
    backoff: Arc<dyn BackoffPolicy>,
    /// Refreshes currently in flight, keyed by reference. The channel carries
    /// the leader's outcome to every follower.
    inflight: Mutex<HashMap<ProviderAuthRef, broadcast::Sender<RefreshOutcome>>>,
}

impl ProviderCredentialLifecycle {
    pub fn new(
        store: Arc<dyn CredentialStateStore>,
        refresher: Arc<dyn ProviderCredentialRefresher>,
        clock: Arc<dyn Clock>,
        backoff: Arc<dyn BackoffPolicy>,
    ) -> Self {
        Self {
            store,
            refresher,
            clock,
            backoff,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Refresh `reference`, joining an in-flight refresh for the same
    /// reference instead of starting a second one (BPLIFE-01).
    ///
    /// Refuses before touching the network when the persisted state says so:
    /// `Revoked` and `ReauthRequired` are terminal, and a live `Cooldown`
    /// answers with the reason that caused it rather than spending another
    /// upstream call.
    pub async fn refresh(&self, reference: &ProviderAuthRef) -> RefreshOutcome {
        // Join or lead, decided while holding the map lock so two callers can
        // never both become leader.
        let mut receiver = {
            let mut inflight = self.inflight.lock().await;
            match inflight.get(reference) {
                Some(sender) => Some(sender.subscribe()),
                None => {
                    // Capacity 1 is enough: the value is sent exactly once and
                    // every subscriber that exists by then receives it.
                    let (sender, _) = broadcast::channel(1);
                    inflight.insert(reference.clone(), sender);
                    None
                }
            }
        };

        if let Some(receiver) = receiver.as_mut() {
            return match receiver.recv().await {
                Ok(outcome) => outcome,
                // The leader was dropped before publishing (task cancelled,
                // panicked). Reported as throttled — transient — so the caller
                // may try again rather than treating a lost race as a
                // credential problem.
                Err(_) => Err(ProviderAuthError::Throttled),
            };
        }

        let outcome = self.lead_refresh(reference).await;

        // Publish and clear, in that order, so a caller arriving between the
        // two joins the NEXT refresh instead of waiting on a closed channel.
        let mut inflight = self.inflight.lock().await;
        if let Some(sender) = inflight.remove(reference) {
            // A send with no subscribers is not an error here: the leader may
            // simply be alone.
            let _ = sender.send(outcome.clone());
        }
        outcome
    }

    /// The refresh the leader actually performs.
    async fn lead_refresh(&self, reference: &ProviderAuthRef) -> RefreshOutcome {
        let current = match self.store.load(reference).await {
            Ok(current) => current,
            Err(e) => {
                // Storage failures are the host's problem, never a statement
                // about the credential: do not persist a state derived from a
                // read that did not happen.
                tracing::error!(
                    event = "provider_credential_state_load_failed",
                    owner = %reference.owner_id,
                    provider = %reference.provider_id,
                    profile = %reference.profile_id,
                    error = %e,
                );
                return Err(ProviderAuthError::Throttled);
            }
        };

        if let Some(record) = &current {
            match &record.state {
                ProviderAuthState::Revoked => return Err(ProviderAuthError::Revoked),
                ProviderAuthState::ReauthRequired { reason } => return Err(*reason),
                ProviderAuthState::Cooldown { until, reason } => {
                    if self.clock.now_nanos() < *until {
                        return Err(*reason);
                    }
                }
                ProviderAuthState::Ready | ProviderAuthState::Refreshing => {}
            }
        }

        let attempt_before = current.as_ref().map(|r| r.attempt).unwrap_or(0);

        // Mark in-flight. A lost CAS means another process moved this
        // credential while we were deciding; re-read and answer from the state
        // it left rather than overwriting it.
        let refreshing = CredentialLifecycleRecord {
            state: ProviderAuthState::Refreshing,
            attempt: attempt_before,
            observed_at: self.clock.now_nanos(),
        };
        match self
            .store
            .compare_and_swap(reference, current.as_ref(), &refreshing)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    event = "provider_credential_transition_lost_race",
                    owner = %reference.owner_id,
                    provider = %reference.provider_id,
                    profile = %reference.profile_id,
                );
                return Err(self.reason_from_current_state(reference).await);
            }
            Err(e) => {
                tracing::error!(
                    event = "provider_credential_state_write_failed",
                    owner = %reference.owner_id,
                    provider = %reference.provider_id,
                    profile = %reference.profile_id,
                    error = %e,
                );
                return Err(ProviderAuthError::Throttled);
            }
        }

        match self.refresher.refresh(reference).await {
            Ok(credential) => {
                self.persist(
                    reference,
                    Some(&refreshing),
                    CredentialLifecycleRecord::ready(self.clock.now_nanos()),
                )
                .await;
                Ok(credential)
            }
            Err(err) => {
                let next = self.state_for_failure(err, attempt_before);
                self.persist(reference, Some(&refreshing), next).await;
                Err(err)
            }
        }
    }

    /// Which state a failed refresh leaves behind (BPLIFE-02).
    ///
    /// Transient failures enter `Cooldown` with a deadline from the injected
    /// [`BackoffPolicy`] and a bumped attempt counter; everything else is
    /// terminal until a human acts. `Revoked` is its own state rather than
    /// `ReauthRequired` because re-authenticating the same reference is not
    /// the remedy — a revoked credential is gone.
    fn state_for_failure(
        &self,
        err: ProviderAuthError,
        attempt_before: u32,
    ) -> CredentialLifecycleRecord {
        let now = self.clock.now_nanos();
        if err == ProviderAuthError::Revoked {
            return CredentialLifecycleRecord {
                state: ProviderAuthState::Revoked,
                attempt: attempt_before,
                observed_at: now,
            };
        }
        if err.is_transient() {
            let attempt = attempt_before.saturating_add(1);
            return CredentialLifecycleRecord {
                state: ProviderAuthState::Cooldown {
                    until: now.saturating_add(self.backoff.cooldown_nanos(attempt)),
                    reason: err,
                },
                attempt,
                observed_at: now,
            };
        }
        CredentialLifecycleRecord {
            state: ProviderAuthState::ReauthRequired { reason: err },
            attempt: attempt_before,
            observed_at: now,
        }
    }

    /// Best-effort persist of a computed transition, logging what it was.
    ///
    /// A lost CAS here is deliberately not retried: something else already
    /// moved this credential, and re-applying our older conclusion on top of
    /// its newer one is how a `Revoked` credential silently becomes `Ready`
    /// again.
    async fn persist(
        &self,
        reference: &ProviderAuthRef,
        expected: Option<&CredentialLifecycleRecord>,
        next: CredentialLifecycleRecord,
    ) {
        match self
            .store
            .compare_and_swap(reference, expected, &next)
            .await
        {
            Ok(true) => tracing::info!(
                event = "provider_credential_transition",
                owner = %reference.owner_id,
                provider = %reference.provider_id,
                profile = %reference.profile_id,
                // Serialized state, which carries only its tag, deadline and a
                // typed reason — no material, by construction.
                state = ?next.state,
                attempt = next.attempt,
                observed_at = next.observed_at,
            ),
            Ok(false) => tracing::warn!(
                event = "provider_credential_transition_not_applied",
                owner = %reference.owner_id,
                provider = %reference.provider_id,
                profile = %reference.profile_id,
            ),
            Err(e) => tracing::error!(
                event = "provider_credential_state_write_failed",
                owner = %reference.owner_id,
                provider = %reference.provider_id,
                profile = %reference.profile_id,
                error = %e,
            ),
        }
    }

    /// Re-read after losing a race and translate the winner's state into the
    /// error this caller should see.
    async fn reason_from_current_state(&self, reference: &ProviderAuthRef) -> ProviderAuthError {
        match self.store.load(reference).await {
            Ok(Some(record)) => match record.state {
                ProviderAuthState::Revoked => ProviderAuthError::Revoked,
                ProviderAuthState::ReauthRequired { reason } => reason,
                ProviderAuthState::Cooldown { reason, .. } => reason,
                // Someone else is refreshing, or already did: transient from
                // this caller's point of view.
                ProviderAuthState::Ready | ProviderAuthState::Refreshing => {
                    ProviderAuthError::Throttled
                }
            },
            Ok(None) | Err(_) => ProviderAuthError::Throttled,
        }
    }

    /// Revoke `reference`, and only `reference` (BPLIFE-04).
    ///
    /// Local state becomes `Revoked` even when the vendor offers no revocation
    /// endpoint, because the operator's intent is not conditional on vendor
    /// support. An upstream failure is reported, but the local record still
    /// moves: leaving a credential the operator revoked in a usable state
    /// would be the worse failure.
    pub async fn revoke(&self, reference: &ProviderAuthRef) -> Result<(), ProviderAuthError> {
        let upstream = self.refresher.revoke(reference).await;

        let current = self.store.load(reference).await.ok().flatten();
        let now = self.clock.now_nanos();
        let revoked = CredentialLifecycleRecord {
            state: ProviderAuthState::Revoked,
            attempt: current.as_ref().map(|r| r.attempt).unwrap_or(0),
            observed_at: now,
        };
        self.persist(reference, current.as_ref(), revoked).await;

        upstream
    }

    /// Drop every trace of `reference` from the host's store.
    ///
    /// Separate from [`Self::revoke`] because they answer different questions:
    /// revoke says "this must stop working", forget says "stop remembering it
    /// at all". Forgetting without revoking would leave a credential the
    /// vendor still honors.
    pub async fn forget(&self, reference: &ProviderAuthRef) -> anyhow::Result<()> {
        self.store.delete(reference).await
    }

    /// The current state, for a status surface. `None` means this reference
    /// has no record — never "ready".
    pub async fn state(
        &self,
        reference: &ProviderAuthRef,
    ) -> anyhow::Result<Option<CredentialLifecycleRecord>> {
        self.store.load(reference).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_types::provider_auth::CredentialKind;
    use bastion_types::SecretValue;
    use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

    /// In-memory store with a real compare-and-swap, plus a switch to make a
    /// write fail so the crash path is assertable.
    #[derive(Default)]
    struct MemStore {
        records: Mutex<HashMap<ProviderAuthRef, CredentialLifecycleRecord>>,
        fail_writes: std::sync::atomic::AtomicBool,
        write_calls: AtomicU32,
    }

    #[async_trait]
    impl CredentialStateStore for MemStore {
        async fn load(
            &self,
            reference: &ProviderAuthRef,
        ) -> anyhow::Result<Option<CredentialLifecycleRecord>> {
            Ok(self.records.lock().await.get(reference).cloned())
        }

        async fn compare_and_swap(
            &self,
            reference: &ProviderAuthRef,
            expected: Option<&CredentialLifecycleRecord>,
            next: &CredentialLifecycleRecord,
        ) -> anyhow::Result<bool> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_writes.load(Ordering::SeqCst) {
                anyhow::bail!("storage unavailable");
            }
            let mut records = self.records.lock().await;
            let current = records.get(reference);
            if current != expected {
                return Ok(false);
            }
            records.insert(reference.clone(), next.clone());
            Ok(true)
        }

        async fn delete(&self, reference: &ProviderAuthRef) -> anyhow::Result<()> {
            self.records.lock().await.remove(reference);
            Ok(())
        }
    }

    /// Counts upstream calls, so "exactly one" is assertable, and can be told
    /// to fail with a specific typed error.
    struct FakeRefresher {
        calls: AtomicU32,
        revokes: AtomicU32,
        outcome: Mutex<Result<(), ProviderAuthError>>,
        /// Held while refreshing, to keep a refresh in flight while other
        /// callers pile up.
        gate: Mutex<()>,
    }

    impl FakeRefresher {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
                revokes: AtomicU32::new(0),
                outcome: Mutex::new(Ok(())),
                gate: Mutex::new(()),
            })
        }

        fn failing(err: ProviderAuthError) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
                revokes: AtomicU32::new(0),
                outcome: Mutex::new(Err(err)),
                gate: Mutex::new(()),
            })
        }
    }

    #[async_trait]
    impl ProviderCredentialRefresher for FakeRefresher {
        async fn refresh(
            &self,
            reference: &ProviderAuthRef,
        ) -> Result<ResolvedProviderCredential, ProviderAuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _held = self.gate.lock().await;
            let outcome = *self.outcome.lock().await;
            outcome.map(|()| {
                ResolvedProviderCredential::new(
                    reference.clone(),
                    CredentialKind::OAuthSubscription,
                    SecretValue::new("fresh-material"),
                )
            })
        }

        async fn revoke(&self, _reference: &ProviderAuthRef) -> Result<(), ProviderAuthError> {
            self.revokes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Test clock: reads are free, advancing is explicit.
    struct FakeClock(AtomicI64);

    impl FakeClock {
        fn at(nanos: i64) -> Arc<Self> {
            Arc::new(Self(AtomicI64::new(nanos)))
        }
        fn advance(&self, nanos: i64) {
            self.0.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now_nanos(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn reference(owner: &str, profile: &str) -> ProviderAuthRef {
        ProviderAuthRef::new(owner, "openai", profile)
    }

    fn lifecycle(
        store: Arc<MemStore>,
        refresher: Arc<FakeRefresher>,
        clock: Arc<FakeClock>,
    ) -> Arc<ProviderCredentialLifecycle> {
        Arc::new(ProviderCredentialLifecycle::new(
            store,
            refresher,
            clock,
            Arc::new(ExponentialBackoff::new_default()),
        ))
    }

    /// BPLIFE-01: N concurrent refreshes, one upstream call, same result for
    /// everyone. The gate keeps the leader's call open until every follower
    /// has joined.
    #[tokio::test]
    async fn concurrent_refreshes_share_a_single_upstream_call() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::ok();
        let clock = FakeClock::at(1_000);
        let life = lifecycle(store, refresher.clone(), clock);
        let reference = reference("alice", "default");

        let held = refresher.gate.lock().await;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let life = life.clone();
            let reference = reference.clone();
            tasks.push(tokio::spawn(async move { life.refresh(&reference).await }));
        }
        // Let every task reach either the leader's upstream call or the
        // follower wait before releasing the gate.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(held);

        let mut ok = 0;
        for task in tasks {
            let outcome = task.await.unwrap();
            match outcome {
                Ok(credential) => {
                    assert_eq!(credential.expose_secret(), "fresh-material");
                    ok += 1;
                }
                Err(e) => panic!("every joined caller must get the leader's success, got {e:?}"),
            }
        }
        assert_eq!(ok, 8);
        assert_eq!(
            refresher.calls.load(Ordering::SeqCst),
            1,
            "a single-use refresh token must not be exchanged twice concurrently"
        );
    }

    /// Different references are independent — one credential refreshing must
    /// never block another owner's.
    #[tokio::test]
    async fn different_references_do_not_share_a_flight() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::ok();
        let clock = FakeClock::at(1_000);
        let life = lifecycle(store, refresher.clone(), clock);

        let a = life.refresh(&reference("alice", "default")).await;
        let b = life.refresh(&reference("mallory", "default")).await;
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 2);
    }

    /// BPLIFE-02: a transient failure enters `Cooldown` with the policy's
    /// deadline, and the attempt counter grows so the next wait is longer.
    #[tokio::test]
    async fn a_transient_failure_enters_cooldown_with_growing_backoff() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::failing(ProviderAuthError::Throttled);
        let clock = FakeClock::at(0);
        let life = lifecycle(store.clone(), refresher.clone(), clock.clone());
        let reference = reference("alice", "default");

        let err = life.refresh(&reference).await.err().unwrap();
        assert_eq!(err, ProviderAuthError::Throttled);
        let record = store.load(&reference).await.unwrap().unwrap();
        assert_eq!(record.attempt, 1);
        assert_eq!(
            record.state,
            ProviderAuthState::Cooldown {
                until: 1_000_000_000,
                reason: ProviderAuthError::Throttled,
            }
        );

        // While in cooldown, no upstream call is spent at all.
        let calls_before = refresher.calls.load(Ordering::SeqCst);
        let err = life.refresh(&reference).await.err().unwrap();
        assert_eq!(err, ProviderAuthError::Throttled);
        assert_eq!(refresher.calls.load(Ordering::SeqCst), calls_before);

        // Past the deadline the attempt happens again and the wait doubles.
        clock.advance(1_000_000_001);
        let err = life.refresh(&reference).await.err().unwrap();
        assert_eq!(err, ProviderAuthError::Throttled);
        let record = store.load(&reference).await.unwrap().unwrap();
        assert_eq!(record.attempt, 2);
        match record.state {
            ProviderAuthState::Cooldown { until, .. } => {
                assert_eq!(until - clock.now_nanos(), 2_000_000_000)
            }
            other => panic!("expected cooldown, got {other:?}"),
        }
    }

    /// A success clears the failure history, so a credential that recovers
    /// does not keep an inflated backoff.
    #[tokio::test]
    async fn a_success_resets_the_attempt_counter() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::failing(ProviderAuthError::Throttled);
        let clock = FakeClock::at(0);
        let life = lifecycle(store.clone(), refresher.clone(), clock.clone());
        let reference = reference("alice", "default");

        life.refresh(&reference).await.err().unwrap();
        assert_eq!(store.load(&reference).await.unwrap().unwrap().attempt, 1);

        *refresher.outcome.lock().await = Ok(());
        clock.advance(2_000_000_000);
        life.refresh(&reference).await.unwrap();

        let record = store.load(&reference).await.unwrap().unwrap();
        assert_eq!(record.state, ProviderAuthState::Ready);
        assert_eq!(record.attempt, 0);
    }

    /// BPLIFE-02: a permanent failure is terminal — `ReauthRequired`, and no
    /// later call spends an upstream request, however long the caller waits.
    #[tokio::test]
    async fn a_permanent_failure_requires_reauth_and_never_retries() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::failing(ProviderAuthError::Invalid);
        let clock = FakeClock::at(0);
        let life = lifecycle(store.clone(), refresher.clone(), clock.clone());
        let reference = reference("alice", "default");

        assert_eq!(
            life.refresh(&reference).await.err().unwrap(),
            ProviderAuthError::Invalid
        );
        assert_eq!(
            store.load(&reference).await.unwrap().unwrap().state,
            ProviderAuthState::ReauthRequired {
                reason: ProviderAuthError::Invalid
            }
        );

        clock.advance(86_400_000_000_000);
        let calls_before = refresher.calls.load(Ordering::SeqCst);
        assert_eq!(
            life.refresh(&reference).await.err().unwrap(),
            ProviderAuthError::Invalid
        );
        assert_eq!(
            refresher.calls.load(Ordering::SeqCst),
            calls_before,
            "no amount of waiting may turn a permanent failure into a retry"
        );
    }

    /// A revoked credential is its own terminal state, not `ReauthRequired`:
    /// re-authenticating the same reference is not the remedy.
    #[tokio::test]
    async fn an_upstream_revocation_lands_in_revoked() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::failing(ProviderAuthError::Revoked);
        let clock = FakeClock::at(0);
        let life = lifecycle(store.clone(), refresher, clock);
        let reference = reference("alice", "default");

        assert_eq!(
            life.refresh(&reference).await.err().unwrap(),
            ProviderAuthError::Revoked
        );
        assert_eq!(
            store.load(&reference).await.unwrap().unwrap().state,
            ProviderAuthState::Revoked
        );
    }

    /// BPLIFE-03: a write that fails mid-transition leaves the last valid
    /// record in place — never a torn or invented one.
    #[tokio::test]
    async fn a_failed_write_preserves_the_last_valid_record() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::ok();
        let clock = FakeClock::at(500);
        let life = lifecycle(store.clone(), refresher, clock);
        let reference = reference("alice", "default");

        life.refresh(&reference).await.unwrap();
        let good = store.load(&reference).await.unwrap().unwrap();
        assert_eq!(good.state, ProviderAuthState::Ready);

        store
            .fail_writes
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let err = life.refresh(&reference).await.err().unwrap();
        assert_eq!(err, ProviderAuthError::Throttled);
        assert_eq!(
            store.load(&reference).await.unwrap().unwrap(),
            good,
            "a storage failure must not rewrite or corrupt the stored record"
        );
    }

    /// A transition computed from state someone else has already replaced is
    /// refused, which is what stops a stale conclusion from resurrecting a
    /// revoked credential.
    #[tokio::test]
    async fn a_transition_from_stale_state_is_not_applied() {
        let store = Arc::new(MemStore::default());
        let reference = reference("alice", "default");
        let revoked = CredentialLifecycleRecord {
            state: ProviderAuthState::Revoked,
            attempt: 0,
            observed_at: 1,
        };
        assert!(store
            .compare_and_swap(&reference, None, &revoked)
            .await
            .unwrap());

        // A record built from the pre-revocation view must lose.
        let ready = CredentialLifecycleRecord::ready(2);
        assert!(!store
            .compare_and_swap(&reference, None, &ready)
            .await
            .unwrap());
        assert_eq!(store.load(&reference).await.unwrap().unwrap(), revoked);
    }

    /// BPLIFE-04: revoking one reference touches nothing else — not the same
    /// owner's other profile, not another owner's same-named profile.
    #[tokio::test]
    async fn revoke_touches_only_the_requested_reference() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::ok();
        let clock = FakeClock::at(10);
        let life = lifecycle(store.clone(), refresher.clone(), clock);

        let targets = [
            reference("alice", "work"),
            reference("alice", "personal"),
            reference("mallory", "work"),
            reference("mallory", "personal"),
        ];
        for reference in &targets {
            life.refresh(reference).await.unwrap();
        }

        life.revoke(&targets[0]).await.unwrap();

        assert_eq!(
            store.load(&targets[0]).await.unwrap().unwrap().state,
            ProviderAuthState::Revoked
        );
        for untouched in &targets[1..] {
            assert_eq!(
                store.load(untouched).await.unwrap().unwrap().state,
                ProviderAuthState::Ready,
                "{untouched:?} was not the revoked reference"
            );
        }
        assert_eq!(
            refresher.revokes.load(Ordering::SeqCst),
            1,
            "exactly one upstream revocation, for the requested reference"
        );
    }

    /// Local intent wins over vendor support: state becomes `Revoked` even
    /// when the vendor call fails, because leaving it usable is worse.
    #[tokio::test]
    async fn revoke_marks_local_state_even_when_upstream_fails() {
        struct FailingRevoke;

        #[async_trait]
        impl ProviderCredentialRefresher for FailingRevoke {
            async fn refresh(
                &self,
                _reference: &ProviderAuthRef,
            ) -> Result<ResolvedProviderCredential, ProviderAuthError> {
                Err(ProviderAuthError::Missing)
            }
            async fn revoke(&self, _reference: &ProviderAuthRef) -> Result<(), ProviderAuthError> {
                Err(ProviderAuthError::UnsupportedProtocol)
            }
        }

        let store = Arc::new(MemStore::default());
        let reference = reference("alice", "default");
        assert!(store
            .compare_and_swap(&reference, None, &CredentialLifecycleRecord::ready(1))
            .await
            .unwrap());

        let life = ProviderCredentialLifecycle::new(
            store.clone(),
            Arc::new(FailingRevoke),
            Arc::new(SystemClock),
            Arc::new(ExponentialBackoff::new_default()),
        );

        let err = life.revoke(&reference).await.err().unwrap();
        assert_eq!(err, ProviderAuthError::UnsupportedProtocol);
        assert_eq!(
            store.load(&reference).await.unwrap().unwrap().state,
            ProviderAuthState::Revoked,
            "an operator's revocation must not depend on vendor support"
        );
    }

    /// `forget` removes the record; it is deliberately NOT what `revoke` does.
    #[tokio::test]
    async fn forget_removes_the_record_without_pretending_to_revoke() {
        let store = Arc::new(MemStore::default());
        let refresher = FakeRefresher::ok();
        let clock = FakeClock::at(10);
        let life = lifecycle(store.clone(), refresher.clone(), clock);
        let reference = reference("alice", "default");

        life.refresh(&reference).await.unwrap();
        life.forget(&reference).await.unwrap();

        assert!(store.load(&reference).await.unwrap().is_none());
        assert_eq!(
            refresher.revokes.load(Ordering::SeqCst),
            0,
            "forgetting must not silently claim an upstream revocation"
        );
    }

    #[test]
    fn backoff_doubles_and_then_caps() {
        let policy = ExponentialBackoff {
            base_nanos: 1_000,
            max_nanos: 8_000,
        };
        assert_eq!(policy.cooldown_nanos(1), 1_000);
        assert_eq!(policy.cooldown_nanos(2), 2_000);
        assert_eq!(policy.cooldown_nanos(3), 4_000);
        assert_eq!(policy.cooldown_nanos(4), 8_000);
        assert_eq!(policy.cooldown_nanos(5), 8_000, "capped");
        // Absurd attempt counts must not overflow into a negative deadline.
        assert_eq!(policy.cooldown_nanos(u32::MAX), 8_000);
    }

    #[tokio::test]
    async fn state_reports_none_for_an_unknown_reference() {
        let store = Arc::new(MemStore::default());
        let life = lifecycle(store, FakeRefresher::ok(), FakeClock::at(0));
        assert!(life
            .state(&reference("nobody", "default"))
            .await
            .unwrap()
            .is_none());
    }
}
