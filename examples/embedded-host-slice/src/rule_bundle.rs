//! M5.1 (`docs/ARCHITECTURE.md` §"M5.1 — propagação
//! de regra versionada"): the host's own `RuleStore` + `TurnContextProvider`
//! built on top of `bastion_types::VersionedContextArtifact`/`ContextRevision`
//! (the contract that had to be BORN in the substrate for this — see
//! `crates/bastion-types/src/context_artifact.rs`), plus the 7 propagation
//! steps the design doc numbers, exercised end-to-end.
//!
//! Everything in this file is host-owned, in-process state — NONE of it
//! touches Bastion's session store (M5 acceptance criterion 7). Publication
//! and fan-out to "workers" are the host's job by design (§M5.1's own
//! closing line); this module is exactly that host-side plumbing, built only
//! from the public `VersionedContextArtifact` API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};
use bastion_runtime::memory::PrivacyTier;
use bastion_types::{ContextRevision, StalePolicy, VersionedContextArtifact};

/// How long the host tolerates not having confirmed a fresh sync with its
/// (hypothetical) upstream rule publisher before treating its own data as
/// "possibly stale". Detecting staleness is host logic (see the module doc
/// on `bastion_types::context_artifact`) — this constant and the freshness
/// bookkeeping below live entirely in the host, never the substrate.
pub const FRESHNESS_TTL_NANOS: i64 = 5 * 60 * 1_000_000_000; // 5 minutes

/// Host-owned, owner-scoped store of rule bundles — one
/// `VersionedContextArtifact` per owner. Lives entirely in this process's
/// memory (a real host would back this with its own database); Bastion never
/// sees it.
#[derive(Default)]
pub struct RuleStore {
    artifacts: Mutex<HashMap<String, VersionedContextArtifact>>,
}

impl RuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an owner with an (initially empty) rule history and its
    /// declared stale-handling policy. An owner never registered here has no
    /// artifact at all — `effective_at` reports `None`, `RuleBundleContextProvider`
    /// injects zero blocks. This IS the owner-scoping mechanism: publishing
    /// only ever targets a registered owner, so a different owner can never
    /// receive it (M5.1 step 2).
    pub fn ensure_owner(&self, owner: &str, stale_policy: StalePolicy) {
        self.artifacts
            .lock()
            .expect("RuleStore mutex poisoned")
            .entry(owner.to_string())
            .or_insert_with(|| VersionedContextArtifact::new(stale_policy));
    }

    /// Publish a new revision for `owner`. Fails if `owner` was never
    /// registered via `ensure_owner`, or if `revision.version` does not
    /// strictly exceed the latest already published (append-only history —
    /// `VersionedContextArtifact::publish`'s own guarantee).
    pub fn publish(&self, owner: &str, revision: ContextRevision) -> anyhow::Result<()> {
        let mut guard = self.artifacts.lock().expect("RuleStore mutex poisoned");
        let artifact = guard.get_mut(owner).ok_or_else(|| {
            anyhow::anyhow!("no rule artifact for owner '{owner}' — call ensure_owner first")
        })?;
        artifact.publish(revision)
    }

    pub fn effective_at(&self, owner: &str, now_nanos: i64) -> Option<ContextRevision> {
        self.artifacts
            .lock()
            .expect("RuleStore mutex poisoned")
            .get(owner)
            .and_then(|a| a.effective_at(now_nanos).cloned())
    }

    /// Most recently PUBLISHED revision regardless of `effective_from` —
    /// audit/trace use only (M5.1 step 4).
    pub fn latest_published(&self, owner: &str) -> Option<ContextRevision> {
        self.artifacts
            .lock()
            .expect("RuleStore mutex poisoned")
            .get(owner)
            .and_then(|a| a.latest_published().cloned())
    }

    /// Full publication history, oldest first — rollback/trace queries
    /// (M5.1 step 5: "auditável").
    pub fn history(&self, owner: &str) -> Vec<ContextRevision> {
        self.artifacts
            .lock()
            .expect("RuleStore mutex poisoned")
            .get(owner)
            .map(|a| a.history().to_vec())
            .unwrap_or_default()
    }

    pub fn stale_policy(&self, owner: &str) -> Option<StalePolicy> {
        self.artifacts
            .lock()
            .expect("RuleStore mutex poisoned")
            .get(owner)
            .map(|a| a.stale_policy())
    }
}

/// A host-controlled logical clock — lets this demonstration advance "now"
/// deterministically (e.g. past a future `effective_from`) without a real
/// wall-clock sleep. Entirely host code; the substrate has no notion of it.
#[derive(Clone)]
pub struct FakeClock(Arc<AtomicI64>);

impl FakeClock {
    pub fn new(start_nanos: i64) -> Self {
        Self(Arc::new(AtomicI64::new(start_nanos)))
    }

    pub fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn advance(&self, delta_nanos: i64) {
        self.0.fetch_add(delta_nanos, Ordering::SeqCst);
    }
}

/// The host's own `TurnContextProvider` (SEAM #2) — injects the owner's
/// currently-EFFECTIVE rule bundle as one opaque block. Zero blocks for an
/// owner with no artifact, or none effective yet — never another owner's
/// content (M5.1 step 2).
pub struct RuleBundleContextProvider {
    store: Arc<RuleStore>,
    clock: FakeClock,
    /// Host-side freshness bookkeeping: nanoseconds (on `clock`) the host
    /// last confirmed it successfully synced with its upstream publisher.
    /// Absent = never synced. This is genuinely host logic — see the module
    /// doc on `bastion_types::context_artifact` for why staleness DETECTION
    /// is deliberately outside the substrate's minimal contract.
    last_synced_at: Mutex<HashMap<String, i64>>,
}

impl RuleBundleContextProvider {
    pub fn new(store: Arc<RuleStore>, clock: FakeClock) -> Self {
        Self {
            store,
            clock,
            last_synced_at: Mutex::new(HashMap::new()),
        }
    }

    /// Host confirms it successfully talked to its upstream rule publisher
    /// for `owner`, at the current (fake) clock time.
    pub fn mark_synced(&self, owner: &str) {
        let now = self.clock.now();
        self.last_synced_at
            .lock()
            .expect("last_synced_at mutex poisoned")
            .insert(owner.to_string(), now);
    }

    fn is_possibly_stale(&self, owner: &str) -> bool {
        let now = self.clock.now();
        match self
            .last_synced_at
            .lock()
            .expect("last_synced_at mutex poisoned")
            .get(owner)
        {
            Some(&last) => now.saturating_sub(last) > FRESHNESS_TTL_NANOS,
            None => true,
        }
    }
}

#[async_trait]
impl TurnContextProvider for RuleBundleContextProvider {
    async fn context_for_turn(
        &self,
        owner: &str,
        _turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        let now = self.clock.now();
        let Some(revision) = self.store.effective_at(owner, now) else {
            return Vec::new();
        };

        if self.is_possibly_stale(owner) {
            match self.store.stale_policy(owner) {
                Some(StalePolicy::FailClosed) => {
                    tracing::warn!(
                        owner,
                        version = revision.version,
                        "rule bundle possibly stale — FailClosed policy: omitting it this turn"
                    );
                    return Vec::new();
                }
                _ => {
                    tracing::warn!(
                        owner,
                        version = revision.version,
                        "rule bundle possibly stale — UseLastKnown policy: serving the last known revision anyway"
                    );
                }
            }
        }

        // M5.1 step 4: "trace da versão" — the applied version + provenance
        // is logged structurally on every turn that reads one.
        tracing::info!(
            owner,
            version = revision.version,
            provenance = %revision.provenance,
            "rule bundle applied to this turn"
        );

        vec![ContextBlock {
            content: format!(
                "<rule_bundle version=\"{}\" provenance=\"{}\">{}</rule_bundle>",
                revision.version, revision.provenance, revision.content
            ),
            max_tier: PrivacyTier::CloudOk,
        }]
    }
}

/// Read the sole content string out of a 0-or-1-block turn-context result.
/// `ContextBlock` has no `Debug`/`PartialEq` derive (see
/// `docs/ARCHITECTURE.md` finding on this slice) — a second consumer
/// asserting on injected content has to destructure fields manually rather
/// than `assert_eq!` the struct, which this helper does once instead of at
/// every call site below.
fn only_content(blocks: &[ContextBlock]) -> Option<&str> {
    match blocks {
        [] => None,
        [b] => Some(b.content.as_str()),
        _ => panic!("expected 0 or 1 context blocks, got {}", blocks.len()),
    }
}

/// Runs the M5.1 design doc's numbered propagation steps against a fresh
/// `RuleStore`/`RuleBundleContextProvider` pair, asserting each one, and
/// returns the provider so the caller can also wire it into a real
/// `AgentLoop` for one live end-to-end SEAM #2 check.
///
/// NOTE (LOOP-REPORT candidate): the design doc's acceptance criteria call
/// these "os 8 passos de propagação", but the doc's own numbered list
/// (§M5.1) has exactly 7 entries. All 7 are covered below, numbered to match
/// the doc's list; no phantom 8th step was invented to force the count.
pub async fn demonstrate_rule_bundle_propagation(
    store: Arc<RuleStore>,
    clock: FakeClock,
) -> anyhow::Result<RuleBundleContextProvider> {
    const OWNER_A: &str = "owner_a";
    const OWNER_B: &str = "owner_b";
    const OWNER_C_FAIL_CLOSED: &str = "owner_c_failclosed";

    store.ensure_owner(OWNER_A, StalePolicy::UseLastKnown);
    // OWNER_B deliberately never registered/published to — proves "no
    // artifact for this owner" is a clean empty result, not a crash.

    let provider = RuleBundleContextProvider::new(store.clone(), clock.clone());
    provider.mark_synced(OWNER_A);

    // Step 1: host publishes RuleBundle v1 for owner A.
    let t0 = clock.now();
    store.publish(
        OWNER_A,
        ContextRevision {
            version: 1,
            content: "max_transfer_usd=100".to_string(),
            provenance: "operator:alice".to_string(),
            effective_from: t0,
        },
    )?;

    // Step 2: two "workers" of owner A both apply v1 identically; a third,
    // owner B, receives NOTHING (scope by owner).
    let worker1 = provider.context_for_turn(OWNER_A, "hi", None).await;
    let worker2 = provider.context_for_turn(OWNER_A, "hi", None).await;
    let owner_b_blocks = provider.context_for_turn(OWNER_B, "hi", None).await;
    let worker1_content = only_content(&worker1).expect("owner A must receive v1");
    assert!(worker1_content.contains("version=\"1\""));
    assert_eq!(
        worker1_content,
        only_content(&worker2).expect("second worker must also receive v1"),
        "both owner-A workers must read the identical effective revision"
    );
    assert!(
        owner_b_blocks.is_empty(),
        "owner B must receive NOTHING — no cross-owner leak"
    );
    println!("[M5.1 1-2] v1 published; both owner-A workers see it identically; owner B sees nothing — OK");

    // Step 3: v2 published with a FUTURE effective_from — no in-flight turn
    // switches rules mid-turn; only the boundary BETWEEN turns can.
    let v2_effective_from = t0 + 3_600 * 1_000_000_000; // +1h on the fake clock
    store.publish(
        OWNER_A,
        ContextRevision {
            version: 2,
            content: "max_transfer_usd=500".to_string(),
            provenance: "operator:alice".to_string(),
            effective_from: v2_effective_from,
        },
    )?;
    let still_v1 = provider.context_for_turn(OWNER_A, "hi", None).await;
    assert!(
        only_content(&still_v1).unwrap().contains("version=\"1\""),
        "a turn before v2's effective_from must still read v1 — no mid-flight switch"
    );
    println!(
        "[M5.1 3] v2 published with a future effective_from; the current turn still reads v1 — OK"
    );

    // Step 4: advance past v2's effective_from — the NEXT turn reads v2;
    // trace (tracing::info! above) records the version applied.
    clock.advance(3_600 * 1_000_000_000 + 1);
    let now_v2 = provider.context_for_turn(OWNER_A, "hi", None).await;
    assert!(only_content(&now_v2).unwrap().contains("version=\"2\""));
    // Trace query: the host's own audit view (`latest_published`, distinct
    // from `effective_at` — see its rustdoc) confirms v2 is what was last
    // published, matching what this turn just read as effective.
    let traced = store
        .latest_published(OWNER_A)
        .expect("a revision must have been published for owner A by now");
    assert_eq!(traced.version, 2);
    println!(
        "[M5.1 4] next turn (after effective_from passed) reads v2; trace query \
         (RuleStore::latest_published) confirms version {} from provenance '{}' — OK",
        traced.version, traced.provenance
    );

    // Step 5: rollback to v1's content as a NEW revision (v3) — auditable,
    // history never rewritten.
    store.publish(
        OWNER_A,
        ContextRevision {
            version: 3,
            content: "max_transfer_usd=100".to_string(),
            provenance: "operator:alice (rollback to v1)".to_string(),
            effective_from: clock.now(),
        },
    )?;
    let history = store.history(OWNER_A);
    assert_eq!(
        history.len(),
        3,
        "rollback must APPEND, never rewrite history"
    );
    let rolled_back = provider.context_for_turn(OWNER_A, "hi", None).await;
    let rolled_back_content = only_content(&rolled_back).unwrap();
    assert!(
        rolled_back_content.contains("version=\"3\"")
            && rolled_back_content.contains("max_transfer_usd=100")
    );
    println!("[M5.1 5] rollback published as v3 (v1's content); the full 3-entry history is preserved — OK");

    // Step 6: a "worker" that missed v2 entirely (never polled during its
    // reign) still recovers the CURRENT correct state (v3) the instant it
    // asks again — no per-worker cache to go stale, the provider always
    // reads live from the shared store.
    let returning_worker = provider.context_for_turn(OWNER_A, "hi", None).await;
    assert_eq!(
        only_content(&returning_worker).unwrap(),
        rolled_back_content
    );
    println!("[M5.1 6] a worker offline during v2 recovers the correct current revision (v3) on its next read — OK");

    // Step 7: a critical rule that might be stale follows its DECLARED
    // policy — the host decides, per artifact.
    //
    // 7a: FailClosed owner whose host-side sync is overdue → omit the rule.
    store.ensure_owner(OWNER_C_FAIL_CLOSED, StalePolicy::FailClosed);
    store.publish(
        OWNER_C_FAIL_CLOSED,
        ContextRevision {
            version: 1,
            content: "critical_rule".to_string(),
            provenance: "operator:alice".to_string(),
            effective_from: clock.now(),
        },
    )?;
    // Deliberately never `mark_synced` this owner — "never synced" reads as
    // possibly-stale.
    let failclosed_blocks = provider
        .context_for_turn(OWNER_C_FAIL_CLOSED, "hi", None)
        .await;
    assert!(
        failclosed_blocks.is_empty(),
        "FailClosed + possibly-stale must omit the rule, never silently serve a possibly-outdated critical one"
    );

    // 7b: UseLastKnown owner (A) whose sync is now overdue too → still
    // serves the last known revision.
    clock.advance(FRESHNESS_TTL_NANOS + 1);
    let stale_but_served = provider.context_for_turn(OWNER_A, "hi", None).await;
    let stale_content = only_content(&stale_but_served)
        .expect("UseLastKnown must keep serving the last known revision even when possibly stale");
    assert!(stale_content.contains("version=\"3\""));
    println!("[M5.1 7] stale-rule policy honored: FailClosed omits a possibly-stale critical rule; UseLastKnown keeps serving the last known one — OK");

    println!(
        "[M5.1] all propagation steps passed — a new rule reaches the right owner, \
         never cross-owner, without a rebuild/redeploy, without depending on the LLM \
         remembering to fetch it"
    );

    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_propagation_walkthrough_passes() {
        let store = Arc::new(RuleStore::new());
        let clock = FakeClock::new(1_000_000_000);
        demonstrate_rule_bundle_propagation(store, clock)
            .await
            .expect("every M5.1 propagation step must pass");
    }
}
