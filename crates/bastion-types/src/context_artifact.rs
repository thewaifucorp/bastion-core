//! Versioned, opaque context artifact — the M1 ADR's minimal contract for
//! propagating a rule/policy update to running agents without a
//! rebuild/redeploy (`docs/revamp/M1-ADR-substrate-split.md` §"APIs públicas
//! mínimas": `VersionedContextArtifact`/`ContextRevision`).
//!
//! This is the contract's ORIGIN, not a pre-existing API this crate merely
//! documents: neither type existed anywhere in the substrate before the M5
//! second-consumer slice (`docs/revamp/C3-m5-second-consumer-design.md`
//! §M5.1) needed to exercise "rule propagation" end-to-end — a LOOP-REPORT
//! finding, closed here with the conservative minimum the design doc asks
//! for: "o OSS só precisa do artefato opaco versionado + provenance +
//! `effective_from` + estratégia de stale; o resto (publicação, fan-out) é do
//! host."
//!
//! Deliberately minimal: publication, fan-out to workers, and *detecting*
//! staleness (e.g. "have I successfully synced with the upstream publisher
//! recently?") stay the host's job — this type only gives every host a
//! shared vocabulary for "opaque artifact + provenance + effective_from + a
//! declared stale strategy" instead of reinventing those fields ad hoc. It
//! is NOT a `TurnContextProvider` itself (that trait lives in
//! `bastion-runtime`, a crate above this one) — a host wraps one of these in
//! its own `TurnContextProvider` impl; SEAM #2 stays the single injection
//! seam, this is just the data it reads from.

use serde::{Deserialize, Serialize};

/// One immutable, published state of a [`VersionedContextArtifact`].
///
/// `content` is opaque exactly like `ContextBlock` (SEAM #2,
/// `bastion_runtime::agent::context`) — the kernel/runtime never parses it,
/// only the host that published it and the host-side `TurnContextProvider`
/// that reads it back understand the format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextRevision {
    /// Monotonically increasing within one artifact's history — comparison
    /// (never wall-clock arrival order) decides "newest". [`VersionedContextArtifact::publish`]
    /// rejects a revision whose `version` does not strictly exceed every
    /// revision already recorded.
    pub version: u64,
    /// Opaque payload in the host's own format.
    pub content: String,
    /// Audit-trail only, host-defined (e.g. `"operator:alice"`,
    /// `"ticket-system:v2"`) — never interpreted for authorization.
    pub provenance: String,
    /// Nanoseconds since `UNIX_EPOCH`. [`VersionedContextArtifact::effective_at`]
    /// never picks a revision whose `effective_from` is still in the future.
    /// A turn must resolve `effective_at` exactly ONCE, at the point
    /// `TurnContextProvider::context_for_turn` is invoked, and hold that
    /// answer for the rest of the turn — never re-read it later in the same
    /// turn — so a revision publish mid-turn cannot change which rule that
    /// turn is judged against (M5.1 step 3).
    pub effective_from: i64,
}

/// What a host-side consumer should do when it cannot confirm the artifact's
/// data is current (e.g. its own fetch/sync from the publisher failed or is
/// overdue). Detecting "am I stale" is host logic — this only carries the
/// DECLARED policy so a host's `TurnContextProvider` has a typed answer
/// instead of inventing its own ad hoc convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StalePolicy {
    /// Keep serving the last known-good revision.
    UseLastKnown,
    /// Treat "possibly stale" as "unavailable" for this turn — safer for a
    /// critical rule than risking a silently outdated one.
    FailClosed,
}

/// An append-only, single-owner history of [`ContextRevision`]s plus the
/// [`StalePolicy`] that applies to it.
///
/// `publish` only ever appends — "rollback" is publishing a NEW revision
/// whose `content` matches an earlier one (M5.1 step 5): the audit trail
/// never loses a step, `history()` always shows the true sequence of
/// publications, including the rollback itself.
#[derive(Debug, Clone)]
pub struct VersionedContextArtifact {
    revisions: Vec<ContextRevision>,
    stale_policy: StalePolicy,
}

impl VersionedContextArtifact {
    /// Start an empty artifact with no published revision yet.
    pub fn new(stale_policy: StalePolicy) -> Self {
        Self {
            revisions: Vec::new(),
            stale_policy,
        }
    }

    /// The declared stale-handling strategy for this artifact.
    pub fn stale_policy(&self) -> StalePolicy {
        self.stale_policy
    }

    /// Append a new revision. Fails closed on a non-monotonic `version` —
    /// history is append-only and versions must strictly increase, so a
    /// caller can never silently overwrite or reorder an already-published
    /// revision (rollback is a NEW revision, never a rewrite — see the
    /// struct-level doc).
    pub fn publish(&mut self, revision: ContextRevision) -> anyhow::Result<()> {
        if let Some(last) = self.revisions.last() {
            if revision.version <= last.version {
                anyhow::bail!(
                    "non-monotonic revision: version {} does not exceed the latest published version {}",
                    revision.version,
                    last.version
                );
            }
        }
        self.revisions.push(revision);
        Ok(())
    }

    /// The revision effective as of `now_nanos`: the newest published
    /// revision whose `effective_from <= now_nanos`. `None` when no revision
    /// has become effective yet (empty history, or every published revision
    /// still lies in the future).
    pub fn effective_at(&self, now_nanos: i64) -> Option<&ContextRevision> {
        self.revisions
            .iter()
            .rev()
            .find(|r| r.effective_from <= now_nanos)
    }

    /// The most recently PUBLISHED revision, regardless of `effective_from`
    /// — audit/trace use (M5.1 step 4: "trace da versão"), never for
    /// deciding what a turn should read (use [`Self::effective_at`] for
    /// that).
    pub fn latest_published(&self) -> Option<&ContextRevision> {
        self.revisions.last()
    }

    /// Full publication history, oldest first — rollback/trace queries.
    pub fn history(&self) -> &[ContextRevision] {
        &self.revisions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(version: u64, content: &str, effective_from: i64) -> ContextRevision {
        ContextRevision {
            version,
            content: content.to_string(),
            provenance: "test".to_string(),
            effective_from,
        }
    }

    #[test]
    fn empty_artifact_has_no_effective_revision() {
        let artifact = VersionedContextArtifact::new(StalePolicy::FailClosed);
        assert!(artifact.effective_at(1_000).is_none());
        assert!(artifact.latest_published().is_none());
        assert!(artifact.history().is_empty());
    }

    #[test]
    fn publish_rejects_non_monotonic_version() {
        let mut artifact = VersionedContextArtifact::new(StalePolicy::UseLastKnown);
        artifact.publish(rev(2, "v2", 0)).expect("v2 publishes");
        assert!(
            artifact.publish(rev(2, "dup", 10)).is_err(),
            "equal version must be rejected"
        );
        assert!(
            artifact.publish(rev(1, "older", 10)).is_err(),
            "lower version must be rejected"
        );
    }

    #[test]
    fn effective_at_picks_newest_revision_not_in_the_future() {
        let mut artifact = VersionedContextArtifact::new(StalePolicy::UseLastKnown);
        artifact.publish(rev(1, "v1", 0)).unwrap();
        artifact.publish(rev(2, "v2", 100)).unwrap();

        assert_eq!(artifact.effective_at(50).unwrap().content, "v1");
        assert_eq!(artifact.effective_at(100).unwrap().content, "v2");
        assert_eq!(artifact.effective_at(200).unwrap().content, "v2");
    }

    #[test]
    fn effective_from_in_the_future_never_wins_early() {
        let mut artifact = VersionedContextArtifact::new(StalePolicy::FailClosed);
        artifact.publish(rev(1, "v1", 1_000)).unwrap();
        assert!(
            artifact.effective_at(500).is_none(),
            "a turn before effective_from must not see the revision yet"
        );
        assert_eq!(artifact.effective_at(1_000).unwrap().content, "v1");
    }

    #[test]
    fn rollback_is_a_new_revision_preserving_full_history() {
        let mut artifact = VersionedContextArtifact::new(StalePolicy::UseLastKnown);
        artifact.publish(rev(1, "v1", 0)).unwrap();
        artifact.publish(rev(2, "v2", 10)).unwrap();
        // "Rollback to v1" = a NEW revision (v3) carrying v1's content —
        // never rewriting history.
        artifact
            .publish(rev(3, "v1", 20))
            .expect("rollback publishes as a new version");

        assert_eq!(artifact.history().len(), 3, "no revision was overwritten");
        assert_eq!(artifact.effective_at(100).unwrap().version, 3);
        assert_eq!(artifact.effective_at(100).unwrap().content, "v1");
        assert_eq!(artifact.latest_published().unwrap().version, 3);
    }

    #[test]
    fn stale_policy_is_readable_by_a_host_side_consumer() {
        let artifact = VersionedContextArtifact::new(StalePolicy::FailClosed);
        assert_eq!(artifact.stale_policy(), StalePolicy::FailClosed);
    }
}
