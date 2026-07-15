//! The kernel `Memory` port (M2 step 3b, decision D1).
//!
//! The trait and its `SharedMemory` alias moved here VERBATIM from
//! `src/memory/mod.rs`: the runtime defines the port, memory backends
//! implement it (the `SqliteMemory` backend and everything else under
//! `src/memory/` stays in the app crate and becomes `bastion-memory` in M2
//! step 4 — correct inversion). The pure data types in the trait's
//! signatures (`Belief`, `BeliefDraft`, `BeliefKind`, `Outcome`,
//! `PendingCorrection`, `PrivacyTier`) live in `bastion-types` and are
//! re-exported here so the moved kernel files' `crate::memory::...` paths
//! keep compiling unchanged.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

pub use bastion_types::{Belief, BeliefDraft, BeliefKind, Outcome, PendingCorrection, PrivacyTier};

/// Core memory abstraction. Every subsystem reads/writes beliefs through this trait.
#[async_trait]
pub trait Memory: Send + Sync {
    /// Store a belief and one provenance row; returns the new belief id.
    // A belief + its provenance is 8 flat fields; bundling them into a struct here
    // would force every impl and caller through a one-use wrapper for no gain.
    #[allow(clippy::too_many_arguments)]
    async fn store_belief(
        &self,
        owner_id: &str,
        persona_tag: Option<&str>,
        content: &str,
        session_id: &str,
        source: &str,
        is_core: bool,
        tier: Option<PrivacyTier>,
    ) -> anyhow::Result<i64>;

    /// Retrieve non-revoked beliefs for (owner, persona_tag).
    /// WHERE owner_id=? AND (persona_tag=? OR persona_tag IS NULL) AND revoked=0 AND weight>0
    async fn retrieve_tagged(
        &self,
        owner_id: &str,
        persona_tag: Option<&str>,
    ) -> anyhow::Result<Vec<Belief>>;

    /// Soft-revoke: set weight=0, revoked=1, revoked_at=now. Row is NEVER deleted (D-15).
    /// Owner-scoped (IDOR guard): only the owning user's belief may be revoked.
    /// Errors when no row matches (id, owner_id) so a wrong owner cannot silently no-op.
    async fn revoke_belief(&self, owner_id: &str, id: i64) -> anyhow::Result<()>;

    /// Soft-supersession: sets `superseded_by=new_id`, `supersedes_at=now` on the OLD
    /// row only (id=old_id). The NEW row (id=new_id) is untouched by this call — it is
    /// presumed to already exist as a normal belief. Row is NEVER deleted (same D-15
    /// principle as revoke_belief). Owner-scoped (IDOR guard): errors when no row
    /// matches (old_id, owner_id) — a wrong owner cannot silently no-op.
    async fn supersede_belief(
        &self,
        owner_id: &str,
        old_id: i64,
        new_id: i64,
    ) -> anyhow::Result<()>;

    /// Load frozen-core beliefs (is_core=1, revoked=0) once at session start.
    async fn load_core(&self, owner_id: &str) -> anyhow::Result<Vec<Belief>>;

    /// Retrieve ALL non-revoked beliefs for an owner (regardless of persona_tag), for .af export.
    async fn retrieve_all_beliefs(&self, owner_id: &str) -> anyhow::Result<Vec<Belief>>;

    /// Return (session_id, source) provenance rows for a belief.
    /// Owner-scoped (IDOR guard): provenance is only returned when the belief is
    /// owned by `owner_id`; cross-owner probes get an empty vec (indistinguishable
    /// from a missing id).
    async fn provenance_for(
        &self,
        owner_id: &str,
        belief_id: i64,
    ) -> anyhow::Result<Vec<(String, String)>>;

    /// Store a procedural belief (kind='procedural') + its provenance row. Mirrors
    /// store_belief's atomic belief+provenance transaction; does NOT widen
    /// store_belief (Pitfall 5).
    async fn store_procedural_belief(&self, draft: BeliefDraft) -> anyhow::Result<i64>;

    /// Increment exactly one counter (helpful/harmful/neutral) on an existing belief.
    /// Content untouched. Owner-scoped (IDOR guard) — errors on cross-owner no-op,
    /// same discipline as revoke_belief.
    async fn record_belief_outcome(
        &self,
        owner_id: &str,
        id: i64,
        outcome: Outcome,
    ) -> anyhow::Result<()>;

    /// Stigmergic reinforcement (ACO pheromone deposit): add `delta` to ONE untagged
    /// procedural belief's `weight` — the retrieval-ranking factor the RAG multiplies by
    /// lexical relevance — capped to bound a runaway trail. Owner-scoped and best-effort:
    /// a no-match (wrong owner, revoked, factual, or persona-tagged) is a silent no-op,
    /// since a trail may be revoked between selection and deposit.
    async fn reinforce_belief(&self, owner_id: &str, id: i64, delta: f64) -> anyhow::Result<()>;

    /// Stigmergic evaporation: multiply every non-revoked UNTAGGED procedural belief's
    /// `weight` by `factor` (= 1 - ρ), floored at `floor` (> 0, so a decayed trail stays
    /// faintly retrievable and NEVER reaches the revoked-sentinel weight of 0). Scoped to the
    /// global procedural playbook (persona_tag IS NULL) — the set the Reflector reinforces —
    /// so no trail decays without ever being reinforceable. Returns the number of trails decayed.
    async fn evaporate_beliefs(
        &self,
        owner_id: &str,
        factor: f64,
        floor: f64,
    ) -> anyhow::Result<u64>;

    /// Enqueue a metadata-only pending-correction signal for `belief_id` (LEARN-04
    /// edit half). Called synchronously right after a contestation revoke — never
    /// carries raw text. Drained by the offline Reflector (07-05) via
    /// `take_pending_corrections`.
    async fn record_pending_correction(
        &self,
        owner_id: &str,
        belief_id: i64,
        tier: Option<PrivacyTier>,
    ) -> anyhow::Result<i64>;

    /// Dequeue (read + delete, one transaction) all pending corrections for
    /// `owner_id`. Owner-scoped (IDOR guard) — a caller can only drain its own queue.
    async fn take_pending_corrections(
        &self,
        owner_id: &str,
    ) -> anyhow::Result<Vec<PendingCorrection>>;
}

/// Clonable shared-handle alias — mirrors SharedProvider from provider/mod.rs.
pub type SharedMemory = Arc<RwLock<Box<dyn Memory>>>;
