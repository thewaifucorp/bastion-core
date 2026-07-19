//! Neutral, owner-scoped durable-store port for a [`TaskCase`] and its
//! attendant records (US-102).
//!
//! `TaskStore` is the mechanism a `Pursue` task's lifecycle persists through:
//! every method is owner-scoped so a wrong `owner` never sees or mutates
//! another owner's data (the IDOR-guard discipline established by
//! `capability/approval.rs` and `capability/permission_queue.rs`), and every
//! mutating method that touches an existing [`TaskCase`] row uses optimistic
//! concurrency (`expected_revision`) so two concurrent writers never
//! silently clobber each other — a stale revision or a wrong owner always
//! bails, never a silent no-op or overwrite.
//!
//! [`crate::task::SqliteTaskStore`] is the concrete, production
//! implementation.

use bastion_agent_runtime::SessionHandle;

use super::{
    Attempt, AttemptId, Evidence, NextDecision, StopReason, TaskCase, TaskCaseId, TaskStatus,
};

/// Durable, owner-scoped store for the adaptive task lifecycle (US-101's
/// [`TaskCase`] / [`Attempt`] / [`Evidence`]). A host wires a concrete
/// implementation (e.g. [`crate::task::SqliteTaskStore`]); the kernel only
/// ever depends on this trait.
#[async_trait::async_trait]
pub trait TaskStore: Send + Sync {
    /// Persist a brand-new [`TaskCase`]. Idempotent on `idempotency_key`: a
    /// second call with a key that already exists is a no-op `Ok(())` —
    /// never a duplicate row, never an error.
    async fn create_case(&self, case: &TaskCase, idempotency_key: &str) -> anyhow::Result<()>;

    /// Load a case by id, scoped to `owner`. `None` when absent OR owned by
    /// someone else — a wrong owner is indistinguishable from "doesn't
    /// exist" to the caller (IDOR guard).
    async fn load_case(&self, owner: &str, id: &TaskCaseId) -> anyhow::Result<Option<TaskCase>>;

    /// All cases owned by `owner`, newest first.
    async fn list_cases_for_owner(&self, owner: &str) -> anyhow::Result<Vec<TaskCase>>;

    /// Rewrite every mutable field of `case` (as it stands in memory) with
    /// optimistic concurrency: succeeds only if the stored row's revision is
    /// still `expected_revision`, in which case the new revision becomes
    /// `expected_revision + 1` (returned). Otherwise bails with a conflict
    /// error — never a silent overwrite.
    async fn update_case(&self, case: &TaskCase, expected_revision: u64) -> anyhow::Result<u64>;

    /// Move a case's status forward. Rejects (bails, no write) whenever: the
    /// case isn't found for `owner`; the current status is already terminal
    /// (a task has exactly one terminal event, ever); the transition isn't
    /// allowed by [`TaskStatus::can_transition_to`]; or `stop_reason` is
    /// `Some` XOR `next.is_terminal()` (a terminal status always carries a
    /// reason, a non-terminal one never does). On success, bumps and
    /// returns the new revision.
    async fn transition_status(
        &self,
        owner: &str,
        id: &TaskCaseId,
        next: TaskStatus,
        stop_reason: Option<StopReason>,
        expected_revision: u64,
    ) -> anyhow::Result<u64>;

    /// Replace the case's single recomputed [`NextDecision`] (or clear it),
    /// OCC-guarded like [`Self::update_case`].
    async fn set_next_decision(
        &self,
        owner: &str,
        id: &TaskCaseId,
        decision: Option<NextDecision>,
        expected_revision: u64,
    ) -> anyhow::Result<u64>;

    /// Append one [`Attempt`], idempotent on `attempt.id`. The owning case
    /// (looked up by `attempt.task`) must already exist — `Attempt` carries
    /// no `owner` field of its own, so the store resolves ownership from the
    /// case row.
    async fn append_attempt(&self, attempt: &Attempt) -> anyhow::Result<()>;

    /// Load one attempt, scoped to `owner`.
    async fn load_attempt(&self, owner: &str, id: &AttemptId) -> anyhow::Result<Option<Attempt>>;

    /// All attempts for `task`, scoped to `owner`, oldest first.
    async fn list_attempts_for_case(
        &self,
        owner: &str,
        task: &TaskCaseId,
    ) -> anyhow::Result<Vec<Attempt>>;

    /// Record one [`Evidence`], idempotent on `evidence.id`. `Evidence`
    /// carries no `task` field; the owning task is resolved via
    /// `evidence.attempt`, which must already have been appended for this
    /// `owner`.
    async fn record_evidence(&self, owner: &str, evidence: &Evidence) -> anyhow::Result<()>;

    /// Upsert the external harness [`SessionHandle`] for `task` (restart
    /// recovery).
    async fn save_external_handle(
        &self,
        owner: &str,
        task: &TaskCaseId,
        handle: &SessionHandle,
    ) -> anyhow::Result<()>;

    /// Load the external handle for `task`, if any was saved.
    async fn load_external_handle(
        &self,
        owner: &str,
        task: &TaskCaseId,
    ) -> anyhow::Result<Option<SessionHandle>>;

    /// Remove the external handle for `task`. Idempotent: deleting an
    /// already-absent handle is not an error.
    async fn delete_external_handle(&self, owner: &str, task: &TaskCaseId) -> anyhow::Result<()>;

    /// Record the last confirmed (durably observed) event marker for
    /// `task`, OCC-guarded like [`Self::update_case`].
    async fn set_last_confirmed_event(
        &self,
        owner: &str,
        task: &TaskCaseId,
        marker: &str,
        expected_revision: u64,
    ) -> anyhow::Result<u64>;

    /// Save an opaque resume checkpoint for `task`, OCC-guarded.
    async fn save_checkpoint(
        &self,
        owner: &str,
        task: &TaskCaseId,
        checkpoint: &serde_json::Value,
        expected_revision: u64,
    ) -> anyhow::Result<u64>;

    /// Load the last saved checkpoint for `task`, if any was ever saved.
    async fn load_checkpoint(
        &self,
        owner: &str,
        task: &TaskCaseId,
    ) -> anyhow::Result<Option<serde_json::Value>>;
}
