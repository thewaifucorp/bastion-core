//! US-106 — parent/child task orchestration over the durable store.
//!
//! Delegation is provenance and control, never a scheduling graph. A parent
//! spawns children as ordinary [`TaskCase`]s that carry a `parent` link;
//! the [`Orchestrator`] lets the parent list, cancel and aggregate them.
//! Each child is an independent case, so one child's failure or conflict
//! never corrupts its siblings or the parent — the concurrency, budget and
//! capability grants per child are the host's decision (US-206); this layer
//! only supervises.
//!
//! The heavy per-session machinery (concurrent sessions, cancel, steer,
//! resume, artifact/usage/permission/terminal events, sandbox/approval
//! coverage) already lives on the `bastion-agent-runtime` `AgentRuntime`
//! contract; this module adds the durable parent/child supervision on top of
//! it rather than duplicating it.

use std::sync::Arc;

use super::store::TaskStore;
use super::{StopReason, TaskCase, TaskCaseId, TaskStatus};

/// Rollup of a parent's children by terminal outcome, so a parent can verify
/// on the aggregation without hiding divergence (failures are counted).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChildSummary {
    pub total: usize,
    pub succeeded: usize,
    /// Failed, escalated or cancelled — any non-success terminal.
    pub failed: usize,
    /// Not yet terminal.
    pub in_flight: usize,
}

/// Supervises the children of a parent task over a [`TaskStore`].
pub struct Orchestrator {
    store: Arc<dyn TaskStore>,
}

impl Orchestrator {
    pub fn new(store: Arc<dyn TaskStore>) -> Self {
        Self { store }
    }

    /// Register `child` under `parent`. The child must share the parent's
    /// owner and carry `parent.id` as its parent link — a child can never be
    /// grafted across owners. Idempotent on `idempotency_key`.
    pub async fn spawn_child(
        &self,
        parent: &TaskCase,
        child: &TaskCase,
        idempotency_key: &str,
    ) -> anyhow::Result<()> {
        if child.owner != parent.owner {
            anyhow::bail!("spawn_child: child owner must match parent owner");
        }
        if child.parent.as_ref() != Some(&parent.id) {
            anyhow::bail!("spawn_child: child.parent must reference the parent case");
        }
        self.store.create_case(child, idempotency_key).await
    }

    /// The children of `parent`, oldest first.
    pub async fn children(
        &self,
        owner: &str,
        parent: &TaskCaseId,
    ) -> anyhow::Result<Vec<TaskCase>> {
        self.store.list_children(owner, parent).await
    }

    /// Cancel every non-terminal child of `parent`, cascading a parent
    /// cancellation. Terminal children and the evidence they produced are left
    /// untouched — cancellation preserves work already done. A sibling that is
    /// already terminal (or races to terminal) never blocks cancelling the
    /// rest. Returns how many children were cancelled.
    pub async fn cancel_children(&self, owner: &str, parent: &TaskCaseId) -> anyhow::Result<usize> {
        let children = self.store.list_children(owner, parent).await?;
        let mut cancelled = 0;
        for c in children {
            if c.status.is_terminal() {
                continue;
            }
            // Best-effort per child: one child's revision conflict must not
            // abort the sweep of its siblings.
            if self
                .store
                .transition_status(
                    owner,
                    &c.id,
                    TaskStatus::Cancelled,
                    Some(StopReason::Cancelled),
                    c.revision,
                )
                .await
                .is_ok()
            {
                cancelled += 1;
            }
        }
        Ok(cancelled)
    }

    /// Aggregate children by terminal outcome for parent-side verification.
    pub async fn summarize_children(
        &self,
        owner: &str,
        parent: &TaskCaseId,
    ) -> anyhow::Result<ChildSummary> {
        let children = self.store.list_children(owner, parent).await?;
        let mut s = ChildSummary::default();
        for c in &children {
            s.total += 1;
            match c.status {
                TaskStatus::Completed => s.succeeded += 1,
                TaskStatus::Failed | TaskStatus::Escalated | TaskStatus::Cancelled => s.failed += 1,
                _ => s.in_flight += 1,
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::*;
    use tempfile::NamedTempFile;

    fn case(id: &str, owner: &str, parent: Option<&str>) -> TaskCase {
        TaskCase {
            id: TaskCaseId(id.into()),
            owner: owner.into(),
            mode: ExecutionMode::Pursue,
            intent: Intent {
                owner: owner.into(),
                mode: ExecutionMode::Pursue,
                summary: String::new(),
                origin: IntentOrigin::Message,
            },
            frame: Frame {
                objective: String::new(),
                acceptance: vec![],
                context_refs: vec![],
            },
            bounds: Bounds::default(),
            status: TaskStatus::Running,
            stop_reason: None,
            attempts: vec![],
            pending_approvals: vec![],
            next_decision: None,
            usage: UsageAccum::default(),
            parent: parent.map(|p| TaskCaseId(p.into())),
            correlation: CorrelationIds::default(),
            business_state: OpaqueState::default(),
            created_at: 0,
            updated_at: 0,
            revision: 1,
        }
    }

    async fn store() -> (NamedTempFile, Arc<SqliteTaskStore>) {
        let f = NamedTempFile::new().unwrap();
        let s = SqliteTaskStore::new(f.path().to_str().unwrap());
        s.init_schema().await.unwrap();
        (f, Arc::new(s))
    }

    #[tokio::test]
    async fn spawn_list_and_summarize_children() {
        let (_f, s) = store().await;
        let orch = Orchestrator::new(s.clone());
        let parent = case("p", "alice", None);
        s.create_case(&parent, "kp").await.unwrap();

        orch.spawn_child(&parent, &case("c1", "alice", Some("p")), "k1")
            .await
            .unwrap();
        orch.spawn_child(&parent, &case("c2", "alice", Some("p")), "k2")
            .await
            .unwrap();

        let kids = orch.children("alice", &parent.id).await.unwrap();
        assert_eq!(kids.len(), 2);

        // one child completes, one stays running
        s.transition_status(
            "alice",
            &TaskCaseId("c1".into()),
            TaskStatus::Completed,
            Some(StopReason::Completed),
            1,
        )
        .await
        .unwrap();
        let sum = orch.summarize_children("alice", &parent.id).await.unwrap();
        assert_eq!(sum.total, 2);
        assert_eq!(sum.succeeded, 1);
        assert_eq!(sum.in_flight, 1);
    }

    #[tokio::test]
    async fn cross_owner_child_is_rejected() {
        let (_f, s) = store().await;
        let orch = Orchestrator::new(s.clone());
        let parent = case("p", "alice", None);
        s.create_case(&parent, "kp").await.unwrap();
        let foreign = case("c1", "bob", Some("p"));
        assert!(orch.spawn_child(&parent, &foreign, "k1").await.is_err());
    }

    #[tokio::test]
    async fn cancel_children_skips_terminal_and_cancels_rest() {
        let (_f, s) = store().await;
        let orch = Orchestrator::new(s.clone());
        let parent = case("p", "alice", None);
        s.create_case(&parent, "kp").await.unwrap();
        orch.spawn_child(&parent, &case("c1", "alice", Some("p")), "k1")
            .await
            .unwrap();
        orch.spawn_child(&parent, &case("c2", "alice", Some("p")), "k2")
            .await
            .unwrap();
        // c1 already terminal (completed) — must be left untouched.
        s.transition_status(
            "alice",
            &TaskCaseId("c1".into()),
            TaskStatus::Completed,
            Some(StopReason::Completed),
            1,
        )
        .await
        .unwrap();

        let cancelled = orch.cancel_children("alice", &parent.id).await.unwrap();
        assert_eq!(cancelled, 1, "only the non-terminal child is cancelled");

        let sum = orch.summarize_children("alice", &parent.id).await.unwrap();
        assert_eq!(sum.succeeded, 1);
        assert_eq!(sum.failed, 1, "cancelled counts as a non-success terminal");
        assert_eq!(sum.in_flight, 0);
    }
}
