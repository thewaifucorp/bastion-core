//! Neutral adaptive-task contract (Adaptive Execution, US-101).
//!
//! Mechanism, not policy: this module defines the owner-scoped, serializable
//! vocabulary the kernel uses to run durable tasks — the three execution
//! modes (`Respond`/`Act`/`Pursue`), the durable [`TaskCase`] record, a
//! concrete [`Attempt`], captured [`Evidence`] and its [`Verdict`], plus the
//! status/stop-reason/budget/correlation machinery.
//!
//! Deliberate boundaries (see `docs/ARCHITECTURE.md` and the core/agent
//! boundary spec):
//!
//! - No NLP heuristics live here. An [`Intent`] arrives with its `mode`
//!   already decided by the consumer; the kernel never classifies text.
//! - No business state. Host-owned domain state is carried opaquely in
//!   [`OpaqueState`] and never interpreted by the kernel.
//! - No graph/DAG. A [`TaskCase`] stores state, evidence and the single
//!   [`NextDecision`]; the next step is recomputed after each observation,
//!   not walked from a persisted plan.
//! - Foreign identities (beliefs, approvals, artifacts) enter only as opaque
//!   reference newtypes so this crate keeps its narrow dependency set
//!   (`bastion-types` + `bastion-agent-runtime`); it never depends on
//!   cognition, memory internals, channels, UX, or any corporate concept.

mod contract;
mod cycle;
mod event;
mod orchestration;
mod ports;
mod sqlite;
mod store;
mod verify;

pub use contract::{
    AcceptanceCriterion, ActionKind, Attempt, Bounds, CandidateAction, CorrelationIds, Evidence,
    EvidenceKind, Frame, Intent, IntentOrigin, NextDecision, OpaqueState, TaskCase, UsageAccum,
    Verdict, VerdictProvenance, VerificationStatus,
};
pub use cycle::AdaptiveCycle;
pub use event::TaskLifecycleEvent;
pub use orchestration::{ChildSummary, Orchestrator};
pub use ports::{ActionOutcome, ChosenStep, Chooser, CycleHistory, TaskExecutor, Verifier};
pub use sqlite::SqliteTaskStore;
pub use store::TaskStore;
pub use verify::LayeredVerifier;

use serde::{Deserialize, Serialize};

/// Which of the three progressive lifecycles a request runs under.
///
/// The cost/latency contract (Gate A) is anchored here: `Respond` never
/// creates a durable record, `Act` may use an ephemeral one, and only
/// `Pursue` requires a durable [`TaskCase`] that survives restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Answer from beliefs/context with no external side effect.
    Respond,
    /// A single bounded effect with no continuity beyond the turn.
    Act,
    /// A durable, resumable objective: multiple dependent effects,
    /// out-of-turn duration, decomposition or adaptation.
    Pursue,
}

impl ExecutionMode {
    /// Only `Pursue` mandates a durable [`TaskCase`]. `Act` MAY persist an
    /// ephemeral record when it needs approval/recovery; `Respond` never does.
    pub fn requires_durable_case(self) -> bool {
        matches!(self, ExecutionMode::Pursue)
    }
}

/// Coarse lifecycle status of a [`TaskCase`]. Terminal variants are the only
/// ones that carry a [`StopReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Running,
    /// Blocked on a pending approval (see [`CorrelationIds`] / `ApprovalRef`).
    AwaitingApproval,
    Paused,
    // --- terminal ---
    Completed,
    Escalated,
    Cancelled,
    Failed,
}

impl TaskStatus {
    /// Terminal states accept no further transition and are the only states
    /// that carry a [`StopReason`].
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskStatus::Completed
                | TaskStatus::Escalated
                | TaskStatus::Cancelled
                | TaskStatus::Failed
        )
    }

    /// Whether a transition `self -> next` is allowed. The store rejects any
    /// transition for which this returns `false` (US-101 acceptance: invalid
    /// transitions are refused). A no-op self-transition is never valid.
    pub fn can_transition_to(self, next: TaskStatus) -> bool {
        use TaskStatus::*;
        match self {
            Pending => matches!(next, Running | Cancelled | Failed),
            Running => matches!(
                next,
                AwaitingApproval | Paused | Completed | Escalated | Cancelled | Failed
            ),
            AwaitingApproval => matches!(next, Running | Cancelled | Failed),
            Paused => matches!(next, Running | Cancelled | Failed),
            // Terminal: no outgoing transitions.
            Completed | Escalated | Cancelled | Failed => false,
        }
    }
}

/// The single, typed reason a task's loop stopped. There is no untyped
/// "done": every terminal status maps to one of these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StopReason {
    /// Verified success.
    Completed,
    /// A declared budget was exhausted.
    BudgetExceeded(BudgetKind),
    /// Owner-initiated cancellation.
    Cancelled,
    /// Parked awaiting a human/approval decision.
    AwaitingApproval,
    /// The objective cannot be achieved; carries a host-supplied reason.
    Impossible(String),
    /// Handed off to a human/other actor; carries a host-supplied reason.
    Escalated(String),
}

/// Which budget dimension was exceeded. Mirrors the enforceable limits on
/// [`Bounds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetKind {
    Steps,
    WallClock,
    Tokens,
    Money,
    Parallelism,
}

// --- Identity & reference newtypes -----------------------------------------
//
// Written out explicitly (not via a macro) so the public-API baseline
// (`scripts/dump-public-api.sh`) records concrete, stable symbol names.

/// Durable, kernel-side identifier of a [`TaskCase`]. This is the correlation
/// anchor; it is distinct from `bastion_agent_runtime::TaskId`, which names a
/// task *inside one external harness session*.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskCaseId(pub String);

/// Identifier of one [`Attempt`] within a [`TaskCase`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(pub String);

/// Identifier of one chosen [`CandidateAction`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub String);

/// Identifier of one captured [`Evidence`] record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceId(pub String);

/// Opaque reference to an artifact held elsewhere (workspace, artifact store).
/// A [`TaskCase`] references artifacts by id; it never inlines their content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactRef(pub String);

/// Opaque reference to a belief owned by the cognition/memory layer. The
/// kernel records which beliefs a decision consulted (for outcome attribution)
/// without depending on the belief store itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BeliefRef(pub String);

/// Opaque reference to a pending-approval row (owned by the `ApprovalGate`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalRef(pub String);

macro_rules! ref_string_impls {
    ($($t:ident),* $(,)?) => {
        $(
            impl $t {
                /// Borrow the underlying string.
                pub fn as_str(&self) -> &str { &self.0 }
            }
            impl core::fmt::Display for $t {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str(&self.0)
                }
            }
            impl From<String> for $t {
                fn from(s: String) -> Self { $t(s) }
            }
        )*
    };
}
ref_string_impls!(
    TaskCaseId,
    AttemptId,
    ActionId,
    EvidenceId,
    ArtifactRef,
    BeliefRef,
    ApprovalRef,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_case() -> TaskCase {
        TaskCase {
            id: TaskCaseId("t1".into()),
            owner: "alice".into(),
            mode: ExecutionMode::Pursue,
            intent: Intent {
                owner: "alice".into(),
                mode: ExecutionMode::Pursue,
                summary: "ship the thing".into(),
                origin: IntentOrigin::Message,
            },
            frame: Frame {
                objective: "green build".into(),
                acceptance: vec![AcceptanceCriterion {
                    description: "tests pass".into(),
                    check: Some("cargo-test".into()),
                }],
                context_refs: vec![ArtifactRef("ctx1".into())],
            },
            bounds: Bounds {
                max_steps: Some(20),
                max_wall_clock_ms: Some(600_000),
                max_tokens: Some(100_000),
                max_cost_usd: Some(1.5),
                max_parallelism: Some(2),
            },
            status: TaskStatus::Running,
            stop_reason: None,
            attempts: vec![AttemptId("a1".into())],
            pending_approvals: vec![],
            next_decision: None,
            usage: UsageAccum::default(),
            parent: None,
            correlation: CorrelationIds::default(),
            business_state: OpaqueState::default(),
            created_at: 1,
            updated_at: 2,
            revision: 1,
        }
    }

    #[test]
    fn valid_transitions_only() {
        assert!(TaskStatus::Pending.can_transition_to(TaskStatus::Running));
        assert!(TaskStatus::Running.can_transition_to(TaskStatus::Completed));
        assert!(TaskStatus::Running.can_transition_to(TaskStatus::AwaitingApproval));
        assert!(TaskStatus::AwaitingApproval.can_transition_to(TaskStatus::Running));
        // No self-transition, no resurrection of terminal states.
        assert!(!TaskStatus::Running.can_transition_to(TaskStatus::Running));
        assert!(!TaskStatus::Completed.can_transition_to(TaskStatus::Running));
        assert!(!TaskStatus::Pending.can_transition_to(TaskStatus::Completed));
    }

    #[test]
    fn terminal_classification() {
        for s in [
            TaskStatus::Completed,
            TaskStatus::Escalated,
            TaskStatus::Cancelled,
            TaskStatus::Failed,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            TaskStatus::Pending,
            TaskStatus::Running,
            TaskStatus::AwaitingApproval,
            TaskStatus::Paused,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn only_pursue_is_durable() {
        assert!(ExecutionMode::Pursue.requires_durable_case());
        assert!(!ExecutionMode::Act.requires_durable_case());
        assert!(!ExecutionMode::Respond.requires_durable_case());
    }

    #[test]
    fn task_case_serde_round_trip() {
        let case = sample_case();
        let json = serde_json::to_string(&case).expect("serialize");
        let back: TaskCase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(case, back);
    }

    #[test]
    fn lifecycle_event_metadata_is_id_only() {
        let ev = TaskLifecycleEvent::Terminal {
            owner: "alice".into(),
            task: TaskCaseId("t1".into()),
            status: TaskStatus::Completed,
            stop_reason: StopReason::Completed,
        };
        assert_eq!(ev.event_name(), "task.terminal");
        assert_eq!(ev.owner(), "alice");
        assert_eq!(ev.task().as_str(), "t1");
        let meta = ev.metadata();
        assert_eq!(meta["owner"], "alice");
        assert_eq!(meta["task"], "t1");
        // Correlatable by owner/task/status; carries no free-text content.
        assert!(meta.get("status").is_some());
        assert!(meta.get("rationale").is_none());
        assert!(meta.get("detail").is_none());
    }
}
