//! Neutral lifecycle events for the adaptive task loop (US-101).
//!
//! These extend the kernel's observability surface without inventing a new
//! bus: each event maps to a stable `event` name plus an id/status-only
//! metadata blob, which is exactly what the existing
//! [`crate::hooks::Observer::record`] contract consumes. Per the PII rule,
//! metadata carries correlation ids and typed statuses only — never prompt
//! text, rationales, verdict detail, or evidence content.

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    ActionId, ApprovalRef, AttemptId, ExecutionMode, StopReason, TaskCaseId, TaskStatus,
    VerificationStatus,
};

/// A point in a task's life worth recording. Every variant is
/// owner/task-correlatable (US-101 acceptance).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskLifecycleEvent {
    Created {
        owner: String,
        task: TaskCaseId,
        mode: ExecutionMode,
    },
    AttemptStarted {
        owner: String,
        task: TaskCaseId,
        attempt: AttemptId,
    },
    ActionChosen {
        owner: String,
        task: TaskCaseId,
        attempt: AttemptId,
        action: ActionId,
    },
    ActionObserved {
        owner: String,
        task: TaskCaseId,
        attempt: AttemptId,
        action: ActionId,
    },
    Verified {
        owner: String,
        task: TaskCaseId,
        attempt: AttemptId,
        status: VerificationStatus,
    },
    Adapted {
        owner: String,
        task: TaskCaseId,
        attempt: AttemptId,
    },
    ApprovalPending {
        owner: String,
        task: TaskCaseId,
        approval: ApprovalRef,
    },
    StatusChanged {
        owner: String,
        task: TaskCaseId,
        status: TaskStatus,
    },
    /// The single terminal event of a task (mirrors the runtime layer's
    /// once-only `Ended` discipline).
    Terminal {
        owner: String,
        task: TaskCaseId,
        status: TaskStatus,
        stop_reason: StopReason,
    },
}

impl TaskLifecycleEvent {
    /// Stable, dotted event name for `Observer::record` and log/OTel keys.
    pub fn event_name(&self) -> &'static str {
        match self {
            TaskLifecycleEvent::Created { .. } => "task.created",
            TaskLifecycleEvent::AttemptStarted { .. } => "task.attempt_started",
            TaskLifecycleEvent::ActionChosen { .. } => "task.action_chosen",
            TaskLifecycleEvent::ActionObserved { .. } => "task.action_observed",
            TaskLifecycleEvent::Verified { .. } => "task.verified",
            TaskLifecycleEvent::Adapted { .. } => "task.adapted",
            TaskLifecycleEvent::ApprovalPending { .. } => "task.approval_pending",
            TaskLifecycleEvent::StatusChanged { .. } => "task.status_changed",
            TaskLifecycleEvent::Terminal { .. } => "task.terminal",
        }
    }

    /// Owner this event belongs to (for owner-scoped routing/filtering).
    pub fn owner(&self) -> &str {
        match self {
            TaskLifecycleEvent::Created { owner, .. }
            | TaskLifecycleEvent::AttemptStarted { owner, .. }
            | TaskLifecycleEvent::ActionChosen { owner, .. }
            | TaskLifecycleEvent::ActionObserved { owner, .. }
            | TaskLifecycleEvent::Verified { owner, .. }
            | TaskLifecycleEvent::Adapted { owner, .. }
            | TaskLifecycleEvent::ApprovalPending { owner, .. }
            | TaskLifecycleEvent::StatusChanged { owner, .. }
            | TaskLifecycleEvent::Terminal { owner, .. } => owner,
        }
    }

    /// The task this event concerns.
    pub fn task(&self) -> &TaskCaseId {
        match self {
            TaskLifecycleEvent::Created { task, .. }
            | TaskLifecycleEvent::AttemptStarted { task, .. }
            | TaskLifecycleEvent::ActionChosen { task, .. }
            | TaskLifecycleEvent::ActionObserved { task, .. }
            | TaskLifecycleEvent::Verified { task, .. }
            | TaskLifecycleEvent::Adapted { task, .. }
            | TaskLifecycleEvent::ApprovalPending { task, .. }
            | TaskLifecycleEvent::StatusChanged { task, .. }
            | TaskLifecycleEvent::Terminal { task, .. } => task,
        }
    }

    /// Id/status-only metadata for `Observer::record`. Contains no free-text
    /// content (PII rule).
    pub fn metadata(&self) -> serde_json::Value {
        let mut meta = json!({
            "owner": self.owner(),
            "task": self.task().as_str(),
        });
        let obj = meta.as_object_mut().expect("json object");
        // Enum fields go through `to_value` (their `Serialize` impl) rather
        // than `json!`, which only accepts `Into<Value>` expressions.
        match self {
            TaskLifecycleEvent::Created { mode, .. } => {
                obj.insert(
                    "mode".into(),
                    serde_json::to_value(mode).unwrap_or(serde_json::Value::Null),
                );
            }
            TaskLifecycleEvent::AttemptStarted { attempt, .. }
            | TaskLifecycleEvent::Adapted { attempt, .. } => {
                obj.insert("attempt".into(), json!(attempt.as_str()));
            }
            TaskLifecycleEvent::ActionChosen {
                attempt, action, ..
            }
            | TaskLifecycleEvent::ActionObserved {
                attempt, action, ..
            } => {
                obj.insert("attempt".into(), json!(attempt.as_str()));
                obj.insert("action".into(), json!(action.as_str()));
            }
            TaskLifecycleEvent::Verified {
                attempt, status, ..
            } => {
                obj.insert("attempt".into(), json!(attempt.as_str()));
                obj.insert(
                    "status".into(),
                    serde_json::to_value(status).unwrap_or(serde_json::Value::Null),
                );
            }
            TaskLifecycleEvent::ApprovalPending { approval, .. } => {
                obj.insert("approval".into(), json!(approval.as_str()));
            }
            TaskLifecycleEvent::StatusChanged { status, .. } => {
                obj.insert(
                    "status".into(),
                    serde_json::to_value(status).unwrap_or(serde_json::Value::Null),
                );
            }
            TaskLifecycleEvent::Terminal {
                status,
                stop_reason,
                ..
            } => {
                obj.insert(
                    "status".into(),
                    serde_json::to_value(status).unwrap_or(serde_json::Value::Null),
                );
                obj.insert(
                    "stop_reason".into(),
                    serde_json::to_value(stop_reason).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        meta
    }
}
