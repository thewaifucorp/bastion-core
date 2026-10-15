//! What a host hands the loop for one turn.

use serde_json::Value;
use std::sync::Arc;

/// One turn, as a host asks for it ([`crate::agent::loop_::AgentLoop::run_turn_with`],
/// [`crate::agent::pool::AgentLoopPool::run_turn`]).
#[derive(Debug, Clone)]
pub struct TurnRequest {
    /// Who the turn is for. Scopes the session, memory, approvals.
    pub owner: String,
    /// The user's message.
    pub input: String,
    /// The session the turn reads and appends to. `None` = the owner's most
    /// recent session (created on first use), the historical
    /// `run_turn_for` behavior. `Some(id)` = the host's own session id: it
    /// is created for `owner` on first use and refused with
    /// `BastionError::SessionOwnerMismatch` if it belongs to someone else.
    pub session_id: Option<String>,
    /// The input comes from an untrusted source (SEC-05): the turn runs
    /// with no capability visible to the model.
    pub untrusted: bool,
    /// Opaque host context carried to every capability the turn dispatches
    /// ([`crate::capability::InvokeCtx::host_context`]). Never read by the
    /// core.
    pub host_context: Option<Arc<Value>>,
}

impl TurnRequest {
    /// A trusted turn for `owner` in their most recent session.
    pub fn new(owner: impl Into<String>, input: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            input: input.into(),
            session_id: None,
            untrusted: false,
            host_context: None,
        }
    }

    /// Run the turn in the host-named session `session_id`.
    pub fn in_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Mark the input as untrusted (or trusted).
    pub fn untrusted(mut self, untrusted: bool) -> Self {
        self.untrusted = untrusted;
        self
    }

    /// Attach the host's opaque per-turn context.
    pub fn with_host_context(mut self, context: Value) -> Self {
        self.host_context = Some(Arc::new(context));
        self
    }
}
