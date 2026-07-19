//! Ports the adaptive cycle drives (US-103/US-104).
//!
//! The cycle is mechanism; *what* to do next, *how* to execute it, and *how*
//! to judge the result are host-supplied through these three seams. Core owns
//! none of the policy: `Chooser` may be an LLM planner, `TaskExecutor` may be
//! the kernel `CapabilityRegistry` or an external `AgentRuntime`, and
//! `Verifier` may be a deterministic check or an LLM judge. Keeping them as
//! ports is what lets the same lifecycle run over a native tool loop, a
//! capability, a delegated harness, or a subagent without the engine changing.

use async_trait::async_trait;

use super::{ApprovalRef, AttemptId, CandidateAction, Evidence, UsageAccum, Verdict};

/// A read-only view of what has happened so far, handed to [`Chooser`] so it
/// can adapt after each observation. Deliberately small — the cycle stores
/// state and the single next decision, never a plan graph.
pub struct CycleHistory<'a> {
    /// The verdict of the most recent attempt, if any.
    pub last_verdict: Option<&'a Verdict>,
    /// How many attempts have run for this task.
    pub attempt_count: u32,
    /// Usage accrued so far (for budget-aware choices).
    pub usage: &'a UsageAccum,
}

/// The outcome of a `Choose` step: either the next action to try, or a typed
/// terminal decision. There is no untyped "give up".
pub enum ChosenStep {
    /// Try this action next.
    Act(CandidateAction),
    /// The chooser believes the objective is met; the engine still requires a
    /// succeeding [`Verdict`] over captured evidence before it will record
    /// `Completed` (US-104: no "done" without proof).
    Complete,
    /// Hand off to a human/other actor; carries a reason.
    Escalate(String),
    /// The objective cannot be achieved; carries a reason.
    Impossible(String),
}

/// Chooses the next step from the current task state. This is where beliefs
/// are consulted; the beliefs actually used must be recorded on the returned
/// [`CandidateAction::belief_refs`] for outcome attribution (US-105).
#[async_trait]
pub trait Chooser: Send + Sync {
    async fn choose(
        &self,
        case: &super::TaskCase,
        history: &CycleHistory<'_>,
    ) -> anyhow::Result<ChosenStep>;
}

/// What one executed action produced. The executor never decides success —
/// it reports observations; [`Verifier`] judges them.
pub struct ActionOutcome {
    /// Evidence captured while executing (by reference; no secrets).
    pub evidence: Vec<Evidence>,
    /// Usage this action consumed, taken from provider/runtime events.
    pub usage: UsageAccum,
    /// Set when the action could not proceed without a human approval; the
    /// cycle parks the task in `AwaitingApproval` rather than looping.
    pub pending_approval: Option<ApprovalRef>,
}

/// Executes a [`CandidateAction`]. Implemented by the host over the
/// `CapabilityRegistry`, an `AgentRuntime`, a native tool loop or a subagent.
/// Every external effect still crosses capability/approval/egress inside the
/// implementation — the engine assumes that boundary is enforced here.
#[async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute(
        &self,
        action: &CandidateAction,
        case: &super::TaskCase,
    ) -> anyhow::Result<ActionOutcome>;

    /// Best-effort cancellation of any in-flight work for this task, so a
    /// cancelled task never leaves an orphaned runtime. Default: nothing to
    /// cancel.
    async fn cancel(&self, _case: &super::TaskCase) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Judges an attempt's evidence into a [`Verdict`]. US-104 requires
/// deterministic verification (exit status/schema/receipt) to be tried before
/// any LLM judge; a `Verifier` implementation orders that internally and
/// records the [`super::VerdictProvenance`] it used.
#[async_trait]
pub trait Verifier: Send + Sync {
    async fn verify(
        &self,
        case: &super::TaskCase,
        attempt: &AttemptId,
        evidence: &[Evidence],
    ) -> anyhow::Result<Verdict>;
}
