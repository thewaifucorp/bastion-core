//! Data contract for the adaptive task lifecycle (US-101).
//!
//! Every type here is owner-scoped and serializable. Timestamps are
//! nanoseconds since the Unix epoch (`i64`), matching the session store
//! convention; the durable store (US-102) stamps them.

use bastion_agent_runtime::BudgetCoverage;
use bastion_types::PrivacyTier;
use serde::{Deserialize, Serialize};

use super::{
    ActionId, ApprovalRef, ArtifactRef, AttemptId, BeliefRef, BudgetKind, EvidenceId,
    ExecutionMode, StopReason, TaskCaseId, TaskStatus,
};

/// A request/objective as handed to the kernel. The `mode` is already decided
/// by the consumer (no NLP in the kernel); `summary` is an opaque,
/// host-authored description the kernel never parses for control decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Intent {
    pub owner: String,
    pub mode: ExecutionMode,
    pub summary: String,
    pub origin: IntentOrigin,
}

/// Where an [`Intent`] came from. All three route through the same lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentOrigin {
    Message,
    Event,
    Schedule,
}

/// The framing of a `Pursue`: what "done" means and which references bound the
/// work. Context enters by reference, never as an inline dump.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    /// Opaque, host-owned objective description.
    pub objective: String,
    /// What must hold for the task to be considered succeeded.
    pub acceptance: Vec<AcceptanceCriterion>,
    /// Inputs/context supplied by reference.
    pub context_refs: Vec<ArtifactRef>,
}

/// One acceptance condition. `check` names a host-registered verifier (or a
/// deterministic check); the kernel does not interpret `description`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceCriterion {
    pub description: String,
    /// Identifier of the verifier that decides this criterion, when a
    /// deterministic/programmatic check applies. `None` defers to judgement
    /// (US-104 orders deterministic checks before any LLM judge).
    pub check: Option<String>,
}

/// The enforceable limits of a task. A violated limit yields a typed
/// [`StopReason::BudgetExceeded`] — never a silent loop.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct Bounds {
    pub max_steps: Option<u32>,
    pub max_wall_clock_ms: Option<u64>,
    pub max_tokens: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub max_parallelism: Option<u32>,
}

/// A typed next action produced by `Choose`. Execution (US-103) routes it
/// through the `CapabilityRegistry` or a declared `AgentRuntime`; the beliefs
/// consulted are recorded for outcome attribution (US-105).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateAction {
    pub id: ActionId,
    pub kind: ActionKind,
    /// Host-authored justification. Kept out of lifecycle events (PII rule).
    pub rationale: String,
    /// Beliefs consulted when choosing this action (opaque refs).
    pub belief_refs: Vec<BeliefRef>,
}

/// What a [`CandidateAction`] does. Deliberately small in US-101; execution
/// wiring and parent/child delegation are refined in US-103/US-106.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ActionKind {
    /// Invoke a kernel capability by name with opaque JSON args.
    Capability {
        name: String,
        args: serde_json::Value,
    },
    /// Delegate to a registered external `AgentRuntime`.
    Runtime {
        runtime_id: String,
        input_ref: ArtifactRef,
    },
    /// Produce a response (the `Respond` terminal action).
    Respond,
    /// Spawn a child task (provenance/control only — never a scheduling
    /// graph). The child is itself a [`TaskCase`]; this carries its id.
    Delegate { child: TaskCaseId },
}

/// Proof of an outcome. Evidence references where the proof lives; it never
/// carries secrets (cookies/credentials/session tokens are excluded by
/// construction — see US-204).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub attempt: AttemptId,
    pub action: Option<ActionId>,
    pub kind: EvidenceKind,
    /// Where the proof is stored.
    pub source_ref: ArtifactRef,
    /// `false` for content from untrusted surfaces (page DOM, vision, model
    /// output). Untrusted evidence never confers authority.
    pub trusted: bool,
    /// Upper privacy tier this evidence may cross (egress bound).
    pub max_tier: Option<PrivacyTier>,
    /// Nanoseconds since the Unix epoch.
    pub captured_at: i64,
}

/// Class of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    ExitStatus,
    TestResult,
    Schema,
    Receipt,
    Diff,
    Artifact,
    /// A recorded observation (e.g. a browser snapshot digest).
    Observation,
    Other,
}

/// Where a [`Verdict`] came from. US-104 requires deterministic sources to be
/// tried before any LLM judge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerdictProvenance {
    /// Decided by a deterministic check (exit status, schema, receipt).
    Deterministic,
    /// Decided by a named, host-registered verifier.
    Verifier(String),
    /// Decided by an LLM judge — recorded with the model used.
    LlmJudge { model: String },
}

/// Whether an outcome met its acceptance criteria. There is no `succeeded`
/// without backing evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Not (yet) verifiable.
    Unverified,
    Failed,
    Partial,
    Succeeded,
}

/// The evaluation of one attempt's result, with provenance and the evidence
/// it rests on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub attempt: AttemptId,
    pub status: VerificationStatus,
    pub provenance: VerdictProvenance,
    pub evidence: Vec<EvidenceId>,
    /// Host-authored detail; excluded from lifecycle events.
    pub detail: Option<String>,
}

/// Accumulated cost/usage for a task or attempt, aggregated from
/// provider/runtime events already emitted — never from an extra model call.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UsageAccum {
    pub llm_calls: u32,
    pub steps: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: Option<f64>,
    /// Fidelity of `cost_usd`/token figures as declared by the source.
    #[serde(default = "default_coverage")]
    pub cost_coverage: BudgetCoverage,
    pub wall_clock_ms: u64,
}

fn default_coverage() -> BudgetCoverage {
    BudgetCoverage::Unknown
}

// `BudgetCoverage` has no `Default`, so `UsageAccum`'s is written out rather
// than derived; a fresh accumulator has no usage and `Unknown` fidelity.
impl Default for UsageAccum {
    fn default() -> Self {
        UsageAccum {
            llm_calls: 0,
            steps: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cost_usd: None,
            cost_coverage: BudgetCoverage::Unknown,
            wall_clock_ms: 0,
        }
    }
}

impl UsageAccum {
    /// Fold an incremental provider/runtime usage delta into the accumulator.
    pub fn add_tokens(&mut self, input: u64, output: u64) {
        self.input_tokens = self.input_tokens.saturating_add(input);
        self.output_tokens = self.output_tokens.saturating_add(output);
    }
}

/// One concrete attempt at a task: the actions it chose, the beliefs it
/// consulted, the usage it accrued and its (optional, until terminal) verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attempt {
    pub id: AttemptId,
    pub task: TaskCaseId,
    /// Nanoseconds since the Unix epoch.
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub actions: Vec<ActionId>,
    /// Beliefs actually used in this attempt's decisions (US-105 attribution).
    pub belief_refs: Vec<BeliefRef>,
    pub usage: UsageAccum,
    pub verdict: Option<Verdict>,
}

/// The one thing `Adapt` writes: the next action to try and why. A [`TaskCase`]
/// stores *this*, not a persisted plan — the next step is recomputed after
/// each observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NextDecision {
    pub action: CandidateAction,
    pub justification: String,
}

/// Host-owned domain state, carried opaquely. The kernel serializes and
/// persists it but never interprets it (Gate D: no business state in Core).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct OpaqueState(pub serde_json::Value);

/// The correlation anchors stamped on every lifecycle event so a task,
/// attempt, action and trace can be joined across surfaces and products.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CorrelationIds {
    pub attempt: Option<AttemptId>,
    pub action: Option<ActionId>,
    /// OpenTelemetry trace id, when a span is active.
    pub trace: Option<String>,
    /// Id of the event that caused this one.
    pub causation: Option<String>,
    /// Cross-product correlation id.
    pub correlation: Option<String>,
}

/// The durable record of a `Pursue`. Survives restart; references artifacts,
/// evidence and beliefs by id rather than storing their content. Holds the
/// current [`NextDecision`], not a plan graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskCase {
    pub id: TaskCaseId,
    pub owner: String,
    pub mode: ExecutionMode,
    pub intent: Intent,
    pub frame: Frame,
    pub bounds: Bounds,
    pub status: TaskStatus,
    /// Set only once the task reaches a terminal status.
    pub stop_reason: Option<StopReason>,
    /// Attempts are stored separately; the case references them by id.
    pub attempts: Vec<AttemptId>,
    pub pending_approvals: Vec<ApprovalRef>,
    /// The single recomputed next step (absent when terminal or awaiting).
    pub next_decision: Option<NextDecision>,
    pub usage: UsageAccum,
    /// Provenance link only — never a scheduling edge.
    pub parent: Option<TaskCaseId>,
    pub correlation: CorrelationIds,
    pub business_state: OpaqueState,
    /// Nanoseconds since the Unix epoch.
    pub created_at: i64,
    pub updated_at: i64,
    /// Monotonic revision for optimistic concurrency in the durable store.
    pub revision: u64,
}

impl TaskCase {
    /// Whether this case has reached a terminal status.
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Convenience: does the current mode mandate durable persistence?
    pub fn requires_durable_case(&self) -> bool {
        self.mode.requires_durable_case()
    }

    /// Map an exceeded budget dimension onto a terminal [`StopReason`].
    pub fn budget_stop(kind: BudgetKind) -> StopReason {
        StopReason::BudgetExceeded(kind)
    }
}
