use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub mod secret;
pub use secret::{NullSecretResolver, SecretRef, SecretResolver, SecretValue};

pub mod context_artifact;
pub use context_artifact::{ContextRevision, StalePolicy, VersionedContextArtifact};

pub mod deployment;
pub use deployment::{
    DeploymentContext, DeploymentMode, EffectAudit, EffectContext, PolicyDecision,
    PolicyDisposition,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: MessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    Tool,
    System,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Assistant => write!(f, "assistant"),
            Role::Tool => write!(f, "tool"),
            Role::System => write!(f, "system"),
        }
    }
}

impl FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Role::User),
            "assistant" => Ok(Role::Assistant),
            "tool" => Ok(Role::Tool),
            "system" => Ok(Role::System),
            other => anyhow::bail!("unknown role: {}", other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
        /// Opaque, provider-specific metadata tied to this tool call — e.g. Gemini's
        /// `extra_content.google.thought_signature` (SO-05). Never interpreted by
        /// Bastion core: stored and re-serialized verbatim on history replay only.
        /// Every provider besides Gemini leaves this `None` and ignores it entirely.
        #[serde(default)]
        extra: Option<serde_json::Value>,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
    /// Opaque, provider-specific metadata (mirrors `ContentPart::ToolUse.extra`) —
    /// copied through 1:1 when a `ToolCall` becomes a `ContentPart::ToolUse` on
    /// history persistence (`src/agent/loop_.rs`). Data, never instructions.
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read: u32,
    pub cache_write: u32,
    /// Real, provider-reported per-request cost in USD, when the provider's own API
    /// exposes one (e.g. OpenRouter's `usage.cost`). `None` when the provider never
    /// reports a cost field (Anthropic/OpenAI/Groq/Gemini/Ollama) — `estimate_cost_usd`
    /// (`src/agent/loop_.rs`) falls back to a hardcoded per-provider table in that case
    /// (SEC-02). Never (de)serialized — no `#[serde]` attribute needed.
    pub actual_cost_usd: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub text: String,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub usage: TokenUsage,
}

/// How a provider call should resolve tool selection (D-01/D-09 unification).
///
/// `Forced(String)` carries the target tool/capability name — either a real MCP tool
/// name or the sentinel `"__structured_output"` (Plan 08-03's forced-tool-call helper
/// for providers that don't support `response_format` natively, see
/// `Provider::supports_json_schema`). This is pure request-shaping data: it carries no
/// capability-registry lookup or invocation logic itself (that dispatch lives in the
/// provider `complete()` impls and Plan 08-03).
#[derive(Debug, Clone, PartialEq)]
pub enum ToolChoice {
    /// Provider decides whether/which tool to call (today's implicit default).
    Auto,
    /// Provider must call some tool, but may choose which one.
    Required,
    /// Provider must call the named tool specifically.
    Forced(String),
}

#[derive(Debug, Clone)]
pub struct CallConfig {
    pub system_prompt: String,
    pub max_tokens: u32,
    pub tools: Vec<serde_json::Value>,
    /// JSON-schema payload for a structured-output request. `None` = no structured
    /// output requested. Replaces the schema argument `complete_structured` used to
    /// take positionally (D-01 unification, removed in Plan 08-09).
    pub response_format: Option<serde_json::Value>,
    /// Forces (or requires/leaves auto) tool selection for this call. `None` =
    /// provider default/auto — unchanged behavior from today.
    pub tool_choice: Option<ToolChoice>,
    /// Per-call sampling temperature override. `None` = provider's own hardcoded
    /// default (unchanged from today). `complete_structured`'s removed overrides all
    /// took an explicit `temperature: f32` argument that must not silently vanish
    /// once callers migrate to `CallConfig.temperature` (Plan 08-07).
    pub temperature: Option<f32>,
}

impl Default for CallConfig {
    fn default() -> Self {
        Self {
            system_prompt: String::new(),
            max_tokens: 4096,
            tools: vec![],
            response_format: None,
            tool_choice: None,
            temperature: None,
        }
    }
}

/// The two concrete production-failure signals the eval regression-capture
/// mechanism wires (EVAL-01). Deliberately scoped — no LLM-judge rubric was
/// designed for a broader failure taxonomy. Moved here from
/// `src/eval/capture.rs` (M2 P2 — `FailureSink` port): this is vocabulary
/// shared across the kernel/product boundary, not capture logic itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Contestation,
    EgressReject,
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FailureKind::Contestation => write!(f, "contestation"),
            FailureKind::EgressReject => write!(f, "egress_reject"),
        }
    }
}

/// Privacy tier consumed by persona/soul.rs (plan 03) and hooks/egress.rs (plan 04).
/// Moved here from `src/memory/mod.rs` (M2 3b — vocabulary shared across the
/// kernel/product boundary, not memory-store logic itself; see
/// `docs/revamp/LOOP-REPORT.md` finding #2).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyTier {
    LocalOnly,
    CloudOk,
}

/// A persisted goal row (GOAL-01). Moved here from `src/goal/mod.rs` (M2 3b —
/// plain data/vocabulary; `GoalEngine` and its SQL-backed impls stay in
/// `src/goal/mod.rs`, see `docs/revamp/LOOP-REPORT.md` finding #2).
#[derive(Debug, Clone, Serialize)]
pub struct Goal {
    pub id: i64,
    pub owner_id: String,
    pub description: String,
    pub metric: Option<String>,
    pub deadline: Option<i64>,
    pub guardian_persona: Option<String>,
    pub last_confirmed: Option<i64>,
}

/// Belief kind — factual (default, Phase 1-6 behavior) or procedural (LEARN-01).
/// Defaults to `Factual` so every pre-Phase-7 row (DB default `'factual'`) decodes
/// identically to before this column existed — zero behavior change for existing data.
///
/// Moved here from `src/memory/mod.rs` (M2 3b, decision D1 — pure data in the
/// `Memory` trait's signatures; the trait itself lives in `bastion-runtime`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BeliefKind {
    #[default]
    Factual,
    Procedural,
}

/// Outcome signal for a procedural belief's helpful/harmful/neutral counters.
/// Maps 1:1 onto `record_belief_outcome`'s counter-increment column choice.
/// Moved here from `src/memory/mod.rs` (M2 3b, decision D1).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Helpful,
    Harmful,
    Neutral,
}

/// Builder-style draft for a new procedural belief. Used by `store_procedural_belief`
/// instead of widening `store_belief`'s already-7-argument signature (Pitfall 5).
/// `insight` maps onto the existing `content` column (ACE terminology overlay) —
/// there is no parallel content field.
/// Moved here from `src/memory/mod.rs` (M2 3b, decision D1).
pub struct BeliefDraft {
    pub owner_id: String,
    pub persona_tag: Option<String>,
    pub issue: Option<String>,
    pub insight: String,
    pub keywords: Vec<String>,
    pub session_id: String,
    pub source: String,
    pub tier: Option<PrivacyTier>,
}

/// A queued, metadata-only "this belief needs a corrected re-learn" signal (LEARN-04
/// edit half). NEVER carries raw correction text — content lives only in the
/// tier-gated life-log/OTel stream the Reflector (07-05) already reads; this row
/// only points at WHICH belief and WHAT tier.
/// Moved here from `src/memory/mod.rs` (M2 3b, decision D1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCorrection {
    pub id: i64,
    pub belief_id: i64,
    pub owner_id: String,
    pub tier: Option<PrivacyTier>,
    pub created_at: i64,
}

/// A retrieved belief (read-only view of the beliefs table row).
/// Moved here from `src/memory/mod.rs` (M2 3b, decision D1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Belief {
    pub id: i64,
    pub owner_id: String,
    pub persona_tag: Option<String>,
    pub content: String,
    pub weight: f64,
    pub is_core: bool,
    /// Privacy tier — None if column absent or unset in DB (treated as LocalOnly by egress gate).
    pub tier: Option<PrivacyTier>,
    /// Factual (default) or procedural (LEARN-01). Never `Option` — decodes to
    /// `Factual` on NULL/unrecognized column value, matching the SQL `DEFAULT 'factual'`.
    pub kind: BeliefKind,
    /// Procedural skill-matching tags. Empty vec on NULL or malformed JSON — never panics.
    pub keywords: Vec<String>,
    /// The problem/context a procedural belief addresses (ACE "issue" terminology).
    pub issue: Option<String>,
    pub helpful_count: i64,
    pub harmful_count: i64,
    pub neutral_count: i64,
    /// Start of this belief's valid-time window (bi-temporal, MEM-01/D-11).
    /// `None` means open from the beginning of time — permissive.
    pub valid_from: Option<i64>,
    /// End of this belief's valid-time window (bi-temporal, MEM-01/D-11). `None`
    /// means open/no-expiry — a PERMISSIVE convention that deliberately diverges
    /// from `tier: Option<PrivacyTier>` 15 lines above in this same struct, whose
    /// `None` is treated as deny-on-ambiguity by the egress gate. Do NOT "fix" this
    /// field by analogy to `tier`'s convention — NULL here means valid, not denied.
    pub valid_until: Option<i64>,
    /// Id of the belief that superseded this one, if any (soft-supersession, D-11).
    /// `None` means this belief has not been superseded.
    pub superseded_by: Option<i64>,
    /// Timestamp (nanos) at which this belief was superseded, if any.
    pub supersedes_at: Option<i64>,
}

/// A single persona's dissenting stance (Cabinet synthesis, CAB-05/D-07).
/// Moved here from `src/cabinet/synth.rs` (M2 step 5) — pure `JsonSchema`-deriving
/// data referenced by `bastion-providers`' ollama.rs GBNF-diagnostic test, which
/// must not depend on the product-level Cabinet synthesis logic itself.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Dissent {
    /// Name of the dissenting persona.
    pub persona: String,
    /// The position that differs from the recommendation.
    pub position: String,
}

/// The unified output of Cabinet synthesis.
///
/// `dissents` is a REQUIRED field (not Option) — the LLM is instructed to populate it
/// whenever any persona's position diverged from the recommendation. Callers must never
/// treat an empty `dissents` as proof of consensus; they should inspect the transcript.
/// Moved here from `src/cabinet/synth.rs` (M2 step 5, same rationale as [`Dissent`]).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CabinetVerdict {
    /// The Cabinet's unified recommendation (single voice).
    pub recommendation: String,
    /// Explicit dissenting positions. Empty only when ALL personas were aligned.
    pub dissents: Vec<Dissent>,
}

/// Canonical persona identifier — a `String` alias for readability at call
/// sites (`Turn.persona`, `RunnerOutput` tags). Moved here from
/// `src/persona/runner.rs` (M2 step 6) — a zero-cost alias referenced by
/// `bastion-cognition`'s Cabinet (`Turn.persona`, `orchestrator.rs`'s JoinSet
/// tagging) without pulling in the `bastion-personas` crate. `persona::runner`
/// re-exports it under the old path.
pub type PersonaId = String;

/// A loaded persona ready for execution. Moved here from `src/persona/mod.rs`
/// (M2 step 6) — pure data (no I/O, no registry lookup logic) referenced by
/// `bastion-cognition`'s Cabinet (`CabinetTable.personas`, `build_table`)
/// without pulling in the `bastion-personas` crate (which owns `PersonaRegistry`,
/// the behavior-bearing type `build_table` no longer needs directly — see
/// `cabinet::build_table`'s `lookup` closure param). `persona::mod` re-exports
/// this under the old path.
#[derive(Debug, Clone, Serialize)]
pub struct Persona {
    /// Canonical persona identifier (matches the directory name / SOUL.md `name` field).
    pub name: String,
    /// Human-readable description from SOUL.md `description:`.
    pub description: Option<String>,
    /// The markdown body of the SOUL.md — used as the LLM system prompt.
    pub system_prompt: String,
    /// Privacy tier: controls which provider backend may process this persona's context.
    pub tier: PrivacyTier,
    /// Routing weight — higher-weight personas are preferred by the router for their domain.
    pub weight: f32,
    /// Declared skill tags (from SOUL.md `skills:`).
    pub skills: Vec<String>,
}

/// Router mode for a turn — Single/Parallel persona dispatch, or convene the
/// Cabinet. Moved here from `src/persona/router.rs` (M2 step 6) — pure
/// `JsonSchema`-deriving data (the router's structured-output schema target)
/// referenced by `bastion-cognition`'s Cabinet (`build_table`'s `RouterDecision`
/// param) without pulling in `bastion-personas`. `persona::router` re-exports
/// it under the old path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Single,
    Parallel,
    Cabinet,
}

/// Why the Cabinet was convened for this turn (GOAL-04 / D-06). Moved here
/// from `src/persona/router.rs` (M2 step 6), same rationale as [`ResponseMode`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConveneReason {
    HighWeight,
    MultiDomainConflict,
    GoalImpact,
    ManualOverride,
}

/// The router's classification of one turn — VERBATIM from spec §2 / AI-SPEC
/// §4b. Moved here from `src/persona/router.rs` (M2 step 6), same rationale as
/// [`ResponseMode`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouterDecision {
    /// PersonaId values to invoke.
    pub personas: Vec<String>,
    /// OwnerId (MESH-ready, multi-owner-aware).
    pub owner: String,
    pub mode: ResponseMode,
    /// Some(..) only when mode == Cabinet.
    pub convene_reason: Option<ConveneReason>,
}

/// Config section for the agent's model/budget settings. Moved here from
/// `src/config.rs` (M2 step 6) — pure `Deserialize` data referenced by
/// `bastion-mesh`'s `interop::export::{export_full, export_template}`
/// (`ConfigBlock::from_config`), which must not depend on the product-level
/// config module. `src/config.rs` re-exports this under its old path so
/// `BastionConfig.agent` keeps compiling unchanged.
#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub default_model: String,
    pub daily_budget_usd: f64,
    /// D-11: ordered list of model-name strings, using the same naming convention
    /// `resolve_provider()` (src/provider/registry.rs) already accepts (e.g.
    /// `"groq/llama-3.1-8b-instant"`, `"gemini-2.0-flash"`). Tried in order when the
    /// primary provider suffers a hard/persistent failure (SO-03/D-10 rung 3, wired
    /// in Plan 08-08). Empty = no provider-switching (today's exact behavior).
    #[serde(default)]
    pub fallback_models: Vec<String>,
}

/// A single `[mcp.servers.*]` entry from `bastion.toml`. Moved here from
/// `src/config.rs` (M2 step 5) — pure `Deserialize` data referenced by
/// `bastion-mcp`'s `McpClient::connect_from_config`, which must not depend
/// on the product-level config module (`src/config.rs` stays in the app
/// crate; it re-exports this type under its old path).
#[derive(Debug, Deserialize, Clone)]
pub struct McpServerEntry {
    pub url: String,
    pub label: String,
    /// Operator-controlled, typed locality flag (Plan 10-08 / T-10-08-01,02,03).
    ///
    /// Defaults to `false` (`#[serde(default)]`) so every EXISTING `[mcp.servers.*]`
    /// entry (memupalace, skill-writer, self-improving, content) is unaffected without
    /// any bastion.toml edit — only a server that EXPLICITLY opts in (e.g. the voice
    /// sidecar, Plan 10-03/10-09) gets its tools classified as local capabilities.
    /// This is a TRUST-BOUNDARY setting: only set `true` on a server that genuinely
    /// never sends data off-host — see 10-08-PLAN.md's threat register (T-10-08-01).
    #[serde(default)]
    pub is_local: bool,
    /// Operator-controlled trust flag (Plan 11-04 / SEC-01), mirroring `is_local`'s
    /// exact shape and default.
    ///
    /// Defaults to `false` (`#[serde(default)]`) so every EXISTING `[mcp.servers.*]`
    /// entry is unaffected without any bastion.toml edit — only a server the operator
    /// EXPLICITLY vouches for gets this set `true`. This is a TRUST-BOUNDARY setting:
    /// it is threaded through the same registration pipeline as `is_local` (config ->
    /// `ToolRegistry::is_trusted()` -> `McpToolAdapter.trusted_override`) but is not
    /// yet consumed by any policy decision in this plan — Plans 11-07 (spotlighting)
    /// and 11-08 (quarantine) are the intended consumers of an operator-marked-trusted
    /// server as their escape hatch (D-09).
    #[serde(default)]
    pub trusted: bool,
}

/// Status of a queued approval row (SEC-01). Moved here from
/// `bastion-runtime`'s `capability/approval.rs` (Ciclo 2.1,
/// `docs/revamp/C2-approval-port-design.md` §1) — pure vocabulary shared by
/// the `ApprovalGate` port and any future consumer/adapter. TEXT-encoded in
/// sqlite (app-layer enum, mirrors `Belief`'s `kind`/`tier` TEXT-enum
/// convention rather than a SQL CHECK constraint); the encode/decode helpers
/// below are pure string mapping, not SQLite logic — the actual
/// `rusqlite::Connection` I/O stays in `SqliteApprovalGate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl ApprovalStatus {
    pub fn to_sql_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Rejected => "rejected",
            ApprovalStatus::Expired => "expired",
        }
    }

    pub fn from_sql_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "pending" => Ok(ApprovalStatus::Pending),
            "approved" => Ok(ApprovalStatus::Approved),
            "rejected" => Ok(ApprovalStatus::Rejected),
            "expired" => Ok(ApprovalStatus::Expired),
            other => anyhow::bail!("unknown approval_queue.status value: {other}"),
        }
    }
}

/// A single row of the `approval_queue` table (schema from Plan 11-01).
/// Moved here from `bastion-runtime`'s `capability/approval.rs` (Ciclo 2.1) —
/// same rationale as [`ApprovalStatus`].
#[derive(Debug, Clone)]
pub struct ApprovalRow {
    pub id: i64,
    pub owner_id: String,
    pub capability_name: String,
    pub args_json: String,
    pub idempotency_hash: String,
    pub status: ApprovalStatus,
    pub result_json: Option<String>,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
    pub executed_at: Option<i64>,
}

/// Scope of a denied approval (Ciclo 2.1, `docs/revamp/C2-approval-port-design.md`
/// §3 — `docs/revamp/LOOP-REPORT.md` finding #5.5): denying a single tool-call
/// does not stop a capable model from reaching the same intent through a
/// different, ungated tool. `Turn` closes that gap fail-closed; `Instance` is
/// reserved for a future "deny just this one" UX (not wired to any producer
/// in this cycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyScope {
    /// Deny only this specific invocation — the tool-loop continues normally,
    /// exactly like every other per-call error the loop already catches and
    /// reports to the model as a tool result.
    Instance,
    /// Deny AND end the tool-loop for this turn — fail-closed against
    /// alternative-tool routing. The turn ends with whatever text the model
    /// already produced this round, plus a warning. Product default (§3):
    /// a user who denies one action almost never wants the same intent
    /// carried out through a different tool in the same turn.
    Turn,
}

/// Disposition returned by an [`ApprovalGate`](../../bastion_runtime/agent/ports/trait.ApprovalGate.html)'s
/// `enqueue_or_reuse` — always the full state, never a bare bool, so
/// `CapabilityRegistry::invoke()` knows exactly what to do next. Moved here
/// from `bastion-runtime`'s `capability/approval.rs` (Ciclo 2.1) — same
/// rationale as [`ApprovalStatus`].
#[derive(Debug, Clone)]
pub enum ApprovalOutcome {
    /// A prior call already ran this exact (owner, capability, args) to
    /// completion. Return this cached result — never re-dispatch (D-03
    /// idempotent-resume).
    AlreadyExecuted(serde_json::Value),
    /// A row is already queued for this exact (owner, capability, args) and is
    /// not yet resolved. Do not insert a second row, do not dispatch.
    AlreadyPending,
    /// The row has been approved by the owner but has not executed yet — the
    /// caller must dispatch NOW and then call `record_executed(id, ...)`.
    ApprovedPendingExecution(i64),
    /// A brand-new row was inserted. Do not dispatch — awaiting owner approval.
    NewlyQueued(i64),
    /// The owner explicitly rejected this row (Ciclo 2.1 — behavior change,
    /// `docs/revamp/C2-approval-port-design.md` §2): callers must surface
    /// this as `Err(BastionError::ApprovalDenied)`, never the same
    /// `Ok({awaiting_approval: true})` shape `AlreadyPending`/`NewlyQueued`
    /// produce. Carries the scope the tool-loop must enforce.
    Rejected(DenyScope),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BastionError {
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("MCP timeout on tool '{tool}' after {elapsed_ms}ms")]
    McpTimeout { tool: String, elapsed_ms: u64 },
    #[error("Tool loop cap exceeded (10 rounds)")]
    ToolLoopCap,
    #[error("Budget exceeded: daily cap reached")]
    BudgetExceeded,
    #[error("Orphaned tool result — no preceding assistant tool_use")]
    OrphanedToolResult,
    #[error("Privacy egress blocked: local-only context bound for non-Ollama provider")]
    PrivacyEgressBlocked,
    /// SEC-01 approval explicitly denied by the owner (Ciclo 2.1 — behavior
    /// change, `docs/revamp/C2-approval-port-design.md` §2). Deliberate
    /// symmetry with `PrivacyEgressBlocked`: callers `downcast_ref::<BastionError>()`
    /// to distinguish "denied" from every other error, exactly like the
    /// egress gate's caught-error. `scope` decides how the kernel tool-loop
    /// reacts — `DenyScope::Instance` reports this as a per-call tool-result
    /// error and continues the round; `DenyScope::Turn` (the product
    /// default, §3) additionally ends the tool-loop for this turn.
    #[error("Approval denied for capability '{capability}'")]
    ApprovalDenied {
        capability: String,
        scope: DenyScope,
    },
    /// Input guardrail rejection — structural input check failed (HOOK-02).
    /// Carries a detail string for logging; MUST NOT be echoed to the client.
    #[error("Input guardrail rejected: {0}")]
    InputGuardrailRejected(String),
    /// Identity error — Agent Card sign/verify failures (SEC-06).
    #[error("Identity error: {0}")]
    IdentityError(String),
    /// Ciclo 2.4 (`docs/revamp/C2-backend-profile-design.md` §3/§5.6):
    /// a runtime-backed turn (`ConversationBackend::Runtime(id)`) could not
    /// be served — `id` unregistered/unhealthy at turn start
    /// (`RuntimeRegistry::resolve`), the adapter's `start`/`resume`/`submit`
    /// failed, or the harness task itself ended in `Cancelled`/`TimedOut`/
    /// `Failed`. Always a typed, surfaced error — never a silent fallback to
    /// `Model` (that would hide a real loss of policy coverage from the
    /// owner).
    #[error("Agent runtime backend unavailable: {0}")]
    BackendUnavailable(String),
    /// Loop 3-D (`docs/revamp/C3-cloud-ready-design.md`, security point 1):
    /// a [`crate::secret::SecretResolver`] could not find material for the
    /// named reference. Carries ONLY the reference name — never a partial
    /// or attempted value — so this error is always safe to log/trace/
    /// surface verbatim.
    #[error("Secret not found for reference '{name}'")]
    SecretNotFound { name: String },
}

/// Strip `<think>...</think>` blocks from LLM output (CORE-09).
/// Handles: multiple blocks, multiline content, no blocks (returns clone).
pub fn strip_think(s: &str) -> String {
    let open = "<think>";
    let close = "</think>";
    let mut result = String::with_capacity(s.len());
    let mut rest = s;

    loop {
        match rest.find(open) {
            None => {
                result.push_str(rest);
                break;
            }
            Some(start) => {
                result.push_str(&rest[..start]);
                rest = &rest[start + open.len()..];
                match rest.find(close) {
                    None => {
                        // Unclosed <think> — treat the remainder as content to discard
                        break;
                    }
                    Some(end) => {
                        rest = &rest[end + close.len()..];
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_think_basic() {
        assert_eq!(
            strip_think("hello <think>reasoning</think> world"),
            "hello  world"
        );
        assert_eq!(strip_think("no thinks here"), "no thinks here");
        assert_eq!(strip_think("<think>only think</think>"), "");
        assert_eq!(
            strip_think("a <think>x</think> b <think>y</think> c"),
            "a  b  c"
        );
        assert_eq!(strip_think("a <think>\nmultiline\n</think> b"), "a  b");
    }

    #[test]
    fn failure_kind_display_matches_serde_rename() {
        assert_eq!(FailureKind::Contestation.to_string(), "contestation");
        assert_eq!(FailureKind::EgressReject.to_string(), "egress_reject");
    }

    #[test]
    fn role_roundtrip() {
        assert_eq!("user".parse::<Role>().unwrap(), Role::User);
        assert_eq!("assistant".parse::<Role>().unwrap(), Role::Assistant);
        assert_eq!(Role::Tool.to_string(), "tool");
        assert_eq!("system".parse::<Role>().unwrap(), Role::System);
    }

    #[test]
    fn call_config_default_has_no_structured_output_request() {
        let cfg = CallConfig::default();
        assert_eq!(cfg.system_prompt, "");
        assert_eq!(cfg.max_tokens, 4096);
        assert!(cfg.tools.is_empty());
        assert!(cfg.response_format.is_none());
        assert!(cfg.tool_choice.is_none());
        assert!(cfg.temperature.is_none());
    }

    #[test]
    fn tool_use_extra_field_roundtrips_through_serde_when_none_and_some() {
        let none_variant = ContentPart::ToolUse {
            id: "call_1".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path": "/tmp/x"}),
            extra: None,
        };
        let json = serde_json::to_value(&none_variant).unwrap();
        let back: ContentPart = serde_json::from_value(json).unwrap();
        match back {
            ContentPart::ToolUse { extra, .. } => assert_eq!(extra, None),
            _ => panic!("expected ToolUse"),
        }

        let some_variant = ContentPart::ToolUse {
            id: "call_2".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path": "/tmp/y"}),
            extra: Some(serde_json::json!({"a": 1})),
        };
        let json = serde_json::to_value(&some_variant).unwrap();
        let back: ContentPart = serde_json::from_value(json).unwrap();
        match back {
            ContentPart::ToolUse { extra, .. } => {
                assert_eq!(extra, Some(serde_json::json!({"a": 1})))
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn tool_call_extra_defaults_to_none_when_absent_from_json() {
        // #[serde(default)] must let older/other-provider payloads without an
        // `extra` key deserialize without error.
        let json = serde_json::json!({"id": "1", "name": "x", "arguments": {}});
        let call: ToolCall = serde_json::from_value(json).unwrap();
        assert_eq!(call.extra, None);
    }

    #[test]
    fn tool_choice_forced_roundtrips_through_debug_and_clone() {
        let choice = ToolChoice::Forced("__structured_output".into());
        let cloned = choice.clone();
        assert_eq!(choice, cloned);
        assert_eq!(format!("{choice:?}"), "Forced(\"__structured_output\")");
    }
}
