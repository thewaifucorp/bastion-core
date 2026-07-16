//! Kernel ports (M2 step 3a): trait seams that let [`crate::agent::loop_::AgentLoop`]
//! depend on abstract capabilities instead of concrete product/cognition types.
//!
//! This is the in-monolith half of the M2 substrate split
//! (`docs/revamp/M2-ports-design.md`): the traits below are introduced and the
//! loop is wired to depend on them, but no file moves crate yet — that is a
//! separate step (3b). Behavior is unchanged; only the seam is added.

use bastion_types::{
    ApprovalOutcome, ApprovalRow, DeploymentContext, EffectAudit, EffectContext, FailureKind, Goal,
    PolicyDecision, PrivacyTier,
};

use crate::capability::CapabilityRegistry;
use crate::provider::{Provider, SharedProvider};
use crate::types::{CallConfig, LlmResponse, Message};

/// Final authority for a requested effect. Managed products inject their
/// server-side adapter; standalone products may compose a local authority.
#[async_trait::async_trait]
pub trait PolicyAuthority: Send + Sync {
    async fn decide(&self, effect: &EffectContext) -> anyhow::Result<PolicyDecision>;
}

/// Append-only observer for attempted and completed effects.
#[async_trait::async_trait]
pub trait EffectAuditor: Send + Sync {
    async fn record(&self, audit: &EffectAudit) -> anyhow::Result<()>;
}

/// P2 — failure telemetry sink.
///
/// Absorbs `eval::capture::record_failure` (`src/eval/capture.rs`), called
/// from the loop's egress-reject path (`agent/loop_.rs`) and from
/// `hooks::output_validator`'s NL-contestation-revoke path (HOOK-03). Resolves
/// the ADR's V4 anomaly (`runtime → cognition` via `hooks/output_validator.rs`
/// using `crate::eval`): both call sites now depend on this trait instead of
/// naming the `eval` module directly.
pub trait FailureSink: Send + Sync {
    /// Record one production-failure signal (EVAL-01).
    ///
    /// Must never panic and never propagate an error — mirrors
    /// `eval::capture::record_failure`'s swallow-on-write-failure contract.
    /// `tier` is the resolved `PrivacyTier` of the turn/belief that failed
    /// (deny-on-ambiguity routing lives in the concrete implementation).
    /// `detail` is a fixed, hardcoded `structural_property` label chosen by
    /// the calling code — never derived from user input (Pitfall 1).
    fn record_failure(&self, kind: FailureKind, tier: Option<PrivacyTier>, detail: &str);
}

/// P3 — external tool catalog.
///
/// Absorbs `McpClient` as a loop field. The M2-ports-design.md sketch scopes
/// this to `tool_defs()` alone (tool *invocation* already flows through
/// `CapabilityRegistry::invoke`, BIG-1, unchanged). In practice `loop_.rs` has
/// two registry-bypass call sites (`dispatch_tool_loop`'s empty-registry
/// fallback, and `run_provider_fallback`'s whole tool-dispatch loop) that call
/// `McpClient::call_tool_with_timeout` directly — these predate this port and
/// are a deliberate escape hatch (registry-bypass safety net), not covered by
/// `CapabilityRegistry::invoke`. To let the `mcp: Arc<McpClient>` FIELD leave
/// the struct entirely (as the design calls for) without changing that
/// behavior, this trait's surface is widened to also cover invocation — a
/// documented divergence from the minimal sketch, not a silent one.
///
/// M3 hardening (LOOP-REPORT.md finding F1): `call_tool_with_timeout` used to
/// document "callers apply their own egress gate" — true today, but nothing
/// in the type system stopped a future call site from forgetting to. The gate
/// is now part of the method's OWN contract: implementations MUST call
/// `bastion_runtime::hooks::egress::check_egress(resolved_tier, "external")`
/// (or the equivalent classification for their destination) BEFORE
/// dispatching, and return its `Err` unchanged on failure. The method **gates
/// internally; callers must pass the resolved tier** — there is no longer a
/// way to reach dispatch without it flowing through the check. Same
/// enforcement point as before (WR-02/D-13), same error type
/// (`BastionError::PrivacyEgressBlocked`), just unforgettable by construction.
#[async_trait::async_trait]
pub trait ToolSource: Send + Sync {
    /// Anthropic-format tool definitions to offer the model this turn, built
    /// from the MCP registry (name/description/input_schema). Used only by
    /// `run_provider_fallback`'s `CallConfig.tools` — the normal path sources
    /// tool defs from `CapabilityRegistry::list_tool_defs` instead.
    async fn tool_defs(&self) -> anyhow::Result<Vec<serde_json::Value>>;

    /// Registry-bypass tool invocation — mirrors `McpClient::call_tool_with_timeout`
    /// exactly (timeout, Composio bounded retry), but gates internally on
    /// `resolved_tier` before dispatching: the implementation must run the
    /// egress check first and short-circuit with its `Err` on denial. Callers
    /// pass the turn's resolved `PrivacyTier` (fail-closed on `None`, same as
    /// `check_egress`'s deny-on-ambiguity rule) — they no longer call
    /// `check_egress` themselves.
    async fn call_tool_with_timeout(
        &self,
        name: &str,
        args: serde_json::Value,
        owner: &str,
        resolved_tier: Option<PrivacyTier>,
    ) -> anyhow::Result<serde_json::Value>;
}

/// SEC-01 — owner-scoped, idempotent approval gate port (Ciclo 2.1,
/// `docs/revamp/C2-approval-port-design.md` §1).
///
/// Absorbs `ApprovalQueue` as a trait: the EXACT surface
/// `CapabilityRegistry::invoke` (Policy 2) and `AgentLoop::approval_resolution`
/// consume from the concrete SQLite-backed queue today — enqueue/idempotent-resume,
/// pending listing, owner-scoped approve/reject, and post-dispatch result
/// caching. `SqliteApprovalGate` (`capability/approval.rs`) is the production
/// implementation — same logic as the pre-port `ApprovalQueue`, now behind
/// this port.
///
/// Approval is NOT optional at the `CapabilityRegistry` construction boundary
/// (no `Option<Arc<dyn ApprovalGate>>` field) — a caller that wants a
/// fail-closed "no persistent queue" policy injects `NullApprovalGate`
/// (`capability/approval.rs`) explicitly, which reproduces the exact
/// fail-closed semantics the old `None` branch of `CapabilityRegistry`'s
/// approval field used to encode.
#[async_trait::async_trait]
pub trait ApprovalGate: Send + Sync {
    /// Enqueue a new approval row for (owner_id, capability_name, args), or
    /// report the disposition of the existing row for this exact triple —
    /// idempotent-resume (D-03). Deterministic hashing over the triple is an
    /// implementation detail of the concrete gate, not part of this contract.
    async fn enqueue_or_reuse(
        &self,
        owner_id: &str,
        capability_name: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<ApprovalOutcome>;

    /// All not-yet-resolved rows for this owner. Empty vec when none exist —
    /// never an error for the "no rows" case.
    async fn pending_for_owner(&self, owner_id: &str) -> anyhow::Result<Vec<ApprovalRow>>;

    /// Approve a pending row. Owner-scoped (IDOR guard) — errors when the
    /// given `owner_id` does not own `id`, rather than silently no-opping.
    async fn approve(&self, owner_id: &str, id: i64) -> anyhow::Result<ApprovalRow>;

    /// Reject a pending row. Owner-scoped (IDOR guard), same discipline as
    /// `approve`.
    async fn reject(&self, owner_id: &str, id: i64) -> anyhow::Result<()>;

    /// Record that an approved row has now executed, caching its result for
    /// idempotent-resume (D-03) — a later `enqueue_or_reuse` for the same
    /// triple returns `AlreadyExecuted(result)` instead of re-dispatching.
    async fn record_executed(&self, id: i64, result: &serde_json::Value) -> anyhow::Result<()>;
}

/// Loop 3-A (6a, `docs/revamp/C3-runtime-followups-design.md` §6a): one
/// harness [`bastion_agent_runtime::RuntimeEvent::PermissionRequest`] parked
/// pending a decision — either an explicit later-turn answer or a
/// fail-closed timeout.
///
/// `row_id` (Bastion's own autoincrement identity, assigned by
/// [`PermissionGate::enqueue`]) is the correlation key a LATER TURN resolves
/// by — never the harness's own `id`. The harness's [`bastion_agent_runtime::PermissionRequestId`]
/// is only unique WITHIN one session (a fresh harness session restarts its
/// own counter), so two concurrently-paused delegated tasks for the SAME
/// owner could easily raise colliding `id`s; `row_id` cannot collide, and is
/// what [`PermissionGate::resolve`] takes.
///
/// Deliberately a DIFFERENT vocabulary/port from [`ApprovalGate`] above (that
/// one gates a `CapabilityRegistry` tool-call invocation keyed by
/// `(owner, capability_name, args)`; this one gates a harness's own in-flight
/// permission prompt) — kept separate so neither trait's contract grows
/// concerns the other doesn't own.
#[derive(Debug, Clone)]
pub struct PendingPermission {
    /// Bastion's own row identity — the correlation key `resolve` takes.
    pub row_id: i64,
    /// The harness's own id for this request — needed to answer
    /// `RuntimeSession::respond_permission(id, decision)` on the REAL
    /// session; never used as a cross-request correlation key (see above).
    pub id: bastion_agent_runtime::PermissionRequestId,
    pub owner: String,
    /// Session the request was raised on — the task/session waiting for it.
    pub session: bastion_agent_runtime::SessionHandle,
    pub action: bastion_agent_runtime::PermissionAction,
    pub detail: String,
    /// Nanoseconds since `UNIX_EPOCH` (matches the `now_nanos()` idiom used
    /// throughout `capability/approval.rs`).
    pub raised_at: i64,
    /// Nanoseconds since `UNIX_EPOCH` — once passed, the request MUST be
    /// resolved as a fail-closed `Deny { scope: Turn }` (whoever notices
    /// first: the paused consumer's own timer, or a later sweep).
    pub expires_at: i64,
}

/// Loop 3-A (6a) — owner-scoped, persisted cross-turn queue for harness
/// permission requests (see [`PendingPermission`]'s rustdoc for why this is
/// a separate port from [`ApprovalGate`]).
///
/// `AgentLoop` defaults to `NullPermissionGate` (`capability::permission_queue`)
/// unless a real gate is injected via `AgentLoop::with_permission_gate` — the
/// SAME "no `Option`, explicit fail-closed default" discipline `ApprovalGate`
/// established (SEC-01). With the default gate, `enqueue` always errors, so
/// every permission request resolves as an IMMEDIATE `Deny { scope: Turn }`
/// — byte-identical to pre-6a behavior for any deployment that doesn't
/// explicitly opt in.
#[async_trait::async_trait]
pub trait PermissionGate: Send + Sync {
    /// Persist a freshly-raised permission request, owner-scoped. Returns
    /// the assigned `row_id` (see [`PendingPermission::row_id`]).
    #[allow(clippy::too_many_arguments)]
    async fn enqueue(
        &self,
        owner_id: &str,
        session: &bastion_agent_runtime::SessionHandle,
        id: bastion_agent_runtime::PermissionRequestId,
        action: &bastion_agent_runtime::PermissionAction,
        detail: &str,
        raised_at: i64,
        expires_at: i64,
    ) -> anyhow::Result<i64>;

    /// All not-yet-resolved requests for this owner. Empty vec when none
    /// exist — never an error for the "no rows" case (mirrors
    /// `ApprovalGate::pending_for_owner`).
    async fn pending_for_owner(&self, owner_id: &str) -> anyhow::Result<Vec<PendingPermission>>;

    /// Resolve a pending request by `row_id`, owner-scoped (IDOR guard,
    /// mirrors `ApprovalGate::approve`/`reject`). Errors if `row_id` doesn't
    /// belong to `owner_id` or is no longer pending (already resolved — by
    /// an earlier explicit decision or a timeout race the caller lost).
    /// Returns the now-resolved row so the caller can read back `id`/
    /// `session` (needed to answer the harness / key the in-memory wake-up)
    /// without a second round trip.
    async fn resolve(
        &self,
        owner_id: &str,
        row_id: i64,
        decision: bastion_agent_runtime::PermissionDecision,
    ) -> anyhow::Result<PendingPermission>;
}

/// M4-07 (`docs/revamp/A-01-agentruntime-contract.md` §5 req 11 — "AuthProfileRef
/// inválido → Auth tipado sem vazamento de secret"): verifies a
/// [`bastion_agent_runtime::AuthProfileRef`] resolves to something usable
/// BEFORE a runtime-backed session is started.
///
/// Neither shipped `AgentRuntime` adapter (`acpx`, `codex_app_server`) reads
/// `SessionSpec::auth` at all — both are host-CLI wrappers that rely on
/// ambient host login (`claude`/`codex`/`opencode` already authenticated on
/// the machine), so the contract's own "invalid auth → typed error"
/// requirement had no discharge point. This port IS that discharge point,
/// injected ABOVE the adapter: only the app layer knows what a configured
/// `[auth.<profile>]` id is supposed to map to (a host-CLI kind, an
/// env-var-backed API key, ...) — the kernel never learns config format or
/// names a concrete CLI (same law as `BackendConfig`/`RuntimeRegistry`).
///
/// Never receives or returns secret material: a conforming implementation
/// checks login/presence state only (e.g. spawn the CLI's own read-only
/// status command — `claude auth status`, `codex login status`, `opencode
/// auth list` — or confirm an env var is SET) and must never read, log, or
/// propagate token/credential bytes.
///
/// `AgentLoop` defaults to [`crate::capability::NullAuthResolver`] (always
/// `Ok` — byte-identical to every pre-M4-07 deployment, since no check of
/// any kind existed before this port); a real resolver is injected via
/// `AgentLoop::with_auth_resolver` only once `[auth.*]` profiles are
/// actually configured (`main.rs` wires the config-driven
/// `AuthProfileRegistry`, app-level).
#[async_trait::async_trait]
pub trait AuthResolver: Send + Sync {
    /// `Ok(())` when `auth` currently resolves to something usable;
    /// otherwise a typed [`bastion_agent_runtime::RuntimeError::Auth`] (never
    /// containing secret material — same discipline the adapter contract
    /// itself requires of this error variant).
    async fn resolve(
        &self,
        auth: &bastion_agent_runtime::AuthProfileRef,
    ) -> Result<(), bastion_agent_runtime::RuntimeError>;
}

/// P4 — optional goal-engine port.
///
/// `GoalEngine` becomes a trait object injected as `Option<Arc<dyn GoalPort>>`
/// with exactly the surface the loop uses: `list_goals`, called from the
/// `/goals` and `/drift` cockpit commands (`cockpit_command`,
/// `agent/loop_.rs`). No other `GoalEngine` method is reachable from the loop
/// (confirmed by reading every call site beyond the import, M2-05).
#[async_trait::async_trait]
pub trait GoalPort: Send + Sync {
    /// Return all goals for `owner_id`.
    async fn list_goals(&self, owner_id: &str) -> anyhow::Result<Vec<Goal>>;
}

/// Pre-compaction memory flush (M2 step 3b, decision A1 — MEM-09).
///
/// Absorbs the loop's direct call to `agent::dream::memory_flush` (cognition:
/// heuristic belief distillation) right before `AutoCompact::compact`. The
/// concrete implementation (`agent::dream::DreamFlush`) closes over the
/// `SharedMemory` at construction — the kernel does not pass memory through
/// this port. `None` = no flush configured (compaction proceeds without it);
/// production injects `Some(...)`.
#[async_trait::async_trait]
pub trait PreCompactionFlush: Send + Sync {
    /// Distill and persist whatever this implementation wants from `history`
    /// before the kernel compacts it. Failure must not abort the turn — the
    /// kernel logs and proceeds (mirrors `memory_flush`'s swallow-errors
    /// contract).
    async fn flush(&self, history: &[Message], owner: &str) -> anyhow::Result<()>;
}

/// Tool-result observer (M2 step 3b, decision A2 — D-06/Gap 1).
///
/// Absorbs the loop's `handle_skill_reload` helper: product-level reaction to
/// a tool result (today: the skill-writer `skill_reloaded` hot-reload signal,
/// including its SEC/CR-02 path sanitization — all moved VERBATIM into the
/// concrete `agent::skills::SkillReloadObserver`). Called by the kernel on
/// EVERY tool result, on both dispatch paths (`dispatch_tool_loop` and
/// `run_provider_fallback`), exactly where `handle_skill_reload` was called.
/// `None` = no observer configured.
pub trait ToolResultObserver: Send + Sync {
    /// Inspect one raw tool-result value. Must be cheap and non-blocking
    /// (the current implementation is synchronous filesystem checks gated on
    /// a JSON flag) and must never panic.
    fn on_tool_result(&self, result: &serde_json::Value);
}

/// Provider resolution by model name (M2 step 3b, decision A3 — D-10 rung 3).
///
/// Absorbs the loop's direct call to `provider::registry::resolve_provider`
/// in the fallback ladder's provider-switch rung. This production field
/// replaces the old `#[cfg(test)] fallback_resolver_override` seam — unit
/// tests now inject a scripted resolver through the same field production
/// uses (`main.rs` injects the registry-backed implementation,
/// `provider::registry::RegistryProviderResolver`).
pub trait ProviderResolver: Send + Sync {
    /// Construct the `Provider` for `model` (may be credential/network-backed
    /// in production). Errors are handled defensively by the caller (an
    /// unresolvable candidate falls back to the original ladder error).
    fn resolve(&self, model: &str) -> anyhow::Result<Box<dyn Provider>>;
}

/// The result of dispatching one slash command. Moved VERBATIM from
/// `agent/command.rs` (M2 step 3b, decision D3): it is the type the kernel's
/// `AgentLoop::handle_command` wrapper returns, so it lives with the port;
/// `agent::command` re-exports it so every existing path keeps compiling.
pub enum CommandResult {
    /// Carries the user-facing text — the stdin console prints it, the webhook
    /// channel (WEB-CMD-01) puts it straight in the JSON reply. Neither path
    /// duplicates formatting logic; this function is the only place that builds it.
    Handled(String),
    Stop,
    Unknown(String),
}

/// P6 `CommandHandler` — cockpit/slash-command dispatch (M2 step 3b, D3).
///
/// Absorbs the loop's dependency on `agent::command::{handle_command,
/// CommandResources}` (product/UX: OTC pairing store, Composio OAuth,
/// `PersonaRegistry` for `/as` and `/cabinet` validation). The kernel wrapper
/// (`AgentLoop::handle_command`) hands the handler exactly the kernel state
/// the old free-function call forwarded — `provider`, `memory`,
/// `&mut forced_persona` — and the concrete implementation
/// (`agent::command::CockpitCommandHandler`) closes over the product-level
/// `CommandResources` at construction in the composition root (`main.rs`).
///
/// Divergence from the design sketch (documented, not silent): the sketch
/// proposed `handle(&self, input, owner, session_id) ->
/// Result<Option<CommandOutcome>>`. The real wrapper passes no `session_id`,
/// and "not a command" is already an in-band [`CommandResult::Unknown`]
/// variant (callers pre-filter on a leading `/` before ever calling), so this
/// signature mirrors the existing wrapper exactly — same semantics, no new
/// `Option` layer.
#[async_trait::async_trait]
pub trait CommandHandler: Send + Sync {
    /// Dispatch one slash command. The argument list mirrors what the loop's
    /// wrapper forwarded to `agent::command::handle_command` (kernel-side
    /// state only — product resources live inside the implementation).
    async fn handle(
        &self,
        input: &str,
        provider: &SharedProvider,
        memory: &crate::memory::SharedMemory,
        forced_persona: &mut Option<String>,
        forced_cabinet: &mut Option<Vec<String>>,
        owner: &str,
    ) -> anyhow::Result<CommandResult>;
}

/// P1 — narrow kernel capability handle exposed to a [`Responder`] via
/// [`TurnContext`].
///
/// The M2-ports-design.md sketch describes `Responder` absorbing
/// route/runner/cabinet dispatch wholesale, hiding "persona routing,
/// single/parallel dispatch and any deliberation" behind one call. In the real
/// code, the moved logic (`dispatch_single_or_parallel`, formerly a private
/// `AgentLoop` method) ALSO calls back into two things that are genuinely
/// kernel-side, not persona/cabinet-side: the capability-registry-gated tool
/// loop (`dispatch_tool_loop`) and the SEAM #2 system-prompt builder
/// (`build_system_prompt`, which reads `context_providers` — opaque blocks the
/// kernel never interprets). Neither references a persona/cabinet type.
/// `TurnKernel` is the minimal seam that lets the moved code keep calling
/// them without the kernel handing the WHOLE `AgentLoop` (and hence every
/// other kernel method) to the `Responder`, and without `Responder`
/// duplicating tool-loop/system-prompt logic. `AgentLoop` is the only
/// implementer.
#[async_trait::async_trait]
pub trait TurnKernel: Send + Sync {
    /// The kernel's single policy-enforcement point (BIG-1) — mutable access
    /// so persona/cabinet dispatch functions (which already take
    /// `&mut CapabilityRegistry` directly: `persona::router::route`,
    /// `cabinet::orchestrator::deliberate`, `cabinet::synth::synthesize`) can
    /// reach it without the kernel losing ownership.
    fn capability_registry(&mut self) -> &mut CapabilityRegistry;

    /// SEAM #2: builds the dynamic system prompt for this turn from the
    /// kernel's own `context_providers` — opaque to the `Responder`.
    async fn build_system_prompt(
        &self,
        owner: &str,
        turn_msg: &str,
        persona: Option<&str>,
    ) -> String;

    /// Appends one message to the session transcript (`SessionManager::append`).
    async fn session_append(
        &self,
        session_id: &str,
        msg: Message,
        output_tokens: Option<u32>,
    ) -> anyhow::Result<()>;

    /// Runs the capability-registry-gated tool loop to completion
    /// (`AgentLoop::dispatch_tool_loop`) for one persona's initial LLM
    /// response — pure kernel logic (capability_registry + egress + session +
    /// tool_source), no persona/cabinet knowledge.
    async fn run_tool_loop(
        &mut self,
        history: &mut Vec<Message>,
        session_id: &str,
        config: &CallConfig,
        initial_response: LlmResponse,
        owner: &str,
        resolved_tier: Option<PrivacyTier>,
    ) -> anyhow::Result<String>;
}

/// The built turn context a [`Responder`] consumes to produce the final
/// assistant response. Deliberately carries no persona/cabinet type — only
/// kernel types (`SharedProvider`, `TurnKernel`, `Message`) and plain data.
pub struct TurnContext<'a> {
    /// Cloned `Arc` — cheap, and avoids the `Responder` needing a `&mut`
    /// borrow of the kernel just to read the active provider.
    pub provider: SharedProvider,
    /// Handle back into the kernel for the two capabilities described on
    /// [`TurnKernel`] (capability registry, system prompt, tool loop, session
    /// append). `AgentLoop` reborrows itself (`&mut *self`) to build this —
    /// freed again as soon as `Responder::respond` returns.
    pub kernel: &'a mut dyn TurnKernel,
    /// Conversation history for this turn — loaded/compacted by the kernel
    /// before `respond` is called; mutated in place (assistant/tool messages
    /// pushed as the dispatch proceeds), mirroring today's `&mut history`.
    pub history: &'a mut Vec<Message>,
    pub session_id: &'a str,
    pub owner: &'a str,
    /// Deployment-level authority context. Generic by design: products supply
    /// adapters and policy services without exposing their names to the core.
    pub deployment: DeploymentContext,
    pub user_input: &'a str,
    /// SEC-05/D-09: true when `user_input` originates from an untrusted
    /// source — the `Responder` must genuinely drain/restore the capability
    /// registry around dispatch, exactly like `run_turn_for_with_trust` did
    /// inline before this port.
    pub untrusted: bool,
    /// Taken from `AgentLoop.forced_persona` (`/as` command) by the kernel
    /// BEFORE constructing this context — passed by value since it is a
    /// take-once read, never restored.
    pub forced_persona: Option<String>,
    pub forced_cabinet: Option<Vec<String>>,
    /// SEAM #4: the turn's root OTel span, so the `Responder` can stamp
    /// `gen_ai.agent.name` once the persona is known (matches today's
    /// `turn_span.set_attribute(...)` call site exactly). An OTel
    /// infrastructure type, not a cognition type.
    pub turn_span: &'a mut opentelemetry::global::BoxedSpan,
}

/// P1 `Responder` — quem responde e como.
///
/// Absorbs `persona::router::{route, RouterDecision, ResponseMode}`,
/// `persona::runner::{run, RunnerOutput}`,
/// `cabinet::{build_table, orchestrator::deliberate, synth::{synthesize, CabinetVerdict}}`,
/// and `render_verdict`. The kernel's `AgentLoop` no longer names any of
/// these types; it only knows `Responder`/`TurnContext`/`RespondOutcome`.
///
/// Divergence from the design-doc sketch: `respond` takes `TurnContext<'_>`
/// BY VALUE, not `&TurnContext<'_>` — the context carries `&mut` fields
/// (`kernel`, `history`) that a shared reference to the struct could not
/// re-borrow mutably (`&TurnContext` would only ever yield `&&mut dyn
/// TurnKernel`, unusable for mutation). Passing the struct by value moves
/// those borrows in without that restriction, while `respond` itself stays
/// `&self` (the design's actual intent — a `Responder` is stored as
/// `Arc<dyn Responder>` and must not need unique access to itself).
#[async_trait::async_trait]
pub trait Responder: Send + Sync {
    /// Given the built turn context, produce the final assistant response.
    /// Hides persona routing, single/parallel dispatch and any deliberation.
    async fn respond(&self, turn: TurnContext<'_>) -> anyhow::Result<RespondOutcome>;
}

/// The `Responder`'s output.
pub struct RespondOutcome {
    pub text: String,
    /// Which agent definition(s) produced it — for session/OTel labeling.
    /// Doubles as the "matched persona" the kernel needs post-routing (was
    /// `turn_persona` in the pre-port code): `attribution.first()`.
    pub attribution: Vec<String>,
    /// Resolved `PrivacyTier` of the persona that handled this turn (`None`
    /// when no persona matched). Deliberate addition beyond the design doc's
    /// `text`/`attribution` sketch: the kernel still needs this for
    /// `run_provider_fallback`'s egress gate and the `FailureSink` call on
    /// the empty-text fallback path, but `PersonaRegistry` — the only thing
    /// that can resolve a persona name to a tier — now lives inside the
    /// `Responder`, not the kernel.
    pub turn_tier: Option<PrivacyTier>,
}
