//! `AgentRuntime` — contract for external agent harnesses (A-01).
//!
//! Second execution abstraction next to [`crate::provider::Provider`]:
//! a `Provider` answers one inference call; an `AgentRuntime` owns a
//! **session** whose external harness runs its own internal tool loop
//! (terminal, files, tools, artifacts) and reports structured events back.
//!
//! Adapters (native app-server, supervised ACP client) live outside the kernel and
//! must pass the conformance suite in [`conformance`]. The kernel never
//! names a concrete harness.
//!
//! Security invariants carried by this contract (threat model in
//! `docs/SUPPORT-MATRIX.md`):
//! - transport is structured protocol only — interpreting human stdout or
//!   ANSI output is a conformance failure, not a fallback;
//! - everything a harness returns is untrusted until policy says otherwise;
//! - permission requests bridge into Bastion's approval queue — an adapter
//!   never auto-approves;
//! - egress filtering happens when the [`TaskInput`] is assembled, before
//!   any content reaches the harness;
//! - auth is an opaque [`AuthProfileRef`]; errors never carry secrets.
//!
//! [`conformance::ConformanceScenarios::watchdog`] bounds live checks,
//! [`SandboxCoverage`] reports detected isolation, [`ResumeSpec`] carries the
//! session properties that can be reapplied, and [`DenyScope`] determines
//! whether a denial ends one request or the whole turn.

pub mod acpx;
pub mod codex;
pub mod conformance;
mod util;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Typed failures of a runtime adapter. `#[non_exhaustive]` like
/// [`crate::types::BastionError`]; carried via `anyhow` at boundaries.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum RuntimeError {
    /// Harness cannot be reached/spawned (missing binary, dead server).
    #[error("harness unavailable: {0}")]
    Unavailable(String),
    /// Structured-protocol violation (invalid frame, out-of-order event).
    /// Fail-closed: the session is considered lost, never reinterpreted.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// Installed harness/client version outside the adapter's pinned range.
    #[error("version mismatch: {0}")]
    Version(String),
    /// Credential resolution/refresh failed. MUST NOT contain token material.
    #[error("auth failed: {0}")]
    Auth(String),
    #[error("task timed out after {0:?}")]
    Timeout(Duration),
    #[error("cancelled")]
    Cancelled,
    /// Harness process/server died mid-session. Bastion session state must
    /// remain intact and readable after this error.
    #[error("harness crashed: {0}")]
    Crashed(String),
    /// `resume` cannot reattach (expired, evicted, foreign owner). A valid,
    /// typed outcome — callers surface it instead of silently starting fresh.
    #[error("session not resumable: {0}")]
    NotResumable(String),
}

/// Opaque reference to a credential/entitlement profile (subscription login,
/// API key, host-authenticated CLI). Resolution happens outside the adapter;
/// the contract only threads the reference. Orthogonal to backend choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProfileRef(pub String);

/// Persistable reference to a harness session, owner-scoped. Stored next to
/// the Bastion session so a daemon restart can [`AgentRuntime::resume`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandle {
    /// Adapter id this handle belongs to (must match `RuntimeDescriptor::id`).
    pub runtime_id: String,
    /// Owner the session was opened for; `resume` revalidates it.
    pub owner: String,
    /// Adapter-internal session reference (opaque to the kernel).
    pub external_ref: String,
}

/// Monotonic task identifier within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub u64);

/// Identifier of a pending permission request raised by the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionRequestId(pub u64);

/// Transport class of an adapter. Informational (UI/diagnostics); the
/// contract semantics are identical across transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// Long-lived structured server process (e.g. app-server protocol).
    AppServer,
    /// Supervised JSON-RPC/NDJSON client subprocess.
    JsonRpcSubprocess,
    /// In-process implementation (tests, embedded hosts).
    Embedded,
}

/// Static feature declaration. Conformance skips checks a runtime honestly
/// declares unsupported — and fails adapters that claim support they lack.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct RuntimeSupports {
    pub resume: bool,
    pub steer: bool,
    pub usage_reporting: bool,
    pub diff_events: bool,
    pub permission_bridge: bool,
    pub concurrent_sessions: bool,
}

/// Who mediates harness tool calls, as observable by Bastion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolVisibility {
    /// Every tool call is bridged through Bastion's capability registry.
    Full,
    /// Tool calls are reported as events but executed inside the harness.
    DeclaredOnly,
    /// No tool-call telemetry at all.
    Opaque,
}

/// Whether harness permission prompts reach Bastion's approval queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalCoverage {
    /// `PermissionRequest` events bridge to the approval queue.
    Bridged,
    /// Harness resolves permissions internally from its pre-set profile.
    HarnessOwned,
}

/// Where egress control is enforced for this backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressCoverage {
    /// Bastion filters what ENTERS the session (input-side chokepoint).
    InputFiltered,
    /// The harness has its own network authority beyond Bastion's control.
    HarnessOwned,
}

/// Fidelity of usage/cost reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetCoverage {
    Reported,
    Estimated,
    /// No usage data — budget policy must fall back to time/task caps.
    Unknown,
}

/// How much of the requested sandbox profile the harness honors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxCoverage {
    Honored,
    Partial,
    None,
}

/// Honest declaration of which policy surfaces this runtime covers in a
/// runtime-backed turn. The product UI renders this; it is never inferred.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PolicyCoverage {
    pub tool_visibility: ToolVisibility,
    pub approvals: ApprovalCoverage,
    pub egress: EgressCoverage,
    pub budget: BudgetCoverage,
    pub sandbox: SandboxCoverage,
}

/// Identity + capability card of an adapter. Static per adapter version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDescriptor {
    /// Stable adapter id, e.g. `"codex_app_server"`.
    pub id: &'static str,
    pub adapter_version: String,
    /// Human-readable pin of the supported harness/client version range.
    pub target_version: String,
    pub transport: Transport,
    pub supports: RuntimeSupports,
    pub policy_coverage: PolicyCoverage,
}

/// Result of a cheap pre-session probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    /// Version actually found on the host.
    pub detected_version: String,
    /// True when a session can be opened right now (binary present,
    /// version in range, auth resolvable).
    pub ready: bool,
    /// Human-readable diagnostics when `ready == false`.
    pub detail: Option<String>,
}

/// Filesystem confinement for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePolicy {
    /// Session root; the harness must not act outside it.
    pub root: PathBuf,
    pub read_only: bool,
    /// Paths under `root` the harness must not touch at all.
    pub deny: Vec<PathBuf>,
}

/// Sandbox request passed to the adapter; coverage is declared in
/// [`PolicyCoverage::sandbox`], not assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxProfile {
    /// No network, workspace-only writes.
    Isolated,
    /// Workspace writes plus network.
    WorkspaceNet,
    /// Host-level trust (owner explicitly opted in).
    Trusted,
}

/// What the harness may do without raising a permission request.
/// Deny-by-default: everything not listed requires a bridge/approval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionProfile {
    /// Allowed tool/action identifiers, adapter-namespaced.
    pub allow: Vec<String>,
}

/// Timeouts for a session; expiry cancels and emits `TimedOut`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    pub per_task: Duration,
    pub idle: Duration,
}

/// Environment allowlist for subprocess transports. Default: empty —
/// the harness inherits nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvPolicy {
    pub allow: BTreeMap<String, String>,
}

/// Wiring of Bastion MCP servers into the harness, so memory/skills stay
/// reachable inside the delegated loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBridgeSpec {
    /// Server names as configured in Bastion, exposed to the harness.
    pub servers: Vec<String>,
}

/// OTel correlation context linking harness spans to the delegating turn.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OtelContext {
    pub trace_id: Option<String>,
    pub parent_span_id: Option<String>,
}

/// The subset of [`SessionSpec`] genuinely re-appliable on
/// [`AgentRuntime::resume`] (Ciclo 2.2, closing A-05 §5.6 / LOOP-REPORT
/// finding #6: `resume` used to take no spec at all, so an adapter could
/// not recover the caller's real policy on reattach and fell back to
/// conservative, adapter-level defaults).
///
/// `workspace` and `sandbox` are deliberately excluded: they are fixed by
/// the original session (a harness session's root/confinement cannot be
/// renegotiated mid-reattach) — only `timeout`/`permissions`/`env` can
/// plausibly change across a daemon restart and be re-applied.
///
/// Not every adapter can honor every field over its resume protocol (e.g. a
/// harness's reattach call may only take a session id, with no channel to
/// change permissions). A conforming adapter applies what its protocol
/// allows and surfaces the rest as a [`RuntimeEvent::Warning`] rather than
/// silently dropping the divergence — see [`crate::codex`] for a real
/// example.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeSpec {
    pub timeout: TimeoutPolicy,
    pub permissions: PermissionProfile,
    pub env: EnvPolicy,
}

/// Everything needed to open a session. Built by the composition layer —
/// egress filtering of the payload happens BEFORE this struct is filled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSpec {
    pub owner: String,
    pub workspace: WorkspacePolicy,
    pub sandbox: SandboxProfile,
    pub permissions: PermissionProfile,
    pub auth: AuthProfileRef,
    /// Target model/agent id inside the harness.
    pub runtime_id: String,
    pub timeout: TimeoutPolicy,
    pub env: EnvPolicy,
    pub mcp_bridge: Option<McpBridgeSpec>,
    pub otel: OtelContext,
}

/// Expected shape of a task result; adapters use it to map harness output,
/// never to loosen policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskExpectation {
    Conversation,
    CodeChange,
    Structured(serde_json::Value),
}

/// Input of one task. `prompt` is already egress-filtered content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInput {
    pub prompt: String,
    pub attachments: Vec<Artifact>,
    pub expected: TaskExpectation,
}

/// Kind of artifact produced by (or fed into) a harness session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    Diff,
    File,
    Log,
}

/// A harness-produced (or provided) artifact with provenance. Treated as
/// untrusted content by consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub kind: ArtifactKind,
    /// Path relative to the session workspace root.
    pub path: PathBuf,
    /// Content digest (`sha256:<hex>`), verified by conformance.
    pub digest: String,
    /// Producing session; `None` for caller-provided inputs.
    pub produced_by: Option<SessionHandle>,
}

/// Terminal outcome of a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskOutcome {
    Success,
    Failed { reason: String },
    Cancelled,
    TimedOut,
}

/// Incremental usage report.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct UsageDelta {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Non-fatal adapter warnings surfaced to observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarnCode {
    UsageDiscrepancy,
    DegradedTransport,
    SandboxDowngrade,
}

/// Action classes a harness may ask permission for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionAction {
    RunCommand,
    WriteFile,
    Network,
    UseTool,
    Other(String),
}

/// Scope of a denied permission request (Ciclo 2.2, mirroring the kernel's
/// `bastion_types::DenyScope` — `docs/SECURITY-INVARIANTS.md`
/// §3). `bastion-agent-runtime` is still a standalone crate (no
/// `bastion-types` dependency; see the M1/M2 substrate split), so this is a
/// deliberate, documented duplicate of the same two-variant vocabulary, not
/// an independently invented one — keep it in sync if the kernel's
/// `DenyScope` ever grows a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyScope {
    /// Deny only this specific permission request; the session/task
    /// continues — whatever the harness does next with a declined action is
    /// bounded only by `policy_coverage`, not by this contract.
    Instance,
    /// Deny AND end the delegated task: after declining, the adapter
    /// cancels the active task gracefully (`RuntimeSession::cancel`
    /// semantics). Product default (mirrors the kernel's `DenyScope::Turn`):
    /// closes the "deny one tool call, harness reroutes through another
    /// ungated one" gap (A-05 §5.5 / LOOP-REPORT finding #5.5) at the
    /// adapter boundary — a denial almost never means "keep trying other
    /// approaches this task".
    Turn,
}

/// Decision returned to the harness for a pending permission request.
/// Produced by Bastion's approval flow — never synthesized by the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionDecision {
    Allow,
    /// Ciclo 2.2: carries [`DenyScope`] — see its rustdoc for what each
    /// variant requires of a conforming adapter.
    Deny {
        scope: DenyScope,
    },
}

/// Cancellation mode for [`RuntimeSession::cancel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelMode {
    /// Cooperative signal, then kill after the grace period.
    Graceful { grace: Duration },
    /// Immediate termination.
    Kill,
}

/// Coarse session state as reported by [`RuntimeSession::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Idle,
    Running,
    Cancelled,
    Crashed,
    Closed,
}

/// Typed, session-ordered event stream. `Ended` is terminal per task and
/// nothing may follow the final task's `Ended` (conformance-enforced).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeEvent {
    Started {
        handle: SessionHandle,
    },
    /// Incremental assistant text.
    MessageDelta {
        task: TaskId,
        text: String,
    },
    /// Harness-exposed reasoning summary, when available.
    Thinking {
        task: TaskId,
        summary: String,
    },
    /// Tool call OBSERVED inside the harness (not mediated by Bastion
    /// unless bridged through MCP). Digests, not payloads.
    ToolCall {
        task: TaskId,
        name: String,
        input_digest: String,
    },
    ToolResult {
        task: TaskId,
        name: String,
        output_digest: String,
        is_error: bool,
    },
    /// Bridged permission prompt; answer via
    /// [`RuntimeSession::respond_permission`].
    PermissionRequest {
        task: TaskId,
        id: PermissionRequestId,
        action: PermissionAction,
        detail: String,
    },
    Diff {
        task: TaskId,
        path: PathBuf,
        added: u32,
        removed: u32,
    },
    Artifact {
        task: TaskId,
        artifact: Artifact,
    },
    Usage {
        task: TaskId,
        delta: UsageDelta,
    },
    Warning {
        task: TaskId,
        code: WarnCode,
        detail: String,
    },
    /// Terminal event of a task.
    ///
    /// Requirement (Ciclo 2.2, A-05 §5.4): some protocols report the same
    /// underlying status for a cooperative cancel ([`RuntimeSession::cancel`])
    /// and for the adapter's own timeout watchdog force-stopping a task. An
    /// adapter over such a protocol MUST disambiguate the two client-side
    /// (e.g. tracking which turn ids it interrupted for a timeout) so it
    /// reports `TaskOutcome::Cancelled` only for a genuine cancel and
    /// `TaskOutcome::TimedOut` for its own timeout — never conflating them
    /// because the wire status happens to match.
    Ended {
        task: TaskId,
        outcome: TaskOutcome,
    },
}

/// Factory/entry point implemented by each adapter. The kernel talks to
/// this trait only; concrete adapters are registered by the composition
/// layer (app or embedded host).
#[async_trait::async_trait]
pub trait AgentRuntime: Send + Sync {
    /// Static identity and capability card.
    fn descriptor(&self) -> RuntimeDescriptor;

    /// Cheap availability probe. Fail-closed: adapters must not open
    /// sessions when `health().ready` would be false.
    async fn health(&self) -> Result<RuntimeHealth, RuntimeError>;

    /// Open a fresh session.
    async fn start(&self, spec: SessionSpec) -> Result<Box<dyn RuntimeSession>, RuntimeError>;

    /// Reattach a persisted session. Must validate `handle.owner` and the
    /// adapter id; returns [`RuntimeError::NotResumable`] instead of ever
    /// silently starting a new session.
    ///
    /// `spec` carries the re-appliable policy subset (Ciclo 2.2 — see
    /// [`ResumeSpec`]); an adapter applies whatever its reattach protocol
    /// allows and reports the rest via [`RuntimeEvent::Warning`].
    async fn resume(
        &self,
        handle: &SessionHandle,
        spec: ResumeSpec,
    ) -> Result<Box<dyn RuntimeSession>, RuntimeError>;
}

/// One live harness session. Not `Clone`: single ownership mirrors the
/// daemon's one-`&mut`-agent serialization model.
#[async_trait::async_trait]
pub trait RuntimeSession: Send {
    /// Persistable reference for restart recovery.
    fn handle(&self) -> SessionHandle;

    /// Submit a task. Returns immediately; progress arrives via
    /// [`RuntimeSession::next_event`]. Whether concurrent submits queue or
    /// reject follows `RuntimeSupports::concurrent_sessions` — but events
    /// of distinct tasks are never interleaved out of order.
    async fn submit(&mut self, input: TaskInput) -> Result<TaskId, RuntimeError>;

    /// Next event in session order. `None` = stream closed (session over or
    /// lost — distinguishable via [`RuntimeSession::status`]). Backpressure
    /// is the adapter's job; terminal events must never be dropped.
    async fn next_event(&mut self) -> Option<RuntimeEvent>;

    /// Mid-task steering message. Errors with [`RuntimeError::Protocol`] if
    /// the adapter declared `supports.steer == false`.
    ///
    /// Requirement (Ciclo 2.2, A-05 §5.3): a harness's own turn-acceptance
    /// acknowledgment MAY arrive before its internal state machine is
    /// actually ready to accept a steer on that turn. An adapter over such a
    /// protocol MUST tolerate this transient readiness gap (e.g. a short
    /// bounded retry) rather than surfacing the harness's spurious rejection
    /// as a hard `Protocol`/`Unavailable` error on the first attempt — only
    /// a rejection that persists past the retry budget is a real error.
    async fn steer(&mut self, text: &str) -> Result<(), RuntimeError>;

    /// Cancel the running task. Idempotent; after completion `status()`
    /// reports `Cancelled` — never a phantom `Running`.
    async fn cancel(&mut self, mode: CancelMode) -> Result<(), RuntimeError>;

    /// Answer a bridged permission request.
    async fn respond_permission(
        &mut self,
        id: PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), RuntimeError>;

    async fn status(&self) -> Result<SessionStatus, RuntimeError>;
}
