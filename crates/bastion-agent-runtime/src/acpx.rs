//! `AcpxAgentRuntime` — A-04 adapter: supervises the `acpx` CLI (a headless
//! Agent Client Protocol client, <https://www.npmjs.com/package/acpx>) as a
//! per-task subprocess speaking structured NDJSON (`--format json`).
//!
//! # Transport
//!
//! `acpx --format json <agent> prompt -s <session>` prints one JSON object
//! per line on **stdout only** — the exact ACP JSON-RPC conversation acpx
//! holds with the wrapped agent (e.g. `claude-agent-acp`). Human banners
//! (`[acpx] created session ...`) go to **stderr**, verified empirically
//! (never mixed into stdout); this adapter only ever reads/parses stdout,
//! and rejects any non-JSON or ANSI-bearing line as [`RuntimeError::Protocol`]
//! (T6 of the A-01 threat model) — stderr is captured for `tracing`
//! diagnostics only, never interpreted.
//!
//! # Session model
//!
//! acpx keeps sessions itself, named (`-s <name>`) and backed by a
//! detached, auto-spawned "queue owner" node process with its own TTL. Each
//! Bastion task spawns a **fresh** `acpx ... prompt -s <name>` process; acpx
//! serializes concurrent invocations against the same named session
//! internally (empirically verified: two concurrent `prompt` calls against
//! one session both complete, and each process's stdout carries only its
//! own frames — no cross-task leakage), so `supports.concurrent_sessions =
//! true` needs no queueing logic on our side.
//!
//! # Honest coverage declarations (see [`AcpxAgentRuntime::descriptor`])
//!
//! - `supports.resume = false`: acpx's own session persistence is a
//!   best-effort, TTL-bound background daemon, not a Bastion-owned
//!   reattach contract. `resume` always returns
//!   [`RuntimeError::NotResumable`], never a silent new session.
//! - `supports.steer = false`: no ACP method observed (or documented by
//!   acpx's CLI surface) to inject text into an in-flight turn; a second
//!   `prompt` call while one is active queues a **new** turn, it does not
//!   steer the current one.
//! - `policy_coverage.approvals = HarnessOwned`: acpx only exposes static,
//!   pre-spawn permission flags (`--approve-all` / `--approve-reads` /
//!   `--deny-all` / `--permission-policy`). Empirically, even without any
//!   of those flags the agent's `session/request_permission` calls are
//!   resolved *by acpx itself* before the invocation completes — there is
//!   no observed way to intercept a request and answer it from the
//!   supervising process over this transport. `respond_permission` is
//!   therefore always an error; `PermissionRequest` events are still
//!   emitted (from the observed, already-resolved request) purely for
//!   observability.
//! - `policy_coverage.sandbox = None`: acpx passes `--cwd` as a hint, not an
//!   enforced jail (no bubblewrap/chroot observed); nothing stops the
//!   wrapped agent writing outside the workspace root via an absolute path.
//!   Unlike [`crate::codex`] (Ciclo 2.2), this is NOT probed at `health()`
//!   time — acpx itself never invokes any confinement mechanism regardless
//!   of host capability, so `None` is the honest answer independent of what
//!   the host could support; there is nothing host-dependent to detect.
//! - `policy_coverage.egress = HarnessOwned`: once a turn starts, the
//!   wrapped agent (e.g. Claude Code) has its own model/tool network
//!   authority; Bastion only filters what enters via `TaskInput`.
//!
//! # Operational requirement (contract finding)
//!
//! acpx is a Node shebang script; this adapter resolves the interpreter at
//! construction time from the **host** `PATH` and invokes it directly, so
//! the spawned child needs no `PATH` of its own. It still needs a `HOME` it
//! can write to for its own config/session store (`~/.acpx`, per-agent
//! session records) — callers must include `HOME` in
//! [`crate::EnvPolicy::allow`] or session creation fails with
//! [`RuntimeError::Unavailable`]. `HOME` is not a credential; this is a
//! functional requirement, not a security bypass.
//!
//! # `--auth-policy` is per-agent, not a crate-wide constant (A-05 §2A fix)
//!
//! acpx's own `--auth-policy` flag controls how it reacts when the wrapped
//! agent's ACP `initialize` advertises `authMethods` acpx doesn't recognize
//! in its own credential store: `fail` aborts the whole invocation before
//! `session/prompt` is ever sent, `skip` proceeds and lets the wrapped
//! agent's own already-persisted credentials answer the ACP handshake
//! itself. This adapter used to hardcode `fail` for every wrapped agent.
//! That is the right, fail-closed default for an agent whose credential
//! posture is unknown (or, like `claude`, spawned through a built-in acpx
//! bridge — [`@agentclientprotocol/claude-agent-acp`] — that never
//! advertises `authMethods` in the first place, so the flag is inert either
//! way). It actively breaks `opencode`: its native ACP server (`opencode
//! acp`) DOES advertise `authMethods: [{"id": "opencode-login", ...}]`, acpx
//! tries to match that against its own store, finds nothing (opencode keeps
//! a separate `~/.local/share/opencode/auth.json` acpx's matcher doesn't
//! know about), and `fail` aborts before the real, working, host-persisted
//! opencode credentials ever get a chance to answer — verified live
//! (`docs/revamp/A-05-conformance-matrix.md` §2A): the identical invocation
//! with `--auth-policy skip` completes a full turn using those same
//! credentials. [`default_auth_policy_for`] picks `"skip"` for `"opencode"`
//! and `"fail"` for everything else (never a security relaxation for an
//! agent that didn't ask for it); [`AcpxAgentRuntime::with_auth_policy`]
//! lets a caller override either way for a specific deployment.

use crate::conformance::FaultInjection;
use crate::util::{
    parse_structured_line, resolve_on_path, resolve_shebang_interpreter, sha256_digest,
    version_satisfies,
};
use crate::*;
use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// Supported `acpx` CLI version range. `health()` compares the real
/// `acpx --version` output against this pin (A-01 T9).
const ACPX_VERSION_REQ: &str = ">=0.12.0, <0.13.0";

/// Per-agent default for acpx's `--auth-policy` flag (module docs —
/// "`--auth-policy` is per-agent"). `"fail"` stays the fail-closed default
/// for every agent whose credential-matching posture with acpx is unknown;
/// `"opencode"` is the one documented exception (A-05 §2A) — its native ACP
/// server advertises `authMethods` acpx cannot match against its own store,
/// so `fail` aborts before its real, working, host-persisted credentials
/// ever get a chance to answer.
fn default_auth_policy_for(agent: &str) -> &'static str {
    match agent {
        "opencode" => "skip",
        _ => "fail",
    }
}

/// Adapter for one ACP agent wrapped by `acpx` (e.g. `"claude"`,
/// `"opencode"`). Stateless/`Clone`-free factory; sessions are independent
/// [`AcpxSession`] instances.
pub struct AcpxAgentRuntime {
    acpx_bin: PathBuf,
    /// `Some(interpreter)` when `acpx_bin` is a `#!`-script (true for the
    /// npm-distributed `acpx`); spawned as `interpreter acpx_bin ...` so the
    /// child never needs `PATH` to find its own interpreter.
    interpreter: Option<PathBuf>,
    agent: String,
    /// `acpx --auth-policy` value threaded into every `prompt` invocation
    /// this adapter spawns (module docs). Defaults per
    /// [`default_auth_policy_for`]; override with [`Self::with_auth_policy`].
    auth_policy: &'static str,
}

impl AcpxAgentRuntime {
    /// Resolves `acpx` from the host `PATH` and targets `agent` (an acpx
    /// agent subcommand, e.g. `"claude"`, `"opencode"`, `"codex"`).
    pub fn new(agent: impl Into<String>) -> Result<Self, RuntimeError> {
        Self::with_binary(resolve_on_path("acpx")?, agent)
    }

    /// Same as [`Self::new`] but with an explicit path to the `acpx`
    /// binary/script (useful in tests or non-standard installs).
    pub(crate) fn with_binary(
        acpx_bin: PathBuf,
        agent: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let interpreter = resolve_shebang_interpreter(&acpx_bin)?;
        let agent = agent.into();
        let auth_policy = default_auth_policy_for(&agent);
        Ok(Self {
            acpx_bin,
            interpreter,
            agent,
            auth_policy,
        })
    }

    /// Overrides the `--auth-policy` value this adapter passes to every
    /// spawned `acpx prompt` invocation, replacing whatever
    /// [`default_auth_policy_for`] picked. For a deployment that needs a
    /// different posture than the built-in per-agent default (e.g. a new
    /// acpx-wrapped agent this adapter doesn't special-case yet) — never
    /// required for `"claude"`/`"opencode"` in their default configuration.
    pub fn with_auth_policy(mut self, policy: &'static str) -> Self {
        self.auth_policy = policy;
        self
    }

    fn descriptor_id(&self) -> &'static str {
        match self.agent.as_str() {
            "claude" => "acpx_claude",
            "opencode" => "acpx_opencode",
            "codex" => "acpx_codex",
            "gemini" => "acpx_gemini",
            _ => "acpx_client",
        }
    }

    /// Base `acpx` invocation (interpreter-aware), env NOT yet configured.
    fn base_command(&self) -> Command {
        let mut cmd = match &self.interpreter {
            Some(interp) => {
                let mut c = Command::new(interp);
                c.arg(&self.acpx_bin);
                c
            }
            None => Command::new(&self.acpx_bin),
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
}

#[async_trait]
impl AgentRuntime for AcpxAgentRuntime {
    fn descriptor(&self) -> RuntimeDescriptor {
        RuntimeDescriptor {
            id: self.descriptor_id(),
            adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            target_version: format!("acpx {ACPX_VERSION_REQ}"),
            transport: Transport::JsonRpcSubprocess,
            supports: RuntimeSupports {
                resume: false,
                steer: false,
                usage_reporting: true,
                diff_events: true,
                permission_bridge: false,
                concurrent_sessions: true,
            },
            policy_coverage: PolicyCoverage {
                tool_visibility: ToolVisibility::DeclaredOnly,
                approvals: ApprovalCoverage::HarnessOwned,
                egress: EgressCoverage::HarnessOwned,
                budget: BudgetCoverage::Reported,
                sandbox: SandboxCoverage::None,
            },
        }
    }

    async fn health(&self) -> Result<RuntimeHealth, RuntimeError> {
        let mut cmd = self.base_command();
        cmd.env_clear();
        cmd.arg("--version");
        let output = cmd
            .output()
            .await
            .map_err(|e| RuntimeError::Unavailable(format!("failed to spawn acpx: {e}")))?;
        if !output.status.success() {
            return Ok(RuntimeHealth {
                detected_version: "unknown".to_string(),
                ready: false,
                detail: Some("acpx --version exited non-zero".to_string()),
            });
        }
        let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match version_satisfies(&raw, ACPX_VERSION_REQ) {
            Ok(true) => Ok(RuntimeHealth {
                detected_version: raw,
                ready: true,
                detail: None,
            }),
            Ok(false) => Ok(RuntimeHealth {
                detected_version: raw.clone(),
                ready: false,
                detail: Some(format!(
                    "acpx {raw} outside supported range {ACPX_VERSION_REQ}"
                )),
            }),
            Err(e) => Ok(RuntimeHealth {
                detected_version: raw,
                ready: false,
                detail: Some(e.to_string()),
            }),
        }
    }

    async fn start(&self, spec: SessionSpec) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        let health = self.health().await?;
        if !health.ready {
            let detail = health.detail.unwrap_or_default();
            return Err(if detail.contains("range") {
                RuntimeError::Version(detail)
            } else {
                RuntimeError::Unavailable(detail)
            });
        }

        let session_name = format!(
            "bastion-{}-{}",
            sanitize_for_session_name(&spec.owner),
            unique_suffix()
        );

        let mut ensure_cmd = self.base_command();
        ensure_cmd.env_clear();
        for (k, v) in &spec.env.allow {
            ensure_cmd.env(k, v);
        }
        ensure_cmd
            .arg("--cwd")
            .arg(&spec.workspace.root)
            .arg(&self.agent)
            .arg("sessions")
            .arg("ensure")
            .arg("--name")
            .arg(&session_name);
        let output = ensure_cmd.output().await.map_err(|e| {
            RuntimeError::Unavailable(format!("failed to spawn acpx sessions ensure: {e}"))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let snippet: String = stderr.chars().take(200).collect();
            return Err(RuntimeError::Unavailable(format!(
                "acpx sessions ensure failed: {snippet}"
            )));
        }

        let handle = SessionHandle {
            runtime_id: self.descriptor_id().to_string(),
            owner: spec.owner.clone(),
            external_ref: session_name.clone(),
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = tx.send(RuntimeEvent::Started {
            handle: handle.clone(),
        });

        Ok(Box::new(AcpxSession {
            acpx_bin: self.acpx_bin.clone(),
            interpreter: self.interpreter.clone(),
            agent: self.agent.clone(),
            auth_policy: self.auth_policy,
            handle,
            session_name,
            workspace_root: spec.workspace.root.clone(),
            permissions: spec.permissions.clone(),
            env_allow: spec.env.allow.clone(),
            per_task_timeout: spec.timeout.per_task,
            next_task_id: 0,
            status: Arc::new(AsyncMutex::new(SessionStatus::Running)),
            garbage: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AsyncMutex::new(Vec::new())),
            event_tx: tx,
            event_rx: rx,
        }))
    }

    async fn resume(
        &self,
        _handle: &SessionHandle,
        _spec: ResumeSpec,
    ) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        Err(RuntimeError::NotResumable(
            "acpx adapter does not support session reattachment across process restarts \
             (acpx's own session persistence is a best-effort, TTL-bound background daemon, \
             not a Bastion-owned reattach contract)"
                .to_string(),
        ))
    }
}

#[async_trait]
impl FaultInjection for AcpxAgentRuntime {
    // All defaults (false): inducing a crash/auth-failure/garbage-frame on a
    // *live* external harness is out of scope for this adapter — those
    // conformance checks report Skip against it. See docs/revamp/A-05.
}

fn sanitize_for_session_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    if cleaned.is_empty() {
        "owner".to_string()
    } else {
        cleaned
    }
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}-{n}")
}

/// Maps a [`PermissionProfile`] onto acpx's coarse static approval flags.
/// acpx has no fine-grained allowlist-by-action-id surface reachable from a
/// non-interactive invocation (see module docs) — this is a documented,
/// honest simplification, not a security relaxation: an empty/absent
/// profile always denies.
fn permission_flags(profile: &PermissionProfile) -> Vec<String> {
    if profile.allow.iter().any(|a| a == "*") {
        vec!["--approve-all".to_string()]
    } else if profile.allow.is_empty() {
        vec!["--deny-all".to_string()]
    } else {
        // Non-empty, non-wildcard: allow reads, still deny writes
        // non-interactively (safe default given no fine-grained mapping).
        vec!["--approve-reads".to_string()]
    }
}

// ---------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------

struct ActiveChild {
    task_id: TaskId,
    child: Arc<AsyncMutex<Child>>,
    cancel_requested: Arc<AtomicBool>,
}

pub(crate) struct AcpxSession {
    acpx_bin: PathBuf,
    interpreter: Option<PathBuf>,
    agent: String,
    /// Copied from [`AcpxAgentRuntime::auth_policy`] at [`AcpxAgentRuntime::start`]
    /// time — see the module docs for why this is per-agent, not hardcoded.
    auth_policy: &'static str,
    handle: SessionHandle,
    session_name: String,
    workspace_root: PathBuf,
    permissions: PermissionProfile,
    env_allow: BTreeMap<String, String>,
    per_task_timeout: Duration,
    next_task_id: u64,
    status: Arc<AsyncMutex<SessionStatus>>,
    garbage: Arc<AtomicBool>,
    active: Arc<AsyncMutex<Vec<ActiveChild>>>,
    event_tx: mpsc::UnboundedSender<RuntimeEvent>,
    event_rx: mpsc::UnboundedReceiver<RuntimeEvent>,
}

impl AcpxSession {
    fn base_command(&self) -> Command {
        let mut cmd = match &self.interpreter {
            Some(interp) => {
                let mut c = Command::new(interp);
                c.arg(&self.acpx_bin);
                c
            }
            None => Command::new(&self.acpx_bin),
        };
        cmd.env_clear();
        for (k, v) in &self.env_allow {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }

    fn build_prompt_command(&self, prompt: &str) -> Command {
        let mut cmd = self.base_command();
        cmd.arg("--format")
            .arg("json")
            .arg("--cwd")
            .arg(&self.workspace_root)
            .arg("--auth-policy")
            .arg(self.auth_policy)
            .arg("--non-interactive-permissions")
            .arg("deny");
        for flag in permission_flags(&self.permissions) {
            cmd.arg(flag);
        }
        cmd.arg(&self.agent)
            .arg("prompt")
            .arg("-s")
            .arg(&self.session_name)
            .arg(prompt);
        cmd
    }

    async fn send_companion_cancel(&self) {
        let mut cmd = self.base_command();
        cmd.arg("--cwd")
            .arg(&self.workspace_root)
            .arg(&self.agent)
            .arg("cancel")
            .arg("-s")
            .arg(&self.session_name);
        if let Ok(mut child) = cmd.spawn() {
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        }
    }
}

#[async_trait]
impl RuntimeSession for AcpxSession {
    fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }

    async fn submit(&mut self, input: TaskInput) -> Result<TaskId, RuntimeError> {
        if self.garbage.load(Ordering::SeqCst) {
            return Err(RuntimeError::Protocol(
                "malformed frame pending on acpx transport".to_string(),
            ));
        }
        {
            let status = self.status.lock().await;
            if *status == SessionStatus::Crashed {
                return Err(RuntimeError::Crashed("session already crashed".to_string()));
            }
        }

        let task_id = TaskId(self.next_task_id);
        self.next_task_id += 1;

        let mut cmd = self.build_prompt_command(&input.prompt);
        let mut child = cmd
            .spawn()
            .map_err(|e| RuntimeError::Unavailable(format!("failed to spawn acpx prompt: {e}")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("acpx child has no stdout".to_string()))?;

        let cancel_requested = Arc::new(AtomicBool::new(false));
        let child_arc = Arc::new(AsyncMutex::new(child));
        self.active.lock().await.push(ActiveChild {
            task_id,
            child: Arc::clone(&child_arc),
            cancel_requested: Arc::clone(&cancel_requested),
        });

        let tx = self.event_tx.clone();
        let workspace_root = self.workspace_root.clone();
        let deadline = tokio::time::Instant::now() + self.per_task_timeout;
        let active_list = Arc::clone(&self.active);
        let garbage = Arc::clone(&self.garbage);
        let status = Arc::clone(&self.status);

        tokio::spawn(async move {
            run_prompt_reader(
                task_id,
                stdout,
                tx,
                workspace_root,
                deadline,
                cancel_requested,
                child_arc,
                garbage,
            )
            .await;
            active_list.lock().await.retain(|c| c.task_id != task_id);
            let mut st = status.lock().await;
            if *st == SessionStatus::Running {
                *st = SessionStatus::Idle;
            }
        });

        {
            let mut st = self.status.lock().await;
            *st = SessionStatus::Running;
        }

        Ok(task_id)
    }

    async fn next_event(&mut self) -> Option<RuntimeEvent> {
        self.event_rx.recv().await
    }

    async fn steer(&mut self, _text: &str) -> Result<(), RuntimeError> {
        Err(RuntimeError::Protocol(
            "acpx adapter declares supports.steer=false: no in-flight-turn injection method \
             observed on this transport"
                .to_string(),
        ))
    }

    async fn cancel(&mut self, mode: CancelMode) -> Result<(), RuntimeError> {
        let snapshot: Vec<(TaskId, Arc<AsyncMutex<Child>>, Arc<AtomicBool>)> = {
            let active = self.active.lock().await;
            active
                .iter()
                .map(|c| {
                    (
                        c.task_id,
                        Arc::clone(&c.child),
                        Arc::clone(&c.cancel_requested),
                    )
                })
                .collect()
        };
        for (_, _, flag) in &snapshot {
            flag.store(true, Ordering::SeqCst);
        }

        match mode {
            CancelMode::Graceful { grace } => {
                if !snapshot.is_empty() {
                    self.send_companion_cancel().await;
                }
                let deadline = tokio::time::Instant::now() + grace;
                for (_, child, _) in &snapshot {
                    let mut c = child.lock().await;
                    let _ = tokio::time::timeout_at(deadline, c.wait()).await;
                    let _ = c.start_kill();
                }
            }
            CancelMode::Kill => {
                for (_, child, _) in &snapshot {
                    let mut c = child.lock().await;
                    let _ = c.start_kill();
                }
            }
        }

        let mut status = self.status.lock().await;
        if *status != SessionStatus::Crashed {
            *status = SessionStatus::Cancelled;
        }
        Ok(())
    }

    async fn respond_permission(
        &mut self,
        _id: PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Protocol(
            "acpx approvals are HarnessOwned (static --approve-all/--deny-all resolved at \
             spawn time): there is no pending request to answer"
                .to_string(),
        ))
    }

    async fn status(&self) -> Result<SessionStatus, RuntimeError> {
        if self.garbage.load(Ordering::SeqCst) {
            return Err(RuntimeError::Protocol(
                "malformed frame received on acpx transport".to_string(),
            ));
        }
        Ok(*self.status.lock().await)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_prompt_reader(
    task: TaskId,
    stdout: tokio::process::ChildStdout,
    tx: mpsc::UnboundedSender<RuntimeEvent>,
    workspace_root: PathBuf,
    deadline: tokio::time::Instant,
    cancel_requested: Arc<AtomicBool>,
    child: Arc<AsyncMutex<Child>>,
    garbage: Arc<AtomicBool>,
) {
    let mut lines = BufReader::new(stdout).lines();
    let mut interp = FrameInterpreter::new(task);
    let mut ended = false;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                let mut c = child.lock().await;
                let _ = c.start_kill();
                let _ = tx.send(RuntimeEvent::Ended { task, outcome: TaskOutcome::TimedOut });
                ended = true;
                break;
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(raw)) => {
                        match parse_structured_line(&raw) {
                            Ok(value) => {
                                let outcome = interp.on_value(&value);
                                for evt in outcome.events {
                                    let _ = tx.send(evt);
                                }
                                if let Some(abs_path) = outcome.artifact_candidate {
                                    if let Ok(bytes) = tokio::fs::read(&abs_path).await {
                                        let rel = abs_path
                                            .strip_prefix(&workspace_root)
                                            .map(Path::to_path_buf)
                                            .unwrap_or(abs_path);
                                        let _ = tx.send(RuntimeEvent::Artifact {
                                            task,
                                            artifact: Artifact {
                                                kind: ArtifactKind::File,
                                                path: rel,
                                                digest: sha256_digest(&bytes),
                                                produced_by: None,
                                            },
                                        });
                                    }
                                }
                                if interp.ended {
                                    ended = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(target: "bastion_agent_runtime::acpx", error = %e, "rejecting non-structured frame");
                                garbage.store(true, Ordering::SeqCst);
                                let _ = child.lock().await.start_kill();
                                break;
                            }
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(e) => {
                        tracing::warn!(target: "bastion_agent_runtime::acpx", error = %e, "stdout read error");
                        break;
                    }
                }
            }
        }
    }

    if !ended {
        let outcome = if cancel_requested.load(Ordering::SeqCst) {
            TaskOutcome::Cancelled
        } else if garbage.load(Ordering::SeqCst) {
            // status()/submit() already fail-closed via the `garbage` flag;
            // still emit a terminal event so the task is never left hanging.
            TaskOutcome::Failed {
                reason: "malformed frame on transport".to_string(),
            }
        } else {
            TaskOutcome::Failed {
                reason: "acpx process ended without a terminal frame (crash or premature exit)"
                    .to_string(),
            }
        };
        let _ = tx.send(RuntimeEvent::Ended { task, outcome });
    }
}

// ---------------------------------------------------------------------
// Frame interpreter — pure, unit-testable mapping of one already-validated
// JSON value (an ACP protocol line, as printed by `acpx --format json`)
// onto zero or more RuntimeEvents.
// ---------------------------------------------------------------------

#[derive(Default)]
struct LineOutcome {
    events: Vec<RuntimeEvent>,
    /// Absolute path of a file a completed write/edit tool call touched;
    /// the async caller re-reads it to emit a digested `Artifact` event.
    artifact_candidate: Option<PathBuf>,
}

struct FrameInterpreter {
    task: TaskId,
    /// JSON-RPC id of our own `session/prompt` request, captured once we
    /// observe acpx print it (we never construct the request ourselves —
    /// acpx generates it as the ACP client and logs it to stdout).
    prompt_id: Option<i64>,
    next_perm_id: u64,
    ended: bool,
    /// `toolCallId -> file_path`, threaded across the multi-frame
    /// `tool_call`/`tool_call_update` sequence: the frame carrying
    /// `rawInput.file_path` is NOT the same frame that carries the terminal
    /// `status: "completed"` (verified empirically — the completion frame
    /// only carries `rawOutput`). We must join them by `toolCallId`.
    tool_file_paths: HashMap<String, PathBuf>,
}

impl FrameInterpreter {
    fn new(task: TaskId) -> Self {
        Self {
            task,
            prompt_id: None,
            next_perm_id: 0,
            ended: false,
            tool_file_paths: HashMap::new(),
        }
    }

    /// Records `rawInput.file_path` for this `toolCallId`, if present, so a
    /// later frame carrying only the terminal `status` (no `rawInput`) can
    /// still be joined back to the file it acted on.
    fn remember_file_path(&mut self, update: &serde_json::Value) {
        let (Some(id), Some(path)) = (
            update.get("toolCallId").and_then(|i| i.as_str()),
            update
                .get("rawInput")
                .and_then(|r| r.get("file_path"))
                .and_then(|f| f.as_str()),
        ) else {
            return;
        };
        self.tool_file_paths
            .insert(id.to_string(), PathBuf::from(path));
    }

    fn on_value(&mut self, v: &serde_json::Value) -> LineOutcome {
        let mut out = LineOutcome::default();
        if self.ended {
            return out;
        }

        let method = v.get("method").and_then(|m| m.as_str());

        if self.prompt_id.is_none() && method == Some("session/prompt") {
            self.prompt_id = v.get("id").and_then(|i| i.as_i64());
        }

        // Terminal response/error correlated to our own prompt request.
        if let (Some(pid), Some(id)) = (self.prompt_id, v.get("id").and_then(|i| i.as_i64())) {
            if id == pid && (v.get("result").is_some() || v.get("error").is_some()) {
                if let Some(result) = v.get("result") {
                    if let Some(usage) = result.get("usage") {
                        out.events.push(RuntimeEvent::Usage {
                            task: self.task,
                            delta: UsageDelta {
                                input_tokens: usage
                                    .get("inputTokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0),
                                output_tokens: usage
                                    .get("outputTokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0),
                            },
                        });
                    }
                    let stop_reason = result
                        .get("stopReason")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");
                    let outcome = match stop_reason {
                        "end_turn" => TaskOutcome::Success,
                        "cancelled" => TaskOutcome::Cancelled,
                        other => TaskOutcome::Failed {
                            reason: format!("stopReason={other}"),
                        },
                    };
                    out.events.push(RuntimeEvent::Ended {
                        task: self.task,
                        outcome,
                    });
                    self.ended = true;
                    return out;
                }
                if let Some(error) = v.get("error") {
                    let msg = error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown error");
                    let reason = if is_auth_like(msg) {
                        "authentication error reported by harness".to_string()
                    } else {
                        msg.to_string()
                    };
                    out.events.push(RuntimeEvent::Ended {
                        task: self.task,
                        outcome: TaskOutcome::Failed { reason },
                    });
                    self.ended = true;
                    return out;
                }
            }
        }

        if method == Some("session/update") {
            if let Some(update) = v.get("params").and_then(|p| p.get("update")) {
                match update.get("sessionUpdate").and_then(|s| s.as_str()) {
                    Some("agent_message_chunk") => {
                        if let Some(text) = update
                            .get("content")
                            .and_then(|c| c.get("text"))
                            .and_then(|t| t.as_str())
                        {
                            if !text.is_empty() {
                                out.events.push(RuntimeEvent::MessageDelta {
                                    task: self.task,
                                    text: text.to_string(),
                                });
                            }
                        }
                    }
                    Some("tool_call") => {
                        let name = tool_name(update);
                        let input_digest = sha256_digest(
                            update
                                .get("rawInput")
                                .map(|v| v.to_string())
                                .unwrap_or_default()
                                .as_bytes(),
                        );
                        self.remember_file_path(update);
                        out.events.push(RuntimeEvent::ToolCall {
                            task: self.task,
                            name,
                            input_digest,
                        });
                    }
                    Some("tool_call_update") => {
                        self.remember_file_path(update);
                        if let Some(contents) = update.get("content").and_then(|c| c.as_array()) {
                            for entry in contents {
                                if entry.get("type").and_then(|t| t.as_str()) == Some("diff") {
                                    let path = entry
                                        .get("path")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or_default();
                                    let old_text = entry.get("oldText").and_then(|t| t.as_str());
                                    let new_text =
                                        entry.get("newText").and_then(|t| t.as_str()).unwrap_or("");
                                    let (added, removed) = line_diff_counts(old_text, new_text);
                                    out.events.push(RuntimeEvent::Diff {
                                        task: self.task,
                                        path: PathBuf::from(path),
                                        added,
                                        removed,
                                    });
                                }
                            }
                        }
                        if let Some(status) = update.get("status").and_then(|s| s.as_str()) {
                            let name = tool_name(update);
                            if status == "completed" || status == "failed" {
                                let raw_output = update
                                    .get("rawOutput")
                                    .map(|v| v.to_string())
                                    .unwrap_or_default();
                                out.events.push(RuntimeEvent::ToolResult {
                                    task: self.task,
                                    name,
                                    output_digest: sha256_digest(raw_output.as_bytes()),
                                    is_error: status == "failed",
                                });
                            }
                            // The frame carrying the terminal `status` is
                            // NOT the same frame that carried `rawInput`
                            // (verified empirically) — join by toolCallId.
                            if status == "completed" {
                                if let Some(id) = update.get("toolCallId").and_then(|i| i.as_str())
                                {
                                    if let Some(path) = self.tool_file_paths.get(id) {
                                        out.artifact_candidate = Some(path.clone());
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            return out;
        }

        if method == Some("session/request_permission") {
            if let Some(params) = v.get("params") {
                let detail = params
                    .get("toolCall")
                    .and_then(|t| t.get("title"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("permission request")
                    .to_string();
                let kind = params
                    .get("toolCall")
                    .and_then(|t| t.get("kind"))
                    .and_then(|k| k.as_str())
                    .unwrap_or("");
                let action = match kind {
                    "edit" => PermissionAction::WriteFile,
                    "execute" => PermissionAction::RunCommand,
                    other => PermissionAction::Other(other.to_string()),
                };
                let id = PermissionRequestId(self.next_perm_id);
                self.next_perm_id += 1;
                out.events.push(RuntimeEvent::PermissionRequest {
                    task: self.task,
                    id,
                    action,
                    detail,
                });
            }
        }

        out
    }
}

fn tool_name(update: &serde_json::Value) -> String {
    update
        .get("title")
        .and_then(|t| t.as_str())
        .or_else(|| {
            update
                .get("_meta")
                .and_then(|m| m.get("claudeCode"))
                .and_then(|c| c.get("toolName"))
                .and_then(|t| t.as_str())
        })
        .unwrap_or("tool")
        .to_string()
}

fn is_auth_like(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    ["auth", "login", "unauthorized", "401", "credential"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Heuristic multiset line diff (not a positional LCS) — good enough for
/// the [`RuntimeEvent::Diff`] telemetry counts; never used for anything
/// safety-critical (approvals stay governed by `PolicyCoverage`, not by
/// this count).
fn line_diff_counts(old: Option<&str>, new: &str) -> (u32, u32) {
    match old {
        None => (new.lines().count() as u32, 0),
        Some(old) => {
            let mut counts: HashMap<&str, i64> = HashMap::new();
            for l in old.lines() {
                *counts.entry(l).or_insert(0) -= 1;
            }
            for l in new.lines() {
                *counts.entry(l).or_insert(0) += 1;
            }
            let added = counts.values().filter(|&&c| c > 0).map(|&c| c as u32).sum();
            let removed = counts
                .values()
                .filter(|&&c| c < 0)
                .map(|&c| (-c) as u32)
                .sum();
            (added, removed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn line(v: serde_json::Value) -> LineOutcome {
        let mut interp = FrameInterpreter::new(TaskId(0));
        interp.on_value(&v)
    }

    #[test]
    fn happy_path_frames_map_to_events() {
        let mut interp = FrameInterpreter::new(TaskId(0));

        let prompt_req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "session/prompt",
            "params": {"sessionId": "s1", "prompt": [{"type":"text","text":"hi"}]}
        });
        assert!(interp.on_value(&prompt_req).events.is_empty());
        assert_eq!(interp.prompt_id, Some(2));

        let delta = json!({
            "jsonrpc":"2.0","method":"session/update",
            "params":{"sessionId":"s1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"ok"}}}
        });
        let out = interp.on_value(&delta);
        assert_eq!(out.events.len(), 1);
        assert!(matches!(&out.events[0], RuntimeEvent::MessageDelta{text, ..} if text == "ok"));

        let empty_delta = json!({
            "jsonrpc":"2.0","method":"session/update",
            "params":{"sessionId":"s1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":""}}}
        });
        assert!(interp.on_value(&empty_delta).events.is_empty());

        let terminal = json!({
            "jsonrpc":"2.0","id":2,
            "result":{"stopReason":"end_turn","usage":{"inputTokens":6,"outputTokens":6,"totalTokens":12}}
        });
        let out = interp.on_value(&terminal);
        assert_eq!(out.events.len(), 2);
        assert!(
            matches!(&out.events[0], RuntimeEvent::Usage{delta, ..} if delta.input_tokens == 6 && delta.output_tokens == 6)
        );
        assert!(matches!(
            &out.events[1],
            RuntimeEvent::Ended {
                outcome: TaskOutcome::Success,
                ..
            }
        ));
        assert!(interp.ended);

        // Nothing further is interpreted once ended.
        assert!(interp.on_value(&delta).events.is_empty());
    }

    #[test]
    fn cancelled_stop_reason_maps_to_cancelled_outcome() {
        let mut interp = FrameInterpreter::new(TaskId(0));
        interp.on_value(&json!({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{}}));
        let out = interp.on_value(&json!({
            "jsonrpc":"2.0","id":3,
            "result":{"stopReason":"cancelled","usage":{"inputTokens":0,"outputTokens":0}}
        }));
        assert!(matches!(
            &out.events[1],
            RuntimeEvent::Ended {
                outcome: TaskOutcome::Cancelled,
                ..
            }
        ));
    }

    #[test]
    fn error_frame_maps_to_failed_and_redacts_auth_message() {
        let mut interp = FrameInterpreter::new(TaskId(0));
        interp.on_value(&json!({"jsonrpc":"2.0","id":5,"method":"session/prompt","params":{}}));
        let out = interp.on_value(&json!({
            "jsonrpc":"2.0","id":5,
            "error":{"code":-32000,"message":"Unauthorized: token sk-abc123 rejected"}
        }));
        match &out.events[0] {
            RuntimeEvent::Ended {
                outcome: TaskOutcome::Failed { reason },
                ..
            } => {
                assert!(!reason.contains("sk-abc123"));
                assert!(reason.contains("authentication"));
            }
            other => panic!("expected Ended/Failed, got {other:?}"),
        }
    }

    /// Reproduces the exact multi-frame `tool_call` → `tool_call_update`
    /// (diff, pre-permission) → `tool_call_update` (post-permission,
    /// `_meta` only) → `tool_call_update` (`status: "completed"`, no
    /// `rawInput`) sequence captured live from `acpx --format json claude
    /// prompt` for a Write tool call. The completion frame does NOT repeat
    /// `rawInput` — the artifact path must be joined by `toolCallId` from
    /// an earlier frame (regression test for that bug).
    #[test]
    fn tool_call_and_result_map_with_digests() {
        let mut interp = FrameInterpreter::new(TaskId(0));

        let pending = json!({
            "jsonrpc":"2.0","method":"session/update",
            "params":{"update":{"_meta":{"claudeCode":{"toolName":"Write"}},"toolCallId":"t1","sessionUpdate":"tool_call","rawInput":{},"status":"pending","title":"Write","kind":"edit","content":[],"locations":[]}}
        });
        let out = interp.on_value(&pending);
        assert!(matches!(&out.events[0], RuntimeEvent::ToolCall{name, ..} if name == "Write"));
        assert!(out.artifact_candidate.is_none());

        let with_diff = json!({
            "jsonrpc":"2.0","method":"session/update",
            "params":{"update":{"_meta":{"claudeCode":{"toolName":"Write"}},"toolCallId":"t1","sessionUpdate":"tool_call_update","rawInput":{"file_path":"/x/hello.txt","content":"hi"},"title":"Write hello.txt","kind":"edit","content":[{"type":"diff","path":"/x/hello.txt","oldText":null,"newText":"hi"}],"locations":[{"path":"/x/hello.txt"}]}}
        });
        let out = interp.on_value(&with_diff);
        assert!(out.events.iter().any(
            |e| matches!(e, RuntimeEvent::Diff{added, removed, ..} if *added == 1 && *removed == 0)
        ));
        assert!(
            out.artifact_candidate.is_none(),
            "no status yet, not a candidate"
        );

        // Post-permission `_meta`-only frame (no status, no rawInput) — must
        // not clear what we already remembered.
        let post_permission = json!({
            "jsonrpc":"2.0","method":"session/update",
            "params":{"update":{"_meta":{"claudeCode":{"toolResponse":{"type":"create"},"toolName":"Write"}},"toolCallId":"t1","sessionUpdate":"tool_call_update"}}
        });
        assert!(interp.on_value(&post_permission).events.is_empty());

        let completed = json!({
            "jsonrpc":"2.0","method":"session/update",
            "params":{"update":{"_meta":{"claudeCode":{"toolName":"Write"}},"toolCallId":"t1","sessionUpdate":"tool_call_update","status":"completed","rawOutput":"File created successfully"}}
        });
        let out = interp.on_value(&completed);
        assert!(out.events.iter().any(|e| matches!(
            e,
            RuntimeEvent::ToolResult {
                is_error: false,
                ..
            }
        )));
        assert_eq!(out.artifact_candidate, Some(PathBuf::from("/x/hello.txt")));
    }

    #[test]
    fn permission_request_is_surfaced_for_observability() {
        let out = line(json!({
            "jsonrpc":"2.0","id":0,"method":"session/request_permission",
            "params":{"toolCall":{"title":"Write hello.txt","kind":"edit"}}
        }));
        assert!(matches!(
            &out.events[0],
            RuntimeEvent::PermissionRequest {
                action: PermissionAction::WriteFile,
                ..
            }
        ));
    }

    #[test]
    fn unknown_frames_are_ignored_not_errors() {
        let out = line(json!({"jsonrpc":"2.0","method":"account/rateLimits/updated","params":{}}));
        assert!(out.events.is_empty());
    }

    #[test]
    fn garbage_line_rejected_by_parse_structured_line() {
        let err = parse_structured_line("[acpx] agent: claude").unwrap_err();
        assert!(matches!(err, RuntimeError::Protocol(_)));
        let err = parse_structured_line("\u{1b}[31mERROR\u{1b}[0m").unwrap_err();
        assert!(matches!(err, RuntimeError::Protocol(_)));
    }

    #[test]
    fn permission_flags_mapping() {
        assert_eq!(
            permission_flags(&PermissionProfile { allow: vec![] }),
            vec!["--deny-all"]
        );
        assert_eq!(
            permission_flags(&PermissionProfile {
                allow: vec!["*".to_string()]
            }),
            vec!["--approve-all"]
        );
        assert_eq!(
            permission_flags(&PermissionProfile {
                allow: vec!["fs.read".to_string()]
            }),
            vec!["--approve-reads"]
        );
    }

    #[test]
    fn descriptor_ids_are_per_agent() {
        // Constructing via with_binary avoids depending on a real `acpx` on
        // PATH for this unit test; interpreter resolution against a
        // non-script path degrades gracefully to `None`.
        let tmp = std::env::temp_dir().join("not-a-real-acpx-binary-marker");
        let _ = std::fs::write(&tmp, b"not a script");
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "claude").expect("construct");
        assert_eq!(rt.descriptor_id(), "acpx_claude");
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "opencode").expect("construct");
        assert_eq!(rt.descriptor_id(), "acpx_opencode");
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "mystery").expect("construct");
        assert_eq!(rt.descriptor_id(), "acpx_client");
        let _ = std::fs::remove_file(&tmp);
    }

    /// A-05 §2A fix: `--auth-policy` defaults to `"fail"` (fail-closed) for
    /// every agent except `opencode`, which defaults to `"skip"` — never the
    /// other way around, and never a blanket relaxation for agents that
    /// didn't ask for it.
    #[test]
    fn auth_policy_defaults_are_per_agent_fail_closed() {
        let tmp = std::env::temp_dir().join("not-a-real-acpx-binary-marker-auth-policy");
        let _ = std::fs::write(&tmp, b"not a script");

        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "claude").expect("construct");
        assert_eq!(rt.auth_policy, "fail");
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "opencode").expect("construct");
        assert_eq!(rt.auth_policy, "skip");
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "mystery").expect("construct");
        assert_eq!(
            rt.auth_policy, "fail",
            "an unknown agent must default to the fail-closed policy, not opencode's exception"
        );

        // Explicit override wins over the per-agent default either way.
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "claude")
            .expect("construct")
            .with_auth_policy("skip");
        assert_eq!(rt.auth_policy, "skip");
        let rt = AcpxAgentRuntime::with_binary(tmp.clone(), "opencode")
            .expect("construct")
            .with_auth_policy("fail");
        assert_eq!(rt.auth_policy, "fail");

        let _ = std::fs::remove_file(&tmp);
    }
}
