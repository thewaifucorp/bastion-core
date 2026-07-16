//! `CodexAppServerRuntime` — A-03 adapter: drives `codex app-server` (the
//! native Codex CLI JSON-RPC protocol over stdio) directly, no ACP client
//! in between.
//!
//! # Protocol
//!
//! One persistent `codex app-server` process per Bastion session, NDJSON
//! JSON-RPC 2.0 duplex over stdin/stdout (stderr is diagnostics-only, never
//! parsed). Handshake and turn lifecycle, reverse-engineered from the
//! shipped JSON Schema bundle (`codex app-server generate-json-schema`) and
//! verified against a real, host-logged-in `codex` 0.144.1 with small
//! scripted probes:
//!
//! ```text
//! → initialize {clientInfo, capabilities.experimentalApi:true}
//! ← result {..}
//! → initialized (notification)
//! → thread/start {cwd, approvalPolicy, sandbox}
//! ← result {thread:{id, ...}}
//! → turn/start {threadId, input:[{type:"text",text}]}
//! ← result {turn:{id, status:"inProgress"}}
//! ← turn/started, item/started, item/agentMessage/delta, ...
//! ← thread/tokenUsage/updated {tokenUsage:{total,last}}
//! ← turn/completed {turn:{id, status: completed|interrupted|failed, error}}
//! ```
//!
//! `capabilities.experimentalApi: true` is required on `initialize` for the
//! `thread/*`/`turn/*` v2 methods to be accepted at all — no server-side
//! `--experimental` flag is needed.
//!
//! # Honest coverage declarations (see [`CodexAppServerRuntime::descriptor`])
//!
//! - `supports.resume = true`: `thread/resume {threadId}` on a **fresh**
//!   `codex app-server` process genuinely reattaches (verified live: start
//!   a turn, kill the process, spawn a new one, `thread/resume` the same
//!   thread id — it works). See the resume() rustdoc for a real contract
//!   gap this surfaced.
//! - `supports.steer = true`: `turn/steer {threadId, expectedTurnId,
//!   input}` genuinely injects into the active turn (verified live).
//! - `policy_coverage.approvals = Bridged`: `item/commandExecution/
//!   requestApproval` and `item/fileChange/requestApproval` are real
//!   server→client JSON-RPC *requests* — answered with `{"id":..,
//!   "result":{"decision":"accept"|"decline"}}` (verified live: a `decline`
//!   response genuinely blocks the file write, `accept` lets it through).
//!   This is a materially stronger bridge than the acpx adapter's
//!   `HarnessOwned` — a key differentiator documented in `docs/SUPPORT-MATRIX.md`.
//! - `policy_coverage.sandbox`: **detected, not a constant** (Ciclo 2.2,
//!   A-05 §5.2 / LOOP-REPORT finding #5). On a host without working
//!   bubblewrap/user-namespaces (verified live in this sandboxed dev
//!   environment), `workspace-write` sandboxing silently fails to engage
//!   and EVERY tool call escalates to an approval request under
//!   `on-request` — the declared sandbox degrades to "ask about
//!   everything" rather than silently executing unconfined. Declaring
//!   `Honored` unconditionally would be dishonest, and so was declaring a
//!   constant `Partial`: a host that genuinely has no `bwrap` at all is
//!   `SandboxCoverage::None`, not an optimistic `Partial`. `health()` (and
//!   therefore `start()`, which always calls it first) now runs
//!   [`probe_sandbox_coverage`] — a cheap, real probe of whether bubblewrap
//!   can actually create a user namespace on this host — and caches the
//!   result for `descriptor()` to report. Before any probe has run, the
//!   cached value is the fail-closed worst case, `SandboxCoverage::None`.
//!   Even a working bubblewrap only proves `Partial`, never `Honored`: a
//!   successful probe shows the *mechanism* is real, not that any specific
//!   turn's `workspace-write` request was actually confined.
//! - `supports.concurrent_sessions = false`: one active turn per thread;
//!   `submit` rejects a second concurrent call.
//! - `policy_coverage.egress = HarnessOwned`: same reasoning as acpx — once
//!   a turn runs, the model/tool loop has its own network authority beyond
//!   what `TaskInput` assembly filtered.
//!
//! # Contract gap found in practice — RESOLVED (Ciclo 2.2)
//!
//! [`AgentRuntime::resume`] used to receive only a [`SessionHandle`], never
//! a [`SessionSpec`] — there was no way to recover the original
//! `EnvPolicy`/`TimeoutPolicy`/`PermissionProfile` purely from the handle.
//! It now takes a [`ResumeSpec`] (A-01 addendum, A-05 §5.6). Codex's
//! `thread/resume` conveniently echoes the thread's own `cwd`, so workspace
//! confinement survives outside the spec entirely; `env`/`timeout` from
//! `ResumeSpec` are applied for real (spawning the new process, and the
//! session's timeout watchdog). `permissions` cannot be threaded through
//! `thread/resume` at all — Codex's reattach protocol takes only a
//! `threadId`, nothing else — so the resumed session surfaces a
//! [`RuntimeEvent::Warning`] on the first task submitted after reattach
//! instead of silently dropping that part of the spec.

use crate::conformance::FaultInjection;
use crate::util::{parse_structured_line, resolve_on_path, sha256_digest, version_satisfies};
use crate::*;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

/// Supported `codex` CLI version range. `health()` compares the real
/// `codex --version` output against this pin (A-01 T9).
const CODEX_VERSION_REQ: &str = ">=0.144.0, <0.145.0";

/// Adapter driving `codex app-server` natively. One process per session.
pub struct CodexAppServerRuntime {
    codex_bin: PathBuf,
    /// Cached result of [`probe_sandbox_coverage`] (Ciclo 2.2, A-05 §5.2):
    /// starts at the fail-closed default `None` and is refreshed every
    /// `health()` call (which `start()` always calls first) — never an
    /// optimistic guess before a real probe has actually run.
    sandbox_coverage: std::sync::Mutex<SandboxCoverage>,
}

impl CodexAppServerRuntime {
    /// Resolves `codex` from the host `PATH`.
    pub fn new() -> Result<Self, RuntimeError> {
        Ok(Self {
            codex_bin: resolve_on_path("codex")?,
            sandbox_coverage: std::sync::Mutex::new(SandboxCoverage::None),
        })
    }

    /// Explicit path to the `codex` binary (tests, non-standard installs).
    pub fn with_binary(codex_bin: PathBuf) -> Self {
        Self {
            codex_bin,
            sandbox_coverage: std::sync::Mutex::new(SandboxCoverage::None),
        }
    }

    /// Reads the cached sandbox-coverage detection (see module docs and
    /// [`probe_sandbox_coverage`]) — worst-case `None` if no probe ran yet.
    /// Tolerates mutex poisoning (a panic while holding the lock is not
    /// expected, but recovering the poisoned value is strictly safer than
    /// panicking again on every subsequent `descriptor()` call).
    fn cached_sandbox_coverage(&self) -> SandboxCoverage {
        *self
            .sandbox_coverage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(&self.codex_bin);
        cmd.arg("app-server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
}

#[async_trait]
impl AgentRuntime for CodexAppServerRuntime {
    fn descriptor(&self) -> RuntimeDescriptor {
        RuntimeDescriptor {
            id: "codex_app_server",
            adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            target_version: format!("codex {CODEX_VERSION_REQ}"),
            transport: Transport::AppServer,
            supports: RuntimeSupports {
                resume: true,
                steer: true,
                usage_reporting: true,
                diff_events: true,
                permission_bridge: true,
                concurrent_sessions: false,
            },
            policy_coverage: PolicyCoverage {
                tool_visibility: ToolVisibility::DeclaredOnly,
                approvals: ApprovalCoverage::Bridged,
                egress: EgressCoverage::HarnessOwned,
                budget: BudgetCoverage::Reported,
                sandbox: self.cached_sandbox_coverage(),
            },
        }
    }

    async fn health(&self) -> Result<RuntimeHealth, RuntimeError> {
        // Ciclo 2.2 (A-05 §5.2): detect sandbox coverage on every health
        // probe rather than declaring a hardcoded constant. `start()` always
        // calls `health()` first, so both paths stay fresh.
        let detected = probe_sandbox_coverage().await;
        *self
            .sandbox_coverage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = detected;

        let mut cmd = Command::new(&self.codex_bin);
        cmd.arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd
            .output()
            .await
            .map_err(|e| RuntimeError::Unavailable(format!("failed to spawn codex: {e}")))?;
        if !output.status.success() {
            return Ok(RuntimeHealth {
                detected_version: "unknown".to_string(),
                ready: false,
                detail: Some("codex --version exited non-zero".to_string()),
            });
        }
        let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // Observed shape: "codex-cli 0.144.1" — take the last whitespace
        // token as the version.
        let version = raw.split_whitespace().last().unwrap_or(&raw).to_string();
        match version_satisfies(&version, CODEX_VERSION_REQ) {
            Ok(true) => Ok(RuntimeHealth {
                detected_version: version,
                ready: true,
                detail: None,
            }),
            Ok(false) => Ok(RuntimeHealth {
                detected_version: version.clone(),
                ready: false,
                detail: Some(format!(
                    "codex {version} outside supported range {CODEX_VERSION_REQ}"
                )),
            }),
            Err(e) => Ok(RuntimeHealth {
                detected_version: version,
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

        let mut cmd = self.base_command();
        cmd.env_clear();
        for (k, v) in &spec.env.allow {
            cmd.env(k, v);
        }
        let child = cmd.spawn().map_err(|e| {
            RuntimeError::Unavailable(format!("failed to spawn codex app-server: {e}"))
        })?;

        let (shared, tx, rx) = Shared::new_with_reader(child)?;

        do_handshake(&shared).await?;
        let thread_id = send_thread_start(
            &shared,
            &spec.workspace.root,
            approval_policy(&spec.permissions),
            sandbox_mode(&spec.sandbox),
        )
        .await
        .map_err(RuntimeError::Unavailable)?;

        let handle = SessionHandle {
            runtime_id: "codex_app_server".to_string(),
            owner: spec.owner.clone(),
            external_ref: thread_id.clone(),
        };
        let _ = tx.send(RuntimeEvent::Started {
            handle: handle.clone(),
        });

        Ok(Box::new(CodexSession {
            shared,
            handle,
            thread_id,
            per_task_timeout: spec.timeout.per_task,
            next_task_id: 0,
            event_tx: tx,
            event_rx: rx,
            pending_resume_warning: None,
        }))
    }

    async fn resume(
        &self,
        handle: &SessionHandle,
        spec: ResumeSpec,
    ) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        if handle.runtime_id != "codex_app_server" {
            return Err(RuntimeError::NotResumable(
                "handle belongs to a different runtime".to_string(),
            ));
        }
        let health = self.health().await?;
        if !health.ready {
            return Err(RuntimeError::Unavailable(health.detail.unwrap_or_default()));
        }

        let mut cmd = self.base_command();
        cmd.env_clear();
        for (k, v) in &spec.env.allow {
            cmd.env(k, v);
        }
        let child = cmd.spawn().map_err(|e| {
            RuntimeError::Unavailable(format!("failed to spawn codex app-server: {e}"))
        })?;
        let (shared, tx, rx) = Shared::new_with_reader(child)?;
        do_handshake(&shared).await.map_err(|e| {
            RuntimeError::Unavailable(format!("handshake failed during resume: {e}"))
        })?;

        let id = shared.alloc_id();
        let (resp_tx, resp_rx) = oneshot::channel();
        shared
            .pending
            .lock()
            .await
            .insert(id, PendingKind::Simple(resp_tx));
        shared
            .write_request(
                id,
                "thread/resume",
                json!({"threadId": handle.external_ref}),
            )
            .await
            .map_err(RuntimeError::Unavailable)?;
        let result = resp_rx.await.map_err(|_| {
            RuntimeError::NotResumable("connection closed during resume".to_string())
        })?;
        let thread = match result {
            Ok(v) => v,
            Err(e) => {
                return Err(RuntimeError::NotResumable(format!(
                    "thread/resume rejected: {}",
                    error_message(&e)
                )))
            }
        };

        let new_handle = SessionHandle {
            runtime_id: "codex_app_server".to_string(),
            owner: handle.owner.clone(),
            external_ref: handle.external_ref.clone(),
        };
        let _ = tx.send(RuntimeEvent::Started {
            handle: new_handle.clone(),
        });

        // `ResumeSpec` (Ciclo 2.2) is applied for what codex's protocol
        // actually allows: `env` above (real subprocess env), `timeout`
        // here (purely client-side watchdog bookkeeping — codex never sees
        // it). `spec.permissions` CANNOT be threaded through
        // `thread/resume` at all: the wire request is `{"threadId": ...}`,
        // nothing else — the resumed thread keeps its original
        // `approvalPolicy` no matter what `spec.permissions` says. Surfaced
        // as a `Warning` on the first task submitted after reattach (see
        // `submit`) rather than silently dropped.
        let _ = thread; // thread metadata available (cwd, etc.) but unused for now.
        Ok(Box::new(CodexSession {
            shared,
            handle: new_handle,
            thread_id: handle.external_ref.clone(),
            per_task_timeout: spec.timeout.per_task,
            next_task_id: 0,
            event_tx: tx,
            event_rx: rx,
            pending_resume_warning: Some(
                "resume() cannot re-apply a PermissionProfile over codex's thread/resume \
                 protocol (it takes only a threadId) — the reattached thread keeps its \
                 original approvalPolicy"
                    .to_string(),
            ),
        }))
    }
}

#[async_trait]
impl FaultInjection for CodexAppServerRuntime {
    // All defaults (false) — see acpx.rs for the same rationale: inducing
    // faults on a live external harness is out of scope for this adapter.
}

fn approval_policy(profile: &PermissionProfile) -> &'static str {
    if profile.allow.iter().any(|a| a == "*") {
        "never"
    } else {
        "on-request"
    }
}

/// Cheap, host-level probe of whether Codex's Linux sandbox mechanism
/// (bubblewrap unprivileged user namespaces) can actually confine anything
/// on this host — run from `health()`, never assumed (Ciclo 2.2, A-05 §5.2 /
/// LOOP-REPORT finding #5).
///
/// Mirrors what `codex` itself would observe (it shells out to `bwrap` for
/// its own sandbox) without needing a live `codex` process: if `bwrap`
/// cannot even be found on `PATH`, or a minimal `--unshare-user` invocation
/// fails (exactly the failure mode this dev host hits — "needs access to
/// create user namespaces"), there is no mechanism to honor any part of the
/// requested sandbox profile at all — [`SandboxCoverage::None`], the
/// fail-closed worst case, never an optimistic [`SandboxCoverage::Partial`].
///
/// This probe never returns [`SandboxCoverage::Honored`]: even a bubblewrap
/// that can create user namespaces only makes the *mechanism* real from
/// outside a live session — it is not proof that a specific turn's
/// `workspace-write` request was actually confined (see module docs).
async fn probe_sandbox_coverage() -> SandboxCoverage {
    let bwrap = match resolve_on_path("bwrap") {
        Ok(p) => p,
        Err(_) => return SandboxCoverage::None,
    };
    let mut cmd = Command::new(&bwrap);
    cmd.args(["--unshare-user", "--dev-bind", "/", "/", "true"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(3), cmd.status()).await {
        Ok(Ok(status)) if status.success() => SandboxCoverage::Partial,
        _ => SandboxCoverage::None,
    }
}

fn sandbox_mode(sandbox: &SandboxProfile) -> &'static str {
    match sandbox {
        SandboxProfile::Isolated => "read-only",
        SandboxProfile::WorkspaceNet => "workspace-write",
        SandboxProfile::Trusted => "danger-full-access",
    }
}

fn error_message(v: &Value) -> String {
    v.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown error")
        .to_string()
}

// ---------------------------------------------------------------------
// Shared connection state (one per live `codex app-server` process)
// ---------------------------------------------------------------------

enum PendingKind {
    /// Generic request awaiting its raw `result`/`error` `Value`.
    Simple(oneshot::Sender<Result<Value, Value>>),
    /// A `turn/start` request: on success, registers `task_map` and
    /// `current_turn` before waking the caller (see module docs — this
    /// ordering, done by the reader itself, avoids a race between
    /// registering the turn and the reader dispatching its first
    /// notification).
    TurnStart {
        task_id: TaskId,
        responder: oneshot::Sender<Result<String, String>>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalKind {
    CommandExecution,
    FileChange,
}

struct Shared {
    stdin: AsyncMutex<ChildStdin>,
    next_id: AtomicI64,
    pending: AsyncMutex<HashMap<i64, PendingKind>>,
    pending_approvals: AsyncMutex<HashMap<u64, (i64, ApprovalKind)>>,
    next_perm_id: AtomicU64,
    task_map: AsyncMutex<HashMap<String, TaskId>>,
    current_turn: AsyncMutex<Option<(TaskId, String)>>,
    /// Turn ids for which `turn/interrupt` was sent by the *timeout*
    /// watchdog rather than [`RuntimeSession::cancel`]. `turn/completed`
    /// reports the same `status: "interrupted"` for both — this set is how
    /// the reader tells a real timeout apart from a genuine cancel and
    /// emits `TimedOut` instead of `Cancelled` (a bug found live: without
    /// it, `check_timeout` observed `Cancelled`).
    timed_out_turns: AsyncMutex<std::collections::HashSet<String>>,
    status: AsyncMutex<SessionStatus>,
    garbage: AtomicBool,
    child: AsyncMutex<Child>,
}

impl Shared {
    /// Takes ownership of `child`'s stdin/stdout, builds the shared
    /// connection state, spawns the background reader loop, and returns
    /// `(shared, event_sender, event_receiver)` for the caller to wire into
    /// a [`CodexSession`] — the sender is handed back too so the caller can
    /// push `Started` onto the same stream the reader will later push
    /// notifications onto.
    #[allow(clippy::type_complexity)]
    fn new_with_reader(
        mut child: Child,
    ) -> Result<
        (
            Arc<Self>,
            mpsc::UnboundedSender<RuntimeEvent>,
            mpsc::UnboundedReceiver<RuntimeEvent>,
        ),
        RuntimeError,
    > {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("codex child has no stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("codex child has no stdout".to_string()))?;

        let shared = Arc::new(Shared {
            stdin: AsyncMutex::new(stdin),
            next_id: AtomicI64::new(0),
            pending: AsyncMutex::new(HashMap::new()),
            pending_approvals: AsyncMutex::new(HashMap::new()),
            next_perm_id: AtomicU64::new(0),
            task_map: AsyncMutex::new(HashMap::new()),
            current_turn: AsyncMutex::new(None),
            timed_out_turns: AsyncMutex::new(std::collections::HashSet::new()),
            status: AsyncMutex::new(SessionStatus::Running),
            garbage: AtomicBool::new(false),
            child: AsyncMutex::new(child),
        });

        let (tx, rx) = mpsc::unbounded_channel();
        let reader_shared = Arc::clone(&shared);
        let reader_tx = tx.clone();
        tokio::spawn(async move {
            run_reader(reader_shared, stdout, reader_tx).await;
        });

        Ok((shared, tx, rx))
    }

    fn alloc_id(&self) -> i64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn write_request(&self, id: i64, method: &str, params: Value) -> Result<(), String> {
        let frame = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        self.write_line(&frame).await
    }

    async fn write_notification(&self, method: &str, params: Value) -> Result<(), String> {
        let frame = json!({"jsonrpc":"2.0","method":method,"params":params});
        self.write_line(&frame).await
    }

    async fn write_response(&self, id: i64, result: Value) -> Result<(), String> {
        let frame = json!({"jsonrpc":"2.0","id":id,"result":result});
        self.write_line(&frame).await
    }

    async fn write_line(&self, frame: &Value) -> Result<(), String> {
        let mut line = frame.to_string();
        line.push('\n');
        let mut stdin = self.stdin.lock().await;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write to codex stdin failed: {e}"))?;
        stdin
            .flush()
            .await
            .map_err(|e| format!("flush codex stdin failed: {e}"))
    }
}

async fn run_reader(
    shared: Arc<Shared>,
    stdout: tokio::process::ChildStdout,
    tx: mpsc::UnboundedSender<RuntimeEvent>,
) {
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(raw)) => match parse_structured_line(&raw) {
                Ok(value) => dispatch_frame(&shared, &tx, value).await,
                Err(e) => {
                    tracing::warn!(target: "bastion_agent_runtime::codex", error = %e, "rejecting non-structured frame");
                    shared.garbage.store(true, Ordering::SeqCst);
                    break;
                }
            },
            Ok(None) => break, // EOF
            Err(e) => {
                tracing::warn!(target: "bastion_agent_runtime::codex", error = %e, "stdout read error");
                break;
            }
        }
    }

    // Connection lost (EOF, IO error, or garbage frame): make sure the
    // process is actually gone — a garbage frame in particular means we
    // stop trusting the stream but the process may still be alive.
    let _ = shared.child.lock().await.start_kill();

    // Fail every pending request/approval and end any active turn as
    // Failed so no caller (or task) hangs forever.
    for (_, kind) in shared.pending.lock().await.drain() {
        match kind {
            PendingKind::Simple(tx) => {
                let _ = tx.send(Err(json!({"message": "connection closed"})));
            }
            PendingKind::TurnStart { responder, .. } => {
                let _ = responder.send(Err("connection closed".to_string()));
            }
        }
    }
    shared.pending_approvals.lock().await.clear();
    if let Some((task_id, _turn_id)) = shared.current_turn.lock().await.take() {
        let _ = tx.send(RuntimeEvent::Ended {
            task: task_id,
            outcome: TaskOutcome::Failed {
                reason: "codex app-server process ended unexpectedly".to_string(),
            },
        });
    }
    *shared.status.lock().await = SessionStatus::Crashed;
}

async fn dispatch_frame(
    shared: &Arc<Shared>,
    tx: &mpsc::UnboundedSender<RuntimeEvent>,
    value: Value,
) {
    let id = value.get("id").and_then(|i| i.as_i64());
    let has_result_or_error = value.get("result").is_some() || value.get("error").is_some();

    if let Some(id) = id {
        if has_result_or_error {
            let pending = shared.pending.lock().await.remove(&id);
            if let Some(kind) = pending {
                complete_pending(shared, kind, &value).await;
                return;
            }
            // A response to a request we didn't originate (or already
            // handled) — ignore.
            return;
        }
        // Has an id AND a method: a server->client REQUEST we must answer.
        if let Some(method) = value.get("method").and_then(|m| m.as_str()) {
            handle_server_request(shared, tx, id, method, &value).await;
            return;
        }
    }

    if let Some(method) = value.get("method").and_then(|m| m.as_str()) {
        dispatch_notification(shared, tx, method, &value).await;
    }
}

async fn complete_pending(shared: &Arc<Shared>, kind: PendingKind, value: &Value) {
    match kind {
        PendingKind::Simple(responder) => {
            let outcome = if let Some(result) = value.get("result") {
                Ok(result.clone())
            } else {
                Err(value.get("error").cloned().unwrap_or(Value::Null))
            };
            let _ = responder.send(outcome);
        }
        PendingKind::TurnStart { task_id, responder } => {
            if let Some(result) = value.get("result") {
                if let Some(turn_id) = result
                    .get("turn")
                    .and_then(|t| t.get("id"))
                    .and_then(|i| i.as_str())
                {
                    shared
                        .task_map
                        .lock()
                        .await
                        .insert(turn_id.to_string(), task_id);
                    *shared.current_turn.lock().await = Some((task_id, turn_id.to_string()));
                    let _ = responder.send(Ok(turn_id.to_string()));
                } else {
                    let _ = responder.send(Err("turn/start result missing turn.id".to_string()));
                }
            } else {
                let msg = value
                    .get("error")
                    .map(error_message)
                    .unwrap_or_else(|| "turn/start failed".to_string());
                let _ = responder.send(Err(msg));
            }
        }
    }
}

async fn handle_server_request(
    shared: &Arc<Shared>,
    tx: &mpsc::UnboundedSender<RuntimeEvent>,
    id: i64,
    method: &str,
    value: &Value,
) {
    let kind = match method {
        "item/commandExecution/requestApproval" | "execCommandApproval" => {
            ApprovalKind::CommandExecution
        }
        "item/fileChange/requestApproval" | "applyPatchApproval" => ApprovalKind::FileChange,
        other => {
            tracing::warn!(
                target: "bastion_agent_runtime::codex",
                method = other,
                "unhandled server request left unanswered (not an approval bridge this adapter implements)"
            );
            return;
        }
    };

    let params = value.get("params").cloned().unwrap_or(Value::Null);
    let turn_id = params.get("turnId").and_then(|t| t.as_str());
    let Some(task_id) = (match turn_id {
        Some(t) => shared.task_map.lock().await.get(t).copied(),
        None => None,
    }) else {
        tracing::warn!(target: "bastion_agent_runtime::codex", "approval request for unknown turn; leaving unanswered");
        return;
    };

    let perm_id = shared.next_perm_id.fetch_add(1, Ordering::Relaxed);
    shared
        .pending_approvals
        .lock()
        .await
        .insert(perm_id, (id, kind));

    let (action, detail) = match kind {
        ApprovalKind::CommandExecution => (
            PermissionAction::RunCommand,
            params
                .get("commandActions")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|a| a.get("command"))
                .and_then(|c| c.as_str())
                .unwrap_or("command execution")
                .to_string(),
        ),
        ApprovalKind::FileChange => (
            PermissionAction::WriteFile,
            params
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("file change")
                .to_string(),
        ),
    };

    let _ = tx.send(RuntimeEvent::PermissionRequest {
        task: task_id,
        id: PermissionRequestId(perm_id),
        action,
        detail,
    });
}

async fn dispatch_notification(
    shared: &Arc<Shared>,
    tx: &mpsc::UnboundedSender<RuntimeEvent>,
    method: &str,
    value: &Value,
) {
    let params = value.get("params").cloned().unwrap_or(Value::Null);

    if method == "turn/completed" {
        let Some(turn) = params.get("turn") else {
            return;
        };
        let Some(turn_id) = turn.get("id").and_then(|i| i.as_str()) else {
            return;
        };
        let task_id = shared.task_map.lock().await.remove(turn_id);
        {
            let mut current = shared.current_turn.lock().await;
            if current.as_ref().map(|(_, t)| t.as_str()) == Some(turn_id) {
                *current = None;
            }
        }
        let was_timeout = shared.timed_out_turns.lock().await.remove(turn_id);
        if let Some(task) = task_id {
            let outcome = if was_timeout {
                // `turn/interrupt` from OUR OWN timeout watchdog reports the
                // same status:"interrupted" as a genuine cancel — this is
                // the only place that tells them apart.
                TaskOutcome::TimedOut
            } else {
                NotificationInterpreter::turn_completed_outcome(turn)
            };
            let _ = tx.send(RuntimeEvent::Ended { task, outcome });
        }
        return;
    }

    let turn_id = params.get("turnId").and_then(|t| t.as_str());
    let Some(turn_id) = turn_id else { return };
    let Some(task_id) = shared.task_map.lock().await.get(turn_id).copied() else {
        return;
    };

    let outcome = NotificationInterpreter::on_notification(task_id, method, &params);
    for evt in outcome.events {
        let _ = tx.send(evt);
    }
    if let Some(abs_path) = outcome.artifact_candidate {
        if let Ok(bytes) = tokio::fs::read(&abs_path).await {
            let _ = tx.send(RuntimeEvent::Artifact {
                task: task_id,
                artifact: Artifact {
                    kind: ArtifactKind::File,
                    path: abs_path,
                    digest: sha256_digest(&bytes),
                    produced_by: None,
                },
            });
        }
    }
}

async fn do_handshake(shared: &Arc<Shared>) -> Result<(), RuntimeError> {
    let id = shared.alloc_id();
    let (resp_tx, resp_rx) = oneshot::channel();
    shared
        .pending
        .lock()
        .await
        .insert(id, PendingKind::Simple(resp_tx));
    shared
        .write_request(
            id,
            "initialize",
            json!({
                "clientInfo": {"name": "bastion", "version": env!("CARGO_PKG_VERSION")},
                "capabilities": {"experimentalApi": true},
            }),
        )
        .await
        .map_err(RuntimeError::Unavailable)?;
    match resp_rx.await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(RuntimeError::Unavailable(format!(
                "initialize rejected: {}",
                error_message(&e)
            )))
        }
        Err(_) => {
            return Err(RuntimeError::Unavailable(
                "connection closed during initialize".to_string(),
            ))
        }
    }
    shared
        .write_notification("initialized", json!({}))
        .await
        .map_err(RuntimeError::Unavailable)
}

async fn send_thread_start(
    shared: &Arc<Shared>,
    cwd: &Path,
    approval_policy: &str,
    sandbox: &str,
) -> Result<String, String> {
    let id = shared.alloc_id();
    let (resp_tx, resp_rx) = oneshot::channel();
    shared
        .pending
        .lock()
        .await
        .insert(id, PendingKind::Simple(resp_tx));
    shared
        .write_request(
            id,
            "thread/start",
            json!({
                "cwd": cwd.to_string_lossy(),
                "approvalPolicy": approval_policy,
                "sandbox": sandbox,
            }),
        )
        .await?;
    let result = resp_rx
        .await
        .map_err(|_| "connection closed during thread/start".to_string())?
        .map_err(|e| format!("thread/start rejected: {}", error_message(&e)))?;
    result
        .get("thread")
        .and_then(|t| t.get("id"))
        .and_then(|i| i.as_str())
        .map(str::to_string)
        .ok_or_else(|| "thread/start result missing thread.id".to_string())
}

// ---------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------

pub(crate) struct CodexSession {
    shared: Arc<Shared>,
    handle: SessionHandle,
    thread_id: String,
    per_task_timeout: Duration,
    next_task_id: u64,
    event_tx: mpsc::UnboundedSender<RuntimeEvent>,
    event_rx: mpsc::UnboundedReceiver<RuntimeEvent>,
    /// Set by [`CodexAppServerRuntime::resume`] when a `ResumeSpec` field
    /// could not be threaded through `thread/resume` (Ciclo 2.2); consumed
    /// (surfaced as a `Warning`) on the first task `submit` allocates —
    /// `None` for a session opened via `start()`, which has no such gap.
    pending_resume_warning: Option<String>,
}

#[async_trait]
impl RuntimeSession for CodexSession {
    fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }

    async fn submit(&mut self, input: TaskInput) -> Result<TaskId, RuntimeError> {
        if self.shared.garbage.load(Ordering::SeqCst) {
            return Err(RuntimeError::Protocol(
                "malformed frame pending on codex transport".to_string(),
            ));
        }
        if *self.shared.status.lock().await == SessionStatus::Crashed {
            return Err(RuntimeError::Crashed("session already crashed".to_string()));
        }
        if self.shared.current_turn.lock().await.is_some() {
            return Err(RuntimeError::Unavailable(
                "a turn is already active on this thread (supports.concurrent_sessions=false)"
                    .to_string(),
            ));
        }

        let task_id = TaskId(self.next_task_id);
        self.next_task_id += 1;

        // Ciclo 2.2: surface the resume()-time permission-profile gap (if
        // any) attached to the first real task, rather than trying to
        // synthesize a session-level event before any TaskId exists.
        if let Some(detail) = self.pending_resume_warning.take() {
            let _ = self.event_tx.send(RuntimeEvent::Warning {
                task: task_id,
                code: WarnCode::DegradedTransport,
                detail,
            });
        }

        let id = self.shared.alloc_id();
        let (resp_tx, resp_rx) = oneshot::channel();
        self.shared.pending.lock().await.insert(
            id,
            PendingKind::TurnStart {
                task_id,
                responder: resp_tx,
            },
        );
        self.shared
            .write_request(
                id,
                "turn/start",
                json!({
                    "threadId": self.thread_id,
                    "input": [{"type": "text", "text": input.prompt}],
                }),
            )
            .await
            .map_err(RuntimeError::Unavailable)?;

        let turn_id = match resp_rx.await {
            Ok(Ok(turn_id)) => turn_id,
            Ok(Err(msg)) => {
                return Err(RuntimeError::Unavailable(format!(
                    "turn/start failed: {msg}"
                )))
            }
            Err(_) => {
                return Err(RuntimeError::Crashed(
                    "connection closed while starting turn".to_string(),
                ))
            }
        };

        spawn_timeout_watchdog(
            Arc::clone(&self.shared),
            self.event_tx.clone(),
            self.thread_id.clone(),
            turn_id,
            task_id,
            self.per_task_timeout,
        );

        Ok(task_id)
    }

    async fn next_event(&mut self) -> Option<RuntimeEvent> {
        self.event_rx.recv().await
    }

    async fn steer(&mut self, text: &str) -> Result<(), RuntimeError> {
        let current = self.shared.current_turn.lock().await.clone();
        let Some((_, turn_id)) = current else {
            return Err(RuntimeError::Protocol(
                "no active turn to steer".to_string(),
            ));
        };

        // The server accepts `turn/start` (and reports the turn as
        // `inProgress`) slightly before its own internal state machine is
        // ready to accept `turn/steer` on it — verified live: an immediate
        // steer right after submit() sometimes gets rejected with "no
        // active turn to steer" from the SERVER itself, while a steer sent
        // ~1s later succeeds. This is a transient server-side readiness
        // race, not a real rejection, so a short bounded retry is the
        // honest fix (not papering over a real unsupported-operation
        // error — any rejection on the final attempt still surfaces).
        const ATTEMPTS: u32 = 4;
        const RETRY_DELAY: Duration = Duration::from_millis(400);
        let mut last_err = String::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            let id = self.shared.alloc_id();
            let (resp_tx, resp_rx) = oneshot::channel();
            self.shared
                .pending
                .lock()
                .await
                .insert(id, PendingKind::Simple(resp_tx));
            self.shared
                .write_request(
                    id,
                    "turn/steer",
                    json!({
                        "threadId": self.thread_id,
                        "expectedTurnId": turn_id,
                        "input": [{"type": "text", "text": text}],
                    }),
                )
                .await
                .map_err(RuntimeError::Unavailable)?;
            match resp_rx.await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => last_err = error_message(&e),
                Err(_) => {
                    return Err(RuntimeError::Crashed(
                        "connection closed during steer".to_string(),
                    ))
                }
            }
        }
        Err(RuntimeError::Protocol(format!(
            "turn/steer rejected after {ATTEMPTS} attempts: {last_err}"
        )))
    }

    async fn cancel(&mut self, mode: CancelMode) -> Result<(), RuntimeError> {
        let current = self.shared.current_turn.lock().await.clone();
        let Some((task_id, turn_id)) = current else {
            let mut status = self.shared.status.lock().await;
            if *status != SessionStatus::Crashed {
                *status = SessionStatus::Cancelled;
            }
            return Ok(());
        };

        let id = self.shared.alloc_id();
        let _ = self
            .shared
            .write_request(
                id,
                "turn/interrupt",
                json!({"threadId": self.thread_id, "turnId": turn_id}),
            )
            .await;

        if let CancelMode::Graceful { grace } = mode {
            let deadline = tokio::time::Instant::now() + grace;
            loop {
                if !self.shared.task_map.lock().await.contains_key(&turn_id) {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let still_pending = self.shared.task_map.lock().await.remove(&turn_id).is_some();
        if still_pending {
            let mut current = self.shared.current_turn.lock().await;
            if current.as_ref().map(|(_, t)| t.as_str()) == Some(turn_id.as_str()) {
                *current = None;
            }
            let _ = self.event_tx.send(RuntimeEvent::Ended {
                task: task_id,
                outcome: TaskOutcome::Cancelled,
            });
        }

        let mut status = self.shared.status.lock().await;
        if *status != SessionStatus::Crashed {
            *status = SessionStatus::Cancelled;
        }
        Ok(())
    }

    async fn respond_permission(
        &mut self,
        id: PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), RuntimeError> {
        let entry = self.shared.pending_approvals.lock().await.remove(&id.0);
        let Some((json_id, _kind)) = entry else {
            return Err(RuntimeError::Protocol(
                "no matching pending permission request".to_string(),
            ));
        };
        let (decision_str, deny_scope) = match decision {
            PermissionDecision::Allow => ("accept", None),
            PermissionDecision::Deny { scope } => ("decline", Some(scope)),
        };
        self.shared
            .write_response(json_id, json!({"decision": decision_str}))
            .await
            .map_err(RuntimeError::Unavailable)?;

        // Ciclo 2.2 (`docs/SECURITY-INVARIANTS.md` §3, A-05
        // §5.5 / LOOP-REPORT finding #5.5): a `Turn`-scoped denial closes
        // the alternate-tool-routing gap at the adapter boundary — the
        // declined tool call is blocked by the `decline` response above,
        // and the adapter itself now also cancels the delegated task
        // gracefully rather than letting the harness try another, ungated
        // tool call for the same goal this turn.
        if deny_scope == Some(DenyScope::Turn) {
            self.cancel(CancelMode::Graceful {
                grace: Duration::from_millis(500),
            })
            .await?;
        }
        Ok(())
    }

    async fn status(&self) -> Result<SessionStatus, RuntimeError> {
        if self.shared.garbage.load(Ordering::SeqCst) {
            return Err(RuntimeError::Protocol(
                "malformed frame received on codex transport".to_string(),
            ));
        }
        Ok(*self.shared.status.lock().await)
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_timeout_watchdog(
    shared: Arc<Shared>,
    tx: mpsc::UnboundedSender<RuntimeEvent>,
    thread_id: String,
    turn_id: String,
    task_id: TaskId,
    per_task_timeout: Duration,
) {
    tokio::spawn(async move {
        tokio::time::sleep(per_task_timeout).await;
        if !shared.task_map.lock().await.contains_key(&turn_id) {
            return; // already ended naturally
        }
        // Mark BEFORE sending the interrupt so the reader (which may
        // process the resulting turn/completed concurrently) always sees
        // the marker in time to classify it as TimedOut, not Cancelled.
        shared.timed_out_turns.lock().await.insert(turn_id.clone());
        let id = shared.alloc_id();
        let _ = shared
            .write_request(
                id,
                "turn/interrupt",
                json!({"threadId": thread_id, "turnId": turn_id}),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let still_active = shared.task_map.lock().await.remove(&turn_id).is_some();
        if still_active {
            shared.timed_out_turns.lock().await.remove(&turn_id);
            let mut current = shared.current_turn.lock().await;
            if current.as_ref().map(|(_, t)| t.as_str()) == Some(turn_id.as_str()) {
                *current = None;
            }
            let _ = tx.send(RuntimeEvent::Ended {
                task: task_id,
                outcome: TaskOutcome::TimedOut,
            });
        }
    });
}

// ---------------------------------------------------------------------
// Notification interpreter — pure, unit-testable mapping of one
// already-resolved (task, method, params) notification onto zero or more
// RuntimeEvents. Turn/task correlation (turnId -> TaskId) happens in the
// async dispatch layer above, which owns the shared state; everything
// content-related is pure here.
// ---------------------------------------------------------------------

#[derive(Default)]
struct NotifyOutcome {
    events: Vec<RuntimeEvent>,
    artifact_candidate: Option<PathBuf>,
}

struct NotificationInterpreter;

impl NotificationInterpreter {
    fn turn_completed_outcome(turn: &Value) -> TaskOutcome {
        match turn.get("status").and_then(|s| s.as_str()) {
            Some("completed") => TaskOutcome::Success,
            Some("interrupted") => TaskOutcome::Cancelled,
            Some("failed") => TaskOutcome::Failed {
                reason: turn
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("turn failed")
                    .to_string(),
            },
            other => TaskOutcome::Failed {
                reason: format!("unexpected turn status: {other:?}"),
            },
        }
    }

    fn on_notification(task: TaskId, method: &str, params: &Value) -> NotifyOutcome {
        let mut out = NotifyOutcome::default();
        match method {
            "item/agentMessage/delta" => {
                if let Some(text) = params.get("delta").and_then(|d| d.as_str()) {
                    if !text.is_empty() {
                        out.events.push(RuntimeEvent::MessageDelta {
                            task,
                            text: text.to_string(),
                        });
                    }
                }
            }
            "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => {
                if let Some(text) = params
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .or_else(|| params.get("text").and_then(|d| d.as_str()))
                {
                    if !text.is_empty() {
                        out.events.push(RuntimeEvent::Thinking {
                            task,
                            summary: text.to_string(),
                        });
                    }
                }
            }
            "item/started" => {
                if let Some(item) = params.get("item") {
                    if let Some((name, digest)) = tool_call_start(item) {
                        out.events.push(RuntimeEvent::ToolCall {
                            task,
                            name,
                            input_digest: digest,
                        });
                    }
                }
            }
            "item/completed" => {
                if let Some(item) = params.get("item") {
                    Self::map_item_completed(task, item, &mut out);
                }
            }
            "thread/tokenUsage/updated" => {
                if let Some(last) = params.get("tokenUsage").and_then(|u| u.get("last")) {
                    out.events.push(RuntimeEvent::Usage {
                        task,
                        delta: UsageDelta {
                            input_tokens: last
                                .get("inputTokens")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0),
                            output_tokens: last
                                .get("outputTokens")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0),
                        },
                    });
                }
            }
            _ => {}
        }
        out
    }

    fn map_item_completed(task: TaskId, item: &Value, out: &mut NotifyOutcome) {
        let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match item_type {
            "commandExecution" => {
                let status = item.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let is_error = status != "completed"
                    || item
                        .get("exitCode")
                        .and_then(|c| c.as_i64())
                        .map(|c| c != 0)
                        .unwrap_or(false);
                let name = item
                    .get("command")
                    .and_then(|c| c.as_str())
                    .unwrap_or("command")
                    .to_string();
                let output = item
                    .get("aggregatedOutput")
                    .and_then(|o| o.as_str())
                    .unwrap_or("");
                out.events.push(RuntimeEvent::ToolResult {
                    task,
                    name,
                    output_digest: sha256_digest(output.as_bytes()),
                    is_error,
                });
            }
            "fileChange" => {
                let status = item.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let is_error = status != "completed";
                out.events.push(RuntimeEvent::ToolResult {
                    task,
                    name: "fileChange".to_string(),
                    output_digest: sha256_digest(status.as_bytes()),
                    is_error,
                });
                if let Some(changes) = item.get("changes").and_then(|c| c.as_array()) {
                    for change in changes {
                        let Some(path) = change.get("path").and_then(|p| p.as_str()) else {
                            continue;
                        };
                        let diff_text = change.get("diff").and_then(|d| d.as_str()).unwrap_or("");
                        let (added, removed) = unified_diff_counts(diff_text);
                        out.events.push(RuntimeEvent::Diff {
                            task,
                            path: PathBuf::from(path),
                            added,
                            removed,
                        });
                        if !is_error {
                            out.artifact_candidate = Some(PathBuf::from(path));
                        }
                    }
                }
            }
            "mcpToolCall" => {
                let is_error = item.get("error").map(|e| !e.is_null()).unwrap_or(false);
                let name = item
                    .get("toolName")
                    .and_then(|n| n.as_str())
                    .unwrap_or("mcp_tool")
                    .to_string();
                out.events.push(RuntimeEvent::ToolResult {
                    task,
                    name,
                    output_digest: sha256_digest(item.to_string().as_bytes()),
                    is_error,
                });
            }
            _ => {}
        }
    }
}

fn tool_call_start(item: &Value) -> Option<(String, String)> {
    let item_type = item.get("type").and_then(|t| t.as_str())?;
    match item_type {
        "commandExecution" => {
            let name = item
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("command");
            Some((name.to_string(), sha256_digest(name.as_bytes())))
        }
        "fileChange" => Some((
            "fileChange".to_string(),
            sha256_digest(item.to_string().as_bytes()),
        )),
        "mcpToolCall" => {
            let name = item
                .get("toolName")
                .and_then(|n| n.as_str())
                .unwrap_or("mcp_tool");
            Some((name.to_string(), sha256_digest(name.as_bytes())))
        }
        _ => None,
    }
}

/// Counts added/removed lines from a unified-diff-style text blob (lines
/// starting with `+`/`-`, excluding the `+++`/`---` header lines). Good
/// enough for the [`RuntimeEvent::Diff`] telemetry counts — not used for
/// anything policy-relevant.
fn unified_diff_counts(diff_text: &str) -> (u32, u32) {
    let mut added = 0u32;
    let mut removed = 0u32;
    for line in diff_text.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(stripped) = line.strip_prefix('+') {
            let _ = stripped;
            added += 1;
        } else if let Some(stripped) = line.strip_prefix('-') {
            let _ = stripped;
            removed += 1;
        }
    }
    if added == 0 && removed == 0 {
        // No diff markers at all (e.g. a plain "new file" dump) — treat
        // every line as added, matching acpx's oldText==None convention.
        added = diff_text.lines().count() as u32;
    }
    (added, removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn turn_completed_outcome_maps_all_statuses() {
        assert_eq!(
            NotificationInterpreter::turn_completed_outcome(&json!({"status":"completed"})),
            TaskOutcome::Success
        );
        assert_eq!(
            NotificationInterpreter::turn_completed_outcome(&json!({"status":"interrupted"})),
            TaskOutcome::Cancelled
        );
        match NotificationInterpreter::turn_completed_outcome(
            &json!({"status":"failed","error":{"message":"boom"}}),
        ) {
            TaskOutcome::Failed { reason } => assert_eq!(reason, "boom"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn agent_message_delta_maps_to_message_delta_and_skips_empty() {
        let out = NotificationInterpreter::on_notification(
            TaskId(0),
            "item/agentMessage/delta",
            &json!({"delta": "ok"}),
        );
        assert!(matches!(&out.events[0], RuntimeEvent::MessageDelta{text, ..} if text == "ok"));

        let out = NotificationInterpreter::on_notification(
            TaskId(0),
            "item/agentMessage/delta",
            &json!({"delta": ""}),
        );
        assert!(out.events.is_empty());
    }

    #[test]
    fn token_usage_updated_maps_last_to_usage_delta() {
        let out = NotificationInterpreter::on_notification(
            TaskId(0),
            "thread/tokenUsage/updated",
            &json!({"tokenUsage":{"total":{"inputTokens":100,"outputTokens":50},"last":{"inputTokens":7,"outputTokens":6}}}),
        );
        assert!(
            matches!(&out.events[0], RuntimeEvent::Usage{delta, ..} if delta.input_tokens == 7 && delta.output_tokens == 6)
        );
    }

    #[test]
    fn command_execution_completed_maps_to_tool_result_with_error_flag() {
        let mut out = NotifyOutcome::default();
        NotificationInterpreter::map_item_completed(
            TaskId(0),
            &json!({"type":"commandExecution","command":"ls","status":"completed","exitCode":0,"aggregatedOutput":"a\nb\n"}),
            &mut out,
        );
        assert!(matches!(
            &out.events[0],
            RuntimeEvent::ToolResult {
                is_error: false,
                ..
            }
        ));

        let mut out = NotifyOutcome::default();
        NotificationInterpreter::map_item_completed(
            TaskId(0),
            &json!({"type":"commandExecution","command":"false","status":"completed","exitCode":1,"aggregatedOutput":""}),
            &mut out,
        );
        assert!(matches!(
            &out.events[0],
            RuntimeEvent::ToolResult { is_error: true, .. }
        ));
    }

    #[test]
    fn file_change_completed_maps_to_diff_and_artifact_candidate() {
        let mut out = NotifyOutcome::default();
        NotificationInterpreter::map_item_completed(
            TaskId(0),
            &json!({
                "type":"fileChange","status":"completed",
                "changes":[{"path":"/x/hello.txt","kind":{"type":"add"},"diff":"hi\n"}]
            }),
            &mut out,
        );
        assert!(out.events.iter().any(
            |e| matches!(e, RuntimeEvent::Diff{added, removed, ..} if *added == 1 && *removed == 0)
        ));
        assert_eq!(out.artifact_candidate, Some(PathBuf::from("/x/hello.txt")));
    }

    #[test]
    fn file_change_failed_does_not_set_artifact_candidate() {
        let mut out = NotifyOutcome::default();
        NotificationInterpreter::map_item_completed(
            TaskId(0),
            &json!({
                "type":"fileChange","status":"failed",
                "changes":[{"path":"/x/hello.txt","kind":{"type":"add"},"diff":"hi\n"}]
            }),
            &mut out,
        );
        assert!(out.artifact_candidate.is_none());
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, RuntimeEvent::ToolResult { is_error: true, .. })));
    }

    #[test]
    fn unified_diff_counts_basic() {
        let diff = "--- a\n+++ b\n-old line\n+new line 1\n+new line 2\n";
        assert_eq!(unified_diff_counts(diff), (2, 1));
        assert_eq!(unified_diff_counts("hi\n"), (1, 0));
    }

    #[test]
    fn approval_policy_mapping() {
        assert_eq!(
            approval_policy(&PermissionProfile {
                allow: vec!["*".to_string()]
            }),
            "never"
        );
        assert_eq!(
            approval_policy(&PermissionProfile { allow: vec![] }),
            "on-request"
        );
    }

    #[test]
    fn sandbox_mode_mapping() {
        assert_eq!(sandbox_mode(&SandboxProfile::Isolated), "read-only");
        assert_eq!(
            sandbox_mode(&SandboxProfile::WorkspaceNet),
            "workspace-write"
        );
        assert_eq!(sandbox_mode(&SandboxProfile::Trusted), "danger-full-access");
    }

    #[test]
    fn unknown_notification_methods_are_ignored() {
        let out = NotificationInterpreter::on_notification(
            TaskId(0),
            "account/rateLimits/updated",
            &json!({}),
        );
        assert!(out.events.is_empty());
    }
}
