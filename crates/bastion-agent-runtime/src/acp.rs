//! `AcpAgentRuntime` — A-06 adapter: Bastion **is** the ACP client.
//!
//! Sibling of [`crate::acpx`], and the reason it exists. `acpx` supervises a
//! third-party headless ACP *client* as a subprocess, so the wrapped agent's
//! `session/request_permission` calls are answered by acpx before Bastion ever
//! sees them — hence `acpx`'s honest `approvals = HarnessOwned` and its
//! always-erroring `respond_permission`. This adapter removes that middleman:
//! it speaks ACP JSON-RPC directly with the agent bridge over stdio, so the
//! permission request lands in *our* handler and
//! [`RuntimeSession::respond_permission`] genuinely answers it.
//!
//! # Transport
//!
//! The official Zed SDK (`agent-client-protocol`), pinned exact. The bridge
//! command is an opaque string (`"claude-agent-acp"`,
//! `"npx -y @agentclientprotocol/codex-acp@^0.0.44"`, `"opencode acp"`, …)
//! parsed shell-style and spawned by [`acp::AcpAgent`].
//!
//! # Measured behavior, not assumed behavior
//!
//! Everything this adapter declares in [`AcpAgentRuntime::descriptor`] was
//! probed live against real bridges with `examples/acp_fs_probe.rs`. Three
//! findings shaped the code, and each is load-bearing:
//!
//! **1. Client-mediated filesystem access is advertised and ignored.** The
//! adapter announces `clientCapabilities.fs.{readTextFile,writeTextFile} =
//! true` and implements both methods with real workspace-root enforcement.
//! Measured result, every bridge tried:
//!
//! | bridge | `fs/write_text_file` | `fs/read_text_file` | `session/request_permission` |
//! |---|---|---|---|
//! | `claude-agent-acp@0.70.0` | 0 | 0 | 1 |
//! | `codex-acp@0.0.44` | 0 | 0 | 0 |
//! | `opencode acp` | 0 | 0 | 0 |
//!
//! Every one wrote the file with its own native tools. `claude-agent-acp`'s
//! bundle even carries the plumbing — `async writeTextFile(params) { return
//! this.client.writeTextFile(params) }` — with no internal call site: exposed,
//! never invoked. So the `fs/*` handlers below are correct, enforced, and (for
//! today's bridges) dead code. They are kept because a bridge that starts
//! honoring the capability gets mediated, root-enforced writes for free, and
//! because a client that advertises a capability it cannot honor is a lie.
//!
//! **2. `policy_coverage.approvals` is per-bridge, not per-adapter.** Being the
//! ACP client guarantees that any permission request the agent *makes* reaches
//! Bastion — it does not make an agent ask. `claude-agent-acp` asks before an
//! edit; `codex-acp` and `opencode` resolved the same edit internally and never
//! asked. [`approvals_for`] therefore reports what each bridge was *observed*
//! to do, the same shape [`crate::acpx::default_auth_policy_for`] uses for its
//! own per-agent divergence. `respond_permission` still answers any request
//! that does arrive, whatever the declaration says.
//!
//! **3. Permission options are ordered deny-first.** `claude-agent-acp@0.70.0`
//! offers `[reject, allow, allow_always]`, so the official SDK example's
//! `options.first()` "auto-approve" is in fact a *denial* — verified live, the
//! tool came back `"User refused permission to run tool"`. Decisions are
//! mapped by [`PermissionOptionKind`], never by position, and an agent that
//! offers no option of the needed kind is a [`RuntimeError::Protocol`] error
//! rather than a guess.
//!
//! # Coverage that did not improve
//!
//! `policy_coverage.sandbox = None`, same as `acpx`. `session/new` carries
//! `cwd`, which is a hint; since writes are native (finding 1) nothing stops
//! the agent writing outside the root by absolute path. The workspace root is
//! enforced on the `fs/*` path only. Confinement of the deliberate case remains
//! a job for the layer above.
//!
//! `egress = HarnessOwned`: once a turn starts the wrapped agent holds its own
//! model/tool network authority. Bastion filters what enters via [`TaskInput`].
//!
//! # Concurrency note (SDK contract)
//!
//! `ConnectionTo`'s handler callbacks run **on the event loop** — a handler
//! that awaits blocks the whole connection, including the notification stream.
//! The permission handler must wait for a human decision that can take minutes,
//! so it returns immediately and hands the (owned) `Responder` to
//! [`acp::ConnectionTo::spawn`], which resolves it later off the loop.

use crate::conformance::FaultInjection;
use crate::util::sha256_digest;
use crate::*;
use acp::schema::v1::{
    CancelNotification, ClientCapabilities, ContentBlock, ContentChunk, Diff,
    FileSystemCapabilities, InitializeRequest, NewSessionRequest, PermissionOptionKind,
    PromptRequest, ReadTextFileRequest, ReadTextFileResponse, RequestPermissionOutcome,
    RequestPermissionRequest, RequestPermissionResponse, SelectedPermissionOutcome, SessionId,
    SessionNotification, SessionUpdate, StopReason, TextContent, ToolCall, ToolCallContent,
    ToolCallStatus, ToolCallUpdate, WriteTextFileRequest, WriteTextFileResponse,
};
use acp::schema::ProtocolVersion;
use agent_client_protocol as acp;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

/// How long `start()` waits for `initialize` + `session/new` to complete before
/// declaring the bridge unusable. Generous: a bridge spawned through `npx` may
/// download its package on first run.
const SESSION_OPEN_TIMEOUT: Duration = Duration::from_secs(120);

/// How long `health()` waits for a bare `initialize` handshake.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

/// Grace given to a cooperative `session/cancel` before the session is simply
/// marked cancelled, when the caller does not specify one.
const DEFAULT_CANCEL_GRACE: Duration = Duration::from_millis(500);

/// Classifies a bridge command into a known agent family. Used for the stable
/// `RuntimeDescriptor::id` and for the observed-coverage table.
///
/// Matching is substring-based over the whole command line because a bridge is
/// frequently invoked indirectly (`npx -y @agentclientprotocol/codex-acp@…`),
/// so the first token is not the agent's name. Order matters: `"opencode"`
/// must be tested before any `"code"`-like pattern.
fn agent_key_for(command: &str) -> &'static str {
    let c = command.to_ascii_lowercase();
    if c.contains("opencode") {
        "opencode"
    } else if c.contains("claude") {
        "claude"
    } else if c.contains("codex") {
        "codex"
    } else if c.contains("gemini") {
        "gemini"
    } else {
        "unknown"
    }
}

/// Stable adapter id per agent family (`RuntimeDescriptor::id` is
/// `&'static str`, so this cannot be built from the command at runtime).
fn descriptor_id_for(agent_key: &str) -> &'static str {
    match agent_key {
        "claude" => "acp_claude",
        "codex" => "acp_codex",
        "opencode" => "acp_opencode",
        "gemini" => "acp_gemini",
        _ => "acp_generic",
    }
}

/// Observed approval coverage per bridge — see module docs, finding 2.
///
/// `Bridged` means the bridge was measured actually raising
/// `session/request_permission` for a guarded action, so the decision reaches
/// Bastion's approval queue. `HarnessOwned` means the bridge resolved the same
/// action from its own internal policy without asking. Fail-closed for an
/// unmeasured bridge: claiming a bridge Bastion has never seen ask is exactly
/// the kind of unearned claim `PolicyCoverage` exists to prevent.
fn approvals_for(agent_key: &str) -> ApprovalCoverage {
    match agent_key {
        // Verified live: raises a permission request before an edit, honors
        // both `allow_once` and `reject_once`.
        "claude" => ApprovalCoverage::Bridged,
        // Verified live: wrote the probe file without ever asking, under each
        // bridge's default policy.
        "codex" | "opencode" => ApprovalCoverage::HarnessOwned,
        _ => ApprovalCoverage::HarnessOwned,
    }
}

/// Adapter for one ACP agent bridge. Cheap to construct; sessions are
/// independent processes.
#[derive(Debug, Clone)]
pub struct AcpAgentRuntime {
    /// Full bridge command line, parsed shell-style at spawn time.
    command: String,
    agent_key: &'static str,
}

impl AcpAgentRuntime {
    /// Build an adapter for a bridge command, e.g. `"claude-agent-acp"` or
    /// `"npx -y @agentclientprotocol/codex-acp@^0.0.44"`.
    pub fn new(command: impl Into<String>) -> Self {
        let command = command.into();
        let agent_key = agent_key_for(&command);
        Self { command, agent_key }
    }

    /// Spawn the bridge, perform a bare `initialize`, and return what it says
    /// about itself. Used by both `health()` and, indirectly, the descriptor's
    /// `target_version`.
    async fn handshake(&self) -> Result<String, RuntimeError> {
        let agent = acp::AcpAgent::from_str(&self.command)
            .map_err(|e| RuntimeError::Unavailable(format!("cannot spawn bridge: {e}")))?;
        let (info_tx, info_rx) = oneshot::channel::<String>();

        let connection = acp::Client.builder().name("bastion-acp").connect_with(
            agent,
            |cx: acp::ConnectionTo<acp::Agent>| async move {
                let init = cx
                    .send_request(InitializeRequest::new(ProtocolVersion::V1))
                    .block_task()
                    .await?;
                let version = init
                    .agent_info
                    .map(|i| format!("{} {}", i.name, i.version))
                    .unwrap_or_else(|| "unknown".to_string());
                let _ = info_tx.send(version);
                Ok(())
            },
        );

        // The connection future ends once the closure returns; we only need the
        // handshake result, so racing the two is enough.
        match tokio::time::timeout(HEALTH_TIMEOUT, async move {
            let _ = connection.await;
            info_rx.await
        })
        .await
        {
            Ok(Ok(version)) => Ok(version),
            Ok(Err(_)) => Err(RuntimeError::Unavailable(
                "bridge closed before completing initialize".to_string(),
            )),
            Err(_) => Err(RuntimeError::Timeout(HEALTH_TIMEOUT)),
        }
    }
}

#[async_trait]
impl AgentRuntime for AcpAgentRuntime {
    fn descriptor(&self) -> RuntimeDescriptor {
        RuntimeDescriptor {
            id: descriptor_id_for(self.agent_key),
            adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            // The ACP protocol level this adapter speaks; the bridge's own
            // version is discovered at `health()` time and is not pinnable
            // (any conforming ACP agent is a valid peer).
            target_version: "acp protocol v1".to_string(),
            transport: Transport::JsonRpcSubprocess,
            supports: RuntimeSupports {
                // ACP has `session/load`, but reattaching a bridge subprocess
                // that died with the daemon is not the same contract; declared
                // false until it is actually implemented and measured.
                resume: false,
                // No ACP v1 method injects text into an in-flight turn. A
                // second `session/prompt` queues a new turn, it does not steer.
                steer: false,
                usage_reporting: true,
                diff_events: true,
                permission_bridge: true,
                // One turn at a time per session: a second `session/prompt`
                // while one is active is rejected rather than queued.
                concurrent_sessions: false,
            },
            policy_coverage: PolicyCoverage {
                tool_visibility: ToolVisibility::DeclaredOnly,
                approvals: approvals_for(self.agent_key),
                egress: EgressCoverage::HarnessOwned,
                budget: BudgetCoverage::Reported,
                // Writes are native (module docs, finding 1); `cwd` is a hint,
                // not a jail.
                sandbox: SandboxCoverage::None,
            },
        }
    }

    async fn health(&self) -> Result<RuntimeHealth, RuntimeError> {
        match self.handshake().await {
            Ok(detected_version) => Ok(RuntimeHealth {
                detected_version,
                ready: true,
                detail: None,
            }),
            Err(e) => Ok(RuntimeHealth {
                detected_version: "unknown".to_string(),
                ready: false,
                detail: Some(e.to_string()),
            }),
        }
    }

    async fn start(&self, spec: SessionSpec) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        if !spec.workspace.root.is_dir() {
            return Err(RuntimeError::Unavailable(format!(
                "workspace root is not a directory: {}",
                spec.workspace.root.display()
            )));
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<SessionId, String>>();

        let shared = Arc::new(Shared::new(event_tx, spec.workspace.clone()));
        let agent = acp::AcpAgent::from_str(&self.command)
            .map_err(|e| RuntimeError::Unavailable(format!("cannot spawn bridge: {e}")))?;

        let handle = SessionHandle {
            runtime_id: descriptor_id_for(self.agent_key).to_string(),
            owner: spec.owner.clone(),
            // Filled in below once the agent assigns one; a session that never
            // reached `session/new` has no external ref worth persisting.
            external_ref: String::new(),
        };

        tokio::spawn(run_connection(
            agent,
            shared.clone(),
            spec.clone(),
            cmd_rx,
            ready_tx,
        ));

        let session_id = match tokio::time::timeout(SESSION_OPEN_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(id))) => id,
            Ok(Ok(Err(detail))) => return Err(RuntimeError::Unavailable(detail)),
            Ok(Err(_)) => {
                return Err(RuntimeError::Unavailable(
                    "bridge exited before opening a session".to_string(),
                ))
            }
            Err(_) => return Err(RuntimeError::Timeout(SESSION_OPEN_TIMEOUT)),
        };

        let handle = SessionHandle {
            external_ref: session_id.0.to_string(),
            ..handle
        };
        shared.emit(RuntimeEvent::Started {
            handle: handle.clone(),
        });

        Ok(Box::new(AcpSession {
            handle,
            shared,
            cmd_tx,
            event_rx,
            per_task_timeout: spec.timeout.per_task,
            next_task_id: 0,
        }))
    }

    async fn resume(
        &self,
        handle: &SessionHandle,
        _spec: ResumeSpec,
    ) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        Err(RuntimeError::NotResumable(format!(
            "{} does not reattach: the bridge subprocess holding session {} \
             does not outlive the daemon that spawned it",
            descriptor_id_for(self.agent_key),
            handle.external_ref
        )))
    }
}

impl FaultInjection for AcpAgentRuntime {
    // Every fault-injection hook keeps its default `false`: this adapter has no
    // side channel into a bridge it did not write. The corresponding
    // conformance checks report `Skip`, which is the honest answer.
}

/// Work items sent from the session handle into the connection's event loop.
enum SessionCommand {
    Prompt {
        task: TaskId,
        text: String,
        timeout: Duration,
    },
    Cancel,
    Close,
}

/// A permission request parked waiting for Bastion's decision.
struct PendingPermission {
    decision_tx: oneshot::Sender<PermissionDecision>,
}

/// State shared between the session handle and the connection task.
struct Shared {
    events: mpsc::UnboundedSender<RuntimeEvent>,
    workspace: WorkspacePolicy,
    pending: AsyncMutex<HashMap<u64, PendingPermission>>,
    next_permission_id: AtomicU64,
    /// TaskId of the turn currently in flight; notifications are attributed to
    /// it. Only meaningful while `active` is true.
    current_task: AtomicU64,
    active: AtomicBool,
    /// Set once a terminal `Ended` has been emitted for the current task, so
    /// late notifications from a cancelled/timed-out turn are dropped instead
    /// of violating "nothing follows `Ended`".
    terminal_emitted: AtomicBool,
    status: AsyncMutex<SessionStatus>,
    /// Cumulative context usage last reported, so `Usage` events can carry a
    /// delta (ACP reports a running total).
    last_usage: AtomicU64,
    /// Per-`tool_call_id` accumulator. ACP `session/update` tool-call frames
    /// are incremental *patches*, not snapshots: measured against
    /// `claude-agent-acp@0.70.0`, the frame carrying `status: "completed"`
    /// carries neither `title` nor `locations` — both arrived on earlier
    /// partial updates. A client that reads only the terminal frame sees an
    /// untitled tool call that touched nothing, which is how the first cut of
    /// this adapter emitted no `Artifact` at all. `std::sync::Mutex` because
    /// the update path is synchronous and never awaits while holding it.
    tool_calls: std::sync::Mutex<HashMap<String, ToolCallState>>,
}

/// Everything learned so far about one in-flight tool call.
#[derive(Default, Clone)]
struct ToolCallState {
    title: String,
    locations: Vec<PathBuf>,
}

impl ToolCallState {
    /// Merges a location without duplicating one already recorded.
    fn remember_location(&mut self, path: &Path) {
        if !self.locations.iter().any(|p| p == path) {
            self.locations.push(path.to_path_buf());
        }
    }
}

impl Shared {
    fn new(events: mpsc::UnboundedSender<RuntimeEvent>, workspace: WorkspacePolicy) -> Self {
        Self {
            events,
            workspace,
            pending: AsyncMutex::new(HashMap::new()),
            next_permission_id: AtomicU64::new(1),
            current_task: AtomicU64::new(0),
            active: AtomicBool::new(false),
            terminal_emitted: AtomicBool::new(true),
            status: AsyncMutex::new(SessionStatus::Idle),
            last_usage: AtomicU64::new(0),
            tool_calls: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Emit an event unless the current task is already terminal. `Started` and
    /// `Ended` bypass the gate; everything else is a per-task event that must
    /// not outlive its `Ended`.
    fn emit(&self, event: RuntimeEvent) {
        let terminal = matches!(event, RuntimeEvent::Ended { .. });
        let started = matches!(event, RuntimeEvent::Started { .. });
        if !terminal && !started && self.terminal_emitted.load(Ordering::SeqCst) {
            return;
        }
        let _ = self.events.send(event);
    }

    fn task(&self) -> TaskId {
        TaskId(self.current_task.load(Ordering::SeqCst))
    }

    /// Emit `Ended` exactly once per task; later attempts (a cancel response
    /// arriving after our own timeout already ended the task) are dropped.
    fn end_task(&self, task: TaskId, outcome: TaskOutcome) {
        if self.terminal_emitted.swap(true, Ordering::SeqCst) {
            return;
        }
        self.active.store(false, Ordering::SeqCst);
        let _ = self.events.send(RuntimeEvent::Ended { task, outcome });
    }

    /// True when `path` is inside the session root and not under a denied
    /// subtree. Both sides are canonicalized where possible so `..` and
    /// symlinks cannot walk out.
    fn path_allowed(&self, path: &Path) -> bool {
        let root = self
            .workspace
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.workspace.root.clone());
        // A file being created does not exist yet, so canonicalize its parent.
        let candidate = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => match path.parent().map(|p| p.canonicalize()) {
                Some(Ok(parent)) => match path.file_name() {
                    Some(name) => parent.join(name),
                    None => return false,
                },
                _ => return false,
            },
        };
        if !candidate.starts_with(&root) {
            return false;
        }
        !self.workspace.deny.iter().any(|denied| {
            let denied = if denied.is_absolute() {
                denied.clone()
            } else {
                root.join(denied)
            };
            candidate.starts_with(&denied)
        })
    }
}

/// Drives one bridge connection for the lifetime of a session.
async fn run_connection(
    agent: acp::AcpAgent,
    shared: Arc<Shared>,
    spec: SessionSpec,
    mut cmd_rx: mpsc::UnboundedReceiver<SessionCommand>,
    ready_tx: oneshot::Sender<Result<SessionId, String>>,
) {
    let notify_shared = shared.clone();
    let perm_shared = shared.clone();
    let write_shared = shared.clone();
    let read_shared = shared.clone();
    let loop_shared = shared.clone();
    let perm_profile = spec.permissions.clone();

    let result = acp::Client
        .builder()
        .name("bastion-acp")
        .on_receive_notification(
            move |notification: SessionNotification, _cx| {
                let shared = notify_shared.clone();
                async move {
                    handle_session_update(&shared, notification.update);
                    Ok(())
                }
            },
            acp::on_receive_notification!(),
        )
        .on_receive_request(
            move |request: RequestPermissionRequest,
                  responder: acp::Responder<RequestPermissionResponse>,
                  cx: acp::ConnectionTo<acp::Agent>| {
                let shared = perm_shared.clone();
                let profile = perm_profile.clone();
                async move {
                    let (action, detail) = describe_permission(&request);

                    // Pre-authorized by the session's permission profile: answer
                    // here, on the loop, and never raise a bridged request — that
                    // is exactly what `PermissionProfile` means.
                    if auto_allowed(&profile, &action) {
                        tracing::debug!(%detail, "permission pre-authorized by profile");
                        let response = permission_response(&request, PermissionDecision::Allow)?;
                        return responder.respond(response);
                    }

                    // Handlers run ON the event loop (see module docs): register
                    // the request, emit the event, and hand the responder to a
                    // spawned task so the loop keeps pumping notifications while
                    // a human decides.
                    let id = shared.next_permission_id.fetch_add(1, Ordering::SeqCst);
                    let (decision_tx, decision_rx) = oneshot::channel();
                    shared
                        .pending
                        .lock()
                        .await
                        .insert(id, PendingPermission { decision_tx });

                    shared.emit(RuntimeEvent::PermissionRequest {
                        task: shared.task(),
                        id: PermissionRequestId(id),
                        action,
                        detail,
                    });

                    let spawn_shared = shared.clone();
                    cx.spawn(async move {
                        // A dropped sender (session torn down mid-decision)
                        // is a denial, never an approval.
                        let decision = decision_rx.await.unwrap_or(PermissionDecision::Deny {
                            scope: DenyScope::Instance,
                        });
                        spawn_shared.pending.lock().await.remove(&id);
                        let response = permission_response(&request, decision)?;
                        responder.respond(response)
                    })
                }
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            move |request: WriteTextFileRequest,
                  responder: acp::Responder<WriteTextFileResponse>,
                  _cx| {
                let shared = write_shared.clone();
                async move {
                    // Dead code against every bridge measured so far (module
                    // docs, finding 1) — and fully enforced anyway, so a bridge
                    // that starts honoring the capability is governed from the
                    // first write rather than from the first bug report.
                    if !shared.path_allowed(&request.path) {
                        return responder.respond_with_internal_error(format!(
                            "write denied by policy: {} is outside the session workspace",
                            request.path.display()
                        ));
                    }
                    match std::fs::write(&request.path, &request.content) {
                        Ok(()) => responder.respond(WriteTextFileResponse::new()),
                        Err(e) => {
                            responder.respond_with_internal_error(format!("write failed: {e}"))
                        }
                    }
                }
            },
            acp::on_receive_request!(),
        )
        .on_receive_request(
            move |request: ReadTextFileRequest,
                  responder: acp::Responder<ReadTextFileResponse>,
                  _cx| {
                let shared = read_shared.clone();
                async move {
                    if !shared.path_allowed(&request.path) {
                        return responder.respond_with_internal_error(format!(
                            "read denied by policy: {} is outside the session workspace",
                            request.path.display()
                        ));
                    }
                    match std::fs::read_to_string(&request.path) {
                        Ok(content) => responder.respond(ReadTextFileResponse::new(content)),
                        Err(e) => {
                            responder.respond_with_internal_error(format!("read failed: {e}"))
                        }
                    }
                }
            },
            acp::on_receive_request!(),
        )
        .connect_with(agent, move |cx: acp::ConnectionTo<acp::Agent>| async move {
            let init = cx
                .send_request(
                    InitializeRequest::new(ProtocolVersion::V1).client_capabilities(
                        ClientCapabilities::new().fs(FileSystemCapabilities::new()
                            .read_text_file(true)
                            .write_text_file(true)),
                    ),
                )
                .block_task()
                .await;
            let init = match init {
                Ok(v) => v,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("initialize failed: {e}")));
                    return Ok(());
                }
            };
            tracing::debug!(
                agent = ?init.agent_info.as_ref().map(|i| i.name.clone()),
                "acp bridge initialized"
            );

            let session = cx
                .send_request(NewSessionRequest::new(loop_shared.workspace.root.clone()))
                .block_task()
                .await;
            let session = match session {
                Ok(v) => v,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("session/new failed: {e}")));
                    return Ok(());
                }
            };
            let session_id = session.session_id.clone();

            // "Surface, never silently drop" (see `ResumeSpec` docs): this
            // adapter does not yet translate Bastion's MCP bridge spec into
            // ACP `mcpServers`, so say so instead of pretending it applied.
            if spec.mcp_bridge.is_some() {
                loop_shared.emit(RuntimeEvent::Warning {
                    task: TaskId(0),
                    code: WarnCode::DegradedTransport,
                    detail: "mcp_bridge is not yet translated into ACP mcpServers; \
                             the session was opened without it"
                        .to_string(),
                });
            }

            let _ = ready_tx.send(Ok(session_id.clone()));
            *loop_shared.status.lock().await = SessionStatus::Idle;

            while let Some(command) = cmd_rx.recv().await {
                match command {
                    SessionCommand::Prompt {
                        task,
                        text,
                        timeout,
                    } => {
                        let shared = loop_shared.clone();
                        let session_id = session_id.clone();
                        let inner = cx.clone();
                        // Spawned, not awaited: the loop must stay free to
                        // process a `Cancel` while the turn is in flight.
                        cx.spawn(async move {
                            run_turn(inner, shared, session_id, task, text, timeout).await;
                            Ok(())
                        })?;
                    }
                    SessionCommand::Cancel => {
                        let _ = cx.send_notification(CancelNotification::new(session_id.clone()));
                    }
                    SessionCommand::Close => break,
                }
            }
            Ok(())
        })
        .await;

    if let Err(e) = result {
        tracing::warn!(error = %e, "acp connection ended with error");
        *shared.status.lock().await = SessionStatus::Crashed;
        // A crash mid-turn must still produce the turn's terminal event.
        if shared.active.load(Ordering::SeqCst) {
            shared.end_task(
                shared.task(),
                TaskOutcome::Failed {
                    reason: format!("bridge connection lost: {e}"),
                },
            );
        }
    } else {
        let mut status = shared.status.lock().await;
        if *status != SessionStatus::Cancelled {
            *status = SessionStatus::Closed;
        }
    }
}

/// Runs one `session/prompt` turn under the per-task timeout watchdog.
async fn run_turn(
    cx: acp::ConnectionTo<acp::Agent>,
    shared: Arc<Shared>,
    session_id: SessionId,
    task: TaskId,
    text: String,
    timeout: Duration,
) {
    *shared.status.lock().await = SessionStatus::Running;
    let request = PromptRequest::new(
        session_id.clone(),
        vec![ContentBlock::Text(TextContent::new(text))],
    );

    let outcome = match tokio::time::timeout(timeout, cx.send_request(request).block_task()).await {
        Ok(Ok(response)) => match response.stop_reason {
            StopReason::EndTurn | StopReason::MaxTokens | StopReason::MaxTurnRequests => {
                TaskOutcome::Success
            }
            StopReason::Refusal => TaskOutcome::Failed {
                reason: "agent refused to continue".to_string(),
            },
            StopReason::Cancelled => TaskOutcome::Cancelled,
            // `StopReason` is `#[non_exhaustive]`: a stop reason added by a
            // future protocol level is reported as a typed failure carrying
            // what the agent actually said, never silently as success.
            other => TaskOutcome::Failed {
                reason: format!("unrecognized stop reason: {other:?}"),
            },
        },
        Ok(Err(e)) => TaskOutcome::Failed {
            reason: format!("prompt failed: {e}"),
        },
        Err(_) => {
            // Our own watchdog, not the caller's cancel: tell the agent to stop,
            // then report `TimedOut` — never `Cancelled`, which would conflate
            // the two (A-05 §5.4).
            let _ = cx.send_notification(CancelNotification::new(session_id));
            TaskOutcome::TimedOut
        }
    };

    let mut status = shared.status.lock().await;
    *status = match &outcome {
        TaskOutcome::Cancelled => SessionStatus::Cancelled,
        _ => SessionStatus::Idle,
    };
    drop(status);
    shared.end_task(task, outcome);
}

/// Maps one ACP `session/update` notification onto the Bastion event stream.
fn handle_session_update(shared: &Shared, update: SessionUpdate) {
    let task = shared.task();
    match update {
        SessionUpdate::AgentMessageChunk(ContentChunk { content, .. }) => {
            if let Some(text) = content_text(&content) {
                shared.emit(RuntimeEvent::MessageDelta { task, text });
            }
        }
        SessionUpdate::AgentThoughtChunk(ContentChunk { content, .. }) => {
            if let Some(summary) = content_text(&content) {
                shared.emit(RuntimeEvent::Thinking { task, summary });
            }
        }
        SessionUpdate::ToolCall(call) => emit_tool_call(shared, task, &call),
        SessionUpdate::ToolCallUpdate(update) => emit_tool_call_update(shared, task, &update),
        SessionUpdate::UsageUpdate(usage) => {
            // ACP reports a running total for the context window; the contract
            // wants a delta. A total that went down (a compaction) yields no
            // event rather than a nonsense negative.
            let previous = shared.last_usage.swap(usage.used, Ordering::SeqCst);
            if usage.used > previous {
                shared.emit(RuntimeEvent::Usage {
                    task,
                    delta: UsageDelta {
                        input_tokens: usage.used - previous,
                        output_tokens: 0,
                    },
                });
            }
        }
        // Not part of this contract's vocabulary; ignored, never an error.
        _ => {}
    }
}

fn emit_tool_call(shared: &Shared, task: TaskId, call: &ToolCall) {
    let key = call.tool_call_id.0.to_string();
    {
        let mut calls = shared.tool_calls.lock().unwrap_or_else(|e| e.into_inner());
        let state = calls.entry(key).or_default();
        if !call.title.is_empty() {
            state.title = call.title.clone();
        }
        for location in &call.locations {
            state.remember_location(&location.path);
        }
        for block in &call.content {
            if let ToolCallContent::Diff(diff) = block {
                state.remember_location(&diff.path);
            }
        }
    }
    shared.emit(RuntimeEvent::ToolCall {
        task,
        name: call.title.clone(),
        input_digest: digest_of(call.raw_input.as_ref()),
    });
    emit_diffs(shared, task, &call.content);
}

fn emit_tool_call_update(shared: &Shared, task: TaskId, update: &ToolCallUpdate) {
    let key = update.tool_call_id.0.to_string();

    // Fold this patch into what is already known about the call, BEFORE acting
    // on its status — the terminal frame is the one that knows least.
    let state = {
        let mut calls = shared.tool_calls.lock().unwrap_or_else(|e| e.into_inner());
        let state = calls.entry(key.clone()).or_default();
        if let Some(title) = &update.fields.title {
            if !title.is_empty() {
                state.title = title.clone();
            }
        }
        if let Some(locations) = &update.fields.locations {
            for location in locations {
                state.remember_location(&location.path);
            }
        }
        if let Some(content) = &update.fields.content {
            for block in content {
                if let ToolCallContent::Diff(diff) = block {
                    state.remember_location(&diff.path);
                }
            }
        }
        state.clone()
    };

    if let Some(content) = &update.fields.content {
        emit_diffs(shared, task, content);
    }

    let is_error = match update.fields.status {
        Some(ToolCallStatus::Completed) => false,
        Some(ToolCallStatus::Failed) => true,
        _ => return,
    };

    shared.emit(RuntimeEvent::ToolResult {
        task,
        name: state.title.clone(),
        output_digest: digest_of(update.fields.raw_output.as_ref()),
        is_error,
    });
    if !is_error {
        emit_artifacts(shared, task, &state);
    }
    shared
        .tool_calls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key);
}

/// Emits a `Diff` event per diff-carrying content block.
fn emit_diffs(shared: &Shared, task: TaskId, content: &[ToolCallContent]) {
    for block in content {
        if let ToolCallContent::Diff(Diff {
            path,
            old_text,
            new_text,
            ..
        }) = block
        {
            let (added, removed) = line_diff_counts(old_text.as_deref(), new_text);
            shared.emit(RuntimeEvent::Diff {
                task,
                path: relative_to_root(shared, path),
                added,
                removed,
            });
        }
    }
}

/// After a tool call completes, publish each touched in-root file as an
/// `Artifact` with a digest of what is actually on disk. The digest is read
/// from the file rather than from the reported diff: the agent wrote natively,
/// so the file is the only source of truth about what happened.
///
/// Takes the accumulated [`ToolCallState`], not the terminal frame — see the
/// `tool_calls` field docs for why the terminal frame is not enough.
fn emit_artifacts(shared: &Shared, task: TaskId, state: &ToolCallState) {
    for path in &state.locations {
        if !shared.path_allowed(path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        shared.emit(RuntimeEvent::Artifact {
            task,
            artifact: Artifact {
                kind: ArtifactKind::File,
                path: relative_to_root(shared, path),
                digest: sha256_digest(&bytes),
                produced_by: None,
            },
        });
    }
}

/// Paths cross the contract relative to the session root ([`Artifact::path`]).
fn relative_to_root(shared: &Shared, path: &Path) -> PathBuf {
    let root = shared
        .workspace
        .root
        .canonicalize()
        .unwrap_or_else(|_| shared.workspace.root.clone());
    let candidate = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    candidate
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
}

fn content_text(content: &ContentBlock) -> Option<String> {
    match content {
        ContentBlock::Text(text) => Some(text.text.clone()),
        _ => None,
    }
}

fn digest_of(value: Option<&serde_json::Value>) -> String {
    let bytes = value
        .map(|v| v.to_string().into_bytes())
        .unwrap_or_default();
    sha256_digest(&bytes)
}

/// Line counts for a diff, matching [`crate::acpx`]'s accounting so the two
/// adapters report the same numbers for the same edit.
fn line_diff_counts(old: Option<&str>, new: &str) -> (u32, u32) {
    let added = new.lines().count() as u32;
    let removed = old.map(|o| o.lines().count() as u32).unwrap_or(0);
    (added, removed)
}

/// Identifier used in [`PermissionProfile::allow`] for each action class this
/// adapter can gate. `PermissionProfile` is documented as
/// "what the harness may do **without** raising a permission request", so an
/// entry here means the decision never reaches the approval queue at all.
///
/// Adapter-namespaced, as the contract requires. `"*"` keeps the wildcard
/// meaning both sibling adapters already give it ([`crate::codex`] maps it to
/// codex's `approval_policy = never`, [`crate::acpx`] to `--approve-all`);
/// unlike them, this adapter can also gate one class at a time, because it is
/// the party actually answering each request.
fn permission_identifier(action: &PermissionAction) -> &'static str {
    match action {
        PermissionAction::WriteFile => "acp:write_file",
        PermissionAction::RunCommand => "acp:run_command",
        PermissionAction::Network => "acp:network",
        PermissionAction::UseTool => "acp:use_tool",
        PermissionAction::Other(_) => "acp:other",
    }
}

/// True when the session's permission profile pre-authorizes this action, so
/// the adapter answers `allow` itself instead of raising a bridged request.
///
/// Deny-by-default: an empty profile (the [`PermissionProfile::default`]) gates
/// everything, which is why a conformance scenario that expects a write to
/// simply succeed must say so in its profile.
fn auto_allowed(profile: &PermissionProfile, action: &PermissionAction) -> bool {
    let id = permission_identifier(action);
    profile.allow.iter().any(|a| a == "*" || a == id)
}

/// Classifies a permission request into the contract's action vocabulary, and
/// renders a human-readable detail line for the approval card.
fn describe_permission(request: &RequestPermissionRequest) -> (PermissionAction, String) {
    let title = request.tool_call.fields.title.clone().unwrap_or_default();
    let paths: Vec<String> = request
        .tool_call
        .fields
        .locations
        .as_ref()
        .map(|l| l.iter().map(|x| x.path.display().to_string()).collect())
        .unwrap_or_default();

    let action = match request.tool_call.fields.kind {
        Some(acp::schema::v1::ToolKind::Edit) | Some(acp::schema::v1::ToolKind::Delete) => {
            PermissionAction::WriteFile
        }
        Some(acp::schema::v1::ToolKind::Execute) => PermissionAction::RunCommand,
        Some(acp::schema::v1::ToolKind::Fetch) => PermissionAction::Network,
        Some(_) | None => PermissionAction::UseTool,
    };

    let detail = if paths.is_empty() {
        title
    } else {
        format!("{title} — {}", paths.join(", "))
    };
    (action, detail)
}

/// Turns a Bastion decision into the ACP option the agent offered.
///
/// Selection is by [`PermissionOptionKind`], never by position: this bridge
/// family orders options deny-first (module docs, finding 3). An agent that
/// offers no option of the required kind is a protocol error — guessing which
/// of its options means "allow" is exactly the mistake that would auto-approve
/// a write nobody approved.
fn permission_response(
    request: &RequestPermissionRequest,
    decision: PermissionDecision,
) -> Result<RequestPermissionResponse, acp::Error> {
    let wanted: &[PermissionOptionKind] = match decision {
        PermissionDecision::Allow => &[
            PermissionOptionKind::AllowOnce,
            PermissionOptionKind::AllowAlways,
        ],
        PermissionDecision::Deny { .. } => &[
            PermissionOptionKind::RejectOnce,
            PermissionOptionKind::RejectAlways,
        ],
    };

    for kind in wanted {
        if let Some(option) = request.options.iter().find(|o| o.kind == *kind) {
            return Ok(RequestPermissionResponse::new(
                RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                    option.option_id.clone(),
                )),
            ));
        }
    }

    // No option of the needed kind. For a denial there is still a safe answer:
    // `Cancelled` ends the request without performing the action. For an
    // approval there is none — refuse rather than pick something.
    match decision {
        PermissionDecision::Deny { .. } => Ok(RequestPermissionResponse::new(
            RequestPermissionOutcome::Cancelled,
        )),
        PermissionDecision::Allow => Err(acp::util::internal_error(
            "agent offered no allow-kind permission option",
        )),
    }
}

/// One live ACP session.
struct AcpSession {
    handle: SessionHandle,
    shared: Arc<Shared>,
    cmd_tx: mpsc::UnboundedSender<SessionCommand>,
    event_rx: mpsc::UnboundedReceiver<RuntimeEvent>,
    per_task_timeout: Duration,
    next_task_id: u64,
}

#[async_trait]
impl RuntimeSession for AcpSession {
    fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }

    async fn submit(&mut self, input: TaskInput) -> Result<TaskId, RuntimeError> {
        if self.shared.active.swap(true, Ordering::SeqCst) {
            return Err(RuntimeError::Protocol(
                "a task is already active and this adapter declares \
                 concurrent_sessions=false"
                    .to_string(),
            ));
        }
        if input.model_hint.is_some() {
            self.shared.emit(RuntimeEvent::Warning {
                task: self.shared.task(),
                code: WarnCode::DegradedTransport,
                detail: "model_hint ignored: ACP v1 selects the model inside the \
                         bridge, with no per-prompt knob"
                    .to_string(),
            });
        }

        self.next_task_id += 1;
        let task = TaskId(self.next_task_id);
        self.shared
            .current_task
            .store(self.next_task_id, Ordering::SeqCst);
        self.shared.terminal_emitted.store(false, Ordering::SeqCst);

        self.cmd_tx
            .send(SessionCommand::Prompt {
                task,
                text: input.prompt,
                timeout: self.per_task_timeout,
            })
            .map_err(|_| {
                self.shared.active.store(false, Ordering::SeqCst);
                RuntimeError::Crashed("bridge connection is gone".to_string())
            })?;
        Ok(task)
    }

    async fn next_event(&mut self) -> Option<RuntimeEvent> {
        self.event_rx.recv().await
    }

    async fn steer(&mut self, _text: &str) -> Result<(), RuntimeError> {
        Err(RuntimeError::Protocol(
            "steer is not supported: ACP v1 has no method to inject text into \
             an in-flight turn"
                .to_string(),
        ))
    }

    async fn cancel(&mut self, mode: CancelMode) -> Result<(), RuntimeError> {
        // Idempotent: cancelling an idle session is a no-op, not an error.
        let _ = self.cmd_tx.send(SessionCommand::Cancel);
        let grace = match mode {
            CancelMode::Graceful { grace } => grace,
            CancelMode::Kill => Duration::ZERO,
        };
        if !grace.is_zero() {
            // Give the agent its chance to answer `stopReason: cancelled`,
            // which is what turns the turn's `Ended` into `Cancelled`.
            tokio::time::sleep(grace.min(DEFAULT_CANCEL_GRACE.max(grace))).await;
        }
        if self.shared.active.load(Ordering::SeqCst) {
            self.shared
                .end_task(self.shared.task(), TaskOutcome::Cancelled);
        }
        *self.shared.status.lock().await = SessionStatus::Cancelled;
        Ok(())
    }

    async fn respond_permission(
        &mut self,
        id: PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), RuntimeError> {
        let entry = self.shared.pending.lock().await.remove(&id.0);
        let Some(entry) = entry else {
            return Err(RuntimeError::Protocol(
                "no matching pending permission request".to_string(),
            ));
        };
        entry.decision_tx.send(decision).map_err(|_| {
            RuntimeError::Protocol("permission request was abandoned by the bridge".to_string())
        })?;

        // `DenyScope::Turn` (the product default) closes the
        // "deny one tool call, the agent reroutes through another ungated one"
        // gap at the adapter boundary — same contract `codex.rs` implements.
        if decision
            == (PermissionDecision::Deny {
                scope: DenyScope::Turn,
            })
        {
            self.cancel(CancelMode::Graceful {
                grace: DEFAULT_CANCEL_GRACE,
            })
            .await?;
        }
        Ok(())
    }

    async fn status(&self) -> Result<SessionStatus, RuntimeError> {
        Ok(*self.shared.status.lock().await)
    }
}

impl Drop for AcpSession {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(SessionCommand::Close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_key_recognizes_bridges_by_command_line() {
        assert_eq!(agent_key_for("claude-agent-acp"), "claude");
        assert_eq!(
            agent_key_for("npx -y @agentclientprotocol/codex-acp@^0.0.44"),
            "codex"
        );
        // `opencode` must not be mistaken for `codex`.
        assert_eq!(agent_key_for("opencode acp"), "opencode");
        assert_eq!(agent_key_for("npx -y opencode-ai acp"), "opencode");
        assert_eq!(agent_key_for("some-unknown-bridge"), "unknown");
    }

    #[test]
    fn descriptor_ids_are_per_agent() {
        assert_eq!(
            AcpAgentRuntime::new("claude-agent-acp").descriptor().id,
            "acp_claude"
        );
        assert_eq!(
            AcpAgentRuntime::new("opencode acp").descriptor().id,
            "acp_opencode"
        );
        assert_eq!(
            AcpAgentRuntime::new("weird-bridge").descriptor().id,
            "acp_generic"
        );
    }

    /// The whole point of the adapter: the bridge Bastion measured actually
    /// asking gets `Bridged`; the ones measured never asking stay honest.
    #[test]
    fn approval_coverage_reflects_measured_behavior_per_bridge() {
        let claude = AcpAgentRuntime::new("claude-agent-acp").descriptor();
        assert_eq!(
            claude.policy_coverage.approvals,
            ApprovalCoverage::Bridged,
            "claude-agent-acp was measured raising session/request_permission"
        );
        for command in [
            "npx -y @agentclientprotocol/codex-acp@^0.0.44",
            "opencode acp",
        ] {
            assert_eq!(
                AcpAgentRuntime::new(command)
                    .descriptor()
                    .policy_coverage
                    .approvals,
                ApprovalCoverage::HarnessOwned,
                "{command} wrote the probe file without ever asking"
            );
        }
    }

    /// Never `Honored`: writes are native, so the root is a hint on that path.
    #[test]
    fn sandbox_coverage_is_none_because_writes_are_native() {
        assert_eq!(
            AcpAgentRuntime::new("claude-agent-acp")
                .descriptor()
                .policy_coverage
                .sandbox,
            SandboxCoverage::None
        );
    }

    fn option(kind: PermissionOptionKind, id: &str) -> acp::schema::v1::PermissionOption {
        acp::schema::v1::PermissionOption::new(
            acp::schema::v1::PermissionOptionId::from(id.to_string()),
            id.to_string(),
            kind,
        )
    }

    fn permission_request(
        options: Vec<acp::schema::v1::PermissionOption>,
    ) -> RequestPermissionRequest {
        RequestPermissionRequest::new(
            SessionId::from("s".to_string()),
            ToolCallUpdate::new(
                acp::schema::v1::ToolCallId::from("t".to_string()),
                acp::schema::v1::ToolCallUpdateFields::default(),
            ),
            options,
        )
    }

    /// Regression pin for the finding that cost a wasted probe run: the real
    /// bridge lists `reject` FIRST, so anything positional approves nothing —
    /// or worse, denies while believing it approved.
    #[test]
    fn allow_selects_the_allow_option_even_when_deny_is_listed_first() {
        let request = permission_request(vec![
            option(PermissionOptionKind::RejectOnce, "reject"),
            option(PermissionOptionKind::AllowOnce, "allow"),
            option(PermissionOptionKind::AllowAlways, "allow_always"),
        ]);
        let response = permission_response(&request, PermissionDecision::Allow).unwrap();
        match response.outcome {
            RequestPermissionOutcome::Selected(selected) => {
                assert_eq!(selected.option_id.0.as_ref(), "allow");
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn deny_selects_a_reject_option() {
        let request = permission_request(vec![
            option(PermissionOptionKind::RejectOnce, "reject"),
            option(PermissionOptionKind::AllowOnce, "allow"),
        ]);
        let response = permission_response(
            &request,
            PermissionDecision::Deny {
                scope: DenyScope::Turn,
            },
        )
        .unwrap();
        match response.outcome {
            RequestPermissionOutcome::Selected(selected) => {
                assert_eq!(selected.option_id.0.as_ref(), "reject");
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    /// Fail-closed: with no allow-kind option on offer, refuse instead of
    /// picking whatever is there.
    #[test]
    fn allow_without_an_allow_option_is_an_error_not_a_guess() {
        let request = permission_request(vec![option(PermissionOptionKind::RejectOnce, "reject")]);
        assert!(permission_response(&request, PermissionDecision::Allow).is_err());
    }

    /// A denial always has a safe answer, even with no reject option offered.
    #[test]
    fn deny_without_a_reject_option_falls_back_to_cancelled() {
        let request = permission_request(vec![option(PermissionOptionKind::AllowOnce, "allow")]);
        let response = permission_response(
            &request,
            PermissionDecision::Deny {
                scope: DenyScope::Instance,
            },
        )
        .unwrap();
        assert!(matches!(
            response.outcome,
            RequestPermissionOutcome::Cancelled
        ));
    }

    /// Deny-by-default: the default profile gates every action class, which is
    /// what makes a bridged approval queue meaningful in the first place.
    #[test]
    fn empty_permission_profile_gates_everything() {
        let profile = PermissionProfile::default();
        for action in [
            PermissionAction::WriteFile,
            PermissionAction::RunCommand,
            PermissionAction::Network,
            PermissionAction::UseTool,
        ] {
            assert!(!auto_allowed(&profile, &action));
        }
    }

    #[test]
    fn permission_profile_pre_authorizes_only_the_listed_class() {
        let profile = PermissionProfile {
            allow: vec!["acp:write_file".to_string()],
        };
        assert!(auto_allowed(&profile, &PermissionAction::WriteFile));
        assert!(!auto_allowed(&profile, &PermissionAction::RunCommand));
        assert!(!auto_allowed(&profile, &PermissionAction::Network));
    }

    /// Same wildcard meaning both sibling adapters give it.
    #[test]
    fn wildcard_pre_authorizes_every_class() {
        let profile = PermissionProfile {
            allow: vec!["*".to_string()],
        };
        assert!(auto_allowed(&profile, &PermissionAction::WriteFile));
        assert!(auto_allowed(&profile, &PermissionAction::RunCommand));
        assert!(auto_allowed(
            &profile,
            &PermissionAction::Other("weird".to_string())
        ));
    }

    /// Regression pin for the bug the live conformance sweep caught: measured
    /// against `claude-agent-acp@0.70.0`, the `status: "completed"` frame
    /// carries neither `title` nor `locations`. Reading only that frame yields
    /// an untitled `ToolResult` and no `Artifact` at all — which is exactly how
    /// `artifact_digest` failed with "no Artifact event observed before Ended".
    #[test]
    fn tool_call_state_accumulates_across_incremental_updates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("written.txt");
        std::fs::write(&target, b"HELLO").unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let shared = Shared::new(
            tx,
            WorkspacePolicy {
                root: root.clone(),
                read_only: false,
                deny: Vec::new(),
            },
        );
        shared.terminal_emitted.store(false, Ordering::SeqCst);

        let id = acp::schema::v1::ToolCallId::from("tc-1".to_string());

        // Frame 1: a placeholder title, no locations — what the bridge sends
        // while the tool input is still streaming.
        handle_session_update(
            &shared,
            SessionUpdate::ToolCall(ToolCall::new(id.clone(), "Preparing file…".to_string())),
        );
        // Frame 2: the real title and the touched path.
        let mut fields = acp::schema::v1::ToolCallUpdateFields::default();
        fields.title = Some("Write written.txt".to_string());
        fields.locations = Some(vec![acp::schema::v1::ToolCallLocation::new(target.clone())]);
        handle_session_update(
            &shared,
            SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(id.clone(), fields)),
        );
        // Frame 3: terminal, and empty of everything that matters.
        let mut done = acp::schema::v1::ToolCallUpdateFields::default();
        done.status = Some(ToolCallStatus::Completed);
        handle_session_update(
            &shared,
            SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(id, done)),
        );

        let mut result_name = None;
        let mut artifact = None;
        while let Ok(event) = rx.try_recv() {
            match event {
                RuntimeEvent::ToolResult { name, is_error, .. } => {
                    assert!(!is_error);
                    result_name = Some(name);
                }
                RuntimeEvent::Artifact { artifact: a, .. } => artifact = Some(a),
                _ => {}
            }
        }

        assert_eq!(
            result_name.as_deref(),
            Some("Write written.txt"),
            "the title from frame 2 must survive to the terminal frame"
        );
        let artifact = artifact.expect("completed tool call must publish its touched file");
        assert_eq!(artifact.path, PathBuf::from("written.txt"));
        assert_eq!(artifact.digest, sha256_digest(b"HELLO"));
    }

    #[test]
    fn path_allowed_rejects_escapes_and_denied_subtrees() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("secrets")).unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        let shared = Shared::new(
            tx,
            WorkspacePolicy {
                root: root.clone(),
                read_only: false,
                deny: vec![PathBuf::from("secrets")],
            },
        );

        assert!(shared.path_allowed(&root.join("ok.txt")));
        assert!(!shared.path_allowed(&root.join("secrets/key.txt")));
        assert!(!shared.path_allowed(&root.join("../escape.txt")));
        assert!(!shared.path_allowed(Path::new("/etc/passwd")));
    }
}
