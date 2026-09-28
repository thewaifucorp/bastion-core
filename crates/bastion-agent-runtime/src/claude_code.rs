//! `ClaudeCodeRuntime` — Claude Code, the unmodified `claude` binary, driven
//! directly as a conversation runtime under the operator's own login.
//!
//! # Why a direct adapter
//!
//! A Claude Pro/Max subscription may only be used through the official
//! `claude` binary, unmodified, under the user's own login. Bastion never sees
//! the credential: it does not read `~/.claude`, does not collect or proxy the
//! OAuth token, does not send Claude Code's identity headers itself, and does
//! not run an agent library in front of the binary. [`crate::acp`] reaches
//! Claude Code through `claude-agent-acp`, which is an Agent SDK application
//! that by default launches the SDK's own bundled copy of Claude Code; this
//! adapter removes that layer and speaks to the installed `claude` itself.
//!
//! # Transport
//!
//! `claude -p --input-format stream-json --output-format stream-json
//! --verbose` keeps one process per session: each [`RuntimeSession::submit`]
//! writes one `user` frame on stdin, and the process answers with NDJSON on
//! stdout (`system`, `assistant`, `user` tool results, `result`). stdout is
//! parsed as structured frames only ([`crate::util::parse_structured_line`]);
//! a non-JSON line fails the session closed. stderr is drained to `tracing`
//! and never interpreted.
//!
//! `--permission-prompt-tool stdio` makes the binary ask its host before a
//! guarded tool runs: a `control_request` of subtype `can_use_tool` carrying
//! the tool name and its full input. That request becomes a
//! [`RuntimeEvent::PermissionRequest`] with the proposed edits, and
//! [`RuntimeSession::respond_permission`] answers it with a
//! `control_response` (`allow` with the unchanged input, or `deny`, with
//! `interrupt` for [`DenyScope::Turn`]). Cancellation and the task watchdog
//! send a `control_request` of subtype `interrupt`; the turn then ends with a
//! `result` of subtype `error_during_execution` and the process stays usable.
//!
//! # Measured behavior (Claude Code 2.1.284, subscription login)
//!
//! - `can_use_tool` arrives for `Write`/`Edit`/`Bash`; reads do not ask in the
//!   `default` permission mode. `allow` executes the tool; `deny` with
//!   `interrupt: true` ends the turn as `error_during_execution`.
//! - One process answers several user frames in order, one `result` each.
//! - `--resume <id>` for an unknown conversation writes a `result` error frame
//!   before any input and exits; a known one waits silently for input.
//!   [`AgentRuntime::resume`] watches for that early frame to return
//!   [`RuntimeError::NotResumable`] instead of a session that fails later.
//! - Conversations are stored by Claude Code per working directory, so the
//!   persisted [`SessionHandle::external_ref`] carries the directory with the
//!   conversation id.
//!
//! # Governance
//!
//! The session loads none of the operator's Claude Code settings
//! (`--setting-sources ""`), so a user `allow` rule, `defaultMode`, hook or
//! plugin cannot answer a permission before Bastion sees it; the mode is
//! pinned to `default`; only the MCP servers Bastion bridged are loaded
//! (`--strict-mcp-config`) and pre-allowed (every call there is already
//! decided by Bastion's own policy server-side). Claude Code's auto memory is
//! off: memory belongs to the Bastion session. The environment is the
//! session's allowlist minus every Anthropic credential or endpoint variable
//! ([`is_withheld_env`]), so the binary authenticates only with its own login.
//! The `system/init` frame is checked: a permission mode other than the one
//! requested, or a credential source other than the login, is surfaced as a
//! [`RuntimeEvent::Warning`].
//!
//! # Session model
//!
//! The Bastion session is canonical: Bastion records the conversation, the
//! permission decisions and the usage. The Claude Code conversation is its
//! child, created with `--session-id`, persisted as the handle Bastion stores
//! next to its own session, and reattached with `--resume` after a restart.

use crate::confine;
use crate::conformance::FaultInjection;
use crate::util::{
    parse_structured_line, resolve_on_path, resolve_shebang_interpreter, sha256_digest,
    version_satisfies,
};
use crate::*;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// Runtime id this adapter registers under.
pub const RUNTIME_ID: &str = "claude";

/// Supported `claude` version range, checked by `health()`: the stream-json
/// control protocol this adapter speaks was measured on 2.1.
pub const CLAUDE_VERSION_REQ: &str = ">=2.1.0, <3.0.0";

/// Permission mode every session runs in: guarded tools ask the host.
const ASKING_MODE: &str = "default";

/// How long `resume` waits for Claude Code to reject an unknown conversation.
const RESUME_PROBE: Duration = Duration::from_millis(1500);

/// How long an interrupted task may take to report its own `result` before
/// the adapter ends it itself.
const INTERRUPT_GRACE: Duration = Duration::from_secs(2);

/// Longest edit preview carried on a permission request, per side, in bytes.
const EDIT_PREVIEW_LIMIT: usize = 16 * 1024;

/// Longest permission-request detail line, in bytes.
const DETAIL_LIMIT: usize = 2000;

/// Environment variables never forwarded to the binary, whatever the session
/// allowlist says: anything that would make Claude Code authenticate with a
/// credential or talk to an endpoint Bastion handed it, instead of the user's
/// own login. Every `ANTHROPIC_*` variable is withheld as well.
const WITHHELD_ENV: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
    "AWS_BEARER_TOKEN_BEDROCK",
];

/// `true` for a variable this runtime never passes to the binary.
pub fn is_withheld_env(name: &str) -> bool {
    name.starts_with("ANTHROPIC_") || WITHHELD_ENV.contains(&name)
}

/// Adapter for the installed `claude` binary.
pub struct ClaudeCodeRuntime {
    claude_bin: PathBuf,
    confinement: Option<HarnessConfinement>,
}

impl ClaudeCodeRuntime {
    /// Resolves `claude` from the host `PATH`.
    pub fn new() -> Result<Self, RuntimeError> {
        Ok(Self::with_binary(resolve_on_path("claude")?))
    }

    /// Explicit path to the `claude` binary (tests, non-standard installs).
    pub fn with_binary(claude_bin: PathBuf) -> Self {
        Self {
            claude_bin,
            confinement: None,
        }
    }

    /// Run Claude Code under OS confinement: the session workspace, the
    /// granted state directories (its own login and conversation store), the
    /// network per profile.
    pub fn with_confinement(mut self, confinement: HarnessConfinement) -> Self {
        self.confinement = Some(confinement);
        self
    }

    /// The program to spawn and its leading arguments: the binary itself, or
    /// its interpreter followed by the script for a script install.
    fn program(&self) -> Result<(PathBuf, Vec<OsString>), RuntimeError> {
        match resolve_shebang_interpreter(&self.claude_bin)? {
            Some(interpreter) => Ok((interpreter, vec![self.claude_bin.clone().into_os_string()])),
            None => Ok((self.claude_bin.clone(), Vec::new())),
        }
    }

    async fn ensure_ready(&self) -> Result<(), RuntimeError> {
        let health = self.health().await?;
        if health.ready {
            return Ok(());
        }
        let detail = health.detail.unwrap_or_default();
        Err(if detail.contains("range") {
            RuntimeError::Version(detail)
        } else {
            RuntimeError::Unavailable(detail)
        })
    }

    /// Spawns one session process and wires its reader.
    async fn spawn(&self, launch: Launch<'_>) -> Result<ClaudeSession, RuntimeError> {
        let root = launch.workspace.root.clone();
        std::fs::create_dir_all(&root).map_err(|e| {
            RuntimeError::Unavailable(format!("cannot create workspace {}: {e}", root.display()))
        })?;
        let mcp_config = launch
            .mcp_bridge
            .filter(|b| !b.servers.is_empty())
            .map(|bridge| McpConfigFile::write(&root, bridge))
            .transpose()?;
        let bridged: Vec<&str> = launch
            .mcp_bridge
            .map(|b| b.servers.iter().map(McpServerEndpoint::name).collect())
            .unwrap_or_default();

        let (program, mut args) = self.program()?;
        args.extend(
            session_args(&SessionArgs {
                conversation: launch.conversation,
                resume: launch.resume,
                mcp_config: mcp_config.as_ref().map(|f| f.path.as_path()),
                bridged: &bridged,
                permissions: launch.permissions,
                model_hint: launch.model_hint,
            })
            .into_iter()
            .map(OsString::from),
        );
        let env = session_env(launch.env);
        let mut cmd = confine::command(
            self.confinement.as_ref(),
            confine::HarnessLaunch {
                program: &program,
                args,
                env: &env,
                workspace: launch.workspace,
                profile: launch.profile,
            },
        )?;
        confine::piped(&mut cmd);
        cmd.current_dir(&root);
        let child = cmd
            .spawn()
            .map_err(|e| RuntimeError::Unavailable(format!("failed to spawn claude: {e}")))?;

        let handle = SessionHandle {
            runtime_id: RUNTIME_ID.to_string(),
            owner: launch.owner.to_string(),
            external_ref: ConversationRef {
                session: launch.conversation.to_string(),
                cwd: root.clone(),
            }
            .encode(),
        };
        let (shared, rx) = Shared::start(child, root, handle.clone(), launch.permissions)?;
        Ok(ClaudeSession {
            shared,
            handle,
            per_task_timeout: launch.timeout.per_task,
            next_task_id: 0,
            event_rx: rx,
            _mcp_config: mcp_config,
        })
    }
}

/// Everything one spawn needs.
struct Launch<'a> {
    owner: &'a str,
    conversation: &'a str,
    resume: bool,
    workspace: &'a WorkspacePolicy,
    profile: SandboxProfile,
    permissions: &'a PermissionProfile,
    env: &'a EnvPolicy,
    timeout: TimeoutPolicy,
    mcp_bridge: Option<&'a McpBridgeSpec>,
    model_hint: Option<&'a str>,
}

#[async_trait]
impl AgentRuntime for ClaudeCodeRuntime {
    fn descriptor(&self) -> RuntimeDescriptor {
        RuntimeDescriptor {
            id: RUNTIME_ID,
            adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            target_version: format!("claude {CLAUDE_VERSION_REQ}"),
            transport: Transport::JsonRpcSubprocess,
            supports: RuntimeSupports {
                resume: true,
                steer: false,
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
                sandbox: confine::coverage(self.confinement.as_ref()),
            },
        }
    }

    async fn health(&self) -> Result<RuntimeHealth, RuntimeError> {
        let (program, args) = self.program()?;
        let output = Command::new(&program)
            .args(args)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| RuntimeError::Unavailable(format!("failed to spawn claude: {e}")))?;
        if !output.status.success() {
            return Ok(RuntimeHealth {
                detected_version: "unknown".to_string(),
                ready: false,
                detail: Some("claude --version exited non-zero".to_string()),
            });
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        // Observed shape: "2.1.284 (Claude Code)".
        let version = raw
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(match version_satisfies(&version, CLAUDE_VERSION_REQ) {
            Ok(true) => RuntimeHealth {
                detected_version: version,
                ready: true,
                detail: None,
            },
            Ok(false) => RuntimeHealth {
                detail: Some(format!(
                    "claude {version} outside supported range {CLAUDE_VERSION_REQ}"
                )),
                detected_version: version,
                ready: false,
            },
            Err(e) => RuntimeHealth {
                detected_version: version,
                ready: false,
                detail: Some(e.to_string()),
            },
        })
    }

    async fn start(&self, spec: SessionSpec) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        self.ensure_ready().await?;
        let conversation = new_conversation_id();
        let session = self
            .spawn(Launch {
                owner: &spec.owner,
                conversation: &conversation,
                resume: false,
                workspace: &spec.workspace,
                profile: spec.sandbox,
                permissions: &spec.permissions,
                env: &spec.env,
                timeout: spec.timeout,
                mcp_bridge: spec.mcp_bridge.as_ref(),
                model_hint: spec.model_hint.as_deref(),
            })
            .await?;
        session.shared.emit_started().await;
        Ok(Box::new(session))
    }

    async fn resume(
        &self,
        handle: &SessionHandle,
        spec: ResumeSpec,
    ) -> Result<Box<dyn RuntimeSession>, RuntimeError> {
        if handle.runtime_id != RUNTIME_ID {
            return Err(RuntimeError::NotResumable(
                "handle belongs to a different runtime".to_string(),
            ));
        }
        if handle.owner.is_empty() {
            return Err(RuntimeError::NotResumable(
                "handle has no owner".to_string(),
            ));
        }
        let reference = ConversationRef::decode(&handle.external_ref).ok_or_else(|| {
            RuntimeError::NotResumable("handle does not name a claude conversation".to_string())
        })?;
        self.ensure_ready().await?;

        // A confined session of this owner only ever ran in the owner's
        // workspace; Claude Code finds the conversation by that directory.
        let root = match &self.confinement {
            Some(confinement) => confinement.owner_workspace(&handle.owner),
            None => reference.cwd.clone(),
        };
        let workspace = WorkspacePolicy {
            root,
            read_only: false,
            deny: Vec::new(),
        };
        let session = self
            .spawn(Launch {
                owner: &handle.owner,
                conversation: &reference.session,
                resume: true,
                workspace: &workspace,
                profile: SandboxProfile::WorkspaceNet,
                permissions: &spec.permissions,
                env: &spec.env,
                timeout: spec.timeout,
                mcp_bridge: spec.mcp_bridge.as_ref(),
                model_hint: None,
            })
            .await?;

        let deadline = Instant::now() + RESUME_PROBE;
        while Instant::now() < deadline {
            if session.shared.state.lock().await.early_exit {
                session.shared.kill().await;
                return Err(RuntimeError::NotResumable(format!(
                    "claude has no conversation {} in {}",
                    reference.session,
                    workspace.root.display()
                )));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        session.shared.emit_started().await;
        Ok(Box::new(session))
    }
}

#[async_trait]
impl FaultInjection for ClaudeCodeRuntime {
    // Every hook keeps its default `false`: inducing faults in a live,
    // logged-in Claude Code is out of scope; the fake-binary tests cover the
    // crash and garbage-frame paths directly.
}

// ---------------------------------------------------------------------
// Command line and environment
// ---------------------------------------------------------------------

struct SessionArgs<'a> {
    conversation: &'a str,
    resume: bool,
    mcp_config: Option<&'a Path>,
    bridged: &'a [&'a str],
    permissions: &'a PermissionProfile,
    model_hint: Option<&'a str>,
}

/// The flags of one session process. Never `--bare` (it drops the login for
/// an API key) and never a flag that skips permissions unless the host's
/// profile explicitly allows everything.
fn session_args(args: &SessionArgs<'_>) -> Vec<String> {
    let mut out: Vec<String> = [
        "-p",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--verbose",
        "--permission-prompt-tool",
        "stdio",
        "--setting-sources",
        "",
        "--strict-mcp-config",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    out.push("--permission-mode".to_string());
    out.push(permission_mode(args.permissions).to_string());

    if let Some(path) = args.mcp_config {
        out.push("--mcp-config".to_string());
        out.push(path.to_string_lossy().into_owned());
    }

    let allowed = allowed_tools(args.permissions, args.bridged);
    if !allowed.is_empty() {
        out.push("--allowedTools".to_string());
        out.push(allowed.join(","));
    }

    if args.resume {
        out.push("--resume".to_string());
    } else {
        out.push("--session-id".to_string());
    }
    out.push(args.conversation.to_string());

    if let Some(model) = args.model_hint.filter(|m| !m.trim().is_empty()) {
        out.push("--model".to_string());
        out.push(model.to_string());
    }
    out
}

/// `default` (ask) unless the host's profile allows everything.
fn permission_mode(permissions: &PermissionProfile) -> &'static str {
    if permissions.allow.iter().any(|a| a == "*") {
        "bypassPermissions"
    } else {
        ASKING_MODE
    }
}

/// Tools that run without asking: the host profile's explicit entries plus
/// every MCP server Bastion bridged in (already governed server-side).
fn allowed_tools(permissions: &PermissionProfile, bridged: &[&str]) -> Vec<String> {
    let mut allowed: Vec<String> = permissions
        .allow
        .iter()
        .filter(|a| a.as_str() != "*" && !a.trim().is_empty())
        .cloned()
        .collect();
    for name in bridged {
        let rule = format!("mcp__{name}");
        if !allowed.contains(&rule) {
            allowed.push(rule);
        }
    }
    allowed
}

/// The session allowlist minus [`is_withheld_env`], with Claude Code's auto
/// memory switched off.
fn session_env(env: &EnvPolicy) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = env
        .allow
        .iter()
        .filter(|(name, _)| !is_withheld_env(name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    out.insert(
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY".to_string(),
        "1".to_string(),
    );
    out
}

/// A random RFC 4122 version-4 id; Claude Code requires a UUID for
/// `--session-id`. Not a secret, only unique.
fn new_conversation_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut words = [0u64; 2];
    for (i, word) in words.iter_mut().enumerate() {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(nanos);
        hasher.write_u64(count);
        hasher.write_u32(std::process::id());
        hasher.write_usize(i);
        *word = hasher.finish();
    }
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&words[0].to_be_bytes());
    bytes[8..].copy_from_slice(&words[1].to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// What [`SessionHandle::external_ref`] holds: the conversation id and the
/// directory Claude Code stored it under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConversationRef {
    session: String,
    cwd: PathBuf,
}

impl ConversationRef {
    fn encode(&self) -> String {
        json!({"session": self.session, "cwd": self.cwd}).to_string()
    }

    fn decode(raw: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(raw).ok()?;
        let session = value.get("session")?.as_str()?.to_string();
        let cwd = PathBuf::from(value.get("cwd")?.as_str()?);
        let valid =
            session.len() == 36 && session.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        (valid && cwd.is_absolute()).then_some(Self { session, cwd })
    }
}

/// The `--mcp-config` file of one session. The bridge headers carry the
/// owner's token, so it goes in a file readable only by the daemon's user
/// (never on the command line, which other local users can list) inside the
/// session workspace, where a confined harness can read it. Removed with the
/// session.
struct McpConfigFile {
    path: PathBuf,
}

impl McpConfigFile {
    fn write(root: &Path, bridge: &McpBridgeSpec) -> Result<Self, RuntimeError> {
        let dir = root.join(".tmp");
        std::fs::create_dir_all(&dir).map_err(|e| {
            RuntimeError::Unavailable(format!("cannot create {}: {e}", dir.display()))
        })?;
        let path = dir.join(format!("bastion-mcp-{}.json", new_conversation_id()));
        let body = mcp_config_json(bridge).to_string();
        write_private(&path, body.as_bytes())
            .map_err(|e| RuntimeError::Unavailable(format!("cannot write the MCP config: {e}")))?;
        Ok(Self { path })
    }
}

impl Drop for McpConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Claude Code's `--mcp-config` document for the bridged servers.
fn mcp_config_json(bridge: &McpBridgeSpec) -> Value {
    let mut servers = serde_json::Map::new();
    for server in &bridge.servers {
        let entry = match server {
            McpServerEndpoint::Http { url, headers, .. } => {
                json!({"type": "http", "url": url, "headers": headers})
            }
            McpServerEndpoint::Stdio {
                command, args, env, ..
            } => json!({"type": "stdio", "command": command, "args": args, "env": env}),
        };
        servers.insert(server.name().to_string(), entry);
    }
    json!({ "mcpServers": servers })
}

// ---------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------

struct PendingPermission {
    request_id: String,
    input: Value,
}

struct State {
    status: SessionStatus,
    current: Option<TaskId>,
    /// Outcome forced by a cancel, a timeout or a turn-scoped denial; wins
    /// over what the `result` frame says.
    ending: Option<TaskOutcome>,
    /// `result` frames still owed by tasks the adapter already ended itself;
    /// their frames are dropped so they never reach a later task.
    skip_results: u32,
    pending: HashMap<u64, PendingPermission>,
    next_permission: u64,
    /// Watchdog clock: time the task ran before the current stretch, and when
    /// the current stretch began (`None` while a decision is pending).
    active_before: Duration,
    active_since: Option<Instant>,
    /// A `result` or EOF arrived before any task: the process refused to
    /// start (an unknown `--resume` conversation).
    early_exit: bool,
    /// The session was killed on purpose; the reader's EOF is expected.
    closing: bool,
    interpreter: Interpreter,
}

struct Shared {
    stdin: AsyncMutex<Option<ChildStdin>>,
    child: AsyncMutex<Child>,
    state: AsyncMutex<State>,
    tx: mpsc::UnboundedSender<RuntimeEvent>,
    handle: SessionHandle,
    next_control: AtomicU64,
    /// The mode the session asked for, checked against `system/init`.
    expected_mode: &'static str,
}

impl Shared {
    fn start(
        mut child: Child,
        root: PathBuf,
        handle: SessionHandle,
        permissions: &PermissionProfile,
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<RuntimeEvent>), RuntimeError> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("claude has no stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("claude has no stdout".to_string()))?;
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::trace!(target: "bastion_agent_runtime::claude_code", len = line.len(), "claude stderr");
                }
            });
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Self {
            stdin: AsyncMutex::new(Some(stdin)),
            child: AsyncMutex::new(child),
            state: AsyncMutex::new(State {
                status: SessionStatus::Idle,
                current: None,
                ending: None,
                skip_results: 0,
                pending: HashMap::new(),
                next_permission: 0,
                active_before: Duration::ZERO,
                active_since: None,
                early_exit: false,
                closing: false,
                interpreter: Interpreter::new(root),
            }),
            tx,
            handle,
            next_control: AtomicU64::new(0),
            expected_mode: permission_mode(permissions),
        });
        let reader = Arc::clone(&shared);
        tokio::spawn(async move { reader.read(stdout).await });
        Ok((shared, rx))
    }

    async fn emit_started(&self) {
        let _ = self.tx.send(RuntimeEvent::Started {
            handle: self.handle.clone(),
        });
    }

    async fn write(&self, frame: &Value) -> Result<(), RuntimeError> {
        let mut line = frame.to_string();
        line.push('\n');
        let mut stdin = self.stdin.lock().await;
        let Some(pipe) = stdin.as_mut() else {
            return Err(RuntimeError::Crashed("claude stdin is closed".to_string()));
        };
        pipe.write_all(line.as_bytes())
            .await
            .map_err(|e| RuntimeError::Crashed(format!("cannot write to claude: {e}")))?;
        pipe.flush()
            .await
            .map_err(|e| RuntimeError::Crashed(format!("cannot write to claude: {e}")))
    }

    async fn interrupt(&self) -> Result<(), RuntimeError> {
        let n = self.next_control.fetch_add(1, Ordering::Relaxed);
        self.write(&json!({
            "type": "control_request",
            "request_id": format!("bastion-{n}"),
            "request": {"subtype": "interrupt"}
        }))
        .await
    }

    async fn kill(&self) {
        self.state.lock().await.closing = true;
        *self.stdin.lock().await = None;
        let _ = self.child.lock().await.start_kill();
    }

    /// Ends `task` with `outcome`: asks Claude Code to interrupt it, waits
    /// `grace` for its own `result`, and ends it here when none comes.
    async fn stop_task(&self, task: TaskId, outcome: TaskOutcome, grace: Duration) {
        let pending: Vec<PendingPermission> = {
            let mut state = self.state.lock().await;
            if state.current != Some(task) {
                return;
            }
            state.ending = Some(outcome.clone());
            state.pending.drain().map(|(_, p)| p).collect()
        };
        for p in pending {
            let _ = self
                .write(&permission_response(&p.request_id, &p.input, false, true))
                .await;
        }
        let _ = self.interrupt().await;
        let deadline = Instant::now() + grace;
        loop {
            if self.state.lock().await.current != Some(task) {
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut state = self.state.lock().await;
        if state.current == Some(task) {
            state.skip_results += 1;
            finish_task(&mut state, &self.tx, task, outcome);
        }
    }

    async fn read(self: Arc<Self>, stdout: ChildStdout) {
        let mut lines = BufReader::new(stdout).lines();
        let failure = loop {
            match lines.next_line().await {
                Ok(Some(raw)) => match parse_structured_line(&raw) {
                    Ok(frame) => self.dispatch(frame).await,
                    Err(e) => break Some(e.to_string()),
                },
                Ok(None) => break None,
                Err(e) => break Some(format!("cannot read claude output: {e}")),
            }
        };
        if let Some(detail) = &failure {
            tracing::warn!(target: "bastion_agent_runtime::claude_code", error = %detail, "rejecting claude transport");
        }
        let _ = self.child.lock().await.start_kill();
        *self.stdin.lock().await = None;
        let mut state = self.state.lock().await;
        state.pending.clear();
        state.early_exit = true;
        if state.closing {
            return;
        }
        if let Some(task) = state.current {
            let reason = failure.unwrap_or_else(|| "claude exited during the task".to_string());
            finish_task(&mut state, &self.tx, task, TaskOutcome::Failed { reason });
        }
        state.status = SessionStatus::Crashed;
    }

    async fn dispatch(&self, frame: Value) {
        let mut state = self.state.lock().await;
        let Some(task) = state.current.filter(|_| state.skip_results == 0) else {
            drop(state);
            return self.dispatch_idle(frame).await;
        };
        let steps = state.interpreter.interpret(task, &frame);
        let mut replies: Vec<Value> = Vec::new();
        for step in steps {
            match step {
                Step::Event(event) => {
                    let _ = self.tx.send(event);
                }
                Step::Init { mode, credential } => {
                    for detail in init_warnings(self.expected_mode, &mode, &credential) {
                        let _ = self.tx.send(RuntimeEvent::Warning {
                            task,
                            code: WarnCode::DegradedTransport,
                            detail,
                        });
                    }
                }
                Step::Artifact(target) => {
                    if let Some(artifact) =
                        artifact_for(&state.interpreter.root, &target, &self.handle)
                    {
                        let _ = self.tx.send(RuntimeEvent::Artifact { task, artifact });
                    }
                }
                Step::Permission {
                    request_id,
                    tool,
                    input,
                    description,
                } => {
                    let id = state.next_permission;
                    state.next_permission += 1;
                    let edits = proposed_edits(&tool, &input, &state.interpreter.root);
                    let detail = permission_detail(&tool, &input, description.as_deref());
                    if let Some(since) = state.active_since.take() {
                        state.active_before += since.elapsed();
                    }
                    state
                        .pending
                        .insert(id, PendingPermission { request_id, input });
                    let _ = self.tx.send(RuntimeEvent::PermissionRequest {
                        task,
                        id: PermissionRequestId(id),
                        action: permission_action(&tool),
                        detail,
                        edits,
                    });
                }
                Step::Reject {
                    request_id,
                    subtype,
                } => {
                    replies.push(control_error(&request_id, &subtype));
                }
                Step::Finished {
                    usage,
                    success,
                    reason,
                } => {
                    let _ = self.tx.send(RuntimeEvent::Usage { task, delta: usage });
                    let outcome = if success {
                        TaskOutcome::Success
                    } else {
                        TaskOutcome::Failed { reason }
                    };
                    finish_task(&mut state, &self.tx, task, outcome);
                }
            }
        }
        drop(state);
        for reply in replies {
            let _ = self.write(&reply).await;
        }
    }

    /// A frame with no task to belong to: the tail of a task the adapter
    /// already ended, or the process refusing to start.
    async fn dispatch_idle(&self, frame: Value) {
        let kind = frame
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reply = {
            let mut state = self.state.lock().await;
            match kind {
                "result" if state.skip_results > 0 => {
                    state.skip_results -= 1;
                    None
                }
                "result" if state.current.is_none() => {
                    state.early_exit = true;
                    None
                }
                // Nobody can decide for a task that is gone: deny.
                "control_request" => {
                    let request_id = frame
                        .get("request_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let request = frame.get("request").cloned().unwrap_or(Value::Null);
                    match request.get("subtype").and_then(Value::as_str) {
                        Some("can_use_tool") => Some(permission_response(
                            &request_id,
                            request.get("input").unwrap_or(&Value::Null),
                            false,
                            true,
                        )),
                        other => Some(control_error(&request_id, other.unwrap_or("unknown"))),
                    }
                }
                _ => None,
            }
        };
        if let Some(reply) = reply {
            let _ = self.write(&reply).await;
        }
    }
}

/// Emits `Ended` and resets the per-task state. Called with the state lock
/// held, so nothing of this task can be emitted after it.
fn finish_task(
    state: &mut State,
    tx: &mpsc::UnboundedSender<RuntimeEvent>,
    task: TaskId,
    outcome: TaskOutcome,
) {
    let outcome = state.ending.take().unwrap_or(outcome);
    state.current = None;
    state.pending.clear();
    state.active_since = None;
    state.active_before = Duration::ZERO;
    if state.status == SessionStatus::Running {
        state.status = SessionStatus::Idle;
    }
    let _ = tx.send(RuntimeEvent::Ended { task, outcome });
}

fn spawn_watchdog(shared: Arc<Shared>, task: TaskId, per_task: Duration) {
    tokio::spawn(async move {
        loop {
            let wait = {
                let state = shared.state.lock().await;
                if state.current != Some(task) {
                    return;
                }
                match state.active_since {
                    // Paused on a permission decision: a person is reading a
                    // diff, which is not the harness running long.
                    None => Duration::from_millis(100),
                    Some(since) => per_task.saturating_sub(state.active_before + since.elapsed()),
                }
            };
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
                continue;
            }
            let paused = shared.state.lock().await.active_since.is_none();
            if paused {
                continue;
            }
            shared
                .stop_task(task, TaskOutcome::TimedOut, INTERRUPT_GRACE)
                .await;
            return;
        }
    });
}

struct ClaudeSession {
    shared: Arc<Shared>,
    handle: SessionHandle,
    per_task_timeout: Duration,
    next_task_id: u64,
    event_rx: mpsc::UnboundedReceiver<RuntimeEvent>,
    _mcp_config: Option<McpConfigFile>,
}

impl Drop for ClaudeSession {
    fn drop(&mut self) {
        if let Ok(mut child) = self.shared.child.try_lock() {
            let _ = child.start_kill();
        }
    }
}

#[async_trait]
impl RuntimeSession for ClaudeSession {
    fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }

    async fn submit(&mut self, input: TaskInput) -> Result<TaskId, RuntimeError> {
        let task = {
            let mut state = self.shared.state.lock().await;
            if state.closing {
                return Err(RuntimeError::Unavailable(
                    "the claude session was killed".to_string(),
                ));
            }
            if state.status == SessionStatus::Crashed {
                return Err(RuntimeError::Crashed("session already crashed".to_string()));
            }
            if state.current.is_some() {
                return Err(RuntimeError::Unavailable(
                    "a task is already active on this session (concurrent_sessions=false)"
                        .to_string(),
                ));
            }
            let task = TaskId(self.next_task_id);
            self.next_task_id += 1;
            state.current = Some(task);
            state.ending = None;
            state.active_before = Duration::ZERO;
            state.active_since = Some(Instant::now());
            state.status = SessionStatus::Running;
            if input.model_hint.is_some() {
                let _ = self.shared.tx.send(RuntimeEvent::Warning {
                    task,
                    code: WarnCode::DegradedTransport,
                    detail: "claude takes the model per session (SessionSpec::model_hint); the \
                             per-task model_hint was not applied"
                        .to_string(),
                });
            }
            task
        };
        let frame = json!({
            "type": "user",
            "message": {"role": "user", "content": input.prompt},
        });
        if let Err(e) = self.shared.write(&frame).await {
            let mut state = self.shared.state.lock().await;
            if state.current == Some(task) {
                state.current = None;
                state.active_since = None;
                state.status = SessionStatus::Crashed;
            }
            return Err(e);
        }
        spawn_watchdog(Arc::clone(&self.shared), task, self.per_task_timeout);
        Ok(task)
    }

    async fn next_event(&mut self) -> Option<RuntimeEvent> {
        self.event_rx.recv().await
    }

    async fn steer(&mut self, _text: &str) -> Result<(), RuntimeError> {
        Err(RuntimeError::Protocol(
            "claude stream-json has no mid-turn steer: a second message queues a new turn"
                .to_string(),
        ))
    }

    async fn cancel(&mut self, mode: CancelMode) -> Result<(), RuntimeError> {
        let current = {
            let mut state = self.shared.state.lock().await;
            if state.status != SessionStatus::Crashed {
                state.status = SessionStatus::Cancelled;
            }
            state.current
        };
        let Some(task) = current else {
            return Ok(());
        };
        match mode {
            CancelMode::Graceful { grace } => {
                self.shared
                    .stop_task(task, TaskOutcome::Cancelled, grace)
                    .await;
            }
            CancelMode::Kill => {
                {
                    let mut state = self.shared.state.lock().await;
                    state.closing = true;
                    if state.current == Some(task) {
                        finish_task(&mut state, &self.shared.tx, task, TaskOutcome::Cancelled);
                    }
                }
                self.shared.kill().await;
            }
        }
        Ok(())
    }

    async fn respond_permission(
        &mut self,
        id: PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), RuntimeError> {
        let (pending, turn) = {
            let mut state = self.shared.state.lock().await;
            let Some(pending) = state.pending.remove(&id.0) else {
                return Err(RuntimeError::Protocol(
                    "no matching pending permission request".to_string(),
                ));
            };
            let turn = matches!(
                decision,
                PermissionDecision::Deny {
                    scope: DenyScope::Turn
                }
            );
            if turn {
                state.ending = Some(TaskOutcome::Cancelled);
            }
            if state.pending.is_empty() && state.current.is_some() {
                state.active_since = Some(Instant::now());
            }
            (pending, turn)
        };
        let allow = decision == PermissionDecision::Allow;
        self.shared
            .write(&permission_response(
                &pending.request_id,
                &pending.input,
                allow,
                turn,
            ))
            .await
    }

    async fn status(&self) -> Result<SessionStatus, RuntimeError> {
        Ok(self.shared.state.lock().await.status)
    }
}

// ---------------------------------------------------------------------
// Control frames
// ---------------------------------------------------------------------

fn permission_response(request_id: &str, input: &Value, allow: bool, interrupt: bool) -> Value {
    let decision = if allow {
        json!({"behavior": "allow", "updatedInput": input})
    } else {
        json!({
            "behavior": "deny",
            "message": "Denied by the owner through Bastion's approval.",
            "interrupt": interrupt
        })
    };
    json!({
        "type": "control_response",
        "response": {"subtype": "success", "request_id": request_id, "response": decision}
    })
}

fn control_error(request_id: &str, subtype: &str) -> Value {
    json!({
        "type": "control_response",
        "response": {
            "subtype": "error",
            "request_id": request_id,
            "error": format!("unsupported control request: {subtype}")
        }
    })
}

/// Warnings for a `system/init` frame that contradicts the session's setup.
fn init_warnings(expected_mode: &str, mode: &str, credential: &str) -> Vec<String> {
    let mut out = Vec::new();
    let asking = |m: &str| m == "default" || m == "manual";
    let mode_ok = if expected_mode == ASKING_MODE {
        asking(mode)
    } else {
        mode == expected_mode
    };
    if !mode.is_empty() && !mode_ok {
        out.push(format!(
            "claude reports permission mode '{mode}' instead of '{expected_mode}'; its actions \
             may not all reach Bastion's approval"
        ));
    }
    if !credential.is_empty() && credential != "none" {
        out.push(format!(
            "claude authenticated with '{credential}' instead of the user's own login"
        ));
    }
    out
}

// ---------------------------------------------------------------------
// Frame interpreter — pure mapping of stdout frames to steps
// ---------------------------------------------------------------------

#[derive(Debug)]
enum Step {
    Event(RuntimeEvent),
    Init {
        mode: String,
        credential: String,
    },
    /// A successful write to this path: emit it as an artifact when it is
    /// inside the workspace.
    Artifact(PathBuf),
    Permission {
        request_id: String,
        tool: String,
        input: Value,
        description: Option<String>,
    },
    Reject {
        request_id: String,
        subtype: String,
    },
    Finished {
        usage: UsageDelta,
        success: bool,
        reason: String,
    },
}

struct ToolUse {
    name: String,
    diffs: Vec<(PathBuf, u32, u32)>,
    target: Option<PathBuf>,
}

struct Interpreter {
    root: PathBuf,
    tools: HashMap<String, ToolUse>,
}

impl Interpreter {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            tools: HashMap::new(),
        }
    }

    fn interpret(&mut self, task: TaskId, frame: &Value) -> Vec<Step> {
        let mut out = Vec::new();
        match frame.get("type").and_then(Value::as_str) {
            Some("system") if frame.get("subtype").and_then(Value::as_str) == Some("init") => {
                out.push(Step::Init {
                    mode: str_field(frame, "permissionMode"),
                    credential: str_field(frame, "apiKeySource"),
                });
            }
            Some("assistant") => {
                for block in content_blocks(frame) {
                    self.assistant_block(task, block, &mut out);
                }
            }
            Some("user") => {
                for block in content_blocks(frame) {
                    self.tool_result(task, block, &mut out);
                }
            }
            Some("control_request") => {
                let request_id = str_field(frame, "request_id");
                let request = frame.get("request").cloned().unwrap_or(Value::Null);
                let subtype = str_field(&request, "subtype");
                if subtype == "can_use_tool" {
                    out.push(Step::Permission {
                        request_id,
                        tool: str_field(&request, "tool_name"),
                        input: request.get("input").cloned().unwrap_or(Value::Null),
                        description: request
                            .get("description")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                } else {
                    out.push(Step::Reject {
                        request_id,
                        subtype,
                    });
                }
            }
            Some("result") => {
                let usage = frame.get("usage").cloned().unwrap_or(Value::Null);
                let count = |key: &str| usage.get(key).and_then(Value::as_u64).unwrap_or(0);
                let subtype = str_field(frame, "subtype");
                let is_error = frame
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let reason = frame
                    .get("errors")
                    .and_then(Value::as_array)
                    .and_then(|e| e.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| subtype.clone());
                self.tools.clear();
                out.push(Step::Finished {
                    usage: UsageDelta {
                        input_tokens: count("input_tokens")
                            + count("cache_read_input_tokens")
                            + count("cache_creation_input_tokens"),
                        output_tokens: count("output_tokens"),
                    },
                    success: subtype == "success" && !is_error,
                    reason,
                });
            }
            _ => {}
        }
        out
    }

    fn assistant_block(&mut self, task: TaskId, block: &Value, out: &mut Vec<Step>) {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                let text = str_field(block, "text");
                if !text.is_empty() {
                    out.push(Step::Event(RuntimeEvent::MessageDelta { task, text }));
                }
            }
            Some("thinking") => {
                let summary = str_field(block, "thinking");
                if !summary.trim().is_empty() {
                    out.push(Step::Event(RuntimeEvent::Thinking { task, summary }));
                }
            }
            Some("tool_use") => {
                let id = str_field(block, "id");
                let name = str_field(block, "name");
                let input = block.get("input").cloned().unwrap_or(Value::Null);
                self.tools.insert(
                    id,
                    ToolUse {
                        name: name.clone(),
                        diffs: edit_counts(&name, &input, &self.root),
                        target: edit_target(&name, &input, &self.root),
                    },
                );
                out.push(Step::Event(RuntimeEvent::ToolCall {
                    task,
                    name,
                    input_digest: sha256_digest(input.to_string().as_bytes()),
                }));
            }
            _ => {}
        }
    }

    fn tool_result(&mut self, task: TaskId, block: &Value, out: &mut Vec<Step>) {
        if block.get("type").and_then(Value::as_str) != Some("tool_result") {
            return;
        }
        let tool = self.tools.remove(&str_field(block, "tool_use_id"));
        let is_error = block
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let content = block.get("content").cloned().unwrap_or(Value::Null);
        out.push(Step::Event(RuntimeEvent::ToolResult {
            task,
            name: tool.as_ref().map(|t| t.name.clone()).unwrap_or_default(),
            output_digest: sha256_digest(content.to_string().as_bytes()),
            is_error,
        }));
        if is_error {
            return;
        }
        if let Some(tool) = tool {
            for (path, added, removed) in tool.diffs {
                out.push(Step::Event(RuntimeEvent::Diff {
                    task,
                    path,
                    added,
                    removed,
                }));
            }
            if let Some(target) = tool.target {
                out.push(Step::Artifact(target));
            }
        }
    }
}

fn str_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn content_blocks(frame: &Value) -> impl Iterator<Item = &Value> {
    frame
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

// ---------------------------------------------------------------------
// Tools: action class, detail, proposed edits
// ---------------------------------------------------------------------

const EDIT_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

fn permission_action(tool: &str) -> PermissionAction {
    match tool {
        t if EDIT_TOOLS.contains(&t) => PermissionAction::WriteFile,
        "Bash" | "BashOutput" | "KillShell" | "KillBash" | "PowerShell" => {
            PermissionAction::RunCommand
        }
        "WebFetch" | "WebSearch" => PermissionAction::Network,
        _ => PermissionAction::UseTool,
    }
}

/// One line the approver reads: the tool and what it acts on.
fn permission_detail(tool: &str, input: &Value, description: Option<&str>) -> String {
    let field = |key: &str| input.get(key).and_then(Value::as_str);
    let subject = match tool {
        "Bash" | "PowerShell" => field("command").map(str::to_string),
        t if EDIT_TOOLS.contains(&t) => field("file_path")
            .or_else(|| field("notebook_path"))
            .map(str::to_string),
        "WebFetch" => field("url").map(str::to_string),
        "WebSearch" => field("query").map(str::to_string),
        _ => None,
    }
    .or_else(|| {
        description
            .filter(|d| !d.trim().is_empty())
            .map(str::to_string)
    })
    .unwrap_or_else(|| input.to_string());
    truncate(&format!("{tool}: {subject}"), DETAIL_LIMIT).0
}

/// `(text, truncated)`: `text` cut at a char boundary to at most `limit`
/// bytes.
fn truncate(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_string(), false);
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

/// Where an edit tool writes, as the path given (absolute, or relative to the
/// workspace root).
fn edit_path(tool: &str, input: &Value, root: &Path) -> Option<PathBuf> {
    if !EDIT_TOOLS.contains(&tool) {
        return None;
    }
    let raw = input
        .get("file_path")
        .or_else(|| input.get("notebook_path"))
        .and_then(Value::as_str)?;
    let path = PathBuf::from(raw);
    Some(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

/// Workspace-relative when the path is inside the root, absolute otherwise:
/// an edit aimed outside must stay visibly outside.
fn display_path(path: &Path, root: &Path) -> PathBuf {
    let normalized = normalize(path);
    match normalized.strip_prefix(normalize(root)) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_path_buf(),
        _ => normalized,
    }
}

/// Lexical `.`/`..` resolution, so `root/../x` is not mistaken for a path
/// inside the root.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `(old, new)` text pairs an edit tool proposes.
fn edit_pairs(tool: &str, input: &Value) -> Vec<(Option<String>, String)> {
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_string);
    match tool {
        "Write" => vec![(None, text(input, "content").unwrap_or_default())],
        "Edit" => vec![(
            text(input, "old_string"),
            text(input, "new_string").unwrap_or_default(),
        )],
        "MultiEdit" => input
            .get("edits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|e| {
                (
                    text(e, "old_string"),
                    text(e, "new_string").unwrap_or_default(),
                )
            })
            .collect(),
        "NotebookEdit" => vec![(None, text(input, "new_source").unwrap_or_default())],
        _ => Vec::new(),
    }
}

/// The edits a permission request would perform, bounded for display.
fn proposed_edits(tool: &str, input: &Value, root: &Path) -> Vec<ProposedEdit> {
    let Some(path) = edit_path(tool, input, root) else {
        return Vec::new();
    };
    let shown = display_path(&path, root);
    edit_pairs(tool, input)
        .into_iter()
        .map(|(old, new)| {
            let (old_text, old_cut) = match old {
                Some(old) => {
                    let (t, cut) = truncate(&old, EDIT_PREVIEW_LIMIT);
                    (Some(t), cut)
                }
                None => (None, false),
            };
            let (new_text, new_cut) = truncate(&new, EDIT_PREVIEW_LIMIT);
            ProposedEdit {
                path: shown.clone(),
                old_text,
                new_text,
                truncated: old_cut || new_cut,
            }
        })
        .collect()
}

/// Line counts of an edit tool's change, from the full (untruncated) input.
fn edit_counts(tool: &str, input: &Value, root: &Path) -> Vec<(PathBuf, u32, u32)> {
    let Some(path) = edit_path(tool, input, root) else {
        return Vec::new();
    };
    let shown = display_path(&path, root);
    edit_pairs(tool, input)
        .into_iter()
        .map(|(old, new)| {
            (
                shown.clone(),
                line_count(&new),
                old.as_deref().map(line_count).unwrap_or(0),
            )
        })
        .collect()
}

fn line_count(text: &str) -> u32 {
    u32::try_from(text.lines().count()).unwrap_or(u32::MAX)
}

fn edit_target(tool: &str, input: &Value, root: &Path) -> Option<PathBuf> {
    edit_path(tool, input, root).map(|p| normalize(&p))
}

/// The written file as an artifact, when it resolves inside the workspace.
fn artifact_for(root: &Path, target: &Path, handle: &SessionHandle) -> Option<Artifact> {
    let root = std::fs::canonicalize(root).ok()?;
    let file = std::fs::canonicalize(target).ok()?;
    let rel = file.strip_prefix(&root).ok()?.to_path_buf();
    let bytes = std::fs::read(&file).ok()?;
    Some(Artifact {
        kind: ArtifactKind::File,
        path: rel,
        digest: sha256_digest(&bytes),
        produced_by: Some(handle.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\w\alice")
        } else {
            PathBuf::from("/w/alice")
        }
    }

    fn abs(rel: &str) -> String {
        root().join(rel).to_string_lossy().into_owned()
    }

    #[test]
    fn withheld_env_covers_every_anthropic_credential_and_endpoint() {
        for name in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_CUSTOM_HEADERS",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
        ] {
            assert!(is_withheld_env(name), "{name} must be withheld");
        }
        for name in ["HOME", "PATH", "TMPDIR", "LANG"] {
            assert!(!is_withheld_env(name), "{name} must pass");
        }
    }

    #[test]
    fn session_env_drops_credentials_and_disables_auto_memory() {
        let env = EnvPolicy {
            allow: BTreeMap::from([
                ("HOME".to_string(), "/home/u".to_string()),
                ("ANTHROPIC_API_KEY".to_string(), "sk-secret".to_string()),
                ("CLAUDE_CODE_OAUTH_TOKEN".to_string(), "tok".to_string()),
            ]),
        };
        let out = session_env(&env);
        assert_eq!(out.get("HOME").map(String::as_str), Some("/home/u"));
        assert!(!out.contains_key("ANTHROPIC_API_KEY"));
        assert!(!out.contains_key("CLAUDE_CODE_OAUTH_TOKEN"));
        assert_eq!(
            out.get("CLAUDE_CODE_DISABLE_AUTO_MEMORY")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn session_args_ask_the_host_and_load_no_operator_settings() {
        let permissions = PermissionProfile::default();
        let args = session_args(&SessionArgs {
            conversation: "11111111-2222-4333-8444-555555555555",
            resume: false,
            mcp_config: Some(Path::new("/w/alice/.tmp/m.json")),
            bridged: &["bastion"],
            permissions: &permissions,
            model_hint: None,
        });
        let joined = args.join(" ");
        assert!(joined.contains("--permission-prompt-tool stdio"));
        assert!(joined.contains("--permission-mode default"));
        assert!(joined.contains("--strict-mcp-config"));
        assert!(joined.contains("--mcp-config /w/alice/.tmp/m.json"));
        assert!(joined.contains("--allowedTools mcp__bastion"));
        assert!(joined.contains("--session-id 11111111-2222-4333-8444-555555555555"));
        let pos = args.iter().position(|a| a == "--setting-sources").unwrap();
        assert_eq!(args[pos + 1], "");
        for forbidden in ["--bare", "--dangerously-skip-permissions", "--resume"] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn session_args_resume_and_model() {
        let permissions = PermissionProfile {
            allow: vec!["Read".to_string(), "*".to_string()],
        };
        let args = session_args(&SessionArgs {
            conversation: "11111111-2222-4333-8444-555555555555",
            resume: true,
            mcp_config: None,
            bridged: &[],
            permissions: &permissions,
            model_hint: Some("sonnet"),
        });
        let joined = args.join(" ");
        assert!(joined.contains("--resume 11111111-2222-4333-8444-555555555555"));
        assert!(!joined.contains("--session-id"));
        assert!(joined.contains("--model sonnet"));
        assert!(joined.contains("--allowedTools Read"));
        assert!(joined.contains("--permission-mode bypassPermissions"));
        assert!(!joined.contains("--mcp-config"));
    }

    #[test]
    fn conversation_ids_are_v4_uuids_and_unique() {
        let a = new_conversation_id();
        let b = new_conversation_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn conversation_ref_round_trips_and_rejects_garbage() {
        let reference = ConversationRef {
            session: new_conversation_id(),
            cwd: root(),
        };
        assert_eq!(
            ConversationRef::decode(&reference.encode()),
            Some(reference)
        );
        assert_eq!(ConversationRef::decode("thread-1"), None);
        assert_eq!(
            ConversationRef::decode(r#"{"session":"../../etc","cwd":"/w"}"#),
            None
        );
        assert_eq!(
            ConversationRef::decode(
                r#"{"session":"11111111-2222-4333-8444-555555555555","cwd":"relative"}"#
            ),
            None
        );
    }

    #[test]
    fn mcp_config_names_each_bridged_server() {
        let bridge = McpBridgeSpec {
            servers: vec![
                McpServerEndpoint::Http {
                    name: "bastion".to_string(),
                    url: "http://127.0.0.1:9/mcp".to_string(),
                    headers: BTreeMap::from([("x-bastion-token".to_string(), "t".to_string())]),
                },
                McpServerEndpoint::Stdio {
                    name: "local".to_string(),
                    command: PathBuf::from("/bin/tool"),
                    args: vec!["serve".to_string()],
                    env: BTreeMap::new(),
                },
            ],
        };
        let config = mcp_config_json(&bridge);
        assert_eq!(config["mcpServers"]["bastion"]["type"], "http");
        assert_eq!(
            config["mcpServers"]["bastion"]["headers"]["x-bastion-token"],
            "t"
        );
        assert_eq!(config["mcpServers"]["local"]["type"], "stdio");
        assert_eq!(config["mcpServers"]["local"]["args"][0], "serve");
    }

    #[test]
    fn actions_are_classified_by_tool() {
        assert!(matches!(
            permission_action("Edit"),
            PermissionAction::WriteFile
        ));
        assert!(matches!(
            permission_action("Write"),
            PermissionAction::WriteFile
        ));
        assert!(matches!(
            permission_action("Bash"),
            PermissionAction::RunCommand
        ));
        assert!(matches!(
            permission_action("WebFetch"),
            PermissionAction::Network
        ));
        assert!(matches!(
            permission_action("mcp__bastion__memory_search"),
            PermissionAction::UseTool
        ));
    }

    #[test]
    fn detail_names_the_command_or_the_file() {
        assert_eq!(
            permission_detail("Bash", &json!({"command": "rm -rf build"}), None),
            "Bash: rm -rf build"
        );
        assert_eq!(
            permission_detail("Write", &json!({"file_path": "/w/a.txt"}), Some("a.txt")),
            "Write: /w/a.txt"
        );
        assert_eq!(
            permission_detail("Task", &json!({}), Some("run a subagent")),
            "Task: run a subagent"
        );
        let long = "x".repeat(DETAIL_LIMIT * 2);
        assert!(permission_detail("Bash", &json!({"command": long}), None).len() <= DETAIL_LIMIT);
    }

    #[test]
    fn edit_proposal_carries_old_and_new_text_relative_to_the_root() {
        let edits = proposed_edits(
            "Edit",
            &json!({"file_path": abs("src/a.rs"), "old_string": "a\n", "new_string": "b\nc\n"}),
            &root(),
        );
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].path, PathBuf::from("src").join("a.rs"));
        assert_eq!(edits[0].old_text.as_deref(), Some("a\n"));
        assert_eq!(edits[0].new_text, "b\nc\n");
        assert!(!edits[0].truncated);
    }

    #[test]
    fn write_outside_the_root_stays_absolute_and_old_text_is_unknown() {
        let outside = root().join("..").join("bob").join("x.txt");
        let edits = proposed_edits(
            "Write",
            &json!({"file_path": outside.to_string_lossy(), "content": "hi"}),
            &root(),
        );
        assert_eq!(edits.len(), 1);
        assert!(edits[0].path.is_absolute(), "{:?}", edits[0].path);
        assert!(edits[0].old_text.is_none());
    }

    #[test]
    fn multi_edit_yields_one_proposal_per_edit_and_long_text_is_truncated() {
        let big = "y".repeat(EDIT_PREVIEW_LIMIT + 10);
        let edits = proposed_edits(
            "MultiEdit",
            &json!({"file_path": abs("f"), "edits": [
                {"old_string": "1", "new_string": "2"},
                {"old_string": "3", "new_string": big}
            ]}),
            &root(),
        );
        assert_eq!(edits.len(), 2);
        assert!(!edits[0].truncated);
        assert!(edits[1].truncated);
        assert_eq!(edits[1].new_text.len(), EDIT_PREVIEW_LIMIT);
    }

    #[test]
    fn non_edit_tools_propose_nothing() {
        assert!(proposed_edits("Bash", &json!({"command": "ls"}), &root()).is_empty());
    }

    #[test]
    fn a_turn_maps_to_events_and_a_result() {
        let mut interpreter = Interpreter::new(root());
        let task = TaskId(0);
        let steps = interpreter.interpret(
            task,
            &json!({"type": "system", "subtype": "init", "permissionMode": "default", "apiKeySource": "none"}),
        );
        assert!(
            matches!(&steps[..], [Step::Init { mode, credential }] if mode == "default" && credential == "none")
        );

        let steps = interpreter.interpret(task, &json!({"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": ""},
            {"type": "text", "text": "writing"},
            {"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": abs("a.txt"), "old_string": "a\n", "new_string": "b\nc\n"}}
        ]}}));
        assert!(
            matches!(&steps[0], Step::Event(RuntimeEvent::MessageDelta { text, .. }) if text == "writing")
        );
        assert!(
            matches!(&steps[1], Step::Event(RuntimeEvent::ToolCall { name, input_digest, .. }) if name == "Edit" && input_digest.starts_with("sha256:"))
        );
        assert_eq!(steps.len(), 2, "an empty thinking block is not an event");

        let steps = interpreter.interpret(
            task,
            &json!({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "ok", "is_error": false}
            ]}}),
        );
        assert!(
            matches!(&steps[0], Step::Event(RuntimeEvent::ToolResult { name, is_error: false, .. }) if name == "Edit")
        );
        assert!(
            matches!(&steps[1], Step::Event(RuntimeEvent::Diff { added: 2, removed: 1, path, .. }) if path == Path::new("a.txt"))
        );
        assert!(matches!(&steps[2], Step::Artifact(_)));

        let steps = interpreter.interpret(task, &json!({"type": "result", "subtype": "success", "is_error": false,
            "usage": {"input_tokens": 3, "cache_read_input_tokens": 10, "cache_creation_input_tokens": 5, "output_tokens": 2}}));
        match &steps[..] {
            [Step::Finished {
                usage,
                success: true,
                ..
            }] => {
                assert_eq!(usage.input_tokens, 18);
                assert_eq!(usage.output_tokens, 2);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_failed_tool_result_is_not_a_diff() {
        let mut interpreter = Interpreter::new(root());
        let task = TaskId(0);
        interpreter.interpret(task, &json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Write", "input": {"file_path": abs("a.txt"), "content": "x"}}
        ]}}));
        let steps = interpreter.interpret(task, &json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "rejected", "is_error": true}
        ]}}));
        assert_eq!(steps.len(), 1);
        assert!(matches!(
            &steps[0],
            Step::Event(RuntimeEvent::ToolResult { is_error: true, .. })
        ));
    }

    #[test]
    fn control_requests_become_permissions_or_rejections() {
        let mut interpreter = Interpreter::new(root());
        let steps = interpreter.interpret(TaskId(0), &json!({"type": "control_request", "request_id": "r1",
            "request": {"subtype": "can_use_tool", "tool_name": "Bash", "input": {"command": "ls"}, "description": "list"}}));
        assert!(
            matches!(&steps[..], [Step::Permission { request_id, tool, .. }] if request_id == "r1" && tool == "Bash")
        );
        let steps = interpreter.interpret(
            TaskId(0),
            &json!({"type": "control_request", "request_id": "r2",
            "request": {"subtype": "hook_callback"}}),
        );
        assert!(matches!(&steps[..], [Step::Reject { subtype, .. }] if subtype == "hook_callback"));
    }

    #[test]
    fn an_error_result_carries_its_reason() {
        let mut interpreter = Interpreter::new(root());
        let steps = interpreter.interpret(
            TaskId(0),
            &json!({"type": "result", "subtype": "error_during_execution", "is_error": true, "errors": ["boom"]}),
        );
        assert!(
            matches!(&steps[..], [Step::Finished { success: false, reason, .. }] if reason == "boom")
        );
    }

    #[test]
    fn noise_frames_are_ignored() {
        let mut interpreter = Interpreter::new(root());
        for frame in [
            json!({"type": "rate_limit_event"}),
            json!({"type": "system", "subtype": "thinking_tokens"}),
            json!({"type": "control_response", "response": {}}),
            json!({"type": "user", "message": {"content": "plain text"}}),
        ] {
            assert!(
                interpreter.interpret(TaskId(0), &frame).is_empty(),
                "{frame}"
            );
        }
    }

    #[test]
    fn permission_responses_follow_the_decision() {
        let allow = permission_response("r1", &json!({"a": 1}), true, false);
        assert_eq!(allow["response"]["response"]["behavior"], "allow");
        assert_eq!(allow["response"]["response"]["updatedInput"]["a"], 1);
        assert_eq!(allow["response"]["request_id"], "r1");
        let deny = permission_response("r2", &Value::Null, false, true);
        assert_eq!(deny["response"]["response"]["behavior"], "deny");
        assert_eq!(deny["response"]["response"]["interrupt"], true);
    }

    #[test]
    fn init_warnings_flag_a_foreign_mode_or_credential() {
        assert!(init_warnings("default", "default", "none").is_empty());
        assert!(init_warnings("default", "manual", "none").is_empty());
        assert_eq!(
            init_warnings("default", "bypassPermissions", "none").len(),
            1
        );
        assert_eq!(
            init_warnings("default", "default", "ANTHROPIC_API_KEY").len(),
            1
        );
        assert!(init_warnings("bypassPermissions", "bypassPermissions", "none").is_empty());
    }
}
