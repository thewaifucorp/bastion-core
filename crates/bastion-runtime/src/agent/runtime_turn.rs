//! Runtime-backed conversation turns (`docs/SUPPORT-MATRIX.md` §3, mode 2):
//! the harness owns the turn's tool loop, Bastion owns the conversation, the
//! permission decisions, and the record.
//!
//! # One harness session per Bastion session, kept between turns
//!
//! A harness session is a live process with its own context. Starting a fresh
//! one every turn (the historical behavior for adapters that cannot reattach)
//! throws that context away, so live sessions are kept in
//! [`AgentLoop::live_runtime_sessions`], keyed by Bastion session id, and
//! reused while they stay idle and healthy. A session idle for longer than
//! [`AgentLoop::runtime_session_idle`] is closed on the next runtime turn.
//!
//! # A permission request parks the turn
//!
//! The daemon serializes every owner through one `&mut AgentLoop`
//! (`docs/ARCHITECTURE.md` §6a), so a turn cannot sit waiting for a person to
//! read a diff. When the harness asks for permission, the turn is *parked*:
//! the request is recorded in the [`PermissionGate`](crate::agent::ports::PermissionGate),
//! the live session keeps the harness paused on it, and the turn returns the
//! request — with the proposed diff — as its answer. The owner's next message
//! resolves it: an approval continues the same harness turn, a rejection
//! denies it, anything else denies it and is then handled as a new message.
//! A request left unanswered past [`AgentLoop::permission_timeout`] is denied.
//! Adapters that pause their own task watchdog while a decision is pending
//! (the ACP adapter does) keep the harness turn alive for the whole wait.

use crate::agent::loop_::AgentLoop;
use crate::types::BastionError;
use bastion_agent_runtime::{
    DenyScope, McpBridgeSpec, PermissionAction, PermissionDecision, PermissionRequestId,
    ProposedEdit, RuntimeEvent, RuntimeSession, SessionStatus, TaskId, TaskInput, TaskOutcome,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Produces the MCP servers a harness session of `owner` gets, so the harness
/// reaches Bastion's memory, personas and capabilities (through Bastion's own
/// policy on the server side). Set by the host via
/// [`AgentLoop::with_runtime_mcp_bridge`]; `None` from the closure means no
/// bridge for that owner.
pub type RuntimeMcpBridge = Arc<dyn Fn(&str) -> Option<McpBridgeSpec> + Send + Sync>;

/// How long a live harness session may sit idle before it is closed.
pub const DEFAULT_RUNTIME_SESSION_IDLE: Duration = Duration::from_secs(30 * 60);

/// Longest diff excerpt rendered per proposed edit, in lines.
const MAX_DIFF_LINES: usize = 60;

/// A harness session kept alive between the turns of one Bastion session.
pub struct LiveRuntimeSession {
    owner: String,
    runtime_id: String,
    session: Box<dyn RuntimeSession>,
    last_used: Instant,
    parked: Option<ParkedTurn>,
}

/// A harness turn paused on a permission request, waiting for the owner.
struct ParkedTurn {
    task: TaskId,
    request: PermissionRequestId,
    /// Row in the permission gate; `None` when the gate could not record it
    /// (the request is still answerable, it just has no audit row).
    row_id: Option<i64>,
    raised_at: Instant,
    /// Assistant text the harness streamed before asking.
    text: String,
    activity: TurnActivity,
}

/// What the harness did during one turn, for the conversation record.
#[derive(Default)]
struct TurnActivity {
    tool_calls: u32,
    edits: Vec<(PathBuf, u32, u32)>,
}

impl TurnActivity {
    fn is_empty(&self) -> bool {
        self.tool_calls == 0 && self.edits.is_empty()
    }
}

/// How driving a harness task stopped.
enum Drive {
    Ended {
        outcome: TaskOutcome,
        text: String,
        activity: TurnActivity,
    },
    Parked {
        parked: ParkedTurn,
        action: PermissionAction,
        detail: String,
        edits: Vec<ProposedEdit>,
    },
}

/// What the owner's message means for a parked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approve,
    Reject,
    /// Not an answer: the request is denied and the message is a new prompt.
    Other,
}

fn answer_for(input: &str) -> Answer {
    let reject = crate::hooks::approval_intent::detect_rejection_intent(input);
    // A message carrying both ("não aprovo") is a rejection: allowing a harness
    // write needs an unambiguous yes.
    if reject {
        Answer::Reject
    } else if crate::hooks::approval_intent::detect_approval_intent(input) {
        Answer::Approve
    } else {
        Answer::Other
    }
}

impl AgentLoop {
    /// Host seam: give runtime-backed sessions (conversation and delegated
    /// tasks) Bastion's MCP servers. See [`RuntimeMcpBridge`].
    pub fn with_runtime_mcp_bridge(mut self, bridge: RuntimeMcpBridge) -> Self {
        self.runtime_mcp_bridge = Some(bridge);
        self
    }

    /// How long a live harness session may sit idle between turns before it
    /// is closed. Defaults to [`DEFAULT_RUNTIME_SESSION_IDLE`].
    pub fn with_runtime_session_idle(mut self, idle: Duration) -> Self {
        self.runtime_session_idle = idle;
        self
    }

    /// True while a harness turn of `owner` is parked on a permission request.
    /// The capability approval intercept yields to it: the owner's "sim" is
    /// answering the question the harness just asked.
    pub(crate) async fn has_parked_runtime_turn(&self, owner: &str) -> bool {
        self.live_runtime_sessions
            .lock()
            .await
            .values()
            .any(|live| live.owner == owner && live.parked.is_some())
    }

    pub(crate) fn runtime_mcp_bridge_for(&self, owner: &str) -> Option<McpBridgeSpec> {
        self.runtime_mcp_bridge
            .as_ref()
            .and_then(|bridge| bridge(owner))
    }

    /// Runs one runtime-backed conversation turn and returns the text to show
    /// and record. See the module docs for the session and parking model.
    pub(crate) async fn run_runtime_backed_turn(
        &mut self,
        runtime_id: &str,
        user_input: &str,
        owner: &str,
        session_id: &str,
        untrusted: bool,
    ) -> anyhow::Result<String> {
        self.close_idle_runtime_sessions(session_id).await;

        let live = self.live_runtime_sessions.lock().await.remove(session_id);
        let mut live = match live {
            // `/backend use` switched runtimes: the old harness session closes
            // when dropped here.
            Some(live) if live.runtime_id != runtime_id => None,
            other => other,
        };

        let mut preface = String::new();
        if let Some(mut current) = live.take() {
            match current.parked.take() {
                None => live = Some(current),
                Some(parked) if untrusted => {
                    // Free text from an unauthenticated channel never answers
                    // a permission request (same rule as the approval queue).
                    current.parked = Some(parked);
                    self.keep_live_session(session_id, current).await;
                    return Ok("Há um pedido de permissão do agente aguardando resposta. \
                               Responda por um canal autenticado."
                        .to_string());
                }
                Some(parked) => {
                    let expired = parked.raised_at.elapsed() > self.permission_timeout;
                    let answer = if expired {
                        Answer::Other
                    } else {
                        answer_for(user_input)
                    };
                    let decision = match answer {
                        Answer::Approve => PermissionDecision::Allow,
                        Answer::Reject | Answer::Other => PermissionDecision::Deny {
                            scope: DenyScope::Turn,
                        },
                    };
                    let drive = self
                        .answer_parked(owner, &mut current, parked, decision)
                        .await?;
                    match drive {
                        Drive::Parked {
                            parked,
                            action,
                            detail,
                            edits,
                        } => {
                            let message = permission_message(
                                runtime_id,
                                &parked.text,
                                &action,
                                &detail,
                                &edits,
                                self.permission_timeout,
                            );
                            current.parked = Some(parked);
                            self.keep_live_session(session_id, current).await;
                            return Ok(message);
                        }
                        Drive::Ended {
                            outcome,
                            text,
                            activity,
                        } => {
                            if answer == Answer::Approve {
                                let text = finish_text(runtime_id, outcome, text, &activity)?;
                                self.keep_if_idle(session_id, current).await;
                                return Ok(text);
                            }
                            if answer == Answer::Reject
                                || (expired
                                    && crate::hooks::approval_intent::detect_approval_intent(
                                        user_input,
                                    ))
                            {
                                self.keep_if_idle(session_id, current).await;
                                let mut reply = if expired {
                                    "O pedido de permissão expirou e foi negado.".to_string()
                                } else {
                                    format!("Negado. O {runtime_id} parou esta tarefa.")
                                };
                                if !text.trim().is_empty() {
                                    reply = format!("{}\n\n{reply}", text.trim_end());
                                }
                                return Ok(append_activity(reply, runtime_id, &activity));
                            }
                            // Not an answer: the request is denied and the
                            // message goes to the harness as a new prompt.
                            preface = if expired {
                                "(O pedido de permissão anterior expirou e foi negado.)\n\n"
                            } else {
                                "(Pedido de permissão anterior negado.)\n\n"
                            }
                            .to_string();
                            live = self.reusable(current).await;
                        }
                    }
                }
            }
        }

        // §3 mode 2: egress-filtered context, judged against the ACTUAL
        // destination (the harness id) — the same mechanism/tier rules the
        // Model path's system prompt uses.
        let (context_parts, _stable_prefix_len) = self
            .build_context_parts_for_destination(owner, user_input, None, runtime_id)
            .await;
        let mut prompt = context_parts.join("\n\n");
        if !prompt.is_empty() {
            prompt.push_str("\n\n");
        }
        prompt.push_str(user_input);

        let mut current = match live {
            Some(live) => live,
            None => {
                self.open_runtime_session(runtime_id, owner, session_id)
                    .await?
            }
        };

        let task = current
            .session
            .submit(TaskInput {
                prompt,
                attachments: Vec::new(),
                expected: bastion_agent_runtime::TaskExpectation::Conversation,
                model_hint: None,
            })
            .await
            .map_err(|e| anyhow::Error::new(BastionError::BackendUnavailable(e.to_string())))?;

        let drive = self
            .drive_runtime_task(
                owner,
                &mut *current.session,
                task,
                String::new(),
                TurnActivity::default(),
            )
            .await?;
        match drive {
            Drive::Parked {
                parked,
                action,
                detail,
                edits,
            } => {
                let message = permission_message(
                    runtime_id,
                    &parked.text,
                    &action,
                    &detail,
                    &edits,
                    self.permission_timeout,
                );
                current.parked = Some(parked);
                self.keep_live_session(session_id, current).await;
                Ok(format!("{preface}{message}"))
            }
            Drive::Ended {
                outcome,
                text,
                activity,
            } => {
                let text = finish_text(runtime_id, outcome, text, &activity)?;
                self.keep_if_idle(session_id, current).await;
                Ok(format!("{preface}{text}"))
            }
        }
    }

    /// Opens (or reattaches) the harness session for a Bastion session.
    async fn open_runtime_session(
        &mut self,
        runtime_id: &str,
        owner: &str,
        session_id: &str,
    ) -> anyhow::Result<LiveRuntimeSession> {
        let runtime = self
            .runtime_registry
            .resolve(runtime_id)
            .await
            .map_err(|e| anyhow::Error::new(BastionError::BackendUnavailable(e.to_string())))?;

        let _ = tokio::fs::create_dir_all(crate::agent::loop_::runtime_workspace_root(
            self.runtime_workspace_base.as_deref(),
            owner,
        ))
        .await;
        let (spec, timeout, permissions, env) = crate::agent::loop_::build_runtime_session_spec(
            owner,
            runtime_id,
            &self.backend_profile,
            self.runtime_workspace_base.as_deref(),
            self.runtime_mcp_bridge_for(owner),
        );

        // M4-07: verify the resolved AuthProfileRef is usable BEFORE
        // start/resume — typed, fail-closed, no secret crosses this boundary.
        self.auth_resolver
            .resolve(&spec.auth)
            .await
            .map_err(|e| anyhow::Error::new(BastionError::BackendUnavailable(e.to_string())))?;

        // Restart recovery: reuse a persisted handle when the adapter can
        // genuinely reattach. A resume failure is not fatal — a fresh
        // harness-side session begins; logged, never silent.
        let persisted = self.session.load_runtime_handle(session_id).await?;
        let session = match persisted {
            Some(handle) if handle.runtime_id == runtime.descriptor().id => {
                let resume_spec = bastion_agent_runtime::ResumeSpec {
                    timeout,
                    permissions,
                    env,
                };
                match runtime.resume(&handle, resume_spec).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::info!(
                            event = "agent_runtime_resume_failed_starting_fresh",
                            runtime_id = %runtime_id,
                            session_id = %session_id,
                            error = %e,
                        );
                        runtime.start(spec).await.map_err(|e| {
                            anyhow::Error::new(BastionError::BackendUnavailable(e.to_string()))
                        })?
                    }
                }
            }
            _ => runtime
                .start(spec)
                .await
                .map_err(|e| anyhow::Error::new(BastionError::BackendUnavailable(e.to_string())))?,
        };

        // Persist the (possibly new) handle immediately: this is the link from
        // the Bastion session to its child harness session, and a crash before
        // the task ends still leaves it reattachable.
        self.session
            .save_runtime_handle(session_id, &session.handle())
            .await?;

        Ok(LiveRuntimeSession {
            owner: owner.to_string(),
            runtime_id: runtime_id.to_string(),
            session,
            last_used: Instant::now(),
            parked: None,
        })
    }

    /// Answers a parked request and keeps driving the same harness task.
    async fn answer_parked(
        &mut self,
        owner: &str,
        live: &mut LiveRuntimeSession,
        parked: ParkedTurn,
        decision: PermissionDecision,
    ) -> anyhow::Result<Drive> {
        if let Some(row_id) = parked.row_id {
            if let Err(e) = self.permission_gate.resolve(owner, row_id, decision).await {
                tracing::warn!(event = "agent_runtime_permission_resolve_failed", error = %e);
            }
        }
        if let Err(e) = live
            .session
            .respond_permission(parked.request, decision)
            .await
        {
            // The harness gave up on the request (its process ended, or it
            // timed the request out itself); the task's own events say how.
            tracing::warn!(event = "agent_runtime_respond_permission_failed", error = %e);
        }
        self.drive_runtime_task(
            owner,
            &mut *live.session,
            parked.task,
            parked.text,
            parked.activity,
        )
        .await
    }

    /// Consumes a task's events until it ends or raises a permission request.
    async fn drive_runtime_task(
        &self,
        owner: &str,
        session: &mut dyn RuntimeSession,
        task: TaskId,
        mut text: String,
        mut activity: TurnActivity,
    ) -> anyhow::Result<Drive> {
        let handle = session.handle();
        loop {
            let Some(event) = session.next_event().await else {
                anyhow::bail!(BastionError::BackendUnavailable(
                    "runtime session event stream closed before the task ended".to_string()
                ));
            };
            match event {
                RuntimeEvent::MessageDelta {
                    task: t,
                    text: delta,
                } if t == task => {
                    text.push_str(&delta);
                }
                RuntimeEvent::ToolCall { task: t, name, .. } if t == task => {
                    activity.tool_calls += 1;
                    tracing::debug!(event = "agent_runtime_tool_call", runtime = %handle.runtime_id, tool = %name);
                }
                RuntimeEvent::Diff {
                    task: t,
                    path,
                    added,
                    removed,
                } if t == task => {
                    activity.edits.push((path, added, removed));
                }
                RuntimeEvent::PermissionRequest {
                    task: t,
                    id,
                    action,
                    detail,
                    edits,
                } if t == task => {
                    let raised = now_nanos();
                    let expires = raised + self.permission_timeout.as_nanos() as i64;
                    let row_id = match self
                        .permission_gate
                        .enqueue(owner, &handle, id, &action, &detail, raised, expires)
                        .await
                    {
                        Ok(row_id) => Some(row_id),
                        Err(e) => {
                            tracing::warn!(event = "agent_runtime_permission_audit_failed", error = %e);
                            None
                        }
                    };
                    return Ok(Drive::Parked {
                        parked: ParkedTurn {
                            task,
                            request: id,
                            row_id,
                            raised_at: Instant::now(),
                            text,
                            activity,
                        },
                        action,
                        detail,
                        edits,
                    });
                }
                RuntimeEvent::Usage { task: t, delta } if t == task => {
                    tracing::debug!(
                        event = "agent_runtime_usage",
                        runtime_id = %handle.runtime_id,
                        input_tokens = delta.input_tokens,
                        output_tokens = delta.output_tokens,
                    );
                    // BUP-03: a harness runs on the operator's own login —
                    // `billing = subscription`, zero metered dollars, tokens
                    // recorded on the turn and the session total.
                    let (meter, scope) = self.active_meter();
                    meter
                        .record_runtime_usage(
                            &scope,
                            &handle.runtime_id,
                            delta.input_tokens,
                            delta.output_tokens,
                            bastion_agent_runtime::BudgetCoverage::Reported,
                        )
                        .await;
                }
                RuntimeEvent::Warning { code, detail, .. } => {
                    tracing::warn!(
                        event = "agent_runtime_warning",
                        runtime_id = %handle.runtime_id,
                        ?code,
                        detail = %detail,
                    );
                }
                RuntimeEvent::Ended { task: t, outcome } if t == task => {
                    return Ok(Drive::Ended {
                        outcome,
                        text,
                        activity,
                    });
                }
                _ => {}
            }
        }
    }

    async fn keep_live_session(&self, session_id: &str, mut live: LiveRuntimeSession) {
        live.last_used = Instant::now();
        self.live_runtime_sessions
            .lock()
            .await
            .insert(session_id.to_string(), live);
    }

    /// Keeps the session for the next turn only when it is idle and healthy;
    /// a cancelled, crashed or closed one is dropped (and its process with it).
    async fn keep_if_idle(&self, session_id: &str, live: LiveRuntimeSession) {
        if let Some(live) = self.reusable(live).await {
            self.keep_live_session(session_id, live).await;
        }
    }

    async fn reusable(&self, live: LiveRuntimeSession) -> Option<LiveRuntimeSession> {
        match live.session.status().await {
            Ok(SessionStatus::Idle) => Some(live),
            _ => None,
        }
    }

    /// Closes sessions idle past [`AgentLoop::runtime_session_idle`] and denies
    /// parked requests past [`AgentLoop::permission_timeout`] — except the
    /// session of the turn being run, whose expired request is answered in
    /// that turn (a late "sim" must read as "expired", not as a new prompt).
    async fn close_idle_runtime_sessions(&self, current: &str) {
        let mut sessions = self.live_runtime_sessions.lock().await;
        let stale: Vec<String> = sessions
            .iter()
            .filter(|(id, _)| id.as_str() != current)
            .filter(|(_, live)| match &live.parked {
                Some(parked) => parked.raised_at.elapsed() > self.permission_timeout,
                None => live.last_used.elapsed() > self.runtime_session_idle,
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            let Some(mut live) = sessions.remove(&id) else {
                continue;
            };
            if let Some(parked) = live.parked.take() {
                let deny = PermissionDecision::Deny {
                    scope: DenyScope::Turn,
                };
                if let Some(row_id) = parked.row_id {
                    let _ = self
                        .permission_gate
                        .resolve(&live.owner, row_id, deny)
                        .await;
                }
                let _ = live.session.respond_permission(parked.request, deny).await;
            }
            tracing::info!(event = "agent_runtime_session_closed_idle", session_id = %id, runtime_id = %live.runtime_id);
        }
    }
}

/// Final text of a task that ended: the assistant text plus what the harness
/// did, or the typed error for an outcome that is not a success.
fn finish_text(
    runtime_id: &str,
    outcome: TaskOutcome,
    text: String,
    activity: &TurnActivity,
) -> anyhow::Result<String> {
    match outcome {
        TaskOutcome::Success => Ok(append_activity(text, runtime_id, activity)),
        TaskOutcome::Cancelled => anyhow::bail!(BastionError::BackendUnavailable(
            "runtime task was cancelled before completion".to_string()
        )),
        TaskOutcome::TimedOut => anyhow::bail!(BastionError::BackendUnavailable(
            "runtime task timed out".to_string()
        )),
        TaskOutcome::Failed { reason } => {
            anyhow::bail!(BastionError::BackendUnavailable(reason))
        }
    }
}

/// Appends a one-line account of the harness's tool use and edits, so the
/// conversation record says what happened, not only what was said.
fn append_activity(text: String, runtime_id: &str, activity: &TurnActivity) -> String {
    if activity.is_empty() {
        return text;
    }
    let mut parts = Vec::new();
    if !activity.edits.is_empty() {
        let edits: Vec<String> = activity
            .edits
            .iter()
            .map(|(path, added, removed)| format!("`{}` (+{added} −{removed})", path.display()))
            .collect();
        parts.push(format!("editou {}", edits.join(", ")));
    }
    if activity.tool_calls > 0 {
        let noun = if activity.tool_calls == 1 {
            "chamada de ferramenta"
        } else {
            "chamadas de ferramenta"
        };
        parts.push(format!("{} {noun}", activity.tool_calls));
    }
    format!(
        "{}\n\n— {runtime_id}: {}.",
        text.trim_end(),
        parts.join("; ")
    )
}

fn action_label(action: &PermissionAction) -> String {
    match action {
        PermissionAction::RunCommand => "executar um comando".to_string(),
        PermissionAction::WriteFile => "escrever em arquivo".to_string(),
        PermissionAction::Network => "acessar a rede".to_string(),
        PermissionAction::UseTool => "usar uma ferramenta".to_string(),
        PermissionAction::Other(other) => other.clone(),
    }
}

/// The turn's answer while a request is parked: what the harness said so far,
/// what it wants to do, the diff when it sent one, and how to answer.
fn permission_message(
    runtime_id: &str,
    text_so_far: &str,
    action: &PermissionAction,
    detail: &str,
    edits: &[ProposedEdit],
    timeout: Duration,
) -> String {
    let mut out = String::new();
    if !text_so_far.trim().is_empty() {
        out.push_str(text_so_far.trim_end());
        out.push_str("\n\n");
    }
    out.push_str(&format!(
        "**O {runtime_id} pede permissão para {}:** {detail}\n",
        action_label(action)
    ));
    for edit in edits {
        out.push('\n');
        out.push_str(&render_edit(edit));
    }
    out.push_str(&format!(
        "\nResponda **sim** para permitir ou **não** para negar. Sem resposta em {} min, \
         o pedido é negado.",
        timeout.as_millis().div_ceil(60_000).max(1)
    ));
    out
}

/// A compact diff of one proposed edit: the changed middle of the file, with
/// the common head and tail dropped, capped at [`MAX_DIFF_LINES`].
fn render_edit(edit: &ProposedEdit) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut header = format!("`{}`", edit.path.display());
    match &edit.old_text {
        None => {
            header.push_str(" (conteúdo anterior não informado)");
            lines.extend(edit.new_text.lines().map(|l| format!("+{l}")));
        }
        Some(old) => {
            let old: Vec<&str> = old.lines().collect();
            let new: Vec<&str> = edit.new_text.lines().collect();
            let head = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
            let tail = old[head..]
                .iter()
                .rev()
                .zip(new[head..].iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            if head > 0 || tail > 0 {
                header.push_str(&format!(" (a partir da linha {})", head + 1));
            }
            lines.extend(old[head..old.len() - tail].iter().map(|l| format!("-{l}")));
            lines.extend(new[head..new.len() - tail].iter().map(|l| format!("+{l}")));
        }
    }
    if edit.truncated {
        header.push_str(" — prévia cortada, o arquivo real é maior");
    }
    let hidden = lines.len().saturating_sub(MAX_DIFF_LINES);
    lines.truncate(MAX_DIFF_LINES);
    let mut out = format!("{header}\n```diff\n{}\n```\n", lines.join("\n"));
    if hidden > 0 {
        out.push_str(&format!("(+{hidden} linhas não mostradas)\n"));
    }
    out
}

fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(old: Option<&str>, new: &str) -> ProposedEdit {
        ProposedEdit {
            path: PathBuf::from("src/lib.rs"),
            old_text: old.map(str::to_string),
            new_text: new.to_string(),
            truncated: false,
        }
    }

    #[test]
    fn an_answer_needs_an_unambiguous_yes() {
        assert_eq!(answer_for("sim"), Answer::Approve);
        assert_eq!(answer_for("Sim, pode fazer"), Answer::Approve);
        assert_eq!(answer_for("não"), Answer::Reject);
        assert_eq!(answer_for("não aprovo"), Answer::Reject);
        assert_eq!(answer_for("muda o nome da função antes"), Answer::Other);
    }

    #[test]
    fn the_diff_shows_only_the_changed_middle() {
        let rendered = render_edit(&edit(Some("a\nb\nc\nd\n"), "a\nB\nc\nd\n"));
        assert!(rendered.contains("(a partir da linha 2)"), "{rendered}");
        assert!(rendered.contains("```diff\n-b\n+B\n```"), "{rendered}");
    }

    #[test]
    fn an_unknown_previous_content_is_said_not_implied() {
        let rendered = render_edit(&edit(None, "x\ny\n"));
        assert!(
            rendered.contains("conteúdo anterior não informado"),
            "{rendered}"
        );
        assert!(rendered.contains("+x\n+y"), "{rendered}");
    }

    #[test]
    fn a_truncated_preview_and_a_long_diff_say_so() {
        let long: String = (0..100).map(|i| format!("l{i}\n")).collect();
        let mut e = edit(None, &long);
        e.truncated = true;
        let rendered = render_edit(&e);
        assert!(rendered.contains("prévia cortada"), "{rendered}");
        assert!(
            rendered.contains("(+40 linhas não mostradas)"),
            "{rendered}"
        );
    }

    #[test]
    fn the_permission_message_carries_request_diff_and_instructions() {
        let message = permission_message(
            "acp_claude",
            "Vou criar o arquivo.",
            &PermissionAction::WriteFile,
            "Write notes.txt",
            &[edit(None, "hello\n")],
            Duration::from_secs(600),
        );
        assert!(message.starts_with("Vou criar o arquivo.\n\n"));
        assert!(message
            .contains("**O acp_claude pede permissão para escrever em arquivo:** Write notes.txt"));
        assert!(message.contains("+hello"));
        assert!(message.contains("Sem resposta em 10 min"));
    }

    #[test]
    fn activity_is_appended_only_when_something_happened() {
        assert_eq!(
            append_activity("ok".into(), "acp_claude", &TurnActivity::default()),
            "ok"
        );
        let activity = TurnActivity {
            tool_calls: 2,
            edits: vec![(PathBuf::from("a.rs"), 3, 1)],
        };
        assert_eq!(
            append_activity("feito".into(), "acp_claude", &activity),
            "feito\n\n— acp_claude: editou `a.rs` (+3 −1); 2 chamadas de ferramenta."
        );
    }
}
