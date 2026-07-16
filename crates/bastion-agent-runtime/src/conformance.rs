//! Conformance suite for [`crate::agent_runtime::AgentRuntime`] adapters (A-02).
//!
//! Every adapter — native app-server, supervised ACP client, or the
//! the embedded [`FakeRuntime`] below
//! reference implementation used by the integration tests — runs the SAME
//! suite. A check never inspects adapter-internal types; it only calls the
//! [`AgentRuntime`]/[`RuntimeSession`] contract and, optionally, the
//! [`FaultInjection`] hooks.
//!
//! # Scenario prompts
//!
//! The suite cannot manufacture adapter-specific behavior (asking a real
//! harness to "hang forever" or "raise a permission request" requires a
//! prompt tailored to that harness). Instead, the caller supplies four
//! [`ConformanceScenarios`] — plain [`TaskInput`]s the target is expected to
//! react to as documented on each field. The suite drives the contract; the
//! caller wires it to what makes the target actually behave that way.
//!
//! # Fault injection
//!
//! Checks 10-12 (crash isolation, typed auth failure, garbage-frame
//! rejection) require inducing a failure that a *conforming* adapter cannot
//! be asked for through the normal contract. [`FaultInjection`] is an
//! optional side-channel the conformance target may implement in addition to
//! [`AgentRuntime`]; every method defaults to `false` ("unsupported"), which
//! turns the corresponding check into [`CheckResult::Skip`] rather than a
//! failure. A real adapter can implement it by reaching into the harness
//! process/connection it already owns (kill the subprocess, poison the
//! cached credential, write a malformed frame on the transport).
//!
//! # Running the suite
//!
//! [`run_all`] runs every check in sequence against one `(runtime, spec,
//! scenarios)` triple and returns a name-tagged result list; [`format_report`]
//! renders it as human-readable text for logs/CI output.

use super::*;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Default upper bound on how long any single check waits for an event
/// before declaring the target unresponsive — generous enough for an
/// in-process fake or a local subprocess adapter. Ciclo 2.2 (A-05 §5.1):
/// this used to be a crate-wide `const`; a live cloud-backed harness makes
/// 14 genuine cold `start()` calls in one `run_all` sweep, and real,
/// variable network/handshake latency can exceed 5s on isolated runs
/// without anything actually being wrong. It is now
/// [`ConformanceScenarios::watchdog`] — callers targeting a live adapter
/// pass something larger (e.g. 30s); this constant is just the suggested
/// default for embedded/local-subprocess targets.
pub const DEFAULT_WATCHDOG: Duration = Duration::from_secs(5);

/// Optional side-channel a conformance target may implement to exercise
/// failure paths that cannot be triggered through the normal
/// [`AgentRuntime`]/[`RuntimeSession`] contract alone.
///
/// Every method defaults to `false` ("this target does not support inducing
/// this fault"), which the corresponding check turns into
/// [`CheckResult::Skip`] instead of [`CheckResult::Fail`]. A method returning
/// `true` asserts the fault was actually induced — the check then requires
/// the typed, contract-compliant reaction (never a panic, never a generic
/// error).
#[async_trait::async_trait]
pub trait FaultInjection: Send + Sync {
    /// Kill the harness process/connection backing the currently active
    /// session, mid-task.
    async fn induce_crash(&self) -> bool {
        false
    }

    /// Make the next [`AgentRuntime::start`] fail credential resolution.
    async fn induce_auth_failure(&self) -> bool {
        false
    }

    /// Feed a malformed/non-protocol frame (simulated human stdout, ANSI
    /// escapes, truncated JSON) into the active session's transport.
    async fn feed_garbage_frame(&self) -> bool {
        false
    }
}

/// Outcome of a single conformance check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// The target satisfies this requirement.
    Pass,
    /// The requirement does not apply to this target (declared unsupported
    /// via [`RuntimeSupports`], [`PolicyCoverage`], or [`FaultInjection`]).
    Skip(String),
    /// The target violates this requirement.
    Fail(String),
}

impl CheckResult {
    /// `true` for [`CheckResult::Pass`].
    pub fn is_pass(&self) -> bool {
        matches!(self, CheckResult::Pass)
    }

    /// `true` for [`CheckResult::Fail`].
    pub fn is_fail(&self) -> bool {
        matches!(self, CheckResult::Fail(_))
    }

    /// `true` for [`CheckResult::Skip`].
    pub fn is_skip(&self) -> bool {
        matches!(self, CheckResult::Skip(_))
    }
}

/// Adapter-specific prompts that drive the named scenarios each check
/// depends on. The suite treats every field as an opaque [`TaskInput`]; it is
/// the caller's responsibility to make submitting it produce the documented
/// reaction from the target under test.
#[derive(Debug, Clone)]
pub struct ConformanceScenarios {
    /// Submitting this MUST lead to `Ended { outcome: Success }`, emitting at
    /// least one `MessageDelta` along the way.
    pub happy_path: TaskInput,
    /// Submitting this MUST NOT reach `Ended` on its own — it only ends via
    /// `cancel` or timeout. Used to keep a task "active" for steer/cancel/
    /// timeout checks.
    pub never_terminates: TaskInput,
    /// Submitting this MUST emit exactly one `PermissionRequest` for the
    /// guarded action. If answered `Allow`, the guarded action executes and
    /// the target emits an `Artifact` or a non-error `ToolResult` before
    /// `Ended`. If answered `Deny`, the target reaches `Ended` without ever
    /// emitting that evidence.
    pub requests_permission: TaskInput,
    /// Submitting this MUST emit at least one `Artifact` event referencing a
    /// file under the session's workspace root, then `Ended { outcome:
    /// Success }`.
    pub produces_artifact: TaskInput,
    /// Upper bound each check waits for an expected event before declaring
    /// the target unresponsive (Ciclo 2.2, A-05 §5.1). Use
    /// [`DEFAULT_WATCHDOG`] for an embedded fake or local-subprocess
    /// adapter; live cloud-backed adapters should pass a larger value (e.g.
    /// 30s) to absorb genuine cold-start/network latency across the 14
    /// `start()` calls one `run_all` sweep makes.
    pub watchdog: Duration,
}

/// Runs every conformance check in sequence against one `(runtime, spec,
/// scenarios)` triple.
///
/// `spec` is used as a template: individual checks clone it and override
/// only what they need (e.g. a short `timeout.per_task` for the timeout
/// check). `spec.workspace.root` must be a real, writable directory — the
/// artifact digest check reads files from it.
pub async fn run_all<R>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> Vec<(&'static str, CheckResult)>
where
    R: AgentRuntime + FaultInjection,
{
    vec![
        (
            "happy_path",
            check_happy_path(runtime, spec, scenarios).await,
        ),
        ("resume", check_resume(runtime, spec).await),
        ("steer", check_steer(runtime, spec, scenarios).await),
        (
            "cancel_graceful",
            check_cancel_graceful(runtime, spec, scenarios).await,
        ),
        (
            "cancel_kill",
            check_cancel_kill(runtime, spec, scenarios).await,
        ),
        ("timeout", check_timeout(runtime, spec, scenarios).await),
        (
            "queue_or_reject",
            check_queue_or_reject(runtime, spec, scenarios).await,
        ),
        (
            "event_ordering_terminal",
            check_event_ordering_terminal(runtime, spec, scenarios).await,
        ),
        (
            "artifact_digest",
            check_artifact_digest(runtime, spec, scenarios).await,
        ),
        (
            "permission_bridge_allow",
            check_permission_bridge_allow(runtime, spec, scenarios).await,
        ),
        (
            "permission_bridge_deny",
            check_permission_bridge_deny(runtime, spec, scenarios).await,
        ),
        (
            "crash_isolation",
            check_crash_isolation(runtime, spec, scenarios).await,
        ),
        ("auth_typed", check_auth_typed(runtime, spec).await),
        (
            "protocol_garbage",
            check_protocol_garbage(runtime, spec).await,
        ),
    ]
}

/// Renders a [`run_all`] report as human-readable text (one line per check,
/// plus a pass/skip/fail tally).
pub fn format_report(results: &[(&'static str, CheckResult)]) -> String {
    let mut out = String::new();
    let (mut pass, mut skip, mut fail) = (0u32, 0u32, 0u32);
    for (name, result) in results {
        let (tag, detail) = match result {
            CheckResult::Pass => {
                pass += 1;
                ("PASS", String::new())
            }
            CheckResult::Skip(reason) => {
                skip += 1;
                ("SKIP", reason.clone())
            }
            CheckResult::Fail(detail) => {
                fail += 1;
                ("FAIL", detail.clone())
            }
        };
        if detail.is_empty() {
            out.push_str(&format!("{tag:<4} {name}\n"));
        } else {
            out.push_str(&format!("{tag:<4} {name}: {detail}\n"));
        }
    }
    out.push_str(&format!("\n{pass} passed, {skip} skipped, {fail} failed\n"));
    out
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

/// Extracts the `TaskId` an event belongs to, if any (`Started` is
/// session-level, not task-level).
fn event_task(evt: &RuntimeEvent) -> Option<TaskId> {
    match evt {
        RuntimeEvent::Started { .. } => None,
        RuntimeEvent::MessageDelta { task, .. }
        | RuntimeEvent::Thinking { task, .. }
        | RuntimeEvent::ToolCall { task, .. }
        | RuntimeEvent::ToolResult { task, .. }
        | RuntimeEvent::PermissionRequest { task, .. }
        | RuntimeEvent::Diff { task, .. }
        | RuntimeEvent::Artifact { task, .. }
        | RuntimeEvent::Usage { task, .. }
        | RuntimeEvent::Warning { task, .. }
        | RuntimeEvent::Ended { task, .. } => Some(*task),
    }
}

/// Fails if any event for a task arrives after that task's own `Ended`
/// (event ordering requirement #7).
fn validate_no_post_terminal_events(events: &[RuntimeEvent]) -> Result<(), String> {
    let mut ended: std::collections::HashSet<TaskId> = std::collections::HashSet::new();
    for evt in events {
        if let Some(t) = event_task(evt) {
            if ended.contains(&t) {
                return Err(format!(
                    "event for task {t:?} arrived after its Ended: {evt:?}"
                ));
            }
            if matches!(evt, RuntimeEvent::Ended { .. }) {
                ended.insert(t);
            }
        }
    }
    Ok(())
}

/// Drains events (bounded by `watchdog`) until the target task's `Ended`
/// is observed, returning its outcome and every event seen along the way
/// (including other tasks', for callers that need to inspect interleaving).
async fn drain_until_ended(
    session: &mut dyn RuntimeSession,
    task: TaskId,
    watchdog: Duration,
) -> Result<(TaskOutcome, Vec<RuntimeEvent>), String> {
    let mut seen = Vec::new();
    loop {
        match tokio::time::timeout(watchdog, session.next_event()).await {
            Ok(Some(evt)) => {
                let matched = if let RuntimeEvent::Ended { task: t, outcome } = &evt {
                    (*t == task).then(|| outcome.clone())
                } else {
                    None
                };
                seen.push(evt);
                if let Some(outcome) = matched {
                    return Ok((outcome, seen));
                }
            }
            Ok(None) => return Err("event stream closed before task Ended".to_string()),
            Err(_) => return Err("timed out waiting for task Ended".to_string()),
        }
    }
}

/// Drains events (bounded by `watchdog`) until a `PermissionRequest` for
/// `task` is observed, returning its id and every event seen so far.
async fn wait_for_permission_request(
    session: &mut dyn RuntimeSession,
    task: TaskId,
    watchdog: Duration,
) -> Result<(PermissionRequestId, Vec<RuntimeEvent>), String> {
    let mut seen = Vec::new();
    loop {
        match tokio::time::timeout(watchdog, session.next_event()).await {
            Ok(Some(evt)) => {
                let matched_id = if let RuntimeEvent::PermissionRequest { task: t, id, .. } = &evt {
                    (*t == task).then_some(*id)
                } else {
                    None
                };
                let is_target_ended =
                    matches!(&evt, RuntimeEvent::Ended { task: t, .. } if *t == task);
                seen.push(evt);
                if let Some(id) = matched_id {
                    return Ok((id, seen));
                }
                if is_target_ended {
                    return Err("task ended before any PermissionRequest was observed".to_string());
                }
            }
            Ok(None) => return Err("event stream closed before PermissionRequest".to_string()),
            Err(_) => return Err("timed out waiting for PermissionRequest".to_string()),
        }
    }
}

/// `true` if any event in `events` for `task` is evidence the harness
/// actually performed the guarded action (an `Artifact`, or a non-error
/// `ToolResult`).
fn guarded_action_executed(events: &[RuntimeEvent], task: TaskId) -> bool {
    events.iter().any(|e| {
        matches!(e, RuntimeEvent::Artifact { task: t, .. } if *t == task)
            || matches!(e, RuntimeEvent::ToolResult { task: t, is_error: false, .. } if *t == task)
    })
}

// ---------------------------------------------------------------------
// Checks — A-01 §5 requirements 1-13
// ---------------------------------------------------------------------

/// #1 — start → submit → stream → `Ended{Success}`; `Started` first; at
/// least one `MessageDelta`.
pub async fn check_happy_path<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    match tokio::time::timeout(scenarios.watchdog, session.next_event()).await {
        Ok(Some(RuntimeEvent::Started { .. })) => {}
        Ok(Some(other)) => {
            return CheckResult::Fail(format!("expected Started first, got {other:?}"))
        }
        Ok(None) => return CheckResult::Fail("event stream closed before Started".to_string()),
        Err(_) => return CheckResult::Fail("timed out waiting for Started".to_string()),
    }
    let task = match session.submit(scenarios.happy_path.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    let (outcome, events) = match drain_until_ended(&mut *session, task, scenarios.watchdog).await {
        Ok(v) => v,
        Err(detail) => return CheckResult::Fail(detail),
    };
    if outcome != TaskOutcome::Success {
        return CheckResult::Fail(format!("expected Success, got {outcome:?}"));
    }
    let has_delta = events
        .iter()
        .any(|e| matches!(e, RuntimeEvent::MessageDelta { task: t, .. } if *t == task));
    if !has_delta {
        return CheckResult::Fail("no MessageDelta observed before Ended".to_string());
    }
    CheckResult::Pass
}

/// #2 — resume after dropping the session handle: works, or returns typed
/// `NotResumable`. If `supports.resume == false`, resume MUST return
/// `NotResumable` (never silently succeed, never a generic error).
pub async fn check_resume<R: AgentRuntime>(runtime: &R, spec: &SessionSpec) -> CheckResult {
    let supports_resume = runtime.descriptor().supports.resume;
    let session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let handle = session.handle();
    drop(session);
    // Ciclo 2.2: resume() takes the re-appliable subset of the original
    // spec (workspace/sandbox stay fixed to the session that's being
    // reattached — only timeout/permissions/env can plausibly travel).
    let resume_spec = ResumeSpec {
        timeout: spec.timeout,
        permissions: spec.permissions.clone(),
        env: spec.env.clone(),
    };
    let result = runtime.resume(&handle, resume_spec).await;
    if supports_resume {
        match result {
            Ok(_) => CheckResult::Pass,
            Err(RuntimeError::NotResumable(_)) => CheckResult::Pass,
            Err(other) => CheckResult::Fail(format!(
                "supports.resume=true but resume() failed atypically: {other}"
            )),
        }
    } else {
        match result {
            Err(RuntimeError::NotResumable(_)) => CheckResult::Pass,
            Ok(_) => CheckResult::Fail("supports.resume=false but resume() succeeded".to_string()),
            Err(other) => CheckResult::Fail(format!(
                "supports.resume=false but resume() returned {other} instead of NotResumable"
            )),
        }
    }
}

/// #3 — steer mid-task succeeds if declared supported; otherwise fails
/// typed with `RuntimeError::Protocol`.
pub async fn check_steer<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let supports_steer = runtime.descriptor().supports.steer;
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    if let Err(e) = session.submit(scenarios.never_terminates.clone()).await {
        return CheckResult::Fail(format!("submit failed: {e}"));
    }
    let result = session.steer("additional context").await;
    let _ = session.cancel(CancelMode::Kill).await;
    if supports_steer {
        match result {
            Ok(()) => CheckResult::Pass,
            Err(e) => CheckResult::Fail(format!("supports.steer=true but steer() failed: {e}")),
        }
    } else {
        match result {
            Err(RuntimeError::Protocol(_)) => CheckResult::Pass,
            Ok(()) => CheckResult::Fail("supports.steer=false but steer() succeeded".to_string()),
            Err(other) => CheckResult::Fail(format!(
                "supports.steer=false but got {other} instead of Protocol"
            )),
        }
    }
}

/// Shared body for #4a/#4b: cancel an active task, expect `Ended{Cancelled}`
/// + `status()==Cancelled`, then verify a second cancel is idempotent.
async fn check_cancel<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
    mode: CancelMode,
) -> CheckResult {
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task = match session.submit(scenarios.never_terminates.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    if let Err(e) = session.cancel(mode).await {
        return CheckResult::Fail(format!("first cancel failed: {e}"));
    }
    let (outcome, _events) = match drain_until_ended(&mut *session, task, scenarios.watchdog).await
    {
        Ok(v) => v,
        Err(detail) => return CheckResult::Fail(detail),
    };
    if outcome != TaskOutcome::Cancelled {
        return CheckResult::Fail(format!("expected Cancelled outcome, got {outcome:?}"));
    }
    match session.status().await {
        Ok(SessionStatus::Cancelled) => {}
        Ok(other) => return CheckResult::Fail(format!("expected status Cancelled, got {other:?}")),
        Err(e) => return CheckResult::Fail(format!("status() failed: {e}")),
    }
    if let Err(e) = session.cancel(mode).await {
        return CheckResult::Fail(format!("second cancel is not idempotent: {e}"));
    }
    CheckResult::Pass
}

/// #4a — graceful cancel of an active task.
pub async fn check_cancel_graceful<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    check_cancel(
        runtime,
        spec,
        scenarios,
        CancelMode::Graceful {
            grace: Duration::from_millis(200),
        },
    )
    .await
}

/// #4b — kill cancel of an active task.
pub async fn check_cancel_kill<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    check_cancel(runtime, spec, scenarios, CancelMode::Kill).await
}

/// #5 — a task that never terminates on its own, under a short
/// `timeout.per_task`, ends as `TimedOut` with no event afterward.
pub async fn check_timeout<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let mut short = spec.clone();
    short.timeout.per_task = Duration::from_millis(100);
    let mut session = match runtime.start(short).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task = match session.submit(scenarios.never_terminates.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    let (outcome, _events) = match drain_until_ended(&mut *session, task, scenarios.watchdog).await
    {
        Ok(v) => v,
        Err(detail) => return CheckResult::Fail(detail),
    };
    if outcome != TaskOutcome::TimedOut {
        return CheckResult::Fail(format!("expected TimedOut, got {outcome:?}"));
    }
    // No event should follow the terminal one.
    match tokio::time::timeout(Duration::from_millis(200), session.next_event()).await {
        Ok(Some(evt)) => CheckResult::Fail(format!("unexpected event after TimedOut: {evt:?}")),
        Ok(None) | Err(_) => CheckResult::Pass,
    }
}

/// #6 — a second `submit` while a task is active rejects or queues per
/// `supports.concurrent_sessions`; events of distinct tasks never intermix
/// out of order.
pub async fn check_queue_or_reject<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let supports_concurrent = runtime.descriptor().supports.concurrent_sessions;
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task_a = match session.submit(scenarios.happy_path.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("first submit failed: {e}")),
    };
    let second = session.submit(scenarios.happy_path.clone()).await;

    if !supports_concurrent {
        return match second {
            Err(_) => CheckResult::Pass,
            Ok(_) => CheckResult::Fail(
                "declared no concurrent_sessions support but accepted a second concurrent submit"
                    .to_string(),
            ),
        };
    }

    let task_b = match second {
        Ok(t) => t,
        Err(e) => {
            return CheckResult::Fail(format!(
                "declared concurrent_sessions=true but second submit was rejected: {e}"
            ))
        }
    };
    if task_b == task_a {
        return CheckResult::Fail(
            "second submit returned the same TaskId as the first".to_string(),
        );
    }

    let mut events = Vec::new();
    let (mut done_a, mut done_b) = (false, false);
    loop {
        match tokio::time::timeout(scenarios.watchdog, session.next_event()).await {
            Ok(Some(evt)) => {
                if let RuntimeEvent::Ended { task, outcome } = &evt {
                    if *task == task_a {
                        if *outcome != TaskOutcome::Success {
                            return CheckResult::Fail(format!("task_a ended with {outcome:?}"));
                        }
                        done_a = true;
                    }
                    if *task == task_b {
                        if *outcome != TaskOutcome::Success {
                            return CheckResult::Fail(format!("task_b ended with {outcome:?}"));
                        }
                        done_b = true;
                    }
                }
                events.push(evt);
                if done_a && done_b {
                    break;
                }
            }
            Ok(None) => {
                return CheckResult::Fail("event stream closed before both tasks ended".to_string())
            }
            Err(_) => {
                return CheckResult::Fail("timed out waiting for both tasks to end".to_string())
            }
        }
    }
    if let Err(detail) = validate_no_post_terminal_events(&events) {
        return CheckResult::Fail(detail);
    }
    CheckResult::Pass
}

/// #7 — `Ended` is unique per task; no event for a task follows its `Ended`;
/// verified across two sequential tasks in the same session.
pub async fn check_event_ordering_terminal<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task1 = match session.submit(scenarios.happy_path.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("first submit failed: {e}")),
    };
    let (outcome1, events1) =
        match drain_until_ended(&mut *session, task1, scenarios.watchdog).await {
            Ok(v) => v,
            Err(detail) => return CheckResult::Fail(detail),
        };
    if outcome1 != TaskOutcome::Success {
        return CheckResult::Fail(format!("expected task1 Success, got {outcome1:?}"));
    }
    if let Err(detail) = validate_no_post_terminal_events(&events1) {
        return CheckResult::Fail(detail);
    }

    let task2 = match session.submit(scenarios.happy_path.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("second submit failed: {e}")),
    };
    if task2 == task1 {
        return CheckResult::Fail("second task reused the first TaskId".to_string());
    }
    let (outcome2, events2) =
        match drain_until_ended(&mut *session, task2, scenarios.watchdog).await {
            Ok(v) => v,
            Err(detail) => return CheckResult::Fail(detail),
        };
    if outcome2 != TaskOutcome::Success {
        return CheckResult::Fail(format!("expected task2 Success, got {outcome2:?}"));
    }
    if let Err(detail) = validate_no_post_terminal_events(&events2) {
        return CheckResult::Fail(detail);
    }
    if events2.iter().any(|e| event_task(e) == Some(task1)) {
        return CheckResult::Fail("task1 event observed while draining task2".to_string());
    }

    match tokio::time::timeout(Duration::from_millis(200), session.next_event()).await {
        Ok(Some(evt)) => CheckResult::Fail(format!("unexpected event after final Ended: {evt:?}")),
        Ok(None) | Err(_) => CheckResult::Pass,
    }
}

/// #8 — an emitted artifact's digest is `sha256:<hex>` and matches the
/// referenced file's content in the session workspace.
pub async fn check_artifact_digest<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task = match session.submit(scenarios.produces_artifact.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    let (outcome, events) = match drain_until_ended(&mut *session, task, scenarios.watchdog).await {
        Ok(v) => v,
        Err(detail) => return CheckResult::Fail(detail),
    };
    if outcome != TaskOutcome::Success {
        return CheckResult::Fail(format!("expected Success, got {outcome:?}"));
    }
    let artifact = events.iter().find_map(|e| match e {
        RuntimeEvent::Artifact { task: t, artifact } if *t == task => Some(artifact.clone()),
        _ => None,
    });
    let artifact = match artifact {
        Some(a) => a,
        None => return CheckResult::Fail("no Artifact event observed before Ended".to_string()),
    };
    let hex = match artifact.digest.strip_prefix("sha256:") {
        Some(h) => h,
        None => {
            return CheckResult::Fail(format!(
                "digest missing 'sha256:' prefix: {}",
                artifact.digest
            ))
        }
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return CheckResult::Fail(format!("digest hex malformed: {hex}"));
    }
    let file_path = spec.workspace.root.join(&artifact.path);
    let bytes = match tokio::fs::read(&file_path).await {
        Ok(b) => b,
        Err(e) => {
            return CheckResult::Fail(format!("cannot read artifact file {file_path:?}: {e}"))
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let computed = format!("{:x}", hasher.finalize());
    if computed != hex {
        return CheckResult::Fail(format!("digest mismatch: event={hex} computed={computed}"));
    }
    CheckResult::Pass
}

/// #9a — `PermissionRequest` → `respond_permission(Allow)` → the guarded
/// action executes. Skipped when `policy_coverage.approvals ==
/// HarnessOwned` (no bridge exists to test).
pub async fn check_permission_bridge_allow<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    if runtime.descriptor().policy_coverage.approvals == ApprovalCoverage::HarnessOwned {
        return CheckResult::Skip(
            "policy_coverage.approvals == HarnessOwned: no approval bridge to test".to_string(),
        );
    }
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task = match session.submit(scenarios.requests_permission.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    let (req_id, pre_events) =
        match wait_for_permission_request(&mut *session, task, scenarios.watchdog).await {
            Ok(v) => v,
            Err(detail) => return CheckResult::Fail(detail),
        };
    if let Err(e) = session
        .respond_permission(req_id, PermissionDecision::Allow)
        .await
    {
        return CheckResult::Fail(format!("respond_permission(Allow) failed: {e}"));
    }
    let (outcome, events) = match drain_until_ended(&mut *session, task, scenarios.watchdog).await {
        Ok(v) => v,
        Err(detail) => return CheckResult::Fail(detail),
    };
    if outcome != TaskOutcome::Success {
        return CheckResult::Fail(format!("expected Success after Allow, got {outcome:?}"));
    }
    let mut all = pre_events;
    all.extend(events);
    if !guarded_action_executed(&all, task) {
        return CheckResult::Fail(
            "Allow decision but no Artifact/ToolResult observed as evidence of execution"
                .to_string(),
        );
    }
    CheckResult::Pass
}

/// #9b — `PermissionRequest` → `respond_permission(Deny{scope: Turn})` → the
/// guarded action does NOT execute. Uses [`DenyScope::Turn`], the product
/// default (Ciclo 2.2, `docs/SECURITY-INVARIANTS.md` §3) — the
/// outcome itself is not asserted (a `Turn` deny may end the task as
/// `Cancelled` rather than `Success`, which is the whole point of closing
/// the alternate-tool-routing gap), only that the guarded action never
/// executed. Skipped when `policy_coverage.approvals == HarnessOwned`.
pub async fn check_permission_bridge_deny<R: AgentRuntime>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    if runtime.descriptor().policy_coverage.approvals == ApprovalCoverage::HarnessOwned {
        return CheckResult::Skip(
            "policy_coverage.approvals == HarnessOwned: no approval bridge to test".to_string(),
        );
    }
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task = match session.submit(scenarios.requests_permission.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    let (req_id, pre_events) =
        match wait_for_permission_request(&mut *session, task, scenarios.watchdog).await {
            Ok(v) => v,
            Err(detail) => return CheckResult::Fail(detail),
        };
    if let Err(e) = session
        .respond_permission(
            req_id,
            PermissionDecision::Deny {
                scope: DenyScope::Turn,
            },
        )
        .await
    {
        return CheckResult::Fail(format!("respond_permission(Deny) failed: {e}"));
    }
    let (_outcome, events) = match drain_until_ended(&mut *session, task, scenarios.watchdog).await
    {
        Ok(v) => v,
        Err(detail) => return CheckResult::Fail(detail),
    };
    let mut all = pre_events;
    all.extend(events);
    if guarded_action_executed(&all, task) {
        return CheckResult::Fail(
            "Deny decision but the guarded action still executed".to_string(),
        );
    }
    CheckResult::Pass
}

/// #10 — crashing the harness mid-task surfaces a typed failure and
/// `status()==Crashed`; the Bastion-side runtime can still open a fresh
/// session afterward. Skipped when [`FaultInjection::induce_crash`] is
/// unsupported.
pub async fn check_crash_isolation<R: AgentRuntime + FaultInjection>(
    runtime: &R,
    spec: &SessionSpec,
    scenarios: &ConformanceScenarios,
) -> CheckResult {
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    let task = match session.submit(scenarios.never_terminates.clone()).await {
        Ok(t) => t,
        Err(e) => return CheckResult::Fail(format!("submit failed: {e}")),
    };
    // Make sure the task is actually underway before inducing the crash.
    match tokio::time::timeout(scenarios.watchdog, session.next_event()).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return CheckResult::Fail("event stream closed before crash induction".to_string())
        }
        Err(_) => {
            return CheckResult::Fail(
                "timed out waiting for the task to start before crash induction".to_string(),
            )
        }
    }
    if !runtime.induce_crash().await {
        let _ = session.cancel(CancelMode::Kill).await;
        return CheckResult::Skip("FaultInjection::induce_crash unsupported".to_string());
    }
    loop {
        match tokio::time::timeout(scenarios.watchdog, session.next_event()).await {
            Ok(Some(RuntimeEvent::Ended { task: t, outcome })) if t == task => {
                if !matches!(outcome, TaskOutcome::Failed { .. }) {
                    return CheckResult::Fail(format!(
                        "expected Failed outcome after crash, got {outcome:?}"
                    ));
                }
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break, // stream closed = session lost, acceptable per contract
            Err(_) => {
                return CheckResult::Fail("timed out waiting for crash to surface".to_string())
            }
        }
    }
    match session.status().await {
        Ok(SessionStatus::Crashed) => {}
        Err(RuntimeError::Crashed(_)) => {}
        Ok(other) => return CheckResult::Fail(format!("expected Crashed status, got {other:?}")),
        Err(other) => return CheckResult::Fail(format!("expected Crashed error, got {other}")),
    }
    match runtime.start(spec.clone()).await {
        Ok(_) => CheckResult::Pass,
        Err(e) => CheckResult::Fail(format!(
            "runtime could not open a new session after crash: {e}"
        )),
    }
}

/// #11 — an induced auth failure surfaces as `RuntimeError::Auth` whose
/// message never contains the credential. Skipped when
/// [`FaultInjection::induce_auth_failure`] is unsupported.
pub async fn check_auth_typed<R: AgentRuntime + FaultInjection>(
    runtime: &R,
    spec: &SessionSpec,
) -> CheckResult {
    if !runtime.induce_auth_failure().await {
        return CheckResult::Skip("FaultInjection::induce_auth_failure unsupported".to_string());
    }
    const SECRET: &str = "SECRET-MARKER-123";
    let mut bad_spec = spec.clone();
    bad_spec.auth = AuthProfileRef(SECRET.to_string());
    match runtime.start(bad_spec).await {
        Err(RuntimeError::Auth(msg)) => {
            if msg.contains(SECRET) {
                CheckResult::Fail("Auth error message leaked the credential marker".to_string())
            } else {
                CheckResult::Pass
            }
        }
        Err(other) => CheckResult::Fail(format!("expected Auth error, got {other}")),
        Ok(_) => CheckResult::Fail(
            "expected an auth failure but the session opened successfully".to_string(),
        ),
    }
}

/// #12 — a malformed/non-protocol frame on the transport is rejected as
/// `RuntimeError::Protocol`, never interpreted. Skipped when
/// [`FaultInjection::feed_garbage_frame`] is unsupported.
pub async fn check_protocol_garbage<R: AgentRuntime + FaultInjection>(
    runtime: &R,
    spec: &SessionSpec,
) -> CheckResult {
    let mut session = match runtime.start(spec.clone()).await {
        Ok(s) => s,
        Err(e) => return CheckResult::Fail(format!("start failed: {e}")),
    };
    if !runtime.feed_garbage_frame().await {
        return CheckResult::Skip("FaultInjection::feed_garbage_frame unsupported".to_string());
    }
    match session.status().await {
        Err(RuntimeError::Protocol(_)) => return CheckResult::Pass,
        Err(other) => return CheckResult::Fail(format!("expected Protocol error, got {other}")),
        Ok(_) => {}
    }
    let follow_up = TaskInput {
        prompt: "noop".to_string(),
        attachments: Vec::new(),
        expected: TaskExpectation::Conversation,
    };
    match session.submit(follow_up).await {
        Err(RuntimeError::Protocol(_)) => CheckResult::Pass,
        Err(other) => CheckResult::Fail(format!("expected Protocol error, got {other}")),
        Ok(_) => {
            CheckResult::Fail("garbage frame induced but no Protocol error surfaced".to_string())
        }
    }
}
