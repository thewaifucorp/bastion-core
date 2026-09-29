//! `ClaudeCodeRuntime` against a scripted stand-in for the `claude` binary
//! (`fixtures/fake_claude.py`): the full conformance suite, the permission
//! bridge with the proposed diff, the environment and command line the binary
//! receives, resume, and the failure paths. Needs `python3` on PATH; skipped
//! without it. Unix only: the fixture is started through its `#!` line.
#![cfg(unix)]

use bastion_agent_runtime::claude_code::ClaudeCodeRuntime;
use bastion_agent_runtime::conformance::{self, ConformanceScenarios};
use bastion_agent_runtime::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn python_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_claude.py")
}

fn runtime() -> ClaudeCodeRuntime {
    ClaudeCodeRuntime::with_binary(fixture())
}

fn spec(root: &Path, env: BTreeMap<String, String>, bridge: Option<McpBridgeSpec>) -> SessionSpec {
    SessionSpec {
        owner: "fake-claude-test".to_string(),
        workspace: WorkspacePolicy {
            root: root.to_path_buf(),
            read_only: false,
            deny: Vec::new(),
        },
        sandbox: SandboxProfile::WorkspaceNet,
        permissions: PermissionProfile::default(),
        auth: AuthProfileRef("claude-subscription".to_string()),
        runtime_id: "claude".to_string(),
        timeout: TimeoutPolicy {
            per_task: Duration::from_secs(30),
            idle: Duration::from_secs(60),
        },
        env: EnvPolicy { allow: env },
        mcp_bridge: bridge,
        otel: OtelContext::default(),
        model_hint: None,
    }
}

fn logged_env(log: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([(
        "FAKE_CLAUDE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    )])
}

fn input(prompt: &str) -> TaskInput {
    TaskInput {
        prompt: prompt.to_string(),
        attachments: Vec::new(),
        expected: TaskExpectation::Conversation,
        model_hint: None,
    }
}

fn log_entries(log: &Path) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn log_field(log: &Path, key: &str) -> Vec<Value> {
    log_entries(log)
        .into_iter()
        .filter_map(|e| e.get(key).cloned())
        .collect()
}

async fn next(session: &mut Box<dyn RuntimeSession>) -> RuntimeEvent {
    tokio::time::timeout(Duration::from_secs(15), session.next_event())
        .await
        .expect("event within 15s")
        .expect("stream open")
}

/// Events of `task` until its `Ended`, answering the first permission request
/// with `decision`.
async fn run(
    session: &mut Box<dyn RuntimeSession>,
    task: TaskId,
    decision: PermissionDecision,
) -> (TaskOutcome, Vec<RuntimeEvent>) {
    let mut seen = Vec::new();
    loop {
        let event = next(session).await;
        if let RuntimeEvent::PermissionRequest { id, .. } = &event {
            session.respond_permission(*id, decision).await.unwrap();
        }
        if let RuntimeEvent::Ended { task: t, outcome } = &event {
            if *t == task {
                let outcome = outcome.clone();
                seen.push(event);
                return (outcome, seen);
            }
        }
        seen.push(event);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_the_conformance_suite() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let scenarios = ConformanceScenarios {
        happy_path: input("say ok"),
        never_terminates: input("NEVER stop"),
        requests_permission: input("PERMISSION please"),
        produces_artifact: input("ARTIFACT now"),
        watchdog: Duration::from_secs(15),
    };
    let results = conformance::run_all(
        &runtime(),
        &spec(dir.path(), BTreeMap::new(), None),
        &scenarios,
    )
    .await;
    let report = conformance::format_report(&results);
    assert!(
        results.iter().all(|(_, r)| !r.is_fail()),
        "conformance failures:\n{report}"
    );
    for check in [
        "happy_path",
        "resume",
        "cancel_graceful",
        "cancel_kill",
        "timeout",
        "artifact_digest",
        "permission_bridge_allow",
        "permission_bridge_deny",
    ] {
        let (_, result) = results.iter().find(|(name, _)| *name == check).unwrap();
        assert!(result.is_pass(), "{check} did not pass:\n{report}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn health_reads_the_installed_version() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let health = runtime().health().await.unwrap();
    assert!(health.ready, "{:?}", health.detail);
    assert_eq!(health.detected_version, "2.1.284");

    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("claude");
    std::fs::write(&old, "#!/bin/sh\necho '1.0.3 (Claude Code)'\n").unwrap();
    let health = ClaudeCodeRuntime::with_binary(old).health().await.unwrap();
    assert!(!health.ready);
    assert!(health.detail.unwrap().contains("outside supported range"));
}

/// The request carries the diff; allowing it answers `allow` with the
/// unchanged input, and the write then shows up as a diff and an artifact.
#[tokio::test(flavor = "multi_thread")]
async fn an_edit_asks_with_its_diff_and_allow_lets_it_through() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let mut session = runtime()
        .start(spec(dir.path(), logged_env(&log), None))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut session).await,
        RuntimeEvent::Started { .. }
    ));

    let task = session.submit(input("EDIT the file")).await.unwrap();
    let (outcome, events) = run(&mut session, task, PermissionDecision::Allow).await;
    assert_eq!(outcome, TaskOutcome::Success);

    let (action, detail, edits) = events
        .iter()
        .find_map(|e| match e {
            RuntimeEvent::PermissionRequest {
                action,
                detail,
                edits,
                ..
            } => Some((action.clone(), detail.clone(), edits.clone())),
            _ => None,
        })
        .expect("a permission request");
    assert!(matches!(action, PermissionAction::WriteFile));
    assert!(detail.starts_with("Edit: "), "{detail}");
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].path, PathBuf::from("e.txt"));
    assert_eq!(edits[0].old_text.as_deref(), Some("a\n"));
    assert_eq!(edits[0].new_text, "b\nc\n");

    assert!(events.iter().any(|e| matches!(e,
        RuntimeEvent::Diff { path, added: 2, removed: 1, .. } if path == Path::new("e.txt"))));
    assert!(events.iter().any(|e| matches!(e,
        RuntimeEvent::Artifact { artifact, .. } if artifact.path == Path::new("e.txt"))));
    assert!(events
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Thinking { .. })));
    assert!(
        events.iter().any(|e| matches!(e,
        RuntimeEvent::Usage { delta, .. } if delta.input_tokens == 18 && delta.output_tokens == 2))
    );

    let answers = log_field(&log, "permission_answer");
    assert_eq!(answers[0]["response"]["behavior"], "allow");
    assert_eq!(
        answers[0]["response"]["updatedInput"]["new_string"],
        "b\nc\n"
    );
}

/// A turn-scoped denial interrupts the turn, which ends `Cancelled`; the file
/// is never written and the same session takes the next message.
#[tokio::test(flavor = "multi_thread")]
async fn a_turn_denial_stops_the_turn_and_keeps_the_session() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let mut session = runtime()
        .start(spec(dir.path(), logged_env(&log), None))
        .await
        .unwrap();

    let task = session.submit(input("PERMISSION to write")).await.unwrap();
    let (outcome, events) = run(
        &mut session,
        task,
        PermissionDecision::Deny {
            scope: DenyScope::Turn,
        },
    )
    .await;
    assert_eq!(outcome, TaskOutcome::Cancelled);
    assert!(!dir.path().join("perm.txt").exists());
    assert!(!events.iter().any(|e| matches!(
        e,
        RuntimeEvent::ToolResult {
            is_error: false,
            ..
        }
    )));
    let answers = log_field(&log, "permission_answer");
    assert_eq!(answers[0]["response"]["behavior"], "deny");
    assert_eq!(answers[0]["response"]["interrupt"], true);

    assert_eq!(session.status().await.unwrap(), SessionStatus::Idle);
    let task = session.submit(input("hello again")).await.unwrap();
    let (outcome, _) = run(&mut session, task, PermissionDecision::Allow).await;
    assert_eq!(outcome, TaskOutcome::Success);
}

/// An instance-scoped denial lets the turn go on.
#[tokio::test(flavor = "multi_thread")]
async fn an_instance_denial_lets_the_turn_continue() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let mut session = runtime()
        .start(spec(dir.path(), logged_env(&log), None))
        .await
        .unwrap();
    let task = session.submit(input("PERMISSION to write")).await.unwrap();
    let (outcome, _) = run(
        &mut session,
        task,
        PermissionDecision::Deny {
            scope: DenyScope::Instance,
        },
    )
    .await;
    assert_eq!(outcome, TaskOutcome::Success);
    assert_eq!(
        log_field(&log, "permission_answer")[0]["response"]["interrupt"],
        false
    );
}

/// The binary runs under its own login only: no Anthropic credential or
/// endpoint from the allowlist reaches it, auto memory is off, and its
/// command line asks the host for permissions and loads none of the
/// operator's settings.
#[tokio::test(flavor = "multi_thread")]
async fn the_binary_gets_no_credential_and_a_governed_command_line() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let mut env = logged_env(&log);
    env.insert(
        "HOME".to_string(),
        dir.path().to_string_lossy().into_owned(),
    );
    for secret in [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ] {
        env.insert(secret.to_string(), "must-not-leak".to_string());
    }
    let mut session = runtime().start(spec(dir.path(), env, None)).await.unwrap();
    let task = session.submit(input("say ok")).await.unwrap();
    let (outcome, _) = run(&mut session, task, PermissionDecision::Allow).await;
    assert_eq!(outcome, TaskOutcome::Success);

    let names: Vec<String> = serde_json::from_value(log_field(&log, "env")[0].clone()).unwrap();
    assert!(names.contains(&"HOME".to_string()));
    assert!(names.contains(&"CLAUDE_CODE_DISABLE_AUTO_MEMORY".to_string()));
    for secret in [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ] {
        assert!(!names.contains(&secret.to_string()), "{secret} leaked");
    }

    let argv: Vec<String> = serde_json::from_value(log_field(&log, "argv")[0].clone()).unwrap();
    let joined = argv.join(" ");
    assert!(joined.contains("--input-format stream-json"));
    assert!(joined.contains("--output-format stream-json"));
    assert!(joined.contains("--permission-prompt-tool stdio"));
    assert!(joined.contains("--permission-mode default"));
    assert!(joined.contains("--strict-mcp-config"));
    assert!(joined.contains("--session-id "));
    let pos = argv.iter().position(|a| a == "--setting-sources").unwrap();
    assert_eq!(argv[pos + 1], "");
    assert!(!argv.iter().any(|a| a == "--bare"));
    assert!(!argv.iter().any(|a| a.contains("dangerously")));

    let handle = session.handle();
    assert_eq!(handle.runtime_id, "claude");
    assert_eq!(handle.owner, "fake-claude-test");
}

/// The bridged MCP servers reach the binary through a private config file,
/// never the command line, and are pre-allowed; the file goes with the
/// session.
#[tokio::test(flavor = "multi_thread")]
async fn the_mcp_bridge_is_handed_over_in_a_private_file() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let bridge = McpBridgeSpec {
        servers: vec![McpServerEndpoint::Http {
            name: "bastion".to_string(),
            url: "http://127.0.0.1:4455/mcp".to_string(),
            headers: BTreeMap::from([("x-bastion-token".to_string(), "t0k".to_string())]),
        }],
    };
    let mut session = runtime()
        .start(spec(dir.path(), logged_env(&log), Some(bridge)))
        .await
        .unwrap();
    let task = session.submit(input("say ok")).await.unwrap();
    run(&mut session, task, PermissionDecision::Allow).await;

    let mcp = &log_field(&log, "mcp")[0];
    assert_eq!(mcp["mcpServers"]["bastion"]["type"], "http");
    assert_eq!(
        mcp["mcpServers"]["bastion"]["headers"]["x-bastion-token"],
        "t0k"
    );
    assert_eq!(log_field(&log, "mcp_mode")[0], "0o600");

    let argv: Vec<String> = serde_json::from_value(log_field(&log, "argv")[0].clone()).unwrap();
    assert!(!argv.iter().any(|a| a.contains("t0k")), "token on argv");
    let pos = argv.iter().position(|a| a == "--allowedTools").unwrap();
    assert_eq!(argv[pos + 1], "mcp__bastion");
    let config = PathBuf::from(&argv[argv.iter().position(|a| a == "--mcp-config").unwrap() + 1]);
    assert!(config.starts_with(dir.path()));
    assert!(config.exists());

    drop(session);
    assert!(!config.exists(), "config file outlived the session");
}

/// A persisted handle reattaches the same conversation (with the bridge
/// again); one Claude Code does not know is `NotResumable`, not a session
/// that fails later.
#[tokio::test(flavor = "multi_thread")]
async fn resume_reattaches_the_same_conversation_or_says_it_cannot() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let mut session = runtime()
        .start(spec(dir.path(), logged_env(&log), None))
        .await
        .unwrap();
    let task = session.submit(input("say ok")).await.unwrap();
    run(&mut session, task, PermissionDecision::Allow).await;
    let handle = session.handle();
    drop(session);

    let bridge = McpBridgeSpec {
        servers: vec![McpServerEndpoint::Http {
            name: "bastion".to_string(),
            url: "http://127.0.0.1:4455/mcp".to_string(),
            headers: BTreeMap::new(),
        }],
    };
    let resume_spec = ResumeSpec {
        timeout: TimeoutPolicy {
            per_task: Duration::from_secs(30),
            idle: Duration::from_secs(60),
        },
        permissions: PermissionProfile::default(),
        env: EnvPolicy {
            allow: logged_env(&log),
        },
        mcp_bridge: Some(bridge),
    };
    let mut resumed = runtime()
        .resume(&handle, resume_spec.clone())
        .await
        .unwrap();
    assert_eq!(resumed.handle(), handle);
    let task = resumed.submit(input("say ok")).await.unwrap();
    let (outcome, _) = run(&mut resumed, task, PermissionDecision::Allow).await;
    assert_eq!(outcome, TaskOutcome::Success);

    let argvs: Vec<Vec<String>> = log_field(&log, "argv")
        .into_iter()
        .map(|a| serde_json::from_value(a).unwrap())
        .collect();
    let second = argvs.last().unwrap();
    let pos = second.iter().position(|a| a == "--resume").unwrap();
    let first = &argvs[0];
    let created = &first[first.iter().position(|a| a == "--session-id").unwrap() + 1];
    assert_eq!(&second[pos + 1], created);
    assert!(second.iter().any(|a| a == "--mcp-config"));

    let unknown_ref = handle
        .external_ref
        .replace(created.as_str(), "0b0e2a4c-1111-4222-8333-944455556666");
    let unknown = SessionHandle {
        external_ref: unknown_ref,
        ..handle.clone()
    };
    let err = runtime()
        .resume(&unknown, resume_spec.clone())
        .await
        .err()
        .expect("unknown conversation");
    assert!(matches!(err, RuntimeError::NotResumable(_)), "{err}");

    let foreign = SessionHandle {
        runtime_id: "acp_claude".to_string(),
        ..handle.clone()
    };
    assert!(matches!(
        runtime().resume(&foreign, resume_spec.clone()).await.err(),
        Some(RuntimeError::NotResumable(_))
    ));
    let garbage = SessionHandle {
        external_ref: "thread-1".to_string(),
        ..handle
    };
    assert!(matches!(
        runtime().resume(&garbage, resume_spec).await.err(),
        Some(RuntimeError::NotResumable(_))
    ));
}

/// A control request the adapter does not implement is answered with an
/// error, not left hanging, and the turn goes on.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsupported_control_request_is_refused() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.jsonl");
    let mut session = runtime()
        .start(spec(dir.path(), logged_env(&log), None))
        .await
        .unwrap();
    let task = session.submit(input("CONTROL then ok")).await.unwrap();
    let (outcome, _) = run(&mut session, task, PermissionDecision::Allow).await;
    assert_eq!(outcome, TaskOutcome::Success);
    let answer = &log_field(&log, "control_answer")[0];
    assert_eq!(answer["subtype"], "error");
    assert_eq!(answer["request_id"], "hook-1");
}

/// Human text on stdout fails the session closed; so does the binary dying
/// mid-turn.
#[tokio::test(flavor = "multi_thread")]
async fn garbage_or_a_crash_fails_the_task_and_the_session() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    for prompt in ["GARBAGE please", "CRASH now"] {
        let dir = tempfile::tempdir().unwrap();
        let mut session = runtime()
            .start(spec(dir.path(), BTreeMap::new(), None))
            .await
            .unwrap();
        let task = session.submit(input(prompt)).await.unwrap();
        let (outcome, _) = run(&mut session, task, PermissionDecision::Allow).await;
        assert!(
            matches!(outcome, TaskOutcome::Failed { .. }),
            "{prompt}: {outcome:?}"
        );
        assert_eq!(session.status().await.unwrap(), SessionStatus::Crashed);
        assert!(session.submit(input("again")).await.is_err());
    }
}

/// A person deciding for longer than the task budget does not time the task
/// out: the watchdog only counts the time the binary is working.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_decision_does_not_count_against_the_task_timeout() {
    if !python_available() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut short = spec(dir.path(), BTreeMap::new(), None);
    short.timeout.per_task = Duration::from_secs(1);
    let mut session = runtime().start(short).await.unwrap();
    let task = session.submit(input("PERMISSION slowly")).await.unwrap();
    loop {
        match next(&mut session).await {
            RuntimeEvent::PermissionRequest { id, .. } => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                session
                    .respond_permission(id, PermissionDecision::Allow)
                    .await
                    .unwrap();
            }
            RuntimeEvent::Ended { task: t, outcome } if t == task => {
                assert_eq!(outcome, TaskOutcome::Success);
                break;
            }
            _ => {}
        }
    }
}
