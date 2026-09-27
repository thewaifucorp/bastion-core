//! `AcpAgentRuntime` against a scripted ACP agent (`fixtures/fake_acp_agent.py`):
//! the MCP bridge reaches `session/new` as `mcpServers`, a permission request
//! is answered by the caller's decision, and the per-task watchdog does not
//! fire while that decision is pending. Needs `python3` on PATH; skipped
//! without it.

use bastion_agent_runtime::acp::AcpAgentRuntime;
use bastion_agent_runtime::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

fn python() -> Option<&'static str> {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "python3")
}

fn spec(root: &Path, per_task: Duration, bridge: Option<McpBridgeSpec>) -> SessionSpec {
    SessionSpec {
        owner: "fake-acp-test".to_string(),
        workspace: WorkspacePolicy {
            root: root.to_path_buf(),
            read_only: false,
            deny: Vec::new(),
        },
        sandbox: SandboxProfile::WorkspaceNet,
        permissions: PermissionProfile::default(),
        auth: AuthProfileRef("none".to_string()),
        runtime_id: "fake".to_string(),
        timeout: TimeoutPolicy {
            per_task,
            idle: Duration::from_secs(60),
        },
        env: EnvPolicy::default(),
        mcp_bridge: bridge,
        otel: OtelContext::default(),
        model_hint: None,
    }
}

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_acp_agent.py")
}

fn runtime(python: &str, log: &Path) -> AcpAgentRuntime {
    runtime_for(python, &fixture(), log)
}

fn runtime_for(python: &str, script: &Path, log: &Path) -> AcpAgentRuntime {
    AcpAgentRuntime::new(format!(
        "{python} '{}' '{}'",
        script.display(),
        log.display()
    ))
}

fn prompt() -> TaskInput {
    TaskInput {
        prompt: "write the file".to_string(),
        attachments: Vec::new(),
        expected: TaskExpectation::Conversation,
        model_hint: None,
    }
}

/// Drives one task: answers its permission request with `decision` after
/// `think`, and returns (assistant text, outcome, edits seen on the request).
async fn drive(
    session: &mut Box<dyn RuntimeSession>,
    decision: PermissionDecision,
    think: Duration,
) -> (String, TaskOutcome, Vec<ProposedEdit>) {
    let task = session.submit(prompt()).await.unwrap();
    let mut text = String::new();
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(30), session.next_event())
            .await
            .expect("event within 30s")
            .expect("stream open");
        match event {
            RuntimeEvent::PermissionRequest { id, edits, .. } => {
                seen = edits;
                tokio::time::sleep(think).await;
                session.respond_permission(id, decision).await.unwrap();
            }
            RuntimeEvent::MessageDelta {
                task: t,
                text: delta,
            } if t == task => text.push_str(&delta),
            RuntimeEvent::Ended { task: t, outcome } if t == task => return (text, outcome, seen),
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_bridge_reaches_session_new_as_mcp_servers() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.json");
    let bridge = McpBridgeSpec {
        servers: vec![
            McpServerEndpoint::Http {
                name: "bastion".to_string(),
                url: "http://127.0.0.1:4455/mcp".to_string(),
                headers: BTreeMap::from([("x-bastion-token".to_string(), "t0k".to_string())]),
            },
            McpServerEndpoint::Stdio {
                name: "local".to_string(),
                command: "/usr/bin/true".into(),
                args: vec!["--flag".to_string()],
                env: BTreeMap::from([("K".to_string(), "V".to_string())]),
            },
        ],
    };

    let session = runtime(python, &log)
        .start(spec(dir.path(), Duration::from_secs(30), Some(bridge)))
        .await
        .unwrap();
    drop(session);

    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert_eq!(
        record["mcpServers"],
        serde_json::json!([
            {
                "type": "http",
                "name": "bastion",
                "url": "http://127.0.0.1:4455/mcp",
                "headers": [{"name": "x-bastion-token", "value": "t0k"}]
            },
            {
                "name": "local",
                "command": "/usr/bin/true",
                "args": ["--flag"],
                "env": [{"name": "K", "value": "V"}]
            }
        ])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_decision_does_not_count_against_the_task_timeout() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.json");
    let mut session = runtime(python, &log)
        .start(spec(dir.path(), Duration::from_secs(1), None))
        .await
        .unwrap();

    // The person takes three times the task budget to decide.
    let (text, outcome, edits) = drive(
        &mut session,
        PermissionDecision::Allow,
        Duration::from_secs(3),
    )
    .await;

    assert_eq!(outcome, TaskOutcome::Success);
    assert_eq!(text, "selected:allow");
    assert_eq!(edits.len(), 1, "the diff travels with the request");
    assert_eq!(edits[0].new_text, "hello\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denial_selects_the_reject_option() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.json");
    let mut session = runtime(python, &log)
        .start(spec(dir.path(), Duration::from_secs(30), None))
        .await
        .unwrap();

    let (text, _outcome, _) = drive(
        &mut session,
        PermissionDecision::Deny {
            scope: DenyScope::Instance,
        },
        Duration::ZERO,
    )
    .await;
    assert_eq!(text, "selected:reject");
}

/// The Claude Code bridge gets a session Bastion governs: none of the
/// operator's Claude Code settings or MCP servers, no auto memory, the mode
/// that asks before editing even when the bridge starts in another, and only
/// Bastion's own bridged server pre-allowed.
#[tokio::test(flavor = "multi_thread")]
async fn a_claude_bridge_session_is_isolated_and_asks() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.json");
    // The adapter recognizes the agent family from the command line.
    let script = dir.path().join("claude-agent-acp-fake.py");
    std::fs::copy(fixture(), &script).unwrap();

    let bridge = McpBridgeSpec {
        servers: vec![McpServerEndpoint::Http {
            name: "bastion".to_string(),
            url: "http://127.0.0.1:1/mcp".to_string(),
            headers: BTreeMap::new(),
        }],
    };
    let session = runtime_for(python, &script, &log)
        .start(spec(dir.path(), Duration::from_secs(30), Some(bridge)))
        .await
        .unwrap();
    assert_eq!(session.handle().runtime_id, "acp_claude");
    drop(session);

    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert_eq!(
        record["meta"],
        serde_json::json!({"claudeCode": {"options": {
            "settingSources": [],
            "strictMcpConfig": true,
            "allowedTools": ["mcp__bastion"]
        }}})
    );
    assert_eq!(record["autoMemoryOff"], "1");
    assert_eq!(record["setMode"], "default");
}

/// Any other bridge is left as configured.
#[tokio::test(flavor = "multi_thread")]
async fn other_bridges_get_no_claude_options() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log.json");
    let session = runtime(python, &log)
        .start(spec(dir.path(), Duration::from_secs(30), None))
        .await
        .unwrap();
    drop(session);
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(record["meta"].is_null());
    assert!(record["autoMemoryOff"].is_null());
    assert!(record.get("setMode").is_none());
}
