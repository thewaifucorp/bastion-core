//! Live A-02 conformance run of [`bastion_agent_runtime::acpx::AcpxAgentRuntime`]
//! against a real, host-authenticated `claude` agent via `acpx`.
//!
//! Not run by default (`cargo test`): it spawns real subprocesses, costs
//! real tokens, and depends on host state (`acpx`/`claude` installed,
//! `claude` already authenticated). Run manually:
//!
//! ```text
//! cargo test -p bastion-agent-runtime --test acpx_live_claude -- --ignored --nocapture
//! ```
//!
//! Small/cheap prompts by design (A-01 §"parsimony"): a handful of few-token
//! turns, never a paid/expensive model choice beyond acpx's default.

use bastion_agent_runtime::acpx::AcpxAgentRuntime;
use bastion_agent_runtime::conformance::{self, ConformanceScenarios};
use bastion_agent_runtime::*;
use std::collections::BTreeMap;
use std::time::Duration;

fn make_spec(workspace_root: std::path::PathBuf) -> SessionSpec {
    let mut allow = BTreeMap::new();
    if let Ok(home) = std::env::var("HOME") {
        allow.insert("HOME".to_string(), home);
    }
    if let Ok(path) = std::env::var("PATH") {
        allow.insert("PATH".to_string(), path);
    }
    SessionSpec {
        owner: "acpx-live-test".to_string(),
        workspace: WorkspacePolicy {
            root: workspace_root,
            read_only: false,
            deny: Vec::new(),
        },
        sandbox: SandboxProfile::WorkspaceNet,
        permissions: PermissionProfile {
            allow: vec!["*".to_string()],
        },
        auth: AuthProfileRef("host-claude-login".to_string()),
        runtime_id: "claude".to_string(),
        timeout: TimeoutPolicy {
            per_task: Duration::from_secs(60),
            idle: Duration::from_secs(120),
        },
        env: EnvPolicy { allow },
        mcp_bridge: None,
        otel: OtelContext::default(),
    }
}

fn make_scenarios() -> ConformanceScenarios {
    ConformanceScenarios {
        happy_path: TaskInput {
            prompt: "Reply with exactly: ok".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::Conversation,
        },
        never_terminates: TaskInput {
            prompt: "Count slowly from 1 to 1000000, one number per line, in words, no code."
                .to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::Conversation,
        },
        requests_permission: TaskInput {
            prompt: "create file permission_probe.txt with content probe".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::CodeChange,
        },
        produces_artifact: TaskInput {
            prompt: "create file hello.txt with content hi".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::CodeChange,
        },
        // Ciclo 2.2 (A-05 §5.1): a live cloud-backed harness makes 14
        // genuine cold `start()` calls in one `run_all` sweep; the embedded
        // fake's 5s default is too tight for real handshake/network
        // latency, which is what actually caused the spurious watchdog
        // timeouts noted in A-05 §5.1.
        watchdog: Duration::from_secs(30),
    }
}

#[tokio::test]
#[ignore = "spawns real acpx+claude subprocesses; run manually with --ignored"]
async fn acpx_claude_conformance_live() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let spec = make_spec(workspace.path().to_path_buf());
    let scenarios = make_scenarios();
    let runtime = AcpxAgentRuntime::new("claude").expect("acpx on PATH");

    let health = runtime.health().await.expect("health probe");
    eprintln!("health: {health:?}");
    assert!(health.ready, "acpx not ready: {health:?}");

    let results = conformance::run_all(&runtime, &spec, &scenarios).await;
    let report = conformance::format_report(&results);
    eprintln!("{report}");

    let failed: Vec<_> = results.iter().filter(|(_, r)| r.is_fail()).collect();
    assert!(failed.is_empty(), "conformance failures:\n{report}");
}

/// Minimal live happy-path check. The full conformance sweep remains in
/// `acpx_claude_conformance_live` above.
#[tokio::test]
#[ignore = "spawns real acpx+claude subprocesses; run manually with --ignored"]
async fn acpx_happy_path_smoke() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let spec = make_spec(workspace.path().to_path_buf());
    let runtime = AcpxAgentRuntime::new("claude").expect("acpx on PATH");

    let health = runtime.health().await.expect("health probe");
    eprintln!("health: {health:?}");
    assert!(health.ready, "acpx not ready: {health:?}");

    let tiny_scenarios = ConformanceScenarios {
        happy_path: TaskInput {
            prompt: "Reply with exactly: ok".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::Conversation,
        },
        never_terminates: TaskInput {
            prompt: "noop".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::Conversation,
        },
        requests_permission: TaskInput {
            prompt: "noop".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::Conversation,
        },
        produces_artifact: TaskInput {
            prompt: "noop".to_string(),
            attachments: Vec::new(),
            expected: TaskExpectation::Conversation,
        },
        watchdog: Duration::from_secs(30),
    };

    let result = conformance::check_happy_path(&runtime, &spec, &tiny_scenarios).await;
    eprintln!("happy_path: {result:?}");
    assert!(result.is_pass(), "happy_path: {result:?}");
}
