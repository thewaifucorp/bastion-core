//! Runs the real [`crate::conformance`] checks against a live ACP bridge
//! through [`bastion_agent_runtime::acp::AcpAgentRuntime`].
//!
//! Not a test: every check spawns a real bridge and spends real model tokens.
//! It exists so the adapter's claims are *measured* rather than asserted —
//! `permission_bridge_allow` / `permission_bridge_deny` in particular, which are
//! the entire reason the direct-ACP adapter exists.
//!
//! ```text
//! nice -n 19 cargo run -j 2 --example acp_conformance -- claude-agent-acp permission
//! nice -n 19 cargo run -j 2 --example acp_conformance -- claude-agent-acp all
//! ```
//!
//! Second argument selects the subset: `permission` (default) runs
//! happy-path + both permission-bridge checks; `all` runs the full sweep.

use bastion_agent_runtime::acp::AcpAgentRuntime;
use bastion_agent_runtime::conformance::{self, ConformanceScenarios};
use bastion_agent_runtime::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .unwrap_or_else(|| "claude-agent-acp".to_string());
    let subset = args.next().unwrap_or_else(|| "permission".to_string());

    let runtime = AcpAgentRuntime::new(&command);
    println!("== adapter: {:?}", runtime.descriptor().id);
    println!(
        "== declared approvals: {:?}",
        runtime.descriptor().policy_coverage.approvals
    );

    let health = runtime.health().await?;
    println!(
        "== health: ready={} {}",
        health.ready, health.detected_version
    );
    if !health.ready {
        println!("== bridge not ready: {:?}", health.detail);
        return Ok(());
    }

    let workdir = std::env::temp_dir().join(format!("acp-conformance-{}", std::process::id()));
    std::fs::create_dir_all(&workdir)?;
    println!("== workspace: {}", workdir.display());

    let spec = SessionSpec {
        owner: "conformance".to_string(),
        workspace: WorkspacePolicy {
            root: workdir.clone(),
            read_only: false,
            deny: Vec::new(),
        },
        sandbox: SandboxProfile::WorkspaceNet,
        permissions: PermissionProfile::default(),
        auth: AuthProfileRef("host".to_string()),
        runtime_id: command.clone(),
        timeout: TimeoutPolicy {
            per_task: Duration::from_secs(180),
            idle: Duration::from_secs(300),
        },
        env: EnvPolicy {
            allow: BTreeMap::new(),
        },
        mcp_bridge: None,
        otel: OtelContext::default(),
        model_hint: None,
    };

    let scenarios = ConformanceScenarios {
        happy_path: text_task("Reply with exactly the word: ready. Do not use any tools."),
        // Nothing terminates on its own here; a long sleep is the closest an
        // agent-driven scenario gets, and cancel/timeout cut it short.
        never_terminates: text_task(
            "Run a shell command that sleeps for 600 seconds, and wait for it.",
        ),
        requests_permission: text_task(
            "Create a file named guarded.txt in the current working directory \
             containing exactly the word: guarded. Create no other files.",
        ),
        produces_artifact: text_task(
            "Create a file named artifact.txt in the current working directory \
             containing exactly the word: artifact. Create no other files.",
        ),
        watchdog: Duration::from_secs(180),
    };

    let results = if subset == "all" {
        let mut results = conformance::run_all(&runtime, &spec, &scenarios).await;

        // `check_artifact_digest` expects its scenario to reach `Success`, but
        // it never answers permission requests. Under the deny-by-default
        // profile above, a bridge that gates writes therefore waits for a
        // decision nobody sends until the per-task watchdog fires — the adapter
        // behaving correctly, failing a check whose precondition the spec never
        // granted. `PermissionProfile` is where that precondition is expressed,
        // so the check is re-run with writes pre-authorized. The strict result
        // is kept alongside it, unedited: hiding it would hide the fact that a
        // gated write really does block.
        let mut permissive = spec.clone();
        permissive.permissions = PermissionProfile {
            allow: vec!["acp:write_file".to_string()],
        };
        let rerun = conformance::check_artifact_digest(&runtime, &permissive, &scenarios).await;
        for entry in results.iter_mut() {
            if entry.0 == "artifact_digest" {
                entry.0 = "artifact_digest (deny-by-default profile)";
            }
        }
        results.push(("artifact_digest (writes pre-authorized)", rerun));
        results
    } else {
        vec![
            (
                "happy_path",
                conformance::check_happy_path(&runtime, &spec, &scenarios).await,
            ),
            (
                "permission_bridge_allow",
                conformance::check_permission_bridge_allow(&runtime, &spec, &scenarios).await,
            ),
            (
                "permission_bridge_deny",
                conformance::check_permission_bridge_deny(&runtime, &spec, &scenarios).await,
            ),
        ]
    };

    println!("\n{}", conformance::format_report(&results));
    println!("workspace kept for inspection: {}", workdir.display());
    Ok(())
}

fn text_task(prompt: &str) -> TaskInput {
    TaskInput {
        prompt: prompt.to_string(),
        attachments: Vec::new(),
        expected: TaskExpectation::Conversation,
        model_hint: None,
    }
}

// Keeps `PathBuf` imported for the workspace root type without an unused warning
// on toolchains that infer it away.
#[allow(dead_code)]
fn _root_type_hint(p: PathBuf) -> PathBuf {
    p
}
