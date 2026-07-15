//! Live A-02 conformance run of [`bastion_agent_runtime::acpx::AcpxAgentRuntime`]
//! against a real, host-authenticated `opencode` agent via `acpx` (A-05
//! matrix cell: `opencode` via `acpx`).
//!
//! Not run by default (`cargo test`): it spawns real subprocesses and
//! depends on host state (`acpx`/`opencode` installed, `opencode auth login`
//! already done). Run manually:
//!
//! ```text
//! cargo test -p bastion-agent-runtime --test acpx_live_opencode -- --ignored --nocapture
//! ```
//!
//! # Result: unblocked (fix(c3): configurable `--auth-policy`)
//!
//! This cell used to be blocked by an *adapter*-level mismatch, not by
//! missing host auth: `opencode auth login` was already done on this host
//! (`opencode auth list` shows `OpenCode Go`/`OpenAI`/`OpenCode Zen`
//! credentials), and the underlying transport genuinely worked — a raw,
//! manual `acpx --format json --cwd <tmp> opencode prompt -s <name> "..."`
//! with `--auth-policy skip` (or no override, acpx's own CLI default)
//! completed a full turn using those credentials. But
//! [`AcpxAgentRuntime`] used to hardcode `--auth-policy fail` for every
//! wrapped agent. `opencode`'s native ACP server (`opencode acp`, invoked by
//! acpx as `npx -y opencode-ai acp`) advertises ACP `authMethods: [{"id":
//! "opencode-login", ...}]` on `initialize`; acpx tried to match that
//! against its **own** credential store (used for agents whose auth it can
//! broker directly), found nothing (opencode manages its own
//! `~/.local/share/opencode/auth.json`, a store acpx's matcher doesn't know
//! about), and with `--auth-policy fail` aborted the whole invocation before
//! `session/prompt` was ever sent. Full mechanism documented in
//! `docs/revamp/A-05-conformance-matrix.md` §2A.
//!
//! The fix (this cycle): `--auth-policy` is now a per-agent field on
//! [`AcpxAgentRuntime`] (see `src/acpx.rs` module docs and
//! `default_auth_policy_for`) — `"skip"` for `"opencode"`, `"fail"` (the
//! prior, unconditional behavior) for every other agent, including
//! `"claude"` (which is unaffected either way — it never advertises ACP
//! `authMethods` in the first place). No change to `--non-interactive-permissions`
//! or the permission-flag mapping: this is exclusively about which stored
//! credential set acpx is allowed to trust for the ACP handshake, not about
//! loosening what the wrapped agent may do without asking.
//!
//! The test below now runs the real, unmodified-by-this-file
//! `AcpxAgentRuntime::new("opencode")` (which picks up the new `"skip"`
//! default). Reproduced live (2026-07-14, `opencode 1.17.15`): **8 passed,
//! 5 skipped, 1 failed** — `happy_path` now genuinely `Pass`es (the whole
//! point of this fix), along with `resume`/`steer`/`cancel_graceful`/
//! `cancel_kill`/`timeout`/`queue_or_reject`/`event_ordering_terminal`; the
//! 5 skips are the same agent-independent
//! HarnessOwned/fault-injection-unimplemented set as the `claude` cell.
//!
//! `artifact_digest` still `Fail`s — but with a DIFFERENT, unrelated reason
//! (`"no Artifact event observed before Ended"`), not the auth-policy abort
//! this fix targeted. `FrameInterpreter`'s tool-call/artifact-candidate
//! joining (`src/acpx.rs`) was written against `claude`'s observed
//! `tool_call`/`tool_call_update` frame shape (`rawInput.file_path`, a
//! `content: [{"type":"diff", ...}]` array on the terminal `status:
//! "completed"` update); `opencode`'s ACP server apparently shapes the
//! equivalent frames differently, so no `Diff`/artifact-candidate ever gets
//! set for its file-write tool call. This is a genuine, newly-discovered
//! adapter-vs-wrapped-agent difference, NOT fixed here (this cycle's scope
//! was narrowly the `--auth-policy` mismatch) — recorded as its own finding
//! in `docs/revamp/A-05-conformance-matrix.md` §2A for a future cycle.
//!
//! # Cost note
//!
//! Small/cheap prompts by design (A-01 §"parsimony"): a handful of few-token
//! turns, using whatever model acpx/opencode picks by default (never an
//! explicit expensive-model override).

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
        auth: AuthProfileRef("host-opencode-login".to_string()),
        runtime_id: "opencode".to_string(),
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
        // Same rationale as the claude live suite (A-05 §5.1): a live
        // cloud-backed harness makes 14 genuine cold `start()` calls in one
        // `run_all` sweep; 5s is too tight for real handshake/network
        // latency.
        watchdog: Duration::from_secs(30),
    }
}

#[tokio::test]
#[ignore = "spawns real acpx+opencode subprocesses; run manually with --ignored"]
async fn acpx_opencode_conformance_live() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let spec = make_spec(workspace.path().to_path_buf());
    let scenarios = make_scenarios();
    let runtime = AcpxAgentRuntime::new("opencode").expect("acpx on PATH");

    let health = runtime.health().await.expect("health probe");
    eprintln!("health: {health:?}");
    assert!(health.ready, "acpx not ready: {health:?}");

    let results = conformance::run_all(&runtime, &spec, &scenarios).await;
    let report = conformance::format_report(&results);
    eprintln!("{report}");

    // Real conformance now (A-05 §2A unblocked by the `--auth-policy` fix),
    // not a documented-block regression lock. `happy_path` is the direct
    // proof this fix targeted: it MUST Pass now. `artifact_digest` is a
    // separate, pre-existing gap in how `FrameInterpreter` joins opencode's
    // tool-call frames (module docs) — asserted explicitly as the one known
    // Fail, not swept into a blanket "no Fail" check that would either mask
    // a real regression or force a dishonest Pass.
    let result_for = |name: &str| {
        results
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| panic!("{name} present in run_all output"))
    };

    let must_pass = [
        "happy_path",
        "resume",
        "steer",
        "cancel_graceful",
        "cancel_kill",
        "timeout",
        "queue_or_reject",
        "event_ordering_terminal",
    ];
    for name in must_pass {
        let result = result_for(name);
        assert!(
            result.is_pass(),
            "{name}: expected Pass now that --auth-policy is configurable per-agent \
             (A-05 §2A fix) -- got: {result:?}\nfull report:\n{report}"
        );
    }

    // Known, separate gap (module docs) — documented here so a future fix
    // (or an unexpected regression to a DIFFERENT failure mode) is caught
    // loudly instead of silently re-labeled.
    let artifact_digest = result_for("artifact_digest");
    assert!(
        artifact_digest.is_fail(),
        "artifact_digest: expected the known, documented Fail (opencode's tool-call frame \
         shape isn't joined by FrameInterpreter the way claude's is) -- if this now Passes, \
         the gap has closed and this assertion (and the module docs) should be updated to \
         Pass instead -- got: {artifact_digest:?}"
    );

    for name in [
        "permission_bridge_allow",
        "permission_bridge_deny",
        "crash_isolation",
        "auth_typed",
        "protocol_garbage",
    ] {
        let result = result_for(name);
        assert!(
            result.is_skip(),
            "{name}: expected Skip (agent-independent, HarnessOwned/fault-injection \
             unimplemented, same as the claude cell) -- got: {result:?}"
        );
    }
}
