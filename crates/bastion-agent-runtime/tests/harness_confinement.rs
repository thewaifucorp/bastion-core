//! A confined harness sees its workspace and granted state, nothing of the
//! operator's home, and only the session's environment.
//!
//! `harness = false`: this binary is also the sandbox helper, forwarding
//! `__bastion-sandbox` to `bastion_sandbox::helper_main` before anything else
//! — the same few lines a host's `main` carries. Skipped without an OS
//! backend unless `BASTION_SANDBOX_TESTS_REQUIRED=1`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use bastion_agent_runtime::{HarnessConfinement, HarnessLaunch, SandboxProfile, WorkspacePolicy};
use bastion_sandbox::{Sandbox, HELPER_MARKER};

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(OsStr::new(HELPER_MARKER)) {
        bastion_sandbox::helper_main(std::env::args_os().skip(1));
    }
    let helper = std::env::current_exe().expect("test binary path");
    let sandbox = match Sandbox::detect(&helper) {
        Ok(sandbox) => sandbox,
        Err(e) if std::env::var("BASTION_SANDBOX_TESTS_REQUIRED").as_deref() == Ok("1") => {
            panic!("sandbox backend required but unavailable: {e}")
        }
        Err(e) => {
            eprintln!("skipping harness confinement tests: {e}");
            return;
        }
    };
    eprintln!("backend: {:?}", sandbox.backend());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        confined_harness_sees_workspace_and_grants_only(&sandbox).await;
        trusted_profile_is_not_confined(&sandbox).await;
    });
    eprintln!("harness_confinement: 2 passed");
}

struct Fixture {
    _root: tempfile::TempDir,
    base: std::path::PathBuf,
    state: std::path::PathBuf,
    secret: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tempdir");
    let base = root.path().join("workspaces");
    let state = root.path().join("home/.harness");
    let secret = root.path().join("home/.ssh/id_ed25519");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, "PRIVATE-KEY").unwrap();
    Fixture {
        base,
        state,
        secret,
        _root: root,
    }
}

/// The shell every harness here is, its script flag, and the environment it
/// needs to start. On Windows `cmd.exe`, whose scripts below avoid quotes
/// (`cmd` does not unescape them).
fn shell() -> (PathBuf, &'static str, BTreeMap<String, String>) {
    let mut env: BTreeMap<String, String> =
        [("SESSION_VAR".to_string(), "session-value".to_string())].into();
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").expect("SystemRoot");
        let system32 = Path::new(&root).join("System32");
        env.insert("PATH".to_string(), system32.to_string_lossy().into_owned());
        env.insert("SystemRoot".to_string(), root);
        (system32.join("cmd.exe"), "/c", env)
    } else {
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        (PathBuf::from("/bin/sh"), "-c", env)
    }
}

/// Runs `script` as the harness through `confinement` and returns stdout.
async fn run(
    confinement: &HarnessConfinement,
    workspace: &WorkspacePolicy,
    profile: SandboxProfile,
    script: &str,
) -> String {
    let (program, flag, env) = shell();
    let launch = HarnessLaunch {
        program: &program,
        args: vec![flag.into(), script.into()],
        env: &env,
        workspace,
        profile,
    };
    let mut command = if profile == SandboxProfile::Trusted {
        let mut c = tokio::process::Command::new(&program);
        c.args([flag, script]).env_clear().envs(&env);
        c
    } else {
        confinement.command(launch).expect("confined command")
    };
    let out = command.output().await.expect("harness runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

async fn confined_harness_sees_workspace_and_grants_only(sandbox: &Sandbox) {
    let fx = fixture();
    std::env::set_var("DAEMON_ONLY_SECRET", "daemon-secret");
    let confinement = HarnessConfinement::new(sandbox.clone(), &fx.base)
        .with_read_write([fx.state.clone(), fx.base.join("does-not-exist")]);
    let workspace = WorkspacePolicy {
        root: confinement.owner_workspace("alice@example"),
        read_only: false,
        deny: Vec::new(),
    };
    let script = if cfg!(windows) {
        // An undefined `%VAR%` stays literal in `cmd /c`, so the daemon's
        // variable shows up as its own name, never as its value.
        format!(
            "echo ws>work.txt && echo WS_OK & \
             echo st>{state}\\state.txt && echo STATE_OK & \
             type {secret} && echo SECRET_READ & \
             echo env=%SESSION_VAR% daemon=%DAEMON_ONLY_SECRET% & \
             echo tmp=%TMPDIR%& type nul>%TMPDIR%\\t && echo TMP_OK",
            state = fx.state.display(),
            secret = fx.secret.display(),
        )
    } else {
        format!(
            "echo ws > work.txt && echo WS_OK; \
             echo st > '{state}/state.txt' && echo STATE_OK; \
             cat '{secret}' && echo SECRET_READ; \
             echo \"env=$SESSION_VAR daemon=$DAEMON_ONLY_SECRET\"; \
             echo \"tmp=$TMPDIR\"; touch \"$TMPDIR/t\" && echo TMP_OK",
            state = fx.state.display(),
            secret = fx.secret.display(),
        )
    };
    let out = run(
        &confinement,
        &workspace,
        SandboxProfile::WorkspaceNet,
        &script,
    )
    .await;
    std::env::remove_var("DAEMON_ONLY_SECRET");

    assert!(out.contains("WS_OK"), "workspace not writable: {out}");
    assert!(workspace.root.join("work.txt").exists());
    assert!(workspace.root.ends_with("alice_example"));
    assert!(
        out.contains("STATE_OK"),
        "granted state dir not writable: {out}"
    );
    assert!(
        !out.contains("PRIVATE-KEY") && !out.contains("SECRET_READ"),
        "read the operator's key: {out}"
    );
    assert!(
        out.contains("env=session-value daemon="),
        "environment leaked or missing: {out}"
    );
    assert!(
        !out.contains("daemon-secret"),
        "daemon environment leaked: {out}"
    );
    assert!(
        out.contains(&format!("tmp={}", workspace.root.join(".tmp").display())),
        "{out}"
    );
    assert!(out.contains("TMP_OK"), "private TMPDIR not writable: {out}");
}

/// `Trusted` is the owner's explicit opt-out: the adapters spawn the harness
/// plainly. This checks the fixture really distinguishes the two (the key is
/// readable when unconfined), so the test above cannot pass vacuously.
async fn trusted_profile_is_not_confined(sandbox: &Sandbox) {
    let fx = fixture();
    let confinement = HarnessConfinement::new(sandbox.clone(), &fx.base);
    let workspace = WorkspacePolicy {
        root: confinement.owner_workspace("bob"),
        read_only: false,
        deny: Vec::new(),
    };
    let out = run(
        &confinement,
        &workspace,
        SandboxProfile::Trusted,
        &if cfg!(windows) {
            format!("type {}", fx.secret.display())
        } else {
            format!("cat '{}'", fx.secret.display())
        },
    )
    .await;
    assert!(out.contains("PRIVATE-KEY"), "fixture broken: {out}");
}
