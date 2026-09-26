//! Runs real programs under the host's backend and checks what they can reach.
//!
//! Skipped (with a message) when [`Sandbox::detect`] finds no backend,
//! unless `BASTION_SANDBOX_TESTS_REQUIRED=1`, which turns the skip into a
//! failure — CI sets it on the runners where bubblewrap is installed.

use bastion_sandbox::{Network, Sandbox, SandboxSpec};
use std::io::Write;
use std::path::Path;
use std::process::Output;

const HELPER: &str = env!("CARGO_BIN_EXE_bastion-sandbox-exec");

fn backend() -> Option<Sandbox> {
    match Sandbox::detect(HELPER) {
        Ok(sandbox) => {
            eprintln!("backend: {:?}", sandbox.backend());
            Some(sandbox)
        }
        Err(e) if std::env::var("BASTION_SANDBOX_TESTS_REQUIRED").as_deref() == Ok("1") => {
            panic!("sandbox backend required but unavailable: {e}")
        }
        Err(e) => {
            eprintln!("skipping: {e}");
            None
        }
    }
}

/// `sh -c <script>` confined by `spec_for(sh)`.
fn sh(script: &str, spec: impl FnOnce(SandboxSpec) -> SandboxSpec) -> Option<Output> {
    let backend = backend()?;
    let spec = spec(
        SandboxSpec::new("/bin/sh")
            .args(["-c", script])
            .env("PATH", "/usr/bin:/bin"),
    );
    Some(
        backend
            .command(&spec)
            .expect("spec builds")
            .output()
            .expect("sandbox runs"),
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_writable_path_is_writable_and_the_write_is_visible_outside() {
    let work = tempfile::tempdir().unwrap();
    let Some(out) = sh("echo hi > out.txt", |s| {
        s.read_write(work.path()).cwd(work.path())
    }) else {
        return;
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(work.path().join("out.txt")).unwrap(),
        "hi\n"
    );
}

#[test]
fn a_read_only_path_is_readable_but_not_writable() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("in.txt"), "secret-ok").unwrap();
    let script = format!(
        "cat '{0}/in.txt'; echo x > '{0}/new.txt' && echo WROTE",
        data.path().display()
    );
    let Some(out) = sh(&script, |s| s.read_only(data.path())) else {
        return;
    };
    assert!(stdout(&out).contains("secret-ok"));
    assert!(!stdout(&out).contains("WROTE"));
    assert!(!data.path().join("new.txt").exists());
}

#[test]
fn a_path_that_was_not_granted_does_not_exist_for_the_child() {
    let granted = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let mut f = std::fs::File::create(hidden.path().join("key")).unwrap();
    f.write_all(b"do-not-read").unwrap();
    let script = format!("cat '{}/key' && echo READ", hidden.path().display());
    let Some(out) = sh(&script, |s| s.read_write(granted.path())) else {
        return;
    };
    assert!(!stdout(&out).contains("do-not-read"));
    assert!(!stdout(&out).contains("READ"));
}

#[test]
fn the_home_directory_is_not_visible_unless_granted() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    if !Path::new(&home).is_dir() {
        return;
    }
    let script = format!("ls -A '{}' && echo LISTED", Path::new(&home).display());
    let Some(out) = sh(&script, |s| s) else {
        return;
    };
    assert!(!stdout(&out).contains("LISTED"), "{}", stdout(&out));
}

#[test]
fn the_environment_is_exactly_the_spec() {
    std::env::set_var("BASTION_SANDBOX_CANARY", "must-not-leak");
    let Some(out) = sh("env", |s| s.env("DECLARED", "yes")) else {
        return;
    };
    std::env::remove_var("BASTION_SANDBOX_CANARY");
    let env = stdout(&out);
    assert!(env.contains("DECLARED=yes"), "{env}");
    assert!(!env.contains("must-not-leak"), "{env}");
}

/// A listener on the host's loopback is reachable only with the network
/// allowed. Uses bash's `/dev/tcp`, present on the hosts CI runs on.
#[test]
fn the_host_loopback_is_unreachable_when_the_network_is_blocked() {
    if !Path::new("/bin/bash").exists() {
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            drop(stream);
        }
    });
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo CONNECTED");
    let run = |network: Network| -> Option<String> {
        let backend = backend()?;
        let spec = SandboxSpec::new("/bin/bash")
            .args(["-c", &script])
            .env("PATH", "/usr/bin:/bin")
            .network(network);
        let out = backend.command(&spec).unwrap().output().unwrap();
        Some(stdout(&out))
    };
    let Some(blocked) = run(Network::Blocked) else {
        return;
    };
    assert!(
        !blocked.contains("CONNECTED"),
        "reached the host with the network blocked"
    );
    let allowed = run(Network::Allowed).unwrap();
    assert!(
        allowed.contains("CONNECTED"),
        "could not reach the host with the network allowed"
    );
}
