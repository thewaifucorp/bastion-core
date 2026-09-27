//! Runs real programs under the host's backend and checks what they can reach.
//!
//! Skipped (with a message) when [`Sandbox::detect`] finds no backend,
//! unless `BASTION_SANDBOX_TESTS_REQUIRED=1`, which turns the skip into a
//! failure — CI sets it on the Windows runner.
//!
//! The cases are the same on every OS; only the shell differs: `/bin/sh` on
//! Unix, `cmd.exe` on Windows (whose scripts avoid quotes, which `cmd` does
//! not unescape).

use bastion_sandbox::{Network, Sandbox, SandboxSpec};
use std::io::Write;
use std::path::{Path, PathBuf};
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

#[cfg(windows)]
fn system_root() -> String {
    std::env::var("SystemRoot").expect("SystemRoot")
}

#[cfg(windows)]
fn system32() -> PathBuf {
    PathBuf::from(system_root()).join("System32")
}

/// The shell with `script`, and the environment it needs to start (the
/// spec's environment is exactly what the child gets).
fn shell_spec(script: &str) -> SandboxSpec {
    #[cfg(unix)]
    {
        SandboxSpec::new("/bin/sh")
            .args(["-c", script])
            .env("PATH", "/usr/bin:/bin")
    }
    #[cfg(windows)]
    {
        SandboxSpec::new(system32().join("cmd.exe"))
            .args(["/d", "/c", script])
            .env("PATH", system32().to_string_lossy())
            .env("SystemRoot", system_root())
    }
}

/// `script` in the shell, confined by `spec`.
fn sh(script: &str, spec: impl FnOnce(SandboxSpec) -> SandboxSpec) -> Option<Output> {
    let backend = backend()?;
    Some(
        backend
            .command(&spec(shell_spec(script)))
            .expect("spec builds")
            .output()
            .expect("sandbox runs"),
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Writes `hi` to `out.txt` in the working directory.
const WRITE_HERE: &str = if cfg!(windows) {
    "echo hi>out.txt"
} else {
    "echo hi > out.txt"
};

/// Prints `file`, then tries to create `new` and prints `WROTE` if it could.
fn read_then_write(file: &Path, new: &Path) -> String {
    if cfg!(windows) {
        format!(
            "type {} & echo x>{} && echo WROTE",
            file.display(),
            new.display()
        )
    } else {
        format!(
            "cat '{}'; echo x > '{}' && echo WROTE",
            file.display(),
            new.display()
        )
    }
}

/// Prints `file`, then `READ` if that worked.
fn read(file: &Path) -> String {
    if cfg!(windows) {
        format!("type {} && echo READ", file.display())
    } else {
        format!("cat '{}' && echo READ", file.display())
    }
}

/// Lists `dir`, then prints `LISTED` if that worked.
fn list(dir: &Path) -> String {
    if cfg!(windows) {
        format!("dir /a {} && echo LISTED", dir.display())
    } else {
        format!("ls -A '{}' && echo LISTED", dir.display())
    }
}

const PRINT_ENV: &str = if cfg!(windows) { "set" } else { "env" };

fn home() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}

#[test]
fn a_writable_path_is_writable_and_the_write_is_visible_outside() {
    let work = tempfile::tempdir().unwrap();
    let Some(out) = sh(WRITE_HERE, |s| s.read_write(work.path()).cwd(work.path())) else {
        return;
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(work.path().join("out.txt"))
            .unwrap()
            .trim_end(),
        "hi"
    );
}

#[test]
fn a_read_only_path_is_readable_but_not_writable() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("in.txt"), "secret-ok").unwrap();
    let script = read_then_write(&data.path().join("in.txt"), &data.path().join("new.txt"));
    let Some(out) = sh(&script, |s| s.read_only(data.path())) else {
        return;
    };
    assert!(
        stdout(&out).contains("secret-ok"),
        "{}{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!stdout(&out).contains("WROTE"));
    assert!(!data.path().join("new.txt").exists());
}

#[test]
fn a_path_that_was_not_granted_does_not_exist_for_the_child() {
    let granted = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let mut f = std::fs::File::create(hidden.path().join("key")).unwrap();
    f.write_all(b"do-not-read").unwrap();
    let Some(out) = sh(&read(&hidden.path().join("key")), |s| {
        s.read_write(granted.path())
    }) else {
        return;
    };
    assert!(!stdout(&out).contains("do-not-read"));
    assert!(!stdout(&out).contains("READ"));
}

#[test]
fn the_home_directory_is_not_visible_unless_granted() {
    let Some(home) = home() else {
        return;
    };
    let Some(out) = sh(&list(&home), |s| s) else {
        return;
    };
    assert!(!stdout(&out).contains("LISTED"), "{}", stdout(&out));
}

#[test]
fn the_environment_is_exactly_the_spec() {
    std::env::set_var("BASTION_SANDBOX_CANARY", "must-not-leak");
    let Some(out) = sh(PRINT_ENV, |s| s.env("DECLARED", "yes")) else {
        return;
    };
    std::env::remove_var("BASTION_SANDBOX_CANARY");
    let env = stdout(&out);
    assert!(env.contains("DECLARED=yes"), "{env}");
    assert!(!env.contains("must-not-leak"), "{env}");
}

/// A program that connects to `127.0.0.1:port` and prints what the listener
/// sends: bash's `/dev/tcp` on Unix, `curl.exe` on Windows.
fn connect_spec(port: u16) -> Option<SandboxSpec> {
    #[cfg(unix)]
    {
        if !Path::new("/bin/bash").exists() {
            return None;
        }
        Some(
            SandboxSpec::new("/bin/bash")
                .args([
                    "-c",
                    &format!("exec 3<>/dev/tcp/127.0.0.1/{port} && cat <&3"),
                ])
                .env("PATH", "/usr/bin:/bin"),
        )
    }
    #[cfg(windows)]
    {
        let curl = system32().join("curl.exe");
        if !curl.exists() {
            return None;
        }
        Some(
            SandboxSpec::new(curl)
                .args([
                    "-s".to_string(),
                    "--max-time".to_string(),
                    "10".to_string(),
                    format!("http://127.0.0.1:{port}/"),
                ])
                .env("SystemRoot", system_root()),
        )
    }
}

/// Whether the host's loopback should be reachable with the network allowed.
/// On Windows only for an elevated helper, which may set the loopback
/// exemption (a machine setting); `net session` succeeds only elevated.
fn loopback_reachable_when_allowed() -> bool {
    if cfg!(windows) {
        std::process::Command::new("net")
            .arg("session")
            .output()
            .is_ok_and(|out| out.status.success())
    } else {
        true
    }
}

/// A listener on the host's loopback is reachable only with the network
/// allowed. It answers every connection with `CONNECTED` (as an HTTP reply,
/// so `curl` prints it too).
#[test]
fn the_host_loopback_is_unreachable_when_the_network_is_blocked() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let Some(spec) = connect_spec(port) else {
        return;
    };
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.write_all(
                b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nCONNECTED",
            );
        }
    });
    let run = |network: Network| -> Option<String> {
        let backend = backend()?;
        let out = backend
            .command(&spec.clone().network(network))
            .unwrap()
            .output()
            .unwrap();
        Some(stdout(&out))
    };
    let Some(blocked) = run(Network::Blocked) else {
        return;
    };
    assert!(
        !blocked.contains("CONNECTED"),
        "reached the host with the network blocked"
    );
    if !loopback_reachable_when_allowed() {
        eprintln!("not elevated: the host loopback stays isolated even when allowed");
        return;
    }
    let allowed = run(Network::Allowed).unwrap();
    assert!(
        allowed.contains("CONNECTED"),
        "could not reach the host with the network allowed"
    );
}

/// BMD-06: without a backend a host gets an error, never an unconfined
/// sandbox. On Windows the probe runs the helper, so a helper that does not
/// exist means no backend.
#[cfg(windows)]
#[test]
fn detect_refuses_when_the_backend_cannot_run() {
    let err = Sandbox::detect(r"C:\definitely\not\a\helper.exe").expect_err("no backend");
    assert!(
        matches!(err, bastion_sandbox::SandboxError::Unavailable(_)),
        "{err}"
    );
}
