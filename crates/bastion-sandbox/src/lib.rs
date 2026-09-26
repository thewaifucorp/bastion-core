//! OS-level confinement for the programs Bastion runs on the host: tool CLIs
//! (git), stdio MCP servers, subprocess extensions, and external agent
//! harnesses (Claude Code, Codex, OpenCode).
//!
//! The in-process checks (`CapabilityRegistry`, approvals, egress) decide
//! *whether* Bastion runs something. This crate bounds *what that program can
//! reach once it runs*: which paths it can see, which it can write, and
//! whether it has a network. Deny by default — a path not listed in the
//! [`SandboxSpec`] is out of reach for the child, the operator's home
//! directory included.
//!
//! Three backends, picked by [`Sandbox::detect`] in this order:
//!
//! - **Linux — bubblewrap.** A fresh mount namespace whose root is an empty
//!   tmpfs; only the system directories (`/usr`, `/etc`, the lib dirs, ...)
//!   and the spec's paths are bound into it, each at its real path. All other
//!   namespaces are unshared, the network one included unless the spec allows
//!   it. Needs unprivileged user namespaces.
//! - **Linux — Landlock + seccomp**, when bubblewrap cannot create namespaces
//!   (Ubuntu 24.04+ restricts them through AppArmor). Same grants, enforced
//!   by the kernel's Landlock LSM without privileges; with the network
//!   blocked, seccomp refuses `AF_INET`/`AF_INET6`/`AF_PACKET` sockets and
//!   `io_uring`.
//! - **macOS — Seatbelt** (`sandbox-exec`). A `(deny default)` profile that
//!   allows reading the system and the spec's paths, writing the spec's
//!   writable paths, and the network only when allowed. Paths reach the
//!   profile as `-D` parameters, never spliced into its text.
//!
//! Paths keep their real names in every backend (macOS cannot remap them), so
//! a program's configuration that names an absolute path still works.
//!
//! ## The helper
//!
//! Every confined program is started through a *helper*: the host's own
//! executable called with [`HELPER_MARKER`] as its first argument, which the
//! host forwards to [`helper_main`] before doing anything else. The helper
//! drops every environment variable the spec did not name, then execs the
//! target under the backend (for Landlock, it confines its own process right
//! before `exec`). One mechanism serves both [`Sandbox::command`] and
//! [`Sandbox::launch`] — the latter for SDKs that only take a program, its
//! arguments and extra environment (the ACP SDK spawns its bridge that way,
//! inheriting the whole daemon environment).
//!
//! Variable *values* never travel in argv (`/proc/<pid>/cmdline` is readable
//! by every user); argv carries only their names, values arrive through the
//! helper's environment.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
mod landlock_backend;

/// First argument that turns a host executable into the sandbox helper.
pub const HELPER_MARKER: &str = "__bastion-sandbox";

/// Whether the child gets a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// No network: on Linux a private network namespace (bubblewrap) or no
    /// Internet sockets (Landlock backend) — the host's `127.0.0.1` is not
    /// reachable either way; on macOS every `network*` operation denied.
    Blocked,
    /// The host's network, unfiltered. For harnesses that must reach their
    /// vendor's API; which destinations are acceptable is not decided here.
    Allowed,
}

/// Everything the child may see and do. Build with [`SandboxSpec::new`] and
/// the builder methods.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    program: PathBuf,
    args: Vec<OsString>,
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    network: Network,
}

impl SandboxSpec {
    /// A spec for `program`, with no arguments, an empty environment, no
    /// extra paths and no network. `program` is resolved to its canonical
    /// path, and its directory is made readable so the binary itself can
    /// load.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            read_only: Vec::new(),
            read_write: Vec::new(),
            network: Network::Blocked,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// One variable of the child's environment. The environment is exactly
    /// what is set here; nothing is inherited from the calling process.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    /// Working directory. It has to be inside a readable or writable path.
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// A directory or file the child may read. Must exist.
    pub fn read_only(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_only.push(path.into());
        self
    }

    /// A directory or file the child may read and write. Must exist.
    pub fn read_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_write.push(path.into());
        self
    }

    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn network_mode(&self) -> Network {
        self.network
    }
}

/// The confinement mechanism in use on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// Path to a working `bwrap`.
    Bubblewrap(PathBuf),
    /// The kernel's Landlock LSM plus seccomp (Linux, no namespaces).
    Landlock,
    /// Path to `sandbox-exec`.
    Seatbelt(PathBuf),
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// No backend works here. The message says why (not installed, user
    /// namespaces disabled, unsupported OS) and is meant for the operator.
    #[error("no OS sandbox available: {0}")]
    Unavailable(String),
    /// A path in the spec could not be resolved (usually: it does not exist).
    #[error("sandbox path {path:?}: {source}")]
    InvalidPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A working backend plus the helper that applies it. Cheap to clone; a host
/// detects one at startup and shares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    backend: Backend,
    helper: PathBuf,
}

/// A confined launch as an SDK takes it: run `program` with `args` and set
/// `env` on top of whatever the SDK inherits — the helper discards anything
/// not named in `args`.
#[derive(Debug, Clone)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: BTreeMap<String, String>,
}

impl Sandbox {
    /// Probe this host, by actually running a trivial confined program: a
    /// `bwrap` that is installed but cannot create namespaces is reported as
    /// unavailable here, not discovered at the first real call. `helper` is
    /// an executable that forwards [`HELPER_MARKER`] invocations to
    /// [`helper_main`] — normally the host's own `std::env::current_exe()`.
    pub fn detect(helper: impl Into<PathBuf>) -> Result<Self, SandboxError> {
        let helper = helper.into();
        let backend = probe(&helper).map_err(SandboxError::Unavailable)?;
        Ok(Self { backend, helper })
    }

    /// A specific backend, without probing. For tests and for hosts that
    /// already know what works.
    pub fn with_backend(backend: Backend, helper: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            helper: helper.into(),
        }
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// The confined launch in SDK form.
    pub fn launch(&self, spec: &SandboxSpec) -> Result<Launch, SandboxError> {
        let resolved = resolve(spec)?;
        Ok(Launch {
            program: self.helper.clone(),
            args: helper_args(&self.backend, spec, &resolved),
            env: spec.env.clone(),
        })
    }

    /// A [`Command`] that runs `spec` confined. Its environment is exactly
    /// the spec's; stdio is left to the caller. Wrap it in
    /// `tokio::process::Command::from` for async use.
    pub fn command(&self, spec: &SandboxSpec) -> Result<Command, SandboxError> {
        let launch = self.launch(spec)?;
        let mut command = Command::new(&launch.program);
        command.args(&launch.args).env_clear().envs(&launch.env);
        Ok(command)
    }
}

#[cfg(target_os = "linux")]
fn probe(helper: &Path) -> Result<Backend, String> {
    let bubblewrap = probe_bubblewrap();
    if bubblewrap.is_ok() {
        return bubblewrap;
    }
    probe_landlock(helper).map_err(|landlock| {
        format!(
            "{}; Landlock fallback: {landlock}",
            bubblewrap.err().unwrap_or_default()
        )
    })
}

/// Runs `true` through the helper under Landlock with the network blocked —
/// both halves of the backend, so a kernel without Landlock or seccomp fails
/// here.
#[cfg(target_os = "linux")]
fn probe_landlock(helper: &Path) -> Result<Backend, String> {
    let sandbox = Sandbox::with_backend(Backend::Landlock, helper);
    let output = sandbox
        .command(&SandboxSpec::new("/usr/bin/true"))
        .map_err(|e| e.to_string())?
        .output()
        .map_err(|e| format!("cannot run the sandbox helper {}: {e}", helper.display()))?;
    if output.status.success() {
        Ok(Backend::Landlock)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(target_os = "linux")]
fn probe_bubblewrap() -> Result<Backend, String> {
    let bwrap =
        find_on_path("bwrap").ok_or_else(|| "bubblewrap (bwrap) is not installed".to_string())?;
    let output = Command::new(&bwrap)
        .args([
            "--die-with-parent",
            "--unshare-all",
            "--ro-bind",
            "/",
            "/",
            "--",
            "true",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .map_err(|e| format!("cannot run {}: {e}", bwrap.display()))?;
    if output.status.success() {
        Ok(Backend::Bubblewrap(bwrap))
    } else {
        Err(format!(
            "{} cannot create namespaces here: {}",
            bwrap.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(target_os = "macos")]
fn probe(_helper: &Path) -> Result<Backend, String> {
    let sandbox_exec = PathBuf::from("/usr/bin/sandbox-exec");
    if !sandbox_exec.exists() {
        return Err("/usr/bin/sandbox-exec is missing".to_string());
    }
    let output = Command::new(&sandbox_exec)
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .env_clear()
        .output()
        .map_err(|e| format!("cannot run sandbox-exec: {e}"))?;
    if output.status.success() {
        Ok(Backend::Seatbelt(sandbox_exec))
    } else {
        Err(format!(
            "sandbox-exec refused a trivial profile: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe(_helper: &Path) -> Result<Backend, String> {
    Err(format!("no sandbox backend for {}", std::env::consts::OS))
}

#[cfg(target_os = "linux")]
fn find_on_path(name: &str) -> Option<PathBuf> {
    let from_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|dir| dir.join(name));
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .into_iter()
        .map(|dir| Path::new(dir).join(name))
        .chain(from_path)
        .find(|candidate| candidate.is_file())
}

/// The spec with every path canonicalized (the program excepted, see
/// [`resolve`]), and the program's directories added to the readable set.
#[derive(Debug, Default, PartialEq)]
struct Resolved {
    program: PathBuf,
    cwd: Option<PathBuf>,
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
}

fn canonical(path: &Path) -> Result<PathBuf, SandboxError> {
    std::fs::canonicalize(path).map_err(|source| SandboxError::InvalidPath {
        path: path.to_path_buf(),
        source,
    })
}

fn resolve(spec: &SandboxSpec) -> Result<Resolved, SandboxError> {
    // Executed by the path it was given, not its symlink target: a
    // virtualenv's `bin/python` is a symlink, and Python finds the venv (its
    // `pyvenv.cfg`, hence its site-packages) only next to the path it was
    // invoked as. Both that directory and the target's are made readable.
    let target = canonical(&spec.program)?;
    let program = if spec.program.is_absolute() {
        spec.program.clone()
    } else {
        target.clone()
    };
    let mut read_only = spec
        .read_only
        .iter()
        .map(|p| canonical(p))
        .collect::<Result<Vec<_>, _>>()?;
    for dir in [program.parent(), target.parent()].into_iter().flatten() {
        let dir = canonical(dir)?;
        if !read_only.contains(&dir) {
            read_only.push(dir);
        }
    }
    let read_write = spec
        .read_write
        .iter()
        .map(|p| canonical(p))
        .collect::<Result<Vec<_>, _>>()?;
    let cwd = spec.cwd.as_deref().map(canonical).transpose()?;
    Ok(Resolved {
        program,
        cwd,
        read_only,
        read_write,
    })
}

// ---------------------------------------------------------------------------
// Helper protocol:
//
//   <HELPER_MARKER> --backend bwrap:<path> | landlock | seatbelt:<path>
//                   --net blocked|allowed [--cwd <path>]
//                   (--ro <path>)* (--rw <path>)* (--keep <NAME>)*
//                   -- <program> [args...]
//
// Paths are already canonical. `--keep` names the variables the child gets;
// their values come from the helper's own environment.
// ---------------------------------------------------------------------------

fn helper_args(backend: &Backend, spec: &SandboxSpec, resolved: &Resolved) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![HELPER_MARKER.into(), "--backend".into()];
    args.push(match backend {
        Backend::Bubblewrap(path) => {
            let mut s = OsString::from("bwrap:");
            s.push(path);
            s
        }
        Backend::Landlock => "landlock".into(),
        Backend::Seatbelt(path) => {
            let mut s = OsString::from("seatbelt:");
            s.push(path);
            s
        }
    });
    args.push("--net".into());
    args.push(match spec.network {
        Network::Blocked => "blocked".into(),
        Network::Allowed => "allowed".into(),
    });
    if let Some(cwd) = &resolved.cwd {
        args.push("--cwd".into());
        args.push(cwd.into());
    }
    for path in &resolved.read_only {
        args.push("--ro".into());
        args.push(path.into());
    }
    for path in &resolved.read_write {
        args.push("--rw".into());
        args.push(path.into());
    }
    for key in spec.env.keys() {
        args.push("--keep".into());
        args.push(key.into());
    }
    args.push("--".into());
    args.push(resolved.program.clone().into());
    args.extend(spec.args.iter().cloned());
    args
}

#[derive(Debug, PartialEq)]
struct HelperRequest {
    backend: Backend,
    network: Network,
    resolved: Resolved,
    keep: Vec<String>,
    args: Vec<OsString>,
}

fn parse_helper_args(args: impl IntoIterator<Item = OsString>) -> Result<HelperRequest, String> {
    let mut args = args.into_iter();
    if args.next().as_deref() != Some(OsStr::new(HELPER_MARKER)) {
        return Err(format!("expected {HELPER_MARKER} as the first argument"));
    }
    let mut backend = None;
    let mut network = None;
    let mut resolved = Resolved::default();
    let mut keep = Vec::new();
    let mut program = None;
    while let Some(flag) = args.next() {
        if flag == "--" {
            program = args.next();
            break;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--backend") => {
                let value = value.to_string_lossy().into_owned();
                backend = Some(if value == "landlock" {
                    Backend::Landlock
                } else if let Some(path) = value.strip_prefix("bwrap:") {
                    Backend::Bubblewrap(PathBuf::from(path))
                } else if let Some(path) = value.strip_prefix("seatbelt:") {
                    Backend::Seatbelt(PathBuf::from(path))
                } else {
                    return Err(format!("unknown backend {value:?}"));
                });
            }
            Some("--net") => {
                network = Some(match value.to_str() {
                    Some("blocked") => Network::Blocked,
                    Some("allowed") => Network::Allowed,
                    _ => return Err(format!("unknown network mode {value:?}")),
                });
            }
            Some("--cwd") => resolved.cwd = Some(PathBuf::from(value)),
            Some("--ro") => resolved.read_only.push(PathBuf::from(value)),
            Some("--rw") => resolved.read_write.push(PathBuf::from(value)),
            Some("--keep") => keep.push(value.to_string_lossy().into_owned()),
            _ => return Err(format!("unknown flag {flag:?}")),
        }
    }
    resolved.program = PathBuf::from(program.ok_or("missing program after --")?);
    Ok(HelperRequest {
        backend: backend.ok_or("missing --backend")?,
        network: network.ok_or("missing --net")?,
        resolved,
        keep,
        args: args.collect(),
    })
}

/// The helper's entry point. A host calls it first thing in `main` when its
/// first argument is [`HELPER_MARKER`], passing its arguments from the marker
/// on (`std::env::args_os().skip(1)`). Never returns: it execs the confined
/// program, or exits with status 126 after printing why it could not.
pub fn helper_main(args: impl IntoIterator<Item = OsString>) -> ! {
    let error = match parse_helper_args(args) {
        Ok(request) => exec_confined(request),
        Err(e) => e,
    };
    eprintln!("bastion-sandbox: {error}");
    std::process::exit(126)
}

/// Returns only on failure (the `exec` itself failing included).
fn exec_confined(request: HelperRequest) -> String {
    let env: Vec<(String, OsString)> = request
        .keep
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (key.clone(), value)))
        .collect();
    let resolved = &request.resolved;
    let mut command = match &request.backend {
        Backend::Bubblewrap(bwrap) => {
            let mut command = Command::new(bwrap);
            command.args(bubblewrap_args(
                request.network,
                resolved,
                &request.args,
                Path::exists,
            ));
            command
        }
        Backend::Seatbelt(sandbox_exec) => {
            let (profile, params) =
                seatbelt_profile(request.network, resolved, &std::env::temp_dir());
            let mut command = Command::new(sandbox_exec);
            command.arg("-p").arg(profile);
            for (name, path) in params {
                let mut define = OsString::from(format!("-D{name}="));
                define.push(path.as_os_str());
                command.arg(define);
            }
            command.arg("--").arg(&resolved.program).args(&request.args);
            if let Some(cwd) = &resolved.cwd {
                command.current_dir(cwd);
            }
            command
        }
        Backend::Landlock => {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = landlock_backend::restrict_self(
                    request.network,
                    &resolved.read_only,
                    &resolved.read_write,
                ) {
                    return e;
                }
                let mut command = Command::new(&resolved.program);
                command.args(&request.args);
                if let Some(cwd) = &resolved.cwd {
                    command.current_dir(cwd);
                }
                command
            }
            #[cfg(not(target_os = "linux"))]
            {
                return "the Landlock backend exists only on Linux".to_string();
            }
        }
    };
    command.env_clear().envs(env);
    exec(command)
}

#[cfg(unix)]
fn exec(mut command: Command) -> String {
    use std::os::unix::process::CommandExt;
    format!("exec failed: {}", command.exec())
}

#[cfg(not(unix))]
fn exec(_command: Command) -> String {
    "the sandbox helper needs a Unix host".to_string()
}

/// System directories a dynamically linked program needs to start. Readable
/// when present; `/etc` carries the resolver, CA certificates and `passwd`,
/// none of which is the operator's secret.
const LINUX_SYSTEM_DIRS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/etc",
    "/opt",
    "/nix/store",
];

/// `/etc/resolv.conf` is a symlink into here on systemd-resolved hosts.
const LINUX_RESOLVER_DIR: &str = "/run/systemd/resolve";

/// bubblewrap's arguments. The environment is not set here: the helper execs
/// bwrap with exactly the kept variables, and bwrap passes them on.
fn bubblewrap_args(
    network: Network,
    resolved: &Resolved,
    program_args: &[OsString],
    exists: impl Fn(&Path) -> bool,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    let mut push = |items: &[&OsStr]| args.extend(items.iter().map(|s| s.to_os_string()));
    push(&[
        "--die-with-parent".as_ref(),
        "--new-session".as_ref(),
        "--unshare-all".as_ref(),
    ]);
    if network == Network::Allowed {
        push(&["--share-net".as_ref()]);
    }
    push(&[
        "--proc".as_ref(),
        "/proc".as_ref(),
        "--dev".as_ref(),
        "/dev".as_ref(),
        "--tmpfs".as_ref(),
        "/tmp".as_ref(),
    ]);
    for dir in LINUX_SYSTEM_DIRS {
        if exists(Path::new(dir)) {
            push(&["--ro-bind".as_ref(), dir.as_ref(), dir.as_ref()]);
        }
    }
    if network == Network::Allowed && exists(Path::new(LINUX_RESOLVER_DIR)) {
        push(&[
            "--ro-bind".as_ref(),
            LINUX_RESOLVER_DIR.as_ref(),
            LINUX_RESOLVER_DIR.as_ref(),
        ]);
    }
    // Read-only first, writable after: a writable path nested in a readable
    // one stays writable because the later bind is on top.
    for path in &resolved.read_only {
        push(&["--ro-bind".as_ref(), path.as_os_str(), path.as_os_str()]);
    }
    for path in &resolved.read_write {
        push(&["--bind".as_ref(), path.as_os_str(), path.as_os_str()]);
    }
    if let Some(cwd) = &resolved.cwd {
        push(&["--chdir".as_ref(), cwd.as_os_str()]);
    }
    push(&["--".as_ref(), resolved.program.as_os_str()]);
    args.extend(program_args.iter().cloned());
    args
}

/// The Seatbelt profile and its `-D` parameters. Pure, so its shape is
/// testable on any host.
fn seatbelt_profile(
    network: Network,
    resolved: &Resolved,
    temp_dir: &Path,
) -> (String, Vec<(String, PathBuf)>) {
    let mut params = Vec::new();
    let mut profile = String::from(SEATBELT_BASE);
    let temp_dir = std::fs::canonicalize(temp_dir).unwrap_or_else(|_| temp_dir.to_path_buf());
    params.push(("TMPDIR".to_string(), temp_dir));
    profile.push_str("(allow file-read* file-write* (subpath (param \"TMPDIR\")))\n");
    for (index, path) in resolved.read_only.iter().enumerate() {
        let name = format!("RO_{index}");
        profile.push_str(&format!(
            "(allow file-read* (subpath (param \"{name}\")))\n"
        ));
        params.push((name, path.clone()));
    }
    for (index, path) in resolved.read_write.iter().enumerate() {
        let name = format!("RW_{index}");
        profile.push_str(&format!(
            "(allow file-read* file-write* (subpath (param \"{name}\")))\n"
        ));
        params.push((name, path.clone()));
    }
    if network == Network::Allowed {
        profile
            .push_str("(allow network-outbound)\n(allow network-inbound)\n(allow system-socket)\n");
    }
    (profile, params)
}

/// Deny everything, then allow what any program needs to start and run:
/// exec/fork, reading the system, the terminal and the null devices. Paths
/// the spec grants are appended by [`seatbelt_profile`].
const SEATBELT_BASE: &str = r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix-shm*)
(allow iokit-open)
(allow pseudo-tty)
(allow file-read-metadata)
(allow file-read* file-write*
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty")
  (regex #"^/dev/fd/") (regex #"^/dev/ttys"))
(allow file-read* (literal "/dev/urandom") (literal "/dev/random"))
(allow file-read*
  (literal "/") (literal "/private") (literal "/etc") (literal "/var") (literal "/tmp")
  (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/System")
  (subpath "/Library") (subpath "/private/etc") (subpath "/private/var/db/timezone")
  (subpath "/opt/homebrew") (subpath "/usr/local"))
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(read_only: &[&str], read_write: &[&str]) -> Resolved {
        Resolved {
            program: PathBuf::from("/usr/bin/tool"),
            cwd: Some(PathBuf::from("/work")),
            read_only: read_only.iter().map(PathBuf::from).collect(),
            read_write: read_write.iter().map(PathBuf::from).collect(),
        }
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn bubblewrap_args_deny_by_default_and_bind_only_what_was_granted() {
        let args = strings(&bubblewrap_args(
            Network::Blocked,
            &resolved(&["/ro"], &["/work"]),
            &["--flag".into()],
            |p| p == Path::new("/usr") || p == Path::new("/etc"),
        ));
        let joined = args.join(" ");
        assert!(joined.starts_with("--die-with-parent --new-session --unshare-all --proc"));
        assert!(!args.contains(&"--share-net".to_string()));
        assert!(joined.contains("--ro-bind /usr /usr"));
        assert!(joined.contains("--ro-bind /etc /etc"));
        // Absent system dirs are not bound (bwrap would fail on them).
        assert!(!joined.contains("/lib64"));
        assert!(joined.contains("--ro-bind /ro /ro"));
        assert!(joined.contains("--bind /work /work"));
        assert!(joined.contains("--chdir /work"));
        assert!(joined.ends_with("-- /usr/bin/tool --flag"));
        // Nothing binds the root or a home directory wholesale.
        assert!(!joined.contains("--bind / /") && !joined.contains("--ro-bind / /"));
    }

    #[test]
    fn bubblewrap_args_share_the_network_and_resolver_only_when_allowed() {
        let args = strings(&bubblewrap_args(
            Network::Allowed,
            &resolved(&[], &[]),
            &[],
            |p| p == Path::new(LINUX_RESOLVER_DIR),
        ));
        assert!(args.contains(&"--share-net".to_string()));
        assert!(args.join(" ").contains("--ro-bind /run/systemd/resolve"));

        let args = strings(&bubblewrap_args(
            Network::Blocked,
            &resolved(&[], &[]),
            &[],
            |_| true,
        ));
        assert!(!args.contains(&"--share-net".to_string()));
        assert!(!args.join(" ").contains(LINUX_RESOLVER_DIR));
    }

    #[test]
    fn writable_binds_come_after_readable_ones() {
        let args = strings(&bubblewrap_args(
            Network::Blocked,
            &resolved(&["/data"], &["/data/rw"]),
            &[],
            |_| false,
        ));
        let ro = args.iter().position(|a| a == "/data").unwrap();
        let rw = args.iter().position(|a| a == "/data/rw").unwrap();
        assert!(ro < rw);
    }

    #[test]
    fn seatbelt_profile_denies_by_default_and_passes_paths_as_parameters() {
        let (profile, params) = seatbelt_profile(
            Network::Blocked,
            &resolved(&["/ro \"quoted\")"], &["/work"]),
            Path::new("/nonexistent-tmp"),
        );
        assert!(profile.starts_with("(version 1)\n(deny default)"));
        assert!(profile.contains("(allow file-read* (subpath (param \"RO_0\")))"));
        assert!(profile.contains("(allow file-read* file-write* (subpath (param \"RW_0\")))"));
        assert!(!profile.contains("network-outbound"));
        // A path with quotes and parentheses never reaches the profile text.
        assert!(!profile.contains("quoted"));
        assert!(params.contains(&("RO_0".to_string(), PathBuf::from("/ro \"quoted\")"))));
        assert!(params.contains(&("RW_0".to_string(), PathBuf::from("/work"))));
        assert!(params.iter().any(|(name, _)| name == "TMPDIR"));
    }

    #[test]
    fn seatbelt_profile_allows_the_network_only_when_asked() {
        let (profile, _) =
            seatbelt_profile(Network::Allowed, &resolved(&[], &[]), Path::new("/tmp"));
        assert!(profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn resolve_rejects_a_missing_path_and_exposes_the_program_directory() {
        let err = resolve(&SandboxSpec::new("/usr/bin/env").read_only("/definitely/not/here"))
            .expect_err("missing path");
        assert!(matches!(err, SandboxError::InvalidPath { .. }));

        let ok = resolve(&SandboxSpec::new("/usr/bin/env")).expect("env exists");
        assert!(
            ok.read_only.iter().any(|p| p.ends_with("bin")),
            "{:?}",
            ok.read_only
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_program_runs_by_its_own_path_with_both_directories_readable() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("install/bin");
        let venv = dir.path().join("venv/bin");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&venv).unwrap();
        std::fs::write(real.join("python3.12"), "").unwrap();
        std::os::unix::fs::symlink(real.join("python3.12"), venv.join("python")).unwrap();
        let resolved = resolve(&SandboxSpec::new(venv.join("python"))).unwrap();
        assert_eq!(resolved.program, venv.join("python"));
        assert!(resolved
            .read_only
            .contains(&std::fs::canonicalize(&venv).unwrap()));
        assert!(resolved
            .read_only
            .contains(&std::fs::canonicalize(&real).unwrap()));
    }

    #[test]
    fn helper_args_round_trip_and_never_carry_env_values() {
        let spec = SandboxSpec::new("/usr/bin/env")
            .arg("--x")
            .env("API_KEY", "super-secret-value")
            .network(Network::Allowed);
        let resolved = Resolved {
            program: PathBuf::from("/usr/bin/env"),
            cwd: Some(PathBuf::from("/w")),
            read_only: vec![PathBuf::from("/ro")],
            read_write: vec![PathBuf::from("/rw")],
        };
        let args = helper_args(
            &Backend::Bubblewrap("/usr/bin/bwrap".into()),
            &spec,
            &resolved,
        );
        assert!(!strings(&args)
            .iter()
            .any(|a| a.contains("super-secret-value")));

        let parsed = parse_helper_args(args).expect("parses");
        assert_eq!(parsed.backend, Backend::Bubblewrap("/usr/bin/bwrap".into()));
        assert_eq!(parsed.network, Network::Allowed);
        assert_eq!(parsed.resolved, resolved);
        assert_eq!(parsed.keep, ["API_KEY"]);
        assert_eq!(parsed.args, [OsString::from("--x")]);
    }

    #[test]
    fn helper_refuses_malformed_requests() {
        let bad = |args: &[&str]| parse_helper_args(args.iter().map(OsString::from)).is_err();
        assert!(bad(&["not-the-marker"]));
        assert!(bad(&[HELPER_MARKER, "--net", "blocked", "--", "/bin/true"]));
        assert!(bad(&[
            HELPER_MARKER,
            "--backend",
            "chroot",
            "--net",
            "blocked",
            "--",
            "/x"
        ]));
        assert!(bad(&[
            HELPER_MARKER,
            "--backend",
            "landlock",
            "--net",
            "maybe",
            "--",
            "/x"
        ]));
        assert!(bad(&[
            HELPER_MARKER,
            "--backend",
            "landlock",
            "--net",
            "blocked",
            "--"
        ]));
    }
}
