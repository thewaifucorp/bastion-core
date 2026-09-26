//! OS confinement for the harness processes the adapters spawn (Claude Code
//! through acpx or ACP, Codex app-server, OpenCode).
//!
//! Without it a harness runs as the daemon's user with the daemon's whole
//! filesystem view: natively that is the operator's real home, `~/.ssh`
//! included, and a prompt-injected session can read or write any of it. With
//! a [`HarnessConfinement`], the adapter starts the harness through
//! `bastion-sandbox`: it sees the system directories, its own install, the
//! session's workspace, and the state directories the host granted (its
//! login, its session store) — nothing else.
//!
//! The network follows the session's [`SandboxProfile`]: `WorkspaceNet` keeps
//! it (the harness has to reach its vendor), `Isolated` removes it, `Trusted`
//! means the owner opted out of confinement for that session.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use bastion_sandbox::{Launch, Network, Sandbox, SandboxSpec};
use tokio::process::Command;

use crate::{RuntimeError, SandboxCoverage, SandboxProfile, WorkspacePolicy};

/// What a host grants its harnesses beyond the session workspace. Built once
/// at startup from a detected [`Sandbox`] and handed to each adapter's
/// `with_confinement`.
#[derive(Debug, Clone)]
pub struct HarnessConfinement {
    sandbox: Sandbox,
    workspace_base: PathBuf,
    read_write: Vec<PathBuf>,
    read_only: Vec<PathBuf>,
}

impl HarnessConfinement {
    /// `workspace_base` is the parent of the per-owner workspaces (the same
    /// base the host gives the agent loop); a resumed session, whose spec
    /// carries no workspace, is confined to `workspace_base/<owner>`.
    pub fn new(sandbox: Sandbox, workspace_base: impl Into<PathBuf>) -> Self {
        Self {
            sandbox,
            workspace_base: workspace_base.into(),
            read_write: Vec::new(),
            read_only: Vec::new(),
        }
    }

    /// State the harness must write: its login and session directories
    /// (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.acpx`, an npm cache).
    /// Paths that do not exist are skipped, so a host can list every
    /// candidate without checking which CLI is installed.
    pub fn with_read_write(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.read_write.extend(paths);
        self
    }

    /// Extra read-only paths, for installs outside the system directories
    /// that the program-prefix rule below does not reach.
    pub fn with_read_only(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.read_only.extend(paths);
        self
    }

    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// The workspace a resumed session of `owner` is confined to.
    pub fn owner_workspace(&self, owner: &str) -> PathBuf {
        owner_workspace(&self.workspace_base, owner)
    }

    /// `launch` as a confined command, whatever its profile (the adapters
    /// skip confinement for `Trusted` before calling this). The workspace is
    /// created if missing; `TMPDIR` defaults to `<workspace>/.tmp`. Stdio is
    /// left to the caller. For harnesses a host starts itself — a CLI login,
    /// a custom agent — with the same grants the adapters use.
    pub fn command(&self, launch: HarnessLaunch<'_>) -> Result<Command, RuntimeError> {
        let spec = spec(self, launch)?;
        let std = self.sandbox.command(&spec).map_err(sandbox_error)?;
        Ok(Command::from(std))
    }

    /// `launch` in the form an SDK spawns it (program, args, extra env).
    pub fn launch(&self, launch: HarnessLaunch<'_>) -> Result<Launch, RuntimeError> {
        let spec = spec(self, launch)?;
        self.sandbox.launch(&spec).map_err(sandbox_error)
    }
}

/// `base/<owner>`, the owner id reduced to `[A-Za-z0-9_]`. The one place this
/// mapping lives: the agent loop uses it to create the workspace, the
/// adapters to confine a resumed session to it.
pub fn owner_workspace(base: &Path, owner: &str) -> PathBuf {
    let sanitized: String = owner
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    base.join(if sanitized.is_empty() {
        "_owner".to_string()
    } else {
        sanitized
    })
}

/// Coverage an adapter reports: filesystem confinement is real, but the
/// network (when kept) is not filtered by destination, so never `Honored`.
pub(crate) fn coverage(confinement: Option<&HarnessConfinement>) -> SandboxCoverage {
    match confinement {
        Some(_) => SandboxCoverage::Partial,
        None => SandboxCoverage::None,
    }
}

/// One harness launch, before confinement.
pub struct HarnessLaunch<'a> {
    pub program: &'a Path,
    pub args: Vec<OsString>,
    /// The harness's entire environment.
    pub env: &'a BTreeMap<String, String>,
    pub workspace: &'a WorkspacePolicy,
    pub profile: SandboxProfile,
}

/// A directory named like `bin` sits in an install prefix whose `lib`
/// (Node's `lib/node_modules`, for one) the program needs too — the layout of
/// nvm, a user-level npm prefix, Homebrew and `/usr/local`.
fn install_prefix(program: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(program).ok()?;
    let bin = canonical.parent()?;
    (bin.file_name()? == "bin").then(|| bin.parent().map(Path::to_path_buf))?
}

fn spec(
    confinement: &HarnessConfinement,
    launch: HarnessLaunch<'_>,
) -> Result<SandboxSpec, RuntimeError> {
    let workspace = &launch.workspace.root;
    std::fs::create_dir_all(workspace).map_err(|e| {
        RuntimeError::Unavailable(format!(
            "cannot create workspace {}: {e}",
            workspace.display()
        ))
    })?;
    // Most CLIs write temporary files; the Landlock backend has no private
    // /tmp, so give them one inside the workspace unless the host chose one.
    let tmp = workspace.join(".tmp");
    let mut env = launch.env.clone();
    if !env.contains_key("TMPDIR") && std::fs::create_dir_all(&tmp).is_ok() {
        env.insert("TMPDIR".to_string(), tmp.to_string_lossy().into_owned());
    }
    let mut spec = SandboxSpec::new(launch.program)
        .args(launch.args)
        .envs(env)
        .cwd(workspace)
        .network(match launch.profile {
            SandboxProfile::Isolated => Network::Blocked,
            SandboxProfile::WorkspaceNet | SandboxProfile::Trusted => Network::Allowed,
        });
    spec = if launch.workspace.read_only {
        spec.read_only(workspace)
    } else {
        spec.read_write(workspace)
    };
    if let Some(prefix) = install_prefix(launch.program) {
        spec = spec.read_only(prefix);
    }
    for path in confinement.read_only.iter().filter(|p| p.exists()) {
        spec = spec.read_only(path);
    }
    for path in confinement.read_write.iter().filter(|p| p.exists()) {
        spec = spec.read_write(path);
    }
    Ok(spec)
}

fn sandbox_error(e: bastion_sandbox::SandboxError) -> RuntimeError {
    RuntimeError::Unavailable(format!("cannot confine the harness: {e}"))
}

/// The harness as a ready-to-spawn command: confined when a confinement is
/// set and the session is not `Trusted`; otherwise exactly what the adapters
/// always spawned (program, args, only the given env). Stdio is left unset;
/// the caller configures it.
pub(crate) fn command(
    confinement: Option<&HarnessConfinement>,
    launch: HarnessLaunch<'_>,
) -> Result<Command, RuntimeError> {
    match confinement {
        Some(confinement) if launch.profile != SandboxProfile::Trusted => {
            confinement.command(launch)
        }
        _ => {
            let mut command = Command::new(launch.program);
            command.args(launch.args).env_clear().envs(launch.env);
            Ok(command)
        }
    }
}

/// The harness in the form an SDK spawns it (program, args, extra env), for
/// the ACP adapter. `None` means "spawn it the way you always did".
pub(crate) fn launch(
    confinement: Option<&HarnessConfinement>,
    launch: HarnessLaunch<'_>,
) -> Result<Option<Launch>, RuntimeError> {
    match confinement {
        Some(confinement) if launch.profile != SandboxProfile::Trusted => {
            confinement.launch(launch).map(Some)
        }
        _ => Ok(None),
    }
}

/// The stdio every harness spawn here uses: JSON-RPC over stdin/stdout, logs
/// on stderr, killed with its handle.
pub(crate) fn piped(command: &mut Command) -> &mut Command {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_workspace_keeps_only_safe_characters() {
        let base = Path::new("/w");
        assert_eq!(owner_workspace(base, "alice@x.io"), base.join("alice_x_io"));
        assert_eq!(owner_workspace(base, "../../etc"), base.join("______etc"));
        assert_eq!(owner_workspace(base, ""), base.join("_owner"));
    }

    #[test]
    fn install_prefix_is_the_parent_of_a_bin_directory() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("prefix/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("tool"), "").unwrap();
        assert_eq!(
            install_prefix(&bin.join("tool")),
            Some(std::fs::canonicalize(dir.path().join("prefix")).unwrap())
        );
        std::fs::write(dir.path().join("loose"), "").unwrap();
        assert_eq!(install_prefix(&dir.path().join("loose")), None);
    }

    #[test]
    fn coverage_is_partial_only_when_confined() {
        assert!(matches!(coverage(None), SandboxCoverage::None));
    }
}
