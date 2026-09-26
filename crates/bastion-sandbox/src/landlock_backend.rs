//! Linux fallback when bubblewrap cannot create namespaces: Landlock for the
//! filesystem, seccomp for the network. Needs no privileges and no user
//! namespace, so it works on distributions that restrict those (Ubuntu 24.04+
//! through AppArmor).
//!
//! Applied by the helper to its own process right before it execs the
//! target, so the target starts already confined and nothing runs between
//! fork and exec.
//!
//! Weaker than bubblewrap in one respect: paths outside the grant still exist
//! for the child (it can `stat` them), they just cannot be opened, listed,
//! written or executed.

use std::path::{Path, PathBuf};

use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    Scope, ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::{Network, LINUX_RESOLVER_DIR, LINUX_SYSTEM_DIRS};

/// Newest ABI this code knows. Older kernels get the subset they support
/// (best effort); a kernel without Landlock at all is refused.
const ABI_TARGET: ABI = ABI::V6;

/// Device files every program may use. `/dev/pts` for a terminal.
const DEVICE_FILES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/pts",
];

/// Address families that reach a network. `AF_UNIX` stays available (local
/// IPC inside the grant); `AF_NETLINK` too, since glibc uses it to list
/// interfaces and it reaches no other host.
const NETWORK_FAMILIES: &[u64] = &[
    libc::AF_INET as u64,
    libc::AF_INET6 as u64,
    libc::AF_PACKET as u64,
];

/// Confine the calling process: Landlock (which also sets `no_new_privs`)
/// and, with the network blocked, the seccomp filter. Irreversible; meant to
/// be followed by `exec`.
pub(crate) fn restrict_self(
    network: Network,
    read_only: &[PathBuf],
    read_write: &[PathBuf],
) -> Result<(), String> {
    let read = AccessFs::from_read(ABI_TARGET);
    let all = AccessFs::from_all(ABI_TARGET);
    let mut readable: Vec<&Path> = LINUX_SYSTEM_DIRS.iter().map(Path::new).collect();
    readable.push(Path::new("/proc"));
    if network == Network::Allowed {
        readable.push(Path::new(LINUX_RESOLVER_DIR));
    }
    readable.extend(read_only.iter().map(PathBuf::as_path));
    // `path_beneath_rules` skips paths that do not exist, which the optional
    // system dirs need; the spec's own paths were canonicalized (so they
    // exist) by the parent.
    let status = Ruleset::default()
        .handle_access(all)
        .and_then(|r| r.scope(Scope::AbstractUnixSocket | Scope::Signal))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules(&readable, read)))
        .and_then(|r| r.add_rules(path_beneath_rules(DEVICE_FILES, all)))
        .and_then(|r| r.add_rules(path_beneath_rules(read_write, all)))
        .and_then(|r| r.restrict_self())
        .map_err(|e| format!("Landlock: {e}"))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err("this kernel does not enforce Landlock".to_string());
    }
    if network == Network::Blocked {
        seccompiler::apply_filter(&network_filter()?).map_err(|e| format!("seccomp: {e}"))?;
    }
    Ok(())
}

fn network_filter() -> Result<BpfProgram, String> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|_| {
        format!(
            "no seccomp support for {} — cannot block the network",
            std::env::consts::ARCH
        )
    })?;
    let socket_rules = NETWORK_FAMILIES
        .iter()
        .map(|family| {
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, *family)
                .and_then(|c| SeccompRule::new(vec![c]))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("seccomp rule: {e}"))?;
    let rules = [
        (libc::SYS_socket, socket_rules),
        // io_uring can open sockets without the socket() syscall; an empty
        // rule chain matches unconditionally.
        (libc::SYS_io_uring_setup, Vec::new()),
    ]
    .into_iter()
    .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;
    BpfProgram::try_from(filter).map_err(|e| format!("seccomp program: {e}"))
}
