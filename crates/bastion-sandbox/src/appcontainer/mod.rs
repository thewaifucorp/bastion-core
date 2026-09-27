//! Windows backend: an AppContainer inside a Job Object.
//!
//! The helper does not `exec` on Windows (there is no such call); it creates
//! the target itself and waits for it, forwarding its exit code:
//!
//! - **AppContainer.** The target runs with a lowbox token — the restricted
//!   token Windows builds for an AppContainer: Low integrity, all privileges
//!   but a handful stripped, and every access check done twice, once for the
//!   user and once for the container. The container half only passes for an
//!   object whose DACL names the container's SID (or "ALL APPLICATION
//!   PACKAGES", which the system directories grant read and execute). The
//!   operator's profile, other users' files and every path the spec did not
//!   grant fail that half.
//! - **Grants are ACEs.** Each granted path gets an allow ACE for the
//!   container SID (read and execute, or read/write/delete for a writable
//!   path), inherited by everything below a directory. A path the system
//!   already lets every AppContainer read is left alone, so the helper never
//!   rewrites the ACL of `C:\Windows` or `C:\Program Files`; a read-only path
//!   whose ACL the operator may not change is skipped too — the child simply
//!   cannot read it, which is the safe side.
//! - **Container per grant set.** The container name is a hash of the grants
//!   and the network mode, so the ACEs of one launch are exactly right for
//!   the next launch with the same grants and never reach a launch with
//!   different ones. The ACEs and the container profile therefore stay after
//!   the child exits (rewriting a workspace's ACL at every launch would cost a
//!   walk of the whole tree): what remains is access for a SID only another
//!   launch with the same grants runs as.
//! - **Network.** With [`Network::Blocked`] the token carries no capability,
//!   and the Windows Filtering Platform drops every socket the container
//!   opens, loopback included. [`Network::Allowed`] adds the
//!   `internetClient`, `internetClientServer` and `privateNetworkClientServer`
//!   capabilities and exempts the container from loopback isolation so the
//!   host's `127.0.0.1` is reachable as on Linux and macOS. The exemption is
//!   a machine setting that needs an elevated helper; without it the child
//!   still has the network, only not the host's loopback.
//! - **Job Object.** The target starts suspended, joins a job that kills
//!   every process in it when the helper goes away (the helper killed
//!   included, like `--die-with-parent`) and that has no access to other
//!   processes' windows, the clipboard, global atoms or system settings; only
//!   then does it resume.
//! - **Environment.** Exactly the kept variables, as the child's environment
//!   block — nothing of the helper's. Windows programs usually need
//!   `SystemRoot` (Winsock does not start without it); the spec has to name
//!   it, as it names `PATH`.
//!
//! The unsafe Win32 calls live in [`win32`], and only there.

#[cfg(windows)]
mod win32;

use std::path::Path;

use crate::{Network, Resolved};

/// Prefix of every container this backend creates.
const NAME_PREFIX: &str = "bastion.sandbox.";

/// SID strings of the capabilities [`Network::Allowed`] adds.
#[cfg_attr(not(windows), allow(dead_code))]
const NETWORK_CAPABILITIES: &[&str] = &[
    "S-1-15-3-1", // internetClient
    "S-1-15-3-2", // internetClientServer
    "S-1-15-3-3", // privateNetworkClientServer
];

/// "ALL APPLICATION PACKAGES": ACEs for it reach every AppContainer.
#[cfg_attr(not(windows), allow(dead_code))]
const ALL_APPLICATION_PACKAGES: &str = "S-1-15-2-1";

/// Container name for a launch: stable for the same grants and network mode,
/// different otherwise. FNV-1a, spelled out so it never changes with the
/// toolchain (a new name would leave the old ACEs behind for nothing).
pub(crate) fn container_name(network: Network, resolved: &Resolved) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes.iter().chain([0u8].iter()) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    feed(match network {
        Network::Blocked => b"net:blocked",
        Network::Allowed => b"net:allowed",
    });
    for (tag, paths) in [
        (&b"ro"[..], &resolved.read_only),
        (&b"rw"[..], &resolved.read_write),
    ] {
        for path in paths {
            feed(tag);
            feed(path.to_string_lossy().as_bytes());
        }
    }
    format!("{NAME_PREFIX}{hash:016x}")
}

/// Appends `arg` to a command line the way the Microsoft C runtime (and so
/// nearly every Windows program) splits it back: quoted when it holds a
/// space, a tab or a quote, backslashes doubled only before a quote.
pub(crate) fn append_arg(line: &mut Vec<u16>, arg: &[u16]) {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    if !line.is_empty() {
        line.push(u16::from(b' '));
    }
    let plain = !arg.is_empty()
        && !arg
            .iter()
            .any(|&c| c == u16::from(b' ') || c == u16::from(b'\t') || c == QUOTE);
    if plain {
        line.extend_from_slice(arg);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0;
    for &c in arg {
        if c == BACKSLASH {
            backslashes += 1;
        } else {
            if c == QUOTE {
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(c);
    }
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
    line.push(QUOTE);
}

/// A Unicode environment block: `NAME=value` entries, each NUL-terminated,
/// then one more NUL. Names are sorted case-insensitively, as Windows keeps
/// them.
pub(crate) fn environment_block(vars: &[(Vec<u16>, Vec<u16>)]) -> Result<Vec<u16>, String> {
    let mut sorted: Vec<&(Vec<u16>, Vec<u16>)> = vars.iter().collect();
    sorted.sort_by_key(|(name, _)| String::from_utf16_lossy(name).to_uppercase());
    let mut block = Vec::new();
    for (name, value) in sorted {
        if name.is_empty() || name.contains(&u16::from(b'=')) || name.contains(&0) {
            return Err(format!(
                "invalid environment variable name {:?}",
                String::from_utf16_lossy(name)
            ));
        }
        if value.contains(&0) {
            return Err(format!(
                "environment variable {} contains a NUL",
                String::from_utf16_lossy(name)
            ));
        }
        block.extend_from_slice(name);
        block.push(u16::from(b'='));
        block.extend_from_slice(value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// Access rights of a read-only and of a writable grant. Writable grants
/// leave out `WRITE_DAC` and `WRITE_OWNER`: the child may change files, not
/// who else may.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod rights {
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
    pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00a0;
    pub const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    pub const DELETE: u32 = 0x0001_0000;
    pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;

    pub const READ: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    pub const READ_WRITE: u32 = READ | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;

    /// Generic bits of an ACE mask replaced by the file rights they stand for.
    pub fn map_generic(mask: u32) -> u32 {
        let mut mapped = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
        if mask & GENERIC_READ != 0 {
            mapped |= FILE_GENERIC_READ;
        }
        if mask & GENERIC_WRITE != 0 {
            mapped |= FILE_GENERIC_WRITE;
        }
        if mask & GENERIC_EXECUTE != 0 {
            mapped |= FILE_GENERIC_EXECUTE;
        }
        if mask & GENERIC_ALL != 0 {
            mapped |= FILE_ALL_ACCESS;
        }
        mapped
    }
}

/// `C:\x` for `\\?\C:\x` and `\\server\share` for `\\?\UNC\server\share`,
/// which is what `canonicalize` returns on Windows: `cmd.exe` refuses a
/// verbatim working directory, and many programs mishandle a verbatim path to
/// themselves. Anything else is returned as is.
pub(crate) fn plain_path(path: &Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}").into();
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return rest.into();
        }
    }
    path.to_path_buf()
}

/// Runs `program` confined and exits with its status. Returns only on
/// failure, like `exec`.
#[cfg(windows)]
pub(crate) fn run(
    network: Network,
    resolved: &Resolved,
    args: &[std::ffi::OsString],
    env: &[(String, std::ffi::OsString)],
) -> String {
    match launch(network, resolved, args, env) {
        Ok(code) => std::process::exit(code as i32),
        Err(e) => e,
    }
}

#[cfg(windows)]
fn launch(
    network: Network,
    resolved: &Resolved,
    args: &[std::ffi::OsString],
    env: &[(String, std::ffi::OsString)],
) -> Result<u32, String> {
    use std::os::windows::ffi::OsStrExt;

    let wide = |s: &std::ffi::OsStr| s.encode_wide().collect::<Vec<u16>>();

    let container = win32::Sid::app_container(&container_name(network, resolved))?;
    let everyone_app = win32::Sid::from_string(ALL_APPLICATION_PACKAGES)?;
    for path in &resolved.read_only {
        grant(path, &container, &everyone_app, rights::READ, false)?;
    }
    for path in &resolved.read_write {
        grant(path, &container, &everyone_app, rights::READ_WRITE, true)?;
    }

    let capabilities = match network {
        Network::Blocked => Vec::new(),
        Network::Allowed => {
            // Best effort: without elevation the child keeps the network
            // but not the host's loopback (see the module docs).
            let _ = win32::exempt_from_loopback_isolation(&container);
            NETWORK_CAPABILITIES
                .iter()
                .map(|sid| win32::Sid::from_string(sid))
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    let mut command_line = Vec::new();
    append_arg(&mut command_line, &wide(resolved.program.as_os_str()));
    for arg in args {
        append_arg(&mut command_line, &wide(arg));
    }
    command_line.push(0);
    let vars: Vec<(Vec<u16>, Vec<u16>)> = env
        .iter()
        .map(|(name, value)| (name.encode_utf16().collect(), wide(value)))
        .collect();
    let environment = environment_block(&vars)?;

    let job = win32::Job::new()?;
    let child = win32::spawn_suspended(win32::Spawn {
        program: &resolved.program,
        command_line,
        environment: &environment,
        cwd: resolved.cwd.as_deref(),
        container: &container,
        capabilities: &capabilities,
    })?;
    if let Err(e) = job.assign(&child) {
        child.terminate();
        return Err(e);
    }
    child.resume()?;
    child.wait()
}

/// Gives the container `wanted` on `path` unless it has it already, through
/// its own SID or "ALL APPLICATION PACKAGES". `required` makes a refused ACL
/// change an error; otherwise the path is left unreadable for the child.
#[cfg(windows)]
fn grant(
    path: &Path,
    container: &win32::Sid,
    everyone_app: &win32::Sid,
    wanted: u32,
    required: bool,
) -> Result<(), String> {
    let granted = win32::allowed_rights(path, &[container, everyone_app])
        .map_err(|e| format!("reading the ACL of {}: {e}", path.display()))?;
    if granted & wanted == wanted {
        return Ok(());
    }
    match win32::add_allow_ace(path, container, wanted, path.is_dir()) {
        Ok(()) => Ok(()),
        Err(e) if !required && e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(format!("granting {} to the sandbox: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn line(args: &[&str]) -> String {
        let mut line = Vec::new();
        for arg in args {
            append_arg(&mut line, &utf16(arg));
        }
        String::from_utf16(&line).unwrap()
    }

    fn resolved(read_only: &[&str], read_write: &[&str]) -> Resolved {
        Resolved {
            program: PathBuf::from(r"C:\Windows\System32\cmd.exe"),
            cwd: None,
            read_only: read_only.iter().map(PathBuf::from).collect(),
            read_write: read_write.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn arguments_are_quoted_the_way_the_c_runtime_splits_them() {
        assert_eq!(line(&["a", "b"]), "a b");
        assert_eq!(
            line(&[r"C:\Program Files\x.exe", ""]),
            r#""C:\Program Files\x.exe" """#
        );
        assert_eq!(line(&["say \"hi\""]), r#""say \"hi\"""#);
        // Backslashes double only before a quote, the closing one included.
        assert_eq!(line(&[r"C:\dir\"]), r"C:\dir\");
        assert_eq!(line(&[r"C:\my dir\"]), r#""C:\my dir\\""#);
        assert_eq!(line(&[r#"a\"b"#]), r#""a\\\"b""#);
        assert_eq!(
            line(&["/c", "echo hi > out.txt"]),
            r#"/c "echo hi > out.txt""#
        );
    }

    #[test]
    fn the_environment_block_holds_exactly_the_given_variables() {
        let block = environment_block(&[
            (utf16("path"), utf16(r"C:\Windows")),
            (utf16("API_KEY"), utf16("v=1")),
        ])
        .unwrap();
        assert_eq!(
            String::from_utf16(&block).unwrap(),
            "API_KEY=v=1\0path=C:\\Windows\0\0"
        );
        assert_eq!(environment_block(&[]).unwrap(), [0, 0]);
        assert!(environment_block(&[(utf16("A=B"), utf16("x"))]).is_err());
        assert!(environment_block(&[(utf16(""), utf16("x"))]).is_err());
        assert!(environment_block(&[(utf16("A"), vec![b'x' as u16, 0])]).is_err());
    }

    #[test]
    fn the_container_follows_the_grants_and_the_network() {
        let base = container_name(Network::Blocked, &resolved(&[r"C:\ro"], &[r"C:\rw"]));
        assert!(base.starts_with(NAME_PREFIX));
        assert!(
            base.len() <= 64,
            "AppContainer names are at most 64 characters"
        );
        assert_eq!(
            base,
            container_name(Network::Blocked, &resolved(&[r"C:\ro"], &[r"C:\rw"]))
        );
        for other in [
            container_name(Network::Allowed, &resolved(&[r"C:\ro"], &[r"C:\rw"])),
            container_name(Network::Blocked, &resolved(&[r"C:\rw"], &[r"C:\ro"])),
            container_name(
                Network::Blocked,
                &resolved(&[r"C:\ro"], &[r"C:\rw", r"C:\x"]),
            ),
            container_name(Network::Blocked, &resolved(&[r"C:\ro", r"C:\rw"], &[])),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn verbatim_paths_become_plain_ones() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\Users\x")),
            PathBuf::from(r"C:\Users\x")
        );
        assert_eq!(
            plain_path(Path::new(r"\\?\UNC\srv\share\x")),
            PathBuf::from(r"\\srv\share\x")
        );
        assert_eq!(
            plain_path(Path::new(r"\\?\Volume{1}\x")),
            PathBuf::from(r"\\?\Volume{1}\x")
        );
        assert_eq!(plain_path(Path::new("/usr/bin")), PathBuf::from("/usr/bin"));
    }

    #[test]
    fn generic_rights_map_to_file_rights() {
        assert_eq!(
            rights::map_generic(rights::GENERIC_READ),
            rights::FILE_GENERIC_READ
        );
        assert_eq!(
            rights::map_generic(rights::GENERIC_READ | rights::GENERIC_EXECUTE) & rights::READ,
            rights::READ
        );
        assert_eq!(
            rights::map_generic(rights::GENERIC_ALL),
            rights::FILE_ALL_ACCESS
        );
        assert_eq!(rights::map_generic(rights::DELETE), rights::DELETE);
    }
}
