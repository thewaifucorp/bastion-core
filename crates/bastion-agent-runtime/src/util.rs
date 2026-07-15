//! Shared helpers for subprocess-transport adapters ([`crate::acpx`],
//! [`crate::codex`]): binary/interpreter resolution, digesting, and
//! structured-frame validation. No adapter-specific protocol knowledge here.

use crate::RuntimeError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Hex-encoded SHA-256 digest of `bytes`, without the `sha256:` prefix.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// `sha256:<hex>` digest of `bytes`, matching the [`crate::Artifact::digest`]
/// format verified by the conformance suite.
pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Resolves `name` to an absolute path by scanning the *caller's own*
/// process `PATH` (never the session's [`crate::EnvPolicy`] allowlist —
/// that would defeat the point of a clean child environment). Accepts an
/// already-absolute path as-is.
pub(crate) fn resolve_on_path(name: &str) -> Result<PathBuf, RuntimeError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return if candidate.is_file() {
            Ok(candidate.to_path_buf())
        } else {
            Err(RuntimeError::Unavailable(format!(
                "binary not found at absolute path: {}",
                candidate.display()
            )))
        };
    }
    let path_var = std::env::var_os("PATH")
        .ok_or_else(|| RuntimeError::Unavailable("PATH not set in host environment".to_string()))?;
    for dir in std::env::split_paths(&path_var) {
        let full = dir.join(name);
        if full.is_file() {
            return Ok(full);
        }
    }
    Err(RuntimeError::Unavailable(format!(
        "binary '{name}' not found on host PATH"
    )))
}

/// If `script` is a `#!`-interpreted script, returns the resolved absolute
/// path of its interpreter (e.g. `node`). Returns `Ok(None)` for native
/// binaries (ELF, no shebang) — those spawn directly. The interpreter itself
/// is resolved from the *caller's* PATH, exactly like [`resolve_on_path`],
/// so the child process never needs `PATH` in its own (allowlisted)
/// environment to be located.
pub(crate) fn resolve_shebang_interpreter(script: &Path) -> Result<Option<PathBuf>, RuntimeError> {
    use std::io::Read;
    let mut file = std::fs::File::open(script)
        .map_err(|e| RuntimeError::Unavailable(format!("cannot open {}: {e}", script.display())))?;
    let mut head = [0u8; 256];
    let n = file.read(&mut head).unwrap_or(0);
    let head = &head[..n];
    if !head.starts_with(b"#!") {
        return Ok(None);
    }
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[2..line_end]);
    let line = line.trim();
    // `#!/usr/bin/env <prog> [args]` — resolve <prog> from our own PATH.
    if let Some(rest) = line.strip_prefix("/usr/bin/env ") {
        let prog = rest.split_whitespace().next().unwrap_or(rest);
        return resolve_on_path(prog).map(Some);
    }
    // Direct interpreter path, e.g. `#!/usr/bin/node`.
    let direct = PathBuf::from(line.split_whitespace().next().unwrap_or(line));
    if direct.is_file() {
        Ok(Some(direct))
    } else {
        Err(RuntimeError::Unavailable(format!(
            "shebang interpreter not found: {line}"
        )))
    }
}

/// `true` when `version` satisfies `req` (a [`semver::VersionReq`] string
/// like `">=0.12.0, <0.13.0"`). Trailing non-numeric suffixes on `version`
/// (e.g. a git-describe tag) are tolerated by truncating at the first
/// component semver can't parse.
pub(crate) fn version_satisfies(version: &str, req: &str) -> Result<bool, RuntimeError> {
    let req = semver::VersionReq::parse(req)
        .map_err(|e| RuntimeError::Version(format!("bad version requirement {req:?}: {e}")))?;
    let parsed = semver::Version::parse(version.trim())
        .map_err(|e| RuntimeError::Version(format!("cannot parse version {version:?}: {e}")))?;
    Ok(req.matches(&parsed))
}

/// Rejects a candidate transport line as non-structured ("human stdout,
/// ANSI") per the A-01 threat model (T6): fail-closed, never interpreted as
/// content. A conforming line is non-empty, free of ANSI escape/control
/// bytes (other than trailing newline already stripped by the caller), and
/// parses as a JSON object.
pub(crate) fn parse_structured_line(line: &str) -> Result<serde_json::Value, RuntimeError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::Protocol("empty transport line".to_string()));
    }
    if trimmed.contains('\u{1b}') {
        return Err(RuntimeError::Protocol(
            "ANSI/control byte on structured transport".to_string(),
        ));
    }
    if !trimmed.starts_with('{') {
        return Err(RuntimeError::Protocol(format!(
            "non-JSON line on structured transport: {:.80}",
            trimmed
        )));
    }
    serde_json::from_str(trimmed)
        .map_err(|e| RuntimeError::Protocol(format!("malformed JSON frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_has_prefix_and_length() {
        let d = sha256_digest(b"hello");
        let hex = d.strip_prefix("sha256:").expect("prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_structured_line_rejects_ansi() {
        let line = "\u{1b}[32mok\u{1b}[0m";
        let err = parse_structured_line(line).unwrap_err();
        assert!(matches!(err, RuntimeError::Protocol(_)));
    }

    #[test]
    fn parse_structured_line_rejects_human_text() {
        let err = parse_structured_line("[acpx] created session foo").unwrap_err();
        assert!(matches!(err, RuntimeError::Protocol(_)));
    }

    #[test]
    fn parse_structured_line_rejects_truncated_json() {
        let err = parse_structured_line("{\"a\":").unwrap_err();
        assert!(matches!(err, RuntimeError::Protocol(_)));
    }

    #[test]
    fn parse_structured_line_accepts_json_object() {
        let v = parse_structured_line(r#"{"jsonrpc":"2.0","id":1}"#).expect("valid json");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn version_satisfies_range() {
        assert!(version_satisfies("0.12.0", ">=0.12.0, <0.13.0").unwrap());
        assert!(!version_satisfies("0.13.0", ">=0.12.0, <0.13.0").unwrap());
        assert!(!version_satisfies("0.11.9", ">=0.12.0, <0.13.0").unwrap());
    }
}
