//! `ContentDigests` — the per-file digests a signature covers.
//!
//! [`ContentDigests::from_dir`] is the one definition of "the bytes a
//! publisher shipped" that both the signing tool and the verifying host use,
//! so the two can never disagree on which files count. It reads files and
//! nothing else: no network, no state, no product I/O.

use crate::error::ExtensionError;
use crate::lockfile::digest_hex;
use crate::trust::SIGNATURE_FILE_SUFFIX;
use std::collections::BTreeMap;
use std::path::Path;

/// Relative path (`/`-separated) → `sha256:<hex>` of the file's bytes,
/// ordered by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentDigests(BTreeMap<String, String>);

impl ContentDigests {
    /// No files.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `bytes` under `path`, replacing any previous entry. `path` must
    /// be relative, `/`-separated, without `.`/`..`/empty segments and
    /// without control characters.
    pub fn insert(&mut self, path: &str, bytes: &[u8]) -> Result<(), ExtensionError> {
        validate_path(path)?;
        self.0.insert(path.to_string(), digest_hex(bytes));
        Ok(())
    }

    /// `(path, digest)` pairs in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(p, d)| (p.as_str(), d.as_str()))
    }

    /// Digest recorded for `path`.
    pub fn get(&self, path: &str) -> Option<&str> {
        self.0.get(path).map(String::as_str)
    }

    /// Number of files.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no file is recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Digest every regular file under `root`, recursively. Files whose name
    /// ends in [`SIGNATURE_FILE_SUFFIX`] are skipped (a signature cannot
    /// cover itself). Hidden files are included: what ships is what is
    /// signed. A symlink, a non-UTF-8 name or an unreadable entry fails the
    /// whole walk — content that cannot be pinned is never silently left
    /// out.
    pub fn from_dir(root: &Path) -> Result<Self, ExtensionError> {
        let mut out = Self::new();
        walk(root, root, &mut out)?;
        Ok(out)
    }
}

fn unreadable(path: &Path, detail: impl ToString) -> ExtensionError {
    ExtensionError::ContentUnreadable {
        path: path.display().to_string(),
        detail: detail.to_string(),
    }
}

fn walk(root: &Path, dir: &Path, out: &mut ContentDigests) -> Result<(), ExtensionError> {
    let entries = std::fs::read_dir(dir).map_err(|e| unreadable(dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| unreadable(dir, e))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| unreadable(&path, e))?;
        if file_type.is_symlink() {
            return Err(unreadable(&path, "symlinks cannot be signed"));
        }
        if file_type.is_dir() {
            walk(root, &path, out)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(unreadable(&path, "not a regular file"));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|e| unreadable(&path, e))?
            .components()
            .map(|c| c.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| unreadable(&path, "file name is not valid UTF-8"))?
            .join("/");
        if relative.ends_with(SIGNATURE_FILE_SUFFIX) {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| unreadable(&path, e))?;
        out.insert(&relative, &bytes)?;
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ExtensionError> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        return Err(ExtensionError::ContentUnreadable {
            path: path.to_string(),
            detail: "not a normalized relative path".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bep-content-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn walks_recursively_and_skips_signature_files() {
        let dir = tempdir();
        std::fs::write(dir.join("pack.toml"), "id = 1").unwrap();
        std::fs::write(dir.join("pack.toml.sig"), "sig").unwrap();
        std::fs::create_dir_all(dir.join("skills/a")).unwrap();
        std::fs::write(dir.join("skills/a/SKILL.md"), "# a").unwrap();
        std::fs::write(dir.join(".hidden"), "h").unwrap();

        let c = ContentDigests::from_dir(&dir).unwrap();
        let paths: Vec<&str> = c.iter().map(|(p, _)| p).collect();
        assert_eq!(paths, vec![".hidden", "pack.toml", "skills/a/SKILL.md"]);
        assert_eq!(
            c.get("skills/a/SKILL.md"),
            Some(digest_hex(b"# a").as_str())
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_dir_is_an_error() {
        let err = ContentDigests::from_dir(Path::new("/definitely/not/here")).unwrap_err();
        assert!(matches!(err, ExtensionError::ContentUnreadable { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        let dir = tempdir();
        std::fs::write(dir.join("real"), "x").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        assert!(ContentDigests::from_dir(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn insert_rejects_non_normalized_paths() {
        let mut c = ContentDigests::new();
        for bad in ["", "/abs", "a/../b", "a//b", "./a", "a\\b", "a\nb"] {
            assert!(c.insert(bad, b"x").is_err(), "{bad:?} must be refused");
        }
        assert!(c.insert("a/b.txt", b"x").is_ok());
        assert_eq!(c.len(), 1);
    }
}
