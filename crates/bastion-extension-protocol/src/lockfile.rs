//! Reproducible loadout lockfile (`loadout.lock`, design doc §3): id+version+
//! hash+signature per component. Pure data + a pure hashing helper — the file
//! I/O (reading/writing `loadout.lock`) is a host concern.

use crate::trust::Signature;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One resolved, locked component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEntry {
    pub id: String,
    pub version: Version,
    /// `sha256:<hex>` digest of the resolved manifest/artifact bytes —
    /// mirrors `bastion_agent_runtime::Artifact.digest`'s convention.
    pub hash: String,
    pub signature: Option<Signature>,
}

/// The full reproducible lock for a `Loadout`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadoutLock {
    pub entries: Vec<LockEntry>,
}

impl LoadoutLock {
    pub fn find(&self, id: &str) -> Option<&LockEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Insert or replace the entry for `entry.id`.
    pub fn upsert(&mut self, entry: LockEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.id == entry.id) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn remove(&mut self, id: &str) -> Option<LockEntry> {
        let idx = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(idx))
    }
}

/// `sha256:<hex>` digest of arbitrary bytes — the sole hashing convention
/// `LockEntry.hash` uses.
pub fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_content_addressed() {
        let a = digest_hex(b"hello");
        let b = digest_hex(b"hello");
        let c = digest_hex(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn upsert_replaces_existing_entry_by_id() {
        let mut lock = LoadoutLock::default();
        lock.upsert(LockEntry {
            id: "acme/widget".to_string(),
            version: Version::new(1, 0, 0),
            hash: digest_hex(b"v1"),
            signature: None,
        });
        lock.upsert(LockEntry {
            id: "acme/widget".to_string(),
            version: Version::new(2, 0, 0),
            hash: digest_hex(b"v2"),
            signature: None,
        });
        assert_eq!(lock.entries.len(), 1);
        assert_eq!(
            lock.find("acme/widget").unwrap().version,
            Version::new(2, 0, 0)
        );
    }

    #[test]
    fn remove_returns_removed_entry() {
        let mut lock = LoadoutLock::default();
        lock.upsert(LockEntry {
            id: "acme/widget".to_string(),
            version: Version::new(1, 0, 0),
            hash: digest_hex(b"v1"),
            signature: None,
        });
        let removed = lock.remove("acme/widget");
        assert!(removed.is_some());
        assert!(lock.find("acme/widget").is_none());
    }
}
