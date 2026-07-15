//! `PermissionSet` — declared, deny-by-default authority an extension may use
//! (`docs/revamp/C3-extension-protocol-design.md` §1.2).
//!
//! REGRA-MÃE (design doc §0/§1): installing an extension NEVER grants
//! authority by itself. Every field here is something the HOST checks before
//! acting on the extension's behalf — nothing here is self-enforcing. See
//! `ExtensionHost`/`HostFacade` (app-level, `src/extension/`) for the actual
//! enforcement chokepoint; this module only carries the DATA and the pure
//! (zero I/O) decision logic both the host and its tests consult.
//!
//! Every `allows_*`/`is_subset_of` method here is intentionally exhaustive-matched
//! (no wildcard `_ => false` catch-all) so that adding a new variant to any of
//! these enums forces the compiler to make every call site re-decide its
//! answer — silent fail-open by omission is a compile error, not a runtime gap.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Outbound network authority. Deny-by-default: `None` (no field on the
/// manifest, or explicit `EgressScope::None`) means the extension may not
/// reach any host at all through the host-mediated egress path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressScope {
    /// No outbound network access.
    #[default]
    None,
    /// Loopback / local-network destinations only (mirrors the kernel's
    /// `PrivacyTier::LocalOnly` intent — never a cloud host).
    LocalOnly,
    /// Exactly these hostnames, and nothing else. An extension declaring
    /// `Hosts(["api.x.com"])` can reach `api.x.com` only — the host's
    /// `check_egress_host` denies every other destination, including
    /// subdomains, unless separately listed.
    Hosts(Vec<String>),
}

impl EgressScope {
    /// Whether `host` is reachable under this scope.
    pub fn allows_host(&self, host: &str) -> bool {
        match self {
            EgressScope::None => false,
            EgressScope::LocalOnly => matches!(host, "localhost" | "127.0.0.1" | "::1"),
            EgressScope::Hosts(hosts) => hosts.iter().any(|h| h == host),
        }
    }

    /// `self` (the extension's request) never exceeds `ceiling` (the
    /// instance's grant). Used both for install-time ceiling checks and for
    /// pack authority checks (design doc §4/§6, acceptance criterion 4).
    ///
    /// `LocalOnly` and `Hosts(_)` are treated as DIFFERENT dimensions (loopback
    /// vs. named external hosts), never automatically comparable — fail-closed
    /// on any combination not explicitly known to be safe.
    pub fn is_subset_of(&self, ceiling: &EgressScope) -> bool {
        match (self, ceiling) {
            (EgressScope::None, _) => true,
            (EgressScope::LocalOnly, EgressScope::None) => false,
            (EgressScope::LocalOnly, EgressScope::LocalOnly) => true,
            (EgressScope::LocalOnly, EgressScope::Hosts(_)) => false,
            (EgressScope::Hosts(_), EgressScope::None) => false,
            (EgressScope::Hosts(_), EgressScope::LocalOnly) => false,
            (EgressScope::Hosts(want), EgressScope::Hosts(have)) => {
                want.iter().all(|h| have.contains(h))
            }
        }
    }
}

/// Filesystem authority. Deny-by-default: `None` means no filesystem access
/// through the host-mediated path at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsScope {
    #[default]
    None,
    WorkspaceRo,
    WorkspaceRw,
    Paths(Vec<PathBuf>),
}

impl FsScope {
    pub fn is_subset_of(&self, ceiling: &FsScope) -> bool {
        match (self, ceiling) {
            (FsScope::None, _) => true,
            (FsScope::WorkspaceRo, FsScope::None) => false,
            (FsScope::WorkspaceRo, FsScope::WorkspaceRo) => true,
            (FsScope::WorkspaceRo, FsScope::WorkspaceRw) => true,
            (FsScope::WorkspaceRo, FsScope::Paths(_)) => false,
            (FsScope::WorkspaceRw, FsScope::None) => false,
            (FsScope::WorkspaceRw, FsScope::WorkspaceRo) => false,
            (FsScope::WorkspaceRw, FsScope::WorkspaceRw) => true,
            (FsScope::WorkspaceRw, FsScope::Paths(_)) => false,
            (FsScope::Paths(_), FsScope::None) => false,
            (FsScope::Paths(_), FsScope::WorkspaceRo) => false,
            (FsScope::Paths(_), FsScope::WorkspaceRw) => false,
            (FsScope::Paths(want), FsScope::Paths(have)) => want.iter().all(|p| have.contains(p)),
        }
    }
}

/// Device classes an extension may request (audio/video/serial/...).
/// `#[non_exhaustive]`-equivalent openness via a catch-all `Other(String)` —
/// new device kinds don't need a protocol-crate release to be declarable, but
/// `is_subset_of`/enforcement still compares by exact match, never by name
/// pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Audio,
    Video,
    Serial,
    Other(String),
}

/// Memory authority. `None` (default) means an extension cannot read or write
/// belief/memory data through the host-mediated path at all. Read/write is
/// ALWAYS scoped to the extension's own owner — there is no cross-owner
/// variant to request; the host enforces the owner match independent of this
/// enum (see [`PermissionSet::allows_memory_read`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScope {
    #[default]
    None,
    ReadOwn,
    ReadWriteOwn,
}

impl MemoryScope {
    fn rank(self) -> u8 {
        match self {
            MemoryScope::None => 0,
            MemoryScope::ReadOwn => 1,
            MemoryScope::ReadWriteOwn => 2,
        }
    }

    pub fn is_subset_of(&self, ceiling: &MemoryScope) -> bool {
        self.rank() <= ceiling.rank()
    }
}

/// Declared, reviewable permission grant (design doc §1.2). Deny-by-default in
/// every field — an extension with a default-constructed `PermissionSet` can
/// register no capability, reach no host, touch no file, open no device, bind
/// no socket, and read no memory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionSet {
    /// Capability NAMES this extension may register/invoke through the
    /// registry. The host checks this at registration time — an extension
    /// cannot register a capability outside this list, regardless of what its
    /// manifest's `provides` field claims (`docs/revamp/C3-extension-protocol-design.md`
    /// §1.2: "enforcement no host, não confiança").
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub egress: EgressScope,
    #[serde(default)]
    pub filesystem: FsScope,
    #[serde(default)]
    pub devices: Vec<DeviceKind>,
    #[serde(default)]
    pub network_bind: bool,
    #[serde(default)]
    pub memory_scope: MemoryScope,
}

impl PermissionSet {
    /// Empty, deny-everything grant — the safe default for an unreviewed
    /// extension and the zero value used by `Default`.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn allows_capability(&self, name: &str) -> bool {
        self.capabilities.iter().any(|c| c == name)
    }

    pub fn allows_egress_host(&self, host: &str) -> bool {
        self.egress.allows_host(host)
    }

    pub fn allows_network_bind(&self) -> bool {
        self.network_bind
    }

    /// Memory read is granted ONLY when `memory_scope` allows reading AND the
    /// requesting owner matches the target owner — cross-owner is never
    /// expressible via `memory_scope` alone (design doc §1.2: "NUNCA
    /// cross-owner").
    pub fn allows_memory_read(&self, requester_owner: &str, target_owner: &str) -> bool {
        matches!(
            self.memory_scope,
            MemoryScope::ReadOwn | MemoryScope::ReadWriteOwn
        ) && requester_owner == target_owner
    }

    pub fn allows_memory_write(&self, requester_owner: &str, target_owner: &str) -> bool {
        matches!(self.memory_scope, MemoryScope::ReadWriteOwn) && requester_owner == target_owner
    }

    /// Whether every authority in `self` is also present in `ceiling`. The
    /// core check behind "a pack/extension cannot ask for more than the
    /// instance grants" (design doc §4, acceptance criterion 4) and behind
    /// "an extension's own declared permissions cannot exceed the instance
    /// ceiling at install time".
    pub fn is_subset_of(&self, ceiling: &PermissionSet) -> bool {
        self.capabilities
            .iter()
            .all(|c| ceiling.capabilities.iter().any(|k| k == c))
            && self.egress.is_subset_of(&ceiling.egress)
            && self.filesystem.is_subset_of(&ceiling.filesystem)
            && self.devices.iter().all(|d| ceiling.devices.contains(d))
            && (!self.network_bind || ceiling.network_bind)
            && self.memory_scope.is_subset_of(&ceiling.memory_scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_permission_set_denies_everything() {
        let p = PermissionSet::none();
        assert!(!p.allows_capability("anything"));
        assert!(!p.allows_egress_host("api.x.com"));
        assert!(!p.allows_egress_host("localhost"));
        assert!(!p.allows_network_bind());
        assert!(!p.allows_memory_read("alice", "alice"));
        assert!(!p.allows_memory_write("alice", "alice"));
    }

    #[test]
    fn egress_hosts_scope_allows_only_declared_hosts() {
        let scope = EgressScope::Hosts(vec!["api.x.com".to_string()]);
        assert!(scope.allows_host("api.x.com"));
        assert!(!scope.allows_host("evil.com"));
        assert!(!scope.allows_host("sub.api.x.com"));
    }

    #[test]
    fn egress_local_only_allows_loopback_not_named_hosts() {
        let scope = EgressScope::LocalOnly;
        assert!(scope.allows_host("localhost"));
        assert!(scope.allows_host("127.0.0.1"));
        assert!(!scope.allows_host("api.x.com"));
    }

    #[test]
    fn memory_scope_read_own_denies_cross_owner() {
        let p = PermissionSet {
            memory_scope: MemoryScope::ReadOwn,
            ..PermissionSet::none()
        };
        assert!(p.allows_memory_read("alice", "alice"));
        assert!(!p.allows_memory_read("alice", "bob"));
        assert!(
            !p.allows_memory_write("alice", "alice"),
            "ReadOwn must not grant write"
        );
    }

    #[test]
    fn memory_scope_read_write_own_still_denies_cross_owner() {
        let p = PermissionSet {
            memory_scope: MemoryScope::ReadWriteOwn,
            ..PermissionSet::none()
        };
        assert!(p.allows_memory_write("alice", "alice"));
        assert!(!p.allows_memory_write("alice", "bob"));
        assert!(!p.allows_memory_read("alice", "bob"));
    }

    #[test]
    fn permission_subset_true_when_within_ceiling() {
        let ceiling = PermissionSet {
            capabilities: vec!["fetch".to_string(), "notify".to_string()],
            egress: EgressScope::Hosts(vec!["api.x.com".to_string(), "cdn.x.com".to_string()]),
            filesystem: FsScope::WorkspaceRw,
            devices: vec![DeviceKind::Audio],
            network_bind: true,
            memory_scope: MemoryScope::ReadWriteOwn,
        };
        let requested = PermissionSet {
            capabilities: vec!["fetch".to_string()],
            egress: EgressScope::Hosts(vec!["api.x.com".to_string()]),
            filesystem: FsScope::WorkspaceRo,
            devices: vec![],
            network_bind: false,
            memory_scope: MemoryScope::ReadOwn,
        };
        assert!(requested.is_subset_of(&ceiling));
    }

    #[test]
    fn permission_subset_false_when_exceeding_ceiling_capability() {
        let ceiling = PermissionSet {
            capabilities: vec!["fetch".to_string()],
            ..PermissionSet::none()
        };
        let requested = PermissionSet {
            capabilities: vec!["fetch".to_string(), "delete_everything".to_string()],
            ..PermissionSet::none()
        };
        assert!(!requested.is_subset_of(&ceiling));
    }

    #[test]
    fn permission_subset_false_when_exceeding_ceiling_network_bind() {
        let ceiling = PermissionSet::none();
        let requested = PermissionSet {
            network_bind: true,
            ..PermissionSet::none()
        };
        assert!(!requested.is_subset_of(&ceiling));
    }

    #[test]
    fn permission_subset_false_when_egress_hosts_exceed_ceiling_hosts() {
        let ceiling = PermissionSet {
            egress: EgressScope::Hosts(vec!["api.x.com".to_string()]),
            ..PermissionSet::none()
        };
        let requested = PermissionSet {
            egress: EgressScope::Hosts(vec!["api.x.com".to_string(), "evil.com".to_string()]),
            ..PermissionSet::none()
        };
        assert!(!requested.is_subset_of(&ceiling));
    }

    #[test]
    fn permission_subset_local_only_never_implied_by_hosts_ceiling() {
        // LocalOnly and Hosts(_) are different dimensions — a ceiling granting
        // named external hosts does NOT imply loopback access is safe to assume,
        // and vice versa. Both directions must fail closed.
        let ceiling = PermissionSet {
            egress: EgressScope::Hosts(vec!["api.x.com".to_string()]),
            ..PermissionSet::none()
        };
        let requested = PermissionSet {
            egress: EgressScope::LocalOnly,
            ..PermissionSet::none()
        };
        assert!(!requested.is_subset_of(&ceiling));
    }
}
