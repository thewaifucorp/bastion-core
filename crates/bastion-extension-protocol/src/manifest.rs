//! Extension/pack manifests (design doc §1.1).

use crate::permission::PermissionSet;
use crate::trust::Signature;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Isolation mechanism a manifest's `entrypoint` runs under (design doc §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    /// Data only — skills, personas, triggers, config. No code runs.
    Declarative,
    /// WASM/WASI sandbox — no syscalls beyond what the host grants.
    Wasm,
    /// Separate OS process, `env_clear` + allowlist, versioned stdio protocol.
    Subprocess,
    /// Linked into the host binary. `official` trust tier only, human review.
    NativeCrate,
}

/// What an extension supplies to the host, tagged by kind with a
/// human/registry-facing name. NOT itself an authority grant — a `Provided`
/// entry only says the extension WANTS to supply this; whether it's allowed
/// to is decided by `PermissionSet` at registration time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum Provided {
    Provider(String),
    Channel(String),
    Capability(String),
    Memory(String),
    Cognition(String),
    Trigger(String),
    Ui(String),
    Service(String),
    Policy(String),
}

impl Provided {
    /// The capability name this entry declares, if it is a `Capability`
    /// variant — used to validate `manifest.provides` against
    /// `manifest.permissions.capabilities` at install time.
    pub fn as_capability_name(&self) -> Option<&str> {
        match self {
            Provided::Capability(name) => Some(name.as_str()),
            _ => None,
        }
    }
}

/// A dependency on another extension, by id and compatible version range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    pub id: String,
    pub version: VersionReq,
}

/// Reference to a secret BY NAME — never a value. Resolution (where the
/// actual secret material lives, how it's injected) is a host/product
/// concern outside this contracts crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub name: String,
}

/// Per-kind entrypoint description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entrypoint {
    Declarative { artifact_path: PathBuf },
    Wasm { module_path: PathBuf },
    Subprocess { command: String, args: Vec<String> },
    NativeCrate { crate_name: String },
}

impl Entrypoint {
    /// The `ExtensionKind` this entrypoint variant corresponds to — used to
    /// validate `manifest.kind` against `manifest.entrypoint` agree (a
    /// manifest cannot claim `kind: Wasm` with a `Subprocess` entrypoint).
    pub fn kind(&self) -> ExtensionKind {
        match self {
            Entrypoint::Declarative { .. } => ExtensionKind::Declarative,
            Entrypoint::Wasm { .. } => ExtensionKind::Wasm,
            Entrypoint::Subprocess { .. } => ExtensionKind::Subprocess,
            Entrypoint::NativeCrate { .. } => ExtensionKind::NativeCrate,
        }
    }
}

/// A migration reference — data only; execution is a host concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRef {
    pub from_version: Version,
    pub description: String,
}

/// Extension manifest (design doc §1.1). Contracts only — parsing/loading a
/// manifest file from disk is a host concern; this type is the validated
/// in-memory shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    /// `"publisher/name"` — namespaced globally.
    pub id: String,
    pub version: Version,
    pub kind: ExtensionKind,
    /// Range of `bastion-extension-protocol` versions this extension
    /// supports — checked against the host's own protocol version before
    /// install/upgrade.
    pub compat: VersionReq,
    pub provides: Vec<Provided>,
    pub requires: Vec<Requirement>,
    /// Declared, reviewable authority (§1.2). Deny-by-default — never
    /// implicit.
    pub permissions: PermissionSet,
    pub secrets: Vec<SecretRef>,
    pub entrypoint: Entrypoint,
    pub migrations: Vec<MigrationRef>,
    /// `None` = unsigned, always resolves to `TrustTier::Local`.
    pub signature: Option<Signature>,
}

impl ExtensionManifest {
    /// Structural self-consistency: `kind` must agree with `entrypoint`, and
    /// every `Provided::Capability(name)` in `provides` must also appear in
    /// `permissions.capabilities` — a manifest cannot even ADVERTISE
    /// providing a capability it hasn't declared permission for. This is a
    /// pure, zero-I/O sanity check; the host runs it before ever
    /// instantiating a mechanism for this manifest.
    pub fn validate_self_consistent(&self) -> Result<(), crate::error::ExtensionError> {
        if self.entrypoint.kind() != self.kind {
            return Err(crate::error::ExtensionError::InvalidManifest {
                id: self.id.clone(),
                reason: format!(
                    "declared kind {:?} does not match entrypoint kind {:?}",
                    self.kind,
                    self.entrypoint.kind()
                ),
            });
        }
        for provided in &self.provides {
            if let Some(name) = provided.as_capability_name() {
                if !self.permissions.allows_capability(name) {
                    return Err(crate::error::ExtensionError::InvalidManifest {
                        id: self.id.clone(),
                        reason: format!(
                            "provides capability '{name}' but permissions.capabilities does not declare it"
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Guided defaults a `Pack` resolves into on activation — data only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadoutDefaults {
    /// Extension ids enabled by default when the pack is activated.
    pub enabled_extensions: Vec<String>,
}

/// Pack manifest (design doc §1.1). A pack COMPOSES extensions/skills/personas
/// — it never gains authority of its own; every member extension is still
/// individually bounded by the instance's grant ceiling (§4, §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackManifest {
    pub id: String,
    pub version: Version,
    pub extensions: Vec<(String, VersionReq)>,
    pub skills: Vec<String>,
    pub personas: Vec<String>,
    pub defaults: LoadoutDefaults,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::PermissionSet;

    fn manifest_with(
        kind: ExtensionKind,
        entrypoint: Entrypoint,
        provides: Vec<Provided>,
        capabilities: Vec<String>,
    ) -> ExtensionManifest {
        ExtensionManifest {
            id: "acme/widget".to_string(),
            version: Version::new(1, 0, 0),
            kind,
            compat: VersionReq::parse("^0.1").unwrap(),
            provides,
            requires: vec![],
            permissions: PermissionSet {
                capabilities,
                ..PermissionSet::none()
            },
            secrets: vec![],
            entrypoint,
            migrations: vec![],
            signature: None,
        }
    }

    #[test]
    fn self_consistent_manifest_validates() {
        let m = manifest_with(
            ExtensionKind::Declarative,
            Entrypoint::Declarative {
                artifact_path: "widget.json".into(),
            },
            vec![Provided::Capability("widget:read".to_string())],
            vec!["widget:read".to_string()],
        );
        assert!(m.validate_self_consistent().is_ok());
    }

    #[test]
    fn kind_entrypoint_mismatch_rejected() {
        let m = manifest_with(
            ExtensionKind::Wasm,
            Entrypoint::Declarative {
                artifact_path: "widget.json".into(),
            },
            vec![],
            vec![],
        );
        assert!(m.validate_self_consistent().is_err());
    }

    #[test]
    fn provides_capability_without_permission_rejected() {
        let m = manifest_with(
            ExtensionKind::Declarative,
            Entrypoint::Declarative {
                artifact_path: "widget.json".into(),
            },
            vec![Provided::Capability("widget:read".to_string())],
            vec![], // permission NOT declared
        );
        assert!(m.validate_self_consistent().is_err());
    }
}
