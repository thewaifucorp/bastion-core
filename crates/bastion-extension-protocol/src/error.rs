//! Typed extension-protocol failures (design doc §8, acceptance criterion 3:
//! every blocked adversarial vector must surface a TYPED error, never a
//! generic string/bool). `#[non_exhaustive]` like `bastion_types::BastionError` —
//! callers match specific variants via `downcast_ref`/direct match, new
//! variants never silently widen an existing `match`'s catch-all.

use semver::{Version, VersionReq};

#[non_exhaustive]
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum ExtensionError {
    /// Adversarial vector (a): an extension tried to register a capability
    /// name outside its declared `PermissionSet.capabilities`.
    #[error("extension '{extension}' attempted to register undeclared capability '{capability}'")]
    CapabilityNotDeclared {
        extension: String,
        capability: String,
    },

    /// A capability name is already owned by another installed extension (or
    /// a kernel/builtin capability) — never silently overwritten.
    #[error("capability '{capability}' is already registered (owner: '{owner}')")]
    CapabilityCollision { capability: String, owner: String },

    /// Adversarial vector (b): an extension tried to reach a host outside its
    /// declared `PermissionSet.egress`.
    #[error("extension '{extension}' attempted egress to undeclared host '{host}'")]
    EgressHostNotGranted { extension: String, host: String },

    /// Adversarial vector (c): an extension tried to read/write memory
    /// belonging to an owner other than the one it is running for.
    #[error(
        "extension '{extension}' attempted cross-owner memory access (requester='{requester}', target='{target}')"
    )]
    MemoryCrossOwnerDenied {
        extension: String,
        requester: String,
        target: String,
    },

    /// Adversarial vector (d): an extension tried to open a listening socket
    /// without `PermissionSet.network_bind`.
    #[error("extension '{extension}' attempted to bind a network socket without network_bind permission")]
    NetworkBindNotGranted { extension: String },

    /// Install/upgrade blocked: the manifest's own declared `permissions`
    /// exceed the instance's grant ceiling, OR (pack composition, design doc
    /// §4/§6, acceptance criterion 4) a pack asks one of its member
    /// extensions to run with more authority than the instance has.
    #[error(
        "extension '{extension}' requests authority exceeding the instance grant (pack: {pack:?})"
    )]
    AuthorityEscalation {
        extension: String,
        /// `Some(pack_id)` when the escalation was discovered while resolving
        /// a pack; `None` for a direct single-extension install.
        pack: Option<String>,
    },

    /// Acceptance criterion 5: an upgrade whose new version breaks a
    /// dependent's declared requirement (or falls outside the protocol's own
    /// `compat` range) is rejected BEFORE the active loadout is touched.
    #[error("upgrade of '{id}' to {found} is incompatible with required range '{required}' (dependent: {dependent:?})")]
    IncompatibleVersion {
        id: String,
        found: Version,
        required: VersionReq,
        /// `Some(dependent_id)` when a currently-installed extension's own
        /// `requires` entry is what rejected the upgrade; `None` when it was
        /// the protocol `compat` range itself.
        dependent: Option<String>,
    },

    #[error("extension '{id}' is not installed")]
    NotFound { id: String },

    #[error("extension '{id}' is already installed at version {version}")]
    AlreadyInstalled { id: String, version: Version },

    #[error("manifest '{id}' is invalid: {reason}")]
    InvalidManifest { id: String, reason: String },

    #[error("signature verification failed for extension '{id}'")]
    SignatureInvalid { id: String },

    #[error("lockfile mismatch for extension '{id}': expected hash {expected}, found {found}")]
    LockfileMismatch {
        id: String,
        expected: String,
        found: String,
    },

    #[error("no rollback target available for extension '{id}'")]
    NoRollbackTarget { id: String },

    /// A mechanism's `activate`/`deactivate` failed for a reason outside the
    /// policy variants above (e.g. subprocess spawn failure, malformed
    /// declarative artifact). Carries a message only — never leaks
    /// secrets/env values.
    #[error("extension '{id}' mechanism error: {detail}")]
    Mechanism { id: String, detail: String },
}
