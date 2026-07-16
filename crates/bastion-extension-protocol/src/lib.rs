//! `bastion-extension-protocol` — contracts for third-party extensions
//! (`docs/ARCHITECTURE.md`, M4-08..12).
//!
//! This is the largest new security surface of the revamp: third-party code
//! enters the runtime. The one rule every type/method in this crate exists to
//! serve (design doc §0/§1):
//!
//! > **Installing an extension NEVER grants authority.** Capabilities,
//! > memory, network, devices, and egress remain mediated by the EXISTING
//! > contracts. A policy extension may only RESTRICT grants — never widen
//! > them.
//!
//! This crate is contracts + pure decision logic only — zero product I/O
//! (`#![forbid(unsafe_code)]`, deps only `bastion-types` + data/hashing
//! crates). The actual enforcement chokepoint (an extension cannot register a
//! capability, reach a host, read memory, or bind a socket without a
//! `PermissionSet` check actually running) lives in the HOST, which is
//! product code (`src/extension/`, `bastion-agent` app) — see
//! `docs/ARCHITECTURE.md` §3.
//!
//! Modules:
//! - [`manifest`] — `ExtensionManifest`/`PackManifest` and their parts (§1.1).
//! - [`permission`] — `PermissionSet` and the deny-by-default scopes it's made
//!   of, plus the pure `allows_*`/`is_subset_of` decision logic (§1.2).
//! - [`trust`] — trust tiers and publisher signatures (§1.3). Informational
//!   only; never consulted by enforcement.
//! - [`error`] — `ExtensionError`, the one typed-error vocabulary every
//!   blocked adversarial vector surfaces through (§8).
//! - [`lockfile`] — `LoadoutLock`/`LockEntry`, the reproducible lock format
//!   (§3).

#![forbid(unsafe_code)]

/// This crate's own version — what `ExtensionManifest.compat` (a
/// `VersionReq`) is checked against before install/upgrade. Exposed as a
/// constant (rather than each host call site hardcoding a literal) so a
/// protocol version bump can't silently drift out of sync with the actual
/// crate version.
pub const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod error;
pub mod lockfile;
pub mod manifest;
pub mod permission;
pub mod trust;

pub use error::ExtensionError;
pub use lockfile::{digest_hex, LoadoutLock, LockEntry};
pub use manifest::{
    Entrypoint, ExtensionKind, ExtensionManifest, LoadoutDefaults, MigrationRef, PackManifest,
    Provided, Requirement, SecretRef,
};
pub use permission::{DeviceKind, EgressScope, FsScope, MemoryScope, PermissionSet};
pub use trust::{Signature, TrustTier};
