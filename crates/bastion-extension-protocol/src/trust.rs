//! Trust tiers and publisher signatures (design doc §1.3).
//!
//! Trust tier is INFORMATIONAL — it decides what the host shows the owner at
//! install time (M4-09) and what ceiling a catalog/discovery layer (out of
//! scope this cycle, M4-13) might apply BEFORE a manifest reaches the host at
//! all. It never widens what `PermissionSet` enforcement allows: a
//! `TrustTier::Official` extension with `egress: Hosts(["evil.com"])` is
//! exactly as constrained as a `TrustTier::Local` one with the same
//! `PermissionSet` — enforcement never consults this enum.

use serde::{Deserialize, Serialize};

/// Trust tier, ordered from least (`Local`, unsigned/dev) to most
/// (`Official`) trusted. `Ord` follows declaration order — do not reorder
/// variants without checking every `<`/`>` comparison call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// No signature — local development. Permitted, but always shown as such.
    Local,
    Community,
    Verified,
    Official,
}

impl TrustTier {
    /// A manifest with no `signature` is always `Local`, regardless of what
    /// tier it claims — trust tier is DERIVED from signature verification,
    /// never a self-reported field the manifest can set directly.
    pub fn without_signature() -> Self {
        TrustTier::Local
    }
}

/// Publisher signature over a manifest's canonical bytes. Verification itself
/// (crypto + a trust-anchor/key-distribution story) is host/product concern —
/// out of scope for this contracts-only crate (§7: no catalog/marketplace this
/// cycle). This type only carries the DATA a verifier needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Publisher identity the signature claims to be from.
    pub publisher: String,
    /// Signing algorithm identifier, e.g. `"ed25519"`.
    pub algorithm: String,
    /// Base64-encoded signature bytes.
    pub value: String,
}
