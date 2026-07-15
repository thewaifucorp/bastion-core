//! Agent identity module — Agent Card struct + Ed25519 signing (SEC-06).
//!
//! `AgentCard` is a signed JSON identity document served at `/agent-card`.
//! The age X25519 keypair (`MESH_IDENTITY_KEY`) is used for mesh E2E encryption;
//! Ed25519 signing keys are derived deterministically from the age key via SHA-256
//! (see [`age_identity::AgeIdentity`] for details).

pub mod age_identity;

use serde::{Deserialize, Serialize};

/// Current Agent Card schema version.
pub const AGENT_CARD_VERSION: u32 = 1;

/// Agent Card — signed JSON identity badge ("crachá").
///
/// Fields are serialised in declaration order.  The `signature` field is populated
/// AFTER signing (it is excluded from the canonical JSON used for signing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Schema version (currently 1).
    pub version: u32,
    /// Human-readable agent name (e.g. "bastion-mario").
    pub name: String,
    /// Age X25519 public key in bech32 format (e.g. "age1...").
    pub pubkey_age: String,
    /// Ed25519 public key encoded in base64url (no padding).
    pub pubkey_ed25519: String,
    /// List of capability names this agent exposes.
    pub capabilities: Vec<String>,
    /// Tags this agent is allowed to sync (drives mesh filter).
    pub allowed_tags: Vec<String>,
    /// Optional mesh endpoint URL (e.g. "https://bastion.example.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_url: Option<String>,
    /// Optional MCP endpoint URL (e.g. "https://bastion.example.com/mcp").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_url: Option<String>,
    /// Base64url-encoded Ed25519 signature over the canonical JSON of all OTHER fields.
    /// Set to `None` before signing; populated with the encoded signature after signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}
