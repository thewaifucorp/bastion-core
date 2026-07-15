//! Mesh connectivity layer — D-02 (LOCKED): ONE pluggable MeshTransport trait.
//! P2P impl (OSS) lives in src/mesh/p2p.rs (Wave 2).
//! Relay impl (closed Bastion Cloud) is a separate repo implementing this trait.

pub mod allowlist;
pub mod context_provider; // stubbed here; full impl in Wave 2

use serde::{Deserialize, Serialize};

/// A tag-filtered set of beliefs from the local owner, destined for a peer.
/// Content is serialized by the transport before encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveSlice {
    /// The sender's owner_id (advisory — receiver must verify via key match).
    pub from_owner: String,
    /// Tag-filtered, CloudOk beliefs (LocalOnly beliefs are removed by filter_for_mesh before here).
    pub beliefs: Vec<crate::memory::Belief>,
}

/// Opaque wire envelope — ciphertext is E2E encrypted with `age`.
/// The relay (closed Bastion Cloud) forwards this blob without reading it.
/// `ciphertext: Vec<u8>` is opaque by type — relay never holds the private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    /// Claimed sender — MUST be verified against registered peer key on ingest.
    pub from_owner: String,
    pub to_owner: String,
    /// age-encrypted serialized SelectiveSlice — opaque to relay.
    pub ciphertext: Vec<u8>,
    /// age recipient public key hint (bech32 string). Used by receiver to select decryption key.
    pub recipient_hint: String,
}

/// Registry of known mesh peers: owner_id → (peer_url, age_pubkey_bech32).
/// Populated from bastion.toml [[mesh.peer]] entries at daemon startup.
#[derive(Debug, Clone, Default)]
pub struct MeshPeerMap {
    peers: std::collections::HashMap<String, MeshPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    /// HTTP URL of the peer daemon's /mesh/ingest endpoint.
    pub peer_url: String,
    /// age public key (bech32 string) for E2E encryption to this peer.
    pub age_pubkey: String,
    /// Tags this peer is allowed to receive (drives filter_for_mesh OwnerAllowlist).
    /// Populated from [[mesh.peer]] allowed_tags in bastion.toml.
    #[serde(default)]
    pub allowed_tags: Vec<String>,
}

impl MeshPeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, owner_id: String, peer: MeshPeer) {
        self.peers.insert(owner_id, peer);
    }

    /// Resolve owner_id → MeshPeer. Returns None if unknown.
    pub fn resolve(&self, owner_id: &str) -> Option<&MeshPeer> {
        self.peers.get(owner_id)
    }

    /// Return all registered peer owner_ids (for iteration in scheduler).
    pub(crate) fn all_peer_owner_ids(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }
}

pub mod p2p;

/// Pluggable transport abstraction.
/// - P2P (OSS): posts ciphertext to peer /mesh/ingest endpoint via reqwest.
/// - Relay (closed): posts to Bastion Cloud hub that forwards blindly.
/// The trait never sees plaintext after encryption — callers encrypt BEFORE calling send().
#[async_trait::async_trait]
pub trait MeshTransport: Send + Sync {
    /// Send a selective slice to a remote owner.
    /// The slice MUST already have LocalOnly beliefs filtered out by filter_for_mesh.
    /// Implementor encrypts with the peer's age public key before transit.
    async fn send(&self, slice: SelectiveSlice, to_owner: &str) -> anyhow::Result<()>;

    /// Receive an incoming envelope (called by /mesh/ingest handler after auth).
    /// Implementor decrypts and verifies from_owner against registered peer keys.
    async fn receive(&self, envelope: MeshEnvelope) -> anyhow::Result<SelectiveSlice>;
}

pub type SharedMeshTransport = std::sync::Arc<dyn MeshTransport>;
