//! P2P MeshTransport implementation (OSS).
//! Sends encrypted MeshEnvelopes to peer daemons via HTTP POST to /mesh/ingest.
//! Uses `age` (X25519 + ChaCha20-Poly1305) for E2E encryption.
//! Relay impl (Bastion Cloud, closed) is a separate repo — same MeshTransport trait.
//!
//! Security properties enforced here:
//! - CR-06: receive() asserts envelope.to_owner == self.local_owner (cross-owner injection prevention).
//! - SEC-02: reqwest client built with redirect::Policy::none() (open-redirect SSRF prevention).

use anyhow::Context;
use opentelemetry::{
    global as otel_global,
    trace::{Span as _, SpanKind, Tracer as _},
    KeyValue,
};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::mesh::{MeshEnvelope, MeshPeerMap, MeshTransport, SelectiveSlice};

pub struct P2PTransport {
    /// Local age identity private key (bech32 string). Loaded from env MESH_IDENTITY_KEY.
    local_identity_key: String,
    /// Registered peer map: owner_id → (peer_url, age_pubkey).
    peers: Arc<tokio::sync::RwLock<MeshPeerMap>>,
    /// SSE broadcast channel — receives mesh_sync events (Pitfall 3: capacity=128, ignore SendError).
    events_tx: broadcast::Sender<String>,
    /// local owner_id (for from_owner in outbound envelopes).
    local_owner: String,
    /// HTTP client (reqwest, already in Cargo.toml).
    http: reqwest::Client,
}

impl P2PTransport {
    pub fn new(
        local_owner: String,
        local_identity_key: String,
        peers: Arc<tokio::sync::RwLock<MeshPeerMap>>,
        events_tx: broadcast::Sender<String>,
    ) -> Self {
        Self {
            local_owner,
            local_identity_key,
            peers,
            events_tx,
            // SEC-02: disable redirects on the outbound mesh client — prevents open-redirect
            // SSRF where a peer serves a 3xx that pivots to a private address.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to build reqwest client"),
        }
    }
}

#[async_trait::async_trait]
impl MeshTransport for P2PTransport {
    /// Send a selective slice to a remote owner.
    ///
    /// CALLER RESPONSIBILITY: call filter_for_mesh BEFORE calling this method.
    /// This impl does NOT re-filter — it trusts the caller to have done so.
    async fn send(&self, slice: SelectiveSlice, to_owner: &str) -> anyhow::Result<()> {
        let peers = self.peers.read().await;
        let peer = peers.resolve(to_owner).ok_or_else(|| {
            anyhow::anyhow!("mesh peer '{}' not registered in MeshPeerMap", to_owner)
        })?;

        // Collect tags for OTel event
        let tags: Vec<String> = {
            let mut tag_set = std::collections::HashSet::new();
            for b in &slice.beliefs {
                if let Some(t) = &b.persona_tag {
                    tag_set.insert(t.clone());
                }
            }
            tag_set.into_iter().collect()
        };
        let belief_count = slice.beliefs.len();

        // Serialize SelectiveSlice to bytes
        let plaintext = serde_json::to_vec(&slice).context("failed to serialize SelectiveSlice")?;

        // age encrypt with peer's public key — simple API: encrypt(&pubkey, plaintext)
        let recipient: age::x25519::Recipient = peer
            .age_pubkey
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid age public key for peer '{}'", to_owner))?;
        let peer_url = peer.peer_url.clone();
        let peer_age_pubkey = peer.age_pubkey.clone();
        drop(peers); // release lock before blocking I/O

        let ciphertext = age::encrypt(&recipient, &plaintext)
            .map_err(|e| anyhow::anyhow!("age encrypt failed: {:?}", e))?;

        let envelope = MeshEnvelope {
            from_owner: self.local_owner.clone(),
            to_owner: to_owner.to_string(),
            ciphertext,
            recipient_hint: peer_age_pubkey,
        };

        let url = format!("{}/mesh/ingest", peer_url.trim_end_matches('/'));

        // OTel mesh_sync span (SEAM #4)
        let tracer = otel_global::tracer("bastion");
        let mut sync_span = tracer
            .span_builder("mesh_sync")
            .with_kind(SpanKind::Internal)
            .with_attributes(vec![
                KeyValue::new("gen_ai.operation.name", "mesh_sync"),
                KeyValue::new("mesh.from_owner", self.local_owner.clone()),
                KeyValue::new("mesh.to_owner", to_owner.to_string()),
                KeyValue::new("mesh.tags", tags.join(",")),
                KeyValue::new("mesh.beliefs_count", belief_count as i64),
            ])
            .start(&tracer);

        // POST to peer /mesh/ingest
        let resp = self
            .http
            .post(&url)
            .json(&envelope)
            .send()
            .await
            .context("failed to POST to peer /mesh/ingest")?;

        let status = resp.status();
        sync_span.set_attribute(KeyValue::new("mesh.http_status", status.as_u16() as i64));
        sync_span.end();

        if !status.is_success() {
            anyhow::bail!("peer /mesh/ingest returned {}", status);
        }

        // Broadcast to SSE (Pitfall 3: ignore SendError — slow/disconnected clients are acceptable)
        let event_json = serde_json::json!({
            "type": "mesh_sync",
            "from_owner": &self.local_owner,
            "to_owner": to_owner,
            "tags": tags,
        })
        .to_string();
        let _ = self.events_tx.send(event_json);

        Ok(())
    }

    async fn receive(&self, envelope: MeshEnvelope) -> anyhow::Result<SelectiveSlice> {
        // age decrypt with local identity — simple API: decrypt(&identity, &ciphertext)
        let identity: age::x25519::Identity = self
            .local_identity_key
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid local age identity key"))?;

        let plaintext = age::decrypt(&identity, &envelope.ciphertext)
            .map_err(|e| anyhow::anyhow!("age decrypt failed: {:?}", e))?;

        let slice: SelectiveSlice = serde_json::from_slice(&plaintext)
            .context("failed to deserialize SelectiveSlice after decrypt")?;

        // Pitfall 2: verify from_owner in envelope matches decrypted slice's from_owner.
        // If a malicious sender injected a different from_owner, the slice mismatch catches it.
        if envelope.from_owner != slice.from_owner {
            anyhow::bail!(
                "from_owner mismatch: envelope claims '{}', payload contains '{}' — rejecting",
                envelope.from_owner,
                slice.from_owner
            );
        }

        // CR-06: verify the envelope is addressed to THIS node's owner.
        // A registered peer must not be able to inject slices meant for a different owner
        // into this node's mesh_slice_store (cross-owner injection prevention).
        if envelope.to_owner != self.local_owner {
            anyhow::bail!(
                "envelope to_owner '{}' does not match local_owner '{}' — rejecting cross-owner injection",
                envelope.to_owner, self.local_owner
            );
        }

        // Verify sender is a registered peer (Pitfall 2 — unregistered peer rejection)
        let peers = self.peers.read().await;
        if peers.resolve(&slice.from_owner).is_none() {
            anyhow::bail!(
                "received mesh envelope from unregistered peer '{}'",
                slice.from_owner
            );
        }

        tracing::info!(
            event = "mesh_slice_received",
            from_owner = %slice.from_owner,
            beliefs_count = slice.beliefs.len(),
        );

        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::MeshPeerMap;
    use std::sync::Arc;
    use tokio::sync::{broadcast, RwLock};

    /// CR-06: receive() must reject envelopes where to_owner != local_owner.
    /// This prevents a registered peer from injecting slices addressed to a different owner.
    #[tokio::test]
    async fn test_receive_rejects_wrong_to_owner() {
        use age::secrecy::ExposeSecret as _;
        // Generate a real age identity/key pair
        let identity = age::x25519::Identity::generate();
        // age::x25519::Identity::to_string() returns a SecretString; expose to get &str
        let identity_str = identity.to_string().expose_secret().to_owned();

        let (tx, _) = broadcast::channel(1);
        let peers = Arc::new(RwLock::new(MeshPeerMap::new()));
        let transport = P2PTransport::new("local-owner".to_string(), identity_str, peers, tx);

        // Build a plaintext SelectiveSlice from "remote-owner"
        let plaintext = serde_json::to_vec(&crate::mesh::SelectiveSlice {
            from_owner: "remote-owner".to_string(),
            beliefs: vec![],
        })
        .unwrap();

        // Encrypt with local node's public key so decrypt succeeds (tests the to_owner check, not decrypt)
        let recipient = identity.to_public();
        let ciphertext =
            age::encrypt(&recipient, &plaintext).expect("age encrypt must succeed in test");

        // Construct envelope addressed to a DIFFERENT owner — NOT "local-owner"
        let envelope = MeshEnvelope {
            from_owner: "remote-owner".to_string(),
            to_owner: "other-owner".to_string(), // mismatch — should be rejected
            ciphertext,
            recipient_hint: identity.to_public().to_string(),
        };

        let result = transport.receive(envelope).await;
        assert!(
            result.is_err(),
            "receive() must reject envelope addressed to wrong owner"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("to_owner") || err_msg.contains("wrong owner"),
            "error must describe the to_owner rejection: {err_msg}",
        );
    }
}
