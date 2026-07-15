//! Age-based identity implementation.
//!
//! [`AgeIdentity`] holds an age X25519 identity key (bech32 string) plus a
//! deterministically-derived Ed25519 signing key.  The derivation uses SHA-256
//! with a domain separator, **not** raw X25519 byte reuse (see RESEARCH.md §Pattern 3).
//!
//! # Security
//!
//! - The age secret key is never logged; only `pubkey_age()` and `pubkey_ed25519()`
//!   are exposed publicly (T-09-01-02).
//! - Signature verification is constant-time (ed25519-dalek bound).
//! - The Ed25519 key is **not** the same as the X25519 key — the derivation is
//!   one-way (SHA-256), so compromising the Ed25519 key does not reveal the age key
//!   and vice-versa.

use crate::identity::AgentCard;
use anyhow::Context;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;

/// Agent identity backed by an age X25519 keypair + Ed25519 signing key.
pub struct AgeIdentity {
    /// Bech32-encoded age X25519 secret key (AGE-SECRET-KEY-1…).
    age_key_bech32: String,
    /// Ed25519 signing key (deterministically derived from the age key).
    signing_key: SigningKey,
    /// Corresponding Ed25519 verifying key.
    verifying_key: VerifyingKey,
}

/// 09-REVIEW.md WR-02: manual `Debug` so `{:?}`/`dbg!`/error-message formatting can
/// never print the raw age secret key — `#[derive(Debug)]` would have contradicted
/// this module's own "the age secret key is never logged" claim the moment any
/// future call site did `tracing::debug!("{:?}", identity)` or similar.
impl fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgeIdentity")
            .field("age_key_bech32", &"[redacted]")
            .field("pubkey_ed25519", &self.pubkey_ed25519())
            .finish()
    }
}

impl AgeIdentity {
    /// Parse an age identity from a bech32-encoded secret key and derive the
    /// Ed25519 signing key deterministically via SHA-256.
    ///
    /// The derivation is a one-way hash: `seed = SHA-256("bastion-agent-card" || key_bech32)`.
    /// This guarantees a different Ed25519 key per age key while keeping it stable
    /// across restarts (no storage needed for the Ed25519 seed).
    ///
    /// # Errors
    ///
    /// Returns an error if `key` is not a valid age X25519 identity string.
    pub fn from_bech32(key: &str) -> anyhow::Result<Self> {
        // Validate by parsing; discard the parsed identity (we keep the string).
        let _identity: age::x25519::Identity = key
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid age identity key"))?;

        // One-way domain-separated derivation — NOT raw X25519 byte reuse (RESEARCH.md).
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"bastion-agent-card-ed25519");
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash);
        let signing_key: SigningKey = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            age_key_bech32: key.to_string(),
            signing_key,
            verifying_key,
        })
    }

    /// Generate a fresh age keypair + Ed25519 keypair.
    ///
    /// The Ed25519 key is deterministically derived from the age key via SHA-256,
    /// matching [`from_bech32`](Self::from_bech32) — so a persisted identity can
    /// be fully restored from the age secret alone.
    pub fn generate() -> Self {
        use age::secrecy::ExposeSecret;

        let age_identity = age::x25519::Identity::generate();
        let age_key = age_identity.to_string().expose_secret().to_owned();

        // Derive Ed25519 from the age key, matching from_bech32's derivation
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"bastion-agent-card-ed25519");
        hasher.update(age_key.as_bytes());
        let hash = hasher.finalize();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Self {
            age_key_bech32: age_key,
            signing_key,
            verifying_key,
        }
    }

    /// Return age secret key in bech32 format (AGE-SECRET-KEY-...).
    /// SECURITY: only call during --with-identity export; never log.
    pub fn age_secret_bech32(&self) -> &str {
        &self.age_key_bech32
    }

    /// Return Ed25519 secret key as base64url-encoded bytes (no padding).
    /// SECURITY: only call during --with-identity export; never log.
    pub(crate) fn ed25519_secret_base64(&self) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        engine.encode(self.signing_key.to_bytes())
    }

    /// Return the age X25519 public key in bech32 format.
    pub fn pubkey_age(&self) -> String {
        let identity: age::x25519::Identity = self
            .age_key_bech32
            .parse()
            .expect("stored age identity key is valid (validated at construction)");
        identity.to_public().to_string()
    }

    /// Return the Ed25519 public key encoded in base64url (no padding).
    pub fn pubkey_ed25519(&self) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        engine.encode(self.verifying_key.to_bytes())
    }

    /// Sign an Agent Card and return the raw Ed25519 signature bytes.
    ///
    /// The signature covers all fields of `card` EXCEPT `signature`, serialised
    /// as canonical JSON (sorted keys, no whitespace).
    pub fn sign_agent_card(&self, card: &AgentCard) -> anyhow::Result<Vec<u8>> {
        let canonical = agent_card_canonical_json(card)?;
        let signature = self.signing_key.sign(canonical.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify an Ed25519 signature against an Agent Card.
    ///
    /// The `pubkey_ed25519` field on the card is used as the verifying key.
    /// This is a **static** method — it does not require an `AgeIdentity` instance.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
    /// or `Err` if the card's `pubkey_ed25519` is malformed.
    pub fn verify_agent_card(card: &AgentCard, signature_bytes: &[u8]) -> anyhow::Result<bool> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let pubkey_bytes: [u8; 32] = engine
            .decode(&card.pubkey_ed25519)
            .context("invalid base64url pubkey_ed25519 on card")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey_ed25519 must be exactly 32 bytes"))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {:?}", e))?;

        let sig = Signature::from_slice(signature_bytes)
            .map_err(|e| anyhow::anyhow!("invalid Ed25519 signature bytes: {:?}", e))?;

        let canonical = agent_card_canonical_json(card)?;

        match verifying_key.verify_strict(canonical.as_bytes(), &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// ---- canonical JSON helper ----

/// Serialize an `AgentCard` to canonical JSON (sorted keys, no whitespace)
/// with the `signature` field excluded (it is not part of the signed payload).
fn agent_card_canonical_json(card: &AgentCard) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(card).context("failed to serialize AgentCard")?;

    // Remove the signature field — it is not part of the signed payload.
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }

    Ok(canonical_json_string(&value))
}

/// Recursively serialise a `serde_json::Value` to compact JSON with **sorted object keys**.
///
/// This is the deterministic canonical form used for signing: same input always
/// produces identical bytes.
fn canonical_json_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let items: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_json = serde_json::Value::String(k.to_string()).to_string();
                    let val_json = canonical_json_string(&map[*k]);
                    format!("{key_json}:{val_json}")
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json_string).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}

// ---- threat-model compliance ----

/// Assemble the error message for public consumption.
/// T-09-01-02: never log secret key bytes; only generic "identity error".
///
/// The detailed error goes to a `debug` span (not `warn`/`error`, so it's off by
/// default) — the caller-facing message is always the generic string, in case a
/// future error variant here ever carries secret material.
#[inline]
pub fn sanitised_identity_error(detail: &str) -> String {
    tracing::debug!(event = "identity_error_detail", %detail);
    "Identity error".to_string()
}

// ---- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    /// Test that `generate()` creates a valid keypair with age and Ed25519 keys.
    #[test]
    fn test_generates_valid_keypair() {
        let identity = AgeIdentity::generate();

        let pubkey_age = identity.pubkey_age();
        let pubkey_ed25519 = identity.pubkey_ed25519();

        assert!(
            pubkey_age.starts_with("age1"),
            "age pubkey must start with 'age1': got {pubkey_age}"
        );
        assert!(
            !pubkey_ed25519.is_empty(),
            "ed25519 pubkey must not be empty"
        );

        // Ed25519 public keys are always 32 bytes → 43 base64url chars (no pad).
        assert_eq!(
            pubkey_ed25519.len(),
            43,
            "base64url ed25519 pubkey should be 43 chars (32 bytes, no padding)"
        );
    }

    /// Test that signing a card produces a signature that `verify_agent_card` accepts.
    #[test]
    fn test_sign_and_verify_agent_card() {
        let identity = AgeIdentity::generate();

        let card = AgentCard {
            version: 1,
            name: "test-agent".to_string(),
            pubkey_age: identity.pubkey_age(),
            pubkey_ed25519: identity.pubkey_ed25519(),
            capabilities: vec!["memory_retrieve".to_string(), "goals_list".to_string()],
            allowed_tags: vec!["mercado".to_string(), "saude".to_string()],
            mesh_url: Some("https://bastion.dev".to_string()),
            mcp_url: None,
            signature: None,
        };

        let signature = identity
            .sign_agent_card(&card)
            .expect("sign_agent_card must succeed");

        // Populate signature on card (what the endpoint would do).
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut signed_card = card.clone();
        signed_card.signature = Some(engine.encode(&signature));

        let verified = AgeIdentity::verify_agent_card(&signed_card, &signature)
            .expect("verify_agent_card must not error");
        assert!(verified, "valid signature must verify");
    }

    /// Test that `verify_agent_card` rejects a tampered card.
    #[test]
    fn test_verify_rejects_tampered_card() {
        let identity = AgeIdentity::generate();

        let card = AgentCard {
            version: 1,
            name: "test-agent".to_string(),
            pubkey_age: identity.pubkey_age(),
            pubkey_ed25519: identity.pubkey_ed25519(),
            capabilities: vec![],
            allowed_tags: vec![],
            mesh_url: None,
            mcp_url: None,
            signature: None,
        };

        let signature = identity
            .sign_agent_card(&card)
            .expect("sign_agent_card must succeed");

        // Tamper with the card name.
        let mut tampered = card.clone();
        tampered.name = "tampered-agent".to_string();

        let verified = AgeIdentity::verify_agent_card(&tampered, &signature)
            .expect("verify_agent_card must not error on tampered card");
        assert!(!verified, "tampered card must not verify");
    }

    /// Test that `from_bech32` parses a valid age key and produces a stable Ed25519 key.
    #[test]
    fn test_from_bech32_parses_valid_key() {
        let age_identity = age::x25519::Identity::generate();
        let key_str = age_identity.to_string().expose_secret().to_owned();

        let identity =
            AgeIdentity::from_bech32(&key_str).expect("from_bech32 must succeed for valid key");

        assert_eq!(
            identity.pubkey_age(),
            age_identity.to_public().to_string(),
            "pubkey_age must match the age identity's public key"
        );
        assert!(
            identity.pubkey_age().starts_with("age1"),
            "age pubkey must start with 'age1'"
        );
    }

    /// Test that `from_bech32` on the same key produces the SAME Ed25519 key (deterministic).
    #[test]
    fn test_from_bech32_deterministic_ed25519() {
        let age_identity = age::x25519::Identity::generate();
        let key_str = age_identity.to_string().expose_secret().to_owned();

        let identity_a = AgeIdentity::from_bech32(&key_str).expect("first parse");
        let identity_b = AgeIdentity::from_bech32(&key_str).expect("second parse");

        assert_eq!(
            identity_a.pubkey_ed25519(),
            identity_b.pubkey_ed25519(),
            "same age key must produce same Ed25519 key"
        );
    }

    /// Sign/verify round-trip with a key loaded via `from_bech32`.
    #[test]
    fn test_sign_verify_from_bech32() {
        let age_identity = age::x25519::Identity::generate();
        let key_str = age_identity.to_string().expose_secret().to_owned();

        let identity = AgeIdentity::from_bech32(&key_str).expect("from_bech32 must succeed");

        let card = AgentCard {
            version: 1,
            name: "persistent-agent".to_string(),
            pubkey_age: identity.pubkey_age(),
            pubkey_ed25519: identity.pubkey_ed25519(),
            capabilities: vec!["test".to_string()],
            allowed_tags: vec![],
            mesh_url: None,
            mcp_url: None,
            signature: None,
        };

        let signature = identity.sign_agent_card(&card).expect("sign must succeed");
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut signed_card = card;
        signed_card.signature = Some(engine.encode(&signature));

        let verified =
            AgeIdentity::verify_agent_card(&signed_card, &signature).expect("verify must succeed");
        assert!(verified, "signature from from_bech32 identity must verify");
    }

    /// Canonical JSON must be deterministic (same card → same JSON).
    #[test]
    fn test_canonical_json_deterministic() {
        let identity = AgeIdentity::generate();

        let card = AgentCard {
            version: 1,
            name: "deterministic-test".to_string(),
            pubkey_age: identity.pubkey_age(),
            pubkey_ed25519: identity.pubkey_ed25519(),
            capabilities: vec!["a".to_string(), "b".to_string()],
            allowed_tags: vec![],
            mesh_url: Some("https://example.com".to_string()),
            mcp_url: None,
            signature: None,
        };

        // Sign twice — same card should produce same canonical JSON → same signature
        let sig1 = identity.sign_agent_card(&card).expect("first sign");
        let sig2 = identity.sign_agent_card(&card).expect("second sign");
        assert_eq!(
            sig1, sig2,
            "same card must produce same signature (deterministic canonical JSON)"
        );

        // Verify self-consistency
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut signed = card.clone();
        signed.signature = Some(engine.encode(&sig1));
        assert!(
            AgeIdentity::verify_agent_card(&signed, &sig1).expect("verify"),
            "self-consistency round-trip"
        );
    }

    /// Canonical JSON key ordering test: {b, a} must produce the same JSON as {a, b}.
    #[test]
    fn test_canonical_json_key_order() {
        use serde_json::json;

        let unordered = json!({
            "z": 1,
            "a": 2,
            "m": 3
        });
        let ordered = json!({
            "a": 2,
            "m": 3,
            "z": 1
        });

        // Both should produce the same canonical form (sorted: a, m, z).
        let result_a = canonical_json_string(&unordered);
        let result_b = canonical_json_string(&ordered);
        assert_eq!(
            result_a, result_b,
            "canonical JSON must be order-independent"
        );

        let expected = r#"{"a":2,"m":3,"z":1}"#;
        assert_eq!(
            result_a, expected,
            "canonical JSON must match expected sorted form"
        );
    }
}
