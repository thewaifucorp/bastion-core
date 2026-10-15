//! Trust tiers, publisher signatures and their verification (design doc
//! §1.3).
//!
//! Trust tier is INFORMATIONAL — it decides what the host shows the owner at
//! install time (M4-09) and what ceiling a catalog/discovery layer might
//! apply BEFORE a manifest reaches the host at all. It never widens what
//! `PermissionSet` enforcement allows: a `TrustTier::Official` extension with
//! `egress: Hosts(["evil.com"])` is exactly as constrained as a
//! `TrustTier::Local` one with the same `PermissionSet` — enforcement never
//! consults this enum.
//!
//! A tier is never self-reported. It is DERIVED by [`TrustAnchors::verify`]:
//! a signature checked against a set of publisher keys the HOST injects.
//! This crate embeds no key of its own — which publishers a host trusts, and
//! at which tier, is the host's decision.
//!
//! | Signature | Outcome |
//! |---|---|
//! | absent | [`Verification::Unsigned`] → `Local` |
//! | from a publisher the host has no key for | [`Verification::UnknownPublisher`] → `Local` (never elevated, never rejected) |
//! | verifies against one of that publisher's keys | [`Verification::Verified`] → that key's tier |
//! | does not verify, malformed, or unsupported algorithm | `Err(ExtensionError::SignatureInvalid)` — the host rejects the install |

use crate::content::ContentDigests;
use crate::error::ExtensionError;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};

/// The only signing algorithm this protocol version accepts.
pub const ED25519: &str = "ed25519";

/// First line of every signed payload. Versioned so a future payload layout
/// can never be confused with this one.
pub const SIGNATURE_DOMAIN: &str = "bastion-extension-protocol/signature/v1";

/// Suffix of a detached signature file: `pack.toml` is signed by
/// `pack.toml.sig`, `extension.toml` by `extension.toml.sig`. Files with
/// this suffix are never part of the signed content (see
/// [`ContentDigests::from_dir`]).
pub const SIGNATURE_FILE_SUFFIX: &str = ".sig";

/// Trust tier, ordered from least (`Local`, unsigned/dev) to most
/// (`Official`) trusted. `Ord` follows declaration order — do not reorder
/// variants without checking every `<`/`>` comparison call site.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// No verified signature — local development or an unknown publisher.
    /// Permitted, but always shown as such.
    #[default]
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

    /// Lower-case wire name (`"official"`, `"local"`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            TrustTier::Local => "local",
            TrustTier::Community => "community",
            TrustTier::Verified => "verified",
            TrustTier::Official => "official",
        }
    }
}

/// Publisher signature over a signed payload (see [`signing_payload`]).
/// Serialized as the detached signature file (`<manifest>.sig`):
///
/// ```toml
/// publisher = "example"
/// algorithm = "ed25519"
/// value = "<standard base64 of the 64-byte signature>"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Publisher identity the signature claims to be from. Selects which
    /// trusted keys are tried; it proves nothing by itself.
    pub publisher: String,
    /// Signing algorithm identifier; only [`ED25519`] is accepted.
    pub algorithm: String,
    /// Standard (padded) base64 of the signature bytes.
    pub value: String,
}

impl Signature {
    /// Sign `payload` with an Ed25519 key given as its 32-byte seed. Used by
    /// publisher tooling; a host only ever verifies.
    pub fn sign_ed25519(publisher: &str, seed: &[u8; 32], payload: &[u8]) -> Self {
        let key = SigningKey::from_bytes(seed);
        Self {
            publisher: publisher.to_string(),
            algorithm: ED25519.to_string(),
            value: base64::engine::general_purpose::STANDARD.encode(key.sign(payload).to_bytes()),
        }
    }
}

/// Which kind of manifest a signature covers. Part of the signed payload, so
/// a pack signature can never be replayed as an extension signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedKind {
    Extension,
    Pack,
}

impl SignedKind {
    fn as_str(self) -> &'static str {
        match self {
            SignedKind::Extension => "extension",
            SignedKind::Pack => "pack",
        }
    }
}

/// The exact bytes a publisher signs and a host verifies:
///
/// ```text
/// bastion-extension-protocol/signature/v1
/// kind <extension|pack>
/// id <id>
/// version <semver>
/// <sha256:hex> <relative/path>      (one line per file, sorted by path)
/// ```
///
/// Every line ends with `\n`. The content lines cover every file of the
/// manifest's directory, the manifest file itself included, so changing any
/// shipped byte (a skill, a persona, a wasm module) invalidates the
/// signature.
pub fn signing_payload(
    kind: SignedKind,
    id: &str,
    version: &Version,
    content: &ContentDigests,
) -> Result<Vec<u8>, ExtensionError> {
    if id.is_empty() || id.chars().any(char::is_control) {
        return Err(ExtensionError::InvalidManifest {
            id: id.to_string(),
            reason: "id is empty or contains control characters".to_string(),
        });
    }
    let mut out = format!(
        "{SIGNATURE_DOMAIN}\nkind {}\nid {id}\nversion {version}\n",
        kind.as_str()
    );
    for (path, digest) in content.iter() {
        out.push_str(digest);
        out.push(' ');
        out.push_str(path);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

/// Result of checking a signature against a host's [`TrustAnchors`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verification {
    /// No signature at all.
    Unsigned,
    /// Signed by a publisher the host holds no key for. Not verifiable, so
    /// never elevated above `Local`.
    UnknownPublisher { publisher: String },
    /// Verified against one of `publisher`'s trusted keys.
    Verified { publisher: String, tier: TrustTier },
}

impl Verification {
    /// The tier this outcome grants.
    pub fn tier(&self) -> TrustTier {
        match self {
            Verification::Unsigned | Verification::UnknownPublisher { .. } => TrustTier::Local,
            Verification::Verified { tier, .. } => *tier,
        }
    }
}

#[derive(Debug, Clone)]
struct TrustedKey {
    publisher: String,
    tier: TrustTier,
    key: VerifyingKey,
}

/// The publisher keys a host trusts, each bound to the tier it grants.
/// Empty by default: with no anchors every signature resolves to
/// [`Verification::UnknownPublisher`] (or fails, if malformed).
///
/// A publisher may hold several keys (rotation): a signature verifies when
/// any of them accepts it.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    keys: Vec<TrustedKey>,
}

impl TrustAnchors {
    /// No trusted keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is trusted.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Trust `public_key` (32 raw Ed25519 bytes) as `publisher`, granting
    /// `tier`. `TrustTier::Local` is refused: it is what an unverified
    /// signature already gets, so a key at that tier would mean nothing.
    pub fn add(
        &mut self,
        publisher: &str,
        tier: TrustTier,
        public_key: &[u8],
    ) -> Result<(), ExtensionError> {
        let invalid = |reason: &str| ExtensionError::InvalidTrustAnchor {
            publisher: publisher.to_string(),
            reason: reason.to_string(),
        };
        if publisher.is_empty() || publisher.chars().any(char::is_whitespace) {
            return Err(invalid("publisher is empty or contains whitespace"));
        }
        if tier == TrustTier::Local {
            return Err(invalid("a trusted key cannot grant the local tier"));
        }
        let bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| invalid("an ed25519 public key is exactly 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| invalid("not a valid ed25519 public key"))?;
        if key.is_weak() {
            return Err(invalid("weak ed25519 public key"));
        }
        self.keys.push(TrustedKey {
            publisher: publisher.to_string(),
            tier,
            key,
        });
        Ok(())
    }

    /// Add every key listed in a public-key file, all at `tier`. One key per
    /// line, `<publisher> ed25519 <standard base64 of the 32-byte key>`;
    /// blank lines and lines starting with `#` are ignored. Returns how many
    /// keys were added. Any malformed line fails the whole file and adds
    /// nothing.
    pub fn add_key_file(&mut self, tier: TrustTier, text: &str) -> Result<usize, ExtensionError> {
        let mut parsed = Self::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [publisher, algorithm, key] = fields.as_slice() else {
                return Err(ExtensionError::InvalidTrustAnchor {
                    publisher: String::new(),
                    reason: format!(
                        "line {}: expected `<publisher> ed25519 <base64 key>`",
                        index + 1
                    ),
                });
            };
            if *algorithm != ED25519 {
                return Err(ExtensionError::InvalidTrustAnchor {
                    publisher: (*publisher).to_string(),
                    reason: format!("line {}: unsupported algorithm '{algorithm}'", index + 1),
                });
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(key)
                .map_err(|_| ExtensionError::InvalidTrustAnchor {
                    publisher: (*publisher).to_string(),
                    reason: format!("line {}: key is not standard base64", index + 1),
                })?;
            parsed.add(publisher, tier, &bytes)?;
        }
        let added = parsed.keys.len();
        self.keys.extend(parsed.keys);
        Ok(added)
    }

    /// Verify `signature` over `payload` for the manifest `subject_id`.
    /// See the module table for every outcome.
    pub fn verify(
        &self,
        subject_id: &str,
        payload: &[u8],
        signature: Option<&Signature>,
    ) -> Result<Verification, ExtensionError> {
        let Some(signature) = signature else {
            return Ok(Verification::Unsigned);
        };
        let invalid = |reason: String| ExtensionError::SignatureInvalid {
            id: subject_id.to_string(),
            reason,
        };
        if signature.algorithm != ED25519 {
            return Err(invalid(format!(
                "unsupported algorithm '{}'",
                signature.algorithm
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&signature.value)
            .map_err(|_| invalid("signature value is not standard base64".to_string()))?;
        let bytes: [u8; 64] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("an ed25519 signature is exactly 64 bytes".to_string()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);

        let mut candidates = self
            .keys
            .iter()
            .filter(|k| k.publisher == signature.publisher)
            .peekable();
        if candidates.peek().is_none() {
            return Ok(Verification::UnknownPublisher {
                publisher: signature.publisher.clone(),
            });
        }
        candidates
            .filter(|k| k.key.verify_strict(payload, &sig).is_ok())
            .map(|k| k.tier)
            .max()
            .map(|tier| Verification::Verified {
                publisher: signature.publisher.clone(),
                tier,
            })
            .ok_or_else(|| {
                invalid(format!(
                    "does not verify against any trusted key of publisher '{}'",
                    signature.publisher
                ))
            })
    }
}

/// Public half of an Ed25519 seed, as standard base64 — the value a
/// public-key file line carries.
pub fn public_key_base64(seed: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];
    const OTHER_SEED: [u8; 32] = [9u8; 32];

    fn content() -> ContentDigests {
        let mut c = ContentDigests::new();
        c.insert("pack.toml", b"id = \"acme/pack\"").unwrap();
        c.insert("skills/a/SKILL.md", b"# a").unwrap();
        c
    }

    fn payload() -> Vec<u8> {
        signing_payload(
            SignedKind::Pack,
            "acme/pack",
            &Version::new(1, 0, 0),
            &content(),
        )
        .unwrap()
    }

    fn anchors_with(publisher: &str, seed: &[u8; 32], tier: TrustTier) -> TrustAnchors {
        let mut a = TrustAnchors::new();
        let line = format!("{publisher} ed25519 {}\n", public_key_base64(seed));
        assert_eq!(a.add_key_file(tier, &line).unwrap(), 1);
        a
    }

    #[test]
    fn payload_layout_is_exact_and_sorted() {
        let text = String::from_utf8(payload()).unwrap();
        let expected = format!(
            "{SIGNATURE_DOMAIN}\nkind pack\nid acme/pack\nversion 1.0.0\n{} pack.toml\n{} skills/a/SKILL.md\n",
            crate::digest_hex(b"id = \"acme/pack\""),
            crate::digest_hex(b"# a"),
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn payload_binds_kind() {
        let ext = signing_payload(
            SignedKind::Extension,
            "acme/pack",
            &Version::new(1, 0, 0),
            &content(),
        )
        .unwrap();
        assert_ne!(ext, payload());
    }

    #[test]
    fn payload_rejects_control_characters_in_id() {
        let err = signing_payload(
            SignedKind::Pack,
            "acme/pack\nkind extension",
            &Version::new(1, 0, 0),
            &content(),
        )
        .unwrap_err();
        assert!(matches!(err, ExtensionError::InvalidManifest { .. }));
    }

    #[test]
    fn absent_signature_is_unsigned_local() {
        let v = TrustAnchors::new()
            .verify("acme/pack", &payload(), None)
            .unwrap();
        assert_eq!(v, Verification::Unsigned);
        assert_eq!(v.tier(), TrustTier::Local);
    }

    #[test]
    fn valid_signature_gets_the_anchor_tier() {
        let anchors = anchors_with("acme", &SEED, TrustTier::Official);
        let sig = Signature::sign_ed25519("acme", &SEED, &payload());
        let v = anchors.verify("acme/pack", &payload(), Some(&sig)).unwrap();
        assert_eq!(
            v,
            Verification::Verified {
                publisher: "acme".to_string(),
                tier: TrustTier::Official
            }
        );
        assert_eq!(v.tier(), TrustTier::Official);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let anchors = anchors_with("acme", &SEED, TrustTier::Official);
        let sig = Signature::sign_ed25519("acme", &SEED, &payload());
        let mut changed = content();
        changed.insert("skills/a/SKILL.md", b"# a, edited").unwrap();
        let other = signing_payload(
            SignedKind::Pack,
            "acme/pack",
            &Version::new(1, 0, 0),
            &changed,
        )
        .unwrap();
        let err = anchors.verify("acme/pack", &other, Some(&sig)).unwrap_err();
        assert!(matches!(err, ExtensionError::SignatureInvalid { .. }));
    }

    #[test]
    fn signature_from_wrong_key_of_known_publisher_is_rejected() {
        let anchors = anchors_with("acme", &SEED, TrustTier::Official);
        let forged = Signature::sign_ed25519("acme", &OTHER_SEED, &payload());
        assert!(matches!(
            anchors.verify("acme/pack", &payload(), Some(&forged)),
            Err(ExtensionError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn unknown_publisher_stays_local_without_rejecting() {
        let anchors = anchors_with("acme", &SEED, TrustTier::Official);
        let sig = Signature::sign_ed25519("someone-else", &OTHER_SEED, &payload());
        let v = anchors.verify("acme/pack", &payload(), Some(&sig)).unwrap();
        assert_eq!(
            v,
            Verification::UnknownPublisher {
                publisher: "someone-else".to_string()
            }
        );
        assert_eq!(v.tier(), TrustTier::Local);
    }

    #[test]
    fn empty_anchors_never_elevate() {
        let sig = Signature::sign_ed25519("acme", &SEED, &payload());
        let v = TrustAnchors::new()
            .verify("acme/pack", &payload(), Some(&sig))
            .unwrap();
        assert_eq!(v.tier(), TrustTier::Local);
    }

    #[test]
    fn unsupported_algorithm_and_malformed_values_are_rejected() {
        let anchors = anchors_with("acme", &SEED, TrustTier::Official);
        let mut sig = Signature::sign_ed25519("acme", &SEED, &payload());
        sig.algorithm = "rsa".to_string();
        assert!(anchors.verify("x", &payload(), Some(&sig)).is_err());

        let mut sig = Signature::sign_ed25519("acme", &SEED, &payload());
        sig.value = "!!not base64!!".to_string();
        assert!(anchors.verify("x", &payload(), Some(&sig)).is_err());

        let mut sig = Signature::sign_ed25519("acme", &SEED, &payload());
        sig.value = base64::engine::general_purpose::STANDARD.encode([1u8; 10]);
        assert!(anchors.verify("x", &payload(), Some(&sig)).is_err());
    }

    #[test]
    fn rotated_keys_both_verify() {
        let mut anchors = anchors_with("acme", &SEED, TrustTier::Official);
        let line = format!("acme ed25519 {}", public_key_base64(&OTHER_SEED));
        anchors.add_key_file(TrustTier::Official, &line).unwrap();
        assert_eq!(anchors.len(), 2);
        for seed in [&SEED, &OTHER_SEED] {
            let sig = Signature::sign_ed25519("acme", seed, &payload());
            assert_eq!(
                anchors
                    .verify("acme/pack", &payload(), Some(&sig))
                    .unwrap()
                    .tier(),
                TrustTier::Official
            );
        }
    }

    #[test]
    fn key_file_ignores_comments_and_rejects_bad_lines_atomically() {
        let mut anchors = TrustAnchors::new();
        let good = format!("# comment\n\nacme ed25519 {}\n", public_key_base64(&SEED));
        assert_eq!(anchors.add_key_file(TrustTier::Official, &good).unwrap(), 1);
        assert_eq!(
            TrustAnchors::new()
                .add_key_file(TrustTier::Official, "# only a comment\n")
                .unwrap(),
            0
        );

        let bad = format!(
            "acme ed25519 {}\nbroken line\n",
            public_key_base64(&OTHER_SEED)
        );
        assert!(anchors.add_key_file(TrustTier::Official, &bad).is_err());
        assert_eq!(anchors.len(), 1, "a bad file adds nothing");

        assert!(TrustAnchors::new()
            .add_key_file(TrustTier::Official, "acme rsa AAAA")
            .is_err());
        assert!(TrustAnchors::new()
            .add_key_file(TrustTier::Official, "acme ed25519 AAAA")
            .is_err());
    }

    #[test]
    fn local_tier_anchor_is_refused() {
        let key = base64::engine::general_purpose::STANDARD
            .decode(public_key_base64(&SEED))
            .unwrap();
        assert!(matches!(
            TrustAnchors::new().add("acme", TrustTier::Local, &key),
            Err(ExtensionError::InvalidTrustAnchor { .. })
        ));
    }

    #[test]
    fn signature_round_trips_as_detached_file_shape() {
        let sig = Signature::sign_ed25519("acme", &SEED, b"x");
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
        assert_eq!(sig.algorithm, ED25519);
    }

    #[test]
    fn tier_wire_names() {
        assert_eq!(TrustTier::Official.as_str(), "official");
        assert_eq!(TrustTier::default(), TrustTier::Local);
        assert!(TrustTier::Official > TrustTier::Verified);
    }
}
