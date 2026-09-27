//! Secrets a node keeps for the owner, dormant (§5.7, BMD-18, BMD-29..33).
//!
//! The primary seals each granted secret to the node's **secrets key** (an
//! age X25519 recipient in the node's enrollment, separate from the replica
//! key). The node stores only ciphertext ([`SealedSecretStore`]); the
//! private half of its secrets key is wrapped by the host with the owner's
//! local presence (Windows Hello, system authentication, passphrase) and
//! unwrapped only at promotion. Nothing in the node side of this crate can
//! open a sealed secret: [`open`] needs that unwrapped identity.
//!
//! Nothing is sealed without a [`SecretGrant`] naming the secret **and** the
//! device ([`seal_for_device`]).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::enrollment::{sig_b64, DeviceId, DeviceRecord};

/// One secret, encrypted to one device's secrets key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub name: String,
    /// Increases with every rotation on the primary (BMD-31).
    pub version: u64,
    pub device: DeviceId,
    #[serde(with = "sig_b64")]
    pub ciphertext: Vec<u8>,
}

/// A secret's current value on the primary.
pub struct SecretValue {
    pub value: Zeroizing<Vec<u8>>,
    pub version: u64,
}

pub fn seal(
    recipient: &str,
    device: &DeviceId,
    name: &str,
    version: u64,
    value: &[u8],
) -> anyhow::Result<SealedSecret> {
    let recipient: age::x25519::Recipient = recipient
        .parse()
        .map_err(|e| anyhow::anyhow!("secrets key of {device}: {e}"))?;
    let ciphertext =
        age::encrypt(&recipient, value).map_err(|e| anyhow::anyhow!("sealing {name}: {e}"))?;
    Ok(SealedSecret {
        name: name.into(),
        version,
        device: device.clone(),
        ciphertext,
    })
}

/// Everything `record` may keep, sealed to its secrets key: exactly the
/// secrets it holds a grant for, each at its current version. A device
/// without a secrets key, revoked, or without grants gets nothing.
pub fn seal_for_device(
    record: &DeviceRecord,
    lookup: impl Fn(&str) -> Option<SecretValue>,
) -> anyhow::Result<Vec<SealedSecret>> {
    let Some(recipient) = &record.enrollment.secrets_recipient else {
        return Ok(Vec::new());
    };
    if record.revoked {
        return Ok(Vec::new());
    }
    record
        .secret_grants
        .iter()
        .filter(|grant| grant.device == record.enrollment.device)
        .filter_map(|grant| lookup(&grant.secret).map(|value| (grant, value)))
        .map(|(grant, value)| {
            seal(
                recipient,
                &record.enrollment.device,
                &grant.secret,
                value.version,
                &value.value,
            )
        })
        .collect()
}

/// Open a sealed secret. Only a promoted device has `identity` (its secrets
/// key, unwrapped with the owner present).
pub fn open(
    identity: &age::x25519::Identity,
    sealed: &SealedSecret,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    age::decrypt(identity, &sealed.ciphertext)
        .map(Zeroizing::new)
        .map_err(|e| anyhow::anyhow!("opening {}: {e}", sealed.name))
}

/// The node's sealed secrets on disk: ciphertext only.
pub struct SealedSecretStore {
    path: PathBuf,
}

impl SealedSecretStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Replace the whole set (what the primary sent is the current truth:
    /// a rotated secret replaces its old version, an ungranted one goes).
    pub fn replace(&self, secrets: &[SealedSecret]) -> anyhow::Result<()> {
        std::fs::write(&self.path, serde_json::to_vec(secrets)?)?;
        Ok(())
    }

    pub fn load(&self) -> anyhow::Result<Vec<SealedSecret>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete everything (revocation).
    pub fn wipe(&self) -> anyhow::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
