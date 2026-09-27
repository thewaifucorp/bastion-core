//! Mutual Ed25519 challenge between a node and a primary (§5.2).
//!
//! 1. node → `Hello { device, nonce_n }`
//! 2. primary → `Challenge { nonce_p, primary: its enrollment, sig_p }`,
//!    where `sig_p` signs `nonce_n` — the node checks the enrollment against
//!    the owner key and `sig_p` against the enrollment's device key.
//! 3. node → `Proof { sig_n }`, signing `nonce_p` — the primary checks it
//!    against the node's key in the registry.
//!
//! Each signature names its side, the owner and the signer's device, so a
//! proof can be neither replayed to another peer nor reflected back.

use super::enrollment::{verify as verify_sig, DeviceId};
use crate::identity::age_identity::AgeIdentity;

const AUTH_DOMAIN: &[u8] = b"bastion-device-auth-v1\0";

#[derive(Debug, Clone, Copy)]
pub(crate) enum Side {
    Primary,
    Node,
}

pub(crate) fn nonce() -> [u8; 32] {
    use rand_core::RngCore;
    let mut nonce = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn bytes(side: Side, owner: &str, device: &DeviceId, nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = AUTH_DOMAIN.to_vec();
    out.extend_from_slice(match side {
        Side::Primary => b"primary\0",
        Side::Node => b"node\0\0\0\0",
    });
    for part in [owner.as_bytes(), device.as_str().as_bytes()] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(nonce);
    out
}

pub(crate) fn sign(
    identity: &AgeIdentity,
    side: Side,
    owner: &str,
    device: &DeviceId,
    nonce: &[u8; 32],
) -> Vec<u8> {
    identity.sign(&bytes(side, owner, device, nonce)).to_vec()
}

pub(crate) fn verify(
    key: &[u8; 32],
    side: Side,
    owner: &str,
    device: &DeviceId,
    nonce: &[u8; 32],
    signature: &[u8],
) -> Result<(), ()> {
    verify_sig(key, &bytes(side, owner, device, nonce), signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_verifies_only_for_its_side_owner_device_and_nonce() {
        let id = AgeIdentity::generate();
        let key = id.verifying_key_bytes();
        let device = DeviceId::new("pc");
        let n = nonce();
        let sig = sign(&id, Side::Node, "alice", &device, &n);
        assert!(verify(&key, Side::Node, "alice", &device, &n, &sig).is_ok());
        assert!(verify(&key, Side::Primary, "alice", &device, &n, &sig).is_err());
        assert!(verify(&key, Side::Node, "bob", &device, &n, &sig).is_err());
        assert!(verify(&key, Side::Node, "alice", &DeviceId::new("x"), &n, &sig).is_err());
        assert!(verify(&key, Side::Node, "alice", &device, &nonce(), &sig).is_err());
    }
}
