//! Wire messages between the primary and a node (§5.2). JSON text frames,
//! one message per frame, tagged by `type`.
//!
//! The node opens the connection; the first frames are the mutual Ed25519
//! challenge (`Hello`/`Challenge`/`Proof`, see `handshake`), after which the
//! primary says `Welcome` and orders flow.

use serde::{Deserialize, Serialize};

use super::enrollment::{sig_b64, DeviceId, Enrollment};
use super::replica::MemoryEvent;
use super::secrets::SealedSecret;

/// Identifies one invocation on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CallId(pub u64);

/// The primary's record that the owner approved this call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRef {
    pub id: i64,
}

/// What proves an effect. Content from a node is untrusted for the primary,
/// like any tool output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// A PNG of a window or screen, base64.
    Screenshot {
        png_base64: String,
        window: String,
    },
    /// A file the call produced or changed.
    File {
        path: String,
        sha256: String,
    },
    Text {
        text: String,
    },
}

/// Why an invocation did not produce a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum InvokeError {
    /// The owner never granted this capability to this node (BMD-10).
    #[error("capability not granted on this device")]
    NotGranted,
    /// The grant requires approval and the order carried none.
    #[error("the grant requires the owner's approval")]
    NeedsApproval,
    /// The order came from an older epoch than the node has seen (BMD-12).
    #[error("order from epoch {got}, this device has seen {seen}")]
    StaleEpoch { seen: u64, got: u64 },
    /// The node does not have this capability at all.
    #[error("no such capability on this device")]
    UnknownCapability,
    /// The arguments fall outside the grant's scope.
    #[error("outside the granted scope: {0}")]
    OutOfScope(String),
    /// The target window closed or changed during a UI action.
    #[error("the window is gone")]
    WindowGone,
    #[error("cancelled")]
    Cancelled,
    /// The node is not connected.
    #[error("device not connected")]
    Unavailable,
    /// The connection dropped before a result arrived: the call may or may
    /// not have run. Never reported as success (§7).
    #[error("outcome unknown (connection lost)")]
    Unknown,
    /// The capability ran and failed.
    #[error("{0}")]
    Failed(String),
}

/// A capability a node offers, as the primary registers it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeToPrimary {
    Hello {
        device: DeviceId,
        epoch_seen: u64,
        replica_seq: Option<u64>,
        /// The node's challenge for the primary.
        #[serde(with = "nonce_b64")]
        nonce: [u8; 32],
    },
    /// The node's answer to the primary's challenge.
    Proof {
        #[serde(with = "sig_b64")]
        signature: Vec<u8>,
    },
    /// What this node offers; sent after `Welcome` and whenever it changes.
    Capabilities {
        capabilities: Vec<CapabilityDescriptor>,
    },
    InvokeResult {
        call: CallId,
        outcome: Result<serde_json::Value, InvokeError>,
        evidence: Vec<Evidence>,
    },
    ReplicaAck {
        seq: u64,
    },
    /// An order the node refused before running it (stale epoch, …) — also
    /// answered as an `InvokeResult`; this is the audit line.
    Rejected {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PrimaryToNode {
    /// The primary's challenge for the node, with the primary's own
    /// owner-signed enrollment and its answer to the node's challenge.
    Challenge {
        #[serde(with = "nonce_b64")]
        nonce: [u8; 32],
        primary: Box<Enrollment>,
        #[serde(with = "sig_b64")]
        signature: Vec<u8>,
    },
    Welcome {
        epoch: u64,
        /// The node's current owner-signed enrollment (its grants).
        enrollment: Box<Enrollment>,
    },
    Invoke {
        call: CallId,
        capability: String,
        args: serde_json::Value,
        approval: Option<ApprovalRef>,
        epoch: u64,
    },
    Cancel {
        call: CallId,
    },
    /// Only for nodes with `holds_replica`.
    Replica {
        from_seq: u64,
        events: Vec<MemoryEvent>,
        epoch: u64,
    },
    /// A newer enrollment for this node (grants changed).
    Grants {
        enrollment: Box<Enrollment>,
    },
    /// The complete set of secrets this node may keep, sealed to its secrets
    /// key (§5.7). Replaces whatever it held.
    Secrets {
        secrets: Vec<SealedSecret>,
        epoch: u64,
    },
    /// The receiver stops being primary.
    Demote {
        new_epoch: u64,
    },
    /// The node was revoked: it deletes its secrets key and disconnects.
    Revoked,
}

mod nonce_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("nonce must be 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_as_tagged_json() {
        let invoke = PrimaryToNode::Invoke {
            call: CallId(7),
            capability: "system.run".into(),
            args: serde_json::json!({"argv": ["git", "status"]}),
            approval: Some(ApprovalRef { id: 3 }),
            epoch: 2,
        };
        let text = serde_json::to_string(&invoke).unwrap();
        assert!(text.contains(r#""type":"invoke""#), "{text}");
        assert_eq!(
            serde_json::from_str::<PrimaryToNode>(&text).unwrap(),
            invoke
        );

        let result = NodeToPrimary::InvokeResult {
            call: CallId(7),
            outcome: Err(InvokeError::StaleEpoch { seen: 3, got: 2 }),
            evidence: vec![Evidence::File {
                path: "out.txt".into(),
                sha256: "ab".into(),
            }],
        };
        let text = serde_json::to_string(&result).unwrap();
        assert_eq!(
            serde_json::from_str::<NodeToPrimary>(&text).unwrap(),
            result
        );
    }
}
