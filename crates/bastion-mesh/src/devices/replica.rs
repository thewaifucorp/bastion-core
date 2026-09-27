//! The memory event log (§5.4): every write the primary makes, in order,
//! so a node with `holds_replica` can rebuild the same state.
//!
//! Events are produced by [`super::log::LoggedMemory`] around the primary's
//! `Memory` (beliefs) and by the host through [`super::log::EventLog::record`]
//! (sessions, personas, config), stored on a node by
//! [`super::replica_store::ReplicaStore`], and turned back into a `Memory`
//! at promotion. Secrets never appear in an event (BMD-18): config events
//! name a key, not its value, and secrets travel apart
//! ([`super::secrets`]).

use serde::{Deserialize, Serialize};

use super::enrollment::DeviceId;
use crate::memory::PrivacyTier;

/// A belief id that never collides across devices: the device that created
/// it and its id there.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GlobalId {
    pub origin: DeviceId,
    pub local: i64,
}

/// What a stored belief carries, enough to store it again elsewhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeliefPayload {
    pub owner_id: String,
    pub persona_tag: Option<String>,
    pub content: String,
    pub session_id: String,
    pub source: String,
    pub is_core: bool,
    pub tier: Option<PrivacyTier>,
    /// `Some` for a procedural belief (its keywords and issue).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedural: Option<Procedural>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Procedural {
    pub keywords: Vec<String>,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemoryEventKind {
    BeliefStored {
        id: GlobalId,
        belief: BeliefPayload,
    },
    BeliefRevoked {
        id: GlobalId,
    },
    BeliefSuperseded {
        old: GlobalId,
        new: GlobalId,
    },
    PersonaChanged {
        name: String,
        contract_digest: String,
        /// The persona's contract text (`SOUL.md`), so a promoted replica
        /// has the persona and not only its digest. `None` when the host
        /// replicates personas another way.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contract: Option<String>,
    },
    SessionAppended {
        session: String,
        message_digest: String,
        /// The message itself (serialized `Message`), for the same reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<serde_json::Value>,
    },
    ConfigChanged {
        key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryEvent {
    /// Order on the primary of the epoch.
    pub seq: u64,
    pub epoch: u64,
    pub origin: DeviceId,
    /// Hybrid logical clock, for a stable tie-break.
    pub at: i64,
    pub kind: MemoryEventKind,
}
