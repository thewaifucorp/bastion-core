//! One agent across the owner's devices (spec `multi-device-brain-and-nodes`):
//! one **primary** holds memory, personas and approvals; **nodes** run what
//! the primary orders, confined, and never decide anything on their own.
//!
//! - [`enrollment`] — device identity, roles, grants, the signed registry.
//! - [`protocol`] — the primary↔node messages.
//! - [`transport`] — text frames over WebSocket/TLS; nodes only dial out.
//! - [`node`] — the node side (fencing, grant checks, stop).
//! - [`hub`] — the primary side and the remote-capability adapter.
//! - [`replica`] — the memory event log's shape.

pub mod enrollment;
pub(crate) mod handshake;
pub mod hub;
pub mod node;
pub mod protocol;
pub mod replica;
pub mod transport;

pub use enrollment::{
    CapabilityGrant, DeviceId, DeviceRecord, DeviceRegistry, Enrollment, EnrollmentApproval,
    EnrollmentError, GrantScope, Platform, Role, SecretGrant,
};
pub use hub::{remote_name, HubEvent, PrimaryHub, RemoteCapability};
pub use node::{
    NodeAgent, NodeCapability, NodeConfig, NodeHandle, NodeState, ReplicaSink, RevocationHook,
    SessionEnd,
};
pub use protocol::{
    ApprovalRef, CallId, CapabilityDescriptor, Evidence, InvokeError, NodeToPrimary, PrimaryToNode,
};
