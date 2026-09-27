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
//! - [`log`] — the primary's event log and the logging `Memory` decorator.
//! - [`replica_store`] — a node's encrypted replica.
//! - [`replicate`] — pushes the log to replica nodes, live and on reconnect.
//! - [`secrets`] — secrets sealed to a node, dormant until promotion.
//! - [`fence`] — the epoch a primary writes in, closed once superseded.
//! - [`reconcile`] — merging a returning ex-primary's writes; the conflict
//!   queue.

pub mod enrollment;
pub mod fence;
pub(crate) mod handshake;
pub mod hub;
pub mod log;
pub mod node;
pub mod protocol;
pub mod reconcile;
pub mod replica;
pub mod replica_store;
pub mod replicate;
pub mod secrets;
pub mod transport;

pub use enrollment::{
    CapabilityGrant, DeviceId, DeviceRecord, DeviceRegistry, Enrollment, EnrollmentApproval,
    EnrollmentError, EpochStart, GrantScope, Platform, Role, SecretGrant,
};
pub use hub::{remote_name, HubEvent, PrimaryHub, RemoteCapability};
pub use node::{
    NodeAgent, NodeCapability, NodeConfig, NodeHandle, NodeState, ProposalSource, ReplicaSink,
    RevocationHook, SecretSink, SessionEnd,
};
pub use protocol::{
    ApprovalRef, CallId, CapabilityDescriptor, Evidence, InvokeError, NodeToPrimary, PrimaryToNode,
};
