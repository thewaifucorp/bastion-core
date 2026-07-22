//! Unified capability registry — single invoke surface with policy middleware.
//!
//! D-13: One canonical capability definition (name + typed I/O + invoke).
//! D-14: SPEC validated with Architect before this implementation.
//!
//! Non-negotiable guardrails (D-13):
//! 1. Uniform interface — registry guarantees, not implementation purity
//! 2. ONE policy middleware at registry boundary (CapabilityRegistry::invoke)
//! 3. No call path bypasses check_egress or approval queue
//!
//! M2 step 3b: the MCP→capability adapters (`adapters.rs`) did NOT move with
//! this module — they are MCP logic (they hold an `Arc<McpClient>`) and stay
//! in the app crate (`src/capability/adapters.rs`), registering themselves
//! through this registry's public API.

pub mod approval;
pub mod auth_resolver;
pub mod permission_queue;
pub mod registry;
pub mod structured_output;

pub use approval::{
    ApprovalOutcome, ApprovalRow, ApprovalStatus, NullApprovalGate, SqliteApprovalGate,
};
pub use auth_resolver::NullAuthResolver;
pub use permission_queue::{NullPermissionGate, SqlitePermissionGate};
pub use registry::{
    check_tool_allowed, Capability, CapabilityRegistry, InvokeCtx, TaggedValue,
    TurnCapabilityScope,
};
