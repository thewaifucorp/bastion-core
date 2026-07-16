//! Bastion kernel runtime (M2 substrate split, `docs/ARCHITECTURE.md`).
//!
//! Hosts the agent tool-loop and its policy boundary: `CapabilityRegistry`
//! (the single tool surface), the session store, the runtime hooks
//! (egress/guardrails/output-validation/approval-intent), the `Provider`
//! trait, the `Memory` trait, and every kernel port (`agent::ports`). It is
//! mechanism, not orchestrator: cognition, personas, channels, MCP wiring and
//! concrete providers live in other crates/the app and enter exclusively
//! through the ports defined here.

pub mod agent;
pub mod capability;
pub mod hooks;
pub mod memory;
pub mod provider;
pub mod session;

/// Internal alias so the files moved verbatim from the monolith keep their
/// `crate::types::...` import paths compiling unchanged. The actual types
/// live in `bastion-types` (extracted earlier in M2).
pub mod types {
    pub use bastion_types::*;
}
