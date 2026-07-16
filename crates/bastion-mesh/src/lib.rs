//! Mesh extension crate (M2 substrate split, step 6,
//! `docs/ARCHITECTURE.md`).
//!
//! Hosts the mesh connectivity layer (`MeshTransport`, the P2P OSS impl, the
//! per-owner export allowlist, the `MeshSliceProvider` SEAM #2 context
//! provider), agent identity (`AgentCard` + Ed25519 signing, SEC-06), the
//! `.af` interop format (export/import), and the periodic mesh-sync
//! scheduler (`scheduler::cron`).
//!
//! `scheduler` lands here rather than in `bastion-cognition` (despite the
//! BACKLOG topology table grouping it there) — see
//! `bastion_cognition::lib`'s doc comment for the M2 step 6 rationale.
//!
//! Depends on the kernel (`bastion-types`, `bastion-runtime`), the
//! quasi-kernel (`bastion-memory`), and both `bastion-cognition` and
//! `bastion-personas` (the `.af` interop format spans goal + persona data;
//! neither of those crates depends back on this one).

pub mod identity;
pub mod interop;
pub mod mesh;
pub mod scheduler;

pub use bastion_cognition::goal;
pub use bastion_personas::persona;
pub use bastion_runtime::{agent, hooks, session};

/// Internal alias so the files moved verbatim from the monolith keep their
/// `crate::memory::...` import paths compiling unchanged.
pub mod memory {
    pub use bastion_memory::*;
}

/// Internal alias so the files moved verbatim from the monolith keep their
/// `crate::types::...` import paths compiling unchanged.
pub mod types {
    pub use bastion_types::*;
}
