//! Cognition extension crate (M2 substrate split, step 6,
//! `docs/ARCHITECTURE.md`).
//!
//! Hosts Dream (heuristic belief distillation/consolidation), the SEAM #2
//! procedural/factual belief-recall context providers, onboarding identity
//! injection, the goal engine (GOAL-01..03), proactive heartbeat/idle
//! scheduling, the offline learning Reflector (delta/dedup, LEARN-02..05),
//! EVAL-01 failure capture + regression verification, and the Cabinet
//! multi-persona deliberation engine (stable contract, decision #6).
//!
//! Depends only on the kernel (`bastion-types`, `bastion-runtime`) and the
//! quasi-kernel (`bastion-memory`) — never on `bastion-personas`, which
//! depends on THIS crate (`PersonaResponder` calls `cabinet::{build_table,
//! orchestrator::deliberate, synth::synthesize}`), not the other way around.
//! `cabinet::build_table` takes a `Fn(&str) -> Option<Persona>` lookup
//! closure rather than `&PersonaRegistry` for exactly this reason (M2 step 6
//! V4 audit — see its doc comment).
//!
//! `scheduler` (periodic mesh-sync cron, `src/scheduler/cron.rs`) is NOT
//! here despite the BACKLOG topology table grouping it under this crate: it
//! is 100% mesh-sync logic (`scheduler/mod.rs` is only `pub mod cron;`) and
//! needs `MeshPeerMap`/`SharedMeshTransport`/`OwnerAllowlist`/`filter_for_mesh`
//! — concrete `bastion-mesh` types, not pure data. Moving it here now would
//! force a forward dependency on a crate this one is extracted before (this
//! is commit 1 of 3; mesh is commit 3). It moves with `bastion-mesh` instead
//! (documented deviation, same pattern as `terminal_agent.rs` landing in
//! `bastion-providers` rather than `bastion-agent-runtime`, M2 step 5).

pub mod agent;
pub mod cabinet;
pub mod eval;
pub mod goal;
pub mod learn;
pub mod proactive;

pub use bastion_runtime::{capability, hooks, provider, session};

/// Internal alias so the files moved verbatim from the monolith keep their
/// `crate::memory::...` import paths compiling unchanged (same pattern as
/// `bastion_runtime::types` / `bastion_providers::types`).
pub mod memory {
    pub use bastion_memory::*;
}

/// Internal alias so the files moved verbatim from the monolith keep their
/// `crate::types::...` import paths compiling unchanged.
pub mod types {
    pub use bastion_types::*;
}
