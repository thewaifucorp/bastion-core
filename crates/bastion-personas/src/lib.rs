//! Personas extension crate (M2 substrate split, step 6,
//! `docs/revamp/M1-ADR-substrate-split.md`).
//!
//! Hosts `Persona`/`PersonaRegistry` (SOUL.md loading), the router (turn
//! classification into Single/Parallel/Cabinet), the runner (Single/Parallel
//! dispatch), and `PersonaResponder` — the production [`Responder`] port
//! implementation (`bastion_runtime::agent::ports::Responder`) that also
//! convenes the Cabinet (`bastion_cognition::cabinet`) for
//! `ResponseMode::Cabinet` turns.
//!
//! Depends on the kernel (`bastion-types`, `bastion-runtime`), the
//! quasi-kernel (`bastion-memory`), and `bastion-cognition` (one-way:
//! `bastion-cognition` never depends back on this crate — see
//! `bastion_cognition::cabinet::build_table`'s doc comment for the V4 cut
//! that keeps it that way).

pub mod persona;

pub use bastion_cognition::cabinet;
pub use bastion_runtime::{agent, capability, hooks, provider};

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
