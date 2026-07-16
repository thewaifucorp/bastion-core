//! Quasi-kernel memory backends (M2 substrate split, step 4,
//! `docs/ARCHITECTURE.md`).
//!
//! The `Memory` port (trait) and its `SharedMemory` alias live in
//! `bastion_runtime::memory` (M2 step 3b) — the runtime defines the port,
//! backends here implement it. The pure belief/provenance data types live in
//! `bastion-types`. This crate re-exports both so callers keep using
//! `bastion_memory::{Memory, SharedMemory, Belief, ...}` without reaching
//! into the runtime crate directly.

pub use bastion_runtime::memory::{Memory, SharedMemory};
pub use bastion_types::{Belief, BeliefDraft, BeliefKind, Outcome, PendingCorrection, PrivacyTier};

pub mod sqlite;
