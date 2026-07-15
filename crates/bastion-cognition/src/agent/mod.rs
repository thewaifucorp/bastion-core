//! Cognition-layer context providers and the Dream belief-distillation
//! mechanism — moved verbatim from `src/agent/{dream,procedural,memory_rag,
//! identity}.rs` (M2 step 6). Named `agent` (not e.g. `providers`) to mirror
//! the monolith's `crate::agent::{dream, procedural, memory_rag, identity}`
//! paths exactly — `bastion::agent::mod.rs` re-exports this submodule under
//! the same names, so external paths keep compiling unchanged.
//!
//! `agent::command` (cockpit UX) and `agent::skills` (SkillsLoader — product,
//! M2 step 7) do NOT move here. Nor does `agent::{loop_, ports, context,
//! handle, compactor}` — those are the kernel and already live in
//! `bastion_runtime::agent`.

pub mod dream;
pub mod identity;
pub mod memory_rag;
pub mod procedural;
