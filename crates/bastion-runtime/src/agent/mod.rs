//! The kernel agent loop and its ports (M2 step 3b).
//!
//! Product/cognition agent modules (`command`, `dream`, `identity`,
//! `memory_rag`, `procedural`, `skills`) did NOT move with this module — they
//! stay in the app crate and reach the loop exclusively through the traits in
//! [`ports`].

pub mod backend;
pub mod compactor;
pub mod context;
pub mod handle;
pub mod loop_;
pub mod ports;
