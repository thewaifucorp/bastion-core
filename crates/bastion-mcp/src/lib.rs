//! MCP client/server plumbing (M2 substrate split, step 5).
//!
//! Hosts the MCP client (`McpClient`, connection/dispatch, Composio OAuth),
//! the tool registry, the `CapabilityRegistry` composition helper
//! (`registry_setup`), the `ToolSource` port implementation, and the
//! MCP→capability adapters (`McpToolAdapter`/`DirectFnAdapter`/
//! `NlCommandAdapter`).
//!
//! `BastionMcpServer` (the axum-mounted MCP *server* surface Bastion exposes
//! to other agents) deliberately stays behind in `src/mcp/server.rs` in the
//! app crate: it depends on `GoalEngine`/`PersonaRegistry`, which are
//! product/cognition-layer types not part of this extraction step (they land
//! in `bastion-cognition`/`bastion-personas` per the BACKLOG topology table).
//! Moving it here now would either create a cycle back into the app crate or
//! require a real port-based redesign — out of scope for a verbatim move.

pub mod adapters;
pub mod client;
pub mod oauth;
pub mod registry;
pub mod registry_setup;
pub mod tool_source;

/// Internal alias so the files moved verbatim from the monolith keep their
/// `crate::types::...` import paths compiling unchanged (same pattern as
/// `bastion_runtime::types` / `bastion_providers::types`).
pub mod types {
    pub use bastion_types::*;
}

pub use client::McpClient;
pub use oauth::ComposioOAuth;
pub use registry::ToolRegistry;
pub use tool_source::McpToolSource;
