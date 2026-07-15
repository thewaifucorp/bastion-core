//! [`ToolSource`] port implementation wrapping the concrete [`McpClient`].
//!
//! `tool_defs` is moved verbatim from `agent/loop_.rs` (M2 P3): the
//! tool-definition-building block from `run_provider_fallback`.
//! `call_tool_with_timeout` was originally a direct passthrough to
//! `McpClient::call_tool_with_timeout`; M3 hardening (LOOP-REPORT.md finding
//! F1) moved the egress gate INSIDE this method — it now runs
//! `bastion_runtime::hooks::egress::check_egress` on the caller-supplied
//! `resolved_tier` before dispatching, instead of relying on both loop call
//! sites to remember to gate before calling in.

use std::sync::Arc;

use crate::client::McpClient;
use bastion_runtime::agent::ports::ToolSource;
use bastion_runtime::hooks::egress::check_egress;
use bastion_types::PrivacyTier;

/// The production [`ToolSource`]: sources tool defs and dispatches
/// registry-bypass tool calls straight from the connected MCP servers.
pub struct McpToolSource {
    mcp: Arc<McpClient>,
}

impl McpToolSource {
    /// Wrap an already-connected [`McpClient`] (shared with the
    /// `CapabilityRegistry`'s `McpToolAdapter`s via the same `Arc`).
    pub fn new(mcp: Arc<McpClient>) -> Self {
        Self { mcp }
    }
}

#[async_trait::async_trait]
impl ToolSource for McpToolSource {
    async fn tool_defs(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        // D-12/D-14b: list_tool_names() returns sorted-by-name output (Plan
        // 08-02) — this tools array is part of CallConfig and therefore part
        // of the byte-stable-prefix contract build_system_prompt documents.
        // Moved verbatim from `agent/loop_.rs::run_provider_fallback`.
        let tools = self
            .mcp
            .registry()
            .list_tool_names()
            .iter()
            .map(|name| {
                let schema = self
                    .mcp
                    .registry()
                    .get_tool_schema(name)
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));
                serde_json::json!({
                    "name": name,
                    "description": format!("External tool: {}", name),
                    "input_schema": schema
                })
            })
            .collect();
        Ok(tools)
    }

    async fn call_tool_with_timeout(
        &self,
        name: &str,
        args: serde_json::Value,
        owner: &str,
        resolved_tier: Option<PrivacyTier>,
    ) -> anyhow::Result<serde_json::Value> {
        // M3/F1: gate BEFORE dispatch, inside the port implementation — the
        // same check (WR-02/D-13) both loop call sites used to apply
        // manually, now unforgettable by construction. Mirrors the
        // destination classification `CapabilityRegistry::invoke` uses for a
        // non-local capability: registry-bypass MCP tools are "external".
        check_egress(resolved_tier, "external")?;
        self.mcp.call_tool_with_timeout(name, args, owner).await
    }
}
