//! Registry composition: populate a [`CapabilityRegistry`] from a connected
//! [`McpClient`] (BIG-1 Gap 2).
//!
//! Moved VERBATIM out of `AgentLoop::new` (M2 step 3b, decision D2): this is
//! MCP logic — the kernel constructor no longer knows how MCP tool metadata
//! maps onto capability adapters. The composition root (`main.rs`) calls this
//! right after constructing the loop, against the SAME registry instance.

use std::sync::Arc;

use crate::client::McpClient;
use bastion_runtime::capability::registry::CapabilityRegistry;

/// Populate `registry` with one [`crate::adapters::McpToolAdapter`] per
/// connected MCP tool.
///
/// BIG-1 (Gap 2): without this the registry stays empty, `list_tool_defs()`
/// returns `[]` (so the normal persona path offers ZERO tools to the LLM), and
/// the `is_empty()` fast-path in `dispatch_tool_loop` bypasses the
/// egress/approval gate. Registering one McpToolAdapter per tool makes ALL
/// tool calls flow through `capability_registry.invoke` (D-13).
pub fn register_mcp_tools(registry: &mut CapabilityRegistry, mcp: &Arc<McpClient>) {
    // Snapshot tool metadata first (owned) so the mcp borrow is released before we
    // mutably borrow the capability registry.
    let mcp_tools: Vec<(String, String, serde_json::Value, String, bool, bool, bool)> = mcp
        .registry()
        .list_tool_names()
        .iter()
        .map(|name| {
            let server_label = mcp.registry().server_for(name).unwrap_or("").to_string();
            let schema = mcp
                .registry()
                .get_tool_schema(name)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));
            let description = mcp
                .registry()
                .get_tool_description(name)
                .unwrap_or("")
                .to_string();
            // Plan 10-08: the load-bearing lookup — any tool whose owning MCP
            // server is config-flagged `is_local = true` (e.g. the voice sidecar,
            // Plan 10-03/10-09's `[mcp.servers.voice]`) is automatically registered
            // as a local capability below, with zero tool-name string matching.
            let is_local = mcp.registry().is_local(name);
            // Plan 11-04: the load-bearing lookup — a tool whose own MCP server
            // self-reported `ToolAnnotations.destructive_hint` (or omitted it,
            // fail-cautious) is automatically registered as needing owner
            // approval below, with zero tool-name string matching. `trusted`
            // mirrors `is_local`'s threading, sourced from the owning server's
            // `McpServerEntry.trusted` config.
            let needs_approval = mcp.registry().needs_approval(name);
            let trusted = mcp.registry().is_trusted(name);
            (
                name.to_string(),
                server_label,
                schema,
                description,
                is_local,
                needs_approval,
                trusted,
            )
        })
        .collect();
    for (tool_name, server_label, schema, description, is_local, needs_approval, trusted) in
        mcp_tools
    {
        let adapter = crate::adapters::McpToolAdapter {
            tool_name: tool_name.clone(),
            server_label,
            description,
            schema,
            mcp: mcp.clone(),
            is_local_override: is_local,
            needs_approval_override: needs_approval,
            trusted_override: trusted,
        };
        if let Err(e) = registry.register(Arc::new(adapter)) {
            tracing::warn!(event = "mcp_capability_register_failed", tool = %tool_name, err = %e);
        }
    }
    let registered = registry.list_tool_defs().len();
    tracing::info!(
        event = "capability_registry_populated",
        mcp_tools = registered
    );
}
