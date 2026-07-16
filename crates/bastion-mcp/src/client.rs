use crate::registry::ToolRegistry;
use crate::types::BastionError;
use rmcp::model::CallToolRequestParams;
use rmcp::{
    service::{RoleClient, RunningService},
    ServiceExt,
};
use serde_json::Value;
use tokio::time::{timeout, Duration};

pub struct McpClient {
    // RunningService<RoleClient, ()> must live for daemon lifetime (Pitfall 3 in RESEARCH.md)
    // RunningService implements Deref<Target = Peer<RoleClient>>, so call list_all_tools()/call_tool() directly on it
    servers: Vec<(String, RunningService<RoleClient, ()>)>,
    registry: ToolRegistry,
    /// SEC-03: Composio OAuth client — when set, a failing tool call against a
    /// Composio-labeled server gets exactly ONE bounded retry after
    /// `refresh_if_expired` (T-11-06-03: never a cascading retry storm). `None`
    /// (the default) is zero behavior change — every call site that doesn't opt in
    /// via [`Self::with_composio_oauth`] behaves exactly as before this plan.
    composio_oauth: Option<std::sync::Arc<crate::oauth::ComposioOAuth>>,
}

impl McpClient {
    /// Connect from the host application's typed MCP server configuration.
    pub async fn connect_from_config(
        servers: &std::collections::HashMap<String, crate::types::McpServerEntry>,
    ) -> anyhow::Result<Self> {
        let mut obj = serde_json::Map::new();
        for (key, entry) in servers {
            let label = if entry.label.is_empty() {
                key.clone()
            } else {
                entry.label.clone()
            };
            // url-based servers (streamable-http / SSE); internal network, no auth header.
            // is_local (Plan 10-08): threaded through so connect_from_servers_obj can pass
            // it to ToolRegistry::register_with_schema — the typed locality flag flows
            // config -> intermediate JSON -> registry, never re-derived from tool_name.
            // trusted (Plan 11-04): threaded the SAME way, alongside is_local, so
            // Plans 11-07/11-08 can consume ToolRegistry::is_trusted() later.
            obj.insert(
                label,
                serde_json::json!({
                    "url": entry.url,
                    "transport": "sse",
                    "is_local": entry.is_local,
                    "trusted": entry.trusted,
                }),
            );
        }
        Self::connect_from_servers_obj(&obj).await
    }

    /// Shared connect loop over a `{ label: {url|command,...} }` map.
    async fn connect_from_servers_obj(
        mcp_servers: &serde_json::Map<String, Value>,
    ) -> anyhow::Result<Self> {
        let mut servers: Vec<(String, RunningService<RoleClient, ()>)> = Vec::new();
        let mut registry = ToolRegistry::new();

        for (label, server_cfg) in mcp_servers {
            let transport = server_cfg
                .get("transport")
                .and_then(|v| v.as_str())
                .unwrap_or("sse");
            // Plan 10-08: typed, operator-controlled locality flag from
            // `[mcp.servers.*].is_local` — defaults to false (fail-closed) for any
            // server config that omits it.
            let is_local = server_cfg
                .get("is_local")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // Plan 11-04: typed, operator-controlled trust flag from
            // `[mcp.servers.*].trusted` — same default-false, same fail-closed
            // convention as is_local above (threaded through the same JSON hop).
            let trusted = server_cfg
                .get("trusted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let service_result = match transport {
                "stdio" => {
                    let command = match server_cfg.get("command").and_then(|v| v.as_str()) {
                        Some(c) => c.to_owned(),
                        None => {
                            tracing::warn!(server = %label, "STDIO server missing 'command' field, skipping");
                            continue;
                        }
                    };
                    let args: Vec<String> = server_cfg
                        .get("args")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    connect_stdio(
                        &command,
                        &args.iter().map(String::as_str).collect::<Vec<_>>(),
                    )
                    .await
                }
                // "sse" is the default transport (see unwrap_or("sse") above); any other
                // value falls through here too.
                _ => {
                    let url = match server_cfg.get("url").and_then(|v| v.as_str()) {
                        Some(u) => u.to_owned(),
                        None => {
                            tracing::warn!(server = %label, "SSE server missing 'url' field, skipping");
                            continue;
                        }
                    };
                    // Optional bearer token: literal or `${ENV_VAR}` reference. Sent as
                    // `Authorization: Bearer <token>`.
                    let auth_token =
                        resolve_secret(server_cfg.get("auth_token").and_then(|v| v.as_str()));
                    // Optional custom headers (each value: literal or `${ENV_VAR}`). Needed by
                    // servers with non-Bearer auth, e.g. Composio's `x-consumer-api-key`.
                    let custom_headers: Vec<(String, String)> = server_cfg
                        .get("headers")
                        .and_then(|v| v.as_object())
                        .map(|obj| {
                            obj.iter()
                                .filter_map(|(k, v)| {
                                    resolve_secret(v.as_str()).map(|val| (k.clone(), val))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    connect_sse(&url, auth_token, custom_headers).await
                }
            };

            match service_result {
                Ok(service) => {
                    // Fetch tools at startup — satisfies CORE-02 (full schemas available immediately)
                    match service.list_all_tools().await {
                        Ok(tools) => {
                            for tool in tools {
                                // input_schema is Arc<JsonObject> (Map<String, Value>) — wrap as Value::Object
                                let schema = Value::Object((*tool.input_schema).clone());
                                let description = tool
                                    .description
                                    .as_ref()
                                    .map(|d| d.to_string())
                                    .unwrap_or_default();
                                // Plan 11-04 / SEC-01: source needs_approval from the MCP
                                // wire protocol's OWN `ToolAnnotations.destructive_hint`
                                // (rmcp::model::Tool.annotations) — never a tool-name
                                // string match. Fail-cautious default: a tool that omits
                                // the hint entirely (annotations absent, or annotations
                                // present but destructive_hint absent) is treated as
                                // destructive (`unwrap_or(true)`), matching the MCP
                                // spec's own fail-cautious semantics and D-01's
                                // "irreversible-only" fail-safe intent.
                                let needs_approval = tool
                                    .annotations
                                    .as_ref()
                                    .and_then(|a| a.destructive_hint)
                                    .unwrap_or(true);
                                registry.register_with_schema(
                                    label,
                                    tool.name.to_string(),
                                    schema,
                                    description,
                                    is_local,
                                    needs_approval,
                                    trusted,
                                );
                            }
                            tracing::info!(server = %label, "MCP server connected and tools registered");
                            servers.push((label.clone(), service));
                        }
                        Err(e) => {
                            tracing::warn!(server = %label, error = %e, "connected but failed to list tools, skipping");
                        }
                    }
                }
                Err(e) => {
                    // Non-fatal — Composio URL might not be configured yet
                    tracing::warn!(server = %label, error = %e, "failed to connect to MCP server, skipping");
                }
            }
        }

        Ok(McpClient {
            servers,
            registry,
            composio_oauth: None,
        })
    }

    /// SEC-03: opt in a Composio OAuth client so calls to Composio-labeled servers
    /// get a bounded single retry (via `refresh_if_expired`) on failure. Builder
    /// style — called once by main.rs after `connect_from_config`, mirrors the
    /// codebase's `with_owner_map`/`with_default_persona` builder idiom.
    pub fn with_composio_oauth(
        mut self,
        oauth: std::sync::Arc<crate::oauth::ComposioOAuth>,
    ) -> Self {
        self.composio_oauth = Some(oauth);
        self
    }

    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// `owner` is the resolved owner for this call — threaded through only so
    /// the Composio bounded-retry below can refresh the RIGHT owner's OAuth
    /// connection (milestone-close code review, 2026-07-13: previously
    /// hardcoded to `DEFAULT_OWNER`, silently refreshing the wrong/nonexistent
    /// connection for any non-default owner in a multi-owner deployment).
    pub async fn call_tool_with_timeout(
        &self,
        name: &str,
        args: Value,
        owner: &str,
    ) -> anyhow::Result<Value> {
        let server_label = match self.registry.server_for(name) {
            Some(label) => label.to_owned(),
            None => anyhow::bail!("tool '{}' not found in any connected MCP server", name),
        };

        match self.dispatch_call(&server_label, name, &args).await {
            Ok(v) => Ok(v),
            Err(e) => {
                // T-11-06-03: bounded single retry for Composio-backed servers. MCP
                // tool-call errors are opaque strings (rmcp doesn't surface a typed
                // HTTP status), so we retry once on ANY failure from a
                // Composio-labeled server rather than string-sniffing for "401" —
                // `refresh_if_expired` itself is cheap (a single GET) and the retry
                // is hard-capped at exactly one attempt, never a cascade.
                match (
                    &self.composio_oauth,
                    composio_toolkit_from_label(&server_label),
                ) {
                    (Some(oauth), Some(toolkit)) => {
                        tracing::warn!(
                            event = "composio_tool_call_retry",
                            server = %server_label,
                            tool = %name,
                            error = %e,
                            "tool call failed on a Composio-backed server — refreshing connection and retrying once"
                        );
                        if let Err(refresh_err) = oauth.refresh_if_expired(owner, toolkit).await {
                            tracing::warn!(event = "composio_refresh_failed", error = %refresh_err);
                        }
                        self.dispatch_call(&server_label, name, &args).await
                    }
                    _ => Err(e),
                }
            }
        }
    }

    /// Single dispatch attempt against an already-resolved server label — extracted
    /// so `call_tool_with_timeout` can call it twice (original + the ONE bounded
    /// Composio retry) without duplicating the timeout/error-mapping logic.
    async fn dispatch_call(
        &self,
        server_label: &str,
        tool_name: &str,
        args: &Value,
    ) -> anyhow::Result<Value> {
        let server = self
            .servers
            .iter()
            .find(|(label, _)| label == server_label)
            .map(|(_, svc)| svc);

        let server = match server {
            Some(s) => s,
            None => anyhow::bail!(
                "server '{}' for tool '{}' not in active connections",
                server_label,
                tool_name
            ),
        };

        let mut params = CallToolRequestParams::new(tool_name.to_owned());
        params.arguments = args.as_object().cloned();

        let call_future = server.call_tool(params);
        match timeout(Duration::from_secs(30), call_future).await {
            Ok(Ok(result)) => {
                Ok(serde_json::to_value(result.content.first()).unwrap_or(Value::Null))
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("tool call failed: {}", e)),
            Err(_elapsed) => Err(BastionError::McpTimeout {
                tool: tool_name.to_owned(),
                elapsed_ms: 30_000,
            }
            .into()),
        }
    }
}

/// Lightweight, self-contained "is this server Composio-backed" signal (no new
/// config surface, per the plan's `<action>`): a server label configured as
/// `composio-<toolkit>`/`composio_<toolkit>` (or bare `composio` as a fallback) is
/// treated as Composio-backed, and the toolkit slug is derived from the label.
/// Returns `None` for any label that doesn't look Composio-backed — the caller
/// then never attempts the bounded retry for ordinary (non-Composio) MCP servers.
fn composio_toolkit_from_label(label: &str) -> Option<&str> {
    let lower_has_composio = label.to_lowercase().contains("composio");
    if !lower_has_composio {
        return None;
    }
    label
        .strip_prefix("composio-")
        .or_else(|| label.strip_prefix("composio_"))
        .or_else(|| label.strip_prefix("Composio-"))
        .or_else(|| label.strip_prefix("Composio_"))
        .filter(|rest| !rest.is_empty())
        .or(Some(label))
}

async fn connect_stdio(
    command: &str,
    args: &[&str],
) -> anyhow::Result<RunningService<RoleClient, ()>> {
    use rmcp::transport::TokioChildProcess;
    let mut cmd = tokio::process::Command::new(command);
    cmd.args(args);
    let transport = TokioChildProcess::new(cmd)?;
    let service: RunningService<RoleClient, ()> = ().serve(transport).await?;
    Ok(service)
}

async fn connect_sse(
    uri: &str,
    auth_token: Option<String>,
    custom_headers: Vec<(String, String)>,
) -> anyhow::Result<RunningService<RoleClient, ()>> {
    use reqwest::header::{HeaderName, HeaderValue};
    use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
    use rmcp::transport::StreamableHttpClientTransport;

    let mut config = StreamableHttpClientTransportConfig::default();
    config.uri = uri.into();
    // Bearer convenience (`Authorization: Bearer <token>`).
    config.auth_header = auth_token;
    // Arbitrary headers — required by servers using non-Bearer auth, e.g.
    // Composio's `x-consumer-api-key`.
    for (name, value) in custom_headers {
        match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            (Ok(n), Ok(v)) => {
                config.custom_headers.insert(n, v);
            }
            _ => tracing::warn!(header = %name, "invalid custom header name/value, skipping"),
        }
    }
    let transport = StreamableHttpClientTransport::from_config(config);
    let service: RunningService<RoleClient, ()> = ().serve(transport).await?;
    Ok(service)
}

/// Resolve a config string that may reference an env var as `${VAR_NAME}`.
/// Literal values pass through unchanged. Returns None for missing/empty.
fn resolve_secret(raw: Option<&str>) -> Option<String> {
    let v = raw?.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(var) = v.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        match std::env::var(var) {
            Ok(val) if !val.trim().is_empty() => Some(val),
            _ => {
                tracing::warn!(env = %var, "auth_token references unset/empty env var");
                None
            }
        }
    } else {
        Some(v.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::CallToolResult;
    use rmcp::service::{MaybeSendFuture, RequestContext, RoleServer};
    use rmcp::ErrorData as McpError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // ── composio_toolkit_from_label (pure, no transport needed) ────────────────

    #[test]
    fn composio_toolkit_from_label_recognizes_dash_and_underscore_prefixes() {
        assert_eq!(composio_toolkit_from_label("composio-gmail"), Some("gmail"));
        assert_eq!(composio_toolkit_from_label("composio_slack"), Some("slack"));
    }

    #[test]
    fn composio_toolkit_from_label_falls_back_to_whole_label() {
        // Bare "composio" (no toolkit suffix) — fallback to the whole label.
        assert_eq!(composio_toolkit_from_label("composio"), Some("composio"));
    }

    #[test]
    fn composio_toolkit_from_label_rejects_non_composio_labels() {
        assert_eq!(composio_toolkit_from_label("memupalace"), None);
        assert_eq!(composio_toolkit_from_label("voice"), None);
    }

    // ── call_tool_with_timeout bounded single retry (real in-process MCP pair) ──

    /// Scripted MCP server that always errors on `call_tool` and counts every
    /// attempt — lets the retry test assert "exactly 2 calls" (original + ONE
    /// bounded retry), never a cascade (T-11-06-03).
    struct AlwaysErrorServer {
        calls: Arc<AtomicUsize>,
    }

    impl rmcp::ServerHandler for AlwaysErrorServer {
        fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + MaybeSendFuture + '_
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(McpError::internal_error("scripted failure", None)))
        }
    }

    async fn make_composio_oauth_with_no_stored_connection(
    ) -> (tempfile::NamedTempFile, crate::oauth::ComposioOAuth) {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let session = bastion_runtime::session::SessionManager::new(&path);
        session.init_schema().await.expect("init_schema");
        // No connection stored for (owner, toolkit) — refresh_if_expired() is a fast
        // no-op (Ok(())) per its own contract, so this test doesn't need a live
        // Composio mock server to exercise the retry-counting behavior.
        let oauth = crate::oauth::ComposioOAuth::new_for_test(&path, "http://unused.invalid");
        (f, oauth)
    }

    #[tokio::test]
    async fn call_tool_with_timeout_retries_exactly_once_for_composio_backed_server() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (server_transport, client_transport) = tokio::io::duplex(4096);

        {
            let calls = calls.clone();
            tokio::spawn(async move {
                let server = AlwaysErrorServer { calls }
                    .serve(server_transport)
                    .await
                    .expect("server connect");
                let _ = server.waiting().await;
            });
        }

        let client_service: RunningService<RoleClient, ()> =
            ().serve(client_transport).await.expect("client connect");

        let mut registry = ToolRegistry::new();
        registry.register_with_schema(
            "composio-gmail",
            "send_email".to_string(),
            serde_json::json!({"type": "object", "properties": {}}),
            String::new(),
            false,
            false,
            false,
        );

        let (_f, oauth) = make_composio_oauth_with_no_stored_connection().await;

        let client = McpClient {
            servers: vec![("composio-gmail".to_string(), client_service)],
            registry,
            composio_oauth: Some(Arc::new(oauth)),
        };

        let result = client
            .call_tool_with_timeout("send_email", serde_json::json!({}), "alice")
            .await;

        assert!(result.is_err(), "scripted server always errors");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "must retry exactly once (original attempt + ONE bounded retry), never a cascade"
        );
    }

    #[tokio::test]
    async fn call_tool_with_timeout_does_not_retry_for_non_composio_server() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (server_transport, client_transport) = tokio::io::duplex(4096);

        {
            let calls = calls.clone();
            tokio::spawn(async move {
                let server = AlwaysErrorServer { calls }
                    .serve(server_transport)
                    .await
                    .expect("server connect");
                let _ = server.waiting().await;
            });
        }

        let client_service: RunningService<RoleClient, ()> =
            ().serve(client_transport).await.expect("client connect");

        let mut registry = ToolRegistry::new();
        registry.register_with_schema(
            "memupalace",
            "recall".to_string(),
            serde_json::json!({"type": "object", "properties": {}}),
            String::new(),
            true,
            false,
            false,
        );

        let (_f, oauth) = make_composio_oauth_with_no_stored_connection().await;

        let client = McpClient {
            servers: vec![("memupalace".to_string(), client_service)],
            registry,
            // composio_oauth is configured, but the server label isn't Composio-backed
            // — must still be zero behavior change (no retry) for ordinary servers.
            composio_oauth: Some(Arc::new(oauth)),
        };

        let result = client
            .call_tool_with_timeout("recall", serde_json::json!({}), "alice")
            .await;

        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "non-Composio-labeled servers must never get the bounded retry"
        );
    }
}
