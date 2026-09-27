//! `url = "unix:/path.sock"`: the client speaks streamable-HTTP MCP to a
//! server listening on a Unix socket — a real rmcp server behind axum, the
//! same stack the sidecars' FastMCP speaks.

#![cfg(unix)]

use std::sync::Arc;

use bastion_mcp::McpClient;
use bastion_types::McpServerEntry;
use rmcp::model::{ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool};
use rmcp::service::{MaybeSendFuture, RequestContext};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, tower::StreamableHttpService, StreamableHttpServerConfig,
};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct OneTool;

impl ServerHandler for OneTool {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + MaybeSendFuture + '_
    {
        let schema = serde_json::json!({"type": "object", "properties": {}});
        let schema = Arc::new(schema.as_object().cloned().unwrap_or_default());
        std::future::ready(Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "remember",
            "store a memory",
            schema,
        )])))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connects_to_an_mcp_server_on_a_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("memory.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let service = StreamableHttpService::new(
        || Ok(OneTool),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    tokio::spawn(async move { axum::serve(listener, router).await });

    let entry: McpServerEntry = serde_json::from_value(serde_json::json!({
        "url": format!("unix:{}", socket.display()),
        "label": "memory",
        "is_local": true,
    }))
    .unwrap();
    let servers = std::collections::HashMap::from([("memory".to_string(), entry)]);
    let client = McpClient::connect_from_config(&servers).await.unwrap();
    assert_eq!(client.registry().server_for("remember"), Some("memory"));
}
