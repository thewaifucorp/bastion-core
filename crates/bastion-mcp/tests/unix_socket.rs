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

const TOKEN_NAME: &str = "mcp/memory-token";
const TOKEN_VALUE: &str = "tok-7f3a9c";

/// Resolves exactly one reference, the way a host's secret store would.
struct OneSecret;

impl bastion_types::SecretResolver for OneSecret {
    fn resolve(
        &self,
        name: &str,
    ) -> Result<bastion_types::SecretValue, bastion_types::BastionError> {
        if name == TOKEN_NAME {
            Ok(bastion_types::SecretValue::new(TOKEN_VALUE))
        } else {
            Err(bastion_types::BastionError::SecretNotFound {
                name: name.to_owned(),
            })
        }
    }
}

/// An MCP server that answers 401 unless `Authorization: Bearer <TOKEN_VALUE>`
/// arrives on every request.
fn serve_with_bearer(socket: &std::path::Path) {
    use axum::http::{header::AUTHORIZATION, StatusCode};
    use axum::response::IntoResponse;
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let service = StreamableHttpService::new(
        || Ok(OneTool),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router =
        axum::Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(
                |req: axum::extract::Request, next: axum::middleware::Next| async move {
                    let expected = format!("Bearer {TOKEN_VALUE}");
                    let ok = req
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v == expected);
                    if ok {
                        next.run(req).await
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                },
            ));
    tokio::spawn(async move { axum::serve(listener, router).await });
}

fn entry_with_token(socket: &std::path::Path, token: Option<&str>) -> McpServerEntry {
    let mut cfg = serde_json::json!({
        "url": format!("unix:{}", socket.display()),
        "label": "memory",
    });
    if let Some(name) = token {
        cfg["bearer_token"] = serde_json::Value::from(name);
    }
    serde_json::from_value(cfg).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_token_reference_is_resolved_and_sent_as_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("memory.sock");
    serve_with_bearer(&socket);

    let entry = entry_with_token(&socket, Some(TOKEN_NAME));
    let servers = std::collections::HashMap::from([("memory".to_string(), entry)]);
    let client = McpClient::connect_from_config_with_secrets(&servers, &OneSecret)
        .await
        .unwrap();
    assert_eq!(client.registry().server_for("remember"), Some("memory"));
}

#[tokio::test(flavor = "multi_thread")]
async fn server_requiring_a_token_is_not_reached_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("memory.sock");
    serve_with_bearer(&socket);

    let no_token = entry_with_token(&socket, None);
    let servers = std::collections::HashMap::from([("memory".to_string(), no_token)]);
    let client = McpClient::connect_from_config_with_secrets(&servers, &OneSecret)
        .await
        .unwrap();
    assert_eq!(client.registry().server_for("remember"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn unresolvable_token_reference_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("memory.sock");
    serve_with_bearer(&socket);

    // Wrong name for this resolver, and no resolver at all.
    let unknown = entry_with_token(&socket, Some("mcp/other-token"));
    let servers = std::collections::HashMap::from([("memory".to_string(), unknown)]);
    let client = McpClient::connect_from_config_with_secrets(&servers, &OneSecret)
        .await
        .unwrap();
    assert_eq!(client.registry().server_for("remember"), None);

    let named = entry_with_token(&socket, Some(TOKEN_NAME));
    let servers = std::collections::HashMap::from([("memory".to_string(), named)]);
    let client = McpClient::connect_from_config(&servers).await.unwrap();
    assert_eq!(client.registry().server_for("remember"), None);
}

#[test]
fn entry_carries_only_the_reference_name() {
    let entry = entry_with_token(std::path::Path::new("/run/m.sock"), Some(TOKEN_NAME));
    assert_eq!(
        entry.bearer_token.as_ref().map(|r| r.name()),
        Some(TOKEN_NAME)
    );
    let shown = format!("{entry:?}");
    assert!(shown.contains(TOKEN_NAME));
    assert!(!shown.contains(TOKEN_VALUE));
}
