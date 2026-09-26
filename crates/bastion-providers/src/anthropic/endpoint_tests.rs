//! The three Claude endpoints end to end against a local HTTP server that
//! plays the vendor: what goes on the wire (URL, auth, body) and how the
//! reply is read back.

use super::*;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One request as the fake vendor saw it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn form(&self) -> std::collections::HashMap<String, String> {
        reqwest::Url::parse(&format!(
            "http://x/?{}",
            String::from_utf8_lossy(&self.body)
        ))
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
    }
}

/// A reply: content type and the body as a list of chunks written with a
/// pause between them, so the client sees them as separate reads.
type Reply = (&'static str, Vec<Vec<u8>>);

/// Serves `route(request)` for every connection; returns the base URL and
/// the log of requests.
async fn serve(
    route: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
) -> (String, Arc<StdMutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let log = Arc::new(StdMutex::new(Vec::new()));
    let route = Arc::new(route);
    let seen_log = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let route = route.clone();
            let log = seen_log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let head_end = loop {
                    let n = socket.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut lines = head.lines();
                let mut first = lines.next().unwrap_or_default().split_whitespace();
                let method = first.next().unwrap_or_default().to_string();
                let path = first.next().unwrap_or_default().to_string();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .collect();
                let len: usize = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                let mut body = buf[head_end + 4..].to_vec();
                while body.len() < len {
                    let n = socket.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                let seen = Seen {
                    method,
                    path,
                    headers,
                    body,
                };
                let (content_type, chunks) = route(&seen);
                log.lock().unwrap().push(seen);
                let total: usize = chunks.iter().map(Vec::len).sum();
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {total}\r\nconnection: close\r\n\r\n"
                );
                let _ = socket.write_all(head.as_bytes()).await;
                for chunk in chunks {
                    let _ = socket.write_all(&chunk).await;
                    let _ = socket.flush().await;
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
            });
        }
    });
    (base, log)
}

/// An SSE reply with a text block ("olá, ") + a tool call, cut into chunks
/// at the worst places: inside the two bytes of "á" and inside the tool
/// call's JSON delta line.
fn sse_reply() -> Reply {
    let events = [
        r#"{"type":"message_start","message":{"usage":{"input_tokens":11,"cache_read_input_tokens":5}}}"#,
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"olá, "}}"#,
        r#"{"type":"content_block_stop","index":0}"#,
        r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"memory_store","input":{}}}"#,
        r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"content\":\"caf"}}"#,
        r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"é\"}"}}"#,
        r#"{"type":"content_block_stop","index":1}"#,
        r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}"#,
        r#"{"type":"message_stop"}"#,
    ];
    let stream: String = events
        .iter()
        .map(|e| format!("event: x\ndata: {e}\n\n"))
        .collect();
    let bytes = stream.into_bytes();
    let accent = bytes.windows(2).position(|w| w == "á".as_bytes()).unwrap() + 1;
    let partial = bytes
        .windows(12)
        .position(|w| w == b"partial_json")
        .unwrap()
        + 5;
    let mut cuts = vec![0, accent, partial, bytes.len()];
    cuts.sort_unstable();
    cuts.dedup();
    let chunks = cuts
        .windows(2)
        .map(|w| bytes[w[0]..w[1]].to_vec())
        .collect();
    ("text/event-stream", chunks)
}

fn assert_parsed(reply: &LlmResponse) {
    assert_eq!(reply.text, "olá, ");
    let calls = reply.tool_calls.as_ref().expect("tool call");
    assert_eq!(calls[0].name, "memory_store");
    assert_eq!(calls[0].arguments, serde_json::json!({"content": "café"}));
    assert_eq!(reply.usage.input_tokens, 11);
    assert_eq!(reply.usage.cache_read, 5);
    assert_eq!(reply.usage.output_tokens, 7);
}

fn user(text: &str) -> Vec<Message> {
    vec![Message {
        role: Role::User,
        content: MessageContent::Text(text.to_string()),
    }]
}

fn provider(model: &str, endpoint: Endpoint) -> AnthropicProvider {
    AnthropicProvider {
        client: http_client(),
        model: model.to_string(),
        endpoint,
    }
}

#[tokio::test]
async fn the_direct_api_survives_events_split_across_reads() {
    let (base, log) = serve(|_| sse_reply()).await;
    let claude = provider(
        "claude-sonnet-4-5",
        Endpoint::Direct {
            api_key: "sk-test".into(),
            base_url: base,
        },
    );
    let reply = claude
        .complete(&user("oi"), &CallConfig::default())
        .await
        .unwrap();
    assert_parsed(&reply);

    let seen = log.lock().unwrap()[0].clone();
    assert_eq!(seen.path, "/v1/messages");
    assert_eq!(seen.header("x-api-key"), Some("sk-test"));
    assert_eq!(seen.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(seen.json()["model"], "claude-sonnet-4-5");
    assert_eq!(seen.json()["stream"], true);
    assert_eq!(claude.name(), "anthropic");
}

#[tokio::test]
async fn bedrock_invokes_the_model_by_url_and_reads_the_whole_message() {
    let (base, log) = serve(|_| {
        (
            "application/json",
            vec![serde_json::to_vec(&serde_json::json!({
                "content": [
                    {"type": "text", "text": "olá, "},
                    {"type": "tool_use", "id": "t1", "name": "memory_store",
                     "input": {"content": "café"}}
                ],
                "usage": {"input_tokens": 11, "output_tokens": 7,
                          "cache_read_input_tokens": 5}
            }))
            .unwrap()],
        )
    })
    .await;
    let claude = provider(
        "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        Endpoint::Bedrock(bedrock::Bedrock::new(
            "us-east-1".into(),
            base,
            Some("bedrock-api-key".into()),
        )),
    );
    let reply = claude
        .complete(&user("oi"), &CallConfig::default())
        .await
        .unwrap();
    assert_parsed(&reply);

    let seen = log.lock().unwrap()[0].clone();
    assert_eq!(seen.method, "POST");
    assert_eq!(
        seen.path,
        "/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke"
    );
    assert_eq!(seen.header("authorization"), Some("Bearer bedrock-api-key"));
    let body = seen.json();
    assert_eq!(body["anthropic_version"], "bedrock-2023-05-31");
    assert!(body.get("model").is_none(), "model travels in the URL");
    assert!(body.get("stream").is_none(), "InvokeModel is not streamed");
    assert_eq!(body["messages"][0]["content"], "oi");
    assert_eq!(claude.name(), "bedrock");
}

#[tokio::test]
async fn vertex_exchanges_a_service_account_jwt_and_reuses_the_token() {
    let Some(pem) = vertex::tests::test_key() else {
        eprintln!("skipping: openssl not found");
        return;
    };
    let (base, log) = serve(|seen| {
        if seen.path == "/token" {
            (
                "application/json",
                vec![br#"{"access_token":"ya29.test","expires_in":3600}"#.to_vec()],
            )
        } else {
            sse_reply()
        }
    })
    .await;
    let (source, _) = vertex::source_from_file(&serde_json::json!({
        "type": "service_account",
        "client_email": "bot@p1.iam.gserviceaccount.com",
        "private_key": pem,
        "token_uri": format!("{base}/token"),
    }))
    .unwrap();
    let claude = provider(
        "claude-sonnet-4-5@20250929",
        Endpoint::Vertex(Box::new(vertex::Vertex::new(
            http_client(),
            "p1".into(),
            "us-east5".into(),
            base,
            source,
        ))),
    );

    for _ in 0..2 {
        let reply = claude
            .complete(&user("oi"), &CallConfig::default())
            .await
            .unwrap();
        assert_parsed(&reply);
    }

    let log = log.lock().unwrap().clone();
    let token_calls: Vec<&Seen> = log.iter().filter(|s| s.path == "/token").collect();
    assert_eq!(token_calls.len(), 1, "the token is cached");
    let form = token_calls[0].form();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    assert_eq!(form["assertion"].split('.').count(), 3);

    let predict = log.iter().find(|s| s.path != "/token").unwrap();
    assert_eq!(
        predict.path,
        "/v1/projects/p1/locations/us-east5/publishers/anthropic/models/\
         claude-sonnet-4-5@20250929:streamRawPredict"
    );
    assert_eq!(predict.header("authorization"), Some("Bearer ya29.test"));
    let body = predict.json();
    assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
    assert!(body.get("model").is_none());
    assert_eq!(body["stream"], true);
    assert_eq!(claude.name(), "vertex");
}

#[tokio::test]
async fn vertex_refreshes_an_authorized_user_login() {
    let (base, log) = serve(|seen| {
        if seen.path == "/token" {
            (
                "application/json",
                vec![br#"{"access_token":"ya29.user","expires_in":3600}"#.to_vec()],
            )
        } else {
            sse_reply()
        }
    })
    .await;
    let (source, _) = vertex::source_from_file(&serde_json::json!({
        "type": "authorized_user",
        "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt",
        "token_uri": format!("{base}/token"),
    }))
    .unwrap();
    let claude = provider(
        "claude-sonnet-4-5@20250929",
        Endpoint::Vertex(Box::new(vertex::Vertex::new(
            http_client(),
            "p1".into(),
            "global".into(),
            base,
            source,
        ))),
    );
    claude
        .complete(&user("oi"), &CallConfig::default())
        .await
        .unwrap();
    let log = log.lock().unwrap().clone();
    let form = log.iter().find(|s| s.path == "/token").unwrap().form();
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["refresh_token"], "rt");
    let predict = log.iter().find(|s| s.path != "/token").unwrap();
    assert_eq!(predict.header("authorization"), Some("Bearer ya29.user"));
}

#[tokio::test]
async fn a_vendor_error_is_reported_with_its_status() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 4096];
        let _ = socket.read(&mut tmp).await;
        let body = r#"{"message":"The security token included in the request is invalid."}"#;
        let _ = socket
            .write_all(
                format!(
                    "HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
    });
    let claude = provider(
        "m",
        Endpoint::Bedrock(bedrock::Bedrock::new(
            "us-east-1".into(),
            base,
            Some("k".into()),
        )),
    );
    let err = claude
        .complete(&user("oi"), &CallConfig::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("bedrock HTTP 403"), "{err}");
    assert!(err.contains("security token"), "{err}");
}
