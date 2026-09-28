//! Claude through the Anthropic Messages API — directly (API key), on Amazon
//! Bedrock, or on Google Vertex AI. The three share the request body and the
//! response shape; they differ in URL, authentication, and a couple of body
//! fields (`model` travels in the URL on Bedrock/Vertex, which take an
//! `anthropic_version` in the body instead of the header).
//!
//! This is the native-loop path for Claude: Bastion owns the tool loop and
//! pays per token. A Claude subscription is not a model provider (Anthropic's
//! terms allow it only inside the unmodified `claude` binary); that path is
//! the `acp_claude` agent runtime.

mod bedrock;
mod vertex;

#[cfg(test)]
mod endpoint_tests;

use futures_util::StreamExt;
use serde_json::Value;
use std::time::Duration;

use super::Provider;
use crate::types::{
    strip_think, CallConfig, LlmResponse, Message, MessageContent, Role, TokenUsage, ToolCall,
    ToolChoice,
};

/// Parse the `message_start` SSE event's `usage` block into `TokenUsage`, extracted
/// as a pure fn so it is unit-testable against a hand-built fixture without a live
/// stream. Uses the same `.and_then(|v| v.as_u64())` idiom already used for
/// `input_tokens` for the two prompt-caching fields (COST-01/D-14a).
fn apply_message_start_usage(usage: &mut TokenUsage, event: &Value) {
    // Messages API: `input_tokens` excludes cache reads/creations.
    usage.convention = crate::types::UsageConvention::Disjoint;
    if let Some(model) = event["message"]["model"].as_str() {
        usage.response_model = Some(model.to_owned());
    }
    if let Some(u) = event["message"]["usage"].as_object() {
        if let Some(inp) = u.get("input_tokens").and_then(|v| v.as_u64()) {
            usage.input_tokens = inp as u32;
        }
        if let Some(cr) = u.get("cache_read_input_tokens").and_then(|v| v.as_u64()) {
            usage.cache_read = cr as u32;
        }
        if let Some(cw) = u
            .get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64())
        {
            usage.cache_write = cw as u32;
        }
    }
}

pub(crate) struct AnthropicProvider {
    client: reqwest::Client,
    model: String,
    endpoint: Endpoint,
}

/// Where the Messages API is reached, and how.
enum Endpoint {
    /// `api.anthropic.com` (or `ANTHROPIC_BASE_URL`) with an API key.
    Direct {
        api_key: String,
        base_url: String,
    },
    Bedrock(bedrock::Bedrock),
    /// Boxed: it holds an RSA key pair, far larger than the other variants.
    Vertex(Box<vertex::Vertex>),
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("reqwest client")
}

impl AnthropicProvider {
    /// Direct API, key from `ANTHROPIC_API_KEY`.
    pub fn from_env(model: &str) -> anyhow::Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| anyhow::anyhow!("ANTHROPIC_API_KEY is not set"))?;
        Ok(Self::with_api_key(model, api_key))
    }

    /// Build directly from an already-resolved credential, bypassing
    /// `std::env` entirely — the host-injected-secret path
    /// (`registry::resolve_provider_with_credential`).
    pub fn with_api_key(model: &str, api_key: impl Into<String>) -> Self {
        Self {
            client: http_client(),
            model: model.to_owned(),
            endpoint: Endpoint::Direct {
                api_key: api_key.into(),
                base_url: std::env::var("ANTHROPIC_BASE_URL")
                    .ok()
                    .filter(|u| !u.is_empty())
                    .unwrap_or_else(|| "https://api.anthropic.com".to_string()),
            },
        }
    }

    /// Claude on Amazon Bedrock; `model` is a Bedrock model or inference
    /// profile id (`us.anthropic.claude-sonnet-4-5-20250929-v1:0`). Region and
    /// credentials come from the standard AWS environment (see
    /// [`bedrock::Bedrock::from_env`]).
    pub fn bedrock(model: &str) -> anyhow::Result<Self> {
        Ok(Self {
            client: http_client(),
            model: model.to_owned(),
            endpoint: Endpoint::Bedrock(bedrock::Bedrock::from_env()?),
        })
    }

    /// Claude on Google Vertex AI; `model` is a Vertex model id
    /// (`claude-sonnet-4-5@20250929`). Project, region and Application
    /// Default Credentials come from the environment (see
    /// [`vertex::Vertex::from_env`]).
    pub fn vertex(model: &str) -> anyhow::Result<Self> {
        let client = http_client();
        Ok(Self {
            endpoint: Endpoint::Vertex(Box::new(vertex::Vertex::from_env(client.clone())?)),
            client,
            model: model.to_owned(),
        })
    }

    /// Sends one request and reads the reply, per endpoint.
    async fn send(&self, mut body: Value) -> anyhow::Result<LlmResponse> {
        let resp = match &self.endpoint {
            Endpoint::Direct { api_key, base_url } => {
                self.client
                    .post(format!("{}/v1/messages", base_url.trim_end_matches('/')))
                    .header("x-api-key", api_key)
                    .header("anthropic-version", "2023-06-01")
                    .header("content-type", "application/json")
                    .json(&body)
                    .send()
                    .await?
            }
            Endpoint::Vertex(vertex) => {
                strip_model(&mut body);
                body["anthropic_version"] = Value::from(vertex::ANTHROPIC_VERSION);
                let token = vertex.access_token().await?;
                self.client
                    .post(vertex.url(&self.model))
                    .bearer_auth(token)
                    .header("content-type", "application/json")
                    .json(&body)
                    .send()
                    .await?
            }
            Endpoint::Bedrock(bedrock) => {
                // InvokeModel answers with the whole message at once: no
                // `stream` key, and the AWS event-stream framing of the
                // streaming variant is not needed for a reply this loop
                // reads in full anyway.
                strip_model(&mut body);
                if let Some(obj) = body.as_object_mut() {
                    obj.remove("stream");
                }
                body["anthropic_version"] = Value::from(bedrock::ANTHROPIC_VERSION);
                let bytes = serde_json::to_vec(&body)?;
                let url = bedrock.url(&self.model);
                let mut request = self
                    .client
                    .post(&url)
                    .header("content-type", "application/json");
                for (name, value) in bedrock.auth_headers(&url, &bytes).await? {
                    request = request.header(name, value);
                }
                let resp = request.body(bytes).send().await?;
                let resp = check_status(resp, self.name()).await?;
                let message: Value = resp.json().await?;
                return Ok(parse_message(&message));
            }
        };

        let resp = check_status(resp, self.name()).await?;
        let mut sse = SseAccumulator::default();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            if sse.feed(&chunk?) {
                break;
            }
        }
        Ok(sse.finish())
    }

    fn messages_to_json(&self, messages: &[Message]) -> Value {
        let mut out = Vec::new();
        for msg in messages {
            let role_str = match msg.role {
                Role::User | Role::Tool | Role::System => "user",
                Role::Assistant => "assistant",
            };
            let content = match &msg.content {
                MessageContent::Text(t) => Value::String(t.clone()),
                MessageContent::Parts(parts) => {
                    let blocks: Vec<Value> = parts
                        .iter()
                        .map(|p| serde_json::to_value(p).unwrap_or(Value::Null))
                        .collect();
                    Value::Array(blocks)
                }
            };
            out.push(serde_json::json!({ "role": role_str, "content": content }));
        }
        Value::Array(out)
    }

    /// Pure request-body assembly, extracted from `complete()` for unit testing
    /// without a live HTTP call.
    ///
    /// COST-01/D-14a (Pitfall 5): `system` is sent as an array of content blocks
    /// (never a plain string) with `cache_control` on that block — Anthropic's
    /// prompt-caching mechanism keys on a specific *content block*, never a bare
    /// top-level request key (verified narrow scope, T-08-02-02: this marker is
    /// applied ONLY to `body["system"]`, the D-12/D-13 stable prefix — never to the
    /// turn-volatile `messages` array).
    ///
    /// D-12/D-14b: when `config.cache_stable_prefix_end` names a real split point,
    /// `system` becomes TWO blocks — the turn-invariant prefix (`cache_control`-tagged,
    /// the same content across turns for the same owner) and the turn-scoped remainder
    /// (untagged, sent fresh every call). Splitting matters because Anthropic charges the
    /// cache write/read against the tagged block's own content — folding a per-turn
    /// value (e.g. an `<active_object>` snapshot) into that same block would invalidate
    /// the cache on every turn instead of just the identity/system-preamble portion. See
    /// `system_content_blocks` below and `tests/prompt_cache_prefix.rs`.
    fn build_request_body(&self, messages_json: Value, config: &CallConfig) -> Value {
        let mut body = serde_json::json!({
            "model":      self.model,
            "max_tokens": config.max_tokens,
            "stream":     true,
            "messages":   messages_json,
        });

        if !config.system_prompt.is_empty() {
            body["system"] = Value::Array(system_content_blocks(
                &config.system_prompt,
                config.cache_stable_prefix_end,
            ));
        }

        if !config.tools.is_empty() {
            body["tools"] = Value::Array(config.tools.clone());
        }

        // T-08-02-03: this is pure request-shaping — AnthropicProvider::complete()
        // never calls registry.invoke() itself. Dispatch of the resulting tool_calls
        // flows through complete_structured_via_forced_tool_call (Plan 08-03/08-07),
        // never inline here.
        match &config.tool_choice {
            Some(ToolChoice::Forced(name)) => {
                body["tool_choice"] = serde_json::json!({"type": "tool", "name": name});
            }
            Some(ToolChoice::Required) => {
                body["tool_choice"] = serde_json::json!({"type": "any"});
            }
            Some(ToolChoice::Auto) | None => {
                // Anthropic's own default — leave the key unset.
            }
        }

        body
    }
}

/// D-12/D-14b: builds the `system` array. With no usable split point, this is the
/// original single-block shape (one `cache_control`-tagged block) — every caller that
/// predates `cache_stable_prefix_end` gets byte-identical behavior. With a real split
/// point, the prefix (`text[..end]`) keeps the `cache_control` tag and the remainder
/// (`text[end..]`) is a second, untagged block — Anthropic reads/writes the cache
/// against the tagged block's own content, so folding turn-varying text into it would
/// invalidate the cache on every turn instead of just that trailing portion.
///
/// `end` is defensively re-validated here (`is_char_boundary`, `<= text.len()`) rather
/// than trusted blindly — `CallConfig::cache_stable_prefix_end` crosses a crate
/// boundary (kernel → provider) and a provider must fail SAFE (fall back to the
/// single-block shape) on an unusable value, never panic on a slice index.
fn system_content_blocks(text: &str, stable_prefix_end: Option<usize>) -> Vec<Value> {
    let usable_end =
        stable_prefix_end.filter(|&end| end > 0 && end < text.len() && text.is_char_boundary(end));

    match usable_end {
        None => vec![serde_json::json!({
            "type": "text",
            "text": text,
            "cache_control": {"type": "ephemeral"},
        })],
        Some(end) => vec![
            serde_json::json!({
                "type": "text",
                "text": &text[..end],
                "cache_control": {"type": "ephemeral"},
            }),
            serde_json::json!({
                "type": "text",
                "text": &text[end..],
            }),
        ],
    }
}

#[async_trait::async_trait]
impl Provider for AnthropicProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let messages_json = self.messages_to_json(messages);
        let body = self.build_request_body(messages_json, config);
        self.send(body).await
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        use crate::types::MessageContent;
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Text(prompt.to_owned()),
        }];
        let config = CallConfig {
            max_tokens: 2048,
            ..Default::default()
        };
        let resp = self.complete(&messages, &config).await?;
        Ok(resp.text)
    }

    fn context_limit(&self) -> usize {
        200_000
    }
    fn model_name(&self) -> &str {
        &self.model
    }
    fn name(&self) -> &'static str {
        match self.endpoint {
            Endpoint::Direct { .. } => "anthropic",
            Endpoint::Bedrock(_) => "bedrock",
            Endpoint::Vertex(_) => "vertex",
        }
    }

    /// D-09: Anthropic has no native `response_format`/json_schema mode. Structured
    /// output for Anthropic routes through `complete_structured_via_forced_tool_call`
    /// (Plan 08-03), consumed by Plan 08-07's callers.
    fn supports_json_schema(&self) -> bool {
        false
    }
}

/// Bedrock and Vertex take the model in the URL and reject it in the body.
fn strip_model(body: &mut Value) {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("model");
    }
}

/// Turns a non-2xx reply into an error carrying the status and the start of
/// the body (which never contains our credentials).
async fn check_status(
    resp: reqwest::Response,
    provider: &str,
) -> anyhow::Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    let cut = body_text
        .char_indices()
        .nth(500)
        .map(|(i, _)| i)
        .unwrap_or(body_text.len());
    anyhow::bail!("{provider} HTTP {status}: {}", &body_text[..cut])
}

/// A complete (non-streamed) Messages API reply — what Bedrock's
/// `InvokeModel` returns.
fn parse_message(message: &Value) -> LlmResponse {
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for block in message["content"].as_array().into_iter().flatten() {
        match block["type"].as_str() {
            Some("text") => text.push_str(block["text"].as_str().unwrap_or_default()),
            Some("tool_use") => tool_calls.push(ToolCall {
                id: block["id"].as_str().unwrap_or_default().to_owned(),
                name: block["name"].as_str().unwrap_or_default().to_owned(),
                arguments: block
                    .get("input")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Default::default())),
                extra: None,
            }),
            _ => {}
        }
    }
    let mut usage = TokenUsage {
        convention: crate::types::UsageConvention::Disjoint,
        response_model: message["model"].as_str().map(str::to_owned),
        ..Default::default()
    };
    let u = &message["usage"];
    usage.input_tokens = u["input_tokens"].as_u64().unwrap_or(0) as u32;
    usage.output_tokens = u["output_tokens"].as_u64().unwrap_or(0) as u32;
    usage.cache_read = u["cache_read_input_tokens"].as_u64().unwrap_or(0) as u32;
    usage.cache_write = u["cache_creation_input_tokens"].as_u64().unwrap_or(0) as u32;
    LlmResponse {
        text: strip_think(&text),
        tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
        usage,
    }
}

/// Incremental reader of the Messages API server-sent events (the direct API
/// and Vertex's `streamRawPredict`).
///
/// Network chunks do not respect line boundaries: an event, or a multi-byte
/// character inside it, can be split across two chunks. Bytes are buffered
/// until a full line is available, so no event is dropped for arriving in
/// pieces — a dropped `input_json_delta` would silently corrupt a tool call.
#[derive(Default)]
struct SseAccumulator {
    pending: Vec<u8>,
    text: String,
    tool_calls: Vec<ToolCall>,
    usage: TokenUsage,
    tool: Option<(String, String, String)>,
    done: bool,
}

impl SseAccumulator {
    /// Consumes a chunk; true once the message has ended.
    fn feed(&mut self, chunk: &[u8]) -> bool {
        self.pending.extend_from_slice(chunk);
        while let Some(newline) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=newline).collect();
            let line = String::from_utf8_lossy(&line);
            self.line(line.trim_end_matches(['\r', '\n']));
            if self.done {
                return true;
            }
        }
        false
    }

    fn line(&mut self, line: &str) {
        let Some(data) = line.strip_prefix("data:").map(str::trim_start) else {
            return;
        };
        if data == "[DONE]" {
            self.done = true;
            return;
        }
        let event: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "SSE parse error — skipping line");
                return;
            }
        };
        match event["type"].as_str().unwrap_or("") {
            "content_block_start" if event["content_block"]["type"] == "tool_use" => {
                self.tool = Some((
                    event["content_block"]["id"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    event["content_block"]["name"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    String::new(),
                ));
            }
            "content_block_delta" => match event["delta"]["type"].as_str().unwrap_or("") {
                "text_delta" => {
                    if let Some(t) = event["delta"]["text"].as_str() {
                        self.text.push_str(t);
                    }
                }
                "input_json_delta" => {
                    if let (Some((_, _, input)), Some(partial)) =
                        (self.tool.as_mut(), event["delta"]["partial_json"].as_str())
                    {
                        input.push_str(partial);
                    }
                }
                _ => {}
            },
            "content_block_stop" => {
                if let Some((id, name, input)) = self.tool.take() {
                    let arguments = serde_json::from_str(&input)
                        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
                    self.tool_calls.push(ToolCall {
                        id,
                        name,
                        arguments,
                        extra: None,
                    });
                }
            }
            "message_delta" => {
                if let Some(out) = event["usage"]["output_tokens"].as_u64() {
                    self.usage.output_tokens = out as u32;
                }
            }
            "message_start" => apply_message_start_usage(&mut self.usage, &event),
            "message_stop" => self.done = true,
            "error" => {
                tracing::warn!(error = %event["error"], "anthropic stream error event");
            }
            _ => {}
        }
    }

    fn finish(self) -> LlmResponse {
        LlmResponse {
            text: strip_think(&self.text),
            tool_calls: (!self.tool_calls.is_empty()).then_some(self.tool_calls),
            usage: self.usage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> AnthropicProvider {
        // Bypass `new()`'s ANTHROPIC_API_KEY env lookup — unit tests exercise pure
        // request-shaping logic only, never a live HTTP call.
        AnthropicProvider::with_api_key("claude-test", "test-key")
    }

    #[test]
    fn build_request_body_sends_system_as_cache_control_tagged_array() {
        let provider = test_provider();
        let config = CallConfig {
            system_prompt: "you are a helpful assistant".into(),
            ..Default::default()
        };
        let body = provider.build_request_body(Value::Array(vec![]), &config);

        assert_eq!(
            body["system"],
            serde_json::json!([{
                "type": "text",
                "text": "you are a helpful assistant",
                "cache_control": {"type": "ephemeral"},
            }])
        );
    }

    #[test]
    fn build_request_body_splits_system_at_the_stable_prefix_boundary() {
        let provider = test_provider();
        let config = CallConfig {
            system_prompt: "STABLEVOLATILE".into(),
            cache_stable_prefix_end: Some(6), // "STABLE" is 6 bytes
            ..Default::default()
        };
        let body = provider.build_request_body(Value::Array(vec![]), &config);

        assert_eq!(
            body["system"],
            serde_json::json!([
                {
                    "type": "text",
                    "text": "STABLE",
                    "cache_control": {"type": "ephemeral"},
                },
                {
                    "type": "text",
                    "text": "VOLATILE",
                },
            ])
        );
    }

    #[test]
    fn build_request_body_ignores_a_boundary_at_or_past_the_end() {
        let provider = test_provider();
        for end in [0usize, 6, 100] {
            let config = CallConfig {
                system_prompt: "STABLE".into(),
                cache_stable_prefix_end: Some(end),
                ..Default::default()
            };
            let body = provider.build_request_body(Value::Array(vec![]), &config);
            assert_eq!(
                body["system"],
                serde_json::json!([{
                    "type": "text",
                    "text": "STABLE",
                    "cache_control": {"type": "ephemeral"},
                }]),
                "end={end} should fall back to the single-block shape"
            );
        }
    }

    #[test]
    fn build_request_body_ignores_a_boundary_not_on_a_char_boundary() {
        let provider = test_provider();
        // "é" is a 2-byte UTF-8 sequence starting at byte 0 — offset 1 lands mid-char.
        let config = CallConfig {
            system_prompt: "école".into(),
            cache_stable_prefix_end: Some(1),
            ..Default::default()
        };
        let body = provider.build_request_body(Value::Array(vec![]), &config);
        assert_eq!(
            body["system"],
            serde_json::json!([{
                "type": "text",
                "text": "école",
                "cache_control": {"type": "ephemeral"},
            }]),
            "a mid-char boundary must fail safe to the single-block shape, never panic"
        );
    }

    #[test]
    fn build_request_body_omits_system_key_when_prompt_empty() {
        let provider = test_provider();
        let config = CallConfig::default();
        let body = provider.build_request_body(Value::Array(vec![]), &config);

        assert!(body.get("system").is_none());
    }

    #[test]
    fn build_request_body_forced_tool_choice_maps_to_anthropic_tool_shape() {
        let provider = test_provider();
        let config = CallConfig {
            tool_choice: Some(ToolChoice::Forced("x".into())),
            ..Default::default()
        };
        let body = provider.build_request_body(Value::Array(vec![]), &config);

        assert_eq!(
            body["tool_choice"],
            serde_json::json!({"type": "tool", "name": "x"})
        );
    }

    #[test]
    fn build_request_body_required_tool_choice_maps_to_any() {
        let provider = test_provider();
        let config = CallConfig {
            tool_choice: Some(ToolChoice::Required),
            ..Default::default()
        };
        let body = provider.build_request_body(Value::Array(vec![]), &config);

        assert_eq!(body["tool_choice"], serde_json::json!({"type": "any"}));
    }

    #[test]
    fn build_request_body_auto_tool_choice_leaves_key_unset() {
        let provider = test_provider();
        let config = CallConfig {
            tool_choice: Some(ToolChoice::Auto),
            ..Default::default()
        };
        let body = provider.build_request_body(Value::Array(vec![]), &config);

        assert!(body.get("tool_choice").is_none());
    }

    #[test]
    fn message_start_event_parses_cache_read_and_cache_write_tokens() {
        let event = serde_json::json!({
            "type": "message_start",
            "message": {
                "usage": {
                    "input_tokens": 100,
                    "cache_read_input_tokens": 40,
                    "cache_creation_input_tokens": 10,
                }
            }
        });

        let mut usage = TokenUsage::default();
        apply_message_start_usage(&mut usage, &event);

        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cache_read, 40);
        assert_eq!(usage.cache_write, 10);
    }

    #[test]
    fn message_start_event_without_cache_fields_leaves_them_zero() {
        let event = serde_json::json!({
            "type": "message_start",
            "message": { "usage": { "input_tokens": 50 } }
        });

        let mut usage = TokenUsage::default();
        apply_message_start_usage(&mut usage, &event);

        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.cache_read, 0);
        assert_eq!(usage.cache_write, 0);
    }

    #[test]
    fn anthropic_provider_declares_no_native_json_schema_support() {
        let provider = test_provider();
        assert!(!provider.supports_json_schema());
    }
}
