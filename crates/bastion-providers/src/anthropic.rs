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
    api_key: String,
    model: String,
}

impl AnthropicProvider {
    pub fn new(model: &str) -> Self {
        let api_key = std::env::var("ANTHROPIC_API_KEY").expect("ANTHROPIC_API_KEY required");
        Self::with_api_key(model, api_key)
    }

    /// Build directly from an already-resolved credential, bypassing
    /// `std::env` entirely — the host-injected-secret path
    /// (`registry::resolve_provider_with_credential`). `new()` above is now
    /// just this plus its own env lookup, so the two constructors can never
    /// drift on client setup.
    pub fn with_api_key(model: &str, api_key: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("reqwest client");

        Self {
            client,
            api_key: api_key.into(),
            model: model.to_owned(),
        }
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

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "Anthropic HTTP {}: {}",
                status,
                &body_text[..body_text.len().min(500)]
            );
        }

        let mut text = String::new();
        let mut tool_calls: Vec<ToolCall> = Vec::new();
        let mut usage = TokenUsage::default();

        // SSE streaming state
        let mut current_tool_id = String::new();
        let mut current_tool_name = String::new();
        let mut current_tool_input = String::new();
        let mut in_tool_use = false;

        let mut stream = resp.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            let chunk_str = std::str::from_utf8(&bytes)
                .map_err(|e| anyhow::anyhow!("SSE UTF-8 error: {}", e))?;

            for line in chunk_str.lines() {
                let data = match line.strip_prefix("data: ") {
                    Some(d) => d,
                    None => continue,
                };

                if data == "[DONE]" {
                    break;
                }

                let event: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "SSE parse error — skipping line");
                        continue;
                    }
                };

                let event_type = event["type"].as_str().unwrap_or("");

                match event_type {
                    "content_block_start" => {
                        let block_type = event["content_block"]["type"].as_str().unwrap_or("");
                        if block_type == "tool_use" {
                            in_tool_use = true;
                            current_tool_id = event["content_block"]["id"]
                                .as_str()
                                .unwrap_or("")
                                .to_owned();
                            current_tool_name = event["content_block"]["name"]
                                .as_str()
                                .unwrap_or("")
                                .to_owned();
                            current_tool_input = String::new();
                        }
                    }

                    "content_block_delta" => {
                        let delta_type = event["delta"]["type"].as_str().unwrap_or("");
                        match delta_type {
                            "text_delta" => {
                                if let Some(t) = event["delta"]["text"].as_str() {
                                    print!("{}", t);
                                    text.push_str(t);
                                }
                            }
                            "input_json_delta" => {
                                if let Some(partial) = event["delta"]["partial_json"].as_str() {
                                    current_tool_input.push_str(partial);
                                }
                            }
                            _ => {}
                        }
                    }

                    "content_block_stop" => {
                        if in_tool_use {
                            let arguments: Value = serde_json::from_str(&current_tool_input)
                                .unwrap_or(Value::Object(serde_json::Map::new()));
                            tool_calls.push(ToolCall {
                                id: std::mem::take(&mut current_tool_id),
                                name: std::mem::take(&mut current_tool_name),
                                arguments,
                                extra: None,
                            });
                            current_tool_input = String::new();
                            in_tool_use = false;
                        }
                    }

                    "message_delta" => {
                        if let Some(u) = event["usage"].as_object() {
                            if let Some(out) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                                usage.output_tokens = out as u32;
                            }
                        }
                    }

                    "message_start" => apply_message_start_usage(&mut usage, &event),

                    "message_stop" => break,

                    _ => {}
                }
            }
        }

        println!();

        let text = strip_think(&text);

        Ok(LlmResponse {
            text,
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            },
            usage,
        })
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
        "anthropic"
    }

    /// D-09: Anthropic has no native `response_format`/json_schema mode. Structured
    /// output for Anthropic routes through `complete_structured_via_forced_tool_call`
    /// (Plan 08-03), consumed by Plan 08-07's callers.
    fn supports_json_schema(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> AnthropicProvider {
        // Bypass `new()`'s ANTHROPIC_API_KEY env lookup — unit tests exercise pure
        // request-shaping logic only, never a live HTTP call.
        AnthropicProvider {
            client: reqwest::Client::new(),
            api_key: "test-key".into(),
            model: "claude-test".into(),
        }
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
