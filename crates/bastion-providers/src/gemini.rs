use async_openai::{
    config::OpenAIConfig,
    types::chat::{
        ChatCompletionMessageToolCalls, CreateChatCompletionRequest,
        CreateChatCompletionRequestArgs, ResponseFormat,
    },
    Client,
};

use super::Provider;
use crate::types::{
    strip_think, CallConfig, ContentPart, LlmResponse, Message, MessageContent, Role, TokenUsage,
    ToolCall,
};

/// OpenAI-compatible provider for Google Gemini via the official compatibility
/// endpoint (https://generativelanguage.googleapis.com/v1beta/openai).
/// Routed when the model name starts with `gemini` (e.g. `gemini-2.0-flash`).
pub(crate) struct GeminiProvider {
    client: Client<OpenAIConfig>,
    /// Raw client for the tool-use round-trip path (SO-05) — only exercised when
    /// tools are in play and no response_format is requested. See `complete_tool_use`.
    http: reqwest::Client,
    api_key: String,
    base: String,
    model: String,
}

impl GeminiProvider {
    pub fn new(model: &str) -> Self {
        // Gemini requires an API key. Reject missing OR empty (avoids opaque 401).
        let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
        if api_key.trim().is_empty() {
            panic!("GEMINI_API_KEY required (missing or empty) — get one at https://aistudio.google.com/apikey");
        }

        let base = std::env::var("GEMINI_BASE_URL").unwrap_or_else(|_| {
            "https://generativelanguage.googleapis.com/v1beta/openai".to_owned()
        });

        let config = OpenAIConfig::default()
            .with_api_base(base.clone())
            .with_api_key(api_key.clone());

        Self {
            client: Client::with_config(config),
            http: reqwest::Client::new(),
            api_key,
            base,
            model: model.to_owned(),
        }
    }

    /// Build the outgoing chat-completion request, folding in `CallConfig.response_format`
    /// / `.temperature` via `response_format=json_object` (D-01 unification;
    /// `complete_structured` was removed from the trait entirely by Plan 08-09).
    /// Extracted as a pure fn (same idiom as `openai.rs::build_request` /
    /// `groq.rs::build_request`) so it's unit-testable without a live HTTP call.
    fn build_request(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<CreateChatCompletionRequest> {
        let oai_messages = super::build_openai_messages(&config.system_prompt, messages);

        let mut args = CreateChatCompletionRequestArgs::default();
        args.model(&self.model)
            .max_completion_tokens(config.max_tokens)
            .messages(oai_messages);
        if !config.tools.is_empty() {
            args.tools(super::anthropic_tools_to_openai(&config.tools));
        }
        if let Some(schema) = &config.response_format {
            // Gemini's OpenAI-compat endpoint honors response_format=json_object (forces a
            // clean JSON object, no prose/fences). We do NOT use json_schema here: schemars
            // emits $ref/$defs for nested enums (RouterDecision modes, etc.) which Gemini's
            // strict json_schema parser rejects, silently breaking the router. json_object +
            // an explicit field list in the system prompt + the caller's parse-retry is the
            // reliable combination. The schema is still used by the caller to describe the
            // fields; it is not sent to Gemini.
            let _ = schema;
            args.response_format(ResponseFormat::JsonObject);
        }
        if let Some(temperature) = config.temperature {
            args.temperature(temperature);
        }
        Ok(args.build()?)
    }

    /// Tool-use round-trip via raw JSON (SO-05). `async-openai`'s typed
    /// `ChatCompletionMessageToolCalls` struct silently DROPS Gemini's non-standard
    /// `tool_calls[].extra_content.google.thought_signature` field on both parse and
    /// re-serialize (RESEARCH Pitfall 4, MEDIUM confidence — community-sourced, not
    /// official Google docs). Without echoing it back, a second sequential tool call
    /// in the same turn 400s on models that require the signature (`gemini-3-*`, per
    /// RESEARCH Assumption A3).
    ///
    /// Builds the same OpenAI-compat request body the typed path would (via
    /// `CreateChatCompletionRequestArgs`, escaped to raw JSON — same idiom as
    /// `groq.rs`'s `build_request`), then overwrites its `messages` array with
    /// `build_gemini_messages`'s raw serialization so any `ContentPart::ToolUse.extra`
    /// (captured from a prior turn by `parse_gemini_tool_calls`) is re-attached as
    /// `extra_content` before the request is sent — round-tripping the opaque blob as
    /// DATA, never interpreting it (T-08-06-01).
    ///
    /// Only entered from `complete()` when `!config.tools.is_empty() &&
    /// config.response_format.is_none()` — the plain-text and structured-output paths
    /// have no tool_calls in play, so `thought_signature` is moot there and they keep
    /// using the typed client (`build_request`/`complete()`'s default branch).
    async fn complete_tool_use(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let oai_messages = super::build_openai_messages(&config.system_prompt, messages);

        let mut args = CreateChatCompletionRequestArgs::default();
        args.model(&self.model)
            .max_completion_tokens(config.max_tokens)
            .tools(super::anthropic_tools_to_openai(&config.tools))
            .messages(oai_messages);
        if let Some(temperature) = config.temperature {
            args.temperature(temperature);
        }
        let request = args.build()?;
        let mut body = serde_json::to_value(&request)?;
        body["messages"] = build_gemini_messages(&config.system_prompt, messages);

        let url = format!("{}/chat/completions", self.base);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("gemini request failed: {e}"))?;

        let status = resp.status();
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("gemini response was not JSON: {e}"))?;

        if !status.is_success() {
            let msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("gemini API error ({}): {msg}", status.as_u16());
        }

        let raw_text = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default();
        let text = strip_think(raw_text);

        let tool_calls = parse_gemini_tool_calls(&json);

        let usage = TokenUsage {
            input_tokens: json["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
            output_tokens: json["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
            ..Default::default()
        };

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
}

/// Parse Gemini's raw JSON chat-completion response into `ToolCall`s, capturing
/// `extra_content` (the `thought_signature` wrapper, SO-05) alongside `id`/
/// `function.{name,arguments}` — the fields the typed `async-openai` deserializer
/// already extracts, plus the one it drops. Factored out as a pure fn so it's
/// fixture-testable without a live Gemini call.
fn parse_gemini_tool_calls(json: &serde_json::Value) -> Vec<ToolCall> {
    json["choices"][0]["message"]["tool_calls"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|tc| {
                    let id = tc["id"].as_str()?.to_owned();
                    let name = tc["function"]["name"].as_str()?.to_owned();
                    let arguments = tc["function"]["arguments"]
                        .as_str()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                    let extra = tc.get("extra_content").cloned();
                    Some(ToolCall {
                        id,
                        name,
                        arguments,
                        extra,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Raw-JSON message serialization for the tool-use round-trip (SO-05) — mirrors
/// `super::build_openai_messages`'s wire shape (system/user/assistant/tool roles),
/// but re-attaches `ContentPart::ToolUse.extra` (Gemini's
/// `extra_content.google.thought_signature`) as a sibling key inside the
/// corresponding `tool_calls[]` entry, which the typed async-openai serializer
/// silently drops (RESEARCH Pitfall 4). Only the assistant tool_calls path differs
/// from the shared helper; text/user/tool messages use the same shape.
fn build_gemini_messages(system: &str, messages: &[Message]) -> serde_json::Value {
    let mut out = Vec::new();

    if !system.is_empty() {
        out.push(serde_json::json!({ "role": "system", "content": system }));
    }

    for msg in messages {
        match msg.role {
            Role::System => {
                out.push(serde_json::json!({
                    "role": "system",
                    "content": super::content_text(&msg.content),
                }));
            }
            Role::User => {
                out.push(serde_json::json!({
                    "role": "user",
                    "content": super::content_text(&msg.content),
                }));
            }
            Role::Assistant => {
                let mut text = String::new();
                let mut tool_calls: Vec<serde_json::Value> = Vec::new();
                if let MessageContent::Parts(parts) = &msg.content {
                    for p in parts {
                        match p {
                            ContentPart::Text { text: t } => {
                                if !text.is_empty() {
                                    text.push('\n');
                                }
                                text.push_str(t);
                            }
                            ContentPart::ToolUse {
                                id,
                                name,
                                input,
                                extra,
                            } => {
                                let mut tc = serde_json::json!({
                                    "id": id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": input.to_string(),
                                    },
                                });
                                if let Some(v) = extra {
                                    tc["extra_content"] = v.clone();
                                }
                                tool_calls.push(tc);
                            }
                            ContentPart::ToolResult { .. } => {}
                        }
                    }
                } else {
                    text = super::content_text(&msg.content);
                }
                let mut entry = serde_json::json!({ "role": "assistant" });
                if !text.is_empty() || tool_calls.is_empty() {
                    entry["content"] = serde_json::Value::String(text);
                }
                if !tool_calls.is_empty() {
                    entry["tool_calls"] = serde_json::Value::Array(tool_calls);
                }
                out.push(entry);
            }
            Role::Tool => {
                if let MessageContent::Parts(parts) = &msg.content {
                    for p in parts {
                        if let ContentPart::ToolResult {
                            tool_use_id,
                            content,
                        } = p
                        {
                            out.push(serde_json::json!({
                                "role": "tool",
                                "tool_call_id": tool_use_id,
                                "content": content,
                            }));
                        }
                    }
                } else {
                    out.push(serde_json::json!({
                        "role": "user",
                        "content": super::content_text(&msg.content),
                    }));
                }
            }
        }
    }

    serde_json::Value::Array(out)
}

#[async_trait::async_trait]
impl Provider for GeminiProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        // SO-05: route tool-use calls through the raw-JSON path so thought_signature
        // round-trips (see `complete_tool_use`'s doc comment). Structured-output
        // requests (response_format set) have no tool_calls in play, so they keep
        // using the typed client below even in the rare case tools are also attached.
        if !config.tools.is_empty() && config.response_format.is_none() {
            return self.complete_tool_use(messages, config).await;
        }

        let request = self.build_request(messages, config)?;

        let response = self
            .client
            .chat()
            .create(request)
            .await
            .map_err(|e| super::clarify_openai_error(self.name(), e))?;

        let choice = response
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Gemini returned no choices"))?;

        let raw_text = choice.message.content.unwrap_or_default();
        let text = strip_think(&raw_text);

        let tool_calls: Vec<ToolCall> = choice
            .message
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .filter_map(|tc| match tc {
                ChatCompletionMessageToolCalls::Function(f) => Some(ToolCall {
                    id: f.id,
                    name: f.function.name,
                    arguments: serde_json::from_str(&f.function.arguments)
                        .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
                    extra: None,
                }),
                _ => None,
            })
            .collect();

        let usage = response
            .usage
            .map(|u| TokenUsage {
                input_tokens: u.prompt_tokens,
                output_tokens: u.completion_tokens,
                ..Default::default()
            })
            .unwrap_or_default();

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

    /// D-09: Gemini's strict json_schema parser rejects `$ref`/`$defs` emitted by
    /// schemars for nested enums (e.g. RouterDecision modes) — callers must not
    /// assume `CallConfig.response_format` is honored natively and should route
    /// structured output through the forced-tool-call helper (Plan 08-03) instead.
    /// `complete()` still honors `response_format=json_object` directly (folded in
    /// by Plan 08-06) for callers that only need "clean JSON, no schema".
    fn supports_json_schema(&self) -> bool {
        false
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
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
        1_000_000
    }
    fn model_name(&self) -> &str {
        &self.model
    }
    fn name(&self) -> &'static str {
        "gemini"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> GeminiProvider {
        // Bypass `new()`'s GEMINI_API_KEY env lookup — unit tests exercise pure
        // request-shaping logic only, never a live HTTP call.
        GeminiProvider {
            client: Client::new(),
            http: reqwest::Client::new(),
            api_key: "test-key".into(),
            base: "https://generativelanguage.googleapis.com/v1beta/openai".into(),
            model: "gemini-test".into(),
        }
    }

    #[test]
    fn build_request_response_format_uses_json_object_never_json_schema() {
        let provider = test_provider();
        let schema = serde_json::json!({"type": "object", "properties": {}});
        let config = CallConfig {
            response_format: Some(schema),
            ..Default::default()
        };
        let request = provider.build_request(&[], &config).unwrap();
        let body = serde_json::to_value(&request).unwrap();

        assert_eq!(body["response_format"]["type"], "json_object");
        assert!(body["response_format"].get("json_schema").is_none());
    }

    #[test]
    fn build_request_no_response_format_omits_the_field() {
        let provider = test_provider();
        let config = CallConfig::default();
        let request = provider.build_request(&[], &config).unwrap();
        let body = serde_json::to_value(&request).unwrap();

        assert!(body.get("response_format").is_none());
    }

    // -----------------------------------------------------------------
    // SO-05: thought_signature capture + replay (Task 2)
    // -----------------------------------------------------------------

    #[test]
    fn thought_signature_captured_from_raw_json_response() {
        let json = serde_json::json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"path\":\"/tmp/x\"}",
                        },
                        "extra_content": { "google": { "thought_signature": "sig123" } },
                    }],
                },
            }],
        });

        let calls = parse_gemini_tool_calls(&json);

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].arguments, serde_json::json!({"path": "/tmp/x"}));
        assert_eq!(
            calls[0].extra,
            Some(serde_json::json!({"google": {"thought_signature": "sig123"}}))
        );
    }

    #[test]
    fn thought_signature_absent_leaves_extra_none() {
        let json = serde_json::json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "read_file", "arguments": "{}" },
                    }],
                },
            }],
        });

        let calls = parse_gemini_tool_calls(&json);

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].extra, None);
    }

    #[test]
    fn build_gemini_messages_reattaches_thought_signature_on_replay() {
        let messages = vec![Message {
            role: Role::Assistant,
            content: MessageContent::Parts(vec![ContentPart::ToolUse {
                id: "call_1".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path": "/tmp/x"}),
                extra: Some(serde_json::json!({"google": {"thought_signature": "sig"}})),
            }]),
        }];

        let out = build_gemini_messages("", &messages);
        let arr = out.as_array().unwrap();

        assert_eq!(arr.len(), 1);
        let tool_call = &arr[0]["tool_calls"][0];
        assert_eq!(tool_call["id"], "call_1");
        assert_eq!(tool_call["function"]["name"], "read_file");
        assert_eq!(
            tool_call["extra_content"],
            serde_json::json!({"google": {"thought_signature": "sig"}})
        );
    }

    #[test]
    fn build_gemini_messages_omits_extra_content_when_none() {
        let messages = vec![Message {
            role: Role::Assistant,
            content: MessageContent::Parts(vec![ContentPart::ToolUse {
                id: "call_1".into(),
                name: "read_file".into(),
                input: serde_json::json!({}),
                extra: None,
            }]),
        }];

        let out = build_gemini_messages("", &messages);
        let arr = out.as_array().unwrap();

        assert!(arr[0]["tool_calls"][0].get("extra_content").is_none());
    }
}
