use async_openai::types::chat::{
    ChatCompletionNamedToolChoice, ChatCompletionToolChoiceOption, CreateChatCompletionRequest,
    CreateChatCompletionRequestArgs, FunctionName, ResponseFormat, ResponseFormatJsonSchema,
    ToolChoiceOptions,
};

use super::Provider;
use crate::types::{
    strip_think, CallConfig, LlmResponse, Message, MessageContent, Role, TokenUsage, ToolCall,
    ToolChoice,
};

/// OpenAI-compatible provider pointed at OpenRouter (https://openrouter.ai).
/// Unlocks dozens of models — including free ones — without a local GPU.
/// Routed when the model name contains '/' (OpenRouter slugs, e.g.
/// `meta-llama/llama-3.3-70b-instruct:free`).
///
/// Requests are built with `async-openai`'s request types (they serialize to the OpenAI
/// wire format), but sent and parsed via raw `reqwest`, mirroring `groq.rs`: OpenRouter's
/// response carries a non-standard `usage.cost` field — the real, per-request dollar cost
/// (SEC-02) — that `async-openai`'s strict typed response deserializer has no slot for.
/// We parse only the fields we need and ignore the rest.
pub struct OpenRouterProvider {
    http: reqwest::Client,
    api_key: String,
    base: String,
    model: String,
}

impl OpenRouterProvider {
    pub fn new(model: &str) -> Self {
        // OpenRouter requires an API key. Reject missing OR empty (avoids opaque 401).
        let api_key = std::env::var("OPENROUTER_API_KEY").unwrap_or_default();
        if api_key.trim().is_empty() {
            panic!("OPENROUTER_API_KEY required (missing or empty) — get one at https://openrouter.ai/keys");
        }

        let base = std::env::var("OPENROUTER_BASE_URL")
            .unwrap_or_else(|_| "https://openrouter.ai/api/v1".to_owned());

        Self {
            http: reqwest::Client::new(),
            api_key,
            base,
            model: model.to_owned(),
        }
    }

    /// POST a chat-completion body and return the parsed JSON, surfacing OpenRouter's
    /// error message on non-2xx. Deliberately lenient: unknown response fields are
    /// ignored. Mirrors `groq.rs::post_chat`.
    async fn post_chat(&self, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/chat/completions", self.base);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("openrouter request failed: {e}"))?;

        let status = resp.status();
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("openrouter response was not JSON: {e}"))?;

        if !status.is_success() {
            let msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("openrouter API error ({}): {msg}", status.as_u16());
        }
        Ok(json)
    }

    /// Build the outgoing chat-completion request, folding in
    /// `CallConfig.response_format`/`.tool_choice`/`.temperature` (D-01 unification;
    /// `complete_structured` was removed from the trait entirely by Plan 08-09).
    /// Mirrors `openai.rs`. Escaped to raw JSON via `serde_json::to_value` in
    /// `complete()` — the *request* wire format is OpenAI-compatible even though the
    /// *response* is not (module docs).
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
        match &config.tool_choice {
            Some(ToolChoice::Forced(name)) => {
                args.tool_choice(ChatCompletionToolChoiceOption::Function(
                    ChatCompletionNamedToolChoice {
                        function: FunctionName { name: name.clone() },
                    },
                ));
            }
            Some(ToolChoice::Required) => {
                args.tool_choice(ChatCompletionToolChoiceOption::Mode(
                    ToolChoiceOptions::Required,
                ));
            }
            Some(ToolChoice::Auto) | None => {
                // OpenRouter's own default — leave the key unset.
            }
        }
        if let Some(schema) = &config.response_format {
            args.response_format(ResponseFormat::JsonSchema {
                json_schema: ResponseFormatJsonSchema {
                    name: "structured".into(),
                    description: None,
                    schema: Some(schema.clone()),
                    strict: Some(true),
                },
            });
        }
        if let Some(temperature) = config.temperature {
            args.temperature(temperature);
        }
        Ok(args.build()?)
    }
}

/// Map OpenRouter's raw JSON `usage` block into Bastion's `TokenUsage`, wiring
/// `prompt_tokens_details.cached_tokens` into `cache_read` (COST-01/D-14a, unchanged)
/// AND the real per-request dollar cost (`usage.cost`, OpenRouter-specific) into
/// `actual_cost_usd` (SEC-02) — `estimate_cost_usd` (`src/agent/loop_.rs`) prefers
/// this real figure over its hardcoded per-provider table whenever it's present.
fn map_usage(json: &serde_json::Value) -> TokenUsage {
    TokenUsage {
        input_tokens: json["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        output_tokens: json["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
        cache_read: json["usage"]["prompt_tokens_details"]["cached_tokens"]
            .as_u64()
            .unwrap_or(0) as u32,
        cache_write: 0,
        actual_cost_usd: json["usage"]["cost"].as_f64(),
    }
}

/// Extract the first choice's message content, stripping any `<think>` block.
/// Mirrors `groq.rs::first_content`.
fn first_content(json: &serde_json::Value) -> &str {
    json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
}

#[async_trait::async_trait]
impl Provider for OpenRouterProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let request = self.build_request(messages, config)?;
        let body = serde_json::to_value(&request)?;
        let json = self.post_chat(&body).await?;

        let text = strip_think(first_content(&json));

        let tool_calls: Vec<ToolCall> = json["choices"][0]["message"]["tool_calls"]
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
                        Some(ToolCall {
                            id,
                            name,
                            arguments,
                            extra: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let usage = map_usage(&json);

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
        128_000
    }
    fn model_name(&self) -> &str {
        &self.model
    }
    fn name(&self) -> &'static str {
        "openrouter"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> OpenRouterProvider {
        // Bypass `new()`'s OPENROUTER_API_KEY env lookup — unit tests exercise
        // pure request-shaping logic only, never a live HTTP call.
        OpenRouterProvider {
            http: reqwest::Client::new(),
            api_key: "test-key".into(),
            base: "https://openrouter.ai/api/v1".into(),
            model: "or-test".into(),
        }
    }

    #[test]
    fn build_request_response_format_produces_strict_json_schema() {
        let provider = test_provider();
        let schema = serde_json::json!({"type": "object", "properties": {}});
        let config = CallConfig {
            response_format: Some(schema.clone()),
            ..Default::default()
        };
        let request = provider.build_request(&[], &config).unwrap();
        let body = serde_json::to_value(&request).unwrap();

        assert_eq!(body["response_format"]["type"], "json_schema");
        assert_eq!(body["response_format"]["json_schema"]["strict"], true);
        assert_eq!(body["response_format"]["json_schema"]["schema"], schema);
    }

    #[test]
    fn build_request_forced_tool_choice_maps_to_openai_function_shape() {
        let provider = test_provider();
        let config = CallConfig {
            tool_choice: Some(ToolChoice::Forced("x".into())),
            ..Default::default()
        };
        let request = provider.build_request(&[], &config).unwrap();
        let body = serde_json::to_value(&request).unwrap();

        assert_eq!(
            body["tool_choice"],
            serde_json::json!({"type": "function", "function": {"name": "x"}})
        );
    }

    #[test]
    fn build_request_temperature_set_when_some_and_omitted_when_none() {
        let provider = test_provider();

        let with_temp = CallConfig {
            temperature: Some(0.3),
            ..Default::default()
        };
        let request = provider.build_request(&[], &with_temp).unwrap();
        let body = serde_json::to_value(&request).unwrap();
        // f32 -> f64 round-trip via serde_json loses precision — compare via the
        // same f32 cast rather than raw JSON equality.
        assert_eq!(body["temperature"].as_f64().unwrap() as f32, 0.3_f32);

        let without_temp = CallConfig::default();
        let request = provider.build_request(&[], &without_temp).unwrap();
        let body = serde_json::to_value(&request).unwrap();
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn map_usage_wires_cached_tokens_into_cache_read() {
        let json = serde_json::json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "prompt_tokens_details": { "cached_tokens": 7 },
            }
        });

        let mapped = map_usage(&json);

        assert_eq!(mapped.cache_read, 7);
        assert_eq!(mapped.input_tokens, 100);
        assert_eq!(mapped.output_tokens, 20);
    }

    #[test]
    fn map_usage_wires_real_cost_into_actual_cost_usd() {
        let json = serde_json::json!({
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "cost": 0.00042,
            }
        });

        let mapped = map_usage(&json);

        assert_eq!(mapped.actual_cost_usd, Some(0.00042));
    }

    #[test]
    fn map_usage_defaults_actual_cost_usd_to_none_when_absent() {
        let json = serde_json::json!({
            "usage": { "prompt_tokens": 10, "completion_tokens": 5 }
        });

        let mapped = map_usage(&json);

        assert_eq!(mapped.actual_cost_usd, None);
    }
}
