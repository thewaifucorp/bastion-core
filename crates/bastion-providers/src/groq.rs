use async_openai::types::chat::{
    ChatCompletionNamedToolChoice, ChatCompletionToolChoiceOption, CreateChatCompletionRequestArgs,
    FunctionName, ResponseFormat, ResponseFormatJsonSchema, ToolChoiceOptions,
};

use super::Provider;
use crate::types::{
    strip_think, CallConfig, LlmResponse, Message, MessageContent, Role, TokenUsage, ToolCall,
    ToolChoice,
};

/// OpenAI-compatible provider pointed at Groq (https://api.groq.com/openai/v1).
/// Groq serves small, fast open models (Llama, Qwen, …) on their LPU stack.
/// Routed when the model name is prefixed `groq/` (e.g. `groq/llama-3.1-8b-instant`,
/// `groq/meta-llama/llama-4-scout-17b-16e-instruct`); the `groq/` prefix is stripped by
/// the registry before this provider is built, so `self.model` is the bare Groq id
/// (which may itself contain a `/`).
///
/// Requests are built with `async-openai`'s request types (they serialize to the OpenAI
/// wire format), but sent and parsed via raw `reqwest`: Groq returns non-OpenAI response
/// fields (e.g. `service_tier: "on_demand"`) that `async-openai`'s strict typed response
/// deserializer rejects. We parse only the fields we need and ignore the rest.
pub struct GroqProvider {
    http: reqwest::Client,
    api_key: String,
    base: String,
    model: String,
}

impl GroqProvider {
    pub fn new(model: &str) -> Self {
        // Groq requires an API key. Reject missing OR empty (avoids an opaque 401).
        let api_key = std::env::var("GROQ_API_KEY").unwrap_or_default();
        if api_key.trim().is_empty() {
            panic!("GROQ_API_KEY required (missing or empty) — get one at https://console.groq.com/keys");
        }
        let base = std::env::var("GROQ_BASE_URL")
            .unwrap_or_else(|_| "https://api.groq.com/openai/v1".to_owned());

        Self {
            http: reqwest::Client::new(),
            api_key,
            base,
            model: model.to_owned(),
        }
    }

    /// POST a chat-completion body and return the parsed JSON, surfacing Groq's error
    /// message on non-2xx. Deliberately lenient: unknown response fields are ignored.
    async fn post_chat(&self, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/chat/completions", self.base);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("groq request failed: {e}"))?;

        let status = resp.status();
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("groq response was not JSON: {e}"))?;

        if !status.is_success() {
            let msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("groq API error ({}): {msg}", status.as_u16());
        }
        Ok(json)
    }

    /// Build the outgoing chat-completion request body, folding in
    /// `CallConfig.response_format`/`.tool_choice`/`.temperature` (D-01 unification;
    /// `complete_structured` was removed from the trait entirely by Plan 08-09).
    /// Built via `async-openai`'s request types then escaped to raw JSON via
    /// `serde_json::to_value`, same idiom `post_chat` expects (see module docs:
    /// Groq's response fields don't fit the strict typed deserializer, but the
    /// *request* wire format is OpenAI-compatible).
    fn build_request(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<serde_json::Value> {
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
                // Groq's own default — leave the key unset.
            }
        }
        if let Some(schema) = &config.response_format {
            // strict:false — Groq's strict validator rejects schemars' representation
            // of `Option<enum>` (an `anyOf` whose branch is a `$ref`, e.g. the
            // router's `convene_reason`): "anyOf branches must be disambiguated".
            // Non-strict still schema-GUIDES generation while tolerating `$ref`
            // branches; the caller serde-parse-retries regardless.
            args.response_format(ResponseFormat::JsonSchema {
                json_schema: ResponseFormatJsonSchema {
                    name: "structured".into(),
                    description: None,
                    schema: Some(schema.clone()),
                    strict: Some(false),
                },
            });
        }
        if let Some(temperature) = config.temperature {
            args.temperature(temperature);
        }
        let request = args.build()?;
        Ok(serde_json::to_value(&request)?)
    }
}

/// Map Groq's raw JSON `usage` block into Bastion's `TokenUsage`, wiring
/// `prompt_tokens_details.cached_tokens` into `cache_read` (COST-01/D-14a).
///
/// Pitfall 6: `llama-4-scout` (Bastion's actual Groq model) is not yet part of
/// Groq's prompt-caching rollout as of this writing, so `cache_read == 0` in
/// practice is EXPECTED, not a bug — this wiring is forward-looking for models/
/// tiers where Groq does surface cached-token counts.
fn map_usage(json: &serde_json::Value) -> TokenUsage {
    TokenUsage {
        input_tokens: json["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        output_tokens: json["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
        cache_read: json["usage"]["prompt_tokens_details"]["cached_tokens"]
            .as_u64()
            .unwrap_or(0) as u32,
        cache_write: 0,
        ..Default::default()
    }
}

/// Extract the first choice's message content, stripping any `<think>` block.
fn first_content(json: &serde_json::Value) -> &str {
    json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
}

#[async_trait::async_trait]
impl Provider for GroqProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let body = self.build_request(messages, config)?;
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
        131_072
    }
    fn model_name(&self) -> &str {
        &self.model
    }
    fn name(&self) -> &'static str {
        "groq"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> GroqProvider {
        // Bypass `new()`'s GROQ_API_KEY env lookup — unit tests exercise pure
        // request-shaping logic only, never a live HTTP call.
        GroqProvider {
            http: reqwest::Client::new(),
            api_key: "test-key".into(),
            base: "https://api.groq.com/openai/v1".into(),
            model: "llama-test".into(),
        }
    }

    #[test]
    fn build_request_response_format_produces_lenient_json_schema() {
        let provider = test_provider();
        let schema = serde_json::json!({"type": "object", "properties": {}});
        let config = CallConfig {
            response_format: Some(schema.clone()),
            ..Default::default()
        };
        let body = provider.build_request(&[], &config).unwrap();

        assert_eq!(body["response_format"]["type"], "json_schema");
        assert_eq!(body["response_format"]["json_schema"]["strict"], false);
        assert_eq!(body["response_format"]["json_schema"]["schema"], schema);
    }

    #[test]
    fn build_request_forced_tool_choice_maps_to_openai_function_shape() {
        let provider = test_provider();
        let config = CallConfig {
            tool_choice: Some(ToolChoice::Forced("x".into())),
            ..Default::default()
        };
        let body = provider.build_request(&[], &config).unwrap();

        assert_eq!(
            body["tool_choice"],
            serde_json::json!({"type": "function", "function": {"name": "x"}})
        );
    }

    #[test]
    fn map_usage_wires_cached_tokens_into_cache_read() {
        let json = serde_json::json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "prompt_tokens_details": { "cached_tokens": 42 },
            }
        });

        let mapped = map_usage(&json);

        assert_eq!(mapped.cache_read, 42);
        assert_eq!(mapped.input_tokens, 100);
        assert_eq!(mapped.output_tokens, 20);
    }

    #[test]
    fn map_usage_defaults_cache_read_to_zero_when_absent() {
        let json = serde_json::json!({
            "usage": { "prompt_tokens": 10, "completion_tokens": 5 }
        });

        let mapped = map_usage(&json);

        assert_eq!(mapped.cache_read, 0);
    }
}
