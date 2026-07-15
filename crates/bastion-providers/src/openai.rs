use async_openai::{
    config::OpenAIConfig,
    types::chat::{
        ChatCompletionMessageToolCalls, ChatCompletionNamedToolChoice,
        ChatCompletionToolChoiceOption, CompletionUsage, CreateChatCompletionRequest,
        CreateChatCompletionRequestArgs, FunctionName, ResponseFormat, ResponseFormatJsonSchema,
        ToolChoiceOptions,
    },
    Client,
};

use super::Provider;
use crate::types::{
    strip_think, CallConfig, LlmResponse, Message, MessageContent, Role, TokenUsage, ToolCall,
    ToolChoice,
};

pub(crate) struct OpenAIProvider {
    client: Client<OpenAIConfig>,
    model: String,
}

impl OpenAIProvider {
    pub fn new(model: &str) -> Self {
        // OPENAI_API_KEY is read automatically by OpenAIConfig::default().
        // Panic with a clear message if it's missing.
        if std::env::var("OPENAI_API_KEY").is_err() {
            panic!("OPENAI_API_KEY required");
        }
        Self {
            client: Client::new(),
            model: model.to_owned(),
        }
    }

    /// Build the outgoing chat-completion request, folding in
    /// `CallConfig.response_format`/`.tool_choice`/`.temperature` (D-01 unification;
    /// `complete_structured` was removed from the trait entirely by Plan 08-09).
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
                // OpenAI's own default — leave the key unset.
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

/// Map an `async-openai` usage block into Bastion's `TokenUsage`, wiring the
/// already-vendored `prompt_tokens_details.cached_tokens` into `cache_read`
/// (COST-01/D-14a — previously silently discarded via `..Default::default()`).
/// OpenAI has no cache-write concept, so `cache_write` stays 0.
fn map_usage(usage: Option<CompletionUsage>) -> TokenUsage {
    usage
        .map(|u| TokenUsage {
            input_tokens: u.prompt_tokens,
            output_tokens: u.completion_tokens,
            cache_read: u
                .prompt_tokens_details
                .as_ref()
                .and_then(|d| d.cached_tokens)
                .unwrap_or(0),
            cache_write: 0,
            ..Default::default()
        })
        .unwrap_or_default()
}

#[async_trait::async_trait]
impl Provider for OpenAIProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
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
            .ok_or_else(|| anyhow::anyhow!("OpenAI returned no choices"))?;

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

        let usage = map_usage(response.usage);

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
        "openai"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> OpenAIProvider {
        // Bypass `new()`'s OPENAI_API_KEY env lookup — unit tests exercise pure
        // request-shaping logic only, never a live HTTP call.
        OpenAIProvider {
            client: Client::new(),
            model: "gpt-test".into(),
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
        // f32 -> f64 round-trip via serde_json loses precision (0.3f32 as f64 !=
        // 0.3f64) — compare via the same f32 cast rather than raw JSON equality.
        assert_eq!(body["temperature"].as_f64().unwrap() as f32, 0.3_f32);

        let without_temp = CallConfig::default();
        let request = provider.build_request(&[], &without_temp).unwrap();
        let body = serde_json::to_value(&request).unwrap();
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn map_usage_wires_cached_tokens_into_cache_read() {
        let usage = CompletionUsage {
            prompt_tokens: 100,
            completion_tokens: 20,
            total_tokens: 120,
            prompt_tokens_details: Some(async_openai::types::chat::PromptTokensDetails {
                audio_tokens: None,
                cached_tokens: Some(7),
            }),
            completion_tokens_details: None,
        };

        let mapped = map_usage(Some(usage));

        assert_eq!(mapped.cache_read, 7);
        assert_eq!(mapped.input_tokens, 100);
        assert_eq!(mapped.output_tokens, 20);
    }
}
