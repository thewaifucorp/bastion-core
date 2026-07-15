//! Minimal turn plumbing — same shape as `examples/embedded-host`'s, kept
//! standalone rather than shared so each example stays readable on its own.
//! The one thing this crate's `MockProvider` needs beyond that example's is
//! router-awareness: `bastion_personas::persona::PersonaResponder` (used
//! here for component 1 — see `main.rs`) issues its OWN provider call first,
//! to classify the turn (`CallConfig.response_format` set), before the
//! persona's own completion call (`response_format: None`). A single branch
//! on that field lets one `MockProvider` serve both calls without a live LLM.

use async_trait::async_trait;
use bastion_runtime::agent::ports::{FailureSink, ProviderResolver, ToolSource};
use bastion_runtime::memory::PrivacyTier;
use bastion_runtime::provider::Provider;
use bastion_runtime::types::{CallConfig, FailureKind, LlmResponse, Message, TokenUsage};

/// Offline stand-in for a real LLM. Branches on whether this call is the
/// persona ROUTER's structured-output classification request
/// (`response_format: Some(_)`) or the persona's own final-answer
/// completion (`response_format: None`) — the two calls
/// `bastion_personas::persona::{router, runner}` make against any
/// `Provider`, live or mocked.
pub struct MockProvider {
    /// The single owner-local persona this host always routes to (component
    /// 1 uses exactly one `AgentDefinition` — no live classification needed).
    persona_name: String,
}

impl MockProvider {
    pub fn new(persona_name: impl Into<String>) -> Self {
        Self {
            persona_name: persona_name.into(),
        }
    }
}

#[async_trait]
impl Provider for MockProvider {
    async fn complete(
        &self,
        _messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        if config.response_format.is_some() {
            // The persona router's classification call — always route
            // Single to this host's one owner-local persona.
            let decision = serde_json::json!({
                "personas": [self.persona_name],
                "mode": "single",
                "convene_reason": null,
            });
            return Ok(LlmResponse {
                text: decision.to_string(),
                tool_calls: None,
                usage: TokenUsage::default(),
            });
        }

        Ok(LlmResponse {
            text: format!("[{}] handled the turn", self.persona_name),
            tool_calls: None,
            usage: TokenUsage::default(),
        })
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        Ok(format!("[{}] (you said: {prompt})", self.persona_name))
    }

    fn context_limit(&self) -> usize {
        1_000_000
    }

    fn model_name(&self) -> &str {
        "mock-embedded-host-slice"
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

pub struct NoTools;

#[async_trait]
impl ToolSource for NoTools {
    async fn tool_defs(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        Ok(Vec::new())
    }

    async fn call_tool_with_timeout(
        &self,
        name: &str,
        _args: serde_json::Value,
        _owner: &str,
        _resolved_tier: Option<PrivacyTier>,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::bail!("embedded-host-slice registers no external MCP tools (requested: {name})")
    }
}

pub struct NoopFailureSink;

impl FailureSink for NoopFailureSink {
    fn record_failure(&self, _kind: FailureKind, _tier: Option<PrivacyTier>, _detail: &str) {}
}

pub struct UnusedResolver;

impl ProviderResolver for UnusedResolver {
    fn resolve(&self, model: &str) -> anyhow::Result<Box<dyn Provider>> {
        anyhow::bail!("embedded-host-slice never resolves a provider by name (requested: {model})")
    }
}
