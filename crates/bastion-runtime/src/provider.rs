//! Kernel provider surface (M2 step 3b): the [`Provider`] trait, the
//! [`SharedProvider`] alias, the D-13 retry wrapper and the D-02
//! forced-tool-call structured-output helper — everything the kernel loop and
//! the extension crates consume. Moved VERBATIM from `src/provider/mod.rs`;
//! the concrete providers and their OpenAI-compat translation helpers stayed
//! there (they become `bastion-providers` in M2 step 4).

use crate::types::{CallConfig, LlmResponse, Message, TokenUsage, ToolChoice};
use futures_util::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// One incremental piece of a streamed completion (streaming/cancellation
/// task). Mirrors the shape a caller needs to reassemble a response
/// progressively: partial text, partial tool-call arguments (providers may
/// stream tool-call JSON in fragments the same way they stream text), and a
/// final usage report once the provider's own stream is otherwise done.
///
/// There is deliberately no `Done` variant — the stream's own end (the
/// `Stream` yielding `None`) is that signal. A separate `Done` chunk would
/// let a provider send it early and still look finished to a caller that
/// only checks for that variant, instead of the stream actually closing.
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// Incremental assistant text.
    TextDelta(String),
    /// Incremental tool-call arguments for the call at `index` — `id`/`name`
    /// are only present on the fragment that starts a given call.
    ToolCallDelta {
        index: usize,
        id: Option<String>,
        name: Option<String>,
        arguments_delta: String,
    },
    /// Final usage, once known. Not every provider can report usage
    /// mid-stream, so this may be the last item before the stream ends.
    Usage(TokenUsage),
}

/// A call was cancelled before or during its provider round-trip
/// (streaming/cancellation task). Distinguishable from a generic transport
/// error so callers — and the conformance suite — can tell "cancelled as
/// requested" apart from "failed on its own".
#[derive(Debug, thiserror::Error)]
#[error("provider call cancelled")]
pub struct ProviderCancelled;

/// The default, honest answer for a provider that has not implemented
/// streaming (streaming/cancellation task). Never fabricate streaming by
/// chunking a whole response after the fact — that would let a connector
/// declare `ModelCapability::Streaming` and pass conformance without any
/// real streaming behind it.
#[derive(Debug, thiserror::Error)]
#[error("provider does not support streaming")]
pub struct ProviderNotStreamable;

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse>;
    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String>;
    fn context_limit(&self) -> usize;
    fn model_name(&self) -> &str;
    /// "anthropic" | "openai" | "gemini" | "openrouter" | "ollama"
    fn name(&self) -> &'static str;

    /// D-09 static capability declaration: does this provider's `complete()` honor
    /// `CallConfig.response_format` via a native json_schema-equivalent mechanism
    /// (OpenAI/Groq/OpenRouter's `json_schema`, Ollama's native `format` field)?
    ///
    /// `true` (default) — callers may set `CallConfig.response_format` directly and
    /// trust the provider to enforce it natively.
    /// `false` — callers must route structured-output requests through
    /// `complete_structured_via_forced_tool_call` (Plan 08-03's forced-tool-call
    /// helper), or rely on the provider's own alternate native mechanism handled
    /// internally by its `complete()` impl (e.g. Gemini's `json_object`, the
    /// terminal_agent provider's prompt-injection — see Plan 08-06).
    ///
    /// Consulted by Plan 08-07's caller branching (router/synth/learn) and Plan
    /// 08-03's forced-tool-call helper.
    fn supports_json_schema(&self) -> bool {
        true
    }

    /// Stream a completion incrementally instead of waiting for the whole
    /// response (streaming/cancellation task). `cancel` lets a caller abort
    /// the underlying upstream connection mid-stream, not just stop reading
    /// from it locally.
    ///
    /// New trait method WITH a default so none of this crate's/`bastion-
    /// providers`'/every test mock's existing `impl Provider` need to
    /// change to keep compiling — only a provider that genuinely streams
    /// from its own upstream overrides this. The default is a typed error,
    /// never a fake single-chunk stream: a provider that has not overridden
    /// this has not earned `ModelCapability::Streaming`, and the
    /// conformance suite (`provider_conformance.rs`) now calls this for
    /// real instead of treating the capability as unverifiable.
    async fn stream(
        &self,
        _messages: &[Message],
        _config: &CallConfig,
        _cancel: CancellationToken,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = anyhow::Result<StreamChunk>> + Send>>> {
        Err(ProviderNotStreamable.into())
    }

    /// A cancellable variant of [`Provider::complete`] (streaming/
    /// cancellation task). `cancel` firing while the call is still in
    /// flight must abort the actual upstream connection — "aborted
    /// upstream, not merely dropped locally" is exactly what
    /// `ModelCapability::Cancellation` claims, and the conformance suite
    /// races cancellation against an in-flight call to catch a provider
    /// that only checks `cancel` up front and then ignores it.
    ///
    /// New trait method WITH a default, same reasoning as [`Provider::
    /// stream`]: the default can only refuse to START an already-cancelled
    /// call — it has no way to interrupt `complete()` once that call has
    /// begun, so it must never be treated as proof of real cancellation.
    /// Only a provider that overrides this to race its own upstream I/O
    /// against `cancel` earns `ModelCapability::Cancellation`.
    async fn complete_cancellable(
        &self,
        messages: &[Message],
        config: &CallConfig,
        cancel: CancellationToken,
    ) -> anyhow::Result<LlmResponse> {
        if cancel.is_cancelled() {
            return Err(ProviderCancelled.into());
        }
        self.complete(messages, config).await
    }
}

pub type SharedProvider = Arc<RwLock<Box<dyn Provider>>>;

/// Exponential backoff retry wrapper for provider calls (D-13: 3 attempts).
/// Does NOT retry on HTTP 400 (context length exceeded — AutoCompact must handle upstream).
pub async fn call_with_retry<F, Fut, T>(mut f: F, max_retries: u32) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut delay = tokio::time::Duration::from_millis(500);
    for attempt in 0..=max_retries {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < max_retries => {
                let msg = e.to_string();
                if msg.contains("HTTP 400") {
                    return Err(e);
                }
                tracing::warn!(attempt, delay_ms = delay.as_millis(), error = %e, "LLM call failed, retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Sentinel capability name used to force a single-tool round-trip for structured
/// output (Plan 08-03). Reserved — never a real MCP tool or user-facing capability.
const STRUCTURED_OUTPUT_TOOL: &str = "__structured_output";

/// D-02 forced-tool-call fallback for providers whose `supports_json_schema()`
/// returns `false` (see `Provider::supports_json_schema`).
///
/// Drives ONE forced-tool-call round-trip through the SAME
/// `CapabilityRegistry::invoke` single-policy-boundary every real tool call
/// already uses — never a parallel dispatch path. Concretely:
/// 1. Register an ephemeral, pure-echo `StructuredOutputCapability` under
///    `STRUCTURED_OUTPUT_TOOL`, scoped to this call via `TurnCapabilityScope`
///    (RAII — cleaned up on `Drop`, even on early `?` return).
/// 2. Call `provider.complete()` with `tool_choice: Forced(STRUCTURED_OUTPUT_TOOL)`
///    and a single tool definition built from `schema` (NOT `response_format` —
///    this helper relies exclusively on `tool_choice`).
/// 3. Extract the model's tool-call arguments and dispatch them through
///    `registry.invoke()` — even though `StructuredOutputCapability::invoke()`
///    is a no-op echo, this hop is mandatory: it is structurally impossible for
///    this helper to bypass the registry and return `tool_call.arguments`
///    directly, which is exactly the guarantee D-02 requires (T-08-03-01).
///
/// The returned JSON string is still a HINT, not schema-validated bytes — callers
/// (Plan 08-07) MUST serde-parse-and-retry, same contract the removed
/// `Provider::complete_structured` (Plan 08-09) used to document; this helper does
/// not weaken it (T-08-03-02).
pub async fn complete_structured_via_forced_tool_call(
    provider: &dyn Provider,
    registry: &mut crate::capability::CapabilityRegistry,
    ctx: &crate::capability::InvokeCtx,
    messages: &[Message],
    base_config: &CallConfig,
    schema: serde_json::Value,
) -> anyhow::Result<String> {
    let cap = Arc::new(
        crate::capability::structured_output::StructuredOutputCapability::new(
            STRUCTURED_OUTPUT_TOOL,
            schema.clone(),
        ),
    );
    // RAII — do not manually remove; the scope's `Drop` handles cleanup even on
    // early `?` return below. `_scope` holds the sole `&mut` for its whole
    // lifetime (required so Drop can always clean up), so `registry` is
    // reborrowed immutably through `Deref` below for the `invoke()` call —
    // this cannot register/remove anything, only read/invoke.
    let _scope = crate::capability::TurnCapabilityScope::new(registry, vec![cap]);
    let registry: &crate::capability::CapabilityRegistry = &_scope;

    let tool_def = serde_json::json!({
        "name": STRUCTURED_OUTPUT_TOOL,
        "description": "Emit the structured response matching the required JSON schema",
        "input_schema": schema,
    });

    let forced_config = CallConfig {
        system_prompt: base_config.system_prompt.clone(),
        max_tokens: base_config.max_tokens,
        tools: vec![tool_def],
        response_format: None,
        tool_choice: Some(ToolChoice::Forced(STRUCTURED_OUTPUT_TOOL.to_owned())),
        temperature: base_config.temperature,
    };

    let response = provider.complete(messages, &forced_config).await?;

    let tool_call = response
        .tool_calls
        .and_then(|tc| tc.into_iter().next())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{}: forced tool_choice returned no tool_calls",
                provider.name()
            )
        })?;

    // Mandatory single-policy-boundary hop (D-02) — never return
    // `tool_call.arguments` directly, even though this capability is a no-op.
    // Plan 11-07 (SEC-04): `.data` unwraps the raw echoed Value from the new
    // `TaggedValue` wrapper — this ephemeral, is_local()==true capability's
    // `trusted` classification is irrelevant here (non-LLM-facing structured
    // output plumbing, not a tool result shown to the model).
    let tagged = registry
        .invoke(STRUCTURED_OUTPUT_TOOL, tool_call.arguments, ctx)
        .await?;

    Ok(serde_json::to_string(&tagged.data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------
    // complete_structured_via_forced_tool_call
    // -----------------------------------------------------------------

    use crate::capability::{CapabilityRegistry, InvokeCtx};
    use crate::types::{TokenUsage, ToolCall};

    /// Scripted `Provider` mock: returns a forced tool_call when the request's
    /// `tool_choice` is `Forced`, or no tool_calls at all when scripted empty —
    /// mirrors `tests/evals/spy_provider.rs::MockProvider`'s scripting shape.
    struct ForcedToolMock {
        arguments: Option<serde_json::Value>,
    }

    #[async_trait::async_trait]
    impl Provider for ForcedToolMock {
        async fn complete(
            &self,
            _messages: &[Message],
            config: &CallConfig,
        ) -> anyhow::Result<LlmResponse> {
            let Some(ToolChoice::Forced(name)) = &config.tool_choice else {
                anyhow::bail!("ForcedToolMock expects a Forced tool_choice");
            };
            let tool_calls = self.arguments.clone().map(|arguments| {
                vec![ToolCall {
                    id: "1".into(),
                    name: name.clone(),
                    arguments,
                    extra: None,
                }]
            });
            Ok(LlmResponse {
                text: String::new(),
                tool_calls,
                usage: TokenUsage::default(),
            })
        }

        async fn complete_simple(&self, _prompt: &str) -> anyhow::Result<String> {
            unreachable!("not exercised by forced_tool_call tests")
        }

        fn context_limit(&self) -> usize {
            8192
        }

        fn model_name(&self) -> &str {
            "forced-tool-mock"
        }

        fn name(&self) -> &'static str {
            "mock"
        }
    }

    fn test_ctx() -> InvokeCtx {
        // LocalOnly (the strictest tier) — the ephemeral capability's
        // `is_local() == true` must still let this pass through egress.
        InvokeCtx {
            owner: "test-owner".into(),
            privacy_tier: Some(crate::memory::PrivacyTier::LocalOnly),
            allowed_tools: None,
        }
    }

    #[tokio::test]
    async fn forced_tool_call_dispatches_through_registry_invoke() {
        let provider = ForcedToolMock {
            arguments: Some(json!({"x": 1})),
        };
        let mut registry = CapabilityRegistry::new();
        let ctx = test_ctx();
        let messages = vec![];
        let config = CallConfig::default();

        let result = complete_structured_via_forced_tool_call(
            &provider,
            &mut registry,
            &ctx,
            &messages,
            &config,
            json!({"type": "object"}),
        )
        .await
        .unwrap();

        assert_eq!(result, r#"{"x":1}"#);
        // The ephemeral capability must be cleaned up (TurnCapabilityScope Drop).
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn forced_tool_call_errors_cleanly_when_no_tool_calls_returned() {
        let provider = ForcedToolMock { arguments: None };
        let mut registry = CapabilityRegistry::new();
        let ctx = test_ctx();
        let messages = vec![];
        let config = CallConfig::default();

        let result = complete_structured_via_forced_tool_call(
            &provider,
            &mut registry,
            &ctx,
            &messages,
            &config,
            json!({"type": "object"}),
        )
        .await;

        assert!(result.is_err());
        assert!(registry.is_empty());
    }
}
