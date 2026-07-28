//! Shared provider conformance suite (BPCONF-04).
//!
//! One suite, parameterized by a connector and the capabilities it declares,
//! so "does this connector actually work" is answered the same way for every
//! vendor instead of once per vendor by whoever wrote it.
//!
//! ## What a run means
//!
//! Every check maps to a DECLARED capability
//! ([`bastion_types::provider_catalog::ModelCapability`]) or to the baseline
//! every provider must satisfy. A capability the descriptor does not declare is
//! not exercised — declaring less is allowed; claiming more is what this catches.
//!
//! Three outcomes, and the third is the one that matters:
//!
//! - [`CheckOutcome::Passed`] — the declared behavior was observed.
//! - [`CheckOutcome::Failed`] — it was declared and did not happen.
//! - [`CheckOutcome::Unverifiable`] — it was declared and this suite has no way
//!   to observe it through the kernel's [`Provider`] surface.
//!
//! `Unverifiable` is deliberately NOT a pass. `Provider` exposes `complete`,
//! `complete_simple`, `context_limit`, `model_name`, `name` and
//! `supports_json_schema` — there is no streaming method and no cancellation
//! token, so a connector declaring `Streaming` or `Cancellation` is making a
//! claim nothing here can check. Reporting that as a pass would let the
//! promotion gate certify an unverified capability, which is precisely the
//! failure mode the gate exists for. [`ConformanceReport::promotion_ready`] is
//! therefore false while any check is `Unverifiable`.
//!
//! ## No live credentials required
//!
//! The suite drives a `&dyn Provider`, so it runs against a fake in CI and
//! against a real connector in an opt-in live run. Same checks, same report —
//! the difference is only which provider is passed in (BPCONF-05 keeps them
//! distinct: `conformance_passed` and `live_e2e_passed` are separate evidence).

use bastion_types::provider_catalog::{ModelCapability, ProviderModelDescriptor};
use serde::Serialize;
use serde_json::json;

use crate::provider::Provider;
use crate::types::{CallConfig, ToolChoice};

/// Result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    /// Declared and not observed. `detail` is the suite's own description, never
    /// a raw provider payload — a conformance report is shareable.
    Failed { detail: String },
    /// Declared, but the kernel's `Provider` surface cannot observe it. Blocks
    /// promotion rather than passing quietly.
    Unverifiable { reason: &'static str },
    /// Not declared, so not exercised.
    NotDeclared,
}

/// One named check and what it observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConformanceCheck {
    /// The capability under test, or `None` for a baseline check every provider
    /// must satisfy regardless of what it declares.
    pub capability: Option<ModelCapability>,
    pub name: &'static str,
    pub outcome: CheckOutcome,
}

impl ConformanceCheck {
    fn passed(name: &'static str, capability: Option<ModelCapability>) -> Self {
        Self {
            capability,
            name,
            outcome: CheckOutcome::Passed,
        }
    }

    fn failed(
        name: &'static str,
        capability: Option<ModelCapability>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            name,
            outcome: CheckOutcome::Failed {
                detail: detail.into(),
            },
        }
    }
}

/// Everything one run observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConformanceReport {
    pub provider_name: String,
    pub model_id: String,
    pub checks: Vec<ConformanceCheck>,
}

impl ConformanceReport {
    /// Checks that failed outright.
    pub fn failures(&self) -> Vec<&ConformanceCheck> {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, CheckOutcome::Failed { .. }))
            .collect()
    }

    /// Declared capabilities this suite could not observe. Not failures, but
    /// not evidence either.
    pub fn unverifiable(&self) -> Vec<&ConformanceCheck> {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, CheckOutcome::Unverifiable { .. }))
            .collect()
    }

    /// Whether this run may set `SupportEvidence::conformance_passed`.
    ///
    /// Requires no failures AND nothing unverifiable: a capability nobody could
    /// check is not a capability anybody verified.
    pub fn promotion_ready(&self) -> bool {
        self.failures().is_empty() && self.unverifiable().is_empty()
    }
}

/// A canary the suite plants in prompts to prove the provider actually received
/// what it was given, rather than replaying a fixture.
const ECHO_CANARY: &str = "bastion-conformance-echo-7f3a";

/// Run the suite against `provider` for the capabilities `descriptor` declares.
///
/// Never panics on a provider error: a failing provider produces a `Failed`
/// check, because the point is a report, not an abort.
pub async fn run_conformance(
    provider: &dyn Provider,
    descriptor: &ProviderModelDescriptor,
) -> ConformanceReport {
    let mut checks = Vec::new();

    // Baseline 1: the provider answers at all, and receives the prompt it was
    // given. A connector that ignores input can otherwise pass a shallower
    // "did it return text" check.
    match provider
        .complete_simple(&format!("Repeat exactly: {ECHO_CANARY}"))
        .await
    {
        Ok(text) if text.contains(ECHO_CANARY) => {
            checks.push(ConformanceCheck::passed("text_completion_echoes_prompt", None))
        }
        Ok(_) => checks.push(ConformanceCheck::failed(
            "text_completion_echoes_prompt",
            None,
            "the response did not contain the prompt's canary, so the prompt may \
             not be reaching the provider",
        )),
        Err(e) => checks.push(ConformanceCheck::failed(
            "text_completion_echoes_prompt",
            None,
            format!("complete_simple failed: {e}"),
        )),
    }

    // Baseline 2: identity matches the catalog. A mismatch means the catalog
    // and the connector disagree about which model is serving requests, which
    // silently invalidates every capability claim below.
    if provider.model_name() == descriptor.model_id {
        checks.push(ConformanceCheck::passed("model_name_matches_catalog", None));
    } else {
        checks.push(ConformanceCheck::failed(
            "model_name_matches_catalog",
            None,
            format!(
                "catalog says '{}', provider reports '{}'",
                descriptor.model_id,
                provider.model_name()
            ),
        ));
    }

    // Baseline 3: a usable context limit. Zero would make every compaction
    // decision downstream nonsense.
    if provider.context_limit() > 0 {
        checks.push(ConformanceCheck::passed("context_limit_is_positive", None));
    } else {
        checks.push(ConformanceCheck::failed(
            "context_limit_is_positive",
            None,
            "context_limit() returned 0",
        ));
    }

    checks.push(check_tools(provider, descriptor).await);
    checks.push(check_structured_output(provider, descriptor).await);
    checks.push(check_usage(provider, descriptor).await);
    checks.push(unverifiable_or_not_declared(
        descriptor,
        ModelCapability::Streaming,
        "streaming",
        "the kernel Provider trait exposes no streaming method, so a streaming \
         claim cannot be observed through it",
    ));
    checks.push(unverifiable_or_not_declared(
        descriptor,
        ModelCapability::Cancellation,
        "cancellation",
        "the kernel Provider trait exposes no cancellation token, so an \
         upstream-abort claim cannot be observed through it",
    ));

    ConformanceReport {
        provider_name: provider.name().to_string(),
        model_id: descriptor.model_id.clone(),
        checks,
    }
}

/// For capabilities the kernel surface cannot reach: `NotDeclared` when the
/// connector is honest about not having it, `Unverifiable` when it claims it.
fn unverifiable_or_not_declared(
    descriptor: &ProviderModelDescriptor,
    capability: ModelCapability,
    name: &'static str,
    reason: &'static str,
) -> ConformanceCheck {
    if descriptor.supports(capability) {
        ConformanceCheck {
            capability: Some(capability),
            name,
            outcome: CheckOutcome::Unverifiable { reason },
        }
    } else {
        ConformanceCheck {
            capability: Some(capability),
            name,
            outcome: CheckOutcome::NotDeclared,
        }
    }
}

async fn check_tools(
    provider: &dyn Provider,
    descriptor: &ProviderModelDescriptor,
) -> ConformanceCheck {
    let name = "tool_call_is_returned_when_forced";
    if !descriptor.supports(ModelCapability::Tools) {
        return ConformanceCheck {
            capability: Some(ModelCapability::Tools),
            name,
            outcome: CheckOutcome::NotDeclared,
        };
    }

    let tool = json!({
        "name": "conformance_probe",
        "description": "Records that a tool call round-tripped.",
        "input_schema": {
            "type": "object",
            "properties": { "ok": { "type": "boolean" } },
            "required": ["ok"]
        }
    });
    let config = CallConfig {
        tools: vec![tool],
        tool_choice: Some(ToolChoice::Forced("conformance_probe".to_string())),
        ..CallConfig::default()
    };

    match provider
        .complete(
            &[crate::types::Message {
                role: crate::types::Role::User,
                content: "Call conformance_probe with ok=true.".to_string(),
            }],
            &config,
        )
        .await
    {
        // The tool is never executed here: this asserts the provider ASKS for
        // it. Executing it would put the suite on the wrong side of the
        // capability boundary.
        Ok(response) => match response.tool_calls {
            Some(calls) if calls.iter().any(|c| c.name == "conformance_probe") => {
                ConformanceCheck::passed(name, Some(ModelCapability::Tools))
            }
            Some(_) => ConformanceCheck::failed(
                name,
                Some(ModelCapability::Tools),
                "a tool call was returned, but not the forced one",
            ),
            None => ConformanceCheck::failed(
                name,
                Some(ModelCapability::Tools),
                "tools are declared and a call was forced, but the response \
                 carried no tool call",
            ),
        },
        Err(e) => ConformanceCheck::failed(
            name,
            Some(ModelCapability::Tools),
            format!("the forced-tool call failed: {e}"),
        ),
    }
}

async fn check_structured_output(
    provider: &dyn Provider,
    descriptor: &ProviderModelDescriptor,
) -> ConformanceCheck {
    let name = "structured_output_returns_parseable_json";
    if !descriptor.supports(ModelCapability::StructuredOutput) {
        return ConformanceCheck {
            capability: Some(ModelCapability::StructuredOutput),
            name,
            outcome: CheckOutcome::NotDeclared,
        };
    }

    // A declared capability must match the provider's own static answer.
    // Disagreement here is a real defect: callers branch on
    // `supports_json_schema` to decide whether to use the forced-tool-call
    // fallback, so a catalog claiming native support for a provider that denies
    // it sends requests down a path the provider cannot honor.
    if !provider.supports_json_schema() {
        return ConformanceCheck::failed(
            name,
            Some(ModelCapability::StructuredOutput),
            "the catalog declares structured output, but the provider reports \
             supports_json_schema() == false",
        );
    }

    let schema = json!({
        "type": "object",
        "properties": { "answer": { "type": "string" } },
        "required": ["answer"],
        "additionalProperties": false
    });
    let config = CallConfig {
        response_format: Some(schema),
        ..CallConfig::default()
    };

    match provider
        .complete(
            &[crate::types::Message {
                role: crate::types::Role::User,
                content: "Answer with a JSON object holding a single \"answer\" field.".to_string(),
            }],
            &config,
        )
        .await
    {
        Ok(response) => match serde_json::from_str::<serde_json::Value>(response.text.trim()) {
            Ok(value) if value.get("answer").is_some() => {
                ConformanceCheck::passed(name, Some(ModelCapability::StructuredOutput))
            }
            Ok(_) => ConformanceCheck::failed(
                name,
                Some(ModelCapability::StructuredOutput),
                "the response parsed as JSON but did not match the requested schema",
            ),
            Err(_) => ConformanceCheck::failed(
                name,
                Some(ModelCapability::StructuredOutput),
                "the response was not parseable JSON despite a response_format request",
            ),
        },
        Err(e) => ConformanceCheck::failed(
            name,
            Some(ModelCapability::StructuredOutput),
            format!("the structured-output call failed: {e}"),
        ),
    }
}

async fn check_usage(
    provider: &dyn Provider,
    descriptor: &ProviderModelDescriptor,
) -> ConformanceCheck {
    let name = "usage_is_reported";
    if !descriptor.supports(ModelCapability::Usage) {
        return ConformanceCheck {
            capability: Some(ModelCapability::Usage),
            name,
            outcome: CheckOutcome::NotDeclared,
        };
    }

    match provider
        .complete(
            &[crate::types::Message {
                role: crate::types::Role::User,
                content: "Say hello.".to_string(),
            }],
            &CallConfig::default(),
        )
        .await
    {
        // All-zero usage is the tell for a connector that fills the struct to
        // satisfy the type instead of reading what the vendor reported. A real
        // call always consumes input tokens.
        Ok(response) => {
            let usage = response.usage;
            if usage.input_tokens == 0 && usage.output_tokens == 0 {
                ConformanceCheck::failed(
                    name,
                    Some(ModelCapability::Usage),
                    "usage is declared but the response reported zero input and \
                     output tokens, which no real call does",
                )
            } else {
                ConformanceCheck::passed(name, Some(ModelCapability::Usage))
            }
        }
        Err(e) => ConformanceCheck::failed(
            name,
            Some(ModelCapability::Usage),
            format!("the usage probe call failed: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LlmResponse, Message, TokenUsage, ToolCall};
    use bastion_types::provider_catalog::{
        ProviderAuthFlow, ProviderSupportDescriptor, SupportEvidence,
    };

    /// A provider whose behavior is dialed in per test — the point being that
    /// the suite needs no credentials to be meaningful.
    struct FakeProvider {
        echo: bool,
        model: &'static str,
        context: usize,
        json_schema: bool,
        tool_call: Option<&'static str>,
        json_text: Option<&'static str>,
        usage: TokenUsage,
        fail: bool,
    }

    impl Default for FakeProvider {
        fn default() -> Self {
            Self {
                echo: true,
                model: "fake-1",
                context: 8_192,
                json_schema: true,
                tool_call: Some("conformance_probe"),
                json_text: Some(r#"{"answer":"hi"}"#),
                usage: TokenUsage {
                    input_tokens: 10,
                    output_tokens: 4,
                    cache_read: 0,
                    cache_write: 0,
                    actual_cost_usd: None,
                },
                fail: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl Provider for FakeProvider {
        async fn complete(
            &self,
            _messages: &[Message],
            config: &CallConfig,
        ) -> anyhow::Result<LlmResponse> {
            if self.fail {
                anyhow::bail!("provider unavailable");
            }
            let structured = config.response_format.is_some();
            let wants_tool = config.tool_choice.is_some();
            Ok(LlmResponse {
                text: if structured {
                    self.json_text.unwrap_or("not json").to_string()
                } else {
                    "ok".to_string()
                },
                tool_calls: if wants_tool {
                    self.tool_call.map(|name| {
                        vec![ToolCall {
                            id: "call-1".to_string(),
                            name: name.to_string(),
                            arguments: json!({"ok": true}),
                            extra: None,
                        }]
                    })
                } else {
                    None
                },
                usage: self.usage.clone(),
            })
        }

        async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
            if self.fail {
                anyhow::bail!("provider unavailable");
            }
            Ok(if self.echo {
                prompt.to_string()
            } else {
                "I would rather not".to_string()
            })
        }

        fn context_limit(&self) -> usize {
            self.context
        }

        fn model_name(&self) -> &str {
            self.model
        }

        fn name(&self) -> &'static str {
            "fake"
        }

        fn supports_json_schema(&self) -> bool {
            self.json_schema
        }
    }

    fn descriptor(capabilities: &[ModelCapability]) -> ProviderModelDescriptor {
        ProviderModelDescriptor::new("fake-1", 0).with_capabilities(capabilities.iter().copied())
    }

    fn outcome<'a>(report: &'a ConformanceReport, name: &str) -> &'a CheckOutcome {
        &report
            .checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check named {name}"))
            .outcome
    }

    /// A connector that declares only what it does passes, and the report is
    /// promotion-ready.
    #[tokio::test]
    async fn an_honest_connector_passes_every_declared_check() {
        let provider = FakeProvider::default();
        let descriptor = descriptor(&[
            ModelCapability::Tools,
            ModelCapability::StructuredOutput,
            ModelCapability::Usage,
        ]);
        let report = run_conformance(&provider, &descriptor).await;
        assert!(report.failures().is_empty(), "{:?}", report.failures());
        assert!(report.unverifiable().is_empty());
        assert!(report.promotion_ready());
    }

    /// Declaring nothing is legal: nothing is exercised, and the baseline still
    /// has to hold.
    #[tokio::test]
    async fn declaring_nothing_exercises_nothing_but_still_checks_the_baseline() {
        let report = run_conformance(&FakeProvider::default(), &descriptor(&[])).await;
        assert!(report.promotion_ready());
        assert_eq!(outcome(&report, "tool_call_is_returned_when_forced"), &CheckOutcome::NotDeclared);
        assert_eq!(outcome(&report, "usage_is_reported"), &CheckOutcome::NotDeclared);
        assert_eq!(
            outcome(&report, "text_completion_echoes_prompt"),
            &CheckOutcome::Passed
        );
    }

    /// BPCONF-04: the suite catches the claim, not the absence. A connector
    /// declaring tools it does not return fails.
    #[tokio::test]
    async fn declaring_tools_without_returning_one_fails() {
        let provider = FakeProvider {
            tool_call: None,
            ..Default::default()
        };
        let report = run_conformance(&provider, &descriptor(&[ModelCapability::Tools])).await;
        assert!(!report.promotion_ready());
        match outcome(&report, "tool_call_is_returned_when_forced") {
            CheckOutcome::Failed { detail } => assert!(detail.contains("no tool call"), "{detail}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn returning_the_wrong_tool_fails() {
        let provider = FakeProvider {
            tool_call: Some("something_else"),
            ..Default::default()
        };
        let report = run_conformance(&provider, &descriptor(&[ModelCapability::Tools])).await;
        match outcome(&report, "tool_call_is_returned_when_forced") {
            CheckOutcome::Failed { detail } => assert!(detail.contains("not the forced one")),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// A catalog claiming native structured output while the provider itself
    /// denies it is a real defect: callers branch on `supports_json_schema` to
    /// decide whether to use the fallback path.
    #[tokio::test]
    async fn a_catalog_claim_contradicting_the_provider_fails() {
        let provider = FakeProvider {
            json_schema: false,
            ..Default::default()
        };
        let report =
            run_conformance(&provider, &descriptor(&[ModelCapability::StructuredOutput])).await;
        match outcome(&report, "structured_output_returns_parseable_json") {
            CheckOutcome::Failed { detail } => {
                assert!(detail.contains("supports_json_schema() == false"), "{detail}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unparseable_structured_output_fails() {
        let provider = FakeProvider {
            json_text: Some("here you go: {answer"),
            ..Default::default()
        };
        let report =
            run_conformance(&provider, &descriptor(&[ModelCapability::StructuredOutput])).await;
        match outcome(&report, "structured_output_returns_parseable_json") {
            CheckOutcome::Failed { detail } => assert!(detail.contains("not parseable JSON")),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// All-zero usage is the tell for a connector filling the struct to satisfy
    /// the type rather than reading what the vendor reported.
    #[tokio::test]
    async fn zeroed_usage_fails_when_usage_is_declared() {
        let provider = FakeProvider {
            usage: TokenUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_read: 0,
                cache_write: 0,
                actual_cost_usd: None,
            },
            ..Default::default()
        };
        let report = run_conformance(&provider, &descriptor(&[ModelCapability::Usage])).await;
        match outcome(&report, "usage_is_reported") {
            CheckOutcome::Failed { detail } => assert!(detail.contains("zero input and")),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// The prompt-echo baseline exists so a provider that ignores its input
    /// cannot pass on "it returned some text".
    #[tokio::test]
    async fn a_provider_that_ignores_the_prompt_fails_the_baseline() {
        let provider = FakeProvider {
            echo: false,
            ..Default::default()
        };
        let report = run_conformance(&provider, &descriptor(&[])).await;
        match outcome(&report, "text_completion_echoes_prompt") {
            CheckOutcome::Failed { detail } => assert!(detail.contains("canary")),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_model_name_disagreement_fails_and_names_both_sides() {
        let provider = FakeProvider {
            model: "actually-fake-2",
            ..Default::default()
        };
        let report = run_conformance(&provider, &descriptor(&[])).await;
        match outcome(&report, "model_name_matches_catalog") {
            CheckOutcome::Failed { detail } => {
                assert!(detail.contains("fake-1") && detail.contains("actually-fake-2"), "{detail}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_zero_context_limit_fails() {
        let provider = FakeProvider {
            context: 0,
            ..Default::default()
        };
        let report = run_conformance(&provider, &descriptor(&[])).await;
        assert!(matches!(
            outcome(&report, "context_limit_is_positive"),
            CheckOutcome::Failed { .. }
        ));
    }

    /// A dead provider produces failures, never a panic — the suite's job is a
    /// report.
    #[tokio::test]
    async fn a_failing_provider_produces_failures_not_a_panic() {
        let provider = FakeProvider {
            fail: true,
            ..Default::default()
        };
        let report = run_conformance(
            &provider,
            &descriptor(&[ModelCapability::Tools, ModelCapability::Usage]),
        )
        .await;
        assert!(report.failures().len() >= 3, "{:?}", report.failures());
        assert!(!report.promotion_ready());
    }

    /// The honest limit of this suite: `Streaming` and `Cancellation` have no
    /// observable surface on the kernel's `Provider`, so declaring them yields
    /// `Unverifiable` — which BLOCKS promotion instead of passing quietly.
    #[tokio::test]
    async fn declaring_streaming_or_cancellation_is_unverifiable_and_blocks_promotion() {
        let report = run_conformance(
            &FakeProvider::default(),
            &descriptor(&[ModelCapability::Streaming, ModelCapability::Cancellation]),
        )
        .await;
        assert!(report.failures().is_empty(), "these are not failures");
        assert_eq!(report.unverifiable().len(), 2);
        assert!(
            !report.promotion_ready(),
            "a capability nobody could check is not a capability anybody verified"
        );
        for check in report.unverifiable() {
            match &check.outcome {
                CheckOutcome::Unverifiable { reason } => {
                    assert!(reason.contains("Provider trait"), "{reason}")
                }
                other => panic!("expected unverifiable, got {other:?}"),
            }
        }
    }

    /// End to end with the promotion gate: a passing report is what lets a
    /// descriptor set `conformance_passed`, and it is still only one of five.
    #[tokio::test]
    async fn a_passing_report_feeds_the_promotion_gate_but_does_not_complete_it() {
        let report = run_conformance(&FakeProvider::default(), &descriptor(&[])).await;
        assert!(report.promotion_ready());

        let mut support =
            ProviderSupportDescriptor::experimental("fake", ProviderAuthFlow::DeviceCode);
        support.evidence = SupportEvidence {
            conformance_passed: report.promotion_ready(),
            ..SupportEvidence::default()
        };
        let missing = support.promote().unwrap_err();
        assert!(!missing.is_empty(), "conformance alone must not promote");
    }
}
