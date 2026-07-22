// Router — classifies an inbound message into a typed RouterDecision.
// DECIDES only; does not execute personas.
// 3-attempt serde-parse-retry on the unified complete() structured output (AI-SPEC §4b),
// with a D-09 runtime catch that degrades to the forced-tool-call path (Plan 08-07/08-03).
// Safe fallback to single persona + review flag on parse exhaustion (CF-2, T-02-09).

use schemars::JsonSchema;
use serde::Deserialize;

use crate::capability::CapabilityRegistry;
use crate::persona::PersonaRegistry;
use crate::provider::Provider;
use crate::types::{CallConfig, Message, MessageContent, Role};

// ---------------------------------------------------------------------------
// RouterDecision types — VERBATIM from spec §2 / AI-SPEC §4b
// ---------------------------------------------------------------------------

/// `ResponseMode`/`ConveneReason`/`RouterDecision` moved to `bastion_types`
/// (M2 step 6) — pure `JsonSchema`-deriving data referenced by
/// `bastion-cognition`'s Cabinet (`build_table`) without pulling in this
/// crate. Re-exported here so every existing `crate::persona::router::...`
/// path keeps compiling.
pub use bastion_types::{ConveneReason, ResponseMode, RouterDecision};

/// What the LLM actually decides. `owner` is NOT here — it is contextual and is
/// injected by `route()` from its caller, never produced by the model. Using this
/// as the structured-output schema/parse target stops the router from failing with
/// "missing field `owner`" when the model (correctly) omits it.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RouterDecisionLlm {
    personas: Vec<String>,
    mode: ResponseMode,
    #[serde(default)]
    convene_reason: Option<ConveneReason>,
}

// ---------------------------------------------------------------------------
// route() — the main entry point
// ---------------------------------------------------------------------------

/// Classify `msg` into a `RouterDecision` using the provider as a cheap 0.0-temp
/// classification call.  Retries serde-parse up to 3 attempts; on exhaustion returns
/// a safe single-persona fallback + logs `router_safe_fallback` (CF-2, AI-SPEC §6).
pub async fn route(
    provider: &dyn Provider,
    registry: &PersonaRegistry,
    msg: &str,
    owner: &str,
    capability_registry: &mut CapabilityRegistry,
) -> anyhow::Result<RouterDecision> {
    // Schema/parse target is the owner-less DTO — owner is injected below, not by the model.
    let schema = schemars::schema_for!(RouterDecisionLlm);
    let response_schema = serde_json::to_value(&schema)
        .map_err(|e| anyhow::anyhow!("failed to serialize router schema: {e}"))?;

    let system_prompt = build_router_system_prompt(registry);

    let messages = vec![Message {
        role: Role::User,
        content: MessageContent::Text(msg.to_owned()),
    }];
    let config = CallConfig {
        system_prompt: system_prompt.clone(),
        max_tokens: 512,
        temperature: Some(0.0),
        response_format: None,
        tool_choice: None,
        tools: vec![],
    };
    // D-09 runtime catch: a `supports_json_schema()==true` provider can still reject the
    // schema at runtime (OpenRouter's per-model variance) — fall through to the
    // forced-tool-call helper on the FIRST such rejection and stay on it for the
    // remaining retry attempts (never bounce back to the direct path mid-retry).
    let mut use_forced = !provider.supports_json_schema();

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        tracing::debug!(
            event = "structured_output_path",
            provider = %provider.name(),
            forced = use_forced
        );
        let raw_result = if use_forced {
            // NOTE: `check_egress` denies `None` on ambiguity (fail-closed) — the
            // ephemeral `StructuredOutputCapability` is `is_local()==true` and only
            // clears the egress gate for a concrete `Some(LocalOnly)` tier (see
            // `complete_structured_via_forced_tool_call`'s own test `test_ctx()` in
            // provider/mod.rs), never for `None`.
            let ctx = crate::capability::InvokeCtx {
                owner: owner.to_owned(),
                privacy_tier: Some(crate::memory::PrivacyTier::LocalOnly),
                // Ephemeral internal structured-output capability, not a
                // persona-dispatched user tool call — no persona contract
                // applies here, so unrestricted (None) is correct.
                allowed_tools: None,
            };
            crate::provider::complete_structured_via_forced_tool_call(
                provider,
                capability_registry,
                &ctx,
                &messages,
                &config,
                response_schema.clone(),
            )
            .await
        } else {
            provider
                .complete(
                    &messages,
                    &CallConfig {
                        response_format: Some(response_schema.clone()),
                        ..config.clone()
                    },
                )
                .await
                .map(|r| r.text)
        };

        let raw = match raw_result {
            Ok(raw) => raw,
            Err(e) => {
                let msg_txt = e.to_string();
                if !use_forced
                    && (msg_txt.contains("response_format")
                        || msg_txt.contains("json_schema")
                        || msg_txt.contains("400"))
                {
                    tracing::warn!(
                        attempt,
                        error = %msg_txt,
                        "router provider rejected the schema at runtime — falling through to forced-tool-call"
                    );
                    use_forced = true;
                } else {
                    tracing::warn!(
                        attempt,
                        error = %msg_txt,
                        "router provider call failed — retrying"
                    );
                }
                continue;
            }
        };

        // Defensive: some providers (e.g. Gemini) wrap JSON in ```fences``` or leading prose
        // despite the instruction. Extract the outermost {...} before parsing.
        let json = extract_json(&raw);
        match serde_json::from_str::<RouterDecisionLlm>(json) {
            Ok(d) => {
                // Observability: log the DECISION metadata (personas/mode/reason) — never the
                // message content (Pitfall 7). Lets operators/UAT confirm routing from logs.
                tracing::info!(
                    event = "router_decision",
                    personas = ?d.personas,
                    mode = ?d.mode,
                    convene_reason = ?d.convene_reason,
                    owner,
                    "router classified message"
                );
                return Ok(RouterDecision {
                    personas: d.personas,
                    owner: owner.to_string(),
                    mode: d.mode,
                    convene_reason: d.convene_reason,
                });
            }
            Err(parse_err) => {
                // Pitfall 7: do NOT log raw for local-only context.
                // Log metadata only (attempt count + error shape), never raw content.
                tracing::warn!(
                    attempt,
                    error = %parse_err,
                    "router output was not valid RouterDecision JSON — retrying"
                );
            }
        }
    }

    // All 3 attempts failed to yield a parseable RouterDecision.
    // Safe fallback: single persona (first in registry or empty sentinel), no convene (CF-2).
    tracing::warn!(
        event = "router_safe_fallback",
        owner,
        "router failed to parse after 3 attempts; falling back to safe single persona"
    );

    let safe_persona = registry
        .names()
        .into_iter()
        .next()
        .unwrap_or("default")
        .to_string();

    Ok(RouterDecision {
        personas: vec![safe_persona],
        owner: owner.to_string(),
        mode: ResponseMode::Single,
        convene_reason: None,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract the outermost JSON object from a model response that may be wrapped in
/// markdown fences or surrounded by prose. Falls back to the trimmed input.
fn extract_json(s: &str) -> &str {
    match (s.find('{'), s.rfind('}')) {
        (Some(a), Some(b)) if b > a => &s[a..=b],
        _ => s.trim(),
    }
}

fn build_router_system_prompt(registry: &PersonaRegistry) -> String {
    let persona_list = registry
        .names()
        .iter()
        .map(|n| {
            let desc = registry
                .get(n)
                .and_then(|p| p.description.as_deref())
                .unwrap_or("general assistant");
            format!("  - {n}: {desc}")
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are the Bastion persona router. Given a user message, decide which personas should respond and in what mode.

Available personas:
{persona_list}

Response modes:
  - single: one persona handles the message (single domain, routine)
  - parallel: multiple personas handle the message concurrently (cross-domain, factual, no conflict)
  - cabinet: multiple personas deliberate together (high-stakes, conflicting priorities, or goal-impact)

Cabinet convene reasons (use when mode=cabinet):
  - high_weight: high-stakes message (risk to health, finance, relationships) → maps to ConveneReason::HighWeight (D-04/D-05)
  - multi_domain_conflict: multiple domains with conflicting advice
  - goal_impact: message may affect a tracked user goal
  - manual_override: user explicitly requested cabinet

Rules:
1. high-stakes messages MUST set mode=cabinet and convene_reason=high_weight (D-04/D-05).
2. convene_reason is ONLY set when mode=cabinet; otherwise it must be null/absent.
3. personas must contain at least one valid persona name from the list above.
4. Match domain keywords carefully — work/job topics go to the career/work persona, not personal projects.

Few-shot examples (use as reference for ambiguous inputs):
  - "reuniões de trabalho" → career/work persona (NOT personal projects)
  - "quero pedir aumento de salário" → career/work persona
  - "receita de bolo" → personal-life/lifestyle persona
  - "plano de fitness" → health/wellness persona
  - "aniversário da esposa" → family/relationships persona
  - "minha meta de 2026" → goals/objectives persona (or parallel if multiple domains)
  - "devo investir em ações?" → finance persona, mode=cabinet if high-stakes amount mentioned
  - "dor no peito" → health persona, mode=cabinet with convene_reason=high_weight

Respond ONLY with a JSON object with exactly these fields:
  {{"personas": ["<name>", ...], "mode": "single|parallel|cabinet", "convene_reason": null}}
Set convene_reason to one of the reasons above ONLY when mode is "cabinet", otherwise null.
Do NOT include an "owner" field. No prose, no markdown fences."#
    )
}

// ---------------------------------------------------------------------------
// Tests (offline — MockProvider only, no live LLM)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityRegistry;
    use crate::memory::PrivacyTier;
    use crate::persona::{Persona, PersonaRegistry};
    use crate::provider::Provider;
    use crate::types::{CallConfig, LlmResponse, Message, ToolCall, ToolChoice};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // --- MockProvider ---

    struct MockProvider {
        /// Scripted responses returned in order. After exhaustion returns the last one.
        responses: Mutex<Vec<String>>,
        /// D-09 static capability declaration this mock reports.
        supports_schema: bool,
        /// If Some, the FIRST direct (non-forced) `complete()` call returns this as an
        /// `Err`, simulating a runtime schema rejection (D-09 runtime catch); consumed
        /// (taken) so it only fires once. Forced-tool-call attempts never see it.
        reject_first_direct: Mutex<Option<String>>,
    }

    impl MockProvider {
        fn new(responses: Vec<String>) -> Self {
            Self {
                responses: Mutex::new(responses),
                supports_schema: true,
                reject_first_direct: Mutex::new(None),
            }
        }

        fn always(response: &str) -> Self {
            Self::new(vec![response.to_string()])
        }

        fn sequence(responses: &[&str]) -> Self {
            Self::new(responses.iter().map(|s| s.to_string()).collect())
        }

        /// A provider that declares `supports_json_schema()==false` — route() must go
        /// straight to the forced-tool-call path.
        fn without_json_schema_support(response: &str) -> Self {
            Self {
                supports_schema: false,
                ..Self::always(response)
            }
        }

        /// A `supports_json_schema()==true` provider whose first direct-path call is
        /// rejected at runtime (schema-shaped error) — route() must fall through to the
        /// forced-tool-call path on the next attempt and succeed.
        fn rejecting_schema_once_then(response: &str) -> Self {
            Self {
                reject_first_direct: Mutex::new(Some(
                    "HTTP 400: response_format not supported by this model".to_string(),
                )),
                ..Self::always(response)
            }
        }
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn complete(
            &self,
            _: &[Message],
            config: &CallConfig,
        ) -> anyhow::Result<LlmResponse> {
            let forced = matches!(config.tool_choice, Some(ToolChoice::Forced(_)));
            if !forced {
                if let Some(err) = self
                    .reject_first_direct
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    anyhow::bail!(err);
                }
            }
            let raw = {
                let mut responses = self.responses.lock().unwrap_or_else(|e| e.into_inner());
                if responses.len() > 1 {
                    responses.remove(0)
                } else {
                    responses[0].clone()
                }
            };
            if forced {
                let Some(ToolChoice::Forced(name)) = config.tool_choice.clone() else {
                    unreachable!("checked by `forced` above")
                };
                let arguments =
                    serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}));
                Ok(LlmResponse {
                    text: String::new(),
                    tool_calls: Some(vec![ToolCall {
                        id: "1".into(),
                        name,
                        arguments,
                        extra: None,
                    }]),
                    usage: Default::default(),
                })
            } else {
                Ok(LlmResponse {
                    text: raw,
                    tool_calls: None,
                    usage: Default::default(),
                })
            }
        }
        async fn complete_simple(&self, _: &str) -> anyhow::Result<String> {
            unimplemented!()
        }
        fn context_limit(&self) -> usize {
            8192
        }
        fn model_name(&self) -> &str {
            "mock"
        }
        fn name(&self) -> &'static str {
            "mock"
        }
        fn supports_json_schema(&self) -> bool {
            self.supports_schema
        }
    }

    // --- Registry builder ---

    fn make_registry() -> PersonaRegistry {
        let mut personas = HashMap::new();
        personas.insert(
            "Saúde".to_string(),
            Persona {
                name: "Saúde".to_string(),
                description: Some("Health persona".to_string()),
                system_prompt: "You are Saúde.".to_string(),
                tier: PrivacyTier::LocalOnly,
                weight: 0.9,
                skills: vec!["health".to_string()],
                ..Default::default()
            },
        );
        personas.insert(
            "Aria".to_string(),
            Persona {
                name: "Aria".to_string(),
                description: Some("General assistant".to_string()),
                system_prompt: "You are Aria.".to_string(),
                tier: PrivacyTier::CloudOk,
                weight: 0.7,
                skills: vec![],
                ..Default::default()
            },
        );
        PersonaRegistry::new_from_map(personas)
    }

    // --- Tests ---

    #[tokio::test]
    async fn valid_single_decision_is_parsed() {
        let json = serde_json::json!({
            "personas": ["Aria"],
            "owner": "user1",
            "mode": "single",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::always(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(&provider, &registry, "hello", "user1", &mut cap_registry)
            .await
            .expect("route failed");

        assert_eq!(decision.mode, ResponseMode::Single);
        assert_eq!(decision.personas, vec!["Aria"]);
        assert!(decision.convene_reason.is_none());
    }

    #[tokio::test]
    async fn valid_cabinet_decision_with_high_weight_is_parsed() {
        // D-04: high-stakes → Cabinet; D-05: convene_reason = HighWeight
        let json = serde_json::json!({
            "personas": ["Saúde", "Aria"],
            "owner": "user1",
            "mode": "cabinet",
            "convene_reason": "high_weight"
        })
        .to_string();

        let provider = MockProvider::always(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(
            &provider,
            &registry,
            "I have chest pains",
            "user1",
            &mut cap_registry,
        )
        .await
        .expect("route failed");

        assert_eq!(decision.mode, ResponseMode::Cabinet);
        assert_eq!(decision.convene_reason, Some(ConveneReason::HighWeight));
    }

    #[tokio::test]
    async fn garbage_3x_falls_back_to_safe_single_persona() {
        // CF-2: 3 consecutive unparseable outputs → safe single-persona fallback
        let provider = MockProvider::sequence(&["not json", "also garbage", "{{ invalid"]);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(&provider, &registry, "test", "user1", &mut cap_registry)
            .await
            .expect("route must not error — safe fallback");

        assert_eq!(
            decision.mode,
            ResponseMode::Single,
            "fallback must be Single"
        );
        assert_eq!(
            decision.personas.len(),
            1,
            "fallback must have exactly 1 persona"
        );
        assert!(
            decision.convene_reason.is_none(),
            "fallback must not convene Cabinet"
        );
    }

    #[tokio::test]
    async fn two_garbage_then_valid_succeeds() {
        // Retry succeeds on the 3rd attempt
        let valid = serde_json::json!({
            "personas": ["Aria"],
            "owner": "u",
            "mode": "parallel",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::sequence(&["garbage", "also bad", &valid]);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(
            &provider,
            &registry,
            "cross-domain query",
            "u",
            &mut cap_registry,
        )
        .await
        .expect("route failed");

        assert_eq!(decision.mode, ResponseMode::Parallel);
    }

    // --- Few-shot routing coverage (misroute prevention) ---

    #[tokio::test]
    async fn routes_work_meeting_to_career_not_projects() {
        // "reuniões de trabalho" must route to a work/career persona, not personal projects.
        // MockProvider simulates LLM correctly following few-shot guidance.
        let json = serde_json::json!({
            "personas": ["Aria"],
            "mode": "single",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::always(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(
            &provider,
            &registry,
            "reuniões de trabalho",
            "user1",
            &mut cap_registry,
        )
        .await
        .expect("route failed");

        assert_eq!(decision.mode, ResponseMode::Single);
        assert!(
            !decision.personas.is_empty(),
            "must have at least one persona"
        );
    }

    #[tokio::test]
    async fn routes_fitness_to_health_persona() {
        // "plano de fitness" → health persona
        let json = serde_json::json!({
            "personas": ["Saúde"],
            "mode": "single",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::always(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(
            &provider,
            &registry,
            "plano de fitness para perder peso",
            "user1",
            &mut cap_registry,
        )
        .await
        .expect("route failed");

        assert_eq!(decision.personas, vec!["Saúde"]);
        assert_eq!(decision.mode, ResponseMode::Single);
    }

    #[tokio::test]
    async fn routes_recipe_to_single_persona() {
        // "receita de bolo" → personal-life/lifestyle persona (single mode)
        let json = serde_json::json!({
            "personas": ["Aria"],
            "mode": "single",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::always(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(
            &provider,
            &registry,
            "receita de bolo de chocolate",
            "user1",
            &mut cap_registry,
        )
        .await
        .expect("route failed");

        assert_eq!(decision.mode, ResponseMode::Single);
        assert!(
            !decision.personas.is_empty(),
            "must have at least one persona"
        );
    }

    #[test]
    fn system_prompt_contains_few_shot_examples() {
        // Structural check: the router system prompt must include few-shot examples
        // to reduce persona misroute (WR / live-UAT finding 2026-06-03).
        let registry = make_registry();
        let prompt = build_router_system_prompt(&registry);
        assert!(
            prompt.contains("Few-shot examples")
                || prompt.contains("few-shot")
                || prompt.contains("few_shot"),
            "Router system prompt must contain few-shot examples section"
        );
        assert!(
            prompt.contains("reuniões de trabalho")
                || prompt.contains("fitness")
                || prompt.contains("Examples"),
            "Router system prompt must contain at least one routing example"
        );
    }

    // --- D-04/D-09: complete()-surface migration (Plan 08-07) ---

    #[tokio::test]
    async fn direct_path_used_when_provider_supports_json_schema() {
        // Test 1: `supports_json_schema()==true` (default) + well-formed response → the
        // direct `complete()` path parses successfully, no forced-tool-call needed.
        let json = serde_json::json!({
            "personas": ["Aria"],
            "mode": "single",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::always(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(&provider, &registry, "hi", "user1", &mut cap_registry)
            .await
            .expect("route failed");

        assert_eq!(decision.mode, ResponseMode::Single);
        assert_eq!(decision.personas, vec!["Aria"]);
    }

    #[tokio::test]
    async fn forced_path_used_when_provider_lacks_json_schema_support() {
        // Test 2: `supports_json_schema()==false` — route() must go straight through
        // `complete_structured_via_forced_tool_call` and still parse successfully.
        let json = serde_json::json!({
            "personas": ["Saúde"],
            "mode": "single",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::without_json_schema_support(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(&provider, &registry, "hi", "user1", &mut cap_registry)
            .await
            .expect("route failed via forced-tool-call path");

        assert_eq!(decision.personas, vec!["Saúde"]);
        // The ephemeral StructuredOutputCapability must be cleaned up (TurnCapabilityScope Drop).
        assert!(cap_registry.is_empty());
    }

    #[tokio::test]
    async fn runtime_schema_rejection_falls_through_to_forced_path() {
        // Test 3: a `supports_json_schema()==true` provider that rejects the schema at
        // runtime on attempt 1 (HTTP-400-shaped error) must fall through to the
        // forced-tool-call path on attempt 2 and still succeed.
        let json = serde_json::json!({
            "personas": ["Aria"],
            "mode": "parallel",
            "convene_reason": null
        })
        .to_string();

        let provider = MockProvider::rejecting_schema_once_then(&json);
        let registry = make_registry();
        let mut cap_registry = CapabilityRegistry::new();
        let decision = route(&provider, &registry, "hi", "user1", &mut cap_registry)
            .await
            .expect("route must recover via the forced-tool-call fallback");

        assert_eq!(decision.mode, ResponseMode::Parallel);
        assert!(cap_registry.is_empty());
    }
}
