//! Cabinet synthesis — unified voice + explicit dissent (CAB-05, D-07).
//!
//! `synthesize()` takes a deliberation transcript and returns a `CabinetVerdict`:
//! - `recommendation`: a unified-voice summary of the Cabinet's collective position.
//! - `dissents`: all divergent positions (REQUIRED field — cannot be silently dropped, CF-3).
//!
//! On parse failure after 3 retries: returns a raw-positions fallback that surfaces
//! each participant's stance. NEVER fabricates a verdict (AI-SPEC §6).
//!
//! D-08: the full debate transcript is opt-in (exposed via `/cabinet`); this function
//! only returns the synthesized verdict, not the raw transcript.

use crate::cabinet::Turn;
use crate::capability::CapabilityRegistry;
use crate::provider::Provider;
use crate::types::{CallConfig, Message, MessageContent, Role};
// `CabinetVerdict`/`Dissent` moved to `bastion-types` (M2 step 5) — pure
// JsonSchema-deriving data shared with `bastion-providers`' ollama.rs
// diagnostic test. Re-exported `pub` here (via the `crate::types` /
// `bastion_types::*` shim) so external paths like
// `crate::cabinet::synth::CabinetVerdict` (e.g. `persona/responder.rs`)
// keep resolving unchanged.
pub use crate::types::{CabinetVerdict, Dissent};

/// Synthesize the Cabinet transcript into a `CabinetVerdict`.
///
/// - Sends a structured completion request with a `CabinetVerdict` JSON schema.
/// - Retries serde-parse up to 3 attempts (AI-SPEC §4b).
/// - On exhaustion: returns a raw-positions `CabinetVerdict` assembled from the
///   transcript (never a fabricated consensus verdict — AI-SPEC §6).
/// - `response_language`: BCP-47 language tag for the synthesis output (e.g. "pt-BR").
///   Defaults to "pt-BR" when callers use `synthesize()` — the primary user is Mario (PT).
pub async fn synthesize(
    provider: &dyn Provider,
    transcript: &[Turn],
    capability_registry: &mut CapabilityRegistry,
) -> anyhow::Result<CabinetVerdict> {
    synthesize_in_language(provider, transcript, "pt-BR", capability_registry).await
}

/// Like `synthesize()` but with an explicit response language tag.
pub async fn synthesize_in_language(
    provider: &dyn Provider,
    transcript: &[Turn],
    response_language: &str,
    capability_registry: &mut CapabilityRegistry,
) -> anyhow::Result<CabinetVerdict> {
    let schema = schemars::schema_for!(CabinetVerdict);
    let response_schema = serde_json::to_value(&schema)
        .map_err(|e| anyhow::anyhow!("failed to serialize CabinetVerdict schema: {e}"))?;

    let system = build_synthesis_prompt(response_language);
    let user = build_transcript_text(transcript);

    let messages = vec![Message {
        role: Role::User,
        content: MessageContent::Text(user),
    }];
    let config = CallConfig {
        system_prompt: system.clone(),
        max_tokens: 4096,
        temperature: Some(0.3),
        response_format: None,
        tool_choice: None,
        tools: vec![],
    };
    // D-09 runtime catch: mirrors persona::router::route — see that function for the
    // full rationale. Once a runtime schema rejection is caught, stay on the forced
    // path for the remaining retry attempts.
    let mut use_forced = !provider.supports_json_schema();

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        tracing::debug!(
            event = "structured_output_path",
            provider = %provider.name(),
            forced = use_forced
        );
        let raw_result = if use_forced {
            // `owner` is inert for this ephemeral, pure-echo capability: it is
            // `is_local()==true` by construction (structured_output.rs), so egress
            // policy never keys on it. A fixed label is honest observability, not a
            // forged identity — no policy decision depends on this value.
            // NOTE: `check_egress` denies `None` on ambiguity (fail-closed) — the
            // ephemeral `StructuredOutputCapability` is `is_local()==true` and only
            // clears the egress gate for a concrete `Some(LocalOnly)` tier (see
            // `complete_structured_via_forced_tool_call`'s own test `test_ctx()` in
            // provider/mod.rs), never for `None`.
            let ctx = crate::capability::InvokeCtx {
                owner: "cabinet_synthesis".to_owned(),
                privacy_tier: Some(crate::memory::PrivacyTier::LocalOnly),
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
                        "cabinet synthesis provider rejected the schema at runtime — falling through to forced-tool-call"
                    );
                    use_forced = true;
                } else {
                    tracing::warn!(
                        attempt,
                        error = %msg_txt,
                        "cabinet synthesis provider call failed — retrying"
                    );
                }
                continue;
            }
        };

        match serde_json::from_str::<CabinetVerdict>(&raw) {
            Ok(verdict) => return Ok(verdict),
            Err(parse_err) => {
                tracing::warn!(
                    attempt,
                    error = %parse_err,
                    "cabinet synthesis output was not valid CabinetVerdict JSON — retrying"
                );
            }
        }
    }

    // All 3 attempts failed. Surface raw positions — NEVER fabricate consensus (AI-SPEC §6).
    tracing::warn!(
        event = "cabinet_synthesis_fallback",
        "synthesis parse failed after 3 attempts; surfacing raw positions"
    );
    Ok(raw_positions_fallback(transcript))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_synthesis_prompt(response_language: &str) -> String {
    format!(
        r#"You are the Cabinet synthesis engine. Your task is to produce a single unified response from a multi-persona deliberation transcript.

Rules:
1. Synthesize a clear, unified RECOMMENDATION that represents the collective position.
2. For ANY persona whose position materially diverged from the recommendation, you MUST include a Dissent entry with their name and their position. This field is REQUIRED — do not omit dissents even if consensus appears strong.
3. If all personas were fully aligned, dissents may be empty — but only if there is ZERO divergence.
4. NEVER fabricate agreement. If in doubt, record the dissent.
5. Respond in {response_language}.

Respond ONLY with a JSON object with exactly these fields:
  {{"recommendation": "<the unified recommendation text>", "dissents": [{{"persona": "<name>", "position": "<their diverging position>"}}]}}
"dissents" must be an array (empty [] only if there was zero divergence). No prose, no markdown fences."#,
        response_language = response_language,
    )
}

fn build_transcript_text(transcript: &[Turn]) -> String {
    if transcript.is_empty() {
        return "No transcript turns available.".to_string();
    }
    transcript
        .iter()
        .map(|t| {
            format!(
                "[{}] ({}): {}",
                t.persona,
                format!("{:?}", t.kind).to_lowercase(),
                t.text
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build a raw-positions fallback verdict.
///
/// `recommendation` explains that synthesis failed and lists raw positions.
/// `dissents` contains each participant's stance so nothing is dropped (CF-3).
fn raw_positions_fallback(transcript: &[Turn]) -> CabinetVerdict {
    let raw_text = build_transcript_text(transcript);
    let recommendation = format!("Could not synthesize — raw positions follow:\n{raw_text}");

    // Each unique persona gets a dissent entry with their last-seen turn as position.
    // This ensures the caller sees ALL stances, not a fabricated consensus.
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for turn in transcript {
        seen.insert(turn.persona.clone(), turn.text.clone());
    }
    let dissents: Vec<Dissent> = seen
        .into_iter()
        .map(|(persona, position)| Dissent { persona, position })
        .collect();

    CabinetVerdict {
        recommendation,
        dissents,
    }
}

// ---------------------------------------------------------------------------
// Tests (offline — MockProvider only, no live LLM)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cabinet::{Turn, TurnKind};
    use crate::provider::Provider;
    use crate::types::{CallConfig, LlmResponse, Message, ToolCall, ToolChoice};
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct ScriptedProvider {
        responses: Mutex<Vec<String>>,
        /// D-09 static capability declaration this mock reports.
        supports_schema: bool,
        /// If Some, the FIRST direct (non-forced) `complete()` call returns this as an
        /// `Err`, simulating a runtime schema rejection; consumed (taken) so it only
        /// fires once. Forced-tool-call attempts never see it.
        reject_first_direct: Mutex<Option<String>>,
    }

    impl ScriptedProvider {
        fn sequence(responses: &[&str]) -> Self {
            Self {
                responses: Mutex::new(responses.iter().map(|s| s.to_string()).collect()),
                supports_schema: true,
                reject_first_direct: Mutex::new(None),
            }
        }

        fn always(response: &str) -> Self {
            Self::sequence(&[response])
        }

        /// A provider that declares `supports_json_schema()==false` — synthesize() must
        /// go straight to the forced-tool-call path.
        fn without_json_schema_support(response: &str) -> Self {
            Self {
                supports_schema: false,
                ..Self::always(response)
            }
        }

        /// A `supports_json_schema()==true` provider whose first direct-path call is
        /// rejected at runtime — synthesize() must fall through to the forced-tool-call
        /// path on the next attempt and succeed.
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
    impl Provider for ScriptedProvider {
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

    fn make_divergent_transcript() -> Vec<Turn> {
        vec![
            Turn {
                persona: "Aria".to_string(),
                kind: TurnKind::Position,
                text: "I recommend approach A because it is safest.".to_string(),
            },
            Turn {
                persona: "Finance".to_string(),
                kind: TurnKind::Position,
                text: "I recommend approach B because it is cheapest.".to_string(),
            },
        ]
    }

    #[tokio::test]
    async fn valid_verdict_with_dissents_is_parsed() {
        let verdict_json = serde_json::json!({
            "recommendation": "Adopt approach A with cost controls.",
            "dissents": [
                { "persona": "Finance", "position": "Approach B is cheaper." }
            ]
        })
        .to_string();

        let provider = ScriptedProvider::always(&verdict_json);
        let transcript = make_divergent_transcript();
        let mut cap_registry = CapabilityRegistry::new();

        let verdict = synthesize(&provider, &transcript, &mut cap_registry)
            .await
            .unwrap();

        assert!(
            !verdict.dissents.is_empty(),
            "dissents must be non-empty for divergent transcript"
        );
        assert_eq!(verdict.dissents[0].persona, "Finance");
    }

    #[tokio::test]
    async fn garbage_3x_returns_raw_positions_fallback_not_panic() {
        // AI-SPEC §6: parse failure → raw positions, no fabricated verdict, no panic.
        let provider = ScriptedProvider::sequence(&["garbage", "also bad", "{{ invalid"]);
        let transcript = make_divergent_transcript();
        let mut cap_registry = CapabilityRegistry::new();

        let verdict = synthesize(&provider, &transcript, &mut cap_registry)
            .await
            .unwrap();

        // Fallback: recommendation contains "raw positions"
        assert!(
            verdict.recommendation.contains("raw positions"),
            "expected raw-positions fallback, got: {}",
            verdict.recommendation
        );
        // Dissents must list all participants (CF-3 — nothing dropped)
        let persona_names: Vec<&str> = verdict
            .dissents
            .iter()
            .map(|d| d.persona.as_str())
            .collect();
        assert!(persona_names.contains(&"Aria"), "Aria must be in dissents");
        assert!(
            persona_names.contains(&"Finance"),
            "Finance must be in dissents"
        );
    }

    #[tokio::test]
    async fn two_garbage_then_valid_succeeds() {
        let verdict_json = serde_json::json!({
            "recommendation": "Go with approach A.",
            "dissents": []
        })
        .to_string();

        let provider = ScriptedProvider::sequence(&["garbage", "also bad", &verdict_json]);
        let transcript = make_divergent_transcript();
        let mut cap_registry = CapabilityRegistry::new();

        let verdict = synthesize(&provider, &transcript, &mut cap_registry)
            .await
            .unwrap();
        assert_eq!(verdict.recommendation, "Go with approach A.");
    }

    #[tokio::test]
    async fn empty_transcript_returns_graceful_fallback() {
        let provider = ScriptedProvider::sequence(&["garbage", "garbage", "garbage"]);
        let mut cap_registry = CapabilityRegistry::new();
        let verdict = synthesize(&provider, &[], &mut cap_registry).await.unwrap();
        // No panic, recommendation mentions raw positions
        assert!(
            verdict.recommendation.contains("raw positions")
                || verdict.recommendation.contains("No transcript")
        );
    }

    #[test]
    fn synth_prompt_contains_language_instruction() {
        // Structural check: synth prompt must instruct the LLM to respond in the given language.
        // Fixes live-UAT finding: verdict came out in EN while persona positions were PT (2026-06-03).
        let prompt = build_synthesis_prompt("pt-BR");
        assert!(
            prompt.contains("pt-BR") || prompt.contains("Respond in"),
            "Synth prompt must contain language instruction; got: {prompt}"
        );
    }

    #[test]
    fn synth_prompt_language_is_injected() {
        // Verify that the language tag is actually interpolated into the prompt.
        let prompt_ptbr = build_synthesis_prompt("pt-BR");
        let prompt_en = build_synthesis_prompt("en-US");
        assert!(prompt_ptbr.contains("pt-BR"), "pt-BR must appear in prompt");
        assert!(prompt_en.contains("en-US"), "en-US must appear in prompt");
        assert_ne!(
            prompt_ptbr, prompt_en,
            "prompts for different languages must differ"
        );
    }

    // --- D-04/D-09: complete()-surface migration (Plan 08-07) ---

    #[tokio::test]
    async fn direct_path_used_when_provider_supports_json_schema() {
        // Test 4a: `supports_json_schema()==true` (default) + well-formed response →
        // the direct `complete()` path parses successfully.
        let verdict_json = serde_json::json!({
            "recommendation": "Go with approach A.",
            "dissents": []
        })
        .to_string();

        let provider = ScriptedProvider::always(&verdict_json);
        let transcript = make_divergent_transcript();
        let mut cap_registry = CapabilityRegistry::new();

        let verdict = synthesize(&provider, &transcript, &mut cap_registry)
            .await
            .unwrap();
        assert_eq!(verdict.recommendation, "Go with approach A.");
    }

    #[tokio::test]
    async fn forced_path_used_when_provider_lacks_json_schema_support() {
        // Test 4b: `supports_json_schema()==false` — synthesize() must go straight
        // through the forced-tool-call path and still parse successfully.
        let verdict_json = serde_json::json!({
            "recommendation": "Go with approach B.",
            "dissents": []
        })
        .to_string();

        let provider = ScriptedProvider::without_json_schema_support(&verdict_json);
        let transcript = make_divergent_transcript();
        let mut cap_registry = CapabilityRegistry::new();

        let verdict = synthesize(&provider, &transcript, &mut cap_registry)
            .await
            .expect("synthesize via forced-tool-call path");
        assert_eq!(verdict.recommendation, "Go with approach B.");
        assert!(cap_registry.is_empty());
    }

    #[tokio::test]
    async fn runtime_schema_rejection_falls_through_to_forced_path() {
        // Test 4c: a `supports_json_schema()==true` provider that rejects the schema at
        // runtime on attempt 1 must fall through to the forced-tool-call path on
        // attempt 2 and still succeed.
        let verdict_json = serde_json::json!({
            "recommendation": "Go with approach C.",
            "dissents": []
        })
        .to_string();

        let provider = ScriptedProvider::rejecting_schema_once_then(&verdict_json);
        let transcript = make_divergent_transcript();
        let mut cap_registry = CapabilityRegistry::new();

        let verdict = synthesize(&provider, &transcript, &mut cap_registry)
            .await
            .expect("synthesize must recover via the forced-tool-call fallback");
        assert_eq!(verdict.recommendation, "Go with approach C.");
        assert!(cap_registry.is_empty());
    }
}
