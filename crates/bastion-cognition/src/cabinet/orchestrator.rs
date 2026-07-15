//! Bounded deliberation orchestrator (CAB-01, D-06).
//!
//! `deliberate()` runs the Cabinet state machine:
//! - DEFAULT_ROUNDS = 2, MAX_ROUNDS = 3 (clamped: rounds.clamp(1, MAX_ROUNDS)).
//! - R1: parallel positions — JoinSet fan-out, each task returns (PersonaId, Result).
//! - R2..n: reply rounds — each persona sees the running transcript.
//! - R3 (cap): forced synthesis handoff signal (synthesis is `synth::synthesize`).
//!
//! CF-3 / Pitfall 4: every transcript turn is tagged by the RETURNED PersonaId from
//! the async task, never by spawn order.
//!
//! Fail-closed egress (CF-1): `check_egress(Some(table.tier), provider_name)` is called
//! before EACH persona's provider call. On error the turn is skipped with `tracing::warn!`.

use tokio::task::JoinSet;

use crate::cabinet::{CabinetTable, Turn, TurnKind};
use crate::hooks::egress::check_egress;
use crate::provider::SharedProvider;
use crate::types::{CallConfig, Message, MessageContent, PersonaId, Role};

pub const DEFAULT_ROUNDS: u8 = 2;
pub const MAX_ROUNDS: u8 = 3;

/// Run the bounded Cabinet deliberation, returning the full tagged transcript.
///
/// Synthesis (CAB-05) is NOT performed here — callers should pass the returned
/// transcript to `synth::synthesize` when they want a `CabinetVerdict`.
///
/// # Arguments
/// - `table`: The convened personas and their resolved tier.
/// - `provider`: Shared provider (Arc<RwLock>) — cloned into each JoinSet task.
/// - `rounds`: Requested round count; clamped to `[1, MAX_ROUNDS]`.
/// - `capability_registry`: Used to snapshot tool definitions for each persona's CallConfig (BIG-1).
pub async fn deliberate(
    table: &CabinetTable,
    provider: SharedProvider,
    rounds: u8,
    capability_registry: &crate::capability::CapabilityRegistry,
) -> anyhow::Result<Vec<Turn>> {
    let rounds = rounds.clamp(1, MAX_ROUNDS);
    let mut transcript: Vec<Turn> = Vec::new();

    // Snapshot tool definitions before the JoinSet spawns.
    // tool_defs is Vec<Value> (not &CapabilityRegistry), safe to clone into each spawn.
    // BIG-1 / Cabinet v1.0: persona receives tools in CallConfig but tool_calls are NOT
    // executed inline in the Cabinet (JoinSet pattern does not support dispatch_tool_loop).
    // The LLM has awareness of capabilities and can reference tools in its position text.
    // Tool execution in Cabinet: Phase 3 roadmap.
    let tool_defs = capability_registry.list_tool_defs();

    for round in 1..=rounds {
        let kind = if round == 1 {
            TurnKind::Position
        } else {
            TurnKind::Reply
        };

        // Build a snapshot of the transcript visible to this round's personas.
        let transcript_snapshot = transcript.clone();
        let tier = table.tier;

        // Fan-out: spawn one task per persona.
        let mut set: JoinSet<(PersonaId, anyhow::Result<String>)> = JoinSet::new();

        for persona in &table.personas {
            let persona_id = persona.name.clone();
            let system_prompt = persona.system_prompt.clone();
            let provider_clone = provider.clone();
            let snap = transcript_snapshot.clone();
            let round_kind = kind.clone();
            let tools = tool_defs.clone();

            set.spawn(async move {
                // Fail-closed egress backstop (CF-1): before every cabinet provider call.
                let provider_name = {
                    let guard = provider_clone.read().await;
                    guard.name().to_owned()
                };
                if let Err(e) = check_egress(Some(tier), &provider_name) {
                    return (persona_id, Err(e));
                }

                // Build the turn prompt.
                let prompt = build_turn_prompt(&persona_id, &system_prompt, &snap, round_kind);

                // Build CallConfig with persona's system prompt and tool definitions.
                let config = CallConfig {
                    system_prompt: system_prompt.clone(),
                    max_tokens: 2048,
                    tools,
                    ..Default::default()
                };

                // Build a single-message history from the constructed prompt.
                let history = vec![Message {
                    role: Role::User,
                    content: MessageContent::Text(prompt),
                }];

                // BIG-1 / Cabinet v1.0: call provider.complete() with tools.
                // tool_calls in response are NOT executed inline — Cabinet uses tools for
                // awareness only (LLM can reference capabilities in its position text).
                // Acquire read lock INSIDE the task (loop_.rs:118-125 pattern).
                let result = {
                    let guard = provider_clone.read().await;
                    guard.complete(&history, &config).await.map(|r| r.text)
                };

                // Tag by RETURNED PersonaId — never by spawn order (CF-3 / Pitfall 4).
                (persona_id, result)
            });
        }

        // Collect results; warn on failures but continue (partial transcript is valid).
        let mut round_turns: Vec<(PersonaId, String)> = Vec::new();
        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok((pid, Ok(text))) => round_turns.push((pid, text)),
                Ok((pid, Err(e))) => {
                    tracing::warn!(
                        persona_id = %pid,
                        round = round,
                        error = %e,
                        "cabinet persona call failed — skipping turn"
                    );
                }
                Err(join_err) => {
                    tracing::warn!(
                        round = round,
                        error = %join_err,
                        "cabinet JoinSet task panicked"
                    );
                }
            }
        }

        // Hard cap guard (loop_.rs discipline): should never trigger due to clamp above,
        // but log a tracing::error! if we somehow exceed MAX_ROUNDS.
        if round > MAX_ROUNDS {
            tracing::error!(
                event = "cabinet_round_cap_exceeded",
                round = round,
                max = MAX_ROUNDS,
                "cabinet round counter exceeded MAX_ROUNDS — truncating"
            );
            break;
        }

        for (pid, text) in round_turns {
            transcript.push(Turn {
                persona: pid,
                kind: kind.clone(),
                text,
            });
        }
    }

    Ok(transcript)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_turn_prompt(
    persona_id: &str,
    system_prompt: &str,
    transcript: &[Turn],
    kind: TurnKind,
) -> String {
    let header = if kind == TurnKind::Position {
        format!(
            "You are {persona_id}. Provide your position on the matter below.\n\n{system_prompt}"
        )
    } else {
        let prior = transcript
            .iter()
            .map(|t| format!("[{}]: {}", t.persona, t.text))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "You are {persona_id}. Review the positions below and provide your reply.\n\n{system_prompt}\n\nTranscript so far:\n{prior}"
        )
    };
    header
}

// ---------------------------------------------------------------------------
// Tests (offline — MockProvider only, no live LLM)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cabinet::{CabinetTable, TurnKind};
    use crate::capability::CapabilityRegistry;
    use crate::memory::PrivacyTier;
    use crate::provider::{Provider, SharedProvider};
    use crate::types::Persona;
    use crate::types::{CallConfig, LlmResponse, Message, TokenUsage};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// MockProvider echoes back "<persona_name>:position" parsed from the config.system_prompt.
    /// Config system_prompt contains "You are <name>." — extract it.
    struct EchoProvider;

    #[async_trait]
    impl Provider for EchoProvider {
        async fn complete(
            &self,
            _: &[Message],
            config: &CallConfig,
        ) -> anyhow::Result<LlmResponse> {
            // Extract the persona name from "You are <Name>." in system_prompt.
            // The system_prompt may have trailing content, so find the first token after "You are ".
            let name = config
                .system_prompt
                .lines()
                .find(|l| l.starts_with("You are "))
                .and_then(|l| l.strip_prefix("You are "))
                .map(|s| s.split(['.', ' ']).next().unwrap_or("unknown"))
                .unwrap_or("unknown");
            Ok(LlmResponse {
                text: format!("response-from:{name}"),
                tool_calls: None,
                usage: TokenUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cache_read: 0,
                    cache_write: 0,
                    ..Default::default()
                },
            })
        }
        async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
            // Kept for backward compatibility — extract name from prompt lines.
            let name = prompt
                .lines()
                .find(|l| l.starts_with("You are "))
                .and_then(|l| l.strip_prefix("You are "))
                .map(|s| s.split(['.', ' ']).next().unwrap_or("unknown"))
                .unwrap_or("unknown");
            Ok(format!("response-from:{name}"))
        }
        fn context_limit(&self) -> usize {
            8192
        }
        fn model_name(&self) -> &str {
            "echo"
        }
        fn name(&self) -> &'static str {
            "mock"
        }
    }

    fn make_provider() -> SharedProvider {
        Arc::new(RwLock::new(Box::new(EchoProvider) as Box<dyn Provider>))
    }

    fn make_registry() -> CapabilityRegistry {
        CapabilityRegistry::new()
    }

    fn make_table(names: &[(&str, PrivacyTier)]) -> CabinetTable {
        let personas: Vec<Persona> = names
            .iter()
            .map(|(name, tier)| Persona {
                name: name.to_string(),
                description: None,
                system_prompt: format!("You are {name}."),
                tier: *tier,
                weight: 0.5,
                skills: vec![],
            })
            .collect();
        let tiers: Vec<PrivacyTier> = personas.iter().map(|p| p.tier).collect();
        let tier = crate::cabinet::policy::table_tier(&tiers);
        CabinetTable { personas, tier }
    }

    #[tokio::test]
    async fn round_count_never_exceeds_max_rounds() {
        let table = make_table(&[
            ("Alpha", PrivacyTier::CloudOk),
            ("Beta", PrivacyTier::CloudOk),
            ("Gamma", PrivacyTier::CloudOk),
        ]);
        let provider = make_provider();

        // Request 99 rounds — must be clamped to MAX_ROUNDS=3
        let transcript = deliberate(&table, provider, 99, &make_registry())
            .await
            .unwrap();

        // Each round produces 3 turns (one per persona), and rounds are clamped to 3
        let max_turns = usize::from(MAX_ROUNDS) * table.personas.len();
        assert!(
            transcript.len() <= max_turns,
            "transcript.len()={} but max_turns={}",
            transcript.len(),
            max_turns
        );
    }

    #[tokio::test]
    async fn transcript_attribution_is_by_returned_persona_id() {
        // CF-3 / Pitfall 4: each turn's `persona` field must match the content.
        let names = [
            ("Alpha", PrivacyTier::CloudOk),
            ("Beta", PrivacyTier::CloudOk),
            ("Gamma", PrivacyTier::CloudOk),
        ];
        let table = make_table(&names);
        let provider = make_provider();

        // 1 round = only position turns (easier to check attribution)
        let transcript = deliberate(&table, provider, 1, &make_registry())
            .await
            .unwrap();

        assert_eq!(transcript.len(), 3, "expected 3 position turns");

        for turn in &transcript {
            // EchoProvider returns "response-from:<name>" (extracted from the config.system_prompt).
            // The persona field (PersonaId) must match the name echoed in the text.
            // This proves attribution is by returned PersonaId — not spawn order (CF-3).
            assert!(
                turn.text
                    .starts_with(&format!("response-from:{}", turn.persona)),
                "attribution mismatch: persona={} text={}",
                turn.persona,
                turn.text
            );
        }
    }

    #[tokio::test]
    async fn r1_turns_are_position_kind() {
        let table = make_table(&[
            ("Alpha", PrivacyTier::CloudOk),
            ("Beta", PrivacyTier::CloudOk),
        ]);
        let provider = make_provider();

        let transcript = deliberate(&table, provider, 1, &make_registry())
            .await
            .unwrap();
        for turn in &transcript {
            assert_eq!(turn.kind, TurnKind::Position);
        }
    }

    #[tokio::test]
    async fn r2_turns_are_reply_kind() {
        let table = make_table(&[
            ("Alpha", PrivacyTier::CloudOk),
            ("Beta", PrivacyTier::CloudOk),
        ]);
        let provider = make_provider();

        let transcript = deliberate(&table, provider, 2, &make_registry())
            .await
            .unwrap();

        // First 2 turns: Position; next 2: Reply
        let positions: Vec<_> = transcript
            .iter()
            .filter(|t| t.kind == TurnKind::Position)
            .collect();
        let replies: Vec<_> = transcript
            .iter()
            .filter(|t| t.kind == TurnKind::Reply)
            .collect();
        assert_eq!(positions.len(), 2);
        assert_eq!(replies.len(), 2);
    }

    #[tokio::test]
    async fn egress_check_blocks_local_only_to_non_ollama() {
        // When the table tier is LocalOnly but provider.name() != "ollama",
        // check_egress must block the call → that persona's turn is skipped.
        // EchoProvider returns name() == "mock" (not "ollama").
        let table = make_table(&[
            ("Saude", PrivacyTier::LocalOnly),
            ("Aria", PrivacyTier::LocalOnly),
        ]);
        let provider = make_provider(); // name() == "mock"

        // All turns should be skipped (egress blocked) — empty transcript.
        let transcript = deliberate(&table, provider, 1, &make_registry())
            .await
            .unwrap();
        assert!(
            transcript.is_empty(),
            "expected empty transcript when egress blocks all calls, got {} turns",
            transcript.len()
        );
    }
}
