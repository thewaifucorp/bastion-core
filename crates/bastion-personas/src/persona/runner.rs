// Runner — executes a RouterDecision by dispatching to persona(s).
// Single: one provider call for the selected persona.
// Parallel: JoinSet fan-out, each task returns (PersonaId, Result) — tagged by RETURNED id,
//           never by spawn order (Pitfall 4 / CF-3 / T-02-07).
// Cabinet: returns ConveneCabinet(decision) — orchestrator (plan 05) takes over.

use tokio::task::JoinSet;

use crate::hooks::egress::check_egress;
use crate::persona::router::RouterDecision;
use crate::persona::{Persona, PersonaRegistry};
use crate::provider::SharedProvider;
use crate::types::{BastionError, CallConfig, LlmResponse, Message};

/// `PersonaId` moved to `bastion_types` (M2 step 6) — a zero-cost `String`
/// alias referenced by `bastion-cognition`'s Cabinet without pulling in this
/// crate. Re-exported here so every existing `crate::persona::runner::PersonaId`
/// path keeps compiling.
pub use bastion_types::PersonaId;

/// Output of a single runner invocation.
#[derive(Debug)]
pub enum RunnerOutput {
    /// Single persona responded; carries (persona_id, llm_response).
    Single(PersonaId, LlmResponse),
    /// Multiple personas responded in parallel; each entry is (persona_id, llm_response).
    /// Entries are in JoinSet completion order — callers must NOT assume any fixed ordering.
    Parallel(Vec<(PersonaId, LlmResponse)>),
    /// Cabinet mode — hand this decision to the Cabinet orchestrator (plan 05).
    ConveneCabinet(RouterDecision),
}

/// Execute the `RouterDecision` against the registry + provider.
///
/// - `history` is the conversation history (threaded through for context).
/// - `config` carries system_prompt + tools already populated by the caller.
/// - The `SharedProvider` (`Arc<RwLock<Box<dyn Provider>>>`) is cloned into each
///   JoinSet task; the read-lock is acquired **inside** each task (loop_.rs:118-125 pattern).
pub async fn run(
    decision: RouterDecision,
    registry: &PersonaRegistry,
    provider: SharedProvider,
    history: &[Message],
    config: &CallConfig,
) -> anyhow::Result<RunnerOutput> {
    match decision.mode {
        crate::persona::router::ResponseMode::Single => {
            run_single(decision, registry, provider, history, config).await
        }
        crate::persona::router::ResponseMode::Parallel => {
            run_parallel(decision, registry, provider, history, config).await
        }
        crate::persona::router::ResponseMode::Cabinet => Ok(RunnerOutput::ConveneCabinet(decision)),
    }
}

// ---------------------------------------------------------------------------
// Single execution
// ---------------------------------------------------------------------------

async fn run_single(
    decision: RouterDecision,
    registry: &PersonaRegistry,
    provider: SharedProvider,
    history: &[Message],
    config: &CallConfig,
) -> anyhow::Result<RunnerOutput> {
    let persona_id = decision
        .personas
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("RouterDecision.personas is empty for Single mode"))?;

    // Fail-closed egress gate (CF-1, PRIV-03): check before EVERY provider call.
    // Resolve name first (no payload held across lock), then tier, then gate.
    let provider_name = provider.read().await.name().to_owned();
    let tier = registry.get(&persona_id).map(|p| p.tier);
    check_egress(tier, &provider_name)?;

    // Override system prompt with the persona's system_prompt.
    let persona_system_prompt = get_system_prompt(registry, &persona_id);
    let persona_config = CallConfig {
        system_prompt: if persona_system_prompt.is_empty() {
            config.system_prompt.clone()
        } else {
            persona_system_prompt
        },
        max_tokens: config.max_tokens,
        tools: config.tools.clone(),
        ..Default::default()
    };

    let response = {
        let guard = provider.read().await;
        guard.complete(history, &persona_config).await?
    };

    Ok(RunnerOutput::Single(persona_id, response))
}

// ---------------------------------------------------------------------------
// Parallel execution (JoinSet — tagged by RETURNED PersonaId, not spawn order)
// ---------------------------------------------------------------------------

async fn run_parallel(
    decision: RouterDecision,
    registry: &PersonaRegistry,
    provider: SharedProvider,
    history: &[Message],
    config: &CallConfig,
) -> anyhow::Result<RunnerOutput> {
    let mut set: JoinSet<(PersonaId, anyhow::Result<LlmResponse>)> = JoinSet::new();

    for persona_id in decision.personas {
        let persona_system_prompt = get_system_prompt(registry, &persona_id);
        let persona_config = CallConfig {
            system_prompt: if persona_system_prompt.is_empty() {
                config.system_prompt.clone()
            } else {
                persona_system_prompt
            },
            max_tokens: config.max_tokens,
            tools: config.tools.clone(),
            ..Default::default()
        };
        let history_clone = history.to_owned();
        let provider_clone = provider.clone(); // clone Arc, not the inner value
                                               // Capture tier before spawning — registry not Send so resolve here.
        let tier = registry.get(&persona_id).map(|p| p.tier);

        set.spawn(async move {
            // Fail-closed egress gate (CF-1, PRIV-03): resolve provider name INSIDE task,
            // check before ANY provider call. Never bypass on block.
            let provider_name = provider_clone.read().await.name().to_owned();
            if let Err(e) = check_egress(tier, &provider_name) {
                return (persona_id, Err(e));
            }

            // Acquire read lock INSIDE the task — loop_.rs:118-125 pattern.
            let response = {
                let guard = provider_clone.read().await;
                guard.complete(&history_clone, &persona_config).await
            };
            // Return (persona_id, Result) — tag by THIS task's persona_id,
            // never by spawn order (T-02-07 / Pitfall 4 / CF-3).
            (persona_id, response)
        });
    }

    let mut results: Vec<(PersonaId, LlmResponse)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    // WR-12: preserve the FIRST typed egress denial so the channel boundary maps an
    // all-blocked parallel turn to 403 (not a flattened anyhow string → 500).
    let mut egress_denial: Option<anyhow::Error> = None;

    while let Some(join_result) = set.join_next().await {
        match join_result {
            Ok((pid, Ok(response))) => results.push((pid, response)),
            Ok((pid, Err(e))) => {
                tracing::warn!(persona_id = %pid, error = %e, "parallel persona call failed");
                if egress_denial.is_none()
                    && matches!(
                        e.downcast_ref::<BastionError>(),
                        Some(BastionError::PrivacyEgressBlocked)
                    )
                {
                    egress_denial = Some(e);
                } else {
                    errors.push(format!("{pid}: {e}"));
                }
            }
            Err(join_err) => {
                tracing::warn!(error = %join_err, "JoinSet task panicked");
            }
        }
    }

    if results.is_empty() {
        // Fail-closed: a typed egress denial takes precedence so it maps to 403 (WR-12).
        if let Some(e) = egress_denial {
            return Err(e);
        }
        anyhow::bail!("all parallel persona calls failed: {}", errors.join("; "));
    }

    Ok(RunnerOutput::Parallel(results))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_system_prompt(registry: &PersonaRegistry, persona_id: &str) -> String {
    registry
        .get(persona_id)
        .map(|p: &Persona| p.system_prompt.clone())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests (offline — MockProvider only, no live LLM)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PrivacyTier;
    use crate::persona::router::{ConveneReason, ResponseMode, RouterDecision};
    use crate::persona::{Persona, PersonaRegistry};
    use crate::provider::{Provider, SharedProvider};
    use crate::types::{CallConfig, LlmResponse, Message, TokenUsage};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // --- MockProvider ---
    // Echoes the persona name embedded in the config.system_prompt
    // (system prompt = "You are <name>.") so attribution tests can verify
    // each (id, response) pair is self-consistent.

    struct EchoProvider;

    #[async_trait]
    impl Provider for EchoProvider {
        async fn complete(
            &self,
            _: &[Message],
            config: &CallConfig,
        ) -> anyhow::Result<LlmResponse> {
            // Return "echo:<persona_name>" extracted from "You are <name>." in the system prompt.
            let name = config
                .system_prompt
                .lines()
                .find(|l| l.starts_with("You are "))
                .and_then(|l| l.strip_prefix("You are "))
                .and_then(|s| s.strip_suffix('.'))
                .unwrap_or("unknown");
            Ok(LlmResponse {
                text: format!("echo:{name}"),
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
            // Kept for backward-compat with other tests that use complete_simple directly.
            let name = prompt
                .lines()
                .find(|l| l.starts_with("You are "))
                .and_then(|l| l.strip_prefix("You are "))
                .and_then(|s| s.strip_suffix('.'))
                .unwrap_or("unknown");
            Ok(format!("echo:{name}"))
        }
        fn context_limit(&self) -> usize {
            8192
        }
        fn model_name(&self) -> &str {
            "echo"
        }
        fn name(&self) -> &'static str {
            "echo"
        }
    }

    fn make_provider() -> SharedProvider {
        Arc::new(RwLock::new(Box::new(EchoProvider) as Box<dyn Provider>))
    }

    fn make_registry_with(names: &[&str]) -> PersonaRegistry {
        let mut personas = HashMap::new();
        for name in names {
            personas.insert(
                name.to_string(),
                Persona {
                    name: name.to_string(),
                    description: None,
                    system_prompt: format!("You are {name}."),
                    tier: PrivacyTier::CloudOk,
                    weight: 0.5,
                    skills: vec![],
                },
            );
        }
        PersonaRegistry::new_from_map(personas)
    }

    fn make_config() -> CallConfig {
        CallConfig {
            system_prompt: "You are Bastion.".to_owned(),
            max_tokens: 256,
            tools: vec![],
            ..Default::default()
        }
    }

    fn make_history() -> Vec<Message> {
        vec![Message {
            role: crate::types::Role::User,
            content: crate::types::MessageContent::Text("hello".to_owned()),
        }]
    }

    fn single_decision(persona: &str) -> RouterDecision {
        RouterDecision {
            personas: vec![persona.to_string()],
            owner: "user1".to_string(),
            mode: ResponseMode::Single,
            convene_reason: None,
        }
    }

    fn parallel_decision(personas: &[&str]) -> RouterDecision {
        RouterDecision {
            personas: personas.iter().map(|s| s.to_string()).collect(),
            owner: "user1".to_string(),
            mode: ResponseMode::Parallel,
            convene_reason: None,
        }
    }

    fn cabinet_decision(personas: &[&str]) -> RouterDecision {
        RouterDecision {
            personas: personas.iter().map(|s| s.to_string()).collect(),
            owner: "user1".to_string(),
            mode: ResponseMode::Cabinet,
            convene_reason: Some(ConveneReason::HighWeight),
        }
    }

    // --- Tests ---

    #[tokio::test]
    async fn single_mode_returns_one_result() {
        let registry = make_registry_with(&["Aria"]);
        let provider = make_provider();
        let output = run(
            single_decision("Aria"),
            &registry,
            provider,
            &make_history(),
            &make_config(),
        )
        .await
        .expect("run failed");

        match output {
            RunnerOutput::Single(id, response) => {
                assert_eq!(id, "Aria");
                assert_eq!(response.text, "echo:Aria");
            }
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parallel_mode_returns_all_tagged_correctly() {
        // Attribution test (T-02-07 / CF-3): 3 personas in parallel; each returned
        // (id, response) pair must be self-consistent regardless of completion order.
        let names = ["Alpha", "Beta", "Gamma"];
        let registry = make_registry_with(&names);
        let provider = make_provider();
        let output = run(
            parallel_decision(&names),
            &registry,
            provider,
            &make_history(),
            &make_config(),
        )
        .await
        .expect("run failed");

        match output {
            RunnerOutput::Parallel(results) => {
                assert_eq!(results.len(), 3, "expected 3 results");
                for (id, response) in &results {
                    // Each text must echo the correct persona name, proving attribution
                    // is by returned PersonaId — not by spawn order.
                    let expected = format!("echo:{id}");
                    assert_eq!(
                        response.text, expected,
                        "attribution mismatch: persona={id} but text={}",
                        response.text
                    );
                }
            }
            other => panic!("expected Parallel, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cabinet_mode_returns_convene_sentinel() {
        let registry = make_registry_with(&["Saúde", "Aria"]);
        let provider = make_provider();
        let decision = cabinet_decision(&["Saúde", "Aria"]);
        let output = run(
            decision,
            &registry,
            provider,
            &make_history(),
            &make_config(),
        )
        .await
        .expect("run failed");

        match output {
            RunnerOutput::ConveneCabinet(d) => {
                assert_eq!(d.mode, ResponseMode::Cabinet);
                assert_eq!(d.convene_reason, Some(ConveneReason::HighWeight));
            }
            other => panic!("expected ConveneCabinet, got {other:?}"),
        }
    }

    // --- WR-12: parallel egress denial must surface as a TYPED error ---

    struct CloudProvider;

    #[async_trait]
    impl Provider for CloudProvider {
        async fn complete(&self, _: &[Message], _: &CallConfig) -> anyhow::Result<LlmResponse> {
            panic!("provider must NOT be called when egress is blocked");
        }
        async fn complete_simple(&self, _prompt: &str) -> anyhow::Result<String> {
            panic!("provider must NOT be called when egress is blocked");
        }
        fn context_limit(&self) -> usize {
            8192
        }
        fn model_name(&self) -> &str {
            "gpt-4o"
        }
        fn name(&self) -> &'static str {
            "openai"
        }
    }

    fn make_local_registry(names: &[&str]) -> PersonaRegistry {
        let mut personas = HashMap::new();
        for name in names {
            personas.insert(
                name.to_string(),
                Persona {
                    name: name.to_string(),
                    description: None,
                    system_prompt: format!("You are {name}."),
                    tier: PrivacyTier::LocalOnly,
                    weight: 0.5,
                    skills: vec![],
                },
            );
        }
        PersonaRegistry::new_from_map(personas)
    }

    #[tokio::test]
    async fn parallel_egress_block_surfaces_typed_error() {
        // All-LocalOnly personas on a cloud provider: every parallel task is egress-blocked,
        // and the runner must return a TYPED PrivacyEgressBlocked (not a flattened string) so
        // the channel boundary maps it to 403, not 500 (WR-12). Provider is never called.
        let registry = make_local_registry(&["Saúde", "Aria"]);
        let provider: SharedProvider =
            Arc::new(RwLock::new(Box::new(CloudProvider) as Box<dyn Provider>));
        let err = run(
            parallel_decision(&["Saúde", "Aria"]),
            &registry,
            provider,
            &make_history(),
            &make_config(),
        )
        .await
        .expect_err("all-blocked parallel turn must error");
        assert!(
            matches!(
                err.downcast_ref::<BastionError>(),
                Some(BastionError::PrivacyEgressBlocked)
            ),
            "expected typed PrivacyEgressBlocked, got: {err:?}"
        );
    }
}
