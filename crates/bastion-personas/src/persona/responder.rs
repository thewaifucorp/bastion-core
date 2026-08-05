//! [`Responder`] port implementation — persona routing, single/parallel
//! dispatch, and Cabinet deliberation (M2 P1).
//!
//! Moved verbatim from `agent/loop_.rs`'s `run_turn_for_with_trust` (the
//! routing/dispatch section), `dispatch_single_or_parallel`, and the private
//! `render_verdict` helper — only the borrow shape changed (`self.foo` on
//! `AgentLoop` becomes `turn.kernel`/`turn.provider`/`self.registry` on
//! `PersonaResponder`), never the logic itself. `PersonaRegistry` moved here
//! from the `AgentLoop` struct too — it is this module's own field now.

use opentelemetry::trace::Span as _;
use std::collections::HashSet;
use std::sync::Arc;

use crate::agent::ports::{RespondOutcome, Responder, TurnContext, TurnKernel};
use crate::persona::PersonaRegistry;
use crate::provider::SharedProvider;
use crate::types::{CallConfig, Message, MessageContent, Role};

/// The production [`Responder`]: classifies the turn via `persona::router`,
/// then dispatches Single/Parallel (via `persona::runner`) or convenes the
/// Cabinet (via `cabinet::{build_table, orchestrator, synth}`), exactly as
/// `AgentLoop::run_turn_for_with_trust` did inline before this port.
pub struct PersonaResponder {
    registry: PersonaRegistry,
    /// CAB-01..04: optional dedicated provider for the Cabinet's legs
    /// (`orchestrator::deliberate`) AND its synthesis call
    /// (`cabinet::synth::synthesize`) — distinct from the turn's
    /// conversational `provider` above. `None` (the default, set via
    /// `PersonaResponder::new`, never a constructor parameter — same
    /// "set post-construction" discipline as `AgentLoop::compaction_provider`)
    /// preserves today's exact behavior: Cabinet uses the live turn
    /// `provider`. Opt in via [`PersonaResponder::with_cabinet_provider`].
    cabinet_provider: Option<SharedProvider>,
}

impl PersonaResponder {
    /// Build a responder over `registry` — the SAME `PersonaRegistry` that
    /// used to live on `AgentLoop.registry`.
    pub fn new(registry: PersonaRegistry) -> Self {
        Self {
            registry,
            cabinet_provider: None,
        }
    }

    /// CAB-01: opt into a dedicated provider for the Cabinet's legs and
    /// synthesis call, distinct from the turn's conversational `provider`.
    /// Without this call, Cabinet uses the live turn `provider`,
    /// byte-identical to pre-seam behavior (CAB-02). Swapping this provider
    /// never affects an in-progress or future `chat_turn` call (CAB-03) —
    /// the turn's own `provider` handle is untouched.
    pub fn with_cabinet_provider(mut self, provider: SharedProvider) -> Self {
        self.cabinet_provider = Some(provider);
        self
    }

    /// CAB-02/03: the SINGLE provider resolution both the Cabinet's legs
    /// (`orchestrator::deliberate`) and its synthesis/egress-gate call read
    /// from — extracted as one pure method so both call sites are
    /// structurally guaranteed to agree (CAB-04: the gate can never check a
    /// different provider than the one synthesis actually calls), and so
    /// the resolution rule itself is unit-testable without standing up a
    /// full `TurnContext`/`TurnKernel` harness (nothing in this crate does
    /// today — `Responder::respond` is only exercised via `AgentLoop`
    /// integration tests in `bastion-runtime`).
    fn effective_cabinet_provider(&self, turn_provider: &SharedProvider) -> SharedProvider {
        self.cabinet_provider
            .clone()
            .unwrap_or_else(|| turn_provider.clone())
    }

    /// Single/Parallel path via runner (BIG-1) — extracted from `respond` so
    /// its caller can wrap the WHOLE call (including where `config.tools` is
    /// snapshotted from `capability_registry`) in a quarantine window (SEC-05)
    /// via `drain_all()`/`restore()` around the call.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_single_or_parallel(
        &self,
        kernel: &mut dyn TurnKernel,
        provider: SharedProvider,
        decision: crate::persona::router::RouterDecision,
        history: &mut Vec<Message>,
        session_id: &str,
        owner: &str,
        user_input: &str,
        turn_persona: Option<&str>,
    ) -> anyhow::Result<String> {
        // Build CallConfig with tools from capability_registry (BIG-1).
        // SEAM #2: system_prompt built dynamically — context_providers inject opaque blocks.
        // D-12/D-14b: cache_stable_prefix_end lets a caching-aware provider (Anthropic)
        // avoid re-sending/re-caching the turn-invariant prefix every turn.
        let (system_prompt, stable_prefix_end) = kernel
            .build_system_prompt_with_cache_boundary(owner, user_input, turn_persona)
            .await;
        let tools = kernel.capability_registry().list_tool_defs();
        let config = CallConfig {
            system_prompt, // ← dinâmico via SEAM #2
            max_tokens: 4096,
            tools,
            cache_stable_prefix_end: Some(stable_prefix_end),
            ..Default::default()
        };

        let output = crate::persona::runner::run(
            decision,
            &self.registry,
            provider,
            history.as_slice(),
            &config,
        )
        .await?;

        // Process tool_calls if present via the kernel's tool loop (BIG-1).
        Ok(match output {
            crate::persona::runner::RunnerOutput::Single(pid, response) => {
                // WR-04 / CR-01: resolve PrivacyTier from the persona actually
                // handling this turn (router-chosen or /as-forced). Re-reading
                // the kernel's forced_persona here would be a privacy bug: it
                // was already consumed by `.take()` before this Responder was
                // called, so a forced LocalOnly persona would resolve to None
                // and get stamped CloudOk — a LocalOnly→cloud downgrade.
                let resolved_tier: Option<crate::memory::PrivacyTier> =
                    self.registry.get(&pid).map(|p| p.tier);
                // Persona contract v2 (Policy 0): resolve the SAME persona's
                // `tools:` allowlist alongside its tier, from the same
                // `self.registry.get(&pid)` lookup already used above. `None`
                // (no `tools:` declared, or persona not found) stays
                // unrestricted — the legacy/back-compat contract.
                let allowed_tools: Option<Arc<HashSet<String>>> =
                    resolve_allowed_tools(self.registry.get(&pid));
                let text = kernel
                    .run_tool_loop(
                        history,
                        session_id,
                        &config,
                        response,
                        owner,
                        resolved_tier,
                        allowed_tools,
                    )
                    .await?;
                // Persist the assistant response (run_tool_loop handles intermediate turns)
                kernel
                    .session_append(
                        session_id,
                        Message {
                            role: Role::Assistant,
                            content: MessageContent::Text(text.clone()),
                        },
                        None,
                    )
                    .await?;
                text
            }
            crate::persona::runner::RunnerOutput::Parallel(results) => {
                // Parallel: run tool-loop for each persona result and collect texts.
                let mut texts: Vec<String> = Vec::new();
                for (pid, response) in results {
                    // CR-01: resolve tier per-persona — each parallel persona may
                    // carry a different tier. fail-closed via check_egress inside
                    // the kernel's tool loop (None → blocked, not defaulted to cloud).
                    let resolved_tier: Option<crate::memory::PrivacyTier> =
                        self.registry.get(&pid).map(|p| p.tier);
                    // Persona contract v2 (Policy 0): same per-persona resolution
                    // as the Single-dispatch branch above — each parallel
                    // persona may carry a different `tools:` allowlist.
                    let allowed_tools: Option<Arc<HashSet<String>>> =
                        resolve_allowed_tools(self.registry.get(&pid));
                    let text = kernel
                        .run_tool_loop(
                            history,
                            session_id,
                            &config,
                            response,
                            owner,
                            resolved_tier,
                            allowed_tools,
                        )
                        .await?;
                    texts.push(text);
                }
                let combined = texts.join("\n\n");
                kernel
                    .session_append(
                        session_id,
                        Message {
                            role: Role::Assistant,
                            content: MessageContent::Text(combined.clone()),
                        },
                        None,
                    )
                    .await?;
                combined
            }
            crate::persona::runner::RunnerOutput::ConveneCabinet(_) => String::new(),
        })
    }
}

#[async_trait::async_trait]
impl Responder for PersonaResponder {
    async fn respond(&self, turn: TurnContext<'_>) -> anyhow::Result<RespondOutcome> {
        let TurnContext {
            provider,
            kernel,
            history,
            session_id,
            owner,
            deployment: _,
            user_input,
            untrusted,
            forced_persona,
            forced_cabinet,
            turn_span,
        } = turn;

        // 4. Router — classify the message into a RouterDecision.
        //    If /as forced a persona, override the router's choice.
        let mut decision = {
            let provider_ref = provider.read().await;
            crate::persona::router::route(
                &**provider_ref,
                &self.registry,
                user_input,
                owner,
                kernel.capability_registry(),
            )
            .await?
        };

        if let Some(personas) = forced_cabinet {
            decision.personas = personas;
            decision.mode = crate::persona::router::ResponseMode::Cabinet;
        } else if let Some(forced) = forced_persona {
            decision.personas = vec![forced.clone()];
            decision.mode = crate::persona::router::ResponseMode::Single;
            decision.convene_reason = None;
        }

        // SEAM #4: registrar persona no span raiz via atributo (span name é imutável).
        // Após routing — persona é conhecida agora.
        let agent_name = decision
            .personas
            .first()
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        turn_span.set_attribute(opentelemetry::KeyValue::new(
            "gen_ai.agent.name",
            agent_name,
        ));

        // WR-01 (review #2): capture the turn's privacy tier from the handling persona
        // ONCE, before `decision` is moved into the dispatch match below. Threaded into
        // `RespondOutcome.turn_tier` so the kernel's fallback path no longer re-reads
        // an already-taken forced_persona (collapsed to None — over-blocked a forced
        // CloudOk persona and relied on accidental fail-closed for LocalOnly). None
        // stays fail-closed.
        let turn_tier: Option<crate::memory::PrivacyTier> = decision
            .personas
            .first()
            .and_then(|name| self.registry.get(name).map(|p| p.tier));

        // Same resolution as turn_tier, same reason: this is threaded into
        // `RespondOutcome.allowed_tools` so `run_provider_fallback` (reached
        // when route_text ends up empty but a persona is still attributed to
        // the turn) enforces this persona's Policy 0 tool-authority contract
        // instead of running unrestricted. Reuses the same helper the
        // single/parallel dispatch path below already calls per-persona.
        let fallback_allowed_tools: Option<Arc<HashSet<String>>> = decision
            .personas
            .first()
            .and_then(|name| resolve_allowed_tools(self.registry.get(name)));

        // SEAM #2: the active persona name scopes belief recall (persona-tagged + global).
        // Resolved ONCE here (like turn_tier) and threaded into build_system_prompt on the
        // single/parallel path, so recall never crosses persona boundaries. `None` (no
        // persona matched) keeps global-only recall — the fail-safe. Also doubles as
        // `RespondOutcome.attribution` — the kernel's fallback path derives its own
        // `turn_persona` from `attribution.first()`.
        let turn_persona: Option<String> = decision.personas.first().cloned();
        let attribution = decision.personas.clone();

        // 5. Dispatch on decision.mode → build response text.
        //    Empty registry → route_text will be empty → kernel falls back to provider.
        let route_text = match decision.mode {
            crate::persona::router::ResponseMode::Cabinet => {
                // Cabinet path: build_table → deliberate → synthesize (D-07 unified voice + dissent)
                // M2 step 6: `build_table` takes a lookup closure, not `&PersonaRegistry`
                // directly (see its doc comment) — this crate owns the registry and
                // resolves names itself, so `bastion-cognition`'s Cabinet never depends
                // on `bastion-personas`.
                //
                // CAB-01..04: every provider use below reads `cabinet_provider`
                // (falling back to the turn's own `provider`), never `provider`
                // directly — this is the ONLY branch that may observe the
                // override; `chat_turn`'s own dispatch (the `_` arm below)
                // always uses `provider` unconditionally, so swapping
                // `cabinet_provider` can never re-route a chat turn.
                let table = crate::cabinet::build_table(
                    |name| self.registry.get(name).cloned(),
                    &decision,
                    None,
                )?;
                let cabinet_provider = self.effective_cabinet_provider(&provider);
                let transcript = crate::cabinet::orchestrator::deliberate(
                    &table,
                    cabinet_provider.clone(),
                    crate::cabinet::orchestrator::DEFAULT_ROUNDS,
                    kernel.capability_registry(),
                    user_input,
                )
                .await?;
                // CR-02: fail-closed egress on synthesis — the transcript may contain LocalOnly
                // content. Gate synthesis on the table tier before touching the cloud provider.
                // CAB-04: gated against the EFFECTIVE provider (the Cabinet
                // override when configured), never the turn's `provider` —
                // the gate must see the same provider synthesis is about to
                // call, or a permissive chat_turn provider could paper over
                // a stricter Cabinet provider's egress posture.
                let synth_provider_name = cabinet_provider.read().await.name().to_owned();
                crate::hooks::egress::check_egress(Some(table.tier), &synth_provider_name)?;
                let provider_ref = cabinet_provider.read().await;
                let verdict = crate::cabinet::synth::synthesize(
                    &**provider_ref,
                    &transcript,
                    kernel.capability_registry(),
                )
                .await?;
                drop(provider_ref);
                render_verdict(&verdict)
            }
            _ => {
                // SEC-05/D-09: when this turn's input is untrusted (received email
                // content; a public-channel Discord/Slack message), the ENTIRE
                // Single/Parallel dispatch section below — including where
                // `config.tools` is snapshotted from `capability_registry` — runs
                // with every pre-existing capability genuinely drained/invisible.
                //
                // `drain_all()`/`restore()` (via `kernel.capability_registry()`)
                // achieve the identical guarantee (genuinely empty for the call's
                // duration, fully restored after); restoration happens whether the
                // call returns `Ok` or `Err`, exactly like a RAII guard would.
                if untrusted {
                    let backup = kernel.capability_registry().drain_all();
                    let result = self
                        .dispatch_single_or_parallel(
                            kernel,
                            provider.clone(),
                            decision,
                            history,
                            session_id,
                            owner,
                            user_input,
                            turn_persona.as_deref(),
                        )
                        .await;
                    kernel.capability_registry().restore(backup);
                    result?
                } else {
                    self.dispatch_single_or_parallel(
                        kernel,
                        provider.clone(),
                        decision,
                        history,
                        session_id,
                        owner,
                        user_input,
                        turn_persona.as_deref(),
                    )
                    .await?
                }
            }
        };

        Ok(RespondOutcome {
            text: route_text,
            attribution,
            turn_tier,
            allowed_tools: fallback_allowed_tools,
        })
    }
}

// ---------------------------------------------------------------------------
// Persona contract v2 helpers
// ---------------------------------------------------------------------------

/// Resolve a persona's contract v2 `tools:` allowlist into the
/// `Option<Arc<HashSet<String>>>` shape `InvokeCtx`/`TurnKernel::run_tool_loop`
/// expect. `None` — either the persona wasn't found in the registry, or it
/// declared no `tools:` at all (pre-contract-v2 / explicitly unrestricted) —
/// stays unrestricted, never treated as "deny everything".
fn resolve_allowed_tools(persona: Option<&bastion_types::Persona>) -> Option<Arc<HashSet<String>>> {
    persona
        .and_then(|p| p.tools.as_ref())
        .map(|list| Arc::new(list.iter().cloned().collect::<HashSet<String>>()))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

fn render_verdict(verdict: &crate::cabinet::synth::CabinetVerdict) -> String {
    let mut out = verdict.recommendation.clone();
    if !verdict.dissents.is_empty() {
        out.push_str("\n\n**Dissenting views:**");
        for d in &verdict.dissents {
            out.push_str(&format!("\n- {}: {}", d.persona, d.position));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests (CAB-01..04) — offline, mock providers only.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;
    use crate::types::{LlmResponse, TokenUsage};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    /// A provider identified only by its `name()` — enough to prove WHICH
    /// provider a call site actually used, without needing a real LLM.
    struct NamedProvider(&'static str);

    #[async_trait]
    impl Provider for NamedProvider {
        async fn complete(&self, _: &[Message], _: &CallConfig) -> anyhow::Result<LlmResponse> {
            Ok(LlmResponse {
                text: format!("from:{}", self.0),
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
        async fn complete_simple(&self, _: &str) -> anyhow::Result<String> {
            Ok(format!("from:{}", self.0))
        }
        fn context_limit(&self) -> usize {
            8192
        }
        fn model_name(&self) -> &str {
            self.0
        }
        fn name(&self) -> &'static str {
            self.0
        }
    }

    fn named_provider(name: &'static str) -> SharedProvider {
        Arc::new(RwLock::new(
            Box::new(NamedProvider(name)) as Box<dyn Provider>
        ))
    }

    fn make_registry() -> PersonaRegistry {
        PersonaRegistry::new_from_map(HashMap::new())
    }

    /// CAB-02: without `with_cabinet_provider`, the effective provider IS
    /// the turn's own provider — byte-identical to pre-seam behavior.
    #[tokio::test]
    async fn without_cabinet_provider_falls_back_to_the_turn_provider() {
        let responder = PersonaResponder::new(make_registry());
        let turn_provider = named_provider("chat");

        let effective = responder.effective_cabinet_provider(&turn_provider);

        assert_eq!(effective.read().await.name(), "chat");
    }

    /// CAB-01/03: with `with_cabinet_provider` configured, the effective
    /// provider is the Cabinet override — NOT the turn's provider — proving
    /// the two are genuinely distinct handles (swapping one can never
    /// re-route the other).
    #[tokio::test]
    async fn with_cabinet_provider_overrides_the_turn_provider() {
        let cabinet = named_provider("cabinet-mock-a");
        let chat = named_provider("chat-mock-b");
        let responder = PersonaResponder::new(make_registry()).with_cabinet_provider(cabinet);

        let effective = responder.effective_cabinet_provider(&chat);

        assert_eq!(
            effective.read().await.name(),
            "cabinet-mock-a",
            "Cabinet must use its own configured provider, not the turn's"
        );
        // The turn's own handle is untouched — a concurrent/subsequent
        // chat_turn call reading `chat` directly still sees "chat-mock-b".
        assert_eq!(chat.read().await.name(), "chat-mock-b");
    }

    /// CAB-04 (structural guarantee): `respond`'s Cabinet arm computes
    /// `cabinet_provider` exactly once via `effective_cabinet_provider` and
    /// reuses that SAME local for both the egress gate
    /// (`check_egress(Some(table.tier), &synth_provider_name)`) and the
    /// `synthesize` call — so a persona whose tier the Cabinet provider's
    /// name rejects is blocked before synthesis ever runs, regardless of
    /// what the turn's own (possibly more permissive) provider would have
    /// allowed. This test pins the mechanism the code review must be able
    /// to see with a one-line diff, rather than re-deriving it: both reads
    /// in the Cabinet arm come from the identical resolved value.
    #[tokio::test]
    async fn effective_provider_resolution_is_a_single_source_of_truth() {
        let cabinet = named_provider("cabinet-strict");
        let responder = PersonaResponder::new(make_registry()).with_cabinet_provider(cabinet);
        let turn_provider = named_provider("chat-permissive");

        // Two independent resolutions from the same responder/turn pair
        // must agree — this is what guarantees the egress gate and the
        // synthesize call can never observe different providers.
        let first = responder.effective_cabinet_provider(&turn_provider);
        let second = responder.effective_cabinet_provider(&turn_provider);
        assert_eq!(first.read().await.name(), second.read().await.name());
        assert_eq!(first.read().await.name(), "cabinet-strict");
    }
}
