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
}

impl PersonaResponder {
    /// Build a responder over `registry` — the SAME `PersonaRegistry` that
    /// used to live on `AgentLoop.registry`.
    pub fn new(registry: PersonaRegistry) -> Self {
        Self { registry }
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
        let system_prompt = kernel
            .build_system_prompt(owner, user_input, turn_persona)
            .await;
        let tools = kernel.capability_registry().list_tool_defs();
        let config = CallConfig {
            system_prompt, // ← dinâmico via SEAM #2
            max_tokens: 4096,
            tools,
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
                let text = kernel
                    .run_tool_loop(history, session_id, &config, response, owner, resolved_tier)
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
                    let text = kernel
                        .run_tool_loop(history, session_id, &config, response, owner, resolved_tier)
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
            user_input,
            untrusted,
            forced_persona,
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

        if let Some(forced) = forced_persona {
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
                let table = crate::cabinet::build_table(
                    |name| self.registry.get(name).cloned(),
                    &decision,
                    None,
                )?;
                let transcript = crate::cabinet::orchestrator::deliberate(
                    &table,
                    provider.clone(),
                    crate::cabinet::orchestrator::DEFAULT_ROUNDS,
                    kernel.capability_registry(),
                )
                .await?;
                // CR-02: fail-closed egress on synthesis — the transcript may contain LocalOnly
                // content. Gate synthesis on the table tier before touching the cloud provider.
                let synth_provider_name = provider.read().await.name().to_owned();
                crate::hooks::egress::check_egress(Some(table.tier), &synth_provider_name)?;
                let provider_ref = provider.read().await;
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
        })
    }
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
