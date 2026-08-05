//! D-12/D-14b regression guard — long referenced from `agent/loop_.rs`'s own doc
//! comments ("`build_system_prompt_parts` (below) is the pub seam
//! `tests/prompt_cache_prefix.rs` uses...") but never actually written until now.
//!
//! Proves the actual contract a caching-aware provider (Anthropic `cache_control`)
//! depends on: `AgentLoop::build_system_prompt_with_cache_boundary` returns a byte
//! offset such that everything BEFORE it is byte-identical across turns with different
//! volatile content (e.g. a changing `turn_msg`, or a per-turn `<active_object>`
//! snapshot from a non-`is_turn_invariant` `TurnContextProvider`), and everything AFTER
//! it is free to vary. A regression here (e.g. someone reordering `context_providers`,
//! or a provider misreporting `is_turn_invariant()`) would silently make Anthropic
//! either pay full price every turn (safe but slow — not what this test catches) or
//! serve a stale volatile block from a cache hit (unsafe — what this test exists to
//! catch, by proving the boundary actually excludes volatile content, not just that it
//! returns SOME number).
//!
//! Fixture note: this integration test binary cannot reuse the kernel's own
//! `#[cfg(test)]`-gated fixtures (`agent/loop_.rs`'s `NoopMemory`/`MockResponder`/etc,
//! itself already documented there as unusable from `tests/` for the same reason) —
//! each file under `tests/` compiles as a separate crate, so those items are invisible
//! here. The minimal fixture below is a small, deliberate duplication, not a design
//! choice specific to this test.

use std::sync::Arc;

use async_trait::async_trait;
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};
use bastion_runtime::agent::loop_::AgentLoop;
use bastion_runtime::agent::ports::{
    FailureSink, ProviderResolver, Responder, ToolSource, TurnContext,
};
use bastion_runtime::capability::approval::SqliteApprovalGate;
use bastion_runtime::memory::{
    Belief, BeliefDraft, Memory, Outcome, PendingCorrection, PrivacyTier,
};
use bastion_runtime::provider::{Provider, SharedProvider};
use bastion_runtime::session::SessionManager;
use bastion_types::{CallConfig, LlmResponse, Message};
use tokio::sync::RwLock;

struct UnusedProvider;

#[async_trait]
impl Provider for UnusedProvider {
    async fn complete(&self, _: &[Message], _: &CallConfig) -> anyhow::Result<LlmResponse> {
        unreachable!("this test never drives a real turn")
    }
    async fn complete_simple(&self, _: &str) -> anyhow::Result<String> {
        unreachable!("this test never drives a real turn")
    }
    fn context_limit(&self) -> usize {
        8192
    }
    fn model_name(&self) -> &str {
        "unused"
    }
    fn name(&self) -> &'static str {
        "unused"
    }
}

struct UnusedResponder;

#[async_trait]
impl Responder for UnusedResponder {
    async fn respond(
        &self,
        _turn: TurnContext<'_>,
    ) -> anyhow::Result<bastion_runtime::agent::ports::RespondOutcome> {
        unreachable!("this test never drives a real turn")
    }
}

struct EmptyToolSource;

#[async_trait]
impl ToolSource for EmptyToolSource {
    async fn tool_defs(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        Ok(vec![])
    }
    async fn call_tool_with_timeout(
        &self,
        name: &str,
        _args: serde_json::Value,
        _owner: &str,
        _resolved_tier: Option<PrivacyTier>,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::bail!("EmptyToolSource has no tool '{name}'")
    }
}

struct NoopFailureSink;

impl FailureSink for NoopFailureSink {
    fn record_failure(
        &self,
        _kind: bastion_types::FailureKind,
        _tier: Option<PrivacyTier>,
        _detail: &str,
    ) {
    }
}

struct UnreachableResolver;

impl ProviderResolver for UnreachableResolver {
    fn resolve(&self, model: &str) -> anyhow::Result<Box<dyn Provider>> {
        anyhow::bail!("no resolver scripted for '{model}'")
    }
}

struct NoopMemory;

#[async_trait]
impl Memory for NoopMemory {
    async fn store_belief(
        &self,
        _owner_id: &str,
        _persona_tag: Option<&str>,
        _content: &str,
        _session_id: &str,
        _source: &str,
        _is_core: bool,
        _tier: Option<PrivacyTier>,
    ) -> anyhow::Result<i64> {
        Ok(1)
    }
    async fn retrieve_tagged(
        &self,
        _owner_id: &str,
        _persona_tag: Option<&str>,
    ) -> anyhow::Result<Vec<Belief>> {
        Ok(vec![])
    }
    async fn revoke_belief(&self, _owner_id: &str, _id: i64) -> anyhow::Result<()> {
        Ok(())
    }
    async fn supersede_belief(
        &self,
        _owner_id: &str,
        _old_id: i64,
        _new_id: i64,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn load_core(&self, _owner_id: &str) -> anyhow::Result<Vec<Belief>> {
        Ok(vec![])
    }
    async fn retrieve_all_beliefs(&self, _owner_id: &str) -> anyhow::Result<Vec<Belief>> {
        Ok(vec![])
    }
    async fn provenance_for(
        &self,
        _owner_id: &str,
        _belief_id: i64,
    ) -> anyhow::Result<Vec<(String, String)>> {
        Ok(vec![])
    }
    async fn store_procedural_belief(&self, _draft: BeliefDraft) -> anyhow::Result<i64> {
        Ok(1)
    }
    async fn record_belief_outcome(
        &self,
        _owner_id: &str,
        _id: i64,
        _outcome: Outcome,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn reinforce_belief(&self, _owner_id: &str, _id: i64, _delta: f64) -> anyhow::Result<()> {
        Ok(())
    }
    async fn evaporate_beliefs(
        &self,
        _owner_id: &str,
        _factor: f64,
        _floor: f64,
    ) -> anyhow::Result<u64> {
        Ok(0)
    }
    async fn reinforce_persona_belief(
        &self,
        _owner_id: &str,
        _id: i64,
        _delta: f64,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn weaken_persona_belief(
        &self,
        _owner_id: &str,
        _id: i64,
        _delta: f64,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn record_pending_correction(
        &self,
        _owner_id: &str,
        _belief_id: i64,
        _tier: Option<PrivacyTier>,
    ) -> anyhow::Result<i64> {
        Ok(1)
    }
    async fn take_pending_corrections(
        &self,
        _owner_id: &str,
    ) -> anyhow::Result<Vec<PendingCorrection>> {
        Ok(vec![])
    }
}

fn make_provider() -> SharedProvider {
    Arc::new(RwLock::new(Box::new(UnusedProvider) as Box<dyn Provider>))
}

async fn make_loop(db_path: &str) -> AgentLoop {
    let session = SessionManager::new(db_path);
    session.init_schema().await.expect("init_schema");
    let session_id = session.create_session().await.expect("create_session");
    let memory = Arc::new(RwLock::new(Box::new(NoopMemory) as Box<dyn Memory>));

    AgentLoop::new(
        make_provider(),
        session,
        Arc::new(EmptyToolSource),
        session_id,
        10.0,
        Arc::new(UnusedResponder),
        memory,
        None,
        vec![],
        Arc::new(SqliteApprovalGate::new(db_path)),
        Arc::new(NoopFailureSink),
        vec![], // context_providers populated per-test via add_context_provider
        Arc::new(UnreachableResolver),
        None,
        None,
    )
}

/// Fixed content, ignores `turn_msg` — the "IdentityProvider-shaped" case.
struct StableProvider {
    content: &'static str,
}

#[async_trait]
impl TurnContextProvider for StableProvider {
    async fn context_for_turn(
        &self,
        _owner: &str,
        _turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        vec![ContextBlock {
            content: self.content.to_string(),
            max_tier: PrivacyTier::CloudOk,
        }]
    }
    fn is_turn_invariant(&self) -> bool {
        true
    }
}

/// Content echoes `turn_msg` — the "active_object snapshot" case: legitimately
/// different every turn, must never be mistaken for stable.
struct VolatileProvider;

#[async_trait]
impl TurnContextProvider for VolatileProvider {
    async fn context_for_turn(
        &self,
        _owner: &str,
        turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        vec![ContextBlock {
            content: format!("<active_object turn=\"{turn_msg}\"/>"),
            max_tier: PrivacyTier::CloudOk,
        }]
    }
    // Default `is_turn_invariant() == false` — deliberately not overridden.
}

#[tokio::test]
async fn stable_prefix_is_byte_identical_across_turns_with_different_volatile_content() {
    let f = tempfile::NamedTempFile::new().unwrap();
    let db_path = f.path().to_str().unwrap().to_owned();
    let mut agent = make_loop(&db_path).await;

    agent.add_context_provider(Box::new(StableProvider {
        content: "You are Bastion.",
    }));
    agent.add_context_provider(Box::new(VolatileProvider));

    let (prompt_turn_1, boundary_1) = agent
        .build_system_prompt_with_cache_boundary("owner-a", "what's the weather", None)
        .await;
    let (prompt_turn_2, boundary_2) = agent
        .build_system_prompt_with_cache_boundary("owner-a", "tell me a joke instead", None)
        .await;

    assert_eq!(
        boundary_1, boundary_2,
        "the stable-prefix boundary must not move across turns for the same provider set"
    );
    assert!(
        boundary_1 > 0 && boundary_1 < prompt_turn_1.len(),
        "boundary must be a real interior split point, got {boundary_1} of {}",
        prompt_turn_1.len()
    );

    // The actual D-14b guarantee: everything BEFORE the boundary is byte-identical...
    assert_eq!(
        &prompt_turn_1[..boundary_1],
        &prompt_turn_2[..boundary_2],
        "stable prefix changed across turns — a caching-aware provider would silently \
         serve stale content from a cache hit"
    );
    // ...and everything AFTER it actually did change (proving the volatile block landed
    // AFTER the boundary, not that the boundary happens to be the whole string by
    // accident).
    assert_ne!(
        &prompt_turn_1[boundary_1..],
        &prompt_turn_2[boundary_2..],
        "volatile suffix must actually vary by turn, or this test would prove nothing"
    );

    // Concretely: the stable part is exactly the DEFAULT_SYSTEM_PROMPT + StableProvider's
    // block, and the volatile part carries the CURRENT turn's active_object content only.
    assert!(prompt_turn_1[..boundary_1].contains("You are Bastion."));
    assert!(!prompt_turn_1[..boundary_1].contains("what's the weather"));
    assert!(prompt_turn_1[boundary_1..].contains("what's the weather"));
    assert!(prompt_turn_2[boundary_2..].contains("tell me a joke instead"));
}

#[tokio::test]
async fn a_volatile_provider_before_a_stable_one_caps_the_boundary_at_its_position() {
    let f = tempfile::NamedTempFile::new().unwrap();
    let db_path = f.path().to_str().unwrap().to_owned();
    let mut agent = make_loop(&db_path).await;

    // Deliberately out of the "documented safe order" — volatile first, stable second —
    // to prove the boundary tracks ACTUAL provider order, not a hardcoded assumption.
    agent.add_context_provider(Box::new(VolatileProvider));
    agent.add_context_provider(Box::new(StableProvider {
        content: "You are Bastion.",
    }));

    let (prompt, boundary) = agent
        .build_system_prompt_with_cache_boundary("owner-a", "hello", None)
        .await;

    // Only DEFAULT_SYSTEM_PROMPT (index 0) is stable here — the volatile provider at
    // index 1 caps the boundary before the later stable provider ever gets a chance to
    // extend it, exactly as documented on `build_context_parts_for_destination`.
    assert!(
        !prompt[..boundary].contains("You are Bastion."),
        "a stable provider AFTER a volatile one must not be folded into the stable prefix"
    );
}

#[tokio::test]
async fn no_context_providers_still_returns_a_usable_boundary_over_the_default_prompt_alone() {
    let f = tempfile::NamedTempFile::new().unwrap();
    let db_path = f.path().to_str().unwrap().to_owned();
    let agent = make_loop(&db_path).await;

    let (prompt, boundary) = agent
        .build_system_prompt_with_cache_boundary("owner-a", "hello", None)
        .await;

    assert_eq!(boundary, prompt.len());
}
