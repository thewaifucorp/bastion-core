//! `minimal-agent` — the smallest complete Bastion turn, built ONLY from
//! substrate crates (`bastion-types`, `bastion-runtime`, `bastion-memory`) —
//! never the product package `bastion`; see `docs/ARCHITECTURE.md`.
//!
//! Runs fully offline: a `MockProvider` stands in for a real LLM, a
//! `SqliteMemory` in a temp directory stands in for a persisted install, and
//! every optional kernel port (goals, tool source, pre-compaction flush,
//! tool-result observer) is either `None` or a trivial "does nothing"
//! implementation. `AgentLoop::run_turn_for` still runs the REAL kernel
//! machinery around that — input guardrail, session persistence, budget
//! accounting, output validation — this is not a fake loop, just a minimal
//! composition of the real one.
//!
//! `cargo run -p minimal-agent` exits 0 and prints the mock reply.

use std::sync::Arc;

use async_trait::async_trait;
use bastion_memory::sqlite::SqliteMemory;
use bastion_memory::{Memory, SharedMemory};
use bastion_runtime::agent::loop_::{AgentLoop, DEFAULT_OWNER};
use bastion_runtime::agent::ports::{
    FailureSink, ProviderResolver, RespondOutcome, Responder, ToolSource, TurnContext,
};
use bastion_runtime::capability::approval::SqliteApprovalGate;
use bastion_runtime::memory::PrivacyTier;
use bastion_runtime::provider::{Provider, SharedProvider};
use bastion_runtime::session::SessionManager;
use bastion_runtime::types::{CallConfig, LlmResponse, Message, TokenUsage};
use bastion_types::FailureKind;
use tokio::sync::RwLock;

/// The whole "model": echoes a canned reply. No network I/O, no credentials.
struct MockProvider;

#[async_trait]
impl Provider for MockProvider {
    async fn complete(
        &self,
        _messages: &[Message],
        _config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        Ok(LlmResponse {
            text: "Hello from minimal-agent!".to_string(),
            tool_calls: None,
            usage: TokenUsage::default(),
        })
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        Ok(format!("Hello from minimal-agent! (you said: {prompt})"))
    }

    fn context_limit(&self) -> usize {
        // Large enough that AutoCompact never triggers for this one-shot demo.
        1_000_000
    }

    fn model_name(&self) -> &str {
        "mock-minimal"
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

/// The whole "responder": no persona routing, no Cabinet deliberation — just
/// calls the injected provider once and returns its text. This is the
/// `Responder` port's minimum viable implementation.
struct EchoResponder;

#[async_trait]
impl Responder for EchoResponder {
    async fn respond(&self, turn: TurnContext<'_>) -> anyhow::Result<RespondOutcome> {
        let text = turn
            .provider
            .read()
            .await
            .complete_simple(turn.user_input)
            .await?;
        Ok(RespondOutcome {
            text,
            attribution: vec!["minimal-agent".to_string()],
            turn_tier: Some(PrivacyTier::CloudOk),
        })
    }
}

/// No external tools in this example — the port must still be supplied, but
/// nothing here ever calls it (the mock response never carries `tool_calls`).
struct NoTools;

#[async_trait]
impl ToolSource for NoTools {
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
        anyhow::bail!("minimal-agent example registers no external tools (requested: {name})")
    }
}

/// Discards failure signals — this example has no eval/regression harness to
/// feed.
struct NoopFailureSink;

impl FailureSink for NoopFailureSink {
    fn record_failure(&self, _kind: FailureKind, _tier: Option<PrivacyTier>, _detail: &str) {}
}

/// Never invoked in this example (no provider-switch fallback ladder is
/// exercised by a single successful mock turn) — fails loudly if it ever is,
/// rather than silently returning something surprising.
struct UnusedResolver;

impl ProviderResolver for UnusedResolver {
    fn resolve(&self, model: &str) -> anyhow::Result<Box<dyn Provider>> {
        anyhow::bail!(
            "minimal-agent example never resolves a provider by name (requested: {model})"
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A fresh SQLite file per run — no state survives the process, no
    // network I/O anywhere in this example.
    let dir = tempfile::tempdir()?;
    let db_path = dir
        .path()
        .join("minimal-agent.sqlite3")
        .to_str()
        .expect("temp path is valid UTF-8")
        .to_string();

    let session = SessionManager::new(db_path.clone());
    session.init_schema().await?;
    let session_id = session.create_session().await?;

    let memory: SharedMemory = Arc::new(RwLock::new(
        Box::new(SqliteMemory::new(&db_path)) as Box<dyn Memory>
    ));
    let provider: SharedProvider =
        Arc::new(RwLock::new(Box::new(MockProvider) as Box<dyn Provider>));

    let mut agent = AgentLoop::new(
        provider,
        SessionManager::new(db_path.clone()),
        Arc::new(NoTools),
        session_id,
        1.0, // daily_budget_usd — irrelevant, "mock" is never budget-checked
        Arc::new(EchoResponder),
        memory,
        None,   // no goal engine
        vec![], // no fallback models
        Arc::new(SqliteApprovalGate::new(db_path.clone())),
        Arc::new(NoopFailureSink),
        vec![], // no injected context blocks
        Arc::new(UnusedResolver),
        None, // no pre-compaction flush
        None, // no tool-result observer
    );

    let reply = agent.run_turn_for("hello", DEFAULT_OWNER).await?;
    println!("{reply}");

    Ok(())
}
