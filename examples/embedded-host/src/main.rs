//! `embedded-host` — the "second consumer" seam (docs/revamp/BACKLOG.md M5,
//! `docs/revamp/M1-ADR-substrate-split.md`), built ONLY from substrate crates
//! (`bastion-types`, `bastion-runtime`, `bastion-memory`) — never the product
//! package `bastion`.
//!
//! Demonstrates the three things an embedding host actually needs from the
//! public API:
//!
//! 1. **Opaque context injection** — a custom `TurnContextProvider` adds a
//!    block the kernel concatenates without interpreting (SEAM #2).
//! 2. **A custom capability, registered through the public
//!    `CapabilityRegistry` API** — no fork of the registry, no product code.
//! 3. **An authorization policy that denies an action, through the host's OWN
//!    `ApprovalGate`** — Ciclo 2.1 (`docs/revamp/C2-approval-port-design.md`)
//!    closed the API gap M3 found here (`AgentLoop::new` used to hardwire its
//!    own SQLite queue with no opt-out, and a denial was indistinguishable
//!    from "still pending"): the host now injects `ThresholdDenyGate` — its
//!    OWN `ApprovalGate` impl, no SQLite at all — into `AgentLoop::new`, and
//!    observes a typed `Err(BastionError::ApprovalDenied)` from `invoke()`.
//!    See `demonstrate_denied_capability` below.
//!
//! Fully offline (mock provider, temp-dir SQLite for session/memory only —
//! the approval gate itself needs no database). `cargo run -p embedded-host`
//! exits 0.

use std::sync::Arc;

use async_trait::async_trait;
use bastion_memory::sqlite::SqliteMemory;
use bastion_memory::{Memory, SharedMemory};
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};
use bastion_runtime::agent::loop_::{AgentLoop, DEFAULT_OWNER};
use bastion_runtime::agent::ports::{
    ApprovalGate, FailureSink, ProviderResolver, RespondOutcome, Responder, ToolSource, TurnContext,
};
use bastion_runtime::capability::{Capability, InvokeCtx};
use bastion_runtime::memory::PrivacyTier;
use bastion_runtime::provider::{Provider, SharedProvider};
use bastion_runtime::session::SessionManager;
use bastion_runtime::types::{CallConfig, LlmResponse, Message, TokenUsage};
use bastion_types::{ApprovalOutcome, ApprovalRow, BastionError, DenyScope, FailureKind};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// 1. Opaque context injection (SEAM #2).
// ---------------------------------------------------------------------------

/// Stands in for an embedding host's own authoritative context (e.g. "the
/// active support ticket", "the object the operator is looking at"). The
/// kernel concatenates `content` into the system prompt VERBATIM — it never
/// parses or interprets it (invariant #8, `docs/SECURITY-INVARIANTS.md`).
struct HostObjectContextProvider;

#[async_trait]
impl TurnContextProvider for HostObjectContextProvider {
    async fn context_for_turn(
        &self,
        _owner: &str,
        _turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        vec![ContextBlock {
            content: "<host_object id=\"ticket-42\">status=open, priority=high</host_object>"
                .to_string(),
            // CloudOk: this embedded host has decided this particular object
            // summary is safe to send to a cloud-backed provider. A real host
            // would derive this per-object, not hardcode it.
            max_tier: PrivacyTier::CloudOk,
        }]
    }
}

// ---------------------------------------------------------------------------
// 2. A custom capability, registered through the public API.
// ---------------------------------------------------------------------------

/// An irreversible, host-defined action. `needs_approval() -> true` is a
/// TYPED property of the capability itself (never a caller-supplied flag —
/// `docs/SECURITY-INVARIANTS.md` invariant #4), decided here by whoever wrote
/// this capability, exactly the way a real embedding host would mark its own
/// dangerous actions.
struct WireTransferCapability;

#[async_trait]
impl Capability for WireTransferCapability {
    fn name(&self) -> &str {
        "wire_transfer"
    }

    fn description(&self) -> &str {
        "Host-defined irreversible action (embedded-host example)"
    }

    fn input_schema(&self) -> &serde_json::Value {
        static SCHEMA: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
        SCHEMA.get_or_init(|| serde_json::json!({"type": "object"}))
    }

    fn needs_approval(&self) -> bool {
        true
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        _ctx: &InvokeCtx,
    ) -> anyhow::Result<serde_json::Value> {
        // Never reached in this example — the host's ThresholdDenyGate denies
        // the amount used below before dispatch, so this never runs (see
        // `demonstrate_denied_capability`).
        Ok(serde_json::json!({"transferred": args}))
    }
}

// ---------------------------------------------------------------------------
// 3. The host's OWN authorization policy — a custom `ApprovalGate`, no
// SQLite at all (Ciclo 2.1, docs/revamp/C2-approval-port-design.md §1).
// ---------------------------------------------------------------------------

/// A minimal, in-memory authorization policy: denies any capability whose
/// `args.amount` exceeds `threshold`, resolved SYNCHRONOUSLY on the very
/// first call — no queue round-trip needed. This is exactly the second
/// authorization mechanism M3-CLOSE found this API had no lever for:
/// `ApprovalQueue` used to be a concrete SQLite struct, not a trait, so the
/// only lever available was reject()-ing an already-queued row. Now a host
/// implements its own decision logic against the `ApprovalGate` port
/// directly.
///
/// The non-`enqueue_or_reuse` methods are unreachable from
/// `CapabilityRegistry::invoke`'s Policy 2 for a capability this gate always
/// resolves synchronously (no row is ever queued, approved, or replayed) —
/// they fail loudly rather than silently no-opping if that assumption ever
/// changes.
struct ThresholdDenyGate {
    threshold: i64,
}

#[async_trait]
impl ApprovalGate for ThresholdDenyGate {
    async fn enqueue_or_reuse(
        &self,
        _owner_id: &str,
        capability_name: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<ApprovalOutcome> {
        let amount = args.get("amount").and_then(|v| v.as_i64()).unwrap_or(0);
        if amount > self.threshold {
            // Ciclo 2.1 §3: `DenyScope::Turn` — the product default. A host
            // that wants "deny just this one" instead would return
            // `DenyScope::Instance`.
            return Ok(ApprovalOutcome::Rejected(DenyScope::Turn));
        }
        anyhow::bail!(
            "ThresholdDenyGate only demonstrates denial in this example — \
             capability '{capability_name}' under the threshold has no defined behavior"
        );
    }

    async fn pending_for_owner(&self, _owner_id: &str) -> anyhow::Result<Vec<ApprovalRow>> {
        Ok(Vec::new())
    }

    async fn approve(&self, _owner_id: &str, id: i64) -> anyhow::Result<ApprovalRow> {
        anyhow::bail!("ThresholdDenyGate resolves synchronously — no queued row {id} to approve")
    }

    async fn reject(&self, _owner_id: &str, id: i64) -> anyhow::Result<()> {
        anyhow::bail!("ThresholdDenyGate resolves synchronously — no queued row {id} to reject")
    }

    async fn record_executed(&self, id: i64, _result: &serde_json::Value) -> anyhow::Result<()> {
        anyhow::bail!(
            "ThresholdDenyGate resolves synchronously — no queued row {id} to record executed"
        )
    }
}

// ---------------------------------------------------------------------------
// Minimal turn plumbing (same shape as the `minimal-agent` example — kept
// here rather than shared, so each example is readable standalone).
// ---------------------------------------------------------------------------

struct MockProvider;

#[async_trait]
impl Provider for MockProvider {
    async fn complete(
        &self,
        _messages: &[Message],
        _config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        Ok(LlmResponse {
            text: "Hello from embedded-host!".to_string(),
            tool_calls: None,
            usage: TokenUsage::default(),
        })
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        Ok(format!("Hello from embedded-host! (you said: {prompt})"))
    }

    fn context_limit(&self) -> usize {
        1_000_000
    }

    fn model_name(&self) -> &str {
        "mock-minimal"
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

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
            attribution: vec!["embedded-host".to_string()],
            turn_tier: Some(PrivacyTier::CloudOk),
        })
    }
}

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
        anyhow::bail!("embedded-host example registers no external tools (requested: {name})")
    }
}

struct NoopFailureSink;

impl FailureSink for NoopFailureSink {
    fn record_failure(&self, _kind: FailureKind, _tier: Option<PrivacyTier>, _detail: &str) {}
}

struct UnusedResolver;

impl ProviderResolver for UnusedResolver {
    fn resolve(&self, model: &str) -> anyhow::Result<Box<dyn Provider>> {
        anyhow::bail!(
            "embedded-host example never resolves a provider by name (requested: {model})"
        )
    }
}

/// Proves the opaque context block from `HostObjectContextProvider` reaches
/// the system prompt byte-identical — the kernel's SEAM #2 contract.
async fn demonstrate_opaque_context(agent: &AgentLoop) {
    let parts = agent
        .build_system_prompt_parts(DEFAULT_OWNER, "hello", None)
        .await;
    let full_prompt = parts.join("\n\n");
    assert!(
        full_prompt
            .contains("<host_object id=\"ticket-42\">status=open, priority=high</host_object>"),
        "the host's opaque context block must reach the system prompt verbatim"
    );
    println!("[1/3] opaque context block reached the system prompt verbatim — OK");
}

/// Proves the host's own capability is reachable through the SAME public
/// `CapabilityRegistry::invoke` every kernel-internal capability uses — no
/// forked dispatch path — and that the host's OWN authorization policy
/// (`ThresholdDenyGate`, injected into `AgentLoop::new` in `main()` below,
/// no SQLite involved) can deny it with a typed `Err`.
///
/// RESOLVED (Ciclo 2.1, `docs/revamp/C2-approval-port-design.md`): this used
/// to document a real API gap found while writing this example — `AgentLoop::new`
/// hardwired its own SQLite `ApprovalQueue` with no opt-out, and even the
/// only available lever (`.reject(owner, id)` on an already-queued row)
/// produced no observable signal: a rejected row mapped to the SAME
/// `Ok({awaiting_approval: true})` outcome as a still-undecided one. Both are
/// closed now: `AgentLoop::new` takes an injected `Arc<dyn ApprovalGate>`
/// (this example's `ThresholdDenyGate`, not `SqliteApprovalGate` — no queue,
/// no database, entirely the host's own in-memory policy), and a denial
/// surfaces as `Err(BastionError::ApprovalDenied { capability, scope })`.
async fn demonstrate_denied_capability(agent: &mut AgentLoop) {
    agent
        .capability_registry
        .register(Arc::new(WireTransferCapability))
        .expect("register wire_transfer");

    let ctx = InvokeCtx {
        owner: DEFAULT_OWNER.to_string(),
        privacy_tier: Some(PrivacyTier::CloudOk),
    };
    // Over the host's ThresholdDenyGate threshold (100) — denied synchronously,
    // no queue round-trip.
    let args = serde_json::json!({"amount": 999});

    let err = agent
        .capability_registry
        .invoke("wire_transfer", args, &ctx)
        .await
        .expect_err(
            "the host's ThresholdDenyGate denies amounts over its threshold — \
             invoke() must return Err, never Ok({awaiting_approval: true})",
        );

    match err.downcast_ref::<BastionError>() {
        Some(BastionError::ApprovalDenied { capability, scope }) => {
            assert_eq!(capability, "wire_transfer");
            assert_eq!(
                *scope,
                DenyScope::Turn,
                "ThresholdDenyGate returns the product default scope"
            );
            println!(
                "[2/3] wire_transfer denied by the host's own ApprovalGate \
                 (ThresholdDenyGate, no SQLite) — invoke() returned a typed \
                 Err(BastionError::ApprovalDenied{{capability: {capability:?}, scope: {scope:?}}})"
            );
        }
        other => {
            panic!("expected Err(BastionError::ApprovalDenied), got: {other:?} (display: {err})")
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db_path = dir
        .path()
        .join("embedded-host.sqlite3")
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
        1.0,
        Arc::new(EchoResponder),
        memory,
        None,
        vec![],
        // The host's OWN authorization policy (Ciclo 2.1) — no SQLite queue,
        // no product code, just an `Arc<dyn ApprovalGate>` this example
        // built itself. Denies any `amount` over 100 (see `ThresholdDenyGate`).
        Arc::new(ThresholdDenyGate { threshold: 100 }),
        Arc::new(NoopFailureSink),
        // The seam a second consumer uses to inject its own authoritative
        // context — no patch to the kernel, just a `Box<dyn TurnContextProvider>`.
        vec![Box::new(HostObjectContextProvider)],
        Arc::new(UnusedResolver),
        None,
        None,
    );

    demonstrate_opaque_context(&agent).await;
    demonstrate_denied_capability(&mut agent).await;

    let reply = agent.run_turn_for("hello", DEFAULT_OWNER).await?;
    println!("[3/3] full turn completed with the host's context/capability wired in: {reply}");

    Ok(())
}
