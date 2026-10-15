use super::*;
use crate::agent::pool::{AgentLoopFactory, AgentLoopPool, AgentLoopPoolConfig, PoolError};
use crate::agent::ports::{RespondOutcome, Responder, TurnContext};
use crate::capability::{Capability, InvokeCtx, TraceContext};
use crate::types::{LlmResponse, ToolCall};
use bastion_types::{ContextRevision, ContextUpdate};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// ── fixtures ────────────────────────────────────────────────────────────

/// Replies after a pause, recording how many turns overlap per session and
/// overall. Persists its reply like the real single-persona dispatch.
#[derive(Default)]
struct SlowResponder {
    in_flight: Mutex<HashMap<String, usize>>,
    max_same_session: AtomicUsize,
    total: AtomicUsize,
    max_total: AtomicUsize,
}

#[async_trait]
impl Responder for SlowResponder {
    async fn respond(&self, turn: TurnContext<'_>) -> anyhow::Result<RespondOutcome> {
        let session = turn.session_id.to_owned();
        {
            let mut map = self.in_flight.lock().unwrap();
            let n = map.entry(session.clone()).or_default();
            *n += 1;
            self.max_same_session.fetch_max(*n, Ordering::SeqCst);
        }
        let total = self.total.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_total.fetch_max(total, Ordering::SeqCst);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let text = format!("reply to {}", turn.user_input);
        turn.kernel
            .session_append(
                turn.session_id,
                Message {
                    role: Role::Assistant,
                    content: MessageContent::Text(text.clone()),
                },
                None,
            )
            .await?;

        self.total.fetch_sub(1, Ordering::SeqCst);
        *self.in_flight.lock().unwrap().get_mut(&session).unwrap() -= 1;
        Ok(RespondOutcome {
            text,
            attribution: vec![],
            turn_tier: None,
            allowed_tools: None,
        })
    }
}

/// A loop over an already-initialized database (a host initializes the
/// schema once at startup, never per loop).
fn slow_loop(db_path: &str, responder: Arc<SlowResponder>) -> AgentLoop {
    let memory: SharedMemory = Arc::new(RwLock::new(
        Box::new(NoopMemory) as Box<dyn crate::memory::Memory>
    ));
    AgentLoop::new(
        make_provider("TestPersona"),
        crate::session::SessionManager::new(db_path),
        Arc::new(EmptyToolSource),
        "unused-default-session".into(),
        10.0,
        responder,
        memory,
        None,
        vec![],
        Arc::new(crate::capability::approval::SqliteApprovalGate::new(
            db_path,
        )),
        Arc::new(NoopFailureSink),
        vec![],
        Arc::new(UnreachableResolver),
        None,
        None,
    )
}

/// A fresh database with the schema in place.
async fn initialized_db() -> (NamedTempFile, String) {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap().to_owned();
    crate::session::SessionManager::new(&path)
        .init_schema()
        .await
        .unwrap();
    (f, path)
}

/// Every message of `session`, as (role, text).
async fn transcript(db_path: &str, session: &str) -> Vec<(Role, String)> {
    crate::session::SessionManager::new(db_path)
        .load_recent(session)
        .await
        .unwrap()
        .into_iter()
        .map(|m| match m.content {
            MessageContent::Text(t) => (m.role, t),
            other => (m.role, format!("{other:?}")),
        })
        .collect()
}

/// Each user message is immediately followed by its own reply.
fn assert_turns_did_not_interleave(messages: &[(Role, String)], turns: usize) {
    assert_eq!(messages.len(), turns * 2, "{messages:?}");
    for pair in messages.chunks(2) {
        assert_eq!(pair[0].0, Role::User);
        assert_eq!(pair[1].0, Role::Assistant);
        assert_eq!(pair[1].1, format!("reply to {}", pair[0].1), "{messages:?}");
    }
}

// ── per-session serialization ───────────────────────────────────────────

#[tokio::test]
async fn loops_sharing_session_locks_serialize_a_session_and_parallelize_sessions() {
    let (_f, path) = initialized_db().await;
    let responder = Arc::new(SlowResponder::default());
    let locks = SessionLocks::new();

    // One loop per request, the way a host without a pool runs them.
    let mut tasks = Vec::new();
    for i in 0..4 {
        for session in ["conv-a", "conv-b"] {
            let agent = slow_loop(&path, responder.clone()).with_session_locks(locks.clone());
            tasks.push(tokio::spawn(async move {
                let mut agent = agent;
                agent
                    .run_turn_with(
                        TurnRequest::new("alice", format!("{session} #{i}")).in_session(session),
                    )
                    .await
                    .unwrap()
            }));
        }
    }
    for t in tasks {
        t.await.unwrap();
    }

    assert_eq!(responder.max_same_session.load(Ordering::SeqCst), 1);
    assert!(
        responder.max_total.load(Ordering::SeqCst) >= 2,
        "different sessions must run in parallel"
    );
    for session in ["conv-a", "conv-b"] {
        assert_turns_did_not_interleave(&transcript(&path, session).await, 4);
    }
    assert_eq!(locks.active(), 0);
}

#[tokio::test]
async fn owner_addressed_and_id_addressed_turns_of_one_session_serialize() {
    let (_f, path) = initialized_db().await;
    let responder = Arc::new(SlowResponder::default());
    let locks = SessionLocks::new();

    // Bob's most recent session is "conv-bob"; half the turns address it by
    // owner, half by id.
    crate::session::SessionManager::new(&path)
        .ensure_session_for("conv-bob", "bob")
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for i in 0..6 {
        let agent = slow_loop(&path, responder.clone()).with_session_locks(locks.clone());
        tasks.push(tokio::spawn(async move {
            let mut agent = agent;
            let request = TurnRequest::new("bob", format!("m{i}"));
            let request = if i % 2 == 0 {
                request.in_session("conv-bob")
            } else {
                request
            };
            agent.run_turn_with(request).await.unwrap()
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(responder.max_same_session.load(Ordering::SeqCst), 1);
    assert_turns_did_not_interleave(&transcript(&path, "conv-bob").await, 6);
}

#[tokio::test]
async fn a_session_of_another_owner_is_refused_before_anything_is_written() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap().to_owned();
    let mut agent = make_loop(&path).await;
    agent
        .run_turn_with(TurnRequest::new("alice", "hi").in_session("conv-1"))
        .await
        .unwrap();
    let before = transcript(&path, "conv-1").await;

    let err = agent
        .run_turn_with(TurnRequest::new("mallory", "show me").in_session("conv-1"))
        .await
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<BastionError>(),
        Some(BastionError::SessionOwnerMismatch { session_id }) if session_id == "conv-1"
    ));
    assert_eq!(transcript(&path, "conv-1").await, before);
}

// ── pool ────────────────────────────────────────────────────────────────

struct Factory {
    path: String,
    responder: Arc<SlowResponder>,
    built: AtomicUsize,
}

#[async_trait]
impl AgentLoopFactory for Factory {
    async fn build(&self) -> anyhow::Result<AgentLoop> {
        self.built.fetch_add(1, Ordering::SeqCst);
        Ok(slow_loop(&self.path, self.responder.clone()))
    }
}

fn pool(
    path: &str,
    config: AgentLoopPoolConfig,
) -> (AgentLoopPool, Arc<Factory>, Arc<SlowResponder>) {
    let responder = Arc::new(SlowResponder::default());
    let factory = Arc::new(Factory {
        path: path.to_owned(),
        responder: responder.clone(),
        built: AtomicUsize::new(0),
    });
    (
        AgentLoopPool::new(factory.clone(), config),
        factory,
        responder,
    )
}

#[tokio::test]
async fn pool_serializes_each_session_and_runs_sessions_in_parallel() {
    let (_f, path) = initialized_db().await;
    let (pool, factory, responder) = pool(&path, AgentLoopPoolConfig::default());

    let mut tasks = Vec::new();
    for i in 0..4 {
        for session in ["conv-a", "conv-b", "conv-c"] {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                pool.run_turn(
                    TurnRequest::new("alice", format!("{session} #{i}")).in_session(session),
                )
                .await
                .unwrap()
            }));
        }
    }
    for t in tasks {
        let turn = t.await.unwrap();
        assert!(turn.text.starts_with("reply to"));
        assert!(turn.usage.is_some());
    }

    assert_eq!(responder.max_same_session.load(Ordering::SeqCst), 1);
    assert!(responder.max_total.load(Ordering::SeqCst) >= 2);
    for session in ["conv-a", "conv-b", "conv-c"] {
        assert_turns_did_not_interleave(&transcript(&path, session).await, 4);
    }
    // Session affinity: one loop per session, reused for all its turns.
    assert_eq!(factory.built.load(Ordering::SeqCst), 3);
    assert_eq!(pool.idle_loops(), 3);
}

#[tokio::test]
async fn pool_bounds_concurrency_and_evicts_the_least_recently_used_loop() {
    let (_f, path) = initialized_db().await;
    let (pool, factory, responder) = pool(
        &path,
        AgentLoopPoolConfig {
            max_concurrent_turns: 1,
            max_idle_loops: 1,
        },
    );

    let mut tasks = Vec::new();
    for session in ["s1", "s2", "s3"] {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            pool.run_turn(TurnRequest::new("alice", "hi").in_session(session))
                .await
                .unwrap()
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(responder.max_total.load(Ordering::SeqCst), 1);
    assert_eq!(pool.idle_loops(), 1);

    // Whichever session ran last is the one kept; the other two rebuild.
    let built = factory.built.load(Ordering::SeqCst);
    for session in ["s1", "s2", "s3"] {
        pool.run_turn(TurnRequest::new("alice", "again").in_session(session))
            .await
            .unwrap();
    }
    assert!(factory.built.load(Ordering::SeqCst) >= built + 2);
}

#[tokio::test]
async fn pool_refuses_a_turn_without_a_session() {
    let (_f, path) = initialized_db().await;
    let (pool, factory, _) = pool(&path, AgentLoopPoolConfig::default());
    let err = pool
        .run_turn(TurnRequest::new("alice", "hi"))
        .await
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<PoolError>(),
        Some(PoolError::SessionRequired)
    ));
    assert_eq!(factory.built.load(Ordering::SeqCst), 0);
}

// ── host context, trace correlation, rule delivery ──────────────────────

#[derive(Debug, Clone, Default)]
struct CapturingExporter(Arc<Mutex<Vec<SpanData>>>);

impl SpanExporter for CapturingExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.0.lock().unwrap().extend(batch);
        Ok(())
    }
}

/// The process-wide tracer, installed once for every test of this binary.
fn spans() -> &'static CapturingExporter {
    static EXPORTER: OnceLock<CapturingExporter> = OnceLock::new();
    EXPORTER.get_or_init(|| {
        let exporter = CapturingExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        opentelemetry::global::set_tracer_provider(provider);
        exporter
    })
}

/// What one `probe` call saw.
#[derive(Debug, Clone)]
struct Seen {
    ctx: InvokeCtx,
    current: Option<TraceContext>,
}

/// Records its `InvokeCtx` and the OTel context current while it runs. The
/// first call also publishes a new rule revision, mid-turn.
struct Probe {
    seen: Arc<Mutex<Vec<Seen>>>,
    policy: PolicyChannel,
    mid_turn_update: Mutex<Option<ContextUpdate>>,
}

static PROBE_SCHEMA: OnceLock<Value> = OnceLock::new();

#[async_trait]
impl Capability for Probe {
    fn name(&self) -> &str {
        "probe"
    }
    fn description(&self) -> &str {
        "records its invocation context"
    }
    fn input_schema(&self) -> &Value {
        PROBE_SCHEMA.get_or_init(|| json!({"type": "object"}))
    }
    fn is_local(&self) -> bool {
        true
    }
    async fn invoke(&self, _args: Value, ctx: &InvokeCtx) -> anyhow::Result<Value> {
        self.seen.lock().unwrap().push(Seen {
            ctx: ctx.clone(),
            current: TraceContext::current(),
        });
        if let Some(update) = self.mid_turn_update.lock().unwrap().take() {
            assert!(self.policy.apply(update).is_published());
        }
        Ok(json!({"ok": true}))
    }
}

/// Answers with two `probe` tool calls, run through the kernel tool loop.
struct ToolCallingResponder;

#[async_trait]
impl Responder for ToolCallingResponder {
    async fn respond(&self, turn: TurnContext<'_>) -> anyhow::Result<RespondOutcome> {
        let call = |id: &str| ToolCall {
            id: id.into(),
            name: "probe".into(),
            arguments: json!({}),
            extra: None,
        };
        let initial = LlmResponse {
            text: String::new(),
            tool_calls: Some(vec![call("c1"), call("c2")]),
            usage: Default::default(),
        };
        let text = turn
            .kernel
            .run_tool_loop(
                turn.history,
                turn.session_id,
                &CallConfig::default(),
                initial,
                turn.owner,
                Some(PrivacyTier::CloudOk),
                None,
            )
            .await?;
        Ok(RespondOutcome {
            text,
            attribution: vec![],
            turn_tier: Some(PrivacyTier::CloudOk),
            allowed_tools: None,
        })
    }
}

fn rule(version: u64, content: Value) -> ContextUpdate {
    ContextUpdate::Snapshot(ContextRevision {
        version,
        content: content.to_string(),
        provenance: "rules-service".into(),
        effective_from: 0,
    })
}

fn attr<'a>(span: &'a SpanData, key: &str) -> Option<&'a opentelemetry::Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| &kv.value)
}

#[tokio::test]
async fn capabilities_see_host_context_trace_and_the_turn_rule_revision() {
    let exporter = spans();
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap().to_owned();

    let policy = PolicyChannel::new();
    assert!(policy.apply(rule(1, json!({"limit": 5}))).is_published());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut agent = make_loop(&path).await.with_policy_channel(policy.clone());
    agent.responder = Arc::new(ToolCallingResponder);
    agent
        .capability_registry
        .register(Arc::new(Probe {
            seen: seen.clone(),
            policy: policy.clone(),
            mid_turn_update: Mutex::new(Some(rule(2, json!({"limit": 9})))),
        }))
        .unwrap();

    let session = "conv-trace-1";
    let host_context = json!({"object": "case-42", "scope": ["read", "write"]});
    agent
        .run_turn_with(
            TurnRequest::new("alice", "check the case")
                .in_session(session)
                .with_host_context(host_context.clone()),
        )
        .await
        .unwrap();

    // Host context reaches every call untouched; both calls of the turn see
    // the revision effective when the turn started, despite the mid-turn
    // update.
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    for call in &calls {
        assert_eq!(call.ctx.host_context.as_deref(), Some(&host_context));
        assert_eq!(call.ctx.policy.as_ref().map(|r| r.version), Some(1));
        assert_eq!(call.ctx.owner, "alice");
    }
    assert_eq!(agent.last_turn_policy_version(), Some(1));

    // Trace: each call's `ctx.trace` is its own `execute_tool` span, which is
    // also the current context while it runs, child of the turn's
    // `invoke_agent` span — the same trace as the turn's model calls.
    let all = exporter.0.lock().unwrap().clone();
    let turn = all
        .iter()
        .find(|s| {
            s.name == "invoke_agent"
                && attr(s, "gen_ai.conversation.id").map(|v| v.as_str().into_owned())
                    == Some(session.to_owned())
        })
        .expect("invoke_agent span of the turn");
    assert_eq!(
        attr(turn, "bastion.policy.version"),
        Some(&opentelemetry::Value::I64(1))
    );
    let trace_id = turn.span_context.trace_id();
    for call in &calls {
        let trace = call.ctx.trace.as_ref().expect("trace context");
        assert_eq!(call.current.as_ref(), Some(trace));
        assert_eq!(trace.trace_id, trace_id.to_string());
        assert_eq!(
            trace.traceparent(),
            format!("00-{}-{}-01", trace.trace_id, trace.span_id)
        );
        let tool = all
            .iter()
            .find(|s| s.span_context.span_id().to_string() == trace.span_id)
            .expect("execute_tool span exported");
        assert_eq!(tool.name, "execute_tool probe");
        assert_eq!(tool.parent_span_id, turn.span_context.span_id());
    }
    assert!(
        all.iter()
            .any(|s| s.span_context.trace_id() == trace_id && s.name.starts_with("chat ")),
        "the turn's model calls share its trace"
    );

    // The next turn runs under the revision published mid-turn.
    seen.lock().unwrap().clear();
    agent
        .run_turn_with(TurnRequest::new("alice", "again").in_session(session))
        .await
        .unwrap();
    let calls = seen.lock().unwrap().clone();
    assert!(calls
        .iter()
        .all(|c| c.ctx.policy.as_ref().map(|r| r.version) == Some(2)));
    assert!(calls.iter().all(|c| c.ctx.host_context.is_none()));
    assert_eq!(agent.last_turn_policy_version(), Some(2));
}

#[tokio::test]
async fn approval_resolution_dispatch_carries_the_reply_turn_host_context() {
    struct Gated(Arc<Mutex<Vec<Seen>>>);

    #[async_trait]
    impl Capability for Gated {
        fn name(&self) -> &str {
            "gated"
        }
        fn description(&self) -> &str {
            "needs approval"
        }
        fn input_schema(&self) -> &Value {
            PROBE_SCHEMA.get_or_init(|| json!({"type": "object"}))
        }
        fn needs_approval(&self) -> bool {
            true
        }
        async fn invoke(&self, _args: Value, ctx: &InvokeCtx) -> anyhow::Result<Value> {
            self.0.lock().unwrap().push(Seen {
                ctx: ctx.clone(),
                current: None,
            });
            Ok(json!({}))
        }
    }

    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap().to_owned();
    let policy = PolicyChannel::new();
    policy.apply(rule(4, json!({})));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut agent = make_loop(&path).await.with_policy_channel(policy);
    agent
        .capability_registry
        .register(Arc::new(Gated(seen.clone())))
        .unwrap();

    // Queue the call (Policy 2), then approve it in a later turn.
    let ctx = InvokeCtx {
        owner: "alice".into(),
        privacy_tier: Some(PrivacyTier::CloudOk),
        ..Default::default()
    };
    let _ = agent
        .capability_registry
        .invoke("gated", json!({}), &ctx)
        .await;
    assert!(seen.lock().unwrap().is_empty(), "queued, not dispatched");

    let reply = agent
        .run_turn_with(TurnRequest::new("alice", "sim").with_host_context(json!({"k": 1})))
        .await
        .unwrap();
    assert!(reply.contains("gated"), "{reply}");
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ctx.host_context.as_deref(), Some(&json!({"k": 1})));
    assert_eq!(calls[0].ctx.policy.as_ref().map(|r| r.version), Some(4));
}
