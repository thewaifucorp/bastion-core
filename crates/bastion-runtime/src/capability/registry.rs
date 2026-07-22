use crate::agent::ports::ApprovalGate;
use crate::capability::approval::NullApprovalGate;
use crate::memory::PrivacyTier;
use async_trait::async_trait;
use bastion_types::{ApprovalOutcome, BastionError};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Invocation context — resolved BEFORE entering registry.invoke.
pub struct InvokeCtx {
    pub owner: String,
    pub privacy_tier: Option<PrivacyTier>,
    /// Persona contract v2 (`tools:` allowlist) — the resolved authority set
    /// for the persona dispatching this call. `None` = unrestricted
    /// (legacy/back-compat: every pre-contract-v2 persona, and every caller
    /// that never resolves a persona at all). `Some(set)` restricts dispatch
    /// to exactly the capability names in `set` — enforced by
    /// `CapabilityRegistry::invoke`'s Policy 0, below.
    pub allowed_tools: Option<Arc<HashSet<String>>>,
}

/// Persona contract v2 tool-authority check (Policy 0) — shared between
/// `CapabilityRegistry::invoke` and the empty-registry MCP-bypass path in
/// `agent/loop_.rs::dispatch_tool_loop` (the SAME historical blind spot the
/// egress check needed a second call site for: `docs/SECURITY-INVARIANTS.md`
/// §4 / this module's own `invoke()` doc). `allowed_tools == None` is the
/// unrestricted/legacy case; `Some(set)` denies fail-closed for any name
/// outside it, raising the SAME typed `BastionError::ToolNotAllowed` from
/// both call sites so neither path's tagging/logging diverges.
pub fn check_tool_allowed(
    allowed_tools: &Option<Arc<HashSet<String>>>,
    name: &str,
) -> anyhow::Result<()> {
    if let Some(allowed) = allowed_tools {
        if !allowed.contains(name) {
            anyhow::bail!(BastionError::ToolNotAllowed {
                capability: name.to_owned(),
            });
        }
    }
    Ok(())
}

/// A capability is anything the agent can invoke through the registry.
#[async_trait]
pub trait Capability: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn input_schema(&self) -> &Value;
    async fn invoke(&self, args: Value, ctx: &InvokeCtx) -> anyhow::Result<Value>;

    /// Whether this capability executes entirely locally (no data leaves the host).
    ///
    /// SECURITY (D-13 guardrail 3): the egress policy keys on THIS typed property,
    /// never on the capability's `name()` string. The default is `false` (treated as
    /// external → LocalOnly tier blocks it, fail-closed). Only adapters that are local
    /// by construction (NlCommandAdapter) override this to `true`. A remote MCP server
    /// cannot opt into the local short-circuit by naming its tool `cmd:*` — locality is
    /// a property of the adapter TYPE, not a forgeable string.
    fn is_local(&self) -> bool {
        false
    }

    /// Whether this capability requires explicit owner approval before it may
    /// dispatch (SEC-01 — irreversible/destructive actions).
    ///
    /// SECURITY: exactly like `is_local()`, this is a TYPED property of the
    /// capability itself, decided by whoever implements it — never derived
    /// from a runtime flag passed in by the caller (the removed
    /// `InvokeCtx.needs_approval` was dead scaffolding: hardcoded `false` at
    /// every construction site, never actually set `true` by any caller). The
    /// default is `false` — the overwhelming majority of capabilities are
    /// unaffected by the approval gate.
    fn needs_approval(&self) -> bool {
        false
    }

    /// Whether this capability's result is TRUSTED content — safe to hand the
    /// LLM without a spotlighting/quarantine warning (SEC-04).
    ///
    /// SECURITY: like `is_local()`/`needs_approval()`, this is a TYPED property
    /// of the capability itself, never derived from the capability's `name()`
    /// string. Default mirrors `is_local()`: a capability that never leaves the
    /// host is trusted-by-default; everything else defaults untrusted unless an
    /// adapter explicitly overrides this (e.g. `McpToolAdapter`'s
    /// `trusted_override` escape hatch, D-09/SEC-05).
    fn is_trusted(&self) -> bool {
        self.is_local()
    }
}

/// The result of `CapabilityRegistry::invoke()` — a capability's raw output
/// PLUS the trust classification computed once at the single policy boundary
/// (SEC-04, spotlighting).
///
/// `trusted` is metadata, never an inline text prefix scattered through the
/// codebase — mirrors `TurnContextProvider`'s "opaque block, core never
/// interprets content" precedent, applied one layer earlier (the invoke()
/// boundary itself, not just system-prompt assembly). The ONE place that
/// decides how an untrusted result is FRAMED for the LLM is
/// `dispatch_tool_loop` (src/agent/loop_.rs) — never a parallel/duplicate
/// framing mechanism elsewhere.
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedValue {
    /// The capability's raw output — exactly what `Capability::invoke()` returned.
    pub data: Value,
    /// The capability name this result came from (mirrors `Capability::name()`).
    pub source: String,
    /// Trust classification, computed ONCE here from `cap.is_trusted()` —
    /// never re-derived downstream from `source`'s string value.
    pub trusted: bool,
}

impl TaggedValue {
    /// The tag a NON-local capability's successful dispatch gets through
    /// `invoke()` (`cap.is_trusted()` defaults to `cap.is_local()`, `false`
    /// for anything non-local). Ciclo 2.1 (`docs/SECURITY-INVARIANTS.md`
    /// §4, LOOP-REPORT.md finding #4): the two `ToolSource`-bypass call sites
    /// in `agent/loop_.rs` (`dispatch_tool_loop`'s empty-registry fallback,
    /// `run_provider_fallback`'s whole tool loop) have no `Capability` object
    /// to call `.is_trusted()` on — this constructor is the SAME wrapping
    /// registry `invoke()` applies, exposed so both bypass paths derive their
    /// tag from it directly instead of a parallel/duplicated convention.
    pub fn untrusted(source: impl Into<String>, data: Value) -> Self {
        Self {
            data,
            source: source.into(),
            trusted: false,
        }
    }
}

/// Unified capability registry.
///
/// Single policy enforcement point — every frontend (direct fn, MCP tool, NL command)
/// invokes through here. check_egress is called once per invoke at this boundary.
#[derive(Clone)]
pub struct CapabilityRegistry {
    inner: HashMap<String, Arc<dyn Capability>>,
    /// SEC-01 approval gate (Ciclo 2.1, `docs/SECURITY-INVARIANTS.md`
    /// §1: `ApprovalGate` port, not a concrete `Option<Arc<ApprovalQueue>>`).
    /// NEVER `Option` — approval is mandatory. `CapabilityRegistry::new()`
    /// wires the explicit fail-closed `NullApprovalGate` by default (see
    /// `invoke()`'s Policy 2 for why that denies fail-closed, never silently
    /// allows, any capability with `needs_approval()==true`); a caller that
    /// wants a real queue calls `.with_approval_gate(...)`.
    approval_gate: Arc<dyn ApprovalGate>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            approval_gate: Arc::new(NullApprovalGate),
        }
    }

    /// Wire a real `ApprovalGate` (e.g. `SqliteApprovalGate`) so Policy 2 can
    /// actually queue/idempotent-resume instead of fail-closed-denying every
    /// `needs_approval()==true` capability.
    pub fn with_approval_gate(mut self, gate: Arc<dyn ApprovalGate>) -> Self {
        self.approval_gate = gate;
        self
    }

    /// Plan 11-04: read access to the wired `ApprovalGate` — lets
    /// `AgentLoop::run_turn_for`'s pre-LLM approval-resolution intercept check
    /// `pending_for_owner`/`approve`/`reject` WITHOUT going through `invoke()`
    /// (there is no capability to invoke yet at that point — resolution decides
    /// whether to dispatch one). Never `None` (Ciclo 2.1) — an unwired registry
    /// carries the explicit fail-closed `NullApprovalGate`, whose
    /// `pending_for_owner` always reports empty so callers degrade gracefully.
    pub fn approval_gate(&self) -> &Arc<dyn ApprovalGate> {
        &self.approval_gate
    }

    /// Register a capability under its `name()`.
    ///
    /// SECURITY: rejects two impersonation vectors (D-13 guardrail):
    /// 1. A non-local capability claiming the reserved `cmd:` namespace — only
    ///    `is_local()` capabilities (NL commands) may use `cmd:` keys, so a remote
    ///    MCP tool named `cmd:exfil` cannot acquire the local egress short-circuit.
    /// 2. Overwriting an existing key — a later registration cannot shadow/impersonate
    ///    an already-registered built-in capability.
    pub fn register(&mut self, cap: Arc<dyn Capability>) -> anyhow::Result<()> {
        let name = cap.name();
        if name.starts_with("cmd:") && !cap.is_local() {
            anyhow::bail!(
                "capability '{}' uses the reserved 'cmd:' namespace but is not a local NL command — refusing to register",
                name
            );
        }
        if self.inner.contains_key(name) {
            anyhow::bail!(
                "capability '{}' is already registered — refusing to overwrite",
                name
            );
        }
        self.inner.insert(name.to_owned(), cap);
        Ok(())
    }

    pub fn list_names(&self) -> Vec<&str> {
        self.inner.keys().map(|s| s.as_str()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Remove a capability by name. Idempotent — returns false if not present.
    ///
    /// SECURITY: remove does NOT check guardrails (cmd: namespace etc.) because
    /// removal does not create an attack vector — only register() needs to check.
    pub fn remove(&mut self, name: &str) -> bool {
        self.inner.remove(name).is_some()
    }

    /// Drain EVERY registered capability, leaving the registry empty.
    ///
    /// SEC-05: the first method to manipulate the WHOLE map at once rather
    /// than a single name at a time — the underlying mechanism backing
    /// `TurnCapabilityScope::quarantine()`. Callers are expected to `restore()`
    /// the returned vec once the quarantine window ends; this method itself
    /// has no memory of what it drained.
    pub fn drain_all(&mut self) -> Vec<Arc<dyn Capability>> {
        self.inner.drain().map(|(_, cap)| cap).collect()
    }

    /// Re-register every capability from a previously `drain_all()`-ed vec,
    /// keyed by each capability's own `.name()` — mirrors `register()`'s key
    /// derivation WITHOUT re-running its guardrail checks (`cmd:` namespace,
    /// duplicate-key rejection). These capabilities were already validated
    /// once at their ORIGINAL registration time; restoring them is not a new,
    /// untrusted registration.
    pub fn restore(&mut self, caps: Vec<Arc<dyn Capability>>) {
        for cap in caps {
            let name = cap.name().to_owned();
            self.inner.insert(name, cap);
        }
    }

    /// Return tool definitions in the JSON format expected by the provider
    /// (name/description/input_schema). Compatible with `anthropic_tools_to_openai()`
    /// in openrouter.rs.
    ///
    /// SORTED by capability name (COST-01/D-14b prerequisite): `self.inner` is a
    /// `HashMap`, whose iteration order is unspecified and can shift across an
    /// intervening register+remove cycle (e.g. `TurnCapabilityScope`, above) even
    /// when the surviving capability set is unchanged. Plan 08-10's byte-stable
    /// cache-prefix guarantee requires this listing to serialize identically
    /// turn-over-turn — an unsorted HashMap iteration would silently invalidate
    /// that guarantee.
    pub fn list_tool_defs(&self) -> Vec<serde_json::Value> {
        let mut caps: Vec<&Arc<dyn Capability>> = self.inner.values().collect();
        caps.sort_by(|a, b| a.name().cmp(b.name()));
        caps.into_iter()
            .map(|cap| {
                serde_json::json!({
                    "name": cap.name(),
                    "description": cap.description(),
                    "input_schema": cap.input_schema()
                })
            })
            .collect()
    }

    /// Single policy enforcement point (D-13 non-negotiable guardrail).
    ///
    /// Policy order:
    /// 0. Tool authority gate (persona contract v2) — fail-closed deny if
    ///    `ctx.allowed_tools` is `Some(set)` and `name` is not in it. Checked
    ///    BEFORE egress/approval — an out-of-contract tool call for a
    ///    tools-restricted persona must never reach those policies at all.
    /// 1. Egress check — fail-closed on LocalOnly or None tier for non-local adapters
    /// 2. Approval gate (SEC-01) — if `cap.needs_approval()`, gate on the wired
    ///    `ApprovalGate` (queue/idempotent-resume/cache/typed-deny), or fail-closed
    ///    deny if only the default `NullApprovalGate` is wired
    /// 3. Dispatch to capability adapter
    ///
    /// SEC-04 (spotlighting): every Ok return path wraps its `Value` in a
    /// `TaggedValue{data, source, trusted}` — computed ONCE here from
    /// `cap.is_trusted()` — including the approval-gate early-returns above
    /// (Policy 2's `AlreadyExecuted`/`awaiting_approval` branches), so every
    /// Ok exit from `invoke()` produces the new type consistently. Ciclo 2.1
    /// (behavior change, `docs/SECURITY-INVARIANTS.md` §2): a
    /// `Rejected` outcome is the one Policy-2 branch that does NOT produce a
    /// `TaggedValue` — it returns `Err(BastionError::ApprovalDenied)` instead,
    /// mirroring Policy 1's own `Err` shape (never a disguised-as-success
    /// `Ok({awaiting_approval: true})`).
    pub async fn invoke(
        &self,
        name: &str,
        args: Value,
        ctx: &InvokeCtx,
    ) -> anyhow::Result<TaggedValue> {
        let cap = self
            .inner
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown capability: {}", name))?;

        // Policy 0: persona tool-authority gate (contract v2 `tools:` allowlist).
        // Checked first — an out-of-contract tool call for a tools-restricted
        // persona must never reach the egress/approval machinery below.
        check_tool_allowed(&ctx.allowed_tools, name)?;

        // Policy 1: egress check.
        // Locality is a TYPED property of the adapter (`is_local()`), NEVER derived from
        // the capability name string — a remote MCP server could otherwise forge a `cmd:`
        // name to acquire the local short-circuit (D-13 guardrail 3). Local capabilities
        // (NL commands) map to "ollama" (always passes); everything else maps to "external"
        // so LocalOnly / None tiers are blocked fail-closed.
        let provider_for_policy = if cap.is_local() { "ollama" } else { "external" };
        crate::hooks::egress::check_egress(ctx.privacy_tier, provider_for_policy)?;

        // Policy 2: approval gate (SEC-01). `needs_approval()` is the SOLE decision
        // source — a typed property of the capability itself, never a caller-supplied
        // flag (T-11-02-01: the removed `InvokeCtx.needs_approval` was exactly that
        // kind of unwired, trust-me flag, and is gone, not left dead alongside this).
        if cap.needs_approval() {
            // Ciclo 2.1: the gate is always wired (NEVER `Option`) — an
            // unattached registry carries `NullApprovalGate`, whose
            // `enqueue_or_reuse` fails closed exactly like the old `None`
            // branch (T-11-02-04, e.g. the Reflector's minimal registry).
            let outcome = self
                .approval_gate
                .enqueue_or_reuse(&ctx.owner, name, &args)
                .await?;
            return match outcome {
                // D-03 idempotent-resume: already ran to completion — return the
                // cached result, never re-dispatch.
                ApprovalOutcome::AlreadyExecuted(cached) => Ok(TaggedValue {
                    data: cached,
                    source: name.to_owned(),
                    trusted: cap.is_trusted(),
                }),
                // Not yet approved (freshly queued or still pending): the
                // capability has NOT run — Dispatch below is structurally
                // unreachable from this branch (T-11-02-02).
                ApprovalOutcome::AlreadyPending | ApprovalOutcome::NewlyQueued(_) => {
                    Ok(TaggedValue {
                        data: serde_json::json!({
                            "awaiting_approval": true,
                            "capability": name,
                        }),
                        source: name.to_owned(),
                        trusted: cap.is_trusted(),
                    })
                }
                // Approved but not yet executed: this invoke() call IS the
                // resolution (triggered by Plan 11-04's NL intercept) — dispatch
                // now and record the result for future idempotent-resume.
                ApprovalOutcome::ApprovedPendingExecution(id) => {
                    let result = cap.invoke(args, ctx).await?;
                    self.approval_gate.record_executed(id, &result).await?;
                    Ok(TaggedValue {
                        data: result,
                        source: name.to_owned(),
                        trusted: cap.is_trusted(),
                    })
                }
                // Ciclo 2.1 (behavior change, §2): the owner explicitly
                // rejected this action. Typed `Err` — never the ambiguous
                // `Ok({awaiting_approval: true})` a still-undecided row gets.
                // `scope` travels with the error so the kernel tool-loop
                // (never this registry — a single-invocation policy boundary
                // has no notion of "the rest of the turn") can decide whether
                // to end the turn (`DenyScope::Turn`, product default) or
                // treat this as a per-call error and continue
                // (`DenyScope::Instance`).
                ApprovalOutcome::Rejected(scope) => {
                    Err(anyhow::anyhow!(BastionError::ApprovalDenied {
                        capability: name.to_owned(),
                        scope,
                    }))
                }
            };
        }

        // Dispatch
        let data = cap.invoke(args, ctx).await?;
        Ok(TaggedValue {
            data,
            source: name.to_owned(),
            trusted: cap.is_trusted(),
        })
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for ephemeral capabilities scoped to a single turn (SEAM #3).
///
/// Registers capabilities on `new()` and removes them on `Drop` — guarantees cleanup
/// even if the turn errors out. Capabilities that fail `register()` are not tracked
/// and will not be removed on drop.
///
/// SEC-05: also doubles as the quarantine guard via `quarantine()` — a SECOND,
/// mutually exclusive usage mode of the same RAII shape. `new()` is
/// ADDITIVE-ONLY (registers new ephemeral caps, restores the pre-existing set
/// untouched); `quarantine()` is SUBTRACTIVE (drains the ENTIRE pre-existing
/// set, leaving nothing visible, restoring all of it on drop). A single scope
/// instance is built via exactly one of these two constructors — never both.
pub struct TurnCapabilityScope<'a> {
    registry: &'a mut CapabilityRegistry,
    registered: Vec<String>,
    /// Populated ONLY by `quarantine()` — the full pre-existing capability
    /// set, drained for this scope's lifetime and restored in `Drop`. Always
    /// empty for a scope built via `new()`.
    quarantined: Vec<Arc<dyn Capability>>,
}

impl<'a> TurnCapabilityScope<'a> {
    /// Create the scope and register capabilities. Registration failures are silently
    /// skipped — those capabilities are not added to `registered` and won't be removed.
    pub fn new(registry: &'a mut CapabilityRegistry, caps: Vec<Arc<dyn Capability>>) -> Self {
        let mut registered = Vec::new();
        for cap in caps {
            let name = cap.name().to_owned();
            if registry.register(cap).is_ok() {
                registered.push(name);
            }
        }
        Self {
            registry,
            registered,
            quarantined: Vec::new(),
        }
    }

    /// Genuinely quarantine the turn (SEC-05): drains EVERY pre-existing
    /// capability so `list_tool_defs()` returns `[]` and `invoke()` errors
    /// "unknown capability" — genuinely invisible, closing the "zero tools
    /// ADDED vs zero tools VISIBLE" gap RESEARCH.md flagged in the previous
    /// additive-only `new()` constructor. Restored in full when the returned
    /// scope drops, even on an early return/panic-unwind.
    pub fn quarantine(registry: &'a mut CapabilityRegistry) -> Self {
        let quarantined = registry.drain_all();
        Self {
            registry,
            registered: Vec::new(),
            quarantined,
        }
    }
}

impl<'a> Drop for TurnCapabilityScope<'a> {
    fn drop(&mut self) {
        for name in &self.registered {
            self.registry.remove(name);
        }
        if !self.quarantined.is_empty() {
            self.registry.restore(std::mem::take(&mut self.quarantined));
        }
    }
}

/// Read-only access to the underlying registry while the scope is alive.
///
/// The scope holds the sole `&mut CapabilityRegistry` for its whole lifetime
/// (needed so `Drop` can always remove what it registered, even on early
/// return) — so callers that need to `invoke()` a capability while it is still
/// registered (e.g. Plan 08-03's `complete_structured_via_forced_tool_call`)
/// cannot reborrow the original `&mut` reference. `Deref` exposes the
/// immutable `invoke`/`list_*` surface without weakening that guarantee:
/// nothing here can register/remove a capability out from under the scope.
impl<'a> std::ops::Deref for TurnCapabilityScope<'a> {
    type Target = CapabilityRegistry;

    fn deref(&self) -> &Self::Target {
        self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::approval::SqliteApprovalGate;

    struct StubCap {
        name: String,
        schema: Value,
    }

    #[async_trait]
    impl Capability for StubCap {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            "stub"
        }
        fn input_schema(&self) -> &Value {
            &self.schema
        }
        async fn invoke(&self, _args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
            Ok(Value::Null)
        }
    }

    fn stub(name: &str) -> Arc<dyn Capability> {
        Arc::new(StubCap {
            name: name.to_owned(),
            schema: serde_json::json!({}),
        })
    }

    #[test]
    fn list_tool_defs_returns_capabilities_sorted_by_name() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("z")).unwrap();
        registry.register(stub("a")).unwrap();
        registry.register(stub("m")).unwrap();

        let names: Vec<String> = registry
            .list_tool_defs()
            .iter()
            .map(|d| d["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn list_tool_defs_is_byte_stable_across_register_remove_cycle() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("z")).unwrap();
        registry.register(stub("a")).unwrap();
        registry.register(stub("m")).unwrap();

        let before = serde_json::to_string(&registry.list_tool_defs()).unwrap();

        // Mirror TurnCapabilityScope: register an ephemeral 4th capability, then drop it.
        {
            let _scope = TurnCapabilityScope::new(&mut registry, vec![stub("ephemeral")]);
        }

        let after = serde_json::to_string(&registry.list_tool_defs()).unwrap();
        assert_eq!(
            before, after,
            "an intervening register+remove cycle must not perturb list_tool_defs() ordering"
        );
    }

    // --- Plan 11-02 (SEC-01): approval gate ------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Stub capability with a configurable `needs_approval()` and a call
    /// counter — proves whether the underlying `invoke()` actually dispatched.
    struct ApprovalStubCap {
        name: String,
        schema: Value,
        approval_required: bool,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Capability for ApprovalStubCap {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            "approval stub"
        }
        fn input_schema(&self) -> &Value {
            &self.schema
        }
        async fn invoke(&self, _args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({"dispatched": true}))
        }
        fn needs_approval(&self) -> bool {
            self.approval_required
        }
    }

    /// SEC-01 approval-gate tests exercise Policy 2 — they must clear Policy 1
    /// (egress) first. `None` is deny-on-ambiguity fail-closed (same as
    /// `LocalOnly` for a non-local stub), which would block these tests before
    /// the approval gate is ever reached; `CloudOk` always clears Policy 1
    /// (`check_egress`) so the assertions below actually test Policy 2.
    fn ctx_for(owner: &str) -> InvokeCtx {
        InvokeCtx {
            owner: owner.to_string(),
            privacy_tier: Some(PrivacyTier::CloudOk),
            allowed_tools: None,
        }
    }

    /// Registry wired with a real SqliteApprovalGate (temp sqlite db) plus one
    /// `needs_approval()==true` capability registered under "dangerous_action".
    async fn make_queue_registry() -> (
        tempfile::NamedTempFile,
        CapabilityRegistry,
        Arc<SqliteApprovalGate>,
        Arc<AtomicUsize>,
    ) {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        crate::session::SessionManager::new(&path)
            .init_schema()
            .await
            .expect("init_schema");
        let queue = Arc::new(SqliteApprovalGate::new(path));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut registry = CapabilityRegistry::new().with_approval_gate(queue.clone());
        registry
            .register(Arc::new(ApprovalStubCap {
                name: "dangerous_action".to_string(),
                schema: serde_json::json!({}),
                approval_required: true,
                calls: calls.clone(),
            }))
            .unwrap();
        (f, registry, queue, calls)
    }

    #[tokio::test]
    async fn needs_approval_true_without_queue_fails_closed() {
        let mut registry = CapabilityRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        registry
            .register(Arc::new(ApprovalStubCap {
                name: "dangerous_action".to_string(),
                schema: serde_json::json!({}),
                approval_required: true,
                calls: calls.clone(),
            }))
            .unwrap();

        let result = registry
            .invoke("dangerous_action", serde_json::json!({}), &ctx_for("alice"))
            .await;
        assert!(
            result.is_err(),
            "no queue wired must fail-closed deny, never silently dispatch"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "must never dispatch when denied"
        );
    }

    #[tokio::test]
    async fn needs_approval_true_with_queue_queues_instead_of_dispatching() {
        let (_f, registry, _queue, calls) = make_queue_registry().await;

        let result = registry
            .invoke(
                "dangerous_action",
                serde_json::json!({"x": 1}),
                &ctx_for("alice"),
            )
            .await
            .expect("first invoke must succeed with an awaiting-approval signal");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "must not dispatch on first call"
        );
        assert_eq!(result.data["awaiting_approval"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn needs_approval_true_dispatches_after_approval_and_records_executed() {
        let (_f, registry, queue, calls) = make_queue_registry().await;
        let args = serde_json::json!({"x": 1});

        registry
            .invoke("dangerous_action", args.clone(), &ctx_for("alice"))
            .await
            .expect("first invoke queues");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let pending = queue
            .pending_for_owner("alice")
            .await
            .expect("pending_for_owner");
        assert_eq!(pending.len(), 1);
        let id = pending[0].id;
        queue.approve("alice", id).await.expect("approve");

        let result = registry
            .invoke("dangerous_action", args, &ctx_for("alice"))
            .await
            .expect("second invoke after approval must dispatch");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must dispatch exactly once after approval"
        );
        assert_eq!(result.data, serde_json::json!({"dispatched": true}));

        let still_pending = queue
            .pending_for_owner("alice")
            .await
            .expect("pending_for_owner 2");
        assert!(
            still_pending.is_empty(),
            "row must no longer be pending after execution (record_executed ran)"
        );
    }

    #[tokio::test]
    async fn needs_approval_false_default_dispatches_immediately_unaffected() {
        let mut registry = CapabilityRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        registry
            .register(Arc::new(ApprovalStubCap {
                name: "safe_action".to_string(),
                schema: serde_json::json!({}),
                approval_required: false,
                calls: calls.clone(),
            }))
            .unwrap();

        let result = registry
            .invoke("safe_action", serde_json::json!({}), &ctx_for("alice"))
            .await
            .expect("default needs_approval()==false must dispatch immediately");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.data, serde_json::json!({"dispatched": true}));
    }

    // --- Plan 11-07 (SEC-04): TaggedValue + Capability::is_trusted() -----------

    /// Stub capability with a configurable `is_local()` and the DEFAULT
    /// `is_trusted()` (mirrors `is_local()`, unmodified).
    struct TrustStubCap {
        name: String,
        schema: Value,
        local: bool,
    }

    #[async_trait]
    impl Capability for TrustStubCap {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            "trust stub"
        }
        fn input_schema(&self) -> &Value {
            &self.schema
        }
        fn is_local(&self) -> bool {
            self.local
        }
        async fn invoke(&self, _args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
            Ok(serde_json::json!({"own": true}))
        }
    }

    /// Test 1: a stub with `is_local()==true` and default `is_trusted()`
    /// invoked via `CapabilityRegistry::invoke()` returns
    /// `TaggedValue{trusted: true, source: <cap name>, data: <cap's own Value>}`.
    #[tokio::test]
    async fn invoke_wraps_local_capability_as_trusted_tagged_value() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(Arc::new(TrustStubCap {
                name: "local_cap".to_string(),
                schema: serde_json::json!({}),
                local: true,
            }))
            .unwrap();

        let tagged = registry
            .invoke(
                "local_cap",
                serde_json::json!({}),
                &InvokeCtx {
                    owner: "alice".to_string(),
                    privacy_tier: Some(PrivacyTier::LocalOnly),
                    allowed_tools: None,
                },
            )
            .await
            .expect("local capability must dispatch under LocalOnly");

        assert!(
            tagged.trusted,
            "is_local()==true must default is_trusted() to true"
        );
        assert_eq!(tagged.source, "local_cap");
        assert_eq!(tagged.data, serde_json::json!({"own": true}));
    }

    /// Test 2: a stub with `is_local()==false` and default `is_trusted()`
    /// returns `trusted: false`.
    #[tokio::test]
    async fn invoke_wraps_non_local_capability_as_untrusted_tagged_value() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(Arc::new(TrustStubCap {
                name: "remote_cap".to_string(),
                schema: serde_json::json!({}),
                local: false,
            }))
            .unwrap();

        let tagged = registry
            .invoke(
                "remote_cap",
                serde_json::json!({}),
                &InvokeCtx {
                    owner: "alice".to_string(),
                    privacy_tier: Some(PrivacyTier::CloudOk),
                    allowed_tools: None,
                },
            )
            .await
            .expect("non-local capability must dispatch under CloudOk");

        assert!(
            !tagged.trusted,
            "is_local()==false must default is_trusted() to false"
        );
        assert_eq!(tagged.source, "remote_cap");
    }

    // --- Plan 11-08 (SEC-05): drain_all/restore + TurnCapabilityScope::quarantine() ---

    #[test]
    fn drain_all_returns_all_capabilities_and_empties_registry() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("a")).unwrap();
        registry.register(stub("b")).unwrap();
        registry.register(stub("c")).unwrap();

        let drained = registry.drain_all();
        assert_eq!(drained.len(), 3);
        assert!(
            registry.is_empty(),
            "drain_all must leave the registry empty"
        );
    }

    #[test]
    fn restore_reregisters_every_drained_capability_byte_identical_list() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("z")).unwrap();
        registry.register(stub("a")).unwrap();
        registry.register(stub("m")).unwrap();

        let before = serde_json::to_string(&registry.list_tool_defs()).unwrap();

        let drained = registry.drain_all();
        assert!(registry.is_empty());

        registry.restore(drained);

        let after = serde_json::to_string(&registry.list_tool_defs()).unwrap();
        assert_eq!(
            before, after,
            "restore() must reproduce the exact same set (list_tool_defs already sorts by name)"
        );
    }

    /// Test 3: `TurnCapabilityScope::quarantine(&mut registry)` — while the
    /// scope is alive, `list_tool_defs()` returns `[]` and `invoke()` errors
    /// "unknown capability" for a PREVIOUSLY-registered name — genuinely
    /// invisible, not just "no new tools added" (the exact gap RESEARCH.md
    /// flagged). Uses the scope's `Deref` (not `registry` directly — the
    /// scope holds the sole `&mut` for its lifetime).
    #[tokio::test]
    async fn quarantine_makes_every_capability_genuinely_invisible_while_alive() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("a")).unwrap();
        registry.register(stub("b")).unwrap();
        registry.register(stub("c")).unwrap();

        {
            let scope = TurnCapabilityScope::quarantine(&mut registry);
            assert!(
                scope.list_tool_defs().is_empty(),
                "quarantine must make list_tool_defs() return [] — not just 'no new tools added'"
            );
            let result = scope
                .invoke(
                    "a",
                    serde_json::json!({}),
                    &InvokeCtx {
                        owner: "alice".to_string(),
                        privacy_tier: Some(PrivacyTier::CloudOk),
                        allowed_tools: None,
                    },
                )
                .await;
            assert!(
                result.is_err(),
                "a previously-registered capability must be genuinely uninvokable during quarantine"
            );
        }
    }

    /// Test 4: when the `quarantine()`-created scope drops, every
    /// originally-registered capability is invocable again, identically to
    /// before quarantine began.
    #[tokio::test]
    async fn quarantine_restores_every_capability_on_drop() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("a")).unwrap();
        registry.register(stub("b")).unwrap();
        registry.register(stub("c")).unwrap();
        let before = serde_json::to_string(&registry.list_tool_defs()).unwrap();

        {
            let _scope = TurnCapabilityScope::quarantine(&mut registry);
        }

        let after = serde_json::to_string(&registry.list_tool_defs()).unwrap();
        assert_eq!(
            before, after,
            "every originally-registered capability must be restored, identical to before quarantine"
        );

        let result = registry
            .invoke(
                "a",
                serde_json::json!({}),
                &InvokeCtx {
                    owner: "alice".to_string(),
                    privacy_tier: Some(PrivacyTier::CloudOk),
                    allowed_tools: None,
                },
            )
            .await;
        assert!(
            result.is_ok(),
            "capability must be invocable again after quarantine scope drops"
        );
    }

    // --- Persona contract v2: Policy 0 tool-authority gate ---------------------

    fn allowed_set(names: &[&str]) -> Option<Arc<HashSet<String>>> {
        Some(Arc::new(names.iter().map(|s| s.to_string()).collect()))
    }

    #[tokio::test]
    async fn invoke_denies_tool_not_in_allowed_set() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("memory_search")).unwrap();

        let result = registry
            .invoke(
                "memory_search",
                serde_json::json!({}),
                &InvokeCtx {
                    owner: "alice".to_string(),
                    privacy_tier: Some(PrivacyTier::CloudOk),
                    allowed_tools: allowed_set(&["goal_create"]),
                },
            )
            .await;

        let err = result.expect_err(
            "a tool outside the persona's allowed_tools set must be denied, never dispatched",
        );
        assert!(
            matches!(
                err.downcast_ref::<BastionError>(),
                Some(BastionError::ToolNotAllowed { capability }) if capability == "memory_search"
            ),
            "expected Err(BastionError::ToolNotAllowed), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn invoke_allows_any_tool_when_allowed_tools_is_none() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("memory_search")).unwrap();

        let result = registry
            .invoke(
                "memory_search",
                serde_json::json!({}),
                &InvokeCtx {
                    owner: "alice".to_string(),
                    privacy_tier: Some(PrivacyTier::CloudOk),
                    allowed_tools: None,
                },
            )
            .await;

        assert!(
            result.is_ok(),
            "allowed_tools: None must stay unrestricted (legacy/back-compat persona contract)"
        );
    }

    #[tokio::test]
    async fn invoke_allows_tool_present_in_allowed_set() {
        let mut registry = CapabilityRegistry::new();
        registry.register(stub("memory_search")).unwrap();

        let result = registry
            .invoke(
                "memory_search",
                serde_json::json!({}),
                &InvokeCtx {
                    owner: "alice".to_string(),
                    privacy_tier: Some(PrivacyTier::CloudOk),
                    allowed_tools: allowed_set(&["memory_search", "goal_create"]),
                },
            )
            .await;

        assert!(
            result.is_ok(),
            "a tool explicitly present in allowed_tools must dispatch normally"
        );
    }

    #[test]
    fn check_tool_allowed_denies_outside_set() {
        let allowed = allowed_set(&["a"]);
        assert!(check_tool_allowed(&allowed, "b").is_err());
    }

    #[test]
    fn check_tool_allowed_allows_none() {
        assert!(check_tool_allowed(&None, "anything").is_ok());
    }

    #[test]
    fn check_tool_allowed_allows_member_of_set() {
        let allowed = allowed_set(&["a", "b"]);
        assert!(check_tool_allowed(&allowed, "b").is_ok());
    }
}
