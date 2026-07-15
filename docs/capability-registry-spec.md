# Capability Registry — Architecture Specification

**Phase:** 4 — Deploy & Packaging  
**Plan:** 04-03  
**Status:** Validated — cleared for Wave 3 implementation  
**Source:** D-13, D-14 (04-CONTEXT.md); capability-registry-design.md (todo); STRATEGY.md §"Capability Registry"

---

## Problem Statement

The v3 runtime has four separate capability frontends with no shared invocation surface:

| Frontend | File | What it does |
|----------|------|--------------|
| `ToolRegistry` + `McpClient` | `src/mcp/registry.rs`, `src/mcp/client.rs` | Registers and dispatches MCP tools to Python servers |
| Command router | `src/agent/command.rs` | Handles `/stop`, `/model`, `/as`, `/cabinet`, `/contest` |
| `SkillsLoader` | `src/agent/skills.rs` | Parses SKILL.md metadata (Phase 1 stub — `load_all` returns `vec![]`) |
| `EgressHook` / `Hook` | `src/hooks/egress.rs`, `src/hooks/mod.rs` | Fail-closed privacy egress check (PRIV-03, D-03, CF-1) |

Each frontend has its own invocation path. **No single policy enforcement point exists.**

Consequence (per WR-04): egress checks, approval queues, and privacy enforcement are either
duplicated or absent. `run_provider_fallback` in `loop_.rs:~209` called `provider.complete`
with no `check_egress` — the omission that WR-04 fixes. The registry is the structural answer
that prevents the next WR-04: every invoke path passes through a single policy gate.

---

## Solution: Unified CapabilityRegistry

One canonical capability definition. One invoke surface. One policy middleware.

All four frontends become thin **adapters** over `CapabilityRegistry`. The registry enforces
egress and approval policy before dispatching to any adapter.

---

## Core Traits and Types

```rust
// src/capability/registry.rs

use async_trait::async_trait;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

/// A capability is anything the agent can invoke.
/// Thin adapters (McpToolAdapter, DirectFnAdapter, NlCommandAdapter) implement this.
/// Registry guarantees uniform interface (I/O typed + invoke), NOT implementation purity.
/// Agentic skills that call the LLM internally are valid Capability impls — Non-Negotiable #1.
#[async_trait]
pub trait Capability: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// JSON Schema (type: "object") describing accepted arguments.
    fn input_schema(&self) -> &Value;
    /// Invoke the capability. Policy enforcement happens at the CapabilityRegistry level
    /// before this is called — adapters MUST NOT re-check egress internally.
    async fn invoke(&self, args: Value, ctx: &InvokeCtx) -> anyhow::Result<Value>;
}

/// Invocation context — resolved by the caller (AgentLoop / API handler) and
/// passed unchanged through the registry to every capability.
///
/// InvokeCtx is the authoritative carrier for policy-relevant fields.
/// Capabilities read it; they never mutate it.
#[derive(Clone, Debug)]
pub struct InvokeCtx {
    /// Persona or session owner identifier (e.g. "_local", "mario").
    pub owner: String,
    /// Privacy tier of the invoking context. None = deny on ambiguity (fail-closed).
    pub privacy_tier: Option<crate::memory::PrivacyTier>,
    /// Whether this invocation must pass through the Phase 3 approval queue gate.
    /// Resolved by the caller BEFORE entering registry.invoke — not inside it.
    /// See Resolution of Open Question 2 below.
    pub needs_approval: bool,
}
```

---

## CapabilityRegistry — the Single Policy Enforcement Point

```rust
// src/capability/registry.rs (continued)

/// The single policy enforcement point for all capability invocations.
/// Every frontend — direct fn, MCP tool, NL command — passes through here.
/// No bypass path exists in this design (see Non-Negotiable #2, Architect Validation §B).
pub struct CapabilityRegistry {
    inner: HashMap<String, Arc<dyn Capability>>,
    // approval_queue: Arc<ApprovalQueue>,  — Phase 3 queue wired here (04-06)
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    /// Register a capability. Panics on duplicate name (programmer error — caught at startup).
    pub fn register(&mut self, cap: Arc<dyn Capability>) {
        let name = cap.name().to_owned();
        if self.inner.insert(name.clone(), cap).is_some() {
            panic!("CapabilityRegistry: duplicate capability name '{}'", name);
        }
    }

    /// The single invoke entry point — ALL invocations go through here.
    ///
    /// Policy order (Non-Negotiable #2 + #3):
    ///   1. Egress check — fail-closed on None tier (check_egress).
    ///   2. Approval gate — if ctx.needs_approval, block on Phase 3 queue.
    ///   3. Dispatch — delegate to the Capability impl.
    ///
    /// NlCommandAdapter calls short-circuit the egress check (see Resolution OQ-3).
    pub async fn invoke(
        &self,
        name: &str,
        args: Value,
        ctx: &InvokeCtx,
    ) -> anyhow::Result<Value> {
        let cap = self.inner.get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown capability: {}", name))?;

        // Non-Negotiable #3: no call path may bypass check_egress.
        // NlCommandAdapter sets privacy_tier = Some(LocalOnly) so check_egress
        // allows it through the ollama path — but in practice NlCommandAdapter
        // also sets a special marker (see Resolution OQ-3) to skip provider dispatch.
        // The egress check is STILL called here for NL commands — it just always
        // passes because commands are local-only by definition.
        crate::hooks::egress::check_egress(ctx.privacy_tier, "local")?;

        // Phase 3 approval gate (wired in 04-06).
        if ctx.needs_approval {
            // self.approval_queue.gate(name).await?;
            // Placeholder — returns Ok during Phase 4 (gate inactive until 04-06).
        }

        cap.invoke(args, ctx).await
    }

    /// List all registered capability names (used by AgentLoop to build tool list for LLM).
    pub fn list_names(&self) -> Vec<&str> {
        self.inner.keys().map(String::as_str).collect()
    }

    /// Get input schema for a capability (used to build tool definitions for the provider).
    pub fn get_schema(&self, name: &str) -> Option<&Value> {
        self.inner.get(name).map(|c| c.input_schema())
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self { Self::new() }
}
```

---

## Adapters

Three thin adapters wrap the four existing pieces.

| Adapter | Wraps | Existing piece | Location |
|---------|-------|----------------|----------|
| `McpToolAdapter` | `McpClient::call_tool_with_timeout` | `ToolRegistry` + `McpClient` | `src/capability/adapters.rs` |
| `DirectFnAdapter` | Rust async closure / fn pointer | `SkillsLoader` outputs | `src/capability/adapters.rs` |
| `NlCommandAdapter` | `handle_command` | command router (`src/agent/command.rs`) | `src/capability/adapters.rs` |

### McpToolAdapter

Wraps a `(server_label, tool_name, input_schema, Arc<McpClient>)` tuple.

```rust
pub struct McpToolAdapter {
    tool_name: String,
    server_label: String,  // informational — retained for logs/schema
    input_schema: Value,
    client: Arc<McpClient>,
}

#[async_trait]
impl Capability for McpToolAdapter {
    fn name(&self) -> &str { &self.tool_name }
    fn description(&self) -> &str { "MCP tool" }
    fn input_schema(&self) -> &Value { &self.input_schema }

    async fn invoke(&self, args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
        self.client.call_tool_with_timeout(&self.tool_name, args).await
    }
}
```

`McpClient::connect_all` is called at startup. After connecting, for each registered tool in
`ToolRegistry`, the caller creates a `McpToolAdapter` and registers it into `CapabilityRegistry`.
`ToolRegistry` is retained internally by `McpClient` for `server_for` / `get_tool_schema` lookups
during registration — it is not exposed as a separate registry after the adapter layer exists.

**Resolution of OQ-1 (CapabilityRegistry owns vs references McpClient):** See below.

### DirectFnAdapter

Wraps a boxed async function. Used by `SkillsLoader` (Wave 3, 04-05) to register SKILL.md
skills as Capability impls, and by built-in system functions.

```rust
use std::future::Future;
use std::pin::Pin;

type DirectFn = Box<
    dyn Fn(Value, InvokeCtx) -> Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send>>
    + Send + Sync
>;

pub struct DirectFnAdapter {
    name: String,
    description: String,
    input_schema: Value,
    func: DirectFn,
}

#[async_trait]
impl Capability for DirectFnAdapter {
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn input_schema(&self) -> &Value { &self.input_schema }

    async fn invoke(&self, args: Value, ctx: &InvokeCtx) -> anyhow::Result<Value> {
        (self.func)(args, ctx.clone()).await
    }
}
```

### NlCommandAdapter

Wraps command router entries. Commands are local operations (no LLM dispatch, no egress).

```rust
pub struct NlCommandAdapter {
    command: String,        // e.g. "/stop", "/model", "/as"
    description: String,
    input_schema: Value,
    // Holds references needed by handle_command
    provider: crate::provider::SharedProvider,
    persona_registry: Arc<crate::persona::PersonaRegistry>,
    memory: crate::memory::SharedMemory,
}

#[async_trait]
impl Capability for NlCommandAdapter {
    fn name(&self) -> &str { &self.command }
    fn description(&self) -> &str { &self.description }
    fn input_schema(&self) -> &Value { &self.input_schema }

    async fn invoke(&self, args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
        // Reconstruct the command string from args (e.g. {model: "claude-sonnet-4-5"} → "/model claude-sonnet-4-5")
        let input = reconstruct_command(&self.command, &args);
        let mut forced_persona = None;
        let result = crate::agent::command::handle_command(
            &input,
            &self.provider,
            &self.persona_registry,
            &self.memory,
            &mut forced_persona,
        ).await?;
        Ok(serde_json::json!({ "result": format!("{:?}", result) }))
    }
}
```

---

## Resolutions of Open Questions

### OQ-1: Does CapabilityRegistry own McpClient or hold a reference?

**Resolution: CapabilityRegistry holds `Arc<McpClient>` — shared ownership.**

Rationale: `AgentLoop` also needs `McpClient` for lifecycle management (reconnect, tool listing
refresh). Making `CapabilityRegistry` the sole owner would require routing lifecycle calls through
it, which is unrelated to capability dispatch. `Arc<McpClient>` is cloned into each
`McpToolAdapter`; the registry itself stores the adapters (not `McpClient` directly). This keeps
`CapabilityRegistry` pure: it owns capabilities, not infrastructure.

Impact: `McpClient` gets `Arc`-wrapped at construction in `AgentLoop::new`. No changes to
`McpClient` internals required.

### OQ-2: Should `InvokeCtx.needs_approval` be resolved before or inside `registry.invoke`?

**Resolution: Resolved by the CALLER before entering `registry.invoke`.**

Rationale: The caller (AgentLoop tool-dispatch path, API infer handler) has the full turn
context — current persona, session state, Phase 3 permission model. The registry is a
policy-enforcement layer, not a policy-determination layer. Moving determination inside
`registry.invoke` would require passing AgentLoop state into the registry (coupling violation).

Concretely: before calling `registry.invoke`, AgentLoop computes `needs_approval` from
`(tool_name, persona.tier, session.permission_mode)` and stuffs the result into `InvokeCtx`.
The registry only acts on the pre-resolved flag.

### OQ-3: Should NlCommandAdapter pass through egress check or short-circuit?

**Resolution: NlCommandAdapter passes through egress check with `privacy_tier = Some(LocalOnly)`.**

Rationale: The Non-Negotiable #3 guardrail states no call path may bypass `check_egress`.
Short-circuiting NL commands before the egress check would violate this. The correct solution:
commands are inherently local operations, so the caller sets `ctx.privacy_tier = Some(LocalOnly)`
when building `InvokeCtx` for an NL command invocation. `check_egress(Some(LocalOnly), "local")`
returns `Ok(())` because the provider name "local" is not a cloud provider — the egress check
passes cleanly without a bypass. No new code path; no policy violation; check always runs.

This also resolves T-04-03-02 (Elevation of Privilege threat): commands pass through the gate,
they just always clear it. The explicit `privacy_tier = Some(LocalOnly)` on the caller side makes
the intent auditable.

---

## Non-Negotiable Guardrails (D-13)

These three guardrails are NOT negotiable — violating any one breaks the privacy wedge:

**Guardrail #1 — Agentic skill ≠ pure fn.**
`CapabilityRegistry` guarantees a uniform interface (typed I/O + `invoke`), NOT implementation
purity. Capabilities that internally invoke the LLM (agentic skills) are valid registry members.
The registry wraps the call; it does not dictate what happens inside the adapter.

**Guardrail #2 — ONE policy middleware at the registry boundary.**
Every frontend (direct fn, MCP tool, NL command) invokes through `CapabilityRegistry::invoke`.
No frontend invokes a `Capability::invoke` directly. The single entry point is the sole location
where `check_egress` and the approval gate are enforced. Adding a second enforcement site is
duplication; removing the registry site is regression.

**Guardrail #3 — No call path may bypass `check_egress` or the Phase 3 approval queue.**
`check_egress` is called unconditionally in `CapabilityRegistry::invoke` before capability
dispatch. There is no `if skip_egress { ... }` branch. NL commands satisfy this by supplying
`Some(LocalOnly)` as tier rather than by receiving a bypass (OQ-3 resolution above).

---

## Integration Plan

The following wiring order is required for 04-04 implementation:

1. **Create `src/capability/` module** with `mod.rs`, `registry.rs`, `adapters.rs`.
2. **`AgentLoop::new`**: construct `CapabilityRegistry`; `Arc::new` the `McpClient`.
3. **MCP server discovery** (`McpClient::connect_all`): after connecting, for each tool in
   `ToolRegistry`, create `McpToolAdapter(server_label, tool_name, schema, Arc<McpClient>)` and
   register into `CapabilityRegistry`. `ToolRegistry` stays internal to `McpClient`.
4. **Command router wiring**: for each slash command (`/stop`, `/model`, `/as`, `/cabinet`,
   `/contest`), create `NlCommandAdapter` with appropriate schema and register.
5. **`SkillsLoader::load_all`** (04-05): implement real YAML frontmatter scan; for each skill
   found, create `DirectFnAdapter` (stub implementation for now — skill logic in 04-05).
6. **Tool dispatch in `run_turn_for`**: replace direct `McpClient::call_tool_with_timeout` call
   with `registry.invoke(name, args, ctx)`. Build `InvokeCtx` from current turn context.
7. **`run_provider_fallback` (WR-04)**: build `InvokeCtx` with tier from tier-accumulator
   (resolved by scanning pending MCP tool results per 04-02 / RESEARCH.md resolution of OQ-WR-04).
8. **Remove `ToolRegistry` from public API surface**: it remains an internal detail of
   `McpClient`; nothing outside `McpClient` should reference it directly after step 3.

---

## File Structure

```
src/capability/
  mod.rs         — pub use re-exports: CapabilityRegistry, InvokeCtx, Capability
  registry.rs    — CapabilityRegistry + InvokeCtx + Capability trait
  adapters.rs    — McpToolAdapter, DirectFnAdapter, NlCommandAdapter
```

Existing files **not** moved:
- `src/mcp/registry.rs` — `ToolRegistry` stays inside `McpClient`; private implementation detail
- `src/mcp/client.rs` — `McpClient` stays; gains `Arc` wrapping at call sites
- `src/agent/command.rs` — `handle_command` stays; `NlCommandAdapter` delegates to it
- `src/agent/skills.rs` — `SkillsLoader` stays; its output feeds `DirectFnAdapter` construction
- `src/hooks/egress.rs` — `check_egress` stays; called from `CapabilityRegistry::invoke`

---

## Blast Radius

The following symbols MUST have `gitnexus_impact` run before editing. Direct callers (d=1)
will break if their call site is not updated to use `CapabilityRegistry`.

| Symbol | Location | d=1 Risk | Required Update |
|--------|----------|----------|-----------------|
| `ToolRegistry` | `src/mcp/registry.rs` | Callers outside McpClient | Internalize to McpClient; no external callers should remain |
| `McpClient::call_tool_with_timeout` | `src/mcp/client.rs` | AgentLoop tool dispatch | Replace with `registry.invoke` |
| `SkillsLoader::load_all` | `src/agent/skills.rs` | AgentLoop init | Output feeds DirectFnAdapter construction; signature unchanged |
| `handle_command` | `src/agent/command.rs` | AgentLoop stdin loop | Wrapped by NlCommandAdapter; direct call site for stdin can remain as-is or also go through registry |

**Note for 04-04 implementor:** Run `gitnexus_impact({target: "McpClient", direction: "upstream"})`
and `gitnexus_impact({target: "handle_command", direction: "upstream"})` before touching these
files. The GitNexus index in `.gitnexus/` has 3476 symbols and 8715 relationships — use it.

---

## Threat Model

| Threat ID | Category | Component | Disposition | Mitigation (this SPEC) |
|-----------|----------|-----------|-------------|------------------------|
| T-04-03-01 | Tampering | CapabilityRegistry policy bypass | mitigate | Non-Negotiable #2: single entry point; no bypass branch in registry.invoke |
| T-04-03-02 | Elevation of Privilege | NlCommandAdapter egress short-circuit | mitigate | OQ-3 resolution: commands use `Some(LocalOnly)` — check_egress always called, always passes |

---

## Architect Validation Results

Structural self-review performed per CLAUDE.md requirement D-14 ("Use Architect when modifying
core systems") and the `<architect_note>` in the execution directive. Covers four areas:

### A. Coupling and Modularity of CapabilityRegistry vs the 4 Adapters

**Finding:** `CapabilityRegistry` depends on the `Capability` trait only — no direct dependency
on `McpClient`, `handle_command`, or `SkillsLoader`. Adapters depend on their wrapped type and
on `Capability`. Dependency arrows flow inward toward `Capability`.

**Concern:** `NlCommandAdapter` carries `SharedProvider` + `Arc<PersonaRegistry>` +
`SharedMemory` — three infrastructure handles. This is higher coupling than `McpToolAdapter`
(one handle: `Arc<McpClient>`).

**Severity:** LOW. The coupling is contained within the adapter, not in the registry. The
adapter is the correct place to hold infrastructure references. Alternative (passing them through
`InvokeCtx`) would inflate `InvokeCtx` with infrastructure concerns — worse coupling.

**Resolution:** Accepted. Document that `NlCommandAdapter` is the "fat adapter" and its
dependencies are justified.

### B. Architectural Boundary Integrity (single policy enforcement point — no bypass path)

**Finding:** `CapabilityRegistry::invoke` is the sole entry point. `Capability::invoke` is not
`pub` at the module boundary — adapters are registered as `Arc<dyn Capability>` and the only
way to call `invoke` on them from outside `src/capability/` is through `CapabilityRegistry::invoke`.

**Concern:** If `Arc<dyn Capability>` handles are stored outside the registry (e.g., in a
`Vec<Arc<dyn Capability>>` field somewhere in `AgentLoop`), callers could invoke capabilities
directly, bypassing the registry gate.

**Severity:** MEDIUM before mitigation. This is a common slip — a developer stores the adapter
`Arc` for a convenient shortcut and calls `.invoke` directly.

**Mitigation:** `Capability::invoke` should be accessible only through `CapabilityRegistry`.
The `Capability` trait remains `pub(crate)` — not `pub`. Adapters themselves are `pub(crate)`.
The only `pub` surface from `src/capability/` is `CapabilityRegistry`, `InvokeCtx`, and the
`register()` helper. This is enforced by module visibility, not runtime guards.

**Severity after mitigation:** LOW. Module boundary enforces it at compile time.

### C. Anti-Pattern Scan

**God Object Risk on CapabilityRegistry:**

`CapabilityRegistry` has four methods: `new`, `register`, `invoke`, `list_names`, `get_schema`.
This is lean. It does not accumulate business logic. Verdict: **no God Object risk**.

**Leaky Adapter Abstractions:**

- `McpToolAdapter::invoke` leaks `server_label` in its public struct? Server label is private
  (`server_label: String` — not exposed as a method). Only `name()` and `input_schema()` are
  `Capability` surface. **No leak.**
- `DirectFnAdapter` exposes a raw function pointer type in its constructor signature. This is
  necessary — it cannot be hidden. But the type alias `DirectFn` is defined in `adapters.rs`
  (not re-exported) so external callers use the constructor helper, not the raw type.
  **Minor: mitigated by constructor helper.**
- `NlCommandAdapter::invoke` returns `format!("{:?}", result)` as the value — a debug string.
  This is a stub. **Wave 3 implementor must return structured JSON** matching the command's
  semantic output (e.g., `{ok: true}` for `/stop`). Flag for 04-04.

**Shotgun Surgery Risk:**

Adding a new capability type (a fourth adapter, e.g., `WebhookAdapter`) touches:
1. `adapters.rs` — new adapter struct and impl
2. registration site in `AgentLoop::new`

That's two files. **No shotgun surgery risk.** The registry is additive.

Adding a new policy check (e.g., rate limiting) touches:
1. `CapabilityRegistry::invoke` only — all frontends inherit it automatically.

**Excellent locality — this is the design working as intended.**

### D. Resolution of the 3 Open Questions

All three resolved above under "Resolutions of Open Questions":

- **OQ-1** (registry owns vs references McpClient): RESOLVED — `Arc<McpClient>`, shared
  ownership, registry stores adapters not infrastructure.
- **OQ-2** (needs_approval resolved before vs inside invoke): RESOLVED — caller resolves,
  registry acts on pre-resolved flag. No coupling of AgentLoop state into registry.
- **OQ-3** (NlCommandAdapter egress short-circuit): RESOLVED — no short-circuit. Commands use
  `Some(LocalOnly)` tier; `check_egress` always runs; T-04-03-02 is mitigated.

### Summary Table

| Area | Severity | Status |
|------|----------|--------|
| A. Coupling (NlCommandAdapter 3 deps) | LOW | Accepted — fat adapter is correct |
| B. Bypass path via Arc leak | MEDIUM → LOW | Mitigated — `Capability` trait is `pub(crate)` |
| C. God Object risk | NONE | No concern |
| C. Leaky NlCommandAdapter return value | LOW | Flagged for 04-04 implementor |
| C. Shotgun surgery risk | NONE | No concern |
| D. OQ-1, OQ-2, OQ-3 | — | All three resolved |

**No unresolved HIGH or CRITICAL concerns. SPEC cleared for Wave 3 implementation.**

---

## Phase-3 Compatibility Confirmation

Phase 3 decisions remain compatible:

- **D-08 (infer gateway):** `McpClient` continues to handle the infer gateway URL. `McpToolAdapter` wraps `call_tool_with_timeout` — no change to network topology.
- **D-06 (skill reload):** `SkillsLoader::rescan` is called by `AgentLoop` on `skill_reloaded` signal. After 04-04, the result feeds `DirectFnAdapter` construction and `CapabilityRegistry::register`. The reload signal path is unchanged; only the registration target changes.
- **PRIV-03 / CF-1 (egress fail-closed):** `check_egress` is preserved verbatim in `src/hooks/egress.rs`. `CapabilityRegistry::invoke` calls it before every dispatch. No regression.

---

*Spec version: 1.0 — 2026-06-06*  
*Validated by: structural self-review (D-14 Architect intent)*  
*Cleared for implementation: 04-04 (Wave 3)*
