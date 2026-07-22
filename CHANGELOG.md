# Changelog

All notable changes to `bastion-core` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[docs/VERSIONING.md](docs/VERSIONING.md) (per-crate, not a single workspace
version).

## Unreleased

### Added

- Persona contract v2: SOUL.md front-matter (`bastion-personas::persona::soul::PersonaFront`)
  gains `objectives`, `goals`, `tools` (capability allowlist), and `scope`,
  all `#[serde(default)]` so pre-v2 SOUL.md files keep parsing unchanged.
  `PersonaFront::validate()` reports every contract-completeness problem
  (empty objectives/goals, missing scope, a suspicious `Some([])` tools
  list) without turning a validation problem into a parse failure; the
  registry loader now `tracing::warn!`s each problem per persona in
  addition to its existing skip-with-warn behavior on real parse errors.
- `bastion_types::Persona` carries the same four fields (plus a `Default`
  impl so existing struct-literal construction sites only need
  `..Default::default()`, not four new explicit fields).
- Per-persona tool-authority enforcement gate (Policy 0):
  `CapabilityRegistry::invoke` denies any capability name outside the
  dispatching persona's resolved `tools:` allowlist BEFORE the egress/
  approval policies run (`InvokeCtx::allowed_tools`, new
  `capability::check_tool_allowed`, `BastionError::ToolNotAllowed`). The
  empty-registry MCP-bypass path in `agent::loop_::AgentLoop::dispatch_tool_loop`
  applies the identical check inline (no `Capability`/`InvokeCtx` of its
  own to carry the gate through) — see `docs/SECURITY-INVARIANTS.md` §9.
  `allowed_tools: None` (no `tools:` declared, or no persona resolved)
  stays unrestricted: every existing persona and every non-persona-scoped
  `InvokeCtx` construction site keeps working exactly as before.

### Changed

- **Breaking** (not caught by the mechanical `docs/api-baseline` check,
  which tracks item presence/name, not signatures — see
  `docs/VERSIONING.md` §2): `agent::ports::TurnKernel::run_tool_loop` gains
  a new `allowed_tools: Option<Arc<HashSet<String>>>` parameter; every
  call site and the sole implementer (`AgentLoop`) are updated in the same
  change. `bastion-types`, `bastion-runtime`, and `bastion-personas`
  advance to `0.2.0` for this and the `Persona`/`InvokeCtx` field additions
  above (exhaustive external struct literals against either type need
  `..Default::default()` now).

## 0.2.0 — 2026-07-20

### Added

- Adaptive Execution task contract in `bastion-runtime`: neutral
  `Respond`/`Act`/`Pursue` modes, owner-scoped durable `TaskCase`s, attempts,
  evidence, verdicts, budgets, lifecycle events, storage, verification, and
  parent/child orchestration behind host-replaceable ports.
- Deployment-context types and outcome attribution for procedural beliefs.
- Core README documentation for the task contract and its product boundary.

### Changed

- `bastion-runtime`, `bastion-types`, and `bastion-cognition` advance to
  `0.1.1` for additive public APIs.

### Fixed

- Procedural-learning reinforcement no longer deposits negative outcomes.

### Removed

- Breaking public API removals advance `bastion-mcp` and `bastion-providers`
  to `0.2.0`: deprecated MCP helper entry points and the legacy terminal-agent
  provider bridge are no longer available.

## 0.1.0 — 2026-07-14

### Added

Initial release — `bastion-core` extracted as a standalone repository from
the original `bastion` monorepo, carrying the full development history of
the substrate crates:

- `bastion-types` — leaf types, IDs, errors, versioned-context artifacts
- `bastion-runtime` — agent loop, capabilities, context, sessions, hooks,
  the `Provider`/`Memory` traits, every kernel port
- `bastion-agent-runtime` — `AgentRuntime` contract + adapters (Codex
  app-server, ACP/`acpx`)
- `bastion-memory` — beliefs, provenance, temporality, contestable-memory
  store
- `bastion-cognition` — Dream/consolidation, procedural learning, goals,
  proactivity, Cabinet deliberation
- `bastion-personas` — `AgentDefinition`/personas, routing, deliberation
- `bastion-mesh` — mesh transport, agent identity, `.af` interop, scheduler
- `bastion-mcp` — MCP client/server
- `bastion-providers` — concrete model providers + auth resolution
- `bastion-extension-protocol` — extension manifests, permissions, trust
  tiers, lockfiles
- `bastion-extension-wasm` — `wasmi`-backed WASM/WASI extension sandbox

`bastion-agent` (the personal-agent product) is the flagship consumer and
continues in its own repository, depending on these crates.
