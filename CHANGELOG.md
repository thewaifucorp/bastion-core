# Changelog

All notable changes to `bastion-core` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[docs/VERSIONING.md](docs/VERSIONING.md) (per-crate, not a single workspace
version).

## Unreleased

## 0.3.0 — 2026-07-27

### Added

- Provider authentication contracts (`bastion-types::provider_auth`), the
  first slice of subscription-backed model providers: `ProviderAuthRef`
  (owner + provider + profile, opaque identifiers only), `CredentialKind`
  (`ApiKey` | `OAuthSubscription`), `ProviderAuthState`
  (`Ready`/`Refreshing`/`Cooldown`/`ReauthRequired`/`Revoked`),
  `ProviderAuthError` as a closed 7-variant vocabulary, the
  `ProviderAuthResolver` port plus its fail-closed `NullProviderAuthResolver`,
  and `ResolvedProviderCredential`.
  - The point of the slice is separating WHO authenticates a model call from
    WHAT executes the turn: a subscription can authenticate inference while
    the kernel keeps the loop, session, tool gate and memory. Nothing in the
    module can select, construct or invoke an `AgentRuntime`.
  - `ResolvedProviderCredential` implements no `Debug`, `Display`,
    `Serialize` or `Deserialize`, and wraps a `SecretValue` (which redacts) —
    a struct holding one cannot be serialized into a config dump, export or
    error payload, because the compiler refuses. `expose_secret` is the one
    grep-able accessor.
  - `ProviderAuthError` has no free-form detail field, so a failure cannot
    carry an upstream response body or token into a message; hosts map
    upstream failures onto the closed vocabulary and keep raw diagnosis in
    their own logs at the call site. `is_transient` classifies retry-worthy
    (`Expired`, `Throttled`) versus terminal, in the contract rather than in
    each host's guess.
  - `bastion-types` advances to `0.2.1` (additive).
  - Resolution stays synchronous for the same reason `SecretResolver` is: it
    happens when a provider is built or a credential refreshed, never per
    token on a hot path, so this crate keeps no async-runtime dependency.

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
- Policy 0 now also covers `run_provider_fallback`, the one dispatch path
  that predated the gate and reached `call_tool_with_timeout` with no
  `check_tool_allowed`: a persona with a `tools:` allowlist could still
  reach any tool through it whenever `route_text` came back empty for a
  turn still attributed to that persona. `RespondOutcome` carries
  `allowed_tools` (resolved by the Responder, for the same reason
  `turn_tier` already is — the `PersonaRegistry` lives in
  `bastion-personas`, not the kernel) and `run_provider_fallback` gates on
  it with the identical wrap. `docs/SECURITY-INVARIANTS.md` §9 updated.
- Two fabric-ready kernel seams in `AgentLoop` (`docs/VERSIONING.md` §6),
  both gating a future 1.0 tag: `fallback_models` becomes
  `SharedFallbackModels` (`Arc<RwLock<..>>`, same shape as `provider`) so a
  cloned handle can hot-swap the fallback ladder on a running loop with no
  `&mut AgentLoop` and no restart — constructor signature unchanged; and a
  new `compaction_provider: Option<SharedProvider>` field plus
  `with_compaction_provider` builder points `AutoCompact::compact`'s
  summarization at a provider distinct from the turn's conversational one
  (`None` is byte-identical to pre-seam behavior).
- Persona-tagged stigmergy in the `Memory` trait:
  `reinforce_persona_belief` and `weaken_persona_belief` mirror the existing
  untagged pair but scope to `persona_tag IS NOT NULL`, which nothing could
  reinforce or weaken before despite the column and
  `retrieve_tagged(owner, Some(persona))` existing since the original
  schema. Reinforce keeps the `MIN(weight + delta, 100.0)` cap and the
  non-negative-delta validation; weaken subtracts floored at `0.0` and does
  not itself revoke.

### Changed

- **Breaking** (same mechanical-check caveat as below):
  `cabinet::orchestrator::deliberate` gains a `user_input: &str` parameter
  (see Fixed). `bastion-cognition` advances to `0.2.0`.
- Cabinet staggers its parallel persona provider calls by
  `PERSONA_SPAWN_STAGGER` (400ms × spawn index) before each task does
  anything else — egress check, prompt building, the call. N personas
  fanning out through a `JoinSet` fired at effectively the same instant,
  which drew spurious 429s on free/low tiers that the same N calls spread
  over a minute fit comfortably within: a 6-persona round routinely lost
  4–5 of its 6 turns to rate limiting. Cheap against typical LLM latency.
- **Breaking** (not caught by the mechanical `docs/api-baseline` check,
  which tracks item presence/name, not signatures — see
  `docs/VERSIONING.md` §2): `agent::ports::TurnKernel::run_tool_loop` gains
  a new `allowed_tools: Option<Arc<HashSet<String>>>` parameter; every
  call site and the sole implementer (`AgentLoop`) are updated in the same
  change. `bastion-types`, `bastion-runtime`, and `bastion-personas`
  advance to `0.2.0` for this and the `Persona`/`InvokeCtx` field additions
  above (exhaustive external struct literals against either type need
  `..Default::default()` now). `bastion-runtime` then advances to `0.2.1`
  and `bastion-memory` to `0.1.1` for the additive `Memory` trait methods
  above (both implementors in-workspace, updated in the same change).

### Fixed

- Cabinet personas never received the actual user question. `deliberate()`
  had no parameter for the user's message and `RouterDecision` has no field
  to carry it, so the question only ever lived inside
  `persona::router::route()`'s own LLM call: `build_turn_prompt()` promised
  "Provide your position on the matter below" and then included no matter,
  in every round, for every past and current use of Cabinet mode. Personas
  reasoned only about their own system prompt — and, on replies, about a
  transcript of other personas also reasoning about nothing. `deliberate()`
  and `build_turn_prompt()` now thread `user_input` into a `Matter: {…}`
  line in both the Position (R1) and Reply (R2+) branches, and the Cabinet
  dispatch arm in `responder.rs` passes the real input instead of dropping
  it. Regression test inspects the message actually sent to the provider
  (not `config.system_prompt`) and asserts the question appears verbatim in
  every turn across both rounds.

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
