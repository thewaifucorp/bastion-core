# M3 — static subset close (2026-07-13)

> Covers the M3 items executable without external dependencies: the F1
> hardening follow-up (LOOP-REPORT.md), M3-02 (security invariants doc),
> M3-04 (examples) and the static half of M3-05 (feature flags + minimal
> build). Reference ADR: `docs/revamp/M1-ADR-substrate-split.md`.

## 1. F1 hardening — egress gated inside `ToolSource`

`ToolSource::call_tool_with_timeout` (`crates/bastion-runtime/src/agent/ports.rs`)
now takes `resolved_tier: Option<PrivacyTier>` and the production
implementation (`McpToolSource`, `crates/bastion-mcp/src/tool_source.rs`)
runs `check_egress(resolved_tier, "external")` internally BEFORE dispatching.
The two loop call sites (`dispatch_tool_loop`'s empty-registry fallback and
`run_provider_fallback`) no longer call `check_egress` themselves — same
check, same logical chokepoint, now unforgettable by construction. Covered by
two new invariant tests (`tests/characterization_boundary.rs`, map row "F1"
in `docs/revamp/M1-07-characterization-map.md`). F1 marked resolved in
`docs/revamp/LOOP-REPORT.md`.

## 2. M3-02 — security invariants reference

`docs/SECURITY-INVARIANTS.md` (public, English): the 10 BACKLOG invariants,
each with 2–4 sentences, the enforcing chokepoint (`crate::path`), and the
covering test(s), sourced from the M1-07 characterization map.

## 3. M3-04 — examples (and the API gaps they found)

`examples/minimal-agent` and `examples/embedded-host`, workspace members,
importing ONLY substrate crates (`bastion-types`/`-runtime`/`-memory`) —
never the root `bastion` package (enforced by a new `examples` CI job:
`cargo check -p minimal-agent -p embedded-host`). Both run fully offline,
exit 0.

**API gaps found (the key output — feed back into M3-01/M5):**

1. **`AgentLoop::new` hardwires its own `ApprovalQueue`** — it constructs
   `CapabilityRegistry::new().with_approval_queue(ApprovalQueue::new(db_path))`
   unconditionally; there is no constructor parameter to opt out or inject an
   alternative decision mechanism. An embedding host that wants a full turn
   cannot reach Policy 2's fail-closed "no queue" denial path at all.
2. **`ApprovalQueue` is a concrete SQLite struct, not a port** — no trait a
   second consumer can implement with its own authorization logic ("auto-deny
   over threshold", "delegate to external review"). The only lever is
   `.reject(owner, id)` on the built-in queue.
3. **A rejected approval is invisible to `invoke()`'s caller** —
   `outcome_for_existing_row` (`crates/bastion-runtime/src/capability/approval.rs`)
   maps a `Rejected` row to `ApprovalOutcome::AlreadyPending`, the same
   outcome as an undecided row. Re-invoking an explicitly denied action
   returns `Ok({awaiting_approval: true})`, never an `Err` (typed or
   otherwise). Contrast with the egress gate's `BastionError::PrivacyEgressBlocked`,
   which callers match via `downcast_ref`. A host cannot express or observe
   "this action was denied" through the public API today.

All three are demonstrated executable in `examples/embedded-host/src/main.rs`
(`demonstrate_denied_capability`, with assertions that will fail loudly if
the gap is ever closed upstream so the example gets updated).

## 4. M3-05 (static half) — feature flags + minimal build

Flags on the root app package (`Cargo.toml [features]`), default = all on
(today's exact behavior). Gates live only at composition points
(`src/main.rs`, `src/channel/mod.rs`, `src/mcp/mod.rs`) — zero `cfg` inside
`crates/*`.

| Feature | Gates | Deps removed when off |
|---|---|---|
| `channels-extra` | Discord/Slack/Email modules + spawn blocks; WhatsApp runtime wiring (module always compiles — types thread through the webhook router) | serenity, slack-morphism, rvstruct, lettre, async-imap, async-native-tls, mailparse |
| `voice` | `channel::voice` module + spawn block | cpal, hound, rustpotter (whole candle subtree), half pin |
| `mcp-server` | `mcp::server` module, `bastion mcp-stdio` subcommand, MCP-over-HTTP routes, `build_token_perms` | rmcp server-side cargo features |

**Skipped (per the >20-line-refactor rule):** a `mesh` flag — mesh types are
threaded through the webhook router's signature and handlers (~90 references
in `src/channel/webhook.rs`: `SharedMeshTransport`/`MeshSliceStore` params,
`/mesh/pair`, `/mesh/ingest`, SSE peer events). Gating it means refactoring
webhook, not adding a composition-point cfg. Candidate for the M4 product
split, where webhook itself becomes product code.

Config keys for compiled-out surfaces still parse; enabling one logs a
`*_not_compiled` warning instead of silently doing nothing.

Supported combinations: default (all on) and `--no-default-features` (min)
are the two gate-checked configurations (CI builds default; the minimal
build was verified locally with `cargo check`/`clippy -D warnings`
`--no-default-features`). Individual flags are additive and independent —
no flag requires or conflicts with another.

### Binary size (release profile: opt-level=z, fat LTO, strip)

| Build | Bytes | MB |
|---|---|---|
| Full (`cargo build --release`, default features) | 24.344.920 | 23,2 MiB (~24,3 MB) |
| Minimal (`cargo build --release --no-default-features`) | 15.592.184 | 14,9 MiB (~15,6 MB) |
| Delta | −8.752.736 | **−36,0%** |

Target "<20MB no mínimo": **met** (15,6 MB). Reference: M2-close full binary
was 24.345.624 bytes — the flags added no overhead to the default build
(−704 bytes, noise).

## 5. Gates (this close)

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS (only the pre-existing `proc-macro-error2` future-incompat notice) |
| `cargo clippy -p bastion --no-default-features -- -D warnings` | PASS |
| `cargo test --workspace` (default features) | PASS — **537 passed, 0 failed** (40 suites: M2's 535 + the 2 new F1 invariant tests; 38 suites + the 2 example crates) |
| `bash scripts/check-crate-deps.sh` | PASS |
| `cargo run -p minimal-agent` / `-p embedded-host` | exit 0, offline |

## 6. Not covered here (remaining M3, at the time of the static pass above)

M3-01 (reduce `pub` to the contract + shim removal), M3-03 (compat tests /
API-breaking CI), M3-06 (semver/MSRV/license policy), M3-07..11
(extension protocol, conformance, manifests, auth, ContextRevision) — all
untouched by this static pass.

## 7. Ciclo 2.3 — M3-01: shim removal + public-surface tightening (2026-07-14)

### 7.1 Shim removal

All 19 M2 re-export shims (`// TEMPORARY re-export shim (M2)` marker) are
gone. Every consumer in `src/`, `tests/`, `src/main.rs` now names the real
crate directly (`bastion_runtime`, `bastion_memory`, `bastion_types`,
`bastion_cognition`, `bastion_mesh`, `bastion_personas`, `bastion_providers`,
`bastion_mcp`, `bastion_agent_runtime`). Mechanical import-path rewrite only
— no logic, assertion, or signature change.

- **17 whole-file/dir shims deleted outright**: `agent_runtime.rs`,
  `cabinet.rs`, `capability/` (dir), `eval.rs`, `goal.rs`, `hooks.rs`,
  `identity.rs`, `interop.rs`, `learn.rs`, `memory/` (dir), `mesh.rs`,
  `persona.rs`, `proactive.rs`, `provider/` (dir), `scheduler.rs`,
  `session.rs`, `types.rs`.
- **2 partial shims rewritten in place**: `agent/mod.rs` (keeps the real
  `command`/`skills` submodules and `default_context_providers`; the
  re-exported kernel/cognition submodules now resolve straight to
  `bastion_runtime::agent::*` / `bastion_cognition::agent::*`) and
  `mcp/mod.rs` (keeps the real, feature-gated `server` submodule; the
  client-side re-exports now resolve straight to `bastion_mcp::*`).
- `src/lib.rs` shrinks to the 5 real app modules: `agent`, `api`, `channel`,
  `config`, `mcp`.
- **No exceptions**: no shim had a legitimate external consumer that
  couldn't be migrated — all 19 came out clean.

### 7.2 Public-surface tightening (mechanical pass)

Method: every `pub fn|struct|enum|trait` declaration was treated as a
downgrade candidate if its identifier had **zero textual occurrences**
anywhere in the workspace outside its own crate (app: outside `src/main.rs`,
`src/bin/*`, `tests/**`, `examples/**`; library crates: outside
`crates/<name>/src/**`, which correctly still counts that crate's *own*
`tests/` dir — e.g. `bastion-agent-runtime/tests/` — as external). Candidates
were downgraded to `pub(crate)`, then verified against the compiler
(`cargo check --workspace --all-targets --all-features`): any
`private_interfaces`/`private-type-leak` error or newly-exposed
`dead_code` warning was treated as proof the item **is** part of the
public contract (leaked through a still-`pub` fn/field/trait method, or a
deliberate null-object like `NoObserver`/`NoDream`) and reverted to `pub`.
No signature was changed, no code moved, no item renamed — visibility only.

Of 365 `pub fn|struct|enum|trait` items workspace-wide, 74 were zero-external
-reference candidates; 48 were reverted after compiler feedback (leaked
through a public signature, or dead-code-only once privatized); **26 net
items** ended up `pub(crate)`.

**Pub item counts (`pub fn|struct|enum|trait`, before → after):**

| Crate | Before | After | Downgraded |
|---|---:|---:|---:|
| `bastion` (app, `src/`) | 73 | 69 | 4 |
| `bastion-types` | 33 | 33 | 0 |
| `bastion-runtime` | 67 | 62 | 5 |
| `bastion-memory` | 2 | 2 | 0 |
| `bastion-providers` | 19 | 14 | 5 |
| `bastion-mcp` | 26 | 25 | 1 |
| `bastion-agent-runtime` | 54 | 51 | 3 |
| `bastion-cognition` | 43 | 38 | 5 |
| `bastion-personas` | 11 | 11 | 0 |
| `bastion-mesh` | 37 | 34 | 3 |
| **Total** | **365** | **339** | **26** |

**Candidates found but NOT touched (reverted to `pub` after compiler
feedback — genuinely part of the public contract despite zero current
textual reference elsewhere)**, grouped by why:

- *Leaked through a still-`pub` fn return / field / trait method* (the
  bulk): `CheckResult` (bastion-agent-runtime, 16 call sites), `McpBridgeSpec`,
  `UsageDelta`, `InputGuardrail`, `EgressHook`, `RegressionCase`,
  `VerifierResult`, `ProgressScore`, `ReplanResult`, `Reflection`, `Dream`
  (trait), `ConsolidationPlan`, `IdentityBlock`, `MemoryEntry`,
  `PersonaEntry`, `GoalEntry`, `SkillEntry`, `AgentConfigExport`,
  `MeshTransport` (trait, plus its `SelectiveSlice` param type),
  `SkillMetadata`, and the whole `BastionConfig` sub-struct tree
  (`MeshPeerConfig`, `MeshConfig`, `IdentityEntry`, `IdentityConfig`,
  `SessionConfig`, `LoggingConfig`, `McpConfig`, `McpServerTokenConfig`,
  `McpServerConfig`, `ChannelsConfig`, `ChannelConfig` ×2 distinct types in
  `src/config.rs` and `src/channel/mod.rs`, `VoiceChannelConfig`).
- *Dead-code-only once privatized* (no external ref, but also apparently
  unconstructed/uncalled even intra-crate — reverted rather than deleted,
  since deleting code was out of scope): `to_sql_str`, `list_names`, `Hook`
  (trait), `Observer` (trait), `NoObserver`, `LifeLog`, `with_binary`
  (codex.rs only — the acpx.rs `with_binary` of the same name stayed
  `pub(crate)`, it has an intra-crate caller), `NoDream`, `NoOpGenerator`,
  `resolve_provider_kind`, `WhatsAppChannel`.
- *Re-exported at crate root through a different file* (E0364/E0365 hard
  errors, not warnings): `parse_soul`, `BastionBlock`, `PersonaFront`
  (`bastion-personas`) — declared `pub(crate)` in `persona/soul.rs` but
  re-exported `pub use soul::{...}` from `persona/mod.rs`; the re-export
  itself needs the source item to be `pub`.

No further candidates are proposed at this time — everything with a
plausible external reach ended up `pub` after the compiler check; the
remaining 26 are true crate-internal-only items.

### 7.3 Gates (this close)

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS (only the pre-existing `proc-macro-error2` future-incompat notice) |
| `cargo test --workspace` | PASS — **570 passed, 5 ignored** (42 suites), unchanged from before this cycle |
| `bash scripts/check-crate-deps.sh` | PASS |

## 8. Not covered here (remaining M3, after Ciclo 2.3)

M3-03 (compat tests / API-breaking CI — now backed by the versioning policy
and public-API baseline in `docs/VERSIONING.md` / `scripts/dump-public-api.sh`),
M3-06 (semver/MSRV/license policy — see `docs/VERSIONING.md`), M3-07..11
(extension protocol, conformance, manifests, auth, ContextRevision) —
untouched by this cycle.
