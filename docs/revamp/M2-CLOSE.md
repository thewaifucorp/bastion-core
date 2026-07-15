# M2 — Close: workspace extraction complete

> Covers M2-01..08 (BACKLOG.md). Reference ADR: `docs/revamp/M1-ADR-substrate-split.md`.
> Baseline: tag `v1.1.0-pre-revamp` (`1528759`), metrics in `docs/revamp/BASELINE.md`.

## 1. Final crate inventory

9 crates + 1 app, all under `crates/*` (workspace `members = ["crates/*"]`), app package `bastion` at repo root (`src/`, `Cargo.toml`).

| Crate | Stability class | Extraction commit |
|---|---|---|
| `bastion-types` | kernel | `ec30069` |
| `bastion-runtime` | kernel | `849e67d` (+ port commits `9856640`, `3fe11d9`, `8b2246a`, `ddb9015`, `d1bac73`, `ddf0006`) |
| `bastion-memory` | quase-kernel | `f6575b5` |
| `bastion-providers` | extension (official) | `9ed9844` |
| `bastion-mcp` | extension (official) | `0488259` |
| `bastion-agent-runtime` | extension (official) | `b614f01` |
| `bastion-cognition` | extension (official, Cabinet stable) | `b46c28f` |
| `bastion-personas` | extension (0.x) | `535c7cc` |
| `bastion-mesh` | extension (official) | `adb13c8` |
| `bastion` (app) | product | `f0f6650` (workspace scaffold) |

## 2. Dependency graph (derived from `crates/*/Cargo.toml`, 2026-07-13)

```
bastion-types   (leaf — no bastion-* deps)
bastion-agent-runtime (leaf — no bastion-* deps; zero crate coupling by design)

bastion-runtime   → types

bastion-memory    → types, runtime
bastion-providers → types, runtime
bastion-mcp       → types, runtime

bastion-cognition → types, runtime, memory
                    (+ mcp, dev-dependencies only — DirectFnAdapter test mock)

bastion-personas  → types, runtime, memory, cognition

bastion-mesh      → types, runtime, memory, cognition, personas

bastion (app)     → types, runtime, memory, providers, mcp,
                     agent-runtime, cognition, personas, mesh   (all 9)
```

Acyclic. No crate depends on the root `bastion` package (checked against every `crates/*/Cargo.toml`). No cycles between extensions.

### Validation against the M2-08 allowlist

Every edge above was checked against the exact allowlist required for M2-08 (see `scripts/check-crate-deps.sh`). **Zero discrepancies** — the workspace as extracted already matches the allowlist precisely, including the two intentionally-narrow edges:

- `bastion-providers` → **no** `bastion-cognition` dependency (the V4 `ollama.rs`↔`cabinet` coupling flagged in the ADR was cut during M2-05b: `ollama.rs` now depends only on `bastion_types::CabinetVerdict`, a pure-data type hoisted to the kernel-adjacent leaf crate — not a cognition dependency).
- `bastion-cognition` → `bastion-mcp` only in `[dev-dependencies]` (test-only mock adapter, `learn::dedup`'s `DirectFnAdapter`) — never a production edge.

## 3. What remains in `src/` (app + shims)

### App-legit (composition/product, stays in `src/` permanently)

- `main.rs`, `lib.rs` — binary entrypoint + module tree
- `api/` — HTTP/SSE surface (`infer.rs`, `mod.rs`)
- `bin/pokedev_cli.rs` — secondary binary
- `channel/` — concrete channel adapters (discord, email, slack, telegram, voice, webhook, whatsapp)
- `config.rs` — `bastion.toml` parsing/config struct (owns the file format; crates never see it, per ADR V2)
- `agent/mod.rs` — partially permanent: `pub mod command; pub mod skills;` + `default_context_providers()` (product-side SEAM #2 composition, moved verbatim out of `AgentLoop::new` in M2 step 3b/6.2); the re-export lines for `bastion_runtime::agent`/`bastion_cognition::agent` submodules are the shim portion (see below)
- `agent/command.rs`, `agent/skills.rs` — cockpit UX / skills loader (product)
- `mcp/mod.rs` — partially permanent: `pub mod server;` (BastionMcpServer depends on `crate::goal`/`crate::persona`, product/cognition layers — cannot move without a cycle or port redesign, out of scope for M2); the re-export lines for `bastion_mcp`'s client/oauth/registry are the shim portion
- `mcp/server.rs` — `BastionMcpServer` (product)

### Pure re-export shims (temporary, 19 files carry the standardized marker)

```
src/agent_runtime.rs   src/cabinet.rs        src/eval.rs
src/goal.rs            src/hooks.rs          src/identity.rs
src/interop.rs         src/learn.rs          src/mesh.rs
src/persona.rs         src/proactive.rs      src/scheduler.rs
src/session.rs         src/types.rs
src/capability/mod.rs  src/memory/mod.rs     src/provider/mod.rs
src/mcp/mod.rs (partial — shim lines only, `pub mod server` is permanent)
src/agent/mod.rs (partial — shim lines only, rest is permanent)
```

Each carries the standardized marker:

```
// TEMPORARY re-export shim (M2). Remove by end of M3 (docs/revamp/M1-ADR-substrate-split.md).
```

`src/types.rs` previously said "remove by end of M2" (stale — written before the decision that shims persist through M2 close so `tests/` keeps compiling against `bastion::...` paths); corrected to M3 during this close-out. All other pre-existing shim comments already carried equivalent meaning (which crate the code moved to, why, and that old paths keep compiling) and were left intact with the standardized marker prepended.

Two empty leftover directories from earlier `git mv` extractions (`src/hooks/`, `src/session/`, superseded by `src/hooks.rs` / `src/session.rs` shims) were removed — they were empty, untracked-by-git artifacts, no content lost.

### Shims pending removal in M3

All 19 files above are slated for removal once M3-01 ("reduzir `pub` ao contrato") lands and every consumer (`tests/`, `src/`) is migrated to import directly from the owning crate (`bastion_types::...`, `bastion_runtime::...`, etc.) instead of `bastion::...`. Removal is gated on M3, not calendar time, per the BACKLOG's decommission-by-evidence rule (M6-04 principle applied early).

## 4. CI: forbidden crate dependencies (M2-08)

`scripts/check-crate-deps.sh` parses every `crates/*/Cargo.toml` and enforces the exact allowlist below (dependencies + dev-dependencies checked separately). Any `bastion-*` dependency edge not in the allowlist, any dependency cycle, or any crate depending on the root `bastion` package fails the script with `exit 1` and a clear message naming the offending crate/edge.

| Crate | Allowed `bastion-*` deps | Allowed `bastion-*` dev-deps |
|---|---|---|
| `bastion-types` | (none) | (none) |
| `bastion-runtime` | `bastion-types` | (none) |
| `bastion-memory` | `bastion-types`, `bastion-runtime` | (none) |
| `bastion-providers` | `bastion-types`, `bastion-runtime` | (none) |
| `bastion-mcp` | `bastion-types`, `bastion-runtime` | (none) |
| `bastion-agent-runtime` | (none) | (none) |
| `bastion-cognition` | `bastion-types`, `bastion-runtime`, `bastion-memory` | `bastion-mcp` |
| `bastion-personas` | `bastion-types`, `bastion-runtime`, `bastion-memory`, `bastion-cognition` | (none) |
| `bastion-mesh` | `bastion-types`, `bastion-runtime`, `bastion-memory`, `bastion-cognition`, `bastion-personas` | (none) |

Global rule enforced regardless of allowlist: no crate under `crates/*` may depend on the root package `bastion` (product → substrate is a one-way street).

Ran against the current workspace: **PASS**, zero violations, zero discrepancies against the allowlist above (see §2's "Validation against the M2-08 allowlist"). Negative-path tested against a throwaway fixture workspace exercising all four violation classes (root-package dependency, crate missing from allowlist, disallowed edge, dependency cycle) — all four correctly detected and reported, non-zero exit.

Wired into `.github/workflows/ci.yml` as a new `crate-deps` job (checkout + script, no Rust toolchain needed — runs in seconds) that the existing `rust` job (`fmt`/`clippy`/`test`) now depends on via `needs: crate-deps`, so it gates before the heavy build/test steps. No other part of the workflow was changed.

## 5. Final gates (M2 close)

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS — clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS — exit 0; only the known future-incompat notice on transitive dep `proc-macro-error2 v2.0.1` (not our code, tracked for the M3 dep audit, same as baseline) |
| `cargo test --workspace` | PASS — **535 passed, 0 failed** (38 suites: unit tests across all 9 crates + the app's `src/lib.rs`/`src/main.rs`/`pokedev_cli` + 15 `tests/` integration suites + the `evals` harness) |
| `cargo build --release` | PASS — binary `target/release/bastion` = **24.345.624 bytes**, vs. baseline `24.183.704` bytes (`v1.1.0-pre-revamp`) → **+161.920 bytes (+0,6695%)**. Consistent with the cumulative deltas reported at each M2 sub-step (+0,16%, +0,19%, ...); the full workspace split (10 Cargo.toml manifests, 19 shim files, crate boundaries) adds a small, expected amount of overhead, well within tolerance — no functional growth. |
| `cargo check -p bastion-runtime` (kernel standalone) | PASS — the kernel crate (`bastion-runtime`, depending only on `bastion-types` + external deps) compiles in isolation, with no product/cognition/extension code pulled in. Confirms the kernel-alone build works without any of `bastion`'s (app) or the extension crates' features. |

## 6. GitNexus / aag reindex

`node .gitnexus/run.cjs analyze` ran successfully (foreground, ~28s, incremental): **6.954 nodes | 14.413 edges | 314 clusters | 300 flows**. No fallback needed; no entry required in `docs/revamp/LOOP-REPORT.md` for this close-out.
