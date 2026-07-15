# M6-PREP — separable state for the physical split (owner executes M6)

> `docs/revamp/BACKLOG.md` M6 (decisões #2/#3/#17). **This document does NOT
> create any repository and deletes nothing destructive.** It maps exactly what
> becomes `bastion-core` vs `bastion-agent`, gives the OWNER a step-by-step to
> create the two repos, and lists the cleanup candidates for item-by-item
> owner approval. Prepared in Loop 3-F; the workspace is proven separable
> (logical boundary holds: `scripts/check-crate-deps.sh` PASS, second consumer
> `examples/embedded-host-slice` imports zero Agent code).

## 0. Pre-conditions (all met)

- M0–M5 logical separation complete; two real consumers exercise the Core API
  (the Agent app + `examples/embedded-host-slice`).
- Crate-dependency CI gate green (one-way boundary enforced, acyclic).
- Public-API baselines committed (`docs/api-baseline/*.txt`), scrub guard green.

## 1. The map — what goes where

### 1.1 `bastion-core` (the substrate) — the 11 crates in `crates/`

The repo split keeps the CURRENT repository as `bastion-core` (preserves
history/stars, decisão #2). Core = the full `crates/` tree, exactly these
**11** crates:

| Crate | Role | Intra-Core deps (stay path deps) |
|---|---|---|
| `bastion-types` | leaf types/IDs/errors | — |
| `bastion-agent-runtime` | `AgentRuntime` contract + adapters (codex, acpx) + legacy terminal-agent behind `legacy-terminal-agent` | — (standalone; no `bastion-*` dep) |
| `bastion-runtime` | agent loop, capabilities, context, sessions, hooks, observability | `bastion-types`, `bastion-agent-runtime` |
| `bastion-memory` | beliefs/provenance/temporality store | `bastion-types`, `bastion-runtime` |
| `bastion-cognition` | Dream, learning, goals, proactivity, Cabinet | `bastion-types`, `bastion-runtime`, `bastion-memory` (+ dev `bastion-mcp`) |
| `bastion-personas` | `AgentDefinition`/personas | `bastion-types`, `bastion-runtime`, `bastion-memory`, `bastion-cognition` |
| `bastion-mesh` | mesh, identity, interop, scheduler | `bastion-types`, `bastion-runtime`, `bastion-memory`, `bastion-cognition`, `bastion-personas` |
| `bastion-mcp` | MCP client/server | `bastion-types`, `bastion-runtime` |
| `bastion-providers` | concrete providers + auth | `bastion-types`, `bastion-runtime` |
| `bastion-extension-protocol` | manifests, lifecycle, permissions | `bastion-types` |
| `bastion-extension-wasm` | wasmi-backed Wasm mechanism sandbox | — (no `bastion-*` dep) |

> Note vs. the M1-ADR "10 crates + app" topology: the actual count is **11** —
> `bastion-extension-wasm` was added in Loop 3-C (the Wasm mechanism's sandbox,
> isolated so `wasmi` never touches the kernel). Update the BACKLOG/M1-ADR
> topology tables to say 11 when convenient (non-blocking).

**Core also keeps** (recommended — see §4 decision D-1): the three
substrate-only demos in `examples/` — `minimal-agent`, `embedded-host`,
`embedded-host-slice` — because they import **only** `bastion-*` crates (never
the `bastion` app) and are the living regression guard for the boundary (M5
gate). Moving them to Agent would still compile via git deps but would remove
the boundary check from Core's own CI.

### 1.2 `bastion-agent` (the product) — the root `bastion` package + distribution

Everything the root package owns today moves to a NEW `bastion-agent` repo,
with the public binary `bastion` (decisão #2):

| Path | Content |
|---|---|
| `src/` | daemon, `main.rs`, `agent/`, `api/`, `bin/` (`pokedev_cli`, `reference-extension-echo`), `channel/`, `config.rs`, `mcp/` composition, `extension/` (host + mechanisms), `secret.rs`, `auth_profile_registry.rs`, `agent_runtime_registry.rs`, `lib.rs` |
| `skills/` | the personal MCP-server skills (memupalace, skill-writer, self-improving, guardrails, life-log, voice, …) — personal distribution; audit orphans (§3) |
| `mobile/` + `bastion/mobile-connect/` | Flutter companion + Node/TS OTC pairing app (preserve — owner's phone-connect app) |
| `installer.sh`, `Dockerfile`, `docker-compose*.yml`, `Makefile`, `scripts/` | distribution/build/CI tooling |
| `config/`, `bastion.toml`, `.env.example`, `.mcp.json` | app config + defaults (review defaults on move) |
| `personas/`, `SOUL.md` (untracked) | owner's personal content — stays local/example, out of the public product repo |

## 2. Cargo dependency rewrite (path → git → crates.io)

Inside Core, the intra-crate deps in §1.1 **remain `path` deps** (all 11 move
together into one Core workspace — nothing to rewrite there).

Only Core's **consumers** rewrite. The Agent's root `Cargo.toml` and any
example that moves converts every `bastion-* = { path = "crates/…" }` /
`{ path = "../…" }` into:

- **Incubation (M6-01, decisão #3): git deps, version-pinned to a tag/rev** —
  never a floating `main`:
  ```toml
  bastion-runtime = { git = "https://github.com/<owner>/bastion-core", tag = "v0.1.0" }
  # …one line per bastion-* crate the Agent uses (today: all 11 via the app).
  ```
- **At M6-02: crates.io version deps** once Core publishes:
  ```toml
  bastion-runtime = "0.1"
  ```

Core's `[workspace]` `members = ["crates/*", "examples/*"]` becomes
`members = ["crates/*", "examples/*"]` (unchanged if examples stay in Core) or
`["crates/*"]` if D-1 sends examples to Agent. Agent's `Cargo.toml` drops the
`[workspace] members = ["crates/*", …]` line entirely and becomes a normal
package (it no longer contains `crates/`). The root package's `[[bin]]`
entries (`bastion`, `pokedev-cli`, `reference-extension-echo`) and
`[features]` (`channels-extra`, `voice`, `mcp-server`, `legacy-terminal-agent`
→ `bastion-providers/legacy-terminal-agent`) move verbatim to Agent.

## 3. Step-by-step the OWNER runs (creates the 2 repos — NOT done here)

> Choose ONE of the two history strategies. `git filter-repo` preserves per-file
> history but rewrites SHAs; a plain copy is simpler but loses granular history
> for the moved subtree. Recommendation: keep Core = this repo in place (history
> intact), and extract only the Agent product into a fresh repo.

**Strategy A — Core stays in place, Agent extracted with history (recommended):**

1. `bastion-core` = this repo, renamed. Nothing extracted; just remove the app
   once Agent is live (see step 5). History/stars preserved (decisão #2).
2. Create the Agent repo carrying its file history:
   ```bash
   # from a fresh clone of this repo
   git clone <this-repo> bastion-agent && cd bastion-agent
   pip install git-filter-repo   # if not present
   git filter-repo \
     --path src/ --path skills/ --path mobile/ --path bastion/mobile-connect/ \
     --path installer.sh --path Dockerfile --path Makefile \
     --path docker-compose.yml --path docker-compose.mesh-e2e.yml \
     --path config/ --path bastion.toml --path .env.example --path .mcp.json \
     --path scripts/ --path tests/     # tests that exercise the app, not the crates
   ```
3. In `bastion-agent`, add a package `Cargo.toml` (from the current root, minus
   `[workspace] members`), rewriting every `bastion-*` dep to git-pinned (§2).
4. `git remote add origin <new bastion-agent url> && git push -u origin main`.

**Strategy B — plain copy (simpler, coarser history):** `cp -r` the §1.2 paths
into a new repo, `git init`, single "import from bastion monorepo @<sha>"
commit referencing the source SHA. Use only if filter-repo history is not
wanted.

**After either strategy — CI cross-repo (M6-02):**
5. Core CI additionally builds `examples/embedded-host-slice` (the reference
   external consumer) against Core HEAD; Agent CI pins min/max supported Core
   versions. Document the compatibility window + upgrade process.
6. Remove the app from `bastion-core` (`src/`, app `tests/`, distribution files)
   ONLY after Agent is proven building against Core git deps — this is M6-04's
   "decommission by evidence", with the monorepo pre-split state archived +
   redirected. **Owner-approved, not automated.**

## 4. Decisions the owner still makes (flagged, not guessed)

- **D-1 — where do the 3 `examples/*` live?** Recommendation: **keep in Core**
  (they import only `bastion-*`, are the M5 boundary regression guard). The
  brief listed "examples" under Agent; if the owner prefers that, they move to
  Agent and convert to git deps (§2) — but Core then loses the in-repo boundary
  proof. Documented, owner's call.
- **D-2 — where does `docs/revamp/` live?** It is the revamp's working record
  (BACKLOG, LOOP-REPORT, A-0x, C2/C3 designs, this file). Recommendation:
  **archive it into the private architecture repo** (same place `.planning`
  went, decisão #17) at split time, leaving only `docs/SECURITY-INVARIANTS.md`,
  `docs/SUPPORT-MATRIX.md`, `docs/VERSIONING.md`, `docs/capability-registry-spec.md`
  and the public `docs/en`/`docs/pt-br` in whichever repo they describe. Until
  then it stays in Core. Non-blocking; owner's call.
- **D-3 — `STRATEGY.md` destination** (inventory `?`): survive-in-public vs.
  move-to-private. Still open (inventory M0-03).

## 5. Cleanup candidates — OWNER APPROVES ITEM BY ITEM (nothing deleted here)

From `docs/revamp/LEGACY-INVENTORY.md` `delete-later`. **None of these are
removed in this commit** — this is the list M6-03 walks with the owner. Tracked
(in git) vs untracked noted, because untracked ones can be removed anytime with
no repo impact.

### 5.1 Tracked — need owner approval before `git rm`

| Path | Tracked files | Note |
|---|---|---|
| `docs/archive/` | 2 | v2/OpenClaw archived docs — stale, superseded by the Rust runtime |
| `.bastion/` | 3 | local state/config committed by mistake? inspect content before removing |
| `bastion.local.toml` | 1 | local override committed by mistake? confirm no secret before removing |
| `benchmark.py` | 1 | Python residue of v2/experiments |
| `conftest.py` | 1 | pytest residue (the real Python MCP servers live under `skills/`) |
| `pyproject.toml` | 1 | Python packaging residue of v2 |

### 5.2 Untracked / gitignored — machine hygiene, removable anytime (no approval needed for build)

`bastion.egg-info/`, `__pycache__/`, `.pytest_cache/`, `.hypothesis/`,
`.venv/`, `v1_cache/`, `testsprite_tests/` (0 tracked), `bastion-a.toml` /
`bastion-b.toml` (0 tracked — mesh E2E fixtures, either move to `tests/` or
drop), `models/`, `.cargo-test.log`, `.local-data/`, plus editor/tool dirs
`.clawhub/`, `.kiro/`, `.playwright-mcp/`, `.gemini/`, `.cursor/`, `.vscode/`,
`.bastion-local/`.

### 5.3 Planning/index tooling — remove at split (decisão #17)

`.planning` (symlink into the private architecture repo), `.gitnexus/`,
`.aag/` + `.aag.lock`, `.claude/`. The planning history is preserved in the
private repo. **Note the still-live AGENTS.md/CLAUDE.md GitNexus + aag blocks**
(between the `<!-- gitnexus:start/end -->` and `<!-- aag:start/end -->`
markers) — these point at `.gitnexus/`/`.aag/`/`.claude/skills/gitnexus/`; when
that tooling is removed those blocks should be stripped too. Left intact for
now (live tooling this loop used).

### 5.4 Already done in this loop (Loop 3-F, commit `docs(m6-prep)`)

Removed the three **clearly-dead `.planning/` references** from `AGENTS.md`
(the `.planning` symlink is gitignored — invisible to any public clone, so the
pointers were dead for a public consumer). The live facts were kept, only the
`.planning/…` path pointers dropped:
- "current intel lives in `.planning/codebase/` (re-mapped …)" → "the current
  source is authoritative; the revamp state lives in `docs/revamp/`".
- "read `.planning/codebase/` intel and use the GitNexus impact tools" → "use
  the GitNexus impact tools".
- "(… not here yet — see `.planning/todos/pending/house-standards-alignment.md`)"
  → "(… not here yet)".

The GitNexus/aag tooling blocks and the `.claude/`/`.gitnexus/`/`.aag/` refs
were **left intact** — they are live code-intelligence tooling, not GSD/.planning,
and are listed in §5.3 for owner approval at the actual M6 cleanup.
