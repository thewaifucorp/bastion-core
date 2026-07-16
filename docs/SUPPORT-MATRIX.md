# Bastion — Backend Support Matrix

> **Version: 0.1.0** (matches the `bastion-agent-runtime` crate version every
> adapter below ships from) · **Generated: 2026-07-14**. This file is the
> derived, human-facing summary of adapter-level conformance and live-run
> scorecards; the raw evidence is the `tests/agent_runtime_backend_live.rs`
> suite and each adapter's own integration tests.

## Read this first: what this table promises, and what it doesn't

This matrix describes **capabilities of specific adapter/harness/version
combinations, measured on real hosts, at the date above** — not a permanent
guarantee of the Bastion Core. Concretely:

- A row can regress, improve, or disappear entirely when the wrapped CLI
  (`claude`, `codex`, `opencode`, `acpx`) ships a new version — every adapter
  pins a supported version range (see `target_version` in
  `bastion_agent_runtime::RuntimeDescriptor`) and refuses to start outside it
  (`RuntimeError::Version`), rather than silently degrading.
- **Terms of service, pricing, rate limits, and what counts as "supported
  usage" belong to each subscription provider (Anthropic, OpenAI, the
  `opencode` project, ...), never to Bastion.** Bastion does not sell, meter,
  or guarantee access to any of these subscriptions — it only automates
  driving an already-authenticated CLI the owner installed and logged into
  themselves, exactly as if they'd typed the command by hand.
- **Policy coverage is an honest declaration, not a marketing claim.** A
  `HarnessOwned` approvals row means Bastion's `ApprovalGate` genuinely does
  not mediate that harness's tool calls — the UI/cockpit surfaces this
  (`BackendProfile.coverage_note`), it is never hidden.
- This table is regenerated from real code and live-run scorecards, not
  hand-maintained prose — if you find a mismatch against the current
  `crates/bastion-agent-runtime/src/{acpx,codex}.rs`, the code wins; file it
  as a docs bug.

## 1. Targets — auth model

| Target | Bastion runtime id | Auth model(s) supported | Auth verified by | Requires an API key? |
|---|---|---|---|---|
| **Model (native inference)** | *(n/a — `ConversationBackend::Model`, always available)* | Traditional API key, per-provider (`[agent] default_model` + provider key: Anthropic/OpenAI/Groq/OpenRouter/...) | Provider call itself (fails at call time if the key is missing/invalid) | **Yes, always** — this is the one path that requires one |
| **Codex / ChatGPT** (native app-server) | `codex_app_server` | ChatGPT subscription login (`codex login`) **or** API key (`codex login --with-api-key`) | `AuthProfileRegistry` → `codex login status` (read-only, checks only the exit code — never reads the token) | **No**, subscription login is sufficient |
| **Claude Code** (via `acpx`) | `acpx_claude` | Claude subscription/OAuth login (`claude auth login`) **or** `ANTHROPIC_API_KEY` | `AuthProfileRegistry` → `claude auth status` (read-only) | **No**, subscription login is sufficient |
| **OpenCode** (via `acpx`) | `acpx_opencode` | OpenCode's own multi-provider login (`opencode auth login` — supports several backends including its own OpenCode Zen/Go accounts) | `AuthProfileRegistry` → `opencode auth list` (read-only) | **No**, subscription/provider login is sufficient |
| **Cursor** (ACP) | *(not yet implemented)* | — | — | — |

M4-07 acceptance criterion, proved live (`tests/agent_runtime_backend_live.rs::m4_07_subscription_backend_works_without_api_key_live`): a personal installation completes a real runtime-backed turn with **zero `*_API_KEY`-suffixed environment variables set**, using only a host CLI subscription login verified by reference. Traditional API-key auth continues to work for every target that supports it — it is never the only path, and never required outside the native Model backend.

## 2. Capabilities (`RuntimeSupports`)

| Target | Resume | Steer (mid-task) | Usage reporting | Diff events | Permission bridge | Concurrent sessions |
|---|---|---|---|---|---|---|
| `codex_app_server` | ✅ genuine reattach (`thread/resume`) | ✅ (bounded retry for a transient server-side race) | ✅ | ✅ | ✅ real bridge | ❌ one active turn per thread |
| `acpx_claude` | ❌ typed `NotResumable` (acpx's own session store is best-effort/TTL, not a Bastion reattach contract) | ❌ typed `Protocol` (no in-flight injection method observed) | ✅ | ✅ | ❌ `HarnessOwned` — see §3 | ✅ |
| `acpx_opencode` | ❌ same as `acpx_claude` (agent-independent, rooted in the acpx transport) | ❌ same as `acpx_claude` | ✅ | ✅ (per-agent frame-shape caveat, §4) | ❌ `HarnessOwned` | ✅ |

## 3. Policy coverage (`PolicyCoverage`)

| Target | Tool visibility | Approvals | Egress | Budget | Sandbox |
|---|---|---|---|---|---|
| `codex_app_server` | `DeclaredOnly` | **`Bridged`** — real `item/*/requestApproval` ↔ `ApprovalGate` round trip | `HarnessOwned` (Bastion filters what enters via `TaskInput`; the harness's own model/tool network authority is its own) | `Reported` | **Detected, not declared** — `Partial` only when a live `bwrap --unshare-user` probe succeeds on the host at `health()` time; `None` (fail-closed) otherwise. Never `Honored`: a working probe proves the *mechanism*, not that one specific turn was actually confined. |
| `acpx_claude` | `DeclaredOnly` | `HarnessOwned` — acpx resolves permission prompts itself from static `--approve-all`/`--deny-all`/`--approve-reads` flags; there is no observed way for Bastion to intercept and answer one | `HarnessOwned` | `Reported` | `None` — acpx passes `--cwd` as a hint only, never an enforced jail |
| `acpx_opencode` | `DeclaredOnly` | `HarnessOwned` (identical mechanism to `acpx_claude` — the acpx transport, not the wrapped agent, owns this) | `HarnessOwned` | `Reported` | `None` |

**Reading `Bridged` vs `HarnessOwned` as a security property, not just a UX one:** even `Bridged` (Codex) only gates *the specific tool call that asked* — a capable model can retry the same goal through a different, ungated tool call after one denial (documented finding). Bastion's product default (`DenyScope::Turn`) closes this by cancelling the task after a denial rather than letting the harness keep trying — this is enforced at the adapter boundary for every target, independent of `ApprovalCoverage`.

## 4. Conformance status (live, reproducible)

| Target | Status | Scorecard |
|---|---|---|
| `acpx_claude` | **Done** | 9 passed, 5 skipped, 0 failed |
| `codex_app_server` | **Done** | 9 passed, 3 skipped, 2 failed-by-construction in the default sweep (resolved by a dedicated approval-bridge run: allow ✅, deny ✅ with the T4 caveat above) |
| `acpx_opencode` | **Mostly done** | 8 passed, 5 skipped, 1 failed (`artifact_digest` — `FrameInterpreter`'s tool-call/artifact joining doesn't yet recognize opencode's frame shape; unrelated to auth) |
| `codex` via `acpx` (3-way comparison cell) | **Unavailable** | The ACP bridge only advertises `gpt-5.3-codex*`/non-codex models, and the Codex backend rejects that family under ChatGPT-subscription auth — a login-mode mismatch external to both adapters, not something Bastion can route around |

## 5. Delegated tasks (mode 3 — `task_runtime`, independent of the conversation backend)

Any target above that supports `start()` can serve as a delegated-task runtime regardless of what the CONVERSATION backend is (a `Model`-conversation owner can still delegate a coding task to `codex_app_server`, for example). Resume-after-restart for an **in-flight** delegated task is a known, disclosed protocol gap: `AgentRuntime::resume` reattaches the harness SESSION, not the specific task that was running — neither `acpx` nor `codex app-server`'s own protocol buffers/replays events across a real process restart. `acpx` additionally cannot serve the resume leg at all (`supports.resume = false`); `codex_app_server` can.

## 6. How to select a backend

Declarative (`bastion.toml`, applied at daemon startup):

```toml
[backend]
conversation = "runtime:acpx_claude"   # or "model" (default), or a bare id
task_runtime = "codex_app_server"      # optional, independent of `conversation`
auth = "host-claude-login"             # references [auth.<profile>] below

[auth.host-claude-login]
kind = "host-cli"
cli = "claude"

[auth.host-chatgpt-login]
kind = "host-cli"
cli = "codex"

[auth.my-openrouter-key]
kind = "api-key"
env_var = "OPENROUTER_API_KEY"
```

Live (no restart, cockpit command — reuses the same command surface as `/goals`/`/drift`/`/memories`):

```
/backends                        — list every backend Bastion currently knows about,
                                    with live health, policy coverage, and which one
                                    is selected right now (for conversation AND task_runtime)
/backend use model               — switch the conversation backend back to Bastion's own loop
/backend use <id>                — switch the conversation backend to a registered runtime
/backend use task:<id>           — set the delegated-task runtime
/backend use task:none           — disable delegation
```

`/backend use` is a global switch on the running daemon process (the daemon serializes every owner's turn through one shared agent loop) — not a per-owner preference yet; it changes what every subsequent turn uses until changed again or the process restarts back to the `[backend]` TOML default. Any id the registry cannot currently resolve (unregistered, or registered but unhealthy right now) is rejected with a diagnostic error and leaves the current selection completely untouched — never a half-applied switch, never a silent fallback to `model`.
