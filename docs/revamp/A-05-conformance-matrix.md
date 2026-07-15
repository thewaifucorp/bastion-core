# A-05 — Adapter conformance matrix (partial)

> Covers the A-05 slice of Trilha A: side-by-side conformance of the two
> adapters implemented so far — `AcpxAgentRuntime` (A-04, supervised ACP
> client) and `CodexAppServerRuntime` (A-03, native app-server). Depends on:
> A-01 contract (`crates/bastion-agent-runtime/src/lib.rs`), A-02 suite
> (`crates/bastion-agent-runtime/src/conformance.rs`).
>
> Scorecards below are from live runs against real, host-authenticated
> harnesses on this dev machine (`acpx 0.12.0`, `claude` Claude Code CLI
> logged in, `codex-cli 0.144.1` logged in via ChatGPT, `opencode 1.17.15`
> logged in via `opencode auth login`) on 2026-07-13/14. Reproduce with
> `cargo test -p bastion-agent-runtime --test <name> -- --ignored
> --nocapture` (tests are `#[ignore]`-gated — they spawn real subprocesses
> and cost real tokens, so they never run in default `cargo test`; the
> opencode run in §2A is the one exception that costs zero tokens, see
> that section for why).

## 1. Scope actually covered

| Cell | Status |
|---|---|
| `claude` via `acpx` (A-04) | **Done** — full run, see §2 |
| `codex` native app-server (A-03) | **Done** — full run, see §3 |
| `opencode` via `acpx` (A-04 smoke) | **Done (mostly)** — `fix(c3): configurable acpx --auth-policy` (Loop 3-B) made `--auth-policy` a per-agent adapter field (`"skip"` for `opencode`, `"fail"` everywhere else, unchanged for `claude`), closing the adapter-level mismatch documented below. Real live re-run: **8 passed, 5 skipped, 1 failed** — `happy_path` genuinely `Pass`es now; one unrelated, newly-discovered gap (`artifact_digest`) remains — see §2A. |
| `codex` via `acpx` (would complete the 3-way matrix) | **Unavailable** — see §4. `acpx codex ...` genuinely reaches the codex ACP bridge, but every prompt fails with `The 'gpt-5.3-codex' model is not supported when using Codex with a ChatGPT account` (verified with the default model and every explicit `gpt-5.3-codex[*]` variant the bridge advertises) — a login-mode mismatch in the bridge itself, not something a prompt/config change on our side fixes. |

The three-way "same suite, three transports" comparison from A-01 §5.14
("Codex nativo E Codex-via-ACP passam idênticos") is therefore **partially**
blocked in this environment: the native side is fully proven; the ACP side
for the *same* harness (codex-via-acpx) cannot run here for a login-config
reason external to both adapters.

## 2. `AcpxAgentRuntime` × `claude` — live scorecard

Command: `cargo test -p bastion-agent-runtime --test acpx_live_claude -- --ignored --nocapture`

| Check | Result |
|---|---|
| happy_path | PASS |
| resume | PASS (typed `NotResumable` — `supports.resume=false`, honest) |
| steer | PASS (typed `Protocol` — `supports.steer=false`, honest) |
| cancel_graceful | PASS |
| cancel_kill | PASS |
| timeout | PASS |
| queue_or_reject | PASS |
| event_ordering_terminal | PASS |
| artifact_digest | PASS |
| permission_bridge_allow | SKIP — `policy_coverage.approvals == HarnessOwned` |
| permission_bridge_deny | SKIP — `policy_coverage.approvals == HarnessOwned` |
| crash_isolation | SKIP — `FaultInjection::induce_crash` unimplemented |
| auth_typed | SKIP — `FaultInjection::induce_auth_failure` unimplemented |
| protocol_garbage | SKIP — `FaultInjection::feed_garbage_frame` unimplemented |

**9 passed, 5 skipped, 0 failed** (reproduced clean on repeat runs; two
earlier runs hit `WATCHDOG`-related timeouts — see §5.1).

### `PolicyCoverage` declared

```
tool_visibility: DeclaredOnly
approvals:       HarnessOwned
egress:          HarnessOwned
budget:          Reported
sandbox:         None
```

`supports`: `resume=false, steer=false, usage_reporting=true, diff_events=true, permission_bridge=false, concurrent_sessions=true`.

## 2A. `AcpxAgentRuntime` × `opencode` — live scorecard

Command: `cargo test -p bastion-agent-runtime --test acpx_live_opencode -- --ignored --nocapture`

> **Status: unblocked (Loop 3-B, `fix(c3): configurable acpx --auth-policy`).**
> The history below (adapter-level `--auth-policy fail` mismatch) is kept
> verbatim as the record of what was found and why; §2A.1 below it has the
> fix and the real, current scorecard.

`opencode auth login` is done on this host (`opencode auth list` shows
`OpenCode Go`/`OpenAI`/`OpenCode Zen` credentials), which resolves the
*previous* blocker recorded here (missing host auth). Re-testing surfaced a
**different, adapter-level** blocker:

`AcpxAgentRuntime::build_prompt_command` (`src/acpx.rs`) unconditionally
appends `--auth-policy fail` for every wrapped agent. `opencode`'s native
ACP server (`opencode acp`, spawned by acpx as `npx -y opencode-ai acp`)
advertises ACP `authMethods: [{"id": "opencode-login", ...}]` on
`initialize`. acpx tries to match that against its **own** credential
store (the one it uses to broker auth directly for agents it understands),
finds nothing — opencode keeps its own, separate
`~/.local/share/opencode/auth.json` that acpx's matcher doesn't know
about — and with `--auth-policy fail` aborts the whole invocation with an
unsolicited, uncorrelated (`"id": null`, no `"method"`) top-level JSON-RPC
error **before `session/prompt` is ever sent**:

```
{"jsonrpc":"2.0","id":null,"error":{"code":-32603,
 "message":"agent advertised auth methods [opencode-login] but no
 matching credentials found",
 "data":{"acpxCode":"RUNTIME","detailCode":"AUTH_REQUIRED","origin":"acp", ...}}}
```

**Proof the underlying pairing is not broken**: the exact same manual
invocation with `--auth-policy skip` (or no `--auth-policy` flag at all —
acpx's own CLI default) completes a full turn using the host's already-
persisted opencode credentials — `session/resume` → `session/prompt` →
`agent_message_chunk` → `Ended{Success}`, real reply, `$0` cost (opencode's
own `-free` models were available too, e.g. `opencode/north-mini-code-free`,
but the default `opencode/big-pickle` used in the working manual run also
reported `cost: {"amount": 0}`).

`claude` is unaffected by the same hardcoded flag because acpx spawns it
through a **built-in agent bridge**
(`@agentclientprotocol/claude-agent-acp`) that never advertises ACP
`authMethods`, so the credential-matching/abort branch simply never
triggers for that agent — an acpx-side, per-wrapped-agent inconsistency,
not something `AcpxAgentRuntime` controls once it hardcodes `fail`.

Because the abort frame has no `"method"` and an `"id"` that never matches
our own `session/prompt` request id, the private `FrameInterpreter` in
`src/acpx.rs` doesn't recognize it as anything actionable (by design — it
only reacts to `session/update` and to responses/errors correlated by id);
it's silently ignored, the acpx child process then exits, stdout hits EOF,
and `run_prompt_reader` reports the generic
`TaskOutcome::Failed { reason: "acpx process ended without a terminal
frame (crash or premature exit)" }` — never anything auth-specific.

**Historical (pre-fix) scorecard, kept for the record:**

| Check | Result |
|---|---|
| happy_path | FAIL — `expected Success, got Failed { reason: "acpx process ended without a terminal frame (crash or premature exit)" }` |
| resume | PASS (typed `NotResumable` — agent-independent, same as claude) |
| steer | PASS (typed `Protocol` — agent-independent, same as claude) |
| cancel_graceful | PASS — tolerates any terminal state, not just Success; the immediate abort still satisfies it |
| cancel_kill | PASS — same tolerance |
| timeout | PASS — same tolerance |
| queue_or_reject | FAIL — `task_b ended with Failed { reason: "acpx process ended without a terminal frame..." }` |
| event_ordering_terminal | FAIL — `expected task1 Success, got Failed { reason: "..." }` |
| artifact_digest | FAIL — `expected Success, got Failed { reason: "..." }` |
| permission_bridge_allow | SKIP — `policy_coverage.approvals == HarnessOwned` |
| permission_bridge_deny | SKIP — `policy_coverage.approvals == HarnessOwned` |
| crash_isolation | SKIP — `FaultInjection::induce_crash` unimplemented |
| auth_typed | SKIP — `FaultInjection::induce_auth_failure` unimplemented |
| protocol_garbage | SKIP — `FaultInjection::feed_garbage_frame` unimplemented |

5 passed, 5 skipped, 4 failed — reproduced clean at the time. **Zero LLM
tokens spent** on that run — the abort happened before `session/prompt` was
sent, so the whole sweep was a free, deterministic transport-level failure.

### 2A.1 Fix + re-run (Loop 3-B, `fix(c3): configurable acpx --auth-policy`)

`--auth-policy` is now a field on `AcpxAgentRuntime`
(`default_auth_policy_for`, `src/acpx.rs`), not a crate-wide hardcoded
constant: `"skip"` for `"opencode"` (the one agent whose ACP server
advertises `authMethods` acpx's own matcher can't resolve — see history
above), `"fail"` (the prior, unconditional behavior) for every other agent,
including `"claude"` (unaffected either way — it never advertises
`authMethods`). `AcpxAgentRuntime::with_auth_policy` lets a caller override
either default explicitly. This closes the gap **without** touching
`FrameInterpreter`'s frame recognition, and without any change to the
permission-flag mapping (`permission_flags`) — exclusively about which
stored credential set acpx trusts for the ACP handshake.

Re-run live (2026-07-14, `opencode 1.17.15`, real `acpx opencode prompt`
subprocesses, real tokens against whatever model acpx/opencode picked by
default — no override):

| Check | Result |
|---|---|
| happy_path | **PASS** — the direct proof of this fix |
| resume | PASS (typed `NotResumable` — agent-independent, same as claude) |
| steer | PASS (typed `Protocol` — agent-independent, same as claude) |
| cancel_graceful | PASS |
| cancel_kill | PASS |
| timeout | PASS |
| queue_or_reject | PASS |
| event_ordering_terminal | PASS |
| artifact_digest | **FAIL** — `"no Artifact event observed before Ended"` — see below, a DIFFERENT, newly-discovered gap |
| permission_bridge_allow | SKIP — `policy_coverage.approvals == HarnessOwned` |
| permission_bridge_deny | SKIP — `policy_coverage.approvals == HarnessOwned` |
| crash_isolation | SKIP — `FaultInjection::induce_crash` unimplemented |
| auth_typed | SKIP — `FaultInjection::induce_auth_failure` unimplemented |
| protocol_garbage | SKIP — `FaultInjection::feed_garbage_frame` unimplemented |

**8 passed, 5 skipped, 1 failed** — reproduced clean
(`crates/bastion-agent-runtime/tests/acpx_live_opencode.rs` asserts this
exact shape: the 8 `must_pass` checks explicitly, the one known
`artifact_digest` Fail explicitly, the 5 Skips explicitly — no blanket
"no Fail" assertion, so a regression to a DIFFERENT failure mode, or an
unexpected Pass, both fail loudly instead of being silently absorbed).

**New finding, not fixed here:** `artifact_digest`'s Fail is unrelated to
the auth-policy mismatch — `FrameInterpreter`'s tool-call/artifact-candidate
joining (`remember_file_path`/the `toolCallId`-keyed `tool_file_paths` map
in `src/acpx.rs`) was written against `claude`'s observed frame shape
(`rawInput.file_path` on the `tool_call` frame, a `content: [{"type":
"diff", ...}]` array on the terminal `tool_call_update`). `opencode`'s ACP
server apparently shapes the equivalent frames differently, so no
`Diff`/artifact-candidate is ever produced for its file-write tool call —
genuine, reproducible, a real adapter-vs-wrapped-agent difference (same
category as the codex-native sandbox-degradation finding in §5.2), not a
regression of this fix. Fixing it would mean teaching `FrameInterpreter` a
second, opencode-specific frame shape — a real adapter change needing its
own impact analysis, out of scope for this cycle (which was narrowly the
`--auth-policy` mismatch). Left for a future cycle.

### `PolicyCoverage` declared

Identical to §2 (`AcpxAgentRuntime`'s `descriptor()` is not
agent-parameterized for `policy_coverage`/`supports` — same declaration for
every wrapped agent):

```
tool_visibility: DeclaredOnly
approvals:       HarnessOwned
egress:          HarnessOwned
budget:          Reported
sandbox:         None
```

`supports`: `resume=false, steer=false, usage_reporting=true, diff_events=true, permission_bridge=false, concurrent_sessions=true`.

## 3. `CodexAppServerRuntime` × `codex` (native) — live scorecard

Command: `cargo test -p bastion-agent-runtime --test codex_live codex_conformance_live_trusted -- --ignored --nocapture`
(sandbox `danger-full-access`, `permissions.allow=["*"]` → `approvalPolicy: "never"` — see §5.2 for why).

| Check | Result |
|---|---|
| happy_path | PASS |
| resume | PASS (genuine reattach — see §3.2) |
| steer | PASS (needed a bounded retry — see §5.3) |
| cancel_graceful | PASS |
| cancel_kill | PASS |
| timeout | PASS (was misreported as `Cancelled` before a fix — see §5.4) |
| queue_or_reject | PASS |
| event_ordering_terminal | PASS |
| artifact_digest | PASS |
| permission_bridge_allow | FAIL in this sweep (expected — this spec's `approvalPolicy: "never"` never raises a request; see §3.1 and the dedicated run below) |
| permission_bridge_deny | FAIL in this sweep (same reason) |
| crash_isolation | SKIP — `FaultInjection::induce_crash` unimplemented |
| auth_typed | SKIP — `FaultInjection::induce_auth_failure` unimplemented |
| protocol_garbage | SKIP — `FaultInjection::feed_garbage_frame` unimplemented |

**9 passed, 3 skipped, 2 failed** (the 2 failures are the same "never" vs
"on-request" tension explained in §3.1, resolved by the dedicated run below
— not a defect).

### 3.1 The permission-bridge tension, and how it was resolved

`conformance::run_all` uses **one** `SessionSpec` for all 14 checks.
`CodexAppServerRuntime` honestly declares `approvals: Bridged` (a real
capability — see §3.3), so `run_all` does not skip
`permission_bridge_allow`/`_deny` the way it does for the acpx adapter.
But the *same* spec also has to keep `happy_path`/`artifact_digest`/etc.
from hanging on an unanswered approval, and this dev host has no working
bubblewrap (§5.2), so **any** `approvalPolicy` other than `"never"` makes
**every** tool call escalate to a real approval request — including the
plain "create hello.txt" prompt those other checks use, with nobody
answering it.

Resolution: `codex_live.rs` ships two separate live tests instead of
forcing one spec to do both jobs:

- `codex_conformance_live_trusted` — `allow=["*"]` → `"never"`, the sweep
  above (9/9 non-bridge checks pass; the two bridge checks are excluded
  from the pass/fail assertion with a comment, since they can't fire under
  this spec by construction).
- `codex_conformance_live_approval_bridge` — a **separate** spec
  (`allow=[]` → `"on-request"`, `sandbox: workspace-write`) that calls
  `conformance::check_permission_bridge_allow`/`_deny` directly (both are
  `pub` in `conformance.rs`), proving the bridge itself:

  ```
  cargo test -p bastion-agent-runtime --test codex_live \
    codex_conformance_live_approval_bridge -- --ignored --nocapture
  ```

  - `permission_bridge_allow`: **Pass** — `item/fileChange/requestApproval`
    observed, `respond_permission(Allow)` sent, `Artifact`/`ToolResult`
    followed, `Ended{Success}`.
  - `permission_bridge_deny`: **not hard-asserted** — reproduced multiple
    times, `respond_permission(Deny)` genuinely blocks the *declined* tool
    call, but a sufficiently agentic model routes around a single denial
    via an alternate, ungated tool call (e.g. a plain shell write instead
    of the structured file-write tool) and the file ends up written
    anyway through that second path. This is a **real A-01 threat-model
    finding** (§5.5), not an adapter defect — the Allow path proves the
    bridge answers real requests; the Deny path shows a single decision
    gates one tool-call instance, not the model's goal.

### 3.2 `resume` — genuine, verified live

Unlike acpx, `thread/resume {threadId}` on a **freshly spawned**
`codex app-server` process reattaches a thread started by a **different,
now-dead** process. Verified with a standalone protocol probe (not through
the Rust adapter): start a turn, `SIGTERM` the process, spawn a new one,
`initialize`/`initialized`, `thread/resume` the same `threadId` →
`{"id":1,"result":{"thread":{...}}}`, success.

### 3.3 `PolicyCoverage` declared

```
tool_visibility: DeclaredOnly
approvals:       Bridged
egress:          HarnessOwned
budget:          Reported
sandbox:         Partial   (not Honored — see §5.2)
```

`supports`: `resume=true, steer=true, usage_reporting=true, diff_events=true, permission_bridge=true, concurrent_sessions=false`.

## 4. `codex` via `acpx` — attempted, unavailable

```
acpx --format json codex exec "Reply with exactly: ok"
```

reaches the real ACP handshake (`initialize`, `session/new`, model list
advertised: `gpt-5.3-codex[low|medium|high|xhigh]`, `gpt-5.5[*]`,
`gpt-5.2[*]`, `gpt-5.4[*]`, `gpt-5.4-mini[*]`) but every actual prompt
returns, inside the ordinary agent-message stream (not a transport error):

```
{"type":"error","status":400,"error":{"type":"invalid_request_error",
 "message":"The 'gpt-5.3-codex' model is not supported when using Codex
 with a ChatGPT account."}}
```

Tried the default model and an explicit `--model "gpt-5.3-codex[low]"` —
same rejection both times. The acpx↔codex ACP bridge apparently only
offers the `gpt-5.3-codex` family (plus non-codex GPT models), and the
Codex backend rejects that family under ChatGPT-subscription auth (as
opposed to API-key auth). This is a login-mode mismatch in the bridge,
external to both `AcpxAgentRuntime` and `CodexAppServerRuntime` — nothing
in our adapters can route around a 400 from the upstream API.

## 5. Contract findings (A-01/A-02 gaps found in practice)

### 5.1 `conformance::WATCHDOG` (5s, hardcoded) is tight for live cloud adapters

Both live suites hit spurious failures shaped like
`"timed out waiting for ... Ended"` on isolated runs, always resolving
clean on retry, never with a wrong *outcome* — only wall-clock. `run_all`
calls `AgentRuntime::start` **14 times** in quick succession (once per
check); for a real cloud-backed harness each `start` is a genuine cold
session (new process, new conversation context, sometimes a fresh
`claude-agent-acp`/model-provider handshake), and 14 of those in ~40-70s
create real, variable latency that a fixed 5s per-event watchdog
(`const WATCHDOG: Duration = Duration::from_secs(5)` in
`conformance.rs`) was not designed to absorb — it fits the embedded
`FakeRuntime` and local-subprocess adapters well, less so a live
cloud-backed one. **Suggested follow-up**: make the watchdog
adapter-declared or run-configurable rather than a crate-wide constant.

### 5.2 Sandbox enforcement is host-dependent, and silently degrades

On this dev host, `bubblewrap`/user-namespaces are unavailable
(`codex` logs `Codex's Linux sandbox uses bubblewrap and needs access to
create user namespaces` on every launch). Consequence, verified live:

- `sandbox: "workspace-write"` + `approvalPolicy: "never"` — file writes
  **fail silently inside the sandbox**, and the model retries several
  alternate strategies (`touch`, shell heredocs, ...) burning tokens
  before giving up with an **empty** file instead of the requested
  content.
- `sandbox: "workspace-write"` + `approvalPolicy: "on-request"` — the
  sandboxed attempt fails, and *that specific failure* is what triggers
  the approval escalation ("command failed; retry without sandbox?") —
  i.e. on this class of host, `on-request` behaves like "ask about
  everything" rather than "ask only when escalating past the sandbox".
- `sandbox: "danger-full-access"` — bypasses the broken sandbox
  entirely; writes succeed on the first attempt with correct content.

`CodexAppServerRuntime` declares `sandbox: Partial`, not `Honored`, to
reflect this: the *intent* (`workspace-write`) is real, but whether it
actually confines anything depends on host kernel capabilities the
adapter cannot detect from inside a JSON-RPC session. **Suggested
follow-up**: `RuntimeHealth` or a dedicated capability probe could surface
"sandbox actually available" so callers don't have to learn this the
way we did (a live conformance run).

### 5.3 `turn/steer` has a transient server-side readiness race

`turn/start`'s acknowledgment (`status: "inProgress"`) arrives before the
server's own turn state machine is ready to accept `turn/steer` on it. A
`turn/steer` sent immediately after `submit()` returns is sometimes
rejected by the **server itself** with `"no active turn to steer"` even
though the adapter's own bookkeeping already shows the turn as active
(reproduced deterministically 3/3 times before the fix; a manual probe
that waited ~3s before steering worked every time). Fixed with a bounded
retry (4 attempts, 400ms apart) in `CodexSession::steer` — a legitimate
robustness fix for a real upstream timing gap, not a workaround for an
adapter bug. Worth an upstream report to the `codex-cli` team.

### 5.4 `turn/interrupt` is ambiguous between "cancelled" and "timed out"

`turn/completed` reports the same `status: "interrupted"` whether the
interrupt was cooperative-cancel (`RuntimeSession::cancel`) or our own
timeout watchdog force-stopping a task. A naive mapping reports
`TaskOutcome::Cancelled` for both, which fails the A-02 `timeout` check
(expects `TimedOut`) — reproduced live. Fixed by tracking
timeout-initiated `turnId`s in a small `Shared.timed_out_turns` set,
checked (and cleared) when `turn/completed` arrives, so the two paths are
told apart client-side. This is inherent to the protocol (no
distinguishing status/reason code from the server) — any adapter over
this protocol needs the same client-side bookkeeping.

### 5.5 A single `respond_permission(Deny)` gates a tool-call instance, not the model's goal (T4-adjacent)

Reproduced live (§3.1): declining one `item/fileChange/requestApproval`
genuinely blocks *that* call — the server accepts the decline and the
declined write never lands — but a capable model can retry the same
underlying goal through a **different, ungated** tool call (e.g. a plain
shell write instead of the structured file-write tool) and succeed
anyway. `PolicyCoverage.approvals: Bridged` is still the honest
declaration (the bridge mechanism genuinely works, faithfully, on the
instance it was asked about), but it should not be read as "the model was
prevented from doing X" — only "this specific tool call was blocked".
Products consuming `Bridged` for a *safety* guarantee (not just a UX
approval prompt) need a policy layer that recognizes and blocks
equivalent alternate tool calls, not just the one that happened to ask —
squarely T4 in the A-01 threat model ("Bypass de approval").

### 5.6 `resume()` receives no `SessionSpec` — real recovery gap

`AgentRuntime::resume(&self, handle: &SessionHandle)` has no
`SessionSpec` parameter, so an adapter cannot recover the original
`EnvPolicy`/`TimeoutPolicy`/`PermissionProfile` purely from the handle.
`CodexAppServerRuntime::resume` recovers `cwd` for free (`thread/resume`
echoes the thread's own metadata) but falls back to conservative,
adapter-level defaults for env allowlist and timeouts
(`with_resume_env`, a fixed 300s/600s timeout pair) — reasonable, but a
real product needs the restart-recovery path to carry (or persist
alongside the `SessionHandle`) enough of the original spec to reopen the
session with the *same* policy, not the adapter's guess. **Suggested
follow-up**: an A-01 addendum — `resume` should probably accept an
optional `SessionSpec` override, with the current handle-only signature
as the fallback for "spec truly lost" cases.

### 5.7 acpx's own transport confirms the "no human stdout" invariant, but needs a live gotcha documented

`acpx --format json` cleanly separates structured NDJSON (stdout, one
JSON-RPC frame per line — verified: every stdout line across all commands
tried parses as JSON) from human banners (`[acpx] created session ...`,
always stderr). The one live gotcha: acpx is a Node shebang script, and
its own config/session store needs `HOME` — an adapter that fully
clears the child env (as the contract requires) must still be told to
allow `HOME` (not a credential) or session creation fails outright. Both
live test files pass `HOME`+`PATH` through `EnvPolicy::allow` for exactly
this reason.

## 6. Gates

`cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace` all green as of the A-03/A-04 commits (see
`crates/bastion-agent-runtime/src/acpx.rs`, `.../codex.rs`, and their
`#[cfg(test)]` modules — 25 unit tests total, subprocess-free, deterministic).

## 7. v2 re-run (Ciclo 2.2 — contract review closing the 6 findings in §5)

`docs/revamp/A-01-agentruntime-contract.md` was revised (v2) to close all 6
findings below by actually changing the contract/adapters, not just
documenting the gap. Re-validated in two passes: the full fake suite (all
14 checks, must stay 14/14/0), and a **minimal live smoke per adapter**
(happy path + the one check each adapter's v2 change actually affects) —
not the full 14-check live sweep again, per parsimony (real tokens/quota).

### 7.1 Fakes — full suite, contract v2

```
cargo test --test agent_runtime_conformance
```

**7 passed** (`agent_runtime_conformance_suite_all_pass` — 14/14 checks
Pass, 0 skip, 0 fail, unchanged from v1 — plus `session_handle_serde_round_trip`,
`runtime_error_auth_display_never_contains_secret_material`, and the two new
Ciclo 2.2 acceptance tests: `deny_turn_scope_cancels_the_task` —
`DenyScope::Turn` genuinely cancels the task (`Ended{Cancelled}` +
`status()==Cancelled`) — and `deny_instance_scope_leaves_task_completing_normally`
— `DenyScope::Instance` preserves the pre-v2 behavior).

### 7.2 `CodexAppServerRuntime` — live smoke, contract v2

```
cargo test -p bastion-agent-runtime --test codex_live codex_v2_resume_smoke -- --ignored --nocapture
```

| Check | Result |
|---|---|
| `health()` sandbox-coverage detection | `SandboxCoverage::None` — probed live (`bwrap --unshare-user ...` fails on this host, no working bubblewrap, exactly the §5.2 finding), NOT the old hardcoded `Partial` |
| `happy_path` | PASS |
| `resume()` with real `ResumeSpec` | PASS — start → submit a warm-up task → drain to `Ended` (a rollout must exist before a thread is resumable — a live detail this smoke found: resuming a thread with zero turns fails `NotResumable("no rollout found for thread id ...")`) → drop (kills the process) → `resume(handle, ResumeSpec{timeout, permissions, env})` on a **brand-new** process → genuine reattach → submit one more task → `Ended{Success}` |
| Permission-profile divergence `Warning` | PASS — the resumed session's first task surfaces `RuntimeEvent::Warning{code: DegradedTransport, ..}` documenting that `ResumeSpec.permissions` could not be threaded through `thread/resume` (protocol takes only a `threadId`) |

**1 passed, 0 failed** (all 3 assertions above are in the one test function).

### 7.3 `AcpxAgentRuntime` × `claude` — live smoke, contract v2

```
cargo test -p bastion-agent-runtime --test acpx_live_claude acpx_v2_happy_path_smoke -- --ignored --nocapture
```

This adapter's own coverage didn't change in v2 (still honestly
`NotResumable`/`HarnessOwned` — no `ResumeSpec`/`DenyScope` behavior newly
exercised here beyond a compiling signature change), so the smoke is a
minimal happy-path re-proof against the v2 contract shape.

| Check | Result |
|---|---|
| `happy_path` | PASS |

**1 passed, 0 failed.**

### 7.4 Findings closed

| # | A-05 §5 finding | v2 fix | Verified |
|---|---|---|---|
| 1 | `WATCHDOG` (5s hardcoded) tight for live cloud adapters | `ConformanceScenarios::watchdog: Duration` (was a crate `const`); live tests now pass 30s | Both live smokes above ran clean with `watchdog: Duration::from_secs(30)` |
| 2 | Sandbox coverage silently degrades, declared as a static `Partial` | `SandboxCoverage` now detected in `health()`/`start()` (`probe_sandbox_coverage`, real `bwrap --unshare-user` probe); no mechanism → `None`, never optimistic `Partial` | §7.2 — detected `None` live on this host (no working bubblewrap), matching the real host capability instead of a hardcoded guess |
| 3 | `turn/steer` readiness race | Already mitigated (bounded retry in `CodexSession::steer`); now a stated contract requirement (`RuntimeSession::steer` rustdoc, A-01 §5.3) | Unchanged behavior, just formalized — no new live run needed for this alone |
| 4 | `turn/interrupt` cancel-vs-timeout ambiguity | Already mitigated (`timed_out_turns` client-side tracking); now a stated contract requirement (`RuntimeEvent::Ended` rustdoc, A-01 §5.4) | Unchanged behavior, just formalized |
| 5 | `respond_permission(Deny)` gates one tool-call instance, not the model's goal (T4-adjacent) | `PermissionDecision::Deny{scope: DenyScope}` — `DenyScope::Turn` (product default) makes the adapter cancel the task gracefully after denying, closing the alternate-tool-routing gap at the adapter boundary; design owned by `docs/revamp/C2-approval-port-design.md` §3 | Fake: `deny_turn_scope_cancels_the_task` (§7.1). Live: not re-exercised this cycle (the live `codex_conformance_live_approval_bridge` deny path from §3.1 already documents the underlying threat; re-proving `Turn`'s cancel-after-deny live is deferred — cheap on the fake, real tokens/quota live, not required to close this finding since the mechanism is adapter-side and fully covered by the fake) |
| 6 | `resume()` had no `SessionSpec`, adapter used conservative defaults | `AgentRuntime::resume(&self, handle, spec: ResumeSpec)` — env/timeout genuinely re-applied; permissions surfaced as `Warning` when the protocol can't carry them | §7.2 — live, both the re-apply and the `Warning` |

Gates: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace` all green post-v2 (**570 passed, 5 ignored** — up
from 568 passed/3 ignored immediately before this cycle's edits; the 5
ignored are the live-only tests: `acpx_claude_conformance_live`,
`acpx_v2_happy_path_smoke`, `codex_conformance_live_trusted`,
`codex_conformance_live_approval_bridge`, `codex_v2_resume_smoke`).
