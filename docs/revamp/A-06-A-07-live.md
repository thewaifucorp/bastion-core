# A-06 / A-07 — live proof scoreboard (Ciclo 2.4)

> Companion to `docs/revamp/C2-backend-profile-design.md` §4. Each row is a
> REAL run against a real, host-authenticated harness through the REAL daemon
> path (`AgentLoop::run_turn_for`/`AgentLoop`'s task-delegation surface) —
> not adapter-level conformance (that's A-03/A-04/A-05).

## A-06 — runtime-backed primary conversation (mode 2)

**Status: PASS, run live.**

| Field | Value |
|---|---|
| Test | `tests/agent_runtime_backend_live.rs::a06_runtime_backed_conversation_live` |
| Command | `cargo test --test agent_runtime_backend_live -- --ignored --nocapture` |
| Harness | `AcpxAgentRuntime("claude")` → `acpx 0.12.0` → Claude Code (host session auth) |
| Path exercised | `AgentLoop::run_turn_for` → `run_turn_for_with_trust` → `ConversationBackend::Runtime("acpx_claude")` branch → `AgentLoop::run_runtime_backed_turn` (real `main.rs`/`AgentLoop` composition path, not a bypass) |
| Prompt | `"Reply with exactly this and nothing else: BASTION-A06-OK"` |
| Result | `health().ready == true` (acpx 0.12.0 detected); response == `"BASTION-A06-OK"`; assistant response found in session history (`SessionManager::load_recent`) — i.e. Bastion's own memory/conversation record, not just the harness's own session |
| Run at | 2026-07-14, this cycle |
| Cost/parsimony | one tiny prompt, no tool calls, ~7s wall time |

What this proves, concretely: a turn that starts at `AgentLoop::run_turn_for` (the exact same entry point every channel funnels through), with `BackendProfile.conversation == Runtime("acpx_claude")`, is served ENTIRELY by the external harness's tool-loop (Claude Code via acpx), and the response comes back through Bastion's normal turn-completion path: persisted to the SQLite session store, returned as the turn's answer. Codex was not used for A-06 (acpx→Claude Code was cheaper/already-authenticated on this host and sufficient to prove the mode-2 wiring; A-03/A-04 already validated both adapters individually at the conformance layer).

### Known scope limits of the mode-2 integration (this cycle, not a defect)

- **Permission requests are NOT resolved cross-turn in mode 2 — by design, not a gap.** The daemon serializes through one `&mut agent` (AGENTS.md architecture law) — `run_runtime_backed_turn` runs synchronously inside one turn and cannot block waiting for a LATER turn's plain-language "sim"/"não" reply without freezing the daemon for every other owner. A `PermissionRequest` event is audited into the `PermissionGate`/`permission_queue` (Loop 3-A, §6a below) and then answered `Deny { scope: DenyScope::Turn }` immediately — fail-closed, consistent with the Model path's own Turn-scoped-denial semantics. Loop 3-A (6a) DID close genuine cross-turn resolution for mode 3 (delegated tasks, which run off the `&mut agent` critical path already) — mode 2 stays immediate-deny-only deliberately; see `run_runtime_backed_turn`'s rustdoc. A-06's prompt was deliberately tool-call-free so this path was never exercised by the passing run above.
- **No trace-context handoff to the harness.** `OtelContext` is left at its default; the existing `invoke_agent` root span still wraps the whole runtime-backed call (process-level correlation), but neither shipped adapter's protocol (codex app-server JSON-RPC, acpx NDJSON) has a slot to carry a `trace_id`/`parent_span_id` into the harness process itself.
- **Workspace root is a fixed per-owner temp directory** (`runtime_workspace_root`, `<tmp>/bastion-agent-runtime-workspaces/<owner>`), not yet a configurable per-deployment policy.

## A-07 — delegated task (mode 3)

**Status: PASS, run live.**

| Field | Value |
|---|---|
| Test | `tests/agent_runtime_delegated_task_live.rs::a07_delegated_task_concurrent_cancel_and_resume_live` |
| Command | `cargo test --test agent_runtime_delegated_task_live -- --ignored --nocapture` |
| Harness | `CodexAppServerRuntime` → `codex-cli 0.144.1` (host ChatGPT login) |
| Surface exercised | `AgentLoop::delegate_task` / `AgentLoop::cancel_delegated_task` / `AgentLoop::resume_delegated_task` — the real host-level API (not a bypass); conversation backend stayed `Model` throughout (delegation is independent of the conversation backend) |
| Run at | 2026-07-14, this cycle | 16.14s total wall time |

Four things proven in one run, all through the real methods:

1. **Delegation is non-blocking.** `delegate_task` (task1, prompt `"Reply with exactly this and nothing else: BASTION-A07-TASK1-OK"`) returned in 1.64s (start + submit only — it does not wait for the task).
2. **The conversation stays responsive concurrently.** Immediately after delegating task1, a normal `run_turn_for` call (Model backend, mocked provider) on the SAME `AgentLoop` completed in 19ms — not blocked on the background task.
3. **Cancel works and reports back.** Task2 (a `sleep 15 && echo done` shell prompt) was cancelled ~2s after delegation via `cancel_delegated_task`; the harness reported `TaskOutcome::Cancelled` ~2s later, delivered via the `pending_tx` PROACT-05 seam as `"[Tarefa delegada '...' cancelada]"`.
4. **Resume-after-restart works, with a disclosed contract limitation.** A third session was started directly, warmed up with one completed turn (codex only persists a resumable rollout after a real turn ran — same finding `codex_v2_resume_smoke` documented), then the process was killed (`drop(session)`, `kill_on_drop`) to simulate a daemon restart. `AgentLoop::resume_delegated_task` reattached the session successfully and submitted a follow-up task (`"...BASTION-A07-RESUME-OK"`), which completed and delivered its result via the same `pending_tx` path. The adapter correctly surfaced a `Warning{code: DegradedTransport}` on resume — codex's `thread/resume` protocol has no field for `PermissionProfile`, so the reattached thread kept its original `approvalPolicy` (documented in `codex.rs`, re-confirmed live here).

### Known scope limits / findings from this cycle (not defects — see rationale in code + `run_runtime_backed_turn`'s rustdoc, shared by mode 3)

- **No cross-restart task continuation in the contract.** `AgentRuntime::resume` reattaches the harness SESSION; neither shipped adapter buffers/replays events for a task that was already in flight when the connection was lost. `resume_delegated_task` is honest about this: it submits a NEW follow-up task on the reattached session rather than pretending to continue the original one. A richer "the exact same task keeps going across a restart" guarantee is not something this contract can deliver today without a protocol-level replay mechanism neither codex nor acpx expose. **Still open (6b) — furo de protocolo do harness, fora de alcance do kernel.**
- ~~**Permission requests during a delegated task get the same fail-closed audited-deny as mode 2**~~ **RESOLVED (Loop 3-A, `docs/revamp/C3-runtime-followups-design.md` §6a).** A delegated task's `PermissionRequest` now genuinely PAUSES (`spawn_delegated_task_consumer` → `wait_for_permission_resolution`) instead of denying instantly: persisted owner-scoped in `permission_queue` (`PermissionGate`/`SqlitePermissionGate`), correlated by `PendingPermission::row_id`, resolvable by a LATER turn via `AgentLoop::respond_permission(owner, row_id, decision)` — or fail-closed `Deny{Turn}` on `expires_at` timeout (default 10 minutes, configurable via `AgentLoop::with_permission_timeout`) or if the task is cancelled while paused. Proven complete against an in-process pause-capable `FakeRuntime` (`tests/agent_runtime_cross_turn_permission.rs`: allow / explicit deny / timeout, 3 passing scenarios) — not re-run live against Codex/acpx this cycle (would require a real permission prompt to stay open for the test's duration).
  - **Per-adapter pause-support matrix (honest, not yet live-verified):** neither `codex_app_server` nor `acpx` has been proven in a live run to keep a `PermissionRequest` genuinely open across an extended wait (this cycle's A-07 live run above had no tool call negotiate a real approval — task2's shell command was cancelled explicitly before any approval negotiation, and task1/task3 needed no tool call at all). Until proven otherwise with a live run, treat BOTH shipped adapters' effective behavior as `Deny{Turn}` at `permission_timeout` — the infra is ready and fully tested on `FakeRuntime`, and works completely with any harness whose own protocol tolerates Bastion holding off on `respond_permission` for the configured window; this is an adapter-protocol property, not a kernel limitation.
- ~~**`pending_tx`/`pending_rx` is not owner-routed.**~~ **RESOLVED (Loop 3-A, `docs/revamp/C3-runtime-followups-design.md` §6d).** The queued item is now `PendingItem { owner: Option<String>, text: String }` — `spawn_delegated_task_consumer` tags results with the delegating owner; `main.rs`'s `pending_rx` arm routes via `run_turn_for(&item.text, owner)`, `DEFAULT_OWNER` only as a fallback for an item with no owner (no current producer omits one). Regression test: `delegate_task_pending_item_never_crosses_owner_boundary` (`crates/bastion-runtime/src/agent/loop_.rs`) — two owners delegate concurrently on the SAME `AgentLoop`, each result arrives tagged with the correct owner, never crossed.
- **acpx cannot be used for the resume leg** (`supports.resume = false`, always `NotResumable` — by honest design, see `acpx.rs`) — A-07's resume proof required Codex specifically; acpx remains a valid `task_runtime` choice for the non-resume parts (delegate/cancel).
