# Changelog

All notable changes to `bastion-core` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[docs/VERSIONING.md](docs/VERSIONING.md) (per-crate, not a single workspace
version).

## Unreleased

## 0.7.0 — 2026-09-26

Repo tag `v0.7.0`. `bastion-sandbox` 0.1.0 → 0.2.0 (`Backend` gained a
variant and is now `#[non_exhaustive]`) sets the minor; no other crate
version changed.

### Added

- **Windows backend for `bastion-sandbox` (BMD-05).** `Sandbox::detect` on
  Windows 10+ returns `Backend::AppContainer`: the helper starts the program
  in an AppContainer (lowbox token — Low integrity, privileges stripped,
  every access checked a second time against the container) inside a Job
  Object, waits for it and exits with its status. Same public API and helper
  protocol (`--backend appcontainer`) as the other backends.
  - **Filesystem:** the container reaches what Windows grants every
    AppContainer (reading `C:\Windows`, `C:\Program Files`) and the spec's
    paths, each granted by an allow ACE for the container SID (read/execute,
    or read/write/delete without `WRITE_DAC`). The operator's profile and any
    other path fail the container half of the access check.
  - **One container per grant set:** its name hashes the grants and the
    network mode, so the ACEs left on a path serve only later launches with
    the same grants; a path already readable by every AppContainer, or a
    read-only path whose ACL the operator cannot change, is not rewritten.
  - **Network:** blocked = no capabilities, every socket dropped by the
    Windows Filtering Platform, loopback included. Allowed = `internetClient`,
    `internetClientServer`, `privateNetworkClientServer`, plus a loopback
    exemption so the host's `127.0.0.1` is reachable — that exemption is a
    machine setting and needs an elevated helper; unelevated, the child has
    the network but not the host's loopback.
  - **Job Object:** the tree dies with the helper (killed included) and has
    no access to other processes' windows, the clipboard, global atoms or
    system settings.
  - **Environment:** exactly the spec's variables, as the child's environment
    block. Windows programs usually need `SystemRoot`; the spec must name it.
  - The Win32 calls live in one module (`src/appcontainer/win32.rs`) with a
    `SAFETY` note on each block; the crate lint went from `forbid` to `deny`
    so that module alone can allow `unsafe_code`.
- **Windows CI job (BMD-07).** `windows-latest` runs clippy
  (`-D warnings`) and the whole workspace's tests with
  `BASTION_SANDBOX_TESTS_REQUIRED=1`, so the confinement suites cannot skip.

### Changed

- `tests/confinement.rs` and `bastion-agent-runtime`'s
  `harness_confinement` run the same cases on every OS (`/bin/sh` on Unix,
  `cmd.exe` on Windows); the loopback case now reads the listener's reply.
  On Windows, with no working backend `Sandbox::detect` fails with
  `SandboxError::Unavailable` (tested), so `[sandbox] mode = "required"`
  keeps refusing to start there as on Linux and macOS (BMD-06).
- `Backend` is `#[non_exhaustive]`: a `match` on it needs a wildcard arm.

## 0.6.1 — 2026-09-26

Repo tag `v0.6.1`. Patch only: `bastion-providers` 0.2.6 → 0.2.7,
`bastion-cognition` 0.2.1 → 0.2.2, `bastion-runtime` 0.4.0 → 0.4.1 (all
additive).

### Added

- **Claude on Amazon Bedrock and Google Vertex AI in the native loop
  (`bastion-providers` 0.2.7).** `bedrock/<model id>` and `vertex/<model id>`
  resolve to the Anthropic provider over those endpoints — Bastion keeps its
  own tool loop, prompt caching and approvals, and pays per token through the
  cloud account.
  - **Bedrock** (`InvokeModel`): a Bedrock API key
    (`AWS_BEARER_TOKEN_BEDROCK`), or SigV4 (`aws-sigv4`) with keys from the
    environment, the profile's static keys in the shared credentials file, or
    `aws configure export-credentials` (SSO, assumed roles,
    `credential_process`; cached until shortly before expiry). Region from
    `AWS_REGION`/`AWS_DEFAULT_REGION`; `AWS_ENDPOINT_URL_BEDROCK_RUNTIME`
    overrides the host. The model id is percent-encoded as one path segment.
  - **Vertex** (`streamRawPredict`): Application Default Credentials — a
    service-account key (RS256 JWT signed locally with `ring`, exchanged at
    its `token_uri`), a `gcloud auth application-default login`
    (`authorized_user`, refresh token), or the metadata server; tokens cached.
    Project from `ANTHROPIC_VERTEX_PROJECT_ID`/`GOOGLE_CLOUD_PROJECT` or the
    credentials file, region `CLOUD_ML_REGION` (default `global`).
  - `name()` is `bedrock`/`vertex`: both are cloud destinations for the
    egress gate and are costed like the Anthropic API.
  - `src/anthropic/endpoint_tests.rs` runs all three endpoints against a local
    fake vendor (URL, auth, body, reply parsing, token caching, error status).
- **`memory_store` / `memory_revoke` capabilities (`bastion-cognition`
  0.2.2, `agent::memory_tools`).** The identity onboarding has always told
  the agent to save its identity with `memory_store`, which no path
  registered — every agent was asked for an identity forever. Both act on the
  caller's owner only; a core belief is refused unless it is the identity
  (`persona_tag = "identity"`), so an injected instruction cannot become
  permanent; `memory_revoke` needs the owner's approval; the tier is explicit
  (identity `cloud_ok`, anything else `local_only` by default).

### Fixed

- The direct Anthropic path no longer writes every streamed token to the
  daemon's stdout (`print!`), no longer drops a server-sent event split across
  two network reads (a split `input_json_delta` silently corrupted a tool
  call's arguments), and returns an error instead of panicking when
  `ANTHROPIC_API_KEY` is unset. `ANTHROPIC_BASE_URL` overrides the host.

## 0.6.0 — 2026-09-26

Repo tag `v0.6.0`. `bastion-agent-runtime` 0.2.1 → 0.3.0 (`McpBridgeSpec`
changed shape) and `bastion-runtime` 0.3.0 → 0.4.0 (new public fields on
`AgentLoop`) set the minor.

### Added

- **`bastion-runtime` 0.4.0 — runtime-backed conversation that asks before it
  acts.** New `agent::runtime_turn`:
  - One live harness session per Bastion session, kept between turns
    (`AgentLoop::live_runtime_sessions`), so an adapter that cannot reattach
    (`acp_*`) keeps its context for the whole conversation. Sessions idle past
    `runtime_session_idle` (30 min, `with_runtime_session_idle`) are closed.
  - A harness permission request **parks the turn** instead of being denied on
    the spot: it is recorded in the `PermissionGate`, the turn answers with the
    request and a compact diff of the proposed edit (changed lines only, cut
    previews labelled as cut), and the owner's next message decides. "sim"
    continues the same harness turn; "não" denies it; any other message denies
    it and is sent as the next prompt; a message with both a yes and a no is a
    no. Untrusted input never answers a request. A request left for
    `permission_timeout` (10 min) is denied — a late "sim" reads "expired",
    never a new prompt. The capability approval intercept yields while a
    harness turn is parked, so the reply goes to the question just asked.
  - Finished turns are recorded with a line naming the files the harness
    edited (`+added −removed`) and how many tools it called.
  - `AgentLoop::with_runtime_mcp_bridge(RuntimeMcpBridge)` supplies MCP
    endpoints per owner; mode 2 and mode 3 sessions receive them in
    `SessionSpec::mcp_bridge`.
- **`bastion-agent-runtime` 0.3.0 — MCP bridge and patient approvals.**
  `McpBridgeSpec { servers: Vec<McpServerEndpoint> }` with `Http { name, url,
  headers }` and `Stdio { name, command, args, env }` (`Debug` prints header
  and variable names, never their values). `AcpAgentRuntime` passes them to the
  agent as ACP `mcpServers` on `session/new`; `AcpxAgentRuntime` and
  `CodexAppServerRuntime` emit a `Warning` saying the bridge was not applied.
  The ACP per-task watchdog no longer counts time spent waiting on a
  permission decision.
- **`acp_claude` sessions are Bastion's, not the operator's Claude Code.**
  Measured live: `claude-agent-acp` loads the operator's whole Claude Code
  setup into the session — settings with their permission `allow` rules and
  `defaultMode`, hooks, plugins, skills, every MCP server on the account — and
  Claude Code's auto memory writes under `~/.claude` without asking. Any of
  that answers or skips a permission request before Bastion sees it. The
  Claude bridge now gets `_meta.claudeCode.options = { settingSources: [],
  strictMcpConfig: true, allowedTools: ["mcp__<bridged server>"] }`,
  `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`, and `session/set_mode` to `default`
  when the bridge starts in another mode (a session that cannot be switched
  fails to open). Only the MCP servers Bastion bridged are pre-allowed: their
  calls are decided by Bastion's own policy server-side. The login is not a
  setting and keeps working. Other bridges are untouched. `tests/acp_fake_bridge.rs` drives the adapter against a
  scripted ACP agent (`tests/fixtures/fake_acp_agent.py`): `mcpServers` on the
  wire, allow/reject option selection, a decision three times longer than the
  task budget still completing, and the Claude isolation options, variable
  and mode switch (absent for other bridges).

### Changed

- **Breaking:** `McpBridgeSpec::servers` is `Vec<McpServerEndpoint>` (was
  `Vec<String>` of names nothing consumed).
- Runtime-backed conversation turns no longer answer permission requests with
  an immediate `Deny { scope: Turn }`; see above. `docs/SUPPORT-MATRIX.md`
  documents mode 2 and the `acp_*` adapters.

## 0.5.0 — 2026-09-26

Repo tag `v0.5.0`. `bastion-runtime` 0.2.6 → 0.3.0 (new public field) sets
the minor; also `bastion-sandbox` 0.1.0 (new crate), `bastion-agent-runtime`
0.2.0 → 0.2.1 and `bastion-mcp` 0.2.0 → 0.2.1 (additive).

### Added

- **`bastion-sandbox` 0.1.0 — OS-level confinement for host programs.** A
  `SandboxSpec` (program, exact environment, cwd, read-only paths, writable
  paths, network blocked or allowed) runs confined; every path not granted is
  out of reach, the operator's home included. `Sandbox::detect(helper)` picks
  the backend by running a confined program:
  - **bubblewrap** (Linux) — empty tmpfs root with only system dirs and the
    grants bound in, all namespaces unshared (network too unless allowed);
  - **Landlock + seccomp** (Linux, when bubblewrap cannot create namespaces —
    Ubuntu 24.04+ restricts them via AppArmor) — the kernel enforces the same
    grants without privileges; a blocked network refuses `AF_INET`,
    `AF_INET6`, `AF_PACKET` sockets and `io_uring`;
  - **Seatbelt** (macOS, `sandbox-exec`) — `(deny default)` profile, paths
    passed as `-D` parameters, never spliced into the profile text.
  Every confined program starts through a helper — the host's own executable
  called with `__bastion-sandbox`, forwarded to `helper_main` (or the bundled
  `bastion-sandbox-exec`) — which keeps only the variables the spec names and
  execs the target under the backend. `Sandbox::command` gives a
  `std::process::Command`; `Sandbox::launch` gives program/args/env for SDKs
  that spawn on their own (the ACP SDK). Variable values never go through
  argv. A program runs by the path it was given (a virtualenv's symlinked
  `bin/python` keeps finding its venv), with its own and its symlink target's
  directories readable. No `unsafe`. `tests/confinement.rs` runs real programs under the host
  backend (writable/read-only/hidden paths, home directory, exact
  environment, host loopback with the network blocked vs allowed);
  `BASTION_SANDBOX_TESTS_REQUIRED=1` turns "no backend" into a failure.
- **`bastion-agent-runtime` 0.2.1 — confined harnesses.** `with_confinement(
  HarnessConfinement)` on `AcpxAgentRuntime`, `CodexAppServerRuntime` and
  `AcpAgentRuntime` starts every session process under `bastion-sandbox`: the
  session workspace (read-only when the policy says so), the harness's
  install prefix, the state directories the host granted (`~/.claude`,
  `~/.codex`, an npm cache — missing ones skipped), only the session's
  `env.allow` (the ACP bridge no longer inherits the daemon's environment
  when confined), a private `TMPDIR` under the workspace, and the network per
  `SandboxProfile` (`Isolated` blocks it, `WorkspaceNet` keeps it, `Trusted`
  skips confinement). Version probes stay unconfined. Descriptors report
  `SandboxCoverage::Partial` when confined (filesystem enforced, network not
  filtered by destination). A resumed Codex session, whose spec carries no
  workspace, is confined to `owner_workspace(base, owner)` — now the single
  mapping the agent loop also uses. `HarnessConfinement::command`/`launch`
  are public for harnesses a host starts itself. Opt-in: without it nothing
  changes.

### Changed

- **stdio MCP servers no longer inherit the daemon's environment.** A
  `transport = "stdio"` server now starts from an empty environment plus
  `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, and what its server table names:
  `env` (literal values), `env_passthrough` (names copied from the daemon when
  set), and an optional `cwd`. Before, it inherited the whole environment, so
  it could read every secret the daemon was started with. No deployment is
  affected today: `McpServerEntry` (what `bastion.toml` feeds
  `McpClient::connect_from_config`) only carries a `url`, so the stdio path is
  unreachable from product config; this hardens it before it is exposed.
  `bastion-mcp` advances to `0.2.1`.
- **MCP servers on Unix sockets.** `url = "unix:/abs/path.sock"` in
  `[mcp.servers.<name>]` speaks the same streamable-HTTP protocol over that
  socket (`http://localhost/mcp` inside it), through rmcp's reqwest client with
  `unix_socket`. No TCP port: only a process that can open the socket file
  reaches the server — how a native install runs its sidecars with no network
  at all. Relative socket paths are rejected. `tests/unix_socket.rs` connects
  to a real rmcp streamable-HTTP server behind axum on a socket.

### Added

- `AgentLoop::with_runtime_workspace_base(base)`: runtime-backed sessions and
  tasks are confined under `base/<owner>` instead of
  `$TMPDIR/bastion-agent-runtime-workspaces/<owner>`, so a host with a real
  workspace (a desktop install) can point external harnesses at it. New public
  field `AgentLoop::runtime_workspace_base` (`None` keeps the old root);
  `bastion-runtime` advances to `0.3.0`.

## 0.4.1 — 2026-09-26

Repo tag `v0.4.1`: only `bastion-providers` advanced, by a patch.

### Added

- **`bastion-providers::codex` — browser login (authorization code + PKCE over a
  loopback callback)**, the desktop alternative to the device flow.
  `start_browser_authorization(config, port)` builds the authorize request with
  the literals of `codex-rs/login/src/{server.rs,oauth/authorization.rs}`
  (`/oauth/authorize`, scope `openid profile email offline_access
  api.connectors.read api.connectors.invoke`, `originator=codex_cli_rs`, S256
  challenge over a 64-byte verifier, 32-byte state, redirect
  `http://127.0.0.1:{port}/auth/callback`). `BROWSER_CALLBACK_PORT` (1455) and
  `BROWSER_CALLBACK_FALLBACK_PORT` (1457) are the only ports the authorize
  endpoint accepts. `BrowserAuthorization::state_matches` compares exactly, and
  its `Debug` redacts the verifier, the state and the URL that carries them.
  `exchange_browser_authorization_code` exchanges against the same
  `/oauth/token` with the loopback `redirect_uri`. Core binds nothing: the host
  runs the callback listener.

### Fixed

- **`bastion-providers::codex` renames reserved tool names on the wire.** Both
  `chatgpt.com/backend-api/codex` and `api.openai.com` reject a user-defined
  function called `tool_search` (`HTTP 400: Function 'tool_search.tool_search'
  not allowed in reserved namespace 'tool_search'`), which fails every turn of a
  registry that has one, not just the calls to it. It now goes out as
  `bastion_tool_search` in the tool list and a forced `tool_choice`, and tool
  calls come back under the original name; a tool genuinely named
  `bastion_<x>` for a non-reserved `<x>` is left alone.
- `bastion-providers` advances to `0.2.6` (additive public API).

## 0.4.0 — 2026-09-25

Repo tag `v0.4.0`: `bastion-types` and `bastion-agent-runtime` advanced their minor.

### Added

- **`bastion-agent-runtime::acp::AcpAgentRuntime` — a direct ACP adapter whose
  permission requests Bastion actually answers.** `AcpxAgentRuntime` supervises a
  third-party ACP client, so `session/request_permission` is resolved inside it
  before Bastion sees it (`approvals = HarnessOwned`). The new adapter speaks ACP
  JSON-RPC over stdio to the bridge directly, on Zed's official
  `agent-client-protocol` SDK (pinned exactly). Everything its `descriptor()`
  declares was measured live with `examples/acp_fs_probe.rs`:
  - filesystem delegation is advertised and ignored by every bridge tested
    (`claude-agent-acp@0.70.0`, `codex-acp@0.0.44`, `opencode acp`); the `fs/*`
    handlers stay, root-confined;
  - `approvals` is per bridge: Claude asks before editing, Codex and OpenCode
    resolve internally and never ask;
  - permission options arrive deny-first, so decisions map by
    `PermissionOptionKind` and a missing kind is an error, never a guess.
  Against `claude-agent-acp@0.70.0`, 11 conformance checks pass (including
  `permission_bridge_allow`/`permission_bridge_deny`) and 3 skip for lack of
  fault injection. Declared as is: `sandbox = None`, `egress = HarnessOwned`,
  `resume`/`steer` false.
- **`RuntimeEvent::PermissionRequest` carries the proposed diff.** New
  `ProposedEdit { path, old_text, new_text, truncated }` in the `edits` field
  (`#[serde(default)]`, so older payloads still deserialize). Requests without a
  diff block report an empty list, never an invented preview; edits outside the
  session root keep their absolute path; previews are cut at 64KB per side on a
  char boundary and marked `truncated`. `acpx` and `codex` report an empty list.
  Adding a field to a variant breaks exhaustive matches, so
  `bastion-agent-runtime` advances to `0.2.0`.
- **Real STABLE/VOLATILE system-prompt caching for Anthropic (D-12/D-14b), plus the
  missing regression test.** Root cause found while wiring a downstream host's
  per-turn context block (an opaque `TurnContextProvider` — SEAM #2's own
  documented use case) into a real turn without breaking cache correctness:
  `AgentLoop::build_system_prompt`'s own doc comments have described a
  STABLE-prefix contract for years (`tests/prompt_cache_prefix.rs` referenced
  repeatedly as the regression guard), but that test file never existed, and
  `AnthropicProvider::build_request_body` always sent the ENTIRE joined system
  prompt as a single `cache_control`-tagged block — a turn-varying context block
  (an `<active_object>` snapshot, a memory-RAG recall block, anything from a
  non-turn-invariant `TurnContextProvider`) anywhere in that string invalidated
  the whole cache on every single turn, silently, with no test catching it.
  - `TurnContextProvider` (`bastion-runtime::agent::context`) gains
    `is_turn_invariant() -> bool` (default `false` — a provider must opt IN to
    being treated as cacheable, never opt out by omission, since misclassifying
    a volatile provider would let a cache hit silently serve a PREVIOUS turn's
    content). `IdentityProvider` (`bastion-cognition`) is the one real provider
    that earns `true` — its own doc already documented ignoring `turn_msg`.
  - `AgentLoop::build_context_parts_for_destination` now computes the boundary
    from the ACTUAL blocks returned THIS turn (a nominally-stable provider can
    legitimately return zero blocks some turns, e.g. `IdentityProvider` before
    onboarding) — never a static per-provider count. New pub
    `AgentLoop::build_system_prompt_with_cache_boundary` exposes it as a byte
    offset without changing either existing `build_system_prompt`/
    `build_system_prompt_parts` signature. `TurnKernel` gains the same method
    (default: whole string volatile, boundary 0 — the safe fallback for any
    future implementer that hasn't opted in; `AgentLoop` overrides it for real).
  - `CallConfig` (`bastion-types`) gains `cache_stable_prefix_end: Option<usize>`
    — `None` (every existing caller, via `Default`) means "treat the whole
    string as volatile," byte-identical to today's behavior.
  - `AnthropicProvider::build_request_body` splits `system` into two content
    blocks when a usable boundary is present: the stable prefix keeps
    `cache_control`, the volatile remainder doesn't. The boundary is
    defensively re-validated (`is_char_boundary`, `<= len`) rather than trusted
    across the kernel→provider crate boundary — an unusable value fails SAFE to
    the original single-block shape, never panics on a slice index.
  - Wired into every real `CallConfig` construction site that builds
    `system_prompt` from `context_providers`: `AgentLoop::run_provider_fallback`
    and `bastion-personas`'s `PersonaResponder::dispatch_single_or_parallel`.
    Found and fixed along the way: `persona::runner::run_single`/`run_parallel`
    rebuild `CallConfig` with `..Default::default()`, which was silently
    dropping the boundary even after the caller set it — and when a persona
    overrides the prompt with its OWN static `system_prompt` (registry-defined,
    never varies by turn), that whole string is itself stable, not just
    whatever boundary applied to the dynamic prompt it replaced. The 3
    genuinely-static prompts elsewhere (`persona::router`'s classifier call,
    `cabinet::synth`'s synthesis call, `learn`'s reflector call) explicitly set
    `None` — they never touch `context_providers`, so no split applies.
  - New `tests/prompt_cache_prefix.rs` (`bastion-runtime`, did not exist before):
    proves the stable prefix is byte-identical across turns with different
    volatile content, proves a volatile provider caps the boundary at its
    position even when a stable provider comes after it (order-dependent, not
    just count-dependent), and the zero-`context_providers` case. Plus 14 new
    unit tests across `anthropic.rs` (split/fallback/char-boundary safety) and
    `runner.rs`/`responder.rs` covering the persona-override boundary logic.
  - Version impact: the new trait methods have defaults and the new pub fn is
    additive, but `CallConfig` gained a public field and has no
    `#[non_exhaustive]`, so a downstream struct literal without
    `..Default::default()` stops compiling. Per `docs/VERSIONING.md` §3 that is
    breaking, the same reasoning that moved `bastion-agent-runtime` to `0.2.0`
    below: `bastion-types` advances to `0.3.0`. `bastion-runtime` advances to
    `0.2.6`, `bastion-cognition` to `0.2.1`, `bastion-personas` to `0.2.2`,
    `bastion-providers` to `0.2.5`.
## 0.3.3 — 2026-08-03

### Fixed

- Blocked user turns no longer remain in session history and leak into later
  provider requests. `AgentLoop` now removes the failed append, stores denied
  payloads as separately retrievable audit evidence, and records an assistant
  refusal instead. `SessionManager` gains `remove_last`,
  `record_blocked_turn`, and `load_blocked_turn`; `bastion-runtime` advances
  to `0.2.5` for the additive public API.
- `bastion-providers::codex` now matches the ChatGPT Codex inference wire
  contract: requests use SSE (`stream: true`), omit the rejected
  `max_output_tokens` field, and collapse streamed text, tool-call items, and
  final usage into the kernel's non-streaming `LlmResponse`.
  `bastion-providers` advances to `0.2.4`.

- **`bastion-providers::codex`'s device-code flow used the wrong endpoints —
  a real `403` on a live E2E run.** Three values, re-derived directly from
  `codex-rs/login/src/device_code_auth.rs`'s literal source and cross-checked
  against a real, unrelated bug report naming the same corrected path
  (`github.com/openai/codex` issue #16079):
  - The device usercode/token endpoints live under `{issuer}/api/accounts/deviceauth/...`,
    not `{issuer}/deviceauth/...` — the missing `/api/accounts` segment is
    what produced the `403`. New `DEVICE_API_PREFIX` const.
  - `DeviceAuthorization::verification_uri` defaults to
    `https://auth.openai.com/codex/device` (issuer-based), not
    `https://chatgpt.com/codex/device` as before.
  - `CodexConfig::redirect_uri` defaults to
    `https://auth.openai.com/deviceauth/callback` (the device flow's own
    callback, now confirmed), not the browser-PKCE flow's
    `http://localhost:1455/auth/callback` it was incorrectly reusing.
  - All three were previously flagged in the module's own "Sourcing and
    confidence" doc as unconfirmed guesses — now confirmed against official
    source, not guessed. 2 new tests lock the corrected values down.

### Added

- `bastion-agent-runtime` advances to `0.1.1` with the optional, wire-compatible
  `model_hint` on `SessionSpec` and `TaskInput`, allowing delegated coding
  runtimes to receive the model selected by host routing while preserving the
  previous behavior when absent.
- `bastion-personas` advances to `0.2.1` with
  `PersonaResponder::with_cabinet_provider`, separating Cabinet deliberation
  from the conversational provider while keeping the turn provider as the
  default. Egress checks and synthesis resolve through the same effective
  provider.
- `docs/MESH.md` documents mesh identity, P2P transport, `.af` interoperability,
  export controls, and the mesh-sync scheduler.

- `bastion-providers::copilot` (BPCOP-01..05) — the GitHub Copilot
  subscription connector, second implementor of `ProviderCredentialRefresher`
  after `codex` (BPCDX, `0.3.2` above), but structurally different from every
  other connector in this crate:
  - GitHub Copilot has **no direct HTTP inference API for third parties** —
    the official `github/copilot-sdk` communicates with the `copilot` CLI
    server over JSON-RPC only, and the old Copilot Extensions HTTP surface
    was fully sunset 2025-11-10. `CopilotProvider` wraps the official Rust
    `github-copilot-sdk` crate (v1.0.8, GA), which spawns/manages the CLI as
    a subprocess over stdio, instead of opening an HTTP connection like
    every other `Provider` impl here.
  - `Transport::Stdio` (not `Tcp` — an unauthenticated loopback port in a
    multi-owner daemon; not `InProcess` — FFI, experimental, one crash takes
    the whole daemon down), `ClientMode::Empty` +
    `SessionConfig::with_available_tools([])` +
    `SessionConfig::deny_all_permissions()` (the closest documented
    approximation of "just answer, never act" this SDK offers — not a
    wire-level guarantee, so the resulting turn is trusted no more than any
    other provider's).
  - One `Client` + one `Session` per `CopilotProvider` instance — verified
    against the real crate source (not docs.rs summaries, which proved
    internally inconsistent this round) that `ClientOptions.github_token`
    and `.mode` are client-level, not per-session, so a shared pool would
    gain nothing here; matches how `SubscriptionModelProvider::build` is
    already called once per `/model` switch.
  - Auth: classic GitHub OAuth App, authorization-code + PKCE
    (`ProviderAuthFlow::AuthorizationCodePkce`) — `gho_` tokens don't expire
    and carry no `refresh_token`, so `CopilotRefresher::refresh` is a
    load-and-return, never an HTTP call (unlike Codex). `revoke` calls
    GitHub's real `DELETE /applications/{client_id}/grant` (unlike Codex's
    documented no-op — GitHub does publish a revocation endpoint).
  - Two things could not be sourced to the same standard and are documented
    at their point of use instead of guessed: whether a `gho_` token needs
    an explicit OAuth `scope` to carry Copilot entitlement (undocumented;
    defaults to none), and whether GitHub's classic OAuth App token endpoint
    actually validates the PKCE `code_verifier` it never documents accepting
    (sent anyway, on the assumption an unrecognized parameter is ignored,
    not rejected).
  - Returned via `support_descriptor()` at `SupportStatus::Experimental`
    (BPCOP-05) — promotion to `Supported` additionally needs a live test
    against a real account confirming the tool-suppression config actually
    prevents the Copilot agent from acting on its own, since that is not
    guaranteed by the SDK's documentation.
  - Not yet wired into `registry::resolve_provider` or bastion-agent's
    connector layer — same follow-up boundary as `codex`'s own entry above.
  - Additive, per `docs/VERSIONING.md` §1: a new module only.
    `bastion-providers` advances to `0.2.3`.

## 0.3.2 — 2026-07-29

### Added

- `bastion-providers::codex` (BPCDX-01..05) — the Codex/ChatGPT subscription
  connector, the first implementor of `ProviderCredentialRefresher`
  (`bastion-runtime`, PR #7) and the first consumer of `provider_catalog`
  (`bastion-types`, PR #8) outside their own test suites:
  - `CodexRefresher` exchanges/refreshes tokens against the device-code and
    `refresh_token` grants OpenAI's own official `openai/codex` CLI uses
    (`codex-rs/login/src/{server.rs,device_code_auth.rs}`), cross-checked
    against three independent third-party implementations. `revoke` is a
    documented no-op — no vendor revocation endpoint was found anywhere in
    that sourcing, and the trait's own contract makes that the correct
    behavior (local state still moves to `Revoked`).
  - `CodexProvider` speaks the Responses API against
    `chatgpt.com/backend-api/codex/responses`, confirmed via
    `simonw/llm-openai-via-codex`'s actual working source rather than the
    Notion card's unverified claim alone.
  - Returned via `support_descriptor()` at `SupportStatus::Experimental`
    (BPCDX-05) — promotion to `Supported` needs a conformance run, a live
    E2E run, a secret-scrub pass and a terms/licence review, none of which
    have happened yet.
  - Two details could not be sourced to the same standard as everything
    else and are documented at their point of use instead of guessed: the
    device flow's final-exchange `redirect_uri` (confirmed only for the
    browser PKCE flow) and the device-login `verification_uri`'s literal
    origin (template confirmed, origin not). Both are `CodexConfig` fields,
    overridable without a code change.
  - Not yet wired into `registry::resolve_provider` — that resolver
    constructs providers from an env var with no credential injection point,
    which is the wrong shape for a subscription connector. Wiring belongs to
    the login/connect service (bastion-agent, same epic, next milestone).
  - Additive, per `docs/VERSIONING.md` §1: a new module only, nothing
    existing changed shape. `bastion-providers` advances to `0.2.2` (on top
    of `0.2.1`'s `with_api_key` addition below).

- Streaming and cancellation on the kernel `Provider` trait
  (`bastion-runtime::provider`), closing the last two capabilities
  `provider_conformance` reported as permanently `Unverifiable`:
  - `Provider::stream` — an incremental completion (`StreamChunk`: text
    delta, tool-call-argument delta, final usage), returned as a boxed
    `Stream` to keep `Provider` dyn-compatible (`&dyn Provider` is how
    `provider_conformance`/callers already use it).
  - `Provider::complete_cancellable` — a cancellable variant of `complete`,
    taking a `tokio_util::sync::CancellationToken` so a caller can abort an
    in-flight call and have the provider tear down the actual upstream
    connection, not just stop waiting locally.
  - Both are NEW trait methods with default implementations — every
    existing `impl Provider` (6 real connectors in `bastion-providers`, 18
    test mocks across `bastion-runtime`/`bastion-cognition`/
    `bastion-personas`/examples) keeps compiling unchanged. The defaults are
    honest typed errors (`ProviderNotStreamable`, `ProviderCancelled`),
    never a fake single-chunk stream or a no-op "cancel" — a provider that
    has not overridden them has not earned
    `ModelCapability::Streaming`/`Cancellation`.
  - `provider_conformance::run_conformance` now exercises both for real:
    `check_streaming` requires 2+ observed chunks (one chunk is
    indistinguishable from `complete()` wrapped in a stream of one);
    `check_cancellation` races cancellation against an in-flight call
    (`tokio::join!`, concurrent — not a sequential await-then-cancel) so a
    provider that only checks the token up front, like the trait's own
    default, cannot pass by accident.
  - Additive, not breaking, per `docs/VERSIONING.md` §1/§3: both new trait
    methods carry defaults, so no existing `impl Provider` changes — the
    baseline diff (`docs/api-baseline/bastion-runtime.txt`: adds
    `StreamChunk`, `ProviderCancelled`, `ProviderNotStreamable`) is three new
    items appearing, nothing removed/renamed/resignatured. `bastion-runtime`
    advances to `0.2.4` (additive).
  - `bastion-runtime` gains a new dependency, `tokio-util` (for
    `CancellationToken`).

- Provider constructors now accept an already-resolved credential instead of
  only reading `std::env` (`bastion-providers::registry::
  resolve_provider_with_credential`), closing a debt `bastion-agent#16`
  disclosed: the agent's `model_config` approve flow had to publish a
  `BASTION_SECRETS_DIR`-only secret into the process environment via
  `std::env::set_var` because there was no injection point.
  - Every keyed provider (Anthropic/OpenAI/Gemini/Groq/OpenRouter) gains a
    `with_api_key(model, api_key)` constructor alongside its existing `new
    (model)`; `new` is now just `with_api_key` plus its own env lookup, so
    the two paths cannot drift. Ollama takes no credential (nothing to
    inject) and is unaffected.
  - `resolve_provider(model)` is unchanged — it's now a one-line wrapper
    around `resolve_provider_with_credential(model, None)`, so every
    existing caller keeps its exact old behavior (including the env-var
    panics on a missing key) without touching this function.
  - Additive per `docs/VERSIONING.md` §1/§3: no existing signature changed,
    only new items added (6 new `pub fn`s across `bastion-providers`).
    `bastion-providers` advances to `0.2.1`.
  - Agent-side follow-up (removing the `std::env::set_var` bridge in
    `bastion-agent`'s `proposals.rs::resolve_provider_secret`) is deliberately
    NOT part of this change — it needs `bastion-agent` repinned to a
    `bastion-providers` release that includes this constructor first.

## 0.3.1 — 2026-07-28

### Added

- Provider catalog, usage and support descriptors
  (`bastion-types::provider_catalog`) plus the shared conformance suite
  (`bastion-runtime::provider_conformance`) — the gate every subscription
  connector passes before it can be called supported:
  - Capabilities are declared PER MODEL and individually (`ModelCapability`:
    streaming, tools, structured output, cancellation, usage). Text completion
    working says nothing about tool calls, which is how a connector ships
    looking finished and fails later at the first tool call or 429. An empty
    capability set means text-only, never "everything".
  - `ProviderUsageSnapshot` makes every quantity optional, and absent means
    *unknown* — never zero, never unlimited. There is deliberately no helper
    computing `remaining` from `limit - used`: vendors count differently
    (requests vs tokens, window vs billing period), so that subtraction
    publishes a number nobody reported. Serialization omits unknown fields
    entirely rather than emitting nulls a client might coerce to 0, and
    `UsageSource` records whether a number came from the vendor or from local
    accounting, which is blind to other clients' usage.
  - `ProviderCatalog::select_model` returns a typed `CatalogError` for an
    unknown model, an expired descriptor, or a missing capability, and never
    substitutes another model — silently downgrading the model a caller chose
    is how a weaker model ends up serving a request nobody redirected. Checks
    run disabled-provider → unknown-model → expiry → capability so the error is
    the actionable one.
  - `SupportStatus::Supported` is unreachable by assignment: the field is
    private and `ProviderSupportDescriptor::promote` requires all five pieces of
    `SupportEvidence` (conformance, live E2E, secret scrub, owner isolation,
    terms review) plus a tested version and date, reporting each missing one. A
    custom `TryFrom` deserializer re-checks the same rule, so a hand-edited
    file claiming supported without evidence fails to LOAD rather than being
    trusted — the gate holds across persistence, not only in Rust.
  - `run_conformance` drives a `&dyn Provider`, so it runs against a fake in CI
    and a real connector in an opt-in live run. Baseline checks include a
    prompt canary (a provider that ignores its input cannot pass on "it
    returned some text"), catalog/provider model-name agreement, and a positive
    context limit; declared capabilities are then each exercised, including
    all-zero usage as the tell for a connector filling the struct instead of
    reading the vendor.
  - `CheckOutcome::Unverifiable` is deliberately not a pass. The kernel
    `Provider` trait has no streaming method and no cancellation token, so a
    connector declaring either is making a claim this suite cannot observe;
    `promotion_ready` is false while any check is unverifiable, rather than
    certifying it quietly.
  - `bastion-types` advances to `0.2.2`, `bastion-runtime` to `0.2.3` (both
    additive).
- Subscription credential lifecycle
  (`bastion-runtime::provider_auth::ProviderCredentialLifecycle`), the state
  machine every subscription connector shares instead of re-inventing:
  - **Single-flight refresh per `ProviderAuthRef`.** N concurrent refreshes of
    the same reference produce exactly one upstream call and every caller gets
    that result. Not an optimization — OAuth refresh tokens are commonly
    single-use, so a second concurrent exchange invalidates the token the first
    just rotated and leaves the credential unusable. Different references never
    block each other.
  - **Typed failure transitions.** A transient failure (`Expired`,
    `Throttled`) enters `Cooldown` with a deadline from an injected
    `BackoffPolicy` and a persisted consecutive-failure counter, so the wait
    grows and survives a restart; a success resets it. Anything else is
    terminal: `ReauthRequired`, or `Revoked` for an upstream revocation —
    which is deliberately not `ReauthRequired`, because re-authenticating the
    same reference is not the remedy. While in cooldown, no upstream call is
    spent at all.
  - **Host-owned persistence through `CredentialStateStore`**, whose
    `compare_and_swap` is what makes an interrupted update safe: a losing
    racer returns `false` rather than erroring, a storage failure leaves the
    last valid record untouched, and a transition computed from stale state is
    refused instead of applied — which is what stops a stale conclusion from
    resurrecting a revoked credential.
  - **`ProviderCredentialRefresher`** is the connector-facing port: two
    straight-line calls (exchange, revoke), inheriting single-flight, backoff,
    transitions and persistence. Those behaviors are tested once here against
    a fake instead of once per vendor against a live account.
  - `revoke` marks local state `Revoked` even when the vendor call fails or
    offers no revocation endpoint — an operator's revocation must not depend on
    vendor support — and touches only the requested reference (proven with two
    owners × two profiles). `forget` deletes the record and is deliberately
    separate: it never claims an upstream revocation.
  - `Clock` and `BackoffPolicy` are injected so every deadline is asserted
    without sleeping. Nothing in the module can enumerate other credentials, so
    a failure can never fall back to another profile, owner or provider.
  - `bastion-runtime` advances to `0.2.2` (additive).
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


## 0.3.0 — 2026-07-27

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
