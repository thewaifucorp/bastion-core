# External agent runtime support

> Code-derived matrix for `bastion-agent-runtime` 0.3.0. Adapter descriptors are the contract; credentialed live tests are reproducible evidence, not a permanent promise about third-party CLIs.

## Adapter capabilities

| Runtime | Transport | Resume | Steer | Usage | Diff events | Permission bridge | Concurrent sessions |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `codex_app_server` | Codex app-server | Yes | Yes | Yes | Yes | Yes | No |
| `acpx_claude` | ACP through `acpx` | No | No | Yes | Yes | No | Yes |
| `acpx_opencode` | ACP through `acpx` | No | No | Yes | Yes | No | Yes |
| `acp_claude` (and other `acp_*`) | ACP, Bastion is the client | No | No | Yes | Yes | Yes | No |

These values come from `RuntimeDescriptor` in `crates/bastion-agent-runtime/src/codex.rs`, `acpx.rs` and `acp.rs`. The `acp_*` id follows the bridge command (`claude-agent-acp` → `acp_claude`, `codex-acp` → `acp_codex`, `opencode acp` → `acp_opencode`).

## Policy coverage

| Runtime | Tool visibility | Approval | Egress | Budget | Sandbox |
| --- | --- | --- | --- | --- | --- |
| `codex_app_server` | Declared tools only | Bridged | Harness-owned | Reported | `Partial` only after a successful live bubblewrap probe; otherwise `None` |
| `acpx_claude` | Declared tools only | Harness-owned | Harness-owned | Reported | None |
| `acpx_opencode` | Declared tools only | Harness-owned | Harness-owned | Reported | None |
| `acp_claude` | Declared tools only | Bridged | Harness-owned | Reported | `Partial` when the host confines it, otherwise None |
| `acp_codex`, `acp_opencode` | Declared tools only | Harness-owned (measured: they never ask) | Harness-owned | Reported | `Partial` when the host confines it, otherwise None |

Any adapter given a `HarnessConfinement` (`with_confinement`) reports `Partial`: the filesystem is enforced by `bastion-sandbox`, the network is on or off per `SandboxProfile` but not filtered by destination. Runtime-backed conversation turns use `WorkspaceNet` (the harness has to reach its model provider).

`HarnessOwned` is a security limitation: the external process owns that policy surface. `Reported` means usage is observed, not that Core can enforce a budget inside the harness. Codex sandbox detection never reports `Honored`; a successful mechanism probe is not proof that a particular task was confined.

## Health and version checks

Both adapters run a version command with a cleared environment and reject an unavailable or unsupported target before starting a session. The supported version requirement is compiled into each adapter and exposed by `RuntimeDescriptor::target_version`; callers should use `health()` rather than duplicating version assumptions in configuration.

## Live conformance suites

Live suites are ignored by default because they spawn authenticated third-party CLIs and can consume quota:

```bash
cargo test -p bastion-agent-runtime --test acpx_live_claude -- --ignored --nocapture
cargo test -p bastion-agent-runtime --test acpx_live_opencode -- --ignored --nocapture
cargo test -p bastion-agent-runtime --test codex_live -- --ignored --nocapture
```

The files themselves record prerequisites, scenarios, and known gaps. Results are environment- and version-specific; rerun them before making a release claim.

## Choosing an execution mode

- Use the native `Provider`/`AgentLoop` path when Core must mediate its own tool loop and egress decisions.
- Use `codex_app_server` when a real Codex approval bridge and resume/steer support are required, while accepting harness-owned egress.
- Use ACP through `acpx` when the wrapped CLI is the desired executor and concurrent sessions matter, while accepting that approval, egress, and sandbox remain outside Core.
- Use `acp_claude` when Claude Code (under the operator's own login) should run the turn and every edit it asks to make must be approved in Bastion, with the diff shown.

## Runtime-backed conversation (mode 2)

`AgentLoop` keeps one live harness session per Bastion session between turns (`agent::runtime_turn`), so an adapter that cannot reattach still keeps its context for the whole conversation; a session idle for `runtime_session_idle` (30 min by default) is closed. When the harness raises a permission request the turn is parked: the request is recorded in the `PermissionGate`, the turn answers with the request and the proposed diff, and the owner's next message decides — an approval continues the same harness turn, a rejection denies it, anything else denies it and becomes the next prompt, and nothing is ever answered from an unauthenticated channel. A request unanswered for `permission_timeout` (10 min) is denied. The ACP adapter does not count that wait against its task timeout. Each finished turn's text is recorded with a line saying which files the harness edited and how many tools it called.

An `acp_claude` session does not load the operator's Claude Code settings, hooks, plugins, skills or account MCP servers (`settingSources: []`, `strictMcpConfig`), runs with auto memory off, and is switched to the `default` (asking) permission mode — otherwise an operator's `allow` rule or `defaultMode` would answer requests before Bastion sees them. Only the MCP servers Bastion bridged are pre-allowed.

`SessionSpec::mcp_bridge` hands a session concrete MCP endpoints (`McpServerEndpoint::Http` or `Stdio`); the host supplies them per owner with `AgentLoop::with_runtime_mcp_bridge`. `acp_*` passes them to the agent as ACP `mcpServers`; `acpx` and `codex_app_server` cannot, and say so with a `Warning` event.

The embedding host owns backend selection and authentication-profile configuration. This library repository does not define a `bastion.toml` schema or `/backend` command.
