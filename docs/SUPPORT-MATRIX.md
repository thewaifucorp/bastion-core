# External agent runtime support

> Code-derived matrix for `bastion-agent-runtime` 0.1.0. Adapter descriptors are the contract; credentialed live tests are reproducible evidence, not a permanent promise about third-party CLIs.

## Adapter capabilities

| Runtime | Transport | Resume | Steer | Usage | Diff events | Permission bridge | Concurrent sessions |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `codex_app_server` | Codex app-server | Yes | Yes | Yes | Yes | Yes | No |
| `acpx_claude` | ACP through `acpx` | No | No | Yes | Yes | No | Yes |
| `acpx_opencode` | ACP through `acpx` | No | No | Yes | Yes | No | Yes |

These values come from `RuntimeDescriptor` in `crates/bastion-agent-runtime/src/codex.rs` and `crates/bastion-agent-runtime/src/acpx.rs`.

## Policy coverage

| Runtime | Tool visibility | Approval | Egress | Budget | Sandbox |
| --- | --- | --- | --- | --- | --- |
| `codex_app_server` | Declared tools only | Bridged | Harness-owned | Reported | `Partial` only after a successful live bubblewrap probe; otherwise `None` |
| `acpx_claude` | Declared tools only | Harness-owned | Harness-owned | Reported | None |
| `acpx_opencode` | Declared tools only | Harness-owned | Harness-owned | Reported | None |

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

The embedding host owns backend selection and authentication-profile configuration. This library repository does not define a `bastion.toml` schema or `/backend` command.
