# Legacy terminal-agent provider

The `bastion-providers` terminal-agent implementation is deprecated. It is retained temporarily behind the `legacy-terminal-agent` Cargo feature, which is off by default.

```bash
cargo build -p bastion-providers --features legacy-terminal-agent
```

## Why it was replaced

The legacy provider launches a headless terminal agent as if it were a model provider. That hides the external harness's tool loop from the native runtime, so Core cannot accurately bridge approvals, describe policy coverage, resume sessions, or emit structured task events.

`bastion-agent-runtime` replaces that path with an explicit `AgentRuntime` contract and concrete adapters:

- `CodexAppServerRuntime` for Codex app-server.
- `AcpxAgentRuntime` for ACP-compatible agents driven through `acpx`.

See [SUPPORT-MATRIX.md](SUPPORT-MATRIX.md) for the coverage each adapter actually declares.

## Migration

1. Stop selecting `claude_code` or `opencode` through the native provider registry.
2. Construct the appropriate `AgentRuntime` in the embedding host.
3. Supply a `SessionSpec` with workspace, permission, timeout, environment, authentication, and sandbox policy.
4. Consume structured `RuntimeEvent` values and surface `PolicyCoverage` to operators.
5. Keep secrets and host CLI login state in the embedding product; Core does not define their configuration format.

Do not copy the old product-level daemon, Docker, channel, or `BASTION__...` instructions into this repository. Those settings belong to the application that embeds Core.
