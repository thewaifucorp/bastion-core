# bastion-core

The **OSS Rust substrate** for building persistent, governable, cognitive AI agents — the stable execution/cognition layer that powers [bastion-agent](https://github.com/thewaifucorp/bastion-agent) and can be embedded by any host.

`bastion-core` is a Cargo workspace of focused crates. It is **mechanism, not orchestrator**: it hosts the agent tool-loop, mediates every tool call through one capability boundary, and injects context/policy through typed seams — it is a host, never a DAG/workflow engine.

## Crates

| Crate | Role |
|---|---|
| `bastion-types` | leaf types, IDs, errors, versioned-context artifacts |
| `bastion-runtime` | agent loop, capabilities, context, sessions, hooks, the `Provider`/`Memory` traits, and every kernel port |
| `bastion-agent-runtime` | `AgentRuntime` contract + adapters (Codex app-server, ACP/`acpx`) — external harnesses that own their own tool loop |
| `bastion-memory` | beliefs, provenance, temporality, contestable-memory store |
| `bastion-cognition` | Dream/consolidation, procedural learning, goals, proactivity, Cabinet deliberation |
| `bastion-personas` | `AgentDefinition`/personas, routing, deliberation |
| `bastion-mesh` | mesh transport, agent identity, `.af` interop, scheduler |
| `bastion-mcp` | MCP client/server |
| `bastion-providers` | concrete model providers + auth resolution |
| `bastion-extension-protocol` | extension manifests, permissions, trust tiers, lockfiles |
| `bastion-extension-wasm` | `wasmi`-backed WASM/WASI extension sandbox |

## Guarantees

- **One tool surface** — everything goes through `CapabilityRegistry::invoke`, the single policy boundary. Agents never get raw SQL.
- **Egress fail-closed** — `check_egress(tier, dest)` gates what leaves to non-local providers; `local-only` context never reaches a cloud provider.
- **Trust follows content** — external/tool content is untrusted; it never gains authority by entering the context.
- **Owner/session isolation**, typed non-bypassable approval, opaque external context.

The one-way crate-dependency boundary (kernel ← extensions ← consumers, never the reverse) is enforced in CI (`scripts/check-crate-deps.sh`). Security invariants: `docs/SECURITY-INVARIANTS.md`. Public-API stability policy: `docs/VERSIONING.md`.

## Embedding

`examples/minimal-agent` and `examples/embedded-host` show a full turn built from substrate crates alone (never the product). `examples/embedded-host-slice` is the reference external consumer that proves the boundary holds for a second host.

## Consumers

- [bastion-agent](https://github.com/thewaifucorp/bastion-agent) — the personal-agent product and flagship consumer.

## License

See [LICENSE](LICENSE). Source-available.
