<!-- generated-by: gsd-doc-writer -->
# Architecture

`bastion-core` is a layered Rust workspace for embedding governed agent behavior into a host application. The host owns entry points, configuration, identity mapping, business state, and deployment; Core owns reusable contracts and mechanisms for turns, capabilities, policy hooks, memory, cognition, integrations, and extensions.

## System overview

```text
embedding host (CLI, service, channel, application)
                         |
                         v
        bastion-personas / bastion-cognition
                         |
                         v
              bastion-runtime agent loop
          /          |          |          \
   providers      memory    capabilities    agent runtimes
      /              |          |                 \
 bastion-       bastion-     bastion-mcp      Codex / ACP
 providers       memory
          \          |          /
              bastion-types

Optional edges: mesh, extension protocol, and WASM sandbox.
```

The dependency allowlist in `scripts/check-crate-deps.sh` is authoritative. It prevents cycles and prevents substrate crates from depending on the product application.

## Layers and crates

### Contracts

`bastion-types` is the shared vocabulary: messages, provider call configuration, privacy tiers, beliefs, approval outcomes, failure kinds, deployment context, and secret references. It is intentionally a leaf dependency.

### Kernel

`bastion-runtime` owns `AgentLoop`, sessions, capabilities, guardrails, egress checks, structured output, observability hooks, and the ports a host implements. `bastion-memory` supplies the governed belief model and its SQLite implementation.

### Intelligence

`bastion-cognition` builds goals, proactive behavior, evaluation, learning, memory retrieval, and Cabinet deliberation on the kernel. `bastion-personas` adds persona definitions, routing, and response composition.

### Integrations and extensions

- `bastion-providers` implements native model providers.
- `bastion-mcp` supplies MCP clients, registry adapters, OAuth support, and a `ToolSource` implementation.
- `bastion-agent-runtime` defines the external-agent contract and Codex/ACP adapters.
- `bastion-mesh` supplies identity, peer transport, `.af` interop, context, and scheduling.
- `bastion-extension-protocol` defines manifests, permissions, trust tiers, signatures, and lockfiles.
- `bastion-extension-wasm` provides the isolated WASM execution mechanism and does not know product manifests or capabilities.

## A turn through the kernel

1. A host constructs an `AgentLoop` with a provider, session manager, responder, memory store, approval gate, and the optional ports it needs.
2. The host calls `AgentLoop::run_turn_for` with input and a canonical owner identifier.
3. The runtime loads owner-scoped session state and injected context, applies trust and privacy handling, and runs input guardrails.
4. The configured responder produces the model-facing response. Native tool calls enter the runtime tool-dispatch path; registered capabilities use `CapabilityRegistry::invoke` for egress, approval, execution, and trust tagging.
5. The runtime validates output, records session state and usage, emits observer events, and returns text to the host.

An external `AgentRuntime` is a different execution mode: the external harness owns its tool loop. Its descriptor declares which policies Bastion can bridge and which remain harness-owned; see [SUPPORT-MATRIX.md](SUPPORT-MATRIX.md).

## Key abstractions

| Abstraction | Location | Purpose |
| --- | --- | --- |
| `AgentLoop` | `crates/bastion-runtime/src/agent/loop_.rs` | Stateful, owner-aware turn execution |
| `Responder` / `TurnContext` | `crates/bastion-runtime/src/agent/ports.rs` | Host-selected response composition |
| `Provider` | `crates/bastion-runtime/src/provider.rs` | Native model completion boundary |
| `Memory` | `crates/bastion-runtime/src/memory.rs` | Owner-scoped governed memory contract |
| `CapabilityRegistry` | `crates/bastion-runtime/src/capability/registry.rs` | Named capability registration and policy mediation |
| `ApprovalGate` / `PermissionGate` | `crates/bastion-runtime/src/agent/ports.rs` | Typed authorization decisions |
| `TurnContextProvider` | `crates/bastion-runtime/src/agent/context.rs` | Opaque host context injection |
| `AgentRuntime` | `crates/bastion-agent-runtime/src/lib.rs` | External agent-harness contract |
| `SecretResolver` | `crates/bastion-types/src/secret.rs` | Resolution of opaque secret references at a boundary |

## Core and product boundary

Core deliberately does not own a daemon, channel adapters, a user-facing configuration schema, mobile clients, Docker composition, or an application's business records. Those belong to an embedding host. `bastion-agent` is the flagship host and contains the Bastion CLI, channels, HTTP surfaces, configuration, sidecars, and mobile application.

This boundary keeps the libraries reusable and makes policy explicit: a host can define its own responder, context provider, authorization policy, tool source, and observability sink without patching the kernel.

## Repository layout

```text
crates/                  published-library-shaped workspace crates
examples/                offline reference compositions
docs/                    active public contracts and guides
docs/api-baseline/       mechanically generated public-item inventories
docs/archive/            historical product documentation
scripts/                 dependency, API, and public-scope checks
.github/workflows/       CI gates
```
