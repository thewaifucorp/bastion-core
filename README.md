<h1 align="center">bastion-core</h1>

<p align="center">
  <strong>The governed Rust foundation for agents that need to remember, reason, and act without inheriting ambient authority.</strong>
</p>

<p align="center">
  <a href="actions/workflows/ci.yml"><img alt="CI" src="actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f2f2ee?labelColor=0b1020"></a>
  <a href="Cargo.toml"><img alt="Rust 2021" src="https://img.shields.io/badge/Rust-2021-f74c00?labelColor=0b1020"></a>
  <img alt="Unsafe code forbidden" src="https://img.shields.io/badge/unsafe-forbidden-8b5cf6?labelColor=0b1020">
  <img alt="Powers bastion-agent" src="https://img.shields.io/badge/powers-bastion--agent-4f8cff?labelColor=0b1020">
</p>

<p align="center">
  <a href="#why-bastion-core">Why Core</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#start-with-a-real-turn">Quick start</a> ·
  <a href="#workspace-crates">Crates</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## The hard part is not calling a model. It is governing what happens next. 🏰

An agent becomes useful when it can retain context, use tools, call providers, coordinate work, and improve over time. Those same capabilities make it difficult to embed safely: untrusted content can look like instructions, memory can quietly become policy, and a convenient tool call can cross an authority boundary the host never intended to grant.

**Bastion Core makes those boundaries part of the architecture.** It is an open-source Rust workspace for building persistent, owner-aware AI agents around typed ports for execution, policy, memory, cognition, personas, providers, MCP, mesh, and sandboxed extensions.

The host keeps control of identity, configuration, channels, deployment, and business state. Core supplies the reusable mechanisms beneath them.

> **Core is a library substrate, not a daemon, CLI, or workflow engine.** If you want the complete self-hosted product, start with `bastion-agent`.

## Why Bastion Core

Most agent frameworks optimize for reaching a tool as quickly as possible. Bastion Core optimizes for reaching it through boundaries a host can inspect, replace, and enforce.

| An agent needs | Core provides |
| --- | --- |
| Long-lived context | **Governed memory** with provenance, temporal validity, correction, contestation, revocation, and canonical-owner isolation. |
| Tools and side effects | **Typed capabilities** mediated by egress checks, approval gates, execution policy, and trust-tagged results. |
| More than one model | **Provider boundaries** for native model calls plus explicit policy-coverage descriptors for external agent runtimes. |
| Product-specific context | **Opaque, privacy-tiered context ports** that let a host contribute state without turning Core into its system of record. |
| Deliberation and continuity | **Goals, evaluation, learning, proactivity, personas, routing, and Cabinet-style synthesis** built above the kernel. |
| Extensibility | **MCP, mesh, extension manifests, permissions, signatures, lockfiles, and a fuel-bounded WASM sandbox.** |
| Operational visibility | **Neutral observer traits and OpenTelemetry-compatible types** without requiring a particular vendor. |

## What stays true at the boundary

### 🛡️ Authority is not context

Text entering a model is information, not permission. Capability names cannot grant locality, approval requirements come from typed capability behavior, and direct external tool results remain untrusted.

### 🧠 Memory is evidence, not unquestionable truth

Memories retain ownership and provenance and can be corrected or revoked. The persistence layer is designed around governed beliefs instead of an opaque profile that silently becomes instruction.

### 🔐 Privacy fails closed

Egress decisions use explicit privacy tiers. Missing classification is denied rather than guessed safe, and local-only context cannot be sent to a cloud provider through the native path.

### 🧑‍💻 The host remains the authority

Core never owns channel authentication, sender mapping, application configuration, deployment, or domain records such as orders and tickets. A host supplies those decisions through narrow ports and commits business changes in its own system of record.

The complete set of implemented properties and code evidence lives in [Security invariants](docs/SECURITY-INVARIANTS.md). Backend-specific differences are explicit in the [support matrix](docs/SUPPORT-MATRIX.md).

## Adaptive Execution (task contract)

`bastion-runtime::task` is the neutral, owner-scoped vocabulary the kernel uses to run durable tasks — mechanism, not policy. It defines the three execution modes (`Respond` / `Act` / `Pursue`), the durable `TaskCase` record, a concrete `Attempt`, captured `Evidence` and its `Verdict`, plus the status/stop-reason/budget/correlation machinery.

Deliberate boundaries: no NLP heuristics live here (an `Intent` arrives with its `mode` already decided by the consumer — the kernel never classifies text); no business state (host domain state is carried opaquely in `OpaqueState` and never interpreted); no graph/DAG (a `TaskCase` stores state, evidence, and a single recomputed `NextDecision` — the next step is derived after each observation, not walked from a stored plan).

| Public type | Lifecycle role |
| --- | --- |
| `ExecutionMode` | `Respond` (no side effect, no record) · `Act` (one bounded effect, ephemeral record if needed) · `Pursue` (durable, resumable — `requires_durable_case()` is true only here). |
| `TaskCase` / `TaskCaseId` | The durable, owner-scoped record a `Pursue` objective persists; survives restart. |
| `Attempt` / `AttemptId` | A concrete step taken against the case. |
| `Evidence` / `EvidenceId` / `EvidenceKind` | What an attempt observed (diff, artifact, tool result …), captured as data. |
| `Verdict` / `VerdictProvenance` / `VerificationStatus` | The verifier's judgment on an attempt's evidence. |
| `AdaptiveCycle`, `Orchestrator`, `TaskStore` / `SqliteTaskStore`, `LayeredVerifier` | Run one cycle, coordinate child tasks (no central DAG), persist cases, and verify — all behind host-replaceable ports (`Chooser`, `TaskExecutor`, `Verifier`). |

`Respond` never touches the store; only `Pursue` mandates a durable `TaskCase`. The host owns activation (which mode a request runs under) and business state; the kernel owns the record and the recomputed next step. `bastion-agent` documents the user-facing side (mode activation, `/task`, `/schedule`, browser, budgets); this crate documents only the contract.

## Architecture

```text
 embedding host: service · CLI · channel · application
                         │
             identity + product policy
                         │
                         ▼
        cognition + personas + response composition
                         │
                         ▼
        ┌───────── Bastion runtime ─────────┐
        │ sessions · guardrails · capabilities │
        │ approvals · privacy · observability  │
        └──────────────────────────────────────┘
             │           │           │
             ▼           ▼           ▼
         providers     memory     tools / MCP
             │                      extensions
             └───────────────────────────┘
                         │
                         ▼
                   bastion-types
```

A native turn is deliberately explicit:

1. The host constructs an `AgentLoop` with its provider, responder, memory, session manager, approval gate, and optional ports.
2. It calls `run_turn_for` with input and a canonical owner identifier.
3. Core loads owner-scoped state and context, applies trust and privacy handling, then runs input guardrails.
4. Tool calls pass through egress, approval, execution, and result-tagging boundaries.
5. Core validates output, persists session state, records usage, emits observer events, and returns text to the host.

Read [Architecture](docs/ARCHITECTURE.md) for the dependency rules, key abstractions, and the distinction between the native loop and external agent harnesses.

## Start with a real turn

The smallest example uses the real kernel with a mock provider and temporary SQLite storage. It requires no credentials and performs no network I/O after dependencies are installed. Copy this repository's clone URL and use it below:

```bash
git clone <this-repository-url> bastion-core
cd bastion-core
cargo run -p minimal-agent
```

Expected output:

```text
Hello from minimal-agent! (you said: hello)
```

Then explore host-owned policy and multi-owner isolation:

```bash
cargo run -p embedded-host
cargo run -p embedded-host-slice
```

These examples are reference compositions, not production daemons. They depend only on workspace crates and never import `bastion-agent`.

### Embed from a Git checkout

The workspace does not currently publish one umbrella `bastion-core` crate. Select only the crates your host needs:
The workspace does not currently publish one umbrella `bastion-core` crate. Select only the crates your host needs, replacing `<this-repository-url>` with the same clone URL:
```toml
[dependencies]
bastion-types = { git = "<this-repository-url>" }
bastion-runtime = { git = "<this-repository-url>" }
bastion-memory = { git = "<this-repository-url>" }
```

Pin production consumers to a revision or release tag rather than tracking a moving branch. See [Versioning](docs/VERSIONING.md) before depending on the public API.

## Workspace crates

| Layer | Crate | Responsibility |
| --- | --- | --- |
| Contracts | `bastion-types` | Messages, privacy tiers, approvals, beliefs, deployment context, failure kinds, and secret references. |
| Kernel | `bastion-runtime` | Agent loop, sessions, typed ports, capabilities, hooks, policy gates, and observability. |
| Kernel | `bastion-memory` | Governed memory contracts and SQLite persistence. |
| Intelligence | `bastion-cognition` | Goals, learning, evaluation, proactivity, retrieval, and Cabinet deliberation. |
| Intelligence | `bastion-personas` | Persona definitions, routing, and response composition. |
| Integrations | `bastion-providers` | Native model-provider implementations. |
| Integrations | `bastion-mcp` | MCP clients, registry adapters, OAuth support, and tool-source integration. |
| Integrations | `bastion-agent-runtime` | External agent-harness contract plus Codex and ACP adapters. |
| Integrations | `bastion-mesh` | Identity, peer transport, `.af` interop, context, and scheduling. |
| Extensions | `bastion-extension-protocol` | Manifests, permissions, trust tiers, signatures, and lockfiles. |
| Extensions | `bastion-extension-wasm` | Isolated, fuel-bounded WASM execution. |

Dependency direction is enforced by [`scripts/check-crate-deps.sh`](scripts/check-crate-deps.sh), keeping the kernel independent from optional integrations and from the product built above it.

## Core vs. bastion-agent

| `bastion-core` owns | `bastion-agent` owns |
| --- | --- |
| Reusable Rust contracts and mechanisms | The installable, self-hosted product |
| Agent loop, policy ports, memory, cognition, and personas | CLI, TUI, daemon, HTTP surfaces, and channels |
| Provider, MCP, mesh, and extension primitives | User-facing configuration and deployment composition |
| Embedding examples and public API contracts | Identity mapping, product policy, sidecars, and mobile clients |

This split is intentional: applications can reuse the governed substrate without inheriting Bastion's product choices, while the flagship agent can evolve its interfaces without turning the kernel into a monolith.

## Documentation

| Guide | Use it for |
| --- | --- |
| [Getting started](docs/GETTING-STARTED.md) | Prerequisites, build, and the first offline turn. |
| [Architecture](docs/ARCHITECTURE.md) | Layers, runtime flow, key abstractions, and the Core/product boundary. |
| [Memory architecture](docs/MEMORY.md) | Belief lifecycle, provenance, validity, isolation, and persistence. |
| [Security invariants](docs/SECURITY-INVARIANTS.md) | Guarantees, evidence, and host responsibilities. |
| [Backend support matrix](docs/SUPPORT-MATRIX.md) | Native and external-runtime policy coverage. |
| [Development](docs/DEVELOPMENT.md) | Repository workflow, code organization, and CI commands. |
| [Testing](docs/TESTING.md) | Deterministic, ignored, and credentialed test suites. |
| [Versioning](docs/VERSIONING.md) | API baselines, compatibility, and release policy. |
| [Pending architecture tasks](docs/tasks/README.md) | Planned changes that are not implemented contracts yet. |

Historical product documentation under `docs/archive/` is preserved for context and is not an implementation reference for this workspace.

## Development

The normal validation loop needs no application `.env` or external service configuration:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
bash scripts/check-crate-deps.sh
bash scripts/dump-public-api.sh --check
bash scripts/check-scope-and-scrub.sh
```

Public API inventories are tracked in `docs/api-baseline/`. If a public item changes, regenerate the baseline with `bash scripts/dump-public-api.sh` and review the diff deliberately.

## Contributing

Bug reports, questions, and design proposals are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before investing in a larger change; it explains project governance, code standards, required checks, security reporting, and how external pull requests are handled.

## License

[MIT](LICENSE). Embed it, adapt it, and build agents whose authority remains explicit.
