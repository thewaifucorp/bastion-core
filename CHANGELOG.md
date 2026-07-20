# Changelog

All notable changes to `bastion-core` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[docs/VERSIONING.md](docs/VERSIONING.md) (per-crate, not a single workspace
version).

## Unreleased

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
