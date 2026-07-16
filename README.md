<!-- generated-by: gsd-doc-writer -->
# bastion-core

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/Rust-2021-orange.svg)](Cargo.toml)

The OSS Rust substrate for building persistent, governable AI agents. It provides embeddable execution, policy, memory, cognition, persona, provider, MCP, mesh, and extension primitives; applications such as `bastion-agent` provide the CLI, channels, configuration, and deployment composition.

`bastion-core` is a library workspace, not a standalone daemon or workflow engine. Hosts choose the crates they need and supply product policy through typed ports.

## Quick start

The smallest example runs offline with a mock provider and temporary SQLite storage:

```bash
git clone <repository-url> bastion-core
cd bastion-core
cargo run -p minimal-agent
```

Expected output includes:

```text
Hello from minimal-agent! (you said: hello)
```

The repository does not currently publish a single installable `bastion-core` package. Workspace crates are consumed as Rust dependencies, while the examples demonstrate complete host composition.

## Workspace

| Layer | Crates | Responsibility |
| --- | --- | --- |
| Contracts | `bastion-types` | Shared messages, privacy tiers, approvals, beliefs, deployment context, and secret references |
| Kernel | `bastion-runtime`, `bastion-memory` | Agent loop, typed ports, capabilities, sessions, hooks, governed memory, and SQLite persistence |
| Intelligence | `bastion-cognition`, `bastion-personas` | Goals, learning, evaluation, proactivity, Cabinet deliberation, persona routing, and response composition |
| Integrations | `bastion-providers`, `bastion-mcp`, `bastion-agent-runtime`, `bastion-mesh` | Model providers, MCP, external agent harnesses, identity, transport, interop, and scheduling |
| Extensions | `bastion-extension-protocol`, `bastion-extension-wasm` | Manifests, permissions, trust, lockfiles, and a fuel-bounded WASM sandbox |

The permitted dependency direction is enforced by `scripts/check-crate-deps.sh`. See [Architecture](docs/ARCHITECTURE.md) for the layers, runtime flow, and Core/product boundary.

## Examples

| Example | What it demonstrates | Command |
| --- | --- | --- |
| `minimal-agent` | Smallest complete offline turn | `cargo run -p minimal-agent` |
| `embedded-host` | Host-defined context and approval policy | `cargo run -p embedded-host` |
| `embedded-host-slice` | Two-owner isolation, rule propagation, and host-owned observability | `cargo run -p embedded-host-slice` |

All examples depend only on workspace crates; none imports the `bastion-agent` product.

## Design guarantees

- Capability execution is mediated by typed policy boundaries, with fail-closed egress and approval behavior.
- Trust follows content; tool output does not become authoritative merely by entering context.
- Session, memory, and approval state are owner-scoped.
- External context is carried through typed ports, leaving application business state with the embedding host.
- Observability is exposed through neutral traits and OpenTelemetry types rather than a required vendor.

The exact contracts and their current code evidence live in [Security invariants](docs/SECURITY-INVARIANTS.md). Backend-specific guarantees live in the [support matrix](docs/SUPPORT-MATRIX.md).

## Documentation

- [Getting started](docs/GETTING-STARTED.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Development](docs/DEVELOPMENT.md)
- [Testing](docs/TESTING.md)
- [Memory architecture](docs/MEMORY.md)
- [Versioning policy](docs/VERSIONING.md)
- [Backend support matrix](docs/SUPPORT-MATRIX.md)
- [Security invariants](docs/SECURITY-INVARIANTS.md)

Historical product documentation is kept under `docs/archive/` and is not an implementation reference for this workspace.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for governance, required checks, and the contribution process.

## License

MIT — see [LICENSE](LICENSE).
