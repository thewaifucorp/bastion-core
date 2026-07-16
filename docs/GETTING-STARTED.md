<!-- generated-by: gsd-doc-writer -->
# Getting started

This guide runs a complete Bastion Core turn without credentials or network services.

## Prerequisites

- Git.
- A current stable Rust toolchain with Cargo. CI intentionally tracks stable rather than promising an older MSRV; see [VERSIONING.md](VERSIONING.md).
- Network access for the first Cargo dependency download. The example itself runs offline.

## Clone and build

```bash
git clone <repository-url> bastion-core
cd bastion-core
cargo build
```

## Run the minimal example

```bash
cargo run -p minimal-agent
```

The example uses a mock provider, a temporary SQLite database, and the real `AgentLoop`. It exits after one turn and prints a greeting containing the input `hello`.

## Explore embedding

Run the host-owned policy example:

```bash
cargo run -p embedded-host
```

Then run the broader two-owner slice:

```bash
cargo run -p embedded-host-slice
```

These are reference hosts, not production daemons. Read their `src/main.rs` files alongside [ARCHITECTURE.md](ARCHITECTURE.md) to see which ports a real application must supply.

## Common setup issues

### Cargo cannot download dependencies

The workspace uses crates from the Rust package ecosystem. Restore registry/network access or use an already populated Cargo cache, then retry `cargo build`.

### A live runtime test asks for a local CLI or login

The default `cargo test` skips tests marked `#[ignore]`. Do not add `--ignored` unless you intend to run a real Codex, Claude, or OpenCode subprocess with the required host authentication. See [TESTING.md](TESTING.md).

### `legacy-terminal-agent` examples or imports are unavailable

The deprecated terminal provider is feature-gated and off by default. New integrations should use `bastion-agent-runtime`; see [terminal-agent-providers.md](terminal-agent-providers.md).

## Next steps

- [Architecture](ARCHITECTURE.md) explains the crate boundaries and turn flow.
- [Development](DEVELOPMENT.md) lists the local and CI checks.
- [Testing](TESTING.md) distinguishes deterministic tests from credentialed live tests.
- [Security invariants](SECURITY-INVARIANTS.md) defines the contracts an embedding host must preserve.
