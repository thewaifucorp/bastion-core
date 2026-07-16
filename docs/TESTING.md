<!-- generated-by: gsd-doc-writer -->
# Testing

The workspace uses Rust's built-in test harness with synchronous and Tokio tests. Most coverage is colocated in crate source modules; live external-runtime tests are separate integration-test files under `crates/bastion-agent-runtime/tests/`.

## Run the default suite

```bash
cargo test
```

This is the CI test command. Tests marked `#[ignore]` are compiled but not executed, so the default suite does not launch authenticated agent CLIs.

Run one crate or one test by name:

```bash
cargo test -p bastion-runtime
cargo test -p bastion-memory owner_isolation
cargo test -p bastion-agent-runtime conformance
```

## Live runtime tests

The following suites spawn real local tools, may use tokens or quota, and require host authentication:

```bash
cargo test -p bastion-agent-runtime --test acpx_live_claude -- --ignored --nocapture
cargo test -p bastion-agent-runtime --test acpx_live_opencode -- --ignored --nocapture
cargo test -p bastion-agent-runtime --test codex_live -- --ignored --nocapture
```

Read the selected test before running it. Each file documents its required binaries, login state, scenarios, and known limitations.

## Writing tests

- Keep focused unit tests in a `#[cfg(test)]` module beside the implementation.
- Use `#[tokio::test]` for async behavior.
- Put a runtime integration that needs a real executable in `crates/bastion-agent-runtime/tests/`, mark it ignored, and document its cost and prerequisites.
- Name tests after the contract they protect, especially for egress, approval, trust, owner isolation, and public boundaries.
- Prefer mock providers, temporary directories, and bundled SQLite over credentials or shared state.

There is no numeric coverage threshold configured. The repository instead uses contract-focused tests, public API baselines, executable examples, and structural scripts.

## CI gates

The `ci` workflow runs on pushes to `main` and pull requests:

| Job | Gate |
| --- | --- |
| `crate-deps` | `bash scripts/check-crate-deps.sh` |
| `rust` | formatting, strict Clippy, and `cargo test` |
| `examples` | `cargo check -p minimal-agent -p embedded-host` |
| `public-api-baseline` | `bash scripts/dump-public-api.sh --check` |
| `scope-and-scrub` | `bash scripts/check-scope-and-scrub.sh` |

The `embedded-host-slice` example remains runnable and documented, although the current CI examples job checks only `minimal-agent` and `embedded-host` explicitly.
