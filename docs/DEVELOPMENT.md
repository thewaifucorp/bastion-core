<!-- generated-by: gsd-doc-writer -->
# Development

## Local setup

```bash
git clone <repository-url> bastion-core
cd bastion-core
cargo build
cargo test
```

No application `.env` or service configuration is required for the normal workspace build and deterministic test suite.

## Common commands

| Command | Purpose |
| --- | --- |
| `cargo build` | Build every default workspace member required by Cargo |
| `cargo test` | Run deterministic tests; ignored live suites remain skipped |
| `cargo fmt --check` | Check Rust formatting using `rustfmt.toml` |
| `cargo clippy --all-targets --all-features -- -D warnings` | Run the strict CI lint gate |
| `cargo run -p minimal-agent` | Exercise a complete offline turn |
| `bash scripts/check-crate-deps.sh` | Enforce the crate dependency allowlist and cycle rules |
| `bash scripts/dump-public-api.sh --check` | Compare public items with `docs/api-baseline/` |
| `bash scripts/check-scope-and-scrub.sh` | Enforce the public repository scope and scrub rules |

If a public item changes, run `bash scripts/dump-public-api.sh`, review the generated diff, and commit the affected baseline with the code change.

## Code organization

Put shared vocabulary in `bastion-types`, execution mechanisms and ports in `bastion-runtime`, and optional behavior in the narrowest extension crate that owns it. New product entry points, channels, deployment configuration, and business-state persistence do not belong in this repository.

The dependency map is explicit in `scripts/check-crate-deps.sh`; update it deliberately when adding a crate or a justified edge.

## Code style

- Public Rust documentation is written in English.
- The workspace forbids unsafe code.
- Prefer typed errors in library APIs; reserve `anyhow` for examples and outer boundaries.
- Avoid `unwrap` and `expect` outside tests unless the invariant is local and documented.
- Use structured `tracing` fields instead of ad hoc output in library code.
- Run rustfmt and Clippy before submitting a change.

## Pull requests

There is no documented branch-name convention. Commits use Conventional Commits, normally with the crate name minus `bastion-` as scope.

Before opening a pull request:

1. Run every command in the required-checks section of [CONTRIBUTING.md](../CONTRIBUTING.md).
2. Update the API baseline if a public item changed.
3. Add a migration note for a breaking change.
4. Explain which crates changed and what reviewers should focus on using the repository PR template.

External design work should begin as an issue; merge rights and proposal handling are described in [CONTRIBUTING.md](../CONTRIBUTING.md).
