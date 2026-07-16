<!-- generated-by: gsd-doc-writer -->
# Contributing to bastion-core

`bastion-core` is the OSS Rust substrate that powers
`bastion-agent` and any host
that embeds it. The source is public — read it, fork it, embed it in your
own project under the terms of [LICENSE](LICENSE).

**Merge rights on this repo are restricted to project maintainers.** This is a
deliberate governance choice, not a reflection on contribution quality: the
core's roadmap has to stay coupled to what's being built on top of it
internally, and an externally-merged change that drifts from that direction
would be actively harmful to maintain. In practice:

- **Bug reports and questions** — open an issue, anyone can. These are read
  and are the best way to influence direction.
- **Pull requests** — external PRs are welcome as a reference/proposal but
  are not merged as-is; a maintainer will either merge it, ask for
  changes, or reimplement the idea directly, depending on fit. Don't expect
  merge-on-green-CI.
- **Design proposals** — open an issue first for anything beyond a small
  fix, before investing time in an implementation.
- New behavior normally enters through a typed port, trait implementation, or
  focused crate rather than a parallel rewrite of the core loop. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development setup

See [Getting started](docs/GETTING-STARTED.md) for prerequisites and the first
offline turn, and [Development](docs/DEVELOPMENT.md) for repository structure
and local workflow.

```bash
git clone <repository-url> bastion-core
cd bastion-core
cargo build
cargo test
```

Rust toolchain: whatever `dtolnay/rust-toolchain@stable` resolves to in CI
(see [docs/VERSIONING.md](docs/VERSIONING.md) §5 for the MSRV policy).

## Required checks before opening a PR

These are the same gates CI runs (`.github/workflows/ci.yml`) — a PR that
fails any of them won't merge:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
bash scripts/check-crate-deps.sh      # kernel ← extensions ← consumers, never reversed
bash scripts/dump-public-api.sh --check   # public API baseline (docs/api-baseline/) up to date
bash scripts/check-scope-and-scrub.sh     # no cloud-orchestration symbols, no leaked names
```

If your change touches a crate's public API (anything in
`docs/api-baseline/<crate>.txt`), regenerate the baseline and commit it:
`bash scripts/dump-public-api.sh`.

## Code standards

- Errors: typed `BastionError` (thiserror, `#[non_exhaustive]`,
  `crates/bastion-types/src/lib.rs`) or the relevant crate's own error
  type), matched at boundaries — `anyhow` only at binary/example
  boundaries, never threaded through library APIs.
- No `unwrap`/`expect` outside test code except a proven invariant.
- `tracing` structured fields for logging, never `println!`.
- English rustdoc on public items.
- The crate is `#![forbid(unsafe_code)]` — no exceptions.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):
`feat(scope): …`, `fix(scope): …`, `docs(scope): …`, `chore(scope): …`, etc.
Scope is usually the crate name minus the `bastion-` prefix (e.g.
`feat(memory): …`, `fix(mesh): …`).

## Breaking changes

See [docs/VERSIONING.md](docs/VERSIONING.md) §3–4: a public API removal
goes through a deprecation cycle, and every breaking change ships a
migration note in the PR description.

## Security

Do not open a public issue for a suspected vulnerability. See
[docs/SECURITY-INVARIANTS.md](docs/SECURITY-INVARIANTS.md) for the
properties that must never regress, and contact the maintainer directly
(see [CODEOWNERS](.github/CODEOWNERS)) to report a concern privately.
