## What / why

## Crate(s) touched

## Checklist

- [ ] `cargo fmt --check` / `cargo clippy --all-targets --all-features -- -D warnings` / `cargo test` all pass
- [ ] `bash scripts/check-crate-deps.sh` passes (no reversed kernel/extension/consumer dependency)
- [ ] Public API changed? Ran `bash scripts/dump-public-api.sh` and committed the updated `docs/api-baseline/*.txt`
- [ ] Breaking public API change is documented in the PR and changelog
- [ ] `bash scripts/check-scope-and-scrub.sh` passes

## Breaking API note (if applicable)

## Anything reviewers should focus on
