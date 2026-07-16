## What / why

## Crate(s) touched

## Checklist

- [ ] `cargo fmt --check` / `cargo clippy --all-targets --all-features -- -D warnings` / `cargo test` all pass
- [ ] `bash scripts/check-crate-deps.sh` passes (no reversed kernel/extension/consumer dependency)
- [ ] Public API changed? Ran `bash scripts/dump-public-api.sh` and committed the updated `docs/api-baseline/*.txt`
- [ ] Breaking change? Migration note included below (see `docs/VERSIONING.md` §3–4)
- [ ] `bash scripts/check-scope-and-scrub.sh` passes

## Migration note (if breaking)

## Anything reviewers should focus on
