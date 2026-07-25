# Versioning policy

This repo (`bastion-core`) is a Cargo workspace with two tiers of crate,
each with a different versioning contract. Both are pre-1.0 today; this
document says what "pre-1.0" is allowed to mean here, and what changes once
a crate crosses 1.0. A third tier — the **App** — is the product version of
`bastion-agent`, which
consumes these crates as a dependency; it is bumped on releases, not on API
shape, and is out of scope for this document.

## The two tiers

| Tier | Crates | Contract |
|---|---|---|
| **Kernel** | `bastion-types`, `bastion-runtime`, `bastion-memory` | Strict semver **once at 1.0**. Pre-1.0: see below. |
| **Extensions** | `bastion-providers`, `bastion-mcp`, `bastion-agent-runtime`, `bastion-cognition`, `bastion-personas`, `bastion-mesh`, `bastion-extension-protocol`, `bastion-extension-wasm` | Semver-shaped but looser: 0.x for the foreseeable future; breaking changes land on a minor bump. |

The kernel/extension split, the dependency allowlist between them, and the
rationale for which crate hosts what are enforced by
`scripts/check-crate-deps.sh` — this document only covers the version-number
contract on top of that split.

## 1. Pre-1.0 rule (today)

Every crate in this workspace is `0.1.0`. Cargo's own semver convention for
`0.x.y` treats the **minor** version (`x`) as the breaking-change slot (a
`0.1 -> 0.2` bump is not caret-compatible; `0.1.0 -> 0.1.1` is) — this
workspace follows that convention literally:

- A **breaking** change to a kernel or extension crate's public API bumps
  its **minor** version (`0.1.0 -> 0.2.0`), even though the crate is still
  `0.x`.
- A **non-breaking** addition or a bug fix bumps its **patch** version
  (`0.1.0 -> 0.1.1`).
- Each crate's version is independent — a breaking change to
  `bastion-mesh` does not force a version bump in `bastion-types` unless
  `bastion-mesh`'s own dependency on it actually changed.

**Public API** here means: everything in `docs/api-baseline/<crate>.txt`
(§2). `pub(crate)` items are never part of the contract; moving an item
from `pub` to `pub(crate)` (or removing it) **is** a breaking change to the
crate that lost it, exactly like it would be at any other version.

## 2. What counts as the public API — the baseline check

`scripts/dump-public-api.sh` dumps a deterministic, sorted list of every
`pub` item (`fn`, `struct`, `enum`, `trait`, `const`, `static`, `type`,
`mod`, and every name a `pub use` re-export makes reachable) per crate into
`docs/api-baseline/<crate>.txt`. It is the mechanical definition of "the
public API" for the purposes of this policy — not full type signatures
(argument/return types can still change without moving an item in or out
of the list), but every item's presence, name, and top-level visibility.

- Regenerate after any change: `bash scripts/dump-public-api.sh`, review
  the diff, commit the updated baseline file(s).
- CI (`public-api-baseline` job, `.github/workflows/ci.yml`) runs
  `bash scripts/dump-public-api.sh --check`, which regenerates into a temp
  dir and diffs against the committed baseline. **A public-API change
  without a baseline update fails CI** with the diff printed inline — the
  gate cannot be silently bypassed by forgetting to run the script.
- A baseline diff is not automatically a version bump by itself (adding a
  new `pub fn` is additive, not breaking) — but every diff should be read
  against §1/§3 before committing: does this line disappearing, appearing,
  or changing kind mean a version bump and changelog entry?

## 3. Breaking changes

Removing or renaming a public item, changing a public signature, moving a
type between crates, or reducing visibility is a breaking change. Bump the
affected pre-1.0 crate's minor version and describe the changed contract in
the PR and changelog.

## 4. MSRV

Minimum Supported Rust Version tracks whatever toolchain this repository's
CI currently builds with — **no explicit lower bound is promised below
current stable**. CI installs `dtolnay/rust-toolchain@stable`; the repository
does not pin a `rust-toolchain` file. Moving with stable is not itself treated as a breaking change
to any crate's semver (consistent with most of the pre-1.0 Rust ecosystem);
it is called out in the PR that bumps it so downstream consumers on an
older toolchain notice.

## 5. What changes at 1.0

Once a kernel crate ships `1.0.0`, normal semver takes over for it:
`MAJOR.MINOR.PATCH` where only `MAJOR` may break, `MINOR` is additive-only,
`PATCH` is fixes-only — no more "minor bump = maybe breaking." Extension
crates are expected to stay 0.x well past the kernel's 1.0 (they are where
new, less-settled surface continues to land); each is free to make its own
1.0 call independently once its own contract has proven stable in
practice.

## 6. 2026-07-25 fabric-readiness pass (pre-1.0 checklist, not a freeze)

Before `bastion-runtime` (Kernel tier) can responsibly cross 1.0, every
`TODO(core seam)`/`TODO(A4 seam)` left in `bastion-agent` (the only external
consumer today) needed an explicit decision: implemented now, or
consciously deferred with a reason recorded. This pass audited all 5 and is
the record of that decision — it does **not** itself declare 1.0; that
remains a separate maintainer call once the kernel's contract has proven
stable in practice (§5).

**Implemented** (both touch `AgentLoop`, `bastion-runtime` — genuinely
Kernel-tier, so both are additive `pub` surface, reflected in the
regenerated `docs/api-baseline/bastion-runtime.txt`):

- `AgentLoop::fallback_models` changed from a plain `Vec<String>` to
  `SharedFallbackModels` (`Arc<RwLock<Vec<String>>>`) — the same shape as
  `provider: SharedProvider` — so a caller holding a cloned handle can
  hot-swap the fallback ladder on a running loop without `&mut AgentLoop`
  or a restart (`bastion-agent/src/proposals.rs`'s `TODO(A4 seam)`).
- `AgentLoop::compaction_provider: Option<SharedProvider>` (new field, opt
  in via `with_compaction_provider`) — lets a caller point
  `AutoCompact::compact`'s summarization call at a different provider than
  the turn's conversational one. `None` (the default) is byte-identical to
  pre-seam behavior (`bastion-agent/src/routing.rs`'s `TODO(core seam)` for
  a dedicated compaction provider).

**Consciously deferred** (all three touch Extension-tier crates —
`bastion-agent-runtime`/`bastion-personas` — not `bastion-runtime`, so none
of them gate a Kernel 1.0 tag; each crate is free to take these up on its
own 0.x schedule):

- Model hint on `SessionSpec`/`TaskInput` for `pursue_task` routing
  (`bastion-agent/src/routing.rs`, `bastion-agent-runtime` crate).
- Per-mode provider override on the Cabinet orchestrator
  (`bastion-agent/src/routing.rs`, `bastion-personas` crate).
- Routing provider construction through the daemon's `SecretResolver` so
  secrets-dir-only keys work in `/proposal approve`'s `model_config`
  handler (`bastion-agent/src/proposals.rs`) — this one isn't a kernel seam
  at all, just a `bastion-agent`-side wiring gap; recorded here only
  because it shared a `TODO(A4 seam)` tag with the two above.

`docs/api-baseline/bastion-runtime.txt` was regenerated (`bash
scripts/dump-public-api.sh`) and reviewed against this list before the
change landed; `public-api-baseline` CI passed on the additive diff (new
`SharedFallbackModels` type, new `with_compaction_provider` fn — no
removal, no rename, no visibility change).
