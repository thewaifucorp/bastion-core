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
| **Extensions** | `bastion-providers`, `bastion-mcp`, `bastion-agent-runtime`, `bastion-cognition`, `bastion-personas`, `bastion-mesh`, `bastion-extension-protocol`, `bastion-extension-wasm` | Semver-shaped but looser: 0.x for the foreseeable future, breaking changes land on a minor bump with a migration note (§3). |

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
  or changing kind mean a version bump and/or a migration note?

## 3. Deprecation policy

Removing or renaming a public item is a two-step process, not a single
commit:

1. **Warn** (patch or minor release): mark the item `#[deprecated(since =
   "…", note = "…")]` pointing at its replacement. It keeps working. This
   release's changelog/PR calls out the deprecation explicitly.
2. **Remove** (the *next* release that touches that crate, minimum):
   delete the deprecated item. This is the breaking change — bump the
   crate's minor version (§1) and write the migration note (below).

A deprecation cannot be introduced and removed in the same release. There
is no fixed calendar window (this project does not run on a release train
yet) — "the next release" is the next version bump of that specific crate,
whatever triggers it.

## 4. Breaking changes require a migration note

Every breaking change (an item removed/renamed without having gone through
§3, a trait's method signature changing, a type moving to a different
crate, a visibility downgrade of something in the baseline) must ship with
a migration note in the same PR: what broke, the old call site, the new
call site. Put it in the PR description and, if the change is significant
enough to need one, a short design note in the relevant crate's doc comment
pointing at the decision. "Bump the version" without a
migration note is not sufficient — the version number tells a consumer
*that* something broke, the note tells them *what to do about it*.

## 5. MSRV

Minimum Supported Rust Version tracks whatever toolchain this repository's
CI currently builds with — **no explicit lower bound is promised below
current stable**. CI installs `dtolnay/rust-toolchain@stable`; the repository
does not pin a `rust-toolchain` file. Moving with stable is not itself treated as a breaking change
to any crate's semver (consistent with most of the pre-1.0 Rust ecosystem);
it is called out in the PR that bumps it so downstream consumers on an
older toolchain notice.

## 6. What changes at 1.0

Once a kernel crate ships `1.0.0`, normal semver takes over for it:
`MAJOR.MINOR.PATCH` where only `MAJOR` may break, `MINOR` is additive-only,
`PATCH` is fixes-only — no more "minor bump = maybe breaking." Extension
crates are expected to stay 0.x well past the kernel's 1.0 (they are where
new, less-settled surface continues to land); each is free to make its own
1.0 call independently once its own contract has proven stable in
practice.
