# Versioning policy

This repo (`bastion-core`) is a Cargo workspace with two tiers of crate,
each with a different versioning contract. Both are pre-1.0 today; this
document says what "pre-1.0" is allowed to mean here, and what changes once
a crate crosses 1.0.

Two numbers sit ON TOP of the crate versions and were, until §7, decided ad
hoc release by release: the git tag on this repo, and the product version of
`bastion-agent`. §7 writes both rules down.

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
  (`bastion-agent/src/routing.rs`, `bastion-agent-runtime` crate) — see the
  separate `feat/pursue-task-model-hint` branch/PR.
- ~~Per-mode provider override on the Cabinet orchestrator~~ — **done,
  2026-07-30**: `bastion-personas` 0.2.0 → 0.2.1
  (`PersonaResponder::with_cabinet_provider`), see `CHANGELOG.md`'s
  Unreleased section.
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

## 7. Repo tags and the product version

§1-§6 govern the version inside each crate's `Cargo.toml`. They say nothing
about the two numbers a human actually reads: `git tag` on this repo, and
`bastion-agent`'s own version. Those were decided per release with no written
criterion — including `v0.2.0`, `v0.3.0` and `bastion-agent` 0.2.4 — so the
next person had to reconstruct the intent from the diff. This section removes
that.

### 7.1 This repo's tag is DERIVED, never judged

A `bastion-core` tag is a label for "which set of crate versions is this",
and it follows mechanically from the crates in the release:

| What happened to the crates in this release | Repo tag |
|---|---|
| Any crate's **minor** advanced (a breaking change, per §1) | **minor** bump on the tag |
| Only **patch** advances (additive APIs, fixes) | **patch** bump on the tag |
| No crate version changed at all (docs, CI, tests only) | **no tag** — do not cut a release |

Consequences, stated so they are not re-litigated:

- The tag carries no independent opinion about how "big" a release feels. A
  release with one breaking rename is a minor bump; a release with three
  large additive subsystems is a patch bump. Size is what the CHANGELOG is
  for.
- Worked example, the release this section was written for: the provider-auth
  contracts, the credential lifecycle and the catalog/conformance suite are
  all additive (`bastion-types` 0.2.1 → 0.2.2, `bastion-runtime` 0.2.2 →
  0.2.3, no minor advance anywhere), so the tag is **`v0.3.1`** — not
  `v0.4.0`, even though three subsystems landed.
- Worked example, `v0.3.0`: `TurnKernel::run_tool_loop` gained a parameter and
  `bastion-types`/`bastion-runtime`/`bastion-personas` advanced their minor,
  so the repo tag advanced its minor too.

### 7.2 `bastion-agent`'s version is NOT derived

The product version answers a different question — "what does an operator get,
and what must they do to upgrade" — so it is a judgment call, made against
this list rather than by feel:

- **minor** when upgrading is not transparent: a config key must be added or
  changed, state migrates, a surface is exposed that was not exposed before,
  or a default behavior changes.
- **patch** when upgrading is transparent: features that are opt-in and
  default-off, fixes, docs, and advancing the pinned `bastion-core` commit
  without a behavior change for an existing deployment.

`bastion-agent` 0.2.4 is a worked example of the patch side: it added two
network surfaces (extension UI, remote credential issuance) and both are
default-off behind explicit config, so an existing deployment upgrading gets
byte-identical behavior. New surface alone does not make a minor — surface
that turns itself on does.

Every `bastion-agent` release names the `bastion-core` commit it pins in its
CHANGELOG entry, so a product version is always traceable to a crate set.

### 7.3 Mechanics for both repos

- Tags are **annotated** (`git tag -a`), never lightweight.
- The tag goes on the merge commit in `main`, after CI is green — not on the
  release branch tip.
- The CHANGELOG section for that version must exist in the commit being
  tagged. A tag pointing at a commit whose CHANGELOG still says `Unreleased`
  is the defect this rule exists to prevent.
- `Cargo.lock` is regenerated with cargo, not hand-edited, so a pin change is
  validated by resolution rather than by eye.
