# Mesh: identity, peer transport, and `.af` interop

`bastion-mesh` (`crates/bastion-mesh`) is the crate that lets one Bastion
instance be recognized by, exchange memory with, and hand its state to
another. It has no dedicated product doc today beyond its own module comments
(`crates/bastion-mesh/src/lib.rs:1-17`) and a four-line mention in the crate
table below — this document is the coherent, product-level explanation: what
mesh is for, how its three pieces fit together, and where the OSS/closed
boundary actually sits.

Mesh depends on the kernel (`bastion-types`, `bastion-runtime`), the
quasi-kernel (`bastion-memory`), and both `bastion-cognition` and
`bastion-personas` — the `.af` interop format spans goal and persona data, so
mesh is not an isolated leaf crate; neither of those two crates depends back
on it (`lib.rs:14-17`).

## 1. Identity — who an agent is

`crates/bastion-mesh/src/identity/` (`identity/mod.rs:1-20`,
`identity/age_identity.rs`).

Every Bastion instance has an `AgentCard` (`identity/mod.rs:20-43`): a signed
JSON identity document — name, an age X25519 public key, an Ed25519 public
key, declared capabilities, allowed sync tags, and optional mesh/MCP endpoint
URLs — served at `/agent-card`. The signature covers the canonical JSON of
every other field.

The private half is an `AgeIdentity` (`identity/age_identity.rs`): an age
X25519 keypair (`MESH_IDENTITY_KEY`, used for mesh end-to-end encryption)
plus an Ed25519 signing key **deterministically derived** from the age key
via a domain-separated SHA-256 hash (`age_identity.rs:49-79`) — never raw
X25519 byte reuse. This means only one secret needs to be generated and
persisted per instance; the signing key is recomputed identically on every
restart. The age secret is never logged — `AgeIdentity`'s own `Debug` impl
is hand-written to redact it (`age_identity.rs:36-43`).

## 2. P2P transport — how two instances talk

`crates/bastion-mesh/src/mesh/` (`mesh/mod.rs:1-42`, `mesh/p2p.rs`,
`mesh/allowlist.rs`, `mesh/context_provider.rs`).

The transport is a single, deliberately locked trait, `MeshTransport`
(`mesh/mod.rs:79-89`): `send(SelectiveSlice, to_owner)` and
`receive(MeshEnvelope) -> SelectiveSlice`. Everything above this trait —
identity, the allowlist, `.af` interop, the scheduler — is transport-agnostic
and never sees plaintext after encryption; callers encrypt before calling
`send`.

**`P2PTransport`** (`mesh/p2p.rs`) is the one OSS implementation: it POSTs an
age-encrypted `MeshEnvelope` to a peer's `/mesh/ingest` HTTP endpoint. Two
security properties worth naming because they're easy to regress silently:
`receive()` asserts `envelope.to_owner == self.local_owner` (cross-owner
injection prevention), and the outbound `reqwest::Client` is built with
`redirect::Policy::none()` (`p2p.rs:46-52`) specifically to block an
open-redirect SSRF where a malicious peer's 3xx response pivots the request
to a private address.

**The relay implementation (Bastion Cloud) is a separate, closed repo that
implements this exact same `MeshTransport` trait.** `MeshTransport` is the
*only* pluggability seam mesh has — swapping P2P for relay never touches
identity, the allowlist, interop, or the scheduler above it. This is a
locked design decision (`mesh/mod.rs:1-3`, "D-02 (LOCKED)"), not an
incidental abstraction.

**`MeshPeerMap`** (`mesh/mod.rs:34-71`) is the registry of known peers
(`owner_id → (peer_url, age_pubkey, allowed_tags)`), populated from
`bastion.toml`'s `[[mesh.peer]]` entries at daemon startup.

**`MeshSliceProvider`** (`mesh/context_provider.rs`) is how a received slice
actually reaches a turn: it implements the kernel's `TurnContextProvider`
seam (SEAM #2), injecting a remote owner's beliefs into the system prompt as
an **opaque** `ContextBlock` — `AgentLoop` includes the content verbatim,
never parses it, capped at `PrivacyTier::CloudOk` since that's the strongest
tier mesh ever carries (`context_provider.rs:1-6`). The same file documents
an async, non-blocking cross-owner Cabinet exchange pattern (`context_provider.rs:6-24`):
one owner's Cabinet deliberation can be written as a `CloudOk` belief tagged
`mesh_cabinet_synthesis`, which flows to any peer whose allowlist includes
that tag and shows up as ordinary context on that peer's next turn. This is
a deliberately neutral, OSS-tier mechanism — richer governance (synchronous
exchange, human-in-the-loop, RBAC) lives in the separate closed layer, not
here.

### The export gate: allowlist, not "everything by default"

`mesh/allowlist.rs`. Nothing leaves an instance just because a peer is
registered. `filter_for_mesh` (`allowlist.rs:23-40`) is a two-stage gate run
on every belief before it can be sent:

1. **Tag allowlist** — the belief's `persona_tag` must appear in that
   specific peer's `OwnerAllowlist.allowed_tags`. A belief with no tag is
   denied by default (conservative-by-construction, not an oversight).
2. **Egress gate** — `check_egress(belief.tier, "mesh")`, the same privacy
   gate used elsewhere in the kernel. `PrivacyTier::LocalOnly` beliefs are
   always denied here, regardless of tag, and this is tested explicitly
   (`allowlist.rs:86-91`, "LocalOnly must never leave the node").

Only `CloudOk` beliefs carrying an explicitly allowlisted tag ever survive
`filter_for_mesh`. This runs *before* the transport ever sees a belief — the
allowlist is a data-selection gate, not a policy check bolted onto the wire
format.

## 3. `.af` interop — moving a whole instance's state

`crates/bastion-mesh/src/interop/` (`interop/mod.rs:1-101`,
`interop/export.rs`, `interop/import.rs`).

`.af` (`AgentFile`, `interop/mod.rs:18-37`) is the export/import format for
an entire instance's portable state: identity (optional), config, memories
(beliefs), goals, personas, and skills, versioned (`AF_VERSION`) and
producer-tagged (`producer: String`, defaulting to `"bastion"` for files
written before this field existed — `interop/mod.rs:20-24`, tested at
`interop/mod.rs:289-303`) so a future non-Bastion producer of the same
format can be told apart without breaking old files.

Two export modes matter for what actually ends up in the file:

- **Ordinary export** (`export_full` without an identity, `interop/export.rs:9-40`)
  never touches identity material at all — verified directly by a test that
  greps the serialized JSON for secret-shaped strings and asserts none are
  present (`interop/mod.rs:326-349`).
- **`--with-identity` export** is a **documented, deliberate exception**: it
  embeds the raw age/Ed25519 *private key* bytes in plaintext
  (`interop/mod.rs:351-361`, pinned by a test that asserts the secret IS
  present). This is correct, not a leak — the keypair itself is the portable
  mesh identity this flag exists to carry to another machine, so there is no
  `SecretRef`-style indirection that could stand in for it the way a
  provider API key can. The one producer of this file hardens it further
  outside this crate (opt-in flag, `chmod 0600` immediately after write).

## 4. Mesh-sync — the scheduler

`crates/bastion-mesh/src/scheduler/` (`scheduler/cron.rs`).

A background task (`spawn_mesh_sync_job`, `cron.rs:29-42`) ticks on
`mesh.sync_interval` (minutes, default 15, `0` disables periodic sync
entirely — manual-only mode) and, per tick, iterates every registered peer,
builds that peer's `OwnerAllowlist` from its `allowed_tags`, runs
`filter_for_mesh`, and calls `MeshTransport::send` — the exact same path a
manual `/mesh-sync` command already uses. The scheduler is additive, not a
replacement: both paths converge on the same allowlist-gated send.

This lives in `bastion-mesh` rather than `bastion-cognition` (despite an
older backlog topology table grouping it there) — see `lib.rs:10-12` for the
M2 step 6 rationale recorded at the time.

## Summary: what's pluggable, what isn't

| Piece | Pluggable? |
|---|---|
| `MeshTransport` (P2P vs. relay) | **Yes — the only seam.** Same trait, either implementation, nothing else changes. |
| Identity (age/Ed25519) | No — one scheme, deterministic derivation. |
| The allowlist gate | No — always runs, always two-stage (tag + tier). |
| `.af` format | No — one versioned schema; producer-tagged for forward compatibility. |
| Scheduler cadence | Configurable interval, not pluggable mechanism. |

If you're evaluating or integrating mesh: the only thing you'd ever swap out
is the transport. Everything above it — who an agent is, what it's allowed
to export, and the portable format it exports to — is fixed, shared
infrastructure between the OSS P2P path and the closed relay path.
