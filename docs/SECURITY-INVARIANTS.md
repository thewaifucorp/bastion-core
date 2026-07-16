# Security invariants

These are the security properties implemented by this workspace. An embedding host can add stricter policy, but must not bypass these boundaries when it uses the corresponding Core mechanism.

## 1. Capability names do not grant locality

`Capability::is_local` is typed behavior. `CapabilityRegistry::register` rejects a non-local capability that claims the reserved `cmd:` namespace and refuses duplicate keys.

- **Code:** `crates/bastion-runtime/src/capability/registry.rs`
- **Evidence:** registry tests for namespace impersonation and key overwrite.

## 2. Egress fails closed

`check_egress` accepts cloud-safe context for any destination and local-only context only for the local provider. A missing privacy tier is denied rather than inferred safe.

- **Code:** `crates/bastion-runtime/src/hooks/egress.rs`
- **Evidence:** the full tier/destination unit-test matrix, including `none_tier_blocks_all_providers`.

`McpToolSource` also performs the egress check before remote dispatch. A host that implements a different `ToolSource` must preserve the same contract.

## 3. Approval is a typed capability property

`Capability::needs_approval` is selected by the capability implementation, not by untrusted invocation input. `CapabilityRegistry` always carries an `ApprovalGate`; its default `NullApprovalGate` denies an approval-requiring capability rather than executing it.

- **Code:** `crates/bastion-runtime/src/capability/registry.rs`, `crates/bastion-runtime/src/agent/ports.rs`, and `crates/bastion-runtime/src/capability/approval.rs`
- **Evidence:** `needs_approval_true_without_queue_fails_closed`, queue-before-dispatch, post-approval dispatch, idempotent reuse, and wrong-owner rejection tests.

## 4. Trust follows the result

`CapabilityRegistry::invoke` returns `TaggedValue`. Trust is derived from the capability's typed `is_trusted` property and travels with the value; it is not re-derived from a capability name.

- **Code:** `crates/bastion-runtime/src/capability/registry.rs`
- **Evidence:** local and non-local tagged-value tests.

Direct `ToolSource` paths do not have a `Capability` instance and therefore treat results as untrusted. They cannot claim trusted locality.

## 5. Owner-scoped state rejects cross-owner access

Session, belief, and approval APIs carry owner identity at their persistence boundaries. Approval resolution checks owner identity, and memory mutation/revocation tests exercise cross-owner denial.

- **Code:** `crates/bastion-runtime/src/session/sqlite.rs`, `crates/bastion-memory/src/sqlite.rs`, and `crates/bastion-runtime/src/capability/approval.rs`
- **Evidence:** owner-scoped pending approvals, wrong-owner approval rejection, and `test_owner_isolation_revoke_and_provenance`.

The product is responsible for mapping an external sender to a canonical owner before calling Core.

## 6. Host context is opaque and tiered

`TurnContextProvider` returns `ContextBlock` values. Core gates each block by its declared privacy tier and otherwise carries its content without parsing it into authority.

- **Code:** `crates/bastion-runtime/src/agent/context.rs` and `crates/bastion-runtime/src/agent/loop_.rs`
- **Evidence:** `context_block_local_only_dropped_on_cloud_provider` and the context assembly unit tests.

## 7. External agent runtimes declare policy coverage

An `AgentRuntime` descriptor distinguishes bridged policy from harness-owned policy. Callers must inspect `PolicyCoverage`; they must not present an external harness as equivalent to the native Core loop.

- **Code:** `crates/bastion-agent-runtime/src/lib.rs`, `crates/bastion-agent-runtime/src/codex.rs`, and `crates/bastion-agent-runtime/src/acpx.rs`
- **Evidence:** adapter unit tests, conformance helpers, and the explicitly ignored live suites documented in [SUPPORT-MATRIX.md](SUPPORT-MATRIX.md).

## 8. Business state remains host-owned

Core persists agent sessions, approvals, and governed memory. It does not provide a generic store for a consuming application's orders, tickets, ledgers, or other authoritative business records.

- **Reference compositions:** `examples/embedded-host/` and `examples/embedded-host-slice/`

The host may inject a neutral reference or summary as context, but commits domain changes in its own system of record.

## Scope of this document

Channel authentication, HTTP authorization, daemon serialization, Docker isolation, and sender-to-owner mapping belong to the embedding product. The `bastion-agent` security documentation is authoritative for those product-level guarantees.
