//! Components 3 and 4 (`docs/revamp/C3-m5-second-consumer-design.md`
//! §"Componentes"): a dynamic, OBJECT-SCOPED capability registered through
//! the public `CapabilityRegistry` API, denied by the host's OWN
//! authorization policy — a different flavor of "own rule" than
//! `examples/embedded-host`'s numeric `ThresholdDenyGate` (that one reads a
//! bare `args.amount`; this one reads the host's own object-status
//! vocabulary), proving the `ApprovalGate` port generalizes beyond a single
//! shape of policy.

use async_trait::async_trait;
use bastion_runtime::capability::{Capability, InvokeCtx};
use bastion_types::{ApprovalOutcome, ApprovalRow, DenyScope};

/// An irreversible, host-defined action SCOPED TO ONE OBJECT — its `name()`
/// bakes the object id in (`approve_object:<id>`), so two different objects
/// are two different capabilities, never a single generic action that takes
/// an object id as a loose argument. `needs_approval() -> true` is a TYPED
/// property of the capability itself (never a caller-supplied flag —
/// `docs/SECURITY-INVARIANTS.md` invariant #4), decided here by whoever
/// wrote this capability.
pub struct ApproveObjectCapability {
    object_id: String,
    name: String,
    schema: serde_json::Value,
}

impl ApproveObjectCapability {
    pub fn new(object_id: impl Into<String>) -> Self {
        let object_id = object_id.into();
        Self {
            name: Self::capability_name(&object_id),
            object_id,
            schema: serde_json::json!({
                "type": "object",
                "properties": { "object_status": { "type": "string" } },
                "required": ["object_status"]
            }),
        }
    }

    /// The object-scoped capability name a caller invokes through the SAME
    /// public `CapabilityRegistry::invoke` every kernel-internal capability
    /// uses — no forked dispatch path.
    pub fn capability_name(object_id: &str) -> String {
        format!("approve_object:{object_id}")
    }
}

#[async_trait]
impl Capability for ApproveObjectCapability {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Host-defined, object-scoped irreversible action (embedded-host-slice example)"
    }

    fn input_schema(&self) -> &serde_json::Value {
        &self.schema
    }

    fn needs_approval(&self) -> bool {
        true
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        _ctx: &InvokeCtx,
    ) -> anyhow::Result<serde_json::Value> {
        // Never reached in this example — `ObjectPolicyDenyGate` (below)
        // denies every `object_status` this demo exercises before dispatch.
        Ok(serde_json::json!({"approved_object": self.object_id, "args": args}))
    }
}

/// The host's OWN authorization policy (Ciclo 2.1,
/// `docs/revamp/C2-approval-port-design.md` §1) — a minimal, synchronous
/// `ApprovalGate` implementation, no SQLite at all. Denies any capability
/// whose `args.object_status` is not the one status this host considers
/// "cleared" — a business-rule shape distinct from `ThresholdDenyGate`'s
/// numeric threshold in `examples/embedded-host`.
///
/// Like `ThresholdDenyGate`, the non-`enqueue_or_reuse` methods are
/// unreachable from `CapabilityRegistry::invoke`'s Policy 2 for a capability
/// this gate always resolves synchronously (no row is ever queued, approved,
/// or replayed) — they fail loudly rather than silently no-opping if that
/// assumption ever changes.
pub struct ObjectPolicyDenyGate {
    /// The single `object_status` value this host considers cleared for
    /// action. Anything else — including a missing field — is denied.
    pub cleared_status: &'static str,
}

#[async_trait]
impl bastion_runtime::agent::ports::ApprovalGate for ObjectPolicyDenyGate {
    async fn enqueue_or_reuse(
        &self,
        _owner_id: &str,
        capability_name: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<ApprovalOutcome> {
        let status = args.get("object_status").and_then(|v| v.as_str());
        if status != Some(self.cleared_status) {
            // Ciclo 2.1 §3: `DenyScope::Turn` — the product default. A host
            // that wants "deny just this one" instead would return
            // `DenyScope::Instance`.
            return Ok(ApprovalOutcome::Rejected(DenyScope::Turn));
        }
        anyhow::bail!(
            "ObjectPolicyDenyGate only demonstrates denial in this example — \
             capability '{capability_name}' with object_status=\"{}\" has no defined behavior",
            self.cleared_status
        );
    }

    async fn pending_for_owner(&self, _owner_id: &str) -> anyhow::Result<Vec<ApprovalRow>> {
        Ok(Vec::new())
    }

    async fn approve(&self, _owner_id: &str, id: i64) -> anyhow::Result<ApprovalRow> {
        anyhow::bail!("ObjectPolicyDenyGate resolves synchronously — no queued row {id} to approve")
    }

    async fn reject(&self, _owner_id: &str, id: i64) -> anyhow::Result<()> {
        anyhow::bail!("ObjectPolicyDenyGate resolves synchronously — no queued row {id} to reject")
    }

    async fn record_executed(&self, id: i64, _result: &serde_json::Value) -> anyhow::Result<()> {
        anyhow::bail!(
            "ObjectPolicyDenyGate resolves synchronously — no queued row {id} to record executed"
        )
    }
}
