//! Ephemeral, pure-echo `Capability` used to route forced-tool-call structured
//! output through `CapabilityRegistry::invoke` (D-02, Plan 08-03).
//!
//! When a provider can be forced to call a single named tool but has no native
//! `json_schema`/`response_format` mechanism, `complete_structured_via_forced_tool_call`
//! (in `src/provider/mod.rs`) registers one of these under a sentinel name, forces
//! the model to call it, and dispatches the resulting arguments through the SAME
//! `CapabilityRegistry::invoke` single-policy-boundary every real tool call uses —
//! never a parallel dispatch path.

use crate::capability::registry::{Capability, InvokeCtx};
use async_trait::async_trait;
use serde_json::Value;

/// Fixed description surfaced to the provider as the forced tool's `description`.
const DESCRIPTION: &str =
    "Emit the structured response matching the required JSON schema — internal, no side effects";

/// A one-shot, side-effect-free `Capability` whose `invoke()` echoes its input
/// verbatim. Exists only to give the forced-tool-call mechanism a real capability
/// to register/invoke through the registry — there is no work to perform because
/// the LLM's tool-call arguments themselves ARE the structured-output payload.
pub struct StructuredOutputCapability {
    name: String,
    description: String,
    schema: Value,
}

impl StructuredOutputCapability {
    pub fn new(name: impl Into<String>, schema: Value) -> Self {
        Self {
            name: name.into(),
            description: DESCRIPTION.to_owned(),
            schema,
        }
    }
}

#[async_trait]
impl Capability for StructuredOutputCapability {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn input_schema(&self) -> &Value {
        &self.schema
    }

    /// SECURITY (D-13 guardrail 3): locality is a typed property of the adapter,
    /// never a name-string. This capability is local by construction — it is a
    /// pure in-process identity echo (`invoke()` below), no data ever leaves the
    /// host — so it always passes `check_egress` regardless of the caller's
    /// privacy tier, exactly like `NlCommandAdapter`. A forged `cmd:`-prefixed
    /// name could never acquire this: locality here comes from the impl itself,
    /// not from how the capability happens to be named.
    fn is_local(&self) -> bool {
        true
    }

    async fn invoke(&self, args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
        // The LLM's forced-tool-call arguments ARE the structured-output payload —
        // there is nothing to execute, just echo them back through the registry.
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> InvokeCtx {
        InvokeCtx {
            owner: "test-owner".into(),
            privacy_tier: None,
        }
    }

    #[test]
    fn new_stores_name_schema_and_is_local() {
        let schema = serde_json::json!({"type": "object"});
        let cap = StructuredOutputCapability::new("x", schema.clone());

        assert_eq!(cap.name(), "x");
        assert_eq!(cap.input_schema(), &schema);
        assert!(cap.is_local());
    }

    #[tokio::test]
    async fn invoke_echoes_args_verbatim() {
        let cap = StructuredOutputCapability::new("x", serde_json::json!({}));
        let args = serde_json::json!({"a": 1});

        let result = cap.invoke(args.clone(), &ctx()).await.unwrap();

        assert_eq!(result, args);
    }
}
