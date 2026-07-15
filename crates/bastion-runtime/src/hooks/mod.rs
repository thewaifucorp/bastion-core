//! Hook and Observer traits for intercepting and observing provider calls.
//!
//! This module defines the TRAIT layer (HOOK-01, HOOK-04) plus the plan-04
//! concrete implementations:
//! - [`egress`]: fail-closed privacy egress check (PRIV-03, D-03, CF-1)
//! - [`guardrails`]: input guardrail — malformed/oversized input (HOOK-02)
//! - [`output_validator`]: NL contestation detection → belief revocation (HOOK-03, D-13)
//! - [`observer`]: life-log Observer (HOOK-05)
//! - [`approval_intent`]: NL approval/rejection phrase detection (SEC-01, D-02, Plan 11-04)
//!
//! AgentLoop wiring of these hooks is plan 08.

pub mod approval_intent;
pub mod egress;
pub mod guardrails;
pub mod observer;
pub mod output_validator;

/// Intercepts provider calls before and after execution.
///
/// The `before_provider` method is the chokepoint for egress control and guardrails;
/// concrete enforcement (checking tier vs provider_name) is added in plan 04.
/// The `after_provider` method may rewrite or flag model output.
#[async_trait::async_trait]
pub trait Hook: Send + Sync {
    /// Called before a provider call. May return an error to abort the call (fail-closed).
    ///
    /// `tier` is the privacy tier of the context being sent; plan 04 uses it to
    /// block local-only data from non-Ollama providers (BastionError::PrivacyEgressBlocked).
    async fn before_provider(
        &self,
        system: &str,
        user: &str,
        provider_name: &str,
        tier: crate::memory::PrivacyTier,
    ) -> anyhow::Result<()> {
        let _ = (system, user, provider_name, tier);
        Ok(())
    }

    /// Called after a provider call. Returning `Some(new_output)` replaces the model output.
    async fn after_provider(&self, output: &str) -> anyhow::Result<Option<String>> {
        let _ = output;
        Ok(None)
    }
}

/// Passively records provider events for audit/life-log purposes (HOOK-04/05).
///
/// Unlike `Hook`, `Observer` is fire-and-forget — errors are silently dropped
/// so a logging failure never aborts a provider call.
#[async_trait::async_trait]
pub trait Observer: Send + Sync {
    /// Record an event with optional structured metadata.
    async fn record(&self, event: &str, metadata: serde_json::Value);
}

/// No-op observer — discards all events. Used as the default in AgentLoop.
pub struct NoObserver;

#[async_trait::async_trait]
impl Observer for NoObserver {
    async fn record(&self, _event: &str, _metadata: serde_json::Value) {}
}
