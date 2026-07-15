//! [`NullAuthResolver`] — default [`crate::agent::ports::AuthResolver`]
//! (M4-07, `docs/revamp/BACKLOG.md`).

use crate::agent::ports::AuthResolver;
use bastion_agent_runtime::{AuthProfileRef, RuntimeError};

/// `AgentLoop`'s default until `AgentLoop::with_auth_resolver` injects a real
/// one (`main.rs` wires the config-driven, app-level `AuthProfileRegistry`).
/// Always `Ok` — byte-identical to every pre-M4-07 deployment: before this
/// port existed, `SessionSpec::auth` was threaded straight to adapters that
/// never even read it, so no verification of any kind happened. This is NOT
/// a security control by itself — real access control is still whatever the
/// adapter's own transport enforces (host CLI login, API key, ...); this
/// resolver only adds an OPT-IN, fail-fast "is this reference even
/// configured to something valid" check on top, when a deployment opts in.
pub struct NullAuthResolver;

#[async_trait::async_trait]
impl AuthResolver for NullAuthResolver {
    async fn resolve(&self, _auth: &AuthProfileRef) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_auth_resolver_always_resolves() {
        let resolver = NullAuthResolver;
        assert!(resolver
            .resolve(&AuthProfileRef("anything".to_string()))
            .await
            .is_ok());
    }
}
