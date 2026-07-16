//! `BackendProfile` / `ConversationBackend` / `RuntimeRegistry` — Ciclo 2.4
//! (`docs/SUPPORT-MATRIX.md`).
//!
//! Kernel-side routing policy: decides, per owner/session, whether a turn is
//! served by Bastion's own tool-loop (`ConversationBackend::Model`, today's
//! only path) or by an external harness through the Trilha A
//! [`bastion_agent_runtime::AgentRuntime`] contract
//! (`ConversationBackend::Runtime(id)`). This is routing policy, not product
//! opinion — no concrete harness is named here, only the abstract trait
//! object the composition root (`main.rs`) populates the registry with.
//!
//! Default (`BackendProfile::default()` + `RuntimeRegistry::default()`) is
//! `Model` + an empty registry — byte-identical to pre-Ciclo-2.4 behavior.
//! Nothing in this module changes what an unconfigured deployment does.

use std::collections::HashMap;
use std::sync::Arc;

use bastion_agent_runtime::{AgentRuntime, AuthProfileRef, PolicyCoverage};

/// Which path serves a turn's conversation (design doc §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationBackend {
    /// Bastion's own tool-loop — inference only, today's only path.
    Model,
    /// An external harness owns the turn's tool-loop. Carries the id of the
    /// [`AgentRuntime`] registered in the [`RuntimeRegistry`] this turn
    /// resolves against (e.g. `"codex_app_server"`, `"acpx_claude"`).
    Runtime(String),
}

impl Default for ConversationBackend {
    /// Model — preserves 100% of pre-Ciclo-2.4 behavior for any owner/session
    /// that never opted into a `[backend]` config section.
    fn default() -> Self {
        ConversationBackend::Model
    }
}

/// Per-owner/session backend selection (design doc §2). Orthogonal fields:
/// `task_runtime` (A-07 delegation) is independent of `conversation` — a
/// `Model`-conversation owner can still delegate tasks to a runtime, and a
/// `Runtime`-conversation owner isn't forced to also delegate.
#[derive(Debug, Clone, Default)]
pub struct BackendProfile {
    pub conversation: ConversationBackend,
    /// Runtime id for delegated tasks (A-07). `None` = delegation disabled.
    pub task_runtime: Option<String>,
    /// Credential/entitlement reference threaded to the adapter, orthogonal
    /// to backend choice (A-01 §1.1).
    pub auth: Option<AuthProfileRef>,
    /// Policy-coverage declaration of the chosen runtime, propagated from its
    /// `RuntimeDescriptor` for the product to display — never a new decision,
    /// just a pass-through of what `descriptor().policy_coverage` already
    /// says. `None` when the conversation backend is `Model` (no coverage
    /// question applies) or before the composition root resolved the id.
    pub coverage_note: Option<PolicyCoverage>,
}

/// Fail-closed failure resolving a [`ConversationBackend::Runtime`] id (or a
/// `task_runtime` id) against the [`RuntimeRegistry`] at the start of a turn
/// (design doc §5.6 / acceptance criterion 6): an unregistered or unhealthy
/// id is ALWAYS a typed error here, never a silent fall-through to `Model` —
/// that would hide a real loss of policy coverage from the owner.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum BackendResolutionError {
    #[error("no AgentRuntime registered for backend id '{0}'")]
    UnknownRuntime(String),
    #[error("AgentRuntime '{0}' is registered but unhealthy: {1}")]
    Unhealthy(String, String),
}

/// Registry of available [`AgentRuntime`] adapters, keyed by
/// `RuntimeDescriptor::id`. Populated once at composition time (`main.rs`)
/// with only the adapters that passed `health()`/auth at startup —
/// conditional registration, never an unhealthy adapter sitting in the map
/// (design doc §2). Cheap to clone (`Arc` map).
#[derive(Clone, Default)]
pub struct RuntimeRegistry {
    runtimes: HashMap<String, Arc<dyn AgentRuntime>>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one adapter under its own declared `descriptor().id`.
    pub fn register(&mut self, runtime: Arc<dyn AgentRuntime>) {
        let id = runtime.descriptor().id.to_string();
        self.runtimes.insert(id, runtime);
    }

    pub fn is_empty(&self) -> bool {
        self.runtimes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.runtimes.len()
    }

    /// Registered-and-unfiltered lookup (no health re-probe) — used where the
    /// caller already knows it wants the raw handle (e.g. reading
    /// `descriptor()` for a `coverage_note` at composition time).
    pub fn get(&self, id: &str) -> Option<Arc<dyn AgentRuntime>> {
        self.runtimes.get(id).cloned()
    }

    /// M4-07: every registered runtime's own `descriptor()` — the
    /// enumeration a listing/selection UX needs (`AgentLoop`'s `/backends`
    /// cockpit command, the support-matrix generator). Registration order is
    /// not meaningful (backed by a `HashMap`); callers that need a stable
    /// order sort by `id` themselves.
    pub fn descriptors(&self) -> Vec<bastion_agent_runtime::RuntimeDescriptor> {
        self.runtimes.values().map(|rt| rt.descriptor()).collect()
    }

    /// Fail-closed resolution used at the START of a turn (design doc §5.6):
    /// re-probes `health()` so an adapter that died since registration is
    /// caught here rather than surfacing as an opaque failure mid-turn.
    /// Never falls back to `Model` — the caller decides what a resolution
    /// error means for the turn (typically: abort with a typed error).
    pub async fn resolve(&self, id: &str) -> Result<Arc<dyn AgentRuntime>, BackendResolutionError> {
        let runtime = self
            .runtimes
            .get(id)
            .cloned()
            .ok_or_else(|| BackendResolutionError::UnknownRuntime(id.to_string()))?;
        let health = runtime
            .health()
            .await
            .map_err(|e| BackendResolutionError::Unhealthy(id.to_string(), e.to_string()))?;
        if !health.ready {
            return Err(BackendResolutionError::Unhealthy(
                id.to_string(),
                health.detail.unwrap_or_default(),
            ));
        }
        Ok(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_agent_runtime::{RuntimeError, RuntimeHealth};

    /// Minimal fake — only what `RuntimeRegistry::resolve` touches
    /// (`descriptor().id` + `health()`). Not the full conformance
    /// `FakeRuntime` (that lives in `bastion-agent-runtime`, a lower crate
    /// this one already depends on, but its test-only fake isn't exported).
    struct FakeAdapter {
        id: &'static str,
        ready: bool,
    }

    #[async_trait::async_trait]
    impl AgentRuntime for FakeAdapter {
        fn descriptor(&self) -> bastion_agent_runtime::RuntimeDescriptor {
            bastion_agent_runtime::RuntimeDescriptor {
                id: self.id,
                adapter_version: "0.0.0".to_string(),
                target_version: "test".to_string(),
                transport: bastion_agent_runtime::Transport::Embedded,
                supports: bastion_agent_runtime::RuntimeSupports::default(),
                policy_coverage: bastion_agent_runtime::PolicyCoverage {
                    tool_visibility: bastion_agent_runtime::ToolVisibility::Full,
                    approvals: bastion_agent_runtime::ApprovalCoverage::Bridged,
                    egress: bastion_agent_runtime::EgressCoverage::InputFiltered,
                    budget: bastion_agent_runtime::BudgetCoverage::Reported,
                    sandbox: bastion_agent_runtime::SandboxCoverage::Honored,
                },
            }
        }

        async fn health(&self) -> Result<RuntimeHealth, RuntimeError> {
            Ok(RuntimeHealth {
                detected_version: "0.0.0".to_string(),
                ready: self.ready,
                detail: if self.ready {
                    None
                } else {
                    Some("fake unhealthy".to_string())
                },
            })
        }

        async fn start(
            &self,
            _spec: bastion_agent_runtime::SessionSpec,
        ) -> Result<Box<dyn bastion_agent_runtime::RuntimeSession>, RuntimeError> {
            Err(RuntimeError::Unavailable(
                "fake: start unimplemented".to_string(),
            ))
        }

        async fn resume(
            &self,
            _handle: &bastion_agent_runtime::SessionHandle,
            _spec: bastion_agent_runtime::ResumeSpec,
        ) -> Result<Box<dyn bastion_agent_runtime::RuntimeSession>, RuntimeError> {
            Err(RuntimeError::NotResumable(
                "fake: resume unimplemented".to_string(),
            ))
        }
    }

    #[test]
    fn default_backend_profile_is_model_with_no_task_runtime() {
        let profile = BackendProfile::default();
        assert_eq!(profile.conversation, ConversationBackend::Model);
        assert!(profile.task_runtime.is_none());
        assert!(profile.auth.is_none());
        assert!(profile.coverage_note.is_none());
    }

    #[test]
    fn empty_registry_is_default() {
        let registry = RuntimeRegistry::default();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn resolve_unknown_id_is_typed_error_never_silent_fallback() {
        let registry = RuntimeRegistry::new();
        // `.err()` (not `.unwrap_err()`): the Ok side is `Arc<dyn AgentRuntime>`,
        // which is deliberately NOT `Debug` (a trait object over an adapter
        // that may hold live subprocess handles) — `unwrap_err()`'s bound
        // (`T: Debug`) doesn't apply to `Option::expect`.
        let err = registry
            .resolve("does_not_exist")
            .await
            .err()
            .expect("must be Err");
        assert!(
            matches!(err, BackendResolutionError::UnknownRuntime(id) if id == "does_not_exist")
        );
    }

    #[tokio::test]
    async fn resolve_registered_unhealthy_runtime_is_typed_error() {
        let mut registry = RuntimeRegistry::new();
        registry.register(Arc::new(FakeAdapter {
            id: "fake_unhealthy",
            ready: false,
        }));
        let err = registry
            .resolve("fake_unhealthy")
            .await
            .err()
            .expect("must be Err");
        assert!(matches!(err, BackendResolutionError::Unhealthy(id, _) if id == "fake_unhealthy"));
    }

    #[tokio::test]
    async fn resolve_registered_healthy_runtime_succeeds() {
        let mut registry = RuntimeRegistry::new();
        registry.register(Arc::new(FakeAdapter {
            id: "fake_healthy",
            ready: true,
        }));
        let runtime = registry
            .resolve("fake_healthy")
            .await
            .expect("must resolve");
        assert_eq!(runtime.descriptor().id, "fake_healthy");
    }

    #[test]
    fn registry_get_does_not_health_probe() {
        let mut registry = RuntimeRegistry::new();
        registry.register(Arc::new(FakeAdapter {
            id: "fake_unhealthy",
            ready: false,
        }));
        // get() is a raw lookup (used at composition time to read the
        // descriptor for a coverage_note) — it must NOT filter on health.
        assert!(registry.get("fake_unhealthy").is_some());
        assert!(registry.get("missing").is_none());
    }
}
