//! Public-neutral deployment vocabulary.
//!
//! The core intentionally names no host product or policy service. A product
//! composes an [`DeploymentContext`] at startup; the turn already carries its
//! canonical owner separately. `Managed` means an external control plane owns
//! policy and lifecycle decisions, not that the core knows who that is.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Who owns the deployment-level lifecycle and authority composition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// The product owns its local profile and lifecycle.
    #[default]
    Standalone,
    /// An external control plane owns policy and lifecycle decisions.
    Managed,
}

/// Immutable deployment metadata attached to every turn.
///
/// It contains identifiers only: secrets, policy bodies, and external-vendor
/// names never cross this neutral core boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentContext {
    #[serde(default)]
    pub mode: DeploymentMode,
    /// Stable worker/deployment identity when a control plane hosts this loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Effective external policy revision for observability and compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
}

impl DeploymentContext {
    pub fn managed(worker_id: impl Into<String>, policy_revision: impl Into<String>) -> Self {
        Self {
            mode: DeploymentMode::Managed,
            worker_id: Some(worker_id.into()),
            policy_revision: Some(policy_revision.into()),
        }
    }
}

/// Neutral decision vocabulary returned by an external or local policy port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDisposition {
    Allow,
    Block,
    Redact,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyDecision {
    pub disposition: PolicyDisposition,
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
}

/// Minimum owner-qualified description of a requested external effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EffectContext {
    pub owner: String,
    pub actor: String,
    pub deployment: DeploymentContext,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EffectAudit {
    pub effect: EffectContext,
    pub decision: PolicyDecision,
    pub outcome: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_standalone_without_public_vendor_name() {
        let context: DeploymentContext = serde_json::from_str("{}").unwrap();
        assert_eq!(context.mode, DeploymentMode::Standalone);
        assert_eq!(
            serde_json::to_string(&DeploymentMode::Managed).unwrap(),
            "\"managed\""
        );
    }

    #[test]
    fn managed_context_carries_only_identifiers() {
        assert_eq!(
            DeploymentContext::managed("worker-7", "rules-42"),
            DeploymentContext {
                mode: DeploymentMode::Managed,
                worker_id: Some("worker-7".into()),
                policy_revision: Some("rules-42".into()),
            }
        );
    }

    #[test]
    fn policy_and_effect_contracts_are_public_neutral() {
        let audit = EffectAudit {
            effect: EffectContext {
                owner: "alice".into(),
                actor: "worker-7".into(),
                deployment: DeploymentContext::managed("worker-7", "rules-42"),
                action: "calendar.create".into(),
                resource: Some("calendar:personal".into()),
            },
            decision: PolicyDecision {
                disposition: PolicyDisposition::Escalate,
                reason: "human approval required".into(),
                policy_revision: Some("rules-42".into()),
            },
            outcome: "pending".into(),
        };
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .to_lowercase()
            .contains("katsui"));
    }
}
