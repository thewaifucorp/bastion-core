//! Verification composition (US-104): deterministic checks before any LLM
//! judge.
//!
//! [`Verdict`] provenance and the four-way [`VerificationStatus`] live in the
//! contract (US-101); the [`super::ports::Verifier`] port is where a host
//! plugs judgement in (US-103). This module adds the one composition the plan
//! mandates: try cheap, deterministic verifiers (exit status, schema,
//! receipt) first and only fall through to an expensive LLM judge when the
//! result cannot be decided deterministically.

use std::sync::Arc;

use async_trait::async_trait;

use super::ports::Verifier;
use super::{AttemptId, Evidence, TaskCase, Verdict, VerdictProvenance, VerificationStatus};

/// Runs a list of verifiers in priority order and returns the first one that
/// reaches a decision (any status other than
/// [`VerificationStatus::Unverified`]). Order deterministic-first,
/// LLM-judge-last so the costly layer only runs when the cheap ones abstain.
///
/// If every layer abstains, the aggregate verdict is `Unverified` — the
/// composition never fabricates a success, honouring "no `succeeded` without
/// evidence" (US-104).
pub struct LayeredVerifier {
    layers: Vec<Arc<dyn Verifier>>,
}

impl LayeredVerifier {
    /// Build a layered verifier. Put deterministic verifiers before any LLM
    /// judge — evaluation stops at the first layer that decides.
    pub fn new(layers: Vec<Arc<dyn Verifier>>) -> Self {
        Self { layers }
    }
}

#[async_trait]
impl Verifier for LayeredVerifier {
    async fn verify(
        &self,
        case: &TaskCase,
        attempt: &AttemptId,
        evidence: &[Evidence],
    ) -> anyhow::Result<Verdict> {
        let mut abstained = Verdict {
            attempt: attempt.clone(),
            status: VerificationStatus::Unverified,
            provenance: VerdictProvenance::Deterministic,
            evidence: Vec::new(),
            detail: Some("no verifier reached a decision".to_string()),
        };
        for layer in &self.layers {
            let verdict = layer.verify(case, attempt, evidence).await?;
            if verdict.status != VerificationStatus::Unverified {
                return Ok(verdict);
            }
            abstained = verdict;
        }
        Ok(abstained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{TaskCase, VerdictProvenance};

    struct FixedLayer(VerificationStatus, VerdictProvenance);
    #[async_trait]
    impl Verifier for FixedLayer {
        async fn verify(
            &self,
            _case: &TaskCase,
            attempt: &AttemptId,
            _evidence: &[Evidence],
        ) -> anyhow::Result<Verdict> {
            Ok(Verdict {
                attempt: attempt.clone(),
                status: self.0,
                provenance: self.1.clone(),
                evidence: vec![],
                detail: None,
            })
        }
    }

    fn dummy_case() -> TaskCase {
        use crate::task::{
            Bounds, CorrelationIds, ExecutionMode, Frame, Intent, IntentOrigin, OpaqueState,
            TaskCaseId, TaskStatus, UsageAccum,
        };
        TaskCase {
            id: TaskCaseId("t".into()),
            owner: "o".into(),
            mode: ExecutionMode::Act,
            intent: Intent {
                owner: "o".into(),
                mode: ExecutionMode::Act,
                summary: String::new(),
                origin: IntentOrigin::Message,
            },
            frame: Frame {
                objective: String::new(),
                acceptance: vec![],
                context_refs: vec![],
            },
            bounds: Bounds::default(),
            status: TaskStatus::Running,
            stop_reason: None,
            attempts: vec![],
            pending_approvals: vec![],
            next_decision: None,
            usage: UsageAccum::default(),
            parent: None,
            correlation: CorrelationIds::default(),
            business_state: OpaqueState::default(),
            created_at: 0,
            updated_at: 0,
            revision: 1,
        }
    }

    #[tokio::test]
    async fn first_deciding_layer_short_circuits() {
        let v = LayeredVerifier::new(vec![
            // deterministic layer abstains...
            Arc::new(FixedLayer(
                VerificationStatus::Unverified,
                VerdictProvenance::Deterministic,
            )),
            // ...LLM judge decides.
            Arc::new(FixedLayer(
                VerificationStatus::Succeeded,
                VerdictProvenance::LlmJudge {
                    model: "m".into(),
                },
            )),
            // never reached
            Arc::new(FixedLayer(
                VerificationStatus::Failed,
                VerdictProvenance::Deterministic,
            )),
        ]);
        let verdict = v
            .verify(&dummy_case(), &AttemptId("a".into()), &[])
            .await
            .unwrap();
        assert_eq!(verdict.status, VerificationStatus::Succeeded);
        assert!(matches!(verdict.provenance, VerdictProvenance::LlmJudge { .. }));
    }

    #[tokio::test]
    async fn all_abstaining_stays_unverified() {
        let v = LayeredVerifier::new(vec![Arc::new(FixedLayer(
            VerificationStatus::Unverified,
            VerdictProvenance::Deterministic,
        ))]);
        let verdict = v
            .verify(&dummy_case(), &AttemptId("a".into()), &[])
            .await
            .unwrap();
        assert_eq!(verdict.status, VerificationStatus::Unverified);
    }

    #[tokio::test]
    async fn deterministic_layer_wins_before_llm() {
        let v = LayeredVerifier::new(vec![
            Arc::new(FixedLayer(
                VerificationStatus::Failed,
                VerdictProvenance::Deterministic,
            )),
            Arc::new(FixedLayer(
                VerificationStatus::Succeeded,
                VerdictProvenance::LlmJudge {
                    model: "m".into(),
                },
            )),
        ]);
        let verdict = v
            .verify(&dummy_case(), &AttemptId("a".into()), &[])
            .await
            .unwrap();
        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(matches!(verdict.provenance, VerdictProvenance::Deterministic));
    }
}
