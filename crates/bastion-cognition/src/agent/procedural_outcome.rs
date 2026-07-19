//! US-105 — exact outcome attribution for procedural beliefs.
//!
//! Recall (`procedural.rs`) surfaces beliefs; this closes the loop by feeding
//! a terminal task verdict back onto *exactly the beliefs a decision used*,
//! so experience compounds without reinforcing coincidence:
//!
//! - Only the belief ids the chooser recorded on its action/attempt are
//!   touched — never every recalled belief.
//! - A failed attempt reinforces negatively; an unverified one reinforces
//!   nothing at all (no proof, no signal — Gate C).
//! - Factual beliefs never receive a procedural outcome (kind guard).
//! - Cross-owner writes are impossible: every mutation goes through the
//!   memory layer's owner-scoped IDOR guard.
//!
//! Idempotency comes from the caller, not a parallel ledger: a `TaskCase`
//! emits exactly one terminal event (the store rejects a second terminal
//! transition, US-102), so the host applies attribution once, at that single
//! terminal point.
//!
//! Utility vs relevance vs confidence stay separate: relevance is the ephemeral
//! lexical match computed at recall; [`bastion_types::Belief::utility`] and
//! [`bastion_types::Belief::confidence`] are derived from the outcome counters
//! this module maintains; and the recall ranking multiplies weight by them so
//! outcome history measurably shifts future selection.

use bastion_runtime::task::VerificationStatus;

use crate::memory::{BeliefKind, Outcome, SharedMemory};

/// Weight nudge applied to a used procedural belief per helpful/harmful
/// outcome (the reinforcement layer caps and floors the trail).
const REINFORCE_DELTA: f64 = 0.1;

/// Map a terminal verification status to the outcome to attribute. An
/// `Unverified` result yields `None`: without proof there is no signal, so
/// nothing is reinforced (positively or negatively).
pub fn outcome_for(status: VerificationStatus) -> Option<Outcome> {
    match status {
        VerificationStatus::Succeeded => Some(Outcome::Helpful),
        VerificationStatus::Failed => Some(Outcome::Harmful),
        VerificationStatus::Partial => Some(Outcome::Neutral),
        VerificationStatus::Unverified => None,
    }
}

/// Applies terminal-verdict outcomes to the procedural beliefs a decision
/// actually used.
pub struct ProceduralLearner {
    memory: SharedMemory,
}

impl ProceduralLearner {
    pub fn new(memory: SharedMemory) -> Self {
        Self { memory }
    }

    /// Attribute `status` to exactly `used_belief_ids`, owner-scoped. Call
    /// once, when the task reaches its single terminal event.
    ///
    /// - Non-procedural beliefs among the ids are skipped.
    /// - Ids not owned by `owner` (or gone) are skipped silently.
    /// - `Unverified` attributes nothing.
    pub async fn attribute(
        &self,
        owner: &str,
        used_belief_ids: &[i64],
        status: VerificationStatus,
    ) -> anyhow::Result<()> {
        let Some(outcome) = outcome_for(status) else {
            return Ok(());
        };
        if used_belief_ids.is_empty() {
            return Ok(());
        }

        let mem = self.memory.read().await;
        // Owner-scoped fetch: a belief owned by someone else is simply not in
        // this set, so a forged id can never be attributed to.
        let owned = mem.retrieve_all_beliefs(owner).await?;

        for &id in used_belief_ids {
            let Some(belief) = owned.iter().find(|b| b.id == id) else {
                continue;
            };
            if belief.kind != BeliefKind::Procedural {
                // Factual beliefs never take a procedural score.
                continue;
            }
            mem.record_belief_outcome(owner, id, outcome).await?;
            let delta = match outcome {
                Outcome::Helpful => REINFORCE_DELTA,
                Outcome::Harmful => -REINFORCE_DELTA,
                Outcome::Neutral => 0.0,
            };
            if delta != 0.0 {
                mem.reinforce_belief(owner, id, delta).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::{BeliefDraft, Memory, PrivacyTier};
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    async fn make_memory(db_path: &str) -> SharedMemory {
        let session = crate::session::SessionManager::new(db_path);
        session.init_schema().await.expect("init_schema");
        Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(db_path)) as Box<dyn Memory>
        ))
    }

    async fn store_procedural(mem: &SharedMemory, owner: &str, content: &str) -> i64 {
        let m = mem.read().await;
        m.store_procedural_belief(BeliefDraft {
            owner_id: owner.to_string(),
            persona_tag: None,
            issue: None,
            insight: content.to_string(),
            keywords: vec![],
            session_id: "s".to_string(),
            source: "test".to_string(),
            tier: Some(PrivacyTier::CloudOk),
        })
        .await
        .expect("store")
    }

    async fn store_factual(mem: &SharedMemory, owner: &str, content: &str) -> i64 {
        let m = mem.read().await;
        m.store_belief(owner, None, content, "s", "test", false, Some(PrivacyTier::CloudOk))
            .await
            .expect("store_belief")
    }

    async fn counts(mem: &SharedMemory, owner: &str, id: i64) -> (i64, i64, i64) {
        let m = mem.read().await;
        let b = m
            .retrieve_all_beliefs(owner)
            .await
            .unwrap()
            .into_iter()
            .find(|b| b.id == id)
            .expect("belief");
        (b.helpful_count, b.harmful_count, b.neutral_count)
    }

    #[tokio::test]
    async fn success_marks_only_used_procedural_belief_helpful() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let used = store_procedural(&mem, "alice", "rebase before push").await;
        let unused = store_procedural(&mem, "alice", "squash before merge").await;

        let learner = ProceduralLearner::new(mem.clone());
        learner
            .attribute("alice", &[used], VerificationStatus::Succeeded)
            .await
            .expect("attribute");

        assert_eq!(counts(&mem, "alice", used).await, (1, 0, 0));
        assert_eq!(
            counts(&mem, "alice", unused).await,
            (0, 0, 0),
            "an unused belief must never be reinforced"
        );
    }

    #[tokio::test]
    async fn failure_reinforces_negatively_never_positively() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let id = store_procedural(&mem, "alice", "risky shortcut").await;
        let learner = ProceduralLearner::new(mem.clone());
        learner
            .attribute("alice", &[id], VerificationStatus::Failed)
            .await
            .expect("attribute");
        assert_eq!(counts(&mem, "alice", id).await, (0, 1, 0));
    }

    #[tokio::test]
    async fn unverified_attributes_nothing() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let id = store_procedural(&mem, "alice", "unproven step").await;
        let learner = ProceduralLearner::new(mem.clone());
        learner
            .attribute("alice", &[id], VerificationStatus::Unverified)
            .await
            .expect("attribute");
        assert_eq!(counts(&mem, "alice", id).await, (0, 0, 0));
    }

    #[tokio::test]
    async fn factual_belief_never_gets_a_procedural_score() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let factual = store_factual(&mem, "alice", "the sky is blue").await;
        let learner = ProceduralLearner::new(mem.clone());
        learner
            .attribute("alice", &[factual], VerificationStatus::Succeeded)
            .await
            .expect("attribute");
        assert_eq!(
            counts(&mem, "alice", factual).await,
            (0, 0, 0),
            "a factual belief must not take a procedural outcome"
        );
    }

    #[tokio::test]
    async fn cross_owner_ids_are_never_attributed() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let alices = store_procedural(&mem, "alice", "alice private strategy").await;
        let learner = ProceduralLearner::new(mem.clone());
        // Bob tries to attribute onto Alice's belief id.
        learner
            .attribute("bob", &[alices], VerificationStatus::Succeeded)
            .await
            .expect("attribute");
        assert_eq!(
            counts(&mem, "alice", alices).await,
            (0, 0, 0),
            "another owner must never move Alice's counters"
        );
    }

    #[test]
    fn utility_and_confidence_track_outcomes() {
        use bastion_types::Belief;
        let mut b = Belief {
            id: 1,
            owner_id: "o".into(),
            persona_tag: None,
            content: String::new(),
            weight: 1.0,
            is_core: false,
            tier: None,
            kind: BeliefKind::Procedural,
            keywords: vec![],
            issue: None,
            helpful_count: 0,
            harmful_count: 0,
            neutral_count: 0,
            valid_from: None,
            valid_until: None,
            superseded_by: None,
            supersedes_at: None,
        };
        assert_eq!(b.utility(), 0.0);
        assert_eq!(b.confidence(), 0.0);
        b.helpful_count = 9;
        assert!(b.utility() > 0.0, "helpful outcomes lift utility");
        assert!(b.confidence() > 0.5, "many observations lift confidence");
        b.harmful_count = 9;
        assert!(b.utility().abs() < 0.01, "balanced outcomes net to ~0 utility");
    }
}
