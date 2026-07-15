use crate::memory::{BeliefDraft, Outcome, PrivacyTier, SharedMemory};

/// ACE-style delta-op against procedural beliefs. Every Reflector output is exactly
/// ONE of these — never a full-set rewrite (RESEARCH Anti-Pattern "context collapse").
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DeltaOp {
    Add {
        issue: Option<String>,
        insight: String,
        keywords: Vec<String>,
        tier: Option<PrivacyTier>,
    },
    Update {
        supersedes: i64,
        issue: Option<String>,
        insight: String,
        keywords: Vec<String>,
    },
    Tag {
        belief_id: i64,
        outcome: Outcome,
    },
    Remove {
        belief_id: i64,
    },
}

impl DeltaOp {
    /// Apply this delta to `memory` for `owner`. Returns the new belief id for
    /// Add/Update (None for Tag/Remove). MUST NOT be called until the caller has
    /// gated this candidate through `eval::verifier::verify_delta` (EVAL-02).
    ///
    /// Lock discipline: `revoke_belief`/`record_belief_outcome` take `memory.write()`;
    /// `store_procedural_belief` only needs `memory.read()` (matches the existing
    /// `store_belief` call pattern elsewhere in the crate) — the `RwLock` here only
    /// guards the `Box<dyn Memory>` swap, not the SQLite connection (SqliteMemory
    /// does its own internal locking via `spawn_blocking`).
    pub async fn apply(&self, memory: &SharedMemory, owner: &str) -> anyhow::Result<Option<i64>> {
        match self {
            DeltaOp::Add {
                issue,
                insight,
                keywords,
                tier,
            } => {
                let mem = memory.read().await;
                let id = mem
                    .store_procedural_belief(BeliefDraft {
                        owner_id: owner.to_owned(),
                        persona_tag: None,
                        issue: issue.clone(),
                        insight: insight.clone(),
                        keywords: keywords.clone(),
                        session_id: "reflector".to_owned(),
                        source: "reflector".to_owned(),
                        tier: *tier,
                    })
                    .await?;
                Ok(Some(id))
            }
            DeltaOp::Update {
                supersedes,
                issue,
                insight,
                keywords,
            } => {
                // Revoke FIRST — if this errors (e.g. `supersedes` belongs to another
                // owner), bail out here and NEVER store the new belief (no orphan).
                {
                    let mem = memory.write().await;
                    mem.revoke_belief(owner, *supersedes).await?;
                }
                let mem = memory.read().await;
                let id = mem
                    .store_procedural_belief(BeliefDraft {
                        owner_id: owner.to_owned(),
                        persona_tag: None,
                        issue: issue.clone(),
                        insight: insight.clone(),
                        keywords: keywords.clone(),
                        session_id: "reflector".to_owned(),
                        source: "reflector".to_owned(),
                        tier: None,
                    })
                    .await?;
                Ok(Some(id))
            }
            DeltaOp::Tag { belief_id, outcome } => {
                let mem = memory.write().await;
                mem.record_belief_outcome(owner, *belief_id, *outcome)
                    .await?;
                Ok(None)
            }
            DeltaOp::Remove { belief_id } => {
                let mem = memory.write().await;
                mem.revoke_belief(owner, *belief_id).await?;
                Ok(None)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (offline — temp-DB SqliteMemory, pattern from agent/memory_rag.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::{BeliefKind, Memory};
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    async fn make_memory() -> (NamedTempFile, SharedMemory) {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_str().unwrap().to_owned();
        let session = crate::session::sqlite::SessionManager::new(&path);
        session.init_schema().await.expect("init_schema");
        let mem: SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&path)) as Box<dyn Memory>
        ));
        (f, mem)
    }

    async fn seed(mem: &SharedMemory, owner: &str, insight: &str) -> i64 {
        let m = mem.read().await;
        m.store_procedural_belief(BeliefDraft {
            owner_id: owner.to_owned(),
            persona_tag: None,
            issue: None,
            insight: insight.to_owned(),
            keywords: vec![],
            session_id: "s".into(),
            source: "test".into(),
            tier: None,
        })
        .await
        .expect("seed")
    }

    #[tokio::test]
    async fn add_stores_exactly_one_procedural_belief() {
        let (_f, mem) = make_memory().await;
        let op = DeltaOp::Add {
            issue: Some("timeouts".into()),
            insight: "retry with backoff".into(),
            keywords: vec!["retry".into()],
            tier: None,
        };
        let id = op.apply(&mem, "owner1").await.expect("apply").expect("id");
        let m = mem.read().await;
        let beliefs = m.retrieve_tagged("owner1", None).await.expect("retrieve");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].id, id);
        assert_eq!(beliefs[0].kind, BeliefKind::Procedural);
        assert_eq!(beliefs[0].content, "retry with backoff");
    }

    #[tokio::test]
    async fn update_revokes_old_then_stores_new_never_mutates_in_place() {
        let (_f, mem) = make_memory().await;
        let old_id = seed(&mem, "owner1", "old insight").await;

        let op = DeltaOp::Update {
            supersedes: old_id,
            issue: None,
            insight: "new insight".into(),
            keywords: vec![],
        };
        let new_id = op.apply(&mem, "owner1").await.expect("apply").expect("id");
        assert_ne!(
            new_id, old_id,
            "Update must mint a NEW belief id, never reuse the old one"
        );

        let m = mem.read().await;
        let beliefs = m.retrieve_tagged("owner1", None).await.expect("retrieve");
        assert_eq!(
            beliefs.len(),
            1,
            "old belief must be revoked (excluded from retrieve_tagged), only the new one remains"
        );
        assert_eq!(beliefs[0].id, new_id);
        assert_eq!(beliefs[0].content, "new insight");
    }

    #[tokio::test]
    async fn update_does_not_orphan_new_belief_when_revoke_fails() {
        let (_f, mem) = make_memory().await;
        // Belief owned by a DIFFERENT owner — revoke_belief("owner1", ...) must Err (IDOR guard).
        let victim_id = seed(&mem, "owner2", "owner2's insight").await;

        let op = DeltaOp::Update {
            supersedes: victim_id,
            issue: None,
            insight: "attempted takeover".into(),
            keywords: vec![],
        };
        let result = op.apply(&mem, "owner1").await;
        assert!(result.is_err(), "cross-owner supersede must error");

        let m = mem.read().await;
        let owner1_beliefs = m.retrieve_tagged("owner1", None).await.expect("retrieve");
        assert!(
            owner1_beliefs.is_empty(),
            "no orphan belief may be created when the supersede revoke fails"
        );
    }

    #[tokio::test]
    async fn tag_increments_counter_without_touching_content() {
        let (_f, mem) = make_memory().await;
        let id = seed(&mem, "owner1", "some insight").await;

        let op = DeltaOp::Tag {
            belief_id: id,
            outcome: Outcome::Helpful,
        };
        let result = op.apply(&mem, "owner1").await.expect("apply");
        assert!(result.is_none());

        let m = mem.read().await;
        let beliefs = m.retrieve_tagged("owner1", None).await.expect("retrieve");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].content, "some insight");
        assert_eq!(beliefs[0].helpful_count, 1);
    }

    #[tokio::test]
    async fn remove_revokes_belief() {
        let (_f, mem) = make_memory().await;
        let id = seed(&mem, "owner1", "to remove").await;

        let op = DeltaOp::Remove { belief_id: id };
        let result = op.apply(&mem, "owner1").await.expect("apply");
        assert!(result.is_none());

        let m = mem.read().await;
        let beliefs = m.retrieve_tagged("owner1", None).await.expect("retrieve");
        assert!(beliefs.is_empty());
    }
}
