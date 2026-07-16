//! CronService: heartbeat + event + idle proactive message queue (PROACT-01 – PROACT-04).
//!
//! # Design (02-RESEARCH §Code Examples, Pitfall 3)
//! Uses `tokio::time::interval` with `MissedTickBehavior::Skip` — never `Runtime::new` or
//! `block_on` inside a callback (T-02-29 nested-runtime anti-pattern).
//!
//! # PROACT-05 guarantee
//! Messages are enqueued into `pending_tx`. The daemon's `select!` arm drains `pending_rx`
//! only BETWEEN turns (structural: select! processes one branch per iteration, and run_turn
//! fully awaits). This module does NOT enforce that — it only enqueues.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

use bastion_runtime::agent::loop_::PendingItem;

use crate::goal::GoalEngine;

/// Proactive message queue producer.
///
/// Multiple methods can send messages into `pending_tx`; the daemon selects from
/// `pending_rx` only between turns (PROACT-05 structural guarantee).
///
/// 6d (`docs/ARCHITECTURE.md`): every item is a
/// [`PendingItem`] tagged with the owner it is FOR — the daemon's consumer
/// routes by that identity instead of always assuming `DEFAULT_OWNER`.
pub struct CronService {
    pending_tx: mpsc::Sender<PendingItem>,
    goals: GoalEngine,
}

impl CronService {
    /// Create a new CronService bound to `pending_tx` and a `GoalEngine`.
    ///
    /// No background tasks are spawned here — callers decide when to activate each job.
    /// NO nested runtime (T-02-29): all methods are async and must be `.await`-ed.
    pub fn new(pending_tx: mpsc::Sender<PendingItem>, goals: GoalEngine) -> Self {
        Self { pending_tx, goals }
    }

    /// PROACT-01 / PROACT-02: heartbeat ticker.
    ///
    /// Ticks on `period` (recommended: 24h in production; short in tests).
    /// Uses `MissedTickBehavior::Skip` so a slow turn never causes a burst of ticks
    /// when the daemon was busy (Pitfall 3 from 02-RESEARCH).
    ///
    /// On each tick: fetches the first goal for `owner` and sends its drift nudge
    /// into `pending_tx` if `drift_nudge` returns `Some(text)` (GOAL-03).
    /// Silently skips if no goals exist or `drift_nudge` returns `None`.
    ///
    /// This method loops forever — callers must `tokio::spawn` it and cancel via
    /// task abortion when the daemon shuts down.
    pub async fn run_heartbeat(&self, period: Duration, owner: &str) {
        let mut iv = interval(period);
        iv.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            iv.tick().await;

            // List goals; silently skip on error
            let goals = match self.goals.list_goals(owner).await {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(event = "heartbeat_list_goals_error", error = %e);
                    continue;
                }
            };

            for goal in &goals {
                match self.goals.drift_nudge(owner, goal.id).await {
                    Ok(Some(text)) => {
                        if self
                            .pending_tx
                            .send(PendingItem::for_owner(owner, text))
                            .await
                            .is_err()
                        {
                            tracing::warn!(event = "heartbeat_pending_tx_closed");
                            return; // channel closed → daemon is shutting down
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(event = "heartbeat_drift_nudge_error", error = %e);
                    }
                }
            }
        }
    }

    /// PROACT-03: on-demand event trigger.
    ///
    /// Enqueues a proactive message for an external event (e.g. webhook/calendar payload),
    /// addressed to `owner` (6d: explicit — never delivered to a different owner's turn).
    /// Fire-and-forget: if `pending_tx` is closed the error is silently swallowed.
    pub async fn on_event(&self, owner: &str, event_text: String) {
        if self
            .pending_tx
            .send(PendingItem::for_owner(owner, event_text))
            .await
            .is_err()
        {
            tracing::warn!(event = "on_event_pending_tx_closed");
        }
    }

    /// PROACT-04: idle distillation trigger.
    ///
    /// When called after an idle period, runs `dream.extract_facts` on `recent` messages
    /// and persists each fact as a belief via `memory` (MEM-05). Then, in the SAME pass
    /// (D-12 — never a separate component), runs `dream.consolidate()` over the owner's
    /// currently-active beliefs and applies the resulting `ConsolidationPlan` via
    /// `Memory::supersede_belief`/`Memory::revoke_belief` (MEM-02). Consolidation runs
    /// unconditionally, even when `extract_facts` produced zero new facts — an idle tick
    /// with no new self-disclosures can still merge/prune the existing belief set.
    ///
    /// Optionally enqueues a follow-up nudge into `pending_tx` after storing beliefs.
    /// Errors at every step are logged and swallowed — idle failures must not abort the
    /// daemon; one bad supersession/prune pair must not block the rest.
    pub async fn idle_tick(
        &self,
        dream: &dyn crate::agent::dream::Dream,
        recent: &[crate::types::Message],
        memory: &crate::memory::SharedMemory,
        owner: &str,
    ) {
        let facts = match dream.extract_facts(recent).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(event = "idle_tick_extract_error", error = %e);
                return;
            }
        };

        let mem = memory.read().await;
        let mut stored = 0usize;
        for fact in &facts {
            match mem
                .store_belief(owner, None, fact, "idle_dream", "dream", false, None)
                .await
            {
                Ok(_) => stored += 1,
                Err(e) => tracing::warn!(event = "idle_tick_store_error", error = %e),
            }
        }

        tracing::info!(event = "idle_tick_complete", owner, stored);

        // MEM-02: consolidate the active belief set alongside extract_facts, in the
        // same pass. Each step below swallows its own errors — a retrieve/consolidate
        // failure skips consolidation for this tick only, never aborts idle_tick.
        let beliefs = match mem.retrieve_tagged(owner, None).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(event = "idle_tick_consolidate_retrieve_error", error = %e);
                return;
            }
        };

        let plan = match dream.consolidate(&beliefs).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(event = "idle_tick_consolidate_error", error = %e);
                return;
            }
        };

        let mut superseded = 0usize;
        for (old_id, new_id) in &plan.supersessions {
            match mem.supersede_belief(owner, *old_id, *new_id).await {
                Ok(_) => superseded += 1,
                Err(e) => tracing::warn!(
                    event = "idle_tick_supersede_error",
                    error = %e,
                    old_id,
                    new_id
                ),
            }
        }

        let mut pruned = 0usize;
        for id in &plan.prune_ids {
            match mem.revoke_belief(owner, *id).await {
                Ok(_) => pruned += 1,
                Err(e) => tracing::warn!(event = "idle_tick_prune_error", error = %e, id),
            }
        }

        tracing::info!(
            event = "idle_tick_consolidate_complete",
            owner,
            superseded,
            pruned
        );
    }
}

// ---------------------------------------------------------------------------
// Tests (offline — short interval, bounded pending_rx; MockDream; temp DB)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::dream::{ConsolidationPlan, Dream};
    use crate::goal::ScoringConfig;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::{Belief, Memory};
    use crate::types::Message;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    // --- MockDream: returns scripted facts + a scripted ConsolidationPlan (or a
    // simulated consolidate() error, to test idle_tick's error-swallow discipline). ---

    struct MockDream {
        facts: Vec<String>,
        consolidation_plan: ConsolidationPlan,
        consolidate_error: bool,
    }

    #[async_trait]
    impl Dream for MockDream {
        async fn extract_facts(&self, _: &[Message]) -> anyhow::Result<Vec<String>> {
            Ok(self.facts.clone())
        }

        async fn consolidate(&self, _: &[Belief]) -> anyhow::Result<ConsolidationPlan> {
            if self.consolidate_error {
                anyhow::bail!("mock consolidate error");
            }
            Ok(self.consolidation_plan.clone())
        }
    }

    async fn setup_db(path: &str) {
        let sm = crate::session::SessionManager::new(path);
        sm.init_schema().await.expect("init_schema");
    }

    // -----------------------------------------------------------------------
    // Heartbeat: ticks at very short interval and enqueues ≥1 message.
    // We create a goal with interactions above threshold so drift_nudge returns Some.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn heartbeat_enqueues_at_least_one_message() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        setup_db(&path).await;

        let sm = crate::session::SessionManager::new(&path);
        let engine = GoalEngine::new(
            &path,
            ScoringConfig {
                window_days: 7,
                progress_threshold: 1,
            },
        );

        // Create a goal
        let _goal_id = engine
            .create_goal("_local", "exercise daily", None, None, None)
            .await
            .expect("create_goal");

        // Insert enough matching messages to hit threshold=1
        let sid = sm.create_session_for("_local").await.expect("session");
        insert_raw_message(&path, &sid, "I exercise every day").await;

        let (tx, mut rx) = mpsc::channel::<PendingItem>(16);
        let svc = CronService::new(tx, engine);

        // Spawn heartbeat with a very short interval (10ms)
        let handle = tokio::spawn(async move {
            svc.run_heartbeat(Duration::from_millis(10), "_local").await;
        });

        // Wait up to 500ms to receive at least one message
        let item = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("timeout waiting for heartbeat message")
            .expect("channel closed");

        handle.abort();

        assert!(
            !item.text.is_empty(),
            "heartbeat message must not be empty; got: {item:?}"
        );
        assert_eq!(
            item.owner.as_deref(),
            Some("_local"),
            "6d: heartbeat item must be tagged with the owner it ran for; got: {item:?}"
        );
    }

    // -----------------------------------------------------------------------
    // on_event: sends an event text into the channel immediately.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn on_event_enqueues_message() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        setup_db(&path).await;

        let engine = GoalEngine::new(&path, ScoringConfig::default());
        let (tx, mut rx) = mpsc::channel::<PendingItem>(16);
        let svc = CronService::new(tx, engine);

        svc.on_event("_local", "calendar: meeting in 10 minutes".to_string())
            .await;

        let item = rx.recv().await.expect("message expected");
        assert_eq!(item.text, "calendar: meeting in 10 minutes");
        assert_eq!(
            item.owner.as_deref(),
            Some("_local"),
            "6d: on_event item must be tagged with the owner it was raised for"
        );
    }

    // -----------------------------------------------------------------------
    // idle_tick: MockDream returns scripted facts → stored as beliefs in temp DB.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn idle_tick_stores_beliefs_in_db() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        setup_db(&path).await;

        let memory: crate::memory::SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&path)) as Box<dyn Memory>,
        ));

        let engine = GoalEngine::new(&path, ScoringConfig::default());
        let (tx, _rx) = mpsc::channel::<PendingItem>(16);
        let svc = CronService::new(tx, engine);

        let dream = MockDream {
            facts: vec![
                "Mario exercises every morning".to_string(),
                "Mario drinks coffee".to_string(),
            ],
            consolidation_plan: ConsolidationPlan::default(),
            consolidate_error: false,
        };

        let messages: Vec<Message> = vec![]; // unused by MockDream

        svc.idle_tick(&dream, &messages, &memory, "_local").await;

        let beliefs = {
            let m = memory.read().await;
            m.retrieve_tagged("_local", None).await.expect("retrieve")
        };

        assert_eq!(
            beliefs.len(),
            2,
            "idle_tick must store all 2 facts; got {}",
            beliefs.len()
        );
    }

    // -----------------------------------------------------------------------
    // idle_tick: MEM-02 — applies a scripted ConsolidationPlan via
    // supersede_belief/revoke_belief, in the same pass as extract_facts, even when
    // extract_facts produces zero new facts.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn idle_tick_applies_consolidation_plan_supersede_and_prune() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        setup_db(&path).await;

        let memory: crate::memory::SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&path)) as Box<dyn Memory>,
        ));

        // Seed 3 real beliefs directly via the Memory trait — supersession/prune are
        // scripted below by exact id, so the actual content/weight doesn't drive the
        // decision here (Dream::consolidate's own decision logic is unit-tested in
        // agent::dream::tests; this test proves idle_tick's WIRING of a given plan).
        let (old_id, new_id, prune_id) = {
            let m = memory.read().await;
            let old_id = m
                .store_belief(
                    "_local",
                    None,
                    "Mario exercises every morning",
                    "seed",
                    "test",
                    false,
                    None,
                )
                .await
                .expect("store old belief");
            let new_id = m
                .store_belief(
                    "_local",
                    None,
                    "Mario exercises each morning",
                    "seed",
                    "test",
                    false,
                    None,
                )
                .await
                .expect("store new belief");
            let prune_id = m
                .store_belief(
                    "_local",
                    None,
                    "Mario dislikes cauliflower",
                    "seed",
                    "test",
                    false,
                    None,
                )
                .await
                .expect("store prune belief");
            (old_id, new_id, prune_id)
        };

        let engine = GoalEngine::new(&path, ScoringConfig::default());
        let (tx, _rx) = mpsc::channel::<PendingItem>(16);
        let svc = CronService::new(tx, engine);

        let dream = MockDream {
            facts: vec![], // proves consolidation runs even with zero new facts
            consolidation_plan: ConsolidationPlan {
                supersessions: vec![(old_id, new_id)],
                prune_ids: vec![prune_id],
            },
            consolidate_error: false,
        };

        let messages: Vec<Message> = vec![];
        svc.idle_tick(&dream, &messages, &memory, "_local").await;

        // Supersession: the OLD row's superseded_by is set; the row is still present
        // (never deleted, D-15) since supersede_belief never touches weight/revoked —
        // retrieve_all_beliefs (WHERE revoked=0 AND weight>0) still returns it.
        let all = {
            let m = memory.read().await;
            m.retrieve_all_beliefs("_local")
                .await
                .expect("retrieve_all")
        };
        let old_row = all
            .iter()
            .find(|b| b.id == old_id)
            .expect("old belief must still be present (non-destructive supersession)");
        assert_eq!(
            old_row.superseded_by,
            Some(new_id),
            "old belief must be marked superseded_by new_id"
        );

        // Pruning: the belief is soft-revoked (revoked=1, weight=0). Verified via a raw
        // query since retrieve_all_beliefs deliberately excludes revoked rows
        // (WHERE revoked=0), so absence there alone wouldn't distinguish "revoked" from
        // "never existed".
        let (revoked, weight) = read_raw_belief_flags(&path, prune_id).await;
        assert!(revoked, "pruned belief must be revoked");
        assert_eq!(
            weight, 0.0,
            "pruned belief must have weight=0 after revoke_belief"
        );
    }

    // -----------------------------------------------------------------------
    // idle_tick: a consolidate() error is logged and swallowed — idle_tick completes
    // normally (mirrors extract_facts's existing error-swallow test coverage).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn idle_tick_swallows_consolidate_error_without_panicking() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        setup_db(&path).await;

        let memory: crate::memory::SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&path)) as Box<dyn Memory>,
        ));

        let engine = GoalEngine::new(&path, ScoringConfig::default());
        let (tx, _rx) = mpsc::channel::<PendingItem>(16);
        let svc = CronService::new(tx, engine);

        let dream = MockDream {
            facts: vec![],
            consolidation_plan: ConsolidationPlan::default(),
            consolidate_error: true,
        };

        let messages: Vec<Message> = vec![];
        // Must not panic/abort — idle_tick completes normally despite consolidate()
        // erroring; if this test hangs or panics, the error-swallow discipline broke.
        svc.idle_tick(&dream, &messages, &memory, "_local").await;
    }

    // -----------------------------------------------------------------------
    // Helper: insert a raw message directly into SQLite (bypasses Role parsing)
    // -----------------------------------------------------------------------

    async fn insert_raw_message(db_path: &str, session_id: &str, content: &str) {
        let path = db_path.to_owned();
        let sid = session_id.to_owned();
        let content = content.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as i64;
            conn.execute(
                "INSERT INTO messages (session_id, role, content, created_at) VALUES (?1, 'user', ?2, ?3)",
                rusqlite::params![sid, content, now],
            ).unwrap();
        })
        .await
        .unwrap();
    }

    // -----------------------------------------------------------------------
    // Helper: read (revoked, weight) directly from SQLite for a given belief id —
    // used to verify pruning since retrieve_all_beliefs excludes revoked rows.
    // -----------------------------------------------------------------------

    async fn read_raw_belief_flags(db_path: &str, id: i64) -> (bool, f64) {
        let path = db_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.query_row(
                "SELECT revoked, weight FROM beliefs WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    let revoked: i64 = row.get(0)?;
                    let weight: f64 = row.get(1)?;
                    Ok((revoked != 0, weight))
                },
            )
            .unwrap()
        })
        .await
        .unwrap()
    }
}
