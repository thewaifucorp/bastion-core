//! Goal engine: persisted goal model (GOAL-01), zero-LLM heuristic progress scoring
//! (GOAL-02, D-09), drift nudge + confirm/replan flow (GOAL-03, D-10/D-11/D-12).
//!
//! Security: all SQL writes use rusqlite::params! (T-02-16).
//! Keyword scoring is done in Rust after fetching rows — no string-built SQL (T-02-16).
//! Window-bounded query caps unbounded scans (T-02-18).
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Heuristic scoring config (D-09 area — Claude's discretion).
/// Mirrors compactor.rs AutoCompact shape.
#[derive(Clone)]
pub struct ScoringConfig {
    /// Look-back window for interaction counting (days).
    pub window_days: i64,
    /// Minimum matching-keyword interactions to flag possible progress.
    pub progress_threshold: u32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            window_days: 7,
            progress_threshold: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A persisted goal row. Moved to `bastion_types::Goal` (M2 3b — plain data;
/// `docs/ARCHITECTURE.md` finding #2). Re-exported here so every existing
/// `crate::goal::Goal` path (and downstream code in this module) keeps
/// compiling unchanged.
pub use bastion_types::Goal;

/// Result of heuristic progress scoring (zero LLM, D-09).
#[derive(Debug, Clone)]
pub struct ProgressScore {
    pub interaction_count: u32,
    pub possible_progress: bool,
}

/// Stub replan result returned after confirm_progress (D-12).
#[derive(Debug, Clone)]
pub struct ReplanResult {
    pub goal_id: i64,
    pub adjusted_steps: Vec<String>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GoalEngine {
    db_path: String,
    cfg: ScoringConfig,
}

impl GoalEngine {
    pub fn new(db_path: impl Into<String>, cfg: ScoringConfig) -> Self {
        Self {
            db_path: db_path.into(),
            cfg,
        }
    }

    // -----------------------------------------------------------------------
    // GOAL-01: persist / list goals
    // -----------------------------------------------------------------------

    /// Insert a new goal; returns the new row id.
    pub async fn create_goal(
        &self,
        owner_id: &str,
        description: &str,
        metric: Option<&str>,
        deadline: Option<i64>,
        guardian_persona: Option<&str>,
    ) -> anyhow::Result<i64> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let description = description.to_owned();
        let metric = metric.map(|s| s.to_owned());
        let guardian_persona = guardian_persona.map(|s| s.to_owned());
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            let now = now_secs();
            conn.execute(
                "INSERT INTO goals (owner_id, description, metric, deadline, guardian_persona, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![owner_id, description, metric, deadline, guardian_persona, now],
            )?;
            Ok::<_, anyhow::Error>(conn.last_insert_rowid())
        })
        .await?
    }

    /// Return all goals for an owner.
    pub async fn list_goals(&self, owner_id: &str) -> anyhow::Result<Vec<Goal>> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            let mut stmt = conn.prepare(
                "SELECT id, owner_id, description, metric, deadline, guardian_persona, last_confirmed \
                 FROM goals WHERE owner_id = ?1 ORDER BY created_at ASC",
            )?;
            let goals: Vec<Goal> = stmt
                .query_map(rusqlite::params![owner_id], |row| {
                    Ok(Goal {
                        id: row.get(0)?,
                        owner_id: row.get(1)?,
                        description: row.get(2)?,
                        metric: row.get(3)?,
                        deadline: row.get(4)?,
                        guardian_persona: row.get(5)?,
                        last_confirmed: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, anyhow::Error>(goals)
        })
        .await?
    }

    // -----------------------------------------------------------------------
    // GOAL-02: heuristic progress scoring (D-09 — zero LLM)
    // -----------------------------------------------------------------------

    /// Compute a ProgressScore for the given goal by counting messages whose
    /// content overlaps with goal keywords within the scoring window.
    /// ZERO provider calls — pure SQLite + Rust-side counting.
    pub async fn score_progress(
        &self,
        owner_id: &str,
        goal_id: i64,
    ) -> anyhow::Result<ProgressScore> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let window_days = self.cfg.window_days;
        let threshold = self.cfg.progress_threshold;

        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;

            // Load the goal to derive keywords
            let goal: Goal = {
                let mut stmt = conn.prepare(
                    "SELECT id, owner_id, description, metric, deadline, guardian_persona, last_confirmed \
                     FROM goals WHERE id = ?1 AND owner_id = ?2",
                )?;
                let mut rows = stmt.query(rusqlite::params![goal_id, owner_id])?;
                match rows.next()? {
                    Some(row) => Goal {
                        id: row.get(0)?,
                        owner_id: row.get(1)?,
                        description: row.get(2)?,
                        metric: row.get(3)?,
                        deadline: row.get(4)?,
                        guardian_persona: row.get(5)?,
                        last_confirmed: row.get(6)?,
                    },
                    None => anyhow::bail!("goal {} not found for owner {}", goal_id, owner_id),
                }
            };

            let keywords = derive_keywords(&goal);

            // Window start: last_confirmed if set, else now - window_days
            let window_start = goal.last_confirmed.unwrap_or_else(|| {
                now_secs() - window_days * 86_400
            });

            // Fetch recent message content within window (Rust-side keyword matching —
            // avoids string-built SQL; satisfies T-02-16 injection-safety requirement).
            // Owner-scoped JOIN (IDOR guard): only count messages from sessions owned
            // by this goal's owner — never let another owner's activity inflate progress.
            let mut stmt = conn.prepare(
                "SELECT m.content FROM messages m \
                 JOIN sessions s ON s.id = m.session_id \
                 WHERE m.created_at > ?1 AND s.owner_id = ?2",
            )?;
            let contents: Vec<String> = stmt
                .query_map(rusqlite::params![window_start, owner_id], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect();

            // Count messages that contain at least one goal keyword
            let interaction_count: u32 = contents
                .iter()
                .filter(|c| {
                    let lower = c.to_lowercase();
                    keywords.iter().any(|kw| lower.contains(kw.as_str()))
                })
                .count() as u32;

            Ok::<_, anyhow::Error>(ProgressScore {
                interaction_count,
                possible_progress: interaction_count >= threshold,
            })
        })
        .await?
    }

    // -----------------------------------------------------------------------
    // GOAL-03: drift nudge + confirm/replan (D-10 / D-11 / D-12)
    // -----------------------------------------------------------------------

    /// Evaluate whether a goal drift or progress nudge should be surfaced.
    /// Returns Some(text) when actionable; None otherwise.
    /// ZERO provider calls; delivery is deferred to PROACT (plan 08).
    pub async fn drift_nudge(
        &self,
        owner_id: &str,
        goal_id: i64,
    ) -> anyhow::Result<Option<String>> {
        let score = self.score_progress(owner_id, goal_id).await?;

        if score.possible_progress {
            // Load goal for nudge text
            let goals = self.list_goals(owner_id).await?;
            if let Some(goal) = goals.iter().find(|g| g.id == goal_id) {
                return Ok(Some(build_confirm_nudge(goal)));
            }
        }

        // Check staleness: no progress in window AND deadline approaching
        let path = self.db_path.clone();
        let owner_id_owned = owner_id.to_owned();
        let window_days = self.cfg.window_days;

        let goal_opt: Option<Goal> = tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            let mut stmt = conn.prepare(
                "SELECT id, owner_id, description, metric, deadline, guardian_persona, last_confirmed \
                 FROM goals WHERE id = ?1 AND owner_id = ?2",
            )?;
            let mut rows = stmt.query(rusqlite::params![goal_id, owner_id_owned])?;
            if let Some(row) = rows.next()? {
                Ok::<_, anyhow::Error>(Some(Goal {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    description: row.get(2)?,
                    metric: row.get(3)?,
                    deadline: row.get(4)?,
                    guardian_persona: row.get(5)?,
                    last_confirmed: row.get(6)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await??;

        if let Some(goal) = goal_opt {
            let now = now_secs();
            let stale_since = goal.last_confirmed.unwrap_or(0);
            let window_secs = window_days * 86_400;
            let is_stale = (now - stale_since) > window_secs;
            // Deadline approaching = within 2x the window
            let deadline_approaching = goal
                .deadline
                .map(|d| d > now && (d - now) < 2 * window_secs)
                .unwrap_or(false);

            if is_stale && deadline_approaching {
                return Ok(Some(build_drift_nudge(&goal)));
            }
        }

        Ok(None)
    }

    /// Confirm progress on a goal: update last_confirmed = now, return a heuristic
    /// replan result (D-12). Called from auto path (D-10) or manual `/goal confirm` (D-11).
    pub async fn confirm_progress(
        &self,
        owner_id: &str,
        goal_id: i64,
    ) -> anyhow::Result<ReplanResult> {
        let path = self.db_path.clone();
        let owner_id_owned = owner_id.to_owned();
        let now = now_secs();

        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            let updated = conn.execute(
                "UPDATE goals SET last_confirmed = ?1 WHERE id = ?2 AND owner_id = ?3",
                rusqlite::params![now, goal_id, owner_id_owned],
            )?;
            if updated == 0 {
                anyhow::bail!("goal {} not found for owner {}", goal_id, owner_id_owned);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        // Heuristic replan: load goal for context
        let goals = self.list_goals(owner_id).await?;
        let adjusted_steps = if let Some(goal) = goals.iter().find(|g| g.id == goal_id) {
            replan_steps(goal)
        } else {
            vec!["Continue no ritmo atual.".to_owned()]
        };

        Ok(ReplanResult {
            goal_id,
            adjusted_steps,
        })
    }
}

/// M2 (P4 `GoalPort` port): the loop only ever needs `list_goals` — this is a
/// pure passthrough to the inherent method, no logic change. Fully-qualified
/// (M2 step 6): once this file lives in `bastion-cognition`, `crate::agent`
/// is this crate's own dream/procedural/memory_rag/identity module, not the
/// kernel's ports (those stay in `bastion_runtime::agent`).
#[async_trait::async_trait]
impl bastion_runtime::agent::ports::GoalPort for GoalEngine {
    async fn list_goals(&self, owner_id: &str) -> anyhow::Result<Vec<Goal>> {
        GoalEngine::list_goals(self, owner_id).await
    }
}

// ---------------------------------------------------------------------------
// Pure string builders (D-10 / D-11 — pt-BR per spec §4)
// ---------------------------------------------------------------------------

/// Builds a confirmation nudge: user may have progressed toward the goal.
pub(crate) fn build_confirm_nudge(goal: &Goal) -> String {
    format!(
        "Parece que você avançou em \"{}\" — confirma?",
        goal.description
    )
}

/// Builds a drift signal: user hasn't progressed in the window and deadline is near.
pub(crate) fn build_drift_nudge(goal: &Goal) -> String {
    format!(
        "Parece que você não avançou em \"{}\" essa semana. Quer retomar?",
        goal.description
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a keyword set from goal description + guardian_persona.
/// Splits on whitespace, lowercases, drops common Portuguese stopwords.
fn derive_keywords(goal: &Goal) -> Vec<String> {
    const STOPWORDS: &[&str] = &[
        "a", "o", "e", "de", "da", "do", "em", "um", "uma", "para", "com", "por", "que", "se",
        "os", "as", "ao", "na", "no", "mais", "mas", "ou", "foi", "ele", "ela", "ser", "ter", "ao",
        "pelo", "pela", "this", "the", "and", "to", "of", "in", "is", "it", "for", "on", "with",
        "at",
    ];

    let mut kws: Vec<String> = goal
        .description
        .split_whitespace()
        .chain(
            goal.guardian_persona
                .as_deref()
                .unwrap_or("")
                .split_whitespace(),
        )
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|w| w.len() > 2 && !STOPWORDS.contains(&w.as_str()))
        .collect();

    kws.sort();
    kws.dedup();
    kws
}

/// Generate simple heuristic next steps after confirmation (Phase-2 replan; D-12).
fn replan_steps(goal: &Goal) -> Vec<String> {
    let mut steps = Vec::new();
    steps.push(format!("Continuar avançando em \"{}\".", goal.description));
    if let Some(metric) = &goal.metric {
        steps.push(format!("Verificar métrica: {}.", metric));
    }
    if let Some(deadline) = goal.deadline {
        let remaining_days = (deadline - now_secs()).max(0) / 86_400;
        steps.push(format!("Prazo restante: {} dias.", remaining_days));
    }
    steps
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests (offline, temp DB — no LLM, no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionManager;

    fn temp_db() -> String {
        // Unique per call: a process-wide atomic counter guarantees no path
        // collision between parallel tests (subsec_nanos alone can collide and
        // make two tests share a DB — flaky cross-contamination of `user1` rows).
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("goal_test_{nanos}_{n}.db"));
        tmp.to_string_lossy().into_owned()
    }

    async fn setup_db(path: &str) -> SessionManager {
        let sm = SessionManager::new(path);
        sm.init_schema().await.expect("init_schema failed");
        sm
    }

    // ------------------------------------------------------------------
    // Task 1 tests: create_goal / list_goals / score_progress
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_and_list_goals() {
        let db = temp_db();
        let _sm = setup_db(&db).await;
        let engine = GoalEngine::new(&db, ScoringConfig::default());

        let id = engine
            .create_goal(
                "user1",
                "aprender Rust",
                Some("livros lidos"),
                None,
                Some("mentor"),
            )
            .await
            .expect("create_goal failed");
        assert!(id > 0);

        let goals = engine.list_goals("user1").await.expect("list_goals failed");
        assert_eq!(goals.len(), 1);
        assert_eq!(goals[0].description, "aprender Rust");
        assert_eq!(goals[0].guardian_persona.as_deref(), Some("mentor"));
    }

    #[tokio::test]
    async fn test_score_progress_below_threshold() {
        let db = temp_db();
        let sm = setup_db(&db).await;
        let engine = GoalEngine::new(
            &db,
            ScoringConfig {
                window_days: 7,
                progress_threshold: 3,
            },
        );

        let goal_id = engine
            .create_goal("user1", "aprender Rust", None, None, None)
            .await
            .unwrap();

        // Insert only 1 message with keyword "rust" — below threshold=3
        let sid = sm.create_session_for("user1").await.unwrap();
        insert_raw_message(&db, &sid, "falei sobre rust hoje").await;

        let score = engine.score_progress("user1", goal_id).await.unwrap();
        assert_eq!(score.interaction_count, 1);
        assert!(!score.possible_progress, "should be false below threshold");
    }

    #[tokio::test]
    async fn test_score_progress_at_threshold() {
        let db = temp_db();
        let sm = setup_db(&db).await;
        let engine = GoalEngine::new(
            &db,
            ScoringConfig {
                window_days: 7,
                progress_threshold: 3,
            },
        );

        let goal_id = engine
            .create_goal("user1", "aprender Rust", None, None, None)
            .await
            .unwrap();

        // Insert 3 messages with keyword "aprender" — at threshold
        let sid = sm.create_session_for("user1").await.unwrap();
        for _ in 0..3 {
            insert_raw_message(&db, &sid, "preciso aprender mais hoje").await;
        }

        let score = engine.score_progress("user1", goal_id).await.unwrap();
        assert!(score.interaction_count >= 3);
        assert!(score.possible_progress, "should be true at threshold");
    }

    // ------------------------------------------------------------------
    // Task 2 tests: drift_nudge / confirm_progress
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_confirm_progress_updates_last_confirmed() {
        let db = temp_db();
        let _sm = setup_db(&db).await;
        let engine = GoalEngine::new(&db, ScoringConfig::default());

        let goal_id = engine
            .create_goal("user1", "ler 12 livros", Some("1 livro/mês"), None, None)
            .await
            .unwrap();

        let before = now_secs();
        let result = engine.confirm_progress("user1", goal_id).await.unwrap();
        let after = now_secs();

        assert_eq!(result.goal_id, goal_id);
        assert!(!result.adjusted_steps.is_empty());

        // Verify last_confirmed was actually written to DB
        let goals = engine.list_goals("user1").await.unwrap();
        let lc = goals[0]
            .last_confirmed
            .expect("last_confirmed should be set");
        assert!(lc >= before && lc <= after, "last_confirmed out of range");
    }

    #[tokio::test]
    async fn test_drift_nudge_returns_some_at_threshold() {
        let db = temp_db();
        let sm = setup_db(&db).await;
        let engine = GoalEngine::new(
            &db,
            ScoringConfig {
                window_days: 7,
                progress_threshold: 3,
            },
        );

        let goal_id = engine
            .create_goal("user1", "aprender Rust", None, None, None)
            .await
            .unwrap();

        let sid = sm.create_session_for("user1").await.unwrap();
        for _ in 0..3 {
            insert_raw_message(&db, &sid, "trabalhei em aprender hoje").await;
        }

        let nudge = engine.drift_nudge("user1", goal_id).await.unwrap();
        assert!(nudge.is_some(), "should return Some nudge at threshold");
        let text = nudge.unwrap();
        assert!(
            text.contains("aprender Rust"),
            "nudge should mention the goal"
        );
    }

    #[tokio::test]
    async fn test_drift_nudge_returns_none_below_threshold() {
        let db = temp_db();
        let _sm = setup_db(&db).await;
        let engine = GoalEngine::new(
            &db,
            ScoringConfig {
                window_days: 7,
                progress_threshold: 3,
            },
        );

        // No messages inserted — score=0, not stale+near-deadline either
        let goal_id = engine
            .create_goal("user1", "aprender Rust", None, None, None)
            .await
            .unwrap();

        let nudge = engine.drift_nudge("user1", goal_id).await.unwrap();
        // With no messages and no deadline, should be None
        assert!(
            nudge.is_none(),
            "should return None when no interactions and no deadline"
        );
    }

    // ------------------------------------------------------------------
    // Helper: insert a raw message row directly (bypasses Role parsing)
    // ------------------------------------------------------------------

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
}
