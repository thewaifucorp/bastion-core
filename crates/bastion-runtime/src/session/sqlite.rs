use crate::types::{BastionError, Message, MessageContent, Role};
use std::time::{SystemTime, UNIX_EPOCH};

/// Open a SQLite connection with WAL mode and a 5-second busy timeout.
/// All internal functions must use this helper so that concurrent writes
/// from the daemon (Telegram double-tap, channel overlap) do not cause
/// SQLITE_BUSY errors (CONC-1).
fn open_conn(path: &str) -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    Ok(conn)
}

/// Ciclo 2.4 (`docs/SUPPORT-MATRIX.md` §3 mode 3):
/// `Clone` added so a delegated task's spawned tokio task (which outlives the
/// `run_turn_for` call that started it) can hold its own handle to persist/
/// delete its `runtime_sessions` row without borrowing `AgentLoop` — cheap
/// (wraps one `String`), no new state, every existing call site unaffected.
#[derive(Clone)]
pub struct SessionManager {
    db_path: String,
}

impl SessionManager {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    pub async fn init_schema(&self) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            conn.execute_batch(
                "
                PRAGMA journal_mode=WAL;
                PRAGMA busy_timeout=5000;

                CREATE TABLE IF NOT EXISTS sessions (
                    id         TEXT    PRIMARY KEY,
                    owner_id   TEXT    NOT NULL DEFAULT '_local',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    role        TEXT    NOT NULL,
                    content     TEXT    NOT NULL,
                    tokens_used INTEGER,
                    created_at  INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_session
                    ON messages(session_id, created_at);

                CREATE TABLE IF NOT EXISTS budget (
                    date      TEXT PRIMARY KEY,
                    total_usd REAL NOT NULL DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS beliefs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id    TEXT    NOT NULL,
                    persona_tag TEXT,
                    content     TEXT    NOT NULL,
                    weight      REAL    NOT NULL DEFAULT 1.0,
                    revoked     INTEGER NOT NULL DEFAULT 0,
                    is_core     INTEGER NOT NULL DEFAULT 0,
                    created_at  INTEGER NOT NULL,
                    revoked_at  INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_beliefs_owner_persona
                    ON beliefs(owner_id, persona_tag, revoked, weight);

                CREATE TABLE IF NOT EXISTS provenance (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    belief_id  INTEGER NOT NULL REFERENCES beliefs(id) ON DELETE CASCADE,
                    session_id TEXT    NOT NULL,
                    source     TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_provenance_belief ON provenance(belief_id);

                CREATE TABLE IF NOT EXISTS goals (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id         TEXT    NOT NULL,
                    description      TEXT    NOT NULL,
                    metric           TEXT,
                    deadline         INTEGER,
                    guardian_persona TEXT,
                    last_confirmed   INTEGER,
                    created_at       INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pending_corrections (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    belief_id  INTEGER NOT NULL,
                    owner_id   TEXT    NOT NULL,
                    tier       TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_pending_corrections_owner ON pending_corrections(owner_id);

                CREATE TABLE IF NOT EXISTS reflector_state (
                    owner_id       TEXT    PRIMARY KEY,
                    last_watermark INTEGER NOT NULL DEFAULT 0,
                    updated_at     INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_queue (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id          TEXT    NOT NULL,
                    capability_name   TEXT    NOT NULL,
                    args_json         TEXT    NOT NULL,
                    idempotency_hash  TEXT    NOT NULL,
                    status            TEXT    NOT NULL DEFAULT 'pending',
                    result_json       TEXT,
                    created_at        INTEGER NOT NULL,
                    resolved_at       INTEGER,
                    executed_at       INTEGER
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_queue_hash
                    ON approval_queue(idempotency_hash);
                CREATE INDEX IF NOT EXISTS idx_approval_queue_owner_status
                    ON approval_queue(owner_id, status);

                CREATE TABLE IF NOT EXISTS composio_connections (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id             TEXT    NOT NULL,
                    toolkit              TEXT    NOT NULL,
                    connected_account_id TEXT    NOT NULL,
                    status               TEXT    NOT NULL DEFAULT 'pending',
                    created_at           INTEGER NOT NULL,
                    updated_at           INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_composio_connections_owner_toolkit
                    ON composio_connections(owner_id, toolkit);

                CREATE TABLE IF NOT EXISTS composio_oauth_state (
                    state      TEXT    PRIMARY KEY,
                    owner_id   TEXT    NOT NULL,
                    toolkit    TEXT    NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                -- Ciclo 2.4 (docs/SUPPORT-MATRIX.md §3):
                -- persisted AgentRuntime SessionHandle for restart recovery.
                -- `key` is caller-chosen: the Bastion session_id for a
                -- runtime-backed conversation (mode 2), or a per-task key for
                -- a delegated task (mode 3) -- this table has no opinion on
                -- what a \"session\" vs \"task\" is.
                CREATE TABLE IF NOT EXISTS runtime_sessions (
                    key          TEXT    PRIMARY KEY,
                    runtime_id   TEXT    NOT NULL,
                    owner_id     TEXT    NOT NULL,
                    external_ref TEXT    NOT NULL,
                    updated_at   INTEGER NOT NULL
                );

                -- Loop 3-A / 6a (docs/ARCHITECTURE.md
                -- section 6a): owner-scoped, persisted cross-turn queue for a
                -- harness's PermissionRequest events. `id` is Bastion's own
                -- identity (the correlation key a later turn resolves by);
                -- `req_id` is the harness's OWN PermissionRequestId, stored
                -- only so a resolved row can answer
                -- RuntimeSession::respond_permission on the real session --
                -- it is only unique WITHIN one harness session, never used
                -- as this table's key. `status` is 'pending' | 'resolved';
                -- a resolved row's `decision_json` records the FINAL
                -- PermissionDecision (an explicit later-turn answer, or a
                -- fail-closed timeout Deny{Turn}) -- never rewritten again
                -- once set.
                CREATE TABLE IF NOT EXISTS permission_queue (
                    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                    req_id                INTEGER NOT NULL,
                    owner_id              TEXT    NOT NULL,
                    session_runtime_id    TEXT    NOT NULL,
                    session_owner         TEXT    NOT NULL,
                    session_external_ref  TEXT    NOT NULL,
                    action_json           TEXT    NOT NULL,
                    detail                TEXT    NOT NULL,
                    status                TEXT    NOT NULL DEFAULT 'pending',
                    decision_json         TEXT,
                    raised_at             INTEGER NOT NULL,
                    expires_at            INTEGER NOT NULL,
                    resolved_at           INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_permission_queue_owner_status
                    ON permission_queue(owner_id, status);
            ",
            )?;
            // Additive migration for pre-existing single-user DBs (idempotent —
            // errors with "duplicate column" on fresh DBs where CREATE already added it).
            let _ = conn.execute(
                "ALTER TABLE sessions ADD COLUMN owner_id TEXT NOT NULL DEFAULT '_local'",
                [],
            );
            // Additive migration: add privacy_tier column to beliefs.
            // NULL = deny-on-ambiguity (safe default — existing rows treated as LocalOnly by egress gate).
            // Ignores "duplicate column name" error on DBs that already have this column (safe re-run).
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN privacy_tier TEXT", []);
            // Additive migration (LEARN-01): procedural belief columns. DEFAULT 'factual'
            // guarantees every pre-Phase-7 row keeps behaving exactly as before this
            // migration — no backfill of existing rows required.
            let _ = conn.execute(
                "ALTER TABLE beliefs ADD COLUMN kind TEXT NOT NULL DEFAULT 'factual'",
                [],
            );
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN keywords TEXT", []);
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN issue TEXT", []);
            let _ = conn.execute(
                "ALTER TABLE beliefs ADD COLUMN helpful_count INTEGER NOT NULL DEFAULT 0",
                [],
            );
            let _ = conn.execute(
                "ALTER TABLE beliefs ADD COLUMN harmful_count INTEGER NOT NULL DEFAULT 0",
                [],
            );
            let _ = conn.execute(
                "ALTER TABLE beliefs ADD COLUMN neutral_count INTEGER NOT NULL DEFAULT 0",
                [],
            );
            // Additive migration (MEM-01/D-10): bi-temporal validity columns.
            // valid_from/valid_until describe the belief's real-world validity
            // window: NULL valid_from = no asserted start, NULL valid_until =
            // open/no expiry yet (PERMISSIVE-on-NULL).
            //
            // IMPORTANT: this is the OPPOSITE convention from `privacy_tier`
            // above, where NULL means deny-on-ambiguity (restrictive). Do NOT
            // "fix" valid_until's NULL handling to match privacy_tier's — an
            // open-ended belief (valid_until IS NULL) must remain visible/valid
            // by design; only an explicit past valid_until closes it out.
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN valid_from INTEGER", []);
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN valid_until INTEGER", []);
            // superseded_by/supersedes_at: set only on the OLD/superseded row
            // (never on the surviving belief) when a later belief replaces it.
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN superseded_by INTEGER", []);
            let _ = conn.execute("ALTER TABLE beliefs ADD COLUMN supersedes_at INTEGER", []);
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    /// Create a session owned by the default single-user identity.
    /// Multi-owner callers (channels binding a chat to a user) MUST use
    /// `create_session_for` so message content is owner-scoped (goal scoring,
    /// life-log, and any per-owner read depend on sessions.owner_id).
    pub async fn create_session(&self) -> anyhow::Result<String> {
        self.create_session_for("_local").await
    }

    /// Create a session owned by `owner_id`. The owner scopes every message
    /// written under this session for cross-tenant isolation.
    pub async fn create_session_for(&self, owner_id: &str) -> anyhow::Result<String> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now: i64 = now_nanos();
            // Use nanosecond timestamp as session ID — unique enough per owner
            let session_id = now.to_string();
            conn.execute(
                "INSERT INTO sessions (id, owner_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![session_id, owner_id, now, now],
            )?;
            Ok::<_, anyhow::Error>(session_id)
        }).await?
    }

    pub async fn load_most_recent_id(&self) -> anyhow::Result<Option<String>> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt =
                conn.prepare("SELECT id FROM sessions ORDER BY updated_at DESC LIMIT 1")?;
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                Ok::<_, anyhow::Error>(Some(row.get::<_, String>(0)?))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    /// Owner-scoped session lookup — returns the most recent session for `owner_id`.
    /// Used by `run_turn_for` to ensure each owner gets their own conversation thread
    /// and never sees another owner's history (CR-04).
    pub async fn load_most_recent_id_for(&self, owner_id: &str) -> anyhow::Result<Option<String>> {
        let path = self.db_path.clone();
        let owner = owner_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(
                "SELECT id FROM sessions WHERE owner_id = ?1 ORDER BY updated_at DESC LIMIT 1",
            )?;
            let mut rows = stmt.query(rusqlite::params![owner])?;
            if let Some(row) = rows.next()? {
                Ok::<_, anyhow::Error>(Some(row.get::<_, String>(0)?))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn load_recent(&self, session_id: &str) -> anyhow::Result<Vec<Message>> {
        let path = self.db_path.clone();
        let sid = session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(
                "SELECT role, content FROM messages WHERE session_id = ?1 ORDER BY created_at ASC",
            )?;
            let messages: Vec<Message> = stmt
                .query_map(rusqlite::params![sid], |row| {
                    let role_str: String = row.get(0)?;
                    let content_str: String = row.get(1)?;
                    Ok((role_str, content_str))
                })?
                .map(|r| -> anyhow::Result<Message> {
                    let (role_str, content_str) = r?;
                    let role: Role = role_str.parse()?;
                    let content: MessageContent = serde_json::from_str(&content_str)
                        .map_err(|e| anyhow::anyhow!("failed to parse content: {}", e))?;
                    Ok(Message { role, content })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(messages)
        })
        .await?
    }

    pub async fn append(
        &self,
        session_id: &str,
        msg: Message,
        tokens_used: Option<u32>,
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let sid = session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;

            // Enforce role sequence integrity: a Tool message must belong to an
            // active tool-dispatch sequence — the immediately preceding row must
            // be either the Assistant message that requested it, or another Tool
            // result from the SAME round (Ciclo 2.1: `dispatch_tool_loop` appends
            // one Tool row per `tool_calls` entry, sequentially, for a
            // multi-tool-call round — e.g. the "denied tool + a skipped-not-executed
            // tool" pairing DenyScope::Turn produces, `docs/SECURITY-INVARIANTS.md`
            // §3 — the second and later Tool rows in that same round were
            // previously and incorrectly rejected as orphaned). Tool after
            // User/System/nothing is still rejected — unchanged.
            if msg.role == Role::Tool {
                let mut stmt = conn.prepare(
                    "SELECT role FROM messages WHERE session_id = ?1 ORDER BY created_at DESC LIMIT 1"
                )?;
                let mut rows = stmt.query(rusqlite::params![sid])?;
                let preceding_role = rows.next()?
                    .map(|r| r.get::<_, String>(0))
                    .transpose()?;

                match preceding_role.as_deref() {
                    Some("assistant") | Some("tool") => {}, // OK
                    _ => return Err(anyhow::anyhow!(BastionError::OrphanedToolResult)),
                }
            }

            let now = now_nanos();
            let role_str = msg.role.to_string();
            let content_str = serde_json::to_string(&msg.content)
                .map_err(|e| anyhow::anyhow!("failed to serialize content: {}", e))?;

            conn.execute(
                "INSERT INTO messages (session_id, role, content, tokens_used, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![sid, role_str, content_str, tokens_used, now],
            )?;

            conn.execute(
                "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, sid],
            )?;

            Ok::<_, anyhow::Error>(())
        }).await?
    }

    pub async fn replace_with_summary(
        &self,
        session_id: &str,
        summary: String,
        recent: &[Message],
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let sid = session_id.to_owned();
        let recent = recent.to_vec();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;

            // Delete all old messages for this session
            conn.execute(
                "DELETE FROM messages WHERE session_id = ?1",
                rusqlite::params![sid],
            )?;

            let now: i64 = now_nanos();

            // Insert summary as system message
            let summary_content = serde_json::to_string(&MessageContent::Text(summary))
                .map_err(|e| anyhow::anyhow!("failed to serialize summary: {}", e))?;
            conn.execute(
                "INSERT INTO messages (session_id, role, content, tokens_used, created_at) VALUES (?1, 'system', ?2, NULL, ?3)",
                rusqlite::params![sid, summary_content, now],
            )?;

            // Insert recent messages in order
            for (i, msg) in recent.iter().enumerate() {
                let ts: i64 = now + (i as i64) + 1;
                let role_str = msg.role.to_string();
                let content_str = serde_json::to_string(&msg.content)
                    .map_err(|e| anyhow::anyhow!("failed to serialize content: {}", e))?;
                conn.execute(
                    "INSERT INTO messages (session_id, role, content, tokens_used, created_at) VALUES (?1, ?2, ?3, NULL, ?4)",
                    rusqlite::params![sid, role_str, content_str, ts],
                )?;
            }

            conn.execute(
                "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, sid],
            )?;

            Ok::<_, anyhow::Error>(())
        }).await?
    }

    pub async fn update_budget(&self, cost_usd: f64) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let today = today_utc();
            conn.execute(
                "INSERT INTO budget(date, total_usd) VALUES(?1, ?2) \
                 ON CONFLICT(date) DO UPDATE SET total_usd = total_usd + ?2",
                rusqlite::params![today, cost_usd],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    pub async fn check_budget(&self, daily_limit: f64) -> anyhow::Result<bool> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let today = today_utc();
            let mut stmt = conn.prepare("SELECT total_usd FROM budget WHERE date = ?1")?;
            let mut rows = stmt.query(rusqlite::params![today])?;
            if let Some(row) = rows.next()? {
                let total: f64 = row.get(0)?;
                Ok::<_, anyhow::Error>(total < daily_limit)
            } else {
                Ok(true) // no spend today
            }
        })
        .await?
    }

    /// Ciclo 2.4 (`docs/SUPPORT-MATRIX.md` §3): persists an
    /// `AgentRuntime::SessionHandle` under a caller-chosen `key`, upserting on
    /// a re-save (e.g. a re-issued handle after `resume`). `key` is the
    /// Bastion session_id for a runtime-backed conversation (mode 2), or a
    /// per-task key for a delegated task (mode 3).
    pub async fn save_runtime_handle(
        &self,
        key: &str,
        handle: &bastion_agent_runtime::SessionHandle,
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let key = key.to_owned();
        let runtime_id = handle.runtime_id.clone();
        let owner = handle.owner.clone();
        let external_ref = handle.external_ref.clone();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now = now_nanos();
            conn.execute(
                "INSERT INTO runtime_sessions(key, runtime_id, owner_id, external_ref, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(key) DO UPDATE SET \
                    runtime_id = excluded.runtime_id, \
                    owner_id = excluded.owner_id, \
                    external_ref = excluded.external_ref, \
                    updated_at = excluded.updated_at",
                rusqlite::params![key, runtime_id, owner, external_ref, now],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    /// Loads a previously persisted handle for `key`, if any — `None` when
    /// nothing was ever saved under it (a fresh conversation/task, not an
    /// error).
    pub async fn load_runtime_handle(
        &self,
        key: &str,
    ) -> anyhow::Result<Option<bastion_agent_runtime::SessionHandle>> {
        let path = self.db_path.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(
                "SELECT runtime_id, owner_id, external_ref FROM runtime_sessions WHERE key = ?1",
            )?;
            let mut rows = stmt.query(rusqlite::params![key])?;
            if let Some(row) = rows.next()? {
                Ok::<_, anyhow::Error>(Some(bastion_agent_runtime::SessionHandle {
                    runtime_id: row.get(0)?,
                    owner: row.get(1)?,
                    external_ref: row.get(2)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    /// Removes a persisted handle — the session/task is over (ended,
    /// cancelled) and no longer resumable/needed. Idempotent: deleting an
    /// already-absent key is not an error.
    pub async fn delete_runtime_handle(&self, key: &str) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            conn.execute(
                "DELETE FROM runtime_sessions WHERE key = ?1",
                rusqlite::params![key],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

fn today_utc() -> String {
    // Simple UTC date — seconds since epoch / 86400 → days since epoch
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    // days since 1970-01-01 → year/month/day
    // Use a simple calculation (no chrono dependency)
    let (y, m, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    async fn make_db() -> (NamedTempFile, SessionManager) {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_str().unwrap().to_owned();
        let sm = SessionManager::new(&path);
        sm.init_schema().await.expect("init_schema");
        (f, sm)
    }

    #[tokio::test]
    async fn test_init_schema_idempotent_rerun() {
        let (_f, sm) = make_db().await;
        // Re-running init_schema against the same DB must not error.
        sm.init_schema().await.expect("second init_schema call");
    }

    #[tokio::test]
    async fn test_approval_queue_table_columns() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        let mut stmt = conn
            .prepare("PRAGMA table_info(approval_queue)")
            .expect("prepare");
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query_map")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        for expected in [
            "id",
            "owner_id",
            "capability_name",
            "args_json",
            "idempotency_hash",
            "status",
            "result_json",
            "created_at",
            "resolved_at",
            "executed_at",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "approval_queue missing column {expected}, has {cols:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_permission_queue_table_columns() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        let mut stmt = conn
            .prepare("PRAGMA table_info(permission_queue)")
            .expect("prepare");
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query_map")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        for expected in [
            "id",
            "req_id",
            "owner_id",
            "session_runtime_id",
            "session_owner",
            "session_external_ref",
            "action_json",
            "detail",
            "status",
            "decision_json",
            "raised_at",
            "expires_at",
            "resolved_at",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "permission_queue missing column {expected}, has {cols:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_composio_connections_table_columns() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        let mut stmt = conn
            .prepare("PRAGMA table_info(composio_connections)")
            .expect("prepare");
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query_map")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        for expected in [
            "id",
            "owner_id",
            "toolkit",
            "connected_account_id",
            "status",
            "created_at",
            "updated_at",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "composio_connections missing column {expected}, has {cols:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_composio_connections_unique_owner_toolkit() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        conn.execute(
            "INSERT INTO composio_connections (owner_id, toolkit, connected_account_id, status, created_at, updated_at) VALUES ('owner1', 'gmail', 'acct1', 'active', 1, 1)",
            [],
        )
        .expect("first insert");
        let second = conn.execute(
            "INSERT INTO composio_connections (owner_id, toolkit, connected_account_id, status, created_at, updated_at) VALUES ('owner1', 'gmail', 'acct2', 'active', 2, 2)",
            [],
        );
        assert!(
            second.is_err(),
            "duplicate (owner_id, toolkit) must violate UNIQUE index"
        );
    }

    /// SEC-03 forgery fix: `composio_oauth_state` is the CSPRNG state-nonce table that
    /// binds an OAuth callback to the owner/toolkit that actually initiated it — the
    /// callback handler must never trust `owner`/`toolkit` fields on the request body
    /// (T-11-06-01, OAuth callback forgery / IDOR).
    #[tokio::test]
    async fn test_composio_oauth_state_table_columns() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        let mut stmt = conn
            .prepare("PRAGMA table_info(composio_oauth_state)")
            .expect("prepare");
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query_map")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        for expected in ["state", "owner_id", "toolkit", "expires_at"] {
            assert!(
                cols.iter().any(|c| c == expected),
                "composio_oauth_state missing column {expected}, has {cols:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_composio_oauth_state_primary_key_rejects_duplicate() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        conn.execute(
            "INSERT INTO composio_oauth_state (state, owner_id, toolkit, expires_at) VALUES ('tok1', 'owner1', 'gmail', 999999999999)",
            [],
        )
        .expect("first insert");
        let second = conn.execute(
            "INSERT INTO composio_oauth_state (state, owner_id, toolkit, expires_at) VALUES ('tok1', 'owner2', 'slack', 999999999999)",
            [],
        );
        assert!(
            second.is_err(),
            "duplicate state token must violate PRIMARY KEY (single-use, CSPRNG-collision-resistant)"
        );
    }

    #[tokio::test]
    async fn test_approval_queue_unique_idempotency_hash() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        conn.execute(
            "INSERT INTO approval_queue (owner_id, capability_name, args_json, idempotency_hash, created_at) VALUES ('owner1', 'cap.send_email', '{}', 'hash1', 1)",
            [],
        )
        .expect("first insert");
        let second = conn.execute(
            "INSERT INTO approval_queue (owner_id, capability_name, args_json, idempotency_hash, created_at) VALUES ('owner1', 'cap.send_email', '{}', 'hash1', 2)",
            [],
        );
        assert!(
            second.is_err(),
            "duplicate idempotency_hash must violate UNIQUE constraint"
        );
    }

    #[tokio::test]
    async fn test_init_schema_idempotent_rerun_after_beliefs_migration() {
        let (_f, sm) = make_db().await;
        // Re-running init_schema a second time (post bi-temporal ALTER TABLE
        // additions) must still be a no-op — duplicate-column errors swallowed.
        sm.init_schema().await.expect("second init_schema call");
    }

    #[tokio::test]
    async fn test_beliefs_bitemporal_columns_nullable_and_default_null() {
        let (_f, sm) = make_db().await;
        let path = sm.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");

        // Pre-existing-style insert that omits the new bi-temporal columns.
        conn.execute(
            "INSERT INTO beliefs (owner_id, persona_tag, content, weight, revoked, is_core, created_at) VALUES ('owner1', NULL, 'test belief', 1.0, 0, 0, 1)",
            [],
        )
        .expect("insert belief");

        let mut stmt = conn.prepare("PRAGMA table_info(beliefs)").expect("prepare");
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query_map")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        for expected in [
            "valid_from",
            "valid_until",
            "superseded_by",
            "supersedes_at",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "beliefs missing column {expected}, has {cols:?}"
            );
        }

        let mut stmt = conn
            .prepare(
                "SELECT valid_from, valid_until, superseded_by, supersedes_at FROM beliefs WHERE content = 'test belief'",
            )
            .expect("prepare select");
        let mut rows = stmt.query([]).expect("query");
        let row = rows.next().expect("row").expect("row present");
        let valid_from: Option<i64> = row.get(0).expect("valid_from");
        let valid_until: Option<i64> = row.get(1).expect("valid_until");
        let superseded_by: Option<i64> = row.get(2).expect("superseded_by");
        let supersedes_at: Option<i64> = row.get(3).expect("supersedes_at");
        assert_eq!(valid_from, None);
        assert_eq!(valid_until, None);
        assert_eq!(superseded_by, None);
        assert_eq!(supersedes_at, None);
    }

    // ── Ciclo 2.4 — runtime_sessions (SessionHandle persistence) ─────────────

    fn sample_handle(external_ref: &str) -> bastion_agent_runtime::SessionHandle {
        bastion_agent_runtime::SessionHandle {
            runtime_id: "codex_app_server".to_string(),
            owner: "alice".to_string(),
            external_ref: external_ref.to_string(),
        }
    }

    #[tokio::test]
    async fn test_load_runtime_handle_returns_none_when_never_saved() {
        let (_f, sm) = make_db().await;
        assert!(sm
            .load_runtime_handle("sess-1")
            .await
            .expect("load must not error")
            .is_none());
    }

    #[tokio::test]
    async fn test_save_then_load_runtime_handle_round_trips() {
        let (_f, sm) = make_db().await;
        let handle = sample_handle("thread-abc");
        sm.save_runtime_handle("sess-1", &handle)
            .await
            .expect("save");
        let loaded = sm
            .load_runtime_handle("sess-1")
            .await
            .expect("load")
            .expect("must be present after save");
        assert_eq!(loaded.runtime_id, handle.runtime_id);
        assert_eq!(loaded.owner, handle.owner);
        assert_eq!(loaded.external_ref, handle.external_ref);
    }

    /// Re-saving under the same key upserts (e.g. a re-issued handle after a
    /// `resume`) rather than erroring on the PRIMARY KEY conflict.
    #[tokio::test]
    async fn test_save_runtime_handle_upserts_on_same_key() {
        let (_f, sm) = make_db().await;
        sm.save_runtime_handle("sess-1", &sample_handle("thread-old"))
            .await
            .expect("first save");
        sm.save_runtime_handle("sess-1", &sample_handle("thread-new"))
            .await
            .expect("second save must upsert, not error");
        let loaded = sm
            .load_runtime_handle("sess-1")
            .await
            .expect("load")
            .expect("present");
        assert_eq!(loaded.external_ref, "thread-new");
    }

    /// Two different keys (e.g. a conversation session + a delegated task)
    /// persist independently.
    #[tokio::test]
    async fn test_runtime_handles_are_isolated_per_key() {
        let (_f, sm) = make_db().await;
        sm.save_runtime_handle("sess-1", &sample_handle("thread-conversation"))
            .await
            .expect("save conversation handle");
        sm.save_runtime_handle("task-42", &sample_handle("thread-task"))
            .await
            .expect("save task handle");
        assert_eq!(
            sm.load_runtime_handle("sess-1")
                .await
                .expect("load")
                .expect("present")
                .external_ref,
            "thread-conversation"
        );
        assert_eq!(
            sm.load_runtime_handle("task-42")
                .await
                .expect("load")
                .expect("present")
                .external_ref,
            "thread-task"
        );
    }

    #[tokio::test]
    async fn test_delete_runtime_handle_removes_it() {
        let (_f, sm) = make_db().await;
        sm.save_runtime_handle("sess-1", &sample_handle("thread-abc"))
            .await
            .expect("save");
        sm.delete_runtime_handle("sess-1").await.expect("delete");
        assert!(sm
            .load_runtime_handle("sess-1")
            .await
            .expect("load must not error")
            .is_none());
    }

    /// Deleting a key that was never saved is not an error (idempotent).
    #[tokio::test]
    async fn test_delete_runtime_handle_on_absent_key_is_not_an_error() {
        let (_f, sm) = make_db().await;
        sm.delete_runtime_handle("never-existed")
            .await
            .expect("delete of absent key must not error");
    }
}
