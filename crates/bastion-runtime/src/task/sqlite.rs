//! `SqliteTaskStore`: the concrete, production [`TaskStore`] (US-102).
//!
//! Follows the sqlite conventions established by `session/sqlite.rs`,
//! `capability/approval.rs` and `capability/permission_queue.rs`:
//! `tokio::task::spawn_blocking` + `Connection::open` + `PRAGMA
//! journal_mode=WAL; PRAGMA busy_timeout=5000;` (rusqlite is sync — a
//! `Connection` is never held across an `.await`), and the owner-scoped IDOR
//! guard (`UPDATE ... WHERE id=?1 AND owner_id=?2`, bailing — never
//! silently no-opping — on zero rows changed).
//!
//! Own tables (deliberately separate from `session/sqlite.rs`'s tables):
//! `task_cases`, `task_attempts`, `task_evidence`, `task_external_handles`.
//!
//! Column layout notes (documented once here rather than at each call site):
//! - `mode`/`status` are stored as their `serde_json` string form (e.g.
//!   `"Pursue"`, the quotes included), not `Debug` — chosen for guaranteed
//!   round-trip safety with `serde_json::from_str`.
//! - Every other structured [`TaskCase`] field (`stop_reason`,
//!   `next_decision`, `intent`, `frame`, `bounds`, `usage`, `correlation`,
//!   `business_state`) is its own `..._json` column, serialized/deserialized
//!   with `serde_json::to_string`/`from_str`.
//! - `TaskCase.attempts: Vec<AttemptId>` and `.pending_approvals:
//!   Vec<ApprovalRef>` have no dedicated column in the spec's base column
//!   list; this file adds `attempts_json`/`pending_approvals_json` columns
//!   to `task_cases` so the whole `TaskCase` round-trips byte-for-byte
//!   (spec's own suggested "simplest" option). The full [`Attempt`] bodies
//!   still live in `task_attempts`, which is the source of truth for
//!   attempt content; `task_cases.attempts_json` only mirrors the id list.
//! - `TaskCase.created_at`/`.updated_at` are stamped by this store itself
//!   (fresh `now_nanos()` on every write that touches them), matching
//!   `session/sqlite.rs`'s convention — never trusted from the caller's
//!   in-memory struct. `Attempt.started_at`/`.ended_at` and
//!   `Evidence.captured_at` are domain timestamps the caller supplies and
//!   are persisted as given.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};
use tokio::task::spawn_blocking;

use super::store::TaskStore;
use super::{
    Attempt, AttemptId, Evidence, NextDecision, StopReason, TaskCase, TaskCaseId, TaskStatus,
};

fn open_conn(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    Ok(conn)
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

const SCHEMA_SQL: &str = "
    PRAGMA journal_mode=WAL;
    PRAGMA busy_timeout=5000;

    CREATE TABLE IF NOT EXISTS task_cases (
        id                     TEXT    PRIMARY KEY,
        owner_id               TEXT    NOT NULL,
        idempotency_key        TEXT    NOT NULL,
        mode                   TEXT    NOT NULL,
        status                 TEXT    NOT NULL,
        stop_reason_json       TEXT,
        parent_id              TEXT,
        attempts_json          TEXT    NOT NULL DEFAULT '[]',
        pending_approvals_json TEXT    NOT NULL DEFAULT '[]',
        next_decision_json     TEXT,
        intent_json            TEXT    NOT NULL,
        frame_json             TEXT    NOT NULL,
        bounds_json            TEXT    NOT NULL,
        usage_json             TEXT    NOT NULL,
        correlation_json       TEXT    NOT NULL,
        business_state_json    TEXT    NOT NULL,
        last_confirmed_event   TEXT,
        checkpoint_json        TEXT,
        revision               INTEGER NOT NULL,
        created_at             INTEGER NOT NULL,
        updated_at             INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_task_cases_idempotency_key
        ON task_cases(idempotency_key);
    CREATE INDEX IF NOT EXISTS idx_task_cases_owner ON task_cases(owner_id);

    CREATE TABLE IF NOT EXISTS task_attempts (
        id           TEXT    PRIMARY KEY,
        owner_id     TEXT    NOT NULL,
        task_id      TEXT    NOT NULL,
        payload_json TEXT    NOT NULL,
        started_at   INTEGER NOT NULL,
        ended_at     INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_task_attempts_owner ON task_attempts(owner_id);
    CREATE INDEX IF NOT EXISTS idx_task_attempts_owner_task
        ON task_attempts(owner_id, task_id);

    CREATE TABLE IF NOT EXISTS task_evidence (
        id           TEXT    PRIMARY KEY,
        owner_id     TEXT    NOT NULL,
        task_id      TEXT    NOT NULL,
        attempt_id   TEXT    NOT NULL,
        payload_json TEXT    NOT NULL,
        captured_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_task_evidence_owner ON task_evidence(owner_id);
    CREATE INDEX IF NOT EXISTS idx_task_evidence_owner_task
        ON task_evidence(owner_id, task_id);

    CREATE TABLE IF NOT EXISTS task_external_handles (
        task_id     TEXT NOT NULL,
        owner_id    TEXT NOT NULL,
        handle_json TEXT NOT NULL,
        PRIMARY KEY (task_id, owner_id)
    );
    CREATE INDEX IF NOT EXISTS idx_task_external_handles_owner
        ON task_external_handles(owner_id);
";

/// Columns read back into a [`TaskCase`] (excludes `idempotency_key`, which
/// is write-only bookkeeping — not part of the `TaskCase` contract).
const CASE_READ_COLUMNS: &str = "id, owner_id, mode, status, stop_reason_json, parent_id, \
    attempts_json, pending_approvals_json, next_decision_json, intent_json, frame_json, \
    bounds_json, usage_json, correlation_json, business_state_json, revision, created_at, \
    updated_at";

struct RawCaseRow {
    id: String,
    owner_id: String,
    mode: String,
    status: String,
    stop_reason_json: Option<String>,
    parent_id: Option<String>,
    attempts_json: String,
    pending_approvals_json: String,
    next_decision_json: Option<String>,
    intent_json: String,
    frame_json: String,
    bounds_json: String,
    usage_json: String,
    correlation_json: String,
    business_state_json: String,
    revision: i64,
    created_at: i64,
    updated_at: i64,
}

fn read_case_row(row: &rusqlite::Row) -> rusqlite::Result<RawCaseRow> {
    Ok(RawCaseRow {
        id: row.get(0)?,
        owner_id: row.get(1)?,
        mode: row.get(2)?,
        status: row.get(3)?,
        stop_reason_json: row.get(4)?,
        parent_id: row.get(5)?,
        attempts_json: row.get(6)?,
        pending_approvals_json: row.get(7)?,
        next_decision_json: row.get(8)?,
        intent_json: row.get(9)?,
        frame_json: row.get(10)?,
        bounds_json: row.get(11)?,
        usage_json: row.get(12)?,
        correlation_json: row.get(13)?,
        business_state_json: row.get(14)?,
        revision: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

fn raw_to_case(raw: RawCaseRow) -> anyhow::Result<TaskCase> {
    Ok(TaskCase {
        id: TaskCaseId(raw.id),
        owner: raw.owner_id,
        mode: serde_json::from_str(&raw.mode)?,
        intent: serde_json::from_str(&raw.intent_json)?,
        frame: serde_json::from_str(&raw.frame_json)?,
        bounds: serde_json::from_str(&raw.bounds_json)?,
        status: serde_json::from_str(&raw.status)?,
        stop_reason: raw
            .stop_reason_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?,
        attempts: serde_json::from_str(&raw.attempts_json)?,
        pending_approvals: serde_json::from_str(&raw.pending_approvals_json)?,
        next_decision: raw
            .next_decision_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?,
        usage: serde_json::from_str(&raw.usage_json)?,
        parent: raw.parent_id.map(TaskCaseId),
        correlation: serde_json::from_str(&raw.correlation_json)?,
        business_state: serde_json::from_str(&raw.business_state_json)?,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
        revision: raw.revision as u64,
    })
}

/// The serialized scalar/opaque columns of a [`TaskCase`], excluding `id`,
/// `owner_id`, `idempotency_key`, `revision`, `created_at` and `updated_at`
/// (each write site handles those directly — the latter three are
/// write-path-dependent: `created_at` only on insert, `updated_at`/
/// `revision` freshly stamped per write, never copied from the in-memory
/// struct).
struct CaseFields {
    mode: String,
    status: String,
    stop_reason_json: Option<String>,
    parent_id: Option<String>,
    attempts_json: String,
    pending_approvals_json: String,
    next_decision_json: Option<String>,
    intent_json: String,
    frame_json: String,
    bounds_json: String,
    usage_json: String,
    correlation_json: String,
    business_state_json: String,
}

fn case_fields(case: &TaskCase) -> anyhow::Result<CaseFields> {
    Ok(CaseFields {
        mode: serde_json::to_string(&case.mode)?,
        status: serde_json::to_string(&case.status)?,
        stop_reason_json: case
            .stop_reason
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
        parent_id: case.parent.as_ref().map(|p| p.as_str().to_string()),
        attempts_json: serde_json::to_string(&case.attempts)?,
        pending_approvals_json: serde_json::to_string(&case.pending_approvals)?,
        next_decision_json: case
            .next_decision
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
        intent_json: serde_json::to_string(&case.intent)?,
        frame_json: serde_json::to_string(&case.frame)?,
        bounds_json: serde_json::to_string(&case.bounds)?,
        usage_json: serde_json::to_string(&case.usage)?,
        correlation_json: serde_json::to_string(&case.correlation)?,
        business_state_json: serde_json::to_string(&case.business_state)?,
    })
}

/// SQLite-backed [`TaskStore`] — the production implementation.
#[derive(Clone)]
pub struct SqliteTaskStore {
    db_path: String,
}

impl SqliteTaskStore {
    /// Build a store over the sqlite file at `db_path`. Does not touch the
    /// database — call [`Self::init_schema`] before first use.
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    /// Create the `task_*` tables/indexes if absent. Safe to call on every
    /// startup (idempotent — every statement is `IF NOT EXISTS`).
    pub async fn init_schema(&self) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            conn.execute_batch(SCHEMA_SQL)?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }
}

#[async_trait::async_trait]
impl TaskStore for SqliteTaskStore {
    async fn create_case(&self, case: &TaskCase, idempotency_key: &str) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let fields = case_fields(case)?;
        let id = case.id.as_str().to_string();
        let owner_id = case.owner.clone();
        let idempotency_key = idempotency_key.to_string();
        let revision = case.revision as i64;
        spawn_blocking(move || {
            let mut conn = open_conn(&path)?;
            let tx = conn.transaction()?;
            let now = now_nanos();

            let already: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM task_cases WHERE idempotency_key = ?1",
                    rusqlite::params![idempotency_key],
                    |r| r.get(0),
                )
                .optional()?;
            if already.is_some() {
                tx.commit()?;
                return Ok::<_, anyhow::Error>(());
            }

            let insert = tx.execute(
                "INSERT INTO task_cases (
                    id, owner_id, idempotency_key, mode, status, stop_reason_json, parent_id,
                    attempts_json, pending_approvals_json, next_decision_json, intent_json,
                    frame_json, bounds_json, usage_json, correlation_json, business_state_json,
                    revision, created_at, updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                    ?18, ?19
                )",
                rusqlite::params![
                    id,
                    owner_id,
                    idempotency_key,
                    fields.mode,
                    fields.status,
                    fields.stop_reason_json,
                    fields.parent_id,
                    fields.attempts_json,
                    fields.pending_approvals_json,
                    fields.next_decision_json,
                    fields.intent_json,
                    fields.frame_json,
                    fields.bounds_json,
                    fields.usage_json,
                    fields.correlation_json,
                    fields.business_state_json,
                    revision,
                    now,
                    now,
                ],
            );

            match insert {
                Ok(_) => {
                    tx.commit()?;
                    Ok(())
                }
                // Either a concurrent create_case won the race on
                // idempotency_key (TOCTOU between our SELECT and this
                // INSERT), or a stale/duplicate `id` was reused — both are
                // treated as the idempotent no-op this method promises.
                Err(rusqlite::Error::SqliteFailure(err, _))
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    tx.commit()?;
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        })
        .await?
    }

    async fn load_case(&self, owner: &str, id: &TaskCaseId) -> anyhow::Result<Option<TaskCase>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let id = id.as_str().to_string();
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let raw = conn
                .query_row(
                    &format!(
                        "SELECT {CASE_READ_COLUMNS} FROM task_cases WHERE id = ?1 AND owner_id = ?2"
                    ),
                    rusqlite::params![id, owner],
                    read_case_row,
                )
                .optional()?;
            match raw {
                Some(r) => Ok::<_, anyhow::Error>(Some(raw_to_case(r)?)),
                None => Ok(None),
            }
        })
        .await?
    }

    async fn list_cases_for_owner(&self, owner: &str) -> anyhow::Result<Vec<TaskCase>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(&format!(
                "SELECT {CASE_READ_COLUMNS} FROM task_cases WHERE owner_id = ?1 \
                 ORDER BY created_at DESC"
            ))?;
            let raws = stmt
                .query_map(rusqlite::params![owner], read_case_row)?
                .collect::<Result<Vec<_>, _>>()?;
            let cases = raws
                .into_iter()
                .map(raw_to_case)
                .collect::<anyhow::Result<Vec<TaskCase>>>()?;
            Ok::<_, anyhow::Error>(cases)
        })
        .await?
    }

    async fn list_children(
        &self,
        owner: &str,
        parent: &TaskCaseId,
    ) -> anyhow::Result<Vec<TaskCase>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let parent_id = parent.as_str().to_string();
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(&format!(
                "SELECT {CASE_READ_COLUMNS} FROM task_cases WHERE owner_id = ?1 \
                 AND parent_id = ?2 ORDER BY created_at ASC"
            ))?;
            let raws = stmt
                .query_map(rusqlite::params![owner, parent_id], read_case_row)?
                .collect::<Result<Vec<_>, _>>()?;
            let cases = raws
                .into_iter()
                .map(raw_to_case)
                .collect::<anyhow::Result<Vec<TaskCase>>>()?;
            Ok::<_, anyhow::Error>(cases)
        })
        .await?
    }

    async fn update_case(&self, case: &TaskCase, expected_revision: u64) -> anyhow::Result<u64> {
        let path = self.db_path.clone();
        let fields = case_fields(case)?;
        let id = case.id.as_str().to_string();
        let owner = case.owner.clone();
        let expected = expected_revision as i64;
        let new_revision = expected_revision.saturating_add(1) as i64;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE task_cases SET
                    mode = ?1, status = ?2, stop_reason_json = ?3, parent_id = ?4,
                    attempts_json = ?5, pending_approvals_json = ?6, next_decision_json = ?7,
                    intent_json = ?8, frame_json = ?9, bounds_json = ?10, usage_json = ?11,
                    correlation_json = ?12, business_state_json = ?13, revision = ?14,
                    updated_at = ?15
                 WHERE id = ?16 AND owner_id = ?17 AND revision = ?18",
                rusqlite::params![
                    fields.mode,
                    fields.status,
                    fields.stop_reason_json,
                    fields.parent_id,
                    fields.attempts_json,
                    fields.pending_approvals_json,
                    fields.next_decision_json,
                    fields.intent_json,
                    fields.frame_json,
                    fields.bounds_json,
                    fields.usage_json,
                    fields.correlation_json,
                    fields.business_state_json,
                    new_revision,
                    now,
                    id,
                    owner,
                    expected,
                ],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "update_case: no row matched id/owner/revision={expected} — stale \
                     expected_revision, wrong owner, or missing case (optimistic concurrency \
                     guard)"
                );
            }
            Ok::<_, anyhow::Error>(new_revision as u64)
        })
        .await?
    }

    async fn transition_status(
        &self,
        owner: &str,
        id: &TaskCaseId,
        next: TaskStatus,
        stop_reason: Option<StopReason>,
        expected_revision: u64,
    ) -> anyhow::Result<u64> {
        let next_terminal = next.is_terminal();
        let reason_given = stop_reason.is_some();
        if next_terminal != reason_given {
            anyhow::bail!(
                "transition_status: stop_reason must be Some(..) iff `next` is terminal \
                 (next={next:?}, next_terminal={next_terminal}, reason_given={reason_given})"
            );
        }
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let id_s = id.as_str().to_string();
        let next_json = serde_json::to_string(&next)?;
        let stop_reason_json = stop_reason
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let expected = expected_revision as i64;
        let new_revision = expected_revision.saturating_add(1) as i64;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let current_status: Option<String> = conn
                .query_row(
                    "SELECT status FROM task_cases WHERE id = ?1 AND owner_id = ?2",
                    rusqlite::params![id_s, owner],
                    |r| r.get(0),
                )
                .optional()?;
            let current_status = current_status
                .ok_or_else(|| anyhow::anyhow!("transition_status: case not found for owner"))?;
            let current: TaskStatus = serde_json::from_str(&current_status)?;
            if current.is_terminal() {
                anyhow::bail!(
                    "transition_status: case is already terminal ({current:?}) — a task has \
                     exactly one terminal event, ever"
                );
            }
            if !current.can_transition_to(next) {
                anyhow::bail!(
                    "transition_status: {current:?} -> {next:?} is not an allowed transition"
                );
            }
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE task_cases SET status = ?1, stop_reason_json = ?2, revision = ?3, \
                 updated_at = ?4 WHERE id = ?5 AND owner_id = ?6 AND revision = ?7",
                rusqlite::params![
                    next_json,
                    stop_reason_json,
                    new_revision,
                    now,
                    id_s,
                    owner,
                    expected,
                ],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "transition_status: revision conflict (expected {expected}) — concurrent \
                     modification between read and write"
                );
            }
            Ok::<_, anyhow::Error>(new_revision as u64)
        })
        .await?
    }

    async fn set_next_decision(
        &self,
        owner: &str,
        id: &TaskCaseId,
        decision: Option<NextDecision>,
        expected_revision: u64,
    ) -> anyhow::Result<u64> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let id_s = id.as_str().to_string();
        let decision_json = decision.as_ref().map(serde_json::to_string).transpose()?;
        let expected = expected_revision as i64;
        let new_revision = expected_revision.saturating_add(1) as i64;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE task_cases SET next_decision_json = ?1, revision = ?2, updated_at = ?3 \
                 WHERE id = ?4 AND owner_id = ?5 AND revision = ?6",
                rusqlite::params![decision_json, new_revision, now, id_s, owner, expected],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "set_next_decision: no row matched id/owner/revision={expected} — stale \
                     expected_revision, wrong owner, or missing case"
                );
            }
            Ok::<_, anyhow::Error>(new_revision as u64)
        })
        .await?
    }

    async fn append_attempt(&self, attempt: &Attempt) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let attempt_id = attempt.id.as_str().to_string();
        let task_id = attempt.task.as_str().to_string();
        let payload_json = serde_json::to_string(attempt)?;
        let started_at = attempt.started_at;
        let ended_at = attempt.ended_at;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let owner: Option<String> = conn
                .query_row(
                    "SELECT owner_id FROM task_cases WHERE id = ?1",
                    rusqlite::params![task_id],
                    |r| r.get(0),
                )
                .optional()?;
            let owner = owner.ok_or_else(|| {
                anyhow::anyhow!("append_attempt: task case {task_id} does not exist")
            })?;
            conn.execute(
                "INSERT OR IGNORE INTO task_attempts
                    (id, owner_id, task_id, payload_json, started_at, ended_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    attempt_id,
                    owner,
                    task_id,
                    payload_json,
                    started_at,
                    ended_at
                ],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    async fn load_attempt(&self, owner: &str, id: &AttemptId) -> anyhow::Result<Option<Attempt>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let id_s = id.as_str().to_string();
        spawn_blocking(move || {
            let payload: Option<String> = open_conn(&path)?
                .query_row(
                    "SELECT payload_json FROM task_attempts WHERE id = ?1 AND owner_id = ?2",
                    rusqlite::params![id_s, owner],
                    |r| r.get(0),
                )
                .optional()?;
            match payload {
                Some(p) => Ok::<_, anyhow::Error>(Some(serde_json::from_str(&p)?)),
                None => Ok(None),
            }
        })
        .await?
    }

    async fn list_attempts_for_case(
        &self,
        owner: &str,
        task: &TaskCaseId,
    ) -> anyhow::Result<Vec<Attempt>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(
                "SELECT payload_json FROM task_attempts WHERE owner_id = ?1 AND task_id = ?2 \
                 ORDER BY started_at ASC",
            )?;
            let payloads = stmt
                .query_map(rusqlite::params![owner, task_id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let attempts = payloads
                .into_iter()
                .map(|p| serde_json::from_str::<Attempt>(&p).map_err(anyhow::Error::from))
                .collect::<anyhow::Result<Vec<Attempt>>>()?;
            Ok::<_, anyhow::Error>(attempts)
        })
        .await?
    }

    async fn record_evidence(&self, owner: &str, evidence: &Evidence) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let evidence_id = evidence.id.as_str().to_string();
        let attempt_id = evidence.attempt.as_str().to_string();
        let payload_json = serde_json::to_string(evidence)?;
        let captured_at = evidence.captured_at;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let task_id: Option<String> = conn
                .query_row(
                    "SELECT task_id FROM task_attempts WHERE id = ?1 AND owner_id = ?2",
                    rusqlite::params![attempt_id, owner],
                    |r| r.get(0),
                )
                .optional()?;
            let task_id = task_id.ok_or_else(|| {
                anyhow::anyhow!(
                    "record_evidence: attempt {attempt_id} not found for owner (cannot resolve \
                     its task)"
                )
            })?;
            conn.execute(
                "INSERT OR IGNORE INTO task_evidence
                    (id, owner_id, task_id, attempt_id, payload_json, captured_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    evidence_id,
                    owner,
                    task_id,
                    attempt_id,
                    payload_json,
                    captured_at,
                ],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    async fn save_external_handle(
        &self,
        owner: &str,
        task: &TaskCaseId,
        handle: &bastion_agent_runtime::SessionHandle,
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        let handle_json = serde_json::to_string(handle)?;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            conn.execute(
                "INSERT INTO task_external_handles (task_id, owner_id, handle_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(task_id, owner_id) DO UPDATE SET handle_json = excluded.handle_json",
                rusqlite::params![task_id, owner, handle_json],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    async fn load_external_handle(
        &self,
        owner: &str,
        task: &TaskCaseId,
    ) -> anyhow::Result<Option<bastion_agent_runtime::SessionHandle>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        spawn_blocking(move || {
            let payload: Option<String> = open_conn(&path)?
                .query_row(
                    "SELECT handle_json FROM task_external_handles \
                     WHERE task_id = ?1 AND owner_id = ?2",
                    rusqlite::params![task_id, owner],
                    |r| r.get(0),
                )
                .optional()?;
            match payload {
                Some(p) => Ok::<_, anyhow::Error>(Some(serde_json::from_str(&p)?)),
                None => Ok(None),
            }
        })
        .await?
    }

    async fn delete_external_handle(&self, owner: &str, task: &TaskCaseId) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            conn.execute(
                "DELETE FROM task_external_handles WHERE task_id = ?1 AND owner_id = ?2",
                rusqlite::params![task_id, owner],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    async fn set_last_confirmed_event(
        &self,
        owner: &str,
        task: &TaskCaseId,
        marker: &str,
        expected_revision: u64,
    ) -> anyhow::Result<u64> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        let marker = marker.to_string();
        let expected = expected_revision as i64;
        let new_revision = expected_revision.saturating_add(1) as i64;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE task_cases SET last_confirmed_event = ?1, revision = ?2, \
                 updated_at = ?3 WHERE id = ?4 AND owner_id = ?5 AND revision = ?6",
                rusqlite::params![marker, new_revision, now, task_id, owner, expected],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "set_last_confirmed_event: no row matched id/owner/revision={expected}"
                );
            }
            Ok::<_, anyhow::Error>(new_revision as u64)
        })
        .await?
    }

    async fn save_checkpoint(
        &self,
        owner: &str,
        task: &TaskCaseId,
        checkpoint: &serde_json::Value,
        expected_revision: u64,
    ) -> anyhow::Result<u64> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        let checkpoint_json = checkpoint.to_string();
        let expected = expected_revision as i64;
        let new_revision = expected_revision.saturating_add(1) as i64;
        spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE task_cases SET checkpoint_json = ?1, revision = ?2, updated_at = ?3 \
                 WHERE id = ?4 AND owner_id = ?5 AND revision = ?6",
                rusqlite::params![checkpoint_json, new_revision, now, task_id, owner, expected],
            )?;
            if changed == 0 {
                anyhow::bail!("save_checkpoint: no row matched id/owner/revision={expected}");
            }
            Ok::<_, anyhow::Error>(new_revision as u64)
        })
        .await?
    }

    async fn load_checkpoint(
        &self,
        owner: &str,
        task: &TaskCaseId,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let path = self.db_path.clone();
        let owner = owner.to_string();
        let task_id = task.as_str().to_string();
        spawn_blocking(move || {
            let payload: Option<Option<String>> = open_conn(&path)?
                .query_row(
                    "SELECT checkpoint_json FROM task_cases WHERE id = ?1 AND owner_id = ?2",
                    rusqlite::params![task_id, owner],
                    |r| r.get(0),
                )
                .optional()?;
            match payload.flatten() {
                Some(p) => Ok::<_, anyhow::Error>(Some(serde_json::from_str(&p)?)),
                None => Ok(None),
            }
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{
        ArtifactRef, Bounds, CorrelationIds, EvidenceId, EvidenceKind, ExecutionMode, Frame,
        Intent, IntentOrigin, OpaqueState, UsageAccum,
    };
    use tempfile::NamedTempFile;

    async fn make_store() -> (NamedTempFile, SqliteTaskStore) {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_str().unwrap().to_owned();
        let store = SqliteTaskStore::new(path);
        store.init_schema().await.expect("init_schema");
        (f, store)
    }

    fn sample_case(id: &str, owner: &str) -> TaskCase {
        TaskCase {
            id: TaskCaseId(id.to_string()),
            owner: owner.to_string(),
            mode: ExecutionMode::Pursue,
            intent: Intent {
                owner: owner.to_string(),
                mode: ExecutionMode::Pursue,
                summary: "ship the thing".into(),
                origin: IntentOrigin::Message,
            },
            frame: Frame {
                objective: "green build".into(),
                acceptance: vec![],
                context_refs: vec![],
            },
            bounds: Bounds::default(),
            status: TaskStatus::Pending,
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

    fn sample_attempt(id: &str, task: &str) -> Attempt {
        Attempt {
            id: AttemptId(id.to_string()),
            task: TaskCaseId(task.to_string()),
            started_at: 100,
            ended_at: None,
            actions: vec![],
            belief_refs: vec![],
            usage: UsageAccum::default(),
            verdict: None,
        }
    }

    fn sample_evidence(id: &str, attempt: &str) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            attempt: AttemptId(attempt.to_string()),
            action: None,
            kind: EvidenceKind::Other,
            source_ref: ArtifactRef("artifact-1".into()),
            trusted: true,
            max_tier: None,
            captured_at: 200,
        }
    }

    #[tokio::test]
    async fn create_then_load_round_trips() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let loaded = store
            .load_case("alice", &TaskCaseId("t1".into()))
            .await
            .expect("load")
            .expect("must exist");
        assert_eq!(loaded.id, case.id);
        assert_eq!(loaded.owner, "alice");
        assert_eq!(loaded.status, TaskStatus::Pending);
        assert_eq!(loaded.revision, 1);
    }

    #[tokio::test]
    async fn create_case_is_idempotent_on_key() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "same-key").await.expect("first");
        store
            .create_case(&case, "same-key")
            .await
            .expect("second must be a no-op, not an error");

        let path = store.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_cases", [], |r| r.get(0))
            .expect("count");
        assert_eq!(
            count, 1,
            "second create with the same key must not insert a row"
        );
    }

    #[tokio::test]
    async fn update_case_rejects_stale_revision() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let mut updated = case.clone();
        updated.frame.objective = "changed".into();
        let new_rev = store.update_case(&updated, 1).await.expect("first update");
        assert_eq!(new_rev, 2);

        // Reusing the now-stale expected_revision (1) must bail.
        let stale = store.update_case(&updated, 1).await;
        assert!(stale.is_err(), "stale expected_revision must be rejected");
    }

    #[tokio::test]
    async fn transition_status_rejects_disallowed_transition() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        // Pending -> Completed is not an allowed transition.
        let result = store
            .transition_status(
                "alice",
                &case.id,
                TaskStatus::Completed,
                Some(StopReason::Completed),
                1,
            )
            .await;
        assert!(result.is_err(), "Pending -> Completed must be rejected");
    }

    #[tokio::test]
    async fn transition_status_allows_a_single_terminal_event_only() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let rev = store
            .transition_status("alice", &case.id, TaskStatus::Running, None, 1)
            .await
            .expect("Pending -> Running must succeed");
        assert_eq!(rev, 2);

        let rev = store
            .transition_status(
                "alice",
                &case.id,
                TaskStatus::Completed,
                Some(StopReason::Completed),
                rev,
            )
            .await
            .expect("Running -> Completed must succeed");
        assert_eq!(rev, 3);

        // A second terminal transition must be refused outright.
        let second_terminal = store
            .transition_status(
                "alice",
                &case.id,
                TaskStatus::Cancelled,
                Some(StopReason::Cancelled),
                rev,
            )
            .await;
        assert!(
            second_terminal.is_err(),
            "a task must never receive a second terminal transition"
        );
    }

    #[tokio::test]
    async fn transition_status_requires_stop_reason_iff_terminal() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let missing_reason = store
            .transition_status("alice", &case.id, TaskStatus::Completed, None, 1)
            .await;
        assert!(
            missing_reason.is_err(),
            "a terminal transition without a stop_reason must be rejected"
        );

        let spurious_reason = store
            .transition_status(
                "alice",
                &case.id,
                TaskStatus::Running,
                Some(StopReason::Completed),
                1,
            )
            .await;
        assert!(
            spurious_reason.is_err(),
            "a non-terminal transition with a stop_reason must be rejected"
        );
    }

    #[tokio::test]
    async fn cross_owner_isolation_on_load_and_update() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let wrong_owner_load = store
            .load_case("mallory", &case.id)
            .await
            .expect("load must not error");
        assert!(
            wrong_owner_load.is_none(),
            "loading with the wrong owner must return None, not another owner's case"
        );

        let mut forged = case.clone();
        forged.owner = "mallory".to_string();
        let wrong_owner_update = store.update_case(&forged, 1).await;
        assert!(
            wrong_owner_update.is_err(),
            "updating with the wrong owner must bail, never silently no-op"
        );
    }

    #[tokio::test]
    async fn attempt_append_and_load_round_trips() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let attempt = sample_attempt("a1", "t1");
        store.append_attempt(&attempt).await.expect("append");

        let loaded = store
            .load_attempt("alice", &AttemptId("a1".into()))
            .await
            .expect("load")
            .expect("must exist");
        assert_eq!(loaded.id, attempt.id);

        let listed = store
            .list_attempts_for_case("alice", &case.id)
            .await
            .expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, attempt.id);
    }

    #[tokio::test]
    async fn append_attempt_is_idempotent_on_id() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        let attempt = sample_attempt("a1", "t1");
        store.append_attempt(&attempt).await.expect("first append");
        store
            .append_attempt(&attempt)
            .await
            .expect("second append must be a no-op, not an error");

        let listed = store
            .list_attempts_for_case("alice", &case.id)
            .await
            .expect("list");
        assert_eq!(
            listed.len(),
            1,
            "duplicate append must not create a second row"
        );
    }

    #[tokio::test]
    async fn record_evidence_is_idempotent_on_id() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");
        let attempt = sample_attempt("a1", "t1");
        store
            .append_attempt(&attempt)
            .await
            .expect("append attempt");

        let evidence = sample_evidence("e1", "a1");
        store
            .record_evidence("alice", &evidence)
            .await
            .expect("first record");
        store
            .record_evidence("alice", &evidence)
            .await
            .expect("second record must be a no-op, not an error");

        let path = store.db_path.clone();
        let conn = open_conn(&path).expect("open_conn");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_evidence", [], |r| r.get(0))
            .expect("count");
        assert_eq!(
            count, 1,
            "duplicate record_evidence must not insert a second row"
        );
    }

    #[tokio::test]
    async fn external_handle_save_load_delete_round_trips() {
        let (_f, store) = make_store().await;
        let task = TaskCaseId("t1".into());
        let handle = bastion_agent_runtime::SessionHandle {
            runtime_id: "codex_app_server".to_string(),
            owner: "alice".to_string(),
            external_ref: "thread-abc".to_string(),
        };

        assert!(store
            .load_external_handle("alice", &task)
            .await
            .expect("load before save must not error")
            .is_none());

        store
            .save_external_handle("alice", &task, &handle)
            .await
            .expect("save");
        let loaded = store
            .load_external_handle("alice", &task)
            .await
            .expect("load")
            .expect("must exist after save");
        assert_eq!(loaded.external_ref, "thread-abc");

        store
            .delete_external_handle("alice", &task)
            .await
            .expect("delete");
        assert!(store
            .load_external_handle("alice", &task)
            .await
            .expect("load after delete must not error")
            .is_none());

        // Deleting an already-absent handle is not an error.
        store
            .delete_external_handle("alice", &task)
            .await
            .expect("second delete must be a no-op, not an error");
    }

    #[tokio::test]
    async fn checkpoint_and_last_confirmed_event_round_trip() {
        let (_f, store) = make_store().await;
        let case = sample_case("t1", "alice");
        store.create_case(&case, "key-1").await.expect("create");

        assert!(store
            .load_checkpoint("alice", &case.id)
            .await
            .expect("load before save must not error")
            .is_none());

        let checkpoint = serde_json::json!({"step": 3});
        let rev = store
            .save_checkpoint("alice", &case.id, &checkpoint, 1)
            .await
            .expect("save_checkpoint");
        assert_eq!(rev, 2);

        let loaded = store
            .load_checkpoint("alice", &case.id)
            .await
            .expect("load")
            .expect("must exist after save");
        assert_eq!(loaded, checkpoint);

        let rev = store
            .set_last_confirmed_event("alice", &case.id, "evt-42", rev)
            .await
            .expect("set_last_confirmed_event");
        assert_eq!(rev, 3);
    }
}
