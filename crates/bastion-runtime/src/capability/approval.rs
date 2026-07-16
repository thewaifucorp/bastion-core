//! Approval queue (SEC-01): an owner-scoped, idempotent gate for capabilities
//! that must never dispatch without explicit owner confirmation (irreversible
//! or destructive actions).
//!
//! This is the real mechanism behind `CapabilityRegistry::invoke()`'s Policy 2 —
//! replacing the permanent fail-closed `bail!` that existed since project
//! inception. It mirrors two established conventions in this codebase:
//! - The sqlite access idiom used throughout `memory/sqlite.rs`/`session/sqlite.rs`:
//!   `task::spawn_blocking` + `Connection::open` + `PRAGMA journal_mode=WAL;
//!   PRAGMA busy_timeout=5000;`.
//! - The owner-scoped IDOR guard established by `memory/sqlite.rs`'s
//!   `revoke_belief`: a mutating `UPDATE ... WHERE id=?1 AND owner_id=?2` that
//!   errors (never silently no-ops) when zero rows changed.
//!
//! The `approval_queue` table itself was created in Plan 11-01
//! (`src/session/sqlite.rs::init_schema`).
//!
//! Ciclo 2.1 (`docs/SECURITY-INVARIANTS.md` §1): `ApprovalStatus`,
//! `ApprovalRow`, `ApprovalOutcome` moved to `bastion-types` (pure vocabulary,
//! no SQLite logic) and re-exported here under their old path. `ApprovalQueue`
//! is renamed `SqliteApprovalGate` and implements the `ApprovalGate` port
//! (`agent::ports`) — same logic, now behind the trait a second consumer can
//! implement. `NullApprovalGate` is the explicit fail-closed default that
//! replaces the old `Option::None` "no queue wired" state.

use crate::agent::ports::ApprovalGate;
pub use bastion_types::{ApprovalOutcome, ApprovalRow, ApprovalStatus, DenyScope};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task;

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

fn parse_row(row: &rusqlite::Row) -> rusqlite::Result<ApprovalRow> {
    let status_str: String = row.get(5)?;
    let status = ApprovalStatus::from_sql_str(&status_str).map_err(|_| {
        rusqlite::Error::InvalidColumnType(5, "status".to_string(), rusqlite::types::Type::Text)
    })?;
    Ok(ApprovalRow {
        id: row.get(0)?,
        owner_id: row.get(1)?,
        capability_name: row.get(2)?,
        args_json: row.get(3)?,
        idempotency_hash: row.get(4)?,
        status,
        result_json: row.get(6)?,
        created_at: row.get(7)?,
        resolved_at: row.get(8)?,
        executed_at: row.get(9)?,
    })
}

const SELECT_COLUMNS: &str = "id, owner_id, capability_name, args_json, idempotency_hash, \
     status, result_json, created_at, resolved_at, executed_at";

fn read_row_by_hash(conn: &Connection, hash: &str) -> anyhow::Result<Option<ApprovalRow>> {
    conn.query_row(
        &format!("SELECT {SELECT_COLUMNS} FROM approval_queue WHERE idempotency_hash = ?1"),
        rusqlite::params![hash],
        parse_row,
    )
    .optional()
    .map_err(Into::into)
}

fn read_row_by_id(conn: &Connection, id: i64) -> anyhow::Result<Option<ApprovalRow>> {
    conn.query_row(
        &format!("SELECT {SELECT_COLUMNS} FROM approval_queue WHERE id = ?1"),
        rusqlite::params![id],
        parse_row,
    )
    .optional()
    .map_err(Into::into)
}

/// Translate an existing row's state into the outcome `enqueue_or_reuse` should
/// report.
///
/// Ciclo 2.1 (behavior change, `docs/SECURITY-INVARIANTS.md` §2): a
/// `Rejected` row now surfaces as `ApprovalOutcome::Rejected(DenyScope::Turn)`
/// — never the same `AlreadyPending` outcome an undecided row reports. The
/// FIRST time this happens for a given row, the row is atomically consumed
/// into the SAME terminal "resolved and done" state `record_executed` already
/// uses (`executed_at`/`result_json`) — reusing the row's EXISTING lifecycle
/// mechanism (D-03 idempotent-resume) rather than inventing a new column or
/// status. This is what keeps a denied action from becoming an unbounded
/// stream of fresh `Err`s on every later identical call: the second (and
/// every subsequent) `enqueue_or_reuse` for this hash hits the
/// `executed_at.is_some()` branch above and returns
/// `Ok(AlreadyExecuted(denial_marker))` — the same idempotent-resume contract
/// a real dispatch's cached result already gets, applied uniformly to a
/// denial. `status` stays `'rejected'` forever (never rewritten to look
/// "executed") and `resolved_at` is untouched — the audit trail (who
/// rejected it, when) is fully preserved; only `executed_at`/`result_json`
/// record that the denial was SIGNALED once. `DenyScope::Turn` is the
/// product default (§3) — the kernel tool-loop ends the turn on this Err,
/// which is the OTHER half of what prevents an in-turn retry loop.
///
/// `Expired` is unreached in production today (no code path ever sets
/// `status='expired'`) and is left mapping to `AlreadyPending`, unchanged —
/// out of this cycle's scope.
fn outcome_for_existing_row(tx: &Connection, row: ApprovalRow) -> anyhow::Result<ApprovalOutcome> {
    if row.executed_at.is_some() {
        let cached: Value = match row.result_json.as_deref() {
            Some(s) => serde_json::from_str(s)?,
            None => Value::Null,
        };
        return Ok(ApprovalOutcome::AlreadyExecuted(cached));
    }
    if row.status == ApprovalStatus::Approved {
        return Ok(ApprovalOutcome::ApprovedPendingExecution(row.id));
    }
    if row.status == ApprovalStatus::Rejected {
        let marker = serde_json::json!({
            "approval_denied": true,
            "capability": row.capability_name,
        });
        let now = now_nanos();
        tx.execute(
            "UPDATE approval_queue SET executed_at = ?2, result_json = ?3 WHERE id = ?1",
            rusqlite::params![row.id, now, marker.to_string()],
        )?;
        return Ok(ApprovalOutcome::Rejected(DenyScope::Turn));
    }
    Ok(ApprovalOutcome::AlreadyPending)
}

/// Owner-scoped, idempotent approval gate backed by the `approval_queue`
/// sqlite table (Plan 11-01). Ciclo 2.1: renamed from `ApprovalQueue` — same
/// struct, same logic, now implementing the `ApprovalGate` port below instead
/// of exposing these as bare inherent methods.
pub struct SqliteApprovalGate {
    db_path: String,
}

impl SqliteApprovalGate {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    /// Deterministic hash over (capability_name, owner, args) — the same
    /// three inputs always produce the same hash; changing any one of them
    /// changes the hash. Used as the `approval_queue.idempotency_hash` UNIQUE
    /// key (D-03). Not part of the `ApprovalGate` port — a SQLite-specific
    /// idempotency-key helper, not something a different gate implementation
    /// need share.
    pub(crate) fn compute_hash(capability_name: &str, args: &Value, owner: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(capability_name.as_bytes());
        hasher.update(b"\0");
        hasher.update(owner.as_bytes());
        hasher.update(b"\0");
        hasher.update(args.to_string().as_bytes());
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[async_trait::async_trait]
impl ApprovalGate for SqliteApprovalGate {
    /// Enqueue a new approval row for (owner_id, capability_name, args), or
    /// reuse the existing one if this exact triple was already seen.
    ///
    /// Wraps the SELECT-then-INSERT in a single sqlite transaction to close
    /// the TOCTOU race on the UNIQUE `idempotency_hash` index (T-11-01-01): if
    /// a concurrent call wins the race and inserts first, the UNIQUE
    /// constraint violation is caught here and the row is re-read instead of
    /// propagating the error.
    async fn enqueue_or_reuse(
        &self,
        owner_id: &str,
        capability_name: &str,
        args: &Value,
    ) -> anyhow::Result<ApprovalOutcome> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let capability_name = capability_name.to_owned();
        let hash = Self::compute_hash(&capability_name, args, &owner_id);
        let args_json = args.to_string();
        task::spawn_blocking(move || {
            let mut conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let tx = conn.transaction()?;

            if let Some(row) = read_row_by_hash(&tx, &hash)? {
                let outcome = outcome_for_existing_row(&tx, row)?;
                tx.commit()?;
                return Ok(outcome);
            }

            let now = now_nanos();
            let insert = tx.execute(
                "INSERT INTO approval_queue \
                    (owner_id, capability_name, args_json, idempotency_hash, status, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
                rusqlite::params![owner_id, capability_name, args_json, hash, now],
            );

            match insert {
                Ok(_) => {
                    let id = tx.last_insert_rowid();
                    tx.commit()?;
                    Ok(ApprovalOutcome::NewlyQueued(id))
                }
                // A concurrent enqueue_or_reuse call won the race on the UNIQUE
                // idempotency_hash index between our SELECT and this INSERT
                // (T-11-01-01 TOCTOU). Re-read instead of propagating — the row
                // that now exists reflects the true, already-decided state.
                Err(rusqlite::Error::SqliteFailure(err, _))
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    let row = read_row_by_hash(&tx, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "approval_queue row vanished after a UNIQUE constraint race on hash {hash}"
                        )
                    })?;
                    let outcome = outcome_for_existing_row(&tx, row)?;
                    tx.commit()?;
                    Ok(outcome)
                }
                Err(e) => Err(e.into()),
            }
        })
        .await?
    }

    /// All `status='pending'` rows for this owner. Empty vec when none exist.
    async fn pending_for_owner(&self, owner_id: &str) -> anyhow::Result<Vec<ApprovalRow>> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let mut stmt = conn.prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM approval_queue WHERE owner_id = ?1 AND status = 'pending'"
            ))?;
            let rows = stmt
                .query_map(rusqlite::params![owner_id], parse_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<Vec<ApprovalRow>, anyhow::Error>(rows)
        })
        .await?
    }

    /// Approve a pending row. Owner-scoped (IDOR guard, mirrors
    /// `revoke_belief`): errors on 0 rows changed rather than silently
    /// no-opping — a wrong `owner_id` for an existing row is always an error,
    /// never a silent pass-through.
    async fn approve(&self, owner_id: &str, id: i64) -> anyhow::Result<ApprovalRow> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE approval_queue SET status = 'approved', resolved_at = ?3 \
                 WHERE id = ?1 AND owner_id = ?2",
                rusqlite::params![id, owner_id, now],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "approval_queue row {id} not found for owner (no row approved) — IDOR guard"
                );
            }
            let row = read_row_by_id(&conn, id)?
                .ok_or_else(|| anyhow::anyhow!("approval_queue row {id} vanished after approve"))?;
            Ok::<ApprovalRow, anyhow::Error>(row)
        })
        .await?
    }

    /// Reject a pending row. Owner-scoped (IDOR guard) — same discipline as
    /// `approve`.
    async fn reject(&self, owner_id: &str, id: i64) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE approval_queue SET status = 'rejected', resolved_at = ?3 \
                 WHERE id = ?1 AND owner_id = ?2",
                rusqlite::params![id, owner_id, now],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "approval_queue row {id} not found for owner (no row rejected) — IDOR guard"
                );
            }
            Ok::<(), anyhow::Error>(())
        })
        .await?
    }

    /// Record that an approved row has now executed, caching its result for
    /// idempotent-resume (D-03) — any later `enqueue_or_reuse` for the same
    /// hash returns `AlreadyExecuted(result)` instead of re-dispatching.
    async fn record_executed(&self, id: i64, result: &Value) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let result_json = result.to_string();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let now = now_nanos();
            let changed = conn.execute(
                "UPDATE approval_queue SET executed_at = ?2, result_json = ?3 WHERE id = ?1",
                rusqlite::params![id, now, result_json],
            )?;
            if changed == 0 {
                anyhow::bail!("approval_queue row {id} not found (record_executed)");
            }
            Ok::<(), anyhow::Error>(())
        })
        .await?
    }
}

/// The explicit fail-closed default (Ciclo 2.1, `docs/SECURITY-INVARIANTS.md`
/// §1): replaces the pre-port `Option::None` "no queue wired" state.
/// `CapabilityRegistry::new()` wires this in by default — a capability with
/// `needs_approval()==true` is unusable (denied) until a real gate (e.g.
/// `SqliteApprovalGate`) is injected via `.with_approval_gate(...)`, exactly
/// like the old `None` branch of `CapabilityRegistry::invoke`'s Policy 2.
/// `pending_for_owner` returns an empty vec (never an error) so
/// `AgentLoop::approval_resolution` — which runs on EVERY turn, wired or not —
/// degrades to its existing "no pending rows" no-op path rather than failing
/// every turn.
pub struct NullApprovalGate;

#[async_trait::async_trait]
impl ApprovalGate for NullApprovalGate {
    async fn enqueue_or_reuse(
        &self,
        _owner_id: &str,
        capability_name: &str,
        _args: &Value,
    ) -> anyhow::Result<ApprovalOutcome> {
        anyhow::bail!(
            "capability '{capability_name}' requires approval but no approval gate is wired — denying fail-closed"
        );
    }

    async fn pending_for_owner(&self, _owner_id: &str) -> anyhow::Result<Vec<ApprovalRow>> {
        Ok(Vec::new())
    }

    async fn approve(&self, _owner_id: &str, id: i64) -> anyhow::Result<ApprovalRow> {
        anyhow::bail!("no approval gate is wired — cannot approve row {id}");
    }

    async fn reject(&self, _owner_id: &str, id: i64) -> anyhow::Result<()> {
        anyhow::bail!("no approval gate is wired — cannot reject row {id}");
    }

    async fn record_executed(&self, id: i64, _result: &Value) -> anyhow::Result<()> {
        anyhow::bail!("no approval gate is wired — cannot record execution for row {id}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    async fn make_queue() -> (NamedTempFile, SqliteApprovalGate) {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let session = crate::session::SessionManager::new(&path);
        session.init_schema().await.expect("init_schema");
        (f, SqliteApprovalGate::new(path))
    }

    fn count_rows(path: &str, hash: &str) -> i64 {
        let conn = Connection::open(path).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM approval_queue WHERE idempotency_hash = ?1",
            rusqlite::params![hash],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn compute_hash_is_deterministic_and_input_sensitive() {
        let args = serde_json::json!({"amount": 10});
        let h1 = SqliteApprovalGate::compute_hash("send_payment", &args, "alice");
        let h2 = SqliteApprovalGate::compute_hash("send_payment", &args, "alice");
        assert_eq!(h1, h2, "same inputs must always produce the same hash");

        let diff_owner = SqliteApprovalGate::compute_hash("send_payment", &args, "bob");
        assert_ne!(h1, diff_owner, "different owner must change the hash");

        let diff_cap = SqliteApprovalGate::compute_hash("send_email", &args, "alice");
        assert_ne!(
            h1, diff_cap,
            "different capability_name must change the hash"
        );

        let diff_args = serde_json::json!({"amount": 20});
        let diff_args_hash = SqliteApprovalGate::compute_hash("send_payment", &diff_args, "alice");
        assert_ne!(h1, diff_args_hash, "different args must change the hash");
    }

    #[tokio::test]
    async fn enqueue_or_reuse_twice_reuses_the_same_row() {
        let (_f, queue) = make_queue().await;
        let path = queue.db_path.clone();
        let args = serde_json::json!({"amount": 10});

        let first = queue
            .enqueue_or_reuse("alice", "send_payment", &args)
            .await
            .unwrap();
        assert!(matches!(first, ApprovalOutcome::NewlyQueued(_)));

        let second = queue
            .enqueue_or_reuse("alice", "send_payment", &args)
            .await
            .unwrap();
        assert!(matches!(second, ApprovalOutcome::AlreadyPending));

        let hash = SqliteApprovalGate::compute_hash("send_payment", &args, "alice");
        assert_eq!(
            count_rows(&path, &hash),
            1,
            "second call must not insert a second row"
        );
    }

    #[tokio::test]
    async fn approved_and_executed_row_is_cached_and_never_rerun() {
        let (_f, queue) = make_queue().await;
        let args = serde_json::json!({"amount": 10});

        let outcome = queue
            .enqueue_or_reuse("alice", "send_payment", &args)
            .await
            .unwrap();
        let id = match outcome {
            ApprovalOutcome::NewlyQueued(id) => id,
            other => panic!("expected NewlyQueued, got {other:?}"),
        };

        queue.approve("alice", id).await.expect("approve");
        let cached_result = serde_json::json!({"status": "sent", "tx_id": "abc123"});
        queue
            .record_executed(id, &cached_result)
            .await
            .expect("record_executed");

        let third = queue
            .enqueue_or_reuse("alice", "send_payment", &args)
            .await
            .unwrap();
        match third {
            ApprovalOutcome::AlreadyExecuted(result) => {
                assert_eq!(result, cached_result, "must return the exact cached JSON")
            }
            other => panic!("expected AlreadyExecuted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn approve_and_reject_with_wrong_owner_errors_idor_guard() {
        let (_f, queue) = make_queue().await;
        let args = serde_json::json!({"amount": 10});

        let outcome = queue
            .enqueue_or_reuse("alice", "send_payment", &args)
            .await
            .unwrap();
        let id = match outcome {
            ApprovalOutcome::NewlyQueued(id) => id,
            other => panic!("expected NewlyQueued, got {other:?}"),
        };

        let approve_wrong = queue.approve("mallory", id).await;
        assert!(
            approve_wrong.is_err(),
            "approve() with the wrong owner_id must error, never silently no-op"
        );

        let reject_wrong = queue.reject("mallory", id).await;
        assert!(
            reject_wrong.is_err(),
            "reject() with the wrong owner_id must error, never silently no-op"
        );
    }

    #[tokio::test]
    async fn pending_for_owner_returns_only_that_owners_pending_rows() {
        let (_f, queue) = make_queue().await;

        let empty = queue.pending_for_owner("alice").await.unwrap();
        assert!(
            empty.is_empty(),
            "must return an empty vec when no rows exist"
        );

        queue
            .enqueue_or_reuse("alice", "send_payment", &serde_json::json!({"amount": 10}))
            .await
            .unwrap();
        queue
            .enqueue_or_reuse("alice", "send_email", &serde_json::json!({"to": "x"}))
            .await
            .unwrap();
        queue
            .enqueue_or_reuse("bob", "send_payment", &serde_json::json!({"amount": 5}))
            .await
            .unwrap();

        let alice_pending = queue.pending_for_owner("alice").await.unwrap();
        assert_eq!(alice_pending.len(), 2);
        assert!(alice_pending.iter().all(|r| r.owner_id == "alice"));
        assert!(alice_pending
            .iter()
            .all(|r| r.status == ApprovalStatus::Pending));

        let bob_pending = queue.pending_for_owner("bob").await.unwrap();
        assert_eq!(bob_pending.len(), 1);
    }

    // --- Ciclo 2.1 (docs/SECURITY-INVARIANTS.md §2): typed
    // rejection + one-time consumption ---------------------------------

    #[tokio::test]
    async fn rejected_row_surfaces_rejected_turn_once_then_already_executed() {
        let (_f, queue) = make_queue().await;
        let args = serde_json::json!({});
        let outcome = queue
            .enqueue_or_reuse("alice", "cap_a", &args)
            .await
            .unwrap();
        let id = match outcome {
            ApprovalOutcome::NewlyQueued(id) => id,
            other => panic!("expected NewlyQueued, got {other:?}"),
        };
        queue.reject("alice", id).await.unwrap();

        // First re-invoke after reject: typed Rejected(Turn) — this is the
        // signal `CapabilityRegistry::invoke` turns into `Err(ApprovalDenied)`.
        let first = queue
            .enqueue_or_reuse("alice", "cap_a", &args)
            .await
            .unwrap();
        assert!(
            matches!(first, ApprovalOutcome::Rejected(DenyScope::Turn)),
            "a freshly-rejected row must surface as Rejected(Turn), not AlreadyPending; got {first:?}"
        );

        // Second re-invoke: the row was consumed into the SAME terminal state
        // `record_executed` uses — never an unbounded stream of fresh Errs for
        // the identical (owner, capability, args) triple.
        let second = queue
            .enqueue_or_reuse("alice", "cap_a", &args)
            .await
            .unwrap();
        assert!(
            matches!(second, ApprovalOutcome::AlreadyExecuted(_)),
            "a Rejected row must be consumed after signaling once — got {second:?}"
        );
        if let ApprovalOutcome::AlreadyExecuted(marker) = second {
            assert_eq!(marker["approval_denied"], serde_json::json!(true));
            assert_eq!(marker["capability"], serde_json::json!("cap_a"));
        }
    }

    #[tokio::test]
    async fn rejected_row_status_and_resolved_at_are_preserved_after_consumption() {
        let (_f, queue) = make_queue().await;
        let path = queue.db_path.clone();
        let args = serde_json::json!({});
        let outcome = queue
            .enqueue_or_reuse("alice", "cap_a", &args)
            .await
            .unwrap();
        let id = match outcome {
            ApprovalOutcome::NewlyQueued(id) => id,
            other => panic!("expected NewlyQueued, got {other:?}"),
        };
        queue.reject("alice", id).await.unwrap();
        // Consume the denial signal (mirrors what a real invoke() does).
        let _ = queue
            .enqueue_or_reuse("alice", "cap_a", &args)
            .await
            .unwrap();

        let conn = Connection::open(&path).unwrap();
        let row = read_row_by_id(&conn, id).unwrap().expect("row must exist");
        assert_eq!(
            row.status,
            ApprovalStatus::Rejected,
            "status must stay 'rejected' forever — auditing who rejected it must never be \
             overwritten to look like a normal execution"
        );
        assert!(
            row.resolved_at.is_some(),
            "resolved_at (set by reject()) must be preserved"
        );
        assert!(
            row.executed_at.is_some(),
            "executed_at is now set — this is the consumption marker, not a claim the \
             capability actually ran"
        );
    }
}
