//! Loop 3-A / 6a (`docs/revamp/C3-runtime-followups-design.md` §6a):
//! owner-scoped, persisted cross-turn queue for a harness's
//! [`bastion_agent_runtime::RuntimeEvent::PermissionRequest`] events.
//!
//! Mirrors `capability/approval.rs`'s conventions exactly (same sqlite
//! access idiom: `task::spawn_blocking` + `Connection::open` + `PRAGMA
//! journal_mode=WAL; PRAGMA busy_timeout=5000;`; same owner-scoped IDOR
//! guard: a mutating `UPDATE ... WHERE id=?1 AND owner_id=?2` that errors,
//! never silently no-ops, when zero rows changed) but is a DELIBERATELY
//! separate table/trait/impl from `ApprovalGate`/`approval_queue` — see
//! [`crate::agent::ports::PendingPermission`]'s rustdoc for why the two
//! vocabularies don't share a contract.
//!
//! The `permission_queue` table itself was added in this cycle
//! (`session/sqlite.rs::init_schema`).

use crate::agent::ports::{PendingPermission, PermissionGate};
use bastion_agent_runtime::{
    PermissionAction, PermissionDecision, PermissionRequestId, SessionHandle,
};
use rusqlite::{Connection, OptionalExtension};
use tokio::task;

fn open_conn(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    Ok(conn)
}

const SELECT_COLUMNS: &str = "id, req_id, owner_id, session_runtime_id, session_owner, \
     session_external_ref, action_json, detail, raised_at, expires_at";

fn parse_row(row: &rusqlite::Row) -> rusqlite::Result<PendingPermission> {
    let req_id: i64 = row.get(1)?;
    let action_json: String = row.get(6)?;
    let action: PermissionAction = serde_json::from_str(&action_json).map_err(|_| {
        rusqlite::Error::InvalidColumnType(
            6,
            "action_json".to_string(),
            rusqlite::types::Type::Text,
        )
    })?;
    Ok(PendingPermission {
        row_id: row.get(0)?,
        id: PermissionRequestId(req_id as u64),
        owner: row.get(2)?,
        session: SessionHandle {
            runtime_id: row.get(3)?,
            owner: row.get(4)?,
            external_ref: row.get(5)?,
        },
        action,
        detail: row.get(7)?,
        raised_at: row.get(8)?,
        expires_at: row.get(9)?,
    })
}

/// SQLite-backed [`PermissionGate`] — the production implementation.
pub struct SqlitePermissionGate {
    db_path: String,
}

impl SqlitePermissionGate {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }
}

#[async_trait::async_trait]
impl PermissionGate for SqlitePermissionGate {
    async fn enqueue(
        &self,
        owner_id: &str,
        session: &SessionHandle,
        id: PermissionRequestId,
        action: &PermissionAction,
        detail: &str,
        raised_at: i64,
        expires_at: i64,
    ) -> anyhow::Result<i64> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let session = session.clone();
        let req_id = id.0 as i64;
        let action_json = serde_json::to_string(action)?;
        let detail = detail.to_owned();
        task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            conn.execute(
                "INSERT INTO permission_queue \
                    (req_id, owner_id, session_runtime_id, session_owner, session_external_ref, \
                     action_json, detail, status, raised_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)",
                rusqlite::params![
                    req_id,
                    owner_id,
                    session.runtime_id,
                    session.owner,
                    session.external_ref,
                    action_json,
                    detail,
                    raised_at,
                    expires_at,
                ],
            )?;
            Ok::<i64, anyhow::Error>(conn.last_insert_rowid())
        })
        .await?
    }

    async fn pending_for_owner(&self, owner_id: &str) -> anyhow::Result<Vec<PendingPermission>> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let mut stmt = conn.prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM permission_queue WHERE owner_id = ?1 AND status = 'pending'"
            ))?;
            let rows = stmt
                .query_map(rusqlite::params![owner_id], parse_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<Vec<PendingPermission>, anyhow::Error>(rows)
        })
        .await?
    }

    async fn resolve(
        &self,
        owner_id: &str,
        row_id: i64,
        decision: PermissionDecision,
    ) -> anyhow::Result<PendingPermission> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let decision_json = serde_json::to_string(&decision)?;
        task::spawn_blocking(move || {
            let conn = open_conn(&path)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;
            let changed = conn.execute(
                "UPDATE permission_queue SET status = 'resolved', decision_json = ?4, resolved_at = ?3 \
                 WHERE id = ?1 AND owner_id = ?2 AND status = 'pending'",
                rusqlite::params![row_id, owner_id, now, decision_json],
            )?;
            if changed == 0 {
                anyhow::bail!(
                    "permission_queue row {row_id} not found for owner (or already resolved) — \
                     IDOR guard / race-lost, no row resolved"
                );
            }
            let row = conn
                .query_row(
                    &format!("SELECT {SELECT_COLUMNS} FROM permission_queue WHERE id = ?1"),
                    rusqlite::params![row_id],
                    parse_row,
                )
                .optional()?
                .ok_or_else(|| {
                    anyhow::anyhow!("permission_queue row {row_id} vanished after resolve")
                })?;
            Ok::<PendingPermission, anyhow::Error>(row)
        })
        .await?
    }
}

/// Loop 3-A (6a) fail-closed default: `AgentLoop` uses this until a real
/// `with_permission_gate(...)` is injected (`main.rs` wires
/// [`SqlitePermissionGate`]). `enqueue` always errors — nothing is ever
/// genuinely persisted/paused — so the caller's own fallback (an immediate
/// `Deny { scope: Turn }`) is what a permission request resolves to: exactly
/// today's pre-6a behavior, byte-identical for any deployment that doesn't
/// opt in.
pub struct NullPermissionGate;

#[async_trait::async_trait]
impl PermissionGate for NullPermissionGate {
    async fn enqueue(
        &self,
        _owner_id: &str,
        _session: &SessionHandle,
        id: PermissionRequestId,
        _action: &PermissionAction,
        _detail: &str,
        _raised_at: i64,
        _expires_at: i64,
    ) -> anyhow::Result<i64> {
        anyhow::bail!(
            "permission request {id:?} cannot be queued — no PermissionGate is wired \
             (fail-closed immediate deny)"
        );
    }

    async fn pending_for_owner(&self, _owner_id: &str) -> anyhow::Result<Vec<PendingPermission>> {
        Ok(Vec::new())
    }

    async fn resolve(
        &self,
        _owner_id: &str,
        row_id: i64,
        _decision: PermissionDecision,
    ) -> anyhow::Result<PendingPermission> {
        anyhow::bail!("no PermissionGate is wired — cannot resolve permission request {row_id}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_agent_runtime::DenyScope;
    use tempfile::NamedTempFile;

    async fn make_gate() -> (NamedTempFile, SqlitePermissionGate) {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let session = crate::session::SessionManager::new(&path);
        session.init_schema().await.expect("init_schema");
        (f, SqlitePermissionGate::new(path))
    }

    fn fake_session() -> SessionHandle {
        SessionHandle {
            runtime_id: "fake".to_string(),
            owner: "alice".to_string(),
            external_ref: "fake-session-1".to_string(),
        }
    }

    #[tokio::test]
    async fn enqueue_then_pending_for_owner_round_trips_every_field() {
        let (_f, gate) = make_gate().await;
        let session = fake_session();
        let row_id = gate
            .enqueue(
                "alice",
                &session,
                PermissionRequestId(7),
                &PermissionAction::RunCommand,
                "run: rm -rf /tmp/x",
                1_000,
                2_000,
            )
            .await
            .expect("enqueue");

        let pending = gate.pending_for_owner("alice").await.expect("pending");
        assert_eq!(pending.len(), 1);
        let row = &pending[0];
        assert_eq!(row.row_id, row_id);
        assert_eq!(row.id, PermissionRequestId(7));
        assert_eq!(row.owner, "alice");
        assert_eq!(row.session, session);
        assert!(matches!(row.action, PermissionAction::RunCommand));
        assert_eq!(row.detail, "run: rm -rf /tmp/x");
        assert_eq!(row.raised_at, 1_000);
        assert_eq!(row.expires_at, 2_000);

        // A different owner sees nothing.
        assert!(gate
            .pending_for_owner("bob")
            .await
            .expect("pending bob")
            .is_empty());
    }

    #[tokio::test]
    async fn resolve_removes_from_pending_and_records_decision() {
        let (_f, gate) = make_gate().await;
        let session = fake_session();
        let row_id = gate
            .enqueue(
                "alice",
                &session,
                PermissionRequestId(1),
                &PermissionAction::WriteFile,
                "write: /tmp/x",
                0,
                999_999,
            )
            .await
            .expect("enqueue");

        let resolved = gate
            .resolve(
                "alice",
                row_id,
                PermissionDecision::Deny {
                    scope: DenyScope::Turn,
                },
            )
            .await
            .expect("resolve");
        assert_eq!(resolved.row_id, row_id);

        assert!(
            gate.pending_for_owner("alice")
                .await
                .expect("pending")
                .is_empty(),
            "resolved row must no longer be pending"
        );
    }

    #[tokio::test]
    async fn resolve_with_wrong_owner_errors_idor_guard() {
        let (_f, gate) = make_gate().await;
        let session = fake_session();
        let row_id = gate
            .enqueue(
                "alice",
                &session,
                PermissionRequestId(1),
                &PermissionAction::UseTool,
                "detail",
                0,
                999_999,
            )
            .await
            .expect("enqueue");

        let err = gate
            .resolve("mallory", row_id, PermissionDecision::Allow)
            .await;
        assert!(
            err.is_err(),
            "resolve() with the wrong owner_id must error, never silently no-op"
        );

        // Row must still be pending for the REAL owner (untouched by the bad attempt).
        assert_eq!(gate.pending_for_owner("alice").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resolve_twice_errors_on_second_call_first_write_wins() {
        let (_f, gate) = make_gate().await;
        let session = fake_session();
        let row_id = gate
            .enqueue(
                "alice",
                &session,
                PermissionRequestId(1),
                &PermissionAction::Network,
                "detail",
                0,
                999_999,
            )
            .await
            .expect("enqueue");

        gate.resolve("alice", row_id, PermissionDecision::Allow)
            .await
            .expect("first resolve must succeed");
        let second = gate
            .resolve(
                "alice",
                row_id,
                PermissionDecision::Deny {
                    scope: DenyScope::Turn,
                },
            )
            .await;
        assert!(
            second.is_err(),
            "a second resolve() on an already-resolved row must error, not silently re-decide"
        );
    }

    #[tokio::test]
    async fn null_permission_gate_enqueue_always_errors() {
        let gate = NullPermissionGate;
        let session = fake_session();
        let err = gate
            .enqueue(
                "alice",
                &session,
                PermissionRequestId(1),
                &PermissionAction::RunCommand,
                "detail",
                0,
                0,
            )
            .await;
        assert!(
            err.is_err(),
            "NullPermissionGate must fail-closed on enqueue — no persistent queue is wired"
        );
    }

    #[tokio::test]
    async fn null_permission_gate_pending_for_owner_is_empty_never_errors() {
        let gate = NullPermissionGate;
        assert!(gate
            .pending_for_owner("alice")
            .await
            .expect("must not error")
            .is_empty());
    }
}
