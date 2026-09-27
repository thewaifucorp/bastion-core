//! Reconciliation (§5.5, BMD-22, BMD-23): when an ex-primary of epoch `e`
//! meets the current primary (epoch `e+k`), what it wrote during `e` that
//! the current one never saw is re-applied here as **proposals** from that
//! device.
//!
//! - `BeliefStored`, `SessionAppended`, `PersonaChanged`, `ConfigChanged`:
//!   union, applied automatically (beliefs are append-only, D-15).
//! - `BeliefRevoked` / `BeliefSuperseded` on a belief this side also revoked
//!   or superseded since the fork: an item in the [`ConflictQueue`]; the
//!   owner decides. Both versions are kept in the queue until then — nothing
//!   is dropped silently.
//!
//! Every accepted proposal is also recorded in this primary's log (keeping
//! its origin), so it replicates onward like any write.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::log::{apply_to_memory, EventLog};
use super::replica::{GlobalId, MemoryEvent, MemoryEventKind};
use crate::memory::Memory;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS device_conflicts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    belief     TEXT NOT NULL,
    ours       TEXT NOT NULL,
    theirs     TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL
);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictStatus {
    Pending,
    KeptOurs,
    TookTheirs,
}

impl ConflictStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::KeptOurs => "kept_ours",
            Self::TookTheirs => "took_theirs",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "kept_ours" => Self::KeptOurs,
            "took_theirs" => Self::TookTheirs,
            _ => Self::Pending,
        }
    }
}

/// Two changes to one belief, one from each side of a partition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    pub id: i64,
    pub belief: GlobalId,
    /// What this primary did to the belief.
    pub ours: MemoryEvent,
    /// What the returning ex-primary did to it.
    pub theirs: MemoryEvent,
    pub status: ConflictStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Keep this side's change; theirs stays recorded in the queue.
    KeepOurs,
    /// Apply their change as well.
    TakeTheirs,
}

/// The owner's queue of conflicts to decide.
pub struct ConflictQueue {
    conn: Mutex<Connection>,
}

impl ConflictQueue {
    pub fn open(db_path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn add(
        &self,
        belief: &GlobalId,
        ours: &MemoryEvent,
        theirs: &MemoryEvent,
    ) -> anyhow::Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO device_conflicts (belief, ours, theirs, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                serde_json::to_string(belief)?,
                serde_json::to_string(ours)?,
                serde_json::to_string(theirs)?,
                theirs.at
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, String, String, String, String)> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    }

    fn decode(raw: (i64, String, String, String, String)) -> anyhow::Result<Conflict> {
        let (id, belief, ours, theirs, status) = raw;
        Ok(Conflict {
            id,
            belief: serde_json::from_str(&belief)?,
            ours: serde_json::from_str(&ours)?,
            theirs: serde_json::from_str(&theirs)?,
            status: ConflictStatus::parse(&status),
        })
    }

    pub fn get(&self, id: i64) -> anyhow::Result<Option<Conflict>> {
        let raw = self
            .conn()
            .query_row(
                "SELECT id, belief, ours, theirs, status FROM device_conflicts WHERE id = ?1",
                params![id],
                Self::row,
            )
            .optional()?;
        raw.map(Self::decode).transpose()
    }

    /// Everything the owner still has to decide, oldest first.
    pub fn pending(&self) -> anyhow::Result<Vec<Conflict>> {
        let conn = self.conn();
        let mut statement = conn.prepare(
            "SELECT id, belief, ours, theirs, status FROM device_conflicts
             WHERE status = 'pending' ORDER BY id",
        )?;
        let rows = statement.query_map([], Self::row)?;
        rows.map(|row| Self::decode(row?)).collect()
    }

    /// The owner's decision. `TakeTheirs` applies their change to `memory`
    /// and records it in `log`.
    pub async fn resolve(
        &self,
        id: i64,
        resolution: Resolution,
        memory: &dyn Memory,
        log: &EventLog,
    ) -> anyhow::Result<Conflict> {
        let mut conflict = self
            .get(id)?
            .ok_or_else(|| anyhow::anyhow!("no conflict {id}"))?;
        if conflict.status != ConflictStatus::Pending {
            anyhow::bail!("conflict {id} was already decided");
        }
        let status = match resolution {
            Resolution::KeepOurs => ConflictStatus::KeptOurs,
            Resolution::TakeTheirs => {
                apply_to_memory(memory, log, std::slice::from_ref(&conflict.theirs)).await?;
                log.record_from(conflict.theirs.origin.clone(), conflict.theirs.kind.clone())?;
                ConflictStatus::TookTheirs
            }
        };
        self.conn().execute(
            "UPDATE device_conflicts SET status = ?1 WHERE id = ?2",
            params![status.as_str(), id],
        )?;
        conflict.status = status;
        Ok(conflict)
    }
}

/// What a reconciliation did.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ReconcileReport {
    /// Proposals accepted, in order (the host restores the session, persona
    /// and config ones).
    pub applied: Vec<MemoryEvent>,
    /// Conflict ids queued for the owner.
    pub conflicts: Vec<i64>,
    /// Proposals this side already had.
    pub already_known: usize,
}

/// The belief an event changes (revoke/supersede) — the one a conflict is
/// about.
fn target(kind: &MemoryEventKind) -> Option<&GlobalId> {
    match kind {
        MemoryEventKind::BeliefRevoked { id } => Some(id),
        MemoryEventKind::BeliefSuperseded { old, .. } => Some(old),
        _ => None,
    }
}

/// Reconcile `theirs` — what an ex-primary wrote as primary of `epoch` —
/// into this primary's `memory` and `log`.
pub async fn reconcile(
    memory: &dyn Memory,
    log: &EventLog,
    queue: &ConflictQueue,
    epoch: u64,
    theirs: Vec<MemoryEvent>,
) -> anyhow::Result<ReconcileReport> {
    // What this side changed since the fork: every event of a newer epoch.
    let ours: Vec<MemoryEvent> = log
        .since(None)?
        .into_iter()
        .filter(|e| e.epoch > epoch)
        .collect();
    let mut report = ReconcileReport::default();
    for event in theirs.into_iter().filter(|e| e.epoch == epoch) {
        if let MemoryEventKind::BeliefStored { id, .. } = &event.kind {
            if log.is_known(id)? {
                report.already_known += 1;
                continue;
            }
        }
        if let Some(belief) = target(&event.kind) {
            if let Some(clash) = ours.iter().find(|mine| target(&mine.kind) == Some(belief)) {
                report.conflicts.push(queue.add(belief, clash, &event)?);
                continue;
            }
        }
        apply_to_memory(memory, log, std::slice::from_ref(&event)).await?;
        log.record_from(event.origin.clone(), event.kind.clone())?;
        report.applied.push(event);
    }
    Ok(report)
}
