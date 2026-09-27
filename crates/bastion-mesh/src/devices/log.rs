//! The primary's memory event log and the `Memory` decorator that feeds it.
//!
//! [`EventLog`] is a SQLite table of [`MemoryEvent`]s with a gapless `seq`,
//! plus the map between [`GlobalId`]s and this device's local belief ids.
//! [`LoggedMemory`] wraps the primary's `Memory`: every belief it stores,
//! revokes or supersedes also becomes an event, which the replicator sends
//! to replica nodes (BMD-16). Weight tweaks, outcome counters and pending
//! corrections are local learning signals and are not replicated.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::broadcast;

use super::enrollment::DeviceId;
use super::replica::{BeliefPayload, GlobalId, MemoryEvent, MemoryEventKind, Procedural};
use crate::memory::{Belief, BeliefDraft, Memory, Outcome, PendingCorrection, PrivacyTier};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS device_memory_events (
    seq    INTEGER PRIMARY KEY,
    epoch  INTEGER NOT NULL,
    origin TEXT NOT NULL,
    at     INTEGER NOT NULL,
    kind   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_global_ids (
    origin       TEXT NOT NULL,
    origin_local INTEGER NOT NULL,
    local        INTEGER NOT NULL UNIQUE,
    owner        TEXT NOT NULL,
    PRIMARY KEY (origin, origin_local)
);
";

/// Append-only log of this primary's memory writes.
pub struct EventLog {
    conn: Mutex<Connection>,
    origin: DeviceId,
    epoch: AtomicU64,
    /// Last hybrid-logical-clock value handed out.
    clock: Mutex<i64>,
    tx: broadcast::Sender<MemoryEvent>,
}

fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

impl EventLog {
    /// Open (creating the tables) the log in `db_path` for events written
    /// by `origin` during `epoch`.
    pub fn open(db_path: &str, origin: DeviceId, epoch: u64) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        conn.execute_batch(SCHEMA)?;
        let last_at: Option<i64> = conn
            .query_row("SELECT MAX(at) FROM device_memory_events", [], |r| r.get(0))
            .optional()?
            .flatten();
        let (tx, _) = broadcast::channel(1024);
        Ok(Self {
            conn: Mutex::new(conn),
            origin,
            epoch: AtomicU64::new(epoch),
            clock: Mutex::new(last_at.unwrap_or(0)),
            tx,
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn origin(&self) -> &DeviceId {
        &self.origin
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// The epoch new events are stamped with (after a promotion).
    pub fn set_epoch(&self, epoch: u64) {
        self.epoch.store(epoch, Ordering::SeqCst);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MemoryEvent> {
        self.tx.subscribe()
    }

    fn tick(&self) -> i64 {
        let mut clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        *clock = now_nanos().max(*clock + 1);
        *clock
    }

    /// Append an event written here, now.
    pub fn record(&self, kind: MemoryEventKind) -> anyhow::Result<MemoryEvent> {
        let at = self.tick();
        let event = {
            let conn = self.conn();
            let seq = conn.query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM device_memory_events",
                [],
                |r| r.get::<_, i64>(0),
            )? as u64;
            let event = MemoryEvent {
                seq,
                epoch: self.epoch(),
                origin: self.origin.clone(),
                at,
                kind,
            };
            insert(&conn, &event)?;
            event
        };
        let _ = self.tx.send(event.clone());
        Ok(event)
    }

    /// Append an event that happened elsewhere, keeping its `seq` (a replica
    /// being turned into this primary's log at promotion). Events at or
    /// below the current last `seq` are skipped.
    pub fn import(&self, event: &MemoryEvent) -> anyhow::Result<bool> {
        let conn = self.conn();
        let last = conn.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM device_memory_events",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64;
        if event.seq <= last {
            return Ok(false);
        }
        insert(&conn, event)?;
        let mut clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        *clock = (*clock).max(event.at);
        Ok(true)
    }

    pub fn last_seq(&self) -> anyhow::Result<Option<u64>> {
        Ok(self
            .conn()
            .query_row("SELECT MAX(seq) FROM device_memory_events", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten()
            .map(|seq| seq as u64))
    }

    /// Events with `seq` greater than `after` (all of them for `None`), in
    /// order.
    pub fn since(&self, after: Option<u64>) -> anyhow::Result<Vec<MemoryEvent>> {
        let conn = self.conn();
        let mut statement = conn.prepare(
            "SELECT seq, epoch, origin, at, kind FROM device_memory_events
             WHERE seq > ?1 ORDER BY seq",
        )?;
        let rows = statement.query_map(params![after.unwrap_or(0) as i64], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (seq, epoch, origin, at, kind) = row?;
            Ok(MemoryEvent {
                seq,
                epoch,
                origin: DeviceId::new(origin),
                at,
                kind: serde_json::from_str(&kind)?,
            })
        })
        .collect()
    }

    /// Events of `epoch` only, in order — what a returning ex-primary wrote
    /// during its epoch (reconciliation).
    pub fn of_epoch(&self, epoch: u64) -> anyhow::Result<Vec<MemoryEvent>> {
        Ok(self
            .since(None)?
            .into_iter()
            .filter(|e| e.epoch == epoch)
            .collect())
    }

    /// Record that local belief `local` of `owner` is `id` everywhere.
    pub fn map(&self, id: &GlobalId, local: i64, owner: &str) -> anyhow::Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO device_global_ids (origin, origin_local, local, owner)
             VALUES (?1, ?2, ?3, ?4)",
            params![id.origin.as_str(), id.local, local, owner],
        )?;
        Ok(())
    }

    /// Local id and owner of a mapped global id.
    fn mapped(&self, id: &GlobalId) -> anyhow::Result<Option<(i64, String)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT local, owner FROM device_global_ids WHERE origin = ?1 AND origin_local = ?2",
                params![id.origin.as_str(), id.local],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// The global id of a local belief: its mapped id, or — for a belief
    /// created here and never mapped — `(this device, local)`.
    pub fn global_id(&self, local: i64) -> anyhow::Result<GlobalId> {
        let mapped: Option<(String, i64)> = self
            .conn()
            .query_row(
                "SELECT origin, origin_local FROM device_global_ids WHERE local = ?1",
                params![local],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match mapped {
            Some((origin, origin_local)) => GlobalId {
                origin: DeviceId::new(origin),
                local: origin_local,
            },
            None => GlobalId {
                origin: self.origin.clone(),
                local,
            },
        })
    }

    /// The local belief a global id refers to, if it exists here.
    pub fn local_id(&self, id: &GlobalId) -> anyhow::Result<Option<i64>> {
        let mapped: Option<i64> = self
            .conn()
            .query_row(
                "SELECT local FROM device_global_ids WHERE origin = ?1 AND origin_local = ?2",
                params![id.origin.as_str(), id.local],
                |r| r.get(0),
            )
            .optional()?;
        Ok(mapped.or((id.origin == self.origin).then_some(id.local)))
    }
}

fn insert(conn: &Connection, event: &MemoryEvent) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO device_memory_events (seq, epoch, origin, at, kind) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event.seq as i64,
            event.epoch as i64,
            event.origin.as_str(),
            event.at,
            serde_json::to_string(&event.kind)?
        ],
    )?;
    Ok(())
}

/// The primary's `Memory`, logging every belief write (BMD-16).
pub struct LoggedMemory {
    inner: Box<dyn Memory>,
    log: std::sync::Arc<EventLog>,
}

impl LoggedMemory {
    pub fn new(inner: Box<dyn Memory>, log: std::sync::Arc<EventLog>) -> Self {
        Self { inner, log }
    }

    pub fn log(&self) -> &std::sync::Arc<EventLog> {
        &self.log
    }

    fn stored(&self, local: i64, belief: BeliefPayload) -> anyhow::Result<()> {
        let id = self.log.global_id(local)?;
        self.log.map(&id, local, &belief.owner_id)?;
        self.log
            .record(MemoryEventKind::BeliefStored { id, belief })?;
        Ok(())
    }
}

#[async_trait]
impl Memory for LoggedMemory {
    async fn store_belief(
        &self,
        owner_id: &str,
        persona_tag: Option<&str>,
        content: &str,
        session_id: &str,
        source: &str,
        is_core: bool,
        tier: Option<PrivacyTier>,
    ) -> anyhow::Result<i64> {
        let local = self
            .inner
            .store_belief(
                owner_id,
                persona_tag,
                content,
                session_id,
                source,
                is_core,
                tier,
            )
            .await?;
        self.stored(
            local,
            BeliefPayload {
                owner_id: owner_id.into(),
                persona_tag: persona_tag.map(Into::into),
                content: content.into(),
                session_id: session_id.into(),
                source: source.into(),
                is_core,
                tier,
                procedural: None,
            },
        )?;
        Ok(local)
    }

    async fn retrieve_tagged(
        &self,
        owner_id: &str,
        persona_tag: Option<&str>,
    ) -> anyhow::Result<Vec<Belief>> {
        self.inner.retrieve_tagged(owner_id, persona_tag).await
    }

    async fn revoke_belief(&self, owner_id: &str, id: i64) -> anyhow::Result<()> {
        self.inner.revoke_belief(owner_id, id).await?;
        let id = self.log.global_id(id)?;
        self.log.record(MemoryEventKind::BeliefRevoked { id })?;
        Ok(())
    }

    async fn supersede_belief(
        &self,
        owner_id: &str,
        old_id: i64,
        new_id: i64,
    ) -> anyhow::Result<()> {
        self.inner
            .supersede_belief(owner_id, old_id, new_id)
            .await?;
        let old = self.log.global_id(old_id)?;
        let new = self.log.global_id(new_id)?;
        self.log
            .record(MemoryEventKind::BeliefSuperseded { old, new })?;
        Ok(())
    }

    async fn load_core(&self, owner_id: &str) -> anyhow::Result<Vec<Belief>> {
        self.inner.load_core(owner_id).await
    }

    async fn retrieve_all_beliefs(&self, owner_id: &str) -> anyhow::Result<Vec<Belief>> {
        self.inner.retrieve_all_beliefs(owner_id).await
    }

    async fn provenance_for(
        &self,
        owner_id: &str,
        belief_id: i64,
    ) -> anyhow::Result<Vec<(String, String)>> {
        self.inner.provenance_for(owner_id, belief_id).await
    }

    async fn store_procedural_belief(&self, draft: BeliefDraft) -> anyhow::Result<i64> {
        let payload = BeliefPayload {
            owner_id: draft.owner_id.clone(),
            persona_tag: draft.persona_tag.clone(),
            content: draft.insight.clone(),
            session_id: draft.session_id.clone(),
            source: draft.source.clone(),
            is_core: false,
            tier: draft.tier,
            procedural: Some(Procedural {
                keywords: draft.keywords.clone(),
                issue: draft.issue.clone(),
            }),
        };
        let local = self.inner.store_procedural_belief(draft).await?;
        self.stored(local, payload)?;
        Ok(local)
    }

    async fn record_belief_outcome(
        &self,
        owner_id: &str,
        id: i64,
        outcome: Outcome,
    ) -> anyhow::Result<()> {
        self.inner
            .record_belief_outcome(owner_id, id, outcome)
            .await
    }

    async fn reinforce_belief(&self, owner_id: &str, id: i64, delta: f64) -> anyhow::Result<()> {
        self.inner.reinforce_belief(owner_id, id, delta).await
    }

    async fn evaporate_beliefs(
        &self,
        owner_id: &str,
        factor: f64,
        floor: f64,
    ) -> anyhow::Result<u64> {
        self.inner.evaporate_beliefs(owner_id, factor, floor).await
    }

    async fn reinforce_persona_belief(
        &self,
        owner_id: &str,
        id: i64,
        delta: f64,
    ) -> anyhow::Result<()> {
        self.inner
            .reinforce_persona_belief(owner_id, id, delta)
            .await
    }

    async fn weaken_persona_belief(
        &self,
        owner_id: &str,
        id: i64,
        delta: f64,
    ) -> anyhow::Result<()> {
        self.inner.weaken_persona_belief(owner_id, id, delta).await
    }

    async fn record_pending_correction(
        &self,
        owner_id: &str,
        belief_id: i64,
        tier: Option<PrivacyTier>,
    ) -> anyhow::Result<i64> {
        self.inner
            .record_pending_correction(owner_id, belief_id, tier)
            .await
    }

    async fn take_pending_corrections(
        &self,
        owner_id: &str,
    ) -> anyhow::Result<Vec<PendingCorrection>> {
        self.inner.take_pending_corrections(owner_id).await
    }
}

/// Apply events to a `Memory` (a replica being promoted, or reconciliation
/// merging the other side's writes). Beliefs are stored under a new local
/// id and mapped to their global id; revocation and supersession resolve
/// global ids through `log`. Returns the non-belief events for the host
/// (sessions, personas, config) in order.
pub async fn apply_to_memory(
    memory: &dyn Memory,
    log: &EventLog,
    events: &[MemoryEvent],
) -> anyhow::Result<Vec<MemoryEvent>> {
    let mut rest = Vec::new();
    for event in events {
        match &event.kind {
            MemoryEventKind::BeliefStored { id, belief } => {
                if log.mapped(id)?.is_some() {
                    continue;
                }
                let local = match &belief.procedural {
                    None => {
                        memory
                            .store_belief(
                                &belief.owner_id,
                                belief.persona_tag.as_deref(),
                                &belief.content,
                                &belief.session_id,
                                &belief.source,
                                belief.is_core,
                                belief.tier,
                            )
                            .await?
                    }
                    Some(procedural) => {
                        memory
                            .store_procedural_belief(BeliefDraft {
                                owner_id: belief.owner_id.clone(),
                                persona_tag: belief.persona_tag.clone(),
                                issue: procedural.issue.clone(),
                                insight: belief.content.clone(),
                                keywords: procedural.keywords.clone(),
                                session_id: belief.session_id.clone(),
                                source: belief.source.clone(),
                                tier: belief.tier,
                            })
                            .await?
                    }
                };
                log.map(id, local, &belief.owner_id)?;
            }
            MemoryEventKind::BeliefRevoked { id } => {
                if let Some((local, owner)) = log.mapped(id)? {
                    memory.revoke_belief(&owner, local).await?;
                }
            }
            MemoryEventKind::BeliefSuperseded { old, new } => {
                if let (Some((old_local, owner)), Some((new_local, _))) =
                    (log.mapped(old)?, log.mapped(new)?)
                {
                    memory
                        .supersede_belief(&owner, old_local, new_local)
                        .await?;
                }
            }
            _ => rest.push(event.clone()),
        }
    }
    Ok(rest)
}
