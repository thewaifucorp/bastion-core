//! Per-session turn serialization.
//!
//! SQLite WAL + `busy_timeout` keeps individual writes consistent, but a turn
//! is a read-modify-write over the whole transcript: two turns of the same
//! session running at once would each load the same history and interleave
//! their appends. [`SessionLocks`] closes that gap with one async mutex per
//! session: turns of the same session queue up in arrival order, turns of
//! different sessions never wait on each other.
//!
//! The registry is a cheap clonable handle. Every [`crate::agent::loop_::AgentLoop`]
//! carries one; a host that runs several loops over the same database (one
//! loop per request, or an [`crate::agent::pool::AgentLoopPool`]) gives them
//! the same handle so the guarantee holds across loops. Entries exist only
//! while a turn holds or waits for them, so the map never grows with the
//! number of sessions ever seen.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{Mutex, OwnedMutexGuard};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LockKey {
    Session(String),
    /// "Most recent session of this owner": the lock a turn takes while it
    /// does not yet know which session it will write to.
    Owner(String),
}

type Slots = HashMap<LockKey, Arc<Mutex<()>>>;

/// Clonable registry of per-session turn locks. See the module docs.
#[derive(Clone, Default)]
pub struct SessionLocks {
    slots: Arc<StdMutex<Slots>>,
}

impl std::fmt::Debug for SessionLocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLocks")
            .field("active", &self.active())
            .finish()
    }
}

impl SessionLocks {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait until no other turn holds `session_id`, then hold it until the
    /// returned guard drops. Waiters are served in arrival order (tokio's
    /// mutex is fair).
    pub async fn lock(&self, session_id: &str) -> SessionGuard {
        self.acquire(LockKey::Session(session_id.to_owned())).await
    }

    /// Hold `session_id` only if nobody does right now.
    pub fn try_lock(&self, session_id: &str) -> Option<SessionGuard> {
        let key = LockKey::Session(session_id.to_owned());
        let slot = self.slot(&key);
        match slot.clone().try_lock_owned() {
            Ok(guard) => Some(SessionGuard {
                guard: Some(guard),
                slot,
                key,
                slots: self.slots.clone(),
            }),
            Err(_) => {
                self.release_slot(&key, &slot);
                None
            }
        }
    }

    /// Serializes turns addressed to "the owner's most recent session"
    /// while that session is resolved (or created).
    pub(crate) async fn lock_owner(&self, owner: &str) -> SessionGuard {
        self.acquire(LockKey::Owner(owner.to_owned())).await
    }

    /// Number of sessions currently held or waited for.
    pub fn active(&self) -> usize {
        self.slots.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    async fn acquire(&self, key: LockKey) -> SessionGuard {
        let slot = self.slot(&key);
        let guard = slot.clone().lock_owned().await;
        SessionGuard {
            guard: Some(guard),
            slot,
            key,
            slots: self.slots.clone(),
        }
    }

    fn slot(&self, key: &LockKey) -> Arc<Mutex<()>> {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone()
    }

    fn release_slot(&self, key: &LockKey, slot: &Arc<Mutex<()>>) {
        remove_if_unused(&self.slots, key, slot);
    }
}

/// Drops the registry entry once only the registry and the caller still
/// reference it. The count is read under the registry lock, which is also
/// where every new reference is handed out, so no waiter can appear between
/// the check and the removal.
fn remove_if_unused(slots: &StdMutex<Slots>, key: &LockKey, slot: &Arc<Mutex<()>>) {
    let mut map = slots.lock().unwrap_or_else(|e| e.into_inner());
    if Arc::strong_count(slot) == 2 {
        map.remove(key);
    }
}

/// Holds one session (or owner resolution) until dropped.
pub struct SessionGuard {
    guard: Option<OwnedMutexGuard<()>>,
    slot: Arc<Mutex<()>>,
    key: LockKey,
    slots: Arc<StdMutex<Slots>>,
}

impl std::fmt::Debug for SessionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGuard")
            .field("key", &self.key)
            .finish()
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // Release first so the next waiter can run, then forget the entry if
        // nobody else is queued on it.
        drop(self.guard.take());
        remove_if_unused(&self.slots, &self.key, &self.slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn same_session_turns_never_overlap() {
        let locks = SessionLocks::new();
        let inside = Arc::new(AtomicUsize::new(0));
        let max_inside = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (locks, inside, max_inside) = (locks.clone(), inside.clone(), max_inside.clone());
            tasks.push(tokio::spawn(async move {
                let _g = locks.lock("s1").await;
                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                max_inside.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                inside.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(max_inside.load(Ordering::SeqCst), 1);
        assert_eq!(locks.active(), 0, "entries are dropped once unused");
    }

    #[tokio::test]
    async fn different_sessions_do_not_wait_on_each_other() {
        let locks = SessionLocks::new();
        let _a = locks.lock("a").await;
        // Would hang (and time out) if "b" shared a's lock.
        let b = tokio::time::timeout(Duration::from_secs(1), locks.lock("b")).await;
        assert!(b.is_ok());
        assert!(locks.try_lock("a").is_none());
        assert!(locks.try_lock("c").is_some());
    }

    #[tokio::test]
    async fn waiters_are_served_in_arrival_order() {
        let locks = SessionLocks::new();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let first = locks.lock("s").await;
        let mut tasks = Vec::new();
        for i in 0..4 {
            let (locks, order) = (locks.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let _g = locks.lock("s").await;
                order.lock().unwrap().push(i);
            }));
            // Let task `i` queue before spawning the next one.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(first);
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn owner_resolution_and_session_keys_are_distinct() {
        let locks = SessionLocks::new();
        let _owner = locks.lock_owner("alice").await;
        assert!(locks.try_lock("alice").is_some());
    }

    #[tokio::test]
    async fn a_failed_try_lock_leaves_no_entry_behind() {
        let locks = SessionLocks::new();
        let held = locks.lock("s").await;
        assert!(locks.try_lock("s").is_none());
        assert_eq!(locks.active(), 1);
        drop(held);
        assert_eq!(locks.active(), 0);
    }
}
