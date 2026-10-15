//! Sharing agent loops between a host's concurrent requests.
//!
//! An [`AgentLoop`] runs one turn at a time (`&mut self`). A host serving
//! many requests at once (an HTTP server, a worker queue) needs more: turns
//! of different sessions in parallel, turns of the same session one after
//! the other, and no rebuilding of a loop for every request.
//! [`AgentLoopPool`] gives exactly that from one clonable handle:
//!
//! - **Per-session serialization.** A turn holds its session in the pool's
//!   [`SessionLocks`] for its whole duration; a second turn of the same
//!   session waits (in arrival order) and then runs on the same loop.
//! - **Cross-session parallelism**, bounded by
//!   [`AgentLoopPoolConfig::max_concurrent_turns`]. A turn waiting for its
//!   session does not hold one of those slots.
//! - **Session affinity.** A loop that served a session is kept idle for
//!   that session and only reused by it, so per-loop state (a `/as`
//!   persona, a `/backend` choice, a live harness session) never leaks into
//!   another session. At most [`AgentLoopPoolConfig::max_idle_loops`] idle
//!   loops are kept; the least recently used is dropped first.
//!
//! Loops come from the host's [`AgentLoopFactory`]. Loops that must follow
//! the same rules get the same [`crate::policy::PolicyChannel`] there; a
//! factory that wires delegated tasks also drains each loop's
//! `pending_rx`, since nothing else does for a pooled loop.

use crate::agent::loop_::AgentLoop;
use crate::agent::turn::TurnRequest;
use crate::session::SessionLocks;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

/// Builds a ready-to-run loop for the pool. Called when a session has no
/// idle loop of its own.
#[async_trait::async_trait]
pub trait AgentLoopFactory: Send + Sync {
    async fn build(&self) -> anyhow::Result<AgentLoop>;
}

/// Pool limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentLoopPoolConfig {
    /// Turns running at the same time, across all sessions. At least 1.
    pub max_concurrent_turns: usize,
    /// Idle loops kept for reuse by the session they last served.
    pub max_idle_loops: usize,
}

impl Default for AgentLoopPoolConfig {
    fn default() -> Self {
        Self {
            max_concurrent_turns: 8,
            max_idle_loops: 64,
        }
    }
}

/// Pool-level refusals, before any turn runs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PoolError {
    /// Pooled turns must name their session (`TurnRequest::in_session`):
    /// the pool serializes and keeps loops per session.
    #[error("a pooled turn must name its session")]
    SessionRequired,
}

/// What a pooled turn produced.
#[derive(Debug, Clone, PartialEq)]
pub struct PooledTurn {
    /// The assistant's reply.
    pub text: String,
    /// Tokens, model calls and dollars of this turn.
    pub usage: Option<crate::task::UsageAccum>,
    /// Rule version the turn ran under ([`crate::policy`]).
    pub policy_version: Option<u64>,
}

/// Clonable handle sharing agent loops between concurrent requests. See the
/// module docs.
#[derive(Clone)]
pub struct AgentLoopPool {
    inner: Arc<Inner>,
}

struct Inner {
    factory: Arc<dyn AgentLoopFactory>,
    locks: SessionLocks,
    permits: Semaphore,
    max_idle: usize,
    idle: Mutex<Idle>,
}

#[derive(Default)]
struct Idle {
    loops: HashMap<String, (AgentLoop, u64)>,
    clock: u64,
}

impl AgentLoopPool {
    /// A pool building its loops with `factory`.
    pub fn new(factory: Arc<dyn AgentLoopFactory>, config: AgentLoopPoolConfig) -> Self {
        Self::with_session_locks(factory, config, SessionLocks::new())
    }

    /// Like [`AgentLoopPool::new`], serializing through `locks` — share them
    /// with loops the host runs outside the pool over the same database.
    pub fn with_session_locks(
        factory: Arc<dyn AgentLoopFactory>,
        config: AgentLoopPoolConfig,
        locks: SessionLocks,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                factory,
                locks,
                permits: Semaphore::new(config.max_concurrent_turns.max(1)),
                max_idle: config.max_idle_loops,
                idle: Mutex::new(Idle::default()),
            }),
        }
    }

    /// The locks the pool serializes sessions through.
    pub fn session_locks(&self) -> &SessionLocks {
        &self.inner.locks
    }

    /// Idle loops currently kept.
    pub fn idle_loops(&self) -> usize {
        self.idle().loops.len()
    }

    /// Run one turn. The request must name its session
    /// ([`TurnRequest::in_session`]); see the module docs for ordering and
    /// concurrency.
    ///
    /// # Errors
    ///
    /// [`PoolError::SessionRequired`] for a request without a session, the
    /// factory's error when a loop cannot be built, and any error of the
    /// turn itself (the loop is kept for the session either way).
    pub async fn run_turn(&self, request: TurnRequest) -> anyhow::Result<PooledTurn> {
        let Some(session_id) = request.session_id.clone() else {
            anyhow::bail!(PoolError::SessionRequired);
        };
        let _session = self.inner.locks.lock(&session_id).await;
        let _permit = self
            .inner
            .permits
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("agent loop pool closed"))?;

        let reused = self.idle().loops.remove(&session_id).map(|(l, _)| l);
        let mut agent = match reused {
            Some(agent) => agent,
            None => self.inner.factory.build().await?,
        };
        tracing::debug!(event = "pool_turn", session_id = %session_id);

        let result = agent.run_turn_held(&request, None).await;
        let usage = agent.last_turn_usage();
        let policy_version = agent.last_turn_policy_version();
        self.keep_idle(session_id, agent);

        result.map(|text| PooledTurn {
            text,
            usage,
            policy_version,
        })
    }

    fn keep_idle(&self, session_id: String, agent: AgentLoop) {
        let max_idle = self.inner.max_idle;
        let evicted = {
            let mut idle = self.idle();
            if max_idle == 0 {
                Some(agent)
            } else {
                idle.clock += 1;
                let tick = idle.clock;
                idle.loops.insert(session_id, (agent, tick));
                if idle.loops.len() > max_idle {
                    let oldest = idle
                        .loops
                        .iter()
                        .min_by_key(|(_, (_, t))| *t)
                        .map(|(k, _)| k.clone());
                    oldest.and_then(|k| idle.loops.remove(&k)).map(|(l, _)| l)
                } else {
                    None
                }
            }
        };
        // Dropped outside the pool lock.
        drop(evicted);
    }

    fn idle(&self) -> std::sync::MutexGuard<'_, Idle> {
        self.inner.idle.lock().unwrap_or_else(|e| e.into_inner())
    }
}
