//! The node side: dial the primary, prove who we are, check who the primary
//! is, then run only what the owner granted, only for the current epoch.
//!
//! Invariants enforced here, independently of the primary:
//! - **BMD-09** — no listener: a node connects out ([`NodeAgent::run`]
//!   takes a connector, never an address to bind).
//! - **BMD-10** — a capability without an owner-signed grant is refused with
//!   [`InvokeError::NotGranted`] before anything runs; a grant that needs
//!   approval refuses an order that carries none.
//! - **BMD-12** — an order or replica batch from an epoch older than the
//!   newest one seen is refused and logged ([`InvokeError::StaleEpoch`]); a
//!   primary whose `Welcome` carries an older epoch is disconnected.
//! - **BMD-02** — a node has no model, memory writer or approver: the only
//!   things it can do are its [`NodeCapability`]s, and only when ordered.
//! - **BMD-15** — [`NodeHandle::stop`] cancels every running call and drops
//!   the connection at once.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use super::enrollment::{CapabilityGrant, DeviceId, Enrollment};
use super::handshake;
use super::protocol::{
    ApprovalRef, CallId, CapabilityDescriptor, Evidence, InvokeError, NodeToPrimary, PrimaryToNode,
};
use super::replica::MemoryEvent;
use super::transport::FrameConn;
use crate::identity::age_identity::AgeIdentity;

/// Something a node can run for the primary. Implementations enforce the
/// grant's scope themselves (which apps, which paths) — they receive it.
#[async_trait]
pub trait NodeCapability: Send + Sync {
    fn descriptor(&self) -> CapabilityDescriptor;

    async fn run(
        &self,
        args: serde_json::Value,
        grant: &CapabilityGrant,
        approval: Option<&ApprovalRef>,
        cancel: CancellationToken,
    ) -> Result<(serde_json::Value, Vec<Evidence>), InvokeError>;
}

/// Where replica batches go on a node with `holds_replica` (§5.4). The
/// sink applies them in order and returns the last `seq` applied.
#[async_trait]
pub trait ReplicaSink: Send + Sync {
    /// The last applied `seq`, to resume from after a reconnect.
    async fn last_seq(&self) -> Option<u64>;
    async fn apply(&self, from_seq: u64, events: Vec<MemoryEvent>) -> anyhow::Result<u64>;
}

/// Called when the primary revokes this device: delete the secrets key
/// (BMD-33) and anything else only an enrolled device should keep.
#[async_trait]
pub trait RevocationHook: Send + Sync {
    async fn revoked(&self);
}

/// What a node remembers between connections.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeState {
    /// Newest epoch seen from any primary (the fencing floor).
    pub epoch_seen: u64,
    /// The newest owner-signed enrollment of this device.
    pub enrollment: Option<Enrollment>,
}

/// A node's fixed identity and trust anchor.
pub struct NodeConfig {
    pub owner: String,
    /// The owner's Ed25519 key: the only thing a node needs to decide
    /// whether a primary and its grants are genuine.
    pub owner_key: [u8; 32],
    pub device: DeviceId,
    pub identity: AgeIdentity,
    /// Where [`NodeState`] is kept (JSON). `None` keeps it in memory only.
    pub state_path: Option<PathBuf>,
}

/// Stops a running node.
#[derive(Clone)]
pub struct NodeHandle {
    stop: CancellationToken,
}

impl NodeHandle {
    /// Cancel every running call and disconnect now (BMD-15). The node does
    /// not reconnect after this.
    pub fn stop(&self) {
        self.stop.cancel();
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.is_cancelled()
    }
}

/// How a connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// The owner pressed stop.
    Stopped,
    /// The primary revoked this device.
    Revoked,
    /// The connection closed or failed; reconnecting is up to the caller.
    Disconnected(String),
    /// The other side is not a primary this node accepts (bad signature,
    /// older epoch, another owner). Not worth reconnecting to.
    Refused(String),
}

pub struct NodeAgent {
    config: NodeConfig,
    state: Mutex<NodeState>,
    capabilities: HashMap<String, Arc<dyn NodeCapability>>,
    replica: Option<Arc<dyn ReplicaSink>>,
    revocation: Option<Arc<dyn RevocationHook>>,
    /// Results of calls that finished after their connection dropped,
    /// reported on the next connection (§7: "reporta ao reconectar").
    outbox: Mutex<Vec<NodeToPrimary>>,
    stop: CancellationToken,
}

type Finished = (
    CallId,
    Result<serde_json::Value, InvokeError>,
    Vec<Evidence>,
);

impl NodeAgent {
    pub fn new(config: NodeConfig) -> anyhow::Result<Self> {
        let state = match &config.state_path {
            Some(path) if path.exists() => serde_json::from_slice(&std::fs::read(path)?)?,
            _ => NodeState::default(),
        };
        Ok(Self {
            config,
            state: Mutex::new(state),
            capabilities: HashMap::new(),
            replica: None,
            revocation: None,
            outbox: Mutex::new(Vec::new()),
            stop: CancellationToken::new(),
        })
    }

    pub fn with_capability(mut self, capability: Arc<dyn NodeCapability>) -> Self {
        self.capabilities
            .insert(capability.descriptor().name, capability);
        self
    }

    pub fn with_replica(mut self, sink: Arc<dyn ReplicaSink>) -> Self {
        self.replica = Some(sink);
        self
    }

    pub fn with_revocation_hook(mut self, hook: Arc<dyn RevocationHook>) -> Self {
        self.revocation = Some(hook);
        self
    }

    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            stop: self.stop.clone(),
        }
    }

    pub async fn state(&self) -> NodeState {
        self.state.lock().await.clone()
    }

    async fn save(&self, state: &NodeState) {
        if let Some(path) = &self.config.state_path {
            let write = serde_json::to_vec_pretty(state)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| Ok(std::fs::write(path, bytes)?));
            if let Err(e) = write {
                tracing::warn!(event = "node_state_not_saved", error = %e);
            }
        }
    }

    /// Serve one connection to a primary until it ends.
    pub async fn run(&self, mut conn: impl FrameConn) -> SessionEnd {
        if self.stop.is_cancelled() {
            return SessionEnd::Stopped;
        }
        let end = tokio::select! {
            end = self.session(&mut conn) => end,
            () = self.stop.cancelled() => SessionEnd::Stopped,
        };
        conn.close().await;
        end
    }

    async fn session(&self, conn: &mut impl FrameConn) -> SessionEnd {
        let welcome = match self.handshake(conn).await {
            Ok(epoch) => epoch,
            Err(end) => return end,
        };
        tracing::info!(event = "node_connected", device = %self.config.device, epoch = welcome);
        let descriptors = self.capabilities.values().map(|c| c.descriptor()).collect();
        if let Err(e) = send(
            conn,
            &NodeToPrimary::Capabilities {
                capabilities: descriptors,
            },
        )
        .await
        {
            return SessionEnd::Disconnected(e.to_string());
        }
        for pending in std::mem::take(&mut *self.outbox.lock().await) {
            if let Err(e) = send(conn, &pending).await {
                return SessionEnd::Disconnected(e.to_string());
            }
        }

        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Finished>();
        let mut running: HashMap<CallId, CancellationToken> = HashMap::new();
        let end = loop {
            tokio::select! {
                frame = conn.recv() => {
                    let text = match frame {
                        Ok(Some(text)) => text,
                        Ok(None) => break SessionEnd::Disconnected("primary closed the connection".into()),
                        Err(e) => break SessionEnd::Disconnected(e.to_string()),
                    };
                    let message = match serde_json::from_str::<PrimaryToNode>(&text) {
                        Ok(message) => message,
                        Err(e) => {
                            tracing::warn!(event = "node_bad_frame", error = %e);
                            continue;
                        }
                    };
                    match self.handle_message(conn, message, &mut running, &done_tx).await {
                        Ok(None) => {}
                        Ok(Some(end)) => break end,
                        Err(e) => break SessionEnd::Disconnected(e.to_string()),
                    }
                }
                Some((call, outcome, evidence)) = done_rx.recv() => {
                    running.remove(&call);
                    let result = NodeToPrimary::InvokeResult { call, outcome, evidence };
                    if let Err(e) = send(conn, &result).await {
                        self.outbox.lock().await.push(result);
                        break SessionEnd::Disconnected(e.to_string());
                    }
                }
            }
        };
        // Calls still running finish on their own and are reported next
        // time — unless the owner stopped the node, which cancels them.
        if end == SessionEnd::Stopped || end == SessionEnd::Revoked {
            for token in running.values() {
                token.cancel();
            }
        } else {
            drop(done_tx);
            while let Some((call, outcome, evidence)) = done_rx.recv().await {
                self.outbox.lock().await.push(NodeToPrimary::InvokeResult {
                    call,
                    outcome,
                    evidence,
                });
            }
        }
        end
    }

    /// Mutual challenge (see `handshake`) and the fencing check on
    /// `Welcome`. Returns the primary's epoch.
    async fn handshake(&self, conn: &mut impl FrameConn) -> Result<u64, SessionEnd> {
        let disconnected = |e: anyhow::Error| SessionEnd::Disconnected(e.to_string());
        let nonce = handshake::nonce();
        let (epoch_seen, replica_seq) = {
            let state = self.state.lock().await;
            let seq = match &self.replica {
                Some(sink) => sink.last_seq().await,
                None => None,
            };
            (state.epoch_seen, seq)
        };
        send(
            conn,
            &NodeToPrimary::Hello {
                device: self.config.device.clone(),
                epoch_seen,
                replica_seq,
                nonce,
            },
        )
        .await
        .map_err(disconnected)?;

        let (primary_nonce, primary, signature) = match recv(conn).await.map_err(disconnected)? {
            PrimaryToNode::Challenge {
                nonce,
                primary,
                signature,
            } => (nonce, primary, signature),
            other => {
                return Err(SessionEnd::Refused(format!(
                    "expected a challenge, got {other:?}"
                )))
            }
        };
        if primary.owner != self.config.owner {
            return Err(SessionEnd::Refused(format!(
                "primary belongs to owner {:?}",
                primary.owner
            )));
        }
        primary
            .verify(&self.config.owner_key)
            .map_err(|e| SessionEnd::Refused(format!("primary enrollment: {e}")))?;
        handshake::verify(
            &primary.device_key,
            handshake::Side::Primary,
            &self.config.owner,
            &primary.device,
            &nonce,
            &signature,
        )
        .map_err(|()| SessionEnd::Refused("the primary's proof does not verify".into()))?;

        let proof = handshake::sign(
            &self.config.identity,
            handshake::Side::Node,
            &self.config.owner,
            &self.config.device,
            &primary_nonce,
        );
        send(conn, &NodeToPrimary::Proof { signature: proof })
            .await
            .map_err(disconnected)?;

        let (epoch, enrollment) = match recv(conn).await.map_err(disconnected)? {
            PrimaryToNode::Welcome { epoch, enrollment } => (epoch, enrollment),
            PrimaryToNode::Revoked => {
                self.revoked().await;
                return Err(SessionEnd::Revoked);
            }
            other => {
                return Err(SessionEnd::Refused(format!(
                    "expected welcome, got {other:?}"
                )))
            }
        };
        if epoch < epoch_seen {
            tracing::warn!(
                event = "node_stale_primary",
                primary = %primary.device,
                epoch,
                epoch_seen
            );
            return Err(SessionEnd::Refused(format!(
                "primary at epoch {epoch}, this device has seen {epoch_seen}"
            )));
        }
        self.accept_enrollment(*enrollment)
            .await
            .map_err(SessionEnd::Refused)?;
        let mut state = self.state.lock().await;
        state.epoch_seen = epoch;
        let snapshot = state.clone();
        drop(state);
        self.save(&snapshot).await;
        Ok(epoch)
    }

    /// Take a newer owner-signed enrollment of this device (its grants).
    async fn accept_enrollment(&self, enrollment: Enrollment) -> Result<(), String> {
        enrollment
            .verify(&self.config.owner_key)
            .map_err(|e| format!("enrollment: {e}"))?;
        if enrollment.device != self.config.device
            || enrollment.device_key != self.config.identity.verifying_key_bytes()
        {
            return Err("the enrollment is for another device".into());
        }
        let mut state = self.state.lock().await;
        if let Some(current) = &state.enrollment {
            if enrollment.revision < current.revision {
                return Err(format!(
                    "enrollment revision {} is older than {}",
                    enrollment.revision, current.revision
                ));
            }
        }
        state.enrollment = Some(enrollment);
        let snapshot = state.clone();
        drop(state);
        self.save(&snapshot).await;
        Ok(())
    }

    async fn revoked(&self) {
        tracing::warn!(event = "node_revoked", device = %self.config.device);
        if let Some(hook) = &self.revocation {
            hook.revoked().await;
        }
        let mut state = self.state.lock().await;
        state.enrollment = None;
        let snapshot = state.clone();
        drop(state);
        self.save(&snapshot).await;
    }

    async fn handle_message(
        &self,
        conn: &mut impl FrameConn,
        message: PrimaryToNode,
        running: &mut HashMap<CallId, CancellationToken>,
        done: &mpsc::UnboundedSender<Finished>,
    ) -> anyhow::Result<Option<SessionEnd>> {
        match message {
            PrimaryToNode::Invoke {
                call,
                capability,
                args,
                approval,
                epoch,
            } => match self.admit(&capability, approval.as_ref(), epoch).await {
                Err(error) => {
                    if matches!(error, InvokeError::StaleEpoch { .. }) {
                        send(
                            conn,
                            &NodeToPrimary::Rejected {
                                reason: format!("{capability}: {error}"),
                            },
                        )
                        .await?;
                    }
                    send(
                        conn,
                        &NodeToPrimary::InvokeResult {
                            call,
                            outcome: Err(error),
                            evidence: Vec::new(),
                        },
                    )
                    .await?;
                }
                Ok((runner, grant)) => {
                    let token = self.stop.child_token();
                    running.insert(call, token.clone());
                    let done = done.clone();
                    tokio::spawn(async move {
                        let result = tokio::select! {
                            result = runner.run(args, &grant, approval.as_ref(), token.clone()) => result,
                            () = token.cancelled() => Err(InvokeError::Cancelled),
                        };
                        let (outcome, evidence) = match result {
                            Ok((value, evidence)) => (Ok(value), evidence),
                            Err(e) => (Err(e), Vec::new()),
                        };
                        let _ = done.send((call, outcome, evidence));
                    });
                }
            },
            PrimaryToNode::Cancel { call } => {
                if let Some(token) = running.get(&call) {
                    token.cancel();
                }
            }
            PrimaryToNode::Grants { enrollment } => {
                if let Err(e) = self.accept_enrollment(*enrollment).await {
                    tracing::warn!(event = "node_grants_refused", error = %e);
                }
            }
            PrimaryToNode::Replica {
                from_seq,
                events,
                epoch,
            } => {
                let seen = self.state.lock().await.epoch_seen;
                if epoch < seen {
                    let reason = format!("replica batch from epoch {epoch}, seen {seen}");
                    tracing::warn!(event = "node_stale_replica", epoch, seen);
                    send(conn, &NodeToPrimary::Rejected { reason }).await?;
                    return Ok(None);
                }
                let holds = self
                    .state
                    .lock()
                    .await
                    .enrollment
                    .as_ref()
                    .is_some_and(|e| e.holds_replica);
                match (&self.replica, holds) {
                    (Some(sink), true) => {
                        let seq = sink.apply(from_seq, events).await?;
                        send(conn, &NodeToPrimary::ReplicaAck { seq }).await?;
                    }
                    _ => {
                        send(
                            conn,
                            &NodeToPrimary::Rejected {
                                reason: "this device does not hold a replica".into(),
                            },
                        )
                        .await?;
                    }
                }
            }
            PrimaryToNode::Demote { new_epoch } => {
                let mut state = self.state.lock().await;
                state.epoch_seen = state.epoch_seen.max(new_epoch);
                let snapshot = state.clone();
                drop(state);
                self.save(&snapshot).await;
            }
            PrimaryToNode::Revoked => {
                self.revoked().await;
                return Ok(Some(SessionEnd::Revoked));
            }
            PrimaryToNode::Challenge { .. } | PrimaryToNode::Welcome { .. } => {
                tracing::warn!(event = "node_unexpected_handshake_frame");
            }
        }
        Ok(None)
    }

    /// Everything an order must pass before it runs.
    async fn admit(
        &self,
        capability: &str,
        approval: Option<&ApprovalRef>,
        epoch: u64,
    ) -> Result<(Arc<dyn NodeCapability>, CapabilityGrant), InvokeError> {
        let state = self.state.lock().await;
        if epoch < state.epoch_seen {
            tracing::warn!(
                event = "node_stale_order",
                capability,
                epoch,
                seen = state.epoch_seen
            );
            return Err(InvokeError::StaleEpoch {
                seen: state.epoch_seen,
                got: epoch,
            });
        }
        let grant = state
            .enrollment
            .as_ref()
            .and_then(|e| e.grant(capability))
            .cloned()
            .ok_or(InvokeError::NotGranted)?;
        drop(state);
        if grant.needs_approval && approval.is_none() {
            return Err(InvokeError::NeedsApproval);
        }
        let runner = self
            .capabilities
            .get(capability)
            .cloned()
            .ok_or(InvokeError::UnknownCapability)?;
        Ok((runner, grant))
    }
}

async fn send(conn: &mut impl FrameConn, message: &NodeToPrimary) -> anyhow::Result<()> {
    conn.send(serde_json::to_string(message)?).await
}

async fn recv(conn: &mut impl FrameConn) -> anyhow::Result<PrimaryToNode> {
    let text = conn
        .recv()
        .await?
        .ok_or_else(|| anyhow::anyhow!("connection closed during the handshake"))?;
    Ok(serde_json::from_str(&text)?)
}
