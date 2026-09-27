//! The primary side: accept node connections, authenticate them against the
//! registry, and route invocations to them.
//!
//! Remote capabilities reach the model only through [`RemoteCapability`],
//! registered in the primary's `CapabilityRegistry` like any other: the
//! registry's single policy boundary (persona authority, egress, approval)
//! runs **before** [`PrimaryHub::invoke`] is ever called (BMD-11). The hub
//! checks the grant once more before sending, so an ungranted call never
//! leaves the primary (BMD-10).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};

type Pending = Arc<std::sync::Mutex<HashMap<CallId, oneshot::Sender<Reply>>>>;

use super::enrollment::{CapabilityGrant, DeviceId, DeviceRegistry, Role};
use super::handshake;
use super::protocol::{
    ApprovalRef, CallId, CapabilityDescriptor, Evidence, InvokeError, NodeToPrimary, PrimaryToNode,
};
use super::replica::MemoryEvent;
use super::transport::FrameConn;
use crate::identity::age_identity::AgeIdentity;
use bastion_runtime::capability::{Capability, InvokeCtx};

/// What happened on the hub, for the host's audit log and UI.
#[derive(Debug, Clone, PartialEq)]
pub enum HubEvent {
    Connected {
        device: DeviceId,
    },
    Disconnected {
        device: DeviceId,
        reason: String,
    },
    /// A connection that failed authentication.
    Refused {
        reason: String,
    },
    /// A node refused an order (stale epoch, no replica, …).
    NodeRejected {
        device: DeviceId,
        reason: String,
    },
    /// A call whose connection dropped before the result: `Unknown`.
    Unknown {
        device: DeviceId,
        call: CallId,
    },
    /// A result that arrived after its call was already given up.
    LateResult {
        device: DeviceId,
        call: CallId,
    },
    ReplicaAck {
        device: DeviceId,
        seq: u64,
    },
    /// A node's first message says it has seen a newer epoch than ours: this
    /// primary is stale and must stop accepting writes (BMD-21).
    NewerEpochSeen {
        device: DeviceId,
        epoch: u64,
    },
}

type Reply = (Result<Value, InvokeError>, Vec<Evidence>);

struct Session {
    id: u64,
    tx: mpsc::UnboundedSender<PrimaryToNode>,
    pending: Pending,
    replica_seq: Option<u64>,
}

struct Inner {
    device: DeviceId,
    identity: AgeIdentity,
    registry: Arc<RwLock<DeviceRegistry>>,
    epoch: AtomicU64,
    sessions: Mutex<HashMap<DeviceId, Session>>,
    descriptors: Mutex<HashMap<DeviceId, Vec<CapabilityDescriptor>>>,
    next_call: AtomicU64,
    next_session: AtomicU64,
    events: broadcast::Sender<HubEvent>,
}

/// The primary's endpoint for its nodes. Cheap to clone.
#[derive(Clone)]
pub struct PrimaryHub {
    inner: Arc<Inner>,
}

impl PrimaryHub {
    /// `device`/`identity` are this primary's own; `registry` must list this
    /// device as `Role::Primary`.
    pub fn new(
        device: DeviceId,
        identity: AgeIdentity,
        registry: Arc<RwLock<DeviceRegistry>>,
        epoch: u64,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Inner {
                device,
                identity,
                registry,
                epoch: AtomicU64::new(epoch),
                sessions: Mutex::new(HashMap::new()),
                descriptors: Mutex::new(HashMap::new()),
                next_call: AtomicU64::new(1),
                next_session: AtomicU64::new(1),
                events,
            }),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.inner.epoch.load(Ordering::SeqCst)
    }

    pub fn device(&self) -> &DeviceId {
        &self.inner.device
    }

    pub fn registry(&self) -> &Arc<RwLock<DeviceRegistry>> {
        &self.inner.registry
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.inner.events.subscribe()
    }

    fn emit(&self, event: HubEvent) {
        let _ = self.inner.events.send(event);
    }

    pub async fn connected(&self) -> Vec<DeviceId> {
        self.inner.sessions.lock().await.keys().cloned().collect()
    }

    /// The last `seq` a connected replica node reported, if any.
    pub async fn replica_seq(&self, device: &DeviceId) -> Option<u64> {
        self.inner
            .sessions
            .lock()
            .await
            .get(device)
            .and_then(|s| s.replica_seq)
    }

    /// Serve one node connection until it closes.
    pub async fn serve(&self, mut conn: impl FrameConn) {
        let (device, replica_seq) = match self.authenticate(&mut conn).await {
            Ok(ok) => ok,
            Err(reason) => {
                tracing::warn!(event = "hub_refused", reason = %reason);
                self.emit(HubEvent::Refused { reason });
                conn.close().await;
                return;
            }
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let pending: Pending = Arc::default();
        let id = self.inner.next_session.fetch_add(1, Ordering::SeqCst);
        if let Some(old) = self.inner.sessions.lock().await.insert(
            device.clone(),
            Session {
                id,
                tx,
                pending: pending.clone(),
                replica_seq,
            },
        ) {
            // A reconnect replaces the old session; its calls are unknown.
            fail_pending(&old.pending, &device, self);
        }
        tracing::info!(event = "hub_node_connected", device = %device);
        self.emit(HubEvent::Connected {
            device: device.clone(),
        });

        let reason = loop {
            tokio::select! {
                outgoing = rx.recv() => {
                    let Some(message) = outgoing else { break "session replaced".to_string() };
                    let revoked = matches!(message, PrimaryToNode::Revoked);
                    match serde_json::to_string(&message) {
                        Ok(text) => if let Err(e) = conn.send(text).await { break e.to_string() },
                        Err(e) => break e.to_string(),
                    }
                    if revoked {
                        break "revoked".to_string();
                    }
                }
                frame = conn.recv() => {
                    let text = match frame {
                        Ok(Some(text)) => text,
                        Ok(None) => break "node closed the connection".to_string(),
                        Err(e) => break e.to_string(),
                    };
                    match serde_json::from_str::<NodeToPrimary>(&text) {
                        Ok(message) => self.on_node_message(&device, &pending, message).await,
                        Err(e) => tracing::warn!(event = "hub_bad_frame", device = %device, error = %e),
                    }
                }
            }
        };
        conn.close().await;
        let mut sessions = self.inner.sessions.lock().await;
        if sessions.get(&device).is_some_and(|s| s.id == id) {
            sessions.remove(&device);
        }
        drop(sessions);
        fail_pending(&pending, &device, self);
        tracing::info!(event = "hub_node_disconnected", device = %device, reason = %reason);
        self.emit(HubEvent::Disconnected { device, reason });
    }

    async fn authenticate(
        &self,
        conn: &mut impl FrameConn,
    ) -> Result<(DeviceId, Option<u64>), String> {
        let hello = recv(conn).await?;
        let NodeToPrimary::Hello {
            device,
            epoch_seen,
            replica_seq,
            nonce,
        } = hello
        else {
            return Err("expected hello".into());
        };
        let (owner, node_key, primary_enrollment) = {
            let registry = self.inner.registry.read().await;
            let node = registry.active(&device).map_err(|e| e.to_string())?;
            if device == self.inner.device {
                return Err("a device cannot connect to itself".into());
            }
            let primary = registry
                .active(&self.inner.device)
                .map_err(|e| format!("this primary: {e}"))?;
            (
                registry.owner().to_string(),
                node.enrollment.device_key,
                primary.enrollment.clone(),
            )
        };
        let epoch = self.epoch();
        if epoch_seen > epoch {
            // Someone was promoted after us: we are the stale one.
            self.emit(HubEvent::NewerEpochSeen {
                device: device.clone(),
                epoch: epoch_seen,
            });
            return Err(format!(
                "{device} has seen epoch {epoch_seen}, this primary is at {epoch}"
            ));
        }
        let challenge = handshake::nonce();
        let signature = handshake::sign(
            &self.inner.identity,
            handshake::Side::Primary,
            &owner,
            &self.inner.device,
            &nonce,
        );
        send(
            conn,
            &PrimaryToNode::Challenge {
                nonce: challenge,
                primary: Box::new(primary_enrollment),
                signature,
            },
        )
        .await?;
        let NodeToPrimary::Proof { signature } = recv(conn).await? else {
            return Err("expected proof".into());
        };
        handshake::verify(
            &node_key,
            handshake::Side::Node,
            &owner,
            &device,
            &challenge,
            &signature,
        )
        .map_err(|()| format!("{device}: proof does not verify"))?;
        let enrollment = self
            .inner
            .registry
            .read()
            .await
            .active(&device)
            .map_err(|e| e.to_string())?
            .enrollment
            .clone();
        send(
            conn,
            &PrimaryToNode::Welcome {
                epoch,
                enrollment: Box::new(enrollment),
            },
        )
        .await?;
        Ok((device, replica_seq))
    }

    async fn on_node_message(&self, device: &DeviceId, pending: &Pending, message: NodeToPrimary) {
        match message {
            NodeToPrimary::Capabilities { capabilities } => {
                self.inner
                    .descriptors
                    .lock()
                    .await
                    .insert(device.clone(), capabilities);
            }
            NodeToPrimary::InvokeResult {
                call,
                outcome,
                evidence,
            } => match lock(pending).remove(&call) {
                Some(reply) => {
                    let _ = reply.send((outcome, evidence));
                }
                None => {
                    tracing::info!(event = "hub_late_result", device = %device, call = call.0);
                    self.emit(HubEvent::LateResult {
                        device: device.clone(),
                        call,
                    });
                }
            },
            NodeToPrimary::ReplicaAck { seq } => {
                if let Some(session) = self.inner.sessions.lock().await.get_mut(device) {
                    session.replica_seq = Some(seq);
                }
                self.emit(HubEvent::ReplicaAck {
                    device: device.clone(),
                    seq,
                });
            }
            NodeToPrimary::Rejected { reason } => {
                tracing::warn!(event = "hub_node_rejected", device = %device, reason = %reason);
                self.emit(HubEvent::NodeRejected {
                    device: device.clone(),
                    reason,
                });
            }
            NodeToPrimary::Hello { .. } | NodeToPrimary::Proof { .. } => {
                tracing::warn!(event = "hub_unexpected_handshake_frame", device = %device);
            }
        }
    }

    /// Send `capability` to `device` and wait for its result. Refuses without
    /// sending when the device is unknown, revoked, not granted `capability`,
    /// or not connected. Dropping the returned future cancels the call on the
    /// node.
    pub async fn invoke(
        &self,
        device: &DeviceId,
        capability: &str,
        args: Value,
        approval: Option<ApprovalRef>,
    ) -> Result<(Value, Vec<Evidence>), InvokeError> {
        let grant = self.grant(device, capability).await?;
        if grant.needs_approval && approval.is_none() {
            return Err(InvokeError::NeedsApproval);
        }
        let call = CallId(self.inner.next_call.fetch_add(1, Ordering::SeqCst));
        let (reply_tx, reply_rx) = oneshot::channel();
        let (tx, pending) = {
            let sessions = self.inner.sessions.lock().await;
            let session = sessions.get(device).ok_or(InvokeError::Unavailable)?;
            lock(&session.pending).insert(call, reply_tx);
            (session.tx.clone(), session.pending.clone())
        };
        tx.send(PrimaryToNode::Invoke {
            call,
            capability: capability.to_string(),
            args,
            approval,
            epoch: self.epoch(),
        })
        .map_err(|_| InvokeError::Unknown)?;
        let guard = CancelOnDrop {
            tx: tx.clone(),
            pending,
            call,
            armed: true,
        };
        let reply = reply_rx.await;
        let mut guard = guard;
        guard.armed = false;
        match reply {
            Ok((Ok(value), evidence)) => Ok((value, evidence)),
            Ok((Err(e), _)) => Err(e),
            // The session ended with the call in flight.
            Err(_) => Err(InvokeError::Unknown),
        }
    }

    async fn grant(
        &self,
        device: &DeviceId,
        capability: &str,
    ) -> Result<CapabilityGrant, InvokeError> {
        let registry = self.inner.registry.read().await;
        let record = registry
            .active(device)
            .map_err(|_| InvokeError::NotGranted)?;
        record
            .enrollment
            .grant(capability)
            .cloned()
            .ok_or(InvokeError::NotGranted)
    }

    /// Push a device's current enrollment (after the owner changed its
    /// grants) to it, if connected.
    pub async fn push_grants(&self, device: &DeviceId) {
        let enrollment = match self.inner.registry.read().await.active(device) {
            Ok(record) => record.enrollment.clone(),
            Err(_) => return,
        };
        if let Some(session) = self.inner.sessions.lock().await.get(device) {
            let _ = session.tx.send(PrimaryToNode::Grants {
                enrollment: Box::new(enrollment),
            });
        }
    }

    /// Tell a revoked device, if connected, and drop it.
    pub async fn notify_revoked(&self, device: &DeviceId) {
        if let Some(session) = self.inner.sessions.lock().await.remove(device) {
            let _ = session.tx.send(PrimaryToNode::Revoked);
        }
    }

    /// Send a replica batch to every connected node that holds a replica.
    pub async fn broadcast_replica(&self, from_seq: u64, events: Vec<MemoryEvent>) {
        let replicas: Vec<DeviceId> = {
            let registry = self.inner.registry.read().await;
            registry
                .devices()
                .filter(|r| !r.revoked && r.enrollment.holds_replica)
                .filter(|r| matches!(r.role, Role::Node { .. }))
                .map(|r| r.enrollment.device.clone())
                .collect()
        };
        let sessions = self.inner.sessions.lock().await;
        for device in replicas {
            if let Some(session) = sessions.get(&device) {
                let _ = session.tx.send(PrimaryToNode::Replica {
                    from_seq,
                    events: events.clone(),
                    epoch: self.epoch(),
                });
            }
        }
    }

    /// Send a replica batch to one node (catch-up after it reconnects).
    pub async fn send_replica(&self, device: &DeviceId, from_seq: u64, events: Vec<MemoryEvent>) {
        if let Some(session) = self.inner.sessions.lock().await.get(device) {
            let _ = session.tx.send(PrimaryToNode::Replica {
                from_seq,
                events,
                epoch: self.epoch(),
            });
        }
    }

    /// Tell every connected node that `new_epoch` exists; used by a primary
    /// that learns it was superseded, and by a new primary to fence the old.
    pub async fn announce_epoch(&self, new_epoch: u64) {
        for session in self.inner.sessions.lock().await.values() {
            let _ = session.tx.send(PrimaryToNode::Demote { new_epoch });
        }
    }

    /// The remote capabilities of `device` to register in the primary's
    /// `CapabilityRegistry`: every granted capability the node has
    /// described. Registered once and left in place (the tool list is part
    /// of the cached prompt prefix); while the node is offline a call returns
    /// [`InvokeError::Unavailable`].
    pub async fn remote_capabilities(&self, device: &DeviceId) -> Vec<Arc<dyn Capability>> {
        let grants: Vec<CapabilityGrant> = match self.inner.registry.read().await.active(device) {
            Ok(record) => record.enrollment.granted.clone(),
            Err(_) => return Vec::new(),
        };
        let descriptors = self
            .inner
            .descriptors
            .lock()
            .await
            .get(device)
            .cloned()
            .unwrap_or_default();
        grants
            .into_iter()
            .filter_map(|grant| {
                let descriptor = descriptors
                    .iter()
                    .find(|d| d.name == grant.capability)?
                    .clone();
                Some(Arc::new(RemoteCapability::new(
                    self.clone(),
                    device.clone(),
                    descriptor,
                    grant,
                )) as Arc<dyn Capability>)
            })
            .collect()
    }
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn fail_pending(pending: &Pending, device: &DeviceId, hub: &PrimaryHub) {
    let drained: Vec<_> = lock(pending).drain().collect();
    for (call, reply) in drained {
        let _ = reply.send((Err(InvokeError::Unknown), Vec::new()));
        tracing::warn!(event = "hub_call_unknown", device = %device, call = call.0);
        hub.emit(HubEvent::Unknown {
            device: device.clone(),
            call,
        });
    }
}

/// A caller that gives up on a call (drops the future) cancels it on the
/// node and forgets it, so the node's answer is reported as late.
struct CancelOnDrop {
    tx: mpsc::UnboundedSender<PrimaryToNode>,
    pending: Pending,
    call: CallId,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            lock(&self.pending).remove(&self.call);
            let _ = self.tx.send(PrimaryToNode::Cancel { call: self.call });
        }
    }
}

async fn send(conn: &mut impl FrameConn, message: &PrimaryToNode) -> Result<(), String> {
    let text = serde_json::to_string(message).map_err(|e| e.to_string())?;
    conn.send(text).await.map_err(|e| e.to_string())
}

async fn recv(conn: &mut impl FrameConn) -> Result<NodeToPrimary, String> {
    let text = conn
        .recv()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("connection closed during the handshake")?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// The model-visible name of a remote capability: `<device>_<capability>`
/// with every character outside `[A-Za-z0-9_-]` replaced by `_` (the tool
/// name alphabet model providers accept), at most 64 characters. The spec's
/// `pc-windows.ui.act` is exposed as `pc-windows_ui_act`.
pub fn remote_name(device: &DeviceId, capability: &str) -> String {
    let raw = format!("{}_{}", device.as_str(), capability);
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect()
}

/// A node's capability as the primary's registry sees it (§5.3). Not local
/// (egress applies), untrusted output (a node's content is like any tool
/// output), and needing approval exactly when its grant does.
pub struct RemoteCapability {
    hub: PrimaryHub,
    device: DeviceId,
    descriptor: CapabilityDescriptor,
    grant: CapabilityGrant,
    name: String,
    description: String,
}

impl RemoteCapability {
    pub fn new(
        hub: PrimaryHub,
        device: DeviceId,
        descriptor: CapabilityDescriptor,
        grant: CapabilityGrant,
    ) -> Self {
        let name = remote_name(&device, &descriptor.name);
        let description = format!("[on device {}] {}", device, descriptor.description);
        Self {
            hub,
            device,
            descriptor,
            grant,
            name,
            description,
        }
    }

    pub fn device(&self) -> &DeviceId {
        &self.device
    }
}

#[async_trait]
impl Capability for RemoteCapability {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn input_schema(&self) -> &Value {
        &self.descriptor.input_schema
    }

    fn needs_approval(&self) -> bool {
        self.grant.needs_approval
    }

    async fn invoke(&self, args: Value, _ctx: &InvokeCtx) -> anyhow::Result<Value> {
        let approval = bastion_runtime::capability::current_approval().map(|id| ApprovalRef { id });
        match self
            .hub
            .invoke(&self.device, &self.descriptor.name, args, approval)
            .await
        {
            Ok((value, evidence)) => Ok(serde_json::json!({
                "device": self.device,
                "result": value,
                "evidence": evidence,
            })),
            Err(e) => Err(anyhow::anyhow!(
                "{} on {}: {e}",
                self.descriptor.name,
                self.device
            )),
        }
    }
}
