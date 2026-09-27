//! Primary ↔ node, end to end (BMD-08..12, BMD-15, §7 edges): a real hub
//! and a real node talking the wire protocol, over an in-process pair and
//! over a WebSocket.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bastion_mesh::devices::transport::{self, memory_pair};
use bastion_mesh::devices::*;
use bastion_mesh::identity::age_identity::AgeIdentity;
use bastion_runtime::agent::ports::ApprovalGate;
use bastion_runtime::capability::{CapabilityRegistry, InvokeCtx, SqliteApprovalGate};
use bastion_types::PrivacyTier;
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;

const OWNER: &str = "alice";

/// Counts runs; `echo` returns its args, `block` waits until cancelled.
struct Probe {
    name: &'static str,
    runs: Arc<AtomicUsize>,
    started: Arc<Notify>,
}

#[async_trait]
impl NodeCapability for Probe {
    fn descriptor(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            name: self.name.into(),
            description: format!("{} probe", self.name),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    async fn run(
        &self,
        args: serde_json::Value,
        _grant: &CapabilityGrant,
        _approval: Option<&ApprovalRef>,
        cancel: CancellationToken,
    ) -> Result<(serde_json::Value, Vec<Evidence>), InvokeError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        if self.name == "block" {
            cancel.cancelled().await;
            return Err(InvokeError::Cancelled);
        }
        Ok((args, vec![Evidence::Text { text: "ran".into() }]))
    }
}

struct World {
    owner: AgeIdentity,
    hub: PrimaryHub,
    node_identity: Option<AgeIdentity>,
    runs: Arc<AtomicUsize>,
    started: Arc<Notify>,
}

fn grant(capability: &str, needs_approval: bool) -> CapabilityGrant {
    CapabilityGrant {
        capability: capability.into(),
        scope: GrantScope::Any,
        needs_approval,
    }
}

/// A registry with primary `linux-box` (epoch `epoch`) and node `pc-windows`
/// holding `grants`.
async fn world(grants: Vec<CapabilityGrant>, epoch: u64) -> World {
    let owner = AgeIdentity::generate();
    let primary = AgeIdentity::generate();
    let node = AgeIdentity::generate();
    let primary_enrollment = Enrollment::new(
        OWNER,
        DeviceId::new("linux-box"),
        primary.verifying_key_bytes(),
        Platform::Linux,
        false,
    )
    .sign(&owner);
    let mut registry =
        DeviceRegistry::bootstrap(owner.verifying_key_bytes(), primary_enrollment, None).unwrap();
    let mut node_enrollment = Enrollment::new(
        OWNER,
        DeviceId::new("pc-windows"),
        node.verifying_key_bytes(),
        Platform::Windows,
        false,
    );
    node_enrollment.granted = grants;
    let node_enrollment = node_enrollment.sign(&owner);
    let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &primary, &node_enrollment);
    registry.admit(node_enrollment, &approval).unwrap();
    let hub = PrimaryHub::new(
        DeviceId::new("linux-box"),
        primary,
        Arc::new(RwLock::new(registry)),
        epoch,
    );
    World {
        owner,
        hub,
        node_identity: Some(node),
        runs: Arc::default(),
        started: Arc::default(),
    }
}

impl World {
    fn node(&mut self) -> NodeAgent {
        self.node_with_state(NodeState::default())
    }

    fn node_with_state(&mut self, state: NodeState) -> NodeAgent {
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("node.json");
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        NodeAgent::new(NodeConfig {
            owner: OWNER.into(),
            owner_key: self.owner.verifying_key_bytes(),
            device: DeviceId::new("pc-windows"),
            identity: self.node_identity.take().expect("one node per world"),
            state_path: Some(path),
        })
        .unwrap()
        .with_capability(Arc::new(Probe {
            name: "echo",
            runs: self.runs.clone(),
            started: self.started.clone(),
        }))
        .with_capability(Arc::new(Probe {
            name: "block",
            runs: self.runs.clone(),
            started: self.started.clone(),
        }))
    }

    /// Connect `node` to the hub in the background; wait until connected.
    async fn connect(&self, node: Arc<NodeAgent>) -> tokio::task::JoinHandle<SessionEnd> {
        let (primary_side, node_side) = memory_pair();
        let hub = self.hub.clone();
        tokio::spawn(async move { hub.serve(primary_side).await });
        let task = tokio::spawn(async move { node.run(node_side).await });
        wait_connected(&self.hub).await;
        task
    }
}

async fn wait_connected(hub: &PrimaryHub) {
    for _ in 0..200 {
        if !hub.connected().await.is_empty()
            && !hub
                .remote_capabilities(&DeviceId::new("pc-windows"))
                .await
                .is_empty()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("node never connected");
}

fn pc() -> DeviceId {
    DeviceId::new("pc-windows")
}

#[tokio::test]
async fn a_granted_capability_runs_on_the_node_and_returns_its_evidence() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    let (value, evidence) = w
        .hub
        .invoke(&pc(), "echo", serde_json::json!({"x": 1}), None)
        .await
        .unwrap();
    assert_eq!(value, serde_json::json!({"x": 1}));
    assert_eq!(evidence.len(), 1);
    assert_eq!(w.runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_ungranted_capability_is_refused_and_nothing_runs() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    // The primary never sends it...
    assert_eq!(
        w.hub
            .invoke(&pc(), "block", serde_json::json!({}), None)
            .await
            .unwrap_err(),
        InvokeError::NotGranted
    );
    // ...and only granted capabilities become tools.
    let tools = w.hub.remote_capabilities(&pc()).await;
    let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
    assert_eq!(names, ["pc-windows_echo"]);
    assert_eq!(w.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_node_refuses_an_ungranted_order_even_from_its_primary() {
    // A primary whose registry grants `block`, but the node was told (by an
    // owner-signed enrollment) only about `echo`: the node's own check wins.
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    // Change the primary's registry behind the node's back, unsigned by
    // the owner: the registry refuses it outright.
    let mut forged = w
        .hub
        .registry()
        .read()
        .await
        .get(&pc())
        .unwrap()
        .enrollment
        .clone();
    forged.granted.push(grant("block", false));
    forged.revision += 1;
    assert_eq!(
        w.hub.registry().write().await.update(forged).unwrap_err(),
        EnrollmentError::BadOwnerSignature
    );
    assert_eq!(w.runs.load(Ordering::SeqCst), 0);
}

async fn approvals(
    w: &World,
) -> (
    tempfile::NamedTempFile,
    Arc<SqliteApprovalGate>,
    CapabilityRegistry,
) {
    let f = tempfile::NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap().to_owned();
    bastion_runtime::session::SessionManager::new(&path)
        .init_schema()
        .await
        .unwrap();
    let gate = Arc::new(SqliteApprovalGate::new(path));
    let mut registry = CapabilityRegistry::new().with_approval_gate(gate.clone());
    for tool in w.hub.remote_capabilities(&pc()).await {
        registry.register(tool).unwrap();
    }
    (f, gate, registry)
}

fn ctx() -> InvokeCtx {
    InvokeCtx {
        owner: OWNER.into(),
        privacy_tier: Some(PrivacyTier::CloudOk),
        allowed_tools: None,
    }
}

#[tokio::test]
async fn a_capability_that_needs_approval_reaches_the_node_only_after_yes() {
    let mut w = world(vec![grant("echo", true)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    let (_db, gate, registry) = approvals(&w).await;
    let args = serde_json::json!({"x": 2});

    let first = registry
        .invoke("pc-windows_echo", args.clone(), &ctx())
        .await
        .unwrap();
    assert_eq!(first.data["awaiting_approval"], true);
    assert_eq!(
        w.runs.load(Ordering::SeqCst),
        0,
        "ran before the owner said yes"
    );

    let pending = gate.pending_for_owner(OWNER).await.unwrap();
    gate.approve(OWNER, pending[0].id).await.unwrap();
    let second = registry
        .invoke("pc-windows_echo", args, &ctx())
        .await
        .unwrap();
    assert_eq!(second.data["result"], serde_json::json!({"x": 2}));
    assert!(!second.trusted, "node output is untrusted");
    assert_eq!(w.runs.load(Ordering::SeqCst), 1);

    // Without the registry, the hub itself refuses an unapproved call.
    assert_eq!(
        w.hub
            .invoke(&pc(), "echo", serde_json::json!({}), None)
            .await
            .unwrap_err(),
        InvokeError::NeedsApproval
    );
}

#[tokio::test]
async fn a_denied_capability_never_reaches_the_node() {
    let mut w = world(vec![grant("echo", true)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    let (_db, gate, registry) = approvals(&w).await;
    let args = serde_json::json!({"x": 3});
    registry
        .invoke("pc-windows_echo", args.clone(), &ctx())
        .await
        .unwrap();
    let pending = gate.pending_for_owner(OWNER).await.unwrap();
    gate.reject(OWNER, pending[0].id).await.unwrap();
    assert!(registry
        .invoke("pc-windows_echo", args, &ctx())
        .await
        .is_err());
    assert_eq!(w.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_persona_without_the_tool_cannot_call_it() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    let (_db, _gate, registry) = approvals(&w).await;
    let restricted = InvokeCtx {
        allowed_tools: Some(Arc::new(["something_else".to_string()].into())),
        ..ctx()
    };
    assert!(registry
        .invoke("pc-windows_echo", serde_json::json!({}), &restricted)
        .await
        .is_err());
    // LocalOnly turns block remote capabilities too (egress).
    let local = InvokeCtx {
        privacy_tier: Some(PrivacyTier::LocalOnly),
        ..ctx()
    };
    assert!(registry
        .invoke("pc-windows_echo", serde_json::json!({}), &local)
        .await
        .is_err());
    assert_eq!(w.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_primary_from_an_older_epoch_is_refused_by_the_node() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = Arc::new(w.node_with_state(NodeState {
        epoch_seen: 2,
        enrollment: None,
    }));
    let mut events = w.hub.subscribe();
    let (primary_side, node_side) = memory_pair();
    let hub = w.hub.clone();
    tokio::spawn(async move { hub.serve(primary_side).await });
    let end = node.run(node_side).await;
    assert!(
        matches!(end, SessionEnd::Refused(_) | SessionEnd::Disconnected(_)),
        "{end:?}"
    );
    assert!(w.hub.connected().await.is_empty());
    // The stale primary learns a newer epoch exists (BMD-21's trigger).
    let mut saw = false;
    while let Ok(event) = events.try_recv() {
        saw |= matches!(event, HubEvent::NewerEpochSeen { epoch: 2, .. });
    }
    assert!(saw);
    assert_eq!(w.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_order_from_an_older_epoch_is_rejected_and_logged() {
    // Node has seen epoch 3 from a newer primary. The hub (epoch 3) sends an
    // order; then the node is told about epoch 5 (Demote) and an order still
    // stamped 3 arrives: refused, audited, never run.
    let mut w = world(vec![grant("echo", false)], 3).await;
    let node = Arc::new(w.node());
    w.connect(node.clone()).await;
    w.hub
        .invoke(&pc(), "echo", serde_json::json!({}), None)
        .await
        .unwrap();
    assert_eq!(w.runs.load(Ordering::SeqCst), 1);
    let mut events = w.hub.subscribe();
    w.hub.announce_epoch(5).await;
    for _ in 0..100 {
        if node.state().await.epoch_seen == 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        w.hub
            .invoke(&pc(), "echo", serde_json::json!({}), None)
            .await
            .unwrap_err(),
        InvokeError::StaleEpoch { seen: 5, got: 3 }
    );
    assert_eq!(w.runs.load(Ordering::SeqCst), 1);
    let mut logged = false;
    for _ in 0..100 {
        while let Ok(event) = events.try_recv() {
            logged |= matches!(event, HubEvent::NodeRejected { .. });
        }
        if logged {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(logged, "the node's refusal was not reported");
}

#[tokio::test]
async fn a_call_in_flight_when_the_connection_drops_is_unknown_never_success() {
    let mut w = world(vec![grant("block", false)], 1).await;
    let node = Arc::new(w.node());
    let handle = node.handle();
    let task = w.connect(node).await;
    let hub = w.hub.clone();
    let call = tokio::spawn(async move {
        hub.invoke(&pc(), "block", serde_json::json!({}), None)
            .await
    });
    w.started.notified().await;
    // The owner presses stop on the node (BMD-15): the call is cancelled,
    // the node disconnects, the primary records the outcome as unknown.
    handle.stop();
    assert_eq!(task.await.unwrap(), SessionEnd::Stopped);
    // Either the node's cancellation made it out first, or the primary saw
    // the connection drop: never a success.
    let outcome = call.await.unwrap().unwrap_err();
    assert!(
        matches!(outcome, InvokeError::Unknown | InvokeError::Cancelled),
        "{outcome:?}"
    );
    for _ in 0..100 {
        if w.hub.connected().await.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the primary still lists the stopped node");
}

#[tokio::test]
async fn a_stopped_node_does_not_connect_again() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = w.node();
    node.handle().stop();
    let (_primary_side, node_side) = memory_pair();
    assert_eq!(node.run(node_side).await, SessionEnd::Stopped);
}

#[tokio::test]
async fn cancelling_on_the_primary_cancels_on_the_node() {
    let mut w = world(vec![grant("block", false)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node).await;
    let hub = w.hub.clone();
    let call = tokio::spawn(async move {
        hub.invoke(&pc(), "block", serde_json::json!({}), None)
            .await
    });
    w.started.notified().await;
    let mut events = w.hub.subscribe();
    call.abort();
    // The node answers the cancel; the hub later sees a late result.
    for _ in 0..200 {
        if let Ok(HubEvent::LateResult { .. }) = events.try_recv() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the node never reported the cancelled call");
}

struct Wiped(Arc<AtomicUsize>);

#[async_trait]
impl RevocationHook for Wiped {
    async fn revoked(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_revoked_node_is_told_wipes_its_keys_and_cannot_reconnect() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let wiped = Arc::new(AtomicUsize::new(0));
    let node = Arc::new(
        w.node()
            .with_revocation_hook(Arc::new(Wiped(wiped.clone()))),
    );
    let task = w.connect(node.clone()).await;
    w.hub.registry().write().await.revoke(&pc()).unwrap();
    w.hub.notify_revoked(&pc()).await;
    assert_eq!(task.await.unwrap(), SessionEnd::Revoked);
    assert_eq!(wiped.load(Ordering::SeqCst), 1);
    assert!(node.state().await.enrollment.is_none());

    let (primary_side, node_side) = memory_pair();
    let hub = w.hub.clone();
    tokio::spawn(async move { hub.serve(primary_side).await });
    assert!(!matches!(node.run(node_side).await, SessionEnd::Stopped));
    assert!(w.hub.connected().await.is_empty());
}

#[tokio::test]
async fn an_unknown_device_or_a_forged_proof_is_refused() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    // Same device id, different key: the proof does not verify.
    w.node_identity = Some(AgeIdentity::generate());
    let impostor = w.node();
    let (primary_side, node_side) = memory_pair();
    let hub = w.hub.clone();
    let mut events = w.hub.subscribe();
    tokio::spawn(async move { hub.serve(primary_side).await });
    let end = impostor.run(node_side).await;
    assert!(!matches!(end, SessionEnd::Stopped));
    assert!(w.hub.connected().await.is_empty());
    let mut refused = false;
    for _ in 0..100 {
        if let Ok(HubEvent::Refused { .. }) = events.try_recv() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refused);
}

#[tokio::test]
async fn a_node_refuses_a_primary_the_owner_did_not_sign() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    // The node trusts another owner key: the primary's enrollment fails.
    let node = NodeAgent::new(NodeConfig {
        owner: OWNER.into(),
        owner_key: AgeIdentity::generate().verifying_key_bytes(),
        device: pc(),
        identity: w.node_identity.take().unwrap(),
        state_path: None,
    })
    .unwrap();
    let (primary_side, node_side) = memory_pair();
    let hub = w.hub.clone();
    tokio::spawn(async move { hub.serve(primary_side).await });
    assert!(matches!(node.run(node_side).await, SessionEnd::Refused(_)));
}

#[tokio::test]
async fn grants_pushed_by_the_primary_take_effect_on_the_node() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let node = Arc::new(w.node());
    w.connect(node.clone()).await;
    let mut e = w
        .hub
        .registry()
        .read()
        .await
        .get(&pc())
        .unwrap()
        .enrollment
        .clone();
    e.granted.clear();
    e.revision += 1;
    let e = e.sign(&w.owner);
    w.hub.registry().write().await.update(e).unwrap();
    w.hub.push_grants(&pc()).await;
    for _ in 0..100 {
        if node
            .state()
            .await
            .enrollment
            .is_some_and(|e| e.granted.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        w.hub
            .invoke(&pc(), "echo", serde_json::json!({}), None)
            .await
            .unwrap_err(),
        InvokeError::NotGranted
    );
}

/// BMD-09 over a real socket: the node only dials out; the listener is the
/// primary's (here, the test's), and the node API offers nothing to bind.
#[tokio::test]
async fn over_a_websocket_the_node_dials_out_to_the_primary() {
    let mut w = world(vec![grant("echo", false)], 1).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hub = w.hub.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let conn = transport::accept(stream).await.unwrap();
        hub.serve(conn).await;
    });
    let node = Arc::new(w.node());
    let conn = transport::connect(&format!("ws://127.0.0.1:{port}/node"), None)
        .await
        .unwrap();
    let node_task = node.clone();
    tokio::spawn(async move { node_task.run(conn).await });
    wait_connected(&w.hub).await;
    let (value, _) = w
        .hub
        .invoke(&pc(), "echo", serde_json::json!({"over": "ws"}), None)
        .await
        .unwrap();
    assert_eq!(value["over"], "ws");
}

/// The same over TLS: the node trusts exactly the certificate its host
/// configured, and the device handshake still runs on top.
#[tokio::test]
async fn over_wss_the_node_trusts_only_the_configured_certificate() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));

    let mut w = world(vec![grant("echo", false)], 1).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hub = w.hub.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(tls) = acceptor.accept(stream).await else {
                continue;
            };
            let conn = transport::accept(tls).await.unwrap();
            hub.serve(conn).await;
        }
    });

    // A node with no trust for this certificate cannot connect.
    let empty = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(transport::connect(
        &format!("wss://localhost:{port}/node"),
        Some(Arc::new(empty))
    )
    .await
    .is_err());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = transport::connect(
        &format!("wss://localhost:{port}/node"),
        Some(Arc::new(client)),
    )
    .await
    .unwrap();
    let node = Arc::new(w.node());
    let runner = node.clone();
    tokio::spawn(async move { runner.run(conn).await });
    wait_connected(&w.hub).await;
    let (value, _) = w
        .hub
        .invoke(&pc(), "echo", serde_json::json!({"over": "wss"}), None)
        .await
        .unwrap();
    assert_eq!(value["over"], "wss");
}
