//! Replicating the primary's memory to a node (BMD-16..18) and sealing
//! secrets to one device (BMD-18, BMD-29..31).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bastion_memory::sqlite::SqliteMemory;
use bastion_memory::Memory;
use bastion_mesh::devices::log::{EventLog, LoggedMemory};
use bastion_mesh::devices::replica::MemoryEventKind;
use bastion_mesh::devices::replica_store::ReplicaStore;
use bastion_mesh::devices::secrets::{self, SealedSecret, SealedSecretStore, SecretValue};
use bastion_mesh::devices::transport::memory_pair;
use bastion_mesh::devices::*;
use bastion_mesh::identity::age_identity::AgeIdentity;
use bastion_types::PrivacyTier;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

const OWNER: &str = "alice";
const CANARY: &str = "belief-canary-7f3a";
const SECRET_CANARY: &str = "sk-secret-canary-91c2";

async fn memory(dir: &std::path::Path, name: &str) -> (String, SqliteMemory) {
    let path = dir.join(name).to_string_lossy().into_owned();
    bastion_runtime::session::SessionManager::new(&path)
        .init_schema()
        .await
        .unwrap();
    (path.clone(), SqliteMemory::new(path))
}

struct Setup {
    dir: tempfile::TempDir,
    owner: AgeIdentity,
    hub: PrimaryHub,
    log: Arc<EventLog>,
    primary_memory: LoggedMemory,
    node_identity: Option<AgeIdentity>,
    secrets_identity: age::x25519::Identity,
}

async fn setup(holds_replica: bool) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let owner = AgeIdentity::generate();
    let primary = AgeIdentity::generate();
    let node = AgeIdentity::generate();
    let secrets_identity = age::x25519::Identity::generate();
    let mut registry = DeviceRegistry::bootstrap(
        owner.verifying_key_bytes(),
        Enrollment::new(
            OWNER,
            DeviceId::new("linux-box"),
            primary.verifying_key_bytes(),
            Platform::Linux,
            false,
        )
        .sign(&owner),
        None,
    )
    .unwrap();
    let mut e = Enrollment::new(
        OWNER,
        DeviceId::new("pc-windows"),
        node.verifying_key_bytes(),
        Platform::Windows,
        holds_replica,
    );
    e.secrets_recipient = Some(secrets_identity.to_public().to_string());
    let e = e.sign(&owner);
    let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &primary, &e);
    registry.admit(e, &approval).unwrap();

    let (path, inner) = memory(dir.path(), "primary.db").await;
    let log = Arc::new(EventLog::open(&path, DeviceId::new("linux-box"), 1).unwrap());
    let primary_memory = LoggedMemory::new(Box::new(inner), log.clone());
    let hub = PrimaryHub::new(
        DeviceId::new("linux-box"),
        primary,
        Arc::new(RwLock::new(registry)),
        1,
    );
    Setup {
        dir,
        owner,
        hub,
        log,
        primary_memory,
        node_identity: Some(node),
        secrets_identity,
    }
}

fn replica_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([7u8; 32])
}

impl Setup {
    fn node(&mut self, store: Arc<ReplicaStore>) -> Arc<NodeAgent> {
        Arc::new(
            NodeAgent::new(NodeConfig {
                owner: OWNER.into(),
                owner_key: self.owner.verifying_key_bytes(),
                device: DeviceId::new("pc-windows"),
                identity: self.node_identity.take().unwrap(),
                state_path: None,
            })
            .unwrap()
            .with_replica(store),
        )
    }

    fn connect(&self, node: Arc<NodeAgent>) -> tokio::task::JoinHandle<SessionEnd> {
        let (a, b) = memory_pair();
        let hub = self.hub.clone();
        tokio::spawn(async move { hub.serve(a).await });
        tokio::spawn(async move { node.run(b).await })
    }

    async fn write_some(&self) -> (i64, i64, i64) {
        let m = &self.primary_memory;
        let a = m
            .store_belief(
                OWNER,
                None,
                &format!("{CANARY} likes tea"),
                "s1",
                "chat",
                false,
                Some(PrivacyTier::LocalOnly),
            )
            .await
            .unwrap();
        let b = m
            .store_belief(
                OWNER,
                Some("coach"),
                "runs on mondays",
                "s1",
                "chat",
                false,
                Some(PrivacyTier::CloudOk),
            )
            .await
            .unwrap();
        let c = m
            .store_belief(
                OWNER,
                None,
                "runs on tuesdays",
                "s2",
                "chat",
                false,
                Some(PrivacyTier::CloudOk),
            )
            .await
            .unwrap();
        m.supersede_belief(OWNER, b, c).await.unwrap();
        let d = m
            .store_belief(OWNER, None, "wrong fact", "s2", "chat", false, None)
            .await
            .unwrap();
        m.revoke_belief(OWNER, d).await.unwrap();
        (a, b, c)
    }
}

async fn wait_for_seq(store: &ReplicaStore, seq: u64) {
    for _ in 0..300 {
        if bastion_mesh::devices::ReplicaSink::last_seq(store).await == Some(seq) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "replica stuck at {:?}, wanted {seq}",
        bastion_mesh::devices::ReplicaSink::last_seq(store).await
    );
}

/// Contents of the owner's live beliefs, and which contents are superseded.
async fn state(memory: &dyn Memory) -> (Vec<String>, Vec<String>) {
    let mut live: Vec<String> = memory
        .retrieve_all_beliefs(OWNER)
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.content)
        .collect();
    live.sort();
    let mut superseded: Vec<String> = memory
        .retrieve_all_beliefs(OWNER)
        .await
        .unwrap()
        .into_iter()
        .filter(|b| b.superseded_by.is_some())
        .map(|b| b.content)
        .collect();
    superseded.sort();
    (live, superseded)
}

#[tokio::test]
async fn the_replica_follows_the_primary_during_use_and_rebuilds_the_same_state() {
    let mut s = setup(true).await;
    let store =
        Arc::new(ReplicaStore::open(s.dir.path().join("replica.bin"), replica_key()).unwrap());
    let node = s.node(store.clone());
    let _replication = bastion_mesh::devices::replicate::spawn(s.hub.clone(), s.log.clone());
    s.connect(node);
    for _ in 0..200 {
        if !s.hub.connected().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    s.write_some().await;
    s.log
        .record(MemoryEventKind::ConfigChanged {
            key: "default_model".into(),
        })
        .unwrap();
    let last = s.log.last_seq().unwrap().unwrap();
    wait_for_seq(&store, last).await;
    // The primary heard the acknowledgement of the last seq.
    for _ in 0..100 {
        if s.hub.replica_seq(&DeviceId::new("pc-windows")).await == Some(last) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        s.hub.replica_seq(&DeviceId::new("pc-windows")).await,
        Some(last)
    );

    // Promotion: rebuild into a fresh memory.
    let (path, fresh) = memory(s.dir.path(), "promoted.db").await;
    let new_log = EventLog::open(&path, DeviceId::new("pc-windows"), 2).unwrap();
    let rest = store.materialize(&fresh, &new_log).await.unwrap();
    assert_eq!(state(&fresh).await, state(&s.primary_memory).await);
    assert!(matches!(
        rest.last().unwrap().kind,
        MemoryEventKind::ConfigChanged { .. }
    ));
    // The promoted log continues the same sequence.
    assert_eq!(new_log.last_seq().unwrap(), Some(last));
    let next = new_log
        .record(MemoryEventKind::ConfigChanged { key: "x".into() })
        .unwrap();
    assert_eq!(next.seq, last + 1);
    assert_eq!(next.epoch, 2);
}

#[tokio::test]
async fn a_node_that_was_offline_catches_up_when_it_connects() {
    let mut s = setup(true).await;
    s.write_some().await;
    let last = s.log.last_seq().unwrap().unwrap();
    let store =
        Arc::new(ReplicaStore::open(s.dir.path().join("replica.bin"), replica_key()).unwrap());
    let _replication = bastion_mesh::devices::replicate::spawn(s.hub.clone(), s.log.clone());
    let node = s.node(store.clone());
    s.connect(node);
    wait_for_seq(&store, last).await;
}

#[tokio::test]
async fn the_replica_file_is_unreadable_without_the_key() {
    let mut s = setup(true).await;
    let path = s.dir.path().join("replica.bin");
    let store = Arc::new(ReplicaStore::open(&path, replica_key()).unwrap());
    let _replication = bastion_mesh::devices::replicate::spawn(s.hub.clone(), s.log.clone());
    let node = s.node(store.clone());
    s.connect(node);
    s.write_some().await;
    wait_for_seq(&store, s.log.last_seq().unwrap().unwrap()).await;

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.is_empty());
    assert!(
        !bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
        "belief text on disk in the clear"
    );
    let wrong = ReplicaStore::open(&path, Zeroizing::new([8u8; 32]));
    assert!(wrong.is_err(), "opened with the wrong key");
    let right = ReplicaStore::open(&path, replica_key()).unwrap();
    assert!(right
        .read_all()
        .unwrap()
        .iter()
        .any(|e| matches!(&e.kind, MemoryEventKind::BeliefStored { belief, .. } if belief.content.contains(CANARY))));
}

#[tokio::test]
async fn a_node_without_holds_replica_refuses_replica_batches() {
    let mut s = setup(false).await;
    let store =
        Arc::new(ReplicaStore::open(s.dir.path().join("replica.bin"), replica_key()).unwrap());
    let node = s.node(store.clone());
    let _replication = bastion_mesh::devices::replicate::spawn(s.hub.clone(), s.log.clone());
    s.connect(node);
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.write_some().await;
    // Not even sent: the registry says this node keeps no replica.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        bastion_mesh::devices::ReplicaSink::last_seq(&*store).await,
        None
    );
}

#[tokio::test]
async fn a_replica_batch_with_a_gap_is_refused_and_duplicates_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = memory(dir.path(), "p.db").await;
    let log = EventLog::open(&path, DeviceId::new("p"), 1).unwrap();
    for key in ["a", "b", "c"] {
        log.record(MemoryEventKind::ConfigChanged { key: key.into() })
            .unwrap();
    }
    let events = log.since(None).unwrap();
    let store = ReplicaStore::open(dir.path().join("r.bin"), replica_key()).unwrap();
    use bastion_mesh::devices::ReplicaSink;
    assert!(store.apply(2, events[1..].to_vec()).await.is_err());
    assert_eq!(store.apply(1, events[..2].to_vec()).await.unwrap(), 2);
    assert_eq!(store.apply(1, events.clone()).await.unwrap(), 3);
    assert_eq!(store.read_all().unwrap().len(), 3);
}

#[tokio::test]
async fn events_never_carry_secret_values() {
    let s = setup(true).await;
    s.log
        .record(MemoryEventKind::ConfigChanged {
            key: "anthropic_api_key".into(),
        })
        .unwrap();
    let serialized = serde_json::to_string(&s.log.since(None).unwrap()).unwrap();
    assert!(!serialized.contains(SECRET_CANARY));
}

fn lookup(name: &str) -> Option<SecretValue> {
    (name == "anthropic_api_key").then(|| SecretValue {
        value: Zeroizing::new(SECRET_CANARY.as_bytes().to_vec()),
        version: 3,
    })
}

#[tokio::test]
async fn secrets_are_sealed_only_per_secret_and_per_device() {
    let s = setup(true).await;
    let pc = DeviceId::new("pc-windows");
    // No grant: nothing.
    let record = s.hub.registry().read().await.get(&pc).unwrap().clone();
    assert!(secrets::seal_for_device(&record, lookup)
        .unwrap()
        .is_empty());

    // A grant for this device: exactly that secret, sealed.
    let mut granted = record.clone();
    granted.secret_grants.push(SecretGrant {
        secret: "anthropic_api_key".into(),
        device: pc.clone(),
        granted_at: 1,
    });
    // A grant naming another device never seals for this one.
    granted.secret_grants.push(SecretGrant {
        secret: "codex:work".into(),
        device: DeviceId::new("laptop"),
        granted_at: 1,
    });
    let sealed = secrets::seal_for_device(&granted, lookup).unwrap();
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].name, "anthropic_api_key");
    assert_eq!(sealed[0].version, 3);
    let bytes = serde_json::to_vec(&sealed).unwrap();
    assert!(!bytes
        .windows(SECRET_CANARY.len())
        .any(|w| w == SECRET_CANARY.as_bytes()));
    // Only the secrets key (unwrapped at promotion) opens it.
    assert_eq!(
        &*secrets::open(&s.secrets_identity, &sealed[0]).unwrap(),
        SECRET_CANARY.as_bytes()
    );
    assert!(secrets::open(&age::x25519::Identity::generate(), &sealed[0]).is_err());

    // A revoked device gets nothing, grants or not.
    granted.revoked = true;
    assert!(secrets::seal_for_device(&granted, lookup)
        .unwrap()
        .is_empty());
}

struct Kept(SealedSecretStore, Arc<AtomicUsize>);

#[async_trait]
impl SecretSink for Kept {
    async fn replace(&self, secrets: Vec<SealedSecret>) -> anyhow::Result<()> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.replace(&secrets)
    }
}

#[tokio::test]
async fn a_rotation_replaces_the_sealed_secret_on_the_node() {
    let mut s = setup(false).await;
    let pc = DeviceId::new("pc-windows");
    let path = s.dir.path().join("sealed.json");
    let calls = Arc::new(AtomicUsize::new(0));
    let node = Arc::new(
        NodeAgent::new(NodeConfig {
            owner: OWNER.into(),
            owner_key: s.owner.verifying_key_bytes(),
            device: pc.clone(),
            identity: s.node_identity.take().unwrap(),
            state_path: None,
        })
        .unwrap()
        .with_secrets(Arc::new(Kept(SealedSecretStore::new(&path), calls.clone()))),
    );
    s.connect(node);
    for _ in 0..200 {
        if !s.hub.connected().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let recipient = s.secrets_identity.to_public().to_string();
    for version in [1, 2] {
        let sealed = secrets::seal(
            &recipient,
            &pc,
            "codex:work",
            version,
            format!("token-v{version}").as_bytes(),
        )
        .unwrap();
        s.hub.send_secrets(&pc, vec![sealed]).await;
        for _ in 0..200 {
            if calls.load(Ordering::SeqCst) == version as usize {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let kept = SealedSecretStore::new(&path).load().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept[0].version, 2,
        "an older token is still the newest one kept"
    );
    assert_eq!(
        &*secrets::open(&s.secrets_identity, &kept[0]).unwrap(),
        b"token-v2"
    );
}
