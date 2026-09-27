//! Losing the primary, promoting a node, and bringing the old primary back
//! (BMD-19..24, §7 "two promoted during a partition").

use std::sync::Arc;
use std::time::Duration;

use bastion_memory::sqlite::SqliteMemory;
use bastion_memory::Memory;
use bastion_mesh::devices::fence::EpochFence;
use bastion_mesh::devices::log::{EventLog, LoggedMemory};
use bastion_mesh::devices::reconcile::{reconcile, ConflictQueue, ConflictStatus, Resolution};
use bastion_mesh::devices::replica::MemoryEventKind;
use bastion_mesh::devices::replica_store::ReplicaStore;
use bastion_mesh::devices::transport::memory_pair;
use bastion_mesh::devices::*;
use bastion_mesh::identity::age_identity::AgeIdentity;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

const OWNER: &str = "alice";

async fn sqlite(dir: &std::path::Path, name: &str) -> (String, SqliteMemory) {
    let path = dir.join(name).to_string_lossy().into_owned();
    bastion_runtime::session::SessionManager::new(&path)
        .init_schema()
        .await
        .unwrap();
    (path.clone(), SqliteMemory::new(path))
}

fn a() -> DeviceId {
    DeviceId::new("linux-box")
}
fn b() -> DeviceId {
    DeviceId::new("pc-windows")
}

async fn contents(memory: &dyn Memory) -> Vec<String> {
    let mut all: Vec<String> = memory
        .retrieve_all_beliefs(OWNER)
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.content)
        .collect();
    all.sort();
    all
}

async fn until<F: std::future::Future<Output = bool>>(mut check: impl FnMut() -> F, what: &str) {
    for _ in 0..300 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out: {what}");
}

#[tokio::test]
async fn a_node_is_promoted_the_old_primary_returns_and_the_owner_decides() {
    let dir = tempfile::tempdir().unwrap();
    let owner = AgeIdentity::generate();
    let a_key = AgeIdentity::generate();
    let b_key = AgeIdentity::generate();
    let a_key_again = AgeIdentity::from_bech32(a_key.age_secret_bech32()).unwrap();
    let b_key_again = AgeIdentity::from_bech32(b_key.age_secret_bech32()).unwrap();

    // Epoch 1: A is primary, B a replica node.
    let mut registry = DeviceRegistry::bootstrap(
        owner.verifying_key_bytes(),
        Enrollment::new(
            OWNER,
            a(),
            a_key.verifying_key_bytes(),
            Platform::Linux,
            true,
        )
        .sign(&owner),
        None,
    )
    .unwrap();
    let e = Enrollment::new(
        OWNER,
        b(),
        b_key.verifying_key_bytes(),
        Platform::Windows,
        true,
    )
    .sign(&owner);
    let approval = EnrollmentApproval::sign(a(), &a_key, &e);
    registry.admit(e, &approval).unwrap();

    let (a_path, a_inner) = sqlite(dir.path(), "a.db").await;
    let a_fence = Arc::new(EpochFence::new(1));
    let a_log = Arc::new(EventLog::open(&a_path, a(), a_fence.clone()).unwrap());
    let a_memory = LoggedMemory::new(Box::new(a_inner), a_log.clone());
    let a_hub = PrimaryHub::new(a(), a_key, Arc::new(RwLock::new(registry)), a_fence.clone());
    let _a_replication = bastion_mesh::devices::replicate::spawn(a_hub.clone(), a_log.clone());

    let replica = Arc::new(
        ReplicaStore::open(dir.path().join("b.replica"), Zeroizing::new([1u8; 32])).unwrap(),
    );
    let b_node = Arc::new(
        NodeAgent::new(NodeConfig {
            owner: OWNER.into(),
            owner_key: owner.verifying_key_bytes(),
            device: b(),
            identity: b_key,
            state_path: None,
        })
        .unwrap()
        .with_replica(replica.clone()),
    );
    let (x, y) = memory_pair();
    let hub = a_hub.clone();
    tokio::spawn(async move { hub.serve(x).await });
    let node = b_node.clone();
    let b_session = tokio::spawn(async move { node.run(y).await });

    let shared = a_memory
        .store_belief(OWNER, None, "shared: likes tea", "s1", "chat", false, None)
        .await
        .unwrap();
    let contested = a_memory
        .store_belief(
            OWNER,
            None,
            "contested: works at X",
            "s1",
            "chat",
            false,
            None,
        )
        .await
        .unwrap();
    let b_revokes = a_memory
        .store_belief(OWNER, None, "stale: lives in Y", "s1", "chat", false, None)
        .await
        .unwrap();
    let _ = shared;
    let fork = a_log.last_seq().unwrap().unwrap();
    until(
        || async { ReplicaSink::last_seq(&*replica).await == Some(fork) },
        "replica caught up",
    )
    .await;
    until(
        || async { b_node.state().await.registry.is_some() },
        "registry replicated",
    )
    .await;

    // Partition: B loses A. Nothing promotes on its own (BMD-20).
    b_session.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let snapshot = b_node.state().await.registry.unwrap();
    assert_eq!(snapshot.primary().unwrap().0.enrollment.device, a());

    // A keeps writing during the partition.
    a_memory
        .store_belief(
            OWNER,
            None,
            "a-only: bought a bike",
            "s2",
            "chat",
            false,
            None,
        )
        .await
        .unwrap();
    a_memory.revoke_belief(OWNER, contested).await.unwrap();

    // The owner promotes B locally (BMD-19): epoch 2, replica rebuilt.
    let mut b_registry = snapshot.clone();
    let epoch = b_registry.promote(&b(), fork).unwrap();
    assert_eq!(epoch, 2);
    let (b_path, b_inner) = sqlite(dir.path(), "b.db").await;
    let b_fence = Arc::new(EpochFence::new(epoch));
    let b_log = Arc::new(EventLog::open(&b_path, b(), b_fence.clone()).unwrap());
    let rest = replica.materialize(&b_inner, &b_log).await.unwrap();
    assert!(rest.is_empty());
    let b_memory = LoggedMemory::new(Box::new(b_inner), b_log.clone());
    assert_eq!(
        contents(&b_memory).await,
        [
            "contested: works at X",
            "shared: likes tea",
            "stale: lives in Y"
        ]
    );
    let b_registry = Arc::new(RwLock::new(b_registry));
    let b_hub = PrimaryHub::new(b(), b_key_again, b_registry.clone(), b_fence.clone());

    // B writes as the new primary: a new belief, a supersession of the
    // belief A revoked (conflict), and a revoke A never touched.
    b_memory
        .store_belief(OWNER, None, "b-only: moved to Z", "s3", "chat", false, None)
        .await
        .unwrap();
    let local = |gid_local: i64| {
        b_log
            .local_id(&bastion_mesh::devices::replica::GlobalId {
                origin: a(),
                local: gid_local,
            })
            .unwrap()
            .unwrap()
    };
    let contested_b = local(contested);
    let revoke_b = local(b_revokes);
    let replacement = b_memory
        .store_belief(
            OWNER,
            None,
            "contested: works at W",
            "s3",
            "chat",
            false,
            None,
        )
        .await
        .unwrap();
    b_memory
        .supersede_belief(OWNER, contested_b, replacement)
        .await
        .unwrap();
    b_memory.revoke_belief(OWNER, revoke_b).await.unwrap();

    // A comes back and meets a device that has seen epoch 2: it stops
    // accepting writes at once (BMD-21).
    a_fence.observe(2);
    assert!(a_memory
        .store_belief(OWNER, None, "late write", "s4", "chat", false, None)
        .await
        .is_err());
    assert!(
        !a_fence.may_refresh(),
        "a stale primary must not refresh credentials"
    );

    // A reconnects to B as a node and hands over what it wrote in epoch 1.
    let a_as_node = Arc::new(
        NodeAgent::new(NodeConfig {
            owner: OWNER.into(),
            owner_key: owner.verifying_key_bytes(),
            device: a(),
            identity: a_key_again,
            state_path: None,
        })
        .unwrap()
        .with_proposals(a_log.clone()),
    );
    let mut b_events = b_hub.subscribe();
    let (x, y) = memory_pair();
    let hub = b_hub.clone();
    tokio::spawn(async move { hub.serve(x).await });
    tokio::spawn(async move { a_as_node.run(y).await });
    until(
        || async { b_hub.connected().await.contains(&a()) },
        "A connected to B",
    )
    .await;
    let after = b_registry.read().await.epoch_start(2).unwrap().after_seq;
    b_hub.request_proposals(&a(), 1, after).await;
    let proposals = loop {
        match tokio::time::timeout(Duration::from_secs(3), b_events.recv()).await {
            Ok(Ok(HubEvent::Proposals {
                events, epoch: 1, ..
            })) => break events,
            Ok(Ok(_)) => continue,
            other => panic!("no proposals: {other:?}"),
        }
    };
    assert_eq!(proposals.len(), 2, "{proposals:?}");

    let queue = ConflictQueue::open(&b_path).unwrap();
    let report = reconcile(&b_memory, &b_log, &queue, 1, proposals)
        .await
        .unwrap();

    // Union without conflict (BMD-22): both sides' new beliefs are present.
    let now = contents(&b_memory).await;
    assert!(
        now.contains(&"a-only: bought a bike".to_string()),
        "{now:?}"
    );
    assert!(now.contains(&"b-only: moved to Z".to_string()), "{now:?}");
    assert!(!now.contains(&"stale: lives in Y".to_string()));
    assert_eq!(report.applied.len(), 1);

    // Conflict (BMD-23): A revoked what B superseded — one item, neither
    // version lost until the owner decides.
    assert_eq!(report.conflicts.len(), 1);
    let pending = queue.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(matches!(
        pending[0].ours.kind,
        MemoryEventKind::BeliefSuperseded { .. }
    ));
    assert!(matches!(
        pending[0].theirs.kind,
        MemoryEventKind::BeliefRevoked { .. }
    ));
    assert!(
        now.contains(&"contested: works at X".to_string()),
        "revoked before the owner decided"
    );

    let decided = queue
        .resolve(pending[0].id, Resolution::TakeTheirs, &b_memory, &b_log)
        .await
        .unwrap();
    assert_eq!(decided.status, ConflictStatus::TookTheirs);
    assert!(!contents(&b_memory)
        .await
        .contains(&"contested: works at X".to_string()));
    assert!(queue.pending().unwrap().is_empty());
    assert!(queue
        .resolve(pending[0].id, Resolution::KeepOurs, &b_memory, &b_log)
        .await
        .is_err());

    // The owner chooses A as primary again (BMD-24): the epoch grows.
    let replica_seq = b_log.last_seq().unwrap().unwrap();
    let epoch = b_registry.write().await.promote(&a(), replica_seq).unwrap();
    assert_eq!(epoch, 3);
    b_fence.observe(3);
    assert!(b_memory
        .store_belief(OWNER, None, "b after demotion", "s5", "chat", false, None)
        .await
        .is_err());
}

#[tokio::test]
async fn of_two_primaries_promoted_in_a_partition_the_higher_epoch_wins() {
    // Two copies of the registry promoted independently: merging them keeps
    // the higher epoch; the other device's fence closes when it sees it.
    let owner = AgeIdentity::generate();
    let a_key = AgeIdentity::generate();
    let b_key = AgeIdentity::generate();
    let c_key = AgeIdentity::generate();
    let mut base = DeviceRegistry::bootstrap(
        owner.verifying_key_bytes(),
        Enrollment::new(
            OWNER,
            a(),
            a_key.verifying_key_bytes(),
            Platform::Linux,
            true,
        )
        .sign(&owner),
        None,
    )
    .unwrap();
    for (id, key) in [("pc-windows", &b_key), ("laptop", &c_key)] {
        let e = Enrollment::new(
            OWNER,
            DeviceId::new(id),
            key.verifying_key_bytes(),
            Platform::Windows,
            true,
        )
        .sign(&owner);
        let approval = EnrollmentApproval::sign(a(), &a_key, &e);
        base.admit(e, &approval).unwrap();
    }
    let mut on_b = base.clone();
    on_b.promote(&b(), 5).unwrap(); // epoch 2
    let mut on_c = base.clone();
    on_c.promote(&DeviceId::new("laptop"), 5).unwrap(); // epoch 2
    on_c.promote(&DeviceId::new("laptop"), 5).unwrap(); // epoch 3 (promoted twice)

    let b_fence = EpochFence::new(on_b.current_epoch());
    on_b.merge(&on_c);
    assert_eq!(
        on_b.primary().unwrap().0.enrollment.device,
        DeviceId::new("laptop")
    );
    assert!(b_fence.observe(on_b.current_epoch()));
    assert!(b_fence.check().is_err());
}
