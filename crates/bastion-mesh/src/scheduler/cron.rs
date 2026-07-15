//! Periodic mesh sync scheduler.
//!
//! Reads `mesh.sync_interval` from bastion.toml (default: 15 minutes).
//! On each tick: iterates all registered peers in MeshPeerMap, builds an OwnerAllowlist
//! per peer from MeshPeer.allowed_tags, calls filter_for_mesh for the local owner,
//! then calls MeshTransport::send for each peer.
//!
//! Manual `/mesh-sync` skill command still works and calls the same send path.
//! The scheduler is ADDITIVE — it does not replace the manual command.
//!
//! Config key: `mesh.sync_interval` (u64, minutes, default 15).
//! Set to 0 to disable periodic sync (manual-only mode).

use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use crate::memory::SharedMemory;
use crate::mesh::allowlist::{filter_for_mesh, OwnerAllowlist};
use crate::mesh::{MeshPeerMap, SelectiveSlice, SharedMeshTransport};

/// Spawn a background task that syncs mesh slices to all registered peers
/// every `sync_interval_minutes` minutes.
///
/// Calls filter_for_mesh (with the peer's allowed_tags) before MeshTransport::send —
/// enforces the same allowlist gate as the manual /mesh-sync command (T-06-02-08).
///
/// Set sync_interval_minutes to 0 to disable periodic sync (returns immediately).
pub fn spawn_mesh_sync_job(
    transport: SharedMeshTransport,
    peers: Arc<tokio::sync::RwLock<MeshPeerMap>>,
    memory: SharedMemory,
    local_owner: String,
    sync_interval_minutes: u64,
) -> tokio::task::JoinHandle<()> {
    if sync_interval_minutes == 0 {
        tracing::info!(
            event = "mesh_sync_job_disabled",
            "periodic mesh sync disabled (sync_interval=0)"
        );
        return tokio::spawn(async {});
    }

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(sync_interval_minutes * 60));
        interval.tick().await; // skip first immediate tick — don't sync on startup

        loop {
            interval.tick().await;

            // Snapshot peer list (owner_id + allowed_tags) under read lock
            let peer_list: Vec<(String, Vec<String>)> = {
                let map = peers.read().await;
                map.all_peer_owner_ids()
                    .into_iter()
                    .filter_map(|owner_id| {
                        map.resolve(&owner_id)
                            .map(|p| (owner_id, p.allowed_tags.clone()))
                    })
                    .collect()
            };

            if peer_list.is_empty() {
                tracing::debug!(
                    event = "mesh_sync_tick_no_peers",
                    "no peers registered, skipping"
                );
                continue;
            }

            let mut synced = 0usize;

            for (peer_owner, allowed_tags) in &peer_list {
                // Build filtered slice for this peer (filter_for_mesh applies allowlist + CloudOk gate)
                let slice =
                    match build_filtered_slice(&memory, &local_owner, peer_owner, allowed_tags)
                        .await
                    {
                        Ok(s) if !s.beliefs.is_empty() => s,
                        Ok(_) => {
                            tracing::debug!(
                                event = "mesh_sync_tick_empty_slice",
                                peer = %peer_owner,
                                "no shareable beliefs for peer — skipping"
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                event = "mesh_sync_tick_slice_error",
                                peer = %peer_owner,
                                error = %e
                            );
                            continue;
                        }
                    };

                if let Err(e) = transport.send(slice, peer_owner).await {
                    // Non-fatal: log and continue to next peer (one peer failure doesn't block others)
                    tracing::warn!(
                        event = "mesh_sync_tick_send_error",
                        peer = %peer_owner,
                        error = %e
                    );
                } else {
                    synced += 1;
                }
            }

            tracing::info!(
                event = "mesh_sync_tick_complete",
                peers_attempted = peer_list.len(),
                peers_synced = synced,
                sync_interval_minutes,
            );
        }
    })
}

/// Build a filtered SelectiveSlice for a specific peer.
/// Loads all beliefs for local_owner, constructs OwnerAllowlist from peer's allowed_tags,
/// passes through filter_for_mesh (tag allowlist + CloudOk egress gate).
async fn build_filtered_slice(
    memory: &SharedMemory,
    local_owner: &str,
    peer_owner: &str,
    allowed_tags: &[String],
) -> anyhow::Result<SelectiveSlice> {
    let mem = memory.read().await;
    // retrieve_tagged(owner, None) returns all non-revoked beliefs for the owner regardless of tag.
    let all_beliefs = mem.retrieve_tagged(local_owner, None).await?;
    drop(mem);

    let allowlist = OwnerAllowlist {
        owner_id: peer_owner.to_string(),
        allowed_tags: allowed_tags.to_vec(),
    };
    let filtered = filter_for_mesh(all_beliefs, &allowlist);

    Ok(SelectiveSlice {
        from_owner: local_owner.to_string(),
        beliefs: filtered,
    })
}
