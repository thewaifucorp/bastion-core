//! MeshSliceProvider: TurnContextProvider impl that injects a remote owner's selective
//! memory slice into the system prompt via SEAM #2 (opaque ContextBlock).
//!
//! SEAM #2 rule: content is OPAQUE — AgentLoop includes it verbatim, never parses.
//! ContextBlock.max_tier = CloudOk (mesh only carries CloudOk beliefs per filter_for_mesh).
//!
//! ## MESH-03: Inter-owner Cabinet (async synthesis exchange) — D-04 (LOCKED) neutral mechanism
//!
//! Pattern (runnable):
//! 1. Mario issues a decision request requiring cross-owner input (e.g. "plan family vacation").
//! 2. Mario's AgentLoop convenes Cabinet locally: Finance + Calendar personas deliberate.
//! 3. After deliberation completes, AgentLoop's caller invokes write_cabinet_synthesis()
//!    explicitly — this function stores the result as a belief tagged "mesh_cabinet_synthesis"
//!    with CloudOk tier. NOTE: write_cabinet_synthesis() is NOT called automatically; the
//!    Cabinet does NOT auto-trigger it. The caller (AgentLoop or skill) decides when to call it.
//! 4. filter_for_mesh includes "mesh_cabinet_synthesis" if "mesh_cabinet_synthesis" is in
//!    Ana's allowlist. Ana's allowlist must list this tag to receive Cabinet synthesis.
//! 5. MeshTransport::send delivers the synthesis slice to Ana's /mesh/ingest.
//! 6. Ana's next turn sees it via MeshSliceProvider (SEAM #2):
//!    "[mario:mesh_cabinet_synthesis] vacation plan: ..."
//! 7. Ana's Cabinet can deliberate with Mario's synthesis as context input.
//!
//! This is an ASYNC exchange — no blocking, no unified Cabinet across instances.
//! Rich governance (sync, HITL, RBAC) lives in a separate closed layer. OSS = neutral mechanism only.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::agent::context::{ContextBlock, TurnContextProvider};
use crate::memory::{Belief, PrivacyTier, SharedMemory};

/// In-memory store of received slices from mesh peers.
/// Keyed by from_owner. Updated by ingest_handler when a new slice arrives.
pub type MeshSliceStore = Arc<RwLock<HashMap<String, Vec<Belief>>>>;

pub struct MeshSliceProvider {
    /// Receives slices from ingest_handler via this store.
    slice_store: MeshSliceStore,
    /// The local owner_id (to scope context correctly).
    /// WR-06: this must be set from the real BASTION_OWNER_ID, not session_id.
    // ponytail: held but not yet read — part of the WR-06 constructor contract; the
    // per-owner slice-scoping read site is not wired yet. Kept (not removed) so the
    // contract and the two public constructors stay stable for that wiring.
    #[allow(dead_code)]
    local_owner: String,
}

impl MeshSliceProvider {
    pub fn new(local_owner: String) -> (Self, MeshSliceStore) {
        let store: MeshSliceStore = Arc::new(RwLock::new(HashMap::new()));
        let provider = Self {
            slice_store: store.clone(),
            local_owner,
        };
        (provider, store)
    }

    pub fn from_store(local_owner: String, slice_store: MeshSliceStore) -> Self {
        Self {
            local_owner,
            slice_store,
        }
    }
}

#[async_trait::async_trait]
impl TurnContextProvider for MeshSliceProvider {
    /// Inject all received mesh slices as opaque ContextBlocks.
    /// Non-fatal: on error → warn + return vec![] (never block the turn).
    /// Content is formatted for human readability but OPAQUE to AgentLoop logic.
    async fn context_for_turn(
        &self,
        _owner: &str,
        _turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        let store = self.slice_store.read().await;
        if store.is_empty() {
            return vec![];
        }

        let mut blocks = Vec::new();
        for (from_owner, beliefs) in store.iter() {
            if beliefs.is_empty() {
                continue;
            }
            // Format as opaque text block — AgentLoop includes verbatim, never parses structure
            let lines: Vec<String> = beliefs
                .iter()
                .map(|b| {
                    let tag = b.persona_tag.as_deref().unwrap_or("general");
                    format!("[{}:{}] {}", from_owner, tag, b.content)
                })
                .collect();
            let content = format!(
                "=== Shared context from {} ===\n{}\n===",
                from_owner,
                lines.join("\n")
            );

            blocks.push(ContextBlock {
                content,
                // CloudOk: filter_for_mesh guarantees only CloudOk beliefs in the slice
                max_tier: PrivacyTier::CloudOk,
            });
        }
        blocks
    }
}

/// MESH-03: Write Cabinet synthesis result as a belief tagged "mesh_cabinet_synthesis".
///
/// Stores with `PrivacyTier::CloudOk` so `filter_for_mesh` includes it when a peer's
/// `allowed_tags` contains `"mesh_cabinet_synthesis"`. Callers invoke this EXPLICITLY
/// after local Cabinet deliberation completes — not called automatically.
///
/// This is the ONLY code path that creates mesh_cabinet_synthesis beliefs —
/// it reuses the existing SharedMemory write path (no new storage mechanism).
pub async fn write_cabinet_synthesis(
    memory: &SharedMemory,
    owner_id: &str,
    synthesis_content: &str,
) -> anyhow::Result<()> {
    let mem = memory.read().await;
    mem.store_belief(
        owner_id,
        Some("mesh_cabinet_synthesis"),
        synthesis_content,
        "cabinet_synthesis",                       // session_id placeholder
        "cabinet_synthesis",                       // source
        false,                                     // not a core belief
        Some(crate::memory::PrivacyTier::CloudOk), // CR-04: synthesis must cross the mesh
    )
    .await?;
    tracing::info!(
        event = "mesh_cabinet_synthesis_written",
        owner_id = %owner_id,
        "Cabinet synthesis stored with CloudOk tier — filter_for_mesh will include it when peer allowlist contains 'mesh_cabinet_synthesis'"
    );
    Ok(())
}
