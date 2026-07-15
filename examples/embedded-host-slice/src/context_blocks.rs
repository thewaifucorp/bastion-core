//! Component 2 (`docs/revamp/C3-m5-second-consumer-design.md` §"Componentes"):
//! authoritative context injection via `TurnContextProvider` (SEAM #2) — no
//! patch to the kernel, just a public trait implementation.
//!
//! Owner-scoped by construction: each owner sees only ITS OWN authoritative
//! object, never another owner's — doubles as part of the M5 two-owner
//! isolation proof (§"Componentes" 5), since `main.rs` runs the SAME
//! provider instance for both owners in one process.

use std::collections::HashMap;

use async_trait::async_trait;
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};
use bastion_runtime::memory::PrivacyTier;

/// Stands in for an embedding host's own authoritative business state (e.g.
/// "the case the operator is looking at"). The kernel concatenates `content`
/// into the system prompt VERBATIM — it never parses or interprets it
/// (invariant #8, `docs/SECURITY-INVARIANTS.md`).
pub struct HostObjectContextProvider {
    /// owner -> this owner's own opaque object block. A real host would
    /// resolve this from its own store keyed by owner; here it is a fixed
    /// map built at construction, which is enough to prove the isolation
    /// property (owner A never sees owner B's object, and vice versa).
    objects: HashMap<String, String>,
}

impl HostObjectContextProvider {
    /// `owner_objects` is `(owner, opaque_content)` pairs — an owner absent
    /// from this list gets zero context blocks (never another owner's).
    pub fn new(owner_objects: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            objects: owner_objects.into_iter().collect(),
        }
    }
}

#[async_trait]
impl TurnContextProvider for HostObjectContextProvider {
    async fn context_for_turn(
        &self,
        owner: &str,
        _turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        match self.objects.get(owner) {
            Some(content) => vec![ContextBlock {
                content: content.clone(),
                // CloudOk: this embedded host has decided this particular
                // object summary is safe to send to a cloud-backed provider.
                // A real host would derive this per-object, never hardcode it.
                max_tier: PrivacyTier::CloudOk,
            }],
            // No object on file for this owner — zero blocks, never another
            // owner's content. `Vec::new()` is an explicitly valid return
            // (see `TurnContextProvider::context_for_turn`'s own rustdoc).
            None => Vec::new(),
        }
    }
}
