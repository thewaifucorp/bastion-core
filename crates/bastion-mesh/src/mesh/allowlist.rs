//! Per-owner export tag allowlist (D-03, D-05).
//! filter_for_mesh runs BEFORE check_egress — LocalOnly beliefs are stripped here
//! so the egress gate only ever sees CloudOk beliefs for mesh.

use crate::hooks::egress::check_egress;
use crate::memory::Belief;

/// Declares which belief tags this owner permits to flow to a specific peer.
#[derive(Debug, Clone)]
pub struct OwnerAllowlist {
    pub owner_id: String,
    /// Tags the remote peer may receive. Conservative: belief with no tag → filtered out.
    pub allowed_tags: Vec<String>,
}

/// Filter beliefs to only those the allowlist permits AND whose tier allows egress.
///
/// Two-stage:
/// 1. Tag allowlist: belief.persona_tag must be in allowed_tags. No tag → filtered out.
/// 2. Egress gate: check_egress(belief.tier, "mesh") — LocalOnly always denied.
///
/// Result: only CloudOk beliefs with an explicitly-allowlisted tag survive.
pub fn filter_for_mesh(beliefs: Vec<Belief>, allowlist: &OwnerAllowlist) -> Vec<Belief> {
    beliefs
        .into_iter()
        .filter(|b| {
            // Stage 1: tag allowlist
            let tag_ok = b
                .persona_tag
                .as_ref()
                .map(|t| allowlist.allowed_tags.contains(t))
                .unwrap_or(false); // no tag → deny (conservative)
            if !tag_ok {
                return false;
            }
            // Stage 2: egress gate — LocalOnly and None tier are denied
            check_egress(b.tier, "mesh").is_ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::{Belief, BeliefDraft, BeliefKind, Memory, PrivacyTier};
    use crate::session::sqlite::SessionManager;
    use tempfile::NamedTempFile;

    fn make_belief(tag: Option<&str>, tier: Option<PrivacyTier>) -> Belief {
        Belief {
            id: 0,
            owner_id: "mario".to_string(),
            persona_tag: tag.map(|t| t.to_string()),
            content: "test belief".to_string(),
            weight: 1.0,
            is_core: false,
            tier,
            kind: BeliefKind::Factual,
            keywords: vec![],
            issue: None,
            helpful_count: 0,
            harmful_count: 0,
            neutral_count: 0,
            valid_from: None,
            valid_until: None,
            superseded_by: None,
            supersedes_at: None,
        }
    }

    fn allowlist(tags: &[&str]) -> OwnerAllowlist {
        OwnerAllowlist {
            owner_id: "ana".to_string(),
            allowed_tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn cloudok_with_allowed_tag_passes() {
        let beliefs = vec![make_belief(Some("mercado"), Some(PrivacyTier::CloudOk))];
        let result = filter_for_mesh(beliefs, &allowlist(&["mercado", "calendario"]));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn localonly_always_filtered_even_if_tag_allowed() {
        let beliefs = vec![make_belief(Some("mercado"), Some(PrivacyTier::LocalOnly))];
        let result = filter_for_mesh(beliefs, &allowlist(&["mercado"]));
        assert!(result.is_empty(), "LocalOnly must never leave the node");
    }

    #[test]
    fn tag_not_in_allowlist_filtered() {
        let beliefs = vec![make_belief(Some("saude"), Some(PrivacyTier::CloudOk))];
        let result = filter_for_mesh(beliefs, &allowlist(&["mercado"]));
        assert!(result.is_empty());
    }

    #[test]
    fn no_tag_filtered() {
        let beliefs = vec![make_belief(None, Some(PrivacyTier::CloudOk))];
        let result = filter_for_mesh(beliefs, &allowlist(&["mercado"]));
        assert!(result.is_empty());
    }

    #[test]
    fn none_tier_filtered() {
        let beliefs = vec![make_belief(Some("mercado"), None)];
        let result = filter_for_mesh(beliefs, &allowlist(&["mercado"]));
        assert!(result.is_empty());
    }

    // LEARN-06: filter_for_mesh destructures Belief but never reads `.kind` — these two
    // tests are a literal one-line diff from `cloudok_with_allowed_tag_passes` /
    // `localonly_always_filtered_even_if_tag_allowed` (kind overridden to Procedural),
    // proving the mesh filter is kind-agnostic today and catching a regression if anyone
    // ever adds a kind-aware branch to the mesh path.
    #[test]
    fn procedural_kind_belief_passes_filter_for_mesh_identically_to_factual() {
        let mut belief = make_belief(Some("mercado"), Some(PrivacyTier::CloudOk));
        belief.kind = BeliefKind::Procedural;
        let result = filter_for_mesh(vec![belief], &allowlist(&["mercado", "calendario"]));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn procedural_kind_local_only_always_filtered() {
        let mut belief = make_belief(Some("mercado"), Some(PrivacyTier::LocalOnly));
        belief.kind = BeliefKind::Procedural;
        let result = filter_for_mesh(vec![belief], &allowlist(&["mercado"]));
        assert!(
            result.is_empty(),
            "LocalOnly must never leave the node, regardless of belief kind"
        );
    }

    // Relocated from `bastion-memory`'s `sqlite.rs` (M2 step 4 — extraction of the
    // `bastion-memory` crate, docs/ARCHITECTURE.md, V4 "memory → mesh"
    // edge). These exercise `SqliteMemory` (a real DB round trip) together with
    // `filter_for_mesh` — cross-cutting integration coverage between the memory
    // backend and the mesh privacy filter. `bastion-memory` cannot depend on `mesh`
    // (mesh stays in the app crate today / becomes `bastion-mesh` after memory in the
    // extraction order), so this is their correct home: the app module that already
    // legally depends on both.

    async fn make_db() -> (NamedTempFile, SqliteMemory) {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_str().unwrap().to_owned();
        let session_mgr = SessionManager::new(&path);
        session_mgr.init_schema().await.expect("init_schema");
        let mem = SqliteMemory::new(&path);
        (f, mem)
    }

    #[tokio::test]
    async fn test_tier_persists_and_survives_filter_for_mesh() {
        let (_f, mem) = make_db().await;

        // Store a CloudOk belief with a tag in the allowlist
        mem.store_belief(
            "owner1",
            Some("mercado"),
            "Alice spends 2k/month on groceries",
            "sess1",
            "user",
            false,
            Some(PrivacyTier::CloudOk),
        )
        .await
        .expect("store cloud-ok belief");

        // Store a LocalOnly belief — should be stripped
        mem.store_belief(
            "owner1",
            Some("mercado"),
            "Alice's bank password",
            "sess2",
            "user",
            false,
            Some(PrivacyTier::LocalOnly),
        )
        .await
        .expect("store local-only belief");

        // Retrieve from real DB (not hand-built Beliefs)
        let beliefs = mem
            .retrieve_tagged("owner1", Some("mercado"))
            .await
            .expect("retrieve");
        assert_eq!(beliefs.len(), 2, "both beliefs should be retrieved");

        // filter_for_mesh with allowlist that includes 'mercado'
        let allowlist = OwnerAllowlist {
            owner_id: "owner1".to_string(),
            allowed_tags: vec!["mercado".to_string()],
        };
        let passed = filter_for_mesh(beliefs, &allowlist);

        // Only CloudOk belief survives
        assert_eq!(
            passed.len(),
            1,
            "only CloudOk belief must survive filter_for_mesh"
        );
        assert_eq!(passed[0].content, "Alice spends 2k/month on groceries");
        assert_eq!(passed[0].tier, Some(PrivacyTier::CloudOk));
    }

    #[tokio::test]
    async fn test_procedural_kind_tier_persists_and_survives_filter_for_mesh() {
        let (_f, mem) = make_db().await;

        // Store a CloudOk procedural belief with a tag in the allowlist
        mem.store_procedural_belief(BeliefDraft {
            owner_id: "owner1".to_string(),
            persona_tag: Some("mercado".to_string()),
            issue: Some("Overspending on groceries".to_string()),
            insight: "Alice spends 2k/month on groceries".to_string(),
            keywords: vec!["budget".to_string()],
            session_id: "sess1".to_string(),
            source: "reflector".to_string(),
            tier: Some(PrivacyTier::CloudOk),
        })
        .await
        .expect("store cloud-ok procedural belief");

        // Store a LocalOnly procedural belief — should be stripped
        mem.store_procedural_belief(BeliefDraft {
            owner_id: "owner1".to_string(),
            persona_tag: Some("mercado".to_string()),
            issue: Some("Sensitive info".to_string()),
            insight: "Alice's bank password".to_string(),
            keywords: vec!["secret".to_string()],
            session_id: "sess2".to_string(),
            source: "reflector".to_string(),
            tier: Some(PrivacyTier::LocalOnly),
        })
        .await
        .expect("store local-only procedural belief");

        // Retrieve from real DB (not hand-built Beliefs)
        let beliefs = mem
            .retrieve_tagged("owner1", Some("mercado"))
            .await
            .expect("retrieve");
        assert_eq!(beliefs.len(), 2, "both beliefs should be retrieved");
        assert!(
            beliefs.iter().all(|b| b.kind == BeliefKind::Procedural),
            "both retrieved beliefs must decode as Procedural"
        );

        // filter_for_mesh with allowlist that includes 'mercado'
        let allowlist = OwnerAllowlist {
            owner_id: "owner1".to_string(),
            allowed_tags: vec!["mercado".to_string()],
        };
        let passed = filter_for_mesh(beliefs, &allowlist);

        // Only CloudOk belief survives
        assert_eq!(
            passed.len(),
            1,
            "only CloudOk procedural belief must survive filter_for_mesh"
        );
        assert_eq!(passed[0].content, "Alice spends 2k/month on groceries");
        assert_eq!(passed[0].tier, Some(PrivacyTier::CloudOk));
        assert_eq!(
            passed[0].kind,
            BeliefKind::Procedural,
            "kind must survive retrieve_tagged -> filter_for_mesh unchanged"
        );
    }
}
