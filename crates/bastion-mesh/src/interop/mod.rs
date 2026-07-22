pub mod export;
pub mod import;

use serde::{Deserialize, Serialize};

pub const AF_VERSION: u32 = 1;

/// Producer identifier written into `.af` interchange files. `version`
/// identifies the schema while this value distinguishes the producing host.
/// A missing producer field resolves to this value.
pub const PRODUCER_ID: &str = "bastion";

fn default_producer() -> String {
    PRODUCER_ID.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFile {
    pub version: u32,
    /// Which product produced this file (Loop 3-D). Absent on any `.af`
    /// exported before this loop — `#[serde(default)]` reads those as
    /// [`PRODUCER_ID`] rather than failing to parse.
    #[serde(default = "default_producer")]
    pub producer: String,
    pub mode: String,
    pub exported_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityBlock>,
    pub config: ConfigBlock,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memories: Vec<MemoryEntry>,
    pub personas: Vec<PersonaEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub goals: Vec<GoalEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<SkillEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBlock {
    pub age_secret: String,
    pub ed25519_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBlock {
    pub agent: AgentConfigExport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigExport {
    pub default_model: String,
    pub daily_budget_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub persona_tag: Option<String>,
    pub content: String,
    pub tier: String,
    pub kind: String,
    pub keywords: Vec<String>,
    pub issue: Option<String>,
    pub weight: f64,
    pub is_core: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaEntry {
    pub name: String,
    pub description: Option<String>,
    pub system_prompt: String,
    pub tier: String,
    pub weight: f32,
    pub skills: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalEntry {
    pub description: String,
    pub metric: Option<String>,
    pub deadline: Option<i64>,
    pub guardian_persona: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillEntry {
    pub name: String,
    pub path: String,
}

pub(crate) fn check_version(v: u32) -> anyhow::Result<()> {
    if v != AF_VERSION {
        anyhow::bail!(
            "Unsupported .af version {}. This Bastion supports version {}.",
            v,
            AF_VERSION
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goal::{GoalEngine, ScoringConfig};
    use crate::identity::age_identity::AgeIdentity;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::{Memory, SharedMemory};
    use crate::persona::{Persona, PersonaRegistry};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    #[test]
    fn test_check_version_accepts_current() {
        assert!(check_version(AF_VERSION).is_ok());
    }

    #[test]
    fn test_check_version_rejects_unknown() {
        let err = check_version(99).unwrap_err();
        assert!(err.to_string().contains("Unsupported .af version 99"));
    }

    #[test]
    fn test_memory_entry_roundtrip() {
        let entry = MemoryEntry {
            persona_tag: Some("test".into()),
            content: "some belief".into(),
            tier: "cloud-ok".into(),
            kind: "factual".into(),
            keywords: vec!["key".into()],
            issue: None,
            weight: 1.0,
            is_core: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: MemoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.content, "some belief");
    }

    /// Full export → serialize → deserialize → import roundtrip.
    /// Verifies identity, memories, goals, and personas survive the cycle.
    #[tokio::test]
    async fn test_full_export_import_roundtrip() {
        // --- Setup source DB ---
        let src = NamedTempFile::new().unwrap();
        let src_path = src.path().to_str().unwrap().to_owned();
        let sm = crate::session::sqlite::SessionManager::new(&src_path);
        sm.init_schema().await.unwrap();
        let src_mem: SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&src_path)) as Box<dyn Memory>
        ));
        let src_goals = GoalEngine::new(&src_path, ScoringConfig::default());

        // Store a belief
        {
            let m = src_mem.read().await;
            m.store_belief(
                "owner1",
                Some("health"),
                "exercises daily",
                "sess1",
                "user",
                false,
                None,
            )
            .await
            .unwrap();
            m.store_belief(
                "owner1",
                Some("identity"),
                "Bastion assistant",
                "sess1",
                "agent",
                true,
                None,
            )
            .await
            .unwrap();
        }

        // Create a goal
        src_goals
            .create_goal("owner1", "be healthy", None, None::<i64>, None)
            .await
            .unwrap();

        // Create personas
        let mut p_map = HashMap::new();
        p_map.insert(
            "helper".into(),
            Persona {
                name: "helper".into(),
                description: Some("helper persona".into()),
                system_prompt: "you help".into(),
                tier: crate::memory::PrivacyTier::CloudOk,
                weight: 1.0,
                skills: vec![],
                ..Default::default()
            },
        );
        let registry = PersonaRegistry::new_from_map(p_map);
        let identity = AgeIdentity::generate();
        let config = crate::types::AgentConfig {
            default_model: "test".into(),
            daily_budget_usd: 0.01,
            fallback_models: vec![],
        };

        // --- Export ---
        let af = crate::interop::export::export_full(
            &src_mem,
            &registry,
            &src_goals,
            &config,
            Some(&identity),
            "owner1",
        )
        .await
        .unwrap();

        assert_eq!(af.mode, "full");
        assert!(af.identity.is_some());
        assert_eq!(af.memories.len(), 2);
        assert_eq!(af.goals.len(), 1);
        assert_eq!(af.personas.len(), 1);

        // --- Serialize roundtrip ---
        let json = serde_json::to_string_pretty(&af).unwrap();
        let af2: AgentFile = serde_json::from_str(&json).unwrap();

        // --- Setup dest DB ---
        let dst = NamedTempFile::new().unwrap();
        let dst_path = dst.path().to_str().unwrap().to_owned();
        let sm2 = crate::session::sqlite::SessionManager::new(&dst_path);
        sm2.init_schema().await.unwrap();
        let dst_mem: SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&dst_path)) as Box<dyn Memory>
        ));
        let dst_goals = GoalEngine::new(&dst_path, ScoringConfig::default());
        let dst_registry = PersonaRegistry::new_from_map(HashMap::new());

        // --- Import ---
        let restored_identity =
            crate::interop::import::import(af2, &dst_mem, &dst_registry, &dst_goals, "owner1")
                .await
                .unwrap()
                .expect("should return identity");

        // --- Verify ---
        assert_eq!(
            restored_identity.age_secret_bech32(),
            identity.age_secret_bech32()
        );
        assert_eq!(
            restored_identity.ed25519_secret_base64(),
            identity.ed25519_secret_base64()
        );

        let m = dst_mem.read().await;
        let beliefs = m.retrieve_all_beliefs("owner1").await.unwrap();
        assert_eq!(beliefs.len(), 2, "both beliefs should be restored");

        let goals = dst_goals.list_goals("owner1").await.unwrap();
        assert_eq!(goals.len(), 1);
        assert_eq!(goals[0].description, "be healthy");
    }

    // ─── Loop 3-D (docs/ARCHITECTURE.md), security point 1 ──

    /// Local to this module's tests — `export.rs`/`import.rs` each have
    /// their own identically-shaped private `make_db` for their own tests;
    /// Rust privacy does not let this module reach either.
    async fn make_db() -> (NamedTempFile, SharedMemory, GoalEngine) {
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path().to_str().unwrap().to_owned();
        let session_mgr = crate::session::sqlite::SessionManager::new(&path);
        session_mgr.init_schema().await.expect("init_schema");
        let mem: SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&path)) as Box<dyn Memory>
        ));
        let goals = GoalEngine::new(&path, ScoringConfig::default());
        (f, mem, goals)
    }

    /// A `.af` exported before this loop has no `producer` field at all —
    /// `#[serde(default)]` must read it back as [`PRODUCER_ID`], never fail
    /// to parse.
    #[test]
    fn test_producer_defaults_when_missing_from_legacy_json() {
        let legacy_json = serde_json::json!({
            "version": AF_VERSION,
            "mode": "template",
            "exported_at": "2026-01-01T00:00:00Z",
            "config": {"agent": {"default_model": "x", "daily_budget_usd": 1.0}},
            "personas": [],
        });
        let af: AgentFile = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(af.producer, PRODUCER_ID);
    }

    #[tokio::test]
    async fn test_export_full_sets_producer_id() {
        let config = crate::types::AgentConfig {
            default_model: "test".into(),
            daily_budget_usd: 0.01,
            fallback_models: vec![],
        };
        let registry = PersonaRegistry::new_from_map(HashMap::new());
        // Cheapest path to an AgentFile here is export_template — producer
        // is set identically by both constructors (same literal, see
        // export.rs), and this test only cares about that one field.
        let af = export::export_template(&registry, &config)
            .await
            .expect("export_template");
        assert_eq!(af.producer, PRODUCER_ID);
    }

    /// The "grep de secret = vazio" test from the design doc §Ponto 1,
    /// applied to the ORDINARY export path (no `--with-identity`): the
    /// serialized `.af` must contain no secret-shaped material at all. This
    /// is the path essentially every export takes.
    #[tokio::test]
    async fn test_export_full_without_identity_leaks_no_secret_material() {
        let (_f, memory, goals) = make_db().await;
        let config = crate::types::AgentConfig {
            default_model: "test".into(),
            daily_budget_usd: 0.01,
            fallback_models: vec![],
        };
        let registry = PersonaRegistry::new_from_map(HashMap::new());

        let af = export::export_full(&memory, &registry, &goals, &config, None, "owner1")
            .await
            .unwrap();
        let json = serde_json::to_string(&af).unwrap();

        assert!(af.identity.is_none());
        // No age/ed25519 identity markers, no provider-API-key-shaped
        // strings — this export path never touches `SecretRef`/
        // `SecretValue` at all (config.rs's `AgentConfigExport` only ever
        // carries `default_model`/`daily_budget_usd`).
        assert!(!json.contains("age_secret"));
        assert!(!json.contains("ed25519_secret"));
        assert!(!json.contains("AGE-SECRET-KEY"));
    }

    /// DOCUMENTED, DELIBERATE EXCEPTION (reported per the Loop 3-D operator
    /// instructions rather than silently changed): `--with-identity` embeds
    /// the raw age/Ed25519 PRIVATE KEY bytes in plaintext by design — that
    /// keypair IS the portable mesh identity `--with-identity` exists to
    /// carry to another machine; there is no "reference" to a private key
    /// that would resolve to the SAME key elsewhere, unlike a provider API
    /// key or a bearer token. This is not a `SecretRef`-eligible secret, and
    /// this loop does not change `IdentityBlock`'s shape (main.rs already
    /// hardens the ONLY producer of this file: opt-in flag, chmod 0600
    /// immediately after write, WR-04). This test pins the exception
    /// explicitly so it can never be mistaken for an accidental leak.
    #[tokio::test]
    async fn test_export_full_with_identity_deliberately_embeds_the_keypair() {
        let (_f, memory, goals) = make_db().await;
        let identity = AgeIdentity::generate();
        let config = crate::types::AgentConfig {
            default_model: "test".into(),
            daily_budget_usd: 0.01,
            fallback_models: vec![],
        };
        let registry = PersonaRegistry::new_from_map(HashMap::new());

        let af = export::export_full(
            &memory,
            &registry,
            &goals,
            &config,
            Some(&identity),
            "owner1",
        )
        .await
        .unwrap();
        let json = serde_json::to_string(&af).unwrap();

        assert!(json.contains(identity.age_secret_bech32()));
    }
}
