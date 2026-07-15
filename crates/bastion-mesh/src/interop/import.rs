use super::*;
use crate::goal::GoalEngine;
use crate::identity::age_identity::AgeIdentity;
use crate::memory::{PrivacyTier, SharedMemory};
use crate::persona::PersonaRegistry;

pub async fn import(
    af: AgentFile,
    memory: &SharedMemory,
    _personas: &PersonaRegistry,
    goals: &GoalEngine,
    owner_id: &str,
) -> anyhow::Result<Option<AgeIdentity>> {
    check_version(af.version)?;

    let identity = if let Some(id_block) = af.identity {
        tracing::info!(event = "import_identity", "restoring identity from .af");
        Some(AgeIdentity::from_bech32(&id_block.age_secret)?)
    } else {
        tracing::info!(event = "import_no_identity", "no identity in .af");
        None
    };

    if !af.memories.is_empty() {
        let mem = memory.write().await;
        for entry in &af.memories {
            let tier = match entry.tier.as_str() {
                "cloud-ok" => Some(PrivacyTier::CloudOk),
                "local-only" => Some(PrivacyTier::LocalOnly),
                _ => None,
            };
            mem.store_belief(
                owner_id,
                entry.persona_tag.as_deref(),
                &entry.content,
                "import",
                "af_import",
                entry.is_core,
                tier,
            )
            .await?;
        }
    }

    if !af.goals.is_empty() {
        for entry in &af.goals {
            goals
                .create_goal(
                    owner_id,
                    &entry.description,
                    entry.metric.as_deref(),
                    entry.deadline,
                    entry.guardian_persona.as_deref(),
                )
                .await?;
        }
    }

    if !af.personas.is_empty() {
        tracing::warn!(
            event = "import_personas_skipped",
            count = af.personas.len(),
            "personas must be manually copied to personas/ directory"
        );
    }
    if !af.skills.is_empty() {
        tracing::warn!(
            event = "import_skills_skipped",
            count = af.skills.len(),
            "skills must be manually installed"
        );
    }

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goal::ScoringConfig;
    use crate::identity::age_identity::AgeIdentity;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::Memory;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

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

    #[tokio::test]
    async fn test_import_rejects_unknown_version() {
        let af = AgentFile {
            version: 99,
            producer: "test".into(),
            mode: "full".into(),
            exported_at: "".into(),
            identity: None,
            config: ConfigBlock {
                agent: AgentConfigExport {
                    default_model: "".into(),
                    daily_budget_usd: 0.0,
                },
            },
            memories: vec![],
            personas: vec![],
            goals: vec![],
            skills: vec![],
        };
        let (_f, memory, goals) = make_db().await;
        let registry = PersonaRegistry::new_from_map(std::collections::HashMap::new());

        let result = import(af, &memory, &registry, &goals, "owner1").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported .af version 99"));
    }

    #[tokio::test]
    async fn test_import_without_identity_returns_none() {
        let af = AgentFile {
            version: AF_VERSION,
            producer: "test".into(),
            mode: "template".into(),
            exported_at: "".into(),
            identity: None,
            config: ConfigBlock {
                agent: AgentConfigExport {
                    default_model: "".into(),
                    daily_budget_usd: 0.0,
                },
            },
            memories: vec![],
            personas: vec![],
            goals: vec![],
            skills: vec![],
        };
        let (_f, memory, goals) = make_db().await;
        let registry = PersonaRegistry::new_from_map(std::collections::HashMap::new());

        let result = import(af, &memory, &registry, &goals, "owner1").await;
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_import_with_identity_returns_identity() {
        let identity = AgeIdentity::generate();
        let age_secret = identity.age_secret_bech32().to_owned();
        let af = AgentFile {
            version: AF_VERSION,
            producer: "test".into(),
            mode: "full".into(),
            exported_at: "".into(),
            identity: Some(IdentityBlock {
                age_secret: age_secret.clone(),
                ed25519_secret: identity.ed25519_secret_base64(),
            }),
            config: ConfigBlock {
                agent: AgentConfigExport {
                    default_model: "".into(),
                    daily_budget_usd: 0.0,
                },
            },
            memories: vec![],
            personas: vec![],
            goals: vec![],
            skills: vec![],
        };
        let (_f, memory, goals) = make_db().await;
        let registry = PersonaRegistry::new_from_map(std::collections::HashMap::new());

        let restored = import(af, &memory, &registry, &goals, "owner1")
            .await
            .unwrap()
            .expect("should return identity");
        assert_eq!(restored.age_secret_bech32(), age_secret);
    }

    #[tokio::test]
    async fn test_import_writes_memories() {
        let af = AgentFile {
            version: AF_VERSION,
            producer: "test".into(),
            mode: "full".into(),
            exported_at: "".into(),
            identity: None,
            config: ConfigBlock {
                agent: AgentConfigExport {
                    default_model: "".into(),
                    daily_budget_usd: 0.0,
                },
            },
            memories: vec![MemoryEntry {
                persona_tag: None,
                content: "imported belief".into(),
                tier: "cloud-ok".into(),
                kind: "factual".into(),
                keywords: vec![],
                issue: None,
                weight: 1.0,
                is_core: false,
            }],
            personas: vec![],
            goals: vec![],
            skills: vec![],
        };
        let (_f, memory, goals) = make_db().await;
        let registry = PersonaRegistry::new_from_map(std::collections::HashMap::new());

        import(af, &memory, &registry, &goals, "owner1")
            .await
            .unwrap();

        let mem = memory.read().await;
        let beliefs = mem.retrieve_all_beliefs("owner1").await.unwrap();
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].content, "imported belief");
    }
}
