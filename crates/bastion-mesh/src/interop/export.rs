use crate::goal::GoalEngine;
use crate::identity::age_identity::AgeIdentity;
use crate::memory::{Belief, PrivacyTier, SharedMemory};
use crate::persona::{Persona, PersonaRegistry};
use crate::types::AgentConfig;

use super::*;

pub async fn export_full(
    memory: &SharedMemory,
    personas: &PersonaRegistry,
    goals: &GoalEngine,
    config: &AgentConfig,
    identity: Option<&AgeIdentity>,
    owner_id: &str,
) -> anyhow::Result<AgentFile> {
    let mem = memory.read().await;
    let beliefs = mem.retrieve_all_beliefs(owner_id).await?;

    Ok(AgentFile {
        version: AF_VERSION,
        producer: PRODUCER_ID.to_string(),
        mode: "full".into(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        identity: identity.map(|id| IdentityBlock {
            age_secret: id.age_secret_bech32().to_owned(),
            ed25519_secret: id.ed25519_secret_base64(),
        }),
        config: ConfigBlock::from_config(config),
        memories: beliefs.into_iter().map(MemoryEntry::from_belief).collect(),
        personas: personas_to_entries(personas),
        goals: goals
            .list_goals(owner_id)
            .await?
            .into_iter()
            .map(GoalEntry::from_goal)
            .collect(),
        skills: load_skills_list().await,
    })
}

pub async fn export_template(
    personas: &PersonaRegistry,
    config: &AgentConfig,
) -> anyhow::Result<AgentFile> {
    Ok(AgentFile {
        version: AF_VERSION,
        producer: PRODUCER_ID.to_string(),
        mode: "template".into(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        identity: None,
        config: ConfigBlock::from_config(config),
        memories: vec![],
        personas: personas_to_entries(personas),
        goals: vec![],
        skills: load_skills_list().await,
    })
}

fn personas_to_entries(registry: &PersonaRegistry) -> Vec<PersonaEntry> {
    registry
        .names()
        .iter()
        .filter_map(|name| registry.get(name))
        .map(PersonaEntry::from_persona)
        .collect()
}

// ---- Helper impls ----

impl ConfigBlock {
    fn from_config(cfg: &AgentConfig) -> Self {
        Self {
            agent: AgentConfigExport {
                default_model: cfg.default_model.clone(),
                daily_budget_usd: cfg.daily_budget_usd,
            },
        }
    }
}

impl MemoryEntry {
    fn from_belief(b: Belief) -> Self {
        Self {
            persona_tag: b.persona_tag,
            content: b.content,
            tier: match b.tier {
                Some(PrivacyTier::CloudOk) => "cloud-ok".into(),
                Some(PrivacyTier::LocalOnly) | None => "local-only".into(),
            },
            kind: "factual".into(),
            keywords: vec![],
            issue: None,
            weight: b.weight,
            is_core: b.is_core,
        }
    }
}

impl PersonaEntry {
    fn from_persona(p: &Persona) -> Self {
        Self {
            name: p.name.clone(),
            description: p.description.clone(),
            system_prompt: p.system_prompt.clone(),
            tier: match p.tier {
                PrivacyTier::CloudOk => "cloud-ok".into(),
                PrivacyTier::LocalOnly => "local-only".into(),
            },
            weight: p.weight,
            skills: p.skills.clone(),
        }
    }
}

impl GoalEntry {
    fn from_goal(g: crate::goal::Goal) -> Self {
        Self {
            description: g.description,
            metric: g.metric,
            deadline: g.deadline,
            guardian_persona: g.guardian_persona,
        }
    }
}

async fn load_skills_list() -> Vec<SkillEntry> {
    let skills_dir = std::path::Path::new("skills");
    if !skills_dir.is_dir() {
        return vec![];
    }
    let mut entries = vec![];
    let mut rd = match tokio::fs::read_dir(skills_dir).await {
        Ok(rd) => rd,
        Err(_) => return vec![],
    };
    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => continue,
        };
        if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            entries.push(SkillEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path().to_string_lossy().into_owned(),
            });
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

#[allow(dead_code)]
fn make_test_config() -> AgentConfig {
    AgentConfig {
        default_model: "test".into(),
        daily_budget_usd: 0.01,
        fallback_models: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goal::ScoringConfig;
    use crate::identity::age_identity::AgeIdentity;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::Memory;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    /// Returns (tempfile guard, SharedMemory, GoalEngine) sharing same SQLite DB.
    /// The tempfile MUST stay alive — dropping it deletes the underlying DB.
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
    async fn test_export_template_omits_identity_memories_goals() {
        let config = make_test_config();
        let mut personas = HashMap::new();
        personas.insert(
            "test".into(),
            Persona {
                name: "test".into(),
                description: None,
                system_prompt: "prompt".into(),
                tier: PrivacyTier::CloudOk,
                weight: 1.0,
                skills: vec![],
                ..Default::default()
            },
        );
        let registry = PersonaRegistry::new_from_map(personas);
        let af = export_template(&registry, &config).await.unwrap();
        assert_eq!(af.mode, "template");
        assert!(af.identity.is_none());
        assert!(af.memories.is_empty());
        assert!(af.goals.is_empty());
        assert_eq!(af.personas.len(), 1);
        assert_eq!(af.personas[0].name, "test");
        assert_eq!(af.version, AF_VERSION);
    }

    #[tokio::test]
    async fn test_export_full_roundtrip() {
        let (_f, memory, goals) = make_db().await;
        let identity = AgeIdentity::generate();
        let config = make_test_config();
        let registry = PersonaRegistry::new_from_map(HashMap::new());

        let af = export_full(
            &memory,
            &registry,
            &goals,
            &config,
            Some(&identity),
            "owner1",
        )
        .await
        .unwrap();
        assert_eq!(af.mode, "full");
        assert!(af.identity.is_some());
        assert_eq!(af.version, AF_VERSION);
        assert!(af.exported_at.contains('T'));
    }

    #[tokio::test]
    async fn test_export_full_no_identity() {
        let (_f, memory, goals) = make_db().await;
        let config = make_test_config();
        let registry = PersonaRegistry::new_from_map(HashMap::new());

        let af = export_full(&memory, &registry, &goals, &config, None, "owner1")
            .await
            .unwrap();
        assert!(af.identity.is_none());
    }
}
