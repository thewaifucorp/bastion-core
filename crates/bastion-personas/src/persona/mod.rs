// Persona registry — loads persona definitions from personas/<name>/SOUL.md.
// Each Persona is parsed from a SOUL.md file (front-matter + body).
// The registry is built at startup and consulted by the router and runner.

pub mod responder;
pub mod router;
pub mod runner;
pub mod soul;

pub use responder::PersonaResponder;
pub use soul::{parse_soul, BastionBlock, PersonaFront};

use crate::memory::PrivacyTier;
use std::collections::HashMap;

/// `Persona` moved to `bastion_types` (M2 step 6) — pure data, referenced by
/// `bastion-cognition`'s Cabinet without pulling in this crate. Re-exported
/// here so every existing `crate::persona::Persona` path keeps compiling.
pub use bastion_types::Persona;

/// A registry of all loaded personas, keyed by `name`.
/// Built at daemon start via `PersonaRegistry::load_dir`.
#[derive(Debug, Default, Clone)]
pub struct PersonaRegistry {
    personas: HashMap<String, Persona>,
}

impl PersonaRegistry {
    /// Construct directly from a map — used in tests and by the router/runner test fixtures.
    /// Production code should use `load_dir`; this constructor is a test/harness fixture.
    pub fn new_from_map(personas: HashMap<String, Persona>) -> Self {
        PersonaRegistry { personas }
    }

    /// Scan `root/personas/<name>/SOUL.md` and build the registry.
    ///
    /// Missing directories and malformed entries are handled independently:
    /// - If `personas/` does not exist → returns an empty registry (not an error).
    /// - Malformed SOUL.md files are skipped with `tracing::warn!` (PERS-07).
    pub async fn load_dir(root: &str) -> anyhow::Result<Self> {
        let personas_path = std::path::PathBuf::from(root).join("personas");

        let mut registry = PersonaRegistry::default();

        let read_dir = match tokio::fs::read_dir(&personas_path).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = %personas_path.display(), "personas/ directory not found — starting with empty registry");
                return Ok(registry);
            }
            Err(e) => return Err(e.into()),
        };

        let mut rd = read_dir;
        loop {
            let entry = match rd.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "error reading personas directory entry — skipping");
                    continue;
                }
            };

            let persona_dir = entry.path();
            if !persona_dir.is_dir() {
                continue;
            }

            let soul_path = persona_dir.join("SOUL.md");
            let md = match tokio::fs::read_to_string(&soul_path).await {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::warn!(path = %soul_path.display(), "no SOUL.md in persona directory — skipping");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(path = %soul_path.display(), error = %e, "error reading SOUL.md — skipping");
                    continue;
                }
            };

            let (front, body) = match crate::persona::parse_soul(&md) {
                Ok(parsed) => parsed,
                Err(e) => {
                    tracing::warn!(path = %soul_path.display(), error = %e, "malformed SOUL.md — skipping persona");
                    continue;
                }
            };

            let persona = Persona {
                name: front.name.clone(),
                description: front.description,
                system_prompt: body,
                tier: front.bastion.privacy_tier,
                weight: front.bastion.weight,
                skills: front.skills,
            };

            tracing::debug!(name = %persona.name, tier = ?persona.tier, "loaded persona");
            registry.personas.insert(front.name, persona);
        }

        Ok(registry)
    }

    /// Retrieve a persona by name.
    pub fn get(&self, name: &str) -> Option<&Persona> {
        self.personas.get(name)
    }

    /// All persona names in the registry.
    pub fn names(&self) -> Vec<&str> {
        self.personas.keys().map(String::as_str).collect()
    }

    /// Resolve the provider model string for a persona, implementing PRIV-02:
    /// - `LocalOnly` → always use the local (Ollama) model string.
    /// - `CloudOk` → use the cloud model string.
    ///
    /// Returns `None` if the persona is not in the registry.
    /// The egress HOOK (plan 04) is the fail-closed backstop; this method is the
    /// routing-time resolution that feeds the right backend to the runner.
    pub fn provider_model_for(
        &self,
        name: &str,
        default_cloud: &str,
        default_local: &str,
    ) -> Option<String> {
        let persona = self.personas.get(name)?;
        Some(match persona.tier {
            PrivacyTier::LocalOnly => default_local.to_string(),
            PrivacyTier::CloudOk => default_cloud.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> PersonaRegistry {
        let mut personas = HashMap::new();
        personas.insert(
            "Saúde".to_string(),
            Persona {
                name: "Saúde".to_string(),
                description: Some("Health persona".to_string()),
                system_prompt: "You are Saúde.".to_string(),
                tier: PrivacyTier::LocalOnly,
                weight: 0.9,
                skills: vec!["health".to_string()],
            },
        );
        personas.insert(
            "Aria".to_string(),
            Persona {
                name: "Aria".to_string(),
                description: Some("General assistant".to_string()),
                system_prompt: "You are Aria.".to_string(),
                tier: PrivacyTier::CloudOk,
                weight: 0.7,
                skills: vec![],
            },
        );
        PersonaRegistry { personas }
    }

    #[test]
    fn get_returns_known_persona() {
        let r = make_registry();
        assert!(r.get("Saúde").is_some());
        assert!(r.get("unknown").is_none());
    }

    #[test]
    fn names_returns_all() {
        let r = make_registry();
        let mut names = r.names();
        names.sort();
        assert_eq!(names, vec!["Aria", "Saúde"]);
    }

    #[test]
    fn provider_model_local_only_routes_to_ollama() {
        let r = make_registry();
        let model = r.provider_model_for("Saúde", "gpt-4o", "ollama:llama3");
        assert_eq!(model.as_deref(), Some("ollama:llama3"));
    }

    #[test]
    fn provider_model_cloud_ok_routes_to_cloud() {
        let r = make_registry();
        let model = r.provider_model_for("Aria", "gpt-4o", "ollama:llama3");
        assert_eq!(model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn provider_model_unknown_returns_none() {
        let r = make_registry();
        assert!(r
            .provider_model_for("unknown", "gpt-4o", "ollama:llama3")
            .is_none());
    }
}
