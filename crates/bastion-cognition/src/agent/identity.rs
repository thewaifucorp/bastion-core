//! M1 — Identidade/voz por onboarding.
//!
//! `IdentityProvider` é um `TurnContextProvider` que:
//! - Se há bloco de identidade na memória (is_core=true, persona_tag="identity"):
//!   retorna o bloco como contexto para o turn (injeção sempre-presente).
//! - Se não há bloco (primeiro uso):
//!   retorna um system prompt de onboarding que convida o agente a se apresentar
//!   e gravar sua identidade via memory_store (disponível como tool via BIG-1).
//!
//! O bloco de identidade NÃO está em bastion.toml — está na camada de memória.
//! Editável por conversa: o agente chama memory_revoke(old_id) + memory_store(new_content).

// M2 step 6: fully-qualified — `crate::agent` in `bastion-cognition` is this
// crate's own dream/procedural/memory_rag/identity module; the kernel's
// context port stays in `bastion_runtime::agent`.
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};

use crate::memory::{PrivacyTier, SharedMemory};

/// System prompt de onboarding para o primeiro uso (sem identidade na memória).
///
/// Convida o agente a definir sua própria identidade/voz e persistir via memory_store.
/// NÃO hardcoda identidade — o agente escreve a sua.
const ONBOARDING_PROMPT: &str = r#"
Você não tem ainda um bloco de identidade definido. Neste turn, apresente-se brevemente ao usuário
e grave sua identidade usando a tool memory_store com os parâmetros:
  is_core: true
  persona_tag: "identity"
  content: "[sua descrição de identidade e voz — ~200-400 palavras]"

Após gravar, continue a conversa normalmente. Em turns futuros, sua identidade será sempre injetada.
"#;

pub struct IdentityProvider {
    memory: SharedMemory,
}

impl IdentityProvider {
    pub fn new(memory: SharedMemory) -> Self {
        Self { memory }
    }
}

#[async_trait::async_trait]
impl TurnContextProvider for IdentityProvider {
    async fn context_for_turn(
        &self,
        owner: &str,
        _turn_msg: &str,
        _persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        let mem = self.memory.read().await;

        match mem.load_core(owner).await {
            Ok(beliefs) => {
                // Filtrar beliefs com persona_tag = "identity"
                let identity_beliefs: Vec<&crate::memory::Belief> = beliefs
                    .iter()
                    .filter(|b| b.persona_tag.as_deref() == Some("identity"))
                    .collect();

                if identity_beliefs.is_empty() {
                    // Primeiro uso — retornar prompt de onboarding.
                    // Tier CloudOk: o onboarding prompt em si não contém dados sensíveis.
                    // Se o resultado do onboarding for LocalOnly, será gravado com tier correto
                    // pela tool memory_store (que recebe o tier explicitamente).
                    vec![ContextBlock {
                        content: ONBOARDING_PROMPT.trim().to_owned(),
                        max_tier: PrivacyTier::CloudOk,
                    }]
                } else {
                    // Turns subsequentes — retornar o bloco de identidade gravado.
                    // Concatenar todos os beliefs de identidade (normalmente 1).
                    let identity_content = identity_beliefs
                        .iter()
                        .map(|b| b.content.as_str())
                        .collect::<Vec<_>>()
                        .join("\n\n");

                    // SECURITY: tier do bloco de identidade é CloudOk por padrão
                    // (identidade escrita pelo próprio agente, não é dado pessoal do usuário).
                    // Se o usuário gravar dados sensíveis na identidade, deve usar LocalOnly
                    // explicitamente — o IdentityProvider não downgrade para LocalOnly aqui.
                    vec![ContextBlock {
                        content: identity_content,
                        max_tier: PrivacyTier::CloudOk,
                    }]
                }
            }
            Err(e) => {
                // Falha ao carregar identidade — não bloquear o turn, logar e retornar vazio.
                // T-05-06-03: DoS mitigation — load_core failure is non-fatal.
                tracing::warn!(
                    event = "identity_load_failed",
                    owner = %owner,
                    error = %e,
                );
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::session::SessionManager;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    async fn make_memory(db_path: &str) -> SharedMemory {
        // Init schema so beliefs table exists before any memory operations.
        let session = SessionManager::new(db_path);
        session.init_schema().await.expect("init_schema");
        Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(db_path)) as Box<dyn crate::memory::Memory>
        ))
    }

    #[tokio::test]
    async fn returns_onboarding_when_no_identity_belief() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let memory = make_memory(&path).await;
        let provider = IdentityProvider::new(memory);

        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].content.contains("memory_store"),
            "onboarding block must mention memory_store; got: {:?}",
            blocks[0].content
        );
        assert_eq!(blocks[0].max_tier, PrivacyTier::CloudOk);
    }

    #[tokio::test]
    async fn returns_identity_block_when_belief_exists() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let memory = make_memory(&path).await;

        // Store an identity belief
        {
            let mem = memory.read().await;
            mem.store_belief(
                "_local",
                Some("identity"),
                "Sou Bastion, assistente pessoal.",
                "sess1",
                "agent",
                true, // is_core=true
                None,
            )
            .await
            .expect("store_belief");
        }

        let provider = IdentityProvider::new(memory);
        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].content.contains("Sou Bastion"),
            "identity block must contain stored content; got: {:?}",
            blocks[0].content
        );
        assert_eq!(blocks[0].max_tier, PrivacyTier::CloudOk);
    }
}
