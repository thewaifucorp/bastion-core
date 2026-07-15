//! SEAM #2 — `MemoryRagProvider`: recall de beliefs por INJEÇÃO de contexto.
//!
//! A perna "injeção RAG" da decisão pendente do BIG-1 (tool-calling vs injeção
//! vs híbrido). Recupera beliefs relevantes pro turn e injeta como bloco opaco no
//! system prompt — funciona com QUALQUER provider, incluindo terminal-agents
//! (PROV-09) que nunca emitem `tool_calls`, e permanece egress-safe: os blocos
//! saem separados por tier, então `build_system_prompt` derruba só o bloco
//! LocalOnly quando o provider é cloud (Pitfall 5).
//!
//! Relevância é LÉXICA e barata (overlap de termos + weight + recência) — de
//! propósito: recall semântico de verdade é papel do memupalace (embedding
//! local), acessível via tool ou apontando o terminal-agent pro MCP dele.
//! Este provider cobre o caminho que não depende do modelo decidir chamar tool.
//!
//! Opt-in via env `BASTION_MEMORY_RAG=1` (wiring em `AgentLoop::new`) até a
//! decisão do híbrido: default-on duplicaria a exposição de memória em providers
//! com function-calling (que já recebem as tools de memória) e cresce o prompt.

// M2 step 6: fully-qualified — `crate::agent` in `bastion-cognition` is this
// crate's own dream/procedural/memory_rag/identity module; the kernel's
// context port stays in `bastion_runtime::agent`.
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};

use crate::memory::{Belief, PrivacyTier, SharedMemory};

/// Máximo de beliefs injetados por turn (após ranking).
const DEFAULT_MAX_BELIEFS: usize = 8;

/// Termos do turn com menos caracteres que isso não contam pro overlap
/// (artigos/preposições dominariam o score).
const MIN_TERM_LEN: usize = 4;

pub struct MemoryRagProvider {
    memory: SharedMemory,
    max_beliefs: usize,
}

impl MemoryRagProvider {
    pub fn new(memory: SharedMemory) -> Self {
        Self {
            memory,
            max_beliefs: DEFAULT_MAX_BELIEFS,
        }
    }

    #[cfg(test)]
    fn with_max(memory: SharedMemory, max_beliefs: usize) -> Self {
        Self {
            memory,
            max_beliefs,
        }
    }
}

/// Overlap léxico: quantos termos (≥ MIN_TERM_LEN chars, case-insensitive) do
/// turn aparecem no conteúdo do belief. Zero = sem relação detectável.
/// `pub(crate)`: o Reflector reusa a MESMA métrica de relevância pra escolher quais
/// trilhas (beliefs procedurais) reforçar por Δτ (estigmergia), garantindo que o depósito
/// mira as trilhas que este ranking de fato surfacaria.
pub(crate) fn lexical_overlap(turn_msg: &str, content: &str) -> usize {
    let content_lower = content.to_lowercase();
    turn_msg
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= MIN_TERM_LEN)
        .filter(|t| content_lower.contains(&t.to_lowercase()))
        .count()
}

/// Formata um grupo de beliefs como bloco opaco. O id entra no texto de
/// propósito: é o handle de contestação por NL (`/contest <id>`, D-14).
fn render_block(beliefs: &[&Belief]) -> String {
    let mut s = String::from(
        "<memory_recall>\nLong-term memories about this owner (contest with /contest <id> if wrong):\n",
    );
    for b in beliefs {
        s.push_str(&format!("- [id {}] {}\n", b.id, b.content));
    }
    s.push_str("</memory_recall>");
    s
}

#[async_trait::async_trait]
impl TurnContextProvider for MemoryRagProvider {
    async fn context_for_turn(
        &self,
        owner: &str,
        turn_msg: &str,
        persona: Option<&str>,
    ) -> Vec<ContextBlock> {
        let beliefs = {
            let mem = self.memory.read().await;
            // Recall ESCOPADO pela persona ativa: `retrieve_tagged(owner, Some(persona))`
            // traz os beliefs desta persona OU globais (untagged) — nunca os de outra
            // persona (o SQL é `persona_tag = ?2 OR persona_tag IS NULL`). `None` (nenhuma
            // persona casou) mantém o recall global-only, que é o fail-safe correto.
            match mem.retrieve_tagged(owner, persona).await {
                Ok(b) => b,
                Err(e) => {
                    // Recall é enriquecimento, nunca bloqueia o turn (fail-open aqui é
                    // correto: sem memória o agente ainda responde; o erro fica visível).
                    tracing::warn!(event = "memory_rag_retrieve_failed", error = %e);
                    return vec![];
                }
            }
        };

        // Identidade já é injetada pelo IdentityProvider — não duplicar. Com recall
        // persona-scoped, um belief "identity" só chega aqui quando a persona ativa
        // for a própria "identity"; este filtro garante que nunca duplique.
        let mut candidates: Vec<&Belief> = beliefs
            .iter()
            .filter(|b| b.persona_tag.as_deref() != Some("identity"))
            .collect();
        if candidates.is_empty() {
            return vec![];
        }

        // Ranking estigmérgico: relevância MODULADA pelo feromônio (weight). Entre beliefs de
        // relevância léxica parecida, a trilha reforçada (weight maior) é preferida; um belief com
        // overlap zero pontua zero por mais alto que seja o weight (feromônio nunca fabrica
        // relevância). Com weight=1.0 (default, pré-reforço) reduz a overlap puro — retrocompatível.
        // Desempate: id desc (mais recente primeiro).
        candidates.sort_by(|a, b| {
            let score_a = lexical_overlap(turn_msg, &a.content) as f64 * a.weight;
            let score_b = lexical_overlap(turn_msg, &b.content) as f64 * b.weight;
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.id.cmp(&a.id))
        });
        candidates.truncate(self.max_beliefs);

        // Um bloco POR TIER, pra que o egress check derrube só o que precisa:
        // tier None = LocalOnly (deny-on-ambiguity, consistente com CR-03).
        let (cloud_ok, local_only): (Vec<&Belief>, Vec<&Belief>) = candidates
            .into_iter()
            .partition(|b| b.tier == Some(PrivacyTier::CloudOk));

        let mut blocks = Vec::with_capacity(2);
        if !cloud_ok.is_empty() {
            blocks.push(ContextBlock {
                content: render_block(&cloud_ok),
                max_tier: PrivacyTier::CloudOk,
            });
        }
        if !local_only.is_empty() {
            blocks.push(ContextBlock {
                content: render_block(&local_only),
                max_tier: PrivacyTier::LocalOnly,
            });
        }
        blocks
    }
}

// ---------------------------------------------------------------------------
// Tests (offline — temp-DB SqliteMemory, pattern from agent/command.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::Memory;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    async fn make_memory(db_path: &str) -> SharedMemory {
        let session = crate::session::SessionManager::new(db_path);
        session.init_schema().await.expect("init_schema");
        Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(db_path)) as Box<dyn Memory>
        ))
    }

    async fn store(
        mem: &SharedMemory,
        owner: &str,
        content: &str,
        tag: Option<&str>,
        tier: Option<PrivacyTier>,
    ) -> i64 {
        let m = mem.read().await;
        m.store_belief(owner, tag, content, "sess1", "test", false, tier)
            .await
            .expect("store")
    }

    #[tokio::test]
    async fn empty_memory_returns_no_blocks() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let provider = MemoryRagProvider::new(mem);
        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn blocks_are_split_by_tier_and_none_is_local_only() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store(
            &mem,
            "_local",
            "likes coffee",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store(
            &mem,
            "_local",
            "medical condition X",
            None,
            Some(PrivacyTier::LocalOnly),
        )
        .await;
        store(&mem, "_local", "untagged legacy belief", None, None).await;

        let provider = MemoryRagProvider::new(mem);
        let blocks = provider.context_for_turn("_local", "hello", None).await;

        assert_eq!(blocks.len(), 2, "one CloudOk block + one LocalOnly block");
        let cloud = blocks
            .iter()
            .find(|b| b.max_tier == PrivacyTier::CloudOk)
            .expect("cloud block");
        let local = blocks
            .iter()
            .find(|b| b.max_tier == PrivacyTier::LocalOnly)
            .expect("local block");
        assert!(cloud.content.contains("likes coffee"));
        assert!(!cloud.content.contains("medical condition"));
        assert!(local.content.contains("medical condition X"));
        // Deny-on-ambiguity: NULL tier must land in the LocalOnly block, never CloudOk.
        assert!(local.content.contains("untagged legacy belief"));
        assert!(!cloud.content.contains("untagged legacy belief"));
    }

    #[tokio::test]
    async fn cap_is_respected() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        for i in 0..12 {
            store(
                &mem,
                "_local",
                &format!("fact number {i}"),
                None,
                Some(PrivacyTier::CloudOk),
            )
            .await;
        }
        let provider = MemoryRagProvider::with_max(mem, 5);
        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert_eq!(blocks.len(), 1);
        let bullets = blocks[0].content.matches("- [id ").count();
        assert_eq!(bullets, 5, "must inject at most max_beliefs");
    }

    #[tokio::test]
    async fn lexical_relevance_wins_over_recency_at_the_cap() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        // Relevant belief stored FIRST (oldest, lowest id)…
        store(
            &mem,
            "_local",
            "the dog is called Rex",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        // …then bury it under newer irrelevant ones, past the cap.
        for i in 0..6 {
            store(
                &mem,
                "_local",
                &format!("unrelated note {i}"),
                None,
                Some(PrivacyTier::CloudOk),
            )
            .await;
        }
        let provider = MemoryRagProvider::with_max(mem, 3);
        let blocks = provider
            .context_for_turn("_local", "what is my dog called?", None)
            .await;
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].content.contains("Rex"),
            "keyword-matching belief must survive the cap: {}",
            blocks[0].content
        );
    }

    #[tokio::test]
    async fn identity_beliefs_are_excluded() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store(
            &mem,
            "_local",
            "I am Bastion, warm and direct",
            Some("identity"),
            Some(PrivacyTier::CloudOk),
        )
        .await;
        // Passa persona=Some("identity") DE PROPÓSITO: assim o `retrieve_tagged` de fato
        // devolve o belief tagged "identity" e o teste exercita o FILTRO (antes passava
        // vazio só porque o SQL não retornava beliefs tagged — verde pelo motivo errado).
        let provider = MemoryRagProvider::new(mem);
        let blocks = provider
            .context_for_turn("_local", "hello", Some("identity"))
            .await;
        assert!(
            blocks.is_empty(),
            "identity is IdentityProvider's job — the filter must drop it even when recalled"
        );
    }

    #[tokio::test]
    async fn owner_scoping_holds() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store(
            &mem,
            "alice",
            "alice secret",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        let provider = MemoryRagProvider::new(mem);
        let blocks = provider.context_for_turn("bob", "hello", None).await;
        assert!(blocks.is_empty(), "bob must never see alice's beliefs");
    }

    #[tokio::test]
    async fn recall_is_scoped_to_active_persona_plus_global() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        // A belief for persona "work", one for persona "home", and one global (untagged).
        store(
            &mem,
            "_local",
            "the office wifi password is hunter2",
            Some("work"),
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store(
            &mem,
            "_local",
            "the kids go to bed at 8pm",
            Some("home"),
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store(
            &mem,
            "_local",
            "the owner prefers concise answers",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;

        let provider = MemoryRagProvider::new(mem);
        let blocks = provider
            .context_for_turn("_local", "hello", Some("work"))
            .await;

        assert_eq!(blocks.len(), 1);
        let content = &blocks[0].content;
        // This persona's belief + the global one are recalled…
        assert!(
            content.contains("office wifi"),
            "work belief must be recalled"
        );
        assert!(
            content.contains("concise answers"),
            "global (untagged) belief must always be recalled"
        );
        // …but the OTHER persona's belief must never leak across the boundary.
        assert!(
            !content.contains("kids go to bed"),
            "home-persona belief must not leak into a work-persona turn"
        );
    }
}
