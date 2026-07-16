//! LEARN-03 — `ProceduralBeliefProvider`: recall de beliefs PROCEDURAIS por injeção
//! de contexto (SEAM #2), mirroring `MemoryRagProvider` (SEAM #2 / BIG-1 "RAG" leg).
//!
//! Mesma mecânica já testada de `MemoryRagProvider`: recall léxico barato, blocos
//! separados por tier (deny-on-ambiguity para tier `None`), egress-safe por
//! construção (`build_system_prompt` derruba só o bloco LocalOnly quando o provider
//! é cloud). A ÚNICA diferença de substância é o predicado de filtro: aqui é
//! INCLUSÃO por `kind == Procedural` (não exclusão por `persona_tag == "identity"`),
//! porque procedural e factual são canais de recall paralelos e não devem duplicar.
//!
//! Always-on (não gated por env, ao contrário de `BASTION_MEMORY_RAG`): beliefs
//! procedurais são um entregável de primeira classe da Fase 7 (LEARN-03), não uma
//! perna experimental do RAG híbrido ainda pendente de decisão (BIG-1).

// M2 step 6: fully-qualified — `crate::agent` in `bastion-cognition` is this
// crate's own dream/procedural/memory_rag/identity module; the kernel's
// context port stays in `bastion_runtime::agent`.
use bastion_runtime::agent::context::{ContextBlock, TurnContextProvider};

use crate::memory::{Belief, BeliefKind, PrivacyTier, SharedMemory};

/// Máximo de beliefs procedurais injetados por turn (após ranking). Constante
/// separada de `memory_rag::DEFAULT_MAX_BELIEFS` de propósito — os dois canais de
/// recall devem ser tunáveis independentemente.
const DEFAULT_MAX_BELIEFS: usize = 8;

/// Termos do turn com menos caracteres que isso não contam pro overlap
/// (artigos/preposições dominariam o score).
const MIN_TERM_LEN: usize = 4;

pub struct ProceduralBeliefProvider {
    memory: SharedMemory,
    max_beliefs: usize,
}

impl ProceduralBeliefProvider {
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
///
/// Duplicado de `memory_rag::lexical_overlap` de propósito — o idioma do
/// codebase prefere helper local por provider a um utils compartilhado aqui.
fn lexical_overlap(turn_msg: &str, content: &str) -> usize {
    let content_lower = content.to_lowercase();
    turn_msg
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= MIN_TERM_LEN)
        .filter(|t| content_lower.contains(&t.to_lowercase()))
        .count()
}

/// Formata um grupo de beliefs procedurais como bloco opaco. O id entra no texto
/// de propósito: é o handle de contestação por NL (`/contest <id>`, D-14). O
/// core NUNCA interpreta este conteúdo como instrução (SEAM #2 boundary rule) —
/// é sempre dado opaco dentro das tags de guidance procedural.
fn render_block(beliefs: &[&Belief]) -> String {
    let mut s = String::from(
        "<procedural_guidance>\nLearned strategies for this owner (contest with /contest <id>):\n",
    );
    for b in beliefs {
        s.push_str(&format!("- [id {}] {}\n", b.id, b.content));
    }
    s.push_str("</procedural_guidance>");
    s
}

#[async_trait::async_trait]
impl TurnContextProvider for ProceduralBeliefProvider {
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
            // persona (o SQL é `persona_tag = ?2 OR persona_tag IS NULL`).
            match mem.retrieve_tagged(owner, persona).await {
                Ok(b) => b,
                Err(e) => {
                    // Recall é enriquecimento, nunca bloqueia o turn (fail-open aqui é
                    // correto: sem memória o agente ainda responde; o erro fica visível).
                    tracing::warn!(event = "procedural_belief_retrieve_failed", error = %e);
                    return vec![];
                }
            }
        };

        // Só beliefs PROCEDURAIS — o canal factual já é coberto por MemoryRagProvider
        // e não deve ser duplicado aqui (inclusão, não exclusão, ao contrário do
        // filtro "identity" de memory_rag.rs).
        let mut candidates: Vec<&Belief> = beliefs
            .iter()
            .filter(|b| b.kind == BeliefKind::Procedural)
            .collect();
        if candidates.is_empty() {
            return vec![];
        }

        // Rank: overlap léxico desc → weight desc → id desc (mais recente primeiro).
        candidates.sort_by(|a, b| {
            let score_a = lexical_overlap(turn_msg, &a.content);
            let score_b = lexical_overlap(turn_msg, &b.content);
            score_b
                .cmp(&score_a)
                .then(
                    b.weight
                        .partial_cmp(&a.weight)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
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
// Tests (offline — temp-DB SqliteMemory, mirrors memory_rag.rs's test suite)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::{BeliefDraft, Memory};
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

    /// Stores a `kind='procedural'` belief via `store_procedural_belief` — the only
    /// path that sets `kind` to `Procedural` (`store_belief` always defaults to
    /// `Factual`, exercised separately by `factual_beliefs_are_excluded`).
    async fn store_procedural(
        mem: &SharedMemory,
        owner: &str,
        content: &str,
        tag: Option<&str>,
        tier: Option<PrivacyTier>,
    ) -> i64 {
        let m = mem.read().await;
        m.store_procedural_belief(BeliefDraft {
            owner_id: owner.to_string(),
            persona_tag: tag.map(|t| t.to_string()),
            issue: None,
            insight: content.to_string(),
            keywords: vec![],
            session_id: "sess1".to_string(),
            source: "test".to_string(),
            tier,
        })
        .await
        .expect("store_procedural_belief")
    }

    /// Stores a `kind='factual'` (default) belief via `store_belief` — used to prove
    /// the procedural filter excludes it.
    async fn store_factual(
        mem: &SharedMemory,
        owner: &str,
        content: &str,
        tag: Option<&str>,
        tier: Option<PrivacyTier>,
    ) -> i64 {
        let m = mem.read().await;
        m.store_belief(owner, tag, content, "sess1", "test", false, tier)
            .await
            .expect("store_belief")
    }

    #[tokio::test]
    async fn empty_memory_returns_no_blocks() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        let provider = ProceduralBeliefProvider::new(mem);
        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn blocks_are_split_by_tier_and_none_is_local_only() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store_procedural(
            &mem,
            "_local",
            "always rebase onto origin/main before pushing",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store_procedural(
            &mem,
            "_local",
            "internal deploy key rotation procedure",
            None,
            Some(PrivacyTier::LocalOnly),
        )
        .await;
        store_procedural(&mem, "_local", "untagged procedural belief", None, None).await;

        let provider = ProceduralBeliefProvider::new(mem);
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
        assert!(cloud.content.contains("always rebase"));
        assert!(!cloud.content.contains("deploy key rotation"));
        assert!(local.content.contains("deploy key rotation"));
        // Deny-on-ambiguity: NULL tier must land in the LocalOnly block, never CloudOk.
        assert!(local.content.contains("untagged procedural belief"));
        assert!(!cloud.content.contains("untagged procedural belief"));
    }

    #[tokio::test]
    async fn cap_is_respected() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        for i in 0..12 {
            store_procedural(
                &mem,
                "_local",
                &format!("procedural strategy number {i}"),
                None,
                Some(PrivacyTier::CloudOk),
            )
            .await;
        }
        let provider = ProceduralBeliefProvider::with_max(mem, 5);
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
        store_procedural(
            &mem,
            "_local",
            "always squash commits before merging",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        // …then bury it under newer irrelevant ones, past the cap.
        for i in 0..6 {
            store_procedural(
                &mem,
                "_local",
                &format!("unrelated strategy {i}"),
                None,
                Some(PrivacyTier::CloudOk),
            )
            .await;
        }
        let provider = ProceduralBeliefProvider::with_max(mem, 3);
        let blocks = provider
            .context_for_turn("_local", "should I squash commits before merging?", None)
            .await;
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].content.contains("squash commits"),
            "keyword-matching belief must survive the cap: {}",
            blocks[0].content
        );
    }

    #[tokio::test]
    async fn factual_beliefs_are_excluded() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store_factual(
            &mem,
            "_local",
            "the owner's favorite color is blue",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        let provider = ProceduralBeliefProvider::new(mem);
        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert!(
            blocks.is_empty(),
            "factual beliefs are MemoryRagProvider's job — the kind filter must drop them"
        );
    }

    #[tokio::test]
    async fn owner_scoping_holds() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store_procedural(
            &mem,
            "alice",
            "alice's private deploy procedure",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        let provider = ProceduralBeliefProvider::new(mem);
        let blocks = provider.context_for_turn("bob", "hello", None).await;
        assert!(blocks.is_empty(), "bob must never see alice's beliefs");
    }

    #[tokio::test]
    async fn recall_is_scoped_to_active_persona_plus_global() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        // A procedural belief for persona "work", one for persona "home", and one
        // global (untagged).
        store_procedural(
            &mem,
            "_local",
            "always run cargo fmt before committing",
            Some("work"),
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store_procedural(
            &mem,
            "_local",
            "put the kids' bikes away before dinner",
            Some("home"),
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store_procedural(
            &mem,
            "_local",
            "the owner prefers concise answers",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;

        let provider = ProceduralBeliefProvider::new(mem);
        let blocks = provider
            .context_for_turn("_local", "hello", Some("work"))
            .await;

        assert_eq!(blocks.len(), 1);
        let content = &blocks[0].content;
        // This persona's belief + the global one are recalled…
        assert!(
            content.contains("cargo fmt"),
            "work belief must be recalled"
        );
        assert!(
            content.contains("concise answers"),
            "global (untagged) belief must always be recalled"
        );
        // …but the OTHER persona's belief must never leak across the boundary.
        assert!(
            !content.contains("kids' bikes"),
            "home-persona belief must not leak into a work-persona turn"
        );
    }

    /// LEARN-03's concrete end-to-end proof: a `LocalOnly` procedural belief's
    /// `ContextBlock` is dropped by `check_egress` when the active provider is a
    /// cloud provider, while a co-existing `CloudOk` procedural belief's content
    /// still makes it through — the same mechanism `build_system_prompt` (SEAM #2)
    /// already applies per-block, unchanged by this plan.
    #[tokio::test]
    async fn a_local_only_procedural_belief_never_reaches_cloud_prompt() {
        let f = NamedTempFile::new().unwrap();
        let mem = make_memory(f.path().to_str().unwrap()).await;
        store_procedural(
            &mem,
            "_local",
            "safe cloud-shareable git workflow tip",
            None,
            Some(PrivacyTier::CloudOk),
        )
        .await;
        store_procedural(
            &mem,
            "_local",
            "internal-only production credential rotation steps",
            None,
            Some(PrivacyTier::LocalOnly),
        )
        .await;

        let provider = ProceduralBeliefProvider::new(mem);
        let blocks = provider.context_for_turn("_local", "hello", None).await;
        assert_eq!(blocks.len(), 2, "one CloudOk block + one LocalOnly block");

        // Simulate build_system_prompt's per-block egress check for a cloud provider.
        let cloud_provider_name = "openrouter";
        let mut prompt_parts: Vec<String> = vec![];
        for block in &blocks {
            if crate::hooks::egress::check_egress(Some(block.max_tier), cloud_provider_name).is_ok()
            {
                prompt_parts.push(block.content.clone());
            }
        }
        let system_prompt = prompt_parts.join("\n\n");

        assert!(
            system_prompt.contains("safe cloud-shareable git workflow tip"),
            "CloudOk procedural belief must reach the cloud-provider system prompt"
        );
        assert!(
            !system_prompt.contains("internal-only production credential rotation steps"),
            "LocalOnly procedural belief must NEVER reach a cloud-provider system prompt"
        );
    }
}
