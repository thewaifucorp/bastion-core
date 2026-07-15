use crate::memory::{Belief, SharedMemory};
use crate::types::Message;

/// A1 `PreCompactionFlush` implementation (M2 step 3b): the MEM-09 flush the
/// loop used to invoke directly as `dream::memory_flush(&history, &self.memory,
/// owner)`. Closes over the `SharedMemory` at construction — the kernel port
/// carries only `(history, owner)`.
pub struct DreamFlush {
    memory: SharedMemory,
}

impl DreamFlush {
    /// Wrap the shared memory backend the flush distills beliefs into.
    pub fn new(memory: SharedMemory) -> Self {
        Self { memory }
    }
}

// M2 step 6: fully-qualified (not `crate::agent::ports`) — once this file
// lives in `bastion-cognition`, `crate::agent` is this crate's OWN dream/
// procedural/memory_rag/identity module, not the kernel's ports/context
// (those stay in `bastion_runtime::agent`).
#[async_trait::async_trait]
impl bastion_runtime::agent::ports::PreCompactionFlush for DreamFlush {
    async fn flush(&self, history: &[Message], owner: &str) -> anyhow::Result<()> {
        // `memory_flush` logs and swallows its own errors (flush failure must
        // not abort the turn) — identical contract to the old direct call.
        memory_flush(history, &self.memory, owner).await;
        Ok(())
    }
}

/// Consolidation decisions produced by `Dream::consolidate()` (MEM-02). Pure data —
/// the caller (`proactive::idle_tick`) applies each decision via
/// `Memory::supersede_belief` / `Memory::revoke_belief`. Never carries side effects
/// itself, mirroring `extract_facts`'s "decide, don't act" shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsolidationPlan {
    /// `(old_id, new_id)` pairs — the OLDER belief (lower id, since ids are
    /// monotonically increasing per `store_belief`'s `AUTOINCREMENT`) is superseded
    /// BY the newer one.
    pub supersessions: Vec<(i64, i64)>,
    /// Ids of beliefs whose `weight` has decayed below the prune floor — soft-revoke
    /// candidates (never a hard delete; the caller uses `revoke_belief`, D-15).
    pub prune_ids: Vec<i64>,
}

/// Dream extracts durable facts from idle session history and consolidates the
/// active belief set (MEM-02).
#[async_trait::async_trait]
pub trait Dream: Send + Sync {
    async fn extract_facts(&self, messages: &[Message]) -> anyhow::Result<Vec<String>>;

    /// MEM-02: pure, offline, zero-LLM/zero-network consolidation decision-maker.
    /// Takes only `&[Belief]` — no `CapabilityRegistry`/`InvokeCtx` in scope, same
    /// zero-cost contract as `extract_facts` and `memory_flush`'s "always offline"
    /// doc comment. Groups beliefs by `(owner_id, persona_tag)` and flags
    /// near-duplicate pairs for supersession plus low-weight beliefs for pruning.
    /// Makes NO DB/network calls itself — the caller (`proactive::idle_tick`)
    /// applies the plan via `Memory::supersede_belief`/`Memory::revoke_belief`.
    async fn consolidate(&self, beliefs: &[Belief]) -> anyhow::Result<ConsolidationPlan>;
}

/// No-op implementation — returns no facts, no consolidation decisions.
pub struct NoDream;

#[async_trait::async_trait]
impl Dream for NoDream {
    async fn extract_facts(&self, _messages: &[Message]) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }

    async fn consolidate(&self, _beliefs: &[Belief]) -> anyhow::Result<ConsolidationPlan> {
        Ok(ConsolidationPlan::default())
    }
}

/// Heuristic dream implementation: extracts facts by finding user messages that
/// assert statements about the owner (simple keyword-based heuristic, offline, zero LLM).
///
/// This is the Phase-2 "scripted" implementation. A real LLM-backed variant can be
/// swapped in by implementing the Dream trait with an LLM call.
pub(crate) struct HeuristicDream;

#[async_trait::async_trait]
impl Dream for HeuristicDream {
    async fn extract_facts(&self, messages: &[Message]) -> anyhow::Result<Vec<String>> {
        use crate::types::{MessageContent, Role};

        let mut facts = Vec::new();
        for msg in messages {
            if msg.role != Role::User {
                continue;
            }
            // Extract text content
            let text = match &msg.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::Parts(parts) => parts
                    .iter()
                    .filter_map(|p| {
                        if let crate::types::ContentPart::Text { text } = p {
                            Some(text.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            };

            // Simple heuristic: user messages that look like factual self-disclosures.
            // Triggers on "I am", "I have", "I like", "I work", "I live", "meu", "eu sou", "eu tenho".
            let lower = text.to_lowercase();
            let triggers = [
                "i am ",
                "i have ",
                "i like ",
                "i work ",
                "i live ",
                "eu sou ",
                "eu tenho ",
                "eu gosto ",
                "eu trabalho ",
                "eu moro ",
                "meu ",
                "minha ",
                "my ",
            ];
            if triggers.iter().any(|t| lower.contains(t)) && text.len() > 10 {
                facts.push(text.trim().to_string());
            }
        }
        Ok(facts)
    }

    async fn consolidate(&self, beliefs: &[Belief]) -> anyhow::Result<ConsolidationPlan> {
        use std::collections::{HashMap, HashSet};

        let mut plan = ConsolidationPlan::default();

        // Prune pass: independent of grouping — any belief whose weight has decayed
        // below the floor is flagged regardless of owner/persona_tag.
        for b in beliefs {
            if b.weight < PRUNE_WEIGHT_FLOOR {
                plan.prune_ids.push(b.id);
            }
        }

        // Group by (owner_id, persona_tag) — consolidation never crosses an owner or
        // persona_tag boundary, mirroring the Reflector's own procedural-trail scoping.
        let mut groups: HashMap<(&str, Option<&str>), Vec<&Belief>> = HashMap::new();
        for b in beliefs {
            groups
                .entry((b.owner_id.as_str(), b.persona_tag.as_deref()))
                .or_default()
                .push(b);
        }

        // Within each group, pair every belief against every other once (O(n^2) per
        // group, T-11-09-02 accepted risk at personal-deployment scale). A belief
        // already paired this pass is skipped so it is never superseded by two
        // different survivors in the same run.
        let mut already_paired: HashSet<i64> = HashSet::new();

        for group in groups.values() {
            for i in 0..group.len() {
                let a = group[i];
                if already_paired.contains(&a.id) {
                    continue;
                }
                for b in group.iter().skip(i + 1) {
                    if already_paired.contains(&b.id) {
                        continue;
                    }
                    let sim = crate::learn::dedup::lexical_similarity(&a.content, &b.content);
                    if sim >= CONSOLIDATE_SIMILARITY_THRESHOLD {
                        let (old_id, new_id) = (a.id.min(b.id), a.id.max(b.id));
                        plan.supersessions.push((old_id, new_id));
                        already_paired.insert(a.id);
                        already_paired.insert(b.id);
                        break;
                    }
                }
            }
        }

        Ok(plan)
    }
}

/// Similarity threshold for MEM-02 belief-content dedup, calibrated INDEPENDENTLY from
/// the Reflector's `dedup::DEFAULT_SIMILARITY_THRESHOLD` (0.90) even though both start
/// from the same `lexical_similarity` primitive — belief-content and Reflector-insight
/// text are different corpora (short, single-fact sentences vs longer procedural
/// insights). 0.90 proved too strict against this module's own fixtures: two beliefs
/// differing by one word out of ~6 short terms ("...every single morning routine" vs
/// "...every single morning schedule") score ~0.83, comfortably a near-duplicate but
/// below 0.90. 0.75 was chosen instead: the near-duplicate fixture
/// (`consolidate_merges_near_duplicate_beliefs`) scores ~0.83 (above), while the
/// borderline-distinct fixture (`consolidate_does_not_merge_dissimilar_beliefs`, two
/// genuinely different facts about the same owner sharing only one term out of nine)
/// scores ~0.11 (well below) — see this module's tests for the exact evidence.
const CONSOLIDATE_SIMILARITY_THRESHOLD: f64 = 0.75;

/// Prune floor for MEM-02 pruning — same value as the stigmergic evaporation pheromone
/// floor (`learn::PHEROMONE_FLOOR` = 0.05; not imported directly since that constant is
/// private to `learn::mod`, but the VALUE is intentionally identical) for consistency of
/// "what counts as negligible weight" across the codebase.
const PRUNE_WEIGHT_FLOOR: f64 = 0.05;

/// MEM-09: memory_flush — distil recent messages to beliefs and persist them.
///
/// Runs BEFORE compaction is invoked in run_turn (loop_.rs compaction branch).
/// Uses HeuristicDream so it is always offline and never makes LLM calls.
///
/// Errors are logged and silently swallowed — flush failure must not abort the turn.
pub async fn memory_flush(messages: &[Message], memory: &SharedMemory, owner: &str) {
    let dream = HeuristicDream;
    let facts = match dream.extract_facts(messages).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(event = "memory_flush_extract_error", error = %e);
            return;
        }
    };

    if facts.is_empty() {
        return;
    }

    let mem = memory.read().await;
    for fact in &facts {
        if let Err(e) = mem
            .store_belief(owner, None, fact, "dream_flush", "dream", false, None)
            .await
        {
            tracing::warn!(event = "memory_flush_store_error", error = %e);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (offline, temp-DB — no LLM)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::sqlite::SqliteMemory;
    use crate::memory::Memory;
    use crate::types::{MessageContent, Role};
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    fn user_msg(text: &str) -> Message {
        Message {
            role: Role::User,
            content: MessageContent::Text(text.to_string()),
        }
    }

    fn assistant_msg(text: &str) -> Message {
        Message {
            role: Role::Assistant,
            content: MessageContent::Text(text.to_string()),
        }
    }

    async fn make_memory(db_path: &str) -> SharedMemory {
        let session = crate::session::SessionManager::new(db_path);
        session.init_schema().await.expect("init_schema");
        Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(db_path)) as Box<dyn Memory>
        ))
    }

    #[tokio::test]
    async fn no_dream_returns_empty() {
        let dream = NoDream;
        let messages = vec![user_msg("I am a developer"), assistant_msg("Got it!")];
        let facts = dream.extract_facts(&messages).await.expect("extract_facts");
        assert!(facts.is_empty(), "NoDream must always return empty");
    }

    #[tokio::test]
    async fn heuristic_dream_extracts_self_disclosure() {
        let dream = HeuristicDream;
        let messages = vec![
            user_msg("I am a software developer living in Brazil"),
            assistant_msg("That's great!"),
            user_msg("what is the weather?"), // no trigger → not extracted
        ];
        let facts = dream.extract_facts(&messages).await.expect("extract_facts");
        assert_eq!(
            facts.len(),
            1,
            "should extract exactly the self-disclosure message"
        );
        assert!(facts[0].contains("developer"), "fact: {}", facts[0]);
    }

    #[tokio::test]
    async fn memory_flush_stores_beliefs_in_temp_db() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let mem = make_memory(&path).await;

        let messages = vec![
            user_msg("I have a dog named Rex"),
            user_msg("Eu gosto de café pela manhã"),
            assistant_msg("Nice to know!"),
            user_msg("what's the weather?"), // no trigger
        ];

        memory_flush(&messages, &mem, "_local").await;

        let beliefs = {
            let m = mem.read().await;
            m.retrieve_tagged("_local", None).await.expect("retrieve")
        };

        assert!(
            !beliefs.is_empty(),
            "at least 1 belief must be stored; got {}",
            beliefs.len()
        );
        let contents: Vec<&str> = beliefs.iter().map(|b| b.content.as_str()).collect();
        assert!(
            contents
                .iter()
                .any(|c| c.contains("dog") || c.contains("Rex") || c.contains("café")),
            "expected a belief about dog or café; got: {:?}",
            contents
        );
    }

    // -----------------------------------------------------------------------
    // Dream::consolidate() (MEM-02) — deterministic fixture-based regression tests (D-14).
    // -----------------------------------------------------------------------

    /// Builds a fixture `Belief` with every non-essential field defaulted, so each test
    /// only spells out the fields it actually varies (id, owner, persona_tag, content,
    /// weight).
    fn belief(
        id: i64,
        owner: &str,
        persona_tag: Option<&str>,
        content: &str,
        weight: f64,
    ) -> Belief {
        Belief {
            id,
            owner_id: owner.to_string(),
            persona_tag: persona_tag.map(|s| s.to_string()),
            content: content.to_string(),
            weight,
            is_core: false,
            tier: None,
            kind: crate::memory::BeliefKind::default(),
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

    /// Test 1: two beliefs, same owner+persona_tag=None, differing only in phrasing —
    /// must merge into exactly one supersession pair (older id superseded by newer).
    #[tokio::test]
    async fn consolidate_merges_near_duplicate_beliefs() {
        let dream = HeuristicDream;
        let beliefs = vec![
            belief(
                1,
                "mario",
                None,
                "Mario exercises every single morning routine",
                0.5,
            ),
            belief(
                2,
                "mario",
                None,
                "Mario exercises every single morning schedule",
                0.5,
            ),
        ];
        let plan = dream.consolidate(&beliefs).await.expect("consolidate");
        assert_eq!(
            plan.supersessions,
            vec![(1, 2)],
            "near-duplicate pair must merge with older(1) superseded by newer(2); got {:?}",
            plan.supersessions
        );
        assert!(
            plan.prune_ids.is_empty(),
            "normal-weight beliefs must not be pruned"
        );
    }

    /// Test 2: two beliefs, same owner+persona_tag, sharing only 1-2 words out of many —
    /// must NOT merge (proves the threshold isn't over-aggressive).
    #[tokio::test]
    async fn consolidate_does_not_merge_dissimilar_beliefs() {
        let dream = HeuristicDream;
        let beliefs = vec![
            belief(
                1,
                "mario",
                None,
                "Mario enjoys drinking coffee every single morning before work",
                0.5,
            ),
            belief(
                2,
                "mario",
                None,
                "Mario dislikes eating spicy food during dinner parties often",
                0.5,
            ),
        ];
        let plan = dream.consolidate(&beliefs).await.expect("consolidate");
        assert!(
            plan.supersessions.is_empty(),
            "borderline-distinct beliefs must not merge; got {:?}",
            plan.supersessions
        );
    }

    /// Test 3: two near-identical-content beliefs but different persona_tag — must NOT
    /// merge (consolidation is scoped to same owner+persona_tag).
    #[tokio::test]
    async fn consolidate_does_not_merge_across_persona_tags() {
        let dream = HeuristicDream;
        let beliefs = vec![
            belief(
                1,
                "mario",
                None,
                "Mario exercises every single morning routine",
                0.5,
            ),
            belief(
                2,
                "mario",
                Some("saude"),
                "Mario exercises every single morning schedule",
                0.5,
            ),
        ];
        let plan = dream.consolidate(&beliefs).await.expect("consolidate");
        assert!(
            plan.supersessions.is_empty(),
            "near-identical content across different persona_tag must not merge; got {:?}",
            plan.supersessions
        );
    }

    /// Test 4: a belief with weight below the prune floor gets pruned; a belief with
    /// normal weight does not.
    #[tokio::test]
    async fn consolidate_prunes_low_weight_beliefs() {
        let dream = HeuristicDream;
        let beliefs = vec![
            belief(1, "mario", None, "Mario likes tea", 0.01),
            belief(2, "mario", None, "Mario dislikes soda", 0.5),
        ];
        let plan = dream.consolidate(&beliefs).await.expect("consolidate");
        assert_eq!(
            plan.prune_ids,
            vec![1],
            "only the low-weight belief must be pruned; got {:?}",
            plan.prune_ids
        );
    }

    /// Test 5 (structural): `consolidate()` takes only `&[Belief]` — no
    /// `CapabilityRegistry`/`InvokeCtx` reachable from this call, proving the
    /// zero-cost/offline contract at the type level (this test file never imports
    /// `crate::capability::registry`).
    #[tokio::test]
    async fn consolidate_is_reachable_with_no_registry_in_scope() {
        let dream = HeuristicDream;
        let beliefs = vec![belief(1, "mario", None, "Mario likes tea", 0.5)];
        let plan = dream
            .consolidate(&beliefs)
            .await
            .expect("consolidate must succeed with zero external dependencies");
        assert!(plan.supersessions.is_empty());
        assert!(plan.prune_ids.is_empty());
    }
}
