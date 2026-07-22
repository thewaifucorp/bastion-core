use crate::capability::registry::{CapabilityRegistry, InvokeCtx};

/// Minimum term length for the lexical-overlap fallback — mirrors
/// `agent::memory_rag::MIN_TERM_LEN` so short function words never dominate the score.
const MIN_TERM_LEN: usize = 4;

/// Default cosine-similarity / lexical-overlap-ratio threshold above which two
/// insight strings are considered near-duplicates.
const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.90;

/// Zero-cost fallback: same word-overlap idiom as `agent::memory_rag::lexical_overlap`,
/// normalized to a 0.0-1.0 ratio (overlap count / max(len_a_terms, len_b_terms)) so it
/// is directly comparable to a cosine-similarity threshold.
///
/// `pub(crate)` (not private): `agent::dream::HeuristicDream::consolidate` (MEM-02, D-13)
/// calls this directly — it needs the exact zero-dependency Jaccard-style primitive, NOT
/// `is_duplicate`, which tries `memory_embed` over MCP first and is therefore not zero-cost.
pub(crate) fn lexical_similarity(a: &str, b: &str) -> f64 {
    let terms = |s: &str| -> std::collections::HashSet<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.chars().count() >= MIN_TERM_LEN)
            .map(|t| t.to_lowercase())
            .collect()
    };
    let (ta, tb) = (terms(a), terms(b));
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let overlap = ta.intersection(&tb).count() as f64;
    overlap / ta.len().max(tb.len()) as f64
}

/// Cosine similarity between two equal-length embedding vectors. Returns 0.0 for
/// mismatched lengths or zero-magnitude vectors instead of dividing by zero.
fn cosine(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let (na, nb): (f64, f64) = (
        a.iter().map(|x| x * x).sum::<f64>().sqrt(),
        b.iter().map(|x| x * x).sum::<f64>().sqrt(),
    );
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Calls the `memory_embed` capability (memupalace MCP tool) via the one sanctioned
/// tool surface (`CapabilityRegistry::invoke`, docs/ARCHITECTURE.md "one tool surface" law) and
/// parses the returned JSON array as an embedding vector.
async fn embed(
    registry: &CapabilityRegistry,
    ctx: &InvokeCtx,
    text: &str,
) -> anyhow::Result<Vec<f64>> {
    let tagged = registry
        .invoke("memory_embed", serde_json::json!({ "text": text }), ctx)
        .await?;
    serde_json::from_value(tagged.data)
        .map_err(|e| anyhow::anyhow!("memory_embed returned non-vector: {e}"))
}

/// True if `candidate` is a semantic near-duplicate of any string in `existing`.
///
/// Tries memupalace's `memory_embed` capability FIRST (via `CapabilityRegistry::invoke`,
/// docs/ARCHITECTURE.md "one tool surface" law); falls back to lexical overlap when the capability
/// call fails (memupalace down, tool missing) — this is enrichment, so it fails OPEN
/// (never blocks the Reflector tick, matches `memory_rag.rs`'s fail-open retrieve
/// discipline) and never panics.
pub async fn is_duplicate(
    registry: &CapabilityRegistry,
    ctx: &InvokeCtx,
    candidate: &str,
    existing: &[String],
    threshold: Option<f64>,
) -> bool {
    let threshold = threshold.unwrap_or(DEFAULT_SIMILARITY_THRESHOLD);
    match embed(registry, ctx, candidate).await {
        Ok(cand_vec) => {
            for e in existing {
                if let Ok(e_vec) = embed(registry, ctx, e).await {
                    if cosine(&cand_vec, &e_vec) >= threshold {
                        return true;
                    }
                }
            }
            false
        }
        Err(e) => {
            tracing::warn!(event = "dedup_embed_unavailable_fallback_lexical", error = %e);
            existing
                .iter()
                .any(|e| lexical_similarity(candidate, e) >= threshold)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (offline — mocked `memory_embed` capability via DirectFnAdapter)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityRegistry, InvokeCtx};
    use crate::memory::PrivacyTier;
    // M2 step 6: `DirectFnAdapter` is an MCP→capability adapter (extracted to
    // `bastion-mcp` in M2 step 5); this dev-only test fixture is the only
    // reason this crate touches `bastion-mcp` at all (dev-dependency, not a
    // production edge).
    use bastion_mcp::adapters::DirectFnAdapter;
    use std::sync::Arc;

    /// Registers a deterministic mock `memory_embed`: any text containing "concise"
    /// or "short" embeds to [1.0, 0.0]; any text containing "pizza" embeds to
    /// [0.0, 1.0]; anything else embeds to [0.5, 0.5] (neither cluster).
    fn registry_with_mock_embed() -> CapabilityRegistry {
        let mut registry = CapabilityRegistry::new();
        let func = Arc::new(
            |args: serde_json::Value| -> anyhow::Result<serde_json::Value> {
                let text = args
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_lowercase();
                let vec = if text.contains("concise") || text.contains("short") {
                    vec![1.0, 0.0]
                } else if text.contains("pizza") {
                    vec![0.0, 1.0]
                } else {
                    vec![0.5, 0.5]
                };
                Ok(serde_json::json!(vec))
            },
        );
        registry
            .register(Arc::new(DirectFnAdapter {
                cap_name: "memory_embed".to_owned(),
                cap_description: "mock embed for tests".to_owned(),
                schema: serde_json::json!({}),
                func,
            }))
            .expect("register mock memory_embed");
        registry
    }

    fn cloud_ok_ctx() -> InvokeCtx {
        InvokeCtx {
            owner: "owner1".to_owned(),
            privacy_tier: Some(PrivacyTier::CloudOk),
            allowed_tools: None,
        }
    }

    #[tokio::test]
    async fn semantic_near_duplicates_detected_via_embedding() {
        let registry = registry_with_mock_embed();
        let ctx = cloud_ok_ctx();
        let existing = vec!["Mario prefers concise replies".to_owned()];
        let is_dup = is_duplicate(
            &registry,
            &ctx,
            "Mario likes short answers",
            &existing,
            None,
        )
        .await;
        assert!(
            is_dup,
            "near-identical embeddings must be flagged as duplicate"
        );
    }

    #[tokio::test]
    async fn unrelated_insights_are_not_duplicates_via_embedding() {
        let registry = registry_with_mock_embed();
        let ctx = cloud_ok_ctx();
        let existing = vec!["Mario prefers concise replies".to_owned()];
        let is_dup = is_duplicate(&registry, &ctx, "I like pizza", &existing, None).await;
        assert!(
            !is_dup,
            "dissimilar embeddings must not be flagged as duplicate"
        );
    }

    #[tokio::test]
    async fn falls_back_to_lexical_overlap_when_memory_embed_is_absent() {
        // No memory_embed registered at all — simulates memupalace being down.
        let registry = CapabilityRegistry::new();
        let ctx = cloud_ok_ctx();

        let existing = vec!["Mario prefers concise replies always".to_owned()];
        let is_dup = is_duplicate(
            &registry,
            &ctx,
            "Mario prefers concise replies always",
            &existing,
            None,
        )
        .await;
        assert!(
            is_dup,
            "identical text must be caught by the lexical fallback"
        );

        let unrelated = vec!["completely unrelated topic here".to_owned()];
        let is_dup_unrelated = is_duplicate(
            &registry,
            &ctx,
            "Mario prefers concise replies always",
            &unrelated,
            None,
        )
        .await;
        assert!(
            !is_dup_unrelated,
            "the lexical fallback must not false-positive on unrelated text"
        );
    }
}
