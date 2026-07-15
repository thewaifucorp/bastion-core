//! Output-validator: natural-language contestation detection → belief revocation.
//!
//! Implements HOOK-03, D-13, D-14, D-15, MEM-07.
//!
//! # Natural-language contestation (D-13)
//! The primary contestation mechanism is natural language — the user says "that's not
//! true anymore" and the system detects intent and soft-revokes the matching belief.
//! The `/contest <id>` slash command is the explicit escape hatch (D-14, wired in plan 08).
//!
//! # Soft-revoke (D-15)
//! Revocation sets weight=0, revoked=1 but NEVER deletes the row (audit trail).
//! The `Memory::revoke_belief(owner_id, id)` call enforces owner-scoping (IDOR guard).
//!
//! # Heuristic matching (Phase-2)
//! When contestation intent is detected, this module attempts to find the most-recently
//! stored non-revoked belief for the owner whose content shares keyword overlap with the
//! user's message. If no belief matches, the call is a no-op — the explicit `/contest <id>`
//! command can be used instead (D-14).
//!
//! # LEARN-04 — edit is reachable, not a dead-end claim
//! Revoke stays synchronous (unchanged). The SAME call site that revokes ALSO enqueues
//! a metadata-only `pending_correction` row (belief_id + owner_id + tier + timestamp,
//! NEVER raw correction text) into a new Contestable Memory DB table. The offline
//! Reflector (07-05) drains that queue every tick and synthesizes the corrected
//! procedural belief as a normal, `verify_delta`-gated `DeltaOp` — "edit" is delivered
//! end-to-end across the sync/offline boundary, not a hot-path call and not an unbuilt
//! claim. This call site also grows the EVAL-01 regression set (tier-gated — see
//! `crate::eval::capture`).

use crate::agent::ports::FailureSink;
use crate::memory::SharedMemory;
use std::sync::Arc;

/// Phrase sets for contestation intent detection (pt-BR + en, case-insensitive).
/// These cover the most common forms of "that belief is wrong / outdated".
const CONTESTATION_PHRASES: &[&str] = &[
    // Portuguese (pt-BR)
    "isso não é mais verdade",
    "isso nao e mais verdade",
    "você está errado sobre",
    "voce esta errado sobre",
    "não é verdade",
    "nao e verdade",
    "isso está errado",
    "isso esta errado",
    "você está errada sobre",
    "voce esta errada sobre",
    // English
    "that's not true anymore",
    "thats not true anymore",
    "you're wrong about",
    "youre wrong about",
    "that is not true",
    "that is no longer true",
    "that is wrong",
    "that's wrong",
    "incorrect about",
    "mistaken about",
];

/// Returns `true` when `text` contains a natural-language contestation phrase.
///
/// Matching is case-insensitive and substring-based. Diacritic-stripped variants
/// are also included in [`CONTESTATION_PHRASES`] so ASCII-normalised input matches.
pub(crate) fn detect_contestation(text: &str) -> bool {
    let lower = text.to_lowercase();
    CONTESTATION_PHRASES
        .iter()
        .any(|&phrase| lower.contains(phrase))
}

/// Output-validator: scans user input for contestation intent and soft-revokes
/// the best-matching belief for the given `owner` (HOOK-03, MEM-07).
pub struct OutputValidator {
    /// M2 (P2 `FailureSink` port): grows the EVAL-01 regression set on
    /// NL-contestation revoke, without naming `crate::eval` directly.
    failure_sink: Arc<dyn FailureSink>,
}

impl OutputValidator {
    /// Build a validator that reports contestation-revoke events to `failure_sink`.
    pub fn new(failure_sink: Arc<dyn FailureSink>) -> Self {
        Self { failure_sink }
    }

    /// Validate `user_input` for contestation intent.
    ///
    /// If `detect_contestation(user_input)` is true, find the most-recent non-revoked
    /// belief for `owner` whose content shares keyword overlap with `user_input`, then
    /// call `memory.revoke_belief(owner, id)` (D-15 soft-revoke, IDOR-safe).
    ///
    /// If no belief matches, this is a no-op. The user can use `/contest <id>` (D-14)
    /// to explicitly target a belief by ID.
    ///
    /// CRITICAL (pitfall 7): never log raw `user_input` content here — callers are
    /// responsible for not passing local-only payloads to this method in log output.
    pub async fn validate(
        &self,
        user_input: &str,
        memory: &SharedMemory,
        owner: &str,
    ) -> anyhow::Result<()> {
        if !detect_contestation(user_input) {
            return Ok(());
        }

        // Retrieve all non-revoked beliefs for this owner.
        let beliefs = {
            let mem = memory.read().await;
            mem.retrieve_tagged(owner, None).await?
        };

        if beliefs.is_empty() {
            return Ok(());
        }

        // Heuristic: score beliefs by keyword overlap with the user input.
        // Use lowercased words with length >= 3 (skip stop words / short tokens).
        let input_words: std::collections::HashSet<&str> = user_input
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
            .filter(|w| w.len() >= 3)
            .collect();

        // Find the best-matching belief (highest overlap, tiebreak by most-recent id).
        let best = beliefs.iter().max_by_key(|b| {
            let belief_words: std::collections::HashSet<&str> = b
                .content
                .split_whitespace()
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
                .filter(|w| w.len() >= 3)
                .collect();
            let overlap = input_words.intersection(&belief_words).count();
            (overlap, b.id)
        });

        if let Some(belief) = best {
            // Only revoke if there is at least one overlapping keyword.
            let belief_words: std::collections::HashSet<&str> = belief
                .content
                .split_whitespace()
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
                .filter(|w| w.len() >= 3)
                .collect();
            let overlap = input_words.intersection(&belief_words).count();
            if overlap > 0 {
                let mem = memory.write().await;
                mem.revoke_belief(owner, belief.id).await?;
                self.failure_sink.record_failure(
                    bastion_types::FailureKind::Contestation,
                    belief.tier,
                    "belief_revoked_on_nl_contestation",
                );
                mem.record_pending_correction(owner, belief.id, belief.tier)
                    .await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detect_contestation phrase coverage ---

    #[test]
    fn detects_pt_br_contestation() {
        assert!(detect_contestation(
            "isso não é mais verdade sobre exercício"
        ));
        assert!(detect_contestation("Você está errado sobre isso"));
        assert!(detect_contestation("não é verdade"));
        assert!(detect_contestation("Isso está errado"));
    }

    #[test]
    fn detects_en_contestation() {
        assert!(detect_contestation("that's not true anymore"));
        assert!(detect_contestation("you're wrong about that"));
        assert!(detect_contestation("That is not true"));
        assert!(detect_contestation("That is no longer true"));
        assert!(detect_contestation("you are mistaken about my habits"));
    }

    #[test]
    fn does_not_trigger_on_normal_text() {
        assert!(!detect_contestation("what's the weather today?"));
        assert!(!detect_contestation("Hello, how are you?"));
        assert!(!detect_contestation("Please summarize the meeting notes."));
        assert!(!detect_contestation("I exercise every morning"));
    }

    #[test]
    fn case_insensitive_match() {
        assert!(detect_contestation("ISSO NAO E MAIS VERDADE"));
        assert!(detect_contestation("YOU'RE WRONG ABOUT"));
    }
}
