//! Approval-intent detection: natural-language yes/no resolution for pending
//! `approval_queue` rows (SEC-01, D-02 — "linguagem natural é o mecanismo BASE").
//!
//! Similar idiom to [`crate::hooks::output_validator::detect_contestation`]: a
//! pure, offline, case-insensitive phrase match against a fixed bilingual list
//! — never an LLM call, never fuzzy matching. It is intentionally NOT a clone of
//! `CONTESTATION_PHRASES` — those phrases mean "you're wrong about X" (belief
//! revocation intent), a semantically unrelated concept from "yes, go ahead" /
//! "no, cancel that" (approval-queue resolution intent).
//!
//! Unlike `detect_contestation`'s low-stakes substring match, a false positive
//! here silently approves-and-dispatches (or rejects) a pending, potentially
//! financial/irreversible action with no real owner confirmation (docs/ARCHITECTURE.md:
//! "financial/irreversible actions need explicit user confirmation; never
//! autonomous") — so matching is word-boundary-based, not raw substring: "sim"
//! matches "Sim, pode fazer" but not "simular uma situação"; "no" matches "no"
//! but not "novo" / "noite" / "Not now" (milestone-close code review, 2026-07-13).

/// Phrase set for APPROVAL intent (pt-BR + en, case-insensitive).
const APPROVAL_PHRASES: &[&str] = &[
    "sim",
    "aprovo",
    "confirmo",
    "pode fazer",
    "autorizo",
    "yes",
    "approve",
    "approved",
    "confirmed",
    "go ahead",
];

/// Phrase set for REJECTION intent (pt-BR + en, case-insensitive).
const REJECTION_PHRASES: &[&str] = &[
    "não", "nao", "rejeito", "cancela", "cancelar", "no", "reject", "cancel", "deny",
];

/// Returns `true` when `phrase` occurs in `text` at a word boundary — i.e. the
/// character immediately before and after the match, if any, is not
/// alphanumeric. Prevents "sim" from matching inside "simular", or "no" from
/// matching inside "novo"/"noite"/"Not" — a plain `str::contains` would.
fn contains_word_boundary(text: &str, phrase: &str) -> bool {
    let mut search_start = 0;
    while let Some(offset) = text[search_start..].find(phrase) {
        let match_start = search_start + offset;
        let match_end = match_start + phrase.len();
        let before_is_boundary = text[..match_start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_is_boundary = text[match_end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_is_boundary && after_is_boundary {
            return true;
        }
        // Advance by at least one byte past this (non-matching) occurrence's
        // start to find the next candidate — `phrase` is never empty here.
        search_start = match_start + phrase.len().max(1);
        if search_start > text.len() {
            break;
        }
    }
    false
}

/// Returns `true` when `text` contains a natural-language approval phrase at
/// a word boundary (case-insensitive).
pub(crate) fn detect_approval_intent(text: &str) -> bool {
    let lower = text.to_lowercase();
    APPROVAL_PHRASES
        .iter()
        .any(|&phrase| contains_word_boundary(&lower, phrase))
}

/// Returns `true` when `text` contains a natural-language rejection phrase at
/// a word boundary (case-insensitive). Same idiom as [`detect_approval_intent`].
pub(crate) fn detect_rejection_intent(text: &str) -> bool {
    let lower = text.to_lowercase();
    REJECTION_PHRASES
        .iter()
        .any(|&phrase| contains_word_boundary(&lower, phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: a representative sample from each phrase set is detected as approval.
    #[test]
    fn detect_approval_intent_recognizes_representative_phrases() {
        for phrase in ["sim", "aprovo", "pode fazer", "yes", "approve", "go ahead"] {
            assert!(
                detect_approval_intent(phrase),
                "expected '{phrase}' to be detected as approval intent"
            );
        }
    }

    /// Test 2: mixed case, embedded in a longer sentence — still detected
    /// (case-insensitive substring match).
    #[test]
    fn detect_approval_intent_is_case_insensitive_and_substring_based() {
        assert!(detect_approval_intent("Sim, pode fazer isso"));
        assert!(detect_approval_intent("YES, APPROVE IT"));
    }

    /// Test 3: an unrelated message is not detected as approval, INCLUDING when
    /// a phrase occurs only as a substring of an unrelated word — the word-
    /// boundary fix (milestone-close code review, 2026-07-13) closes exactly
    /// this class of false positive.
    #[test]
    fn detect_approval_intent_current_behavior_on_unrelated_and_substring_input() {
        assert!(!detect_approval_intent("what's the weather?"));
        // "sim" is a substring of "simular" but not a whole word here — must
        // NOT match (this used to be an accepted false positive; now fixed).
        assert!(!detect_approval_intent("simular uma situação"));
    }

    /// Regression (milestone-close code review, 2026-07-13): concrete real-world
    /// phrases that used to misfire via raw substring matching must not anymore.
    /// A pending SEC-01 approval row must never be resolved by these.
    #[test]
    fn word_boundary_fix_prevents_concrete_real_world_false_positives() {
        // "no" is a substring of "Not"/"now"/"novo"/"noite" — none of these are
        // the rejection word "no" on its own.
        assert!(!detect_rejection_intent("Not now, I'm driving"));
        assert!(!detect_rejection_intent("novo pedido chegou"));
        assert!(!detect_rejection_intent("boa noite!"));
        // "sim" is a substring of "simples"/"simular" — not the approval word
        // "sim" on its own.
        assert!(!detect_approval_intent("simples assim!"));
        assert!(!detect_approval_intent("vou simular uma proposta"));
        // Sanity: the real words, as actual standalone words, still match.
        assert!(detect_rejection_intent("no, cancela isso"));
        assert!(detect_approval_intent("sim, pode confirmar"));
    }

    /// Test 4: explicit rejection phrases are NOT detected as approval, and vice
    /// versa — the two phrase sets are disjoint in practice for these examples.
    #[test]
    fn rejection_phrases_are_not_detected_as_approval_and_vice_versa() {
        for phrase in ["não", "no", "rejeito", "cancela"] {
            assert!(
                !detect_approval_intent(phrase),
                "expected '{phrase}' to NOT be detected as approval intent"
            );
            assert!(
                detect_rejection_intent(phrase),
                "expected '{phrase}' to be detected as rejection intent"
            );
        }
        for phrase in ["sim", "aprovo", "yes", "approve"] {
            assert!(
                !detect_rejection_intent(phrase),
                "expected '{phrase}' to NOT be detected as rejection intent"
            );
        }
    }
}
