//! Cabinet mixed-tier downgrade policy (PRIV-04, D-01/D-02).
//!
//! `table_tier` is a pure function that resolves the effective [`PrivacyTier`] for
//! a Cabinet deliberation. Rules (D-01):
//! - If ANY persona in the table is `LocalOnly`, the WHOLE deliberation is pinned
//!   to `LocalOnly` — most-restrictive-wins.
//! - An empty table defaults to `LocalOnly` (deny-side safety: no personas, no cloud).
//!
//! **Scoping (D-02):** This resolution is scoped to the current [`RouterDecision`]
//! deliberation only. Persona structs are never mutated; the downgrade is ephemeral
//! and is NOT persisted to the persona registry or any storage backend.

use crate::memory::PrivacyTier;

/// Resolve the effective privacy tier for a Cabinet table.
///
/// Returns `LocalOnly` if:
/// - The slice is empty (deny-side default), OR
/// - Any element is `LocalOnly` (most-restrictive-wins, D-01).
///
/// Returns `CloudOk` only when every persona in the table is `CloudOk`.
///
/// # Scoping (D-02)
/// This function does not mutate any persona state. The returned tier is used only
/// for the duration of the current deliberation round.
pub(crate) fn table_tier(tiers: &[PrivacyTier]) -> PrivacyTier {
    if tiers.is_empty() || tiers.contains(&PrivacyTier::LocalOnly) {
        PrivacyTier::LocalOnly
    } else {
        PrivacyTier::CloudOk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PrivacyTier::{CloudOk, LocalOnly};

    #[test]
    fn all_cloud_ok_returns_cloud_ok() {
        assert_eq!(table_tier(&[CloudOk, CloudOk]), CloudOk);
    }

    #[test]
    fn mixed_with_local_only_returns_local_only() {
        assert_eq!(table_tier(&[CloudOk, LocalOnly]), LocalOnly);
    }

    #[test]
    fn single_local_only_returns_local_only() {
        assert_eq!(table_tier(&[LocalOnly]), LocalOnly);
    }

    #[test]
    fn empty_table_returns_local_only() {
        // Deny-side default: empty table = most restrictive.
        assert_eq!(table_tier(&[]), LocalOnly);
    }

    #[test]
    fn single_cloud_ok_returns_cloud_ok() {
        assert_eq!(table_tier(&[CloudOk]), CloudOk);
    }

    #[test]
    fn any_local_in_large_table_returns_local_only() {
        assert_eq!(
            table_tier(&[CloudOk, CloudOk, LocalOnly, CloudOk]),
            LocalOnly
        );
    }
}
