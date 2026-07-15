//! EVAL-01: tier-gated regression capture — grows the deterministic regression set
//! from concrete production-failure signals (NL contestation revoke, egress reject).
//!
//! # Structural-only, no content (Pitfall 1 — the highest-risk mechanism in this phase)
//! [`RegressionCase`] has NO content field at all — it is structurally impossible to
//! leak raw turn/belief text through this struct. Only `structural_property` (a fixed,
//! hardcoded label chosen by the CALLING CODE — never derived from user input) and
//! `tier` are ever recorded.
//!
//! # Tier routing (deny-on-ambiguity)
//! - `Some(PrivacyTier::CloudOk)` → the git-committed fixture
//!   (`tests/evals/fixtures/dataset.jsonl`, or `$BASTION_EVAL_FIXTURES` if set).
//! - `Some(PrivacyTier::LocalOnly)` OR `None` (ambiguous/untagged) → the gitignored
//!   local-only store (`.bastion-local/regression-local.jsonl`, or
//!   `$BASTION_EVAL_LOCAL_STORE` if set). Ambiguous tier is treated exactly like
//!   LocalOnly — never assumed safe (same philosophy as `hooks::egress::check_egress`).
//!
//! A write failure (e.g. read-only filesystem) is logged via `tracing::warn!` and
//! swallowed — `record_failure` never propagates an error, never panics the calling turn.

use crate::memory::PrivacyTier;
use std::io::Write as _;

/// M2 (P2 `FailureSink` port): `FailureKind` moved to `bastion-types` — it is
/// vocabulary shared across the kernel/product boundary, not capture logic.
/// Re-exported here so existing `crate::eval::capture::FailureKind` paths keep
/// working unchanged.
pub use bastion_types::FailureKind;

/// One regression-set entry. There is deliberately NO content field on this struct —
/// structurally impossible to serialize raw turn/belief text through it (Pitfall 1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegressionCase {
    pub id: String,
    pub kind: String,
    pub structural_property: String,
    pub tier: Option<String>,
}

fn tier_str(tier: Option<PrivacyTier>) -> Option<String> {
    tier.map(|t| match t {
        PrivacyTier::CloudOk => "cloud-ok".to_string(),
        PrivacyTier::LocalOnly => "local-only".to_string(),
    })
}

fn committed_fixture_path() -> String {
    std::env::var("BASTION_EVAL_FIXTURES")
        .unwrap_or_else(|_| "tests/evals/fixtures/dataset.jsonl".to_owned())
}

fn local_only_store_path() -> String {
    std::env::var("BASTION_EVAL_LOCAL_STORE")
        .unwrap_or_else(|_| ".bastion-local/regression-local.jsonl".to_owned())
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn append_case(path: &str, case: &RegressionCase) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let line = serde_json::to_string(case)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

/// Record one production-turn failure into the tier-gated regression set (EVAL-01).
///
/// Tier routing is deny-on-ambiguity: only `Some(PrivacyTier::CloudOk)` ever reaches
/// the git-committed fixture; `Some(PrivacyTier::LocalOnly)` and `None` both route to
/// the gitignored local-only store. A write failure is logged via `tracing::warn!`
/// and swallowed — never propagated, never panics the calling turn.
pub fn record_failure(kind: FailureKind, tier: Option<PrivacyTier>, structural_property: &str) {
    let path = match tier {
        Some(PrivacyTier::CloudOk) => committed_fixture_path(),
        _ => local_only_store_path(),
    };
    let case = RegressionCase {
        id: format!("{kind}-{}", now_nanos()),
        kind: kind.to_string(),
        structural_property: structural_property.to_owned(),
        tier: tier_str(tier),
    };
    if let Err(e) = append_case(&path, &case) {
        tracing::warn!(event = "regression_capture_failed", error = %e, path = %path);
    }
}

/// The regression cases loaded from a JSONL file — what `verify_delta` replays
/// (src/eval/verifier.rs).
#[derive(Debug, Clone, Default)]
pub struct RegressionSet {
    pub cases: Vec<RegressionCase>,
}

impl RegressionSet {
    /// Load from `path`. Missing file → empty `cases`. Malformed lines are skipped
    /// via `filter_map` — never panics on a corrupt fixture.
    pub fn load(path: &str) -> Self {
        let cases = std::fs::read_to_string(path)
            .map(|raw_text| {
                raw_text
                    .lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect()
            })
            .unwrap_or_default();
        RegressionSet { cases }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Env vars are process-global; serialize every test in this module that touches
    // BASTION_EVAL_FIXTURES / BASTION_EVAL_LOCAL_STORE to avoid cross-test flakiness.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn with_env<T>(fixtures: &str, local: &str, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BASTION_EVAL_FIXTURES", fixtures);
        std::env::set_var("BASTION_EVAL_LOCAL_STORE", local);
        let result = f();
        std::env::remove_var("BASTION_EVAL_FIXTURES");
        std::env::remove_var("BASTION_EVAL_LOCAL_STORE");
        result
    }

    #[test]
    fn cloud_ok_routes_to_committed_fixture_path() {
        let dir = TempDir::new().expect("tempdir");
        let fixtures = dir.path().join("dataset.jsonl");
        let local = dir.path().join("local.jsonl");

        with_env(fixtures.to_str().unwrap(), local.to_str().unwrap(), || {
            record_failure(
                FailureKind::Contestation,
                Some(PrivacyTier::CloudOk),
                "belief_revoked_on_nl_contestation",
            );
        });

        assert!(
            fixtures.exists(),
            "CloudOk capture must reach the fixture path"
        );
        assert!(
            !local.exists(),
            "CloudOk capture must NOT reach the local-only store"
        );
        let raw_text = std::fs::read_to_string(&fixtures).unwrap();
        let case: RegressionCase = serde_json::from_str(raw_text.lines().next().unwrap()).unwrap();
        assert_eq!(case.tier.as_deref(), Some("cloud-ok"));
        assert_eq!(
            case.structural_property,
            "belief_revoked_on_nl_contestation"
        );
    }

    /// CRITICAL (T-07-04-01/02): a LocalOnly-tagged turn must NEVER reach the
    /// git-committed fixture path — only the gitignored local-only store.
    #[test]
    fn local_only_never_reaches_committed_fixture() {
        let dir = TempDir::new().expect("tempdir");
        let fixtures = dir.path().join("dataset.jsonl");
        let local = dir.path().join("local.jsonl");

        with_env(fixtures.to_str().unwrap(), local.to_str().unwrap(), || {
            record_failure(
                FailureKind::EgressReject,
                Some(PrivacyTier::LocalOnly),
                "localonly_belief_blocked_from_cloud_provider",
            );
        });

        assert!(
            !fixtures.exists(),
            "LocalOnly capture must NEVER create/append to the committed fixture path"
        );
        assert!(
            local.exists(),
            "LocalOnly capture must reach the local-only store"
        );
        let raw_text = std::fs::read_to_string(&local).unwrap();
        let case: RegressionCase = serde_json::from_str(raw_text.lines().next().unwrap()).unwrap();
        assert_eq!(case.tier.as_deref(), Some("local-only"));
    }

    /// Ambiguous tier (`None`) is deny-on-ambiguity — routed to the local-only store,
    /// never the committed fixture, mirroring `hooks::egress::check_egress`.
    #[test]
    fn none_tier_routes_to_local_store_deny_on_ambiguity() {
        let dir = TempDir::new().expect("tempdir");
        let fixtures = dir.path().join("dataset.jsonl");
        let local = dir.path().join("local.jsonl");

        with_env(fixtures.to_str().unwrap(), local.to_str().unwrap(), || {
            record_failure(FailureKind::EgressReject, None, "ambiguous_tier_case");
        });

        assert!(
            !fixtures.exists(),
            "None tier must never reach the committed fixture"
        );
        assert!(
            local.exists(),
            "None tier must route to the local-only store"
        );
    }

    #[test]
    fn write_failure_is_swallowed_never_panics() {
        // Point the committed-fixture path at a directory (not a file) — the
        // subsequent OpenOptions::open must fail, and record_failure must swallow it.
        let dir = TempDir::new().expect("tempdir");
        let bogus_fixture_dir = dir.path().join("dataset.jsonl");
        std::fs::create_dir_all(&bogus_fixture_dir).unwrap();
        let local = dir.path().join("local.jsonl");

        with_env(
            bogus_fixture_dir.to_str().unwrap(),
            local.to_str().unwrap(),
            || {
                // Must not panic even though the "file" path is actually a directory.
                record_failure(
                    FailureKind::Contestation,
                    Some(PrivacyTier::CloudOk),
                    "belief_revoked_on_nl_contestation",
                );
            },
        );
    }

    #[test]
    fn regression_set_load_missing_file_returns_empty() {
        let set = RegressionSet::load("/nonexistent/path/does-not-exist.jsonl");
        assert!(set.cases.is_empty());
    }

    #[test]
    fn regression_set_load_skips_malformed_lines() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("mixed.jsonl");
        std::fs::write(
            &path,
            "not json at all\n{\"id\":\"a\",\"kind\":\"contestation\",\"structural_property\":\"x\",\"tier\":null}\n",
        )
        .unwrap();

        let set = RegressionSet::load(path.to_str().unwrap());
        assert_eq!(
            set.cases.len(),
            1,
            "malformed line must be skipped, not panic"
        );
        assert_eq!(set.cases[0].id, "a");
    }
}
