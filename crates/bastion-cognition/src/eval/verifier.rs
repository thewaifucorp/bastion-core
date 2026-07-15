//! EVAL-02: the promoted, in-process-callable merge gate.
//!
//! `verify_delta` is the SAME function `cargo test --test evals` exercises (via the
//! thin wrappers in `tests/evals/mod.rs`) and what the offline Reflector (07-05) calls
//! before ever applying a candidate `DeltaOp` to the live belief store — no drift
//! between the CI gate and the runtime merge gate.

use crate::eval::capture::RegressionSet;
use crate::hooks::egress::check_egress;
use crate::learn::delta::DeltaOp;
use crate::memory::{Memory, PrivacyTier, SharedMemory};

#[derive(Debug, Clone, Default)]
pub struct VerifierResult {
    pub passed: bool,
    pub failed_cases: Vec<String>,
}

const EGRESS_CASES: &[(Option<PrivacyTier>, &str, bool)] = &[
    (Some(PrivacyTier::CloudOk), "ollama", true),
    (Some(PrivacyTier::CloudOk), "openai", true),
    (Some(PrivacyTier::CloudOk), "gemini", true),
    (Some(PrivacyTier::CloudOk), "openrouter", true),
    (Some(PrivacyTier::CloudOk), "anthropic", true),
    (Some(PrivacyTier::LocalOnly), "ollama", true),
    (Some(PrivacyTier::LocalOnly), "openai", false),
    (Some(PrivacyTier::LocalOnly), "gemini", false),
    (Some(PrivacyTier::LocalOnly), "openrouter", false),
    (Some(PrivacyTier::LocalOnly), "anthropic", false),
    (None, "ollama", false),
    (None, "openai", false),
    (None, "gemini", false),
    (None, "openrouter", false),
    (None, "anthropic", false),
];

/// Promoted from `tests/evals/mod.rs::privacy_egress_matrix` (one case). `expected_ok`
/// is the TEST's expectation, not a live derivation — this asserts `check_egress`
/// still matches it.
pub fn assert_egress_case(
    tier: Option<PrivacyTier>,
    provider: &str,
    expected_ok: bool,
) -> VerifierResult {
    let ok = check_egress(tier, provider).is_ok();
    if ok == expected_ok {
        VerifierResult {
            passed: true,
            failed_cases: vec![],
        }
    } else {
        VerifierResult {
            passed: false,
            failed_cases: vec![format!("egress_case:{tier:?}+{provider}")],
        }
    }
}

/// Whole-matrix convenience used by `verify_delta`'s structural gate.
pub(crate) fn assert_egress_matrix() -> VerifierResult {
    let mut failed = vec![];
    for (tier, provider, expected_ok) in EGRESS_CASES {
        let r = assert_egress_case(*tier, provider, *expected_ok);
        failed.extend(r.failed_cases);
    }
    VerifierResult {
        passed: failed.is_empty(),
        failed_cases: failed,
    }
}

/// Promoted from `tests/evals/mod.rs::memory_revocation_clean`'s `retrieve_tagged`
/// half (the raw-row `revoked=1`/`weight=0` assertion stays `SqliteMemory`-specific
/// and is NOT promoted here — it is not part of the abstract `Memory` trait contract).
pub async fn assert_revocation_clean(
    memory: &SharedMemory,
    owner: &str,
) -> anyhow::Result<VerifierResult> {
    let id = {
        let mem = memory.read().await;
        mem.store_belief(
            owner,
            None,
            "verifier scratch belief",
            "verifier",
            "eval",
            false,
            None,
        )
        .await?
    };
    let before_has = {
        let mem = memory.read().await;
        mem.retrieve_tagged(owner, None)
            .await?
            .iter()
            .any(|b| b.id == id)
    };
    {
        let mem = memory.write().await;
        mem.revoke_belief(owner, id).await?;
    }
    let after_excludes = {
        let mem = memory.read().await;
        !mem.retrieve_tagged(owner, None)
            .await?
            .iter()
            .any(|b| b.id == id)
    };
    let mut failed = vec![];
    if !before_has {
        failed.push("revocation_clean:not_retrievable_before_revoke".to_owned());
    }
    if !after_excludes {
        failed.push("revocation_clean:still_retrievable_after_revoke".to_owned());
    }
    Ok(VerifierResult {
        passed: failed.is_empty(),
        failed_cases: failed,
    })
}

/// EVAL-02: applies `candidate` to a SCRATCH belief set (a throwaway temp-file
/// `SqliteMemory`, NEVER the caller's live `SharedMemory`) and replays the
/// deterministic structural checks plus every loaded regression case. A single
/// failing case rejects the whole delta.
pub async fn verify_delta(
    candidate: &DeltaOp,
    owner: &str,
    regression_set: &RegressionSet,
) -> anyhow::Result<VerifierResult> {
    let scratch_file = tempfile::NamedTempFile::new()?;
    let scratch_path = scratch_file
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("scratch tempfile path is not valid UTF-8"))?
        .to_owned();
    crate::session::SessionManager::new(&scratch_path)
        .init_schema()
        .await?;
    let scratch: SharedMemory = std::sync::Arc::new(tokio::sync::RwLock::new(Box::new(
        crate::memory::sqlite::SqliteMemory::new(&scratch_path),
    )
        as Box<dyn Memory>));

    if let Err(e) = candidate.apply(&scratch, owner).await {
        return Ok(VerifierResult {
            passed: false,
            failed_cases: vec![format!("delta_apply_failed: {e}")],
        });
    }

    let mut failed = Vec::new();
    let matrix = assert_egress_matrix();
    failed.extend(matrix.failed_cases.clone());
    let revocation = assert_revocation_clean(&scratch, owner).await?;
    failed.extend(revocation.failed_cases.clone());

    // Replay EVAL-01-grown regression cases by structural_property dispatch (never
    // raw content — Pitfall 1). Unrecognized labels are forward-compatible no-ops.
    for case in &regression_set.cases {
        match case.structural_property.as_str() {
            "belief_revoked_on_nl_contestation" if !revocation.passed => {
                failed.push(format!(
                    "regression[{}]:{}",
                    case.id, case.structural_property
                ));
            }
            "localonly_belief_blocked_from_cloud_provider" if !matrix.passed => {
                failed.push(format!(
                    "regression[{}]:{}",
                    case.id, case.structural_property
                ));
            }
            _ => {}
        }
    }

    Ok(VerifierResult {
        passed: failed.is_empty(),
        failed_cases: failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::capture::RegressionSet;
    use crate::memory::sqlite::SqliteMemory;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn make_scratch_memory() -> (tempfile::NamedTempFile, SharedMemory) {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let path = f
            .path()
            .to_str()
            .expect("tempfile path is valid UTF-8")
            .to_owned();
        crate::session::SessionManager::new(&path)
            .init_schema()
            .await
            .expect("init_schema");
        let mem: SharedMemory = Arc::new(RwLock::new(
            Box::new(SqliteMemory::new(&path)) as Box<dyn Memory>
        ));
        (f, mem)
    }

    #[test]
    fn assert_egress_case_matching_expectation_passes() {
        let r = assert_egress_case(Some(PrivacyTier::CloudOk), "openai", true);
        assert!(r.passed);
        assert!(r.failed_cases.is_empty());
    }

    #[test]
    fn assert_egress_case_correctly_predicted_denial_passes() {
        // expected_ok=false correctly predicts a LocalOnly+openai denial — the
        // EXPECTATION matched reality, so this passes.
        let r = assert_egress_case(Some(PrivacyTier::LocalOnly), "openai", false);
        assert!(r.passed, "correct prediction of denial must pass");
    }

    #[test]
    fn assert_egress_case_wrong_expectation_fails() {
        // A wrong expectation (CloudOk+openai claimed to fail) must be rejected.
        let r = assert_egress_case(Some(PrivacyTier::CloudOk), "openai", false);
        assert!(!r.passed);
        assert!(!r.failed_cases.is_empty());
    }

    #[test]
    fn assert_egress_matrix_all_pass() {
        let r = assert_egress_matrix();
        assert!(r.passed, "full matrix must pass: {:?}", r.failed_cases);
    }

    #[tokio::test]
    async fn assert_revocation_clean_passes_on_scratch_memory() {
        let (_f, mem) = make_scratch_memory().await;
        let r = assert_revocation_clean(&mem, "owner1")
            .await
            .expect("assert_revocation_clean");
        assert!(r.passed, "revocation must be clean: {:?}", r.failed_cases);
    }

    #[tokio::test]
    async fn verify_delta_accepts_valid_add_on_empty_regression_set() {
        let op = DeltaOp::Add {
            issue: None,
            insight: "test".into(),
            keywords: vec![],
            tier: Some(PrivacyTier::CloudOk),
        };
        let result = verify_delta(&op, "owner1", &RegressionSet { cases: vec![] })
            .await
            .expect("verify_delta");
        assert!(
            result.passed,
            "valid delta on empty regression set must pass: {:?}",
            result.failed_cases
        );
    }

    #[tokio::test]
    async fn verify_delta_rejects_delta_that_fails_to_apply() {
        // Removing a nonexistent belief on the fresh scratch set fails to apply →
        // rejected, never reaches the live store (the EVAL-02 "failing delta is
        // rejected" proof).
        let op = DeltaOp::Remove { belief_id: 999_999 };
        let result = verify_delta(&op, "owner1", &RegressionSet { cases: vec![] })
            .await
            .expect("verify_delta");
        assert!(!result.passed);
        assert!(
            result
                .failed_cases
                .iter()
                .any(|c| c.contains("delta_apply_failed")),
            "failed_cases must mention delta_apply_failed: {:?}",
            result.failed_cases
        );
    }

    #[tokio::test]
    async fn verify_delta_never_touches_caller_live_memory() {
        // The live memory handed to verify_delta must remain empty after the call —
        // proof the candidate was applied only to a scratch instance.
        let (_f, live) = make_scratch_memory().await;
        let op = DeltaOp::Add {
            issue: None,
            insight: "should not land in live memory".into(),
            keywords: vec![],
            tier: None,
        };
        let _ = verify_delta(&op, "owner1", &RegressionSet { cases: vec![] })
            .await
            .expect("verify_delta");

        let live_beliefs = {
            let mem = live.read().await;
            mem.retrieve_tagged("owner1", None).await.expect("retrieve")
        };
        assert!(
            live_beliefs.is_empty(),
            "verify_delta must never write to the caller's live SharedMemory"
        );
    }
}
