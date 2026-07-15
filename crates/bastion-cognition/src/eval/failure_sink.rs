//! [`FailureSink`] port implementation backed by the EVAL-01 regression-capture
//! mechanism (`crate::eval::capture`).
//!
//! Thin wrapper: [`EvalFailureSink::record_failure`] forwards verbatim to
//! [`crate::eval::capture::record_failure`] — no logic moves, only the call
//! site's dependency on `crate::eval` is replaced by a dependency on the
//! `FailureSink` trait (M2 P2).

// M2 step 6: fully-qualified — `crate::agent` in `bastion-cognition` is this
// crate's own dream/procedural/memory_rag/identity module; the kernel's
// ports stay in `bastion_runtime::agent`.
use bastion_runtime::agent::ports::FailureSink;

use crate::eval::capture::{record_failure, FailureKind};
use crate::memory::PrivacyTier;

/// The production [`FailureSink`]: grows the EVAL-01 tier-gated regression set.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvalFailureSink;

impl FailureSink for EvalFailureSink {
    fn record_failure(&self, kind: FailureKind, tier: Option<PrivacyTier>, detail: &str) {
        record_failure(kind, tier, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mirrors the env-var guard in `eval::capture`'s own tests — BASTION_EVAL_*
    // env vars are process-global.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn forwards_to_eval_capture_record_failure() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let fixtures = dir.path().join("dataset.jsonl");
        let local = dir.path().join("local.jsonl");
        std::env::set_var("BASTION_EVAL_FIXTURES", fixtures.to_str().unwrap());
        std::env::set_var("BASTION_EVAL_LOCAL_STORE", local.to_str().unwrap());

        let sink = EvalFailureSink;
        sink.record_failure(
            FailureKind::EgressReject,
            Some(PrivacyTier::CloudOk),
            "test_detail",
        );

        std::env::remove_var("BASTION_EVAL_FIXTURES");
        std::env::remove_var("BASTION_EVAL_LOCAL_STORE");

        assert!(
            fixtures.exists(),
            "record_failure must reach the fixture path"
        );
    }
}
