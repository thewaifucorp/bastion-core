//! Life-log Observer — records interaction events for audit/analysis (HOOK-05).
//!
//! # Metadata-only (pitfall 7, AI-SPEC §7, T-02-13)
//! `LifeLog::record` emits structured tracing spans containing ONLY metadata:
//! persona_id, tier, mode, token counts, latency, and similar operational metrics.
//! It MUST NOT receive or log raw message bodies, especially local-only content.
//! The CALLER is responsible for never passing raw message content in `metadata`.
//! Violating this would constitute a local-only egress violation at the logging layer.
//!
//! # Fire-and-forget
//! Like all `Observer` implementations, errors are silently dropped so a logging
//! failure never aborts a provider call.

/// Life-log observer: records interaction events as structured tracing log entries.
///
/// # CRITICAL — metadata only
/// The `metadata` argument MUST contain only operational metadata (persona id,
/// privacy tier label, mode, token counts, latency ms, session id, etc.).
/// Raw user or system message bodies — especially any LocalOnly-tier content —
/// MUST NOT be included. Passing raw content here is a security violation
/// equivalent to an egress leak (T-02-13 / pitfall 7).
pub struct LifeLog;

#[async_trait::async_trait]
impl crate::hooks::Observer for LifeLog {
    /// Record `event` with structured `metadata`.
    ///
    /// Emits a `tracing::info!` entry. The metadata value is formatted as a JSON
    /// string in the log output for downstream analysis pipelines.
    ///
    /// **Metadata must not contain raw message content** (see module-level doc).
    async fn record(&self, event: &str, metadata: serde_json::Value) {
        tracing::info!(
            event = event,
            metadata = %metadata,
            "lifelog"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::Observer;

    /// Smoke test: LifeLog::record must not panic given a valid metadata JSON object.
    #[tokio::test]
    async fn lifelog_record_does_not_panic() {
        let log = LifeLog;
        let metadata = serde_json::json!({
            "persona_id": "bastion-default",
            "tier": "cloud-ok",
            "mode": "chat",
            "token_count": 128,
            "latency_ms": 342,
            "session_id": "sess-abc123"
        });
        // Must not panic
        log.record("provider_call_complete", metadata).await;
    }

    /// Verify LifeLog works with an empty metadata object.
    #[tokio::test]
    async fn lifelog_record_empty_metadata() {
        let log = LifeLog;
        log.record("test_event", serde_json::Value::Object(Default::default()))
            .await;
    }

    /// Verify LifeLog works with metadata containing only operational fields.
    #[tokio::test]
    async fn lifelog_record_operational_metadata() {
        let log = LifeLog;
        let metadata = serde_json::json!({
            "persona_id": "health-coach",
            "tier": "local-only",
            "input_tokens": 50,
            "output_tokens": 200
        });
        log.record("interaction", metadata).await;
    }
}
