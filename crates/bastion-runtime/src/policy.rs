//! Rule/policy delivery to running loops.
//!
//! [`DeploymentContext::policy_revision`](bastion_types::DeploymentContext)
//! is a label fixed at startup, and a [`VersionedContextArtifact`] is a
//! history the host keeps. A host whose rules change while its loops serve
//! turns also needs to hand a new revision (whole, or as a delta) to loops
//! that are already running, and to know which revision is now in force.
//! [`PolicyChannel`] is that mechanism.
//!
//! The core never interprets a revision's content (business semantics stay
//! with the host). What it guarantees:
//!
//! - **Versioned, acknowledged delivery.** [`PolicyChannel::apply`] answers
//!   every [`ContextUpdate`] with a [`ContextAck`] naming the version
//!   effective afterwards, whether the update was applied, scheduled
//!   (`effective_from` in the future), already published, or rejected.
//!   Versions strictly increase; history is append-only
//!   ([`VersionedContextArtifact`]).
//! - **Deltas never land on the wrong base.** A [`ContextUpdate::Delta`]
//!   names the version it was computed against and is refused unless that
//!   is the latest published version; the patch is an RFC 7386 JSON Merge
//!   Patch over the base revision's JSON content.
//! - **One revision per turn.** A turn takes the revision effective when it
//!   starts and keeps it until it ends, even if an update lands mid-turn.
//!   The turn's capabilities receive it
//!   ([`crate::capability::InvokeCtx::policy`]), its root span carries
//!   `<ns>.policy.version`, the `Responder` sees it as
//!   `DeploymentContext::policy_revision`, and
//!   [`crate::agent::loop_::AgentLoop::last_turn_policy_version`] reports
//!   the version the last turn actually ran under.
//! - **Host validation.** An optional [`PolicyValidator`] sees each
//!   candidate revision before it is published; a refusal publishes nothing.
//!
//! The channel is a cheap clonable handle: give the same one to every loop
//! that must follow the same rules.

use bastion_types::{
    ContextAck, ContextAckStatus, ContextRevision, ContextUpdate, ContextUpdateRejection,
    StalePolicy, VersionedContextArtifact,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Host check run on a candidate revision before it is published.
pub trait PolicyValidator: Send + Sync {
    /// `Err(detail)` refuses the revision; `detail` is returned to the
    /// sender inside [`ContextUpdateRejection::Invalid`].
    fn validate(&self, revision: &ContextRevision) -> Result<(), String>;
}

/// Clonable handle delivering rule revisions to running loops. See the
/// module docs.
#[derive(Clone)]
pub struct PolicyChannel {
    artifact: Arc<Mutex<VersionedContextArtifact>>,
    validator: Option<Arc<dyn PolicyValidator>>,
}

impl Default for PolicyChannel {
    fn default() -> Self {
        Self::from_artifact(VersionedContextArtifact::new(StalePolicy::UseLastKnown))
    }
}

impl std::fmt::Debug for PolicyChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let artifact = self.artifact();
        f.debug_struct("PolicyChannel")
            .field(
                "latest_version",
                &artifact.latest_published().map(|r| r.version),
            )
            .field("validator", &self.validator.is_some())
            .finish()
    }
}

impl PolicyChannel {
    /// A channel with nothing published and no validator.
    pub fn new() -> Self {
        Self::default()
    }

    /// A channel continuing an artifact the host already has (its history,
    /// its declared stale policy).
    pub fn from_artifact(artifact: VersionedContextArtifact) -> Self {
        Self {
            artifact: Arc::new(Mutex::new(artifact)),
            validator: None,
        }
    }

    /// Run `validator` on every candidate revision before it is published.
    pub fn with_validator(mut self, validator: Arc<dyn PolicyValidator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// The revision effective right now (`None` until one is).
    pub fn effective(&self) -> Option<Arc<ContextRevision>> {
        self.artifact()
            .effective_at(now_nanos())
            .cloned()
            .map(Arc::new)
    }

    /// A copy of the artifact (history, stale policy) for audit.
    pub fn snapshot(&self) -> VersionedContextArtifact {
        self.artifact().clone()
    }

    /// Deliver one update and report what is in force afterwards. Updates
    /// are handled one at a time; a turn already running keeps the revision
    /// it started with.
    pub fn apply(&self, update: ContextUpdate) -> ContextAck {
        let requested_version = update.version();
        let mut artifact = self.artifact();
        let status = match self.candidate(&artifact, update) {
            Err(rejection) => ContextAckStatus::Rejected(rejection),
            Ok(None) => ContextAckStatus::Unchanged,
            Ok(Some(revision)) => {
                let scheduled = revision.effective_from > now_nanos();
                match artifact.publish(revision) {
                    Ok(()) if scheduled => ContextAckStatus::Scheduled,
                    Ok(()) => ContextAckStatus::Applied,
                    // `candidate` already proved the version is newer.
                    Err(_) => ContextAckStatus::Rejected(ContextUpdateRejection::NotNewer),
                }
            }
        };
        let ack = ContextAck {
            requested_version,
            effective_version: artifact.effective_at(now_nanos()).map(|r| r.version),
            latest_version: artifact.latest_published().map(|r| r.version),
            status,
        };
        drop(artifact);
        if ack.is_published() {
            tracing::info!(
                event = "policy_update",
                requested = ack.requested_version,
                effective = ?ack.effective_version,
                status = ?ack.status,
            );
        } else {
            tracing::warn!(
                event = "policy_update_rejected",
                requested = ack.requested_version,
                effective = ?ack.effective_version,
                status = ?ack.status,
            );
        }
        ack
    }

    /// `Ok(None)` = identical redelivery, `Ok(Some(rev))` = publish `rev`.
    fn candidate(
        &self,
        artifact: &VersionedContextArtifact,
        update: ContextUpdate,
    ) -> Result<Option<ContextRevision>, ContextUpdateRejection> {
        let latest = artifact.latest_published();
        let revision = match update {
            ContextUpdate::Snapshot(revision) => revision,
            ContextUpdate::Delta {
                base_version,
                version,
                patch,
                provenance,
                effective_from,
            } => {
                let Some(base) = latest.filter(|l| l.version == base_version) else {
                    return Err(ContextUpdateRejection::StaleBase { base_version });
                };
                if !patch.is_object() {
                    return Err(invalid("a delta patch must be a JSON object".into()));
                }
                let mut content: Value = serde_json::from_str(&base.content).map_err(|e| {
                    invalid(format!("base revision {base_version} is not JSON: {e}"))
                })?;
                merge_patch(&mut content, &patch);
                ContextRevision {
                    version,
                    content: content.to_string(),
                    provenance,
                    effective_from,
                }
            }
        };
        if let Some(latest) = latest {
            if revision.version == latest.version && revision.content == latest.content {
                return Ok(None);
            }
            if revision.version <= latest.version {
                return Err(ContextUpdateRejection::NotNewer);
            }
        }
        if let Some(validator) = &self.validator {
            validator.validate(&revision).map_err(invalid)?;
        }
        Ok(Some(revision))
    }

    fn artifact(&self) -> std::sync::MutexGuard<'_, VersionedContextArtifact> {
        self.artifact.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn invalid(detail: String) -> ContextUpdateRejection {
    ContextUpdateRejection::Invalid { detail }
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// RFC 7386 JSON Merge Patch: object members merge recursively, `null`
/// removes a member, anything else replaces the target.
fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    if let Value::Object(target) = target {
        for (key, value) in patch {
            if value.is_null() {
                target.remove(key);
            } else {
                merge_patch(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn revision(version: u64, content: Value, effective_from: i64) -> ContextRevision {
        ContextRevision {
            version,
            content: content.to_string(),
            provenance: "test".into(),
            effective_from,
        }
    }

    fn snapshot(version: u64, content: Value) -> ContextUpdate {
        ContextUpdate::Snapshot(revision(version, content, 0))
    }

    fn delta(base_version: u64, version: u64, patch: Value) -> ContextUpdate {
        ContextUpdate::Delta {
            base_version,
            version,
            patch,
            provenance: "test".into(),
            effective_from: 0,
        }
    }

    fn content(channel: &PolicyChannel) -> Value {
        serde_json::from_str(&channel.effective().unwrap().content).unwrap()
    }

    #[test]
    fn snapshot_then_delta_reports_the_effective_version() {
        let channel = PolicyChannel::new();
        assert!(channel.effective().is_none());

        let ack = channel.apply(snapshot(1, json!({"limit": 5, "mode": "strict"})));
        assert_eq!(ack.status, ContextAckStatus::Applied);
        assert_eq!(ack.effective_version, Some(1));

        let ack = channel.apply(delta(1, 2, json!({"limit": 7, "mode": null})));
        assert_eq!(ack.status, ContextAckStatus::Applied);
        assert_eq!(ack.effective_version, Some(2));
        assert_eq!(content(&channel), json!({"limit": 7}));
        assert_eq!(channel.snapshot().history().len(), 2, "history is kept");
    }

    #[test]
    fn delta_on_a_stale_base_is_refused_and_nothing_changes() {
        let channel = PolicyChannel::new();
        let ack = channel.apply(delta(0, 1, json!({})));
        assert_eq!(
            ack.status,
            ContextAckStatus::Rejected(ContextUpdateRejection::StaleBase { base_version: 0 })
        );
        assert_eq!(ack.effective_version, None);

        channel.apply(snapshot(1, json!({"a": 1})));
        channel.apply(snapshot(2, json!({"a": 2})));
        let ack = channel.apply(delta(1, 3, json!({"a": 3})));
        assert!(!ack.is_published());
        assert_eq!(ack.effective_version, Some(2));
        assert_eq!(content(&channel), json!({"a": 2}));
    }

    #[test]
    fn redelivery_is_idempotent_and_older_versions_are_refused() {
        let channel = PolicyChannel::new();
        channel.apply(snapshot(2, json!({"a": 1})));
        assert_eq!(
            channel.apply(snapshot(2, json!({"a": 1}))).status,
            ContextAckStatus::Unchanged
        );
        for stale in [snapshot(2, json!({"a": 2})), snapshot(1, json!({"a": 1}))] {
            assert_eq!(
                channel.apply(stale).status,
                ContextAckStatus::Rejected(ContextUpdateRejection::NotNewer)
            );
        }
        assert_eq!(content(&channel), json!({"a": 1}));
    }

    #[test]
    fn a_future_revision_is_scheduled_not_effective() {
        let channel = PolicyChannel::new();
        channel.apply(snapshot(1, json!({"a": 1})));
        let ack = channel.apply(ContextUpdate::Snapshot(revision(
            2,
            json!({"a": 2}),
            i64::MAX,
        )));
        assert_eq!(ack.status, ContextAckStatus::Scheduled);
        assert_eq!(ack.effective_version, Some(1));
        assert_eq!(ack.latest_version, Some(2));
        assert_eq!(channel.effective().unwrap().version, 1);
    }

    #[test]
    fn malformed_updates_are_invalid() {
        let channel = PolicyChannel::new();
        channel.apply(ContextUpdate::Snapshot(ContextRevision {
            version: 1,
            content: "not json".into(),
            provenance: "test".into(),
            effective_from: 0,
        }));
        assert!(matches!(
            channel.apply(delta(1, 2, json!({"a": 1}))).status,
            ContextAckStatus::Rejected(ContextUpdateRejection::Invalid { .. })
        ));
        channel.apply(snapshot(2, json!({})));
        assert!(matches!(
            channel.apply(delta(2, 3, json!([1]))).status,
            ContextAckStatus::Rejected(ContextUpdateRejection::Invalid { .. })
        ));
    }

    #[test]
    fn the_host_validator_can_refuse_a_revision() {
        struct NeedsLimit;
        impl PolicyValidator for NeedsLimit {
            fn validate(&self, revision: &ContextRevision) -> Result<(), String> {
                if revision.content.contains("limit") {
                    Ok(())
                } else {
                    Err("limit is required".into())
                }
            }
        }
        let channel = PolicyChannel::new().with_validator(Arc::new(NeedsLimit));
        channel.apply(snapshot(1, json!({"limit": 1})));
        let ack = channel.apply(delta(1, 2, json!({"limit": null})));
        assert_eq!(
            ack.status,
            ContextAckStatus::Rejected(ContextUpdateRejection::Invalid {
                detail: "limit is required".into()
            })
        );
        assert_eq!(ack.effective_version, Some(1));
    }

    #[test]
    fn clones_share_what_is_in_force() {
        let channel = PolicyChannel::new();
        let other = channel.clone();
        channel.apply(snapshot(1, json!(null)));
        assert_eq!(other.effective().unwrap().version, 1);
    }

    #[test]
    fn merge_patch_follows_rfc_7386() {
        // RFC 7386 appendix A, a representative subset.
        let cases = [
            (json!({"a": "b"}), json!({"a": "c"}), json!({"a": "c"})),
            (
                json!({"a": "b"}),
                json!({"b": "c"}),
                json!({"a": "b", "b": "c"}),
            ),
            (json!({"a": "b"}), json!({"a": null}), json!({})),
            (
                json!({"a": [{"b": "c"}]}),
                json!({"a": [1]}),
                json!({"a": [1]}),
            ),
            (json!(["a", "b"]), json!({"a": "c"}), json!({"a": "c"})),
            (
                json!({"e": null}),
                json!({"a": 1}),
                json!({"e": null, "a": 1}),
            ),
            (
                json!({}),
                json!({"a": {"bb": {"ccc": null}}}),
                json!({"a": {"bb": {}}}),
            ),
        ];
        for (mut target, patch, expected) in cases {
            merge_patch(&mut target, &patch);
            assert_eq!(target, expected);
        }
    }
}
