//! Provider catalog, usage and support descriptors (BPCONF-01..05).
//!
//! Vendors expose models, capabilities and limits in different shapes and with
//! different levels of honesty. Without a common contract two failures follow,
//! and both have been observed in products that skipped this step:
//!
//! 1. **The UI invents precision.** A missing quota field renders as `0%` or
//!    "unlimited", and a user makes a decision on a number nobody reported.
//!    Every optional field here means exactly one thing when absent —
//!    *unknown* — and this module offers no helper that fabricates a value for
//!    it (BPCONF-02).
//! 2. **A connector looks finished until it isn't.** Text completion works, so
//!    it ships; the failure surfaces later at a tool call, a structured-output
//!    request, or the first 429. So capabilities are declared PER MODEL and
//!    individually (BPCONF-01), and a declaration is a claim that
//!    [`crate::provider_catalog`]'s consumer is expected to verify rather than
//!    trust.
//!
//! ## Selection never substitutes
//!
//! [`ProviderCatalog::select_model`] returns a typed [`CatalogError`] when the
//! requested model is unknown, its descriptor has expired, or it lacks a
//! required capability. It never quietly picks a different model (BPCONF-03):
//! silently downgrading "the model you asked for" is how a cheaper or weaker
//! model ends up serving a request the caller believed it had chosen.
//!
//! ## Promotion is evidence-gated
//!
//! [`SupportStatus::Supported`] cannot be set by writing it. It is produced
//! only by [`ProviderSupportDescriptor::promote`], which requires every item of
//! [`SupportEvidence`] and reports each missing one (BPCONF-05). A connector
//! therefore starts `Experimental` and stays there until conformance, a live
//! end-to-end run, secret-scrub verification, owner-isolation verification and
//! a terms/licence review have all actually happened.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// How an operator authenticates a provider — the mechanism, recorded so an
/// operator knows what a `connect` will ask of them before it starts.
///
/// A closed enum: adding a variant is a minor bump on this crate, which is the
/// intended friction. A host that needs a mechanism absent here is describing
/// something the product has not reviewed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthFlow {
    /// A long-lived key the operator pastes or mounts. No login, no refresh.
    ApiKey,
    /// The vendor shows a code, the operator approves it on another device.
    /// Works without a browser on the daemon's host, which is why it is the
    /// common shape for a headless deployment.
    DeviceCode,
    /// Browser redirect with PKCE and a loopback callback. Needs a browser on
    /// the same machine, or a forwarded port.
    AuthorizationCodePkce,
    /// An entitlement discovered from an existing session, then exchanged for a
    /// short-lived inference token.
    TokenExchange,
}

/// One capability a model either has or does not, declared individually
/// (BPCONF-01).
///
/// Deliberately NOT a single "supported" boolean: text completion working says
/// nothing about tool calls, and a connector that assumed otherwise is exactly
/// the failure this enum exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    /// Incremental token delivery.
    Streaming,
    /// Tool/function calling.
    Tools,
    /// Schema-constrained output enforced by the vendor, as opposed to a
    /// prompt asking nicely.
    StructuredOutput,
    /// A request can be aborted upstream, not merely dropped locally.
    Cancellation,
    /// The vendor reports token usage for the call.
    Usage,
}

impl ModelCapability {
    pub const ALL: [ModelCapability; 5] = [
        ModelCapability::Streaming,
        ModelCapability::Tools,
        ModelCapability::StructuredOutput,
        ModelCapability::Cancellation,
        ModelCapability::Usage,
    ];
}

/// One model, as observed at a point in time.
///
/// `valid_until` exists because a catalog goes stale: a vendor removes a model,
/// renames it, or changes what it supports. `None` means "no expiry declared",
/// which is honest but weaker — a consumer cannot tell a fresh observation from
/// a two-year-old one without `observed_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderModelDescriptor {
    pub model_id: String,
    /// Exactly what was verified for THIS model. An empty set is legal and
    /// means "text completion only" — never "everything".
    pub capabilities: BTreeSet<ModelCapability>,
    /// When this descriptor was observed, nanoseconds since the Unix epoch.
    pub observed_at: i64,
    /// When it stops being trustworthy. `None` = no expiry declared.
    pub valid_until: Option<i64>,
}

impl ProviderModelDescriptor {
    pub fn new(model_id: impl Into<String>, observed_at: i64) -> Self {
        Self {
            model_id: model_id.into(),
            capabilities: BTreeSet::new(),
            observed_at,
            valid_until: None,
        }
    }

    pub fn with_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = ModelCapability>,
    ) -> Self {
        self.capabilities = capabilities.into_iter().collect();
        self
    }

    pub fn with_valid_until(mut self, valid_until: i64) -> Self {
        self.valid_until = Some(valid_until);
        self
    }

    pub fn supports(&self, capability: ModelCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Whether this observation is still inside its declared validity.
    ///
    /// A descriptor with no `valid_until` is treated as current: refusing it
    /// would make "no expiry declared" indistinguishable from "expired", and
    /// the vendor that publishes no expiry is the common case.
    pub fn is_current_at(&self, now: i64) -> bool {
        match self.valid_until {
            Some(valid_until) => now < valid_until,
            None => true,
        }
    }
}

/// Where a usage number came from, so a surface can say so.
///
/// A number a vendor reported and a number the product counted locally are not
/// interchangeable: the second misses anything spent outside this deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// Reported by the vendor's own API.
    VendorApi,
    /// Counted by this deployment. Blind to usage from other clients.
    LocalAccounting,
}

/// A point-in-time view of consumption (BPCONF-02).
///
/// Every quantity is optional, and absent means *unknown* — never zero, never
/// unlimited. There is deliberately no method here that computes `remaining`
/// from `limit - used`: vendors count differently (requests vs tokens,
/// per-window vs per-billing-period), so that subtraction produces a number
/// nobody published, which is the precise failure this type exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderUsageSnapshot {
    pub provider_id: String,
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u64>,
    /// Human-facing window label the vendor uses ("5h", "daily", "month"),
    /// carried verbatim rather than parsed — normalizing it would invent a
    /// precision the vendor did not state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    /// When the window resets, if the vendor says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<i64>,
    pub source: UsageSource,
    pub observed_at: i64,
}

impl ProviderUsageSnapshot {
    /// An "I asked and learned nothing" snapshot — every quantity unknown.
    ///
    /// Exists so a connector whose vendor publishes no usage endpoint can still
    /// return a well-formed snapshot with provenance and a timestamp, instead of
    /// being tempted to synthesize numbers to fill the shape.
    pub fn unknown(
        provider_id: impl Into<String>,
        profile_id: impl Into<String>,
        source: UsageSource,
        observed_at: i64,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            profile_id: profile_id.into(),
            used: None,
            limit: None,
            remaining: None,
            period: None,
            reset_at: None,
            source,
            observed_at,
        }
    }

    /// Whether this snapshot carries any quantity at all. `false` means a
    /// surface must render "unknown" rather than a progress bar.
    pub fn has_any_quantity(&self) -> bool {
        self.used.is_some() || self.limit.is_some() || self.remaining.is_some()
    }

    /// Whether the snapshot is older than `max_age_nanos` at `now` — the input
    /// to a "stale" label. Reported, never acted on here.
    pub fn is_stale_at(&self, now: i64, max_age_nanos: i64) -> bool {
        now.saturating_sub(self.observed_at) > max_age_nanos
    }
}

/// How much a connector is trusted, and by whose decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    /// Every promotion gate has been met (see [`SupportEvidence`]).
    Supported,
    /// Usable, unverified. Where a connector starts and where it stays until
    /// the evidence exists.
    Experimental,
    /// Turned off — by an operator, or because the vendor changed something.
    /// Affects this connector only.
    Disabled,
}

/// The five things that must be true before a connector may be called
/// `Supported` (BPCONF-05).
///
/// Modeled as data rather than left to a reviewer's memory, so promotion is a
/// checkable function instead of a judgment call, and so a half-verified
/// connector cannot be promoted by editing one field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportEvidence {
    /// The shared conformance suite passed for every declared capability.
    pub conformance_passed: bool,
    /// An opt-in run against a real account passed.
    pub live_e2e_passed: bool,
    /// A canary injected into vendor responses never appeared in logs,
    /// telemetry, errors or exports.
    pub scrub_verified: bool,
    /// Two owners' credentials proved isolated from each other.
    pub isolation_verified: bool,
    /// The vendor's terms/licence position on this use was reviewed by a human.
    pub terms_reviewed: bool,
}

/// A promotion gate that was not met.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum MissingEvidence {
    #[error("the conformance suite has not passed for every declared capability")]
    Conformance,
    #[error("no live end-to-end run has passed")]
    LiveE2e,
    #[error("secret-scrub verification is missing")]
    Scrub,
    #[error("owner-isolation verification is missing")]
    Isolation,
    #[error("the vendor's terms have not been reviewed")]
    Terms,
}

impl SupportEvidence {
    /// Every gate still open, in a stable order.
    pub fn missing(&self) -> Vec<MissingEvidence> {
        let mut missing = Vec::new();
        if !self.conformance_passed {
            missing.push(MissingEvidence::Conformance);
        }
        if !self.live_e2e_passed {
            missing.push(MissingEvidence::LiveE2e);
        }
        if !self.scrub_verified {
            missing.push(MissingEvidence::Scrub);
        }
        if !self.isolation_verified {
            missing.push(MissingEvidence::Isolation);
        }
        if !self.terms_reviewed {
            missing.push(MissingEvidence::Terms);
        }
        missing
    }

    pub fn is_complete(&self) -> bool {
        self.missing().is_empty()
    }
}

/// What is known about a connector as a whole.
///
/// `tested_version`/`tested_at` are what make a stale claim visible: "we
/// verified this against vendor CLI 1.4 in July" ages honestly, while a bare
/// `Supported` does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProviderSupportDescriptorWire")]
pub struct ProviderSupportDescriptor {
    pub provider_id: String,
    pub auth_flow: ProviderAuthFlow,
    status: SupportStatus,
    /// Vendor/protocol version the verification ran against, when there is a
    /// meaningful version to name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tested_version: Option<String>,
    /// When that verification ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tested_at: Option<i64>,
    /// What an operator's account must already have (an active subscription, a
    /// specific plan tier, an organization seat). Free text because it is
    /// operator-facing prose, not a machine decision.
    #[serde(default)]
    pub account_requirements: Vec<String>,
    pub evidence: SupportEvidence,
}

/// Deserialization shape for [`ProviderSupportDescriptor`], existing purely so
/// the promotion gate survives persistence.
///
/// Without it, `status` being a private field would stop code from ASSIGNING
/// `Supported` while a hand-edited (or tampered) JSON/TOML file could still
/// declare it — the gate would hold in Rust and leak everywhere else. The
/// `TryFrom` below re-checks the same rule [`ProviderSupportDescriptor::promote`]
/// enforces, so a descriptor that claims `Supported` without complete evidence
/// and a tested version fails to load instead of being trusted.
#[derive(Deserialize)]
struct ProviderSupportDescriptorWire {
    provider_id: String,
    auth_flow: ProviderAuthFlow,
    status: SupportStatus,
    #[serde(default)]
    tested_version: Option<String>,
    #[serde(default)]
    tested_at: Option<i64>,
    #[serde(default)]
    account_requirements: Vec<String>,
    #[serde(default)]
    evidence: SupportEvidence,
}

impl TryFrom<ProviderSupportDescriptorWire> for ProviderSupportDescriptor {
    type Error = String;

    fn try_from(wire: ProviderSupportDescriptorWire) -> Result<Self, Self::Error> {
        if wire.status == SupportStatus::Supported {
            let missing = wire.evidence.missing();
            if !missing.is_empty() {
                return Err(format!(
                    "provider '{}' claims supported but is missing evidence: {}",
                    wire.provider_id,
                    missing
                        .iter()
                        .map(|m| m.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            if wire.tested_version.is_none() || wire.tested_at.is_none() {
                return Err(format!(
                    "provider '{}' claims supported without a tested version and date",
                    wire.provider_id
                ));
            }
        }
        Ok(Self {
            provider_id: wire.provider_id,
            auth_flow: wire.auth_flow,
            status: wire.status,
            tested_version: wire.tested_version,
            tested_at: wire.tested_at,
            account_requirements: wire.account_requirements,
            evidence: wire.evidence,
        })
    }
}

impl ProviderSupportDescriptor {
    /// A new connector: `Experimental`, no evidence. The only entry point —
    /// there is no constructor that starts `Supported`.
    pub fn experimental(provider_id: impl Into<String>, auth_flow: ProviderAuthFlow) -> Self {
        Self {
            provider_id: provider_id.into(),
            auth_flow,
            status: SupportStatus::Experimental,
            tested_version: None,
            tested_at: None,
            account_requirements: Vec::new(),
            evidence: SupportEvidence::default(),
        }
    }

    pub fn status(&self) -> SupportStatus {
        self.status
    }

    /// Promote to `Supported`, or report every gate still open (BPCONF-05).
    ///
    /// `status` is private and this is the only way to reach `Supported`, so
    /// the gate cannot be bypassed by assigning the field. `tested_version` and
    /// `tested_at` are required too: a promotion that cannot say what it was
    /// tested against is not a promotion.
    pub fn promote(mut self) -> Result<Self, Vec<MissingEvidence>> {
        let missing = self.evidence.missing();
        if !missing.is_empty() {
            return Err(missing);
        }
        if self.tested_at.is_none() || self.tested_version.is_none() {
            return Err(vec![MissingEvidence::Conformance]);
        }
        self.status = SupportStatus::Supported;
        Ok(self)
    }

    /// Turn this connector off. Always allowed, from any state: a vendor
    /// changing something upstream must be answerable immediately, and
    /// disabling one connector never touches another.
    pub fn disable(mut self) -> Self {
        self.status = SupportStatus::Disabled;
        self
    }

    /// Whether a caller may select this connector at all.
    pub fn is_selectable(&self) -> bool {
        !matches!(self.status, SupportStatus::Disabled)
    }
}

/// Why a model selection was refused (BPCONF-03).
///
/// Every variant names what the caller asked for. None of them is recoverable
/// by this module choosing something else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CatalogError {
    #[error("provider '{provider_id}' is disabled")]
    ProviderDisabled { provider_id: String },
    #[error("no model '{model_id}' in this provider's catalog")]
    UnknownModel { model_id: String },
    #[error("the catalog entry for '{model_id}' expired at {valid_until}")]
    ModelExpired { model_id: String, valid_until: i64 },
    #[error("model '{model_id}' does not declare the {capability:?} capability")]
    MissingCapability {
        model_id: String,
        capability: ModelCapability,
    },
}

/// One provider's support descriptor plus the models it offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCatalog {
    pub support: ProviderSupportDescriptor,
    pub models: Vec<ProviderModelDescriptor>,
}

impl ProviderCatalog {
    pub fn new(support: ProviderSupportDescriptor, models: Vec<ProviderModelDescriptor>) -> Self {
        Self { support, models }
    }

    /// The descriptor for `model_id` if it is present, current, and declares
    /// every capability in `required` — otherwise a typed refusal.
    ///
    /// Checks run in a deliberate order so the error is the most actionable
    /// one: disabled provider, then unknown model, then expiry, then
    /// capabilities. A caller told "missing capability" about a model that no
    /// longer exists would chase the wrong problem.
    pub fn select_model(
        &self,
        model_id: &str,
        required: &[ModelCapability],
        now: i64,
    ) -> Result<&ProviderModelDescriptor, CatalogError> {
        if !self.support.is_selectable() {
            return Err(CatalogError::ProviderDisabled {
                provider_id: self.support.provider_id.clone(),
            });
        }
        let model = self
            .models
            .iter()
            .find(|m| m.model_id == model_id)
            .ok_or_else(|| CatalogError::UnknownModel {
                model_id: model_id.to_string(),
            })?;
        if !model.is_current_at(now) {
            return Err(CatalogError::ModelExpired {
                model_id: model.model_id.clone(),
                valid_until: model.valid_until.unwrap_or_default(),
            });
        }
        for capability in required {
            if !model.supports(*capability) {
                return Err(CatalogError::MissingCapability {
                    model_id: model.model_id.clone(),
                    capability: *capability,
                });
            }
        }
        Ok(model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(now: i64) -> ProviderCatalog {
        ProviderCatalog::new(
            ProviderSupportDescriptor::experimental("openai", ProviderAuthFlow::DeviceCode),
            vec![
                ProviderModelDescriptor::new("gpt-5", now)
                    .with_capabilities([ModelCapability::Tools, ModelCapability::Usage]),
                ProviderModelDescriptor::new("gpt-5-mini", now)
                    .with_capabilities([ModelCapability::Tools])
                    .with_valid_until(now + 1_000),
            ],
        )
    }

    /// BPCONF-01: capabilities are per model, so one model having tools says
    /// nothing about another, and text completion implies nothing at all.
    #[test]
    fn capabilities_are_declared_per_model() {
        let catalog = catalog(0);
        let full = catalog
            .select_model("gpt-5", &[ModelCapability::Usage], 0)
            .unwrap();
        assert!(full.supports(ModelCapability::Usage));

        let err = catalog
            .select_model("gpt-5-mini", &[ModelCapability::Usage], 0)
            .unwrap_err();
        assert_eq!(
            err,
            CatalogError::MissingCapability {
                model_id: "gpt-5-mini".into(),
                capability: ModelCapability::Usage,
            }
        );
    }

    /// An empty capability set means text-only, never "everything".
    #[test]
    fn an_empty_capability_set_grants_nothing() {
        let model = ProviderModelDescriptor::new("bare", 0);
        for capability in ModelCapability::ALL {
            assert!(!model.supports(capability), "{capability:?}");
        }
    }

    /// BPCONF-03: a removed model refuses, and never resolves to a neighbor.
    #[test]
    fn an_unknown_model_refuses_without_substituting() {
        let catalog = catalog(0);
        let err = catalog.select_model("gpt-4o", &[], 0).unwrap_err();
        assert_eq!(
            err,
            CatalogError::UnknownModel {
                model_id: "gpt-4o".into()
            }
        );
    }

    #[test]
    fn an_expired_entry_refuses_and_names_its_deadline() {
        let catalog = catalog(0);
        // Inside validity.
        assert!(catalog.select_model("gpt-5-mini", &[], 999).is_ok());
        // Past it.
        let err = catalog.select_model("gpt-5-mini", &[], 1_000).unwrap_err();
        assert_eq!(
            err,
            CatalogError::ModelExpired {
                model_id: "gpt-5-mini".into(),
                valid_until: 1_000,
            }
        );
    }

    /// No declared expiry must not read as expired — a vendor publishing no
    /// expiry is the common case.
    #[test]
    fn a_model_without_an_expiry_stays_current() {
        let model = ProviderModelDescriptor::new("gpt-5", 0);
        assert!(model.is_current_at(i64::MAX));
    }

    /// Disabling is answerable immediately and scoped: the refusal names the
    /// provider, and the check runs before anything model-specific.
    #[test]
    fn a_disabled_provider_refuses_before_looking_at_models() {
        let mut catalog = catalog(0);
        catalog.support = catalog.support.clone().disable();
        let err = catalog.select_model("nonexistent", &[], 0).unwrap_err();
        assert_eq!(
            err,
            CatalogError::ProviderDisabled {
                provider_id: "openai".into()
            },
            "a disabled provider must not be reported as a missing model"
        );
    }

    /// BPCONF-05: `Supported` is unreachable without every gate, and the error
    /// enumerates exactly what is missing rather than saying "not allowed".
    #[test]
    fn promotion_requires_every_piece_of_evidence() {
        let descriptor =
            ProviderSupportDescriptor::experimental("openai", ProviderAuthFlow::DeviceCode);
        assert_eq!(descriptor.status(), SupportStatus::Experimental);

        let missing = descriptor.clone().promote().unwrap_err();
        assert_eq!(
            missing,
            vec![
                MissingEvidence::Conformance,
                MissingEvidence::LiveE2e,
                MissingEvidence::Scrub,
                MissingEvidence::Isolation,
                MissingEvidence::Terms,
            ]
        );

        // Four of five is still Experimental.
        let mut almost = descriptor.clone();
        almost.evidence = SupportEvidence {
            conformance_passed: true,
            live_e2e_passed: true,
            scrub_verified: true,
            isolation_verified: true,
            terms_reviewed: false,
        };
        assert_eq!(almost.promote().unwrap_err(), vec![MissingEvidence::Terms]);
    }

    /// Evidence alone is not enough: a promotion that cannot say what it was
    /// tested against is not a promotion.
    #[test]
    fn promotion_also_requires_a_tested_version_and_date() {
        let mut descriptor =
            ProviderSupportDescriptor::experimental("openai", ProviderAuthFlow::DeviceCode);
        descriptor.evidence = SupportEvidence {
            conformance_passed: true,
            live_e2e_passed: true,
            scrub_verified: true,
            isolation_verified: true,
            terms_reviewed: true,
        };
        assert!(descriptor.clone().promote().is_err());

        descriptor.tested_version = Some("codex-cli 1.4.2".into());
        descriptor.tested_at = Some(1_700_000_000_000_000_000);
        let promoted = descriptor.promote().unwrap();
        assert_eq!(promoted.status(), SupportStatus::Supported);
        assert!(promoted.is_selectable());
    }

    /// Disabling a promoted connector is always allowed — upstream changes do
    /// not wait for a re-verification.
    #[test]
    fn a_supported_connector_can_still_be_disabled() {
        let mut descriptor =
            ProviderSupportDescriptor::experimental("openai", ProviderAuthFlow::ApiKey);
        descriptor.evidence = SupportEvidence {
            conformance_passed: true,
            live_e2e_passed: true,
            scrub_verified: true,
            isolation_verified: true,
            terms_reviewed: true,
        };
        descriptor.tested_version = Some("v1".into());
        descriptor.tested_at = Some(1);
        let disabled = descriptor.promote().unwrap().disable();
        assert_eq!(disabled.status(), SupportStatus::Disabled);
        assert!(!disabled.is_selectable());
    }

    /// BPCONF-02: absent means unknown. The type offers no way to turn that
    /// into a number, and an all-unknown snapshot is still well-formed.
    #[test]
    fn an_unknown_snapshot_carries_provenance_but_no_quantities() {
        let snapshot =
            ProviderUsageSnapshot::unknown("openai", "default", UsageSource::VendorApi, 42);
        assert!(!snapshot.has_any_quantity());
        assert_eq!(snapshot.source, UsageSource::VendorApi);
        assert_eq!(snapshot.observed_at, 42);

        // Serialization omits the unknown fields entirely rather than emitting
        // nulls a client might coerce to 0.
        let json = serde_json::to_value(&snapshot).unwrap();
        let object = json.as_object().unwrap();
        for absent in ["used", "limit", "remaining", "period", "reset_at"] {
            assert!(!object.contains_key(absent), "{absent} must be omitted");
        }
    }

    #[test]
    fn a_partial_snapshot_reports_only_what_it_has() {
        let mut snapshot =
            ProviderUsageSnapshot::unknown("openai", "default", UsageSource::VendorApi, 0);
        snapshot.limit = Some(100);
        assert!(snapshot.has_any_quantity());
        // `remaining` was not reported, so it stays unknown — deriving
        // `limit - used` would publish a number the vendor never gave.
        assert!(snapshot.remaining.is_none());
        assert!(snapshot.used.is_none());
    }

    #[test]
    fn staleness_is_reported_against_an_explicit_budget() {
        let snapshot = ProviderUsageSnapshot::unknown(
            "openai",
            "default",
            UsageSource::LocalAccounting,
            1_000,
        );
        assert!(!snapshot.is_stale_at(1_500, 1_000));
        assert!(snapshot.is_stale_at(2_500, 1_000));
    }

    #[test]
    fn descriptors_round_trip_through_json() {
        let catalog = catalog(7);
        let json = serde_json::to_string(&catalog).unwrap();
        let parsed: ProviderCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, catalog);
        assert_eq!(parsed.support.status(), SupportStatus::Experimental);
    }

    /// The promotion gate has to survive persistence: a private field stops
    /// Rust code from assigning `Supported`, but a hand-edited file would
    /// otherwise walk straight past it.
    #[test]
    fn a_stored_descriptor_claiming_supported_without_evidence_fails_to_load() {
        let json = serde_json::json!({
            "provider_id": "openai",
            "auth_flow": "device_code",
            "status": "supported",
            "evidence": {
                "conformance_passed": true,
                "live_e2e_passed": false,
                "scrub_verified": false,
                "isolation_verified": false,
                "terms_reviewed": false
            }
        });
        let err = serde_json::from_value::<ProviderSupportDescriptor>(json)
            .expect_err("a tampered descriptor must not load as supported");
        let message = err.to_string();
        assert!(message.contains("missing evidence"), "{message}");
        assert!(message.contains("live end-to-end"), "{message}");
    }

    #[test]
    fn a_stored_descriptor_claiming_supported_without_a_version_fails_to_load() {
        let json = serde_json::json!({
            "provider_id": "openai",
            "auth_flow": "api_key",
            "status": "supported",
            "evidence": {
                "conformance_passed": true,
                "live_e2e_passed": true,
                "scrub_verified": true,
                "isolation_verified": true,
                "terms_reviewed": true
            }
        });
        let err = serde_json::from_value::<ProviderSupportDescriptor>(json)
            .expect_err("supported without a tested version must not load");
        assert!(err.to_string().contains("tested version"), "{err}");
    }

    /// A fully-evidenced stored descriptor still loads — the gate refuses the
    /// unearned claim, not persistence itself.
    #[test]
    fn a_fully_evidenced_stored_descriptor_loads_as_supported() {
        let json = serde_json::json!({
            "provider_id": "openai",
            "auth_flow": "device_code",
            "status": "supported",
            "tested_version": "codex-cli 1.4.2",
            "tested_at": 1_700_000_000_000_000_000_i64,
            "evidence": {
                "conformance_passed": true,
                "live_e2e_passed": true,
                "scrub_verified": true,
                "isolation_verified": true,
                "terms_reviewed": true
            }
        });
        let descriptor: ProviderSupportDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(descriptor.status(), SupportStatus::Supported);
    }
}
