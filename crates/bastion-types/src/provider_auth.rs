//! Provider authentication contracts — separating WHO authenticates a model
//! call from WHAT executes the turn (subscription-backed model providers,
//! BPAUTH-01..05).
//!
//! The native path historically assumed one shape of credential: an API key
//! read from the environment by the provider constructor itself. Anything
//! else — a subscription the user logged into — was reachable only by
//! delegating the whole turn to an external agent runtime, which also handed
//! that runtime the loop, the session and the tool decisions.
//!
//! Those are two independent questions, and this module exists to keep them
//! independent:
//!
//! - **Authentication**: which credential proves this owner may call this
//!   provider. That is what the types below describe.
//! - **Execution**: who owns the loop, the session, the tool gate and the
//!   memory for the turn. Unchanged by anything here.
//!
//! A subscription can therefore authenticate inference while Bastion keeps
//! executing the turn. Nothing in this module selects, constructs or invokes
//! an `AgentRuntime` (BPAUTH-04) — it has no dependency that would let it.
//!
//! ## What lives here, and what deliberately does not
//!
//! This crate defines the CONTRACT only, exactly like [`crate::secret`]:
//! [`ProviderAuthResolver`] is a port, and every concrete resolver (env var,
//! keyring, OS credential store, a host's secret manager, an OAuth flow) is
//! product/host composition. The kernel never learns where a credential
//! lives, and this module never learns how a provider speaks HTTP.
//!
//! Storage is likewise absent. A [`ProviderAuthRef`] is three opaque
//! identifiers; where the material behind it is persisted, and by whom, is a
//! host decision (BPAUTH-03: an API key keeps being resolved by host
//! composition, with no change to the inference contract).
//!
//! ## Secret discipline
//!
//! [`ResolvedProviderCredential`] is the only type here that touches secret
//! material, and it is built so the material cannot leak structurally rather
//! than by reviewer vigilance: no `Debug`, no `Display`, no `Serialize`, no
//! `Deserialize`, and the inner value is a [`crate::SecretValue`], which
//! redacts even if someone adds a `Debug` derive above it later. Every other
//! type here — refs, states, errors — carries identifiers and reasons only,
//! so they are safe in a log line, a status response, a config dump or an
//! `.af` export (BPAUTH-02).
//!
//! Error messages are sanitized by construction: [`ProviderAuthError`] has no
//! variant that can carry a provider's raw response body or a token, so a
//! failure cannot smuggle credential material into a message the way a
//! stringly-typed error would (BPAUTH-05).

use serde::{Deserialize, Serialize};

use crate::SecretValue;

/// Which shape of credential authenticates a provider call.
///
/// This is deliberately NOT "which provider" and NOT "which protocol": both
/// variants are reachable for the same provider (an operator may hold an
/// Anthropic API key on one profile and a subscription on another), and the
/// executing side never branches on this — it receives an already-resolved
/// credential either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialKind {
    /// A long-lived key the host resolves from its own configuration. Never
    /// refreshed, never expires on its own, revoked by the operator removing
    /// it.
    #[serde(rename = "api_key")]
    ApiKey,
    /// A subscription login: short-lived material that expires, refreshes,
    /// can be revoked upstream, and can be throttled independently of the
    /// account's own quota.
    /// Spelled out rather than left to `rename_all = "snake_case"`, which
    /// would emit `o_auth_subscription` for this variant name.
    #[serde(rename = "oauth_subscription")]
    OAuthSubscription,
}

/// Identifies exactly one credential without containing it (BPAUTH-01).
///
/// All three fields are opaque identifiers chosen by the host. `profile_id`
/// is scoped WITHIN `owner_id`: two owners may use the same `profile_id`
/// string and must resolve to different credentials, so a resolver keyed on
/// `profile_id` alone is wrong by construction.
///
/// Safe to log, serialize and export: there is nothing here to redact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderAuthRef {
    /// The canonical owner this credential belongs to — the same identity the
    /// rest of the kernel scopes by.
    pub owner_id: String,
    /// Which provider the credential authenticates against (`"anthropic"`,
    /// `"openai"`, …). A plain string, not an enum: a host may register a
    /// provider this crate has never heard of.
    pub provider_id: String,
    /// Which of that owner's credentials for that provider. Lets one owner
    /// hold several (work and personal, two subscriptions, a key plus a
    /// subscription) without them colliding.
    pub profile_id: String,
}

impl ProviderAuthRef {
    pub fn new(
        owner_id: impl Into<String>,
        provider_id: impl Into<String>,
        profile_id: impl Into<String>,
    ) -> Self {
        Self {
            owner_id: owner_id.into(),
            provider_id: provider_id.into(),
            profile_id: profile_id.into(),
        }
    }
}

/// Where a credential currently stands, as a state a host can persist and
/// render.
///
/// This is a description, not a schedule: nothing here decides WHEN a refresh
/// happens or how long a cooldown lasts. `Cooldown`/`ReauthRequired` carry a
/// [`ProviderAuthError`] as their reason precisely so the vocabulary stays
/// closed — a state can never explain itself with a raw upstream message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderAuthState {
    /// Usable right now.
    Ready,
    /// A refresh is in flight. Distinct from `Ready` so a caller can tell
    /// "usable" from "about to be usable", and distinct from `Cooldown` so a
    /// concurrent caller waits instead of starting a second refresh.
    Refreshing,
    /// Temporarily unusable, and retrying before `until` is pointless.
    /// `until` is nanoseconds since the Unix epoch, the same convention the
    /// rest of the kernel's timestamps use.
    Cooldown {
        until: i64,
        reason: ProviderAuthError,
    },
    /// Unusable until a human logs in again. Terminal without operator
    /// action: no backoff will fix it, which is exactly what separates it
    /// from `Cooldown`.
    ReauthRequired { reason: ProviderAuthError },
    /// Withdrawn — by the operator here, or upstream. Never transitions back
    /// to `Ready`: a new credential is a new [`ProviderAuthRef`].
    Revoked,
}

impl ProviderAuthState {
    /// Whether a call may be attempted with this credential right now.
    ///
    /// `Refreshing` answers `false`: the material in hand is the stale one,
    /// and attempting with it is what produces a spurious 401.
    pub fn is_usable(&self) -> bool {
        matches!(self, ProviderAuthState::Ready)
    }

    /// Whether only a human can move this state forward.
    pub fn needs_human(&self) -> bool {
        matches!(
            self,
            ProviderAuthState::ReauthRequired { .. } | ProviderAuthState::Revoked
        )
    }
}

/// Every way authenticating a provider can fail, as a closed vocabulary
/// (BPAUTH-05).
///
/// Deliberately carries NO free-form detail field. A host mapping an upstream
/// failure into this enum has to make a judgment ("this 401 means the token
/// expired") and loses the raw body — that loss is the point: the message can
/// then never contain a token, a cookie, or a response fragment. Where richer
/// diagnosis is needed, it belongs in the host's own logs at the point of the
/// call, not threaded through this type into a status response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthError {
    /// No credential exists for this reference.
    #[error("no credential is configured for this reference")]
    Missing,
    /// A credential exists but the provider rejected it as malformed or
    /// unknown — as opposed to expired, which is recoverable by refresh.
    #[error("the credential was rejected as invalid")]
    Invalid,
    /// Past its lifetime; a refresh may recover it.
    #[error("the credential has expired")]
    Expired,
    /// Only a fresh human login recovers it.
    #[error("re-authentication is required")]
    ReauthRequired,
    /// Withdrawn here or upstream. A refresh must not be attempted.
    #[error("the credential has been revoked")]
    Revoked,
    /// Rate-limited or quota-exhausted. Says nothing about the credential's
    /// validity — retrying later is the correct response.
    #[error("the provider is throttling this credential")]
    Throttled,
    /// The provider spoke something this connector does not implement (an
    /// unexpected auth challenge, a protocol version bump). Never a reason to
    /// try another owner's credential or another provider.
    #[error("the provider used an unsupported authentication protocol")]
    UnsupportedProtocol,
}

impl ProviderAuthError {
    /// Whether waiting and retrying the SAME credential can plausibly
    /// succeed. `false` means the failure is terminal until something outside
    /// the retry loop changes.
    ///
    /// Note `Expired` is transient here: expiry is what a refresh exists to
    /// fix. `Invalid` is not — refreshing a credential the provider calls
    /// malformed just spends quota.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ProviderAuthError::Expired | ProviderAuthError::Throttled
        )
    }
}

/// A credential resolved and ready to authenticate one provider call.
///
/// Construction is the only way material enters this type and
/// [`Self::expose_secret`] is the only way it leaves, both grep-able. It
/// implements no `Debug`, `Display`, `Serialize` or `Deserialize` — a struct
/// holding one cannot be serialized into a config dump, an export or an error
/// payload by accident, because the compiler refuses (BPAUTH-02).
///
/// Callers consume the exposed value immediately at the point of use (build
/// an `Authorization` header) and never store it, log it, or place it in an
/// error path.
#[derive(Clone)]
pub struct ResolvedProviderCredential {
    reference: ProviderAuthRef,
    kind: CredentialKind,
    material: SecretValue,
}

impl ResolvedProviderCredential {
    pub fn new(reference: ProviderAuthRef, kind: CredentialKind, material: SecretValue) -> Self {
        Self {
            reference,
            kind,
            material,
        }
    }

    /// Which credential this is — safe to log, and the only identity a
    /// consumer needs for correlation.
    pub fn reference(&self) -> &ProviderAuthRef {
        &self.reference
    }

    /// API key or subscription. Available so a connector can adjust the
    /// header it builds, never so the executing side can choose a different
    /// execution path.
    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// Explicit, grep-able access to the raw material — the one sanctioned
    /// escape hatch, same contract as [`crate::SecretValue::expose_secret`].
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.material.expose_secret()
    }
}

/// Resolve a [`ProviderAuthRef`] to usable material (BPAUTH-03/04).
///
/// The port a provider constructor takes INSTEAD of reading the environment
/// itself. Implementations live in host/product code: env var, mounted file,
/// keyring, an OAuth connector's token store. This crate ships none.
///
/// Two rules the port shape enforces rather than documents:
///
/// - it returns a credential, never a provider or a runtime — an
///   implementation has nothing here to construct or select an
///   `AgentRuntime` with (BPAUTH-04);
/// - failures are [`ProviderAuthError`] values, so a resolver cannot invent
///   an error string carrying an upstream payload (BPAUTH-05).
///
/// Synchronous for the same reason [`crate::SecretResolver`] is: resolution
/// happens when a provider is built or when a credential is refreshed, not
/// per token on a hot path, so a blocking implementation is an acceptable
/// trade-off and keeps this crate free of an async-runtime dependency.
pub trait ProviderAuthResolver: Send + Sync {
    fn resolve(
        &self,
        reference: &ProviderAuthRef,
    ) -> Result<ResolvedProviderCredential, ProviderAuthError>;
}

/// Always-fails resolver — the fail-closed default until a real one is
/// injected, mirroring [`crate::NullSecretResolver`]. Never treats an
/// unconfigured credential as present or empty.
pub struct NullProviderAuthResolver;

impl ProviderAuthResolver for NullProviderAuthResolver {
    fn resolve(
        &self,
        _reference: &ProviderAuthRef,
    ) -> Result<ResolvedProviderCredential, ProviderAuthError> {
        Err(ProviderAuthError::Missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A resolver keyed the way a correct implementation must be: by the
    /// WHOLE reference, never by `profile_id` alone.
    struct MapResolver {
        entries: HashMap<ProviderAuthRef, String>,
    }

    impl ProviderAuthResolver for MapResolver {
        fn resolve(
            &self,
            reference: &ProviderAuthRef,
        ) -> Result<ResolvedProviderCredential, ProviderAuthError> {
            self.entries
                .get(reference)
                .map(|material| {
                    ResolvedProviderCredential::new(
                        reference.clone(),
                        CredentialKind::OAuthSubscription,
                        SecretValue::new(material.clone()),
                    )
                })
                .ok_or(ProviderAuthError::Missing)
        }
    }

    /// BPAUTH-01: the same `profile_id` under two owners is two credentials.
    /// A resolver that collided them would hand one owner the other's token.
    #[test]
    fn the_same_profile_id_under_two_owners_resolves_distinctly() {
        let alice = ProviderAuthRef::new("alice", "anthropic", "default");
        let mallory = ProviderAuthRef::new("mallory", "anthropic", "default");
        assert_ne!(alice, mallory);

        let mut entries = HashMap::new();
        entries.insert(alice.clone(), "alice-material".to_string());
        entries.insert(mallory.clone(), "mallory-material".to_string());
        let resolver = MapResolver { entries };

        assert_eq!(
            resolver.resolve(&alice).unwrap().expose_secret(),
            "alice-material"
        );
        assert_eq!(
            resolver.resolve(&mallory).unwrap().expose_secret(),
            "mallory-material"
        );
    }

    #[test]
    fn an_unknown_reference_is_missing_not_a_silent_empty_credential() {
        let resolver = MapResolver {
            entries: HashMap::new(),
        };
        let err = resolver
            .resolve(&ProviderAuthRef::new("alice", "anthropic", "default"))
            .expect_err("an absent credential must fail");
        assert_eq!(err, ProviderAuthError::Missing);
    }

    #[test]
    fn the_null_resolver_fails_closed() {
        let err = NullProviderAuthResolver
            .resolve(&ProviderAuthRef::new("alice", "openai", "default"))
            .expect_err("the fail-closed default must never resolve");
        assert_eq!(err, ProviderAuthError::Missing);
    }

    /// BPAUTH-02, the part a type system can enforce: the reference is safe
    /// to log and the material is not reachable through any formatting or
    /// serialization path — only through `expose_secret`.
    #[test]
    fn a_reference_is_loggable_and_carries_no_material() {
        let reference = ProviderAuthRef::new("alice", "anthropic", "work");
        let debug = format!("{reference:?}");
        assert!(debug.contains("alice") && debug.contains("work"));

        let json = serde_json::to_string(&reference).unwrap();
        assert!(json.contains("\"owner_id\":\"alice\""));

        // The credential wrapping it exposes the same reference for
        // correlation, while the material needs the explicit accessor.
        let credential = ResolvedProviderCredential::new(
            reference.clone(),
            CredentialKind::ApiKey,
            SecretValue::new("CANARY-do-not-leak"),
        );
        assert_eq!(credential.reference(), &reference);
        assert_eq!(credential.kind(), CredentialKind::ApiKey);
        assert_eq!(credential.expose_secret(), "CANARY-do-not-leak");
    }

    /// The inner `SecretValue` redacts, so even a future `Debug` derive on a
    /// struct that holds one cannot print the material.
    #[test]
    fn the_inner_secret_value_redacts_in_debug() {
        let material = SecretValue::new("CANARY-do-not-leak");
        assert!(!format!("{material:?}").contains("CANARY"));
        assert!(!format!("{material}").contains("CANARY"));
    }

    /// BPAUTH-05: no variant can carry an upstream payload, so no error
    /// message can leak one. Asserted over EVERY variant rather than a
    /// sample, so adding a variant with a `String` field fails here.
    #[test]
    fn no_error_variant_can_carry_upstream_payload() {
        let all = [
            ProviderAuthError::Missing,
            ProviderAuthError::Invalid,
            ProviderAuthError::Expired,
            ProviderAuthError::ReauthRequired,
            ProviderAuthError::Revoked,
            ProviderAuthError::Throttled,
            ProviderAuthError::UnsupportedProtocol,
        ];
        for err in all {
            let message = err.to_string();
            assert!(!message.is_empty());
            // A payload-carrying variant would need a field; `Copy` on the
            // enum is what structurally prevents a `String` one.
            let _copied = err;
            assert_eq!(_copied, err);
        }
    }

    /// Retry classification is part of the contract, not each host's guess:
    /// expiry and throttling are worth retrying, the rest are not.
    #[test]
    fn transient_classification_separates_refreshable_from_terminal() {
        assert!(ProviderAuthError::Expired.is_transient());
        assert!(ProviderAuthError::Throttled.is_transient());
        for terminal in [
            ProviderAuthError::Missing,
            ProviderAuthError::Invalid,
            ProviderAuthError::ReauthRequired,
            ProviderAuthError::Revoked,
            ProviderAuthError::UnsupportedProtocol,
        ] {
            assert!(!terminal.is_transient(), "{terminal:?} must not be retried");
        }
    }

    #[test]
    fn only_ready_is_usable_and_only_human_states_need_a_human() {
        assert!(ProviderAuthState::Ready.is_usable());
        // Refreshing holds STALE material — attempting with it is what
        // produces the spurious 401 this state exists to avoid.
        assert!(!ProviderAuthState::Refreshing.is_usable());
        assert!(!ProviderAuthState::Revoked.is_usable());

        assert!(!ProviderAuthState::Ready.needs_human());
        assert!(!ProviderAuthState::Cooldown {
            until: 42,
            reason: ProviderAuthError::Throttled,
        }
        .is_usable());
        assert!(!ProviderAuthState::Cooldown {
            until: 42,
            reason: ProviderAuthError::Throttled,
        }
        .needs_human());
        assert!(ProviderAuthState::ReauthRequired {
            reason: ProviderAuthError::Expired,
        }
        .needs_human());
        assert!(ProviderAuthState::Revoked.needs_human());
    }

    /// A persisted state has to round-trip: a host stores it between
    /// processes, and the reason inside it is part of what it renders.
    #[test]
    fn state_round_trips_through_json_with_its_reason() {
        let state = ProviderAuthState::Cooldown {
            until: 1_700_000_000_000_000_000,
            reason: ProviderAuthError::Throttled,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"state\":\"cooldown\""));
        assert!(json.contains("\"reason\":\"throttled\""));
        assert_eq!(
            serde_json::from_str::<ProviderAuthState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn credential_kind_round_trips_snake_case() {
        assert_eq!(
            serde_json::to_string(&CredentialKind::OAuthSubscription).unwrap(),
            "\"oauth_subscription\""
        );
        assert_eq!(
            serde_json::from_str::<CredentialKind>("\"api_key\"").unwrap(),
            CredentialKind::ApiKey
        );
    }
}
