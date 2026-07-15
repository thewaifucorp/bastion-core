//! Secret-by-reference primitives — C3 cloud-ready contract, security point 1
//! (`docs/revamp/C3-cloud-ready-design.md`): config and manifests carry a
//! [`SecretRef`] (the secret's NAME), never a value. The actual material is
//! resolved exactly once — at boot, or at extension-activation time — by
//! whatever [`SecretResolver`] the deployment injects (an env var, a mounted
//! file, a hosted operator's secret manager, ...). This crate defines the
//! contract only; every concrete resolver is product/host code
//! (`src/secret.rs` in the `bastion` app crate) — the kernel never learns
//! *where* a secret lives, exactly like [`AuthResolver`] never learns *how* a
//! host CLI authenticates (`crates/bastion-runtime/src/agent/ports.rs`).
//!
//! This is deliberately the SAME shape as
//! `bastion_extension_protocol::manifest::SecretRef` (also a bare name, never
//! a value) — that type stays independent because it's part of a versioned,
//! serialized wire artifact (`ExtensionManifest`), while this one is the
//! general-purpose primitive for daemon/app-level operational config
//! (`bastion.toml`, env-sourced tokens, ...). Both obey the identical rule;
//! [`SecretResolver::resolve`] takes a plain `&str` name so ONE resolver
//! implementation can serve both call sites without coupling the two crates.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A named reference to a secret. Never holds the secret's value — safe to
/// embed in config structs, log fields, `tracing` spans, and `.af` exports;
/// `Display`/`Debug`/`Serialize` only ever expose the reference name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef(pub String);

impl SecretRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret-ref:{}", self.0)
    }
}

impl From<&str> for SecretRef {
    fn from(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl From<String> for SecretRef {
    fn from(name: String) -> Self {
        Self(name)
    }
}

/// Resolved secret material. Intentionally NOT `Serialize`/`Deserialize` —
/// it structurally cannot be round-tripped into a config dump, a `.af`
/// export, or any other serialized artifact. `Debug` and `Display` always
/// redact; [`Self::expose_secret`] is the one sanctioned escape hatch.
///
/// Callers must consume the exposed `&str` immediately at the point of use
/// (build an HMAC key, an `Authorization` header, ...) and must never log
/// it, store it beyond that point, or pass it into an error/export path.
#[derive(Clone)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicit, grep-able access to the raw secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Injectable secret resolution: env var, mounted file, a hosted operator's
/// secret manager, ... Implemented at the product/host level (the kernel and
/// this contracts crate only define the trait) — same division of labor as
/// `AuthResolver`/`AuthProfileRegistry`.
///
/// Resolution happens once at boot (or once per extension activation), never
/// per-turn on a hot path — a blocking implementation (reading a mounted
/// file, one synchronous HTTP call to a secret manager) is an acceptable
/// trade-off and keeps this trait (and `bastion-types` itself) free of an
/// async-runtime dependency.
pub trait SecretResolver: Send + Sync {
    /// Resolve `name` — a [`SecretRef`]'s or an extension-manifest
    /// `SecretRef`'s name — to its material, or a typed
    /// [`crate::BastionError::SecretNotFound`]. The error variant carries
    /// only `name`, never a partial or attempted value.
    fn resolve(&self, name: &str) -> Result<SecretValue, crate::BastionError>;
}

/// Always-fails resolver — the fail-closed default until a real one is
/// injected. Byte-identical in spirit to `NullAuthResolver`/
/// `NullApprovalGate`: never silently treats an unconfigured secret as
/// present or empty.
pub struct NullSecretResolver;

impl SecretResolver for NullSecretResolver {
    fn resolve(&self, name: &str) -> Result<SecretValue, crate::BastionError> {
        Err(crate::BastionError::SecretNotFound {
            name: name.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_debug_never_contains_raw_bytes() {
        let v = SecretValue::new("s3cr3t-payload-xyz");
        let debug = format!("{v:?}");
        assert!(!debug.contains("s3cr3t-payload-xyz"));
        assert_eq!(debug, "SecretValue(<redacted>)");
    }

    #[test]
    fn secret_value_display_never_contains_raw_bytes() {
        let v = SecretValue::new("another-super-secret-value");
        let shown = format!("{v}");
        assert!(!shown.contains("another-super-secret-value"));
        assert_eq!(shown, "<redacted>");
    }

    #[test]
    fn secret_value_expose_secret_returns_raw_bytes() {
        let v = SecretValue::new("raw-value-42");
        assert_eq!(v.expose_secret(), "raw-value-42");
    }

    #[test]
    fn secret_ref_display_never_needs_a_value_to_exist() {
        let r = SecretRef::new("APP_JWT_SECRET");
        assert_eq!(format!("{r}"), "secret-ref:APP_JWT_SECRET");
    }

    #[test]
    fn secret_ref_serializes_to_name_only() {
        // `SecretRef` is a serde newtype — it serializes transparently as
        // the bare name string, never wrapped in an object with a value
        // field. A round trip through JSON can never carry more than the
        // reference name.
        let r = SecretRef::new("BASTION_INFER_TOKEN");
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#""BASTION_INFER_TOKEN""#);
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn null_secret_resolver_always_fails_closed() {
        let resolver = NullSecretResolver;
        let err = resolver.resolve("ANY_SECRET").unwrap_err();
        match err {
            crate::BastionError::SecretNotFound { name } => assert_eq!(name, "ANY_SECRET"),
            other => panic!("expected SecretNotFound, got {other:?}"),
        }
    }

    #[test]
    fn null_secret_resolver_error_display_never_leaks_a_value() {
        let resolver = NullSecretResolver;
        let err = resolver.resolve("SOME_TOKEN_NAME").unwrap_err();
        let shown = err.to_string();
        assert!(shown.contains("SOME_TOKEN_NAME"));
        // Only the reference name may appear — there is no value to leak by
        // construction (the resolver never had one), but this regression
        // test pins that invariant so a future edit can't accidentally wire
        // an attempted/partial value into the error path.
    }
}
