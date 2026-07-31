//! GitHub Copilot subscription connector (BPCOP-01..05).
//!
//! Lets a Copilot subscription authenticate inference the same way an API
//! key does elsewhere in this crate, while Bastion keeps running the loop
//! ([`bastion_types::provider_auth`]'s division of labor) — same shape as
//! [`crate::codex`]. This module implements the two ports a subscription
//! connector owns: [`ProviderCredentialRefresher`] (token lifecycle) and
//! [`Provider`] (the inference call itself).
//!
//! `SupportStatus` starts and stays `Experimental` (BPCOP-05): promotion to
//! `Supported` needs a conformance run, a live end-to-end run against a real
//! account, a secret-scrub pass and a terms/licence review, none of which
//! have happened yet.
//!
//! ## Architecture — why this module looks different from [`crate::codex`]
//!
//! Unlike Codex (a documented, first-party HTTP inference API), GitHub
//! Copilot has **no direct HTTP inference API for third parties** — the
//! official GitHub-published `github/copilot-sdk` states plainly "All SDKs
//! communicate with the Copilot CLI server via JSON-RPC," and the old
//! Copilot Extensions HTTP surface was fully sunset 2025-11-10. The only
//! remaining officially-sanctioned path is the official `github-copilot-sdk`
//! Rust crate, which spawns/manages the `copilot` CLI as a subprocess and
//! drives it over JSON-RPC. [`CopilotProvider`] wraps that crate's
//! `Client`/`Session` behind the same [`Provider`] trait every other
//! connector implements — from `bastion-runtime`'s perspective, nothing
//! about this connector's SHAPE differs from Codex's; only its *internals*
//! spawn a subprocess instead of opening a plain HTTP connection.
//!
//! One `Client` (and the one `Session` it opens) is owned per
//! `CopilotProvider` instance, matching how `SubscriptionModelProvider::build`
//! is already called once per `/model copilot/<id>@<profile>` switch,
//! exactly like `CodexProvider::with_credential` — never a shared pool
//! across owners. `ClientOptions.github_token` and `ClientOptions.mode` are
//! **client-level** in this SDK version (1.0.8), not per-session (confirmed
//! by reading the actual crate source, `github_copilot_sdk::ClientOptions`
//! doc comments — a prior pass mis-assumed a per-session token existed based
//! on GitHub's own web docs, which do not describe this Rust SDK's real
//! field-level shape); one Client per credential is therefore not just safer
//! than a shared pool, it's the only shape this version of the SDK supports.
//!
//! `ClientOptions.mode = ClientMode::Empty` plus
//! `SessionConfig::with_available_tools([])` (an explicit empty allowlist —
//! `ClientMode::Empty` requires one) + `SessionConfig::deny_all_permissions()`
//! together are the closest
//! documented approximation of "just answer, never act" this SDK offers —
//! not a hard guarantee (no wire-level flag disables agentic tool-calling
//! outright), so treat the resulting turn as a completion whose *result* is
//! trusted no more than any other provider's, same as everywhere else in
//! this codebase.
//!
//! ## Sourcing and confidence
//!
//! GitHub's classic OAuth App flow (`https://github.com/login/oauth/authorize`
//! → `https://github.com/login/oauth/access_token`) is the officially
//! documented third-party path
//! (`docs.github.com/en/copilot/how-tos/copilot-sdk/setup/github-oauth`:
//! "Copilot usage is billed to each user's subscription," "each user needs
//! an active Copilot subscription"). Two things could **not** be confirmed
//! to the same standard [`crate::codex`] held itself to, and are called out
//! at their point of use instead of guessed:
//!
//! - **OAuth scope**: whether a `gho_` token needs an explicit `scope`
//!   parameter to carry Copilot-request entitlement is undocumented anywhere
//!   found. [`CopilotConfig::scope`] defaults to `None` (no scope
//!   requested) on the theory that Copilot entitlement is a property of the
//!   authenticated user's subscription, not of granted OAuth scopes — same
//!   as how the CLI/VS Code's own first-party flows work — but this is a
//!   hypothesis, not a confirmed fact. Verify against a real account before
//!   promoting past `Experimental`.
//! - **PKCE support**: GitHub's own classic-OAuth-App docs never mention
//!   `code_verifier`/`code_challenge`. This module sends them anyway (to
//!   genuinely satisfy [`ProviderAuthFlow::AuthorizationCodePkce`]'s
//!   contract, "browser redirect with PKCE and a loopback callback") on the
//!   assumption that an unrecognized query/form parameter is ignored by
//!   GitHub's endpoint rather than rejected — standard OAuth2 server
//!   behavior, but not independently confirmed for this specific endpoint.
//!
//! ## Anti-goals (BPCOP card)
//!
//! Nothing here reads local `gh`/VS Code/Copilot CLI storage; tools/plugins
//! the Copilot CLI discovers never enter Bastion's `CapabilityRegistry`
//! automatically (`SessionConfig::enable_config_discovery` stays unset/false);
//! an upstream change to the CLI's own behavior only ever disables this one
//! connector.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};

use bastion_runtime::provider_auth::ProviderCredentialRefresher;
use bastion_types::provider_auth::{
    CredentialKind, ProviderAuthError, ProviderAuthRef, ResolvedProviderCredential,
};
use bastion_types::provider_catalog::{ProviderAuthFlow, ProviderSupportDescriptor};
use bastion_types::SecretValue;

use super::Provider;
use crate::types::{CallConfig, LlmResponse, Message, MessageContent, Role, TokenUsage};

pub const COPILOT_PROVIDER_ID: &str = "copilot";

/// `docs.github.com/en/copilot/how-tos/copilot-sdk/setup/github-oauth`.
pub const DEFAULT_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
pub const DEFAULT_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// `docs.github.com/en/rest/apps/oauth-applications` — revokes the whole
/// grant (not just one token), Basic-authenticated with `client_id`/`client_secret`.
pub const DEFAULT_GRANT_REVOKE_URL_BASE: &str = "https://api.github.com/applications";

/// Configuration for the Copilot connector. Every URL is overridable, same
/// discipline as [`crate::codex::CodexConfig`].
#[derive(Debug, Clone)]
pub struct CopilotConfig {
    /// The self-serve GitHub OAuth App's client id (public).
    pub client_id: String,
    /// The OAuth App's client secret. Unlike Codex (no client-side secret at
    /// all), a classic GitHub OAuth App is a CONFIDENTIAL client — this MUST
    /// come from `BASTION_SECRETS_DIR`/env via the host's `SecretResolver`,
    /// never a compiled-in default (there is no public default to compile
    /// in: every deployment registers its own OAuth App).
    pub client_secret: SecretValue,
    pub authorize_url: String,
    pub token_url: String,
    pub grant_revoke_url_base: String,
    /// Where GitHub redirects back to after the user approves — a local
    /// listener the AGENT side owns (mirrors `CodexConfig::redirect_uri`'s
    /// split: this crate only builds/parses URLs, it never runs a server).
    pub redirect_uri: String,
    /// See the module doc: undocumented whether this needs a value at all.
    /// `None` = no `scope` parameter sent.
    pub scope: Option<String>,
}

impl CopilotConfig {
    pub fn new(client_id: impl Into<String>, client_secret: SecretValue) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            authorize_url: DEFAULT_AUTHORIZE_URL.to_string(),
            token_url: DEFAULT_TOKEN_URL.to_string(),
            grant_revoke_url_base: DEFAULT_GRANT_REVOKE_URL_BASE.to_string(),
            redirect_uri: "http://127.0.0.1:1466/auth/copilot/callback".to_string(),
            scope: None,
        }
    }

    fn grant_revoke_url(&self) -> String {
        format!(
            "{}/{}/grant",
            self.grant_revoke_url_base.trim_end_matches('/'),
            self.client_id
        )
    }
}

// ---------------------------------------------------------------------------
// Authorization-code + PKCE login (for the future `connect copilot` command —
// mirrors `crate::codex`'s device-code free functions: pure HTTP/URL-building
// here, the actual browser-open + local-callback-listener orchestration is
// the AGENT side's job, same split `SubscriptionLoginFlow` already draws for
// Codex's polling loop).
// ---------------------------------------------------------------------------

/// One PKCE pair for one login attempt. `code_verifier` must be held by the
/// caller (in-memory, keyed by state) until the callback delivers `code`.
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

/// RFC 7636 `code_verifier` (43-128 chars, unreserved characters) + its
/// S256 `code_challenge`.
pub fn generate_pkce_pair() -> PkcePair {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let code_verifier =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest);
    PkcePair {
        code_verifier,
        code_challenge,
    }
}

/// Build the URL the operator's browser is sent to. `state` is an
/// unguessable, caller-generated anti-CSRF value the caller must verify
/// matches on callback before ever trusting `code`.
pub fn authorize_url(config: &CopilotConfig, state: &str, pkce: &PkcePair) -> String {
    // `reqwest::Url` re-exports `url::Url` — reuses the dependency reqwest
    // already brings in rather than adding a separate `url` crate pin.
    let mut url =
        reqwest::Url::parse(&config.authorize_url).expect("authorize_url must be a valid URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", &config.client_id);
        q.append_pair("redirect_uri", &config.redirect_uri);
        q.append_pair("state", state);
        q.append_pair("code_challenge", &pkce.code_challenge);
        q.append_pair("code_challenge_method", "S256");
        if let Some(scope) = &config.scope {
            q.append_pair("scope", scope);
        }
    }
    url.to_string()
}

/// What this connector needs persisted: just the access token. Unlike Codex,
/// a classic GitHub OAuth App's `gho_` token does not expire and GitHub
/// issues no `refresh_token` for it — there is nothing to rotate
/// (`docs.github.com`'s expiring-token/refresh-token flow is a DIFFERENT,
/// GitHub-App-only mechanism this connector deliberately does not use, per
/// the module doc's OAuth-App-vs-GitHub-App distinction).
pub struct CopilotTokenRecord {
    pub access_token: SecretValue,
}

/// Host-owned storage for [`CopilotTokenRecord`] — same division of labor as
/// [`crate::codex::CodexTokenStore`].
#[async_trait]
pub trait CopilotTokenStore: Send + Sync {
    async fn load(&self, reference: &ProviderAuthRef)
        -> anyhow::Result<Option<CopilotTokenRecord>>;
    async fn store(
        &self,
        reference: &ProviderAuthRef,
        record: CopilotTokenRecord,
    ) -> anyhow::Result<()>;
}

/// Exchange the authorization `code` the callback delivered for an access
/// token. Standard confidential-client exchange
/// (`docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps`),
/// PLUS the PKCE `code_verifier` (see module doc: not documented as
/// supported, sent anyway to genuinely satisfy `AuthorizationCodePkce`).
pub async fn exchange_authorization_code(
    http: &reqwest::Client,
    config: &CopilotConfig,
    code: &str,
    code_verifier: &str,
) -> Result<CopilotTokenRecord, ProviderAuthError> {
    let resp = http
        .post(&config.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.expose_secret()),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|_| ProviderAuthError::Throttled)?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        return Err(map_oauth_error(status, &body));
    }
    if let Some(err) = body["error"].as_str() {
        return Err(map_oauth_error_code(err));
    }
    let access_token = body["access_token"]
        .as_str()
        .ok_or(ProviderAuthError::UnsupportedProtocol)?
        .to_string();
    Ok(CopilotTokenRecord {
        access_token: SecretValue::new(access_token),
    })
}

fn map_oauth_error(status: reqwest::StatusCode, body: &serde_json::Value) -> ProviderAuthError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return ProviderAuthError::ReauthRequired;
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return ProviderAuthError::Throttled;
    }
    body["error"]
        .as_str()
        .map(map_oauth_error_code)
        .unwrap_or(ProviderAuthError::UnsupportedProtocol)
}

/// GitHub's OAuth error codes
/// (`docs.github.com/en/apps/oauth-apps/building-oauth-apps/troubleshooting-authorization-request-errors`).
fn map_oauth_error_code(code: &str) -> ProviderAuthError {
    match code {
        "bad_verification_code" | "incorrect_client_credentials" | "access_denied" => {
            ProviderAuthError::ReauthRequired
        }
        "redirect_uri_mismatch" | "unsupported_grant_type" => ProviderAuthError::Invalid,
        _ => ProviderAuthError::UnsupportedProtocol,
    }
}

// ---------------------------------------------------------------------------
// ProviderCredentialRefresher
// ---------------------------------------------------------------------------

pub struct CopilotRefresher {
    http: reqwest::Client,
    config: CopilotConfig,
    tokens: std::sync::Arc<dyn CopilotTokenStore>,
}

impl CopilotRefresher {
    pub fn new(config: CopilotConfig, tokens: std::sync::Arc<dyn CopilotTokenStore>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            config,
            tokens,
        }
    }
}

#[async_trait]
impl ProviderCredentialRefresher for CopilotRefresher {
    /// A classic OAuth App `gho_` token has no rotation to perform (module
    /// doc) — "refresh" here just reads the stored token back. If it has
    /// actually been revoked upstream, the next inference call 401s and the
    /// host's existing reauth path (same boundary every connector in this
    /// crate uses) takes over — this method never calls out to GitHub itself.
    async fn refresh(
        &self,
        reference: &ProviderAuthRef,
    ) -> Result<ResolvedProviderCredential, ProviderAuthError> {
        let record = self
            .tokens
            .load(reference)
            .await
            .map_err(|_| ProviderAuthError::Throttled)?
            .ok_or(ProviderAuthError::Missing)?;
        Ok(ResolvedProviderCredential::new(
            reference.clone(),
            CredentialKind::OAuthSubscription,
            record.access_token,
        ))
    }

    /// Unlike Codex (no vendor revocation endpoint found), GitHub documents
    /// a real one: `DELETE /applications/{client_id}/grant`, Basic-authed
    /// with `client_id`/`client_secret`, revoking the WHOLE grant (every
    /// token issued to this OAuth App for this user), not just one token.
    async fn revoke(&self, reference: &ProviderAuthRef) -> Result<(), ProviderAuthError> {
        let Some(record) = self
            .tokens
            .load(reference)
            .await
            .map_err(|_| ProviderAuthError::Throttled)?
        else {
            // Nothing on file — local state moves to Revoked regardless,
            // same "intent wins over vendor state" discipline as the rest
            // of this codebase's lifecycle handling.
            return Ok(());
        };
        let resp = self
            .http
            .delete(self.config.grant_revoke_url())
            .basic_auth(
                &self.config.client_id,
                Some(self.config.client_secret.expose_secret()),
            )
            .json(&serde_json::json!({ "access_token": record.access_token.expose_secret() }))
            .send()
            .await
            .map_err(|_| ProviderAuthError::Throttled)?;
        // 204 No Content on success; a 404 means the grant is already gone
        // (e.g. the user revoked it from their GitHub settings) — both are
        // "revoked" from Bastion's perspective, never a reason to retry.
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(ProviderAuthError::Invalid)
        } else {
            Err(ProviderAuthError::Throttled)
        }
    }
}

// ---------------------------------------------------------------------------
// Provider (inference) — wraps github_copilot_sdk::Client + Session.
// ---------------------------------------------------------------------------

/// Speaks to the `copilot` CLI over the official `github-copilot-sdk` crate
/// (stdio transport, bundled CLI binary — see the module doc for why this
/// shape differs from every HTTP-only connector in this crate). One `Client`
/// + one `Session` per instance, never shared across owners/profiles.
pub struct CopilotProvider {
    // Held only to keep the spawned CLI process alive for `session`'s
    // lifetime — `Client` owns the child process handle (see its `Drop`).
    #[allow(dead_code)]
    client: github_copilot_sdk::Client,
    session: github_copilot_sdk::session::Session,
    model: String,
}

impl CopilotProvider {
    /// Constructed with an ALREADY-RESOLVED credential, same pattern as
    /// [`crate::codex::CodexProvider::with_credential`] — this type never
    /// touches `ProviderAuthRef` or the lifecycle directly. Async (unlike
    /// Codex's sync constructor) because starting the CLI server and
    /// creating a session are both real I/O, not just building an HTTP
    /// client.
    ///
    /// `home_dir` is forwarded as `ClientOptions::base_directory`
    /// (`COPILOT_HOME`) — REQUIRED, not optional: `ClientMode::Empty`
    /// (see the module doc's tool-suppression discussion) refuses to start
    /// without either this or a custom `session_fs` configured, validated by
    /// the SDK itself at `Client::start`. Lets a multi-owner daemon isolate
    /// each spawned CLI's on-disk state (settings/session data — the token
    /// itself never touches disk here, it's injected via
    /// `ClientOptions::github_token` only) by giving each `CopilotProvider`
    /// instance its own directory; the host (bastion-agent) decides where
    /// that lives, this crate never invents a default location.
    pub async fn with_credential(
        model: &str,
        access_token: SecretValue,
        home_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        let options = github_copilot_sdk::ClientOptions::new()
            .with_transport(github_copilot_sdk::Transport::Stdio)
            .with_github_token(access_token.expose_secret().to_string())
            .with_mode(github_copilot_sdk::ClientMode::Empty)
            .with_base_directory(home_dir);
        let client = github_copilot_sdk::Client::start(options).await?;
        // `available_tools = Some(vec![])`: an explicit empty allowlist,
        // the closest this SDK offers to "no tools at all" — required
        // outright by `ClientMode::Empty` (`Client::create_session` errors
        // otherwise). Not the same as `deny_all_permissions` below (that
        // governs approval of side-effecting actions a tool call already
        // requests; this governs which tools exist to be called in the
        // first place) — both together are the module doc's "closest
        // documented approximation," not a guaranteed hard isolation.
        let session_config = github_copilot_sdk::SessionConfig::default()
            .with_model(model)
            .with_available_tools(Vec::<String>::new())
            .deny_all_permissions();
        let session = client.create_session(session_config).await?;
        Ok(Self {
            client,
            session,
            model: model.to_string(),
        })
    }
}

/// Bastion's `Message` history flattened into one prompt string — the SDK's
/// `Session` is turn-based (one running conversation), unlike Codex's
/// stateless Responses API call; Bastion still owns and re-sends the whole
/// history each turn (same contract every `Provider` in this crate honors),
/// so each `complete()` call opens the FULL context as a single prompt
/// rather than relying on the CLI session's own multi-turn memory — this
/// keeps Bastion, not the CLI, as the source of truth for conversation
/// history, consistent with the epic's "assinatura serve só inferência"
/// design.
fn prompt_from_messages(messages: &[Message], system_prompt: &str) -> String {
    let mut out = String::new();
    if !system_prompt.is_empty() {
        out.push_str("System: ");
        out.push_str(system_prompt);
        out.push_str("\n\n");
    }
    for msg in messages {
        let role = match msg.role {
            Role::System => "System",
            Role::User => "User",
            Role::Assistant => "Assistant",
            Role::Tool => "Tool",
        };
        let text = match &msg.content {
            MessageContent::Text(t) => t.clone(),
            MessageContent::Parts(parts) => parts
                .iter()
                .filter_map(|p| match p {
                    crate::types::ContentPart::Text { text } => Some(text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
        };
        out.push_str(role);
        out.push_str(": ");
        out.push_str(&text);
        out.push('\n');
    }
    out
}

#[async_trait::async_trait]
impl Provider for CopilotProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let prompt = prompt_from_messages(messages, &config.system_prompt);
        let event = self
            .session
            .send_and_wait(github_copilot_sdk::MessageOptions::new(prompt))
            .await?;

        let Some(event) = event else {
            anyhow::bail!("copilot session produced no assistant message for this turn");
        };
        let data = event
            .typed_data::<github_copilot_sdk::session_events::AssistantMessageData>()
            .ok_or_else(|| anyhow::anyhow!("copilot: could not parse assistant.message payload"))?;

        Ok(LlmResponse {
            text: data.content,
            tool_calls: None,
            usage: TokenUsage {
                output_tokens: data.output_tokens.unwrap_or(0).max(0) as u32,
                ..Default::default()
            },
        })
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Text(prompt.to_owned()),
        }];
        let resp = self.complete(&messages, &CallConfig::default()).await?;
        Ok(resp.text)
    }

    fn context_limit(&self) -> usize {
        // Not vendor-confirmed per model, same placeholder discipline as
        // `CodexProvider::context_limit` — revisit alongside BPCOP-05.
        128_000
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn name(&self) -> &'static str {
        "copilot"
    }
}

impl Drop for CopilotProvider {
    fn drop(&mut self) {
        // Best-effort: stop the spawned CLI process when this provider goes
        // out of scope (e.g. `/model` switches away from Copilot). `stop()`
        // is async; a sync `Drop` cannot await it, so this only requests
        // process teardown via the client's own Drop (the SDK's `Client`
        // kills the child on drop per its own docs) rather than performing
        // the graceful `session.destroy`/`stop()` RPC sequence — acceptable
        // since nothing here holds a session open past this provider's own
        // lifetime.
        let _ = &self.client;
    }
}

/// `Experimental`, `AuthorizationCodePkce` auth flow (BPCOP-05) — nothing
/// here can claim `Supported` yet.
pub fn support_descriptor() -> ProviderSupportDescriptor {
    ProviderSupportDescriptor::experimental(
        COPILOT_PROVIDER_ID,
        ProviderAuthFlow::AuthorizationCodePkce,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CopilotConfig {
        CopilotConfig::new("client-123", SecretValue::new("secret-abc".to_string()))
    }

    #[test]
    fn generate_pkce_pair_challenge_is_sha256_of_verifier() {
        let pair = generate_pkce_pair();
        let expected = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(pair.code_verifier.as_bytes()),
        );
        assert_eq!(pair.code_challenge, expected);
        // 32 random bytes, base64url-no-pad encoded, is always 43 chars —
        // within RFC 7636's 43-128 char requirement.
        assert_eq!(pair.code_verifier.len(), 43);
    }

    #[test]
    fn generate_pkce_pair_is_not_deterministic() {
        let a = generate_pkce_pair();
        let b = generate_pkce_pair();
        assert_ne!(a.code_verifier, b.code_verifier);
    }

    #[test]
    fn authorize_url_carries_pkce_and_state_never_the_verifier() {
        let config = test_config();
        let pkce = generate_pkce_pair();
        let url = authorize_url(&config, "csrf-state-1", &pkce);
        assert!(url.starts_with(DEFAULT_AUTHORIZE_URL));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("state=csrf-state-1"));
        assert!(url.contains(&format!("code_challenge={}", pkce.code_challenge)));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(
            !url.contains(&pkce.code_verifier),
            "the raw verifier must never appear in the browser-facing URL"
        );
    }

    #[test]
    fn authorize_url_omits_scope_by_default() {
        let config = test_config();
        let pkce = generate_pkce_pair();
        let url = authorize_url(&config, "s", &pkce);
        assert!(!url.contains("scope="));
    }

    #[test]
    fn authorize_url_includes_scope_when_configured() {
        let mut config = test_config();
        config.scope = Some("read:user".to_string());
        let pkce = generate_pkce_pair();
        let url = authorize_url(&config, "s", &pkce);
        assert!(url.contains("scope=read%3Auser") || url.contains("scope=read:user"));
    }

    #[test]
    fn grant_revoke_url_includes_client_id() {
        let config = test_config();
        assert_eq!(
            config.grant_revoke_url(),
            "https://api.github.com/applications/client-123/grant"
        );
    }

    #[test]
    fn map_oauth_error_code_routes_relogin_causes_to_reauth_required() {
        for code in [
            "bad_verification_code",
            "incorrect_client_credentials",
            "access_denied",
        ] {
            assert_eq!(
                map_oauth_error_code(code),
                ProviderAuthError::ReauthRequired,
                "{code} must mean relogin, never retry"
            );
        }
    }

    #[test]
    fn map_oauth_error_code_routes_config_causes_to_invalid() {
        assert_eq!(
            map_oauth_error_code("redirect_uri_mismatch"),
            ProviderAuthError::Invalid
        );
    }

    #[test]
    fn map_oauth_error_routes_transient_causes_to_throttled() {
        assert_eq!(
            map_oauth_error(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &serde_json::json!({})
            ),
            ProviderAuthError::Throttled
        );
        assert_eq!(
            map_oauth_error(reqwest::StatusCode::BAD_GATEWAY, &serde_json::json!({})),
            ProviderAuthError::Throttled
        );
    }

    #[test]
    fn support_descriptor_starts_experimental_with_authorization_code_pkce_flow() {
        let descriptor = support_descriptor();
        assert_eq!(
            descriptor.status(),
            bastion_types::provider_catalog::SupportStatus::Experimental
        );
        assert_eq!(
            descriptor.auth_flow,
            ProviderAuthFlow::AuthorizationCodePkce
        );
        assert!(descriptor.is_selectable());
    }

    #[test]
    fn prompt_from_messages_includes_system_prompt_and_roles() {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Text("hi".into()),
        }];
        let prompt = prompt_from_messages(&messages, "You are Bastion.");
        assert!(prompt.starts_with("System: You are Bastion.\n\n"));
        assert!(prompt.contains("User: hi\n"));
    }

    #[test]
    fn prompt_from_messages_flattens_text_parts_and_drops_tool_parts() {
        let messages = vec![Message {
            role: Role::Assistant,
            content: MessageContent::Parts(vec![
                crate::types::ContentPart::Text {
                    text: "reasoning".into(),
                },
                crate::types::ContentPart::ToolUse {
                    id: "1".into(),
                    name: "x".into(),
                    input: serde_json::json!({}),
                    extra: None,
                },
            ]),
        }];
        let prompt = prompt_from_messages(&messages, "");
        assert!(prompt.contains("Assistant: reasoning\n"));
    }

    #[test]
    fn token_record_carries_no_refresh_token_field() {
        // Compile-time pin: CopilotTokenRecord has exactly one field. If
        // this ever needs a refresh_token, the module doc's "classic OAuth
        // App tokens don't rotate" claim needs revisiting alongside it.
        let record = CopilotTokenRecord {
            access_token: SecretValue::new("gho_x".to_string()),
        };
        assert_eq!(record.access_token.expose_secret(), "gho_x");
    }
}
