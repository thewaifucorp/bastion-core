//! Codex/ChatGPT subscription connector (BPCDX-01..05).
//!
//! Lets a ChatGPT subscription authenticate inference the same way an API key
//! does elsewhere in this crate, while Bastion keeps running the loop
//! ([`bastion_types::provider_auth`]'s division of labor). This module
//! implements the two ports a subscription connector owns:
//! [`bastion_runtime::provider_auth::ProviderCredentialRefresher`] (token
//! exchange) and [`Provider`] (the inference call itself). Everything else —
//! single-flight, backoff, state persistence — comes from
//! [`bastion_runtime::provider_auth::ProviderCredentialLifecycle`] for free.
//!
//! `SupportStatus` starts and stays `Experimental` (BPCDX-05): promotion to
//! `Supported` needs a conformance run, a live end-to-end run against a real
//! account, a secret-scrub pass and a terms/licence review, none of which
//! have happened yet. [`support_descriptor`] returns exactly that.
//!
//! ## Sourcing and confidence
//!
//! None of this is documented by OpenAI in prose — `learn.chatgpt.com/docs/auth`
//! confirms the *shape* of `~/.codex/auth.json` (`access_token`, `id_token`,
//! `refresh_token`, `last_refresh`) and the refresh-on-401 behavior, but not
//! the wire protocol. Every URL and field below is instead read directly out
//! of OpenAI's own **official, Apache-2.0, public** `openai/codex` repository
//! (`codex-rs/login/src/{server.rs,device_code_auth.rs}`), cross-checked
//! against three independent third-party implementations
//! (`github.com/7shi/codex-oauth`, `github.com/numman-ali/opencode-openai-codex-auth`,
//! `github.com/simonw/llm-openai-via-codex`) that agree with it and with each
//! other. That is the strongest sourcing available short of OpenAI publishing
//! a spec, but it is still an unversioned internal surface OpenAI could change
//! without notice — which is exactly why BPCDX-05 gates `Supported`.
//!
//! 2026-08-01 update: the three items below were re-derived directly from
//! `codex-rs/login/src/device_code_auth.rs`'s literal source (quoted
//! verbatim, not summarized) after a live E2E run against the real
//! `auth.openai.com` returned `403` on the endpoint this module used to
//! build. Independently cross-checked against a real, unrelated user's bug
//! report naming the exact same corrected path
//! (`github.com/openai/codex` issue #16079, a proxy/TLS report that quotes
//! `https://auth.openai.com/api/accounts/deviceauth/usercode` verbatim).
//!
//! - **Device endpoints are under `/api/accounts`, not the issuer root.**
//!   `device_code_auth.rs`: `let base_url = opts.issuer.trim_end_matches('/');
//!   let api_base_url = format!("{base_url}/api/accounts");` — the usercode
//!   and token-poll requests both go to `{api_base_url}/deviceauth/{usercode,token}`.
//!   The previous `{issuer}/deviceauth/...` (missing `/api/accounts`) is what
//!   produced the `403`.
//! - [`DeviceAuthorization::verification_uri`]: now confirmed —
//!   `device_code_auth.rs`: `verification_url: format!("{base_url}/codex/device")`
//!   where `base_url` is `opts.issuer` (`https://auth.openai.com`), NOT
//!   `https://chatgpt.com` as previously defaulted.
//! - [`CodexConfig::redirect_uri`]: confirmed for the *browser* PKCE flow
//!   (`http://localhost:{port}/auth/callback`, `codex-rs/login/src/server.rs`),
//!   and now ALSO confirmed for the *headless* device flow this module
//!   actually implements — a separate, real value:
//!   `device_code_auth.rs`: `let redirect_uri = format!("{base_url}/deviceauth/callback");`
//!   (same `base_url` = issuer). The device flow's own exchange
//!   (`exchange_authorization_code`) must use this value, not the
//!   browser-flow's localhost callback it was defaulting to before.
//!
//! A THIRD claim from earlier research — that the API base might be
//! `https://chatgpt.com/backend-api/wham` rather than `.../backend-api/codex`
//! — turned out not to be a real conflict: `.../backend-api/wham/usage` is a
//! real, separate endpoint (rate-limit polling, confirmed via
//! `github.com/openai/codex` issue #10869) that coexists with
//! `.../backend-api/codex/responses` (the inference endpoint this module
//! calls), which `simonw/llm-openai-via-codex`'s actual working source
//! confirms directly. [`DEFAULT_API_BASE`] uses the latter.
//!
//! ## Anti-goals (BPCDX card)
//!
//! Nothing here copies OmniRoute code or licence text, tunnels through an
//! app-server, or imports Codex CLI plugins/memory/task state — this module
//! only ever does two things: exchange a token, and shape one inference
//! request.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use serde_json::{json, Value};

use bastion_runtime::provider_auth::ProviderCredentialRefresher;
use bastion_types::provider_auth::{
    CredentialKind, ProviderAuthError, ProviderAuthRef, ResolvedProviderCredential,
};
use bastion_types::provider_catalog::{ProviderAuthFlow, ProviderSupportDescriptor};
use bastion_types::SecretValue;

use super::Provider;
use crate::types::{CallConfig, LlmResponse, Message, MessageContent, Role, TokenUsage, ToolCall};

pub const CODEX_PROVIDER_ID: &str = "codex";

/// The Codex CLI's own OAuth client id. Independently confirmed by
/// `github.com/simonw/llm-openai-via-codex`'s working source,
/// `github.com/7shi/codex-oauth`, and web search — no client registration of
/// Bastion's own exists (Mario, 2026-07-27: the OpenAI platform API has no
/// `/oauth/authorize` for third-party client registration today). Outreach to
/// change this is tracked separately (M0 of the epic plan) and does not block
/// using the public default.
pub const DEFAULT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// `codex-rs/login/src/server.rs`: `const DEFAULT_ISSUER: &str = "https://auth.openai.com";`
pub const DEFAULT_ISSUER: &str = "https://auth.openai.com";

/// Confirmed via `simonw/llm-openai-via-codex`'s actual request-building code
/// (base URL `"https://chatgpt.com/backend-api/codex"`, `/responses` appended
/// per call) and independently via a direct quote citing the same path as
/// used by Pi and Opencode. See the module doc for why the earlier
/// `/backend-api/wham` finding is not a conflict with this.
pub const DEFAULT_API_BASE: &str = "https://chatgpt.com/backend-api/codex";

/// `codex-rs/login/src/device_code_auth.rs`: `let api_base_url =
/// format!("{base_url}/api/accounts");` — the device endpoints live under
/// this prefix, not the issuer root directly (see the module doc's
/// 2026-08-01 update).
pub const DEVICE_API_PREFIX: &str = "/api/accounts";

/// `codex-rs/login/src/device_code_auth.rs`: `{api_base_url}/deviceauth/usercode`.
pub const DEFAULT_DEVICE_AUTHORIZATION_PATH: &str = "/deviceauth/usercode";

/// `codex-rs/login/src/device_code_auth.rs`: `{api_base_url}/deviceauth/token`.
pub const DEFAULT_DEVICE_TOKEN_PATH: &str = "/deviceauth/token";

/// Configuration for the Codex connector. Every URL is overridable so a
/// deployment can react to OpenAI changing this undocumented surface without
/// a code change (see the module doc's sourcing note).
#[derive(Debug, Clone)]
pub struct CodexConfig {
    pub client_id: String,
    /// `codex-rs`'s `issuer` — origin for `/oauth/token` and the device-flow
    /// endpoints below.
    pub issuer: String,
    /// Origin + path for the Responses-API inference call, WITHOUT the
    /// trailing `/responses` (added by [`CodexProvider`] per call).
    pub api_base: String,
    /// The device flow's own callback, `{issuer}/deviceauth/callback` —
    /// confirmed via `codex-rs/login/src/device_code_auth.rs` (see the
    /// module doc's 2026-08-01 update). Distinct from the browser PKCE
    /// flow's `http://localhost:{port}/auth/callback`, which this module
    /// does not implement.
    pub redirect_uri: String,
    /// Shown to the operator alongside the user code during device login.
    /// `{issuer}/codex/device` — confirmed via `codex-rs/login/src/device_code_auth.rs`
    /// (see the module doc's 2026-08-01 update).
    pub verification_uri: String,
}

impl CodexConfig {
    pub fn token_url(&self) -> String {
        format!("{}/oauth/token", self.issuer.trim_end_matches('/'))
    }

    pub fn device_authorization_url(&self) -> String {
        format!(
            "{}{DEVICE_API_PREFIX}{DEFAULT_DEVICE_AUTHORIZATION_PATH}",
            self.issuer.trim_end_matches('/')
        )
    }

    pub fn device_token_url(&self) -> String {
        format!(
            "{}{DEVICE_API_PREFIX}{DEFAULT_DEVICE_TOKEN_PATH}",
            self.issuer.trim_end_matches('/')
        )
    }

    pub fn responses_url(&self) -> String {
        format!("{}/responses", self.api_base.trim_end_matches('/'))
    }
}

impl Default for CodexConfig {
    fn default() -> Self {
        Self {
            client_id: DEFAULT_CLIENT_ID.to_string(),
            issuer: DEFAULT_ISSUER.to_string(),
            api_base: DEFAULT_API_BASE.to_string(),
            // codex-rs/login/src/device_code_auth.rs: `{issuer}/deviceauth/callback`.
            redirect_uri: format!("{DEFAULT_ISSUER}/deviceauth/callback"),
            // codex-rs/login/src/device_code_auth.rs: `{issuer}/codex/device`.
            verification_uri: format!("{DEFAULT_ISSUER}/codex/device"),
        }
    }
}

// ---------------------------------------------------------------------------
// Device-code login (for the future `connect codex` command, M3 of the epic
// plan — exposed here now so that command has a real port to call into
// instead of a second, divergent implementation).
// ---------------------------------------------------------------------------

pub struct DeviceAuthorization {
    pub device_auth_id: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval_secs: u64,
}

pub enum DevicePollOutcome {
    /// Not approved yet — the caller should sleep `interval_secs` and poll again.
    Pending,
    Authorized {
        authorization_code: String,
        code_verifier: String,
    },
}

/// Step 1: `POST {issuer}/api/accounts/deviceauth/usercode`.
pub async fn start_device_authorization(
    http: &reqwest::Client,
    config: &CodexConfig,
) -> anyhow::Result<DeviceAuthorization> {
    let resp = http
        .post(config.device_authorization_url())
        .json(&json!({ "client_id": config.client_id }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "codex device authorization request failed: HTTP {}",
            resp.status()
        );
    }
    let body: Value = resp.json().await?;
    Ok(DeviceAuthorization {
        device_auth_id: body["device_auth_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("codex device authorization: missing device_auth_id"))?
            .to_string(),
        user_code: body["user_code"]
            .as_str()
            .or_else(|| body["usercode"].as_str())
            .ok_or_else(|| anyhow::anyhow!("codex device authorization: missing user_code"))?
            .to_string(),
        verification_uri: config.verification_uri.clone(),
        interval_secs: body["interval"].as_u64().unwrap_or(5),
    })
}

/// Step 2: `POST {issuer}/api/accounts/deviceauth/token`, called every `interval_secs`
/// until it returns [`DevicePollOutcome::Authorized`]. Per `codex-rs`: a 403
/// or 404 means "not approved yet", any other non-2xx is terminal.
pub async fn poll_device_authorization(
    http: &reqwest::Client,
    config: &CodexConfig,
    device_auth_id: &str,
    user_code: &str,
) -> Result<DevicePollOutcome, ProviderAuthError> {
    let resp = http
        .post(config.device_token_url())
        .json(&json!({ "device_auth_id": device_auth_id, "user_code": user_code }))
        .send()
        .await
        .map_err(|_| ProviderAuthError::Throttled)?;

    match resp.status() {
        s if s.is_success() => {
            let body: Value = resp
                .json()
                .await
                .map_err(|_| ProviderAuthError::UnsupportedProtocol)?;
            let authorization_code = body["authorization_code"]
                .as_str()
                .ok_or(ProviderAuthError::UnsupportedProtocol)?
                .to_string();
            let code_verifier = body["code_verifier"]
                .as_str()
                .ok_or(ProviderAuthError::UnsupportedProtocol)?
                .to_string();
            Ok(DevicePollOutcome::Authorized {
                authorization_code,
                code_verifier,
            })
        }
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND => {
            Ok(DevicePollOutcome::Pending)
        }
        reqwest::StatusCode::UNAUTHORIZED => Err(ProviderAuthError::ReauthRequired),
        reqwest::StatusCode::TOO_MANY_REQUESTS => Err(ProviderAuthError::Throttled),
        _ => Err(ProviderAuthError::UnsupportedProtocol),
    }
}

/// Step 3: exchange the `authorization_code` the poll above returned for
/// real tokens, against the SAME `/oauth/token` endpoint the refresher below
/// uses (standard `authorization_code` + PKCE grant, `codex-rs/login/src/server.rs`).
pub async fn exchange_authorization_code(
    http: &reqwest::Client,
    config: &CodexConfig,
    authorization_code: &str,
    code_verifier: &str,
) -> Result<CodexTokenRecord, ProviderAuthError> {
    let resp = http
        .post(config.token_url())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", authorization_code),
            ("redirect_uri", &config.redirect_uri),
            ("client_id", &config.client_id),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|_| ProviderAuthError::Throttled)?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(map_token_error(status, &body));
    }
    token_record_from_response(&body).ok_or(ProviderAuthError::UnsupportedProtocol)
}

/// What the connector needs persisted between the OAuth dance and every
/// future refresh: the rotating refresh material plus the account id read
/// out of the id_token (needed on every inference call's
/// `ChatGPT-Account-Id` header, confirmed by `codex-oauth`/`llm-openai-via-codex`).
///
/// Deliberately NOT [`ResolvedProviderCredential`]: that type is the
/// short-lived, per-call INFERENCE credential (the access token); this is the
/// longer-lived material the refresher itself needs to produce one.
pub struct CodexTokenRecord {
    pub refresh_token: SecretValue,
    pub account_id: Option<String>,
}

/// Host-owned storage for [`CodexTokenRecord`] — the vendor material
/// [`bastion_runtime::provider_auth::CredentialStateStore`] deliberately
/// never sees (that store persists only the lifecycle's state machine, not
/// secrets). Same division of labor as [`bastion_types::secret::SecretResolver`]:
/// this crate defines the port, the host implements it.
#[async_trait]
pub trait CodexTokenStore: Send + Sync {
    async fn load(&self, reference: &ProviderAuthRef) -> anyhow::Result<Option<CodexTokenRecord>>;
    /// Called after every successful exchange. The refresh_token OpenAI issues
    /// is single-use and rotates on every exchange (confirmed by
    /// `learn.chatgpt.com/docs/auth`'s refresh-on-401/stale-refresh
    /// description) — the value this replaces must never be sent again, even
    /// if the caller crashes immediately after this returns.
    async fn store(
        &self,
        reference: &ProviderAuthRef,
        record: CodexTokenRecord,
    ) -> anyhow::Result<()>;
}

/// Decode the `id_token` JWT's payload (no signature check — Codex CLI itself
/// only ever reads claims from it locally, never trusts it as a security
/// boundary; `learn.chatgpt.com`/`YanZiBin/codex-auth-json` confirm this is
/// the CLI's own behavior too) and pull `chatgpt_account_id` from the
/// `https://api.openai.com/auth` claim namespace.
fn decode_chatgpt_account_id(id_token: &str) -> Option<String> {
    let payload_b64 = id_token.split('.').nth(1)?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    claims
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(str::to_string)
}

/// Maps a non-2xx `/oauth/token` response onto the closed
/// [`ProviderAuthError`] vocabulary (BPAUTH-05) per the BPCDX card's error
/// table: `invalid_grant`/`refresh_token_reused`/401 mean relogin, never
/// retry; timeouts/429/5xx are transient.
fn map_token_error(status: reqwest::StatusCode, body: &Value) -> ProviderAuthError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return ProviderAuthError::ReauthRequired;
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return ProviderAuthError::Throttled;
    }
    match body["error"].as_str().unwrap_or("") {
        "invalid_grant" | "refresh_token_reused" => ProviderAuthError::ReauthRequired,
        "invalid_client" => ProviderAuthError::Invalid,
        _ => ProviderAuthError::UnsupportedProtocol,
    }
}

/// Pure extraction of a successful `/oauth/token` response into what this
/// connector persists — split out so it is unit-testable against a fixture
/// without a live call.
fn token_record_from_response(body: &Value) -> Option<CodexTokenRecord> {
    let refresh_token = body["refresh_token"].as_str()?.to_string();
    let account_id = body["id_token"]
        .as_str()
        .and_then(decode_chatgpt_account_id);
    Some(CodexTokenRecord {
        refresh_token: SecretValue::new(refresh_token),
        account_id,
    })
}

// ---------------------------------------------------------------------------
// ProviderCredentialRefresher
// ---------------------------------------------------------------------------

pub struct CodexRefresher {
    http: reqwest::Client,
    config: CodexConfig,
    tokens: std::sync::Arc<dyn CodexTokenStore>,
}

impl CodexRefresher {
    pub fn new(config: CodexConfig, tokens: std::sync::Arc<dyn CodexTokenStore>) -> Self {
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
impl ProviderCredentialRefresher for CodexRefresher {
    async fn refresh(
        &self,
        reference: &ProviderAuthRef,
    ) -> Result<ResolvedProviderCredential, ProviderAuthError> {
        // A storage failure here is the host's problem, not a statement about
        // the credential — Throttled mirrors how ProviderCredentialLifecycle
        // itself treats a CredentialStateStore load failure.
        let record = self
            .tokens
            .load(reference)
            .await
            .map_err(|_| ProviderAuthError::Throttled)?
            .ok_or(ProviderAuthError::Missing)?;

        let resp = self
            .http
            .post(self.config.token_url())
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", record.refresh_token.expose_secret()),
                ("client_id", &self.config.client_id),
            ])
            .send()
            .await
            .map_err(|_| ProviderAuthError::Throttled)?;

        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(map_token_error(status, &body));
        }

        let access_token = body["access_token"]
            .as_str()
            .ok_or(ProviderAuthError::UnsupportedProtocol)?
            .to_string();

        // Some grants omit refresh_token when the vendor chooses not to
        // rotate on this exchange; keep the one already on file rather than
        // treating an absent field as "cleared" (BPLIFE-05 discipline extends
        // to this connector's own persisted material, not just the lifecycle's).
        let new_record = match token_record_from_response(&body) {
            Some(fresh) => fresh,
            None => CodexTokenRecord {
                refresh_token: record.refresh_token.clone(),
                account_id: body["id_token"]
                    .as_str()
                    .and_then(decode_chatgpt_account_id)
                    .or(record.account_id.clone()),
            },
        };
        self.tokens
            .store(reference, new_record)
            .await
            .map_err(|_| ProviderAuthError::Throttled)?;

        Ok(ResolvedProviderCredential::new(
            reference.clone(),
            CredentialKind::OAuthSubscription,
            SecretValue::new(access_token),
        ))
    }

    /// No vendor revocation endpoint was found in any of the sourcing above
    /// (see the module doc) — `Ok(())` is correct per this trait's own
    /// contract: local state still moves to `Revoked` regardless.
    async fn revoke(&self, _reference: &ProviderAuthRef) -> Result<(), ProviderAuthError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Provider (inference)
// ---------------------------------------------------------------------------

/// Speaks the Responses API against [`DEFAULT_API_BASE`] (or an overridden
/// `api_base`), the same request/response shape `simonw/llm-openai-via-codex`
/// builds via the official `openai` Python SDK's `client.responses.create()`
/// — the request/response FIELD NAMES themselves (`input`, `instructions`,
/// `store`, `output_text`, ...) are OpenAI's public, documented Responses API
/// schema; only the base URL, auth header shape and the `store=false`
/// requirement are the reverse-engineered part.
pub struct CodexProvider {
    client: reqwest::Client,
    api_base: String,
    access_token: String,
    account_id: Option<String>,
    model: String,
}

impl CodexProvider {
    /// Constructed with an ALREADY-RESOLVED credential, same pattern as
    /// `AnthropicProvider::with_api_key`/`OpenAIProvider`'s secret-injection
    /// sibling — this type never touches `ProviderAuthRef` or the lifecycle
    /// directly. The host resolves a credential (refreshing through
    /// [`CodexRefresher`] as needed) and hands this constructor the result.
    pub fn with_credential(
        model: &str,
        access_token: impl Into<String>,
        account_id: Option<String>,
    ) -> Self {
        Self::with_config(model, access_token, account_id, CodexConfig::default())
    }

    pub fn with_config(
        model: &str,
        access_token: impl Into<String>,
        account_id: Option<String>,
        config: CodexConfig,
    ) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
            api_base: config.api_base,
            access_token: access_token.into(),
            account_id,
            model: model.to_owned(),
        }
    }

    fn build_request(&self, messages: &[Message], config: &CallConfig) -> Value {
        let mut body = json!({
            "model": self.model,
            "input": codex_input_from_messages(messages),
            "instructions": config.system_prompt,
            // The ChatGPT Codex backend is stream-only. OpenAI's own
            // ResponsesApiRequest sets this to true and does not expose a
            // max_output_tokens field; a live E2E returned HTTP 400 when we
            // sent stream=false plus max_output_tokens.
            "store": false,
            "stream": true,
        });
        if let Some(temperature) = config.temperature {
            body["temperature"] = json!(temperature);
        }
        if !config.tools.is_empty() {
            body["tools"] = json!(codex_tools_from_anthropic(&config.tools));
            body["tool_choice"] = codex_tool_choice(config.tool_choice.as_ref());
        }
        body
    }
}

/// Anthropic-shaped `{name, description, input_schema}` tool defs (what
/// `CallConfig.tools` carries in this codebase, see `lib.rs`'s
/// `anthropic_tools_to_openai`) into the Responses API's FLAT function-tool
/// shape (`{type, name, description, parameters}` — no nested `function`
/// object, unlike Chat Completions).
fn codex_tools_from_anthropic(tools: &[Value]) -> Vec<Value> {
    tools
        .iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_owned();
            Some(json!({
                "type": "function",
                "name": name,
                "description": t.get("description").and_then(|d| d.as_str()),
                "parameters": t.get("input_schema").cloned().unwrap_or(json!({"type": "object", "properties": {}})),
            }))
        })
        .collect()
}

fn codex_tool_choice(choice: Option<&crate::types::ToolChoice>) -> Value {
    match choice {
        Some(crate::types::ToolChoice::Forced(name)) => json!({"type": "function", "name": name}),
        Some(crate::types::ToolChoice::Required) => json!("required"),
        Some(crate::types::ToolChoice::Auto) | None => json!("auto"),
    }
}

/// Bastion's `Message` history into the Responses API's `input` array —
/// `content` items must be `"input_text"`, never `"text"` (the other
/// WHAM-specific requirement the sourcing above calls out).
fn codex_input_from_messages(messages: &[Message]) -> Vec<Value> {
    messages
        .iter()
        .map(|msg| {
            let role = match msg.role {
                Role::System | Role::User | Role::Tool => "user",
                Role::Assistant => "assistant",
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
            json!({
                "role": role,
                "content": [{"type": "input_text", "text": text}],
            })
        })
        .collect()
}

/// Parse a non-streaming Responses API result — official, documented schema
/// (`response.output[]` items, `response.usage`), not part of the
/// reverse-engineered surface.
fn parse_codex_response(body: &Value) -> LlmResponse {
    let mut text = String::new();
    let mut tool_calls = Vec::new();

    if let Some(output) = body["output"].as_array() {
        for item in output {
            match item["type"].as_str() {
                Some("message") => {
                    if let Some(content) = item["content"].as_array() {
                        for part in content {
                            if part["type"].as_str() == Some("output_text") {
                                if let Some(t) = part["text"].as_str() {
                                    text.push_str(t);
                                }
                            }
                        }
                    }
                }
                Some("function_call") => {
                    let name = item["name"].as_str().unwrap_or_default().to_string();
                    let arguments = item["arguments"]
                        .as_str()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or(Value::Object(serde_json::Map::new()));
                    tool_calls.push(ToolCall {
                        id: item["call_id"].as_str().unwrap_or_default().to_string(),
                        name,
                        arguments,
                        extra: None,
                    });
                }
                _ => {}
            }
        }
    }

    let usage = body["usage"]
        .as_object()
        .map(|u| TokenUsage {
            input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            cache_read: u
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            cache_write: 0,
            ..Default::default()
        })
        .unwrap_or_default();

    LlmResponse {
        text,
        tool_calls: if tool_calls.is_empty() {
            None
        } else {
            Some(tool_calls)
        },
        usage,
    }
}

/// Collapse the Codex backend's SSE-only Responses wire format into the
/// non-streaming [`Provider::complete`] result expected by the kernel.
/// Text arrives as deltas, while function calls arrive as completed output
/// items; `response.completed.response` carries usage but may have an empty
/// `output`, so none of those sources can replace the others.
fn parse_codex_sse(body: &str) -> anyhow::Result<LlmResponse> {
    let mut streamed_text = String::new();
    let mut completed_items = Vec::new();
    let mut completed_response = Value::Null;

    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let event: Value = serde_json::from_str(data)
            .map_err(|e| anyhow::anyhow!("codex SSE contained invalid JSON: {e}"))?;
        match event["type"].as_str() {
            Some("response.output_text.delta") => {
                if let Some(delta) = event["delta"].as_str() {
                    streamed_text.push_str(delta);
                }
            }
            Some("response.output_item.done") => {
                if !event["item"].is_null() {
                    completed_items.push(event["item"].clone());
                }
            }
            Some("response.completed") => completed_response = event["response"].clone(),
            Some("error") | Some("response.failed") => {
                let message = event["error"]["message"]
                    .as_str()
                    .or_else(|| event["response"]["error"]["message"].as_str())
                    .or_else(|| event["message"].as_str())
                    .unwrap_or("<no message>");
                anyhow::bail!("codex API stream failed: {message}");
            }
            _ => {}
        }
    }

    let mut result = parse_codex_response(&completed_response);
    if !streamed_text.is_empty() {
        result.text = streamed_text;
    }
    if !completed_items.is_empty() {
        let item_result = parse_codex_response(&json!({"output": completed_items}));
        if result.text.is_empty() {
            result.text = item_result.text;
        }
        if result.tool_calls.is_none() {
            result.tool_calls = item_result.tool_calls;
        }
    }
    Ok(result)
}

#[async_trait::async_trait]
impl Provider for CodexProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let mut req = self
            .client
            .post(format!("{}/responses", self.api_base.trim_end_matches('/')))
            .bearer_auth(&self.access_token)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(account_id) = &self.account_id {
            req = req.header("ChatGPT-Account-Id", account_id);
        }

        let resp = req
            .json(&self.build_request(messages, config))
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            // A 401 here is the host's cue to drive
            // ProviderCredentialLifecycle::refresh and retry with a fresh
            // provider instance — this type does not retry itself, same
            // boundary the secret-injection design already established for
            // every other provider in this crate.
            anyhow::bail!(
                "codex API error: HTTP {status}: {}",
                serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|value| value["error"]["message"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| "<no message>".to_string())
            );
        }
        parse_codex_sse(&body)
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Text(prompt.to_owned()),
        }];
        let config = CallConfig {
            max_tokens: 2048,
            ..Default::default()
        };
        let resp = self.complete(&messages, &config).await?;
        Ok(resp.text)
    }

    fn context_limit(&self) -> usize {
        // Not vendor-confirmed per model (see module doc's sourcing
        // standard) — a conservative placeholder, same precedent as
        // `OpenAIProvider::context_limit`'s flat 128_000. Revisit alongside
        // BPCDX-05's promotion review.
        128_000
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn name(&self) -> &'static str {
        "codex"
    }
}

/// `Experimental`, `DeviceCode` auth flow — the only entry point
/// [`ProviderSupportDescriptor`] offers (BPCONF-05); nothing here can claim
/// `Supported`.
pub fn support_descriptor() -> ProviderSupportDescriptor {
    ProviderSupportDescriptor::experimental(CODEX_PROVIDER_ID, ProviderAuthFlow::DeviceCode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentPart, ToolChoice};

    #[test]
    fn config_urls_are_built_from_the_confirmed_paths() {
        let config = CodexConfig::default();
        assert_eq!(config.token_url(), "https://auth.openai.com/oauth/token");
        assert_eq!(
            config.device_authorization_url(),
            "https://auth.openai.com/api/accounts/deviceauth/usercode"
        );
        assert_eq!(
            config.device_token_url(),
            "https://auth.openai.com/api/accounts/deviceauth/token"
        );
        assert_eq!(
            config.responses_url(),
            "https://chatgpt.com/backend-api/codex/responses"
        );
    }

    /// A live E2E run (2026-08-01) against the real `auth.openai.com` caught
    /// this exact regression: the device endpoints live under `/api/accounts`,
    /// not the issuer root — a `403` on `device_authorization_url()` before
    /// this fix. Locked down separately from the other URL assertions above
    /// so a future edit can't silently drop the prefix again.
    #[test]
    fn device_urls_include_the_api_accounts_prefix() {
        let config = CodexConfig::default();
        assert!(config
            .device_authorization_url()
            .contains("/api/accounts/deviceauth/"));
        assert!(config
            .device_token_url()
            .contains("/api/accounts/deviceauth/"));
    }

    /// `verification_uri`/`redirect_uri` default to `{issuer}`-based values,
    /// not the browser-flow's `chatgpt.com`/`localhost` placeholders that
    /// were defaulted here before this fix.
    #[test]
    fn verification_and_redirect_defaults_are_issuer_based() {
        let config = CodexConfig::default();
        assert_eq!(
            config.verification_uri,
            "https://auth.openai.com/codex/device"
        );
        assert_eq!(
            config.redirect_uri,
            "https://auth.openai.com/deviceauth/callback"
        );
    }

    #[test]
    fn decode_chatgpt_account_id_reads_the_auth_namespace_claim() {
        let claims = json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct-123",
                "organization_id": "org-456",
            }
        });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let id_token = format!("header.{payload}.signature");

        assert_eq!(
            decode_chatgpt_account_id(&id_token),
            Some("acct-123".to_string())
        );
    }

    #[test]
    fn decode_chatgpt_account_id_is_none_for_garbage_input() {
        assert_eq!(decode_chatgpt_account_id("not-a-jwt"), None);
        assert_eq!(decode_chatgpt_account_id(""), None);
    }

    #[test]
    fn map_token_error_routes_relogin_causes_to_reauth_required() {
        for code in ["invalid_grant", "refresh_token_reused"] {
            let body = json!({"error": code});
            assert_eq!(
                map_token_error(reqwest::StatusCode::BAD_REQUEST, &body),
                ProviderAuthError::ReauthRequired,
                "{code} must mean relogin, never retry"
            );
        }
        assert_eq!(
            map_token_error(reqwest::StatusCode::UNAUTHORIZED, &json!({})),
            ProviderAuthError::ReauthRequired,
            "a bare 401 must mean relogin even without an error body"
        );
    }

    #[test]
    fn map_token_error_routes_transient_causes_to_throttled() {
        assert_eq!(
            map_token_error(reqwest::StatusCode::TOO_MANY_REQUESTS, &json!({})),
            ProviderAuthError::Throttled
        );
        assert_eq!(
            map_token_error(reqwest::StatusCode::BAD_GATEWAY, &json!({})),
            ProviderAuthError::Throttled,
            "5xx must be treated as transient, never as a statement about the credential"
        );
    }

    #[test]
    fn token_record_from_response_reads_refresh_token_and_account_id() {
        let claims = json!({"https://api.openai.com/auth": {"chatgpt_account_id": "acct-1"}});
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let body = json!({
            "access_token": "at",
            "refresh_token": "rt-rotated",
            "id_token": format!("h.{payload}.s"),
        });
        let record = token_record_from_response(&body).unwrap();
        assert_eq!(record.refresh_token.expose_secret(), "rt-rotated");
        assert_eq!(record.account_id, Some("acct-1".to_string()));
    }

    #[test]
    fn token_record_from_response_none_without_a_refresh_token() {
        assert!(token_record_from_response(&json!({"access_token": "at"})).is_none());
    }

    #[test]
    fn input_uses_input_text_never_text() {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Text("hi".into()),
        }];
        let input = codex_input_from_messages(&messages);
        assert_eq!(input[0]["role"], "user");
        assert_eq!(input[0]["content"][0]["type"], "input_text");
        assert_eq!(input[0]["content"][0]["text"], "hi");
    }

    #[test]
    fn input_flattens_text_parts_and_drops_tool_parts() {
        let messages = vec![Message {
            role: Role::Assistant,
            content: MessageContent::Parts(vec![
                ContentPart::Text {
                    text: "reasoning".into(),
                },
                ContentPart::ToolUse {
                    id: "1".into(),
                    name: "x".into(),
                    input: json!({}),
                    extra: None,
                },
            ]),
        }];
        let input = codex_input_from_messages(&messages);
        assert_eq!(input[0]["content"][0]["text"], "reasoning");
    }

    #[test]
    fn build_request_matches_the_codex_streaming_contract() {
        let provider = CodexProvider::with_credential("gpt-5", "tok", None);
        let body = provider.build_request(&[], &CallConfig::default());
        assert_eq!(body["store"], false);
        assert_eq!(body["stream"], true);
        assert!(
            body.get("max_output_tokens").is_none(),
            "the ChatGPT Codex backend rejects max_output_tokens"
        );
    }

    #[test]
    fn build_request_omits_tools_when_empty_and_includes_them_when_present() {
        let provider = CodexProvider::with_credential("gpt-5", "tok", None);

        let empty = provider.build_request(&[], &CallConfig::default());
        assert!(empty.get("tools").is_none());

        let config = CallConfig {
            tools: vec![json!({
                "name": "read_file",
                "description": "reads a file",
                "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
            })],
            tool_choice: Some(ToolChoice::Forced("read_file".into())),
            ..Default::default()
        };
        let with_tools = provider.build_request(&[], &config);
        assert_eq!(with_tools["tools"][0]["type"], "function");
        assert_eq!(with_tools["tools"][0]["name"], "read_file");
        assert!(
            with_tools["tools"][0].get("function").is_none(),
            "Responses API tools are flat, unlike Chat Completions"
        );
        assert_eq!(
            with_tools["tool_choice"],
            json!({"type": "function", "name": "read_file"})
        );
    }

    #[test]
    fn parse_response_extracts_text_and_function_calls() {
        let body = json!({
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": "hello"}]},
                {"type": "function_call", "call_id": "c1", "name": "read_file", "arguments": "{\"path\":\"/tmp/x\"}"},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5, "input_tokens_details": {"cached_tokens": 2}},
        });
        let resp = parse_codex_response(&body);
        assert_eq!(resp.text, "hello");
        let calls = resp.tool_calls.unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "c1");
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].arguments, json!({"path": "/tmp/x"}));
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
        assert_eq!(resp.usage.cache_read, 2);
    }

    #[test]
    fn parse_response_handles_a_text_only_reply_with_no_output_array() {
        let resp = parse_codex_response(&json!({}));
        assert_eq!(resp.text, "");
        assert!(resp.tool_calls.is_none());
    }

    #[test]
    fn parse_sse_combines_text_tool_calls_and_completed_usage() {
        let body = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hel\"}\n\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"c1\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"/tmp/x\\\"}\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"input_tokens_details\":{\"cached_tokens\":2}}}}\n\n",
            "data: [DONE]\n\n",
        );
        let resp = parse_codex_sse(body).unwrap();
        assert_eq!(resp.text, "hello");
        assert_eq!(resp.tool_calls.as_ref().unwrap()[0].name, "read_file");
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
        assert_eq!(resp.usage.cache_read, 2);
    }

    #[test]
    fn parse_sse_surfaces_vendor_failure_without_accepting_partial_text() {
        let body = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
            "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"model unavailable\"}}}\n\n",
        );
        let err = parse_codex_sse(body).unwrap_err();
        assert!(err.to_string().contains("model unavailable"));
    }

    #[test]
    fn support_descriptor_starts_experimental_with_device_code_flow() {
        let descriptor = support_descriptor();
        assert_eq!(
            descriptor.status(),
            bastion_types::provider_catalog::SupportStatus::Experimental
        );
        assert_eq!(descriptor.auth_flow, ProviderAuthFlow::DeviceCode);
        assert!(descriptor.is_selectable());
    }
}
