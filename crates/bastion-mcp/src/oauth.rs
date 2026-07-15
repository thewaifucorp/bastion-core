//! Composio OAuth (AuthKit) integration (SEC-03).
//!
//! Replaces Composio's static `x-consumer-api-key` header auth (still used for the
//! per-MCP-server connection in `bastion.toml [mcp.servers]`) with a real, per-owner
//! OAuth consent flow. This is a REST initiate→poll→callback dance against Composio's
//! OWN `connected_accounts` API — Bastion is a caller to Composio's API, not the
//! RFC 6749 OAuth client to the third-party service (Gmail/Slack/etc). Composio itself
//! brokers and auto-refreshes the underlying third-party OAuth tokens server-side.
//!
//! Flow (mirrors the existing OTC pairing pattern, D-06):
//!   1. Owner runs `/connect-app-composio <toolkit>` → [`ComposioOAuth::initiate`] POSTs
//!      to Composio's connected-accounts initiate endpoint and returns a `redirect_url`.
//!   2. Owner opens the URL in a browser and authorizes.
//!   3. Composio calls back Bastion's `POST /auth/composio/callback` with the resulting
//!      `connected_account_id` → [`ComposioOAuth::store_connection`] persists ONLY that
//!      reference id into the `composio_connections` table (Plan 11-01) — never a raw
//!      third-party OAuth token, and never into `bastion.toml`.
//!   4. [`ComposioOAuth::refresh_if_expired`] re-syncs the LOCAL `status` column against
//!      Composio's own connected-accounts GET endpoint on demand (e.g. after a failed
//!      tool call) — this is a "detect + re-sync" job, NOT a third-party refresh-grant
//!      exchange (Pitfall 4): Composio auto-refreshes the underlying token server-side.
//!
//! sqlite access follows the established `task::spawn_blocking` + WAL/busy_timeout idiom
//! (`src/capability/approval.rs`, `src/session/sqlite.rs`).
//!
//! Live E2E verification against a real Composio account is explicitly DEFERRED to
//! Phase 12 (STATE.md's 2026-07-10 decision) — the exact wire field names below
//! (`redirect_url`/`status`) reflect Composio's v3 REST API as documented at the time
//! of writing and MUST be reconfirmed against a live account before Phase 12 closes.

use rusqlite::Connection;
use tokio::task;

/// SEC-03 forgery fix (T-11-06-01): TTL for a pending OAuth state-nonce, in seconds.
/// Wider than the 5-minute OTC pairing window (`generate_otc` in `agent/command.rs`)
/// because this window must cover a full third-party consent flow in the owner's
/// browser (Gmail/Slack login + 2FA + consent screens), not just typing a short code.
const OAUTH_STATE_TTL_SECS: i64 = 900;

/// Generate an unguessable, single-use CSPRNG state token (32 random bytes, hex).
/// Binds `ComposioOAuth::initiate()` to the `/auth/composio/callback` webhook so the
/// callback can never be forged with an arbitrary `{owner, toolkit}` pair (T-11-06-01).
fn generate_state_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Owner-scoped Composio OAuth client, backed by the `composio_connections` sqlite
/// table (Plan 11-01: id, owner_id, toolkit, connected_account_id, status, created_at,
/// updated_at; UNIQUE(owner_id, toolkit)).
pub struct ComposioOAuth {
    http: reqwest::Client,
    api_key: String,
    db_path: String,
    base: String,
}

impl ComposioOAuth {
    /// `COMPOSIO_API_KEY` is Composio's PLATFORM API key (Dashboard -> Settings -> API
    /// Keys) — distinct from the per-MCP-server `x-consumer-api-key` already configured
    /// in `bastion.toml [mcp.servers]`. Reject missing OR empty (avoids an opaque 401
    /// deep in a REST call, mirrors `GroqProvider::new`/`OpenRouterProvider::new`).
    pub fn new(db_path: impl Into<String>) -> Self {
        let api_key = std::env::var("COMPOSIO_API_KEY").unwrap_or_default();
        if api_key.trim().is_empty() {
            panic!(
                "COMPOSIO_API_KEY required (missing or empty) — get one at \
                 https://app.composio.dev (Dashboard -> Settings -> API Keys)"
            );
        }
        let base = std::env::var("COMPOSIO_BASE_URL")
            .unwrap_or_else(|_| "https://backend.composio.dev".to_owned());

        Self {
            http: reqwest::Client::new(),
            api_key,
            db_path: db_path.into(),
            base,
        }
    }

    /// Test-only constructor bypassing the `COMPOSIO_API_KEY` env lookup entirely —
    /// lets OTHER crates' tests (e.g. the app crate's `agent::command`'s
    /// `/connect-app-composio` tests, `channel::webhook`'s callback tests) build a
    /// working `ComposioOAuth` against a local scripted server without mutating a
    /// process-global env var (which would race against this module's own
    /// `new_panics_when_composio_api_key_missing_or_empty` test under parallel
    /// `cargo test`). Fields stay private; this is the sanctioned test-only seam.
    ///
    /// Not `#[cfg(test)]`-gated (M2 step 5): items behind `#[cfg(test)]` don't exist
    /// in a crate's compiled rlib when it's linked as an ordinary path dependency, so
    /// downstream crates' own test code can never reach a `#[cfg(test)]` item across
    /// the boundary — only a plain `pub` fn does. `pub(crate)` was likewise no longer
    /// reachable once this module left the app crate.
    pub fn new_for_test(db_path: impl Into<String>, base: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: "test-key".into(),
            db_path: db_path.into(),
            base: base.into(),
        }
    }

    /// POST a JSON body to a Composio API path, surfacing Composio's error message on
    /// non-2xx (mirrors `GroqProvider::post_chat`'s raw-reqwest send/parse/error idiom).
    async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("composio request failed: {e}"))?;
        Self::parse_response(resp).await
    }

    /// GET a Composio API path. Same error-surfacing idiom as [`Self::post_json`].
    async fn get_json(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("composio request failed: {e}"))?;
        Self::parse_response(resp).await
    }

    async fn parse_response(resp: reqwest::Response) -> anyhow::Result<serde_json::Value> {
        let status = resp.status();
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("composio response was not JSON: {e}"))?;
        if !status.is_success() {
            let msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .or_else(|| json.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("composio API error ({}): {msg}", status.as_u16());
        }
        Ok(json)
    }

    /// Initiate a Composio OAuth connection for `toolkit` (e.g. "gmail", "slack") on
    /// behalf of `owner_id`. Returns Composio's own `redirect_url` — the owner opens
    /// this in a browser to authorize; Composio calls back with the resulting
    /// `connected_account_id` once consent completes.
    ///
    /// `owner_id` is threaded into the request so a future multi-tenant Composio
    /// project can disambiguate connections server-side; today's single-owner
    /// deployments pass `agent::loop_::DEFAULT_OWNER`.
    ///
    /// SEC-03 forgery fix (T-11-06-01): also mints a CSPRNG state-nonce and persists
    /// `(state, owner_id, toolkit, expires_at)` in `composio_oauth_state` BEFORE the
    /// Composio call, then passes `state` through in the initiate request body so
    /// Composio's own callback is expected to echo it back. `/auth/composio/callback`
    /// (`channel/webhook.rs`) derives `owner`/`toolkit` EXCLUSIVELY from this
    /// server-side record (via [`Self::consume_state`]) — never from the callback
    /// body's own fields — closing the "anyone who can reach the endpoint can bind an
    /// arbitrary connection to any owner" forgery hole. The exact `state` passthrough
    /// field name is Bastion's own webhook contract, not a confirmed Composio API
    /// field — MUST be reconfirmed against a live Composio account before Phase 12
    /// closes (same live-verify deferral this module's header already documents).
    pub async fn initiate(&self, owner_id: &str, toolkit: &str) -> anyhow::Result<String> {
        let state = generate_state_token();
        self.store_pending_state(owner_id, toolkit, &state).await?;

        let body = serde_json::json!({
            "toolkit": { "slug": toolkit },
            "user_id": owner_id,
            "state": state,
        });
        let json = self
            .post_json("/api/v3/connected_accounts/link", &body)
            .await?;
        let redirect_url = json
            .get("redirect_url")
            .or_else(|| json.get("redirectUrl"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("composio initiate response missing redirect_url: {json}")
            })?;
        Ok(redirect_url.to_owned())
    }

    /// Persist a freshly-minted state-nonce with a `OAUTH_STATE_TTL_SECS` expiry.
    /// `state` is 32 CSPRNG bytes hex-encoded (see [`generate_state_token`]) — a
    /// PRIMARY KEY collision is not a case this needs to defensively upsert around.
    async fn store_pending_state(
        &self,
        owner_id: &str,
        toolkit: &str,
        state: &str,
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let toolkit = toolkit.to_owned();
        let state = state.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let expires_at = now_nanos() + OAUTH_STATE_TTL_SECS * 1_000_000_000;
            conn.execute(
                "INSERT INTO composio_oauth_state (state, owner_id, toolkit, expires_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![state, owner_id, toolkit, expires_at],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await?
    }

    /// Look up and CONSUME (delete-on-read, single-use) a pending OAuth state-nonce.
    /// Returns `Some((owner_id, toolkit))` only when the state exists AND has not yet
    /// expired; returns `None` for a missing, expired, or already-consumed state —
    /// the caller (`composio_callback_handler`) maps every `None` to a generic
    /// 401/403, never distinguishing "unknown" from "expired" (mirrors the OTC
    /// enumeration-oracle guard, WR-03).
    ///
    /// Always deletes the row when found (even if expired) so a leaked/replayed state
    /// can never be consumed twice, expired or not.
    pub async fn consume_state(&self, state: &str) -> anyhow::Result<Option<(String, String)>> {
        let path = self.db_path.clone();
        let state = state.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let row = conn
                .query_row(
                    "SELECT owner_id, toolkit, expires_at FROM composio_oauth_state WHERE state = ?1",
                    rusqlite::params![state],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional_result()?;

            let Some((owner_id, toolkit, expires_at)) = row else {
                return Ok::<Option<(String, String)>, anyhow::Error>(None);
            };

            // Single-use: delete unconditionally, whether or not it was still valid.
            conn.execute(
                "DELETE FROM composio_oauth_state WHERE state = ?1",
                rusqlite::params![state],
            )?;

            if expires_at < now_nanos() {
                return Ok(None);
            }
            Ok(Some((owner_id, toolkit)))
        })
        .await?
    }

    /// Test-only seam: insert a known state directly, bypassing `initiate()`'s
    /// Composio HTTP round-trip. Lets other crates' tests (e.g. the app crate's
    /// `channel::webhook` callback tests) exercise the consume/expire/replay paths
    /// against a deterministic token without a scripted Composio server. Mirrors
    /// [`Self::new_for_test`]'s "sanctioned test-only seam" precedent — not
    /// `#[cfg(test)]`-gated, for the same cross-crate-visibility reason.
    pub async fn insert_state_for_test(
        &self,
        state: &str,
        owner_id: &str,
        toolkit: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let state = state.to_owned();
        let owner_id = owner_id.to_owned();
        let toolkit = toolkit.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let expires_at = now_nanos() + ttl_secs * 1_000_000_000;
            conn.execute(
                "INSERT INTO composio_oauth_state (state, owner_id, toolkit, expires_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![state, owner_id, toolkit, expires_at],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await?
    }

    /// Upsert the (owner_id, toolkit) -> connected_account_id mapping. Calling this
    /// twice for the same (owner_id, toolkit) updates the existing row via the
    /// UNIQUE(owner_id, toolkit) index — never a duplicate row, never an error.
    /// Only Composio's own reference id is ever persisted here — never a raw
    /// third-party OAuth token (T-11-06-02).
    pub async fn store_connection(
        &self,
        owner_id: &str,
        toolkit: &str,
        connected_account_id: &str,
    ) -> anyhow::Result<()> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let toolkit = toolkit.to_owned();
        let connected_account_id = connected_account_id.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let now = now_nanos();
            conn.execute(
                "INSERT INTO composio_connections \
                    (owner_id, toolkit, connected_account_id, status, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 'active', ?4, ?4) \
                 ON CONFLICT(owner_id, toolkit) DO UPDATE SET \
                    connected_account_id = excluded.connected_account_id, \
                    status = 'active', \
                    updated_at = excluded.updated_at",
                rusqlite::params![owner_id, toolkit, connected_account_id, now],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await?
    }

    /// Look up the current `connected_account_id` for (owner_id, toolkit). `None` when
    /// no connection has been established yet.
    pub async fn current_connection(
        &self,
        owner_id: &str,
        toolkit: &str,
    ) -> anyhow::Result<Option<String>> {
        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let toolkit = toolkit.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let result = conn
                .query_row(
                    "SELECT connected_account_id FROM composio_connections \
                     WHERE owner_id = ?1 AND toolkit = ?2",
                    rusqlite::params![owner_id, toolkit],
                    |row| row.get::<_, String>(0),
                )
                .optional_result()?;
            Ok::<Option<String>, anyhow::Error>(result)
        })
        .await?
    }

    /// Re-fetch the connection's CURRENT status from Composio's own connected-accounts
    /// GET endpoint and update the local `status`/`updated_at` row. This is the narrow
    /// "detect + re-sync" job D-07 requires — NOT a third-party OAuth refresh-grant
    /// exchange (Pitfall 4): Composio auto-refreshes the underlying token server-side,
    /// Bastion never holds or exchanges a raw refresh_token.
    ///
    /// No-ops (returns `Ok(())`) when no connection exists yet for (owner_id, toolkit) —
    /// there is nothing to refresh.
    pub async fn refresh_if_expired(&self, owner_id: &str, toolkit: &str) -> anyhow::Result<()> {
        let Some(connected_account_id) = self.current_connection(owner_id, toolkit).await? else {
            return Ok(());
        };

        let json = self
            .get_json(&format!(
                "/api/v3/connected_accounts/{connected_account_id}"
            ))
            .await?;
        let status = json
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| {
                tracing::warn!(
                    event = "composio_refresh_missing_status",
                    connected_account_id = %connected_account_id,
                    "composio connected-account response had no 'status' field — defaulting to 'active'"
                );
                "active".to_string()
            });

        let path = self.db_path.clone();
        let owner_id = owner_id.to_owned();
        let toolkit = toolkit.to_owned();
        task::spawn_blocking(move || {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
            let now = now_nanos();
            conn.execute(
                "UPDATE composio_connections SET status = ?3, updated_at = ?4 \
                 WHERE owner_id = ?1 AND toolkit = ?2",
                rusqlite::params![owner_id, toolkit, status, now],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await?
    }
}

/// Local extension trait — `rusqlite::OptionalExtension` renamed inline to avoid a
/// naming collision with the method name in this module's own doc comments.
trait OptionalResultExt<T> {
    fn optional_result(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalResultExt<T> for rusqlite::Result<T> {
    fn optional_result(self) -> rusqlite::Result<Option<T>> {
        use rusqlite::OptionalExtension;
        self.optional()
    }
}

fn now_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Bypass `new()`'s COMPOSIO_API_KEY env lookup for tests that don't exercise it
    /// directly (mirrors `GroqProvider`'s `test_provider()`).
    fn test_oauth(db_path: &str, base: &str) -> ComposioOAuth {
        ComposioOAuth::new_for_test(db_path, base)
    }

    async fn make_db() -> (NamedTempFile, String) {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_owned();
        let session = bastion_runtime::session::SessionManager::new(&path);
        session.init_schema().await.expect("init_schema");
        (f, path)
    }

    #[test]
    fn new_panics_when_composio_api_key_missing_or_empty() {
        // Sequential within this single test — no other test in this module touches
        // COMPOSIO_API_KEY, so there is no cross-test race on the env var.
        std::env::remove_var("COMPOSIO_API_KEY");
        let missing = std::panic::catch_unwind(|| ComposioOAuth::new("test.db"));
        assert!(missing.is_err(), "must panic when env var is unset");

        std::env::set_var("COMPOSIO_API_KEY", "   ");
        let empty = std::panic::catch_unwind(|| ComposioOAuth::new("test.db"));
        assert!(
            empty.is_err(),
            "must panic when env var is empty/whitespace"
        );

        std::env::remove_var("COMPOSIO_API_KEY");
    }

    /// Spin up a tiny local axum server implementing Composio's initiate endpoint —
    /// no mocking crate needed (axum + tokio are already deps, mirrors the codebase's
    /// own `serve_with_mesh` idiom, just bound to an ephemeral port for the test).
    async fn spawn_scripted_composio_server(redirect_url: &'static str) -> std::net::SocketAddr {
        let app = axum::Router::new().route(
            "/api/v3/connected_accounts/link",
            axum::routing::post(move || async move {
                axum::Json(serde_json::json!({ "redirect_url": redirect_url }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    #[tokio::test]
    async fn initiate_returns_redirect_url_from_scripted_response() {
        let addr = spawn_scripted_composio_server("https://composio.dev/auth/xyz").await;
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, &format!("http://{addr}"));

        let redirect_url = oauth.initiate("alice", "gmail").await.expect("initiate");
        assert_eq!(redirect_url, "https://composio.dev/auth/xyz");
    }

    #[tokio::test]
    async fn store_connection_upserts_and_does_not_duplicate() {
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, "http://unused.invalid");

        oauth
            .store_connection("alice", "gmail", "ca_1")
            .await
            .expect("first store");
        oauth
            .store_connection("alice", "gmail", "ca_2")
            .await
            .expect("second store (update)");

        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM composio_connections WHERE owner_id='alice' AND toolkit='gmail'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "must upsert, never duplicate the (owner, toolkit) row"
        );

        let current = oauth
            .current_connection("alice", "gmail")
            .await
            .expect("current_connection");
        assert_eq!(
            current,
            Some("ca_2".to_string()),
            "must reflect the latest id"
        );
    }

    #[tokio::test]
    async fn current_connection_returns_none_when_absent() {
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, "http://unused.invalid");

        let result = oauth
            .current_connection("bob", "slack")
            .await
            .expect("current_connection");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn refresh_if_expired_is_a_noop_when_no_connection_exists() {
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, "http://unused.invalid");

        // No connection stored for (carol, gmail) — must not error, must not call out.
        oauth
            .refresh_if_expired("carol", "gmail")
            .await
            .expect("refresh_if_expired no-op");
    }

    #[tokio::test]
    async fn refresh_if_expired_resyncs_status_from_composio() {
        let app = axum::Router::new().route(
            "/api/v3/connected_accounts/{id}",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "status": "EXPIRED" })) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, &format!("http://{addr}"));
        oauth
            .store_connection("dave", "gmail", "ca_9")
            .await
            .expect("seed connection");

        oauth
            .refresh_if_expired("dave", "gmail")
            .await
            .expect("refresh_if_expired");

        let conn = Connection::open(&path).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM composio_connections WHERE owner_id='dave' AND toolkit='gmail'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            status, "expired",
            "local status must resync from Composio's response"
        );
    }

    // ── SEC-03 forgery fix: state-nonce tests (T-11-06-01) ─────────────────────

    /// `initiate()` mints and persists a state-nonce; a valid, unconsumed state
    /// resolves to the (owner_id, toolkit) that actually called `initiate()`.
    #[tokio::test]
    async fn initiate_persists_a_consumable_state_bound_to_owner_and_toolkit() {
        let addr = spawn_scripted_composio_server("https://composio.dev/auth/xyz").await;
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, &format!("http://{addr}"));

        oauth.initiate("alice", "gmail").await.expect("initiate");

        // initiate() doesn't return the state (it's Composio's job to echo it back
        // via the callback), so read it directly from the table to drive consume_state.
        let conn = Connection::open(&path).unwrap();
        let state: String = conn
            .query_row(
                "SELECT state FROM composio_oauth_state WHERE owner_id='alice' AND toolkit='gmail'",
                [],
                |row| row.get(0),
            )
            .expect("state row must exist after initiate()");

        let consumed = oauth.consume_state(&state).await.expect("consume_state");
        assert_eq!(consumed, Some(("alice".to_string(), "gmail".to_string())));
    }

    /// consume_state is single-use: a second consume of the same token returns None.
    #[tokio::test]
    async fn consume_state_is_single_use() {
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, "http://unused.invalid");
        oauth
            .insert_state_for_test("tok-1", "alice", "gmail", 900)
            .await
            .expect("insert_state_for_test");

        let first = oauth.consume_state("tok-1").await.expect("first consume");
        assert_eq!(first, Some(("alice".to_string(), "gmail".to_string())));

        let second = oauth.consume_state("tok-1").await.expect("second consume");
        assert_eq!(second, None, "state must be consumed exactly once");
    }

    /// An expired state is rejected (and still consumed/deleted so it can't be retried).
    #[tokio::test]
    async fn consume_state_rejects_expired_state() {
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, "http://unused.invalid");
        // Negative TTL — already expired the instant it's inserted.
        oauth
            .insert_state_for_test("tok-expired", "alice", "gmail", -60)
            .await
            .expect("insert_state_for_test");

        let result = oauth
            .consume_state("tok-expired")
            .await
            .expect("consume_state");
        assert_eq!(result, None, "expired state must not resolve");

        // Deleted on the first (failed) consume — a retry must also return None,
        // not resurrect the expired row.
        let retry = oauth
            .consume_state("tok-expired")
            .await
            .expect("consume_state retry");
        assert_eq!(retry, None);
    }

    /// An unknown/never-issued state returns None (never an error, never a panic).
    #[tokio::test]
    async fn consume_state_rejects_unknown_state() {
        let (_f, path) = make_db().await;
        let oauth = test_oauth(&path, "http://unused.invalid");
        let result = oauth
            .consume_state("never-issued")
            .await
            .expect("consume_state");
        assert_eq!(result, None);
    }
}
