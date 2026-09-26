//! Google Vertex AI endpoint for Claude: `streamRawPredict` with an OAuth
//! access token from Application Default Credentials.
//!
//! Credentials (ADC), first match wins:
//! 1. the file in `GOOGLE_APPLICATION_CREDENTIALS`, else gcloud's
//!    `application_default_credentials.json` (under `CLOUDSDK_CONFIG`, else
//!    `~/.config/gcloud`) — a `service_account` key (a JWT signed here with
//!    its RSA key, exchanged at its `token_uri`) or an `authorized_user`
//!    login from `gcloud auth application-default login` (its refresh token
//!    exchanged at Google's token endpoint);
//! 2. the metadata server (`GCE_METADATA_HOST`, else
//!    `metadata.google.internal`) when running on Google Cloud.
//!
//! The project is `ANTHROPIC_VERTEX_PROJECT_ID`, else `GOOGLE_CLOUD_PROJECT`,
//! else the credentials file's own project. The region is `CLOUD_ML_REGION`,
//! else `global`. `ANTHROPIC_VERTEX_BASE_URL` overrides the host. Tokens are
//! cached until shortly before they expire and never logged.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use serde_json::Value;
use tokio::sync::Mutex;

/// `anthropic_version` Vertex expects in the request body.
pub(super) const ANTHROPIC_VERSION: &str = "vertex-2023-10-16";

const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// A token is refreshed this long before it expires.
const REFRESH_MARGIN: Duration = Duration::from_secs(120);

pub(crate) struct Vertex {
    client: reqwest::Client,
    project: String,
    region: String,
    base_url: String,
    source: Source,
    cached: Mutex<Option<(String, Instant)>>,
}

/// Where access tokens come from.
pub(super) enum Source {
    ServiceAccount {
        email: String,
        key: ring::signature::RsaKeyPair,
        token_uri: String,
    },
    AuthorizedUser {
        client_id: String,
        client_secret: String,
        refresh_token: String,
        token_uri: String,
    },
    Metadata {
        host: String,
    },
}

impl Vertex {
    pub(crate) fn from_env(client: reqwest::Client) -> anyhow::Result<Self> {
        let (source, file_project) = match adc_file() {
            Some(path) => {
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    anyhow::anyhow!("cannot read credentials {}: {e}", path.display())
                })?;
                let json: Value = serde_json::from_str(&text)
                    .map_err(|_| anyhow::anyhow!("credentials {} are not JSON", path.display()))?;
                source_from_file(&json)?
            }
            None => (
                Source::Metadata {
                    host: env("GCE_METADATA_HOST")
                        .unwrap_or_else(|| "metadata.google.internal".to_string()),
                },
                None,
            ),
        };
        let project = env("ANTHROPIC_VERTEX_PROJECT_ID")
            .or_else(|| env("GOOGLE_CLOUD_PROJECT"))
            .or(file_project)
            .ok_or_else(|| {
                anyhow::anyhow!("Vertex needs a project: set ANTHROPIC_VERTEX_PROJECT_ID")
            })?;
        let region = env("CLOUD_ML_REGION").unwrap_or_else(|| "global".to_string());
        let base_url = env("ANTHROPIC_VERTEX_BASE_URL").unwrap_or_else(|| {
            if region == "global" {
                "https://aiplatform.googleapis.com".to_string()
            } else {
                format!("https://{region}-aiplatform.googleapis.com")
            }
        });
        Ok(Self::new(client, project, region, base_url, source))
    }

    pub(super) fn new(
        client: reqwest::Client,
        project: String,
        region: String,
        base_url: String,
        source: Source,
    ) -> Self {
        Self {
            client,
            project,
            region,
            base_url: base_url.trim_end_matches('/').to_string(),
            source,
            cached: Mutex::new(None),
        }
    }

    pub(crate) fn url(&self, model: &str) -> String {
        format!(
            "{}/v1/projects/{}/locations/{}/publishers/anthropic/models/{model}:streamRawPredict",
            self.base_url, self.project, self.region
        )
    }

    pub(crate) async fn access_token(&self) -> anyhow::Result<String> {
        let mut cached = self.cached.lock().await;
        if let Some((token, until)) = cached.as_ref() {
            if Instant::now() + REFRESH_MARGIN < *until {
                return Ok(token.clone());
            }
        }
        let (token, lifetime) = self.fetch_token().await?;
        *cached = Some((token.clone(), Instant::now() + lifetime));
        Ok(token)
    }

    async fn fetch_token(&self) -> anyhow::Result<(String, Duration)> {
        let response = match &self.source {
            Source::ServiceAccount {
                email,
                key,
                token_uri,
            } => {
                let assertion = service_account_jwt(email, key, token_uri, SystemTime::now())?;
                self.client
                    .post(token_uri)
                    .form(&[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", assertion.as_str()),
                    ])
                    .send()
                    .await?
            }
            Source::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
                token_uri,
            } => {
                self.client
                    .post(token_uri)
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("client_id", client_id.as_str()),
                        ("client_secret", client_secret.as_str()),
                        ("refresh_token", refresh_token.as_str()),
                    ])
                    .send()
                    .await?
            }
            Source::Metadata { host } => self
                .client
                .get(format!(
                    "http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
                ))
                .header("Metadata-Flavor", "Google")
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "no Google credentials for Vertex: set GOOGLE_APPLICATION_CREDENTIALS, \
                             run `gcloud auth application-default login`, or run on Google Cloud"
                    )
                })?,
        };
        if !response.status().is_success() {
            let status = response.status();
            // The OAuth error body names the problem (`invalid_grant`, ...)
            // and never echoes the secret we sent.
            let body = response.text().await.unwrap_or_default();
            let cut = body
                .char_indices()
                .nth(300)
                .map(|(i, _)| i)
                .unwrap_or(body.len());
            anyhow::bail!("Google token endpoint HTTP {status}: {}", &body[..cut]);
        }
        let json: Value = response.json().await?;
        let token = json["access_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Google token endpoint returned no access_token"))?;
        let lifetime = Duration::from_secs(json["expires_in"].as_u64().unwrap_or(3600));
        Ok((token.to_string(), lifetime))
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The ADC file to use, if any exists.
fn adc_file() -> Option<PathBuf> {
    if let Some(path) = env("GOOGLE_APPLICATION_CREDENTIALS") {
        return Some(PathBuf::from(path));
    }
    let dir = env("CLOUDSDK_CONFIG")
        .map(PathBuf::from)
        .or_else(|| env("HOME").map(|h| PathBuf::from(h).join(".config/gcloud")))?;
    let path = dir.join("application_default_credentials.json");
    path.is_file().then_some(path)
}

/// The token source a credentials file describes, and its project.
pub(super) fn source_from_file(json: &Value) -> anyhow::Result<(Source, Option<String>)> {
    let field = |name: &str| json[name].as_str().map(str::to_string);
    let project = field("project_id").or_else(|| field("quota_project_id"));
    match json["type"].as_str() {
        Some("service_account") => {
            let (Some(email), Some(pem)) = (field("client_email"), field("private_key")) else {
                anyhow::bail!("service account credentials lack client_email or private_key");
            };
            let key = rsa_key_from_pem(&pem)?;
            Ok((
                Source::ServiceAccount {
                    email,
                    key,
                    token_uri: field("token_uri").unwrap_or_else(|| GOOGLE_TOKEN_URI.to_string()),
                },
                project,
            ))
        }
        Some("authorized_user") => {
            let (Some(client_id), Some(client_secret), Some(refresh_token)) = (
                field("client_id"),
                field("client_secret"),
                field("refresh_token"),
            ) else {
                anyhow::bail!("authorized_user credentials are incomplete; run `gcloud auth application-default login` again");
            };
            Ok((
                Source::AuthorizedUser {
                    client_id,
                    client_secret,
                    refresh_token,
                    token_uri: field("token_uri").unwrap_or_else(|| GOOGLE_TOKEN_URI.to_string()),
                },
                project,
            ))
        }
        Some(other) => anyhow::bail!(
            "credentials of type '{other}' are not supported for Vertex; use a service account \
             key or `gcloud auth application-default login`"
        ),
        None => anyhow::bail!("credentials file has no type"),
    }
}

/// The PKCS#8 RSA key of a service account's `private_key` PEM.
fn rsa_key_from_pem(pem: &str) -> anyhow::Result<ring::signature::RsaKeyPair> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| anyhow::anyhow!("service account private_key is not valid PEM"))?;
    ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|_| anyhow::anyhow!("service account private_key is not a PKCS#8 RSA key"))
}

/// The signed JWT a service account exchanges for an access token (RFC 7523).
fn service_account_jwt(
    email: &str,
    key: &ring::signature::RsaKeyPair,
    audience: &str,
    now: SystemTime,
) -> anyhow::Result<String> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let iat = now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = b64.encode(serde_json::to_vec(&serde_json::json!({
        "iss": email,
        "scope": SCOPE,
        "aud": audience,
        "iat": iat,
        "exp": iat + 3600,
    }))?);
    let signing_input = format!("{header}.{claims}");
    let mut signature = vec![0u8; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| anyhow::anyhow!("could not sign the service account assertion"))?;
    Ok(format!("{signing_input}.{}", b64.encode(signature)))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A throwaway 2048-bit PKCS#8 key, generated per run so no private key
    /// is ever committed. `None` without `openssl` on PATH.
    pub(crate) fn test_key() -> Option<String> {
        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        String::from_utf8(output.stdout).ok()
    }

    #[test]
    fn a_service_account_jwt_verifies_with_its_public_key() {
        let Some(pem) = test_key() else {
            eprintln!("skipping: openssl not found");
            return;
        };
        let key = rsa_key_from_pem(&pem).unwrap();
        let jwt = service_account_jwt(
            "bot@p.iam.gserviceaccount.com",
            &key,
            "https://oauth2.googleapis.com/token",
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        )
        .unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims: Value = serde_json::from_slice(&b64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "bot@p.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["exp"], 4_600);

        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref(),
        );
        public
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &b64.decode(parts[2]).unwrap(),
            )
            .expect("signature verifies");
    }

    #[test]
    fn credential_files_map_to_their_source() {
        let Some(pem) = test_key() else {
            eprintln!("skipping: openssl not found");
            return;
        };
        let (source, project) = source_from_file(&serde_json::json!({
            "type": "service_account",
            "project_id": "p1",
            "client_email": "bot@p1.iam.gserviceaccount.com",
            "private_key": pem,
        }))
        .unwrap();
        assert!(
            matches!(source, Source::ServiceAccount { ref token_uri, .. } if token_uri == GOOGLE_TOKEN_URI)
        );
        assert_eq!(project.as_deref(), Some("p1"));

        let (source, project) = source_from_file(&serde_json::json!({
            "type": "authorized_user",
            "client_id": "c", "client_secret": "s", "refresh_token": "r",
            "quota_project_id": "q1",
        }))
        .unwrap();
        assert!(matches!(source, Source::AuthorizedUser { .. }));
        assert_eq!(project.as_deref(), Some("q1"));

        assert!(source_from_file(&serde_json::json!({"type": "external_account"})).is_err());
        assert!(source_from_file(&serde_json::json!({
            "type": "service_account", "client_email": "x", "private_key": "nope"
        }))
        .is_err());
    }
}
