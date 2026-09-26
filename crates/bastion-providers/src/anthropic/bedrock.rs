//! Amazon Bedrock endpoint for Claude: `InvokeModel`, authenticated with a
//! Bedrock API key or SigV4.
//!
//! Credentials, first match wins:
//! 1. `AWS_BEARER_TOKEN_BEDROCK` — a Bedrock API key, sent as a bearer token;
//! 2. `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`);
//! 3. static keys of the profile (`AWS_PROFILE`, else `default`) in the shared
//!    credentials file (`AWS_SHARED_CREDENTIALS_FILE`, else `~/.aws/credentials`);
//! 4. `aws configure export-credentials` — the AWS CLI resolves anything else
//!    it knows (SSO, assumed roles, `credential_process`) and hands back
//!    temporary keys, cached here until shortly before they expire.
//!
//! The region is `AWS_REGION`, else `AWS_DEFAULT_REGION`. The endpoint is
//! `AWS_ENDPOINT_URL_BEDROCK_RUNTIME`, else `AWS_ENDPOINT_URL`, else the
//! regional `bedrock-runtime` host. Secrets never reach a log or an error.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use tokio::sync::Mutex;

/// `anthropic_version` Bedrock expects in the request body.
pub(super) const ANTHROPIC_VERSION: &str = "bedrock-2023-05-31";

/// SigV4 service name of the Bedrock runtime.
const SERVICE: &str = "bedrock";

/// Temporary credentials are refreshed this long before they expire.
const REFRESH_MARGIN: Duration = Duration::from_secs(120);

pub(crate) struct Bedrock {
    region: String,
    endpoint: String,
    bearer: Option<String>,
    cached: Mutex<Option<Credentials>>,
}

impl Bedrock {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let region = env("AWS_REGION")
            .or_else(|| env("AWS_DEFAULT_REGION"))
            .ok_or_else(|| {
                anyhow::anyhow!("Bedrock needs a region: set AWS_REGION (e.g. us-east-1)")
            })?;
        let endpoint = env("AWS_ENDPOINT_URL_BEDROCK_RUNTIME")
            .or_else(|| env("AWS_ENDPOINT_URL"))
            .unwrap_or_else(|| format!("https://bedrock-runtime.{region}.amazonaws.com"));
        Ok(Self::new(region, endpoint, env("AWS_BEARER_TOKEN_BEDROCK")))
    }

    pub(super) fn new(region: String, endpoint: String, bearer: Option<String>) -> Self {
        Self {
            region,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bearer,
            cached: Mutex::new(None),
        }
    }

    /// `InvokeModel` URL. The model id is percent-encoded as one path segment
    /// (`:` in a version suffix becomes `%3A`), which is also the form SigV4's
    /// canonical request is computed from.
    pub(crate) fn url(&self, model: &str) -> String {
        format!("{}/model/{}/invoke", self.endpoint, encode_segment(model))
    }

    /// Headers that authenticate a POST of `body` to `url`.
    pub(crate) async fn auth_headers(
        &self,
        url: &str,
        body: &[u8],
    ) -> anyhow::Result<Vec<(String, String)>> {
        if let Some(token) = &self.bearer {
            return Ok(vec![("authorization".into(), format!("Bearer {token}"))]);
        }
        let credentials = self.credentials().await?;
        let identity = credentials.into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(SERVICE)
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()?
            .into();
        let request = SignableRequest::new(
            "POST",
            url,
            [("content-type", "application/json")].into_iter(),
            SignableBody::Bytes(body),
        )?;
        let (instructions, _signature) = sign(request, &params)?.into_parts();
        let (headers, _query) = instructions.into_parts();
        Ok(headers
            .into_iter()
            .map(|h| (h.name().to_string(), h.value().to_string()))
            .collect())
    }

    async fn credentials(&self) -> anyhow::Result<Credentials> {
        let mut cached = self.cached.lock().await;
        if let Some(credentials) = cached.as_ref() {
            let fresh = credentials
                .expiry()
                .is_none_or(|at| at > SystemTime::now() + REFRESH_MARGIN);
            if fresh {
                return Ok(credentials.clone());
            }
        }
        let credentials = resolve_credentials().await?;
        *cached = Some(credentials.clone());
        Ok(credentials)
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn profile() -> String {
    env("AWS_PROFILE").unwrap_or_else(|| "default".to_string())
}

async fn resolve_credentials() -> anyhow::Result<Credentials> {
    if let (Some(id), Some(secret)) = (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY")) {
        return Ok(Credentials::new(
            id,
            secret,
            env("AWS_SESSION_TOKEN"),
            None,
            "environment",
        ));
    }
    if let Some(credentials) = shared_file_credentials(&profile())? {
        return Ok(credentials);
    }
    if let Some(credentials) = cli_credentials(&profile()).await? {
        return Ok(credentials);
    }
    anyhow::bail!(
        "no AWS credentials for Bedrock: set AWS_BEARER_TOKEN_BEDROCK (a Bedrock API key), \
         AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, static keys for profile '{}' in \
         ~/.aws/credentials, or install the AWS CLI logged in to that profile",
        profile()
    )
}

fn shared_credentials_path() -> Option<PathBuf> {
    env("AWS_SHARED_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .or_else(|| env("HOME").map(|h| PathBuf::from(h).join(".aws/credentials")))
}

/// Static keys of `profile` in the shared credentials file. `None` when the
/// file, the profile or its keys are absent.
fn shared_file_credentials(profile: &str) -> anyhow::Result<Option<Credentials>> {
    let Some(path) = shared_credentials_path() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("cannot read {}: {e}", path.display()),
    };
    let section = ini_section(&text, profile);
    match (
        section.get("aws_access_key_id"),
        section.get("aws_secret_access_key"),
    ) {
        (Some(id), Some(secret)) => Ok(Some(Credentials::new(
            id.clone(),
            secret.clone(),
            section.get("aws_session_token").cloned(),
            None,
            "shared-credentials-file",
        ))),
        _ => Ok(None),
    }
}

/// Keys of one `[section]` of an INI file, lower-cased, values trimmed.
fn ini_section(text: &str, name: &str) -> std::collections::HashMap<String, String> {
    let mut current = None::<String>;
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = Some(header.trim().to_string());
            continue;
        }
        if current.as_deref() != Some(name) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    out
}

/// Temporary keys from `aws configure export-credentials --format process`.
/// `None` when the AWS CLI is not installed.
async fn cli_credentials(profile: &str) -> anyhow::Result<Option<Credentials>> {
    let aws = env("BASTION_AWS_CLI").unwrap_or_else(|| "aws".to_string());
    let output = match tokio::process::Command::new(&aws)
        .args(["configure", "export-credentials", "--format", "process"])
        .args(["--profile", profile])
        .kill_on_drop(true)
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("cannot run the AWS CLI: {e}"),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        anyhow::bail!("the AWS CLI could not export credentials for profile '{profile}': {first}");
    }
    parse_process_credentials(&output.stdout).map(Some)
}

/// The `credential_process` JSON shape (`Version`, `AccessKeyId`,
/// `SecretAccessKey`, `SessionToken`, `Expiration` in RFC 3339).
fn parse_process_credentials(stdout: &[u8]) -> anyhow::Result<Credentials> {
    let v: serde_json::Value = serde_json::from_slice(stdout)
        .map_err(|_| anyhow::anyhow!("the AWS CLI returned credentials in an unknown format"))?;
    let field = |name: &str| v[name].as_str().map(str::to_string);
    let (Some(id), Some(secret)) = (field("AccessKeyId"), field("SecretAccessKey")) else {
        anyhow::bail!("the AWS CLI returned no access key");
    };
    let expiry = field("Expiration").and_then(|at| parse_rfc3339(&at));
    Ok(Credentials::new(
        id,
        secret,
        field("SessionToken"),
        expiry,
        "aws-cli",
    ))
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)` → `SystemTime`. Just enough for the
/// `Expiration` the AWS CLI prints; `None` for anything else, which makes the
/// credentials count as non-expiring for this process and be re-fetched only
/// on a failure — never a panic.
fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let (date, rest) = text.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>());
    let (year, month, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (time, offset) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) => rest.split_at(i),
        None => (rest, "Z"),
    };
    let mut t = time.split(':');
    let hour = t.next()?.parse::<i64>().ok()?;
    let minute = t.next()?.parse::<i64>().ok()?;
    let second = t.next()?.split('.').next()?.parse::<i64>().ok()?;
    let offset_secs = match offset.chars().next() {
        Some('Z' | 'z') | None => 0,
        Some(sign) => {
            let (h, m) = offset[1..].split_once(':')?;
            let secs = h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60;
            if sign == '-' {
                -secs
            } else {
                secs
            }
        }
    };
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    let secs = u64::try_from(secs).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// Percent-encodes one URL path segment (RFC 3986 unreserved kept).
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_model_id_is_one_encoded_path_segment() {
        let bedrock = Bedrock {
            region: "us-east-1".into(),
            endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com".into(),
            bearer: None,
            cached: Mutex::new(None),
        };
        assert_eq!(
            bedrock.url("us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/\
             us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke"
        );
        assert_eq!(
            encode_segment("arn:aws:bedrock:us-east-1:1:inference-profile/x"),
            "arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fx"
        );
    }

    #[test]
    fn a_profile_section_is_read_from_the_shared_file() {
        let text = "[default]\naws_access_key_id = AKIADEFAULT\naws_secret_access_key=s0\n\n\
                    [work]\n# comment\naws_access_key_id=AKIAWORK\naws_secret_access_key = s1\n\
                    aws_session_token = tok\n";
        let work = ini_section(text, "work");
        assert_eq!(work["aws_access_key_id"], "AKIAWORK");
        assert_eq!(work["aws_session_token"], "tok");
        assert_eq!(ini_section(text, "default")["aws_secret_access_key"], "s0");
        assert!(ini_section(text, "missing").is_empty());
    }

    #[test]
    fn cli_process_credentials_carry_their_expiry() {
        let creds = parse_process_credentials(
            br#"{"Version":1,"AccessKeyId":"ASIA1","SecretAccessKey":"s","SessionToken":"t","Expiration":"2026-09-26T20:00:00+00:00"}"#,
        )
        .unwrap();
        assert_eq!(creds.access_key_id(), "ASIA1");
        assert_eq!(creds.session_token(), Some("t"));
        assert_eq!(
            creds.expiry(),
            parse_rfc3339("2026-09-26T20:00:00Z"),
            "offset form and Z form agree"
        );
        assert!(parse_process_credentials(b"not json").is_err());
    }

    #[test]
    fn rfc3339_timestamps_convert_exactly() {
        assert_eq!(
            parse_rfc3339("1970-01-01T00:00:00Z"),
            Some(SystemTime::UNIX_EPOCH)
        );
        assert_eq!(
            parse_rfc3339("2000-03-01T00:00:00Z"),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(951_868_800))
        );
        assert_eq!(
            parse_rfc3339("2026-09-26T21:30:15.123-01:30"),
            parse_rfc3339("2026-09-26T23:00:15Z")
        );
        assert_eq!(parse_rfc3339("garbage"), None);
    }

    #[tokio::test]
    async fn sigv4_signs_the_request_with_the_session_token() {
        let bedrock = Bedrock {
            region: "us-east-1".into(),
            endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com".into(),
            bearer: None,
            cached: Mutex::new(Some(Credentials::new(
                "AKIDEXAMPLE",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                Some("session".into()),
                None,
                "test",
            ))),
        };
        let url = bedrock.url("anthropic.claude-3-haiku-20240307-v1:0");
        let headers = bedrock.auth_headers(&url, b"{}").await.unwrap();
        let get = |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.as_str())
                .unwrap_or_default()
        };
        let auth = get("authorization");
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
            "{auth}"
        );
        assert!(auth.contains("/us-east-1/bedrock/aws4_request"), "{auth}");
        assert!(
            auth.contains("SignedHeaders=") && auth.contains("x-amz-date"),
            "{auth}"
        );
        assert_eq!(get("x-amz-security-token"), "session");
        assert!(!get("x-amz-date").is_empty());
    }

    #[tokio::test]
    async fn a_bedrock_api_key_is_a_bearer_token() {
        let bedrock = Bedrock {
            region: "us-east-1".into(),
            endpoint: "https://x".into(),
            bearer: Some("bedrock-key".into()),
            cached: Mutex::new(None),
        };
        assert_eq!(
            bedrock
                .auth_headers("https://x/model/m/invoke", b"{}")
                .await
                .unwrap(),
            vec![(
                "authorization".to_string(),
                "Bearer bedrock-key".to_string()
            )]
        );
    }
}
