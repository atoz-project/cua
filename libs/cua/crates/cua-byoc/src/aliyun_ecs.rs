// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Alibaba Cloud ECS (`--on aliyun-ecs`): sandboxes in your Alibaba Cloud
//! account over direct HTTPS OpenAPI V3 (`ACS3-HMAC-SHA256`) with
//! least-privilege RAM sub-account AccessKeys.
//!
//! Credentials resolve in precedence order:
//! 1. `--token-stdin` (`<access_key_id>:<access_key_secret>`)
//! 2. `ALIBABA_CLOUD_ACCESS_KEY_ID` + `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
//! 3. Explicit `--profile <name>` in `~/.aliyun/config.json` (`AK` mode)
//! 4. Saved credentials in the Cua credential store (`byoc-aliyun-ecs-token`)
//! 5. Active `current` profile in `~/.aliyun/config.json` (`AK` mode)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::Engine as _;
use cua_sandbox_core::Error;
use cua_sandbox_core::byoc::{CloudCredentials, CloudKind};
use cua_sandbox_core::placement::Runtime;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::aliyun_net::{self, NetLocks, NetworkConfig};
use crate::api::{
    CloudApi, Result, Secret, Target, Tested, cloud_err, retry_backoff, retryable_status,
};
use crate::model::{self, Capabilities, Connection, ProvisionSpec, Resource, Tier, tag};

/// Default Alibaba Cloud region when neither `--region` nor a CLI profile specifies one.
pub const DEFAULT_REGION: &str = "cn-hangzhou";

/// Name of the AccessKey pair in the Cua credential store.
pub const SECRET_NAME: &str = "byoc-aliyun-ecs-token";

/// Alibaba Cloud STS OpenAPI version.
pub const STS_API_VERSION: &str = "2015-04-01";
/// Alibaba Cloud ECS OpenAPI version.
pub const ECS_API_VERSION: &str = "2014-05-26";
/// Alibaba Cloud VPC OpenAPI version.
pub const VPC_API_VERSION: &str = "2016-04-28";

/// Default global STS endpoint.
pub const STS_ENDPOINT: &str = "https://sts.aliyuncs.com";

/// Default baseline Linux Docker-on-VM instance type (2 vCPU, 4 GiB).
pub const LINUX_INSTANCE_TYPE: &str = "ecs.e-c1m2.large";
/// Default baseline Linux-slim instance type (2 vCPU, 2 GiB).
pub const SLIM_INSTANCE_TYPE: &str = "ecs.e-c1m1.large";
/// Default baseline Windows Direct VM instance type (4 vCPU, 8 GiB).
pub const WINDOWS_INSTANCE_TYPE: &str = "ecs.c7.xlarge";

/// Where the Cua credential store keeps the AccessKey pair (and a fake in tests).
pub trait TokenStore: Send + Sync + 'static {
    /// The saved `<access_key_id>:<access_key_secret>` token, if any.
    fn load(&self) -> Option<String>;
    /// Saves the token (0600 or the OS vault).
    fn save(&self, token: &str) -> std::io::Result<()>;
    /// Removes it; returns whether there was one.
    fn clear(&self) -> bool;
}

/// The Cua credential store ([`cua_auth::Store`]).
pub struct CuaCredentialStore;

impl TokenStore for CuaCredentialStore {
    fn load(&self) -> Option<String> {
        let bytes = cua_auth::Store::from_env()
            .load_secret(SECRET_NAME)
            .ok()??;
        String::from_utf8(bytes)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    }

    fn save(&self, token: &str) -> std::io::Result<()> {
        cua_auth::Store::from_env()
            .save_secret(SECRET_NAME, token.as_bytes())
            .map_err(std::io::Error::other)
    }

    fn clear(&self) -> bool {
        cua_auth::Store::from_env()
            .clear_secret(SECRET_NAME)
            .unwrap_or(false)
    }
}

/// RAM AccessKey credentials in memory (never printed in `Debug`).
#[derive(Clone, PartialEq, Eq)]
pub struct AliyunCredentials {
    /// AccessKey ID.
    pub access_key_id: String,
    /// AccessKey Secret (wiped on drop, redacted in `Debug`).
    pub access_key_secret: Secret,
}

impl AliyunCredentials {
    /// Formats as `<access_key_id>:<access_key_secret>` for storage in `TokenStore`.
    pub fn to_pair(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!(
            "{}:{}",
            self.access_key_id,
            self.access_key_secret.expose()
        ))
    }
}

impl std::fmt::Debug for AliyunCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AliyunCredentials")
            .field("access_key_id", &"<redacted>")
            .field("access_key_secret", &self.access_key_secret)
            .finish()
    }
}

/// Parses `<access_key_id>:<access_key_secret>`.
pub fn parse_token_pair(raw: &str) -> std::result::Result<AliyunCredentials, String> {
    let trimmed = raw.trim();
    let Some((ak, sk)) = trimmed.split_once(':') else {
        return Err(
            "aliyun-ecs: expected <access_key_id>:<access_key_secret> (missing ':' separator)"
                .into(),
        );
    };
    let ak = ak.trim();
    let sk = sk.trim();
    if ak.is_empty()
        || sk.is_empty()
        || ak.chars().any(char::is_whitespace)
        || sk.chars().any(char::is_whitespace)
    {
        return Err(
            "aliyun-ecs: malformed AccessKey pair; expected non-empty <access_key_id>:<access_key_secret> with no whitespace"
                .into(),
        );
    }
    Ok(AliyunCredentials {
        access_key_id: ak.to_string(),
        access_key_secret: Secret::new(sk),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CredSource {
    TokenStdin,
    Env,
    ExplicitProfile(String),
    Saved,
    CurrentProfile(String),
}

impl CredSource {
    fn describe(&self) -> String {
        match self {
            CredSource::TokenStdin => "AccessKey passed via --token-stdin".into(),
            CredSource::Env => {
                "ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET".into()
            }
            CredSource::ExplicitProfile(p) => format!("~/.aliyun/config.json profile {p:?}"),
            CredSource::Saved => "AccessKey saved by `cua cloud connect aliyun-ecs`".into(),
            CredSource::CurrentProfile(p) => {
                format!("~/.aliyun/config.json active profile {p:?}")
            }
        }
    }
}

#[derive(Deserialize)]
struct AliyunCliConfig {
    #[serde(default)]
    current: String,
    #[serde(default)]
    profiles: Vec<AliyunCliProfile>,
}

#[derive(Deserialize)]
struct AliyunCliProfile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    access_key_secret: String,
    #[serde(default)]
    region_id: String,
}

/// Path to `~/.aliyun/config.json`, if `HOME` is set.
pub fn aliyun_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| !h.as_os_str().is_empty())
        .map(|h| h.join(".aliyun").join("config.json"))
}

fn read_cli_profile(
    path: &Path,
    explicit_name: Option<&str>,
) -> std::result::Result<Option<(String, AliyunCredentials, Option<String>)>, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if explicit_name.is_some() => {
            return Err(format!(
                "aliyun-ecs: profile {:?} requested, but {} could not be read: {e}",
                explicit_name.unwrap_or_default(),
                path.display()
            ));
        }
        Err(_) => return Ok(None),
    };

    let cfg: AliyunCliConfig = serde_json::from_str(&content)
        .map_err(|e| format!("aliyun-ecs: failed to parse {}: {e}", path.display()))?;

    let target_name = match explicit_name {
        Some(name) => name.trim(),
        None => {
            let cur = cfg.current.trim();
            if cur.is_empty() {
                return Ok(None);
            }
            cur
        }
    };

    let Some(prof) = cfg.profiles.iter().find(|p| p.name.trim() == target_name) else {
        if explicit_name.is_some() {
            return Err(format!(
                "aliyun-ecs: profile {target_name:?} not found in {}",
                path.display()
            ));
        }
        return Ok(None);
    };

    if !prof.mode.trim().eq_ignore_ascii_case("AK") {
        return Err(format!(
            "aliyun-ecs: profile {target_name:?} uses mode {:?}; only AK mode profiles (access_key_id + access_key_secret) are supported, or pass --token-stdin / ALIBABA_CLOUD_ACCESS_KEY_ID + ALIBABA_CLOUD_ACCESS_KEY_SECRET",
            prof.mode
        ));
    }

    let ak = prof.access_key_id.trim();
    let sk = prof.access_key_secret.trim();
    if ak.is_empty() || sk.is_empty() {
        return Err(format!(
            "aliyun-ecs: profile {target_name:?} in {} is missing access_key_id or access_key_secret",
            path.display()
        ));
    }

    let region = Some(prof.region_id.trim().to_ascii_lowercase()).filter(|r| !r.is_empty());
    Ok(Some((
        prof.name.trim().to_string(),
        AliyunCredentials {
            access_key_id: ak.to_string(),
            access_key_secret: Secret::new(sk),
        },
        region,
    )))
}

fn validate_region(region: &str) -> Result<String> {
    let r = region.trim().to_ascii_lowercase();
    let ok = !r.is_empty()
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !r.starts_with('-')
        && !r.ends_with('-');
    if !ok {
        return Err(Error::InvalidArgument(format!(
            "aliyun-ecs: invalid region {region:?} (expected e.g. cn-hangzhou, cn-shanghai, ap-southeast-1)"
        )));
    }
    Ok(r)
}

/// RFC 3986 percent-encoding: leaves `[A-Za-z0-9\-_.~]` unescaped, encodes all other bytes as `%XX`.
pub fn rfc3986_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Canonicalizes query parameters per RFC 3986 sorted by `(encoded_key, encoded_value)`.
pub fn canonical_query_string(params: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (rfc3986_encode(k), rfc3986_encode(v)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Computed `ACS3-HMAC-SHA256` signature headers for one OpenAPI V3 request.
#[derive(Clone, Debug)]
pub struct Acs3SignedHeaders {
    pub authorization: String,
    pub content_sha256: String,
    pub date: String,
    pub nonce: String,
    pub host: String,
}

/// Signs an Alibaba Cloud OpenAPI V3 request with `ACS3-HMAC-SHA256`.
#[allow(clippy::too_many_arguments)]
pub fn sign_acs3(
    method: &str,
    url: &url::Url,
    canonical_query: &str,
    action: &str,
    version: &str,
    body: &[u8],
    content_type: Option<&str>,
    timestamp_utc: &str,
    nonce: &str,
    creds: &AliyunCredentials,
) -> Acs3SignedHeaders {
    let host_str = url.host_str().unwrap_or("");
    let host = match url.port() {
        Some(p) => format!("{host_str}:{p}"),
        None => host_str.to_string(),
    };
    let content_sha256 = hex::encode(Sha256::digest(body));

    let mut hdrs: BTreeMap<&str, String> = BTreeMap::new();
    hdrs.insert("host", host.clone());
    hdrs.insert("x-acs-action", action.to_string());
    hdrs.insert("x-acs-content-sha256", content_sha256.clone());
    hdrs.insert("x-acs-date", timestamp_utc.to_string());
    hdrs.insert("x-acs-signature-nonce", nonce.to_string());
    hdrs.insert("x-acs-version", version.to_string());
    if let Some(ct) = content_type {
        hdrs.insert("content-type", ct.to_string());
    }

    let mut canonical_headers = String::new();
    let mut signed_headers = Vec::with_capacity(hdrs.len());
    for (k, v) in &hdrs {
        canonical_headers.push_str(&format!("{k}:{}\n", v.trim()));
        signed_headers.push(*k);
    }
    let signed_headers_str = signed_headers.join(";");
    let canonical_uri = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers_str,
        content_sha256
    );
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed_canonical}");

    let mut mac = Hmac::<Sha256>::new_from_slice(creds.access_key_secret.expose().as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
        creds.access_key_id, signed_headers_str, signature
    );

    Acs3SignedHeaders {
        authorization,
        content_sha256,
        date: timestamp_utc.to_string(),
        nonce: nonce.to_string(),
        host,
    }
}

/// Alibaba Cloud ECS provider (`--on aliyun-ecs`).
pub struct AliyunEcs {
    http: reqwest::Client,
    sts_endpoint: String,
    ecs_endpoint_override: Option<String>,
    vpc_endpoint_override: Option<String>,
    store: Arc<dyn TokenStore>,
    staged: Mutex<Option<std::result::Result<AliyunCredentials, String>>>,
    aliyun_config: Option<PathBuf>,
    net_locks: NetLocks,
    poll: Duration,
}

impl Default for AliyunEcs {
    fn default() -> Self {
        Self::new()
    }
}

impl AliyunEcs {
    /// Creates an `AliyunEcs` client targeting real Alibaba Cloud endpoints and `cua_auth::Store`.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
            sts_endpoint: STS_ENDPOINT.to_string(),
            ecs_endpoint_override: None,
            vpc_endpoint_override: None,
            store: Arc::new(CuaCredentialStore),
            staged: Mutex::new(None),
            aliyun_config: aliyun_config_path(),
            net_locks: NetLocks::new(),
            poll: Duration::from_secs(2),
        }
    }

    /// Creates an `AliyunEcs` client with custom endpoints, `TokenStore`, and `~/.aliyun/config.json` path (for tests).
    pub fn with_endpoints(
        ecs_url: &str,
        sts_url: &str,
        vpc_url: &str,
        store: Arc<dyn TokenStore>,
        aliyun_config: Option<PathBuf>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
            sts_endpoint: sts_url.trim_end_matches('/').to_string(),
            ecs_endpoint_override: Some(ecs_url.trim_end_matches('/').to_string()),
            vpc_endpoint_override: Some(vpc_url.trim_end_matches('/').to_string()),
            store,
            staged: Mutex::new(None),
            aliyun_config,
            net_locks: NetLocks::new(),
            poll: Duration::from_secs(2),
        }
    }

    /// Overrides the polling interval for state waits and dependency retries (for fast tests).
    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    pub(crate) fn poll_interval(&self) -> Duration {
        self.poll
    }

    pub(crate) fn profile_hint<'a>(&self, conn: &'a Connection) -> Option<&'a str> {
        (!conn.profile.is_empty()).then_some(conn.profile.as_str())
    }
    pub(crate) fn ecs_endpoint(&self, region: &str) -> String {
        self.ecs_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ecs.{region}.aliyuncs.com"))
    }

    pub(crate) fn vpc_endpoint(&self, region: &str) -> String {
        self.vpc_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://vpc.{region}.aliyuncs.com"))
    }

    fn env_credentials() -> std::result::Result<Option<AliyunCredentials>, String> {
        let id = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let secret = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match (id, secret) {
            (Some(ak), Some(sk)) => Ok(Some(AliyunCredentials {
                access_key_id: ak,
                access_key_secret: Secret::new(sk),
            })),
            (Some(_), None) | (None, Some(_)) => Err(
                "aliyun-ecs: both ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET must be set (only one was provided)"
                    .into(),
            ),
            (None, None) => Ok(None),
        }
    }

    fn resolve_credentials(
        &self,
        profile_hint: Option<&str>,
    ) -> Result<(AliyunCredentials, CredSource)> {
        // 1. --token-stdin
        if let Some(res) = self.staged.lock().unwrap().clone() {
            let creds = res.map_err(Error::InvalidArgument)?;
            return Ok((creds, CredSource::TokenStdin));
        }

        // 2. Environment variables
        if let Some(creds) = Self::env_credentials().map_err(Error::ContribNotConfigured)? {
            return Ok((creds, CredSource::Env));
        }

        // 3. Explicit --profile <name>
        let explicit = profile_hint.map(str::trim).filter(|s| !s.is_empty());
        if let Some(name) = explicit {
            let Some(path) = self.aliyun_config.as_deref() else {
                return Err(Error::ContribNotConfigured(format!(
                    "aliyun-ecs: profile {name:?} requested, but HOME is not set to locate ~/.aliyun/config.json"
                )));
            };
            let (_, creds, _) = read_cli_profile(path, Some(name))
                .map_err(Error::ContribNotConfigured)?
                .ok_or_else(|| {
                    Error::ContribNotConfigured(format!(
                        "aliyun-ecs: profile {name:?} not found in {}",
                        path.display()
                    ))
                })?;
            return Ok((creds, CredSource::ExplicitProfile(name.to_string())));
        }

        // 4. Saved credentials in TokenStore
        if let Some(saved) = self.store.load() {
            let creds = parse_token_pair(&saved).map_err(Error::ContribNotConfigured)?;
            return Ok((creds, CredSource::Saved));
        }

        // 5. Active `current` profile in ~/.aliyun/config.json
        if let Some(path) = self.aliyun_config.as_deref()
            && let Some((name, creds, _)) =
                read_cli_profile(path, None).map_err(Error::ContribNotConfigured)?
        {
            return Ok((creds, CredSource::CurrentProfile(name)));
        }

        Err(Error::ContribNotConfigured(
            "aliyun-ecs: no Alibaba Cloud credentials found; pass `<access_key_id>:<access_key_secret>` via `--token-stdin`, set `ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, or configure an `AK` mode profile (`--profile` or active `current` profile in `~/.aliyun/config.json`)"
                .into(),
        ))
    }

    pub(crate) async fn call_raw(
        &self,
        endpoint: &str,
        method: &str,
        action: &str,
        version: &str,
        params: &[(String, String)],
        profile_hint: Option<&str>,
    ) -> Result<(reqwest::StatusCode, ApiBody)> {
        let is_post = method.eq_ignore_ascii_case("POST");
        let idempotent = method.eq_ignore_ascii_case("GET");
        let (creds, _) = self.resolve_credentials(profile_hint)?;
        let base = endpoint.trim_end_matches('/');
        let encoded = canonical_query_string(params);
        let (full_url, canonical_query, body_bytes, content_type): (_, _, Vec<u8>, Option<&str>) =
            if is_post && !encoded.is_empty() {
                (
                    format!("{base}/"),
                    String::new(),
                    encoded.into_bytes(),
                    Some("application/x-www-form-urlencoded"),
                )
            } else if encoded.is_empty() {
                (format!("{base}/"), String::new(), Vec::new(), None)
            } else {
                (format!("{base}/?{encoded}"), encoded, Vec::new(), None)
            };
        let parsed = url::Url::parse(&full_url)
            .map_err(|e| cloud_err("aliyun-ecs", action, format!("invalid URL: {e}")))?;

        let mut tries = 0u32;
        loop {
            let now_ts = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
            let nonce = format!("{:032x}", rand::random::<u128>());
            let signed = sign_acs3(
                method,
                &parsed,
                &canonical_query,
                action,
                version,
                &body_bytes,
                content_type,
                &now_ts,
                &nonce,
                &creds,
            );
            let req_method = match method {
                "POST" => reqwest::Method::POST,
                _ => reqwest::Method::GET,
            };
            let mut req = self
                .http
                .request(req_method, parsed.as_str())
                .header("host", &signed.host)
                .header("x-acs-action", action)
                .header("x-acs-version", version)
                .header("x-acs-date", &signed.date)
                .header("x-acs-signature-nonce", &signed.nonce)
                .header("x-acs-content-sha256", &signed.content_sha256)
                .header("authorization", &signed.authorization);
            if let Some(ct) = content_type {
                req = req.header("content-type", ct);
            }
            if !body_bytes.is_empty() {
                req = req.body(body_bytes.clone());
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    if idempotent {
                        tries += 1;
                        if let Some(wait) = retry_backoff(tries) {
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                    }
                    return Err(cloud_err("aliyun-ecs", action, e));
                }
            };

            let status = resp.status();
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    if idempotent {
                        tries += 1;
                        if let Some(wait) = retry_backoff(tries) {
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                    }
                    return Err(cloud_err(
                        "aliyun-ecs",
                        action,
                        format!("failed to read HTTP {status} response body: {e}"),
                    ));
                }
            };

            if retryable_status(status.as_u16(), idempotent) {
                tries += 1;
                if let Some(wait) = retry_backoff(tries) {
                    tokio::time::sleep(wait).await;
                    continue;
                }
            }

            if status.is_success() {
                if bytes.is_empty() {
                    return Err(cloud_err(
                        "aliyun-ecs",
                        action,
                        format!("empty response body on HTTP {status}"),
                    ));
                }
                let v: Value = serde_json::from_slice(&bytes).map_err(|e| {
                    let snippet = sanitize_snippet(&bytes);
                    cloud_err(
                        "aliyun-ecs",
                        action,
                        format!("invalid JSON response on HTTP {status}: {e} (body: {snippet})"),
                    )
                })?;
                if !v.is_object() {
                    let snippet = sanitize_snippet(&bytes);
                    return Err(cloud_err(
                        "aliyun-ecs",
                        action,
                        format!("unexpected non-object JSON response on HTTP {status}: {snippet}"),
                    ));
                }
                return Ok((status, ApiBody::Json(v)));
            }

            let body = match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) if v.is_object() => ApiBody::Json(v),
                _ => ApiBody::Text(sanitize_snippet(&bytes)),
            };
            return Ok((status, body));
        }
    }

    pub(crate) async fn call_ok(
        &self,
        endpoint: &str,
        method: &str,
        action: &str,
        version: &str,
        params: &[(String, String)],
        profile_hint: Option<&str>,
    ) -> Result<Value> {
        let (status, body) = self
            .call_raw(endpoint, method, action, version, params, profile_hint)
            .await?;
        if !status.is_success() {
            return Err(map_api_error(action, version, status, &body));
        }
        match body {
            ApiBody::Json(v) => Ok(v),
            ApiBody::Text(s) => Err(cloud_err(
                "aliyun-ecs",
                action,
                format!("unexpected non-JSON response on HTTP {status}: {s}"),
            )),
        }
    }

    async fn resolve_ubuntu_image(&self, conn: &Connection, region: &str) -> Result<String> {
        let profile_hint = self.profile_hint(conn);
        let v = self
            .call_ok(
                &self.ecs_endpoint(region),
                "GET",
                "DescribeImages",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("ImageOwnerAlias".into(), "system".into()),
                    ("OSType".into(), "linux".into()),
                    ("Status".into(), "Available".into()),
                    ("ImageName".into(), "ubuntu_24_04_x64*".into()),
                    ("Architecture".into(), "x86_64".into()),
                    ("PageSize".into(), "50".into()),
                ],
                profile_hint,
            )
            .await?;

        let best = v["Images"]["Image"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|img| {
                img["Status"]
                    .as_str()
                    .is_none_or(|s| s.eq_ignore_ascii_case("Available"))
            })
            .filter(|img| {
                img["ImageId"]
                    .as_str()
                    .is_some_and(|id| !id.trim().is_empty())
            })
            .max_by(|a, b| {
                let ca = a["CreationTime"].as_str().unwrap_or("");
                let cb = b["CreationTime"].as_str().unwrap_or("");
                ca.cmp(cb)
            });

        best.and_then(|img| img["ImageId"].as_str())
            .map(|s| s.trim().to_string())
            .ok_or_else(|| {
                cloud_err(
                    "aliyun-ecs",
                    "DescribeImages",
                    format!("no Ubuntu 24.04 system image found in {region}"),
                )
            })
    }

    async fn guard(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
        verb: &str,
    ) -> Result<Option<String>> {
        let Some((state, tags)) = self.describe(conn, r).await? else {
            return Ok(None);
        };
        if !model::is_ours(&tags, owner) {
            return Err(Error::Cloud(format!(
                "aliyun-ecs: refusing to {verb} {} {} (it does not carry {}=true and {}={})",
                r.resource_type,
                r.id,
                tag::MANAGED,
                tag::OWNER,
                model::label_value(owner)
            )));
        }
        Ok(Some(state))
    }
}

pub(crate) enum ApiBody {
    Json(Value),
    Text(String),
}

fn sanitize_snippet(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut last_ws = false;
    for ch in raw.chars() {
        if out.chars().count() >= 200 {
            out.push_str("...");
            break;
        }
        if ch.is_control() || ch.is_whitespace() {
            if !last_ws && !out.is_empty() {
                out.push(' ');
                last_ws = true;
            }
        } else {
            out.push(ch);
            last_ws = false;
        }
    }
    out.trim().to_string()
}

pub(crate) fn api_error_code_message(v: &Value) -> (&str, &str) {
    let code = v["Code"].as_str().unwrap_or("");
    let msg = v["Message"].as_str().unwrap_or("");
    (code, msg)
}

pub(crate) fn map_api_error(
    action: &str,
    version: &str,
    status: reqwest::StatusCode,
    body: &ApiBody,
) -> Error {
    let svc = match version {
        STS_API_VERSION => "sts",
        VPC_API_VERSION => "vpc",
        _ => "ecs",
    };
    let perm = format!("{svc}:{action}");
    match body {
        ApiBody::Text(snippet) => {
            if snippet.is_empty() {
                cloud_err("aliyun-ecs", action, format!("HTTP {status} (empty body)"))
            } else {
                cloud_err("aliyun-ecs", action, format!("HTTP {status}: {snippet}"))
            }
        }
        ApiBody::Json(v) => {
            let (code, msg) = api_error_code_message(v);
            match code {
                "InvalidAccessKeyId.NotFound"
                | "SignatureDoesNotMatch"
                | "IncompleteSignature"
                | "InvalidSecurityToken" => cloud_err(
                    "aliyun-ecs",
                    action,
                    format!(
                        "{code}: {msg} (check your AccessKey ID and Secret via --token-stdin, ALIBABA_CLOUD_ACCESS_KEY_ID/SECRET, or ~/.aliyun/config.json)"
                    ),
                ),
                "Forbidden.RAM"
                | "Forbidden.Unauthorized"
                | "UnauthorizedOperation"
                | "NoPermission" => cloud_err(
                    "aliyun-ecs",
                    action,
                    format!(
                        "{code}: RAM user is missing permission `{perm}` ({msg}); attach the Cua BYOC least-privilege RAM policy"
                    ),
                ),
                "" => cloud_err(
                    "aliyun-ecs",
                    action,
                    format!(
                        "HTTP {status}: {}",
                        sanitize_snippet(v.to_string().as_bytes())
                    ),
                ),
                _ => cloud_err("aliyun-ecs", action, format!("{code}: {msg}")),
            }
        }
    }
}

fn state_of(s: &str) -> String {
    match s {
        "Pending" | "Starting" => "pending".into(),
        "Running" => "running".into(),
        "Stopping" => "stopping".into(),
        "Stopped" => "stopped".into(),
        _ => s.to_ascii_lowercase(),
    }
}

fn sanitize_hostname(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    s = s.trim_matches(['-', '.']).to_string();
    if s.len() > 63 {
        s.truncate(63);
        s = s.trim_end_matches(['-', '.']).to_string();
    }
    if s.len() < 2 { "cua-sandbox".into() } else { s }
}

fn is_zone_capacity_error(code: &str) -> bool {
    matches!(
        code,
        "OperationDenied.NoStock"
            | "OperationDenied.ZoneSoldOut"
            | "Zone.NotOnSale"
            | "InstanceType.NotOnSale"
            | "InvalidInstanceType.NotSupported"
            | "InvalidInstanceType.ValueNotSupported"
            | "InvalidResource.NotEnough"
            | "InsufficientInstanceCapacity"
            | "InsufficientCapacity"
            | "ResourceInsufficient"
    )
}

fn is_instance_not_found(code: &str) -> bool {
    matches!(
        code,
        "InvalidInstanceId.NotFound" | "InvalidInstanceID.NotFound"
    )
}

/// Resolves the ECS instance type for `spec` (modular helper for `#5` / `#6`).
pub fn instance_type_for(spec: &ProvisionSpec) -> &str {
    let explicit = spec.machine_type.trim();
    if !explicit.is_empty() {
        return explicit;
    }
    match spec.family.as_str() {
        "windows" => WINDOWS_INSTANCE_TYPE,
        "linux-slim" => SLIM_INSTANCE_TYPE,
        _ => LINUX_INSTANCE_TYPE,
    }
}

/// Resolves the `(size_gib, category)` system disk parameters for `spec`.
pub fn system_disk_for(spec: &ProvisionSpec) -> (u32, &'static str) {
    let min_gb = if spec.family == "windows" { 60 } else { 40 };
    (spec.disk_gb.max(min_gb), "cloud_essd")
}

impl AliyunEcs {
    async fn discover_windows_image(
        &self,
        ecs: &str,
        region: &str,
        profile_hint: Option<&str>,
    ) -> Result<String> {
        let v = self
            .call_ok(
                ecs,
                "GET",
                "DescribeImages",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.into()),
                    ("ImageOwnerAlias".into(), "system".into()),
                    ("OSType".into(), "windows".into()),
                    ("Status".into(), "Available".into()),
                    ("Architecture".into(), "x86_64".into()),
                    ("PageSize".into(), "50".into()),
                ],
                profile_hint,
            )
            .await?;
        let imgs = v["Images"]["Image"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let score = |img: &Value| -> u8 {
            let name = img["ImageName"].as_str().unwrap_or("").to_ascii_lowercase();
            let en = img["OSNameEn"].as_str().unwrap_or("").to_ascii_lowercase();
            let is_2022 = name.contains("2022") || en.contains("2022");
            let is_en = name.contains("en-us") || name.contains("_en_") || en.contains("english");
            match (is_2022, is_en) {
                (true, true) => 3,
                (true, false) => 2,
                (false, true) => 1,
                (false, false) => 0,
            }
        };
        imgs.iter()
            .filter(|img| {
                img["Status"]
                    .as_str()
                    .is_none_or(|s| s.eq_ignore_ascii_case("Available"))
            })
            .filter(|img| {
                img["ImageId"]
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty())
            })
            .max_by(|a, b| {
                score(a).cmp(&score(b)).then_with(|| {
                    let ca = a["CreationTime"].as_str().unwrap_or("");
                    let cb = b["CreationTime"].as_str().unwrap_or("");
                    ca.cmp(cb)
                })
            })
            .and_then(|img| img["ImageId"].as_str())
            .map(|s| s.trim().to_string())
            .ok_or_else(|| {
                Error::Cloud(format!(
                    "aliyun-ecs: no official Windows Server x86_64 image found in {region}"
                ))
            })
    }
}

#[async_trait]
impl CloudApi for AliyunEcs {
    fn name(&self) -> &'static str {
        "aliyun-ecs"
    }

    fn title(&self) -> &'static str {
        "Alibaba Cloud ECS"
    }

    fn tier(&self) -> Tier {
        Tier::Vm
    }

    fn arches(&self) -> Vec<&'static str> {
        vec!["amd64"]
    }

    fn runtimes(&self) -> Vec<Runtime> {
        vec![
            Runtime::Other("docker".into()),
            Runtime::Other("native".into()),
        ]
    }

    fn supported_oses(&self) -> &'static [&'static str] {
        &["linux", "windows"]
    }

    fn default_disk_gb(&self, family: &str) -> u32 {
        match family {
            "windows" => 60,
            "linux" | "linux-slim" => 40,
            _ => crate::provider::disk_for(family),
        }
    }

    fn check_size_for(
        &self,
        family: &str,
        cpus: u32,
        memory_mb: u64,
    ) -> (Option<u32>, Option<u64>) {
        if family == "windows" {
            (Some(cpus.max(4)), Some(memory_mb.max(8192)))
        } else {
            (
                Some(cpus).filter(|c| *c > 0),
                Some(memory_mb).filter(|m| *m > 0),
            )
        }
    }

    fn detect(&self) -> CloudCredentials {
        if let Some(Ok(_)) = self.staged.lock().unwrap().as_ref() {
            return CloudCredentials {
                found: true,
                source: CredSource::TokenStdin.describe(),
            };
        }
        if matches!(Self::env_credentials(), Ok(Some(_))) {
            return CloudCredentials {
                found: true,
                source: CredSource::Env.describe(),
            };
        }
        if self
            .store
            .load()
            .as_deref()
            .is_some_and(|s| parse_token_pair(s).is_ok())
        {
            return CloudCredentials {
                found: true,
                source: CredSource::Saved.describe(),
            };
        }
        if let Some(path) = self.aliyun_config.as_deref()
            && let Ok(Some((name, _, _))) = read_cli_profile(path, None)
        {
            return CloudCredentials {
                found: true,
                source: CredSource::CurrentProfile(name).describe(),
            };
        }
        CloudCredentials::default()
    }

    fn resolve(&self, t: &Target) -> Result<Connection> {
        let using_inline_or_env = t.token.is_some()
            || self.staged.lock().unwrap().is_some()
            || matches!(Self::env_credentials(), Ok(Some(_)));

        let mut profile = if using_inline_or_env {
            String::new()
        } else {
            t.profile
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_default()
        };

        let cli_profile =
            if !using_inline_or_env && (!profile.is_empty() || self.store.load().is_none()) {
                self.aliyun_config.as_deref().and_then(|p| {
                    read_cli_profile(p, (!profile.is_empty()).then_some(profile.as_str()))
                        .ok()
                        .flatten()
                })
            } else {
                None
            };

        if profile.is_empty()
            && !using_inline_or_env
            && self.store.load().is_none()
            && let Some((name, _, _)) = &cli_profile
        {
            profile = name.clone();
        }

        let region_raw = match t.region.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => r.to_string(),
            None => cli_profile
                .and_then(|(_, _, r)| r)
                .unwrap_or_else(|| DEFAULT_REGION.to_string()),
        };
        let region = validate_region(&region_raw)?;
        let (vpc_id, vswitch_id) = match crate::aliyun_existing_vpc::normalize_existing_vpc(
            t.vpc_id.as_deref(),
            t.vswitch_id.as_deref(),
        )? {
            Some((v, w)) => (Some(v), Some(w)),
            None => (None, None),
        };

        Ok(Connection {
            provider: "aliyun-ecs".into(),
            profile,
            region,
            ttl_hours: model::DEFAULT_TTL_HOURS,
            vpc_id,
            vswitch_id,
            no_public_ip: t.no_public_ip,
            ..Default::default()
        })
    }

    fn stage_secret(&self, t: &Target) {
        let mut guard = self.staged.lock().unwrap();
        match t.token.as_deref() {
            Some(raw) => *guard = Some(parse_token_pair(raw)),
            None => *guard = None,
        }
    }

    fn persist_secret(&self) -> Result<()> {
        let staged = self.staged.lock().unwrap().take();
        let to_save = match staged {
            Some(Ok(creds)) => Some(creds),
            Some(Err(e)) => return Err(Error::InvalidArgument(e)),
            None => match Self::env_credentials() {
                Ok(Some(creds)) => Some(creds),
                _ => None,
            },
        };
        if let Some(creds) = to_save {
            self.store.save(&creds.to_pair()).map_err(Error::Io)?;
        }
        Ok(())
    }

    fn forget_secret(&self) {
        *self.staged.lock().unwrap() = None;
        self.store.clear();
    }

    fn unstage_secret(&self) {
        *self.staged.lock().unwrap() = None;
    }

    fn kinds(&self, _: &Connection) -> Vec<CloudKind> {
        vec![
            CloudKind {
                image: "linux".into(),
                kind: "container".into(),
                supported: true,
                reason: "one ECS VM running Docker on Ubuntu 24.04".into(),
                machine_type: LINUX_INSTANCE_TYPE.into(),
                usd_per_hour: 0.043,
            },
            CloudKind {
                image: "linux-slim".into(),
                kind: "container".into(),
                supported: true,
                reason: "one ECS VM running Docker on Ubuntu 24.04".into(),
                machine_type: SLIM_INSTANCE_TYPE.into(),
                usd_per_hour: 0.030,
            },
            CloudKind {
                image: "windows".into(),
                kind: "vm".into(),
                supported: true,
                reason: "Windows Direct VM Sandbox".into(),
                machine_type: WINDOWS_INSTANCE_TYPE.into(),
                usd_per_hour: 0.125,
            },
            CloudKind {
                image: "omarchy".into(),
                kind: "vm".into(),
                supported: false,
                reason: "omarchy is not offered on Alibaba Cloud ECS".into(),
                ..Default::default()
            },
            CloudKind {
                image: "macos".into(),
                kind: "vm".into(),
                supported: false,
                reason: "macOS runs only on Apple hardware; Alibaba Cloud ECS has none".into(),
                ..Default::default()
            },
        ]
    }

    async fn test(&self, conn: &Connection) -> Tested {
        let mut t = Tested::default();
        let profile_hint = (!conn.profile.is_empty()).then_some(conn.profile.as_str());

        let (_, source) = match self.resolve_credentials(profile_hint) {
            Ok(v) => v,
            Err(e) => {
                t.check("credentials", false, e.to_string());
                return t;
            }
        };

        // 1. Credentials: sts:GetCallerIdentity
        let identity = match self
            .call_ok(
                &self.sts_endpoint,
                "GET",
                "GetCallerIdentity",
                STS_API_VERSION,
                &[],
                profile_hint,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                t.check("credentials", false, e.to_string());
                return t;
            }
        };
        let account_id = identity["AccountId"]
            .as_str()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        if account_id.is_empty() {
            t.check(
                "credentials",
                false,
                "sts:GetCallerIdentity returned an empty AccountId",
            );
            return t;
        }
        t.account = account_id.clone();
        t.check(
            "credentials",
            true,
            format!("{}; account {account_id}", source.describe()),
        );

        let ecs = self.ecs_endpoint(&conn.region);
        let vpc = self.vpc_endpoint(&conn.region);

        // 2. Region: ecs:DescribeRegions
        match self
            .call_ok(
                &ecs,
                "GET",
                "DescribeRegions",
                ECS_API_VERSION,
                &[],
                profile_hint,
            )
            .await
        {
            Ok(v) => {
                let found = v["Regions"]["Region"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|r| r["RegionId"].as_str() == Some(conn.region.as_str()));
                if found {
                    t.check("region", true, format!("{} available", conn.region));
                } else {
                    t.check(
                        "region",
                        false,
                        format!("region {:?} is not enabled in this account", conn.region),
                    );
                    return t;
                }
            }
            Err(e) => {
                t.check("region", false, e.to_string());
                return t;
            }
        }

        // 3. Machine offerings: ecs:DescribeAvailableResource
        let mut discovered_type = LINUX_INSTANCE_TYPE.to_string();
        match self
            .call_ok(
                &ecs,
                "GET",
                "DescribeAvailableResource",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), conn.region.clone()),
                    ("DestinationResource".into(), "InstanceType".into()),
                    ("InstanceChargeType".into(), "PostPaid".into()),
                    ("IoOptimized".into(), "optimized".into()),
                ],
                profile_hint,
            )
            .await
        {
            Ok(v) => {
                let mut available_types = Vec::new();
                for zone in v["AvailableZones"]["AvailableZone"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    for ar in zone["AvailableResources"]["AvailableResource"]
                        .as_array()
                        .into_iter()
                        .flatten()
                    {
                        for sr in ar["SupportedResources"]["SupportedResource"]
                            .as_array()
                            .into_iter()
                            .flatten()
                        {
                            let status = sr["Status"].as_str().unwrap_or("");
                            if status == "Available"
                                && let Some(val) = sr["Value"].as_str()
                                && !available_types.iter().any(|x| x == val)
                            {
                                available_types.push(val.to_string());
                            }
                        }
                    }
                }
                if available_types.is_empty() {
                    t.check(
                        "machine",
                        false,
                        format!(
                            "no PostPaid ECS instance types available in {}",
                            conn.region
                        ),
                    );
                    return t;
                }
                if let Some(preferred) = available_types
                    .iter()
                    .find(|x| x.as_str() == LINUX_INSTANCE_TYPE)
                    .or_else(|| available_types.first())
                {
                    discovered_type = preferred.clone();
                }
                t.check(
                    "machine",
                    true,
                    format!(
                        "{} instance types in {}; baseline {} (~$0.043/h)",
                        available_types.len(),
                        conn.region,
                        discovered_type
                    ),
                );
            }
            Err(e) => {
                t.check("machine", false, e.to_string());
                return t;
            }
        }

        // 4. Image lookup: ecs:DescribeImages (Ubuntu 24.04)
        let discovered_image = match self.resolve_ubuntu_image(conn, &conn.region).await {
            Ok(img_id) => {
                t.check("image", true, format!("Ubuntu 24.04 ({img_id})"));
                img_id
            }
            Err(e) => {
                t.check("image", false, e.to_string());
                return t;
            }
        };

        // 4b. Existing VPC / VSwitch validation when configured (#8).
        let existing_vpc_pair = conn.vpc_id.as_deref().zip(conn.vswitch_id.as_deref());
        if let Some((vpc_id, vswitch_id)) = existing_vpc_pair {
            match crate::aliyun_existing_vpc::validate_existing_vpc(
                self,
                &conn.region,
                vpc_id,
                vswitch_id,
                profile_hint,
            )
            .await
            {
                Ok(info) => {
                    t.check(
                        "vpc",
                        true,
                        format!(
                            "VPC {vpc_id} / VSwitch {vswitch_id} available in {} ({})",
                            conn.region,
                            if info.zone_id.is_empty() {
                                "zone unknown"
                            } else {
                                info.zone_id.as_str()
                            }
                        ),
                    );
                }
                Err(e) => {
                    t.check("vpc", false, e.to_string());
                    return t;
                }
            }
        }

        // 5. Permissions: DescribeInstances, DescribeVpcs, DescribeVSwitches, DescribeSecurityGroups,
        //    CreateVpc DryRun=true (isolated mode), CreateSecurityGroup DryRun=true, RunInstances DryRun=true
        if let Err(e) = self
            .call_ok(
                &ecs,
                "GET",
                "DescribeInstances",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), conn.region.clone()),
                    ("PageSize".into(), "1".into()),
                ],
                profile_hint,
            )
            .await
        {
            t.check("permissions", false, e.to_string());
            return t;
        }

        let (first_vpc_id, vsw_id, vsw_vpc_id, matching_sg_id) =
            if let Some((vpc_id, vswitch_id)) = existing_vpc_pair {
                let sgs = match self
                    .call_ok(
                        &ecs,
                        "GET",
                        "DescribeSecurityGroups",
                        ECS_API_VERSION,
                        &[
                            ("RegionId".into(), conn.region.clone()),
                            ("VpcId".into(), vpc_id.to_string()),
                            ("PageSize".into(), "50".into()),
                        ],
                        profile_hint,
                    )
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        t.check("permissions", false, e.to_string());
                        return t;
                    }
                };
                let sg_id = sgs["SecurityGroups"]["SecurityGroup"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|sg| {
                        sg["VpcId"].as_str() == Some(vpc_id)
                            && aliyun_net::tags_of(sg)
                                .get(tag::MANAGED)
                                .map(String::as_str)
                                == Some("true")
                    })
                    .and_then(|sg| sg["SecurityGroupId"].as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                (
                    Some(vpc_id.to_string()),
                    Some(vswitch_id.to_string()),
                    Some(vpc_id.to_string()),
                    sg_id,
                )
            } else {
                let vpcs = match self
                    .call_ok(
                        &vpc,
                        "GET",
                        "DescribeVpcs",
                        VPC_API_VERSION,
                        &[
                            ("RegionId".into(), conn.region.clone()),
                            ("PageSize".into(), "1".into()),
                        ],
                        profile_hint,
                    )
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        t.check("permissions", false, e.to_string());
                        return t;
                    }
                };
                let first_vpc_id = vpcs["Vpcs"]["Vpc"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|x| x["VpcId"].as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);

                let vsw = match self
                    .call_ok(
                        &vpc,
                        "GET",
                        "DescribeVSwitches",
                        VPC_API_VERSION,
                        &[
                            ("RegionId".into(), conn.region.clone()),
                            ("PageSize".into(), "1".into()),
                        ],
                        profile_hint,
                    )
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        t.check("permissions", false, e.to_string());
                        return t;
                    }
                };

                let first_vsw = vsw["VSwitches"]["VSwitch"]
                    .as_array()
                    .and_then(|a| a.first());
                let vsw_id = first_vsw
                    .and_then(|x| x["VSwitchId"].as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let vsw_vpc_id = first_vsw
                    .and_then(|x| x["VpcId"].as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);

                let mut sg_params = vec![
                    ("RegionId".into(), conn.region.clone()),
                    ("PageSize".into(), "10".into()),
                ];
                if let Some(ref vpc_id) = vsw_vpc_id {
                    sg_params.push(("VpcId".into(), vpc_id.clone()));
                }
                let sgs = match self
                    .call_ok(
                        &ecs,
                        "GET",
                        "DescribeSecurityGroups",
                        ECS_API_VERSION,
                        &sg_params,
                        profile_hint,
                    )
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        t.check("permissions", false, e.to_string());
                        return t;
                    }
                };

                let matching_sg_id = vsw_vpc_id.as_deref().and_then(|vpc_id| {
                    sgs["SecurityGroups"]["SecurityGroup"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|sg| sg["VpcId"].as_str() == Some(vpc_id))
                        .and_then(|sg| sg["SecurityGroupId"].as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                });
                (first_vpc_id, vsw_id, vsw_vpc_id, matching_sg_id)
            };

        if existing_vpc_pair.is_none() {
            let vpc_dry_params = vec![
                ("RegionId".into(), conn.region.clone()),
                ("CidrBlock".into(), aliyun_net::VPC_CIDR.into()),
                ("VpcName".into(), "cua-sb-dryrun".into()),
                ("Tag.1.Key".into(), tag::MANAGED.into()),
                ("Tag.1.Value".into(), "true".into()),
                ("DryRun".into(), "true".into()),
            ];
            match self
                .call_raw(
                    &vpc,
                    "POST",
                    "CreateVpc",
                    VPC_API_VERSION,
                    &vpc_dry_params,
                    profile_hint,
                )
                .await
            {
                Ok((status, body)) => {
                    let code = match &body {
                        ApiBody::Json(v) => api_error_code_message(v).0,
                        ApiBody::Text(_) => "",
                    };
                    if status.is_success() || code != "DryRunOperation" {
                        t.check(
                            "permissions",
                            false,
                            map_api_error("CreateVpc", VPC_API_VERSION, status, &body).to_string(),
                        );
                        return t;
                    }
                }
                Err(e) => {
                    t.check("permissions", false, e.to_string());
                    return t;
                }
            }
        }

        let sg_vpc_id = vsw_vpc_id.or(first_vpc_id);
        let mut sg_dry_params = vec![
            ("RegionId".into(), conn.region.clone()),
            ("SecurityGroupName".into(), "cua-sandboxes-dryrun".into()),
            ("SecurityGroupType".into(), "enterprise".into()),
            ("Tag.1.Key".into(), tag::MANAGED.into()),
            ("Tag.1.Value".into(), "true".into()),
            ("DryRun".into(), "true".into()),
        ];
        let has_vpc = if let Some(ref vpc_id) = sg_vpc_id {
            sg_dry_params.push(("VpcId".into(), vpc_id.clone()));
            true
        } else {
            false
        };
        match self
            .call_raw(
                &ecs,
                "POST",
                "CreateSecurityGroup",
                ECS_API_VERSION,
                &sg_dry_params,
                profile_hint,
            )
            .await
        {
            Ok((status, body)) => {
                let code = match &body {
                    ApiBody::Json(v) => api_error_code_message(v).0,
                    ApiBody::Text(_) => "",
                };
                let ok_dry = !status.is_success()
                    && (code == "DryRunOperation" || (!has_vpc && code == "InvalidVpcId.NotFound"));
                if !ok_dry {
                    t.check(
                        "permissions",
                        false,
                        map_api_error("CreateSecurityGroup", ECS_API_VERSION, status, &body)
                            .to_string(),
                    );
                    return t;
                }
            }
            Err(e) => {
                t.check("permissions", false, e.to_string());
                return t;
            }
        }

        let mut run_params = vec![
            ("RegionId".into(), conn.region.clone()),
            ("ImageId".into(), discovered_image),
            ("InstanceType".into(), discovered_type),
            ("Tag.1.Key".into(), tag::MANAGED.into()),
            ("Tag.1.Value".into(), "true".into()),
            ("DryRun".into(), "true".into()),
        ];
        if conn.no_public_ip {
            run_params.push(("InternetMaxBandwidthOut".into(), "0".into()));
        }
        let has_vswitch = if let Some(id) = vsw_id {
            run_params.push(("VSwitchId".into(), id));
            if let Some(sg_id) = matching_sg_id {
                run_params.push(("SecurityGroupId".into(), sg_id));
            }
            true
        } else {
            false
        };

        match self
            .call_raw(
                &ecs,
                "POST",
                "RunInstances",
                ECS_API_VERSION,
                &run_params,
                profile_hint,
            )
            .await
        {
            Ok((status, body)) => {
                let code = match &body {
                    ApiBody::Json(v) => api_error_code_message(v).0,
                    ApiBody::Text(_) => "",
                };
                if !status.is_success() && code == "DryRunOperation" {
                    let msg = if existing_vpc_pair.is_some() {
                        "RAM permissions verified (RunInstances, CreateSecurityGroup DryRun passed)"
                    } else {
                        "RAM permissions verified (RunInstances, CreateVpc, CreateSecurityGroup DryRun passed)"
                    };
                    t.check("permissions", true, msg);
                } else if !has_vswitch
                    && !status.is_success()
                    && code == "InvalidVSwitchId.NotFound"
                {
                    // Account has zero VSwitches in this region; Alibaba Cloud checked RAM
                    // authorization before reporting the missing VSwitchId.
                    t.check(
                        "permissions",
                        true,
                        "RAM permissions verified (RunInstances DryRun passed auth check)",
                    );
                } else {
                    t.check(
                        "permissions",
                        false,
                        map_api_error("RunInstances", ECS_API_VERSION, status, &body).to_string(),
                    );
                }
            }
            Err(e) => {
                t.check("permissions", false, e.to_string());
            }
        }

        t
    }

    async fn provision(&self, conn: &Connection, spec: &ProvisionSpec) -> Result<Vec<Resource>> {
        match spec.family.as_str() {
            "windows" => {
                if !spec.runtime.is_empty() && spec.runtime != "native" {
                    return Err(Error::Unsupported {
                        provider: cua_sandbox_core::ProviderKind::Contrib,
                        op: format!(
                            "aliyun-ecs Windows sandboxes use --runtime native (got --runtime {})",
                            spec.runtime
                        ),
                    });
                }
            }
            "linux" | "linux-slim" => {
                if !spec.runtime.is_empty() && spec.runtime != "docker" {
                    return Err(Error::Unsupported {
                        provider: cua_sandbox_core::ProviderKind::Contrib,
                        op: format!(
                            "aliyun-ecs does not yet support --runtime {} on {} (Direct VM for Linux is tracked in #7)",
                            spec.runtime, spec.family
                        ),
                    });
                }
            }
            _ => {
                return Err(Error::Unsupported {
                    provider: cua_sandbox_core::ProviderKind::Contrib,
                    op: format!("aliyun-ecs does not support {} sandboxes", spec.family),
                });
            }
        }
        let owner = spec
            .tags
            .get(tag::OWNER)
            .cloned()
            .filter(|o| !o.is_empty())
            .ok_or_else(|| Error::InvalidArgument("aliyun-ecs: missing cua-owner tag".into()))?;
        let region = spec.region_or(conn).to_string();
        let profile_hint = self.profile_hint(conn);
        let ecs_ep = self.ecs_endpoint(&region);

        let instance_type = instance_type_for(spec).to_string();
        let image_id = if spec.family == "windows" {
            self.discover_windows_image(&ecs_ep, &region, profile_hint)
                .await?
        } else {
            self.resolve_ubuntu_image(conn, &region).await?
        };
        let net_cfg = NetworkConfig::from_connection(conn)?;
        let net = aliyun_net::prepare_network(
            self,
            conn,
            &region,
            &owner,
            &instance_type,
            &net_cfg,
            &self.net_locks,
        )
        .await?;

        if net.candidates.is_empty() {
            aliyun_net::rollback_made(self, conn, &net.made).await;
            return Err(Error::Cloud(format!(
                "aliyun-ecs: no availability zone in {region} supports {instance_type}"
            )));
        }

        let (disk_gb, disk_category) = system_disk_for(spec);
        let host_name = sanitize_hostname(&spec.name);
        let auto_release =
            (spec.ttl_secs > 0).then(|| model::rfc3339(model::now() + spec.ttl_secs.max(1860)));
        let user_data_b64 = (!spec.user_data.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(spec.user_data.as_bytes()));

        let mut tried = Vec::new();
        for (idx, cand) in net.candidates.iter().enumerate() {
            let (vswitch_id, made_vsw) = match &cand.vswitch_id {
                Some(id) => (id.clone(), None),
                None => match aliyun_net::ensure_vswitch_for_zone(
                    self,
                    conn,
                    &region,
                    &owner,
                    &net.vpc_id,
                    &cand.zone_id,
                    &self.net_locks,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        aliyun_net::rollback_made(self, conn, &net.made).await;
                        return Err(e);
                    }
                },
            };

            let client_token = if idx == 0 {
                spec.name.clone()
            } else {
                format!("{}-z{idx}", spec.name)
            };

            let mut params = vec![
                ("RegionId".into(), region.clone()),
                ("VSwitchId".into(), vswitch_id.clone()),
                ("SecurityGroupId".into(), net.security_group_id.clone()),
                ("ImageId".into(), image_id.clone()),
                ("InstanceType".into(), instance_type.clone()),
                ("Amount".into(), "1".into()),
                ("MinAmount".into(), "1".into()),
                ("InstanceName".into(), spec.name.clone()),
                ("HostName".into(), host_name.clone()),
                ("InstanceChargeType".into(), "PostPaid".into()),
                ("StoppedMode".into(), "StopCharging".into()),
                ("DeletionProtection".into(), "false".into()),
                ("HttpEndpoint".into(), "enabled".into()),
                ("HttpTokens".into(), "required".into()),
                ("SystemDisk.Category".into(), disk_category.into()),
                ("SystemDisk.Size".into(), disk_gb.to_string()),
                ("ClientToken".into(), client_token),
            ];
            if !cand.zone_id.is_empty() {
                params.push(("ZoneId".into(), cand.zone_id.clone()));
            }
            if net.public_ip_mbps > 0 {
                params.push(("InternetChargeType".into(), "PayByTraffic".into()));
                params.push((
                    "InternetMaxBandwidthOut".into(),
                    net.public_ip_mbps.to_string(),
                ));
            } else {
                params.push(("InternetMaxBandwidthOut".into(), "0".into()));
            }
            if let Some(ref release) = auto_release {
                params.push(("AutoReleaseTime".into(), release.clone()));
            }
            if let Some(pw) = spec.desktop_password.as_deref().filter(|p| !p.is_empty()) {
                params.push(("Password".into(), pw.into()));
            }
            if let Some(ref ud) = user_data_b64 {
                params.push(("UserData".into(), ud.clone()));
            }
            params.extend(aliyun_net::tag_params(&spec.tags));

            match self
                .call_raw(
                    &ecs_ep,
                    "POST",
                    "RunInstances",
                    ECS_API_VERSION,
                    &params,
                    profile_hint,
                )
                .await
            {
                Ok((status, body)) if status.is_success() => {
                    let ApiBody::Json(v) = body else {
                        if let Some(ref vsw) = made_vsw {
                            let _ = aliyun_net::delete_part(self, conn, vsw).await;
                        }
                        aliyun_net::rollback_made(self, conn, &net.made).await;
                        return Err(cloud_err(
                            "aliyun-ecs",
                            "RunInstances",
                            "unexpected non-JSON response",
                        ));
                    };
                    let Some(inst_id) = v["InstanceIdSets"]["InstanceIdSet"]
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(|x| x.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    else {
                        if let Some(ref vsw) = made_vsw {
                            let _ = aliyun_net::delete_part(self, conn, vsw).await;
                        }
                        aliyun_net::rollback_made(self, conn, &net.made).await;
                        return Err(cloud_err(
                            "aliyun-ecs",
                            "RunInstances",
                            "RunInstances returned no InstanceId",
                        ));
                    };

                    let mut r = Resource {
                        provider: "aliyun-ecs".into(),
                        id: inst_id.to_string(),
                        resource_type: "instance".into(),
                        name: spec.name.clone(),
                        region: region.clone(),
                        zone: cand.zone_id.clone(),
                        created: model::now(),
                        expires: model::tag_expires(&spec.tags),
                        tags: spec.tags.clone(),
                        state: "pending".into(),
                        ..Default::default()
                    };
                    r.extra.insert("machine_type".into(), instance_type);
                    r.extra.insert("image".into(), image_id);
                    r.extra.insert("vpc".into(), net.vpc_id);
                    r.extra.insert("vswitch".into(), vswitch_id);
                    r.extra
                        .insert("security_group".into(), net.security_group_id);

                    let mut out = vec![r];
                    out.extend(net.made);
                    if let Some(vsw) = made_vsw {
                        out.push(vsw);
                    }
                    return Ok(out);
                }
                Ok((status, body)) => {
                    let code = match &body {
                        ApiBody::Json(v) => api_error_code_message(v).0.to_string(),
                        ApiBody::Text(_) => String::new(),
                    };
                    let err = map_api_error("RunInstances", ECS_API_VERSION, status, &body);
                    if let Some(ref vsw) = made_vsw {
                        let _ = aliyun_net::delete_part(self, conn, vsw).await;
                    }
                    if is_zone_capacity_error(&code) {
                        tried.push(format!("{} ({vswitch_id}): {err}", cand.zone_id));
                        continue;
                    }
                    aliyun_net::rollback_made(self, conn, &net.made).await;
                    return Err(err);
                }
                Err(e) => {
                    if let Some(ref vsw) = made_vsw {
                        let _ = aliyun_net::delete_part(self, conn, vsw).await;
                    }
                    aliyun_net::rollback_made(self, conn, &net.made).await;
                    return Err(e);
                }
            }
        }

        aliyun_net::rollback_made(self, conn, &net.made).await;
        Err(cloud_err(
            "aliyun-ecs",
            &format!("start a {instance_type} in {region}"),
            format!("tried {} zones: {}", tried.len(), tried.join("; ")),
        ))
    }

    async fn describe(
        &self,
        conn: &Connection,
        r: &Resource,
    ) -> Result<Option<(String, BTreeMap<String, String>)>> {
        if r.id.is_empty() {
            return Ok(None);
        }
        if aliyun_net::is_network_type(&r.resource_type) {
            return aliyun_net::describe_part(self, conn, r).await;
        }
        if r.resource_type != "instance" {
            return Ok(None);
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
        let profile_hint = self.profile_hint(conn);
        let ids_json = serde_json::to_string(&[&r.id]).unwrap_or_default();
        let v = self
            .call_ok(
                &self.ecs_endpoint(region),
                "GET",
                "DescribeInstances",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("InstanceIds".into(), ids_json),
                ],
                profile_hint,
            )
            .await?;
        let Some(inst) = v["Instances"]["Instance"]
            .as_array()
            .and_then(|a| a.first())
        else {
            return Ok(None);
        };
        let state = state_of(inst["Status"].as_str().unwrap_or(""));
        Ok(Some((state, aliyun_net::tags_of(inst))))
    }

    async fn stop(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()> {
        let Some(state) = self.guard(conn, r, owner, "stop").await? else {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        };
        if r.resource_type != "instance" {
            return Err(Error::InvalidArgument(format!(
                "aliyun-ecs: cannot stop {}",
                r.resource_type
            )));
        }
        if state == "stopped" {
            return Ok(());
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
        let profile_hint = self.profile_hint(conn);
        if state != "stopping" {
            self.call_ok(
                &self.ecs_endpoint(region),
                "POST",
                "StopInstance",
                ECS_API_VERSION,
                &[
                    ("InstanceId".into(), r.id.clone()),
                    ("StoppedMode".into(), "StopCharging".into()),
                ],
                profile_hint,
            )
            .await?;
        }
        for _ in 0..60 {
            match self.describe(conn, r).await?.map(|(s, _)| s).as_deref() {
                Some("stopped") | None => return Ok(()),
                _ => tokio::time::sleep(self.poll).await,
            }
        }
        Err(Error::Timeout(format!(
            "aliyun-ecs: instance {} did not reach Stopped state",
            r.id
        )))
    }

    async fn start(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()> {
        let Some(state) = self.guard(conn, r, owner, "start").await? else {
            return Err(Error::NotFound(format!("aliyun-ecs instance {}", r.id)));
        };
        if r.resource_type != "instance" {
            return Err(Error::InvalidArgument(format!(
                "aliyun-ecs: cannot start {}",
                r.resource_type
            )));
        }
        if state == "running" {
            return Ok(());
        }
        if state == "stopping" {
            for _ in 0..60 {
                match self.describe(conn, r).await?.map(|(s, _)| s).as_deref() {
                    Some("stopping") => tokio::time::sleep(self.poll).await,
                    _ => break,
                }
            }
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
        let profile_hint = self.profile_hint(conn);
        self.call_ok(
            &self.ecs_endpoint(region),
            "POST",
            "StartInstance",
            ECS_API_VERSION,
            &[("InstanceId".into(), r.id.clone())],
            profile_hint,
        )
        .await?;
        Ok(())
    }

    async fn delete(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()> {
        crate::aliyun_existing_vpc::guard_user_network_untouched(conn, r)?;
        let Some(state) = self.guard(conn, r, owner, "delete").await? else {
            return Ok(());
        };
        if aliyun_net::is_network_type(&r.resource_type) {
            return aliyun_net::delete_part(self, conn, r).await;
        }
        if r.resource_type != "instance" {
            return Ok(());
        }
        if matches!(state.as_str(), "terminated" | "deleted") {
            return Ok(());
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
        let profile_hint = self.profile_hint(conn);
        let (status, body) = self
            .call_raw(
                &self.ecs_endpoint(region),
                "POST",
                "DeleteInstance",
                ECS_API_VERSION,
                &[
                    ("InstanceId".into(), r.id.clone()),
                    ("Force".into(), "true".into()),
                ],
                profile_hint,
            )
            .await?;
        if !status.is_success() {
            let code = match &body {
                ApiBody::Json(v) => api_error_code_message(v).0,
                ApiBody::Text(_) => "",
            };
            if is_instance_not_found(code) {
                return Ok(());
            }
            return Err(map_api_error(
                "DeleteInstance",
                ECS_API_VERSION,
                status,
                &body,
            ));
        }
        for _ in 0..30 {
            match self.describe(conn, r).await? {
                None => return Ok(()),
                Some((st, _)) if matches!(st.as_str(), "terminated" | "deleted") => return Ok(()),
                _ => tokio::time::sleep(self.poll).await,
            }
        }
        Ok(())
    }

    async fn list_owned(&self, conn: &Connection, owner: &str) -> Result<Vec<Resource>> {
        let profile_hint = self.profile_hint(conn);
        let mut base = vec![("RegionId".into(), conn.region.clone())];
        base.extend(aliyun_net::owner_tag_filters(owner));
        let instances = aliyun_net::paginated_query(
            self,
            &self.ecs_endpoint(&conn.region),
            "DescribeInstances",
            ECS_API_VERSION,
            &base,
            ("Instances", "Instance"),
            profile_hint,
        )
        .await?;

        let mut out = Vec::new();
        for inst in instances {
            let tags = aliyun_net::tags_of(&inst);
            if !model::is_ours(&tags, owner) {
                continue;
            }
            let id = inst["InstanceId"].as_str().unwrap_or_default().to_string();
            if id.is_empty() {
                continue;
            }
            let mut r = Resource {
                provider: "aliyun-ecs".into(),
                id,
                resource_type: "instance".into(),
                name: inst["InstanceName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                region: inst["RegionId"]
                    .as_str()
                    .unwrap_or(&conn.region)
                    .to_string(),
                zone: inst["ZoneId"].as_str().unwrap_or_default().to_string(),
                state: state_of(inst["Status"].as_str().unwrap_or("")),
                expires: model::tag_expires(&tags),
                tags,
                ..Default::default()
            };
            if let Some(vpc) = inst["VpcAttributes"]["VpcId"].as_str()
                && !vpc.is_empty()
            {
                r.extra.insert("vpc".into(), vpc.into());
            }
            if let Some(vsw) = inst["VpcAttributes"]["VSwitchId"].as_str()
                && !vsw.is_empty()
            {
                r.extra.insert("vswitch".into(), vsw.into());
            }
            out.push(r);
        }
        out.extend(aliyun_net::list_parts(self, conn, owner).await?);
        Ok(out)
    }

    async fn boot_log(&self, conn: &Connection, r: &Resource) -> Result<Option<String>> {
        if r.id.is_empty() || r.resource_type != "instance" {
            return Ok(None);
        }
        let region = if r.region.is_empty() {
            conn.region.as_str()
        } else {
            r.region.as_str()
        };
        let profile_hint = self.profile_hint(conn);
        let (status, body) = self
            .call_raw(
                &self.ecs_endpoint(region),
                "GET",
                "GetInstanceConsoleOutput",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("InstanceId".into(), r.id.clone()),
                    ("RemoveSymbols".into(), "true".into()),
                ],
                profile_hint,
            )
            .await?;
        if !status.is_success() {
            let code = match &body {
                ApiBody::Json(v) => api_error_code_message(v).0,
                ApiBody::Text(_) => "",
            };
            if is_instance_not_found(code) {
                return Ok(None);
            }
            return Err(map_api_error(
                "GetInstanceConsoleOutput",
                ECS_API_VERSION,
                status,
                &body,
            ));
        }
        let ApiBody::Json(v) = body else {
            return Ok(None);
        };
        let Some(encoded) = v["ConsoleOutput"].as_str() else {
            return Ok(None);
        };
        let compact: String = encoded.split_whitespace().collect();
        if compact.is_empty() {
            return Ok(None);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| encoded.to_string());
        Ok(Some(decoded))
    }

    fn capabilities(&self, _conn: &Connection) -> Capabilities {
        Capabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3986_encoding_and_canonical_query() {
        assert_eq!(rfc3986_encode("abc-123_4.5~6"), "abc-123_4.5~6");
        assert_eq!(rfc3986_encode("hello world/*"), "hello%20world%2F%2A");
        let q = canonical_query_string(&[
            ("Z".into(), "1".into()),
            ("A".into(), "hello world~".into()),
            ("B".into(), "x+y".into()),
        ]);
        assert_eq!(q, "A=hello%20world~&B=x%2By&Z=1");
    }

    #[test]
    fn parse_token_pair_and_debug_redaction() {
        let creds = parse_token_pair("  LTAI5tTestKey : SuperSecretValue123  ").unwrap();
        assert_eq!(creds.access_key_id, "LTAI5tTestKey");
        assert_eq!(creds.access_key_secret.expose(), "SuperSecretValue123");
        let pair: zeroize::Zeroizing<String> = creds.to_pair();
        assert_eq!(pair.as_str(), "LTAI5tTestKey:SuperSecretValue123");
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("SuperSecretValue123"), "{dbg}");
        assert!(!dbg.contains("LTAI5tTestKey"), "{dbg}");
        assert!(dbg.contains("redacted"), "{dbg}");

        for bad in [
            "",
            "no-colon",
            ":secret",
            "ak:",
            "ak with space:sk",
            "ak:sk with space",
        ] {
            assert!(parse_token_pair(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sign_acs3_includes_host_port_and_sorted_headers() {
        let creds = AliyunCredentials {
            access_key_id: "LTAI_AK".into(),
            access_key_secret: Secret::new("SK_SECRET"),
        };
        let url = url::Url::parse("http://127.0.0.1:8080/?RegionId=cn-hangzhou").unwrap();
        let signed = sign_acs3(
            "GET",
            &url,
            "RegionId=cn-hangzhou",
            "DescribeRegions",
            "2014-05-26",
            b"",
            None,
            "2026-11-20T00:00:00Z",
            "0123456789abcdef0123456789abcdef",
            &creds,
        );
        assert_eq!(signed.host, "127.0.0.1:8080");
        assert_eq!(
            signed.content_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(signed.authorization.starts_with(
            "ACS3-HMAC-SHA256 Credential=LTAI_AK,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature="
        ));
    }

    #[test]
    fn map_api_error_sanitizes_empty_code_json() {
        let long = format!("prefix\n\x07{}", "x".repeat(300));
        let body = ApiBody::Json(serde_json::json!({ "Message": "", "detail": long }));
        let err = map_api_error(
            "DescribeRegions",
            ECS_API_VERSION,
            reqwest::StatusCode::BAD_GATEWAY,
            &body,
        );
        let msg = err.to_string();
        let snippet = msg.split_once("HTTP 502 Bad Gateway: ").unwrap().1;
        assert!(!msg.contains('\n'), "{msg}");
        assert!(!msg.contains('\x07'), "{msg}");
        assert!(snippet.ends_with("..."), "{msg}");
        assert_eq!(snippet.chars().count(), 203, "{msg}");
    }
}
