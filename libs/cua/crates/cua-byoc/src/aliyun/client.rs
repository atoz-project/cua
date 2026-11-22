// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Alibaba Cloud OpenAPI V3 (`ACS3-HMAC-SHA256`) signing, HTTP transport with
//! retry/backoff, error mapping, hostname helpers, and shared pagination loops.

use std::collections::BTreeMap;
use std::time::SystemTime;

use cua_sandbox_core::Error;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::AliyunEcs;
use super::auth::AliyunCredentials;
use crate::api::{Result, cloud_err, retry_backoff, retryable_status};

/// Alibaba Cloud STS OpenAPI version.
pub const STS_API_VERSION: &str = "2015-04-01";
/// Alibaba Cloud ECS OpenAPI version.
pub const ECS_API_VERSION: &str = "2014-05-26";
/// Alibaba Cloud VPC OpenAPI version.
pub const VPC_API_VERSION: &str = "2016-04-28";

/// Default global STS endpoint.
pub const STS_ENDPOINT: &str = "https://sts.aliyuncs.com";

pub(crate) enum ApiBody {
    Json(Value),
    Text(String),
}

pub(crate) fn validate_region(region: &str) -> Result<String> {
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

/// Inputs to [`sign_acs3`].
pub struct SignRequest<'a> {
    pub method: &'a str,
    pub url: &'a url::Url,
    pub canonical_query: &'a str,
    pub action: &'a str,
    pub version: &'a str,
    pub body: &'a [u8],
    pub content_type: Option<&'a str>,
    pub timestamp_utc: &'a str,
    pub nonce: &'a str,
    pub creds: &'a AliyunCredentials,
}

/// Signs an Alibaba Cloud OpenAPI V3 request with `ACS3-HMAC-SHA256`.
pub fn sign_acs3(req: &SignRequest<'_>) -> Acs3SignedHeaders {
    let host_str = req.url.host_str().unwrap_or("");
    let host = match req.url.port() {
        Some(p) => format!("{host_str}:{p}"),
        None => host_str.to_string(),
    };
    let content_sha256 = hex::encode(Sha256::digest(req.body));

    let mut hdrs: BTreeMap<&str, String> = BTreeMap::new();
    hdrs.insert("host", host.clone());
    hdrs.insert("x-acs-action", req.action.to_string());
    hdrs.insert("x-acs-content-sha256", content_sha256.clone());
    hdrs.insert("x-acs-date", req.timestamp_utc.to_string());
    hdrs.insert("x-acs-signature-nonce", req.nonce.to_string());
    hdrs.insert("x-acs-version", req.version.to_string());
    if let Some(ct) = req.content_type {
        hdrs.insert("content-type", ct.to_string());
    }

    let mut canonical_headers = String::new();
    let mut signed_headers = Vec::with_capacity(hdrs.len());
    for (k, v) in &hdrs {
        canonical_headers.push_str(&format!("{k}:{}\n", v.trim()));
        signed_headers.push(*k);
    }
    let signed_headers_str = signed_headers.join(";");
    let canonical_uri = if req.url.path().is_empty() {
        "/"
    } else {
        req.url.path()
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.to_ascii_uppercase(),
        canonical_uri,
        req.canonical_query,
        canonical_headers,
        signed_headers_str,
        content_sha256
    );
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed_canonical}");

    let mut mac = Hmac::<Sha256>::new_from_slice(req.creds.access_key_secret.expose().as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
        req.creds.access_key_id, signed_headers_str, signature
    );

    Acs3SignedHeaders {
        authorization,
        content_sha256,
        date: req.timestamp_utc.to_string(),
        nonce: req.nonce.to_string(),
        host,
    }
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

pub(crate) fn state_of(s: &str) -> String {
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

/// Sanitizes an Alibaba Cloud ECS Windows `HostName` (NetBIOS computer name):
/// 2-15 chars, ASCII letters/digits/`-` only, no `.`, no leading/trailing `-`,
/// not all-digits, and collision-resistant via SHA-256 suffix for long names.
fn sanitize_windows_hostname(name: &str) -> String {
    let mut clean = String::with_capacity(name.len());
    let mut prev_dash = false;
    for raw in name.chars() {
        let c = raw.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            clean.push(c);
            prev_dash = false;
        } else if !clean.is_empty() && !prev_dash {
            clean.push('-');
            prev_dash = true;
        }
    }
    while clean.ends_with('-') {
        clean.pop();
    }

    if clean.is_empty() {
        return "cua-win".into();
    }

    let has_letter = |s: &str| s.bytes().any(|b| b.is_ascii_alphabetic());

    if (2..=15).contains(&clean.len()) && has_letter(&clean) {
        return clean;
    }
    if clean.len() <= 13 && (!has_letter(&clean) || clean.len() == 1) {
        return format!("w-{clean}");
    }

    let digest = Sha256::digest(name.as_bytes());
    let hash = hex::encode(&digest[..4]);
    let mut prefix: String = clean.chars().take(6).collect();
    while prefix.ends_with('-') {
        prefix.pop();
    }
    if !has_letter(&prefix) {
        prefix = format!("w{prefix}");
        prefix.truncate(6);
        while prefix.ends_with('-') {
            prefix.pop();
        }
    }
    format!("{prefix}-{hash}")
}

pub(crate) fn sanitize_hostname_for_family(name: &str, family: &str) -> String {
    if family == "windows" {
        sanitize_windows_hostname(name)
    } else {
        sanitize_hostname(name)
    }
}

pub(crate) fn is_zone_capacity_error(code: &str) -> bool {
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

pub(crate) fn is_instance_not_found(code: &str) -> bool {
    matches!(
        code,
        "InvalidInstanceId.NotFound" | "InvalidInstanceID.NotFound"
    )
}

impl AliyunEcs {
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
            let signed = sign_acs3(&SignRequest {
                method,
                url: &parsed,
                canonical_query: &canonical_query,
                action,
                version,
                body: &body_bytes,
                content_type,
                timestamp_utc: &now_ts,
                nonce: &nonce,
                creds: &creds,
            });
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

    /// Paginates an OpenAPI V3 `PageNumber`/`PageSize` query and collects all
    /// elements under `response[outer_key][inner_key]`.
    pub(crate) async fn paginated_page_number(
        &self,
        endpoint: &str,
        action: &str,
        version: &str,
        base_params: &[(String, String)],
        (outer_key, inner_key): (&str, &str),
        profile_hint: Option<&str>,
    ) -> Result<Vec<Value>> {
        const PAGE_SIZE: usize = 50;
        const MAX_PAGES: usize = 100;
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let mut params = base_params.to_vec();
            params.push(("PageNumber".into(), page.to_string()));
            params.push(("PageSize".into(), PAGE_SIZE.to_string()));
            let v = self
                .call_ok(endpoint, "GET", action, version, &params, profile_hint)
                .await?;
            let items = v[outer_key][inner_key]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let count = items.len();
            out.extend(items);
            let total = v["TotalCount"].as_u64().map(|n| n as usize);
            if count == 0 || count < PAGE_SIZE || total.is_some_and(|t| out.len() >= t) {
                break;
            }
        }
        Ok(out)
    }

    /// Paginates an OpenAPI V3 `NextToken` query and collects all elements
    /// under `response[outer_key][inner_key]`.
    pub(crate) async fn paginated_next_token(
        &self,
        endpoint: &str,
        action: &str,
        version: &str,
        base_params: &[(String, String)],
        (outer_key, inner_key): (&str, &str),
        profile_hint: Option<&str>,
    ) -> Result<Vec<Value>> {
        const MAX_PAGES: usize = 100;
        let mut out = Vec::new();
        let mut next_token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut params = base_params.to_vec();
            if let Some(ref token) = next_token {
                params.push(("NextToken".into(), token.clone()));
            }
            let v = self
                .call_ok(endpoint, "GET", action, version, &params, profile_hint)
                .await?;
            if let Some(items) = v[outer_key][inner_key].as_array() {
                out.extend(items.iter().cloned());
            }
            let next = v["NextToken"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            match next {
                Some(tok) if Some(&tok) != next_token.as_ref() => next_token = Some(tok),
                _ => break,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Secret;

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
    fn sign_acs3_includes_host_port_and_sorted_headers() {
        let creds = AliyunCredentials {
            access_key_id: "LTAI_AK".into(),
            access_key_secret: Secret::new("SK_SECRET"),
        };
        let url = url::Url::parse("http://127.0.0.1:8080/?RegionId=cn-hangzhou").unwrap();
        let signed = sign_acs3(&SignRequest {
            method: "GET",
            url: &url,
            canonical_query: "RegionId=cn-hangzhou",
            action: "DescribeRegions",
            version: "2014-05-26",
            body: b"",
            content_type: None,
            timestamp_utc: "2026-11-20T00:00:00Z",
            nonce: "0123456789abcdef0123456789abcdef",
            creds: &creds,
        });
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

    #[test]
    fn sanitize_windows_hostname_enforces_netbios_rules_and_preserves_uniqueness() {
        fn assert_valid_netbios(h: &str) {
            assert!(
                (2..=15).contains(&h.len()),
                "Windows HostName length must be 2..=15, got {h:?} ({})",
                h.len()
            );
            assert!(
                !h.contains('.'),
                "Windows HostName must not contain '.': {h:?}"
            );
            assert!(
                !h.starts_with('-') && !h.ends_with('-'),
                "Windows HostName must not start/end with '-': {h:?}"
            );
            assert!(
                h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "Windows HostName contains invalid chars: {h:?}"
            );
            assert!(
                !h.chars().all(|c| c.is_ascii_digit()),
                "Windows HostName must not be all-digits: {h:?}"
            );
        }

        let cases = [
            "cua-aliyun-ecs-aaaaaaaaaaaa",
            "cua-aliyun-ecs-aaaaaaaaaaab",
            "cua-aliyun-ecs-d347029537d8",
            "win.box.01",
            "Win_Box 02!",
            "a",
            "9",
            "123456",
            "12345678901234",
            "123456789012345",
            "123-456-78901234",
            "---...___",
            "",
            "my-very-long-windows-sandbox-name-1-suffix",
            "my-very-long-windows-sandbox-name-2-suffix",
        ];
        for raw in cases {
            assert_valid_netbios(&sanitize_windows_hostname(raw));
        }

        let a = sanitize_windows_hostname("cua-aliyun-ecs-aaaaaaaaaaaa");
        let b = sanitize_windows_hostname("cua-aliyun-ecs-aaaaaaaaaaab");
        assert_ne!(a, b, "distinct 27-char names must not collide: {a} vs {b}");

        let m1 = sanitize_windows_hostname("my-very-long-windows-sandbox-name-1-suffix");
        let m2 = sanitize_windows_hostname("my-very-long-windows-sandbox-name-2-suffix");
        assert_ne!(m1, m2, "long names differing in middle must not collide");

        assert_eq!(sanitize_windows_hostname("win.box.01"), "win-box-01");
        assert_eq!(
            sanitize_hostname_for_family("cua-aliyun-ecs-aaaaaaaaaaaa", "linux"),
            "cua-aliyun-ecs-aaaaaaaaaaaa"
        );
        assert_eq!(
            sanitize_hostname_for_family("my.linux.host.01", "linux"),
            "my.linux.host.01"
        );
    }
}
