// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! A fake Alibaba Cloud OpenAPI V3 server (STS, ECS, VPC) verifying
//! `ACS3-HMAC-SHA256` signatures on every request.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct RecordedCall {
    pub action: String,
    pub version: String,
    pub method: String,
    pub access_key_id: String,
    pub params: BTreeMap<String, String>,
}

pub struct FakeAliyun {
    /// Allowed AccessKey pairs (`access_key_id` -> `access_key_secret`).
    pub keys: BTreeMap<String, String>,
    /// Allowed regions (`DescribeRegions`).
    pub regions: Vec<String>,
    /// Available instance types (`DescribeAvailableResource`).
    pub available_instance_types: Vec<String>,
    /// Existing instances keyed by `InstanceId`.
    pub instances: BTreeMap<String, Value>,
    /// Optional VSwitches for `DescribeVSwitches`.
    pub vswitches: Vec<Value>,
    /// Optional SecurityGroups for `DescribeSecurityGroups`.
    pub security_groups: Vec<Value>,
    /// Recorded verified calls.
    pub calls: Vec<RecordedCall>,
    /// Number of upcoming calls to reject with HTTP 429 `Throttling.User`.
    pub throttle: u32,
    /// Actions (e.g. `"ecs:RunInstances"`, `"vpc:DescribeVpcs"`) that fail with HTTP 403 `Forbidden.RAM`.
    pub forbidden_actions: BTreeSet<String>,
    /// Simulate VPC-only region returning `InvalidVSwitchId.NotFound` on `DryRun=true` when `VSwitchId` is omitted.
    pub run_instances_missing_vswitch: bool,
    /// Optional forced error `(http_status, code, message)` for `RunInstances DryRun=true`.
    pub run_instances_dry_run_error: Option<(u16, String, String)>,
    /// Optional forced auth failure code (e.g. `"InvalidAccessKeyId.NotFound"`).
    pub force_auth_error: Option<(String, String)>,
}

impl Default for FakeAliyun {
    fn default() -> Self {
        let mut keys = BTreeMap::new();
        keys.insert("LTAI_TEST_AK".to_string(), "secret123".to_string());
        Self {
            keys,
            regions: vec![
                "cn-hangzhou".into(),
                "cn-shanghai".into(),
                "cn-beijing".into(),
                "ap-southeast-1".into(),
            ],
            available_instance_types: vec![
                "ecs.e-c1m2.large".into(),
                "ecs.c7.xlarge".into(),
                "ecs.g7.large".into(),
            ],
            instances: BTreeMap::new(),
            vswitches: Vec::new(),
            security_groups: Vec::new(),
            calls: Vec::new(),
            throttle: 0,
            forbidden_actions: BTreeSet::new(),
            run_instances_missing_vswitch: false,
            run_instances_dry_run_error: None,
            force_auth_error: None,
        }
    }
}

pub type S = Arc<Mutex<FakeAliyun>>;

fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "Code": code,
            "Message": msg,
            "RequestId": "fake-req-id"
        })),
    )
        .into_response()
}

fn rfc3986_encode(input: &str) -> String {
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

fn parse_query_params(raw: &str) -> BTreeMap<String, String> {
    if raw.is_empty() {
        return BTreeMap::new();
    }
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn verify_acs3_signature(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    keys: &BTreeMap<String, String>,
) -> std::result::Result<(String, String, String), (StatusCode, &'static str, String)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "IncompleteSignature",
                "missing Authorization header".to_string(),
            )
        })?;
    let rest = auth.strip_prefix("ACS3-HMAC-SHA256 ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "IncompleteSignature",
            format!("unexpected Authorization scheme: {auth}"),
        )
    })?;

    let mut credential = None;
    let mut signed_headers_raw = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers_raw = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v.to_string());
        }
    }

    let ak = credential.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "IncompleteSignature",
            "missing Credential in Authorization".to_string(),
        )
    })?;
    let signed_headers_str = signed_headers_raw.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "IncompleteSignature",
            "missing SignedHeaders in Authorization".to_string(),
        )
    })?;
    let got_sig = signature.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "IncompleteSignature",
            "missing Signature in Authorization".to_string(),
        )
    })?;

    let secret = keys.get(&ak).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "InvalidAccessKeyId.NotFound",
            format!("Specified access key {ak:?} is not found."),
        )
    })?;

    let action = headers
        .get("x-acs-action")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "missing x-acs-action header".to_string(),
            )
        })?
        .to_string();
    let version = headers
        .get("x-acs-version")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "missing x-acs-version header".to_string(),
            )
        })?
        .to_string();

    for req_hdr in [
        "host",
        "x-acs-action",
        "x-acs-content-sha256",
        "x-acs-date",
        "x-acs-signature-nonce",
        "x-acs-version",
    ] {
        if !headers.contains_key(req_hdr) {
            return Err((
                StatusCode::BAD_REQUEST,
                "IncompleteSignature",
                format!("missing required header {req_hdr}"),
            ));
        }
    }

    let expected_body_hash = hex::encode(Sha256::digest(body));
    let got_body_hash = headers
        .get("x-acs-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if got_body_hash != expected_body_hash {
        return Err((
            StatusCode::BAD_REQUEST,
            "SignatureDoesNotMatch",
            format!(
                "x-acs-content-sha256 mismatch: got {got_body_hash}, expected {expected_body_hash}"
            ),
        ));
    }

    let signed_headers: Vec<&str> = signed_headers_str.split(';').collect();
    // Verify signed_headers are sorted and contain host and all x-acs-* headers present.
    let mut sorted_check = signed_headers.clone();
    sorted_check.sort_unstable();
    if signed_headers != sorted_check {
        return Err((
            StatusCode::BAD_REQUEST,
            "IncompleteSignature",
            "SignedHeaders must be sorted lowercase".to_string(),
        ));
    }
    if !signed_headers.contains(&"host") {
        return Err((
            StatusCode::BAD_REQUEST,
            "IncompleteSignature",
            "SignedHeaders must include host".to_string(),
        ));
    }
    for key in headers.keys() {
        let name = key.as_str();
        if name.starts_with("x-acs-") && !signed_headers.contains(&name) {
            return Err((
                StatusCode::BAD_REQUEST,
                "IncompleteSignature",
                format!("SignedHeaders missing {name}"),
            ));
        }
    }

    let canonical_uri = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };

    let raw_query = uri.query().unwrap_or("");
    let canonical_query = if raw_query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw_query.as_bytes())
            .map(|(k, v)| (rfc3986_encode(&k), rfc3986_encode(&v)))
            .collect();
        pairs.sort();
        let rebuilt = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        if rebuilt != raw_query {
            return Err((
                StatusCode::BAD_REQUEST,
                "SignatureDoesNotMatch",
                format!(
                    "query string is not canonical RFC3986 sorted: got {raw_query}, expected {rebuilt}"
                ),
            ));
        }
        rebuilt
    };

    let mut canonical_headers = String::new();
    for h in &signed_headers {
        let val = headers
            .get(*h)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "IncompleteSignature",
                    format!("signed header {h} missing from request"),
                )
            })?;
        canonical_headers.push_str(&format!("{h}:{}\n", val.trim()));
    }

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers_str,
        expected_body_hash
    );
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed_canonical}");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(string_to_sign.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());
    if got_sig != expected_sig {
        return Err((
            StatusCode::BAD_REQUEST,
            "SignatureDoesNotMatch",
            format!(
                "Specified signature is not matched with our calculation. canonical={canonical_request:?}"
            ),
        ));
    }

    Ok((ak, action, version))
}

fn action_permission_key(action: &str, version: &str) -> String {
    let svc = match version {
        "2015-04-01" => "sts",
        "2016-04-28" => "vpc",
        _ => "ecs",
    };
    format!("{svc}:{action}")
}

pub async fn handle(
    State(s): State<S>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut f = s.lock().unwrap();
    if f.throttle > 0 {
        f.throttle -= 1;
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "Throttling.User",
            "Request was denied due to user flow control.",
        );
    }

    if let Some((code, msg)) = f.force_auth_error.clone() {
        return err(StatusCode::UNAUTHORIZED, &code, &msg);
    }

    let (ak, action, version) = match verify_acs3_signature(&method, &uri, &headers, &body, &f.keys)
    {
        Ok(v) => v,
        Err((status, code, msg)) => return err(status, code, &msg),
    };

    let mut params = parse_query_params(uri.query().unwrap_or(""));
    if method == Method::POST
        && !body.is_empty()
        && headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"))
    {
        for (k, v) in url::form_urlencoded::parse(&body) {
            params.insert(k.into_owned(), v.into_owned());
        }
    }

    f.calls.push(RecordedCall {
        action: action.clone(),
        version: version.clone(),
        method: method.to_string(),
        access_key_id: ak,
        params: params.clone(),
    });

    let perm_key = action_permission_key(&action, &version);
    if f.forbidden_actions.contains(&perm_key) || f.forbidden_actions.contains(&action) {
        return err(
            StatusCode::FORBIDDEN,
            "Forbidden.RAM",
            &format!("User not authorized to operate on {perm_key}"),
        );
    }

    match (version.as_str(), action.as_str()) {
        ("2015-04-01", "GetCallerIdentity") => (
            StatusCode::OK,
            axum::Json(json!({
                "AccountId": "123456789012",
                "Arn": "acs:ram::123456789012:user/cua-byoc",
                "IdentityType": "RAMUser",
                "PrincipalId": "20000001",
                "RequestId": "req-sts-1",
                "UserId": "20000001"
            })),
        )
            .into_response(),
        ("2014-05-26", "DescribeRegions") => {
            let regions: Vec<Value> = f
                .regions
                .iter()
                .map(|r| json!({ "RegionId": r, "LocalName": r }))
                .collect();
            (
                StatusCode::OK,
                axum::Json(json!({
                    "Regions": { "Region": regions },
                    "RequestId": "req-regions-1"
                })),
            )
                .into_response()
        }
        ("2014-05-26", "DescribeAvailableResource") => {
            let region = params
                .get("RegionId")
                .cloned()
                .unwrap_or_else(|| "cn-hangzhou".into());
            let supported: Vec<Value> = f
                .available_instance_types
                .iter()
                .map(|t| {
                    json!({
                        "Value": t,
                        "Status": "Available",
                        "StatusCategory": "WithStock"
                    })
                })
                .collect();
            (
                StatusCode::OK,
                axum::Json(json!({
                    "AvailableZones": {
                        "AvailableZone": [{
                            "RegionId": region,
                            "ZoneId": format!("{region}-h"),
                            "Status": "Available",
                            "AvailableResources": {
                                "AvailableResource": [{
                                    "Type": "InstanceType",
                                    "SupportedResources": {
                                        "SupportedResource": supported
                                    }
                                }]
                            }
                        }]
                    },
                    "RequestId": "req-avail-1"
                })),
            )
                .into_response()
        }
        ("2014-05-26", "DescribeImages") => (
            StatusCode::OK,
            axum::Json(json!({
                "Images": {
                    "Image": [{
                        "ImageId": "ubuntu_24_04_x64_20G_alibase_20250101.vhd",
                        "ImageName": "ubuntu_24_04_x64_20G_alibase_20250101.vhd",
                        "OSType": "linux",
                        "Architecture": "x86_64",
                        "Status": "Available"
                    }]
                },
                "TotalCount": 1,
                "RequestId": "req-images-1"
            })),
        )
            .into_response(),
        ("2014-05-26", "DescribeInstances") => {
            let mut tag_filters = Vec::new();
            for i in 1..=5 {
                if let (Some(k), Some(v)) = (
                    params.get(&format!("Tag.{i}.Key")),
                    params.get(&format!("Tag.{i}.Value")),
                ) {
                    tag_filters.push((k.clone(), v.clone()));
                }
            }
            let id_filter: Option<Vec<String>> = params
                .get("InstanceIds")
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok());
            let region_filter = params.get("RegionId").cloned();
            let items: Vec<Value> = f
                .instances
                .values()
                .filter(|inst| {
                    if let Some(ref reg) = region_filter
                        && inst["RegionId"].as_str().unwrap_or(reg.as_str()) != reg
                    {
                        return false;
                    }
                    if let Some(ref ids) = id_filter
                        && !ids
                            .iter()
                            .any(|id| Some(id.as_str()) == inst["InstanceId"].as_str())
                    {
                        return false;
                    }
                    tag_filters.iter().all(|(k, v)| {
                        inst["Tags"]["Tag"].as_array().is_some_and(|arr| {
                            arr.iter().any(|t| {
                                t["TagKey"].as_str() == Some(k.as_str())
                                    && t["TagValue"].as_str() == Some(v.as_str())
                            })
                        })
                    })
                })
                .cloned()
                .collect();
            let total = items.len();
            (
                StatusCode::OK,
                axum::Json(json!({
                    "Instances": { "Instance": items },
                    "TotalCount": total,
                    "PageNumber": 1,
                    "PageSize": 50,
                    "RequestId": "req-instances-1"
                })),
            )
                .into_response()
        }
        ("2014-05-26", "DescribeSecurityGroups") => {
            let vpc_filter = params.get("VpcId").cloned();
            let sgs: Vec<Value> = f
                .security_groups
                .iter()
                .filter(|sg| match &vpc_filter {
                    Some(v) => sg["VpcId"].as_str() == Some(v.as_str()),
                    None => true,
                })
                .cloned()
                .collect();
            let total = sgs.len();
            (
                StatusCode::OK,
                axum::Json(json!({
                    "SecurityGroups": { "SecurityGroup": sgs },
                    "TotalCount": total,
                    "RequestId": "req-sg-1"
                })),
            )
                .into_response()
        }
        ("2016-04-28", "DescribeVpcs") => (
            StatusCode::OK,
            axum::Json(json!({
                "Vpcs": { "Vpc": [] },
                "TotalCount": 0,
                "RequestId": "req-vpc-1"
            })),
        )
            .into_response(),
        ("2016-04-28", "DescribeVSwitches") => {
            let vsw = f.vswitches.clone();
            let total = vsw.len();
            (
                StatusCode::OK,
                axum::Json(json!({
                    "VSwitches": { "VSwitch": vsw },
                    "TotalCount": total,
                    "RequestId": "req-vsw-1"
                })),
            )
                .into_response()
        }
        ("2014-05-26", "RunInstances") => {
            if params.get("DryRun").map(String::as_str) == Some("true") {
                if let Some((status_u16, ref code, ref msg)) = f.run_instances_dry_run_error {
                    let st = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_REQUEST);
                    return err(st, code, msg);
                }
                if f.run_instances_missing_vswitch && !params.contains_key("VSwitchId") {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "InvalidVSwitchId.NotFound",
                        "The specified VSwitchId does not exist.",
                    );
                }
                return err(
                    StatusCode::PRECONDITION_FAILED,
                    "DryRunOperation",
                    "Request validation has been passed with DryRun flag set.",
                );
            }
            let id = format!("i-fake-{}", f.instances.len() + 1);
            f.instances.insert(
                id.clone(),
                json!({
                    "InstanceId": id,
                    "Status": "Running",
                    "RegionId": params.get("RegionId").cloned().unwrap_or_else(|| "cn-hangzhou".into()),
                    "Tags": { "Tag": [] }
                }),
            );
            (
                StatusCode::OK,
                axum::Json(json!({
                    "InstanceIdSets": { "InstanceIdSet": [id] },
                    "RequestId": "req-run-1"
                })),
            )
                .into_response()
        }
        _ => err(
            StatusCode::BAD_REQUEST,
            "InvalidAction.NotFound",
            &format!("Unsupported action {version}:{action}"),
        ),
    }
}
