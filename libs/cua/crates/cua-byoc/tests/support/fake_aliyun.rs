// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! A fake Alibaba Cloud OpenAPI V3 server (STS, ECS, VPC) verifying
//! `ACS3-HMAC-SHA256` signatures on every request.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
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

pub type RunHook = Arc<dyn Fn(&str, &BTreeMap<String, String>) + Send + Sync>;

pub struct FakeAliyun {
    /// Allowed AccessKey pairs (`access_key_id` -> `access_key_secret`).
    pub keys: BTreeMap<String, String>,
    /// Allowed regions (`DescribeRegions`).
    pub regions: Vec<String>,
    /// Availability zones in the region (`DescribeZones`). Empty defaults to `["<region>-h"]`.
    pub zones: Vec<String>,
    /// Available instance types (`DescribeAvailableResource`).
    pub available_instance_types: Vec<String>,
    /// Per-zone capacity/offering errors (`zone_id` -> `error_code`) omitted from `DescribeAvailableResource`
    /// and returned from `RunInstances`.
    pub sold_out_zones: BTreeMap<String, String>,
    /// Per-zone errors returned only at `RunInstances` time (`zone_id` -> `error_code`),
    /// simulating a TOCTOU capacity failure after `DescribeAvailableResource`.
    pub run_fail_zones: BTreeMap<String, String>,
    /// Existing VPCs (`DescribeVpcs`).
    pub vpcs: Vec<Value>,
    /// Existing VSwitches (`DescribeVSwitches`).
    pub vswitches: Vec<Value>,
    /// Existing SecurityGroups (`DescribeSecurityGroups`).
    pub security_groups: Vec<Value>,
    /// Security group rules keyed by `SecurityGroupId`.
    pub security_group_rules: BTreeMap<String, Vec<Value>>,
    /// Existing instances keyed by `InstanceId`.
    pub instances: BTreeMap<String, Value>,
    /// Raw console output keyed by `InstanceId` (`GetInstanceConsoleOutput`).
    pub console_outputs: BTreeMap<String, String>,
    /// Recorded verified calls.
    pub calls: Vec<RecordedCall>,
    /// Number of upcoming calls to reject with HTTP 429 `Throttling.User`.
    pub throttle: u32,
    /// Number of upcoming `DeleteSecurityGroup`/`DeleteVSwitch`/`DeleteVpc` calls to reject with `DependencyViolation`.
    pub transient_dependency_errors: u32,
    /// Actions (e.g. `"ecs:RunInstances"`, `"vpc:DescribeVpcs"`) that fail with HTTP 403 `Forbidden.RAM`.
    pub forbidden_actions: BTreeSet<String>,
    /// Simulate VPC-only region returning `InvalidVSwitchId.NotFound` on `DryRun=true` when `VSwitchId` is omitted.
    pub run_instances_missing_vswitch: bool,
    /// Simulate `CreateSecurityGroup DryRun=true` returning `InvalidVpcId.NotFound` when `VpcId` is omitted.
    pub create_sg_missing_vpc: bool,
    /// Optional forced error `(http_status, code, message)` for `RunInstances DryRun=true`.
    pub run_instances_dry_run_error: Option<(u16, String, String)>,
    /// Optional forced error `(http_status, code, message)` for non-DryRun `RunInstances`.
    pub run_instances_error: Option<(u16, String, String)>,
    /// Optional forced auth failure code (e.g. `"InvalidAccessKeyId.NotFound"`).
    pub force_auth_error: Option<(String, String)>,
    /// Monotonic counter for generated IDs.
    pub next_id: u64,
    /// Optional hook called after a successful `RunInstances` (outside the mutex).
    pub on_run_instance: Option<RunHook>,
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
            zones: Vec::new(),
            available_instance_types: vec![
                "ecs.e-c1m2.large".into(),
                "ecs.c7.xlarge".into(),
                "ecs.g7.large".into(),
            ],
            sold_out_zones: BTreeMap::new(),
            run_fail_zones: BTreeMap::new(),
            vpcs: Vec::new(),
            vswitches: Vec::new(),
            security_groups: Vec::new(),
            security_group_rules: BTreeMap::new(),
            instances: BTreeMap::new(),
            console_outputs: BTreeMap::new(),
            calls: Vec::new(),
            throttle: 0,
            transient_dependency_errors: 0,
            forbidden_actions: BTreeSet::new(),
            run_instances_missing_vswitch: false,
            create_sg_missing_vpc: false,
            run_instances_dry_run_error: None,
            run_instances_error: None,
            force_auth_error: None,
            next_id: 1,
            on_run_instance: None,
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

fn parse_tag_params(params: &BTreeMap<String, String>, ecs_format: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for i in 1..=20 {
        let Some(k) = params.get(&format!("Tag.{i}.Key")) else {
            continue;
        };
        let v = params
            .get(&format!("Tag.{i}.Value"))
            .cloned()
            .unwrap_or_default();
        if ecs_format {
            out.push(json!({ "TagKey": k, "TagValue": v }));
        } else {
            out.push(json!({ "Key": k, "Value": v }));
        }
    }
    out
}

fn extract_tag_filters(params: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut filters = Vec::new();
    for i in 1..=20 {
        if let (Some(k), Some(v)) = (
            params.get(&format!("Tag.{i}.Key")),
            params.get(&format!("Tag.{i}.Value")),
        ) {
            filters.push((k.clone(), v.clone()));
        }
    }
    filters
}

fn matches_tag_filters(obj: &Value, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(k, v)| {
        obj["Tags"]["Tag"].as_array().is_some_and(|arr| {
            arr.iter().any(|t| {
                let tk = t["TagKey"].as_str().or_else(|| t["Key"].as_str());
                let tv = t["TagValue"].as_str().or_else(|| t["Value"].as_str());
                tk == Some(k.as_str()) && tv == Some(v.as_str())
            })
        })
    })
}

fn paginate(
    items: Vec<Value>,
    params: &BTreeMap<String, String>,
) -> (Vec<Value>, usize, usize, usize) {
    let total = items.len();
    let page_num = params
        .get("PageNumber")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(1);
    let page_size = params
        .get("PageSize")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(50);
    let start = (page_num - 1).saturating_mul(page_size);
    let page_items = if start >= items.len() {
        Vec::new()
    } else {
        items.into_iter().skip(start).take(page_size).collect()
    };
    (page_items, total, page_num, page_size)
}

fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.trim().split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = u32::from(ip) & mask;
    let end = start | !mask;
    Some((start, end))
}

fn cidrs_overlap(a: &str, b: &str) -> bool {
    match (parse_cidr(a), parse_cidr(b)) {
        (Some((a0, a1)), Some((b0, b1))) => a0 <= b1 && b0 <= a1,
        _ => a.trim() == b.trim(),
    }
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
    let (resp, hook_call) = {
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

        let (ak, action, version) =
            match verify_acs3_signature(&method, &uri, &headers, &body, &f.keys) {
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

        let mut post_run_hook = None;
        let resp = match (version.as_str(), action.as_str()) {
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
            ("2014-05-26", "DescribeZones") => {
                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let zone_ids = if f.zones.is_empty() {
                    vec![format!("{region}-h")]
                } else {
                    f.zones.clone()
                };
                let zones: Vec<Value> = zone_ids
                    .into_iter()
                    .map(|zid| {
                        json!({
                            "ZoneId": zid,
                            "LocalName": zid,
                            "Status": "Available"
                        })
                    })
                    .collect();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "Zones": { "Zone": zones },
                        "RequestId": "req-zones-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeAvailableResource") => {
                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let zone_ids = if f.zones.is_empty() {
                    vec![format!("{region}-h")]
                } else {
                    f.zones.clone()
                };
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
                let azs: Vec<Value> = zone_ids
                    .into_iter()
                    .filter(|zid| !f.sold_out_zones.contains_key(zid))
                    .map(|zid| {
                        json!({
                            "RegionId": region,
                            "ZoneId": zid,
                            "Status": "Available",
                            "AvailableResources": {
                                "AvailableResource": [{
                                    "Type": "InstanceType",
                                    "SupportedResources": {
                                        "SupportedResource": supported
                                    }
                                }]
                            }
                        })
                    })
                    .collect();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "AvailableZones": {
                            "AvailableZone": azs
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
                        "Image": [
                            {
                                "ImageId": "ubuntu_24_04_x64_20G_alibase_20240601.vhd",
                                "ImageName": "ubuntu_24_04_x64_20G_alibase_20240601.vhd",
                                "OSType": "linux",
                                "Architecture": "x86_64",
                                "Status": "Available",
                                "CreationTime": "2024-06-01T00:00:00Z"
                            },
                            {
                                "ImageId": "ubuntu_24_04_x64_20G_alibase_20250101.vhd",
                                "ImageName": "ubuntu_24_04_x64_20G_alibase_20250101.vhd",
                                "OSType": "linux",
                                "Architecture": "x86_64",
                                "Status": "Available",
                                "CreationTime": "2025-01-01T00:00:00Z"
                            }
                        ]
                    },
                    "TotalCount": 2,
                    "RequestId": "req-images-1"
                })),
            )
                .into_response(),
            ("2014-05-26", "DescribeInstances") => {
                let tag_filters = extract_tag_filters(&params);
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
                        matches_tag_filters(inst, &tag_filters)
                    })
                    .cloned()
                    .collect();
                let (page_items, total, page_num, page_size) = paginate(items, &params);
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "Instances": { "Instance": page_items },
                        "TotalCount": total,
                        "PageNumber": page_num,
                        "PageSize": page_size,
                        "RequestId": "req-instances-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "CreateSecurityGroup") => {
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    if f.create_sg_missing_vpc && !params.contains_key("VpcId") {
                        err(
                            StatusCode::BAD_REQUEST,
                            "InvalidVpcId.NotFound",
                            "The specified VpcId does not exist.",
                        )
                    } else {
                        err(
                            StatusCode::PRECONDITION_FAILED,
                            "DryRunOperation",
                            "Request validation has been passed with DryRun flag set.",
                        )
                    }
                } else {
                    let sg_id = format!("sg-fake-{}", f.next_id);
                    f.next_id += 1;
                    let sg_type = params
                        .get("SecurityGroupType")
                        .cloned()
                        .unwrap_or_else(|| "normal".into());
                    let inner = if sg_type == "enterprise" {
                        "Drop"
                    } else {
                        "Accept"
                    };
                    let tags = parse_tag_params(&params, true);
                    f.security_groups.push(json!({
                        "SecurityGroupId": sg_id,
                        "SecurityGroupName": params.get("SecurityGroupName").cloned().unwrap_or_default(),
                        "VpcId": params.get("VpcId").cloned().unwrap_or_default(),
                        "RegionId": params.get("RegionId").cloned().unwrap_or_else(|| "cn-hangzhou".into()),
                        "SecurityGroupType": sg_type,
                        "InnerAccessPolicy": inner,
                        "Tags": { "Tag": tags }
                    }));
                    f.security_group_rules.insert(sg_id.clone(), Vec::new());
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "SecurityGroupId": sg_id,
                            "RequestId": "req-csg-1"
                        })),
                    )
                        .into_response()
                }
            }
            ("2014-05-26", "DescribeSecurityGroups") => {
                let vpc_filter = params.get("VpcId").cloned();
                let sg_id_filter = params.get("SecurityGroupId").cloned();
                let region_filter = params.get("RegionId").cloned();
                let tag_filters = extract_tag_filters(&params);
                let sgs: Vec<Value> = f
                    .security_groups
                    .iter()
                    .filter(|sg| {
                        if let Some(ref reg) = region_filter
                            && let Some(sg_reg) = sg["RegionId"].as_str()
                            && sg_reg != reg
                        {
                            return false;
                        }
                        if let Some(ref v) = vpc_filter
                            && sg["VpcId"].as_str() != Some(v.as_str())
                        {
                            return false;
                        }
                        if let Some(ref id) = sg_id_filter
                            && sg["SecurityGroupId"].as_str() != Some(id.as_str())
                        {
                            return false;
                        }
                        matches_tag_filters(sg, &tag_filters)
                    })
                    .cloned()
                    .collect();
                let (page_items, total, page_num, page_size) = paginate(sgs, &params);
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "SecurityGroups": { "SecurityGroup": page_items },
                        "TotalCount": total,
                        "PageNumber": page_num,
                        "PageSize": page_size,
                        "RequestId": "req-sg-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeSecurityGroupAttribute") => {
                let sg_id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                if let Some(sg) = f
                    .security_groups
                    .iter()
                    .find(|sg| sg["SecurityGroupId"].as_str() == Some(sg_id.as_str()))
                    .cloned()
                {
                    let rules = f
                        .security_group_rules
                        .get(&sg_id)
                        .cloned()
                        .unwrap_or_default();
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "SecurityGroupId": sg_id,
                            "VpcId": sg["VpcId"],
                            "RegionId": sg["RegionId"],
                            "InnerAccessPolicy": sg["InnerAccessPolicy"].as_str().unwrap_or("Drop"),
                            "Permissions": { "Permission": rules },
                            "RequestId": "req-sga-1"
                        })),
                    )
                        .into_response()
                } else {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidSecurityGroupId.NotFound",
                        "SecurityGroup does not exist.",
                    )
                }
            }
            ("2014-05-26", "AuthorizeSecurityGroupEgress") => {
                let sg_id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                if !f
                    .security_groups
                    .iter()
                    .any(|sg| sg["SecurityGroupId"].as_str() == Some(sg_id.as_str()))
                {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidSecurityGroupId.NotFound",
                        "SecurityGroup does not exist.",
                    )
                } else {
                    let ip_proto = params
                        .get("Permissions.1.IpProtocol")
                        .or_else(|| params.get("IpProtocol"))
                        .cloned()
                        .unwrap_or_default();
                    let port_range = params
                        .get("Permissions.1.PortRange")
                        .or_else(|| params.get("PortRange"))
                        .cloned()
                        .unwrap_or_default();
                    let dest_cidr = params
                        .get("Permissions.1.DestCidrIp")
                        .or_else(|| params.get("DestCidrIp"))
                        .cloned()
                        .unwrap_or_default();
                    let policy = params
                        .get("Permissions.1.Policy")
                        .or_else(|| params.get("Policy"))
                        .cloned()
                        .unwrap_or_else(|| "Accept".into());
                    let priority = params
                        .get("Permissions.1.Priority")
                        .or_else(|| params.get("Priority"))
                        .cloned()
                        .unwrap_or_else(|| "1".into());
                    f.security_group_rules
                        .entry(sg_id)
                        .or_default()
                        .push(json!({
                            "Direction": "egress",
                            "IpProtocol": ip_proto,
                            "PortRange": port_range,
                            "DestCidrIp": dest_cidr,
                            "Policy": policy,
                            "Priority": priority,
                        }));
                    (
                        StatusCode::OK,
                        axum::Json(json!({ "RequestId": "req-asge-1" })),
                    )
                        .into_response()
                }
            }
            ("2014-05-26", "DeleteSecurityGroup") => {
                if f.transient_dependency_errors > 0 {
                    f.transient_dependency_errors -= 1;
                    err(
                        StatusCode::BAD_REQUEST,
                        "DependencyViolation",
                        "Security group has dependent resources.",
                    )
                } else {
                    let sg_id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                    let in_use = f.instances.values().any(|inst| {
                        inst["SecurityGroupIds"]["SecurityGroupId"]
                            .as_array()
                            .is_some_and(|arr| arr.iter().any(|x| x.as_str() == Some(&sg_id)))
                    });
                    if in_use {
                        err(
                            StatusCode::BAD_REQUEST,
                            "DependencyViolation",
                            "SecurityGroup is in use by an instance.",
                        )
                    } else if let Some(pos) = f
                        .security_groups
                        .iter()
                        .position(|sg| sg["SecurityGroupId"].as_str() == Some(&sg_id))
                    {
                        f.security_groups.remove(pos);
                        f.security_group_rules.remove(&sg_id);
                        (
                            StatusCode::OK,
                            axum::Json(json!({ "RequestId": "req-dsg-1" })),
                        )
                            .into_response()
                    } else {
                        err(
                            StatusCode::NOT_FOUND,
                            "InvalidSecurityGroupId.NotFound",
                            "SecurityGroup not found.",
                        )
                    }
                }
            }
            ("2016-04-28", "CreateVpc") => {
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    err(
                        StatusCode::PRECONDITION_FAILED,
                        "DryRunOperation",
                        "Request validation has been passed with DryRun flag set.",
                    )
                } else {
                    let vpc_id = format!("vpc-fake-{}", f.next_id);
                    f.next_id += 1;
                    let tags = parse_tag_params(&params, false);
                    f.vpcs.push(json!({
                        "VpcId": vpc_id,
                        "VpcName": params.get("VpcName").cloned().unwrap_or_default(),
                        "CidrBlock": params.get("CidrBlock").cloned().unwrap_or_else(|| "10.77.0.0/16".into()),
                        "RegionId": params.get("RegionId").cloned().unwrap_or_else(|| "cn-hangzhou".into()),
                        "IsDefault": false,
                        "Status": "Available",
                        "Tags": { "Tag": tags }
                    }));
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "VpcId": vpc_id,
                            "RequestId": "req-cvpc-1"
                        })),
                    )
                        .into_response()
                }
            }
            ("2016-04-28", "DescribeVpcs") => {
                let vpc_id_filter = params.get("VpcId").cloned();
                let region_filter = params.get("RegionId").cloned();
                let tag_filters = extract_tag_filters(&params);
                let vpcs: Vec<Value> = f
                    .vpcs
                    .iter()
                    .filter(|vpc| {
                        if let Some(ref reg) = region_filter
                            && let Some(vpc_reg) = vpc["RegionId"].as_str()
                            && vpc_reg != reg
                        {
                            return false;
                        }
                        if let Some(ref id) = vpc_id_filter
                            && vpc["VpcId"].as_str() != Some(id.as_str())
                        {
                            return false;
                        }
                        matches_tag_filters(vpc, &tag_filters)
                    })
                    .cloned()
                    .collect();
                let (page_items, total, page_num, page_size) = paginate(vpcs, &params);
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "Vpcs": { "Vpc": page_items },
                        "TotalCount": total,
                        "PageNumber": page_num,
                        "PageSize": page_size,
                        "RequestId": "req-vpc-1"
                    })),
                )
                    .into_response()
            }
            ("2016-04-28", "DeleteVpc") => {
                let vpc_id = params.get("VpcId").cloned().unwrap_or_default();
                let has_children = f
                    .vswitches
                    .iter()
                    .any(|v| v["VpcId"].as_str() == Some(&vpc_id))
                    || f.security_groups
                        .iter()
                        .any(|sg| sg["VpcId"].as_str() == Some(&vpc_id));
                if has_children {
                    err(
                        StatusCode::BAD_REQUEST,
                        "DependencyViolation",
                        "VPC has dependent VSwitches or SecurityGroups.",
                    )
                } else if let Some(pos) = f
                    .vpcs
                    .iter()
                    .position(|v| v["VpcId"].as_str() == Some(&vpc_id))
                {
                    if f.vpcs[pos]["IsDefault"].as_bool().unwrap_or(false) {
                        err(
                            StatusCode::BAD_REQUEST,
                            "Forbidden.DefaultVpc",
                            "Cannot delete default VPC.",
                        )
                    } else {
                        f.vpcs.remove(pos);
                        (
                            StatusCode::OK,
                            axum::Json(json!({ "RequestId": "req-dvpc-1" })),
                        )
                            .into_response()
                    }
                } else {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidVpcId.NotFound",
                        "VPC not found.",
                    )
                }
            }
            ("2016-04-28", "CreateVSwitch") => {
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    err(
                        StatusCode::PRECONDITION_FAILED,
                        "DryRunOperation",
                        "Request validation has been passed with DryRun flag set.",
                    )
                } else {
                    let vpc_id = params.get("VpcId").cloned().unwrap_or_default();
                    let cidr = params.get("CidrBlock").cloned().unwrap_or_default();
                    let overlaps = f.vswitches.iter().any(|v| {
                        v["VpcId"].as_str() == Some(&vpc_id)
                            && v["CidrBlock"]
                                .as_str()
                                .is_some_and(|c| cidrs_overlap(c, &cidr))
                    });
                    if overlaps {
                        err(
                            StatusCode::BAD_REQUEST,
                            "InvalidCidrBlock.Overlapping",
                            "VSwitch CIDR overlaps an existing VSwitch.",
                        )
                    } else {
                        let vsw_id = format!("vsw-fake-{}", f.next_id);
                        f.next_id += 1;
                        let tags = parse_tag_params(&params, false);
                        f.vswitches.push(json!({
                            "VSwitchId": vsw_id,
                            "VSwitchName": params.get("VSwitchName").cloned().unwrap_or_default(),
                            "VpcId": vpc_id,
                            "ZoneId": params.get("ZoneId").cloned().unwrap_or_default(),
                            "CidrBlock": cidr,
                            "RegionId": params.get("RegionId").cloned().unwrap_or_else(|| "cn-hangzhou".into()),
                            "IsDefault": false,
                            "Status": "Available",
                            "Tags": { "Tag": tags }
                        }));
                        (
                            StatusCode::OK,
                            axum::Json(json!({
                                "VSwitchId": vsw_id,
                                "RequestId": "req-cvsw-1"
                            })),
                        )
                            .into_response()
                    }
                }
            }
            ("2016-04-28", "DescribeVSwitches") => {
                let vpc_filter = params.get("VpcId").cloned();
                let zone_filter = params.get("ZoneId").cloned();
                let vsw_id_filter = params.get("VSwitchId").cloned();
                let region_filter = params.get("RegionId").cloned();
                let tag_filters = extract_tag_filters(&params);
                let vsw: Vec<Value> = f
                    .vswitches
                    .iter()
                    .filter(|v| {
                        if let Some(ref reg) = region_filter
                            && let Some(v_reg) = v["RegionId"].as_str()
                            && v_reg != reg
                        {
                            return false;
                        }
                        if let Some(ref vpc) = vpc_filter
                            && v["VpcId"].as_str() != Some(vpc.as_str())
                        {
                            return false;
                        }
                        if let Some(ref z) = zone_filter
                            && v["ZoneId"].as_str() != Some(z.as_str())
                        {
                            return false;
                        }
                        if let Some(ref id) = vsw_id_filter
                            && v["VSwitchId"].as_str() != Some(id.as_str())
                        {
                            return false;
                        }
                        matches_tag_filters(v, &tag_filters)
                    })
                    .cloned()
                    .collect();
                let (page_items, total, page_num, page_size) = paginate(vsw, &params);
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "VSwitches": { "VSwitch": page_items },
                        "TotalCount": total,
                        "PageNumber": page_num,
                        "PageSize": page_size,
                        "RequestId": "req-vsw-1"
                    })),
                )
                    .into_response()
            }
            ("2016-04-28", "DeleteVSwitch") => {
                if f.transient_dependency_errors > 0 {
                    f.transient_dependency_errors -= 1;
                    err(
                        StatusCode::BAD_REQUEST,
                        "DependencyViolation",
                        "VSwitch has active instances.",
                    )
                } else {
                    let vsw_id = params.get("VSwitchId").cloned().unwrap_or_default();
                    let in_use = f
                        .instances
                        .values()
                        .any(|inst| inst["VpcAttributes"]["VSwitchId"].as_str() == Some(&vsw_id));
                    if in_use {
                        err(
                            StatusCode::BAD_REQUEST,
                            "DependencyViolation",
                            "VSwitch is in use by an instance.",
                        )
                    } else if let Some(pos) = f
                        .vswitches
                        .iter()
                        .position(|v| v["VSwitchId"].as_str() == Some(&vsw_id))
                    {
                        f.vswitches.remove(pos);
                        (
                            StatusCode::OK,
                            axum::Json(json!({ "RequestId": "req-dvsw-1" })),
                        )
                            .into_response()
                    } else {
                        err(
                            StatusCode::NOT_FOUND,
                            "InvalidVSwitchId.NotFound",
                            "VSwitch not found.",
                        )
                    }
                }
            }
            ("2014-05-26", "RunInstances") => {
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    if let Some((status_u16, ref code, ref msg)) = f.run_instances_dry_run_error {
                        let st =
                            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_REQUEST);
                        err(st, code, msg)
                    } else if f.run_instances_missing_vswitch && !params.contains_key("VSwitchId") {
                        err(
                            StatusCode::BAD_REQUEST,
                            "InvalidVSwitchId.NotFound",
                            "The specified VSwitchId does not exist.",
                        )
                    } else {
                        err(
                            StatusCode::PRECONDITION_FAILED,
                            "DryRunOperation",
                            "Request validation has been passed with DryRun flag set.",
                        )
                    }
                } else if let Some((status_u16, ref code, ref msg)) = f.run_instances_error {
                    let st = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_REQUEST);
                    err(st, code, msg)
                } else if let Some(zone_err) = params
                    .get("ZoneId")
                    .and_then(|z| f.sold_out_zones.get(z).or_else(|| f.run_fail_zones.get(z)))
                    .cloned()
                {
                    err(
                        StatusCode::FORBIDDEN,
                        &zone_err,
                        "No capacity available in requested zone.",
                    )
                } else {
                    let id = format!("i-fake-{}", f.next_id);
                    f.next_id += 1;
                    let region = params
                        .get("RegionId")
                        .cloned()
                        .unwrap_or_else(|| "cn-hangzhou".into());
                    let vsw_id = params.get("VSwitchId").cloned().unwrap_or_default();
                    let vpc_id = f
                        .vswitches
                        .iter()
                        .find(|v| v["VSwitchId"].as_str() == Some(&vsw_id))
                        .and_then(|v| v["VpcId"].as_str())
                        .unwrap_or("")
                        .to_string();
                    let sg_id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                    let bw_out = params
                        .get("InternetMaxBandwidthOut")
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(0);
                    let pub_ips: Vec<String> = if bw_out > 0 {
                        vec!["203.0.113.10".into()]
                    } else {
                        vec![]
                    };
                    let tags = parse_tag_params(&params, true);
                    f.instances.insert(
                        id.clone(),
                        json!({
                            "InstanceId": id,
                            "InstanceName": params.get("InstanceName").cloned().unwrap_or_default(),
                            "HostName": params.get("HostName").cloned().unwrap_or_default(),
                            "InstanceType": params.get("InstanceType").cloned().unwrap_or_default(),
                            "ImageId": params.get("ImageId").cloned().unwrap_or_default(),
                            "Status": "Running",
                            "RegionId": region,
                            "ZoneId": params.get("ZoneId").cloned().unwrap_or_default(),
                            "InstanceChargeType": params.get("InstanceChargeType").cloned().unwrap_or_default(),
                            "StoppedMode": params.get("StoppedMode").cloned().unwrap_or_default(),
                            "AutoReleaseTime": params.get("AutoReleaseTime").cloned().unwrap_or_default(),
                            "InternetChargeType": params.get("InternetChargeType").cloned().unwrap_or_default(),
                            "InternetMaxBandwidthOut": bw_out,
                            "PublicIpAddress": { "IpAddress": pub_ips },
                            "MetadataOptions": {
                                "HttpEndpoint": params.get("HttpEndpoint").cloned().unwrap_or_default(),
                                "HttpTokens": params.get("HttpTokens").cloned().unwrap_or_default(),
                            },
                            "SystemDisk": {
                                "Category": params.get("SystemDisk.Category").cloned().unwrap_or_default(),
                                "Size": params.get("SystemDisk.Size").cloned().unwrap_or_default(),
                            },
                            "VpcAttributes": {
                                "VpcId": vpc_id,
                                "VSwitchId": vsw_id,
                            },
                            "SecurityGroupIds": {
                                "SecurityGroupId": [sg_id]
                            },
                            "Tags": { "Tag": tags }
                        }),
                    );
                    if let Some(hook) = f.on_run_instance.clone() {
                        post_run_hook = Some((hook, id.clone(), params.clone()));
                    }
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "InstanceIdSets": { "InstanceIdSet": [id] },
                            "RequestId": "req-run-1"
                        })),
                    )
                        .into_response()
                }
            }
            ("2014-05-26", "StopInstance") => {
                let id = params.get("InstanceId").cloned().unwrap_or_default();
                if let Some(inst) = f.instances.get_mut(&id) {
                    inst["Status"] = json!("Stopped");
                    if let Some(mode) = params.get("StoppedMode") {
                        inst["StoppedMode"] = json!(mode);
                    }
                    (
                        StatusCode::OK,
                        axum::Json(json!({ "RequestId": "req-stop-1" })),
                    )
                        .into_response()
                } else {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidInstanceId.NotFound",
                        "Instance not found.",
                    )
                }
            }
            ("2014-05-26", "StartInstance") => {
                let id = params.get("InstanceId").cloned().unwrap_or_default();
                if let Some(inst) = f.instances.get_mut(&id) {
                    inst["Status"] = json!("Running");
                    (
                        StatusCode::OK,
                        axum::Json(json!({ "RequestId": "req-start-1" })),
                    )
                        .into_response()
                } else {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidInstanceId.NotFound",
                        "Instance not found.",
                    )
                }
            }
            ("2014-05-26", "DeleteInstance") => {
                let id = params.get("InstanceId").cloned().unwrap_or_default();
                if f.instances.remove(&id).is_some() {
                    (
                        StatusCode::OK,
                        axum::Json(json!({ "RequestId": "req-del-1" })),
                    )
                        .into_response()
                } else {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidInstanceId.NotFound",
                        "Instance not found.",
                    )
                }
            }
            ("2014-05-26", "GetInstanceConsoleOutput") => {
                let id = params.get("InstanceId").cloned().unwrap_or_default();
                if !f.instances.contains_key(&id) {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidInstanceId.NotFound",
                        "Instance not found.",
                    )
                } else {
                    let encoded = f
                        .console_outputs
                        .get(&id)
                        .map(|raw| base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()))
                        .unwrap_or_default();
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "InstanceId": id,
                            "ConsoleOutput": encoded,
                            "RequestId": "req-console-1"
                        })),
                    )
                        .into_response()
                }
            }
            _ => err(
                StatusCode::BAD_REQUEST,
                "InvalidAction.NotFound",
                &format!("Unsupported action {version}:{action}"),
            ),
        };
        (resp, post_run_hook)
    };

    if let Some((hook, id, params)) = hook_call {
        hook(&id, &params);
    }
    resp
}
