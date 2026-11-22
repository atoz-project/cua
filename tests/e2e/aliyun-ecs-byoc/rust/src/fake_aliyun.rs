// SPDX-License-Identifier: MIT

use std::collections::{BTreeMap, BTreeSet};
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
    pub host: String,
    pub access_key_id: String,
    pub params: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootFailMode {
    StopImmediately,
    TerminateImmediately,
    NeverJoinRelay,
}

#[derive(Clone, Debug)]
pub struct FakeVpc {
    pub vpc_id: String,
    pub region_id: String,
    pub cidr_block: String,
    pub vpc_name: String,
    pub tags: BTreeMap<String, String>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug)]
pub struct FakeVSwitch {
    pub vswitch_id: String,
    pub vpc_id: String,
    pub zone_id: String,
    pub region_id: String,
    pub cidr_block: String,
    pub vswitch_name: String,
    pub tags: BTreeMap<String, String>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug)]
pub struct FakeSg {
    pub sg_id: String,
    pub vpc_id: String,
    pub region_id: String,
    pub sg_name: String,
    pub tags: BTreeMap<String, String>,
    pub ingress_rules: Vec<Value>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug)]
pub struct FakeInstance {
    pub instance_id: String,
    pub instance_name: String,
    pub region_id: String,
    pub zone_id: String,
    pub vpc_id: String,
    pub vswitch_id: String,
    pub security_group_id: String,
    pub instance_type: String,
    pub image_id: String,
    pub status: String,
    pub instance_charge_type: String,
    pub stopped_mode: String,
    pub auto_release_time: Option<String>,
    pub http_tokens: Option<String>,
    pub key_pair_name: Option<String>,
    pub ram_role_name: Option<String>,
    pub internet_max_bandwidth_out: Option<String>,
    pub system_disk_category: Option<String>,
    pub system_disk_size: Option<String>,
    pub user_data_raw: String,
    pub user_data_decoded: String,
    pub tags: BTreeMap<String, String>,
    pub client_token: Option<String>,
    pub machine_id: Option<String>,
}

impl FakeInstance {
    pub fn to_api_json(&self) -> Value {
        let tag_items: Vec<Value> = self
            .tags
            .iter()
            .map(|(k, v)| json!({ "TagKey": k, "TagValue": v }))
            .collect();
        json!({
            "InstanceId": self.instance_id,
            "InstanceName": self.instance_name,
            "RegionId": self.region_id,
            "ZoneId": self.zone_id,
            "InstanceType": self.instance_type,
            "ImageId": self.image_id,
            "Status": self.status,
            "InstanceChargeType": self.instance_charge_type,
            "StoppedMode": self.stopped_mode,
            "AutoReleaseTime": self.auto_release_time,
            "VpcAttributes": {
                "VpcId": self.vpc_id,
                "VSwitchId": self.vswitch_id,
                "PrivateIpAddress": { "IpAddress": ["172.16.0.10"] }
            },
            "SecurityGroupIds": {
                "SecurityGroupId": if self.security_group_id.is_empty() {
                    vec![]
                } else {
                    vec![self.security_group_id.clone()]
                }
            },
            "PublicIpAddress": {
                "IpAddress": if self.internet_max_bandwidth_out.as_deref() == Some("0") {
                    Vec::<String>::new()
                } else {
                    vec!["47.96.0.10".to_string()]
                }
            },
            "Tags": { "Tag": tag_items }
        })
    }
}

#[derive(Clone, Debug)]
pub struct FakeImage {
    pub image_id: String,
    pub image_name: String,
    pub os_type: String,
    pub arch: String,
    pub status: String,
    pub owner_alias: String,
    pub region_id: String,
}

#[derive(Clone, Debug)]
pub struct FakeInstanceType {
    pub id: String,
    pub cpu_core_count: u32,
    pub memory_size_gb: f64,
}

pub type BootCallback = Arc<dyn Fn(&FakeInstance, &BTreeMap<String, String>) + Send + Sync>;
pub type StateCallback = Arc<dyn Fn(&FakeInstance, bool) + Send + Sync>;

pub struct FakeAliyun {
    pub keys: BTreeMap<String, String>,
    pub regions: Vec<String>,
    pub zones: BTreeMap<String, Vec<String>>,
    pub instance_types: Vec<FakeInstanceType>,
    pub images: Vec<FakeImage>,
    pub vpcs: BTreeMap<String, FakeVpc>,
    pub vswitches: BTreeMap<String, FakeVSwitch>,
    pub security_groups: BTreeMap<String, FakeSg>,
    pub security_group_rules: BTreeMap<String, Vec<Value>>,
    pub instances: BTreeMap<String, FakeInstance>,
    pub calls: Vec<RecordedCall>,
    pub authorize_sg_calls: usize,
    pub throttle: u32,
    pub forbidden_actions: BTreeSet<String>,
    pub enforce_cua_managed_tag_condition: bool,
    pub run_instances_missing_vswitch: bool,
    pub run_instances_dry_run_error: Option<(u16, String, String)>,
    pub force_auth_error: Option<(String, String)>,
    pub sold_out_zones: BTreeSet<String>,
    pub run_fail_zones: BTreeSet<String>,
    pub unsupported_zones: BTreeSet<String>,
    pub boot_fail: Option<BootFailMode>,
    pub console_output: Option<String>,
    pub console_error: bool,
    pub fail_delete: bool,
    pub fail_run_instances: bool,
    pub client_tokens: BTreeMap<String, String>,
    pub on_boot: Option<BootCallback>,
    pub on_power: Option<StateCallback>,
    next_id: u64,
}

impl Default for FakeAliyun {
    fn default() -> Self {
        let mut keys = BTreeMap::new();
        keys.insert("LTAI_TEST_AK".to_string(), "secret123".to_string());

        let regions: Vec<String> = vec![
            "cn-hangzhou".into(),
            "cn-shanghai".into(),
            "cn-beijing".into(),
            "ap-southeast-1".into(),
        ];

        let mut zones = BTreeMap::new();
        for r in &regions {
            zones.insert(
                r.clone(),
                vec![format!("{r}-h"), format!("{r}-i"), format!("{r}-j")],
            );
        }

        let mut images = Vec::new();
        for r in &regions {
            images.push(FakeImage {
                image_id: "ubuntu_24_04_x64_20G_alibase_20250101.vhd".into(),
                image_name: "ubuntu_24_04_x64_20G_alibase_20250101.vhd".into(),
                os_type: "linux".into(),
                arch: "x86_64".into(),
                status: "Available".into(),
                owner_alias: "system".into(),
                region_id: r.clone(),
            });
            images.push(FakeImage {
                image_id: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250101.vhd".into(),
                image_name: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250101.vhd".into(),
                os_type: "windows".into(),
                arch: "x86_64".into(),
                status: "Available".into(),
                owner_alias: "system".into(),
                region_id: r.clone(),
            });
        }

        let instance_types = vec![
            FakeInstanceType {
                id: "ecs.e-c1m2.large".into(),
                cpu_core_count: 2,
                memory_size_gb: 4.0,
            },
            FakeInstanceType {
                id: "ecs.e-c1m1.large".into(),
                cpu_core_count: 2,
                memory_size_gb: 2.0,
            },
            FakeInstanceType {
                id: "ecs.c7.xlarge".into(),
                cpu_core_count: 4,
                memory_size_gb: 8.0,
            },
            FakeInstanceType {
                id: "ecs.g7.large".into(),
                cpu_core_count: 2,
                memory_size_gb: 8.0,
            },
            FakeInstanceType {
                id: "ecs.g7.xlarge".into(),
                cpu_core_count: 4,
                memory_size_gb: 16.0,
            },
            FakeInstanceType {
                id: "ecs.g7.2xlarge".into(),
                cpu_core_count: 8,
                memory_size_gb: 32.0,
            },
        ];

        Self {
            keys,
            regions,
            zones,
            instance_types,
            images,
            vpcs: BTreeMap::new(),
            vswitches: BTreeMap::new(),
            security_groups: BTreeMap::new(),
            security_group_rules: BTreeMap::new(),
            instances: BTreeMap::new(),
            calls: Vec::new(),
            authorize_sg_calls: 0,
            throttle: 0,
            forbidden_actions: BTreeSet::new(),
            enforce_cua_managed_tag_condition: false,
            run_instances_missing_vswitch: false,
            run_instances_dry_run_error: None,
            force_auth_error: None,
            sold_out_zones: BTreeSet::new(),
            run_fail_zones: BTreeSet::new(),
            unsupported_zones: BTreeSet::new(),
            boot_fail: None,
            console_output: None,
            console_error: false,
            fail_delete: false,
            fail_run_instances: false,
            client_tokens: BTreeMap::new(),
            on_boot: None,
            on_power: None,
            next_id: 1,
        }
    }
}

impl FakeAliyun {
    fn next_seq(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn add_key(&mut self, ak: &str, sk: &str) {
        self.keys.insert(ak.to_string(), sk.to_string());
    }

    pub fn add_image(&mut self, img: FakeImage) {
        self.images.push(img);
    }

    pub fn count_calls(&self, action: &str) -> usize {
        self.calls.iter().filter(|c| c.action == action).count()
    }

    pub fn calls_for(&self, action: &str) -> Vec<RecordedCall> {
        self.calls
            .iter()
            .filter(|c| c.action == action)
            .cloned()
            .collect()
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

fn parse_tags(params: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    for i in 1..=32 {
        if let Some(k) = params.get(&format!("Tag.{i}.Key")) {
            let v = params
                .get(&format!("Tag.{i}.Value"))
                .cloned()
                .unwrap_or_default();
            tags.insert(k.clone(), v);
        }
    }
    tags
}

fn has_cua_managed_tag(tags: &BTreeMap<String, String>) -> bool {
    tags.get("cua-managed").map(String::as_str) == Some("true")
}

fn matches_glob(pattern: &str, text: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        text.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        text.ends_with(suffix)
    } else {
        text == pattern
    }
}

type Acs3VerifyOk = (String, String, String, String);
type Acs3VerifyErr = (StatusCode, &'static str, String);

fn verify_acs3_signature(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    keys: &BTreeMap<String, String>,
) -> std::result::Result<Acs3VerifyOk, Acs3VerifyErr> {
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

    let host_hdr = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    Ok((ak, action, version, host_hdr))
}

fn action_permission_key(action: &str, version: &str) -> String {
    let svc = match version {
        "2015-04-01" => "sts",
        "2016-04-28" => "vpc",
        _ => "ecs",
    };
    format!("{svc}:{action}")
}

fn parse_instance_ids_param(params: &BTreeMap<String, String>) -> Vec<String> {
    if let Some(id) = params.get("InstanceId")
        && !id.is_empty()
    {
        return vec![id.clone()];
    }
    if let Some(json_ids) = params.get("InstanceIds")
        && let Ok(parsed) = serde_json::from_str::<Vec<String>>(json_ids)
    {
        return parsed;
    }
    let mut out = Vec::new();
    for i in 1..=32 {
        if let Some(id) = params.get(&format!("InstanceId.{i}")) {
            out.push(id.clone());
        }
    }
    out
}

fn extract_machine_id(user_data: &str) -> Option<String> {
    let files = crate::decode_cloud_init_write_files(user_data);
    if let Some(mid) = files
        .get("/etc/cua/relay/machine-id")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return Some(mid.to_string());
    }
    let ps_files = crate::decode_ps_puts(user_data);
    if let Some(mid) = ps_files
        .get("machine-id")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return Some(mid.to_string());
    }
    let expanded = crate::decode_user_data_scripts(user_data);
    for line in expanded.lines() {
        let trimmed = line.trim();
        for marker in ["--machine-id ", "CUA_MACHINE_ID=", "machine_id="] {
            if let Some(idx) = trimmed.find(marker) {
                let rest = &trimmed[idx + marker.len()..];
                let val = rest
                    .trim_start_matches(['"', '\'', '='])
                    .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ';')
                    .next()
                    .unwrap_or("");
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
        if let Some(idx) = trimmed.find("/m/") {
            let rest = &trimmed[idx + 3..];
            let val = rest
                .split(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | ';' | '`'))
                .next()
                .unwrap_or("");
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

pub async fn handle(
    State(s): State<S>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut post_boot: Option<(FakeInstance, BTreeMap<String, String>, BootCallback)> = None;
    let mut post_power: Option<(FakeInstance, bool, StateCallback)> = None;

    let resp = {
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

        let (ak, action, version, host_hdr) =
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
            host: host_hdr,
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
            ("2014-05-26", "DescribeZones") => {
                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let zone_list: Vec<Value> = f
                    .zones
                    .get(&region)
                    .cloned()
                    .unwrap_or_else(|| vec![format!("{region}-h")])
                    .into_iter()
                    .map(|z| json!({ "ZoneId": z, "LocalName": z }))
                    .collect();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "Zones": { "Zone": zone_list },
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
                let zone_ids = f
                    .zones
                    .get(&region)
                    .cloned()
                    .unwrap_or_else(|| vec![format!("{region}-h")]);
                let avail_zones: Vec<Value> = zone_ids
                    .iter()
                    .map(|z| {
                        let supported: Vec<Value> = f
                            .instance_types
                            .iter()
                            .map(|t| {
                                let status = if f.sold_out_zones.contains(z) {
                                    "WithoutStock"
                                } else {
                                    "Available"
                                };
                                json!({
                                    "Value": t.id,
                                    "Status": status,
                                    "StatusCategory": if status == "Available" { "WithStock" } else { "WithoutStock" }
                                })
                            })
                            .collect();
                        json!({
                            "RegionId": region,
                            "ZoneId": z,
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
                            "AvailableZone": avail_zones
                        },
                        "RequestId": "req-avail-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeInstanceTypes") => {
                let repeat_list: Vec<String> = (1..=10)
                    .filter_map(|i| params.get(&format!("InstanceTypes.{i}")).cloned())
                    .collect();
                let requested: Option<Vec<String>> = if !repeat_list.is_empty() {
                    Some(repeat_list)
                } else {
                    params
                        .get("InstanceTypes")
                        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                        .or_else(|| params.get("InstanceType").map(|id| vec![id.clone()]))
                };
                let items: Vec<Value> = f
                    .instance_types
                    .iter()
                    .filter(|t| {
                        requested
                            .as_ref()
                            .is_none_or(|reqs| reqs.iter().any(|id| id == &t.id))
                    })
                    .map(|t| {
                        json!({
                            "InstanceTypeId": t.id,
                            "CpuCoreCount": t.cpu_core_count,
                            "MemorySize": t.memory_size_gb,
                        })
                    })
                    .collect();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "InstanceTypes": { "InstanceType": items },
                        "RequestId": "req-itypes-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeImages") => {
                let region_filter = params.get("RegionId").cloned();
                let image_id_filter = params.get("ImageId").cloned();
                let image_name_filter = params.get("ImageName").cloned();
                let os_filter = params.get("OSType").cloned();
                let owner_filter = params.get("ImageOwnerAlias").cloned();
                let status_filter = params.get("Status").cloned();

                let items: Vec<Value> = f
                    .images
                    .iter()
                    .filter(|img| {
                        region_filter.as_ref().is_none_or(|r| &img.region_id == r)
                            && image_id_filter
                                .as_ref()
                                .is_none_or(|id| id.split(',').any(|x| x.trim() == img.image_id))
                            && image_name_filter
                                .as_ref()
                                .is_none_or(|pat| matches_glob(pat, &img.image_name))
                            && os_filter
                                .as_ref()
                                .is_none_or(|os| img.os_type.eq_ignore_ascii_case(os))
                            && owner_filter
                                .as_ref()
                                .is_none_or(|o| img.owner_alias.eq_ignore_ascii_case(o))
                            && status_filter
                                .as_ref()
                                .is_none_or(|st| img.status.eq_ignore_ascii_case(st))
                    })
                    .map(|img| {
                        json!({
                            "ImageId": img.image_id,
                            "ImageName": img.image_name,
                            "OSType": img.os_type,
                            "Architecture": img.arch,
                            "Status": img.status,
                            "ImageOwnerAlias": img.owner_alias,
                        })
                    })
                    .collect();
                let total = items.len();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "Images": { "Image": items },
                        "TotalCount": total,
                        "RequestId": "req-images-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeInstances") => {
                let tag_filters = parse_tags(&params);
                let id_filter: Option<Vec<String>> = params
                    .get("InstanceIds")
                    .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok());
                let region_filter = params.get("RegionId").cloned();
                let items: Vec<Value> = f
                    .instances
                    .values()
                    .filter(|inst| {
                        if let Some(ref reg) = region_filter
                            && &inst.region_id != reg
                        {
                            return false;
                        }
                        if let Some(ref ids) = id_filter
                            && !ids.iter().any(|id| id == &inst.instance_id)
                        {
                            return false;
                        }
                        tag_filters.iter().all(|(k, v)| inst.tags.get(k) == Some(v))
                    })
                    .map(FakeInstance::to_api_json)
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
            ("2014-05-26", "CreateSecurityGroup") => {
                // Real Alibaba Cloud ECS `CreateSecurityGroup` does NOT support `DryRun=true`:
                // it ignores `DryRun` and creates the security group returning HTTP 200 OK.
                let tags = parse_tags(&params);
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true tag on ecs:CreateSecurityGroup",
                    );
                }
                let seq = f.next_seq();
                let id = format!("sg-fake-{seq}");
                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let vpc_id = params.get("VpcId").cloned().unwrap_or_default();
                let sg_name = params.get("SecurityGroupName").cloned().unwrap_or_default();
                f.security_groups.insert(
                    id.clone(),
                    FakeSg {
                        sg_id: id.clone(),
                        vpc_id,
                        region_id: region,
                        sg_name,
                        tags,
                        ingress_rules: Vec::new(),
                        is_user_owned: false,
                    },
                );
                f.security_group_rules.insert(id.clone(), Vec::new());
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "SecurityGroupId": id,
                        "RequestId": "req-csg-1"
                    })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeSecurityGroups") => {
                let vpc_filter = params.get("VpcId").cloned();
                let sg_id_filter = params.get("SecurityGroupId").cloned();
                let region_filter = params.get("RegionId").cloned();
                let tag_filters = parse_tags(&params);
                let sgs: Vec<Value> = f
                    .security_groups
                    .values()
                    .filter(|sg| {
                        vpc_filter.as_ref().is_none_or(|v| &sg.vpc_id == v)
                            && sg_id_filter.as_ref().is_none_or(|id| &sg.sg_id == id)
                            && region_filter.as_ref().is_none_or(|r| &sg.region_id == r)
                            && tag_filters.iter().all(|(k, v)| sg.tags.get(k) == Some(v))
                    })
                    .map(|sg| {
                        let tag_items: Vec<Value> = sg
                            .tags
                            .iter()
                            .map(|(k, v)| json!({ "TagKey": k, "TagValue": v }))
                            .collect();
                        json!({
                            "SecurityGroupId": sg.sg_id,
                            "SecurityGroupName": sg.sg_name,
                            "VpcId": sg.vpc_id,
                            "RegionId": sg.region_id,
                            "Tags": { "Tag": tag_items },
                        })
                    })
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
            ("2014-05-26", "DeleteSecurityGroup") => {
                let id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                let Some(sg) = f.security_groups.get(&id).cloned() else {
                    return err(
                        StatusCode::NOT_FOUND,
                        "InvalidSecurityGroupId.NotFound",
                        "The specified SecurityGroupId does not exist.",
                    );
                };
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&sg.tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true on ecs:DeleteSecurityGroup",
                    );
                }
                if f.instances.values().any(|i| i.security_group_id == id) {
                    return err(
                        StatusCode::CONFLICT,
                        "DependencyViolation",
                        "SecurityGroup still has instances.",
                    );
                }
                f.security_groups.remove(&id);
                f.security_group_rules.remove(&id);
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-dsg-1" })),
                )
                    .into_response()
            }
            ("2014-05-26", "DescribeSecurityGroupAttribute") => {
                let sg_id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                if let Some(sg) = f.security_groups.get(&sg_id).cloned() {
                    let mut rules = f
                        .security_group_rules
                        .get(&sg_id)
                        .cloned()
                        .unwrap_or_default();
                    for r in &sg.ingress_rules {
                        let mut rule = r.clone();
                        if let Some(obj) = rule.as_object_mut() {
                            obj.entry("Direction".to_string())
                                .or_insert_with(|| json!("ingress"));
                            obj.entry("Policy".to_string())
                                .or_insert_with(|| json!("Accept"));
                        }
                        rules.push(rule);
                    }
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "SecurityGroupId": sg_id,
                            "VpcId": sg.vpc_id,
                            "RegionId": sg.region_id,
                            "InnerAccessPolicy": "Drop",
                            "Permissions": { "Permission": rules },
                            "RequestId": "req-sga-1"
                        })),
                    )
                        .into_response()
                } else {
                    err(
                        StatusCode::NOT_FOUND,
                        "InvalidSecurityGroupId.NotFound",
                        "The specified SecurityGroupId does not exist.",
                    )
                }
            }
            ("2014-05-26", "AuthorizeSecurityGroupEgress") => {
                let sg_id = params.get("SecurityGroupId").cloned().unwrap_or_default();
                let Some(sg) = f.security_groups.get(&sg_id).cloned() else {
                    return err(
                        StatusCode::NOT_FOUND,
                        "InvalidSecurityGroupId.NotFound",
                        "The specified SecurityGroupId does not exist.",
                    );
                };
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&sg.tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true on ecs:AuthorizeSecurityGroupEgress",
                    );
                }
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
            ("2014-05-26", "AuthorizeSecurityGroup") => {
                f.authorize_sg_calls += 1;
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-asg-1" })),
                )
                    .into_response()
            }
            ("2016-04-28", "CreateVpc") => {
                let tags = parse_tags(&params);
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true tag on vpc:CreateVpc",
                    );
                }
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    return err(
                        StatusCode::PRECONDITION_FAILED,
                        "DryRunOperation",
                        "Request validation has been passed with DryRun flag set.",
                    );
                }
                let seq = f.next_seq();
                let id = format!("vpc-fake-{seq}");
                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let cidr = params
                    .get("CidrBlock")
                    .cloned()
                    .unwrap_or_else(|| "172.16.0.0/16".into());
                let name = params.get("VpcName").cloned().unwrap_or_default();
                f.vpcs.insert(
                    id.clone(),
                    FakeVpc {
                        vpc_id: id.clone(),
                        region_id: region,
                        cidr_block: cidr,
                        vpc_name: name,
                        tags,
                        is_user_owned: false,
                    },
                );
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "VpcId": id,
                        "RequestId": "req-cvpc-1"
                    })),
                )
                    .into_response()
            }
            ("2016-04-28", "DescribeVpcs") => {
                let vpc_id_filter = params.get("VpcId").cloned();
                let region_filter = params.get("RegionId").cloned();
                let tag_filters = parse_tags(&params);
                let items: Vec<Value> = f
                    .vpcs
                    .values()
                    .filter(|v| {
                        vpc_id_filter
                            .as_ref()
                            .is_none_or(|id| id.split(',').any(|x| x.trim() == v.vpc_id))
                            && region_filter.as_ref().is_none_or(|r| &v.region_id == r)
                            && tag_filters.iter().all(|(k, val)| v.tags.get(k) == Some(val))
                    })
                    .map(|v| {
                        let tag_items: Vec<Value> = v
                            .tags
                            .iter()
                            .map(|(k, val)| json!({ "Key": k, "Value": val, "TagKey": k, "TagValue": val }))
                            .collect();
                        json!({
                            "VpcId": v.vpc_id,
                            "VpcName": v.vpc_name,
                            "CidrBlock": v.cidr_block,
                            "RegionId": v.region_id,
                            "Status": "Available",
                            "Tags": { "Tag": tag_items },
                        })
                    })
                    .collect();
                let total = items.len();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "Vpcs": { "Vpc": items },
                        "TotalCount": total,
                        "RequestId": "req-vpc-1"
                    })),
                )
                    .into_response()
            }
            ("2016-04-28", "DeleteVpc") => {
                let id = params.get("VpcId").cloned().unwrap_or_default();
                let Some(vpc) = f.vpcs.get(&id).cloned() else {
                    return err(
                        StatusCode::NOT_FOUND,
                        "InvalidVpcId.NotFound",
                        "The specified VpcId does not exist.",
                    );
                };
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&vpc.tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true on vpc:DeleteVpc",
                    );
                }
                if f.vswitches.values().any(|v| v.vpc_id == id)
                    || f.security_groups.values().any(|s| s.vpc_id == id)
                {
                    return err(
                        StatusCode::CONFLICT,
                        "DependencyViolation",
                        "VPC still has dependent VSwitches or SecurityGroups.",
                    );
                }
                f.vpcs.remove(&id);
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-dvpc-1" })),
                )
                    .into_response()
            }
            ("2016-04-28", "CreateVSwitch") => {
                let tags = parse_tags(&params);
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true tag on vpc:CreateVSwitch",
                    );
                }
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    return err(
                        StatusCode::PRECONDITION_FAILED,
                        "DryRunOperation",
                        "Request validation has been passed with DryRun flag set.",
                    );
                }
                let seq = f.next_seq();
                let id = format!("vsw-fake-{seq}");
                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let vpc_id = params.get("VpcId").cloned().unwrap_or_default();
                let zone_id = params
                    .get("ZoneId")
                    .cloned()
                    .unwrap_or_else(|| format!("{region}-h"));
                let cidr = params
                    .get("CidrBlock")
                    .cloned()
                    .unwrap_or_else(|| "172.16.1.0/24".into());
                let name = params.get("VSwitchName").cloned().unwrap_or_default();
                f.vswitches.insert(
                    id.clone(),
                    FakeVSwitch {
                        vswitch_id: id.clone(),
                        vpc_id,
                        zone_id,
                        region_id: region,
                        cidr_block: cidr,
                        vswitch_name: name,
                        tags,
                        is_user_owned: false,
                    },
                );
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "VSwitchId": id,
                        "RequestId": "req-cvsw-1"
                    })),
                )
                    .into_response()
            }
            ("2016-04-28", "DescribeVSwitches") => {
                let vsw_id_filter = params.get("VSwitchId").cloned();
                let vpc_id_filter = params.get("VpcId").cloned();
                let region_filter = params.get("RegionId").cloned();
                let tag_filters = parse_tags(&params);
                let items: Vec<Value> = f
                    .vswitches
                    .values()
                    .filter(|v| {
                        vsw_id_filter.as_ref().is_none_or(|id| &v.vswitch_id == id)
                            && vpc_id_filter.as_ref().is_none_or(|vpc| &v.vpc_id == vpc)
                            && region_filter.as_ref().is_none_or(|r| &v.region_id == r)
                            && tag_filters.iter().all(|(k, val)| v.tags.get(k) == Some(val))
                    })
                    .map(|v| {
                        let tag_items: Vec<Value> = v
                            .tags
                            .iter()
                            .map(|(k, val)| json!({ "Key": k, "Value": val, "TagKey": k, "TagValue": val }))
                            .collect();
                        json!({
                            "VSwitchId": v.vswitch_id,
                            "VSwitchName": v.vswitch_name,
                            "VpcId": v.vpc_id,
                            "ZoneId": v.zone_id,
                            "RegionId": v.region_id,
                            "CidrBlock": v.cidr_block,
                            "Status": "Available",
                            "Tags": { "Tag": tag_items },
                        })
                    })
                    .collect();
                let total = items.len();
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "VSwitches": { "VSwitch": items },
                        "TotalCount": total,
                        "RequestId": "req-vsw-1"
                    })),
                )
                    .into_response()
            }
            ("2016-04-28", "DeleteVSwitch") => {
                let id = params.get("VSwitchId").cloned().unwrap_or_default();
                let Some(vsw) = f.vswitches.get(&id).cloned() else {
                    return err(
                        StatusCode::NOT_FOUND,
                        "InvalidVSwitchId.NotFound",
                        "The specified VSwitchId does not exist.",
                    );
                };
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&vsw.tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true on vpc:DeleteVSwitch",
                    );
                }
                if f.instances.values().any(|i| i.vswitch_id == id) {
                    return err(
                        StatusCode::CONFLICT,
                        "DependencyViolation",
                        "VSwitch still has running or stopped instances.",
                    );
                }
                f.vswitches.remove(&id);
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-dvsw-1" })),
                )
                    .into_response()
            }
            ("2014-05-26", "RunInstances") => {
                if params.get("DryRun").map(String::as_str) == Some("true") {
                    if let Some((status_u16, ref code, ref msg)) = f.run_instances_dry_run_error {
                        let st =
                            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_REQUEST);
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

                if f.fail_run_instances {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "Injected RunInstances failure",
                    );
                }

                let tags = parse_tags(&params);
                if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&tags) {
                    return err(
                        StatusCode::FORBIDDEN,
                        "Forbidden.RAM",
                        "RAM policy Condition requires cua-managed=true tag on ecs:RunInstances",
                    );
                }

                if let Some(ct) = params.get("ClientToken")
                    && let Some(existing_id) = f.client_tokens.get(ct).cloned()
                {
                    return (
                        StatusCode::OK,
                        axum::Json(json!({
                            "InstanceIdSets": { "InstanceIdSet": [existing_id] },
                            "RequestId": "req-run-idempotent"
                        })),
                    )
                        .into_response();
                }

                let region = params
                    .get("RegionId")
                    .cloned()
                    .unwrap_or_else(|| "cn-hangzhou".into());
                let vsw_id = params.get("VSwitchId").cloned().unwrap_or_default();
                let zone_id = params
                    .get("ZoneId")
                    .cloned()
                    .or_else(|| f.vswitches.get(&vsw_id).map(|v| v.zone_id.clone()))
                    .unwrap_or_else(|| format!("{region}-h"));

                if f.sold_out_zones.contains(&zone_id) || f.run_fail_zones.contains(&zone_id) {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "OperationDenied.NoStock",
                        &format!("Zone {zone_id} is out of stock"),
                    );
                }
                if f.unsupported_zones.contains(&zone_id) {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "Zone.NotOnSale",
                        &format!("Zone {zone_id} does not support requested instance type"),
                    );
                }

                let vpc_id = f
                    .vswitches
                    .get(&vsw_id)
                    .map(|v| v.vpc_id.clone())
                    .unwrap_or_default();
                let user_data_raw = params.get("UserData").cloned().unwrap_or_default();
                let user_data_decoded = base64::engine::general_purpose::STANDARD
                    .decode(&user_data_raw)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                let machine_id = extract_machine_id(&user_data_decoded)
                    .or_else(|| tags.get("cua-machine").cloned());

                let seq = f.next_seq();
                let id = format!("i-fake-{seq}");
                let status = match f.boot_fail {
                    Some(BootFailMode::StopImmediately) => "Stopped",
                    _ => "Running",
                }
                .to_string();

                let inst = FakeInstance {
                    instance_id: id.clone(),
                    instance_name: params.get("InstanceName").cloned().unwrap_or_default(),
                    region_id: region,
                    zone_id,
                    vpc_id,
                    vswitch_id: vsw_id,
                    security_group_id: params.get("SecurityGroupId").cloned().unwrap_or_default(),
                    instance_type: params.get("InstanceType").cloned().unwrap_or_default(),
                    image_id: params.get("ImageId").cloned().unwrap_or_default(),
                    status,
                    instance_charge_type: params
                        .get("InstanceChargeType")
                        .cloned()
                        .unwrap_or_default(),
                    stopped_mode: params.get("StoppedMode").cloned().unwrap_or_default(),
                    auto_release_time: params.get("AutoReleaseTime").cloned(),
                    http_tokens: params.get("HttpTokens").cloned(),
                    key_pair_name: params.get("KeyPairName").cloned(),
                    ram_role_name: params.get("RamRoleName").cloned(),
                    internet_max_bandwidth_out: params.get("InternetMaxBandwidthOut").cloned(),
                    system_disk_category: params.get("SystemDisk.Category").cloned(),
                    system_disk_size: params.get("SystemDisk.Size").cloned(),
                    user_data_raw,
                    user_data_decoded,
                    tags,
                    client_token: params.get("ClientToken").cloned(),
                    machine_id,
                };
                if let Some(ref ct) = inst.client_token {
                    f.client_tokens.insert(ct.clone(), id.clone());
                }
                if f.boot_fail != Some(BootFailMode::TerminateImmediately) {
                    f.instances.insert(id.clone(), inst.clone());
                }
                if f.boot_fail.is_none()
                    && let Some(cb) = f.on_boot.clone()
                {
                    post_boot = Some((inst, params.clone(), cb));
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
            ("2014-05-26", "StopInstance" | "StopInstances") => {
                let ids = parse_instance_ids_param(&params);
                for id in &ids {
                    let Some(inst) = f.instances.get(id).cloned() else {
                        return err(
                            StatusCode::NOT_FOUND,
                            "InvalidInstanceId.NotFound",
                            "The specified InstanceId does not exist.",
                        );
                    };
                    if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&inst.tags) {
                        return err(
                            StatusCode::FORBIDDEN,
                            "Forbidden.RAM",
                            "RAM policy Condition requires cua-managed=true on ecs:StopInstance",
                        );
                    }
                }
                let power_cb = f.on_power.clone();
                for id in &ids {
                    if let Some(inst) = f.instances.get_mut(id) {
                        inst.status = "Stopped".into();
                        if let Some(ref cb) = power_cb {
                            post_power = Some((inst.clone(), false, cb.clone()));
                        }
                    }
                }
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-stop-1" })),
                )
                    .into_response()
            }
            ("2014-05-26", "StartInstance" | "StartInstances") => {
                let ids = parse_instance_ids_param(&params);
                for id in &ids {
                    let Some(inst) = f.instances.get(id).cloned() else {
                        return err(
                            StatusCode::NOT_FOUND,
                            "InvalidInstanceId.NotFound",
                            "The specified InstanceId does not exist.",
                        );
                    };
                    if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&inst.tags) {
                        return err(
                            StatusCode::FORBIDDEN,
                            "Forbidden.RAM",
                            "RAM policy Condition requires cua-managed=true on ecs:StartInstance",
                        );
                    }
                }
                let power_cb = f.on_power.clone();
                for id in &ids {
                    if let Some(inst) = f.instances.get_mut(id) {
                        inst.status = "Running".into();
                        if let Some(ref cb) = power_cb {
                            post_power = Some((inst.clone(), true, cb.clone()));
                        }
                    }
                }
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-start-1" })),
                )
                    .into_response()
            }
            ("2014-05-26", "DeleteInstance" | "DeleteInstances") => {
                if f.fail_delete {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "Injected DeleteInstance failure",
                    );
                }
                let ids = parse_instance_ids_param(&params);
                for id in &ids {
                    let Some(inst) = f.instances.get(id).cloned() else {
                        return err(
                            StatusCode::NOT_FOUND,
                            "InvalidInstanceId.NotFound",
                            "The specified InstanceId does not exist.",
                        );
                    };
                    if f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(&inst.tags) {
                        return err(
                            StatusCode::FORBIDDEN,
                            "Forbidden.RAM",
                            "RAM policy Condition requires cua-managed=true on ecs:DeleteInstance",
                        );
                    }
                }
                for id in &ids {
                    if let Some(inst) = f.instances.remove(id)
                        && let Some(cb) = f.on_power.clone()
                    {
                        post_power = Some((inst, false, cb));
                    }
                }
                (
                    StatusCode::OK,
                    axum::Json(json!({ "RequestId": "req-del-1" })),
                )
                    .into_response()
            }
            ("2014-05-26", "GetInstanceConsoleOutput") => {
                if f.console_error {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "Console output unavailable",
                    );
                }
                let raw = f
                    .console_output
                    .clone()
                    .unwrap_or_else(|| "cloud-init: boot log line\n".into());
                let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "InstanceId": params.get("InstanceId").cloned().unwrap_or_default(),
                        "ConsoleOutput": encoded,
                        "RequestId": "req-console-1"
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
    };

    if let Some((inst, params, cb)) = post_boot {
        cb(&inst, &params);
    }
    if let Some((inst, online, cb)) = post_power {
        cb(&inst, online);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_machine_id_decodes_b64_write_files() {
        let mid_b64 = base64::engine::general_purpose::STANDARD.encode("cloud-0123456789abcdef\n");
        let ud = format!(
            "#cloud-config\nwrite_files:\n  - path: /etc/cua/relay/machine-id\n    encoding: b64\n    content: {mid_b64}\n"
        );
        assert_eq!(
            extract_machine_id(&ud).as_deref(),
            Some("cloud-0123456789abcdef")
        );
    }
}
