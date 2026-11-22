// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! ACS3-HMAC-SHA256 signature verification and OpenAPI parameter/CIDR/pagination helpers.

use std::collections::BTreeMap;

use axum::http::{HeaderMap, Method, StatusCode, Uri};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use crate::aliyun::client::rfc3986_encode;
pub(crate) use crate::aliyun::net::cidrs_overlap;

pub type Acs3VerifyOk = (String, String, String, String);
pub type Acs3VerifyErr = (StatusCode, &'static str, String);

pub fn parse_query_params(raw: &str) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn parse_tags(params: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    (1..=32)
        .filter_map(|i| {
            let k = params.get(&format!("Tag.{i}.Key"))?;
            let v = params
                .get(&format!("Tag.{i}.Value"))
                .cloned()
                .unwrap_or_default();
            Some((k.clone(), v))
        })
        .collect()
}

pub fn has_cua_managed_tag(tags: &BTreeMap<String, String>) -> bool {
    tags.get("cua-managed").map(String::as_str) == Some("true")
}

pub fn matches_glob(pattern: &str, text: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        text.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        text.ends_with(suffix)
    } else {
        text == pattern
    }
}

pub fn paginate(
    items: Vec<Value>,
    params: &BTreeMap<String, String>,
) -> (Vec<Value>, usize, usize, usize) {
    let total = items.len();
    let pos = |k, def: usize| {
        params
            .get(k)
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(def)
    };
    let (page_num, page_size) = (pos("PageNumber", 1), pos("PageSize", 50));
    let start = (page_num - 1).saturating_mul(page_size);
    (
        items.into_iter().skip(start).take(page_size).collect(),
        total,
        page_num,
        page_size,
    )
}

pub fn parse_instance_ids_param(params: &BTreeMap<String, String>) -> Vec<String> {
    if let Some(id) = params.get("InstanceId").filter(|s| !s.is_empty()) {
        return vec![id.clone()];
    }
    if let Some(Ok(ids)) = params
        .get("InstanceIds")
        .map(|s| serde_json::from_str::<Vec<String>>(s))
    {
        return ids;
    }
    (1..=32)
        .filter_map(|i| params.get(&format!("InstanceId.{i}")).cloned())
        .collect()
}

pub fn action_permission_key(action: &str, version: &str) -> String {
    let svc = match version {
        "2015-04-01" => "sts",
        "2016-04-28" => "vpc",
        _ => "ecs",
    };
    format!("{svc}:{action}")
}

fn hdr<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

fn unauth(msg: impl Into<String>) -> Acs3VerifyErr {
    (StatusCode::UNAUTHORIZED, "IncompleteSignature", msg.into())
}

fn bad_req(code: &'static str, msg: impl Into<String>) -> Acs3VerifyErr {
    (StatusCode::BAD_REQUEST, code, msg.into())
}

pub fn verify_acs3_signature(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    keys: &BTreeMap<String, String>,
) -> Result<Acs3VerifyOk, Acs3VerifyErr> {
    let auth = hdr(headers, "authorization").ok_or_else(|| unauth("missing Authorization"))?;
    let rest = auth
        .strip_prefix("ACS3-HMAC-SHA256 ")
        .ok_or_else(|| unauth(format!("unexpected Authorization scheme: {auth}")))?;
    let kv: BTreeMap<&str, &str> = rest
        .split(',')
        .filter_map(|p| p.trim().split_once('='))
        .collect();
    let get_auth = |k| {
        kv.get(k)
            .copied()
            .ok_or_else(|| unauth(format!("missing {k}")))
    };
    let (ak, signed_headers_str, got_sig) = (
        get_auth("Credential")?,
        get_auth("SignedHeaders")?,
        get_auth("Signature")?,
    );
    let secret = keys.get(ak).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "InvalidAccessKeyId.NotFound",
            format!("access key {ak:?} not found"),
        )
    })?;

    let req_hdr = |k| {
        hdr(headers, k)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| bad_req("MissingParameter", format!("missing {k}")))
    };
    let (action, version) = (req_hdr("x-acs-action")?, req_hdr("x-acs-version")?);
    for req in [
        "host",
        "x-acs-action",
        "x-acs-content-sha256",
        "x-acs-date",
        "x-acs-signature-nonce",
        "x-acs-version",
    ] {
        if !headers.contains_key(req) {
            return Err(bad_req(
                "IncompleteSignature",
                format!("missing required header {req}"),
            ));
        }
    }

    let expected_body_hash = hex::encode(Sha256::digest(body));
    let got_body_hash = hdr(headers, "x-acs-content-sha256").unwrap_or("");
    if got_body_hash != expected_body_hash {
        return Err(bad_req(
            "SignatureDoesNotMatch",
            format!("body sha256 mismatch: {got_body_hash}"),
        ));
    }

    let signed_headers: Vec<&str> = signed_headers_str.split(';').collect();
    let mut sorted = signed_headers.clone();
    sorted.sort_unstable();
    if signed_headers != sorted || !signed_headers.contains(&"host") {
        return Err(bad_req(
            "IncompleteSignature",
            "SignedHeaders must be sorted lowercase incl. host",
        ));
    }
    for name in headers.keys().map(|k| k.as_str()) {
        if name.starts_with("x-acs-") && !signed_headers.contains(&name) {
            return Err(bad_req(
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
        let mut pairs: Vec<_> = url::form_urlencoded::parse(raw_query.as_bytes())
            .map(|(k, v)| (rfc3986_encode(&k), rfc3986_encode(&v)))
            .collect();
        pairs.sort();
        let rebuilt = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        if rebuilt != raw_query {
            return Err(bad_req(
                "SignatureDoesNotMatch",
                format!("non-canonical query: {raw_query}"),
            ));
        }
        rebuilt
    };

    let mut canonical_headers = String::new();
    for h in &signed_headers {
        let val = hdr(headers, h)
            .ok_or_else(|| bad_req("IncompleteSignature", format!("signed header {h} missing")))?;
        canonical_headers.push_str(&format!("{h}:{}\n", val.trim()));
    }
    let canonical_request = format!(
        "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers_str}\n{expected_body_hash}",
        method.as_str(),
    );
    let string_to_sign = format!(
        "ACS3-HMAC-SHA256\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(string_to_sign.as_bytes());
    if got_sig != hex::encode(mac.finalize().into_bytes()) {
        return Err(bad_req(
            "SignatureDoesNotMatch",
            format!("signature mismatch: {canonical_request:?}"),
        ));
    }
    Ok((
        ak.to_string(),
        action,
        version,
        hdr(headers, "host").unwrap_or("").to_string(),
    ))
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn b64_utf8(raw: &str) -> Option<String> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

pub fn decode_cloud_init_write_files(user_data: &str) -> BTreeMap<String, String> {
    let (mut files, mut in_wf) = (BTreeMap::new(), false);
    let mut cur: (Option<String>, Option<String>, Option<String>) = (None, None, None);
    let flush = |out: &mut BTreeMap<String, String>,
                 c: &mut (Option<String>, Option<String>, Option<String>)| {
        if let (Some(path), Some(raw)) = (c.0.take(), c.2.take()) {
            let b64 = matches!(
                c.1.take().unwrap_or_default().to_ascii_lowercase().as_str(),
                "b64" | "base64"
            );
            out.insert(
                path,
                if b64 {
                    b64_utf8(&raw).unwrap_or(raw)
                } else {
                    raw
                },
            );
        } else {
            *c = (None, None, None);
        }
    };
    for line in user_data.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if !line.starts_with([' ', '\t', '-']) {
            if t == "write_files:" {
                in_wf = true;
            } else if in_wf {
                flush(&mut files, &mut cur);
                in_wf = false;
            }
            continue;
        }
        if !in_wf {
            continue;
        }
        let f = t
            .strip_prefix("- ")
            .map(|r| {
                flush(&mut files, &mut cur);
                r.trim()
            })
            .unwrap_or(t);
        match f.split_once(':') {
            Some(("path", v)) => cur.0 = Some(unquote(v)),
            Some(("encoding", v)) => cur.1 = Some(unquote(v)),
            Some(("content", v)) => cur.2 = Some(unquote(v)),
            _ => {}
        }
    }
    if in_wf {
        flush(&mut files, &mut cur);
    }
    files
}

pub fn decode_ps_puts(user_data: &str) -> BTreeMap<String, String> {
    let marker = "Put (Join-Path $sd '";
    user_data
        .lines()
        .filter_map(|line| {
            let (name, after) = line[line.find(marker)? + marker.len()..].split_once("')")?;
            Some((
                name.into(),
                b64_utf8(after.trim().strip_prefix('\'')?.strip_suffix('\'')?)?,
            ))
        })
        .collect()
}

pub fn extract_machine_id(user_data: &str) -> Option<String> {
    let (files, ps_files) = (
        decode_cloud_init_write_files(user_data),
        decode_ps_puts(user_data),
    );
    if let Some(mid) = files
        .get("/etc/cua/relay/machine-id")
        .or_else(|| ps_files.get("machine-id"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return Some(mid.into());
    }
    let mut expanded = String::from(user_data);
    for content in files.values().chain(ps_files.values()) {
        expanded.push('\n');
        expanded.push_str(content);
    }
    let markers = [
        ("--machine-id ", true, false),
        ("CUA_MACHINE_ID=", true, false),
        ("machine_id=", true, false),
        ("/m/", false, true),
    ];
    for trimmed in expanded.lines().map(str::trim) {
        for (marker, trim_lead, sep) in markers {
            if let Some(idx) = trimmed.find(marker) {
                let mut rest = &trimmed[idx + marker.len()..];
                if trim_lead {
                    rest = rest.trim_start_matches(['"', '\'', '=']);
                }
                let val = rest
                    .split(|c: char| {
                        c.is_whitespace()
                            || matches!(c, '"' | '\'' | ';')
                            || (sep && matches!(c, '/' | '`'))
                    })
                    .next()
                    .unwrap_or("");
                if !val.is_empty() {
                    return Some(val.into());
                }
            }
        }
    }
    None
}
