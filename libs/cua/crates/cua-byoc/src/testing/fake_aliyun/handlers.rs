// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Axum request handler and ECS/STS OpenAPI V3 action dispatcher for [`FakeAliyun`].

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};

use super::handlers_net::{
    handle_describe_available, handle_describe_images, handle_describe_instance_types, handle_sg,
    handle_vpc, handle_vswitch,
};
use super::sig::{
    action_permission_key, extract_machine_id, has_cua_managed_tag, paginate,
    parse_instance_ids_param, parse_query_params, parse_tags, verify_acs3_signature,
};
use super::state::{
    BootCallback, BootFailMode, FakeAliyun, FakeInstance, RecordedCall, RunHook, S, StateCallback,
};

pub(crate) type Params = BTreeMap<String, String>;

#[derive(Default)]
pub struct PostHooks {
    pub boot: Option<(FakeInstance, Params, BootCallback)>,
    pub run_instance: Option<(String, Params, RunHook)>,
    pub power: Vec<(FakeInstance, bool, StateCallback)>,
}

impl PostHooks {
    pub fn fire(self) {
        if let Some((inst, params, cb)) = self.boot {
            cb(&inst, &params);
        }
        if let Some((id, params, cb)) = self.run_instance {
            cb(&id, &params);
        }
        for (inst, online, cb) in self.power {
            cb(&inst, online);
        }
    }
}

pub(crate) fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    (
        status,
        axum::Json(json!({ "Code": code, "Message": msg, "RequestId": "fake-req-id" })),
    )
        .into_response()
}

pub(crate) fn ok(body: Value) -> Response {
    (StatusCode::OK, axum::Json(body)).into_response()
}

pub(crate) fn not_found(code: &str, msg: &str) -> Response {
    err(StatusCode::NOT_FOUND, code, msg)
}

pub(crate) fn bad_req(code: &str, msg: &str) -> Response {
    err(StatusCode::BAD_REQUEST, code, msg)
}

pub(crate) fn paged_ok(
    outer: &str,
    inner: &str,
    items: Vec<Value>,
    params: &Params,
    req_id: &str,
) -> Response {
    let (page, total, page_num, page_size) = paginate(items, params);
    ok(json!({
        outer: { inner: page }, "TotalCount": total,
        "PageNumber": page_num, "PageSize": page_size, "RequestId": req_id
    }))
}

pub(crate) fn p_str(p: &Params, k: &str) -> String {
    p.get(k).cloned().unwrap_or_default()
}

pub(crate) fn p_or(p: &Params, k: &str, def: &str) -> String {
    p.get(k).cloned().unwrap_or_else(|| def.into())
}

pub(crate) fn is_dry_run(p: &Params) -> bool {
    p.get("DryRun").map(String::as_str) == Some("true")
}

pub(crate) fn dry_run_ok() -> Response {
    err(
        StatusCode::PRECONDITION_FAILED,
        "DryRunOperation",
        "Request validation has been passed with DryRun flag set.",
    )
}

pub(crate) fn check_cua_tag(f: &FakeAliyun, tags: &Params, action: &str) -> Option<Response> {
    (f.enforce_cua_managed_tag_condition && !has_cua_managed_tag(tags)).then(|| {
        err(
            StatusCode::FORBIDDEN,
            "Forbidden.RAM",
            &format!("RAM policy Condition requires cua-managed=true on {action}"),
        )
    })
}

pub(crate) fn check_transient_dep(f: &mut FakeAliyun, msg: &str) -> Option<Response> {
    if f.transient_dependency_errors == 0 {
        return None;
    }
    f.transient_dependency_errors -= 1;
    let code = f
        .transient_dependency_code
        .as_deref()
        .unwrap_or("DependencyViolation");
    Some(bad_req(code, msg))
}

fn is_valid_windows_hostname(hn: &str) -> bool {
    (2..=15).contains(&hn.len())
        && !hn.contains('.')
        && !hn.starts_with('-')
        && !hn.ends_with('-')
        && hn.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !hn.chars().all(|c| c.is_ascii_digit())
}

pub async fn handle(
    State(s): State<S>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (resp, hooks) = {
        let mut f = s.lock().unwrap();
        dispatch_locked(&mut f, &method, &uri, &headers, &body)
    };
    hooks.fire();
    resp
}

pub fn dispatch_locked(
    f: &mut FakeAliyun,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> (Response, PostHooks) {
    let mut hooks = PostHooks::default();
    if f.throttle > 0 {
        f.throttle -= 1;
        return (
            err(
                StatusCode::TOO_MANY_REQUESTS,
                "Throttling.User",
                "Request throttled.",
            ),
            hooks,
        );
    }
    if let Some((code, msg)) = f.force_auth_error.clone() {
        return (err(StatusCode::UNAUTHORIZED, &code, &msg), hooks);
    }
    let (ak, action, version, host_hdr) =
        match verify_acs3_signature(method, uri, headers, body, &f.keys) {
            Ok(v) => v,
            Err((status, code, msg)) => return (err(status, code, &msg), hooks),
        };
    let mut params = parse_query_params(uri.query().unwrap_or(""));
    if *method == Method::POST
        && !body.is_empty()
        && headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"))
    {
        for (k, v) in url::form_urlencoded::parse(body) {
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
        return (
            err(
                StatusCode::FORBIDDEN,
                "Forbidden.RAM",
                &format!("Not authorized on {perm_key}"),
            ),
            hooks,
        );
    }

    let resp = match (version.as_str(), action.as_str()) {
        ("2015-04-01", "GetCallerIdentity") => ok(json!({
            "AccountId": "123456789012", "Arn": "acs:ram::123456789012:user/cua-byoc",
            "IdentityType": "RAMUser", "PrincipalId": "20000001",
            "RequestId": "req-sts-1", "UserId": "20000001"
        })),
        ("2014-05-26", "DescribeRegions") => {
            let regions: Vec<Value> = f
                .regions
                .iter()
                .map(|r| json!({ "RegionId": r, "LocalName": r }))
                .collect();
            ok(json!({ "Regions": { "Region": regions }, "RequestId": "req-regions-1" }))
        }
        ("2014-05-26", "DescribeZones") => {
            let zones: Vec<Value> = f
                .effective_zones(&p_or(&params, "RegionId", "cn-hangzhou"))
                .into_iter()
                .map(|z| json!({ "ZoneId": z, "LocalName": z, "Status": "Available" }))
                .collect();
            ok(json!({ "Zones": { "Zone": zones }, "RequestId": "req-zones-1" }))
        }
        ("2014-05-26", "DescribeAvailableResource") => handle_describe_available(f, &params),
        ("2014-05-26", "DescribeInstanceTypes") => handle_describe_instance_types(f, &params),
        ("2014-05-26", "DescribeImages") => handle_describe_images(f, &params),
        ("2014-05-26", "DescribeInstances") => handle_describe_instances(f, &params),
        (
            "2014-05-26",
            "CreateSecurityGroup"
            | "DescribeSecurityGroups"
            | "DescribeSecurityGroupAttribute"
            | "AuthorizeSecurityGroupEgress"
            | "AuthorizeSecurityGroup"
            | "DeleteSecurityGroup",
        ) => handle_sg(f, &action, &params),
        ("2016-04-28", "CreateVpc" | "DescribeVpcs" | "DeleteVpc") => {
            handle_vpc(f, &action, &params)
        }
        ("2016-04-28", "CreateVSwitch" | "DescribeVSwitches" | "DeleteVSwitch") => {
            handle_vswitch(f, &action, &params)
        }
        ("2014-05-26", "RunInstances") => handle_run_instances(f, &params, &mut hooks),
        (
            "2014-05-26",
            "StopInstance"
            | "StopInstances"
            | "StartInstance"
            | "StartInstances"
            | "ModifyInstanceAutoReleaseTime"
            | "TagResources"
            | "DeleteInstance"
            | "DeleteInstances"
            | "GetInstanceConsoleOutput",
        ) => handle_instance_ops(f, &action, &params, &mut hooks),
        _ => bad_req(
            "InvalidAction.NotFound",
            &format!("Unsupported action {version}:{action}"),
        ),
    };
    (resp, hooks)
}

fn handle_describe_instances(f: &mut FakeAliyun, params: &Params) -> Response {
    if let Some(response) = &f.describe_instances_response {
        return ok(response.clone());
    }
    let tag_filters = parse_tags(params);
    let id_filter: Option<Vec<String>> = params
        .get("InstanceIds")
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok());
    let region = params.get("RegionId").cloned();
    let items: Vec<Value> = f
        .instances
        .values_mut()
        .filter(|inst| {
            (inst.region_id.is_empty() || region.as_ref().is_none_or(|r| &inst.region_id == r))
                && id_filter
                    .as_ref()
                    .is_none_or(|ids| ids.iter().any(|id| id == &inst.instance_id))
                && tag_filters.iter().all(|(k, v)| inst.tags.get(k) == Some(v))
        })
        .map(|inst| {
            if inst.status == "Pending" && inst.pending_describe_ticks > 0 {
                inst.pending_describe_ticks -= 1;
                if inst.pending_describe_ticks == 0 {
                    inst.status = "Running".into();
                }
            }
            inst.to_api_json()
        })
        .collect();
    paged_ok("Instances", "Instance", items, params, "req-instances-1")
}

fn handle_run_instances(f: &mut FakeAliyun, params: &Params, hooks: &mut PostHooks) -> Response {
    if is_dry_run(params) {
        if let Some((st, ref code, ref msg)) = f.run_instances_dry_run_error {
            return err(
                StatusCode::from_u16(st).unwrap_or(StatusCode::BAD_REQUEST),
                code,
                msg,
            );
        }
        if f.run_instances_missing_vswitch && !params.contains_key("VSwitchId") {
            return bad_req(
                "InvalidVSwitchId.NotFound",
                "The specified VSwitchId does not exist.",
            );
        }
        return dry_run_ok();
    }
    if f.fail_run_instances {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Injected RunInstances failure",
        );
    }
    if let Some((st, ref code, ref msg)) = f.run_instances_error {
        return err(
            StatusCode::from_u16(st).unwrap_or(StatusCode::BAD_REQUEST),
            code,
            msg,
        );
    }
    let tags = parse_tags(params);
    if let Some(r) = check_cua_tag(f, &tags, "ecs:RunInstances") {
        return r;
    }
    if let Some(id) = params
        .get("ClientToken")
        .and_then(|ct| f.client_tokens.get(ct))
    {
        return ok(
            json!({ "InstanceIdSets": { "InstanceIdSet": [id] }, "RequestId": "req-run-idempotent" }),
        );
    }

    let region = p_or(params, "RegionId", "cn-hangzhou");
    let vsw_id = p_str(params, "VSwitchId");
    let zone_id = params
        .get("ZoneId")
        .cloned()
        .or_else(|| f.vswitches.get(&vsw_id).map(|v| v.zone_id.clone()))
        .unwrap_or_else(|| format!("{region}-h"));

    if let Some(fault) = f.zone_faults.get(&zone_id) {
        return err(
            StatusCode::FORBIDDEN,
            fault.code(),
            "No capacity available in requested zone.",
        );
    }

    let img_id = p_str(params, "ImageId");
    let is_win = f
        .images
        .iter()
        .any(|i| i.image_id == img_id && i.os_type.eq_ignore_ascii_case("windows"));
    if is_win
        && let Some(hn) = params.get("HostName")
        && !is_valid_windows_hostname(hn)
    {
        return bad_req(
            "InvalidHostName.Malformed",
            "The specified parameter \"HostName\" is not valid.",
        );
    }
    if let Some(rel) = params.get("AutoReleaseTime")
        && let Some(r) = validate_auto_release_time(rel)
    {
        return r;
    }

    let vpc_id = f
        .vswitches
        .get(&vsw_id)
        .map(|v| v.vpc_id.clone())
        .unwrap_or_default();
    let user_data_raw = p_str(params, "UserData");
    let user_data_decoded = base64::engine::general_purpose::STANDARD
        .decode(&user_data_raw)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let machine_id =
        extract_machine_id(&user_data_decoded).or_else(|| tags.get("cua-machine").cloned());
    let id = format!("i-fake-{}", f.next_seq());
    let status = if f.boot_fail == Some(BootFailMode::StopImmediately) {
        "Stopped"
    } else {
        "Running"
    };
    let inst = FakeInstance {
        instance_id: id.clone(),
        instance_name: p_str(params, "InstanceName"),
        host_name: p_str(params, "HostName"),
        region_id: region,
        zone_id,
        vpc_id,
        vswitch_id: vsw_id,
        security_group_id: p_str(params, "SecurityGroupId"),
        extra_security_group_ids: Vec::new(),
        instance_type: p_str(params, "InstanceType"),
        image_id: img_id,
        status: status.into(),
        pending_describe_ticks: 0,
        instance_charge_type: p_str(params, "InstanceChargeType"),
        stopped_mode: p_str(params, "StoppedMode"),
        auto_release_time: params.get("AutoReleaseTime").cloned(),
        http_endpoint: p_str(params, "HttpEndpoint"),
        http_tokens: params.get("HttpTokens").cloned(),
        key_pair_name: params.get("KeyPairName").cloned(),
        ram_role_name: params.get("RamRoleName").cloned(),
        internet_charge_type: p_str(params, "InternetChargeType"),
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
        hooks.boot = Some((inst, params.clone(), cb));
    }
    if let Some(cb) = f.on_run_instance.clone() {
        hooks.run_instance = Some((id.clone(), params.clone(), cb));
    }
    ok(json!({ "InstanceIdSets": { "InstanceIdSet": [id] }, "RequestId": "req-run-1" }))
}

fn validate_auto_release_time(rel: &str) -> Option<Response> {
    if rel.is_empty() {
        return None;
    }
    let Ok(ts) = humantime::parse_rfc3339(rel) else {
        return Some(bad_req(
            "InvalidAutoReleaseTime.Malformed",
            "AutoReleaseTime must be UTC ISO 8601 (YYYY-MM-DDTHH:MM:SSZ).",
        ));
    };
    if !rel.ends_with(":00Z") {
        return Some(bad_req(
            "InvalidAutoReleaseTime.Malformed",
            "AutoReleaseTime must use :00Z UTC suffix.",
        ));
    }
    if let Ok(d) = ts.duration_since(std::time::UNIX_EPOCH)
        && d.as_secs() < crate::model::now() + 1800
    {
        return Some(bad_req(
            "InvalidAutoReleaseTime.LessThanMin",
            "AutoReleaseTime must be at least 30 minutes from now.",
        ));
    }
    None
}

fn validate_instances(f: &FakeAliyun, ids: &[String], perm: &str) -> Option<Response> {
    for id in ids {
        let Some(inst) = f.instances.get(id) else {
            return Some(not_found(
                "InvalidInstanceId.NotFound",
                "Instance not found.",
            ));
        };
        if let Some(r) = check_cua_tag(f, &inst.tags, perm) {
            return Some(r);
        }
    }
    None
}

fn set_instances_power(
    f: &mut FakeAliyun,
    params: &Params,
    perm: &str,
    new_status: &str,
    online: bool,
    req_id: &str,
    hooks: &mut PostHooks,
) -> Response {
    let ids = parse_instance_ids_param(params);
    if let Some(r) = validate_instances(f, &ids, perm) {
        return r;
    }
    let power_cb = f.on_power.clone();
    if !online
        && ids
            .iter()
            .any(|id| f.instances.get(id).is_some_and(|i| i.status == "Pending"))
    {
        return bad_req(
            "IncorrectInstanceStatus",
            "The current status of the resource does not support this operation.",
        );
    }
    for id in &ids {
        if let Some(inst) = f.instances.get_mut(id) {
            inst.status = new_status.into();
            if !online && let Some(mode) = params.get("StoppedMode") {
                inst.stopped_mode = mode.clone();
            }
            if let Some(ref cb) = power_cb {
                hooks.power.push((inst.clone(), online, cb.clone()));
            }
        }
    }
    ok(json!({ "RequestId": req_id }))
}

fn handle_instance_ops(
    f: &mut FakeAliyun,
    action: &str,
    params: &Params,
    hooks: &mut PostHooks,
) -> Response {
    match action {
        "StopInstance" | "StopInstances" => set_instances_power(
            f,
            params,
            "ecs:StopInstance",
            "Stopped",
            false,
            "req-stop-1",
            hooks,
        ),
        "StartInstance" | "StartInstances" => set_instances_power(
            f,
            params,
            "ecs:StartInstance",
            "Running",
            true,
            "req-start-1",
            hooks,
        ),
        "ModifyInstanceAutoReleaseTime" => {
            let id = p_str(params, "InstanceId");
            if let Some(r) = validate_instances(
                f,
                std::slice::from_ref(&id),
                "ecs:ModifyInstanceAutoReleaseTime",
            ) {
                return r;
            }
            let rel = p_str(params, "AutoReleaseTime");
            if let Some(r) = validate_auto_release_time(&rel) {
                return r;
            }
            if let Some(inst) = f.instances.get_mut(&id) {
                inst.auto_release_time = (!rel.is_empty()).then_some(rel);
            }
            ok(json!({ "RequestId": "req-rel-1" }))
        }
        "TagResources" => {
            let req_tags = parse_tags(params);
            if let Some(r) = check_cua_tag(f, &req_tags, "ecs:TagResources") {
                return r;
            }
            let ids: Vec<String> = (1..=32)
                .filter_map(|i| params.get(&format!("ResourceId.{i}")).cloned())
                .collect();
            if p_or(params, "ResourceType", "instance") == "instance" {
                if let Some(r) = validate_instances(f, &ids, "ecs:TagResources") {
                    return r;
                }
                for id in &ids {
                    if let Some(inst) = f.instances.get_mut(id) {
                        inst.tags.extend(req_tags.clone());
                    }
                }
            }
            ok(json!({ "RequestId": "req-tag-1" }))
        }
        "DeleteInstance" | "DeleteInstances" => {
            if f.fail_delete {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "Injected DeleteInstance failure",
                );
            }
            let ids = parse_instance_ids_param(params);
            if let Some(r) = validate_instances(f, &ids, "ecs:DeleteInstance") {
                return r;
            }
            let power_cb = f.on_power.clone();
            if !f.delete_instance_without_removal {
                for id in &ids {
                    if let Some(inst) = f.instances.remove(id)
                        && let Some(cb) = &power_cb
                    {
                        hooks.power.push((inst, false, cb.clone()));
                    }
                }
            }
            ok(json!({ "RequestId": "req-del-1" }))
        }
        "GetInstanceConsoleOutput" => {
            if f.console_error {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "Console output unavailable",
                );
            }
            let id = p_str(params, "InstanceId");
            if f.require_instance_for_console && !f.instances.contains_key(&id) {
                return not_found("InvalidInstanceId.NotFound", "Instance not found.");
            }
            let raw = f
                .console_outputs
                .get(&id)
                .cloned()
                .or_else(|| f.console_output.clone())
                .unwrap_or_else(|| {
                    if f.require_instance_for_console {
                        String::new()
                    } else {
                        "cloud-init: boot log line\n".into()
                    }
                });
            let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            ok(json!({ "InstanceId": id, "ConsoleOutput": encoded, "RequestId": "req-console-1" }))
        }
        _ => unreachable!(),
    }
}
