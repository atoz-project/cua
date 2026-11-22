// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Network part inspection, listing, ownership guards, fast active-blocker
//! detection, deletion retries, and rollback for `aliyun-ecs`.

use std::collections::BTreeMap;

use cua_sandbox_core::Error;
use serde_json::Value;

use super::AliyunEcs;
use super::client::{
    ApiBody, ECS_API_VERSION, VPC_API_VERSION, api_error_code_message, map_api_error,
};
use super::existing_vpc;
use super::net::{net_resource, owner_tag_filters, tags_of, vpc_name, vswitch_name};
use crate::api::Result;
use crate::model::{self, Connection, Resource, tag};

fn is_not_found_code(code: &str) -> bool {
    matches!(
        code,
        "InvalidVpcId.NotFound"
            | "InvalidVSwitchId.NotFound"
            | "InvalidSecurityGroupId.NotFound"
            | "InvalidSecurityGroup.NotFound"
    )
}

fn is_retryable_delete_code(code: &str) -> bool {
    code == "DependencyViolation"
        || code.starts_with("DependencyViolation.")
        || matches!(
            code,
            "InUse"
                | "VpcInUse"
                | "IncorrectVpcStatus"
                | "IncorrectVSwitchStatus"
                | "ResourceInUse"
                | "InvalidOperation.Conflict"
        )
}

fn is_cua_vswitch_name(vsw: &Value, owner: &str) -> bool {
    let name = vsw["VSwitchName"].as_str().unwrap_or("");
    let zone = vsw["ZoneId"].as_str().unwrap_or("");
    if !zone.is_empty() {
        name == vswitch_name(owner, zone)
    } else {
        name.starts_with(&format!("{}-", vpc_name(owner)))
    }
}

/// Returns Cua ownership tags for a VPC only when it is safe for Cua to manage.
/// Default VPCs and the configured `conn.vpc_id` are never Cua-owned; in
/// existing-VPC mode, only prior Cua-created isolated VPCs (`cua-sb-<owner>`)
/// distinct from `conn.vpc_id` keep their tags.
fn vpc_owned_tags(conn: &Connection, vpc: &Value) -> BTreeMap<String, String> {
    let id = vpc["VpcId"].as_str().map(str::trim).unwrap_or("");
    if vpc["IsDefault"].as_bool().unwrap_or(false)
        || (!id.is_empty() && conn.vpc_id.as_deref() == Some(id))
    {
        return BTreeMap::new();
    }
    let tags = tags_of(vpc);
    if existing_vpc::is_existing_vpc_connection(conn) {
        let Some(owner) = tags
            .get(tag::OWNER)
            .map(String::as_str)
            .filter(|o| !o.is_empty())
        else {
            return BTreeMap::new();
        };
        if tags.get(tag::MANAGED).map(String::as_str) != Some("true")
            || vpc["VpcName"].as_str() != Some(vpc_name(owner).as_str())
        {
            return BTreeMap::new();
        }
    }
    tags
}

/// Returns Cua ownership tags for a VSwitch only when it is safe for Cua to
/// manage. Default VSwitches, `conn.vswitch_id`, and any VSwitch inside
/// `conn.vpc_id` are never Cua-owned; in existing-VPC mode, only prior
/// Cua-created isolated VSwitches (`cua-sb-<owner>-<zone>`) keep their tags.
fn vswitch_owned_tags(conn: &Connection, vsw: &Value) -> BTreeMap<String, String> {
    let id = vsw["VSwitchId"].as_str().map(str::trim).unwrap_or("");
    if vsw["IsDefault"].as_bool().unwrap_or(false)
        || (!id.is_empty() && conn.vswitch_id.as_deref() == Some(id))
        || (conn.vpc_id.is_some() && vsw["VpcId"].as_str() == conn.vpc_id.as_deref())
    {
        return BTreeMap::new();
    }
    let tags = tags_of(vsw);
    if existing_vpc::is_existing_vpc_connection(conn) {
        let Some(owner) = tags
            .get(tag::OWNER)
            .map(String::as_str)
            .filter(|o| !o.is_empty())
        else {
            return BTreeMap::new();
        };
        if tags.get(tag::MANAGED).map(String::as_str) != Some("true")
            || !is_cua_vswitch_name(vsw, owner)
        {
            return BTreeMap::new();
        }
    }
    tags
}

/// Describes one network part (`vpc`, `vswitch`/`subnet`, `security_group`).
pub async fn describe_part(
    api: &AliyunEcs,
    conn: &Connection,
    r: &Resource,
) -> Result<Option<(String, BTreeMap<String, String>)>> {
    if r.id.is_empty() {
        return Ok(None);
    }
    let region = if r.region.is_empty() {
        conn.region.as_str()
    } else {
        r.region.as_str()
    };
    let profile_hint = api.profile_hint(conn);
    match r.resource_type.as_str() {
        "vpc" => {
            let v = api
                .call_ok(
                    &api.vpc_endpoint(region),
                    "GET",
                    "DescribeVpcs",
                    VPC_API_VERSION,
                    &[
                        ("RegionId".into(), region.to_string()),
                        ("VpcId".into(), r.id.clone()),
                    ],
                    profile_hint,
                )
                .await?;
            let Some(vpc) = v["Vpcs"]["Vpc"].as_array().and_then(|a| a.first()) else {
                return Ok(None);
            };
            let tags = vpc_owned_tags(conn, vpc);
            let state = vpc["Status"]
                .as_str()
                .unwrap_or("available")
                .to_ascii_lowercase();
            Ok(Some((state, tags)))
        }
        "vswitch" | "subnet" => {
            let v = api
                .call_ok(
                    &api.vpc_endpoint(region),
                    "GET",
                    "DescribeVSwitches",
                    VPC_API_VERSION,
                    &[
                        ("RegionId".into(), region.to_string()),
                        ("VSwitchId".into(), r.id.clone()),
                    ],
                    profile_hint,
                )
                .await?;
            let Some(vsw) = v["VSwitches"]["VSwitch"].as_array().and_then(|a| a.first()) else {
                return Ok(None);
            };
            let tags = vswitch_owned_tags(conn, vsw);
            let state = vsw["Status"]
                .as_str()
                .unwrap_or("available")
                .to_ascii_lowercase();
            Ok(Some((state, tags)))
        }
        "security_group" => {
            let v = api
                .call_ok(
                    &api.ecs_endpoint(region),
                    "GET",
                    "DescribeSecurityGroups",
                    ECS_API_VERSION,
                    &[
                        ("RegionId".into(), region.to_string()),
                        ("SecurityGroupId".into(), r.id.clone()),
                    ],
                    profile_hint,
                )
                .await?;
            let Some(sg) = v["SecurityGroups"]["SecurityGroup"]
                .as_array()
                .and_then(|a| a.first())
            else {
                return Ok(None);
            };
            Ok(Some(("available".into(), tags_of(sg))))
        }
        _ => Ok(None),
    }
}

/// Lists all Cua-owned network parts (`security_group`, `vswitch`, `vpc`) in
/// `conn.region`, verifying [`model::is_ours`] on every returned row.
pub async fn list_parts(api: &AliyunEcs, conn: &Connection, owner: &str) -> Result<Vec<Resource>> {
    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(&conn.region);
    let vpc_ep = api.vpc_endpoint(&conn.region);
    let mut base = vec![("RegionId".into(), conn.region.clone())];
    base.extend(owner_tag_filters(owner));

    let mut out = Vec::new();

    for sg in api
        .paginated_page_number(
            &ecs_ep,
            "DescribeSecurityGroups",
            ECS_API_VERSION,
            &base,
            ("SecurityGroups", "SecurityGroup"),
            profile_hint,
        )
        .await?
    {
        let tags = tags_of(&sg);
        if !model::is_ours(&tags, owner) {
            continue;
        }
        let Some(id) = sg["SecurityGroupId"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let name = sg["SecurityGroupName"].as_str().unwrap_or_default();
        let vpc = sg["VpcId"].as_str().unwrap_or_default();
        let mut r = net_resource(&conn.region, "", "security_group", id, name, &tags, &[]);
        if !vpc.is_empty() {
            r.extra.insert("vpc".into(), vpc.into());
        }
        out.push(r);
    }

    for vsw in api
        .paginated_page_number(
            &vpc_ep,
            "DescribeVSwitches",
            VPC_API_VERSION,
            &base,
            ("VSwitches", "VSwitch"),
            profile_hint,
        )
        .await?
    {
        let tags = vswitch_owned_tags(conn, &vsw);
        if !model::is_ours(&tags, owner) {
            continue;
        }
        let Some(id) = vsw["VSwitchId"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let name = vsw["VSwitchName"].as_str().unwrap_or_default();
        let zone = vsw["ZoneId"].as_str().unwrap_or_default();
        let vpc = vsw["VpcId"].as_str().unwrap_or_default();
        let mut r = net_resource(&conn.region, zone, "vswitch", id, name, &tags, &[]);
        if !vpc.is_empty() {
            r.extra.insert("vpc".into(), vpc.into());
        }
        out.push(r);
    }

    for vpc in api
        .paginated_page_number(
            &vpc_ep,
            "DescribeVpcs",
            VPC_API_VERSION,
            &base,
            ("Vpcs", "Vpc"),
            profile_hint,
        )
        .await?
    {
        let tags = vpc_owned_tags(conn, &vpc);
        if !model::is_ours(&tags, owner) {
            continue;
        }
        let Some(id) = vpc["VpcId"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let name = vpc["VpcName"].as_str().unwrap_or_default();
        out.push(net_resource(&conn.region, "", "vpc", id, name, &tags, &[]));
    }

    Ok(out)
}

/// Returns `true` if ANY active (non-terminated/deleted) instance — including
/// Cua-owned peer instances — or remaining child VPC resource references `r`,
/// so concurrent NoStock fallback/rollback fails fast instead of waiting out
/// the full ENI-release retry budget.
async fn has_active_blocker(
    api: &AliyunEcs,
    region: &str,
    r: &Resource,
    profile_hint: Option<&str>,
) -> bool {
    let mut params = vec![("RegionId".into(), region.to_string())];
    match r.resource_type.as_str() {
        "security_group" => params.push(("SecurityGroupId".into(), r.id.clone())),
        "vswitch" | "subnet" => params.push(("VSwitchId".into(), r.id.clone())),
        "vpc" => params.push(("VpcId".into(), r.id.clone())),
        _ => return false,
    }
    if let Ok(instances) = api
        .paginated_page_number(
            &api.ecs_endpoint(region),
            "DescribeInstances",
            ECS_API_VERSION,
            &params,
            ("Instances", "Instance"),
            profile_hint,
        )
        .await
    {
        for inst in instances {
            let st = inst["Status"].as_str().unwrap_or("");
            if st.eq_ignore_ascii_case("terminated") || st.eq_ignore_ascii_case("deleted") {
                continue;
            }
            let refs_part = match r.resource_type.as_str() {
                "security_group" => inst["SecurityGroupIds"]["SecurityGroupId"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|x| x.as_str() == Some(r.id.as_str()))),
                "vswitch" | "subnet" => {
                    inst["VpcAttributes"]["VSwitchId"].as_str() == Some(r.id.as_str())
                }
                "vpc" => inst["VpcAttributes"]["VpcId"].as_str() == Some(r.id.as_str()),
                _ => false,
            };
            if refs_part {
                return true;
            }
        }
    }
    if r.resource_type == "vpc" {
        let vpc_params = vec![
            ("RegionId".into(), region.to_string()),
            ("VpcId".into(), r.id.clone()),
        ];
        if let Ok(vswitches) = api
            .paginated_page_number(
                &api.vpc_endpoint(region),
                "DescribeVSwitches",
                VPC_API_VERSION,
                &vpc_params,
                ("VSwitches", "VSwitch"),
                profile_hint,
            )
            .await
            && vswitches
                .iter()
                .any(|vsw| vsw["VpcId"].as_str() == Some(r.id.as_str()))
        {
            return true;
        }
        if let Ok(sgs) = api
            .paginated_page_number(
                &api.ecs_endpoint(region),
                "DescribeSecurityGroups",
                ECS_API_VERSION,
                &vpc_params,
                ("SecurityGroups", "SecurityGroup"),
                profile_hint,
            )
            .await
            && sgs
                .iter()
                .any(|sg| sg["VpcId"].as_str() == Some(r.id.as_str()))
        {
            return true;
        }
    }
    false
}

/// Deletes one network part (`security_group`, `vswitch`/`subnet`, `vpc`),
/// retrying transient dependency violations (e.g. ENI release after
/// `DeleteInstance`) while short-circuiting immediately when an active blocker
/// still references the resource, and treating `NotFound` as `Ok(())`.
pub async fn delete_part(api: &AliyunEcs, conn: &Connection, r: &Resource) -> Result<()> {
    existing_vpc::guard_user_network_untouched(conn, r)?;
    if r.id.is_empty() {
        return Ok(());
    }
    if matches!(
        r.resource_type.as_str(),
        "vpc" | "vswitch" | "subnet" | "security_group"
    ) {
        let Some((_, tags)) = describe_part(api, conn, r).await? else {
            return Ok(());
        };
        let is_cua_tagged = tags.get(tag::MANAGED).map(String::as_str) == Some("true")
            && tags.get(tag::OWNER).is_some_and(|o| !o.is_empty());
        if !is_cua_tagged {
            return Err(Error::Cloud(format!(
                "aliyun-ecs: refusing to delete non-Cua-owned {} {}",
                r.resource_type, r.id
            )));
        }
    }
    let region = if r.region.is_empty() {
        conn.region.as_str()
    } else {
        r.region.as_str()
    };
    let profile_hint = api.profile_hint(conn);
    let (endpoint, action, version, id_param) = match r.resource_type.as_str() {
        "security_group" => (
            api.ecs_endpoint(region),
            "DeleteSecurityGroup",
            ECS_API_VERSION,
            "SecurityGroupId",
        ),
        "vswitch" | "subnet" => (
            api.vpc_endpoint(region),
            "DeleteVSwitch",
            VPC_API_VERSION,
            "VSwitchId",
        ),
        "vpc" => (
            api.vpc_endpoint(region),
            "DeleteVpc",
            VPC_API_VERSION,
            "VpcId",
        ),
        other => {
            return Err(Error::InvalidArgument(format!(
                "aliyun-ecs: {other} is not a network resource"
            )));
        }
    };

    let params = vec![
        ("RegionId".into(), region.to_string()),
        (id_param.into(), r.id.clone()),
    ];
    let mut tries = 0u32;
    loop {
        let (status, body) = api
            .call_raw(&endpoint, "POST", action, version, &params, profile_hint)
            .await?;
        if status.is_success() {
            return Ok(());
        }
        let code = match &body {
            ApiBody::Json(v) => api_error_code_message(v).0,
            ApiBody::Text(_) => "",
        };
        if is_not_found_code(code) {
            return Ok(());
        }
        // Alibaba Cloud keeps primary ENIs in `Status: Deleting` for up to ~4 minutes
        // after `DeleteInstance(Force=true)` before `DeleteVSwitch` succeeds (~376s budget
        // at the default 2s poll interval; unit tests override `poll_interval()` to 10ms).
        if is_retryable_delete_code(code) && tries < 100 {
            if tries == 0 && has_active_blocker(api, region, r, profile_hint).await {
                return Err(map_api_error(action, version, status, &body));
            }
            let poll = api.poll_interval();
            let wait = if tries < 12 {
                poll
            } else {
                poll.saturating_mul(2)
            };
            tries += 1;
            tokio::time::sleep(wait).await;
            continue;
        }
        return Err(map_api_error(action, version, status, &body));
    }
}

/// Best-effort rollback of only the network parts newly created during a
/// failed `provision()` (in reverse dependency order: VSwitch -> SG -> VPC).
pub async fn rollback_made(api: &AliyunEcs, conn: &Connection, made: &[Resource]) {
    let mut ordered: Vec<&Resource> = made.iter().collect();
    ordered.sort_by_key(|r| match r.resource_type.as_str() {
        "vswitch" | "subnet" => 0,
        "security_group" => 1,
        "vpc" => 2,
        _ => 3,
    });
    for r in ordered {
        let _ = delete_part(api, conn, r).await;
    }
}
