// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Isolated VPC and per-zone `/20` VSwitch provisioning, CIDR allocation,
//! ownership tagging, inspection, and listing for `aliyun-ecs`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use cua_sandbox_core::Error;
use serde_json::Value;

use super::AliyunEcs;
use super::client::{ECS_API_VERSION, VPC_API_VERSION};
use super::existing_vpc;
use super::net::{
    NetLocks, delete_part_owned, net_resource, owner_tag_filters, part_tags, tag_params, tags_of,
};
use crate::api::Result;
use crate::model::{self, Connection, Resource, tag};

/// The VPC's IPv4 CIDR block.
pub const VPC_CIDR: &str = "10.77.0.0/16";

/// Maximum `/20` VSwitches that fit inside a `/16` (`10.77.0.0/16`).
pub const MAX_ZONES: usize = 16;

/// Name of `owner`'s isolated VPC (`cua-sb-<owner>`).
pub fn vpc_name(owner: &str) -> String {
    format!("cua-sb-{}", model::label_value(owner))
}

/// Name of `owner`'s per-zone VSwitch (`cua-sb-<owner>-<zone>`).
pub fn vswitch_name(owner: &str, zone_id: &str) -> String {
    format!("cua-sb-{}-{zone_id}", model::label_value(owner))
}

/// The `/20` VSwitch CIDR at `index` inside `10.77.0.0/16` (`0..16`).
pub fn vswitch_cidr(index: usize) -> Option<String> {
    (index < MAX_ZONES).then(|| format!("10.77.{}.0/20", index * 16))
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

/// Returns whether two IPv4 CIDR blocks overlap.
pub(crate) fn cidrs_overlap(a: &str, b: &str) -> bool {
    match (parse_cidr(a), parse_cidr(b)) {
        (Some((a0, a1)), Some((b0, b1))) => a0 <= b1 && b0 <= a1,
        _ => a.trim() == b.trim(),
    }
}

fn next_free_vswitch_cidr(used_cidrs: &[String]) -> Option<String> {
    (0..MAX_ZONES)
        .filter_map(vswitch_cidr)
        .find(|cand| !used_cidrs.iter().any(|u| cidrs_overlap(cand, u)))
}

#[derive(Clone, Copy)]
struct VpcResourceSpec {
    action: &'static str,
    id_param: &'static str,
    outer_key: &'static str,
    inner_key: &'static str,
    label: &'static str,
}

const VPC_SPEC: VpcResourceSpec = VpcResourceSpec {
    action: "DescribeVpcs",
    id_param: "VpcId",
    outer_key: "Vpcs",
    inner_key: "Vpc",
    label: "VPC",
};

const VSWITCH_SPEC: VpcResourceSpec = VpcResourceSpec {
    action: "DescribeVSwitches",
    id_param: "VSwitchId",
    outer_key: "VSwitches",
    inner_key: "VSwitch",
    label: "VSwitch",
};

async fn wait_vpc_resource_available(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    spec: VpcResourceSpec,
    id: &str,
) -> Result<()> {
    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);
    for _ in 0..60 {
        let v = api
            .call_ok(
                &vpc_ep,
                "GET",
                spec.action,
                VPC_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    (spec.id_param.into(), id.to_string()),
                ],
                profile_hint,
            )
            .await?;
        if let Some(obj) = v[spec.outer_key][spec.inner_key]
            .as_array()
            .and_then(|a| a.first())
        {
            let status = obj["Status"].as_str().unwrap_or("Available");
            if status.eq_ignore_ascii_case("Available") {
                return Ok(());
            }
        }
        tokio::time::sleep(api.poll_interval()).await;
    }
    Err(Error::Timeout(format!(
        "aliyun-ecs: {} {id} did not become Available in {region}",
        spec.label
    )))
}

async fn find_vpc(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
) -> Result<Option<String>> {
    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);
    let mut base = vec![("RegionId".into(), region.to_string())];
    base.extend(owner_tag_filters(owner));
    let items = api
        .paginated_page_number(
            &vpc_ep,
            "DescribeVpcs",
            VPC_API_VERSION,
            &base,
            ("Vpcs", "Vpc"),
            profile_hint,
        )
        .await?;
    let expected_name = vpc_name(owner);
    Ok(items
        .into_iter()
        .filter(|v| {
            !v["IsDefault"].as_bool().unwrap_or(false)
                && model::is_ours(&tags_of(v), owner)
                && v["VpcName"]
                    .as_str()
                    .is_none_or(|n| n.is_empty() || n == expected_name)
        })
        .filter_map(|v| v["VpcId"].as_str().map(str::to_string))
        .filter(|id| !id.is_empty())
        .min())
}

pub(crate) async fn ensure_vpc(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
) -> Result<(String, Option<Resource>)> {
    if let Some(id) = find_vpc(api, conn, region, owner).await? {
        wait_vpc_resource_available(api, conn, region, VPC_SPEC, &id).await?;
        return Ok((id, None));
    }

    let name = vpc_name(owner);
    let tags = part_tags(owner);
    let token = format!("cua-vpc-{:016x}", rand::random::<u64>());
    let mut params = vec![
        ("RegionId".into(), region.to_string()),
        ("CidrBlock".into(), VPC_CIDR.to_string()),
        ("VpcName".into(), name.clone()),
        ("ClientToken".into(), token),
    ];
    params.extend(tag_params(&tags));

    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);
    let created = api
        .call_ok(
            &vpc_ep,
            "POST",
            "CreateVpc",
            VPC_API_VERSION,
            &params,
            profile_hint,
        )
        .await?;
    let id = created["VpcId"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Cloud("aliyun-ecs: CreateVpc returned no VpcId".into()))?
        .to_string();

    if let Err(e) = wait_vpc_resource_available(api, conn, region, VPC_SPEC, &id).await {
        let _ = delete_part_owned(
            api,
            conn,
            &net_resource(region, "", "vpc", &id, &name, &tags, &[]),
            Some(owner),
        )
        .await;
        return Err(e);
    }

    // Alibaba Cloud CreateVpc does not enforce a unique VpcName across concurrent callers.
    if let Some(winner) = find_vpc(api, conn, region, owner).await?
        && winner != id
    {
        let _ = delete_part_owned(
            api,
            conn,
            &net_resource(region, "", "vpc", &id, &name, &tags, &[]),
            Some(owner),
        )
        .await;
        wait_vpc_resource_available(api, conn, region, VPC_SPEC, &winner).await?;
        return Ok((winner, None));
    }

    Ok((
        id.clone(),
        Some(net_resource(
            region,
            "",
            "vpc",
            &id,
            &name,
            &tags,
            &[("cidr", VPC_CIDR)],
        )),
    ))
}

/// Finds or creates Cua's `/20` VSwitch in `zone_id` inside `vpc_id`, skipping
/// any CIDR blocks already occupied in `vpc_id`.
pub async fn ensure_vswitch_for_zone(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
    vpc_id: &str,
    zone_id: &str,
    locks: &NetLocks,
) -> Result<(String, Option<Resource>)> {
    let _guard = locks.net_lock.lock().await;
    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);

    let existing = api
        .paginated_page_number(
            &vpc_ep,
            "DescribeVSwitches",
            VPC_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("VpcId".into(), vpc_id.to_string()),
            ],
            ("VSwitches", "VSwitch"),
            profile_hint,
        )
        .await?;

    if let Some(vsw) = existing.iter().find(|v| {
        !v["IsDefault"].as_bool().unwrap_or(false)
            && v["ZoneId"].as_str() == Some(zone_id)
            && model::is_ours(&tags_of(v), owner)
    }) && let Some(id) = vsw["VSwitchId"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        wait_vpc_resource_available(api, conn, region, VSWITCH_SPEC, id).await?;
        return Ok((id.to_string(), None));
    }

    let used_cidrs: Vec<String> = existing
        .iter()
        .filter_map(|v| v["CidrBlock"].as_str().map(str::to_string))
        .collect();
    let cidr = next_free_vswitch_cidr(&used_cidrs).ok_or_else(|| {
        Error::Cloud(format!(
            "aliyun-ecs: no free /20 VSwitch CIDR left in VPC {vpc_id} for zone {zone_id}"
        ))
    })?;

    let name = vswitch_name(owner, zone_id);
    let tags = part_tags(owner);
    let token = format!("cua-vsw-{:016x}", rand::random::<u64>());
    let mut params = vec![
        ("RegionId".into(), region.to_string()),
        ("VpcId".into(), vpc_id.to_string()),
        ("ZoneId".into(), zone_id.to_string()),
        ("CidrBlock".into(), cidr.clone()),
        ("VSwitchName".into(), name.clone()),
        ("ClientToken".into(), token),
    ];
    params.extend(tag_params(&tags));

    let created = api
        .call_ok(
            &vpc_ep,
            "POST",
            "CreateVSwitch",
            VPC_API_VERSION,
            &params,
            profile_hint,
        )
        .await?;
    let id = created["VSwitchId"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Cloud("aliyun-ecs: CreateVSwitch returned no VSwitchId".into()))?
        .to_string();

    if let Err(e) = wait_vpc_resource_available(api, conn, region, VSWITCH_SPEC, &id).await {
        let _ = delete_part_owned(
            api,
            conn,
            &net_resource(region, zone_id, "vswitch", &id, &name, &tags, &[]),
            Some(owner),
        )
        .await;
        return Err(e);
    }

    Ok((
        id.clone(),
        Some(net_resource(
            region,
            zone_id,
            "vswitch",
            &id,
            &name,
            &tags,
            &[("vpc", vpc_id), ("cidr", &cidr)],
        )),
    ))
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

pub(crate) async fn describe_vpc(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    id: &str,
) -> Result<Option<(String, BTreeMap<String, String>)>> {
    let v = api
        .call_ok(
            &api.vpc_endpoint(region),
            "GET",
            "DescribeVpcs",
            VPC_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("VpcId".into(), id.to_string()),
            ],
            api.profile_hint(conn),
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

pub(crate) async fn describe_vswitch(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    id: &str,
) -> Result<Option<(String, BTreeMap<String, String>)>> {
    let v = api
        .call_ok(
            &api.vpc_endpoint(region),
            "GET",
            "DescribeVSwitches",
            VPC_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("VSwitchId".into(), id.to_string()),
            ],
            api.profile_hint(conn),
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

pub(crate) async fn list_vswitches(
    api: &AliyunEcs,
    conn: &Connection,
    owner: &str,
) -> Result<Vec<Resource>> {
    let mut base = vec![("RegionId".into(), conn.region.clone())];
    base.extend(owner_tag_filters(owner));
    let mut out = Vec::new();
    for vsw in api
        .paginated_page_number(
            &api.vpc_endpoint(&conn.region),
            "DescribeVSwitches",
            VPC_API_VERSION,
            &base,
            ("VSwitches", "VSwitch"),
            api.profile_hint(conn),
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
    Ok(out)
}

pub(crate) async fn list_vpcs(
    api: &AliyunEcs,
    conn: &Connection,
    owner: &str,
) -> Result<Vec<Resource>> {
    let mut base = vec![("RegionId".into(), conn.region.clone())];
    base.extend(owner_tag_filters(owner));
    let mut out = Vec::new();
    for vpc in api
        .paginated_page_number(
            &api.vpc_endpoint(&conn.region),
            "DescribeVpcs",
            VPC_API_VERSION,
            &base,
            ("Vpcs", "Vpc"),
            api.profile_hint(conn),
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

pub(crate) async fn has_vpc_children(
    api: &AliyunEcs,
    region: &str,
    vpc_id: &str,
    profile_hint: Option<&str>,
) -> bool {
    vpc_has_matching_children(api, region, vpc_id, profile_hint, |_| true).await
}

pub(crate) async fn vpc_has_non_cua_children(
    api: &AliyunEcs,
    region: &str,
    vpc_id: &str,
    expected_owner: Option<&str>,
    profile_hint: Option<&str>,
) -> bool {
    vpc_has_matching_children(api, region, vpc_id, profile_hint, |tags| {
        !super::net::is_cua_owned_tags(tags, expected_owner)
    })
    .await
}

async fn vpc_has_matching_children(
    api: &AliyunEcs,
    region: &str,
    vpc_id: &str,
    profile_hint: Option<&str>,
    pred: impl Fn(&BTreeMap<String, String>) -> bool,
) -> bool {
    let vpc_params = vec![
        ("RegionId".into(), region.to_string()),
        ("VpcId".into(), vpc_id.to_string()),
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
            .any(|vsw| vsw["VpcId"].as_str() == Some(vpc_id) && pred(&tags_of(vsw)))
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
            .any(|sg| sg["VpcId"].as_str() == Some(vpc_id) && pred(&tags_of(sg)))
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vswitch_cidrs_are_disjoint_slash_20s_inside_vpc_slash_16() {
        assert_eq!(VPC_CIDR, "10.77.0.0/16");
        assert_eq!(vswitch_cidr(0).unwrap(), "10.77.0.0/20");
        assert_eq!(vswitch_cidr(1).unwrap(), "10.77.16.0/20");
        assert_eq!(vswitch_cidr(15).unwrap(), "10.77.240.0/20");
        assert!(vswitch_cidr(16).is_none());

        assert_eq!(
            next_free_vswitch_cidr(&["10.77.0.0/20".into(), "10.77.16.0/20".into()]).as_deref(),
            Some("10.77.32.0/20")
        );
        assert_eq!(
            next_free_vswitch_cidr(&["10.77.0.0/19".into()]).as_deref(),
            Some("10.77.32.0/20"),
            "must skip overlapping /19 covering first two /20 slots"
        );
    }
}
