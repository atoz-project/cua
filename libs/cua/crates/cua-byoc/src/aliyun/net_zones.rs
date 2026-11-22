// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Zone candidate ordering and zero-ingress Security Group provisioning for
//! `aliyun-ecs`.

use std::collections::BTreeSet;

use cua_sandbox_core::Error;

use super::AliyunEcs;
use super::client::ECS_API_VERSION;
use super::net::{net_resource, owner_tag_filters, part_tags, sg_name, tag_params, tags_of};
use super::net_lifecycle::delete_part;
use super::sizing::is_with_stock_category;
use crate::api::Result;
use crate::model::{self, Connection, Resource};

/// Discovers availability zones in deterministic order: stock-available zones
/// for `instance_type` first, supplemented by remaining available zones from
/// `DescribeZones`.
pub async fn discover_zones(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    instance_type: &str,
) -> Result<Vec<String>> {
    discover_zones_with_stock(api, conn, region, instance_type, None).await
}

/// Orders candidate zones putting `precomputed_stock_zones` first (avoiding a
/// duplicate `DescribeAvailableResource` call when sizing already fetched them),
/// supplemented by remaining zones from `DescribeZones`.
pub(crate) async fn discover_zones_with_stock(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    instance_type: &str,
    precomputed_stock_zones: Option<&[String]>,
) -> Result<Vec<String>> {
    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(region);

    let mut avail_err: Option<Error> = None;
    let mut stock_zones: Vec<String> = match precomputed_stock_zones {
        Some(zones) if !zones.is_empty() => {
            let mut z = zones.to_vec();
            z.sort();
            z
        }
        _ => {
            let mut found = Vec::new();
            match api
                .call_ok(
                    &ecs_ep,
                    "GET",
                    "DescribeAvailableResource",
                    ECS_API_VERSION,
                    &[
                        ("RegionId".into(), region.to_string()),
                        ("DestinationResource".into(), "InstanceType".into()),
                        ("InstanceChargeType".into(), "PostPaid".into()),
                        ("IoOptimized".into(), "optimized".into()),
                        ("InstanceType".into(), instance_type.to_string()),
                    ],
                    profile_hint,
                )
                .await
            {
                Ok(v) => {
                    for az in v["AvailableZones"]["AvailableZone"]
                        .as_array()
                        .into_iter()
                        .flatten()
                    {
                        if let Some(st) = az["Status"].as_str()
                            && !st.eq_ignore_ascii_case("Available")
                        {
                            continue;
                        }
                        let Some(zone_id) = az["ZoneId"]
                            .as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        else {
                            continue;
                        };
                        let has_type = az["AvailableResources"]["AvailableResource"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .flat_map(|ar| {
                                ar["SupportedResources"]["SupportedResource"]
                                    .as_array()
                                    .into_iter()
                                    .flatten()
                            })
                            .any(|sr| {
                                sr["Value"].as_str() == Some(instance_type)
                                    && sr["Status"].as_str() == Some("Available")
                                    && is_with_stock_category(sr["StatusCategory"].as_str())
                            });
                        if has_type && !found.iter().any(|z| z == zone_id) {
                            found.push(zone_id.to_string());
                        }
                    }
                    found.sort();
                }
                Err(e) => avail_err = Some(e),
            }
            found
        }
    };

    let mut all_zones = Vec::new();
    match api
        .call_ok(
            &ecs_ep,
            "GET",
            "DescribeZones",
            ECS_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("InstanceChargeType".into(), "PostPaid".into()),
            ],
            profile_hint,
        )
        .await
    {
        Ok(v) => {
            for z in v["Zones"]["Zone"].as_array().into_iter().flatten() {
                if let Some(st) = z["Status"].as_str()
                    && !st.eq_ignore_ascii_case("Available")
                {
                    continue;
                }
                if let Some(zid) = z["ZoneId"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    && !all_zones.iter().any(|x| x == zid)
                {
                    all_zones.push(zid.to_string());
                }
            }
            all_zones.sort();
        }
        Err(e) if stock_zones.is_empty() => {
            if let Some(ae) = avail_err {
                return Err(ae);
            }
            return Err(e);
        }
        Err(_) => {}
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut ordered = Vec::new();
    for z in stock_zones.drain(..).chain(all_zones) {
        if seen.insert(z.clone()) {
            ordered.push(z);
        }
    }
    Ok(ordered)
}

async fn authorize_sg_egress(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    sg_id: &str,
) -> Result<()> {
    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(region);
    api.call_ok(
        &ecs_ep,
        "POST",
        "AuthorizeSecurityGroupEgress",
        ECS_API_VERSION,
        &[
            ("RegionId".into(), region.to_string()),
            ("SecurityGroupId".into(), sg_id.to_string()),
            ("Permissions.1.IpProtocol".into(), "all".into()),
            ("Permissions.1.PortRange".into(), "-1/-1".into()),
            ("Permissions.1.DestCidrIp".into(), "0.0.0.0/0".into()),
            ("Permissions.1.Policy".into(), "accept".into()),
            ("Permissions.1.Priority".into(), "1".into()),
        ],
        profile_hint,
    )
    .await?;
    Ok(())
}

async fn verify_and_repair_sg(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    sg_id: &str,
) -> Result<()> {
    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(region);
    let attr = api
        .call_ok(
            &ecs_ep,
            "GET",
            "DescribeSecurityGroupAttribute",
            ECS_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("SecurityGroupId".into(), sg_id.to_string()),
            ],
            profile_hint,
        )
        .await?;

    if let Some(inner) = attr["InnerAccessPolicy"].as_str()
        && !inner.eq_ignore_ascii_case("Drop")
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: refusing security group {sg_id}: expected InnerAccessPolicy=Drop, got {inner:?}"
        )));
    }

    let perms = attr["Permissions"]["Permission"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut has_egress = false;
    for p in &perms {
        let dir = p["Direction"].as_str().unwrap_or("");
        let policy = p["Policy"].as_str().unwrap_or("");
        if dir.eq_ignore_ascii_case("ingress") && policy.eq_ignore_ascii_case("accept") {
            return Err(Error::Cloud(format!(
                "aliyun-ecs: refusing security group {sg_id}: unexpected ingress rule present"
            )));
        }
        if dir.eq_ignore_ascii_case("egress")
            && policy.eq_ignore_ascii_case("accept")
            && p["IpProtocol"]
                .as_str()
                .is_some_and(|x| x.eq_ignore_ascii_case("all"))
            && p["PortRange"].as_str() == Some("-1/-1")
            && p["DestCidrIp"].as_str() == Some("0.0.0.0/0")
        {
            has_egress = true;
        }
    }
    if !has_egress {
        authorize_sg_egress(api, conn, region, sg_id).await?;
    }
    Ok(())
}

async fn find_security_group(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
    vpc_id: &str,
) -> Result<Option<String>> {
    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(region);
    let name = sg_name(owner);
    let mut base = vec![
        ("RegionId".into(), region.to_string()),
        ("VpcId".into(), vpc_id.to_string()),
    ];
    base.extend(owner_tag_filters(owner));
    let sgs = api
        .paginated_page_number(
            &ecs_ep,
            "DescribeSecurityGroups",
            ECS_API_VERSION,
            &base,
            ("SecurityGroups", "SecurityGroup"),
            profile_hint,
        )
        .await?;
    Ok(sgs
        .into_iter()
        .filter(|sg| {
            sg["VpcId"].as_str() == Some(vpc_id)
                && sg["SecurityGroupName"].as_str() == Some(name.as_str())
                && model::is_ours(&tags_of(sg), owner)
        })
        .filter_map(|sg| {
            sg["SecurityGroupId"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .min())
}

pub(crate) async fn ensure_security_group(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
    vpc_id: &str,
) -> Result<(String, Option<Resource>)> {
    if let Some(id) = find_security_group(api, conn, region, owner, vpc_id).await? {
        verify_and_repair_sg(api, conn, region, &id).await?;
        return Ok((id, None));
    }

    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(region);
    let name = sg_name(owner);
    let tags = part_tags(owner);
    let token = format!("cua-sg-{:016x}", rand::random::<u64>());
    let mut params = vec![
        ("RegionId".into(), region.to_string()),
        ("VpcId".into(), vpc_id.to_string()),
        ("SecurityGroupName".into(), name.clone()),
        (
            "Description".into(),
            "Cua sandboxes (outbound only, zero ingress)".into(),
        ),
        ("SecurityGroupType".into(), "enterprise".into()),
        ("ClientToken".into(), token),
    ];
    params.extend(tag_params(&tags));

    let created = api
        .call_ok(
            &ecs_ep,
            "POST",
            "CreateSecurityGroup",
            ECS_API_VERSION,
            &params,
            profile_hint,
        )
        .await?;
    let id = created["SecurityGroupId"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::Cloud("aliyun-ecs: CreateSecurityGroup returned no SecurityGroupId".into())
        })?
        .to_string();

    if let Err(e) = authorize_sg_egress(api, conn, region, &id).await {
        let _ = delete_part(
            api,
            conn,
            &net_resource(region, "", "security_group", &id, &name, &tags, &[]),
        )
        .await;
        return Err(e);
    }

    if let Some(winner) = find_security_group(api, conn, region, owner, vpc_id).await?
        && winner != id
    {
        let _ = delete_part(
            api,
            conn,
            &net_resource(region, "", "security_group", &id, &name, &tags, &[]),
        )
        .await;
        verify_and_repair_sg(api, conn, region, &winner).await?;
        return Ok((winner, None));
    }

    Ok((
        id.clone(),
        Some(net_resource(
            region,
            "",
            "security_group",
            &id,
            &name,
            &tags,
            &[("vpc", vpc_id)],
        )),
    ))
}
