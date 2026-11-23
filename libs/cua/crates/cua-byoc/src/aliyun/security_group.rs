// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Zero-ingress enterprise Security Group provisioning, verification, listing,
//! and inspection for `aliyun-ecs`.

use std::collections::BTreeMap;

use cua_sandbox_core::Error;

use super::AliyunEcs;
use super::client::ECS_API_VERSION;
use super::net::{
    delete_part_owned, net_resource, owner_tag_filters, part_tags, tag_params, tags_of,
};
use crate::api::Result;
use crate::model::{self, Connection, Resource};

/// Name of `owner`'s zero-ingress Security Group (`cua-sandboxes-<owner>`).
pub fn sg_name(owner: &str) -> String {
    format!("cua-sandboxes-{}", model::label_value(owner))
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
        let _ = delete_part_owned(
            api,
            conn,
            &net_resource(region, "", "security_group", &id, &name, &tags, &[]),
            Some(owner),
        )
        .await;
        return Err(e);
    }

    if let Some(winner) = find_security_group(api, conn, region, owner, vpc_id).await?
        && winner != id
    {
        let _ = delete_part_owned(
            api,
            conn,
            &net_resource(region, "", "security_group", &id, &name, &tags, &[]),
            Some(owner),
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

pub(crate) async fn describe_security_group(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    id: &str,
) -> Result<Option<(String, BTreeMap<String, String>)>> {
    let v = api
        .call_ok(
            &api.ecs_endpoint(region),
            "GET",
            "DescribeSecurityGroups",
            ECS_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("SecurityGroupId".into(), id.to_string()),
            ],
            api.profile_hint(conn),
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

pub(crate) async fn list_security_groups(
    api: &AliyunEcs,
    conn: &Connection,
    owner: &str,
) -> Result<Vec<Resource>> {
    let mut base = vec![("RegionId".into(), conn.region.clone())];
    base.extend(owner_tag_filters(owner));
    let mut out = Vec::new();
    for sg in api
        .paginated_page_number(
            &api.ecs_endpoint(&conn.region),
            "DescribeSecurityGroups",
            ECS_API_VERSION,
            &base,
            ("SecurityGroups", "SecurityGroup"),
            api.profile_hint(conn),
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
    Ok(out)
}
