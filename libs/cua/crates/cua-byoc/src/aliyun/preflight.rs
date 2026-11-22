// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Read-only preflight checks (`cua cloud test aliyun-ecs` / `connect`) verifying
//! credentials, region, machine offerings, official & configured Cloud Image IDs,
//! existing VPC/VSwitch validity, and RAM permissions without creating resources.

use super::AliyunEcs;
use super::client::{
    ApiBody, ECS_API_VERSION, STS_API_VERSION, VPC_API_VERSION, api_error_code_message,
    map_api_error,
};
use super::existing_vpc;
use super::image;
use super::net;
use super::sizing::{
    LINUX_INSTANCE_TYPE, describe_instance_types_batch, ecs_instance_spec,
    is_excluded_instance_family, is_with_stock_category, lookup_instance_type,
    select_best_dynamic_candidate,
};
use crate::api::Tested;
use crate::model::{Connection, tag};

pub(crate) async fn run_preflight_test(api: &AliyunEcs, conn: &Connection) -> Tested {
    let mut t = Tested::default();
    let profile_hint = api.profile_hint(conn);

    let (_, source) = match api.resolve_credentials(profile_hint) {
        Ok(v) => v,
        Err(e) => {
            t.check("credentials", false, e.to_string());
            return t;
        }
    };

    let identity = match api
        .call_ok(
            &api.sts_endpoint,
            "GET",
            "GetCallerIdentity",
            STS_API_VERSION,
            &[],
            profile_hint,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            t.check("credentials", false, e.to_string());
            return t;
        }
    };
    let account_id = identity["AccountId"]
        .as_str()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    if account_id.is_empty() {
        t.check(
            "credentials",
            false,
            "sts:GetCallerIdentity returned an empty AccountId",
        );
        return t;
    }
    t.account = account_id.clone();
    t.check(
        "credentials",
        true,
        format!("{}; account {account_id}", source.describe()),
    );

    let ecs = api.ecs_endpoint(&conn.region);
    let vpc = api.vpc_endpoint(&conn.region);

    match api
        .call_ok(
            &ecs,
            "GET",
            "DescribeRegions",
            ECS_API_VERSION,
            &[],
            profile_hint,
        )
        .await
    {
        Ok(v) => {
            let found = v["Regions"]["Region"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r["RegionId"].as_str() == Some(conn.region.as_str()));
            if found {
                t.check("region", true, format!("{} available", conn.region));
            } else {
                t.check(
                    "region",
                    false,
                    format!("region {:?} is not enabled in this account", conn.region),
                );
                return t;
            }
        }
        Err(e) => {
            t.check("region", false, e.to_string());
            return t;
        }
    }

    let discovered_type: String;
    match api
        .call_ok(
            &ecs,
            "GET",
            "DescribeAvailableResource",
            ECS_API_VERSION,
            &[
                ("RegionId".into(), conn.region.clone()),
                ("DestinationResource".into(), "InstanceType".into()),
                ("InstanceChargeType".into(), "PostPaid".into()),
                ("IoOptimized".into(), "optimized".into()),
            ],
            profile_hint,
        )
        .await
    {
        Ok(v) => {
            let mut available_types = Vec::new();
            for zone in v["AvailableZones"]["AvailableZone"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some(st) = zone["Status"].as_str()
                    && !st.eq_ignore_ascii_case("Available")
                {
                    continue;
                }
                for ar in zone["AvailableResources"]["AvailableResource"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    for sr in ar["SupportedResources"]["SupportedResource"]
                        .as_array()
                        .into_iter()
                        .flatten()
                    {
                        let status = sr["Status"].as_str().unwrap_or("");
                        if status == "Available"
                            && is_with_stock_category(sr["StatusCategory"].as_str())
                            && let Some(val) = sr["Value"].as_str()
                            && !available_types.iter().any(|x| x == val)
                        {
                            available_types.push(val.to_string());
                        }
                    }
                }
            }
            if available_types.is_empty() {
                t.check(
                    "machine",
                    false,
                    format!(
                        "no PostPaid ECS instance types available in {}",
                        conn.region
                    ),
                );
                return t;
            }
            if let Some(ref custom_type) = conn.instance_type {
                if !available_types.iter().any(|x| x == custom_type) {
                    t.check(
                        "machine",
                        false,
                        format!(
                            "instance type {custom_type:?} is not available for PostPaid ECS in {}",
                            conn.region
                        ),
                    );
                    return t;
                }
                let (vcpus, mem_mb, usd) =
                    match lookup_instance_type(api, conn, &conn.region, custom_type).await {
                        Ok(s) => s,
                        Err(e) => {
                            t.check("machine", false, e.to_string());
                            return t;
                        }
                    };
                if let Some(max) = conn.max_size
                    && !max.fits(vcpus, mem_mb)
                {
                    t.check(
                        "machine",
                        false,
                        format!(
                            "instance type {custom_type:?} ({vcpus} vCPU, {} GB) exceeds --max-size {max}",
                            mem_mb.div_ceil(1024)
                        ),
                    );
                    return t;
                }
                discovered_type = custom_type.clone();
                t.check(
                    "machine",
                    true,
                    format!(
                        "{} instance types in {}; configured {custom_type} ({vcpus} vCPU, {} GB, ~${usd:.3}/h)",
                        available_types.len(),
                        conn.region,
                        mem_mb.div_ceil(1024),
                    ),
                );
            } else {
                let meta_map =
                    describe_instance_types_batch(api, conn, &conn.region, &available_types).await;
                let cands: Vec<(String, Vec<String>)> = available_types
                    .iter()
                    .cloned()
                    .map(|id| (id, Vec::new()))
                    .collect();
                let (picked, est_usd) = if let Some((id, meta, _)) = select_best_dynamic_candidate(
                    "linux",
                    2,
                    4096,
                    conn.max_size,
                    &cands,
                    &meta_map,
                ) {
                    (id, meta.usd_per_hour)
                } else if let Some(first) = available_types
                    .iter()
                    .find(|id| !is_excluded_instance_family(id, None, None))
                    .or_else(|| available_types.first())
                {
                    let u = meta_map
                        .get(first)
                        .map(|m| m.usd_per_hour)
                        .or_else(|| ecs_instance_spec(first).map(|(_, _, u)| u))
                        .unwrap_or(0.043);
                    (first.clone(), u)
                } else {
                    (LINUX_INSTANCE_TYPE.to_string(), 0.043)
                };
                discovered_type = picked;
                t.check(
                    "machine",
                    true,
                    format!(
                        "{} instance types in {}; baseline {} (~${est_usd:.3}/h)",
                        available_types.len(),
                        conn.region,
                        discovered_type
                    ),
                );
            }
        }
        Err(e) => {
            t.check("machine", false, e.to_string());
            return t;
        }
    }

    let discovered_image =
        match image::resolve_official_image(api, conn, &conn.region, "linux").await {
            Ok(img) => {
                t.check("image", true, format!("Ubuntu 24.04 ({})", img.image_id));
                img.image_id
            }
            Err(e) => {
                t.check("image", false, e.to_string());
                return t;
            }
        };

    let existing_vpc_pair = conn.vpc_id.as_deref().zip(conn.vswitch_id.as_deref());
    if let Some((vpc_id, vswitch_id)) = existing_vpc_pair {
        match existing_vpc::validate_existing_vpc(
            api,
            &conn.region,
            vpc_id,
            vswitch_id,
            profile_hint,
        )
        .await
        {
            Ok(info) => {
                t.check(
                    "vpc",
                    true,
                    format!(
                        "VPC {vpc_id} / VSwitch {vswitch_id} available in {} ({})",
                        conn.region,
                        if info.zone_id.is_empty() {
                            "zone unknown"
                        } else {
                            info.zone_id.as_str()
                        }
                    ),
                );
            }
            Err(e) => {
                t.check("vpc", false, e.to_string());
                return t;
            }
        }
    }

    let mut custom_images_ok = true;
    if let Some(ref win_id) = conn.windows_image_id {
        match image::validate_image_id(api, conn, &conn.region, win_id, "windows").await {
            Ok(img) => t.check(
                "windows_image",
                true,
                format!("Windows Cloud Image ID {} available", img.image_id),
            ),
            Err(e) => {
                t.check("windows_image", false, e.to_string());
                custom_images_ok = false;
            }
        }
    }
    let mut dry_run_image = discovered_image;
    if let Some(ref lin_id) = conn.linux_image_id {
        match image::validate_image_id(api, conn, &conn.region, lin_id, "linux").await {
            Ok(img) => {
                t.check(
                    "linux_image",
                    true,
                    format!("Linux Cloud Image ID {} available", img.image_id),
                );
                dry_run_image = img.image_id;
            }
            Err(e) => {
                t.check("linux_image", false, e.to_string());
                custom_images_ok = false;
            }
        }
    }
    if !custom_images_ok {
        return t;
    }

    // Alibaba Cloud ECS `CreateSecurityGroup` does not support `DryRun=true`, so
    // preflight never invokes `CreateSecurityGroup`.
    if let Err(e) = api
        .call_ok(
            &ecs,
            "GET",
            "DescribeInstances",
            ECS_API_VERSION,
            &[
                ("RegionId".into(), conn.region.clone()),
                ("PageSize".into(), "1".into()),
            ],
            profile_hint,
        )
        .await
    {
        t.check("permissions", false, e.to_string());
        return t;
    }

    let (vsw_id, matching_sg_id) = if let Some((vpc_id, vswitch_id)) = existing_vpc_pair {
        let sgs = match api
            .call_ok(
                &ecs,
                "GET",
                "DescribeSecurityGroups",
                ECS_API_VERSION,
                &[
                    ("RegionId".into(), conn.region.clone()),
                    ("VpcId".into(), vpc_id.to_string()),
                    ("PageSize".into(), "50".into()),
                ],
                profile_hint,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                t.check("permissions", false, e.to_string());
                return t;
            }
        };
        let sg_id = sgs["SecurityGroups"]["SecurityGroup"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|sg| {
                sg["VpcId"].as_str() == Some(vpc_id)
                    && net::tags_of(sg).get(tag::MANAGED).map(String::as_str) == Some("true")
            })
            .and_then(|sg| sg["SecurityGroupId"].as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        (Some(vswitch_id.to_string()), sg_id)
    } else {
        if let Err(e) = api
            .call_ok(
                &vpc,
                "GET",
                "DescribeVpcs",
                VPC_API_VERSION,
                &[
                    ("RegionId".into(), conn.region.clone()),
                    ("PageSize".into(), "1".into()),
                ],
                profile_hint,
            )
            .await
        {
            t.check("permissions", false, e.to_string());
            return t;
        }

        let vsw = match api
            .call_ok(
                &vpc,
                "GET",
                "DescribeVSwitches",
                VPC_API_VERSION,
                &[
                    ("RegionId".into(), conn.region.clone()),
                    ("PageSize".into(), "1".into()),
                ],
                profile_hint,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                t.check("permissions", false, e.to_string());
                return t;
            }
        };

        let first_vsw = vsw["VSwitches"]["VSwitch"]
            .as_array()
            .and_then(|a| a.first());
        let vsw_id = first_vsw
            .and_then(|x| x["VSwitchId"].as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let vsw_vpc_id = first_vsw
            .and_then(|x| x["VpcId"].as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let mut sg_params = vec![
            ("RegionId".into(), conn.region.clone()),
            ("PageSize".into(), "10".into()),
        ];
        if let Some(ref vpc_id) = vsw_vpc_id {
            sg_params.push(("VpcId".into(), vpc_id.clone()));
        }
        let sgs = match api
            .call_ok(
                &ecs,
                "GET",
                "DescribeSecurityGroups",
                ECS_API_VERSION,
                &sg_params,
                profile_hint,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                t.check("permissions", false, e.to_string());
                return t;
            }
        };

        let matching_sg_id = vsw_vpc_id.as_deref().and_then(|vpc_id| {
            sgs["SecurityGroups"]["SecurityGroup"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|sg| sg["VpcId"].as_str() == Some(vpc_id))
                .and_then(|sg| sg["SecurityGroupId"].as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
        (vsw_id, matching_sg_id)
    };

    if existing_vpc_pair.is_none() {
        let vpc_dry_params = vec![
            ("RegionId".into(), conn.region.clone()),
            ("CidrBlock".into(), net::VPC_CIDR.into()),
            ("VpcName".into(), "cua-sb-dryrun".into()),
            ("Tag.1.Key".into(), tag::MANAGED.into()),
            ("Tag.1.Value".into(), "true".into()),
            ("DryRun".into(), "true".into()),
        ];
        match api
            .call_raw(
                &vpc,
                "POST",
                "CreateVpc",
                VPC_API_VERSION,
                &vpc_dry_params,
                profile_hint,
            )
            .await
        {
            Ok((status, body)) => {
                let code = match &body {
                    ApiBody::Json(v) => api_error_code_message(v).0,
                    ApiBody::Text(_) => "",
                };
                if status.is_success() || code != "DryRunOperation" {
                    t.check(
                        "permissions",
                        false,
                        map_api_error("CreateVpc", VPC_API_VERSION, status, &body).to_string(),
                    );
                    return t;
                }
            }
            Err(e) => {
                t.check("permissions", false, e.to_string());
                return t;
            }
        }
    }

    let mut run_params = vec![
        ("RegionId".into(), conn.region.clone()),
        ("ImageId".into(), dry_run_image),
        ("InstanceType".into(), discovered_type),
        ("Tag.1.Key".into(), tag::MANAGED.into()),
        ("Tag.1.Value".into(), "true".into()),
        ("DryRun".into(), "true".into()),
    ];
    if conn.no_public_ip {
        run_params.push(("InternetMaxBandwidthOut".into(), "0".into()));
    }
    let has_matching_sg = matching_sg_id.is_some();
    let has_vswitch = if let Some(id) = vsw_id {
        run_params.push(("VSwitchId".into(), id));
        if let Some(sg_id) = matching_sg_id {
            run_params.push(("SecurityGroupId".into(), sg_id));
        }
        true
    } else {
        false
    };

    match api
        .call_raw(
            &ecs,
            "POST",
            "RunInstances",
            ECS_API_VERSION,
            &run_params,
            profile_hint,
        )
        .await
    {
        Ok((status, body)) => {
            let code = match &body {
                ApiBody::Json(v) => api_error_code_message(v).0,
                ApiBody::Text(_) => "",
            };
            if !status.is_success() && code == "DryRunOperation" {
                let msg = if existing_vpc_pair.is_some() {
                    "RAM permissions verified (RunInstances DryRun passed)"
                } else {
                    "RAM permissions verified (RunInstances, CreateVpc DryRun passed)"
                };
                t.check("permissions", true, msg);
            } else if !has_vswitch && !status.is_success() && code == "InvalidVSwitchId.NotFound" {
                t.check(
                    "permissions",
                    true,
                    "RAM permissions verified (RunInstances DryRun passed auth check)",
                );
            } else if existing_vpc_pair.is_some()
                && !has_matching_sg
                && !status.is_success()
                && matches!(
                    code,
                    "InvalidSecurityGroupId" | "InvalidSecurityGroupId.NotFound"
                )
            {
                t.check(
                    "permissions",
                    true,
                    "RAM permissions verified (RunInstances DryRun passed)",
                );
            } else {
                t.check(
                    "permissions",
                    false,
                    map_api_error("RunInstances", ECS_API_VERSION, status, &body).to_string(),
                );
            }
        }
        Err(e) => {
            t.check("permissions", false, e.to_string());
        }
    }

    t
}
