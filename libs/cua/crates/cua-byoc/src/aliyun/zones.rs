// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Availability zone discovery and stock-first candidate ordering for `aliyun-ecs`.

use std::collections::BTreeSet;

use cua_sandbox_core::Error;

use super::AliyunEcs;
use super::client::ECS_API_VERSION;
use super::sizing::is_with_stock_category;
use crate::api::Result;
use crate::model::Connection;

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
