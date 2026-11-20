// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Isolated VPC, VSwitch, and zero-ingress Security Group management for
//! Alibaba Cloud ECS (`--on aliyun-ecs`).
//!
//! One VPC per cua home and region (`cua-sb-<owner>`, `10.77.0.0/16`):
//!
//! - one `/20` VSwitch per availability zone (`cua-sb-<owner>-<zone>`,
//!   `10.77.<16*k>.0/20`, skipping any CIDRs already in use in the VPC);
//! - one zero-ingress enterprise Security Group (`cua-sandboxes-<owner>`) with
//!   explicit outbound-only internet egress (`0.0.0.0/0`, `all`, `-1/-1`,
//!   `accept`, priority `1`) and no inbound or intra-group lateral traffic;
//! - every part carries all 6 Cua tags (`cua-managed`, `cua-owner`,
//!   `cua-space`, `cua-machine`, `cua-created-by`, `cua-expires`) at creation
//!   time, keeping `cua-machine=""` so [`crate::sweep`] never confuses shared
//!   network resources with relay machines;
//! - existing account VPCs, default VPCs, VSwitches, and Security Groups
//!   without Cua's tags are never modified or deleted.
//!
//! Structured around [`NetworkConfig`] and [`NetworkMode`] so future existing
//! VPC/VSwitch/`--no-public-ip` support plugs in without changing
//! [`crate::aliyun_ecs::AliyunEcs::provision`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use cua_sandbox_core::Error;
use serde_json::Value;

use crate::aliyun_ecs::{
    AliyunEcs, ApiBody, ECS_API_VERSION, VPC_API_VERSION, api_error_code_message, map_api_error,
};
use crate::api::Result;
use crate::model::{self, Connection, Resource, tag};

/// The VPC's IPv4 CIDR block.
pub const VPC_CIDR: &str = "10.77.0.0/16";

/// Maximum `/20` VSwitches that fit inside a `/16` (`10.77.0.0/16`).
pub const MAX_ZONES: usize = 16;

/// Default PayByTraffic public IPv4 egress bandwidth cap (Mbps).
pub const DEFAULT_PUBLIC_BANDWIDTH_MBPS: u32 = 100;

/// Networking mode for an `aliyun-ecs` connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    /// Cua-managed isolated VPC (`cua-sb-<owner>`), per-zone `/20` VSwitches,
    /// and zero-ingress Security Group (`cua-sandboxes-<owner>`).
    Isolated,
}

/// Resolved networking parameters for provisioning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Isolated Cua VPC vs future user-supplied VPC/VSwitch.
    pub mode: NetworkMode,
    /// `> 0` => `PayByTraffic` public IPv4 with `InternetMaxBandwidthOut`;
    /// `0` => no public IPv4.
    pub public_ip_mbps: u32,
}

impl NetworkConfig {
    /// Derives the network configuration from `conn`.
    pub fn from_connection(_conn: &Connection) -> Result<Self> {
        Ok(Self {
            mode: NetworkMode::Isolated,
            public_ip_mbps: DEFAULT_PUBLIC_BANDWIDTH_MBPS,
        })
    }
}

/// Per-provider mutexes serializing shared VPC/VSwitch and Security Group
/// creation across concurrent launches in the same home.
pub struct NetLocks {
    pub net_lock: tokio::sync::Mutex<()>,
    pub group_lock: tokio::sync::Mutex<()>,
}

impl Default for NetLocks {
    fn default() -> Self {
        Self::new()
    }
}

impl NetLocks {
    /// Creates unlocked network mutexes.
    pub fn new() -> Self {
        Self {
            net_lock: tokio::sync::Mutex::new(()),
            group_lock: tokio::sync::Mutex::new(()),
        }
    }
}

/// One candidate zone (and optional pre-selected VSwitch) to try when
/// launching an instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneCandidate {
    pub zone_id: String,
    pub vswitch_id: Option<String>,
}

/// Network artifacts prepared for an instance launch.
#[derive(Clone, Debug)]
pub struct PreparedNetwork {
    pub vpc_id: String,
    pub security_group_id: String,
    pub candidates: Vec<ZoneCandidate>,
    pub public_ip_mbps: u32,
    /// Newly created shared parts (`security_group`, `vpc`, `vswitch`) to
    /// record on success or roll back on total provisioning failure.
    pub made: Vec<Resource>,
}

/// Name of `owner`'s isolated VPC (`cua-sb-<owner>`).
pub fn vpc_name(owner: &str) -> String {
    format!("cua-sb-{}", model::label_value(owner))
}

/// Name of `owner`'s zero-ingress Security Group (`cua-sandboxes-<owner>`).
pub fn sg_name(owner: &str) -> String {
    format!("cua-sandboxes-{}", model::label_value(owner))
}

/// Name of `owner`'s per-zone VSwitch (`cua-sb-<owner>-<zone>`).
pub fn vswitch_name(owner: &str, zone_id: &str) -> String {
    format!("cua-sb-{}-{zone_id}", model::label_value(owner))
}

/// The `/20` VSwitch CIDR at `index` inside `10.77.0.0/16` (`0..16`).
pub fn vswitch_cidr(index: usize) -> Option<String> {
    (index < MAX_ZONES).then(|| format!("10.77.{}.0/20", index * 16))
}

/// Whether `resource_type` is a network resource managed by `aliyun_net`.
pub fn is_network_type(resource_type: &str) -> bool {
    matches!(
        resource_type,
        "vpc" | "vswitch" | "subnet" | "security_group"
    )
}

/// All 6 mandatory Cua tags for shared network resources (`cua-space=""` and
/// `cua-machine=""` so [`crate::sweep`] never mistakes them for relay
/// machines).
pub fn part_tags(owner: &str) -> BTreeMap<String, String> {
    let mut t = model::tags(owner, "", "", 0);
    t.insert(tag::MACHINE.into(), String::new());
    t
}

/// Encodes `tags` as `Tag.N.Key` / `Tag.N.Value` OpenAPI query/form pairs.
pub(crate) fn tag_params(tags: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut params = Vec::with_capacity(tags.len() * 2);
    for (i, (k, v)) in tags.iter().enumerate() {
        let idx = i + 1;
        params.push((format!("Tag.{idx}.Key"), k.clone()));
        params.push((format!("Tag.{idx}.Value"), v.clone()));
    }
    params
}

/// Reads Cua tags from either ECS (`TagKey`/`TagValue`) or VPC (`Key`/`Value`)
/// JSON objects.
pub fn tags_of(obj: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for item in obj["Tags"]["Tag"].as_array().into_iter().flatten() {
        let k = item["TagKey"].as_str().or_else(|| item["Key"].as_str());
        let v = item["TagValue"].as_str().or_else(|| item["Value"].as_str());
        if let (Some(k), Some(v)) = (k, v) {
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

pub(crate) fn owner_tag_filters(owner: &str) -> [(String, String); 4] {
    [
        ("Tag.1.Key".into(), tag::MANAGED.into()),
        ("Tag.1.Value".into(), "true".into()),
        ("Tag.2.Key".into(), tag::OWNER.into()),
        ("Tag.2.Value".into(), model::label_value(owner)),
    ]
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

fn next_free_vswitch_cidr(used_cidrs: &[String]) -> Option<String> {
    (0..MAX_ZONES)
        .filter_map(vswitch_cidr)
        .find(|cand| !used_cidrs.iter().any(|u| cidrs_overlap(cand, u)))
}

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
    matches!(
        code,
        "DependencyViolation"
            | "InUse"
            | "VpcInUse"
            | "IncorrectVpcStatus"
            | "IncorrectVSwitchStatus"
            | "ResourceInUse"
            | "InvalidOperation.Conflict"
    )
}

fn net_resource(
    region: &str,
    zone: &str,
    kind: &str,
    id: &str,
    name: &str,
    tags: &BTreeMap<String, String>,
    extra: &[(&str, &str)],
) -> Resource {
    Resource {
        provider: "aliyun-ecs".into(),
        id: id.into(),
        resource_type: kind.into(),
        name: name.into(),
        region: region.into(),
        zone: zone.into(),
        created: model::now(),
        expires: 0,
        tags: tags.clone(),
        state: "available".into(),
        extra: extra
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        ..Default::default()
    }
}

pub(crate) async fn paginated_query(
    api: &AliyunEcs,
    endpoint: &str,
    action: &str,
    version: &str,
    base_params: &[(String, String)],
    (outer_key, inner_key): (&str, &str),
    profile_hint: Option<&str>,
) -> Result<Vec<Value>> {
    const PAGE_SIZE: usize = 50;
    const MAX_PAGES: usize = 100;
    let mut out = Vec::new();
    for page in 1..=MAX_PAGES {
        let mut params = base_params.to_vec();
        params.push(("PageNumber".into(), page.to_string()));
        params.push(("PageSize".into(), PAGE_SIZE.to_string()));
        let v = api
            .call_ok(endpoint, "GET", action, version, &params, profile_hint)
            .await?;
        let items = v[outer_key][inner_key]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let count = items.len();
        out.extend(items);
        let total = v["TotalCount"].as_u64().map(|n| n as usize);
        if count == 0 || count < PAGE_SIZE || total.is_some_and(|t| out.len() >= t) {
            break;
        }
    }
    Ok(out)
}

async fn wait_vpc_available(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    vpc_id: &str,
) -> Result<()> {
    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);
    for _ in 0..60 {
        let v = api
            .call_ok(
                &vpc_ep,
                "GET",
                "DescribeVpcs",
                VPC_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("VpcId".into(), vpc_id.to_string()),
                ],
                profile_hint,
            )
            .await?;
        if let Some(vpc) = v["Vpcs"]["Vpc"].as_array().and_then(|a| a.first()) {
            let status = vpc["Status"].as_str().unwrap_or("Available");
            if status.eq_ignore_ascii_case("Available") {
                return Ok(());
            }
        }
        tokio::time::sleep(api.poll_interval()).await;
    }
    Err(Error::Timeout(format!(
        "aliyun-ecs: VPC {vpc_id} did not become Available in {region}"
    )))
}

async fn wait_vswitch_available(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    vswitch_id: &str,
) -> Result<()> {
    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);
    for _ in 0..60 {
        let v = api
            .call_ok(
                &vpc_ep,
                "GET",
                "DescribeVSwitches",
                VPC_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    ("VSwitchId".into(), vswitch_id.to_string()),
                ],
                profile_hint,
            )
            .await?;
        if let Some(vsw) = v["VSwitches"]["VSwitch"].as_array().and_then(|a| a.first()) {
            let status = vsw["Status"].as_str().unwrap_or("Available");
            if status.eq_ignore_ascii_case("Available") {
                return Ok(());
            }
        }
        tokio::time::sleep(api.poll_interval()).await;
    }
    Err(Error::Timeout(format!(
        "aliyun-ecs: VSwitch {vswitch_id} did not become Available in {region}"
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
    let items = paginated_query(
        api,
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

async fn ensure_vpc(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
) -> Result<(String, Option<Resource>)> {
    if let Some(id) = find_vpc(api, conn, region, owner).await? {
        wait_vpc_available(api, conn, region, &id).await?;
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

    if let Err(e) = wait_vpc_available(api, conn, region, &id).await {
        let _ = delete_part(
            api,
            conn,
            &net_resource(region, "", "vpc", &id, &name, &tags, &[]),
        )
        .await;
        return Err(e);
    }

    // Race-loser cleanup: if two processes created a VPC concurrently, keep
    // the lowest VpcId and delete our empty redundant one.
    if let Some(winner) = find_vpc(api, conn, region, owner).await?
        && winner != id
    {
        let _ = delete_part(
            api,
            conn,
            &net_resource(region, "", "vpc", &id, &name, &tags, &[]),
        )
        .await;
        wait_vpc_available(api, conn, region, &winner).await?;
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

/// Discovers availability zones in deterministic order: stock-available zones
/// for `instance_type` first (from `DescribeAvailableResource`), supplemented
/// by remaining available zones from `DescribeZones`.
pub async fn discover_zones(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    instance_type: &str,
) -> Result<Vec<String>> {
    let profile_hint = api.profile_hint(conn);
    let ecs_ep = api.ecs_endpoint(region);

    let mut stock_zones = Vec::new();
    let avail_res = api
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
        .await;
    if let Ok(v) = &avail_res {
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
                });
            if has_type && !stock_zones.iter().any(|z| z == zone_id) {
                stock_zones.push(zone_id.to_string());
            }
        }
        stock_zones.sort();
    }

    let mut all_zones = Vec::new();
    let zones_res = api
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
        .await;
    match zones_res {
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
            avail_res?;
            return Err(e);
        }
        Err(_) => {}
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut ordered = Vec::new();
    for z in stock_zones.into_iter().chain(all_zones) {
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
    let sgs = paginated_query(
        api,
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

async fn ensure_security_group(
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

    // Race-loser cleanup: if two processes created a security group concurrently,
    // keep the lowest SecurityGroupId and delete our redundant one.
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

/// Ensures Cua's VPC, Security Group, and ordered zone candidates are ready.
pub async fn prepare_network(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
    instance_type: &str,
    cfg: &NetworkConfig,
    locks: &NetLocks,
) -> Result<PreparedNetwork> {
    let mut made = Vec::new();
    let (vpc_id, candidates) = match &cfg.mode {
        NetworkMode::Isolated => {
            let _guard = locks.net_lock.lock().await;
            let (vpc_id, vpc_made) = ensure_vpc(api, conn, region, owner).await?;
            if let Some(r) = vpc_made {
                made.push(r);
            }
            let zones = match discover_zones(api, conn, region, instance_type).await {
                Ok(z) => z,
                Err(e) => {
                    rollback_made(api, conn, &made).await;
                    return Err(e);
                }
            };
            let candidates = zones
                .into_iter()
                .map(|zone_id| ZoneCandidate {
                    zone_id,
                    vswitch_id: None,
                })
                .collect();
            (vpc_id, candidates)
        }
    };

    let security_group_id = {
        let _guard = locks.group_lock.lock().await;
        match ensure_security_group(api, conn, region, owner, &vpc_id).await {
            Ok((sg_id, sg_made)) => {
                if let Some(r) = sg_made {
                    made.push(r);
                }
                sg_id
            }
            Err(e) => {
                rollback_made(api, conn, &made).await;
                return Err(e);
            }
        }
    };

    Ok(PreparedNetwork {
        vpc_id,
        security_group_id,
        candidates,
        public_ip_mbps: cfg.public_ip_mbps,
        made,
    })
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

    let existing = paginated_query(
        api,
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
        wait_vswitch_available(api, conn, region, id).await?;
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

    if let Err(e) = wait_vswitch_available(api, conn, region, &id).await {
        let _ = delete_part(
            api,
            conn,
            &net_resource(region, zone_id, "vswitch", &id, &name, &tags, &[]),
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
            // Default VPCs are never owned by Cua regardless of tags.
            let tags = if vpc["IsDefault"].as_bool().unwrap_or(false) {
                BTreeMap::new()
            } else {
                tags_of(vpc)
            };
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
            // Default VSwitches are never owned by Cua regardless of tags.
            let tags = if vsw["IsDefault"].as_bool().unwrap_or(false) {
                BTreeMap::new()
            } else {
                tags_of(vsw)
            };
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

    for sg in paginated_query(
        api,
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

    for vsw in paginated_query(
        api,
        &vpc_ep,
        "DescribeVSwitches",
        VPC_API_VERSION,
        &base,
        ("VSwitches", "VSwitch"),
        profile_hint,
    )
    .await?
    {
        if vsw["IsDefault"].as_bool().unwrap_or(false) {
            continue;
        }
        let tags = tags_of(&vsw);
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

    for vpc in paginated_query(
        api,
        &vpc_ep,
        "DescribeVpcs",
        VPC_API_VERSION,
        &base,
        ("Vpcs", "Vpc"),
        profile_hint,
    )
    .await?
    {
        if vpc["IsDefault"].as_bool().unwrap_or(false) {
            continue;
        }
        let tags = tags_of(&vpc);
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

/// Deletes one network part (`security_group`, `vswitch`/`subnet`, `vpc`),
/// retrying dependency violations and treating `NotFound` as `Ok(())`.
pub async fn delete_part(api: &AliyunEcs, conn: &Connection, r: &Resource) -> Result<()> {
    if r.id.is_empty() {
        return Ok(());
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
        if is_retryable_delete_code(code) && tries < 24 {
            tries += 1;
            tokio::time::sleep(api.poll_interval()).await;
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

    #[test]
    fn part_tags_carry_all_six_keys_with_empty_machine_and_space() {
        let t = part_tags("Owner_1");
        assert_eq!(t.len(), 6, "{t:?}");
        assert_eq!(t.get(tag::MANAGED).map(String::as_str), Some("true"));
        assert_eq!(t.get(tag::OWNER).map(String::as_str), Some("owner_1"));
        assert_eq!(t.get(tag::SPACE).map(String::as_str), Some(""));
        assert_eq!(t.get(tag::MACHINE).map(String::as_str), Some(""));
        assert!(t.contains_key(tag::CREATED_BY));
        assert_eq!(t.get(tag::EXPIRES).map(String::as_str), Some("0"));
        assert!(model::is_ours(&t, "Owner_1"));
        assert!(!model::is_ours(&t, "someone-else"));
        assert_eq!(vpc_name("Owner_1"), "cua-sb-owner_1");
        assert_eq!(sg_name("Owner_1"), "cua-sandboxes-owner_1");
        assert_eq!(
            vswitch_name("Owner_1", "cn-hangzhou-h"),
            "cua-sb-owner_1-cn-hangzhou-h"
        );
    }

    #[test]
    fn tags_of_reads_both_ecs_and_vpc_schemas() {
        let ecs_json = serde_json::json!({
            "Tags": { "Tag": [
                { "TagKey": "cua-managed", "TagValue": "true" },
                { "TagKey": "cua-owner", "TagValue": "me" }
            ]}
        });
        let vpc_json = serde_json::json!({
            "Tags": { "Tag": [
                { "Key": "cua-managed", "Value": "true" },
                { "Key": "cua-owner", "Value": "me" }
            ]}
        });
        assert_eq!(tags_of(&ecs_json), tags_of(&vpc_json));
        assert!(model::is_ours(&tags_of(&vpc_json), "me"));
    }

    #[test]
    fn network_config_and_types() {
        let cfg = NetworkConfig::from_connection(&Connection::default()).unwrap();
        assert_eq!(cfg.mode, NetworkMode::Isolated);
        assert_eq!(cfg.public_ip_mbps, DEFAULT_PUBLIC_BANDWIDTH_MBPS);
        assert!(is_network_type("vpc"));
        assert!(is_network_type("vswitch"));
        assert!(is_network_type("subnet"));
        assert!(is_network_type("security_group"));
        assert!(!is_network_type("instance"));
    }
}
