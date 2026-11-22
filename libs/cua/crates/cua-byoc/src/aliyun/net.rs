// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Isolated VPC, VSwitch, and zero-ingress Security Group management for
//! Alibaba Cloud ECS (`--on aliyun-ecs`).
//!
//! One VPC per cua home and region (`cua-sb-<owner>`, `10.77.0.0/16`):
//! - one `/20` VSwitch per availability zone (`cua-sb-<owner>-<zone>`,
//!   `10.77.<16*k>.0/20`, skipping any CIDRs already in use in the VPC);
//! - one zero-ingress enterprise Security Group (`cua-sandboxes-<owner>`) with
//!   explicit outbound-only internet egress (`0.0.0.0/0`, `all`, `-1/-1`,
//!   `accept`, priority `1`) and no inbound or intra-group lateral traffic;
//! - every part carries all 6 Cua tags at creation time (`cua-machine=""`);
//! - existing account VPCs, default VPCs, VSwitches, and Security Groups
//!   without Cua's tags are never modified or deleted.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use cua_sandbox_core::Error;
use serde_json::Value;

use super::AliyunEcs;
use super::client::VPC_API_VERSION;
use super::existing_vpc;
use super::net_zones::{discover_zones_with_stock, ensure_security_group};
use crate::api::Result;
use crate::model::{self, Connection, Resource, tag};

pub use super::net_lifecycle::{delete_part, describe_part, list_parts, rollback_made};
pub use super::net_zones::discover_zones;

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
    /// User-supplied existing VPC and VSwitch (`--vpc-id`, `--vswitch-id`).
    Existing { vpc_id: String, vswitch_id: String },
}

/// Resolved networking parameters for provisioning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Isolated Cua VPC vs user-supplied VPC/VSwitch.
    pub mode: NetworkMode,
    /// `> 0` => `PayByTraffic` public IPv4 with `InternetMaxBandwidthOut`;
    /// `0` => no public IPv4.
    pub public_ip_mbps: u32,
}

impl NetworkConfig {
    /// Derives the network configuration from `conn`.
    pub fn from_connection(conn: &Connection) -> Result<Self> {
        let mode = match existing_vpc::normalize_existing_vpc(
            conn.vpc_id.as_deref(),
            conn.vswitch_id.as_deref(),
        )? {
            Some((vpc_id, vswitch_id)) => NetworkMode::Existing { vpc_id, vswitch_id },
            None => NetworkMode::Isolated,
        };
        let public_ip_mbps = if conn.no_public_ip {
            0
        } else {
            DEFAULT_PUBLIC_BANDWIDTH_MBPS
        };
        Ok(Self {
            mode,
            public_ip_mbps,
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

/// Whether `resource_type` is a network resource managed by `aliyun::net`.
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

pub(crate) fn net_resource(
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

#[allow(clippy::too_many_arguments)]
async fn wait_vpc_resource_available(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    action: &str,
    id_param: &str,
    id: &str,
    (outer_key, inner_key): (&str, &str),
    label: &str,
) -> Result<()> {
    let profile_hint = api.profile_hint(conn);
    let vpc_ep = api.vpc_endpoint(region);
    for _ in 0..60 {
        let v = api
            .call_ok(
                &vpc_ep,
                "GET",
                action,
                VPC_API_VERSION,
                &[
                    ("RegionId".into(), region.to_string()),
                    (id_param.into(), id.to_string()),
                ],
                profile_hint,
            )
            .await?;
        if let Some(obj) = v[outer_key][inner_key].as_array().and_then(|a| a.first()) {
            let status = obj["Status"].as_str().unwrap_or("Available");
            if status.eq_ignore_ascii_case("Available") {
                return Ok(());
            }
        }
        tokio::time::sleep(api.poll_interval()).await;
    }
    Err(Error::Timeout(format!(
        "aliyun-ecs: {label} {id} did not become Available in {region}"
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

async fn ensure_vpc(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
) -> Result<(String, Option<Resource>)> {
    if let Some(id) = find_vpc(api, conn, region, owner).await? {
        wait_vpc_resource_available(
            api,
            conn,
            region,
            "DescribeVpcs",
            "VpcId",
            &id,
            ("Vpcs", "Vpc"),
            "VPC",
        )
        .await?;
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

    if let Err(e) = wait_vpc_resource_available(
        api,
        conn,
        region,
        "DescribeVpcs",
        "VpcId",
        &id,
        ("Vpcs", "Vpc"),
        "VPC",
    )
    .await
    {
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
        wait_vpc_resource_available(
            api,
            conn,
            region,
            "DescribeVpcs",
            "VpcId",
            &winner,
            ("Vpcs", "Vpc"),
            "VPC",
        )
        .await?;
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
    prepare_network_with_stock(api, conn, region, owner, instance_type, cfg, locks, None).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_network_with_stock(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    owner: &str,
    instance_type: &str,
    cfg: &NetworkConfig,
    locks: &NetLocks,
    precomputed_stock_zones: Option<&[String]>,
) -> Result<PreparedNetwork> {
    let mut made = Vec::new();
    let (vpc_id, candidates) = match &cfg.mode {
        NetworkMode::Isolated => {
            let _guard = locks.net_lock.lock().await;
            let (vpc_id, vpc_made) = ensure_vpc(api, conn, region, owner).await?;
            if let Some(r) = vpc_made {
                made.push(r);
            }
            let zones = match discover_zones_with_stock(
                api,
                conn,
                region,
                instance_type,
                precomputed_stock_zones,
            )
            .await
            {
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
        NetworkMode::Existing { vpc_id, vswitch_id } => {
            let profile_hint = api.profile_hint(conn);
            let info =
                existing_vpc::validate_existing_vpc(api, region, vpc_id, vswitch_id, profile_hint)
                    .await?;
            let candidates = vec![ZoneCandidate {
                zone_id: info.zone_id,
                vswitch_id: Some(vswitch_id.clone()),
            }];
            (vpc_id.clone(), candidates)
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
        wait_vpc_resource_available(
            api,
            conn,
            region,
            "DescribeVSwitches",
            "VSwitchId",
            id,
            ("VSwitches", "VSwitch"),
            "VSwitch",
        )
        .await?;
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

    if let Err(e) = wait_vpc_resource_available(
        api,
        conn,
        region,
        "DescribeVSwitches",
        "VSwitchId",
        &id,
        ("VSwitches", "VSwitch"),
        "VSwitch",
    )
    .await
    {
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

        let existing_cfg = NetworkConfig::from_connection(&Connection {
            vpc_id: Some("vpc-user-1".into()),
            vswitch_id: Some("vsw-user-1".into()),
            no_public_ip: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            existing_cfg.mode,
            NetworkMode::Existing {
                vpc_id: "vpc-user-1".into(),
                vswitch_id: "vsw-user-1".into(),
            }
        );
        assert_eq!(existing_cfg.public_ip_mbps, 0);

        let standalone_no_pub = NetworkConfig::from_connection(&Connection {
            no_public_ip: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(standalone_no_pub.mode, NetworkMode::Isolated);
        assert_eq!(standalone_no_pub.public_ip_mbps, 0);

        assert!(
            NetworkConfig::from_connection(&Connection {
                vpc_id: Some("vpc-only".into()),
                ..Default::default()
            })
            .is_err()
        );

        assert!(is_network_type("vpc"));
        assert!(is_network_type("vswitch"));
        assert!(is_network_type("subnet"));
        assert!(is_network_type("security_group"));
        assert!(!is_network_type("instance"));
    }
}
