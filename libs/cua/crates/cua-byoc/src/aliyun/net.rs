// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Networking facade for Alibaba Cloud ECS (`--on aliyun-ecs`), coordinating
//! [`super::vpc`], [`super::security_group`], [`super::zones`], and
//! [`super::existing_vpc`].
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

use cua_sandbox_core::Error;
use serde_json::Value;

use super::AliyunEcs;
use super::client::{
    ApiBody, ECS_API_VERSION, VPC_API_VERSION, api_error_code_message, map_api_error,
};
use super::existing_vpc;
use super::security_group::{describe_security_group, ensure_security_group, list_security_groups};
use super::vpc::{
    describe_vpc, describe_vswitch, ensure_vpc, has_vpc_children, list_vpcs, list_vswitches,
};
use super::zones::discover_zones_with_stock;
use crate::api::Result;
use crate::model::{self, Connection, Resource, tag};

pub use super::security_group::sg_name;
pub(crate) use super::vpc::cidrs_overlap;
pub use super::vpc::{
    MAX_ZONES, VPC_CIDR, ensure_vswitch_for_zone, vpc_name, vswitch_cidr, vswitch_name,
};
pub use super::zones::discover_zones;

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
    match r.resource_type.as_str() {
        "vpc" => describe_vpc(api, conn, region, &r.id).await,
        "vswitch" | "subnet" => describe_vswitch(api, conn, region, &r.id).await,
        "security_group" => describe_security_group(api, conn, region, &r.id).await,
        _ => Ok(None),
    }
}

/// Lists all Cua-owned network parts (`security_group`, `vswitch`, `vpc`) in
/// `conn.region`, verifying [`model::is_ours`] on every returned row.
pub async fn list_parts(api: &AliyunEcs, conn: &Connection, owner: &str) -> Result<Vec<Resource>> {
    let mut out = list_security_groups(api, conn, owner).await?;
    out.extend(list_vswitches(api, conn, owner).await?);
    out.extend(list_vpcs(api, conn, owner).await?);
    Ok(out)
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
    r.resource_type == "vpc" && has_vpc_children(api, region, &r.id, profile_hint).await
}

/// Deletes one network part (`security_group`, `vswitch`/`subnet`, `vpc`),
/// verifying Cua ownership once before issuing the delete, retrying transient
/// dependency violations while failing fast on active blockers, and treating
/// `NotFound` as `Ok(())`.
pub async fn delete_part(api: &AliyunEcs, conn: &Connection, r: &Resource) -> Result<()> {
    delete_part_owned(api, conn, r, None).await
}

pub(crate) async fn delete_part_owned(
    api: &AliyunEcs,
    conn: &Connection,
    r: &Resource,
    expected_owner: Option<&str>,
) -> Result<()> {
    existing_vpc::guard_user_network_untouched(conn, r)?;
    if r.id.is_empty() {
        return Ok(());
    }
    if is_network_type(&r.resource_type) {
        let Some((_, tags)) = describe_part(api, conn, r).await? else {
            return Ok(());
        };
        match expected_owner {
            Some(owner) => {
                if !model::is_ours(&tags, owner) {
                    return Err(Error::Cloud(format!(
                        "aliyun-ecs: refusing to delete {} {} (it does not carry {}=true and {}={})",
                        r.resource_type,
                        r.id,
                        tag::MANAGED,
                        tag::OWNER,
                        model::label_value(owner)
                    )));
                }
            }
            None => {
                let is_cua_tagged = tags.get(tag::MANAGED).map(String::as_str) == Some("true")
                    && tags.get(tag::OWNER).is_some_and(|o| !o.is_empty());
                if !is_cua_tagged {
                    return Err(Error::Cloud(format!(
                        "aliyun-ecs: refusing to delete non-Cua-owned {} {}",
                        r.resource_type, r.id
                    )));
                }
            }
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
/// failed `provision()`, ordered by [`Resource::delete_rank`].
pub async fn rollback_made(api: &AliyunEcs, conn: &Connection, made: &[Resource]) {
    let mut ordered: Vec<&Resource> = made.iter().collect();
    ordered.sort_by_key(|r| r.delete_rank());
    for r in ordered {
        let owner = r.tags.get(tag::OWNER).map(String::as_str);
        let _ = delete_part_owned(api, conn, r, owner).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConnectionExtras;

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
            extras: ConnectionExtras {
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                no_public_ip: true,
                ..Default::default()
            },
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
            extras: ConnectionExtras {
                no_public_ip: true,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        assert_eq!(standalone_no_pub.mode, NetworkMode::Isolated);
        assert_eq!(standalone_no_pub.public_ip_mbps, 0);

        assert!(
            NetworkConfig::from_connection(&Connection {
                extras: ConnectionExtras {
                    vpc_id: Some("vpc-only".into()),
                    ..Default::default()
                },
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
