// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Existing VPC / VSwitch attachment and private-only (`--no-public-ip`)
//! validation and safety guards for `aliyun-ecs`.
//!
//! Keeps user-owned VPCs, VSwitches, and security groups untouched while
//! validating existence/region/ownership and ensuring [`super::net`] manages
//! only a dedicated Cua-tagged zero-ingress security group
//! (`cua-sandboxes-<owner>`).

use cua_sandbox_core::Error;

use super::AliyunEcs;
use super::client::VPC_API_VERSION;
use crate::api::Result;
use crate::model::{Connection, Resource};

/// Validated metadata for an existing user VPC and VSwitch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingVpcInfo {
    pub vpc_id: String,
    pub vswitch_id: String,
    pub zone_id: String,
}

/// Validates and normalizes `(--vpc-id, --vswitch-id)`.
///
/// Both must be specified together (or both omitted), and neither may be empty
/// or whitespace. `--no-public-ip` is orthogonal and valid in both isolated
/// and existing-VPC modes.
pub fn normalize_existing_vpc(
    vpc_id: Option<&str>,
    vswitch_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    match (vpc_id, vswitch_id) {
        (None, None) => Ok(None),
        (Some(vpc), None) => {
            if vpc.trim().is_empty() {
                return Err(Error::InvalidArgument(
                    "aliyun-ecs: --vpc-id cannot be empty".into(),
                ));
            }
            Err(Error::InvalidArgument(
                "aliyun-ecs: --vpc-id requires --vswitch-id (pass both --vpc-id and --vswitch-id together)"
                    .into(),
            ))
        }
        (None, Some(vsw)) => {
            if vsw.trim().is_empty() {
                return Err(Error::InvalidArgument(
                    "aliyun-ecs: --vswitch-id cannot be empty".into(),
                ));
            }
            Err(Error::InvalidArgument(
                "aliyun-ecs: --vswitch-id requires --vpc-id (pass both --vpc-id and --vswitch-id together)"
                    .into(),
            ))
        }
        (Some(vpc), Some(vsw)) => {
            let vpc = vpc.trim();
            let vsw = vsw.trim();
            if vpc.is_empty() {
                return Err(Error::InvalidArgument(
                    "aliyun-ecs: --vpc-id cannot be empty".into(),
                ));
            }
            if vsw.is_empty() {
                return Err(Error::InvalidArgument(
                    "aliyun-ecs: --vswitch-id cannot be empty".into(),
                ));
            }
            Ok(Some((vpc.to_string(), vsw.to_string())))
        }
    }
}

/// Read-only preflight validation of an existing VPC and VSwitch in `region`.
/// Creates NO VPC, VSwitch, or security group.
pub async fn validate_existing_vpc(
    ecs: &AliyunEcs,
    region: &str,
    vpc_id: &str,
    vswitch_id: &str,
    profile_hint: Option<&str>,
) -> Result<ExistingVpcInfo> {
    let vpc_ep = ecs.vpc_endpoint(region);
    let vpcs = ecs
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

    let vpc_obj = vpcs["Vpcs"]["Vpc"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|v| v["VpcId"].as_str() == Some(vpc_id))
        .ok_or_else(|| {
            Error::Cloud(format!(
                "aliyun-ecs: VPC {vpc_id} was not found in region {region}"
            ))
        })?;

    if let Some(actual_reg) = vpc_obj["RegionId"].as_str().filter(|s| !s.is_empty())
        && actual_reg != region
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: VPC {vpc_id} belongs to region {actual_reg}, not {region}"
        )));
    }
    if let Some(status) = vpc_obj["Status"].as_str().filter(|s| !s.is_empty())
        && status != "Available"
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: VPC {vpc_id} is not Available (status: {status})"
        )));
    }

    let vsws = ecs
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

    let vsw_obj = vsws["VSwitches"]["VSwitch"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|v| v["VSwitchId"].as_str() == Some(vswitch_id))
        .ok_or_else(|| {
            Error::Cloud(format!(
                "aliyun-ecs: VSwitch {vswitch_id} was not found in region {region}"
            ))
        })?;

    if let Some(actual_reg) = vsw_obj["RegionId"].as_str().filter(|s| !s.is_empty())
        && actual_reg != region
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: VSwitch {vswitch_id} belongs to region {actual_reg}, not {region}"
        )));
    }
    let actual_vpc = vsw_obj["VpcId"].as_str().unwrap_or("");
    if actual_vpc != vpc_id {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: VSwitch {vswitch_id} belongs to VPC {actual_vpc:?}, not {vpc_id}"
        )));
    }
    if let Some(status) = vsw_obj["Status"].as_str().filter(|s| !s.is_empty())
        && status != "Available"
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: VSwitch {vswitch_id} is not Available (status: {status})"
        )));
    }
    if let Some(avail_ips) = vsw_obj["AvailableIpAddressCount"].as_u64()
        && avail_ips == 0
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: VSwitch {vswitch_id} has 0 available IP addresses"
        )));
    }

    Ok(ExistingVpcInfo {
        vpc_id: vpc_id.to_string(),
        vswitch_id: vswitch_id.to_string(),
        zone_id: vsw_obj["ZoneId"].as_str().unwrap_or("").to_string(),
    })
}

/// Returns `true` when `conn` uses an existing user VPC/VSwitch, in which case
/// user-owned VPCs and VSwitches must never be listed, modified, or deleted.
pub fn is_existing_vpc_connection(conn: &Connection) -> bool {
    conn.vpc_id.is_some() || conn.vswitch_id.is_some()
}

/// Refuses deleting a user-owned VPC or VSwitch even if somehow passed or tagged.
pub fn guard_user_network_untouched(conn: &Connection, r: &Resource) -> Result<()> {
    if matches!(r.resource_type.as_str(), "vpc" | "vswitch" | "subnet")
        && (conn.vpc_id.as_deref() == Some(r.id.as_str())
            || conn.vswitch_id.as_deref() == Some(r.id.as_str())
            || (is_existing_vpc_connection(conn)
                && !r.name.is_empty()
                && !r.name.starts_with("cua-sb-")))
    {
        return Err(Error::Cloud(format!(
            "aliyun-ecs: refusing to delete user-owned {} {}",
            r.resource_type, r.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_existing_vpc_enforces_pair_and_non_empty_ids() {
        assert_eq!(normalize_existing_vpc(None, None).unwrap(), None);
        assert_eq!(
            normalize_existing_vpc(Some(" vpc-1 "), Some(" vsw-1 ")).unwrap(),
            Some(("vpc-1".into(), "vsw-1".into()))
        );
        let err_missing_vpc = normalize_existing_vpc(None, Some("vsw-1")).unwrap_err();
        assert!(
            err_missing_vpc.to_string().contains("vpc-id"),
            "{err_missing_vpc}"
        );

        let err_missing_vsw = normalize_existing_vpc(Some("vpc-1"), None).unwrap_err();
        assert!(
            err_missing_vsw.to_string().contains("vswitch-id"),
            "{err_missing_vsw}"
        );

        assert!(normalize_existing_vpc(Some("  "), Some("vsw-1")).is_err());
        assert!(normalize_existing_vpc(Some("vpc-1"), Some("")).is_err());
    }

    #[test]
    fn guard_refuses_deleting_user_vpc_or_vswitch() {
        let conn = Connection {
            provider: "aliyun-ecs".into(),
            region: "cn-hangzhou".into(),
            extras: crate::model::ConnectionExtras {
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let vpc_res = Resource {
            provider: "aliyun-ecs".into(),
            id: "vpc-user-1".into(),
            resource_type: "vpc".into(),
            ..Default::default()
        };
        let vsw_res = Resource {
            provider: "aliyun-ecs".into(),
            id: "vsw-user-1".into(),
            resource_type: "vswitch".into(),
            ..Default::default()
        };
        assert!(guard_user_network_untouched(&conn, &vpc_res).is_err());
        assert!(guard_user_network_untouched(&conn, &vsw_res).is_err());
    }
}
