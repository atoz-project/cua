// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Catalog (available resources, instance types, images) and network (VPC, VSwitch,
//! SecurityGroup) OpenAPI V3 handlers for [`FakeAliyun`].

use std::collections::BTreeMap;

use axum::response::Response;
use serde_json::{Value, json};

use super::handlers::{
    Params, bad_req, check_cua_tag, check_transient_dep, dry_run_ok, is_dry_run, not_found, ok,
    p_or, p_str, paged_ok,
};
use super::sig::{cidrs_overlap, matches_glob, parse_tags};
use super::state::{FakeAliyun, FakeInstance, FakeSg, FakeVSwitch, FakeVpc, merge_extra};

fn matches_region_and_tags(
    region: &str,
    tags: &BTreeMap<String, String>,
    params: &Params,
    tag_filters: &Params,
) -> bool {
    (region.is_empty() || params.get("RegionId").is_none_or(|r| region == r))
        && tag_filters.iter().all(|(k, v)| tags.get(k) == Some(v))
}

pub(crate) fn handle_describe_available(f: &FakeAliyun, params: &Params) -> Response {
    let azs: Vec<Value> = if let Some(ref custom) = f.available_zones_override {
        let zf = params.get("ZoneId").map(String::as_str);
        custom
            .iter()
            .filter(|z| zf.is_none_or(|w| z["ZoneId"].as_str() == Some(w)))
            .cloned()
            .collect()
    } else {
        let region = p_or(params, "RegionId", "cn-hangzhou");
        let types: Vec<&str> = match &f.available_instance_types {
            Some(list) => list.iter().map(String::as_str).collect(),
            None => f.instance_types.iter().map(|t| t.id.as_str()).collect(),
        };
        f.effective_zones(&region)
            .into_iter()
            .map(|z| {
                let sold_out = f.zone_faults.get(&z).is_some_and(|zf| zf.is_sold_out());
                let (st, cat) = if sold_out {
                    ("WithoutStock", "WithoutStock")
                } else {
                    ("Available", "WithStock")
                };
                let supported: Vec<Value> = types
                    .iter()
                    .map(|t| json!({ "Value": t, "Status": st, "StatusCategory": cat }))
                    .collect();
                json!({
                    "RegionId": region, "ZoneId": z, "Status": "Available",
                    "AvailableResources": { "AvailableResource": [{
                        "Type": "InstanceType",
                        "SupportedResources": { "SupportedResource": supported }
                    }]}
                })
            })
            .collect()
    };
    ok(json!({ "AvailableZones": { "AvailableZone": azs }, "RequestId": "req-avail-1" }))
}

pub(crate) fn handle_describe_instance_types(f: &FakeAliyun, params: &Params) -> Response {
    let repeat: Vec<String> = (1..=10)
        .filter_map(|i| params.get(&format!("InstanceTypes.{i}")).cloned())
        .collect();
    let requested = if f.ignore_instance_types_filter {
        None
    } else if !repeat.is_empty() {
        Some(repeat)
    } else {
        params
            .get("InstanceTypes")
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .or_else(|| params.get("InstanceType").map(|id| vec![id.clone()]))
    };
    let items: Vec<Value> = f
        .instance_types
        .iter()
        .filter(|t| requested.as_ref().is_none_or(|r| r.iter().any(|x| x == &t.id)))
        .map(|t| {
            let mut item = json!({
                "InstanceTypeId": t.id, "CpuCoreCount": t.cpu_core_count, "MemorySize": t.memory_size_gb
            });
            merge_extra(&mut item, f.instance_type_details.get(&t.id));
            item
        })
        .collect();
    let offset: usize = params
        .get("NextToken")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (page, next) = match f.instance_types_page_size {
        Some(ps) if ps > 0 => {
            let end = offset.saturating_add(ps).min(items.len());
            let next = if end < items.len() {
                end.to_string()
            } else {
                String::new()
            };
            (items.get(offset..end).unwrap_or(&[]).to_vec(), next)
        }
        _ => (items, String::new()),
    };
    ok(
        json!({ "InstanceTypes": { "InstanceType": page }, "NextToken": next, "RequestId": "req-inst-types-1" }),
    )
}

pub(crate) fn handle_describe_images(f: &FakeAliyun, params: &Params) -> Response {
    let mut items: Vec<Value> = f
        .images
        .iter()
        .filter(|img| {
            (img.region_id.is_empty() || params.get("RegionId").is_none_or(|r| &img.region_id == r))
                && params
                    .get("ImageId")
                    .is_none_or(|id| id.split(',').any(|x| x.trim() == img.image_id))
                && params
                    .get("ImageName")
                    .is_none_or(|pat| matches_glob(pat, &img.image_name))
                && params
                    .get("OSType")
                    .is_none_or(|os| img.os_type.eq_ignore_ascii_case(os))
                && params
                    .get("ImageOwnerAlias")
                    .is_none_or(|o| img.owner_alias.eq_ignore_ascii_case(o))
                && params
                    .get("Status")
                    .is_none_or(|st| img.status.eq_ignore_ascii_case(st))
        })
        .map(super::state::FakeImage::to_api_json)
        .collect();
    let total = items.len();
    if let Some(ps) = params.get("PageSize").and_then(|s| s.parse().ok()) {
        items.truncate(ps);
    }
    ok(json!({ "Images": { "Image": items }, "TotalCount": total, "RequestId": "req-images-1" }))
}

fn instance_uses_sg(inst: &FakeInstance, sg_id: &str) -> bool {
    inst.security_group_id == sg_id || inst.extra_security_group_ids.iter().any(|x| x == sg_id)
}

pub(crate) fn handle_sg(f: &mut FakeAliyun, action: &str, params: &Params) -> Response {
    match action {
        "CreateSecurityGroup" => {
            // Alibaba Cloud ECS `CreateSecurityGroup` ignores `DryRun=true` and creates the SG.
            let tags = parse_tags(params);
            if let Some(r) = check_cua_tag(f, &tags, "ecs:CreateSecurityGroup") {
                return r;
            }
            if let Some(id) = params
                .get("ClientToken")
                .and_then(|ct| f.client_tokens.get(ct))
            {
                return ok(json!({ "SecurityGroupId": id, "RequestId": "req-csg-idempotent" }));
            }
            let id = format!("sg-fake-{}", f.next_seq());
            let sg_type = p_or(params, "SecurityGroupType", "normal");
            let inner = if sg_type == "enterprise" {
                "Drop"
            } else {
                "Accept"
            };
            f.security_groups.insert(
                id.clone(),
                FakeSg {
                    sg_id: id.clone(),
                    vpc_id: p_str(params, "VpcId"),
                    region_id: p_or(params, "RegionId", "cn-hangzhou"),
                    sg_name: p_str(params, "SecurityGroupName"),
                    sg_type,
                    inner_access_policy: inner.into(),
                    tags,
                    ..Default::default()
                },
            );
            if let Some(ct) = params.get("ClientToken") {
                f.client_tokens.insert(ct.clone(), id.clone());
            }
            f.security_group_rules.insert(id.clone(), Vec::new());
            ok(json!({ "SecurityGroupId": id, "RequestId": "req-csg-1" }))
        }
        "DescribeSecurityGroups" => {
            let tf = parse_tags(params);
            let sgs: Vec<Value> = f
                .security_groups
                .values()
                .filter(|sg| {
                    params.get("VpcId").is_none_or(|v| &sg.vpc_id == v)
                        && params
                            .get("SecurityGroupId")
                            .is_none_or(|id| &sg.sg_id == id)
                        && matches_region_and_tags(&sg.region_id, &sg.tags, params, &tf)
                })
                .map(FakeSg::to_api_json)
                .collect();
            paged_ok("SecurityGroups", "SecurityGroup", sgs, params, "req-sg-1")
        }
        "DescribeSecurityGroupAttribute" => {
            let sg_id = p_str(params, "SecurityGroupId");
            let Some(sg) = f.security_groups.get(&sg_id).cloned() else {
                return not_found(
                    "InvalidSecurityGroupId.NotFound",
                    "SecurityGroup not found.",
                );
            };
            let mut rules = f
                .security_group_rules
                .get(&sg_id)
                .cloned()
                .unwrap_or_default();
            for r in &sg.ingress_rules {
                let mut rule = r.clone();
                if let Some(obj) = rule.as_object_mut() {
                    obj.entry("Direction").or_insert_with(|| json!("ingress"));
                    obj.entry("Policy").or_insert_with(|| json!("Accept"));
                }
                rules.push(rule);
            }
            if let Some(dir) = params
                .get("Direction")
                .map(String::as_str)
                .filter(|d| !d.is_empty() && !d.eq_ignore_ascii_case("all"))
            {
                rules.retain(|r| {
                    r["Direction"]
                        .as_str()
                        .is_some_and(|x| x.eq_ignore_ascii_case(dir))
                });
            }
            let inner = if sg.inner_access_policy.is_empty() {
                "Drop"
            } else {
                sg.inner_access_policy.as_str()
            };
            ok(json!({
                "SecurityGroupId": sg_id, "VpcId": sg.vpc_id, "RegionId": sg.region_id,
                "InnerAccessPolicy": inner, "Permissions": { "Permission": rules }, "RequestId": "req-sga-1"
            }))
        }
        "AuthorizeSecurityGroupEgress" => {
            let sg_id = p_str(params, "SecurityGroupId");
            let Some(sg) = f.security_groups.get(&sg_id).cloned() else {
                return not_found(
                    "InvalidSecurityGroupId.NotFound",
                    "SecurityGroup not found.",
                );
            };
            if let Some(r) = check_cua_tag(f, &sg.tags, "ecs:AuthorizeSecurityGroupEgress") {
                return r;
            }
            let get = |p1, flat, def: &str| {
                params
                    .get(p1)
                    .or_else(|| params.get(flat))
                    .cloned()
                    .unwrap_or_else(|| def.into())
            };
            f.security_group_rules
                .entry(sg_id)
                .or_default()
                .push(json!({
                    "Direction": "egress",
                    "IpProtocol": get("Permissions.1.IpProtocol", "IpProtocol", ""),
                    "PortRange": get("Permissions.1.PortRange", "PortRange", ""),
                    "DestCidrIp": get("Permissions.1.DestCidrIp", "DestCidrIp", ""),
                    "Policy": get("Permissions.1.Policy", "Policy", "Accept"),
                    "Priority": get("Permissions.1.Priority", "Priority", "1"),
                }));
            ok(json!({ "RequestId": "req-asge-1" }))
        }
        "AuthorizeSecurityGroup" => {
            f.authorize_sg_calls += 1;
            ok(json!({ "RequestId": "req-asg-1" }))
        }
        "DeleteSecurityGroup" => {
            if let Some(r) = check_transient_dep(f, "Security group has dependent resources.") {
                return r;
            }
            let id = p_str(params, "SecurityGroupId");
            let Some(sg) = f.security_groups.get(&id).cloned() else {
                return not_found(
                    "InvalidSecurityGroupId.NotFound",
                    "SecurityGroup not found.",
                );
            };
            if let Some(r) = check_cua_tag(f, &sg.tags, "ecs:DeleteSecurityGroup") {
                return r;
            }
            if f.instances.values().any(|i| instance_uses_sg(i, &id)) {
                return bad_req(
                    "DependencyViolation",
                    "SecurityGroup is in use by an instance.",
                );
            }
            f.security_groups.remove(&id);
            f.security_group_rules.remove(&id);
            ok(json!({ "RequestId": "req-dsg-1" }))
        }
        _ => unreachable!(),
    }
}

pub(crate) fn handle_vpc(f: &mut FakeAliyun, action: &str, params: &Params) -> Response {
    match action {
        "CreateVpc" => {
            let tags = parse_tags(params);
            if let Some(r) = check_cua_tag(f, &tags, "vpc:CreateVpc") {
                return r;
            }
            if is_dry_run(params) {
                return dry_run_ok();
            }
            if let Some(id) = params
                .get("ClientToken")
                .and_then(|ct| f.client_tokens.get(ct))
            {
                return ok(json!({ "VpcId": id, "RequestId": "req-cvpc-idempotent" }));
            }
            let id = format!("vpc-fake-{}", f.next_seq());
            f.vpcs.insert(
                id.clone(),
                FakeVpc {
                    vpc_id: id.clone(),
                    region_id: p_or(params, "RegionId", "cn-hangzhou"),
                    cidr_block: p_or(params, "CidrBlock", "10.77.0.0/16"),
                    vpc_name: p_str(params, "VpcName"),
                    tags,
                    ..Default::default()
                },
            );
            if let Some(ct) = params.get("ClientToken") {
                f.client_tokens.insert(ct.clone(), id.clone());
            }
            ok(json!({ "VpcId": id, "RequestId": "req-cvpc-1" }))
        }
        "DescribeVpcs" => {
            let tf = parse_tags(params);
            let items: Vec<Value> = f
                .vpcs
                .values()
                .filter(|v| {
                    params
                        .get("VpcId")
                        .is_none_or(|id| id.split(',').any(|x| x.trim() == v.vpc_id))
                        && matches_region_and_tags(&v.region_id, &v.tags, params, &tf)
                })
                .map(FakeVpc::to_api_json)
                .collect();
            paged_ok("Vpcs", "Vpc", items, params, "req-vpc-1")
        }
        "DeleteVpc" => {
            if let Some(r) = check_transient_dep(f, "VPC has dependent resources.") {
                return r;
            }
            let id = p_str(params, "VpcId");
            let Some(vpc) = f.vpcs.get(&id).cloned() else {
                return not_found("InvalidVpcId.NotFound", "VPC not found.");
            };
            if let Some(r) = check_cua_tag(f, &vpc.tags, "vpc:DeleteVpc") {
                return r;
            }
            if f.vswitches.values().any(|v| v.vpc_id == id)
                || f.security_groups.values().any(|s| s.vpc_id == id)
            {
                return bad_req("DependencyViolation", "VPC has dependent resources.");
            }
            if vpc.is_default {
                return bad_req("Forbidden.DefaultVpc", "Cannot delete default VPC.");
            }
            f.vpcs.remove(&id);
            ok(json!({ "RequestId": "req-dvpc-1" }))
        }
        _ => unreachable!(),
    }
}

pub(crate) fn handle_vswitch(f: &mut FakeAliyun, action: &str, params: &Params) -> Response {
    match action {
        "CreateVSwitch" => {
            let tags = parse_tags(params);
            if let Some(r) = check_cua_tag(f, &tags, "vpc:CreateVSwitch") {
                return r;
            }
            if is_dry_run(params) {
                return dry_run_ok();
            }
            if let Some(id) = params
                .get("ClientToken")
                .and_then(|ct| f.client_tokens.get(ct))
            {
                return ok(json!({ "VSwitchId": id, "RequestId": "req-cvsw-idempotent" }));
            }
            let vpc_id = p_str(params, "VpcId");
            let cidr = p_or(params, "CidrBlock", "172.16.1.0/24");
            if f.vswitches
                .values()
                .any(|v| v.vpc_id == vpc_id && cidrs_overlap(&v.cidr_block, &cidr))
            {
                return bad_req(
                    "InvalidCidrBlock.Overlapping",
                    "VSwitch CIDR overlaps an existing VSwitch.",
                );
            }
            let id = format!("vsw-fake-{}", f.next_seq());
            let region = p_or(params, "RegionId", "cn-hangzhou");
            f.vswitches.insert(
                id.clone(),
                FakeVSwitch {
                    vswitch_id: id.clone(),
                    vpc_id,
                    zone_id: params
                        .get("ZoneId")
                        .cloned()
                        .unwrap_or_else(|| format!("{region}-h")),
                    region_id: region,
                    cidr_block: cidr,
                    vswitch_name: p_str(params, "VSwitchName"),
                    tags,
                    ..Default::default()
                },
            );
            if let Some(ct) = params.get("ClientToken") {
                f.client_tokens.insert(ct.clone(), id.clone());
            }
            ok(json!({ "VSwitchId": id, "RequestId": "req-cvsw-1" }))
        }
        "DescribeVSwitches" => {
            let tf = parse_tags(params);
            let items: Vec<Value> = f
                .vswitches
                .values()
                .filter(|v| {
                    params.get("VSwitchId").is_none_or(|id| &v.vswitch_id == id)
                        && params.get("VpcId").is_none_or(|vpc| &v.vpc_id == vpc)
                        && params.get("ZoneId").is_none_or(|z| &v.zone_id == z)
                        && matches_region_and_tags(&v.region_id, &v.tags, params, &tf)
                })
                .map(FakeVSwitch::to_api_json)
                .collect();
            paged_ok("VSwitches", "VSwitch", items, params, "req-vsw-1")
        }
        "DeleteVSwitch" => {
            if let Some(r) =
                check_transient_dep(f, "VSwitch has active instances or deleting ENIs.")
            {
                return r;
            }
            let id = p_str(params, "VSwitchId");
            let Some(vsw) = f.vswitches.get(&id).cloned() else {
                return not_found("InvalidVSwitchId.NotFound", "VSwitch not found.");
            };
            if let Some(r) = check_cua_tag(f, &vsw.tags, "vpc:DeleteVSwitch") {
                return r;
            }
            if f.instances.values().any(|i| i.vswitch_id == id) {
                return bad_req("DependencyViolation", "VSwitch is in use by an instance.");
            }
            f.vswitches.remove(&id);
            ok(json!({ "RequestId": "req-dvsw-1" }))
        }
        _ => unreachable!(),
    }
}
