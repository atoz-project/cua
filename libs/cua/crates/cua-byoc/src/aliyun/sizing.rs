// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Alibaba Cloud ECS instance type catalog, disk sizing validation, and
//! dynamic `WithStock` X86 instance selector (returning both the selected SKU
//! and its in-stock availability zones for single-pass provisioning).

use std::collections::BTreeMap;

use cua_sandbox_core::Error;
use cua_sandbox_core::byoc::CloudKind;
use serde_json::Value;

use super::AliyunEcs;
use super::client::{ECS_API_VERSION, VPC_API_VERSION};
use crate::api::Result;
use crate::model::{self, Connection, ProvisionSpec};

/// Default baseline Linux Docker-on-VM instance type (2 vCPU, 4 GiB).
pub const LINUX_INSTANCE_TYPE: &str = "ecs.e-c1m2.large";
/// Default baseline Linux-slim instance type (2 vCPU, 2 GiB).
pub const SLIM_INSTANCE_TYPE: &str = "ecs.e-c1m1.large";
/// Default baseline Windows Direct VM instance type (4 vCPU, 8 GiB).
pub const WINDOWS_INSTANCE_TYPE: &str = "ecs.c7.xlarge";

/// Minimum ECS `cloud_essd` system disk size in GiB.
pub const MIN_DISK_GB: u32 = 20;
/// Maximum ECS `cloud_essd` system disk size in GiB.
pub const MAX_DISK_GB: u32 = 32_768;
/// Default Linux ECS system disk size in GiB (`cloud_essd`).
pub const LINUX_DEFAULT_DISK_GB: u32 = 40;
/// Default Windows Direct VM ECS system disk size in GiB (`cloud_essd`).
pub const WINDOWS_DEFAULT_DISK_GB: u32 = 60;
/// Estimated hourly USD cost per GiB of `cloud_essd` storage (~$0.10/GB/month).
pub const ESSD_USD_PER_GB_HOUR: f64 = 0.00014;

/// Built-in Alibaba Cloud ECS instance type specs: `(vcpus, memory_mb, usd_per_hour)`.
pub fn ecs_instance_spec(instance_type: &str) -> Option<(u32, u64, f64)> {
    match instance_type.trim() {
        "ecs.e-c1m1.large" => Some((2, 2048, 0.030)),
        "ecs.e-c1m2.large" => Some((2, 4096, 0.043)),
        "ecs.e-c1m2.xlarge" => Some((4, 8192, 0.086)),
        "ecs.e-c1m4.large" => Some((2, 8192, 0.056)),
        "ecs.c7.large" => Some((2, 4096, 0.063)),
        "ecs.c7.xlarge" => Some((4, 8192, 0.125)),
        "ecs.c7.2xlarge" => Some((8, 16384, 0.250)),
        "ecs.c7.4xlarge" => Some((16, 32768, 0.500)),
        "ecs.g7.large" => Some((2, 8192, 0.085)),
        "ecs.g7.xlarge" => Some((4, 16384, 0.170)),
        "ecs.g7.2xlarge" => Some((8, 32768, 0.340)),
        "ecs.g7.4xlarge" => Some((16, 65536, 0.680)),
        "ecs.r7.large" => Some((2, 16384, 0.110)),
        "ecs.r7.xlarge" => Some((4, 32768, 0.220)),
        "ecs.u1-c1m2.large" => Some((2, 4096, 0.048)),
        "ecs.u1-c1m2.xlarge" => Some((4, 8192, 0.096)),
        _ => None,
    }
}

/// Validates ECS `cloud_essd` system disk size bounds (`20..=32768` GiB).
pub fn validate_disk_gb(disk_gb: u32) -> Result<u32> {
    if !(MIN_DISK_GB..=MAX_DISK_GB).contains(&disk_gb) {
        return Err(Error::InvalidArgument(format!(
            "aliyun-ecs: disk size {disk_gb} GiB is out of range ({MIN_DISK_GB}..={MAX_DISK_GB} GiB for cloud_essd)"
        )));
    }
    Ok(disk_gb)
}

/// Resolves the ECS instance type for `spec`.
pub fn instance_type_for(spec: &ProvisionSpec) -> &str {
    let explicit = spec.machine_type.trim();
    if !explicit.is_empty() {
        return explicit;
    }
    default_instance_type_for(&spec.family)
}

pub(crate) fn default_instance_type_for(family: &str) -> &'static str {
    match family {
        "windows" => WINDOWS_INSTANCE_TYPE,
        "linux-slim" => SLIM_INSTANCE_TYPE,
        _ => LINUX_INSTANCE_TYPE,
    }
}

/// Resolves the `(size_gib, category)` system disk parameters for `spec`.
pub fn system_disk_for(spec: &ProvisionSpec) -> (u32, &'static str) {
    let min_gb = if spec.family == "windows" {
        WINDOWS_DEFAULT_DISK_GB
    } else {
        LINUX_DEFAULT_DISK_GB
    };
    (spec.disk_gb.max(min_gb), "cloud_essd")
}

pub(crate) fn is_with_stock_category(cat: Option<&str>) -> bool {
    match cat.map(str::trim) {
        None | Some("") => true, // Mock/fake-server compatibility when omitted
        Some(c) => c == "WithStock",
    }
}

pub(crate) fn target_compute_for(spec: &ProvisionSpec) -> (u32, u32) {
    match spec.family.as_str() {
        "windows" => {
            let vcpus = spec.cpus.unwrap_or(4).max(4);
            let mem_mb = spec.memory_mb.unwrap_or(8192).max(8192);
            let mem_gib = u32::try_from(mem_mb.div_ceil(1024))
                .unwrap_or(u32::MAX)
                .max(8);
            (vcpus, mem_gib)
        }
        "linux-slim" => {
            let raw_cpus = spec.cpus.unwrap_or(2);
            let raw_mem_mb = spec.memory_mb.unwrap_or(4096);
            if raw_cpus <= 2 && raw_mem_mb <= 4096 {
                (2, 2)
            } else {
                let vcpus = raw_cpus.max(2);
                let mem_gib = u32::try_from(raw_mem_mb.div_ceil(1024))
                    .unwrap_or(u32::MAX)
                    .max(2);
                (vcpus, mem_gib)
            }
        }
        _ => {
            let vcpus = spec.cpus.unwrap_or(2).max(2);
            let mem_mb = spec.memory_mb.unwrap_or(4096).max(4096);
            let mem_gib = u32::try_from(mem_mb.div_ceil(1024))
                .unwrap_or(u32::MAX)
                .max(4);
            (vcpus, mem_gib)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InstanceTypeMeta {
    pub vcpus: u32,
    pub memory_mb: u64,
    pub cpu_arch: Option<String>,
    pub gpu_amount: Option<u64>,
    pub usd_per_hour: f64,
}

/// Output of dynamic instance selection: chosen SKU, its specs/price, and the
/// sorted list of `WithStock` availability zones discovered in the same query.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedInstanceSelection {
    pub instance_type: String,
    pub vcpus: u32,
    pub memory_mb: u64,
    pub usd_per_hour: f64,
    pub stock_zones: Vec<String>,
}

fn instance_family_token(id: &str) -> String {
    let lower = id.trim().to_ascii_lowercase();
    let after_ecs = lower.strip_prefix("ecs.").unwrap_or(&lower);
    after_ecs.split('.').next().unwrap_or(after_ecs).to_string()
}

pub(crate) fn is_excluded_instance_family(
    id: &str,
    cpu_arch: Option<&str>,
    gpu_amount: Option<u64>,
) -> bool {
    if cpu_arch
        .map(str::trim)
        .is_some_and(|a| !a.is_empty() && !a.eq_ignore_ascii_case("x86"))
    {
        return true;
    }
    if gpu_amount.is_some_and(|g| g > 0) {
        return true;
    }
    let fam = instance_family_token(id);
    let base = fam.split('-').next().unwrap_or(&fam);
    if base.is_empty() {
        return true;
    }
    // Alibaba Cloud ARM families:
    // - Yitian / newer ARM families ending in `y` or `m` (c8y, g8y, r8y, c8m, g8m, r8m, av8m)
    // - Ampere Altra ARM families ending in `r` under c/g/r prefixes (c6r, g6r, r6r); preserves `i4r`.
    if (base.ends_with('y') || base.ends_with('m'))
        && base.len() >= 2
        && base[..base.len() - 1].bytes().any(|b| b.is_ascii_digit())
    {
        return true;
    }
    if (base.starts_with('c') || base.starts_with('g') || base.starts_with('r'))
        && base.ends_with('r')
        && base.len() >= 3
        && base[1..base.len() - 1].bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    // GPU / FPGA / video-transcoding / internal test families.
    if base.starts_with("gn")
        || base.starts_with("sgn")
        || base.starts_with("vgn")
        || base.starts_with("cgn")
        || base.starts_with("hfgn")
        || base.starts_with("ebmgn")
        || (base.starts_with("ga") && base[2..].starts_with(|c: char| c.is_ascii_digit()))
        || (base.starts_with("gp") && base[2..].starts_with(|c: char| c.is_ascii_digit()))
        || (base.starts_with('f') && base[1..].starts_with(|c: char| c.is_ascii_digit()))
        || fam.starts_with("video")
        || fam == "poc-test"
        || fam == "e-test"
    {
        return true;
    }
    // Bare-metal / supercomputing clusters (ebm*, scc*, scch*).
    if base.starts_with("ebm") || base.starts_with("scc") {
        return true;
    }
    false
}

/// Returns `(tier, sub_rank)` where lower is preferred:
/// - `0`: non-burstable mainstream families (`e-*`, `u*`, `c*`, `g*`, `hfc*`, `hfg*`, `sn*`, `n4*`)
/// - `1`: other non-burstable x86 families (`r*`, `ic*`)
/// - `2`: burstable families (`t5*`, `t6*`, `t7*`)
fn family_preference_tier(id: &str) -> (u8, u8) {
    let fam = instance_family_token(id);
    let base = fam.split('-').next().unwrap_or(&fam);
    if base.starts_with('t') && base[1..].starts_with(|c: char| c.is_ascii_digit()) {
        return (2, 0);
    }
    if fam.starts_with("e-") || base == "e" {
        return (0, 0);
    }
    if base.starts_with('u') {
        return (0, 1);
    }
    if base.starts_with('c') {
        return (0, 2);
    }
    if base.starts_with('g') {
        return (0, 3);
    }
    if base.starts_with("hfc")
        || base.starts_with("hfg")
        || base.starts_with("sn")
        || base.starts_with("n4")
    {
        return (0, 4);
    }
    (1, 0)
}

pub(crate) fn estimate_usd_per_hour(vcpus: u32, memory_mb: u64) -> f64 {
    let mem_gib = memory_mb as f64 / 1024.0;
    (f64::from(vcpus) * 0.025 + mem_gib * 0.005).max(0.01)
}

pub(crate) fn select_best_dynamic_candidate(
    family: &str,
    target_vcpus: u32,
    target_mem_mb: u64,
    max_size: Option<model::MaxSize>,
    candidates: &[(String, Vec<String>)],
    meta_map: &BTreeMap<String, InstanceTypeMeta>,
) -> Option<(String, InstanceTypeMeta, Vec<String>)> {
    #[derive(Eq, PartialEq, Ord, PartialOrd)]
    struct RankKey {
        cpu_excess: u32,
        mem_excess: u64,
        tier: (u8, u8),
        not_baseline: bool,
        price_micros: u64,
        id: String,
    }
    struct Ranked {
        key: RankKey,
        id: String,
        meta: InstanceTypeMeta,
        zones: Vec<String>,
    }

    let baseline = default_instance_type_for(family);
    let meta_populated = !meta_map.is_empty();
    let mut ranked: Vec<Ranked> = Vec::new();

    for (id, zones) in candidates {
        let meta = if let Some(m) = meta_map.get(id) {
            m.clone()
        } else if let Some((vcpus, memory_mb, usd)) = ecs_instance_spec(id) {
            InstanceTypeMeta {
                vcpus,
                memory_mb,
                cpu_arch: None,
                gpu_amount: None,
                usd_per_hour: usd,
            }
        } else if !meta_populated {
            InstanceTypeMeta {
                vcpus: target_vcpus,
                memory_mb: target_mem_mb,
                cpu_arch: None,
                gpu_amount: None,
                usd_per_hour: estimate_usd_per_hour(target_vcpus, target_mem_mb),
            }
        } else {
            continue;
        };

        if is_excluded_instance_family(id, meta.cpu_arch.as_deref(), meta.gpu_amount) {
            continue;
        }
        if meta.vcpus < target_vcpus || meta.memory_mb < target_mem_mb {
            continue;
        }
        if let Some(max) = max_size
            && !max.fits(meta.vcpus, meta.memory_mb)
        {
            continue;
        }

        let key = RankKey {
            cpu_excess: meta.vcpus - target_vcpus,
            mem_excess: meta.memory_mb - target_mem_mb,
            tier: family_preference_tier(id),
            not_baseline: id != baseline,
            price_micros: (meta.usd_per_hour * 1_000_000.0).round() as u64,
            id: id.clone(),
        };
        ranked.push(Ranked {
            key,
            id: id.clone(),
            meta,
            zones: zones.clone(),
        });
    }

    ranked.sort_by(|a, b| a.key.cmp(&b.key));
    ranked.into_iter().next().map(|r| (r.id, r.meta, r.zones))
}

fn collect_instance_type_metas(items: &[Value], out: &mut BTreeMap<String, InstanceTypeMeta>) {
    for item in items {
        let Some(id) = item["InstanceTypeId"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let Some(vcpus) = item["CpuCoreCount"]
            .as_u64()
            .and_then(|c| u32::try_from(c).ok())
            .filter(|&c| c > 0)
        else {
            continue;
        };
        let Some(mem_gib) = item["MemorySize"].as_f64().filter(|&m| m > 0.0) else {
            continue;
        };
        let memory_mb = (mem_gib * 1024.0).round() as u64;
        let cpu_arch = item["CpuArchitecture"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let gpu_amount = item["GPUAmount"]
            .as_u64()
            .or_else(|| item["GpuAmount"].as_u64());
        let usd_per_hour = ecs_instance_spec(id)
            .map(|(_, _, u)| u)
            .unwrap_or_else(|| estimate_usd_per_hour(vcpus, memory_mb));
        out.insert(
            id.to_string(),
            InstanceTypeMeta {
                vcpus,
                memory_mb,
                cpu_arch,
                gpu_amount,
                usd_per_hour,
            },
        );
    }
}

pub(crate) async fn query_available_instance_types(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    target_vcpus: u32,
    target_mem_gib: Option<u32>,
    target_zone: Option<&str>,
) -> Result<Vec<(String, Vec<String>)>> {
    let profile_hint = api.profile_hint(conn);
    let ecs = api.ecs_endpoint(region);
    let mut params = vec![
        ("RegionId".into(), region.to_string()),
        ("DestinationResource".into(), "InstanceType".into()),
        ("InstanceChargeType".into(), "PostPaid".into()),
        ("IoOptimized".into(), "optimized".into()),
        ("Cores".into(), target_vcpus.to_string()),
    ];
    if let Some(mem) = target_mem_gib {
        params.push(("Memory".into(), mem.to_string()));
    }
    if let Some(tz) = target_zone {
        params.push(("ZoneId".into(), tz.to_string()));
    }
    let v = api
        .call_ok(
            &ecs,
            "GET",
            "DescribeAvailableResource",
            ECS_API_VERSION,
            &params,
            profile_hint,
        )
        .await?;

    let mut zones_by_type: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
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
        let zone_id = zone["ZoneId"].as_str().unwrap_or("").trim();
        if let Some(tz) = target_zone
            && zone_id != tz
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
                if sr["Status"].as_str() == Some("Available")
                    && is_with_stock_category(sr["StatusCategory"].as_str())
                    && let Some(val) = sr["Value"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                {
                    let entry = zones_by_type.entry(val.to_string()).or_insert_with(|| {
                        order.push(val.to_string());
                        Vec::new()
                    });
                    if !zone_id.is_empty() && !entry.iter().any(|z| z == zone_id) {
                        entry.push(zone_id.to_string());
                    }
                }
            }
        }
    }
    Ok(order
        .into_iter()
        .map(|id| {
            let mut z = zones_by_type.remove(&id).unwrap_or_default();
            z.sort();
            (id, z)
        })
        .collect())
}

pub(crate) async fn describe_instance_types_batch(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    ids: &[String],
) -> BTreeMap<String, InstanceTypeMeta> {
    let mut out = BTreeMap::new();
    if ids.is_empty() {
        return out;
    }
    let profile_hint = api.profile_hint(conn);
    let ecs = api.ecs_endpoint(region);
    // Alibaba Cloud ECS caps DescribeInstanceTypes RepeatList (`InstanceTypes.N`) at 10 items.
    // For <= 20 candidates, fetch in RepeatList chunks of 10; for larger candidate sets,
    // paginate the unfiltered regional catalog via NextToken so all pages are covered.
    if ids.len() <= 20 {
        for chunk in ids.chunks(10) {
            let base_params: Vec<(String, String)> = chunk
                .iter()
                .enumerate()
                .map(|(i, id)| (format!("InstanceTypes.{}", i + 1), id.clone()))
                .collect();
            if let Ok(items) = api
                .paginated_next_token(
                    &ecs,
                    "DescribeInstanceTypes",
                    ECS_API_VERSION,
                    &base_params,
                    ("InstanceTypes", "InstanceType"),
                    profile_hint,
                )
                .await
            {
                collect_instance_type_metas(&items, &mut out);
            }
        }
    } else if let Ok(items) = api
        .paginated_next_token(
            &ecs,
            "DescribeInstanceTypes",
            ECS_API_VERSION,
            &[],
            ("InstanceTypes", "InstanceType"),
            profile_hint,
        )
        .await
    {
        collect_instance_type_metas(&items, &mut out);
    }
    out
}

pub(crate) async fn lookup_instance_type(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    instance_type: &str,
) -> Result<(u32, u64, f64)> {
    let instance_type = instance_type.trim();
    if instance_type.is_empty() {
        return Err(Error::InvalidArgument(
            "aliyun-ecs: instance_type cannot be empty".into(),
        ));
    }
    if let Some(spec) = ecs_instance_spec(instance_type) {
        return Ok(spec);
    }
    let profile_hint = api.profile_hint(conn);
    let v = api
        .call_ok(
            &api.ecs_endpoint(region),
            "GET",
            "DescribeInstanceTypes",
            ECS_API_VERSION,
            &[("InstanceTypes.1".into(), instance_type.to_string())],
            profile_hint,
        )
        .await?;
    let Some(item) = v["InstanceTypes"]["InstanceType"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|it| it["InstanceTypeId"].as_str() == Some(instance_type))
        })
    else {
        return Err(Error::InvalidArgument(format!(
            "aliyun-ecs: unknown instance type {instance_type:?} in region {region}"
        )));
    };
    let vcpus = item["CpuCoreCount"]
        .as_u64()
        .and_then(|c| u32::try_from(c).ok())
        .filter(|&c| c > 0)
        .ok_or_else(|| {
            Error::Cloud(format!(
                "aliyun-ecs: DescribeInstanceTypes returned invalid CpuCoreCount for {instance_type:?}"
            ))
        })?;
    let mem_gib = item["MemorySize"]
        .as_f64()
        .filter(|&m| m > 0.0)
        .ok_or_else(|| {
            Error::Cloud(format!(
                "aliyun-ecs: DescribeInstanceTypes returned invalid MemorySize for {instance_type:?}"
            ))
        })?;
    let memory_mb = (mem_gib * 1024.0).round() as u64;
    let est_usd_per_hour = estimate_usd_per_hour(vcpus, memory_mb);
    Ok((vcpus, memory_mb, est_usd_per_hour))
}

pub(crate) async fn resolve_dynamic_instance_type_for_spec(
    api: &AliyunEcs,
    conn: &Connection,
    region: &str,
    spec: &ProvisionSpec,
) -> ResolvedInstanceSelection {
    let profile_hint = api.profile_hint(conn);
    let target_zone = if let Some(vsw_id) = conn
        .vswitch_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        api.call_ok(
            &api.vpc_endpoint(region),
            "GET",
            "DescribeVSwitches",
            VPC_API_VERSION,
            &[
                ("RegionId".into(), region.to_string()),
                ("VSwitchId".into(), vsw_id.to_string()),
            ],
            profile_hint,
        )
        .await
        .ok()
        .and_then(|resp| {
            resp["VSwitches"]["VSwitch"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|vsw| vsw["ZoneId"].as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
    } else {
        None
    };

    let (target_vcpus, target_mem_gib) = target_compute_for(spec);
    let target_mem_mb = u64::from(target_mem_gib) * 1024;

    for mem_filter in [Some(target_mem_gib), None] {
        let Ok(cands) = query_available_instance_types(
            api,
            conn,
            region,
            target_vcpus,
            mem_filter,
            target_zone.as_deref(),
        )
        .await
        else {
            break;
        };
        if cands.is_empty() {
            continue;
        }
        let ids: Vec<String> = cands.iter().map(|(id, _)| id.clone()).collect();
        let meta_map = describe_instance_types_batch(api, conn, region, &ids).await;
        if let Some((picked, meta, zones)) = select_best_dynamic_candidate(
            &spec.family,
            target_vcpus,
            target_mem_mb,
            conn.max_size,
            &cands,
            &meta_map,
        ) {
            return ResolvedInstanceSelection {
                instance_type: picked,
                vcpus: meta.vcpus,
                memory_mb: meta.memory_mb,
                usd_per_hour: meta.usd_per_hour,
                stock_zones: zones,
            };
        }
    }

    let fallback = default_instance_type_for(&spec.family).to_string();
    let (vcpus, memory_mb, usd) = ecs_instance_spec(&fallback).unwrap_or_else(|| {
        (
            target_vcpus,
            target_mem_mb,
            estimate_usd_per_hour(target_vcpus, target_mem_mb),
        )
    });
    ResolvedInstanceSelection {
        instance_type: fallback,
        vcpus,
        memory_mb,
        usd_per_hour: usd,
        stock_zones: Vec::new(),
    }
}

pub(crate) fn kinds_for(conn: &Connection) -> Vec<CloudKind> {
    let custom_type = conn
        .instance_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let custom_usd = custom_type.and_then(|t| ecs_instance_spec(t).map(|(_, _, u)| u));
    vec![
        CloudKind {
            image: "linux".into(),
            kind: "container".into(),
            supported: true,
            reason: "one ECS VM running Docker on Ubuntu 24.04".into(),
            machine_type: custom_type.unwrap_or(LINUX_INSTANCE_TYPE).into(),
            usd_per_hour: custom_usd.unwrap_or(0.043),
        },
        CloudKind {
            image: "linux-slim".into(),
            kind: "container".into(),
            supported: true,
            reason: "one ECS VM running Docker on Ubuntu 24.04".into(),
            machine_type: custom_type.unwrap_or(SLIM_INSTANCE_TYPE).into(),
            usd_per_hour: custom_usd.unwrap_or(0.030),
        },
        CloudKind {
            image: "windows".into(),
            kind: "vm".into(),
            supported: true,
            reason: "Windows Direct VM Sandbox".into(),
            machine_type: custom_type.unwrap_or(WINDOWS_INSTANCE_TYPE).into(),
            usd_per_hour: custom_usd.unwrap_or(0.125),
        },
        CloudKind {
            image: "omarchy".into(),
            kind: "vm".into(),
            supported: false,
            reason: "omarchy is not offered on Alibaba Cloud ECS".into(),
            ..Default::default()
        },
        CloudKind {
            image: "macos".into(),
            kind: "vm".into(),
            supported: false,
            reason: "macOS runs only on Apple hardware; Alibaba Cloud ECS has none".into(),
            ..Default::default()
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_instance_selection_filters_exclusions_and_ranks_mainstream_over_burstable() {
        assert!(is_with_stock_category(None));
        assert!(is_with_stock_category(Some("")));
        assert!(is_with_stock_category(Some("WithStock")));
        assert!(!is_with_stock_category(Some("ClosedWithStock")));
        assert!(!is_with_stock_category(Some("WithoutStock")));

        for excluded in [
            ("ecs.c8y.xlarge", Some("ARM"), None),
            ("ecs.g8y.large", None, None),
            ("ecs.r8y.large", None, None),
            ("ecs.c6r.xlarge", None, None),
            ("ecs.g6r.xlarge", None, None),
            ("ecs.r6r.large", None, None),
            ("ecs.c8m.xlarge", None, None),
            ("ecs.g8m.xlarge", None, None),
            ("ecs.r8m.xlarge", None, None),
            ("ecs.av8m.xlarge", None, None),
            ("ecs.ga1.xlarge", None, None),
            ("ecs.gp7.xlarge", None, None),
            ("ecs.cgn8i.xlarge", None, None),
            ("ecs.hfgn6g.xlarge", None, None),
            ("ecs.video-trans.large", None, None),
            ("ecs.poc-test.large", None, None),
            ("ecs.e-test.large", None, None),
            ("ecs.gn7i-c8g1.2xlarge", Some("X86"), Some(1)),
            ("ecs.sgn7i.large", None, None),
            ("ecs.vgn6i.large", None, None),
            ("ecs.f3.large", None, None),
            ("ecs.ebmgn7.xlarge", None, None),
            ("ecs.ebmg7.32xlarge", None, None),
            ("ecs.sccg7.large", None, None),
        ] {
            assert!(
                is_excluded_instance_family(excluded.0, excluded.1, excluded.2),
                "{excluded:?} should be excluded"
            );
        }
        for allowed in [
            ("ecs.i4r.xlarge", Some("X86"), Some(0)),
            ("ecs.i4r.xlarge", None, None),
            ("ecs.hfc7.xlarge", Some("X86"), Some(0)),
            ("ecs.c9i.xlarge", Some("X86"), None),
            ("ecs.u2a-c1m2.xlarge", Some("X86"), None),
        ] {
            assert!(
                !is_excluded_instance_family(allowed.0, allowed.1, allowed.2),
                "{allowed:?} should be allowed"
            );
        }

        let cands = vec![
            ("ecs.c8y.xlarge".into(), vec!["ap-southeast-1a".into()]),
            ("ecs.gn7i.xlarge".into(), vec!["ap-southeast-1a".into()]),
            ("ecs.ebmg7.xlarge".into(), vec!["ap-southeast-1a".into()]),
            ("ecs.t6-c1m2.xlarge".into(), vec!["ap-southeast-1a".into()]),
            ("ecs.c9i.xlarge".into(), vec!["ap-southeast-1b".into()]),
            ("ecs.g7.2xlarge".into(), vec!["ap-southeast-1a".into()]),
        ];
        let mk =
            |vcpus, memory_mb, arch: Option<&str>, gpu_amount, usd_per_hour| InstanceTypeMeta {
                vcpus,
                memory_mb,
                cpu_arch: arch.map(str::to_string),
                gpu_amount,
                usd_per_hour,
            };
        let meta = BTreeMap::from([
            (
                "ecs.c8y.xlarge".into(),
                mk(4, 8192, Some("ARM"), None, 0.08),
            ),
            (
                "ecs.gn7i.xlarge".into(),
                mk(4, 8192, Some("X86"), Some(1), 0.90),
            ),
            (
                "ecs.ebmg7.xlarge".into(),
                mk(4, 8192, Some("X86"), None, 0.50),
            ),
            (
                "ecs.t6-c1m2.xlarge".into(),
                mk(4, 8192, Some("X86"), None, 0.05),
            ),
            (
                "ecs.c9i.xlarge".into(),
                mk(4, 8192, Some("X86"), None, 0.14),
            ),
            (
                "ecs.g7.2xlarge".into(),
                mk(8, 32768, Some("X86"), None, 0.34),
            ),
        ]);

        let (picked, _, zones) =
            select_best_dynamic_candidate("windows", 4, 8192, None, &cands, &meta).unwrap();
        assert_eq!(picked, "ecs.c9i.xlarge");
        assert_eq!(zones, vec!["ap-southeast-1b".to_string()]);

        let only_burstable = vec![("ecs.t6-c1m2.xlarge".into(), vec!["ap-southeast-1a".into()])];
        let (picked_b, _, _) =
            select_best_dynamic_candidate("windows", 4, 8192, None, &only_burstable, &meta)
                .unwrap();
        assert_eq!(picked_b, "ecs.t6-c1m2.xlarge");

        let big_only = vec![("ecs.g7.2xlarge".into(), vec!["ap-southeast-1a".into()])];
        let max_4x16 = model::MaxSize::parse("4x16");
        assert!(
            select_best_dynamic_candidate("windows", 4, 8192, max_4x16, &big_only, &meta).is_none()
        );
    }
}
