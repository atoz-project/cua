// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Thin JSON-state adapter over [`cua_byoc::testing::fake_aliyun`] for `tests/aliyun_ecs*.rs`.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Response;
use cua_byoc::testing::fake_aliyun::{
    self as canon, FakeImage, FakeInstance, FakeInstanceType, FakeSg, FakeVSwitch, FakeVpc,
};
use serde_json::{Value, json};

pub use cua_byoc::testing::fake_aliyun::{RecordedCall, RunHook};

pub struct FakeAliyun {
    pub keys: BTreeMap<String, String>,
    pub regions: Vec<String>,
    pub zones: Vec<String>,
    pub available_instance_types: Vec<String>,
    pub sold_out_zones: BTreeMap<String, String>,
    pub run_fail_zones: BTreeMap<String, String>,
    pub vpcs: Vec<Value>,
    pub vswitches: Vec<Value>,
    pub security_groups: Vec<Value>,
    pub security_group_rules: BTreeMap<String, Vec<Value>>,
    pub instance_types: BTreeMap<String, (u32, f64)>,
    pub instance_type_details: BTreeMap<String, Value>,
    pub instance_types_page_size: Option<usize>,
    pub ignore_instance_types_filter: bool,
    pub available_zones_override: Option<Vec<Value>>,
    pub images: Vec<Value>,
    pub instances: BTreeMap<String, Value>,
    pub console_outputs: BTreeMap<String, String>,
    pub calls: Vec<RecordedCall>,
    pub throttle: u32,
    pub transient_dependency_errors: u32,
    pub transient_dependency_code: Option<String>,
    pub forbidden_actions: BTreeSet<String>,
    pub run_instances_missing_vswitch: bool,
    pub run_instances_dry_run_error: Option<(u16, String, String)>,
    pub run_instances_error: Option<(u16, String, String)>,
    pub force_auth_error: Option<(String, String)>,
    pub next_id: u64,
    pub on_run_instance: Option<RunHook>,
}

const DEFAULT_IMAGES: &[(&str, &str, Option<&str>, &str, u32)] = &[
    (
        "ubuntu_24_04_x64_20G_alibase_20240601.vhd",
        "linux",
        None,
        "2024-06-01T00:00:00Z",
        20,
    ),
    (
        "ubuntu_24_04_x64_20G_alibase_20250101.vhd",
        "linux",
        None,
        "2025-01-01T00:00:00Z",
        20,
    ),
    (
        "win2019_1809_x64_dtc_zh-cn_40G_alibase_20240601.vhd",
        "windows",
        Some("Windows Server 2019 Datacenter Edition 64bit Chinese"),
        "2024-06-01T00:00:00Z",
        40,
    ),
    (
        "win2022_21H2_x64_dtc_en-us_40G_alibase_20250201.vhd",
        "windows",
        Some("Windows Server 2022 Datacenter Edition 64bit"),
        "2025-02-01T00:00:00Z",
        40,
    ),
];

impl Default for FakeAliyun {
    fn default() -> Self {
        let images = DEFAULT_IMAGES
            .iter()
            .map(|&(id, os, os_en, created, size)| {
                let mut v = json!({
                    "ImageId": id, "ImageName": id, "ImageOwnerAlias": "system",
                    "OSType": os, "Architecture": "x86_64", "Status": "Available",
                    "CreationTime": created, "Size": size
                });
                if let Some(en) = os_en {
                    v["OSNameEn"] = json!(en);
                }
                v
            })
            .collect();
        let types = [
            ("ecs.e-c1m2.large", 2, 4.0),
            ("ecs.e-c1m1.large", 2, 2.0),
            ("ecs.c7.xlarge", 4, 8.0),
            ("ecs.g7.large", 2, 8.0),
            ("ecs.g7.4xlarge", 16, 64.0),
        ];
        Self {
            keys: BTreeMap::from([("LTAI_TEST_AK".into(), "secret123".into())]),
            regions: ["cn-hangzhou", "cn-shanghai", "cn-beijing", "ap-southeast-1"]
                .map(Into::into)
                .into(),
            available_instance_types: types.iter().map(|(id, ..)| (*id).into()).collect(),
            instance_types: types
                .into_iter()
                .map(|(id, c, m)| (id.into(), (c, m)))
                .collect(),
            images,
            next_id: 1,
            zones: Vec::new(),
            sold_out_zones: BTreeMap::new(),
            run_fail_zones: BTreeMap::new(),
            vpcs: Vec::new(),
            vswitches: Vec::new(),
            security_groups: Vec::new(),
            security_group_rules: BTreeMap::new(),
            instance_type_details: BTreeMap::new(),
            instance_types_page_size: None,
            ignore_instance_types_filter: false,
            available_zones_override: None,
            instances: BTreeMap::new(),
            console_outputs: BTreeMap::new(),
            calls: Vec::new(),
            throttle: 0,
            transient_dependency_errors: 0,
            transient_dependency_code: None,
            forbidden_actions: BTreeSet::new(),
            run_instances_missing_vswitch: false,
            run_instances_dry_run_error: None,
            run_instances_error: None,
            force_auth_error: None,
            on_run_instance: None,
        }
    }
}

pub type S = Arc<Mutex<FakeAliyun>>;

fn json_tags(obj: &Value) -> BTreeMap<String, String> {
    obj["Tags"]["Tag"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| {
            let k = t["TagKey"].as_str().or_else(|| t["Key"].as_str())?;
            let v = t["TagValue"]
                .as_str()
                .or_else(|| t["Value"].as_str())
                .unwrap_or("");
            Some((k.into(), v.into()))
        })
        .collect()
}

fn sfield(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").into()
}

fn map_val_into<T>(
    items: &[Value],
    id_key: &str,
    dst: &mut BTreeMap<String, T>,
    extra: &mut BTreeMap<String, Value>,
    build: impl Fn(&str, &Value) -> T,
) {
    for v in items {
        let id = sfield(v, id_key);
        dst.insert(id.clone(), build(&id, v));
        extra.insert(id, v.clone());
    }
}

fn to_canonical(f: &FakeAliyun) -> canon::FakeAliyun {
    let mut c = canon::FakeAliyun {
        keys: f.keys.clone(),
        regions: f.regions.clone(),
        zones: BTreeMap::new(),
        flat_zones: Some(f.zones.clone()),
        instance_types: f
            .instance_types
            .iter()
            .map(|(id, &(cpu, mem))| FakeInstanceType {
                id: id.clone(),
                cpu_core_count: cpu,
                memory_size_gb: mem,
            })
            .collect(),
        available_instance_types: Some(f.available_instance_types.clone()),
        instance_type_details: f.instance_type_details.clone(),
        instance_types_page_size: f.instance_types_page_size,
        ignore_instance_types_filter: f.ignore_instance_types_filter,
        available_zones_override: f.available_zones_override.clone(),
        images: Vec::new(),
        security_group_rules: f.security_group_rules.clone(),
        calls: f.calls.clone(),
        throttle: f.throttle,
        transient_dependency_errors: f.transient_dependency_errors,
        transient_dependency_code: f.transient_dependency_code.clone(),
        forbidden_actions: f.forbidden_actions.clone(),
        run_instances_missing_vswitch: f.run_instances_missing_vswitch,
        run_instances_dry_run_error: f.run_instances_dry_run_error.clone(),
        run_instances_error: f.run_instances_error.clone(),
        force_auth_error: f.force_auth_error.clone(),
        sold_out_zone_errors: f.sold_out_zones.clone(),
        run_fail_zone_errors: f.run_fail_zones.clone(),
        omit_sold_out_zones_in_available: true,
        console_outputs: f.console_outputs.clone(),
        require_instance_for_console: true,
        on_run_instance: f.on_run_instance.clone(),
        next_id: f.next_id,
        ..canon::FakeAliyun::default()
    };
    for img in &f.images {
        let id = sfield(img, "ImageId");
        c.images.push(FakeImage {
            image_id: id.clone(),
            image_name: sfield(img, "ImageName"),
            os_type: sfield(img, "OSType"),
            arch: sfield(img, "Architecture"),
            status: sfield(img, "Status"),
            owner_alias: sfield(img, "ImageOwnerAlias"),
            region_id: sfield(img, "RegionId"),
        });
        c.extra_image_fields.insert(id, img.clone());
    }
    map_val_into(
        &f.vpcs,
        "VpcId",
        &mut c.vpcs,
        &mut c.extra_vpc_fields,
        |id, v| FakeVpc {
            vpc_id: id.into(),
            region_id: sfield(v, "RegionId"),
            cidr_block: sfield(v, "CidrBlock"),
            vpc_name: sfield(v, "VpcName"),
            tags: json_tags(v),
            ..Default::default()
        },
    );
    map_val_into(
        &f.vswitches,
        "VSwitchId",
        &mut c.vswitches,
        &mut c.extra_vswitch_fields,
        |id, v| FakeVSwitch {
            vswitch_id: id.into(),
            vpc_id: sfield(v, "VpcId"),
            zone_id: sfield(v, "ZoneId"),
            region_id: sfield(v, "RegionId"),
            cidr_block: sfield(v, "CidrBlock"),
            vswitch_name: sfield(v, "VSwitchName"),
            tags: json_tags(v),
            ..Default::default()
        },
    );
    map_val_into(
        &f.security_groups,
        "SecurityGroupId",
        &mut c.security_groups,
        &mut c.extra_sg_fields,
        |id, sg| FakeSg {
            sg_id: id.into(),
            vpc_id: sfield(sg, "VpcId"),
            region_id: sfield(sg, "RegionId"),
            sg_name: sfield(sg, "SecurityGroupName"),
            tags: json_tags(sg),
            ..Default::default()
        },
    );
    for (id, inst) in &f.instances {
        let sg_id = inst["SecurityGroupIds"]["SecurityGroupId"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or("")
            .into();
        let bw = inst["InternetMaxBandwidthOut"]
            .as_u64()
            .map(|n| n.to_string())
            .or_else(|| inst["InternetMaxBandwidthOut"].as_str().map(Into::into));
        c.instances.insert(
            id.clone(),
            FakeInstance {
                instance_id: id.clone(),
                instance_name: sfield(inst, "InstanceName"),
                region_id: sfield(inst, "RegionId"),
                zone_id: sfield(inst, "ZoneId"),
                vpc_id: sfield(&inst["VpcAttributes"], "VpcId"),
                vswitch_id: sfield(&inst["VpcAttributes"], "VSwitchId"),
                security_group_id: sg_id,
                instance_type: sfield(inst, "InstanceType"),
                image_id: sfield(inst, "ImageId"),
                status: sfield(inst, "Status"),
                instance_charge_type: sfield(inst, "InstanceChargeType"),
                stopped_mode: sfield(inst, "StoppedMode"),
                auto_release_time: inst["AutoReleaseTime"].as_str().map(Into::into),
                http_tokens: inst["MetadataOptions"]["HttpTokens"]
                    .as_str()
                    .map(Into::into),
                internet_max_bandwidth_out: bw,
                system_disk_category: inst["SystemDisk"]["Category"].as_str().map(Into::into),
                system_disk_size: inst["SystemDisk"]["Size"].as_str().map(Into::into),
                tags: json_tags(inst),
                ..Default::default()
            },
        );
        c.extra_instance_fields.insert(id.clone(), inst.clone());
    }
    c
}

fn sync_vec<T>(
    vec: &mut Vec<Value>,
    id_key: &str,
    map: &BTreeMap<String, T>,
    to_json: impl Fn(&T) -> Value,
) {
    vec.retain(|v| v[id_key].as_str().is_some_and(|id| map.contains_key(id)));
    let existing: BTreeSet<String> = vec
        .iter()
        .filter_map(|v| v[id_key].as_str().map(Into::into))
        .collect();
    for (id, item) in map {
        if !existing.contains(id) {
            vec.push(to_json(item));
        }
    }
}

fn sync_from_canonical(f: &mut FakeAliyun, c: canon::FakeAliyun) {
    f.calls = c.calls;
    f.throttle = c.throttle;
    f.transient_dependency_errors = c.transient_dependency_errors;
    f.security_group_rules = c.security_group_rules;
    f.next_id = c.next_id;
    sync_vec(&mut f.vpcs, "VpcId", &c.vpcs, |v| {
        v.to_api_json(c.extra_vpc_fields.get(&v.vpc_id))
    });
    sync_vec(&mut f.vswitches, "VSwitchId", &c.vswitches, |v| {
        v.to_api_json(c.extra_vswitch_fields.get(&v.vswitch_id))
    });
    sync_vec(
        &mut f.security_groups,
        "SecurityGroupId",
        &c.security_groups,
        |sg| sg.to_api_json(c.extra_sg_fields.get(&sg.sg_id)),
    );
    f.instances = c
        .instances
        .iter()
        .map(|(id, inst)| {
            (
                id.clone(),
                inst.to_api_json_with_extra(c.extra_instance_fields.get(id)),
            )
        })
        .collect();
}

pub async fn handle(
    State(s): State<S>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (resp, hooks) = {
        let mut f = s.lock().unwrap();
        let mut canonical = to_canonical(&f);
        let (resp, hooks) = canon::dispatch_locked(&mut canonical, &method, &uri, &headers, &body);
        sync_from_canonical(&mut f, canonical);
        (resp, hooks)
    };
    hooks.fire();
    resp
}
