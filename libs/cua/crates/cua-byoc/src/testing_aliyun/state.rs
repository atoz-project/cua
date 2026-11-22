// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Typed state and resource models for [`FakeAliyun`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub struct RecordedCall {
    pub action: String,
    pub version: String,
    pub method: String,
    pub host: String,
    pub access_key_id: String,
    pub params: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootFailMode {
    StopImmediately,
    TerminateImmediately,
    NeverJoinRelay,
}

#[derive(Clone, Debug, Default)]
pub struct FakeVpc {
    pub vpc_id: String,
    pub region_id: String,
    pub cidr_block: String,
    pub vpc_name: String,
    pub tags: BTreeMap<String, String>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FakeVSwitch {
    pub vswitch_id: String,
    pub vpc_id: String,
    pub zone_id: String,
    pub region_id: String,
    pub cidr_block: String,
    pub vswitch_name: String,
    pub tags: BTreeMap<String, String>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FakeSg {
    pub sg_id: String,
    pub vpc_id: String,
    pub region_id: String,
    pub sg_name: String,
    pub tags: BTreeMap<String, String>,
    pub ingress_rules: Vec<Value>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FakeInstance {
    pub instance_id: String,
    pub instance_name: String,
    pub region_id: String,
    pub zone_id: String,
    pub vpc_id: String,
    pub vswitch_id: String,
    pub security_group_id: String,
    pub instance_type: String,
    pub image_id: String,
    pub status: String,
    pub instance_charge_type: String,
    pub stopped_mode: String,
    pub auto_release_time: Option<String>,
    pub http_tokens: Option<String>,
    pub key_pair_name: Option<String>,
    pub ram_role_name: Option<String>,
    pub internet_max_bandwidth_out: Option<String>,
    pub system_disk_category: Option<String>,
    pub system_disk_size: Option<String>,
    pub user_data_raw: String,
    pub user_data_decoded: String,
    pub tags: BTreeMap<String, String>,
    pub client_token: Option<String>,
    pub machine_id: Option<String>,
}

pub(crate) fn tags_json(tags: &BTreeMap<String, String>, ecs_schema: bool) -> Vec<Value> {
    let (kk, vk) = if ecs_schema {
        ("TagKey", "TagValue")
    } else {
        ("Key", "Value")
    };
    tags.iter().map(|(k, v)| json!({ kk: k, vk: v })).collect()
}

pub(crate) fn merge_extra(base: &mut Value, extra: Option<&Value>) {
    if let (Some(dst), Some(src)) = (base.as_object_mut(), extra.and_then(Value::as_object)) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
}

impl FakeVpc {
    pub fn to_api_json(&self, extra: Option<&Value>) -> Value {
        let mut out = json!({
            "VpcId": self.vpc_id, "VpcName": self.vpc_name, "CidrBlock": self.cidr_block,
            "RegionId": self.region_id, "IsDefault": false, "Status": "Available",
            "Tags": { "Tag": tags_json(&self.tags, false) },
        });
        merge_extra(&mut out, extra);
        out
    }
}

impl FakeVSwitch {
    pub fn to_api_json(&self, extra: Option<&Value>) -> Value {
        let mut out = json!({
            "VSwitchId": self.vswitch_id, "VSwitchName": self.vswitch_name,
            "VpcId": self.vpc_id, "ZoneId": self.zone_id, "RegionId": self.region_id,
            "CidrBlock": self.cidr_block, "IsDefault": false, "Status": "Available",
            "Tags": { "Tag": tags_json(&self.tags, false) },
        });
        merge_extra(&mut out, extra);
        out
    }
}

impl FakeSg {
    pub fn to_api_json(&self, extra: Option<&Value>) -> Value {
        let mut out = json!({
            "SecurityGroupId": self.sg_id, "SecurityGroupName": self.sg_name,
            "VpcId": self.vpc_id, "RegionId": self.region_id,
            "Tags": { "Tag": tags_json(&self.tags, true) },
        });
        merge_extra(&mut out, extra);
        out
    }
}

impl FakeInstance {
    pub fn to_api_json(&self) -> Value {
        self.to_api_json_with_extra(None)
    }

    pub fn to_api_json_with_extra(&self, extra: Option<&Value>) -> Value {
        let bw_out: u32 = self
            .internet_max_bandwidth_out
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let pub_ips: Vec<String> = if bw_out > 0 {
            vec!["203.0.113.10".into()]
        } else {
            Vec::new()
        };
        let sgs = if self.security_group_id.is_empty() {
            vec![]
        } else {
            vec![self.security_group_id.clone()]
        };
        let mut out = json!({
            "InstanceId": self.instance_id, "InstanceName": self.instance_name,
            "RegionId": self.region_id, "ZoneId": self.zone_id,
            "InstanceType": self.instance_type, "ImageId": self.image_id,
            "Status": self.status, "InstanceChargeType": self.instance_charge_type,
            "StoppedMode": self.stopped_mode,
            "AutoReleaseTime": self.auto_release_time.clone().unwrap_or_default(),
            "InternetMaxBandwidthOut": bw_out,
            "MetadataOptions": {
                "HttpEndpoint": "", "HttpTokens": self.http_tokens.clone().unwrap_or_default(),
            },
            "SystemDisk": {
                "Category": self.system_disk_category.clone().unwrap_or_default(),
                "Size": self.system_disk_size.clone().unwrap_or_default(),
            },
            "VpcAttributes": {
                "VpcId": self.vpc_id, "VSwitchId": self.vswitch_id,
                "PrivateIpAddress": { "IpAddress": ["172.16.0.10"] }
            },
            "SecurityGroupIds": { "SecurityGroupId": sgs },
            "PublicIpAddress": { "IpAddress": pub_ips },
            "Tags": { "Tag": tags_json(&self.tags, true) }
        });
        merge_extra(&mut out, extra);
        if let Some(obj) = out.as_object_mut() {
            obj.insert("Status".into(), json!(self.status));
            obj.insert("StoppedMode".into(), json!(self.stopped_mode));
        }
        out
    }
}

#[derive(Clone, Debug)]
pub struct FakeImage {
    pub image_id: String,
    pub image_name: String,
    pub os_type: String,
    pub arch: String,
    pub status: String,
    pub owner_alias: String,
    pub region_id: String,
}

#[derive(Clone, Debug)]
pub struct FakeInstanceType {
    pub id: String,
    pub cpu_core_count: u32,
    pub memory_size_gb: f64,
}

pub type BootCallback = Arc<dyn Fn(&FakeInstance, &BTreeMap<String, String>) + Send + Sync>;
pub type StateCallback = Arc<dyn Fn(&FakeInstance, bool) + Send + Sync>;
pub type RunHook = Arc<dyn Fn(&str, &BTreeMap<String, String>) + Send + Sync>;
pub type S = Arc<Mutex<FakeAliyun>>;

pub struct FakeAliyun {
    pub keys: BTreeMap<String, String>,
    pub regions: Vec<String>,
    pub zones: BTreeMap<String, Vec<String>>,
    pub flat_zones: Option<Vec<String>>,
    pub instance_types: Vec<FakeInstanceType>,
    pub available_instance_types: Option<Vec<String>>,
    pub instance_type_details: BTreeMap<String, Value>,
    pub instance_types_page_size: Option<usize>,
    pub ignore_instance_types_filter: bool,
    pub available_zones_override: Option<Vec<Value>>,
    pub images: Vec<FakeImage>,
    pub vpcs: BTreeMap<String, FakeVpc>,
    pub vswitches: BTreeMap<String, FakeVSwitch>,
    pub security_groups: BTreeMap<String, FakeSg>,
    pub security_group_rules: BTreeMap<String, Vec<Value>>,
    pub instances: BTreeMap<String, FakeInstance>,
    pub extra_vpc_fields: BTreeMap<String, Value>,
    pub extra_vswitch_fields: BTreeMap<String, Value>,
    pub extra_sg_fields: BTreeMap<String, Value>,
    pub extra_image_fields: BTreeMap<String, Value>,
    pub extra_instance_fields: BTreeMap<String, Value>,
    pub calls: Vec<RecordedCall>,
    pub authorize_sg_calls: usize,
    pub throttle: u32,
    pub transient_dependency_errors: u32,
    pub transient_dependency_code: Option<String>,
    pub forbidden_actions: BTreeSet<String>,
    pub enforce_cua_managed_tag_condition: bool,
    pub run_instances_missing_vswitch: bool,
    pub run_instances_dry_run_error: Option<(u16, String, String)>,
    pub run_instances_error: Option<(u16, String, String)>,
    pub force_auth_error: Option<(String, String)>,
    pub sold_out_zones: BTreeSet<String>,
    pub sold_out_zone_errors: BTreeMap<String, String>,
    pub run_fail_zones: BTreeSet<String>,
    pub run_fail_zone_errors: BTreeMap<String, String>,
    pub unsupported_zones: BTreeSet<String>,
    pub omit_sold_out_zones_in_available: bool,
    pub boot_fail: Option<BootFailMode>,
    pub console_output: Option<String>,
    pub console_outputs: BTreeMap<String, String>,
    pub console_error: bool,
    pub require_instance_for_console: bool,
    pub fail_delete: bool,
    pub fail_run_instances: bool,
    pub client_tokens: BTreeMap<String, String>,
    pub on_boot: Option<BootCallback>,
    pub on_power: Option<StateCallback>,
    pub on_run_instance: Option<RunHook>,
    pub next_id: u64,
}

impl Default for FakeAliyun {
    fn default() -> Self {
        let regions: Vec<String> = ["cn-hangzhou", "cn-shanghai", "cn-beijing", "ap-southeast-1"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let zones = regions
            .iter()
            .map(|r| {
                (
                    r.clone(),
                    vec![format!("{r}-h"), format!("{r}-i"), format!("{r}-j")],
                )
            })
            .collect();
        let mut images = Vec::new();
        for r in &regions {
            for (id, os) in [
                ("ubuntu_24_04_x64_20G_alibase_20250101.vhd", "linux"),
                (
                    "win2022_21H2_x64_dtc_en-us_40G_alibase_20250101.vhd",
                    "windows",
                ),
            ] {
                images.push(FakeImage {
                    image_id: id.into(),
                    image_name: id.into(),
                    os_type: os.into(),
                    arch: "x86_64".into(),
                    status: "Available".into(),
                    owner_alias: "system".into(),
                    region_id: r.clone(),
                });
            }
        }
        let instance_types = [
            ("ecs.e-c1m2.large", 2, 4.0),
            ("ecs.e-c1m1.large", 2, 2.0),
            ("ecs.c7.xlarge", 4, 8.0),
            ("ecs.g7.large", 2, 8.0),
            ("ecs.g7.xlarge", 4, 16.0),
            ("ecs.g7.2xlarge", 8, 32.0),
        ]
        .into_iter()
        .map(|(id, cpu, mem)| FakeInstanceType {
            id: id.into(),
            cpu_core_count: cpu,
            memory_size_gb: mem,
        })
        .collect();

        Self {
            keys: BTreeMap::from([("LTAI_TEST_AK".into(), "secret123".into())]),
            regions,
            zones,
            flat_zones: None,
            instance_types,
            available_instance_types: None,
            instance_type_details: BTreeMap::new(),
            instance_types_page_size: None,
            ignore_instance_types_filter: false,
            available_zones_override: None,
            images,
            vpcs: BTreeMap::new(),
            vswitches: BTreeMap::new(),
            security_groups: BTreeMap::new(),
            security_group_rules: BTreeMap::new(),
            instances: BTreeMap::new(),
            extra_vpc_fields: BTreeMap::new(),
            extra_vswitch_fields: BTreeMap::new(),
            extra_sg_fields: BTreeMap::new(),
            extra_image_fields: BTreeMap::new(),
            extra_instance_fields: BTreeMap::new(),
            calls: Vec::new(),
            authorize_sg_calls: 0,
            throttle: 0,
            transient_dependency_errors: 0,
            transient_dependency_code: None,
            forbidden_actions: BTreeSet::new(),
            enforce_cua_managed_tag_condition: false,
            run_instances_missing_vswitch: false,
            run_instances_dry_run_error: None,
            run_instances_error: None,
            force_auth_error: None,
            sold_out_zones: BTreeSet::new(),
            sold_out_zone_errors: BTreeMap::new(),
            run_fail_zones: BTreeSet::new(),
            run_fail_zone_errors: BTreeMap::new(),
            unsupported_zones: BTreeSet::new(),
            omit_sold_out_zones_in_available: false,
            boot_fail: None,
            console_output: None,
            console_outputs: BTreeMap::new(),
            console_error: false,
            require_instance_for_console: false,
            fail_delete: false,
            fail_run_instances: false,
            client_tokens: BTreeMap::new(),
            on_boot: None,
            on_power: None,
            on_run_instance: None,
            next_id: 1,
        }
    }
}

impl FakeAliyun {
    pub(crate) fn next_seq(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub(crate) fn effective_zones(&self, region: &str) -> Vec<String> {
        let list = self.flat_zones.as_ref().or_else(|| self.zones.get(region));
        list.filter(|z| !z.is_empty())
            .cloned()
            .unwrap_or_else(|| vec![format!("{region}-h")])
    }

    pub fn add_key(&mut self, ak: &str, sk: &str) {
        self.keys.insert(ak.to_string(), sk.to_string());
    }

    pub fn add_image(&mut self, img: FakeImage) {
        self.images.push(img);
    }

    pub fn count_calls(&self, action: &str) -> usize {
        self.calls.iter().filter(|c| c.action == action).count()
    }

    pub fn calls_for(&self, action: &str) -> Vec<RecordedCall> {
        self.calls
            .iter()
            .filter(|c| c.action == action)
            .cloned()
            .collect()
    }
}
