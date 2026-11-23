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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneFault {
    /// Reported as `WithoutStock` in `DescribeAvailableResource` and fails `RunInstances` with the given code.
    SoldOut(String),
    /// Reported as `WithStock` in `DescribeAvailableResource`, but fails `RunInstances` with the given code.
    RunFail(String),
}

impl ZoneFault {
    pub fn code(&self) -> &str {
        match self {
            ZoneFault::SoldOut(c) | ZoneFault::RunFail(c) => c.as_str(),
        }
    }

    pub fn is_sold_out(&self) -> bool {
        matches!(self, ZoneFault::SoldOut(_))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeVpc {
    pub vpc_id: String,
    pub region_id: String,
    pub cidr_block: String,
    pub vpc_name: String,
    pub status: String,
    pub is_default: bool,
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
    pub status: String,
    pub is_default: bool,
    pub available_ip_address_count: Option<u32>,
    pub tags: BTreeMap<String, String>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FakeSg {
    pub sg_id: String,
    pub vpc_id: String,
    pub region_id: String,
    pub sg_name: String,
    pub sg_type: String,
    pub inner_access_policy: String,
    pub tags: BTreeMap<String, String>,
    pub ingress_rules: Vec<Value>,
    pub is_user_owned: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FakeInstance {
    pub instance_id: String,
    pub instance_name: String,
    pub host_name: String,
    pub region_id: String,
    pub zone_id: String,
    pub vpc_id: String,
    pub vswitch_id: String,
    pub security_group_id: String,
    pub extra_security_group_ids: Vec<String>,
    pub instance_type: String,
    pub image_id: String,
    pub status: String,
    pub instance_charge_type: String,
    pub stopped_mode: String,
    pub auto_release_time: Option<String>,
    pub http_endpoint: String,
    pub http_tokens: Option<String>,
    pub key_pair_name: Option<String>,
    pub ram_role_name: Option<String>,
    pub internet_charge_type: String,
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
    pub fn to_api_json(&self) -> Value {
        let status = if self.status.is_empty() {
            "Available"
        } else {
            self.status.as_str()
        };
        json!({
            "VpcId": self.vpc_id,
            "VpcName": self.vpc_name,
            "CidrBlock": self.cidr_block,
            "RegionId": self.region_id,
            "IsDefault": self.is_default,
            "Status": status,
            "Tags": { "Tag": tags_json(&self.tags, false) },
        })
    }
}

impl FakeVSwitch {
    pub fn to_api_json(&self) -> Value {
        let status = if self.status.is_empty() {
            "Available"
        } else {
            self.status.as_str()
        };
        let mut out = json!({
            "VSwitchId": self.vswitch_id,
            "VSwitchName": self.vswitch_name,
            "VpcId": self.vpc_id,
            "ZoneId": self.zone_id,
            "RegionId": self.region_id,
            "CidrBlock": self.cidr_block,
            "IsDefault": self.is_default,
            "Status": status,
            "Tags": { "Tag": tags_json(&self.tags, false) },
        });
        if let Some(avail) = self.available_ip_address_count {
            out["AvailableIpAddressCount"] = json!(avail);
        }
        out
    }
}

impl FakeSg {
    pub fn to_api_json(&self) -> Value {
        let mut out = json!({
            "SecurityGroupId": self.sg_id,
            "SecurityGroupName": self.sg_name,
            "VpcId": self.vpc_id,
            "RegionId": self.region_id,
            "Tags": { "Tag": tags_json(&self.tags, true) },
        });
        if !self.sg_type.is_empty() {
            out["SecurityGroupType"] = json!(self.sg_type);
        }
        if !self.inner_access_policy.is_empty() {
            out["InnerAccessPolicy"] = json!(self.inner_access_policy);
        }
        out
    }
}

impl FakeInstance {
    pub fn all_security_group_ids(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.security_group_id.is_empty() {
            out.push(self.security_group_id.clone());
        }
        for sg in &self.extra_security_group_ids {
            if !sg.is_empty() && !out.iter().any(|x| x == sg) {
                out.push(sg.clone());
            }
        }
        out
    }

    pub fn to_api_json(&self) -> Value {
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
        let sgs = self.all_security_group_ids();
        json!({
            "InstanceId": self.instance_id,
            "InstanceName": self.instance_name,
            "HostName": self.host_name,
            "RegionId": self.region_id,
            "ZoneId": self.zone_id,
            "InstanceType": self.instance_type,
            "ImageId": self.image_id,
            "Status": self.status,
            "InstanceChargeType": self.instance_charge_type,
            "StoppedMode": self.stopped_mode,
            "AutoReleaseTime": self.auto_release_time.clone().unwrap_or_default(),
            "InternetChargeType": self.internet_charge_type,
            "InternetMaxBandwidthOut": bw_out,
            "MetadataOptions": {
                "HttpEndpoint": self.http_endpoint,
                "HttpTokens": self.http_tokens.clone().unwrap_or_default(),
            },
            "SystemDisk": {
                "Category": self.system_disk_category.clone().unwrap_or_default(),
                "Size": self.system_disk_size.clone().unwrap_or_default(),
            },
            "VpcAttributes": {
                "VpcId": self.vpc_id,
                "VSwitchId": self.vswitch_id,
                "PrivateIpAddress": { "IpAddress": ["172.16.0.10"] }
            },
            "SecurityGroupIds": { "SecurityGroupId": sgs },
            "PublicIpAddress": { "IpAddress": pub_ips },
            "Tags": { "Tag": tags_json(&self.tags, true) }
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeImage {
    pub image_id: String,
    pub image_name: String,
    pub os_type: String,
    pub os_name_en: Option<String>,
    pub arch: String,
    pub status: String,
    pub owner_alias: String,
    pub region_id: String,
    pub creation_time: String,
    pub size_gb: u32,
}

impl FakeImage {
    pub fn to_api_json(&self) -> Value {
        let mut item = json!({
            "ImageId": self.image_id,
            "ImageName": self.image_name,
            "OSType": self.os_type,
            "Architecture": self.arch,
            "Status": self.status,
            "ImageOwnerAlias": self.owner_alias,
        });
        if let Some(ref en) = self.os_name_en {
            item["OSNameEn"] = json!(en);
        }
        if !self.creation_time.is_empty() {
            item["CreationTime"] = json!(self.creation_time);
        }
        if self.size_gb > 0 {
            item["Size"] = json!(self.size_gb);
        }
        item
    }
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
    pub zone_faults: BTreeMap<String, ZoneFault>,
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
        let images = [
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
        ]
        .into_iter()
        .map(|(id, os, os_en, created, size)| FakeImage {
            image_id: id.into(),
            image_name: id.into(),
            os_type: os.into(),
            os_name_en: os_en.map(str::to_string),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "system".into(),
            region_id: String::new(),
            creation_time: created.into(),
            size_gb: size,
        })
        .collect();
        let instance_types = [
            ("ecs.e-c1m2.large", 2, 4.0),
            ("ecs.e-c1m1.large", 2, 2.0),
            ("ecs.c7.xlarge", 4, 8.0),
            ("ecs.g7.large", 2, 8.0),
            ("ecs.g7.xlarge", 4, 16.0),
            ("ecs.g7.2xlarge", 8, 32.0),
            ("ecs.g7.4xlarge", 16, 64.0),
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
            zone_faults: BTreeMap::new(),
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
        self.zones
            .get(region)
            .filter(|z| !z.is_empty())
            .cloned()
            .unwrap_or_else(|| vec![format!("{region}-h")])
    }

    pub fn add_key(&mut self, ak: &str, sk: &str) {
        self.keys.insert(ak.to_string(), sk.to_string());
    }

    pub fn add_image(&mut self, img: FakeImage) {
        self.images.push(img);
    }

    pub fn seed_vpc(&mut self, vpc: FakeVpc) {
        self.vpcs.insert(vpc.vpc_id.clone(), vpc);
    }

    pub fn seed_vswitch(&mut self, vsw: FakeVSwitch) {
        self.vswitches.insert(vsw.vswitch_id.clone(), vsw);
    }

    pub fn seed_sg(&mut self, sg: FakeSg) {
        self.security_groups.insert(sg.sg_id.clone(), sg);
    }

    pub fn seed_instance(&mut self, inst: FakeInstance) {
        self.instances.insert(inst.instance_id.clone(), inst);
    }

    pub fn seed_zone(&mut self, region: &str, zone: impl Into<String>) {
        self.zones
            .entry(region.to_string())
            .or_default()
            .push(zone.into());
    }

    pub fn set_zones(&mut self, region: &str, zones: Vec<String>) {
        self.zones.insert(region.to_string(), zones);
    }

    pub fn add_instance_type(&mut self, id: &str, cpu_core_count: u32, memory_size_gb: f64) {
        if let Some(existing) = self.instance_types.iter_mut().find(|t| t.id == id) {
            existing.cpu_core_count = cpu_core_count;
            existing.memory_size_gb = memory_size_gb;
        } else {
            self.instance_types.push(FakeInstanceType {
                id: id.to_string(),
                cpu_core_count,
                memory_size_gb,
            });
        }
        if let Some(avail) = &mut self.available_instance_types
            && !avail.iter().any(|x| x == id)
        {
            avail.push(id.to_string());
        }
    }

    pub fn mark_zone_sold_out(&mut self, zone: impl Into<String>, code: impl Into<String>) {
        self.zone_faults
            .insert(zone.into(), ZoneFault::SoldOut(code.into()));
    }

    pub fn mark_zone_run_fail(&mut self, zone: impl Into<String>, code: impl Into<String>) {
        self.zone_faults
            .insert(zone.into(), ZoneFault::RunFail(code.into()));
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
