// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Focused integration tests for Alibaba Cloud Windows `vminit` image selection,
//! relaxed CSAS/operator security group egress verification, and `DeleteInstance`
//! permission-denied degradation across `delete`, `sweep`, and `disconnect`.
#![cfg(feature = "aliyun-ecs")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use cua_byoc::RelayAccess;
use cua_byoc::aliyun_ecs::{AliyunEcs, TokenStore};
use cua_byoc::aliyun_net;
use cua_byoc::api::{CloudApi, Target};
use cua_byoc::model::{self, Connection, Resource};
use cua_byoc::testing::fake_aliyun::{
    BootFailMode, FakeImage, FakeInstance, FakeSg, FakeVSwitch, FakeVpc, MemStore, S, sig,
    start_fake,
};
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{CloudManager, ConnectRequest};
use cua_sandbox_core::{CreateOptions, Error, ProviderKind, Sandboxes, Status};
use cua_spacesd_client::testing::{MockAuth, MockServer};
use serde_json::json;

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn decode_b64_str(s: &str) -> String {
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
}

fn conn(api: &AliyunEcs) -> Connection {
    api.resolve(&Target {
        provider: "aliyun-ecs".into(),
        ..Default::default()
    })
    .unwrap()
}

struct EnvGuard {
    prev_id: Option<String>,
    prev_secret: Option<String>,
}

impl EnvGuard {
    fn clear() -> Self {
        let prev_id = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").ok();
        let prev_secret = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").ok();
        unsafe {
            std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID");
            std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        }
        Self {
            prev_id,
            prev_secret,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.prev_id {
                Some(v) => std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_ID", v),
                None => std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID"),
            }
            match &self.prev_secret {
                Some(v) => std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET", v),
                None => std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
            }
        }
    }
}

struct ForbiddenDeleteFixture {
    home: tempfile::TempDir,
    sbx: Sandboxes,
    api: Arc<AliyunEcs>,
    s: S,
    _store: Arc<MemStore>,
    _relay: Arc<FakeRelay>,
    _mock_spacesd: MockServer,
    owner: String,
    owner_tag: String,
}

impl ForbiddenDeleteFixture {
    async fn start() -> Self {
        let home = tempfile::tempdir().unwrap();
        let relay = Arc::new(FakeRelay::start().await);
        relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
        let relay_access = RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
        );
        let mock_spacesd = MockServer::start(MockAuth::default()).await;
        let (api, s, store) = start_fake(Duration::from_millis(5)).await;
        {
            let mut f = s.lock().unwrap();
            f.enforce_cua_managed_tag_condition = true;
            f.forbidden_actions.insert("ecs:DeleteInstance".into());
            f.add_image(FakeImage {
                image_id: "m-2zeeqpoalo73r1psdqjb".into(),
                image_name: "siren-chrome-win11".into(),
                owner_alias: "self".into(),
                os_type: "windows".into(),
                arch: "x86_64".into(),
                status: "Available".into(),
                creation_time: "2026-10-31T17:14:23Z".into(),
                size_gb: 100,
                ..Default::default()
            });
            let relay_hook = relay.clone();
            let mock_url = mock_spacesd.url();
            f.on_run_instance = Some(Arc::new(move |_id, params| {
                let ud = decode_b64_str(params.get("UserData").unwrap());
                assert!(
                    ud.starts_with("[powershell]\n"),
                    "Windows image must receive [powershell] header: {}",
                    &ud[..ud.len().min(60)]
                );
                let mid = sig::extract_machine_id(&ud).unwrap();
                relay_hook.tunnel(&mid, &mock_url);
                relay_hook.set_online(&mid, true, "0.16.5");
            }));
        }

        let sbx = cua_byoc::install_with(
            Sandboxes::builder().state_dir(home.path().join("sandboxes")),
            home.path(),
            vec![api.clone()],
            relay_access,
        )
        .build();
        let clouds = sbx.clouds().unwrap();
        clouds
            .connect_with(&ConnectRequest {
                target: Target {
                    provider: "aliyun-ecs".into(),
                    region: Some("cn-hangzhou".into()),
                    token: Some("LTAI_TEST_AK:secret123".into()),
                    windows_image_id: Some("m-2zeeqpoalo73r1psdqjb".into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();
        let owner = cua_byoc::Store::new(home.path()).owner_id().unwrap();
        let owner_tag = model::label_value(&owner);
        Self {
            home,
            sbx,
            api,
            s,
            _store: store,
            _relay: relay,
            _mock_spacesd: mock_spacesd,
            owner,
            owner_tag,
        }
    }

    fn clouds(&self) -> Arc<dyn CloudManager> {
        self.sbx.clouds().unwrap().clone()
    }
}

#[tokio::test]
async fn official_windows_image_excludes_server_core_and_prefers_win2025() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();

    let (api, s, store) = start_fake(Duration::from_millis(5)).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "wincore_2025_x64_dtc_en-us_40G_alibase_20261015.vhd".into(),
            image_name: "wincore_2025_x64_dtc_en-us_40G_alibase_20261015.vhd".into(),
            os_type: "windows".into(),
            os_name_en: Some(
                "Windows Server 2025 DataCenter Edition 64bit English Edition(Without UI)".into(),
            ),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "system".into(),
            creation_time: "2026-10-15T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "wincore_2022_x64_dtc_en-us_40G_alibase_20261014.vhd".into(),
            image_name: "wincore_2022_x64_dtc_en-us_40G_alibase_20261014.vhd".into(),
            os_type: "windows".into(),
            os_name_en: Some(
                "Windows Server 2022 DataCenter Edition 64bit English Edition(Without UI)".into(),
            ),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "system".into(),
            creation_time: "2026-10-14T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "win2019_1809_x64_dtc_en-us_40G_alibase_20251101.vhd".into(),
            image_name: "win2019_1809_x64_dtc_en-us_40G_alibase_20251101.vhd".into(),
            os_type: "windows".into(),
            os_name_en: Some("Windows Server 2019 DataCenter Edition 64bit English Edition".into()),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "system".into(),
            creation_time: "2025-11-01T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "win2025_24H2_x64_dtc_en-us_40G_alibase_20251001.vhd".into(),
            image_name: "win2025_24H2_x64_dtc_en-us_40G_alibase_20251001.vhd".into(),
            os_type: "windows".into(),
            os_name_en: Some("Windows Server 2025 DataCenter Edition 64bit English Edition".into()),
            arch: "x86_64".into(),
            status: "Available".into(),
            owner_alias: "system".into(),
            creation_time: "2025-10-01T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
    }
    let c = Connection {
        provider: "aliyun-ecs".into(),
        region: "cn-beijing".into(),
        ..Default::default()
    };
    let win = api.resolve_official_image(&c, "windows").await.unwrap();
    assert_eq!(
        win.image_id,
        "win2025_24H2_x64_dtc_en-us_40G_alibase_20251001.vhd"
    );
}

#[tokio::test]
async fn verify_sg_allows_csas_and_operator_ingress_while_repairing_missing_egress() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();

    let (api, s, store) = start_fake(Duration::from_millis(5)).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let owner = "owner-csas";
    let tags = aliyun_net::part_tags(owner);
    {
        let mut f = s.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-csas-1".into(),
            vpc_name: aliyun_net::vpc_name(owner),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-csas-1".into(),
            vswitch_name: aliyun_net::vswitch_name(owner, "cn-hangzhou-h"),
            vpc_id: "vpc-csas-1".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "10.77.0.0/20".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-csas-1".into(),
            sg_name: aliyun_net::sg_name(owner),
            vpc_id: "vpc-csas-1".into(),
            region_id: "cn-hangzhou".into(),
            sg_type: "enterprise".into(),
            inner_access_policy: "Accept".into(),
            tags: tags.clone(),
            ingress_rules: vec![
                json!({
                    "Direction": "ingress",
                    "Policy": "Accept",
                    "Priority": 1,
                    "IpProtocol": "ALL",
                    "PortRange": "-1/-1",
                    "NicType": "intranet",
                    "SourceCidrIp": "172.20.0.250",
                    "Description": "Created by CSAS automatically. Do not modify or delete this rule."
                }),
                json!({
                    "Direction": "ingress",
                    "Policy": "Accept",
                    "Priority": 1,
                    "IpProtocol": "ALL",
                    "PortRange": "-1/-1",
                    "NicType": "intranet",
                    "SourceCidrIp": "172.20.0.251",
                    "Description": "Created by CSAS automatically. Do not modify or delete this rule."
                }),
                json!({
                    "Direction": "ingress",
                    "Policy": "Accept",
                    "Priority": 10,
                    "IpProtocol": "TCP",
                    "PortRange": "3389/3389",
                    "NicType": "internet",
                    "SourceCidrIp": "0.0.0.0/0"
                }),
                json!({
                    "Direction": "ingress",
                    "Policy": "Accept",
                    "Priority": 10,
                    "IpProtocol": "TCP",
                    "PortRange": "443/443",
                    "NicType": "internet",
                    "Ipv6SourceCidrIp": "::/0"
                }),
            ],
            ..Default::default()
        });
    }

    let c = conn(&api);
    let cfg = aliyun_net::NetworkConfig::from_connection(&c).unwrap();
    let locks = aliyun_net::NetLocks::default();
    let prepared = aliyun_net::prepare_network(
        &api,
        &c,
        "cn-hangzhou",
        owner,
        "ecs.c7.xlarge",
        &cfg,
        &locks,
    )
    .await
    .unwrap();
    assert_eq!(prepared.security_group_id, "sg-csas-1");

    let f = s.lock().unwrap();
    assert_eq!(f.count_calls("AuthorizeSecurityGroupEgress"), 1);
    let attr_call = f
        .calls_for("DescribeSecurityGroupAttribute")
        .into_iter()
        .last()
        .unwrap();
    assert_eq!(
        attr_call.params.get("Direction").map(String::as_str),
        Some("egress")
    );
    let egress_rules = f.security_group_rules.get("sg-csas-1").unwrap();
    assert!(
        egress_rules
            .iter()
            .any(|r| r["Direction"] == "egress" && r["DestCidrIp"] == "0.0.0.0/0"),
        "expected repaired egress rule: {egress_rules:?}"
    );
}

#[tokio::test]
async fn delete_instance_forbidden_force_stops_tightens_autorelease_and_keeps_network_in_sweep_all()
{
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    let clouds = fix.clouds();

    let mut opts = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts.contrib = Some("aliyun-ecs".into());
    opts.name = Some("win11-scp-del".into());
    opts.os = "windows".into();
    opts.disk_gb = Some(100);
    opts.ready_timeout = Duration::from_secs(10);
    let sb = fix.sbx.create(opts).await.unwrap();

    // Owned network parts still verify ownership first, then reject stop/start with
    // InvalidArgument; non-instance, non-network types reject immediately with zero calls.
    let vsw_id = {
        let f = fix.s.lock().unwrap();
        f.vswitches.keys().next().unwrap().clone()
    };
    let vsw_res = Resource {
        provider: "aliyun-ecs".into(),
        id: vsw_id,
        resource_type: "vswitch".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    fix.s.lock().unwrap().calls.clear();
    let err = fix
        .api
        .stop(&conn(&fix.api), &vsw_res, &fix.owner)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    {
        let f = fix.s.lock().unwrap();
        assert_eq!(f.count_calls("DescribeVSwitches"), 1);
        assert_eq!(f.count_calls("StopInstance"), 0);
        assert_eq!(f.count_calls("DescribeInstances"), 0);
    }

    let disk_res = Resource {
        provider: "aliyun-ecs".into(),
        id: "d-noninstance".into(),
        resource_type: "disk".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    fix.s.lock().unwrap().calls.clear();
    let err = fix
        .api
        .stop(&conn(&fix.api), &disk_res, &fix.owner)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    assert!(fix.s.lock().unwrap().calls.is_empty());

    fix.s.lock().unwrap().calls.clear();
    let del_now = model::now();
    let original_details = sb.provider_details();
    let inst_id = original_details["id"].clone();
    let delete_err = sb.delete().await.unwrap_err();

    let rel_str = {
        let f = fix.s.lock().unwrap();
        let stop_call = f
            .calls_for("StopInstance")
            .into_iter()
            .last()
            .expect("expected StopInstance fallback");
        assert_eq!(
            stop_call.params.get("StoppedMode").map(String::as_str),
            Some("StopCharging")
        );
        assert_eq!(
            stop_call.params.get("ForceStop").map(String::as_str),
            Some("true")
        );
        let rel_call = f
            .calls_for("ModifyInstanceAutoReleaseTime")
            .into_iter()
            .last()
            .expect("expected ModifyInstanceAutoReleaseTime tightening");
        assert_eq!(
            rel_call.params.get("RegionId").map(String::as_str),
            Some("cn-hangzhou")
        );
        let rel_str = rel_call.params.get("AutoReleaseTime").unwrap().clone();
        assert!(rel_str.ends_with(":00Z"), "expected :00Z UTC: {rel_str}");
        let rel_secs = humantime::parse_rfc3339(&rel_str)
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            rel_secs >= del_now + 1800 && rel_secs <= del_now + 1980,
            "AutoReleaseTime {rel_str} ({rel_secs}) must be ~31m ahead of {del_now}"
        );
        let tag_call = f
            .calls_for("TagResources")
            .into_iter()
            .last()
            .expect("expected TagResources fallback");
        let applied_tags = sig::parse_tags(&tag_call.params);
        assert_eq!(
            applied_tags.get("cua-managed").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            applied_tags.get("cua-decommissioned").map(String::as_str),
            Some("true")
        );
        assert_eq!(f.instances.len(), 1);
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst.status, "Stopped");
        assert_eq!(inst.stopped_mode, "StopCharging");
        assert_eq!(inst.auto_release_time.as_deref(), Some(rel_str.as_str()));
        assert_eq!(
            inst.tags.get("cua-decommissioned").map(String::as_str),
            Some("true")
        );
        rel_str
    };

    let delete_error = delete_err.to_string();
    assert!(
        delete_error.contains("Forbidden.RAM")
            && delete_error.contains("AutoReleaseTime")
            && delete_error.contains(&rel_str),
        "scheduled deletion must retain its evidence: {delete_error}"
    );

    let listed = fix.sbx.list().await.unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].name, "win11-scp-del");
    assert_eq!(listed[0].status, Status::Suspended);
    let persisted = fix.sbx.persisted_details("win11-scp-del");
    assert_eq!(persisted.get("auto_release_time"), Some(&rel_str));
    assert_eq!(
        persisted.get(cua_sandbox_core::byoc::DETAIL_RELAY_MACHINE),
        original_details.get(cua_sandbox_core::byoc::DETAIL_RELAY_MACHINE)
    );

    let store = cua_byoc::Store::new(fix.home.path());
    let recorded = store
        .resources()
        .unwrap()
        .into_iter()
        .find(|r| r.id == inst_id)
        .expect("scheduled instance record must be retained");
    assert_eq!(recorded.state, "stopped");
    assert_eq!(recorded.extra.get("auto_release_time"), Some(&rel_str));
    let status = clouds.status(Some("aliyun-ecs")).await.unwrap();
    let status_instance = status
        .resources
        .iter()
        .find(|r| r.id == inst_id)
        .expect("cloud status must retain the scheduled instance");
    assert_eq!(status_instance.state, "stopped");
    let audits = store.audit_entries(1000).unwrap();
    assert!(
        audits.iter().any(|a| {
            a.action == "resource_deleted" && a.id == inst_id && a.outcome == "failed"
        })
    );
    assert!(
        !audits
            .iter()
            .any(|a| { a.action == "resource_deleted" && a.id == inst_id && a.outcome == "ok" })
    );

    // A scheduled instance remains visible in every sweep, while shared network
    // parts stay held until its provider-attested release timer fires.
    let swept_normal = clouds
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    let normal_instance = swept_normal
        .resources
        .iter()
        .find(|i| i.resource.id == inst_id)
        .expect("normal sweep must list the scheduled instance");
    assert_eq!(normal_instance.resource.state, "stopped");
    assert_ne!(normal_instance.action, "deleted");
    let swept_all = clouds.sweep(Some("aliyun-ecs"), false, true).await.unwrap();
    let held_instance = swept_all
        .resources
        .iter()
        .find(|i| i.resource.id == inst_id)
        .expect("forced sweep must list the scheduled instance");
    assert_eq!(held_instance.action, "keep");
    assert_eq!(held_instance.resource.state, "stopped");
    assert!(
        held_instance.reason.contains("DeleteInstance") && held_instance.reason.contains(&rel_str),
        "expected decommission reason and provider-read schedule: {held_instance:?}"
    );
    assert!(
        swept_all
            .resources
            .iter()
            .filter(|i| i.resource.resource_type != "instance")
            .all(|i| i.action == "keep" && i.reason.contains("AutoReleaseTime")),
        "expected AutoReleaseTime network holds: {swept_all:?}"
    );

    // Direct `CloudApi::delete` on a held shared network part must return a clean diagnostic
    // error rather than an internal prefix token.
    let held_vsw = swept_all
        .resources
        .iter()
        .find(|i| i.resource.resource_type == "vswitch")
        .unwrap()
        .resource
        .id
        .clone();
    let held_vsw_res = Resource {
        provider: "aliyun-ecs".into(),
        id: held_vsw,
        resource_type: "vswitch".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    let direct_del_err = fix
        .api
        .delete(&conn(&fix.api), &held_vsw_res, &fix.owner)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        direct_del_err.contains("cannot delete vswitch")
            && direct_del_err.contains("AutoReleaseTime")
            && !direct_del_err.contains("cua-decommissioning-hold"),
        "unexpected direct delete error: {direct_del_err}"
    );

    // `disconnect --delete` fails clearly naming AutoReleaseTime hold while instance still exists,
    // then succeeds cleanly once AutoReleaseTime releases the instance.
    let disc_err = clouds.disconnect("aliyun-ecs", true).await.unwrap_err();
    assert!(
        disc_err.to_string().contains("AutoReleaseTime"),
        "expected AutoReleaseTime guidance in disconnect error: {disc_err}"
    );

    // Repeating deletion of the still-visible decommissioned instance stays
    // pending and does not issue another DeleteInstance.
    fix.s.lock().unwrap().calls.clear();
    let repeated = fix.sbx.delete("win11-scp-del").await.unwrap_err();
    assert!(repeated.to_string().contains("AutoReleaseTime"));
    assert_eq!(fix.s.lock().unwrap().count_calls("DeleteInstance"), 0);
    assert!(store.resources().unwrap().iter().any(|r| r.id == inst_id));

    // Only the instance's actual disappearance permits record and state removal.
    fix.s.lock().unwrap().instances.clear();
    fix.sbx.delete("win11-scp-del").await.unwrap();
    assert!(fix.sbx.list().await.unwrap().is_empty());
    assert!(!store.resources().unwrap().iter().any(|r| r.id == inst_id));
    assert!(
        !clouds
            .status(Some("aliyun-ecs"))
            .await
            .unwrap()
            .resources
            .iter()
            .any(|r| r.id == inst_id)
    );
    let disc_ok = clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(disc_ok.left.is_empty(), "{disc_ok:?}");
    let f = fix.s.lock().unwrap();
    assert!(f.vpcs.is_empty() && f.vswitches.is_empty() && f.security_groups.is_empty());
    drop(fix.home);
}

#[tokio::test]
async fn delete_instance_forbidden_handles_pending_and_failed_boot_rollback() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;

    // Pending instance waits until Running before StopInstance(ForceStop=true, StopCharging).
    {
        let mut f = fix.s.lock().unwrap();
        f.seed_instance(FakeInstance {
            instance_id: "i-scp-pending".into(),
            instance_name: "cua-aliyun-ecs-pending".into(),
            region_id: "cn-hangzhou".into(),
            status: "Pending".into(),
            pending_describe_ticks: 2,
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), fix.owner_tag.clone()),
                ("cua-expires".into(), "0".into()),
            ]),
            ..Default::default()
        });
        f.calls.clear();
    }
    let pend_res = Resource {
        provider: "aliyun-ecs".into(),
        id: "i-scp-pending".into(),
        resource_type: "instance".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    let pending_err = fix
        .api
        .delete(&conn(&fix.api), &pend_res, &fix.owner)
        .await
        .unwrap_err();
    assert!(pending_err.to_string().contains("AutoReleaseTime"));
    {
        let f = fix.s.lock().unwrap();
        let inst = f.instances.get("i-scp-pending").unwrap();
        assert_eq!(inst.status, "Stopped");
        assert_eq!(inst.stopped_mode, "StopCharging");
        assert_eq!(
            inst.tags.get("cua-decommissioned").map(String::as_str),
            Some("true")
        );
        let stop_call = f.calls_for("StopInstance").into_iter().last().unwrap();
        assert_eq!(
            stop_call.params.get("ForceStop").map(String::as_str),
            Some("true")
        );
    }

    // Failed boot rollback retains its schedule and remains eligible for sweep deletion.
    {
        let mut f = fix.s.lock().unwrap();
        f.on_run_instance = None;
        f.boot_fail = Some(BootFailMode::StopImmediately);
        f.calls.clear();
    }
    let mut opts_fail = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts_fail.contrib = Some("aliyun-ecs".into());
    opts_fail.name = Some("win11-scp-rollback".into());
    opts_fail.os = "windows".into();
    opts_fail.disk_gb = Some(100);
    opts_fail.ready_timeout = Duration::from_millis(80);
    assert!(fix.sbx.create(opts_fail).await.is_err());
    fix.s.lock().unwrap().boot_fail = None;
    assert_eq!(fix.s.lock().unwrap().instances.len(), 2);
    assert!(fix.s.lock().unwrap().instances.values().all(|i| {
        i.status == "Stopped"
            && i.stopped_mode == "StopCharging"
            && i.tags.get("cua-decommissioned").map(String::as_str) == Some("true")
    }));
    assert!(fix.sbx.list().await.unwrap().is_empty());
    let store = cua_byoc::Store::new(fix.home.path());
    let rollback = store
        .resources()
        .unwrap()
        .into_iter()
        .find(|r| r.sandbox == "aliyun-ecs:win11-scp-rollback")
        .expect("failed-create rollback record must remain");
    assert_eq!(rollback.state, "failed");
    let rollback_release = fix.s.lock().unwrap().instances[&rollback.id]
        .auto_release_time
        .clone()
        .unwrap();
    assert_eq!(
        rollback.extra.get("auto_release_time"),
        Some(&rollback_release)
    );
}

#[tokio::test]
async fn failed_create_rollback_without_ttl_remains_sweep_deletable_after_refresh() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    {
        let mut f = fix.s.lock().unwrap();
        f.on_run_instance = None;
        f.boot_fail = Some(BootFailMode::StopImmediately);
        f.forbidden_actions
            .insert("ecs:ModifyInstanceAutoReleaseTime".into());
    }
    let mut opts = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts.contrib = Some("aliyun-ecs".into());
    opts.name = Some("win11-no-ttl-rollback".into());
    opts.os = "windows".into();
    opts.disk_gb = Some(100);
    opts.ttl = Some(Duration::ZERO);
    opts.ready_timeout = Duration::from_millis(80);
    assert!(fix.sbx.create(opts).await.is_err());

    let store = cua_byoc::Store::new(fix.home.path());
    let rollback = store
        .resources()
        .unwrap()
        .into_iter()
        .find(|r| r.sandbox == "aliyun-ecs:win11-no-ttl-rollback")
        .expect("failed-create rollback record must remain");
    assert_eq!(rollback.expires, 0);
    let delete_calls = fix.s.lock().unwrap().count_calls("DeleteInstance");

    let swept = fix
        .clouds()
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    let row = swept
        .resources
        .iter()
        .find(|item| item.resource.id == rollback.id)
        .expect("rollback instance must remain in sweep");
    assert_eq!(row.action, "failed");
    assert!(row.reason.contains("a failed create left it"), "{row:?}");
    assert!(
        row.reason.contains("ModifyInstanceAutoReleaseTime"),
        "{row:?}"
    );
    assert_eq!(
        fix.s.lock().unwrap().count_calls("DeleteInstance"),
        delete_calls + 1,
        "a no-TTL failed create must retry deletion"
    );
    let retained = store
        .resources()
        .unwrap()
        .into_iter()
        .find(|r| r.id == rollback.id)
        .unwrap();
    assert_eq!(retained.state, "failed");
}

#[tokio::test]
async fn sweep_first_forbidden_delete_refreshes_held_item_and_record() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    let store = cua_byoc::Store::new(fix.home.path());
    let id = "i-sweep-first-held";
    let expires = model::now().saturating_sub(60);
    let tags = BTreeMap::from([
        ("cua-managed".into(), "true".into()),
        ("cua-owner".into(), fix.owner_tag.clone()),
        ("cua-expires".into(), expires.to_string()),
    ]);
    store
        .record(Resource {
            provider: "aliyun-ecs".into(),
            id: id.into(),
            resource_type: "instance".into(),
            name: "cua-sweep-first-held".into(),
            region: "cn-hangzhou".into(),
            sandbox: "aliyun-ecs:sweep-first-held".into(),
            state: "running".into(),
            expires,
            tags: tags.clone(),
            ..Default::default()
        })
        .unwrap();
    fix.s.lock().unwrap().seed_instance(FakeInstance {
        instance_id: id.into(),
        instance_name: "cua-sweep-first-held".into(),
        region_id: "cn-hangzhou".into(),
        status: "Running".into(),
        tags,
        ..Default::default()
    });

    let clouds = fix.clouds();
    let swept = clouds
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    let row = swept
        .resources
        .iter()
        .find(|item| item.resource.id == id)
        .expect("held instance must remain in sweep");
    let release = fix.s.lock().unwrap().instances[id]
        .auto_release_time
        .clone()
        .unwrap();
    assert_eq!(row.action, "keep");
    assert_eq!(row.resource.state, "stopped");
    assert_eq!(row.resource.sandbox, "aliyun-ecs:sweep-first-held");
    assert!(row.reason.contains(&release), "{row:?}");

    let record = store
        .resources()
        .unwrap()
        .into_iter()
        .find(|r| r.id == id)
        .unwrap();
    assert_eq!(record.state, "stopped");
    assert_eq!(record.extra.get("auto_release_time"), Some(&release));
    let status = clouds.status(Some("aliyun-ecs")).await.unwrap();
    let status_row = status.resources.iter().find(|r| r.id == id).unwrap();
    assert_eq!(status_row.state, "stopped");
}

#[tokio::test]
async fn delete_instance_forbidden_sweeps_expired_orphan_and_enforces_cloud_backstop() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    let clouds = fix.clouds();

    // Expired orphan with NO cloud AutoReleaseTime gets StopCharging + ~31m timer armed.
    fix.s.lock().unwrap().seed_instance(FakeInstance {
        instance_id: "i-scp-expired".into(),
        instance_name: "cua-aliyun-ecs-scp-exp".into(),
        region_id: "cn-hangzhou".into(),
        status: "Running".into(),
        auto_release_time: None,
        tags: BTreeMap::from([
            ("cua-managed".into(), "true".into()),
            ("cua-owner".into(), fix.owner_tag.clone()),
            (
                "cua-expires".into(),
                model::now().saturating_sub(60).to_string(),
            ),
            ("cua-machine".into(), "cloud-scp-exp".into()),
        ]),
        ..Default::default()
    });
    let exp_now = model::now();
    let swept_exp = clouds
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    let expired = swept_exp
        .resources
        .iter()
        .find(|i| i.resource.id == "i-scp-expired")
        .expect("scheduled expired instance must remain in sweep");
    assert_eq!(expired.action, "keep");
    assert!(expired.reason.contains("AutoReleaseTime"));
    {
        let f = fix.s.lock().unwrap();
        let exp_inst = f.instances.get("i-scp-expired").unwrap();
        assert_eq!(exp_inst.status, "Stopped");
        assert_eq!(exp_inst.stopped_mode, "StopCharging");
        assert_eq!(
            exp_inst.tags.get("cua-decommissioned").map(String::as_str),
            Some("true")
        );
        let rel_str = exp_inst
            .auto_release_time
            .as_deref()
            .expect("expired orphan missing cloud AutoReleaseTime must have timer armed");
        let rel_secs = humantime::parse_rfc3339(rel_str)
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(rel_secs >= exp_now + 1800 && rel_secs <= exp_now + 1980);
    }

    // --no-ttl (expires == 0) remains held when ModifyInstanceAutoReleaseTime is allowed.
    fix.s.lock().unwrap().seed_instance(FakeInstance {
        instance_id: "i-scp-no-ttl-allowed".into(),
        instance_name: "cua-aliyun-ecs-no-ttl-ok".into(),
        region_id: "cn-hangzhou".into(),
        status: "Running".into(),
        tags: BTreeMap::from([
            ("cua-managed".into(), "true".into()),
            ("cua-owner".into(), fix.owner_tag.clone()),
            ("cua-expires".into(), "0".into()),
        ]),
        ..Default::default()
    });
    let no_ttl_allowed = fix
        .api
        .delete(
            &conn(&fix.api),
            &Resource {
                provider: "aliyun-ecs".into(),
                id: "i-scp-no-ttl-allowed".into(),
                resource_type: "instance".into(),
                region: "cn-hangzhou".into(),
                expires: 0,
                ..Default::default()
            },
            &fix.owner,
        )
        .await
        .unwrap_err();
    assert!(no_ttl_allowed.to_string().contains("AutoReleaseTime"));
    assert!(
        fix.s
            .lock()
            .unwrap()
            .instances
            .get("i-scp-no-ttl-allowed")
            .unwrap()
            .auto_release_time
            .is_some()
    );

    // If ModifyInstanceAutoReleaseTime is also forbidden, a missing cloud timer
    // fails and an existing provider timer remains the held release deadline.
    let future_rel = model::rfc3339(((model::now() + 28800).div_ceil(60)) * 60);
    {
        let mut f = fix.s.lock().unwrap();
        f.forbidden_actions
            .insert("ecs:ModifyInstanceAutoReleaseTime".into());
        f.seed_instance(FakeInstance {
            instance_id: "i-scp-no-ttl".into(),
            instance_name: "cua-aliyun-ecs-no-ttl".into(),
            region_id: "cn-hangzhou".into(),
            status: "Running".into(),
            auto_release_time: None,
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), fix.owner_tag.clone()),
                ("cua-expires".into(), "0".into()),
            ]),
            ..Default::default()
        });
        f.seed_instance(FakeInstance {
            instance_id: "i-scp-with-ttl".into(),
            instance_name: "cua-aliyun-ecs-with-ttl".into(),
            region_id: "cn-hangzhou".into(),
            status: "Running".into(),
            auto_release_time: Some(future_rel.clone()),
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), fix.owner_tag.clone()),
                ("cua-expires".into(), (model::now() + 28800).to_string()),
            ]),
            ..Default::default()
        });
    }
    let no_ttl_err = fix
        .api
        .delete(
            &conn(&fix.api),
            &Resource {
                provider: "aliyun-ecs".into(),
                id: "i-scp-no-ttl".into(),
                resource_type: "instance".into(),
                region: "cn-hangzhou".into(),
                expires: 0,
                ..Default::default()
            },
            &fix.owner,
        )
        .await
        .unwrap_err();
    assert!(
        no_ttl_err
            .to_string()
            .contains("ModifyInstanceAutoReleaseTime"),
        "{no_ttl_err}"
    );
    assert_eq!(
        fix.s.lock().unwrap().instances["i-scp-no-ttl"].status,
        "Stopped"
    );

    let with_ttl_err = fix
        .api
        .delete(
            &conn(&fix.api),
            &Resource {
                provider: "aliyun-ecs".into(),
                id: "i-scp-with-ttl".into(),
                resource_type: "instance".into(),
                region: "cn-hangzhou".into(),
                expires: model::now() + 28800,
                ..Default::default()
            },
            &fix.owner,
        )
        .await
        .unwrap_err();
    assert!(
        with_ttl_err.to_string().contains(&future_rel),
        "held error must expose the existing provider timer: {with_ttl_err}"
    );
    let listed = fix
        .api
        .list_owned(&conn(&fix.api), &fix.owner)
        .await
        .unwrap();
    let listed_with_ttl = listed
        .iter()
        .find(|r| r.id == "i-scp-with-ttl")
        .expect("modification-denied instance must remain listed");
    assert_eq!(listed_with_ttl.state, "stopped");
    assert_eq!(
        listed_with_ttl.extra.get("auto_release_time"),
        Some(&future_rel)
    );
    let f = fix.s.lock().unwrap();
    let with_ttl = f.instances.get("i-scp-with-ttl").unwrap();
    assert_eq!(with_ttl.status, "Stopped");
    assert_eq!(with_ttl.stopped_mode, "StopCharging");
    assert_eq!(
        with_ttl.tags.get("cua-decommissioned").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn delete_after_region_switch_refreshes_record_in_instance_region() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    let mut opts = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts.contrib = Some("aliyun-ecs".into());
    opts.name = Some("win11-region-switch".into());
    opts.os = "windows".into();
    opts.disk_gb = Some(100);
    opts.ready_timeout = Duration::from_secs(10);
    let sb = fix.sbx.create(opts).await.unwrap();
    let inst_id = sb.provider_details()["id"].clone();

    let clouds = fix.clouds();
    clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-beijing".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                windows_image_id: Some("m-2zeeqpoalo73r1psdqjb".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    let store = cua_byoc::Store::new(fix.home.path());
    assert_eq!(
        store.connection("aliyun-ecs").unwrap().unwrap().region,
        "cn-beijing"
    );

    let err = sb.delete().await.unwrap_err();
    assert!(err.to_string().contains("AutoReleaseTime"), "{err}");
    let release = fix.s.lock().unwrap().instances[&inst_id]
        .auto_release_time
        .clone()
        .unwrap();
    let record = store
        .resources()
        .unwrap()
        .into_iter()
        .find(|r| r.id == inst_id)
        .unwrap();
    assert_eq!(record.region, "cn-hangzhou");
    assert_eq!(record.state, "stopped");
    assert_eq!(record.extra.get("auto_release_time"), Some(&release));
    assert_eq!(
        fix.sbx.persisted_details("win11-region-switch")["auto_release_time"],
        release
    );
}

#[tokio::test]
async fn terminated_instance_remains_in_sweep_and_blocks_disconnect_until_exact_absence() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    {
        let mut f = fix.s.lock().unwrap();
        f.forbidden_actions.remove("ecs:DeleteInstance");
        f.delete_instance_without_removal = true;
    }
    let mut opts = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts.contrib = Some("aliyun-ecs".into());
    opts.name = Some("win11-terminated-visible".into());
    opts.os = "windows".into();
    opts.disk_gb = Some(100);
    opts.ready_timeout = Duration::from_secs(10);
    let sb = fix.sbx.create(opts).await.unwrap();
    let inst_id = sb.provider_details()["id"].clone();
    fix.s
        .lock()
        .unwrap()
        .instances
        .get_mut(&inst_id)
        .unwrap()
        .status = "Terminated".into();

    let err = sb.delete().await.unwrap_err();
    assert!(matches!(err, Error::Timeout(_)), "{err:?}");
    let store = cua_byoc::Store::new(fix.home.path());
    assert!(store.resources().unwrap().iter().any(|r| r.id == inst_id));

    let clouds = fix.clouds();
    let swept = clouds
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    let row = swept
        .resources
        .iter()
        .find(|item| item.resource.id == inst_id)
        .expect("a visible Terminated instance must remain in sweep");
    assert_eq!(row.resource.state, "terminated");
    assert_eq!(row.action, "keep");

    let err = clouds.disconnect("aliyun-ecs", true).await.unwrap_err();
    assert!(err.to_string().contains(&inst_id), "{err}");
    assert!(store.connection("aliyun-ecs").unwrap().is_some());
    assert!(store.resources().unwrap().iter().any(|r| r.id == inst_id));

    fix.s.lock().unwrap().instances.clear();
    clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(store.connection("aliyun-ecs").unwrap().is_none());
    assert!(!store.resources().unwrap().iter().any(|r| r.id == inst_id));
}

#[tokio::test]
async fn delete_instance_success_requires_provider_absence_before_completion() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    {
        let mut f = fix.s.lock().unwrap();
        f.forbidden_actions.remove("ecs:DeleteInstance");
        f.delete_instance_without_removal = true;
        for (id, status) in [
            ("i-delete-visible", "Running"),
            ("i-delete-terminated", "Terminated"),
        ] {
            f.seed_instance(FakeInstance {
                instance_id: id.into(),
                instance_name: format!("cua-{id}"),
                region_id: "cn-hangzhou".into(),
                status: status.into(),
                tags: BTreeMap::from([
                    ("cua-managed".into(), "true".into()),
                    ("cua-owner".into(), fix.owner_tag.clone()),
                ]),
                ..Default::default()
            });
        }
    }

    for (id, status) in [
        ("i-delete-visible", "Running"),
        ("i-delete-terminated", "Terminated"),
    ] {
        fix.s.lock().unwrap().calls.clear();
        let err = fix
            .api
            .delete(
                &conn(&fix.api),
                &Resource {
                    provider: "aliyun-ecs".into(),
                    id: id.into(),
                    resource_type: "instance".into(),
                    region: "cn-hangzhou".into(),
                    ..Default::default()
                },
                &fix.owner,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        let f = fix.s.lock().unwrap();
        assert_eq!(f.count_calls("DeleteInstance"), 1);
        assert_eq!(f.instances[id].status, status);
    }
}

#[tokio::test]
async fn delete_instance_forbidden_tag_failure_still_returns_held() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    {
        let mut f = fix.s.lock().unwrap();
        f.forbidden_actions.insert("ecs:TagResources".into());
        f.seed_instance(FakeInstance {
            instance_id: "i-tag-denied".into(),
            instance_name: "cua-aliyun-ecs-tag-denied".into(),
            region_id: "cn-hangzhou".into(),
            status: "Running".into(),
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), fix.owner_tag.clone()),
            ]),
            ..Default::default()
        });
    }
    let err = fix
        .api
        .delete(
            &conn(&fix.api),
            &Resource {
                provider: "aliyun-ecs".into(),
                id: "i-tag-denied".into(),
                resource_type: "instance".into(),
                region: "cn-hangzhou".into(),
                ..Default::default()
            },
            &fix.owner,
        )
        .await
        .unwrap_err();
    let actual_release = fix.s.lock().unwrap().instances["i-tag-denied"]
        .auto_release_time
        .clone()
        .unwrap();
    assert!(
        err.to_string().contains("Forbidden.RAM") && err.to_string().contains(&actual_release),
        "tag failure must not erase the scheduled outcome: {err}"
    );
    let listed = fix
        .api
        .list_owned(&conn(&fix.api), &fix.owner)
        .await
        .unwrap();
    let instance = listed
        .iter()
        .find(|r| r.id == "i-tag-denied")
        .expect("tag failure must not hide the scheduled instance");
    assert_eq!(instance.state, "stopped");
    assert_eq!(
        instance.extra.get("auto_release_time"),
        Some(&actual_release)
    );
    assert!(!instance.tags.contains_key("cua-decommissioned"));
}

#[tokio::test]
async fn describe_instances_rejects_malformed_multiple_and_mismatched_rows() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::clear();
    let fix = ForbiddenDeleteFixture::start().await;
    let resource = Resource {
        provider: "aliyun-ecs".into(),
        id: "i-exact".into(),
        resource_type: "instance".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    let cases = [
        ("missing array", json!({ "Instances": {} })),
        (
            "multiple rows",
            json!({ "Instances": { "Instance": [
                { "InstanceId": "i-exact" },
                { "InstanceId": "i-exact" }
            ] } }),
        ),
        (
            "mismatched ID",
            json!({ "Instances": { "Instance": [{ "InstanceId": "i-other" }] } }),
        ),
    ];
    for (case, response) in cases {
        fix.s.lock().unwrap().describe_instances_response = Some(response);
        let err = fix
            .api
            .describe(&conn(&fix.api), &resource)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Cloud(_)), "{case}: {err:?}");
    }
}
