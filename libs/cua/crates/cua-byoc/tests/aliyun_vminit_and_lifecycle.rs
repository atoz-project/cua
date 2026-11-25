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
use cua_sandbox_core::{CreateOptions, Error, ProviderKind, Sandboxes};
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
    sb.delete().await.unwrap();

    {
        let f = fix.s.lock().unwrap();
        // Single inspect_owned_instance call reused by decommission_without_delete (+1 poll).
        assert!(f.count_calls("DescribeInstances") <= 2, "{:?}", f.calls);
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
        let rel_str = rel_call.params.get("AutoReleaseTime").unwrap();
        assert!(rel_str.ends_with(":00Z"), "expected :00Z UTC: {rel_str}");
        let rel_secs = humantime::parse_rfc3339(rel_str)
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
    }

    assert!(fix.sbx.list().await.unwrap().is_empty());

    // `sweep --delete` keeps shared network parts for active instances / unforced runs,
    // while `sweep --all --delete` reports the AutoReleaseTime decommissioning hold.
    let swept_normal = clouds
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    assert!(
        swept_normal
            .resources
            .iter()
            .all(|i| i.action == "keep" && i.reason == "shared by Cua sandboxes here"),
        "{swept_normal:?}"
    );
    let swept_all = clouds.sweep(Some("aliyun-ecs"), false, true).await.unwrap();
    assert!(
        swept_all.resources.iter().all(|i| {
            i.resource.resource_type != "instance"
                && i.action == "keep"
                && i.reason.contains("AutoReleaseTime")
        }),
        "expected AutoReleaseTime hold reason: {swept_all:?}"
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

    // Repeating `api.delete` on a decommissioned instance is a no-op with 0 DeleteInstance calls.
    let inst_id = fix
        .s
        .lock()
        .unwrap()
        .instances
        .keys()
        .next()
        .unwrap()
        .clone();
    let decomm_res = Resource {
        provider: "aliyun-ecs".into(),
        id: inst_id,
        resource_type: "instance".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    fix.s.lock().unwrap().calls.clear();
    fix.api
        .delete(&conn(&fix.api), &decomm_res, &fix.owner)
        .await
        .unwrap();
    assert_eq!(fix.s.lock().unwrap().count_calls("DeleteInstance"), 0);

    // Simulate cloud AutoReleaseTime firing: shared network parts now delete cleanly.
    fix.s.lock().unwrap().instances.clear();
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
    fix.api
        .delete(&conn(&fix.api), &pend_res, &fix.owner)
        .await
        .unwrap();
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

    // Failed boot rollback when DeleteInstance is forbidden degrades cleanly to StopCharging.
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
    assert!(
        swept_exp
            .resources
            .iter()
            .any(|i| i.resource.id == "i-scp-expired" && i.action == "deleted"),
        "{swept_exp:?}"
    );
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

    // --no-ttl (expires == 0) succeeds when ModifyInstanceAutoReleaseTime is allowed.
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
    fix.api
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
        .unwrap();
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

    // If ModifyInstanceAutoReleaseTime is also forbidden: fail on missing cloud AutoReleaseTime,
    // succeed when cloud AutoReleaseTime is already armed at launch.
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
            auto_release_time: Some(future_rel),
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

    fix.api
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
        .unwrap();
    let f = fix.s.lock().unwrap();
    let with_ttl = f.instances.get("i-scp-with-ttl").unwrap();
    assert_eq!(with_ttl.status, "Stopped");
    assert_eq!(with_ttl.stopped_mode, "StopCharging");
    assert_eq!(
        with_ttl.tags.get("cua-decommissioned").map(String::as_str),
        Some("true")
    );
}
