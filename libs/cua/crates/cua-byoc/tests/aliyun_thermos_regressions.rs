// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Regression tests for Aliyun ECS single-pass `prepare_provision`,
//! SKU-exact budget enforcement, `WindowsInitHeader` selection, cross-region
//! resolution, and fast `has_active_blocker` rollback.
#![cfg(feature = "aliyun-ecs")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use cua_byoc::RelayAccess;
use cua_byoc::aliyun_ecs::{AliyunEcs, TokenStore};
use cua_byoc::api::{CloudApi, Target, WindowsInitHeader};
use cua_byoc::model::{self, ProvisionSpec, Resource};
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::ConnectRequest;
use cua_sandbox_core::{CreateOptions, ProviderKind, Sandboxes};
use cua_spacesd_client::testing::{MockAuth, MockServer};
use serde_json::json;

#[path = "support/fake_aliyun.rs"]
mod fake_aliyun;
use fake_aliyun::{S, handle};

#[derive(Default)]
struct MemStore(Mutex<Option<String>>);

impl TokenStore for MemStore {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, t: &str) -> std::io::Result<()> {
        *self.0.lock().unwrap() = Some(t.into());
        Ok(())
    }
    fn clear(&self) -> bool {
        self.0.lock().unwrap().take().is_some()
    }
}

async fn start_fake(poll: Duration) -> (AliyunEcs, S) {
    let s: S = Arc::default();
    let app = axum::Router::new().fallback(handle).with_state(s.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let store = Arc::new(MemStore::default());
    let api = AliyunEcs::with_endpoints(&base, &base, &base, store, None).with_poll(poll);
    (api, s)
}

fn decode_b64(s: &str) -> String {
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
}

fn count_action(s: &S, action: &str) -> usize {
    s.lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| c.action == action)
        .count()
}

async fn build_connected_aliyun(
    budget_usd_month: Option<f64>,
    ttl_hours: Option<u32>,
    windows_image_id: Option<&str>,
    extra_images: Vec<serde_json::Value>,
    poll: Duration,
) -> (tempfile::TempDir, Sandboxes, S, Arc<FakeRelay>, MockServer) {
    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let mock_spacesd = MockServer::start(MockAuth::default()).await;
    let (api, s) = start_fake(poll).await;
    if !extra_images.is_empty() {
        s.lock().unwrap().images.extend(extra_images);
    }
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();
    let connected = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                windows_image_id: windows_image_id.map(str::to_string),
                ..Default::default()
            },
            budget_usd_month,
            ttl_hours,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(connected.provider.status, "connected", "{connected:?}");
    // Clear preflight calls from `connect_with` so create-only counts are exact.
    s.lock().unwrap().calls.clear();
    (home, sandboxes, s, relay, mock_spacesd)
}

fn install_online_hook(s: &S, relay: &Arc<FakeRelay>, mock_url: String) {
    let relay = relay.clone();
    s.lock().unwrap().on_run_instance = Some(Arc::new(move |_id, params| {
        for i in 1..=12 {
            if params.get(&format!("Tag.{i}.Key")).map(String::as_str) == Some(model::tag::MACHINE)
                && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
            {
                relay.tunnel(mid, &mock_url);
                relay.set_online(mid, true, "0.29.0");
            }
        }
    }));
}

#[tokio::test]
async fn create_runs_single_pass_prepare_provision_without_duplicate_api_calls() {
    // 1. Official Linux create: exactly 1 DescribeAvailableResource, 1 DescribeInstanceTypes, 1 DescribeImages.
    let (_home, sandboxes, s, relay, mock_spacesd) =
        build_connected_aliyun(None, None, None, vec![], Duration::from_millis(5)).await;
    install_online_hook(&s, &relay, mock_spacesd.url());

    let mut linux =
        CreateOptions::new(ProviderKind::Contrib, "registry.invalid/trycua/linux:24.04");
    linux.contrib = Some("aliyun-ecs".into());
    linux.name = Some("single-pass-linux".into());
    sandboxes.create(linux).await.unwrap();

    assert_eq!(
        count_action(&s, "DescribeAvailableResource"),
        1,
        "expected single DescribeAvailableResource call during create"
    );
    assert_eq!(
        count_action(&s, "DescribeInstanceTypes"),
        1,
        "expected single DescribeInstanceTypes call during create"
    );
    assert_eq!(
        count_action(&s, "DescribeImages"),
        1,
        "expected single DescribeImages call during create"
    );

    // 2. Official Windows fallback create: single pass AND `[powershell]` vminit header.
    s.lock().unwrap().calls.clear();
    let mut win_official = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_official.contrib = Some("aliyun-ecs".into());
    win_official.name = Some("single-pass-win-official".into());
    win_official.os = "windows".into();
    sandboxes.create(win_official).await.unwrap();

    assert_eq!(count_action(&s, "DescribeAvailableResource"), 1);
    assert_eq!(count_action(&s, "DescribeInstanceTypes"), 1);
    assert_eq!(count_action(&s, "DescribeImages"), 1);
    let official_ud = {
        let f = s.lock().unwrap();
        let run = f
            .calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap();
        decode_b64(run.params.get("UserData").unwrap())
    };
    assert!(
        official_ud.starts_with("[powershell]\r\n") || official_ud.starts_with("[powershell]\n"),
        "official Windows fallback must use Aliyun vminit [powershell] header, got: {:?}",
        &official_ud[..official_ud.len().min(80)]
    );

    // 3. Custom Windows image (connection-default): `#ps1_sysnative` header.
    let (_home2, sandboxes2, s2, relay2, mock_spacesd2) = build_connected_aliyun(
        None,
        None,
        Some("m-customwin202501"),
        vec![json!({
            "ImageId": "m-customwin202501",
            "ImageName": "custom-windows-golden",
            "ImageOwnerAlias": "self",
            "OSType": "windows",
            "Architecture": "x86_64",
            "Status": "Available",
            "CreationTime": "2025-03-01T00:00:00Z",
            "Size": 60
        })],
        Duration::from_millis(5),
    )
    .await;
    install_online_hook(&s2, &relay2, mock_spacesd2.url());

    let mut win_custom = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_custom.contrib = Some("aliyun-ecs".into());
    win_custom.name = Some("single-pass-win-custom".into());
    win_custom.os = "windows".into();
    sandboxes2.create(win_custom).await.unwrap();

    assert_eq!(count_action(&s2, "DescribeAvailableResource"), 1);
    assert_eq!(count_action(&s2, "DescribeInstanceTypes"), 1);
    assert_eq!(count_action(&s2, "DescribeImages"), 1);
    let custom_ud = {
        let f = s2.lock().unwrap();
        let run = f
            .calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap();
        decode_b64(run.params.get("UserData").unwrap())
    };
    assert!(
        custom_ud.starts_with("#ps1_sysnative\r\n") || custom_ud.starts_with("#ps1_sysnative\n"),
        "custom Windows image must use Cloudbase-Init #ps1_sysnative header, got: {:?}",
        &custom_ud[..custom_ud.len().min(80)]
    );
}

#[tokio::test]
async fn budget_checked_against_exact_resolved_sku_and_blocks_pricier_fallback() {
    // One-hour static estimate for a small Linux box (~$0.04/h) passes a $0.25 budget,
    // while the only in-stock dynamic SKU (`ecs.g7.4xlarge`, 16 vCPU / 64 GiB, ~$0.95/h)
    // exceeds $0.25 and must be refused before `RunInstances`.
    let (_home, sandboxes, s, relay, mock_spacesd) =
        build_connected_aliyun(Some(0.25), None, None, vec![], Duration::from_millis(5)).await;
    install_online_hook(&s, &relay, mock_spacesd.url());
    {
        let mut f = s.lock().unwrap();
        f.available_instance_types = vec!["ecs.g7.4xlarge".into()];
    }

    let mut o = CreateOptions::new(ProviderKind::Contrib, "registry.invalid/trycua/linux:24.04");
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some("budget-guard-box".into());
    let err = sandboxes.create(o).await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("budget") || msg.contains("limit") || msg.contains("month"),
        "expected budget refusal for pricier dynamic SKU, got: {err}"
    );
    assert_eq!(
        count_action(&s, "RunInstances"),
        0,
        "RunInstances must not be called when resolved SKU exceeds budget"
    );
}

#[tokio::test]
async fn prepare_provision_uses_spec_region_and_preserves_sku_and_header() {
    let (api, s) = start_fake(Duration::from_millis(5)).await;
    let mut conn = api
        .resolve(&Target {
            provider: "aliyun-ecs".into(),
            region: Some("cn-hangzhou".into()),
            token: Some("LTAI_TEST_AK:secret123".into()),
            ..Default::default()
        })
        .unwrap();
    api.stage_secret(&Target {
        provider: "aliyun-ecs".into(),
        token: Some("LTAI_TEST_AK:secret123".into()),
        ..Default::default()
    });
    conn.region = "cn-hangzhou".into();

    let mut spec = ProvisionSpec {
        name: "cross-region-win".into(),
        family: "windows".into(),
        image: "windows".into(),
        kind: "vm".into(),
        region: "cn-shanghai".into(),
        cpus: Some(4),
        memory_mb: Some(8 * 1024),
        disk_gb: 60,
        user_data: "[powershell]\r\nWrite-Host 'hi'\r\n".into(),
        tags: model::tags("owner1", "cross-region-win", "cloud-cr1", 1_900_000_000),
        ttl_secs: 3600,
        arch: "amd64".into(),
        ..Default::default()
    };

    let prep = api.prepare_provision(&conn, &spec).await.unwrap();
    assert_eq!(prep.windows_header, Some(WindowsInitHeader::AliyunVminit));
    let sizing = prep.sizing.as_ref().expect("resolved sizing");
    let resolved_sku = sizing
        .machine_type
        .as_deref()
        .expect("resolved machine_type");
    assert_eq!(resolved_sku, "ecs.c7.xlarge");

    spec.machine_type = resolved_sku.to_string();
    spec.provider_plan = prep.provider_plan.clone();
    api.provision(&conn, &spec).await.unwrap();

    let f = s.lock().unwrap();
    for action in [
        "DescribeAvailableResource",
        "DescribeImages",
        "RunInstances",
    ] {
        let matching: Vec<_> = f.calls.iter().filter(|c| c.action == action).collect();
        assert_eq!(matching.len(), 1, "expected 1 {action} call");
        assert_eq!(
            matching[0].params.get("RegionId").map(String::as_str),
            Some("cn-shanghai"),
            "{action} must target spec.region (cn-shanghai), not conn.region"
        );
    }
    let run = f.calls.iter().find(|c| c.action == "RunInstances").unwrap();
    assert_eq!(
        run.params.get("InstanceType").map(String::as_str),
        Some(resolved_sku),
        "launched SKU must exactly match the prepared SKU"
    );
}

#[tokio::test]
async fn fast_rollback_short_circuits_immediately_when_cua_owned_peer_uses_network() {
    // Use a long poll interval (5s): if rollback retried DependencyViolation instead
    // of short-circuiting on tries==0, this test would take >5s (and 376s in production).
    let (api, s) = start_fake(Duration::from_secs(5)).await;
    api.stage_secret(&Target {
        provider: "aliyun-ecs".into(),
        token: Some("LTAI_TEST_AK:secret123".into()),
        ..Default::default()
    });
    let conn = api
        .resolve(&Target {
            provider: "aliyun-ecs".into(),
            region: Some("cn-hangzhou".into()),
            ..Default::default()
        })
        .unwrap();

    let owner = "owner-peer";
    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-peer-1",
            "VpcName": "cua-vpc-peer",
            "Status": "Available",
            "CidrBlock": "10.0.0.0/16",
            "Tags": { "Tag": [
                { "Key": model::tag::MANAGED, "Value": "true" },
                { "Key": model::tag::OWNER, "Value": owner }
            ]}
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-peer-1",
            "VpcId": "vpc-peer-1",
            "ZoneId": "cn-hangzhou-h",
            "Status": "Available",
            "CidrBlock": "10.0.1.0/24",
            "Tags": { "Tag": [
                { "Key": model::tag::MANAGED, "Value": "true" },
                { "Key": model::tag::OWNER, "Value": owner }
            ]}
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-peer-1",
            "VpcId": "vpc-peer-1",
            "SecurityGroupName": "cua-sg-peer",
            "Tags": { "Tag": [
                { "Key": model::tag::MANAGED, "Value": "true" },
                { "Key": model::tag::OWNER, "Value": owner }
            ]}
        }));
        // A running Cua-owned peer instance in the same VSwitch/SG/VPC.
        f.instances.insert(
            "i-peer-running".into(),
            json!({
                "InstanceId": "i-peer-running",
                "InstanceName": "peer-box",
                "RegionId": "cn-hangzhou",
                "ZoneId": "cn-hangzhou-h",
                "Status": "Running",
                "VpcAttributes": {
                    "VpcId": "vpc-peer-1",
                    "VSwitchId": "vsw-peer-1"
                },
                "SecurityGroupIds": { "SecurityGroupId": ["sg-peer-1"] },
                "Tags": { "Tag": [
                    { "Key": model::tag::MANAGED, "Value": "true" },
                    { "Key": model::tag::OWNER, "Value": owner }
                ]}
            }),
        );
        f.transient_dependency_errors = 10;
    }

    let started = Instant::now();
    for (kind, id) in [
        ("vswitch", "vsw-peer-1"),
        ("security_group", "sg-peer-1"),
        ("vpc", "vpc-peer-1"),
    ] {
        let r = Resource {
            provider: "aliyun-ecs".into(),
            resource_type: kind.into(),
            id: id.into(),
            region: "cn-hangzhou".into(),
            name: id.into(),
            state: "active".into(),
            ..Default::default()
        };
        let err = api.delete(&conn, &r, owner).await.unwrap_err();
        assert!(
            err.to_string().contains("still in use")
                || err.to_string().contains("active")
                || err.to_string().contains("DependencyViolation"),
            "unexpected error for {kind}: {err}"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "fast rollback with active Cua-owned peer took {elapsed:?} (expected < 1s)"
    );
    assert_eq!(count_action(&s, "DeleteVSwitch"), 1);
    assert_eq!(count_action(&s, "DeleteSecurityGroup"), 1);
    assert_eq!(count_action(&s, "DeleteVpc"), 1);
}
