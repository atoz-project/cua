// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Hermetic end-to-end tests for `aliyun-ecs` existing VPC/VSwitch attachment
//! and private-only (`--no-public-ip`) networking (`#8`).
#![cfg(feature = "aliyun-ecs")]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use cua_byoc::RelayAccess;
use cua_byoc::aliyun_ecs::{AliyunEcs, TokenStore};
use cua_byoc::api::{CloudApi, Target};
use cua_byoc::model::{self, Tier};
use cua_byoc::testing::FakeProvider;
use cua_host::relay::AccountTokens;
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{CloudManager, ConnectRequest, RelayMode};
use cua_sandbox_core::{CreateOptions, Error, ProviderKind, Sandboxes};
use cua_spacesd_client::testing::{MockAuth, MockServer};
use serde_json::json;

#[path = "support/fake_aliyun.rs"]
mod fake_aliyun;
use fake_aliyun::{S, handle};

struct FailingTokens;

#[async_trait::async_trait]
impl AccountTokens for FailingTokens {
    async fn access_token(&self) -> cua_host::Result<String> {
        Err(cua_host::Error::Unauthenticated(
            "not signed in to cua.ai".into(),
        ))
    }
}

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

async fn start_aliyun(
    aliyun_config: Option<std::path::PathBuf>,
) -> (Arc<AliyunEcs>, S, Arc<MemStore>) {
    let s: S = Arc::default();
    let app = axum::Router::new().fallback(handle).with_state(s.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let store = Arc::new(MemStore::default());
    let api = Arc::new(
        AliyunEcs::with_endpoints(&base, &base, &base, store.clone(), aliyun_config)
            .with_poll(std::time::Duration::from_millis(5)),
    );
    (api, s, store)
}

fn seed_user_vpc(s: &S, region: &str, vpc_id: &str, vsw_id: &str, user_sg_id: Option<&str>) {
    let mut f = s.lock().unwrap();
    f.vpcs.push(json!({
        "VpcId": vpc_id,
        "RegionId": region,
        "Status": "Available",
        "CidrBlock": "10.20.0.0/16",
        "VpcName": "user-vpc",
    }));
    f.vswitches.push(json!({
        "VSwitchId": vsw_id,
        "VpcId": vpc_id,
        "RegionId": region,
        "ZoneId": format!("{region}-h"),
        "Status": "Available",
        "CidrBlock": "10.20.1.0/24",
        "AvailableIpAddressCount": 200,
    }));
    if let Some(sg_id) = user_sg_id {
        f.security_groups.push(json!({
            "SecurityGroupId": sg_id,
            "SecurityGroupName": "cua-sandboxes-lookalike",
            "VpcId": vpc_id,
            "RegionId": region,
            "Tags": { "Tag": [] }
        }));
    }
}

fn build_env(
    home: &std::path::Path,
    apis: Vec<Arc<dyn CloudApi>>,
    relay_url: &str,
) -> (Sandboxes, Arc<dyn CloudManager>) {
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.join("sandboxes")),
        home,
        apis,
        RelayAccess::new(relay_url.to_string(), Arc::new(FailingTokens)),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap().clone();
    (sandboxes, clouds)
}

#[tokio::test]
async fn non_aliyun_providers_reject_vpc_vswitch_and_no_public_ip_flags() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let aws_fake = FakeProvider::new("aws", Tier::Vm);
    let (_, clouds) = build_env(dir.path(), vec![aws_fake], &relay.url);

    for bad_target in [
        Target {
            provider: "aws".into(),
            vpc_id: Some("vpc-1".into()),
            vswitch_id: Some("vsw-1".into()),
            ..Default::default()
        },
        Target {
            provider: "aws".into(),
            no_public_ip: true,
            ..Default::default()
        },
        Target {
            provider: "aws".into(),
            vswitch_id: Some("vsw-1".into()),
            ..Default::default()
        },
    ] {
        let err = clouds.test(&bad_target).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

        let err = clouds.connect(&bad_target, false, None).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

        let err = clouds
            .connect_with(&ConnectRequest {
                target: bad_target,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    }
}

#[tokio::test]
async fn preflight_rejects_incomplete_or_mismatched_vpc_vswitch_without_creating_resources() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let (api, s, store) = start_aliyun(None).await;
    let (_, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);

    let err = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            vswitch_id: Some("vsw-1".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(_)) && err.to_string().contains("vpc-id"),
        "{err:?}"
    );

    let err = clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                vpc_id: Some("vpc-1".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(_)) && err.to_string().contains("vswitch-id"),
        "{err:?}"
    );

    let err = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            vpc_id: Some("   ".into()),
            vswitch_id: Some("vsw-1".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-a",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-b",
            "VpcId": "vpc-other",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "AvailableIpAddressCount": 100,
        }));
    }
    let report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-a".into()),
            vswitch_id: Some("vsw-b".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!report.ok, "{report:?}");
    let joined = report
        .checks
        .iter()
        .map(|c| c.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        joined.contains("vpc-a") && joined.contains("vsw-b"),
        "{joined}"
    );

    let err = clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                vpc_id: Some("vpc-a".into()),
                vswitch_id: Some("vsw-b".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("vpc-a") || err.to_string().contains("vsw-b"),
        "{err}"
    );
    assert!(
        store.load().is_none(),
        "failed connect must not store creds"
    );

    seed_user_vpc(&s, "cn-shanghai", "vpc-sh", "vsw-sh", None);
    let report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-sh".into()),
            vswitch_id: Some("vsw-sh".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!report.ok, "{report:?}");
    let joined = report
        .checks
        .iter()
        .map(|c| c.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(joined.contains("vpc-sh"), "{joined}");

    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-full",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-full",
            "VpcId": "vpc-full",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "AvailableIpAddressCount": 0,
        }));
    }
    let report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-full".into()),
            vswitch_id: Some("vsw-full".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!report.ok, "{report:?}");

    let f = s.lock().unwrap();
    assert!(f.instances.is_empty());
    assert!(
        f.calls.iter().all(|c| !matches!(
            c.action.as_str(),
            "CreateVpc" | "CreateVSwitch" | "CreateSecurityGroup"
        )),
        "calls: {:?}",
        f.calls
    );
}

#[tokio::test]
async fn test_existing_vpc_and_standalone_no_public_ip_pass_dry_run_with_zero_resources() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let (api, s, _) = start_aliyun(None).await;
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-1",
        "vsw-user-1",
        Some("sg-user-1"),
    );
    let (_, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);

    let report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-user-1".into()),
            vswitch_id: Some("vsw-user-1".into()),
            no_public_ip: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(report.ok, "{report:?}");
    {
        let f = s.lock().unwrap();
        let run = f
            .calls
            .iter()
            .rev()
            .find(|c| c.action == "RunInstances")
            .unwrap();
        assert_eq!(run.params.get("DryRun").map(String::as_str), Some("true"));
        assert_eq!(
            run.params.get("VSwitchId").map(String::as_str),
            Some("vsw-user-1")
        );
        assert_eq!(
            run.params
                .get("InternetMaxBandwidthOut")
                .map(String::as_str),
            Some("0")
        );
        assert_eq!(
            f.calls
                .iter()
                .filter(
                    |c| c.params.get("DryRun").map(String::as_str) != Some("true")
                        && matches!(
                            c.action.as_str(),
                            "CreateVpc" | "CreateVSwitch" | "CreateSecurityGroup"
                        )
                )
                .count(),
            0
        );
        assert_eq!(
            f.calls.iter().filter(|c| c.action == "CreateVpc").count(),
            0
        );
        assert_eq!(f.vpcs.len(), 1);
        assert_eq!(f.vswitches.len(), 1);
        assert_eq!(f.security_groups.len(), 1);
        assert!(f.instances.is_empty());
    }

    let standalone = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            no_public_ip: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(standalone.ok, "{standalone:?}");
    let f = s.lock().unwrap();
    let run = f
        .calls
        .iter()
        .rev()
        .find(|c| c.action == "RunInstances")
        .unwrap();
    assert_eq!(
        run.params
            .get("InternetMaxBandwidthOut")
            .map(String::as_str),
        Some("0")
    );
}

fn decode_cloud_init_file(user_data: &str, path: &str) -> Option<String> {
    let marker = format!("path: {path}\n");
    let at = user_data.find(&marker)?;
    let rest = &user_data[at..];
    let c = rest.find("content: ")? + "content: ".len();
    let end = rest[c..].find('\n').unwrap_or(rest.len() - c);
    let raw = rest[c..c + end].trim();
    let bytes = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    String::from_utf8(bytes).ok()
}

fn env_value(env_file: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    env_file
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_string))
}

fn wire_fake_aliyun_to_relay(s: &S, relay: &Arc<FakeRelay>, mock_url: &str) {
    let relay = relay.clone();
    let mock_url = mock_url.to_string();
    s.lock().unwrap().on_run_instance = Some(Arc::new(move |_inst_id, params| {
        let user_data_b64 = params.get("UserData").map(String::as_str).unwrap_or("");
        let user_data = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(user_data_b64)
                .unwrap_or_default(),
        )
        .unwrap_or_default();
        if let Some(machine) = decode_cloud_init_file(&user_data, "/etc/cua/relay/machine-id") {
            let machine = machine.trim().to_string();
            let env_file =
                decode_cloud_init_file(&user_data, "/etc/cua/sandbox.env").unwrap_or_default();
            let env_tok = env_value(&env_file, "CUA_ENV_TOKEN");
            relay.tunnel(&machine, &mock_url);
            relay.set_static_online(&machine, true, env_tok.as_deref());
        }
    }));
}

fn create_opts(name: &str) -> CreateOptions {
    let mut o = CreateOptions::new(ProviderKind::Contrib, "registry.invalid/trycua/linux:24.04");
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some(name.into());
    o
}

#[tokio::test]
async fn existing_vpc_no_public_ip_with_static_relay_lifecycle_and_sg_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "intranet-static-relay-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _) = start_aliyun(None).await;
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-1",
        "vsw-user-1",
        Some("sg-lookalike"),
    );
    s.lock().unwrap().security_groups.push(json!({
        "SecurityGroupId": "sg-user-1",
        "SecurityGroupName": "user-default-sg",
        "VpcId": "vpc-user-1",
        "RegionId": "cn-hangzhou",
        "Tags": { "Tag": [] }
    }));
    wire_fake_aliyun_to_relay(&s, &relay, &mock_spacesd.url());

    let (sandboxes, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);

    let connected = clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                no_public_ip: true,
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();
    assert!(connected.provider.connected);
    assert_eq!(connected.provider.vpc_id.as_deref(), Some("vpc-user-1"));
    assert_eq!(connected.provider.vswitch_id.as_deref(), Some("vsw-user-1"));
    assert!(connected.provider.no_public_ip);

    let sb1 = sandboxes.create(create_opts("priv-box-1")).await.unwrap();
    let client = sb1.spacesd().await.unwrap();
    let health = client.health().await.unwrap();
    assert_eq!(health.status, 1);

    let sg_created_id = {
        let f = s.lock().unwrap();
        assert_eq!(
            f.calls.iter().filter(|c| c.action == "CreateVpc").count(),
            0
        );
        assert_eq!(
            f.calls
                .iter()
                .filter(|c| c.action == "CreateVSwitch")
                .count(),
            0
        );
        assert_eq!(
            f.calls
                .iter()
                .filter(|c| c.action == "CreateSecurityGroup"
                    && c.params.get("DryRun").map(String::as_str) != Some("true"))
                .count(),
            1
        );
        let create_sg = f
            .calls
            .iter()
            .find(|c| {
                c.action == "CreateSecurityGroup"
                    && c.params.get("DryRun").map(String::as_str) != Some("true")
            })
            .unwrap();
        assert_eq!(
            create_sg
                .params
                .get("SecurityGroupType")
                .map(String::as_str),
            Some("enterprise")
        );
        assert!(
            !f.calls
                .iter()
                .any(|c| c.action.starts_with("AuthorizeSecurityGroup")
                    && c.action != "AuthorizeSecurityGroupEgress")
        );
        assert_eq!(f.instances.len(), 1);
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst["VpcAttributes"]["VpcId"].as_str(), Some("vpc-user-1"));
        assert_eq!(
            inst["VpcAttributes"]["VSwitchId"].as_str(),
            Some("vsw-user-1")
        );
        let sg_id = inst["SecurityGroupIds"]["SecurityGroupId"][0]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(sg_id, "sg-lookalike");
        assert_ne!(sg_id, "sg-user-1");
        let rules = &f.security_group_rules[&sg_id];
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["Direction"].as_str(), Some("egress"));
        assert_eq!(rules[0]["DestCidrIp"].as_str(), Some("0.0.0.0/0"));

        let run_call = f
            .calls
            .iter()
            .rev()
            .find(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap();
        assert_eq!(
            run_call
                .params
                .get("InternetMaxBandwidthOut")
                .map(String::as_str),
            Some("0")
        );
        assert!(!run_call.params.contains_key("InternetChargeType"));
        assert_eq!(inst["InternetMaxBandwidthOut"].as_u64(), Some(0));
        assert_eq!(inst["InternetChargeType"].as_str(), Some(""));
        assert_eq!(
            inst["MetadataOptions"]["HttpTokens"].as_str(),
            Some("required")
        );

        let tags = cua_byoc::aliyun_net::tags_of(inst);
        for key in [
            model::tag::MANAGED,
            model::tag::OWNER,
            model::tag::SPACE,
            model::tag::MACHINE,
            model::tag::CREATED_BY,
            model::tag::EXPIRES,
        ] {
            assert!(tags.contains_key(key), "missing tag {key}: {tags:?}");
        }
        sg_id
    };

    let _sb2 = sandboxes.create(create_opts("priv-box-2")).await.unwrap();
    {
        let f = s.lock().unwrap();
        assert_eq!(
            f.calls
                .iter()
                .filter(|c| c.action == "CreateSecurityGroup"
                    && c.params.get("DryRun").map(String::as_str) != Some("true"))
                .count(),
            1
        );
        assert_eq!(f.instances.len(), 2);
        for inst in f.instances.values() {
            assert_eq!(
                inst["SecurityGroupIds"]["SecurityGroupId"][0].as_str(),
                Some(sg_created_id.as_str())
            );
        }
    }

    sandboxes.suspend("priv-box-1").await.unwrap();
    sandboxes.resume("priv-box-1").await.unwrap();
    sandboxes.delete("priv-box-1").await.unwrap();
    sandboxes.delete("priv-box-2").await.unwrap();
    assert!(s.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn standalone_no_public_ip_without_vpc_sets_zero_bandwidth() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "standalone-no-pub-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _) = start_aliyun(None).await;
    wire_fake_aliyun_to_relay(&s, &relay, &mock_spacesd.url());

    let (sandboxes, clouds) = build_env(dir.path(), vec![api], &relay.url);
    let connected = clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                no_public_ip: true,
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();
    assert!(connected.provider.no_public_ip);
    assert_eq!(connected.provider.vpc_id, None);
    assert_eq!(connected.provider.vswitch_id, None);

    let _sb = sandboxes
        .create(create_opts("no-pub-isolated"))
        .await
        .unwrap();
    {
        let f = s.lock().unwrap();
        let inst = f.instances.values().next().unwrap();
        assert_eq!(inst["InternetMaxBandwidthOut"].as_u64(), Some(0));
        assert_eq!(inst["InternetChargeType"].as_str(), Some(""));
        let run_call = f
            .calls
            .iter()
            .rev()
            .find(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap();
        assert_eq!(
            run_call
                .params
                .get("InternetMaxBandwidthOut")
                .map(String::as_str),
            Some("0")
        );
        assert!(!run_call.params.contains_key("InternetChargeType"));
    }
    sandboxes.suspend("no-pub-isolated").await.unwrap();
    sandboxes.resume("no-pub-isolated").await.unwrap();
    sandboxes.delete("no-pub-isolated").await.unwrap();
}

#[tokio::test]
async fn sweep_and_disconnect_delete_only_cua_instances_and_sg_preserving_user_network() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "cleanup-static-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _) = start_aliyun(None).await;
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-1",
        "vsw-user-1",
        Some("sg-lookalike"),
    );
    s.lock().unwrap().security_groups.push(json!({
        "SecurityGroupId": "sg-user-1",
        "SecurityGroupName": "user-sg",
        "VpcId": "vpc-user-1",
        "RegionId": "cn-hangzhou",
        "Tags": { "Tag": [] }
    }));
    wire_fake_aliyun_to_relay(&s, &relay, &mock_spacesd.url());

    let (sandboxes, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);
    clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                no_public_ip: true,
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();

    let _sb = sandboxes.create(create_opts("sweep-me")).await.unwrap();

    assert!(clouds.disconnect("aliyun-ecs", false).await.is_err());

    s.lock().unwrap().transient_dependency_errors = 2;
    let sweep = clouds.sweep(Some("aliyun-ecs"), false, true).await.unwrap();
    assert!(!sweep.dry_run);
    {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty(), "Cua instances must be deleted");
        assert_eq!(
            f.calls.iter().filter(|c| c.action == "DeleteVpc").count(),
            0
        );
        assert_eq!(
            f.calls
                .iter()
                .filter(|c| c.action == "DeleteVSwitch")
                .count(),
            0
        );
        assert_eq!(f.vpcs.len(), 1);
        assert_eq!(f.vswitches.len(), 1);
        let sg_ids: Vec<&str> = f
            .security_groups
            .iter()
            .filter_map(|g| g["SecurityGroupId"].as_str())
            .collect();
        assert_eq!(sg_ids, vec!["sg-lookalike", "sg-user-1"]);
    }

    let _sb2 = sandboxes.create(create_opts("disc-me")).await.unwrap();
    clouds.disconnect("aliyun-ecs", true).await.unwrap();
    {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty());
        assert_eq!(
            f.calls.iter().filter(|c| c.action == "DeleteVpc").count(),
            0
        );
        assert_eq!(
            f.calls
                .iter()
                .filter(|c| c.action == "DeleteVSwitch")
                .count(),
            0
        );
        assert_eq!(f.vpcs.len(), 1);
        assert_eq!(f.vswitches.len(), 1);
        let sg_ids: Vec<&str> = f
            .security_groups
            .iter()
            .filter_map(|g| g["SecurityGroupId"].as_str())
            .collect();
        assert_eq!(sg_ids, vec!["sg-lookalike", "sg-user-1"]);
    }
    let st = clouds.status(Some("aliyun-ecs")).await.unwrap();
    assert!(!st.providers[0].connected);
}

#[tokio::test]
async fn delete_refuses_user_vpc_vswitch_and_unowned_sg_even_if_tagged() {
    let (api, s, _) = start_aliyun(None).await;
    api.stage_secret(&Target {
        provider: "aliyun-ecs".into(),
        token: Some("LTAI_TEST_AK:secret123".into()),
        ..Default::default()
    });
    let mut conn = api
        .resolve(&Target {
            provider: "aliyun-ecs".into(),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-user-1".into()),
            vswitch_id: Some("vsw-user-1".into()),
            ..Default::default()
        })
        .unwrap();
    conn.vpc_id = Some("vpc-user-1".into());
    conn.vswitch_id = Some("vsw-user-1".into());

    let owner = "owner-abc";
    let tags = model::tags(owner, "sb", "m", 0);
    s.lock().unwrap().security_groups.push(json!({
        "SecurityGroupId": "sg-lookalike",
        "SecurityGroupName": "cua-sandboxes-lookalike",
        "VpcId": "vpc-user-1",
        "RegionId": "cn-hangzhou",
        "Tags": { "Tag": [] }
    }));

    for res in [
        model::Resource {
            provider: "aliyun-ecs".into(),
            id: "vpc-user-1".into(),
            resource_type: "vpc".into(),
            region: "cn-hangzhou".into(),
            tags: tags.clone(),
            ..Default::default()
        },
        model::Resource {
            provider: "aliyun-ecs".into(),
            id: "vsw-user-1".into(),
            resource_type: "vswitch".into(),
            region: "cn-hangzhou".into(),
            tags: tags.clone(),
            ..Default::default()
        },
        model::Resource {
            provider: "aliyun-ecs".into(),
            id: "sg-lookalike".into(),
            resource_type: "security_group".into(),
            region: "cn-hangzhou".into(),
            ..Default::default()
        },
    ] {
        assert!(api.delete(&conn, &res, owner).await.is_err(), "{res:?}");
        assert!(
            cua_byoc::aliyun_net::delete_part(&api, &conn, &res)
                .await
                .is_err(),
            "delete_part must also refuse user-owned {}",
            res.resource_type
        );
    }
    assert!(
        cua_byoc::aliyun_net::delete_part(
            &api,
            &conn,
            &model::Resource {
                provider: "aliyun-ecs".into(),
                id: "sg-missing".into(),
                resource_type: "security_group".into(),
                region: "cn-hangzhou".into(),
                ..Default::default()
            },
        )
        .await
        .is_ok(),
        "delete_part must treat already-deleted security_group as Ok(())"
    );
    {
        let vpc_tags: Vec<_> = cua_byoc::aliyun_net::part_tags(owner)
            .into_iter()
            .map(|(k, v)| json!({ "Key": k, "Value": v }))
            .collect();
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-user-1",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "IsDefault": false,
            "Tags": { "Tag": vpc_tags.clone() }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-user-1",
            "VpcId": "vpc-user-1",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "IsDefault": false,
            "Tags": { "Tag": vpc_tags }
        }));
    }
    let owned = api.list_owned(&conn, owner).await.unwrap();
    assert!(
        owned
            .iter()
            .all(|r| !matches!(r.resource_type.as_str(), "vpc" | "vswitch")),
        "existing-VPC mode must never list user VPC/VSwitch: {owned:?}"
    );
    let f = s.lock().unwrap();
    assert_eq!(
        f.calls.iter().filter(|c| c.action == "DeleteVpc").count(),
        0
    );
    assert_eq!(
        f.calls
            .iter()
            .filter(|c| c.action == "DeleteVSwitch")
            .count(),
        0
    );
    assert_eq!(
        f.calls
            .iter()
            .filter(|c| c.action == "DeleteSecurityGroup")
            .count(),
        0
    );
}

#[tokio::test]
async fn mode_switch_isolated_to_existing_vpc_cleans_prior_isolated_network_and_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "switch-mode-static-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _) = start_aliyun(None).await;
    wire_fake_aliyun_to_relay(&s, &relay, &mock_spacesd.url());

    let (sandboxes, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);

    clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();

    let _iso_sb = sandboxes.create(create_opts("iso-box-1")).await.unwrap();
    sandboxes.delete("iso-box-1").await.unwrap();

    let (iso_vpc_id, iso_vsw_id, iso_sg_id) = {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty());
        assert_eq!(f.vpcs.len(), 1);
        assert_eq!(f.vswitches.len(), 1);
        assert_eq!(f.security_groups.len(), 1);
        (
            f.vpcs[0]["VpcId"].as_str().unwrap().to_string(),
            f.vswitches[0]["VSwitchId"].as_str().unwrap().to_string(),
            f.security_groups[0]["SecurityGroupId"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    };

    let owner = cua_byoc::Store::new(dir.path()).owner_id().unwrap();
    let spoofed_tags: Vec<_> = cua_byoc::aliyun_net::part_tags(&owner)
        .into_iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-1",
        "vsw-user-1",
        Some("sg-user-lookalike"),
    );
    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-default-spoofed",
            "VpcName": cua_byoc::aliyun_net::vpc_name(&owner),
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": spoofed_tags.clone() }
        }));
        f.vpcs.push(json!({
            "VpcId": "vpc-other-spoofed",
            "VpcName": "corp-other-vpc",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": spoofed_tags }
        }));
    }

    clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                no_public_ip: true,
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();

    let disc = clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(disc.disconnected, "{disc:?}");
    assert!(disc.left.is_empty(), "{disc:?}");

    {
        let f = s.lock().unwrap();
        assert!(
            !f.vpcs.iter().any(|v| v["VpcId"] == iso_vpc_id),
            "prior isolated VPC {iso_vpc_id} must be deleted: {:?}",
            f.vpcs
        );
        assert!(
            !f.vswitches.iter().any(|v| v["VSwitchId"] == iso_vsw_id),
            "prior isolated VSwitch {iso_vsw_id} must be deleted: {:?}",
            f.vswitches
        );
        assert!(
            !f.security_groups
                .iter()
                .any(|g| g["SecurityGroupId"] == iso_sg_id),
            "prior isolated SG {iso_sg_id} must be deleted: {:?}",
            f.security_groups
        );

        let vpc_ids: Vec<&str> = f.vpcs.iter().filter_map(|v| v["VpcId"].as_str()).collect();
        assert_eq!(
            vpc_ids,
            vec!["vpc-user-1", "vpc-default-spoofed", "vpc-other-spoofed"]
        );
        let vsw_ids: Vec<&str> = f
            .vswitches
            .iter()
            .filter_map(|v| v["VSwitchId"].as_str())
            .collect();
        assert_eq!(vsw_ids, vec!["vsw-user-1"]);
        let sg_ids: Vec<&str> = f
            .security_groups
            .iter()
            .filter_map(|g| g["SecurityGroupId"].as_str())
            .collect();
        assert_eq!(sg_ids, vec!["sg-user-lookalike"]);

        for c in &f.calls {
            if c.action == "DeleteVpc" {
                assert_eq!(c.params.get("VpcId"), Some(&iso_vpc_id));
            }
            if c.action == "DeleteVSwitch" {
                assert_eq!(c.params.get("VSwitchId"), Some(&iso_vsw_id));
            }
        }
    }

    let store = cua_byoc::Store::new(dir.path());
    assert!(store.resources().unwrap().is_empty());
    let st = clouds.status(Some("aliyun-ecs")).await.unwrap();
    assert!(!st.providers[0].connected);
}

#[tokio::test]
async fn stale_store_user_network_records_do_not_wedge_sweep_or_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "stale-store-static-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);

    let (api, s, _) = start_aliyun(None).await;
    let store = cua_byoc::Store::new(dir.path());
    let owner = store.owner_id().unwrap();
    let spoofed_tags_kv = cua_byoc::aliyun_net::part_tags(&owner);
    let spoofed_tags: Vec<_> = spoofed_tags_kv
        .iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();

    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-user-1",
            "VpcName": cua_byoc::aliyun_net::vpc_name(&owner),
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "CidrBlock": "10.20.0.0/16",
            "Tags": { "Tag": spoofed_tags.clone() }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-user-1",
            "VSwitchName": cua_byoc::aliyun_net::vswitch_name(&owner, "cn-hangzhou-h"),
            "VpcId": "vpc-user-1",
            "RegionId": "cn-hangzhou",
            "ZoneId": "cn-hangzhou-h",
            "IsDefault": false,
            "Status": "Available",
            "CidrBlock": "10.20.1.0/24",
            "AvailableIpAddressCount": 200,
            "Tags": { "Tag": spoofed_tags.clone() }
        }));
        f.vpcs.push(json!({
            "VpcId": "vpc-default-spoofed",
            "VpcName": cua_byoc::aliyun_net::vpc_name(&owner),
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": spoofed_tags }
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-user-1",
            "SecurityGroupName": "user-sg",
            "VpcId": "vpc-user-1",
            "RegionId": "cn-hangzhou",
            "Tags": { "Tag": [] }
        }));
    }

    let (_, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);
    clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                no_public_ip: true,
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();

    let conn = store.connection("aliyun-ecs").unwrap().unwrap();
    assert!(
        cua_byoc::aliyun_net::delete_part(
            &api,
            &conn,
            &model::Resource {
                provider: "aliyun-ecs".into(),
                id: "vpc-default-spoofed".into(),
                resource_type: "vpc".into(),
                region: "cn-hangzhou".into(),
                tags: spoofed_tags_kv.clone(),
                ..Default::default()
            },
        )
        .await
        .is_err()
    );

    let seed_stale_records = || {
        for (ty, id) in [
            ("vpc", "vpc-user-1"),
            ("vswitch", "vsw-user-1"),
            ("vpc", "vpc-default-spoofed"),
            ("security_group", "sg-user-1"),
        ] {
            store
                .record(model::Resource {
                    provider: "aliyun-ecs".into(),
                    id: id.into(),
                    resource_type: ty.into(),
                    region: "cn-hangzhou".into(),
                    state: "available".into(),
                    created: model::now() - 3600,
                    ..Default::default()
                })
                .unwrap();
        }
    };

    seed_stale_records();
    let sweep = clouds.sweep(Some("aliyun-ecs"), false, true).await.unwrap();
    assert!(
        sweep.resources.iter().all(|i| i.action == "forgotten"),
        "expected all stale unowned records forgotten, got: {sweep:?}"
    );
    assert!(store.resources().unwrap().is_empty());

    seed_stale_records();
    let disc = clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(disc.disconnected, "{disc:?}");
    assert!(disc.left.is_empty(), "{disc:?}");
    assert!(store.resources().unwrap().is_empty());

    let f = s.lock().unwrap();
    assert_eq!(
        f.calls.iter().filter(|c| c.action == "DeleteVpc").count(),
        0
    );
    assert_eq!(
        f.calls
            .iter()
            .filter(|c| c.action == "DeleteVSwitch")
            .count(),
        0
    );
    assert_eq!(
        f.calls
            .iter()
            .filter(|c| c.action == "DeleteSecurityGroup")
            .count(),
        0
    );
    assert_eq!(f.vpcs.len(), 2);
    assert_eq!(f.vswitches.len(), 1);
    assert_eq!(f.security_groups.len(), 1);
}

#[tokio::test]
async fn isolated_and_existing_vpc_sandboxes_both_sgs_cleaned_on_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "iso-and-existing-sgs-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _) = start_aliyun(None).await;
    wire_fake_aliyun_to_relay(&s, &relay, &mock_spacesd.url());

    let (sandboxes, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);

    clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();

    let _iso_sb = sandboxes.create(create_opts("iso-1")).await.unwrap();
    sandboxes.delete("iso-1").await.unwrap();

    let (iso_vpc_id, iso_vsw_id, iso_sg_id) = {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty());
        assert_eq!(f.vpcs.len(), 1);
        assert_eq!(f.vswitches.len(), 1);
        assert_eq!(f.security_groups.len(), 1);
        (
            f.vpcs[0]["VpcId"].as_str().unwrap().to_string(),
            f.vswitches[0]["VSwitchId"].as_str().unwrap().to_string(),
            f.security_groups[0]["SecurityGroupId"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    };

    let store = cua_byoc::Store::new(dir.path());
    let owner = store.owner_id().unwrap();
    let spoofed_tags: Vec<_> = cua_byoc::aliyun_net::part_tags(&owner)
        .into_iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-1",
        "vsw-user-1",
        Some("sg-lookalike"),
    );
    {
        let mut f = s.lock().unwrap();
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-user-1",
            "SecurityGroupName": "user-default-sg",
            "VpcId": "vpc-user-1",
            "RegionId": "cn-hangzhou",
            "Tags": { "Tag": [] }
        }));
        f.vpcs.push(json!({
            "VpcId": "vpc-default-spoofed",
            "VpcName": cua_byoc::aliyun_net::vpc_name(&owner),
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": spoofed_tags.clone() }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-default-spoofed",
            "VSwitchName": cua_byoc::aliyun_net::vswitch_name(&owner, "cn-hangzhou-h"),
            "VpcId": "vpc-default-spoofed",
            "RegionId": "cn-hangzhou",
            "ZoneId": "cn-hangzhou-h",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": spoofed_tags.clone() }
        }));
        f.vpcs.push(json!({
            "VpcId": "vpc-other-spoofed",
            "VpcName": "corp-other-vpc",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": spoofed_tags }
        }));
    }

    clouds
        .connect(
            &Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                region: Some("cn-hangzhou".into()),
                vpc_id: Some("vpc-user-1".into()),
                vswitch_id: Some("vsw-user-1".into()),
                no_public_ip: true,
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            Some(2),
        )
        .await
        .unwrap();

    let _existing_sb = sandboxes.create(create_opts("existing-1")).await.unwrap();
    sandboxes.delete("existing-1").await.unwrap();

    let existing_sg_id = {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty());
        f.security_groups
            .iter()
            .find(|g| {
                g["VpcId"] == "vpc-user-1"
                    && g["SecurityGroupId"] != "sg-lookalike"
                    && g["SecurityGroupId"] != "sg-user-1"
            })
            .expect("existing-VPC Cua SG created")["SecurityGroupId"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_ne!(iso_sg_id, existing_sg_id);

    let sg_records: Vec<String> = store
        .resources()
        .unwrap()
        .into_iter()
        .filter(|r| r.resource_type == "security_group")
        .map(|r| r.id)
        .collect();
    assert!(
        sg_records.contains(&iso_sg_id) && sg_records.contains(&existing_sg_id),
        "expected both Cua SG records in Store, got: {sg_records:?}"
    );

    let disc = clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(disc.disconnected, "{disc:?}");
    assert!(disc.left.is_empty(), "{disc:?}");
    let deleted_ids: Vec<&str> = disc.deleted.iter().map(|r| r.id.as_str()).collect();
    for expected in [
        iso_vpc_id.as_str(),
        iso_vsw_id.as_str(),
        iso_sg_id.as_str(),
        existing_sg_id.as_str(),
    ] {
        assert!(
            deleted_ids.contains(&expected),
            "expected {expected} in deleted list, got: {deleted_ids:?}"
        );
    }

    {
        let f = s.lock().unwrap();
        let vpc_ids: Vec<&str> = f.vpcs.iter().filter_map(|v| v["VpcId"].as_str()).collect();
        assert_eq!(
            vpc_ids,
            vec!["vpc-user-1", "vpc-default-spoofed", "vpc-other-spoofed"]
        );
        let vsw_ids: Vec<&str> = f
            .vswitches
            .iter()
            .filter_map(|v| v["VSwitchId"].as_str())
            .collect();
        assert_eq!(vsw_ids, vec!["vsw-user-1", "vsw-default-spoofed"]);
        let sg_ids: Vec<&str> = f
            .security_groups
            .iter()
            .filter_map(|g| g["SecurityGroupId"].as_str())
            .collect();
        assert_eq!(sg_ids, vec!["sg-lookalike", "sg-user-1"]);

        for c in &f.calls {
            if c.action == "DeleteVpc" {
                assert_eq!(c.params.get("VpcId"), Some(&iso_vpc_id));
            }
            if c.action == "DeleteVSwitch" {
                assert_eq!(c.params.get("VSwitchId"), Some(&iso_vsw_id));
            }
            if c.action == "DeleteSecurityGroup" {
                let target = c.params.get("SecurityGroupId").map(String::as_str);
                assert!(
                    target == Some(iso_sg_id.as_str()) || target == Some(existing_sg_id.as_str()),
                    "unexpected DeleteSecurityGroup target: {target:?}"
                );
            }
        }
    }

    assert!(store.resources().unwrap().is_empty());
    let st = clouds.status(Some("aliyun-ecs")).await.unwrap();
    assert!(!st.providers[0].connected);
}

#[tokio::test]
async fn two_existing_vpcs_same_sg_name_sweep_and_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "two-existing-vpcs-secret";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _) = start_aliyun(None).await;
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-a",
        "vsw-user-a",
        Some("sg-user-a"),
    );
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-b",
        "vsw-user-b",
        Some("sg-user-b"),
    );
    wire_fake_aliyun_to_relay(&s, &relay, &mock_spacesd.url());

    let (sandboxes, clouds) = build_env(dir.path(), vec![api.clone()], &relay.url);
    let store = cua_byoc::Store::new(dir.path());

    let target_for = |vpc: &str, vsw: &str| Target {
        provider: "aliyun-ecs".into(),
        token: Some("LTAI_TEST_AK:secret123".into()),
        region: Some("cn-hangzhou".into()),
        vpc_id: Some(vpc.into()),
        vswitch_id: Some(vsw.into()),
        no_public_ip: true,
        relay_url: Some(relay.url.clone()),
        relay_mode: Some(RelayMode::Static),
        relay_token: Some(static_secret.into()),
        ..Default::default()
    };

    clouds
        .connect(&target_for("vpc-user-a", "vsw-user-a"), false, Some(2))
        .await
        .unwrap();
    let _sb_a = sandboxes.create(create_opts("box-a")).await.unwrap();
    sandboxes.delete("box-a").await.unwrap();

    clouds
        .connect(&target_for("vpc-user-b", "vsw-user-b"), false, Some(2))
        .await
        .unwrap();
    let _sb_b = sandboxes.create(create_opts("box-b")).await.unwrap();
    sandboxes.delete("box-b").await.unwrap();

    let (sg_a, sg_b) = {
        let f = s.lock().unwrap();
        let find_sg = |vpc: &str, user_sg: &str| {
            f.security_groups
                .iter()
                .find(|g| g["VpcId"] == vpc && g["SecurityGroupId"] != user_sg)
                .expect("Cua SG created in VPC")["SecurityGroupId"]
                .as_str()
                .unwrap()
                .to_string()
        };
        (
            find_sg("vpc-user-a", "sg-user-a"),
            find_sg("vpc-user-b", "sg-user-b"),
        )
    };
    assert_ne!(sg_a, sg_b);
    let sg_records: Vec<String> = store
        .resources()
        .unwrap()
        .into_iter()
        .filter(|r| r.resource_type == "security_group")
        .map(|r| r.id)
        .collect();
    assert!(
        sg_records.contains(&sg_a) && sg_records.contains(&sg_b),
        "expected both Cua SG records in Store, got: {sg_records:?}"
    );

    let sweep = clouds.sweep(Some("aliyun-ecs"), false, true).await.unwrap();
    let swept_deleted: Vec<&str> = sweep
        .resources
        .iter()
        .filter(|i| i.action == "deleted" && i.resource.resource_type == "security_group")
        .map(|i| i.resource.id.as_str())
        .collect();
    assert!(
        swept_deleted.contains(&sg_a.as_str()) && swept_deleted.contains(&sg_b.as_str()),
        "expected both SGs deleted by sweep, got: {sweep:?}"
    );
    assert!(store.resources().unwrap().is_empty());
    {
        let f = s.lock().unwrap();
        let sg_ids: Vec<&str> = f
            .security_groups
            .iter()
            .filter_map(|g| g["SecurityGroupId"].as_str())
            .collect();
        assert_eq!(sg_ids, vec!["sg-user-a", "sg-user-b"]);
        assert_eq!(f.vpcs.len(), 2);
        assert_eq!(f.vswitches.len(), 2);
        assert_eq!(
            f.calls.iter().filter(|c| c.action == "DeleteVpc").count(),
            0
        );
        assert_eq!(
            f.calls
                .iter()
                .filter(|c| c.action == "DeleteVSwitch")
                .count(),
            0
        );
    }

    clouds
        .connect(&target_for("vpc-user-a", "vsw-user-a"), false, Some(2))
        .await
        .unwrap();
    let _sb_a2 = sandboxes.create(create_opts("box-a2")).await.unwrap();
    sandboxes.delete("box-a2").await.unwrap();

    clouds
        .connect(&target_for("vpc-user-b", "vsw-user-b"), false, Some(2))
        .await
        .unwrap();
    let _sb_b2 = sandboxes.create(create_opts("box-b2")).await.unwrap();
    sandboxes.delete("box-b2").await.unwrap();

    let disc = clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(disc.disconnected, "{disc:?}");
    assert!(disc.left.is_empty(), "{disc:?}");
    assert_eq!(
        disc.deleted
            .iter()
            .filter(|r| r.resource_type == "security_group")
            .count(),
        2,
        "{disc:?}"
    );
    assert!(store.resources().unwrap().is_empty());

    let f = s.lock().unwrap();
    let sg_ids: Vec<&str> = f
        .security_groups
        .iter()
        .filter_map(|g| g["SecurityGroupId"].as_str())
        .collect();
    assert_eq!(sg_ids, vec!["sg-user-a", "sg-user-b"]);
    assert_eq!(f.vpcs.len(), 2);
    assert_eq!(f.vswitches.len(), 2);
    assert_eq!(
        f.calls.iter().filter(|c| c.action == "DeleteVpc").count(),
        0
    );
    assert_eq!(
        f.calls
            .iter()
            .filter(|c| c.action == "DeleteVSwitch")
            .count(),
        0
    );
}

#[tokio::test]
async fn existing_vpc_test_passes_when_dry_run_reports_missing_sg_before_cua_sg_exists() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let (api, s, _) = start_aliyun(None).await;
    seed_user_vpc(
        &s,
        "cn-hangzhou",
        "vpc-user-1",
        "vsw-user-1",
        Some("sg-user-1"),
    );
    s.lock().unwrap().run_instances_dry_run_error = Some((
        400,
        "InvalidSecurityGroupId".into(),
        "The specified SecurityGroupId is invalid or does not exist.".into(),
    ));
    let (_, clouds) = build_env(dir.path(), vec![api], &relay.url);

    // 1. Existing VPC with no Cua SG yet: VSwitchId is sent without SecurityGroupId,
    // so live ECS returns InvalidSecurityGroupId after checking RAM authorization.
    let report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-user-1".into()),
            vswitch_id: Some("vsw-user-1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(report.ok, "{report:?}");

    let no_vpc_report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!no_vpc_report.ok, "{no_vpc_report:?}");

    let owner = cua_byoc::state::Store::new(&dir.path().join("cloud"))
        .owner_id()
        .unwrap();
    s.lock().unwrap().security_groups.push(json!({
        "SecurityGroupId": "sg-cua-existing",
        "SecurityGroupName": format!("cua-sandboxes-{owner}"),
        "VpcId": "vpc-user-1",
        "RegionId": "cn-hangzhou",
        "Tags": { "Tag": [
            { "TagKey": "cua-managed", "TagValue": "true" },
            { "TagKey": "cua-owner", "TagValue": owner }
        ]}
    }));
    let with_sg_report = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            token: Some("LTAI_TEST_AK:secret123".into()),
            region: Some("cn-hangzhou".into()),
            vpc_id: Some("vpc-user-1".into()),
            vswitch_id: Some("vsw-user-1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!with_sg_report.ok, "{with_sg_report:?}");
}
