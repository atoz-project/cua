// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Hermetic end-to-end tests for `aliyun-ecs` against an in-process `axum`
//! fake Alibaba Cloud OpenAPI V3 server verifying `ACS3-HMAC-SHA256` signatures.
#![cfg(feature = "aliyun-ecs")]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use cua_byoc::RelayAccess;
use cua_byoc::aliyun_ecs::{AliyunEcs, TokenStore};
use cua_byoc::aliyun_net;
use cua_byoc::api::{CloudApi, Target};
use cua_byoc::model::{self, Connection, ProvisionSpec, Resource};
use cua_byoc::testing::fake_aliyun::{
    FakeAliyun, FakeImage, FakeInstance, FakeSg, FakeVSwitch, FakeVpc, MemStore, S, handle,
};
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{ConnectRequest, DETAIL_RELAY_MACHINE};
use cua_sandbox_core::placement::Runtime;
use cua_sandbox_core::{CreateOptions, ProviderKind, Sandboxes, Status};
use serde_json::json;

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvGuard {
    prev_id: Option<String>,
    prev_secret: Option<String>,
}

impl EnvGuard {
    fn set(id: Option<&str>, secret: Option<&str>) -> Self {
        let prev_id = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").ok();
        let prev_secret = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").ok();
        unsafe {
            match id {
                Some(v) => std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_ID", v),
                None => std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID"),
            }
            match secret {
                Some(v) => std::env::set_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET", v),
                None => std::env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
            }
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

async fn start(aliyun_config: Option<std::path::PathBuf>) -> (AliyunEcs, S, Arc<MemStore>) {
    let s: S = Arc::default();
    let app = axum::Router::new().fallback(handle).with_state(s.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let store = Arc::new(MemStore::default());
    let api = AliyunEcs::with_endpoints(&base, &base, &base, store.clone(), aliyun_config)
        .with_poll(std::time::Duration::from_millis(5));
    (api, s, store)
}

fn target(token: Option<&str>) -> Target {
    Target {
        provider: "aliyun-ecs".into(),
        token: token.map(Into::into),
        ..Default::default()
    }
}

fn conn(api: &AliyunEcs) -> Connection {
    api.resolve(&target(None)).unwrap()
}

fn read_all(dir: &Path) -> String {
    let mut out = String::new();
    for entry in walkdir(dir) {
        if let Ok(s) = std::fs::read_to_string(&entry) {
            out.push_str(&s);
        }
    }
    out
}

fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                files.extend(walkdir(&p));
            } else {
                files.push(p);
            }
        }
    }
    files
}

fn write_aliyun_config(dir: &Path, current: &str) -> std::path::PathBuf {
    let path = dir.join("config.json");
    let cfg = json!({
        "current": current,
        "meta_path": "",
        "profiles": [
            {
                "name": "oauth",
                "mode": "AK",
                "access_key_id": "LTAI_CUR_AK",
                "access_key_secret": "cur_secret_123",
                "region_id": "cn-shanghai",
                "output_format": "json",
                "language": "zh",
                "site": "china",
                "auto_plugin_install": true
            },
            {
                "name": "webhook_manager",
                "mode": "AK",
                "access_key_id": "LTAI_WH_AK",
                "access_key_secret": "wh_secret_456",
                "region_id": "ap-southeast-1",
                "output_format": "json",
                "language": "zh",
                "site": "china"
            },
            {
                "name": "sts_prof",
                "mode": "StsToken",
                "access_key_id": "STS_AK",
                "access_key_secret": "sts_secret",
                "region_id": "cn-hangzhou"
            }
        ]
    });
    std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn test_happy_path_signs_acs3_and_creates_zero_resources() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    let c = conn(&api);
    assert_eq!(c.provider, "aliyun-ecs");
    assert_eq!(c.region, "cn-hangzhou");

    let tested = api.test(&c).await;
    assert!(tested.ok(), "{:?}", tested.checks);
    assert_eq!(tested.account, "123456789012");
    let names: Vec<&str> = tested.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        ["credentials", "region", "machine", "image", "permissions"]
    );

    let f = s.lock().unwrap();
    assert!(f.instances.is_empty(), "test must create zero instances");
    let run_call = f
        .calls
        .iter()
        .find(|call| call.action == "RunInstances")
        .expect("RunInstances dry-run must be called");
    assert_eq!(
        run_call.params.get("DryRun").map(String::as_str),
        Some("true")
    );
    assert!(
        store.load().is_none(),
        "test must never persist credentials into TokenStore"
    );
}

#[tokio::test]
async fn actionable_errors_retries_and_secret_redaction() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok());
    assert_eq!(t.checks[0].name, "credentials");
    assert!(
        t.checks[0].detail.contains("--token-stdin"),
        "{:?}",
        t.checks
    );
    assert!(
        t.checks[0].detail.contains("ALIBABA_CLOUD_ACCESS_KEY_ID"),
        "{:?}",
        t.checks
    );

    api.stage_secret(&target(Some("not-a-pair")));
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok());
    assert!(t.checks[0].detail.contains("missing ':'"), "{:?}", t.checks);
    assert!(api.persist_secret().is_err());

    api.stage_secret(&target(Some("LTAI_UNKNOWN:topsecret-do-not-leak")));
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok());
    assert_eq!(t.checks[0].name, "credentials");
    assert!(
        t.checks[0].detail.contains("InvalidAccessKeyId.NotFound"),
        "{:?}",
        t.checks
    );
    assert!(
        !t.checks[0].detail.contains("topsecret-do-not-leak"),
        "secret leaked in error: {:?}",
        t.checks
    );

    let dbg = format!("{:?}", target(Some("LTAI_TEST_AK:topsecret-do-not-leak")));
    assert!(!dbg.contains("topsecret-do-not-leak"), "{dbg}");
    assert!(dbg.contains("redacted"), "{dbg}");

    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    s.lock()
        .unwrap()
        .forbidden_actions
        .insert("ecs:RunInstances".into());
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok());
    let perm = t.checks.iter().find(|c| c.name == "permissions").unwrap();
    assert!(!perm.ok);
    assert!(perm.detail.contains("Forbidden.RAM"), "{perm:?}");
    assert!(perm.detail.contains("ecs:RunInstances"), "{perm:?}");
    s.lock().unwrap().forbidden_actions.clear();

    s.lock()
        .unwrap()
        .forbidden_actions
        .insert("vpc:DescribeVpcs".into());
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok());
    let perm = t.checks.iter().find(|c| c.name == "permissions").unwrap();
    assert!(
        !perm.ok && perm.detail.contains("vpc:DescribeVpcs"),
        "{perm:?}"
    );
    s.lock().unwrap().forbidden_actions.clear();

    s.lock().unwrap().run_instances_missing_vswitch = true;
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
    s.lock().unwrap().run_instances_missing_vswitch = false;

    let bad_reg_target = Target {
        provider: "aliyun-ecs".into(),
        region: Some("cn-mars-1".into()),
        token: Some("LTAI_TEST_AK:secret123".into()),
        ..Default::default()
    };
    api.stage_secret(&bad_reg_target);
    let t = api.test(&api.resolve(&bad_reg_target).unwrap()).await;
    assert!(!t.ok());
    let reg_chk = t.checks.iter().find(|c| c.name == "region").unwrap();
    assert!(
        !reg_chk.ok && reg_chk.detail.contains("cn-mars-1"),
        "{reg_chk:?}"
    );

    let syntax_err = api
        .resolve(&Target {
            provider: "aliyun-ecs".into(),
            region: Some("bad region!".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert!(
        syntax_err.to_string().contains("invalid region"),
        "{syntax_err}"
    );

    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    s.lock().unwrap().throttle = 2;
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
}

#[tokio::test]
async fn credential_precedence_and_aliyun_config_profiles() {
    let _env_lock = ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = write_aliyun_config(dir.path(), "oauth");
    let (api, s, store) = start(Some(cfg_path)).await;
    {
        let mut f = s.lock().unwrap();
        f.keys.insert("LTAI_CUR_AK".into(), "cur_secret_123".into());
        f.keys.insert("LTAI_WH_AK".into(), "wh_secret_456".into());
        f.keys
            .insert("LTAI_SAVED_AK".into(), "saved_secret_789".into());
        f.keys.insert("LTAI_ENV_AK".into(), "env_secret_abc".into());
        f.keys
            .insert("LTAI_STDIN_AK".into(), "stdin_secret_xyz".into());
    }

    let last_ak = || -> String {
        s.lock()
            .unwrap()
            .calls
            .last()
            .expect("recorded call")
            .access_key_id
            .clone()
    };

    {
        let _env = EnvGuard::set(None, None);
        let t_none = target(None);
        api.stage_secret(&t_none);
        let c = api.resolve(&t_none).unwrap();
        assert_eq!(c.region, "cn-shanghai");
        assert_eq!(c.profile, "oauth");
        let res = api.test(&c).await;
        assert!(res.ok(), "{:?}", res.checks);
        assert_eq!(last_ak(), "LTAI_CUR_AK");

        let t_reg = Target {
            region: Some("cn-beijing".into()),
            ..target(None)
        };
        assert_eq!(api.resolve(&t_reg).unwrap().region, "cn-beijing");

        store.save("LTAI_SAVED_AK:saved_secret_789").unwrap();
        let c_saved = api.resolve(&t_none).unwrap();
        assert_eq!(c_saved.region, "cn-hangzhou");
        assert_eq!(c_saved.profile, "");
        let res = api.test(&c_saved).await;
        assert!(res.ok(), "{:?}", res.checks);
        assert_eq!(last_ak(), "LTAI_SAVED_AK");

        let t_prof = Target {
            profile: Some("webhook_manager".into()),
            ..target(None)
        };
        let c_prof = api.resolve(&t_prof).unwrap();
        assert_eq!(c_prof.region, "ap-southeast-1");
        assert_eq!(c_prof.profile, "webhook_manager");
        let res = api.test(&c_prof).await;
        assert!(res.ok(), "{:?}", res.checks);
        assert_eq!(last_ak(), "LTAI_WH_AK");

        let t_missing = Target {
            profile: Some("no_such_profile".into()),
            ..target(None)
        };
        let res = api.test(&api.resolve(&t_missing).unwrap()).await;
        assert!(!res.ok());
        assert!(
            res.checks[0].detail.contains("no_such_profile"),
            "{:?}",
            res.checks
        );

        let t_sts = Target {
            profile: Some("sts_prof".into()),
            ..target(None)
        };
        let res = api.test(&api.resolve(&t_sts).unwrap()).await;
        assert!(!res.ok());
        assert!(
            res.checks[0].detail.contains("StsToken") && res.checks[0].detail.contains("AK mode"),
            "{:?}",
            res.checks
        );
    }

    {
        let _env = EnvGuard::set(Some("LTAI_ENV_AK"), Some("env_secret_abc"));
        let t_prof = Target {
            profile: Some("webhook_manager".into()),
            ..target(None)
        };
        api.stage_secret(&t_prof);
        let c = api.resolve(&t_prof).unwrap();
        let res = api.test(&c).await;
        assert!(res.ok(), "{:?}", res.checks);
        assert_eq!(last_ak(), "LTAI_ENV_AK");

        let t_stdin = Target {
            profile: Some("webhook_manager".into()),
            token: Some("LTAI_STDIN_AK:stdin_secret_xyz".into()),
            ..target(None)
        };
        api.stage_secret(&t_stdin);
        let c = api.resolve(&t_stdin).unwrap();
        let res = api.test(&c).await;
        assert!(res.ok(), "{:?}", res.checks);
        assert_eq!(last_ak(), "LTAI_STDIN_AK");
    }

    {
        let _env = EnvGuard::set(Some("LTAI_ONLY_ID"), None);
        api.stage_secret(&target(None));
        let res = api.test(&conn(&api)).await;
        assert!(!res.ok());
        assert!(
            res.checks[0]
                .detail
                .contains("both ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
            "{:?}",
            res.checks
        );
    }
}

#[tokio::test]
async fn clouds_and_sandboxes_connect_status_disconnect_and_secret_hygiene() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let (api, s, store) = start(None).await;
    let api = Arc::new(api);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![api.clone()],
        RelayAccess::from_env(),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    s.lock()
        .unwrap()
        .forbidden_actions
        .insert("ecs:RunInstances".into());
    let err = clouds
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ecs:RunInstances"), "{err}");
    assert!(store.load().is_none(), "failed connect must not save token");
    assert!(
        !home.path().join("cloud/state.json").exists(),
        "failed connect must not persist connection"
    );
    s.lock().unwrap().forbidden_actions.clear();

    let connected = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-shanghai".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            make_default: true,
            ttl_hours: None,
            budget_usd_month: Some(75.0),
            max_size: Some("4x16".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(connected.provider.status, "connected");
    assert!(connected.provider.connected);
    assert!(connected.provider.default);
    assert_eq!(connected.provider.account, "123456789012");
    assert_eq!(connected.provider.region, "cn-shanghai");
    assert_eq!(connected.provider.ttl_hours, 8);
    assert_eq!(connected.provider.budget_usd_month, Some(75.0));
    assert_eq!(connected.provider.max_size, "4x16");
    assert_eq!(store.load().as_deref(), Some("LTAI_TEST_AK:secret123"));

    let disk_contents = read_all(home.path());
    assert!(!disk_contents.contains("secret123"), "{disk_contents}");
    assert!(!disk_contents.contains("LTAI_TEST_AK"), "{disk_contents}");

    let status = clouds.status(Some("aliyun-ecs")).await.unwrap();
    let status_json = serde_json::to_string(&status).unwrap();
    assert!(!status_json.contains("secret123"), "{status_json}");
    assert!(!status_json.contains("LTAI_TEST_AK"), "{status_json}");
    let p = &status.providers[0];
    assert_eq!(p.name, "aliyun-ecs");
    assert_eq!(p.region, "cn-shanghai");
    assert_eq!(p.budget_usd_month, Some(75.0));
    assert_eq!(p.spent_month, 0.0);
    assert_eq!(p.running, 0);
    for img in ["windows", "linux", "linux-slim"] {
        let k = p.kinds.iter().find(|k| k.image == img).expect(img);
        assert!(k.supported, "{k:?}");
        assert!(k.usd_per_hour > 0.0, "{k:?}");
    }
    for unsupported_img in ["macos", "omarchy"] {
        let k = p
            .kinds
            .iter()
            .find(|k| k.image == unsupported_img)
            .expect(unsupported_img);
        assert!(!k.supported, "{k:?}");
    }

    let owner = cua_byoc::Store::new(home.path()).owner_id().unwrap();
    let owner_tag = model::label_value(&owner);
    {
        let mut f = s.lock().unwrap();
        f.seed_instance(FakeInstance {
            instance_id: "i-foreign-1".into(),
            instance_name: "foreign".into(),
            region_id: "cn-shanghai".into(),
            status: "Running".into(),
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), "someone-else".into()),
            ]),
            ..Default::default()
        });
        f.seed_instance(FakeInstance {
            instance_id: "i-owned-1".into(),
            instance_name: "cua-sb-1".into(),
            region_id: "cn-shanghai".into(),
            status: "Running".into(),
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), owner_tag.clone()),
            ]),
            ..Default::default()
        });
    }

    let refused = clouds.disconnect("aliyun-ecs", false).await.unwrap_err();
    assert!(
        refused.to_string().contains("NOT disconnected"),
        "{refused}"
    );
    assert!(
        store.load().is_some(),
        "credentials kept on refused disconnect"
    );

    let owned_res = cua_byoc::model::Resource {
        provider: "aliyun-ecs".into(),
        id: "i-owned-1".into(),
        resource_type: "instance".into(),
        region: "cn-shanghai".into(),
        ..Default::default()
    };
    let (st, tags) = api
        .describe(&conn(&api), &owned_res)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st, "running");
    assert_eq!(
        tags.get("cua-owner").map(String::as_str),
        Some(owner_tag.as_str())
    );
    let missing_res = cua_byoc::model::Resource {
        id: "i-missing-1".into(),
        ..owned_res
    };
    assert!(
        api.describe(&conn(&api), &missing_res)
            .await
            .unwrap()
            .is_none()
    );

    s.lock().unwrap().instances.remove("i-owned-1");
    let disc = clouds.disconnect("aliyun-ecs", false).await.unwrap();
    assert!(disc.disconnected);
    assert!(
        store.load().is_none(),
        "disconnect must clear stored credentials"
    );
    let after_status = clouds.status(Some("aliyun-ecs")).await.unwrap();
    assert!(!after_status.providers[0].connected);
    assert!(!after_status.providers[0].default);

    let dir = tempfile::tempdir().unwrap();
    let cfg_path = write_aliyun_config(dir.path(), "oauth");
    let (api_prof, s_prof, store_prof) = start(Some(cfg_path)).await;
    s_prof
        .lock()
        .unwrap()
        .keys
        .insert("LTAI_CUR_AK".into(), "cur_secret_123".into());
    let home2 = tempfile::tempdir().unwrap();
    let sandboxes2 = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home2.path().join("sandboxes")),
        home2.path(),
        vec![Arc::new(api_prof)],
        RelayAccess::from_env(),
    )
    .build();
    let clouds2 = sandboxes2.clouds().unwrap();
    let prof_conn = clouds2
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                profile: Some("oauth".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(prof_conn.provider.profile, "oauth");
    assert_eq!(prof_conn.provider.region, "cn-shanghai");
    assert!(
        store_prof.load().is_none(),
        "CLI profile connect must not duplicate ~/.aliyun/config.json secret into TokenStore"
    );

    let oidc_res = clouds2
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                ..Default::default()
            },
            auth: Some("oidc".into()),
            ..Default::default()
        })
        .await;
    if let Ok(out) = oidc_res {
        assert_eq!(out.provider.status, "failed");
    }

    let _ = BTreeMap::<String, String>::new();
}

#[tokio::test]
async fn token_stdin_or_env_with_profile_clears_connection_profile_post_connect() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = write_aliyun_config(cfg_dir.path(), "oauth");
    let (api, s, _store) = start(Some(cfg_path.clone())).await;
    {
        let mut f = s.lock().unwrap();
        f.keys
            .insert("LTAI_STDIN_AK".into(), "stdin_secret_xyz".into());
        f.keys.insert("LTAI_WH_AK".into(), "wh_secret_456".into());
        f.keys.insert("LTAI_ENV_AK".into(), "env_secret_abc".into());
    }

    let home = tempfile::tempdir().unwrap();
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        RelayAccess::from_env(),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let connected = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                profile: Some("webhook_manager".into()),
                token: Some("LTAI_STDIN_AK:stdin_secret_xyz".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(connected.provider.profile, "");

    s.lock().unwrap().calls.clear();
    let disc = clouds.disconnect("aliyun-ecs", false).await.unwrap();
    assert!(disc.disconnected);
    let calls = s.lock().unwrap().calls.clone();
    assert!(!calls.is_empty());
    assert!(
        calls.iter().all(|c| c.access_key_id == "LTAI_STDIN_AK"),
        "post-connect calls must use saved TokenStore AK, got: {calls:?}"
    );

    let (api_env, s_env, _store_env) = start(Some(cfg_path)).await;
    {
        let mut f = s_env.lock().unwrap();
        f.keys.insert("LTAI_ENV_AK".into(), "env_secret_abc".into());
        f.keys.insert("LTAI_WH_AK".into(), "wh_secret_456".into());
    }
    let home_env = tempfile::tempdir().unwrap();
    let sandboxes_env = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home_env.path().join("sandboxes")),
        home_env.path(),
        vec![Arc::new(api_env)],
        RelayAccess::from_env(),
    )
    .build();
    let clouds_env = sandboxes_env.clouds().unwrap();
    {
        let _env2 = EnvGuard::set(Some("LTAI_ENV_AK"), Some("env_secret_abc"));
        let conn_env = clouds_env
            .connect_with(&ConnectRequest {
                target: Target {
                    provider: "aliyun-ecs".into(),
                    profile: Some("webhook_manager".into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(conn_env.provider.profile, "");
    }
    s_env.lock().unwrap().calls.clear();
    let disc_env = clouds_env.disconnect("aliyun-ecs", false).await.unwrap();
    assert!(disc_env.disconnected);
    let env_calls = s_env.lock().unwrap().calls.clone();
    assert!(!env_calls.is_empty());
    assert!(
        env_calls.iter().all(|c| c.access_key_id == "LTAI_ENV_AK"),
        "post-connect calls must use saved TokenStore env AK, got: {env_calls:?}"
    );
}

#[tokio::test]
async fn clouds_test_and_failed_connect_unstage_secret() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home_clean = tempfile::tempdir().unwrap();
    let (api_clean, s_clean, _store_clean) = start(None).await;
    let sandboxes_clean = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home_clean.path().join("sandboxes")),
        home_clean.path(),
        vec![Arc::new(api_clean)],
        RelayAccess::from_env(),
    )
    .build();
    let clouds_clean = sandboxes_clean.clouds().unwrap();

    let test_ok = clouds_clean
        .test(&target(Some("LTAI_TEST_AK:secret123")))
        .await
        .unwrap();
    assert!(test_ok.ok);
    let st_after_test = clouds_clean.status(Some("aliyun-ecs")).await.unwrap();
    assert!(
        !st_after_test.providers[0].credentials.found,
        "status after test(--token-stdin) must not see stale staged secret: {:?}",
        st_after_test.providers[0].credentials
    );

    let err_region = clouds_clean
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("bad region!".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        err_region.to_string().contains("invalid region"),
        "{err_region}"
    );
    let st_after_bad_region = clouds_clean.status(Some("aliyun-ecs")).await.unwrap();
    assert!(
        !st_after_bad_region.providers[0].credentials.found,
        "status after failed resolve() in connect must not see stale staged secret: {:?}",
        st_after_bad_region.providers[0].credentials
    );

    s_clean
        .lock()
        .unwrap()
        .forbidden_actions
        .insert("ecs:RunInstances".into());
    let err_perm = clouds_clean
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        err_perm.to_string().contains("ecs:RunInstances"),
        "{err_perm}"
    );
    let st_after_perm = clouds_clean.status(Some("aliyun-ecs")).await.unwrap();
    assert!(
        !st_after_perm.providers[0].credentials.found,
        "status after failed test() in connect must not see stale staged secret: {:?}",
        st_after_perm.providers[0].credentials
    );

    let home = tempfile::tempdir().unwrap();
    let (api, _s, _store) = start(None).await;
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        RelayAccess::from_env(),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    clouds
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap();

    let bad_test = clouds
        .test(&target(Some("LTAI_TEST_AK:WRONG_ULTRA_SECRET_XYZ")))
        .await
        .unwrap();
    assert!(!bad_test.ok);

    let disc = clouds.disconnect("aliyun-ecs", false).await.unwrap();
    assert!(disc.disconnected);
}

async fn serve_raw(raw_response: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let resp = raw_response.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&resp).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn call_raw_rejects_malformed_truncated_json_and_empty_account_id() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let malformed_resp =
        b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n<html>not json</html>"
            .to_vec();
    let bad_url = serve_raw(malformed_resp).await;
    let store = Arc::new(MemStore::default());
    let api = AliyunEcs::with_endpoints(&bad_url, &bad_url, &bad_url, store, None);
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    let c = conn(&api);

    let t = api.test(&c).await;
    assert!(!t.ok(), "200 malformed JSON must fail test: {:?}", t.checks);
    assert!(!t.checks[0].ok, "{:?}", t.checks);

    assert!(
        api.list_owned(&c, "owner1").await.is_err(),
        "200 malformed JSON on list_owned must return Err, never Ok(vec![])"
    );
    let r = cua_byoc::model::Resource {
        provider: "aliyun-ecs".into(),
        id: "i-1".into(),
        resource_type: "instance".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    assert!(
        api.describe(&c, &r).await.is_err(),
        "200 malformed JSON on describe must return Err, never Ok(None)"
    );

    let truncated_resp =
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"AccountId\":\"123"
            .to_vec();
    let trunc_url = serve_raw(truncated_resp).await;
    let api_trunc = AliyunEcs::with_endpoints(
        &trunc_url,
        &trunc_url,
        &trunc_url,
        Arc::new(MemStore::default()),
        None,
    );
    api_trunc.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    let c_trunc = conn(&api_trunc);
    let t_trunc = api_trunc.test(&c_trunc).await;
    assert!(
        !t_trunc.ok(),
        "200 truncated body must fail test: {:?}",
        t_trunc.checks
    );
    assert!(!t_trunc.checks[0].ok, "{:?}", t_trunc.checks);
    assert!(
        api_trunc.list_owned(&c_trunc, "owner1").await.is_err(),
        "200 truncated body on list_owned must return Err"
    );
    assert!(
        api_trunc.describe(&c_trunc, &r).await.is_err(),
        "200 truncated body on describe must return Err"
    );

    let empty_acct_body = r#"{"AccountId":""}"#;
    let empty_acct_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{empty_acct_body}",
        empty_acct_body.len()
    )
    .into_bytes();
    let empty_acct_url = serve_raw(empty_acct_resp).await;
    let api_empty = AliyunEcs::with_endpoints(
        &empty_acct_url,
        &empty_acct_url,
        &empty_acct_url,
        Arc::new(MemStore::default()),
        None,
    );
    api_empty.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    let t_empty = api_empty.test(&conn(&api_empty)).await;
    assert!(
        !t_empty.ok(),
        "empty AccountId must fail test: {:?}",
        t_empty.checks
    );
    assert!(!t_empty.checks[0].ok, "{:?}", t_empty.checks);

    let html_502 = "<html><body>502 Bad Gateway</body></html>";
    let resp_502 = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html_502}",
        html_502.len()
    )
    .into_bytes();
    let url_502 = serve_raw(resp_502).await;
    let api_502 = AliyunEcs::with_endpoints(
        &url_502,
        &url_502,
        &url_502,
        Arc::new(MemStore::default()),
        None,
    );
    api_502.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    let t_502 = api_502.test(&conn(&api_502)).await;
    assert!(!t_502.ok());
    let detail = &t_502.checks[0].detail;
    assert!(
        detail.contains("502 Bad Gateway") && !detail.ends_with(": null"),
        "502 error must preserve body snippet, got: {detail}"
    );
}

#[tokio::test]
async fn test_permissions_checks_vswitch_sg_and_rejects_missing_parameter() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));

    s.lock()
        .unwrap()
        .forbidden_actions
        .insert("vpc:DescribeVSwitches".into());
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok(), "{:?}", t.checks);
    let perm = t.checks.iter().find(|c| c.name == "permissions").unwrap();
    assert!(!perm.ok, "{perm:?}");
    assert!(
        perm.detail.contains("Forbidden.RAM") && perm.detail.contains("vpc:DescribeVSwitches"),
        "{perm:?}"
    );
    s.lock().unwrap().forbidden_actions.clear();

    {
        let mut f = s.lock().unwrap();
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-match-1".into(),
            vpc_id: "vpc-match-1".into(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-other-vpc".into(),
            vpc_id: "vpc-other".into(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-match-1".into(),
            vpc_id: "vpc-match-1".into(),
            ..Default::default()
        });
        f.calls.clear();
    }
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
    {
        let f = s.lock().unwrap();
        let run = f
            .calls
            .iter()
            .rev()
            .find(|c| c.action == "RunInstances")
            .unwrap();
        assert_eq!(
            run.params.get("VSwitchId").map(String::as_str),
            Some("vsw-match-1")
        );
        assert_eq!(
            run.params.get("SecurityGroupId").map(String::as_str),
            Some("sg-match-1")
        );
    }

    s.lock().unwrap().run_instances_dry_run_error = Some((
        400,
        "InvalidVSwitchId.NotFound".into(),
        "bad vswitch".into(),
    ));
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok(), "{:?}", t.checks);
    let perm = t.checks.iter().find(|c| c.name == "permissions").unwrap();
    assert!(
        !perm.ok && perm.detail.contains("InvalidVSwitchId.NotFound"),
        "{perm:?}"
    );

    s.lock().unwrap().run_instances_dry_run_error = Some((
        400,
        "MissingParameter".into(),
        "missing required param".into(),
    ));
    let t_with_vsw = api.test(&conn(&api)).await;
    assert!(!t_with_vsw.ok(), "{:?}", t_with_vsw.checks);
    assert!(
        !t_with_vsw
            .checks
            .iter()
            .find(|c| c.name == "permissions")
            .unwrap()
            .ok
    );

    {
        let mut f = s.lock().unwrap();
        f.vswitches.clear();
        f.security_groups.clear();
    }
    let t_no_vsw = api.test(&conn(&api)).await;
    assert!(!t_no_vsw.ok(), "{:?}", t_no_vsw.checks);
    assert!(
        !t_no_vsw
            .checks
            .iter()
            .find(|c| c.name == "permissions")
            .unwrap()
            .ok
    );
    s.lock().unwrap().run_instances_dry_run_error = None;

    {
        let mut f = s.lock().unwrap();
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-only-1".into(),
            vpc_id: "vpc-no-sg".into(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-wrong-vpc".into(),
            vpc_id: "vpc-other".into(),
            ..Default::default()
        });
        f.calls.clear();
    }
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
    let f = s.lock().unwrap();
    let run = f
        .calls
        .iter()
        .rev()
        .find(|c| c.action == "RunInstances")
        .unwrap();
    assert_eq!(
        run.params.get("VSwitchId").map(String::as_str),
        Some("vsw-only-1")
    );
    assert!(!run.params.contains_key("SecurityGroupId"));
}

const HERMETIC_LINUX_IMAGE: &str = "registry.invalid/trycua/linux:24.04";

fn decode_cloud_init_file(user_data: &str, path: &str) -> String {
    let at = user_data
        .find(&format!("path: {path}\n"))
        .unwrap_or_else(|| panic!("missing {path} in user_data"));
    let rest = &user_data[at..];
    let c = rest.find("content: ").unwrap() + "content: ".len();
    let end = rest[c..].find('\n').unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&rest[c..c + end])
        .unwrap();
    String::from_utf8(bytes).unwrap()
}

fn sb_create_opts(name: &str) -> CreateOptions {
    let mut o = CreateOptions::new(ProviderKind::Contrib, HERMETIC_LINUX_IMAGE);
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some(name.into());
    o
}

#[tokio::test]
async fn test_permissions_dry_runs_vpc_and_creates_zero_security_groups() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));

    // 1. Passing test sends Tag.1.Key=cua-managed on RunInstances and CreateVpc DryRun=true,
    //    and NEVER calls CreateSecurityGroup (which ignores DryRun=true on real Alibaba Cloud).
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
    {
        let f = s.lock().unwrap();
        assert!(
            f.vpcs.is_empty() && f.security_groups.is_empty() && f.instances.is_empty(),
            "test must create zero resources: vpcs={:?} sgs={:?} inst={:?}",
            f.vpcs,
            f.security_groups,
            f.instances
        );
        assert!(
            !f.calls.iter().any(|c| c.action == "CreateSecurityGroup"),
            "AliyunEcs::test() must never call CreateSecurityGroup (DryRun=true is ignored live)"
        );
        for action in ["RunInstances", "CreateVpc"] {
            let call = f
                .calls
                .iter()
                .find(|c| c.action == action)
                .unwrap_or_else(|| panic!("missing DryRun call for {action}"));
            assert_eq!(call.params.get("DryRun").map(String::as_str), Some("true"));
            assert_eq!(
                call.params.get("Tag.1.Key").map(String::as_str),
                Some("cua-managed")
            );
            assert_eq!(
                call.params.get("Tag.1.Value").map(String::as_str),
                Some("true")
            );
        }
    }

    {
        let mut f = s.lock().unwrap();
        f.calls.clear();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-unrelated".into(),
            vpc_name: "cua-relay-sg-vpc".into(),
            cidr_block: "10.0.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: BTreeMap::from([
                ("role".into(), "cua-relay".into()),
                ("managed-by".into(), "manual".into()),
            ]),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-unrelated".into(),
            vswitch_name: "cua-relay-sg-vsw".into(),
            vpc_id: "vpc-unrelated".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "10.0.1.0/24".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            ..Default::default()
        });
    }
    let t_pre = api.test(&conn(&api)).await;
    assert!(t_pre.ok(), "{:?}", t_pre.checks);
    {
        let f = s.lock().unwrap();
        assert!(
            f.security_groups.is_empty(),
            "test() must create zero security groups even with pre-existing VPC: {:?}",
            f.security_groups
        );
        assert!(
            !f.calls.iter().any(|c| c.action == "CreateSecurityGroup"),
            "CreateSecurityGroup must not be called when pre-existing VPC exists"
        );
    }

    for perm_action in [
        "vpc:CreateVpc",
        "ecs:DescribeSecurityGroups",
        "ecs:RunInstances",
    ] {
        s.lock()
            .unwrap()
            .forbidden_actions
            .insert(perm_action.into());
        let t = api.test(&conn(&api)).await;
        assert!(!t.ok(), "{perm_action} must fail test");
        let perm = t.checks.iter().find(|c| c.name == "permissions").unwrap();
        assert!(
            !perm.ok && perm.detail.contains("Forbidden.RAM") && perm.detail.contains(perm_action),
            "{perm:?}"
        );
        s.lock().unwrap().forbidden_actions.clear();
    }
}

#[tokio::test]
async fn linux_docker_on_vm_sandbox_lifecycle_vpc_reuse_and_security_invariants() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let relay_access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );

    let (api, s, _store) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-acct-default".into(),
            vpc_name: "default-vpc".into(),
            cidr_block: "172.16.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            is_default: true,
            status: "Available".into(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-acct-existing".into(),
            vswitch_name: "prod-vsw".into(),
            vpc_id: "vpc-acct-default".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "172.16.0.0/24".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-acct-existing".into(),
            sg_name: "prod-sg".into(),
            vpc_id: "vpc-acct-default".into(),
            region_id: "cn-hangzhou".into(),
            sg_type: "normal".into(),
            inner_access_policy: "Accept".into(),
            ..Default::default()
        });
        let relay_hook = relay.clone();
        f.on_run_instance = Some(Arc::new(move |_inst_id, params| {
            let ud_b64 = params.get("UserData").expect("UserData must be passed");
            let ud = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(ud_b64)
                    .unwrap(),
            )
            .unwrap();
            let machine_id = decode_cloud_init_file(&ud, "/etc/cua/relay/machine-id")
                .trim()
                .to_string();
            relay_hook.set_online(&machine_id, true, "0.1.0");
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        relay_access,
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();
    clouds
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap();

    let owner = cua_byoc::Store::new(home.path()).owner_id().unwrap();
    let owner_tag = model::label_value(&owner);

    s.lock().unwrap().calls.clear();

    let mut opts = sb_create_opts("sb-one");
    opts.runtime = Runtime::Other("docker".into());
    let sb1 = sandboxes.create(opts).await.unwrap();
    let details1 = sb1.provider_details();
    let machine1 = details1[DETAIL_RELAY_MACHINE].clone();
    assert!(machine1.starts_with("cloud-"), "{details1:?}");
    assert_eq!(
        details1.get("runtime").map(String::as_str),
        Some("docker-on-vm")
    );

    {
        let f = s.lock().unwrap();
        let create_vpc = f.calls.iter().find(|c| c.action == "CreateVpc").unwrap();
        assert_eq!(
            create_vpc.params.get("CidrBlock").map(String::as_str),
            Some("10.77.0.0/16")
        );
        assert_eq!(
            create_vpc.params.get("VpcName").map(String::as_str),
            Some(aliyun_net::vpc_name(&owner).as_str())
        );

        let create_sg = f
            .calls
            .iter()
            .find(|c| c.action == "CreateSecurityGroup")
            .unwrap();
        assert_eq!(
            create_sg
                .params
                .get("SecurityGroupName")
                .map(String::as_str),
            Some(aliyun_net::sg_name(&owner).as_str())
        );
        assert_eq!(
            create_sg
                .params
                .get("SecurityGroupType")
                .map(String::as_str),
            Some("enterprise")
        );

        let egress = f
            .calls
            .iter()
            .find(|c| c.action == "AuthorizeSecurityGroupEgress")
            .unwrap();
        assert_eq!(
            egress
                .params
                .get("Permissions.1.IpProtocol")
                .map(String::as_str),
            Some("all")
        );
        assert_eq!(
            egress
                .params
                .get("Permissions.1.PortRange")
                .map(String::as_str),
            Some("-1/-1")
        );
        assert_eq!(
            egress
                .params
                .get("Permissions.1.DestCidrIp")
                .map(String::as_str),
            Some("0.0.0.0/0")
        );
        assert_eq!(
            egress
                .params
                .get("Permissions.1.Policy")
                .map(String::as_str),
            Some("accept")
        );
        assert!(
            !f.calls
                .iter()
                .any(|c| c.action.starts_with("AuthorizeSecurityGroup")
                    && c.action != "AuthorizeSecurityGroupEgress")
        );

        let run = f.calls.iter().find(|c| c.action == "RunInstances").unwrap();
        assert_eq!(
            run.params.get("InstanceType").map(String::as_str),
            Some("ecs.e-c1m2.large")
        );
        assert_eq!(
            run.params.get("ImageId").map(String::as_str),
            Some("ubuntu_24_04_x64_20G_alibase_20250101.vhd")
        );
        assert_eq!(
            run.params.get("SystemDisk.Category").map(String::as_str),
            Some("cloud_essd")
        );
        assert_eq!(
            run.params.get("SystemDisk.Size").map(String::as_str),
            Some("40")
        );
        assert_eq!(
            run.params.get("InstanceChargeType").map(String::as_str),
            Some("PostPaid")
        );
        assert_eq!(
            run.params.get("StoppedMode").map(String::as_str),
            Some("StopCharging")
        );
        assert!(
            run.params
                .get("AutoReleaseTime")
                .is_some_and(|s| s.ends_with('Z')),
            "AutoReleaseTime missing: {:?}",
            run.params
        );
        assert_eq!(
            run.params.get("HttpEndpoint").map(String::as_str),
            Some("enabled")
        );
        assert_eq!(
            run.params.get("HttpTokens").map(String::as_str),
            Some("required")
        );
        assert_eq!(
            run.params.get("InternetChargeType").map(String::as_str),
            Some("PayByTraffic")
        );
        assert_eq!(
            run.params
                .get("InternetMaxBandwidthOut")
                .map(String::as_str),
            Some("100")
        );
        assert!(!run.params.contains_key("KeyPairName"));
        assert!(!run.params.contains_key("Password"));
        assert!(!run.params.contains_key("RamRoleName"));

        let ud = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(run.params.get("UserData").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(ud.starts_with("#cloud-config\n"));
        assert!(!ud.contains("cmt_"), "token must not be in clear text");
        let script = decode_cloud_init_file(&ud, "/usr/local/sbin/cua-first-boot");
        assert!(script.contains("100.100.100.200/32"), "{script}");
        assert!(script.contains("docker.io"), "{script}");
        assert!(
            script.contains("docker run -d --name cua-sandbox"),
            "{script}"
        );
        assert!(script.contains("shutdown -h +480"), "{script}");
        assert!(ud.contains("cua-expire.timer"));

        let inst = f.instances.values().next().unwrap();
        let inst_tags = &inst.tags;
        for key in [
            "cua-managed",
            "cua-owner",
            "cua-space",
            "cua-machine",
            "cua-created-by",
            "cua-expires",
        ] {
            assert!(inst_tags.contains_key(key), "missing {key}: {inst_tags:?}");
        }
        assert_eq!(inst_tags["cua-managed"], "true");
        assert_eq!(inst_tags["cua-owner"], owner_tag);
        assert_eq!(inst_tags["cua-space"], "sb-one");
        assert_eq!(inst_tags["cua-machine"], machine1);

        let cua_vpc = f
            .vpcs
            .values()
            .find(|v| v.vpc_id != "vpc-acct-default")
            .unwrap();
        let vpc_tags = &cua_vpc.tags;
        assert_eq!(vpc_tags.len(), 6, "{vpc_tags:?}");
        assert_eq!(vpc_tags["cua-machine"], "");
        assert_eq!(vpc_tags["cua-space"], "");

        let cua_vsw = f
            .vswitches
            .values()
            .find(|v| v.vswitch_id != "vsw-acct-existing")
            .unwrap();
        assert_eq!(cua_vsw.cidr_block, "10.77.0.0/20");
        let vsw_tags = &cua_vsw.tags;
        assert_eq!(vsw_tags.len(), 6, "{vsw_tags:?}");
        assert_eq!(vsw_tags["cua-machine"], "");

        let cua_sg = f
            .security_groups
            .values()
            .find(|g| g.sg_id != "sg-acct-existing")
            .unwrap();
        let sg_tags = &cua_sg.tags;
        assert_eq!(sg_tags.len(), 6, "{sg_tags:?}");
        assert_eq!(sg_tags["cua-machine"], "");
    }

    s.lock().unwrap().calls.clear();
    let _sb2 = sandboxes.create(sb_create_opts("sb-two")).await.unwrap();
    {
        let f = s.lock().unwrap();
        assert!(!f.calls.iter().any(|c| c.action == "CreateVpc"));
        assert!(!f.calls.iter().any(|c| c.action == "CreateVSwitch"));
        assert!(!f.calls.iter().any(|c| c.action == "CreateSecurityGroup"));
        assert!(
            f.calls
                .iter()
                .any(|c| c.action == "DescribeSecurityGroupAttribute"),
            "SG reuse must verify rules via DescribeSecurityGroupAttribute"
        );
        assert_eq!(f.vpcs.len(), 2);
        assert_eq!(f.vswitches.len(), 2);
        assert_eq!(f.security_groups.len(), 2);
    }

    sandboxes.suspend("sb-one").await.unwrap();
    {
        let f = s.lock().unwrap();
        let stop_call = f.calls.iter().find(|c| c.action == "StopInstance").unwrap();
        assert_eq!(
            stop_call.params.get("StoppedMode").map(String::as_str),
            Some("StopCharging")
        );
    }
    let st_susp = sandboxes.get("sb-one").await.unwrap().status;
    assert_eq!(st_susp, Status::Suspended);

    sandboxes.resume("sb-one").await.unwrap();
    assert_eq!(
        sandboxes.get("sb-one").await.unwrap().status,
        Status::Running
    );

    sandboxes.delete("sb-one").await.unwrap();
    sandboxes.delete("sb-two").await.unwrap();
    assert!(relay.machine(&machine1).is_none());
    {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty());
        assert!(f.vpcs.contains_key("vpc-acct-default"));
        assert!(f.vswitches.contains_key("vsw-acct-existing"));
        assert!(f.security_groups.contains_key("sg-acct-existing"));
    }
}

#[tokio::test]
async fn preflight_budget_max_size_and_unsupported_modes_refuse_before_cloud_calls() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home1 = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", None);
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let (api1, s1, _) = start(None).await;
    let sb_max = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home1.path().join("sandboxes")),
        home1.path(),
        vec![Arc::new(api1)],
        access.clone(),
    )
    .build();
    sb_max
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            max_size: Some("1x2".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    s1.lock().unwrap().calls.clear();

    let err_size = sb_max.create(sb_create_opts("too-big")).await.unwrap_err();
    assert!(
        err_size
            .to_string()
            .contains("allows machines up to 1 vCPU"),
        "{err_size}"
    );
    assert!(
        s1.lock().unwrap().calls.is_empty(),
        "max-size refusal must happen before ANY cloud API call"
    );

    let home1b = tempfile::tempdir().unwrap();
    let (api1b, s1b, _) = start(None).await;
    let sb_max_4x16 = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home1b.path().join("sandboxes")),
        home1b.path(),
        vec![Arc::new(api1b)],
        access.clone(),
    )
    .build();
    sb_max_4x16
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            max_size: Some("4x16".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    s1b.lock().unwrap().calls.clear();

    let mut opts_8x32 = sb_create_opts("too-big-4x16");
    opts_8x32.cpus = 8;
    opts_8x32.memory_mb = 32768;
    let err_size_4x16 = sb_max_4x16.create(opts_8x32).await.unwrap_err();
    assert!(
        err_size_4x16
            .to_string()
            .contains("allows machines up to 4 vCPU"),
        "{err_size_4x16}"
    );
    assert!(
        s1b.lock().unwrap().calls.is_empty(),
        "4x16 max-size refusal must happen before ANY cloud API call"
    );

    let home2 = tempfile::tempdir().unwrap();
    let (api2, s2, _) = start(None).await;
    let sb_budget = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home2.path().join("sandboxes")),
        home2.path(),
        vec![Arc::new(api2)],
        access,
    )
    .build();
    sb_budget
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            budget_usd_month: Some(0.01),
            ..Default::default()
        })
        .await
        .unwrap();
    s2.lock().unwrap().calls.clear();

    let err_budget = sb_budget
        .create(sb_create_opts("over-budget"))
        .await
        .unwrap_err();
    assert!(err_budget.to_string().contains("budget"), "{err_budget}");
    assert!(
        s2.lock().unwrap().calls.is_empty(),
        "budget refusal must happen before ANY cloud API call"
    );

    let mut bad_rt_opts = sb_create_opts("runtime-unsupported");
    bad_rt_opts.runtime = Runtime::Qemu;
    let err_rt = sb_budget.create(bad_rt_opts).await.unwrap_err();
    assert!(
        err_rt.to_string().contains("docker") || err_rt.to_string().contains("native"),
        "{err_rt}"
    );
    assert!(s2.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn cross_zone_capacity_retry_and_total_failure_network_rollback() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);

    {
        let mut f = s.lock().unwrap();
        f.set_zones(
            "cn-hangzhou",
            vec!["cn-hangzhou-h".into(), "cn-hangzhou-i".into()],
        );
        f.mark_zone_run_fail("cn-hangzhou-h", "OperationDenied.NoStock");
    }
    let spec = ProvisionSpec {
        name: "cua-aliyun-ecs-retry1".into(),
        family: "linux".into(),
        image: HERMETIC_LINUX_IMAGE.into(),
        kind: "container".into(),
        machine_type: "ecs.e-c1m2.large".into(),
        disk_gb: 40,
        user_data: "#cloud-config\n".into(),
        tags: model::tags("owner1", "sb-retry", "cloud-retry", 0),
        ttl_secs: 3600,
        arch: "amd64".into(),
        runtime: "docker".into(),
        ..Default::default()
    };
    let made = api.provision(&c, &spec).await.unwrap();
    assert_eq!(made[0].zone, "cn-hangzhou-i");
    {
        let f = s.lock().unwrap();
        let run_zones: Vec<&str> = f
            .calls
            .iter()
            .filter(|call| call.action == "RunInstances")
            .filter_map(|call| call.params.get("ZoneId").map(String::as_str))
            .collect();
        assert_eq!(run_zones, ["cn-hangzhou-h", "cn-hangzhou-i"]);
        assert_eq!(
            f.vswitches.len(),
            1,
            "unused VSwitch from sold-out zone must be cleaned up"
        );
        assert_eq!(
            f.vswitches.values().next().unwrap().zone_id,
            "cn-hangzhou-i"
        );
    }

    let (api2, s2, store2) = start(None).await;
    store2.save("LTAI_TEST_AK:secret123").unwrap();
    {
        let mut f = s2.lock().unwrap();
        f.set_zones(
            "cn-hangzhou",
            vec!["cn-hangzhou-h".into(), "cn-hangzhou-i".into()],
        );
        f.mark_zone_sold_out("cn-hangzhou-h", "Zone.NotOnSale");
        f.mark_zone_sold_out("cn-hangzhou-i", "OperationDenied.NoStock");
    }
    let err = api2.provision(&conn(&api2), &spec).await.unwrap_err();
    assert!(
        err.to_string().contains("tried 2 zones"),
        "expected multi-zone failure summary, got: {err}"
    );
    {
        let f = s2.lock().unwrap();
        assert!(f.instances.is_empty());
        assert!(f.vswitches.is_empty());
        assert!(f.security_groups.is_empty());
        assert!(f.vpcs.is_empty(), "newly created VPC must be rolled back");
    }
}

#[tokio::test]
async fn failed_boot_redacts_console_output_and_rolls_back_instance_and_relay() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", None);
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let (api, s, _) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        let s_hook = s.clone();
        f.on_run_instance = Some(Arc::new(move |inst_id, _params| {
            let mut f = s_hook.lock().unwrap();
            if let Some(inst) = f.instances.get_mut(inst_id) {
                inst.status = "Stopped".into();
            }
            f.console_outputs.insert(
                inst_id.to_string(),
                concat!(
                    "[    1.23] cloud-init: docker pull failed\n",
                    "Authorization: Bearer topsecret_bearer_token_12345\n",
                    "CUA_RELAY_TOKEN=cmt_super_secret_token_999\n",
                    "CUA_ENV_TOKEN=envtok_never_leak_987654\n",
                    "[    2.34] systemd: cua-first-boot exited with status 1\n"
                )
                .to_string(),
            );
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();
    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut opts = sb_create_opts("boot-fail");
    opts.env
        .insert("CUA_ENV_TOKEN".into(), "envtok_never_leak_987654".into());
    let err = sandboxes.create(opts).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("cua-first-boot exited with status 1"), "{msg}");
    assert!(!msg.contains("topsecret_bearer_token_12345"), "{msg}");
    assert!(!msg.contains("cmt_super_secret_token_999"), "{msg}");
    assert!(!msg.contains("envtok_never_leak_987654"), "{msg}");

    let log_dir = home.path().join("cloud").join("boot-logs");
    let logs: Vec<_> = std::fs::read_dir(&log_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(logs.len(), 1);
    let saved_log = std::fs::read_to_string(logs[0].path()).unwrap();
    assert!(saved_log.contains("cloud-init: docker pull failed"));
    assert!(!saved_log.contains("topsecret_bearer_token_12345"));
    assert!(!saved_log.contains("cmt_super_secret_token_999"));
    assert!(!saved_log.contains("envtok_never_leak_987654"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(logs[0].path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let f = s.lock().unwrap();
    assert!(
        f.instances.is_empty(),
        "failed instance must be rolled back"
    );
    assert_eq!(f.vpcs.len(), 1, "shared VPC remains reusable");
    assert_eq!(f.security_groups.len(), 1);
}

#[tokio::test]
async fn tag_guards_sweep_ordering_and_disconnect_refusal_vs_delete() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", None);
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let (api, s, _) = start(None).await;
    {
        let relay_hook = relay.clone();
        s.lock().unwrap().on_run_instance = Some(Arc::new(move |_inst_id, params| {
            let ud = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(params.get("UserData").unwrap())
                    .unwrap(),
            )
            .unwrap();
            let mid = decode_cloud_init_file(&ud, "/etc/cua/relay/machine-id")
                .trim()
                .to_string();
            relay_hook.set_online(&mid, true, "0.1.0");
        }));
    }
    let api = Arc::new(api);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![api.clone()],
        access,
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();
    clouds
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap();

    let owner = cua_byoc::Store::new(home.path()).owner_id().unwrap();
    let owner_tag = model::label_value(&owner);

    {
        let mut f = s.lock().unwrap();
        let owner_tags = BTreeMap::from([
            ("cua-managed".into(), "true".into()),
            ("cua-owner".into(), owner_tag.clone()),
        ]);
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-default".into(),
            vpc_name: "default".into(),
            cidr_block: "172.16.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            is_default: true,
            status: "Available".into(),
            tags: owner_tags.clone(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-default".into(),
            vswitch_name: "default-vsw".into(),
            vpc_id: "vpc-default".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "172.16.0.0/24".into(),
            region_id: "cn-hangzhou".into(),
            is_default: true,
            status: "Available".into(),
            tags: owner_tags,
            ..Default::default()
        });
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-untagged".into(),
            cidr_block: "192.168.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-untagged".into(),
            vpc_id: "vpc-untagged".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "192.168.0.0/24".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-untagged".into(),
            vpc_id: "vpc-untagged".into(),
            region_id: "cn-hangzhou".into(),
            ..Default::default()
        });
        f.seed_instance(FakeInstance {
            instance_id: "i-untagged".into(),
            region_id: "cn-hangzhou".into(),
            status: "Running".into(),
            ..Default::default()
        });
        f.seed_instance(FakeInstance {
            instance_id: "i-foreign".into(),
            region_id: "cn-hangzhou".into(),
            status: "Running".into(),
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), "someone-else".into()),
            ]),
            ..Default::default()
        });
    }

    let c = conn(&api);
    assert!(
        api.list_owned(&c, &owner).await.unwrap().is_empty(),
        "list_owned must exclude default/untagged/foreign resources"
    );
    s.lock().unwrap().calls.clear();
    for (ty, id) in [
        ("instance", "i-untagged"),
        ("instance", "i-foreign"),
        ("vpc", "vpc-default"),
        ("vpc", "vpc-untagged"),
        ("vswitch", "vsw-default"),
        ("vswitch", "vsw-untagged"),
        ("security_group", "sg-untagged"),
    ] {
        let r = Resource {
            provider: "aliyun-ecs".into(),
            id: id.into(),
            resource_type: ty.into(),
            region: "cn-hangzhou".into(),
            ..Default::default()
        };
        let err_del = api.delete(&c, &r, &owner).await.unwrap_err();
        assert!(err_del.to_string().contains("refusing"), "{id}: {err_del}");
        if ty == "instance" || id == "vsw-default" || id == "vpc-default" {
            let err_stop = api.stop(&c, &r, &owner).await.unwrap_err();
            assert!(
                err_stop.to_string().contains("refusing"),
                "{id}: {err_stop}"
            );
            let err_start = api.start(&c, &r, &owner).await.unwrap_err();
            assert!(
                err_start.to_string().contains("refusing"),
                "{id}: {err_start}"
            );
        }
    }
    {
        let f = s.lock().unwrap();
        for mutating in [
            "StopInstance",
            "StartInstance",
            "DeleteInstance",
            "DeleteVpc",
            "DeleteVSwitch",
            "DeleteSecurityGroup",
        ] {
            assert!(
                !f.calls.iter().any(|call| call.action == mutating),
                "tag guard leaked mutating call {mutating}"
            );
        }
    }

    let _sb = sandboxes.create(sb_create_opts("sb-live")).await.unwrap();
    let expired_at = model::now().saturating_sub(60);
    s.lock().unwrap().seed_instance(FakeInstance {
        instance_id: "i-expired".into(),
        instance_name: "cua-aliyun-ecs-exp".into(),
        region_id: "cn-hangzhou".into(),
        status: "Running".into(),
        tags: BTreeMap::from([
            ("cua-managed".into(), "true".into()),
            ("cua-owner".into(), owner_tag),
            ("cua-expires".into(), expired_at.to_string()),
            ("cua-machine".into(), "cloud-expired-1".into()),
        ]),
        ..Default::default()
    });

    let refused = clouds.disconnect("aliyun-ecs", false).await.unwrap_err();
    assert!(
        refused.to_string().contains("NOT disconnected"),
        "{refused}"
    );

    let swept = clouds
        .sweep(Some("aliyun-ecs"), false, false)
        .await
        .unwrap();
    assert!(
        swept
            .resources
            .iter()
            .any(|i| i.resource.id == "i-expired" && i.action == "deleted"),
        "{swept:?}"
    );
    assert!(!s.lock().unwrap().instances.contains_key("i-expired"));
    assert_eq!(s.lock().unwrap().instances.len(), 3);

    {
        let mut f = s.lock().unwrap();
        f.transient_dependency_errors = 1;
        f.calls.clear();
    }
    let disc = clouds.disconnect("aliyun-ecs", true).await.unwrap();
    assert!(disc.disconnected);

    let f = s.lock().unwrap();
    let del_order: Vec<&str> = f
        .calls
        .iter()
        .filter(|c| {
            matches!(
                c.action.as_str(),
                "DeleteInstance" | "DeleteSecurityGroup" | "DeleteVSwitch" | "DeleteVpc"
            )
        })
        .map(|c| c.action.as_str())
        .collect();
    let pos_inst = del_order
        .iter()
        .position(|a| *a == "DeleteInstance")
        .unwrap();
    let pos_sg = del_order
        .iter()
        .position(|a| *a == "DeleteSecurityGroup")
        .unwrap();
    let pos_vsw = del_order
        .iter()
        .position(|a| *a == "DeleteVSwitch")
        .unwrap();
    let pos_vpc = del_order.iter().position(|a| *a == "DeleteVpc").unwrap();
    assert!(
        pos_inst < pos_sg && pos_sg < pos_vsw && pos_vsw < pos_vpc,
        "{del_order:?}"
    );

    assert_eq!(f.instances.len(), 2);
    assert!(f.instances.contains_key("i-untagged"));
    assert!(f.instances.contains_key("i-foreign"));
    assert_eq!(f.vpcs.len(), 2);
    assert!(f.vpcs.contains_key("vpc-default"));
    assert!(f.vpcs.contains_key("vpc-untagged"));
    assert_eq!(f.vswitches.len(), 2);
    assert!(f.vswitches.contains_key("vsw-default"));
    assert!(f.vswitches.contains_key("vsw-untagged"));
    assert_eq!(f.security_groups.len(), 1);
}

#[tokio::test]
async fn default_vswitch_with_spoofed_cua_tags_is_never_reused() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);

    let vpc_tags = aliyun_net::part_tags("owner1");
    {
        let mut f = s.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-owned-1".into(),
            vpc_name: aliyun_net::vpc_name("owner1"),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: vpc_tags.clone(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-default-spoofed".into(),
            vswitch_name: "default-vsw".into(),
            vpc_id: "vpc-owned-1".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "10.77.0.0/20".into(),
            region_id: "cn-hangzhou".into(),
            is_default: true,
            status: "Available".into(),
            tags: vpc_tags,
            ..Default::default()
        });
    }

    let locks = aliyun_net::NetLocks::default();
    let (chosen_id, made) = aliyun_net::ensure_vswitch_for_zone(
        &api,
        &c,
        "cn-hangzhou",
        "owner1",
        "vpc-owned-1",
        "cn-hangzhou-h",
        &locks,
    )
    .await
    .unwrap();
    assert_ne!(
        chosen_id, "vsw-default-spoofed",
        "must never reuse an IsDefault=true VSwitch even with Cua tags"
    );
    assert!(
        made.is_some(),
        "must create a dedicated non-default VSwitch instead"
    );
    let f = s.lock().unwrap();
    assert!(
        f.calls.iter().any(|call| call.action == "CreateVSwitch"),
        "expected CreateVSwitch call"
    );
}

#[tokio::test]
async fn security_group_tie_breaker_and_race_loser_cleanup() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api1, s1, store1) = start(None).await;
    store1.save("LTAI_TEST_AK:secret123").unwrap();
    let c1 = conn(&api1);
    let vpc_tags = aliyun_net::part_tags("owner1");
    {
        let mut f = s1.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-owned-1".into(),
            vpc_name: aliyun_net::vpc_name("owner1"),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: vpc_tags.clone(),
            ..Default::default()
        });
        for sg_id in ["sg-zeta", "sg-alpha"] {
            f.seed_sg(FakeSg {
                sg_id: sg_id.into(),
                sg_name: aliyun_net::sg_name("owner1"),
                vpc_id: "vpc-owned-1".into(),
                region_id: "cn-hangzhou".into(),
                sg_type: "enterprise".into(),
                inner_access_policy: "Drop".into(),
                tags: vpc_tags.clone(),
                ..Default::default()
            });
            f.security_group_rules.insert(
                sg_id.into(),
                vec![json!({
                    "Direction": "egress",
                    "IpProtocol": "all",
                    "PortRange": "-1/-1",
                    "DestCidrIp": "0.0.0.0/0",
                    "Policy": "accept",
                    "Priority": "1",
                })],
            );
        }
    }
    let cfg = aliyun_net::NetworkConfig::from_connection(&c1).unwrap();
    let locks1 = aliyun_net::NetLocks::default();
    let net = aliyun_net::prepare_network(
        &api1,
        &c1,
        "cn-hangzhou",
        "owner1",
        "ecs.e-c1m2.large",
        &cfg,
        &locks1,
    )
    .await
    .unwrap();
    assert_eq!(
        net.security_group_id, "sg-alpha",
        "must pick lowest SecurityGroupId on tie"
    );

    let s2: S = Arc::new(Mutex::new(FakeAliyun::default()));
    {
        let mut f = s2.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-owned-race".into(),
            vpc_name: aliyun_net::vpc_name("owner1"),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: vpc_tags,
            ..Default::default()
        });
    }
    let fake_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_addr = fake_listener.local_addr().unwrap();
    let fake_router = axum::Router::new()
        .route("/", axum::routing::any(handle))
        .with_state(s2.clone());
    tokio::spawn(async move {
        let _ = axum::serve(fake_listener, fake_router).await;
    });

    let create_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let client = reqwest::Client::new();
    let proxy_router = axum::Router::new().route(
        "/",
        axum::routing::any({
            let create_barrier = create_barrier.clone();
            let client = client.clone();
            let target_url = format!("http://{fake_addr}/");
            move |req: axum::extract::Request| {
                let create_barrier = create_barrier.clone();
                let client = client.clone();
                let target_url = target_url.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let action = parts
                        .headers
                        .get("x-acs-action")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                    if action == "CreateSecurityGroup" {
                        create_barrier.wait().await;
                    }
                    let mut out_url = target_url;
                    if let Some(q) = parts.uri.query() {
                        out_url.push('?');
                        out_url.push_str(q);
                    }
                    let mut fwd = client.request(parts.method, &out_url).body(bytes);
                    for (k, v) in &parts.headers {
                        fwd = fwd.header(k, v);
                    }
                    let resp = fwd.send().await.unwrap();
                    let status = resp.status();
                    let resp_bytes = resp.bytes().await.unwrap();
                    (
                        status,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        resp_bytes,
                    )
                }
            }
        }),
    );
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, proxy_router).await;
    });
    let proxy_url = format!("http://{proxy_addr}");

    let store_a = Arc::new(MemStore::default());
    store_a.save("LTAI_TEST_AK:secret123").unwrap();
    let api_a = AliyunEcs::with_endpoints(&proxy_url, &proxy_url, &proxy_url, store_a, None)
        .with_poll(std::time::Duration::from_millis(5));

    let store_b = Arc::new(MemStore::default());
    store_b.save("LTAI_TEST_AK:secret123").unwrap();
    let api_b = AliyunEcs::with_endpoints(&proxy_url, &proxy_url, &proxy_url, store_b, None)
        .with_poll(std::time::Duration::from_millis(5));

    let ca = conn(&api_a);
    let cb = conn(&api_b);
    let locks_a = aliyun_net::NetLocks::default();
    let locks_b = aliyun_net::NetLocks::default();

    let (res_a, res_b) = tokio::join!(
        aliyun_net::prepare_network(
            &api_a,
            &ca,
            "cn-hangzhou",
            "owner1",
            "ecs.e-c1m2.large",
            &cfg,
            &locks_a
        ),
        aliyun_net::prepare_network(
            &api_b,
            &cb,
            "cn-hangzhou",
            "owner1",
            "ecs.e-c1m2.large",
            &cfg,
            &locks_b
        ),
    );
    let net_a = res_a.unwrap();
    let net_b = res_b.unwrap();
    assert_eq!(net_a.security_group_id, net_b.security_group_id);
    assert_eq!(net_a.security_group_id, "sg-fake-1");
    assert_eq!(
        s2.lock().unwrap().security_groups.len(),
        1,
        "race-loser security group must be deleted"
    );
}

#[tokio::test]
async fn spaces_create_linux_on_aliyun_ecs_runs_docker_on_vm() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let token = Arc::new(cua_spaces::relay::StaticToken("acct-tok".into()));
    let access = RelayAccess::new(relay.url.clone(), token.clone());

    let (api, s, _) = start(None).await;
    {
        let relay_hook = relay.clone();
        s.lock().unwrap().on_run_instance = Some(Arc::new(move |_inst_id, params| {
            let ud = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(params.get("UserData").unwrap())
                    .unwrap(),
            )
            .unwrap();
            let mid = decode_cloud_init_file(&ud, "/etc/cua/relay/machine-id")
                .trim()
                .to_string();
            relay_hook.set_online(&mid, true, "0.1.0");
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();
    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ..Default::default()
        })
        .await
        .unwrap();

    let spaces = cua_spaces::Spaces::builder()
        .home(home.path())
        .sandboxes(sandboxes)
        .relay(cua_spaces::relay::RelayAccount::new(
            relay.url.clone(),
            token,
        ))
        .build();
    let mut policy = spaces.elastic_policy();
    policy.autoscale = false;
    spaces.set_elastic_policy(&policy).unwrap();

    let info = spaces
        .create(cua_spaces::SpaceCreate {
            on: Some(cua_sandbox_core::placement::On::Provider(
                "aliyun-ecs".into(),
            )),
            image: Some(HERMETIC_LINUX_IMAGE.into()),
            name: Some("Aliyun Space".into()),
            runtime: Runtime::Other("docker".into()),
            ..Default::default()
        })
        .await
        .unwrap()
        .ready()
        .unwrap();

    assert!(info.id.starts_with("relay:cloud-"), "{}", info.id);
    assert_eq!(info.name, "aliyun-space");
    assert_eq!(
        spaces.cloud_sandbox_of(&info.id).unwrap().as_deref(),
        Some("aliyun-space")
    );
    let machine = info.id.trim_start_matches("relay:");
    assert!(relay.machine(machine).is_some());

    spaces.delete(&info.id).await.unwrap();
    assert!(s.lock().unwrap().instances.is_empty());
    assert!(relay.machine(machine).is_none());
}

#[tokio::test]
async fn vswitch_skips_used_cidrs_and_linux_slim_enforces_40g_cloud_essd() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);

    let vpc_tags = aliyun_net::part_tags("owner1");
    {
        let mut f = s.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-pre-1".into(),
            vpc_name: aliyun_net::vpc_name("owner1"),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: vpc_tags,
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-other-zone".into(),
            vswitch_name: "other".into(),
            vpc_id: "vpc-pre-1".into(),
            zone_id: "cn-hangzhou-z".into(),
            cidr_block: "10.77.0.0/20".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            ..Default::default()
        });
    }

    assert_eq!(api.default_disk_gb("linux"), 40);
    assert_eq!(api.default_disk_gb("linux-slim"), 40);
    assert_eq!(api.default_disk_gb("windows"), 60);
    assert_eq!(
        api.runtimes(),
        vec![
            Runtime::Other("docker".into()),
            Runtime::Other("native".into()),
        ]
    );
    assert_eq!(api.supported_oses(), &["linux", "windows"]);

    let spec = ProvisionSpec {
        name: "cua-aliyun-ecs-slim1".into(),
        family: "linux-slim".into(),
        image: HERMETIC_LINUX_IMAGE.into(),
        kind: "container".into(),
        machine_type: String::new(),
        disk_gb: 30, // Must clamp up to 40 GiB minimum for Alibaba Cloud ESSD
        user_data: "#cloud-config\n".into(),
        tags: model::tags("owner1", "slim", "cloud-slim", 0),
        ttl_secs: 0,
        arch: "amd64".into(),
        runtime: "docker".into(),
        ..Default::default()
    };
    let made = api.provision(&c, &spec).await.unwrap();
    assert_eq!(made[0].extra["machine_type"], "ecs.e-c1m1.large");

    let f = s.lock().unwrap();
    let new_vsw = f
        .vswitches
        .values()
        .find(|v| v.vswitch_id != "vsw-other-zone")
        .unwrap();
    assert_eq!(
        new_vsw.cidr_block, "10.77.16.0/20",
        "must skip occupied 10.77.0.0/20"
    );
    let run = f.calls.iter().find(|c| c.action == "RunInstances").unwrap();
    assert_eq!(
        run.params.get("SystemDisk.Size").map(String::as_str),
        Some("40")
    );
    assert_eq!(
        run.params.get("SystemDisk.Category").map(String::as_str),
        Some("cloud_essd")
    );
    assert!(!run.params.contains_key("AutoReleaseTime"));
}

fn decode_b64_str(raw: &str) -> String {
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .expect("valid base64"),
    )
    .expect("valid utf8")
}

fn decode_ps_put(script: &str, name: &str) -> Option<String> {
    let needle = format!("'{name}') '");
    let idx = script.find(&needle)? + needle.len();
    let rest = &script[idx..];
    let end = rest.find('\'')?;
    Some(decode_b64_str(&rest[..end]))
}

#[tokio::test]
async fn windows_direct_vm_account_mode_lifecycle_and_userdata_contract() {
    use cua_sandbox_core::placement::Kind;
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "user-win", Some("win@example.com"));
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    let api = Arc::new(api);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![api.clone()],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let mirror_sha = "cd".repeat(32);
    let mirror_url = format!("https://mirror.example.com/cua-spacesd.exe#sha256={mirror_sha}");

    clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                spacesd_download_url: Some(mirror_url.clone()),
                ..Default::default()
            },
            max_size: Some("2x4".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut o_small = CreateOptions::new(ProviderKind::Contrib, "windows");
    o_small.contrib = Some("aliyun-ecs".into());
    o_small.name = Some("win-too-big".into());
    o_small.os = "windows".into();
    let err = sandboxes.create(o_small).await.unwrap_err();
    assert!(err.to_string().contains("2 vCPU"), "{err}");
    assert!(s.lock().unwrap().instances.is_empty());

    let connected = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                ..Default::default()
            },
            max_size: Some("4x16".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        connected.provider.spacesd_download_url.as_deref(),
        Some(mirror_url.as_str())
    );

    let mut o_docker = CreateOptions::new(ProviderKind::Contrib, "windows");
    o_docker.contrib = Some("aliyun-ecs".into());
    o_docker.name = Some("win-docker-nope".into());
    o_docker.os = "windows".into();
    o_docker.runtime = Runtime::Other("docker".into());
    let err = sandboxes.create(o_docker).await.unwrap_err();
    assert!(
        err.to_string().contains("native") || err.to_string().contains("VM"),
        "{err}"
    );

    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
    }

    let mut o = CreateOptions::new(ProviderKind::Contrib, "windows");
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some("win-acct-1".into());
    o.os = "windows".into();
    let sb = sandboxes.create(o).await.unwrap();
    assert_eq!(sb.placement(), (Kind::Vm, Runtime::Other("native".into())));

    let run_call = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run_call.params.get("InstanceType").map(String::as_str),
        Some("ecs.c7.xlarge")
    );
    assert_eq!(
        run_call.params.get("SystemDisk.Size").map(String::as_str),
        Some("60")
    );
    assert_eq!(
        run_call
            .params
            .get("SystemDisk.Category")
            .map(String::as_str),
        Some("cloud_essd")
    );
    assert_eq!(
        run_call
            .params
            .get("InstanceChargeType")
            .map(String::as_str),
        Some("PostPaid")
    );
    assert_eq!(
        run_call.params.get("StoppedMode").map(String::as_str),
        Some("StopCharging")
    );
    assert_eq!(
        run_call.params.get("HttpTokens").map(String::as_str),
        Some("optional")
    );
    assert!(run_call.params.contains_key("AutoReleaseTime"));
    let img_id = run_call.params.get("ImageId").unwrap();
    assert!(img_id.starts_with("win2022_"), "{img_id}");
    let ecs_pw = run_call.params.get("Password").unwrap();
    assert!(ecs_pw.len() >= 16);

    let mut run_tags = BTreeMap::new();
    for i in 1..=10 {
        if let (Some(k), Some(v)) = (
            run_call.params.get(&format!("Tag.{i}.Key")),
            run_call.params.get(&format!("Tag.{i}.Value")),
        ) {
            run_tags.insert(k.clone(), v.clone());
        }
    }
    for req_key in [
        model::tag::MANAGED,
        model::tag::OWNER,
        model::tag::SPACE,
        model::tag::MACHINE,
        model::tag::CREATED_BY,
        model::tag::EXPIRES,
    ] {
        assert!(run_tags.contains_key(req_key), "missing tag {req_key}");
    }

    let user_data = decode_b64_str(run_call.params.get("UserData").unwrap());
    assert!(user_data.starts_with("[powershell]\n"));
    assert!(user_data.contains("Is64BitOperatingSystem"));
    assert!(user_data.contains(r"Sysnative\WindowsPowerShell\v1.0\powershell.exe"));
    assert!(user_data.len() < 16 * 1024);
    assert!(!user_data.contains(ecs_pw));
    assert!(user_data.contains("*S-1-5-18:(OI)(CI)F"));
    assert!(user_data.contains("*S-1-5-32-544:(OI)(CI)F"));
    assert!(user_data.contains("https://mirror.example.com/cua-spacesd.exe"));
    assert!(user_data.contains(&mirror_sha));
    assert!(!user_data.contains("100.100.100.200"));
    assert!(!user_data.contains("New-NetFirewallRule"));
    assert!(user_data.contains("S-1-5-21-*-500"));
    assert!(user_data.contains("Start-Process") && user_data.contains("reboot-wait.ps1"));
    assert!(user_data.contains("AutoAdminLogon"));
    assert!(user_data.contains("-AtLogOn"));
    assert!(user_data.contains("EventID=24"));
    let tscon = decode_ps_put(&user_data, "tscon-recover.ps1").unwrap();
    assert!(tscon.contains("tscon.exe") && tscon.contains("/dest:console"));
    let launcher = decode_ps_put(&user_data, "launch-spacesd.ps1").unwrap();
    assert!(launcher.contains("--relay-jwks"));
    assert!(decode_ps_put(&user_data, "jwks.json").is_some());

    let client = sb.spacesd().await.unwrap();
    client.health().await.unwrap();

    sandboxes.suspend("win-acct-1").await.unwrap();
    {
        let f = s.lock().unwrap();
        let stop_call = f
            .calls
            .iter()
            .rfind(|c| c.action == "StopInstance")
            .unwrap();
        assert_eq!(
            stop_call.params.get("StoppedMode").map(String::as_str),
            Some("StopCharging")
        );
    }
    sandboxes.resume("win-acct-1").await.unwrap();
    assert_eq!(
        sandboxes.get("win-acct-1").await.unwrap().status,
        cua_sandbox_core::Status::Running
    );

    let inst_id = sb.provider_details()["id"].clone();
    let inst_res = model::Resource {
        provider: "aliyun-ecs".into(),
        id: inst_id.clone(),
        resource_type: "instance".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    assert!(
        api.delete(&conn(&api), &inst_res, "wrong-owner")
            .await
            .is_err()
    );
    assert!(s.lock().unwrap().instances.contains_key(&inst_id));

    sandboxes.delete("win-acct-1").await.unwrap();
    assert!(!s.lock().unwrap().instances.contains_key(&inst_id));
}

#[tokio::test]
async fn windows_direct_vm_static_mode_and_failed_boot_redaction_rollback() {
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_tok = "static-win-secret-token-xyz";
    relay.add_static_token(static_tok);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("unused".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(cua_sandbox_core::byoc::RelayMode::Static),
                relay_token: Some(static_tok.into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            let mut mid = None;
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                {
                    mid = params.get(&format!("Tag.{i}.Value")).cloned();
                }
            }
            if let Some(mid) = mid {
                let ud = decode_b64_str(params.get("UserData").unwrap());
                let env_tok = decode_ps_put(&ud, "env-token").unwrap();
                relay.tunnel(&mid, &mock_url);
                relay.set_static_online(&mid, true, Some(&env_tok));
            }
        }));
    }

    let mut o = CreateOptions::new(ProviderKind::Contrib, "windows");
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some("win-static-1".into());
    o.os = "windows".into();
    let sb = sandboxes.create(o).await.unwrap();
    let run_call = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    let ud = decode_b64_str(run_call.params.get("UserData").unwrap());
    assert!(decode_ps_put(&ud, "jwks.json").is_none());
    assert!(decode_ps_put(&ud, "env-token").is_some());
    let policy: serde_json::Value =
        serde_json::from_str(&decode_ps_put(&ud, "host-policy.json").unwrap()).unwrap();
    assert!(policy.get("owner").is_none());
    let launcher = decode_ps_put(&ud, "launch-spacesd.ps1").unwrap();
    assert!(!launcher.contains("--relay-jwks"));
    assert!(launcher.contains("--token-file"));

    let client = sb.spacesd().await.unwrap();
    client.health().await.unwrap();
    sandboxes.delete("win-static-1").await.unwrap();

    {
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(|_id, _| {}));
    }
    let s_clone = s.clone();
    let (fail_tx, mut fail_rx) = tokio::sync::oneshot::channel::<()>();
    let fail_tx = Arc::new(Mutex::new(Some(fail_tx)));
    let captured_pw: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cred_mirror = format!(
        "https://dluser:MyPass998877@mirror.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256={}",
        "ef".repeat(32)
    );
    let cred_err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(cua_sandbox_core::byoc::RelayMode::Static),
                relay_token: Some(static_tok.into()),
                spacesd_download_url: Some(cred_mirror.clone()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(!cred_err.to_string().contains("MyPass998877"), "{cred_err}");
    assert!(
        !cred_err.to_string().contains("DeadBeefCafe9988"),
        "{cred_err}"
    );

    let mirror_url = format!(
        "https://mirror.example.com/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256={}",
        "ef".repeat(32)
    );
    let conn_res = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(cua_sandbox_core::byoc::RelayMode::Static),
                relay_token: Some(static_tok.into()),
                spacesd_download_url: Some(mirror_url.clone()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    let conn_dbg = format!("{conn_res:?}");
    assert!(!conn_dbg.contains("DeadBeefCafe9988"), "{conn_dbg}");
    {
        let mut f = s.lock().unwrap();
        let s_inner = s_clone.clone();
        let fail_tx = fail_tx.clone();
        let captured_pw = captured_pw.clone();
        let mirror_url = mirror_url.clone();
        let cred_mirror = cred_mirror.clone();
        f.on_run_instance = Some(Arc::new(move |id, params| {
            let id_owned = id.to_string();
            let pw = params.get("Password").cloned().unwrap_or_default();
            *captured_pw.lock().unwrap() = Some(pw.clone());
            let s2 = s_inner.clone();
            let tx = fail_tx.clone();
            let mirror_url = mirror_url.clone();
            let cred_mirror = cred_mirror.clone();
            tokio::spawn(async move {
                let mut f = s2.lock().unwrap();
                f.console_outputs.insert(
                    id_owned.clone(),
                    format!(
                        "cloudbase-init starting\nCUA_RELAY_TOKEN={static_tok}\nWinlogonPassword={pw}\nInvoke-WebRequest failed: {mirror_url}\nfallback: {cred_mirror}\nfatal: mirror download 404\n"
                    ),
                );
                if let Some(inst) = f.instances.get_mut(&id_owned) {
                    inst.status = "Stopped".into();
                }
                if let Some(ch) = tx.lock().unwrap().take() {
                    let _ = ch.send(());
                }
            });
        }));
    }

    let mut o_fail = CreateOptions::new(ProviderKind::Contrib, "windows");
    o_fail.contrib = Some("aliyun-ecs".into());
    o_fail.name = Some("win-boot-fail".into());
    o_fail.os = "windows".into();
    let err = sandboxes.create(o_fail).await.unwrap_err();
    let _ = fail_rx.try_recv();
    let pw = captured_pw.lock().unwrap().clone().unwrap();
    assert!(
        err.to_string()
            .contains("stopped before its sandbox came online"),
        "{err}"
    );
    assert!(
        err.to_string().contains("fatal: mirror download 404"),
        "{err}"
    );
    assert!(!err.to_string().contains(static_tok), "{err}");
    assert!(!err.to_string().contains(&pw), "{err}");
    assert!(!err.to_string().contains("MyPass998877"), "{err}");
    assert!(!err.to_string().contains("DeadBeefCafe9988"), "{err}");
    assert!(
        s.lock().unwrap().instances.is_empty(),
        "failed boot instance must be rolled back"
    );

    let boot_logs_dir = home.path().join("cloud/boot-logs");
    let logs: Vec<String> = std::fs::read_dir(&boot_logs_dir)
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!logs.is_empty());
    for log in &logs {
        assert!(!log.contains(static_tok), "{log}");
        assert!(!log.contains(&pw), "{log}");
        assert!(!log.contains("MyPass998877"), "{log}");
        assert!(!log.contains("DeadBeefCafe9988"), "{log}");
        assert!(log.contains("fatal: mirror download 404"), "{log}");
    }
}

#[tokio::test]
async fn spaces_create_windows_on_aliyun_ecs_static_relay_infers_os_and_vm_kind() {
    use cua_sandbox_core::placement::On;
    use cua_spaces::{SpaceCreate, Spaces};
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_tok = "static-spaces-win-tok";
    relay.add_static_token(static_tok);
    relay.set_account_auth(false);
    let mock_holder: Arc<Mutex<Option<MockServer>>> = Arc::new(Mutex::new(None));
    let expected_env_tok: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let (api, s, _store) = start(None).await;
    {
        let relay = relay.clone();
        let mock_holder = mock_holder.clone();
        let expected_env_tok = expected_env_tok.clone();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            let mut mid = None;
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                {
                    mid = params.get(&format!("Tag.{i}.Value")).cloned();
                }
            }
            if let Some(mid) = mid {
                let ud = decode_b64_str(params.get("UserData").unwrap());
                let env_tok = decode_ps_put(&ud, "env-token").unwrap();
                *expected_env_tok.lock().unwrap() = Some(env_tok.clone());
                let relay = relay.clone();
                let mock_holder = mock_holder.clone();
                tokio::spawn(async move {
                    let mock = MockServer::start(MockAuth {
                        token: Some(env_tok.clone()),
                        ..Default::default()
                    })
                    .await;
                    let mock_url = mock.url();
                    *mock_holder.lock().unwrap() = Some(mock);
                    relay.tunnel(&mid, &mock_url);
                    relay.set_static_online(&mid, true, Some(&env_tok));
                });
            }
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("unused".into())),
        ),
    )
    .build();
    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(cua_sandbox_core::byoc::RelayMode::Static),
                relay_token: Some(static_tok.into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    let spaces = Spaces::builder()
        .home(home.path())
        .sandboxes(sandboxes.clone())
        .build();

    let created = spaces
        .create(SpaceCreate {
            on: Some(On::Provider("aliyun-ecs".into())),
            image: Some("windows".into()),
            name: Some("Win Space".into()),
            ..Default::default()
        })
        .await
        .unwrap()
        .ready()
        .unwrap();

    assert!(created.id.starts_with("relay:cloud-"), "{}", created.id);
    assert_eq!(created.kind, "vm");

    let expected_tok = expected_env_tok.lock().unwrap().clone().unwrap();
    let space = spaces.space(&created.id).await.unwrap();
    space.spacesd().unwrap().health().await.unwrap();
    let sb_name = spaces.cloud_sandbox_of(&created.id).unwrap().unwrap();
    let sb = sandboxes.connect(&sb_name).await.unwrap();
    assert_eq!(sb.env_token().as_deref(), Some(expected_tok.as_str()));
    let ep = sb.service("env").unwrap().endpoint().await.unwrap();
    assert!(
        ep.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case(cua_spacesd_client::transport::ENV_TOKEN_HEADER)
                && v == &format!("Bearer {expected_tok}")
        }),
        "missing/wrong env token header in {:?}",
        ep.headers
    );

    let run_call = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run_call.params.get("InstanceType").map(String::as_str),
        Some("ecs.c7.xlarge")
    );
    assert_eq!(
        run_call.params.get("SystemDisk.Size").map(String::as_str),
        Some("60")
    );

    let off = spaces.stop(&created.id).await.unwrap();
    assert_eq!(off.state, "stopped");
    let on = spaces.start(&created.id).await.unwrap();
    assert_eq!(on.state, "running");
    spaces.delete(&created.id).await.unwrap();
    assert!(s.lock().unwrap().instances.is_empty());
    drop(mock_holder);
}

#[tokio::test]
async fn connection_defaults_validated_in_test_persisted_and_rejected_on_unsupported_clouds() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "m-win11-golden".into(),
            image_name: "win11-golden".into(),
            owner_alias: "self".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 50,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-ubuntu-golden".into(),
            image_name: "ubuntu-golden".into(),
            owner_alias: "self".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 25,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-creating-win".into(),
            image_name: "win-creating".into(),
            owner_alias: "self".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Creating".into(),
            size_gb: 50,
            ..Default::default()
        });
        f.add_instance_type("ecs.c7.2xlarge", 8, 16.0);
    }

    let dir = tempfile::tempdir().unwrap();
    let relay = cua_host::testing::FakeRelay::start().await;
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let api_arc = Arc::new(api);
    let mut apis: Vec<Arc<dyn CloudApi>> = vec![api_arc.clone()];
    let fake_other = cua_byoc::testing::FakeProvider::new("hetzner", model::Tier::Vm);
    apis.push(fake_other);
    let (_, clouds) = cua_byoc::clouds(dir.path(), apis, access);

    use cua_sandbox_core::byoc::CloudManager as _;

    for bad in [
        Target {
            provider: "hetzner".into(),
            windows_image_id: Some("m-win11-golden".into()),
            ..Default::default()
        },
        Target {
            provider: "hetzner".into(),
            linux_image_id: Some("m-ubuntu-golden".into()),
            ..Default::default()
        },
        Target {
            provider: "hetzner".into(),
            instance_type: Some("ecs.c7.2xlarge".into()),
            ..Default::default()
        },
    ] {
        let err = clouds.test(&bad).await.unwrap_err();
        assert!(
            matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
            "{err:?}"
        );
    }

    let err = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            windows_image_id: Some("   ".into()),
            token: Some("LTAI_TEST_AK:secret123".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );

    let wrong_os = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            windows_image_id: Some("m-ubuntu-golden".into()),
            token: Some("LTAI_TEST_AK:secret123".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!wrong_os.ok, "{:?}", wrong_os.checks);
    assert!(
        wrong_os
            .checks
            .iter()
            .any(|c| c.name == "windows_image" && !c.ok && c.detail.contains("OSType")),
        "{:?}",
        wrong_os.checks
    );

    let unavail = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            windows_image_id: Some("m-creating-win".into()),
            token: Some("LTAI_TEST_AK:secret123".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!unavail.ok);
    assert!(
        unavail
            .checks
            .iter()
            .any(|c| c.name == "windows_image" && !c.ok && c.detail.contains("Creating")),
        "{:?}",
        unavail.checks
    );

    let missing_inst = clouds
        .test(&Target {
            provider: "aliyun-ecs".into(),
            instance_type: Some("ecs.does-not-exist".into()),
            token: Some("LTAI_TEST_AK:secret123".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!missing_inst.ok);
    assert!(
        missing_inst
            .checks
            .iter()
            .any(|c| c.name == "machine" && !c.ok),
        "{:?}",
        missing_inst.checks
    );

    let valid = Target {
        provider: "aliyun-ecs".into(),
        windows_image_id: Some(" m-win11-golden ".into()),
        linux_image_id: Some(" m-ubuntu-golden ".into()),
        instance_type: Some(" ecs.c7.2xlarge ".into()),
        token: Some("LTAI_TEST_AK:secret123".into()),
        ..Default::default()
    };
    let report = clouds.test(&valid).await.unwrap();
    assert!(report.ok, "{:?}", report.checks);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "windows_image" && c.ok)
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "linux_image" && c.ok)
    );
    {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty(), "test must create zero instances");
        let img_call = f
            .calls
            .iter()
            .find(|c| {
                c.action == "DescribeImages"
                    && c.params.get("ImageId").map(String::as_str) == Some("m-win11-golden")
            })
            .expect("DescribeImages for custom windows_image_id");
        assert!(
            !img_call.params.contains_key("ImageOwnerAlias"),
            "custom image lookup must not filter ImageOwnerAlias=system: {:?}",
            img_call.params
        );
    }

    let connected = clouds
        .connect_with(&ConnectRequest {
            target: valid,
            budget_usd_month: Some(200.0),
            max_size: Some("8x32x200".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        connected.provider.windows_image_id.as_deref(),
        Some("m-win11-golden")
    );
    assert_eq!(
        connected.provider.linux_image_id.as_deref(),
        Some("m-ubuntu-golden")
    );
    assert_eq!(
        connected.provider.instance_type.as_deref(),
        Some("ecs.c7.2xlarge")
    );
    assert!(store.load().is_some());

    let updated = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                ..Default::default()
            },
            budget_usd_month: Some(300.0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        updated.provider.windows_image_id.as_deref(),
        Some("m-win11-golden")
    );
    assert_eq!(
        updated.provider.linux_image_id.as_deref(),
        Some("m-ubuntu-golden")
    );
    assert_eq!(
        updated.provider.instance_type.as_deref(),
        Some("ecs.c7.2xlarge")
    );
    assert_eq!(updated.provider.budget_usd_month, Some(300.0));
    assert_eq!(updated.provider.max_size, "8x32x200");
}

#[tokio::test]
async fn connect_with_enforces_max_size_before_persisting_and_preserves_limits_on_reconnect() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "m-win11".into(),
            image_name: "win11".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 60,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-lin1".into(),
            image_name: "lin1".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_instance_type("ecs.c7.2xlarge", 8, 16.0);
    }
    let dir = tempfile::tempdir().unwrap();
    let relay = cua_host::testing::FakeRelay::start().await;
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let (_, clouds) = cua_byoc::clouds(dir.path(), vec![Arc::new(api)], access);
    use cua_sandbox_core::byoc::CloudManager as _;

    let err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                instance_type: Some("ecs.g7.4xlarge".into()),
                ..Default::default()
            },
            max_size: Some("4x16".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("--max-size 4x16"),
        "expected max-size rejection, got: {err}"
    );
    assert!(
        store.load().is_none(),
        "credentials must NOT be persisted when max_size check fails"
    );
    assert!(
        cua_byoc::Store::new(dir.path())
            .connection("aliyun-ecs")
            .unwrap()
            .is_none(),
        "state.json must NOT persist a connection whose instance_type exceeds max_size"
    );

    let connected = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                windows_image_id: Some("m-win11".into()),
                linux_image_id: Some("m-lin1".into()),
                instance_type: Some("ecs.c7.2xlarge".into()),
                ..Default::default()
            },
            budget_usd_month: Some(200.0),
            max_size: Some("8x32x200".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(connected.provider.budget_usd_month, Some(200.0));
    assert_eq!(connected.provider.max_size, "8x32x200");

    let updated_budget = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                ..Default::default()
            },
            budget_usd_month: Some(300.0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(updated_budget.provider.budget_usd_month, Some(300.0));
    assert_eq!(updated_budget.provider.max_size, "8x32x200");
    assert_eq!(
        updated_budget.provider.windows_image_id.as_deref(),
        Some("m-win11")
    );
    assert_eq!(
        updated_budget.provider.linux_image_id.as_deref(),
        Some("m-lin1")
    );
    assert_eq!(
        updated_budget.provider.instance_type.as_deref(),
        Some("ecs.c7.2xlarge")
    );

    let updated_img = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                windows_image_id: Some("m-win11".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(updated_img.provider.budget_usd_month, Some(300.0));
    assert_eq!(updated_img.provider.max_size, "8x32x200");

    let err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                ..Default::default()
            },
            max_size: Some("4x16".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--max-size 4x16"), "{err}");
    let saved = cua_byoc::Store::new(dir.path())
        .connection("aliyun-ecs")
        .unwrap()
        .unwrap();
    assert_eq!(
        saved.max_size.map(|m| m.to_string()).as_deref(),
        Some("8x32x200")
    );
}

#[tokio::test]
async fn image_precedence_official_fallback_and_preflight_limits_enforce_before_provisioning() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "ubuntu_24_04_x64_20G_alibase_20250601.vhd".into(),
            image_name: "ubuntu_24_04_x64_20G_alibase_20250601.vhd".into(),
            owner_alias: "system".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            creation_time: "2025-06-01T00:00:00Z".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd".into(),
            image_name: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd".into(),
            owner_alias: "system".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            creation_time: "2025-09-01T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "win2019_1809_x64_dtc_en-us_40G_alibase_20251001.vhd".into(),
            image_name: "win2019_1809_x64_dtc_en-us_40G_alibase_20251001.vhd".into(),
            owner_alias: "system".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            creation_time: "2025-10-01T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-conn-win".into(),
            image_name: "conn-win".into(),
            owner_alias: "self".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 50,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-create-win".into(),
            image_name: "create-win".into(),
            owner_alias: "self".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 50,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-conn-lin".into(),
            image_name: "conn-lin".into(),
            owner_alias: "self".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-create-lin".into(),
            image_name: "create-lin".into(),
            owner_alias: "self".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_instance_type("ecs.custom.8c32g", 8, 32.0);
    }

    let base_conn = Connection {
        provider: "aliyun-ecs".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));

    let lin_spec = model::ProvisionSpec {
        family: "linux".into(),
        disk_gb: 40,
        ..Default::default()
    };
    let resolved_lin = api.resolve_image_id(&base_conn, &lin_spec).await.unwrap();
    assert_eq!(
        resolved_lin.image_id,
        "ubuntu_24_04_x64_20G_alibase_20250601.vhd"
    );
    assert_eq!(resolved_lin.source, "official-fallback");

    let win_spec = model::ProvisionSpec {
        family: "windows".into(),
        disk_gb: 60,
        ..Default::default()
    };
    let resolved_win = api.resolve_image_id(&base_conn, &win_spec).await.unwrap();
    assert_eq!(
        resolved_win.image_id,
        "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd"
    );
    assert_eq!(resolved_win.source, "official-fallback");

    let mut conn_with_defaults = base_conn.clone();
    conn_with_defaults.windows_image_id = Some("m-conn-win".into());
    conn_with_defaults.linux_image_id = Some("m-conn-lin".into());
    assert_eq!(
        api.resolve_image_id(&conn_with_defaults, &win_spec)
            .await
            .unwrap()
            .image_id,
        "m-conn-win"
    );
    assert_eq!(
        api.resolve_image_id(&conn_with_defaults, &lin_spec)
            .await
            .unwrap()
            .image_id,
        "m-conn-lin"
    );
    let win_override = model::ProvisionSpec {
        cloud_image_id: Some("m-create-win".into()),
        ..win_spec.clone()
    };
    assert_eq!(
        api.resolve_image_id(&conn_with_defaults, &win_override)
            .await
            .unwrap()
            .image_id,
        "m-create-win"
    );
    let lin_override = model::ProvisionSpec {
        cloud_image_id: Some("m-create-lin".into()),
        ..lin_spec.clone()
    };
    assert_eq!(
        api.resolve_image_id(&conn_with_defaults, &lin_override)
            .await
            .unwrap()
            .image_id,
        "m-create-lin"
    );

    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(cua_host::testing::FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let api_arc = Arc::new(api);
    let sbx = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![api_arc.clone()],
        access,
    )
    .build();
    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                windows_image_id: Some("m-conn-win".into()),
                linux_image_id: Some("m-conn-lin".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            budget_usd_month: Some(0.50),
            max_size: Some("4x16x80".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    s.lock().unwrap().calls.clear();

    let mut big_inst =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "windows");
    big_inst.contrib = Some("aliyun-ecs".into());
    big_inst.os = "windows".into();
    big_inst.instance_type = Some("ecs.g7.4xlarge".into());
    let err = sbx.create(big_inst).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(err.to_string().contains("up to 4 vCPU and 16 GB"), "{err}");

    let mut custom_big = cua_sandbox_core::CreateOptions::new(
        cua_sandbox_core::ProviderKind::Contrib,
        "ghcr.io/trycua/linux:24.04",
    );
    custom_big.contrib = Some("aliyun-ecs".into());
    custom_big.instance_type = Some("ecs.custom.8c32g".into());
    let err = sbx.create(custom_big).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(err.to_string().contains("8 vCPU"), "{err}");

    let mut big_disk =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "windows");
    big_disk.contrib = Some("aliyun-ecs".into());
    big_disk.os = "windows".into();
    big_disk.disk_gb = Some(120);
    let err = sbx.create(big_disk).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(
        err.to_string().contains("allows disks up to 80 GB"),
        "{err}"
    );

    let mut small_disk =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "windows");
    small_disk.contrib = Some("aliyun-ecs".into());
    small_disk.os = "windows".into();
    small_disk.disk_gb = Some(30);
    let err = sbx.create(small_disk).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(
        err.to_string().contains("smaller than Cloud Image ID"),
        "{err}"
    );

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                ..Default::default()
            },
            budget_usd_month: Some(0.05),
            ..Default::default()
        })
        .await
        .unwrap();
    s.lock().unwrap().calls.clear();
    let mut over_budget =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "windows");
    over_budget.contrib = Some("aliyun-ecs".into());
    over_budget.os = "windows".into();
    let err = sbx.create(over_budget).await.unwrap_err();
    assert!(matches!(err, cua_sandbox_core::Error::Cloud(_)), "{err:?}");
    assert!(err.to_string().contains("budget"), "{err}");

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                ..Default::default()
            },
            budget_usd_month: Some(100.0),
            ..Default::default()
        })
        .await
        .unwrap();
    s.lock().unwrap().calls.clear();
    let mut wrong_os_create =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "windows");
    wrong_os_create.contrib = Some("aliyun-ecs".into());
    wrong_os_create.os = "windows".into();
    wrong_os_create.cloud_image_id = Some("m-conn-lin".into());
    let err = sbx.create(wrong_os_create).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(err.to_string().contains("OSType"), "{err}");

    let mut missing_img =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "windows");
    missing_img.contrib = Some("aliyun-ecs".into());
    missing_img.os = "windows".into();
    missing_img.cloud_image_id = Some("m-does-not-exist".into());
    let err = sbx.create(missing_img).await.unwrap_err();
    assert!(matches!(err, cua_sandbox_core::Error::Cloud(_)), "{err:?}");

    let f = s.lock().unwrap();
    for forbidden in [
        "RunInstances",
        "CreateVpc",
        "CreateVSwitch",
        "CreateSecurityGroup",
    ] {
        assert!(
            !f.calls.iter().any(|c| c.action == forbidden),
            "preflight rejections must never reach {forbidden}: {:?}",
            f.calls
        );
    }
    assert!(f.instances.is_empty());
    assert_eq!(relay.register_calls(), 0);
    assert!(
        cua_byoc::Store::new(dir.path())
            .resources()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn validate_image_id_and_official_fallback_require_ostype_and_available_status() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.images.retain(|img| img.os_type != "windows");
        f.add_image(FakeImage {
            image_id: "m-missing-ostype".into(),
            image_name: "missing-ostype".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-empty-ostype".into(),
            image_name: "empty-ostype".into(),
            os_type: "   ".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 40,
            ..Default::default()
        });
        // Add >100 non-win2022 system Windows images BEFORE the win2022 image so an unfiltered
        // PageSize=50 or PageSize=100 query truncates win2022 unless ImageName=win2022* is queried.
        for i in 0..105 {
            f.add_image(FakeImage {
                image_id: format!("win2016_x64_dtc_{i:03}.vhd"),
                image_name: format!("win2016_x64_dtc_{i:03}.vhd"),
                owner_alias: "system".into(),
                os_type: "windows".into(),
                arch: "x86_64".into(),
                status: "Available".into(),
                creation_time: "2024-01-01T00:00:00Z".into(),
                size_gb: 40,
                ..Default::default()
            });
        }
        f.add_image(FakeImage {
            image_id: "ubuntu_24_04_x64_missing_status.vhd".into(),
            image_name: "ubuntu_24_04_x64_missing_status.vhd".into(),
            owner_alias: "system".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            creation_time: "2026-01-01T00:00:00Z".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd".into(),
            image_name: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd".into(),
            owner_alias: "system".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            creation_time: "2025-09-01T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
    }
    let conn = Connection {
        provider: "aliyun-ecs".into(),
        region: "cn-hangzhou".into(),
        ..Default::default()
    };
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));

    for bad_id in ["m-missing-ostype", "m-empty-ostype"] {
        let err = api
            .validate_image_id(&conn, bad_id, "windows")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("OSType"),
            "missing/empty OSType must fail: {err}"
        );
    }

    let win = api.resolve_official_image(&conn, "windows").await.unwrap();
    assert_eq!(
        win.image_id,
        "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd"
    );

    let lin = api.resolve_official_image(&conn, "linux").await.unwrap();
    assert_eq!(lin.image_id, "ubuntu_24_04_x64_20G_alibase_20250101.vhd");
}

#[tokio::test]
async fn os_vs_image_family_and_linux_image_with_windows_substring() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "m-lin-tools".into(),
            image_name: "linux-tools".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 40,
            ..Default::default()
        });
    }
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(cua_host::testing::FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let sbx = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();
    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    s.lock().unwrap().calls.clear();

    let mut mismatch =
        cua_sandbox_core::CreateOptions::new(cua_sandbox_core::ProviderKind::Contrib, "linux");
    mismatch.contrib = Some("aliyun-ecs".into());
    mismatch.os = "windows".into();
    mismatch.cloud_image_id = Some("m-lin-tools".into());
    let err = sbx.create(mismatch).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(s.lock().unwrap().calls.is_empty());

    let mock_spacesd = cua_spacesd_client::testing::MockServer::start(
        cua_spacesd_client::testing::MockAuth::default(),
    )
    .await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
    }
    let mut lin_win_name = cua_sandbox_core::CreateOptions::new(
        cua_sandbox_core::ProviderKind::Contrib,
        "myorg/windows-tools:1",
    );
    lin_win_name.contrib = Some("aliyun-ecs".into());
    lin_win_name.os = "linux".into();
    lin_win_name.cloud_image_id = Some("m-lin-tools".into());
    lin_win_name.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(lin_win_name).await.unwrap();
    sb.delete().await.unwrap();
    let run_call = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run_call.params.get("ImageId").map(String::as_str),
        Some("m-lin-tools")
    );
    let ud = decode_b64_str(run_call.params.get("UserData").unwrap());
    assert!(ud.starts_with("#cloud-config"), "{ud}");
}

#[tokio::test]
async fn run_instances_receives_resolved_image_instance_type_and_disk_across_precedence() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "ubuntu_24_04_x64_20G_alibase_20250601.vhd".into(),
            image_name: "ubuntu_24_04_x64_20G_alibase_20250601.vhd".into(),
            owner_alias: "system".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            creation_time: "2025-06-01T00:00:00Z".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd".into(),
            image_name: "win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd".into(),
            owner_alias: "system".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            creation_time: "2025-09-01T00:00:00Z".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-conn-win".into(),
            image_name: "conn-win".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 50,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-create-win".into(),
            image_name: "create-win".into(),
            os_type: "windows".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 50,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-conn-lin".into(),
            image_name: "conn-lin".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-create-lin".into(),
            image_name: "create-lin".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 20,
            ..Default::default()
        });
        f.add_instance_type("ecs.c7.2xlarge", 8, 16.0);
        f.add_instance_type("ecs.custom.8c32g", 8, 32.0);
    }

    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(cua_host::testing::FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let mock_spacesd = cua_spacesd_client::testing::MockServer::start(
        cua_spacesd_client::testing::MockAuth::default(),
    )
    .await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
    }

    let sbx = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();

    let last_run = |s: &S| {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    let mut lin_official = sb_create_opts("lin-official");
    lin_official.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(lin_official).await.unwrap();
    sb.delete().await.unwrap();
    let r = last_run(&s);
    assert_eq!(
        r.params.get("ImageId").map(String::as_str),
        Some("ubuntu_24_04_x64_20G_alibase_20250601.vhd")
    );
    assert_eq!(
        r.params.get("InstanceType").map(String::as_str),
        Some("ecs.e-c1m2.large")
    );
    assert_eq!(
        r.params.get("SystemDisk.Size").map(String::as_str),
        Some("40")
    );
    assert_eq!(
        r.params.get("HttpTokens").map(String::as_str),
        Some("required")
    );
    assert!(decode_b64_str(r.params.get("UserData").unwrap()).starts_with("#cloud-config"));

    let mut win_official = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_official.contrib = Some("aliyun-ecs".into());
    win_official.name = Some("win-official".into());
    win_official.os = "windows".into();
    win_official.runtime = Runtime::Other("native".into());
    win_official.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(win_official).await.unwrap();
    sb.delete().await.unwrap();
    let r = last_run(&s);
    assert_eq!(
        r.params.get("ImageId").map(String::as_str),
        Some("win2022_21H2_x64_dtc_en-us_40G_alibase_20250901.vhd")
    );
    assert_eq!(
        r.params.get("InstanceType").map(String::as_str),
        Some("ecs.c7.xlarge")
    );
    assert_eq!(
        r.params.get("SystemDisk.Size").map(String::as_str),
        Some("60")
    );
    assert_eq!(
        r.params.get("HttpTokens").map(String::as_str),
        Some("optional")
    );
    let win_official_ud = decode_b64_str(r.params.get("UserData").unwrap());
    assert!(win_official_ud.starts_with("[powershell]\n"));
    assert!(win_official_ud.contains("Is64BitOperatingSystem"));

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                windows_image_id: Some("m-conn-win".into()),
                linux_image_id: Some("m-conn-lin".into()),
                instance_type: Some("ecs.c7.2xlarge".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    let mut lin_conn = sb_create_opts("lin-conn");
    lin_conn.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(lin_conn).await.unwrap();
    sb.delete().await.unwrap();
    let r = last_run(&s);
    assert_eq!(
        r.params.get("ImageId").map(String::as_str),
        Some("m-conn-lin")
    );
    assert_eq!(
        r.params.get("InstanceType").map(String::as_str),
        Some("ecs.c7.2xlarge")
    );
    assert_eq!(
        r.params.get("SystemDisk.Size").map(String::as_str),
        Some("40")
    );
    assert!(decode_b64_str(r.params.get("UserData").unwrap()).starts_with("#cloud-config"));

    let mut win_conn = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_conn.contrib = Some("aliyun-ecs".into());
    win_conn.name = Some("win-conn".into());
    win_conn.os = "windows".into();
    win_conn.runtime = Runtime::Other("native".into());
    win_conn.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(win_conn).await.unwrap();
    sb.delete().await.unwrap();
    let r = last_run(&s);
    assert_eq!(
        r.params.get("ImageId").map(String::as_str),
        Some("m-conn-win")
    );
    assert_eq!(
        r.params.get("InstanceType").map(String::as_str),
        Some("ecs.c7.2xlarge")
    );
    assert_eq!(
        r.params.get("SystemDisk.Size").map(String::as_str),
        Some("60")
    );
    assert_eq!(
        r.params.get("HttpTokens").map(String::as_str),
        Some("optional")
    );
    assert!(decode_b64_str(r.params.get("UserData").unwrap()).starts_with("[powershell]\n"));

    let mut lin_over = sb_create_opts("lin-override");
    lin_over.cloud_image_id = Some("m-create-lin".into());
    lin_over.instance_type = Some("ecs.g7.large".into());
    lin_over.disk_gb = Some(80);
    lin_over.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(lin_over).await.unwrap();
    sb.delete().await.unwrap();
    let r = last_run(&s);
    assert_eq!(
        r.params.get("ImageId").map(String::as_str),
        Some("m-create-lin")
    );
    assert_eq!(
        r.params.get("InstanceType").map(String::as_str),
        Some("ecs.g7.large")
    );
    assert_eq!(
        r.params.get("SystemDisk.Size").map(String::as_str),
        Some("80")
    );
    assert_eq!(
        r.params.get("HttpTokens").map(String::as_str),
        Some("required")
    );
    assert!(decode_b64_str(r.params.get("UserData").unwrap()).starts_with("#cloud-config"));

    let mut win_over = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_over.contrib = Some("aliyun-ecs".into());
    win_over.name = Some("win-override".into());
    win_over.os = "windows".into();
    win_over.runtime = Runtime::Other("native".into());
    win_over.cloud_image_id = Some("m-create-win".into());
    win_over.instance_type = Some("ecs.custom.8c32g".into());
    win_over.disk_gb = Some(120);
    win_over.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(win_over).await.unwrap();
    sb.delete().await.unwrap();
    let r = last_run(&s);
    assert_eq!(
        r.params.get("ImageId").map(String::as_str),
        Some("m-create-win")
    );
    assert_eq!(
        r.params.get("InstanceType").map(String::as_str),
        Some("ecs.custom.8c32g")
    );
    assert_eq!(
        r.params.get("SystemDisk.Size").map(String::as_str),
        Some("120")
    );
    assert_eq!(
        r.params.get("HttpTokens").map(String::as_str),
        Some("optional")
    );
    assert!(decode_b64_str(r.params.get("UserData").unwrap()).starts_with("[powershell]\n"));
}

#[tokio::test]
async fn cloud_sandboxes_create_rejects_disk_zero_and_whitespace_directly() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(cua_host::testing::FakeRelay::start().await);
    relay.add_account("acct-tok", "user-1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let (providers, clouds) = cua_byoc::clouds(dir.path(), vec![Arc::new(api)], access);
    use cua_sandbox_core::byoc::CloudManager as _;
    clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    let provider = providers.into_iter().next().unwrap();
    s.lock().unwrap().calls.clear();

    let base_spec = || cua_sandbox_core::ProviderCreate {
        name: "test-direct".into(),
        image: cua_sandbox_core::ProviderImage {
            reference: "windows".into(),
            pinned_ref: "windows".into(),
            digest: String::new(),
            kind: cua_sandbox_core::RunKind::Vm,
            arch: "amd64".into(),
            spacesd: Some(true),
        },
        os: "windows".into(),
        cpus: 4,
        memory_mb: 8192,
        env: Default::default(),
        command: None,
        ports: vec![],
        ttl: None,
        labels: Default::default(),
        registry_credentials: None,
        timeout: std::time::Duration::from_secs(60),
        runtime: cua_sandbox_core::placement::Runtime::Auto,
        gpu: None,
        egress: Default::default(),
        no_network: false,
        protect: false,
        disk_gb: None,
        cloud_image_id: None,
        instance_type: None,
    };

    let mut zero = base_spec();
    zero.disk_gb = Some(0);
    let err = provider.create(&zero).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );

    for bad in ["", "   ", "m-foo bar"] {
        let mut s1 = base_spec();
        s1.cloud_image_id = Some(bad.into());
        let err = provider.create(&s1).await.unwrap_err();
        assert!(
            matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
            "{err:?}"
        );

        let mut s2 = base_spec();
        s2.instance_type = Some(bad.into());
        let err = provider.create(&s2).await.unwrap_err();
        assert!(
            matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
            "{err:?}"
        );
    }
    assert!(s.lock().unwrap().calls.is_empty());
}

fn decode_native_cloud_init_file(user_data: &str, path: &str) -> Option<String> {
    let at = user_data.find(&format!("path: {path}\n"))?;
    let rest = &user_data[at..];
    let c = rest.find("content: ")? + "content: ".len();
    if let Some(after_pipe) = rest[c..].strip_prefix("|\n") {
        let mut out = String::new();
        let mut indent: Option<usize> = None;
        for line in after_pipe.split('\n') {
            if line.is_empty() {
                out.push('\n');
                continue;
            }
            let spaces = line.bytes().take_while(|b| *b == b' ').count();
            let ind = *indent.get_or_insert(spaces);
            if spaces < ind {
                break;
            }
            out.push_str(&line[ind..]);
            out.push('\n');
        }
        while out.ends_with("\n\n") {
            out.pop();
        }
        return Some(out);
    }
    let end = rest[c..].find('\n').unwrap_or(rest.len() - c);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(rest[c..c + end].trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

#[tokio::test]
async fn aliyun_ecs_linux_direct_vm_account_relay_and_docker_default() {
    use cua_sandbox_core::placement::{Kind, Runtime};
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
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
    clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    let sb_docker = sandboxes
        .create(sb_create_opts("linux-docker-default"))
        .await
        .unwrap();
    assert_eq!(
        sb_docker.placement(),
        (Kind::Container, Runtime::Other("docker-on-vm".into()))
    );
    assert_eq!(
        sb_docker
            .provider_details()
            .get("runtime")
            .map(String::as_str),
        Some("docker-on-vm")
    );
    sandboxes.delete("linux-docker-default").await.unwrap();
    s.lock().unwrap().calls.clear();

    let mut opts = sb_create_opts("linux-native-acct");
    opts.runtime = Runtime::Other("native".into());
    opts.env.insert("APP_ENV".into(), "production".into());
    let sb = sandboxes.create(opts).await.unwrap();
    assert_eq!(sb.placement(), (Kind::Vm, Runtime::Other("native".into())));
    assert_eq!(
        sb.provider_details().get("runtime").map(String::as_str),
        Some("native")
    );

    let run_call = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run_call.params.get("InstanceType").map(String::as_str),
        Some("ecs.e-c1m2.large")
    );
    assert_eq!(
        run_call.params.get("SystemDisk.Size").map(String::as_str),
        Some("40")
    );
    assert_eq!(
        run_call
            .params
            .get("SystemDisk.Category")
            .map(String::as_str),
        Some("cloud_essd")
    );
    assert_eq!(
        run_call
            .params
            .get("InstanceChargeType")
            .map(String::as_str),
        Some("PostPaid")
    );
    assert_eq!(
        run_call.params.get("StoppedMode").map(String::as_str),
        Some("StopCharging")
    );
    assert_eq!(
        run_call.params.get("HttpTokens").map(String::as_str),
        Some("required")
    );
    assert!(run_call.params.contains_key("AutoReleaseTime"));
    assert!(!run_call.params.contains_key("Password"));
    let img_id = run_call.params.get("ImageId").unwrap();
    assert!(img_id.starts_with("ubuntu_24_04"), "{img_id}");

    let mut run_tags = BTreeMap::new();
    for i in 1..=10 {
        if let (Some(k), Some(v)) = (
            run_call.params.get(&format!("Tag.{i}.Key")),
            run_call.params.get(&format!("Tag.{i}.Value")),
        ) {
            run_tags.insert(k.clone(), v.clone());
        }
    }
    for req_key in [
        model::tag::MANAGED,
        model::tag::OWNER,
        model::tag::SPACE,
        model::tag::MACHINE,
        model::tag::CREATED_BY,
        model::tag::EXPIRES,
    ] {
        assert!(run_tags.contains_key(req_key), "missing tag {req_key}");
    }

    let ud = decode_b64_str(run_call.params.get("UserData").unwrap());
    assert!(ud.starts_with("#cloud-config\n"));
    assert!(ud.len() < 16 * 1024, "UserData {} >= 16384", ud.len());
    let boot = decode_native_cloud_init_file(&ud, "/usr/local/sbin/cua-first-boot").unwrap();
    assert!(!boot.contains("docker.io") && !boot.contains("docker run"));
    assert!(boot.contains("/usr/local/bin/cua-spacesd"));
    assert!(boot.contains("sha256sum"));
    assert!(boot.contains("100.100.100.200/32"));
    assert!(ud.contains("cua-expire.timer"));
    assert!(decode_native_cloud_init_file(&ud, "/etc/systemd/system/cua-expire.timer").is_some());
    assert!(boot.contains("CUA_ENV_NO_DESKTOP=true"));
    assert!(boot.contains("libxkbcommon0"));
    assert!(boot.contains("cua-spacesd.service"));
    let envf = decode_native_cloud_init_file(&ud, "/etc/cua/spacesd.env").unwrap();
    assert!(envf.contains("APP_ENV=production\n"));
    assert!(envf.contains("CUA_RELAY_JWKS=/etc/cua/relay/jwks.json"));
    assert!(decode_native_cloud_init_file(&ud, "/etc/cua/relay/jwks.json").is_some());

    sandboxes.suspend("linux-native-acct").await.unwrap();
    sandboxes.resume("linux-native-acct").await.unwrap();
    sandboxes.delete("linux-native-acct").await.unwrap();
    assert!(s.lock().unwrap().instances.is_empty());
}

#[tokio::test]
async fn aliyun_ecs_linux_slim_direct_vm_static_relay_mirror_and_failed_boot_rollback() {
    use cua_sandbox_core::placement::{Kind, Runtime};
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_tok = "static-linux-native-secret-xyz";
    relay.add_static_token(static_tok);
    relay.set_account_auth(false);
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("unused".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let mirror_sha = "ab".repeat(32);
    let mirror_url = format!(
        "https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz#sha256={mirror_sha}"
    );
    clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(cua_sandbox_core::byoc::RelayMode::Static),
                relay_token: Some(static_tok.into()),
                spacesd_download_url: Some(mirror_url.clone()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            let mut mid = None;
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                {
                    mid = params.get(&format!("Tag.{i}.Value")).cloned();
                }
            }
            if let Some(mid) = mid {
                let ud = decode_b64_str(params.get("UserData").unwrap());
                let envf = decode_native_cloud_init_file(&ud, "/etc/cua/spacesd.env").unwrap();
                let env_tok = envf
                    .lines()
                    .find_map(|l| l.strip_prefix("CUA_ENV_TOKEN="))
                    .unwrap()
                    .to_string();
                relay.tunnel(&mid, &mock_url);
                relay.set_static_online(&mid, true, Some(&env_tok));
            }
        }));
    }

    let mut o = CreateOptions::new(
        ProviderKind::Contrib,
        "registry.invalid/trycua/linux:24.04-slim",
    );
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some("linux-slim-static-native".into());
    o.runtime = Runtime::Other("native".into());
    let sb = sandboxes.create(o).await.unwrap();
    assert_eq!(sb.placement(), (Kind::Vm, Runtime::Other("native".into())));

    let run_call = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run_call.params.get("InstanceType").map(String::as_str),
        Some("ecs.e-c1m1.large")
    );
    let ud = decode_b64_str(run_call.params.get("UserData").unwrap());
    assert!(ud.len() < 16 * 1024, "UserData {} >= 16384", ud.len());
    assert!(!ud.contains(static_tok));
    assert!(decode_native_cloud_init_file(&ud, "/etc/cua/relay/jwks.json").is_none());
    let boot = decode_native_cloud_init_file(&ud, "/usr/local/sbin/cua-first-boot").unwrap();
    assert!(boot.contains("https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz"));
    assert!(boot.contains(&mirror_sha));

    let client = sb.spacesd().await.unwrap();
    client.health().await.unwrap();
    sandboxes.delete("linux-slim-static-native").await.unwrap();
    assert!(s.lock().unwrap().instances.is_empty());

    {
        let s_inner = s.clone();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |id, params| {
            let id_owned = id.to_string();
            let ud = decode_b64_str(params.get("UserData").unwrap());
            let envf = decode_native_cloud_init_file(&ud, "/etc/cua/spacesd.env").unwrap();
            let env_tok = envf
                .lines()
                .find_map(|l| l.strip_prefix("CUA_ENV_TOKEN="))
                .unwrap()
                .to_string();
            let s2 = s_inner.clone();
            tokio::spawn(async move {
                let mut f = s2.lock().unwrap();
                f.console_outputs.insert(
                    id_owned.clone(),
                    format!(
                        "cua-first-boot: chmod 0600 /etc/cua/spacesd.env\n\
                         cua-first-boot: CUA_ENV_TOKEN={env_tok}\n\
                         cua-first-boot: relay_token={static_tok}\n\
                         cua-first-boot: downloading https://user:s3cr3t\\@mirror.example.com/cua-spacesd.tar.gz\n\
                         cua-first-boot: fatal: linux native SHA-256 mismatch\n"
                    ),
                );
                if let Some(inst) = f.instances.get_mut(&id_owned) {
                    inst.status = "Stopped".into();
                }
            });
        }));
    }

    let mut o_fail = CreateOptions::new(ProviderKind::Contrib, HERMETIC_LINUX_IMAGE);
    o_fail.contrib = Some("aliyun-ecs".into());
    o_fail.name = Some("linux-native-boot-fail".into());
    o_fail.runtime = Runtime::Other("native".into());
    let err = sandboxes.create(o_fail).await.unwrap_err().to_string();
    assert!(
        err.contains("fatal: linux native SHA-256 mismatch"),
        "{err}"
    );
    assert!(!err.contains(static_tok), "{err}");
    assert!(!err.contains("spacesd.env"), "{err}");
    assert!(!err.contains("s3cr3t"), "{err}");
    assert!(!err.contains("user:"), "{err}");
    assert!(
        s.lock().unwrap().instances.is_empty(),
        "failed Linux native boot instance must be rolled back"
    );

    let boot_logs_dir = home.path().join("cloud/boot-logs");
    let logs: Vec<String> = std::fs::read_dir(&boot_logs_dir)
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!logs.is_empty());
    for log in &logs {
        assert!(!log.contains(static_tok), "{log}");
        assert!(!log.contains("spacesd.env"), "{log}");
        assert!(!log.contains("s3cr3t"), "{log}");
        assert!(!log.contains("user:"), "{log}");
        assert!(
            log.contains("fatal: linux native SHA-256 mismatch"),
            "{log}"
        );
    }
}

#[tokio::test]
async fn linux_native_supports_custom_linux_image_id_cloud_image_id_instance_type_and_disk() {
    use cua_sandbox_core::placement::{Kind, Runtime};
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    {
        let mut f = s.lock().unwrap();
        f.add_image(FakeImage {
            image_id: "m-lin-conn-native".into(),
            image_name: "lin-conn-native".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 30,
            ..Default::default()
        });
        f.add_image(FakeImage {
            image_id: "m-lin-over-native".into(),
            image_name: "lin-over-native".into(),
            os_type: "linux".into(),
            arch: "x86_64".into(),
            status: "Available".into(),
            size_gb: 40,
            ..Default::default()
        });
        f.add_instance_type("ecs.c7.2xlarge", 8, 16.0);
    }

    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let mock_spacesd = MockServer::start(MockAuth::default()).await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
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
    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("cn-hangzhou".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                linux_image_id: Some("m-lin-conn-native".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    let mut o_conn = sb_create_opts("lin-native-conn-img");
    o_conn.runtime = Runtime::Other("native".into());
    let sb1 = sandboxes.create(o_conn).await.unwrap();
    assert_eq!(sb1.placement(), (Kind::Vm, Runtime::Other("native".into())));
    sandboxes.delete("lin-native-conn-img").await.unwrap();
    let run1 = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run1.params.get("ImageId").map(String::as_str),
        Some("m-lin-conn-native")
    );
    assert!(decode_b64_str(run1.params.get("UserData").unwrap()).starts_with("#cloud-config\n"));

    let mut o_over = sb_create_opts("lin-native-override-img");
    o_over.runtime = Runtime::Other("native".into());
    o_over.cloud_image_id = Some("m-lin-over-native".into());
    o_over.instance_type = Some("ecs.c7.2xlarge".into());
    o_over.disk_gb = Some(90);
    let sb2 = sandboxes.create(o_over).await.unwrap();
    assert_eq!(sb2.placement(), (Kind::Vm, Runtime::Other("native".into())));
    sandboxes.delete("lin-native-override-img").await.unwrap();
    let run2 = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert_eq!(
        run2.params.get("ImageId").map(String::as_str),
        Some("m-lin-over-native")
    );
    assert_eq!(
        run2.params.get("InstanceType").map(String::as_str),
        Some("ecs.c7.2xlarge")
    );
    assert_eq!(
        run2.params.get("SystemDisk.Size").map(String::as_str),
        Some("90")
    );
    let ud2 = decode_b64_str(run2.params.get("UserData").unwrap());
    assert!(ud2.starts_with("#cloud-config\n"));
    let boot2 = decode_native_cloud_init_file(&ud2, "/usr/local/sbin/cua-first-boot").unwrap();
    assert!(!boot2.contains("docker.io") && !boot2.contains("docker run"));
}

#[tokio::test]
async fn create_options_ttl_zero_disables_connection_default_auto_release_time() {
    use std::time::Duration;

    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let mock_spacesd = MockServer::start(MockAuth::default()).await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
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
    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            ttl_hours: Some(8),
            ..Default::default()
        })
        .await
        .unwrap();

    let _sb_default = sandboxes
        .create(sb_create_opts("ttl-default"))
        .await
        .unwrap();
    sandboxes.delete("ttl-default").await.unwrap();
    let run_default = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert!(
        run_default.params.contains_key("AutoReleaseTime"),
        "expected AutoReleaseTime when CreateOptions.ttl is None: {:?}",
        run_default.params
    );

    let mut o_zero = sb_create_opts("ttl-zero");
    o_zero.ttl = Some(Duration::ZERO);
    let _sb_zero = sandboxes.create(o_zero).await.unwrap();
    sandboxes.delete("ttl-zero").await.unwrap();
    let run_zero = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap()
            .clone()
    };
    assert!(
        !run_zero.params.contains_key("AutoReleaseTime"),
        "expected no AutoReleaseTime when CreateOptions.ttl is Some(ZERO): {:?}",
        run_zero.params
    );
}

#[tokio::test]
async fn delete_part_retries_more_than_four_transient_dependency_violations_and_short_circuits_non_cua_blocker()
 {
    use std::time::{Duration, Instant};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    let api = api.with_poll(Duration::from_millis(10));
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));
    let c = conn(&api);
    let owner = "owner1";
    let tags = aliyun_net::part_tags(owner);

    {
        let mut f = s.lock().unwrap();
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-retry-1".into(),
            vpc_name: aliyun_net::vpc_name(owner),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-retry-1".into(),
            vswitch_name: aliyun_net::vswitch_name(owner, "cn-hangzhou-h"),
            vpc_id: "vpc-retry-1".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "10.77.0.0/20".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-retry-1".into(),
            sg_name: aliyun_net::sg_name(owner),
            vpc_id: "vpc-retry-1".into(),
            region_id: "cn-hangzhou".into(),
            sg_type: "enterprise".into(),
            inner_access_policy: "Drop".into(),
            tags: tags.clone(),
            ..Default::default()
        });
    }

    for (rtype, rid, action) in [
        ("security_group", "sg-retry-1", "DeleteSecurityGroup"),
        ("vswitch", "vsw-retry-1", "DeleteVSwitch"),
        ("vpc", "vpc-retry-1", "DeleteVpc"),
    ] {
        {
            let mut f = s.lock().unwrap();
            f.calls.clear();
            f.transient_dependency_errors = 6;
        }
        let res = Resource {
            provider: "aliyun-ecs".into(),
            id: rid.into(),
            resource_type: rtype.into(),
            region: "cn-hangzhou".into(),
            tags: tags.clone(),
            ..Default::default()
        };
        aliyun_net::delete_part(&api, &c, &res)
            .await
            .unwrap_or_else(|e| panic!("{rtype} must succeed after 6 transient retries: {e}"));
        let del_count = s
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.action == action)
            .count();
        assert_eq!(
            del_count, 7,
            "{action} should be attempted 7 times (6 DependencyViolation + 1 success)"
        );
    }

    let slow_api = api.with_poll(Duration::from_secs(5));
    {
        let mut f = s.lock().unwrap();
        f.calls.clear();
        f.transient_dependency_errors = 0;
        f.seed_vpc(FakeVpc {
            vpc_id: "vpc-blocked-1".into(),
            vpc_name: aliyun_net::vpc_name(owner),
            cidr_block: "10.77.0.0/16".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-blocked-1".into(),
            vswitch_name: aliyun_net::vswitch_name(owner, "cn-hangzhou-h"),
            vpc_id: "vpc-blocked-1".into(),
            zone_id: "cn-hangzhou-h".into(),
            cidr_block: "10.77.0.0/20".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_sg(FakeSg {
            sg_id: "sg-blocked-1".into(),
            sg_name: aliyun_net::sg_name(owner),
            vpc_id: "vpc-blocked-1".into(),
            region_id: "cn-hangzhou".into(),
            sg_type: "enterprise".into(),
            inner_access_policy: "Drop".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.seed_instance(FakeInstance {
            instance_id: "i-foreign-blocker".into(),
            instance_name: "foreign-box".into(),
            region_id: "cn-hangzhou".into(),
            zone_id: "cn-hangzhou-h".into(),
            status: "Running".into(),
            vpc_id: "vpc-blocked-1".into(),
            vswitch_id: "vsw-blocked-1".into(),
            security_group_id: "sg-blocked-1".into(),
            tags: BTreeMap::from([
                ("cua-managed".into(), "true".into()),
                ("cua-owner".into(), "other-owner".into()),
            ]),
            ..Default::default()
        });
    }

    let t0 = Instant::now();
    for (rtype, rid, action) in [
        ("security_group", "sg-blocked-1", "DeleteSecurityGroup"),
        ("vswitch", "vsw-blocked-1", "DeleteVSwitch"),
        ("vpc", "vpc-blocked-1", "DeleteVpc"),
    ] {
        let res = Resource {
            provider: "aliyun-ecs".into(),
            id: rid.into(),
            resource_type: rtype.into(),
            region: "cn-hangzhou".into(),
            tags: tags.clone(),
            ..Default::default()
        };
        let err = aliyun_net::delete_part(&slow_api, &c, &res)
            .await
            .expect_err("permanently blocked part must return DependencyViolation error");
        assert!(err.to_string().contains("DependencyViolation"), "{err}");
        let attempts = s
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.action == action)
            .count();
        assert_eq!(
            attempts, 1,
            "{action} must short-circuit after 1 attempt when blocked by foreign instance"
        );
    }
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "permanent blocker checks took {:?}, expected immediate short-circuit",
        t0.elapsed()
    );
}

#[tokio::test]
async fn clamped_disk_gb_cannot_bypass_max_size_or_budget() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    let home = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(home.path().join("sandboxes")),
        home.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();

    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            max_size: Some("4x16x30".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    s.lock().unwrap().calls.clear();

    let mut small_disk = sb_create_opts("clamp-max-size");
    small_disk.disk_gb = Some(25);
    let err = sandboxes.create(small_disk).await.unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "{err:?}"
    );
    assert!(
        err.to_string().contains("allows disks up to 30 GB")
            && err.to_string().contains("needs 40 GB"),
        "{err}"
    );
    assert!(
        !s.lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.action == "RunInstances"),
        "RunInstances must not be called when clamped disk exceeds --max-size"
    );

    sandboxes
        .clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: target(Some("LTAI_TEST_AK:secret123")),
            max_size: Some("4x16x80".into()),
            budget_usd_month: Some(0.047),
            ..Default::default()
        })
        .await
        .unwrap();
    s.lock().unwrap().calls.clear();

    let mut under_priced = sb_create_opts("clamp-budget");
    under_priced.disk_gb = Some(25);
    let budget_err = sandboxes.create(under_priced).await.unwrap_err();
    assert!(
        matches!(budget_err, cua_sandbox_core::Error::Cloud(_)),
        "{budget_err:?}"
    );
    assert!(
        budget_err.to_string().contains("budget of $0.05")
            || budget_err.to_string().contains("budget"),
        "{budget_err}"
    );
    assert!(
        !s.lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.action == "RunInstances"),
        "RunInstances must not be called when clamped disk exceeds --budget"
    );
}

#[tokio::test]
async fn aliyun_ecs_windows_auto_falls_back_when_c7_xlarge_unavailable() {
    use cua_sandbox_core::placement::Runtime;
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.available_instance_types =
            Some(vec!["ecs.e-c1m2.large".into(), "ecs.e-c1m2.xlarge".into()]);
        f.add_instance_type("ecs.e-c1m2.xlarge", 4, 8.0);
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
    }

    let sbx = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("ap-southeast-1".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();

    let mut win_auto = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_auto.contrib = Some("aliyun-ecs".into());
    win_auto.name = Some("win-auto-fallback".into());
    win_auto.os = "windows".into();
    win_auto.runtime = Runtime::Other("native".into());
    win_auto.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(win_auto).await.unwrap();
    assert_eq!(
        sb.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.e-c1m2.xlarge")
    );
    {
        let f = s.lock().unwrap();
        let run = f
            .calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap();
        assert_eq!(
            run.params.get("InstanceType").map(String::as_str),
            Some("ecs.e-c1m2.xlarge")
        );
    }
    sb.delete().await.unwrap();

    let mut win_explicit = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_explicit.contrib = Some("aliyun-ecs".into());
    win_explicit.name = Some("win-explicit-c7".into());
    win_explicit.os = "windows".into();
    win_explicit.runtime = Runtime::Other("native".into());
    win_explicit.instance_type = Some("ecs.c7.xlarge".into());
    win_explicit.ready_timeout = std::time::Duration::from_secs(10);
    let sb2 = sbx.create(win_explicit).await.unwrap();
    assert_eq!(
        sb2.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.c7.xlarge")
    );
    sb2.delete().await.unwrap();
}

#[tokio::test]
async fn aliyun_net_delete_part_retries_dependency_violation_network_interface_past_48s_budget() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    let api = api.with_poll(std::time::Duration::from_millis(5));
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);
    let owner = "owner-eni-retry";
    let tags = aliyun_net::part_tags(owner);

    {
        let mut f = s.lock().unwrap();
        f.seed_vswitch(FakeVSwitch {
            vswitch_id: "vsw-eni-retry".into(),
            vswitch_name: aliyun_net::vswitch_name(owner, "ap-southeast-1a"),
            vpc_id: "vpc-eni-retry".into(),
            zone_id: "ap-southeast-1a".into(),
            cidr_block: "10.77.0.0/20".into(),
            region_id: "cn-hangzhou".into(),
            status: "Available".into(),
            tags: tags.clone(),
            ..Default::default()
        });
        f.transient_dependency_errors = 30;
        f.transient_dependency_code = Some("DependencyViolation.NetworkInterface".into());
    }

    let res = Resource {
        provider: "aliyun-ecs".into(),
        id: "vsw-eni-retry".into(),
        resource_type: "vswitch".into(),
        region: "cn-hangzhou".into(),
        tags,
        ..Default::default()
    };
    aliyun_net::delete_part(&api, &c, &res)
        .await
        .expect("DeleteVSwitch must retry DependencyViolation.NetworkInterface past 24 attempts");
    let del_count = s
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|call| call.action == "DeleteVSwitch")
        .count();
    assert_eq!(
        del_count, 31,
        "DeleteVSwitch should be attempted 31 times (30 DependencyViolation.NetworkInterface + 1 success)"
    );
}

#[tokio::test]
async fn windows_run_instances_enforces_netbios_hostname_15_char_limit_and_uniqueness() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);

    let win_spec = |name: &str| ProvisionSpec {
        name: name.into(),
        family: "windows".into(),
        image: "windows".into(),
        kind: "vm".into(),
        machine_type: "ecs.c7.xlarge".into(),
        machine_type_explicit: true,
        disk_gb: 60,
        user_data: "[powershell]\nWrite-Output ok\n".into(),
        tags: model::tags("owner-hn", "win-hn", "cloud-hn", 0),
        ttl_secs: 3600,
        arch: "amd64".into(),
        runtime: "native".into(),
        ..Default::default()
    };

    let assert_valid_netbios = |h: &str| {
        assert!(
            (2..=15).contains(&h.len()),
            "Windows RunInstances HostName must be 2..=15 chars, got {h:?} ({})",
            h.len()
        );
        assert!(
            h.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
            "Windows HostName must be [A-Za-z0-9-], got {h:?}"
        );
        assert!(!h.contains('.'), "Windows HostName must omit '.': {h:?}");
        assert!(
            !h.starts_with('-') && !h.ends_with('-'),
            "Windows HostName must not start/end with '-': {h:?}"
        );
        assert!(
            !h.chars().all(|ch| ch.is_ascii_digit()),
            "Windows HostName must not be all-digits: {h:?}"
        );
    };

    api.provision(&c, &win_spec("cua-aliyun-ecs-aaaaaaaaaaaa"))
        .await
        .unwrap();
    api.provision(&c, &win_spec("cua-aliyun-ecs-aaaaaaaaaaab"))
        .await
        .unwrap();
    api.provision(&c, &win_spec("win.box.01")).await.unwrap();
    api.provision(&c, &win_spec("123456789012345"))
        .await
        .unwrap();

    let win_hostnames: Vec<String> = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .filter(|call| call.action == "RunInstances" && !call.params.contains_key("DryRun"))
            .map(|call| call.params.get("HostName").cloned().unwrap_or_default())
            .collect()
    };
    assert_eq!(win_hostnames.len(), 4);
    for hn in &win_hostnames {
        assert_valid_netbios(hn);
    }
    assert_ne!(
        win_hostnames[0], win_hostnames[1],
        "distinct cua-aliyun-ecs-<12-hex> names must produce distinct NetBIOS HostNames"
    );
    assert_eq!(win_hostnames[2], "win-box-01");

    s.lock().unwrap().calls.clear();
    let lin_spec = ProvisionSpec {
        name: "cua-aliyun-ecs-aaaaaaaaaaaa".into(),
        family: "linux".into(),
        image: HERMETIC_LINUX_IMAGE.into(),
        kind: "container".into(),
        machine_type: "ecs.e-c1m2.large".into(),
        machine_type_explicit: true,
        disk_gb: 40,
        user_data: "#cloud-config\n".into(),
        tags: model::tags("owner-hn", "lin-hn", "cloud-hn-lin", 0),
        ttl_secs: 3600,
        arch: "amd64".into(),
        runtime: "docker".into(),
        ..Default::default()
    };
    api.provision(&c, &lin_spec).await.unwrap();
    let mut lin_dots = lin_spec.clone();
    lin_dots.name = "my.linux.host.01".into();
    api.provision(&c, &lin_dots).await.unwrap();
    let lin_hostnames: Vec<String> = {
        let f = s.lock().unwrap();
        f.calls
            .iter()
            .filter(|call| call.action == "RunInstances" && !call.params.contains_key("DryRun"))
            .map(|call| call.params.get("HostName").cloned().unwrap_or_default())
            .collect()
    };
    assert_eq!(
        lin_hostnames,
        vec![
            "cua-aliyun-ecs-aaaaaaaaaaaa".to_string(),
            "my.linux.host.01".to_string(),
        ]
    );
}

#[tokio::test]
async fn dynamic_instance_type_selection_queries_cores_memory_filters_with_stock_and_aligns_zone() {
    use cua_sandbox_core::placement::Runtime;
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.set_zones(
            "ap-southeast-1",
            vec!["ap-southeast-1a".into(), "ap-southeast-1b".into()],
        );
        f.add_instance_type("ecs.c8y.xlarge", 4, 8.0);
        f.add_instance_type("ecs.gn7i.xlarge", 4, 8.0);
        f.add_instance_type("ecs.ebmg7.xlarge", 4, 8.0);
        f.add_instance_type("ecs.t6-c1m2.xlarge", 4, 8.0);
        f.add_instance_type("ecs.c9i.xlarge", 4, 8.0);
        f.add_instance_type("ecs.u2a-c1m2.xlarge", 4, 8.0);
        f.add_instance_type("ecs.g8i.2xlarge", 8, 16.0);
        f.instance_type_details
            .insert("ecs.c8y.xlarge".into(), json!({ "CpuArchitecture": "ARM" }));
        f.instance_type_details.insert(
            "ecs.gn7i.xlarge".into(),
            json!({ "CpuArchitecture": "X86", "GpuAmount": 1 }),
        );
        f.instance_type_details.insert(
            "ecs.ebmg7.xlarge".into(),
            json!({ "CpuArchitecture": "X86" }),
        );
        f.instance_type_details.insert(
            "ecs.t6-c1m2.xlarge".into(),
            json!({ "CpuArchitecture": "X86" }),
        );
        f.instance_type_details
            .insert("ecs.c9i.xlarge".into(), json!({ "CpuArchitecture": "X86" }));
        f.instance_type_details.insert(
            "ecs.u2a-c1m2.xlarge".into(),
            json!({ "CpuArchitecture": "X86" }),
        );
        f.instance_type_details.insert(
            "ecs.g8i.2xlarge".into(),
            json!({ "CpuArchitecture": "X86" }),
        );

        f.available_zones_override = Some(vec![
            json!({
                "RegionId": "ap-southeast-1",
                "ZoneId": "ap-southeast-1a",
                "Status": "Available",
                "AvailableResources": {
                    "AvailableResource": [{
                        "Type": "InstanceType",
                        "SupportedResources": {
                            "SupportedResource": [
                                { "Value": "ecs.c7.xlarge", "Status": "Available", "StatusCategory": "ClosedWithStock" },
                                { "Value": "ecs.c9i.xlarge", "Status": "Available", "StatusCategory": "ClosedWithStock" },
                                { "Value": "ecs.c8y.xlarge", "Status": "Available", "StatusCategory": "WithStock" },
                                { "Value": "ecs.gn7i.xlarge", "Status": "Available", "StatusCategory": "WithStock" },
                                { "Value": "ecs.ebmg7.xlarge", "Status": "Available", "StatusCategory": "WithStock" },
                                { "Value": "ecs.t6-c1m2.xlarge", "Status": "Available", "StatusCategory": "WithStock" },
                                { "Value": "ecs.e-c1m2.large", "Status": "Available", "StatusCategory": "WithStock" }
                            ]
                        }
                    }]
                }
            }),
            json!({
                "RegionId": "ap-southeast-1",
                "ZoneId": "ap-southeast-1b",
                "Status": "Available",
                "AvailableResources": {
                    "AvailableResource": [{
                        "Type": "InstanceType",
                        "SupportedResources": {
                            "SupportedResource": [
                                { "Value": "ecs.c9i.xlarge", "Status": "Available", "StatusCategory": "WithStock" },
                                { "Value": "ecs.g8i.2xlarge", "Status": "Available", "StatusCategory": "WithStock" }
                            ]
                        }
                    }]
                }
            }),
        ]);

        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
    }

    let sbx = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("ap-southeast-1".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            max_size: Some("4x8x80".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    s.lock().unwrap().calls.clear();

    let mut win_opts = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_opts.contrib = Some("aliyun-ecs".into());
    win_opts.name = Some("win-dynamic-c9i".into());
    win_opts.os = "windows".into();
    win_opts.runtime = Runtime::Other("native".into());
    win_opts.ready_timeout = std::time::Duration::from_secs(10);
    let sb = sbx.create(win_opts).await.unwrap();

    assert_eq!(
        sb.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.c9i.xlarge")
    );
    {
        let f = s.lock().unwrap();
        let avail_calls: Vec<_> = f
            .calls
            .iter()
            .filter(|c| c.action == "DescribeAvailableResource")
            .collect();
        assert!(
            avail_calls.iter().any(|c| {
                c.params.get("Cores").map(String::as_str) == Some("4")
                    && c.params.get("Memory").map(String::as_str) == Some("8")
            }),
            "DescribeAvailableResource must pass Cores=4 & Memory=8: {avail_calls:?}"
        );
        assert!(
            f.calls.iter().any(|c| c.action == "DescribeInstanceTypes"),
            "DescribeInstanceTypes must be queried to inspect architecture/GPU/sizing"
        );
        let run = f
            .calls
            .iter()
            .rfind(|c| c.action == "RunInstances" && !c.params.contains_key("DryRun"))
            .unwrap();
        assert_eq!(
            run.params.get("InstanceType").map(String::as_str),
            Some("ecs.c9i.xlarge")
        );
        assert_eq!(
            run.params.get("ZoneId").map(String::as_str),
            Some("ap-southeast-1b"),
            "RunInstances must align with the WithStock zone of ecs.c9i.xlarge"
        );
        let run_vsw = run.params.get("VSwitchId").unwrap();
        let vsw = f.vswitches.get(run_vsw.as_str()).unwrap();
        assert_eq!(
            vsw.zone_id.as_str(),
            "ap-southeast-1b",
            "created VSwitch must be in the WithStock zone of the selected instance type"
        );
    }
    sb.delete().await.unwrap();

    {
        let mut f = s.lock().unwrap();
        f.available_zones_override = Some(vec![json!({
            "RegionId": "ap-southeast-1",
            "ZoneId": "ap-southeast-1a",
            "Status": "Available",
            "AvailableResources": {
                "AvailableResource": [{
                    "Type": "InstanceType",
                    "SupportedResources": {
                        "SupportedResource": [
                            { "Value": "ecs.c9i.xlarge", "Status": "Available", "StatusCategory": "WithoutStock" },
                            { "Value": "ecs.u2a-c1m2.xlarge", "Status": "Available", "StatusCategory": "WithStock" }
                        ]
                    }
                }]
            }
        })]);
    }
    let mut win_u2a = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_u2a.contrib = Some("aliyun-ecs".into());
    win_u2a.name = Some("win-dynamic-u2a".into());
    win_u2a.os = "windows".into();
    win_u2a.runtime = Runtime::Other("native".into());
    win_u2a.ready_timeout = std::time::Duration::from_secs(10);
    let sb2 = sbx.create(win_u2a).await.unwrap();
    assert_eq!(
        sb2.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.u2a-c1m2.xlarge")
    );
    sb2.delete().await.unwrap();

    let mut win_explicit = CreateOptions::new(ProviderKind::Contrib, "windows");
    win_explicit.contrib = Some("aliyun-ecs".into());
    win_explicit.name = Some("win-explicit-override".into());
    win_explicit.os = "windows".into();
    win_explicit.runtime = Runtime::Other("native".into());
    win_explicit.instance_type = Some("ecs.c7.xlarge".into());
    win_explicit.ready_timeout = std::time::Duration::from_secs(10);
    let sb3 = sbx.create(win_explicit).await.unwrap();
    assert_eq!(
        sb3.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.c7.xlarge")
    );
    sb3.delete().await.unwrap();
}

#[tokio::test]
async fn lookup_instance_type_sends_repeat_list_and_requires_exact_match() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);
    {
        let mut f = s.lock().unwrap();
        f.add_instance_type("ecs.t1.xsmall", 1, 0.5);
        f.add_instance_type("ecs.u2a-c1m2.xlarge", 4, 8.0);
    }

    let (cpus, mem_mb, _) = api
        .lookup_instance_type(&c, "ecs.u2a-c1m2.xlarge")
        .await
        .unwrap();
    assert_eq!((cpus, mem_mb), (4, 8192));
    {
        let f = s.lock().unwrap();
        let call = f
            .calls
            .iter()
            .rfind(|call| call.action == "DescribeInstanceTypes")
            .unwrap();
        assert_eq!(
            call.params.get("InstanceTypes.1").map(String::as_str),
            Some("ecs.u2a-c1m2.xlarge")
        );
        assert!(
            !call.params.contains_key("InstanceTypes"),
            "must use RepeatList InstanceTypes.1 instead of JSON InstanceTypes: {:?}",
            call.params
        );
    }

    s.lock().unwrap().ignore_instance_types_filter = true;
    let err = api
        .lookup_instance_type(&c, "ecs.missing-page2.xlarge")
        .await
        .unwrap_err();
    assert!(
        matches!(err, cua_sandbox_core::Error::InvalidArgument(_)),
        "expected InvalidArgument for missing instance type, got {err:?}"
    );
}

#[tokio::test]
async fn dynamic_instance_selection_chunks_repeat_list_by_10_paginates_next_token_and_excludes_gpu_amount()
 {
    use cua_sandbox_core::placement::Runtime;
    use cua_spacesd_client::testing::{MockAuth, MockServer};

    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-tok", "u1", Some("ada@example.com"));
    let access = RelayAccess::new(
        relay.url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        let mut f = s.lock().unwrap();
        f.set_zones("ap-southeast-1", vec!["ap-southeast-1a".into()]);
        let mut supported = Vec::new();
        for idx in 1..=10 {
            let id = format!("ecs.d10-{idx:02}.xlarge");
            f.add_instance_type(&id, 2, 4.0);
            f.instance_type_details
                .insert(id.clone(), json!({ "CpuArchitecture": "X86" }));
            supported.push(json!({
                "Value": id,
                "Status": "Available",
                "StatusCategory": "WithStock"
            }));
        }
        // Include GPU (uppercase GPUAmount), unexcluded-prefix GPU, ARM c6r, and target u2a.
        for (id, details) in [
            (
                "ecs.ga1.xlarge",
                json!({ "CpuArchitecture": "X86", "GPUAmount": 1 }),
            ),
            (
                "ecs.custom-gpu.xlarge",
                json!({ "CpuArchitecture": "X86", "GPUAmount": 1 }),
            ),
            ("ecs.c6r.xlarge", json!({ "CpuArchitecture": "ARM" })),
            (
                "ecs.u2a-c1m2.xlarge",
                json!({ "CpuArchitecture": "X86", "GPUAmount": 0 }),
            ),
        ] {
            f.add_instance_type(id, 4, 8.0);
            f.instance_type_details.insert(id.into(), details);
            supported.push(json!({
                "Value": id,
                "Status": "Available",
                "StatusCategory": "WithStock"
            }));
        }
        f.available_zones_override = Some(vec![json!({
            "RegionId": "ap-southeast-1",
            "ZoneId": "ap-southeast-1a",
            "Status": "Available",
            "AvailableResources": {
                "AvailableResource": [{
                    "Type": "InstanceType",
                    "SupportedResources": {
                        "SupportedResource": supported
                    }
                }]
            }
        })]);
        f.on_run_instance = Some(Arc::new(move |_id, params| {
            for i in 1..=10 {
                if params.get(&format!("Tag.{i}.Key")).map(String::as_str)
                    == Some(model::tag::MACHINE)
                    && let Some(mid) = params.get(&format!("Tag.{i}.Value"))
                {
                    relay.tunnel(mid, &mock_url);
                    relay.set_online(mid, true, "0.16.5");
                    break;
                }
            }
        }));
    }

    let sbx = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![Arc::new(api)],
        access,
    )
    .build();

    sbx.clouds()
        .unwrap()
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aliyun-ecs".into(),
                region: Some("ap-southeast-1".into()),
                token: Some("LTAI_TEST_AK:secret123".into()),
                ..Default::default()
            },
            max_size: Some("4x8x80".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    s.lock().unwrap().calls.clear();

    let mut opts1 = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts1.contrib = Some("aliyun-ecs".into());
    opts1.name = Some("win-chunk10-gpu".into());
    opts1.os = "windows".into();
    opts1.runtime = Runtime::Other("native".into());
    opts1.ready_timeout = std::time::Duration::from_secs(10);
    let sb1 = sbx.create(opts1).await.unwrap();
    assert_eq!(
        sb1.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.u2a-c1m2.xlarge")
    );
    {
        let f = s.lock().unwrap();
        let dt_calls: Vec<_> = f
            .calls
            .iter()
            .filter(|c| c.action == "DescribeInstanceTypes")
            .collect();
        assert_eq!(dt_calls.len(), 2, "14 candidates must split into 10 + 4");
        assert!(dt_calls[0].params.contains_key("InstanceTypes.10"));
        assert!(!dt_calls[0].params.contains_key("InstanceTypes.11"));
        assert!(dt_calls[1].params.contains_key("InstanceTypes.4"));
        assert!(!dt_calls[1].params.contains_key("InstanceTypes.5"));
    }
    sb1.delete().await.unwrap();

    {
        let mut f = s.lock().unwrap();
        f.instance_types_page_size = Some(6);
        let mut supported = Vec::new();
        for idx in 1..=21 {
            let id = format!("ecs.a-small-{idx:02}.large");
            f.add_instance_type(&id, 2, 4.0);
            f.instance_type_details
                .insert(id.clone(), json!({ "CpuArchitecture": "X86" }));
            supported.push(json!({
                "Value": id,
                "Status": "Available",
                "StatusCategory": "WithStock"
            }));
        }
        f.add_instance_type("ecs.c9a.xlarge", 4, 8.0);
        f.instance_type_details.insert(
            "ecs.c9a.xlarge".into(),
            json!({ "CpuArchitecture": "X86", "GPUAmount": 0 }),
        );
        for extra in [
            "ecs.ga1.xlarge",
            "ecs.custom-gpu.xlarge",
            "ecs.c6r.xlarge",
            "ecs.c9a.xlarge",
        ] {
            supported.push(json!({
                "Value": extra,
                "Status": "Available",
                "StatusCategory": "WithStock"
            }));
        }
        f.available_zones_override = Some(vec![json!({
            "RegionId": "ap-southeast-1",
            "ZoneId": "ap-southeast-1a",
            "Status": "Available",
            "AvailableResources": {
                "AvailableResource": [{
                    "Type": "InstanceType",
                    "SupportedResources": {
                        "SupportedResource": supported
                    }
                }]
            }
        })]);
        f.calls.clear();
    }

    let mut opts2 = CreateOptions::new(ProviderKind::Contrib, "windows");
    opts2.contrib = Some("aliyun-ecs".into());
    opts2.name = Some("win-next-token".into());
    opts2.os = "windows".into();
    opts2.runtime = Runtime::Other("native".into());
    opts2.ready_timeout = std::time::Duration::from_secs(10);
    let sb2 = sbx.create(opts2).await.unwrap();
    assert_eq!(
        sb2.provider_details()
            .get("machine_type")
            .map(String::as_str),
        Some("ecs.c9a.xlarge")
    );
    {
        let f = s.lock().unwrap();
        let dt_calls: Vec<_> = f
            .calls
            .iter()
            .filter(|c| c.action == "DescribeInstanceTypes")
            .collect();
        assert!(
            dt_calls.len() >= 2 && dt_calls.iter().any(|c| c.params.contains_key("NextToken")),
            "expected paginated DescribeInstanceTypes calls with NextToken: {dt_calls:?}"
        );
        assert!(
            dt_calls
                .iter()
                .all(|c| !c.params.contains_key("InstanceTypes.1")),
            "> 20 candidates must query unfiltered paginated DescribeInstanceTypes"
        );
    }
    sb2.delete().await.unwrap();
}
