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
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{ConnectRequest, DETAIL_RELAY_MACHINE};
use cua_sandbox_core::placement::Runtime;
use cua_sandbox_core::{CreateOptions, ProviderKind, Sandboxes, Status};
use serde_json::json;

#[path = "support/fake_aliyun.rs"]
mod fake_aliyun;
use fake_aliyun::{FakeAliyun, S, handle};

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

    // 1. Missing credentials
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

    // 2. Malformed --token-stdin
    api.stage_secret(&target(Some("not-a-pair")));
    let t = api.test(&conn(&api)).await;
    assert!(!t.ok());
    assert!(t.checks[0].detail.contains("missing ':'"), "{:?}", t.checks);
    assert!(api.persist_secret().is_err());

    // 3. Invalid AccessKey ID / secret never leaked
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

    // 4. Target Debug redacts token
    let dbg = format!("{:?}", target(Some("LTAI_TEST_AK:topsecret-do-not-leak")));
    assert!(!dbg.contains("topsecret-do-not-leak"), "{dbg}");
    assert!(dbg.contains("redacted"), "{dbg}");

    // 5. Missing RAM permission on ecs:RunInstances DryRun=true
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

    // 6. Missing RAM permission on vpc:DescribeVpcs
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

    // 7. VPC-only region returning InvalidVSwitchId.NotFound after RAM auth still passes permissions
    s.lock().unwrap().run_instances_missing_vswitch = true;
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
    s.lock().unwrap().run_instances_missing_vswitch = false;

    // 8. Unknown region rejected; bad region syntax rejected at resolve()
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

    // 9. 429 Throttling is retried and succeeds
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

    // 5. Fallback to active `current` profile ("oauth"), inheriting its region_id ("cn-shanghai").
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

        // Explicit --region wins over profile region_id.
        let t_reg = Target {
            region: Some("cn-beijing".into()),
            ..target(None)
        };
        assert_eq!(api.resolve(&t_reg).unwrap().region, "cn-beijing");

        // 4. Saved credentials in TokenStore beat active `current` profile.
        store.save("LTAI_SAVED_AK:saved_secret_789").unwrap();
        let c_saved = api.resolve(&t_none).unwrap();
        assert_eq!(c_saved.region, "cn-hangzhou");
        assert_eq!(c_saved.profile, "");
        let res = api.test(&c_saved).await;
        assert!(res.ok(), "{:?}", res.checks);
        assert_eq!(last_ak(), "LTAI_SAVED_AK");

        // 3. Explicit --profile beats saved TokenStore and `current` profile.
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

        // Missing --profile returns crisp error.
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

        // Non-AK mode profile returns crisp error.
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

    // 2. Env vars beat explicit --profile and saved TokenStore.
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

        // 1. --token-stdin beats env vars, --profile, and TokenStore.
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

    // Partial env var fails loudly rather than falling back to TokenStore/profile.
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

    // 1. Failed connect must NOT persist credentials or connection state.
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

    // 2. Passing connect persists AK/SK into TokenStore (never plaintext in state/audit/status),
    //    records region, budget, max_size, and ttl_hours (default 8 when None).
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

    // Verify zero plaintext secret leakage across disk state, audit, and status JSON.
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

    // 3. disconnect refuses when an owned instance still exists, ignoring untagged/foreign ones.
    let owner = cua_byoc::Store::new(home.path()).owner_id().unwrap();
    let owner_tag = model::label_value(&owner);
    {
        let mut f = s.lock().unwrap();
        // Foreign instance (must be ignored by list_owned and not block disconnect by itself).
        f.instances.insert(
            "i-foreign-1".into(),
            json!({
                "InstanceId": "i-foreign-1",
                "InstanceName": "foreign",
                "RegionId": "cn-shanghai",
                "Status": "Running",
                "Tags": { "Tag": [
                    { "TagKey": "cua-managed", "TagValue": "true" },
                    { "TagKey": "cua-owner", "TagValue": "someone-else" }
                ]}
            }),
        );
        // Owned instance (must block disconnect without --delete).
        f.instances.insert(
            "i-owned-1".into(),
            json!({
                "InstanceId": "i-owned-1",
                "InstanceName": "cua-sb-1",
                "RegionId": "cn-shanghai",
                "Status": "Running",
                "Tags": { "Tag": [
                    { "TagKey": "cua-managed", "TagValue": "true" },
                    { "TagKey": "cua-owner", "TagValue": owner_tag }
                ]}
            }),
        );
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

    // describe() returns live state + tags for owned instance, None for missing.
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

    // Remove owned instance; foreign instance remains; disconnect now succeeds cleanly.
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

    // Connecting via ~/.aliyun/config.json profile does NOT duplicate secrets into TokenStore.
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

    // Passing --oidc or --sealed to aliyun-ecs fails cleanly without connecting.
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

    // Connect with BOTH --token-stdin AND --profile webhook_manager.
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

    // Subsequent disconnect (calls list_owned) must authenticate with LTAI_STDIN_AK from TokenStore,
    // NEVER switching to webhook_manager (LTAI_WH_AK).
    s.lock().unwrap().calls.clear();
    let disc = clouds.disconnect("aliyun-ecs", false).await.unwrap();
    assert!(disc.disconnected);
    let calls = s.lock().unwrap().calls.clone();
    assert!(!calls.is_empty());
    assert!(
        calls.iter().all(|c| c.access_key_id == "LTAI_STDIN_AK"),
        "post-connect calls must use saved TokenStore AK, got: {calls:?}"
    );

    // Same check when connecting via env vars + --profile webhook_manager.
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
    // Env vars dropped now; disconnect must still use saved LTAI_ENV_AK from TokenStore.
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

    // 1. In a clean environment (no env/saved/profile), test(--token-stdin) and failed connect(--token-stdin)
    //    must unstage the secret so subsequent status() reports credentials.found == false.
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

    // Failed connect via invalid region (early `?` in resolve) must also unstage.
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

    // Failed connect via failed API check must also unstage.
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

    // 2. connect -> test(wrong --token-stdin) -> disconnect(false) must succeed without SignatureDoesNotMatch.
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

    // 1. 200 OK malformed JSON on GetCallerIdentity, list_owned, and describe must return Err (and fail test).
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

    // 2. 200 OK truncated HTTP body (Content-Length mismatch / early EOF) must fail GetCallerIdentity, list_owned, describe.
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

    // 3. 200 OK JSON with empty AccountId must fail credentials check.
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

    // 4. 502 HTML error body must preserve a snippet (never "null").
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

    // 1. DescribeVSwitches returning Forbidden.RAM must fail permissions (never swallowed).
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

    // 2. When VSwitchId (with VpcId) and matching-VPC SecurityGroupId exist, both are attached to RunInstances DryRun=true.
    {
        let mut f = s.lock().unwrap();
        f.vswitches.push(json!({
            "VSwitchId": "vsw-match-1",
            "VpcId": "vpc-match-1",
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-other-vpc",
            "VpcId": "vpc-other",
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-match-1",
            "VpcId": "vpc-match-1",
        }));
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

    // 3. When VSwitchId IS supplied, InvalidVSwitchId.NotFound must FAIL permissions.
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

    // 4. MissingParameter must FAIL permissions both WITH VSwitchId and WITHOUT VSwitchId.
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

    // 5. Fallback cleanly when VSwitchId exists but no SecurityGroup exists in that VPC.
    {
        let mut f = s.lock().unwrap();
        f.vswitches.push(json!({
            "VSwitchId": "vsw-only-1",
            "VpcId": "vpc-no-sg",
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-wrong-vpc",
            "VpcId": "vpc-other",
        }));
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
async fn test_permissions_dry_runs_vpc_and_sg_with_cua_managed_tag() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, _) = start(None).await;
    api.stage_secret(&target(Some("LTAI_TEST_AK:secret123")));

    // 1. Passing test sends Tag.1.Key=cua-managed on RunInstances, CreateVpc, CreateSecurityGroup DryRun=true.
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
    {
        let f = s.lock().unwrap();
        assert!(f.vpcs.is_empty() && f.security_groups.is_empty() && f.instances.is_empty());
        for action in ["RunInstances", "CreateVpc", "CreateSecurityGroup"] {
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

    // 2. Forbidden.RAM on vpc:CreateVpc or ecs:CreateSecurityGroup fails permissions (never swallowed).
    for perm_action in ["vpc:CreateVpc", "ecs:CreateSecurityGroup"] {
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

    // 3. Account with zero VPCs returning InvalidVpcId.NotFound on CreateSecurityGroup DryRun=true passes.
    s.lock().unwrap().create_sg_missing_vpc = true;
    let t = api.test(&conn(&api)).await;
    assert!(t.ok(), "{:?}", t.checks);
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
    // Seed pre-existing account network resources that Cua MUST NOT touch.
    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-acct-default",
            "VpcName": "default-vpc",
            "CidrBlock": "172.16.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": [] }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-acct-existing",
            "VSwitchName": "prod-vsw",
            "VpcId": "vpc-acct-default",
            "ZoneId": "cn-hangzhou-h",
            "CidrBlock": "172.16.0.0/24",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "Tags": { "Tag": [] }
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-acct-existing",
            "SecurityGroupName": "prod-sg",
            "VpcId": "vpc-acct-default",
            "RegionId": "cn-hangzhou",
            "SecurityGroupType": "normal",
            "InnerAccessPolicy": "Accept",
            "Tags": { "Tag": [] }
        }));
        // Simulate real guest boot: decode UserData #cloud-config and bring machine online on FakeRelay.
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

    // Clear test/connect calls so we inspect provisioning calls cleanly.
    s.lock().unwrap().calls.clear();

    // 1. Create Linux Docker-on-VM sandbox with explicit `--runtime docker`.
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

    // Inspect created cloud calls & resources.
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
        // Never add any ingress rules!
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

        // Verify UserData (#cloud-config) blocks 100.100.100.200, installs docker, joins relay, schedules TTL.
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

        // Verify all 6 tags on Instance, VPC, VSwitch, SG.
        let inst = f.instances.values().next().unwrap();
        let inst_tags = aliyun_net::tags_of(inst);
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
            .iter()
            .find(|v| v["VpcId"] != "vpc-acct-default")
            .unwrap();
        let vpc_tags = aliyun_net::tags_of(cua_vpc);
        assert_eq!(vpc_tags.len(), 6, "{vpc_tags:?}");
        assert_eq!(vpc_tags["cua-machine"], "");
        assert_eq!(vpc_tags["cua-space"], "");

        let cua_vsw = f
            .vswitches
            .iter()
            .find(|v| v["VSwitchId"] != "vsw-acct-existing")
            .unwrap();
        assert_eq!(cua_vsw["CidrBlock"], "10.77.0.0/20");
        let vsw_tags = aliyun_net::tags_of(cua_vsw);
        assert_eq!(vsw_tags.len(), 6, "{vsw_tags:?}");
        assert_eq!(vsw_tags["cua-machine"], "");

        let cua_sg = f
            .security_groups
            .iter()
            .find(|g| g["SecurityGroupId"] != "sg-acct-existing")
            .unwrap();
        let sg_tags = aliyun_net::tags_of(cua_sg);
        assert_eq!(sg_tags.len(), 6, "{sg_tags:?}");
        assert_eq!(sg_tags["cua-machine"], "");
    }

    // 2. Second sandbox reuses existing VPC, VSwitch, and SG without creating new ones.
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

    // 3. Suspend (stop) preserves system disk & transitions to Stopped, resume (start) brings back Running.
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

    // 4. Delete both sandboxes; pre-existing account network remains untouched.
    sandboxes.delete("sb-one").await.unwrap();
    sandboxes.delete("sb-two").await.unwrap();
    assert!(relay.machine(&machine1).is_none());
    {
        let f = s.lock().unwrap();
        assert!(f.instances.is_empty());
        assert!(f.vpcs.iter().any(|v| v["VpcId"] == "vpc-acct-default"));
        assert!(
            f.vswitches
                .iter()
                .any(|v| v["VSwitchId"] == "vsw-acct-existing")
        );
        assert!(
            f.security_groups
                .iter()
                .any(|g| g["SecurityGroupId"] == "sg-acct-existing")
        );
    }
}

#[tokio::test]
async fn preflight_budget_max_size_and_unsupported_modes_refuse_before_cloud_calls() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    // 1. --max-size 1x2 rejects default 2c/4g BEFORE any cloud provisioning call.
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

    // 2. --budget 0.01 rejects 0.043/h machine BEFORE any cloud provisioning call.
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

    // 3. --runtime native is refused cleanly until M4 (#5).
    let mut native_opts = sb_create_opts("native-unsupported");
    native_opts.runtime = Runtime::Other("native".into());
    let err_native = sb_budget.create(native_opts).await.unwrap_err();
    assert!(
        err_native.to_string().contains("docker") || err_native.to_string().contains("native"),
        "{err_native}"
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

    // Case A: Zone cn-hangzhou-h fails RunInstances with OperationDenied.NoStock;
    // provision cleans up -h's unused VSwitch and retries in cn-hangzhou-i -> succeeds.
    {
        let mut f = s.lock().unwrap();
        f.zones = vec!["cn-hangzhou-h".into(), "cn-hangzhou-i".into()];
        f.run_fail_zones
            .insert("cn-hangzhou-h".into(), "OperationDenied.NoStock".into());
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
        assert_eq!(f.vswitches[0]["ZoneId"], "cn-hangzhou-i");
    }

    // Case B: Fresh provision where ALL zones fail with Zone.NotOnSale -> newly created SG & VPC rolled back.
    let (api2, s2, store2) = start(None).await;
    store2.save("LTAI_TEST_AK:secret123").unwrap();
    {
        let mut f = s2.lock().unwrap();
        f.zones = vec!["cn-hangzhou-h".into(), "cn-hangzhou-i".into()];
        f.sold_out_zones
            .insert("cn-hangzhou-h".into(), "Zone.NotOnSale".into());
        f.sold_out_zones
            .insert("cn-hangzhou-i".into(), "OperationDenied.NoStock".into());
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
                inst["Status"] = json!("Stopped");
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

    // Saved boot log file is redacted and 0600, instance & relay machine rolled back, shared VPC kept.
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

    // Pre-seed default VPC (even with forged cua-managed tag!), untagged, and other-owner resources.
    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-default",
            "VpcName": "default",
            "CidrBlock": "172.16.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": [
                { "Key": "cua-managed", "Value": "true" },
                { "Key": "cua-owner", "Value": owner_tag }
            ]}
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-default",
            "VSwitchName": "default-vsw",
            "VpcId": "vpc-default",
            "ZoneId": "cn-hangzhou-h",
            "CidrBlock": "172.16.0.0/24",
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": [
                { "Key": "cua-managed", "Value": "true" },
                { "Key": "cua-owner", "Value": owner_tag }
            ]}
        }));
        f.vpcs.push(json!({
            "VpcId": "vpc-untagged",
            "CidrBlock": "192.168.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": [] }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-untagged",
            "VpcId": "vpc-untagged",
            "ZoneId": "cn-hangzhou-h",
            "CidrBlock": "192.168.0.0/24",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "Tags": { "Tag": [] }
        }));
        f.security_groups.push(json!({
            "SecurityGroupId": "sg-untagged",
            "VpcId": "vpc-untagged",
            "RegionId": "cn-hangzhou",
            "Tags": { "Tag": [] }
        }));
        f.instances.insert(
            "i-untagged".into(),
            json!({
                "InstanceId": "i-untagged",
                "RegionId": "cn-hangzhou",
                "Status": "Running",
                "Tags": { "Tag": [] }
            }),
        );
        f.instances.insert(
            "i-foreign".into(),
            json!({
                "InstanceId": "i-foreign",
                "RegionId": "cn-hangzhou",
                "Status": "Running",
                "Tags": { "Tag": [
                    { "TagKey": "cua-managed", "TagValue": "true" },
                    { "TagKey": "cua-owner", "TagValue": "someone-else" }
                ]}
            }),
        );
    }

    // Tag-guard refusal: list_owned excludes and stop/start/delete refuse on untagged,
    // foreign, and default VPC/VSwitch (even with forged tags) with 0 mutating calls.
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

    // Create a live sandbox and also seed an expired owned instance.
    let _sb = sandboxes.create(sb_create_opts("sb-live")).await.unwrap();
    let expired_at = model::now().saturating_sub(60);
    s.lock().unwrap().instances.insert(
        "i-expired".into(),
        json!({
            "InstanceId": "i-expired",
            "InstanceName": "cua-aliyun-ecs-exp",
            "RegionId": "cn-hangzhou",
            "Status": "Running",
            "Tags": { "Tag": [
                { "TagKey": "cua-managed", "TagValue": "true" },
                { "TagKey": "cua-owner", "TagValue": owner_tag },
                { "TagKey": "cua-expires", "TagValue": expired_at.to_string() },
                { "TagKey": "cua-machine", "TagValue": "cloud-expired-1" }
            ]}
        }),
    );

    // disconnect without --delete refuses while managed instances exist.
    let refused = clouds.disconnect("aliyun-ecs", false).await.unwrap_err();
    assert!(
        refused.to_string().contains("NOT disconnected"),
        "{refused}"
    );

    // Regular sweep removes ONLY expired owned instance, keeping live sandbox & shared VPC/VSwitch/SG.
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
    assert_eq!(s.lock().unwrap().instances.len(), 3); // i-untagged, i-foreign, sb-live

    // disconnect --delete sweeps in dependency order (instance -> security_group -> vswitch -> vpc)
    // and succeeds even with transient DependencyViolation retries!
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

    // Only untagged, foreign, and default resources remain!
    assert_eq!(f.instances.len(), 2);
    assert!(f.instances.contains_key("i-untagged"));
    assert!(f.instances.contains_key("i-foreign"));
    assert_eq!(f.vpcs.len(), 2);
    assert!(f.vpcs.iter().any(|v| v["VpcId"] == "vpc-default"));
    assert!(f.vpcs.iter().any(|v| v["VpcId"] == "vpc-untagged"));
    assert_eq!(f.vswitches.len(), 2);
    assert!(f.vswitches.iter().any(|v| v["VSwitchId"] == "vsw-default"));
    assert!(f.vswitches.iter().any(|v| v["VSwitchId"] == "vsw-untagged"));
    assert_eq!(f.security_groups.len(), 1);
}

#[tokio::test]
async fn default_vswitch_with_spoofed_cua_tags_is_never_reused() {
    let _env_lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::set(None, None);

    let (api, s, store) = start(None).await;
    store.save("LTAI_TEST_AK:secret123").unwrap();
    let c = conn(&api);

    let vpc_tags: Vec<_> = aliyun_net::part_tags("owner1")
        .into_iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();
    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-owned-1",
            "VpcName": aliyun_net::vpc_name("owner1"),
            "CidrBlock": "10.77.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": vpc_tags }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-default-spoofed",
            "VSwitchName": "default-vsw",
            "VpcId": "vpc-owned-1",
            "ZoneId": "cn-hangzhou-h",
            "CidrBlock": "10.77.0.0/20",
            "RegionId": "cn-hangzhou",
            "IsDefault": true,
            "Status": "Available",
            "Tags": { "Tag": vpc_tags }
        }));
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

    // 1. Lowest-ID tie-breaker: when multiple Cua SGs exist, prepare_network picks the lowest ID.
    let (api1, s1, store1) = start(None).await;
    store1.save("LTAI_TEST_AK:secret123").unwrap();
    let c1 = conn(&api1);
    let vpc_tags: Vec<_> = aliyun_net::part_tags("owner1")
        .into_iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();
    let sg_tags: Vec<_> = aliyun_net::part_tags("owner1")
        .into_iter()
        .map(|(k, v)| json!({ "TagKey": k, "TagValue": v }))
        .collect();
    {
        let mut f = s1.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-owned-1",
            "VpcName": aliyun_net::vpc_name("owner1"),
            "CidrBlock": "10.77.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": vpc_tags.clone() }
        }));
        for sg_id in ["sg-zeta", "sg-alpha"] {
            f.security_groups.push(json!({
                "SecurityGroupId": sg_id,
                "SecurityGroupName": aliyun_net::sg_name("owner1"),
                "VpcId": "vpc-owned-1",
                "RegionId": "cn-hangzhou",
                "SecurityGroupType": "enterprise",
                "InnerAccessPolicy": "Drop",
                "Tags": { "Tag": sg_tags.clone() }
            }));
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

    // 2. Concurrent race across separate NetLocks: both create SGs behind a barrier,
    //    both converge on the lowest ID, and the race loser is deleted.
    let s2: S = Arc::new(Mutex::new(FakeAliyun::default()));
    {
        let mut f = s2.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-owned-race",
            "VpcName": aliyun_net::vpc_name("owner1"),
            "CidrBlock": "10.77.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": vpc_tags }
        }));
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

    // Pre-create an owned VPC that already has a non-Cua VSwitch occupying 10.77.0.0/20 in another zone.
    let vpc_tags: Vec<_> = aliyun_net::part_tags("owner1")
        .into_iter()
        .map(|(k, v)| json!({ "Key": k, "Value": v }))
        .collect();
    {
        let mut f = s.lock().unwrap();
        f.vpcs.push(json!({
            "VpcId": "vpc-pre-1",
            "VpcName": aliyun_net::vpc_name("owner1"),
            "CidrBlock": "10.77.0.0/16",
            "RegionId": "cn-hangzhou",
            "IsDefault": false,
            "Status": "Available",
            "Tags": { "Tag": vpc_tags }
        }));
        f.vswitches.push(json!({
            "VSwitchId": "vsw-other-zone",
            "VSwitchName": "other",
            "VpcId": "vpc-pre-1",
            "ZoneId": "cn-hangzhou-z",
            "CidrBlock": "10.77.0.0/20",
            "RegionId": "cn-hangzhou",
            "Status": "Available",
            "Tags": { "Tag": [] }
        }));
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
        .iter()
        .find(|v| v["VSwitchId"] != "vsw-other-zone")
        .unwrap();
    assert_eq!(
        new_vsw["CidrBlock"], "10.77.16.0/20",
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

    // 1. Connect with --max-size 2x4 -> Windows (4 vCPU / 8 GiB) must be refused before any cloud call.
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

    // 2. Reconnect with --max-size 4x16 (and omit spacesd_download_url -> preserved!).
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

    // 3. Explicit --runtime docker on Windows is refused cleanly.
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

    // 4. Hook FakeAliyun RunInstances to simulate guest joining FakeRelay.
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

    // 5. Create Windows Direct VM Sandbox.
    let mut o = CreateOptions::new(ProviderKind::Contrib, "windows");
    o.contrib = Some("aliyun-ecs".into());
    o.name = Some("win-acct-1".into());
    o.os = "windows".into();
    let sb = sandboxes.create(o).await.unwrap();
    assert_eq!(sb.placement(), (Kind::Vm, Runtime::Other("native".into())));

    // Inspect RunInstances call parameters & decoded #ps1_sysnative UserData.
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
        Some("required")
    );
    assert!(run_call.params.contains_key("AutoReleaseTime"));
    let img_id = run_call.params.get("ImageId").unwrap();
    assert!(img_id.starts_with("win2022_"), "{img_id}");
    let ecs_pw = run_call.params.get("Password").unwrap();
    assert!(ecs_pw.len() >= 16);

    // All 6 Cua tags attached at creation time.
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
    assert!(user_data.starts_with("#ps1_sysnative\n"));
    assert!(user_data.len() < 16 * 1024);
    assert!(!user_data.contains(ecs_pw));
    assert!(user_data.contains("*S-1-5-18:(OI)(CI)F"));
    assert!(user_data.contains("*S-1-5-32-544:(OI)(CI)F"));
    assert!(user_data.contains("https://mirror.example.com/cua-spacesd.exe"));
    assert!(user_data.contains(&mirror_sha));
    assert!(user_data.contains("100.100.100.200"));
    assert!(user_data.contains("AutoAdminLogon"));
    assert!(user_data.contains("-AtLogOn"));
    assert!(user_data.contains("EventID=24"));
    let tscon = decode_ps_put(&user_data, "tscon-recover.ps1").unwrap();
    assert!(tscon.contains("tscon.exe") && tscon.contains("/dest:console"));
    let launcher = decode_ps_put(&user_data, "launch-spacesd.ps1").unwrap();
    assert!(launcher.contains("--relay-jwks"));
    assert!(decode_ps_put(&user_data, "jwks.json").is_some());

    // Connect spacesd over FakeRelay.
    let client = sb.spacesd().await.unwrap();
    client.health().await.unwrap();

    // Stop / Start / Tag-guarded Delete.
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

    // Wrong owner cannot delete the instance.
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

    // 1. Successful Static Relay Mode Windows Direct VM create.
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

    // 2. Failed boot: instance stops/dies before joining -> boot log fetched, secrets redacted, rolled back.
    {
        let mut f = s.lock().unwrap();
        f.on_run_instance = Some(Arc::new(|_id, _| {}));
    }
    let s_clone = s.clone();
    let (fail_tx, mut fail_rx) = tokio::sync::oneshot::channel::<()>();
    let fail_tx = Arc::new(Mutex::new(Some(fail_tx)));
    {
        let mut f = s.lock().unwrap();
        let s_inner = s_clone.clone();
        let fail_tx = fail_tx.clone();
        f.on_run_instance = Some(Arc::new(move |id, params| {
            let id_owned = id.to_string();
            let pw = params.get("Password").cloned().unwrap_or_default();
            let s2 = s_inner.clone();
            let tx = fail_tx.clone();
            tokio::spawn(async move {
                let mut f = s2.lock().unwrap();
                f.console_outputs.insert(
                    id_owned.clone(),
                    format!(
                        "cloudbase-init starting\nCUA_RELAY_TOKEN={static_tok}\nWinlogonPassword={pw}\nfatal: mirror download 404\n"
                    ),
                );
                if let Some(inst) = f.instances.get_mut(&id_owned) {
                    inst["Status"] = json!("Stopped");
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
    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let (api, s, _store) = start(None).await;
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
}
