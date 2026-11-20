// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Hermetic end-to-end tests for `aliyun-ecs` against an in-process `axum`
//! fake Alibaba Cloud OpenAPI V3 server verifying `ACS3-HMAC-SHA256` signatures.
#![cfg(feature = "aliyun-ecs")]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use cua_byoc::RelayAccess;
use cua_byoc::aliyun_ecs::{AliyunEcs, TokenStore};
use cua_byoc::api::{CloudApi, Target};
use cua_byoc::model::{self, Connection};
use cua_sandbox_core::Sandboxes;
use cua_sandbox_core::byoc::ConnectRequest;
use serde_json::json;

#[path = "support/fake_aliyun.rs"]
mod fake_aliyun;
use fake_aliyun::{S, handle};

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
    let api = AliyunEcs::with_endpoints(&base, &base, &base, store.clone(), aliyun_config);
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
