// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Hermetic end-to-end tests for per-connection self-hosted relay URLs and
//! Static Relay Mode across validation, credential storage, bootstrap,
//! lifecycle, failure rollback, secret redaction, mode switching, and
//! coexistence with Account Relay Mode.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use cua_byoc::model::{self, Tier};
use cua_byoc::testing::FakeProvider;
use cua_byoc::{RelayAccess, Target};
use cua_host::relay::AccountTokens;
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{ConnectRequest, DETAIL_RELAY_MACHINE, RelayMode};
use cua_sandbox_core::{CreateOptions, Error, ProviderKind, Sandboxes};
use cua_spacesd_client::testing::{MockAuth, MockServer};

struct FailingTokens;

#[async_trait::async_trait]
impl AccountTokens for FailingTokens {
    async fn access_token(&self) -> cua_host::Result<String> {
        Err(cua_host::Error::Unauthenticated(
            "not signed in to cua.ai".into(),
        ))
    }
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

fn store_secret(home: &std::path::Path, key: &str) -> Option<String> {
    let store = cua_auth::Store::File(home.join("credentials.json"));
    store
        .load_secret(key)
        .unwrap()
        .map(|b| String::from_utf8(b).unwrap())
}

fn create_opts(provider: &str, name: &str) -> CreateOptions {
    let mut o = CreateOptions::new(ProviderKind::Contrib, "registry.invalid/trycua/linux:24.04");
    o.contrib = Some(provider.into());
    o.name = Some(name.into());
    o
}

#[tokio::test]
async fn validation_rejects_invalid_relay_combinations_without_persisting_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let fake = FakeProvider::new("aws", Tier::Vm);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake],
        RelayAccess::new(relay.url.clone(), Arc::new(FailingTokens)),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-tok".into()),
                ..Default::default()
            },
            auth: Some("oidc".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    let err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-tok".into()),
                ..Default::default()
            },
            auth: Some("sealed".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    for mode in [None, Some(RelayMode::Account)] {
        let err = clouds
            .connect(
                &Target {
                    provider: "aws".into(),
                    relay_mode: mode,
                    relay_token: Some("static-tok".into()),
                    ..Default::default()
                },
                false,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    }

    let err = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("   \n ".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    let err = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-tok".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    let err = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    let err = clouds
        .test(&Target {
            provider: "aws".into(),
            relay_url: Some("ftp://relay.example".into()),
            relay_mode: Some(RelayMode::Static),
            relay_token: Some("static-tok".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");

    let err = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-tok".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cloud(_)), "{err:?}");
    assert!(
        err.to_string().contains("static"),
        "expected static token probe failure, got: {err}"
    );

    assert_eq!(store_secret(dir.path(), "byoc-relay-token-aws"), None);
    let status = clouds.status(Some("aws")).await.unwrap();
    assert!(!status.providers[0].connected);
}

#[tokio::test]
async fn account_mode_custom_relay_url_isolates_registration_and_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let default_relay = Arc::new(FakeRelay::start().await);
    let custom_relay = Arc::new(FakeRelay::start().await);
    default_relay.add_account("acct-token", "user-1", Some("ada@example.com"));
    custom_relay.add_account("acct-token", "user-1", Some("ada@example.com"));

    let fake = FakeProvider::new("aws", Tier::Vm);
    {
        let custom_relay = custom_relay.clone();
        fake.on_boot(Arc::new(move |spec, _| {
            custom_relay.set_online(&spec.tags[model::tag::MACHINE], true, "0.1.0");
        }));
    }
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake.clone()],
        RelayAccess::new(
            default_relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-token".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();
    let conn = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(format!("{}/", custom_relay.url)),
                relay_mode: Some(RelayMode::Account),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(conn.provider.relay_mode, Some(RelayMode::Account));
    assert_eq!(
        conn.provider.relay_url.as_deref(),
        Some(custom_relay.url.as_str())
    );

    let sb = sandboxes
        .create(create_opts("aws", "custom-acct"))
        .await
        .unwrap();
    let machine = sb.provider_details()[DETAIL_RELAY_MACHINE].clone();
    assert!(custom_relay.machine(&machine).is_some());
    assert!(default_relay.machine(&machine).is_none());

    let spec = fake.account.lock().unwrap().specs[0].clone();
    let sb_env = decode_cloud_init_file(&spec.user_data, "/etc/cua/sandbox.env").unwrap();
    assert_eq!(
        env_value(&sb_env, "CUA_ENV_RELAY_URL").as_deref(),
        Some(custom_relay.url.as_str())
    );
    assert!(
        decode_cloud_init_file(&spec.user_data, "/etc/cua/relay/jwks.json").is_some(),
        "account mode still pins JWKS"
    );

    sandboxes.delete("custom-acct").await.unwrap();
    assert!(custom_relay.machine(&machine).is_none());
}

#[tokio::test]
async fn static_relay_full_lifecycle_without_cua_auth_login_and_secret_redaction() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "static-relay-secret-987654";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);

    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let vm_fake = FakeProvider::new("aws", Tier::Vm);

    struct StaticModalTransport {
        relay: Arc<FakeRelay>,
        mock_url: String,
        envs: Mutex<Vec<serde_json::Value>>,
        sandboxes: Mutex<std::collections::BTreeMap<String, serde_json::Value>>,
    }

    #[async_trait::async_trait]
    impl cua_byoc::modal::HelperTransport for StaticModalTransport {
        async fn call_with_token(
            &self,
            req: serde_json::Value,
            _token: &cua_byoc::modal::ModalToken,
            d: std::time::Duration,
        ) -> cua_byoc::Result<serde_json::Value> {
            self.call(req, true, d).await
        }

        async fn call(
            &self,
            req: serde_json::Value,
            _profile_only: bool,
            _: std::time::Duration,
        ) -> cua_byoc::Result<serde_json::Value> {
            let mut sbs = self.sandboxes.lock().unwrap();
            Ok(match req["op"].as_str().unwrap_or_default() {
                "check" => {
                    serde_json::json!({"account": {"profile": req["profile"], "environment": req["environment"], "sandboxes": sbs.len()}})
                }
                "create" => {
                    self.envs.lock().unwrap().push(req["env"].clone());
                    let id = format!("sb-{}", sbs.len() + 1);
                    let sb = serde_json::json!({"id": id, "name": req["name"], "status": "running", "tags": req["tags"]});
                    sbs.insert(id, sb.clone());
                    let machine = req["env"]["CUA_ENV_MACHINE_ID"].as_str().unwrap();
                    let env_tok = req["env"]["CUA_ENV_TOKEN"].as_str().unwrap();
                    self.relay.tunnel(machine, &self.mock_url);
                    self.relay.set_static_online(machine, true, Some(env_tok));
                    serde_json::json!({"sandbox": sb})
                }
                "get" => match sbs.get(req["id"].as_str().unwrap_or_default()) {
                    Some(sb) => serde_json::json!({"sandbox": sb}),
                    None => {
                        serde_json::json!({"error": {"kind": "not_found", "message": "Sandbox not found"}})
                    }
                },
                "list" => {
                    serde_json::json!({"sandboxes": sbs.values().cloned().collect::<Vec<_>>()})
                }
                "delete" => {
                    sbs.remove(req["id"].as_str().unwrap_or_default());
                    serde_json::json!({})
                }
                other => {
                    serde_json::json!({"error": {"kind": "invalid", "message": format!("unknown op {other}")}})
                }
            })
        }
    }

    let modal_transport = Arc::new(StaticModalTransport {
        relay: relay.clone(),
        mock_url: mock_spacesd.url(),
        envs: Mutex::default(),
        sandboxes: Mutex::default(),
    });
    let modal_toml = dir.path().join("modal.toml");
    std::fs::write(
        &modal_toml,
        "[cuaai]\ntoken_id = \"ak-secret\"\ntoken_secret = \"as-secret\"\nactive = true\n",
    )
    .unwrap();
    let modal_api = Arc::new(cua_byoc::modal::ModalApi::with(
        modal_transport.clone(),
        Arc::new(cua_contrib::image_config::FixedConfigSource(
            cua_contrib::image_config::ImageConfig {
                cmd: vec!["/opt/cua/desktop/entrypoint.sh".into()],
                ..Default::default()
            },
        )),
        Some(modal_toml),
    ));

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![vm_fake.clone(), modal_api],
        RelayAccess::new(relay.url.clone(), Arc::new(FailingTokens)),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let target = Target {
        provider: "aws".into(),
        region: Some("us-west-2".into()),
        relay_url: Some(format!("{}/", relay.url)),
        relay_mode: Some(RelayMode::Static),
        relay_token: Some(static_secret.into()),
        ..Default::default()
    };
    assert!(!format!("{target:?}").contains(static_secret));

    let tested = clouds.test(&target).await.unwrap();
    assert!(tested.ok, "{tested:?}");
    assert_eq!(store_secret(dir.path(), "byoc-relay-token-aws"), None);

    let conn = clouds.connect(&target, false, Some(2)).await.unwrap();
    assert!(conn.provider.connected);
    assert_eq!(conn.provider.relay_mode, Some(RelayMode::Static));
    assert_eq!(conn.provider.relay_url.as_deref(), Some(relay.url.as_str()));
    assert_eq!(
        store_secret(dir.path(), "byoc-relay-token-aws").as_deref(),
        Some(static_secret)
    );

    let seen_env_tokens: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let relay = relay.clone();
        let seen = seen_env_tokens.clone();
        let mock_url = mock_spacesd.url();
        vm_fake.on_boot(Arc::new(move |spec, _| {
            let machine = spec.tags[model::tag::MACHINE].clone();
            let sb_env = decode_cloud_init_file(&spec.user_data, "/etc/cua/sandbox.env").unwrap();
            let env_tok = env_value(&sb_env, "CUA_ENV_TOKEN").unwrap();
            seen.lock().unwrap().push((machine.clone(), env_tok));
            relay.tunnel(&machine, &mock_url);
            relay.set_static_online(&machine, true, Some("wrong-env-token-1234"));
        }));
    }
    vm_fake.account.lock().unwrap().boot_log = Some(format!(
        "systemd starting\nCUA_RELAY_TOKEN={static_secret}\nCUA_ENV_TOKEN=should_redact_too\nerror: unit failed\n"
    ));

    let err = sandboxes
        .create(create_opts("aws", "bad-env"))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("static relay rejected environment token"),
        "{err}"
    );
    assert!(vm_fake.account.lock().unwrap().resources.is_empty());
    let (bad_machine, _) = seen_env_tokens.lock().unwrap()[0].clone();
    assert_eq!(store_secret(dir.path(), "byoc-env-tokens-aws"), None);
    assert!(
        !cua_byoc::Store::new(dir.path())
            .resources()
            .unwrap()
            .iter()
            .any(|r| r.resource_type == model::RELAY_MACHINE)
    );
    let boot_logs_dir = dir.path().join("cloud/boot-logs");
    let log_files: Vec<_> = std::fs::read_dir(&boot_logs_dir)
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!log_files.is_empty());
    for log in &log_files {
        assert!(!log.contains(static_secret), "{log}");
        assert!(!log.contains("should_redact_too"), "{log}");
    }
    let _ = bad_machine;

    {
        let relay = relay.clone();
        let seen = seen_env_tokens.clone();
        let mock_url = mock_spacesd.url();
        vm_fake.on_boot(Arc::new(move |spec, _| {
            let machine = spec.tags[model::tag::MACHINE].clone();
            let sb_env = decode_cloud_init_file(&spec.user_data, "/etc/cua/sandbox.env").unwrap();
            let env_tok = env_value(&sb_env, "CUA_ENV_TOKEN").unwrap();
            seen.lock()
                .unwrap()
                .push((machine.clone(), env_tok.clone()));
            relay.tunnel(&machine, &mock_url);
            relay.set_static_online(&machine, true, Some(&env_tok));
        }));
    }

    let sb = sandboxes
        .create(create_opts("aws", "static-vm"))
        .await
        .unwrap();
    let details = sb.provider_details();
    let machine = details[DETAIL_RELAY_MACHINE].clone();
    assert!(
        machine.len() >= 8
            && machine.len() <= 64
            && machine
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "invalid machine id format: {machine}"
    );

    let spec = vm_fake
        .account
        .lock()
        .unwrap()
        .specs
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        decode_cloud_init_file(&spec.user_data, "/etc/cua/relay/machine-token").as_deref(),
        Some(static_secret)
    );
    assert!(
        decode_cloud_init_file(&spec.user_data, "/etc/cua/relay/jwks.json").is_none(),
        "empty jwks must be omitted in Static mode"
    );
    let policy_raw = decode_cloud_init_file(&spec.user_data, "/etc/cua/relay/policy.json").unwrap();
    let policy: serde_json::Value = serde_json::from_str(&policy_raw).unwrap();
    assert!(policy.get("owner").is_none(), "{policy}");
    assert_eq!(policy["sharing"], true);

    let client = sb.spacesd().await.unwrap();
    let caps = client.refresh_capabilities().await.unwrap();
    assert!(!caps.features.is_empty() || caps.protocol_version > 0);
    let health = client.health().await.unwrap();
    assert_eq!(health.status, 1);

    sandboxes.suspend("static-vm").await.unwrap();
    sandboxes.resume("static-vm").await.unwrap();
    sandboxes.delete("static-vm").await.unwrap();
    assert_eq!(store_secret(dir.path(), "byoc-env-tokens-aws"), None);

    clouds
        .connect(
            &Target {
                provider: "modal".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    let modal_sb = sandboxes
        .create(create_opts("modal", "static-box"))
        .await
        .unwrap();
    let modal_machine = modal_sb.provider_details()[DETAIL_RELAY_MACHINE].clone();
    let m_env = modal_transport.envs.lock().unwrap()[0].clone();
    assert_eq!(m_env["CUA_RELAY_TOKEN"], static_secret);
    assert_eq!(m_env["CUA_ENV_RELAY_URL"], relay.url);
    assert!(m_env.get("CUA_RELAY_JWKS_JSON").is_none());
    let m_policy: serde_json::Value =
        serde_json::from_str(m_env["CUA_HOST_POLICY_JSON"].as_str().unwrap()).unwrap();
    assert!(m_policy.get("owner").is_none());
    assert!(
        store_secret(dir.path(), "byoc-env-tokens-modal")
            .unwrap()
            .contains(&modal_machine)
    );
    sandboxes.delete("static-box").await.unwrap();
    assert_eq!(store_secret(dir.path(), "byoc-env-tokens-modal"), None);

    for path in [
        dir.path().join("cloud/state.json"),
        dir.path().join("cloud/links.json"),
        dir.path().join("cloud/audit.jsonl"),
    ] {
        if path.exists() {
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(
                !content.contains(static_secret),
                "secret leaked in {path:?}"
            );
        }
    }
    let status_json = serde_json::to_string(&clouds.status(None).await.unwrap()).unwrap();
    assert!(!status_json.contains(static_secret));
}

#[tokio::test]
async fn static_reconnect_reuses_token_switch_and_disconnect_clear_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_static_token("static-secret-abc");
    relay.add_account("acct-token", "user-1", Some("ada@example.com"));

    let fake = FakeProvider::new("aws", Tier::Vm);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-token".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-secret-abc".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        store_secret(dir.path(), "byoc-relay-token-aws").as_deref(),
        Some("static-secret-abc")
    );

    let reconnected = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: None,
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reconnected.provider.relay_mode, Some(RelayMode::Static));
    assert_eq!(
        store_secret(dir.path(), "byoc-relay-token-aws").as_deref(),
        Some("static-secret-abc")
    );

    let switched = clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_mode: Some(RelayMode::Account),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(switched.provider.relay_mode, Some(RelayMode::Account));
    assert_eq!(store_secret(dir.path(), "byoc-relay-token-aws"), None);

    clouds
        .connect(
            &Target {
                provider: "aws".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-secret-abc".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    cua_auth::Store::File(dir.path().join("credentials.json"))
        .save_secret("byoc-env-tokens-aws", br#"{"cloud-11112222":"tok"}"#)
        .unwrap();

    clouds.disconnect("aws", false).await.unwrap();
    assert_eq!(store_secret(dir.path(), "byoc-relay-token-aws"), None);
    assert_eq!(store_secret(dir.path(), "byoc-env-tokens-aws"), None);
}

#[tokio::test]
async fn account_and_static_clouds_coexist_in_the_same_home() {
    let dir = tempfile::tempdir().unwrap();
    let acct_relay = Arc::new(FakeRelay::start().await);
    acct_relay.add_account("acct-token", "user-1", Some("ada@example.com"));
    let static_relay = Arc::new(FakeRelay::start().await);
    static_relay.add_static_token("static-coexist-tok");
    static_relay.set_account_auth(false);

    let mock_spacesd = MockServer::start(MockAuth::default()).await;

    let aws_fake = FakeProvider::new("aws", Tier::Vm);
    {
        let acct_relay = acct_relay.clone();
        aws_fake.on_boot(Arc::new(move |spec, _| {
            acct_relay.set_online(&spec.tags[model::tag::MACHINE], true, "0.1.0");
        }));
    }
    let hetzner_fake = FakeProvider::new("hetzner", Tier::Vm);
    {
        let static_relay = static_relay.clone();
        let mock_url = mock_spacesd.url();
        hetzner_fake.on_boot(Arc::new(move |spec, _| {
            let machine = spec.tags[model::tag::MACHINE].clone();
            let sb_env = decode_cloud_init_file(&spec.user_data, "/etc/cua/sandbox.env").unwrap();
            let env_tok = env_value(&sb_env, "CUA_ENV_TOKEN").unwrap();
            static_relay.tunnel(&machine, &mock_url);
            static_relay.set_static_online(&machine, true, Some(&env_tok));
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![aws_fake.clone(), hetzner_fake.clone()],
        RelayAccess::new(
            acct_relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-token".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    clouds
        .connect(
            &Target {
                provider: "aws".into(),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    clouds
        .connect(
            &Target {
                provider: "hetzner".into(),
                relay_url: Some(static_relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-coexist-tok".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();

    let sb_acct = sandboxes
        .create(create_opts("aws", "acct-vm"))
        .await
        .unwrap();
    let sb_static = sandboxes
        .create(create_opts("hetzner", "static-vm"))
        .await
        .unwrap();
    let acct_machine = sb_acct.provider_details()[DETAIL_RELAY_MACHINE].clone();
    let static_machine = sb_static.provider_details()[DETAIL_RELAY_MACHINE].clone();

    assert!(acct_relay.machine(&acct_machine).is_some());
    assert!(acct_relay.machine(&static_machine).is_none());

    sandboxes.delete("static-vm").await.unwrap();
    sandboxes.delete("acct-vm").await.unwrap();
}

#[tokio::test]
async fn static_connection_missing_url_or_token_never_reaches_account_relay_on_delete_or_rollback()
{
    use cua_sandbox_core::Provider as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let acct_hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = acct_hits.clone();
    let acct_app = axum::Router::new().fallback(move || {
        let hits = hits_clone.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({})),
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let acct_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, acct_app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let static_relay = Arc::new(FakeRelay::start().await);
    static_relay.add_static_token("static-tok");
    let mock_spacesd = MockServer::start(MockAuth::default()).await;
    let fake = FakeProvider::new("hetzner", Tier::Vm);
    {
        let static_relay = static_relay.clone();
        let mock_url = mock_spacesd.url();
        fake.on_boot(Arc::new(move |spec, _| {
            let machine = spec.tags[model::tag::MACHINE].clone();
            let sb_env = decode_cloud_init_file(&spec.user_data, "/etc/cua/sandbox.env").unwrap();
            let env_tok = env_value(&sb_env, "CUA_ENV_TOKEN").unwrap();
            static_relay.tunnel(&machine, &mock_url);
            static_relay.set_static_online(&machine, true, Some(&env_tok));
        }));
    }

    let relay_access = RelayAccess::new(
        acct_url.clone(),
        Arc::new(cua_host::relay::StaticToken("acct-tok".into())),
    );
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake.clone()],
        relay_access.clone(),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();
    clouds
        .connect(
            &Target {
                provider: "hetzner".into(),
                relay_url: Some(static_relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-tok".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();

    // 1. Create a sandbox, then corrupt the stored static connection (drop relay_url
    //    and clear its static token) before calling endpoint() and delete().
    let sb = sandboxes
        .create(create_opts("hetzner", "corrupt-static-del"))
        .await
        .unwrap();
    let machine_id = sb.provider_details()[DETAIL_RELAY_MACHINE].clone();
    let store = cua_byoc::Store::new(dir.path());
    let mut conn = store.connection("hetzner").unwrap().unwrap();
    conn.relay_url = None;
    store.connect(conn).unwrap();
    let cred_store = cua_auth::Store::File(dir.path().join("credentials.json"));
    let _ = cred_store.clear_secret("byoc-relay-token-hetzner");

    let provider = cua_byoc::CloudSandboxes::new(
        fake.clone(),
        Arc::new(cua_byoc::Store::new(dir.path())),
        relay_access.clone(),
    );
    let inst = provider
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "corrupt-static-del")
        .unwrap();
    let ep_err = provider.endpoint(&inst, 8000).unwrap_err();
    assert!(
        ep_err.to_string().contains("no relay URL is recorded"),
        "expected static relay error from endpoint(), got: {ep_err}"
    );
    sandboxes.delete("corrupt-static-del").await.unwrap();
    assert_eq!(
        acct_hits.load(Ordering::SeqCst),
        0,
        "delete must never fall back to the account relay for a misconfigured static connection"
    );
    let env_map: Option<Vec<u8>> = cred_store.load_secret("byoc-env-tokens-hetzner").unwrap();
    assert!(
        env_map.is_none_or(|b| !String::from_utf8_lossy(&b).contains(&machine_id)),
        "local env token should still be cleaned up on delete"
    );

    // 2. Rollback path: restore valid relay_url + token for prepare_join, then inject a
    //    boot hook that corrupts the connection's relay_url, clears its static token,
    //    and stops the VM so boot fails and rollback runs with missing static config.
    let mut valid_conn = store.connection("hetzner").unwrap().unwrap();
    valid_conn.relay_url = Some(static_relay.url.clone());
    store.connect(valid_conn).unwrap();
    cred_store
        .save_secret("byoc-relay-token-hetzner", b"static-tok")
        .unwrap();
    let home_for_hook = dir.path().to_path_buf();
    let fake_for_hook = fake.clone();
    fake.on_boot(Arc::new(move |_spec, res| {
        let store = cua_byoc::Store::new(&home_for_hook);
        if let Ok(Some(mut c)) = store.connection("hetzner") {
            c.relay_url = None;
            let _ = store.connect(c);
        }
        let creds = cua_auth::Store::File(home_for_hook.join("credentials.json"));
        let _ = creds.clear_secret("byoc-relay-token-hetzner");
        if let Some(r) = fake_for_hook
            .account
            .lock()
            .unwrap()
            .resources
            .get_mut(&res.id)
        {
            r.state = "stopped".into();
        }
    }));
    let err = sandboxes
        .create(create_opts("hetzner", "static-rollback-vm"))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("stopped") || err.to_string().contains("relay"),
        "{err}"
    );
    assert_eq!(
        acct_hits.load(Ordering::SeqCst),
        0,
        "rollback must never reach the account relay for a static connection"
    );
}
