// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Hermetic end-to-end tests for Linux Direct VM Sandbox (`--runtime native`),
//! verifying runtime dispatch (`native` vs default `docker`), `--spacesd-download-url`
//! mirror plumbing, decoded `#cloud-config` `UserData` contracts, Account & Static
//! Relay Mode lifecycles, failed-boot rollback & secret redaction, and `aliyun-ecs`
//! placement capabilities.

use std::sync::Arc;

use base64::Engine as _;
use cua_byoc::model::{self, Tier};
use cua_byoc::testing::FakeProvider;
use cua_byoc::{RelayAccess, Target};
use cua_host::relay::AccountTokens;
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{ConnectRequest, DETAIL_RELAY_MACHINE, RelayMode};
use cua_sandbox_core::placement::{Axis, Kind, On, Runtime};
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
    let raw = rest[c..c + end].trim();
    let bytes = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    String::from_utf8(bytes).ok()
}

fn extract_heredoc(script: &str, marker: &str) -> Option<String> {
    let start_tag = format!("<<'{marker}'\n");
    let start = script.find(&start_tag)? + start_tag.len();
    let end_tag = format!("\n{marker}\n");
    let end = script[start..].find(&end_tag)?;
    Some(format!("{}\n", &script[start..start + end]))
}

fn create_opts(provider: &str, image: &str, name: &str) -> CreateOptions {
    let mut o = CreateOptions::new(ProviderKind::Contrib, image);
    o.contrib = Some(provider.into());
    o.name = Some(name.into());
    o
}

#[tokio::test]
async fn linux_and_linux_slim_dispatch_docker_default_vs_native_direct_vm() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-token", "user-1", Some("ada@example.com"));

    let fake = FakeProvider::new("fake-direct", Tier::Vm);
    fake.set_runtimes(vec![
        Runtime::Other("docker".into()),
        Runtime::Other("native".into()),
    ]);
    {
        let relay = relay.clone();
        fake.on_boot(Arc::new(move |spec, _| {
            relay.set_online(&spec.tags[model::tag::MACHINE], true, "0.1.0");
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake.clone()],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-token".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    // Invalid mirror URL fails fast before persisting anything.
    let bad_err = clouds
        .connect(
            &Target {
                provider: "fake-direct".into(),
                region: Some("cn-hangzhou".into()),
                spacesd_download_url: Some("http://mirror.example.cn/cua-spacesd.tar.gz".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(bad_err, Error::InvalidArgument(_)), "{bad_err:?}");

    // Connect with custom HTTPS mirror URL (Account Relay Mode).
    let mirror = "https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz";
    let connected = clouds
        .connect(
            &Target {
                provider: "fake-direct".into(),
                region: Some("cn-hangzhou".into()),
                spacesd_download_url: Some(mirror.into()),
                ..Default::default()
            },
            false,
            Some(4),
        )
        .await
        .unwrap();
    assert_eq!(
        connected.provider.spacesd_download_url.as_deref(),
        Some(mirror)
    );
    let status = clouds.status(Some("fake-direct")).await.unwrap();
    assert_eq!(
        status.providers[0].spacesd_download_url.as_deref(),
        Some(mirror)
    );

    // 1. Default (`auto`) on `linux` keeps Docker-on-VM (`docker`).
    let sb_docker = sandboxes
        .create(create_opts(
            "fake-direct",
            "registry.invalid/trycua/linux:24.04",
            "linux-default",
        ))
        .await
        .unwrap();
    assert_eq!(
        sb_docker
            .provider_details()
            .get("runtime")
            .map(String::as_str),
        Some("docker-on-vm")
    );
    let spec_docker = fake.account.lock().unwrap().specs[0].clone();
    assert_eq!(spec_docker.kind, "container");
    let boot_docker =
        decode_cloud_init_file(&spec_docker.user_data, "/usr/local/sbin/cua-first-boot").unwrap();
    assert!(boot_docker.contains("docker run -d"), "{boot_docker}");

    // 2. `--runtime native` on `linux` produces Linux Direct VM `cloud-init` (no Docker).
    let mut o_native = create_opts(
        "fake-direct",
        "registry.invalid/trycua/linux:24.04",
        "linux-native",
    );
    o_native.runtime = Runtime::Other("native".into());
    o_native.env.insert("APP_ENV".into(), "production".into());
    o_native.env.insert("LOG_FORMAT".into(), "json".into());
    let sb_native = sandboxes.create(o_native).await.unwrap();
    assert_eq!(
        sb_native
            .provider_details()
            .get("runtime")
            .map(String::as_str),
        Some("native")
    );
    let spec_native = fake.account.lock().unwrap().specs[1].clone();
    assert!(
        spec_native.user_data.len() < 16 * 1024,
        "Account Relay native UserData {} >= 16384",
        spec_native.user_data.len()
    );
    assert_eq!(spec_native.kind, "vm");
    assert_eq!(spec_native.runtime, "native");
    assert_eq!(spec_native.spacesd_download_url.as_deref(), Some(mirror));
    assert!(
        !spec_native.user_data.contains("cmt_"),
        "no plaintext secret"
    );
    assert!(
        !spec_native
            .user_data
            .contains("docker.service.d/cua-metadata.conf")
    );
    let boot_native =
        decode_cloud_init_file(&spec_native.user_data, "/usr/local/sbin/cua-first-boot").unwrap();
    assert!(!boot_native.contains("docker.io"));
    assert!(!boot_native.contains("docker run"));
    assert!(boot_native.contains("/usr/local/bin/cua-spacesd"));
    assert!(boot_native.contains(mirror));
    assert!(boot_native.contains("sha256sum"));
    assert!(boot_native.contains("systemctl enable --now cua-host-net.service"));
    assert!(boot_native.contains("systemctl enable --now cua-spacesd.service"));
    assert!(boot_native.contains("shutdown -h +240"));
    let host_net = extract_heredoc(&boot_native, "CUA_HOST_NET").unwrap();
    assert!(host_net.contains("100.100.100.200/32"));
    let env_native =
        decode_cloud_init_file(&spec_native.user_data, "/etc/cua/spacesd.env").unwrap();
    assert!(env_native.contains("CUA_RELAY_JWKS=/etc/cua/relay/jwks.json"));
    assert!(env_native.contains("APP_ENV=production\n"));
    assert!(env_native.contains("LOG_FORMAT=json\n"));
    assert!(decode_cloud_init_file(&spec_native.user_data, "/etc/cua/relay/jwks.json").is_some());
    let starter = extract_heredoc(&boot_native, "CUA_SPACESD_START").unwrap();
    assert!(starter.contains("CUA_ENV_NO_DESKTOP=true"));
    assert!(starter.contains("join"));
    assert!(boot_native.contains("libxkbcommon0"));

    // 3. `--runtime native` on `linux-slim` also works cleanly.
    let mut o_slim = create_opts(
        "fake-direct",
        "registry.invalid/trycua/linux:24.04-slim",
        "slim-native",
    );
    o_slim.runtime = Runtime::Other("native".into());
    let sb_slim = sandboxes.create(o_slim).await.unwrap();
    assert_eq!(
        sb_slim
            .provider_details()
            .get("runtime")
            .map(String::as_str),
        Some("native")
    );

    // 4. Invalid runtime fails placement before creating relay/cloud resources.
    let before_calls = fake.calls().len();
    let mut o_bad = create_opts(
        "fake-direct",
        "registry.invalid/trycua/linux:24.04",
        "bad-rt",
    );
    o_bad.runtime = Runtime::Qemu;
    let err = sandboxes.create(o_bad).await.unwrap_err();
    assert!(
        matches!(err, Error::InvalidPlacement(ref p) if p.axis == Axis::Runtime && p.valid == ["auto", "docker", "native"]),
        "{err:?}"
    );
    assert_eq!(fake.calls().len(), before_calls);

    // 5. Invalid `--env` keys fail closed before creating relay/cloud resources.
    for bad_key in ["", "#COMMENT", "A=B", "A\nB", "A\rB", "A\0B", "BAD-KEY"] {
        let mut o_bad_env = create_opts(
            "fake-direct",
            "registry.invalid/trycua/linux:24.04",
            "bad-env",
        );
        o_bad_env.runtime = Runtime::Other("native".into());
        o_bad_env.env.insert(bad_key.into(), "val".into());
        let env_err = sandboxes.create(o_bad_env).await.unwrap_err();
        assert!(
            matches!(env_err, Error::InvalidArgument(_)),
            "{bad_key:?} -> {env_err:?}"
        );
    }
    assert_eq!(fake.calls().len(), before_calls);

    // Lifecycle: suspend, resume, delete.
    let machine = sb_native.provider_details()[DETAIL_RELAY_MACHINE].clone();
    sandboxes.suspend("linux-native").await.unwrap();
    assert!(fake.calls().iter().any(|c| c.starts_with("stop fake-")));
    sandboxes.resume("linux-native").await.unwrap();
    assert!(fake.calls().iter().any(|c| c.starts_with("start fake-")));
    sandboxes.delete("linux-native").await.unwrap();
    assert!(relay.machine(&machine).is_none());
}

#[tokio::test]
async fn linux_native_static_relay_lifecycle_and_failed_boot_redaction() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let static_secret = "static-native-secret-xyz";
    relay.add_static_token(static_secret);
    relay.set_account_auth(false);

    let mock_spacesd = MockServer::start(MockAuth::default()).await;
    let fake = FakeProvider::new("fake-static", Tier::Vm);
    fake.set_runtimes(vec![
        Runtime::Other("docker".into()),
        Runtime::Other("native".into()),
    ]);
    {
        let relay = relay.clone();
        let mock_url = mock_spacesd.url();
        fake.on_boot(Arc::new(move |spec, _| {
            let machine = &spec.tags[model::tag::MACHINE];
            let envf = decode_cloud_init_file(&spec.user_data, "/etc/cua/spacesd.env").unwrap();
            let env_tok = envf
                .lines()
                .find_map(|l| l.strip_prefix("CUA_ENV_TOKEN="))
                .unwrap()
                .to_string();
            relay.tunnel(machine, &mock_url);
            relay.set_static_online(machine, true, Some(&env_tok));
        }));
    }

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake.clone()],
        RelayAccess::new(relay.url.clone(), Arc::new(FailingTokens)),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    // Connect via `connect_with` in Static Relay Mode + custom loopback mirror (no `cua auth login`).
    let mirror = "http://127.0.0.1:9999/cua-spacesd-linux-x86_64.tar.gz";
    let connected = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "fake-static".into(),
                region: Some("cn-hangzhou".into()),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some(static_secret.into()),
                spacesd_download_url: Some(mirror.into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(connected.provider.relay_mode, Some(RelayMode::Static));
    assert_eq!(
        connected.provider.spacesd_download_url.as_deref(),
        Some(mirror)
    );

    let mut o = create_opts(
        "fake-static",
        "registry.invalid/trycua/linux:24.04",
        "static-native",
    );
    o.runtime = Runtime::Other("native".into());
    o.env.insert("APP_ENV".into(), "production".into());
    o.env.insert("LOG_FORMAT".into(), "json".into());
    let sb = sandboxes.create(o).await.unwrap();
    let machine = sb.provider_details()[DETAIL_RELAY_MACHINE].clone();
    assert!(machine.starts_with("cloud-"), "{machine}");
    assert_eq!(
        sb.provider_details().get("runtime").map(String::as_str),
        Some("native")
    );

    let spec = fake.account.lock().unwrap().specs[0].clone();
    assert!(
        spec.user_data.len() < 16 * 1024,
        "Static Relay native UserData {} >= 16384",
        spec.user_data.len()
    );
    assert!(!spec.user_data.contains(static_secret));
    assert!(
        decode_cloud_init_file(&spec.user_data, "/etc/cua/relay/jwks.json").is_none(),
        "static mode omits jwks.json"
    );
    let envf = decode_cloud_init_file(&spec.user_data, "/etc/cua/spacesd.env").unwrap();
    assert!(!envf.contains("CUA_RELAY_JWKS="), "{envf}");
    let env_tok = envf
        .lines()
        .find_map(|l| l.strip_prefix("CUA_ENV_TOKEN="))
        .expect("static mode writes CUA_ENV_TOKEN")
        .to_string();
    assert!(
        !spec.user_data.contains(&env_tok),
        "env_token must be b64 only"
    );
    let policy: serde_json::Value = serde_json::from_str(
        &decode_cloud_init_file(&spec.user_data, "/etc/cua/relay/policy.json").unwrap(),
    )
    .unwrap();
    assert!(policy.get("owner").is_none());

    // Suspend, resume, delete.
    sandboxes.suspend("static-native").await.unwrap();
    sandboxes.resume("static-native").await.unwrap();
    sandboxes.delete("static-native").await.unwrap();
    assert!(fake.account.lock().unwrap().resources.is_empty());

    // Failed boot: captures boot_log, redacts secrets, rolls back instance & env_token.
    {
        let acct = fake.account.clone();
        fake.on_boot(Arc::new(move |spec, r| {
            let envf = decode_cloud_init_file(&spec.user_data, "/etc/cua/spacesd.env").unwrap();
            let leaked_env = envf
                .lines()
                .find_map(|l| l.strip_prefix("CUA_ENV_TOKEN="))
                .unwrap();
            acct.lock().unwrap().boot_log = Some(format!(
                "cua-first-boot: chmod 0600 /etc/cua/spacesd.env\n\
                 cua-first-boot: downloading cua-spacesd from https://user:s3cr3t@mirror.example.com/cua-spacesd.tar.gz\n\
                 cua-first-boot: CUA_ENV_TOKEN={leaked_env}\n\
                 cua-first-boot: relay_token={static_secret}\n\
                 cua-first-boot: SHA-256 verification failed for cua-spacesd download\n"
            ));
            acct.lock().unwrap().resources.get_mut(&r.id).unwrap().state = "terminated".into();
        }));
    }
    let mut o_fail = create_opts(
        "fake-static",
        "registry.invalid/trycua/linux:24.04",
        "static-fail",
    );
    o_fail.runtime = Runtime::Other("native".into());
    let err = sandboxes.create(o_fail).await.unwrap_err().to_string();
    assert!(err.contains("SHA-256 verification failed"), "{err}");
    assert!(!err.contains(static_secret), "secret leaked: {err}");
    assert!(!err.contains("spacesd.env"), "spacesd.env leaked: {err}");
    assert!(!err.contains("s3cr3t"), "URL password leaked: {err}");
    assert!(!err.contains("user:"), "URL username leaked: {err}");
    assert!(fake.account.lock().unwrap().resources.is_empty());
    let cred_store = cua_auth::Store::File(dir.path().join("credentials.json"));
    assert_eq!(
        cred_store
            .load_secret("byoc-env-tokens-fake-static")
            .unwrap(),
        None
    );
}

#[cfg(feature = "aliyun-ecs")]
#[tokio::test]
async fn aliyun_ecs_registers_docker_and_native_placement_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let _sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![Arc::new(cua_byoc::aliyun_ecs::AliyunEcs::new())],
        RelayAccess::new(relay.url.clone(), Arc::new(FailingTokens)),
    )
    .build();

    let on = On::parse("aliyun-ecs").unwrap();
    assert_eq!(
        cua_sandbox_core::placement::validate(&on, Kind::Auto, &Runtime::Other("native".into()))
            .unwrap(),
        Kind::Vm
    );
    assert_eq!(
        cua_sandbox_core::placement::validate(&on, Kind::Auto, &Runtime::Other("docker".into()))
            .unwrap(),
        Kind::Container
    );
    let err = cua_sandbox_core::placement::validate(&on, Kind::Auto, &Runtime::Qemu).unwrap_err();
    assert_eq!(err.valid, ["auto", "docker", "native"]);
}

#[tokio::test]
async fn credential_bearing_spacesd_download_url_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    relay.add_account("acct-token", "user-1", Some("ada@example.com"));

    let fake = FakeProvider::new("fake-cred-url", Tier::Vm);
    fake.set_runtimes(vec![
        Runtime::Other("docker".into()),
        Runtime::Other("native".into()),
    ]);

    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake.clone()],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("acct-token".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    for bad in [
        "https://user:secret@mirror.example.com/cua-spacesd.tar.gz",
        "http://user:secret@localhost:8080/cua-spacesd",
        "https://127.0.0.1@evil.com/bin",
        "https://user@mirror.example.com/bin",
        "https://s3cr3t\\@mirror.example.com/bin",
        "https://user:8443\\@mirror.example.com/bin",
        "https://user:12345\\@mirror.example.com/bin",
        "https://mirror.example.com\\@s3cr3t@evil.com/bin",
        "https://user:123456#@evil.com/bin",
        "https://user:123456?x=@evil.com/bin",
        "https://user:8080#@evil.com/bin",
        "https://user:8080?x=@evil.com/bin",
        "https://user:s3cr3t?@evil.com/bin",
        "https://user:s3cr3t#@evil.com/bin",
        "https://user:s3cr3t secret/@evil.com/bin?sig=DeadBeef",
        "https://ada@org:p4ssw0rd/@evil.com/bin",
        "https://ada@org:8080/@evil.com/bin",
    ] {
        let test_err = clouds
            .test(&Target {
                provider: "fake-cred-url".into(),
                region: Some("cn-hangzhou".into()),
                spacesd_download_url: Some(bad.into()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(
            matches!(test_err, Error::InvalidArgument(_)),
            "{bad}: {test_err:?}"
        );
        assert!(
            !test_err.to_string().contains("secret") && !test_err.to_string().contains("s3cr3t"),
            "secret leaked for {bad}: {test_err}"
        );

        let err = clouds
            .connect(
                &Target {
                    provider: "fake-cred-url".into(),
                    region: Some("cn-hangzhou".into()),
                    spacesd_download_url: Some(bad.into()),
                    ..Default::default()
                },
                false,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{bad}: {err:?}");
        assert!(
            !err.to_string().contains("secret") && !err.to_string().contains("s3cr3t"),
            "secret leaked for {bad}: {err}"
        );

        let err2 = clouds
            .connect_with(&ConnectRequest {
                target: Target {
                    provider: "fake-cred-url".into(),
                    region: Some("cn-hangzhou".into()),
                    spacesd_download_url: Some(bad.into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err2, Error::InvalidArgument(_)), "{bad}: {err2:?}");
        assert!(
            !err2.to_string().contains("secret") && !err2.to_string().contains("s3cr3t"),
            "secret leaked for {bad}: {err2}"
        );
    }

    assert!(!dir.path().join("cloud/state.json").exists());
    assert!(!dir.path().join("cloud/links.json").exists());

    // Even if a persisted state.json contains a credential-bearing URL (e.g.
    // from an older version or manual edit), CloudSandboxes::create fails closed.
    clouds
        .connect(
            &Target {
                provider: "fake-cred-url".into(),
                region: Some("cn-hangzhou".into()),
                ..Default::default()
            },
            false,
            None,
        )
        .await
        .unwrap();
    let state_path = dir.path().join("cloud/state.json");
    for persisted_bad in [
        "https://user:secret@mirror.example.com/cua-spacesd.tar.gz",
        "https://s3cr3t\\@mirror.example.com/bin",
        "https://user:8443\\@mirror.example.com/bin",
    ] {
        let mut state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        let conn_obj = state["connections"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|c| c["provider"] == "fake-cred-url")
            .unwrap();
        conn_obj["spacesd_download_url"] = serde_json::json!(persisted_bad);
        std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

        let calls_before = fake.calls().len();
        let mut o = create_opts(
            "fake-cred-url",
            "registry.invalid/trycua/linux:24.04",
            "should-fail",
        );
        o.runtime = Runtime::Other("native".into());
        let create_err = sandboxes.create(o).await.unwrap_err();
        assert!(
            matches!(create_err, Error::InvalidArgument(_)),
            "{persisted_bad}: {create_err:?}"
        );
        assert!(
            !create_err.to_string().contains("secret")
                && !create_err.to_string().contains("s3cr3t"),
            "secret leaked: {create_err}"
        );
        assert_eq!(fake.calls().len(), calls_before);
    }
}
