// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Regression tests for `connect_with` / `connect_sealed` / `PreparedTarget`
//! target validation, Azure static-relay rejection, and generic custom-VPC flags.

use std::sync::Arc;

use cua_byoc::model::Tier;
use cua_byoc::testing::FakeProvider;
use cua_byoc::{RelayAccess, Target};
use cua_host::testing::FakeRelay;
use cua_sandbox_core::byoc::{ConnectRequest, RelayMode};
use cua_sandbox_core::{Error, Sandboxes};

#[tokio::test]
async fn azure_static_relay_is_rejected_before_oidc_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let azure = FakeProvider::new("azure", Tier::Vm);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![azure],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("unused".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "azure".into(),
                relay_url: Some(relay.url.clone()),
                relay_mode: Some(RelayMode::Static),
                relay_token: Some("static-tok".into()),
                ..Default::default()
            },
            auth: None,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(ref m) if m.contains("cannot be combined with --oidc or --sealed")),
        "expected static-relay rejection for Azure, got: {err:?}"
    );
}

#[tokio::test]
async fn custom_vpc_flags_rejected_generically_by_supports_custom_vpc() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(FakeRelay::start().await);
    let fake = FakeProvider::new("hetzner", Tier::Vm);
    let sandboxes = cua_byoc::install_with(
        Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
        dir.path(),
        vec![fake],
        RelayAccess::new(
            relay.url.clone(),
            Arc::new(cua_host::relay::StaticToken("unused".into())),
        ),
    )
    .build();
    let clouds = sandboxes.clouds().unwrap();

    let err = clouds
        .connect_with(&ConnectRequest {
            target: Target {
                provider: "hetzner".into(),
                vpc_id: Some("vpc-123".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap_err();
    match err {
        Error::InvalidArgument(msg) => {
            assert!(msg.contains("hetzner"), "{msg}");
            assert!(
                !msg.contains("aliyun-ecs"),
                "error must not hardcode aliyun-ecs: {msg}"
            );
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[tokio::test]
async fn create_rejects_mismatched_os_or_hashed_dir_spacesd_download_url_before_cloud_or_relay() {
    use cua_sandbox_core::{CreateOptions, ProviderKind};

    let sha = "a".repeat(64);
    let cases = [
        (
            "linux",
            "linux",
            "https://mirror.example.com/cua-spacesd.exe".to_string(),
            "Windows artifact",
        ),
        (
            "windows",
            "windows",
            "https://mirror.example.com/cua-spacesd-linux-x86_64.tar.gz".to_string(),
            "Linux artifact",
        ),
        (
            "linux",
            "linux",
            format!("https://mirror.example.com/releases/#sha256={sha}"),
            "directory mirror",
        ),
    ];

    for (idx, (os, image, url, expected)) in cases.into_iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(FakeRelay::start().await);
        let fake = FakeProvider::new("fakecloud", Tier::Vm);
        fake.account.lock().unwrap().supported_oses = Some(&["linux", "windows"]);
        fake.set_runtimes(vec![cua_sandbox_core::placement::Runtime::Other(
            "native".into(),
        )]);
        let sandboxes = cua_byoc::install_with(
            Sandboxes::builder().state_dir(dir.path().join("sandboxes")),
            dir.path(),
            vec![fake.clone()],
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
                    provider: "fakecloud".into(),
                    spacesd_download_url: Some(url),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();

        let calls_before = fake.calls().len();
        let mut opts = CreateOptions::new(ProviderKind::Contrib, image);
        opts.contrib = Some("fakecloud".into());
        opts.name = Some(format!("cross-os-{idx}"));
        opts.os = os.into();
        let err = sandboxes.create(opts).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains(expected)),
            "case {idx} ({os}): expected InvalidArgument containing {expected:?}, got {err:?}"
        );
        assert_eq!(
            fake.calls().len(),
            calls_before,
            "case {idx} must fail before calling cloud API: {:?}",
            fake.calls()
        );
        assert_eq!(
            relay.register_calls(),
            0,
            "case {idx} must fail before registering on relay"
        );
    }
}

#[cfg(all(feature = "federation", feature = "hetzner"))]
#[path = "sealed_support/mod.rs"]
mod sealed_support;

#[cfg(all(feature = "federation", feature = "hetzner"))]
#[path = "support/fake_hetzner.rs"]
mod fake_hetzner;

#[cfg(all(feature = "federation", feature = "hetzner"))]
mod sealed_relay_probe {
    use std::sync::{Arc, Mutex};

    use cua_byoc::Clouds;
    use cua_byoc::api::{CloudApi, Target};
    use cua_byoc::federation::IssuerClient;
    use cua_byoc::hetzner::{Hetzner, TokenStore};
    use cua_byoc::sealed::PoolSealer;
    use cua_sandbox_core::byoc::{CloudManager as _, ConnectRequest};

    use crate::fake_hetzner::{S, handle};
    use crate::sealed_support::{FakeIssuer, FakePool};

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

    #[tokio::test]
    async fn connect_sealed_probes_custom_relay_before_mutating_issuer() {
        let s: S = Arc::default();
        let app = axum::Router::new().fallback(handle).with_state(s);
        let h_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h_addr = h_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(h_listener, app).await.unwrap() });

        let broken_app = axum::Router::new()
            .fallback(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "relay down") });
        let r_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let r_addr = r_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(r_listener, broken_app).await.unwrap() });

        let home = tempfile::tempdir().unwrap();
        let store = Arc::new(MemStore::default());
        let api = Arc::new(
            Hetzner::with_endpoint(&format!("http://{h_addr}/v1"), store, None)
                .with_poll(std::time::Duration::from_millis(10)),
        );
        let issuer = Arc::new(FakeIssuer::default());
        let pool = FakePool::new();
        let sealer = pool.join("laptop");

        let clouds = Clouds::new(
            home.path(),
            vec![api as Arc<dyn CloudApi>],
            Arc::new(cua_byoc::Store::new(home.path())),
        )
        .with_issuer(issuer.clone() as Arc<dyn IssuerClient>)
        .with_sealer(sealer as Arc<dyn PoolSealer>);

        let out = clouds
            .connect_with(&ConnectRequest {
                target: Target {
                    provider: "hetzner".into(),
                    region: Some("fsn1".into()),
                    token: Some("hcloud-SEALED-token-0123456789".into()),
                    relay_url: Some(format!("http://{r_addr}")),
                    ..Default::default()
                },
                auth: Some("sealed".into()),
                budget_usd_month: Some(50.0),
                max_size: Some("4x8".into()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(out.provider.status, "failed", "{out:?}");
        assert!(
            out.checks.iter().any(|c| c.name == "relay" && !c.ok),
            "expected failed relay check: {:?}",
            out.checks
        );
        assert!(
            issuer.changes.lock().unwrap().is_empty(),
            "issuer must not be mutated before relay probe passes: {:?}",
            issuer.changes.lock().unwrap()
        );
        assert!(
            issuer.conns.lock().unwrap().is_empty(),
            "no server connection should be created when relay probe fails"
        );
    }
}
