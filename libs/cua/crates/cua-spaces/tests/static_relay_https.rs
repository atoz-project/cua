// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! HTTPS coexistence, port-443 plaintext spy, UDP presence skip, plain-MCP
//! `/m/...` fallback, and upfront store-clean rejection tests for Static Relay
//! Mode Spaces (`relay:<machine-id>`).

use cua_sandbox_core::testing::McpTestServer;
use cua_spaces::presence::{Identity as PresenceIdentity, PresenceDatagrams};
use cua_spaces::relay::StaticToken;
use cua_spaces::{Provider, RelayAccount, Space, SpaceId, Spaces, Transport};
use cua_spacesd_client::testing::{
    HttpSpy, HttpsConnectProxy, MockAuth, MockServer, StaticRelayRouter, write_tls_fixture,
};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;

const MACHINE_A: &str = "machine-alpha-01";
const MACHINE_B: &str = "machine-beta-002";
const TOKEN_A: &str = "static-relay-token-alpha-secret";
const TOKEN_A_ROTATED: &str = "static-relay-token-alpha-rotated";
const TOKEN_B: &str = "static-relay-token-beta-secret";

const HTTPS_SUBPROCESS_ENV: &str = "CUA_TEST_STATIC_RELAY_HTTPS";
const HTTPS_FIXTURE_ENV: &str = "CUA_TEST_STATIC_RELAY_FIXTURE";
const HTTPS_PROXY_ADDR_ENV: &str = "CUA_TEST_STATIC_RELAY_PROXY";

struct SpyPresenceDatagrams {
    connect_calls: Arc<AtomicUsize>,
}

impl PresenceDatagrams for SpyPresenceDatagrams {
    fn connect<'a>(
        &'a self,
        _space: &'a Space,
        _info: &'a cua_spacesd_client::pb::PresenceDatagrams,
        _timeout: Duration,
    ) -> futures_util::future::BoxFuture<
        'a,
        cua_spaces::Result<cua_spaces::presence::DatagramChannel>,
    > {
        self.connect_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(cua_spaces::Error::Stream(
                "UDP presence datagrams must not be dialed for Static Relay Spaces".into(),
            ))
        })
    }
}

async fn mock_machine(id: &str, token: &str) -> MockServer {
    MockServer::start(MockAuth {
        token: Some(token.into()),
        gateway: None,
        prefix: Some(format!("/m/{id}")),
    })
    .await
}

async fn assert_bash(space: &Space, marker: &str) {
    let out = space
        .bash(&format!("echo {marker}"), Duration::from_secs(5))
        .await
        .unwrap();
    assert!(out.render().contains(marker), "{}", out.render());
}

/// Full HTTPS Seam 1 test in an isolated child process with `SSL_CERT_FILE`
/// and `HTTPS_PROXY` + `HTTP_PROXY` pointing at our in-process TLS relay and
/// port-443 plaintext spy.
#[test]
fn static_relay_https_two_machines_coexist_with_zero_account_or_plaintext_leaks() {
    if std::env::var_os(HTTPS_SUBPROCESS_ENV).is_some() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_https_seam1_suite());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    write_tls_fixture(dir.path(), &["relay.invalid"]);

    let mut attempt = 0;
    let output = loop {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args([
            "--exact",
            "static_relay_https_two_machines_coexist_with_zero_account_or_plaintext_leaks",
            "--nocapture",
        ]);
        for k in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "SSL_CERT_DIR",
            "CUA_ENV_TOKEN",
            "CUA_RELAY_URL",
        ] {
            child.env_remove(k);
        }
        let out = child
            .env(HTTPS_SUBPROCESS_ENV, "1")
            .env(HTTPS_FIXTURE_ENV, dir.path())
            .env(HTTPS_PROXY_ADDR_ENV, addr.to_string())
            .env("SSL_CERT_FILE", dir.path().join("roots.pem"))
            .env("HTTPS_PROXY", format!("http://{addr}"))
            .env("HTTP_PROXY", format!("http://{addr}"))
            .env("NO_PROXY", "127.0.0.1,localhost")
            .output()
            .unwrap();
        attempt += 1;
        if out.status.success()
            || attempt >= 5
            || !String::from_utf8_lossy(&out.stderr).contains("AddrInUse")
        {
            break out;
        }
    };
    assert!(
        output.status.success(),
        "HTTPS Seam 1 subprocess failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn run_https_seam1_suite() {
    let fixture_dir = std::path::PathBuf::from(std::env::var_os(HTTPS_FIXTURE_ENV).unwrap());
    let proxy_addr = std::env::var(HTTPS_PROXY_ADDR_ENV).unwrap();

    // Two distinct cua-spacesd servers behind one HTTPS origin (`https://relay.invalid`).
    let srv_a = mock_machine(MACHINE_A, TOKEN_A).await;
    srv_a.state.advertise(&["presence"]);
    srv_a
        .state
        .offer_presence_datagrams(cua_spacesd_client::pb::PresenceDatagrams {
            endpoint: Some(cua_spacesd_client::pb::QuicEndpoint {
                port: 49999,
                certificate_sha256: "00".repeat(32),
                alpn: String::new(),
            }),
            ticket: "udp-ticket".into(),
            ..Default::default()
        });
    let srv_b = mock_machine(MACHINE_B, TOKEN_B).await;
    let srv_a_rotated = mock_machine(MACHINE_A, TOKEN_A_ROTATED).await;

    let router =
        StaticRelayRouter::start(&[(MACHINE_A, srv_a.addr), (MACHINE_B, srv_b.addr)]).await;
    let proxy =
        HttpsConnectProxy::bind(&proxy_addr, &fixture_dir, &[("relay.invalid", router.addr)]).await;

    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let udp_dial_calls = Arc::new(AtomicUsize::new(0));
    cua_spaces::presence::register_presence_datagrams(Arc::new(SpyPresenceDatagrams {
        connect_calls: udp_dial_calls.clone(),
    }));

    let home = tempfile::tempdir().unwrap();
    let build_spaces = || {
        Spaces::builder()
            .home(home.path())
            .probe_timeout(Duration::from_secs(5))
            .relay(RelayAccount::new(
                &account_spy_url,
                Arc::new(StaticToken("account-spy-bearer".into())),
            ))
            .build()
    };
    let spaces = build_spaces();

    let info_a = spaces
        .add(
            &format!("https://relay.invalid/m/{MACHINE_A}"),
            Some(TOKEN_A.into()),
            Some("alpha-box".into()),
        )
        .await
        .expect("machine A static relay add must succeed");
    assert_eq!(info_a.id, format!("relay:{MACHINE_A}"));
    assert_eq!(info_a.provider, Provider::Relay);
    assert_eq!(info_a.name, "alpha-box");
    assert!(info_a.added_at.is_some());

    let info_b = spaces
        .add(
            &format!("https://relay.invalid/m/{MACHINE_B}/"),
            Some(TOKEN_B.into()),
            None,
        )
        .await
        .expect("machine B static relay add must succeed");
    assert_eq!(info_b.id, format!("relay:{MACHINE_B}"));
    assert_eq!(info_b.provider, Provider::Relay);
    assert!(
        !info_b.name.contains("relay.invalid:443"),
        "{}",
        info_b.name
    );
    assert!(info_b.added_at.is_some());

    // Stored credentials match BYOC Static Relay format (`url` normalized, `token: Some`).
    for (machine, token) in [(MACHINE_A, TOKEN_A), (MACHINE_B, TOKEN_B)] {
        let cred = spaces
            .registry()
            .credential(&format!("relay:{machine}"))
            .unwrap()
            .expect("credential persisted");
        assert_eq!(
            cred.url.as_deref(),
            Some(format!("https://relay.invalid/m/{machine}").as_str())
        );
        assert_eq!(cred.token.as_deref(), Some(token));
    }

    let reloaded = build_spaces();
    assert_eq!(reloaded.list().unwrap().len(), 2);
    let id_a = SpaceId::Relay {
        machine_id: MACHINE_A.into(),
    };
    let id_b = SpaceId::Relay {
        machine_id: MACHINE_B.into(),
    };
    assert_eq!(
        reloaded.resolve(&format!("relay:{MACHINE_A}")).unwrap(),
        id_a
    );
    assert_eq!(reloaded.resolve(MACHINE_A).unwrap(), id_a);
    assert_eq!(reloaded.resolve("alpha-box").unwrap(), id_a);
    assert_eq!(
        reloaded
            .resolve(&format!("https://relay.invalid/m/{MACHINE_B}"))
            .unwrap(),
        id_b
    );
    assert_eq!(
        reloaded.find("alpha-box").await.unwrap().id,
        format!("relay:{MACHINE_A}")
    );
    assert_eq!(
        reloaded.find(MACHINE_B).await.unwrap().id,
        format!("relay:{MACHINE_B}")
    );

    let space_a = reloaded.space("alpha-box").await.unwrap();
    let space_b = reloaded.space(&format!("relay:{MACHINE_B}")).await.unwrap();
    assert_eq!(space_a.provider(), Provider::Relay);
    assert_eq!(space_b.provider(), Provider::Relay);
    assert_eq!(
        space_a.route().map(|r| r.transport()),
        Some(Transport::RelayHttps)
    );
    assert_bash(&space_a, "hello-alpha").await;
    assert_bash(&space_b, "hello-beta").await;

    // Presence skips LAN UDP datagrams for Static Relay Space (`Provider::Relay`).
    let presence = space_a
        .join_presence_with(
            PresenceIdentity {
                id: "user-1".into(),
                display_name: "Tester".into(),
                ..Default::default()
            },
            Duration::from_secs(5),
            true,
        )
        .await
        .unwrap();
    assert!(!presence.uses_datagrams());
    assert_eq!(udp_dial_calls.load(Ordering::SeqCst), 0);
    presence.leave().await.unwrap();

    // Rotate MACHINE_A token live via StaticRelayRouter + rename/remove MACHINE_B.
    router.set_route(MACHINE_A, srv_a_rotated.addr);
    let updated = reloaded
        .add(
            &format!("https://relay.invalid/m/{MACHINE_A}"),
            Some(TOKEN_A_ROTATED.into()),
            Some("alpha-rotated".into()),
        )
        .await
        .unwrap();
    assert_eq!(updated.id, format!("relay:{MACHINE_A}"));
    assert_eq!(updated.name, "alpha-rotated");
    assert_eq!(
        reloaded
            .registry()
            .credential(&format!("relay:{MACHINE_A}"))
            .unwrap()
            .unwrap()
            .token
            .as_deref(),
        Some(TOKEN_A_ROTATED)
    );
    assert_bash(
        &reloaded.space("alpha-rotated").await.unwrap(),
        "rotated-ok",
    )
    .await;

    let renamed = reloaded
        .rename(&format!("relay:{MACHINE_B}"), "beta-renamed")
        .await
        .unwrap();
    assert_eq!(renamed.shown_name(), "beta-renamed");
    reloaded
        .remove(&format!("relay:{MACHINE_B}"))
        .await
        .unwrap();
    assert_eq!(reloaded.list().unwrap().len(), 1);

    let paths = router.seen_paths();
    for (machine, token) in [(MACHINE_A, TOKEN_A), (MACHINE_B, TOKEN_B)] {
        assert!(
            paths.iter().any(|(p, a)| {
                p.starts_with(&format!("/m/{machine}/"))
                    && a.as_deref() == Some(&format!("Bearer {token}"))
            }),
            "expected Bearer token on /m/{machine}: {paths:?}"
        );
    }
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());
    assert!(
        proxy.leaks().is_empty(),
        "port-443 leaks: {:?}",
        proxy.leaks()
    );
}

#[tokio::test]
async fn plain_http_mcp_under_m_path_registers_as_direct_without_token() {
    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    // Case 1 & 2: `/m/tools/mcp` and `/m/mcp` register as `direct:` without a token.
    let mcp_short = McpTestServer::start("/m/tools").await.unwrap();
    let info_short = spaces
        .add(
            &format!("{}/m/tools/mcp", mcp_short.url),
            None,
            Some("mcp-short".into()),
        )
        .await
        .expect("plain MCP at /m/tools/mcp must succeed without token");
    assert_eq!(info_short.provider, Provider::Direct);
    assert!(info_short.id.starts_with("direct:"), "{}", info_short.id);
    assert_eq!(info_short.services, ["mcp"]);
    let (tools, _) = spaces
        .space("mcp-short")
        .await
        .unwrap()
        .list_tools(Some("mcp"))
        .await
        .unwrap();
    assert!(!tools.is_empty());

    let mcp_m = McpTestServer::start("/m").await.unwrap();
    let info_m = spaces
        .add(&format!("{}/m/mcp", mcp_m.url), None, Some("mcp-m".into()))
        .await
        .expect("plain MCP at /m/mcp must succeed without token");
    assert_eq!(info_m.provider, Provider::Direct);
    assert!(info_m.id.starts_with("direct:"), "{}", info_m.id);

    // Case 3: exact `/m/<valid-machine-id>` fails upfront without token/--service,
    // while `--service mcp` or a token falls back to `direct:` MCP.
    let mcp_exact = McpTestServer::start("").await.unwrap();
    let router = StaticRelayRouter::start(&[]).await;
    router.set_rewrite(
        "mcp-service-001",
        SocketAddr::from(([127, 0, 0, 1], mcp_exact.port())),
        "/mcp",
    );
    let exact_url = format!("{}/m/mcp-service-001", router.url());

    let err_no_tok = spaces.add(&exact_url, None, None).await.unwrap_err();
    assert_eq!(err_no_tok.tag(), "invalid_argument", "{err_no_tok}");
    assert!(
        err_no_tok.to_string().contains("--token")
            && err_no_tok.to_string().contains("CUA_ENV_TOKEN")
    );

    let info_svc = spaces
        .add_with_service(
            &exact_url,
            None,
            Some("mcp-exact-svc".into()),
            Some("mcp".into()),
        )
        .await
        .expect("plain MCP at /m/<valid-id> with explicit --service registers as direct");
    assert_eq!(info_svc.provider, Provider::Direct);
    assert_eq!(info_svc.id, format!("direct:{}", router.addr));
    assert_eq!(info_svc.services, ["mcp"]);

    let info_tok = spaces
        .add(
            &exact_url,
            Some("mcp-bearer-token".into()),
            Some("mcp-exact".into()),
        )
        .await
        .expect("plain MCP at /m/<valid-id> with token falls back to direct");
    assert_eq!(info_tok.provider, Provider::Direct);
    assert_eq!(info_tok.id, format!("direct:{}", router.addr));
    assert_eq!(info_tok.services, ["mcp"]);
    let (tools, _) = spaces
        .space("mcp-exact")
        .await
        .unwrap()
        .list_tools(Some("mcp"))
        .await
        .unwrap();
    assert!(!tools.is_empty());

    // Case 4: unreachable `/m/tools` without token propagates real transport error.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let err_dead = spaces
        .add(&format!("http://{dead_addr}/m/tools"), None, None)
        .await
        .unwrap_err();
    assert!(
        !err_dead
            .to_string()
            .contains("invalid Static Relay machine id"),
        "{err_dead}"
    );
    assert_ne!(err_dead.tag(), "invalid_argument", "{err_dead}");
    assert_eq!(account_spy.count(), 0);
}

#[tokio::test]
async fn upfront_rejections_missing_token_host_flag_and_malformed_machine_id_never_mutate_stores() {
    let (spy_origin, net_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(3))
        .build();

    for (url, tok) in [
        (format!("{spy_origin}/m/{MACHINE_A}"), None),
        (format!("{spy_origin}/m/{MACHINE_A}"), Some(String::new())),
        (format!("{spy_origin}/m/{MACHINE_A}"), Some("   ".into())),
        (format!("{spy_origin}/m/{MACHINE_B}/"), None),
    ] {
        let err = spaces.add(&url, tok, None).await.unwrap_err();
        assert_eq!(err.tag(), "invalid_argument", "{url}: {err}");
        let msg = err.to_string();
        assert!(
            msg.contains("--token") && msg.contains("CUA_ENV_TOKEN"),
            "{msg}"
        );
    }

    let err = spaces
        .add_direct_host(
            &format!("{spy_origin}/m/{MACHINE_A}"),
            Some(TOKEN_A.into()),
            Some("bad-host".into()),
        )
        .await
        .unwrap_err();
    assert_eq!(err.tag(), "invalid_argument", "{err}");
    assert!(
        err.to_string().contains("--host") && err.to_string().contains("Direct Host"),
        "{err}"
    );

    let too_long = "a".repeat(65);
    for bad_id in [
        "short",
        "UPPERCASE123",
        "-leading-dash",
        "trailing-dash-",
        "bad_under_score",
        too_long.as_str(),
    ] {
        let err = spaces
            .add(
                &format!("{spy_origin}/m/{bad_id}"),
                Some(TOKEN_A.into()),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.tag(), "invalid_argument", "{bad_id}: {err}");
        assert!(
            err.to_string().contains("[a-z0-9-]{8,64}"),
            "{bad_id}: {err}"
        );
    }

    let extra_err = spaces
        .add(
            &format!("{spy_origin}/m/{MACHINE_A}/mcp"),
            Some(TOKEN_A.into()),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(extra_err.tag(), "invalid_argument", "{extra_err}");
    assert!(
        extra_err
            .to_string()
            .contains("without extra path segments"),
        "{extra_err}"
    );

    assert_eq!(
        net_spy.count(),
        0,
        "upfront validation must make 0 connections: {:?}",
        net_spy.snapshot()
    );
    assert!(spaces.list().unwrap().is_empty());
    assert!(!spaces.registry().spaces_path().exists());
    assert!(!spaces.registry().credentials_path().exists());
    assert!(!spaces.registry().direct_hosts_path().exists());
}

#[tokio::test]
async fn direct_space_has_no_legacy_static_relay_branch() {
    let srv = mock_machine(MACHINE_A, TOKEN_A).await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(3))
        .build();

    let direct_id = format!("direct:{}", srv.addr);
    spaces
        .registry()
        .upsert(
            cua_proto::daemon::v1::Space {
                id: direct_id.clone(),
                name: "legacy-direct".into(),
                ..Default::default()
            },
            cua_spaces::registry::Credential {
                url: Some(format!("{}/m/{MACHINE_A}", srv.url())),
                token: Some(TOKEN_A.into()),
                ..Default::default()
            },
        )
        .unwrap();

    let space = spaces.space(&direct_id).await.unwrap();
    assert_eq!(space.provider(), Provider::Direct);
    assert_eq!(
        space.route().map(|r| r.transport()),
        Some(Transport::Direct)
    );
}
