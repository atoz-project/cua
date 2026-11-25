// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! End-to-end integration test for Static Relay Mode Spaces (`relay:<machine-id>`)
//! against a real in-process `cua-relay` (Static Token Mode, mesh enabled) and two
//! real in-process `cua-spacesd` server cores on `/m/<machine-id-1>` and
//! `/m/<machine-id-2>`, plus a plain HTTP MCP server under `/m` and an Account
//! Relay HTTP spy (`0` hits).

use std::sync::Arc;
use std::time::Duration;

use cua_host::StaticToken;
use cua_relay::mesh::MeshConfig;
use cua_relay::server::{Relay, RelayConfig};
use cua_sandbox_core::testing::McpTestServer;
use cua_spaces::{Provider, RelayAccount, SpaceId, SpaceInfo, Spaces};
use cua_spacesd_client::testing::HttpSpy;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const REG_TOKEN: &str = "e2e-static-relay-reg-token";
const MACHINE_1: &str = "e2e-static-mach-01";
const MACHINE_2: &str = "e2e-static-mach-02";
const TOKEN_1: &str = "e2e-spacesd-env-token-001";
const TOKEN_1_ROTATED: &str = "e2e-spacesd-env-token-001-rotated";
const TOKEN_2: &str = "e2e-spacesd-env-token-002";

async fn wait_add(spaces: &Spaces, url: &str, token: &str, name: &str) -> SpaceInfo {
    for _ in 0..80 {
        if let Ok(info) = spaces.add(url, Some(token.into()), Some(name.into())).await {
            return info;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {name} ({url}) to join real cua-relay");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_inproc_static_relay_and_two_spacesd_end_to_end() {
    // 1. Boot a real in-process cua-relay in Static Token Mode with mesh enabled.
    let relay = Relay::new(RelayConfig {
        tokens: vec![REG_TOKEN.into()],
        oidc: None,
        mesh: MeshConfig {
            enabled: true,
            relay: true,
            stun: Vec::new(),
        },
        ..RelayConfig::default()
    });
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let relay_http = format!("http://{relay_addr}");
    let relay_ws = format!("ws://{relay_addr}");
    let shutdown = CancellationToken::new();
    let relay_stop = shutdown.clone();
    tokio::spawn(async move {
        let _ = relay
            .serve(relay_listener, relay_stop.cancelled_owned())
            .await;
    });

    // 2. Boot two real in-process cua-spacesd server cores and join both onto the relay + mesh.
    let (mut srv1, srv2) = tokio::join!(
        cua_spaces_e2e::driver_with_token(TOKEN_1, |_| {}),
        cua_spaces_e2e::driver_with_token(TOKEN_2, |_| {}),
    );

    for (machine_id, srv) in [(MACHINE_1, &srv1), (MACHINE_2, &srv2)] {
        let mut join = cua_relay::client::JoinConfig::new(
            relay_ws.clone(),
            REG_TOKEN.into(),
            machine_id.into(),
            srv.addr,
        );
        join.heartbeat = Duration::from_secs(1);
        let mesh_cfg = srv.ctx.mesh_host_config(
            &relay_http,
            REG_TOKEN,
            None,
            machine_id,
            join.account.clone(),
            srv.addr,
        );
        tokio::spawn(cua_relay::client::run(join, shutdown.clone()));
        tokio::spawn(cua_spacesd_server::mesh_host::run(
            mesh_cfg,
            shutdown.clone(),
        ));
    }

    // 3. Account Relay spy (must receive 0 hits) + plain HTTP MCP server under `/m`.
    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let plain_mcp = McpTestServer::start("/m").await.unwrap();
    let plain_mcp_url = format!("{}/m/mcp", plain_mcp.url);

    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(8))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    // Wait concurrently for both real cua-spacesd machines to finish joining cua-relay.
    let url1 = format!("{relay_http}/m/{MACHINE_1}");
    let url2 = format!("{relay_http}/m/{MACHINE_2}");
    let (info1, info2) = tokio::join!(
        wait_add(&spaces, &url1, TOKEN_1, "real-one"),
        wait_add(&spaces, &url2, TOKEN_2, "real-two"),
    );
    assert_eq!(info1.id, format!("relay:{MACHINE_1}"));
    assert_eq!(info1.provider, Provider::Relay);
    assert_eq!(info1.name, "real-one");
    assert_eq!(info2.id, format!("relay:{MACHINE_2}"));
    assert_eq!(info2.provider, Provider::Relay);
    assert_eq!(info2.name, "real-two");

    // Plain HTTP MCP under `/m/mcp` registers as `direct:` without a token.
    let mcp_info = spaces
        .add(&plain_mcp_url, None, Some("plain-mcp".into()))
        .await
        .expect("plain HTTP MCP on /m/mcp must register as direct without token");
    assert_eq!(mcp_info.provider, Provider::Direct);
    assert!(mcp_info.id.starts_with("direct:"), "{}", mcp_info.id);
    let (mcp_tools, _) = spaces
        .space("plain-mcp")
        .await
        .unwrap()
        .list_tools(Some("mcp"))
        .await
        .unwrap();
    assert!(mcp_tools.iter().any(|t| t.name == "add"), "{mcp_tools:?}");

    // Multi-machine coexistence in list + reach + thread_home + real spacesd RPC execution.
    let listed = spaces.list().unwrap();
    assert_eq!(
        listed.len(),
        3,
        "expected 2 static relay + 1 mcp: {listed:?}"
    );
    assert!(listed.iter().any(|s| s.id == format!("relay:{MACHINE_1}")));
    assert!(listed.iter().any(|s| s.id == format!("relay:{MACHINE_2}")));

    let reach1 = spaces.reach(&format!("relay:{MACHINE_1}")).await;
    assert!(reach1.reachable && !reach1.listed_offline, "{reach1:?}");
    let reach2 = spaces.reach(&format!("relay:{MACHINE_2}")).await;
    assert!(reach2.reachable && !reach2.listed_offline, "{reach2:?}");

    assert!(matches!(
        spaces
            .thread_home(&format!("relay:{MACHINE_1}"))
            .await
            .unwrap(),
        cua_spaces::thread_route::ThreadHome::Here(None)
    ));

    let sp1 = spaces.space("real-one").await.unwrap();
    let sp2 = spaces.space("real-two").await.unwrap();
    srv1.confine(&sp1).await;
    srv2.confine(&sp2).await;

    let out1 = sp1
        .bash("echo from-real-spacesd-1", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        out1.render().contains("from-real-spacesd-1"),
        "{}",
        out1.render()
    );
    let out2 = sp2
        .bash("echo from-real-spacesd-2", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        out2.render().contains("from-real-spacesd-2"),
        "{}",
        out2.render()
    );

    // Live token rotation on machine 1: rotate server env token, verify old token fails,
    // re-add with rotated token, verify immediate RPC success while sibling machine 2 stays live.
    assert!(srv1.ctx.apply_file_token(Some(TOKEN_1_ROTATED)));
    srv1.token = TOKEN_1_ROTATED.into();
    assert!(
        spaces.add(&url1, Some(TOKEN_1.into()), None).await.is_err(),
        "revoked token must fail on re-add"
    );
    assert!(
        spaces.space("real-one").await.is_err(),
        "stale connection must be evicted after token revocation"
    );

    let rotated = spaces
        .add(&url1, Some(TOKEN_1_ROTATED.into()), None)
        .await
        .expect("re-add with rotated token must succeed against live cua-spacesd");
    assert_eq!(rotated.id, format!("relay:{MACHINE_1}"));
    assert_eq!(rotated.name, "real-one");

    let sp1_rot = spaces.space("real-one").await.unwrap();
    srv1.confine(&sp1_rot).await;
    let out1_rot = sp1_rot
        .bash("echo rotated-live-ok", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        out1_rot.render().contains("rotated-live-ok"),
        "{}",
        out1_rot.render()
    );

    // Isolated remove of machine 1 leaves sibling machine 2 intact and operational.
    let removed = spaces.remove(&format!("relay:{MACHINE_1}")).await.unwrap();
    assert_eq!(removed.id, format!("relay:{MACHINE_1}"));
    assert!(spaces.resolve("real-one").is_err());
    assert!(
        spaces
            .registry()
            .credential(&format!("relay:{MACHINE_1}"))
            .unwrap()
            .is_none()
    );
    assert!(spaces.is_static_relay_space(&SpaceId::Relay {
        machine_id: MACHINE_2.into(),
    }));
    let out2_after = spaces
        .space("real-two")
        .await
        .unwrap()
        .bash("echo sibling-still-alive", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        out2_after.render().contains("sibling-still-alive"),
        "{}",
        out2_after.render()
    );

    // Account Relay spy must have received ZERO requests across the entire E2E flow.
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 hits across real Static Relay E2E flow: {:?}",
        account_spy.snapshot()
    );

    shutdown.cancel();
}
