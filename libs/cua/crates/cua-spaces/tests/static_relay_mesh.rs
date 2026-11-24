// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Static Token Mode WireGuard mesh pairing and per-machine forward eviction
//! tests for Static Relay Mode Spaces (`relay:<machine-id>`).

use cua_mesh::testing::FakeCoordinator;
use cua_mesh::{Mesh, MeshConfig, Mode, NodeKind, static_auth};
use cua_spaces::relay::StaticToken;
use cua_spaces::{RelayAccount, Spaces, Transport};
use cua_spacesd_client::testing::{HttpSpy, MockAuth, MockServer};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MACHINE_A: &str = "machine-alpha-01";
const MACHINE_B: &str = "machine-beta-002";
const TOKEN_A: &str = "static-relay-token-alpha-secret";
const TOKEN_A_ROTATED: &str = "static-relay-token-alpha-rotated";
const TOKEN_B: &str = "static-relay-token-beta-secret";

/// Starts a Static Token Mode mesh machine bridging `spacesd` streams to `up_v1`,
/// optionally switching token verification and upstream to `rotation` when its flag flips.
async fn start_mesh_machine(
    coord: &FakeCoordinator,
    dir: &Path,
    machine_id: &'static str,
    token_v1: &'static str,
    up_v1: SocketAddr,
    rotation: Option<(&'static str, SocketAddr, Arc<AtomicBool>)>,
) -> Mesh {
    let mut cfg = MeshConfig::new(
        coord.url.clone(),
        NodeKind::Machine,
        Some(dir.join(format!("{machine_id}.json"))),
        static_auth(vec![("x-cua-machine-id".into(), machine_id.into())]),
    );
    cfg.stun = vec![coord.stun.to_string()];
    cfg.approved_path = Some(dir.join(format!("{machine_id}-approved.json")));
    let verifier_rot = rotation.as_ref().map(|(tok, _, flag)| (*tok, flag.clone()));
    cfg.pair_verifier = Some(Arc::new(move |client, ts, proof| {
        let tok = match &verifier_rot {
            Some((tok_v2, flag)) if flag.load(Ordering::SeqCst) => *tok_v2,
            _ => token_v1,
        };
        cua_mesh::proto::verify_pair_proof(
            tok,
            machine_id,
            client,
            ts,
            proof,
            cua_mesh::proto::now_secs(),
        )
    }));
    let mesh = Mesh::start(cfg).await.unwrap();
    mesh.wait_ready(Duration::from_secs(10)).await.unwrap();
    let m = mesh.clone();
    let accept_rot = rotation.map(|(_, up, flag)| (up, flag));
    tokio::spawn(async move {
        while let Some(mut incoming) = m.accept().await {
            if incoming.header.service == "spacesd" {
                let upstream = match &accept_rot {
                    Some((up_v2, flag)) if flag.load(Ordering::SeqCst) => *up_v2,
                    _ => up_v1,
                };
                tokio::spawn(async move {
                    if let Ok(mut tcp) = TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut incoming.stream, &mut tcp).await;
                    }
                });
            }
        }
    });
    mesh
}

/// Fronts `/v1/info` (advertising mesh v1 + STUN) and splices `/v1/mesh/*` to
/// `coord`, standing in for a Static Token Mode `cua-relay` origin.
async fn start_static_mesh_relay(coord: &FakeCoordinator) -> String {
    let coord_addr: SocketAddr = coord.url.strip_prefix("http://").unwrap().parse().unwrap();
    let stun_str = coord.stun.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let relay_url = format!("http://{relay_addr}");
    tokio::spawn(async move {
        loop {
            let Ok((mut client_tcp, _)) = listener.accept().await else {
                break;
            };
            let stun_str = stun_str.clone();
            tokio::spawn(async move {
                let mut peek = vec![0u8; 4096];
                let Ok(n) = client_tcp.peek(&mut peek).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let head = String::from_utf8_lossy(&peek[..n]);
                let first_line = head.lines().next().unwrap_or_default();
                if first_line.starts_with("GET /v1/info ") {
                    let mut sink = vec![0u8; n];
                    let _ = client_tcp.read(&mut sink).await;
                    let body = serde_json::json!({
                        "account_auth": false,
                        "issuer": serde_json::Value::Null,
                        "mesh": { "stun": [stun_str], "version": 1 },
                        "public_url": format!("http://{relay_addr}"),
                        "state_writable": false,
                        "static_tokens": true,
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = client_tcp.write_all(resp.as_bytes()).await;
                    return;
                }
                if first_line.contains("/v1/mesh/") {
                    if let Ok(mut upstream) = TcpStream::connect(coord_addr).await {
                        let _ = tokio::io::copy_bidirectional(&mut client_tcp, &mut upstream).await;
                    }
                    return;
                }
                let _ = client_tcp
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    relay_url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_relay_mesh_enabled_pairs_and_dials_two_machines_without_account_relay() {
    let coord = FakeCoordinator::start(Mode::Static).await;
    let mesh_dir = tempfile::tempdir().unwrap();

    let srv_a = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: None,
    })
    .await;
    let srv_b = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: None,
    })
    .await;

    let _machine_a = start_mesh_machine(
        &coord,
        mesh_dir.path(),
        MACHINE_A,
        TOKEN_A,
        srv_a.addr,
        None,
    )
    .await;
    let _machine_b = start_mesh_machine(
        &coord,
        mesh_dir.path(),
        MACHINE_B,
        TOKEN_B,
        srv_b.addr,
        None,
    )
    .await;
    let relay_url = start_static_mesh_relay(&coord).await;

    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(8))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    let info_a = spaces
        .add(
            &format!("{relay_url}/m/{MACHINE_A}"),
            Some(TOKEN_A.into()),
            Some("mesh-alpha".into()),
        )
        .await
        .expect("machine A over static mesh must add");
    let info_b = spaces
        .add(
            &format!("{relay_url}/m/{MACHINE_B}"),
            Some(TOKEN_B.into()),
            Some("mesh-beta".into()),
        )
        .await
        .expect("machine B over static mesh must add");
    assert_eq!(info_a.id, format!("relay:{MACHINE_A}"));
    assert_eq!(info_b.id, format!("relay:{MACHINE_B}"));

    let space_a = spaces.space("mesh-alpha").await.unwrap();
    let space_b = spaces.space("mesh-beta").await.unwrap();
    assert_eq!(
        space_a.route().map(|r| r.transport()),
        Some(Transport::Mesh),
        "expected mesh transport for A, got {:?}",
        space_a.route()
    );
    assert_eq!(
        space_b.route().map(|r| r.transport()),
        Some(Transport::Mesh),
        "expected mesh transport for B, got {:?}",
        space_b.route()
    );
    assert!(
        space_a
            .bash("echo mesh-a", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("mesh-a")
    );
    assert!(
        space_b
            .bash("echo mesh-b", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("mesh-b")
    );
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 requests during Static Relay mesh ops: {:?}",
        account_spy.snapshot()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_relay_mesh_token_rotation_evicts_forward_without_affecting_sibling() {
    let coord = FakeCoordinator::start(Mode::Static).await;
    let mesh_dir = tempfile::tempdir().unwrap();

    let srv_a_v1 = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: None,
    })
    .await;
    let srv_a_v2 = MockServer::start(MockAuth {
        token: Some(TOKEN_A_ROTATED.into()),
        gateway: None,
        prefix: None,
    })
    .await;
    let srv_b = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: None,
    })
    .await;

    let rotated = Arc::new(AtomicBool::new(false));
    let _machine_a = start_mesh_machine(
        &coord,
        mesh_dir.path(),
        MACHINE_A,
        TOKEN_A,
        srv_a_v1.addr,
        Some((TOKEN_A_ROTATED, srv_a_v2.addr, rotated.clone())),
    )
    .await;
    let _machine_b = start_mesh_machine(
        &coord,
        mesh_dir.path(),
        MACHINE_B,
        TOKEN_B,
        srv_b.addr,
        None,
    )
    .await;
    let relay_url = start_static_mesh_relay(&coord).await;

    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(8))
        .build();

    spaces
        .add(
            &format!("{relay_url}/m/{MACHINE_A}"),
            Some(TOKEN_A.into()),
            Some("mesh-a".into()),
        )
        .await
        .unwrap();
    spaces
        .add(
            &format!("{relay_url}/m/{MACHINE_B}"),
            Some(TOKEN_B.into()),
            Some("mesh-b".into()),
        )
        .await
        .unwrap();

    let sa = spaces.space("mesh-a").await.unwrap();
    assert_eq!(sa.route().map(|r| r.transport()), Some(Transport::Mesh));
    assert!(
        sa.bash("echo a-v1", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("a-v1")
    );

    // Rotate MACHINE_A's token on the server; old token now fails on re-add AND evicts cache/forward.
    rotated.store(true, Ordering::SeqCst);
    assert!(
        spaces
            .add(
                &format!("{relay_url}/m/{MACHINE_A}"),
                Some(TOKEN_A.into()),
                None
            )
            .await
            .is_err()
    );
    assert!(
        spaces.space("mesh-a").await.is_err(),
        "old cached mesh forward/connection must be evicted after revocation"
    );

    // Re-add with rotated token: must evict old forward and succeed immediately over mesh.
    spaces
        .add(
            &format!("{relay_url}/m/{MACHINE_A}"),
            Some(TOKEN_A_ROTATED.into()),
            None,
        )
        .await
        .unwrap();
    let sa2 = spaces.space("mesh-a").await.unwrap();
    assert_eq!(sa2.route().map(|r| r.transport()), Some(Transport::Mesh));
    assert!(
        sa2.bash("echo a-v2", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("a-v2")
    );

    // Sibling MACHINE_B on the same static relay mesh must remain unaffected.
    let sb = spaces.space("mesh-b").await.unwrap();
    assert_eq!(sb.route().map(|r| r.transport()), Some(Transport::Mesh));
    assert!(
        sb.bash("echo b-still-ok", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("b-still-ok")
    );
}
