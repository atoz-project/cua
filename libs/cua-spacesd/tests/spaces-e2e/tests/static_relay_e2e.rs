// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! End-to-end integration test for Static Relay Mode Spaces (`relay:<machine-id>`)
//! against a real in-process `cua-relay` (Static Token Mode, mesh enabled) and two
//! real in-process `cua-spacesd` server cores on `/m/<machine-id-1>` and
//! `/m/<machine-id-2>`, plus a plain HTTP MCP `/m/tools` server and an Account
//! Relay HTTP spy (`0` hits).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cua_host::StaticToken;
use cua_relay::mesh::MeshConfig;
use cua_relay::server::{Relay, RelayConfig};
use cua_spaces::{Provider, RelayAccount, SpaceId, Spaces};
use cua_spaces_e2e::FakeTools;
use cua_spacesd_server::{ServerBuilder, ServerConfig, ServerContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const REG_TOKEN: &str = "e2e-static-relay-reg-token";
const MACHINE_1: &str = "e2e-static-mach-01";
const MACHINE_2: &str = "e2e-static-mach-02";
const TOKEN_1: &str = "e2e-spacesd-env-token-001";
const TOKEN_1_ROTATED: &str = "e2e-spacesd-env-token-001-rotated";
const TOKEN_2: &str = "e2e-spacesd-env-token-002";

#[derive(Default)]
struct AccountRelaySpy {
    requests: Mutex<Vec<String>>,
}

impl AccountRelaySpy {
    async fn start() -> (String, Arc<Self>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let spy = Arc::new(Self::default());
        let bg = spy.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let bg = bg.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let line = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    bg.requests.lock().unwrap().push(line);
                    let body = r#"{"error":"account relay must not be called"}"#;
                    let resp = format!(
                        "HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), spy)
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn snapshot(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

struct LiveSpacesd {
    addr: SocketAddr,
    ctx: ServerContext,
    home: std::path::PathBuf,
    bin: std::path::PathBuf,
    _dirs: Vec<tempfile::TempDir>,
}

async fn start_spacesd(token: &str) -> LiveSpacesd {
    let dirs: Vec<tempfile::TempDir> = (0..5).map(|_| tempfile::tempdir().unwrap()).collect();
    let canon = |d: &tempfile::TempDir| d.path().canonicalize().unwrap();
    let (data, downloads, teleport_home, home, bin) = (
        canon(&dirs[0]),
        canon(&dirs[1]),
        canon(&dirs[2]),
        canon(&dirs[3]),
        canon(&dirs[4]),
    );
    let config = ServerConfig {
        data_dir: data,
        downloads_dir: Some(downloads),
        teleport_home: Some(teleport_home.clone()),
        shutdown_grace: Duration::from_secs(1),
        ..ServerConfig::default()
    };
    let ctx = ServerContext::new(config, Some(token.into()));
    let receiver_host =
        Arc::new(cua_spacesd_teleport::FakeHost::new().with_home(teleport_home.clone()));
    let teleport = Arc::new(cua_spacesd_teleport::Receiver::with_host(
        teleport_home,
        receiver_host,
    ));
    let server = ServerBuilder::new(ctx.clone())
        .tools(Arc::new(FakeTools))
        .teleport_receiver(teleport)
        .build();
    let addr = cua_spacesd_server::spawn_local(server).await.unwrap();
    LiveSpacesd {
        addr,
        ctx,
        home,
        bin,
        _dirs: dirs,
    }
}

impl LiveSpacesd {
    async fn confine(&self, space: &cua_spaces::Space, token: &str) {
        let home = self.home.display().to_string();
        let vars = [
            ("HOME".to_string(), home),
            (
                "PATH".to_string(),
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.bin.display()),
            ),
        ];
        space
            .spacesd()
            .unwrap()
            .init(cua_spacesd_client::pb::InitRequest {
                token: token.into(),
                env: vars.into_iter().collect(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

/// Minimal Streamable HTTP MCP server mounted on `/m/tools` answering
/// `initialize`, `notifications/initialized`, and `tools/list`.
async fn start_plain_mcp_on_m_tools() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if head.len() > 16_384 || sock.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    head.push(b[0]);
                }
                let head_str = String::from_utf8_lossy(&head);
                let first = head_str.lines().next().unwrap_or_default();
                let path = first.split_whitespace().nth(1).unwrap_or_default();
                let content_len: usize = head_str
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; content_len];
                if content_len > 0 && sock.read_exact(&mut body).await.is_err() {
                    return;
                }
                if path != "/m/tools" {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    return;
                }
                let req: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let (status, resp_body) = match method {
                    "initialize" => (
                        "200 OK",
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "protocolVersion": "2025-03-26",
                                "capabilities": { "tools": {} },
                                "serverInfo": { "name": "e2e-plain-mcp", "version": "0.1.0" }
                            }
                        })
                        .to_string(),
                    ),
                    "notifications/initialized" => ("202 Accepted", String::new()),
                    "tools/list" => (
                        "200 OK",
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [{
                                    "name": "ping_tool",
                                    "description": "Plain MCP tool",
                                    "inputSchema": { "type": "object", "properties": {} }
                                }]
                            }
                        })
                        .to_string(),
                    ),
                    _ => (
                        "200 OK",
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "method not found" }
                        })
                        .to_string(),
                    ),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/m/tools")
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
    let srv1 = start_spacesd(TOKEN_1).await;
    let srv2 = start_spacesd(TOKEN_2).await;

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

    // 3. Account Relay spy (must receive 0 hits) + plain HTTP MCP server at /m/tools.
    let (account_spy_url, account_spy) = AccountRelaySpy::start().await;
    let plain_mcp_url = start_plain_mcp_on_m_tools().await;

    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(8))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    // Wait for both real cua-spacesd machines to finish joining the real cua-relay.
    let url1 = format!("{relay_http}/m/{MACHINE_1}");
    let url2 = format!("{relay_http}/m/{MACHINE_2}");

    let mut info1 = None;
    for _ in 0..80 {
        match spaces
            .add(&url1, Some(TOKEN_1.into()), Some("real-one".into()))
            .await
        {
            Ok(i) => {
                info1 = Some(i);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let info1 = info1.expect("machine 1 joined real cua-relay and registered");
    assert_eq!(info1.id, format!("relay:{MACHINE_1}"));
    assert_eq!(info1.provider, Provider::Relay);
    assert_eq!(info1.name, "real-one");

    let mut info2 = None;
    for _ in 0..80 {
        match spaces
            .add(&url2, Some(TOKEN_2.into()), Some("real-two".into()))
            .await
        {
            Ok(i) => {
                info2 = Some(i);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let info2 = info2.expect("machine 2 joined real cua-relay and registered");
    assert_eq!(info2.id, format!("relay:{MACHINE_2}"));
    assert_eq!(info2.provider, Provider::Relay);
    assert_eq!(info2.name, "real-two");

    // Plain HTTP MCP on /m/tools registers as direct: without a token.
    let mcp_info = spaces
        .add(&plain_mcp_url, None, Some("plain-mcp".into()))
        .await
        .expect("plain HTTP MCP on /m/tools must register as direct without token");
    assert_eq!(mcp_info.provider, Provider::Direct);
    assert!(mcp_info.id.starts_with("direct:"), "{}", mcp_info.id);
    let (mcp_tools, _) = spaces
        .space("plain-mcp")
        .await
        .unwrap()
        .list_tools(Some("mcp"))
        .await
        .unwrap();
    assert!(
        mcp_tools.iter().any(|t| t.name == "ping_tool"),
        "{mcp_tools:?}"
    );

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
    srv1.confine(&sp1, TOKEN_1).await;
    srv2.confine(&sp2, TOKEN_2).await;

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
    srv1.confine(&sp1_rot, TOKEN_1_ROTATED).await;
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
