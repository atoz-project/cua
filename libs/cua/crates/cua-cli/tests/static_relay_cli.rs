// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Seam 1 CLI integration tests for Static Relay Mode Spaces (`cua spaces add`,
//! `cua spaces ls`, `cua sb exec`) against an HTTPS origin with two `cua-spacesd`
//! instances, a plain HTTP MCP `/m/...` server, an Account Relay HTTP spy, and a
//! port-443 plaintext TCP/HTTP spy.

mod common;

use base64::Engine;
use common::Home;
use cua_sandbox_core::testing::McpTestServer;
use cua_spacesd_client::testing::{MockAuth, MockServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MACHINE_A: &str = "cli-alpha-000001";
const MACHINE_B: &str = "cli-beta-0000002";
const TOKEN_A: &str = "cli-static-token-alpha-secret";
const TOKEN_A_ROTATED: &str = "cli-static-token-alpha-rotated";
const TOKEN_A_V3: &str = "cli-static-token-alpha-v3";
const TOKEN_B: &str = "cli-static-token-beta-secret";

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

fn pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn write_tls_fixture(dir: &Path, hosts: &[&str]) {
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let root = ca.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::new(ca, key);
    let leaf =
        rcgen::CertificateParams::new(hosts.iter().map(|h| (*h).to_string()).collect::<Vec<_>>())
            .unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    std::fs::write(dir.join("leaf.der"), leaf.der()).unwrap();
    std::fs::write(dir.join("key.der"), leaf_key.serialize_der()).unwrap();
    std::fs::write(dir.join("roots.pem"), pem(root.der())).unwrap();
}

async fn read_http_head(socket: &mut (impl AsyncRead + Unpin)) -> Option<String> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        if data.len() > 8192 {
            return None;
        }
        let mut b = [0u8; 1];
        if socket.read_exact(&mut b).await.is_err() {
            return None;
        }
        data.push(b[0]);
    }
    String::from_utf8(data).ok()
}

async fn start_static_router(routes: HashMap<String, SocketAddr>) -> SocketAddr {
    use http_body_util::BodyExt as _;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoServer;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        let client_h2: hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            tonic::body::Body,
        > = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http();
        let client_h1: hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            tonic::body::Body,
        > = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let routes = routes.clone();
            let client_h2 = client_h2.clone();
            let client_h1 = client_h1.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let routes = routes.clone();
                    let client_h2 = client_h2.clone();
                    let client_h1 = client_h1.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        if path == "/v1/info" {
                            let body = r#"{"account_auth":false,"issuer":null,"mesh":null,"public_url":"https://relay.invalid","state_writable":false,"static_tokens":true}"#;
                            return Ok::<_, std::convert::Infallible>(
                                http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(tonic::body::Body::new(
                                        http_body_util::Full::new(bytes::Bytes::from(body))
                                            .map_err(|never| match never {}),
                                    ))
                                    .unwrap(),
                            );
                        }
                        if let Some(rest) = path.strip_prefix("/m/") {
                            let (machine_id, _) = rest.split_once('/').unwrap_or((rest, ""));
                            if let Some(&upstream) = routes.get(machine_id) {
                                let pq = req
                                    .uri()
                                    .path_and_query()
                                    .map(|pq| pq.as_str())
                                    .unwrap_or(&path);
                                let uri: http::Uri =
                                    format!("http://{upstream}{pq}").parse().unwrap();
                                let is_h2 = req.version() == http::Version::HTTP_2;
                                let (parts, incoming_body) = req.into_parts();
                                let body = tonic::body::Body::new(
                                    incoming_body
                                        .map_err(|e| tonic::Status::internal(e.to_string())),
                                );
                                let mut fwd =
                                    http::Request::builder().method(parts.method).uri(uri);
                                if is_h2 {
                                    fwd = fwd.version(http::Version::HTTP_2);
                                }
                                for (k, v) in &parts.headers {
                                    if k != http::header::HOST {
                                        fwd = fwd.header(k, v);
                                    }
                                }
                                let fwd = fwd.body(body).unwrap();
                                let resp = if is_h2 {
                                    client_h2.request(fwd).await
                                } else {
                                    client_h1.request(fwd).await
                                };
                                if let Ok(r) = resp {
                                    let (rparts, rbody) = r.into_parts();
                                    let mapped = tonic::body::Body::new(
                                        rbody.map_err(|e| tonic::Status::internal(e.to_string())),
                                    );
                                    return Ok(http::Response::from_parts(rparts, mapped));
                                }
                            }
                        }
                        Ok(http::Response::builder()
                            .status(404)
                            .body(tonic::body::Body::new(
                                http_body_util::Full::new(bytes::Bytes::from("not found"))
                                    .map_err(|never| match never {}),
                            ))
                            .unwrap())
                    }
                });
                let _ = AutoServer::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn cli_static_relay_add_ls_sb_exec_and_rejections_zero_leaks() {
    let srv_a = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_b = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_B}")),
    })
    .await;

    let mut routes = HashMap::new();
    routes.insert(MACHINE_A.to_string(), srv_a.addr);
    routes.insert(MACHINE_B.to_string(), srv_b.addr);
    let router_addr = start_static_router(routes).await;

    let tls_dir = tempfile::tempdir().unwrap();
    write_tls_fixture(tls_dir.path(), &["relay.invalid"]);
    let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![
            std::fs::read(tls_dir.path().join("leaf.der"))
                .unwrap()
                .into(),
        ],
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            std::fs::read(tls_dir.path().join("key.der")).unwrap(),
        )
        .into(),
    )
    .unwrap();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    let plaintext_leaks = Arc::new(Mutex::new(Vec::<String>::new()));
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let leaks_bg = plaintext_leaks.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = proxy.accept().await else {
                break;
            };
            let tls_cfg = tls_cfg.clone();
            let leaks = leaks_bg.clone();
            tokio::spawn(async move {
                let Some(head) = read_http_head(&mut socket).await else {
                    return;
                };
                if !head.starts_with("CONNECT relay.invalid:443 ") {
                    leaks.lock().unwrap().push(head);
                    let _ = socket
                        .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
                        .await;
                    return;
                }
                if socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    return;
                }
                let Ok(hello) = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    socket,
                )
                .await
                else {
                    leaks
                        .lock()
                        .unwrap()
                        .push("non-TLS bytes on port-443 tunnel".into());
                    return;
                };
                assert_eq!(hello.client_hello().server_name(), Some("relay.invalid"));
                let Ok(mut tls_stream) = hello.into_stream(tls_cfg).await else {
                    return;
                };
                if let Ok(mut upstream) = TcpStream::connect(router_addr).await {
                    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await;
                }
            });
        }
    });

    let (account_spy_url, account_spy) = AccountRelaySpy::start().await;

    let mut home = Home::new();
    home.set(
        "SSL_CERT_FILE",
        tls_dir.path().join("roots.pem").display().to_string(),
    );
    home.set("HTTPS_PROXY", format!("http://{proxy_addr}"));
    home.set("HTTP_PROXY", format!("http://{proxy_addr}"));
    home.set("NO_PROXY", "127.0.0.1,localhost");
    home.set("CUA_RELAY_URL", &account_spy_url);

    // Seed a valid stored account auth session so ANY accidental Account Relay lookup
    // in `cua sb` or `cua spaces add` fires against `account_spy` instead of being skipped!
    std::fs::create_dir_all(home.cua_home()).unwrap();
    std::fs::write(
        home.cua_home().join("credentials.json"),
        r#"{"access_token":"spy-account-jwt","refresh_token":null,"expires_at":"2099-01-01T00:00:00Z","token_type":"Bearer"}"#,
    )
    .unwrap();

    let missing_tok = home
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
        ])
        .await;
    assert_ne!(missing_tok.code, 0, "{missing_tok:?}");
    assert!(
        missing_tok.stderr.contains("--token") && missing_tok.stderr.contains("CUA_ENV_TOKEN"),
        "{missing_tok:?}"
    );
    let mut home_blank_tok = Home::new();
    home_blank_tok.env = home.env.clone();
    home_blank_tok.set("CUA_ENV_TOKEN", "   ");
    let blank_tok = home_blank_tok
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
        ])
        .await;
    assert_ne!(blank_tok.code, 0, "{blank_tok:?}");
    assert!(
        blank_tok.stderr.contains("--token") && blank_tok.stderr.contains("CUA_ENV_TOKEN"),
        "{blank_tok:?}"
    );
    assert!(!home.cua_home().join("spaces.json").exists());

    let bad_host = home
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
            "--host",
            "--token",
            TOKEN_A,
        ])
        .await;
    assert_ne!(bad_host.code, 0, "{bad_host:?}");
    assert!(bad_host.stderr.contains("--host"), "{bad_host:?}");
    assert!(!home.cua_home().join("spaces.json").exists());
    assert!(!home.cua_home().join("direct-hosts.json").exists());

    let bad_id = home
        .run(&[
            "--embedded",
            "spaces",
            "add",
            "https://relay.invalid/m/BAD_ID",
            "--token",
            TOKEN_A,
        ])
        .await;
    assert_ne!(bad_id.code, 0, "{bad_id:?}");
    assert!(bad_id.stderr.contains("[a-z0-9-]{8,64}"), "{bad_id:?}");
    assert!(!home.cua_home().join("spaces.json").exists());

    let added_a = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_A}"),
            "--token",
            TOKEN_A,
            "--name",
            "alpha-cli",
        ])
        .await;
    let json_a = added_a.ok().json();
    assert_eq!(json_a["id"], format!("relay:{MACHINE_A}"));
    assert_eq!(json_a["name"], "alpha-cli");
    assert_eq!(json_a["provider"], "relay");

    let mut home_env_tok = Home::new();
    home_env_tok.env = home.env.clone();
    home_env_tok.set("CUA_ENV_TOKEN", TOKEN_B);
    let added_b = home_env_tok
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("https://relay.invalid/m/{MACHINE_B}"),
            "--name",
            "beta-cli",
        ])
        .await;
    let json_b = added_b.ok().json();
    assert_eq!(json_b["id"], format!("relay:{MACHINE_B}"));
    assert_eq!(json_b["name"], "beta-cli");
    assert_eq!(json_b["provider"], "relay");

    let mcp = McpTestServer::start("/m/tools").await.unwrap();
    let added_mcp = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("{}/m/tools/mcp", mcp.url),
            "--name",
            "mcp-cli",
        ])
        .await;
    let json_mcp = added_mcp.ok().json();
    assert_eq!(json_mcp["provider"], "direct");
    assert!(json_mcp["id"].as_str().unwrap().starts_with("direct:"));

    let exec_qualified = home
        .run(&[
            "--embedded",
            "sb",
            "exec",
            &format!("relay:{MACHINE_A}"),
            "echo",
            "from-qualified",
        ])
        .await;
    exec_qualified.ok();
    assert!(
        exec_qualified.stdout.contains("from-qualified"),
        "{exec_qualified:?}"
    );

    let exec_bare_id = home
        .run(&[
            "--embedded",
            "sb",
            "exec",
            MACHINE_B,
            "echo",
            "from-bare-id",
        ])
        .await;
    exec_bare_id.ok();
    assert!(
        exec_bare_id.stdout.contains("from-bare-id"),
        "{exec_bare_id:?}"
    );

    let exec_name = home
        .run(&["--embedded", "sb", "exec", "alpha-cli", "echo", "from-name"])
        .await;
    exec_name.ok();
    assert!(exec_name.stdout.contains("from-name"), "{exec_name:?}");

    std::fs::remove_file(home.cua_home().join("credentials.json")).unwrap();
    let ls = home.run(&["--json", "spaces", "ls", "--no-size"]).await;
    let ls_json = ls.ok().json();
    let ids: Vec<&str> = ls_json["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert!(
        ids.contains(&format!("relay:{MACHINE_A}").as_str()),
        "{ids:?}"
    );
    assert!(
        ids.contains(&format!("relay:{MACHINE_B}").as_str()),
        "{ids:?}"
    );
    assert!(ids.iter().any(|id| id.starts_with("direct:")), "{ids:?}");

    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 requests during Static Relay CLI add/ls/sb exec: {:?}",
        account_spy.snapshot()
    );
    assert!(
        plaintext_leaks.lock().unwrap().is_empty(),
        "Port-443 plaintext spy caught plaintext HTTP leaks: {:?}",
        plaintext_leaks.lock().unwrap()
    );
}

#[tokio::test]
async fn cli_static_relay_rotation_rm_isolation_share_refusal_and_relay_register_non_regression() {
    let srv_a_v1 = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_a_v2 = MockServer::start(MockAuth {
        token: Some(TOKEN_A_ROTATED.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_a_v3 = MockServer::start(MockAuth {
        token: Some(TOKEN_A_V3.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_b = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_B}")),
    })
    .await;

    let mut routes_1 = HashMap::new();
    routes_1.insert(MACHINE_A.to_string(), srv_a_v1.addr);
    routes_1.insert(MACHINE_B.to_string(), srv_b.addr);
    let router_1 = start_static_router(routes_1).await;

    let mut routes_2_v2 = HashMap::new();
    routes_2_v2.insert(MACHINE_A.to_string(), srv_a_v2.addr);
    let router_2_v2 = start_static_router(routes_2_v2).await;

    let mut routes_2_v3 = HashMap::new();
    routes_2_v3.insert(MACHINE_A.to_string(), srv_a_v3.addr);
    let router_2_v3 = start_static_router(routes_2_v3).await;

    let active_v3 = Arc::new(AtomicBool::new(false));

    let tls_dir = tempfile::tempdir().unwrap();
    write_tls_fixture(tls_dir.path(), &["relay.invalid", "relay2.invalid"]);
    let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![
            std::fs::read(tls_dir.path().join("leaf.der"))
                .unwrap()
                .into(),
        ],
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            std::fs::read(tls_dir.path().join("key.der")).unwrap(),
        )
        .into(),
    )
    .unwrap();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    let plaintext_leaks = Arc::new(Mutex::new(Vec::<String>::new()));
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let leaks_bg = plaintext_leaks.clone();
    let active_v3_bg = active_v3.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = proxy.accept().await else {
                break;
            };
            let tls_cfg = tls_cfg.clone();
            let leaks = leaks_bg.clone();
            let active_v3_bg = active_v3_bg.clone();
            tokio::spawn(async move {
                let Some(head) = read_http_head(&mut socket).await else {
                    return;
                };
                let is_relay1 = head.starts_with("CONNECT relay.invalid:443 ");
                let is_relay2 = head.starts_with("CONNECT relay2.invalid:443 ");
                if !is_relay1 && !is_relay2 {
                    leaks.lock().unwrap().push(head);
                    let _ = socket
                        .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
                        .await;
                    return;
                }
                if socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    return;
                }
                let Ok(hello) = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    socket,
                )
                .await
                else {
                    leaks
                        .lock()
                        .unwrap()
                        .push("non-TLS bytes on port-443 tunnel".into());
                    return;
                };
                let Ok(mut tls_stream) = hello.into_stream(tls_cfg).await else {
                    return;
                };
                let target = if is_relay1 {
                    router_1
                } else if active_v3_bg.load(Ordering::SeqCst) {
                    router_2_v3
                } else {
                    router_2_v2
                };
                if let Ok(mut upstream) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await;
                }
            });
        }
    });

    let (account_spy_url, account_spy) = AccountRelaySpy::start().await;

    let mut home = Home::new();
    home.set(
        "SSL_CERT_FILE",
        tls_dir.path().join("roots.pem").display().to_string(),
    );
    home.set("HTTPS_PROXY", format!("http://{proxy_addr}"));
    home.set("HTTP_PROXY", format!("http://{proxy_addr}"));
    home.set("NO_PROXY", "127.0.0.1,localhost");
    home.set("CUA_RELAY_URL", &account_spy_url);

    // Seed valid account auth so any accidental Account Relay call hits `account_spy`.
    std::fs::create_dir_all(home.cua_home()).unwrap();
    std::fs::write(
        home.cua_home().join("credentials.json"),
        r#"{"access_token":"spy-account-jwt","refresh_token":null,"expires_at":"2099-01-01T00:00:00Z","token_type":"Bearer"}"#,
    )
    .unwrap();

    home.run(&[
        "--embedded",
        "--json",
        "spaces",
        "add",
        &format!("https://relay.invalid/m/{MACHINE_A}"),
        "--token",
        TOKEN_A,
        "--name",
        "alpha-cli",
    ])
    .await
    .ok();
    home.run(&[
        "--embedded",
        "--json",
        "spaces",
        "add",
        &format!("https://relay.invalid/m/{MACHINE_B}"),
        "--token",
        TOKEN_B,
        "--name",
        "beta-cli",
    ])
    .await
    .ok();

    // Rename alpha-cli -> alpha-renamed.
    home.run(&[
        "--embedded",
        "spaces",
        "rename",
        &format!("relay:{MACHINE_A}"),
        "alpha-renamed",
    ])
    .await
    .ok();

    // Rotate URL (`relay2.invalid`) and token WITHOUT `--name`: preserves stored name + display_name.
    let rot_no_name = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("https://relay2.invalid/m/{MACHINE_A}"),
            "--token",
            TOKEN_A_ROTATED,
        ])
        .await
        .ok()
        .json();
    assert_eq!(rot_no_name["id"], format!("relay:{MACHINE_A}"));
    assert_eq!(rot_no_name["name"], "alpha-cli");
    assert_eq!(rot_no_name["display_name"], "alpha-renamed");

    let exec_rot = home
        .run(&[
            "--embedded",
            "sb",
            "exec",
            "alpha-renamed",
            "echo",
            "rotated-url-ok",
        ])
        .await;
    exec_rot.ok();
    assert!(exec_rot.stdout.contains("rotated-url-ok"), "{exec_rot:?}");

    // Re-add WITH explicit `--name`: updates name and clears stale `display_name`.
    let rot_named = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &format!("https://relay2.invalid/m/{MACHINE_A}"),
            "--token",
            TOKEN_A_ROTATED,
            "--name",
            "alpha-final",
        ])
        .await
        .ok()
        .json();
    assert_eq!(rot_named["name"], "alpha-final");
    assert_eq!(rot_named["display_name"], "");

    // Revoke TOKEN_A_ROTATED on relay2.invalid -> old token fails on `cua sb exec` and `cua spaces add`.
    active_v3.store(true, Ordering::SeqCst);
    let revoked_exec = home
        .run(&["--embedded", "sb", "exec", "alpha-final", "echo", "revoked"])
        .await;
    assert_ne!(
        revoked_exec.code, 0,
        "revoked token must fail on cua sb exec: {revoked_exec:?}"
    );
    let revoked_add = home
        .run(&[
            "--embedded",
            "spaces",
            "add",
            &format!("https://relay2.invalid/m/{MACHINE_A}"),
            "--token",
            TOKEN_A_ROTATED,
        ])
        .await;
    assert_ne!(
        revoked_add.code, 0,
        "re-add with revoked token must fail: {revoked_add:?}"
    );

    // Rotate to TOKEN_A_V3 -> very next `cua sb exec` immediately succeeds.
    home.run(&[
        "--embedded",
        "--json",
        "spaces",
        "add",
        &format!("https://relay2.invalid/m/{MACHINE_A}"),
        "--token",
        TOKEN_A_V3,
    ])
    .await
    .ok();
    let exec_v3 = home
        .run(&[
            "--embedded",
            "sb",
            "exec",
            "alpha-final",
            "echo",
            "v3-cli-ok",
        ])
        .await;
    exec_v3.ok();
    assert!(exec_v3.stdout.contains("v3-cli-ok"), "{exec_v3:?}");

    for args in [
        vec![
            "--embedded",
            "spaces",
            "share",
            "alpha-final",
            "bob@example.com",
            "--yes",
        ],
        vec![
            "--embedded",
            "spaces",
            "share",
            "alpha-final",
            "team:Design Team",
            "--yes",
        ],
        vec![
            "--embedded",
            "spaces",
            "unshare",
            "alpha-final",
            "bob@example.com",
        ],
        vec!["--embedded", "spaces", "unshare", "alpha-final", "--all"],
        vec!["--embedded", "spaces", "shares", "alpha-final"],
    ] {
        let out = home.run(&args).await;
        assert_ne!(out.code, 0, "sharing op {args:?} must fail: {out:?}");
        assert!(
            out.stderr.contains("Static Relay") && out.stderr.contains("Account Relay"),
            "sharing op {args:?} must explain Static Relay vs Account Relay Mode: {out:?}"
        );
    }

    let rm_a = home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "rm",
            &format!("relay:{MACHINE_A}"),
        ])
        .await;
    let rm_json = rm_a.ok().json();
    assert_eq!(rm_json["removed"]["id"], format!("relay:{MACHINE_A}"));

    // Sibling MACHINE_B remains completely untouched.
    let exec_b = home
        .run(&[
            "--embedded",
            "sb",
            "exec",
            "beta-cli",
            "echo",
            "sibling-alive",
        ])
        .await;
    exec_b.ok();
    assert!(exec_b.stdout.contains("sibling-alive"), "{exec_b:?}");

    // Removing MACHINE_A a second time fails (NotFound) and does not touch MACHINE_B.
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 hits across add/rotate/rename/share/unshare/shares/rm: {:?}",
        account_spy.snapshot()
    );
    assert!(
        plaintext_leaks.lock().unwrap().is_empty(),
        "Port-443 plaintext spy caught plaintext HTTP leaks: {:?}",
        plaintext_leaks.lock().unwrap()
    );

    // Verify no duplicates remained, stale `alpha-renamed` does not resolve, and only MACHINE_B is listed.
    std::fs::remove_file(home.cua_home().join("credentials.json")).unwrap();
    let stale_exec = home
        .run(&["--embedded", "sb", "exec", "alpha-renamed", "echo", "stale"])
        .await;
    assert_ne!(
        stale_exec.code, 0,
        "stale display_name must not resolve after --name update: {stale_exec:?}"
    );
    let rm_again = home
        .run(&["--embedded", "spaces", "rm", &format!("relay:{MACHINE_A}")])
        .await;
    assert_ne!(
        rm_again.code, 0,
        "second rm of already-removed relay space must fail: {rm_again:?}"
    );
    let ls = home.run(&["--json", "spaces", "ls", "--no-size"]).await;
    let ls_json = ls.ok().json();
    let ids: Vec<&str> = ls_json["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert_eq!(ids, vec![format!("relay:{MACHINE_B}")]);

    let fake_relay = cua_host::testing::FakeRelay::start().await;
    fake_relay.add_account("ada-token", "ada", Some("ada@example.com"));
    let direct_srv = MockServer::start(MockAuth::default()).await;
    direct_srv.state.advertise(&["relay_attach"]);
    let state = direct_srv.state.clone();
    let relay_bg = fake_relay.clone();
    tokio::spawn(async move {
        for _ in 0..400 {
            if let Some(a) = state.relay_attached.lock().unwrap().clone() {
                relay_bg.set_online(&a.machine_id, true, "0.1.0");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let mut acct_home = Home::new();
    acct_home.set("CUA_RELAY_URL", &fake_relay.url);
    std::fs::create_dir_all(acct_home.cua_home()).unwrap();
    std::fs::write(
        acct_home.cua_home().join("credentials.json"),
        r#"{"access_token":"ada-token","refresh_token":null,"expires_at":"2099-01-01T00:00:00Z","token_type":"Bearer"}"#,
    )
    .unwrap();

    let added_direct = acct_home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "add",
            &direct_srv.url(),
            "--name",
            "direct-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(added_direct["provider"], "direct");

    let reg = acct_home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "relay-register",
            "direct-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(reg["online"], true, "{reg}");
    assert!(
        reg["relay_space"].as_str().unwrap().starts_with("relay:"),
        "{reg}"
    );

    let unreg = acct_home
        .run(&[
            "--embedded",
            "--json",
            "spaces",
            "relay-unregister",
            "direct-cli",
        ])
        .await
        .ok()
        .json();
    assert_eq!(unreg["unregistered"], true, "{unreg}");
}

#[tokio::test]
async fn cli_static_relay_daemon_mode_and_offline_share_refusal_zero_account_hits() {
    const LOOPBACK: &str = if cfg!(unix) { "off" } else { "127.0.0.1:0" };

    let (account_spy_url, account_spy) = AccountRelaySpy::start().await;
    let srv = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let url = format!("{}/m/{MACHINE_A}", srv.url());

    let mut home = Home::new();
    home.set("CUA_RELAY_URL", &account_spy_url);
    home.set("CUA_DAEMON_NO_RELAY", "1");
    std::fs::create_dir_all(home.cua_home()).unwrap();
    std::fs::write(
        home.cua_home().join("credentials.json"),
        r#"{"access_token":"spy-account-jwt","refresh_token":null,"expires_at":"2099-01-01T00:00:00Z","token_type":"Bearer"}"#,
    )
    .unwrap();

    home.run(&[
        "--embedded",
        "--json",
        "spaces",
        "add",
        &url,
        "--token",
        TOKEN_A,
        "--name",
        "offline-alpha",
    ])
    .await
    .ok();

    // Stop the mock server so the Static Relay Space is genuinely offline.
    drop(srv);

    home.run(&["daemon", "start", "--loopback", LOOPBACK])
        .await
        .ok();

    let cases: &[&[&str]] = &[
        &["spaces", "share", "offline-alpha", "bob@example.com"],
        &[
            "spaces",
            "share",
            "offline-alpha",
            "bob@example.com",
            "--yes",
        ],
        &[
            "spaces",
            "share",
            "offline-alpha",
            "team:Design Team",
            "--yes",
        ],
        &["spaces", "unshare", "offline-alpha", "bob@example.com"],
        &["spaces", "unshare", "offline-alpha", "team:Design Team"],
        &["spaces", "unshare", "offline-alpha", "--all"],
        &["spaces", "shares", "offline-alpha"],
    ];

    let mut failures = Vec::new();
    for args in cases {
        let out = home.run(args).await;
        if out.code == 0
            || !out.stderr.contains("Static Relay")
            || !out.stderr.contains("Account Relay")
            || out.stderr.contains("stdin is not a terminal")
        {
            failures.push(format!("{args:?} -> {out:?}"));
        }
    }

    home.run(&["daemon", "stop"]).await.ok();

    assert!(
        failures.is_empty(),
        "daemon-mode offline share refusals failed:\n{}",
        failures.join("\n")
    );
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 hits in daemon mode for offline Static Relay share/unshare/shares: {:?}",
        account_spy.snapshot()
    );
}
