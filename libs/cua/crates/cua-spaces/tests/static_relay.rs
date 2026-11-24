// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Seam 1 integration tests for Static Relay Mode Spaces on `relay:<machine-id>`.
//!
//! Exercises:
//! - Two `cua-spacesd` instances on `/m/<id-1>` and `/m/<id-2>` behind one HTTPS origin
//!   (real TLS + ALPN h2 via `SSL_CERT_FILE` and a port-443 proxy/plaintext spy).
//! - Static Token Mode WireGuard mesh (`cua_mesh::Mode::Static`) pairing and dialing
//!   both machines behind one relay origin.
//! - Plain HTTP MCP servers mounted at `/m/...` registering as `direct:` without a token.
//! - Account Relay HTTP spy asserting 0 requests across Static Relay add/resolve/list/connect/rename/remove.
//! - Port-443 plaintext TCP/HTTP spy asserting 0 plaintext HTTP requests or bearer token leaks.
//! - Upfront rejections for missing/empty token, `--host` combination before store mutation,
//!   and malformed `<machine-id>` segments.

use base64::Engine;
use cua_mesh::testing::FakeCoordinator;
use cua_mesh::{Mesh, MeshConfig, Mode, NodeKind, static_auth};
use cua_sandbox_core::testing::McpTestServer;
use cua_spaces::presence::{Identity as PresenceIdentity, PresenceDatagrams};
use cua_spaces::relay::StaticToken;
use cua_spaces::{Provider, RelayAccount, SpaceId, Spaces, Transport};
use cua_spacesd_client::testing::{MockAuth, MockServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MACHINE_A: &str = "machine-alpha-01";
const MACHINE_B: &str = "machine-beta-002";
const TOKEN_A: &str = "static-relay-token-alpha-secret";
const TOKEN_A_ROTATED: &str = "static-relay-token-alpha-rotated";
const TOKEN_B: &str = "static-relay-token-beta-secret";

const HTTPS_SUBPROCESS_ENV: &str = "CUA_TEST_STATIC_RELAY_HTTPS";
const HTTPS_FIXTURE_ENV: &str = "CUA_TEST_STATIC_RELAY_FIXTURE";
const HTTPS_PROXY_ADDR_ENV: &str = "CUA_TEST_STATIC_RELAY_PROXY";

#[derive(Default)]
struct HttpSpy {
    requests: Mutex<Vec<String>>,
}

impl HttpSpy {
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

fn write_tls_fixture(dir: &Path, host: &str) {
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let root = ca.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::new(ca, key);
    let leaf = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
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

type SeenPaths = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Starts an in-process HTTP/2 + HTTP/1.1 router that dispatches `/m/<id>/...`
/// to the matching upstream `MockServer` while rejecting `/v1/machines` (Static
/// Token Mode relay has no Account Relay directory).
async fn start_static_path_router(
    routes: HashMap<String, SocketAddr>,
    mesh_info_coord: Option<String>,
    seen_paths: SeenPaths,
) -> SocketAddr {
    use http_body_util::BodyExt as _;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoServer;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        let client: hyper_util::client::legacy::Client<
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
            let mesh_info_coord = mesh_info_coord.clone();
            let seen_paths = seen_paths.clone();
            let client = client.clone();
            let client_h1 = client_h1.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let routes = routes.clone();
                    let mesh_info_coord = mesh_info_coord.clone();
                    let seen_paths = seen_paths.clone();
                    let client = client.clone();
                    let client_h1 = client_h1.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let auth = req
                            .headers()
                            .get(http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        seen_paths.lock().unwrap().push((path.clone(), auth));

                        if path == "/v1/info" {
                            let body = if mesh_info_coord.is_some() {
                                r#"{"account_auth":false,"issuer":null,"mesh":{"stun":[],"version":1},"public_url":"http://relay","state_writable":false,"static_tokens":true}"#
                            } else {
                                r#"{"account_auth":false,"issuer":null,"mesh":null,"public_url":"https://relay.invalid","state_writable":false,"static_tokens":true}"#
                            };
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
                                    client.request(fwd).await
                                } else {
                                    client_h1.request(fwd).await
                                };
                                match resp {
                                    Ok(r) => {
                                        let (parts, b) = r.into_parts();
                                        let mapped =
                                            tonic::body::Body::new(b.map_err(|e| {
                                                tonic::Status::internal(e.to_string())
                                            }));
                                        return Ok(http::Response::from_parts(parts, mapped));
                                    }
                                    Err(e) => {
                                        return Ok(http::Response::builder()
                                            .status(502)
                                            .body(tonic::body::Body::new(
                                                http_body_util::Full::new(bytes::Bytes::from(
                                                    e.to_string(),
                                                ))
                                                .map_err(|never| match never {}),
                                            ))
                                            .unwrap());
                                    }
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

struct SpyPresenceDatagrams {
    connect_calls: Arc<AtomicUsize>,
}

impl PresenceDatagrams for SpyPresenceDatagrams {
    fn connect<'a>(
        &'a self,
        _space: &'a cua_spaces::Space,
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
    write_tls_fixture(dir.path(), "relay.invalid");

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
    let srv_a = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
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

    let srv_b = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_B}")),
    })
    .await;

    let srv_a_rotated = MockServer::start(MockAuth {
        token: Some(TOKEN_A_ROTATED.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;

    let active_a = Arc::new(AtomicBool::new(false));
    let seen_relay_paths = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));

    // Route table: switchable upstream for MACHINE_A to test token rotation on re-add.
    let router_addr = {
        let mut routes = HashMap::new();
        routes.insert(MACHINE_A.to_string(), srv_a.addr);
        routes.insert(MACHINE_B.to_string(), srv_b.addr);
        start_static_path_router(routes, None, seen_relay_paths.clone()).await
    };
    let router_rotated_addr = {
        let mut routes = HashMap::new();
        routes.insert(MACHINE_A.to_string(), srv_a_rotated.addr);
        routes.insert(MACHINE_B.to_string(), srv_b.addr);
        start_static_path_router(routes, None, seen_relay_paths.clone()).await
    };

    // TLS config for `relay.invalid` with ALPN h2 + http/1.1.
    let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![std::fs::read(fixture_dir.join("leaf.der")).unwrap().into()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            std::fs::read(fixture_dir.join("key.der")).unwrap(),
        )
        .into(),
    )
    .unwrap();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    // Port-443 plaintext TCP/HTTP spy + HTTPS CONNECT proxy.
    let plaintext_leaks = Arc::new(Mutex::new(Vec::<String>::new()));
    let proxy = TcpListener::bind(&proxy_addr).await.unwrap();
    let leaks_bg = plaintext_leaks.clone();
    let active_a_bg = active_a.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = proxy.accept().await else {
                break;
            };
            let tls_cfg = tls_cfg.clone();
            let leaks = leaks_bg.clone();
            let active_a_bg = active_a_bg.clone();
            tokio::spawn(async move {
                let Some(head) = read_http_head(&mut socket).await else {
                    return;
                };
                if !head.starts_with("CONNECT relay.invalid:443 ") {
                    // Any plaintext HTTP request to port 443 or non-CONNECT traffic is a leak!
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
                        .push("non-TLS bytes sent on port-443 tunnel".into());
                    return;
                };
                assert_eq!(hello.client_hello().server_name(), Some("relay.invalid"));
                let Ok(mut tls_stream) = hello.into_stream(tls_cfg).await else {
                    return;
                };
                let target = if active_a_bg.load(Ordering::SeqCst) {
                    router_rotated_addr
                } else {
                    router_addr
                };
                if let Ok(mut upstream) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await;
                }
            });
        }
    });

    // Account Relay HTTP spy: MUST receive 0 requests across all Static Relay operations.
    let (account_spy_url, account_spy) = HttpSpy::start().await;

    // Spy PresenceDatagrams: MUST never be dialed for Static Relay Spaces (Provider::Relay).
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
    let cred_a = spaces
        .registry()
        .credential(&format!("relay:{MACHINE_A}"))
        .unwrap()
        .expect("cred A persisted");
    assert_eq!(
        cred_a.url.as_deref(),
        Some(format!("https://relay.invalid/m/{MACHINE_A}").as_str())
    );
    assert_eq!(cred_a.token.as_deref(), Some(TOKEN_A));

    let cred_b = spaces
        .registry()
        .credential(&format!("relay:{MACHINE_B}"))
        .unwrap()
        .expect("cred B persisted");
    assert_eq!(
        cred_b.url.as_deref(),
        Some(format!("https://relay.invalid/m/{MACHINE_B}").as_str())
    );
    assert_eq!(cred_b.token.as_deref(), Some(TOKEN_B));

    let reloaded = build_spaces();
    let listed = reloaded.list().unwrap();
    assert_eq!(listed.len(), 2, "both machines must coexist: {listed:?}");
    assert_eq!(
        reloaded.resolve(&format!("relay:{MACHINE_A}")).unwrap(),
        SpaceId::Relay {
            machine_id: MACHINE_A.into()
        }
    );
    assert_eq!(
        reloaded.resolve(MACHINE_A).unwrap(),
        SpaceId::Relay {
            machine_id: MACHINE_A.into()
        }
    );
    assert_eq!(
        reloaded.resolve("alpha-box").unwrap(),
        SpaceId::Relay {
            machine_id: MACHINE_A.into()
        }
    );
    assert_eq!(
        reloaded
            .resolve(&format!("https://relay.invalid/m/{MACHINE_B}"))
            .unwrap(),
        SpaceId::Relay {
            machine_id: MACHINE_B.into()
        }
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
    let out_a = space_a
        .bash("echo hello-alpha", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(out_a.render().contains("hello-alpha"), "{}", out_a.render());
    let out_b = space_b
        .bash("echo hello-beta", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(out_b.render().contains("hello-beta"), "{}", out_b.render());

    // Verify presence skips LAN UDP datagrams for Static Relay Space (`Provider::Relay`).
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
    assert_eq!(
        udp_dial_calls.load(Ordering::SeqCst),
        0,
        "Static Relay Space must skip LAN UDP presence datagrams"
    );
    presence.leave().await.unwrap();

    active_a.store(true, Ordering::SeqCst);
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
    let cred_a2 = reloaded
        .registry()
        .credential(&format!("relay:{MACHINE_A}"))
        .unwrap()
        .unwrap();
    assert_eq!(cred_a2.token.as_deref(), Some(TOKEN_A_ROTATED));
    let space_a2 = reloaded.space("alpha-rotated").await.unwrap();
    let out_a2 = space_a2
        .bash("echo rotated-ok", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        out_a2.render().contains("rotated-ok"),
        "{}",
        out_a2.render()
    );

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

    let paths = seen_relay_paths.lock().unwrap().clone();
    assert!(
        paths.iter().any(|(p, a)| {
            p.starts_with(&format!("/m/{MACHINE_A}/"))
                && a.as_deref() == Some(&format!("Bearer {TOKEN_A}"))
        }),
        "expected Bearer TOKEN_A on /m/{MACHINE_A}: {paths:?}"
    );
    assert!(
        paths.iter().any(|(p, a)| {
            p.starts_with(&format!("/m/{MACHINE_B}/"))
                && a.as_deref() == Some(&format!("Bearer {TOKEN_B}"))
        }),
        "expected Bearer TOKEN_B on /m/{MACHINE_B}: {paths:?}"
    );
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 requests during Static Relay ops, got: {:?}",
        account_spy.snapshot()
    );
    assert!(
        plaintext_leaks.lock().unwrap().is_empty(),
        "Port-443 plaintext spy detected leaks: {:?}",
        plaintext_leaks.lock().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_relay_mesh_enabled_pairs_and_dials_two_machines_without_account_relay() {
    let coord = FakeCoordinator::start(Mode::Static).await;
    let mesh_dir = tempfile::tempdir().unwrap();

    // Two mock spacesd servers bridged onto the Static Token Mode mesh coordinator.
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

    async fn start_mesh_machine(
        coord: &FakeCoordinator,
        dir: &Path,
        machine_id: &'static str,
        token: &'static str,
        upstream: SocketAddr,
    ) -> Mesh {
        let mut cfg = MeshConfig::new(
            coord.url.clone(),
            NodeKind::Machine,
            Some(dir.join(format!("{machine_id}.json"))),
            static_auth(vec![("x-cua-machine-id".into(), machine_id.into())]),
        );
        cfg.stun = vec![coord.stun.to_string()];
        cfg.approved_path = Some(dir.join(format!("{machine_id}-approved.json")));
        cfg.pair_verifier = Some(Arc::new(move |client, ts, proof| {
            cua_mesh::proto::verify_pair_proof(
                token,
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
        tokio::spawn(async move {
            while let Some(mut incoming) = m.accept().await {
                if incoming.header.service == "spacesd" {
                    tokio::spawn(async move {
                        if let Ok(mut tcp) = TcpStream::connect(upstream).await {
                            let _ =
                                tokio::io::copy_bidirectional(&mut incoming.stream, &mut tcp).await;
                        }
                    });
                }
            }
        });
        mesh
    }

    let _machine_a =
        start_mesh_machine(&coord, mesh_dir.path(), MACHINE_A, TOKEN_A, srv_a.addr).await;
    let _machine_b =
        start_mesh_machine(&coord, mesh_dir.path(), MACHINE_B, TOKEN_B, srv_b.addr).await;

    // Front `/v1/info` (advertising mesh v1) + `/v1/mesh/connect` (spliced to FakeCoordinator)
    // behind one Static Token Mode relay origin.
    let coord_addr: SocketAddr = coord.url.strip_prefix("http://").unwrap().parse().unwrap();
    let stun_str = coord.stun.to_string();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let relay_url = format!("http://{relay_addr}");
    tokio::spawn(async move {
        loop {
            let Ok((mut client_tcp, _)) = relay_listener.accept().await else {
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

#[tokio::test]
async fn static_relay_rotation_updates_url_token_name_and_evicts_cached_connections() {
    let (account_spy_url, account_spy) = HttpSpy::start().await;

    // Two distinct static relay servers (simulating URL rotation) and a rotated-token
    // replacement on server 2 (simulating live token revocation + rotation).
    let srv_v1 = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_v2 = MockServer::start(MockAuth {
        token: Some(TOKEN_A_ROTATED.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let srv_v3 = MockServer::start(MockAuth {
        token: Some("static-relay-token-alpha-v3".into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;

    // Switchable backend behind relay_2 so we can revoke TOKEN_A_ROTATED on the same URL.
    let active_v3 = Arc::new(AtomicBool::new(false));
    let seen_paths = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let relay_2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_2_addr = relay_2_listener.local_addr().unwrap();
    let active_v3_bg = active_v3.clone();
    let seen_bg = seen_paths.clone();
    let v2_addr = srv_v2.addr;
    let v3_addr = srv_v3.addr;
    tokio::spawn(async move {
        loop {
            let Ok((mut client_tcp, _)) = relay_2_listener.accept().await else {
                break;
            };
            let target = if active_v3_bg.load(Ordering::SeqCst) {
                v3_addr
            } else {
                v2_addr
            };
            let seen_bg = seen_bg.clone();
            tokio::spawn(async move {
                let mut peek = vec![0u8; 512];
                if let Ok(n) = client_tcp.peek(&mut peek).await {
                    let head = String::from_utf8_lossy(&peek[..n]);
                    seen_bg.lock().unwrap().push((
                        format!("relay2->{target}"),
                        head.lines().next().map(str::to_string),
                    ));
                }
                if let Ok(mut upstream) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut client_tcp, &mut upstream).await;
                }
            });
        }
    });

    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    let url_1 = format!("{}/m/{MACHINE_A}", srv_v1.url());
    let url_2 = format!("http://{relay_2_addr}/m/{MACHINE_A}");

    // Initial registration with explicit name + warm connection cache.
    let initial = spaces
        .add(&url_1, Some(TOKEN_A.into()), Some("alpha-initial".into()))
        .await
        .unwrap();
    assert_eq!(initial.id, format!("relay:{MACHINE_A}"));
    assert_eq!(initial.name, "alpha-initial");

    let s1 = spaces.space("alpha-initial").await.unwrap();
    assert!(
        s1.bash("echo v1", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("v1")
    );

    // Rename sets `meta.display_name`.
    let renamed = spaces
        .rename(&format!("relay:{MACHINE_A}"), "alpha-renamed")
        .await
        .unwrap();
    assert_eq!(renamed.shown_name(), "alpha-renamed");
    assert_eq!(renamed.display_name, "alpha-renamed");

    // Rotate URL + token WITHOUT passing `--name`: existing name + display_name must stay intact,
    // no duplicate record created, and cached connection to url_1 must be replaced immediately.
    let rotated_no_name = spaces
        .add(&url_2, Some(TOKEN_A_ROTATED.into()), None)
        .await
        .unwrap();
    assert_eq!(rotated_no_name.id, format!("relay:{MACHINE_A}"));
    assert_eq!(
        rotated_no_name.name, "alpha-initial",
        "re-add without --name must preserve existing stored name instead of clobbering it"
    );
    assert_eq!(
        rotated_no_name.display_name, "alpha-renamed",
        "re-add without --name must preserve existing display_name"
    );
    assert_eq!(spaces.list().unwrap().len(), 1);
    let cred2 = spaces
        .registry()
        .credential(&format!("relay:{MACHINE_A}"))
        .unwrap()
        .unwrap();
    assert_eq!(cred2.url.as_deref(), Some(url_2.as_str()));
    assert_eq!(cred2.token.as_deref(), Some(TOKEN_A_ROTATED));

    // Very next SDK call must hit relay_2 (not cached srv_v1).
    let s2 = spaces.space("alpha-renamed").await.unwrap();
    assert!(
        s2.bash("echo v2", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("v2")
    );
    assert!(
        !seen_paths.lock().unwrap().is_empty(),
        "next SDK call must route to rotated relay_2 URL"
    );

    // Now re-add WITH explicit `--name`: must update stored name AND clear stale display_name.
    let rotated_named = spaces
        .add(
            &url_2,
            Some(TOKEN_A_ROTATED.into()),
            Some("alpha-final".into()),
        )
        .await
        .unwrap();
    assert_eq!(rotated_named.name, "alpha-final");
    assert_eq!(rotated_named.display_name, "");
    assert_eq!(rotated_named.shown_name(), "alpha-final");
    assert_eq!(spaces.list().unwrap().len(), 1);
    assert!(
        spaces.resolve("alpha-renamed").is_err(),
        "stale display_name must no longer resolve after explicit --name update"
    );
    assert_eq!(
        spaces.resolve("alpha-final").unwrap(),
        SpaceId::Relay {
            machine_id: MACHINE_A.into()
        }
    );

    // Revoke TOKEN_A_ROTATED on relay_2 (only v3 token is accepted now).
    // Attempting to re-add with the revoked token must fail AND evict the stale cached connection
    // so a subsequent `spaces.space(...)` fails instead of reusing the pre-revocation connection.
    active_v3.store(true, Ordering::SeqCst);
    let revoked_err = spaces
        .add(&url_2, Some(TOKEN_A_ROTATED.into()), None)
        .await
        .unwrap_err();
    assert_ne!(revoked_err.tag(), "", "{revoked_err}");
    assert!(
        spaces.space("alpha-final").await.is_err(),
        "revoked token must fail on next spaces.space() instead of continuing on cached connection"
    );

    // Now rotate to the valid v3 token: must succeed immediately on next SDK call.
    let rotated_v3 = spaces
        .add(&url_2, Some("static-relay-token-alpha-v3".into()), None)
        .await
        .unwrap();
    assert_eq!(rotated_v3.shown_name(), "alpha-final");
    let s3 = spaces.space("alpha-final").await.unwrap();
    assert!(
        s3.bash("echo v3-ok", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("v3-ok")
    );
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());
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
    let start_mesh_machine = |machine_id: &'static str,
                              token_v1: &'static str,
                              token_v2: Option<&'static str>,
                              up_v1: SocketAddr,
                              up_v2: Option<SocketAddr>,
                              rotated: Arc<AtomicBool>| {
        let coord_url = coord.url.clone();
        let stun = coord.stun.to_string();
        let dir = mesh_dir.path().to_path_buf();
        async move {
            let mut cfg = MeshConfig::new(
                coord_url,
                NodeKind::Machine,
                Some(dir.join(format!("{machine_id}.json"))),
                static_auth(vec![("x-cua-machine-id".into(), machine_id.into())]),
            );
            cfg.stun = vec![stun];
            cfg.approved_path = Some(dir.join(format!("{machine_id}-approved.json")));
            let rot_v = rotated.clone();
            cfg.pair_verifier = Some(Arc::new(move |client, ts, proof| {
                let tok = if rot_v.load(Ordering::SeqCst) {
                    token_v2.unwrap_or(token_v1)
                } else {
                    token_v1
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
            tokio::spawn(async move {
                while let Some(mut incoming) = m.accept().await {
                    if incoming.header.service == "spacesd" {
                        let upstream = if rotated.load(Ordering::SeqCst) {
                            up_v2.unwrap_or(up_v1)
                        } else {
                            up_v1
                        };
                        tokio::spawn(async move {
                            if let Ok(mut tcp) = TcpStream::connect(upstream).await {
                                let _ =
                                    tokio::io::copy_bidirectional(&mut incoming.stream, &mut tcp)
                                        .await;
                            }
                        });
                    }
                }
            });
            mesh
        }
    };

    let _machine_a = start_mesh_machine(
        MACHINE_A,
        TOKEN_A,
        Some(TOKEN_A_ROTATED),
        srv_a_v1.addr,
        Some(srv_a_v2.addr),
        rotated.clone(),
    )
    .await;
    let _machine_b = start_mesh_machine(
        MACHINE_B,
        TOKEN_B,
        None,
        srv_b.addr,
        None,
        Arc::new(AtomicBool::new(false)),
    )
    .await;

    let coord_addr: SocketAddr = coord.url.strip_prefix("http://").unwrap().parse().unwrap();
    let stun_str = coord.stun.to_string();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let relay_url = format!("http://{relay_addr}");
    tokio::spawn(async move {
        loop {
            let Ok((mut client_tcp, _)) = relay_listener.accept().await else {
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

#[tokio::test]
async fn static_relay_remove_isolates_siblings_skips_account_relay_and_returns_not_found() {
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

    let seen_paths = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let mut routes = HashMap::new();
    routes.insert(MACHINE_A.to_string(), srv_a.addr);
    routes.insert(MACHINE_B.to_string(), srv_b.addr);
    let router_addr = start_static_path_router(routes, None, seen_paths).await;
    let relay_origin = format!("http://{router_addr}");

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

    spaces
        .add(
            &format!("{relay_origin}/m/{MACHINE_A}"),
            Some(TOKEN_A.into()),
            Some("rm-alpha".into()),
        )
        .await
        .unwrap();
    spaces
        .add(
            &format!("{relay_origin}/m/{MACHINE_B}"),
            Some(TOKEN_B.into()),
            Some("rm-beta".into()),
        )
        .await
        .unwrap();

    // Warm both connections in the cache.
    assert!(
        spaces
            .space("rm-alpha")
            .await
            .unwrap()
            .bash("echo a-before", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("a-before")
    );
    assert!(
        spaces
            .space("rm-beta")
            .await
            .unwrap()
            .bash("echo b-before", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("b-before")
    );

    // Removing MACHINE_A must delete only MACHINE_A's record, credential, and cached connection,
    // making 0 Account Relay calls while leaving sibling MACHINE_B untouched.
    let removed = spaces.remove(&format!("relay:{MACHINE_A}")).await.unwrap();
    assert_eq!(removed.id, format!("relay:{MACHINE_A}"));
    assert_eq!(
        account_spy.count(),
        0,
        "removing a Static Relay Space must never hit Account Relay: {:?}",
        account_spy.snapshot()
    );
    assert!(
        spaces
            .registry()
            .get(&format!("relay:{MACHINE_A}"))
            .unwrap()
            .is_none()
    );
    assert!(
        spaces
            .registry()
            .credential(&format!("relay:{MACHINE_A}"))
            .unwrap()
            .is_none()
    );
    assert!(spaces.resolve("rm-alpha").is_err());

    // Sibling MACHINE_B on the same relay host stays intact and operational.
    let listed = spaces.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, format!("relay:{MACHINE_B}"));
    let cred_b = spaces
        .registry()
        .credential(&format!("relay:{MACHINE_B}"))
        .unwrap()
        .expect("sibling credential must remain intact");
    assert_eq!(cred_b.token.as_deref(), Some(TOKEN_B));
    assert!(
        spaces
            .space("rm-beta")
            .await
            .unwrap()
            .bash("echo b-after", Duration::from_secs(5))
            .await
            .unwrap()
            .render()
            .contains("b-after")
    );
    assert_eq!(account_spy.count(), 0, "{:?}", account_spy.snapshot());

    // Removing a non-existent / already-removed `relay:<id>` must return NotFound.
    let no_account_spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .build();
    let err_again = no_account_spaces
        .remove(&format!("relay:{MACHINE_A}"))
        .await
        .unwrap_err();
    assert_eq!(
        err_again.tag(),
        "not_found",
        "removing already-deleted relay id must return NotFound: {err_again}"
    );
    let err_unknown = no_account_spaces
        .remove("relay:unregistered-0001")
        .await
        .unwrap_err();
    assert_eq!(
        err_unknown.tag(),
        "not_found",
        "removing unknown relay id must return NotFound: {err_unknown}"
    );
    let err_with_account = spaces.remove("relay:unregistered-0002").await.unwrap_err();
    assert_eq!(
        err_with_account.tag(),
        "not_found",
        "removing unknown relay id with account configured must return NotFound: {err_with_account}"
    );
}

#[tokio::test]
async fn static_relay_refuses_account_sharing_with_zero_account_relay_hits_while_direct_relay_register_works()
 {
    struct AlwaysAllow;
    impl cua_spaces::share::ShareConsent for AlwaysAllow {
        fn confirm(&self, _reason: &str) -> std::result::Result<(), String> {
            Ok(())
        }
    }

    let srv_a = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;

    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .share_consent(Arc::new(AlwaysAllow))
        .build();

    spaces
        .add(
            &format!("{}/m/{MACHINE_A}", srv_a.url()),
            Some(TOKEN_A.into()),
            Some("share-alpha".into()),
        )
        .await
        .unwrap();

    let assert_refused = |label: &str, err: cua_spaces::Error| {
        assert_eq!(
            err.tag(),
            "invalid_argument",
            "{label} must fail with invalid_argument, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("Static Relay") && msg.contains("Account Relay"),
            "{label} error must explain Static Relay vs Account Relay Mode: {msg}"
        );
    };

    assert_refused(
        "share_space(email)",
        spaces
            .share_space(
                "share-alpha",
                "bob@example.com",
                cua_spaces::share::ShareRole::Viewer,
            )
            .await
            .unwrap_err(),
    );
    assert_refused(
        "share_space(team)",
        spaces
            .share_space(
                &format!("relay:{MACHINE_A}"),
                "team:design",
                cua_spaces::share::ShareRole::Editor,
            )
            .await
            .unwrap_err(),
    );
    assert_refused(
        "share_with_team",
        spaces
            .share_with_team("share-alpha", "design")
            .await
            .unwrap_err(),
    );
    assert_refused(
        "unshare_space(email)",
        spaces
            .unshare_space("share-alpha", Some("bob@example.com"))
            .await
            .unwrap_err(),
    );
    assert_refused(
        "unshare_space(team)",
        spaces
            .unshare_space("share-alpha", Some("team:design"))
            .await
            .unwrap_err(),
    );
    assert_refused(
        "unshare_space(all)",
        spaces.unshare_space("share-alpha", None).await.unwrap_err(),
    );
    assert_refused(
        "unshare_from_team",
        spaces
            .unshare_from_team("share-alpha", "design")
            .await
            .unwrap_err(),
    );
    assert_refused(
        "space_shares",
        spaces.space_shares("share-alpha").await.unwrap_err(),
    );
    assert_refused(
        "relay_register",
        spaces.relay_register("share-alpha").await.unwrap_err(),
    );
    assert_refused(
        "relay_unregister",
        spaces.relay_unregister("share-alpha").await.unwrap_err(),
    );
    let leave_results = spaces
        .leave_many(&[format!("relay:{MACHINE_A}"), "share-alpha".into()])
        .await;
    assert_eq!(leave_results.len(), 2);
    for r in &leave_results {
        assert!(!r.ok, "leave_many must refuse Static Relay Space: {r:?}");
        assert!(
            r.error
                .as_deref()
                .is_some_and(|e| e.contains("it's yours; delete it instead")),
            "unexpected leave_many error: {r:?}"
        );
    }
    assert!(
        spaces
            .registry()
            .get(&format!("relay:{MACHINE_A}"))
            .unwrap()
            .is_some(),
        "leave_many must never delete a Static Relay Space record"
    );
    assert!(
        spaces
            .registry()
            .credential(&format!("relay:{MACHINE_A}"))
            .unwrap()
            .is_some(),
        "leave_many must never delete a Static Relay Space credential"
    );
    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 hits for share/unshare/shares/leave on Static Relay Space: {:?}",
        account_spy.snapshot()
    );

    // Even when signed out (no RelayAccount), refusal happens BEFORE `self.relay()`.
    let signed_out = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(5))
        .build();
    assert_refused(
        "signed-out share_space",
        signed_out
            .share_space(
                "share-alpha",
                "bob@example.com",
                cua_spaces::share::ShareRole::Viewer,
            )
            .await
            .unwrap_err(),
    );
    assert_refused(
        "signed-out unshare_space",
        signed_out
            .unshare_space("share-alpha", None)
            .await
            .unwrap_err(),
    );
    assert_refused(
        "signed-out space_shares",
        signed_out.space_shares("share-alpha").await.unwrap_err(),
    );
    let signed_out_leave = signed_out.leave_many(&[format!("relay:{MACHINE_A}")]).await;
    assert_eq!(signed_out_leave.len(), 1);
    assert!(!signed_out_leave[0].ok, "{signed_out_leave:?}");
    assert!(
        signed_out_leave[0]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("it's yours; delete it instead")),
        "{signed_out_leave:?}"
    );

    // Non-regression: Account Relay Mode `relay_register` on a direct Space still works.
    let fake_relay = cua_host::testing::FakeRelay::start().await;
    fake_relay.add_account("ada-token", "ada", Some("ada@example.com"));
    let direct_srv = MockServer::start(MockAuth::default()).await;
    direct_srv.state.advertise(&["relay_attach"]);
    let acct_home = tempfile::tempdir().unwrap();
    let acct_spaces = Spaces::builder()
        .home(acct_home.path())
        .relay(RelayAccount::new(
            &fake_relay.url,
            Arc::new(StaticToken("ada-token".into())),
        ))
        .build();
    let direct_info = acct_spaces
        .add(&direct_srv.url(), None, Some("direct-box".into()))
        .await
        .unwrap();
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
    let reg = acct_spaces.relay_register(&direct_info.id).await.unwrap();
    assert!(reg.online);
    assert_eq!(reg.relay_space, format!("relay:{}", reg.machine));
    let listed_shares = acct_spaces.space_shares(&direct_info.id).await.unwrap();
    assert_eq!(listed_shares.machine, reg.machine);
    assert!(acct_spaces.relay_unregister(&direct_info.id).await.unwrap());
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

    // Case 1: `/m/tools` (segment shorter than valid_machine_id) without token.
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

    // Case 2: `/m/<valid-machine-id>` where the server is a plain HTTP MCP server without token.
    let mcp_valid_seg = McpTestServer::start("/m").await.unwrap();
    let info_valid = spaces
        .add(
            &format!("{}/m/mcp", mcp_valid_seg.url),
            None,
            Some("mcp-m".into()),
        )
        .await
        .expect("plain MCP at /m/mcp must succeed without token");
    assert_eq!(info_valid.provider, Provider::Direct);
    assert!(info_valid.id.starts_with("direct:"), "{}", info_valid.id);

    // Case 3: exact `/m/<valid-machine-id>` without token and without `--service` MUST fail
    // immediately upfront (never probing MCP first), while passing `--service mcp` or a token
    // still registers a plain MCP server as `direct:`.
    let mcp_exact_origin = McpTestServer::start("").await.unwrap();
    let rewrite_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rewrite_addr = rewrite_listener.local_addr().unwrap();
    let upstream_port = mcp_exact_origin.port();
    tokio::spawn(async move {
        let client: hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            hyper::body::Incoming,
        > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
        loop {
            let Ok((tcp, _)) = rewrite_listener.accept().await else {
                break;
            };
            let client = client.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |mut req: http::Request<hyper::body::Incoming>| {
                        let client = client.clone();
                        async move {
                            let uri: http::Uri = format!("http://127.0.0.1:{upstream_port}/mcp")
                                .parse()
                                .unwrap();
                            *req.uri_mut() = uri;
                            req.headers_mut().remove(http::header::HOST);
                            client.request(req).await
                        }
                    },
                );
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(tcp), svc)
                .await;
            });
        }
    });
    let exact_url = format!("http://{rewrite_addr}/m/mcp-service-001");
    let err_no_tok = spaces.add(&exact_url, None, None).await.unwrap_err();
    assert_eq!(err_no_tok.tag(), "invalid_argument", "{err_no_tok}");
    assert!(
        err_no_tok.to_string().contains("--token")
            && err_no_tok.to_string().contains("CUA_ENV_TOKEN"),
        "{err_no_tok}"
    );

    let info_exact_service = spaces
        .add_with_service(
            &exact_url,
            None,
            Some("mcp-exact-svc".into()),
            Some("mcp".into()),
        )
        .await
        .expect(
            "plain MCP at exact /m/<valid-machine-id> with explicit --service registers as direct",
        );
    assert_eq!(info_exact_service.provider, Provider::Direct);
    assert_eq!(info_exact_service.id, format!("direct:{rewrite_addr}"));
    assert_eq!(info_exact_service.services, ["mcp"]);

    let info_exact_tok = spaces
        .add(
            &exact_url,
            Some("mcp-bearer-token".into()),
            Some("mcp-exact".into()),
        )
        .await
        .expect("plain MCP at exact /m/<valid-machine-id> with token falls back to direct");
    assert_eq!(info_exact_tok.provider, Provider::Direct);
    assert_eq!(info_exact_tok.id, format!("direct:{rewrite_addr}"));
    assert_eq!(info_exact_tok.services, ["mcp"]);
    let (tools, _) = spaces
        .space("mcp-exact")
        .await
        .unwrap()
        .list_tools(Some("mcp"))
        .await
        .unwrap();
    assert!(!tools.is_empty());

    // Case 4: unreachable plain-MCP `/m/tools` without token MUST propagate the real
    // MCP/transport error, never misreporting it as "invalid Static Relay machine id".
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    let err_dead_mcp = spaces
        .add(&format!("http://{dead_addr}/m/tools"), None, None)
        .await
        .unwrap_err();
    assert!(
        !err_dead_mcp
            .to_string()
            .contains("invalid Static Relay machine id"),
        "unreachable /m/tools must propagate real MCP/transport error, got: {err_dead_mcp}"
    );
    assert_ne!(
        err_dead_mcp.tag(),
        "invalid_argument",
        "unreachable /m/tools must not fail with invalid_argument: {err_dead_mcp}"
    );

    assert_eq!(account_spy.count(), 0);
}

#[tokio::test]
async fn upfront_rejections_missing_token_host_flag_and_malformed_machine_id_never_mutate_stores() {
    // TCP spy listener: upfront validation MUST fail with ZERO network I/O.
    let net_spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let net_spy_addr = net_spy.local_addr().unwrap();
    let net_hits = Arc::new(AtomicUsize::new(0));
    let net_hits_bg = net_hits.clone();
    tokio::spawn(async move {
        while let Ok((_sock, _)) = net_spy.accept().await {
            net_hits_bg.fetch_add(1, Ordering::SeqCst);
        }
    });
    let spy_origin = format!("http://{net_spy_addr}");

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
            "missing-token error must be actionable: {msg}"
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
        "unexpected --host error: {err}"
    );
    assert!(
        !spaces.registry().spaces_path().exists(),
        "spaces.json must not be created on --host rejection"
    );
    assert!(
        !spaces.registry().credentials_path().exists(),
        "spaces-credentials.json must not be created on --host rejection"
    );
    assert!(
        !spaces.registry().direct_hosts_path().exists(),
        "direct-hosts.json must not be created on --host rejection"
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
        let url = format!("{spy_origin}/m/{bad_id}");
        let err = spaces
            .add(&url, Some(TOKEN_A.into()), None)
            .await
            .unwrap_err();
        assert_eq!(err.tag(), "invalid_argument", "{bad_id}: {err}");
        assert!(
            err.to_string().contains("[a-z0-9-]{8,64}"),
            "malformed id error must cite grammar for {bad_id}: {err}"
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
        "extra path segments error: {extra_err}"
    );

    assert_eq!(
        net_hits.load(Ordering::SeqCst),
        0,
        "upfront Static Relay validation must make ZERO network connections"
    );
    assert!(spaces.list().unwrap().is_empty());
    assert!(!spaces.registry().spaces_path().exists());
    assert!(!spaces.registry().credentials_path().exists());
    assert!(!spaces.registry().direct_hosts_path().exists());
}

#[tokio::test]
async fn direct_space_has_no_legacy_static_relay_branch() {
    let srv = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
    let home = tempfile::tempdir().unwrap();
    let spaces = Spaces::builder()
        .home(home.path())
        .probe_timeout(Duration::from_secs(3))
        .build();

    // Manually seed a pre-release `direct:<host>:<port>` record with a `/m/<id>` credential URL:
    // with the legacy `Via::Static` branch deleted from `SpaceId::Direct`, connecting uses
    // `Transport::Direct` only and never routes via `ChannelRoute::Relay` or mesh.
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
        Some(Transport::Direct),
        "SpaceId::Direct must not route through legacy Via::Static relay/mesh"
    );
}

#[tokio::test]
async fn static_relay_bypasses_account_relay_in_reach_thread_home_and_checkpoints() {
    let srv = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_A}")),
    })
    .await;
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

    let space_id = format!("relay:{MACHINE_A}");
    spaces
        .add(
            &format!("{}/m/{MACHINE_A}", srv.url()),
            Some(TOKEN_A.into()),
            Some("bypass-box".into()),
        )
        .await
        .unwrap();

    // 1. Spaces::reach must skip relay_directory while still probing the Static Relay Space.
    let reach = spaces.reach(&space_id).await;
    assert!(reach.reachable, "{reach:?}");
    assert!(!reach.listed_offline, "{reach:?}");
    assert_eq!(reach.reason, None);

    // 2. Spaces::thread_home must return ThreadHome::Here(None) without calling relay_row.
    let home_route = spaces.thread_home(&space_id).await.unwrap();
    assert!(
        matches!(home_route, cua_spaces::thread_route::ThreadHome::Here(None)),
        "expected ThreadHome::Here(None), got {home_route:?}"
    );
    let home_by_name = spaces.thread_home("bypass-box").await.unwrap();
    assert!(
        matches!(
            home_by_name,
            cua_spaces::thread_route::ThreadHome::Here(None)
        ),
        "expected ThreadHome::Here(None) by name, got {home_by_name:?}"
    );

    // 3. Spaces::checkpoint_space calls provider_of, which must return None without relay_row.
    let ckpt_err = spaces
        .checkpoint_space(&space_id, "snap-1", false)
        .await
        .unwrap_err();
    assert_eq!(ckpt_err.tag(), "wrong_provider", "{ckpt_err}");

    assert_eq!(
        account_spy.count(),
        0,
        "Account Relay must receive 0 hits during reach/thread_home/checkpoint_space: {:?}",
        account_spy.snapshot()
    );
}

#[tokio::test]
async fn byoc_static_relay_create_in_cloud_matches_manual_spaces_add_persistence() {
    struct StaticCloudManager;

    #[async_trait::async_trait]
    impl cua_sandbox_core::byoc::CloudManager for StaticCloudManager {
        async fn status(
            &self,
            _provider: Option<&str>,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::byoc::CloudStatusReport> {
            Ok(cua_sandbox_core::byoc::CloudStatusReport::default())
        }

        fn relay_mode(&self, provider: &str) -> Option<cua_sandbox_core::byoc::RelayMode> {
            (provider == "aws").then_some(cua_sandbox_core::byoc::RelayMode::Static)
        }

        async fn test(
            &self,
            _target: &cua_sandbox_core::byoc::CloudTarget,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::byoc::CloudTestReport> {
            unimplemented!()
        }

        async fn connect(
            &self,
            _target: &cua_sandbox_core::byoc::CloudTarget,
            _make_default: bool,
            _ttl_hours: Option<u32>,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::byoc::CloudConnected> {
            unimplemented!()
        }

        async fn disconnect(
            &self,
            _provider: &str,
            _delete: bool,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::byoc::CloudDisconnected> {
            unimplemented!()
        }

        async fn sweep(
            &self,
            _provider: Option<&str>,
            _dry_run: bool,
            _all: bool,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::byoc::CloudSweepReport> {
            unimplemented!()
        }

        async fn auto_sweep(
            &self,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::byoc::CloudSweepReport> {
            unimplemented!()
        }

        async fn audit(
            &self,
            _limit: usize,
        ) -> cua_sandbox_core::Result<Vec<cua_sandbox_core::byoc::CloudAuditEntry>> {
            unimplemented!()
        }
    }

    struct FakeStaticByocProvider {
        relay_origin: String,
        machine_id: String,
        env_token: String,
    }

    impl FakeStaticByocProvider {
        fn instance(&self, name: &str) -> cua_sandbox_core::ProviderInstance {
            let mut inst = cua_sandbox_core::ProviderInstance::new(
                "inst-static-1",
                name,
                cua_sandbox_core::Status::Running,
            );
            inst.details.insert(
                cua_sandbox_core::byoc::DETAIL_RELAY_MACHINE.into(),
                self.machine_id.clone(),
            );
            inst.details.insert(
                cua_sandbox_core::byoc::DETAIL_PLACE.into(),
                "AWS \u{b7} us-west-2".into(),
            );
            inst.endpoints.insert(
                cua_sandbox_core::ENV_PORT,
                cua_sandbox_core::ServiceEndpoint {
                    url: format!("{}/m/{}", self.relay_origin, self.machine_id),
                    headers: vec![],
                },
            );
            inst
        }
    }

    #[async_trait::async_trait]
    impl cua_sandbox_core::Provider for FakeStaticByocProvider {
        fn name(&self) -> &'static str {
            "aws"
        }

        fn capabilities(&self) -> cua_sandbox_core::ProviderCapabilities {
            cua_sandbox_core::ProviderCapabilities {
                kinds: vec![cua_sandbox_core::RunKind::Container],
                runtime: "fake",
                arches: vec!["amd64"],
                image_mode: cua_sandbox_core::ImageMode::Direct,
                ports: cua_sandbox_core::PortExposure::Https,
                command: false,
                env_to_entrypoint: true,
                private_registry: false,
                suspend: false,
                max_cpus: None,
                max_memory_mb: None,
                credential_env: &[],
                gpus: vec![],
                oses: vec!["linux"],
                custom_disk_gb: false,
                custom_cloud_image: false,
            }
        }

        fn check_configured(&self) -> cua_sandbox_core::Result<()> {
            Ok(())
        }

        async fn create(
            &self,
            spec: &cua_sandbox_core::ProviderCreate,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::ProviderInstance> {
            Ok(self.instance(&spec.name))
        }

        async fn get(
            &self,
            _id: &str,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::ProviderInstance> {
            Ok(self.instance("byoc-static-box"))
        }

        async fn list(&self) -> cua_sandbox_core::Result<Vec<cua_sandbox_core::ProviderInstance>> {
            Ok(vec![])
        }

        async fn delete(&self, _id: &str) -> cua_sandbox_core::Result<()> {
            Ok(())
        }

        fn endpoint(
            &self,
            instance: &cua_sandbox_core::ProviderInstance,
            port: u16,
        ) -> cua_sandbox_core::Result<cua_sandbox_core::ServiceEndpoint> {
            instance
                .endpoints
                .get(&port)
                .cloned()
                .ok_or_else(|| cua_sandbox_core::Error::NotFound(format!("port {port}")))
        }

        fn connect_options(
            &self,
            instance: &cua_sandbox_core::ProviderInstance,
            port: u16,
        ) -> Option<cua_sandbox_core::Result<cua_spacesd_client::ConnectOptions>> {
            let ep = instance.endpoints.get(&port)?;
            Some(
                cua_spacesd_client::ConnectOptions::parse(&ep.url)
                    .map(|o| o.token(&self.env_token))
                    .map_err(|e| cua_sandbox_core::Error::InvalidArgument(e.to_string())),
            )
        }

        fn joins_relay(&self) -> bool {
            true
        }

        fn keeps_internet_only(&self) -> bool {
            true
        }
    }

    const BYOC_MACHINE: &str = "cloud-0123456789abcdef";
    let srv_byoc = MockServer::start(MockAuth {
        token: Some(TOKEN_A.into()),
        gateway: None,
        prefix: Some(format!("/m/{BYOC_MACHINE}")),
    })
    .await;
    let srv_manual = MockServer::start(MockAuth {
        token: Some(TOKEN_B.into()),
        gateway: None,
        prefix: Some(format!("/m/{MACHINE_B}")),
    })
    .await;

    let seen = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let mut routes = HashMap::new();
    routes.insert(BYOC_MACHINE.to_string(), srv_byoc.addr);
    routes.insert(MACHINE_B.to_string(), srv_manual.addr);
    let router_addr = start_static_path_router(routes, None, seen).await;
    let relay_origin = format!("http://{router_addr}");

    let (account_spy_url, account_spy) = HttpSpy::start().await;
    let home = tempfile::tempdir().unwrap();
    let sandboxes = cua_sandbox_core::Sandboxes::builder()
        .state_dir(home.path().join("sandboxes"))
        .clouds(Arc::new(StaticCloudManager))
        .provider(Arc::new(FakeStaticByocProvider {
            relay_origin: relay_origin.clone(),
            machine_id: BYOC_MACHINE.into(),
            env_token: TOKEN_A.into(),
        }))
        .build();
    let spaces = Spaces::builder()
        .home(home.path())
        .sandboxes(sandboxes)
        .probe_timeout(Duration::from_secs(5))
        .relay(RelayAccount::new(
            &account_spy_url,
            Arc::new(StaticToken("account-spy-bearer".into())),
        ))
        .build();

    let created = spaces
        .create(cua_spaces::SpaceCreate {
            name: Some("byoc-static-box".into()),
            image: Some("linux".into()),
            on: Some(cua_sandbox_core::placement::On::Provider("aws".into())),
            env: [("CUA_ENV_TOKEN".to_string(), TOKEN_A.to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let byoc_info = match created {
        cua_spaces::SpaceCreated::Ready { info, .. } => info,
        other => panic!("expected Ready, got {other:?}"),
    };

    let manual_info = spaces
        .add(
            &format!("{relay_origin}/m/{MACHINE_B}"),
            Some(TOKEN_B.into()),
            Some("manual-static-box".into()),
        )
        .await
        .unwrap();

    // Both `create_in_cloud` (BYOC Static Relay) and `Spaces::add` persist identical
    // canonical `relay:<machine-id>` records in `spaces.json` and `Credential { url, token }`
    // in `spaces-credentials.json`.
    assert_eq!(byoc_info.id, format!("relay:{BYOC_MACHINE}"));
    assert_eq!(byoc_info.provider, Provider::Relay);
    assert_eq!(manual_info.id, format!("relay:{MACHINE_B}"));
    assert_eq!(manual_info.provider, Provider::Relay);

    let rec_byoc = spaces
        .registry()
        .get(&byoc_info.id)
        .unwrap()
        .expect("BYOC record in spaces.json");
    let rec_manual = spaces
        .registry()
        .get(&manual_info.id)
        .unwrap()
        .expect("manual record in spaces.json");
    assert_eq!(rec_byoc.id, format!("relay:{BYOC_MACHINE}"));
    assert_eq!(rec_manual.id, format!("relay:{MACHINE_B}"));
    assert!(rec_byoc.added_at.is_some());
    assert!(rec_manual.added_at.is_some());

    let cred_byoc = spaces
        .registry()
        .credential(&byoc_info.id)
        .unwrap()
        .expect("BYOC credential in spaces-credentials.json");
    let cred_manual = spaces
        .registry()
        .credential(&manual_info.id)
        .unwrap()
        .expect("manual credential in spaces-credentials.json");
    assert_eq!(
        cred_byoc.url.as_deref(),
        Some(format!("{relay_origin}/m/{BYOC_MACHINE}").as_str())
    );
    assert_eq!(
        cred_manual.url.as_deref(),
        Some(format!("{relay_origin}/m/{MACHINE_B}").as_str())
    );
    assert_eq!(cred_byoc.token.as_deref(), Some(TOKEN_A));
    assert_eq!(cred_manual.token.as_deref(), Some(TOKEN_B));
    assert!(spaces.is_static_relay_space(&SpaceId::Relay {
        machine_id: BYOC_MACHINE.into(),
    }));
    assert!(spaces.is_static_relay_space(&SpaceId::Relay {
        machine_id: MACHINE_B.into(),
    }));

    assert_eq!(
        account_spy.count(),
        0,
        "BYOC Static Relay create + manual add must make 0 Account Relay calls: {:?}",
        account_spy.snapshot()
    );
}
