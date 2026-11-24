// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Shared Static Relay test harnesses (`HttpSpy`, `StaticRelayRouter`,
//! `HttpsConnectProxy`, and `write_tls_fixture`), compiled only under `testing`.

use base64::Engine;
use http_body_util::BodyExt as _;
use hyper::service::service_fn;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServer;
use std::{collections::HashMap, net::SocketAddr, path::Path, sync::Arc, sync::Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type HttpClient = Client<HttpConnector, tonic::body::Body>;
type Resp = http::Response<tonic::body::Body>;

const SPY_RESP: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\n\
content-type: application/json\r\ncontent-length: 44\r\nconnection: close\r\n\r\n\
{\"error\":\"account relay must not be called\"}";
const STATIC_INFO: &str = r#"{"account_auth":false,"issuer":null,"mesh":null,"public_url":"https://relay.invalid","state_writable":false,"static_tokens":true}"#;

/// Loopback HTTP spy recording the first line of every request and answering HTTP 500.
#[derive(Clone, Default)]
pub struct HttpSpy {
    requests: Arc<Mutex<Vec<String>>>,
}

impl HttpSpy {
    pub async fn start() -> (String, Self) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let spy = Self::default();
        let reqs = spy.requests.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let reqs = reqs.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let raw = String::from_utf8_lossy(&buf[..n]);
                    reqs.lock()
                        .unwrap()
                        .push(raw.lines().next().unwrap_or_default().into());
                    let _ = sock.write_all(SPY_RESP).await;
                });
            }
        });
        (format!("http://{addr}"), spy)
    }
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    pub fn snapshot(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// Writes a test CA (`roots.pem`) and leaf cert/key (`leaf.der`, `key.der`) for `hosts`.
pub fn write_tls_fixture(dir: &Path, hosts: &[&str]) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate().unwrap();
    let root = ca.self_signed(&key).unwrap();
    let issuer = Issuer::new(ca, key);
    let leaf_key = KeyPair::generate().unwrap();
    let sans: Vec<String> = hosts.iter().map(|h| (*h).into()).collect();
    let leaf = CertificateParams::new(sans)
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(root.der())
    );
    std::fs::write(dir.join("leaf.der"), leaf.der()).unwrap();
    std::fs::write(dir.join("key.der"), leaf_key.serialize_der()).unwrap();
    std::fs::write(dir.join("roots.pem"), pem).unwrap();
}

fn text_resp(status: u16, ct: &str, body: impl Into<bytes::Bytes>) -> Resp {
    let full = http_body_util::Full::new(body.into()).map_err(|never| match never {});
    http::Response::builder()
        .status(status)
        .header("content-type", ct)
        .body(tonic::body::Body::new(full))
        .unwrap()
}

struct RouterState {
    routes: Mutex<HashMap<String, (SocketAddr, Option<String>)>>,
    seen: Mutex<Vec<(String, Option<String>)>>,
    h2: HttpClient,
    h1: HttpClient,
}

async fn route_request(req: http::Request<hyper::body::Incoming>, st: Arc<RouterState>) -> Resp {
    let path = req.uri().path().to_string();
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    st.seen.lock().unwrap().push((path.clone(), auth));
    if path == "/v1/info" {
        return text_resp(200, "application/json", STATIC_INFO);
    }
    let id = path
        .strip_prefix("/m/")
        .map(|r| r.split_once('/').map_or(r, |(id, _)| id));
    let Some((upstream, rewrite)) = id.and_then(|id| st.routes.lock().unwrap().get(id).cloned())
    else {
        return text_resp(404, "text/plain", "not found");
    };
    let (mut parts, body) = req.into_parts();
    let pq = rewrite
        .as_deref()
        .or_else(|| parts.uri.path_and_query().map(|p| p.as_str()))
        .unwrap_or("/");
    parts.uri = format!("http://{upstream}{pq}").parse().unwrap();
    parts.headers.remove(http::header::HOST);
    let body = tonic::body::Body::new(body.map_err(|e| tonic::Status::internal(e.to_string())));
    let fwd = http::Request::from_parts(parts, body);
    let resp = if fwd.version() == http::Version::HTTP_2 {
        st.h2.request(fwd).await
    } else {
        st.h1.request(fwd).await
    };
    match resp {
        Ok(r) => {
            let (rp, rb) = r.into_parts();
            let rb = tonic::body::Body::new(rb.map_err(|e| tonic::Status::internal(e.to_string())));
            http::Response::from_parts(rp, rb)
        }
        Err(e) => text_resp(502, "text/plain", e.to_string()),
    }
}

/// HTTP/2 + HTTP/1.1 Static Relay router serving `/v1/info` and `/m/<id>/...`
/// with live-swappable upstreams and request recording.
#[derive(Clone)]
pub struct StaticRelayRouter {
    pub addr: SocketAddr,
    state: Arc<RouterState>,
}

impl StaticRelayRouter {
    pub async fn start(routes: &[(&str, SocketAddr)]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let map = routes.iter().map(|&(k, u)| (k.into(), (u, None))).collect();
        let state = Arc::new(RouterState {
            routes: Mutex::new(map),
            seen: Mutex::new(Vec::new()),
            h2: Client::builder(TokioExecutor::new())
                .http2_only(true)
                .build_http(),
            h1: Client::builder(TokioExecutor::new()).build_http(),
        });
        let bg = state.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let st = bg.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let st = st.clone();
                        async move { Ok::<_, std::convert::Infallible>(route_request(req, st).await) }
                    });
                    let _ = AutoServer::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        Self { addr, state }
    }
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn set_route(&self, id: &str, up: SocketAddr) {
        self.state
            .routes
            .lock()
            .unwrap()
            .insert(id.into(), (up, None));
    }
    pub fn set_rewrite(&self, id: &str, up: SocketAddr, path: &str) {
        self.state
            .routes
            .lock()
            .unwrap()
            .insert(id.into(), (up, Some(path.into())));
    }
    pub fn seen_paths(&self) -> Vec<(String, Option<String>)> {
        self.state.seen.lock().unwrap().clone()
    }
}

struct ProxyState {
    tls_cfg: Arc<rustls::ServerConfig>,
    upstreams: HashMap<String, SocketAddr>,
    leaks: Mutex<Vec<String>>,
}

async fn handle_connect(mut sock: TcpStream, st: Arc<ProxyState>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") && head.len() <= 8192 {
        let mut b = [0];
        if sock.read_exact(&mut b).await.is_err() {
            return;
        }
        head.push(b[0]);
    }
    let Ok(head) = String::from_utf8(head) else {
        return;
    };
    let push_leak = |m: String| st.leaks.lock().unwrap().push(m);
    let matched = st.upstreams.iter().find_map(|(h, &t)| {
        head.starts_with(&format!("CONNECT {h}:443 "))
            .then_some((h.as_str(), t))
    });
    let Some((host, target)) = matched else {
        push_leak(head);
        let _ = sock
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    };
    if sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
        return;
    }
    let Ok(hello) =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), sock).await
    else {
        push_leak("non-TLS bytes sent on port-443 tunnel".into());
        return;
    };
    let sni = hello.client_hello().server_name().map(str::to_string);
    if sni.as_deref() != Some(host) {
        push_leak(format!("unexpected SNI {sni:?}"));
        return;
    }
    if let Ok(mut tls) = hello.into_stream(st.tls_cfg.clone()).await
        && let Ok(mut up) = TcpStream::connect(target).await
    {
        let _ = tokio::io::copy_bidirectional(&mut tls, &mut up).await;
    }
}

/// Port-443 plaintext-vs-CONNECT sniffer and TLS terminating tunnel.
#[derive(Clone)]
pub struct HttpsConnectProxy {
    pub addr: SocketAddr,
    state: Arc<ProxyState>,
}

impl HttpsConnectProxy {
    pub async fn start(tls_dir: &Path, routes: &[(&str, SocketAddr)]) -> Self {
        Self::bind("127.0.0.1:0", tls_dir, routes).await
    }
    pub async fn bind(bind_addr: &str, tls_dir: &Path, routes: &[(&str, SocketAddr)]) -> Self {
        let read = |f| std::fs::read(tls_dir.join(f)).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(read("key.der")).into();
        let prov = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(prov)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![read("leaf.der").into()], key)
            .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let upstreams = routes.iter().map(|&(h, u)| (h.into(), u)).collect();
        let state = Arc::new(ProxyState {
            tls_cfg: Arc::new(cfg),
            upstreams,
            leaks: Mutex::new(Vec::new()),
        });
        let listener = TcpListener::bind(bind_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bg = state.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                tokio::spawn(handle_connect(s, bg.clone()));
            }
        });
        Self { addr, state }
    }
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn leaks(&self) -> Vec<String> {
        self.state.leaks.lock().unwrap().clone()
    }
}
