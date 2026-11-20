// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use base64::Engine as _;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct AliyunConnectProxy {
    pub url: String,
    pub ca_pem: String,
    pub blocked_egress: Arc<Mutex<Vec<String>>>,
    pub allowed_connects: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AliyunConnectProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn is_allowed_aliyun_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "sts.aliyuncs.com"
        || (h.ends_with(".aliyuncs.com") && (h.starts_with("ecs.") || h.starts_with("vpc.")))
}

impl AliyunConnectProxy {
    pub async fn start(router: Router, ca_pem_path: &Path) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self signed ca");
        let ca_pem = pem(ca_cert.der());
        std::fs::write(ca_pem_path, &ca_pem).expect("write ca pem");

        let issuer = Arc::new(rcgen::Issuer::new(ca_params, ca_key));
        let cert_cache: Arc<Mutex<BTreeMap<String, Arc<rustls::ServerConfig>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let blocked_egress = Arc::new(Mutex::new(Vec::new()));
        let allowed_connects = Arc::new(Mutex::new(Vec::new()));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind connect proxy");
        let addr = listener.local_addr().expect("proxy addr");
        let url = format!("http://{addr}");

        let blocked = blocked_egress.clone();
        let allowed = allowed_connects.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let router = router.clone();
                let issuer = issuer.clone();
                let cache = cert_cache.clone();
                let blocked = blocked.clone();
                let allowed = allowed.clone();
                tokio::spawn(async move {
                    let _ = handle_client(stream, router, issuer, cache, blocked, allowed).await;
                });
            }
        });

        Self {
            url,
            ca_pem,
            blocked_egress,
            allowed_connects,
            task,
        }
    }

    pub fn blocked_egress(&self) -> Vec<String> {
        self.blocked_egress.lock().unwrap().clone()
    }

    pub fn allowed_connects(&self) -> Vec<String> {
        self.allowed_connects.lock().unwrap().clone()
    }
}

fn get_or_build_server_config(
    host: &str,
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    cache: &Mutex<BTreeMap<String, Arc<rustls::ServerConfig>>>,
) -> Arc<rustls::ServerConfig> {
    if let Some(cfg) = cache.lock().unwrap().get(host).cloned() {
        return cfg;
    }
    let leaf_params = rcgen::CertificateParams::new(vec![host.to_string()]).expect("leaf params");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params.signed_by(&leaf_key, issuer).expect("sign leaf");

    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls_pki_types::CertificateDer::from(
            leaf_cert.der().to_vec(),
        )],
        rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            leaf_key.serialize_der(),
        )),
    )
    .expect("server config");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let arc = Arc::new(cfg);
    cache.lock().unwrap().insert(host.to_string(), arc.clone());
    arc
}

async fn read_connect_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return String::from_utf8(buf).ok();
                }
            }
        }
    }
    None
}

async fn handle_client(
    mut stream: TcpStream,
    router: Router,
    issuer: Arc<rcgen::Issuer<'static, rcgen::KeyPair>>,
    cache: Arc<Mutex<BTreeMap<String, Arc<rustls::ServerConfig>>>>,
    blocked: Arc<Mutex<Vec<String>>>,
    allowed: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let Some(head) = read_connect_head(&mut stream).await else {
        return Ok(());
    };
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    let host = target.split(':').next().unwrap_or(target);
    if !is_allowed_aliyun_host(host) {
        blocked.lock().unwrap().push(target.to_string());
        let _ = stream
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    allowed.lock().unwrap().push(target.to_string());
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let hello =
        match tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
            .await
        {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };
    let sni = hello
        .client_hello()
        .server_name()
        .unwrap_or(host)
        .to_string();
    let cfg = get_or_build_server_config(&sni, &issuer, &cache);
    let tls_stream = match hello.into_stream(cfg).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let svc = TowerToHyperService::new(router);
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), svc)
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_allowed_aliyun_host;

    #[test]
    fn host_allowlist_permits_only_sts_ecs_vpc() {
        assert!(is_allowed_aliyun_host("sts.aliyuncs.com"));
        assert!(is_allowed_aliyun_host("STS.ALIYUNCS.COM"));
        assert!(is_allowed_aliyun_host("ecs.cn-hangzhou.aliyuncs.com"));
        assert!(is_allowed_aliyun_host("vpc.ap-southeast-1.aliyuncs.com"));

        assert!(!is_allowed_aliyun_host("ram.aliyuncs.com"));
        assert!(!is_allowed_aliyun_host("evil.aliyuncs.com"));
        assert!(!is_allowed_aliyun_host("example.com"));
        assert!(!is_allowed_aliyun_host("aliyuncs.com"));
    }
}
