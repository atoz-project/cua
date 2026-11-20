// SPDX-License-Identifier: MIT

pub mod fake_aliyun;
pub mod fake_mirror;
pub mod fake_relay;
pub mod proxy;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use base64::Engine as _;
use cua_spacesd_client::testing::{MockAuth, MockServer};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

use fake_aliyun::{FakeAliyun, S, handle as aliyun_handle};
use fake_mirror::FakeMirror;
use fake_relay::{FakeOidc, FakeRelay};
use proxy::AliyunConnectProxy;

const SCRUB_ENV: &[&str] = &[
    "ALIBABA_CLOUD_ACCESS_KEY_ID",
    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    "ALIBABACLOUD_ACCESS_KEY_ID",
    "ALIBABACLOUD_ACCESS_KEY_SECRET",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CUA_DAEMON",
    "CUA_DAEMON_TOKEN",
    "CUA_ENV_TOKEN",
    "CUA_OIDC_ISSUER",
    "CUA_OIDC_CLIENT_ID",
    "CUA_RELAY_URL",
    "CUA_SPACES_API_URL",
    "CUA_DEFAULT_ON",
    "CUA_DEFAULT_KIND",
    "CUA_DEFAULT_RUNTIME",
    "CUA_AGENT",
    "CUA_AGENT_RUN_ID",
    "CLAUDECODE",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CODEX_SANDBOX",
];

#[derive(Debug, Clone)]
pub struct CmdOut {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOut {
    pub fn ok(&self) -> &Self {
        assert_eq!(
            self.code, 0,
            "expected exit 0, got {}\nstdout:\n{}\nstderr:\n{}",
            self.code, self.stdout, self.stderr
        );
        self
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "stdout is not valid JSON ({e}):\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }

    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("repo root")
        .to_path_buf()
}

pub fn resolve_cua_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("CUA_BIN") {
            let pb = PathBuf::from(p);
            if pb.exists() {
                return pb;
            }
        }
        let repo = repo_root();
        let manifest = repo.join("libs/cua/Cargo.toml");
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--manifest-path",
                manifest.to_str().expect("utf-8 manifest path"),
                "-p",
                "cua-cli",
                "--features",
                "byoc",
                "--bin",
                "cua",
            ])
            .status()
            .expect("invoke cargo build for cua-cli");
        assert!(
            status.success(),
            "cargo build cua-cli --features byoc failed"
        );
        repo.join("libs/cua/target/debug/cua")
    })
    .clone()
}

fn extract_env_token(user_data: &str) -> Option<String> {
    for line in user_data.lines() {
        let trimmed = line.trim();
        for marker in ["CUA_ENV_TOKEN=", "env_token=", "--env-token ", "--token "] {
            if let Some(idx) = trimmed.find(marker) {
                let rest = &trimmed[idx + marker.len()..];
                let val = rest
                    .trim_start_matches(['"', '\'', '='])
                    .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';'))
                    .next()
                    .unwrap_or("");
                if !val.is_empty() && !val.starts_with("cmt_") {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

pub struct AliyunWorld {
    pub dir: tempfile::TempDir,
    pub env: HashMap<String, String>,
    pub aliyun: S,
    pub proxy: AliyunConnectProxy,
    pub relay: FakeRelay,
    pub oidc: FakeOidc,
    pub mirror: FakeMirror,
    pub mock_spacesd: MockServer,
    daemon: Option<tokio::process::Child>,
}

impl AliyunWorld {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca-roots.pem");

        let aliyun: S = Arc::new(Mutex::new(FakeAliyun::default()));
        let relay = FakeRelay::start().await;
        let oidc = FakeOidc::start(Some(relay.clone())).await;
        let mirror = FakeMirror::start().await;
        let mock_spacesd = MockServer::start(MockAuth::default()).await;
        let mock_url = format!("http://{}", mock_spacesd.addr);

        {
            let relay_boot = relay.clone();
            let mock_boot = mock_url.clone();
            let relay_power = relay.clone();
            let mut f = aliyun.lock().unwrap();
            f.on_boot = Some(Arc::new(move |inst, _params| {
                if let Some(ref mid) = inst.machine_id {
                    if let Some(env_tok) = extract_env_token(&inst.user_data_decoded) {
                        relay_boot.register_static_machine(mid, &inst.instance_name, &env_tok);
                    }
                    relay_boot.set_online(mid, true, "0.1.0");
                    relay_boot.tunnel(mid, &mock_boot);
                }
            }));
            f.on_power = Some(Arc::new(move |inst, online| {
                if let Some(ref mid) = inst.machine_id {
                    relay_power.set_online(mid, online, "0.1.0");
                }
            }));
        }

        let router = Router::new()
            .fallback(aliyun_handle)
            .with_state(aliyun.clone());
        let proxy = AliyunConnectProxy::start(router, &ca_path).await;

        let mut env = HashMap::new();
        env.insert("HOME".into(), dir.path().display().to_string());
        env.insert("USERPROFILE".into(), dir.path().display().to_string());
        env.insert(
            "CUA_HOME".into(),
            dir.path().join(".cua").display().to_string(),
        );
        env.insert("CUA_TEST".into(), "1".into());
        env.insert("CUA_CREDENTIAL_STORE".into(), "file".into());
        env.insert("CUA_NO_BROWSER".into(), "1".into());
        env.insert("CUA_LOG".into(), "error".into());
        env.insert("CUA_TELEMETRY".into(), "0".into());
        env.insert("CUA_TELEMETRY_FORBID_NETWORK".into(), "1".into());
        env.insert(
            "CUA_TELEMETRY_ENDPOINT".into(),
            "http://127.0.0.1:9/batch/".into(),
        );
        env.insert("CUA_RELAY_URL".into(), "http://127.0.0.1:9".into());
        env.insert("CUA_OIDC_POLL_UNIT_MS".into(), "5".into());
        env.insert("HTTPS_PROXY".into(), proxy.url.clone());
        env.insert("SSL_CERT_FILE".into(), ca_path.display().to_string());
        env.insert("NO_PROXY".into(), "127.0.0.1,localhost".into());

        Self {
            dir,
            env,
            aliyun,
            proxy,
            relay,
            oidc,
            mirror,
            mock_spacesd,
            daemon: None,
        }
    }

    pub fn set_env(&mut self, k: &str, v: impl Into<String>) -> &mut Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn remove_env(&mut self, k: &str) -> &mut Self {
        self.env.remove(k);
        self
    }

    pub fn with_account_relay(&mut self) -> &mut Self {
        self.env
            .insert("CUA_RELAY_URL".into(), self.relay.url.clone());
        self.env
            .insert("CUA_OIDC_ISSUER".into(), self.oidc.url.clone());
        self
    }

    pub fn cua_home(&self) -> PathBuf {
        self.dir.path().join(".cua")
    }

    pub fn write_aliyun_config(&self, value: &Value) -> PathBuf {
        let dir = self.dir.path().join(".aliyun");
        std::fs::create_dir_all(&dir).expect("mkdir .aliyun");
        let path = dir.join("config.json");
        std::fs::write(&path, serde_json::to_string_pretty(value).unwrap())
            .expect("write config.json");
        path
    }

    pub fn build_command(&self, args: &[&str]) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(resolve_cua_bin());
        for k in SCRUB_ENV {
            cmd.env_remove(k);
        }
        cmd.envs(&self.env)
            .args(args)
            .current_dir(self.dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }

    pub async fn run(&self, args: &[&str]) -> CmdOut {
        let mut full = vec!["--embedded"];
        full.extend_from_slice(args);
        self.run_raw(&full).await
    }

    pub async fn run_raw(&self, args: &[&str]) -> CmdOut {
        let mut cmd = self.build_command(args);
        cmd.stdin(Stdio::null());
        let child = cmd.spawn().expect("spawn cua");
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .unwrap_or_else(|_| panic!("cua {args:?} timed out"))
            .expect("wait_with_output");
        CmdOut {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    pub async fn run_with_stdin(&self, args: &[&str], stdin_data: &str) -> CmdOut {
        let mut full = vec!["--embedded"];
        full.extend_from_slice(args);
        self.run_raw_with_stdin(&full, stdin_data).await
    }

    pub async fn run_raw_with_stdin(&self, args: &[&str], stdin_data: &str) -> CmdOut {
        let mut cmd = self.build_command(args);
        cmd.stdin(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn cua");
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_data.as_bytes())
                .await
                .expect("write stdin");
            stdin.shutdown().await.ok();
        }
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .unwrap_or_else(|_| panic!("cua {args:?} timed out"))
            .expect("wait_with_output");
        CmdOut {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    pub async fn auth_login(&mut self) -> CmdOut {
        self.with_account_relay();
        let out = self.run(&["auth", "login", "--no-browser"]).await;
        out.ok();
        out
    }

    pub async fn start_daemon(&mut self) -> (String, String) {
        let mut cmd = self.build_command(&["daemon", "start", "--foreground"]);
        cmd.stdin(Stdio::null());
        let child = cmd.spawn().expect("spawn cua daemon");
        self.daemon = Some(child);

        let discovery = self.cua_home().join("daemon.json");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(raw) = std::fs::read_to_string(&discovery)
                && let Ok(v) = serde_json::from_str::<Value>(&raw)
                && let (Some(url), Some(tok)) = (
                    v["loopback_url"].as_str().or_else(|| v["url"].as_str()),
                    v["token"].as_str(),
                )
            {
                return (url.to_string(), tok.to_string());
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out waiting for {}", discovery.display());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub fn walk_cua_home(&self) -> Vec<PathBuf> {
        walk_dir(&self.cua_home())
    }

    pub fn assert_no_secrets_in_non_secret_files(&self, secrets: &[&str]) {
        for path in self.walk_cua_home() {
            let rel = path
                .strip_prefix(self.cua_home())
                .unwrap_or(&path)
                .to_string_lossy();
            if rel.starts_with("secrets") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                for sec in secrets {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(sec.as_bytes());
                    assert!(
                        !text.contains(sec) && !text.contains(&b64),
                        "secret leaked in {} (rel={rel}): {text}",
                        path.display()
                    );
                }
            }
        }
    }

    pub fn assert_no_secrets_anywhere(&self, secrets: &[&str]) {
        for path in self.walk_cua_home() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for sec in secrets {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(sec.as_bytes());
                    assert!(
                        !text.contains(sec) && !text.contains(&b64),
                        "secret persisted unexpectedly in {}: {text}",
                        path.display()
                    );
                }
            }
        }
    }

    pub fn assert_no_unexpected_egress(&self) {
        let blocked = self.proxy.blocked_egress();
        assert!(
            blocked.is_empty(),
            "unexpected non-aliyuncs.com HTTPS CONNECT attempts: {blocked:?}"
        );
    }
}

fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.extend(walk_dir(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

pub fn make_tags(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}
