// SPDX-License-Identifier: MIT

//! Thin E2E wrapper over [`cua_host::testing::FakeRelay`] (Account + Static
//! Relay Mode) plus [`FakeOidc`] for hermetic device-login scenarios.

use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

use axum::Router;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use base64::Engine as _;
use cua_host::testing::FakeRelay as InnerFakeRelay;
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct StaticMachine {
    pub id: String,
    pub name: String,
    pub env_token: String,
    pub online: bool,
    pub version: String,
    pub tunnel_target: Option<String>,
}

#[derive(Clone)]
pub struct FakeRelay {
    pub url: String,
    inner: InnerFakeRelay,
    static_machines: Arc<Mutex<BTreeMap<String, StaticMachine>>>,
}

impl std::ops::Deref for FakeRelay {
    type Target = InnerFakeRelay;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl FakeRelay {
    pub async fn start() -> Self {
        let inner = InnerFakeRelay::start().await;
        Self {
            url: inner.url.clone(),
            inner,
            static_machines: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Simulates a guest joining a static relay (ADR 0003: no control-plane
    /// `POST /v1/machines` route exists in Static Relay Mode).
    pub fn register_static_machine(&self, id: &str, name: &str, env_token: &str) {
        self.static_machines.lock().unwrap().insert(
            id.into(),
            StaticMachine {
                id: id.into(),
                name: name.into(),
                env_token: env_token.into(),
                online: false,
                version: String::new(),
                tunnel_target: None,
            },
        );
        self.inner.set_static_online(id, false, Some(env_token));
    }

    pub fn set_online(&self, id: &str, online: bool, version: &str) {
        self.inner.set_online(id, online, version);
        let env_tok = self.static_machines.lock().unwrap().get_mut(id).map(|m| {
            m.online = online;
            m.version = version.into();
            m.env_token.clone()
        });
        if let Some(tok) = env_tok {
            self.inner.set_static_online(id, online, Some(&tok));
        }
    }

    pub fn tunnel(&self, id: &str, target: &str) {
        self.inner.tunnel(id, target);
        if let Some(m) = self.static_machines.lock().unwrap().get_mut(id) {
            m.tunnel_target = Some(target.into());
        }
    }

    pub fn static_machine(&self, id: &str) -> Option<StaticMachine> {
        self.static_machines.lock().unwrap().get(id).cloned()
    }

    pub fn static_machines(&self) -> Vec<StaticMachine> {
        self.static_machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }
}

pub fn unsigned_jwt(claims: Value) -> String {
    let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    format!(
        "{}.{}.sig",
        enc(br#"{"alg":"none"}"#),
        enc(claims.to_string().as_bytes())
    )
}

pub struct FakeOidc {
    pub url: String,
    pub requests: Arc<Mutex<Vec<(String, String)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeOidc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeOidc {
    pub async fn start(relay: Option<FakeRelay>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let polls = Arc::new(AtomicU32::new(0));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake oidc");
        let url = format!("http://{}", listener.local_addr().expect("oidc addr"));
        let (base, reqs_dev, reqs_tok) = (url.clone(), requests.clone(), requests.clone());

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move {
                    axum::Json(json!({
                        "token_endpoint": format!("{base}/token"),
                        "device_authorization_endpoint": format!("{base}/device"),
                        "revocation_endpoint": format!("{base}/revoke"),
                    }))
                }),
            )
            .route(
                "/device",
                post(move |body: Bytes| async move {
                    reqs_dev.lock().unwrap().push(("/device".into(), String::from_utf8_lossy(&body).into()));
                    axum::Json(json!({
                        "device_code": "dc-e2e-1", "user_code": "E2E-CODE",
                        "verification_uri": "https://login.test/device",
                        "verification_uri_complete": "https://login.test/device?code=E2E-CODE",
                        "expires_in": 60, "interval": 1
                    }))
                }),
            )
            .route(
                "/token",
                post(move |body: Bytes| async move {
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    reqs_tok.lock().unwrap().push(("/token".into(), body_str.clone()));
                    let grant = url::form_urlencoded::parse(body_str.as_bytes())
                        .find(|(k, _)| k == "grant_type")
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default();
                    if grant == "urn:ietf:params:oauth:grant-type:device_code"
                        && polls.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "authorization_pending"})))
                            .into_response();
                    }
                    let token = unsigned_jwt(json!({
                        "preferred_username": "e2e-tester", "email": "e2e@cua.test",
                        "sub": "u-e2e-1", "azp": "cua-cli", "iss": "https://auth.test", "exp": 4_102_444_800_i64,
                    }));
                    if let Some(ref r) = relay {
                        r.add_account(&token, "u-e2e-1", Some("e2e@cua.test"));
                        r.fresh_sign_in("u-e2e-1");
                    }
                    (StatusCode::OK, axum::Json(json!({
                        "access_token": token, "refresh_token": "rt-e2e-1",
                        "expires_in": 3600, "token_type": "Bearer"
                    }))).into_response()
                }),
            )
            .route("/revoke", post(|| async { axum::Json(json!({})) }));

        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url,
            requests,
            task,
        }
    }
}
