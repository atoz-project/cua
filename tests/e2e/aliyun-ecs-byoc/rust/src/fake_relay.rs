// SPDX-License-Identifier: MIT

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
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

#[derive(Default)]
struct StaticState {
    public_url: String,
    static_tokens: BTreeSet<String>,
    static_machines: BTreeMap<String, StaticMachine>,
    proxied: Vec<(String, Option<String>)>,
}

#[derive(Clone)]
pub struct FakeRelay {
    pub url: String,
    inner: InnerFakeRelay,
    static_state: Arc<Mutex<StaticState>>,
    task: Arc<tokio::task::JoinHandle<()>>,
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        if Arc::strong_count(&self.task) == 1 {
            self.task.abort();
        }
    }
}

fn bearer_from(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-cua-relay-authorization")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

impl FakeRelay {
    pub async fn start() -> Self {
        let inner = InnerFakeRelay::start().await;
        let static_state = Arc::new(Mutex::new(StaticState::default()));
        let http = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("relay proxy client");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind dual-mode fake relay");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        static_state.lock().unwrap().public_url = url.clone();

        let ctx = Arc::new(RelayCtx {
            inner: inner.clone(),
            static_state: static_state.clone(),
            http: http.clone(),
        });

        let app = Router::new()
            .route("/v1/info", get(handle_info))
            .route("/v1/machines", any(handle_machines))
            .route("/v1/machines/{id}", any(handle_machine_one))
            .route("/m/{id}/health", any(handle_machine_health))
            .route("/m/{id}/{*rest}", any(handle_machine_proxy))
            .fallback(forward_to_inner)
            .with_state(ctx);

        let task = Arc::new(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));

        Self {
            url,
            inner,
            static_state,
            task,
        }
    }

    pub fn add_account(&self, token: &str, id: &str, email: Option<&str>) {
        self.inner.add_account(token, id, email);
    }

    pub fn fresh_sign_in(&self, id: &str) {
        self.inner.fresh_sign_in(id);
    }

    pub fn add_static_token(&self, token: &str) {
        self.static_state
            .lock()
            .unwrap()
            .static_tokens
            .insert(token.to_string());
    }

    pub fn register_static_machine(&self, id: &str, name: &str, env_token: &str) {
        let mut st = self.static_state.lock().unwrap();
        st.static_machines.insert(
            id.to_string(),
            StaticMachine {
                id: id.to_string(),
                name: name.to_string(),
                env_token: env_token.to_string(),
                online: false,
                version: String::new(),
                tunnel_target: None,
            },
        );
    }

    pub fn set_online(&self, id: &str, online: bool, version: &str) {
        self.inner.set_online(id, online, version);
        if let Some(m) = self
            .static_state
            .lock()
            .unwrap()
            .static_machines
            .get_mut(id)
        {
            m.online = online;
            m.version = version.to_string();
        }
    }

    pub fn tunnel(&self, id: &str, target: &str) {
        self.inner.tunnel(id, target);
        if let Some(m) = self
            .static_state
            .lock()
            .unwrap()
            .static_machines
            .get_mut(id)
        {
            m.tunnel_target = Some(target.to_string());
        }
    }

    pub fn machine(&self, id: &str) -> Option<cua_host::relay::Machine> {
        self.inner.machine(id)
    }

    pub fn static_machine(&self, id: &str) -> Option<StaticMachine> {
        self.static_state
            .lock()
            .unwrap()
            .static_machines
            .get(id)
            .cloned()
    }

    pub fn static_machines(&self) -> Vec<StaticMachine> {
        self.static_state
            .lock()
            .unwrap()
            .static_machines
            .values()
            .cloned()
            .collect()
    }

    pub fn register_calls(&self) -> usize {
        self.inner.register_calls()
    }

    pub fn proxied(&self) -> Vec<(String, Option<String>)> {
        let mut out = self.inner.proxied();
        out.extend(self.static_state.lock().unwrap().proxied.clone());
        out
    }

    pub fn fail_registrations(&self, statuses: &[u16]) {
        self.inner.fail_registrations(statuses);
    }

    pub fn fail_deletes(&self, statuses: &[u16]) {
        self.inner.fail_deletes(statuses);
    }
}

struct RelayCtx {
    inner: InnerFakeRelay,
    static_state: Arc<Mutex<StaticState>>,
    http: reqwest::Client,
}

async fn handle_info(State(ctx): State<Arc<RelayCtx>>) -> Response {
    let url = ctx.static_state.lock().unwrap().public_url.clone();
    (
        StatusCode::OK,
        axum::Json(json!({
            "public_url": url,
            "issuer": "fake-relay",
            "account_auth": true,
            "static_tokens": true
        })),
    )
        .into_response()
}

async fn handle_machines(
    State(ctx): State<Arc<RelayCtx>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tok = bearer_from(&headers);
    if method == Method::POST
        && let Some(ref t) = tok
        && ctx.static_state.lock().unwrap().static_tokens.contains(t)
    {
        let payload: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
        let id = payload["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("m-static-{}", rand::random::<u32>()));
        let name = payload["name"].as_str().unwrap_or(&id).to_string();
        let env_token = payload["env_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("env_{:032x}", rand::random::<u128>()));
        let mut st = ctx.static_state.lock().unwrap();
        let public_url = st.public_url.clone();
        st.static_machines.insert(
            id.clone(),
            StaticMachine {
                id: id.clone(),
                name: name.clone(),
                env_token: env_token.clone(),
                online: false,
                version: String::new(),
                tunnel_target: None,
            },
        );
        return (
            StatusCode::CREATED,
            axum::Json(json!({
                "machine": {
                    "id": id,
                    "name": name,
                    "online": false,
                    "sharing": true,
                    "url": format!("{public_url}/m/{id}"),
                },
                "machine_token": env_token,
                "env_token": env_token,
            })),
        )
            .into_response();
    }
    forward_request(&ctx.http, &ctx.inner.url, method, &uri, &headers, body).await
}

async fn handle_machine_one(
    State(ctx): State<Arc<RelayCtx>>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let static_entry = ctx
        .static_state
        .lock()
        .unwrap()
        .static_machines
        .get(&id)
        .cloned();
    if let Some(m) = static_entry {
        let tok = bearer_from(&headers);
        let static_tokens = ctx.static_state.lock().unwrap().static_tokens.clone();
        let authorized = tok
            .as_deref()
            .is_some_and(|t| t == m.env_token || static_tokens.contains(t));
        if !authorized {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "invalid or missing static/env bearer token"})),
            )
                .into_response();
        }
        if method == Method::DELETE {
            ctx.static_state.lock().unwrap().static_machines.remove(&id);
            return StatusCode::NO_CONTENT.into_response();
        }
        let public_url = ctx.static_state.lock().unwrap().public_url.clone();
        return (
            StatusCode::OK,
            axum::Json(json!({
                "id": m.id,
                "name": m.name,
                "online": m.online,
                "sharing": true,
                "version": m.version,
                "url": format!("{public_url}/m/{}", m.id),
            })),
        )
            .into_response();
    }
    forward_request(&ctx.http, &ctx.inner.url, method, &uri, &headers, body).await
}

async fn handle_machine_health(
    State(ctx): State<Arc<RelayCtx>>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let static_entry = ctx
        .static_state
        .lock()
        .unwrap()
        .static_machines
        .get(&id)
        .cloned();
    if let Some(m) = static_entry {
        let tok = bearer_from(&headers);
        if tok.as_deref() != Some(m.env_token.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "invalid or missing env_token"})),
            )
                .into_response();
        }
        if m.online {
            return (
                StatusCode::OK,
                axum::Json(json!({"ok": true, "online": true, "version": m.version})),
            )
                .into_response();
        }
        return (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({"error": "machine offline"})),
        )
            .into_response();
    }
    forward_request(&ctx.http, &ctx.inner.url, method, &uri, &headers, body).await
}

async fn handle_machine_proxy(
    State(ctx): State<Arc<RelayCtx>>,
    Path((id, rest)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let static_entry = ctx
        .static_state
        .lock()
        .unwrap()
        .static_machines
        .get(&id)
        .cloned();
    if let Some(m) = static_entry {
        let tok = bearer_from(&headers);
        if tok.as_deref() != Some(m.env_token.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "invalid or missing env_token"})),
            )
                .into_response();
        }
        ctx.static_state
            .lock()
            .unwrap()
            .proxied
            .push((uri.path().to_string(), tok));
        if !m.online {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "the computer is not connected"})),
            )
                .into_response();
        }
        if let Some(target) = m.tunnel_target {
            let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
            let target_url = format!("{}/{rest}{query}", target.trim_end_matches('/'));
            return forward_to_target(&ctx.http, &target_url, method, &headers, body).await;
        }
        return (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({"error": "no tunnel registered"})),
        )
            .into_response();
    }
    forward_request(&ctx.http, &ctx.inner.url, method, &uri, &headers, body).await
}

async fn forward_to_inner(
    State(ctx): State<Arc<RelayCtx>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    forward_request(&ctx.http, &ctx.inner.url, method, &uri, &headers, body).await
}

async fn forward_request(
    http: &reqwest::Client,
    base: &str,
    method: Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{pq}", base.trim_end_matches('/'));
    forward_to_target(http, &url, method, headers, body).await
}

async fn forward_to_target(
    http: &reqwest::Client,
    url: &str,
    method: Method,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let mut req = http.request(method, url).body(body);
    for (k, v) in headers {
        if k != axum::http::header::HOST && k != axum::http::header::CONTENT_LENGTH {
            req = req.header(k, v);
        }
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let mut out = Response::builder().status(resp.status());
    for (k, v) in resp.headers() {
        if k != axum::http::header::CONTENT_LENGTH && k != axum::http::header::TRANSFER_ENCODING {
            out = out.header(k, v);
        }
    }
    let bytes = resp.bytes().await.unwrap_or_default();
    out.body(axum::body::Body::from(bytes))
        .unwrap_or_else(|e| (StatusCode::BAD_GATEWAY, e.to_string()).into_response())
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
        let reqs_clone = requests.clone();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake oidc");
        let url = format!("http://{}", listener.local_addr().expect("oidc addr"));
        let base_url = url.clone();

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let base = base_url.clone();
                    move || async move {
                        axum::Json(json!({
                            "token_endpoint": format!("{base}/token"),
                            "device_authorization_endpoint": format!("{base}/device"),
                            "revocation_endpoint": format!("{base}/revoke"),
                        }))
                    }
                }),
            )
            .route(
                "/device",
                axum::routing::post({
                    let reqs = reqs_clone.clone();
                    move |body: Bytes| async move {
                        reqs.lock()
                            .unwrap()
                            .push(("/device".into(), String::from_utf8_lossy(&body).into()));
                        axum::Json(json!({
                            "device_code": "dc-e2e-1",
                            "user_code": "E2E-CODE",
                            "verification_uri": "https://login.test/device",
                            "verification_uri_complete": "https://login.test/device?code=E2E-CODE",
                            "expires_in": 60,
                            "interval": 1
                        }))
                    }
                }),
            )
            .route(
                "/token",
                axum::routing::post({
                    let reqs = reqs_clone.clone();
                    let polls = polls.clone();
                    let relay = relay.clone();
                    move |body: Bytes| async move {
                        let body_str = String::from_utf8_lossy(&body).to_string();
                        reqs.lock()
                            .unwrap()
                            .push(("/token".into(), body_str.clone()));
                        let grant = url::form_urlencoded::parse(body_str.as_bytes())
                            .find(|(k, _)| k == "grant_type")
                            .map(|(_, v)| v.into_owned())
                            .unwrap_or_default();
                        if grant == "urn:ietf:params:oauth:grant-type:device_code"
                            && polls.fetch_add(1, Ordering::SeqCst) == 0
                        {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(json!({"error": "authorization_pending"})),
                            )
                                .into_response();
                        }
                        let token = unsigned_jwt(json!({
                            "preferred_username": "e2e-tester",
                            "email": "e2e@cua.test",
                            "sub": "u-e2e-1",
                            "azp": "cua-cli",
                            "iss": "https://auth.test",
                            "exp": 4_102_444_800_i64,
                        }));
                        if let Some(ref r) = relay {
                            r.add_account(&token, "u-e2e-1", Some("e2e@cua.test"));
                            r.fresh_sign_in("u-e2e-1");
                        }
                        (
                            StatusCode::OK,
                            axum::Json(json!({
                                "access_token": token,
                                "refresh_token": "rt-e2e-1",
                                "expires_in": 3600,
                                "token_type": "Bearer"
                            })),
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/revoke",
                axum::routing::post(|| async { axum::Json(json!({})) }),
            );

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
