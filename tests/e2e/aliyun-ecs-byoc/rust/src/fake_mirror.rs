// SPDX-License-Identifier: MIT

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

#[derive(Default)]
pub struct MirrorState {
    pub linux_bytes: Vec<u8>,
    pub windows_bytes: Vec<u8>,
    pub linux_sha256: String,
    pub windows_sha256: String,
    pub status_override: Option<u16>,
    pub corrupt_bytes: bool,
    pub requests: Vec<String>,
}

pub struct FakeMirror {
    pub url: String,
    pub state: Arc<Mutex<MirrorState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeMirror {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeMirror {
    pub async fn start() -> Self {
        let linux_bytes = b"#!/bin/sh\necho fake-cua-spacesd-linux\n".to_vec();
        let windows_bytes = b"MZfake-cua-spacesd-windows-pe".to_vec();
        let linux_sha256 = hex::encode(Sha256::digest(&linux_bytes));
        let windows_sha256 = hex::encode(Sha256::digest(&windows_bytes));

        let state = Arc::new(Mutex::new(MirrorState {
            linux_bytes,
            windows_bytes,
            linux_sha256,
            windows_sha256,
            status_override: None,
            corrupt_bytes: false,
            requests: Vec::new(),
        }));

        let app = Router::new()
            .route("/{file}", get(serve_file))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake mirror");
        let addr = listener.local_addr().expect("mirror addr");
        let url = format!("http://{addr}");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self { url, state, task }
    }

    pub fn linux_url(&self) -> String {
        format!("{}/cua-spacesd", self.url)
    }

    pub fn windows_url(&self) -> String {
        format!("{}/cua-spacesd.exe", self.url)
    }

    pub fn linux_sha256(&self) -> String {
        self.state.lock().unwrap().linux_sha256.clone()
    }

    pub fn windows_sha256(&self) -> String {
        self.state.lock().unwrap().windows_sha256.clone()
    }

    pub fn set_status_override(&self, status: Option<u16>) {
        self.state.lock().unwrap().status_override = status;
    }

    pub fn set_corrupt_bytes(&self, corrupt: bool) {
        self.state.lock().unwrap().corrupt_bytes = corrupt;
    }

    pub fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().requests.clone()
    }
}

async fn serve_file(
    State(s): State<Arc<Mutex<MirrorState>>>,
    Path(file): Path<String>,
) -> Response {
    let mut st = s.lock().unwrap();
    st.requests.push(file.clone());
    if let Some(code) = st.status_override {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (status, format!("mirror injected error {code}")).into_response();
    }
    match file.as_str() {
        "cua-spacesd" => {
            let mut body = st.linux_bytes.clone();
            if st.corrupt_bytes {
                body.extend_from_slice(b"-CORRUPTED");
            }
            (StatusCode::OK, body).into_response()
        }
        "cua-spacesd.sha256" => (
            StatusCode::OK,
            format!("{}  cua-spacesd\n", st.linux_sha256),
        )
            .into_response(),
        "cua-spacesd.exe" => {
            let mut body = st.windows_bytes.clone();
            if st.corrupt_bytes {
                body.extend_from_slice(b"-CORRUPTED");
            }
            (StatusCode::OK, body).into_response()
        }
        "cua-spacesd.exe.sha256" => (
            StatusCode::OK,
            format!("{}  cua-spacesd.exe\n", st.windows_sha256),
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
