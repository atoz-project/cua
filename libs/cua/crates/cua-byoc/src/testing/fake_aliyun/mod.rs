// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Canonical fake Alibaba Cloud OpenAPI V3 server (STS, ECS, VPC) verifying
//! `ACS3-HMAC-SHA256` signatures on every request.

pub mod handlers;
mod handlers_net;
pub mod sig;
pub mod state;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::aliyun_ecs::{AliyunEcs, TokenStore};

pub use handlers::{PostHooks, dispatch_locked, handle};
pub use sig::{decode_cloud_init_write_files, decode_ps_puts};
pub use state::{
    BootCallback, BootFailMode, FakeAliyun, FakeImage, FakeInstance, FakeInstanceType, FakeSg,
    FakeVSwitch, FakeVpc, RecordedCall, RunHook, S, StateCallback, ZoneFault,
};

#[derive(Default)]
pub struct MemStore(Mutex<Option<String>>);

impl TokenStore for MemStore {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, t: &str) -> std::io::Result<()> {
        *self.0.lock().unwrap() = Some(t.into());
        Ok(())
    }
    fn clear(&self) -> bool {
        self.0.lock().unwrap().take().is_some()
    }
}

/// Starts an isolated in-memory [`FakeAliyun`] HTTP server and an [`AliyunEcs`]
/// provider wired to it with custom `poll` and optional `~/.aliyun/config.json` path.
pub async fn start_fake_with(
    poll: Duration,
    aliyun_config: Option<PathBuf>,
) -> (Arc<AliyunEcs>, S, Arc<MemStore>) {
    let s: S = Arc::default();
    let app = axum::Router::new().fallback(handle).with_state(s.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let store = Arc::new(MemStore::default());
    let api = Arc::new(
        AliyunEcs::with_endpoints(&base, &base, &base, store.clone(), aliyun_config)
            .with_poll(poll),
    );
    (api, s, store)
}

/// Convenience wrapper for [`start_fake_with`] with `aliyun_config = None`.
pub async fn start_fake(poll: Duration) -> (Arc<AliyunEcs>, S, Arc<MemStore>) {
    start_fake_with(poll, None).await
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    #[test]
    fn extract_machine_id_decodes_b64_write_files() {
        let mid_b64 = base64::engine::general_purpose::STANDARD.encode("cloud-0123456789abcdef\n");
        let ud = format!(
            "#cloud-config\nwrite_files:\n  - path: /etc/cua/relay/machine-id\n    encoding: b64\n    content: {mid_b64}\n"
        );
        assert_eq!(
            super::sig::extract_machine_id(&ud).as_deref(),
            Some("cloud-0123456789abcdef")
        );
    }
}
