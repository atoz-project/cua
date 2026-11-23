// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Canonical fake Alibaba Cloud OpenAPI V3 server (STS, ECS, VPC) verifying
//! `ACS3-HMAC-SHA256` signatures on every request.

pub mod handlers;
mod handlers_net;
pub mod sig;
pub mod state;

pub use handlers::{PostHooks, dispatch_locked, handle};
pub use sig::{decode_cloud_init_write_files, decode_ps_puts};
pub use state::{
    BootCallback, BootFailMode, FakeAliyun, FakeImage, FakeInstance, FakeInstanceType, FakeSg,
    FakeVSwitch, FakeVpc, RecordedCall, RunHook, S, StateCallback, ZoneFault,
};

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
