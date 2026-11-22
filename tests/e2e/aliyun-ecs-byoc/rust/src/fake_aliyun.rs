// SPDX-License-Identifier: MIT

//! Re-exports the canonical fake Alibaba Cloud OpenAPI V3 server from
//! `cua_byoc::testing::fake_aliyun`.

pub use cua_byoc::testing::fake_aliyun::{
    BootCallback, BootFailMode, FakeAliyun, FakeImage, FakeInstance, FakeInstanceType, FakeSg,
    FakeVSwitch, FakeVpc, RecordedCall, S, StateCallback, ZoneFault, handle,
};
