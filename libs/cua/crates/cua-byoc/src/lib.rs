// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Your own cloud account as a sandbox location: `--on aws`, `azure`,
//! `gcp`, `modal`, `hetzner` for sandboxes (the SDK, `cua sb`, cua-bench) and, on top, for
//! Spaces.
//!
//! | Provider | How a sandbox runs | Credentials |
//! |---|---|---|
//! | `aws` (EC2) | one small VM per sandbox; Docker runs the image | the AWS CLI's profiles, SSO, assume-role |
//! | `gcp` (Compute Engine) | the same | the gcloud CLI's sign-in, or Cua's issuer (workload identity federation) |
//! | `azure` (Virtual Machines) | the same | Cua's issuer (a managed identity's federated credential) |
//! | `hetzner` (Cloud) | one small server per sandbox; Docker runs the image (containers only: no `/dev/kvm`) | a project API token in the Cua credential store |
//! | `modal` (Sandboxes) | one Modal sandbox (gVisor, or Modal's VM runtime) | `~/.modal.toml` profiles |
//!
//! Every cloud sandbox's cua-spacesd dials out to the cua.ai relay as a
//! machine of the signed-in account, so it needs no inbound port; the SDK
//! reaches it there ([`relay`]). Everything Cua creates is tagged
//! ([`model::tags`]) and recorded ([`Store`]) before it exists; delete,
//! stop, start and [`sweep`] act only on resources the cloud shows with
//! this home's tags.
//!
//! - [`CloudApi`]: what one cloud implements (the `aws`, `gcp`, `modal`
//!   modules).
//! - [`CloudSandboxes`]: a cloud as a sandbox-layer provider.
//! - [`Clouds`]: `cua cloud` (connect, test, status, disconnect, sweep).
//! - [`install`]: registers both on a `SandboxesBuilder`.

use std::path::Path;
use std::sync::Arc;

pub mod alerts;
#[cfg(feature = "aliyun-ecs")]
pub mod aliyun;
#[cfg(feature = "aliyun-ecs")]
pub use aliyun as aliyun_ecs;
#[cfg(feature = "aliyun-ecs")]
pub use aliyun::existing_vpc as aliyun_existing_vpc;
#[cfg(feature = "aliyun-ecs")]
pub use aliyun::net as aliyun_net;
pub mod api;
pub mod audit;
pub mod autosweep;
#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "aws")]
pub mod aws_shares;
#[cfg(feature = "aws")]
pub mod awsnet;
#[cfg(feature = "azure")]
pub mod azure;
pub mod bootlog;
pub mod bootstrap;
pub use bootstrap::win as bootstrap_win;
pub mod cloud_shares;
#[cfg(any(test, feature = "testing"))]
pub mod conformance;
pub mod connect;
#[cfg(feature = "federation")]
pub mod federation;
#[cfg(feature = "gcp")]
pub mod gcp;
#[cfg(feature = "hetzner")]
pub mod hetzner;
pub mod hostnet;
pub mod hosts;
pub mod limits;
pub mod manager;
#[cfg(feature = "modal")]
pub mod modal;
pub mod modal_net;
pub mod model;
pub mod policy;
pub mod provider;
pub mod relay;
#[cfg(feature = "federation")]
pub mod sealed;
pub mod share_edge;
pub mod share_net;
#[cfg(feature = "federation")]
pub mod spend;
pub mod state;
pub mod sweep;
pub(crate) mod target;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod trust;
pub mod usage;

pub use api::{
    CloudApi, PreparedProvision, Result, Secret, SecretSource, Target, Tested, WindowsInitHeader,
};
/// Routes of public TCP shares (they live in `cua-share`; this path stays
/// for the cloud modules).
pub use cua_share::route as share_route;
pub use manager::Clouds;
pub use model::{
    Auth, Billing, Capabilities, Connection, ConnectionExtras, HostType, MaxSize, ProvisionSpec,
    Resource, Supplies, Tier,
};
pub use provider::CloudSandboxes;
pub use relay::{ConnectionRelay, Join, RelayAccess};
pub use state::Store;

/// Every cloud this build includes (its cargo features).
pub fn builtin_apis() -> Vec<Arc<dyn CloudApi>> {
    builtin_apis_for(None)
}

#[allow(clippy::vec_init_then_push)]
fn builtin_apis_for(
    #[cfg_attr(not(feature = "aliyun-ecs"), allow(unused_variables))] home: Option<&Path>,
) -> Vec<Arc<dyn CloudApi>> {
    #[allow(unused_mut)]
    let mut v: Vec<Arc<dyn CloudApi>> = Vec::new();
    #[cfg(feature = "aws")]
    v.push(Arc::new(aws::Aws::new()));
    #[cfg(feature = "modal")]
    v.push(Arc::new(modal::ModalApi::from_env()));
    #[cfg(feature = "gcp")]
    v.push(Arc::new(gcp::Gcp::new()));
    #[cfg(feature = "hetzner")]
    v.push(Arc::new(hetzner::Hetzner::new()));
    #[cfg(feature = "azure")]
    v.push(Arc::new(azure::Azure::new()));
    #[cfg(feature = "aliyun-ecs")]
    v.push(Arc::new(match home {
        Some(h) => aliyun::AliyunEcs::for_home(h),
        None => aliyun::AliyunEcs::new(),
    }));
    v
}

/// The clouds of `home` over `apis`, joining sandboxes to `relay`: the
/// providers to register and the manager behind `cua cloud`.
pub fn clouds(
    home: &Path,
    apis: Vec<Arc<dyn CloudApi>>,
    relay: RelayAccess,
) -> (Vec<Arc<dyn cua_sandbox_core::Provider>>, Arc<Clouds>) {
    for a in &apis {
        a.scope_home(home);
    }
    let store = Arc::new(Store::new(home));
    let providers = apis
        .iter()
        .map(|a| {
            Arc::new(CloudSandboxes::new(a.clone(), store.clone(), relay.clone()))
                as Arc<dyn cua_sandbox_core::Provider>
        })
        .collect();
    (
        providers,
        Arc::new(Clouds::new(home, apis, store).with_relay(relay)),
    )
}

/// Registers this build's clouds on `builder` (a cloud provider replaces a
/// contrib one of the same name), with the state of `home` and the relay
/// of the environment and the `cua auth login` session.
pub fn install(
    builder: cua_sandbox_core::SandboxesBuilder,
    home: &Path,
) -> cua_sandbox_core::SandboxesBuilder {
    install_with(
        builder,
        home,
        builtin_apis_for(Some(home)),
        RelayAccess::from_env(),
    )
}

/// [`install`] with explicit clouds and relay (tests, fixtures).
pub fn install_with(
    mut builder: cua_sandbox_core::SandboxesBuilder,
    home: &Path,
    apis: Vec<Arc<dyn CloudApi>>,
    relay: RelayAccess,
) -> cua_sandbox_core::SandboxesBuilder {
    // Clouds with a choice of engine validate `--runtime` in the placement
    // model like any location.
    for a in &apis {
        let runtimes = a.runtimes();
        if !runtimes.is_empty() {
            let _ = cua_sandbox_core::placement::register_provider(
                cua_sandbox_core::placement::Capabilities {
                    name: a.name().into(),
                    description: format!("your {} account", a.title()),
                    kinds: cloud_kinds(runtimes),
                },
            );
        }
    }
    let (providers, manager) = clouds(home, apis, relay);
    for p in providers {
        builder = builder.provider(p);
    }
    builder.clouds(manager)
}

/// A cloud's engines by kind: a microVM engine (Modal's VM runtime, wire
/// word `microvm`, or Firecracker) runs `--kind microvm`; `native` runs
/// Direct VM Sandboxes (`--kind vm`); the rest run containers.
pub fn cloud_kinds(
    runtimes: Vec<cua_sandbox_core::placement::Runtime>,
) -> Vec<cua_sandbox_core::placement::KindSupport> {
    use cua_sandbox_core::placement::{Kind, KindSupport, Runtime};
    let mut containers = Vec::new();
    let mut vms = Vec::new();
    let mut micro = Vec::new();
    for r in runtimes {
        if r.as_str() == "microvm" || r == Runtime::Firecracker {
            micro.push(r);
        } else if r.as_str() == "native" {
            vms.push(r);
        } else {
            containers.push(r);
        }
    }
    let mut kinds = Vec::new();
    if !containers.is_empty() {
        kinds.push(KindSupport {
            kind: Kind::Container,
            runtimes: containers,
        });
    }
    if !vms.is_empty() {
        kinds.push(KindSupport {
            kind: Kind::Vm,
            runtimes: vms,
        });
    }
    if !micro.is_empty() {
        kinds.push(KindSupport {
            kind: Kind::MicroVm,
            runtimes: micro,
        });
    }
    kinds
}

#[cfg(test)]
mod tests {
    use super::*;
    use cua_sandbox_core::placement::{Kind, Runtime};

    #[test]
    fn cloud_kinds_partitions_native_docker_and_microvm() {
        let kinds = cloud_kinds(vec![
            Runtime::Other("docker".into()),
            Runtime::Other("native".into()),
            Runtime::Other("microvm".into()),
        ]);
        assert_eq!(kinds.len(), 3);
        assert_eq!(kinds[0].kind, Kind::Container);
        assert_eq!(kinds[0].runtimes, vec![Runtime::Other("docker".into())]);
        assert_eq!(kinds[1].kind, Kind::Vm);
        assert_eq!(kinds[1].runtimes, vec![Runtime::Other("native".into())]);
        assert_eq!(kinds[2].kind, Kind::MicroVm);
        assert_eq!(kinds[2].runtimes, vec![Runtime::Other("microvm".into())]);

        let modal = cloud_kinds(vec![Runtime::Gvisor, Runtime::Other("microvm".into())]);
        assert_eq!(modal.len(), 2);
        assert_eq!(modal[0].kind, Kind::Container);
        assert_eq!(modal[1].kind, Kind::MicroVm);
    }

    #[cfg(feature = "aliyun-ecs")]
    #[test]
    fn aliyun_ecs_offers_docker_default_then_native() {
        let api = aliyun_ecs::AliyunEcs::new();
        assert_eq!(
            api.runtimes(),
            vec![
                Runtime::Other("docker".into()),
                Runtime::Other("native".into()),
            ]
        );
    }
}
