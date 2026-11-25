// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! What one cloud implements ([`CloudApi`]). Everything
//! provider-independent (relay registration, records, tags, the wait,
//! rollback, the sweeper's rules) is in [`crate::CloudSandboxes`], the
//! sandbox-layer provider built on it; a cloud only maps it onto its API.
//!
//! Safety contract every implementation keeps:
//!
//! - [`CloudApi::provision`] tags every resource it creates with
//!   [`crate::ProvisionSpec::tags`] in the create call itself (never after),
//!   and creates nothing else: no IAM users or keys, no change to an
//!   existing network, security group or firewall (it may create one
//!   dedicated, tagged, outbound-only group or rule and reuse it).
//! - [`CloudApi::delete`], [`CloudApi::stop`] and [`CloudApi::start`] read
//!   the resource's current tags first and refuse unless
//!   [`crate::model::is_ours`] holds for the owner they are given.
//! - [`CloudApi::list_owned`] filters by the `cua-managed` and `cua-owner`
//!   tags on the server and checks them again on every row it returns.

use std::collections::BTreeMap;

use async_trait::async_trait;
use cua_sandbox_core::Error;
use cua_sandbox_core::byoc::{CloudCheck, CloudCredentials, CloudKind};

pub use cua_sandbox_core::byoc::CloudTarget as Target;

use crate::model::{Capabilities, Connection, HostType, ProvisionSpec, Resource, Tier};

/// This crate's result.
pub type Result<T> = std::result::Result<T, Error>;

/// A cloud call failed (the `cloud` error kind): `what` it was doing and
/// the cloud's own message.
pub fn cloud_err(provider: &str, what: &str, e: impl std::fmt::Display) -> Error {
    Error::Cloud(format!("{provider}: {what}: {e}"))
}

/// `target` as a connection's names (a provider fills in its defaults).
pub fn target_of(c: &Connection) -> Target {
    let some = |s: &String| (!s.is_empty()).then(|| s.clone());
    Target {
        provider: c.provider.clone(),
        profile: some(&c.profile),
        region: some(&c.region),
        zone: some(&c.zone),
        project: some(&c.project),
        environment: some(&c.environment),
        token: None,
        relay_url: c.relay_url.clone(),
        relay_mode: c.relay_mode,
        relay_token: None,
        spacesd_download_url: c.spacesd_download_url.clone(),
        vpc_id: c.vpc_id.clone(),
        vswitch_id: c.vswitch_id.clone(),
        no_public_ip: c.no_public_ip,
        windows_image_id: c.windows_image_id.clone(),
        linux_image_id: c.linux_image_id.clone(),
        instance_type: c.instance_type.clone(),
    }
}

/// Resolved effective machine sizing (vCPUs, RAM, effective disk GiB, total
/// hourly price including disk) returned by [`CloudApi::prepare_provision`]
/// before `--max-size` and `--budget` preflight checks.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolvedSizing {
    pub machine_type: Option<String>,
    pub vcpus: u32,
    pub memory_mb: u64,
    pub disk_gb: Option<u32>,
    pub usd_per_hour: f64,
}

/// Single-pass resolved sizing, Cloud Image ID, and candidate availability
/// zones returned by [`CloudApi::prepare_provision`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PreparedProvision {
    pub sizing: Option<ResolvedSizing>,
    pub cloud_image_id: Option<String>,
    /// Optional ordered availability zones where the selected shape has stock.
    pub candidate_zones: Option<Vec<String>>,
}

impl PreparedProvision {
    /// Writes resolved sizing, Cloud Image ID, and stock-zone hints onto `spec`.
    pub fn apply_to(&self, spec: &mut ProvisionSpec) {
        if let Some(sizing) = &self.sizing {
            if let Some(mt) = sizing
                .machine_type
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                spec.machine_type = mt.to_string();
            }
            if let Some(disk_gb) = sizing.disk_gb {
                spec.disk_gb = disk_gb;
            }
        }
        if let Some(img) = &self.cloud_image_id {
            spec.cloud_image_id = Some(img.clone());
        }
        if self.candidate_zones.is_some() {
            spec.candidate_zones = self.candidate_zones.clone();
        }
        spec.prepared = true;
    }
}

/// A cloud API token in memory: never printed (`Debug` says `redacted`),
/// never serialized, and wiped when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    /// Holds `s`.
    pub fn new(s: impl Into<String>) -> Self {
        Secret(zeroize::Zeroizing::new(s.into()))
    }

    /// The token, to put in a request.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

/// Where a cloud gets the API token of a connection whose token is sealed
/// to the account's devices ([`crate::model::Auth::Sealed`]). The clouds
/// that take a token ask it before their own local sources.
#[async_trait]
pub trait SecretSource: Send + Sync + 'static {
    /// `None`: `provider`'s connection is not sealed (use the local
    /// token). `Some(Err)`: it is, and could not be opened here (the
    /// error says why); a local token is then not used in its place.
    async fn secret(&self, provider: &str) -> Option<Result<Secret>>;

    /// Whether `provider`'s connection is sealed (without opening it).
    fn sealed(&self, provider: &str) -> bool;
}

/// The result of [`CloudApi::test`].
#[derive(Clone, Debug, Default)]
pub struct Tested {
    /// The account, project or workspace reached.
    pub account: String,
    /// The checks, in order.
    pub checks: Vec<CloudCheck>,
}

impl Tested {
    /// Whether every check passed.
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    /// Adds a check.
    pub fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        self.checks.push(CloudCheck {
            name: name.into(),
            ok,
            detail: detail.into(),
        });
    }
}

/// Outcome of [`CloudApi::delete_in_sweep`] when a shared resource may be
/// temporarily kept while decommissioned instances await scheduled cloud
/// release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SweepDelete {
    /// Resource was deleted (or was already absent).
    Deleted,
    /// Shared resource is still held only by stopped decommissioned instances
    /// awaiting their scheduled cloud release timer.
    Held {
        /// Human-readable reason surfaced in sweep output.
        reason: String,
    },
}

/// One cloud.
#[async_trait]
pub trait CloudApi: Send + Sync + 'static {
    /// The location word (`aws`).
    fn name(&self) -> &'static str;

    /// How people name it (`AWS`, `Google Cloud`, `Modal`).
    fn title(&self) -> &'static str;

    /// How it runs a sandbox.
    fn tier(&self) -> Tier;

    /// The CPU architectures of the machines it picks, preferred first
    /// (`arm64` where it is cheaper).
    fn arches(&self) -> Vec<&'static str>;

    /// The engines it offers for `--runtime`, default first (empty: one
    /// engine, `--runtime` does not apply).
    fn runtimes(&self) -> Vec<cua_sandbox_core::placement::Runtime> {
        vec![]
    }

    /// Guest operating systems this cloud runs (`"linux"`, `"windows"`).
    fn supported_oses(&self) -> &'static [&'static str] {
        &["linux"]
    }

    /// Default boot disk size in GiB for `family`.
    fn default_disk_gb(&self, family: &str) -> u32 {
        crate::provider::disk_for(family)
    }

    /// Estimated hourly USD cost per GiB of boot disk storage.
    fn disk_usd_per_gb_hour(&self) -> f64 {
        0.0
    }

    /// Effective `(vcpus, memory_mb)` checked against `--max-size` when
    /// creating `family`.
    fn check_size_for(
        &self,
        _family: &str,
        cpus: u32,
        memory_mb: u64,
    ) -> (Option<u32>, Option<u64>) {
        (
            Some(cpus).filter(|c| *c > 0),
            Some(memory_mb).filter(|m| *m > 0),
        )
    }
    /// Whether the cloud enforces a Space's network rules itself, outside
    /// the guest ([`crate::modal_net`]). Otherwise a Space that asks for
    /// rules is refused here, never created without them.
    fn takes_network_rules(&self) -> bool {
        false
    }

    /// Whether this cloud supports connection-level default Cloud Image IDs
    /// (`--windows-image-id`, `--linux-image-id`) and default `--instance-type`.
    fn supports_image_defaults(&self) -> bool {
        false
    }

    /// Whether this cloud supports per-create `--cloud-image-id`, `--instance-type`,
    /// and `--disk` / `disk_gb` overrides.
    fn supports_custom_image_and_sizing(&self) -> bool {
        false
    }

    /// Whether this cloud supports attaching to an existing VPC/VSwitch and
    /// suppressing public IP assignment (`--vpc-id`, `--vswitch-id`, `--no-public-ip`).
    fn supports_custom_vpc(&self) -> bool {
        false
    }

    /// Scopes any home-backed credential store to `home` (set by [`crate::clouds`]
    /// and [`crate::install`]). Default: no-op.
    fn scope_home(&self, _home: &std::path::Path) {}

    /// Resolves effective machine sizing, Cloud Image ID, and any
    /// provider-specific launch plan in a single pass before limit checks and
    /// [`CloudApi::provision`].
    async fn prepare_provision(
        &self,
        _conn: &Connection,
        _spec: &ProvisionSpec,
    ) -> Result<PreparedProvision> {
        Ok(PreparedProvision::default())
    }

    /// Whether this machine has the cloud's CLI sign-in or config, and
    /// where (never reading a secret into Cua).
    fn detect(&self) -> CloudCredentials;

    /// `target` with this provider's defaults filled in (the profile's
    /// region, gcloud's project).
    fn resolve(&self, target: &Target) -> Result<Connection>;
    /// Called with the target of a connect or test before its checks: a
    /// cloud that takes an API token (Hetzner) holds `target.token` for
    /// them. Nothing is saved yet.
    fn stage_secret(&self, _target: &Target) {}

    /// Called after a connect's checks passed: saves what
    /// [`CloudApi::stage_secret`] held (or the environment's token) in the
    /// Cua credential store.
    fn persist_secret(&self) -> Result<()> {
        Ok(())
    }

    /// Called on disconnect: removes what [`CloudApi::persist_secret`] saved.
    fn forget_secret(&self) {}

    /// Drops what [`CloudApi::stage_secret`] held without saving it (a
    /// token that is sealed instead).
    fn unstage_secret(&self) {}

    /// Whether its API token can be sealed to the account's devices
    /// ([`crate::model::Auth::Sealed`]: Hetzner, Modal).
    fn seals(&self) -> bool {
        false
    }

    /// The API token a connect would use: `target.token`, else the one
    /// this device already has (the saved token, the environment's, the
    /// cloud CLI's). For sealing it ([`CloudApi::seals`]); `None` when
    /// there is none or the cloud takes no token.
    fn local_secret(&self, _target: &Target) -> Option<Secret> {
        None
    }

    /// Where the tokens of sealed connections come from (set once, by
    /// [`crate::Clouds`]).
    fn attach_secrets(&self, _source: std::sync::Arc<dyn SecretSource>) {}

    /// What it can run for each image family on `conn`, the machine type
    /// Cua picks and the estimated hourly cost.
    fn kinds(&self, conn: &Connection) -> Vec<CloudKind>;

    /// Checks `conn` without creating anything.
    async fn test(&self, conn: &Connection) -> Tested;

    /// Creates what one sandbox needs, tagged with `spec.tags`, and returns
    /// every resource it created (the instance or sandbox first). A
    /// failure leaves nothing behind that it could delete.
    async fn provision(&self, conn: &Connection, spec: &ProvisionSpec) -> Result<Vec<Resource>>;

    /// The resource's current state (`pending`, `running`, `stopping`,
    /// `stopped`, `terminated`, `gone`) and its tags (`None`: gone).
    async fn describe(
        &self,
        conn: &Connection,
        r: &Resource,
    ) -> Result<Option<(String, BTreeMap<String, String>)>>;

    /// Stops it (refused unless its tags are `owner`'s). Platforms that
    /// cannot stop return `invalid_argument` saying so.
    async fn stop(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()>;

    /// Starts it (refused unless its tags are `owner`'s).
    async fn start(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()>;

    /// Deletes it (refused unless its tags are `owner`'s). Deleting one
    /// already gone is not an error.
    async fn delete(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()>;

    /// Deletes `r` during a sweep, returning [`SweepDelete::Held`] instead of
    /// failing when only stopped decommissioned instances keep a shared
    /// resource attached.
    async fn delete_in_sweep(
        &self,
        conn: &Connection,
        r: &Resource,
        owner: &str,
    ) -> Result<SweepDelete> {
        self.delete(conn, r, owner)
            .await
            .map(|()| SweepDelete::Deleted)
    }

    /// Every resource in `conn`'s account and region tagged
    /// `cua-managed=true` and `cua-owner=<owner>`.
    async fn list_owned(&self, conn: &Connection, owner: &str) -> Result<Vec<Resource>>;

    /// What it supplies to the elastic pool, how it bills, where and its
    /// limits (`provider-contract.md`). Default: nothing (one sandbox per
    /// machine only).
    fn capabilities(&self, _conn: &Connection) -> Capabilities {
        Capabilities::default()
    }

    /// The machine types it offers on `conn`, cheapest first (live when the
    /// API has prices, else a built-in table). Default: none.
    async fn host_types(&self, _conn: &Connection) -> Result<Vec<HostType>> {
        Ok(vec![])
    }

    /// The machine's console or serial log as the cloud has it (`None`: the
    /// cloud keeps none, or nothing is there yet). Read-only. A failed
    /// create reads it before deleting the machine, so the reason it never
    /// came online survives; the caller filters secrets and bounds the time.
    async fn boot_log(&self, _conn: &Connection, _r: &Resource) -> Result<Option<String>> {
        Ok(None)
    }
}

/// How long to wait before retry `n` (1-based) of a rate-limited or
/// briefly unavailable cloud call: 0.25 s doubling, at most 3 retries.
#[cfg_attr(
    not(any(
        feature = "gcp",
        feature = "azure",
        feature = "modal",
        feature = "aliyun-ecs"
    )),
    allow(dead_code)
)]
pub(crate) fn retry_backoff(n: u32) -> Option<std::time::Duration> {
    (n <= 3).then(|| std::time::Duration::from_millis(250 << (n - 1)))
}

/// Whether an HTTP answer is worth a retry: 429 and 503 always (the cloud
/// did not act on the call), 500, 502 and 504 only for reads and deletes
/// (a create that may have happened is never repeated).
#[cfg_attr(
    not(any(
        feature = "gcp",
        feature = "azure",
        feature = "modal",
        feature = "aliyun-ecs"
    )),
    allow(dead_code)
)]
pub(crate) fn retryable_status(status: u16, idempotent: bool) -> bool {
    matches!(status, 429 | 503) || (idempotent && matches!(status, 500 | 502 | 504))
}

/// Drops any staged secret on a [`CloudApi`] when the guard leaves scope
/// (including across early returns or cancelled futures).
pub(crate) struct UnstageGuard<'a>(pub &'a dyn CloudApi);

impl Drop for UnstageGuard<'_> {
    fn drop(&mut self) {
        self.0.unstage_secret();
    }
}
