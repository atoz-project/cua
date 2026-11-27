// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! [`CloudSandboxes`]: one cloud as a sandbox-layer
//! [`cua_sandbox_core::Provider`]. The provider-independent flow of a
//! create, get, delete, stop and start: the relay machine the sandbox joins
//! as, the record before the cloud call, tags, the wait until it is online,
//! and rollback of everything a failed create made. The cloud's own calls
//! are its [`CloudApi`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cua_sandbox_core::byoc::DETAIL_RELAY_MACHINE;
use cua_sandbox_core::provider::{
    ImageMode, PortExposure, ProviderCapabilities, ProviderCreate, ProviderInstance, RunKind,
};
use cua_sandbox_core::{Error, ServiceEndpoint, Status};

use crate::api::{CloudApi, Result};
use crate::audit;
use crate::bootlog;
use crate::bootstrap::{
    VmBoot, WindowsVmBoot, cloud_init, linux_native_cloud_init, windows_user_data,
};
use crate::model::{self, Connection, ProvisionSpec, Resource, Tier, now};
use crate::relay::{ConnectionRelay, RelayAccess};
use crate::state::Store;
use crate::target::{create_family, resolve_kind_and_runtime, validate_custom_create_options};

/// How long a new cloud machine may take to come online on the relay: a
/// VM's first boot installs Docker or runs Windows `vminit`, binary download, and AutoLogon reboot.
pub const ONLINE_WAIT: Duration = Duration::from_secs(20 * 60);

/// Instance details (`provider_details`).
pub mod detail {
    /// Where it runs ("AWS · us-west-2").
    pub const PLACE: &str = cua_sandbox_core::byoc::DETAIL_PLACE;
    /// The provider-attested automatic release time (RFC 3339).
    pub const AUTO_RELEASE_TIME: &str = "auto_release_time";
    /// The machine type.
    pub const MACHINE_TYPE: &str = "machine_type";
    /// The provider-attested cloud image ID.
    pub const CLOUD_IMAGE_ID: &str = "cloud_image_id";
    /// The estimated cost per hour (US dollars).
    pub const USD_PER_HOUR: &str = "usd_per_hour";
    /// When it expires (RFC 3339), when it does.
    pub const EXPIRES: &str = "expires";
    /// The engine it runs on, when the cloud offers a choice (`vm`).
    pub const RUNTIME: &str = "runtime";
}

/// The image family a reference belongs to (what [`CloudApi::kinds`]
/// prices).
pub fn family_of(reference: &str) -> &'static str {
    let r = reference.to_ascii_lowercase();
    if r.contains("windows") {
        "windows"
    } else if r.contains("omarchy") {
        "omarchy"
    } else if r.contains("macos") {
        "macos"
    } else if r.contains("-slim") {
        "linux-slim"
    } else {
        "linux"
    }
}

/// One cloud as a sandbox provider.
pub struct CloudSandboxes {
    api: Arc<dyn CloudApi>,
    store: Arc<Store>,
    relay: RelayAccess,
}

pub(crate) fn merge_refreshed_record(rec: &Resource, fresh: Resource) -> Resource {
    let mut updated = rec.clone();
    updated.name = fresh.name;
    updated.region = fresh.region;
    updated.zone = fresh.zone;
    updated.state = if rec.state == "failed" {
        rec.state.clone()
    } else {
        fresh.state
    };
    updated.expires = fresh.expires;
    updated.tags = fresh.tags;
    updated.extra.remove(detail::AUTO_RELEASE_TIME);
    updated.extra.extend(fresh.extra);
    updated
}

impl CloudSandboxes {
    /// `api`, recording into `store`, joining its sandboxes to `relay`.
    pub fn new(api: Arc<dyn CloudApi>, store: Arc<Store>, relay: RelayAccess) -> Self {
        CloudSandboxes { api, store, relay }
    }

    /// The cloud's API.
    pub fn api(&self) -> &Arc<dyn CloudApi> {
        &self.api
    }

    fn io(e: std::io::Error) -> Error {
        Error::Io(e)
    }

    fn connection(&self) -> Result<Connection> {
        self.store
            .connection(self.api.name())
            .map_err(Self::io)?
            .ok_or_else(|| {
                Error::ContribNotConfigured(format!(
                    "{} is not connected: run `cua cloud connect {}` first (it checks the \
                     account without creating anything)",
                    self.api.title(),
                    self.api.name()
                ))
            })
    }

    fn connection_relay(&self, conn: &Connection) -> Result<ConnectionRelay> {
        ConnectionRelay::for_connection(conn, &self.relay)
    }

    async fn forget_connection_machine(&self, conn: &Connection, machine: &str) {
        match self.connection_relay(conn) {
            Ok(relay) => {
                relay
                    .forget_machine(&self.store, self.api.name(), machine)
                    .await;
            }
            Err(e) => {
                tracing::warn!(machine, "skipping relay cleanup: {e}");
                if conn.is_static_relay() {
                    let _ = crate::relay::remove_env_token(
                        self.store.home().as_deref(),
                        self.api.name(),
                        machine,
                    );
                }
            }
        }
    }

    /// What the sandbox's relay machine says about it (no secrets): every
    /// device of the account labels it with it and knows where it can be
    /// deleted permanently.
    fn meta(&self, conn: &Connection, sandbox: &str, owner: &str) -> BTreeMap<String, String> {
        use cua_sandbox_core::byoc::meta;
        let mut m = BTreeMap::from([
            (meta::PROVIDER.to_string(), self.api.name().to_string()),
            (meta::PLACE.to_string(), conn.label(self.api.title())),
            (meta::SANDBOX.to_string(), sandbox.to_string()),
            (meta::OWNER.to_string(), owner.to_string()),
            (meta::DEVICE.to_string(), cua_host::device_name()),
        ]);
        // This home is a host on the relay: other devices ask it to delete.
        if let Some(home) = self.store.home()
            && let Ok(Some(c)) = cua_host::Host::new(&home).config()
            && c.mode == "relay"
            && let Some(id) = c.machine_id.filter(|i| !i.is_empty())
        {
            m.insert(meta::HOST.to_string(), id);
        }
        m.retain(|_, v| !v.is_empty());
        for v in m.values_mut() {
            if v.chars().count() > 256 {
                *v = v.chars().take(256).collect();
            }
        }
        m
    }

    fn record_of(&self, id: &str) -> Result<Option<Resource>> {
        Ok(self
            .store
            .resources()
            .map_err(Self::io)?
            .into_iter()
            .find(|r| {
                r.provider == self.api.name()
                    && matches!(r.resource_type.as_str(), "instance" | "sandbox")
                    && r.id == id
            }))
    }

    async fn refresh_record(&self, conn: &Connection, owner: &str, rec: &Resource) -> bool {
        let listed = match self.api.list_owned(conn, owner).await {
            Ok(listed) => listed,
            Err(e) => {
                tracing::warn!(resource = %rec.id, "could not refresh retained resource: {e}");
                return false;
            }
        };
        let Some(fresh) = listed.into_iter().find(|r| {
            r.provider == rec.provider && r.resource_type == rec.resource_type && r.id == rec.id
        }) else {
            return false;
        };
        let updated = merge_refreshed_record(rec, fresh);
        if let Err(e) = self.store.record(updated) {
            tracing::warn!(resource = %rec.id, "could not save refreshed resource: {e}");
            return false;
        }
        true
    }

    fn instance(&self, r: &Resource, status: Status, conn: &Connection) -> ProviderInstance {
        let mut i = ProviderInstance::new(
            r.id.clone(),
            r.sandbox
                .split_once(':')
                .map_or(r.sandbox.clone(), |(_, n)| n.to_string()),
            status,
        );
        if !r.machine.is_empty() {
            i.details
                .insert(DETAIL_RELAY_MACHINE.into(), r.machine.clone());
        }
        i.details
            .insert(detail::PLACE.into(), conn.label(self.api.title()));
        for k in [
            detail::MACHINE_TYPE,
            detail::CLOUD_IMAGE_ID,
            detail::AUTO_RELEASE_TIME,
            detail::USD_PER_HOUR,
            detail::RUNTIME,
        ] {
            if let Some(v) = r.extra.get(k) {
                i.details.insert(k.into(), v.clone());
            }
        }
        if r.expires > 0 {
            i.details
                .insert(detail::EXPIRES.into(), model::rfc3339(r.expires));
        }
        i
    }

    /// A check the wait runs between polls: fails at once when the machine
    /// is gone or stopped.
    async fn alive(&self, conn: &Connection, r: &Resource) -> Result<()> {
        match self.api.describe(conn, r).await {
            Ok(Some((state, _))) if is_dead(&state) => Err(Error::Cloud(format!(
                "{}: {} {} is {state} before its sandbox came online (its boot log is saved before cleanup)",
                self.api.name(),
                r.resource_type,
                r.id
            ))),
            Ok(None) => Err(Error::Cloud(format!(
                "{}: {} {} is gone before its sandbox came online",
                self.api.name(),
                r.resource_type,
                r.id
            ))),
            // A transient API error is not a verdict on the machine.
            _ => Ok(()),
        }
    }

    /// Deletes what a failed create made (best effort; what could not be
    /// deleted stays recorded, for the sweeper).
    async fn rollback(&self, conn: &Connection, owner: &str, made: &[Resource], machine: &str) {
        for r in made {
            if r.id.is_empty() {
                let listed = self.api.list_owned(conn, owner).await.unwrap_or_default();
                if !listed.iter().any(|x| x.name == r.name) {
                    let _ = self.store.forget(r);
                }
                continue;
            }
            match self.api.delete(conn, r, owner).await {
                Ok(()) => {
                    let _ = self.store.forget(r);
                    self.store.audit(audit::of_resource(
                        "resource_deleted",
                        r,
                        "rollback",
                        "ok",
                        "the create failed",
                    ));
                }
                Err(e) => {
                    self.store.audit(audit::of_resource(
                        "resource_deleted",
                        r,
                        "rollback",
                        "failed",
                        &e.to_string(),
                    ));
                    tracing::warn!(resource = %r.id, "rollback left it for the sweeper: {e}");
                    let mut failed = r.clone();
                    failed.state = "failed".into();
                    if !self.refresh_record(conn, owner, &failed).await {
                        let _ = self.store.record(failed);
                    }
                }
            }
        }
        if !machine.is_empty() {
            self.forget_connection_machine(conn, machine).await;
        }
    }

    /// Reads `r`'s boot log (bounded, never failing), keeps the filtered
    /// tail under `<home>/cloud/boot-logs/` and returns what the error
    /// should add (`None`: the cloud had nothing to show).
    async fn keep_boot_log(
        &self,
        conn: &Connection,
        r: &Resource,
        secrets: &[&str],
    ) -> Option<String> {
        let raw = match tokio::time::timeout(bootlog::FETCH_TIMEOUT, self.api.boot_log(conn, r))
            .await
        {
            Ok(Ok(Some(raw))) => raw,
            Ok(Ok(None)) => return None,
            Ok(Err(e)) => {
                tracing::warn!(resource = %r.id, "boot log not read: {e}");
                return None;
            }
            Err(_) => {
                tracing::warn!(resource = %r.id, "boot log not read: the cloud did not answer in time");
                return None;
            }
        };
        let lines = bootlog::filter(&raw, secrets);
        if lines.is_empty() {
            return None;
        }
        let path = self
            .store
            .home()
            .and_then(|h| match bootlog::save(&h, &r.id, &lines) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(resource = %r.id, "boot log not saved: {e}");
                    None
                }
            });
        Some(bootlog::summary(path.as_deref(), &lines))
    }
}

fn extract_url_secrets(raw_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let no_frag = raw_url.split('#').next().unwrap_or(raw_url);
    if let Ok(u) = url::Url::parse(no_frag)
        && (!u.username().is_empty() || u.password().is_some() || u.query().is_some())
    {
        out.push(raw_url.to_string());
        out.push(no_frag.to_string());
        if !u.username().is_empty() {
            out.push(u.username().to_string());
        }
        if let Some(pw) = u.password() {
            out.push(pw.to_string());
        }
        if let Some(q) = u.query() {
            out.push(q.to_string());
            for (_, v) in u.query_pairs() {
                out.push(v.into_owned());
            }
        }
    }
    out
}

/// A state a machine does not come back from on its own.
/// `e` with the boot log evidence appended to its message.
fn with_evidence(e: Error, evidence: Option<String>) -> Error {
    let Some(ev) = evidence else { return e };
    match e {
        Error::Timeout(m) => Error::Timeout(format!("{m}\n{ev}")),
        Error::Cloud(m) => Error::Cloud(format!("{m}\n{ev}")),
        other => other,
    }
}

pub(crate) fn is_dead(state: &str) -> bool {
    matches!(
        state,
        "terminated" | "shutting-down" | "stopping" | "stopped" | "gone" | "deleted"
    )
}

fn status_of(state: &str) -> Status {
    match state {
        "running" => Status::Running,
        // A stopped VM is what `suspend` makes (its disk stays; `resume`
        // starts it): the sandbox layer shows it as suspended, not exited.
        "stopped" | "stopping" | "suspended" => Status::Suspended,
        "pending" | "starting" | "provisioning" => Status::Provisioning,
        other => Status::Unknown(other.to_string()),
    }
}

/// The runtime word a create asked for, checked against what the cloud
/// offers (empty: its default).
pub fn runtime_word(
    api: &dyn CloudApi,
    asked: &cua_sandbox_core::placement::Runtime,
) -> Result<String> {
    use cua_sandbox_core::placement::{Axis, PlacementError, Runtime};
    if *asked == Runtime::Auto {
        return Ok(String::new());
    }
    let offered = api.runtimes();
    if offered.contains(asked) {
        return Ok(asked.as_str().to_string());
    }
    let mut valid = vec!["auto".to_string()];
    valid.extend(offered.iter().map(|r| r.as_str().to_string()));
    Err(PlacementError::new(
        Axis::Runtime,
        asked.as_str(),
        format!(
            "--runtime {asked} does not apply to {} (it offers: {})",
            api.name(),
            valid.join(", ")
        ),
        valid,
    )
    .into())
}

/// The boot disk a family needs, in GiB.
pub fn disk_for(family: &str) -> u32 {
    match family {
        "windows" => 100,
        "omarchy" | "linux-vm" => 50,
        _ => 30,
    }
}

#[async_trait]
impl cua_sandbox_core::Provider for CloudSandboxes {
    fn name(&self) -> &'static str {
        self.api.name()
    }

    fn supported_oses(&self) -> &'static [&'static str] {
        self.api.supported_oses()
    }

    fn capabilities(&self) -> ProviderCapabilities {
        let oses = self.api.supported_oses().to_vec();
        let mut kinds = vec![RunKind::Container];
        if self.api.runtimes().iter().any(|r| r.as_str() == "native")
            || oses.iter().any(|o| o.eq_ignore_ascii_case("windows"))
        {
            kinds.push(RunKind::Vm);
        }
        let custom = self.api.supports_custom_image_and_sizing();
        ProviderCapabilities {
            kinds,
            // The default engine (`--runtime` picks another where offered).
            runtime: match (self.api.tier(), self.api.runtimes().first()) {
                (_, Some(cua_sandbox_core::placement::Runtime::Gvisor)) => "gvisor",
                (Tier::Vm, _) => "docker-on-vm",
                (Tier::Sandbox, _) => "platform",
            },
            arches: self.api.arches(),
            image_mode: ImageMode::Direct,
            // Every port is reached through the relay (cua-spacesd's own
            // gRPC-Web and WebSocket there).
            ports: PortExposure::Https,
            command: self.api.tier() == Tier::Sandbox,
            env_to_entrypoint: true,
            private_registry: false,
            suspend: self.api.tier() == Tier::Vm,
            max_cpus: None,
            max_memory_mb: None,
            credential_env: &[],
            // No GPU in your cloud (yet): GPU machine types are off.
            gpus: vec![],
            oses,
            custom_disk_gb: custom,
            custom_cloud_image: custom,
        }
    }

    fn check_configured(&self) -> Result<()> {
        self.connection().map(|_| ())
    }

    fn joins_relay(&self) -> bool {
        true
    }

    fn takes_network_rules(&self) -> bool {
        self.api.takes_network_rules()
    }

    /// A VM-per-sandbox cloud: the computer's own firewall (installed by
    /// bootstrap before the sandbox starts, [`crate::hostnet`]) keeps it to
    /// the internet.
    fn keeps_internet_only(&self) -> bool {
        matches!(self.api.tier(), Tier::Vm)
    }

    async fn create(&self, spec: &ProviderCreate) -> Result<ProviderInstance> {
        let conn = self.connection()?;
        let family = create_family(spec);
        if let Some(url) = conn.spacesd_download_url.as_deref() {
            crate::target::normalize_spacesd_download_url(url)?;
            let os_family = match family {
                "windows" => "windows",
                "macos" => "macos",
                _ => "linux",
            };
            cua_sandbox_core::byoc::validate_spacesd_url_for_os(url, os_family)
                .map_err(Error::InvalidArgument)?;
        }
        let kinds = self.api.kinds(&conn);
        let offer = kinds.iter().find(|k| k.image == family).ok_or_else(|| {
            let ran = kinds
                .iter()
                .filter(|k| k.supported)
                .map(|k| k.image.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Error::UnsupportedImage(format!(
                "{} does not run {family} sandboxes (it runs: {ran})",
                self.api.title()
            ))
        })?;
        if !offer.supported {
            return Err(Error::UnsupportedImage(format!(
                "{family} on {}: {}",
                self.api.title(),
                offer.reason
            )));
        }
        let (effective_kind, effective_runtime) =
            resolve_kind_and_runtime(self.api.as_ref(), family, spec)?;
        let is_linux_native = matches!(self.api.tier(), Tier::Vm)
            && matches!(family, "linux" | "linux-slim")
            && effective_runtime == "native";
        crate::bootstrap::validate_env_keys(&spec.env, is_linux_native)?;
        let (cloud_image_id, spec_instance_type) =
            validate_custom_create_options(self.api.as_ref(), spec)?;
        let explicit_machine_type = spec_instance_type.or_else(|| {
            conn.instance_type
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
        let machine_type_explicit = explicit_machine_type.is_some();
        let mut machine_type = explicit_machine_type.unwrap_or_else(|| offer.machine_type.clone());
        let disk_gb = spec
            .disk_gb
            .unwrap_or_else(|| self.api.default_disk_gb(family));
        let owner = self.store.owner_id().map_err(Self::io)?;
        let created = now();
        let ttl_secs = match spec.ttl {
            Some(t) => t.as_secs(),
            None => u64::from(conn.ttl_hours) * 3600,
        };
        let expires = if ttl_secs == 0 { 0 } else { created + ttl_secs };
        let suffix = format!("{:016x}", rand::random::<u64>());
        let machine = format!("cloud-{suffix}");
        let resource_name = format!("cua-{}-{}", self.api.name(), &suffix[..12]);
        let sandbox = format!("{}:{}", self.api.name(), spec.name);
        let conn_relay = ConnectionRelay::for_create(
            &conn,
            &self.relay,
            self.store.home().as_deref(),
            self.api.name(),
            self.api.title(),
        )?;
        // The network rules the Space asked for: kept by the cloud itself or
        // refused, before anything is made (never created without them).
        let network = if spec.egress.is_empty() && !spec.no_network && !spec.protect {
            None
        } else if self.api.takes_network_rules() {
            crate::modal_net::request(
                &spec.egress,
                spec.no_network,
                spec.protect,
                conn_relay.url(),
            )?
        } else if spec.egress.is_empty() && !spec.no_network && matches!(self.api.tier(), Tier::Vm)
        {
            // Internet only, kept by the computer's own firewall.
            None
        } else {
            return Err(Error::InvalidArgument(format!(
                "{} cannot keep a Space's network rules: it runs the Space on a computer cua \
                 does not control the network of. Use Modal, or run the Space on this machine \
                 or one of yours",
                self.api.title()
            )));
        };
        let desktop_password = if family == "windows" {
            Some(crate::bootstrap_win::generate_desktop_password())
        } else {
            None
        };
        let mut provision = ProvisionSpec {
            name: resource_name.clone(),
            family: family.into(),
            image: spec.image.pinned_ref.clone(),
            kind: effective_kind.into(),
            machine_type: machine_type.clone(),
            machine_type_explicit,
            disk_gb,
            cpus: Some(spec.cpus),
            memory_mb: Some(spec.memory_mb),
            tags: BTreeMap::new(),
            ttl_secs,
            arch: spec.image.arch.clone(),
            runtime: effective_runtime.clone(),
            network,
            spacesd_download_url: conn.spacesd_download_url.clone(),
            desktop_password: desktop_password.clone(),
            cloud_image_id,
            ..Default::default()
        };
        // Say a budget share passed before a new machine adds to it.
        crate::alerts::check_all(&self.store, now());
        let spent = self
            .store
            .spent_for_limits(&conn, now())
            .await
            .map_err(Self::io)?;
        if self.api.supports_custom_image_and_sizing() {
            let (min_cpus, min_mem_mb) = self.api.check_size_for(family, spec.cpus, spec.memory_mb);
            let min_usd_floor = if machine_type_explicit {
                0.0
            } else {
                f64::from(min_cpus.unwrap_or(2)) * 0.01
                    + f64::from(disk_gb) * self.api.disk_usd_per_gb_hour()
            };
            crate::limits::check_new_machine_with_disk(
                &conn,
                self.api.title(),
                min_cpus,
                min_mem_mb,
                Some(disk_gb),
                min_usd_floor,
                spent,
            )?;
        }
        let prep = self.api.prepare_provision(&conn, &provision).await?;
        prep.apply_to(&mut provision);
        if !provision.machine_type.is_empty() {
            machine_type = provision.machine_type.clone();
        } else {
            machine_type = offer.machine_type.clone();
            provision.machine_type = machine_type.clone();
        }
        let (eff_cpus, eff_mem_mb, eff_disk_gb, eff_usd) = match &prep.sizing {
            Some(s) => (
                Some(s.vcpus.max(spec.cpus)),
                Some(s.memory_mb.max(spec.memory_mb)),
                s.disk_gb.unwrap_or(disk_gb),
                s.usd_per_hour,
            ),
            None => {
                let (c, m) = self.api.check_size_for(family, spec.cpus, spec.memory_mb);
                (c, m, disk_gb, offer.usd_per_hour)
            }
        };
        crate::limits::check_new_machine_with_disk(
            &conn,
            self.api.title(),
            eff_cpus,
            eff_mem_mb,
            Some(eff_disk_gb),
            eff_usd,
            spent,
        )?;
        let (join, static_env_token) = conn_relay
            .prepare_join(
                &self.store,
                self.api.name(),
                &machine,
                &spec.name,
                self.meta(&conn, &spec.name, &owner),
                spec.env.get("CUA_ENV_TOKEN").map(String::as_str),
            )
            .await?;
        let mut guest_env = spec.env.clone();
        if let Some(tok) = &static_env_token {
            guest_env.insert("CUA_ENV_TOKEN".into(), tok.clone());
        }
        let mut rec = Resource {
            provider: self.api.name().into(),
            resource_type: match self.api.tier() {
                Tier::Vm => "instance".into(),
                Tier::Sandbox => "sandbox".into(),
            },
            name: resource_name.clone(),
            region: conn.region.clone(),
            zone: conn.zone.clone(),
            project: if conn.project.is_empty() {
                conn.environment.clone()
            } else {
                conn.project.clone()
            },
            sandbox: sandbox.clone(),
            machine: machine.clone(),
            created,
            expires,
            tags: model::tags(&owner, &spec.name, &machine, expires),
            state: "pending".into(),
            ..Default::default()
        };
        rec.extra.insert(detail::MACHINE_TYPE.into(), machine_type);
        rec.extra
            .insert(detail::USD_PER_HOUR.into(), format!("{eff_usd:.4}"));
        if matches!(self.api.tier(), Tier::Vm) {
            let detail_rt = if effective_runtime == "native" {
                "native"
            } else {
                "docker-on-vm"
            };
            rec.extra.insert(detail::RUNTIME.into(), detail_rt.into());
        } else if !effective_runtime.is_empty() {
            rec.extra
                .insert(detail::RUNTIME.into(), effective_runtime.clone());
        }
        self.store.record(rec.clone()).map_err(Self::io)?;
        self.store.audit(audit::of_resource(
            "resource_recorded",
            &rec,
            "user",
            "ok",
            "recorded before the cloud call",
        ));
        provision.tags = rec.tags.clone();
        match self.api.tier() {
            Tier::Vm if family == "windows" => {
                let boot = WindowsVmBoot {
                    join: &join,
                    env: &guest_env,
                    expires,
                    ttl_secs,
                    provider: self.api.name(),
                    spacesd_download_url: conn.spacesd_download_url.as_deref(),
                    desktop_user: "Administrator",
                    desktop_password: desktop_password.as_deref().unwrap_or_default(),
                };
                provision.user_data = windows_user_data(&boot);
            }
            Tier::Vm => {
                let (net_guard, share_slots) = VmBoot::switches();
                let boot = VmBoot {
                    join: &join,
                    image: &spec.image.pinned_ref,
                    env: &guest_env,
                    expires,
                    ttl_secs,
                    shm_mb: 2048,
                    provider: self.api.name(),
                    net_guard,
                    share_slots,
                };
                provision.user_data =
                    if matches!(family, "linux" | "linux-slim") && provision.runtime == "native" {
                        linux_native_cloud_init(&boot, conn.spacesd_download_url.as_deref())
                    } else {
                        cloud_init(&boot)
                    };
            }
            Tier::Sandbox => {
                let mut env = guest_env.clone();
                env.extend(join.guest_env());
                provision.env = env;
                provision.command = spec.command.clone();
            }
        }
        let made = match self.api.provision(&conn, &provision).await {
            Ok(m) => m,
            Err(e) => {
                self.store.audit(audit::of_resource(
                    "resource_created",
                    &rec,
                    "user",
                    "failed",
                    &e.to_string(),
                ));
                self.rollback(&conn, &owner, &[rec], &machine).await;
                return Err(e);
            }
        };
        let mut all = Vec::new();
        for (i, r) in made.into_iter().enumerate() {
            let r = if i == 0 {
                rec.id = r.id.clone();
                rec.state = r.state.clone();
                rec.extra.extend(r.extra.clone());
                rec.clone()
            } else {
                r
            };
            self.store.record(r.clone()).map_err(Self::io)?;
            self.store.audit(audit::of_resource(
                "resource_created",
                &r,
                "user",
                "ok",
                "the cloud created it",
            ));
            all.push(r);
        }
        let budget = spec.timeout.max(ONLINE_WAIT);
        let joined = conn_relay
            .wait_online(
                self.store.home().as_deref(),
                self.api.name(),
                &machine,
                static_env_token.as_deref(),
                budget,
                || self.alive(&conn, &rec),
            )
            .await;
        if let Err(e) = joined {
            // The evidence first: the rollback deletes the machine and its
            // log with it.
            let owned_secrets = conn
                .spacesd_download_url
                .as_deref()
                .map(extract_url_secrets)
                .unwrap_or_default();
            let mut secrets: Vec<&str> = vec![&join.machine_token];
            if !join.jwks_json.is_empty() {
                secrets.push(&join.jwks_json);
            }
            if let Some(pw) = desktop_password.as_deref() {
                secrets.push(pw);
            }
            secrets.extend(guest_env.values().map(String::as_str));
            secrets.extend(owned_secrets.iter().map(String::as_str));
            let evidence = self.keep_boot_log(&conn, &all[0], &secrets).await;
            self.rollback(&conn, &owner, &all[..1], &machine).await;
            return Err(with_evidence(e, evidence));
        }
        rec.state = "running".into();
        self.store.record(rec.clone()).map_err(Self::io)?;
        self.store.audit(audit::of_resource(
            "resource_confirmed",
            &rec,
            "user",
            "ok",
            "joined the relay",
        ));
        Ok(self.instance(&rec, Status::Running, &conn))
    }

    async fn get(&self, id: &str) -> Result<ProviderInstance> {
        let conn = self.connection()?;
        let rec = self
            .record_of(id)?
            .ok_or_else(|| Error::NotFound(format!("{}:{id}", self.api.name())))?;
        match self.api.describe(&conn, &rec).await? {
            Some((state, _)) => Ok(self.instance(&rec, status_of(&state), &conn)),
            None => Err(Error::NotFound(format!("{}:{id}", self.api.name()))),
        }
    }

    async fn list(&self) -> Result<Vec<ProviderInstance>> {
        let conn = self.connection()?;
        let owner = self.store.owner_id().map_err(Self::io)?;
        let records = self.store.resources().map_err(Self::io)?;
        Ok(self
            .api
            .list_owned(&conn, &owner)
            .await?
            .into_iter()
            .filter(|r| matches!(r.resource_type.as_str(), "instance" | "sandbox"))
            .map(|r| {
                let rec = records
                    .iter()
                    .find(|x| x.provider == r.provider && x.id == r.id)
                    .cloned()
                    .unwrap_or(r.clone());
                self.instance(&rec, status_of(&r.state), &conn)
            })
            .collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let conn = self.connection()?;
        let owner = self.store.owner_id().map_err(Self::io)?;
        let rec = match self.record_of(id)? {
            Some(r) => r,
            None => {
                // Not recorded here: only a resource tagged with this owner
                // is deleted (a create from this home that died before its
                // record was written).
                let listed = self.api.list_owned(&conn, &owner).await?;
                match listed.into_iter().find(|r| r.id == id) {
                    Some(r) => r,
                    None => return Ok(()),
                }
            }
        };
        if let Err(e) = self.api.delete(&conn, &rec, &owner).await {
            self.refresh_record(&conn, &owner, &rec).await;
            self.store.audit(audit::of_resource(
                "resource_deleted",
                &rec,
                "user",
                "failed",
                &e.to_string(),
            ));
            return Err(e);
        }
        self.store.forget(&rec).map_err(Self::io)?;
        self.store.audit(audit::of_resource(
            "resource_deleted",
            &rec,
            "user",
            "ok",
            "deleted with its sandbox",
        ));
        if !rec.machine.is_empty() {
            self.forget_connection_machine(&conn, &rec.machine).await;
        }
        Ok(())
    }

    fn endpoint(&self, instance: &ProviderInstance, _port: u16) -> Result<ServiceEndpoint> {
        let machine = instance
            .details
            .get(DETAIL_RELAY_MACHINE)
            .ok_or_else(|| Error::NotFound(format!("the relay computer of {}", instance.id)))?;
        let url = match self.connection() {
            Ok(conn) => self.connection_relay(&conn)?.machine_url(machine),
            Err(_) => self.relay.machine_url(machine),
        };
        Ok(ServiceEndpoint {
            url,
            headers: vec![],
        })
    }

    fn connect_options(
        &self,
        instance: &ProviderInstance,
        _port: u16,
    ) -> Option<Result<cua_spacesd_client::ConnectOptions>> {
        let machine = instance.details.get(DETAIL_RELAY_MACHINE)?;
        let conn = match self.connection() {
            Ok(c) => c,
            Err(_) => return Some(self.relay.connect_options(machine)),
        };
        let relay = match self.connection_relay(&conn) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        Some(relay.connect_options(self.store.home().as_deref(), self.api.name(), machine))
    }

    // A cloud VM stops (compute billing stops, its disk stays) and starts
    // again; a cloud sandbox platform (Modal) cannot.
    fn power(&self) -> Option<cua_sandbox_core::PowerControl> {
        (self.api.tier() == Tier::Vm).then_some(cua_sandbox_core::PowerControl::Stop)
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        cua_sandbox_core::Provider::stop(self, id).await
    }

    async fn resume(&self, id: &str) -> Result<ProviderInstance> {
        cua_sandbox_core::Provider::start(self, id).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        let conn = self.connection()?;
        let owner = self.store.owner_id().map_err(Self::io)?;
        let mut rec = self
            .record_of(id)?
            .ok_or_else(|| Error::NotFound(format!("{}:{id}", self.api.name())))?;
        self.api.stop(&conn, &rec, &owner).await?;
        rec.state = "stopped".into();
        self.store.record(rec).map_err(Self::io)
    }

    async fn start(&self, id: &str) -> Result<ProviderInstance> {
        let conn = self.connection()?;
        let owner = self.store.owner_id().map_err(Self::io)?;
        let mut rec = self
            .record_of(id)?
            .ok_or_else(|| Error::NotFound(format!("{}:{id}", self.api.name())))?;
        self.api.start(&conn, &rec, &owner).await?;
        if !rec.machine.is_empty() {
            let relay = self.connection_relay(&conn)?;
            relay
                .wait_online(
                    self.store.home().as_deref(),
                    self.api.name(),
                    &rec.machine,
                    None,
                    ONLINE_WAIT,
                    || self.alive(&conn, &rec),
                )
                .await?;
        }
        rec.state = "running".into();
        self.store.record(rec.clone()).map_err(Self::io)?;
        Ok(self.instance(&rec, Status::Running, &conn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_and_states() {
        assert_eq!(family_of("ghcr.io/trycua/linux:24.04"), "linux");
        assert_eq!(family_of("ghcr.io/trycua/linux:24.04-slim"), "linux-slim");
        assert_eq!(family_of("ghcr.io/trycua/windows:2022"), "windows");
        assert_eq!(status_of("running"), Status::Running);
        assert_eq!(status_of("stopped"), Status::Suspended);
        assert_eq!(status_of("gone"), Status::Unknown("gone".into()));
        assert!(is_dead("terminated") && !is_dead("pending"));
    }
}
