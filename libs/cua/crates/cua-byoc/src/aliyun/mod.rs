// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Alibaba Cloud ECS (`--on aliyun-ecs`): sandboxes in your Alibaba Cloud
//! account over direct HTTPS OpenAPI V3 (`ACS3-HMAC-SHA256`) with
//! least-privilege RAM sub-account AccessKeys.
//!
//! Credentials resolve in precedence order:
//! 1. `--token-stdin` (`<access_key_id>:<access_key_secret>`)
//! 2. `ALIBABA_CLOUD_ACCESS_KEY_ID` + `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
//! 3. Explicit `--profile <name>` in `~/.aliyun/config.json` (`AK` mode)
//! 4. Saved credentials in the Cua credential store (`byoc-aliyun-ecs-token`)
//! 5. Active `current` profile in `~/.aliyun/config.json` (`AK` mode)

pub mod auth;
pub mod client;
pub mod existing_vpc;
pub mod image;
mod lifecycle;
pub mod net;
mod preflight;
pub mod security_group;
pub mod sizing;
pub mod vpc;
pub mod zones;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cua_sandbox_core::Error;
use cua_sandbox_core::byoc::{CloudCredentials, CloudKind};
use cua_sandbox_core::placement::Runtime;

use crate::api::{CloudApi, PreparedProvision, ResolvedSizing, Result, Target, Tested, cloud_err};
use crate::model::{self, Capabilities, Connection, ProvisionSpec, Resource, Tier, tag};

pub use auth::{
    AliyunCredentials, CuaCredentialStore, SECRET_NAME, TokenStore, aliyun_config_path,
    parse_token_pair,
};
pub use client::{
    Acs3SignedHeaders, ECS_API_VERSION, STS_API_VERSION, STS_ENDPOINT, SignRequest,
    VPC_API_VERSION, canonical_query_string, rfc3986_encode, sign_acs3,
};
pub use image::{ResolvedCloudImage, WindowsInitHeader};
pub use sizing::{
    ESSD_USD_PER_GB_HOUR, LINUX_DEFAULT_DISK_GB, LINUX_INSTANCE_TYPE, MAX_DISK_GB, MIN_DISK_GB,
    SLIM_INSTANCE_TYPE, WINDOWS_DEFAULT_DISK_GB, WINDOWS_INSTANCE_TYPE, ecs_instance_spec,
    instance_type_for, system_disk_for, validate_disk_gb,
};

use auth::CredSource;
use client::{
    ApiBody, api_error_code_message, is_zone_capacity_error, map_api_error,
    sanitize_hostname_for_family, validate_region,
};
use net::{NetLocks, NetworkConfig};

/// Default Alibaba Cloud region when neither `--region` nor a CLI profile specifies one.
pub const DEFAULT_REGION: &str = "cn-hangzhou";

/// Alibaba Cloud ECS provider (`--on aliyun-ecs`).
pub struct AliyunEcs {
    pub(crate) http: reqwest::Client,
    pub(crate) sts_endpoint: String,
    ecs_endpoint_override: Option<String>,
    vpc_endpoint_override: Option<String>,
    store: Arc<dyn TokenStore>,
    staged: Mutex<Option<std::result::Result<AliyunCredentials, String>>>,
    aliyun_config: Option<PathBuf>,
    net_locks: NetLocks,
    poll: Duration,
}

impl Default for AliyunEcs {
    fn default() -> Self {
        Self::new()
    }
}

impl AliyunEcs {
    /// Creates an `AliyunEcs` client targeting real Alibaba Cloud endpoints and `cua_auth::Store`.
    pub fn new() -> Self {
        Self::with_store(Arc::new(CuaCredentialStore::default()))
    }

    /// Creates an `AliyunEcs` client whose credential store is scoped to `home`.
    pub fn for_home(home: &Path) -> Self {
        Self::with_store(Arc::new(CuaCredentialStore::new(Some(home.to_path_buf()))))
    }

    fn with_store(store: Arc<dyn TokenStore>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
            sts_endpoint: STS_ENDPOINT.to_string(),
            ecs_endpoint_override: None,
            vpc_endpoint_override: None,
            store,
            staged: Mutex::new(None),
            aliyun_config: auth::default_aliyun_config_path(),
            net_locks: NetLocks::new(),
            poll: Duration::from_secs(2),
        }
    }

    /// Creates an `AliyunEcs` client with custom endpoints, `TokenStore`, and `~/.aliyun/config.json` path (for tests).
    pub fn with_endpoints(
        ecs_url: &str,
        sts_url: &str,
        vpc_url: &str,
        store: Arc<dyn TokenStore>,
        aliyun_config: Option<PathBuf>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("http client"),
            sts_endpoint: sts_url.trim_end_matches('/').to_string(),
            ecs_endpoint_override: Some(ecs_url.trim_end_matches('/').to_string()),
            vpc_endpoint_override: Some(vpc_url.trim_end_matches('/').to_string()),
            store,
            staged: Mutex::new(None),
            aliyun_config,
            net_locks: NetLocks::new(),
            poll: Duration::from_secs(2),
        }
    }

    /// Overrides the polling interval for state waits and dependency retries (for fast tests).
    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    pub(crate) fn poll_interval(&self) -> Duration {
        self.poll
    }

    pub(crate) fn profile_hint<'a>(&self, conn: &'a Connection) -> Option<&'a str> {
        (!conn.profile.is_empty()).then_some(conn.profile.as_str())
    }

    pub(crate) fn ecs_endpoint(&self, region: &str) -> String {
        self.ecs_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ecs.{region}.aliyuncs.com"))
    }

    pub(crate) fn vpc_endpoint(&self, region: &str) -> String {
        self.vpc_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://vpc.{region}.aliyuncs.com"))
    }

    pub(crate) fn resolve_credentials(
        &self,
        profile_hint: Option<&str>,
    ) -> Result<(AliyunCredentials, CredSource)> {
        auth::resolve_credentials(
            &self.staged,
            self.store.as_ref(),
            self.aliyun_config.as_deref(),
            profile_hint,
        )
    }

    /// Validates an explicit Cloud Image ID in `conn.region`.
    pub async fn validate_image_id(
        &self,
        conn: &Connection,
        image_id: &str,
        expected_os: &str,
    ) -> Result<ResolvedCloudImage> {
        image::validate_image_id(self, conn, &conn.region, image_id, expected_os).await
    }

    /// Looks up the newest available official Alibaba Cloud system image for `target_os`.
    pub async fn resolve_official_image(
        &self,
        conn: &Connection,
        target_os: &str,
    ) -> Result<ResolvedCloudImage> {
        image::resolve_official_image(self, conn, &conn.region, target_os).await
    }

    /// Resolves Cloud Image ID in precedence order (`per-create` -> `connection-default` -> `official-fallback`).
    pub async fn resolve_image_id(
        &self,
        conn: &Connection,
        spec: &ProvisionSpec,
    ) -> Result<ResolvedCloudImage> {
        image::resolve_image_id(self, conn, spec).await
    }

    /// Resolves `(vcpus, memory_mb, instance_usd_per_hour)` from the built-in ECS
    /// catalog or `ecs:DescribeInstanceTypes`.
    pub async fn lookup_instance_type(
        &self,
        conn: &Connection,
        instance_type: &str,
    ) -> Result<(u32, u64, f64)> {
        sizing::lookup_instance_type(self, conn, &conn.region, instance_type).await
    }

    /// Picks an available, in-stock (`WithStock`) `x86_64` mainstream instance type for `family` in `region`.
    pub async fn resolve_default_instance_type(
        &self,
        conn: &Connection,
        region: &str,
        family: &str,
    ) -> String {
        let spec = ProvisionSpec {
            family: family.to_string(),
            ..Default::default()
        };
        sizing::resolve_dynamic_instance_type_for_spec(self, conn, region, &spec)
            .await
            .instance_type
    }

    fn validate_family_runtime(spec: &ProvisionSpec) -> Result<()> {
        match spec.family.as_str() {
            "windows" => {
                if !spec.runtime.is_empty() && spec.runtime != "native" {
                    return Err(Error::Unsupported {
                        provider: cua_sandbox_core::ProviderKind::Contrib,
                        op: format!(
                            "aliyun-ecs Windows sandboxes use --runtime native (got --runtime {})",
                            spec.runtime
                        ),
                    });
                }
            }
            "linux" | "linux-slim" => {
                if !spec.runtime.is_empty() && spec.runtime != "docker" && spec.runtime != "native"
                {
                    return Err(Error::Unsupported {
                        provider: cua_sandbox_core::ProviderKind::Contrib,
                        op: format!(
                            "aliyun-ecs does not support --runtime {} on {}",
                            spec.runtime, spec.family
                        ),
                    });
                }
            }
            _ => {
                return Err(Error::Unsupported {
                    provider: cua_sandbox_core::ProviderKind::Contrib,
                    op: format!("aliyun-ecs does not support {} sandboxes", spec.family),
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CloudApi for AliyunEcs {
    fn name(&self) -> &'static str {
        "aliyun-ecs"
    }

    fn title(&self) -> &'static str {
        "Alibaba Cloud ECS"
    }

    fn tier(&self) -> Tier {
        Tier::Vm
    }

    fn arches(&self) -> Vec<&'static str> {
        vec!["amd64"]
    }

    fn runtimes(&self) -> Vec<Runtime> {
        vec![
            Runtime::Other("docker".into()),
            Runtime::Other("native".into()),
        ]
    }

    fn supported_oses(&self) -> &'static [&'static str] {
        &["linux", "windows"]
    }

    fn supports_image_defaults(&self) -> bool {
        true
    }

    fn supports_custom_image_and_sizing(&self) -> bool {
        true
    }

    fn supports_custom_vpc(&self) -> bool {
        true
    }

    fn scope_home(&self, home: &Path) {
        self.store.scope_home(home);
    }

    fn default_disk_gb(&self, family: &str) -> u32 {
        match family {
            "windows" => WINDOWS_DEFAULT_DISK_GB,
            "linux" | "linux-slim" => LINUX_DEFAULT_DISK_GB,
            _ => crate::provider::disk_for(family),
        }
    }

    fn disk_usd_per_gb_hour(&self) -> f64 {
        ESSD_USD_PER_GB_HOUR
    }

    fn check_size_for(
        &self,
        family: &str,
        cpus: u32,
        memory_mb: u64,
    ) -> (Option<u32>, Option<u64>) {
        if family == "windows" {
            (Some(cpus.max(4)), Some(memory_mb.max(8192)))
        } else {
            (
                Some(cpus).filter(|c| *c > 0),
                Some(memory_mb).filter(|m| *m > 0),
            )
        }
    }

    fn detect(&self) -> CloudCredentials {
        auth::detect_credentials(
            &self.staged,
            self.store.as_ref(),
            self.aliyun_config.as_deref(),
        )
    }

    fn resolve(&self, t: &Target) -> Result<Connection> {
        let using_inline_or_env = t.token.is_some()
            || self.staged.lock().unwrap().is_some()
            || matches!(auth::env_credentials(), Ok(Some(_)));

        let mut profile = if using_inline_or_env {
            String::new()
        } else {
            t.profile
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_default()
        };

        let cli_profile =
            if !using_inline_or_env && (!profile.is_empty() || self.store.load().is_none()) {
                self.aliyun_config.as_deref().and_then(|p| {
                    auth::read_cli_profile(p, (!profile.is_empty()).then_some(profile.as_str()))
                        .ok()
                        .flatten()
                })
            } else {
                None
            };

        if profile.is_empty()
            && !using_inline_or_env
            && self.store.load().is_none()
            && let Some((name, _, _)) = &cli_profile
        {
            profile = name.clone();
        }

        let region_raw = match t.region.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => r.to_string(),
            None => cli_profile
                .and_then(|(_, _, r)| r)
                .unwrap_or_else(|| DEFAULT_REGION.to_string()),
        };
        let region = validate_region(&region_raw)?;
        let (vpc_id, vswitch_id) = match existing_vpc::normalize_existing_vpc(
            t.vpc_id.as_deref(),
            t.vswitch_id.as_deref(),
        )? {
            Some((v, w)) => (Some(v), Some(w)),
            None => (None, None),
        };
        let windows_image_id = cua_sandbox_core::byoc::normalize_optional_token(
            "aliyun-ecs: --windows-image-id",
            t.windows_image_id.as_deref(),
        )?;
        let linux_image_id = cua_sandbox_core::byoc::normalize_optional_token(
            "aliyun-ecs: --linux-image-id",
            t.linux_image_id.as_deref(),
        )?;
        let instance_type = cua_sandbox_core::byoc::normalize_optional_token(
            "aliyun-ecs: --instance-type",
            t.instance_type.as_deref(),
        )?;

        Ok(Connection {
            provider: "aliyun-ecs".into(),
            profile,
            region,
            ttl_hours: model::DEFAULT_TTL_HOURS,
            extras: model::ConnectionExtras {
                vpc_id,
                vswitch_id,
                no_public_ip: t.no_public_ip,
                windows_image_id,
                linux_image_id,
                instance_type,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn stage_secret(&self, t: &Target) {
        let mut guard = self.staged.lock().unwrap();
        match t.token.as_deref() {
            Some(raw) => *guard = Some(parse_token_pair(raw)),
            None => *guard = None,
        }
    }

    fn persist_secret(&self) -> Result<()> {
        let staged = self.staged.lock().unwrap().take();
        let to_save = match staged {
            Some(Ok(creds)) => Some(creds),
            Some(Err(e)) => return Err(Error::InvalidArgument(e)),
            None => match auth::env_credentials() {
                Ok(Some(creds)) => Some(creds),
                _ => None,
            },
        };
        if let Some(creds) = to_save {
            self.store.save(&creds.to_pair()).map_err(Error::Io)?;
        }
        Ok(())
    }

    fn forget_secret(&self) {
        *self.staged.lock().unwrap() = None;
        self.store.clear();
    }

    fn unstage_secret(&self) {
        *self.staged.lock().unwrap() = None;
    }

    fn kinds(&self, conn: &Connection) -> Vec<CloudKind> {
        sizing::kinds_for(conn)
    }

    async fn test(&self, conn: &Connection) -> Tested {
        preflight::run_preflight_test(self, conn).await
    }

    async fn prepare_provision(
        &self,
        conn: &Connection,
        spec: &ProvisionSpec,
    ) -> Result<PreparedProvision> {
        Self::validate_family_runtime(spec)?;
        if spec.disk_gb > 0 {
            validate_disk_gb(spec.disk_gb)?;
        }
        let (effective_disk_gb, _disk_category) = system_disk_for(spec);
        validate_disk_gb(effective_disk_gb)?;
        let disk_usd = f64::from(effective_disk_gb) * ESSD_USD_PER_GB_HOUR;

        let region = spec.region_or(conn).to_string();
        let mut effective_conn = conn.clone();
        if !region.is_empty() && effective_conn.region != region {
            effective_conn.region = region.clone();
        }

        let explicit = spec.machine_type.trim();
        let (instance_type, vcpus, memory_mb, inst_usd, stock_zones) = if spec.machine_type_explicit
            || (!explicit.is_empty() && explicit != sizing::default_instance_type_for(&spec.family))
        {
            let (vcpus, memory_mb, inst_usd) =
                sizing::lookup_instance_type(self, &effective_conn, &region, explicit).await?;
            (explicit.to_string(), vcpus, memory_mb, inst_usd, None)
        } else {
            let sel = sizing::resolve_dynamic_instance_type_for_spec(
                self,
                &effective_conn,
                &region,
                spec,
            )
            .await;
            let zones = (!sel.stock_zones.is_empty()).then_some(sel.stock_zones);
            (
                sel.instance_type,
                sel.vcpus,
                sel.memory_mb,
                sel.usd_per_hour,
                zones,
            )
        };

        let resolved_image = image::resolve_image_id(self, &effective_conn, spec).await?;
        let windows_header =
            (spec.family == "windows").then(|| resolved_image.windows_init_header());

        Ok(PreparedProvision {
            sizing: Some(ResolvedSizing {
                machine_type: Some(instance_type),
                vcpus,
                memory_mb,
                disk_gb: Some(effective_disk_gb),
                usd_per_hour: inst_usd + disk_usd,
            }),
            cloud_image_id: Some(resolved_image.image_id),
            windows_header,
            candidate_zones: stock_zones,
        })
    }

    async fn provision(&self, conn: &Connection, spec: &ProvisionSpec) -> Result<Vec<Resource>> {
        Self::validate_family_runtime(spec)?;
        let owner = spec
            .tags
            .get(tag::OWNER)
            .cloned()
            .filter(|o| !o.is_empty())
            .ok_or_else(|| Error::InvalidArgument("aliyun-ecs: missing cua-owner tag".into()))?;

        let mut resolved_spec;
        let spec = if !spec.machine_type.trim().is_empty()
            && spec
                .cloud_image_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            && spec.disk_gb > 0
        {
            validate_disk_gb(spec.disk_gb)?;
            spec
        } else {
            let prep = self.prepare_provision(conn, spec).await?;
            resolved_spec = spec.clone();
            prep.apply_to(&mut resolved_spec);
            &resolved_spec
        };

        let region = spec.region_or(conn).to_string();
        let instance_type = spec.machine_type.trim().to_string();
        let (disk_gb, disk_category) = system_disk_for(spec);
        let image_id = spec
            .cloud_image_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Cloud("aliyun-ecs: missing resolved Cloud Image ID".into()))?
            .to_string();

        let profile_hint = self.profile_hint(conn);
        let ecs_ep = self.ecs_endpoint(&region);
        let mut effective_conn = conn.clone();
        if !region.is_empty() && effective_conn.region != region {
            effective_conn.region = region.clone();
        }

        let net_cfg = NetworkConfig::from_connection(&effective_conn)?;
        let net = net::prepare_network_with_stock(
            self,
            &effective_conn,
            &region,
            &owner,
            &instance_type,
            &net_cfg,
            &self.net_locks,
            spec.candidate_zones.as_deref(),
        )
        .await?;

        if net.candidates.is_empty() {
            net::rollback_made(self, &effective_conn, &net.made).await;
            return Err(Error::Cloud(format!(
                "aliyun-ecs: no availability zone in {region} supports {instance_type}"
            )));
        }

        let host_name = sanitize_hostname_for_family(&spec.name, &spec.family);
        let auto_release =
            (spec.ttl_secs > 0).then(|| model::rfc3339(model::now() + spec.ttl_secs.max(1860)));
        let user_data_b64 = (!spec.user_data.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(spec.user_data.as_bytes()));
        // Alibaba Cloud official Windows images support only IMDSv1 (`ImdsSupport: "v1"`),
        // so `HttpTokens=required` blocks `vminit` (`INSTANCE_metaservernotavailable`);
        // Windows blocks `100.100.100.200` via Windows Defender Firewall before desktop logon.
        let http_tokens = if spec.family == "windows" {
            "optional"
        } else {
            "required"
        };

        let mut tried = Vec::new();
        for (idx, cand) in net.candidates.iter().enumerate() {
            let (vswitch_id, made_vsw) = match &cand.vswitch_id {
                Some(id) => (id.clone(), None),
                None => match net::ensure_vswitch_for_zone(
                    self,
                    &effective_conn,
                    &region,
                    &owner,
                    &net.vpc_id,
                    &cand.zone_id,
                    &self.net_locks,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        net::rollback_made(self, &effective_conn, &net.made).await;
                        return Err(e);
                    }
                },
            };

            let client_token = if idx == 0 {
                spec.name.clone()
            } else {
                format!("{}-z{idx}", spec.name)
            };

            let mut params = vec![
                ("RegionId".into(), region.clone()),
                ("VSwitchId".into(), vswitch_id.clone()),
                ("SecurityGroupId".into(), net.security_group_id.clone()),
                ("ImageId".into(), image_id.clone()),
                ("InstanceType".into(), instance_type.clone()),
                ("Amount".into(), "1".into()),
                ("MinAmount".into(), "1".into()),
                ("InstanceName".into(), spec.name.clone()),
                ("HostName".into(), host_name.clone()),
                ("InstanceChargeType".into(), "PostPaid".into()),
                ("StoppedMode".into(), "StopCharging".into()),
                ("DeletionProtection".into(), "false".into()),
                ("HttpEndpoint".into(), "enabled".into()),
                ("HttpTokens".into(), http_tokens.into()),
                ("SystemDisk.Category".into(), disk_category.into()),
                ("SystemDisk.Size".into(), disk_gb.to_string()),
                ("ClientToken".into(), client_token),
            ];
            if !cand.zone_id.is_empty() {
                params.push(("ZoneId".into(), cand.zone_id.clone()));
            }
            if net.public_ip_mbps > 0 {
                params.push(("InternetChargeType".into(), "PayByTraffic".into()));
                params.push((
                    "InternetMaxBandwidthOut".into(),
                    net.public_ip_mbps.to_string(),
                ));
            } else {
                params.push(("InternetMaxBandwidthOut".into(), "0".into()));
            }
            if let Some(ref release) = auto_release {
                params.push(("AutoReleaseTime".into(), release.clone()));
            }
            if let Some(pw) = spec.desktop_password.as_deref().filter(|p| !p.is_empty()) {
                params.push(("Password".into(), pw.into()));
            }
            if let Some(ref ud) = user_data_b64 {
                params.push(("UserData".into(), ud.clone()));
            }
            params.extend(net::tag_params(&spec.tags));

            match self
                .call_raw(
                    &ecs_ep,
                    "POST",
                    "RunInstances",
                    ECS_API_VERSION,
                    &params,
                    profile_hint,
                )
                .await
            {
                Ok((status, body)) if status.is_success() => {
                    let ApiBody::Json(v) = body else {
                        if let Some(ref vsw) = made_vsw {
                            let _ =
                                net::delete_part_owned(self, &effective_conn, vsw, Some(&owner))
                                    .await;
                        }
                        net::rollback_made(self, &effective_conn, &net.made).await;
                        return Err(cloud_err(
                            "aliyun-ecs",
                            "RunInstances",
                            "unexpected non-JSON response",
                        ));
                    };
                    let Some(inst_id) = v["InstanceIdSets"]["InstanceIdSet"]
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(|x| x.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    else {
                        if let Some(ref vsw) = made_vsw {
                            let _ =
                                net::delete_part_owned(self, &effective_conn, vsw, Some(&owner))
                                    .await;
                        }
                        net::rollback_made(self, &effective_conn, &net.made).await;
                        return Err(cloud_err(
                            "aliyun-ecs",
                            "RunInstances",
                            "RunInstances returned no InstanceId",
                        ));
                    };

                    let mut r = Resource {
                        provider: "aliyun-ecs".into(),
                        id: inst_id.to_string(),
                        resource_type: "instance".into(),
                        name: spec.name.clone(),
                        region: region.clone(),
                        zone: cand.zone_id.clone(),
                        created: model::now(),
                        expires: model::tag_expires(&spec.tags),
                        tags: spec.tags.clone(),
                        state: "pending".into(),
                        ..Default::default()
                    };
                    r.extra.insert("machine_type".into(), instance_type);
                    r.extra.insert("image".into(), image_id);
                    r.extra.insert("vpc".into(), net.vpc_id);
                    r.extra.insert("vswitch".into(), vswitch_id);
                    r.extra
                        .insert("security_group".into(), net.security_group_id);

                    let mut out = vec![r];
                    out.extend(net.made);
                    if let Some(vsw) = made_vsw {
                        out.push(vsw);
                    }
                    return Ok(out);
                }
                Ok((status, body)) => {
                    let code = match &body {
                        ApiBody::Json(v) => api_error_code_message(v).0.to_string(),
                        ApiBody::Text(_) => String::new(),
                    };
                    let err = map_api_error("RunInstances", ECS_API_VERSION, status, &body);
                    if let Some(ref vsw) = made_vsw {
                        let _ =
                            net::delete_part_owned(self, &effective_conn, vsw, Some(&owner)).await;
                    }
                    if is_zone_capacity_error(&code) {
                        tried.push(format!("{} ({vswitch_id}): {err}", cand.zone_id));
                        continue;
                    }
                    net::rollback_made(self, &effective_conn, &net.made).await;
                    return Err(err);
                }
                Err(e) => {
                    if let Some(ref vsw) = made_vsw {
                        let _ =
                            net::delete_part_owned(self, &effective_conn, vsw, Some(&owner)).await;
                    }
                    net::rollback_made(self, &effective_conn, &net.made).await;
                    return Err(e);
                }
            }
        }

        net::rollback_made(self, &effective_conn, &net.made).await;
        Err(cloud_err(
            "aliyun-ecs",
            &format!("start a {instance_type} in {region}"),
            format!("tried {} zones: {}", tried.len(), tried.join("; ")),
        ))
    }

    async fn describe(
        &self,
        conn: &Connection,
        r: &Resource,
    ) -> Result<Option<(String, BTreeMap<String, String>)>> {
        self.describe_resource(conn, r).await
    }

    async fn stop(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()> {
        self.stop_resource(conn, r, owner).await
    }

    async fn start(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()> {
        self.start_resource(conn, r, owner).await
    }

    async fn delete(&self, conn: &Connection, r: &Resource, owner: &str) -> Result<()> {
        self.delete_resource(conn, r, owner).await
    }

    async fn list_owned(&self, conn: &Connection, owner: &str) -> Result<Vec<Resource>> {
        self.list_owned_resources(conn, owner).await
    }

    async fn boot_log(&self, conn: &Connection, r: &Resource) -> Result<Option<String>> {
        self.fetch_boot_log(conn, r).await
    }

    fn capabilities(&self, _conn: &Connection) -> Capabilities {
        Capabilities::default()
    }
}
