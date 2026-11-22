// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Your own cloud account as a sandbox location (`--on aws`, `gcp`,
//! `modal`, `hetzner`, `aliyun-ecs`): the records every surface shares
//! (`cua cloud`, the SDK, the Spaces `cloud_*` tools, the apps) and
//! [`CloudManager`], the service that connects, checks and sweeps the clouds.
//! The providers themselves are ordinary [`crate::Provider`]s registered like
//! the contrib ones; they live in the `cua-byoc` crate.
//!
//! Every cloud sandbox is a relay machine of the signed-in cua.ai account (or
//! a self-hosted relay in Static Relay Mode): the guest's cua-spacesd dials
//! out to the relay (no inbound port), and the SDK reaches it there
//! ([`crate::Provider::connect_options`]). Its instance details carry
//! [`DETAIL_RELAY_MACHINE`], which is how Spaces shows it as
//! `relay:<machine>`.

#[path = "byoc_reports.rs"]
mod byoc_reports;
#[path = "byoc_url.rs"]
mod byoc_url;

pub use byoc_reports::*;
pub use byoc_url::*;

use serde::{Deserialize, Serialize};

use crate::Result;

/// The instance detail naming the relay machine a cloud sandbox joined as.
pub const DETAIL_RELAY_MACHINE: &str = "relay_machine";

/// Relay machine metadata (`meta`) a cloud sandbox's machine is registered
/// with, so every device of the account can label it and knows where it
/// can be deleted. No secrets.
pub mod meta {
    /// The provider word (`aws`, `gcp`, `hetzner`, `modal`, `aliyun-ecs`).
    pub const PROVIDER: &str = "cua.cloud.provider";
    /// Where it runs, for people ("AWS · us-west-2").
    pub const PLACE: &str = "cua.cloud.place";
    /// The sandbox's name.
    pub const SANDBOX: &str = "cua.cloud.sandbox";
    /// The cua home that created it (its `cua-owner` tag).
    pub const OWNER: &str = "cua.cloud.owner";
    /// That home's own relay machine, when it is a host other devices can
    /// ask to delete it (`HostSpacesService.DeleteCloudSpace`).
    pub const HOST: &str = "cua.cloud.host";
    /// That home's device name, for "delete it there".
    pub const DEVICE: &str = "cua.cloud.device";
}

/// The instance detail naming where a cloud sandbox runs ("AWS ·
/// us-west-2"), shown next to its Space.
pub const DETAIL_PLACE: &str = "place";

/// Human-readable title for a cloud provider location (`aws` -> `"AWS"`).
pub fn provider_title(name: &str) -> &str {
    match name {
        "aliyun-ecs" => "Alibaba Cloud ECS",
        "aws" => "AWS",
        "gcp" => "Google Cloud",
        "azure" => "Microsoft Azure",
        "hetzner" => "Hetzner Cloud",
        "modal" => "Modal",
        _ => name,
    }
}

/// Where a cloud's credentials were found on this machine.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudCredentials {
    /// Whether the cloud's CLI sign-in (or its config) is on this machine.
    pub found: bool,
    /// Where ("~/.aws profile default", "gcloud account ada@x.io"), never a
    /// secret. Empty when none was found.
    #[serde(default)]
    pub source: String,
}

/// What a cloud can run for one image family, and at what cost.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudKind {
    /// The image family (`linux`, `linux-slim`, `windows`, `omarchy`,
    /// `macos`).
    pub image: String,
    /// `container` or `vm`.
    pub kind: String,
    /// Whether a sandbox of it can be created there.
    pub supported: bool,
    /// Why not (one line), or a note on how it runs.
    #[serde(default)]
    pub reason: String,
    /// The machine type Cua picks for it (`t3.medium`, `e2-medium`, a
    /// Modal CPU and memory size).
    #[serde(default)]
    pub machine_type: String,
    /// The estimated on-demand cost per hour in US dollars while it runs
    /// (compute and disk; not network).
    #[serde(default)]
    pub usd_per_hour: f64,
}

/// How a cloud connection authenticates with its relay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    /// Backed by user account authentication and a machine directory, where
    /// each cloud sandbox is registered dynamically under the signed-in
    /// account.
    #[default]
    Account,
    /// Self-hosted relay authenticated by a shared registration token and
    /// per-sandbox environment tokens, requiring no account sign-in.
    Static,
}

impl RelayMode {
    /// Wire word (`account` or `static`).
    pub fn as_str(self) -> &'static str {
        match self {
            RelayMode::Account => "account",
            RelayMode::Static => "static",
        }
    }

    /// Parses `account` or `static` (case-insensitive, trimmed).
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "account" => Ok(RelayMode::Account),
            "static" => Ok(RelayMode::Static),
            other => Err(crate::Error::InvalidArgument(format!(
                "relay_mode {other:?} is not account or static"
            ))),
        }
    }
}

impl std::fmt::Display for RelayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The default official Cua relay URL.
pub const DEFAULT_RELAY_URL: &str = "https://relay.cua.ai";

fn is_false(b: &bool) -> bool {
    !*b
}

fn redact_opt_url(url: &Option<String>) -> Option<String> {
    url.as_deref().map(redact_url)
}

fn redact_secret(secret: &Option<String>) -> Option<&'static str> {
    secret.as_ref().map(|_| "<redacted>")
}

macro_rules! debug_fields {
    ($ds:expr, $self:expr; $($field:ident),* $(,)?) => {{
        let mut d = $ds;
        $(d.field(stringify!($field), &$self.$field);)*
        d
    }};
}

/// Validates and trims an optional identifier or token (`cloud_image_id`,
/// `instance_type`, `--windows-image-id`, etc.), rejecting empty/whitespace-only
/// values and values containing internal whitespace.
pub fn normalize_optional_token(label: &str, raw: Option<&str>) -> Result<Option<String>> {
    let Some(s) = raw else {
        return Ok(None);
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(crate::Error::InvalidArgument(format!(
            "{label} cannot be empty"
        )));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(crate::Error::InvalidArgument(format!(
            "{label} {trimmed:?} must not contain whitespace"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

/// One cloud as `cloud_status` lists it.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudProvider {
    /// `aws`, `gcp`, `hetzner`, `modal`, `aliyun-ecs`.
    pub name: String,
    /// `AWS`, `Google Cloud`, `Hetzner Cloud`, `Modal`, `Alibaba Cloud ECS`.
    pub title: String,
    /// `vm` (one VM per sandbox) or `sandbox` (one platform sandbox each).
    pub tier: String,
    /// Whether it is connected (`cloud_connect`).
    pub connected: bool,
    /// Whether it is the default location (`default.on`).
    #[serde(default)]
    pub default: bool,
    /// The credentials found on this machine.
    #[serde(default)]
    pub credentials: CloudCredentials,
    /// The account, project or workspace the credentials reach (after a
    /// test or connect).
    #[serde(default)]
    pub account: String,
    /// AWS or Modal profile.
    #[serde(default)]
    pub profile: String,
    /// Region (a Hetzner location such as `fsn1`).
    #[serde(default)]
    pub region: String,
    /// GCP zone.
    #[serde(default)]
    pub zone: String,
    /// GCP project.
    #[serde(default)]
    pub project: String,
    /// Modal environment.
    #[serde(default)]
    pub environment: String,
    /// How the apps name it once connected: "AWS · us-west-2".
    #[serde(default)]
    pub label: String,
    /// Hours after which a sandbox there deletes itself (0: never).
    #[serde(default)]
    pub ttl_hours: u32,
    /// What it can run, and the cost.
    #[serde(default)]
    pub kinds: Vec<CloudKind>,
    /// How it reaches the cloud: `cli` (the cloud CLI's sign-in on this
    /// device), `oidc` (Cua's issuer, no stored key) or `sealed`; empty
    /// when not connected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth: String,
    /// [`status`]: `connected`, `waiting-for-approval`, `not-connected`
    /// (and, from `cloud_connect`, `needs-trust`, `checking`, `failed`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    /// The monthly budget (US dollars), when one is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_usd_month: Option<f64>,
    /// The largest machine Cua may create there (`4x16`: vCPUs x GiB),
    /// empty: no limit.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub max_size: String,
    /// Estimated US dollars Cua's machines there cost this calendar month
    /// (UTC), list price times runtime.
    #[serde(default)]
    pub spent_month: f64,
    /// Machines (and sandboxes) Cua runs there now.
    #[serde(default)]
    pub running: u32,
    /// What waits for a person's approval in Cua Spaces: `connection`,
    /// `limits`, or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub approval: String,
    /// The agent whose link or limits wait for approval, when an agent
    /// asked.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub approval_agent: String,
    /// The monthly budget an agent asked for, waiting for approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_budget_usd_month: Option<f64>,
    /// The largest machine an agent asked for (`4x16`), waiting for
    /// approval.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pending_max_size: String,
    /// Whether the caller can approve or deny what waits (`cloud_approve`):
    /// a person's session on a device signed in to the account, never an
    /// agent.
    #[serde(default)]
    pub can_approve: bool,
    /// A better way to link it that this link could switch to (`oidc` for
    /// an AWS link through the CLI sign-in), or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub suggest_auth: String,
    /// What is wrong with the link and what to do, in one plain sentence
    /// (for example, it was disconnected on another device), or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issue: String,
    /// `sealed`: the devices that can open the account's API token now
    /// (names, else ids). At least one must be online for machines to be
    /// made there unattended.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holders: Vec<String>,
    /// Per-connection relay base URL (`https://relay.cua.ai` by default),
    /// or `None` when not connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Relay authentication mode (`account` or `static`), or `None` when
    /// not connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_mode: Option<RelayMode>,
    /// Optional custom `cua-spacesd` binary mirror URL (with optional
    /// `#sha256=<64 hex>` fragment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spacesd_download_url: Option<String>,
    /// Existing Alibaba Cloud VPC ID to attach sandboxes to (`aliyun-ecs`),
    /// or `None` for Cua's isolated VPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,
    /// Existing Alibaba Cloud VSwitch ID to attach sandboxes to (`aliyun-ecs`),
    /// or `None` for Cua's isolated VPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vswitch_id: Option<String>,
    /// Whether public IPv4 assignment is disabled (`InternetMaxBandwidthOut=0`)
    /// on `aliyun-ecs`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_public_ip: bool,
    /// Default Windows Cloud Image ID (`aliyun-ecs`: `--windows-image-id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_image_id: Option<String>,
    /// Default Linux Cloud Image ID (`aliyun-ecs`: `--linux-image-id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux_image_id: Option<String>,
    /// Default cloud instance type (`aliyun-ecs`: `--instance-type`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
}

impl std::fmt::Debug for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        debug_fields!(f.debug_struct("CloudProvider"), self;
            name, title, tier, connected, default, credentials, account, profile, region, zone,
            project, environment, label, ttl_hours, kinds, auth, status, budget_usd_month,
            max_size, spent_month, running, approval, approval_agent, pending_budget_usd_month,
            pending_max_size, can_approve, suggest_auth, issue, holders, relay_url, relay_mode,
            vpc_id, vswitch_id, no_public_ip, windows_image_id, linux_image_id, instance_type
        )
        .field(
            "spacesd_download_url",
            &redact_opt_url(&self.spacesd_download_url),
        )
        .finish()
    }
}

/// The words of [`CloudProvider::status`] and [`CloudConnected`]'s outcome.
pub mod status {
    /// Ready: Spaces can be created there.
    pub const CONNECTED: &str = "connected";
    /// Not linked.
    pub const NOT_CONNECTED: &str = "not-connected";
    /// The cloud does not trust Cua yet: a person sets up the trust
    /// (`next.open`).
    pub const NEEDS_TRUST: &str = "needs-trust";
    /// Recorded; the check that proves it works has not run
    /// (`next.run`).
    pub const CHECKING: &str = "checking";
    /// An agent linked it or raised a limit: a person approves it in Cua
    /// Spaces.
    pub const WAITING_FOR_APPROVAL: &str = "waiting-for-approval";
    /// It did not work; `checks` and `next` say why.
    pub const FAILED: &str = "failed";
}

/// The next step of a `cloud_connect`: a command for the agent to run, or
/// a page for a person to open, and why.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudNext {
    /// The exact command the agent runs next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// The page a person opens next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<String>,
    /// What the person pastes there (an AWS CloudShell command), when
    /// there is something to paste.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paste: Option<String>,
    /// Why, in plain words.
    pub why: String,
}

impl CloudNext {
    /// Whether it waits on a person (a page to open).
    pub fn for_person(&self) -> bool {
        self.open.is_some()
    }
}

/// The environment variable a Cua agent run carries with its agent's name
/// (a persistent agent or routine).
pub const AGENT_VAR: &str = "CUA_AGENT";

/// The run id every Cua agent run carries: an agent with no name is still
/// an agent.
pub const AGENT_RUN_VAR: &str = "CUA_AGENT_RUN_ID";

/// Coding agents that mark their shells, and the name each acts as.
pub const CODING_AGENT_VARS: &[(&str, &str)] = &[
    ("CLAUDECODE", "claude-code"),
    ("CURSOR_AGENT", "cursor"),
    ("GEMINI_CLI", "gemini-cli"),
    ("CODEX_SANDBOX", "codex"),
];

/// The Cua agent this process runs for ([`AGENT_VAR`], else
/// [`AGENT_RUN_VAR`]) over `env`; `None` when none.
pub fn cua_agent_with(env: impl Fn(&str) -> Option<String>) -> Option<String> {
    [AGENT_VAR, AGENT_RUN_VAR]
        .into_iter()
        .filter_map(env)
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
}

/// [`cua_agent_with`] over this process's environment.
pub fn cua_agent() -> Option<String> {
    cua_agent_with(|k| std::env::var(k).ok())
}

/// Who runs this process, over `env`: a Cua agent's name or run id, else a
/// coding agent that marks its shell (Claude Code, Cursor, Gemini CLI,
/// Codex); `None` when a person does.
pub fn caller_agent_with(env: impl Fn(&str) -> Option<String>) -> Option<String> {
    cua_agent_with(&env).or_else(|| {
        CODING_AGENT_VARS
            .iter()
            .find(|(k, _)| env(k).is_some_and(|v| !v.trim().is_empty()))
            .map(|(_, name)| (*name).to_string())
    })
}

/// [`caller_agent_with`] over this process's environment.
pub fn caller_agent() -> Option<String> {
    caller_agent_with(|k| std::env::var(k).ok())
}

/// What `cloud_connect` asks for.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConnectRequest {
    /// Where in the account.
    pub target: CloudTarget,
    /// Also make it the default location.
    pub make_default: bool,
    /// Hours a Space there lives (default 8, 0: never).
    pub ttl_hours: Option<u32>,
    /// `cli` (default: the cloud CLI's sign-in), `oidc` or `sealed`.
    pub auth: Option<String>,
    /// The monthly budget, US dollars.
    pub budget_usd_month: Option<f64>,
    /// The largest machine, `4x16` (vCPUs x GiB).
    pub max_size: Option<String>,
    /// AWS: the 12-digit account id the trust stack is in.
    pub account_id: Option<String>,
    /// AWS: the role, when it is not `cua-spaces`.
    pub role_arn: Option<String>,
    /// Google Cloud `oidc`: the project number (the trust script prints
    /// it). The project id is `target.project`.
    pub project_number: Option<String>,
    /// Google Cloud `oidc`: a service account to act as (default: none,
    /// the federated identity calls Google directly).
    pub service_account: Option<String>,
    /// Azure: the subscription id.
    pub subscription_id: Option<String>,
    /// Azure: the Microsoft Entra tenant id.
    pub tenant_id: Option<String>,
    /// Azure: the client id of the `cua-spaces` managed identity.
    pub client_id: Option<String>,
    /// Azure: the resource group Cua works in (default `cua-spaces`).
    pub resource_group: Option<String>,
    /// Run the check that proves the link works (a `check` token, the
    /// exchange, a dry run).
    pub check: bool,
    /// The agent that asks, when an agent does (its changes wait for a
    /// person's approval).
    pub agent: Option<String>,
}

impl ConnectRequest {
    /// The way it links, `cli`, `oidc` or `sealed`: the one asked for,
    /// else `oidc` for Azure (it has no CLI sign-in link) and for a Google
    /// Cloud project number or service account (they name OIDC trust),
    /// else `cli`.
    pub fn auth_word(&self) -> String {
        let given = |o: &Option<String>| o.as_deref().is_some_and(|v| !v.trim().is_empty());
        match self
            .auth
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            Some(a) => a.to_ascii_lowercase(),
            None if self.target.provider.eq_ignore_ascii_case("azure") => "oidc".into(),
            None if self.target.provider.eq_ignore_ascii_case("gcp")
                && (given(&self.project_number) || given(&self.service_account)) =>
            {
                "oidc".into()
            }
            None => "cli".into(),
        }
    }

    /// Whether it asks for today's CLI sign-in link ([`Self::auth_word`]
    /// is `cli`).
    pub fn is_cli(&self) -> bool {
        self.auth_word() == "cli"
    }
}

/// Where in a cloud account sandboxes go (`cloud_connect`, `cloud_test`).
/// Clouds with a CLI sign-in (AWS, Google Cloud, Hetzner, Modal) use it, and Cua
/// stores only these names. A cloud that has only an API token (Hetzner)
/// takes it in [`CloudTarget::token`]: used for the checks, saved in the
/// Cua credential store only when they pass, and never in `Debug` output,
/// logs or the connection record.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudTarget {
    /// `aws`, `gcp`, `hetzner`, `modal`, `aliyun-ecs`.
    pub provider: String,
    /// AWS or Modal profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Region (a Hetzner location such as `fsn1`).
    #[serde(default)]
    pub region: Option<String>,
    /// GCP zone.
    #[serde(default)]
    pub zone: Option<String>,
    /// GCP project.
    #[serde(default)]
    pub project: Option<String>,
    /// Modal environment.
    #[serde(default)]
    pub environment: Option<String>,
    /// The API token of a cloud that has no CLI sign-in (Hetzner). Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Per-connection relay base URL (defaults to `https://relay.cua.ai`
    /// in Account Relay Mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Relay authentication mode (`account` or `static`; defaults to `account`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_mode: Option<RelayMode>,
    /// Shared static relay registration token for Static Relay Mode. Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_token: Option<String>,
    /// Optional custom `cua-spacesd` binary mirror URL (with optional
    /// `#sha256=<64 hex>` fragment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spacesd_download_url: Option<String>,
    /// Existing Alibaba Cloud VPC ID (`aliyun-ecs` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,
    /// Existing Alibaba Cloud VSwitch ID (`aliyun-ecs` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vswitch_id: Option<String>,
    /// Do not assign a public IPv4 address (`InternetMaxBandwidthOut=0`,
    /// `aliyun-ecs` only).
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_public_ip: bool,
    /// Default Windows Cloud Image ID (`aliyun-ecs`: `--windows-image-id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_image_id: Option<String>,
    /// Default Linux Cloud Image ID (`aliyun-ecs`: `--linux-image-id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux_image_id: Option<String>,
    /// Default cloud instance type (`aliyun-ecs`: `--instance-type`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
}

impl std::fmt::Debug for CloudTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        debug_fields!(f.debug_struct("CloudTarget"), self;
            provider, profile, region, zone, project, environment, relay_url, relay_mode,
            vpc_id, vswitch_id, no_public_ip, windows_image_id, linux_image_id, instance_type
        )
        .field("token", &redact_secret(&self.token))
        .field("relay_token", &redact_secret(&self.relay_token))
        .field(
            "spacesd_download_url",
            &redact_opt_url(&self.spacesd_download_url),
        )
        .finish()
    }
}

/// Connects, checks and sweeps your clouds (implemented in `cua-byoc`).
#[async_trait::async_trait]
pub trait CloudManager: Send + Sync + 'static {
    /// `cloud_status`: `provider` narrows it to one cloud.
    async fn status(&self, provider: Option<&str>) -> Result<CloudStatusReport>;

    /// The configured relay mode for `provider`, if connected.
    fn relay_mode(&self, _provider: &str) -> Option<RelayMode> {
        None
    }

    /// `cloud_test`: creates nothing.
    async fn test(&self, target: &CloudTarget) -> Result<CloudTestReport>;

    /// `cloud_connect`: runs the test first; with `make_default`, sets
    /// `default.on`. `ttl_hours` (default 8, 0: never) deletes every
    /// sandbox there after that long.
    async fn connect(
        &self,
        target: &CloudTarget,
        make_default: bool,
        ttl_hours: Option<u32>,
    ) -> Result<CloudConnected>;

    /// `cloud_connect` with every option: federation (`auth`), limits,
    /// the check. Without `auth` (or `cli`) it is [`CloudManager::connect`]
    /// plus the limits.
    async fn connect_with(&self, req: &ConnectRequest) -> Result<CloudConnected> {
        if !req.is_cli() {
            return Err(not_built());
        }
        let mut c = self
            .connect(&req.target, req.make_default, req.ttl_hours)
            .await?;
        c.provider.status = status::CONNECTED.into();
        Ok(c)
    }

    /// `cloud_disconnect`: refuses while Spaces Cua created still run
    /// there (it lists them). With `delete`, deletes everything Cua created
    /// there first and forgets the connection only once the cloud confirms
    /// nothing is left.
    async fn disconnect(&self, provider: &str, delete: bool) -> Result<CloudDisconnected>;

    /// `cloud_approve`: a person approves (or, with `deny`, declines) what
    /// an agent asked for on `provider`: its link, or its raised limits.
    /// Refused when an agent calls.
    async fn approve(&self, provider: &str, deny: bool) -> Result<CloudProvider> {
        let _ = (provider, deny);
        Err(not_built())
    }

    /// `cloud_sweep`: dry run unless `dry_run` is false.
    async fn sweep(
        &self,
        provider: Option<&str>,
        dry_run: bool,
        all: bool,
    ) -> Result<CloudSweepReport>;

    /// The machine types every linked cloud offers to the elastic pool,
    /// one row per type and region (empty: no cloud linked, or none can
    /// add machines now).
    async fn host_offers(&self) -> Result<Vec<HostTypeOffer>> {
        Ok(vec![])
    }

    /// The hosts this home added to the pool, in every linked cloud.
    async fn hosts(&self) -> Result<Vec<CloudHost>> {
        Ok(vec![])
    }

    /// Adds a host: it is tagged and recorded first, then created; it
    /// installs cua, joins the account's pool as a host that provides
    /// Spaces, and ends on its own at its TTL. Returns once the cloud
    /// accepted it (state `booting`); [`CloudManager::hosts`] shows it
    /// `joined` when it is in the pool.
    async fn add_host(&self, _req: &AddHost) -> Result<CloudHost> {
        Err(not_built())
    }

    /// Removes a host this home added (refused for anything else).
    async fn remove_host(&self, _name: &str) -> Result<()> {
        Err(not_built())
    }

    /// Cordons a host this home added (it takes no new Spaces and drains),
    /// or opens it again.
    async fn cordon_host(&self, _name: &str, _cordoned: bool) -> Result<()> {
        Err(not_built())
    }

    /// The automatic sweep the daemon schedules: deletes what
    /// `cloud_sweep` with `dry_run: false` (and not `all`) deletes, in
    /// every connected cloud; one failing cloud does not stop the others.
    async fn auto_sweep(&self) -> Result<CloudSweepReport>;

    /// `cloud_audit`: the newest `limit` lines of the audit log, newest
    /// last.
    async fn audit(&self, limit: usize) -> Result<Vec<CloudAuditEntry>>;

    /// `cloud_audit` with every option: `provider` narrows it to one cloud;
    /// clouds linked to the account also bring the account's entries
    /// (`source: account`). Oldest first, newest last.
    async fn audit_for(
        &self,
        provider: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CloudAuditEntry>> {
        let mut v = self.audit(limit).await?;
        if let Some(p) = provider {
            v.retain(|e| e.provider.eq_ignore_ascii_case(p));
        }
        Ok(v)
    }

    /// `cloud_cost`: what the machines Cua created cost since `since`
    /// (`YYYY-MM-DD`; default the first of this month), grouped `by`
    /// ([`cost_by`]).
    async fn cost(
        &self,
        _provider: Option<&str>,
        _by: &str,
        _since: Option<&str>,
    ) -> Result<CloudCostReport> {
        Err(not_built())
    }
}

/// The error a cloud word without a manager in this build gets.
pub fn not_built() -> crate::Error {
    crate::Error::Unsupported {
        provider: crate::ProviderKind::Contrib,
        op: "your own cloud (aws, gcp, hetzner, modal): this build has no cloud providers (build the \
             cua CLI or SDK with the `byoc` feature, which the release builds include)"
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_title_maps_known_clouds_and_falls_back_to_name() {
        assert_eq!(provider_title("aliyun-ecs"), "Alibaba Cloud ECS");
        assert_eq!(provider_title("aws"), "AWS");
        assert_eq!(provider_title("gcp"), "Google Cloud");
        assert_eq!(provider_title("azure"), "Microsoft Azure");
        assert_eq!(provider_title("hetzner"), "Hetzner Cloud");
        assert_eq!(provider_title("modal"), "Modal");
        assert_eq!(provider_title("custom-cloud"), "custom-cloud");
    }

    #[test]
    fn azure_and_named_google_trust_link_through_the_issuer() {
        let req = |provider: &str, f: &dyn Fn(&mut ConnectRequest)| {
            let mut r = ConnectRequest {
                target: CloudTarget {
                    provider: provider.into(),
                    ..Default::default()
                },
                ..Default::default()
            };
            f(&mut r);
            r
        };
        assert_eq!(req("aws", &|_| {}).auth_word(), "cli");
        assert!(req("gcp", &|_| {}).is_cli());
        assert_eq!(req("azure", &|_| {}).auth_word(), "oidc");
        assert_eq!(
            req("gcp", &|r| r.project_number = Some("123".into())).auth_word(),
            "oidc"
        );
        assert_eq!(
            req("gcp", &|r| r.service_account = Some(" ".into())).auth_word(),
            "cli"
        );
        assert_eq!(
            req("aws", &|r| r.auth = Some(" OIDC ".into())).auth_word(),
            "oidc"
        );
        assert_eq!(
            req("azure", &|r| r.auth = Some("sealed".into())).auth_word(),
            "sealed"
        );
    }

    #[test]
    fn relay_mode_defaults_serializes_and_target_redacts_relay_token() {
        assert_eq!(RelayMode::default(), RelayMode::Account);
        assert_eq!(RelayMode::Account.as_str(), "account");
        assert_eq!(RelayMode::Static.as_str(), "static");
        assert_eq!(RelayMode::parse("ACCOUNT").unwrap(), RelayMode::Account);
        assert_eq!(RelayMode::parse(" static ").unwrap(), RelayMode::Static);
        assert!(RelayMode::parse("bogus").is_err());

        let t = CloudTarget {
            provider: "hetzner".into(),
            relay_url: Some("https://relay.example".into()),
            relay_mode: Some(RelayMode::Static),
            relay_token: Some("super-secret-relay-token".into()),
            ..Default::default()
        };
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("super-secret-relay-token"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");

        let p: CloudProvider =
            serde_json::from_str(r#"{"name":"aws","title":"AWS","tier":"vm","connected":false}"#)
                .unwrap();
        assert_eq!(p.relay_url, None);
        assert_eq!(p.relay_mode, None);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(!serialized.contains("relay_url"));
        assert!(!serialized.contains("relay_mode"));
    }

    #[test]
    fn existing_vpc_fields_default_and_skip_serializing_when_unset() {
        let t = CloudTarget {
            provider: "aliyun-ecs".into(),
            vpc_id: Some("vpc-123".into()),
            vswitch_id: Some("vsw-456".into()),
            no_public_ip: true,
            ..Default::default()
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("vpc-123"), "{dbg}");
        assert!(dbg.contains("vsw-456"), "{dbg}");
        assert!(dbg.contains("no_public_ip: true"), "{dbg}");

        let p: CloudProvider = serde_json::from_str(
            r#"{"name":"aliyun-ecs","title":"Alibaba Cloud ECS","tier":"vm","connected":false}"#,
        )
        .unwrap();
        assert_eq!(p.vpc_id, None);
        assert_eq!(p.vswitch_id, None);
        assert!(!p.no_public_ip);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(!serialized.contains("vpc_id"), "{serialized}");
        assert!(!serialized.contains("vswitch_id"), "{serialized}");
        assert!(!serialized.contains("no_public_ip"), "{serialized}");
    }
}
