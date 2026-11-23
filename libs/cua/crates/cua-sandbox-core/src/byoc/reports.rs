// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Report, audit, budget, sweep, and elastic-pool types for BYOC clouds.

use serde::{Deserialize, Serialize};

use crate::byoc::{CloudNext, CloudProvider};

/// One thing Cua created in a cloud.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudResource {
    /// `aws`, `gcp`, `hetzner`, `modal`.
    pub provider: String,
    /// The cloud's id (`i-0abc...`, the instance name, `sb-...`).
    pub id: String,
    /// `instance`, `security_group`, `firewall`, `sandbox`, ...
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The sandbox it belongs to (`aws:<name>`), empty for shared
    /// resources (a security group).
    #[serde(default)]
    pub sandbox: String,
    /// The relay machine the sandbox joined as (its Space is
    /// `relay:<machine>`), when it has one.
    #[serde(default)]
    pub machine: String,
    /// Region (or zone).
    #[serde(default)]
    pub region: String,
    /// The cloud's state (`running`, `stopped`, `terminated`, `gone`).
    #[serde(default)]
    pub state: String,
    /// When Cua created it (RFC 3339).
    #[serde(default)]
    pub created: String,
    /// When it expires (RFC 3339; empty: never).
    #[serde(default)]
    pub expires: String,
    /// Whether it is past `expires`.
    #[serde(default)]
    pub expired: bool,
    /// Who started it: the agent's name, or `user`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub started_by: String,
    /// Estimated US dollars it cost so far (list price times runtime).
    #[serde(default)]
    pub cost_usd: f64,
}

/// `cloud_status`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudStatusReport {
    /// The default location (`default.on`), for example `aws`.
    #[serde(default)]
    pub default_on: String,
    /// Every cloud this build supports.
    pub providers: Vec<CloudProvider>,
    /// What Cua created in them.
    #[serde(default)]
    pub resources: Vec<CloudResource>,
}

/// One check of `cloud_test`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudCheck {
    /// `credentials`, `permissions`, `quota`, `region`, ...
    pub name: String,
    /// Whether it passed.
    pub ok: bool,
    /// What was found, or what to fix.
    #[serde(default)]
    pub detail: String,
}

/// `cloud_test`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudTestReport {
    /// The cloud.
    pub provider: String,
    /// Whether every check passed.
    pub ok: bool,
    /// The account, project or workspace the credentials reach.
    #[serde(default)]
    pub account: String,
    /// The checks, in order.
    pub checks: Vec<CloudCheck>,
}

/// `cloud_connect`: the cloud as `cloud_status` lists it (its `status`
/// is the outcome), the checks it ran, the next step and how to verify.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudConnected {
    /// The cloud, as `cloud_status` lists it.
    #[serde(flatten)]
    pub provider: CloudProvider,
    /// The checks it ran.
    #[serde(default)]
    pub checks: Vec<CloudCheck>,
    /// What to do next (`None`: nothing, it is connected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<CloudNext>,
    /// The command that confirms it (`cua cloud status aws`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verify: String,
}

/// `cloud_disconnect`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudDisconnected {
    /// The cloud.
    pub provider: String,
    /// Whether a connection was forgotten.
    pub disconnected: bool,
    /// Resources Cua still records there.
    #[serde(default)]
    pub left: Vec<CloudResource>,
    /// With `delete`: what was deleted from the account first (the
    /// receipt), each resource as `cloud_status` lists it.
    #[serde(default)]
    pub deleted: Vec<CloudResource>,
}

/// One line of the cloud audit log (`cloud_audit`): something Cua did in a
/// cloud account. Never carries a secret or a token.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudAuditEntry {
    /// When (RFC 3339, UTC).
    pub ts: String,
    /// `connect`, `disconnect`, `resource_recorded`, `resource_created`,
    /// `resource_confirmed` or `resource_deleted`.
    pub action: String,
    /// `aws`, `gcp`, `modal`.
    pub provider: String,
    /// The resource type (`instance`, `sandbox`, `security_group`, ...);
    /// empty for `connect` and `disconnect`.
    #[serde(default)]
    pub kind: String,
    /// The cloud id (the name Cua chose while a create is under way).
    #[serde(default)]
    pub id: String,
    /// The sandbox (Space) it belongs to; empty for shared resources.
    #[serde(default)]
    pub space: String,
    /// Who did it: `user`, `sweep`, `auto-sweep`, `disconnect` or
    /// `rollback`.
    #[serde(default)]
    pub actor: String,
    /// `ok`, `failed` or `refused`.
    #[serde(default)]
    pub outcome: String,
    /// A short note (the reason, or the error).
    #[serde(default)]
    pub detail: String,
    /// Where it was recorded: `device` (this cua home's log) or `account`
    /// (Cua's issuer, for clouds linked to the account: tokens issued or
    /// refused, approvals, limit changes). Empty from an older cua: this
    /// device.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

/// How `cloud_cost` groups the spend.
pub mod cost_by {
    /// One row per Space.
    pub const SPACE: &str = "space";
    /// One row per agent (`user` for what a person started).
    pub const AGENT: &str = "agent";
    /// One row per UTC day (`YYYY-MM-DD`).
    pub const DAY: &str = "day";
    /// One row per cloud.
    pub const CLOUD: &str = "cloud";
    /// Every grouping, in the order the docs list them.
    pub const ALL: &[&str] = &[SPACE, AGENT, DAY, CLOUD];
}

/// One row of `cloud_cost`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudCostRow {
    /// The Space, agent, day (`YYYY-MM-DD`) or cloud.
    pub key: String,
    /// Estimated US dollars (list price times runtime), to the cent.
    pub usd: f64,
    /// Machine hours, to the hundredth.
    pub hours: f64,
    /// How many machines ran.
    pub machines: u32,
}

/// `cloud_cost`: what the machines Cua created cost, estimated from list
/// price times runtime (the cloud's bill is the final word).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudCostReport {
    /// `space`, `agent`, `day` or `cloud`.
    pub by: String,
    /// The first day counted (`YYYY-MM-DD`, UTC).
    pub since: String,
    /// Up to when (RFC 3339).
    pub until: String,
    /// The rows: by day oldest first, otherwise the costliest first.
    pub rows: Vec<CloudCostRow>,
    /// The sum of the rows, to the cent.
    pub total_usd: f64,
}

/// A cloud's spend crossed a share of its monthly budget.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudBudgetAlert {
    /// `aws`, `gcp`, `hetzner`, `modal`.
    pub provider: String,
    /// `AWS`, `Google Cloud`, ...
    pub title: String,
    /// 50, 80 or 100.
    pub percent: u32,
    /// `YYYY-MM` (UTC).
    pub month: String,
    /// Estimated US dollars spent this month.
    pub spent_usd: f64,
    /// The monthly budget.
    pub budget_usd: f64,
}

impl CloudBudgetAlert {
    /// "AWS reached 80% of its budget".
    pub fn title_line(&self) -> String {
        if self.percent >= 100 {
            format!("{} reached its monthly budget", self.title)
        } else {
            format!("{} reached {}% of its budget", self.title, self.percent)
        }
    }

    /// One plain sentence with the figures and what happens next.
    pub fn body_line(&self) -> String {
        let figures = format!(
            "About ${:.2} of ${:.2} spent this month.",
            self.spent_usd, self.budget_usd
        );
        if self.percent >= 100 {
            format!(
                "{figures} New machines there are refused until next month; stopping and \
                 deleting still work. Raise it with `cua cloud connect {} --budget <usd>`.",
                self.provider
            )
        } else {
            figures
        }
    }
}

/// Where budget alerts go besides the audit log: the app's notification
/// feed, registered by the Spaces runtime. Takes the cua home and the alert.
pub type BudgetAlertSink =
    std::sync::Arc<dyn Fn(&std::path::Path, &CloudBudgetAlert) + Send + Sync>;

fn alert_sink() -> &'static std::sync::RwLock<Option<BudgetAlertSink>> {
    static SINK: std::sync::OnceLock<std::sync::RwLock<Option<BudgetAlertSink>>> =
        std::sync::OnceLock::new();
    SINK.get_or_init(Default::default)
}

/// Sets where budget alerts are posted (the last call wins).
pub fn set_budget_alert_sink(sink: BudgetAlertSink) {
    *alert_sink().write().expect("alert sink") = Some(sink);
}

/// Posts `alert` for the cua home `home` to the registered sink, if any;
/// whether one was registered.
pub fn post_budget_alert(home: &std::path::Path, alert: &CloudBudgetAlert) -> bool {
    let sink = alert_sink().read().expect("alert sink").clone();
    match sink {
        Some(f) => {
            f(home, alert);
            true
        }
        None => false,
    }
}

/// One row of `cloud_sweep`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudSweepItem {
    /// The resource.
    #[serde(flatten)]
    pub resource: CloudResource,
    /// `delete` (dry run), `deleted`, `keep`, `forget`, `forgotten` or
    /// `failed`.
    pub action: String,
    /// Why.
    #[serde(default)]
    pub reason: String,
}

/// `cloud_sweep`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudSweepReport {
    /// Whether nothing was deleted.
    pub dry_run: bool,
    /// What was found.
    pub resources: Vec<CloudSweepItem>,
}

/// What a linked cloud supplies to the elastic pool.
pub mod supplies {
    /// Machines the pool controls: each runs cua-spacesd as a host and many
    /// Spaces run on it (AWS, GCP, Hetzner).
    pub const HOSTS: &str = "hosts";
    /// Spaces directly, one platform sandbox each (Modal).
    pub const SPACES: &str = "spaces";
}

/// One machine type a linked cloud offers to the elastic pool, in one
/// region: what the solver may add (`cua cloud plan` lists them).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HostTypeOffer {
    /// `aws`, `gcp`, `hetzner`, `modal`.
    pub provider: String,
    /// The cloud's type name (`cx33`, `c7g.xlarge`; for a Spaces supplier
    /// a size word such as `2x4`).
    pub type_name: String,
    /// Region or location.
    pub region: String,
    /// `amd64` or `arm64`.
    pub arch: String,
    /// vCPUs.
    pub vcpus: u32,
    /// Memory, MiB.
    pub memory_mb: u64,
    /// Boot disk, GiB.
    #[serde(default)]
    pub disk_gb: u32,
    /// It has `/dev/kvm` (runs `vm` and `microvm` Spaces).
    #[serde(default)]
    pub kvm: bool,
    /// Kinds its hosts create.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Accelerator, or empty.
    #[serde(default)]
    pub gpu: String,
    /// On-demand USD per hour, with what every machine of it carries.
    pub usd_per_hour: f64,
    /// Billed in steps of this many seconds.
    pub billing_step_secs: u64,
    /// Minimum billed seconds.
    pub billing_min_secs: u64,
    /// Typical seconds from add to ready (learned when measured).
    pub boot_secs: u32,
    /// [`supplies::HOSTS`] or [`supplies::SPACES`].
    pub supplies: String,
    /// How many more machines this provider allows now.
    #[serde(default)]
    pub max_new: u32,
    /// The quota pool its vCPUs count against (`hetzner/shared`); empty:
    /// none.
    #[serde(default)]
    pub quota: String,
    /// That pool's vCPU limit when the cloud says it (0: unknown).
    #[serde(default)]
    pub quota_vcpus: u32,
    /// 0 in the region you linked; n > 0 in the provider's n-th nearby
    /// region, which the pool uses only when every type it could use in the
    /// linked region has just failed (the cloud had no capacity there).
    #[serde(default)]
    pub fallback: u8,
}

/// A cloud host the elastic pool added (or `cua cloud hosts add`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudHost {
    /// Its pool name (`hetzner-3`).
    pub name: String,
    /// Provider.
    pub provider: String,
    /// Machine type.
    pub type_name: String,
    /// Region.
    pub region: String,
    /// The cloud's id.
    #[serde(default)]
    pub id: String,
    /// Its relay machine once joined (empty before).
    #[serde(default)]
    pub machine: String,
    /// `creating`, `booting`, `joined`, `cordoned`, `removing`, `gone`.
    pub state: String,
    /// Unix seconds it was created (billing starts).
    pub started: u64,
    /// Unix seconds it ends on its own at the latest (its TTL).
    #[serde(default)]
    pub expires: u64,
    /// USD per hour.
    pub usd_per_hour: f64,
    /// Billing step, seconds.
    pub billing_step_secs: u64,
    /// Minimum billed, seconds.
    pub billing_min_secs: u64,
    /// Added by hand (`cua cloud hosts add`): the scaler never removes it.
    #[serde(default)]
    pub pinned: bool,
}

/// Adds one host.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AddHost {
    /// Provider.
    pub provider: String,
    /// Machine type.
    pub type_name: String,
    /// Region (empty: the connection's).
    #[serde(default)]
    pub region: String,
    /// Pool name (empty: `<provider>-<n>`).
    #[serde(default)]
    pub name: String,
    /// Added by hand: never removed by the scaler.
    #[serde(default)]
    pub pinned: bool,
    /// Seconds until it ends on its own (0: the default, 24 h).
    #[serde(default)]
    pub ttl_secs: u64,
    /// Images it pulls as soon as it joined (the ones it is added for), so
    /// its first Spaces start without a pull.
    #[serde(default)]
    pub prepull: Vec<String>,
}
