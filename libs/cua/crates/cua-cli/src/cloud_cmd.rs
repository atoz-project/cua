// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! `cua cloud`: Spaces in your own cloud account (AWS, Google Cloud,
//! Hetzner, Modal, Alibaba Cloud ECS) as a location for sandboxes and Spaces.
//! The providers are the sandbox layer's (`cua-byoc`); this `cua` reaches them
//! through the `cloud_*` tools, in the daemon when one runs, else in process.

use std::io::Write;
use std::sync::Arc;

use clap::{Args, Subcommand};
use cua_sdk::{CloudTarget, Cua, CuaError};

use crate::util::{hint_line, line};

/// `cua cloud connect --help`: written so an agent can follow it end to
/// end without asking anything but what only a person knows.
const CONNECT_HELP: &str = "\
How it ends (every run, also with --json):
  status   connected | needs-trust | checking | waiting-for-approval | failed
  next     run: the exact command to run next, or
           open: a page a person opens (paste: what they paste there)
           why: what it is for, in plain words
  verify   the command that confirms it: cua cloud status <cloud>
  checks   what the check found
Exit code: 0 connected, 10 the next step is yours (run it), 11 it waits on a
person (send them `next`), 1 error.

AWS without a stored key (for agents: follow `next` until connected):
  1. Ask the person for a monthly budget (US dollars), the region and the
     largest machine, then run:
       cua cloud connect aws --oidc --region us-west-2 --budget 200 --max-size 4x16
  2. status needs-trust: send the person `next.open` (AWS CloudShell, or the
     CloudFormation quick-create link) and `next.paste`. It creates one
     stack, cua-spaces: an OIDC provider and the cua-spaces role, scoped to
     what Cua tags cua-managed=true. No keys. Ask them for the 12-digit AWS
     account id when it shows CREATE_COMPLETE.
  3. Run `next.run` (the same command with --account-id <ID> --check). It
     gets a check token, exchanges it with AWS STS and dry-runs a machine.
     Nothing is created.
  4. status connected: done. status waiting-for-approval: an agent made the
     link (or raised a limit), so a person approves it in the Cua Spaces
     app; then `cua cloud status aws` says connected.
  Verify: cua cloud status aws

Hetzner and Modal: the API token is sealed to your devices (only devices of
your account open it; Cua's servers keep ciphertext). Ask the person for a
budget and the token (Hetzner: Read & Write, Cloud Console, Security, API
tokens; Modal: `modal token new`, given as <token id>:<token secret>), then:
  cua cloud connect hetzner --token-stdin --region fsn1 --budget 50 --max-size 4x8
  It seals by default on a device with the account's pool keys when a
  budget is given; --sealed insists on it, --no-sealed keeps the token on
  this device only (as before). --sealed without a token seals the one this
  device already has.
  Verify: cua cloud status hetzner (its line says which devices can open it)

Google Cloud without a stored key:
  1. cua cloud connect gcp --oidc --project my-project --region us-central1 --budget 200 --max-size 4x16
  2. status needs-trust: a person opens `next.open` (Google Cloud Shell with
     Cua's trust script) and pastes `next.paste`: it creates the workload
     identity pool cua, its provider, the role cuaSpaces and one binding. No
     keys, no service accounts. It prints the project number. An agent on a
     machine signed in to gcloud gets `next.run` instead (the same script).
  3. Run `next.run` (with --project-number <N> --check): Google's STS
     exchanges a check token and the role's permissions are checked.
  Verify: cua cloud status gcp

Azure (always without a stored key):
  1. cua cloud connect azure --region westus2 --budget 200 --max-size 4x16
  2. status needs-trust: a person opens `next.open` (Deploy to Azure) and
     deploys into resource group cua-spaces: the cua-spaces managed identity
     trusting Cua's tokens, with Virtual Machine Contributor and Network
     Contributor on that group only. No keys. Ask for the outputs
     subscriptionId, tenantId and clientId. An agent on a machine signed in
     to the az CLI gets `next.run` instead.
  3. Run `next.run` (with --subscription --tenant --client-id --check):
     Microsoft Entra exchanges a check token, the resource group is read
     and a machine is validated.
  Verify: cua cloud status azure

Alibaba Cloud ECS (RAM sub-account AccessKey, `AK` mode):
  Resolves credentials in order: --token-stdin (<access_key_id>:<access_key_secret>),
  ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET, --profile <name>
  in ~/.aliyun/config.json, saved credential store, or the active `current`
  profile in ~/.aliyun/config.json. Default region: `cn-hangzhou`.
    cua cloud connect aliyun-ecs --token-stdin --region cn-hangzhou --budget 50 --max-size 4x16
    cua cloud connect aliyun-ecs --profile webhook_manager --region cn-shanghai
  Optional existing VPC attachment and private-only networking (--no-public-ip):
    cua cloud connect aliyun-ecs --vpc-id vpc-xxx --vswitch-id vsw-yyy --no-public-ip
  Optional default Cloud Image IDs and instance type:
    cua cloud connect aliyun-ecs --windows-image-id m-win11 --linux-image-id m-ubuntu --instance-type ecs.c7.2xlarge
  Verify: cua cloud status aliyun-ecs

Self-hosted relay (per connection, default https://relay.cua.ai in Account Relay Mode):
  Account Relay Mode on a custom relay keeps dynamic machine registration and JWKS:
    cua cloud connect aws --relay-url https://relay.example.com --region us-west-2
  Static Relay Mode uses a shared relay token and per-sandbox env tokens (no cua auth login):
    cua cloud connect hetzner --relay-mode static --relay-url https://relay.example.com --relay-token-stdin --region fsn1

Other clouds use their own CLI sign-in on this device.
`cua cloud trust <cloud>` prints the trust setup file (aws, gcp, azure).
Docs for agents: https://cua.ai/docs/spaces/guides/connect-a-cloud

Examples:
  # AWS without a stored key: start, then check with the account id
  cua cloud connect aws --oidc --region us-west-2 --budget 200 --max-size 4x16
  cua cloud connect aws --oidc --region us-west-2 --budget 200 --max-size 4x16 --account-id 123456789012 --check
  # Google Cloud without a stored key: start, then check with the project number
  cua cloud connect gcp --oidc --project my-project --region us-central1 --budget 200
  cua cloud connect gcp --oidc --project my-project --region us-central1 --budget 200 --project-number 123456789012 --check
  # Azure: start, then check with the template's outputs
  cua cloud connect azure --region westus2 --budget 200 --max-size 4x16
  cua cloud connect azure --region westus2 --budget 200 --subscription 00000000-0000-0000-0000-000000000000 --tenant 11111111-1111-1111-1111-111111111111 --client-id 22222222-2222-2222-2222-222222222222 --check
  # The cloud CLI's sign-in on this device, with the same limits
  cua cloud connect aws --profile sandbox --region us-west-2 --budget 50 --default
  cua cloud connect gcp --project my-project --region us-central1
  cua cloud connect modal --environment spaces
  # Hetzner: the project's API token on standard input, sealed to your devices
  cua cloud connect hetzner --token-stdin --region fsn1 --budget 50 --max-size 4x8
  # Modal: <token id>:<token secret> on standard input, sealed to your devices
  cua cloud connect modal --token-stdin --budget 50
  # Seal the Hetzner token this device already has
  cua cloud connect hetzner --sealed --budget 50
  # Spaces there delete themselves after 4 hours (default 8; 0: never)
  cua cloud connect aws --ttl-hours 4
  # Alibaba Cloud ECS: RAM AccessKey via stdin or ~/.aliyun/config.json profile
  cua cloud connect aliyun-ecs --token-stdin --region cn-hangzhou --budget 50 --max-size 4x16 --ttl-hours 8
  cua cloud connect aliyun-ecs --profile oauth --region cn-hangzhou
  cua cloud connect aliyun-ecs --profile oauth --region cn-hangzhou --spacesd-download-url https://mirror.example.com/cua-spacesd.exe
  cua cloud connect aliyun-ecs --profile oauth --vpc-id vpc-xxx --vswitch-id vsw-yyy --no-public-ip
  # Self-hosted relay: Account Relay Mode or Static Relay Mode
  cua cloud connect aws --relay-url https://relay.example.com --region us-west-2
  cua cloud connect hetzner --relay-mode static --relay-url https://relay.example.com --relay-token-stdin --region fsn1";

/// Where in a cloud account Spaces go.
#[derive(Args, Debug, Clone, Default)]
pub struct TargetArgs {
    /// `aws`, `azure`, `gcp`, `hetzner`, `modal` or `aliyun-ecs`.
    pub provider: String,
    /// AWS profile (`~/.aws/config`), Modal profile (`~/.modal.toml`), or
    /// Alibaba Cloud CLI profile (`~/.aliyun/config.json`).
    #[arg(long)]
    pub profile: Option<String>,
    /// AWS, Google Cloud, Azure or Alibaba Cloud region, or Hetzner location
    /// (default `fsn1` for Hetzner, `cn-hangzhou` for `aliyun-ecs`).
    #[arg(long)]
    pub region: Option<String>,
    /// Google Cloud zone (default: the region's `-a` zone).
    #[arg(long)]
    pub zone: Option<String>,
    /// Google Cloud project (default: `gcloud config get project`).
    #[arg(long)]
    pub project: Option<String>,
    /// Modal environment (default: the profile's).
    #[arg(long)]
    pub environment: Option<String>,
    /// Hetzner, Modal or Alibaba Cloud ECS: read the API token / AccessKey
    /// pair from stdin (Hetzner: Read & Write project token; Modal: `<token
    /// id>:<token secret>`; Alibaba Cloud ECS: `<access_key_id>:<access_key_secret>`).
    /// Hetzner and Modal seal to your devices when a budget is given (or with
    /// --no-sealed save on this device); Alibaba Cloud ECS saves into this
    /// device's Cua credential store.
    #[arg(long)]
    pub token_stdin: bool,
    /// Per-connection relay base URL (defaults to `https://relay.cua.ai`
    /// in Account Relay Mode).
    #[arg(long, value_name = "URL")]
    pub relay_url: Option<String>,
    /// Relay authentication mode (`account` or `static`; defaults to
    /// `account`).
    #[arg(long, value_parser = ["account", "static"])]
    pub relay_mode: Option<String>,
    /// Static Relay Mode: read the shared static relay registration token
    /// from stdin (never pass tokens in argv).
    #[arg(long, conflicts_with = "token_stdin")]
    pub relay_token_stdin: bool,
    /// Optional custom `cua-spacesd` binary mirror URL for Windows Direct VM
    /// provisioning (with optional `#sha256=<64 hex>` fragment).
    #[arg(long, value_name = "URL")]
    pub spacesd_download_url: Option<String>,
    /// Existing Alibaba Cloud VPC ID (`aliyun-ecs` only). Must be paired
    /// with `--vswitch-id`.
    #[arg(long, value_name = "VPC_ID")]
    pub vpc_id: Option<String>,
    /// Existing Alibaba Cloud VSwitch ID (`aliyun-ecs` only). Must be paired
    /// with `--vpc-id`.
    #[arg(long, value_name = "VSWITCH_ID")]
    pub vswitch_id: Option<String>,
    /// Do not assign a public IPv4 address (`InternetMaxBandwidthOut=0`,
    /// `aliyun-ecs` only).
    #[arg(long)]
    pub no_public_ip: bool,
    /// Alibaba Cloud ECS: default Windows Cloud Image ID (`m-xxx`, e.g.
    /// golden Windows 10/11/Server image) for Windows sandboxes.
    #[arg(long, value_name = "IMAGE_ID")]
    pub windows_image_id: Option<String>,
    /// Alibaba Cloud ECS: default Linux Cloud Image ID (`m-xxx`) for Linux
    /// sandboxes.
    #[arg(long, value_name = "IMAGE_ID")]
    pub linux_image_id: Option<String>,
    /// Alibaba Cloud ECS: default instance type (e.g. `ecs.c7.2xlarge`).
    #[arg(long, value_name = "TYPE")]
    pub instance_type: Option<String>,
}

impl TargetArgs {
    fn target(&self) -> CloudTarget {
        self.target_with_stdin(|| std::io::read_to_string(std::io::stdin()).unwrap_or_default())
    }

    fn target_with_stdin(&self, read_stdin: impl FnOnce() -> String) -> CloudTarget {
        let (token, relay_token) = if self.token_stdin {
            (Some(read_stdin().trim().to_string()), None)
        } else if self.relay_token_stdin {
            (None, Some(read_stdin().trim().to_string()))
        } else {
            (None, None)
        };
        CloudTarget {
            token,
            provider: self.provider.trim().to_ascii_lowercase(),
            profile: self.profile.clone(),
            region: self.region.clone(),
            zone: self.zone.clone(),
            project: self.project.clone(),
            environment: self.environment.clone(),
            relay_url: self.relay_url.clone(),
            relay_mode: self.relay_mode.clone(),
            relay_token,
            spacesd_download_url: self.spacesd_download_url.clone(),
            vpc_id: self.vpc_id.clone(),
            vswitch_id: self.vswitch_id.clone(),
            no_public_ip: self.no_public_ip,
            windows_image_id: self.windows_image_id.clone(),
            linux_image_id: self.linux_image_id.clone(),
            instance_type: self.instance_type.clone(),
        }
    }
}

/// `cua cloud`.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CloudCmd {
    /// Your clouds: found credentials, the connected account and region,
    /// what each runs at what hourly cost, and what Cua created there.
    #[command(
        visible_alias = "ls",
        after_help = "Examples:
  cua cloud status
  cua cloud status aws --json"
    )]
    Status {
        /// Only this cloud (`aws`, `azure`, `gcp`, `hetzner`, `modal`, `aliyun-ecs`).
        provider: Option<String>,
    },
    /// Connect a cloud account Spaces can be created in. Never prompts and
    /// is safe to run again: every run ends with a status, the next step and
    /// the command that verifies it. With --oidc, AWS and Google Cloud are
    /// linked without any key: Cua signs short-lived tokens that your
    /// account trusts. Azure is always linked that way. Without it, the
    /// cloud's own CLI sign-in on this device is used (Cua stores only the
    /// profile, region, project or environment names; Hetzner's API token
    /// goes to the Cua credential store).
    #[command(after_help = CONNECT_HELP)]
    Connect {
        #[command(flatten)]
        target: TargetArgs,
        /// Also make it the default location (`default.on`).
        #[arg(long = "default")]
        make_default: bool,
        /// Delete each Space there after this many hours (default 8; 0:
        /// never; Modal caps a sandbox at 24; a Hetzner server shuts itself
        /// down then and `cua cloud sweep --delete` removes it).
        #[arg(long)]
        ttl_hours: Option<u32>,
        /// Link without a stored key: Cua's issuer signs 15-minute tokens
        /// your account trusts (AWS, Google Cloud; Azure always).
        #[arg(long, conflicts_with_all = ["sealed", "no_sealed"])]
        oidc: bool,
        /// Hetzner, Modal: seal the API token to your devices (the token
        /// given on stdin, else the one this device has). The default when
        /// this device has the account's pool keys and a budget is given.
        #[arg(long, conflicts_with = "no_sealed")]
        sealed: bool,
        /// Hetzner: keep the API token on this device only (in the Cua
        /// credential store), as before sealing.
        #[arg(long)]
        no_sealed: bool,
        /// The most Cua may spend there per calendar month, in US dollars.
        /// New machines are refused once it is reached; stopping and
        /// deleting always works. Needed with --oidc.
        #[arg(long, value_name = "USD")]
        budget: Option<f64>,
        /// The largest machine Cua may create there: vCPUs x GB, for
        /// example 4x16.
        #[arg(long, value_name = "VCPUxGB")]
        max_size: Option<String>,
        /// With --oidc: the 12-digit AWS account id the trust stack is in.
        #[arg(long, value_name = "ID")]
        account_id: Option<String>,
        /// With --oidc: the role ARN, only if it is not named cua-spaces.
        #[arg(long, value_name = "ARN")]
        role_arn: Option<String>,
        /// Google Cloud with --oidc: the project number (the trust script
        /// prints it).
        #[arg(long, value_name = "NUMBER")]
        project_number: Option<String>,
        /// Google Cloud with --oidc: a service account to act as (default:
        /// none, the federated identity calls Google directly).
        #[arg(long, value_name = "EMAIL")]
        service_account: Option<String>,
        /// Azure: the subscription id (the template's subscriptionId).
        #[arg(long = "subscription", value_name = "ID")]
        subscription_id: Option<String>,
        /// Azure: the Microsoft Entra tenant id (the template's tenantId).
        #[arg(long = "tenant", value_name = "ID")]
        tenant_id: Option<String>,
        /// Azure: the cua-spaces managed identity's client id (the
        /// template's clientId).
        #[arg(long, value_name = "ID")]
        client_id: Option<String>,
        /// Azure: the resource group Cua works in, the only one its roles
        /// reach (default cua-spaces).
        #[arg(long, value_name = "NAME")]
        resource_group: Option<String>,
        /// With --oidc (and Azure): prove the link works (a check token,
        /// the exchange with the cloud, a dry run, permission check or
        /// validate; nothing is created) and save it.
        #[arg(long)]
        check: bool,
    },
    /// Approve what an agent asked for on a cloud: its link, or a higher
    /// budget or larger machines. For a person only (refused in an agent's
    /// shell). With --deny, decline it: the limits in force stay, and a
    /// link never approved is disconnected.
    #[command(after_help = "Examples:
  cua cloud status aws
  cua cloud approve aws
  cua cloud approve aws --deny")]
    Approve {
        /// `aws`, `gcp`, `hetzner` or `modal`.
        provider: String,
        /// Decline instead of approving.
        #[arg(long)]
        deny: bool,
    },
    /// Print the file that makes a cloud trust Cua's tokens (no keys):
    /// the AWS CloudFormation stack, the Google Cloud trust script, or the
    /// Azure resource group template. `cua cloud connect` says when and
    /// how to run it.
    #[command(after_help = "Examples:
  cua cloud trust gcp > cua-trust.sh
  cua cloud trust azure > cua-spaces.json
  cua cloud trust aws > cua-spaces.yaml")]
    Trust {
        /// `aws`, `gcp` or `azure`.
        cloud: String,
    },
    /// Check a cloud account without creating anything: credentials,
    /// permissions (by dry run), quota, the region and machine types.
    #[command(after_help = "Examples:
  cua cloud test aws
  cua cloud test gcp --project my-project")]
    Test {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Forget a connected cloud. Refused while Spaces Cua created there
    /// still run (they would keep billing unseen); add --delete to delete
    /// everything Cua created there first, then disconnect.
    #[command(after_help = "Examples:
  cua cloud disconnect aws
  # delete everything Cua created in the account, then disconnect
  cua cloud disconnect aws --delete")]
    Disconnect {
        /// `aws`, `azure`, `gcp`, `hetzner`, `modal` or `aliyun-ecs`.
        provider: String,
        /// Delete everything Cua created there first; disconnect only
        /// once the cloud confirms nothing is left.
        #[arg(long)]
        delete: bool,
    },
    /// What Cua did in your clouds: connects, disconnects, and every
    /// resource recorded, created, confirmed and deleted (by you, a sweep,
    /// the automatic sweep or disconnect --delete). Newest last. Never
    /// shows a secret.
    #[command(after_help = "Examples:
  cua cloud audit
  cua cloud audit --limit 200
  cua cloud audit --json")]
    Audit {
        /// How many of the newest entries (default 50).
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Only this cloud (`aws`, `gcp`, `hetzner`, `modal`).
        #[arg(long)]
        cloud: Option<String>,
    },
    /// What the machines Cua created in your clouds cost: each one's list
    /// price times how long it ran, by Space, agent, UTC day or cloud. An
    /// estimate; the cloud's own bill is the final word.
    #[command(after_help = "Examples:
  cua cloud cost
  cua cloud cost --by agent --since 2026-10-01
  cua cloud cost --cloud aws --by day --format csv > aws-october.csv")]
    Cost {
        /// Only this cloud (`aws`, `gcp`, `hetzner`, `modal`).
        #[arg(long)]
        cloud: Option<String>,
        /// One row per `space`, `agent`, `day` or `cloud`.
        #[arg(long, default_value = "space", value_parser = ["space", "agent", "day", "cloud"])]
        by: String,
        /// The first day counted, YYYY-MM-DD (UTC). Default: the first of
        /// this month.
        #[arg(long, value_name = "YYYY-MM-DD")]
        since: Option<String>,
        /// `table`, `csv` (header: key,usd,hours,machines) or `json`.
        #[arg(long, default_value = "table", value_parser = ["table", "csv", "json"])]
        format: String,
    },
    /// Find what Cua left in your clouds: expired Spaces and resources
    /// whose Space is gone (with --all, every Cua resource). Lists them
    /// unless --delete. Only resources Cua tagged and recorded are ever
    /// touched.
    #[command(after_help = "Examples:
  cua cloud sweep
  cua cloud sweep aws --delete
  cua cloud sweep --all --delete")]
    Sweep {
        /// Only this cloud.
        provider: Option<String>,
        /// Delete what it finds (default: list only).
        #[arg(long)]
        delete: bool,
        /// Include Cua resources that have not expired (every Space there).
        #[arg(long)]
        all: bool,
    },
    /// Add hosts in your cloud to your pool: computers made for Cua work
    /// that join by themselves (`cua cloud add aws`).
    #[command(after_help = "Examples:
  cua cloud add aws --count 2 --type g6.xlarge --ttl-hours 6
  cua cloud add aws --list
  cua cloud add aws --down")]
    Add {
        #[command(subcommand)]
        cloud: AddCloud,
    },
    /// What the elastic pool would do for some Spaces: where each goes
    /// (your devices first, then hosts with room, then new cloud machines
    /// at the least cost) and what it costs. Pins are constraints of the
    /// same solve. With --apply, adds the machines (then create the Spaces
    /// with --on auto).
    #[command(after_help = "Examples:
  cua cloud plan --count 256 --image linux:24.04-slim --caller batch --duration-secs 1800
  cua cloud plan --count 20 --provider aws --instance-type c7g.xlarge --json
  cua cloud plan --count 64 --no-scale
  cua cloud plan --count 32 --apply")]
    Plan(PlanArgs),
    /// The hosts the elastic pool runs in your clouds: add them by hand
    /// (pinned: the scaler never removes them), list or remove them.
    #[command(subcommand)]
    Hosts(HostsCmd),
    /// The elastic pool's budget: a $/hour cap, a monthly cap, the
    /// autoscale switch. Without flags, shows them and what the clouds cost
    /// now.
    #[command(after_help = "Examples:
  cua cloud budget
  cua cloud budget --max-per-hour 2 --monthly 40
  cua cloud budget --autoscale off")]
    Budget {
        /// Most USD per hour your clouds may cost at once.
        #[arg(long = "max-per-hour")]
        max_usd_per_hour: Option<f64>,
        /// Most USD per calendar month on elastic hosts.
        #[arg(long = "monthly")]
        monthly_usd: Option<f64>,
        /// `on` or `off`: add and remove cloud hosts by itself. Off, you
        /// manage machines: `--on auto` uses only what runs, and `--on
        /// <cloud>` gives each Space a cloud machine of its own.
        #[arg(long)]
        autoscale: Option<String>,
        /// Most hosts one placement adds.
        #[arg(long)]
        max_new_hosts: Option<u32>,
        /// `on` or `off`: keep an idle host warm when demand predicts a
        /// Space soon.
        #[arg(long)]
        warm: Option<String>,
        /// `on` or `off`: let one small VM Space buy a KVM metal host
        /// (dollars an hour). Off, such a request is refused and says so.
        #[arg(long)]
        allow_metal: Option<String>,
    },
    /// Run the elastic pool's scale-in pass now (the daemon runs one every
    /// 30 s): idle hosts go at the end of their paid time.
    #[command(after_help = "Examples:
  cua cloud reconcile
  cua cloud reconcile --watch")]
    Reconcile {
        /// Keep running a pass every 30 s.
        #[arg(long)]
        watch: bool,
    },
}

/// `cua cloud plan`.
#[derive(Args, Debug, Clone, Default)]
pub struct PlanArgs {
    /// How many Spaces.
    #[arg(long, default_value_t = 1)]
    pub count: u32,
    /// Image (default linux).
    #[arg(long)]
    pub image: Option<String>,
    /// `container`, `vm` or `microvm`.
    #[arg(long)]
    pub kind: Option<String>,
    /// vCPUs each.
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Memory each, MiB.
    #[arg(long)]
    pub memory_mb: Option<u64>,
    /// Keep them on one machine (forks of one checkpoint).
    #[arg(long)]
    pub together: bool,
    /// `interactive`, `batch`, `compat` or `persistent_agent`.
    #[arg(long)]
    pub caller: Option<String>,
    /// Expected lifetime, seconds.
    #[arg(long)]
    pub duration_secs: Option<u64>,
    /// Only this cloud.
    #[arg(long)]
    pub provider: Option<String>,
    /// Only this region.
    #[arg(long)]
    pub region: Option<String>,
    /// Only this machine type.
    #[arg(long)]
    pub instance_type: Option<String>,
    /// Exactly this many new machines.
    #[arg(long)]
    pub hosts: Option<u32>,
    /// Add no machines.
    #[arg(long)]
    pub no_scale: bool,
    /// Only your own devices.
    #[arg(long)]
    pub devices_only: bool,
    /// A $/hour cap for this plan.
    #[arg(long = "max-per-hour")]
    pub max_usd_per_hour: Option<f64>,
    /// Add the machines the plan needs.
    #[arg(long)]
    pub apply: bool,
}

/// `cua cloud hosts`.
#[derive(Subcommand, Debug)]
pub enum HostsCmd {
    /// The hosts with their state and cost.
    #[command(
        visible_alias = "ls",
        after_help = "Examples:
  cua cloud hosts ls"
    )]
    List,
    /// Add hosts by hand (pinned: never removed by the scaler).
    #[command(after_help = "Examples:
  cua cloud hosts add --provider hetzner --type cax41 --region fsn1
  cua cloud hosts add --provider aws --type c7g.xlarge --count 2 --ttl-hours 4")]
    Add {
        /// `aws`, `gcp` or `hetzner`.
        #[arg(long)]
        provider: String,
        /// Machine type (`cua cloud plan --json` lists the offers).
        #[arg(long = "type")]
        instance_type: String,
        /// Region (default: the connection's).
        #[arg(long)]
        region: Option<String>,
        /// How many.
        #[arg(long, default_value_t = 1)]
        count: u32,
        /// Hours until each ends on its own (1 to 168, default 24).
        #[arg(long)]
        ttl_hours: Option<u32>,
    },
    /// Remove hosts this home added (their Spaces end).
    #[command(
        visible_alias = "rm",
        after_help = "Examples:
  cua cloud hosts rm hetzner-1
  cua cloud hosts rm aws-1 aws-2"
    )]
    Remove {
        /// Their names (`hetzner-1`).
        #[arg(required = true)]
        names: Vec<String>,
    },
}

fn on_off(v: Option<String>, flag: &str) -> Result<Option<bool>, CuaError> {
    match v.as_deref().map(str::trim) {
        None => Ok(None),
        Some("on" | "true" | "yes") => Ok(Some(true)),
        Some("off" | "false" | "no") => Ok(Some(false)),
        Some(o) => Err(CuaError::InvalidArgument(format!(
            "--{flag} {o}: on or off"
        ))),
    }
}

fn host_line(h: &cua_sdk::ElasticHost) -> String {
    format!(
        "{:<12} {:<8} {:<12} {:<10} {:<9} ${:.4}/h{}",
        h.name,
        h.provider,
        h.type_name,
        h.region,
        h.state,
        h.usd_per_hour,
        if h.pinned { "  pinned" } else { "" }
    )
}

/// `cua cloud add <cloud>`.
#[derive(Subcommand, Debug)]
pub enum AddCloud {
    /// EC2 hosts in your connected AWS account (`cua cloud connect aws`)
    /// that join your pool by themselves: Ubuntu 24.04 for CPU types, the
    /// AWS Deep Learning Base GPU image for g*/p* types. Each one is
    /// dedicated (made only for this work: jobs run in its own Space, with
    /// its GPU) and powers off (and is terminated) at its TTL.
    #[command(after_help = "Examples:
  cua cloud add aws --count 2 --type c7i.large
  cua cloud add aws --count 2 --type g6.xlarge --ttl-hours 6 --tag team=ml
  cua cloud add aws --list
  cua cloud add aws --down")]
    Aws(crate::onboard::AwsArgs),
}

fn json_line(out: &mut dyn Write, v: serde_json::Value) {
    line(out, v.to_string());
}

/// Runs `cmd` through `cua`'s Spaces (the daemon's when one runs).
pub async fn run(
    cua: &Arc<Cua>,
    cmd: CloudCmd,
    json: bool,
    out: &mut dyn Write,
) -> Result<i32, CuaError> {
    let spaces = cua.spaces();
    match cmd {
        CloudCmd::Status { provider } => {
            let s = spaces
                .cloud_status(provider.map(|p| p.to_ascii_lowercase()))
                .await?;
            if json {
                json_line(out, status_json(&s));
                return Ok(0);
            }
            for p in &s.providers {
                line(out, provider_line(p));
                if p.connected
                    && let Some(l) = limits_line(p)
                {
                    line(out, l);
                }
                for l in hint_lines(p) {
                    line(out, l);
                }
            }
            for p in s.providers.iter().filter(|p| p.connected) {
                let kinds: Vec<String> = p
                    .kinds
                    .iter()
                    .filter(|k| k.supported)
                    .map(|k| format!("{} {} ~${:.2}/h", k.image, k.machine_type, k.usd_per_hour))
                    .collect();
                if !kinds.is_empty() {
                    line(out, format!("  {}: {}", p.title, kinds.join(", ")));
                }
            }
            if !s.resources.is_empty() {
                line(out, "");
                line(out, "Created by Cua:");
                for r in &s.resources {
                    line(out, resource_line(r));
                }
            }
        }
        CloudCmd::Connect {
            target,
            make_default,
            ttl_hours,
            oidc,
            sealed,
            no_sealed,
            budget,
            max_size,
            account_id,
            role_arn,
            project_number,
            service_account,
            subscription_id,
            tenant_id,
            client_id,
            resource_group,
            check,
        } => {
            let t = target.target();
            let options = cua_sdk::CloudConnectOptions {
                auth: if oidc {
                    Some("oidc".to_string())
                } else if sealed {
                    Some("sealed".to_string())
                } else if no_sealed {
                    Some("cli".to_string())
                } else {
                    None
                },
                budget_usd_month: budget,
                max_size,
                account_id,
                role_arn,
                project_number,
                service_account,
                subscription_id,
                tenant_id,
                client_id,
                resource_group,
                check,
                agent: cua_sandbox_core::byoc::caller_agent(),
            };
            let provider = t.provider.clone();
            let result = spaces
                .cloud_connect(t, make_default, ttl_hours, Some(options))
                .await;
            link_event(
                "connect",
                &provider,
                result
                    .as_ref()
                    .map(|c| (c.provider.auth.as_str(), c.provider.status.as_str())),
            );
            let c = match result {
                Ok(c) => c,
                // Every run ends with a status, also when it errs.
                Err(e) => cua_sdk::CloudConnected {
                    provider: cua_sdk::CloudProvider {
                        name: provider.clone(),
                        status: "failed".into(),
                        ..Default::default()
                    },
                    next: Some(cua_sdk::CloudNext {
                        why: plain_error(&e.to_string()),
                        ..Default::default()
                    }),
                    verify: format!("cua cloud status {provider}"),
                    ..Default::default()
                },
            };
            let code = connect_exit_code(&c);
            if json {
                json_line(out, connect_json(&c));
            } else {
                for l in connect_lines(&c) {
                    line(out, l);
                }
            }
            return Ok(code);
        }
        CloudCmd::Test { target } => {
            let r = spaces.cloud_test(target.target()).await?;
            if json {
                json_line(
                    out,
                    serde_json::json!({
                        "provider": r.provider,
                        "ok": r.ok,
                        "account": r.account,
                        "checks": checks_json(&r.checks),
                    }),
                );
            } else {
                for c in &r.checks {
                    line(out, check_line(c));
                }
                line(
                    out,
                    if r.ok {
                        "Ready. Nothing was created.".to_string()
                    } else {
                        "Not ready: fix what failed above. Nothing was created.".to_string()
                    },
                );
            }
            return Ok(if r.ok { 0 } else { 1 });
        }
        CloudCmd::Approve { provider, deny } => {
            // A person's decision: never an agent's, whatever the daemon
            // runs as.
            if let Some(agent) = cua_sandbox_core::byoc::caller_agent() {
                return Err(cua_sdk::CuaError::InvalidArgument(format!(
                    "only a person can {} what an agent asked for, and this shell is {agent}'s: \
                     ask the person to run `cua cloud approve {}` or to open Cua Spaces",
                    if deny { "deny" } else { "approve" },
                    provider.to_ascii_lowercase()
                )));
            }
            let result = spaces
                .cloud_approve(provider.to_ascii_lowercase(), deny)
                .await;
            link_event(
                if deny { "deny" } else { "approve" },
                &provider.to_ascii_lowercase(),
                result
                    .as_ref()
                    .map(|p| (p.auth.as_str(), p.status.as_str())),
            );
            let p = result?;
            if json {
                json_line(out, provider_json(&p));
                return Ok(0);
            }
            line(
                out,
                format!(
                    "{} {}.",
                    if deny { "Denied for" } else { "Approved for" },
                    p.title
                ),
            );
            line(out, provider_line(&p));
            if p.connected
                && let Some(l) = limits_line(&p)
            {
                line(out, l);
            }
        }
        CloudCmd::Disconnect { provider, delete } => {
            let result = spaces
                .cloud_disconnect(provider.to_ascii_lowercase(), delete)
                .await;
            link_event(
                "disconnect",
                &provider.to_ascii_lowercase(),
                result.as_ref().map(|d| {
                    (
                        "none",
                        if d.disconnected {
                            "not_connected"
                        } else {
                            "connected"
                        },
                    )
                }),
            );
            let d = result?;
            if json {
                json_line(
                    out,
                    serde_json::json!({
                        "provider": d.provider,
                        "disconnected": d.disconnected,
                        "deleted": d.deleted.iter().map(resource_json).collect::<Vec<_>>(),
                        "left": d.left.iter().map(resource_json).collect::<Vec<_>>(),
                    }),
                );
                return Ok(0);
            }
            if !d.deleted.is_empty() {
                line(out, "Deleted from that account:");
                for r in &d.deleted {
                    line(out, resource_line(r));
                }
            }
            line(
                out,
                if d.disconnected {
                    format!("Disconnected {}.", d.provider)
                } else {
                    format!("{} was not connected.", d.provider)
                },
            );
            if !d.left.is_empty() {
                hint_line(
                    out,
                    "Still recorded for that account (`cua cloud sweep --all --delete` after reconnecting removes them):",
                );
                for r in &d.left {
                    line(out, resource_line(r));
                }
            }
        }
        CloudCmd::Cost {
            cloud,
            by,
            since,
            format,
        } => {
            let r = spaces
                .cloud_cost(by, since, cloud.map(|c| c.to_ascii_lowercase()))
                .await?;
            match (json, format.as_str()) {
                (true, _) | (_, "json") => json_line(out, cost_json(&r)),
                (_, "csv") => {
                    let _ = out.write_all(cost_csv(&r.rows).as_bytes());
                }
                _ => {
                    for l in cost_table(&r) {
                        line(out, l);
                    }
                }
            }
        }
        CloudCmd::Audit { limit, cloud } => {
            let mut entries = spaces.cloud_audit(Some(limit)).await?;
            if let Some(c) = cloud {
                entries.retain(|e| e.provider.eq_ignore_ascii_case(&c));
            }
            if json {
                json_line(
                    out,
                    serde_json::Value::Array(entries.iter().map(audit_json).collect()),
                );
                return Ok(0);
            }
            if entries.is_empty() {
                line(out, "Nothing recorded yet.");
            }
            for e in &entries {
                line(out, audit_line(e));
            }
        }
        CloudCmd::Sweep {
            provider,
            delete,
            all,
        } => {
            let r = spaces
                .cloud_sweep(provider.map(|p| p.to_ascii_lowercase()), !delete, all)
                .await?;
            if json {
                json_line(
                    out,
                    serde_json::json!({
                        "dry_run": r.dry_run,
                        "resources": r.resources.iter().map(|i| {
                            let mut v = resource_json(&i.resource);
                            v["action"] = i.action.clone().into();
                            v["reason"] = i.reason.clone().into();
                            v
                        }).collect::<Vec<_>>(),
                    }),
                );
                return Ok(0);
            }
            if r.resources.is_empty() {
                line(out, "Nothing to clean up.");
            }
            for i in &r.resources {
                line(
                    out,
                    format!(
                        "{:<8} {}  ({})",
                        i.action,
                        resource_line(&i.resource).trim_start(),
                        i.reason
                    ),
                );
            }
            if r.dry_run && r.resources.iter().any(|i| i.action == "delete") {
                line(out, "Dry run: add --delete to delete these.");
            }
            if r.resources.iter().any(|i| i.action == "failed") {
                return Ok(1);
            }
        }
        CloudCmd::Plan(a) => {
            let p = spaces
                .cloud_plan(cua_sdk::ElasticPlanRequest {
                    count: Some(a.count),
                    image: a.image,
                    kind: a.kind,
                    cpus: a.cpus,
                    memory_mb: a.memory_mb,
                    together: Some(a.together),
                    caller: a.caller,
                    duration_secs: a.duration_secs,
                    provider: a.provider,
                    region: a.region,
                    instance_type: a.instance_type,
                    hosts: a.hosts,
                    no_scale: Some(a.no_scale),
                    devices_only: Some(a.devices_only),
                    max_usd_per_hour: a.max_usd_per_hour,
                    apply: a.apply,
                })
                .await?;
            if json {
                line(out, p.json);
                return Ok(0);
            }
            for e in &p.explain {
                line(out, e);
            }
            line(
                out,
                format!(
                    "{} new machine{} (+${:.4}/h), ${:.4} for the work (lower bound ${:.4}); ready in ~{} s; {} solver",
                    p.new_hosts.len(),
                    if p.new_hosts.len() == 1 { "" } else { "s" },
                    p.added_usd_per_hour,
                    p.projected_usd,
                    p.lower_bound_usd,
                    p.ready_in_secs,
                    p.solver
                ),
            );
            for h in &p.added {
                line(out, format!("added {}", host_line(h)));
            }
            if !p.unplaced.is_empty() {
                return Ok(1);
            }
        }
        CloudCmd::Hosts(HostsCmd::List) => {
            let hosts = spaces.cloud_hosts().await?;
            if json {
                json_line(
                    out,
                    hosts
                        .iter()
                        .map(|h| {
                            serde_json::json!({"name": h.name, "provider": h.provider, "type": h.type_name,
                                "region": h.region, "id": h.id, "machine": h.machine, "state": h.state,
                                "started": h.started, "expires": h.expires, "usd_per_hour": h.usd_per_hour,
                                "pinned": h.pinned})
                        })
                        .collect(),
                );
                return Ok(0);
            }
            if hosts.is_empty() {
                hint_line(
                    out,
                    "No elastic hosts (they are added when your machines are full, or with cua cloud hosts add).",
                );
            }
            let total: f64 = hosts
                .iter()
                .filter(|h| h.state != "gone")
                .map(|h| h.usd_per_hour)
                .sum();
            for h in &hosts {
                line(out, host_line(h));
            }
            if !hosts.is_empty() {
                line(out, format!("{} hosts, ${total:.4}/h", hosts.len()));
            }
        }
        CloudCmd::Hosts(HostsCmd::Add {
            provider,
            instance_type,
            region,
            count,
            ttl_hours,
        }) => {
            let hosts = spaces
                .cloud_add_host(provider, instance_type, region, Some(count), ttl_hours)
                .await?;
            for h in &hosts {
                if json {
                    json_line(
                        out,
                        serde_json::json!({"name": h.name, "provider": h.provider, "type": h.type_name, "region": h.region, "state": h.state}),
                    );
                } else {
                    line(out, format!("added {}", host_line(h)));
                }
            }
        }
        CloudCmd::Hosts(HostsCmd::Remove { names }) => {
            let r = spaces.cloud_remove_host(names).await?;
            if json {
                json_line(
                    out,
                    serde_json::json!({"removed": r.removed, "failed": r.failed}),
                );
            } else {
                for n in &r.removed {
                    line(out, format!("removed {n}"));
                }
                for f in &r.failed {
                    line(out, format!("NOT removed {f}"));
                }
            }
            if !r.failed.is_empty() {
                return Ok(1);
            }
        }
        CloudCmd::Budget {
            max_usd_per_hour,
            monthly_usd,
            autoscale,
            max_new_hosts,
            warm,
            allow_metal,
        } => {
            let b = spaces
                .cloud_budget(cua_sdk::ElasticBudgetUpdate {
                    max_usd_per_hour,
                    monthly_usd,
                    autoscale: on_off(autoscale, "autoscale")?,
                    max_new_hosts,
                    warm: on_off(warm, "warm")?,
                    allow_metal: on_off(allow_metal, "allow-metal")?,
                })
                .await?;
            if json {
                json_line(
                    out,
                    serde_json::json!({"autoscale": b.autoscale, "max_usd_per_hour": b.max_usd_per_hour,
                        "monthly_usd": b.monthly_usd, "max_new_hosts": b.max_new_hosts, "warm": b.warm,
                        "allow_metal": b.allow_metal, "month_usd": b.month_usd, "running_usd_per_hour": b.running_usd_per_hour, "hosts": b.hosts}),
                );
            } else {
                line(
                    out,
                    format!(
                        "autoscale {} · cap ${:.2}/h · ${:.2}/month (spent ${:.2}) · {} hosts at ${:.4}/h now",
                        if b.autoscale { "on" } else { "off" },
                        b.max_usd_per_hour,
                        b.monthly_usd,
                        b.month_usd,
                        b.hosts,
                        b.running_usd_per_hour
                    ),
                );
            }
        }
        CloudCmd::Reconcile { watch } => loop {
            let d = spaces.cloud_reconcile().await?;
            for x in &d {
                if json {
                    json_line(
                        out,
                        serde_json::json!({"host": x.host, "action": x.action, "reason": x.reason, "until": x.until, "saves_usd": x.saves_usd}),
                    );
                } else {
                    line(out, format!("{:<12} {:<7} {}", x.host, x.action, x.reason));
                }
            }
            if !watch {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        },
        // Run without a Space client (in the CLI).
        CloudCmd::Trust { .. } => {
            return Err(CuaError::Internal(
                "cua cloud trust runs in the CLI, not through Spaces".into(),
            ));
        }
        CloudCmd::Add { .. } => {
            return Err(CuaError::Internal(
                "cua cloud add runs in the CLI, not through Spaces".into(),
            ));
        }
    }
    Ok(0)
}

fn provider_line(p: &cua_sdk::CloudProvider) -> String {
    let state = if p.connected {
        // The label leads with the title ("AWS · us-west-2"): print the place.
        let place = p
            .label
            .strip_prefix(&p.title)
            .map(|r| r.trim_start_matches([' ', '\u{b7}']))
            .filter(|r| !r.is_empty())
            .unwrap_or(&p.label);
        let mut s = if p.status == "waiting-for-approval" {
            format!("waiting for approval · {place}")
        } else {
            format!("connected · {place}")
        };
        if !p.account.is_empty() {
            s.push_str(&format!(" · {}", p.account));
        }
        if p.default {
            s.push_str(" · default");
        }
        s
    } else if p.credentials.found {
        format!(
            "not connected · credentials found ({})",
            p.credentials.source
        )
    } else {
        "not connected · no credentials found".to_string()
    };
    format!("{:<13} {state}", p.title)
}

/// `cua_cloud_link` for one action: the cloud's word, how it is linked
/// and where it stands (or that it failed). Only vocabulary words leave
/// this device: never an account, a region or a token.
fn link_event<E>(action: &str, cloud: &str, result: Result<(&str, &str), &E>) {
    use cua_telemetry::Outcome;
    let (auth, status, outcome) = match result {
        Ok((auth, status)) => (
            if auth.is_empty() { "none" } else { auth },
            status,
            if status == "failed" {
                Outcome::Error
            } else {
                Outcome::Ok
            },
        ),
        Err(_) => ("none", "error", Outcome::Error),
    };
    if let Some(e) = cua_telemetry::events::cloud_link(action, cloud, auth, status, outcome) {
        cua_telemetry::capture(e);
    }
}

/// What to do about a cloud, one short line each: what is wrong with its
/// link, what waits for the person's approval, and a better way to link it.
fn hint_lines(p: &cua_sdk::CloudProvider) -> Vec<String> {
    let mut out = Vec::new();
    if !p.issue.is_empty() {
        out.push(format!("  {}", p.issue));
    }
    if !p.approval.is_empty() && p.can_approve {
        let who = if p.approval_agent.is_empty() {
            "An agent".to_string()
        } else {
            format!("Agent {}", p.approval_agent)
        };
        let what = if p.approval == "limits" {
            let mut asked = Vec::new();
            if let Some(b) = p.pending_budget_usd_month {
                asked.push(format!("a budget of {} a month", usd(b)));
            }
            if !p.pending_max_size.is_empty() {
                asked.push(format!(
                    "machines up to {}",
                    size_words(&p.pending_max_size)
                ));
            }
            if asked.is_empty() {
                "higher limits".to_string()
            } else {
                asked.join(" and ")
            }
        } else {
            format!("to use {}", p.title)
        };
        out.push(format!("  {who} asks for {what}."));
        out.push(format!(
            "  Approve: cua cloud approve {}   Deny: cua cloud approve {} --deny",
            p.name, p.name
        ));
    }
    if p.suggest_auth == "oidc" {
        out.push(format!(
            "  Switch to OIDC (no stored key): cua cloud connect {} --oidc",
            p.name
        ));
    }
    out
}

fn resource_line(r: &cua_sdk::CloudResource) -> String {
    let mut s = format!("  {:<6} {:<15} {}", r.provider, r.resource_type, r.id);
    if !r.state.is_empty() {
        s.push_str(&format!(" {}", r.state));
    }
    if !r.sandbox.is_empty() {
        s.push_str(&format!(" · {}", r.sandbox));
    }
    if r.expired {
        s.push_str(" · expired");
    } else if !r.expires.is_empty() {
        s.push_str(&format!(" · expires {}", r.expires));
    }
    s
}

fn audit_json(e: &cua_sdk::CloudAuditEntry) -> serde_json::Value {
    serde_json::json!({
        "ts": e.ts, "action": e.action, "provider": e.provider, "kind": e.kind,
        "id": e.id, "space": e.space, "actor": e.actor, "outcome": e.outcome,
        "detail": e.detail, "source": if e.source.is_empty() { "device" } else { e.source.as_str() },
    })
}

/// The CSV header of `cua cloud cost --format csv`; scripts read it, so it
/// only ever gains columns at the end.
pub(crate) const COST_CSV_HEADER: &str = "key,usd,hours,machines";

fn cost_csv(rows: &[cua_sdk::CloudCostRow]) -> String {
    let mut s = format!("{COST_CSV_HEADER}\n");
    for r in rows {
        let key = if r.key.contains([',', '"', '\n']) {
            format!("\"{}\"", r.key.replace('"', "\"\""))
        } else {
            r.key.clone()
        };
        s.push_str(&format!(
            "{key},{:.2},{:.2},{}\n",
            r.usd, r.hours, r.machines
        ));
    }
    s
}

fn cost_json(r: &cua_sdk::CloudCostReport) -> serde_json::Value {
    serde_json::json!({
        "by": r.by, "since": r.since, "until": r.until, "total_usd": r.total_usd,
        "rows": r.rows.iter().map(|x| serde_json::json!({
            "key": x.key, "usd": x.usd, "hours": x.hours, "machines": x.machines,
        })).collect::<Vec<_>>(),
    })
}

/// Plain columns, the total last.
fn cost_table(r: &cua_sdk::CloudCostReport) -> Vec<String> {
    if r.rows.is_empty() {
        return vec![format!("Nothing ran since {}.", r.since)];
    }
    let head = match r.by.as_str() {
        "agent" => "Agent",
        "day" => "Day",
        "cloud" => "Cloud",
        _ => "Space",
    };
    let w = r
        .rows
        .iter()
        .map(|x| x.key.chars().count())
        .max()
        .unwrap_or(0)
        .max(head.len());
    let mut out = vec![format!(
        "{head:<w$}  {:>10}  {:>8}  {:>8}",
        "Cost", "Hours", "Machines"
    )];
    for x in &r.rows {
        out.push(format!(
            "{:<w$}  {:>10}  {:>8.2}  {:>8}",
            x.key,
            usd(x.usd),
            x.hours,
            x.machines
        ));
    }
    out.push(format!(
        "Total {} since {} (estimated from list prices).",
        usd(r.total_usd),
        r.since
    ));
    out
}

fn audit_line(e: &cua_sdk::CloudAuditEntry) -> String {
    let mut s = format!("{} {:<6} {:<18}", e.ts, e.provider, e.action);
    for part in [&e.kind, &e.id] {
        if !part.is_empty() {
            s.push_str(&format!(" {part}"));
        }
    }
    if !e.space.is_empty() {
        s.push_str(&format!(" · {}", e.space));
    }
    s.push_str(&format!(" · {} · {}", e.actor, e.outcome));
    if !e.detail.is_empty() {
        s.push_str(&format!(" · {}", e.detail));
    }
    if e.source == "account" {
        s.push_str(" (account)");
    }
    s
}

/// "  Budget $200 a month, $3.10 spent. Machines up to 4 vCPU and 16 GB.
/// 2 running. Signs in through Cua." for a connected cloud with limits.
fn limits_line(p: &cua_sdk::CloudProvider) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(b) = p.budget_usd_month {
        parts.push(format!(
            "Budget {} a month, {} spent.",
            usd(b),
            usd((p.spent_month * 100.0).round() / 100.0)
        ));
    }
    if !p.max_size.is_empty() {
        parts.push(format!("Machines up to {}.", size_words(&p.max_size)));
    }
    if p.running > 0 {
        parts.push(format!("{} running.", p.running));
    }
    if p.auth == "oidc" {
        parts.push("Signs in through Cua.".into());
    }
    if p.auth == "sealed" {
        parts.push(if p.holders.is_empty() {
            "Token sealed to your devices.".to_string()
        } else {
            format!("Token sealed; can open it: {}.", p.holders.join(", "))
        });
    }
    if p.relay_mode.as_deref() == Some("static") {
        let url = p.relay_url.as_deref().unwrap_or_default();
        parts.push(format!("Static Relay Mode ({url})."));
    } else if let Some(url) = p
        .relay_url
        .as_deref()
        .filter(|u| !u.is_empty() && *u != "https://relay.cua.ai")
    {
        parts.push(format!("Relay: {url}."));
    }
    if let Some(url) = p.spacesd_download_url.as_deref().filter(|u| !u.is_empty()) {
        parts.push(format!("cua-spacesd mirror: {url}."));
    }
    if let (Some(vpc), Some(vsw)) = (p.vpc_id.as_deref(), p.vswitch_id.as_deref()) {
        parts.push(format!("Existing VPC {vpc} / {vsw}."));
    }
    if p.no_public_ip {
        parts.push("Private-only (--no-public-ip).".into());
    }
    if let Some(id) = p.windows_image_id.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("Windows Cloud Image ID: {id}."));
    }
    if let Some(id) = p.linux_image_id.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("Linux Cloud Image ID: {id}."));
    }
    if let Some(t) = p.instance_type.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("Default instance type: {t}."));
    }
    match p.approval.as_str() {
        "connection" => parts.push("A person approves it in Cua Spaces.".into()),
        "limits" => parts.push("A person approves the new limits in Cua Spaces.".into()),
        _ => {}
    }
    (!parts.is_empty()).then(|| format!("  {}", parts.join(" ")))
}

fn check_line(c: &cua_sdk::CloudCheck) -> String {
    format!(
        "{} {:<12} {}",
        if c.ok { "ok  " } else { "FAIL" },
        c.name,
        c.detail
    )
}

/// An error's text without a repeated kind prefix ("invalid argument:
/// invalid argument: x" is "invalid argument: x").
fn plain_error(s: &str) -> String {
    let mut out = s.trim().to_string();
    while let Some((head, rest)) = out.split_once(": ") {
        if rest.starts_with(&format!("{head}: ")) {
            out = rest.to_string();
        } else {
            break;
        }
    }
    out
}

/// The exit code of a connect: 0 connected, 11 waits on a person, 10 the
/// next step is the caller's, 1 error.
fn connect_exit_code(c: &cua_sdk::CloudConnected) -> i32 {
    match c.provider.status.as_str() {
        "connected" => 0,
        "needs-trust" | "waiting-for-approval" => 11,
        _ => match &c.next {
            Some(n) if n.open.is_some() => 11,
            Some(n) if n.run.is_some() => 10,
            _ => 1,
        },
    }
}

fn next_json(n: &cua_sdk::CloudNext) -> serde_json::Value {
    let mut v = serde_json::json!({ "why": n.why });
    if let Some(r) = &n.run {
        v["run"] = r.clone().into();
    }
    if let Some(o) = &n.open {
        v["open"] = o.clone().into();
    }
    if let Some(p) = &n.paste {
        v["paste"] = p.clone().into();
    }
    v
}

/// `--json`: `{status, next: {run?, open?, paste?, why}, verify, checks,
/// provider}`.
fn connect_json(c: &cua_sdk::CloudConnected) -> serde_json::Value {
    serde_json::json!({
        "status": c.provider.status,
        "next": c.next.as_ref().map(next_json),
        "verify": c.verify,
        "checks": checks_json(&c.checks),
        "provider": provider_json(&c.provider),
    })
}

/// "$200" or "$12.50".
fn usd(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("${v:.0}")
    } else {
        format!("${v:.2}")
    }
}

/// "4 vCPU and 16 GB" of "4x16" (or "4 vCPU, 16 GB, and 100 GB disk" of "4x16x100").
fn size_words(s: &str) -> String {
    let parts: Vec<&str> = s.split('x').collect();
    match parts.as_slice() {
        [c, m] => format!("{c} vCPU and {m} GB"),
        [c, m, d] => format!("{c} vCPU, {m} GB, and {d} GB disk"),
        _ => s.to_string(),
    }
}

/// A connect's result as short plain lines.
fn connect_lines(c: &cua_sdk::CloudConnected) -> Vec<String> {
    let p = &c.provider;
    let title = if p.title.is_empty() {
        p.name.as_str()
    } else {
        p.title.as_str()
    };
    let state = match p.status.as_str() {
        "connected" => "connected",
        "needs-trust" => "needs trust",
        "checking" => "recorded, not checked yet",
        "waiting-for-approval" => "waiting for approval",
        "failed" => "not connected",
        other => other,
    };
    let mut out = vec![format!("{title}: {state}")];
    if p.status != "failed" || p.connected {
        if !p.region.is_empty() {
            out.push(format!("Region: {}", p.region));
        }
        if let Some(b) = p.budget_usd_month {
            out.push(format!("Budget: {} a month", usd(b)));
        }
        if !p.max_size.is_empty() {
            out.push(format!("Machines up to {}", size_words(&p.max_size)));
        }
        if p.auth == "oidc" {
            out.push("Signs in through Cua (no stored key)".into());
        }
        if p.relay_mode.as_deref() == Some("static") {
            let url = p.relay_url.as_deref().unwrap_or_default();
            out.push(format!("Relay: {url} (static)"));
        } else if let Some(url) = p
            .relay_url
            .as_deref()
            .filter(|u| !u.is_empty() && *u != "https://relay.cua.ai")
        {
            out.push(format!("Relay: {url} (account)"));
        }
        if let Some(url) = p.spacesd_download_url.as_deref().filter(|u| !u.is_empty()) {
            out.push(format!("cua-spacesd mirror: {url}"));
        }
        if let (Some(vpc), Some(vsw)) = (p.vpc_id.as_deref(), p.vswitch_id.as_deref()) {
            out.push(format!("VPC: {vpc} (VSwitch {vsw})"));
        }
        if p.no_public_ip {
            out.push("Public IP: disabled (--no-public-ip)".into());
        }
        if let Some(id) = p.windows_image_id.as_deref().filter(|s| !s.is_empty()) {
            out.push(format!("Windows Cloud Image ID: {id}"));
        }
        if let Some(id) = p.linux_image_id.as_deref().filter(|s| !s.is_empty()) {
            out.push(format!("Linux Cloud Image ID: {id}"));
        }
        if let Some(t) = p.instance_type.as_deref().filter(|s| !s.is_empty()) {
            out.push(format!("Default instance type: {t}"));
        }
    }
    for ch in &c.checks {
        out.push(check_line(ch));
    }
    if let Some(n) = &c.next {
        if let Some(o) = &n.open {
            out.push(format!("Next, for a person: open {o}"));
        }
        if let Some(paste) = &n.paste {
            out.push(format!("Paste there: {paste}"));
        }
        if let Some(r) = &n.run {
            out.push(format!("Next: {r}"));
        }
        out.push(format!("Why: {}", n.why));
    }
    if p.status == "connected" {
        out.push(format!(
            "Create a Space there: cua spaces create --on {}",
            p.name
        ));
    }
    if !c.verify.is_empty() {
        out.push(format!("Verify: {}", c.verify));
    }
    out
}

fn checks_json(checks: &[cua_sdk::CloudCheck]) -> serde_json::Value {
    checks
        .iter()
        .map(|c| serde_json::json!({"name": c.name, "ok": c.ok, "detail": c.detail}))
        .collect()
}

fn provider_json(p: &cua_sdk::CloudProvider) -> serde_json::Value {
    serde_json::json!({
        "name": p.name,
        "title": p.title,
        "tier": p.tier,
        "connected": p.connected,
        "default": p.default,
        "credentials": {"found": p.credentials.found, "source": p.credentials.source},
        "account": p.account,
        "profile": p.profile,
        "region": p.region,
        "zone": p.zone,
        "project": p.project,
        "environment": p.environment,
        "label": p.label,
        "ttl_hours": p.ttl_hours,
        "auth": p.auth,
        "status": p.status,
        "budget_usd_month": p.budget_usd_month,
        "max_size": p.max_size,
        "spent_month": p.spent_month,
        "running": p.running,
        "approval": p.approval,
        "approval_agent": p.approval_agent,
        "pending_budget_usd_month": p.pending_budget_usd_month,
        "pending_max_size": p.pending_max_size,
        "can_approve": p.can_approve,
        "suggest_auth": p.suggest_auth,
        "issue": p.issue,
        "holders": p.holders,
        "relay_url": p.relay_url,
        "relay_mode": p.relay_mode,
        "spacesd_download_url": p.spacesd_download_url,
        "vpc_id": p.vpc_id,
        "vswitch_id": p.vswitch_id,
        "no_public_ip": p.no_public_ip,
        "windows_image_id": p.windows_image_id,
        "linux_image_id": p.linux_image_id,
        "instance_type": p.instance_type,
        "kinds": p.kinds.iter().map(|k| serde_json::json!({
            "image": k.image, "kind": k.kind, "supported": k.supported, "reason": k.reason,
            "machine_type": k.machine_type, "usd_per_hour": k.usd_per_hour,
        })).collect::<Vec<_>>(),
    })
}

fn resource_json(r: &cua_sdk::CloudResource) -> serde_json::Value {
    serde_json::json!({
        "provider": r.provider,
        "id": r.id,
        "type": r.resource_type,
        "sandbox": r.sandbox,
        "machine": r.machine,
        "region": r.region,
        "state": r.state,
        "created": r.created,
        "expires": r.expires,
        "expired": r.expired,
        "started_by": r.started_by,
        "cost_usd": r.cost_usd,
    })
}

fn status_json(s: &cua_sdk::CloudStatus) -> serde_json::Value {
    serde_json::json!({
        "default_on": s.default_on,
        "providers": s.providers.iter().map(provider_json).collect::<Vec<_>>(),
        "resources": s.resources.iter().map(resource_json).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct T {
        #[command(subcommand)]
        cmd: CloudCmd,
    }

    fn parse(a: &[&str]) -> CloudCmd {
        T::try_parse_from(std::iter::once("cloud").chain(a.iter().copied()))
            .unwrap()
            .cmd
    }

    fn parse_err(a: &[&str]) -> bool {
        T::try_parse_from(std::iter::once("cloud").chain(a.iter().copied())).is_err()
    }

    #[test]
    fn an_audit_line_names_who_did_what() {
        let e = cua_sdk::CloudAuditEntry {
            ts: "2026-10-21T09:00:00Z".into(),
            action: "resource_deleted".into(),
            provider: "aws".into(),
            kind: "instance".into(),
            id: "i-1".into(),
            space: "research".into(),
            actor: "auto-sweep".into(),
            outcome: "ok".into(),
            detail: "expired".into(),
            source: String::new(),
        };
        let l = audit_line(&e);
        assert!(
            l.ends_with("instance i-1 · research · auto-sweep · ok · expired"),
            "{l}"
        );
        assert_eq!(audit_json(&e)["actor"], "auto-sweep");
    }

    #[test]
    fn approve_parses_and_hint_lines_are_short_and_plain() {
        assert!(matches!(
            parse(&["approve", "aws"]),
            CloudCmd::Approve { provider, deny: false } if provider == "aws"
        ));
        assert!(matches!(
            parse(&["approve", "aws", "--deny"]),
            CloudCmd::Approve { deny: true, .. }
        ));
        assert!(parse_err(&["approve"]));
        let p = cua_sdk::CloudProvider {
            name: "aws".into(),
            title: "AWS".into(),
            connected: true,
            auth: "cli".into(),
            suggest_auth: "oidc".into(),
            ..Default::default()
        };
        assert_eq!(
            hint_lines(&p),
            vec!["  Switch to OIDC (no stored key): cua cloud connect aws --oidc".to_string()]
        );
        let p = cua_sdk::CloudProvider {
            name: "aws".into(),
            title: "AWS".into(),
            connected: true,
            auth: "oidc".into(),
            approval: "limits".into(),
            approval_agent: "researcher".into(),
            pending_budget_usd_month: Some(500.0),
            can_approve: true,
            ..Default::default()
        };
        let l = hint_lines(&p);
        assert_eq!(
            l[0],
            "  Agent researcher asks for a budget of $500 a month."
        );
        assert!(l[1].contains("cua cloud approve aws --deny"), "{l:?}");
        // An agent's shell gets no approve line (it could not run it).
        let agent = cua_sdk::CloudProvider {
            can_approve: false,
            ..p
        };
        assert!(hint_lines(&agent).is_empty());
        for line in hint_lines(&cua_sdk::CloudProvider {
            issue: "AWS was disconnected from your Cua account.".into(),
            ..Default::default()
        }) {
            assert!(!line.contains('\u{b7}'), "no dot chains: {line}");
        }
        let j = provider_json(&agent);
        for k in [
            "approval_agent",
            "pending_budget_usd_month",
            "pending_max_size",
            "can_approve",
            "suggest_auth",
            "issue",
        ] {
            assert!(j.get(k).is_some(), "{k} missing from --json");
        }
    }

    #[test]
    fn a_connected_cloud_prints_its_place_once() {
        let p = cua_sdk::CloudProvider {
            name: "gcp".into(),
            title: "Google Cloud".into(),
            connected: true,
            label: "Google Cloud \u{b7} us-central1".into(),
            account: "cua-byoc-test".into(),
            ..Default::default()
        };
        let l = provider_line(&p);
        assert_eq!(l.matches("Google Cloud").count(), 1, "{l}");
        assert!(l.contains("connected · us-central1 · cua-byoc-test"), "{l}");
    }

    #[test]
    fn connect_takes_the_agent_flags_and_never_prompts() {
        match parse(&[
            "connect",
            "aws",
            "--oidc",
            "--region",
            "us-west-2",
            "--budget",
            "200",
            "--max-size",
            "4x16",
            "--account-id",
            "123456789012",
            "--check",
        ]) {
            CloudCmd::Connect {
                target,
                oidc,
                budget,
                max_size,
                account_id,
                check,
                role_arn,
                ..
            } => {
                assert_eq!(target.provider, "aws");
                assert!(oidc && check);
                assert_eq!(budget, Some(200.0));
                assert_eq!(max_size.as_deref(), Some("4x16"));
                assert_eq!(account_id.as_deref(), Some("123456789012"));
                assert_eq!(role_arn, None);
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_err(&["connect", "aws", "--budget", "lots"]));
        match parse(&[
            "connect",
            "gcp",
            "--oidc",
            "--project",
            "my-project",
            "--project-number",
            "123456789012",
            "--service-account",
            "cua@my-project.iam.gserviceaccount.com",
            "--budget",
            "200",
            "--check",
        ]) {
            CloudCmd::Connect {
                target,
                project_number,
                service_account,
                ..
            } => {
                assert_eq!(target.project.as_deref(), Some("my-project"));
                assert_eq!(project_number.as_deref(), Some("123456789012"));
                assert_eq!(
                    service_account.as_deref(),
                    Some("cua@my-project.iam.gserviceaccount.com")
                );
            }
            other => panic!("{other:?}"),
        }
        match parse(&[
            "connect",
            "azure",
            "--region",
            "westus2",
            "--budget",
            "200",
            "--subscription",
            "s",
            "--tenant",
            "t",
            "--client-id",
            "c",
            "--resource-group",
            "rg",
            "--check",
        ]) {
            CloudCmd::Connect {
                target,
                oidc,
                subscription_id,
                tenant_id,
                client_id,
                resource_group,
                check,
                ..
            } => {
                assert_eq!(target.provider, "azure");
                // Azure needs no --oidc: it has no other way.
                assert!(!oidc && check);
                assert_eq!(
                    (
                        subscription_id.as_deref(),
                        tenant_id.as_deref(),
                        client_id.as_deref(),
                        resource_group.as_deref()
                    ),
                    (Some("s"), Some("t"), Some("c"), Some("rg"))
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&["trust", "gcp"]),
            CloudCmd::Trust { cloud } if cloud == "gcp"
        ));
        // The help an agent follows names every status, the exit codes and
        // the steps.
        for word in [
            "needs-trust",
            "checking",
            "waiting-for-approval",
            "connected",
            "failed",
            "0 connected, 10",
            "11 it waits on a",
            "--account-id <ID> --check",
            "cua cloud status aws",
            "--project-number <N> --check",
            "cua cloud status gcp",
            "--subscription --tenant --client-id --check",
            "cua cloud status azure",
            "https://cua.ai/docs/spaces/guides/connect-a-cloud",
        ] {
            assert!(CONNECT_HELP.contains(word), "{word}");
        }
    }

    #[test]
    fn hetzner_and_modal_seal_their_token_unless_told_not_to() {
        match parse(&[
            "connect",
            "hetzner",
            "--token-stdin",
            "--region",
            "fsn1",
            "--budget",
            "50",
            "--max-size",
            "4x8",
        ]) {
            CloudCmd::Connect {
                target,
                sealed,
                no_sealed,
                oidc,
                budget,
                ..
            } => {
                assert!(target.token_stdin);
                // Neither: the default (sealed with pool keys and a budget).
                assert!(!sealed && !no_sealed && !oidc);
                assert_eq!(budget, Some(50.0));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&["connect", "hetzner", "--sealed", "--budget", "50"]),
            CloudCmd::Connect { sealed: true, .. }
        ));
        assert!(matches!(
            parse(&["connect", "hetzner", "--no-sealed", "--token-stdin"]),
            CloudCmd::Connect {
                no_sealed: true,
                ..
            }
        ));
        assert!(parse_err(&[
            "connect",
            "hetzner",
            "--sealed",
            "--no-sealed"
        ]));
        assert!(parse_err(&["connect", "aws", "--oidc", "--sealed"]));
        for word in [
            "--token-stdin --region fsn1 --budget 50",
            "--no-sealed",
            "<token id>:<token secret>",
            "can open it",
            "--sealed without a token",
        ] {
            assert!(CONNECT_HELP.contains(word), "{word}");
        }
        // Status says who can open it.
        let p = cua_sdk::CloudProvider {
            name: "hetzner".into(),
            title: "Hetzner".into(),
            connected: true,
            auth: "sealed".into(),
            holders: vec!["Dillon's MacBook".into(), "studio".into()],
            ..Default::default()
        };
        assert_eq!(
            limits_line(&p).unwrap(),
            "  Token sealed; can open it: Dillon's MacBook, studio."
        );
        assert_eq!(provider_json(&p)["holders"][1], "studio");
    }

    fn outcome(status: &str, next: Option<cua_sdk::CloudNext>) -> cua_sdk::CloudConnected {
        cua_sdk::CloudConnected {
            provider: cua_sdk::CloudProvider {
                name: "aws".into(),
                title: "AWS".into(),
                status: status.into(),
                region: "us-west-2".into(),
                auth: "oidc".into(),
                budget_usd_month: Some(200.0),
                max_size: "4x16".into(),
                connected: status == "connected",
                ..Default::default()
            },
            next,
            verify: "cua cloud status aws".into(),
            ..Default::default()
        }
    }

    #[test]
    fn every_connect_ends_with_status_next_and_verify() {
        let run = |r: &str| cua_sdk::CloudNext {
            run: Some(r.into()),
            why: "w".into(),
            ..Default::default()
        };
        let open = cua_sdk::CloudNext {
            open: Some("https://us-west-2.console.aws.amazon.com/cloudshell/home".into()),
            paste: Some("curl … && aws cloudformation deploy …".into()),
            why: "AWS does not trust Cua yet.".into(),
            ..Default::default()
        };
        assert_eq!(connect_exit_code(&outcome("connected", None)), 0);
        assert_eq!(connect_exit_code(&outcome("checking", Some(run("x")))), 10);
        assert_eq!(connect_exit_code(&outcome("failed", Some(run("x")))), 10);
        assert_eq!(
            connect_exit_code(&outcome("needs-trust", Some(open.clone()))),
            11
        );
        assert_eq!(
            connect_exit_code(&outcome(
                "waiting-for-approval",
                Some(cua_sdk::CloudNext {
                    why: "a person approves".into(),
                    ..Default::default()
                })
            )),
            11
        );
        assert_eq!(connect_exit_code(&outcome("failed", None)), 1);
        assert_eq!(
            plain_error("invalid argument: invalid argument: max size"),
            "invalid argument: max size"
        );
        assert_eq!(plain_error("cloud: aws: x"), "cloud: aws: x");

        let v = connect_json(&outcome("needs-trust", Some(open.clone())));
        assert_eq!(v["status"], "needs-trust");
        assert_eq!(v["verify"], "cua cloud status aws");
        assert!(v["next"]["open"].as_str().unwrap().contains("cloudshell"));
        assert!(v["next"].get("run").is_none());
        assert_eq!(v["checks"], serde_json::json!([]));
        assert_eq!(v["provider"]["budget_usd_month"], 200.0);
        assert!(connect_json(&outcome("connected", None))["next"].is_null());

        let lines = connect_lines(&outcome("needs-trust", Some(open)));
        assert_eq!(lines[0], "AWS: needs trust");
        assert!(
            lines.contains(&"Budget: $200 a month".to_string()),
            "{lines:?}"
        );
        assert!(lines.contains(&"Machines up to 4 vCPU and 16 GB".to_string()));
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("Next, for a person: open https://"))
        );
        assert!(lines.iter().any(|l| l.starts_with("Paste there: ")));
        assert_eq!(lines.last().unwrap(), "Verify: cua cloud status aws");
        // Short plain lines: no "a · b · c" chains.
        assert!(lines.iter().all(|l| !l.contains('\u{b7}')), "{lines:?}");
        let done = connect_lines(&outcome("connected", None));
        assert_eq!(done[0], "AWS: connected");
        assert!(done.contains(&"Create a Space there: cua spaces create --on aws".to_string()));
    }

    #[test]
    fn the_commands_parse() {
        match parse(&["connect", "aws", "--region", "us-west-2", "--default"]) {
            CloudCmd::Connect {
                target,
                make_default,
                ttl_hours,
                ..
            } => {
                assert_eq!(target.target().provider, "aws");
                assert_eq!(target.region.as_deref(), Some("us-west-2"));
                assert!(make_default);
                assert_eq!(ttl_hours, None);
            }
            other => panic!("{other:?}"),
        }
        match parse(&["sweep", "gcp"]) {
            CloudCmd::Sweep {
                provider,
                delete,
                all,
            } => assert_eq!(
                (provider.as_deref(), delete, all),
                (Some("gcp"), false, false)
            ),
            other => panic!("{other:?}"),
        }
        match parse(&[
            "add",
            "aws",
            "--count",
            "2",
            "--type",
            "g6.xlarge",
            "--ttl-hours",
            "6",
            "--tag",
            "team=ml",
        ]) {
            CloudCmd::Add {
                cloud: AddCloud::Aws(a),
            } => {
                assert_eq!((a.count, a.instance_type.as_str()), (2, "g6.xlarge"));
                assert_eq!(
                    (a.ttl_hours, a.tags.as_slice()),
                    (Some(6), &["team=ml".to_string()][..])
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&["add", "aws", "--down", "--name", "aws-3"]),
            CloudCmd::Add { cloud: AddCloud::Aws(a) } if a.down && a.name.as_deref() == Some("aws-3")
        ));
        assert!(parse_err(&["add", "aws", "--list", "--down"]));
        assert!(matches!(
            parse(&["disconnect", "AWS"]),
            CloudCmd::Disconnect { provider, delete: false } if provider == "AWS"
        ));
        assert!(matches!(
            parse(&["disconnect", "aws", "--delete"]),
            CloudCmd::Disconnect { delete: true, .. }
        ));
        assert!(matches!(
            parse(&["audit"]),
            CloudCmd::Audit {
                limit: 50,
                cloud: None
            }
        ));
        assert!(matches!(
            parse(&["audit", "--limit", "7", "--cloud", "aws"]),
            CloudCmd::Audit { limit: 7, cloud: Some(c) } if c == "aws"
        ));
        assert!(matches!(
            parse(&["cost"]),
            CloudCmd::Cost { by, format, since: None, cloud: None } if by == "space" && format == "table"
        ));
        assert!(matches!(
            parse(&["cost", "--by", "day", "--since", "2026-10-01", "--format", "csv", "--cloud", "aws"]),
            CloudCmd::Cost { by, format, since: Some(d), cloud: Some(c) }
                if by == "day" && format == "csv" && d == "2026-10-01" && c == "aws"
        ));
        assert!(parse_err(&["cost", "--by", "week"]));
        assert!(parse_err(&["cost", "--format", "xml"]));
        assert!(parse_err(&["audit", "--limit", "many"]));
        assert!(matches!(
            parse(&["ls"]),
            CloudCmd::Status { provider: None }
        ));
        match parse(&["connect", "hetzner", "--token-stdin", "--region", "nbg1"]) {
            CloudCmd::Connect { target, .. } => {
                assert_eq!(target.provider, "hetzner");
                assert!(target.token_stdin);
                assert_eq!(target.region.as_deref(), Some("nbg1"));
            }
            other => panic!("{other:?}"),
        }
        // Without the flag the token is never read from stdin.
        match parse(&["connect", "hetzner"]) {
            CloudCmd::Connect { target, .. } => {
                assert!(!target.token_stdin);
                assert_eq!(target.target().token, None);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&["test", "MODAL", "--environment", "e"]),
            CloudCmd::Test { target } if target.target().provider == "modal"
        ));
    }

    #[test]
    fn aliyun_ecs_commands_and_help_parse() {
        match parse(&[
            "test",
            "ALIYUN-ECS",
            "--profile",
            "webhook_manager",
            "--region",
            "cn-shanghai",
        ]) {
            CloudCmd::Test { target } => {
                let t = target.target();
                assert_eq!(t.provider, "aliyun-ecs");
                assert_eq!(t.profile.as_deref(), Some("webhook_manager"));
                assert_eq!(t.region.as_deref(), Some("cn-shanghai"));
            }
            other => panic!("{other:?}"),
        }
        match parse(&[
            "connect",
            "aliyun-ecs",
            "--token-stdin",
            "--region",
            "cn-hangzhou",
            "--budget",
            "50",
            "--max-size",
            "4x16",
            "--ttl-hours",
            "4",
            "--default",
        ]) {
            CloudCmd::Connect {
                target,
                make_default,
                ttl_hours,
                budget,
                max_size,
                ..
            } => {
                assert_eq!(target.provider, "aliyun-ecs");
                assert!(target.token_stdin);
                assert_eq!(target.region.as_deref(), Some("cn-hangzhou"));
                assert!(make_default);
                assert_eq!(ttl_hours, Some(4));
                assert_eq!(budget, Some(50.0));
                assert_eq!(max_size.as_deref(), Some("4x16"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&["status", "aliyun-ecs"]),
            CloudCmd::Status { provider: Some(p) } if p == "aliyun-ecs"
        ));
        assert!(matches!(
            parse(&["disconnect", "aliyun-ecs"]),
            CloudCmd::Disconnect { provider, delete: false } if provider == "aliyun-ecs"
        ));
        for needle in [
            "aliyun-ecs",
            "ALIBABA_CLOUD_ACCESS_KEY_ID",
            "~/.aliyun/config.json",
            "cn-hangzhou",
        ] {
            assert!(CONNECT_HELP.contains(needle), "{needle}");
        }
    }

    #[test]
    fn token_stdin_preserves_empty_or_whitespace_input() {
        let empty = TargetArgs {
            provider: "aliyun-ecs".into(),
            token_stdin: true,
            ..Default::default()
        };
        assert_eq!(
            empty.target_with_stdin(String::new).token.as_deref(),
            Some("")
        );
        assert_eq!(
            empty
                .target_with_stdin(|| "  \n\t ".into())
                .token
                .as_deref(),
            Some("")
        );
        assert_eq!(
            empty
                .target_with_stdin(|| " ak:sk \n".into())
                .token
                .as_deref(),
            Some("ak:sk")
        );
        let no_stdin = TargetArgs {
            provider: "aliyun-ecs".into(),
            token_stdin: false,
            ..Default::default()
        };
        assert_eq!(no_stdin.target_with_stdin(|| "ignored".into()).token, None);
    }

    #[test]
    fn cost_prints_plain_columns_and_a_stable_csv() {
        let r = cua_sdk::CloudCostReport {
            by: "space".into(),
            since: "2026-10-01".into(),
            until: "2026-10-24T12:00:00Z".into(),
            rows: vec![
                cua_sdk::CloudCostRow {
                    key: "research".into(),
                    usd: 4.5,
                    hours: 9.0,
                    machines: 2,
                },
                cua_sdk::CloudCostRow {
                    key: "a,b".into(),
                    usd: 1.0,
                    hours: 1.0,
                    machines: 1,
                },
            ],
            total_usd: 5.5,
        };
        // Scripts read this header: only ever add columns at the end.
        assert_eq!(COST_CSV_HEADER, "key,usd,hours,machines");
        assert_eq!(
            cost_csv(&r.rows),
            "key,usd,hours,machines\nresearch,4.50,9.00,2\n\"a,b\",1.00,1.00,1\n"
        );
        let t = cost_table(&r);
        assert!(t[0].starts_with("Space"), "{t:?}");
        assert!(t[1].contains("$4.50"), "{t:?}");
        assert_eq!(
            t[3],
            "Total $5.50 since 2026-10-01 (estimated from list prices)."
        );
        assert!(
            t.iter().all(|l| !l.contains('\u{b7}')),
            "no dot chains: {t:?}"
        );
        let empty = cua_sdk::CloudCostReport {
            since: "2026-10-01".into(),
            ..Default::default()
        };
        assert_eq!(cost_table(&empty), vec!["Nothing ran since 2026-10-01."]);
        assert_eq!(cost_json(&r)["rows"][0]["key"], "research");
    }

    #[test]
    fn relay_flags_parse_conflict_preserve_empty_stdin_and_redact_output() {
        match parse(&[
            "connect",
            "hetzner",
            "--relay-url",
            "https://relay.example.com/",
            "--relay-mode",
            "static",
            "--relay-token-stdin",
            "--spacesd-download-url",
            "https://mirror.example.com/cua-spacesd.exe",
        ]) {
            CloudCmd::Connect { target, .. } => {
                assert_eq!(
                    target.relay_url.as_deref(),
                    Some("https://relay.example.com/")
                );
                assert_eq!(target.relay_mode.as_deref(), Some("static"));
                assert!(target.relay_token_stdin);
                assert_eq!(
                    target.spacesd_download_url.as_deref(),
                    Some("https://mirror.example.com/cua-spacesd.exe")
                );
                let wire = target.target_with_stdin(|| "  static-tok \n".into());
                assert_eq!(wire.relay_token.as_deref(), Some("static-tok"));
                assert_eq!(wire.relay_mode.as_deref(), Some("static"));
                assert_eq!(
                    wire.spacesd_download_url.as_deref(),
                    Some("https://mirror.example.com/cua-spacesd.exe")
                );
                assert!(!format!("{wire:?}").contains("static-tok"));
            }
            other => panic!("{other:?}"),
        }

        // Empty stdin for --relay-token-stdin produces Some("") so backend rejects it cleanly.
        let empty = TargetArgs {
            provider: "hetzner".into(),
            relay_token_stdin: true,
            ..Default::default()
        };
        assert_eq!(
            empty
                .target_with_stdin(|| " \t\n ".into())
                .relay_token
                .as_deref(),
            Some("")
        );

        // --relay-token-stdin conflicts with --token-stdin.
        parse_err(&["connect", "hetzner", "--token-stdin", "--relay-token-stdin"]);

        // connect_lines / limits_line / provider_json show relay mode & URL without tokens.
        let p = cua_sdk::CloudProvider {
            name: "hetzner".into(),
            title: "Hetzner Cloud".into(),
            connected: true,
            status: "connected".into(),
            auth: "token".into(),
            relay_url: Some("https://relay.example.com".into()),
            relay_mode: Some("static".into()),
            ..Default::default()
        };
        let lines = connect_lines(&cua_sdk::CloudConnected {
            provider: p.clone(),
            verify: "cua cloud status hetzner".into(),
            ..Default::default()
        });
        assert!(
            lines
                .iter()
                .any(|l| l == "Relay: https://relay.example.com (static)"),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("https://relay.example.com"))
        );
        let lim = limits_line(&p).unwrap();
        assert!(lim.contains("https://relay.example.com"), "{lim}");
        assert!(lim.contains("Static Relay Mode"), "{lim}");
        let j = provider_json(&p);
        assert_eq!(j["relay_mode"], "static");
        assert_eq!(j["relay_url"], "https://relay.example.com");
    }

    #[test]
    fn aliyun_ecs_existing_vpc_flags_parse_and_render() {
        match parse(&[
            "test",
            "aliyun-ecs",
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--no-public-ip",
        ]) {
            CloudCmd::Test { target } => {
                let wire = target.target_with_stdin(String::new);
                assert_eq!(wire.vpc_id.as_deref(), Some("vpc-user-1"));
                assert_eq!(wire.vswitch_id.as_deref(), Some("vsw-user-1"));
                assert!(wire.no_public_ip);
            }
            other => panic!("{other:?}"),
        }
        match parse(&[
            "connect",
            "aliyun-ecs",
            "--vpc-id",
            "vpc-user-1",
            "--vswitch-id",
            "vsw-user-1",
            "--no-public-ip",
        ]) {
            CloudCmd::Connect { target, .. } => {
                let wire = target.target_with_stdin(String::new);
                assert_eq!(wire.vpc_id.as_deref(), Some("vpc-user-1"));
                assert_eq!(wire.vswitch_id.as_deref(), Some("vsw-user-1"));
                assert!(wire.no_public_ip);
            }
            other => panic!("{other:?}"),
        }

        let p = cua_sdk::CloudProvider {
            name: "aliyun-ecs".into(),
            title: "Alibaba Cloud ECS".into(),
            connected: true,
            status: "connected".into(),
            vpc_id: Some("vpc-user-1".into()),
            vswitch_id: Some("vsw-user-1".into()),
            no_public_ip: true,
            ..Default::default()
        };
        let lim = limits_line(&p).unwrap();
        assert!(
            lim.contains("vpc-user-1") && lim.contains("vsw-user-1"),
            "{lim}"
        );
        assert!(lim.contains("--no-public-ip"), "{lim}");

        let lines = connect_lines(&cua_sdk::CloudConnected {
            provider: p.clone(),
            verify: "cua cloud status aliyun-ecs".into(),
            ..Default::default()
        });
        assert!(
            lines
                .iter()
                .any(|l| l.contains("vpc-user-1") && l.contains("vsw-user-1")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("--no-public-ip")),
            "{lines:?}"
        );

        let j = provider_json(&p);
        assert_eq!(j["vpc_id"], "vpc-user-1");
        assert_eq!(j["vswitch_id"], "vsw-user-1");
        assert_eq!(j["no_public_ip"], true);
    }

    #[test]
    fn cloud_connect_and_test_parse_image_id_and_instance_type_defaults() {
        match parse(&[
            "connect",
            "aliyun-ecs",
            "--region",
            "cn-hangzhou",
            "--windows-image-id",
            "m-win11",
            "--linux-image-id",
            "m-ubuntu",
            "--instance-type",
            "ecs.c7.2xlarge",
            "--max-size",
            "8x32x120",
        ]) {
            CloudCmd::Connect {
                target, max_size, ..
            } => {
                assert_eq!(max_size.as_deref(), Some("8x32x120"));
                let wire = target.target_with_stdin(String::new);
                assert_eq!(wire.windows_image_id.as_deref(), Some("m-win11"));
                assert_eq!(wire.linux_image_id.as_deref(), Some("m-ubuntu"));
                assert_eq!(wire.instance_type.as_deref(), Some("ecs.c7.2xlarge"));
            }
            other => panic!("{other:?}"),
        }

        match parse(&[
            "test",
            "aliyun-ecs",
            "--windows-image-id",
            "m-win10",
            "--linux-image-id",
            "m-lin",
            "--instance-type",
            "ecs.g7.large",
        ]) {
            CloudCmd::Test { target } => {
                let wire = target.target_with_stdin(String::new);
                assert_eq!(wire.windows_image_id.as_deref(), Some("m-win10"));
                assert_eq!(wire.linux_image_id.as_deref(), Some("m-lin"));
                assert_eq!(wire.instance_type.as_deref(), Some("ecs.g7.large"));
            }
            other => panic!("{other:?}"),
        }

        assert_eq!(size_words("4x16"), "4 vCPU and 16 GB");
        assert_eq!(size_words("8x32x120"), "8 vCPU, 32 GB, and 120 GB disk");

        let p = cua_sdk::CloudProvider {
            name: "aliyun-ecs".into(),
            title: "Alibaba Cloud ECS".into(),
            connected: true,
            status: "connected".into(),
            windows_image_id: Some("m-win11".into()),
            linux_image_id: Some("m-ubuntu".into()),
            instance_type: Some("ecs.c7.2xlarge".into()),
            ..Default::default()
        };
        let lim = limits_line(&p).unwrap();
        assert!(lim.contains("Windows Cloud Image ID: m-win11"), "{lim}");
        assert!(lim.contains("Linux Cloud Image ID: m-ubuntu"), "{lim}");
        assert!(
            lim.contains("Default instance type: ecs.c7.2xlarge"),
            "{lim}"
        );
        let j = provider_json(&p);
        assert_eq!(j["windows_image_id"], "m-win11");
        assert_eq!(j["linux_image_id"], "m-ubuntu");
        assert_eq!(j["instance_type"], "ecs.c7.2xlarge");
    }
}
