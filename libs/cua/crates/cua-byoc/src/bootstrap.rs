// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! The first boot of a cloud VM that runs one sandbox: cloud-init user
//! data that installs Docker and runs the sandbox's image with its
//! cua-spacesd joined to the relay as the machine the client registered.
//! No inbound port and no account credential on the VM; nothing but Docker
//! is installed (the image carries its own driver).
//!
//! Three guardrails make a forgotten VM end on its own:
//!
//! - `shutdown -h +<ttl>` from the first boot, with the cloud's
//!   instance-initiated shutdown set to terminate (or delete);
//! - a `cua-expire` systemd timer that shuts the VM down once the time in
//!   `/etc/cua/expires` has passed, again after every reboot or start;
//! - the `cua-expires` tag the sweeper reads.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::relay::Join;

pub use crate::bootstrap_win::{WindowsVmBoot, windows_user_data};

/// The container the VM runs the sandbox in.
pub const CONTAINER: &str = "cua-sandbox";

/// The user the Linux images run cua-spacesd as (`cua`, uid 1000): the
/// relay files are theirs, readable by nobody else.
pub const GUEST_UID: u32 = 1000;

/// The Docker drop-in that keeps containers from the metadata service
/// (169.254.169.254) but lets DNS through (Compute Engine's resolver is that
/// address). `-I` inserts at the top, so the DNS exceptions go in last.
pub const METADATA_RULES: &str = "[Service]\n\
     ExecStartPost=-/sbin/iptables -I DOCKER-USER -d 169.254.169.254 -j DROP\n\
     ExecStartPost=-/sbin/iptables -I DOCKER-USER -d 100.100.100.200 -j DROP\n\
     ExecStartPost=-/sbin/iptables -I DOCKER-USER -d 169.254.169.254 -p udp --dport 53 -j RETURN\n\
     ExecStartPost=-/sbin/iptables -I DOCKER-USER -d 169.254.169.254 -p tcp --dport 53 -j RETURN\n";

/// The environment variables a Linux image's start script reads extra
/// driver arguments from, newest spelling first.
pub const JOIN_ARG_VARS: &[&str] = &["CUA_SPACESD_ARGS", "CUA_GUESTD_ARGS", "CUA_ENV_DRIVER_ARGS"];

/// What one VM's first boot needs.
#[derive(Clone, Debug)]
pub struct VmBoot<'a> {
    /// The relay machine the sandbox joins as.
    pub join: &'a Join,
    /// The image (pinned by digest when resolved).
    pub image: &'a str,
    /// The guest environment (the spacesd token among it: secret).
    pub env: &'a BTreeMap<String, String>,
    /// Unix seconds after which the VM shuts itself down (0: never).
    pub expires: u64,
    /// Seconds from boot for the `shutdown -h` backstop (0: none).
    pub ttl_secs: u64,
    /// Shared memory for the desktop's browsers, in MiB.
    pub shm_mb: u32,
    /// The cloud (`aws`, `gcp`, `azure`, `hetzner`): the network guard
    /// ([`crate::hostnet`]) reads its resolver and own network by it.
    pub provider: &'a str,
    /// Secure Spaces: the computer's own network guard keeps the sandbox to
    /// the internet. Without it the old Docker drop-in only keeps it from
    /// the metadata service.
    pub net_guard: bool,
    /// Public TCP shares: the container publishes the share slots.
    pub share_slots: bool,
}

impl VmBoot<'_> {
    /// The two switches as the experiments on this computer say.
    pub fn switches() -> (bool, bool) {
        (
            cua_vmm::network::Mode::from_env() == cua_vmm::network::Mode::Secure,
            cua_vmm::experiments::enabled(cua_vmm::experiments::Gate::TcpShares),
        )
    }
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// Single-quotes `s` for `sh`.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The script the VM runs once (as root) from cloud-init.
pub fn first_boot_script(boot: &VmBoot<'_>) -> String {
    let mut s = String::from(
        "#!/bin/sh\n\
         # Cua: this VM runs one sandbox; its cua-spacesd dials out to the relay.\n\
         set -eu\n\
         export DEBIAN_FRONTEND=noninteractive HOME=/root\n\
         log() { echo \"[cua-first-boot] $(date -u +%FT%TZ) $*\"; }\n\
         retry() { n=0; until \"$@\"; do n=$((n+1)); [ $n -ge 5 ] && return 1; sleep $((n*5)); done; }\n",
    );
    if boot.ttl_secs > 0 {
        let minutes = boot.ttl_secs.div_ceil(60).max(1);
        s.push_str(&format!(
            "log 'backstop: shutdown in {minutes} min'\n\
             shutdown -h +{minutes} 'cua: this sandbox reached its time limit' || true\n"
        ));
    }
    // Docker's bridge defaults to MTU 1500; on a smaller network (Compute
    // Engine's 1460) TLS from the sandbox stalls while the host's own pulls
    // work. Use the host interface's MTU.
    s.push_str(
        "dev=$(ip route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i==\"dev\") {print $(i+1); exit}}')\n\
         mtu=$(cat /sys/class/net/${dev:-eth0}/mtu 2>/dev/null || echo 1500)\n\
         mkdir -p /etc/docker\n\
         [ -s /etc/docker/daemon.json ] || printf '{\"mtu\": %s}\\n' \"$mtu\" > /etc/docker/daemon.json\n\
         log \"docker mtu $mtu\"\n",
    );
    s.push_str(
        "log 'installing Docker'\n\
         if ! command -v docker >/dev/null; then\n\
         \x20 if command -v apt-get >/dev/null; then\n\
         \x20   retry apt-get update -q\n\
         \x20   retry apt-get install -y -q docker.io\n\
         \x20 elif command -v dnf >/dev/null; then\n\
         \x20   retry dnf install -y docker\n\
         \x20 fi\n\
         fi\n\
         systemctl enable --now docker\n",
    );
    // The guard is in place before the sandbox's container exists.
    if boot.net_guard {
        s.push_str(&crate::hostnet::install_snippet(&crate::hostnet::HostNet {
            provider: boot.provider,
            extra_cidrs: &[],
        }));
    }
    s.push_str(&format!(
        "chown -R {uid}:{uid} /etc/cua/relay && chmod 0700 /etc/cua/relay && chmod 0600 /etc/cua/relay/*\n\
         log 'pulling the image'\n\
         retry docker pull {image}\n\
         docker rm -f {CONTAINER} >/dev/null 2>&1 || true\n\
         log 'starting the sandbox'\n\
         docker run -d --name {CONTAINER} --restart unless-stopped --shm-size {shm}m \\\n\
         \x20 --env-file /etc/cua/sandbox.env \\\n\
         {slots_flag}\
         \x20 -v /etc/cua/relay:/run/cua-relay:ro \\\n\
         \x20 {image}\n\
         shred -u /etc/cua/sandbox.env 2>/dev/null || rm -f /etc/cua/sandbox.env\n\
         log 'started; the driver log follows (the boot log shows why a sandbox never comes online)'\n\
         sleep 60\n\
         docker exec {CONTAINER} sh -c 'tail -n 40 /var/log/supervisor/cua-spacesd.log /var/log/supervisor/cua-guestd.log /var/log/supervisor/cua-env-driver.log 2>/dev/null' \\\n\
         \x20 | grep -v -i -e token -e 'cmt_' || true\n\
         log 'done'\n",
        uid = GUEST_UID,
        slots_flag = if boot.share_slots {
            let slots = format!(
                "{}-{}",
                crate::share_net::HOST_SLOTS.0,
                crate::share_net::HOST_SLOTS.1
            );
            format!("\x20 -p {slots}:{slots} \\\n")
        } else {
            String::new()
        },
        image = sh_quote(boot.image),
        shm = boot.shm_mb.max(64),
    ));
    s
}

/// The environment file of the container: the guest environment plus the
/// relay join (files mounted at `/run/cua-relay`, which every cua-spacesd
/// with `join` reads). Secret.
pub fn container_env(boot: &VmBoot<'_>) -> String {
    let mut env = boot.env.clone();
    // Every spelling of the driver's extra arguments: images from before
    // the cua-spacesd rename read CUA_GUESTD_ARGS (or CUA_ENV_DRIVER_ARGS).
    for k in JOIN_ARG_VARS {
        env.insert((*k).into(), "join".into());
    }
    env.insert("CUA_ENV_RELAY_URL".into(), boot.join.relay_url.clone());
    env.insert(
        "CUA_RELAY_TOKEN_FILE".into(),
        "/run/cua-relay/machine-token".into(),
    );
    env.insert(
        "CUA_ENV_MACHINE_ID_FILE".into(),
        "/run/cua-relay/machine-id".into(),
    );
    if !boot.join.jwks_json.trim().is_empty() {
        env.insert("CUA_RELAY_JWKS".into(), "/run/cua-relay/jwks.json".into());
    }
    // Public TCP shares straight from this computer: the slots the container
    // publishes, which cua-spacesd serves only while a share holds one (and
    // the cloud firewall opens only then).
    if boot.share_slots {
        env.insert(
            "CUA_SHARE_SLOTS".into(),
            format!(
                "{}-{}",
                crate::share_net::HOST_SLOTS.0,
                crate::share_net::HOST_SLOTS.1
            ),
        );
    }
    env.insert(
        "CUA_HOST_POLICY".into(),
        "/run/cua-relay/policy.json".into(),
    );
    let mut out = String::new();
    for (k, v) in env {
        if !is_valid_env_key(&k, false) {
            continue;
        }
        // `--env-file` takes the rest of the line verbatim.
        let v = v.replace(['\r', '\n'], " ");
        out.push_str(&format!("{k}={v}\n"));
    }
    out
}

/// Returns `true` if `key` is safe to emit into a `KEY=VALUE` env file.
/// When `posix_only` is `true` (Linux Direct VM `sh` loader), also requires
/// `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_valid_env_key(key: &str, posix_only: bool) -> bool {
    if key.is_empty() || key.starts_with('#') || key.contains(['=', '\n', '\r', '\0']) {
        return false;
    }
    if !posix_only {
        return true;
    }
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Validates `--env` keys before provisioning so invalid/injectable keys fail
/// closed before touching relay or cloud resources.
pub fn validate_env_keys(
    env: &BTreeMap<String, String>,
    posix_only: bool,
) -> cua_sandbox_core::Result<()> {
    for key in env.keys() {
        if !is_valid_env_key(key, posix_only) {
            return Err(cua_sandbox_core::Error::InvalidArgument(format!(
                "invalid environment variable name {key:?}"
            )));
        }
    }
    Ok(())
}

const EXPIRE_SCRIPT: &str = "#!/bin/sh\n\
     # Cua: shut this VM down once its sandbox's time limit has passed.\n\
     exp=$(cat /etc/cua/expires 2>/dev/null || echo 0)\n\
     [ \"${exp:-0}\" -gt 0 ] 2>/dev/null || exit 0\n\
     if [ \"$(date +%s)\" -ge \"$exp\" ]; then\n\
     \x20 logger -t cua-expire 'time limit reached; shutting down'\n\
     \x20 exec /sbin/shutdown -h now 'cua: this sandbox reached its time limit'\n\
     fi\n";
const EXPIRE_SERVICE: &str = "[Unit]\nDescription=Cua: end this VM after its sandbox's time limit\n\n\
     [Service]\nType=oneshot\nExecStart=/usr/local/bin/cua-expire\n";
const EXPIRE_TIMER: &str = "[Unit]\nDescription=Cua: check this sandbox's time limit\n\n\
     [Timer]\nOnBootSec=1min\nOnUnitActiveSec=2min\n\n\
     [Install]\nWantedBy=timers.target\n";

/// Helper that writes the shared TTL expiry files (`expires`, `cua-expire`,
/// `cua-expire.service`, `cua-expire.timer`) into `#cloud-config` `write_files`.
fn push_expire_files(y: &mut String, expires: u64) {
    let file = |path: &str, perm: &str, content: &str| {
        format!(
            "  - path: {path}\n    permissions: '{perm}'\n    owner: root:root\n    encoding: b64\n    content: {}\n",
            b64(content)
        )
    };
    y.push_str(&file("/etc/cua/expires", "0644", &format!("{expires}\n")));
    y.push_str(&file("/usr/local/bin/cua-expire", "0755", EXPIRE_SCRIPT));
    y.push_str(&file(
        "/etc/systemd/system/cua-expire.service",
        "0644",
        EXPIRE_SERVICE,
    ));
    y.push_str(&file(
        "/etc/systemd/system/cua-expire.timer",
        "0644",
        EXPIRE_TIMER,
    ));
}

/// The `#cloud-config` user data for `boot`. Secret: the machine and
/// spacesd tokens are in it (base64, never in clear), and reach only this
/// VM; the providers limit the metadata service to the VM itself.
pub fn cloud_init(boot: &VmBoot<'_>) -> String {
    let file = |path: &str, perm: &str, content: &str| {
        format!(
            "  - path: {path}\n    permissions: '{perm}'\n    owner: root:root\n    encoding: b64\n    content: {}\n",
            b64(content)
        )
    };
    // No password logins on a machine whose only access is the relay.
    let mut y = String::from("#cloud-config\nssh_pwauth: false\n");
    y.push_str("write_files:\n");
    y.push_str(&file(
        "/etc/cua/relay/machine-token",
        "0600",
        &boot.join.machine_token,
    ));
    y.push_str(&file(
        "/etc/cua/relay/machine-id",
        "0600",
        &format!("{}\n", boot.join.machine_id),
    ));
    if !boot.join.jwks_json.trim().is_empty() {
        y.push_str(&file(
            "/etc/cua/relay/jwks.json",
            "0600",
            &boot.join.jwks_json,
        ));
    }
    y.push_str(&file(
        "/etc/cua/relay/policy.json",
        "0600",
        &boot.join.policy_json(),
    ));
    y.push_str(&file("/etc/cua/sandbox.env", "0600", &container_env(boot)));
    push_expire_files(&mut y, boot.expires);
    // After every Docker start (reboots, stop and start): the sandbox cannot
    // read the cloud's metadata service (the user data holds its tokens),
    // except DNS, which Compute Engine serves at the same address. (Under
    // Secure Spaces the computer's network guard does this, and more.)
    if !boot.net_guard {
        y.push_str(&file(
            "/etc/systemd/system/docker.service.d/cua-metadata.conf",
            "0644",
            METADATA_RULES,
        ));
    }
    y.push_str(&file(
        "/usr/local/sbin/cua-first-boot",
        "0700",
        &first_boot_script(boot),
    ));
    y.push_str(
        "runcmd:\n\
         \x20 - [systemctl, daemon-reload]\n\
         \x20 - [systemctl, enable, --now, cua-expire.timer]\n\
         \x20 - [sh, -c, '/usr/local/sbin/cua-first-boot 2>&1 | tee /var/log/cua-first-boot.log']\n",
    );
    y
}

/// Environment file (`/etc/cua/spacesd.env`, `0600`) for Linux Direct VM
/// (`--runtime native`), loaded literally by `/usr/local/sbin/cua-spacesd-start`.
/// Secret.
pub fn native_spacesd_env(boot: &VmBoot<'_>) -> String {
    let mut env = BTreeMap::new();
    env.insert("CUA_ENV_DATA_DIR".into(), "/var/lib/cua/spacesd".into());
    env.insert("CUA_ENV_LOG".into(), "info".into());
    for (k, v) in boot.env {
        env.insert(k.clone(), v.clone());
    }
    env.insert("CUA_ENV_RELAY_URL".into(), boot.join.relay_url.clone());
    env.insert(
        "CUA_RELAY_TOKEN_FILE".into(),
        "/etc/cua/relay/machine-token".into(),
    );
    env.insert(
        "CUA_ENV_MACHINE_ID_FILE".into(),
        "/etc/cua/relay/machine-id".into(),
    );
    if !boot.join.jwks_json.trim().is_empty() {
        env.insert("CUA_RELAY_JWKS".into(), "/etc/cua/relay/jwks.json".into());
    } else {
        env.remove("CUA_RELAY_JWKS");
    }
    if boot.share_slots {
        env.insert(
            "CUA_SHARE_SLOTS".into(),
            format!(
                "{}-{}",
                crate::share_net::HOST_SLOTS.0,
                crate::share_net::HOST_SLOTS.1
            ),
        );
    } else {
        env.remove("CUA_SHARE_SLOTS");
    }
    env.insert(
        "CUA_HOST_POLICY".into(),
        "/etc/cua/relay/policy.json".into(),
    );
    let mut out = String::new();
    for (k, v) in env {
        if !is_valid_env_key(&k, true) {
            continue;
        }
        let v = v.replace(['\r', '\n'], " ");
        out.push_str(&format!("{k}={v}\n"));
    }
    out
}

/// Systemd unit for `cua-spacesd join` on Linux Direct VM (`--runtime native`).
pub fn native_spacesd_service() -> &'static str {
    "[Unit]\n\
     Description=Cua Spaces daemon (Direct VM Sandbox)\n\
     After=network-online.target cua-host-net.service display-manager.service gdm.service lightdm.service sddm.service cua-desktop.service\n\
     Wants=network-online.target cua-host-net.service\n\
     Requires=cua-host-net.service\n\n\
     [Service]\n\
     Type=simple\n\
     ExecStart=/usr/local/sbin/cua-spacesd-start\n\
     Restart=always\n\
     RestartSec=1\n\
     OOMScoreAdjust=-1000\n\
     MemoryMin=64M\n\
     Delegate=yes\n\
     KillMode=mixed\n\
     TimeoutStopSec=10\n\
     LimitNOFILE=1048576\n\
     StateDirectory=cua/spacesd\n\n\
     [Install]\n\
     WantedBy=multi-user.target\n"
}

/// Lightweight starter wrapper (`/usr/local/sbin/cua-spacesd-start`) that
/// loads `/etc/cua/spacesd.env` literally, attaches `cua-spacesd join` to an
/// existing Wayland/X11 desktop session if present, or starts immediately in
/// headless mode (`CUA_ENV_NO_DESKTOP=true`).
pub fn native_spacesd_start_script() -> &'static str {
    r#"#!/bin/sh
set -eu
if [ -r /etc/cua/spacesd.env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; *'='*) ;; *) continue ;; esac
    key=${line%%=*}
    val=${line#*=}
    case "$key" in ''|[0-9]*|*[!A-Za-z0-9_]*) continue ;; esac
    export "$key=$val"
  done < /etc/cua/spacesd.env
fi
probe_desktop() {
  found=1
  if [ -r /run/cua-desktop/desktop.env ]; then
    set -a; . /run/cua-desktop/desktop.env; set +a
    [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && found=0
  fi
  if [ -z "${WAYLAND_DISPLAY:-}" ]; then
    for sock in /run/user/*/wayland-*; do
      [ -S "$sock" ] || continue
      case "$sock" in *.lock) continue ;; esac
      uid_dir=${sock%/*}
      export XDG_RUNTIME_DIR="$uid_dir" WAYLAND_DISPLAY="${sock##*/}"
      [ -S "$uid_dir/bus" ] && export DBUS_SESSION_BUS_ADDRESS="unix:path=$uid_dir/bus"
      for hypr in "$uid_dir"/hypr/*; do
        [ -d "$hypr" ] || continue
        export HYPRLAND_INSTANCE_SIGNATURE="${hypr##*/}"; break
      done
      found=0; break
    done
  fi
  if [ -z "${DISPLAY:-}" ]; then
    for sock in /tmp/.X11-unix/X*; do
      [ -S "$sock" ] || continue
      num=${sock##*/X}
      case "$num" in ''|*[!0-9]*) continue ;; esac
      export DISPLAY=":$num"
      if [ -z "${XAUTHORITY:-}" ]; then
        for auth in /run/user/*/gdm/Xauthority /run/user/*/.mutter-Xwaylandauth* /var/run/lightdm/root/:"$num" /home/*/.Xauthority /root/.Xauthority; do
          [ -r "$auth" ] && { export XAUTHORITY="$auth"; break; }
        done
      fi
      found=0; break
    done
  fi
  return "$found"
}
if ! probe_desktop && command -v systemctl >/dev/null 2>&1; then
  dm=0
  for unit in display-manager.service gdm.service gdm3.service lightdm.service sddm.service cua-desktop.service; do
    case "$(systemctl is-active "$unit" 2>/dev/null || true)" in activating|reloading) dm=1; break ;; esac
  done
  if [ "$dm" = 1 ]; then
    i=0
    while [ "$i" -lt 30 ] && ! probe_desktop; do sleep 1; i=$((i + 1)); done
  fi
fi
[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && export CUA_ENV_NO_DESKTOP=true
BIN=/usr/local/bin/cua-spacesd
[ -x "$BIN" ] || BIN=$(command -v cua-spacesd)
exec "$BIN" join
"#
}

/// First-boot script (`/usr/local/sbin/cua-first-boot`) for Linux Direct VM
/// (`--runtime native`). No Docker is installed or run. Writes `cua-host-net`,
/// `cua-spacesd-start`, and their systemd units (keeping `UserData` well under
/// 16 KB raw by avoiding per-file base64/YAML overhead).
pub fn native_first_boot_script(boot: &VmBoot<'_>, spacesd_download_url: Option<&str>) -> String {
    let mut s = String::from(
        "#!/bin/sh\n\
# Cua: Direct VM Sandbox bootstrap.\n\
set -eu\n\
export DEBIAN_FRONTEND=noninteractive HOME=/root\n\
log() { echo \"[cua-first-boot] $(date -u +%FT%TZ) $*\"; }\n\
retry() { n=0; until \"$@\"; do n=$((n+1)); [ $n -ge 5 ] && return 1; sleep $((n*5)); done; }\n",
    );
    if boot.ttl_secs > 0 {
        let minutes = boot.ttl_secs.div_ceil(60).max(1);
        s.push_str(&format!(
            "log 'backstop: shutdown in {minutes} min'\n\
shutdown -h +{minutes} 'cua: this sandbox reached its time limit' || true\n"
        ));
    }

    let version = cua_host::driver::SPACESD_VERSION.trim();
    let repo = cua_host::driver::RELEASE_REPOSITORY;
    let (custom_url, pinned_sha) = match spacesd_download_url
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        Some(raw) => match raw.split_once('#') {
            Some((u, frag)) => (
                Some(u),
                frag.strip_prefix("sha256=")
                    .map(|h| h.trim().to_ascii_lowercase())
                    .unwrap_or_default(),
            ),
            None => (Some(raw), String::new()),
        },
        None => (None, String::new()),
    };

    let resolve_url = match custom_url {
        Some(u) => format!(
            "DL_URL={}\n\
             DL_URL=$(printf '%s' \"$DL_URL\" | sed -e \"s/{{version}}/$VERSION/g\" -e \"s/{{arch}}/$ARCH/g\")\n\
             case \"$DL_URL\" in */) DL_URL=\"${{DL_URL}}cua-spacesd-linux-${{ARCH}}.tar.gz\" ;; esac\n",
            sh_quote(u)
        ),
        None => format!(
            "DL_URL=\"https://github.com/{repo}/releases/download/cua-spacesd-v{version}/cua-spacesd-linux-${{ARCH}}.tar.gz\"\n"
        ),
    };

    let host_net_snippet = crate::hostnet::native_install_snippet(&crate::hostnet::HostNet {
        provider: boot.provider,
        extra_cidrs: &[],
    });

    s.push_str(&format!(
        r#"VERSION={version_q}
PINNED_SHA={pinned_sha_q}
chmod 0700 /etc/cua/relay && chmod 0600 /etc/cua/relay/* /etc/cua/spacesd.env
BIN=""
for cand in /usr/local/bin/cua-spacesd /usr/bin/cua-spacesd /opt/cua/bin/cua-spacesd; do
  [ -x "$cand" ] && {{ BIN="$cand"; break; }}
done
if [ -z "$BIN" ]; then
  cand=$(command -v cua-spacesd 2>/dev/null || true)
  [ -n "$cand" ] && [ -x "$cand" ] && BIN="$cand"
fi
if [ -n "$BIN" ]; then
  log "using pre-installed cua-spacesd at $BIN"
  if [ "$BIN" != /usr/local/bin/cua-spacesd ]; then
    mkdir -p /usr/local/bin && ln -sf "$BIN" /usr/local/bin/cua-spacesd
  fi
else
  raw_arch=$(uname -m)
  case "$raw_arch" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) log "unsupported architecture: $raw_arch"; exit 1 ;;
  esac
  {resolve_url}
  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT
  SAFE_DL_URL=$(printf '%s' "$DL_URL" | sed -e 's#[?#].*$##' -e 's#^\([a-zA-Z0-9+.-]*://\)[^/]*@#\1<redacted>@#')
  log "downloading cua-spacesd from $SAFE_DL_URL"
  retry curl -fsSL -o "$TMP_DIR/payload" "$DL_URL"
  if [ -n "$PINNED_SHA" ]; then
    EXPECTED_SHA="$PINNED_SHA"
  else
    retry curl -fsSL -o "$TMP_DIR/payload.sha256" "${{DL_URL}}.sha256"
    EXPECTED_SHA=$(awk '{{print $1; exit}}' "$TMP_DIR/payload.sha256" | tr 'A-F' 'a-f')
  fi
  if ! printf '%s' "$EXPECTED_SHA" | grep -Eq '^[0-9a-f]{{64}}$'; then
    log 'invalid or missing SHA-256 checksum for cua-spacesd download'; exit 1
  fi
  if ! printf '%s  %s\n' "$EXPECTED_SHA" "$TMP_DIR/payload" | sha256sum -c -; then
    log 'SHA-256 verification failed for cua-spacesd download'; exit 1
  fi
  mkdir -p /usr/local/bin
  if case "$DL_URL" in *.tar.gz|*.tgz) true ;; *) gzip -t "$TMP_DIR/payload" 2>/dev/null ;; esac; then
    tar -xzf "$TMP_DIR/payload" -C "$TMP_DIR" cua-spacesd 2>/dev/null || tar -xzf "$TMP_DIR/payload" -C "$TMP_DIR"
    EXTRACTED="$TMP_DIR/cua-spacesd"
    [ -f "$EXTRACTED" ] || EXTRACTED=$(find "$TMP_DIR" -name cua-spacesd -type f | head -n 1)
    [ -n "$EXTRACTED" ] && [ -f "$EXTRACTED" ] || {{ log 'cua-spacesd binary not found in archive'; exit 1; }}
    install -m 0755 "$EXTRACTED" /usr/local/bin/cua-spacesd
  else
    install -m 0755 "$TMP_DIR/payload" /usr/local/bin/cua-spacesd
  fi
  rm -rf "$TMP_DIR"; trap - EXIT
fi
if ! /usr/local/bin/cua-spacesd --version >/dev/null 2>&1; then
  if command -v ldd >/dev/null 2>&1 && ldd /usr/local/bin/cua-spacesd 2>/dev/null | grep -q 'not found'; then
    log 'installing X11/xkb libs'
    if command -v apt-get >/dev/null 2>&1; then
      retry apt-get update -q
      retry apt-get install -y -q --no-install-recommends libx11-6 libxext6 libxi6 libxtst6 libxkbcommon0
    elif command -v dnf >/dev/null 2>&1; then
      retry dnf install -y libX11 libXext libXi libXtst libxkbcommon
    fi
  fi
  /usr/local/bin/cua-spacesd --version >/dev/null
fi
{host_net_snippet}cat > /usr/local/sbin/cua-spacesd-start <<'CUA_SPACESD_START'
{starter}CUA_SPACESD_START
chmod 0755 /usr/local/sbin/cua-spacesd-start
cat > /etc/systemd/system/cua-spacesd.service <<'CUA_SPACESD_UNIT'
{unit}CUA_SPACESD_UNIT
systemctl daemon-reload
systemctl enable --now cua-spacesd.service
log 'done'
"#,
        version_q = sh_quote(version),
        pinned_sha_q = sh_quote(&pinned_sha),
        starter = native_spacesd_start_script(),
        unit = native_spacesd_service(),
    ));
    s
}

/// `#cloud-config` user data for Linux Direct VM (`--runtime native`):
/// runs `cua-spacesd join` directly under systemd without Docker, checks
/// pre-installed `cua-spacesd` first (else downloads from
/// `spacesd_download_url` or versioned GitHub Releases with SHA-256),
/// blocks `100.100.100.200` on host `OUTPUT`, installs `cua-expire`, and
/// auto-detects an existing desktop session or starts headless immediately.
pub fn linux_native_cloud_init(boot: &VmBoot<'_>, spacesd_download_url: Option<&str>) -> String {
    let b64_file = |path: &str, perm: &str, content: &str| {
        format!(
            "- path: {path}\n  permissions: '{perm}'\n  owner: root:root\n  encoding: b64\n  content: {}\n",
            b64(content)
        )
    };
    let push_plain = |y: &mut String, path: &str, perm: &str, content: &str| {
        y.push_str(&format!(
            "- path: {path}\n  permissions: '{perm}'\n  owner: root:root\n  content: |\n"
        ));
        for line in content.strip_suffix('\n').unwrap_or(content).split('\n') {
            if !line.is_empty() {
                y.push_str("   ");
                y.push_str(line);
            }
            y.push('\n');
        }
    };
    let mut y = String::from("#cloud-config\nssh_pwauth: false\nwrite_files:\n");
    y.push_str(&b64_file(
        "/etc/cua/relay/machine-token",
        "0600",
        &boot.join.machine_token,
    ));
    y.push_str(&b64_file(
        "/etc/cua/relay/machine-id",
        "0600",
        &format!("{}\n", boot.join.machine_id),
    ));
    if !boot.join.jwks_json.trim().is_empty() {
        y.push_str(&b64_file(
            "/etc/cua/relay/jwks.json",
            "0600",
            &boot.join.jwks_json,
        ));
    }
    y.push_str(&b64_file(
        "/etc/cua/relay/policy.json",
        "0600",
        &boot.join.policy_json(),
    ));
    y.push_str(&b64_file(
        "/etc/cua/spacesd.env",
        "0600",
        &native_spacesd_env(boot),
    ));
    y.push_str(&b64_file(
        "/etc/cua/expires",
        "0644",
        &format!("{}\n", boot.expires),
    ));
    push_plain(&mut y, "/usr/local/bin/cua-expire", "0755", EXPIRE_SCRIPT);
    push_plain(
        &mut y,
        "/etc/systemd/system/cua-expire.service",
        "0644",
        EXPIRE_SERVICE,
    );
    push_plain(
        &mut y,
        "/etc/systemd/system/cua-expire.timer",
        "0644",
        EXPIRE_TIMER,
    );
    push_plain(
        &mut y,
        "/usr/local/sbin/cua-first-boot",
        "0700",
        &native_first_boot_script(boot, spacesd_download_url),
    );
    y.push_str(
        "runcmd:\n\
         \x20 - [systemctl, daemon-reload]\n\
         \x20 - [systemctl, enable, --now, cua-expire.timer]\n\
         \x20 - [sh, -c, '/usr/local/sbin/cua-first-boot 2>&1 | tee /var/log/cua-first-boot.log']\n",
    );
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join() -> Join {
        Join {
            relay_url: "https://relay.example".into(),
            machine_id: "cloud-0123456789abcdef".into(),
            machine_token: "cmt_secret".into(),
            jwks_json: r#"{"keys":[]}"#.into(),
            owner: "acct".into(),
            owner_email: "a@example.com".into(),
        }
    }

    pub(crate) fn decode(y: &str, path: &str) -> String {
        let at = y.find(&format!("path: {path}\n")).expect(path);
        let rest = &y[at..];
        let c = rest.find("content: ").unwrap() + "content: ".len();
        if let Some(after_pipe) = rest[c..].strip_prefix("|\n") {
            let mut out = String::new();
            let mut indent: Option<usize> = None;
            for line in after_pipe.split('\n') {
                if line.is_empty() {
                    out.push('\n');
                    continue;
                }
                let spaces = line.bytes().take_while(|b| *b == b' ').count();
                let ind = *indent.get_or_insert(spaces);
                if spaces < ind {
                    break;
                }
                out.push_str(&line[ind..]);
                out.push('\n');
            }
            while out.ends_with("\n\n") {
                out.pop();
            }
            return out;
        }
        let end = rest[c..].find('\n').unwrap();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(&rest[c..c + end])
                .unwrap(),
        )
        .unwrap()
    }

    fn extract_heredoc(script: &str, marker: &str) -> String {
        let start_tag = format!("<<'{marker}'\n");
        let start = script.find(&start_tag).expect(marker) + start_tag.len();
        let end_tag = format!("\n{marker}\n");
        let end = script[start..].find(&end_tag).expect(marker);
        format!("{}\n", &script[start..start + end])
    }

    #[test]
    fn the_user_data_runs_the_image_joined_to_the_relay_and_ends_itself() {
        let j = join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".to_string(), "envtok".to_string())]);
        let y = cloud_init(&VmBoot {
            join: &j,
            image: "ghcr.io/trycua/linux@sha256:abc",
            env: &env,
            expires: 1_900_000_000,
            ttl_secs: 8 * 3600,
            shm_mb: 2048,
            provider: "aws",
            net_guard: true,
            share_slots: true,
        });
        assert!(y.starts_with("#cloud-config\n"));
        // Secrets never appear in clear text.
        assert!(!y.contains("cmt_secret") && !y.contains("envtok"));
        assert_eq!(decode(&y, "/etc/cua/relay/machine-token"), "cmt_secret");
        assert_eq!(
            decode(&y, "/etc/cua/relay/machine-id").trim(),
            "cloud-0123456789abcdef"
        );
        let policy: serde_json::Value =
            serde_json::from_str(&decode(&y, "/etc/cua/relay/policy.json")).unwrap();
        assert_eq!(policy["owner"], "acct");
        let envf = decode(&y, "/etc/cua/sandbox.env");
        assert!(envf.contains("CUA_SPACESD_ARGS=join\n"));
        assert!(envf.contains("CUA_GUESTD_ARGS=join\n"));
        assert!(envf.contains("CUA_ENV_TOKEN=envtok\n"));
        assert!(envf.contains("CUA_RELAY_TOKEN_FILE=/run/cua-relay/machine-token\n"));
        assert!(envf.contains("CUA_ENV_RELAY_URL=https://relay.example\n"));
        // Share slots: published by the container, served only while shared.
        assert!(envf.contains("CUA_SHARE_SLOTS=26500-26515\n"));
        assert_eq!(decode(&y, "/etc/cua/expires").trim(), "1900000000");
        let script = decode(&y, "/usr/local/sbin/cua-first-boot");
        assert!(script.contains("-p 26500-26515:26500-26515"));
        assert!(script.contains("shutdown -h +480"), "{script}");
        assert!(script.contains("docker run -d --name cua-sandbox --restart unless-stopped"));
        assert!(script.contains("'ghcr.io/trycua/linux@sha256:abc'"));
        assert!(script.contains("-v /etc/cua/relay:/run/cua-relay:ro"));
        assert!(script.contains("/etc/docker/daemon.json"), "{script}");
        // The user data (with the machine token) is not readable from the
        // sandbox: the network guard is installed before the container runs.
        let guard = script.find("cat > /usr/local/sbin/cua-host-net").unwrap();
        let run = script.find("docker run -d").unwrap();
        assert!(guard < run, "{script}");
        assert!(script.contains("systemctl enable --now cua-host-net.service"));
        assert!(script.contains("PLATFORM_V4=\"169.254.169.254/32 169.254.170.2/32"));
        assert!(!y.contains("docker.service.d/cua-metadata.conf"));
        assert!(script.contains("shred -u /etc/cua/sandbox.env"));
        assert!(y.contains("enable, --now, cua-expire.timer"));
        assert!(y.len() < 16 * 1024, "{}", y.len());
    }

    #[test]
    fn without_the_experiments_the_machine_boots_as_it_always_did() {
        let j = join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".to_string(), "envtok".to_string())]);
        let y = cloud_init(&VmBoot {
            join: &j,
            image: "ghcr.io/trycua/linux@sha256:abc",
            env: &env,
            expires: 1_900_000_000,
            ttl_secs: 8 * 3600,
            shm_mb: 2048,
            provider: "aws",
            net_guard: false,
            share_slots: false,
        });
        // The old Docker drop-in keeps the sandbox from the metadata service,
        // DNS excepted; there is no network guard and no published slots.
        let rules = decode(&y, "/etc/systemd/system/docker.service.d/cua-metadata.conf");
        let drop = rules.find("-j DROP").unwrap();
        let dns = rules.find("--dport 53 -j RETURN").unwrap();
        assert!(dns > drop, "{rules}");
        assert!(rules.contains("-d 100.100.100.200 -j DROP"), "{rules}");
        let script = decode(&y, "/usr/local/sbin/cua-first-boot");
        assert!(!script.contains("cua-host-net"), "{script}");
        assert!(!script.contains("-p 26500-26515"), "{script}");
        assert!(!decode(&y, "/etc/cua/sandbox.env").contains("CUA_SHARE_SLOTS"));
    }

    #[test]
    fn no_ttl_means_no_backstop() {
        let j = join();
        let env = BTreeMap::new();
        let y = cloud_init(&VmBoot {
            join: &j,
            image: "x'y",
            env: &env,
            expires: 0,
            ttl_secs: 0,
            shm_mb: 0,
            provider: "gcp",
            net_guard: true,
            share_slots: false,
        });
        let script = decode(&y, "/usr/local/sbin/cua-first-boot");
        assert!(!script.contains("shutdown -h +"));
        assert!(script.contains("'x'\\''y'"), "{script}");
        assert!(script.contains("--shm-size 64m"));
    }

    #[test]
    fn static_relay_empty_jwks_omits_jwks_file_and_env() {
        let j = Join {
            relay_url: "https://relay.selfhosted.example".into(),
            machine_id: "cloud-0123456789abcdef".into(),
            machine_token: "static_secret_tok".into(),
            jwks_json: String::new(),
            owner: String::new(),
            owner_email: String::new(),
        };
        let env = BTreeMap::from([("CUA_ENV_TOKEN".to_string(), "envtok".to_string())]);
        let y = cloud_init(&VmBoot {
            join: &j,
            image: "ghcr.io/trycua/linux@sha256:abc",
            env: &env,
            expires: 0,
            ttl_secs: 0,
            shm_mb: 512,
            provider: "aws",
            net_guard: true,
            share_slots: false,
        });
        assert!(!y.contains("path: /etc/cua/relay/jwks.json"), "{y}");
        let sb_env = decode(&y, "/etc/cua/sandbox.env");
        assert!(!sb_env.contains("CUA_RELAY_JWKS="), "{sb_env}");
        assert!(sb_env.contains("CUA_ENV_RELAY_URL=https://relay.selfhosted.example"));
        assert_eq!(
            decode(&y, "/etc/cua/relay/machine-token"),
            "static_secret_tok"
        );
        let policy: serde_json::Value =
            serde_json::from_str(&decode(&y, "/etc/cua/relay/policy.json")).unwrap();
        assert!(policy.get("owner").is_none());
        assert_eq!(policy["sharing"], true);
    }

    #[test]
    fn linux_native_cloud_init_skips_docker_checks_preinstalled_and_validates_scripts() {
        let j = join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".to_string(), "envtok".to_string())]);
        let y = linux_native_cloud_init(
            &VmBoot {
                join: &j,
                image: "ghcr.io/trycua/linux:24.04",
                env: &env,
                expires: 1_900_000_000,
                ttl_secs: 8 * 3600,
                shm_mb: 2048,
                provider: "aliyun-ecs",
                net_guard: true,
                share_slots: false,
            },
            None,
        );
        assert!(y.starts_with("#cloud-config\n"));
        assert!(y.contains("ssh_pwauth: false"));
        assert!(!y.contains("cmt_secret") && !y.contains("envtok"));
        assert!(y.len() < 16 * 1024, "UserData too large: {}", y.len());

        // No Docker installation, daemon config, or container launch anywhere.
        assert!(!y.contains("docker.service.d/cua-metadata.conf"));
        let first_boot = decode(&y, "/usr/local/sbin/cua-first-boot");
        for forbidden in [
            "docker.io",
            "docker pull",
            "docker run",
            "docker exec",
            "/etc/docker/daemon.json",
            "apt-get install -y -q xorg",
            "apt-get install -y -q lightdm",
            "dnf install -y lightdm",
            "xfce4",
            "xvfb",
            "/releases/latest",
        ] {
            assert!(
                !first_boot.contains(forbidden),
                "found {forbidden:?} in:\n{first_boot}"
            );
        }

        // Checks pre-installed binary before downloading default versioned GitHub Releases tarball.
        let pre_pos = first_boot.find("/usr/local/bin/cua-spacesd").unwrap();
        let dl_pos = first_boot.find("releases/download/cua-spacesd-v").unwrap();
        assert!(pre_pos < dl_pos, "{first_boot}");
        let expected_ver = cua_host::driver::SPACESD_VERSION.trim();
        assert!(
            first_boot.contains(&format!("cua-spacesd-v{expected_ver}/cua-spacesd-linux-")),
            "{first_boot}"
        );
        assert!(first_boot.contains("sha256sum"), "{first_boot}");

        // Host metadata firewall (100.100.100.200) enabled before cua-spacesd.service.
        let fw_pos = first_boot
            .find("systemctl enable --now cua-host-net.service")
            .unwrap();
        let svc_pos = first_boot
            .find("systemctl enable --now cua-spacesd.service")
            .unwrap();
        assert!(fw_pos < svc_pos, "{first_boot}");
        assert!(first_boot.contains("shutdown -h +480"), "{first_boot}");

        let host_net = extract_heredoc(&first_boot, "CUA_HOST_NET");
        assert!(host_net.contains("100.100.100.200/32"), "{host_net}");
        let host_net_unit = extract_heredoc(&first_boot, "CUA_HOST_NET_UNIT");
        assert!(host_net_unit.contains("Before=cua-spacesd.service"));

        // TTL timer + expiry file.
        assert_eq!(decode(&y, "/etc/cua/expires").trim(), "1900000000");
        assert!(y.contains("enable, --now, cua-expire.timer"));

        // Systemd cua-spacesd.service & starter wrapper.
        let unit = extract_heredoc(&first_boot, "CUA_SPACESD_UNIT");
        assert!(
            !unit.contains("EnvironmentFile="),
            "systemd EnvironmentFile= corrupts \\/quotes/spaces:\n{unit}"
        );
        for want in [
            "After=network-online.target cua-host-net.service display-manager.service gdm.service lightdm.service sddm.service cua-desktop.service",
            "ExecStart=/usr/local/sbin/cua-spacesd-start",
            "Restart=always",
            "OOMScoreAdjust=-1000",
            "MemoryMin=64M",
            "LimitNOFILE=1048576",
        ] {
            assert!(unit.contains(want), "missing {want:?} in:\n{unit}");
        }
        let starter = extract_heredoc(&first_boot, "CUA_SPACESD_START");
        assert!(starter.contains("/etc/cua/spacesd.env"), "{starter}");
        assert!(starter.contains("while IFS= read -r"), "{starter}");
        assert!(
            starter.contains("/run/cua-desktop/desktop.env"),
            "{starter}"
        );
        assert!(starter.contains("/run/user/*/wayland-*"), "{starter}");
        assert!(starter.contains("/tmp/.X11-unix/X*"), "{starter}");
        assert!(starter.contains("XAUTHORITY"), "{starter}");
        assert!(starter.contains("CUA_ENV_NO_DESKTOP=true"), "{starter}");
        assert!(starter.contains("join"), "{starter}");

        // Account Relay Mode files & env.
        assert!(y.contains("path: /etc/cua/relay/jwks.json"));
        let envf = decode(&y, "/etc/cua/spacesd.env");
        assert!(envf.contains("CUA_ENV_RELAY_URL=https://relay.example\n"));
        assert!(envf.contains("CUA_RELAY_TOKEN_FILE=/etc/cua/relay/machine-token\n"));
        assert!(envf.contains("CUA_ENV_MACHINE_ID_FILE=/etc/cua/relay/machine-id\n"));
        assert!(envf.contains("CUA_HOST_POLICY=/etc/cua/relay/policy.json\n"));
        assert!(envf.contains("CUA_RELAY_JWKS=/etc/cua/relay/jwks.json\n"));
        let policy: serde_json::Value =
            serde_json::from_str(&decode(&y, "/etc/cua/relay/policy.json")).unwrap();
        assert_eq!(policy["owner"], "acct");

        // All generated shell scripts pass `sh -n`.
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in [
            ("first_boot.sh", first_boot),
            ("starter.sh", starter),
            ("host_net.sh", host_net),
            ("expire.sh", decode(&y, "/usr/local/bin/cua-expire")),
        ] {
            let p = dir.path().join(name);
            std::fs::write(&p, &content).unwrap();
            let st = std::process::Command::new("sh")
                .arg("-n")
                .arg(&p)
                .status()
                .unwrap();
            assert!(st.success(), "{name} failed sh -n");
        }
    }

    #[test]
    fn linux_native_cloud_init_supports_custom_mirror_static_relay_and_no_ttl() {
        let j = Join {
            relay_url: "https://relay.internal".into(),
            machine_id: "cloud-fedcba9876543210".into(),
            machine_token: "static_relay_secret".into(),
            jwks_json: String::new(),
            owner: String::new(),
            owner_email: String::new(),
        };
        let env = BTreeMap::from([("CUA_ENV_TOKEN".to_string(), "envtok_static".to_string())]);
        let hex = "ab".repeat(32);
        let mirror =
            format!("https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz#sha256={hex}");
        let y = linux_native_cloud_init(
            &VmBoot {
                join: &j,
                image: "ghcr.io/trycua/linux:24.04-slim",
                env: &env,
                expires: 0,
                ttl_secs: 0,
                shm_mb: 512,
                provider: "aliyun-ecs",
                net_guard: true,
                share_slots: false,
            },
            Some(&mirror),
        );
        assert!(!y.contains("static_relay_secret") && !y.contains("envtok_static"));
        assert!(!y.contains("path: /etc/cua/relay/jwks.json"));
        let envf = decode(&y, "/etc/cua/spacesd.env");
        assert!(!envf.contains("CUA_RELAY_JWKS="), "{envf}");
        assert!(envf.contains("CUA_ENV_TOKEN=envtok_static\n"), "{envf}");
        assert!(
            envf.contains("CUA_ENV_RELAY_URL=https://relay.internal\n"),
            "{envf}"
        );
        let policy: serde_json::Value =
            serde_json::from_str(&decode(&y, "/etc/cua/relay/policy.json")).unwrap();
        assert!(policy.get("owner").is_none());

        let first_boot = decode(&y, "/usr/local/sbin/cua-first-boot");
        assert!(!first_boot.contains("shutdown -h +"));
        assert!(
            first_boot.contains("https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz"),
            "{first_boot}"
        );
        assert!(first_boot.contains(&hex), "{first_boot}");
        assert!(!first_boot.contains("github.com"), "{first_boot}");
    }

    #[test]
    fn linux_native_cloud_init_stays_well_below_16k_under_realistic_payloads() {
        let realistic_env = BTreeMap::from([
            (
                "CUA_ENV_TOKEN".to_string(),
                "0123456789abcdef0123456789abcdef".to_string(),
            ),
            ("APP_ENV".to_string(), "production".to_string()),
            (
                "API_BASE".to_string(),
                "https://api.example.com/v1".to_string(),
            ),
        ]);
        let hex = "0123456789abcdef".repeat(4);
        let mirror =
            format!("https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz#sha256={hex}");

        let acct_join = Join {
            relay_url: "https://relay.example.com".into(),
            machine_id: "cloud-0123456789abcdef".into(),
            machine_token: "cmt_0123456789abcdef0123456789abcdef01234567".into(),
            jwks_json: r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1","alg":"EdDSA","use":"sig"}]}"#.into(),
            owner: "acct-user-0123456789".into(),
            owner_email: "ada@example.com".into(),
        };
        let acct_ud = linux_native_cloud_init(
            &VmBoot {
                join: &acct_join,
                image: "ubuntu:24.04",
                env: &realistic_env,
                expires: 1_900_000_000,
                ttl_secs: 3600,
                shm_mb: 2048,
                provider: "aliyun-ecs",
                net_guard: true,
                share_slots: true,
            },
            Some(&mirror),
        );
        assert!(
            acct_ud.len() < 16 * 1024,
            "Account Relay UserData {} >= 16384",
            acct_ud.len()
        );
        assert!(
            acct_ud.len() < 14_000,
            "Account Relay UserData {} >= 14000 target",
            acct_ud.len()
        );

        let static_join = Join {
            relay_url: "https://relay.selfhosted.example.com".into(),
            machine_id: "cloud-fedcba9876543210".into(),
            machine_token: "static_tok_0123456789abcdef0123456789abcdef01".into(),
            jwks_json: String::new(),
            owner: String::new(),
            owner_email: String::new(),
        };
        let static_ud = linux_native_cloud_init(
            &VmBoot {
                join: &static_join,
                image: "ubuntu:24.04",
                env: &realistic_env,
                expires: 1_900_000_000,
                ttl_secs: 3600,
                shm_mb: 2048,
                provider: "aliyun-ecs",
                net_guard: true,
                share_slots: true,
            },
            Some(&mirror),
        );
        assert!(
            static_ud.len() < 16 * 1024,
            "Static Relay UserData {} >= 16384",
            static_ud.len()
        );
        assert!(
            static_ud.len() < 14_000,
            "Static Relay UserData {} >= 14000 target",
            static_ud.len()
        );

        // If PyYAML is installed, verify cloud-init YAML parses cleanly and decodes
        // `/usr/local/sbin/cua-first-boot` verbatim.
        if let Ok(mut child) = std::process::Command::new("python3")
            .args([
                "-c",
                "import sys, yaml; d = yaml.safe_load(sys.stdin.read()); assert isinstance(d['write_files'], list); fb = [f for f in d['write_files'] if f['path'] == '/usr/local/sbin/cua-first-boot'][0]; sys.stdout.write(fb['content'])",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            use std::io::Write as _;
            child.stdin.as_mut().unwrap().write_all(acct_ud.as_bytes()).unwrap();
            let out = child.wait_with_output().unwrap();
            if out.status.success() {
                let expected = native_first_boot_script(
                    &VmBoot {
                        join: &acct_join,
                        image: "ubuntu:24.04",
                        env: &realistic_env,
                        expires: 1_900_000_000,
                        ttl_secs: 3600,
                        shm_mb: 2048,
                        provider: "aliyun-ecs",
                        net_guard: true,
                        share_slots: true,
                    },
                    Some(&mirror),
                );
                assert_eq!(String::from_utf8(out.stdout).unwrap(), expected);
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                assert!(
                    stderr.contains("No module named 'yaml'"),
                    "YAML validation failed: {stderr}"
                );
            }
        }
    }

    #[test]
    fn linux_native_spacesd_env_loaded_literally_by_sh_preserves_values_and_relay_vars() {
        let j = join();
        let env = BTreeMap::from([
            ("CUA_ENV_RELAY_A".to_string(), "oops\\".to_string()),
            ("CUA_RELAY_A".to_string(), "oops2\\".to_string()),
            ("QUOTES_TEST".to_string(), "\"quoted\"".to_string()),
            ("CR_TEST".to_string(), "foo\rbar".to_string()),
            ("TRAILING_SPACES".to_string(), "val   ".to_string()),
            ("DOLLAR_SIGN".to_string(), "$PATH/${HOME}".to_string()),
        ]);
        let y = linux_native_cloud_init(
            &VmBoot {
                join: &j,
                image: "ubuntu:24.04",
                env: &env,
                expires: 1_900_000_000,
                ttl_secs: 3600,
                shm_mb: 2048,
                provider: "aliyun-ecs",
                net_guard: true,
                share_slots: false,
            },
            None,
        );
        assert!(y.len() < 14_000, "UserData too large: {}", y.len());

        let envf = decode(&y, "/etc/cua/spacesd.env");
        assert!(!envf.contains('\r'), "CR leaked into spacesd.env: {envf:?}");

        let first_boot = decode(&y, "/usr/local/sbin/cua-first-boot");
        let unit = extract_heredoc(&first_boot, "CUA_SPACESD_UNIT");
        assert!(
            !unit.contains("EnvironmentFile="),
            "systemd EnvironmentFile= must not be used (mangles \\, quotes, trailing spaces):\n{unit}"
        );

        let starter = extract_heredoc(&first_boot, "CUA_SPACESD_START");
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join("spacesd.env");
        std::fs::write(&env_path, &envf).unwrap();
        let fake_bin = dir.path().join("cua-spacesd");
        std::fs::write(
            &fake_bin,
            "#!/bin/sh\npython3 -c 'import json, os, sys; print(json.dumps({k: os.environ.get(k) for k in sys.argv[1:]}))' \"$@\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let rewritten_starter = starter
            .replace("/etc/cua/spacesd.env", &env_path.display().to_string())
            .replace("/usr/local/bin/cua-spacesd", &fake_bin.display().to_string())
            .replace(
                "exec \"$BIN\" join",
                "exec \"$BIN\" CUA_ENV_RELAY_A CUA_ENV_RELAY_URL CUA_RELAY_A CUA_RELAY_JWKS QUOTES_TEST CR_TEST TRAILING_SPACES DOLLAR_SIGN CUA_RELAY_TOKEN_FILE CUA_ENV_MACHINE_ID_FILE CUA_HOST_POLICY",
            );
        let starter_path = dir.path().join("starter.sh");
        std::fs::write(&starter_path, &rewritten_starter).unwrap();

        let out = std::process::Command::new("sh")
            .arg(&starter_path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "starter failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(got["CUA_ENV_RELAY_A"], "oops\\");
        assert_eq!(got["CUA_ENV_RELAY_URL"], "https://relay.example");
        assert_eq!(got["CUA_RELAY_A"], "oops2\\");
        assert_eq!(got["CUA_RELAY_JWKS"], "/etc/cua/relay/jwks.json");
        assert_eq!(got["QUOTES_TEST"], "\"quoted\"");
        assert_eq!(got["CR_TEST"], "foo bar");
        assert_eq!(got["TRAILING_SPACES"], "val   ");
        assert_eq!(got["DOLLAR_SIGN"], "$PATH/${HOME}");
        assert_eq!(got["CUA_RELAY_TOKEN_FILE"], "/etc/cua/relay/machine-token");
        assert_eq!(got["CUA_ENV_MACHINE_ID_FILE"], "/etc/cua/relay/machine-id");
        assert_eq!(got["CUA_HOST_POLICY"], "/etc/cua/relay/policy.json");

        // Also test `dash` if installed on the host.
        if let Ok(dash_out) = std::process::Command::new("dash")
            .arg(&starter_path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
        {
            assert!(
                dash_out.status.success(),
                "dash starter failed: {}",
                String::from_utf8_lossy(&dash_out.stderr)
            );
            let dash_got: serde_json::Value = serde_json::from_slice(&dash_out.stdout).unwrap();
            assert_eq!(dash_got, got);
        }

        // Invalid env keys are rejected by `validate_env_keys` and never emitted into `spacesd.env`.
        for bad_key in [
            "", "#COMMENT", "A=B", "A\nB", "A\rB", "A\0B", "BAD-KEY", "1BAD",
        ] {
            let bad_map = BTreeMap::from([(bad_key.to_string(), "val".to_string())]);
            assert!(
                validate_env_keys(&bad_map, true).is_err(),
                "expected invalid key error for {bad_key:?}"
            );
            let bad_envf = native_spacesd_env(&VmBoot {
                join: &j,
                image: "ubuntu:24.04",
                env: &bad_map,
                expires: 0,
                ttl_secs: 0,
                shm_mb: 512,
                provider: "aliyun-ecs",
                net_guard: true,
                share_slots: false,
            });
            assert!(
                !bad_envf.contains("=val\n"),
                "invalid key {bad_key:?} leaked into spacesd.env:\n{bad_envf}"
            );
            assert!(bad_envf.contains("CUA_ENV_RELAY_URL=https://relay.example\n"));
        }
    }

    #[test]
    fn native_first_boot_safe_dl_url_strips_query_before_userinfo_and_cleans_static_env() {
        let j = Join {
            relay_url: "https://relay.internal".into(),
            machine_id: "cloud-fedcba9876543210".into(),
            machine_token: "static_relay_secret".into(),
            jwks_json: String::new(),
            owner: String::new(),
            owner_email: String::new(),
        };
        let injected_env = BTreeMap::from([
            ("CUA_ENV_TOKEN".to_string(), "envtok".to_string()),
            (
                "CUA_RELAY_JWKS".to_string(),
                "/tmp/evil-jwks.json".to_string(),
            ),
            ("CUA_SHARE_SLOTS".to_string(), "1-2".to_string()),
        ]);
        let boot = VmBoot {
            join: &j,
            image: "ubuntu:24.04",
            env: &injected_env,
            expires: 0,
            ttl_secs: 0,
            shm_mb: 512,
            provider: "aliyun-ecs",
            net_guard: true,
            share_slots: false,
        };
        let envf = native_spacesd_env(&boot);
        assert!(
            !envf.contains("CUA_RELAY_JWKS="),
            "Static mode must strip CUA_RELAY_JWKS: {envf}"
        );
        assert!(
            !envf.contains("CUA_SHARE_SLOTS="),
            "share_slots=false must strip CUA_SHARE_SLOTS: {envf}"
        );

        let script = native_first_boot_script(&boot, Some("https://mirror.example.com/bin"));
        let safe_line = script
            .lines()
            .find(|l| l.trim_start().starts_with("SAFE_DL_URL="))
            .expect("SAFE_DL_URL line")
            .trim();
        let hex = "0123456789abcdef".repeat(4);
        for (dl_url, expected) in [
            (
                format!(
                    "https://mirror.example.com?user=ada@example.com&sig=AbCd9988#sha256={hex}"
                ),
                "https://mirror.example.com".to_string(),
            ),
            (
                format!("https://u:p@mirror.example.com/bin?sig=Secret#sha256={hex}"),
                "https://<redacted>@mirror.example.com/bin".to_string(),
            ),
            (
                "https://mirror.example.com/@org/cua-spacesd.tar.gz?sig=Secret".to_string(),
                "https://mirror.example.com/@org/cua-spacesd.tar.gz".to_string(),
            ),
            (
                format!(
                    "https://ada@org:secret@mirror.example.com/@org/bin?sig=Secret#sha256={hex}"
                ),
                "https://<redacted>@mirror.example.com/@org/bin".to_string(),
            ),
            (
                "https://ada@org:secret@mirror.example.com".to_string(),
                "https://<redacted>@mirror.example.com".to_string(),
            ),
        ] {
            let probe = format!(
                "DL_URL={}\n{safe_line}\nprintf '%s' \"$SAFE_DL_URL\"\n",
                sh_quote(&dl_url)
            );
            for shell in ["sh", "dash"] {
                let out = std::process::Command::new(shell)
                    .arg("-c")
                    .arg(&probe)
                    .output()
                    .expect(shell);
                assert!(out.status.success(), "{shell} failed for {dl_url}");
                let got = String::from_utf8(out.stdout).unwrap();
                assert_eq!(got, expected, "under {shell} for {dl_url}");
            }
        }
    }

    #[test]
    fn linux_native_first_boot_installs_libxkbcommon_and_uses_true_for_no_desktop() {
        let j = join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".to_string(), "envtok".to_string())]);
        let boot = VmBoot {
            join: &j,
            image: "ghcr.io/trycua/linux:24.04",
            env: &env,
            expires: 0,
            ttl_secs: 0,
            shm_mb: 512,
            provider: "aliyun-ecs",
            net_guard: true,
            share_slots: false,
        };
        let first_boot = native_first_boot_script(&boot, None);
        assert!(
            first_boot.contains("libx11-6 libxext6 libxi6 libxtst6 libxkbcommon0"),
            "{first_boot}"
        );
        assert!(
            first_boot.contains("libX11 libXext libXi libXtst libxkbcommon"),
            "{first_boot}"
        );
        let starter = native_spacesd_start_script();
        assert!(starter.contains("CUA_ENV_NO_DESKTOP=true"), "{starter}");
        assert!(!starter.contains("CUA_ENV_NO_DESKTOP=1"), "{starter}");
    }
}
