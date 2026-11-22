// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! First-boot `#cloud-config` generator for Linux Direct VM Sandboxes
//! (`--runtime native`): runs `cua-spacesd join` directly under systemd
//! without Docker, checks pre-installed `cua-spacesd` first (else downloads
//! from a Spacesd Mirror URL or GitHub Releases with SHA-256 verification),
//! blocks cloud metadata endpoints on host `OUTPUT`, installs `cua-expire`,
//! and attaches to an existing desktop session or starts headless immediately.

use std::collections::BTreeMap;

use super::{
    EXPIRE_SCRIPT, EXPIRE_SERVICE, EXPIRE_TIMER, VmBoot, is_valid_env_key, push_b64_file,
    push_relay_files, sh_quote,
};

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

    let (resolve_url, safe_dl_url) = match custom_url {
        Some(u) => {
            let expanded = u.replace("{version}", version);
            let resolved = match expanded.split_once('?') {
                Some((path, query)) if path.ends_with('/') => {
                    format!("{path}cua-spacesd-linux-{{arch}}.tar.gz?{query}")
                }
                None if expanded.ends_with('/') => {
                    format!("{expanded}cua-spacesd-linux-{{arch}}.tar.gz")
                }
                _ => expanded,
            };
            let safe = cua_sandbox_core::byoc::redact_url(&resolved);
            (
                format!(
                    "DL_URL={}\n\
                     DL_URL=$(printf '%s' \"$DL_URL\" | sed -e \"s/{{arch}}/$ARCH/g\")\n",
                    sh_quote(&resolved)
                ),
                sh_quote(&safe),
            )
        }
        None => (
            format!(
                "DL_URL=\"https://github.com/{repo}/releases/download/cua-spacesd-v{version}/cua-spacesd-linux-${{ARCH}}.tar.gz\"\n"
            ),
            format!(
                "\"https://github.com/{repo}/releases/download/cua-spacesd-v{version}/cua-spacesd-linux-${{ARCH}}.tar.gz\""
            ),
        ),
    };

    let host_net_snippet = crate::hostnet::native_install_snippet(&crate::hostnet::HostNet {
        provider: boot.provider,
        extra_cidrs: &[],
    });

    s.push_str(&format!(
        r#"PINNED_SHA={pinned_sha_q}
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
  SAFE_DL_URL={safe_dl_url}
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
    push_relay_files(&mut y, "", boot.join);
    push_b64_file(
        &mut y,
        "",
        "/etc/cua/spacesd.env",
        "0600",
        &native_spacesd_env(boot),
    );
    push_b64_file(
        &mut y,
        "",
        "/etc/cua/expires",
        "0644",
        &format!("{}\n", boot.expires),
    );
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
    use super::super::tests::{decode, join};
    use super::super::validate_env_keys;
    use super::*;
    use crate::relay::Join;

    fn extract_heredoc(script: &str, marker: &str) -> String {
        let start_tag = format!("<<'{marker}'\n");
        let start = script.find(&start_tag).expect(marker) + start_tag.len();
        let end_tag = format!("\n{marker}\n");
        let end = script[start..].find(&end_tag).expect(marker);
        format!("{}\n", &script[start..start + end])
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
            assert!(!first_boot.contains(forbidden), "found {forbidden:?}");
        }

        let pre_pos = first_boot.find("/usr/local/bin/cua-spacesd").unwrap();
        let dl_pos = first_boot.find("releases/download/cua-spacesd-v").unwrap();
        assert!(pre_pos < dl_pos, "{first_boot}");
        let expected_ver = cua_host::driver::SPACESD_VERSION.trim();
        assert!(first_boot.contains(&format!("cua-spacesd-v{expected_ver}/cua-spacesd-linux-")));
        assert!(first_boot.contains("sha256sum"));

        let fw_pos = first_boot
            .find("systemctl enable --now cua-host-net.service")
            .unwrap();
        let svc_pos = first_boot
            .find("systemctl enable --now cua-spacesd.service")
            .unwrap();
        assert!(fw_pos < svc_pos);
        assert!(first_boot.contains("shutdown -h +480"));

        let host_net = extract_heredoc(&first_boot, "CUA_HOST_NET");
        assert!(host_net.contains("100.100.100.200/32"));
        let host_net_unit = extract_heredoc(&first_boot, "CUA_HOST_NET_UNIT");
        assert!(host_net_unit.contains("Before=cua-spacesd.service"));

        assert_eq!(decode(&y, "/etc/cua/expires").trim(), "1900000000");
        assert!(y.contains("enable, --now, cua-expire.timer"));

        let unit = extract_heredoc(&first_boot, "CUA_SPACESD_UNIT");
        assert!(!unit.contains("EnvironmentFile="));
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
        for want in [
            "/etc/cua/spacesd.env",
            "while IFS= read -r",
            "/run/cua-desktop/desktop.env",
            "/run/user/*/wayland-*",
            "/tmp/.X11-unix/X*",
            "XAUTHORITY",
            "CUA_ENV_NO_DESKTOP=true",
            "join",
        ] {
            assert!(starter.contains(want), "missing {want:?} in:\n{starter}");
        }

        assert!(y.contains("path: /etc/cua/relay/jwks.json"));
        let envf = decode(&y, "/etc/cua/spacesd.env");
        for want in [
            "CUA_ENV_RELAY_URL=https://relay.example\n",
            "CUA_RELAY_TOKEN_FILE=/etc/cua/relay/machine-token\n",
            "CUA_ENV_MACHINE_ID_FILE=/etc/cua/relay/machine-id\n",
            "CUA_HOST_POLICY=/etc/cua/relay/policy.json\n",
            "CUA_RELAY_JWKS=/etc/cua/relay/jwks.json\n",
        ] {
            assert!(envf.contains(want), "missing {want:?} in {envf}");
        }
        let policy: serde_json::Value =
            serde_json::from_str(&decode(&y, "/etc/cua/relay/policy.json")).unwrap();
        assert_eq!(policy["owner"], "acct");

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
        assert!(envf.contains("CUA_ENV_RELAY_URL=https://relay.internal\n"));
        let policy: serde_json::Value =
            serde_json::from_str(&decode(&y, "/etc/cua/relay/policy.json")).unwrap();
        assert!(policy.get("owner").is_none());

        let first_boot = decode(&y, "/usr/local/sbin/cua-first-boot");
        assert!(!first_boot.contains("shutdown -h +"));
        assert!(
            first_boot.contains("https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz")
        );
        assert!(first_boot.contains(&hex) && !first_boot.contains("github.com"));
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
            acct_ud.len() < 14_000,
            "Account Relay UserData {}",
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
            static_ud.len() < 14_000,
            "Static Relay UserData {}",
            static_ud.len()
        );

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
                assert!(stderr.contains("No module named 'yaml'"), "YAML failed: {stderr}");
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
        assert!(!unit.contains("EnvironmentFile="));

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
            "{}",
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

        if let Ok(dash_out) = std::process::Command::new("dash")
            .arg(&starter_path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
        {
            assert!(
                dash_out.status.success(),
                "{}",
                String::from_utf8_lossy(&dash_out.stderr)
            );
            let dash_got: serde_json::Value = serde_json::from_slice(&dash_out.stdout).unwrap();
            assert_eq!(dash_got, got);
        }

        for bad_key in [
            "", "#COMMENT", "A=B", "A\nB", "A\rB", "A\0B", "BAD-KEY", "1BAD",
        ] {
            let bad_map = BTreeMap::from([(bad_key.to_string(), "val".to_string())]);
            assert!(validate_env_keys(&bad_map, true).is_err(), "{bad_key:?}");
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
            assert!(!bad_envf.contains("=val\n"), "leaked {bad_key:?}");
            assert!(bad_envf.contains("CUA_ENV_RELAY_URL=https://relay.example\n"));
        }
    }

    #[test]
    fn native_first_boot_uses_host_redacted_dl_url_and_cleans_static_env() {
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
        assert!(!envf.contains("CUA_RELAY_JWKS=") && !envf.contains("CUA_SHARE_SLOTS="));

        let hex = "0123456789abcdef".repeat(4);
        for (dl_url, expected) in [
            (
                format!(
                    "https://mirror.example.com?user=ada@example.com&sig=AbCd9988#sha256={hex}"
                ),
                "https://mirror.example.com",
            ),
            (
                format!("https://u:p@mirror.example.com/bin?sig=Secret#sha256={hex}"),
                "https://mirror.example.com/bin",
            ),
            (
                "https://mirror.example.com/@org/cua-spacesd.tar.gz?sig=Secret".to_string(),
                "https://mirror.example.com/@org/cua-spacesd.tar.gz",
            ),
            (
                format!(
                    "https://ada@org:secret@mirror.example.com/@org/bin?sig=Secret#sha256={hex}"
                ),
                "<redacted>",
            ),
            (
                "https://ada@org:secret@mirror.example.com".to_string(),
                "<redacted>",
            ),
            (
                "https://mirror.example.com/cua-spacesd/?sig=Secret".to_string(),
                "https://mirror.example.com/cua-spacesd/cua-spacesd-linux-{arch}.tar.gz",
            ),
        ] {
            let script = native_first_boot_script(&boot, Some(&dl_url));
            let safe_line = script
                .lines()
                .find(|l| l.trim_start().starts_with("SAFE_DL_URL="))
                .expect("SAFE_DL_URL line")
                .trim();
            assert!(
                !safe_line.contains("sed"),
                "must not use sed redactor: {safe_line}"
            );
            assert_eq!(
                safe_line,
                format!("SAFE_DL_URL='{}'", expected),
                "for {dl_url}"
            );
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
        assert!(first_boot.contains("libx11-6 libxext6 libxi6 libxtst6 libxkbcommon0"));
        assert!(first_boot.contains("libX11 libXext libXi libXtst libxkbcommon"));
        let starter = native_spacesd_start_script();
        assert!(
            starter.contains("CUA_ENV_NO_DESKTOP=true")
                && !starter.contains("CUA_ENV_NO_DESKTOP=1")
        );
    }
}
