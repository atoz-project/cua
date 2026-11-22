// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! First-boot `#cloud-config` generator for Docker-on-VM cloud sandboxes
//! (and re-exports for Linux and Windows Direct VM bootstraps).
//!
//! Three guardrails end forgotten VMs: first-boot `shutdown -h +<ttl>`,
//! a `cua-expire` systemd timer checking `/etc/cua/expires`, and the
//! `cua-expires` cloud tag read by the sweeper.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::relay::Join;

mod linux_native;
pub mod win;

pub use linux_native::*;
pub use win::{WindowsVmBoot, windows_user_data};

/// Resolves an optional custom `cua-spacesd` mirror URL into
/// `(resolved_url_without_fragment, optional_sha256_hex)`.
///
/// Expands `{version}` (and `{arch}` when `arch_replacement` is `Some`),
/// splits off `#sha256=<hex>`, and appends `dir_asset_name` when the path
/// before `?` ends with `/`.
pub(crate) fn resolve_spacesd_download<'a>(
    raw: Option<&'a str>,
    version: &str,
    arch_replacement: Option<&str>,
    dir_asset_name: &str,
) -> Option<(String, Option<&'a str>)> {
    let trimmed = raw.map(str::trim).filter(|u| !u.is_empty())?;
    let (base, sha) = match trimmed.split_once('#') {
        Some((u, frag)) => (u, frag.strip_prefix("sha256=").map(str::trim)),
        None => (trimmed, None),
    };
    let mut expanded = base.replace("{version}", version);
    if let Some(arch) = arch_replacement {
        expanded = expanded.replace("{arch}", arch);
    }
    let resolved = match expanded.split_once('?') {
        Some((path, query)) if path.ends_with('/') => format!("{path}{dir_asset_name}?{query}"),
        None if expanded.ends_with('/') => format!("{expanded}{dir_asset_name}"),
        _ => expanded,
    };
    Some((resolved, sha))
}

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
    pub join: &'a Join,
    pub image: &'a str,
    pub env: &'a BTreeMap<String, String>,
    /// Unix seconds after which the VM shuts itself down (0: never).
    pub expires: u64,
    /// Seconds from boot for the `shutdown -h` backstop (0: none).
    pub ttl_secs: u64,
    pub shm_mb: u32,
    /// Cloud provider (`aws`, `gcp`, `azure`, `hetzner`, `aliyun-ecs`).
    pub provider: &'a str,
    /// Enable host network guard (`crate::hostnet`); else Docker metadata drop-in.
    pub net_guard: bool,
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

pub(super) fn b64(s: &str) -> String {
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
         log \"docker mtu $mtu\"\n\
         log 'installing Docker'\n\
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
            let (lo, hi) = crate::share_net::HOST_SLOTS;
            format!("\x20 -p {lo}-{hi}:{lo}-{hi} \\\n")
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
    // Older images read CUA_GUESTD_ARGS or CUA_ENV_DRIVER_ARGS instead of CUA_SPACESD_ARGS.
    for k in JOIN_ARG_VARS {
        env.insert((*k).into(), "join".into());
    }
    for (k, v) in [
        ("CUA_ENV_RELAY_URL", boot.join.relay_url.as_str()),
        ("CUA_RELAY_TOKEN_FILE", "/run/cua-relay/machine-token"),
        ("CUA_ENV_MACHINE_ID_FILE", "/run/cua-relay/machine-id"),
        ("CUA_HOST_POLICY", "/run/cua-relay/policy.json"),
    ] {
        env.insert(k.into(), v.into());
    }
    if !boot.join.jwks_json.trim().is_empty() {
        env.insert("CUA_RELAY_JWKS".into(), "/run/cua-relay/jwks.json".into());
    }
    if boot.share_slots {
        let (lo, hi) = crate::share_net::HOST_SLOTS;
        env.insert("CUA_SHARE_SLOTS".into(), format!("{lo}-{hi}"));
    }
    let mut out = String::new();
    for (k, v) in env {
        if !is_valid_env_key(&k, false) {
            continue;
        }
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

pub(super) const EXPIRE_SCRIPT: &str = "#!/bin/sh\n\
     # Cua: shut this VM down once its sandbox's time limit has passed.\n\
     exp=$(cat /etc/cua/expires 2>/dev/null || echo 0)\n\
     [ \"${exp:-0}\" -gt 0 ] 2>/dev/null || exit 0\n\
     if [ \"$(date +%s)\" -ge \"$exp\" ]; then\n\
     \x20 logger -t cua-expire 'time limit reached; shutting down'\n\
     \x20 exec /sbin/shutdown -h now 'cua: this sandbox reached its time limit'\n\
     fi\n";
pub(super) const EXPIRE_SERVICE: &str = "[Unit]\nDescription=Cua: end this VM after its sandbox's time limit\n\n\
     [Service]\nType=oneshot\nExecStart=/usr/local/bin/cua-expire\n";
pub(super) const EXPIRE_TIMER: &str = "[Unit]\nDescription=Cua: check this sandbox's time limit\n\n\
     [Timer]\nOnBootSec=1min\nOnUnitActiveSec=2min\n\n\
     [Install]\nWantedBy=timers.target\n";

pub(super) fn push_b64_file(y: &mut String, indent: &str, path: &str, perm: &str, content: &str) {
    y.push_str(&format!(
        "{indent}- path: {path}\n{indent}  permissions: '{perm}'\n{indent}  owner: root:root\n{indent}  encoding: b64\n{indent}  content: {}\n",
        b64(content)
    ));
}

fn push_b64_files(y: &mut String, indent: &str, files: &[(&str, &str, &str)]) {
    for &(path, perm, content) in files {
        push_b64_file(y, indent, path, perm, content);
    }
}

pub(super) fn push_relay_files(y: &mut String, indent: &str, join: &Join) {
    let mid = format!("{}\n", join.machine_id);
    let policy = join.policy_json();
    push_b64_files(
        y,
        indent,
        &[
            ("/etc/cua/relay/machine-token", "0600", &join.machine_token),
            ("/etc/cua/relay/machine-id", "0600", &mid),
        ],
    );
    if !join.jwks_json.trim().is_empty() {
        push_b64_file(
            y,
            indent,
            "/etc/cua/relay/jwks.json",
            "0600",
            &join.jwks_json,
        );
    }
    push_b64_file(y, indent, "/etc/cua/relay/policy.json", "0600", &policy);
}

/// The `#cloud-config` user data for `boot`. Secret: tokens are base64-encoded
/// and reach only this VM.
pub fn cloud_init(boot: &VmBoot<'_>) -> String {
    let mut y = String::from("#cloud-config\nssh_pwauth: false\nwrite_files:\n");
    push_relay_files(&mut y, "  ", boot.join);
    let env = container_env(boot);
    let expires = format!("{}\n", boot.expires);
    let first_boot = first_boot_script(boot);
    push_b64_files(
        &mut y,
        "  ",
        &[
            ("/etc/cua/sandbox.env", "0600", &env),
            ("/etc/cua/expires", "0644", &expires),
            ("/usr/local/bin/cua-expire", "0755", EXPIRE_SCRIPT),
            (
                "/etc/systemd/system/cua-expire.service",
                "0644",
                EXPIRE_SERVICE,
            ),
            ("/etc/systemd/system/cua-expire.timer", "0644", EXPIRE_TIMER),
        ],
    );
    // Without Secure Spaces net_guard, keep the Docker metadata drop-in (DNS
    // exception is required for Compute Engine's 169.254.169.254 resolver).
    if !boot.net_guard {
        let p = "/etc/systemd/system/docker.service.d/cua-metadata.conf";
        push_b64_file(&mut y, "  ", p, "0644", METADATA_RULES);
    }
    push_b64_file(
        &mut y,
        "  ",
        "/usr/local/sbin/cua-first-boot",
        "0700",
        &first_boot,
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
pub(super) mod tests {
    use super::*;

    pub(super) fn join() -> Join {
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
        let rest = &y[y.find(&format!("path: {path}\n")).expect(path)..];
        let c = rest.find("content: ").unwrap() + "content: ".len();
        if let Some(after_pipe) = rest[c..].strip_prefix("|\n") {
            let (mut out, mut indent) = (String::new(), None);
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
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&rest[c..c + end])
            .unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn vm_boot<'a>(
        join: &'a Join,
        env: &'a BTreeMap<String, String>,
        net_guard: bool,
        share_slots: bool,
    ) -> VmBoot<'a> {
        VmBoot {
            join,
            image: "ghcr.io/trycua/linux@sha256:abc",
            env,
            expires: 1_900_000_000,
            ttl_secs: 8 * 3600,
            shm_mb: 2048,
            provider: "aws",
            net_guard,
            share_slots,
        }
    }

    #[test]
    fn the_user_data_runs_the_image_joined_to_the_relay_and_ends_itself() {
        let j = join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "envtok".into())]);
        let y = cloud_init(&vm_boot(&j, &env, true, true));
        assert!(y.starts_with("#cloud-config\n"));
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
        for want in [
            "CUA_SPACESD_ARGS=join\n",
            "CUA_GUESTD_ARGS=join\n",
            "CUA_ENV_TOKEN=envtok\n",
            "CUA_RELAY_TOKEN_FILE=/run/cua-relay/machine-token\n",
            "CUA_ENV_RELAY_URL=https://relay.example\n",
            "CUA_SHARE_SLOTS=26500-26515\n",
        ] {
            assert!(envf.contains(want), "missing {want:?} in {envf}");
        }
        assert_eq!(decode(&y, "/etc/cua/expires").trim(), "1900000000");
        let script = decode(&y, "/usr/local/sbin/cua-first-boot");
        for want in [
            "-p 26500-26515:26500-26515",
            "shutdown -h +480",
            "docker run -d --name cua-sandbox --restart unless-stopped",
            "'ghcr.io/trycua/linux@sha256:abc'",
            "-v /etc/cua/relay:/run/cua-relay:ro",
            "/etc/docker/daemon.json",
            "systemctl enable --now cua-host-net.service",
            "PLATFORM_V4=\"169.254.169.254/32 169.254.170.2/32",
            "shred -u /etc/cua/sandbox.env",
        ] {
            assert!(script.contains(want), "missing {want:?} in {script}");
        }
        assert!(
            script.find("cat > /usr/local/sbin/cua-host-net").unwrap()
                < script.find("docker run -d").unwrap()
        );
        assert!(!y.contains("docker.service.d/cua-metadata.conf"));
        assert!(y.contains("enable, --now, cua-expire.timer"));
        assert!(y.len() < 16 * 1024, "{}", y.len());
    }

    #[test]
    fn without_the_experiments_the_machine_boots_as_it_always_did() {
        let j = join();
        let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "envtok".into())]);
        let y = cloud_init(&vm_boot(&j, &env, false, false));
        let rules = decode(&y, "/etc/systemd/system/docker.service.d/cua-metadata.conf");
        assert!(rules.find("--dport 53 -j RETURN").unwrap() > rules.find("-j DROP").unwrap());
        assert!(rules.contains("-d 100.100.100.200 -j DROP"), "{rules}");
        let script = decode(&y, "/usr/local/sbin/cua-first-boot");
        assert!(!script.contains("cua-host-net") && !script.contains("-p 26500-26515"));
        assert!(!decode(&y, "/etc/cua/sandbox.env").contains("CUA_SHARE_SLOTS"));
    }

    #[test]
    fn no_ttl_means_no_backstop() {
        let (j, env) = (join(), BTreeMap::new());
        let mut b = vm_boot(&j, &env, true, false);
        (b.image, b.expires, b.ttl_secs, b.shm_mb, b.provider) = ("x'y", 0, 0, 0, "gcp");
        let script = decode(&cloud_init(&b), "/usr/local/sbin/cua-first-boot");
        assert!(!script.contains("shutdown -h +"));
        assert!(script.contains("'x'\\''y'") && script.contains("--shm-size 64m"));
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
        let env = BTreeMap::from([("CUA_ENV_TOKEN".into(), "envtok".into())]);
        let mut b = vm_boot(&j, &env, true, false);
        (b.expires, b.ttl_secs, b.shm_mb) = (0, 0, 512);
        let y = cloud_init(&b);
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
        assert!(policy.get("owner").is_none() && policy["sharing"] == true);
    }
}
