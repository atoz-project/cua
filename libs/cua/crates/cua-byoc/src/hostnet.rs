// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Host firewall guard installed on first boot before any container or Direct VM daemon starts.
//!
//! For container bridges (`docker0`, `br-+`), traffic is filtered on `DOCKER-USER`
//! (and `INPUT` for host-bound traffic): allow DNS (port 53) to the host resolver,
//! then block cloud metadata endpoints (`PLATFORM_DENY_*`), the host's own VPC/subnet
//! CIDRs, and private/reserved ranges (`DEFAULT_DENY_*`). On Azure, `168.63.129.16`
//! serves both DNS and the provisioning wire server, so containers use a host-local
//! `dnsmasq` stub on `169.254.53.53` (`--stop-dns-rebind`).
//!
//! For Direct VM Sandboxes (`--runtime native`), the same renderer targets host
//! `OUTPUT` (with `nft` fallback when `iptables` is absent) to unconditionally block
//! cloud metadata endpoints while preserving loopback, VPC DNS, and relay egress.

use crate::bootstrap::sh_quote;

/// Cloud metadata and wire-server endpoints Spaces may never reach.
pub const PLATFORM_DENY_V4: &[&str] = &[
    "169.254.169.254/32",
    "169.254.170.2/32",
    "168.63.129.16/32",
    "100.100.100.200/32",
];
pub const PLATFORM_DENY_V6: &[&str] = &["fd00:ec2::254/128"];
pub const DEFAULT_DENY_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
pub const DEFAULT_DENY_V6: &[&str] = &[
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];
pub const LOCAL_DNS: &str = "169.254.53.53";
pub const AZURE_WIRESERVER: &str = "168.63.129.16";
pub const SCRIPT_PATH: &str = "/usr/local/sbin/cua-host-net";
pub const UNIT: &str = "cua-host-net.service";
pub const STATE_FILE: &str = "/etc/cua/host-net.cidrs";

/// Host context for the firewall guard.
#[derive(Clone, Copy, Debug)]
pub struct HostNet<'a> {
    pub provider: &'a str,
    pub extra_cidrs: &'a [String],
}

impl HostNet<'_> {
    /// True on Azure, where DNS goes through the host-local `dnsmasq` stub.
    pub fn local_dns(&self) -> bool {
        self.provider == "azure"
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardTarget {
    DockerBridge,
    NativeOutput,
}

fn list(items: &[&str]) -> String {
    items.join(" ")
}

/// Shared POSIX `sh` renderer for both [`script`] (`DOCKER-USER` + `INPUT`) and
/// [`native_script`] (`OUTPUT`, with `nft` fallback).
fn render_script(net: &HostNet<'_>, target: GuardTarget) -> String {
    let extra = net.extra_cidrs.join(" ");
    let platform_v4 = list(PLATFORM_DENY_V4);
    let platform_v6 = list(PLATFORM_DENY_V6);
    let (comment, guard_chain, parent_chain) = match target {
        GuardTarget::DockerBridge => (
            "Cua: keep Spaces off the cloud's metadata service, its private network and\n# this computer. Traffic from container bridges only; rebuilt on every run.",
            "CUA-SPACE-GUARD",
            "DOCKER-USER",
        ),
        GuardTarget::NativeOutput => (
            "Cua: block cloud metadata endpoints on host OUTPUT for Direct VM Sandboxes.",
            "CUA-HOST-GUARD",
            "OUTPUT",
        ),
    };

    let mut s = format!(
        "#!/bin/sh\n\
         # {comment}\n\
         set -eu\n\
         PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin\n\
         PLATFORM_V4=\"{platform_v4}\"\n\
         PLATFORM_V6=\"{platform_v6}\"\n\
         EXTRA_CIDRS=\"{extra}\"\n\
         GUARD={guard_chain}\n"
    );

    if target == GuardTarget::DockerBridge {
        let local_dns = if net.local_dns() { "1" } else { "0" };
        s.push_str(&format!(
            "PROVIDER={provider}\n\
             LOCAL_DNS={local_dns}\n\
             LOCAL_DNS_ADDR={LOCAL_DNS}\n\
             WIRESERVER={AZURE_WIRESERVER}\n\
             DEFAULT_V4=\"{default_v4}\"\n\
             DEFAULT_V6=\"{default_v6}\"\n\
             STATE={STATE_FILE}\n\
             INPUT_GUARD=CUA-SPACE-INPUT\n\
             BRIDGES=\"docker0 br-+\"\n",
            provider = sh_quote(net.provider),
            default_v4 = list(DEFAULT_DENY_V4),
            default_v6 = list(DEFAULT_DENY_V6),
        ));
    }

    s.push_str(&format!(
        r#"run() {{ if [ "${{CUA_NET_DRY:-0}}" = 1 ]; then echo "$*"; else "$@"; fi; }}
resolvers() {{
  if [ -n "${{CUA_NET_RESOLVERS+x}}" ]; then echo $CUA_NET_RESOLVERS; return; fi
  for f in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
    [ -r "$f" ] || continue
    out=""
    for ns in $(awk '$1=="nameserver"{{print $2}}' "$f"); do
      case "$ns" in 127.*|::1|*:*|{AZURE_WIRESERVER}|100.100.100.200) ;; *) out="$out $ns" ;; esac
    done
    if [ -n "$out" ]; then echo $out; return; fi
  done
  return 0
}}
fresh() {{ run $1 -N "$2" 2>/dev/null || true; run $1 -F "$2"; }}
"#
    ));

    match target {
        GuardTarget::DockerBridge => {
            s.push_str(
                r#"own_cidrs() {
  if [ -n "${CUA_NET_CIDRS+x}" ]; then echo $CUA_NET_CIDRS; return; fi
  found=""
  if [ "$PROVIDER" = aws ]; then
    t=$(curl -fsS -m 3 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token 2>/dev/null || true)
    if [ -n "$t" ]; then
      mac=$(curl -fsS -m 3 -H "X-aws-ec2-metadata-token: $t" http://169.254.169.254/latest/meta-data/mac 2>/dev/null || true)
      [ -n "$mac" ] && found=$(curl -fsS -m 3 -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/vpc-ipv4-cidr-blocks" 2>/dev/null || true)
    fi
  fi
  routes=$(ip -4 -o route show scope link 2>/dev/null | awk '$0 !~ / dev (docker|br-|veth|virbr|cua)/ && $1 ~ /\//{print $1}' || true)
  if [ -f "$STATE" ]; then found="$found $(cat "$STATE")"; fi
  all=$(echo $found $routes $EXTRA_CIDRS | tr ' ' '\n' | grep -E '^[0-9.]+/[0-9]+$' | sort -u | tr '\n' ' ')
  if [ "${CUA_NET_DRY:-0}" != 1 ] && [ -n "$all" ]; then
    mkdir -p /etc/cua && echo "$all" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
  fi
  echo $all
}
hook() {
  tool=$1; parent=$2; chain=$3
  run $tool -N "$parent" 2>/dev/null || true
  for br in $BRIDGES; do
    if [ "${CUA_NET_DRY:-0}" = 1 ] || ! $tool -C "$parent" -i "$br" -j "$chain" 2>/dev/null; then
      run $tool -I "$parent" 1 -i "$br" -j "$chain"
    fi
  done
}
RES=$(resolvers)
CIDRS=$(own_cidrs)
"#,
            );
            render_iptables_guard(&mut s, target, parent_chain, "");
        }
        GuardTarget::NativeOutput => {
            s.push_str(
                r#"hook() {
  if [ "${CUA_NET_DRY:-0}" = 1 ] || ! $1 -C "$2" -j "$3" 2>/dev/null; then
    run $1 -I "$2" 1 -j "$3"
  fi
}
backend=""
if [ "${CUA_NET_DRY:-0}" = 1 ]; then backend="${CUA_NET_BACKEND:-iptables}"
elif command -v iptables >/dev/null 2>&1; then backend=iptables
elif command -v nft >/dev/null 2>&1; then backend=nft
fi
if [ "$backend" = iptables ]; then
  RES=$(resolvers)
"#,
            );
            render_iptables_guard(&mut s, target, parent_chain, "  ");
            let platform_v4_nft = PLATFORM_DENY_V4.join(", ");
            let platform_v6_nft = PLATFORM_DENY_V6.join(", ");
            s.push_str(&format!(
                r#"elif [ "$backend" = nft ]; then
  RES=$(resolvers)
  NFT_RULES=$(
    printf 'table inet cua_host_guard {{\n  chain output {{\n    type filter hook output priority -100; policy accept;\n    oifname "lo" return\n'
    for r in $RES; do
      if [ "$r" = 100.100.100.200 ]; then continue; fi
      printf '    ip daddr %s udp dport 53 return\n    ip daddr %s tcp dport 53 return\n' "$r" "$r"
    done
    printf '    ip daddr {{ {platform_v4_nft} }} drop\n'
    for n in $EXTRA_CIDRS; do
      case "$n" in *:*) printf '    ip6 daddr %s drop\n' "$n" ;; *) printf '    ip daddr %s drop\n' "$n" ;; esac
    done
    printf '    ip6 daddr {{ {platform_v6_nft} }} drop\n  }}\n}}\n'
  )
  if [ "${{CUA_NET_DRY:-0}}" = 1 ]; then printf '%s\n' "$NFT_RULES"
  else nft delete table inet cua_host_guard 2>/dev/null || true; printf '%s\n' "$NFT_RULES" | nft -f -
  fi
else
  echo "cua: neither iptables nor nft is installed to block metadata endpoints" >&2; exit 1
fi
"#
            ));
        }
    }

    s
}

/// Emits the shared IPv4 + IPv6 `iptables`/`ip6tables` guard chains for
/// `target`, hooked into `parent_chain` (`DOCKER-USER` or `OUTPUT`).
fn render_iptables_guard(s: &mut String, target: GuardTarget, parent_chain: &str, pad: &str) {
    let (lo_v4, lo_v6, tail_v4, tail_v6, input_v4, input_v6) = match target {
        GuardTarget::DockerBridge => (
            String::new(),
            String::new(),
            format!(
                "{pad}for n in $CIDRS; do run iptables -A $GUARD -d \"$n\" -j DROP; done\n\
                 {pad}for n in $DEFAULT_V4; do run iptables -A $GUARD -d \"$n\" -j DROP; done\n"
            ),
            format!(
                "{pad}  for n in $DEFAULT_V6; do run ip6tables -A $GUARD -d \"$n\" -j DROP; done\n"
            ),
            format!(
                "{pad}fresh iptables $INPUT_GUARD\n\
                 {pad}run iptables -A $INPUT_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n\
                 {pad}if [ \"$LOCAL_DNS\" = 1 ]; then\n\
                 {pad}  run iptables -A $INPUT_GUARD -d \"$LOCAL_DNS_ADDR\" -p udp --dport 53 -j RETURN\n\
                 {pad}  run iptables -A $INPUT_GUARD -d \"$LOCAL_DNS_ADDR\" -p tcp --dport 53 -j RETURN\n\
                 {pad}fi\n\
                 {pad}run iptables -A $INPUT_GUARD -j DROP\n\
                 {pad}hook iptables INPUT $INPUT_GUARD\n"
            ),
            format!(
                "{pad}  fresh ip6tables $INPUT_GUARD\n\
                 {pad}  run ip6tables -A $INPUT_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n\
                 {pad}  run ip6tables -A $INPUT_GUARD -p ipv6-icmp -j RETURN\n\
                 {pad}  run ip6tables -A $INPUT_GUARD -j DROP\n\
                 {pad}  hook ip6tables INPUT $INPUT_GUARD\n"
            ),
        ),
        GuardTarget::NativeOutput => (
            format!("{pad}run iptables -A $GUARD -o lo -j RETURN\n"),
            format!("{pad}  run ip6tables -A $GUARD -o lo -j RETURN\n"),
            format!(
                "{pad}for n in $EXTRA_CIDRS; do case \"$n\" in *:*) ;; *) run iptables -A $GUARD -d \"$n\" -j DROP ;; esac; done\n"
            ),
            format!(
                "{pad}  for n in $EXTRA_CIDRS; do case \"$n\" in *:*) run ip6tables -A $GUARD -d \"$n\" -j DROP ;; *) ;; esac; done\n"
            ),
            String::new(),
            String::new(),
        ),
    };
    s.push_str(&format!(
        "{pad}fresh iptables $GUARD\n\
         {lo_v4}\
         {pad}for r in $RES; do\n\
         {pad}  if [ \"$r\" = 100.100.100.200 ]; then continue; fi\n\
         {pad}  run iptables -A $GUARD -d \"$r\" -p udp --dport 53 -j RETURN\n\
         {pad}  run iptables -A $GUARD -d \"$r\" -p tcp --dport 53 -j RETURN\n\
         {pad}done\n\
         {pad}for n in $PLATFORM_V4; do run iptables -A $GUARD -d \"$n\" -j DROP; done\n\
         {tail_v4}\
         {pad}run iptables -A $GUARD -j RETURN\n\
         {pad}hook iptables {parent_chain} $GUARD\n\
         {input_v4}\
         {pad}if [ \"${{CUA_NET_DRY:-0}}\" = 1 ] || command -v ip6tables >/dev/null 2>&1; then\n\
         {pad}  fresh ip6tables $GUARD\n\
         {lo_v6}\
         {pad}  for n in $PLATFORM_V6; do run ip6tables -A $GUARD -d \"$n\" -j DROP; done\n\
         {tail_v6}\
         {pad}  run ip6tables -A $GUARD -j RETURN\n\
         {pad}  hook ip6tables {parent_chain} $GUARD\n\
         {input_v6}\
         {pad}fi\n"
    ));
}

/// Guard script for container bridges (`DOCKER-USER` + `INPUT`).
pub fn script(net: &HostNet<'_>) -> String {
    render_script(net, GuardTarget::DockerBridge)
}

/// Host-level `OUTPUT` firewall script for Direct VM Sandboxes (`--runtime native`).
pub fn native_script(net: &HostNet<'_>) -> String {
    render_script(net, GuardTarget::NativeOutput)
}

/// Systemd unit for the Docker bridge guard (re-runs on Docker restart).
pub fn unit() -> &'static str {
    "[Unit]\n\
     Description=Cua: keep Spaces off the cloud's metadata service and private network\n\
     After=docker.service network-online.target\n\
     Wants=network-online.target\n\
     PartOf=docker.service\n\n\
     [Service]\n\
     Type=oneshot\n\
     RemainAfterExit=yes\n\
     ExecStart=/usr/local/sbin/cua-host-net\n\n\
     [Install]\n\
     WantedBy=multi-user.target docker.service\n"
}

/// Systemd unit for the Direct VM `OUTPUT` guard (starts before `cua-spacesd.service`).
pub fn native_unit() -> &'static str {
    "[Unit]\n\
     Description=Cua: keep Direct VM Spaces off the cloud metadata service\n\
     After=network-online.target\n\
     Wants=network-online.target\n\
     Before=cua-spacesd.service\n\n\
     [Service]\n\
     Type=oneshot\n\
     RemainAfterExit=yes\n\
     ExecStart=/usr/local/sbin/cua-host-net\n\n\
     [Install]\n\
     WantedBy=multi-user.target\n"
}

/// Azure local `dnsmasq` resolver unit forwarding to the wire server.
pub fn dns_unit() -> String {
    format!(
        "[Unit]\n\
         Description=Cua: DNS for Spaces (the wire server is not reachable from a Space)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         Before=docker.service\n\n\
         [Service]\n\
         ExecStartPre=-/sbin/ip link add cua-dns0 type dummy\n\
         ExecStartPre=-/sbin/ip addr add {LOCAL_DNS}/32 dev cua-dns0\n\
         ExecStartPre=/sbin/ip link set cua-dns0 up\n\
         ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null \
         --listen-address={LOCAL_DNS} --bind-interfaces --no-resolv --no-hosts \
         --server={AZURE_WIRESERVER} --stop-dns-rebind --cache-size=1000\n\
         Restart=always\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

fn render_install_snippet(net: &HostNet<'_>, target: GuardTarget) -> String {
    let (header, unit_text) = if target == GuardTarget::DockerBridge {
        (
            "# Cua: the host's network guard for Spaces (see hostnet.rs).\n",
            unit(),
        )
    } else {
        (
            "# Cua: host metadata firewall for Direct VM Spaces.\n",
            native_unit(),
        )
    };
    let mut s = format!(
        "{header}mkdir -p /etc/cua\n\
         cat > {SCRIPT_PATH} <<'CUA_HOST_NET'\n{}CUA_HOST_NET\n\
         chmod 755 {SCRIPT_PATH}\n\
         cat > /etc/systemd/system/{UNIT} <<'CUA_HOST_NET_UNIT'\n{unit_text}CUA_HOST_NET_UNIT\n",
        render_script(net, target),
    );
    if target == GuardTarget::DockerBridge && net.local_dns() {
        s.push_str(&format!(
            "( command -v dnsmasq >/dev/null || apt-get install -y -qq dnsmasq-base ) || {{ echo 'cua: no local resolver for Spaces'; exit 1; }}\n\
             cat > /etc/systemd/system/cua-dns.service <<'CUA_DNS_UNIT'\n{}CUA_DNS_UNIT\n\
             mkdir -p /etc/docker\n\
             python3 - <<'CUA_DNS_DOCKER'\n\
             import json, os\n\
             p = '/etc/docker/daemon.json'\n\
             d = json.load(open(p)) if os.path.exists(p) and os.path.getsize(p) else {{}}\n\
             d['dns'] = ['{LOCAL_DNS}']\n\
             json.dump(d, open(p, 'w'))\n\
             CUA_DNS_DOCKER\n\
             systemctl daemon-reload\n\
             systemctl enable --now cua-dns.service\n\
             systemctl restart docker\n",
            dns_unit()
        ));
    }
    s.push_str(&format!(
        "systemctl daemon-reload\nsystemctl enable --now {UNIT}\n"
    ));
    s
}

/// Shell lines that install and start the Docker bridge guard (plus Azure local DNS).
pub fn install_snippet(net: &HostNet<'_>) -> String {
    render_install_snippet(net, GuardTarget::DockerBridge)
}

/// Shell lines that install and start [`native_unit`].
pub fn native_install_snippet(net: &HostNet<'_>) -> String {
    render_install_snippet(net, GuardTarget::NativeOutput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::process::Command;

    #[derive(Debug)]
    struct Rule {
        chain: String,
        dst: Option<String>,
        proto: Option<String>,
        dport: Option<u16>,
        ctstate: bool,
        target: String,
    }

    fn run_sh(script_text: &str, envs: &[(&str, Option<&str>)]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guard.sh");
        std::fs::write(&path, script_text).unwrap();
        let mut cmd = Command::new("sh");
        cmd.arg(&path).env("CUA_NET_DRY", "1");
        for &(k, v) in envs {
            if let Some(val) = v {
                cmd.env(k, val);
            } else {
                cmd.env_remove(k);
            }
        }
        let out = cmd.output().expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn run_dry(net: &HostNet<'_>, resolvers: &str, cidrs: &str) -> Vec<String> {
        run_sh(
            &script(net),
            &[
                ("CUA_NET_RESOLVERS", Some(resolvers)),
                ("CUA_NET_CIDRS", Some(cidrs)),
            ],
        )
        .lines()
        .map(str::to_string)
        .collect()
    }

    fn rules(lines: &[String], tool: &str) -> Vec<Rule> {
        lines
            .iter()
            .filter_map(|l| {
                let w: Vec<&str> = l.split_whitespace().collect();
                if w.first() != Some(&tool) || w.get(1) != Some(&"-A") {
                    return None;
                }
                let get = |flag: &str| {
                    w.iter()
                        .position(|x| *x == flag)
                        .and_then(|i| w.get(i + 1))
                        .map(|s| (*s).to_string())
                };
                Some(Rule {
                    chain: w[2].to_string(),
                    dst: get("-d"),
                    proto: get("-p"),
                    dport: get("--dport").and_then(|p| p.parse().ok()),
                    ctstate: w.contains(&"--ctstate"),
                    target: get("-j").unwrap(),
                })
            })
            .collect()
    }

    fn in_net(cidr: &str, ip: Ipv4Addr) -> bool {
        let (a, p) = cidr.split_once('/').unwrap_or((cidr, "32"));
        let a: Ipv4Addr = a.parse().unwrap();
        let p: u32 = p.parse().unwrap();
        let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
        u32::from(a) & mask == u32::from(ip) & mask
    }

    fn forwarded(rules: &[Rule], ip: Ipv4Addr, proto: &str, port: u16) -> bool {
        for r in rules.iter().filter(|r| r.chain == "CUA-SPACE-GUARD") {
            let dst_hit = r.dst.as_deref().is_none_or(|d| in_net(d, ip));
            let proto_hit = r.proto.as_deref().is_none_or(|p| p == proto);
            let port_hit = r.dport.is_none_or(|p| p == port);
            if dst_hit && proto_hit && port_hit && !r.ctstate {
                return r.target == "RETURN";
            }
        }
        true
    }

    fn host(provider: &'static str) -> HostNet<'static> {
        HostNet {
            provider,
            extra_cidrs: &[],
        }
    }

    fn assert_valid_sh(script_text: &str, label: &str) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.sh");
        std::fs::write(&path, script_text).unwrap();
        let st = Command::new("sh").arg("-n").arg(&path).status().unwrap();
        assert!(st.success(), "{label}");
    }

    #[test]
    fn the_script_is_valid_sh_for_every_cloud() {
        for provider in ["aws", "gcp", "azure", "hetzner", "x'y"] {
            assert_valid_sh(&script(&host(provider)), provider);
        }
    }

    #[test]
    fn a_container_reaches_the_internet_and_dns_but_nothing_private() {
        let lines = run_dry(&host("aws"), "10.20.0.2", "10.20.0.0/16 10.20.1.0/24");
        let r = rules(&lines, "iptables");
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        for (a, p, port) in [
            ("93.184.216.34", "tcp", 443),
            ("1.1.1.1", "udp", 53),
            ("10.20.0.2", "udp", 53),
            ("10.20.0.2", "tcp", 53),
        ] {
            assert!(forwarded(&r, ip(a), p, port), "{a}:{port}");
        }
        for (a, p, port) in [
            ("10.20.0.2", "tcp", 443),
            ("10.20.0.2", "udp", 123),
            ("169.254.169.254", "tcp", 80),
            ("169.254.169.254", "udp", 53),
            ("169.254.170.2", "tcp", 80),
            ("169.254.170.2", "udp", 53),
            ("168.63.129.16", "tcp", 80),
            ("168.63.129.16", "udp", 53),
            ("100.100.100.200", "tcp", 80),
            ("100.100.100.200", "udp", 53),
            ("10.20.5.6", "tcp", 22),
            ("172.31.4.4", "tcp", 22),
            ("192.168.1.1", "tcp", 80),
            ("100.64.0.1", "tcp", 80),
            ("127.0.0.1", "tcp", 80),
            ("169.254.1.1", "tcp", 80),
            ("224.0.0.251", "udp", 5353),
            ("255.255.255.255", "udp", 67),
        ] {
            assert!(!forwarded(&r, ip(a), p, port), "{a}:{port}");
        }
    }

    #[test]
    fn a_public_vpc_range_is_blocked_too() {
        let lines = run_dry(&host("aws"), "", "44.0.0.0/16");
        let r = rules(&lines, "iptables");
        assert!(!forwarded(&r, "44.0.9.9".parse().unwrap(), "tcp", 22));
        assert!(forwarded(&r, "44.1.0.1".parse().unwrap(), "tcp", 22));
    }

    #[test]
    fn the_google_resolver_is_the_metadata_address_and_only_dns_passes() {
        let lines = run_dry(&host("aws"), "169.254.169.254", "");
        let r = rules(&lines, "iptables");
        let md: Ipv4Addr = "169.254.169.254".parse().unwrap();
        assert!(forwarded(&r, md, "udp", 53));
        assert!(!forwarded(&r, md, "tcp", 80) && !forwarded(&r, md, "tcp", 443));
    }

    #[test]
    fn the_machine_itself_takes_only_replies_and_the_azure_resolver() {
        let lines = run_dry(&host("aws"), "10.0.0.2", "10.0.0.0/16");
        let input: Vec<_> = rules(&lines, "iptables")
            .into_iter()
            .filter(|r| r.chain == "CUA-SPACE-INPUT")
            .collect();
        assert!(input[0].ctstate && input.last().unwrap().target == "DROP");
        assert!(input.last().unwrap().dst.is_none());
        assert!(input.iter().all(|r| r.dst.as_deref() != Some(LOCAL_DNS)));
        let az = run_dry(&host("azure"), "", "10.1.0.0/16");
        let az_r = rules(&az, "iptables");
        let dns: Vec<_> = az_r
            .iter()
            .filter(|r| r.chain == "CUA-SPACE-INPUT" && r.dst.as_deref() == Some(LOCAL_DNS))
            .collect();
        assert_eq!(dns.len(), 2);
        assert!(
            dns.iter()
                .all(|r| r.dport == Some(53) && r.target == "RETURN")
        );
        assert!(!forwarded(
            &az_r,
            "168.63.129.16".parse().unwrap(),
            "udp",
            53
        ));
    }

    #[test]
    fn the_guard_hooks_both_chains_for_every_bridge_and_both_families() {
        let lines = run_dry(&host("aws"), "10.0.0.2", "10.0.0.0/16");
        for tool in ["iptables", "ip6tables"] {
            for (parent, chain) in [
                ("DOCKER-USER", "CUA-SPACE-GUARD"),
                ("INPUT", "CUA-SPACE-INPUT"),
            ] {
                for br in ["docker0", "br-+"] {
                    let want = format!("{tool} -I {parent} 1 -i {br} -j {chain}");
                    assert!(lines.contains(&want), "missing {want}");
                }
            }
        }
        let v6 = rules(&lines, "ip6tables");
        let hit = |ip: &str| {
            let ip: std::net::Ipv6Addr = ip.parse().unwrap();
            v6.iter().filter(|r| r.chain == "CUA-SPACE-GUARD").any(|r| {
                r.target == "DROP"
                    && r.dst.as_deref().is_some_and(|d| {
                        let (a, p) = d.split_once('/').unwrap();
                        let (a, p): (std::net::Ipv6Addr, u32) =
                            (a.parse().unwrap(), p.parse().unwrap());
                        let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                        u128::from(a) & mask == u128::from(ip) & mask
                    })
            })
        };
        assert!(hit("fd00:ec2::254") && hit("fe80::1") && hit("fd12:3456::1") && hit("::1"));
        assert!(!hit("2606:4700::1111"));
    }

    #[test]
    fn extra_networks_the_provider_knows_are_blocked() {
        let extra = vec!["44.5.0.0/16".to_string()];
        let net = HostNet {
            provider: "hetzner",
            extra_cidrs: &extra,
        };
        let lines = run_dry(&net, "185.12.64.1", "");
        assert!(script(&net).contains("EXTRA_CIDRS=\"44.5.0.0/16\""));
        let r = rules(&lines, "iptables");
        assert!(forwarded(&r, "185.12.64.1".parse().unwrap(), "udp", 53));
    }

    #[test]
    fn the_lists_are_complete_and_ordered_for_the_floor() {
        assert_eq!(DEFAULT_DENY_V4.len(), 11);
        for n in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ] {
            assert!(DEFAULT_DENY_V4.contains(&n));
        }
        let s = script(&host("aws"));
        let (dns, plat, own, def) = (
            s.find("--dport 53 -j RETURN").unwrap(),
            s.find("for n in $PLATFORM_V4").unwrap(),
            s.find("for n in $CIDRS").unwrap(),
            s.find("for n in $DEFAULT_V4").unwrap(),
        );
        assert!(dns < plat && plat < own && own < def);
    }

    #[test]
    fn the_install_snippet_writes_the_guard_and_starts_it_before_containers() {
        let s = install_snippet(&host("aws"));
        assert!(s.contains("cat > /usr/local/sbin/cua-host-net <<'CUA_HOST_NET'"));
        assert!(
            s.contains("systemctl enable --now cua-host-net.service") && !s.contains("dnsmasq")
        );
        let az = install_snippet(&host("azure"));
        for want in [
            "dnsmasq",
            "--server=168.63.129.16",
            "--stop-dns-rebind",
            "d['dns'] = ['169.254.53.53']",
        ] {
            assert!(az.contains(want), "missing {want}");
        }
        assert!(az.find("cua-dns.service").unwrap() < az.rfind("cua-host-net.service").unwrap());
    }

    #[test]
    fn native_output_guard_blocks_metadata_keeps_loopback_dns_and_relay_egress() {
        let s = native_script(&host("aliyun-ecs"));
        assert_valid_sh(&s, "native_script");
        let stdout = run_sh(
            &s,
            &[
                ("CUA_NET_RESOLVERS", Some("100.100.2.136 100.100.100.200")),
                ("CUA_NET_CIDRS", Some("")),
            ],
        );
        let lines: Vec<&str> = stdout.lines().collect();
        for want in [
            "iptables -I OUTPUT 1 -j CUA-HOST-GUARD",
            "ip6tables -I OUTPUT 1 -j CUA-HOST-GUARD",
            "iptables -A CUA-HOST-GUARD -o lo -j RETURN",
            "iptables -A CUA-HOST-GUARD -d 100.100.2.136 -p udp --dport 53 -j RETURN",
            "ip6tables -A CUA-HOST-GUARD -d fd00:ec2::254/128 -j DROP",
        ] {
            assert!(lines.contains(&want), "missing {want:?}");
        }
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("100.100.100.200") && l.contains("RETURN"))
        );
        for md in PLATFORM_DENY_V4 {
            assert!(
                lines.contains(&format!("iptables -A CUA-HOST-GUARD -d {md} -j DROP").as_str())
            );
        }
        let last = lines
            .iter()
            .rfind(|l| l.starts_with("iptables -A CUA-HOST-GUARD "))
            .copied();
        assert_eq!(last, Some("iptables -A CUA-HOST-GUARD -j RETURN"));
        let u = native_unit();
        assert!(
            u.contains("Before=cua-spacesd.service")
                && u.contains("WantedBy=multi-user.target")
                && !u.contains("docker.service")
        );
    }

    #[test]
    fn native_output_guard_nft_fallback_matches_iptables_rules() {
        let extra = vec!["10.42.0.0/16".to_string(), "fd00:42::/48".to_string()];
        let net = HostNet {
            provider: "aliyun-ecs",
            extra_cidrs: &extra,
        };
        let nft_rules = run_sh(
            &native_script(&net),
            &[
                ("CUA_NET_BACKEND", Some("nft")),
                ("CUA_NET_RESOLVERS", Some("100.100.2.136 100.100.100.200")),
            ],
        );
        for want in [
            "oifname \"lo\" return",
            "ip daddr 100.100.2.136 udp dport 53 return",
            "ip daddr 100.100.2.136 tcp dport 53 return",
            "ip daddr 10.42.0.0/16 drop",
            "ip6 daddr fd00:42::/48 drop",
            "fd00:ec2::254/128",
        ] {
            assert!(nft_rules.contains(want), "missing {want}");
        }
        assert!(
            !nft_rules.contains("100.100.100.200 udp dport 53 return")
                && !nft_rules.contains("100.100.100.200 tcp dport 53 return")
        );
        for md in PLATFORM_DENY_V4 {
            assert!(nft_rules.contains(md), "missing {md}");
        }
        if let Ok(mut child) = Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(nft_rules.as_bytes())
                .unwrap();
            let check = child.wait_with_output().unwrap();
            assert!(
                check.status.success(),
                "nft -c failed: {}",
                String::from_utf8_lossy(&check.stderr)
            );
        }
    }

    fn run_with_resolv(script_text: &str, resolv: &str, envs: &[(&str, Option<&str>)]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("resolv.conf");
        std::fs::write(&fake, resolv).unwrap();
        let patched = script_text.replace(
            "/run/systemd/resolve/resolv.conf /etc/resolv.conf",
            &format!(
                "{} {}",
                dir.path().join("missing.conf").display(),
                fake.display()
            ),
        );
        run_sh(&patched, envs)
    }

    #[test]
    fn native_output_guard_succeeds_with_stub_only_resolv_conf() {
        let extra = vec!["10.42.0.0/16".to_string(), "fd00:42::/48".to_string()];
        let net = HostNet {
            provider: "aliyun-ecs",
            extra_cidrs: &extra,
        };
        let script_text = native_script(&net);
        let stub = "nameserver 127.0.0.53\nnameserver 100.100.100.200\nnameserver ::1\n";
        for backend in ["iptables", "nft"] {
            let stdout = run_with_resolv(
                &script_text,
                stub,
                &[
                    ("CUA_NET_BACKEND", Some(backend)),
                    ("CUA_NET_RESOLVERS", None),
                ],
            );
            if backend == "iptables" {
                let lines: Vec<&str> = stdout.lines().collect();
                assert!(
                    lines.contains(&"iptables -A CUA-HOST-GUARD -d 100.100.100.200/32 -j DROP")
                );
                assert!(lines.contains(&"iptables -A CUA-HOST-GUARD -d 10.42.0.0/16 -j DROP"));
                assert!(!lines.contains(&"iptables -A CUA-HOST-GUARD -d fd00:42::/48 -j DROP"));
                assert!(lines.contains(&"ip6tables -A CUA-HOST-GUARD -d fd00:42::/48 -j DROP"));
            } else {
                assert!(stdout.contains("100.100.100.200/32"));
            }
        }
    }

    #[test]
    fn docker_script_blocks_alibaba_metadata_and_dns_leak() {
        let script_text = script(&host("aliyun-ecs"));
        let env_out = run_sh(
            &script_text,
            &[
                ("CUA_NET_CIDRS", Some("10.77.0.0/16")),
                ("CUA_NET_RESOLVERS", Some("100.100.2.136 100.100.100.200")),
            ],
        );
        let file_out = run_with_resolv(
            &script_text,
            "nameserver 127.0.0.53\nnameserver 168.63.129.16\nnameserver 100.100.100.200\nnameserver 100.100.2.136\n",
            &[
                ("CUA_NET_CIDRS", Some("10.77.0.0/16")),
                ("CUA_NET_RESOLVERS", None),
            ],
        );
        for stdout in [env_out, file_out] {
            let lines: Vec<&str> = stdout.lines().collect();
            for proto in ["udp", "tcp"] {
                let want = format!(
                    "iptables -A CUA-SPACE-GUARD -d 100.100.2.136 -p {proto} --dport 53 -j RETURN"
                );
                assert!(lines.contains(&want.as_str()), "missing {want}");
            }
            assert!(
                !lines
                    .iter()
                    .any(|l| l.contains("100.100.100.200") && l.contains("RETURN"))
            );
            assert!(lines.contains(&"iptables -A CUA-SPACE-GUARD -d 100.100.100.200/32 -j DROP"));
        }
    }
}
