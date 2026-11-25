---
status: accepted
---

# 0002. Native Direct VM Sandbox runtime (`--runtime native`) for Alibaba Cloud ECS

Existing BYOC VM providers run Linux hosts with Docker containers and reject Windows images because ordinary cloud VMs lack nested `/dev/kvm`. For `aliyun-ecs`, we decided to introduce a **Direct VM Sandbox** execution path (`--runtime native`) that runs `cua-spacesd join` directly on native Windows (Windows 10, Windows 11, and Windows Server) and native Linux ECS instances bootstrapped via ECS `UserData`, while preserving Docker-on-VM (`--runtime docker`) for Linux and deferring elastic pool hosts (`Supplies::Hosts`) to Phase 2.

## Considered Options

- **Nested QEMU+KVM on Linux / bare-metal ECS**: Rejected for Phase 1 because bare-metal or nested-KVM SKUs are expensive, narrow in availability, and cannot boot a user's existing custom Windows 10/11 ECS images directly.
- **Alibaba Cloud Assistant (`RunCommand`) as default bootstrap channel**: Rejected as the default in favor of ECS `UserData` so `aliyun-ecs` stays consistent with other BYOC VM providers, avoids extra RAM permissions, and requires no command-polling loop.

## Consequences

- **Runtime defaults and specs**:
  - `windows` defaults to `--runtime native` with a 4 vCPU / 8 GiB default instance type and 60 GiB `cloud_essd` root disk.
  - `linux` defaults to `--runtime docker` (2 vCPU / 4 GiB, 40 GiB `cloud_essd`) and switches to Direct VM Sandbox only when `--runtime native` is requested.
  - Native Linux images that lack a running desktop environment start `cua-spacesd join` in headless mode without installing desktop packages during boot.
- **Custom Cloud Image IDs and binary provisioning**:
  - Connection defaults (`--windows-image-id`, `--linux-image-id`) and per-create overrides (`--cloud-image-id`) select the ECS `ImageId`, falling back to official Alibaba Cloud images when omitted (excluding headless `wincore` / `(Without UI)` Windows Server Core images and preferring `win2025` -> `win2022` -> `win2019`).
  - Both official Alibaba Cloud Windows Server images and custom Windows 10/11/Server images on `aliyun-ecs` use Alibaba Cloud `vminit` (`[powershell]` `UserData`), because stock `cloudbase-init` queries legacy `2009-04-04` metadata endpoints that return `404` on Alibaba Cloud ECS.
  - Bootstrap checks whether `cua-spacesd` is already installed on the image; if absent, it downloads the binary from a connection-configurable custom download URL (defaulting to GitHub Releases) with SHA-256 verification.
- **Windows interactive session and RDP disconnect recovery**:
  - Windows desktop capture and UI automation fail in Session 0, so `UserData` resolves the local Administrator account (matching configured name or built-in SID `S-1-5-21-*-500` and enabling it if disabled), configures AutoLogon, disables auto-lock and screensavers, registers an `AtLogOn` interactive scheduled task (`LogonType Interactive`) for `cua-spacesd.exe` in Session >= 1, installs a `SYSTEM` scheduled task triggered by RDP disconnect Event ID `24` to run `tscon <SessionId> /dest:console`, and detaches the AutoLogon reboot until `vminit` archives `C:\ProgramData\aliyun\vminit\POST_Main` (avoiding reboot races with `Plugin_Main_LaunchAssist`).
- **Billing, auth, and lifecycle safety**:
  - Phase 1 authenticates via RAM sub-account AccessKey (environment variables, `~/.aliyun/config.json` profile, or `--token-stdin` local credential store) paired with a least-privilege RAM Policy; OIDC federation is deferred.
  - Instances launch as `PostPaid` with `StoppedMode=StopCharging`, native ECS `AutoReleaseTime` (default 8 hours via `--ttl-hours`), in-guest shutdown timer, `HttpTokens=required` (IMDSv2) on Linux (blocking `100.100.100.200` on the host firewall), and `HttpTokens=optional` on Windows (with zero RAM instance role and no guest outbound metadata firewall block so `vminit` and Day-2 Cloud Assistant remain operational), plus `cua-managed=true` resource tagging.
  - Cua security groups ensure outbound `0.0.0.0/0` egress and allow external enterprise CSAS or operator ingress rules rather than failing validation.
  - When `ecs:DeleteInstance` is blocked by RAM or organization Resource Directory Control Policies (`Forbidden.RAM`), instance teardown degrades gracefully to `StopInstance(StoppedMode=StopCharging)`, tightens `ModifyInstanceAutoReleaseTime` to the platform minimum window (~31 minutes ahead), and best-effort tags `cua-decommissioned=true` so `list` and `sweep` treat the instance as terminated during the countdown.
