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
  - Connection defaults (`--windows-image-id`, `--linux-image-id`) and per-create overrides (`--cloud-image-id`) select the ECS `ImageId`, falling back to official Alibaba Cloud images when omitted.
  - Official Alibaba Cloud Windows Server images use Alibaba Cloud `vminit` (`[powershell]` `UserData`), while custom Windows 10/11 images must have `cloudbase-init` pre-installed to execute `#ps1_sysnative` ECS `UserData`.
  - Bootstrap checks whether `cua-spacesd` is already installed on the image; if absent, it downloads the binary from a connection-configurable custom download URL (defaulting to GitHub Releases) with SHA-256 verification.
- **Windows interactive session and RDP disconnect recovery**:
  - Windows desktop capture and UI automation fail in Session 0, so `UserData` configures AutoLogon, disables auto-lock and screensavers, registers an `AtLogOn` interactive scheduled task (`LogonType Interactive`) for `cua-spacesd.exe` in Session >= 1, and installs a `SYSTEM` scheduled task triggered by RDP disconnect Event ID `24` to run `tscon <SessionId> /dest:console`.
- **Billing, auth, and lifecycle safety**:
  - Phase 1 authenticates via RAM sub-account AccessKey (environment variables, `~/.aliyun/config.json` profile, or `--token-stdin` local credential store) paired with a least-privilege RAM Policy; OIDC federation is deferred.
  - Instances launch as `PostPaid` with `StoppedMode=StopCharging`, native ECS `AutoReleaseTime` (default 8 hours via `--ttl-hours`), in-guest shutdown timer, `HttpTokens=required` (IMDSv2) on Linux and `HttpTokens=optional` on Windows (where Alibaba Cloud `vminit`/`cloudbase-init` lacks IMDSv2 support, mitigated by zero RAM role and first-boot OS firewall blocking of `100.100.100.200` and `169.254.169.254`), and `cua-managed=true` resource tagging.
