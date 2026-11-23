---
status: accepted
---

# 0003. Per-connection self-hosted relay and dual-mode VPC networking for BYOC

Currently `cua-byoc` assumes every cloud sandbox registers dynamically against an account-mode relay via `cua auth login` and a process-wide `CUA_RELAY_URL`. To support private, air-gapped, and self-hosted deployments on Alibaba Cloud ECS (and BYOC generally), we decided to support per-connection Relay configuration on cloud connections (`cua cloud connect`) across both official `https://relay.cua.ai` and self-hosted `cua-relay` (in either **Account Relay Mode** or **Static Relay Mode**), paired with dual-mode ECS VPC networking.

## Considered Options

- **Require Account Mode (OIDC) for all self-hosted relays**: Rejected because self-hosters commonly run `cua-relay` in Static Relay Mode (`relay_url` + shared `relay_token` + per-sandbox `env_token`) without running an OIDC issuer or calling `cua auth login`.
- **Rely exclusively on global `CUA_RELAY_URL` environment variable**: Rejected because different cloud connections may target different relays (official vs. VPC-internal self-hosted).
- **Forbid attaching to existing user VPCs**: Rejected because sandboxes targeting an intranet self-hosted relay inside a user's Alibaba Cloud VPC need explicit placement in that VPC without a public IP.

## Consequences

- **Per-connection Relay modes**:
  - A cloud connection stores its own relay target (`https://relay.cua.ai` by default, or a custom URL) and auth mode (Account Relay Mode or Static Relay Mode).
  - In Static Relay Mode, cloud sandbox provisioning passes the shared `relay_token` and generated per-sandbox `env_token` directly to `cua-spacesd join` without requiring `cua auth login` or account enrollment.
- **Dual-mode ECS VPC networking**:
  - **Isolated Cua VPC (default)**: Automatically creates and reuses a tagged VPC (`cua-sb-<owner>`), VSwitch, zero-ingress security group, and `PayByTraffic` public IPv4 address.
  - **Existing VPC mode**: `cua cloud connect aliyun-ecs` accepts `--vpc-id` and `--vswitch-id` (with optional `--no-public-ip`) so sandboxes can reach VPC-internal self-hosted relays or egress through an existing NAT gateway, while still creating only a dedicated, Cua-tagged zero-ingress security group and never modifying user security groups.
