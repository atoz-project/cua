---
status: accepted
---

# 0001. Name the Alibaba Cloud ECS BYOC provider `aliyun-ecs`

Alibaba Cloud offers both general-purpose IaaS virtual machines (ECS) and a separate managed Agent Sandbox service that we plan to integrate later. We decided to name the ECS-backed BYOC provider `aliyun-ecs` (`cua cloud connect aliyun-ecs`, `--on aliyun-ecs`, `aliyun-ecs:<name>`), reserving `aliyun-sandbox` (or `aliyun-agent-sandbox`) for the managed Agent Sandbox service, because `libs/cua/crates/cua-sandbox-core/src/placement.rs` and `refs.rs` restrict provider names to `[a-z0-9-_]` and reserve `:` as the `<provider>:<sandbox-name>` separator.

## Considered Options

- **`aliyun`**: Too broad; would conflict with or obscure Alibaba Cloud's separate managed Agent Sandbox service when it is added later.
- **`aliyun:ecs`**: Invalid under Cua's ref and placement grammar, which splits `<provider>:<sandbox-name>` on `:`.
- **`aliyun-ecs` (chosen)**: Unambiguous, consistent with `placement.rs` (`[a-z0-9-_]`), and leaves clean sibling namespace room for `aliyun-sandbox`.

## Consequences

- All BYOC CLI commands, placement targets, state records, and tags for ECS use `aliyun-ecs`.
- Any future Alibaba Cloud managed sandbox provider must pick a distinct `[a-z0-9-_]` location name such as `aliyun-sandbox` or `aliyun-agent-sandbox`.
