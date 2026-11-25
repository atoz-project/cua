---
status: accepted
---

# 0004. Unify Static Relay Spaces on relay:<machine-id>

Previously, `cua spaces add` with a Static Relay `/m/<machine-id>` URL persisted the entry under `direct:<relay-host>:<port>` because upstream equated `relay:<machine-id>` with OIDC account-directory Computers, causing multi-machine collisions on the same relay host and plaintext HTTP token leaks in `cua sb`. Meanwhile, BYOC Static Relay provisioning (`cloud.rs`) persisted equivalent Spaces under `relay:<machine-id>`. Separating **reachability** (`direct:` vs `relay:`) from **domain role** (`Space` vs account `Computer`), we decided to unify all Static Relay Spaces on `relay:<machine-id>` paired with local `Credential { url, token }` storage, falling back to `direct:<host>:<port>` only for non-spacesd MCP endpoints.

## Considered Options

- **Keep `direct:<host>:<port>` for `cua spaces add` and patch downstream consumers**: Rejected because the `direct:` grammar forbids path segments, making multi-machine identification behind a single relay authority impossible.
- **Introduce an origin-qualified ref variant (such as `relay:<host>/<machine-id>`)**: Rejected because it breaks `valid_machine_id` and slash-free invariants across Rust, Python, TypeScript, daemon, and UI codebases as well as existing BYOC `relay:cloud-<hex>` records.

## Consequences

- **Single persisted Static Relay format**: Both `cua spaces add https://<relay>/m/<machine-id> --token <tok>` and BYOC Static Relay `cua spaces create` store `relay:<machine-id>` in `spaces.json` with `Credential { url, token }` in `spaces-credentials.json`, re-adding the same `<machine-id>` updates its stored URL, token, and name idempotently, and `SpaceId::Direct`'s duplicated `Via::Static` relay branch is removed without legacy migration shims.
- **Mandatory per-Space token on manual Static Relay add**: `cua spaces add` with a `/m/<machine-id>` URL requires a non-empty `--token` (or `CUA_ENV_TOKEN`), preventing unauthenticated exposure and keeping `token: Some` (Static Relay) unambiguous against `token: None` (custom Account Relay).
- **Ordinary Space semantics in UI and CLI**: Static Relay `relay:<machine-id>` entries represent ordinary `Space`s rather than account `Computer`s, so Desktop and Web UIs render them in the Spaces list instead of the account Computers/Machines page, exempt them from unenrolled account-device lockouts, isolate them from account-directory `share`/unregister calls, and reject `--host` on `/m/<machine-id>` URLs before writing `spaces.json`.
