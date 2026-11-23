# Alibaba Cloud ECS (`aliyun-ecs`) BYOC E2E Test Suite

Opaque-box, requirement-driven 4-tier E2E test suite plus opt-in live ECS smoke verification for the `aliyun-ecs` BYOC provider and per-connection self-hosted relay.

## Canonical Vocabulary

- **Provider Location**: `aliyun-ecs` (reserving `aliyun-sandbox` / `aliyun-agent-sandbox` for future managed services per ADR-0001).
- **Cloud Image ID**: Vendor OS image ID (`m-xxx` or official OS image ID).
- **Sandbox Image**: Cua workload family (`linux`, `linux-slim`, `windows`).
- **Direct VM Sandbox**: Single-sandbox VM running `cua-spacesd` directly on the guest OS (`--runtime native`, ADR-0002).
- **Docker-on-VM Sandbox**: Single-sandbox Linux VM running Docker to host one container (`--runtime docker`).
- **Account Relay Mode**: User account authentication with `cmt_` machine tokens, JWKS, and enrolled device sessions (ADR-0003).
- **Static Relay Mode**: Shared registration `relay_token` and per-sandbox `env_token` bearer authentication with zero `cua auth login` (ADR-0003).

## Lanes

| Lane | Gate / Requirements | Scope |
|---|---|---|
| `baseline` | None (hermetic) | Feature 1 (`#2`) auth, `cloud test/connect/status/disconnect`, live-guard, and `test_runner.py` |
| `hermetic` | None (hermetic) | All 96 Tiers 1–4 scenarios across Features F1–F8 (`AliyunConnectProxy` + `FakeAliyun` + `FakeRelay` + `FakeMirror`) |
| `live` | `--profile <name>` + `CUA_E2E_ALIYUN_LIVE=1` | Real Alibaba Cloud ECS smoke test (`#9`) + post-teardown `aliyun` CLI resource leak check |

## Environment Variables

- `CUA_BIN`: Optional path to prebuilt `cua` binary (otherwise `run.py` builds `libs/cua` with `-p cua-cli --features byoc --bin cua`).
- `CUA_E2E_ALIYUN_LIVE=1`: Explicit opt-in required for `live_ecs_smoke`.
- `CUA_E2E_ALIYUN_PROFILE`: Default `aliyun` CLI AK-mode profile for `--lanes live` (e.g. `oauth` or `webhook_manager`).
- `CUA_E2E_ALIYUN_REGION`: Region for `--lanes live` (default `cn-hangzhou`).
- `CUA_E2E_RUN`: Unique per-run tag prefix for live leak detection.

## Commands

```bash
# Runner unit tests
python3 -m unittest tests/e2e/aliyun-ecs-byoc/test_runner.py

# Baseline lane (Feature 1 / #2 checks + runner tests)
python3 tests/e2e/aliyun-ecs-byoc/run.py --lanes baseline --strict

# Full hermetic 4-tier suite (96 scenarios)
python3 tests/e2e/aliyun-ecs-byoc/run.py --lanes hermetic --strict

# Single tier
python3 tests/e2e/aliyun-ecs-byoc/run.py --lanes hermetic --tier 1 --strict

# Opt-in live Alibaba Cloud ECS smoke test + post-teardown leak check
python3 tests/e2e/aliyun-ecs-byoc/run.py --lanes live --profile oauth --region cn-hangzhou
```
