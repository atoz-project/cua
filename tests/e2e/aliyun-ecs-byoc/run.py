#!/usr/bin/env python3
"""Run the aliyun-ecs BYOC E2E test suite (baseline, hermetic, live)."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

SUITE = Path(__file__).resolve().parent
REPO = SUITE.parents[2]
RUST_DIR = SUITE / "rust"
MANIFEST = RUST_DIR / "Cargo.toml"
LIBS_CUA_MANIFEST = REPO / "libs" / "cua" / "Cargo.toml"
CUA_DEFAULT_BIN = REPO / "libs" / "cua" / "target" / "debug" / "cua"

TIER_FILES = {
    1: "tier1_feature_coverage",
    2: "tier2_boundary_negative",
    3: "tier3_cross_feature",
    4: "tier4_scenarios",
}

TEST_LINE_RE = re.compile(r"^test\s+([A-Za-z0-9_:]+)\s+\.\.\.\s+(ok|FAILED|ignored)\b")


def raise_open_file_limit(want: int = 10240) -> None:
    """Ensure RLIMIT_NOFILE is >= 10240 when permitted by the OS hard limit."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY or soft >= want:
            return
        target = want if hard == resource.RLIM_INFINITY else min(want, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ImportError, ValueError, OSError):
        pass


def load_scenarios(path: Path | None = None) -> dict:
    target = path or (SUITE / "scenarios.json")
    return json.loads(target.read_text(encoding="utf-8"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--lanes",
        default="hermetic",
        help="comma-separated lanes: baseline, hermetic, live",
    )
    ap.add_argument(
        "--tier",
        type=int,
        choices=[1, 2, 3, 4],
        default=None,
        help="restrict hermetic execution to a single tier (1..4)",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="fail on any missing scenario, unexpected skip/ignored, or failed test",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="results directory (default: temporary directory under TMPDIR/RUNNER_TEMP)",
    )
    ap.add_argument(
        "--profile",
        default=os.environ.get("CUA_E2E_ALIYUN_PROFILE") or os.environ.get("ALIYUN_PROFILE"),
        help="aliyun CLI AK-mode profile name (required for --lanes live)",
    )
    ap.add_argument(
        "--region",
        default=os.environ.get("CUA_E2E_ALIYUN_REGION") or "cn-hangzhou",
        help="Alibaba Cloud region for --lanes live (default: cn-hangzhou)",
    )
    ap.add_argument(
        "--no-build",
        action="store_true",
        help="skip building cua CLI when CUA_BIN is already set",
    )
    ap.add_argument(
        "--run",
        default=os.environ.get("CUA_E2E_RUN") or secrets.token_hex(4),
        help="unique run identifier",
    )
    ap.add_argument(
        "--owner",
        default=os.environ.get("CUA_E2E_SMOKE_OWNER"),
        help="cua-owner tag value for detecting shared VPC/VSwitch/SG leaks in --lanes live",
    )
    return ap.parse_args(argv)


def build_cua_cli(env: dict[str, str], skip_if_present: bool = False) -> Path:
    explicit = env.get("CUA_BIN")
    if explicit and skip_if_present and Path(explicit).exists():
        return Path(explicit)
    cmd = [
        "cargo",
        "build",
        "--manifest-path",
        str(LIBS_CUA_MANIFEST),
        "-p",
        "cua-cli",
        "--features",
        "byoc",
        "--bin",
        "cua",
    ]
    print(f"$ {' '.join(cmd)}", flush=True)
    res = subprocess.run(cmd, env=env, cwd=REPO)
    if res.returncode != 0:
        raise SystemExit(f"failed to build cua CLI (exit {res.returncode})")
    if not CUA_DEFAULT_BIN.exists():
        raise SystemExit(f"expected cua binary at {CUA_DEFAULT_BIN}")
    return CUA_DEFAULT_BIN


def parse_cargo_test_output(stdout: str, stderr: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for line in f"{stdout}\n{stderr}".splitlines():
        m = TEST_LINE_RE.match(line.strip())
        if not m:
            continue
        name = m.group(1).split("::")[-1]
        raw_status = m.group(2)
        if raw_status == "ok":
            results[name] = "pass"
        elif raw_status == "FAILED":
            results[name] = "fail"
        else:
            results[name] = "skip"
    return results


def expected_scenarios(reg: dict, lanes: list[str], tier: int | None) -> list[dict]:
    wanted: list[dict] = []
    for sc in reg["scenarios"]:
        sc_lane = sc["lane"]
        in_lane = (
            sc_lane in lanes
            or ("hermetic" in lanes and sc_lane == "baseline")
            or ("live" in lanes and sc_lane == "live")
        )
        if not in_lane:
            continue
        if tier is not None and sc_lane != "live" and sc["tier"] != tier:
            continue
        wanted.append(sc)
    return wanted


def evaluate_results(
    expected: list[dict], observed: dict[str, str], strict: bool
) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    problems: list[str] = []
    for sc in expected:
        test_name = sc["test_name"]
        status = observed.get(test_name, "missing")
        rows.append(
            {
                "id": sc["id"],
                "feature": sc["feature"],
                "tier": sc["tier"],
                "milestone": sc["milestone"],
                "lane": sc["lane"],
                "test_name": test_name,
                "status": status,
            }
        )
        if status == "fail":
            problems.append(f"fail: {sc['id']} ({test_name})")
        elif strict and status in ("skip", "missing"):
            problems.append(f"strict {status}: {sc['id']} ({test_name})")
    return rows, problems


def render_reports(out: Path, rows: list[dict], run_id: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# aliyun-ecs BYOC E2E Results (run {run_id})",
        "",
        "| ID | Feature | Tier | Milestone | Lane | Test | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['id']} | {r['feature']} | {r['tier']} | {r['milestone']} "
            f"| {r['lane']} | `{r['test_name']}` | {r['status']} |"
        )
    (out / "matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _extract_tags(item: dict) -> dict[str, str]:
    tags: dict[str, str] = {}
    raw_tags = item.get("Tags", {})
    tag_list = raw_tags.get("Tag", []) if isinstance(raw_tags, dict) else raw_tags
    if not isinstance(tag_list, list):
        return tags
    for t in tag_list:
        if not isinstance(t, dict):
            continue
        k = t.get("TagKey") or t.get("Key")
        v = t.get("TagValue") or t.get("Value")
        if isinstance(k, str) and isinstance(v, str):
            tags[k] = v
    return tags


def _is_e2e_leaked_resource(item: dict, run_id: str, owner: str | None = None) -> bool:
    tags = _extract_tags(item)
    if tags.get("cua-managed") != "true":
        return False
    space = tags.get("cua-space", "")
    created_by = tags.get("cua-created-by", "")
    res_owner = tags.get("cua-owner", "")
    if space.startswith(f"cua-e2e-{run_id}-") or created_by == f"cua-e2e-{run_id}":
        return True
    if owner and res_owner == owner:
        return True
    name = (
        item.get("SecurityGroupName")
        or item.get("VpcName")
        or item.get("InstanceName")
        or ""
    )
    if name in ("cua-sandboxes-dryrun", "cua-sb-dryrun"):
        return True
    if not space and not created_by and not res_owner:
        return True
    return False


def check_aliyun_leaks(
    profile: str,
    region: str,
    run_id: str,
    owner: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    page_size: int = 50,
) -> list[str]:
    """Query Alibaba Cloud via aliyun CLI for any leftover E2E-tagged resources."""
    if not shutil.which("aliyun") and runner is subprocess.run:
        return ["aliyun CLI not found on PATH for post-teardown leak verification"]

    queries = [
        (
            "instance",
            ["aliyun", "ecs", "DescribeInstances", "--profile", profile, "--RegionId", region],
            ("Instances", "Instance"),
            "InstanceId",
        ),
        (
            "vpc",
            ["aliyun", "vpc", "DescribeVpcs", "--profile", profile, "--RegionId", region],
            ("Vpcs", "Vpc"),
            "VpcId",
        ),
        (
            "vswitch",
            ["aliyun", "vpc", "DescribeVSwitches", "--profile", profile, "--RegionId", region],
            ("VSwitches", "VSwitch"),
            "VSwitchId",
        ),
        (
            "security_group",
            [
                "aliyun",
                "ecs",
                "DescribeSecurityGroups",
                "--profile",
                profile,
                "--RegionId",
                region,
            ],
            ("SecurityGroups", "SecurityGroup"),
            "SecurityGroupId",
        ),
    ]
    leaks: list[str] = []
    for kind, base_cmd, path_keys, id_key in queries:
        page = 1
        seen = 0
        while page <= 200:
            cmd = [*base_cmd, "--PageSize", str(page_size), "--PageNumber", str(page)]
            proc = runner(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                leaks.append(
                    f"leak check command failed ({' '.join(cmd)}): "
                    f"{proc.stderr.strip() or proc.stdout.strip()}"
                )
                break
            try:
                payload = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError as exc:
                leaks.append(f"invalid JSON from {' '.join(cmd)}: {exc}")
                break
            node = payload
            for k in path_keys:
                node = node.get(k, {}) if isinstance(node, dict) else {}
            items = node if isinstance(node, list) else []
            for item in items:
                if isinstance(item, dict) and _is_e2e_leaked_resource(item, run_id, owner):
                    rid = item.get(id_key, "<unknown>")
                    leaks.append(f"leaked {kind}: {rid} (run {run_id})")
            seen += len(items)
            total_count = payload.get("TotalCount") if isinstance(payload, dict) else None
            if not items:
                break
            if isinstance(total_count, int):
                if seen >= total_count:
                    break
            elif len(items) < page_size:
                break
            page += 1
    return leaks


def run_cargo_test(args: list[str], env: dict[str, str]) -> tuple[int, dict[str, str]]:
    cmd = [
        "cargo",
        "test",
        "--locked",
        "--manifest-path",
        str(MANIFEST),
        *args,
    ]
    print(f"$ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, env=env, cwd=RUST_DIR, capture_output=True, text=True)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode, parse_cargo_test_output(proc.stdout, proc.stderr)


def run_baseline_lane(
    expected: list[dict], env: dict[str, str]
) -> tuple[int, dict[str, str]]:
    unit_cmd = [sys.executable, "-m", "unittest", str(SUITE / "test_runner.py")]
    print(f"$ {' '.join(unit_cmd)}", flush=True)
    unit_rc = subprocess.run(unit_cmd, env=env, cwd=REPO).returncode

    by_file: dict[str, list[str]] = {}
    for sc in expected:
        by_file.setdefault(sc["test_file"], []).append(sc["test_name"])

    observed: dict[str, str] = {}
    rc = unit_rc
    for test_file, names in sorted(by_file.items()):
        for name in names:
            step_rc, parsed = run_cargo_test(
                ["--test", test_file, "--", "--exact", name, "--nocapture"],
                env,
            )
            observed.update(parsed)
            rc = rc or step_rc
    return rc, observed


def run_hermetic_lane(
    tier: int | None, env: dict[str, str]
) -> tuple[int, dict[str, str]]:
    if tier is not None:
        files = [TIER_FILES[tier]]
    else:
        files = [TIER_FILES[t] for t in sorted(TIER_FILES)]
    observed: dict[str, str] = {}
    rc = 0
    for test_file in files:
        step_rc, parsed = run_cargo_test(
            ["--test", test_file, "--", "--test-threads=2"],
            env,
        )
        observed.update(parsed)
        rc = rc or step_rc
    return rc, observed


def run_live_lane(
    profile: str | None,
    region: str,
    run_id: str,
    env: dict[str, str],
    owner: str | None = None,
    out: Path | None = None,
) -> tuple[int, dict[str, str], list[str]]:
    if not profile:
        raise SystemExit(
            "--lanes live requires --profile <aliyun-ak-profile> (or CUA_E2E_ALIYUN_PROFILE)"
        )
    owner_file = (out / "smoke-owner.txt") if out else (Path("/tmp") / f"cua-owner-{run_id}.txt")
    live_env = dict(
        env,
        CUA_E2E_ALIYUN_LIVE="1",
        CUA_E2E_ALIYUN_PROFILE=profile,
        CUA_E2E_ALIYUN_REGION=region,
        CUA_E2E_RUN=run_id,
        CUA_E2E_OWNER_FILE=str(owner_file),
    )
    rc = 1
    observed: dict[str, str] = {}
    leaks: list[str] = []
    try:
        rc, observed = run_cargo_test(
            ["--test", "live_ecs_smoke", "--", "--ignored", "--nocapture", "--test-threads=1"],
            live_env,
        )
    finally:
        smoke_owner = owner
        if not smoke_owner and owner_file.exists():
            smoke_owner = owner_file.read_text(encoding="utf-8").strip() or None
        leaks = check_aliyun_leaks(profile, region, run_id, owner=smoke_owner)
        if leaks:
            print("POST-TEARDOWN LEAK CHECK FAILED:", file=sys.stderr)
            for leak in leaks:
                print(f"  - {leak}", file=sys.stderr)
    return rc, observed, leaks


def main(argv: list[str] | None = None) -> int:
    raise_open_file_limit()
    args = parse_args(argv)
    lanes = [x.strip() for x in args.lanes.split(",") if x.strip()]
    valid_lanes = {"baseline", "hermetic", "live"}
    unknown = [lane for lane in lanes if lane not in valid_lanes]
    if not lanes or unknown:
        raise SystemExit(f"invalid --lanes {args.lanes!r}; expected baseline|hermetic|live")
    if "live" in lanes and not args.profile:
        raise SystemExit(
            "--lanes live requires --profile <aliyun-ak-profile> (or CUA_E2E_ALIYUN_PROFILE)"
        )

    reg = load_scenarios()
    out = (
        args.out.resolve()
        if args.out
        else Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/tmp")
        / f"aliyun-ecs-e2e-{args.run}"
    )

    env = dict(os.environ)
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    if cargo_bin not in env.get("PATH", "").split(os.pathsep):
        env["PATH"] = f"{cargo_bin}{os.pathsep}{env.get('PATH', '')}"

    cua_bin = build_cua_cli(env, skip_if_present=args.no_build)
    env["CUA_BIN"] = str(cua_bin)
    env["CUA_E2E_RUN"] = args.run

    t0 = time.monotonic()
    observed: dict[str, str] = {}
    exit_code = 0
    live_leaks: list[str] = []

    if "baseline" in lanes and "hermetic" not in lanes:
        baseline_expected = expected_scenarios(reg, ["baseline"], args.tier)
        rc, obs = run_baseline_lane(baseline_expected, env)
        observed.update(obs)
        exit_code = exit_code or rc

    if "hermetic" in lanes:
        rc, obs = run_hermetic_lane(args.tier, env)
        observed.update(obs)
        exit_code = exit_code or rc

    if "live" in lanes:
        rc, obs, live_leaks = run_live_lane(
            args.profile, args.region, args.run, env, owner=args.owner, out=out
        )
        observed.update(obs)
        exit_code = exit_code or rc

    expected = expected_scenarios(reg, lanes, args.tier)
    rows, problems = evaluate_results(expected, observed, args.strict)
    problems.extend(live_leaks)
    render_reports(out, rows, args.run)

    elapsed = time.monotonic() - t0
    passed = sum(1 for r in rows if r["status"] == "pass")
    print(f"\nCompleted {passed}/{len(rows)} scenarios in {elapsed:.1f}s -> {out}")
    if problems:
        print("PROBLEMS:", file=sys.stderr)
        for prob in problems:
            print(f"  - {prob}", file=sys.stderr)
        return 1
    return 1 if exit_code != 0 else 0


if __name__ == "__main__":
    sys.exit(main())
