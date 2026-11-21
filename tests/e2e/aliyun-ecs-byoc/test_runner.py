#!/usr/bin/env python3
"""Unit tests for scenarios.json integrity and run.py orchestration logic."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SUITE = Path(__file__).resolve().parent
sys.path.insert(0, str(SUITE))
import run  # noqa: E402


class ScenariosRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reg = run.load_scenarios()
        self.scenarios = self.reg["scenarios"]

    def test_hermetic_total_and_tier_thresholds(self) -> None:
        hermetic = [s for s in self.scenarios if s["lane"] != "live"]
        live = [s for s in self.scenarios if s["lane"] == "live"]
        self.assertEqual(len(hermetic), 96)
        self.assertGreaterEqual(len(hermetic), 93)
        self.assertEqual(len(live), 1)
        self.assertEqual(live[0]["id"], "LIVE-01")

        t1 = [s for s in hermetic if s["tier"] == 1]
        t2 = [s for s in hermetic if s["tier"] == 2]
        t3 = [s for s in hermetic if s["tier"] == 3]
        t4 = [s for s in hermetic if s["tier"] == 4]

        self.assertEqual(len(t1), 40)
        self.assertEqual(len(t2), 40)
        self.assertGreaterEqual(len(t3), 8)
        self.assertEqual(len(t3), 10)
        self.assertGreaterEqual(len(t4), 5)
        self.assertEqual(len(t4), 6)

        for feat_idx in range(1, 9):
            feat = f"F{feat_idx}"
            self.assertGreaterEqual(
                sum(1 for s in t1 if s["feature"] == feat),
                5,
                f"Tier 1 missing >= 5 tests for {feat}",
            )
            self.assertGreaterEqual(
                sum(1 for s in t2 if s["feature"] == feat),
                5,
                f"Tier 2 missing >= 5 tests for {feat}",
            )

    def test_unique_ids_and_required_fields(self) -> None:
        ids = [s["id"] for s in self.scenarios]
        names = [s["test_name"] for s in self.scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(names), len(set(names)))
        for sc in self.scenarios:
            for key in ("id", "feature", "tier", "milestone", "lane", "test_file", "test_name"):
                self.assertIn(key, sc)


class RunnerBehaviorTests(unittest.TestCase):
    def test_parse_args_supports_lanes_tier_strict_out_profile_region(self) -> None:
        ns = run.parse_args(
            [
                "--lanes",
                "baseline",
                "--tier",
                "2",
                "--strict",
                "--out",
                "/tmp/e2e-out",
                "--profile",
                "oauth",
                "--region",
                "cn-shanghai",
            ]
        )
        self.assertEqual(ns.lanes, "baseline")
        self.assertEqual(ns.tier, 2)
        self.assertTrue(ns.strict)
        self.assertEqual(ns.out, Path("/tmp/e2e-out"))
        self.assertEqual(ns.profile, "oauth")
        self.assertEqual(ns.region, "cn-shanghai")

    def test_strict_mode_fails_on_skip_and_missing(self) -> None:
        reg = run.load_scenarios()
        expected = run.expected_scenarios(reg, ["baseline"], None)
        observed = {sc["test_name"]: "pass" for sc in expected}
        observed[expected[0]["test_name"]] = "skip"
        observed.pop(expected[1]["test_name"])

        _, non_strict_problems = run.evaluate_results(expected, observed, strict=False)
        self.assertEqual(non_strict_problems, [])

        _, strict_problems = run.evaluate_results(expected, observed, strict=True)
        self.assertEqual(len(strict_problems), 2)
        self.assertTrue(any("strict skip" in p for p in strict_problems))
        self.assertTrue(any("strict missing" in p for p in strict_problems))

    def test_check_aliyun_leaks_detects_leftover_resources_with_mocked_subprocess(self) -> None:
        run_id = "abc123"

        def fake_runner_clean(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            action = cmd[2]
            if action == "DescribeInstances":
                body = json.dumps(
                    {
                        "Instances": {
                            "Instance": [
                                {
                                    "InstanceId": "i-unrelated",
                                    "Tags": {
                                        "Tag": [{"TagKey": "cua-managed", "TagValue": "false"}]
                                    },
                                },
                                {
                                    "InstanceId": "i-other-run",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "cua-managed", "TagValue": "true"},
                                            {"TagKey": "cua-space", "TagValue": "cua-e2e-other-1"},
                                        ]
                                    },
                                },
                            ]
                        }
                    }
                )
            else:
                body = "{}"
            return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

        self.assertEqual(
            run.check_aliyun_leaks("oauth", "cn-hangzhou", run_id, runner=fake_runner_clean),
            [],
        )

        def fake_runner_leaked(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            action = cmd[2]
            if action == "DescribeVpcs":
                body = json.dumps(
                    {
                        "Vpcs": {
                            "Vpc": [
                                {
                                    "VpcId": "vpc-leaked-1",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "cua-managed", "TagValue": "true"},
                                            {
                                                "TagKey": "cua-space",
                                                "TagValue": f"cua-e2e-{run_id}-box",
                                            },
                                        ]
                                    },
                                }
                            ]
                        }
                    }
                )
            else:
                body = "{}"
            return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

        leaks = run.check_aliyun_leaks("oauth", "cn-hangzhou", run_id, runner=fake_runner_leaked)
        self.assertEqual(len(leaks), 1)
        self.assertIn("vpc-leaked-1", leaks[0])

    def test_check_aliyun_leaks_paginates_and_matches_cua_owner_shared_resources(self) -> None:
        run_id = "run99"
        smoke_owner = "deadbeef12345678"
        seen_pages: list[int] = []

        def fake_paginated_runner(
            cmd: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess:
            action = cmd[2]
            page = int(cmd[cmd.index("--PageNumber") + 1])
            page_size = int(cmd[cmd.index("--PageSize") + 1])
            self.assertEqual(page_size, 50)
            if action == "DescribeInstances":
                seen_pages.append(page)
                if page < 3:
                    items = [{"InstanceId": f"i-ok-{page}-{i}"} for i in range(50)]
                else:
                    items = [
                        {"InstanceId": "i-ok-3-0"},
                        {
                            "InstanceId": "i-leaked-page3",
                            "Tags": {
                                "Tag": [
                                    {"TagKey": "cua-managed", "TagValue": "true"},
                                    {"TagKey": "cua-space", "TagValue": f"cua-e2e-{run_id}-ld"},
                                ]
                            },
                        },
                    ]
                body = json.dumps(
                    {"TotalCount": 102, "PageSize": 50, "Instances": {"Instance": items}}
                )
            elif action == "DescribeVpcs":
                body = json.dumps(
                    {
                        "TotalCount": 2,
                        "Vpcs": {
                            "Vpc": [
                                {
                                    "VpcId": "vpc-other-owner",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "cua-managed", "TagValue": "true"},
                                            {"TagKey": "cua-owner", "TagValue": "other999"},
                                            {"TagKey": "cua-created-by", "TagValue": "0-1-0"},
                                        ]
                                    },
                                },
                                {
                                    "VpcId": "vpc-shared-smoke",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "cua-managed", "TagValue": "true"},
                                            {"TagKey": "cua-owner", "TagValue": smoke_owner},
                                            {"TagKey": "cua-created-by", "TagValue": "0-1-0"},
                                        ]
                                    },
                                },
                            ]
                        },
                    }
                )
            elif action == "DescribeSecurityGroups":
                body = json.dumps(
                    {
                        "TotalCount": 1,
                        "SecurityGroups": {
                            "SecurityGroup": [
                                {
                                    "SecurityGroupId": "sg-shared-smoke",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "cua-managed", "TagValue": "true"},
                                            {"TagKey": "cua-owner", "TagValue": smoke_owner},
                                        ]
                                    },
                                }
                            ]
                        },
                    }
                )
            else:
                body = json.dumps({"TotalCount": 0})
            return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

        leaks = run.check_aliyun_leaks(
            "oauth",
            "cn-hangzhou",
            run_id,
            owner=smoke_owner,
            runner=fake_paginated_runner,
        )
        self.assertEqual(seen_pages, [1, 2, 3])
        self.assertEqual(len(leaks), 3)
        joined = "\n".join(leaks)
        self.assertIn("i-leaked-page3", joined)
        self.assertIn("vpc-shared-smoke", joined)
        self.assertIn("sg-shared-smoke", joined)
        self.assertNotIn("vpc-other-owner", joined)

    def test_check_aliyun_leaks_catches_dryrun_sg_and_ignores_permanent_relay(self) -> None:
        run_id = "run_dry"

        def fake_runner(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            action = cmd[2]
            if action == "DescribeInstances":
                body = json.dumps(
                    {
                        "TotalCount": 1,
                        "Instances": {
                            "Instance": [
                                {
                                    "InstanceId": "i-cua-relay-sg",
                                    "InstanceName": "cua-relay-sg",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "role", "TagValue": "cua-relay"},
                                            {"TagKey": "managed-by", "TagValue": "manual"},
                                        ]
                                    },
                                }
                            ]
                        },
                    }
                )
            elif action == "DescribeSecurityGroups":
                body = json.dumps(
                    {
                        "TotalCount": 3,
                        "SecurityGroups": {
                            "SecurityGroup": [
                                {
                                    "SecurityGroupId": "sg-cua-relay",
                                    "SecurityGroupName": "cua-relay-sg",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "role", "TagValue": "cua-relay"},
                                            {"TagKey": "managed-by", "TagValue": "manual"},
                                        ]
                                    },
                                },
                                {
                                    "SecurityGroupId": "sg-nodeskclaw",
                                    "SecurityGroupName": "nodeskclaw-sg",
                                    "Tags": {"Tag": []},
                                },
                                {
                                    "SecurityGroupId": "sg-dryrun-leak",
                                    "SecurityGroupName": "cua-sandboxes-dryrun",
                                    "Tags": {
                                        "Tag": [
                                            {"TagKey": "cua-managed", "TagValue": "true"},
                                        ]
                                    },
                                },
                            ]
                        },
                    }
                )
            else:
                body = json.dumps({"TotalCount": 0})
            return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

        leaks = run.check_aliyun_leaks("webhook_manager", "ap-southeast-1", run_id, runner=fake_runner)
        self.assertEqual(len(leaks), 1)
        self.assertIn("sg-dryrun-leak", leaks[0])

    def test_live_lane_validates_profile_before_building_cua_cli(self) -> None:
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("CUA_E2E_ALIYUN_PROFILE", "ALIYUN_PROFILE")
        }
        with (
            mock.patch.dict(os.environ, clean_env, clear=True),
            mock.patch.object(
                run,
                "build_cua_cli",
                side_effect=AssertionError("build_cua_cli must not be called without --profile"),
            ),
        ):
            with self.assertRaises(SystemExit) as ctx:
                run.main(["--lanes", "live"])
            self.assertIn("--profile", str(ctx.exception))

    def test_parse_cargo_test_output_handles_live_smoke_lines_and_stderr(self) -> None:
        ok_stdout = "running 1 test\ntest live_ecs_smoke ... ok\n\ntest result: ok. 1 passed;\n"
        fail_stdout = "running 1 test\ntest live_ecs_smoke ... FAILED\n\ntest result: FAILED.\n"
        diag_stderr = (
            "CUA_E2E_SMOKE_OWNER=97bce51b794adeb1\n"
            "[live_ecs_smoke] linux docker probe:\nLinux ...\n"
        )
        self.assertEqual(
            run.parse_cargo_test_output(ok_stdout, diag_stderr),
            {"live_ecs_smoke": "pass"},
        )
        self.assertEqual(
            run.parse_cargo_test_output(fail_stdout, diag_stderr),
            {"live_ecs_smoke": "fail"},
        )


if __name__ == "__main__":
    unittest.main()
