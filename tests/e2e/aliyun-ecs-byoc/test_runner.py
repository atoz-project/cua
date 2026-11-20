#!/usr/bin/env python3
"""Unit tests for scenarios.json integrity and run.py orchestration logic."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
