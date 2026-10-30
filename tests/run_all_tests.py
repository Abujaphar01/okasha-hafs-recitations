#!/usr/bin/env python3
"""
Master E2E Test Suite Runner for Okasha Hafs Platform.
Executes the comprehensive 4-Tier test suite:
  Tier 1: Feature Coverage (Manifest, WebView, WebKit, CSP, Tailwind, SW Origin, Cache Sync, Hygiene)
  Tier 2: Boundary & Corner Cases (Navigation interception, Cross-origin cache, Malformed range, CSP)
  Tier 3: Cross-Feature Interactions (Offline range audio, Virtual origin + SW, Sync, Back navigation)
  Tier 4: Real-World Scenarios (Android assembleDebug, Localhost HTTP serving, Audio range streaming)

Usage:
  python tests/run_all_tests.py [--all] [--tier {1,2,3,4}] [--verbose] [--json]
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

# Ensure tests directory is in sys.path
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

import test_tier1_feature_coverage
import test_tier2_boundary_corner
import test_tier3_cross_feature
import test_tier4_real_world


def get_tier_suite(tier: int) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    if tier == 1:
        return loader.loadTestsFromModule(test_tier1_feature_coverage)
    elif tier == 2:
        return loader.loadTestsFromModule(test_tier2_boundary_corner)
    elif tier == 3:
        return loader.loadTestsFromModule(test_tier3_cross_feature)
    elif tier == 4:
        return loader.loadTestsFromModule(test_tier4_real_world)
    else:
        raise ValueError(f"Unknown tier: {tier}")


def run_tier(tier: int, verbosity: int = 1) -> tuple[int, int, int, float, list[dict[str, str]]]:
    suite = get_tier_suite(tier)
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=verbosity)
    start_time = time.time()
    result = runner.run(suite)
    duration = time.time() - start_time

    errors = []
    for test, err in result.failures:
        errors.append({"test": str(test), "type": "FAILURE", "detail": err})
    for test, err in result.errors:
        errors.append({"test": str(test), "type": "ERROR", "detail": err})

    return (
        result.testsRun,
        result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        len(result.failures) + len(result.errors),
        duration,
        errors,
    )


def main():
    parser = argparse.ArgumentParser(description="Okasha Hafs Platform 4-Tier Test Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run specific tier only")
    parser.add_argument("--all", action="store_true", default=True, help="Run all 4 tiers (default)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose test execution")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    selected_tiers = [args.tier] if args.tier else [1, 2, 3, 4]

    tier_names = {
        1: "Tier 1: Feature Coverage (Static, Manifest, WebView, CSP, SW)",
        2: "Tier 2: Boundary & Corner Cases (Interception, Cache, Range, CSP)",
        3: "Tier 3: Cross-Feature Interactions (Offline 206, Virtual Origin, Sync)",
        4: "Tier 4: Real-World Scenarios (Android Build, Localhost HTTP, Audio)",
    }

    results: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tiers": {},
        "summary": {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "duration_seconds": 0.0,
            "success": True,
        },
    }

    if not args.json:
        print("=" * 76)
        print(" OKASHA HAFS PLATFORM — 4-TIER E2E SECURITY & INTEGRATION TEST SUITE")
        print("=" * 76)

    overall_success = True
    total_start = time.time()

    for t in selected_tiers:
        tier_title = tier_names[t]
        if not args.json:
            print(f"\n[RUNNING] {tier_title}...")

        run_count, pass_count, fail_count, duration, failures = run_tier(t, verbosity=2 if args.verbose else 1)

        results["tiers"][f"tier_{t}"] = {
            "name": tier_title,
            "tests_run": run_count,
            "passed": pass_count,
            "failed": fail_count,
            "duration": round(duration, 3),
            "failures": failures,
        }

        results["summary"]["total_tests"] += run_count
        results["summary"]["passed"] += pass_count
        results["summary"]["failed"] += fail_count

        if fail_count > 0:
            overall_success = False

        if not args.json:
            status_badge = "PASS" if fail_count == 0 else "FAIL"
            print(f"[{status_badge}] {tier_title}: {pass_count}/{run_count} passed ({round(duration, 2)}s)")
            if failures:
                for f in failures:
                    print(f"   x {f['test']} - {f['type']}")
                    for line in f['detail'].strip().split("\n")[-3:]:
                        print(f"     {line}")

    total_duration = time.time() - total_start
    results["summary"]["duration_seconds"] = round(total_duration, 3)
    results["summary"]["success"] = overall_success

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "=" * 76)
        print(" FINAL TEST SUMMARY")
        print("=" * 76)
        print(f" Total Tests Executed : {results['summary']['total_tests']}")
        print(f" Total Passed         : {results['summary']['passed']}")
        print(f" Total Failed         : {results['summary']['failed']}")
        print(f" Total Duration       : {round(total_duration, 2)} seconds")
        print(f" Overall Result       : {'PASSED (0 ERRORS)' if overall_success else 'FAILED'}")
        print("=" * 76)

    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()
