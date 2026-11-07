#!/usr/bin/env python3
"""Run source/fixture tests without requiring the original game or local exports.

The original-byte provenance suite remains available through unittest discovery.
No unavailable original image is replaced with fabricated evidence in public CI.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_ONLY = {
    "test_pi_startup_abi_evidence_gate_v2": "requires local canonical decompilations",
    "test_x64_startup_100ec5c0_return_domain": "reads the original game image",
}


def main() -> int:
    sys.path.insert(0, str(ROOT / "scripts"))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for path in sorted((ROOT / "scripts").glob("test_*.py")):
        reason = LOCAL_ONLY.get(path.stem)
        if path.stem.endswith("_provenance"):
            reason = "requires the original game, local canonical exports or private reports"
        if reason:
            print(f"Local-only suite: {path.name}: {reason}", flush=True)
            continue
        suite.addTests(loader.loadTestsFromName(path.stem))
    suite.addTests(loader.discover(str(ROOT / "tests"), pattern="test_*.py"))
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        return 1
    if not suite.countTestCases():
        print("No public tests discovered", file=sys.stderr)
        return 1
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
