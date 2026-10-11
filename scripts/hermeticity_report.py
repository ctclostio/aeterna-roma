#!/usr/bin/env python3
"""Report which parts of the test suite are hermetic.

The suite is not runnable on a clean clone.  Roughly a quarter of it reads
local artifacts that `.gitignore` excludes: the copyrighted game binary, the
canonical export under `src_canonical_out/`, and frozen swarm fixtures under
`out/pi-swarm/`.  Before this was measured, a clean checkout reported 249
errors that were indistinguishable from real regressions.

This tool classifies each test module by the artifacts it needs, so CI scope
and local-vs-CI parity are a decision rather than a guess.  It performs static
inspection only -- it does not execute the suite.

Usage:
    py -3.15 scripts/hermeticity_report.py [--json]

Exit status is 0 even when non-hermetic modules exist; the report is advisory.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# Artifact -> the path that must exist for the module to run.
ARTIFACTS = {
    "game-dll": "Total War Rome II/empire.retail.dll",
    "canonical-export": "src_canonical_out/empire.retail.dll",
    "decomp-export": "src_out/empire.retail.dll",
    "canonical-stage": "generated/canonical",
    "swarm-fixtures": "out/pi-swarm",
}

# Files that reference an artifact path or read it directly.
PROBE = re.compile(
    r"Total War Rome II/empire\.retail\.dll"
    r"|src_canonical_out"
    r"|src_out"
    r"|generated/canonical"
    r"|out/pi-swarm",
    re.IGNORECASE,
)


def classify(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    hits = []
    for key, needle in ARTIFACTS.items():
        if PROBE.search(text) and needle.split("/")[0] in text:
            hits.append(key)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    presence = {k: (ROOT / v).exists() for k, v in ARTIFACTS.items()}

    rows = []
    for mod in sorted(SCRIPTS.glob("test_*.py")):
        needs = classify(mod)
        rows.append(
            {
                "module": mod.name,
                "hermetic": not needs,
                "needs": needs,
                "runnable_here": all(presence[k] for k in needs),
            }
        )

    hermetic = [r for r in rows if r["hermetic"]]
    blocked = [r for r in rows if not r["hermetic"]]
    runnable = [r for r in rows if r["runnable_here"]]

    if args.as_json:
        print(
            json.dumps(
                {
                    "artifact_presence": presence,
                    "modules": rows,
                    "summary": {
                        "total": len(rows),
                        "hermetic": len(hermetic),
                        "artifact_dependent": len(blocked),
                        "runnable_in_this_checkout": len(runnable),
                    },
                },
                indent=2,
            )
        )
        return 0

    print("artifact presence in this checkout:")
    for k, v in ARTIFACTS.items():
        print("  %-18s %s" % (k, "present" if presence[k] else "ABSENT"))
    print()
    print(
        "modules: %d total | %d hermetic | %d need local artifacts | "
        "%d runnable here"
        % (len(rows), len(hermetic), len(blocked), len(runnable))
    )
    print()
    print("artifact-dependent modules (must be excluded from CI or fed fixtures):")
    by_need: dict[str, list[str]] = {}
    for r in blocked:
        by_need.setdefault(",".join(r["needs"]), []).append(r["module"])
    for need, mods in sorted(by_need.items()):
        print("  [%s] %d module(s)" % (need, len(mods)))
        for m in mods:
            print("      %s" % m)
    print()
    print("Hermetic modules can run anywhere and are the CI candidate set.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
