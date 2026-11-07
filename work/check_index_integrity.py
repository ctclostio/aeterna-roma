#!/usr/bin/env python3
"""Structural integrity checks for the new canonical function index."""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"
TEXT_LO = 0x10001000
TEXT_HI = 0x1172E5FF


def parse_ranges(text: str):
    out = []
    for part in (text or "").split(","):
        if not part:
            continue
        lo, hi = part.split("-")
        out.append((int(lo, 16), int(hi, 16)))
    return out


def main() -> int:
    rows = list(csv.DictReader(INDEX.open(encoding="utf-8"), delimiter="\t"))
    print("rows:", len(rows))
    entries = [int(r["entry"], 16) for r in rows]
    names = [r["canonical_name"] for r in rows]
    print("unique entries:", len(set(entries)))
    print("unique canonical names:", len(set(names)))
    print("zero size:", sum(1 for r in rows if int(r["size"]) == 0))
    print("outside text:", sum(1 for r in rows if not (TEXT_LO <= int(r["entry"], 16) <= TEXT_HI)))

    ranges = []
    for r in rows:
        for lo, hi in parse_ranges(r["body_ranges"]):
            ranges.append((lo, hi, r["entry"]))
    ranges.sort()
    overlaps = []
    for i in range(1, len(ranges)):
        if ranges[i][0] <= ranges[i - 1][1]:
            overlaps.append((ranges[i - 1], ranges[i]))
    print("body ranges:", len(ranges))
    print("overlaps:", len(overlaps))
    for o in overlaps[:5]:
        print("  ", o)
    outside = sum(1 for lo, hi, _ in ranges if lo < TEXT_LO or hi > TEXT_HI)
    print("outside text ranges:", outside)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
