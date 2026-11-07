#!/usr/bin/env python3
"""Consolidate the recovery waves and check body-range overlaps."""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"

WAVES = [
    ("wave1_named", "gap_apply.tsv"),
    ("wave2_table", "gap_tier2_apply.tsv"),
    ("wave3_table", "gap_tier3_apply.tsv"),
    ("wave4_undisassembled", "gap_undisassembled_apply.tsv"),
]


def parse_ranges(text: str):
    out = []
    for part in (text or "").split(","):
        if not part:
            continue
        lo, hi = part.split("-")
        out.append((int(lo, 16), int(hi, 16)))
    return out


def main() -> int:
    rows = []
    for wave, name in WAVES:
        path = WORK / name
        if not path.exists():
            print(f"missing {path}")
            continue
        for r in csv.DictReader(path.open(encoding="utf-8"), delimiter="\t"):
            status = r.get("status", "")
            if status not in ("created", "function_exists"):
                continue
            addr_text = r.get("address") or r.get("start")
            if not addr_text:
                continue
            body = r.get("body_ranges", "")
            for lo, hi in parse_ranges(body):
                rows.append((wave, int(addr_text, 16), lo, hi, r.get("size", "")))

    print("created body ranges:", len(rows))
    print("by wave:", Counter(r[0] for r in rows))

    # Check overlaps among recovered ranges.
    rows.sort(key=lambda r: (r[2], r[3]))
    overlaps = []
    active = []
    for wave, addr, lo, hi, size in rows:
        active = [a for a in active if a[3] >= lo]
        for a in active:
            if a[2] <= hi:
                overlaps.append((a, (wave, addr, lo, hi, size)))
        active.append((wave, addr, lo, hi, size))
    print("overlaps among recovered ranges:", len(overlaps))
    for o in overlaps[:10]:
        print("  ", o)

    # Check against the pre-recovery canonical index.
    old = {}
    index = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"
    for r in csv.DictReader(index.open(encoding="utf-8"), delimiter="\t"):
        for lo, hi in parse_ranges(r["body_ranges"]):
            old[(lo, hi)] = r["entry"]
    old_sorted = sorted(old)
    old_starts = [x[0] for x in old_sorted]
    import bisect
    old_overlaps = []
    for wave, addr, lo, hi, size in rows:
        pos = bisect.bisect_right(old_starts, hi)
        idx = pos - 1
        while idx >= 0:
            olo, ohi = old_sorted[idx]
            if ohi >= lo:
                old_overlaps.append((wave, addr, lo, hi, old[(olo, ohi)]))
            if olo < lo - 0x20000:
                break
            idx -= 1
    print("overlaps with pre-recovery index:", len(old_overlaps))
    for o in old_overlaps[:10]:
        print("  ", o)

    out = WORK / "recovery_all.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("wave\taddress\tbody_start\tbody_end\tsize\n")
        for row in rows:
            fh.write("%s\t0x%08x\t0x%08x\t0x%08x\t%s\n" % row)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
