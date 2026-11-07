#!/usr/bin/env python3
"""Summarize the recovered functions by address band, size and name."""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"
INDEX = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"

WAVES = [
    ("wave1_named", WORK / "gap_apply.tsv"),
    ("wave2_table", WORK / "gap_tier2_apply.tsv"),
    ("wave3_table", WORK / "gap_tier3_apply.tsv"),
    ("wave4_undisassembled", WORK / "gap_undisassembled_apply.tsv"),
]


def read_wave(path: Path):
    out = []
    for r in csv.DictReader(path.open(encoding="utf-8"), delimiter="\t"):
        status = r.get("status", "")
        if status not in ("created", "function_exists"):
            continue
        addr = r.get("address") or r.get("start")
        if not addr:
            continue
        out.append(int(addr, 16))
    return out


def main() -> int:
    index = {}
    for r in csv.DictReader(INDEX.open(encoding="utf-8"), delimiter="\t"):
        index[int(r["entry"], 16)] = r

    all_recovered = []
    for wave, path in WAVES:
        addrs = read_wave(path)
        print(f"{wave}: {len(addrs)}")
        all_recovered.extend(addrs)
    all_recovered = sorted(set(all_recovered))
    print(f"unique recovered: {len(all_recovered)}")

    bands = Counter()
    for addr in all_recovered:
        bands[f"0x{addr >> 20 << 20:08x}"] += 1
    print("address bands:")
    for band, count in sorted(bands.items()):
        print(f"  {band}: {count}")

    sizes = [int(index[a]["size"]) for a in all_recovered if a in index]
    print("size min/max/avg:", min(sizes), max(sizes), round(sum(sizes) / len(sizes), 1))
    buckets = Counter()
    for s in sizes:
        if s <= 16:
            buckets["<=16 (thunk/leaf)"] += 1
        elif s <= 64:
            buckets["17-64"] += 1
        elif s <= 256:
            buckets["65-256"] += 1
        elif s <= 1024:
            buckets["257-1024"] += 1
        elif s <= 8192:
            buckets["1025-8192"] += 1
        else:
            buckets[">8192"] += 1
    print("size buckets:")
    for k, v in buckets.items():
        print(f"  {k}: {v}")

    named = sum(1 for a in all_recovered
                if a in index and not index[a]["original_name"].startswith("FUN_"))
    print(f"recovered with a non-default name: {named}")

    print("largest recovered:")
    for a in sorted(all_recovered, key=lambda a: -int(index[a]["size"]))[:20]:
        print(f"  0x{a:08x} {index[a]['size']:>7} {index[a]['original_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
