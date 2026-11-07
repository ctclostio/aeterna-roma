#!/usr/bin/env python3
"""Post-export acceptance checks for the 2026-11 code-recovery wave.

Verifies the canonical index and the per-function C files for every recovered
address, plus the 20 startup registrar handlers.  Read-only.
"""
from __future__ import annotations

import csv
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "src_canonical_out" / "empire.retail.dll"
INDEX = CANON / "canonical_function_index.tsv"
DECOMP = CANON / "canonical_decomp"
SNAPSHOT = CANON / "canonical_snapshot.tsv"
STATUS = CANON / "canonical_export_status.tsv"
WORK = ROOT / "work"

WAVES = [
    ("wave1", WORK / "gap_addresses.tsv"),
    ("wave2", WORK / "gap_addresses_tier2.tsv"),
    ("wave3", WORK / "gap_addresses_tier3.tsv"),
]


def read_addresses(path: Path):
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if f and f[0]:
            out.append(int(f[0], 16))
    return out


def main() -> int:
    failures = []
    index = {}
    for i, line in enumerate(INDEX.read_text(encoding="utf-8", errors="replace").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if not f or not f[0]:
            continue
        entry = int(f[0], 16)
        if entry in index:
            failures.append(f"duplicate index entry 0x{entry:08x}")
        index[entry] = f

    snapshot = SNAPSHOT.read_text(encoding="utf-8").splitlines()
    print("snapshot:", snapshot[1] if len(snapshot) > 1 else "MISSING")
    status = STATUS.read_text(encoding="utf-8").splitlines()
    print("status:", status[1] if len(status) > 1 else "MISSING")

    total_checked = 0
    missing = []
    failed = []
    for wave, path in WAVES:
        addrs = read_addresses(path)
        print(f"{wave}: {len(addrs)} addresses")
        for addr in addrs:
            total_checked += 1
            if addr not in index:
                missing.append((wave, addr))
                continue
            cfile = DECOMP / f"decomp_fn_{addr:08x}.c"
            if not cfile.exists():
                failed.append((wave, addr, "missing file"))
                continue
            text = cfile.read_text(encoding="utf-8", errors="replace")
            if "// Export result: success" not in text:
                failed.append((wave, addr, "not success"))

    # Wave 4 lives in a different report shape.
    wave4 = WORK / "gap_undisassembled_apply.tsv"
    if wave4.exists():
        rows = [r for r in csv.DictReader(wave4.open(encoding="utf-8"), delimiter="\t")
                if r.get("status") == "created"]
        print(f"wave4: {len(rows)} addresses")
        for r in rows:
            addr = int(r["start"], 16)
            total_checked += 1
            if addr not in index:
                missing.append(("wave4", addr))
                continue
            cfile = DECOMP / f"decomp_fn_{addr:08x}.c"
            if not cfile.exists():
                failed.append(("wave4", addr, "missing file"))
                continue
            text = cfile.read_text(encoding="utf-8", errors="replace")
            if "// Export result: success" not in text:
                failed.append(("wave4", addr, "not success"))

    handlers = []
    gap = WORK / "gap_addresses.tsv"
    for i, line in enumerate(gap.read_text(encoding="utf-8").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if len(f) >= 3 and f[2] == "registrar_handler":
            handlers.append(int(f[0], 16))
    print(f"registrar handlers: {len(handlers)}")
    for addr in handlers:
        if addr not in index:
            missing.append(("handler", addr))

    print(f"checked: {total_checked} recovered addresses")
    print(f"missing from index: {len(missing)}")
    print(f"missing/failed C files: {len(failed)}")
    for item in missing[:20]:
        print("  missing", item)
    for item in failed[:20]:
        print("  failed", item)

    if len(index) != 81280:
        failures.append(f"canonical index has {len(index)} entries, expected 81280")
    if missing or failed:
        failures.append("recovered addresses did not all resolve")
    if len(handlers) != 20:
        failures.append(f"expected 20 registrar handlers, found {len(handlers)}")

    if failures:
        print("FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
