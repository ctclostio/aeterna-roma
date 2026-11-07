#!/usr/bin/env python3
"""Scan the recovered functions' canonical C files for export/decompiler defects."""
from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECOMP = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
WORK = ROOT / "work"

WAVES = [
    ("wave1", WORK / "gap_apply.tsv"),
    ("wave2", WORK / "gap_tier2_apply.tsv"),
    ("wave3", WORK / "gap_tier3_apply.tsv"),
    ("wave4", WORK / "gap_undisassembled_apply.tsv"),
]

WARNING_RE = re.compile(r"/\* WARNING: (.+?) \*/")


def addrs(path: Path):
    out = []
    for r in csv.DictReader(path.open(encoding="utf-8"), delimiter="\t"):
        if r.get("status") not in ("created", "function_exists"):
            continue
        a = r.get("address") or r.get("start")
        if a:
            out.append(int(a, 16))
    return out


def main() -> int:
    rows = []
    for wave, path in WAVES:
        for addr in addrs(path):
            cfile = DECOMP / f"decomp_fn_{addr:08x}.c"
            if not cfile.exists():
                rows.append((wave, addr, "missing_file", ""))
                continue
            text = cfile.read_text(encoding="utf-8", errors="replace")
            if "// Export result: success" not in text:
                rows.append((wave, addr, "export_not_success", ""))
                continue
            warnings = WARNING_RE.findall(text)
            for warning in warnings:
                rows.append((wave, addr, "warning", warning))
            if "halt_baddata()" in text:
                rows.append((wave, addr, "halt_baddata", ""))
            body = text.split("// Export result: success", 1)[-1]
            if "{" not in body or "}" not in body:
                rows.append((wave, addr, "no_body", ""))

    path = WORK / "recovered_defects.tsv"
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("wave\taddress\tcategory\tdetail\n")
        for wave, addr, category, detail in rows:
            fh.write("%s\t0x%08x\t%s\t%s\n" % (wave, addr, category, detail.replace("\t", " ")))
    print("rows:", len(rows))
    print("categories:", Counter(r[2] for r in rows))
    print("waves:", Counter(r[0] for r in rows))
    print("wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
