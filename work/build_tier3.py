#!/usr/bin/env python3
"""Build recovery wave 3: remaining data-table function pointers.

After waves 1 (named addresses) and 2 (runs referenced by .rdata/.data tables),
a handful of table-referenced runs remain because the first pass filtered on a
buggy run length.  This wave selects every remaining run whose start is a
.rdata/.data/_RDATA pointer target, has a real length of at least 5 bytes, and
ends in RET or JMP.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"


def main() -> int:
    runs = list(csv.DictReader(
        (WORK / "undefined_classified_after_tier2.tsv").open(encoding="utf-8"),
        delimiter="\t"))
    pointers = list(csv.DictReader(
        (WORK / "code_pointer_targets.tsv").open(encoding="utf-8"),
        delimiter="\t"))

    table_targets: dict[int, list[str]] = {}
    for row in pointers:
        if row["in_index"] == "1" or row["in_gap"] == "1":
            continue
        if row["source_section"] == ".text":
            continue
        target = int(row["target"], 16)
        table_targets.setdefault(target, []).append(
            f'{row["source"]}:{row["source_section"]}')

    selected = []
    for run in runs:
        start = int(run["start"], 16)
        if start not in table_targets:
            continue
        prev_max = run["prev_function_max"]
        if prev_max and start <= int(prev_max, 16):
            continue
        if run["has_ret"] != "1" and run["last_mnemonic"] != "JMP":
            continue
        if int(run["size"]) < 5:
            continue
        selected.append((start, table_targets[start]))

    selected.sort()
    out = WORK / "gap_addresses_tier3.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("address\tname\tsource\tprologue_shape\n")
        for start, sources in selected:
            fh.write("0x%08x\t\ttable_pointer:%s\t%s\n" % (
                start, sources[0], "table"))
    print(f"selected remaining table runs: {len(selected)}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
