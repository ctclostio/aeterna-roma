#!/usr/bin/env python3
"""Build the second recovery wave from undefined instruction runs.

Tier A: undefined runs whose start is the target of a function-pointer table in
.rdata/.data/_RDATA.  These are the strongest candidates: a data table points
at the address, the address is not inside any function, and the run is a
standalone instruction sequence ending in RET or JMP.

Output: work/gap_addresses_tier2.tsv (address, name, source, shape)
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"


def main() -> int:
    runs = list(csv.DictReader(
        (WORK / "undefined_classified.tsv").open(encoding="utf-8"),
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
    skipped_inside = 0
    skipped_no_terminal = 0
    skipped_tiny = 0
    for run in runs:
        start = int(run["start"], 16)
        if start not in table_targets:
            continue
        prev_max = run["prev_function_max"]
        if prev_max and start <= int(prev_max, 16):
            skipped_inside += 1
            continue
        if run["has_ret"] != "1" and run["last_mnemonic"] != "JMP":
            skipped_no_terminal += 1
            continue
        if int(run["size"]) < 5:
            skipped_tiny += 1
            continue
        selected.append((start, table_targets[start]))

    selected.sort()
    out = WORK / "gap_addresses_tier2.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("address\tname\tsource\tprologue_shape\n")
        for start, sources in selected:
            fh.write("0x%08x\t\ttable_pointer:%s\t%s\n" % (
                start, sources[0], "table"))
    print(f"table targets: {len(table_targets)}")
    print(f"selected runs: {len(selected)}")
    print(f"skipped inside prev range: {skipped_inside}")
    print(f"skipped no terminal: {skipped_no_terminal}")
    print(f"skipped tiny: {skipped_tiny}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
