#!/usr/bin/env python3
"""Build the post-wave switch-table repair worklist.

21 addressed `JMP [reg*4+table]` warnings in 10 functions are joined by 8
selector-normalization failures in 6 functions.  The latter have no warning
address in the decompiler text but do contain real code jump tables.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"

# function entry -> number of real code jump-table sites, from
# work/decomp_defects_summary_after.md (instruction-level inspection).
NO_ADDRESS = {
    0x10A054B0: 2,
    0x10F1F890: 4,
    0x1130AA70: 2,
    0x114B7D80: 8,
    0x116B8EBC: 5,
    0x116BA4BA: 5,
}


def main() -> int:
    rows = []
    with (WORK / "switch_table_repairs.tsv").open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            rows.append((int(r["function_entry"], 16), "addressed_jump",
                         r["jump_address"], r["table_address"], r["entries"],
                         r["targets"], "21 addressed indexed jumps"))
    for entry, sites in sorted(NO_ADDRESS.items()):
        rows.append((entry, "selector_normalization", "", "", str(sites), "",
                     "no warning address; real code jump tables in body"))

    out = WORK / "switch_table_repairs_after.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("function_entry\tkind\tjump_address\ttable_address\tentries\ttargets\tnote\n")
        for row in rows:
            fh.write("0x%08x\t%s\t%s\t%s\t%s\t%s\t%s\n" % row)
    print("rows:", len(rows))
    print("functions:", len({r[0] for r in rows}))
    print("addressed jumps:", sum(1 for r in rows if r[1] == "addressed_jump"))
    print("no-address selector failures:", sum(1 for r in rows if r[1] == "selector_normalization"))
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
