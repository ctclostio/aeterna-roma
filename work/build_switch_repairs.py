#!/usr/bin/env python3
"""Build the manual switch-table repair worklist from the jumptable warnings.

Only `JMP dword ptr [reg*4 + table]` instructions are true switch tables.  The
other jumptable warnings are virtual dispatch or IAT thunks.
"""
from __future__ import annotations

import csv
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"


def load_pe():
    data = DLL.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt = struct.unpack_from("<H", data, coff + 16)[0]
    s0 = coff + 20 + opt
    base = struct.unpack_from("<I", data, coff + 20 + 28)[0]
    secs = []
    for i in range(nsec):
        o = s0 + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode()
        vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
        secs.append((name, base + va, base + va + max(vsz, rsz), roff))
    return data, base, secs


def main() -> int:
    data, base, secs = load_pe()
    text_lo = base + 0x1000
    text_hi = base + 0x172e4ea

    def off(va):
        for _n, lo, hi, roff in secs:
            if lo <= va < hi:
                return roff + (va - lo)
        return None

    def u32(va):
        o = off(va)
        return struct.unpack_from("<I", data, o)[0] if o is not None else None

    rows = list(csv.DictReader(
        (WORK / "_jumptable_dump.tsv").open(encoding="utf-8"), delimiter="\t"))
    out = []
    for row in rows:
        instruction = row["instruction"]
        if "*0x4" not in instruction:
            continue
        match = re.search(r"\+\s*0x([0-9a-f]+)\]", instruction)
        if not match:
            continue
        table = int(match.group(1), 16)
        targets = []
        for i in range(256):
            value = u32(table + 4 * i)
            if value is None or not (text_lo <= value < text_hi):
                break
            targets.append(value)
        out.append((int(row["function_entry"], 16),
                    int(row["address"], 16), table, targets))

    path = WORK / "switch_table_repairs.tsv"
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("function_entry\tjump_address\ttable_address\tentries\ttargets\n")
        for function, jump, table, targets in out:
            fh.write("0x%08x\t0x%08x\t0x%08x\t%d\t%s\n" % (
                function, jump, table, len(targets),
                ",".join("0x%08x" % t for t in targets)))
    print(f"true switch tables: {len(out)}")
    print(f"functions: {len({r[0] for r in out})}")
    print(f"total entries: {sum(len(r[3]) for r in out)}")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
