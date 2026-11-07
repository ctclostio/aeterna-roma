#!/usr/bin/env python3
"""Build the consolidated gap-recovery address list.

Inputs:
  work/gap_recon.tsv         1,973 named .text addresses with no function
  work/gap_registrar_status.tsv  20 registrar handlers with no function

Output:
  work/gap_addresses.tsv     address, proposed name, source, prologue shape
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"


def main() -> int:
    rows = []
    seen = set()

    recon = WORK / "gap_recon.tsv"
    for i, line in enumerate(recon.read_text(encoding="utf-8").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if len(f) < 4:
            continue
        addr, name, shape = f[0], f[1], f[2]
        key = int(addr, 16)
        if key in seen:
            raise SystemExit(f"duplicate address in recon: {addr}")
        seen.add(key)
        rows.append((key, addr, name, "environment_variables", shape))

    reg = WORK / "gap_registrar_status.tsv"
    for i, line in enumerate(reg.read_text(encoding="utf-8").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if len(f) < 5:
            continue
        addr, in_index, in_canon, name, _bytes = f[:5]
        if in_index == "1" or in_canon == "1":
            continue
        key = int(addr, 16)
        if key in seen:
            raise SystemExit(f"duplicate address across sources: {addr}")
        seen.add(key)
        rows.append((key, addr, name, "registrar_handler", "handler"))

    rows.sort(key=lambda r: r[0])
    out = WORK / "gap_addresses.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("address\tname\tsource\tprologue_shape\n")
        for _key, addr, name, source, shape in rows:
            fh.write(f"{addr}\t{name}\t{source}\t{shape}\n")
    print(f"wrote {out} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
