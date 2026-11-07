#!/usr/bin/env python3
"""Scan PE data sections for dwords that point into .text.

Function-pointer tables (vtables, dispatch tables, callbacks) are the strongest
evidence that an undefined .text address is a real function entry.  This tool
does not touch Ghidra; it produces the candidate list that the Ghidra recovery
pass validates.
"""
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
INDEX = ROOT / "src_out" / "empire.retail.dll" / "function_index.txt"
WORK = ROOT / "work"


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
        name = data[o:o + 8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append({"name": name, "va": va, "vsz": vsz, "roff": roff,
                     "rsz": rsz, "chars": chars})
    return data, base, secs


def load_index():
    addrs = set()
    for line in INDEX.read_text(encoding="utf-8", errors="replace").splitlines():
        f = line.split("\t")
        if f and f[0].startswith("0x"):
            addrs.add(int(f[0], 16))
    return addrs


def load_gap():
    addrs = set()
    path = WORK / "gap_addresses.tsv"
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if f and f[0].startswith("0x"):
            addrs.add(int(f[0], 16))
    return addrs


def main():
    data, base, secs = load_pe()
    text = next(s for s in secs if s["name"] == ".text")
    text_lo = base + text["va"]
    text_hi = text_lo + text["vsz"]
    index = load_index()
    gap = load_gap()

    # Scan every data section, 4-byte aligned.
    hits = []
    for s in secs:
        if s["name"] not in (".rdata", ".data", "_RDATA", ".text"):
            continue
        off = s["roff"]
        end = off + s["rsz"]
        # Keep alignment relative to the section's virtual address.
        start = off + ((4 - (s["va"] % 4)) % 4)
        for o in range(start, end - 3, 4):
            value = struct.unpack_from("<I", data, o)[0]
            if text_lo <= value < text_hi:
                va = base + s["va"] + (o - off)
                hits.append((va, value, s["name"]))

    by_target = defaultdict(list)
    for va, target, secname in hits:
        by_target[target].append((va, secname))

    unknown = {t: src for t, src in by_target.items()
               if t not in index and t not in gap}
    known = {t: src for t, src in by_target.items()
             if t in index or t in gap}
    print(f"data dwords pointing into .text: {len(hits)}")
    print(f"unique targets: {len(by_target)}")
    print(f"already indexed or gap-listed: {len(known)}")
    print(f"unknown targets: {len(unknown)}")

    src_sections = Counter(sec for srcs in unknown.values() for _va, sec in srcs)
    print("unknown target source sections:", dict(src_sections))

    # A table-like source is one whose neighbours also point into .text.
    # Report the contiguous run length around each source for triage.
    out = WORK / "code_pointer_targets.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("target\tsource\tsource_section\tin_index\tin_gap\n")
        for target in sorted(by_target):
            for va, secname in by_target[target]:
                fh.write("0x%08x\t0x%08x\t%s\t%d\t%d\n" % (
                    target, va, secname, target in index, target in gap))
    print(f"wrote {out}")

    # Unknown targets that appear in at least two data locations are almost
    # certainly function-table entries, not incidental integers.
    multi = {t: src for t, src in unknown.items() if len(src) >= 2}
    print(f"unknown targets with >=2 pointer sources: {len(multi)}")

    out2 = WORK / "code_pointer_unknown.tsv"
    with out2.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("target\tsource_count\tsources\n")
        for target in sorted(unknown):
            srcs = unknown[target]
            fh.write("0x%08x\t%d\t%s\n" % (
                target, len(srcs),
                ",".join("0x%08x:%s" % (va, sec) for va, sec in srcs)))
    print(f"wrote {out2}")


if __name__ == "__main__":
    main()
