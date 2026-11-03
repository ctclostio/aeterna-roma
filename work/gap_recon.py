#!/usr/bin/env python3
"""Read-only reconnaissance of the documented code-recovery gaps.

Compares the named classification corpus against the Ghidra function index and
the canonical export, then inspects the bytes at every missing address to
classify the prologue shape.  Writes work/gap_recon.tsv and prints a summary.

No Ghidra access; safe to run alongside any writer.
"""
from __future__ import annotations

import re
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
INDEX = ROOT / "src_out" / "empire.retail.dll" / "function_index.txt"
CANON = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"
WORK = ROOT / "work"
ADDR_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{6,8})\t")

REGISTRAR_MISSING = """
0x100d38b0 0x100e1470 0x100e16f0 0x100e8410 0x100e8550 0x100e85e0
0x100e8660 0x100e8760 0x100e8810 0x100e8bb0 0x100e8be0 0x100e8c00 0x100e8d40
0x100e8df0 0x100e8e10 0x100e8e50 0x100e9230 0x100e9270 0x100e9490 0x100ea040
""".split()


def load_pe():
    data = DLL.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe_off + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    sec0 = coff + 20 + opt_size
    image_base = struct.unpack_from("<I", data, coff + 20 + 28)[0]
    secs = []
    for i in range(nsec):
        o = sec0 + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append({"name": name, "va": va, "vsz": vsz, "roff": roff,
                     "rsz": rsz, "chars": chars})
    return data, image_base, secs


def rva2off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsz"], s["rsz"]):
            return s["roff"] + (rva - s["va"])
    return None


def load_named():
    named = {}
    for path in sorted(WORK.glob("funcid_*.tsv")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = ADDR_RE.match(line)
            if not m:
                continue
            f = line.split("\t")
            if len(f) > 1 and f[1]:
                named[int(m.group(1), 16)] = f[1]
    return named


def load_index():
    addrs = set()
    for line in INDEX.read_text(encoding="utf-8", errors="replace").splitlines():
        f = line.split("\t")
        if f and f[0].startswith("0x"):
            addrs.add(int(f[0], 16))
    return addrs


def load_canonical():
    addrs = set()
    for i, line in enumerate(CANON.read_text(encoding="utf-8", errors="replace").splitlines()):
        if i == 0:
            continue
        f = line.split("\t")
        if f and f[0]:
            addrs.add(int(f[0], 16))
    return addrs


def main():
    data, image_base, secs = load_pe()
    text = [s for s in secs if s["name"] == ".text"]
    print("image base 0x%08x" % image_base)
    for s in secs:
        print("  %-8s va=0x%08x vsz=0x%08x rsz=0x%08x chars=0x%08x" %
              (s["name"], s["va"], s["vsz"], s["rsz"], s["chars"]))

    named = load_named()
    index = load_index()
    canon = load_canonical()
    print("named corpus addresses: %d" % len(named))
    print("function_index entries: %d" % len(index))
    print("canonical entries:      %d" % len(canon))

    # The report's gap definition: named addresses in .text that appear in
    # neither index nor canonical export.
    def in_text(va):
        rva = va - image_base
        return any(s["va"] <= rva < s["va"] + s["vsz"] for s in text)

    dangling = sorted(a for a in named if in_text(a) and a not in index and a not in canon)
    print("dangling named .text addresses: %d" % len(dangling))
    only_index = sorted(a for a in named if in_text(a) and a in index and a not in canon)
    only_canon = sorted(a for a in named if in_text(a) and a in canon and a not in index)
    print("named in index but not canonical: %d" % len(only_index))
    print("named in canonical but not index: %d" % len(only_canon))

    missing_registrar = [int(x, 16) for x in REGISTRAR_MISSING]
    print("registrar missing still missing: %d / %d" %
          (sum(1 for a in missing_registrar if a not in canon), len(missing_registrar)))
    for a in missing_registrar:
        print("  0x%08x canon=%s index=%s named=%s" %
              (a, a in canon, a in index, named.get(a, "")))

    # Classify prologue bytes at each dangling address.
    shapes = Counter()
    rows = []
    for va in dangling:
        off = rva2off(secs, va - image_base)
        b = data[off:off + 24] if off is not None else b""
        hexs = b.hex(" ")
        shape = "other"
        if b[:1] == b"\x51" and b[1:2] == b"\x6a":
            shape = "push_ecx_push_imm"
        elif b[:1] == b"\x55" and b[1:2] == b"\x8b":
            shape = "push_ebp_mov_ebp"
        elif b[:1] == b"\x55":
            shape = "push_ebp"
        elif b[:1] == b"\x53":
            shape = "push_ebx"
        elif b[:1] == b"\x56":
            shape = "push_esi"
        elif b[:1] == b"\x57":
            shape = "push_edi"
        elif b[:1] == b"\x8b":
            shape = "mov"
        elif b[:1] == b"\x6a":
            shape = "push_imm"
        elif b[:1] == b"\xe9":
            shape = "jmp_rel32"
        elif b[:1] == b"\xcc":
            shape = "int3"
        elif b[:1] == b"\xc3":
            shape = "ret"
        shapes[shape] += 1
        rows.append((va, named.get(va, ""), shape, hexs))

    print("prologue shapes:")
    for k, v in shapes.most_common():
        print("  %-24s %d" % (k, v))

    out = WORK / "gap_recon.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("address\tname\tprologue_shape\tbytes\n")
        for va, name, shape, hexs in rows:
            fh.write("0x%08x\t%s\t%s\t%s\n" % (va, name, shape, hexs))
    print("wrote %s (%d rows)" % (out, len(rows)))

    # Also emit the registrar list with current status.
    out2 = WORK / "gap_registrar_status.tsv"
    with out2.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("address\tin_index\tin_canonical\tname\tbytes\n")
        for va in missing_registrar:
            off = rva2off(secs, va - image_base)
            b = data[off:off + 16] if off is not None else b""
            fh.write("0x%08x\t%d\t%d\t%s\t%s\n" %
                     (va, va in index, va in canon, named.get(va, ""), b.hex(" ")))
    print("wrote %s" % out2)


if __name__ == "__main__":
    sys.exit(main())
