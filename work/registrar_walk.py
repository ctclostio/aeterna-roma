#!/usr/bin/env python3
"""Resolve the app_init registrar hubs in empire.retail.dll and walk the call
graph outward from them.

Track 3 of the Rome II port.  The engine compiles essentially /GR-, so vtable
*class names* are unavailable (see work/rtti_scan.py and
docs/engine_architecture.md).  What survives is the vtable *slot data* itself:
the registrar hub at 0x100ea060 installs 23 vtable pointers through the
append helper FUN_100e2460, and those pointers lead straight to the concrete
handler addresses that the startup path depends on.  That gives a grounded
root set to traverse from, which is what this tool builds.

Outputs (written next to the repo root):
  work/registrar_roots.tsv    hub VA, slot symbol, vtable VA, slot index, fn VA
  work/registrar_reach.tsv    fn VA, depth, parent VA, edge kind, via-root
  work/registrar_unreached.tsv  decompiled functions not reached (named only)
"""
import re
import struct
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / 'Total War Rome II' / 'empire.retail.dll'
DECOMP = ROOT / 'src_out' / 'empire.retail.dll' / 'decomp'
INDEX = ROOT / 'src_out' / 'empire.retail.dll' / 'function_index.txt'

HUB = 0x100ea060
MAX_DEPTH = int(sys.argv[1]) if len(sys.argv) > 1 else 3


def load_pe():
    data = DLL.read_bytes()
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    coff = pe_off + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff + 16)[0]
    sec0 = coff + 20 + opt_size
    image_base = struct.unpack_from('<I', data, coff + 20 + 28)[0]
    secs = []
    for i in range(nsec):
        o = sec0 + i * 40
        name = data[o:o + 8].rstrip(b'\0').decode()
        vsz, va, rsz, roff = struct.unpack_from('<IIII', data, o + 8)
        secs.append((name, va, vsz, roff, rsz))
    return data, image_base, secs


def make_rva2off(secs):
    def rva2off(rva):
        for _n, va, vsz, roff, rsz in secs:
            if va <= rva < va + max(vsz, rsz):
                return roff + (rva - va)
        return None
    return rva2off


def read_u32(data, rva2off, va):
    off = rva2off(va - IMAGE_BASE)
    if off is None or off + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, off)[0]


def text_ranges(secs):
    return [(IMAGE_BASE + va, vsz) for n, va, vsz, _r, _rs in secs if n == '.text']


def in_text(p, ranges):
    return any(lo <= p < lo + sz for lo, sz in ranges)


def main():
    global IMAGE_BASE
    data, IMAGE_BASE, secs = load_pe()
    rva2off = make_rva2off(secs)
    tranges = text_ranges(secs)

    hub_c = DECOMP / f'{HUB:08x}_FUN_{HUB:08x}.c'
    if not hub_c.exists():
        cands = list(DECOMP.glob(f'{HUB:08x}_*.c'))
        if not cands:
            raise SystemExit(f'hub decompilation not found: {hub_c}')
        hub_c = cands[0]
    hub_src = hub_c.read_text(encoding='utf-8', errors='replace')

    slots = re.findall(r'\*puVar3 = &(PTR_\w+)', hub_src)
    print(f'hub 0x{HUB:x}: {len(slots)} vtable installations')

    roots = []
    with open(ROOT / 'work' / 'registrar_roots.tsv', 'w', encoding='utf8') as f:
        for order, sym in enumerate(slots):
            addr = int(sym.split('_')[-1], 16)

            # Ghidra renders the vtable symbol itself as PTR_<name> and the
            # hub does `*obj = &PTR_<name>`, so `addr` is already the vtable
            # base.  Fall back to a dereference only if the direct read yields
            # no in-.text slots.
            def slots_at(base):
                out = []
                i = 0
                while True:
                    p = read_u32(data, rva2off, base + 4 * i)
                    if p is None or not in_text(p, tranges):
                        break
                    out.append(p)
                    i += 1
                return out

            vt = addr
            fns = slots_at(vt)
            if not fns:
                deref = read_u32(data, rva2off, addr)
                if deref is not None:
                    fns = slots_at(deref)
                    vt = deref
            if not fns:
                f.write(f'0x{HUB:x}\t{order:02d}\t{sym}\t0x{vt:x}\t-\tnone\n')
                continue
            for idx, fn in enumerate(fns):
                roots.append((order, sym, vt, idx, fn))
                f.write(f'0x{HUB:x}\t{order:02d}\t{sym}\t0x{vt:x}\t{idx}\t0x{fn:x}\n')

    root_fns = {r[4] for r in roots}
    print(f'resolved {len(roots)} handler slots across '
          f'{len({r[0] for r in roots})} vtables; '
          f'{len(root_fns)} distinct handler functions')

    idx_map = {}
    if INDEX.exists():
        for line in INDEX.read_text(encoding='utf-8', errors='replace').splitlines():
            p = line.split('\t')
            if len(p) >= 2 and p[0].startswith('0x'):
                idx_map[int(p[0], 16)] = p[1]

    known = set()
    for cand in (ROOT / 'work').glob('funcid_*.tsv'):
        for line in cand.read_text(encoding='utf-8', errors='replace').splitlines():
            p = line.split('\t')
            if p and re.fullmatch(r'0x[0-9a-fA-F]+', p[0]):
                known.add(int(p[0], 16))

    print(f'index: {len(idx_map)} functions; already-named: {len(known)}')

    call_re = re.compile(r'\b(FUN_([0-9a-f]{8}))\s*\(')
    data_cache = {}

    def decomp_of(va):
        if va in data_cache:
            return data_cache[va]
        path = DECOMP / f'{va:08x}_{idx_map.get(va, "FUN_%08x" % va)}.c'
        txt = None
        if path.exists():
            txt = path.read_text(encoding='utf-8', errors='replace')
        elif not path.exists():
            cands = list(DECOMP.glob(f'{va:08x}_*.c'))
            if cands:
                txt = cands[0].read_text(encoding='utf-8', errors='replace')
        data_cache[va] = txt
        return txt

    seen = {}
    order_out = []
    q = deque()
    for r in sorted(root_fns):
        seen[r] = 0
        q.append((r, None, 'root', r))

    while q:
        va, parent, kind, via = q.popleft()
        d = seen[va]
        order_out.append((va, d, parent, kind, via))
        if d >= MAX_DEPTH:
            continue
        txt = decomp_of(va)
        if not txt:
            continue
        callees = []
        for _full, hexaddr in call_re.findall(txt):
            t = int(hexaddr, 16)
            if t == va or not in_text(t, tranges):
                continue
            if t not in seen:
                callees.append(t)
        for t in dict.fromkeys(callees):
            if t not in seen:
                seen[t] = d + 1
                q.append((t, va, 'call', via))

    by_depth = {}
    for va, d, _p, _k, _v in order_out:
        by_depth[d] = by_depth.get(d, 0) + 1
    print(f'reached {len(seen)} functions within depth {MAX_DEPTH}: {by_depth}')

    fresh = {v for v in seen if v not in known}
    print(f'  of which unnamed by funcid: {len(fresh)}')

    with open(ROOT / 'work' / 'registrar_reach.tsv', 'w', encoding='utf8') as f:
        f.write('addr\tname\tdepth\tparent\tedge\tvia_root\n')
        for va, d, parent, kind, via in sorted(order_out, key=lambda r: (r[1], r[0])):
            f.write(f'0x{va:x}\t{idx_map.get(va, "")}\t{d}\t'
                    f'{("0x%x" % parent) if parent else "-"}\t{kind}\t0x{via:x}\n')

    with open(ROOT / 'work' / 'registrar_unreached.tsv', 'w', encoding='utf8') as f:
        for va in sorted(idx_map):
            if va not in seen:
                f.write(f'0x{va:x}\t{idx_map[va]}\n')

    print(f'wrote registrar_roots.tsv, registrar_reach.tsv, '
          f'registrar_unreached.tsv ({len(idx_map) - len(seen)} unreachable)')


if __name__ == '__main__':
    main()
