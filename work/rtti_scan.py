#!/usr/bin/env python3
"""Scan empire.retail.dll for MSVC x86 RTTI: type descriptors, complete object
locators, vftables. Output:
  work/rtti_classes.tsv        vftable VA -> class name, entry count
  work/rtti_vtable_slots.tsv   member-fn VA -> class, slot, vftable VA
"""
import struct, re
from pathlib import Path

DLL = Path('../Total War Rome II/empire.retail.dll')
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
    name = data[o:o+8].rstrip(b'\0').decode()
    vsz, va, rsz, roff = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, va, vsz, roff, rsz))

def rva2off(rva):
    for n, va, vsz, roff, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return roff + (rva - va)
    return None

# --- 1. type descriptors -------------------------------------------------
name_re = re.compile(rb'\.\?A[VBUWE][\x20-\x7e]{1,180}?@@\x00')
td_by_va = {}
for n, sva, vsz, roff, rsz in secs:
    if rsz == 0:
        continue
    blob = data[roff:roff+rsz]
    for m in name_re.finditer(blob):
        raw = m.group()[:-1].decode('ascii')
        td_rva = sva + m.start() - 8          # name starts at TD+8 (vfptr,spare)
        if td_rva >= 0:
            td_by_va[image_base + td_rva] = raw
print('type descriptors:', len(td_by_va))

def demangle(nm):
    s = re.sub(r'^\.\\?A', '.?A', nm)
    s = s.replace('.?AV', 'class ').replace('.?AU', 'struct ')
    s = s.replace('.?AW', 'enum ').replace('.?AB', 'union ')
    s = s.replace('@', '::').rstrip(':')
    return s

# --- 2. complete object locators ----------------------------------------
col_to_class = {}
td_vas = set(td_by_va)
for n, sva, vsz, roff, rsz in secs:
    if rsz == 0 or n not in ('.rdata', '.data'):
        continue
    blob = data[roff:roff+rsz]
    for i in range(0, len(blob) - 20, 4):
        sig, off, cdoff, ptd, pcd = struct.unpack_from('<IIIII', blob, i)
        if sig == 0 and off == 0 and ptd in td_vas:
            col_va = image_base + sva + i
            col_to_class[col_va] = demangle(td_by_va[ptd])
print('COLs:', len(col_to_class))

# --- 3. vftables preceded by COL ref ------------------------------------
text_ranges = [(image_base + va, vsz) for n, va, vsz, roff, rsz in secs if n == '.text']
rd_n, rd_va, rd_vsz, rd_roff, rd_rsz = [s for s in secs if s[0] == '.rdata'][0]
blob = data[rd_roff:rd_roff+rd_rsz]
N = len(blob) // 4
fn_slots = {}
vftab_out = []
i = 0
while i < N - 1:
    pcol = struct.unpack_from('<I', blob, i * 4)[0]
    if pcol in col_to_class:
        j = i + 1
        while j < N:
            p = struct.unpack_from('<I', blob, j * 4)[0]
            if any(lo <= p < lo + sz for lo, sz in text_ranges):
                j += 1
            else:
                break
        cnt = j - (i + 1)
        if cnt >= 2:
            vt_va = image_base + rd_va + (i + 1) * 4
            cls = col_to_class[pcol]
            vftab_out.append((vt_va, cls, cnt))
            for k in range(cnt):
                fp = struct.unpack_from('<I', blob, (i + 1 + k) * 4)[0]
                fn_slots.setdefault(fp, []).append((vt_va, cls, k))
        i = j
    else:
        i += 1

with open('rtti_classes.tsv', 'w', encoding='utf8') as f:
    for vt, cls, cnt in sorted(vftab_out):
        f.write(f'0x{vt:x}\t{cls}\t{cnt}\n')
with open('rtti_vtable_slots.tsv', 'w', encoding='utf8') as f:
    for fn in sorted(fn_slots):
        vt, cls, slot = fn_slots[fn][0]
        f.write(f'0x{fn:x}\t{cls}\tslot{slot}\t0x{vt:x}\n')
print('vftables:', len(vftab_out), ' member fns mapped:', len(fn_slots))
