import struct
from pathlib import Path
p = Path(r'X:\decompilation\Total War Rome II\empire.retail.dll')
d = p.read_bytes()
pe = struct.unpack_from('<I', d, 0x3c)[0]
coff = pe + 4
nsec = struct.unpack_from('<H', d, coff + 2)[0]
opt = struct.unpack_from('<H', d, coff + 16)[0]
s0 = coff + 20 + opt
base = struct.unpack_from('<I', d, coff + 20 + 28)[0]
secs = []
for i in range(nsec):
    o = s0 + i * 40
    name = d[o:o + 8].rstrip(b'\0').decode()
    vsz, va, rsz, roff = struct.unpack_from('<IIII', d, o + 8)
    secs.append((name, va, vsz, roff, rsz))


def off(va):
    rva = va - base
    for n, va0, vsz, roff, rsz in secs:
        if va0 <= rva < va0 + max(vsz, rsz):
            return roff + rva - va0


for va in (0x10004f20, 0x10005110, 0x100052c0, 0x100d38b0, 0x100e1470, 0x100e9490, 0x100e8410):
    o = off(va)
    b = d[o:o + 192]
    print(hex(va), b.hex(' '))
