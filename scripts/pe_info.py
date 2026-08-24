#!/usr/bin/env python3
"""Extract PE metadata (exports, imports, sections) from PE32 binaries.
Usage: python pe_info.py <binary> [--out DIR]"""
import struct, sys, os, json
from pathlib import Path

def rva_to_off(pe_data, rva, sections):
    for name, vsize, vaddr, rawsize, rawoff in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            delta = rva - vaddr
            if delta < rawsize:
                return rawoff + delta
            return None
    return None

def cstr(data, off):
    end = data.find(b'\0', off)
    return data[off:end].decode('utf-8', 'replace') if end != -1 else ''

def main():
    path = Path(sys.argv[1])
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else path.parent / 'pe_meta'
    out_dir.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()

    e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
    assert data[e_lfanew:e_lfanew+4] == b'PE\0\0', "not PE"
    coff = e_lfanew + 4
    machine, nsec, _, _, _, optsz, _ = struct.unpack('<HHIIIHH', data[coff:coff+20])
    opt = coff + 20
    magic = struct.unpack('<H', data[opt:opt+2])[0]
    is_pe32p = magic == 0x20b
    entry_rva = struct.unpack('<I', data[opt+16:opt+20])[0]
    if is_pe32p:
        image_base = struct.unpack('<Q', data[opt+24:opt+32])[0]
        dd_off = opt + 112
    else:
        image_base = struct.unpack('<I', data[opt+28:opt+32])[0]
        dd_off = opt + 96
    n_dirs = struct.unpack('<I', data[dd_off-4:dd_off])[0]

    sec_off = opt + optsz
    sections = []
    for i in range(nsec):
        s = sec_off + i*40
        nm = data[s:s+8].rstrip(b'\0').decode('ascii','replace')
        vsize, vaddr, rawsize, rawoff = struct.unpack('<IIII', data[s+8:s+24])
        chars = struct.unpack('<I', data[s+36:s+40])[0]
        sections.append((nm, vsize, vaddr, rawsize, rawoff))
        print(f"  section {nm:<8} va=0x{vaddr:08x} vs=0x{vsize:06x} raw=0x{rawoff:08x}")

    print(f"Machine: {'x86' if machine==0x14c else hex(machine)}  PE32{'+' if is_pe32p else ''}  Entry RVA: 0x{entry_rva:x}  ImageBase: 0x{image_base:x}")
    print(f"Data directories: {n_dirs}")

    # Exports (dir 0)
    exports = []
    exp_rva = struct.unpack('<I', data[dd_off:dd_off+4])[0]
    if exp_rva:
        o = rva_to_off(data, exp_rva, sections)
        if o is not None:
            _, _, _, _, name_rva, base, nfun, nnames, afun_rva, aname_rva, aord_rva = struct.unpack('<IIHHIIIIIII', data[o:o+40])
            dll_name = cstr(data, rva_to_off(data, name_rva, sections)) if name_rva else ''
            print(f"Export DLL name: {dll_name}, functions={nfun}, names={nnames}")
            fo = rva_to_off(data, afun_rva, sections)
            no = rva_to_off(data, aname_rva, sections)
            oo = rva_to_off(data, aord_rva, sections)
            funcs = struct.unpack(f'<{nfun}I', data[fo:fo+4*nfun]) if fo else []
            names_offs = struct.unpack(f'<{nnames}I', data[no:no+4*nnames]) if no else []
            ords = struct.unpack(f'<{nnames}H', data[oo:oo+2*nnames]) if oo else []
            addr2name = {}
            names = []
            for i, noff in enumerate(names_offs):
                nm = cstr(data, rva_to_off(data, noff, sections))
                ord_idx = ords[i]
                if ord_idx < len(funcs):
                    addr2name[funcs[ord_idx]] = nm
                    names.append((hex(funcs[ord_idx]), nm))
            exports = names
            with open(out_dir / f"{path.stem}_exports.txt", 'w') as f:
                for a, n in sorted(addr2name.items()):
                    f.write(f"0x{a+image_base:08x}\t{n}\n")
            print(f"  -> wrote {len(exports)} named exports")

    # Imports (dir 1)
    imp_rva = struct.unpack('<I', data[dd_off+8:dd_off+12])[0]
    imports = {}
    if imp_rva:
        o = rva_to_off(data, imp_rva, sections)
        while o is not None and o+20 <= len(data):
            oft, tds, fc, name_rva, ft = struct.unpack('<IIIII', data[o:o+20])
            if name_rva == 0: break
            dll = cstr(data, rva_to_off(data, name_rva, sections))
            thunk_rva = oft or ft
            syms = []
            to = rva_to_off(data, thunk_rva, sections)
            while to:
                val = struct.unpack('<I', data[to:to+4])[0]
                if val == 0: break
                if val & 0x80000000:
                    syms.append(f"ord_{val & 0xffff}")
                else:
                    ho = rva_to_off(data, val & 0x7fffffff, sections)
                    if ho: syms.append(cstr(data, ho+2))
                to += 4
            imports[dll] = syms
            o += 20
        with open(out_dir / f"{path.stem}_imports.json", 'w') as f:
            json.dump(imports, f, indent=1)
        total = sum(len(v) for v in imports.values())
        print(f"  -> wrote {total} imports across {len(imports)} DLLs")
        for dll in sorted(imports): print(f"     {dll}: {len(imports[dll])}")

if __name__ == '__main__':
    main()
