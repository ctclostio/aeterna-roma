#!/usr/bin/env python3
"""Filter opaque_types candidates: drop any type already defined by system headers.
Usage: python filter_opaque.py <candidates_file> <out_file>"""
import subprocess, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

PROBE_PRELUDE = (
    "#include <windows.h>\n"
    "#include <stdbool.h>\n"
    "#include <stdint.h>\n"
    "#include <stddef.h>\n"
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <time.h>\n"
    "#include <math.h>\n"
    "#include <errno.h>\n"
    "#include <excpt.h>\n"
    "#include <wtypes.h>\n"
)

EXCLUDED = {'__int8','__int16','__int32','__int64','_int8','_int16','_int32','_int64',
            '__int128','_Float16','__cdecl','__stdcall','__thiscall','__fastcall',
            '__declspec','__pragma','__w64','__ptr32','__ptr64','__restrict'}

def probe(t):
    if t in EXCLUDED:
        return t, True  # drop keywords
    if not t.replace('_', 'a').isalnum():
        return t, True  # drop anything with weird chars
    probe_f = Path('build_test') / f'probe_{t}.c'
    obj_f = probe_f.with_suffix('.obj')
    probe_f.write_text(PROBE_PRELUDE + t + " *p;\n")
    cmd = f'"{VCVARS}" >nul 2>&1 && cl /nologo /c /W0 "{probe_f}" /Fo"{obj_f}"'
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors='replace')
    ok = r.returncode == 0
    probe_f.unlink(missing_ok=True)
    obj_f.unlink(missing_ok=True)
    return t, ok

def main():
    cands = []
    for l in Path(sys.argv[1]).read_text().splitlines():
        l = l.strip().rstrip(';')
        if not l or l.startswith('#') or l.startswith('/*'):
            continue
        cands.append(l.split()[-1] if ' ' in l else l)
    Path('build_test').mkdir(exist_ok=True)
    exists, missing = [], []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for t, ok in ex.map(probe, cands):
            (exists if ok else missing).append(t)
    out = ["#pragma once", "/* Auto-generated opaque fwd decls (system-collision filtered).\n   Sized dummy bodies so BY-VALUE struct use compiles; real layouts come from RTTI recovery later. */"]
    out += [f"typedef struct {{ unsigned char _pad_[64]; }} {t};" for t in sorted(missing)]
    Path(sys.argv[2]).write_text('\n'.join(out) + '\n')
    print(f"kept={len(missing)} dropped_as_defined={len(exists)}")
    print("dropped:", ' '.join(sorted(exists)[:30]))

if __name__ == '__main__':
    main()
