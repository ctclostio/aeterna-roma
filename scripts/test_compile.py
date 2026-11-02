#!/usr/bin/env python3
"""Compile sample decompiled files with MSVC x64; report error taxonomy.
Usage: python test_compile.py [N]"""
import os, subprocess, random, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
INC = Path("src/include").resolve()
OUTDIR = Path("build_test"); OUTDIR.mkdir(exist_ok=True)

ENV_CMD = f'"{VCVARS}" >nul 2>&1 && echo READY'

def msvc_env():
    import subprocess as sp
    cmd = f'"{VCVARS}" >nul 2>&1 && set'
    out = sp.check_output(cmd, shell=True, text=True, errors='replace')
    env = dict(os.environ)
    for line in out.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            if k.upper() in ('PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR') or k.startswith('VSCMD') or k.isupper():
                env[k] = v
    return env

def try_compile(path, env):
    obj = OUTDIR / (Path(path).stem + '.obj')
    inner = f'cl /nologo /c /W0 /EHsc /FI"{INC}/umbrella.h" "{path}" /Fo"{obj}"'
    r = subprocess.run(inner, shell=True, capture_output=True, text=True, errors='replace', env=env)
    outtxt = (r.stdout or '') + '\n' + (r.stderr or '')
    return path, r.returncode, outtxt[:3000]

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    env = msvc_env()
    d = Path('buildable')
    files = sorted(str(p) for p in d.glob('*.c'))
    random.seed(42)
    sample = random.sample(files, n)
    ok = fail = 0
    errs = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for path, rc, errtxt in ex.map(lambda p: try_compile(p, env), sample):
            if rc == 0: ok += 1
            else:
                fail += 1
                first = next((l for l in errtxt.splitlines() if 'error' in l.lower()), 'unknown')[:120]
                key = first.split(':')[0] + ':' + (first.split('error C')[1][:4] if 'error C' in first else first[:60])
                errs.setdefault(key, []).append((path, first))
    print(f"compiled={ok} failed={fail} / {len(sample)}")
    print("\nTop error categories:")
    for k, v in sorted(errs.items(), key=lambda x: -len(x[1]))[:12]:
        print(f"  [{len(v)}] {k}")
        print(f"       e.g. {v[0][1][:110]}")
        print(f"       in  {Path(v[0][0]).name}")

if __name__ == '__main__':
    main()
