#!/usr/bin/env python3
"""Converging header fixer: alternates compile feedback between
opaque_types.h (add missing / drop conflicting) and functions.h (drop colliding protos).
Usage: python prune_opaque.py [iterations]"""
import subprocess, sys, random, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
INC = Path("src/include").resolve()
OUTDIR = Path("build_test"); OUTDIR.mkdir(exist_ok=True)

def msvc_env():
    import os
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
    return r.returncode, ((r.stdout or '') + '\n' + (r.stderr or ''))

def err_names(errs, code):
    """Names quoted in given error codes."""
    out = set()
    for e in errs:
        for m in re.finditer(code + r"[^\n']*'([A-Za-z_][A-Za-z0-9_]*)'", e):
            out.add(m.group(1))
    return out

def main():
    n_iter = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    d = Path('buildable')
    files = sorted(str(p) for p in d.glob('*.c'))
    random.seed(42)
    sample = random.sample(files, min(120, len(files)))

    opq_path = INC / 'opaque_types.h'
    fnh_path = INC / 'functions.h'

    env = msvc_env()

    for it in range(n_iter):
        opq = opq_path.read_text().splitlines()
        fnh = fnh_path.read_text().splitlines()

        results = list(ThreadPoolExecutor(max_workers=8).map(lambda p: try_compile(p, env), sample))
        errs = [e for rc, e in results if rc != 0]
        ok = sum(1 for rc, _ in results if rc == 0)
        print(f"[iter {it}] compiled={ok}/{len(sample)}")

        # 1) C2011/C2371 type-redefinitions -> drop our conflicting typedefs
        bad_types = err_names(errs, 'C2011') | err_names(errs, 'C2371')
        new_opq = [l for l in opq
                   if not (l.startswith('typedef') and any(
                       l.endswith(f' {b};') or f' {b} {b};' in l for b in bad_types))]
        # 2) C2365/C2733: identifier redeclared as different kind
        #    C2371 handled too when the name matches one of our prototype lines
        c2365 = (err_names(errs, 'C2365') | err_names(errs, 'C2733') | err_names(errs, 'C2373')
                 | err_names(errs, 'C2374') | err_names(errs, 'C2375') | err_names(errs, 'C2556'))
        # calls that clash with our (possibly wrong-arity) prototypes -> drop those protos;
        # C then falls back to implicit/unprototyped linkage for skeleton purposes
        errs_joined = chr(10).join(errs)
        for code in ('C2064', 'C2198', 'C2197'):
            pat = re.compile(code + "[^" + chr(10) + "]*?[A-Za-z0-9_ ]([A-Za-z_][A-Za-z0-9_]*)\\(")
            for m in pat.finditer(errs_joined):
                c2365.add(m.group(1))
        our_protos = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", chr(10).join(fnh)))
        c2371f = {n for n in err_names(errs, 'C2371') if n in our_protos}
        c2365 |= c2371f
        print(f"  DEBUG: raw2371={len(err_names(errs,'C2371'))} our_protos={len(our_protos)} c2371f={len(c2371f)} c2365={len(c2365)} errs={len(errs)}")
        # 2b) syntax errors ON our proto lines (e.g. C2059 <parameter-list>) -> drop that proto
        _n2059 = 0
        for e in errs:
            mm = re.search(r'functions\.h\((\d+)\): error C2059', e)
            if mm:
                _n2059 += 1
                ln = int(mm.group(1)) - 1  # convert 1-based file line to 0-based list idx
                if 0 <= ln < len(fnh):
                    ident = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", fnh[ln])
                    if ident:
                        c2365.add(ident.group(1))
        print(f"  DEBUG2: n2059={_n2059}")
        fn_set = set()
        for b in c2365:
            pat = re.compile(r'\b' + re.escape(b) + r'\s*\(')
            # these collide with real system declarations -> drop ALL our proto lines
            fn_set |= {l for l in fnh if pat.search(l)}
        new_opq = [l for l in new_opq if not any(f' {b} {b};' in l for b in c2365)]
        new_fnh = [l for l in fnh if l not in fn_set]

        # 3) C2143/C2061/C2059 unknown-type near '*' -> ADD missing opaque typedefs
        miss = set()
        for e in errs:
            for m in re.finditer(r"C2143[^\n]*before '\*'", e):
                ln = int(re.search(r'\((\d+)\)', e.split("error C2143")[0]).group(1))
                src_line = None
                # find corresponding source line in functions.h by number prefix in message
                mm = re.search(r'functions\.h\((\d+)\)', e)
                continue
        # simpler: scan every functions.h line referenced by ANY syntax error for undeclared identifiers
        ref_lines = set()
        for e in errs:
            mm = re.search(r'functions\.h\((\d+)\): error C(2143|2061|2059|2065)', e)
            if mm:
                ref_lines.add(int(mm.group(1)) - 1)   # +2 offset: 2 header comment lines
        known = {'void','int','char','short','long','float','double','bool','uint','ushort','ubyte',
                 'byte','undefined1','undefined2','undefined3','undefined4','undefined6','undefined8',
                 'float10','HANDLE','DWORD','HMODULE','HKEY','LSTATUS','LPVOID','FARPROC','BOOL','UINT',
                 'WCHAR','LPCVOID','LPWSTR','HWND','HDC','HGLRC','SIZE_T','SOCKET','GUID','FILE',
                 'va_list','size_t','wchar_t','errno_t'}
        have = set(re.findall(r'typedef struct (\w+) \w+;', '\n'.join(new_opq)))
        for idx in ref_lines:
            if 0 <= idx < len(new_fnh):
                for tid in re.findall(r'(?:^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]{2,})\s*\*', new_fnh[idx]):
                    if tid not in known and tid not in have and not tid.startswith(('FUN_','PTR_')):
                        miss.add(tid)
                for tid in re.findall(r'(?:^|\(|,)\s*([A-Za-z_][A-Za-z0-9_]{2,})\s+\*?param_', new_fnh[idx]):
                    if tid not in known and tid not in have:
                        miss.add(tid)
        for t in sorted(miss):
            new_opq.append(f"typedef struct {t} {t};")

        changed = (new_opq != opq) or (new_fnh != fnh)
        opq_path.write_text('\n'.join(new_opq) + '\n')
        fnh_path.write_text('\n'.join(new_fnh) + '\n')
        added = len(miss)
        print(f"  dropped_typedefs={len(opq)-len(new_opq)} dropped_protos={len(fnh)-len(new_fnh)} added_typedefs={added}")
        if not changed and ok > 0:
            break
        if ok == len(sample):
            break

    # final taxonomy
    results = list(ThreadPoolExecutor(max_workers=8).map(lambda p: try_compile(p, env), sample))
    cats = {}
    for rc, e in results:
        if rc == 0: continue
        first = next((l for l in e.splitlines() if 'error' in l.lower()), 'unknown')
        key = ('C' + first.split('error C')[1][:4]) if 'error C' in first else first[:60]
        cats.setdefault(key, []).append(first[:130])
    ok = sum(1 for rc, _ in results if rc == 0)
    print(f"\nFINAL: compiled={ok}/{len(sample)}")
    for k, v in sorted(cats.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"  [{len(v)}] {k}  e.g. {v[0]}")

if __name__ == '__main__':
    main()
