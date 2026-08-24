#!/usr/bin/env python3
"""Generate a compilable x64 skeleton from Ghidra decompiled C corpus.

Outputs into --outdir:
  include/ghidra_compat.h    types + convention macros
  include/globals_decls.h    extern decls for every referenced global
  include/functions.h        prototype for every function
  manifest.tsv               addr -> module -> file map

Usage: python gen_build_skeleton.py <decomp_dir> <out_root>
"""
import os, re, sys, json
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor

SIG_RE = re.compile(
    r'^(?P<conv>(?:__thiscall|__stdcall|__cdecl|__fastcall)\s+)?'
    r'(?P<ret>[A-Za-z_][A-Za-z0-9_ \*\<\>:]*?)\s+\*?(?P<name>[A-Za-z_][A-Za-z0-9_:.\$<>!=+%\-]*)'
    r'\s*\((?P<args>[^)]*)\)',
)
GLOBALS_RE = re.compile(r'\b((?:DAT|UNK|PTR)_[0-9a-f]{6,}|s_[A-Za-z][A-Za-z0-9_]{2,})\b')
CONVS = {'__thiscall', '__stdcall', '__cdecl', '__fastcall'}

def norm_type(t):
    t = t.strip()
    for c in CONVS: t = t.replace(c, '')
    return ' '.join(t.split())

def parse_file(path):
    try:
        txt = Path(path).read_text('utf-8', 'replace')
    except OSError:
        return None
    if 'DECOMPILATION FAILED' in txt[:600]:
        return ('failed', None, None, set())
    # locate definition start: join wrapped lines until '{', then match
    lines = txt.split('\n')
    sig_line = None
    buf = ''
    in_comment = False
    for l in lines[:40]:
        ls = l.strip()
        if in_comment:
            if '*/' in ls: in_comment = False
            continue
        if not ls or (ls.startswith('//') and not buf):
            continue
        if (ls.startswith('//') or ls.startswith('/*')) and not buf:
            if ls.startswith('/*') and '*/' not in ls:
                in_comment = True
            continue
        if '{' in ls and sig_line is None and '(' in buf + ls:
            # definition line found; stop accumulating at brace boundary
            cand = (buf + ' ' + ls).split('{')[0].strip()
            m = SIG_RE.match(cand)
            if m:
                sig_line = (cand, m)
            break
        buf = (buf + ' ' + ls).strip()
        if '(' in buf:
            m = SIG_RE.match(buf.rstrip(';'))
            if m:
                sig_line = (buf, m)
                break
        if len(buf) > 2000:
            break
    globs = set(GLOBALS_RE.findall(txt))
    if not sig_line:
        return None
    return ('ok', sig_line[0], sig_line[1].groupdict(), globs)

def main():
    decomp = Path(sys.argv[1]); out = Path(sys.argv[2])
    inc = out / 'include'; inc.mkdir(parents=True, exist_ok=True)

    files = sorted(decomp.glob('*.c'))
    print(f"scanning {len(files)} files ...")
    results = []
    with ProcessPoolExecutor(max_workers=8) as ex:
        for r in ex.map(parse_file, files, chunksize=64):
            results.append(r)

    ok = [r for r in results if r and r[0] == 'ok']
    failed = sum(1 for r in results if r and r[0] == 'failed')
    print(f"parsed ok={len(ok)} failed={failed} unparsed={len(results)-len(ok)-failed}")

    # ---- functions.h ----
    seen_names = set(); decls = []
    all_globals = set()
    for _, _, d, g in ok:
        all_globals |= g
    for _, sigstr, d, _g in ok:
        name = d['name']
        if name in seen_names: continue
        seen_names.add(name)
        conv = (d['conv'] or '').strip()
        ret = norm_type(d['ret']) or 'int'
        args = d['args'].strip() or 'void'
        args = ', '.join(a.strip() for a in args.split(',') if a.strip())
        if not args: args = 'void'
        decls.append(f"/* {conv} */ {ret} {name}({args});")
    (inc / 'functions.h').write_text(
        "/* Auto-generated: prototypes for all decompiled functions */\n"
        "#pragma once\n" + "\n".join(decls) + "\n", encoding='utf-8')
    print(f"functions.h: {len(decls)} unique prototypes")

    # ---- globals_decls.h ----
    gl = []
    for g in sorted(all_globals):
        if g.startswith('s_'):
            gl.append(f"extern char {g}[];")
        else:
            gl.append(f"extern unsigned char {g}[];")
    (inc / 'globals_decls.h').write_text(
        "/* Auto-generated: extern decls for referenced globals (byte arrays;\n"
        "   name decays to address, matching Ghidra usage patterns) */\n"
        "#pragma once\n" + "\n".join(gl) + "\n", encoding='utf-8')
    print(f"globals_decls.h: {len(gl)} globals")

    # ---- ghidra_compat.h ----
    compat = """#pragma once
/* Ghidra decompiler type compatibility layer for x64 MSVC */
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  undefined1; typedef uint16_t undefined2;
typedef uint32_t undefined4; typedef uint64_t undefined8;
typedef uint8_t  byte;       typedef uint16_t ushort;
typedef uint32_t uint;       typedef uint8_t  ubyte;
typedef int      undefined4_signed_hack_dummy;

/* calling conventions collapse under MS x64 */
#define __thiscall
#define __stdcall
#define __cdecl
#define __fastcall

/* Ghidra casts through these freely */
typedef union {
  undefined1 u1; undefined2 u2; undefined4 u4; undefined8 u8;
  void *p; float f; double d;
} any_value;
"""
    (inc / 'ghidra_compat.h').write_text(compat, encoding='utf-8')
    print("ghidra_compat.h written")

    # ---- manifest ----
    with open(out / 'manifest.tsv', 'w') as mf:
        mf.write("file\tstatus\tsignature\n")
        for path, r in zip(files, results):
            st = r[0] if r else 'unparsed'
            sig = r[1].replace('\t', ' ') if (r and r[1]) else ''
            mf.write(f"{path.name}\t{st}\t{sig}\n")
    print("manifest.tsv written")

if __name__ == '__main__':
    main()
