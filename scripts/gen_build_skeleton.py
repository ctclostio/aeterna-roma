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

QUALIFIED_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)')
OPERATOR_MAP = {'=':'eq','==':'eq_eq','!=':'ne','<':'lt','>':'gt','+':'add','-':'sub','*':'deref',
                '/':'div','[]':'idx','()':'call','->':'arrow','!':'not','%':'mod','&':'addr',
                '<<':'shl','>>':'shr','++':'inc','--':'dec'}
OP_RE = re.compile(r'\boperator(=|==|!=|<|>|\+|-|\*|/|\[\]|\(\)|->|!|%|&|<<|>>|\+\+|--)(?=\()')

def strip_templates(txt):
    """Iteratively remove <...> groups, innermost first (handles nesting)."""
    while True:
        new = re.sub(r'<[^<>]*>', lambda m, o=txt: '', txt)
        if new == txt:
            return txt
        txt = new

def sanitize(txt):
    # normalize whitespace around scope resolution from line-wrapping
    txt = re.sub(r'\s*::\s*', '::', txt)
    # flatten Ns::Class::member -> Ns_Class_member
    def flat(m):
        return m.group(1).replace('::', '_')
    txt = QUALIFIED_RE.sub(flat, txt)
    def opsub(m):
        return '_operator_' + OPERATOR_MAP.get(m.group(1), 'op')
    txt = re.sub(r'operator([=!<>+\-*/%&|]+)', opsub, txt)
    txt = strip_templates(txt)
    # final safety net: no legal C declaration contains '::'
    txt = txt.replace('::', '_')
    # collapse double underscores created by joins
    txt = re.sub(r'_{3,}', '__', txt)
    return txt

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

    # ---- functions.h (collision-aware) ----
    # per-file sanitized signature line; identifier = last ident before '(' at top level
    def ident_of(line):
        ms = list(re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', line))
        return ms[-1].group(1) if ms else None
    from collections import Counter
    all_globals = set()
    for _, _, d, g in ok:
        all_globals |= g
    per_file = []
    for path, r in zip(files, results):
        if not (r and r[0] == 'ok'):
            continue
        line = sanitize(r[1]).rstrip()
        if not line.endswith(';'):
            line += ';'
        d = r[2]
        # VALIDITY GATE: if sanitized signature is not sane C, emit safe variadic stub
        mm = re.search(r'\(([^()]*)\)\s*;$', line)
        bad = (mm is None)
        if not bad:
            inner = mm.group(1)
            bad = ('(' in inner or '*' == inner.strip()[:1]
                   or re.search(r'(^|,)\s*\*', inner) is not None
                   or not re.search(r'[A-Za-z_]\w*\s*\([^()]*\)\s*;$', line))
        if bad:
            conv = (d['conv'] or '').strip()
            ret = norm_type(d['ret']) or 'int'
            addr = Path(path).name.split('_')[0]
            nm = sanitize(d['name']).replace('(', '').replace(')', '')
            nm = re.sub(r'[^A-Za-z0-9_]', '_', nm)[:80]
            line = f"/* {conv} {r[1][:100]} */ {ret} {nm}_{addr}(undefined4, ...);".replace('/*  */','/* */')
        per_file.append((Path(path).name, line))

    counts = Counter(i for _, l in per_file if (i := ident_of(l)))
    renames = {}   # fname -> (old_ident, new_ident)
    decls = []
    seen_final = set()
    for fname, line in per_file:
        ident = ident_of(line)
        if ident and counts[ident] > 1:
            new_id = f"{ident}_{fname.split('_')[0]}"
            renames[fname] = (ident, new_id)
            line = line.replace(f" {ident}(", f" {new_id}(", 1)
            ident = new_id
        if ident and ident not in seen_final:
            seen_final.add(ident)
            decls.append(line)
    (inc / 'functions.h').write_text(
        "/* Auto-generated: prototypes for all decompiled functions */\n"
        "#pragma once\n" + "\n".join(decls) + "\n", encoding='utf-8')
    print(f"functions.h: {len(decls)} unique prototypes ({len(renames)} collision-renamed)")

    # ---- buildable tree: copies with ONLY the signature sanitized ----
    buildable = out.parent / 'buildable'
    buildable.mkdir(exist_ok=True)
    n_san = 0
    for path, r in zip(files, results):
        if not (r and r[0] == 'ok'):
            continue
        fname = Path(path).name
        raw = Path(path).read_text('utf-8', 'replace')
        head, sep, tail = raw.partition('\n{')
        san_head = sanitize(head)
        if fname in renames:
            old_id, new_id = renames[fname]
            san_head = san_head.replace(f" {old_id}(", f" {new_id}(", 1)
        if san_head != head:
            n_san += 1
        (buildable / fname).write_text(san_head + sep + tail, encoding='utf-8')
    print(f"buildable/: {n_san} files with sanitized signatures")

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
/* x87 extended precision (Ghidra float10); MSVC has no 80-bit long double */
typedef long double float10;
typedef int64_t  longlong;   typedef uint64_t ulonglong;
typedef uint32_t undefined3; typedef uint32_t undefined5;
typedef uint32_t undefined6; typedef uint64_t undefined7;

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
