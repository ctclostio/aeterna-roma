#!/usr/bin/env python3
"""Callee-cluster subsystem propagation for the registrar-reachable set.

Track 3.  The RTTI survey concluded that naming for this binary must rely on
"strings, API calls, and callee-cluster propagation".  registrar_evidence.py
implements the first two; this implements the third.

Most startup handlers are thin vtable dispatch shims with no strings of their
own, so their local evidence is empty.  But they call into functions that *are*
already named.  We seed a subsystem table from the existing 9,036-name corpus
and propagate it backwards along call edges: a function whose named callees
overwhelmingly sit in one subsystem inherits that subsystem.

Provenance is carried on every row so a reviewer can tell a locally-evidenced
name from an inherited one.  Nothing is merged into the corpus automatically.
"""
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECOMP = ROOT / 'src_out' / 'empire.retail.dll' / 'decomp'
WORK = ROOT / 'work'

ADDR = re.compile(r'^(?:0x)?([0-9a-fA-F]{6,8})\t')
FUN_RE = re.compile(r'\bFUN_([0-9a-f]{8})\s*\(')
STR_RE = re.compile(r'"([^"\\\n]{6,160})"')

# A subsystem is only inherited when it is both dominant and backed by enough
# independent evidence, otherwise opaque leaf clusters invent noise.
MIN_CALLEES = 2
DOMINANCE = 0.60

# Subsystems too generic to carry a propagation decision.
WEAK = {'unknown', 'unknown_opaque', 'unknown_str', 'core-math', 'core',
        'replay/rest', ''}


def load_seed():
    """addr -> (name, subsystem) from every funcid TSV. Later files win."""
    seed = {}
    for p in sorted(WORK.glob('funcid_*.tsv')):
        for line in p.read_text(encoding='utf-8', errors='replace').splitlines():
            m = ADDR.match(line)
            if not m:
                continue
            f = line.split('\t')
            if len(f) >= 3 and f[1]:
                seed[int(m.group(1), 16)] = (f[1], f[2].strip())
    return seed


def decomp_of(va):
    path = DECOMP / f'{va:08x}_FUN_{va:08x}.c'
    if path.exists():
        return path.read_text(encoding='utf-8', errors='replace')
    cands = sorted(DECOMP.glob(f'{va:08x}_*.c'))
    return cands[0].read_text(encoding='utf-8', errors='replace') if cands else None


def main():
    reach = WORK / 'registrar_reach.tsv'
    if not reach.exists():
        raise SystemExit('run registrar_walk.py first')

    rows = [l.split('\t') for l in
            reach.read_text(encoding='utf-8').splitlines()[1:]]
    depth = {int(r[0], 16): int(r[2]) for r in rows if len(r) >= 6}

    seed = load_seed()
    print(f'seed corpus: {len(seed)} named addresses')

    # Direct edges, computed once.
    edges = {}
    strs_of = {}
    for va in depth:
        src = decomp_of(va)
        if src is None:
            continue
        c = {int(h, 16) for h in FUN_RE.findall(src)}
        c.discard(va)
        edges[va] = c
        strs_of[va] = STR_RE.findall(src)
    print(f'edges for {len(edges)} reachable functions')

    subs = {va: s for va, (_n, s) in seed.items()}
    named = {va for va, (n, _s) in seed.items() if n}

    # Reverse index: callee -> set of callers.
    callers = defaultdict(set)
    for va, cs in edges.items():
        for c in cs:
            callers[c].add(va)

    rounds = 0
    while True:
        rounds += 1
        added = 0
        for va, cs in edges.items():
            if va in subs:
                continue
            tally = Counter()
            for c in cs:
                s = subs.get(c)
                if s and s not in WEAK:
                    tally[s] += 1
            if not tally:
                continue
            total = sum(tally.values())
            top, n = tally.most_common(1)[0]
            if n >= MIN_CALLEES and n / total >= DOMINANCE:
                subs[va] = top
                added += 1
        print(f'  round {rounds}: +{added} propagated (total {len(subs)})')
        if not added:
            break
        if rounds > 12:
            print('  stopping at round cap')
            break

    # Confidence: more independent callee support -> higher tier.
    def tier(va):
        if va in named:
            return 'seed'
        if strs_of.get(va):
            return 'local+prop'
        tally = Counter()
        for c in edges.get(va, ()):
            s = subs.get(c)
            if s and s not in WEAK:
                tally[s] += 1
        n = tally.most_common(1)[0][1] if tally else 0
        return 'prop-3+' if n >= 3 else 'prop-2'

    out = WORK / 'registrar_propagated.tsv'
    dist = Counter()
    with out.open('w', encoding='utf-8') as fh:
        fh.write('addr\tdepth\tassigned_subsystem\tconfidence\t'
                 'support_callees\ttop_callee_subsystems\tstrings\n')
        for va in sorted(depth, key=lambda v: (depth[v], v)):
            s = subs.get(va)
            if va in named:
                s = seed[va][1]
            if not s:
                continue
            t = tier(va)
            dist[t] += 1
            tally = Counter()
            for c in edges.get(va, ()):
                cs_ = subs.get(c)
                if cs_ and cs_ not in WEAK:
                    tally[cs_] += 1
            sup = ','.join(f'{k}x{v}' for k, v in tally.most_common(3))
            sl = ' | '.join(strs_of.get(va, [])[:2]).replace('\t', ' ')[:110]
            fh.write(f'0x{va:x}\t{depth[va]}\t{s}\t{t}\t'
                     f'{sum(tally.values())}\t{sup}\t{sl}\n')

    print(f'\nwrote {out.name}')
    for k, v in sorted(dist.items()):
        print(f'  {k}: {v}')

    unknown = [v for v in depth if not subs.get(v)]
    print(f'\nstill unassigned: {len(unknown)} of {len(depth)}')


if __name__ == '__main__':
    main()
