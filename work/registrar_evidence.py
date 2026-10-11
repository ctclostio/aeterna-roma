#!/usr/bin/env python3
"""Extract per-function evidence for the registrar-reachable set and propose
names.  Track 3.

Reads work/registrar_reach.tsv (produced by registrar_walk.py) and, for every
reached function that the funcid corpus has not already named, pulls the same
evidence the batch1 rule engine used:

  str:      distinctive string literals
  api:      imported Win32/CRT entry points called
  callees:  direct FUN_ calls, with multiplicity

and proposes a conservative name from the strongest available signal.  The
proposals are advisory: they are written to work/registrar_proposed.tsv for
review, never merged into the funcid corpus.
"""
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECOMP = ROOT / 'src_out' / 'empire.retail.dll' / 'decomp'
WORK = ROOT / 'work'

STR_RE = re.compile(r'"([^"\\\n]{6,160})"')
FUN_RE = re.compile(r'\b(FUN_[0-9a-f]{8})\s*\(')
ADDR_RE = re.compile(r'^0x[0-9a-f]+$')

API_RE = re.compile(r'\b('
                    r'(?:Create|Open|Close|Read|Write|Delete|Find|Query|Set|Get|'
                    r'Reg|Virtual|Heap|Global|Local|Map|Unmap|Load|Free|Add|Remove|'
                    r'Enable|Disable|Is|Has|Co|Ole|Crypt|Http|Internet|WSA|Wsa|'
                    r'send|recv|connect|bind|listen|accept|socket|select|'
                    r'fopen|fclose|fread|fwrite|fprintf|printf|malloc|free|'
                    r'memcpy|memset|strlen|strcmp|wcscpy|Interlocked|'
                    r'Enter|Leave|Init|Exit|Terminate|Wait|Sleep|switch)'
                    r'[A-Za-z0-9_]{2,40})\s*\(')

# subsystem keyword -> ordered most-specific first
RULES = [
    # Bink is a video codec, not audio - must precede the audio rule.
    ('video',      [r'bink', r'\.bk2', r'\.avi', r'\.mp4', r'video']),
    ('vfs-pack',   [r'\.pack', r'packfile', r'PFH', r'mount.*pack', r'pack.*mount',
                    r'VersionChecker', r'\.esf', r'FileIndex', r'CaseSensitive']),
    ('db',         [r'db[/\\]', r'\.esf', r'database', r'DBTable', r'\btbl_',
                    r'Schema', r'FieldDef', r'RecordSet', r'SaveGame', r'campaign_table']),
    ('audio',      [r'\.wav', r'\.ogg', r'bank', r'sound', r'audio', r'music',
                    r'Wwise', r'Bink', r'\.bnk', r'volume', r'channel']),
    ('render',     [r'\.shader', r'\.vs\b', r'\.ps\b', r'texture', r'\.dds',
                    r'render', r'material', r'camera', r'\.mesh', r'\.skeleton',
                    r'nvapi', r'D3D', r'OpenGL', r'shader', r'lod', r'atmosphere']),
    ('ui',         [r'\.ui_', r'interface', r'component', r'layout', r'tooltip',
                    r'screen', r'menu', r'button', r'window.*style']),
    ('input',      [r'DirectInput', r'GetAsyncKeyState', r'keybd', r'mouse',
                    r'joystick', r'gamepad', r'XInput']),
    ('ai',         [r'CAI_', r'\bAI\b', r'agent', r'behaviou?r', r'pathfind',
                    r'navmesh', r'task', r'utility']),
    ('anim',       [r'animation', r'\.anim', r'clip', r'keyframe', r'skeleton',
                    r'\.ska', r'\.cas', r'FxAnim', r'anim']),
    ('campaign',   [r'campaign', r'province', r'settlement', r'faction',
                    r'turn', r'diplomacy', r'trade', r'city', r'economy']),
    ('battle',     [r'battle', r'unit', r'cohort', r'morale', r'combat',
                    r'formation', r'attack', r'siege', r'victory']),
    ('net',        [r'socket', r'winsock', r'steam', r'multiplayer', r'lobby',
                    r'peer', r'connect', r'packet', r'msg_']),
    ('save',       [r'\.sav', r'savegame', r'seriali[sz]', r'loadgame']),
    ('script',     [r'lua', r'ca_script', r'command_', r'trigger', r'script']),
    ('core',       [r'\.log', r'telemetry', r'assert', r'DeathReport',
                    r'thread', r'mutex', r'commandline', r'registry']),
]


def load_named():
    named = {}
    for p in WORK.glob('funcid_*.tsv'):
        for line in p.read_text(encoding='utf-8', errors='replace').splitlines():
            f = line.split('\t')
            if f and ADDR_RE.match(f[0]) and len(f) > 1 and f[1]:
                named[int(f[0], 16)] = f[1]
    return named


def evidence_for(va):
    path = DECOMP / f'{va:08x}_FUN_{va:08x}.c'
    if not path.exists():
        cands = sorted(DECOMP.glob(f'{va:08x}_*.c'))
        if not cands:
            return None
        path = cands[0]
    src = path.read_text(encoding='utf-8', errors='replace')
    strs = [s for s in STR_RE.findall(src) if not s.startswith('DAT_')]
    apis = Counter(API_RE.findall(src))
    callees = Counter(FUN_RE.findall(src))
    callees.pop(f'FUN_{va:08x}', None)
    return strs, apis, callees, len(src)


def classify(strs, apis, callees, size):
    blob = ' '.join(strs).lower()
    if not blob and not apis:
        return 'unknown_opaque', 'no strings and no API calls; leaf helper'
    for subs, pats in RULES:
        for pat in pats:
            m = re.search(pat, blob, re.I)
            if m:
                return subs, f'str:{m.group(0)[:48]!r}'
    if apis:
        top = apis.most_common(1)[0]
        return 'core', f'api:{top[0]}x{top[1]}'
    return 'unknown_str', f'{len(strs)} string literals, no distinctive token'


def main():
    reach = WORK / 'registrar_reach.tsv'
    if not reach.exists():
        raise SystemExit('run registrar_walk.py first')
    named = load_named()
    rows = []
    for line in reach.read_text(encoding='utf-8').splitlines()[1:]:
        f = line.split('\t')
        if len(f) < 6:
            continue
        va = int(f[0], 16)
        rows.append((va, int(f[2]), f[1], f[4]))

    out = WORK / 'registrar_proposed.tsv'
    stats = Counter()
    with out.open('w', encoding='utf8') as fh:
        fh.write('addr\tprior_name\tproposed_name\tsubsystem\tdepth\tedge\t'
                 'evidence\tstrings\tapi_calls\tsize\n')
        for va, depth, ghidra, edge in sorted(rows, key=lambda r: (r[1], r[0])):
            ev = evidence_for(va)
            if ev is None:
                continue
            strs, apis, callees, size = ev
            subs, why = classify(strs, apis, callees, size)
            prior = named.get(va, '')
            stats['prior' if prior else 'new'] += 1
            stats['subs:' + subs] += 1
            if prior:
                continue
            sl = ' | '.join(strs[:3]).replace('\t', ' ')[:150]
            ap = ','.join(f'{k}x{v}' for k, v in apis.most_common(4))
            fh.write(f'0x{va:x}\t\t{subs}_{va:x}\t{subs}\t{depth}\t{edge}\t'
                     f'{why[:90]}\t{sl}\t{ap}\t{size}\n')
    print(f'wrote {out.name}')
    for k, v in sorted(stats.items()):
        print(f'  {k}: {v}')


if __name__ == '__main__':
    main()
