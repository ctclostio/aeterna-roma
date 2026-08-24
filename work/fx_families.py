#!/usr/bin/env python3
"""Solo funcid pass step 3 (v4): token-family layer over v3 output.
Names remaining unknown-with-strings functions from their most distinctive literal;
maps ALLCAPS family prefixes to subsystems.
Output: work/funcid_batch1_v4.tsv
"""
import json, re
from pathlib import Path
from collections import Counter

ROOT = Path('X:/decompilation')
recs = {r['addr']: r for r in (json.loads(l) for l in open(ROOT / 'work/batch1_evidence.jsonl', encoding='utf-8'))}

FAM_SUBSYS = [
    (r'^CAI_', 'campaign'), (r'^CND_', 'campaign'), (r'^CDIR_', 'campaign'),
    (r'^(POLITICAL|DIPLOMACY|ALLIANCE|SENATE)', 'campaign'),
    (r'^(SPRAWL|SETTLEMENT|SLOT|REGION|PROVINCE|FACTION|CHARACTER|COMMERCE|TRADE|MILITARY|MISSION)', 'campaign'),
    (r'^(UNIT|UNITS|ARMY|NAVY|NAVAL|SIEGE|BATTLE|DEPLOY|REINFORCE|SHIPS|MELEE|PROJECTILE|ATTACKER|DEFENDER)', 'battle'),
    (r'^(TEXTURE|SHADER|MESH|MODEL|EFFECT|PARTICLE|CAMERA|SCENE|RENDER|SHADOW|LIGHT|TERRAIN|WATER|SKY)', 'render'),
    (r'^(ANIM|SKELETON|RIG)', 'anim'), (r'^(UI_|WIDGET|COMPONENT|LIST_BOX|PANEL|BUTTON|MENU|HUD|ICON|FONT|CURSOR)', 'ui'),
    (r'^(SOUND|MUSIC|AUDIO|VOICE|VOLUME)', 'audio'), (r'^(SAVE|LOAD_GAME)', 'fs'),
    (r'^(STEAM|LOBBY|MULTIPLAYER|NETWORK)', 'net'), (r'^(LUA|SCRIPT)', 'script'),
]

def clean_ident(s, maxlen=44):
    s = re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_').lower()
    s = re.sub(r'_+', '_', s)
    return s[:maxlen].strip('_') or 'x'

def fam_subsys(s):
    for pat, sub in FAM_SUBSYS:
        if re.search(pat, s): return sub
    return None

rows = []
stats = Counter()
for line in open(ROOT / 'work/funcid_batch1_v3.tsv', encoding='utf-8'):
    addr, nm, sub, ev = line.rstrip('\n').split('\t')
    r = recs.get(addr.lower())
    if sub == 'unknown' and r and r['strings']:
        # pick best literal: first ALLCAPS-ish or longest informative one
        best = None
        for s in r['strings']:
            if re.match(r'^[A-Z][A-Z0-9_]{4,}$', s):
                best = s; break
        if best is None:
            cand = [s for s in r['strings'] if len(s) >= 6 and not s.startswith('\\x')]
            best = max(cand, key=len) if cand else None
        if best:
            fs = fam_subsys(best)
            newsub = fs or sub
            newnm = f'{(fs or "game")}_{clean_ident(best)}'
            # avoid silly names starting with game_
            rows.append((addr, newnm, newsub, f'str:"{best[:50]}"'))
            stats['family-named' if fs else 'string-named'] += 1
            continue
    rows.append((addr, nm, sub, ev))
    stats[sub] += 1

out = open(ROOT / 'work/funcid_batch1_v4.tsv', 'w', encoding='utf-8')
out.write('\n'.join('\t'.join(x) for x in sorted(rows)) + '\n')
out.close()
print('layer stats:', dict(stats))
subc = Counter(r[2] for r in rows)
for k, v in subc.most_common(): print(f'{v:6d} {k}')
