#!/usr/bin/env python3
"""Solo funcid pass step 2 (v3): rules + FaceFX band membership + callee propagation.
Output: work/funcid_batch1_v3.tsv
"""
import json, re
from pathlib import Path
from collections import Counter

ROOT = Path('X:/decompilation')
recs = [json.loads(l) for l in open(ROOT / 'work/batch1_evidence.jsonl', encoding='utf-8')]

BANDS = [(0x100d6560,0x1011fe30),(0x101a0430,0x101b0ee0),(0x105421e0,0x1054d6a0),
         (0x10a281c0,0x10a34830),(0x10ed3cd0,0x10eec190)]
def inband(a):
    try: v = int(a, 16)
    except Exception: return False
    return any(s <= v <= e for s, e in BANDS)
# exports addr set (any OC3Ent/Fx export anywhere)
FX_EXP = set()
for line in open(ROOT / 'pe_meta/empire.retail_exports.txt', encoding='utf-8', errors='replace'):
    p = line.split('\t')
    if p[0].startswith('0x') and ('OC3Ent' in line or re.search(r'Fx[A-Z]', line)):
        FX_EXP.add(p[0][2:].lower())

def clean_ident(s, maxlen=40):
    s = re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_').lower()
    return s[:maxlen].strip('_') or 'x'
def joined(r): return ' '.join(r['strings'])
def fx_ratio(r):
    tot = sum(r['fun_resolved'].values())
    fx = sum(v for k, v in r['fun_resolved'].items() if k.startswith('facefx:'))
    return (fx / tot) if tot else 0.0
def top_fx(r):
    fxs = [(k.split(':', 1)[1], v) for k, v in r['fun_resolved'].items() if k.startswith('facefx:')]
    fxs.sort(key=lambda x: -x[1])
    return fxs[0][0] if fxs else None
def ev_first_str(r, pat=None):
    for s in r['strings']:
        if pat is None or re.search(pat, s, re.I):
            t = s if len(s) <= 60 else s[:57] + '...'
            return f'str:"{t}"'
    return None
def ev_imp(r, *names):
    hits = [i for i in r['imports'] if any(re.search(n, i) for n in names)]
    return ('imp:' + ','.join(hits[:3])) if hits else None
def fsm(r, pat):
    for s in r['strings']:
        if re.search(pat, s, re.I): return s
    return None

def fx_frac(r):
    fa = r.get('fun_addrs', [])
    if not fa: return 0.0
    return sum(1 for a in fa if inband(a) or a in FX_EXP) / len(fa)

prior = {}
for f in ['funcid_main.tsv','funcid_solo.tsv','funcid_todo2_out.tsv','funcid_todo2_results.tsv']:
    try:
        for line in open(ROOT / 'work' / f, encoding='utf-8'):
            p = line.rstrip('\n').split('\t')
            if len(p) >= 4:
                prior.setdefault(p[0].strip().lower(), (p[2], p[1]))
    except FileNotFoundError:
        pass
def callee_prior(cname):
    for pre in ('', 'thunk_FUN_'):
        c = cname
        if pre == '' and cname.startswith('FUN_'): c = cname[4:]
        elif pre == 'thunk_FUN_' and cname.startswith('thunk_FUN_'): c = cname[10:]
        else: continue
        pr = prior.get(c.lower())
        if pr: return pr
    pr = prior.get(cname.lower())
    return pr

MATH_OPS = {'SQRT','fpatan','fsin','fcos','ROUND','ABS'}
IGNORE_CALLS = {'CONCAT11','CONCAT22','CONCAT31','CONCAT33','CONCAT44','CONCAT12','CONCAT13','SUB41','SUB42',
                'ROUND','SQRT','ABS','block','swi','guard_check_icall','_atexit','_memset','n'}

RULES = []
def rule(pred, subsys, namef, evf): RULES.append((pred, subsys, namef, evf))

rule(lambda r: '"eventID"' in joined(r) and 'steamID' in joined(r), 'net',
     lambda r: 'telemetry_event_json_build_full' if 'hwid' in joined(r) else 'telemetry_event_json_build',
     lambda r: 'str:eventID/steamID/sessionID JSON kv builder')

NET_KW = r'socket|socks[45]|gethostbyname|WSA\w*error|certificate|issuer|ldap|https?://|proxy'
rule(lambda r: ev_imp(r, r'WSAStartup|closesocket') or re.search(NET_KW, joined(r)), 'net',
     lambda r: 'net_socket_' + clean_ident(fsm(r, NET_KW) or 'io'), 
     lambda r: ev_first_str(r, NET_KW) or ev_imp(r, r'WSAStartup|closesocket'))

rule(lambda r: re.search(r'invalid distance too far|invalid hash bucket|incorrect header check|invalid block type|need dictionary|invalid bit length', joined(r)), 'fs',
     lambda r: 'zlib_inflate_decompress', lambda r: 'str:zlib inflate error literals')

rule(lambda r: re.search(r'Unexpected format .* used with type', joined(r)), 'middleware-facefx',
     lambda r: 'facefx_archive_type_mismatch_error', lambda r: ev_first_str(r, 'Unexpected format'))

rule(lambda r: 'LUA function' in joined(r) or re.search(r'\blua_\w', joined(r)), 'script',
     lambda r: 'script_lua_binding_dispatch' if 'not found' in joined(r) else 'script_lua_api_call',
     lambda r: ev_first_str(r, 'lua|LUA') or 'call:lua pattern')


# ---- FaceFX: strong resolved-callee ratio ----
rule(lambda r: fx_ratio(r) >= 0.5 and sum(r['fun_resolved'].values()) >= 3, 'middleware-facefx',
     lambda r: 'facefx_' + clean_ident(top_fx(r)),
     lambda r: f'call:{top_fx(r)}')

rule(lambda r: re.search(r'\.pack|\.esf|manifest\.txt', joined(r)), 'fs',
     lambda r: 'fs_pack_mount_startpos_scan' if '.esf' in joined(r) else 'fs_pack_file_enumerate',
     lambda r: ev_first_str(r, r'\.pack|\.esf|manifest') or ev_imp(r, 'FindFirstFile'))
rule(lambda r: ev_imp(r, r'GetTempFileName|GetTempPath'), 'fs', lambda r: 'fs_temp_file_create',
     lambda r: ev_imp(r, r'GetTempFileName|GetTempPath'))
rule(lambda r: ev_imp(r, r'CreateFile|ReadFile|WriteFile|FindFirstFile|SetFilePointer|CreateFileMapping'), 'fs',
     lambda r: 'fs_win32_io_buffered' if not r['strings'] else 'fs_win32_io_' + clean_ident(r['strings'][0], 28),
     lambda r: ev_imp(r, r'CreateFile|ReadFile|WriteFile|FindFirstFile'))

rule(lambda r: re.search(r'steam|MULTIPLAYER|multiplayer|lobby', joined(r)) or ev_imp(r, 'SteamAPI'), 'net',
     lambda r: 'net_steam_' + clean_ident(fsm(r, r'steam|lobby|multiplayer') or 'api_glue', 30),
     lambda r: ev_first_str(r, r'steam|lobby|multiplayer') or 'imp:SteamAPI')
rule(lambda r: re.search(r'twitch', joined(r), re.I), 'middleware-twitch', lambda r: 'twitch_api_call',
     lambda r: ev_first_str(r, 'twitch'))

rule(lambda r: re.search(r'\bsound\b|\baudio\b|\bmusic\b|\bvoice\b|mixer|volume|XAudio|\.wav|\.mp3|\.ogg', joined(r), re.I) and not re.search(r'dropdown', joined(r)), 'audio',
     lambda r: 'audio_' + clean_ident(fsm(r, r'sound|audio|music|voice|volume') or 'init', 34),
     lambda r: ev_first_str(r, r'sound|audio|music|voice|volume') or ev_imp(r, 'XAudio|dsound'))

RENDER_KW = r'shader|texture|\bmesh\b|render|vertex|pixel|d3d|direct3d|framebuffer|depth.?buffer|sampler|raster|\bgpu\b|wireframe|mip|lighting|\blight\b|ambient|deferred|\bcloud\b|\bterrain\b|collision|colour'
rule(lambda r: ev_imp(r, r'wgl|Direct3D|D3DPERF|gl[A-Z]'), 'render',
     lambda r: 'render_gl_' + clean_ident(fsm(r, RENDER_KW) or 'context_or_ext', 30),
     lambda r: ev_imp(r, r'wgl|Direct3D|D3DPERF|gl[A-Z]'))
rule(lambda r: re.search(RENDER_KW, joined(r), re.I), 'render',
     lambda r: 'render_' + clean_ident(fsm(r, RENDER_KW) or 'scene', 34), lambda r: ev_first_str(r, RENDER_KW))

rule(lambda r: re.search(r'\banim|skeleton|\brig\b|blend.?tree|motion', joined(r), re.I), 'anim',
     lambda r: 'anim_' + clean_ident(fsm(r, r'anim|skeleton|rig|motion') or 'clip', 34),
     lambda r: ev_first_str(r, r'anim|skeleton|rig|motion'))

CAMP_KW = r'campaign|politics|diplomacy|religion|province|region_|faction|trade|mission|startpos|treasury|\btax\b|senate|family_tree|estate|research|alliance|REGION_OWNERSHIP'
rule(lambda r: re.search(CAMP_KW, joined(r)), 'campaign',
     lambda r: 'campaign_' + clean_ident(fsm(r, CAMP_KW) or 'logic', 38), lambda r: ev_first_str(r, CAMP_KW))

BATTLE_KW = r'\bbattle\b|\bunits?\b|\barmy\b|naval|reinforcement|morale|melee|cavalry|infantry|siege|artillery|formation|garrison|regroup|\brout|attacker|defender|DEPLOYMENT|PROJECTILE|TEST AI BUILD|UNIT_LIST|SHIP_LIST'
rule(lambda r: re.search(BATTLE_KW, joined(r)), 'battle',
     lambda r: 'battle_' + clean_ident(fsm(r, BATTLE_KW) or 'logic', 38), lambda r: ev_first_str(r, BATTLE_KW))

UI_KW = r'\bUI/|widget|component|layout|dropdown|slider|button|panel|tooltip|cursor|\bfont\b|\bmenu\b|\bhud\b|icon|text_box|scrollbar'
rule(lambda r: re.search(UI_KW, joined(r)) or ev_imp(r, 'PeekMessage|ShowWindow|RegisterClass|GetCursorPos|MessageBox'), 'ui',
     lambda r: ('ui_' + clean_ident(fsm(r, UI_KW), 36)) if fsm(r, UI_KW) else 'ui_win32_message_pump',
     lambda r: ev_first_str(r, UI_KW) or ev_imp(r, 'PeekMessage|ShowWindow|RegisterClass'))

rule(lambda r: ev_imp(r, r'RegOpenKey|RegQueryValue') or 'HARDWARE\\DESCRIPTION' in joined(r), 'core',
     lambda r: 'sys_info_registry_query' if 'HARDWARE' in joined(r) else 'core_config_registry_read',
     lambda r: ev_first_str(r, r'HARDWARE|SOFTWARE') or ev_imp(r, r'RegOpenKey|RegQueryValue'))
rule(lambda r: ev_imp(r, r'VirtualAlloc|VirtualFree|VirtualQuery|HeapCreate|HeapAlloc'), 'core',
     lambda r: 'core_mem_virtual_allocator', lambda r: ev_imp(r, r'VirtualAlloc|VirtualFree|VirtualQuery|HeapAlloc') or ev_first_str(r, 'VirtualAlloc'))
rule(lambda r: ev_imp(r, r'CreateThread|_beginthread|EnterCriticalSection|InitializeCriticalSectionAndSpinCount|ReleaseSemaphore|WaitForSingleObject|CreateSemaphore'), 'core',
     lambda r: 'core_thread_sync_primitive', lambda r: ev_imp(r, r'thread|CriticalSection|Semaphore|WaitFor|CreateSemaphore'))
rule(lambda r: ev_imp(r, r'timeGetTime|QueryPerformanceCounter') and len(r['imports']) <= 4, 'core',
     lambda r: 'core_time_source_query', lambda r: ev_imp(r, r'timeGetTime|QueryPerformanceCounter'))
rule(lambda r: ev_imp(r, r'OutputDebugString|IsDebuggerPresent'), 'core', lambda r: 'core_debug_output',
     lambda r: ev_imp(r, r'OutputDebugString|IsDebuggerPresent'))

# ---- FaceFX: band-membership heuristic (weak, runs last) ----
rule(lambda r: fx_frac(r) >= 0.7 and not joined(r), 'middleware-facefx',
     lambda r: 'facefx_sdk_internal', lambda r: f'fx-callee-frac={fx_frac(r):.0%}')
rule(lambda r: fx_frac(r) >= 0.85, 'middleware-facefx',
     lambda r: 'facefx_sdk_internal', lambda r: f'fx-callee-frac={fx_frac(r):.0%} (has strings)')


def classify(r):
    for pred, subsys, namef, evf in RULES:
        try:
            if pred(r):
                return subsys, namef(r), (evf(r) or 'pattern'), 'rule'
        except Exception:
            continue
    if r['size'] < 64:
        tgt = next(iter(r['named_calls']), None) or (next(iter(r.get('fun_addrs', ['']), None)))
        return 'unknown', 'thunk_to_' + clean_ident(tgt or 'unk'), 'size<64B', 'thunk'
    # math cluster
    mops = sum(v for k, v in r['named_calls'].items() if k in MATH_OPS)
    mdistinct = sum(1 for k in r['named_calls'] if k in MATH_OPS)
    if not r['strings'] and not r['imports'] and (mops >= 8 or mdistinct >= 3):
        dom = max(((k, v) for k, v in r['named_calls'].items() if k in MATH_OPS), key=lambda x: x[1])[0]
        opmap = {'SQRT':'sqrt','fpatan':'atan2','fsin':'sin','fcos':'cos','ROUND':'round','ABS':'abs'}
        return 'core-math', f'math_{opmap.get(dom,"op")}_heavy_compute', f'math intrins: {[k for k in r["named_calls"] if k in MATH_OPS]}', 'math'
    # static init/dtor chains
    if not r['strings'] and not r['imports'] and r['named_calls'].get('_atexit', 0) >= 1:
        return 'crt', 'crt_static_init_or_dtor_chain', 'calls _atexit; no strings/imports', 'atexit'
    if r['vftables']:
        return 'unknown', 'unknown_vtable_impl_' + clean_ident(r['vftables'][0]), 'vftable:' + ','.join(r['vftables'][:2]), 'vtable'
    if r['strings']:
        return 'unknown', 'unknown_str_' + clean_ident(r['strings'][0], 30), ev_first_str(r), 'str-only'
    jmc = '__CheckForDebuggerJustMyCode' in r['named_calls']
    tag = 'jmc_compiled;' if jmc else ''
    return 'unknown', 'unknown_opaque', f'{tag}size:{r["size"]}B no-xrefs', 'opaque'

results = {}; how = Counter()
for r in recs:
    sub, nm, ev, src = classify(r)
    results[r['addr'].lower()] = [nm, sub, ev]
    how[src] += 1

# propagation rounds: inherit subsystem from identified callees
for _round in range(4):
    changed = 0
    for r in recs:
        a = r['addr'].lower()
        nm, sub, ev = results[a]
        if sub != 'unknown': continue
        votes = Counter(); names = []
        cands = list(r['fun_resolved'].items()) + [(k, v) for k, v in r['named_calls'].items() if k not in IGNORE_CALLS]
        for cname, cnt in cands:
            src_pr = callee_prior(cname)
            ca = None
            if cname.startswith('FUN_'): ca = cname[4:].lower()
            elif cname.startswith('thunk_FUN_'): ca = cname[10:].lower()
            if src_pr is None and ca and ca in results:
                sn, ss, se = results[ca]
                if ss != 'unknown': src_pr = (ss, sn)
            if src_pr is None and cname.lower() in results:
                sn, ss, se = results[cname.lower()]
                if ss != 'unknown': src_pr = (ss, sn)
            if src_pr and not src_pr[0].startswith('unknown') and src_pr[1] != 'thunk_to_unk':
                votes[src_pr[0]] += cnt
                if len(names) < 3: names.append(src_pr[1])
        if votes:
            best, n = votes.most_common(1)[0]
            if n >= max(2, 0.5 * sum(votes.values())):
                results[a] = [f'{best}_via_' + clean_ident(names[0]), best,
                              f'callee-vote:{names}']
                changed += 1
    if not changed: break

out = open(ROOT / 'work/funcid_batch1_v3.tsv', 'w', encoding='utf-8')
rows = []; final = Counter()
for r in recs:
    nm, sub, ev = results[r['addr'].lower()]
    final[sub] += 1
    rows.append(f"{r['addr']}\t{nm}\t{sub}\t{ev}")
out.write('\n'.join(sorted(rows)) + '\n')
out.close()
print('methods:', dict(how))
print('subsystems:')
for k, v in final.most_common(): print(f'{v:6d} {k}')
