#!/usr/bin/env python3
"""Per-shard classification digests."""
import re
from pathlib import Path

addrs=[a.strip() for a in Path('work/all_shard_addrs.txt').read_text().split() if a.strip()]
N=3
shards=[addrs[i::N] for i in range(N)]
for i,s in enumerate(shards):
    disk=Path(f'work/shard_{i:02d}.txt').read_text().split()
    assert disk==s, f"shard {i} mismatch"
print("shard files match round-robin split")

DEC=Path('src_out/empire.retail.dll/decomp')
KNOWN=re.compile(r'\b(memset|memcpy|memmove|strcpy|strncpy|strcat|strcmp|strncmp|strlen|strstr|_stricmp|_strnicmp|sprintf|_snprintf|fprintf|printf|sscanf|atoi|atof|strtod|malloc|free|realloc|calloc|qsort|bsearch|fopen|fread|fwrite|fclose|fseek|ftell|CreateFile[A-Za-z]*|ReadFile|WriteFile|CloseHandle|Sleep|GetCurrentThreadId|EnterCriticalSection|LeaveCriticalSection|InitializeCriticalSection\w*|DeleteCriticalSection|CreateThread|CreateEventW?|SetEvent|WaitForSingleObject|InterlockedIncrement|InterlockedDecrement|LoadLibrary[AW]|GetProcAddress|GetModuleHandle[AW]?|GetLastError|OutputDebugString[AW]?|MultiByteToWideChar|WideCharToMultiByte|CoInitialize|CoCreateGuid|Direct3DCreate9|timeGetTime|QueryPerformanceCounter|GetTickCount|GetLocalTime|GetVersionEx[AW]?|RegOpenKeyEx[AW]?|RegQueryValueEx[AW]?|RegCloseKey|rand|srand|floor|sqrt|pow|cos|sin|tan|atan2|fabs|FindFirstFileW|FindNextFileW|FindClose|CreateSemaphoreA|GetCurrentProcessId|IsDebuggerPresent|VirtualAlloc|VirtualFree|PeekMessageW|GetActiveWindow|CreateDialogIndirectParamW|EndDialog|DialogBoxIndirectParamW)\b\s*\(')
STOP={'Entry','Function','Signature','Size','WARNING','Globals','Subroutine','BOOL','HANDLE','LONG','DWORD','FILE','LPVOID','LPMSG','HWND','DLGPROC'}
VARISH=re.compile(r'^(CONCAT|CARRY|SUB4|BVar|DVar|FVar|uVar|iVar|pcVar|puVar|local_|in_|extraout|DAT|LAB|PTR|uRam|_DAT)')

TYPES=re.compile(r'\b((?:[A-Z][A-Za-z0-9]*::)+[A-Z][A-Za-z0-9]*)\b|\b(Fx[A-Za-z0-9_]+)\b')

def feat(a):
    h=a[2:]
    txt=(DEC/f'{h}_FUN_{h}.c').read_text(errors='ignore')
    m=re.search(r'Size: (\d+)',txt); size=m.group(1) if m else '?'
    strs=[]
    for s in re.findall(r'"((?:[^"\\]|\\.){1,120})"',txt):
        if s not in strs: strs.append(s)
    strs=strs[:14]
    apis=sorted(set(KNOWN.findall(txt)))
    types=[]
    for mm in TYPES.finditer(txt):
        t=mm.group(1) or mm.group(2)
        if t not in types and not VARISH.match(t): types.append(t)
    types=types[:8]
    ptrw=sorted(set(re.findall(r'\*\s*\w+\s*(?:\[\d+\]\s*)?=\s*&(\w+);',txt)))[:8]
    allocs=sorted(set(re.findall(r'FUN_[0-9a-f]{8}\((0x[0-9a-f]+)\)',txt)))[:8]
    fc={}
    for mm in re.finditer(r'(FUN_[0-9a-f]{8})\s*\(',txt): fc[mm.group(1)]=fc.get(mm.group(1),0)+1
    top=sorted(((c,n) for c,n in fc.items() if c!=f'FUN_{h}'),key=lambda kv:-kv[1])[:6]
    L=[f'### {a} size={size} uniqCalls={len(fc)}']
    if strs: L.append('  STR: '+' | '.join(s[:70] for s in strs))
    if apis: L.append('  API: '+', '.join(apis))
    if types: L.append('  TYP: '+', '.join(types))
    if ptrw: L.append('  PTRW: '+', '.join(ptrw))
    if allocs: L.append('  ALLOC: '+', '.join(allocs))
    if top: L.append('  CALLEES: '+', '.join(f'{c}x{n}' for c,n in top))
    return '\n'.join(L)

for i,s in enumerate(shards):
    Path(f'work/digest_{i:02d}.txt').write_text('\n'.join(feat(a) for a in s)+'\n')
    print(f'digest_{i:02d}: {len(s)} funcs')
