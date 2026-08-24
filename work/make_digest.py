#!/usr/bin/env python3
"""Extract classification evidence per function into one digest file."""
import re
from pathlib import Path

addrs = [a.strip() for a in Path('work/all_shard_addrs.txt').read_text().split() if a.strip()]
DEC = Path('src_out/empire.retail.dll/decomp')

# Known Windows/API/CRT-ish call names to flag explicitly
KNOWN = re.compile(r'\b(memset|memcpy|memmove|strcpy|strncpy|strcat|strcmp|strncmp|strlen|strstr|'
                   r'_stricmp|_strnicmp|sprintf|_snprintf|fprintf|printf|sscanf|atoi|atof|strtod|'
                   r'malloc|free|realloc|calloc|qsort|bsearch|fopen|fread|fwrite|fclose|fseek|ftell|'
                   r'CreateFile[A-Za-z]*|ReadFile|WriteFile|CloseHandle|Sleep|GetCurrentThreadId|'
                   r'EnterCriticalSection|LeaveCriticalSection|InitializeCriticalSection\w*|'
                   r'DeleteCriticalSection|CreateThread|CreateEventW?|SetEvent|WaitForSingleObject|'
                   r'InterlockedIncrement|InterlockedDecrement|LoadLibrary[AW]|GetProcAddress|'
                   r'GetModuleHandle[AW]?|GetLastError|OutputDebugString[AW]?|MultiByteToWideChar|'
                   r'WideCharToMultiByte|CoInitialize|Direct3DCreate9|timeGetTime|QueryPerformanceCounter|'
                   r'GetTickCount|GetLocalTime|rand|srand|floor|sqrt|pow|cos|sin|tan|atan2|fabs)\b\s*\(')

out = []
for a in addrs:
    h = a[2:]
    p = DEC / f'{h}_FUN_{h}.c'
    txt = p.read_text(errors='ignore')
    hdr = re.search(r'Entry: 0x([0-9a-f]+)\s+Size: (\d+)', txt)
    size = hdr.group(2) if hdr else '?'

    strs = re.findall(r'"((?:[^"\\]|\\.){1,120})"', txt)
    # dedupe preserve order, cap 12
    seen = []; 
    for s in strs:
        if s not in seen: seen.append(s)
    strs = seen[:12]

    apis = sorted(set(KNOWN.findall(txt)))

    # typed symbols from RTTI (anything not FUN_/generic ghidra junk)
    types = sorted(set(re.findall(r'\b((?:[A-Z][A-Za-z0-9]*::)*[A-Z][A-Za-z0-9]{2,})\b', txt)))
    # filter out ghidra keywords/junk
    junk = {'undefined','undefined1','undefined2','undefined4','undefined8','byte','word','dword',
            'char','short','int','uint','long','bool','float','double','void','DAT','LAB','PTR','DAT_'}
    types = [t for t in types if t not in junk and not t.startswith('FUN')][:10]

    vtables = sorted(set(re.findall(r'&(PTR_[A-Za-z0-9_]+|DAT_[0-9a-f]{8})\s*;', txt)))[:6]
    vt_writes = sorted(set(re.findall(r'\*\s*[A-Za-z]+\w*\s*=\s*&(\w+);', txt)))[:6]

    fun_calls = {}
    for m in re.finditer(r'(FUN_[0-9a-f]{8})\s*\(', txt):
        fun_calls[m.group(1)] = fun_calls.get(m.group(1), 0) + 1
    ncalls = len(fun_calls)
    top_callees = sorted(fun_calls.items(), key=lambda kv:-kv[1])[:8]

    allocs = sorted(set(re.findall(r'FUN_[0-9a-f]{8}\((0x[0-9a-f]+)\)', txt)))[:8]

    lines = txt.count('\n')
    out.append(f"### {a} size={size} lines={lines} funCalls={ncalls}/{len(fun_calls)}uniq")
    if strs:   out.append("  STR: " + ' | '.join(s.replace('\n','\\n')[:60] for s in strs))
    if apis:   out.append("  API: " + ', '.join(apis))
    if types:  out.append("  TYP: " + ', '.join(types))
    if vt_writes: out.append("  VTW: " + ', '.join(vt_writes))
    if allocs: out.append("  ALLOC-SIZES: " + ', '.join(allocs))
    if top_callees: out.append("  CALLEES: " + ', '.join(f"{c}x{n}" for c,n in top_callees))

Path('work/digest_all.txt').write_text('\n'.join(out))
print(f"wrote work/digest_all.txt for {len(addrs)} funcs, {len(out)} feature-lines")
