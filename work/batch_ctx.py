#!/usr/bin/env python3
"""Print compact context for a batch of addresses: sig, strings, API/callee names, size."""
import sys, re, os
DECOMP = 'X:/decompilation/src_out/empire.retail.dll/decomp'
addrs = [a.strip() for a in sys.argv[1:] if a.strip()]
for a in addrs:
    f = f"{DECOMP}/{a[2:]}_FUN_{a[2:]}.c"
    try:
        src = open(f, encoding='utf-8', errors='replace').read()
    except OSError as e:
        print(f"### {a} MISSING"); continue
    nlines = src.count('\n')
    m = re.search(r'^([^\n]*FUN_[0-9a-f]+\([^)]*\))', src, re.M)
    sig = m.group(1).strip() if m else '?'
    strs = re.findall(r'"((?:[^"\\\n]|\\.){2,60})"', src)
    # dedupe preserve order, skip generic single chars
    seen = []; 
    for s in strs:
        if s not in seen and len(s) > 1: seen.append(s)
    apis = sorted(set(re.findall(r'\b(?:CreateFile|FindFirstFile|ReadFile|WriteFile|LoadLibrary|GetProcAddress|VirtualAlloc|HeapAlloc|GetProcessHeap|CoTaskMem|WideCharToMultiByte|MultiByteToWideChar|fopen|fread|fwrite|malloc|free|memcpy|memset|sprintf|printf|swprintf|MessageBox|QueryPerformance|Sleep|EnterCriticalSection|LeaveCriticalSection|[A-Z][A-Za-z]+File[W]?|[A-Z][A-Za-z]+Resource[A-Za-z]*)\b', src)))
    calls = {}
    for c in re.findall(r'\b(FUN_[0-9a-f]{8})\(', src):
        calls[c] = calls.get(c, 0) + 1
    topcalls = sorted(calls.items(), key=lambda x: -x[1])[:12]
    named = sorted(set(re.findall(r'\b([A-Z][A-Za-z0-9_]{4,})\s*\(', src)) - set(apis))[:20]
    print(f"### {a} ({nlines}L)")
    print(f"sig: {sig}")
    if seen: print(f"str: {seen[:25]}")
    if apis: print(f"api: {apis[:15]}")
    if named: print(f"named: {named[:18]}")
    if topcalls: print("fun:", ' '.join(f"{c}x{n}" for c,n in topcalls))
