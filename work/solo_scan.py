import re, sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
D = r"X:/decompilation/src_out/empire.retail.dll/decomp"
def scan(addr):
    a = addr.replace('0x','')
    path = None
    for f in os.listdir(D):
        if f.startswith(a):
            path = os.path.join(D, f); break
    if not path:
        print(f"=== {addr} MISSING"); return
    src = open(path, encoding='utf-8', errors='replace').read()
    lines = src.count('\n')
    strs = re.findall(r'"([^"]{4,80})"', src)
    # dedupe preserving order
    seen = []; 
    for s in strs:
        if s not in seen: seen.append(s)
    calls = {}
    for m in re.findall(r'\b(FUN_[0-9a-f]{8})\b', src):
        calls[m] = calls.get(m,0)+1
    apis = sorted(set(re.findall(r'\b(IsDebuggerPresent|GetTickCount|GetLastError|CreateFile[AW]|ReadFile|WriteFile|FindFirstFile[AW]|FindNextFile[AW]|CloseHandle|Sleep|WaitForSingleObject|EnterCriticalSection|LeaveCriticalSection|InitializeCriticalSection|DeleteCriticalSection|GetCurrentThreadId?|TlsGetValue|TlsSetValue|InterlockedIncrement|InterlockedDecrement|LoadLibrary[AW]?|GetProcAddress|VirtualAlloc|VirtualFree|VirtualProtect|HeapAlloc|HeapFree|GetProcessHeap|malloc|free|memcpy|memset|memmove|wcsncpy|strcpy|strcat|sprintf|_snprintf|fprintf|MultiByteToWideChar|WideCharToMultiByte|SendMessage[AW]?|PostMessage[AW]?|RegisterClass[AW]?|CreateWindowEx[AW]?|ShowWindow|UpdateWindow|DestroyWindow|DefWindowProc[AW]?|GetMessage[AW]?|PeekMessage[AW]?|TranslateMessage|DispatchMessage[AW]?|timeBeginPeriod|timeGetTime|waveOut[A-Za-z]+|directsound[a-z]*|DirectSoundCreate|CoCreateInstance|CoInitialize|RegOpenKeyEx[AW]?|RegQueryValueEx[AW]?|RegSetValueEx[AW]?|GetModuleFileName[AW]?|GetModuleHandle[AW]?|OutputDebugString[AW]?|SetEvent|CreateEvent[AW]?|CreateThread|_beginthreadex|fopen|fread|fwrite|fclose|fseek|ftell|_wfopen|qsort|bsearch|sqrt|sinf?|cosf?|atan2f?|powf?)\b', src)))
    dats = sorted(set(re.findall(r'\bDAT_[0-9a-f]{8}\b', src)))[:12]
    vts = sorted(set(re.findall(r'&DAT_[0-9a-f]{8}|vftable', src)))
    print(f"=== {addr} ({os.path.basename(path)}) {lines}L")
    if seen: print("  STR:", ' | '.join(s[:70] for s in seen[:14]))
    top = sorted(calls.items(), key=lambda x:-x[1])[:18]
    if top: print("  CALLS:", ', '.join(f"{k}x{v}" for k,v in top))
    if apis: print("  API:", ', '.join(apis[:20]))
    if dats: print("  DATS:", ', '.join(dats))
for a in sys.argv[1:]:
    scan(a)
