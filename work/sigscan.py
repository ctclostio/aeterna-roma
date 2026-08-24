import sys, os, re
d='../src_out/empire.retail.dll/decomp'
addrs=[a.strip() for a in open('shard_00.txt') if a.strip()]
start,n=int(sys.argv[1]),int(sys.argv[2])
apis=re.compile(r'\b(CREATE|MessageBox|GetDevice|Draw|Present|fopen|fread|fwrite|CreateFile|ReadFile|WriteFile|socket|send|recv|WSA|DirectSound|waveOut|midi|CoCreate|RegOpen|RegQuery|LoadLibrary|GetProcAddress|Sleep|WaitFor|EnterCritical|LeaveCritical|Interlocked|QueryPerformance|timeGetTime|GetTickCount|PeekMessage|DispatchMessage|ShowCursor|SetCursor|ClipCursor|GetAsyncKeyState)\w*',re.I)
for a in addrs[start:start+n]:
    p=os.path.join(d,a[2:]+'_FUN_'+a[2:]+'.c')
    if not os.path.exists(p): print(f'--- {a} MISSING'); continue
    t=open(p,encoding='utf-8',errors='replace').read()
    strs=set(re.findall(r'"([^"\n]{4,60})"',t))
    ap=sorted(set(m.group(0) for m in apis.finditer(t)))
    calls=sorted(set(re.findall(r'FUN_[0-9a-f]{8}',t)))[:6]
    vt=sorted(set(re.findall(r'PTR_FUN_[0-9a-f]{8}|PTR_LAB_[0-9a-f]{8}',t)))[:3]
    flts=sorted(set(re.findall(r'0x[34][0-9a-f]{7}',t)))[:5]
    big=sorted(set(re.findall(r'FUN_100d12b0\((0x[0-9a-f]+)\)',t)))
    sz=len(t)
    ec='thiscall' if 'in_ECX' in t else ''
    print(f'--- {a} ({sz}B){ec}')
    if strs: print('  str:',list(strs)[:6])
    if ap: print('  api:',ap[:8])
    if vt: print('  vt:',vt)
    if flts: print('  f:',flts)
    if big: print('  alloc:',big)
    if calls: print('  calls:',calls)
