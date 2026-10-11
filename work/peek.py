import pickle,re,sys,io
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,errors='replace')
recs=pickle.load(open('evidence.pkl','rb'))
done=set(l.split('\t')[0] for l in open('funcid_solo_batch1.tsv',encoding='utf-8'))
dark=sorted((r for a,r in recs.items() if a not in done), key=lambda r:-r['size'])
lo,hi=int(sys.argv[1]),int(sys.argv[2])
for r in dark[lo:hi]:
    a=r['addr']
    txt=open(f'../src_out/empire.retail.dll/decomp/{a[2:]}_FUN_{a[2:]}.c',encoding='utf-8',errors='replace').read()
    # distinctive ops
    feats=[]
    if 'QueryPerformanceCounter' in txt: feats.append('QPC')
    for api in ('CreateFileW','ReadFile','WriteFile','fopen','fwrite','VirtualAlloc','HeapAlloc','CoCreateGuid','RegOpenKeyW','socket','send','WSAStartup','CreateThread','WaitForSingleObject','EnterCriticalSection','InitializeCriticalSectionAndSpinCount','GetTickCount','timeGetTime','memcpy','sprintf'):
        if api in txt: feats.append(api)
    vts=re.findall(r'\*\*\(code \*\*\)\(\*\(int \*\*\)\(param_\d \+ (0x[0-9a-f]+)\)\)',txt)[:4]
    consts=re.findall(r'= (0x[0-9a-f]{5,7});',txt)[:6]
    nswitch=r['switch']
    print(f"{a} sz={r['size']} sw={nswitch} feats={feats[:8]} vt={vts} consts={consts}")
    print(f"    funs: {' '.join(f'{c}x{n}' for c,n in r['funs'][:6])}")
print(f'# {lo}:{hi} of {len(dark)}')
