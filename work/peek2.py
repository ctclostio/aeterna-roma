import pickle,re,sys,io
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,errors='replace')
recs=pickle.load(open('evidence.pkl','rb'))
named={}
for line in open('funcid_solo_batch1.tsv',encoding='utf-8'):
    p=line.rstrip('\n').split('\t')
    if len(p)>=2: named.setdefault(p[0][2:],p[1])
done=set(l.split('\t')[0] for l in open('funcid_solo_batch1.tsv',encoding='utf-8'))
dark=sorted((r for a,r in recs.items() if a not in done), key=lambda r:-r['size'])
lo,hi=int(sys.argv[1]),int(sys.argv[2])
for r in dark[lo:hi]:
    a=r['addr']
    try: txt=open(f'../src_out/empire.retail.dll/decomp/{a[2:]}_FUN_{a[2:]}.c',encoding='utf-8',errors='replace').read()
    except:
        import glob
        g=glob.glob(f'../src_out/empire.retail.dll/decomp/{a[2:]}_*.c')
        if not g:
            print(f'{a} sz={r["size"]} NO_FILE'); continue
        txt=open(g[0],encoding='utf-8',errors='replace').read()
    feats=[]
    for api in ('QueryPerformanceCounter','CreateFileW','ReadFile','WriteFile','fopen','fwrite','VirtualAlloc','HeapAlloc','CoCreateGuid','socket','send','recv','CreateThread','WaitForSingleObject','GetTickCount','timeGetTime','PeekMessageW','RegOpenKey','FindResourceW','GetSaveFileNameW','wglGetProcAddress','SetPixelFormat','BinkOpen','TTV_','SSL_','X509'):
        if api in txt: feats.append(api)
    # top callees w/ names
    cc={}
    for m in re.finditer(r'\bFUN_([0-9a-f]{8})\b',txt):
        cc[m.group(1)]=cc.get(m.group(1),0)+1
    top=sorted(cc.items(),key=lambda kv:-kv[1])[:5]
    tops=' '.join(f"{named.get(c,c[:6])}x{n}" for c,n in top)
    nloc=len(re.findall(r'(?:local|aiStack|auStack|uStack|puStack|pcStack|pwStack|pfStack|iStack)\S* \[',txt))
    print(f"{a} sz={r['size']} sw={r['switch']} locarr={nloc} feats={feats}")
    print(f"   calls: {tops}")
print(f'# {lo}:{hi} of {len(dark)}')
