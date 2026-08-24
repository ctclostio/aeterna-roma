import sys, os
d='../src_out/empire.retail.dll/decomp'
addrs=[a.strip() for a in open('shard_00.txt') if a.strip()]
start,n=int(sys.argv[1]),int(sys.argv[2])
for a in addrs[start:start+n]:
    p=os.path.join(d,a[2:]+'_FUN_'+a[2:]+'.c')
    print('='*20, a, '='*20)
    if os.path.exists(p):
        t=open(p,encoding='utf-8',errors='replace').read()
        print(t[:6000])
        if len(t)>6000: print(f'...[TRUNC {len(t)} bytes]')
    else:
        print('MISSING')
