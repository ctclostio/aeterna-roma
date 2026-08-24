import sys, os, re
d='../src_out/empire.retail.dll/decomp'
addrs=[a.strip() for a in open('shard_00.txt') if a.strip()]
start,n=int(sys.argv[1]),int(sys.argv[2])
H=int(sys.argv[3]) if len(sys.argv)>3 else 1600
for a in addrs[start:start+n]:
    p=os.path.join(d,a[2:]+'_FUN_'+a[2:]+'.c')
    if not os.path.exists(p): print(f'===== {a} MISSING'); continue
    t=open(p,encoding='utf-8',errors='replace').read()
    print(f'===== {a} len={len(t)}')
    print(t[:H])
    print()
