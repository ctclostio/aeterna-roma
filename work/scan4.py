import pickle, sys, io
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,errors='replace')
recs=pickle.load(open('evidence.pkl','rb'))
done=set(l.split('\t')[0] for l in open('funcid_solo_batch1.tsv',encoding='utf-8'))
lo,hi=int(sys.argv[1]),int(sys.argv[2])
mid=[a for a,r in recs.items() if a not in done and 1<=len(r['strings'])<=2]
mid.sort(key=lambda x:int(x,16))
for a in mid[lo:hi]:
    r=recs[a]
    api=[x for x in r['api'] if len(x)>4 and not x.startswith(('CONCAT','ZEXT','SEXT','SBORROW','CARRY','LAB_','FID_','thunk_'))][:5]
    print(f"{a} sz={r['size']} :: {' | '.join(x[:56] for x in r['strings'][:2])}")
    if api: print(f"   api: {','.join(api)}")
print(f"# range {lo}:{hi} of {len(mid)}")
