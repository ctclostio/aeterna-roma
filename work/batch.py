import subprocess,sys
from pathlib import Path
shard=sys.argv[1]; start=int(sys.argv[2]); count=int(sys.argv[3])
addrs=[x for x in Path(shard).read_text().split()]
for a in addrs[start:start+count]:
    r=subprocess.run(['python','work/extract_evidence.py',a],capture_output=True,text=True)
    print(r.stdout.rstrip()); print(r.stderr.rstrip()[:200] if r.returncode else '', end='\n')
