"""Aggregate audit verdicts from workflow journals given as args."""
import json, sys
S = dict(sampled=0, ok=0, vague=0, wrong=0); shards = 0; redo = []; pats = []
for f in sys.argv[1:]:
    for line in open(f, encoding="utf-8"):
        j = json.loads(line)
        if j.get("type") != "result": continue
        v = j.get("result") or j.get("value")
        if isinstance(v, dict) and "wrong" in v:
            shards += 1
            for k in S: S[k] += v.get(k, 0)
            if v["wrong"] >= 4: redo.append(v["sid"])
            if v.get("worst_pattern", "none")[:4].lower() != "none": pats.append(f"{v['sid']}: {v['worst_pattern'][:230]}")
n = S["sampled"] or 1
print(f"audited shards {shards}: {S} ok={100*S['ok']/n:.1f}% vague={100*S['vague']/n:.1f}% wrong={100*S['wrong']/n:.1f}% redo={redo}")
for p in pats[-int(__import__('os').environ.get('NPAT', 0)):] if __import__('os').environ.get('NPAT') else []: print(" ", p)
