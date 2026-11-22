"""Deterministic audit sample: mostly [H]/[M] rows (semantic claims), a few [L]."""
import hashlib, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT
sid, n = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 12
rows = [l.split("\t") for l in (OUT / f"{sid}.tsv").read_text(encoding="utf-8").splitlines()]
key = lambda r: hashlib.sha256((sid + r[0]).encode()).hexdigest()
sem = sorted((r for r in rows if r[3][:3] in ("[H]", "[M]")), key=key)
low = sorted((r for r in rows if r[3][:3] == "[L]"), key=key)
k = min(len(low), max(2, n // 5))
pick = sem[: n - k] + low[:k]
if len(pick) < n: pick += [r for r in low[k:] + sem[n - k:]][: n - len(pick)]
print(",".join(r[0] for r in pick))
