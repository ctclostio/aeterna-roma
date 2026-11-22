"""Print prior-analysis lines (docs/, port/, work/*.md) that mention each shard address."""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, ROOT

sid = sys.argv[1]
addrs = (HERE / "shards" / f"{sid}.txt").read_text().split()
files = [p for d in ("docs", "port") for p in (ROOT / d).rglob("*")
         if p.is_file() and p.suffix in {".md", ".h", ".c", ".cpp", ".json", ".tsv"} and p.stat().st_size < 4_000_000]
files += list((ROOT / "work").glob("*.md"))
pat = re.compile(r"(?:0x)?(" + "|".join(addrs) + r")\b", re.I)
hits = {}
for p in files:
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        for m in pat.finditer(ln):
            lst = hits.setdefault(m.group(1).lower(), [])
            if len(lst) < 3:
                lst.append(f"{p.relative_to(ROOT).as_posix()}: {ln.strip()[:200]}")
for a in addrs:
    if a in hits:
        print(f"0x{a}"); print("\n".join("  " + h for h in hits[a]))
print(f"[{len(hits)}/{len(addrs)} addresses have prior mentions]")
