"""Shared helpers: live name corpus + store access."""
import re, sqlite3
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = ROOT / "work"
OUT = HERE / "out"
ADDR = re.compile(r"^(?:0x)?([0-9a-fA-F]{8})$")
NAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,120}$")

def db():
    return sqlite3.connect(HERE / "store.sqlite")

def _scan(path, named):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        f = line.split("\t")
        if len(f) < 2 or not f[1].strip():
            continue
        m = ADDR.match(f[0].strip())
        if m:
            named.setdefault(m.group(1).lower(), (f[1].strip(), f[2].strip() if len(f) > 2 else ""))

def load_names(include_wave=True):
    """addr -> (name, subsystem). Existing corpus first; wave outputs only fill gaps."""
    named = {}
    for p in sorted(WORK.glob("funcid_*.tsv")):
        _scan(p, named)
    if include_wave and OUT.exists():
        for p in sorted(OUT.glob("*.tsv")):
            _scan(p, named)
    return named
