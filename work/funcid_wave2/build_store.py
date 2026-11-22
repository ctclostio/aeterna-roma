"""Build work/funcid_wave2/store.sqlite: canonical index + bodies + call edges + table slots.

Static inputs only (canonical export, pe_meta, code_pointer_targets). Live names are
read by packet.py at packet time so later shards see earlier shards' names.
"""
import json, re, sqlite3, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAN = ROOT / "generated/canonical/f0caa97fbcb663124542c80eaebc440031e3d65708ec0630678beb77d85a884a"
DB = Path(__file__).with_name("store.sqlite")

def rows(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        hdr = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            yield dict(zip(hdr, line.rstrip("\n").split("\t")))

def body_of(text):
    lines = text.splitlines()
    i = 0
    while i < len(lines) and (lines[i].startswith("//") or not lines[i].strip()):
        i += 1
    out = [l for l in lines[i:] if not l.startswith("// Canonical export EOF")]
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)

def main():
    if DB.exists():
        DB.unlink()
    db = sqlite3.connect(DB)
    db.executescript("""
    create table fn(addr text primary key, size int, kind text, orig text, qual text, src_type text,
                    sig text, thunk text, body text);
    create table edge(src text, dst text, n int);
    create table slot(target text, slot int);
    create table imp(name text primary key);
    """)
    fns = []
    for r in rows(CAN / "metadata/canonical_function_index.tsv"):
        a = r["entry"].lower()
        if not re.fullmatch(r"[0-9a-f]{8}", a):
            continue
        p = CAN / "sources" / f"decomp_fn_{a}.c"
        try:
            body = body_of(p.read_text(encoding="utf-8", errors="replace"))
        except FileNotFoundError:
            body = ""
        thunk = (r.get("resolved_thunk_target") or r.get("direct_thunk_target") or "").lower()
        fns.append((a, int(r["size"] or 0), r["kind"], r["original_name"], r["original_qualified_name"],
                    r["source_type"], r["signature"], thunk, body))
    db.executemany("insert into fn values (?,?,?,?,?,?,?,?,?)", fns)
    edges = []
    for r in rows(CAN / "references.tsv"):
        if r.get("target_kind") == "function":
            edges.append((r["source_entry"].lower(), r["target_address"].lower(), int(r["occurrences"] or 1)))
    db.executemany("insert into edge values (?,?,?)", edges)
    slots = []
    for r in rows(ROOT / "work/code_pointer_targets.tsv"):
        slots.append((r["target"].lower().removeprefix("0x"), int(r["source"], 16)))
    db.executemany("insert into slot values (?,?)", slots)
    imps = json.loads((ROOT / "pe_meta/empire.retail_imports.json").read_text())
    names = set()
    for dll, lst in imps.items():
        for it in lst:
            n = it.get("name") if isinstance(it, dict) else it
            if n:
                names.add(str(n))
    db.executemany("insert or ignore into imp values (?)", [(n,) for n in names])
    db.executescript("""
    create index e_src on edge(src); create index e_dst on edge(dst);
    create index s_t on slot(target); create index s_s on slot(slot);
    """)
    db.commit()
    print(f"fn={len(fns)} edges={len(edges)} slots={len(slots)} imports={len(names)}")

if __name__ == "__main__":
    main()
