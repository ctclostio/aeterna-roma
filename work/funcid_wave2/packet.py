"""Emit evidence packets for a shard (or ad-hoc address list) using LIVE names.

usage: packet.py <shard_id>            -> writes packets/<shard_id>_pN.txt, prints paths
       packet.py --addrs a,b,c [--tag t] -> same for ad-hoc list (audit use)
"""
import bisect, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, db, load_names

BODY_CAP = 3000
PART_CHARS = 40000
FN_TOK = re.compile(r"\bdecomp_fn_([0-9a-f]{8})\b")
STR = re.compile(r'L?"(?:[^"\\n]|\.)*"')
DECL = re.compile(r"^\s+[A-Za-z_][\w \*]*?[\s\*]\w+(\s*\[[^\]]*\])?;\s*(//.*)?$")

def strip_decls(body):
    lines = body.splitlines()
    try:
        i = lines.index("{")
    except ValueError:
        return body
    j = i + 1
    while j < len(lines) and DECL.match(lines[j]):
        j += 1
    if j < len(lines) and not lines[j].strip():
        j += 1
    return "\n".join(lines[:i + 1] + lines[j:])

def render(body, named):
    def sub(m):
        a = m.group(1)
        return f"{named[a][0]}/*{a}*/" if a in named else f"fn_{a}"
    return FN_TOK.sub(sub, body)

def sites(c, a, callers, named):
    out = []
    tok = f"decomp_fn_{a}"
    pref = sorted(callers, key=lambda x: x not in named)[:6]
    for x in pref:
        r = c.execute("select body from fn where addr=?", (x,)).fetchone()
        if not r: continue
        for ln in r[0].splitlines():
            if tok in ln:
                who = named[x][0] if x in named else f"fn_{x}"
                out.append(f"  {who}: {render(ln.strip(), named)[:220]}")
                break
    return out

def build(addrs, tag, with_sites=False):
    named = load_names()
    c = db()
    keys = sorted(named)
    out = []
    for a in addrs:
        r = c.execute("select size,kind,orig,qual,sig,thunk,body from fn where addr=?", (a,)).fetchone()
        if not r:
            out.append(f"@@ 0x{a} MISSING\n"); continue
        size, kind, orig, qual, sig, thunk, body = r
        callers = [x for (x,) in c.execute("select src from edge where dst=? order by src", (a,))]
        ncallees = c.execute("select count(*) from edge where src=?", (a,)).fetchone()[0]
        nm_callers = [f"{named[x][0]}@{x}" for x in callers if x in named][:6]
        un_callers = [f"fn_{x}" for x in callers if x not in named][:3]
        k = bisect.bisect_left(keys, a)
        prev = keys[k - 1] if k > 0 else None
        nxt = keys[k] if k < len(keys) and keys[k] != a else (keys[k + 1] if k + 1 < len(keys) else None)
        nb = []
        if prev: nb.append(f"prev={named[prev][0]}[{named[prev][1]}]@-0x{int(a,16)-int(prev,16):x}")
        if nxt: nb.append(f"next={named[nxt][0]}[{named[nxt][1]}]@+0x{int(nxt,16)-int(a,16):x}")
        sib = []
        for (s,) in c.execute("select slot from slot where target=? limit 3", (a,)):
            for (t,) in c.execute("select target from slot where slot between ? and ? and target<>?",
                                  (s - 32, s + 32, a)):
                if t in named and len(sib) < 5:
                    sib.append(named[t][0])
        head = f"@@ 0x{a} size={size} kind={kind}"
        if not orig.startswith(("FUN_", "thunk_FUN_")): head += f" ghidra_sym={qual}"
        if thunk: head += f" thunk_to={named.get(thunk, ('fn_'+thunk,))[0]}"
        head += f" callers={len(callers)} callees={ncallees}"
        lines = [head]
        if callers: lines.append("callers: " + ", ".join(nm_callers + un_callers))
        lines.append("near: " + " ".join(nb))
        if sib: lines.append("table_siblings: " + ", ".join(dict.fromkeys(sib)))
        if with_sites and callers:
            lines.append("call_sites:"); lines += sites(c, a, callers, named)
        b = render(strip_decls(body), named)
        if len(b) > BODY_CAP:
            rest = b[BODY_CAP:]
            strs = list(dict.fromkeys(STR.findall(rest)))[:12]
            calls = list(dict.fromkeys(re.findall(r"\b(\w+)/\*[0-9a-f]{8}\*/", rest)))[:12]
            b = b[:BODY_CAP] + f"\n...[truncated {len(rest)} chars; later strings: {' '.join(strs)}; later named calls: {', '.join(calls)}]"
        lines.append(b)
        out.append("\n".join(lines) + "\n")
    pdir = HERE / "packets"; pdir.mkdir(exist_ok=True)
    for old in pdir.glob(f"{tag}_p*.txt"):
        old.unlink()
    parts, cur = [], ""
    for blk in out:
        if cur and len(cur) + len(blk) > PART_CHARS:
            parts.append(cur); cur = ""
        cur += blk + "\n"
    if cur: parts.append(cur)
    paths = []
    for i, p in enumerate(parts):
        f = pdir / f"{tag}_p{i}.txt"
        f.write_text(p, encoding="utf-8", newline="\n")
        paths.append(str(f))
    print(f"{len(addrs)} functions, {len(parts)} parts:")
    print("\n".join(paths))

if __name__ == "__main__":
    if sys.argv[1] == "--addrs":
        tag = sys.argv[sys.argv.index("--tag") + 1] if "--tag" in sys.argv else "adhoc"
        build([x.lower().removeprefix("0x") for x in sys.argv[2].split(",") if x], tag)
    else:
        sid = sys.argv[1]
        addrs = (HERE / "shards" / f"{sid}.txt").read_text().split()
        build(addrs, sid, with_sites=sid.startswith("h"))
