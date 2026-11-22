"""Tier 0: adopt Ghidra library/import symbols for unnamed functions; resolve thunks.

usage: mechanical.py lib      -> work/funcid_w2_library.tsv
       mechanical.py thunks   -> work/funcid_w2_thunks.tsv (run after agent waves; idempotent)
"""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import WORK, db, load_names

def detemplate(s):
    out, depth = [], 0
    for ch in s:
        if ch == "<": depth += 1
        elif ch == ">": depth = max(0, depth - 1)
        elif depth == 0: out.append(ch)
    return "".join(out)

def san(s):
    s = re.sub(r"<lambda_[0-9a-f]+>", "lambda", s)
    if len(s) > 60:
        s = detemplate(s)
    s = s.replace("::", "__").replace("`", "").replace("'", "")
    s = re.sub(r"[^A-Za-z0-9_]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")[:110] or "anon"
    return "_" + s if s[0].isdigit() else s

def subsys(q):
    ql = q.lower()
    if "oc3ent" in ql or ql.startswith("fx"): return "middleware-facefx"
    if ql.startswith("curl") or "curl_" in ql: return "net-curl"
    if "libeay32" in ql or "ssleay32" in ql: return "net"
    if "twitchsdk" in ql: return "net"
    if "d3dx" in ql or "d3d" in ql: return "render"
    if "steam" in ql: return "net"
    if "binkw" in ql: return "render"
    return "crt"

def lib():
    out = WORK / "funcid_w2_library.tsv"
    if out.exists(): out.unlink()
    named = load_names(include_wave=False)
    rows = []
    for a, orig, qual, kind, thunk in db().execute("select addr,orig,qual,kind,thunk from fn"):
        if a in named or orig.startswith(("FUN_", "thunk_FUN_")):
            continue
        if thunk.startswith("external:"):
            name = f"imp_thunk_{san(orig)}"
            ev = f"mechanical: Ghidra import thunk -> {qual}"
        else:
            base = san(qual)
            m = re.match(r"(Catch_All|Catch|Unwind)@", orig)
            if m:
                name = f"seh_{m.group(1).lower()}_{a}"
            elif re.search(r"lambda|operator", base) or len(base) < 4:
                name = f"{base}_{a}"
            else:
                name = base
            ev = f"mechanical: Ghidra library/analysis symbol {qual}"[:300]
        rows.append(f"0x{a}\t{name}\t{subsys(qual)}\t{ev}")
    (WORK / "funcid_w2_library.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
    print("library rows", len(rows))

def thunks():
    out = WORK / "funcid_w2_thunks.tsv"
    if out.exists(): out.unlink()
    for _ in range(4):  # chains of thunks
        named = load_names()
        rows = []
        for a, thunk in db().execute("select addr,thunk from fn where kind='thunk' or thunk<>''"):
            if a in named or not thunk.startswith("internal:"):
                continue
            t = thunk.split(":")[1].lower()
            if t in named:
                tname, tsub = named[t]
                clean_name = f"thunk_{san(tname)[:100]}"
                clean_sub = re.sub(r"\(.*?\)", "", tsub or "").strip().lower().replace("_", "-")
                if not re.fullmatch(r"[a-z]+(?:-[a-z]+)*", clean_sub):
                    clean_sub = "core"
                ev = re.sub(r"\s+", " ", f"mechanical: jmp thunk to 0x{t} ({tname})").strip()[:300]
                rows.append(f"0x{a}\t{clean_name}\t{clean_sub}\t{ev}")
        if not rows: break
        with open(out, "a", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(rows) + "\n")
        print("thunk rows +", len(rows))

if __name__ == "__main__":
    {"lib": lib, "thunks": thunks}[sys.argv[1]]()
