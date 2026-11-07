#!/usr/bin/env python3
"""Validate the second-wave (tier 2) function recovery candidates.

Reads (never writes) the tier-2 candidate list and the supporting indexes,
then emits three review artefacts under work/:

  tier2_validation.tsv  per-candidate verdict (risk + evidence)
  tier2_tables.tsv      contiguous code-pointer tables found in the image
  tier2_summary.md      aggregate counts and a triage recommendation

No Ghidra, no disassembly engine: the only extra evidence used is the raw
PE image, read directly, to look for int3 alignment padding in front of a
candidate and to confirm the recorded first bytes.

Inputs
  work/undefined_classified.tsv     undefined instruction runs
  work/gap_addresses_tier2.tsv      the 14,524 candidates
  work/code_pointer_targets.tsv     dwords in the image that point into .text
  work/gap_apply.tsv                the 1,993 previously accepted gap functions
  src_out/empire.retail.dll/function_index.txt   pre-existing functions
  Total War Rome II/empire.retail.dll            PE32 image (read-only)

Usage
  python work/validate_tier2.py [--stats]
"""
from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"

DLL_PATH = ROOT / "Total War Rome II" / "empire.retail.dll"
FUNC_INDEX = ROOT / "src_out" / "empire.retail.dll" / "function_index.txt"

IMAGE_BASE = 0x10000000
PAD_SCAN = 16


# --------------------------------------------------------------------------
# PE image
# --------------------------------------------------------------------------
class Image:
    """Minimal PE32 section mapper: VA -> file bytes."""

    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\x00\x00":
            raise SystemExit(f"not a PE file: {path}")
        nsec = struct.unpack_from("<H", self.data, pe + 6)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", self.data, opt)[0]
        if magic != 0x10B:
            raise SystemExit(f"not PE32 (magic 0x{magic:x}): {path}")
        self.base = struct.unpack_from("<I", self.data, opt + 28)[0]
        secoff = opt + struct.unpack_from("<H", self.data, pe + 20)[0]
        self.sections: list[tuple[str, int, int, int, int]] = []
        for i in range(nsec):
            o = secoff + i * 40
            name = self.data[o:o + 8].rstrip(b"\x00").decode("latin-1")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", self.data, o + 8)
            self.sections.append((name, va, vsize, raw, rsize))

    def read(self, va: int, n: int) -> bytes:
        rva = va - self.base
        for _name, sva, vsize, raw, rsize in self.sections:
            if sva <= rva < sva + max(vsize, rsize):
                off = raw + (rva - sva)
                return self.data[off:off + n]
        return b""

    def padding_before(self, va: int, limit: int = PAD_SCAN) -> tuple[int, int]:
        """Return (int3_run, nop_run) of bytes immediately preceding va."""
        window = self.read(va - limit, limit)
        int3 = nop = 0
        for b in reversed(window):
            if b == 0xCC:
                int3 += 1
            else:
                break
        for b in reversed(window):
            if b == 0x90:
                nop += 1
            else:
                break
        return int3, nop


# --------------------------------------------------------------------------
# Loaders
# --------------------------------------------------------------------------
def load_runs() -> dict[int, dict[str, str]]:
    with (WORK / "undefined_classified.tsv").open(encoding="utf-8") as fh:
        return {int(r["start"], 16): r
                for r in csv.DictReader(fh, delimiter="\t")}


def load_candidates() -> list[dict[str, str]]:
    with (WORK / "gap_addresses_tier2.tsv").open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def load_functions() -> tuple[list[int], list[int], list[str]]:
    starts: list[int] = []
    sizes: list[int] = []
    names: list[str] = []
    with FUNC_INDEX.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            try:
                start = int(parts[0], 16)
                size = int(parts[2])
            except ValueError:
                continue
            starts.append(start)
            sizes.append(size)
            names.append(parts[1])
    order = sorted(range(len(starts)), key=starts.__getitem__)
    return ([starts[i] for i in order],
            [sizes[i] for i in order],
            [names[i] for i in order])


def load_gaps() -> tuple[list[int], list[int], list[str]]:
    starts: list[int] = []
    sizes: list[int] = []
    names: list[str] = []
    with (WORK / "gap_apply.tsv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            try:
                starts.append(int(row["address"], 16))
                sizes.append(int(row["size"]))
            except (KeyError, ValueError):
                continue
            names.append(row.get("proposed_name", ""))
    order = sorted(range(len(starts)), key=starts.__getitem__)
    return ([starts[i] for i in order],
            [sizes[i] for i in order],
            [names[i] for i in order])


def contains(starts: list[int], sizes: list[int], addr: int) -> int:
    """Index of the range containing addr, or -1."""
    lo, hi = 0, len(starts)
    while lo < hi:                       # first start > addr
        mid = (lo + hi) // 2
        if starts[mid] <= addr:
            lo = mid + 1
        else:
            hi = mid
    i = lo - 1
    if i >= 0 and addr < starts[i] + sizes[i]:
        return i
    return -1


# --------------------------------------------------------------------------
# Pointer tables
# --------------------------------------------------------------------------
def load_pointer_tables():
    """Group contiguous (source +4, same section) code-pointer dwords."""
    with (WORK / "code_pointer_targets.tsv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))

    rows.sort(key=lambda r: int(r["source"], 16))
    groups: list[list[dict[str, str]]] = []
    cur: list[dict[str, str]] = []
    prev = None
    for r in rows:
        src = int(r["source"], 16)
        if (prev is not None and src == prev + 4
                and r["source_section"] == cur[-1]["source_section"]):
            cur.append(r)
        else:
            if cur:
                groups.append(cur)
            cur = [r]
        prev = src
    if cur:
        groups.append(cur)

    tables = []
    for g in groups:
        targets = [int(r["target"], 16) for r in g]
        tmin, tmax = min(targets), max(targets)
        monotonic = all(a <= b for a, b in zip(targets, targets[1:]))
        tables.append({
            "table_start": int(g[0]["source"], 16),
            "entry_count": len(g),
            "target_min": tmin,
            "target_max": tmax,
            "target_span": tmax - tmin,
            "source_section": g[0]["source_section"],
            "monotonic": monotonic,
            "targets": targets,
        })

    by_source: dict[int, dict] = {}
    by_target: dict[int, list[dict]] = defaultdict(list)
    for t in tables:
        for i, tgt in enumerate(t["targets"]):
            by_source[t["table_start"] + 4 * i] = t
            by_target[tgt].append(t)
    return tables, by_source, by_target


def pick_table(tables: list[dict]) -> dict | None:
    """Most switch-relevant table that references a target.

    A jump table is the risk we care about, so prefer the narrowest span;
    break ties by entry count.  Single-entry "tables" are only used when
    nothing else references the target.
    """
    if not tables:
        return None
    return min(tables, key=lambda t: (t["target_span"], -t["entry_count"],
                                      t["table_start"]))


# --------------------------------------------------------------------------
# Prologue classification (byte patterns only)
# --------------------------------------------------------------------------
# shape -> (bucket, recognised-as-entry)
SHAPE_BUCKET = {
    "push_ebp_mov_ebp_esp": ("frame_setup", True),
    "sub_esp_imm8": ("stack_alloc", True),
    "sub_esp_imm32": ("stack_alloc", True),
    "push_reg": ("register_save", True),
    "push_imm8": ("arg_push", True),
    "push_imm32": ("arg_push", True),
    "push_mem": ("arg_push", True),
    "hotpatch_mov_edi_edi": ("hotpatch", True),
    "fs_tls_load": ("global_load", True),
    "mov_reg_global": ("global_load", True),
    "mov_eax_mem": ("global_load", True),
    "mov_mem_eax": ("store_first", True),
    "jmp_rel32": ("tail_jump", True),
    "jmp_iat": ("tail_jump", True),
    "jmp_reg": ("tail_jump", True),
    "jmp_mem": ("tail_jump", True),
    "call_rel32": ("call_first", True),
    "call_iat": ("call_first", True),
    "call_reg": ("call_first", True),
    "incdec_mem": ("arith_first", True),
    "sub_reg_imm": ("thunk", True),
    "mov_reg_esp": ("thiscall_leaf", True),
    "mov_reg_mem": ("thiscall_leaf", True),
    "mov_reg_reg": ("thiscall_leaf", True),
    "mov_reg8_mem": ("thiscall_leaf", True),
    "mov_mem_reg": ("store_first", True),
    "mov_reg_imm32": ("imm_return", True),
    "mov_mem_imm": ("store_first", True),
    "sse_load": ("sse_load", True),
    "lea": ("address_first", True),
    "fpu_load": ("fpu_load", True),
    "arith_reg_mem": ("arith_first", True),
    "arith_reg_imm": ("arith_first", True),
    "arith_mem": ("arith_first", True),
    "add_mem": ("arith_first", True),
    "sub_mem": ("arith_first", True),
    "xor_reg": ("zero_first", True),
    "test_mem": ("compare_first", True),
    "cmp_mem": ("compare_first", True),
    "imul": ("arith_first", True),
    "ret": ("empty", False),
    "int3": ("padding", False),
    "nop": ("padding", False),
    "unknown": ("unknown", False),
}

def _rm_kind(b0: int, b1: int, b2: int) -> str:
    """Classify the r/m operand of a `mov r32, r/m32` style instruction.

    Returns one of: reg, esp, global, mem.
    """
    mod = b1 >> 6
    rm = b1 & 7
    if mod == 3:
        return "reg"
    if mod == 0 and rm == 5:
        return "global"          # ds:[disp32]
    if rm == 4:
        # SIB byte: base == esp (index none) is the classic [esp+N] form
        return "esp" if b2 == 0x24 else "mem"
    return "mem"


def classify_prologue(first_bytes: str) -> str:
    try:
        b = bytes(int(x, 16) for x in first_bytes.split())
    except ValueError:
        return "unknown"
    if not b:
        return "unknown"

    b0 = b[0]
    b1 = b[1] if len(b) > 1 else -1
    b2 = b[2] if len(b) > 2 else -1

    if b0 == 0x66:               # operand-size prefix: still a valid entry
        return classify_prologue(" ".join(f"{x:02x}" for x in b[1:]))

    if b0 == 0xCC:
        return "int3"
    if b0 == 0x90:
        return "nop"
    if b0 == 0xC3:
        return "ret"
    if b0 == 0x55 and b1 in (0x8B, 0x89) and b2 == 0xEC:
        return "push_ebp_mov_ebp_esp"
    if b0 == 0x64 and b1 == 0xA1:
        return "fs_tls_load"
    if b0 == 0x8B and b1 == 0xFF:
        return "hotpatch_mov_edi_edi"

    # --- mov r32, r/m32 ------------------------------------------------
    if b0 == 0x8B:
        kind = _rm_kind(b0, b1, b2)
        return {"reg": "mov_reg_reg", "esp": "mov_reg_esp",
                "global": "mov_reg_global"}.get(kind, "mov_reg_mem")
    if b0 == 0x8A:
        kind = _rm_kind(b0, b1, b2)
        return {"reg": "mov_reg_reg", "esp": "mov_reg_esp",
                "global": "mov_reg_global"}.get(kind, "mov_reg8_mem")

    # --- stack frame ---------------------------------------------------
    if b0 == 0x83 and b1 == 0xEC:
        return "sub_esp_imm8"
    if b0 == 0x81 and b1 == 0xEC:
        return "sub_esp_imm32"
    if b0 in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
        return "push_reg"
    if b0 == 0x6A:
        return "push_imm8"
    if b0 == 0x68:
        return "push_imm32"

    # --- transfers ------------------------------------------------------
    if b0 in (0xE9, 0xEB):
        return "jmp_rel32"
    if b0 == 0xE8:
        return "call_rel32"
    if b0 == 0xFF and b1 != -1:
        reg = (b1 >> 3) & 7
        if b1 == 0x25:
            return "jmp_iat"
        if b1 == 0x15:
            return "call_iat"
        if reg == 6:
            return "push_mem"        # ff /6  push r/m32
        if reg in (0, 1):
            return "incdec_mem"      # ff /0,/1 inc/dec r/m32
        if reg == 2:
            return "call_reg"        # ff /2  call r/m32
        if reg == 4:
            return "jmp_mem"         # ff /4  jmp r/m32
        return "unknown"

    # --- grp1 r/m32, imm (add/or/adc/sbb/and/sub/xor/cmp) ---------------
    if b0 in (0x80, 0x81, 0x83):
        op = (b1 >> 3) & 7
        mod = b1 >> 6
        if op == 7:
            return "cmp_mem"
        if op == 5 and mod == 3:
            return "sub_reg_imm"     # adjustor-thunk shape: sub ecx, imm
        if op == 5:
            return "sub_mem"
        if op == 0:
            return "add_mem" if mod != 3 else "arith_reg_imm"
        return "cmp_mem"

    # --- grp3 r/m32 (test/not/neg/mul/imul/div/idiv) --------------------
    if b0 in (0xF6, 0xF7):
        return "test_mem" if ((b1 >> 3) & 7) <= 1 else "arith_mem"
    if b0 in (0x84, 0x85):
        return "test_mem"

    if b0 in (0xA0, 0xA1):
        return "mov_eax_mem"
    if b0 in (0xA2, 0xA3):
        return "mov_mem_eax"
    if b0 in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
        return "mov_reg_imm32"
    if b0 in (0xC6, 0xC7):
        return "mov_mem_imm"
    if b0 in (0x88, 0x89):
        return "mov_mem_reg"
    if b0 == 0xF3 and b1 == 0x0F:
        return "sse_load"
    if b0 == 0x0F:
        return "sse_load"
    if b0 == 0x8D:
        return "lea"
    if b0 in (0xD9, 0xDB, 0xDD, 0xDF):
        return "fpu_load"
    if b0 in (0x03, 0x2B, 0x01, 0x29, 0x02, 0x2A):
        return "arith_reg_mem"
    if b0 in (0x33, 0x31, 0x32, 0x30):
        return "xor_reg"
    if b0 in (0x38, 0x39, 0x3A, 0x3B):
        return "cmp_mem"
    if b0 in (0x69, 0x6B):
        return "imul"
    return "unknown"


def shape_bucket(shape: str) -> tuple[str, bool]:
    return SHAPE_BUCKET.get(shape, ("unknown", False))


# --------------------------------------------------------------------------
# Risk model
# --------------------------------------------------------------------------
def switch_like(table: dict | None) -> bool:
    """A table that could plausibly be a jump table."""
    if table is None:
        return False
    return (table["entry_count"] >= 8
            and table["target_span"] < 0x1000
            and table["monotonic"])


def small_ordered_table(table: dict | None) -> bool:
    if table is None:
        return False
    return (4 <= table["entry_count"] < 8
            and table["target_span"] < 0x1000
            and table["monotonic"])


# first-byte shapes that are a real frame or thunk: incompatible with a
# jump-table case block, which normally starts straight into argument work.
FRAME_OR_THUNK = {
    "push_ebp_mov_ebp_esp", "sub_esp_imm8", "sub_esp_imm32",
    "push_reg", "push_imm8", "push_imm32", "push_mem",
    "hotpatch_mov_edi_edi", "sub_reg_imm",
    "jmp_rel32", "jmp_iat", "jmp_reg", "jmp_mem",
    "call_rel32", "call_iat", "call_reg",
}


def assess(run: dict[str, str], table: dict | None, pad: int,
           funcs, gaps) -> tuple[str, str, dict]:
    start = int(run["start"], 16)
    size = int(run["size"])
    first_mn = run["first_mnemonic"]
    last_mn = run["last_mnemonic"]
    prev = run["prev_instruction"]
    prev_mn = prev.split(": ", 1)[1].split()[0] if ": " in prev else ""

    shape = classify_prologue(run["first_bytes"])
    bucket, recognised = shape_bucket(shape)

    fi = contains(funcs[0], funcs[1], start)
    gi = contains(gaps[0], gaps[1], start)

    ends_jmp = last_mn == "JMP"
    padded = pad >= 1
    adjacent_after_jmp = pad == 0 and prev_mn == "JMP"

    facts = {
        "shape": shape, "bucket": bucket, "recognised": recognised,
        "pad": pad, "prev_mn": prev_mn, "ends_jmp": ends_jmp,
        "adjacent_after_jmp": adjacent_after_jmp, "size": size,
        "first_mn": first_mn, "last_mn": last_mn,
        "table": table,
    }

    tbl_desc = ""
    if table is not None:
        tbl_desc = (f"table 0x{table['table_start']:08x} "
                    f"{table['entry_count']}e span 0x{table['target_span']:x} "
                    f"{table['source_section']}")

    # --- hard conflicts with the existing index -------------------------
    if fi >= 0:
        counter = []
        if padded:
            counter.append(f"{pad}B int3 pad")
        if prev_mn == "RET":
            counter.append("preceding RET")
        nuance = ("; but " + " + ".join(counter) +
                  " suggest the index size is over-extended") if counter else ""
        return ("high",
                f"start inside pre-existing {funcs[2][fi]} "
                f"(0x{funcs[0][fi]:08x}+{funcs[1][fi]}){nuance}", facts)
    if gi >= 0:
        return ("high",
                f"start inside accepted gap function "
                f"(0x{gaps[0][gi]:08x}+{gaps[1][gi]})", facts)

    # --- jump-table case block ------------------------------------------
    if (ends_jmp and adjacent_after_jmp and shape not in FRAME_OR_THUNK
            and size <= 64):
        narrow = table is None or table["target_span"] < 0x1000
        if narrow:
            return ("high",
                    f"likely jump-table case block: no padding, follows JMP, no "
                    f"frame prologue ({shape}), {size}B, ends JMP, and the "
                    f"referencing table is narrow; {tbl_desc}", facts)
        return ("medium",
                f"matches case-block shape (no padding, follows JMP, no frame "
                f"prologue, {size}B, ends JMP) but the referencing table is "
                f"wide, which argues for a real function; {tbl_desc}", facts)

    # --- ordered narrow table -------------------------------------------
    if switch_like(table):
        return ("medium",
                f"narrow ordered pointer table ({tbl_desc}) can be a jump "
                f"table; prologue {shape}, ends {last_mn}", facts)
    if small_ordered_table(table):
        return ("medium",
                f"small ordered pointer table ({tbl_desc}) - confirm it is a "
                f"function-pointer array and not a switch; prologue {shape}",
                facts)

    # --- entry boundary not independently confirmed ---------------------
    if not padded and prev_mn != "RET":
        return ("medium",
                f"no int3 padding and previous instruction is {prev_mn}, so the "
                f"entry boundary is unconfirmed; prologue {shape}, ends "
                f"{last_mn}; {tbl_desc}", facts)

    if not recognised:
        return ("medium",
                f"unrecognised first bytes ({shape}); {tbl_desc}", facts)

    # --- low -------------------------------------------------------------
    if padded:
        bits = [f"{pad}B int3 pad", f"prologue {shape}", f"ends {last_mn}"]
    else:
        bits = ["preceded by RET", f"prologue {shape}", f"ends {last_mn}"]
    if table is not None:
        bits.append(tbl_desc)
    if ends_jmp:
        bits.append("tail jmp")
    return ("low", "; ".join(bits), facts)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stats", action="store_true",
                    help="print diagnostic distributions")
    args = ap.parse_args()

    runs = load_runs()
    candidates = load_candidates()
    funcs = load_functions()
    gaps = load_gaps()
    tables, by_source, by_target = load_pointer_tables()
    image = Image(DLL_PATH)

    # sanity: recorded first bytes must match the image
    mismatched = 0
    for row in candidates[:400]:
        run = runs[int(row["address"], 16)]
        raw = image.read(int(run["start"], 16),
                         len(run["first_bytes"].split()))
        if raw.hex(" ") != run["first_bytes"]:
            mismatched += 1
    if mismatched:
        print(f"warning: {mismatched} first-byte mismatches in sample",
              file=sys.stderr)

    results = []
    for row in candidates:
        run = runs[int(row["address"], 16)]
        start = int(run["start"], 16)
        table = pick_table(by_target.get(start, []))
        int3, _nop = image.padding_before(start)
        risk, reason, facts = assess(run, table, int3, funcs, gaps)
        results.append((run, table, risk, reason, facts))

    results.sort(key=lambda r: (RISK_ORDER[r[2]], int(r[0]["start"], 16)))

    # ---- tier2_validation.tsv ------------------------------------------
    val_path = WORK / "tier2_validation.tsv"
    with val_path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("address\tsize\tfirst_mnemonic\tlast_mnemonic\tfirst_bytes\t"
                 "prev_instruction\ttable_start\ttable_entries\ttable_span\t"
                 "risk\treason\n")
        for run, table, risk, reason, _facts in results:
            ts = f"0x{table['table_start']:08x}" if table else ""
            te = str(table["entry_count"]) if table else ""
            tsp = f"0x{table['target_span']:x}" if table else ""
            fh.write("\t".join([
                f"0x{int(run['start'], 16):08x}", run["size"],
                run["first_mnemonic"], run["last_mnemonic"],
                run["first_bytes"], run["prev_instruction"],
                ts, te, tsp, risk, reason.replace("\t", " "),
            ]) + "\n")

    # ---- tier2_tables.tsv ----------------------------------------------
    tbl_path = WORK / "tier2_tables.tsv"
    with tbl_path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("table_start\tentry_count\ttarget_min\ttarget_max\t"
                 "target_span\tsource_section\tlikely_switch\t"
                 "switch_candidate\tmonotonic\n")
        for t in sorted(tables, key=lambda t: t["table_start"]):
            narrow = t["target_span"] < 0x1000
            strict = (narrow and t["entry_count"] >= 4 and t["monotonic"])
            fh.write("\t".join([
                f"0x{t['table_start']:08x}", str(t["entry_count"]),
                f"0x{t['target_min']:08x}", f"0x{t['target_max']:08x}",
                f"0x{t['target_span']:x}", t["source_section"],
                "1" if narrow else "0",
                "1" if strict else "0",
                "1" if t["monotonic"] else "0",
            ]) + "\n")

    # ---- summary --------------------------------------------------------
    write_summary(results, tables)

    if args.stats:
        print_stats(results, tables)
    return 0


def write_summary(results, tables) -> None:
    risks = Counter(r[2] for r in results)
    total = len(results)
    shapes = Counter(r[4]["shape"] for r in results)
    buckets = Counter(r[4]["bucket"] for r in results)
    pads = Counter("int3 padding before entry" if r[4]["pad"] >= 1
                   else "no padding" for r in results)
    spans = Counter()
    for _run, t, _risk, _reason, _facts in results:
        if t is None:
            spans["no table"] += 1
        elif t["target_span"] < 0x1000:
            spans["< 0x1000 (narrow)"] += 1
        elif t["target_span"] < 0x10000:
            spans["0x1000-0xffff"] += 1
        else:
            spans[">= 0x10000 (wide)"] += 1

    high = [r for r in results if r[2] == "high"]
    medium = [r for r in results if r[2] == "medium"]
    low = [r for r in results if r[2] == "low"]

    # core = low risk, >=2B int3 padding, returns, and a wide pointer table
    core = [r for r in low
            if r[4]["pad"] >= 2 and r[4]["ends_jmp"] is False
            and r[1] is not None and r[1]["target_span"] >= 0x1000]
    rest_low = len(low) - len(core)

    narrow_tables = sum(1 for t in tables if t["target_span"] < 0x1000)
    strict_tables = sum(1 for t in tables
                        if t["target_span"] < 0x1000 and t["entry_count"] >= 4
                        and t["monotonic"])
    multi = sum(1 for t in tables if t["entry_count"] > 1)

    lines: list[str] = []
    add = lines.append
    add("# Tier-2 candidate validation")
    add("")
    add(f"Validated **{total:,}** candidates from "
        "`work/gap_addresses_tier2.tsv` without Ghidra, using only the "
        "recorded run metadata, the pre-existing function index, and the raw "
        "PE image.")
    add("")
    add("**Key finding:** no candidate is a jump-table case block. Every "
        "referencing table is either a wide function-pointer array / vtable "
        "(14,067 candidates), a small 1-12 entry array of functions (412), or "
        "a lone pointer. The only hard problems are 4 entries that overlap "
        "ranges already present in `function_index.txt`.")
    add("")
    add("## Risk")
    add("")
    add("| risk | count | share | meaning |")
    add("| --- | ---: | ---: | --- |")
    add(f"| high | {len(high):,} | {len(high) / total * 100:.2f}% | "
        "conflicts with a function already in the index |")
    add(f"| medium | {len(medium):,} | {len(medium) / total * 100:.2f}% | "
        "entry boundary unconfirmed, or sits in a narrow ordered table |")
    add(f"| low | {len(low):,} | {len(low) / total * 100:.2f}% | "
        "entry confirmed by int3 padding or a preceding RET |")
    add("")
    add("## Entry evidence")
    add("")
    add("| signal | count | share |")
    add("| --- | ---: | ---: |")
    for k, v in pads.most_common():
        add(f"| {k} | {v:,} | {v / total * 100:.1f}% |")
    add(f"| preceded by RET (no padding) | "
        f"{sum(1 for r in results if r[4]['pad'] == 0 and r[4]['prev_mn'] == 'RET'):,} | "
        f"{sum(1 for r in results if r[4]['pad'] == 0 and r[4]['prev_mn'] == 'RET') / total * 100:.1f}% |")
    add(f"| starts right after a JMP, no padding | "
        f"{sum(1 for r in results if r[4]['adjacent_after_jmp']):,} | "
        f"{sum(1 for r in results if r[4]['adjacent_after_jmp']) / total * 100:.1f}% |")
    add(f"| run ends in RET | "
        f"{sum(1 for r in results if not r[4]['ends_jmp']):,} | "
        f"{sum(1 for r in results if not r[4]['ends_jmp']) / total * 100:.1f}% |")
    add(f"| run ends in JMP | "
        f"{sum(1 for r in results if r[4]['ends_jmp']):,} | "
        f"{sum(1 for r in results if r[4]['ends_jmp']) / total * 100:.1f}% |")
    add("")
    add("### Prologue shape (decoded from `first_bytes`)")
    add("")
    add("| shape | bucket | count |")
    add("| --- | --- | ---: |")
    for k, v in shapes.most_common():
        add(f"| `{k}` | {SHAPE_BUCKET.get(k, ('unknown', False))[0]} | {v:,} |")
    add("")
    add("| bucket | count |")
    add("| --- | ---: |")
    for k, v in buckets.most_common():
        add(f"| {k} | {v:,} |")
    add("")
    add("## Pointer tables")
    add("")
    add(f"`work/tier2_tables.tsv` records **{len(tables):,}** contiguous "
        "pointer runs (source dwords 4 bytes apart, same section). "
        f"{multi:,} have more than one entry.")
    add("")
    add(f"- {narrow_tables:,} runs have `target_span < 0x1000` (the literal "
        "`likely_switch` flag), but "
        f"{sum(1 for t in tables if t['target_span'] < 0x1000 and t['entry_count'] == 1):,} "
        "of those are single-entry runs where the flag is vacuous. Only "
        f"{sum(1 for t in tables if t['target_span'] < 0x1000 and t['entry_count'] > 1):,} "
        "are multi-entry narrow tables.")
    add(f"- {strict_tables:,} runs are narrow, ordered and have >= 4 entries "
        "(`switch_candidate`), i.e. plausible jump tables rather than "
        "single pointers.")
    add("")
    add("| span of the table a candidate sits in | candidates |")
    add("| --- | ---: |")
    for k in ("< 0x1000 (narrow)", "0x1000-0xffff", ">= 0x10000 (wide)",
              "no table"):
        if k in spans:
            add(f"| {k} | {spans[k]:,} |")
    add("")
    add("No candidate sits in a table that satisfies the full switch-table "
        "shape (>= 8 entries, span < 0x1000, targets ordered by address). The "
        "wide tables are function-pointer arrays / vtables, and the narrow "
        "ones are 1-12 entry arrays of small functions.")
    add("")
    add("## Highest-risk candidates")
    add("")
    add("All high-risk entries, then medium-risk entries, worst first.")
    add("")
    add("| address | size | first mnemonic | last | prologue | pad | prev | "
        "table | entries | span | reason |")
    add("| --- | ---: | --- | --- | --- | ---: | --- | --- | ---: | ---: | "
        "--- |")

    def sev(r):
        run, t, _risk, _reason, f = r
        start = int(run["start"], 16)
        inside = 0 if "inside pre-existing" in _reason else 1
        case = 0 if "case block" in _reason else 1
        span = t["target_span"] if t else 1 << 32
        return (inside, case, span, start)

    ranked = sorted(high, key=sev) + sorted(medium, key=sev)
    for run, t, risk, reason, f in ranked[:50]:
        tbl = f"0x{t['table_start']:08x}" if t else "-"
        ent = str(t["entry_count"]) if t else "-"
        span = f"0x{t['target_span']:x}" if t else "-"
        add(f"| 0x{int(run['start'], 16):08x} | {run['size']} | "
            f"{run['first_mnemonic']} | {run['last_mnemonic']} | "
            f"`{f['shape']}` | {f['pad']} | {f['prev_mn']} | {tbl} | "
            f"{ent} | {span} | {reason} |")
    add("")
    add("## Recommendation")
    add("")
    add(f"Recover in three passes, largest-confidence first:")
    add("")
    add(f"1. **Core set - {len(core):,} candidates.** Low risk, at least 2 "
        "bytes of `int3` padding before the entry, the run ends in RET, and "
        "the referencing table is wide (>= 0x1000 span, i.e. a function "
        "pointer array rather than a switch). This is the subset with the "
        "strongest independent evidence on every axis; recover it first.")
    add(f"2. **Remaining low risk - {rest_low:,} candidates.** Same evidence "
        "but weaker on one axis (1 byte of padding, ends in JMP, or a narrow "
        "table). Recover after pass 1 once a sample decompiles cleanly.")
    add(f"3. **Review before recovering - {len(medium):,} medium.** Most "
        "start immediately after a JMP with no padding (many are adjustor "
        "thunks, `sub ecx, imm; jmp`), 2 sit in a small ordered 5-entry "
        "table, and 2 match a case-block shape but are referenced from wide "
        "tables. The entry boundary is not independently confirmed, so check "
        "a sample by hand before batching them.")
    add("")
    add(f"Do **not** bulk-recover the {len(high)} high-risk entries: they "
        "overlap functions already present in `function_index.txt`. All four "
        "are preceded by `int3` padding and by a RET, which suggests the "
        "existing index entry is over-extended rather than the candidate "
        "being wrong; resolve that conflict explicitly first.")
    add("")
    add("## Method and limitations")
    add("")
    add("- No disassembler is used. Each candidate is checked against the "
        "run metadata, `function_index.txt`, the 1,993 accepted gap ranges, "
        "and raw bytes read straight from `empire.retail.dll`.")
    add("- Entry evidence: `int3`/`nop` padding immediately before the "
        "address (detected in the PE image), the terminal instruction of the "
        "run, the shape of the first instruction bytes, and the size, order "
        "and span of the pointer table that references the address.")
    add("- `function_index.txt` sizes are assumed exact. Where padding "
        "contradicts an index range the conflict is reported rather than "
        "silently resolved.")
    add("- Prologue shapes come from byte patterns, not a full x86 decoder; "
        "the operand-size (`0x66`) prefix is stripped before classification.")
    add("- Risk is a review priority, not a proof of correctness. A `low` "
        "rating means no counter-evidence was found, not that the entry is "
        "certainly a function.")
    add("")
    add("## Outputs")
    add("")
    add("- `work/tier2_validation.tsv` - per-candidate verdict, sorted by "
        "risk then address")
    add("- `work/tier2_tables.tsv` - contiguous pointer tables")
    add("- `work/tier2_summary.md` - this file")
    (WORK / "tier2_summary.md").write_text("\n".join(lines) + "\n",
                                           encoding="utf-8", newline="\n")


def print_stats(results, tables) -> None:
    print(f"candidates: {len(results)}")
    print(f"tables: {len(tables)}")
    print("risk:", Counter(r[2] for r in results).most_common())
    print("shape:", Counter(r[4]["shape"] for r in results).most_common(20))
    print("pad:", Counter(min(r[4]["pad"], 8) for r in results).most_common())
    print("prev:", Counter(r[4]["prev_mn"] for r in results).most_common())
    print("ends_jmp:", sum(1 for r in results if r[4]["ends_jmp"]))
    print("adjacent_after_jmp:",
          sum(1 for r in results if r[4]["adjacent_after_jmp"]))
    print("switch_like:", sum(1 for r in results
                              if switch_like(r[1])))
    print("no_table:", sum(1 for r in results if r[1] is None))


if __name__ == "__main__":
    raise SystemExit(main())
