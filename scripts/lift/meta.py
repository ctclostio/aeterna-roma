"""Per-function trial metadata and job files shared by both sides of the test.

The rules here are the ones docs/lifted_tier.md lists under "Per-function
metadata". Both the reference debugger and the lifted runner read the job file
this module writes, so neither side derives call sites or stubs on its own.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from functools import lru_cache

import capstone
from capstone import x86_const as X

from image import IMAGE_BASE, PAGE, Function, function_index, load_functions, load_image

INSN_CPUID, INSN_RDTSC, INSN_TRAP, INSN_XGETBV, INSN_RDTSCP = 1, 2, 3, 4, 5
STUB_KINDS = {
    X.X86_INS_CPUID: INSN_CPUID,
    X.X86_INS_RDTSC: INSN_RDTSC,
    X.X86_INS_RDTSCP: INSN_RDTSCP,
    X.X86_INS_XGETBV: INSN_XGETBV,
    X.X86_INS_INT: INSN_TRAP,
    X.X86_INS_INT1: INSN_TRAP,
    X.X86_INS_INTO: INSN_TRAP,
    X.X86_INS_SYSCALL: INSN_TRAP,
    X.X86_INS_SYSENTER: INSN_TRAP,
}
# x87 instructions that do not consume ST(0); anything else starting with "f"
# right after a call means the callee returned a value on the x87 stack.
X87_NON_CONSUMERS = frozenset({
    "fld", "fild", "fbld", "fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2",
    "fldcw", "fnstcw", "fnstsw", "fninit", "fnclex", "fldenv", "fnstenv", "fnsave", "frstor",
    "fxsave", "fxrstor", "ffree", "fwait", "femms", "fnop", "fdecstp", "fincstp",
})
WINDOW_MAX = 1024
SEED_BASE = 0x5EED0000


def mix32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= x >> 16
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x ^= x >> 13
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x ^= x >> 16
    return x


def seed_for(addr: int, index: int) -> int:
    return mix32(addr ^ (SEED_BASE + index))


@dataclass
class Meta:
    fn: Function
    insns: list  # capstone instructions, ascending, over all body ranges
    calls: dict[int, tuple[int, bool]] = field(default_factory=dict)  # return addr -> (pop_bytes, fp_ret)
    stubs: dict[int, tuple[int, int]] = field(default_factory=dict)   # addr -> (length, kind)
    windows: list[tuple[int, int]] = field(default_factory=list)      # (lo, hi_exclusive)
    undecoded: int = 0  # bytes in the body ranges capstone could not decode


@lru_cache(maxsize=1)
def _decoder() -> capstone.Cs:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    return md


@lru_cache(maxsize=1)
def _starts() -> list[int]:
    return [f.addr for f in load_functions()]


@lru_cache(maxsize=1)
def _range_starts() -> tuple[list[int], list[int]]:
    spans = sorted(r for f in load_functions() for r in f.ranges)
    return [lo for lo, _ in spans], [hi for _, hi in spans]


def in_any_function(addr: int) -> bool:
    los, his = _range_starts()
    i = bisect.bisect_right(los, addr) - 1
    return i >= 0 and addr < his[i]


def decode(fn: Function) -> tuple[list, int]:
    image = load_image()
    md = _decoder()
    insns, undecoded = [], 0
    for lo, hi in fn.ranges:
        end = lo
        for ins in md.disasm(image[lo - IMAGE_BASE:hi - IMAGE_BASE], lo):
            insns.append(ins)
            end = ins.address + ins.size
        undecoded += hi - end
    return insns, undecoded


def build_meta(fn: Function) -> Meta:
    insns, undecoded = decode(fn)
    meta = Meta(fn=fn, insns=insns, undecoded=undecoded)
    index = function_index()
    by_addr = {ins.address: ins for ins in insns}
    pages = {a & ~(PAGE - 1) for lo, hi in fn.ranges for a in range(lo & ~(PAGE - 1), hi, PAGE)}
    starts = _starts()
    windows = set()
    for ins in insns:
        if ins.id == X.X86_INS_CALL:
            site = ins.address + ins.size
            op = ins.operands[0]
            callee = index.get(op.imm & 0xFFFFFFFF) if op.type == X.X86_OP_IMM else None
            if callee is not None:
                meta.calls[site] = (callee.pop_bytes, callee.fp_ret)
            else:
                nxt = by_addr.get(site)
                fp = bool(nxt and nxt.mnemonic.startswith("f") and nxt.mnemonic not in X87_NON_CONSUMERS)
                meta.calls[site] = (0, fp)
        kind = STUB_KINDS.get(ins.id)
        if kind is not None:
            meta.stubs[ins.address] = (ins.size, kind)
        for op in ins.operands:
            if op.type != X.X86_OP_MEM or op.mem.segment in (X.X86_REG_FS, X.X86_REG_GS):
                continue
            disp = op.mem.disp & 0xFFFFFFFF
            if (disp & ~(PAGE - 1)) not in pages or in_any_function(disp):
                continue
            nxt_start = starts[bisect.bisect_right(starts, disp)] if disp < starts[-1] else disp + WINDOW_MAX
            windows.add((disp, min(nxt_start, disp + WINDOW_MAX, (max(pages) + PAGE))))
    meta.windows = sorted(windows)
    return meta


def job_lines(meta: Meta, trials: list[tuple[int, int, int]]) -> list[str]:
    """trials: (seed, mode, budget). mode 0 = fast, 1 = step."""
    fn = meta.fn
    out = [f"F {fn.addr:x} {len(fn.ranges)} {len(meta.calls)} {len(meta.stubs)} {len(meta.windows)}"]
    out += [f"R {lo:x} {hi:x}" for lo, hi in fn.ranges]
    out += [f"C {site:x} {pop} {int(fp)}" for site, (pop, fp) in sorted(meta.calls.items())]
    out += [f"I {addr:x} {length} {kind}" for addr, (length, kind) in sorted(meta.stubs.items())]
    out += [f"W {lo:x} {hi:x}" for lo, hi in meta.windows]
    out += [f"T {seed:x} {mode} {budget}" for seed, mode, budget in trials]
    out.append("E")
    return out
