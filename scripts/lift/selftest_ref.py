"""Self-tests for the reference debugger (docs/lifted_tier.md, "Reference side").

    python scripts/lift/selftest_ref.py            synthetic tests, then the real image when present
    python scripts/lift/selftest_ref.py --no-real  synthetic tests only (no game image needed)
    python scripts/lift/selftest_ref.py --real-only [--functions N]

The synthetic stage builds a small flat image out of hand-encoded x86 snippets,
runs ref_dbg.exe on it and checks terminal records, trace facts and digests.
Expected digests come from an independent Python port of lift_model.h below, so
a passing run also pins how the debugger feeds the model.

The real stage takes a few thousand functions of the game image through
meta.py, runs them twice and checks that the run completes without harness
failures and that both runs agree line for line.
"""
from __future__ import annotations

import argparse
import collections
import random
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_ref  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "generated" / "lifted" / "ref" / "selftest"

M32 = 0xFFFFFFFF
PAGE = 4096
IMAGE_BASE = 0x10000000
ARENA_LO, ARENA_HI = 0x20000000, 0x60000000
STACK_TOP = 0x5FF00000
SENTINEL = 0xDEAD
EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI = range(8)
REG_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
T_LEAVE, T_FAULT, T_EXC, T_STEP = 1, 2, 3, 4
S_OK, S_TIMEOUT, S_HARNESS = 0, 1, 5
X_DIV, X_BKPT, X_ILL, X_PRIV, X_FP, X_TRAP, X_OTHER = 1, 2, 3, 4, 5, 6, 7
INSN_CPUID, INSN_RDTSC, INSN_TRAP = 1, 2, 3
PEEK_INVALID = 0xFFFFFFFF
FAST, STEP = 0, 1

# The TEB page ref_dbg presents to every trial: its address and its nonzero dwords.
MODEL_TEB = 0x7EFDD000
MODEL_TEB_FIELDS = {0x00: 0xFFFFFFFF, 0x04: ARENA_HI, 0x08: STACK_TOP - 0x100000, 0x18: MODEL_TEB,
                    0x20: 0x1000, 0x24: 0x1004, 0x2C: 0x5FD00000, 0x30: 0x5FC00000}
FOREIGN_ZONES = [(0x10000, 0x1000000), (0x7E000000, 0x80000000)]

# ---- Python port of lift_model.h ------------------------------------------------


def mix32(x: int) -> int:
    x &= M32
    x ^= x >> 16
    x = (x * 0x85EBCA6B) & M32
    x ^= x >> 13
    x = (x * 0xC2B2AE35) & M32
    x ^= x >> 16
    return x


def hash2(a: int, b: int) -> int:
    return mix32(((a * 0x9E3779B1) & M32) ^ mix32((b + 0x7F4A7C15) & M32))


def shape_ptr(h: int) -> int:
    return 0x20000000 + (((h >> 3) % (0x30000000 >> 4)) << 4)


FLOATS = (0x3F800000, 0x3F000000, 0x40000000, 0xBF800000, 0x42C80000, 0x3E800000, 0x40400000, 0x41200000)


def shape(h: int) -> int:
    k = h & 7
    if k <= 2:
        return shape_ptr(h)
    if k == 3:
        return 0
    if k == 4:
        return (h >> 3) & 0x3F
    if k == 5:
        return (h >> 3) & 3
    if k == 6:
        return FLOATS[(h >> 3) & 7]
    return mix32(h ^ 0xA5A5A5A5)


def fill_dword(seed: int, addr: int) -> int:
    return SENTINEL if addr == STACK_TOP else shape(hash2(seed, addr >> 2))


def fill_byte(seed: int, addr: int) -> int:
    return (fill_dword(seed, addr & ~3) >> (8 * (addr & 3))) & 0xFF


def init_gpr(seed: int) -> list[int]:
    r = [shape(hash2(seed ^ 0x52454753, i)) for i in range(8)]
    r[ECX] = shape_ptr(hash2(seed ^ 0x52454753, 0x100))
    r[ESP] = STACK_TOP
    return r


FX_ST, FX_XMM = 32, 160


def init_fx(seed: int) -> bytearray:
    fx = bytearray(512)
    struct.pack_into("<H", fx, 0, 0x027F)
    struct.pack_into("<I", fx, 24, 0x1F80)
    for i in range(32):
        struct.pack_into("<I", fx, FX_XMM + 4 * i, shape(hash2(seed ^ 0x584D4D30, i)))
    return fx


def stub_call_regs(seed: int, n: int) -> tuple[int, int, int]:
    return tuple(shape(hash2(seed ^ 0x43414C4C, 4 * n + k)) for k in range(3))


ST0_VALUES = tuple(bytes.fromhex(v) for v in (
    "0000000000000080ff3f", "0000000000000080fe3f", "00000000000000800040", "00000000000000000000",
    "0000000000000080ffbf", "00000000000000c80540", "0000000000000080fd3f", "00000000000000c00040"))
ST0_DOUBLES = (1.0, 0.5, 2.0, 0.0, -1.0, 100.0, 0.25, 3.0)


def stub_call_st0_index(seed: int, n: int) -> int:
    return hash2(seed ^ 0x43414C4C, 4 * n + 3) & 7


def stub_insn_regs(seed: int, n: int) -> list[int]:
    return [mix32(hash2(seed ^ 0x494E534E, 4 * n + k)) for k in range(4)]


class Digest:
    """lm_hash and the record functions built on it."""

    def __init__(self) -> None:
        self.h = 0xCBF29CE484222325

    def raw(self, data: bytes) -> None:
        h = self.h
        for b in data:
            h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        self.h = h

    def u32(self, v: int) -> None:
        self.raw(struct.pack("<I", v & M32))

    def fx(self, fx: bytes) -> None:
        self.raw(fx[0:2])
        self.raw(fx[2:4])
        self.raw(fx[4:5])
        for i in range(8):
            self.raw(fx[FX_ST + 16 * i:FX_ST + 16 * i + 10])
        self.raw(fx[24:28])
        self.raw(fx[FX_XMM:FX_XMM + 128])

    def state(self, r: list[int], df: int, fx: bytes) -> None:
        for v in r:
            self.u32(v)
        self.u32(df)
        self.fx(fx)

    def call(self, target: int, site: int, r: list[int], df: int, fx: bytes, stack: list[int]) -> None:
        self.u32(0x43)
        self.u32(target)
        self.u32(site)
        self.state(r, df, fx)
        for w in stack:
            self.u32(w)

    def insn(self, kind: int, eip: int) -> None:
        self.u32(0x49)
        self.u32(kind)
        self.u32(eip)

    def terminal(self, kind: int, a: int, b: int, r: list[int], df: int, fx: bytes) -> None:
        self.u32(0x54)
        self.u32(kind)
        self.u32(a)
        self.u32(b)
        self.state(r, df, fx)

    def mem(self, changed: dict[int, int]) -> None:
        self.u32(0x4D)
        for addr in sorted(changed):
            self.u32(addr)
            self.raw(bytes([changed[addr]]))
        self.u32(0x45)
        self.u32(len(changed))


def arena_diff(seed: int, addr: int, data: bytes) -> dict[int, int]:
    """Bytes of `data` written at an arena address that differ from the pristine fill."""
    return {addr + i: b for i, b in enumerate(data) if b != fill_byte(seed, addr + i)}


def u32le(v: int) -> bytes:
    return struct.pack("<I", v & M32)


# ---- synthetic image -------------------------------------------------------------


@dataclass
class Fn:
    name: str
    entry: int
    ranges: list[tuple[int, int]]
    calls: list[tuple[int, int, int]] = field(default_factory=list)    # (return address, pop bytes, fp_ret)
    stubs: list[tuple[int, int, int]] = field(default_factory=list)    # (address, length, kind)
    windows: list[tuple[int, int]] = field(default_factory=list)
    trials: list[tuple[int, int, int]] = field(default_factory=list)   # (seed, mode, budget)

    def job_lines(self) -> list[str]:
        out = [f"F {self.entry:x} {len(self.ranges)} {len(self.calls)} {len(self.stubs)} {len(self.windows)}"]
        out += [f"R {lo:x} {hi:x}" for lo, hi in self.ranges]
        out += [f"C {site:x} {pop} {fp}" for site, pop, fp in self.calls]
        out += [f"I {addr:x} {length} {kind}" for addr, length, kind in self.stubs]
        out += [f"W {lo:x} {hi:x}" for lo, hi in self.windows]
        out += [f"T {seed:x} {mode} {budget}" for seed, mode, budget in self.trials]
        out.append("E")
        return out


@dataclass
class Result:
    status: int
    tkind: int
    a: int
    b: int
    digest: int
    steps: int
    line: str


class Synthetic:
    """A flat image assembled from byte snippets, plus the functions defined on it."""

    SIZE = 0x10000
    OUTSIDE = IMAGE_BASE + 0xC000    # image page that never belongs to a body
    DATA = IMAGE_BASE + 0xA000       # image data page

    def __init__(self) -> None:
        self.image = bytearray(self.SIZE)
        self.next = IMAGE_BASE + 0x1000
        self.fns: list[Fn] = []

    def put(self, addr: int, data: bytes) -> None:
        self.image[addr - IMAGE_BASE:addr - IMAGE_BASE + len(data)] = data

    def place(self, size: int) -> int:
        """Next free code slot; slots are 0x40 apart so each body sits among filler."""
        addr = self.next
        self.next = (addr + size + 0x7F) & ~0x3F
        return addr

    def fn(self, name: str, code: bytes, *, at: int | None = None, **kw) -> Fn:
        entry = self.place(len(code)) if at is None else at
        self.put(entry, code)
        f = Fn(name=name, entry=entry, ranges=[(entry, entry + len(code))], **kw)
        self.fns.append(f)
        return f


def rel32(src_next: int, target: int) -> bytes:
    return struct.pack("<i", target - src_next)


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks = 0

    def eq(self, what: str, got, want) -> None:
        self.checks += 1
        if got != want:
            def show(v) -> str:
                text = f"{v:#x}" if isinstance(v, int) else repr(v)
                return text if len(text) <= 200 else text[:200] + "..."
            self.failures.append(f"{what}: got {show(got)}, expected {show(want)}")

    def ok(self, what: str, cond: bool) -> None:
        self.checks += 1
        if not cond:
            self.failures.append(what)


def run_ref(image: Path, jobs: Path, out: Path, env: Path, *extra: str, timeout: float = 3600.0):
    dbg, _ = build_ref.build()
    cmd = [str(dbg), "--image", str(image), "--jobs", str(jobs), "--out", str(out), "--env", str(env), *extra]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def read_results(path: Path) -> dict[tuple[int, int, int], Result]:
    out = {}
    for line in path.read_text().splitlines():
        entry, seed, mode, status, tkind, a, b, digest, steps = line.split()
        out[(int(entry, 16), int(seed, 16), int(mode))] = Result(
            int(status), int(tkind), int(a, 16), int(b, 16), int(digest, 16), int(steps), line)
    return out


def read_env(path: Path) -> dict:
    env = {"foreign": []}
    for line in path.read_text().splitlines():
        key, *rest = line.split()
        if key == "foreign":
            env["foreign"].append((int(rest[0], 16), int(rest[1], 16)))
        elif key == "teb":
            env["teb"] = bytes.fromhex(rest[0])
        else:
            env[key] = int(rest[0], 16)
    return env


def parse_trace(text: str) -> dict:
    """Trace of one trial: lists of call/insn/page/step/mem lines and the term/fx/end fields."""
    t = {"call": [], "insn": [], "page": [], "step": [], "mem": {}, "term": None, "end": None, "st": {}, "xmm": {}}
    for line in text.splitlines():
        if not line.strip():
            continue
        head, *rest = line.split()
        fields = dict(p.split("=", 1) for p in rest if "=" in p)
        if head in ("call", "insn", "step"):
            fields["n"] = rest[0]
            t[head].append(fields)
        elif head == "page":
            t["page"].append(int(rest[0], 16))
        elif head == "mem":
            t["mem"][int(rest[0], 16)] = int(rest[1], 16)
        elif head in ("term", "end", "fx", "trial"):
            t[head] = fields if fields else rest
        elif head.startswith("st") and head[2:].isdigit():
            t["st"][int(head[2:])] = bytes.fromhex(rest[0])
        elif head.startswith("xmm"):
            t["xmm"][int(head[3:])] = bytes.fromhex(rest[0])
    return t


# ---- synthetic stage ---------------------------------------------------------------

SEEDS = (0x1, 0x2, 0x5EED1234)


def expected_leave(seed: int, *, target: int = SENTINEL, regs: dict[int, int] | None = None, esp: int = STACK_TOP + 4,
                   df: int = 0, fx: bytes | None = None, mem: dict[int, int] | None = None, pre=None) -> int:
    """Digest of a trial that ends by leaving the body."""
    d = pre or Digest()
    r = init_gpr(seed)
    r[ESP] = esp
    for k, v in (regs or {}).items():
        r[k] = v
    d.terminal(T_LEAVE, target, 0, r, df, fx if fx is not None else init_fx(seed))
    d.mem(mem or {})
    return d.h


def expected_stop(seed: int, kind: int, a: int, b: int, *, regs: dict[int, int] | None = None, esp: int = STACK_TOP,
                  mem: dict[int, int] | None = None) -> int:
    d = Digest()
    r = init_gpr(seed)
    r[ESP] = esp
    for k, v in (regs or {}).items():
        r[k] = v
    d.terminal(kind, a, b, r, 0, init_fx(seed))
    d.mem(mem or {})
    return d.h


def build_synthetic():
    """Returns (Synthetic, checks) where checks is a list of callables(results, traces, env, checker)."""
    syn = Synthetic()
    checks = []
    traced: list[tuple[int, int, int]] = []
    both = [(s, FAST, 0) for s in SEEDS] + [(s, STEP, 1000) for s in SEEDS]
    OUT = Synthetic.OUTSIDE

    def each(f: Fn, modes=(FAST, STEP)):
        return [(seed, mode) for seed, mode, _ in f.trials if mode in modes]

    def expect(f: Fn, fn_digest, *, tkind=T_LEAVE, a=SENTINEL, b=0, steps=None, modes=(FAST, STEP)):
        """Check every trial of f against a digest function of the seed."""
        def check(res, traces, env, c):
            for seed, mode in each(f, modes):
                r = res[(f.entry, seed, mode)]
                tag = f"{f.name} seed={seed:x} mode={mode}"
                c.eq(f"{tag} status", r.status, S_OK)
                c.eq(f"{tag} tkind", r.tkind, tkind)
                c.eq(f"{tag} a", r.a, a(seed) if callable(a) else a)
                c.eq(f"{tag} b", r.b, b(seed) if callable(b) else b)
                c.eq(f"{tag} digest", r.digest, fn_digest(seed))
                if steps is not None:
                    c.eq(f"{tag} steps", r.steps, steps if mode == STEP else 0)
        checks.append(check)

    # ret
    f_ret = syn.fn("ret", b"\xc3", trials=both)
    expect(f_ret, lambda s: expected_leave(s), steps=1)
    traced.append((f_ret.entry, SEEDS[0], FAST))

    def check_ret_trace(res, traces, env, c):
        t = traces[(f_ret.entry, SEEDS[0], FAST)]
        r = init_gpr(SEEDS[0])
        c.eq("ret trace term kind", t["term"]["kind"], "1")
        c.eq("ret trace esp", int(t["term"]["esp"], 16), STACK_TOP + 4)
        for i, name in enumerate(REG_NAMES):
            if i != ESP:
                c.eq(f"ret trace {name}", int(t["term"][name], 16), r[i])
        c.eq("ret trace pages", t["page"], [STACK_TOP])
        c.eq("ret trace mem", t["mem"], {})
        c.eq("ret trace fcw", t["fx"]["fcw"], "027f")
        c.eq("ret trace mxcsr", t["fx"]["mxcsr"], "00001f80")
        c.eq("ret trace xmm5", t["xmm"][5], bytes(init_fx(SEEDS[0])[FX_XMM + 80:FX_XMM + 96]))
        c.eq("ret trace digest", int(t["end"]["digest"], 16), res[(f_ret.entry, SEEDS[0], FAST)].digest)
    checks.append(check_ret_trace)

    # mov eax, imm32; ret
    f = syn.fn("mov_eax_ret", b"\xb8\x78\x56\x34\x12\xc3", trials=both)
    expect(f, lambda s: expected_leave(s, regs={EAX: 0x12345678}), steps=2)

    # ret 8
    f = syn.fn("ret8", b"\xc2\x08\x00", trials=both)
    expect(f, lambda s: expected_leave(s, esp=STACK_TOP + 12), steps=1)

    # mov dword [ecx], 0xaabbccdd; ret
    f_store = syn.fn("store", b"\xc7\x01\xdd\xcc\xbb\xaa\xc3", trials=both)
    expect(f_store, lambda s: expected_leave(s, mem=arena_diff(s, init_gpr(s)[ECX], u32le(0xAABBCCDD))), steps=2)
    traced.append((f_store.entry, SEEDS[1], FAST))

    def check_store_trace(res, traces, env, c):
        s = SEEDS[1]
        t = traces[(f_store.entry, s, FAST)]
        c.eq("store trace mem", t["mem"], arena_diff(s, init_gpr(s)[ECX], u32le(0xAABBCCDD)))
        c.ok("store trace mem non-empty", len(t["mem"]) > 0)
    checks.append(check_store_trace)

    # mov eax, [ecx]; ret  (lazy arena fill as the guest reads it)
    f = syn.fn("load", b"\x8b\x01\xc3", trials=both)
    expect(f, lambda s: expected_leave(s, regs={EAX: fill_dword(s, init_gpr(s)[ECX])}), steps=2)

    # reads and writes of invalid addresses
    f1 = syn.fn("read_null", b"\xa1\x40\x00\x00\x00\xc3", trials=both)
    expect(f1, lambda s: expected_stop(s, T_FAULT, f1.entry, 0x40), tkind=T_FAULT, a=f1.entry, b=0x40, steps=0)
    f2 = syn.fn("read_high", b"\xa1\x00\x00\x00\x90\xc3", trials=both)
    expect(f2, lambda s: expected_stop(s, T_FAULT, f2.entry, 0x90000000), tkind=T_FAULT, a=f2.entry, b=0x90000000)
    f3 = syn.fn("write_null", b"\xa3\x44\x00\x00\x00\xc3", trials=both)
    expect(f3, lambda s: expected_stop(s, T_FAULT, f3.entry, 0x44), tkind=T_FAULT, a=f3.entry, b=0x44)
    # dword that starts on the last arena page and ends past it
    f4 = syn.fn("read_straddle", b"\xa1\xfe\xff\xff\x5f\xc3", trials=both)
    expect(f4, lambda s: expected_stop(s, T_FAULT, f4.entry, ARENA_HI), tkind=T_FAULT, a=f4.entry, b=ARENA_HI)
    # nop; mov eax, [0x40]: the fault reports the instruction, not the function entry
    f5 = syn.fn("read_null_later", b"\x90\xa1\x40\x00\x00\x00\xc3", trials=both)
    expect(f5, lambda s: expected_stop(s, T_FAULT, f5.entry + 1, 0x40), tkind=T_FAULT, a=f5.entry + 1, b=0x40,
           steps=1)
    # movaps xmm0, [ecx+1]: alignment #GP
    f6 = syn.fn("movaps_unaligned", b"\x0f\x28\x41\x01\xc3", trials=both)
    expect(f6, lambda s: expected_stop(s, T_FAULT, f6.entry, 0xFFFFFFFF), tkind=T_FAULT, a=f6.entry, b=0xFFFFFFFF)

    # push imm; call OUT; ret   (callee pops 4)
    e = syn.place(11)
    code = b"\x68\x44\x33\x22\x11" + b"\xe8" + rel32(e + 10, OUT) + b"\xc3"
    f_call = syn.fn("call_out", code, at=e, calls=[(e + 10, 4, 0)], trials=both)

    def call_digest(s: int) -> int:
        d = Digest()
        r = init_gpr(s)
        r[ESP] = STACK_TOP - 8
        stack = [0x11223344, SENTINEL] + [fill_dword(s, STACK_TOP + 4 + 4 * k) for k in range(6)]
        d.call(OUT, f_call.entry + 10, r, 0, init_fx(s), stack)
        eax, ecx, edx = stub_call_regs(s, 0)
        mem = arena_diff(s, STACK_TOP - 4, u32le(0x11223344))
        mem.update(arena_diff(s, STACK_TOP - 8, u32le(f_call.entry + 10)))
        return expected_leave(s, regs={EAX: eax, ECX: ecx, EDX: edx}, mem=mem, pre=d)
    expect(f_call, call_digest, steps=3)
    traced.append((f_call.entry, SEEDS[0], FAST))
    traced.append((f_call.entry, SEEDS[0], STEP))

    def check_call_trace(res, traces, env, c):
        s = SEEDS[0]
        for mode in (FAST, STEP):
            t = traces[(f_call.entry, s, mode)]
            c.eq(f"call trace events mode={mode}", len(t["call"]), 1)
            ev = t["call"][0]
            c.eq("call trace n", ev["n"], "0")
            c.eq("call trace target", int(ev["target"], 16), OUT)
            c.eq("call trace site", int(ev["site"], 16), f_call.entry + 10)
            c.eq("call trace esp", int(ev["esp"], 16), STACK_TOP - 8)
            c.eq("call trace ecx", int(ev["ecx"], 16), init_gpr(s)[ECX])
            words = [int(w, 16) for w in ev["stack"].split(",")]
            c.eq("call trace stack[0]", words[0], 0x11223344)
            c.eq("call trace stack[1]", words[1], SENTINEL)
            c.eq("call trace stack[2]", words[2], fill_dword(s, STACK_TOP + 4))
            eax, ecx, edx = stub_call_regs(s, 0)
            c.eq("call trace stub eax", int(t["term"]["eax"], 16), eax)
            c.eq("call trace stub ecx", int(t["term"]["ecx"], 16), ecx)
            c.eq("call trace stub edx", int(t["term"]["edx"], 16), edx)
            c.eq("call trace final esp (pop_bytes honoured)", int(t["term"]["esp"], 16), STACK_TOP + 4)
            c.eq("call trace pages", sorted(t["page"]), [STACK_TOP - PAGE, STACK_TOP])
        c.eq("call trace steps", [x["n"] for x in traces[(f_call.entry, s, STEP)]["step"]], ["0", "1", "2"])
    checks.append(check_call_trace)

    # call to filler on the body's own page (breakpoint path instead of an execute fault)
    e = syn.place(6)
    f_near = syn.fn("call_filler", b"\xe8" + rel32(e + 5, e + 0x20) + b"\xc3", at=e, calls=[(e + 5, 0, 0)],
                    trials=both)

    def near_digest(s: int) -> int:
        d = Digest()
        r = init_gpr(s)
        r[ESP] = STACK_TOP - 4
        stack = [SENTINEL] + [fill_dword(s, STACK_TOP + 4 + 4 * k) for k in range(7)]
        d.call(f_near.entry + 0x20, f_near.entry + 5, r, 0, init_fx(s), stack)
        eax, ecx, edx = stub_call_regs(s, 0)
        return expected_leave(s, regs={EAX: eax, ECX: ecx, EDX: edx},
                              mem=arena_diff(s, STACK_TOP - 4, u32le(f_near.entry + 5)), pre=d)
    expect(f_near, near_digest, steps=2)

    # mov esi, ecx; call OUT; fstp qword [esi]; ret   (callee returns on the x87 stack)
    e = syn.place(10)
    code = b"\x89\xce" + b"\xe8" + rel32(e + 7, OUT) + b"\xdd\x1e\xc3"
    f_fp = syn.fn("call_fp_ret", code, at=e, calls=[(e + 7, 0, 1)], trials=both)

    def fp_digest(s: int) -> int:
        d = Digest()
        r = init_gpr(s)
        ptr = r[ECX]
        r[ESP] = STACK_TOP - 4
        r[ESI] = ptr
        stack = [SENTINEL] + [fill_dword(s, STACK_TOP + 4 + 4 * k) for k in range(7)]
        d.call(OUT, f_fp.entry + 7, r, 0, init_fx(s), stack)
        eax, ecx, edx = stub_call_regs(s, 0)
        k = stub_call_st0_index(s, 0)
        fx = init_fx(s)
        fx[FX_ST + 16 * 7:FX_ST + 16 * 7 + 10] = ST0_VALUES[k]   # pushed, stored and popped: left in the freed register
        mem = arena_diff(s, ptr, struct.pack("<d", ST0_DOUBLES[k]))
        mem.update(arena_diff(s, STACK_TOP - 4, u32le(f_fp.entry + 7)))
        return expected_leave(s, regs={EAX: eax, ECX: ecx, EDX: edx, ESI: ptr}, fx=fx, mem=mem, pre=d)
    expect(f_fp, fp_digest, steps=4)

    # call eax; ret   (indirect call, target is whatever the seed put in eax)
    f_ind = syn.fn("call_eax", b"\xff\xd0\xc3", trials=both)
    f_ind.calls = [(f_ind.entry + 2, 0, 0)]

    def ind_digest(s: int) -> int:
        d = Digest()
        r = init_gpr(s)
        r[ESP] = STACK_TOP - 4
        stack = [SENTINEL] + [fill_dword(s, STACK_TOP + 4 + 4 * k) for k in range(7)]
        d.call(init_gpr(s)[EAX], f_ind.entry + 2, r, 0, init_fx(s), stack)
        eax, ecx, edx = stub_call_regs(s, 0)
        return expected_leave(s, regs={EAX: eax, ECX: ecx, EDX: edx},
                              mem=arena_diff(s, STACK_TOP - 4, u32le(f_ind.entry + 2)), pre=d)
    expect(f_ind, ind_digest, steps=2)

    # jmp OUT   (tail jump: [esp] is the sentinel, not a call site)
    e = syn.place(5)
    f = syn.fn("tail_jmp", b"\xe9" + rel32(e + 5, OUT), at=e, trials=both)
    expect(f, lambda s: expected_leave(s, target=OUT, esp=STACK_TOP), a=OUT, steps=1)
    # jmp eax
    f = syn.fn("jmp_eax", b"\xff\xe0", trials=both)
    expect(f, lambda s: expected_leave(s, target=init_gpr(s)[EAX], esp=STACK_TOP), a=lambda s: init_gpr(s)[EAX],
           steps=1)
    # nop, then control runs off the end of the body into filler
    f_fall = syn.fn("fall_off", b"\x90", trials=both)
    expect(f_fall, lambda s: expected_leave(s, target=f_fall.entry + 1, esp=STACK_TOP), a=f_fall.entry + 1, steps=1)

    # recursion inside the body: mov eax,3; L: dec eax; jz done; call L; done: ret
    e = syn.place(14)
    f_rec = syn.fn("recursion", b"\xb8\x03\x00\x00\x00\x48\x74\x05\xe8\xf8\xff\xff\xff\xc3", at=e,
                   calls=[(e + 13, 0, 0)], trials=both)

    def rec_digest(s: int) -> int:
        mem = arena_diff(s, STACK_TOP - 4, u32le(f_rec.entry + 13))
        mem.update(arena_diff(s, STACK_TOP - 8, u32le(f_rec.entry + 13)))
        return expected_leave(s, regs={EAX: 0}, mem=mem)
    expect(f_rec, rec_digest, steps=12)

    # xor ecx, ecx; div ecx
    f_div = syn.fn("div_zero", b"\x31\xc9\xf7\xf1\xc3", trials=both)
    expect(f_div, lambda s: expected_stop(s, T_EXC, f_div.entry + 2, X_DIV, regs={ECX: 0}), tkind=T_EXC,
           a=f_div.entry + 2, b=X_DIV, steps=1)
    # nop; int3; ret
    f_bp = syn.fn("int3", b"\x90\xcc\xc3", trials=both)
    expect(f_bp, lambda s: expected_stop(s, T_EXC, f_bp.entry + 1, X_BKPT), tkind=T_EXC, a=f_bp.entry + 1, b=X_BKPT,
           steps=1)
    # hlt, ud2
    f_hlt = syn.fn("hlt", b"\xf4\xc3", trials=both)
    expect(f_hlt, lambda s: expected_stop(s, T_EXC, f_hlt.entry, X_PRIV), tkind=T_EXC, a=f_hlt.entry, b=X_PRIV)
    f_ud = syn.fn("ud2", b"\x0f\x0b\xc3", trials=both)
    expect(f_ud, lambda s: expected_stop(s, T_EXC, f_ud.entry, X_ILL), tkind=T_EXC, a=f_ud.entry, b=X_ILL)

    # cpuid; ret   /   rdtsc; ret   /   int 0x2e
    f_cpuid = syn.fn("cpuid", b"\x0f\xa2\xc3", trials=both)
    f_cpuid.stubs = [(f_cpuid.entry, 2, INSN_CPUID)]

    def cpuid_digest(s: int) -> int:
        d = Digest()
        d.insn(INSN_CPUID, f_cpuid.entry)
        v = stub_insn_regs(s, 0)
        return expected_leave(s, regs={EAX: v[0], EBX: v[1], ECX: v[2], EDX: v[3]}, pre=d)
    expect(f_cpuid, cpuid_digest, steps=2)
    traced.append((f_cpuid.entry, SEEDS[0], FAST))

    def check_cpuid_trace(res, traces, env, c):
        t = traces[(f_cpuid.entry, SEEDS[0], FAST)]
        v = stub_insn_regs(SEEDS[0], 0)
        c.eq("cpuid trace events", [(x["n"], x["kind"], int(x["addr"], 16)) for x in t["insn"]],
             [("0", "1", f_cpuid.entry)])
        c.eq("cpuid trace ebx", int(t["term"]["ebx"], 16), v[1])
    checks.append(check_cpuid_trace)

    f_tsc = syn.fn("rdtsc", b"\x0f\x31\x0f\x31\xc3", trials=both)
    f_tsc.stubs = [(f_tsc.entry, 2, INSN_RDTSC), (f_tsc.entry + 2, 2, INSN_RDTSC)]

    def tsc_digest(s: int) -> int:
        d = Digest()
        d.insn(INSN_RDTSC, f_tsc.entry)
        d.insn(INSN_RDTSC, f_tsc.entry + 2)
        v = stub_insn_regs(s, 1)
        return expected_leave(s, regs={EAX: v[0], EDX: v[3]}, pre=d)
    expect(f_tsc, tsc_digest, steps=3)

    f_int = syn.fn("int2e", b"\x90\xcd\x2e\xc3", trials=both)
    f_int.stubs = [(f_int.entry + 1, 2, INSN_TRAP)]
    expect(f_int, lambda s: expected_stop(s, T_EXC, f_int.entry + 1, X_TRAP), tkind=T_EXC, a=f_int.entry + 1,
           b=X_TRAP, steps=1)

    # jmp $   (fast: wall-clock limit; step: budget)
    f_loop = syn.fn("loop", b"\xeb\xfe", trials=[(SEEDS[0], FAST, 0), (SEEDS[0], STEP, 100), (SEEDS[1], STEP, 7)])

    def check_loop(res, traces, env, c):
        r = res[(f_loop.entry, SEEDS[0], FAST)]
        c.eq("loop fast status", r.status, S_TIMEOUT)
        c.eq("loop fast line", r.line.split()[3:], ["1", "0", "0", "0", "0" * 16, "0"])
        r = res[(f_loop.entry, SEEDS[0], STEP)]
        c.eq("loop step", (r.status, r.tkind, r.a, r.b, r.steps), (S_OK, T_STEP, f_loop.entry, 0, 100))
        c.eq("loop step digest", r.digest, expected_stop(SEEDS[0], T_STEP, f_loop.entry, 0))
        r = res[(f_loop.entry, SEEDS[1], STEP)]
        c.eq("loop step 7", (r.tkind, r.a, r.steps), (T_STEP, f_loop.entry, 7))
    checks.append(check_loop)

    # mov eax,1; add eax,2; ret  with a budget that ends on the ret
    f_bud = syn.fn("budget", b"\xb8\x01\x00\x00\x00\x83\xc0\x02\xc3",
                   trials=[(SEEDS[0], STEP, 2), (SEEDS[0], STEP, 3), (SEEDS[0], STEP, 1)])

    def check_budget(res, traces, env, c):
        # three trials share (entry, seed, mode); the result file keeps them in job order
        lines = [ln.split() for ln in res["lines"] if ln.split()[0] == f"{f_bud.entry:x}"]
        c.eq("budget 2", lines[0][4:7] + lines[0][8:], ["4", f"{f_bud.entry + 8:x}", "0", "2"])
        c.eq("budget 2 digest", int(lines[0][7], 16),
             expected_stop(SEEDS[0], T_STEP, f_bud.entry + 8, 0, regs={EAX: 3}))
        c.eq("budget 3 (the ret leaves first)", lines[1][4:7] + lines[1][8:], ["1", "dead", "0", "3"])
        c.eq("budget 1", lines[2][4:7] + lines[2][8:], ["4", f"{f_bud.entry + 5:x}", "0", "1"])
    checks.append(check_budget)

    # fld1; fstp qword [ecx]; ret
    f = syn.fn("fld1_fstp", b"\xd9\xe8\xdd\x19\xc3", trials=both)

    def fld_digest(s: int) -> int:
        fx = init_fx(s)
        fx[FX_ST + 16 * 7:FX_ST + 16 * 7 + 10] = ST0_VALUES[0]
        return expected_leave(s, fx=fx, mem=arena_diff(s, init_gpr(s)[ECX], struct.pack("<d", 1.0)))
    expect(f, fld_digest, steps=3)
    # fld1; ret   (value left on the x87 stack: top = 7, tag bit 7)
    f = syn.fn("fld1_ret", b"\xd9\xe8\xc3", trials=both)

    def fld_ret_digest(s: int) -> int:
        fx = init_fx(s)
        fx[FX_ST:FX_ST + 10] = ST0_VALUES[0]
        struct.pack_into("<H", fx, 2, 0x3800)
        fx[4] = 0x80
        return expected_leave(s, fx=fx)
    expect(f, fld_ret_digest, steps=2)

    # movups [ecx], xmm3; ret   /   fnstcw [ecx]; ret   /   stmxcsr [ecx]; ret
    f = syn.fn("movups_store", b"\x0f\x11\x19\xc3", trials=both)
    expect(f, lambda s: expected_leave(
        s, mem=arena_diff(s, init_gpr(s)[ECX], bytes(init_fx(s)[FX_XMM + 48:FX_XMM + 64]))), steps=2)
    f = syn.fn("fnstcw", b"\xd9\x39\xc3", trials=both)
    expect(f, lambda s: expected_leave(s, mem=arena_diff(s, init_gpr(s)[ECX], b"\x7f\x02")), steps=2)
    f = syn.fn("stmxcsr", b"\x0f\xae\x19\xc3", trials=both)
    expect(f, lambda s: expected_leave(s, mem=arena_diff(s, init_gpr(s)[ECX], u32le(0x1F80))), steps=2)
    # movups xmm6, [ecx]; ret   (XMM register in the terminal state)
    f = syn.fn("movups_load", b"\x0f\x10\x31\xc3", trials=both)

    def movups_load_digest(s: int) -> int:
        fx = init_fx(s)
        ptr = init_gpr(s)[ECX]
        fx[FX_XMM + 96:FX_XMM + 112] = b"".join(u32le(fill_dword(s, ptr + 4 * k)) for k in range(4))
        return expected_leave(s, fx=fx)
    expect(f, movups_load_digest, steps=2)

    # std; ret   (direction flag is part of the state)
    f = syn.fn("std", b"\xfd\xc3", trials=both)
    expect(f, lambda s: expected_leave(s, df=1), steps=2)

    # FS: mov eax, fs:[0]; ret   /   the self pointer   /   through the self pointer by flat address
    #     /   through the thread-local storage pointer   /   write, then read back in a later trial
    f_fs0 = syn.fn("fs0", b"\x64\xa1\x00\x00\x00\x00\xc3", trials=both)
    f_fs18 = syn.fn("fs_self", b"\x64\xa1\x18\x00\x00\x00\xc3", trials=both)
    f_fsflat = syn.fn("fs_self_flat", b"\x64\xa1\x18\x00\x00\x00\x8b\x40\x30\xc3", trials=both)
    f_fstls = syn.fn("fs_tls", b"\x64\xa1\x2c\x00\x00\x00\x8b\x00\xc3", trials=both)
    f_fsw = syn.fn("fs_write", b"\x64\x89\x0d\x14\x00\x00\x00\xc3", trials=both)
    f_fsr = syn.fn("fs_read_after_write", b"\x64\xa1\x14\x00\x00\x00\xc3", trials=both)
    f_fsend = syn.fn("fs_last_dword", b"\x64\xa1\xfc\x0f\x00\x00\xc3", trials=both)
    f_fspast = syn.fn("fs_past_page", b"\x64\xa1\x00\x10\x00\x00\xc3", trials=both)
    traced.append((f_fs0.entry, SEEDS[0], FAST))

    def check_fs(res, traces, env, c):
        teb = env["teb"]
        word = lambda off: struct.unpack_from("<I", teb, off)[0]
        want = bytearray(PAGE)
        for off, value in MODEL_TEB_FIELDS.items():
            want[off:off + 4] = u32le(value)
        c.eq("env fs_base", env["fs_base"], MODEL_TEB)
        c.eq("env teb", teb, bytes(want))
        c.eq("fs0 trace eax", int(traces[(f_fs0.entry, SEEDS[0], FAST)]["term"]["eax"], 16), word(0))
        for seed, mode in each(f_fs0):
            tag = f"seed={seed:x} mode={mode}"
            c.eq(f"fs0 {tag}", res[(f_fs0.entry, seed, mode)].digest, expected_leave(seed, regs={EAX: word(0)}))
            c.eq(f"fs_self {tag}", res[(f_fs18.entry, seed, mode)].digest,
                 expected_leave(seed, regs={EAX: env["fs_base"]}))
            # The TEB is only reachable through FS on the reference side; the trial is given up.
            c.eq(f"fs_self_flat {tag}", res[(f_fsflat.entry, seed, mode)].status, S_HARNESS)
            c.eq(f"fs_tls {tag}", res[(f_fstls.entry, seed, mode)].digest,
                 expected_leave(seed, regs={EAX: fill_dword(seed, word(0x2C))}))
            ecx = init_gpr(seed)[ECX]
            mem = {env["fs_base"] + 0x14 + i: b for i, b in enumerate(u32le(ecx)) if b != teb[0x14 + i]}
            c.eq(f"fs_write {tag}", res[(f_fsw.entry, seed, mode)].digest, expected_leave(seed, mem=mem))
            c.eq(f"fs_read_after_write {tag} (TEB restored)", res[(f_fsr.entry, seed, mode)].digest,
                 expected_leave(seed, regs={EAX: word(0x14)}))
            c.eq(f"fs_last_dword {tag}", res[(f_fsend.entry, seed, mode)].digest,
                 expected_leave(seed, regs={EAX: word(0xFFC)}))
            # Past the modelled page the child has whatever follows its real TEB. The lifted runner
            # excludes such a trial as foreign; here it only has to end without a harness failure.
            past = res[(f_fspast.entry, seed, mode)]
            c.ok(f"fs_past_page {tag}", past.status == S_OK and past.tkind in (T_LEAVE, T_FAULT))
    checks.append(check_fs)

    # data window: a table next to the body, read and jumped through
    e = syn.place(0x60)
    table = e + 0x40
    syn.put(table, u32le(0xCAFEF00D) + u32le(e + 9))
    f_win = syn.fn("window_read", b"\xa1" + u32le(table) + b"\xc3", at=e, windows=[(table, table + 8)], trials=both)
    expect(f_win, lambda s: expected_leave(s, regs={EAX: 0xCAFEF00D}), steps=2)
    # xor eax,eax; jmp [eax*4 + table+4] -> e2+9: ret
    e2 = syn.place(0x60)
    table2 = e2 + 0x40
    syn.put(table2, u32le(e2 + 9))
    f_jt = syn.fn("jump_table", b"\x31\xc0\xff\x24\x85" + u32le(table2) + b"\xc3", at=e2,
                  windows=[(table2, table2 + 4)], trials=both)
    expect(f_jt, lambda s: expected_leave(s, regs={EAX: 0}), steps=3)
    # the same read without a window: fast mode sees filler, step mode the image
    e3 = syn.place(0x60)
    table3 = e3 + 0x40
    syn.put(table3, u32le(0xCAFEF00D))
    f_now = syn.fn("no_window_read", b"\xa1" + u32le(table3) + b"\xc3", at=e3, trials=both)
    expect(f_now, lambda s: expected_leave(s, regs={EAX: 0xCCCCCCCC}), modes=(FAST,))
    expect(f_now, lambda s: expected_leave(s, regs={EAX: 0xCAFEF00D}), modes=(STEP,))
    # image data on another page: read, and a write that the next trial must not see
    syn.put(Synthetic.DATA, u32le(0x0BADF00D))
    f_img = syn.fn("image_rw", b"\xa1" + u32le(Synthetic.DATA) + b"\x89\x0d" + u32le(Synthetic.DATA) + b"\xc3",
                   trials=both)
    expect(f_img, lambda s: expected_leave(s, regs={EAX: 0x0BADF00D}, mem={
        Synthetic.DATA + i: b for i, b in enumerate(u32le(init_gpr(s)[ECX])) if b != u32le(0x0BADF00D)[i]}), steps=3)
    # write into filler on the body's own page: reported, and repaired for the next trial
    e4 = syn.place(0x40)
    f_self = syn.fn("write_own_page", b"\xc6\x05" + u32le(e4 + 0x20) + b"\x55\xc3", at=e4, trials=both)
    expect(f_self, lambda s: expected_leave(s, mem={f_self.entry + 0x20: 0x55}), steps=2)

    # mov edi,ecx; mov ecx,0x2800; rep stosb; ret   (several lazy pages, diff in address order)
    f_stos = syn.fn("rep_stosb", b"\x89\xcf\xb9\x00\x28\x00\x00\xf3\xaa\xc3",
                    trials=[(s, FAST, 0) for s in SEEDS] + [(SEEDS[0], STEP, 20000)])

    def stos_digest(s: int) -> int:
        r = init_gpr(s)
        ptr = r[ECX]
        return expected_leave(s, regs={ECX: 0, EDI: (ptr + 0x2800) & M32},
                              mem=arena_diff(s, ptr, bytes([r[EAX] & 0xFF]) * 0x2800))
    expect(f_stos, stos_digest)

    def check_stos_steps(res, traces, env, c):
        c.eq("rep stosb steps", res[(f_stos.entry, SEEDS[0], STEP)].steps, 2 + 0x2800 + 1)
    checks.append(check_stos_steps)

    # rep movsd with ecx = 3 and ecx = 0 under single stepping
    f_rep3 = syn.fn("rep_movsd_3", b"\x89\xce\x8d\xb9\x00\x01\x00\x00\xb9\x03\x00\x00\x00\xf3\xa5\xc3", trials=both)

    def rep3_digest(s: int) -> int:
        ptr = init_gpr(s)[ECX]
        data = b"".join(u32le(fill_dword(s, ptr + 4 * k)) for k in range(3))
        return expected_leave(s, regs={ECX: 0, ESI: ptr + 12, EDI: ptr + 0x10C},
                              mem=arena_diff(s, ptr + 0x100, data))
    expect(f_rep3, rep3_digest, steps=3 + 3 + 1)
    f_rep0 = syn.fn("rep_movsd_0", b"\x31\xc9\xf3\xa5\xc3", trials=both)
    expect(f_rep0, lambda s: expected_leave(s, regs={ECX: 0}), steps=3)

    # pushfd; pop eax; ret   (the harness's trap flag must not leak into the image PUSHFD stores)
    f_pushf = syn.fn("pushfd", b"\x9c\x58\xc3", trials=both)

    expect(f_pushf, lambda s: expected_leave(s, regs={EAX: 0x202}, mem=arena_diff(s, STACK_TOP - 4, u32le(0x202))),
           steps=3)
    # push 0x202; popfd; nop; ret
    f = syn.fn("popfd", b"\x68\x02\x02\x00\x00\x9d\x90\xc3", trials=both)
    expect(f, lambda s: expected_leave(s, mem=arena_diff(s, STACK_TOP - 4, u32le(0x202))), steps=4)
    # pushfd; or dword [esp],0x100; popfd; nop; nop; ret   (guest sets TF itself)
    f_tf = syn.fn("guest_tf", b"\x9c\x81\x0c\x24\x00\x01\x00\x00\x9d\x90\x90\xc3",
                  trials=[(s, FAST, 0) for s in SEEDS])

    expect(f_tf, lambda s: expected_leave(s, mem=arena_diff(s, STACK_TOP - 4, u32le(0x302))), modes=(FAST,))

    # a function with an unusable description is reported as a harness failure, and the run goes on
    f_bad = Fn(name="bad_range", entry=IMAGE_BASE + 0x200000, ranges=[(IMAGE_BASE + 0x200000, IMAGE_BASE + 0x200001)],
               trials=[(SEEDS[0], FAST, 0)])
    syn.fns.append(f_bad)
    f_after = syn.fn("after_bad", b"\xc3", trials=[(SEEDS[0], FAST, 0)])

    def check_bad(res, traces, env, c):
        c.eq("bad range status", res[(f_bad.entry, SEEDS[0], FAST)].status, S_HARNESS)
        c.eq("trial after bad range", res[(f_after.entry, SEEDS[0], FAST)].digest, expected_leave(SEEDS[0]))
    checks.append(check_bad)

    def check_env(res, traces, env, c):
        c.eq("env image_size", env["image_size"], Synthetic.SIZE)
        # The whole high zone, and before it what the child kept accessible in the low zone.
        low, low_zone = env["foreign"][:-1], FOREIGN_ZONES[0]
        c.eq("env foreign: high zone", env["foreign"][-1:], FOREIGN_ZONES[1:])
        c.ok("env foreign: the child keeps something in the low zone (at least its TEB)", len(low) > 0)
        c.ok("env foreign: low ranges are page ranges inside the low zone",
             all(low_zone[0] <= lo < hi <= low_zone[1] and lo % PAGE == 0 and hi % PAGE == 0 for lo, hi in low))
        c.ok("env foreign: low ranges are ascending and disjoint",
             all(a[1] < b[0] for a, b in zip(low, low[1:])))
    checks.append(check_env)

    return syn, checks, traced


def synthetic_stage() -> bool:
    WORK.mkdir(parents=True, exist_ok=True)
    syn, checks, traced = build_synthetic()
    image, jobs = WORK / "synthetic.bin", WORK / "synthetic.job"
    image.write_bytes(syn.image)
    # Every function appears twice, so one process runs each trial twice in the same environment.
    job_lines = [line for f in syn.fns for line in f.job_lines()]
    jobs.write_text("\n".join(job_lines + job_lines) + "\n", newline="\n")
    c = Checker()

    runs = []
    for i in (1, 2):
        out, env = WORK / f"synthetic{i}.out", WORK / f"synthetic{i}.env"
        done = run_ref(image, jobs, out, env)
        if done.returncode != 0:
            print(done.stdout + done.stderr)
            print(f"FAIL: ref_dbg exited with {done.returncode}")
            return False
        runs.append((out, env, done.stderr.strip()))
    n_trials = sum(len(f.trials) for f in syn.fns)
    passes = []
    for out, _env, _summary in runs:
        lines = out.read_text().splitlines()
        c.eq("one result line per trial", len(lines), 2 * n_trials)
        c.eq("determinism: a trial repeated in the same process", lines[:n_trials], lines[n_trials:])
        passes.append(lines[:n_trials])
    # A second process has a child of its own, with its TEB and heaps somewhere else.
    past = {f"{f.entry:x}" for f in syn.fns if f.name == "fs_past_page"}
    c.eq("determinism: two processes", [ln for ln in passes[0] if ln.split()[0] not in past],
         [ln for ln in passes[1] if ln.split()[0] not in past])
    # Only the low-zone foreign ranges describe the child; the rest of the environment is fixed.
    fixed = [{k: v if k != "foreign" else v[-1:] for k, v in read_env(env).items()} for _out, env, _summary in runs]
    c.eq("determinism: environment files", fixed[0], fixed[1])
    lines1 = passes[0]
    res = read_results(runs[0][0])
    res["lines"] = lines1
    env = read_env(runs[0][1])

    traces = {}
    for entry, seed, mode in traced:
        out, tenv = WORK / "trace.out", WORK / "trace.env"
        done = run_ref(image, jobs, out, tenv, "--trace", f"{entry:x}", f"{seed:x}")
        blocks = [b for b in done.stdout.split("trial ")[1:]]
        for block in blocks:
            head = block.split("\n", 1)[0].split()
            traces[(int(head[0], 16), int(head[1], 16), int(head[2]))] = parse_trace("trial " + block)
        got = traces.get((entry, seed, mode))
        c.ok(f"trace for {entry:x} {seed:x} {mode} present", got is not None and got["end"] is not None)
        if got is not None and got["end"] is not None and (entry, seed, mode) in res:
            c.eq(f"trace digest equals batch digest {entry:x} {seed:x} {mode}", int(got["end"]["digest"], 16),
                 res[(entry, seed, mode)].digest)

    for check in checks:
        try:
            check(res, traces, env, c)
        except Exception as exc:  # a missing line or field is a test failure, not a crash
            c.failures.append(f"{getattr(check, '__name__', 'check')}: {type(exc).__name__}: {exc}")
    for line in c.failures:
        print("FAIL:", line)
    print(f"synthetic: {len(syn.fns)} functions, {n_trials} trials run twice in each of two processes, "
          f"{c.checks} checks, {len(c.failures)} failures")
    print("  " + runs[0][2])
    return not c.failures


# ---- real image stage -----------------------------------------------------------------


def classify(meta) -> set[str]:
    tags = set()
    if meta.calls:
        tags.add("calls")
    if meta.stubs:
        tags.add("stubs")
    if meta.windows:
        tags.add("windows")
    for ins in meta.insns:
        m = ins.mnemonic
        if m.startswith("f") and m not in ("fs",):
            tags.add("x87")
        if "xmm" in ins.op_str:
            tags.add("sse")
        if "fs:" in ins.op_str:
            tags.add("fs")
        if m.startswith("rep"):
            tags.add("rep")
    return tags


def select_functions(count: int):
    """A reproducible mix: tiny, ordinary and large bodies, with quotas for calls, x87, SSE and FS use."""
    import image as img
    import meta as mt

    fns = [f for f in img.load_functions() if f.size > 0]
    rng = random.Random(0x1F7ED)
    rng.shuffle(fns)
    quota = {"tiny": count // 6, "large": count // 12, "x87": count // 8, "sse": count // 8, "fs": count // 8,
             "calls": count // 4, "windows": count // 30, "stubs": 8}
    have = collections.Counter()
    chosen, passed = [], []
    for f in fns[:4 * count]:
        if len(chosen) >= count:
            break
        m = mt.build_meta(f)
        if m.undecoded:
            continue
        tags = classify(m)
        if f.size <= 16:
            tags.add("tiny")
        if f.size >= 1500:
            tags.add("large")
        wanted = [t for t in tags if have[t] < quota.get(t, 0)]
        room = len(chosen) < count - sum(max(0, quota[t] - have[t]) for t in quota)
        if wanted or room:
            chosen.append((m, tags))
            have.update(tags)
        else:
            passed.append((m, tags))
    for m, tags in passed[:count - len(chosen)]:  # quotas the image could not fill
        chosen.append((m, tags))
        have.update(tags)
    chosen.sort(key=lambda item: item[0].fn.addr)
    return chosen, have


def real_stage(count: int, step_functions: int, keep: bool) -> bool:
    import image as img
    import meta as mt

    if not img.IMAGE_PATH.exists() and not (img.GENERATED / "image.bin").exists():
        print("real: game image not present, skipped")
        return True
    WORK.mkdir(parents=True, exist_ok=True)
    flat = img.flat_image_path()
    t0 = time.time()
    chosen, have = select_functions(count)
    lines = []
    n_fast = n_step = 0
    for i, (m, _tags) in enumerate(chosen):
        trials = [(mt.seed_for(m.fn.addr, k), FAST, 0) for k in range(4)]
        if i < step_functions:
            trials += [(mt.seed_for(m.fn.addr, k), STEP, 2000) for k in range(2)]
        n_fast += 4
        n_step += len(trials) - 4
        lines += mt.job_lines(m, trials)
    jobs = WORK / "real.job"
    jobs.write_text("\n".join(lines) + "\n", newline="\n")
    print(f"real: {len(chosen)} functions selected in {time.time() - t0:.1f} s "
          f"({n_fast} fast trials, {n_step} step trials); tags {dict(sorted(have.items()))}")

    outs = []
    for i in (1, 2):
        out, env = WORK / f"real{i}.out", WORK / f"real{i}.env"
        t0 = time.time()
        done = run_ref(flat, jobs, out, env)
        print(f"  run {i}: exit {done.returncode}, {time.time() - t0:.1f} s wall; {done.stderr.strip()}")
        if done.returncode != 0:
            return False
        outs.append(out.read_text().splitlines())
    ok = True
    status = collections.Counter()
    tkind = collections.Counter()
    exc = collections.Counter()
    for line in outs[0]:
        p = line.split()
        status[(int(p[2]), int(p[3]))] += 1
        if p[3] == "0":
            tkind[(int(p[2]), int(p[4]))] += 1
            if p[4] == "3":
                exc[int(p[6], 16)] += 1
    names = {1: "LEAVE", 2: "FAULT", 3: "EXC", 4: "STEP"}
    snames = {0: "OK", 1: "TIMEOUT", 5: "HARNESS"}
    for mode in (FAST, STEP):
        print(f"  mode {mode}: statuses " + ", ".join(f"{snames.get(s, s)}={n}" for (m, s), n in sorted(status.items())
                                                       if m == mode)
              + "; terminals " + ", ".join(f"{names[k]}={n}" for (m, k), n in sorted(tkind.items()) if m == mode))
    print("  exception classes " + ", ".join(f"{k}={n}" for k, n in sorted(exc.items())))
    harness = sum(n for (m, s), n in status.items() if s == S_HARNESS)
    if harness:
        print(f"FAIL: {harness} harness failures")
        ok = False
    if len(outs[0]) != n_fast + n_step or len(outs[1]) != len(outs[0]):
        print(f"FAIL: expected {n_fast + n_step} result lines, got {len(outs[0])} and {len(outs[1])}")
        ok = False
    # A wall-clock timeout depends on machine load, and what a child keeps in the low zone
    # depends on the child: an access there faults in one child and reads its memory in another
    # (the lifted runner reports the trial as foreign for the child that has memory there).
    # Every other line must be identical.
    zones = read_env(WORK / "real1.env")["foreign"] + read_env(WORK / "real2.env")["foreign"]

    def foreign_fault(line: str) -> bool:
        p = line.split()
        return p[3] == "0" and p[4] == str(T_FAULT) and any(lo <= int(p[6], 16) < hi for lo, hi in zones)

    differing = [(a, b) for a, b in zip(outs[0], outs[1]) if a != b]
    hard = [(a, b) for a, b in differing
            if a.split()[3] != "1" and b.split()[3] != "1" and not foreign_fault(a) and not foreign_fault(b)]
    print(f"  determinism: {len(differing)} lines differ between the runs, "
          f"{len(differing) - len(hard)} of them involve a timeout or a foreign zone")
    for a, b in hard[:10]:
        print("    ", a, "|", b)
    if hard:
        print(f"FAIL: {len(hard)} non-timeout lines differ between two runs")
        ok = False
    # Fast and step mode are two mechanisms for the same protocol. A trial run both ways must
    # agree unless the step budget ended it. (A function that reads filler bytes on its own
    # pages may legitimately differ, see "Reference side" in the design note.)
    by_key = {tuple(line.split()[:3]): line.split() for line in outs[0]}
    agree = disagree = 0
    for (entry, seed, mode), step in by_key.items():
        fast = by_key.get((entry, seed, str(FAST)))
        if mode != str(STEP) or fast is None or fast[3] != "0" or step[3] != "0" or step[4] == str(T_STEP):
            continue
        if fast[3:8] == step[3:8]:
            agree += 1
        else:
            disagree += 1
            if disagree <= 10:
                print("    ", " ".join(fast), "|", " ".join(step))
    print(f"  fast and step mode agree on {agree} of {agree + disagree} trials run both ways")
    if disagree:
        print(f"FAIL: {disagree} trials differ between fast and step mode")
        ok = False
    if not keep:
        for name in ("real2.out", "real2.env"):
            (WORK / name).unlink(missing_ok=True)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-tests for the reference debugger.")
    parser.add_argument("--no-real", action="store_true", help="skip the stage that needs the game image")
    parser.add_argument("--real-only", action="store_true", help="skip the synthetic stage")
    parser.add_argument("--functions", type=int, default=3000, help="functions in the real-image stage")
    parser.add_argument("--step-functions", type=int, default=300, help="of those, how many also run in step mode")
    parser.add_argument("--keep", action="store_true", help="keep the second result file of the real stage")
    args = parser.parse_args()
    build_ref.build()
    ok = True
    if not args.real_only:
        ok = synthetic_stage() and ok
    if not args.no_real:
        ok = real_stage(args.functions, args.step_functions, args.keep) and ok
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
