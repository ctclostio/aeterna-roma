"""Self-test of the lifted side: runtime, runner, thunks and lifter.

    python scripts/lift/selftest_lift.py                 every stage
    python scripts/lift/selftest_lift.py --no-real       the stages that need no game image
    python scripts/lift/selftest_lift.py --only vectors  one stage: flags, vectors, synthetic or real

No reference debugger is involved. The stages:

  flags      lift_flagtest.exe runs every integer flag helper of lift_rt.c
             against the real instruction on the host CPU.
  vectors    random register-only instruction encodings are lifted, compiled
             and run; registers and flags must equal those of the same bytes
             executed on the host. This checks the lifter's operand decoding
             and its use of the helpers end to end.
  synthetic  hand-encoded snippets in a synthetic image, with expected
             terminals, registers, memory bytes, call/stub events, coverage and
             step counts: fault atomicity, rep strings, x87/SIMD thunks, FS,
             step mode. Every digest is recomputed from the trace with the
             Python port of lift_model.h below.
  real       a spread of functions of the game image, several seeds each:
             no harness failures, two identical runs; reports lifting and
             compile speed and, over the whole inventory, which instructions
             the lifter does not translate.

Everything is written under generated/lifted/selftest/.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import json
import random
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capstone  # noqa: E402

import build_batch  # noqa: E402
import image as image_mod  # noqa: E402
import meta as meta_mod  # noqa: E402
import toolchain  # noqa: E402
from image import GENERATED, Function  # noqa: E402

WORK = GENERATED / "selftest"
M32 = 0xFFFFFFFF
PAGE = 4096
IMAGE_BASE = 0x10000000
ARENA_LO, ARENA_HI = 0x20000000, 0x60000000
STACK_TOP = 0x5FF00000
SENTINEL = 0xDEAD
REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
T_LEAVE, T_FAULT, T_EXC, T_STEP = 1, 2, 3, 4
S_OK, S_FOREIGN, S_BUDGET, S_UNSUPPORTED, S_HARNESS = 0, 2, 3, 4, 5
X_DIV, X_BKPT, X_ILL, X_PRIV, X_FP, X_TRAP = 1, 2, 3, 4, 5, 6
FAST, STEP = 0, 1
STATUS_FLAGS = 0x8D5  # CF PF AF ZF SF OF in an EFLAGS image

# The environment the reference debugger gives every trial (tests/lift_ref/ref_dbg.c).
MODEL_TEB = 0x7EFDD000
MODEL_TEB_FIELDS = {0x00: 0xFFFFFFFF, 0x04: ARENA_HI, 0x08: STACK_TOP - 0x100000, 0x18: MODEL_TEB,
                    0x20: 0x1000, 0x24: 0x1004, 0x2C: 0x5FD00000, 0x30: 0x5FC00000}
FOREIGN_ZONES = ((0x10000, 0x1000000), (0x7E000000, 0x80000000))


# ---- Python port of lift_model.h ---------------------------------------------------


def mix32(x: int) -> int:
    x &= M32
    x ^= x >> 16
    x = (x * 0x85EBCA6B) & M32
    x ^= x >> 13
    x = (x * 0xC2B2AE35) & M32
    return x ^ (x >> 16)


def hash2(a: int, b: int) -> int:
    return mix32(((a * 0x9E3779B1) & M32) ^ mix32((b + 0x7F4A7C15) & M32))


def shape_ptr(h: int) -> int:
    return 0x20000000 + (((h >> 3) % (0x30000000 >> 4)) << 4)


SHAPE_FLOATS = (0x3F800000, 0x3F000000, 0x40000000, 0xBF800000, 0x42C80000, 0x3E800000, 0x40400000, 0x41200000)


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
        return SHAPE_FLOATS[(h >> 3) & 7]
    return mix32(h ^ 0xA5A5A5A5)


def fill_dword(seed: int, addr: int) -> int:
    return SENTINEL if addr == STACK_TOP else shape(hash2(seed, addr >> 2))


def init_gpr(seed: int) -> list[int]:
    r = [shape(hash2(seed ^ 0x52454753, i)) for i in range(8)]
    r[1] = shape_ptr(hash2(seed ^ 0x52454753, 0x100))
    r[4] = STACK_TOP
    return r


def init_fx(seed: int) -> bytearray:
    fx = bytearray(512)
    struct.pack_into("<H", fx, 0, 0x027F)
    struct.pack_into("<I", fx, 24, 0x1F80)
    for i in range(32):
        struct.pack_into("<I", fx, 160 + 4 * i, shape(hash2(seed ^ 0x584D4D30, i)))
    return fx


def stub_call_regs(seed: int, n: int) -> tuple[int, int, int]:
    return tuple(shape(hash2(seed ^ 0x43414C4C, 4 * n + k)) for k in range(3))


STUB_ST0_FLOATS = (1.0, 0.5, 2.0, 0.0, -1.0, 100.0, 0.25, 3.0)


def stub_call_st0(seed: int, n: int) -> float:
    return STUB_ST0_FLOATS[hash2(seed ^ 0x43414C4C, 4 * n + 3) & 7]


def stub_insn_regs(seed: int, n: int) -> list[int]:
    return [mix32(hash2(seed ^ 0x494E534E, 4 * n + k)) for k in range(4)]


class Digest:
    """lm_hash and the records built on it."""

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
        self.raw(fx[0:5])
        for i in range(8):
            self.raw(fx[32 + 16 * i:42 + 16 * i])
        self.raw(fx[24:28])
        self.raw(fx[160:288])

    def state(self, regs: list[int], df: int, fx: bytes) -> None:
        for v in regs:
            self.u32(v)
        self.u32(df)
        self.fx(fx)

    def call(self, target: int, site: int, regs: list[int], df: int, fx: bytes, stack: list[int]) -> None:
        for v in (0x43, target, site):
            self.u32(v)
        self.state(regs, df, fx)
        for w in stack:
            self.u32(w)

    def insn(self, kind: int, addr: int) -> None:
        for v in (0x49, kind, addr):
            self.u32(v)

    def terminal(self, kind: int, a: int, b: int, regs: list[int], df: int, fx: bytes) -> None:
        for v in (0x54, kind, a, b):
            self.u32(v)
        self.state(regs, df, fx)

    def mem(self, changed: dict[int, int]) -> None:
        self.u32(0x4D)
        for addr in sorted(changed):
            self.u32(addr)
            self.raw(bytes((changed[addr],)))
        self.u32(0x45)
        self.u32(len(changed))


def fx_hash(fx: bytes) -> int:
    d = Digest()
    d.fx(fx)
    return d.h


# ---- bookkeeping ----------------------------------------------------------------------


class Checker:
    def __init__(self) -> None:
        self.checks = 0
        self.failures: list[str] = []

    def eq(self, what: str, got, want) -> bool:
        self.checks += 1
        if got != want:
            show = (lambda v: f"{v:#x}" if isinstance(v, int) and not isinstance(v, bool) else repr(v))
            self.failures.append(f"{what}: got {show(got)}, want {show(want)}")
            return False
        return True

    def ok(self, what: str, cond: bool) -> bool:
        return self.eq(what, bool(cond), True)

    def report(self, stage: str, since: int) -> bool:
        new = self.failures[since:]
        for line in new[:40]:
            print(f"  FAIL {line}")
        if len(new) > 40:
            print(f"  ... and {len(new) - 40} more")
        print(f"[{stage}] {'ok' if not new else f'{len(new)} FAILED'}")
        return not new


def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def write_env(path: Path, image_size: int) -> bytes:
    """The reference's environment file for an image of image_size bytes; returns the TEB page."""
    teb = bytearray(PAGE)
    for off, value in MODEL_TEB_FIELDS.items():
        struct.pack_into("<I", teb, off, value)
    lines = [f"fs_base {MODEL_TEB:x}", f"image_size {image_size:x}", f"teb {teb.hex()}"]
    lines += [f"foreign {lo:x} {hi:x}" for lo, hi in FOREIGN_ZONES]
    path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    return bytes(teb)


# ---- synthetic images -------------------------------------------------------------------

LINE = re.compile(r"^(?:(@\w+):)?\s*([^|]*)\|\s*(.*)$")
PLACEHOLDER_SIZE = {"rel32": 4, "abs32": 4, "rel8": 1}


class Fn:
    """One hand-encoded function: lines of `[@label:] <hex bytes> | <disassembly>`.

    A byte position may be {rel32:NAME}, {rel8:NAME} or {abs32:NAME}, where
    NAME is a local @label, another function or a table; the disassembly text
    names the same address as {NAME}. The text is compared with capstone's
    reading of the bytes, so a mis-encoded test fails loudly instead of
    testing something else.
    """

    def __init__(self, name: str, addr: int, text: str, pop_bytes: int, fp_ret: bool) -> None:
        self.name, self.addr, self.pop_bytes, self.fp_ret = name, addr, pop_bytes, fp_ret
        self.lines = []  # (offset, tokens, size, disassembly)
        self.labels: dict[str, int] = {}
        offset = 0
        for raw in text.strip().splitlines():
            raw = raw.strip()
            if not raw or raw.startswith(";"):
                continue
            m = LINE.match(raw)
            if m is None:
                raise ValueError(f"{name}: bad line {raw!r}")
            label, tokens, asm = m.group(1), m.group(2).split(), m.group(3).strip()
            if label:
                self.labels[label] = addr + offset
            size = sum(PLACEHOLDER_SIZE[t[1:].split(":")[0]] if t.startswith("{") else 1 for t in tokens)
            self.lines.append((offset, tokens, size, asm))
            offset += size
        self.size = offset
        self.insn_addrs = [addr + off for off, _, _, _ in self.lines]

    def at(self, label: str) -> int:
        return self.labels[label]

    def index_of(self, label: str) -> int:
        return self.insn_addrs.index(self.labels[label])

    def encode(self, resolve) -> bytes:
        out = bytearray()
        for offset, tokens, size, _ in self.lines:
            end = self.addr + offset + size
            for t in tokens:
                if not t.startswith("{"):
                    out.append(int(t, 16))
                    continue
                kind, name = t[1:-1].split(":")
                target = self.labels[name] if name.startswith("@") else resolve(name)
                if kind == "abs32":
                    out += struct.pack("<I", target)
                elif kind == "rel32":
                    out += struct.pack("<i", target - end)
                else:
                    out += struct.pack("<b", target - end)
        return bytes(out)

    def expected_text(self, resolve) -> list[str]:
        def sub(m):
            name = m.group(1)
            return f"{self.labels[name] if name.startswith('@') else resolve(name):#x}"
        return [re.sub(r"\{([@\w]+)\}", sub, asm) for _, _, _, asm in self.lines]


class Synth:
    """A flat image made of Fn bodies and data tables, and its function inventory."""

    def __init__(self, name: str, size: int = 0x40000) -> None:
        self.name = name
        self.buf = bytearray(size)
        self.cursor = IMAGE_BASE + 0x1000
        self.data_cursor = IMAGE_BASE + size - 0x8000
        self.fns: dict[str, Fn] = {}
        self.symbols: dict[str, int] = {}
        self.path = WORK / f"{name}.bin"

    def fn(self, name: str, text: str, pop_bytes: int = 0, fp_ret: bool = False) -> Fn:
        f = Fn(name, self.cursor, text, pop_bytes, fp_ret)
        self.fns[name] = f
        self.symbols[name] = f.addr
        self.cursor = (f.addr + f.size + 16) & ~15  # at least one byte between bodies
        if self.cursor >= self.data_cursor:
            raise ValueError("synthetic image is full")
        return f

    def table(self, name: str, dwords: list[int]) -> int:
        addr = self.data_cursor
        self.symbols[name] = addr
        self.put(addr, b"".join(struct.pack("<I", v) for v in dwords))
        self.data_cursor += (4 * len(dwords) + 15) & ~15
        return addr

    def put(self, addr: int, data: bytes) -> None:
        self.buf[addr - IMAGE_BASE:addr - IMAGE_BASE + len(data)] = data

    def finish(self, c: Checker) -> None:
        """Encodes every function, checks the encodings against capstone, writes the image."""
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        for f in self.fns.values():
            code = f.encode(self.symbols.__getitem__)
            self.put(f.addr, code)
            got = [" ".join(f"{i.mnemonic} {i.op_str}".split()) for i in md.disasm(code, f.addr)]
            want = [" ".join(t.split()) for t in f.expected_text(self.symbols.__getitem__)]
            if got != want:
                for g, w in zip(got + ["<nothing>"] * len(want), want + ["<nothing>"] * len(got)):
                    if g != w:
                        c.eq(f"{self.name}/{f.name} encoding", g, w)
                        break
        WORK.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(self.buf)

    def functions(self) -> tuple[Function, ...]:
        return tuple(Function(addr=f.addr, name=f.name, ranges=((f.addr, f.addr + f.size),), sha256="",
                              pop_bytes=f.pop_bytes, fp_ret=f.fp_ret)
                     for f in sorted(self.fns.values(), key=lambda f: f.addr))

    @contextlib.contextmanager
    def installed(self):
        """Makes meta.py see this image and inventory instead of the game's."""
        saved = (meta_mod.load_image, meta_mod.load_functions, meta_mod.function_index)
        functions = self.functions()
        index = {f.addr: f for f in functions}
        image = bytes(self.buf)
        meta_mod.load_image = lambda: image
        meta_mod.load_functions = lambda: functions
        meta_mod.function_index = lambda: index
        meta_mod._starts.cache_clear()
        meta_mod._range_starts.cache_clear()
        try:
            yield lambda entry: meta_mod.build_meta(index[entry])
        finally:
            meta_mod.load_image, meta_mod.load_functions, meta_mod.function_index = saved
            meta_mod._starts.cache_clear()
            meta_mod._range_starts.cache_clear()

    def pristine(self, seed: int, addr: int, teb: bytes | None) -> int:
        if IMAGE_BASE <= addr < IMAGE_BASE + len(self.buf):
            return self.buf[addr - IMAGE_BASE]
        if ARENA_LO <= addr < ARENA_HI:
            return (fill_dword(seed, addr & ~3) >> (8 * (addr & 3))) & 0xFF
        if teb is not None and MODEL_TEB <= addr < MODEL_TEB + PAGE:
            return teb[addr - MODEL_TEB]
        raise ValueError(f"{addr:#x} is not model memory")


# ---- running a batch and reading its trace ----------------------------------------------


def parse_trace(text: str) -> list[dict]:
    trials, cur = [], None
    for line in text.splitlines():
        tok = line.split()
        if not tok:
            continue
        kv = dict(t.split("=", 1) for t in tok[1:] if "=" in t)
        kind = tok[0]
        if kind == "trial":
            cur = {"entry": int(tok[1], 16), "seed": int(tok[2], 16), "mode": int(tok[3]), "events": [], "mem": {},
                   "pages": [], "step_lines": [], "term": None, "fx": None, "end": None}
            trials.append(cur)
        elif cur is None:
            raise ValueError(f"trace line outside a trial: {line}")
        elif kind == "call":
            cur["events"].append({"type": "call", "n": int(tok[1]), "target": int(kv["target"], 16),
                                  "site": int(kv["site"], 16), "regs": [int(kv[r], 16) for r in REGS],
                                  "df": int(kv["df"]), "fx": int(kv["fx"], 16),
                                  "stack": [int(w, 16) for w in kv["stack"].split(",")]})
        elif kind == "insn":
            cur["events"].append({"type": "insn", "n": int(tok[1]), "kind": int(kv["kind"]), "addr": int(kv["addr"], 16)})
        elif kind == "step":
            cur["step_lines"].append((int(tok[1]), int(tok[2], 16)))
        elif kind == "page":
            cur["pages"].append(int(tok[1], 16))
        elif kind == "term":
            cur["term"] = {"kind": int(kv["kind"]), "a": int(kv["a"], 16), "b": int(kv["b"], 16),
                           "regs": [int(kv[r], 16) for r in REGS], "df": int(kv["df"])}
            cur["fx"] = bytearray(512)
        elif kind == "fx":
            struct.pack_into("<HHB", cur["fx"], 0, int(kv["fcw"], 16), int(kv["fsw"], 16), int(kv["ftw"], 16))
            struct.pack_into("<I", cur["fx"], 24, int(kv["mxcsr"], 16))
        elif kind.startswith("st") and kind[2:].isdigit():
            cur["fx"][32 + 16 * int(kind[2:]):42 + 16 * int(kind[2:])] = bytes.fromhex(tok[1])
        elif kind.startswith("xmm"):
            cur["fx"][160 + 16 * int(kind[3:]):176 + 16 * int(kind[3:])] = bytes.fromhex(tok[1])
        elif kind == "mem":
            cur["mem"][int(tok[1], 16)] = int(tok[2], 16)
        elif kind == "end":
            cur["end"] = {"status": int(kv["status"]), "digest": int(kv["digest"], 16), "steps": int(kv["steps"])}
        else:
            raise ValueError(f"unknown trace line: {line}")
    return trials


def trace_digest(tr: dict) -> int | None:
    """Digest recomputed from a trial's trace, or None when a call event's
    x87/SSE state is not the initial one (the trace only carries its hash)."""
    d = Digest()
    fx0 = init_fx(tr["seed"])
    for ev in tr["events"]:
        if ev["type"] == "insn":
            d.insn(ev["kind"], ev["addr"])
        elif ev["fx"] != fx_hash(fx0):
            return None
        else:
            d.call(ev["target"], ev["site"], ev["regs"], ev["df"], fx0, ev["stack"])
    t = tr["term"]
    d.terminal(t["kind"], t["a"], t["b"], t["regs"], t["df"], tr["fx"])
    d.mem(tr["mem"])
    return d.h


def run_traced(c: Checker, label: str, synth: Synth, trials: dict[int, list], env: Path | None, cov: bool = False):
    """Builds a batch from a synthetic image, runs every trial with tracing and
    returns (traces in job order, batch, coverage lines). Result lines must
    agree with the trace and every digest with the Python model."""
    out_dir = WORK / label
    with synth.installed() as meta_for:
        batch = build_batch.build_batch(list(trials), out_dir, trials, meta_for=meta_for)
    cmd = [batch.runner, "--image", synth.path, "--jobs", batch.job_file, "--out", out_dir / "results.txt",
           "--trace", "0", "0"]
    if env is not None:
        cmd += ["--env", env]
    if cov:
        cmd += ["--cov", out_dir / "cov.txt"]
    proc = run(cmd)
    if not c.eq(f"{label}: runner exit status", proc.returncode, 0):
        print(proc.stderr[-2000:])
        return [], batch, []
    traces = parse_trace(proc.stdout)
    results = [line.split() for line in (out_dir / "results.txt").read_text().splitlines()]
    order = [(entry, t) for entry in sorted(trials) for t in trials[entry]]
    c.eq(f"{label}: traced trials", len(traces), len(order))
    c.eq(f"{label}: result lines", len(results), len(order))
    for (entry, (seed, mode, _)), tr, res in zip(order, traces, results):
        what = f"{label} {entry:x}/{seed:x}/{mode}"
        c.eq(f"{what}: trial header", (tr["entry"], tr["seed"], tr["mode"]), (entry, seed, mode))
        end, term = tr["end"], tr["term"]
        want = [f"{entry:x}", f"{seed:x}", str(mode), str(end["status"])]
        if end["status"] == S_OK:
            want += [str(term["kind"]), f"{term['a']:x}", f"{term['b']:x}", f"{end['digest']:016x}", str(end["steps"])]
            c.eq(f"{what}: result line", res, want)
            digest = trace_digest(tr)
            if digest is not None:
                c.eq(f"{what}: digest against the model port", end["digest"], digest)
        else:
            c.eq(f"{what}: result line", res[:5] + res[7:8], want + ["0", f"{0:016x}"])
    cov_lines = [line.split() for line in (out_dir / "cov.txt").read_text().splitlines()] if cov else []
    return traces, batch, cov_lines


# ---- stage: flags ----------------------------------------------------------------------------


def flagtest_exe() -> Path:
    out = WORK / "flagtest"
    objs = toolchain.build_runtime_objs(out, ("lift_rt.c", "lift_flagtest.c"))
    exe = out / "lift_flagtest.exe"
    if not exe.exists() or any(o.stat().st_mtime > exe.stat().st_mtime for o in objs):
        toolchain.link_exe(exe, objs)
    return exe


def stage_flags(c: Checker, args, report: dict) -> None:
    proc = run([flagtest_exe(), "--iters", str(args.flag_iters)])
    tail = (proc.stdout.strip().splitlines() or ["<no output>"])[-1]
    print(f"  {tail}")
    m = re.search(r"(\d+) comparisons, (\d+) mismatches", tail)
    c.ok("flagtest ran", m is not None and proc.returncode in (0, 1))
    if m:
        report["flag_comparisons"] = int(m.group(1))
        c.eq("flag helper mismatches against the host CPU", int(m.group(2)), 0)
        if int(m.group(2)):
            print("\n".join(proc.stdout.splitlines()[:30]))


# ---- stage: vectors --------------------------------------------------------------------------

R32 = (0, 1, 2, 3, 6, 7)  # the registers the host harness carries: no esp, no ebp
EDGES = (0, 1, 2, 3, 0xF, 0x10, 0x1F, 0x20, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF,
         0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 0x55555555, 0xAAAAAAAA)


def value(rng) -> int:
    k = rng.randrange(4)
    if k == 0:
        return rng.choice(EDGES)
    if k == 1:
        return rng.randrange(64)
    return rng.getrandbits(32)


def mrm(reg: int, rm: int) -> bytes:
    return bytes((0xC0 | (reg << 3) | rm,))


def imm(rng, size: int) -> bytes:
    return (value(rng) & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def p66(rng) -> tuple[bytes, int]:
    """Operand-size prefix or nothing, and the immediate size that goes with it."""
    return (b"\x66", 2) if rng.random() < 0.3 else (b"", 4)


def g_alu(rng):
    base, form = 8 * rng.randrange(8), rng.randrange(9)
    r, m, r8, m8 = rng.choice(R32), rng.choice(R32), rng.randrange(8), rng.randrange(8)
    pre, isz = p66(rng)
    if form == 0:
        return bytes((base,)) + mrm(r8, m8)
    if form == 1:
        return pre + bytes((base + 1,)) + mrm(r, m)
    if form == 2:
        return bytes((base + 2,)) + mrm(r8, m8)
    if form == 3:
        return pre + bytes((base + 3,)) + mrm(r, m)
    if form == 4:
        return bytes((base + 4,)) + imm(rng, 1)
    if form == 5:
        return pre + bytes((base + 5,)) + imm(rng, isz)
    if form == 6:
        return b"\x80" + mrm(base >> 3, m8) + imm(rng, 1)
    if form == 7:
        return pre + b"\x81" + mrm(base >> 3, m) + imm(rng, isz)
    return pre + b"\x83" + mrm(base >> 3, m) + imm(rng, 1)


def g_test(rng):
    form = rng.randrange(6)
    r, m = rng.choice(R32), rng.choice(R32)
    pre, isz = p66(rng)
    if form == 0:
        return b"\x84" + mrm(rng.randrange(8), rng.randrange(8))
    if form == 1:
        return pre + b"\x85" + mrm(r, m)
    if form == 2:
        return b"\xa8" + imm(rng, 1)
    if form == 3:
        return pre + b"\xa9" + imm(rng, isz)
    if form == 4:
        return b"\xf6" + mrm(0, rng.randrange(8)) + imm(rng, 1)
    return pre + b"\xf7" + mrm(0, m) + imm(rng, isz)


def g_group3(rng):
    """not, neg, mul, imul, div, idiv. Divides get operands that often do not trap."""
    op = rng.randrange(2, 8)
    pre, _ = p66(rng)
    wide = rng.random() < 0.7
    code = (pre + b"\xf7" + mrm(op, rng.choice(R32))) if wide else (b"\xf6" + mrm(op, rng.randrange(8)))
    fix = {}
    if op >= 6 and rng.random() < 0.8:
        if not wide:
            fix[0] = rng.randrange(0x4000)  # AX / r8
        elif op == 6:
            fix[2] = rng.randrange(4)
        else:
            fix[0] = value(rng)
            fix[2] = 0xFFFFFFFF if fix[0] & (0x8000 if pre else 0x80000000) else 0
    return code, fix


def g_incdec(rng):
    pre, _ = p66(rng)
    op = rng.randrange(2)
    return b"\xfe" + mrm(op, rng.randrange(8)) if rng.random() < 0.4 else pre + b"\xff" + mrm(op, rng.choice(R32))


def g_shift(rng):
    op, form = rng.randrange(8), rng.randrange(3)
    pre, _ = p66(rng)
    wide = rng.random() < 0.6
    rm = mrm(op, rng.choice(R32) if wide else rng.randrange(8))
    opcode = (0xC0, 0xD0, 0xD2)[form] + wide
    return (pre if wide else b"") + bytes((opcode,)) + rm + (imm(rng, 1) if form == 0 else b"")


def g_double_shift(rng):
    pre, _ = p66(rng)
    opcode = rng.choice((0xA4, 0xA5, 0xAC, 0xAD))
    return pre + bytes((0x0F, opcode)) + mrm(rng.choice(R32), rng.choice(R32)) + (imm(rng, 1) if opcode & 1 == 0 else b"")


def g_imul(rng):
    pre, isz = p66(rng)
    form = rng.randrange(3)
    rm = mrm(rng.choice(R32), rng.choice(R32))
    if form == 0:
        return pre + b"\x0f\xaf" + rm
    if form == 1:
        return pre + b"\x69" + rm + imm(rng, isz)
    return pre + b"\x6b" + rm + imm(rng, 1)


def g_extend(rng):
    opcode = rng.choice((0xB6, 0xB7, 0xBE, 0xBF))
    if opcode & 1:
        return bytes((0x0F, opcode)) + mrm(rng.choice(R32), rng.choice(R32))
    return p66(rng)[0] + bytes((0x0F, opcode)) + mrm(rng.choice(R32), rng.randrange(8))


def g_mov(rng):
    form = rng.randrange(8)
    pre, isz = p66(rng)
    r, m = rng.choice(R32), rng.choice(R32)
    if form == 0:
        return bytes((rng.choice((0x88, 0x8A)),)) + mrm(rng.randrange(8), rng.randrange(8))
    if form == 1:
        return pre + bytes((rng.choice((0x89, 0x8B)),)) + mrm(r, m)
    if form == 2:
        return bytes((0xB0 | rng.randrange(8),)) + imm(rng, 1)
    if form == 3:
        return pre + bytes((0xB8 | r,)) + imm(rng, isz)
    if form == 4:
        return b"\xc6" + mrm(0, rng.randrange(8)) + imm(rng, 1)
    if form == 5:
        return pre + b"\xc7" + mrm(0, m) + imm(rng, isz)
    if form == 6:
        return rng.choice((b"\x86" + mrm(rng.randrange(8), rng.randrange(8)), pre + b"\x87" + mrm(r, m)))
    return pre + bytes((0x90 | rng.choice((1, 2, 3, 6, 7)),))


def g_lea(rng):
    pre, _ = p66(rng)
    reg, base, index, scale = rng.choice(R32), rng.choice(R32), rng.choice(R32), rng.randrange(4)
    form = rng.randrange(5)
    if form == 0:
        return pre + b"\x8d" + bytes((reg << 3 | base,))
    if form == 1:
        return pre + b"\x8d" + bytes((0x40 | reg << 3 | base,)) + imm(rng, 1)
    if form == 2:
        return pre + b"\x8d" + bytes((0x80 | reg << 3 | base,)) + imm(rng, 4)
    if form == 3:
        return pre + b"\x8d" + bytes((0x44 | reg << 3, scale << 6 | index << 3 | base)) + imm(rng, 1)
    return pre + b"\x8d" + bytes((0x04 | reg << 3, scale << 6 | index << 3 | 5)) + imm(rng, 4)


def g_cond(rng):
    cc, form = rng.randrange(16), rng.randrange(4)
    if form == 0:
        return bytes((0x0F, 0x90 | cc)) + mrm(0, rng.randrange(8))
    if form == 1:
        return p66(rng)[0] + bytes((0x0F, 0x40 | cc)) + mrm(rng.choice(R32), rng.choice(R32))
    skipped = bytes((0xB0 | rng.randrange(8),)) + imm(rng, 1)  # mov r8, imm8
    if form == 2:
        return bytes((0x70 | cc, len(skipped))) + skipped
    return bytes((rng.choice((0xE0, 0xE1, 0xE2, 0xE3)), len(skipped))) + skipped  # loopne, loope, loop, jecxz


def g_bit(rng):
    pre, _ = p66(rng)
    form = rng.randrange(4)
    rm = mrm(rng.choice(R32), rng.choice(R32))
    if form == 0:
        return pre + bytes((0x0F, rng.choice((0xA3, 0xAB, 0xB3, 0xBB)))) + rm
    if form == 1:
        return pre + b"\x0f\xba" + mrm(rng.randrange(4, 8), rng.choice(R32)) + imm(rng, 1)
    if form == 2:
        return pre + bytes((0x0F, rng.choice((0xBC, 0xBD)))) + rm
    return bytes((0x0F, 0xC8 | rng.choice(R32)))


def g_exchange(rng):
    pre, _ = p66(rng)
    opcode = rng.choice((0xC0, 0xC1, 0xB0, 0xB1))  # xadd, cmpxchg
    if opcode & 1:
        return pre + bytes((0x0F, opcode)) + mrm(rng.choice(R32), rng.choice(R32))
    return bytes((0x0F, opcode)) + mrm(rng.randrange(8), rng.randrange(8))


def g_single(rng):
    return rng.choice((b"\x99", b"\x98", b"\x66\x98", b"\x66\x99", b"\x9f", b"\x9e", b"\xf8", b"\xf9", b"\xf5",
                       b"\x90", b"\x0f\x1f\xc0", b"\x66\x90"))


GENERATORS = (g_alu, g_alu, g_alu, g_test, g_group3, g_group3, g_incdec, g_shift, g_shift, g_shift, g_double_shift,
              g_imul, g_extend, g_mov, g_lea, g_cond, g_cond, g_bit, g_bit, g_exchange, g_single)


def packed_flags(eflags: int) -> int:
    """EFLAGS image -> the LAHF/SETO form lift_flagtest --exec takes and prints."""
    return ((eflags & 0xD5) << 8) | ((eflags >> 11) & 1)


def stage_vectors(c: Checker, args, report: dict) -> None:
    rng = random.Random(0x11F7)
    synth = Synth("vectors", size=0x10000 + 0x60 * args.vectors + 0x10000)
    vectors, trials = [], {}
    for n in range(args.vectors):
        made = GENERATORS[n % len(GENERATORS)](rng)
        code, fix = made if isinstance(made, tuple) else (made, {})
        regs = [value(rng) for _ in range(6)]
        for index, v in fix.items():
            regs[index] = v
        eflags = 0x202 | (rng.getrandbits(12) & STATUS_FLAGS)
        prologue = b"".join(bytes((0xB8 | r,)) + struct.pack("<I", v) for r, v in zip(R32, regs))
        prologue += b"\x68" + struct.pack("<I", eflags) + b"\x9d"                 # push imm32; popfd
        body = prologue + code + b"\x9c\x5d\xc3"                                  # pushfd; pop ebp; ret
        f = synth.fn(f"v{n}", "")
        f.size = len(body)
        synth.put(f.addr, body)
        synth.cursor = (f.addr + f.size + 16) & ~15
        vectors.append((f.addr, f.addr + len(prologue), code, regs, eflags))
        trials[f.addr] = [(1, FAST, 0)]
    WORK.mkdir(parents=True, exist_ok=True)
    synth.path.write_bytes(synth.buf)

    vec_file = WORK / "vectors.txt"
    vec_file.write_text("".join(
        f"{code.hex()} {' '.join(f'{v:x}' for v in regs)} {packed_flags(eflags):x}\n"
        for _, _, code, regs, eflags in vectors), encoding="ascii", newline="\n")
    host = run([flagtest_exe(), "--exec", vec_file])
    host_lines = host.stdout.split("\n")
    if not c.eq("host executions", (host.returncode, len(host_lines) - 1), (0, len(vectors))):
        return

    traces, batch, _ = run_traced(c, "vectors", synth, trials, None)
    unsupported = [u for f in batch.functions.values() for u in f.unsupported]
    c.eq("vector instructions the lifter refused", [f"{m} {raw}" for _, m, raw, _ in unsupported][:10], [])
    faults = 0
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for (entry, insn_addr, code, regs, eflags), line, tr in zip(vectors, host_lines, traces):
        text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(code, insn_addr))
        what = f"vector {code.hex()} ({text}) regs {' '.join(f'{v:x}' for v in regs)} eflags {eflags:x}"
        term = tr["term"]
        if term is None:
            c.ok(f"{what}: trial has a terminal (status {tr['end']['status']})", False)
            continue
        got = [term["regs"][r] for r in R32]
        if line.strip() == "FAULT":
            faults += 1
            c.eq(f"{what}: divide error", (term["kind"], term["a"], term["b"], got), (T_EXC, insn_addr, X_DIV, regs))
            continue
        fields = [int(v, 16) for v in line.split()]
        want_flags = fields[6]
        c.eq(f"{what}: terminal", (term["kind"], term["a"]), (T_LEAVE, SENTINEL))
        c.eq(f"{what}: registers", " ".join(f"{v:08x}" for v in got), " ".join(f"{v:08x}" for v in fields[:6]))
        c.eq(f"{what}: flags", packed_flags(term["regs"][5]), want_flags)
    report["vectors"] = len(vectors)
    report["vector_divide_errors"] = faults
    print(f"  {len(vectors)} instruction vectors against the host ({faults} divide errors)")


# ---- stage: synthetic ------------------------------------------------------------------------


class Suite:
    def __init__(self, name: str, min_thunks: int = 0) -> None:
        self.synth = Synth(name)
        self.min_thunks = min_thunks
        self.cases = []  # (fn, seed, mode, budget, expectations)

    def fn(self, name: str, text: str, **kw) -> Fn:
        return self.synth.fn(name, text, **kw)

    def expect(self, f: Fn, *, seed: int = 1, mode: int = FAST, budget: int = 0, **exp) -> None:
        self.cases.append((f, seed, mode, budget, exp))

    def run(self, c: Checker, env: Path | None, teb: bytes | None) -> None:
        self.synth.finish(c)
        trials: dict[int, list] = {}
        for f, seed, mode, budget, _ in self.cases:
            trials.setdefault(f.addr, []).append((seed, mode, budget))
        traces, batch, cov = run_traced(c, self.synth.name, self.synth, trials, env, cov=True)
        if not traces:
            return
        for info in batch.functions.values():
            c.eq(f"{self.synth.name} {info.entry:x}: untranslated instructions", info.unsupported, [])
        self.check_thunks(c, batch)
        by_key = collections.defaultdict(list)
        for tr in traces:
            by_key[(tr["entry"], tr["seed"], tr["mode"])].append(tr)
        cov_by_key = collections.defaultdict(list)
        for row in cov:
            if row[0] == "T":  # T entry seed mode insns n_covered bitmap
                cov_by_key[(int(row[1], 16), int(row[2], 16), int(row[3]))].append(
                    (int(row[4]), row[6] if len(row) > 6 else ""))
        for f, seed, mode, budget, exp in self.cases:
            key = (f.addr, seed, mode)
            self.check(c, f, seed, mode, budget, exp, by_key[key].pop(0), cov_by_key[key].pop(0), teb)

    def check_thunks(self, c: Checker, batch) -> None:
        """Every thunk of the batch must be straight-line x64 code ending in ret that never names rsp."""
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        text = (batch.out_dir / "batch.c").read_text()
        thunks = re.findall(r"LIFT_THUNK\((\w+)\) = \{([^}]*)\};", text)
        c.ok(f"{self.synth.name}: batch has at least {self.min_thunks} thunks", len(thunks) >= self.min_thunks)
        for name, body in thunks:
            code = bytes(int(b, 16) for b in body.split(","))
            insns = list(md.disasm(code, 0))
            c.eq(f"thunk {name}: decodes completely", sum(i.size for i in insns), len(code))
            c.eq(f"thunk {name}: ends in ret", insns[-1].mnemonic if insns else "", "ret")
            c.ok(f"thunk {name}: leaves rsp alone", not any("sp" in i.op_str for i in insns))
            c.ok(f"thunk {name}: is straight-line", not any(i.mnemonic[0] == "j" or i.mnemonic == "call" for i in insns))

    def check(self, c: Checker, f: Fn, seed: int, mode: int, budget: int, exp: dict, tr: dict, cov: tuple, teb) -> None:
        what = f"{self.synth.name}/{f.name} seed {seed:x} mode {mode} budget {budget}"
        end, term = tr["end"], tr["term"]
        insns, cov = cov
        if not c.eq(f"{what}: status", end["status"], exp.get("status", S_OK)) or end["status"] != S_OK:
            return
        for key in ("kind", "a", "b"):
            if key in exp:
                c.eq(f"{what}: terminal {key}", term[key], exp[key])
        # The result line carries the step count in step mode only; the
        # coverage file has the number of completed instructions in both.
        c.eq(f"{what}: reported steps", end["steps"], insns if mode == STEP else 0)
        if "steps" in exp:
            c.eq(f"{what}: steps", insns, exp["steps"])
        if "df" in exp:
            c.eq(f"{what}: df", term["df"], exp["df"])
        for name, want in exp.get("regs", {}).items():
            c.eq(f"{what}: {name}", term["regs"][REGS.index(name)], want & M32)
        if "mem" in exp:
            want = {}
            for addr, data in exp["mem"].items():
                for i, b in enumerate(data):
                    if b != self.synth.pristine(seed, addr + i, teb):
                        want[addr + i] = b
            c.eq(f"{what}: changed memory", {f"{a:x}": b for a, b in sorted(tr["mem"].items())},
                 {f"{a:x}": b for a, b in sorted(want.items())})
        if "calls" in exp or "insns" in exp:
            calls = [e for e in tr["events"] if e["type"] == "call"]
            insns = [(e["kind"], e["addr"]) for e in tr["events"] if e["type"] == "insn"]
            c.eq(f"{what}: stubbed instructions", insns, exp.get("insns", []))
            c.eq(f"{what}: call events", len(calls), len(exp.get("calls", [])))
            for n, (got, want) in enumerate(zip(calls, exp.get("calls", []))):
                c.eq(f"{what}: call {n} target/site", (got["target"], got["site"]), (want["target"], want["site"]))
                if "stack" in want:
                    c.eq(f"{what}: call {n} stack", got["stack"][:len(want["stack"])], want["stack"])
                for name, v in want.get("regs", {}).items():
                    c.eq(f"{what}: call {n} {name}", got["regs"][REGS.index(name)], v & M32)
        for key, want in exp.get("fx", {}).items():
            fx = tr["fx"]
            if key in ("fcw", "fsw"):
                got = struct.unpack_from("<H", fx, 0 if key == "fcw" else 2)[0]
            elif key == "ftw":
                got = fx[4]
            elif key == "mxcsr":
                got = struct.unpack_from("<I", fx, 24)[0]
            elif key.startswith("st"):
                got, want = bytes(fx[32 + 16 * int(key[2:]):42 + 16 * int(key[2:])]).hex(), want.replace(" ", "")
            else:
                got, want = bytes(fx[160 + 16 * int(key[3:]):176 + 16 * int(key[3:])]).hex(), want.replace(" ", "")
            c.eq(f"{what}: {key}", got, want)
        if "covered" in exp:
            bits = bytes.fromhex(cov)
            got = [k for k in range(len(f.lines)) if bits[k // 8] >> (k % 8) & 1]
            c.eq(f"{what}: covered instructions", got, sorted(f.index_of(x) if isinstance(x, str) else x for x in exp["covered"]))
        if mode == STEP and tr["step_lines"]:
            c.eq(f"{what}: step trace numbering", [n for n, _ in tr["step_lines"]], list(range(len(tr["step_lines"]))))


def le32(*values: int) -> bytes:
    return b"".join(struct.pack("<I", v & M32) for v in values)


def f32(value: float) -> bytes:
    return struct.pack("<f", value)


def build_core_suite() -> Suite:
    """Integer, control-flow, memory, event and step-mode behaviour (run with the model environment)."""
    s = Suite("core")
    seed = 1
    gpr = init_gpr(seed)

    f = s.fn("arith_ret", """
        31 c9             | xor ecx, ecx
        b8 78 56 34 12    | mov eax, 0x12345678
        05 88 a9 cb ed    | add eax, 0xedcba988
        0f 94 c1          | sete cl
        0f 92 c5          | setb ch
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, a=SENTINEL, b=0, steps=6, mem={}, calls=[], covered=range(6),
             regs={"eax": 0, "ecx": 0x0101, "esp": STACK_TOP + 4, "ebx": gpr[3], "esi": gpr[6], "edi": gpr[7]},
             fx={"fcw": 0x027F, "fsw": 0, "ftw": 0, "mxcsr": 0x1F80, "xmm3": bytes(init_fx(seed)[208:224]).hex()})

    f = s.fn("ret_imm", "c2 08 00 | ret 8")
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=1, regs={"esp": STACK_TOP + 12, "eax": gpr[0]})

    f = s.fn("mem_rw", """
        bf 00 00 00 30          | mov edi, 0x30000000
        c7 07 44 33 22 11       | mov dword ptr [edi], 0x11223344
        66 c7 47 06 cd ab       | mov word ptr [edi + 6], 0xabcd
        c6 47 09 7f             | mov byte ptr [edi + 9], 0x7f
        8b 07                   | mov eax, dword ptr [edi]
        0f b7 5f 06             | movzx ebx, word ptr [edi + 6]
        0f be 4f 09             | movsx ecx, byte ptr [edi + 9]
        8d 54 87 10             | lea edx, [edi + eax*4 + 0x10]
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=9,
             regs={"eax": 0x11223344, "ebx": 0xABCD, "ecx": 0x7F, "edx": 0x7488CD20},
             mem={0x30000000: le32(0x11223344), 0x30000006: b"\xcd\xab", 0x30000009: b"\x7f"})

    f = s.fn("straddle", """
        c7 05 fe 0f 00 30 dd cc bb aa   | mov dword ptr [0x30000ffe], 0xaabbccdd
        a1 fe 0f 00 30                  | mov eax, dword ptr [0x30000ffe]
        66 8b 1d ff 0f 00 30            | mov bx, word ptr [0x30000fff]
        c3                              | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"eax": 0xAABBCCDD, "ebx": (gpr[3] & 0xFFFF0000) | 0xBBCC},
             mem={0x30000FFE: le32(0xAABBCCDD)})

    f = s.fn("frame", """
        55                      | push ebp
        89 e5                   | mov ebp, esp
        83 ec 10                | sub esp, 0x10
        c7 45 fc 2a 00 00 00    | mov dword ptr [ebp - 4], 0x2a
        8b 45 fc                | mov eax, dword ptr [ebp - 4]
        c9                      | leave
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=7, regs={"eax": 0x2A, "ebp": gpr[5], "esp": STACK_TOP + 4},
             mem={STACK_TOP - 4: le32(gpr[5]), STACK_TOP - 8: le32(0x2A)})

    f = s.fn("stack_forms", """
        68 44 33 22 11          | push 0x11223344
        6a ff                   | push -1
        66 6a 05                | push 5
        66 5b                   | pop bx
        59                      | pop ecx
        8f 04 24                | pop dword ptr [esp]
        9c                      | pushfd
        58                      | pop eax
        c3                      | ret
    """)
    # pop [esp] stores the popped dword at the new top of stack, which the ret then takes.
    s.expect(f, kind=T_LEAVE, a=0x11223344, steps=9,
             regs={"ecx": 0xFFFFFFFF, "ebx": (gpr[3] & 0xFFFF0000) | 5, "eax": 0x202, "esp": STACK_TOP + 4},
             mem={STACK_TOP - 4: le32(0x202), STACK_TOP - 8: le32(0xFFFFFFFF), STACK_TOP - 10: b"\x05\x00",
                  STACK_TOP: le32(0x11223344)})

    # ---- faults leave the pre-instruction state --------------------------------------
    f = s.fn("fault_rmw", """
        b8 01 00 00 00    | mov eax, 1
        bb 00 00 00 70    | mov ebx, 0x70000000
        @f: 01 03         | add dword ptr [ebx], eax
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x70000000, steps=2, regs={"eax": 1, "esp": STACK_TOP}, mem={},
             covered=[0, 1, 2])

    f = s.fn("fault_push", """
        bc 00 00 00 20    | mov esp, 0x20000000
        @f: 50            | push eax
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x1FFFFFFC, steps=1, regs={"esp": 0x20000000}, mem={})

    f = s.fn("fault_straddle", """
        b8 44 33 22 11          | mov eax, 0x11223344
        @f: a3 fe ff ff 5f      | mov dword ptr [0x5ffffffe], eax
        c3                      | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x60000000, steps=1, mem={})

    f = s.fn("fault_pop_mem", """
        bb 00 00 00 70    | mov ebx, 0x70000000
        @f: 8f 03         | pop dword ptr [ebx]
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x70000000, steps=1, regs={"esp": STACK_TOP}, mem={})

    f = s.fn("fault_xchg", """
        b9 05 00 00 00    | mov ecx, 5
        bb fe ff ff 5f    | mov ebx, 0x5ffffffe
        @f: 87 0b         | xchg dword ptr [ebx], ecx
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x60000000, regs={"ecx": 5}, mem={})

    f = s.fn("fault_low", """
        31 c0             | xor eax, eax
        @f: 8b 40 08      | mov eax, dword ptr [eax + 8]
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=8, steps=1, regs={"eax": 0})

    f = s.fn("fault_ret", """
        bc 00 00 00 70    | mov esp, 0x70000000
        @f: c3            | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x70000000, steps=1, regs={"esp": 0x70000000})

    f = s.fn("foreign", """
        @f: a1 00 00 40 00    | mov eax, dword ptr [0x400000]
        c3                    | ret
    """)
    s.expect(f, status=S_FOREIGN)

    f = s.fn("addr16", """
        bb 78 56 34 12    | mov ebx, 0x12345678
        @f: 67 8b 07      | mov eax, dword ptr [bx]
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x5678, steps=1)

    # ---- string instructions ----------------------------------------------------------
    f = s.fn("rep_movs_fault", """
        be f8 ff ff 5f    | mov esi, 0x5ffffff8
        bf 00 00 00 30    | mov edi, 0x30000000
        b9 04 00 00 00    | mov ecx, 4
        @f: f3 a5         | rep movsd dword ptr es:[edi], dword ptr [esi]
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x60000000, steps=5,
             regs={"ecx": 2, "esi": 0x60000000, "edi": 0x30000008},
             mem={0x30000000: le32(fill_dword(seed, 0x5FFFFFF8), fill_dword(seed, 0x5FFFFFFC))})

    f = s.fn("rep_stos_down", """
        fd                | std
        bf 0c 00 00 30    | mov edi, 0x3000000c
        b8 dd cc bb aa    | mov eax, 0xaabbccdd
        b9 03 00 00 00    | mov ecx, 3
        f3 ab             | rep stosd dword ptr es:[edi], eax
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=8, df=1, regs={"edi": 0x30000000, "ecx": 0},
             mem={0x30000004: le32(0xAABBCCDD) * 3})

    f = s.fn("strlen", """
        bf 00 01 00 30          | mov edi, 0x30000100
        c7 07 61 62 63 64       | mov dword ptr [edi], 0x64636261
        c7 47 04 65 00 66 67    | mov dword ptr [edi + 4], 0x67660065
        30 c0                   | xor al, al
        b9 ff ff ff ff          | mov ecx, 0xffffffff
        f2 ae                   | repne scasb al, byte ptr es:[edi]
        f7 d1                   | not ecx
        49                      | dec ecx
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=14, regs={"ecx": 5, "edi": 0x30000106})

    f = s.fn("memcmp", """
        31 c0                   | xor eax, eax
        be 00 02 00 30          | mov esi, 0x30000200
        bf 00 03 00 30          | mov edi, 0x30000300
        c7 06 41 42 43 44       | mov dword ptr [esi], 0x44434241
        c7 07 41 42 58 44       | mov dword ptr [edi], 0x44584241
        b9 04 00 00 00          | mov ecx, 4
        f3 a6                   | repe cmpsb byte ptr [esi], byte ptr es:[edi]
        0f 97 c0                | seta al
        0f 92 c4                | setb ah
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=12, regs={"eax": 0x0100, "ecx": 1, "esi": 0x30000203, "edi": 0x30000303})

    f = s.fn("rep_zero", """
        31 c9             | xor ecx, ecx
        f3 a4             | rep movsb byte ptr es:[edi], byte ptr [esi]
        f3 ab             | rep stosd dword ptr es:[edi], eax
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=4, mem={}, regs={"esi": gpr[6], "edi": gpr[7]})

    f = s.fn("lods", """
        be 00 04 00 30          | mov esi, 0x30000400
        c7 06 78 56 34 12       | mov dword ptr [esi], 0x12345678
        31 c0                   | xor eax, eax
        ac                      | lodsb al, byte ptr [esi]
        66 ad                   | lodsw ax, word ptr [esi]
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"eax": 0x3456, "esi": 0x30000403})

    f = s.fn("movs_single", """
        be 00 04 00 30          | mov esi, 0x30000400
        bf 00 05 00 30          | mov edi, 0x30000500
        c7 06 78 56 34 12       | mov dword ptr [esi], 0x12345678
        a5                      | movsd dword ptr es:[edi], dword ptr [esi]
        66 a5                   | movsw word ptr es:[edi], word ptr [esi]
        a4                      | movsb byte ptr es:[edi], byte ptr [esi]
        c3                      | ret
    """)
    tail = le32(fill_dword(seed, 0x30000404))
    s.expect(f, kind=T_LEAVE, steps=7, regs={"esi": 0x30000407, "edi": 0x30000507},
             mem={0x30000400: le32(0x12345678), 0x30000500: le32(0x12345678) + tail[:3]})

    # ---- control flow and events --------------------------------------------------------
    f = s.fn("inbody_call", """
        e8 {rel32:@L}           | call {@L}
        c3                      | ret
        @L: b8 05 00 00 00      | mov eax, 5
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=4, calls=[], regs={"eax": 5, "esp": STACK_TOP + 4},
             mem={STACK_TOP - 4: le32(f.addr + 5)}, covered=[0, 1, 2, 3])

    callee = s.fn("callee_stdcall_fp", "c2 08 00 | ret 8", pop_bytes=8, fp_ret=True)
    f = s.fn("call_events", """
        bf 00 05 00 30          | mov edi, 0x30000500
        68 22 22 00 00          | push 0x2222
        68 11 11 00 00          | push 0x1111
        e8 {rel32:callee_stdcall_fp} | call {callee_stdcall_fp}
        @r1: d9 1f              | fstp dword ptr [edi]
        89 c6                   | mov esi, eax
        ff d1                   | call ecx
        @r2: c3                 | ret
    """)
    for sd in (1, 2, 3):
        stub0, stub1 = stub_call_regs(sd, 0), stub_call_regs(sd, 1)
        stack0 = [0x1111, 0x2222, SENTINEL] + [fill_dword(sd, STACK_TOP + 4 * k) for k in range(1, 6)]
        stack1 = [SENTINEL] + [fill_dword(sd, STACK_TOP + 4 * k) for k in range(1, 8)]
        s.expect(f, seed=sd, kind=T_LEAVE, a=SENTINEL, steps=8,
                 calls=[{"target": callee.addr, "site": f.at("@r1"), "stack": stack0,
                         "regs": {"esp": STACK_TOP - 12, "edi": 0x30000500, "eax": init_gpr(sd)[0]}},
                        {"target": stub0[1], "site": f.at("@r2"), "stack": stack1,
                         "regs": {"esp": STACK_TOP - 4, "esi": stub0[0], "ecx": stub0[1], "edx": stub0[2]}}],
                 regs={"eax": stub1[0], "ecx": stub1[1], "edx": stub1[2], "esi": stub0[0], "esp": STACK_TOP + 4},
                 mem={0x30000500: f32(stub_call_st0(sd, 0)), STACK_TOP - 4: le32(f.at("@r2")),
                      STACK_TOP - 8: le32(0x1111), STACK_TOP - 12: le32(f.at("@r1"))},
                 fx={"ftw": 0, "fsw": 0})

    f = s.fn("tail_jmp", "e9 {rel32:callee_stdcall_fp} | jmp {callee_stdcall_fp}")
    s.expect(f, kind=T_LEAVE, a=callee.addr, steps=1, calls=[], regs={"esp": STACK_TOP})

    f = s.fn("jump_table", """
        b8 01 00 00 00              | mov eax, 1
        ff 24 85 {abs32:JT}         | jmp dword ptr [eax*4 + {JT}]
        @c0: bb 0a 00 00 00         | mov ebx, 0xa
        c3                          | ret
        @c1: bb 0b 00 00 00         | mov ebx, 0xb
        c3                          | ret
    """)
    s.synth.table("JT", [f.at("@c0"), f.at("@c1")])
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=4, regs={"ebx": 0xB}, covered=[0, 1, 4, 5])

    f = s.fn("stubbed_insns", """
        0f a2             | cpuid
        89 c6             | mov esi, eax
        @t: 0f 31         | rdtsc
        c3                | ret
    """)
    first, second = stub_insn_regs(seed, 0), stub_insn_regs(seed, 1)
    s.expect(f, kind=T_LEAVE, steps=4, insns=[(1, f.addr), (2, f.at("@t"))],
             regs={"eax": second[0], "edx": second[3], "ebx": first[1], "ecx": first[2], "esi": first[0]})

    f = s.fn("trap", """
        90                | nop
        @f: cd 2e         | int 0x2e
        c3                | ret
    """)
    s.expect(f, kind=T_EXC, a=f.at("@f"), b=X_TRAP, steps=1, insns=[])
    for name, code, text, cls in (("int3", "cc", "int3", X_BKPT), ("ud2", "0f 0b", "ud2", X_ILL), ("hlt", "f4", "hlt", X_PRIV)):
        f = s.fn(name, f"90 | nop\n @f: {code} | {text}\n c3 | ret")
        s.expect(f, kind=T_EXC, a=f.at("@f"), b=cls, steps=1, regs={"esp": STACK_TOP})

    f = s.fn("div_zero", """
        b8 0a 00 00 00    | mov eax, 0xa
        31 d2             | xor edx, edx
        31 c9             | xor ecx, ecx
        @f: f7 f1         | div ecx
        c3                | ret
    """)
    s.expect(f, kind=T_EXC, a=f.at("@f"), b=X_DIV, steps=3, regs={"eax": 10, "edx": 0})

    f = s.fn("idiv_overflow", """
        b8 00 00 00 80    | mov eax, 0x80000000
        ba ff ff ff ff    | mov edx, 0xffffffff
        b9 ff ff ff ff    | mov ecx, 0xffffffff
        @f: f7 f9         | idiv ecx
        c3                | ret
    """)
    s.expect(f, kind=T_EXC, a=f.at("@f"), b=X_DIV, regs={"eax": 0x80000000, "edx": 0xFFFFFFFF})

    f = s.fn("bit_and_atomic", """
        31 db                   | xor ebx, ebx
        bf 00 0d 00 30          | mov edi, 0x30000d00
        c7 07 01 00 00 00       | mov dword ptr [edi], 1
        b8 20 00 00 00          | mov eax, 0x20
        0f ab 07                | bts dword ptr [edi], eax
        0f 92 c3                | setb bl
        b9 05 00 00 00          | mov ecx, 5
        87 0f                   | xchg dword ptr [edi], ecx
        f0 0f c1 0f             | lock xadd dword ptr [edi], ecx
        b8 06 00 00 00          | mov eax, 6
        ba 09 00 00 00          | mov edx, 9
        f0 0f b1 17             | lock cmpxchg dword ptr [edi], edx
        c3                      | ret
    """)
    word1 = fill_dword(seed, 0x30000D04)
    s.expect(f, kind=T_LEAVE, steps=13, regs={"ebx": word1 & 1, "ecx": 5, "eax": 6, "edx": 9},
             mem={0x30000D00: le32(9, word1 | 1)})

    # ---- FS and the TEB page --------------------------------------------------------------
    f = s.fn("fs_access", """
        b9 44 33 22 11              | mov ecx, 0x11223344
        64 a1 18 00 00 00           | mov eax, dword ptr fs:[0x18]
        64 8b 1d 30 00 00 00        | mov ebx, dword ptr fs:[0x30]
        64 89 0d 00 07 00 00        | mov dword ptr fs:[0x700], ecx
        64 8b 35 00 07 00 00        | mov esi, dword ptr fs:[0x700]
        8d 78 04                    | lea edi, [eax + 4]
        8b 3f                       | mov edi, dword ptr [edi]
        c3                          | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=8, regs={"eax": MODEL_TEB, "ebx": 0x5FC00000, "esi": 0x11223344, "edi": ARENA_HI},
             mem={MODEL_TEB + 0x700: le32(0x11223344)})

    # Segment registers read as the selectors of a 32-bit thread on 64-bit Windows.
    f = s.fn("segment_read", """
        8c d8             | mov eax, ds
        8c cb             | mov ebx, cs
        66 8c e1          | mov cx, fs
        bf 00 0e 00 30    | mov edi, 0x30000e00
        8c 17             | mov word ptr [edi], ss
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=6, regs={"eax": 0x2B, "ebx": 0x23, "ecx": (gpr[1] & 0xFFFF0000) | 0x53},
             mem={0x30000E00: b"\x2b\x00"})

    # ---- step mode --------------------------------------------------------------------------
    f = s.fn("loop", """
        b9 03 00 00 00    | mov ecx, 3
        @L: 49            | dec ecx
        @J: 75 {rel8:@L}  | jne {@L}
        @R: c3            | ret
    """)
    s.expect(f, kind=T_LEAVE, a=SENTINEL, steps=8, regs={"ecx": 0})
    s.expect(f, mode=STEP, budget=100, kind=T_LEAVE, a=SENTINEL, steps=8)
    s.expect(f, mode=STEP, budget=8, kind=T_LEAVE, a=SENTINEL, steps=8)
    s.expect(f, mode=STEP, budget=7, kind=T_STEP, a=f.at("@R"), b=0, steps=7, regs={"ecx": 0, "esp": STACK_TOP})
    s.expect(f, mode=STEP, budget=4, kind=T_STEP, a=f.at("@J"), steps=4, regs={"ecx": 1})
    s.expect(f, mode=STEP, budget=1, kind=T_STEP, a=f.at("@L"), steps=1, regs={"ecx": 3})
    # The budget is looked at after a step, so a budget of 0 behaves like 1.
    s.expect(f, mode=STEP, budget=0, kind=T_STEP, a=f.at("@L"), steps=1, regs={"ecx": 3})

    f = s.fn("rep_steps", """
        bf 00 06 00 30    | mov edi, 0x30000600
        b9 05 00 00 00    | mov ecx, 5
        b0 5a             | mov al, 0x5a
        @S: f3 aa         | rep stosb byte ptr es:[edi], al
        @R: c3            | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=9, mem={0x30000600: b"\x5a" * 5})
    s.expect(f, mode=STEP, budget=5, kind=T_STEP, a=f.at("@S"), steps=5, regs={"ecx": 3, "edi": 0x30000602},
             mem={0x30000600: b"\x5a" * 2})
    s.expect(f, mode=STEP, budget=8, kind=T_STEP, a=f.at("@R"), steps=8, regs={"ecx": 0}, mem={0x30000600: b"\x5a" * 5})

    f = s.fn("step_call", """
        e8 {rel32:callee_stdcall_fp}  | call {callee_stdcall_fp}
        @r: c3                        | ret
    """)
    stub0 = stub_call_regs(seed, 0)
    one_call = [{"target": callee.addr, "site": f.at("@r")}]
    # The stub pops the return address and the callee's 8 bytes, so the ret takes the dword at STACK_TOP + 8.
    after = fill_dword(seed, STACK_TOP + 8)
    s.expect(f, mode=STEP, budget=1, kind=T_STEP, a=f.at("@r"), steps=1, calls=one_call,
             regs={"eax": stub0[0], "esp": STACK_TOP + 8}, fx={"ftw": 0x80, "fsw": 0x3800})
    s.expect(f, mode=STEP, budget=2, kind=T_LEAVE, a=after, steps=2, calls=one_call, regs={"esp": STACK_TOP + 12})

    f = s.fn("step_fault", """
        bb 00 00 00 70    | mov ebx, 0x70000000
        @f: 8b 03         | mov eax, dword ptr [ebx]
        c3                | ret
    """)
    s.expect(f, mode=STEP, budget=5, kind=T_FAULT, a=f.at("@f"), b=0x70000000, steps=1)
    return s


def build_fp_suite() -> Suite:
    """x87, MMX and SSE instructions through host thunks."""
    s = Suite("fp", min_thunks=40)
    seed = 1
    gpr = init_gpr(seed)

    f = s.fn("x87_basic", """
        bf 00 07 00 30    | mov edi, 0x30000700
        d9 e8             | fld1
        d9 e8             | fld1
        de c1             | faddp st(1)
        db 1f             | fistp dword ptr [edi]
        d9 e8             | fld1
        d9 5f 04          | fstp dword ptr [edi + 4]
        d9 eb             | fldpi
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=9, mem={0x30000700: le32(2) + f32(1.0)},
             fx={"fcw": 0x027F, "fsw": 0x3800, "ftw": 0x80, "st0": "35c26821a2da0fc90040", "st1": "00" * 10})

    f = s.fn("x87_straddle", """
        d9 e8                   | fld1
        dd 1d fc 0f 00 30       | fstp qword ptr [0x30000ffc]
        dd 05 fc 0f 00 30       | fld qword ptr [0x30000ffc]
        d9 1d 00 20 00 30       | fstp dword ptr [0x30002000]
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, mem={0x30000FFC: struct.pack("<d", 1.0), 0x30002000: f32(1.0)}, fx={"ftw": 0, "fsw": 0})

    f = s.fn("x87_fault", """
        d9 e8                   | fld1
        @f: dd 1d fc ff ff 5f   | fstp qword ptr [0x5ffffffc]
        c3                      | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x60000000, steps=1, mem={}, fx={"ftw": 0x80, "fsw": 0x3800})

    f = s.fn("x87_compare", """
        31 c0             | xor eax, eax
        d9 e8             | fld1
        d9 ee             | fldz
        df f1             | fcompi st(1)
        0f 92 c0          | setb al
        0f 94 c4          | sete ah
        dd d8             | fstp st(0)
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"eax": 0x0001}, fx={"ftw": 0, "fsw": 0})

    f = s.fn("x87_status", """
        31 c0             | xor eax, eax
        d9 e8             | fld1
        d9 ee             | fldz
        d8 d1             | fcom st(1)
        df e0             | fnstsw ax
        9b                | wait
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"eax": 0x3100}, fx={"ftw": 0xC0, "fsw": 0x3100})

    f = s.fn("x87_cmov", """
        d9 e8             | fld1
        d9 ee             | fldz
        f9                | stc
        da c1             | fcmovb st(0), st(1)
        bf 00 07 00 30    | mov edi, 0x30000700
        d9 1f             | fstp dword ptr [edi]
        f8                | clc
        d9 ee             | fldz
        da c1             | fcmovb st(0), st(1)
        d9 5f 04          | fstp dword ptr [edi + 4]
        dd d8             | fstp st(0)
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, mem={0x30000700: f32(1.0) + f32(0.0)}, fx={"ftw": 0})

    f = s.fn("x87_unmasked", """
        bf 00 08 00 30          | mov edi, 0x30000800
        66 c7 07 7b 02          | mov word ptr [edi], 0x27b
        d9 2f                   | fldcw word ptr [edi]
        d9 e8                   | fld1
        d9 ee                   | fldz
        de f9                   | fdivp st(1)
        @w: d9 e8               | fld1
        c3                      | ret
    """)
    s.expect(f, kind=T_EXC, a=f.at("@w"), b=X_FP, steps=6, fx={"fcw": 0x027B, "ftw": 0xC0})

    callee = s.fn("callee_fp", "c3 | ret", fp_ret=True)
    f = s.fn("fp_return", """
        bf 00 09 00 30          | mov edi, 0x30000900
        d9 e8                   | fld1
        e8 {rel32:callee_fp}    | call {callee_fp}
        @r: de c1               | faddp st(1)
        d9 1f                   | fstp dword ptr [edi]
        c3                      | ret
    """)
    for sd in (1, 2, 3, 4):
        s.expect(f, seed=sd, kind=T_LEAVE, a=SENTINEL, steps=6, mem={0x30000900: f32(1.0 + stub_call_st0(sd, 0)),
                                                                  STACK_TOP - 4: le32(f.at("@r"))}, fx={"ftw": 0})

    f = s.fn("mmx", """
        b8 03 00 00 00    | mov eax, 3
        0f 6e c0          | movd mm0, eax
        0f fe c0          | paddd mm0, mm0
        0f 7e c3          | movd ebx, mm0
        bf 00 0a 00 30    | mov edi, 0x30000a00
        0f 7f 07          | movq qword ptr [edi], mm0
        0f fe 07          | paddd mm0, qword ptr [edi]
        0f 7e c1          | movd ecx, mm0
        0f 77             | emms
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"ebx": 6, "ecx": 12}, mem={0x30000A00: le32(6, 0)}, fx={"ftw": 0})

    f = s.fn("sse_scalar", """
        31 c9             | xor ecx, ecx
        b8 00 00 80 3f    | mov eax, 0x3f800000
        66 0f 6e c0       | movd xmm0, eax
        b8 00 00 00 40    | mov eax, 0x40000000
        66 0f 6e c8       | movd xmm1, eax
        f3 0f 58 c1       | addss xmm0, xmm1
        66 0f 7e c3       | movd ebx, xmm0
        0f 2f c1          | comiss xmm0, xmm1
        0f 97 c1          | seta cl
        0f 9a c5          | setp ch
        f3 0f 2c f0       | cvttss2si esi, xmm0
        0f 50 e8          | movmskps ebp, xmm0
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=13, regs={"ebx": 0x40400000, "ecx": 1, "esi": 3, "ebp": 0, "edi": gpr[7]},
             fx={"xmm0": "00004040" + "00" * 12, "xmm1": "00000040" + "00" * 12, "mxcsr": 0x1F80,
                 "xmm7": bytes(init_fx(seed)[272:288]).hex()})

    f = s.fn("sse_unordered", """
        31 c9             | xor ecx, ecx
        b8 00 00 c0 7f    | mov eax, 0x7fc00000
        66 0f 6e c0       | movd xmm0, eax
        f9                | stc
        0f 2e c0          | ucomiss xmm0, xmm0
        0f 9a c1          | setp cl
        0f 94 c5          | sete ch
        0f 92 c2          | setb dl
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"ecx": 0x0101, "edx": (gpr[2] & 0xFFFFFF00) | 1}, fx={"mxcsr": 0x1F80})

    f = s.fn("sse_gprs", """
        b8 01 00 00 00    | mov eax, 1
        66 0f 6e c0       | movd xmm0, eax
        66 0f 7e c1       | movd ecx, xmm0
        41                | inc ecx
        66 0f 6e c9       | movd xmm1, ecx
        66 0f 7e ca       | movd edx, xmm1
        42                | inc edx
        66 0f 6e d2       | movd xmm2, edx
        66 0f 7e d3       | movd ebx, xmm2
        43                | inc ebx
        66 0f 6e db       | movd xmm3, ebx
        66 0f 7e dd       | movd ebp, xmm3
        45                | inc ebp
        66 0f 6e e5       | movd xmm4, ebp
        66 0f 7e e6       | movd esi, xmm4
        46                | inc esi
        66 0f 6e ee       | movd xmm5, esi
        66 0f 7e ef       | movd edi, xmm5
        47                | inc edi
        66 0f 6e f7       | movd xmm6, edi
        66 0f 6e f8       | movd xmm7, eax
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=22,
             regs={"eax": 1, "ecx": 2, "edx": 3, "ebx": 4, "ebp": 5, "esi": 6, "edi": 7, "esp": STACK_TOP + 4},
             fx={f"xmm{n}": le32(v, 0, 0, 0).hex() for n, v in enumerate((1, 2, 3, 4, 5, 6, 7, 1))})

    f = s.fn("sse_memory", """
        b8 44 33 22 11          | mov eax, 0x11223344
        66 0f 6e c0             | movd xmm0, eax
        66 0f 70 c0 00          | pshufd xmm0, xmm0, 0
        bf 00 0b 00 30          | mov edi, 0x30000b00
        0f 29 07                | movaps xmmword ptr [edi], xmm0
        0f 11 05 fa 0f 00 30    | movups xmmword ptr [0x30000ffa], xmm0
        0f 10 0d fa 0f 00 30    | movups xmm1, xmmword ptr [0x30000ffa]
        66 0f 7e cb             | movd ebx, xmm1
        66 0f fe 07             | paddd xmm0, xmmword ptr [edi]
        66 0f 7e c1             | movd ecx, xmm0
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, regs={"ebx": 0x11223344, "ecx": 0x22446688},
             mem={0x30000B00: le32(0x11223344) * 4, 0x30000FFA: le32(0x11223344) * 4})

    f = s.fn("sse_misaligned", """
        bf 01 00 00 30    | mov edi, 0x30000001
        @f: 0f 28 07      | movaps xmm0, xmmword ptr [edi]
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0xFFFFFFFF, steps=1, regs={"edi": 0x30000001},
             fx={"xmm0": bytes(init_fx(seed)[160:176]).hex()})

    f = s.fn("sse_misaligned_store", """
        bf 08 00 00 30    | mov edi, 0x30000008
        @f: 66 0f 7f 07   | movdqa xmmword ptr [edi], xmm0
        c3                | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0xFFFFFFFF, steps=1, mem={})

    f = s.fn("sse_page_fault", """
        @f: 0f 10 05 f8 ff ff 5f    | movups xmm0, xmmword ptr [0x5ffffff8]
        c3                          | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x60000000, steps=0)

    f = s.fn("sse_convert_memory", """
        bf 00 0c 00 30          | mov edi, 0x30000c00
        c7 07 00 00 20 41       | mov dword ptr [edi], 0x41200000
        f3 0f 2c 37             | cvttss2si esi, dword ptr [edi]
        f3 0f 2c 1f             | cvttss2si ebx, dword ptr [edi]
        f3 0f 2a 07             | cvtsi2ss xmm0, dword ptr [edi]
        66 0f 2f 47 02          | comisd xmm0, xmmword ptr [edi + 2]
        f3 0f 2c 3f             | cvttss2si edi, dword ptr [edi]
        c3                      | ret
    """)
    s.expect(f, kind=T_LEAVE, steps=8, regs={"esi": 10, "ebx": 10, "edi": 10},
             fx={"xmm0": (struct.pack("<f", float(0x41200000)) + bytes(init_fx(seed)[164:176])).hex()})

    f = s.fn("sse_unmasked", """
        bf 00 0d 00 30          | mov edi, 0x30000d00
        c7 07 80 1d 00 00       | mov dword ptr [edi], 0x1d80
        0f ae 17                | ldmxcsr dword ptr [edi]
        b8 00 00 80 3f          | mov eax, 0x3f800000
        66 0f 6e c0             | movd xmm0, eax
        0f 57 c9                | xorps xmm1, xmm1
        @f: f3 0f 5e c1         | divss xmm0, xmm1
        c3                      | ret
    """)
    s.expect(f, kind=T_EXC, a=f.at("@f"), b=X_FP, steps=6, fx={"xmm0": "0000803f" + "00" * 12, "xmm1": "00" * 16})

    f = s.fn("mxcsr", """
        bf 00 0e 00 30          | mov edi, 0x30000e00
        0f ae 1f                | stmxcsr dword ptr [edi]
        c7 47 04 00 00 01 00    | mov dword ptr [edi + 4], 0x10000
        @f: 0f ae 57 04         | ldmxcsr dword ptr [edi + 4]
        c3                      | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0xFFFFFFFF, steps=3,
             mem={0x30000E00: le32(0x1F80, 0x10000)}, fx={"mxcsr": 0x1F80})

    # The trial after the faulting ones must start from a clean host state again.
    f = s.fn("after_faults", """
        d9 e8             | fld1
        d9 e8             | fld1
        de c1             | faddp st(1)
        bf 00 0f 00 30    | mov edi, 0x30000f00
        d9 1f             | fstp dword ptr [edi]
        0f ae 5f 04       | stmxcsr dword ptr [edi + 4]
        c3                | ret
    """)
    s.expect(f, kind=T_LEAVE, mem={0x30000F00: f32(2.0) + le32(0x1F80)}, fx={"fcw": 0x027F, "fsw": 0, "ftw": 0})
    return s


def build_noenv_suite() -> Suite:
    """Without an environment file there is no TEB page and nothing is foreign."""
    s = Suite("noenv")
    f = s.fn("fs_fault", """
        @f: 64 a1 18 00 00 00    | mov eax, dword ptr fs:[0x18]
        c3                       | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x18, steps=0)
    f = s.fn("low_fault", """
        @f: a1 00 00 40 00    | mov eax, dword ptr [0x400000]
        c3                    | ret
    """)
    s.expect(f, kind=T_FAULT, a=f.at("@f"), b=0x400000, steps=0)
    return s


def stage_synthetic(c: Checker, args, report: dict) -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    n_cases = 0
    for build, with_env in ((build_core_suite, True), (build_fp_suite, True), (build_noenv_suite, False)):
        suite = build()
        env = WORK / f"{suite.synth.name}.env"
        teb = write_env(env, len(suite.synth.buf)) if with_env else None
        suite.run(c, env if with_env else None, teb)
        n_cases += len(suite.cases)
        print(f"  {suite.synth.name}: {len(suite.synth.fns)} functions, {len(suite.cases)} trials")
    report["synthetic_trials"] = n_cases


# ---- stage: real image -----------------------------------------------------------------------------


def stage_real(c: Checker, args, report: dict) -> None:
    functions = image_mod.load_functions()
    step = max(1, len(functions) // args.functions)
    entries = [f.addr for f in functions[::step]][:args.functions]
    trials = {e: [(meta_mod.seed_for(e, n), FAST, 0) for n in range(args.seeds)] for e in entries}
    out_dir = WORK / "real"
    batch = build_batch.build_batch(entries, out_dir, trials)
    n_insn = sum(f.n_insn for f in batch.functions.values())
    t = batch.timings
    report["real"] = {
        "functions": len(entries), "instructions": n_insn, "thunks": batch.n_thunks, "trials": len(entries) * args.seeds,
        "lift_seconds": round(t["lift"], 2), "lift_functions_per_s": round(len(entries) / t["lift"]),
        "lift_instructions_per_s": round(n_insn / t["lift"]), "compile_seconds": round(t["compile"], 2),
        "link_seconds": round(t["link"], 2),
        "fully_translated": sum(1 for f in batch.functions.values() if not f.unsupported),
    }
    print(f"  batch: {len(entries)} functions, {n_insn} instructions, {batch.n_thunks} thunks; lift {t['lift']:.2f}s, "
          f"compile {t['compile']:.2f}s, link {t['link']:.2f}s")

    image = image_mod.flat_image_path()
    env = WORK / "real.env"
    write_env(env, (image.stat().st_size + PAGE - 1) & ~(PAGE - 1))
    outputs = []
    for n in (1, 2):
        out = out_dir / f"results{n}.txt"
        t0 = time.perf_counter()
        proc = run([batch.runner, "--image", image, "--jobs", batch.job_file, "--env", env, "--out", out,
                    "--cov", out_dir / f"cov{n}.txt"])
        seconds = time.perf_counter() - t0
        if not c.eq(f"real run {n}: exit status", proc.returncode, 0):
            print(proc.stderr[-2000:])
            return
        outputs.append(out.read_bytes())
        print(f"  run {n}: {proc.stderr.strip().splitlines()[-1]}")
        report["real"][f"run{n}_seconds"] = round(seconds, 2)
    c.ok("real: two runs give identical result files", outputs[0] == outputs[1])
    c.ok("real: two runs give identical coverage files",
         (out_dir / "cov1.txt").read_bytes() == (out_dir / "cov2.txt").read_bytes())
    rows = [line.split() for line in outputs[0].decode().splitlines()]
    c.eq("real: result lines", len(rows), len(entries) * args.seeds)
    status = collections.Counter(int(r[3]) for r in rows)
    kinds = collections.Counter(int(r[4]) for r in rows if r[3] == "0")
    c.eq("real: harness failures", status[S_HARNESS], 0)
    covered = total = executed = 0
    for row in (line.split() for line in (out_dir / "cov1.txt").read_text().splitlines()):
        if row[0] == "F":
            total += int(row[2])
            covered += int(row[3])
        else:
            executed += int(row[4])
    report["real"].update(status={str(k): v for k, v in sorted(status.items())},
                          terminal_kinds={str(k): v for k, v in sorted(kinds.items())},
                          instruction_coverage=round(covered / max(total, 1), 4), instructions_executed=executed)
    print(f"  status {dict(sorted(status.items()))}, terminal kinds {dict(sorted(kinds.items()))}, "
          f"instructions reached {covered}/{total}, executed {executed}")

    # Which instructions the lifter does not translate, over the whole inventory.
    t0 = time.perf_counter()
    hist, reasons = collections.Counter(), collections.Counter()
    n_insn = clean = 0
    thunks = set()
    for lifted, _ in build_batch.lift_many([f.addr for f in functions], keep_code=False):
        n_insn += lifted.n_insn
        clean += not lifted.unsupported
        thunks.update(lifted.thunks)
        for _, mnemonic, _, reason in lifted.unsupported:
            hist[mnemonic] += 1
            reasons[reason] += 1
    seconds = time.perf_counter() - t0
    report["population"] = {
        "functions": len(functions), "instructions": n_insn, "seconds": round(seconds, 1),
        "functions_per_s": round(len(functions) / seconds), "instructions_per_s": round(n_insn / seconds),
        "fully_translated": clean, "fully_translated_fraction": round(clean / len(functions), 6),
        "distinct_thunks": len(thunks), "unsupported_mnemonics": dict(hist.most_common()),
        "unsupported_reasons": dict(reasons.most_common()),
    }
    print(f"  inventory: {len(functions)} functions, {n_insn} instructions lifted in {seconds:.1f}s; "
          f"{clean} ({100.0 * clean / len(functions):.3f}%) fully translated")
    print(f"  not translated: {dict(hist.most_common())}")


STAGES = {"flags": stage_flags, "vectors": stage_vectors, "synthetic": stage_synthetic, "real": stage_real}


def main() -> int:
    ap = argparse.ArgumentParser(description="Self-test of the lifted side.")
    ap.add_argument("--only", choices=sorted(STAGES), action="append", help="run only this stage (repeatable)")
    ap.add_argument("--no-real", action="store_true", help="skip the stage that needs the game image")
    ap.add_argument("--flag-iters", type=int, default=20000, help="random operand sets per flag-helper family")
    ap.add_argument("--vectors", type=int, default=6000, help="instruction vectors against the host")
    ap.add_argument("--functions", type=int, default=2000, help="functions of the game image in the real stage")
    ap.add_argument("--seeds", type=int, default=4, help="trials per function in the real stage")
    args = ap.parse_args()
    stages = args.only or [s for s in STAGES if not (args.no_real and s == "real")]
    if "real" in stages and not image_mod.IMAGE_PATH.exists():
        print("game image not present: skipping the real stage")
        stages.remove("real")

    c = Checker()
    report: dict = {}
    ok = True
    for name in STAGES:
        if name not in stages:
            continue
        since = len(c.failures)
        t0 = time.perf_counter()
        try:
            STAGES[name](c, args, report)
        except toolchain.BuildError as error:
            c.ok(f"{name}: build\n{str(error)[:3000]}", False)
        ok &= c.report(f"{name} {time.perf_counter() - t0:.1f}s", since)
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="ascii", newline="\n")
    print(f"{c.checks} checks, {len(c.failures)} failures")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
