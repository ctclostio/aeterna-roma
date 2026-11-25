"""No-ops, flag-bit instructions and instructions that always raise."""
from __future__ import annotations

from .base import op


@op("nop", "pause", "endbr32", "prefetch", "prefetchw", "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2",
    "prefetchwt1")
def nop(e, i):
    # Multi-byte nops and prefetch hints carry a memory operand that is never accessed.
    pass


@op("cld")
def cld(e, i):
    e.line("c->df = 0u;")


@op("std")
def std(e, i):
    e.line("c->df = 1u;")


@op("clc")
def clc(e, i):
    e.line("c->cf = 0u;")


@op("stc")
def stc(e, i):
    e.line("c->cf = 1u;")


@op("cmc")
def cmc(e, i):
    e.line("c->cf ^= 1u;")


def _raises(cls):
    def handler(e, i):
        e.line(f"lift_exc(c, {cls});")
        e.fallthrough = False
    return handler


op("int3")(_raises("LM_X_BKPT"))
op("ud2", "ud0", "ud1")(_raises("LM_X_ILL"))
# At CPL 3 with IOPL 0 these raise #GP, which Windows reports as a privileged instruction.
op("hlt", "cli", "sti", "in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd")(_raises("LM_X_PRIV"))
