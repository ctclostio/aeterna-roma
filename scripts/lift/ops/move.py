"""Moves, extensions, lea, xchg, cmovcc, sign-extension of the accumulator,
lahf/sahf."""
from __future__ import annotations

from capstone import x86_const as X

from .base import (CC_NAMES, EAX, EBX, EDX, OP_MEM, OP_REG, SEG_PREFIX_FS, Unsupported, cc_expr, ea, op, rd, reg_wr,
                   wr)


# Selectors of a 32-bit thread on 64-bit Windows, where the reference runs.
# They are fixed by the system's descriptor table, not by the process.
SEGMENT_SELECTOR = {X.X86_REG_CS: 0x23, X.X86_REG_SS: 0x2B, X.X86_REG_DS: 0x2B, X.X86_REG_ES: 0x2B,
                    X.X86_REG_FS: 0x53, X.X86_REG_GS: 0x2B}


@op("mov")
def mov(e, i):
    dst, src = i.ops
    if src.type == OP_REG and src.reg in SEGMENT_SELECTOR:
        # A memory destination takes 16 bits; a 32-bit register is zero extended.
        e.line(wr(i, dst, f"0x{SEGMENT_SELECTOR[src.reg]:x}u"))
        return
    e.line(wr(i, dst, rd(i, src, dst.size)))


@op("movzx")
def movzx(e, i):
    dst, src = i.ops
    e.line(reg_wr(dst.reg, rd(i, src)))


@op("movsx")
def movsx(e, i):
    dst, src = i.ops
    if src.size not in (1, 2):
        raise Unsupported("movsx source size")
    e.line(reg_wr(dst.reg, f"LIFT_SX{src.size * 8}({rd(i, src)})"))


@op("lea")
def lea(e, i):
    dst, src = i.ops
    if src.type != OP_MEM:
        raise Unsupported("lea operand")
    # LEA yields the offset only: a segment override does not add its base.
    e.line(reg_wr(dst.reg, ea(i, src, segment=False)))


@op("xchg")
def xchg(e, i):
    a, b = i.ops
    if a.type == OP_REG and b.type == OP_MEM:
        a, b = b, a
    read, write = e.rw(i, a)
    e.decl(f"uint32_t x = {read};")
    e.decl(f"uint32_t y = {rd(i, b)};")
    e.line(write("y"))
    e.line(wr(i, b, "x"))


def _cmov(name):
    def handler(e, i):
        dst, src = i.ops
        # The source is read (and can fault) whether or not the move happens.
        e.decl(f"uint32_t v = {rd(i, src)};")
        e.line(f"if ({cc_expr(name)}) {reg_wr(dst.reg, 'v')}")
    return handler


for _name in CC_NAMES:
    op("cmov" + _name)(_cmov(_name))


@op("cdq")
def cdq(e, i):
    e.line(f"c->r[{EDX}] = (c->r[{EAX}] & 0x80000000u) ? 0xffffffffu : 0u;")


@op("cwd")
def cwd(e, i):
    e.line(f"LIFT_W16({EDX}, (c->r[{EAX}] & 0x8000u) ? 0xffffu : 0u);")


@op("cwde")
def cwde(e, i):
    e.line(f"c->r[{EAX}] = LIFT_SX16(c->r[{EAX}]);")


@op("cbw")
def cbw(e, i):
    e.line(f"LIFT_W16({EAX}, LIFT_SX8(c->r[{EAX}]));")


@op("xlatb")
def xlatb(e, i):
    if i.addr16:
        raise Unsupported("16-bit xlat")
    segment = " + LIFT_FS" if i.seg == SEG_PREFIX_FS else ""
    e.line(f"LIFT_W8L({EAX}, lift_r8(c, c->r[{EBX}] + LIFT_R8L({EAX}){segment}));")


@op("lahf")
def lahf(e, i):
    e.line(f"LIFT_W8H({EAX}, lift_flags_pack(c) >> 8);")


@op("sahf")
def sahf(e, i):
    e.line(f"lift_sahf(c, LIFT_R8H({EAX}));")
