"""Integer arithmetic: add/adc/sub/sbb/cmp, inc/dec/neg, multiplies, divides,
xadd and cmpxchg. LOCK prefixes need no handling: trials are single threaded.
"""
from __future__ import annotations

from .base import OP_IMM, Unsupported, op, rd, reg_rd, reg_wr, sz
from capstone import x86_const as X

ACC = {1: X.X86_REG_AL, 2: X.X86_REG_AX, 4: X.X86_REG_EAX}


def _binary(helper):
    def handler(e, i):
        dst, src = i.ops
        size = dst.size
        read, write = e.rw(i, dst)
        e.line(write(f"lift_{helper}{sz(size)}(c, {read}, {rd(i, src, size)})"))
    return handler


for _mnem in ("add", "adc", "sub", "sbb"):
    op(_mnem)(_binary(_mnem))


@op("cmp")
def cmp(e, i):
    a, b = i.ops
    e.line(f"(void)lift_sub{sz(a.size)}(c, {rd(i, a)}, {rd(i, b, a.size)});")


def _unary(helper):
    def handler(e, i):
        dst = i.ops[0]
        read, write = e.rw(i, dst)
        e.line(write(f"lift_{helper}{sz(dst.size)}(c, {read})"))
    return handler


for _mnem in ("inc", "dec", "neg"):
    op(_mnem)(_unary(_mnem))


def _accumulator(helper):
    """One-operand mul/imul/div/idiv: the helper works on AL/AX/EAX, AH/DX/EDX."""
    def handler(e, i):
        src = i.ops[0]
        e.line(f"lift_{helper}{sz(src.size)}(c, {rd(i, src)});")
    return handler


op("mul")(_accumulator("mul"))
op("div")(_accumulator("div"))
op("idiv")(_accumulator("idiv"))


@op("imul")
def imul(e, i):
    ops = i.ops
    if len(ops) == 1:
        e.line(f"lift_imul1_{sz(ops[0].size)}(c, {rd(i, ops[0])});")
        return
    dst = ops[0]
    size = dst.size
    if size not in (2, 4):
        raise Unsupported("imul size")
    if len(ops) == 2:
        a, b = rd(i, dst), rd(i, ops[1], size)
    else:
        if ops[2].type != OP_IMM:
            raise Unsupported("imul form")
        a, b = rd(i, ops[1], size), rd(i, ops[2], size)
    e.line(reg_wr(dst.reg, f"lift_imul{sz(size)}(c, {a}, {b})"))


@op("xadd")
def xadd(e, i):
    dst, src = i.ops
    size = dst.size
    read, write = e.rw(i, dst)
    e.decl(f"uint32_t a = {read};")
    e.decl(f"uint32_t r = lift_add{sz(size)}(c, a, {reg_rd(src.reg)});")
    # The source register gets the old destination first, so "xadd r, r" ends with the sum.
    e.line(reg_wr(src.reg, "a"))
    e.line(write("r"))


@op("cmpxchg")
def cmpxchg(e, i):
    dst, src = i.ops
    size = dst.size
    if size not in ACC:
        raise Unsupported("cmpxchg size")
    acc = ACC[size]
    read, write = e.rw(i, dst)
    e.decl(f"uint32_t d = {read};")
    e.line(f"(void)lift_sub{sz(size)}(c, {reg_rd(acc)}, d);")
    # On a mismatch the CPU also writes the old value back; that store cannot
    # fault after the read and changes nothing, so it is left out.
    e.line(f"if (c->zf) {{ {write(reg_rd(src.reg))} }} else {{ {reg_wr(acc, 'd')} }}")
