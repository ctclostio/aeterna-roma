"""Logic, shifts and rotates, double shifts, bit tests and scans, setcc."""
from __future__ import annotations

from capstone import x86_const as X

from .base import CC_NAMES, OP_IMM, OP_MEM, OP_REG, Unsupported, cc_expr, ea, op, rd, reg_rd, reg_wr, sz, wr

CL = X.X86_REG_CL


def _logic(c_op):
    def handler(e, i):
        dst, src = i.ops
        size = dst.size
        read, write = e.rw(i, dst)
        e.line(write(f"lift_logic{sz(size)}(c, {read} {c_op} {rd(i, src, size)})"))
    return handler


op("and")(_logic("&"))
op("or")(_logic("|"))
op("xor")(_logic("^"))


@op("test")
def test(e, i):
    a, b = i.ops
    e.line(f"(void)lift_logic{sz(a.size)}(c, {rd(i, a)} & {rd(i, b, a.size)});")


@op("not")
def not_(e, i):
    dst = i.ops[0]
    read, write = e.rw(i, dst)
    e.line(write(f"~{read}"))


def _count(i, o) -> tuple[str, bool]:
    """(count expression, is immediate) for a shift count operand."""
    if o.type == OP_IMM:
        return f"0x{o.imm & 0xFF:x}u", True
    if o.type == OP_REG and o.reg == CL:
        return reg_rd(CL), False
    raise Unsupported("shift count operand")


def _shift(helper, imm_helper=None):
    def handler(e, i):
        dst = i.ops[0]
        count, is_imm = _count(i, i.ops[1]) if len(i.ops) > 1 else ("1u", True)
        read, write = e.rw(i, dst)
        name = imm_helper if (is_imm and imm_helper) else helper
        e.line(write(f"lift_{name}{sz(dst.size)}(c, {read}, {count})"))
    return handler


op("shl", "sal")(_shift("shl"))
op("shr")(_shift("shr"))
op("sar")(_shift("sar"))
# The host's undefined OF differs between CL and immediate counts for ROL/ROR.
op("rol")(_shift("rol", "roli"))
op("ror")(_shift("ror", "rori"))
op("rcl")(_shift("rcl"))
op("rcr")(_shift("rcr"))


def _double_shift(helper):
    def handler(e, i):
        dst, src, cnt = i.ops
        if dst.size not in (2, 4):
            raise Unsupported("double shift size")
        count, _ = _count(i, cnt)
        read, write = e.rw(i, dst)
        e.line(write(f"lift_{helper}{sz(dst.size)}(c, {read}, {reg_rd(src.reg)}, {count})"))
    return handler


op("shld")(_double_shift("shld"))
op("shrd")(_double_shift("shrd"))


def _bit_test(update):
    """bt/bts/btr/btc. update is a C operator applied with the bit mask, or None."""
    def handler(e, i):
        dst, src = i.ops
        size = dst.size
        if size not in (2, 4):
            raise Unsupported("bit test size")
        bits = size * 8
        if dst.type == OP_MEM and src.type == OP_REG:
            # A register bit offset addresses the bit string at the operand:
            # the word is selected by the signed offset divided by the size.
            ext = "(int32_t)" if size == 4 else "(int32_t)(int16_t)"
            shift = 5 if size == 4 else 4
            e.decl(f"uint32_t off = {reg_rd(src.reg)};")
            e.decl(f"uint32_t ea = {ea(i, dst)} + {size}u * (uint32_t)({ext}off >> {shift});")
        else:
            e.decl(f"uint32_t off = {rd(i, src, 1) if src.type == OP_IMM else reg_rd(src.reg)};")
            if dst.type == OP_MEM:
                e.decl(f"uint32_t ea = {ea(i, dst)};")
        e.decl(f"uint32_t v = {rd(i, dst, size, 'ea')};")
        e.decl(f"uint32_t m = 1u << (off & {bits - 1}u);")
        e.line("lift_bt_flags(c, (v & m) != 0u);")
        if update is not None:
            e.line(wr(i, dst, update, size, "ea"))
    return handler


op("bt")(_bit_test(None))
op("bts")(_bit_test("v | m"))
op("btr")(_bit_test("v & ~m"))
op("btc")(_bit_test("v ^ m"))


def _bit_scan(helper):
    def handler(e, i):
        dst, src = i.ops
        if dst.size not in (2, 4):
            raise Unsupported("bit scan size")
        e.line(reg_wr(dst.reg, f"lift_{helper}{sz(dst.size)}(c, {reg_rd(dst.reg)}, {rd(i, src)})"))
    return handler


op("bsf")(_bit_scan("bsf"))
op("bsr")(_bit_scan("bsr"))


@op("bswap")
def bswap(e, i):
    dst = i.ops[0]
    if dst.size != 4:
        raise Unsupported("16-bit bswap")
    e.decl(f"uint32_t v = {reg_rd(dst.reg)};")
    e.line(reg_wr(dst.reg, "(v >> 24) | ((v >> 8) & 0xff00u) | ((v << 8) & 0xff0000u) | (v << 24)"))


def _setcc(name):
    def handler(e, i):
        e.line(wr(i, i.ops[0], cc_expr(name), 1))
    return handler


for _name in CC_NAMES:
    op("set" + _name)(_setcc(_name))
