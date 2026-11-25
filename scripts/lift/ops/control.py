"""Control flow and stack instructions.

Direct transfers to an instruction start inside the body are C gotos; every
other transfer sets c->eip and re-enters the dispatch switch, whose default
case is the leave-the-body routine (call events, stubs, LM_T_LEAVE).
"""
from __future__ import annotations

from .base import CC_NAMES, ECX, ESP, OP_IMM, OP_MEM, OP_REG, Unsupported, cc_expr, ea, op, rd, reg_wr, sz, wr


def _near32(i) -> None:
    if i.opsize16:
        raise Unsupported("16-bit near transfer")


@op("call")
def call(e, i):
    _near32(i)
    target = i.ops[0]
    if target.type == OP_IMM:
        e.line(f"lift_push32(c, 0x{i.next:08x}u);")
        e.jump(target.imm)
    else:
        # The target is read before the return address is pushed (call [esp+n], call esp).
        e.decl(f"uint32_t t = {rd(i, target)};")
        e.line(f"lift_push32(c, 0x{i.next:08x}u);")
        e.dispatch("t")


@op("jmp")
def jmp(e, i):
    _near32(i)
    target = i.ops[0]
    if target.type == OP_IMM:
        e.jump(target.imm)
    else:
        e.dispatch(rd(i, target))


def _jcc(name):
    def handler(e, i):
        _near32(i)
        e.line(f"if ({cc_expr(name)}) {e.goto(i.ops[0].imm)}")
    return handler


for _name in CC_NAMES:
    op("j" + _name)(_jcc(_name))


@op("jecxz")
def jecxz(e, i):
    if i.addr16:
        raise Unsupported("jcxz")
    e.line(f"if (c->r[{ECX}] == 0u) {e.goto(i.ops[0].imm)}")


def _loop(cond):
    def handler(e, i):
        if i.addr16:
            raise Unsupported("16-bit loop counter")
        e.line(f"if (--c->r[{ECX}] != 0u{cond}) {e.goto(i.ops[0].imm)}")
    return handler


op("loop")(_loop(""))
op("loope")(_loop(" && c->zf"))
op("loopne")(_loop(" && !c->zf"))


@op("ret")
def ret(e, i):
    _near32(i)
    extra = i.ops[0].imm & 0xFFFF if i.ops else 0
    e.decl(f"uint32_t t = lift_r32(c, c->r[{ESP}]);")
    e.line(f"c->r[{ESP}] += 0x{4 + extra:x}u;")
    e.dispatch("t")


@op("push")
def push(e, i):
    src = i.ops[0]
    size = src.size
    if size not in (2, 4):
        raise Unsupported("push size")
    e.line(f"lift_push{sz(size)}(c, {rd(i, src)});")


@op("pop")
def pop(e, i):
    dst = i.ops[0]
    size = dst.size
    if size not in (2, 4):
        raise Unsupported("pop size")
    bits = sz(size)
    if dst.type == OP_REG:
        # A temporary keeps "pop esp/sp" well defined: the popped value wins.
        e.decl(f"uint32_t v = lift_pop{bits}(c);")
        e.line(reg_wr(dst.reg, "v"))
    elif dst.type == OP_MEM:
        # The destination address uses ESP after the pop; ESP itself moves
        # only once the store is known not to fault.
        e.decl(f"uint32_t sp = c->r[{ESP}];")
        e.decl(f"uint32_t v = lift_r{bits}(c, sp);")
        e.decl("uint32_t ea;")
        e.line(f"c->r[{ESP}] = sp + {size}u;")
        e.line(f"ea = {ea(i, dst)};")
        e.line(f"c->r[{ESP}] = sp;")
        e.line(wr(i, dst, "v", size, "ea"))
        e.line(f"c->r[{ESP}] = sp + {size}u;")
    else:
        raise Unsupported("pop operand")


@op("leave")
def leave(e, i):
    if i.opsize16:
        raise Unsupported("16-bit leave")
    e.decl("uint32_t bp = c->r[5];")
    e.decl("uint32_t v = lift_r32(c, bp);")
    e.line(f"c->r[{ESP}] = bp + 4u;")
    e.line("c->r[5] = v;")


@op("pushfd")
def pushfd(e, i):
    e.line("lift_push32(c, lift_eflags_get(c));")


@op("pushf")
def pushf(e, i):
    e.line("lift_push16(c, lift_eflags_get(c));")


@op("popfd")
def popfd(e, i):
    # lift_eflags_set can end the trial (popped TF), so ESP moves afterwards.
    e.decl(f"uint32_t v = lift_r32(c, c->r[{ESP}]);")
    e.line("lift_eflags_set(c, v);")
    e.line(f"c->r[{ESP}] += 4u;")


@op("popf")
def popf(e, i):
    e.decl(f"uint32_t v = lift_r16(c, c->r[{ESP}]);")
    e.line("lift_eflags_set16(c, v);")
    e.line(f"c->r[{ESP}] += 2u;")
