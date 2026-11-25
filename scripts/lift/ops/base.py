"""Shared machinery for instruction handlers: registry, instruction view,
operand accessors and the per-function emitter.

C conventions the handlers rely on (see lift_rt.h):
  * ``c`` is the ``lift_ctx *``; 32-bit registers are ``c->r[n]`` in x86
    encoding order, sub-registers go through LIFT_R16/R8L/R8H and
    LIFT_W16/W8L/W8H.
  * Memory goes through lift_r8/16/32 and lift_w8/16/32, which end the trial
    on an invalid access. An instruction must finish every access that can
    fault before it changes registers or flags, so handlers read first, then
    write memory, then write registers. A read-modify-write of one location
    needs no separate probe: the write cannot fault after the read succeeded.
  * Flag helpers (lift_add32, ...) return the truncated result and update the
    flags; conditions are the LIFT_CC_* macros.
"""
from __future__ import annotations

from capstone import x86_const as X

REGISTRY: dict[str, callable] = {}


class Unsupported(Exception):
    """Raised by a handler for an instruction form it does not translate."""


def op(*mnemonics: str):
    def register(fn):
        for m in mnemonics:
            if m in REGISTRY:
                raise ValueError(f"duplicate handler for {m}")
            REGISTRY[m] = fn
        return fn
    return register


# capstone register id -> (encoding index, size in bytes, kind); kind is
# "d" dword, "w" word, "l" low byte, "h" high byte (AH/CH/DH/BH).
GPR: dict[int, tuple[int, int, str]] = {}
for _i, _names in enumerate((("EAX", "AX", "AL", "AH"), ("ECX", "CX", "CL", "CH"), ("EDX", "DX", "DL", "DH"),
                             ("EBX", "BX", "BL", "BH"), ("ESP", "SP"), ("EBP", "BP"), ("ESI", "SI"), ("EDI", "DI"))):
    for _name, (_size, _kind) in zip(_names, ((4, "d"), (2, "w"), (1, "l"), (1, "h"))):
        GPR[getattr(X, "X86_REG_" + _name)] = (_i, _size, _kind)

EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI = range(8)
XMM = {getattr(X, f"X86_REG_XMM{n}"): n for n in range(8)}
MMX = {getattr(X, f"X86_REG_MM{n}"): n for n in range(8)}
SEG_PREFIX_FS = 0x64
SIZE_SUFFIX = {1: "8", 2: "16", 4: "32"}
SIZE_MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}
CC_NAMES = ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g")
OP_REG, OP_IMM, OP_MEM = X.X86_OP_REG, X.X86_OP_IMM, X.X86_OP_MEM


def sz(size: int) -> str:
    try:
        return SIZE_SUFFIX[size]
    except KeyError:
        raise Unsupported(f"operand size {size}") from None


def cc_expr(name: str) -> str:
    return "LIFT_CC_" + name.upper()


class Ins:
    """What a handler needs from one decoded instruction."""

    __slots__ = ("cs", "addr", "size", "next", "mnem", "ops", "rep", "lock", "seg", "opsize16", "addr16")

    def __init__(self, cs):
        self.cs = cs
        self.addr = cs.address
        self.size = cs.size
        self.next = (cs.address + cs.size) & 0xFFFFFFFF
        mnem = cs.mnemonic
        # capstone folds rep/lock/bnd prefixes into the mnemonic text
        self.mnem = mnem.rsplit(" ", 1)[1] if " " in mnem else mnem
        self.ops = cs.operands
        prefix = cs.prefix
        self.rep = prefix[0] if prefix[0] in (0xF2, 0xF3) else 0
        self.lock = prefix[0] == 0xF0
        self.seg = prefix[1]
        self.opsize16 = prefix[2] == 0x66
        self.addr16 = cs.addr_size == 2


def reg_rd(reg: int) -> str:
    try:
        n, _, kind = GPR[reg]
    except KeyError:
        raise Unsupported("register operand outside the general registers") from None
    if kind == "d":
        return f"c->r[{n}]"
    return {"w": "LIFT_R16", "l": "LIFT_R8L", "h": "LIFT_R8H"}[kind] + f"({n})"


def reg_wr(reg: int, val: str) -> str:
    try:
        n, _, kind = GPR[reg]
    except KeyError:
        raise Unsupported("register operand outside the general registers") from None
    if kind == "d":
        return f"c->r[{n}] = {val};"
    return {"w": "LIFT_W16", "l": "LIFT_W8L", "h": "LIFT_W8H"}[kind] + f"({n}, {val});"


def imm(value: int, size: int) -> str:
    return f"0x{value & SIZE_MASK[size]:x}u"


def ea(i: Ins, o, segment: bool = True) -> str:
    """Effective address of a memory operand as a C expression (uint32_t)."""
    m = o.mem
    parts = []
    if m.base:
        parts.append(reg_rd(m.base))
    if m.index and m.index != X.X86_REG_EIZ:
        parts.append(reg_rd(m.index) + (f" * {m.scale}u" if m.scale != 1 else ""))
    disp = m.disp & 0xFFFFFFFF
    if disp or not parts:
        parts.append(f"0x{disp:x}u")
    expr = " + ".join(parts)
    if i.addr16:
        expr = f"(({expr}) & 0xffffu)"
    if segment and m.segment == X.X86_REG_FS:
        expr += " + LIFT_FS"
    return expr


def rd(i: Ins, o, size: int | None = None, addr: str | None = None) -> str:
    """Value of an operand as a C expression, truncated to its size."""
    if o.type == OP_REG:
        return reg_rd(o.reg)
    if o.type == OP_IMM:
        return imm(o.imm, size or o.size)
    if o.type == OP_MEM:
        return f"lift_r{sz(size or o.size)}(c, {addr or ea(i, o)})"
    raise Unsupported("operand type")


def wr(i: Ins, o, val: str, size: int | None = None, addr: str | None = None) -> str:
    """C statement storing val into a register or memory operand."""
    if o.type == OP_REG:
        return reg_wr(o.reg, val)
    if o.type == OP_MEM:
        return f"lift_w{sz(size or o.size)}(c, {addr or ea(i, o)}, {val});"
    raise Unsupported("operand type")


class Emitter:
    """Collects the C statements of one function."""

    def __init__(self, starts):
        self.starts = starts          # instruction start addresses inside the body
        self.thunks: dict[str, tuple[bytes, int]] = {}
        self.body: list[str] = []     # statements of the instruction being emitted
        self.block = False            # the statements declare a local and need braces
        self.fallthrough = True

    def begin(self) -> None:
        self.body = []
        self.block = False
        self.fallthrough = True

    def line(self, text: str) -> None:
        self.body.append(text)

    def decl(self, text: str) -> None:
        self.block = True
        self.body.append(text)

    def rw(self, i: Ins, o, size: int | None = None):
        """(read expression, write-statement function) for a read-modify-write
        operand. A memory operand's address is evaluated once into ``ea``."""
        if o.type == OP_MEM:
            self.decl(f"uint32_t ea = {ea(i, o)};")
            return rd(i, o, size, "ea"), lambda val: wr(i, o, val, size, "ea")
        return rd(i, o, size), lambda val: wr(i, o, val, size)

    def goto(self, target: int) -> str:
        """Statement transferring control to a guest address known at lift time."""
        target &= 0xFFFFFFFF
        if target in self.starts:
            return f"goto L_{target:08x};"
        return f"{{ c->eip = 0x{target:08x}u; goto leave; }}"

    def jump(self, target: int) -> None:
        self.line(self.goto(target))
        self.fallthrough = False

    def dispatch(self, expr: str) -> None:
        """Transfer to a guest address computed at run time."""
        self.line(f"c->eip = {expr}; goto dispatch;")
        self.fallthrough = False

    def thunk(self, name: str, code: bytes, flags: int = 0) -> str:
        self.thunks.setdefault(name, (code, flags))
        return name
