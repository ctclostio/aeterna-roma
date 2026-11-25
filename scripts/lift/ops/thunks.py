"""x87 and SIMD instructions: executed on the host through byte thunks.

These instructions are not re-expressed in C. Each becomes a call to a small
leaf routine made of the original instruction bytes, so its semantics are the
host CPU's on both sides of the differential test. Thunks are identified by
their bytes (the name is derived from them), which deduplicates them within a
batch and keeps a function's generated C independent of the batch it is in.

Two thunk shapes (calling conventions in lift_rt.h):

  lx_*  "plain": the instruction with its memory operand rewritten to [rcx],
        then ret. Used for x87 and for MMX/control forms that touch neither
        XMM nor general registers. Variants: ``_a`` returns AX (fnstsw ax),
        ``_f`` loads the guest status flags first and returns them after
        (fcomi family, fcmovcc).

  ls_*  "context": rcx = lift_ctx, edx = packed flags, r8 = memory operand.
        Saves the host's xmm6/xmm7 and any callee-saved general register it
        borrows into the context, loads guest XMM0..7 and the general-register
        operands into the same-numbered host registers, runs the instruction
        with its memory operand rewritten to [r8], stores everything back and
        returns the packed flags.

Thunks never touch rsp. A host fault inside one is caught by the runtime's
vectored handler, which restores the saved registers named by the thunk's
LIFT_TF_* flags.
"""
from __future__ import annotations

from capstone import x86_const as X

from .base import GPR, MMX, OP_MEM, OP_REG, XMM, Unsupported, ea, op

LEGACY_PREFIXES = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3))
# Segment and address-size prefixes belong to the original memory operand,
# which the thunk replaces with a host pointer.
DROPPED_PREFIXES = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x67))
NO_MODRM = frozenset((b"\x0f\x77", b"\x0f\x0e", b"\x9b"))  # emms, femms, wait

TF_XMM, TF_RBX, TF_RBP, TF_RSI, TF_RDI = 0x01, 0x02, 0x04, 0x08, 0x10
CALLEE_SAVED = {3: (TF_RBX, 0xE0), 5: (TF_RBP, 0xE8), 6: (TF_RSI, 0xF0), 7: (TF_RDI, 0xF8)}  # gpr -> (flag, save slot)
OFF_R, OFF_XMM, OFF_SAVE_XMM = 0x00, 0x40, 0xC0

FLAGS_IN = bytes((0x89, 0xD0, 0x04, 0x7F, 0x9E))  # mov eax, edx; add al, 7fh (OF); sahf
FLAGS_OUT = bytes((0x0F, 0x90, 0xC0, 0x9F))       # seto al; lahf
RET = b"\xc3"

# Memory operand size of x87 instructions by (opcode, ModRM reg field). The
# environment/state forms are absent: they are not translated (see below).
X87_MEM_SIZE = {}
for _reg in range(8):
    X87_MEM_SIZE[(0xD8, _reg)] = 4
    X87_MEM_SIZE[(0xDA, _reg)] = 4
    X87_MEM_SIZE[(0xDC, _reg)] = 8
    X87_MEM_SIZE[(0xDE, _reg)] = 2
X87_MEM_SIZE.update({
    (0xD9, 0): 4, (0xD9, 2): 4, (0xD9, 3): 4, (0xD9, 5): 2, (0xD9, 7): 2,
    (0xDB, 0): 4, (0xDB, 1): 4, (0xDB, 2): 4, (0xDB, 3): 4, (0xDB, 5): 10, (0xDB, 7): 10,
    (0xDD, 0): 8, (0xDD, 1): 8, (0xDD, 2): 8, (0xDD, 3): 8, (0xDD, 7): 2,
    (0xDF, 0): 2, (0xDF, 1): 2, (0xDF, 2): 2, (0xDF, 3): 2, (0xDF, 4): 10, (0xDF, 5): 8, (0xDF, 6): 10, (0xDF, 7): 8,
})

# Not translated: the x87 environment and FXSAVE images expose the last
# instruction and operand pointers, which are host addresses in a thunk; the
# 64-bit FXSAVE layout also differs. MASKMOV addresses memory through EDI
# implicitly. VEX encodings are outside the modelled state (XMM0..7 only).
NOT_TRANSLATED = frozenset((
    "fnstenv", "fldenv", "fnsave", "frstor", "fxsave", "fxrstor", "fxsave64", "fxrstor64", "xsave", "xrstor",
    "xsaveopt", "xsavec", "xsaves", "xrstors", "maskmovq", "maskmovdqu",
))
# Instructions that write EFLAGS; the thunk loads the guest flags first, so
# flags the instruction preserves stay correct whatever the CPU does.
FLAG_WRITERS = frozenset((
    "comiss", "comisd", "ucomiss", "ucomisd", "ptest", "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm",
))
IMPLICIT_GPR = {"pcmpestri": (0, 1, 2), "pcmpestrm": (0, 2), "pcmpistri": (1,)}
# Capstone reports the wrong memory operand size for these.
MEM_SIZE_FIX = {"comisd": 8}
# 16-byte memory operands that do not require alignment.
UNALIGNED_OK = frozenset(("movups", "movupd", "movdqu", "lddqu", "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm"))
SIMD_GROUPS = frozenset((X.X86_GRP_MMX, X.X86_GRP_SSE1, X.X86_GRP_SSE2, X.X86_GRP_SSE3, X.X86_GRP_SSSE3,
                         X.X86_GRP_SSE41, X.X86_GRP_SSE42, X.X86_GRP_3DNOW, X.X86_GRP_AES, X.X86_GRP_PCLMUL,
                         X.X86_GRP_SHA))


def _split(raw: bytes):
    """-> (legacy prefixes, opcode bytes, rest)"""
    n = 0
    while n < len(raw) and raw[n] in LEGACY_PREFIXES:
        n += 1
    first = raw[n]
    if first in (0xC4, 0xC5, 0x62, 0x8F):
        raise Unsupported("VEX/EVEX/XOP encoding")
    if first == 0x0F:
        oplen = 3 if raw[n + 1] in (0x38, 0x3A) else 2
    else:
        oplen = 1
    return raw[:n], raw[n:n + oplen], raw[n + oplen:]


def _modrm_len(rest: bytes, addr16: bool) -> int:
    modrm = rest[0]
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3:
        return 1
    if addr16:
        return 1 + (2 if (mod == 0 and rm == 6) else (0, 1, 2)[mod])
    n = 1 + (0, 1, 4)[mod]
    if rm == 4:
        n += 1
        if mod == 0 and (rest[1] & 7) == 5:
            n += 4
    elif mod == 0 and rm == 5:
        n += 4
    return n


def _r9(reg: int, disp: int) -> bytes:
    """ModRM (+disp) for [r9 + disp] with the given reg field; the caller supplies REX.B."""
    if disp < 0x80:
        return bytes((0x41 | (reg << 3), disp))
    return bytes((0x81 | (reg << 3),)) + disp.to_bytes(4, "little")


def _context_thunk(insn: bytes, xmm: bool, gprs: tuple[int, ...], flags: bool) -> tuple[bytes, int]:
    code = bytearray(b"\x49\x89\xc9")                                 # mov r9, rcx
    desc = 0
    if xmm:
        desc |= TF_XMM
        code += b"\x41\x0f\x11" + _r9(6, OFF_SAVE_XMM)                # movups [r9+save], xmm6
        code += b"\x41\x0f\x11" + _r9(7, OFF_SAVE_XMM + 16)           # movups [r9+save+16], xmm7
    for g in gprs:
        if g in CALLEE_SAVED:
            flag, slot = CALLEE_SAVED[g]
            desc |= flag
            code += b"\x49\x89" + _r9(g, slot)                        # mov [r9+slot], r64
    if xmm:
        for n in range(8):
            code += b"\x41\x0f\x10" + _r9(n, OFF_XMM + 16 * n)        # movups xmmN, [r9+xmm+16n]
    if flags:
        code += FLAGS_IN
    for g in gprs:
        code += b"\x41\x8b" + _r9(g, OFF_R + 4 * g)                   # mov r32, [r9+4g]
    code += insn
    for g in gprs:
        code += b"\x41\x89" + _r9(g, OFF_R + 4 * g)                   # mov [r9+4g], r32
    if flags:
        code += FLAGS_OUT
    if xmm:
        for n in range(8):
            code += b"\x41\x0f\x11" + _r9(n, OFF_XMM + 16 * n)        # movups [r9+xmm+16n], xmmN
        code += b"\x41\x0f\x10" + _r9(6, OFF_SAVE_XMM)                # movups xmm6, [r9+save]
        code += b"\x41\x0f\x10" + _r9(7, OFF_SAVE_XMM + 16)
    for g in gprs:
        if g in CALLEE_SAVED:
            code += b"\x49\x8b" + _r9(g, CALLEE_SAVED[g][1])          # mov r64, [r9+slot]
    code += RET
    return bytes(code), desc


def _mem_operand(i):
    mems = [o for o in i.ops if o.type == OP_MEM]
    if len(mems) != 1:
        raise Unsupported("memory operand not explicit")
    return mems[0]


def _parse(i):
    """-> (kept prefixes, opcode, modrm or None, tail after modrm/sib/disp)"""
    raw = bytes(i.cs.bytes)
    prefixes, opcode, rest = _split(raw)
    kept = bytes(p for p in prefixes if p not in DROPPED_PREFIXES)
    if opcode in NO_MODRM:
        return kept, opcode, None, rest
    if not rest:
        raise Unsupported("truncated instruction")
    mlen = _modrm_len(rest, i.addr16)
    offset = i.cs.modrm_offset
    if offset and offset != len(prefixes) + len(opcode):
        raise Unsupported("ModRM position disagrees with the decoder")
    return kept, opcode, rest[0], rest[mlen:]


def _x87(e, i):
    kept, opcode, modrm, tail = _parse(i)
    if modrm is None:  # wait
        e.line(f"LIFT_TX({e.thunk('lx_' + opcode.hex(), kept + opcode + RET)})(0);")
        return
    first = opcode[0]
    if modrm >= 0xC0:
        insn = kept + opcode + bytes((modrm,))
        stem = "lx_" + insn.hex()
        if first == 0xDF and modrm == 0xE0:  # fnstsw ax
            e.line(f"LIFT_W16(0, LIFT_TXR({e.thunk(stem + '_a', insn + RET)})(0, 0u));")
        elif (first in (0xDA, 0xDB) and modrm < 0xE0) or (first in (0xDB, 0xDF) and 0xE8 <= modrm <= 0xF7):
            # fcmovcc reads EFLAGS; fcomi/fcomip/fucomi/fucomip write them.
            name = e.thunk(stem + "_f", FLAGS_IN + insn + FLAGS_OUT + RET)
            e.line(f"lift_flags_unpack(c, LIFT_TXR({name})(0, lift_flags_pack(c)));")
        else:
            e.line(f"LIFT_TX({e.thunk(stem, insn + RET)})(0);")
        return
    size = X87_MEM_SIZE.get((first, (modrm >> 3) & 7))
    if size is None:
        raise Unsupported("x87 environment/state instruction")
    insn = kept + opcode + bytes(((modrm & 0x38) | 0x01,))  # mod=00 rm=001: [rcx]
    e.decl(f"uint8_t *m = lift_mptr(c, {ea(i, _mem_operand(i))}, {size}u);")
    e.line(f"LIFT_TX({e.thunk('lx_' + insn.hex(), insn + RET)})(m);")
    e.line("LIFT_MDONE();")


def _simd(e, i):
    mnem = i.mnem
    kept, opcode, modrm, tail = _parse(i)
    xmm = False
    gprs = set(IMPLICIT_GPR.get(mnem, ()))
    high_byte = False
    for o in i.ops:
        if o.type != OP_REG:
            continue
        if o.reg in XMM:
            xmm = True
        elif o.reg in GPR:
            index, _, kind = GPR[o.reg]
            gprs.add(index)
            high_byte |= kind == "h"
        elif o.reg not in MMX:
            raise Unsupported("register outside XMM0..7/MM0..7/general registers")
    if 4 in gprs:
        raise Unsupported("esp as an operand of a thunked instruction")
    flags = mnem in FLAG_WRITERS
    has_mem = modrm is not None and modrm < 0xC0
    plain = not xmm and not gprs and not flags

    if has_mem:
        mem = _mem_operand(i)
        size = MEM_SIZE_FIX.get(mnem, mem.size)
        if not 1 <= size <= 16:
            raise Unsupported(f"memory operand size {size}")
        if high_byte:
            raise Unsupported("high-byte register with a rewritten memory operand")
        aligned = size == 16 and mnem not in UNALIGNED_OK
        e.decl(f"uint8_t *m = lift_mptr{'_a16' if aligned else ''}(c, {ea(i, mem)}, {size}u);")
        if plain:
            insn = kept + opcode + bytes(((modrm & 0x38) | 0x01,)) + tail          # [rcx]
        else:
            insn = kept + b"\x41" + opcode + bytes(((modrm & 0x38),)) + tail      # REX.B, [r8]
    else:
        if any(o.type == OP_MEM for o in i.ops):
            raise Unsupported("implicit memory operand")
        insn = kept + opcode + (bytes((modrm,)) if modrm is not None else b"") + tail
    arg = "m" if has_mem else "0"

    if plain:
        e.line(f"LIFT_TX({e.thunk('lx_' + insn.hex(), insn + RET)})({arg});")
    else:
        order = tuple(sorted(gprs))
        code, desc = _context_thunk(insn, xmm, order, flags)
        suffix = ("x" if xmm else "") + ("f" if flags else "") + "".join(str(g) for g in order)
        name = e.thunk(f"ls_{insn.hex()}_{suffix}", code, desc)
        if flags:
            e.line(f"lift_flags_unpack(c, LIFT_TS({name})(c, lift_flags_pack(c), {arg}));")
        else:
            e.line(f"(void)LIFT_TS({name})(c, 0u, {arg});")
    if has_mem and i.ops[0].type == OP_MEM:
        e.line("LIFT_MDONE();")  # the memory operand is the destination


def lift_thunk(e, i):
    """Fallback for every instruction without a C handler."""
    if i.mnem in NOT_TRANSLATED:
        raise Unsupported("state image instruction")
    raw = i.cs.bytes
    n = 0
    while n < len(raw) and raw[n] in LEGACY_PREFIXES:
        n += 1
    if n < len(raw) and (0xD8 <= raw[n] <= 0xDF or raw[n] == 0x9B):
        _x87(e, i)
    elif any(o.type == OP_REG and (o.reg in XMM or o.reg in MMX) for o in i.ops) or \
            not SIMD_GROUPS.isdisjoint(i.cs.groups):
        _simd(e, i)
    else:
        raise Unsupported("no handler")


op("wait")(_x87)
