"""String instructions. The loops live in the runtime (lift_movs and friends),
which runs one iteration at a time so faults and step accounting are exact.

movsd and cmpsd are also SSE2 mnemonics; those forms have a two-byte opcode
and are passed on to the thunk family.
"""
from __future__ import annotations

from .base import SEG_PREFIX_FS, Unsupported, op
from . import thunks

# first opcode byte -> (runtime routine, takes a source segment, compares)
STRING_OPS = {
    0xA4: ("movs", True, False), 0xA5: ("movs", True, False),
    0xA6: ("cmps", True, True), 0xA7: ("cmps", True, True),
    0xAA: ("stos", False, False), 0xAB: ("stos", False, False),
    0xAC: ("lods", True, False), 0xAD: ("lods", True, False),
    0xAE: ("scas", False, True), 0xAF: ("scas", False, True),
}


def string_op(e, i):
    opcode = i.cs.opcode[0]
    if opcode not in STRING_OPS:
        thunks.lift_thunk(e, i)
        return
    routine, has_source, compares = STRING_OPS[opcode]
    if i.addr16:
        raise Unsupported("16-bit string addressing")
    size = 1 if opcode % 2 == 0 else (2 if i.opsize16 else 4)
    if i.rep == 0:
        rep = "LIFT_REP_NONE"
    elif compares and i.rep == 0xF2:
        rep = "LIFT_REP_NE"
    else:
        rep = "LIFT_REP_E"  # F3, and F2 on a non-comparing instruction, repeat on ECX alone
    args = f"c, {size}u, {rep}"
    if has_source:
        if i.seg not in (0, SEG_PREFIX_FS, 0x26, 0x2E, 0x36, 0x3E, 0x65):
            raise Unsupported("string segment override")
        args += ", LIFT_FS" if i.seg == SEG_PREFIX_FS else ", 0u"
    e.line(f"lift_{routine}({args});")


op("movsb", "movsw", "movsd", "cmpsb", "cmpsw", "cmpsd", "stosb", "stosw", "stosd", "lodsb", "lodsw", "lodsd",
   "scasb", "scasw", "scasd")(string_op)
