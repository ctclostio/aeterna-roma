"""Lifts one function to C (see docs/lifted_tier.md, "Lifted side").

The generated function is a dispatch switch over guest instruction addresses
with one label per instruction:

    void lifted_<entry>(lift_ctx *c) {
    dispatch:
        switch (c->eip) { case <addr>: goto L_<addr>; ... default: goto leave; }
    leave:
        lift_leave(c);       /* call event + stub, or the end of the trial */
        goto dispatch;
    L_<addr>: LIFT_I(<addr>, <k>) <statements>
        ...
    }

Instruction semantics come from the handler registry in the ops package; an
instruction without a handler goes to the x87/SIMD thunk family, and what that
cannot take either becomes LIFT_UNSUPPORTED and is reported. The text depends
only on the function's bytes and metadata (thunk names are derived from thunk
bytes), so it can be hashed per function.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import ops
from ops.thunks import lift_thunk


@dataclass
class Lifted:
    entry: int
    code: str                                   # C text of lifted_<entry>
    n_insn: int
    addrs: list[int]                            # instruction addresses; coverage index k -> addrs[k]
    thunks: dict[str, tuple[bytes, int]]        # name -> (code bytes, LIFT_TF_* flags)
    unsupported: list[tuple[int, str, str, str]] = field(default_factory=list)  # (addr, mnemonic, hex bytes, reason)


def function_name(entry: int) -> str:
    return f"lifted_{entry:08x}"


def lift_function(meta) -> Lifted:
    insns = meta.insns
    entry = meta.fn.addr
    starts = {ins.address for ins in insns}
    e = ops.Emitter(starts)
    unsupported = []
    out = [f"void {function_name(entry)}(lift_ctx *c) {{", "dispatch:", "    switch (c->eip) {"]
    out += [f"    case 0x{ins.address:08x}u: goto L_{ins.address:08x};" for ins in insns]
    out += ["    default: goto leave;", "    }", "leave:", "    lift_leave(c);", "    goto dispatch;"]

    last = len(insns) - 1
    for k, cs in enumerate(insns):
        addr = cs.address
        end = addr + cs.size
        e.begin()
        stub = meta.stubs.get(addr)
        if stub is not None:
            e.line(f"lift_stub_insn(c, {stub[1]}u);")
        else:
            try:
                i = ops.Ins(cs)
                ops.REGISTRY.get(i.mnem, lift_thunk)(e, i)
            except ops.Unsupported as why:
                reason = str(why)
            except (KeyError, IndexError, ValueError, AttributeError) as error:
                reason = f"handler error: {type(error).__name__}: {error}"
            else:
                reason = None
            if reason is not None:
                unsupported.append((addr, cs.mnemonic, bytes(cs.bytes).hex(), reason))
                e.begin()
                e.line(f"LIFT_UNSUPPORTED(0x{addr:08x}u);")
                e.fallthrough = False
        # Control that runs off this instruction continues at `end`; say so
        # unless the next label is exactly there.
        if e.fallthrough and (k == last or insns[k + 1].address != end):
            e.line(e.goto(end))
        body = " ".join(e.body)
        if e.block:
            body = "{ " + body + " }"
        out.append(f"L_{addr:08x}: LIFT_I(0x{addr:08x}u, {k}) {body}")
    out.append("}")
    if meta.undecoded:
        unsupported.append((entry, "(undecoded)", "", f"{meta.undecoded} bytes of the body did not decode"))
    return Lifted(entry=entry, code="\n".join(out) + "\n", n_insn=len(insns), addrs=[ins.address for ins in insns],
                  thunks=e.thunks, unsupported=unsupported)
