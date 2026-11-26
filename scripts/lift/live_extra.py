"""Functions the live runner needs that are not in the 81,280-row inventory.

The inventory (work/binary_contracts/) does not cover every byte of code the
image executes: most static initializers and some CRT helpers have no row.
When the live runner reaches such an address, its body is found here by
following control flow from the entry, and recorded in
port/lifted_live/extra_functions.tsv so the build lifts it like any other
function. These rows are not part of the inventory and are never counted in it.

    python scripts/lift/live_extra.py add 116a1af6 [...]   discover these entries and what they call
    python scripts/lift/live_extra.py initterm             seed from the static-initializer tables
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys

from capstone import x86_const as X

from image import IMAGE_BASE, ROOT, Function, load_image, parse_ranges
from meta import _decoder, in_any_function

TABLE = ROOT / "port" / "lifted_live" / "extra_functions.tsv"
STARTUP_SLOTS = ROOT / "port" / "startup_audit" / "startup_slots.tsv"
ENDS = frozenset({X.X86_INS_RET, X.X86_INS_RETF, X.X86_INS_IRETD, X.X86_INS_INT3, X.X86_INS_HLT, X.X86_INS_UD2})
BRANCHES = frozenset({X.X86_INS_LOOP, X.X86_INS_LOOPE, X.X86_INS_LOOPNE, X.X86_INS_JECXZ, X.X86_INS_JCXZ})
JUMP_TABLE_MAX = 1024
JUMP_TABLE_REACH = 0x10000


def load_rows() -> dict[int, tuple[tuple[tuple[int, int], ...], str]]:
    """entry -> (ranges, found_by)."""
    if not TABLE.exists():
        return {}
    with open(TABLE, newline="", encoding="utf-8") as fh:
        return {int(r["address"], 16): (parse_ranges(r["body_ranges"]), r["found_by"])
                for r in csv.DictReader(fh, delimiter="\t")}


def load_extra() -> list[Function]:
    image = load_image()
    out = []
    for entry, (ranges, _) in sorted(load_rows().items()):
        digest = hashlib.sha256(b"".join(image[lo - IMAGE_BASE:hi - IMAGE_BASE] for lo, hi in ranges)).hexdigest()
        out.append(Function(addr=entry, name=f"extra_{entry:08x}", ranges=ranges, sha256=digest, pop_bytes=0, fp_ret=False))
    return out


def save_rows(rows) -> None:
    lines = ["address\tbody_ranges\tfound_by"]
    for entry, (ranges, why) in sorted(rows.items()):
        lines.append(f"{entry:08x}\t{';'.join(f'{lo:08x}-{hi - 1:08x}' for lo, hi in ranges)}\t{why}")
    TABLE.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")


def discover(entry: int, known_entries=()) -> tuple[tuple[tuple[int, int], ...], set[int]]:
    """(body ranges, direct call targets) of the code reachable from entry without leaving it.

    A path ends at a return, at an indirect jump that is not a jump table, and
    where it runs or jumps into a function that is already known.
    """
    image, md = load_image(), _decoder()
    size_of: dict[int, int] = {}
    calls: set[int] = set()
    work = [entry]

    def known(addr: int) -> bool:
        return addr != entry and (in_any_function(addr) or addr in known_entries)

    while work:
        addr = work.pop()
        while addr not in size_of and 0 <= addr - IMAGE_BASE < len(image) and not known(addr):
            ins = next(md.disasm(image[addr - IMAGE_BASE:addr - IMAGE_BASE + 15], addr, 1), None)
            if ins is None:
                break
            size_of[addr] = ins.size
            op = ins.operands[0] if ins.operands else None
            target = op.imm & 0xFFFFFFFF if op is not None and op.type == X.X86_OP_IMM else None
            if ins.id in ENDS:
                break
            if ins.id == X.X86_INS_CALL:
                if target is not None:
                    calls.add(target)
            elif ins.id == X.X86_INS_JMP:
                if target is not None:
                    work.append(target)
                elif op.type == X.X86_OP_MEM and op.mem.base == 0 and op.mem.index != 0 and op.mem.scale == 4:
                    table = (op.mem.disp & 0xFFFFFFFF) - IMAGE_BASE
                    for i in range(JUMP_TABLE_MAX):
                        if not 0 <= table + 4 * i <= len(image) - 4:
                            break
                        case, = struct.unpack_from("<I", image, table + 4 * i)
                        if abs(case - entry) >= JUMP_TABLE_REACH or known(case):
                            break
                        work.append(case)
                break
            elif target is not None and (ins.id in BRANCHES or X.X86_GRP_JUMP in ins.groups):
                work.append(target)
            addr += ins.size
    ranges: list[list[int]] = []
    for addr in sorted(size_of):
        if ranges and ranges[-1][1] == addr:
            ranges[-1][1] = addr + size_of[addr]
        else:
            ranges.append([addr, addr + size_of[addr]])
    return tuple((lo, hi) for lo, hi in ranges), calls


def add(entries, why: str) -> list[int]:
    """Discovers the entries and, transitively, the unknown functions they call. Returns what was added."""
    rows = load_rows()
    image_size = len(load_image())
    added = []
    work = [(e, why) for e in entries]
    while work:
        entry, reason = work.pop()
        if entry in rows or not 0 <= entry - IMAGE_BASE < image_size:
            continue
        ranges, calls = discover(entry, rows)
        if not ranges:
            continue
        rows[entry] = (ranges, reason)
        added.append(entry)
        work += [(t, "call") for t in calls if t not in rows and not in_any_function(t)]
    if added:
        save_rows(rows)
    return added


def initterm_targets() -> list[int]:
    with open(STARTUP_SLOTS, newline="", encoding="utf-8") as fh:
        return [int(r["raw_target_va"], 16) for r in csv.DictReader(fh, delimiter="\t")
                if r["is_null"] == "no" and r["target_executable"] == "yes"]


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["initterm"]:
        added = add([t for t in initterm_targets() if not in_any_function(t)], "initterm")
    elif argv[:1] == ["add"] and len(argv) > 1:
        added = add([int(a, 16) for a in argv[1:]], "run")
    else:
        print(__doc__)
        return 1
    rows = load_rows()
    print(f"added {len(added)}; {len(rows)} extra functions, {sum(hi - lo for r, _ in rows.values() for lo, hi in r)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
