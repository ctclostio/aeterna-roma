"""Functions the live runner needs that are not in the 81,280-row inventory.

The inventory (work/binary_contracts/) does not cover every byte of code the
image executes: most static initializers and some CRT helpers have no row.
When the live runner reaches such an address, its body is found here by
following control flow from the entry, and recorded in
port/lifted_live/extra_functions.tsv so the build lifts it like any other
function. These rows are not part of the inventory and are never counted in it.

    python scripts/lift/live_extra.py add 116a1af6 [...]   discover these entries and what they call
    python scripts/lift/live_extra.py initterm             seed from the static-initializer tables
    python scripts/lift/live_extra.py relocs               seed from the image's relocations (see reloc_targets)
    python scripts/lift/live_extra.py relocs --list        print what `relocs` would seed, and change nothing
    python scripts/lift/live_extra.py tables               print the rows that are a table, not code (see table_rows)
    python scripts/lift/live_extra.py tables --drop        and take them out of the table

A run that reaches code nothing lifts stops there, the address is added and the run is repeated: one address for each
run. `relocs` finds, without a run, the addresses of that kind that the image itself names.
"""
from __future__ import annotations

import bisect
import csv
import hashlib
import struct
import sys
from functools import lru_cache

from capstone import x86_const as X

from image import IMAGE_BASE, ROOT, Function, load_functions, load_image, parse_ranges
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

    A path ends at a return, at an indirect jump that is not a jump table,
    where it runs or jumps into a function that is already known, and at bytes
    that a relocation marks as an address: no instruction begins there, it is a
    table kept in the code section (reached after a call that does not return).
    """
    image, md, marked = load_image(), _decoder(), relocations()
    size_of: dict[int, int] = {}
    calls: set[int] = set()
    work = [entry]

    def known(addr: int) -> bool:
        return addr != entry and (in_any_function(addr) or addr in known_entries)

    while work:
        addr = work.pop()
        while addr not in size_of and 0 <= addr - IMAGE_BASE < len(image) and not known(addr) and addr not in marked:
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


def sections(image: bytes) -> list[tuple[int, int, bool]]:
    """(lo, hi_exclusive, executable) of each section, from the headers the mapped image keeps."""
    pe, = struct.unpack_from("<I", image, 0x3C)
    count, = struct.unpack_from("<H", image, pe + 6)
    table = pe + 24 + struct.unpack_from("<H", image, pe + 20)[0]
    out = []
    for at in range(table, table + 40 * count, 40):
        size, rva = struct.unpack_from("<II", image, at + 8)
        out.append((IMAGE_BASE + rva, IMAGE_BASE + rva + size, bool(struct.unpack_from("<I", image, at + 36)[0] & 0x20000000)))
    return out


@lru_cache(maxsize=1)
def relocations() -> dict[int, int]:
    """site -> the address its 4 bytes hold, for each IMAGE_REL_BASED_HIGHLOW entry of the image's base relocation table."""
    image = load_image()
    pe, = struct.unpack_from("<I", image, 0x3C)
    rva, size = struct.unpack_from("<II", image, pe + 24 + 96 + 8 * 5)  # PE32 data directory 5
    out, at = {}, rva
    while at < rva + size:
        page, block = struct.unpack_from("<II", image, at)
        if block < 8:
            break
        for entry, in struct.iter_unpack("<H", image[at + 8:at + block]):
            if entry >> 12 == 3:
                out[IMAGE_BASE + page + (entry & 0xFFF)], = struct.unpack_from("<I", image, page + (entry & 0xFFF))
        at += block
    return out


RELOC_KINDS = ("pointer", "case", "operand")


def reloc_targets(rows) -> dict[int, str]:
    """Code that the image's relocations name and nothing lifts: address -> how the address is held.

    A relocation marks 4 bytes of the image as an address. Where that address is in the code section and outside
    every lifted range (the inventory's and those of rows), a run that gets there stops. Three ways of holding it
    are taken, each of which is a way for execution to get there:
      pointer  the 4 bytes are outside the code section: a vtable slot, a table of handlers. Nearly all of these are
               the thunks that adjust `this` before a jump to the method (sub ecx, n / jmp), which the inventory
               does not list;
      case     the 4 bytes are a slot of a jump table that lifted code jumps through (jmp [reg*4 + table]). The
               slots are read from the table's address for as long as each is itself a relocation that holds a
               code address: the blocks of a switch whose function the inventory ends before them;
      operand  the 4 bytes are the immediate of an instruction of lifted code: push offset handler.
    Not taken: an address that lifted code holds as a displacement (a jump table or the byte table that indexes
    one: data kept in the code section), and anything named only by code that is not lifted.

    What is not checked is that the bytes there are code. Nothing but a pointer to data kept in the code section
    would not be, and `relocs --list` shows the first instructions of each for a look before they are added.
    """
    image, md = load_image(), _decoder()
    code = [(lo, hi) for lo, hi, executable in sections(image) if executable]

    def in_code(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in code)

    held = {site: target for site, target in relocations().items() if in_code(target)}
    spans = sorted({r for f in load_functions() for r in f.ranges} | {r for ranges, _ in rows.values() for r in ranges})
    union: list[list[int]] = []
    for lo, hi in spans:
        if union and lo <= union[-1][1]:
            union[-1][1] = max(union[-1][1], hi)
        else:
            union.append([lo, hi])
    starts = [lo for lo, _ in union]
    found: dict[int, str] = {}

    def take(target: int, kind: str) -> None:
        i = bisect.bisect_right(starts, target) - 1
        if i < 0 or target >= union[i][1]:
            found.setdefault(target, kind)

    sites = sorted(held)
    for site in sites:
        if not in_code(site):
            take(held[site], "pointer")
    for lo, hi in spans:
        i = bisect.bisect_left(sites, lo)
        if i == len(sites) or sites[i] >= hi:
            continue  # no instruction of this range holds such an address
        for ins in md.disasm(image[lo - IMAGE_BASE:hi - IMAGE_BASE], lo):
            if ins.imm_size == 4 and ins.address + ins.imm_offset in held:
                take(held[ins.address + ins.imm_offset], "operand")
            if ins.id == X.X86_INS_JMP and ins.disp_size == 4 and ins.address + ins.disp_offset in held:
                mem = ins.operands[0].mem
                if ins.operands[0].type == X.X86_OP_MEM and mem.base == 0 and mem.index != 0 and mem.scale == 4:
                    slot = held[ins.address + ins.disp_offset]
                    while slot in held:
                        take(held[slot], "case")
                        slot += 4
    return found


def table_rows(rows) -> list[int]:
    """Rows that are not code: the entry's first byte is one of the 4 that a relocation marks as an address.

    No instruction begins there. Such a row is a jump table kept in the code section, taken for a function because
    lifted code names its address (as the displacement of jmp [reg*4 + table]) and lifted as whatever its bytes
    decode to.
    """
    marked = relocations()
    return sorted(entry for entry in rows if any(entry - back in marked for back in range(4)))


def first_instructions(addr: int, count: int = 3) -> str:
    image = load_image()
    return "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in _decoder().disasm(image[addr - IMAGE_BASE:addr - IMAGE_BASE + 48], addr, count))


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
    elif argv == ["relocs", "--list"]:
        found = reloc_targets(load_rows())
        for entry, kind in sorted(found.items()):
            print(f"{entry:08x}\t{kind}\t{first_instructions(entry)}")
        print(f"{len(found)} addresses: " + ", ".join(f"{sum(k == kind for k in found.values())} {kind}" for kind in RELOC_KINDS))
        return 0
    elif argv in (["tables"], ["tables", "--drop"]):
        rows = load_rows()
        found = table_rows(rows)
        for entry in found:
            print(f"{entry:08x}\t{rows[entry][1]}\t{first_instructions(entry)}")
        if found and argv[1:]:
            save_rows({entry: row for entry, row in rows.items() if entry not in found})
        print(f"{len(found)} of {len(rows)} rows are tables{', dropped' if found and argv[1:] else ''}")
        return 0
    elif argv == ["relocs"]:
        added = []
        while True:  # lifted code names more code: until a pass adds nothing
            found = reloc_targets(load_rows())
            new = [e for kind in RELOC_KINDS for e in add([e for e, k in found.items() if k == kind], kind)]
            if not new:
                break
            added += new
            print(f"pass: {len(found)} addresses named, {len(new)} rows added")
    else:
        print(__doc__)
        return 1
    rows = load_rows()
    print(f"added {len(added)}; {len(rows)} extra functions, {sum(hi - lo for r, _ in rows.values() for lo, hi in r)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
