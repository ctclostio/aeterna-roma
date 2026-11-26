"""Compares the lifted DLL start-up with the original DLL's.

    python scripts/lift/compare_orig.py

Runs DLL_PROCESS_ATTACH twice: the game's own 32-bit empire.retail.dll in
port/lifted_live/orig32.c, and the lifted code in live.exe (build it first:
build_live.py). Compares

  calls   every call through the import table, in order: which import and
          from which return address
  memory  the image's writable sections afterwards, dword by dword. Values
          that differ are explained only when both are addresses of the same
          kind (heap/stack on both sides, or another module on both sides),
          or the process or thread id; everything else is counted as a
          difference and listed.

The result goes to port/lifted_live/verify_init.json. Exit status 0 means the
comparison ran, not that the two agree: read the report.
"""
from __future__ import annotations

import difflib
import json
import struct
import subprocess
import sys
from array import array

import toolchain
from build_live import LIVE_DIR, OUT
from image import IMAGE_PATH

PREFERRED = 0x10000000
RESULT = LIVE_DIR / "verify_init.json"
CLASS = ("not an address", "image", "heap/stack", "other module")


def import_names(image: bytes) -> dict[int, str]:
    """Import-table slot RVA -> dll!name, from the mapped image."""
    u32 = lambda off: struct.unpack_from("<I", image, off)[0]
    text = lambda off: image[off:image.index(b"\0", off)].decode("ascii")
    names, desc = {}, u32(u32(0x3C) + 24 + 96 + 8)
    while u32(desc + 12):
        dll, lookup, iat = text(u32(desc + 12)), u32(desc) or u32(desc + 16), u32(desc + 16)
        while value := u32(lookup):
            names[iat] = f"{dll}!{'#%d' % (value & 0xFFFF) if value >> 31 else text(value + 2)}"
            lookup, iat = lookup + 4, iat + 4
        desc += 20
    return names


def read_trace(path) -> array:
    words = array("I")
    words.frombytes(path.read_bytes())
    return words


def read_mem(path) -> dict:
    data = path.read_bytes()
    magic, base, result, pid, tid, count = struct.unpack_from("<4sIIIII", data, 0)
    if magic != b"LMEM":
        raise SystemExit(f"{path} is not a memory record")
    table = [struct.unpack_from("<II", data, 24 + 8 * i) for i in range(count)]
    off, sections = 24 + 8 * count, []
    for rva, size in table:
        words = array("I")
        words.frombytes(data[off:off + size])
        sections.append((rva, words, data[off + size:off + size + size // 4]))
        off += size + size // 4
    return {"base": base, "result": result, "ids": {pid, tid}, "sections": sections}


def compare_calls(orig: array, lifted: array, names: dict[int, str]) -> dict:
    n_orig, n_lifted = len(orig) // 2, len(lifted) // 2
    same = min(len(orig), len(lifted))
    first = next((i // 2 for i in range(0, same, 2) if orig[i] != lifted[i] or orig[i + 1] != lifted[i + 1]), None)
    if first is None and n_orig != n_lifted:
        first = same // 2
    out = {"original_calls": n_orig, "lifted_calls": n_lifted, "identical": first is None, "first_difference": first}
    print(f"calls through the import table: original {n_orig}, lifted {n_lifted}")
    if first is None:
        print("  identical: same imports, same order, same return addresses")
        return out
    pairs = lambda t: [(t[i], t[i + 1]) for i in range(0, len(t), 2)]
    blocks = [op for op in difflib.SequenceMatcher(None, pairs(orig), pairs(lifted), autojunk=False).get_opcodes() if op[0] != "equal"]
    out["differing_stretches"] = len(blocks)
    out["calls_in_differing_stretches"] = {"original": sum(b[2] - b[1] for b in blocks), "lifted": sum(b[4] - b[3] for b in blocks)}
    print(f"  {len(blocks)} differing stretches: {out['calls_in_differing_stretches']['original']} original calls, "
          f"{out['calls_in_differing_stretches']['lifted']} lifted calls")
    print(f"  FIRST DIFFERENCE at call {first}")
    show = lambda t, i: f"{names.get(t[2 * i], hex(t[2 * i]))} from {t[2 * i + 1]:08x}" if i < len(t) // 2 else "(end)"
    for i in range(max(0, first - 4), first + 5):
        mark = "  " if i < first else "!="
        print(f"  {i:8d} {mark} original {show(orig, i):58s} lifted {show(lifted, i)}")
    out["context"] = [{"call": i, "original": show(orig, i), "lifted": show(lifted, i)} for i in range(max(0, first - 4), first + 5)]
    return out


def stack_cookie(orig: dict, lifted: dict, cookie_rva: int) -> tuple[set, set]:
    """The loader's random stack cookie and its complement, as each side holds them."""
    def values(mem):
        for rva, words, _ in mem["sections"]:
            if rva <= cookie_rva < rva + 4 * len(words):
                v = words[(cookie_rva - rva) // 4]
                return {v, v ^ 0xFFFFFFFF}
        return set()
    return values(orig), values(lifted)


def partial_image_address(va: int, vb: int, delta: int) -> bool:
    """The upper 1-3 bytes are what is left of an image address whose lower bytes were overwritten with the same
    data on both sides (a short string stored over an old pointer): the lifted value's upper bytes lie in the image
    and the original's are those bytes rebased."""
    for low in (1, 2, 3):
        shift = 8 * low
        if (va ^ vb) & ((1 << shift) - 1) == 0:
            hi_o, hi_l, moved = va >> shift, vb >> shift, (-delta & 0xFFFFFFFF) >> shift
            if PREFERRED >> shift <= hi_l <= (PREFERRED + 0x2300000) >> shift and hi_o - hi_l in (moved, moved + 1):
                return True
    return False


def compare_memory(title: str, orig: dict, lifted: dict, cookies: tuple[set, set], origin: int) -> dict:
    """origin: what a region's key is relative to (the image base for sections, 0 for allocations)."""
    counts = {"equal": 0, "image_address_rebased": 0, "image_address_partly_overwritten": 0, "heap_or_stack_address_pair": 0,
              "other_module_address_pair": 0, "process_or_thread_id": 0, "stack_cookie": 0, "different": 0}
    delta, different = PREFERRED - orig["base"], []
    cookie_o, cookie_l = cookies
    if len(orig["sections"]) != len(lifted["sections"]):
        raise SystemExit(f"{title}: the two records list different regions")
    for (rva, a, ca), (rva_l, b, cb) in zip(orig["sections"], lifted["sections"]):
        if rva != rva_l or len(a) != len(b):
            raise SystemExit(f"{title}: the two records list different regions")
        for i, (va, vb) in enumerate(zip(a, b)):
            if va == vb:
                counts["equal"] += 1
            elif ca[i] == cb[i] == 1 and (va + delta) & 0xFFFFFFFF == vb:
                counts["image_address_rebased"] += 1  # the original was loaded at another base
            elif va in cookie_o and vb in cookie_l:
                counts["stack_cookie"] += 1
            elif partial_image_address(va, vb, delta):
                counts["image_address_partly_overwritten"] += 1
            elif ca[i] == cb[i] == 2:
                counts["heap_or_stack_address_pair"] += 1
            elif ca[i] == cb[i] == 3:
                counts["other_module_address_pair"] += 1
            elif va in orig["ids"] and vb in lifted["ids"]:
                counts["process_or_thread_id"] += 1
            else:
                counts["different"] += 1
                different.append((origin + rva + 4 * i, va, vb, ca[i], cb[i]))
    runs = []
    for item in different:  # a run: differing dwords at most 16 bytes apart
        if runs and item[0] - runs[-1][-1][0] <= 16:
            runs[-1].append(item)
        else:
            runs.append([item])
    total = sum(counts.values())
    print(f"{title}: {total} dwords in {len(orig['sections'])} regions")
    for key, value in counts.items():
        print(f"  {key.replace('_', ' '):28s} {value:9d}")
    print(f"  the differing dwords form {len(runs)} runs; first 30:")
    for run in runs[:30]:
        addr, va, vb, ca, cb = run[0]
        print(f"    {addr:08x} x{len(run):<5d} original {va:08x} ({CLASS[ca]}), lifted {vb:08x} ({CLASS[cb]})")
    return {"dwords": total, **counts, "difference_runs": len(runs),
            "first_runs": [{"address": f"{r[0][0]:08x}", "dwords": len(r), "original": f"{r[0][1]:08x}", "lifted": f"{r[0][2]:08x}"}
                           for r in runs[:40]]}


def main() -> int:
    game_dir = IMAGE_PATH.parent
    orig32 = OUT / "orig32.exe"
    try:
        toolchain.run_tool(["cl", "/nologo", "/TC", "/W3", "/O2", "/arch:IA32", "/guard:cf-", "/GS-", "/D_CRT_SECURE_NO_WARNINGS",
                            f"/Fo{OUT / 'orig32.obj'}", f"/Fe{orig32}", str(LIVE_DIR / "orig32.c"),
                            # At 0x00400000 like Rome2.exe, so that range is taken in both processes.
                            "/link", "/DYNAMICBASE:NO", "/FIXED"], cwd=OUT, arch="x86")
    except toolchain.BuildError as error:
        print(str(error)[-4000:], file=sys.stderr)
        return 1
    for name in ("orig.trace", "orig.mem", "orig.heap", "orig.env", "orig.valloc", "lifted.trace", "lifted.mem", "lifted.heap"):
        (OUT / name).unlink(missing_ok=True)
    ref = subprocess.run([str(orig32), str(game_dir), str(OUT / "orig")], capture_output=True, text=True, errors="replace", timeout=600)
    print((ref.stdout + ref.stderr).strip())
    if ref.returncode != 0 or not (OUT / "orig.mem").exists():
        print(f"orig32 failed (exit {ref.returncode})", file=sys.stderr)
        return 1
    run = subprocess.run([str(OUT / "live.exe"), "--image", str(OUT / "image.bin"), "--game-dir", str(game_dir),
                          "--record", str(OUT / "lifted"), "--mirror", str(OUT / "orig.env"),
                          "--place", str(OUT / "orig.valloc")],
                         capture_output=True, text=True, errors="replace", timeout=1800)
    (OUT / "last_compare_run.txt").write_text(run.stdout + run.stderr, encoding="utf-8", newline="\n")
    print("\n".join(line for line in (run.stdout + run.stderr).splitlines() if line.startswith(("STOP", "  eip", "instructions exec"))))
    if not (OUT / "lifted.mem").exists():
        print("live.exe wrote no record", file=sys.stderr)
        return 1

    orig, lifted = read_mem(OUT / "orig.mem"), read_mem(OUT / "lifted.mem")
    image = (OUT / "image.bin").read_bytes()
    u32 = lambda off: struct.unpack_from("<I", image, off)[0]
    cookie_rva = u32(u32(u32(0x3C) + 24 + 96 + 8 * 10) + 60) - PREFERRED  # load configuration: SecurityCookie
    print(f"DLL entry returned: original {orig['result']}, lifted {lifted['result']}; original loaded at {orig['base']:08x}")
    result = {"entry_result": {"original": orig["result"], "lifted": lifted["result"]},
              "original_base": f"{orig['base']:08x}",
              "calls": compare_calls(read_trace(OUT / "orig.trace"), read_trace(OUT / "lifted.trace"), import_names(image))}
    cookies = stack_cookie(orig, lifted, cookie_rva)
    result["memory"] = compare_memory("writable sections after start-up", orig, lifted, cookies, PREFERRED)
    result["engine_heap"] = compare_memory("VirtualAlloc regions after start-up", read_mem(OUT / "orig.heap"),
                                           read_mem(OUT / "lifted.heap"), cookies, 0)
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
