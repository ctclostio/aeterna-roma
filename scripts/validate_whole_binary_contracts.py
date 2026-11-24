#!/usr/bin/env python3
"""Fail-closed pure-stdlib validator for `work/binary_contracts/`.

Supports two modes:
- `--public-only` (CI mode without the copyrighted game image): verifies manifest
  hashes, file size limits (< 25 MB), schema/invariant integrity across all 81,280
  functions, 9,639 vtables, 181 RTTI descriptors, class field layouts, globals,
  and full reconciliation against curated `port/recovered_types/contracts.json`.
- Full PE verification (default when `Total War Rome II/empire.retail.dll` is
  present): additionally re-hashes all 81,280 function bodies, checks every
  function's exact machine exit instruction encoding/target, re-hashes all 9,639
  vtables, re-hashes all 181 RTTI descriptors & 15 COLs, and checks every global's
  PE initial bytes and storage classification.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from type_recovery_contracts import IMAGE_SHA256, IMAGE_SIZE, image_bytes, parse_pe32

CONTRACTS_DIR = ROOT / "work" / "binary_contracts"
DLL_PATH = ROOT / "Total War Rome II" / "empire.retail.dll"
CURATED_CONTRACTS = ROOT / "port" / "recovered_types" / "contracts.json"
HIER_IN = ROOT / "work" / "indirect_call_hierarchy_after.tsv"
VTABLES_IN = ROOT / "work" / "indirect_call_vtables_after.tsv"

MAX_FILE_BYTES = 25 * 1024 * 1024
_HEX8_RE = re.compile(r"^[0-9a-f]{8}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_VA0X_RE = re.compile(r"^0x[0-9a-f]{8}$")
_OFF_RE = re.compile(r"^0x[0-9a-f]+$")
_VALID_CCS = {"thiscall", "cdecl", "stdcall", "fastcall", "unknown"}
_VALID_EXITS = {
    "ret",
    "bnd_ret",
    "tail_jmp_rel32",
    "tail_jmp_rel8",
    "tail_jmp_iat",
    "tail_jmp_global",
    "tail_jmp_indirect",
    "noreturn_call_rel32",
    "noreturn_call_iat",
    "trap_int3",
    "fallthrough_stub",
}
_VALID_STORAGES = {"file", "zero_fill", "file_and_zero_fill"}


def _parse_and_check_ranges(rng_str: str, expected_bytes: int, entry_hex: str) -> list[tuple[int, int]]:
    if not rng_str:
        raise ValueError(f"empty body_ranges for {entry_hex}")
    ranges: list[tuple[int, int]] = []
    prev_end = -1
    for seg in rng_str.split(";"):
        parts = seg.split("-")
        if len(parts) != 2 or not _HEX8_RE.match(parts[0]) or not _HEX8_RE.match(parts[1]):
            raise ValueError(f"malformed range segment in {entry_hex}: {seg!r}")
        s, e = int(parts[0], 16), int(parts[1], 16)
        if s > e or s <= prev_end:
            raise ValueError(f"unordered or overlapping ranges in {entry_hex}: {rng_str}")
        ranges.append((s, e))
        prev_end = e
    total = sum(e - s + 1 for s, e in ranges)
    if total != expected_bytes:
        raise ValueError(f"body_ranges size sum {total} != bytes {expected_bytes} for {entry_hex}")
    entry_va = int(entry_hex, 16)
    if not any(s <= entry_va <= e for s, e in ranges):
        raise ValueError(f"entry {entry_hex} outside body_ranges {rng_str}")
    return ranges


def _verify_pe_function_exit(
    parts: list[tuple[int, bytes]],
    ranges: list[tuple[int, int]],
    row: dict,
    image: bytes,
    base: int,
    sections: list[tuple[int, int, int, int]],
) -> None:
    addr = row["address"]
    ekind = row["exit_kind"]
    pop = int(row["callee_pop_bytes"])
    eaddrs = [int(a, 16) for a in row["exit_addresses"].split(";") if a]
    etarget = int(row["exit_target"], 16) if row["exit_target"] else None

    if ekind in ("ret", "bnd_ret"):
        for pc in eaddrs:
            part_data = next((d[pc - s:] for s, d in parts if s <= pc < s + len(d)), b"")
            if ekind == "bnd_ret":
                if pop == 0 and part_data[:2] == b"\xf2\xc3":
                    continue
                if len(part_data) >= 4 and part_data[:2] == b"\xf2\xc2" and struct.unpack_from("<H", part_data, 2)[0] == pop:
                    continue
            else:
                if pop == 0 and (part_data[:1] == b"\xc3" or part_data[:2] == b"\xf2\xc3"):
                    continue
                if len(part_data) >= 3 and part_data[:1] == b"\xc2" and struct.unpack_from("<H", part_data, 1)[0] == pop:
                    continue
                if len(part_data) >= 4 and part_data[:2] == b"\xf2\xc2" and struct.unpack_from("<H", part_data, 2)[0] == pop:
                    continue
            raise ValueError(f"PE return bytes disagree at 0x{pc:08x} in {addr} (kind={ekind}, pop={pop})")
        return

    pc = eaddrs[0]
    tail_bytes = next((d[pc - s:] for s, d in parts if s <= pc < s + len(d)), b"")
    unpref = tail_bytes[1:] if tail_bytes[:1] == b"\xf2" else tail_bytes
    pref_len = 1 if tail_bytes[:1] == b"\xf2" else 0

    if ekind == "tail_jmp_rel32":
        if len(unpref) < 5 or unpref[0] != 0xE9:
            raise ValueError(f"tail_jmp_rel32 opcode mismatch at 0x{pc:08x} in {addr}")
        actual_tgt = (pc + pref_len + 5 + struct.unpack_from("<i", unpref, 1)[0]) & 0xFFFFFFFF
        if actual_tgt != etarget:
            raise ValueError(f"tail_jmp_rel32 target mismatch in {addr}: {actual_tgt:08x} != {etarget}")
    elif ekind == "tail_jmp_rel8":
        if len(unpref) < 2 or unpref[0] != 0xEB:
            raise ValueError(f"tail_jmp_rel8 opcode mismatch at 0x{pc:08x} in {addr}")
        actual_tgt = (pc + pref_len + 2 + struct.unpack_from("<b", unpref, 1)[0]) & 0xFFFFFFFF
        if actual_tgt != etarget:
            raise ValueError(f"tail_jmp_rel8 target mismatch in {addr}")
    elif ekind in ("tail_jmp_iat", "tail_jmp_global"):
        if len(unpref) < 6 or unpref[:2] != b"\xff\x25":
            raise ValueError(f"{ekind} opcode mismatch at 0x{pc:08x} in {addr}")
        actual_slot = struct.unpack_from("<I", unpref, 2)[0]
        if actual_slot != etarget:
            raise ValueError(f"{ekind} slot mismatch in {addr}")
    elif ekind == "tail_jmp_indirect":
        if len(unpref) < 2 or unpref[0] != 0xFF or ((unpref[1] >> 3) & 7) != 4:
            raise ValueError(f"tail_jmp_indirect ModRM mismatch at 0x{pc:08x} in {addr}")
    elif ekind == "noreturn_call_rel32":
        if len(tail_bytes) < 5 or tail_bytes[0] != 0xE8:
            raise ValueError(f"noreturn_call_rel32 opcode mismatch at 0x{pc:08x} in {addr}")
        actual_tgt = (pc + 5 + struct.unpack_from("<i", tail_bytes, 1)[0]) & 0xFFFFFFFF
        if actual_tgt != etarget:
            raise ValueError(f"noreturn_call_rel32 target mismatch in {addr}")
    elif ekind == "noreturn_call_iat":
        if len(tail_bytes) < 6 or tail_bytes[:2] != b"\xff\x15":
            raise ValueError(f"noreturn_call_iat opcode mismatch at 0x{pc:08x} in {addr}")
        actual_slot = struct.unpack_from("<I", tail_bytes, 2)[0]
        if actual_slot != etarget:
            raise ValueError(f"noreturn_call_iat slot mismatch in {addr}")
    elif ekind == "trap_int3":
        if tail_bytes[:1] != b"\xcc":
            raise ValueError(f"trap_int3 opcode mismatch at 0x{pc:08x} in {addr}")
    elif ekind == "fallthrough_stub":
        expected_next = ranges[-1][1] + 1
        if etarget != expected_next:
            raise ValueError(f"fallthrough_stub target mismatch in {addr}")
        image_bytes(image, base, sections, expected_next, 1)


def _read_tsv(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def validate_all(
    contracts_dir: Path = CONTRACTS_DIR,
    *,
    image_bytes_data: bytes | None = None,
    curated_path: Path | None = CURATED_CONTRACTS,
    hier_path: Path | None = HIER_IN,
    vtables_path: Path | None = VTABLES_IN,
) -> dict:
    """Validate all whole-binary contracts, optionally verifying raw PE bytes against `image_bytes_data`."""
    manifest_path = contracts_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "rome2-whole-binary-contracts-v1":
        raise ValueError("unknown whole-binary contracts schema")
    if manifest.get("image") != {"bytes": IMAGE_SIZE, "sha256": IMAGE_SHA256}:
        raise ValueError("manifest image target differs from pinned target")

    file_meta = manifest.get("files")
    expected_files = {
        "function_contracts_part1.tsv",
        "function_contracts_part2.tsv",
        "non_proc_curated_slots.tsv",
        "rtti_contracts.tsv",
        "vtable_class_contracts.tsv",
        "class_field_layouts.tsv",
        "global_contracts.tsv",
    }
    if not isinstance(file_meta, dict) or set(file_meta.keys()) != expected_files:
        raise ValueError("manifest files map incomplete or unexpected")

    # 1. Verify exact SHA-256 and < 25 MB size bound for every artifact in manifest
    for fname, meta in file_meta.items():
        fp = contracts_dir / fname
        if not fp.is_file():
            raise ValueError(f"missing contract artifact: {fname}")
        raw = fp.read_bytes()
        if len(raw) >= MAX_FILE_BYTES:
            raise ValueError(f"artifact exceeds 25 MB limit: {fname} ({len(raw)} bytes)")
        if len(raw) != meta["bytes"]:
            raise ValueError(f"artifact byte length mismatch: {fname}")
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise ValueError(f"artifact sha256 mismatch: {fname}")

    base = 0
    sections: list[tuple[int, int, int, int]] = []
    if image_bytes_data is not None:
        if len(image_bytes_data) != IMAGE_SIZE or hashlib.sha256(image_bytes_data).hexdigest() != IMAGE_SHA256:
            raise ValueError("original image differs from pinned target")
        base, sections = parse_pe32(image_bytes_data)

    # 2. Validate 81,280 function contracts across part1 + part2
    fn_rows = _read_tsv(contracts_dir / "function_contracts_part1.tsv") + _read_tsv(
        contracts_dir / "function_contracts_part2.tsv"
    )
    if len(fn_rows) != manifest["counts"]["canonical_functions"]:
        raise ValueError(f"function count {len(fn_rows)} != manifest {manifest['counts']['canonical_functions']}")

    fn_by_addr: dict[str, dict] = {}
    prev_va = -1
    for row in fn_rows:
        addr = row["address"]
        if not _HEX8_RE.match(addr):
            raise ValueError(f"invalid function address: {addr!r}")
        va = int(addr, 16)
        if va <= prev_va:
            raise ValueError(f"unsorted or duplicate function address: {addr}")
        prev_va = va

        if not _HEX64_RE.match(row["sha256"]):
            raise ValueError(f"invalid function sha256 at {addr}")
        nbytes = int(row["bytes"])
        if nbytes <= 0:
            raise ValueError(f"non-positive function size at {addr}")
        rngs = _parse_and_check_ranges(row["body_ranges"], nbytes, addr)

        cc = row["calling_convention"]
        rx = row["receiver_register"]
        if cc not in _VALID_CCS:
            raise ValueError(f"invalid calling_convention at {addr}: {cc}")
        expected_rx = "ECX" if cc == "thiscall" else ("ECX,EDX" if cc == "fastcall" else "none")
        if rx != expected_rx:
            raise ValueError(f"receiver_register {rx} disagrees with cc {cc} at {addr}")

        stack_bytes = int(row["stack_argument_bytes"])
        pop_bytes = int(row["callee_pop_bytes"])
        if stack_bytes < 0 or stack_bytes % 4 or pop_bytes < 0 or pop_bytes % 4 or pop_bytes > stack_bytes:
            raise ValueError(f"invalid x86 stack contract at {addr}: stack={stack_bytes}, pop={pop_bytes}")
        if cc == "cdecl" and pop_bytes != 0:
            raise ValueError(f"cdecl callee must not pop caller args at {addr}")

        ekind = row["exit_kind"]
        if ekind not in _VALID_EXITS:
            raise ValueError(f"invalid exit_kind at {addr}: {ekind}")
        eaddrs = [a for a in row["exit_addresses"].split(";") if a]
        if not eaddrs:
            raise ValueError(f"missing exit_addresses at {addr}")
        for ea in eaddrs:
            if not _VA0X_RE.match(ea):
                raise ValueError(f"malformed exit_address {ea!r} at {addr}")
            ev = int(ea, 16)
            if not any(s <= ev <= e for s, e in rngs):
                raise ValueError(f"exit_address {ea} outside body_ranges at {addr}")

        need_target = ekind in (
            "tail_jmp_rel32",
            "tail_jmp_rel8",
            "tail_jmp_iat",
            "tail_jmp_global",
            "noreturn_call_rel32",
            "noreturn_call_iat",
            "fallthrough_stub",
        )
        if need_target and not _VA0X_RE.match(row["exit_target"]):
            raise ValueError(f"missing or malformed exit_target for {ekind} at {addr}")
        if not need_target and row["exit_target"]:
            raise ValueError(f"unexpected exit_target for {ekind} at {addr}")

        if image_bytes_data is not None:
            parts = [(s, image_bytes(image_bytes_data, base, sections, s, e - s + 1)[0]) for s, e in rngs]
            actual_sha = hashlib.sha256(b"".join(d for _, d in parts)).hexdigest()
            if actual_sha != row["sha256"]:
                raise ValueError(f"PE body SHA-256 mismatch at function {addr}")
            _verify_pe_function_exit(parts, rngs, row, image_bytes_data, base, sections)

        fn_by_addr[addr] = row

    # 3. Validate non_proc_curated_slots.tsv
    np_rows = _read_tsv(contracts_dir / "non_proc_curated_slots.tsv")
    np_by_addr: dict[str, dict] = {}
    for row in np_rows:
        addr = row["address"]
        if not _HEX8_RE.match(addr) or addr in fn_by_addr or addr in np_by_addr:
            raise ValueError(f"invalid non_proc_curated_slot address: {addr}")
        nbytes = int(row["bytes"])
        rngs = _parse_and_check_ranges(row["body_ranges"], nbytes, addr)
        if image_bytes_data is not None:
            parts = [(s, image_bytes(image_bytes_data, base, sections, s, e - s + 1)[0]) for s, e in rngs]
            if hashlib.sha256(b"".join(d for _, d in parts)).hexdigest() != row["sha256"]:
                raise ValueError(f"PE body SHA-256 mismatch at non-proc slot {addr}")
        np_by_addr[addr] = row

    # 4. Validate RTTI contracts (181 TypeDescriptors + 15 COLs)
    rtti_rows = _read_tsv(contracts_dir / "rtti_contracts.tsv")
    if len(rtti_rows) != manifest["counts"]["rtti_type_descriptors"]:
        raise ValueError("rtti count disagrees with manifest")
    seen_td: set[str] = set()
    col_by_vt: dict[str, dict] = {}
    for rr in rtti_rows:
        td = rr["td_address"]
        if not _HEX8_RE.match(td) or td in seen_td or not rr["mangled_name"].startswith(".?A"):
            raise ValueError(f"invalid RTTI TypeDescriptor row: {td}")
        seen_td.add(td)
        td_bytes = int(rr["td_bytes"])
        if td_bytes <= 8 or not _HEX64_RE.match(rr["td_sha256"]):
            raise ValueError(f"invalid RTTI metadata at {td}")
        if rr["col_address"]:
            if not (_HEX8_RE.match(rr["col_address"]) and _HEX64_RE.match(rr["col_sha256"]) and _HEX8_RE.match(rr["vtable_address"])):
                raise ValueError(f"invalid RTTI COL fields at {td}")
            col_by_vt[rr["vtable_address"]] = rr
        if image_bytes_data is not None:
            td_va = int(td, 16)
            td_raw, _ = image_bytes(image_bytes_data, base, sections, td_va, td_bytes)
            if hashlib.sha256(td_raw).hexdigest() != rr["td_sha256"]:
                raise ValueError(f"PE RTTI TD sha256 mismatch at {td}")
            if rr["col_address"]:
                col_raw, _ = image_bytes(image_bytes_data, base, sections, int(rr["col_address"], 16), 20)
                if hashlib.sha256(col_raw).hexdigest() != rr["col_sha256"]:
                    raise ValueError(f"PE RTTI COL sha256 mismatch at {rr['col_address']}")

    # 5. Validate 9,639 vtable class contracts
    vt_rows = _read_tsv(contracts_dir / "vtable_class_contracts.tsv")
    if len(vt_rows) != manifest["counts"]["vtables"]:
        raise ValueError("vtable count disagrees with manifest")
    vt_by_addr: dict[str, dict] = {}
    prev_vt = -1
    for vr in vt_rows:
        vt = vr["vtable"]
        if not _HEX8_RE.match(vt):
            raise ValueError(f"invalid vtable address: {vt}")
        v_va = int(vt, 16)
        if v_va <= prev_vt:
            raise ValueError(f"unsorted or duplicate vtable: {vt}")
        prev_vt = v_va
        scnt = int(vr["slot_count"])
        if scnt <= 0 or not _HEX8_RE.match(vr["first_slot"]) or not _HEX64_RE.match(vr["vtable_bytes_sha256"]):
            raise ValueError(f"invalid vtable fields at {vt}")
        if vt in col_by_vt and vr["rtti_col_address"] != col_by_vt[vt]["col_address"]:
            raise ValueError(f"vtable {vt} missing RTTI COL link")
        if image_bytes_data is not None:
            vt_raw, _ = image_bytes(image_bytes_data, base, sections, v_va, scnt * 4)
            if hashlib.sha256(vt_raw).hexdigest() != vr["vtable_bytes_sha256"]:
                raise ValueError(f"PE vtable bytes sha256 mismatch at {vt}")
            if f"{struct.unpack_from('<I', vt_raw, 0)[0]:08x}" != vr["first_slot"]:
                raise ValueError(f"PE vtable first_slot mismatch at {vt}")
        vt_by_addr[vt] = vr

    # Cross-check against tracked indirect-call vtables & hierarchy inventory if present
    if hier_path and hier_path.is_file():
        inv_hier = {r["vtable"].lower().removeprefix("0x"): r for r in _read_tsv(hier_path)}
        if set(vt_by_addr.keys()) != set(inv_hier.keys()):
            raise ValueError("vtable set disagrees with indirect_call_hierarchy_after.tsv")
        for vt, hrow in inv_hier.items():
            if vt_by_addr[vt]["slot_count"] != hrow["slot_count"]:
                raise ValueError(f"vtable slot_count disagrees with hierarchy at {vt}")

    # 6. Validate class field layouts (all vtables exist and carry +0x0 vptr)
    cf_rows = _read_tsv(contracts_dir / "class_field_layouts.tsv")
    if len(cf_rows) != manifest["counts"]["class_field_entries"]:
        raise ValueError("class_field_entries count disagrees with manifest")
    seen_vt_off: set[tuple[str, int]] = set()
    vptr0_vts: set[str] = set()
    cf_counts: dict[str, int] = collections.Counter()
    for cr in cf_rows:
        vt = cr["vtable"]
        if vt not in vt_by_addr or not _OFF_RE.match(cr["offset"]):
            raise ValueError(f"invalid class field row: {cr}")
        off = int(cr["offset"], 16)
        w = int(cr["width"])
        if w <= 0 or (vt, off) in seen_vt_off:
            raise ValueError(f"duplicate or non-positive width field ({vt}, {cr['offset']})")
        seen_vt_off.add((vt, off))
        cf_counts[vt] += 1
        if off == 0 and cr["access_kind"] == "vptr":
            vptr0_vts.add(vt)
    if vptr0_vts != set(vt_by_addr.keys()):
        raise ValueError("one or more vtables missing +0x0 vptr entry in class_field_layouts.tsv")
    for vt, vr in vt_by_addr.items():
        if cf_counts[vt] != int(vr["observed_field_count"]):
            raise ValueError(f"observed_field_count mismatch for vtable {vt}")

    # 7. Validate static global contracts
    gl_rows = _read_tsv(contracts_dir / "global_contracts.tsv")
    if len(gl_rows) != manifest["counts"]["globals"]:
        raise ValueError("global_contracts count disagrees with manifest")
    gl_by_addr: dict[str, dict] = {}
    prev_ga = -1
    for gr in gl_rows:
        addr = gr["address"]
        if not _HEX8_RE.match(addr):
            raise ValueError(f"invalid global address: {addr}")
        ga = int(addr, 16)
        if ga <= prev_ga:
            raise ValueError(f"unsorted or duplicate global address: {addr}")
        prev_ga = ga
        w = int(gr["width"])
        if w <= 0 or gr["storage"] not in _VALID_STORAGES or len(gr["initial_hex_le"]) != 2 * w:
            raise ValueError(f"invalid global storage/width at {addr}")
        if image_bytes_data is not None:
            raw_g, stor_g = image_bytes(image_bytes_data, base, sections, ga, w, allow_zero_fill=True)
            if raw_g.hex() != gr["initial_hex_le"] or stor_g != gr["storage"]:
                raise ValueError(f"PE global bytes disagree at {addr}")
        gl_by_addr[addr] = gr

    # 8. Reconcile against curated C17 contracts (`port/recovered_types/contracts.json`)
    if curated_path and curated_path.is_file():
        curated = json.loads(curated_path.read_text(encoding="utf-8"))
        for cf in curated["functions"]:
            addr = cf["address"].lower()
            if addr in fn_by_addr:
                if fn_by_addr[addr]["curated_layer_pinned"] != "true":
                    raise ValueError(f"curated function {addr} not marked curated_layer_pinned=true")
            elif addr in np_by_addr:
                if np_by_addr[addr]["sha256"] != cf["sha256"] or int(np_by_addr[addr]["bytes"]) != cf["bytes"]:
                    raise ValueError(f"non-proc curated slot mismatch at {addr}")
            else:
                raise ValueError(f"curated function missing from whole-binary contracts: {addr}")
        for cg in curated["globals"]:
            addr = cg["address"].lower()
            gr = gl_by_addr.get(addr)
            if (
                gr is None
                or gr["curated_global_pinned"] != "true"
                or int(gr["width"]) != cg["width"]
                or gr["storage"] != cg["storage"]
                or gr["initial_hex_le"] != cg["initial_hex_le"]
            ):
                raise ValueError(f"curated global reconciliation failed at {addr}")
        for cv in curated["vtables"]:
            vt = cv["address"].lower()
            vr = vt_by_addr.get(vt)
            if (
                vr is None
                or vr["curated_vtable_pinned"] != "true"
                or vr["first_slot"] != cv["first_slot_code_identity"]
            ):
                raise ValueError(f"curated vtable reconciliation failed at {vt}")

    return {
        "schema": manifest["schema"],
        "verified": True,
        "pe_verified": image_bytes_data is not None,
        "canonical_functions": len(fn_by_addr),
        "non_proc_curated_slots": len(np_by_addr),
        "vtables": len(vt_by_addr),
        "class_field_entries": len(cf_rows),
        "rtti_type_descriptors": len(rtti_rows),
        "globals": len(gl_by_addr),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--contracts-dir", type=Path, default=CONTRACTS_DIR)
    parser.add_argument("--image", type=Path, default=DLL_PATH)
    parser.add_argument("--public-only", action="store_true", help="Skip PE-image byte verification (CI mode)")
    args = parser.parse_args(argv)

    img_bytes: bytes | None = None
    if not args.public_only and args.image.is_file():
        img_bytes = args.image.read_bytes()

    try:
        res = validate_all(args.contracts_dir, image_bytes_data=img_bytes)
    except (OSError, ValueError, KeyError, TypeError, struct.error, AssertionError) as exc:
        parser.exit(1, f"whole-binary contract validation failed: {exc}\n")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
