"""Validate curated guest layout evidence without opening the shared Ghidra DB.

This checks an original image and an explicit contract registry. It does not
infer classes, apply types to Ghidra, or treat unknown bytes as native pointers.
Zero-filled PE virtual tails are distinguished from bytes stored in the file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
IMAGE_SIZE = 28_278_272
CONTRACT = ROOT / "port/recovered_types/contracts.json"


def require_range(data: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError("range outside image")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40)
    if data[:2] != b"MZ":
        raise ValueError("missing MZ")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    require_range(data, pe, 24)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    require_range(data, optional, optional_size)
    if machine != 0x14c or optional_size < 32:
        raise ValueError("expected x86 PE32")
    if struct.unpack_from("<H", data, optional)[0] != 0x10b:
        raise ValueError("expected PE32 optional header")
    base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = []
    for index in range(count):
        pos = optional + optional_size + 40 * index
        require_range(data, pos, 40)
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, pos + 8)
        require_range(data, raw_offset, raw_size)
        if rva + max(virtual_size, raw_size) > 1 << 32:
            raise ValueError("section address overflow")
        sections.append((rva, virtual_size, raw_offset, raw_size))
    return base, sections


def image_bytes(data: bytes, base: int, sections, address: int, size: int,
                *, allow_zero_fill: bool = False) -> tuple[bytes, str]:
    if not isinstance(size, int) or size <= 0 or address < base or address + size > 1 << 32:
        raise ValueError("invalid image address range")
    rva = address - base
    matches = []
    for start, virtual_size, raw_offset, raw_size in sections:
        delta = rva - start
        extent = max(virtual_size, raw_size)
        if delta < 0 or delta + size > extent:
            continue
        if delta + size <= raw_size:
            off = raw_offset + delta
            require_range(data, off, size)
            matches.append((data[off:off + size], "file"))
        elif allow_zero_fill and delta + size <= virtual_size:
            stored = max(0, raw_size - delta)
            off = raw_offset + min(delta, raw_size)
            require_range(data, off, stored)
            matches.append((data[off:off + stored] + bytes(size - stored),
                            "zero_fill" if stored == 0 else "file_and_zero_fill"))
    if len(matches) != 1:
        raise ValueError(f"0x{address:08x} has {len(matches)} admissible mappings")
    return matches[0]


def function_body_parts(image: bytes, base: int, sections, function: dict):
    """Read curated body ranges, excluding gaps in a Ghidra AddressSet."""
    entry = int(function["address"], 16)
    size = function["bytes"]
    if type(size) is not int or size <= 0:
        raise ValueError("invalid function body size")
    ranges = function.get("body_ranges")
    if ranges is None:
        data, _ = image_bytes(image, base, sections, entry, size)
        return [(entry, data)]
    if not isinstance(ranges, list) or not ranges:
        raise ValueError("invalid function body ranges")
    parts = []
    previous_end = -1
    for item in ranges:
        start, end = int(item["start"], 16), int(item["end"], 16)
        if start > end or start <= previous_end:
            raise ValueError("invalid function body ranges: unordered or overlapping")
        data, _ = image_bytes(image, base, sections, start, end - start + 1)
        parts.append((start, data)); previous_end = end
    if sum(len(data) for _, data in parts) != size or not any(
            start <= entry < start + len(data) for start, data in parts):
        raise ValueError("function body ranges disagree with size or entry")
    return parts


def validate_contracts(image: bytes, registry: dict) -> dict:
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("original image differs from pinned target")
    if registry.get("schema") != "rome2-recovered-types-v1":
        raise ValueError("unknown type contract schema")
    if registry.get("image") != {"bytes": IMAGE_SIZE, "sha256": IMAGE_SHA256}:
        raise ValueError("contract target differs from pinned target")
    base, sections = parse_pe32(image)
    for category in ("functions", "globals", "vtables", "instruction_witnesses"):
        if not isinstance(registry.get(category), list) or not registry[category]:
            raise ValueError(f"empty or invalid {category}")
        addresses = [item["address"] for item in registry[category]]
        if len(set(addresses)) != len(addresses):
            raise ValueError(f"duplicate {category} identity")
    for function in registry["functions"]:
        parts = function_body_parts(image, base, sections, function)
        body = b"".join(data for _, data in parts)
        if hashlib.sha256(body).hexdigest() != function["sha256"]:
            raise ValueError(f"function bytes changed: {function['address']}")
        stack = function["stack_argument_bytes"]
        pop = function.get("callee_pop_bytes", stack)
        if (not isinstance(stack, int) or stack < 0 or stack % 4 or
                not isinstance(pop, int) or pop < 0 or pop % 4 or pop > stack):
            raise ValueError("invalid x86 stack contract")
        if function.get("calling_convention") == "cdecl" and pop != 0:
            raise ValueError("cdecl callee must not pop caller arguments")
        tail = b"\xc3" if pop == 0 else b"\xc2" + struct.pack("<H", pop)
        returns = function.get("return_instruction_addresses")
        if returns is None:
            if not parts[-1][1].endswith(tail):
                raise ValueError(f"stack return disagrees: {function['address']}")
        else:
            # Some complete functions end in a backward branch; their RET is
            # earlier in the body. Curate instruction addresses from REA's
            # complete assembly, while retaining the full original-body hash.
            if not isinstance(returns, list) or not returns or len(set(returns)) != len(returns):
                raise ValueError("invalid explicit return instruction list")
            for address in returns:
                pc = int(address, 16)
                if not any(start <= pc and pc + len(tail) <= start + len(data)
                           and data[pc - start:pc - start + len(tail)] == tail
                           for start, data in parts):
                    raise ValueError(f"stack return disagrees: {function['address']}")
    for entry in registry["globals"]:
        value, storage = image_bytes(image, base, sections, int(entry["address"], 16),
                                     entry["width"], allow_zero_fill=True)
        if value.hex() != entry["initial_hex_le"] or storage != entry["storage"]:
            raise ValueError(f"global initial storage disagrees: {entry['address']}")
    for entry in registry["vtables"]:
        slot, _ = image_bytes(image, base, sections, int(entry["address"], 16), 4)
        if f"{int.from_bytes(slot, 'little'):08x}" != entry["first_slot_code_identity"]:
            raise ValueError(f"vtable identity disagrees: {entry['address']}")
    for witness in registry["instruction_witnesses"]:
        expected = bytes.fromhex(witness["hex"])
        actual, _ = image_bytes(image, base, sections, int(witness["address"], 16), len(expected))
        if actual != expected:
            raise ValueError(f"instruction witness disagrees: {witness['address']}")
    return {"schema": registry["schema"], "verified": True,
            **{key: len(registry[key]) for key in (
                "functions", "globals", "vtables", "instruction_witnesses")},
            "scope": "static original-image evidence; native behavior requires separate tests"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=ROOT / "Total War Rome II/empire.retail.dll")
    parser.add_argument("--contracts", type=Path, default=CONTRACT)
    args = parser.parse_args(argv)
    try:
        result = validate_contracts(args.image.read_bytes(), json.loads(args.contracts.read_text("utf-8")))
    except (OSError, ValueError, KeyError, TypeError, struct.error) as exc:
        parser.exit(1, f"type contract validation failed: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
