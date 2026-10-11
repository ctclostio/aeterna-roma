#!/usr/bin/env python3
"""Authenticate the effect-free normal handler at original 0x100e85d0.

The original PE is parsed strictly as data and never loaded or executed.  The
authenticated instructions establish one ignored zero argument to a one-byte
RET helper, AL=1, and RET 4.  They do not establish a native x64 ABI, define
upper EAX, or authorize linking either recovered address into the port.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
INDEX = (
    ROOT / "src_canonical_out" / "empire.retail.dll" /
    "canonical_function_index.tsv"
)
CANONICAL = (
    ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
)

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"

IMAGE_BASE = 0x10000000
FUNCTION_VA = 0x100E85D0
FUNCTION_BYTES = bytes.fromhex("6a00e889dffeff83c404b001c20400")
FUNCTION_SHA256 = "1bf8d344edb832e512961f8bbafeb5f9a04cceb1e70cbf31d758151c6df970ff"
FUNCTION_RAW_OFFSET = 0x000E79D0

NOOP_VA = 0x100D6560
NOOP_BYTES = bytes.fromhex("c3")
NOOP_SHA256 = "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e"
NOOP_RAW_OFFSET = 0x000D5960
NOOP_CANONICAL_SHA256 = (
    "b2dd76946e1873f4fa7ddeb7f0eae493a93649788f0946882777879a4e185bf6"
)

VTABLE_PAIR_VA = 0x1173F214
VTABLE_PAIR_BYTES = bytes.fromhex("b0380d10d0850e10")
VTABLE_PAIR_SHA256 = (
    "a28eae14e25dad6de1bfce2611db689b66661af348650307a08ed3e03258788d"
)
VTABLE_PAIR_RAW_OFFSET = 0x0173DC14


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} lies outside the {len(data)}-byte input")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    require_range(data, optional, optional_size, "optional header")
    if (
        machine != 0x014C
        or not 1 <= section_count <= 96
        or optional_size < 96
        or struct.unpack_from("<H", data, optional)[0] != 0x010B
        or struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE
    ):
        raise ValueError("original image is not the expected bounded PE32 image")

    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = table + index * 40
        raw_name = data[offset:offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII section name") from exc
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append((name, rva, virtual_size, raw_offset, raw_size))
    return tuple(sections)


def read_va(data: bytes, sections, va: int, size: int):
    if va < IMAGE_BASE:
        raise ValueError(f"VA 0x{va:08x} precedes image base")
    rva = va - IMAGE_BASE
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size in sections:
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset:offset + size], name, offset


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 5, "rel32 call")
    if body[offset] != 0xE8:
        raise ValueError(f"0x{instruction_va:08x} is not CALL rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


class Startup100e85d0NormalAdapterProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_exact_15_byte_handler_body(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(FUNCTION_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(body, FUNCTION_BYTES)
        self.assertEqual(len(body), 15)
        self.assertEqual(sha256(body), FUNCTION_SHA256)

    def test_only_call_targets_the_exact_one_byte_ret(self):
        call_offsets = tuple(
            offset
            for offset in range(len(FUNCTION_BYTES) - 4)
            if FUNCTION_BYTES[offset] == 0xE8
        )
        self.assertEqual(call_offsets, (2,))
        self.assertEqual(
            rel32_target(FUNCTION_BYTES, FUNCTION_VA, FUNCTION_VA + 2),
            NOOP_VA,
        )

        callee, section, raw_offset = read_va(
            self.dll, self.sections, NOOP_VA, len(NOOP_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", NOOP_RAW_OFFSET))
        self.assertEqual(callee, NOOP_BYTES)
        self.assertEqual(sha256(callee), NOOP_SHA256)

    def test_stack_shape_al_one_and_ret4_are_exact(self):
        body = FUNCTION_BYTES
        self.assertEqual(body[0:2], bytes.fromhex("6a00"), "push helper argument 0")
        self.assertEqual(body[2], 0xE8, "direct helper call")
        self.assertEqual(body[7:10], bytes.fromhex("83c404"), "discard helper argument")
        self.assertEqual(body[10:12], bytes.fromhex("b001"), "define AL as one")
        self.assertEqual(body[12:15], bytes.fromhex("c20400"), "RET 4")
        self.assertNotIn(
            bytes.fromhex("b801000000"),
            body,
            "the machine body does not define full EAX",
        )

    def test_vtable_method_identity_is_exact(self):
        pair, section, raw_offset = read_va(
            self.dll, self.sections, VTABLE_PAIR_VA, len(VTABLE_PAIR_BYTES)
        )
        self.assertEqual((section, raw_offset), (".rdata", VTABLE_PAIR_RAW_OFFSET))
        self.assertEqual(pair, VTABLE_PAIR_BYTES)
        self.assertEqual(sha256(pair), VTABLE_PAIR_SHA256)
        self.assertEqual(struct.unpack("<II", pair), (0x100D38B0, FUNCTION_VA))

    def test_noop_canonical_authority_is_exact(self):
        self.assertEqual(sha256(INDEX.read_bytes()), INDEX_SHA256)
        canonical = CANONICAL / "decomp_fn_100d6560.c"
        self.assertTrue(canonical.exists())
        self.assertEqual(sha256(canonical.read_bytes()), NOOP_CANONICAL_SHA256)

        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                INDEX.read_text(encoding="utf-8").splitlines(), delimiter="\t"
            )
        }
        row = rows["100d6560"]
        self.assertEqual(
            (
                row["canonical_name"],
                row["original_name"],
                row["signature"],
                row["size"],
                row["kind"],
                row["body_ranges"],
            ),
            (
                "decomp_fn_100d6560",
                "guard_check_icall",
                "undefined __cdecl guard_check_icall(void)",
                "1",
                "func",
                "100d6560-100d6560",
            ),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
