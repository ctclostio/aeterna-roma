#!/usr/bin/env python3
"""Evidence-only provenance: 0x100ea4d0 admits no read-only executable port.

The adjacent suffix call 0x100df489 -> 0x100ea4d0 is documented but not ported.
Every invocation reaches the 4-byte allocator 0x100d12b0 before any branch.
Every normally returning execution calls that allocator and initializer
0x100e2460 six times; non-null allocations receive one of six vtable-style
function-pointer stores.  This test pins the exact original bytes, the
canonical decompilation, and that allocation/mutation evidence so that a
future executable port cannot be introduced silently.
"""

from __future__ import annotations

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

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
CANONICAL_100EA4D0_SHA256 = (
    "122ca8ff594fb0becdc7c07999f235b64418efd18f0f08026a25ad9da066ce99"
)
CANONICAL_ALLOCATOR_HASHES = {
    "100d12b0": "664f9d5f53e7f8053bc6cd3ff40173262984c4c26484949e3352b16349de2316",
    "100fcc80": "9dbd299240f648438f3e5a9e0a1d55707790af16b4d95c58f190c0475a034e6f",
}

IMAGE_BASE = 0x10000000

EA4D0_VA = 0x100EA4D0
EA4D0_SIZE = 265
EA4D0_SHA256 = "582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3"

ALLOCATOR_VA = 0x100D12B0
ALLOCATOR_WRAPPER_BYTES = bytes.fromhex(
    "6a00ff742408e8c5b9020083c408c3"
)
ALLOCATOR_WRAPPER_SHA256 = (
    "b02e52cdf692d826b0cd12279dd4988b1688add865ed80ef5e281181a0c1d243"
)
CORE_ALLOCATOR_VA = 0x100FCC80
INITIALIZER_VA = 0x100E2460

# The six vtable-style function pointers stored through the allocated pointer.
VTABLE_IMMEDIATES = (
    0x1173F20C,
    0x1173F214,
    0x1173F21C,
    0x1173F224,
    0x1173F2EC,
    0x1173F2DC,
)
ALLOC_CALL_OFFSETS = (0x06, 0x3B, 0x64, 0x8D, 0xB6, 0xDF)
INITIALIZER_CALL_OFFSETS = (0x2C, 0x55, 0x7E, 0xA7, 0xD0, 0xF9)
PUSH4_OFFSETS = (0x02, 0x39, 0x62, 0x8B, 0xB4, 0xDD)
NULL_CHECK_OFFSETS = (0x10, 0x45, 0x6E, 0x97, 0xC0, 0xE9)
VTABLE_STORE_OFFSETS = (0x12, 0x47, 0x70, 0x99, 0xC2, 0xEB)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError(f"{label} lies outside the {len(data)}-byte input")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
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
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append((name, rva, virtual_size, raw_offset, raw_size))
    return tuple(sections)


def read_va(data: bytes, sections, va: int, size: int):
    rva = va - IMAGE_BASE
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size in sections:
        delta = rva - section_rva
        if delta >= 0 and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset : offset + size], name, offset


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    if body[offset] not in (0xE8, 0xE9):
        raise ValueError(f"0x{instruction_va:08x} is not an E8/E9 rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


class Startup100ea4d0EvidenceProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_canonical_decompilation_is_pinned(self):
        path = CANONICAL / "decomp_fn_100ea4d0.c"
        self.assertTrue(path.exists(), "canonical 100ea4d0 missing")
        self.assertEqual(sha256(path.read_bytes()), CANONICAL_100EA4D0_SHA256)
        for entry, expected_hash in CANONICAL_ALLOCATOR_HASHES.items():
            allocator_path = CANONICAL / f"decomp_fn_{entry}.c"
            self.assertTrue(allocator_path.exists(), f"canonical {entry} missing")
            self.assertEqual(sha256(allocator_path.read_bytes()), expected_hash)

    def test_allocator_wrapper_is_pinned(self):
        actual, section, offset = read_va(
            self.dll,
            self.sections,
            ALLOCATOR_VA,
            len(ALLOCATOR_WRAPPER_BYTES),
        )
        self.assertEqual((section, offset), (".text", 0x000D06B0))
        self.assertEqual(actual, ALLOCATOR_WRAPPER_BYTES)
        self.assertEqual(sha256(actual), ALLOCATOR_WRAPPER_SHA256)
        self.assertEqual(actual[:6], bytes.fromhex("6a00ff742408"))
        self.assertEqual(
            rel32_target(actual, ALLOCATOR_VA, ALLOCATOR_VA + 6),
            CORE_ALLOCATOR_VA,
            "allocation wrapper no longer calls 0x100fcc80",
        )
        self.assertEqual(actual[-4:], bytes.fromhex("83c408c3"))

    def test_entry_window_is_exact(self):
        actual, section, offset = read_va(
            self.dll, self.sections, EA4D0_VA, EA4D0_SIZE
        )
        self.assertEqual(section, ".text")
        self.assertEqual(sha256(actual), EA4D0_SHA256)
        self.assertEqual(len(actual), EA4D0_SIZE)
        # Prologue: push esi; push edi; push 4; mov edi, ecx.
        self.assertEqual(actual[0:6], bytes.fromhex("56576a048bf9"),
                         "prologue changed")
        # The first allocation call targets the 4-byte allocator.
        self.assertEqual(
            rel32_target(actual, EA4D0_VA, EA4D0_VA + 6), ALLOCATOR_VA,
            "first allocation call 0x100d12b0 changed")
        # The first heap-object mutation stores 0x1173f20c through [eax].
        self.assertEqual(actual[18:24],
                         bytes.fromhex("c700") + struct.pack("<I", 0x1173F20C),
                          "first heap-object mutation changed")
        # The function ends with a single ret at the final byte.
        self.assertEqual(actual[-1:], bytes.fromhex("c3"), "epilogue changed")

    def test_every_invocation_allocates_and_normal_return_builds_six_nodes(self):
        actual, _section, _offset = read_va(
            self.dll, self.sections, EA4D0_VA, EA4D0_SIZE
        )
        # The first allocator call is reached before any control transfer.
        self.assertEqual(actual[:6], bytes.fromhex("56576a048bf9"))
        for push_offset, call_offset in zip(PUSH4_OFFSETS, ALLOC_CALL_OFFSETS):
            self.assertEqual(actual[push_offset : push_offset + 2], b"\x6a\x04")
            self.assertEqual(
                rel32_target(actual, EA4D0_VA, EA4D0_VA + call_offset),
                ALLOCATOR_VA,
                f"allocator call at +{call_offset:#x} changed",
            )
        for call_offset in INITIALIZER_CALL_OFFSETS:
            self.assertEqual(
                rel32_target(actual, EA4D0_VA, EA4D0_VA + call_offset),
                INITIALIZER_VA,
                f"initializer call at +{call_offset:#x} changed",
            )
        for call_offset in INITIALIZER_CALL_OFFSETS[:-1]:
            self.assertEqual(
                actual[call_offset + 5 : call_offset + 13],
                bytes.fromhex("84c0750433c08900"),
                f"initializer failure trap at +{call_offset:#x} changed",
            )
        self.assertEqual(
            actual[INITIALIZER_CALL_OFFSETS[-1] + 5 :],
            bytes.fromhex("5f5e84c0750433c08900c3"),
            "final initializer failure trap or epilogue changed",
        )
        for check_offset, store_offset, imm in zip(
            NULL_CHECK_OFFSETS, VTABLE_STORE_OFFSETS, VTABLE_IMMEDIATES
        ):
            self.assertEqual(actual[check_offset : check_offset + 2], b"\x74\x08")
            self.assertEqual(
                actual[store_offset : store_offset + 6],
                b"\xc7\x00" + struct.pack("<I", imm),
            )
            self.assertEqual(
                actual[store_offset + 6 : store_offset + 10],
                bytes.fromhex("eb0233c0"),
            )
        # No allocation-free return exists.
        self.assertNotIn(bytes.fromhex("c3"), actual[:-1],
                          "an early return would admit a read-only path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
