#!/usr/bin/env python3
"""Independent provenance gate for the static guest32 0x100f1c10 slice."""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
CANONICAL_ROOT = (
    ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
)
LEAF_CANONICAL = CANONICAL_ROOT / "decomp_fn_100f1c10.c"
PARENT_CANONICAL = CANONICAL_ROOT / "decomp_fn_100ed3c0.c"
FUNCTION_INDEX = (
    ROOT
    / "src_canonical_out"
    / "empire.retail.dll"
    / "canonical_function_index.tsv"
)
STARTUP_SLOTS = ROOT / "port" / "startup_audit" / "startup_slots.tsv"

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
LEAF_CANONICAL_SHA256 = (
    "ec3103cb0e6c9060bdb7a027949e496a9a4e81dc13ec5d3918638feeea071ed7"
)
PARENT_CANONICAL_SHA256 = (
    "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8"
)
STARTUP_SLOTS_SHA256 = (
    "453de546bbbd64e858aa80cd2ce09552904098e02cb0861689c24bd21e67ff6b"
)

IMAGE_BASE = 0x10000000
LEAF_VA = 0x100F1C10
LEAF_BYTES = bytes.fromhex("c701000000008bc1c7410400000000c741089040af11c3")
LEAF_SHA256 = "6c689fc50bf6bfcfb73dc23095cfc6c98a757df32867c8d8b77514129bb8a2a1"
PARENT_PREFIX_VA = 0x100ED3C0
PARENT_PREFIX_BYTES = bytes.fromhex(
    "81ec0c0900008d4c2404c605c8319f1101c605c5319f1101c7042400000000"
    "e82c4800008d4c2410e823480000"
)
PARENT_PREFIX_SHA256 = (
    "3a9aed8d84672298e7b237e62c45b7a7056ce3aed7c555e2e80ce4c6037813df"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError(f"{label} is outside the {len(data)}-byte file")


def parse_pe32_sections(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if machine != 0x014C or not 1 <= section_count <= 96:
        raise ValueError("original image is not a bounded x86 PE")
    require_range(data, optional, optional_size, "optional header")
    if optional_size < 96 or struct.unpack_from("<H", data, optional)[0] != 0x010B:
        raise ValueError("original image is not PE32")
    if struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE:
        raise ValueError("unexpected image base")

    section_table = optional + optional_size
    require_range(data, section_table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = section_table + index * 40
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


class StartupTripletProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (
            DLL,
            LEAF_CANONICAL,
            PARENT_CANONICAL,
            FUNCTION_INDEX,
            STARTUP_SLOTS,
        ):
            if not path.is_file():
                raise AssertionError(f"required pinned input is missing: {path}")
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32_sections(cls.dll)

    def test_leaf_bytes_and_exact_three_cell_semantics(self):
        body, section, offset = read_va(
            self.dll, self.sections, LEAF_VA, len(LEAF_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xF1010))
        self.assertEqual(body, LEAF_BYTES)
        self.assertEqual(sha256(body), LEAF_SHA256)
        self.assertEqual(body[0:2], b"\xc7\x01")
        self.assertEqual(struct.unpack_from("<I", body, 2)[0], 0)
        self.assertEqual(body[6:8], b"\x8b\xc1")
        self.assertEqual(body[8:11], b"\xc7\x41\x04")
        self.assertEqual(struct.unpack_from("<I", body, 11)[0], 0)
        self.assertEqual(body[15:18], b"\xc7\x41\x08")
        self.assertEqual(struct.unpack_from("<I", body, 18)[0], 0x11AF4090)
        self.assertEqual(body[22], 0xC3)

    def test_parent_prefix_calls_leaf_twice_for_adjacent_destinations(self):
        body, section, offset = read_va(
            self.dll,
            self.sections,
            PARENT_PREFIX_VA,
            len(PARENT_PREFIX_BYTES),
        )
        self.assertEqual((section, offset), (".text", 0xEC7C0))
        self.assertEqual(body, PARENT_PREFIX_BYTES)
        self.assertEqual(sha256(body), PARENT_PREFIX_SHA256)
        self.assertEqual(body[6:10], b"\x8d\x4c\x24\x04")
        self.assertEqual(body[36:40], b"\x8d\x4c\x24\x10")
        for call_offset in (31, 40):
            self.assertEqual(body[call_offset], 0xE8)
            displacement = struct.unpack_from("<i", body, call_offset + 1)[0]
            target = PARENT_PREFIX_VA + call_offset + 5 + displacement
            self.assertEqual(target, LEAF_VA)

    def test_canonical_sources_and_index_rows_are_exact(self):
        self.assertEqual(sha256(LEAF_CANONICAL.read_bytes()), LEAF_CANONICAL_SHA256)
        self.assertEqual(
            sha256(PARENT_CANONICAL.read_bytes()), PARENT_CANONICAL_SHA256
        )
        index_bytes = FUNCTION_INDEX.read_bytes()
        self.assertEqual(sha256(index_bytes), INDEX_SHA256)
        rows = list(
            csv.DictReader(index_bytes.decode("utf-8").splitlines(), delimiter="\t")
        )
        by_entry = {row["entry"]: row for row in rows}
        leaf = by_entry["100f1c10"]
        self.assertEqual(leaf["canonical_name"], "decomp_fn_100f1c10")
        self.assertEqual(leaf["size"], "23")
        self.assertEqual(leaf["body_ranges"], "100f1c10-100f1c26")
        parent = by_entry["100ed3c0"]
        self.assertEqual(parent["canonical_name"], "decomp_fn_100ed3c0")
        self.assertEqual(parent["size"], "400")
        self.assertEqual(parent["body_ranges"], "100ed3c0-100ed54f")

    def test_startup_table_is_pinned_and_has_no_direct_target(self):
        slot_bytes = STARTUP_SLOTS.read_bytes()
        self.assertEqual(sha256(slot_bytes), STARTUP_SLOTS_SHA256)
        rows = list(
            csv.DictReader(slot_bytes.decode("utf-8").splitlines(), delimiter="\t")
        )
        targets = {row["raw_target_va"] for row in rows}
        self.assertFalse({"100f1c10", "100ed3c0", "100edd70"} & targets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
