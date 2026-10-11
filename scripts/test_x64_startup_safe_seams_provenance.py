#!/usr/bin/env python3
"""Authenticate inert x86 evidence for the bounded 100f1bb0/100f1cc0 seams."""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
INDEX = (
    ROOT
    / "src_canonical_out"
    / "empire.retail.dll"
    / "canonical_function_index.tsv"
)
CANONICAL = (
    ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
)

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
CANONICAL_HASHES = {
    "100f1bb0": "97f290b71b7614457fb149f107899d69391b1e07f847a0b7448248cf8aa1fcc6",
    "100f1cc0": "8cd70d65677361ef62405e7621495b03ddb3901696a4a01c429ff609bc4b4a69",
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
}

MEASURE_VA = 0x100F1BB0
MEASURE_BYTES = bytes.fromhex(
    "568b7424088bc6578bf9660f1f4400000fb71083c0026685d275f52bc683e802"
    "d1f889078d04465056e852d7ffff8bc75f5ec20400"
)
MEASURE_SHA256 = "94088db58e056bb26dba6ce27d33c6353afce3b9300dfa63810c813dd115b2eb"
SCAN_VA = 0x100F1BC0
SCAN_BYTES = bytes.fromhex("0fb71083c0026685d275f52bc683e802d1f8")
SCAN_SHA256 = "aba7a7430b421914b8b6d6c603995dbbc06c93b0b97de47d61bb633e889c5555"

NOOP_VA = 0x100F1CC0
NOOP_BYTES = bytes.fromhex(
    "568b710881fe9040af11742585f674218b76fc85f6741a56e873310300a1b03e"
    "9f1183c40485c074086a0056ffd083c4085ec3"
)
NOOP_SHA256 = "bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4"
NOOP_PREFIX = bytes.fromhex("568b710881fe9040af11742585f67421")
NOOP_PREFIX_SHA256 = "520e0b8dca85eb186a400c043dcd137c68bbb3da2d1f6990ab2e86590caa9172"
NOOP_EPILOGUE = bytes.fromhex("5ec3")

PARENT_VA = 0x100ED42C
PARENT_BYTES = bytes.fromhex(
    "8b44241c8d4c2428ffb42418090000894424588a4424248844245c8b44242889"
    "442460c644246400e857470000508d442438508d4c246ce8081effff8d4c2428"
    "e84f480000"
)
PARENT_SHA256 = "8be7ffb391c31778f273fcd94315254c837528f6a5bf0f37004d4513aeb4148d"

IMAGE_BASE = 0x10000000


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


def rel32_target(body: bytes, body_va: int, call_va: int) -> int:
    offset = call_va - body_va
    if body[offset] != 0xE8:
        raise ValueError(f"0x{call_va:08x} is not an E8 call")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return call_va + 5 + displacement


def short_branch_target(body: bytes, body_va: int, branch_va: int) -> int:
    offset = branch_va - body_va
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return branch_va + 2 + displacement


class StartupSafeSeamsProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_measure_body_and_bounded_stop_line(self):
        body, section, offset = read_va(
            self.dll, self.sections, MEASURE_VA, len(MEASURE_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xF0FB0))
        self.assertEqual(body, MEASURE_BYTES)
        self.assertEqual(sha256(body), MEASURE_SHA256)

        scan_offset = SCAN_VA - MEASURE_VA
        scan = body[scan_offset : scan_offset + len(SCAN_BYTES)]
        self.assertEqual(scan, SCAN_BYTES)
        self.assertEqual(sha256(scan), SCAN_SHA256)
        self.assertEqual(short_branch_target(scan, SCAN_VA, 0x100F1BC9), SCAN_VA)
        self.assertEqual(scan[-7:], bytes.fromhex("2bc683e802d1f8"))

        self.assertEqual(body[0x22:0x24], b"\x89\x07")
        self.assertEqual(rel32_target(body, MEASURE_VA, 0x100F1BD9), 0x100EF330)
        self.assertEqual(body[0x32:0x35], b"\xc2\x04\x00")

    def test_nonowning_noop_branches_precede_owning_path(self):
        body, section, offset = read_va(
            self.dll, self.sections, NOOP_VA, len(NOOP_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xF10C0))
        self.assertEqual(body, NOOP_BYTES)
        self.assertEqual(sha256(body), NOOP_SHA256)
        self.assertEqual(body[: len(NOOP_PREFIX)], NOOP_PREFIX)
        self.assertEqual(sha256(NOOP_PREFIX), NOOP_PREFIX_SHA256)
        self.assertEqual(struct.unpack_from("<I", body, 6)[0], 0x11AF4090)
        self.assertEqual(short_branch_target(body, NOOP_VA, 0x100F1CCA), 0x100F1CF1)
        self.assertEqual(short_branch_target(body, NOOP_VA, 0x100F1CCE), 0x100F1CF1)
        self.assertEqual(body[-2:], NOOP_EPILOGUE)

        self.assertEqual(body[0x10:0x15], bytes.fromhex("8b76fc85f6"))
        self.assertEqual(rel32_target(body, NOOP_VA, 0x100F1CD8), 0x10124E50)
        self.assertEqual(body[0x1D:0x22], bytes.fromhex("a1b03e9f11"))
        self.assertEqual(body[0x2C:0x2E], b"\xff\xd0")

    def test_parent_call_sites_are_exact(self):
        body, section, offset = read_va(
            self.dll, self.sections, PARENT_VA, len(PARENT_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xEC82C))
        self.assertEqual(body, PARENT_BYTES)
        self.assertEqual(sha256(body), PARENT_SHA256)
        self.assertEqual(body.count(b"\xe8"), 3)
        self.assertEqual(rel32_target(body, PARENT_VA, 0x100ED454), MEASURE_VA)
        self.assertEqual(rel32_target(body, PARENT_VA, 0x100ED463), 0x100DF270)
        self.assertEqual(rel32_target(body, PARENT_VA, 0x100ED46C), NOOP_VA)
        self.assertEqual(body[4:8], bytes.fromhex("8d4c2428"))
        self.assertEqual(body[8:15], bytes.fromhex("ffb42418090000"))
        self.assertEqual(body[-9:-5], bytes.fromhex("8d4c2428"))

    def test_canonical_sources_and_index_rows_are_exact(self):
        for entry, expected_hash in CANONICAL_HASHES.items():
            source = CANONICAL / f"decomp_fn_{entry}.c"
            self.assertEqual(sha256(source.read_bytes()), expected_hash)

        index_bytes = INDEX.read_bytes()
        self.assertEqual(sha256(index_bytes), INDEX_SHA256)
        rows = list(
            csv.DictReader(index_bytes.decode("utf-8").splitlines(), delimiter="\t")
        )
        by_entry = {row["entry"]: row for row in rows}
        expected = {
            "100f1bb0": ("decomp_fn_100f1bb0", "53", "100f1bb0-100f1be4"),
            "100f1cc0": ("decomp_fn_100f1cc0", "51", "100f1cc0-100f1cf2"),
            "100ed3c0": ("decomp_fn_100ed3c0", "400", "100ed3c0-100ed54f"),
        }
        for entry, fields in expected.items():
            row = by_entry[entry]
            self.assertEqual(
                (row["canonical_name"], row["size"], row["body_ranges"]), fields
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
