#!/usr/bin/env python3
"""Independent provenance gates for the first guest32 behavior slice."""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
CANONICAL = ROOT / "src_canonical_out" / "empire.retail.dll" / \
    "canonical_decomp"
EXPORT_MANIFEST = ROOT / "port" / "x64_exports" / "export_manifest.tsv"

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
EXPORT_MANIFEST_SHA256 = (
    "e1df5a9e9e20c555a7d1d97a106b469e961c4abf88dcd03889c3a126d152b117"
)
IMAGE_BASE = 0x10000000

THUNK_VA = 0x1093C450
THUNK_BYTES = bytes.fromhex("8b 09 e9 49 bd 7a ff")
THUNK_SHA256 = "f7ae2c69da41f139815d8f7f3ef3b4e16b9315deff22fd399fee79822ebb41cf"
GET_CSTR_VA = 0x100E81A0
GET_CSTR_BYTES = bytes.fromhex("8d 41 04 c3")
GET_CSTR_SHA256 = "4181cb1fec090d6487f323c8ce84a17ff37429613d7843b4f5f40f5eae266b77"

CANONICAL_HASHES = {
    "decomp_fn_1093c450.c":
        "df5a37ce9129cf6fabd29d1484cb1fc659bb74beae1da1d4a1f24e1e1b1828a6",
    "decomp_fn_100e81a0.c":
        "55b88a81ff531950985f43699115453b1f11439b8c0b79b2232ece28fb0fb6b4",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_sections(data: bytes):
    """Return independently parsed PE32 section mappings."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("missing MZ")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ValueError("invalid PE offset")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if machine != 0x014C:
        raise ValueError("not x86")
    if optional_size < 96 or optional + optional_size > len(data):
        raise ValueError("invalid optional header")
    if struct.unpack_from("<H", data, optional)[0] != 0x010B:
        raise ValueError("not PE32")
    if struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE:
        raise ValueError("unexpected image base")
    if not 1 <= section_count <= 96:
        raise ValueError("invalid section count")
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise ValueError("truncated section table")

    sections = []
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, virtual_address, raw_size, raw_offset = \
            struct.unpack_from("<IIII", data, offset + 8)
        if raw_offset + raw_size > len(data):
            raise ValueError(f"section {name} extends past EOF")
        sections.append(
            (name, virtual_address, max(virtual_size, raw_size),
             raw_offset, raw_size)
        )
    return sections


def read_va(data: bytes, sections, va: int, size: int):
    rva = va - IMAGE_BASE
    matches = []
    for section in sections:
        name, section_rva, extent, raw_offset, raw_size = section
        delta = rva - section_rva
        if 0 <= delta and delta + size <= extent:
            if delta + size > raw_size:
                raise ValueError(f"VA 0x{va:08x} is not fully raw-backed")
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} mappings")
    name, offset = matches[0]
    return data[offset:offset + size], name, offset


class OriginalInstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DLL.is_file():
            raise AssertionError(f"pinned original DLL is missing: {DLL}")
        cls.data = DLL.read_bytes()
        if sha256(cls.data) != DLL_SHA256:
            raise AssertionError("original DLL hash differs from the pinned corpus")
        cls.sections = parse_sections(cls.data)

    def test_forwarder_loads_one_guest_cell_and_tail_jumps(self):
        body, section, file_offset = read_va(
            self.data, self.sections, THUNK_VA, len(THUNK_BYTES)
        )
        self.assertEqual(section, ".text")
        self.assertEqual(file_offset, 0x93B850)
        self.assertEqual(body, THUNK_BYTES)
        self.assertEqual(sha256(body), THUNK_SHA256)
        self.assertEqual(body[:2], b"\x8b\x09")  # mov ecx, dword ptr [ecx]
        self.assertEqual(body[2], 0xE9)            # near relative tail jump
        displacement = struct.unpack_from("<i", body, 3)[0]
        self.assertEqual(THUNK_VA + len(body) + displacement, GET_CSTR_VA)

    def test_get_cstr_adds_four_then_returns(self):
        body, section, file_offset = read_va(
            self.data, self.sections, GET_CSTR_VA, len(GET_CSTR_BYTES)
        )
        self.assertEqual(section, ".text")
        self.assertEqual(file_offset, 0xE75A0)
        self.assertEqual(body, GET_CSTR_BYTES)
        self.assertEqual(sha256(body), GET_CSTR_SHA256)
        self.assertEqual(body[:3], b"\x8d\x41\x04")  # lea eax, [ecx+4]
        self.assertEqual(body[3], 0xC3)                 # ret


class CanonicalIdentityTests(unittest.TestCase):
    def test_canonical_source_hashes_are_pinned(self):
        for name, expected in CANONICAL_HASHES.items():
            with self.subTest(source=name):
                path = CANONICAL / name
                self.assertTrue(path.is_file())
                self.assertEqual(sha256(path.read_bytes()), expected)

    def test_public_alias_identity_is_not_a_port_abi_claim(self):
        self.assertTrue(
            EXPORT_MANIFEST.is_file(),
            f"export manifest is missing: {EXPORT_MANIFEST}",
        )
        manifest_bytes = EXPORT_MANIFEST.read_bytes()
        self.assertEqual(sha256(manifest_bytes), EXPORT_MANIFEST_SHA256)
        rows = list(
            csv.DictReader(
                manifest_bytes.decode("utf-8").splitlines(), delimiter="\t"
            )
        )
        aliases = [row for row in rows if row["target_va"] == "100e81a0"]
        self.assertEqual([int(row["ordinal"]) for row in aliases], [243, 266])
        self.assertEqual(
            {row["target_symbol"] for row in aliases},
            {"rome2_export_code_100e81a0"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
