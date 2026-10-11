#!/usr/bin/env python3
"""Authenticate the inert x86 evidence for the bounded 0x100f1aa0 empty path."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = ROOT / "scripts" / "x64_startup_100f1aa0_empty_fixture.json"

EXPECTED_PURPOSE = (
    "Read-only byte provenance for the original x86 empty-source path "
    "0x100ed3c0 -> 0x100f1aa0 -> 0x100ef330; this fixture does not "
    "authorize recovered-code execution, the nonempty allocator path, or a "
    "native ABI."
)
EXPECTED_DLL_SHA256 = (
    "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
)
EXPECTED_INDEX_SHA256 = (
    "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
)
EXPECTED_WRAPPER_SHA256 = (
    "cec1214bba5a2c2c8c45487abf0da2412df9dcb634da206f6f6e74f6c619e92e"
)
EXPECTED_HELPER_SHA256 = (
    "b343025d84a700b1a9e37ffcafc5222ad53a23643c1c99aede37ab1e2193b93d"
)
EXPECTED_EMPTY_SHA256 = (
    "4453992ce0b1a2df255117ba5d3a67c837b9f9b582dbc178fd42d5cd65533db2"
)
EXPECTED_PARENT_SHA256 = (
    "c3106d9e62cf34416f1dff3cfc016a4807845c69a0bddb10c0c0c4dbe88724be"
)
EXPECTED_LIMITATIONS = [
    "All original x86 bytes are parsed as inert data and are never loaded or "
    "executed.",
    "The parent setup instructions authenticate two direct call sites and "
    "prior address loads, not complete register def/use paths or a callable "
    "parent ABI.",
    "Only the helper branch taken when the copied count is zero is admitted; "
    "0x100ef347 and the allocator call to 0x100fcc80 remain outside the port "
    "boundary.",
    "The original ret immediates describe x86 stack mechanics and do not "
    "define the native x64 API.",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_int(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"expected canonical hex string, got {value!r}")
    return int(value, 16)


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} is outside the {len(data)}-byte file")


def parse_pe32(data: bytes):
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
    if not 1 <= section_count <= 96:
        raise ValueError("implausible section count")
    require_range(data, optional, optional_size, "optional header")
    if optional_size < 96:
        raise ValueError("truncated PE32 optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    image_base = struct.unpack_from("<I", data, optional + 28)[0]

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
        sections.append(
            {
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
            }
        )
    return machine, magic, image_base, tuple(sections)


def read_va(data: bytes, image_base: int, sections, va: int, size: int):
    if va < image_base:
        raise ValueError(f"VA 0x{va:08x} precedes image base")
    rva = va - image_base
    matches = []
    for section in sections:
        delta = rva - section["rva"]
        if delta >= 0 and size <= section["raw_size"] - delta:
            matches.append((section["name"], section["raw_offset"] + delta))
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    section_name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset : offset + size], section_name, offset


def decode_rel32_call(body: bytes, offset: int, instruction_va: int):
    require_range(body, offset, 5, "rel32 call")
    if body[offset] != 0xE8:
        raise ValueError("expected E8 rel32 call")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    next_va = instruction_va + 5
    return displacement, next_va, next_va + displacement


class Startup100f1aa0EmptyProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURE_PATH.is_file():
            raise AssertionError(f"fixture is missing: {FIXTURE_PATH}")
        cls.fixture = json.loads(FIXTURE_PATH.read_bytes())
        original_path = ROOT / cls.fixture["original_pe"]["path"]
        cls.pe = original_path.read_bytes()
        cls.machine, cls.magic, cls.image_base, cls.sections = parse_pe32(cls.pe)

    def assert_keys(self, value, expected, label):
        self.assertEqual(set(value), set(expected), f"{label} keys changed")

    def fixture_range(self, record):
        start = hex_int(record["va_start"])
        size = record["size"]
        fixture_bytes = bytes.fromhex(record["hex"])
        self.assertEqual(len(fixture_bytes), size)
        self.assertEqual(hex_int(record["va_end_exclusive"]), start + size)
        actual, section, offset = read_va(
            self.pe, self.image_base, self.sections, start, size
        )
        self.assertEqual((section, offset), (".text", hex_int(record["file_offset"])))
        self.assertEqual(actual, fixture_bytes)
        self.assertEqual(sha256(actual), record["sha256"])
        return actual

    def test_fixture_and_original_pe_are_exact_and_inert(self):
        self.assert_keys(
            self.fixture,
            {
                "schema_version",
                "purpose",
                "original_pe",
                "canonical_index",
                "copy_wrapper",
                "sequence_helper",
                "parent_window",
                "limitations",
            },
            "fixture",
        )
        self.assertEqual(self.fixture["schema_version"], 1)
        self.assertEqual(self.fixture["purpose"], EXPECTED_PURPOSE)
        self.assertEqual(self.fixture["limitations"], EXPECTED_LIMITATIONS)
        original = self.fixture["original_pe"]
        self.assertEqual(len(self.pe), original["size"])
        self.assertEqual(sha256(self.pe), EXPECTED_DLL_SHA256)
        self.assertEqual(original["sha256"], EXPECTED_DLL_SHA256)
        self.assertEqual(
            (self.machine, self.magic, self.image_base),
            (hex_int(original["machine"]), hex_int(original["optional_magic"]),
             hex_int(original["image_base"])),
        )
        text = [section for section in self.sections if section["name"] == ".text"]
        self.assertEqual(len(text), 1)
        expected_text = original["text_section"]
        self.assertEqual(
            text[0],
            {
                "name": expected_text["name"],
                "rva": hex_int(expected_text["rva"]),
                "virtual_size": hex_int(expected_text["virtual_size"]),
                "raw_offset": hex_int(expected_text["raw_offset"]),
                "raw_size": hex_int(expected_text["raw_size"]),
            },
        )

    def test_canonical_sources_and_index_rows_are_exact(self):
        index = self.fixture["canonical_index"]
        index_bytes = (ROOT / index["path"]).read_bytes()
        self.assertEqual(index["sha256"], EXPECTED_INDEX_SHA256)
        self.assertEqual(sha256(index_bytes), EXPECTED_INDEX_SHA256)
        rows = list(
            csv.DictReader(index_bytes.decode("utf-8").splitlines(), delimiter="\t")
        )
        by_entry = {row["entry"]: row for row in rows}
        expected_rows = {
            "100f1aa0": ("decomp_fn_100f1aa0", "32", "100f1aa0-100f1abf"),
            "100ef330": ("decomp_fn_100ef330", "124", "100ef330-100ef3ab"),
        }
        for entry, expected in expected_rows.items():
            row = by_entry[entry]
            self.assertEqual(
                (row["canonical_name"], row["size"], row["body_ranges"]),
                expected,
            )

        for key, expected_hash in (
            ("copy_wrapper", "42a3bfb8a5e82cd1cc46e40022641169bddbb0af62e42f3d1ea53ce98c7e0fd4"),
            ("sequence_helper", "cd306dafa21f1ceeaf16c4f66840cab347d12a264baaa80b690dba6f7ab58f3b"),
        ):
            source = self.fixture[key]["canonical_source"]
            self.assertEqual(source["sha256"], expected_hash)
            self.assertEqual(sha256((ROOT / source["path"]).read_bytes()), expected_hash)

    def test_copy_wrapper_body_and_helper_call_are_exact(self):
        wrapper = self.fixture["copy_wrapper"]
        body = self.fixture_range(wrapper)
        self.assertEqual(wrapper["sha256"], EXPECTED_WRAPPER_SHA256)
        self.assertEqual(body[0:4], b"\x8b\x44\x24\x04")
        self.assertEqual(body[6:8], b"\x8b\xf9")
        self.assertEqual(body[8:10], b"\x8b\x10")
        self.assertEqual(body[10:12], b"\x89\x17")
        self.assertEqual(body[12:15], b"\x8b\x70\x08")
        self.assertEqual(body[15:18], b"\x8d\x04\x56")
        self.assertEqual(body[18:20], b"\x50\x56")
        self.assertEqual(body[25:29], b"\x8b\xc7\x5f\x5e")
        self.assertEqual(body[29:32], b"\xc2\x04\x00")
        self.assertEqual(body.count(b"\xe8"), 1)

        call = wrapper["helper_call"]
        self.assert_keys(
            call, {"va", "bytes", "next_va", "rel32", "target_va"},
            "helper_call",
        )
        call_va = hex_int(call["va"])
        call_offset = call_va - hex_int(wrapper["va_start"])
        displacement, next_va, target_va = decode_rel32_call(
            body, call_offset, call_va
        )
        self.assertEqual(body[call_offset : call_offset + 5], bytes.fromhex(call["bytes"]))
        self.assertEqual((displacement, next_va, target_va),
            (call["rel32"], hex_int(call["next_va"]), hex_int(call["target_va"])))
        self.assertEqual(target_va, 0x100EF330)

    def test_empty_prefix_and_allocator_stop_line_are_exact(self):
        helper = self.fixture["sequence_helper"]
        body = self.fixture_range(helper)
        self.assertEqual(helper["sha256"], EXPECTED_HELPER_SHA256)
        empty = helper["empty_prefix"]
        empty_body = self.fixture_range(empty)
        self.assertEqual(empty["sha256"], EXPECTED_EMPTY_SHA256)
        self.assertEqual(empty_body, body[:23])
        self.assertNotIn(0xE8, empty_body)

        zero = helper["zero_branch"]
        self.assertEqual(empty_body[8:10], bytes.fromhex(zero["test_bytes"]))
        self.assertEqual(empty_body[10:12], bytes.fromhex(zero["branch_bytes"]))
        branch_target = hex_int(zero["branch_va"]) + 2 + struct.unpack_from(
            "<b", bytes.fromhex(zero["branch_bytes"]), 1
        )[0]
        self.assertEqual(branch_target, hex_int(zero["branch_target_va"]))
        self.assertEqual(branch_target, 0x100EF347)
        self.assertEqual(empty_body[12:19], bytes.fromhex(zero["sentinel_store_bytes"]))
        self.assertEqual(struct.unpack_from("<I", empty_body, 15)[0],
            hex_int(zero["guest_identity"]))
        self.assertEqual(empty_body[19:23], bytes.fromhex(zero["return_bytes"]))
        self.assertEqual(empty_body[20], 0xC2)
        self.assertEqual(struct.unpack_from("<H", empty_body, 21)[0],
            zero["callee_cleanup_bytes"])

        boundary = helper["nonempty_boundary"]
        prefix = bytes.fromhex(boundary["prefix_through_allocator_call"])
        self.assertEqual(len(prefix), boundary["prefix_size"])
        self.assertEqual(sha256(prefix), boundary["prefix_sha256"])
        boundary_offset = hex_int(boundary["va_start"]) - hex_int(helper["va_start"])
        self.assertEqual(body[boundary_offset : boundary_offset + len(prefix)], prefix)
        call_va = hex_int(boundary["allocator_call_va"])
        call_offset = call_va - hex_int(helper["va_start"])
        displacement, next_va, target_va = decode_rel32_call(body, call_offset, call_va)
        self.assertEqual(body[call_offset : call_offset + 5],
            bytes.fromhex(boundary["allocator_call_bytes"]))
        self.assertEqual((displacement, next_va, target_va),
            (boundary["allocator_rel32"], hex_int(boundary["allocator_next_va"]),
             hex_int(boundary["allocator_target_va"])))
        self.assertEqual(target_va, 0x100FCC80)
        self.assertEqual(body.count(b"\xe8"), 1)

    def test_parent_has_exactly_two_authenticated_direct_call_sites(self):
        parent = self.fixture["parent_window"]
        body = self.fixture_range(parent)
        self.assertEqual(parent["sha256"], EXPECTED_PARENT_SHA256)
        self.assertEqual(len(parent["calls"]), 2)
        self.assertEqual(body.count(b"\xe8"), 2)
        for call in parent["calls"]:
            call_va = hex_int(call["va"])
            call_offset = call_va - hex_int(parent["va_start"])
            displacement, next_va, target_va = decode_rel32_call(
                body, call_offset, call_va
            )
            self.assertEqual(body[call_offset : call_offset + 5],
                bytes.fromhex(call["bytes"]))
            self.assertEqual((displacement, next_va, target_va),
                (call["rel32"], hex_int(call["next_va"]),
                 hex_int(call["target_va"])))
            self.assertEqual(target_va, 0x100F1AA0)
            for va_key, bytes_key in (
                ("source_address_setup_va", "source_address_setup_bytes"),
                ("destination_prior_load_va", "destination_prior_load_bytes"),
            ):
                instruction_va = hex_int(call[va_key])
                instruction = bytes.fromhex(call[bytes_key])
                offset = instruction_va - hex_int(parent["va_start"])
                self.assertLess(instruction_va, call_va)
                self.assertEqual(body[offset : offset + len(instruction)], instruction)


if __name__ == "__main__":
    unittest.main(verbosity=2)
