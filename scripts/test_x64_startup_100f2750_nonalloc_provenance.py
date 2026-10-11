#!/usr/bin/env python3
"""Authenticate the bounded nonallocating subset of original 0x100f2750."""

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

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
CANONICAL_HASHES = {
    "100df270": "9309918694adc92b151210f40eeb1965a144d68b24967a9aa160ecdf8517de72",
    "100f2750": "16c0b2bd1980f7c8870b9a74720c17df25b4f8a883e56f3ba2a4a5eff68f706b",
    "116bde50": "728b229623b1f3920cc393fe27f922620fb6e07ef4df2b3713291834b77f2069",
}

IMAGE_BASE = 0x10000000
BODY_VA = 0x100F2750
BODY_SIZE = 157
BODY_SHA256 = "bf302936751abe0c0d8d59c44a0f1903e1f427f4388fe85b397f73d692243744"

NONALLOC_VA = 0x100F275B
NONALLOC_BYTES = bytes.fromhex(
    "8b073b460477283bfe747d8d04450200000050ff7708ff7608"
    "e8d7b65c018b0783c40c89068bc65f5e83c40cc20400"
)
NONALLOC_SHA256 = "0a2a9e2f5ee334ba45835b9626381c0469c6d9f2b6f29ea7bcced218b6cbee1c"

EXCLUDED_VA = 0x100F278A
EXCLUDED_BYTES = bytes.fromhex(
    "8b4f08894424088d044150518d4c2410e891cbffff8b4424088906"
    "8b44240c8946048b7e088b44241089460881ff9040af11742585ff"
    "74218b7ffc85ff741a57e881260300a1b03e9f1183c40485c07408"
    "6a0057ffd083c4085f8bc65e83c40cc20400"
)
EXCLUDED_SHA256 = "a3202d7bd2e087f54099e3538f0f866d37e753abfbed186cc25708f65c590199"

HELPER_ENTRY_VA = 0x116BDE50
HELPER_ENTRY_BYTES = bytes.fromhex(
    "57568b7424108b4c24148b7c240c8bc18bd103c63bfe7608"
    "3bf80f829402000083f9200f82d2040000"
)
HELPER_ENTRY_SHA256 = "8667436f1a982774ffd568c2cc5662bf2502d3d8c069e74e4f97c68556743f9f"

HELPER_TAIL_VA = 0x116BE34B
HELPER_TAIL_BYTES = bytes.fromhex(
    "83e11f74308bc1c1e902740f8b16891783c70483c60483e90175f1"
    "8bc883e10374138a06880746474975f78da424000000008d4900"
    "8b44240c5e5fc3"
)
HELPER_TAIL_SHA256 = "21bc1288b991185718be8173454906f71342c430083019a29fe503f38f7634eb"

PARENT_VA = 0x100DF46D
PARENT_BYTES = bytes.fromhex(
    "ffb42418040000893d40319f11e8c18d00008d4868e8c93201008bcfe842b00000"
)
PARENT_SHA256 = "723bd9e4fdab4eaa8aa9ea40b1f6b01661d2d388c59dacf4ac8f488ca59ee8ed"


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


def near_jcc_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    if body[offset] != 0x0F or not 0x80 <= body[offset + 1] <= 0x8F:
        raise ValueError(f"0x{instruction_va:08x} is not a near Jcc")
    displacement = struct.unpack_from("<i", body, offset + 2)[0]
    return instruction_va + 6 + displacement


class Startup100f2750NonallocProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_full_body_and_both_top_level_routes_are_exact(self):
        body, section, offset = read_va(
            self.dll, self.sections, BODY_VA, BODY_SIZE
        )
        self.assertEqual((section, offset), (".text", 0x000F1B50))
        self.assertEqual(sha256(body), BODY_SHA256)
        for va, expected, raw_offset, expected_hash in (
            (NONALLOC_VA, NONALLOC_BYTES, 0x000F1B5B, NONALLOC_SHA256),
            (EXCLUDED_VA, EXCLUDED_BYTES, 0x000F1B8A, EXCLUDED_SHA256),
        ):
            actual, section, offset = read_va(
                self.dll, self.sections, va, len(expected)
            )
            self.assertEqual((section, offset), (".text", raw_offset))
            self.assertEqual(actual, expected)
            self.assertEqual(sha256(actual), expected_hash)
        self.assertEqual(NONALLOC_VA + len(NONALLOC_BYTES), EXCLUDED_VA)
        self.assertEqual(EXCLUDED_VA + len(EXCLUDED_BYTES), BODY_VA + BODY_SIZE)

    def test_nonallocating_control_flow_and_copy_width_are_exact(self):
        self.assertEqual(NONALLOC_BYTES[0:7], bytes.fromhex("8b073b46047728"))
        self.assertEqual(NONALLOC_BYTES[7:11], bytes.fromhex("3bfe747d"))
        self.assertEqual(
            NONALLOC_BYTES[11:18], bytes.fromhex("8d044502000000")
        )
        self.assertEqual(
            rel32_target(NONALLOC_BYTES, NONALLOC_VA, 0x100F2774),
            HELPER_ENTRY_VA,
        )
        self.assertIn(bytes.fromhex("8b0783c40c8906"), NONALLOC_BYTES)
        self.assertEqual(NONALLOC_BYTES[-3:], bytes.fromhex("c20400"))
        self.assertEqual(EXCLUDED_BYTES[-3:], bytes.fromhex("c20400"))

    def test_allocation_release_and_callback_route_is_explicitly_excluded(self):
        self.assertEqual(
            rel32_target(EXCLUDED_BYTES, EXCLUDED_VA, 0x100F279A),
            0x100EF330,
        )
        self.assertEqual(
            rel32_target(EXCLUDED_BYTES, EXCLUDED_VA, 0x100F27CA),
            0x10124E50,
        )
        self.assertIn(bytes.fromhex("a1b03e9f11"), EXCLUDED_BYTES)
        self.assertIn(bytes.fromhex("ffd0"), EXCLUDED_BYTES)
        self.assertNotIn(bytes.fromhex("a1b03e9f11"), NONALLOC_BYTES)
        self.assertNotIn(bytes.fromhex("ffd0"), NONALLOC_BYTES)

    def test_short_forward_helper_entry_and_tail_are_exact(self):
        for va, expected, raw_offset, expected_hash in (
            (HELPER_ENTRY_VA, HELPER_ENTRY_BYTES, 0x016BD250,
             HELPER_ENTRY_SHA256),
            (HELPER_TAIL_VA, HELPER_TAIL_BYTES, 0x016BD74B,
             HELPER_TAIL_SHA256),
        ):
            actual, section, offset = read_va(
                self.dll, self.sections, va, len(expected)
            )
            self.assertEqual((section, offset), (".text", raw_offset))
            self.assertEqual(actual, expected)
            self.assertEqual(sha256(actual), expected_hash)
        self.assertEqual(
            near_jcc_target(HELPER_ENTRY_BYTES, HELPER_ENTRY_VA, 0x116BDE6A),
            0x116BE104,
        )
        self.assertEqual(
            near_jcc_target(HELPER_ENTRY_BYTES, HELPER_ENTRY_VA, 0x116BDE73),
            HELPER_TAIL_VA,
        )
        self.assertEqual(
            HELPER_ENTRY_BYTES[32:41], bytes.fromhex("83f9200f82d2040000")
        )
        self.assertEqual(HELPER_TAIL_BYTES[0:3], bytes.fromhex("83e11f"))
        self.assertIn(bytes.fromhex("8b168917"), HELPER_TAIL_BYTES)
        self.assertIn(bytes.fromhex("8a068807"), HELPER_TAIL_BYTES)
        self.assertEqual(HELPER_TAIL_BYTES[-3:], bytes.fromhex("5e5fc3"))
        self.assertNotIn(b"\xe8", HELPER_ENTRY_BYTES + HELPER_TAIL_BYTES)

    def test_fifteen_unit_external_ceiling_is_mechanically_below_threshold(self):
        for count in range(15):
            self.assertLess(2 * (count + 1), 32)
        self.assertEqual(2 * (15 + 1), 32)

    def test_parent_call_site_is_exact(self):
        actual, section, offset = read_va(
            self.dll, self.sections, PARENT_VA, len(PARENT_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000DE86D))
        self.assertEqual(actual, PARENT_BYTES)
        self.assertEqual(sha256(actual), PARENT_SHA256)
        self.assertEqual(
            rel32_target(actual, PARENT_VA, 0x100DF47A), 0x100E8240
        )
        self.assertEqual(
            rel32_target(actual, PARENT_VA, 0x100DF482), BODY_VA
        )
        self.assertEqual(
            rel32_target(actual, PARENT_VA, 0x100DF489), 0x100EA4D0
        )

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
        self.assertEqual(
            (
                by_entry["100f2750"]["canonical_name"],
                by_entry["100f2750"]["size"],
                by_entry["100f2750"]["body_ranges"],
            ),
            ("decomp_fn_100f2750", "157", "100f2750-100f27ec"),
        )
        helper = by_entry["116bde50"]
        self.assertEqual(
            (helper["canonical_name"], helper["size"]),
            ("decomp_fn_116bde50", "1330"),
        )
        self.assertIn("116bde50-116be0ab", helper["body_ranges"])
        self.assertIn("116be2a0-116be386", helper["body_ranges"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
