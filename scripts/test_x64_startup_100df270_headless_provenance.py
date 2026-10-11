#!/usr/bin/env python3
"""Authenticate the deterministic middle slice of original 0x100df270."""

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
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
    "100f0eb0": "edd6638c9a813298b807f2776c80d2b517ebdbe45ce91c64eda5d00965f3eb8e",
    "100f1aa0": "42a3bfb8a5e82cd1cc46e40022641169bddbb0af62e42f3d1ea53ce98c7e0fd4",
    "100ef330": "cd306dafa21f1ceeaf16c4f66840cab347d12a264baaa80b690dba6f7ab58f3b",
    "1014d170": "e8beeafe648a778ef905c70b13ddc51124d67c01550d070f57f46b2aabe9f4bc",
}

IMAGE_BASE = 0x10000000
BODY_VA = 0x100DF270
BODY_SIZE = 640
BODY_SHA256 = "d5a89108422a8c8a07d7150501805b70cedf81686b2f6a7e105e6d39d3a725f7"

SLICE_VA = 0x100DF343
SLICE_BYTES = bytes.fromhex(
    "6a008d8f0c080000c707f4f27311e85a1b0100"
    "c7871c080000000000008d8f2c080000c7872008000000000000"
    "8b45008987240800008b4504898728080000"
    "8d450850e8152701008d4514508d8f38080000e806270100"
    "8b45208d8fa00800008987440800000fb64524888748080000"
    "8b452889874c0800000fb6452c888750080000"
    "89bf54080000c7875808000000000000c7875c08000000000000"
    "c787600800000000000089bf64080000c7876808000000000000"
    "c7876c08000000000000c7877008000000000000"
    "c7877408000018dc7311c7877808000000000000"
    "c7877c08000000000000c7878008000000000000"
    "c7878808000000000000c7878c08000000000000"
    "c7879408000000000000c78798080000ffffffff"
    "c7879c08000000000000e803dd0600"
)
SLICE_SHA256 = "a28d5aa15f78ba8ae4aac1738d5163d4cccf7d1d6d124eb0c117a6d09914beff"

PRE_PLATFORM_VA = 0x100DF326
PRE_PLATFORM_BYTES = bytes.fromhex(
    "8b35a8f672116a006854389f116a006a5effd66a006a006a006a5dffd6"
)
POST_DIRECT_VA = 0x100DF46D
POST_DIRECT_BYTES = bytes.fromhex(
    "ffb42418040000893d40319f11e8c18d00008d4868e8c93201008bcfe842b00000"
)
POST_VIRTUAL_VA = 0x100DF48E
POST_VIRTUAL_BYTES = bytes.fromhex(
    "8b0d40319f1181c1740800006a028b01ff500c81383b4e0000741f"
    "6a2de8205202006a12e8195202006a16e8125202006a21e80b52020083c410"
    "8b0d40319f1181c1740800006a028b01ff500cc7003b4e0000"
)
EPILOGUE_VA = 0x100DF4E1
EPILOGUE_BYTES = bytes.fromhex("8bc75f5e5d5b81c400040000c20800")

EMPTY_HELPER_VA = 0x100EF330
EMPTY_HELPER_PREFIX = bytes.fromhex(
    "578bf98b0789470485c0750bc747089040af115fc20800"
)

PARENT_VA = 0x100ED454
PARENT_BYTES = bytes.fromhex(
    "e857470000508d442438508d4c246ce8081effff8d4c2428e84f480000"
)

SUBCALLEES = {
    0x100F0EB0: (
        0x000F02B0,
        bytes.fromhex("8b4424048941088bc1c7410400000000c701081e7411c20400"),
        "57c03d1bf27013e09a19ee8f022d1a8cda1d8aebab903c604e89f8911ed207ea",
    ),
    0x100F1AA0: (
        0x000F0EA0,
        bytes.fromhex("8b44240456578bf98b1089178b70088d04565056e877d8ffff8bc75f5ec20400"),
        "cec1214bba5a2c2c8c45487abf0da2412df9dcb634da206f6f6e74f6c619e92e",
    ),
    0x1014D170: (
        0x0014C570,
        bytes.fromhex("c701000000008bc1c7410400000000c3"),
        "0dc45eb005beeee23d821213be4ca374524024b2b55a3305f93a52ebc00206f8",
    ),
}


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
    if body[offset] != 0xE8:
        raise ValueError(f"0x{instruction_va:08x} is not an E8 call")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


class Startup100df270HeadlessProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_full_body_and_deterministic_slice_are_exact(self):
        body, section, offset = read_va(
            self.dll, self.sections, BODY_VA, BODY_SIZE
        )
        self.assertEqual((section, offset), (".text", 0x000DE670))
        self.assertEqual(sha256(body), BODY_SHA256)
        slice_body, section, offset = read_va(
            self.dll, self.sections, SLICE_VA, len(SLICE_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000DE743))
        self.assertEqual(slice_body, SLICE_BYTES)
        self.assertEqual(sha256(slice_body), SLICE_SHA256)
        self.assertEqual(SLICE_VA + len(SLICE_BYTES), POST_DIRECT_VA)

    def test_slice_has_only_the_four_admitted_direct_calls(self):
        calls = {
            0x100DF351: 0x100F0EB0,
            0x100DF386: 0x100F1AA0,
            0x100DF395: 0x100F1AA0,
            0x100DF468: 0x1014D170,
        }
        self.assertEqual(SLICE_BYTES.count(b"\xe8"), len(calls))
        for call_va, target in calls.items():
            self.assertEqual(rel32_target(SLICE_BYTES, SLICE_VA, call_va), target)
        for forbidden in (b"\xff\x15", b"\xff\xd6", b"\xff\x50\x0c"):
            self.assertNotIn(forbidden, SLICE_BYTES)
        self.assertEqual(SLICE_BYTES[0:2], b"\x6a\x00")
        self.assertEqual(SLICE_BYTES[8:14], bytes.fromhex("c707f4f27311"))
        self.assertIn(bytes.fromhex("89bf54080000"), SLICE_BYTES)
        self.assertIn(bytes.fromhex("89bf64080000"), SLICE_BYTES)
        self.assertIn(bytes.fromhex("c7877408000018dc7311"), SLICE_BYTES)
        self.assertIn(bytes.fromhex("c78798080000ffffffff"), SLICE_BYTES)

    def test_platform_prefix_and_side_effecting_suffix_are_excluded(self):
        for va, expected, expected_offset, expected_hash in (
            (PRE_PLATFORM_VA, PRE_PLATFORM_BYTES, 0x000DE726,
             "47d815e428da227d13b5e324bc1e1a0ae0b39c2d24c44fdd75c6c78523b0460e"),
            (POST_DIRECT_VA, POST_DIRECT_BYTES, 0x000DE86D,
             "723bd9e4fdab4eaa8aa9ea40b1f6b01661d2d388c59dacf4ac8f488ca59ee8ed"),
            (POST_VIRTUAL_VA, POST_VIRTUAL_BYTES, 0x000DE88E,
             "a1880c963dd3d2264fdba6215f25f12e8bc0b60964f262bf184eb91dd5440b39"),
        ):
            actual, section, offset = read_va(
                self.dll, self.sections, va, len(expected)
            )
            self.assertEqual((section, offset), (".text", expected_offset))
            self.assertEqual(actual, expected)
            self.assertEqual(sha256(actual), expected_hash)
        self.assertEqual(PRE_PLATFORM_BYTES[-2:], b"\xff\xd6")
        self.assertIn(bytes.fromhex("893d40319f11"), POST_DIRECT_BYTES)
        self.assertEqual(POST_VIRTUAL_BYTES.count(bytes.fromhex("ff500c")), 2)

    def test_admitted_leaf_bodies_are_exact(self):
        for va, (expected_offset, expected, expected_hash) in SUBCALLEES.items():
            actual, section, offset = read_va(
                self.dll, self.sections, va, len(expected)
            )
            self.assertEqual((section, offset), (".text", expected_offset))
            self.assertEqual(actual, expected)
            self.assertEqual(sha256(actual), expected_hash)
        self.assertEqual(SUBCALLEES[0x100F0EB0][1][-3:], b"\xc2\x04\x00")
        self.assertEqual(SUBCALLEES[0x100F1AA0][1][-3:], b"\xc2\x04\x00")
        self.assertEqual(SUBCALLEES[0x1014D170][1][-1:], b"\xc3")

    def test_empty_helper_target_and_zero_branch_are_self_contained(self):
        wrapper = SUBCALLEES[0x100F1AA0][1]
        self.assertEqual(
            rel32_target(wrapper, 0x100F1AA0, 0x100F1AB4),
            EMPTY_HELPER_VA,
        )
        actual, section, offset = read_va(
            self.dll, self.sections, EMPTY_HELPER_VA, len(EMPTY_HELPER_PREFIX)
        )
        self.assertEqual((section, offset), (".text", 0x000EE730))
        self.assertEqual(actual, EMPTY_HELPER_PREFIX)
        self.assertEqual(
            sha256(actual),
            "4453992ce0b1a2df255117ba5d3a67c837b9f9b582dbc178fd42d5cd65533db2",
        )
        self.assertEqual(actual[8:12], bytes.fromhex("85c0750b"))
        self.assertEqual(actual[12:19], bytes.fromhex("c747089040af11"))
        self.assertEqual(actual[19:23], bytes.fromhex("5fc20800"))

    def test_complete_epilogue_is_explicitly_excluded(self):
        actual, section, offset = read_va(
            self.dll, self.sections, EPILOGUE_VA, len(EPILOGUE_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000DE8E1))
        self.assertEqual(actual, EPILOGUE_BYTES)
        self.assertEqual(
            sha256(actual),
            "f7bba3364b25a356892625a1efb456f5f22459b6e56ccb6e2cd6ca462bf392fe",
        )
        self.assertEqual(EPILOGUE_VA + len(EPILOGUE_BYTES), BODY_VA + BODY_SIZE)
        self.assertEqual(actual[-3:], b"\xc2\x08\x00")

    def test_parent_packet_and_call_site_are_exact(self):
        actual, section, offset = read_va(
            self.dll, self.sections, PARENT_VA, len(PARENT_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000EC854))
        self.assertEqual(actual, PARENT_BYTES)
        self.assertEqual(
            sha256(actual),
            "d5d1e05e59ce9530f514a209d763fcd30cf73c893821680c4074e1cffd21da6a",
        )
        self.assertEqual(rel32_target(actual, PARENT_VA, 0x100ED454), 0x100F1BB0)
        self.assertEqual(rel32_target(actual, PARENT_VA, 0x100ED463), BODY_VA)
        self.assertEqual(rel32_target(actual, PARENT_VA, 0x100ED46C), 0x100F1CC0)
        self.assertEqual(actual[5:15], bytes.fromhex("508d442438508d4c246c"))

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
            "100df270": ("decomp_fn_100df270", "640", "100df270-100df4ef"),
            "100ed3c0": ("decomp_fn_100ed3c0", "400", "100ed3c0-100ed54f"),
            "100f0eb0": ("decomp_fn_100f0eb0", "25", "100f0eb0-100f0ec8"),
            "100f1aa0": ("decomp_fn_100f1aa0", "32", "100f1aa0-100f1abf"),
            "100ef330": ("decomp_fn_100ef330", "124", "100ef330-100ef3ab"),
            "1014d170": ("decomp_fn_1014d170", "16", "1014d170-1014d17f"),
        }
        for entry, fields in expected.items():
            row = by_entry[entry]
            self.assertEqual(
                (row["canonical_name"], row["size"], row["body_ranges"]),
                fields,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
