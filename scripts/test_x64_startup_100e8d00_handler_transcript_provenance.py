#!/usr/bin/env python3
"""Authenticate the bounded effect transcript at original 0x100e8d00.

The original PE is parsed strictly as data and is never loaded or executed.
The evidence pins the complete handler body, its vtable slot, all six direct
call targets, the raw push order and callee-visible argument identities, the
PRE_DB_APP_INIT object, deferred stack cleanup, and AL publication ordering.
Nothing here authorizes native linkage to any recovered address.
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
FUNCTION_VA = 0x100E8D00
FUNCTION_BYTES = bytes.fromhex(
    "6a016a00e857d4bc00"
    "6a00e830d00200"
    "6a006844fb7311e8d43c1f01"
    "6a01e87dc30200"
    "6a00e8a6c40200"
    "83c41c"
    "e87e9f1f01"
    "b001c20400"
)
FUNCTION_SHA256 = "721c0a9b4df58497dd3362758ecbb2f73be24e5223bbad3faf01b3442811b3fe"
FUNCTION_RAW_OFFSET = 0x000E8100

CALL_OFFSETS = (4, 11, 23, 30, 37, 45)
CALL_TARGETS = (
    0x10CB6160,
    0x10115D40,
    0x112DC9F0,
    0x101150A0,
    0x101151D0,
    0x112E2CB0,
)

RAW_PUSH_GROUPS = (
    (1, 0),
    (0,),
    (0, 0x1173FB44),
    (1,),
    (0,),
    (),
)
CALLEE_ARGUMENTS = (
    (0, 1),
    (0,),
    (0x1173FB44, 0),
    (1,),
    (0,),
    (),
)

PRE_DB_APP_INIT_VA = 0x1173FB44
PRE_DB_APP_INIT_BYTES = b"PRE_DB_APP_INIT\0"
PRE_DB_APP_INIT_SHA256 = (
    "b9e1501a299ac770d9d93afc12907cf7a7e21280553b2e56c0d1abf4cfda7909"
)
PRE_DB_APP_INIT_RAW_OFFSET = 0x0173E544

VTABLE_PAIR_VA = 0x1173F20C
VTABLE_PAIR_BYTES = bytes.fromhex("20170e10008d0e10")
VTABLE_PAIR_SHA256 = (
    "492887edb7260c8a514ea97b3b158276f1d27b20599980dfb0e50157b0449dea"
)
VTABLE_PAIR_RAW_OFFSET = 0x0173DC0C

CANONICAL_HASHES = {
    "decomp_fn_101150a0.c":
        "6f6a4d093c84226eed472b7ed32ad1c130bf532d65517873393a6cd181706d11",
    "decomp_fn_101151d0.c":
        "f93c1c5f6f6f3471cc2aa088813982e6edba623190a7dccc6466230e5dbb3c54",
    "decomp_fn_10cb6160.c":
        "32bb470e183e00c59c0b387f9f88aa2c6316316c4da5b6c4b3921f09cb099eed",
    "decomp_fn_112dc9f0.c":
        "1db91c95142252eaf43349c6b57327d27f5e527ccac979d5fe1138e201c944b1",
}

CANONICAL_ROWS = {
    "101150a0": (
        "decomp_fn_101150a0", "FUN_101150a0",
        "undefined FUN_101150a0(void)", "47", "func",
        "101150a0-101150ce",
    ),
    "101151d0": (
        "decomp_fn_101151d0", "FUN_101151d0",
        "undefined FUN_101151d0(void)", "25", "func",
        "101151d0-101151e8",
    ),
    "10cb6160": (
        "decomp_fn_10cb6160", "FUN_10cb6160",
        "undefined FUN_10cb6160(void)", "529", "func",
        "10cb6160-10cb6370",
    ),
    "112dc9f0": (
        "decomp_fn_112dc9f0", "FUN_112dc9f0",
        "undefined FUN_112dc9f0(void)", "244", "func",
        "112dc9f0-112dcae3",
    ),
}


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


def rel32_target(body: bytes, instruction_offset: int) -> int:
    require_range(body, instruction_offset, 5, "rel32 call")
    if body[instruction_offset] != 0xE8:
        raise ValueError(
            f"0x{FUNCTION_VA + instruction_offset:08x} is not CALL rel32"
        )
    displacement = struct.unpack_from("<i", body, instruction_offset + 1)[0]
    return FUNCTION_VA + instruction_offset + 5 + displacement


class Startup100e8d00HandlerTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_exact_55_byte_handler_body(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(FUNCTION_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(body, FUNCTION_BYTES)
        self.assertEqual(len(body), 55)
        self.assertEqual(sha256(body), FUNCTION_SHA256)

    def test_all_six_direct_call_targets_are_exact(self):
        observed_offsets = tuple(
            offset for offset, value in enumerate(FUNCTION_BYTES)
            if value == 0xE8
        )
        self.assertEqual(observed_offsets, CALL_OFFSETS)
        self.assertEqual(
            tuple(rel32_target(FUNCTION_BYTES, offset) for offset in CALL_OFFSETS),
            CALL_TARGETS,
        )

    def test_raw_push_order_and_callee_arguments_are_exact(self):
        encoded_push_groups = (
            ((0, bytes.fromhex("6a01")), (2, bytes.fromhex("6a00"))),
            ((9, bytes.fromhex("6a00")),),
            (
                (16, bytes.fromhex("6a00")),
                (18, bytes.fromhex("6844fb7311")),
            ),
            ((28, bytes.fromhex("6a01")),),
            ((35, bytes.fromhex("6a00")),),
            (),
        )
        decoded_groups = []
        for group in encoded_push_groups:
            values = []
            for offset, encoding in group:
                self.assertEqual(
                    FUNCTION_BYTES[offset:offset + len(encoding)], encoding
                )
                if encoding[0] == 0x6A:
                    values.append(encoding[1])
                else:
                    self.assertEqual(encoding[0], 0x68)
                    values.append(struct.unpack_from("<I", encoding, 1)[0])
            decoded_groups.append(tuple(values))

        self.assertEqual(tuple(decoded_groups), RAW_PUSH_GROUPS)
        self.assertEqual(
            tuple(tuple(reversed(group)) for group in decoded_groups),
            CALLEE_ARGUMENTS,
        )
        self.assertEqual(
            FUNCTION_BYTES[42:45],
            bytes.fromhex("83c41c"),
            "seven pushed dwords are discarded before the sixth call",
        )

    def test_complete_instruction_shape_ignores_handler_inputs(self):
        instruction_encodings = (
            "6a01", "6a00", "e857d4bc00",
            "6a00", "e830d00200",
            "6a00", "6844fb7311", "e8d43c1f01",
            "6a01", "e87dc30200",
            "6a00", "e8a6c40200",
            "83c41c", "e87e9f1f01", "b001", "c20400",
        )
        self.assertEqual(
            b"".join(bytes.fromhex(item) for item in instruction_encodings),
            FUNCTION_BYTES,
        )
        self.assertEqual(FUNCTION_BYTES[50:52], bytes.fromhex("b001"))
        self.assertEqual(FUNCTION_BYTES[52:55], bytes.fromhex("c20400"))
        self.assertEqual(
            CALL_OFFSETS[-1] + 5,
            50,
            "AL=1 follows the return from the sixth direct call",
        )

    def test_pre_db_app_init_identity_and_bytes_are_exact(self):
        text, section, raw_offset = read_va(
            self.dll,
            self.sections,
            PRE_DB_APP_INIT_VA,
            len(PRE_DB_APP_INIT_BYTES),
        )
        self.assertEqual(
            (section, raw_offset),
            (".rdata", PRE_DB_APP_INIT_RAW_OFFSET),
        )
        self.assertEqual(text, PRE_DB_APP_INIT_BYTES)
        self.assertEqual(sha256(text), PRE_DB_APP_INIT_SHA256)
        self.assertEqual(CALLEE_ARGUMENTS[2], (PRE_DB_APP_INIT_VA, 0))

    def test_vtable_method_identity_is_exact(self):
        pair, section, raw_offset = read_va(
            self.dll, self.sections, VTABLE_PAIR_VA, len(VTABLE_PAIR_BYTES)
        )
        self.assertEqual((section, raw_offset), (".rdata", VTABLE_PAIR_RAW_OFFSET))
        self.assertEqual(pair, VTABLE_PAIR_BYTES)
        self.assertEqual(sha256(pair), VTABLE_PAIR_SHA256)
        self.assertEqual(struct.unpack("<II", pair), (0x100E1720, FUNCTION_VA))
        self.assertEqual(struct.unpack_from("<I", pair, 4)[0], FUNCTION_VA)

    def test_canonical_callee_authority_and_known_gaps_are_exact(self):
        self.assertEqual(sha256(INDEX.read_bytes()), INDEX_SHA256)
        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                INDEX.read_text(encoding="utf-8").splitlines(), delimiter="\t"
            )
        }

        for entry, expected in CANONICAL_ROWS.items():
            row = rows[entry]
            self.assertEqual(
                (
                    row["canonical_name"],
                    row["original_name"],
                    row["signature"],
                    row["size"],
                    row["kind"],
                    row["body_ranges"],
                ),
                expected,
            )

        for filename, expected_hash in CANONICAL_HASHES.items():
            self.assertEqual(sha256((CANONICAL / filename).read_bytes()), expected_hash)

        self.assertNotIn("100e8d00", rows)
        self.assertNotIn("10115d40", rows)
        self.assertNotIn("112e2cb0", rows)
        self.assertEqual(rows["100e8c80"]["body_ranges"], "100e8c80-100e8cfe")
        self.assertEqual(rows["100e8e80"]["body_ranges"], "100e8e80-100e922a")
        self.assertEqual(rows["10115ca0"]["body_ranges"], "10115ca0-10115ce9")
        self.assertEqual(rows["10115dd0"]["body_ranges"], "10115dd0-10115dda")
        self.assertEqual(rows["112e2c20"]["body_ranges"], "112e2c20-112e2ca6")
        self.assertEqual(rows["112e2ce0"]["body_ranges"], "112e2ce0-112e32a1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
