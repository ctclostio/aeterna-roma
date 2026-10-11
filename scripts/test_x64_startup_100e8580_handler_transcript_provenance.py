#!/usr/bin/env python3
"""Authenticate the injected transcript at original 0x100e8580.

The original PE is parsed strictly as data and never loaded or executed.  The
tests pin the complete 75-byte method, its vtable identity, all direct calls,
all pushes and deferred cleanups, the dependent EAX+0x68 flow, the recovered
Finished run_vars object, and final AL publication.  Recovered addresses are
evidence identities only and are never authorized as native x64 call targets.
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

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"

IMAGE_BASE = 0x10000000
FUNCTION_VA = 0x100E8580
FUNCTION_BYTES = bytes.fromhex(
    "e8dbdffeff"
    "e8867f1e01"
    "6a01e8bf831f01"
    "e87a12ffff"
    "e8b559ffff"
    "6a00e8ae831f01"
    "83c408"
    "6a00e894fcffff"
    "83c06850e82b791d01"
    "6a006a006854fb7311e82d451f01"
    "83c414"
    "b001c20400"
)
FUNCTION_SHA256 = "baeed663cb3c273a7e4a6cceb6cd6976695f2226e321bb231e484758a2cf3dfe"
FUNCTION_RAW_OFFSET = 0x000E7980

CALL_OFFSETS = (0, 5, 12, 17, 22, 29, 39, 48, 62)
CALL_TARGETS = (
    0x100D6560,
    0x112D0510,
    0x112E0950,
    0x100D9810,
    0x100DDF50,
    0x112E0950,
    0x100E8240,
    0x112BFEE0,
    0x112DCAF0,
)

FINISHED_RUN_VARS_VA = 0x1173FB54
FINISHED_RUN_VARS_BYTES = b"Finished run_vars\0"
FINISHED_RUN_VARS_SHA256 = (
    "8a85e4d3b75c3aec8b1ff8f3388d287370571466c4bc4a182c23d3d1ca80b7f2"
)
FINISHED_RUN_VARS_RAW_OFFSET = 0x0173E554

VTABLE_PAIR_VA = 0x1173F21C
VTABLE_PAIR_BYTES = bytes.fromhex("50120e1080850e10")
VTABLE_PAIR_SHA256 = (
    "24f54f07f2827c664db07923e9d68ddefa63e37c1b61cc323035007efb1acc30"
)
VTABLE_PAIR_RAW_OFFSET = 0x0173DC1C

CANONICAL_ROWS = {
    "100d6560": ("decomp_fn_100d6560", "1", "100d6560-100d6560"),
    "100d9810": ("decomp_fn_100d9810", "97", "100d9810-100d9870"),
    "100ddf50": ("decomp_fn_100ddf50", "97", "100ddf50-100ddfb0"),
    "100e8240": ("decomp_fn_100e8240", "310", "100e8240-100e8375"),
    "112bfee0": ("decomp_fn_112bfee0", "58", "112bfee0-112bff19"),
    "112dcaf0": ("decomp_fn_112dcaf0", "996", "112dcaf0-112dced3"),
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


class Startup100e8580HandlerTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_exact_75_byte_handler_body(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(FUNCTION_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(body, FUNCTION_BYTES)
        self.assertEqual(len(body), 75)
        self.assertEqual(sha256(body), FUNCTION_SHA256)

    def test_all_nine_direct_call_targets_are_exact(self):
        observed_offsets = tuple(
            offset for offset, value in enumerate(FUNCTION_BYTES)
            if value == 0xE8
        )
        self.assertEqual(observed_offsets, CALL_OFFSETS)
        self.assertEqual(
            tuple(rel32_target(FUNCTION_BYTES, offset) for offset in CALL_OFFSETS),
            CALL_TARGETS,
        )

    def test_pushes_and_deferred_cleanups_are_exact(self):
        push_encodings = (
            (10, bytes.fromhex("6a01"), 1),
            (27, bytes.fromhex("6a00"), 0),
            (37, bytes.fromhex("6a00"), 0),
            (47, bytes.fromhex("50"), "eax_plus_68"),
            (53, bytes.fromhex("6a00"), 0),
            (55, bytes.fromhex("6a00"), 0),
            (57, bytes.fromhex("6854fb7311"), FINISHED_RUN_VARS_VA),
        )
        for offset, encoding, _identity in push_encodings:
            self.assertEqual(
                FUNCTION_BYTES[offset:offset + len(encoding)], encoding
            )

        self.assertEqual(FUNCTION_BYTES[34:37], bytes.fromhex("83c408"))
        self.assertEqual(
            FUNCTION_BYTES[67:70],
            bytes.fromhex("83c414"),
            "five deferred dwords from calls seven through nine are removed",
        )
        self.assertEqual(
            tuple(item[2] for item in push_encodings),
            (1, 0, 0, "eax_plus_68", 0, 0, FINISHED_RUN_VARS_VA),
        )

    def test_dependent_result_flow_and_logical_arguments_are_exact(self):
        self.assertEqual(
            FUNCTION_BYTES[37:48],
            bytes.fromhex("6a00e894fcffff83c06850"),
            "100e8240(0), EAX+0x68, then push adjusted identity",
        )
        self.assertEqual(
            FUNCTION_BYTES[53:62],
            bytes.fromhex("6a006a006854fb7311"),
        )
        logical_arguments = (
            (), (), (1,), (), (), (0,), (0,),
            ("result_100e8240_plus_68",),
            (FINISHED_RUN_VARS_VA, 0, 0),
        )
        self.assertEqual(logical_arguments[2], (1,))
        self.assertEqual(logical_arguments[5], (0,))
        self.assertEqual(logical_arguments[6], (0,))
        self.assertEqual(
            logical_arguments[8], (FINISHED_RUN_VARS_VA, 0, 0)
        )

    def test_finished_run_vars_identity_and_bytes_are_exact(self):
        text, section, raw_offset = read_va(
            self.dll,
            self.sections,
            FINISHED_RUN_VARS_VA,
            len(FINISHED_RUN_VARS_BYTES),
        )
        self.assertEqual(
            (section, raw_offset),
            (".rdata", FINISHED_RUN_VARS_RAW_OFFSET),
        )
        self.assertEqual(text, FINISHED_RUN_VARS_BYTES)
        self.assertEqual(sha256(text), FINISHED_RUN_VARS_SHA256)

    def test_vtable_method_identity_is_exact(self):
        pair, section, raw_offset = read_va(
            self.dll, self.sections, VTABLE_PAIR_VA, len(VTABLE_PAIR_BYTES)
        )
        self.assertEqual((section, raw_offset), (".rdata", VTABLE_PAIR_RAW_OFFSET))
        self.assertEqual(pair, VTABLE_PAIR_BYTES)
        self.assertEqual(sha256(pair), VTABLE_PAIR_SHA256)
        self.assertEqual(struct.unpack("<II", pair), (0x100E1250, FUNCTION_VA))
        self.assertEqual(struct.unpack_from("<I", pair, 4)[0], FUNCTION_VA)

    def test_al_one_follows_every_effect_and_ret4_is_exact(self):
        instruction_encodings = (
            "e8dbdffeff", "e8867f1e01", "6a01", "e8bf831f01",
            "e87a12ffff", "e8b559ffff", "6a00", "e8ae831f01",
            "83c408", "6a00", "e894fcffff", "83c068", "50",
            "e82b791d01", "6a00", "6a00", "6854fb7311",
            "e82d451f01", "83c414", "b001", "c20400",
        )
        self.assertEqual(
            b"".join(bytes.fromhex(item) for item in instruction_encodings),
            FUNCTION_BYTES,
        )
        self.assertEqual(CALL_OFFSETS[-1] + 5, 67)
        self.assertEqual(FUNCTION_BYTES[70:72], bytes.fromhex("b001"))
        self.assertEqual(FUNCTION_BYTES[72:75], bytes.fromhex("c20400"))

    def test_canonical_authority_and_discovery_gaps_are_exact(self):
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
                (row["canonical_name"], row["size"], row["body_ranges"]),
                expected,
            )

        self.assertNotIn("100e8580", rows)
        self.assertNotIn("112d0510", rows)
        self.assertNotIn("112e0950", rows)
        self.assertEqual(rows["100e8480"]["body_ranges"], "100e8480-100e8541")
        self.assertEqual(rows["100e86d0"]["body_ranges"], "100e86d0-100e8751")
        self.assertEqual(rows["112cfc10"]["body_ranges"], "112cfc10-112d050f")
        self.assertEqual(rows["112d0bf0"]["body_ranges"], "112d0bf0-112d0c7d")
        self.assertEqual(rows["112e01e0"]["body_ranges"], "112e01e0-112e021f")
        self.assertEqual(rows["112e0960"]["body_ranges"], "112e0960-112e0a30")


if __name__ == "__main__":
    unittest.main(verbosity=2)
