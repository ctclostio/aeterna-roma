#!/usr/bin/env python3
"""Authenticate the bounded allocation-free append prefix of 0x100e2460."""

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
CANONICAL_SHA256 = "38aa07ab66bd4e551a830131c500a76a9a37a3c67c7f97fbf8fdc6c20bc67451"

IMAGE_BASE = 0x10000000
FUNCTION_VA = 0x100E2460
FUNCTION_SIZE = 252
FUNCTION_SHA256 = "33066e9680f5ed234e0f9fcc114d0542a33b4280cda936ed55e7e6b9b7c82123"

CONTROL_VA = 0x100E2460
CONTROL_BYTES = bytes.fromhex(
    "53568bf18b4e088b46043bc8730f8b460c8b5c240c891c88e9b0000000"
)
CONTROL_SHA256 = "129c7a2963c963a6f498c65ab6c392269eeaf592017904e7d495eaf05dcb188f"

EXCLUDED_VA = 0x100E247D
EXCLUDED_BYTES = bytes.fromhex(
    "85c07524506a04c7460401000000e8f0a701008b4e0883c4088b5c240c"
    "89460c891c88e988000000578b7e0c03c0894604741633c985c0510f48"
    "c1c1e00250e8bfa7010083c408eb0233c08b4e0833d289460c85c97411"
    "8b4e0c8b0497890491428b4e083bd172ef8b5c24108d4424103bc77228"
    "558d148d000000008d6c24148d043a3be85d73148b4e0c8d4424102bc7"
    "c1f8028b048189040aeb068b460c891c8885ff740957e827a7010083c4"
    "045f"
)
EXCLUDED_SHA256 = "a57de6025b31b5dcc04dae6e2063beb9ad1b7c4c960a8740cfaaf557c6c4f37b"

TAIL_VA = 0x100E252D
TAIL_BYTES = bytes.fromhex(
    "ff46088bcb8b03ff7424108b4004ffd08b3570f672118ad86a016a006a00"
    "6a006a00ffd685c075f05e8ac35bc20800"
)
TAIL_SHA256 = "fb4f572129c1d66b60be22c9f9ca6d9698be8a95281df72c232787f279c354c0"

ALLOCATOR_VA = 0x100FCC80
FREE_VA = 0x100FCC50
PEEK_MESSAGE_IAT_VA = 0x1172F670

EA4D0_VA = 0x100EA4D0
EA4D0_SIZE = 265
EA4D0_CALL_OFFSETS = (0x2C, 0x55, 0x7E, 0xA7, 0xD0, 0xF9)
EA060_VA = 0x100EA060
EA060_SIZE = 1123
EA060_CALL_OFFSETS = (
    0x02C, 0x055, 0x07E, 0x0A7, 0x0D0, 0x0F9,
    0x182, 0x1AB, 0x1E0, 0x209, 0x232, 0x25B,
    0x284, 0x2BB, 0x2E4, 0x30D, 0x336, 0x35F,
    0x388, 0x3B1, 0x3DA, 0x403, 0x453,
)

VTABLE_PAIRS = {
    0x1173F20C: (0x100E1720, 0x100E8D00),
    0x1173F214: (0x100D38B0, 0x100E85D0),
    0x1173F21C: (0x100E1250, 0x100E8580),
    0x1173F224: (0x100E1900, 0x100E9340),
    0x1173F2EC: (0x100E18C0, 0x100E92C0),
    0x1173F2DC: (0x100E1470, 0x100E87A0),
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
        or optional_size < 112
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
    return optional, tuple(sections)


def read_rva(data: bytes, sections, rva: int, size: int):
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size in sections:
        delta = rva - section_rva
        if delta >= 0 and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"RVA 0x{rva:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"RVA 0x{rva:08x}")
    return data[offset : offset + size], name, offset


def read_va(data: bytes, sections, va: int, size: int):
    return read_rva(data, sections, va - IMAGE_BASE, size)


def read_c_string(data: bytes, sections, rva: int) -> str:
    raw, _name, offset = read_rva(data, sections, rva, 1)
    del raw
    end = data.find(b"\0", offset)
    if end < 0 or end - offset > 4096:
        raise ValueError(f"unterminated string at RVA 0x{rva:08x}")
    return data[offset:end].decode("ascii")


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    if body[offset] not in (0xE8, 0xE9):
        raise ValueError(f"0x{instruction_va:08x} is not an E8/E9 rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


def imported_name_at_iat(data: bytes, optional: int, sections, iat_va: int):
    import_rva, import_size = struct.unpack_from("<II", data, optional + 104)
    if import_rva == 0 or import_size < 20:
        raise ValueError("bounded import directory is missing")
    for descriptor_index in range(import_size // 20):
        descriptor, _section, _offset = read_rva(
            data, sections, import_rva + descriptor_index * 20, 20
        )
        original_thunk, _stamp, _chain, name_rva, first_thunk = (
            struct.unpack("<IIIII", descriptor)
        )
        if descriptor == b"\0" * 20:
            break
        dll_name = read_c_string(data, sections, name_rva)
        lookup_rva = original_thunk or first_thunk
        for thunk_index in range(65536):
            thunk_bytes, _section, _offset = read_rva(
                data, sections, lookup_rva + thunk_index * 4, 4
            )
            thunk = struct.unpack("<I", thunk_bytes)[0]
            if thunk == 0:
                break
            current_iat_va = IMAGE_BASE + first_thunk + thunk_index * 4
            if current_iat_va != iat_va:
                continue
            if thunk & 0x80000000:
                return dll_name, f"ordinal-{thunk & 0xffff}"
            return dll_name, read_c_string(data, sections, thunk + 2)
    raise ValueError(f"IAT cell 0x{iat_va:08x} is not imported")


class Startup100e2460AppendPrefixProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.optional, cls.sections = parse_pe32(cls.dll)

    def test_canonical_identity_and_index_row_are_exact(self):
        self.assertEqual(sha256(INDEX.read_bytes()), INDEX_SHA256)
        canonical = CANONICAL / "decomp_fn_100e2460.c"
        self.assertTrue(canonical.exists())
        self.assertEqual(sha256(canonical.read_bytes()), CANONICAL_SHA256)
        rows = list(csv.DictReader(
            INDEX.read_text(encoding="utf-8").splitlines(), delimiter="\t"
        ))
        row = {item["entry"]: item for item in rows}["100e2460"]
        self.assertEqual(
            (row["canonical_name"], row["size"], row["body_ranges"]),
            ("decomp_fn_100e2460", "252", "100e2460-100e255b"),
        )

    def test_full_entry_and_three_windows_are_exact(self):
        body, section, offset = read_va(
            self.dll, self.sections, FUNCTION_VA, FUNCTION_SIZE
        )
        self.assertEqual((section, offset), (".text", 0x000E1860))
        self.assertEqual(sha256(body), FUNCTION_SHA256)
        self.assertEqual(
            body, CONTROL_BYTES + EXCLUDED_BYTES + TAIL_BYTES,
            "the three windows must cover the full original function",
        )
        self.assertEqual(sha256(CONTROL_BYTES), CONTROL_SHA256)
        self.assertEqual(sha256(EXCLUDED_BYTES), EXCLUDED_SHA256)
        self.assertEqual(sha256(TAIL_BYTES), TAIL_SHA256)
        self.assertEqual(CONTROL_VA + len(CONTROL_BYTES), EXCLUDED_VA)
        self.assertEqual(EXCLUDED_VA + len(EXCLUDED_BYTES), TAIL_VA)
        self.assertEqual(TAIL_VA + len(TAIL_BYTES), 0x100E255C)

    def test_admitted_control_is_unsigned_preallocated_append_only(self):
        b = CONTROL_BYTES
        self.assertEqual(b[0:4], bytes.fromhex("53568bf1"), "thiscall prologue")
        self.assertEqual(b[4:10], bytes.fromhex("8b4e088b4604"),
                         "load count then capacity")
        self.assertEqual(b[10:14], bytes.fromhex("3bc8730f"),
                         "unsigned count >= capacity exclusion")
        self.assertEqual(CONTROL_VA + 14 + b[13], EXCLUDED_VA)
        self.assertEqual(b[14:17], bytes.fromhex("8b460c"),
                         "load backing identity")
        self.assertEqual(b[17:21], bytes.fromhex("8b5c240c"),
                         "load first stack argument")
        self.assertEqual(b[21:24], bytes.fromhex("891c88"),
                         "store element at backing + count*4")
        self.assertEqual(
            rel32_target(b, CONTROL_VA, CONTROL_VA + 24), TAIL_VA,
            "preallocated control must jump to the mandatory common tail",
        )
        self.assertNotIn(b"\xe8", b, "control window must not call a helper")

    def test_excluded_window_contains_both_allocator_calls_and_free(self):
        body, _section, _offset = read_va(
            self.dll, self.sections, FUNCTION_VA, FUNCTION_SIZE
        )
        self.assertEqual(
            rel32_target(body, FUNCTION_VA, 0x100E248B), ALLOCATOR_VA
        )
        self.assertEqual(
            rel32_target(body, FUNCTION_VA, 0x100E24BC), ALLOCATOR_VA
        )
        self.assertEqual(rel32_target(body, FUNCTION_VA, 0x100E2524), FREE_VA)
        self.assertEqual(body[0x1D:0x21], bytes.fromhex("85c07524"),
                         "capacity-zero branch changed")
        self.assertEqual(body[0x45:0x4C], bytes.fromhex("578b7e0c03c089"),
                         "growth entry changed")

    def test_common_tail_is_mandatory_dispatch_and_message_drain(self):
        b = TAIL_BYTES
        self.assertEqual(b[0:3], bytes.fromhex("ff4608"), "count increment")
        self.assertEqual(
            b[3:16], bytes.fromhex("8bcb8b03ff7424108b4004ffd0"),
            "vtable-slot-4 thiscall dispatch changed",
        )
        self.assertEqual(b[16:22], bytes.fromhex("8b3570f67211"),
                         "PeekMessageW IAT-cell load changed")
        self.assertEqual(
            b[24:36], bytes.fromhex("6a016a006a006a006a00ffd6"),
            "PeekMessageW(NULL,NULL,0,0,PM_REMOVE) call changed",
        )
        self.assertEqual(b[36:40], bytes.fromhex("85c075f0"),
                         "message-drain back edge changed")
        self.assertEqual(
            TAIL_VA + 40 + struct.unpack("<b", b[39:40])[0],
            0x100E2545,
            "message-drain branch target changed",
        )
        self.assertEqual(b[-7:], bytes.fromhex("5e8ac35bc20800"),
                         "saved AL result or ret 8 epilogue changed")
        self.assertEqual(
            imported_name_at_iat(
                self.dll, self.optional, self.sections, PEEK_MESSAGE_IAT_VA
            ),
            ("USER32.dll", "PeekMessageW"),
        )

    def test_direct_callers_and_vtable_method_pairs_are_exact(self):
        for caller_va, caller_size, expected_offsets in (
            (EA4D0_VA, EA4D0_SIZE, EA4D0_CALL_OFFSETS),
            (EA060_VA, EA060_SIZE, EA060_CALL_OFFSETS),
        ):
            body, section, _offset = read_va(
                self.dll, self.sections, caller_va, caller_size
            )
            self.assertEqual(section, ".text")
            actual_offsets = tuple(
                offset
                for offset in range(len(body) - 4)
                if body[offset] == 0xE8
                and rel32_target(body, caller_va, caller_va + offset)
                    == FUNCTION_VA
            )
            self.assertEqual(actual_offsets, expected_offsets)

        for vtable, expected_pair in VTABLE_PAIRS.items():
            pair, section, _offset = read_va(
                self.dll, self.sections, vtable, 8
            )
            self.assertEqual(section, ".rdata")
            self.assertEqual(struct.unpack("<II", pair), expected_pair)


if __name__ == "__main__":
    unittest.main(verbosity=2)
