#!/usr/bin/env python3
"""Authenticate original handler 0x100e87a0 as machine evidence only.

The original PE is parsed strictly as data and is never loaded or executed.
These tests pin the complete handler, its registered vtable pair, policy
constructor and callback identities, allocation/null/global-publication
control flow, FaceFX call tuple, no-op cleanup, and AL-only return.  The
portable injected-effect API and its fail-closed prefix-commit policy are port
decisions; no x86 address below is authorized as a native x64 call target.
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

FUNCTION_VA = 0x100E87A0
FUNCTION_BYTES = bytes.fromhex(
    "83ec14"
    "8d0c24"
    "e8e5b5de00"
    "6a04"
    "c744240402000000"
    "c644240801"
    "c744240cb0120d10"
    "c744241090210e10"
    "c7442414a0210e10"
    "e8d98afeff"
    "83c404"
    "85c0"
    "7408"
    "c70028ff7311"
    "eb02"
    "33c0"
    "6a06"
    "50"
    "a358389f11"
    "8d442408"
    "50"
    "e8a6dfde00"
    "83c40c"
    "8d0c24"
    "e85bddfeff"
    "b001"
    "83c414"
    "c20400"
)
FUNCTION_SHA256 = "0917917b3f65047b219059555acfb913b8cd9f91ccf6908e8295619d0dea710d"
FUNCTION_RAW_OFFSET = 0x000E7BA0
DIRECT_CALL_OFFSETS = (6, 50, 85, 96)
DIRECT_CALL_TARGETS = (0x10ED3D90, 0x100D12B0, 0x10ED67A0, 0x100D6560)

REGISTERED_VTABLE_PAIR_VA = 0x1173F2DC
REGISTERED_VTABLE_PAIR_BYTES = bytes.fromhex("70140e10a0870e10")
REGISTERED_VTABLE_PAIR_SHA256 = (
    "2053789917661c2352a1b94f0a09d6e24e534772a0f7cab361ce09de5e0962d2"
)
REGISTERED_VTABLE_PAIR_RAW_OFFSET = 0x0173DCDC
REGISTERED_CONSTRUCTOR_VA = 0x100E1470

LISTENER_VTABLE_VA = 0x1173FF28
LISTENER_VTABLE_BYTES = bytes.fromhex("40140e10c0220e1010140e10")
LISTENER_VTABLE_SHA256 = (
    "a918b100bb37ca2ff326b725e71e93402a7830b887c24f1652196b081754f89d"
)
LISTENER_VTABLE_RAW_OFFSET = 0x0173E928

POLICY_CONSTRUCTOR_VA = 0x10ED3D90
POLICY_CONSTRUCTOR_BYTES = bytes.fromhex(
    "c70100000000"
    "8bc1"
    "c6410400"
    "c7410800000000"
    "c7410c00000000"
    "c7411000000000"
    "c3"
)
POLICY_CONSTRUCTOR_SHA256 = (
    "734ec54e53a4ef7ce721f14dcef8de83298f9f663dab714ae166530dac2ec23d"
)
POLICY_CONSTRUCTOR_RAW_OFFSET = 0x00ED3190

ALLOCATE_WRAPPER_VA = 0x100D12B0
ALLOCATE_WRAPPER_BYTES = bytes.fromhex("6a00ff742408e8c5b9020083c408c3")
ALLOCATE_WRAPPER_SHA256 = (
    "b02e52cdf692d826b0cd12279dd4988b1688add865ed80ef5e281181a0c1d243"
)
ALLOCATE_WRAPPER_RAW_OFFSET = 0x000D06B0
ALLOCATOR_VA = 0x100FCC80
ALLOCATOR_SIZE = 380
ALLOCATOR_SHA256 = "da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8"
ALLOCATOR_RAW_OFFSET = 0x000FC080

ALLOCATE_DEBUG_VA = 0x100E2190
ALLOCATE_DEBUG_BYTES = bytes.fromhex("c744240800000000e9e3aa0100")
ALLOCATE_DEBUG_SHA256 = (
    "2ecc9afa62be900f800ef0e049aa8a458104b28ef5d814fdcebc6cc0ebf07cdb"
)
ALLOCATE_DEBUG_RAW_OFFSET = 0x000E1590
FREE_CALLBACK_VA = 0x100E21A0
FREE_CALLBACK_BYTES = bytes.fromhex("ff742404e8a7aa010059c3")
FREE_CALLBACK_SHA256 = (
    "f89c847f7b5439309b955866f2b43a5211c6bfa66c556cd074922e4aae3d353e"
)
FREE_CALLBACK_RAW_OFFSET = 0x000E15A0
FREE_HELPER_VA = 0x100FCC50
FREE_HELPER_SIZE = 37
FREE_HELPER_SHA256 = "3c9eb430ade389d3f31098476cad63aa88c0ce9f130e7b4781897129d65c1cb4"
FREE_HELPER_RAW_OFFSET = 0x000FC050

GLOBAL_LISTENER_VA = 0x119F3858
FACEFX_STARTUP_VA = 0x10ED67A0
FACEFX_STARTUP_SIZE = 2967
FACEFX_STARTUP_SHA256 = (
    "c07f0a38172dd4db4e4b744c36202247fc9ec71d7521f35497672f2c62bc97cd"
)
FACEFX_STARTUP_RAW_OFFSET = 0x00ED5BA0
NOOP_DESTRUCTOR_VA = 0x100D6560
NOOP_DESTRUCTOR_BYTES = bytes.fromhex("c3")
NOOP_DESTRUCTOR_SHA256 = (
    "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e"
)
NOOP_DESTRUCTOR_RAW_OFFSET = 0x000D5960

CANONICAL_HASHES = {
    "decomp_fn_100e87a0.c":
        "290d0b817e5d9d5fb4fdc9f2803983f5d4945451c36f0b0d1a65e8c0776c53dd",
    "decomp_fn_10ed3d90.c":
        "7964cca6cb0b6a900a1834f5bf9ae0dc3bfe7d9e505605b2959024c005b6caca",
    "decomp_fn_100d12b0.c":
        "664f9d5f53e7f8053bc6cd3ff40173262984c4c26484949e3352b16349de2316",
    "decomp_fn_100fcc80.c":
        "9dbd299240f648438f3e5a9e0a1d55707790af16b4d95c58f190c0475a034e6f",
    "decomp_fn_100fcc50.c":
        "05c04f3a86ed0ffff6869efab3c1a654fddf39ff43c7488f348e311b73fad6ab",
    "decomp_fn_10ed67a0.c":
        "1705ce5ed844e1b81db384963a0e2e47d6604c30672b13cb0c324f331685da09",
    "decomp_fn_100d6560.c":
        "b2dd76946e1873f4fa7ddeb7f0eae493a93649788f0946882777879a4e185bf6",
}

CANONICAL_ROWS = {
    "100e87a0": ("decomp_fn_100e87a0", "109", "100e87a0-100e880c"),
    "10ed3d90": ("decomp_fn_10ed3d90", "34", "10ed3d90-10ed3db1"),
    "100d12b0": ("decomp_fn_100d12b0", "15", "100d12b0-100d12be"),
    "100fcc80": ("decomp_fn_100fcc80", "380", "100fcc80-100fcdfb"),
    "100fcc50": ("decomp_fn_100fcc50", "37", "100fcc50-100fcc74"),
    "10ed67a0": ("decomp_fn_10ed67a0", "2967", "10ed67a0-10ed7336"),
    "100d6560": ("decomp_fn_100d6560", "1", "100d6560-100d6560"),
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
        machine != 0x014C or not 1 <= section_count <= 96 or
        optional_size < 96 or
        struct.unpack_from("<H", data, optional)[0] != 0x010B or
        struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE
    ):
        raise ValueError("original image is not the expected bounded PE32 image")
    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = table + index * 40
        raw_name = data[offset:offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii")
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
    section, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset:offset + size], section, offset


def rel32_target(body: bytes, body_va: int, offset: int, opcode: int = 0xE8) -> int:
    require_range(body, offset, 5, "rel32 transfer")
    if body[offset] != opcode:
        raise ValueError(f"0x{body_va + offset:08x} has the wrong opcode")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return body_va + offset + 5 + displacement


def rel8_target(body: bytes, body_va: int, offset: int, opcode: int) -> int:
    require_range(body, offset, 2, "rel8 branch")
    if body[offset] != opcode:
        raise ValueError(f"0x{body_va + offset:08x} has the wrong branch opcode")
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return body_va + offset + 2 + displacement


class Startup100e87a0HandlerTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_exact_109_byte_handler_control_flow_and_boundaries(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(FUNCTION_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(body, FUNCTION_BYTES)
        self.assertEqual(len(body), 109)
        self.assertEqual(sha256(body), FUNCTION_SHA256)
        self.assertEqual(
            tuple(rel32_target(body, FUNCTION_VA, offset)
                  for offset in DIRECT_CALL_OFFSETS),
            DIRECT_CALL_TARGETS,
        )
        self.assertEqual(rel8_target(body, FUNCTION_VA, 60, 0x74), 0x100E87E6)
        self.assertEqual(rel8_target(body, FUNCTION_VA, 68, 0xEB), 0x100E87E8)
        before, before_section, before_raw = read_va(
            self.dll, self.sections, FUNCTION_VA - 2, 2
        )
        after, after_section, after_raw = read_va(
            self.dll, self.sections, FUNCTION_VA + len(body), 3
        )
        self.assertEqual((before_section, before_raw, before),
                         (".text", FUNCTION_RAW_OFFSET - 2, b"\xcc\xcc"))
        self.assertEqual((after_section, after_raw, after),
                         (".text", FUNCTION_RAW_OFFSET + 109, b"\xcc\xcc\xcc"))

    def test_policy_local_and_opaque_handler_inputs_are_exact(self):
        self.assertEqual(FUNCTION_BYTES[0:11], bytes.fromhex(
            "83ec148d0c24e8e5b5de00"
        ))
        self.assertEqual(FUNCTION_BYTES[11:50], bytes.fromhex(
            "6a04"
            "c744240402000000"
            "c644240801"
            "c744240cb0120d10"
            "c744241090210e10"
            "c7442414a0210e10"
        ))
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 17)[0], 2)
        self.assertEqual(FUNCTION_BYTES[25], 1)
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 30)[0], 0x100D12B0)
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 38)[0], 0x100E2190)
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 46)[0], 0x100E21A0)
        self.assertEqual(FUNCTION_BYTES[-3:], bytes.fromhex("c20400"))

        constructor, section, raw_offset = read_va(
            self.dll, self.sections, POLICY_CONSTRUCTOR_VA,
            len(POLICY_CONSTRUCTOR_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".text", POLICY_CONSTRUCTOR_RAW_OFFSET))
        self.assertEqual(constructor, POLICY_CONSTRUCTOR_BYTES)
        self.assertEqual(sha256(constructor), POLICY_CONSTRUCTOR_SHA256)
        # ECX is overwritten with &local before its first use, and the sole
        # stack argument is discarded only by RET 4.
        self.assertEqual(FUNCTION_BYTES[3:6], bytes.fromhex("8d0c24"))

    def test_allocation_wrapper_and_policy_callback_identities_are_exact(self):
        wrapper, section, raw_offset = read_va(
            self.dll, self.sections, ALLOCATE_WRAPPER_VA,
            len(ALLOCATE_WRAPPER_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".text", ALLOCATE_WRAPPER_RAW_OFFSET))
        self.assertEqual(wrapper, ALLOCATE_WRAPPER_BYTES)
        self.assertEqual(sha256(wrapper), ALLOCATE_WRAPPER_SHA256)
        self.assertEqual(wrapper[:6], bytes.fromhex("6a00ff742408"))
        self.assertEqual(rel32_target(wrapper, ALLOCATE_WRAPPER_VA, 6), ALLOCATOR_VA)

        allocator, section, raw_offset = read_va(
            self.dll, self.sections, ALLOCATOR_VA, ALLOCATOR_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", ALLOCATOR_RAW_OFFSET))
        self.assertEqual(sha256(allocator), ALLOCATOR_SHA256)

        debug, section, raw_offset = read_va(
            self.dll, self.sections, ALLOCATE_DEBUG_VA,
            len(ALLOCATE_DEBUG_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".text", ALLOCATE_DEBUG_RAW_OFFSET))
        self.assertEqual(debug, ALLOCATE_DEBUG_BYTES)
        self.assertEqual(sha256(debug), ALLOCATE_DEBUG_SHA256)
        self.assertEqual(rel32_target(debug, ALLOCATE_DEBUG_VA, 8, 0xE9), ALLOCATOR_VA)

        free_callback, section, raw_offset = read_va(
            self.dll, self.sections, FREE_CALLBACK_VA,
            len(FREE_CALLBACK_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".text", FREE_CALLBACK_RAW_OFFSET))
        self.assertEqual(free_callback, FREE_CALLBACK_BYTES)
        self.assertEqual(sha256(free_callback), FREE_CALLBACK_SHA256)
        self.assertEqual(
            rel32_target(free_callback, FREE_CALLBACK_VA, 4), FREE_HELPER_VA
        )
        free_helper, section, raw_offset = read_va(
            self.dll, self.sections, FREE_HELPER_VA, FREE_HELPER_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", FREE_HELPER_RAW_OFFSET))
        self.assertEqual(sha256(free_helper), FREE_HELPER_SHA256)

    def test_registered_pair_listener_vtable_and_global_publication_are_exact(self):
        pair, section, raw_offset = read_va(
            self.dll, self.sections, REGISTERED_VTABLE_PAIR_VA,
            len(REGISTERED_VTABLE_PAIR_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".rdata", REGISTERED_VTABLE_PAIR_RAW_OFFSET))
        self.assertEqual(pair, REGISTERED_VTABLE_PAIR_BYTES)
        self.assertEqual(sha256(pair), REGISTERED_VTABLE_PAIR_SHA256)
        self.assertEqual(
            struct.unpack("<II", pair), (REGISTERED_CONSTRUCTOR_VA, FUNCTION_VA)
        )

        listener_vtable, section, raw_offset = read_va(
            self.dll, self.sections, LISTENER_VTABLE_VA,
            len(LISTENER_VTABLE_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".rdata", LISTENER_VTABLE_RAW_OFFSET))
        self.assertEqual(listener_vtable, LISTENER_VTABLE_BYTES)
        self.assertEqual(sha256(listener_vtable), LISTENER_VTABLE_SHA256)
        self.assertEqual(
            struct.unpack("<III", listener_vtable),
            (0x100E1440, 0x100E22C0, 0x100E1410),
        )

        self.assertEqual(FUNCTION_BYTES[58:72], bytes.fromhex(
            "85c07408c70028ff7311eb0233c0"
        ))
        self.assertEqual(FUNCTION_BYTES[72:80], bytes.fromhex(
            "6a0650a358389f11"
        ))
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 76)[0],
                         GLOBAL_LISTENER_VA)
        # Both the nonnull vtable store and null XOR converge before the A3
        # global write; null therefore remains a normal published value.
        self.assertEqual(rel8_target(FUNCTION_BYTES, FUNCTION_VA, 60, 0x74),
                         0x100E87E6)
        self.assertEqual(rel8_target(FUNCTION_BYTES, FUNCTION_VA, 68, 0xEB),
                         0x100E87E8)

    def test_facefx_call_tuple_cleanup_and_al_publication_are_exact(self):
        self.assertEqual(FUNCTION_BYTES[72:90], bytes.fromhex(
            "6a0650a358389f118d44240850e8a6dfde00"
        ))
        self.assertEqual(rel32_target(FUNCTION_BYTES, FUNCTION_VA, 85),
                         FACEFX_STARTUP_VA)
        # push 6; push listener; publish listener; push &policy; CALL is the
        # exact cdecl logical tuple (policy, listener, 6).
        self.assertEqual(FUNCTION_BYTES[90:101], bytes.fromhex(
            "83c40c8d0c24e85bddfeff"
        ))
        facefx, section, raw_offset = read_va(
            self.dll, self.sections, FACEFX_STARTUP_VA, FACEFX_STARTUP_SIZE
        )
        self.assertEqual((section, raw_offset),
                         (".text", FACEFX_STARTUP_RAW_OFFSET))
        self.assertEqual(sha256(facefx), FACEFX_STARTUP_SHA256)

        destructor, section, raw_offset = read_va(
            self.dll, self.sections, NOOP_DESTRUCTOR_VA,
            len(NOOP_DESTRUCTOR_BYTES)
        )
        self.assertEqual((section, raw_offset),
                         (".text", NOOP_DESTRUCTOR_RAW_OFFSET))
        self.assertEqual(destructor, NOOP_DESTRUCTOR_BYTES)
        self.assertEqual(sha256(destructor), NOOP_DESTRUCTOR_SHA256)
        self.assertEqual(FUNCTION_BYTES[101:], bytes.fromhex("b00183c414c20400"))
        self.assertNotIn(bytes.fromhex("b801000000"), FUNCTION_BYTES)

    def test_canonical_rows_sources_and_irreducible_native_effects_are_exact(self):
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
        for filename, expected_hash in CANONICAL_HASHES.items():
            self.assertEqual(
                sha256((CANONICAL / filename).read_bytes()), expected_hash
            )

        handler_text = (CANONICAL / "decomp_fn_100e87a0.c").read_text(
            encoding="utf-8"
        )
        for token in (
            "decomp_fn_10ed3d90(&local_14);",
            "local_14 = 2;",
            "local_10 = 1;",
            "local_c = decomp_fn_100d12b0;",
            "local_8 = &LAB_100e2190;",
            "local_4 = &LAB_100e21a0;",
            "DAT_119f3858 = (FxLogListener *)decomp_fn_100d12b0(4);",
            "*(undefined ***)DAT_119f3858 = &PTR_LAB_1173ff28;",
            "decomp_fn_10ed67a0((FxMemoryAllocationPolicy *)&local_14,DAT_119f3858,6);",
            "decomp_fn_100d6560();",
        ):
            self.assertIn(token, handler_text)

        allocator_text = (CANONICAL / "decomp_fn_100fcc80.c").read_text(
            encoding="utf-8"
        )
        for token in (
            "RegOpenKeyExW", "GetProcessHeap()", "HeapSetInformation",
            "decomp_fn_101254a0(param_1)", "(&DAT_119f3eb4)[param_2]",
        ):
            self.assertIn(token, allocator_text)
        facefx_text = (CANONICAL / "decomp_fn_10ed67a0.c").read_text(
            encoding="utf-8"
        )
        for token in (
            "FxMemoryAllocationPolicy *param_1",
            "FxLogListener *param_2",
            "FxLogLevel param_3",
            "decomp_g_119f3890",
            "Starting up FaceFX SDK...",
        ):
            self.assertIn(token, facefx_text)

    def test_evidence_and_port_policy_remain_separate(self):
        normalized = " ".join((__doc__ or "").split())
        self.assertIn("machine evidence only", normalized)
        self.assertIn("port decisions", normalized)
        self.assertIn("no x86 address", normalized)
        self.assertNotIn("safe to call natively", normalized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
