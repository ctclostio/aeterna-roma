#!/usr/bin/env python3
"""Authenticate the remaining original 0x100df270 suffix as inert evidence.

The original PE is parsed strictly as data and is never loaded or executed.
These tests pin the complete 131-byte suffix, its receiver and stack-argument
provenance, direct-call order, global publication, both selector-2 virtual
queries, conditional four-call branch, final 0x4e3b publication, and receiver
return.  Original x86 addresses remain evidence identities, not native x64
call targets.
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

FUNCTION_VA = 0x100DF270
FUNCTION_SIZE = 640
FUNCTION_RAW_OFFSET = 0x000DE670
FUNCTION_SHA256 = "d5a89108422a8c8a07d7150501805b70cedf81686b2f6a7e105e6d39d3a725f7"

PROLOGUE_BYTES = bytes.fromhex(
    "81ec00040000"       # sub esp, 0x400
    "53"               # push ebx
    "55"               # push ebp
    "8bac240c040000"   # mov ebp, [esp+0x40c] (first stack argument)
    "56"               # push esi
    "8b356cf67211"     # mov esi, [0x1172f66c]
    "57"               # push edi
    "8b5500"           # mov edx, [ebp]
    "8bf9"             # mov edi, ecx (receiver)
)
PROLOGUE_SHA256 = "e6e1a6ac697efd91a15f8ad9c4f79da1ff6384a974ee78e5689e6a19abab8103"

SUFFIX_VA = 0x100DF46D
SUFFIX_END_VA = 0x100DF4F0
SUFFIX_RAW_OFFSET = 0x000DE86D
SUFFIX_BYTES = bytes.fromhex(
    "ffb42418040000"     # push original second stack argument
    "893d40319f11"       # [0x119f3140] = edi
    "e8c18d0000"         # 0x100e8240
    "8d4868"             # ecx = eax + 0x68
    "e8c9320100"         # 0x100f2750; consumes the pending argument
    "8bcf"               # ecx = edi
    "e842b00000"         # 0x100ea4d0
    "8b0d40319f11"       # ecx = [0x119f3140]
    "81c174080000"       # ecx += 0x874
    "6a02"               # selector 2
    "8b01"               # eax = [ecx]
    "ff500c"             # call [eax+0x0c]
    "81383b4e0000"       # compare returned dword with 0x4e3b
    "741f"               # equal: skip the four direct calls
    "6a2d" "e820520200" # 0x101046d0(0x2d)
    "6a12" "e819520200" # 0x101046d0(0x12)
    "6a16" "e812520200" # 0x101046d0(0x16)
    "6a21" "e80b520200" # 0x101046d0(0x21)
    "83c410"             # caller cleanup for four cdecl arguments
    "8b0d40319f11"       # ecx = [0x119f3140]
    "81c174080000"       # ecx += 0x874
    "6a02"               # selector 2
    "8b01"               # eax = [ecx]
    "ff500c"             # call [eax+0x0c]
    "c7003b4e0000"       # publish 0x4e3b through returned pointer
    "8bc7"               # eax = edi (return receiver)
    "5f5e5d5b"           # restore edi, esi, ebp, ebx
    "81c400040000"       # discard 0x400-byte local frame
    "c20800"             # return and pop two stack arguments
)
SUFFIX_SHA256 = "27ee666d2327c9360be2f4175ee5ea58bf49e112a6a29af6760451d6a7341b75"

GLOBAL_RECEIVER_VA = 0x119F3140
OWNER_VTABLE_FIELD_OFFSET = 0x874
SELECTOR = 2
FINAL_MARKER = 0x4E3B

DIRECT_CALL_OFFSETS = (0x0D, 0x15, 0x1C, 0x3E, 0x45, 0x4C, 0x53)
DIRECT_CALL_TARGETS = (
    0x100E8240,
    0x100F2750,
    0x100EA4D0,
    0x101046D0,
    0x101046D0,
    0x101046D0,
    0x101046D0,
)
CONDITIONAL_ARGUMENTS = (0x2D, 0x12, 0x16, 0x21)
FIRST_VIRTUAL_OFFSET = 0x21
SECOND_VIRTUAL_OFFSET = 0x5B
CONDITIONAL_BRANCH_OFFSET = 0x3A
FINAL_STORE_OFFSET = 0x6E
EPILOGUE_OFFSET = 0x74

# The deterministic middle region writes this vtable identity into receiver
# +0x874 before the suffix publishes the receiver globally and queries it.
OWNER_VTABLE_STORE_VA = 0x100DF40E
OWNER_VTABLE_STORE_BYTES = bytes.fromhex("c7877408000018dc7311")
OWNER_VTABLE_STORE_SHA256 = (
    "4106f745d4f2da3fdb473f17d025131207b056778fe8669da8026bf0e9e5c22f"
)
OWNER_VTABLE_VA = 0x1173DC18
OWNER_VTABLE_BYTES = bytes.fromhex(
    "d07c0d10"  # +0x00 -> 0x100d7cd0
    "f07c0d10"  # +0x04 -> 0x100d7cf0
    "a07c0d10"  # +0x08 -> 0x100d7ca0
    "b07c0d10"  # +0x0c -> 0x100d7cb0 (queried slot)
)
OWNER_VTABLE_SHA256 = "9a0d519d0650c71ac22f44ed71db5ba81b3396bfabbb0dbce56cc4c1cdb1be80"
OWNER_VTABLE_RAW_OFFSET = 0x0173C618
SELECTOR_VIRTUAL_TARGET = 0x100D7CB0
SELECTOR_VIRTUAL_BYTES = bytes.fromhex(
    "8b442404"           # eax = selector
    "83f844"             # compare selector with 0x44
    "770d"               # out-of-range fallback
    "8b0485f82d9f11"     # eax = [0x119f2df8 + selector*4]
    "83c048"             # eax += 0x48
    "c20400"             # callee pops selector
    "b80c2f9f11"         # fallback pointer 0x119f2f0c
    "c20400"
)

BODY_AUTHORITIES = {
    "100d7cb0": (30, 0x000D70B0,
        "8e7c3cb7be9f858b1dff371942d43c20ba1bd4f244fd89523232a19ac9923ca3"),
    "100e8240": (310, 0x000E7640,
        "efb0d9f3230f06154ec5468d071a78b162d30b31f36d00c86cdfe2bf855bb61c"),
    "100ea4d0": (265, 0x000E98D0,
        "582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3"),
    "100f2750": (157, 0x000F1B50,
        "bf302936751abe0c0d8d59c44a0f1903e1f427f4388fe85b397f73d692243744"),
    "101046d0": (370, 0x00103AD0,
        "f483c236006d96b5a858d85e0c0bf2fa3f127a0a4ddf63083b4ae40941fb9bb1"),
}

# 0x100e8240's admitted completed route publishes this exact EAX identity.
# Its short already-initialized branch and its long initialization route both
# converge on the same MOV/epilogue; the suffix then derives identity +0x68.
CRASH_RECORD_RETURN_VA = 0x100E825F
CRASH_RECORD_RETURN_BYTES = bytes.fromhex("b8383a9f1183c40cc3")
CRASH_RECORD_RETURN_SHA256 = (
    "2f9276c71c07bfbd5ce6bbd7a0c1a4f35ee263c468ff7ee4e1d91f52c8b16e21"
)
CRASH_RECORD_IDENTITY = 0x119F3A38
CRASH_RECORD_EARLY_REJOIN_VA = 0x100E827C
CRASH_RECORD_EARLY_REJOIN_BYTES = bytes.fromhex("75e1")
CRASH_RECORD_EARLY_REJOIN_SHA256 = (
    "3e03e8f456dc4cfddce0a70f78db5f71e70bab19b2b01724156fd1c0b02162a1"
)
CRASH_RECORD_FINAL_REJOIN_VA = 0x100E8371
CRASH_RECORD_FINAL_REJOIN_BYTES = bytes.fromhex("e9e9feffff")
CRASH_RECORD_FINAL_REJOIN_SHA256 = (
    "48d313fccc8440682781d9c280fba27d63ee9444d88dcd8b1e6e21a2b30f1078"
)

CANONICAL_HASHES = {
    "decomp_fn_100d7cb0.c":
        "68f4b19452352fc709c6745163061c81481d608a293e883c13824f068edec909",
    "decomp_fn_100df270.c":
        "9309918694adc92b151210f40eeb1965a144d68b24967a9aa160ecdf8517de72",
    "decomp_fn_100e8240.c":
        "aa030e847e3d0ab772c70c11a58d36c9a14680f3d5cf357f4b9066a9d53b551b",
    "decomp_fn_100ea4d0.c":
        "122ca8ff594fb0becdc7c07999f235b64418efd18f0f08026a25ad9da066ce99",
    "decomp_fn_100f2750.c":
        "16c0b2bd1980f7c8870b9a74720c17df25b4f8a883e56f3ba2a4a5eff68f706b",
    "decomp_fn_101046d0.c":
        "310dbe3bf261ebe48cfa35f6aa87848bef4e03f916b19d26ddc1754731bc8d88",
}

CANONICAL_ROWS = {
    "100d7cb0": ("decomp_fn_100d7cb0", "30", "100d7cb0-100d7ccd"),
    "100df270": ("decomp_fn_100df270", "640", "100df270-100df4ef"),
    "100e8240": ("decomp_fn_100e8240", "310", "100e8240-100e8375"),
    "100ea4d0": ("decomp_fn_100ea4d0", "265", "100ea4d0-100ea5d8"),
    "100f2750": ("decomp_fn_100f2750", "157", "100f2750-100f27ec"),
    "101046d0": ("decomp_fn_101046d0", "370", "101046d0-10104841"),
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


def rel32_target(body: bytes, body_va: int, instruction_offset: int) -> int:
    require_range(body, instruction_offset, 5, "rel32 call")
    if body[instruction_offset] != 0xE8:
        raise ValueError(
            f"0x{body_va + instruction_offset:08x} is not CALL rel32"
        )
    displacement = struct.unpack_from("<i", body, instruction_offset + 1)[0]
    return body_va + instruction_offset + 5 + displacement


def rel8_target(body: bytes, body_va: int, instruction_offset: int) -> int:
    require_range(body, instruction_offset, 2, "short branch")
    displacement = struct.unpack_from("<b", body, instruction_offset + 1)[0]
    return body_va + instruction_offset + 2 + displacement


def rel32_jump_target(body: bytes, body_va: int, instruction_offset: int) -> int:
    require_range(body, instruction_offset, 5, "rel32 jump")
    if body[instruction_offset] != 0xE9:
        raise ValueError(
            f"0x{body_va + instruction_offset:08x} is not JMP rel32"
        )
    displacement = struct.unpack_from("<i", body, instruction_offset + 1)[0]
    return body_va + instruction_offset + 5 + displacement


class Startup100df270SuffixTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_exact_131_byte_suffix_and_function_boundaries(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, FUNCTION_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(len(body), FUNCTION_SIZE)
        self.assertEqual(sha256(body), FUNCTION_SHA256)

        suffix, section, raw_offset = read_va(
            self.dll, self.sections, SUFFIX_VA, len(SUFFIX_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", SUFFIX_RAW_OFFSET))
        self.assertEqual(suffix, SUFFIX_BYTES)
        self.assertEqual(len(suffix), 131)
        self.assertEqual(sha256(suffix), SUFFIX_SHA256)
        self.assertEqual(SUFFIX_VA + len(suffix), SUFFIX_END_VA)
        self.assertEqual(SUFFIX_END_VA, FUNCTION_VA + FUNCTION_SIZE)
        self.assertEqual(0x100DF343 + 298, SUFFIX_VA)

    def test_receiver_and_second_stack_argument_provenance_are_exact(self):
        prologue, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(PROLOGUE_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(prologue, PROLOGUE_BYTES)
        self.assertEqual(sha256(prologue), PROLOGUE_SHA256)
        self.assertEqual(prologue[-2:], bytes.fromhex("8bf9"))

        # At the suffix, ESP is entry ESP - 0x400 - four saved registers.
        # Therefore [ESP+0x418] is entry [ESP+8], the second stack argument.
        self.assertEqual(0x418 - 0x400 - 4 * 4, 8)
        self.assertEqual(SUFFIX_BYTES[0:7], bytes.fromhex("ffb42418040000"))
        self.assertEqual(
            SUFFIX_BYTES[7:13],
            bytes.fromhex("893d") + struct.pack("<I", GLOBAL_RECEIVER_VA),
        )
        self.assertEqual(SUFFIX_BYTES[0x1A:0x1C], bytes.fromhex("8bcf"))

    def test_direct_call_order_and_argument_lifetime_are_exact(self):
        observed_offsets = tuple(
            offset for offset, value in enumerate(SUFFIX_BYTES)
            if value == 0xE8
        )
        self.assertEqual(observed_offsets, DIRECT_CALL_OFFSETS)
        self.assertEqual(
            tuple(
                rel32_target(SUFFIX_BYTES, SUFFIX_VA, offset)
                for offset in DIRECT_CALL_OFFSETS
            ),
            DIRECT_CALL_TARGETS,
        )
        self.assertEqual(
            SUFFIX_BYTES[0x12:0x1C],
            bytes.fromhex("8d4868e8c93201008bcf"),
        )
        # There is no caller stack adjustment between the first two calls:
        # the pending stack argument survives 0x100e8240, while ECX becomes
        # its EAX result +0x68 for the thiscall 0x100f2750 invocation.
        self.assertNotIn(bytes.fromhex("83c404"), SUFFIX_BYTES[0x12:0x1A])

    def test_global_owner_and_two_selector_virtual_calls_are_exact(self):
        store, section, raw_offset = read_va(
            self.dll,
            self.sections,
            OWNER_VTABLE_STORE_VA,
            len(OWNER_VTABLE_STORE_BYTES),
        )
        self.assertEqual((section, raw_offset), (".text", 0x000DE80E))
        self.assertEqual(store, OWNER_VTABLE_STORE_BYTES)
        self.assertEqual(sha256(store), OWNER_VTABLE_STORE_SHA256)

        table, section, raw_offset = read_va(
            self.dll, self.sections, OWNER_VTABLE_VA, len(OWNER_VTABLE_BYTES)
        )
        self.assertEqual((section, raw_offset), (".rdata", OWNER_VTABLE_RAW_OFFSET))
        self.assertEqual(table, OWNER_VTABLE_BYTES)
        self.assertEqual(sha256(table), OWNER_VTABLE_SHA256)
        self.assertEqual(struct.unpack_from("<I", table, 0x0C)[0],
                         SELECTOR_VIRTUAL_TARGET)

        virtual_query = (
            bytes.fromhex("8b0d")
            + struct.pack("<I", GLOBAL_RECEIVER_VA)
            + bytes.fromhex("81c1")
            + struct.pack("<I", OWNER_VTABLE_FIELD_OFFSET)
            + bytes((0x6A, SELECTOR, 0x8B, 0x01, 0xFF, 0x50, 0x0C))
        )
        self.assertEqual(len(virtual_query), 19)
        self.assertEqual(
            SUFFIX_BYTES[FIRST_VIRTUAL_OFFSET:FIRST_VIRTUAL_OFFSET + 19],
            virtual_query,
        )
        self.assertEqual(
            SUFFIX_BYTES[SECOND_VIRTUAL_OFFSET:SECOND_VIRTUAL_OFFSET + 19],
            virtual_query,
        )
        self.assertEqual(SUFFIX_BYTES.count(bytes.fromhex("ff500c")), 2)
        self.assertEqual(SUFFIX_BYTES.count(struct.pack("<I", GLOBAL_RECEIVER_VA)), 3)

        selector_body, section, raw_offset = read_va(
            self.dll,
            self.sections,
            SELECTOR_VIRTUAL_TARGET,
            len(SELECTOR_VIRTUAL_BYTES),
        )
        self.assertEqual((section, raw_offset), (".text", 0x000D70B0))
        self.assertEqual(selector_body, SELECTOR_VIRTUAL_BYTES)
        self.assertEqual(selector_body.count(bytes.fromhex("c20400")), 2)

    def test_conditional_four_call_route_and_final_marker_are_exact(self):
        self.assertEqual(
            SUFFIX_BYTES[0x34:0x3A],
            bytes.fromhex("8138") + struct.pack("<I", FINAL_MARKER),
        )
        self.assertEqual(SUFFIX_BYTES[CONDITIONAL_BRANCH_OFFSET], 0x74)
        self.assertEqual(
            rel8_target(SUFFIX_BYTES, SUFFIX_VA, CONDITIONAL_BRANCH_OFFSET),
            SUFFIX_VA + SECOND_VIRTUAL_OFFSET,
        )

        for index, argument in enumerate(CONDITIONAL_ARGUMENTS):
            push_offset = 0x3C + index * 7
            call_offset = push_offset + 2
            self.assertEqual(
                SUFFIX_BYTES[push_offset:push_offset + 2],
                bytes((0x6A, argument)),
            )
            self.assertEqual(
                rel32_target(SUFFIX_BYTES, SUFFIX_VA, call_offset),
                0x101046D0,
            )
        self.assertEqual(SUFFIX_BYTES[0x58:0x5B], bytes.fromhex("83c410"))
        self.assertEqual(
            SUFFIX_BYTES[FINAL_STORE_OFFSET:FINAL_STORE_OFFSET + 6],
            bytes.fromhex("c700") + struct.pack("<I", FINAL_MARKER),
        )

    def test_epilogue_returns_receiver_and_pops_two_arguments(self):
        epilogue = SUFFIX_BYTES[EPILOGUE_OFFSET:]
        self.assertEqual(len(epilogue), 15)
        self.assertEqual(
            epilogue,
            bytes.fromhex("8bc75f5e5d5b81c400040000c20800"),
        )
        self.assertEqual(epilogue[0:2], bytes.fromhex("8bc7"))
        self.assertEqual(epilogue[-3:], bytes.fromhex("c20800"))

    def test_all_direct_and_resolved_virtual_callee_bodies_are_pinned(self):
        for entry, (size, raw_offset, expected_hash) in BODY_AUTHORITIES.items():
            body, section, observed_raw = read_va(
                self.dll, self.sections, int(entry, 16), size
            )
            self.assertEqual((section, observed_raw), (".text", raw_offset))
            self.assertEqual(len(body), size)
            self.assertEqual(sha256(body), expected_hash)

    def test_100e8240_completed_route_returns_the_exact_crash_record(self):
        returned, section, raw_offset = read_va(
            self.dll,
            self.sections,
            CRASH_RECORD_RETURN_VA,
            len(CRASH_RECORD_RETURN_BYTES),
        )
        self.assertEqual((section, raw_offset), (".text", 0x000E765F))
        self.assertEqual(returned, CRASH_RECORD_RETURN_BYTES)
        self.assertEqual(sha256(returned), CRASH_RECORD_RETURN_SHA256)
        self.assertEqual(returned[0], 0xB8)
        self.assertEqual(struct.unpack_from("<I", returned, 1)[0],
                         CRASH_RECORD_IDENTITY)
        self.assertEqual(returned[5:], bytes.fromhex("83c40cc3"))

        early, section, raw_offset = read_va(
            self.dll,
            self.sections,
            CRASH_RECORD_EARLY_REJOIN_VA,
            len(CRASH_RECORD_EARLY_REJOIN_BYTES),
        )
        self.assertEqual((section, raw_offset), (".text", 0x000E767C))
        self.assertEqual(early, CRASH_RECORD_EARLY_REJOIN_BYTES)
        self.assertEqual(sha256(early), CRASH_RECORD_EARLY_REJOIN_SHA256)
        self.assertEqual(
            rel8_target(early, CRASH_RECORD_EARLY_REJOIN_VA, 0),
            CRASH_RECORD_RETURN_VA,
        )

        final, section, raw_offset = read_va(
            self.dll,
            self.sections,
            CRASH_RECORD_FINAL_REJOIN_VA,
            len(CRASH_RECORD_FINAL_REJOIN_BYTES),
        )
        self.assertEqual((section, raw_offset), (".text", 0x000E7771))
        self.assertEqual(final, CRASH_RECORD_FINAL_REJOIN_BYTES)
        self.assertEqual(sha256(final), CRASH_RECORD_FINAL_REJOIN_SHA256)
        self.assertEqual(
            rel32_jump_target(final, CRASH_RECORD_FINAL_REJOIN_VA, 0),
            CRASH_RECORD_RETURN_VA,
        )

        canonical = (
            CANONICAL / "decomp_fn_100e8240.c"
        ).read_text(encoding="utf-8")
        self.assertIn("return &DAT_119f3a38;", canonical)

    def test_canonical_sources_rows_and_cross_check_are_exact(self):
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

        parent_text = (
            CANONICAL / "decomp_fn_100df270.c"
        ).read_text(encoding="utf-8")
        for token in (
            "param_1[0x21d] = &PTR_LAB_1173dc18;",
            "DAT_119f3140 = param_1;",
            "decomp_fn_100e8240(param_3);",
            "decomp_fn_100f2750(param_3);",
            "decomp_fn_100ea4d0();",
            "if (*piVar3 != 0x4e3b) {",
            "decomp_fn_101046d0(0x2d);",
            "decomp_fn_101046d0(0x12);",
            "decomp_fn_101046d0(0x16);",
            "decomp_fn_101046d0(0x21);",
            "*puVar4 = 0x4e3b;",
            "return param_1;",
        ):
            self.assertIn(token, parent_text)

        selector_text = (
            CANONICAL / "decomp_fn_100d7cb0.c"
        ).read_text(encoding="utf-8")
        for token in (
            "if (param_1 < 0x45) {",
            "&DAT_119f2df8 + param_1 * 4",
            "+ 0x48",
            "return &DAT_119f2f0c;",
        ):
            self.assertIn(token, selector_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
