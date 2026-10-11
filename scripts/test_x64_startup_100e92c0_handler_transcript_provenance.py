#!/usr/bin/env python3
"""Authenticate the bounded transcript for original handler 0x100e92c0.

The original PE is parsed strictly as data and never loaded or executed.  The
tests pin the complete handler, its vtable/constructor pair, all six direct
calls, both short branches, shared stack-local getter plumbing, dependent
result widths, final argument order, and AL-only publication.  Canonical
artifacts authenticate why every effect remains injected: the prefix and
suffix touch extensive global/platform state, while the predicates/getters
enter the Steam process-global context and indirect virtual interfaces.
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
FUNCTION_VA = 0x100E92C0
FUNCTION_BYTES = bytes.fromhex(
    "83ec105657"
    "e8a6d6feff"
    "0f57c0"
    "660f13442408"
    "660f13442410"
    "e89250ef00"
    "84c0742c"
    "e8e956ef00"
    "84c07423"
    "8d44241050"
    "e87b4fef00"
    "8b308b7804"
    "8d44241450"
    "e88c56ef00"
    "83c408"
    "8b088b4004"
    "eb10"
    "8b7c240c"
    "8b742408"
    "8b442414"
    "8b4c2410"
    "50515756"
    "e829befeff"
    "83c410"
    "b001"
    "5f5e83c410c20400"
)
FUNCTION_SHA256 = "6a667df2e872494bc91549ca47c5fe87664bfe94737a065b8bd7018154715e6d"
FUNCTION_RAW_OFFSET = 0x000E86C0

DIRECT_CALL_OFFSETS = (5, 25, 34, 48, 63, 98)
DIRECT_CALL_TARGETS = (
    0x100D6970,
    0x10FDE370,
    0x10FDE9D0,
    0x10FDE270,
    0x10FDE990,
    0x100D5150,
)

FIRST_FALSE_BRANCH_OFFSET = 32
SECOND_FALSE_BRANCH_OFFSET = 41
SUCCESS_JOIN_BRANCH_OFFSET = 76
FALLBACK_VA = 0x100E930E
FINAL_CALL_SETUP_VA = 0x100E931E

VTABLE_PAIR_VA = 0x1173F2EC
VTABLE_PAIR_BYTES = bytes.fromhex("c0180e10c0920e10")
VTABLE_PAIR_SHA256 = "096ded79eb865c98c3857f0bb8397834ef3e717011263891f2d6182e858eb5e6"
VTABLE_PAIR_RAW_OFFSET = 0x0173DCEC
CONSTRUCTOR_VA = 0x100E18C0

STEAM_CONTEXT_IAT_VA = 0x1172F94C

PREDICATE_370_BYTES = bytes.fromhex(
    "6898a09d11ff154cf9721183c40483780c000f95c0c3"
)
PREDICATE_9D0_BYTES = bytes.fromhex(
    "6898a09d11ff154cf9721183c404837804000f95c0c3"
)
GETTER_270_BYTES = bytes.fromhex(
    "6898a09d11ff154cf9721183c4048b480c8b01ff5024"
    "8b4c240489018bc1c7410400000000c3"
)
GETTER_990_BYTES = bytes.fromhex(
    "83ec086898a09d11ff154cf9721183c4048d14248b4804"
    "528b01ff50088b54240c8b08890a8b48048bc2894a04"
    "83c408c3"
)

BODY_AUTHORITIES = {
    "100e18c0": (49, 0x000E0CC0,
        "d2a9d2fe17115fc3a1ebad22a1ac1ea8d45fe19bab1216e68c9223d8364bd1de"),
    "100e92c0": (116, FUNCTION_RAW_OFFSET, FUNCTION_SHA256),
    "100d6970": (335, 0x000D5D70,
        "ce32c87bbbf1475492bfb7edf3ba6503c828416d67a493b715db9edcf907ecf6"),
    "10fde370": (22, 0x00FDD770,
        "995c35bb94299404a58c14158ed56fa6d6ac80c595489bd0fd1446746549429c"),
    "10fde9d0": (22, 0x00FDDDD0,
        "530555674511b3fd1426ddd8682f15cc8b95fce01077981aac2b533d89bf2ae1"),
    "10fde270": (38, 0x00FDD670,
        "e2e45622dc3e817af4ec90e4af9df774f9d9e3553cee5e1f6dc6a12236d6146a"),
    "10fde990": (49, 0x00FDDD90,
        "2454175dea78e57e058f7112b03e4d6c4d2cdee92cba2ea9f3ba636f0282d6d9"),
    "100d5150": (3531, 0x000D4550,
        "a380f9db2d47150a869409d06ee0458f28256862244349d5e2c97535be2c0ee0"),
}

CANONICAL_HASHES = {
    "decomp_fn_100e18c0.c":
        "2cd877871da88ce45c33df973334ebc03bc7723070f4d579940bd588f504120d",
    "decomp_fn_100e92c0.c":
        "567b522896efc2faa2a7ead930da0deb0d687edcbc939b0df2d7851dded0db8a",
    "decomp_fn_100d6970.c":
        "321f0b33538d9f4e436ccd74cf22e837bbc8d91d73cb890f3feb4fec0bf8309a",
    "decomp_fn_10fde370.c":
        "5729fbfb85fd7952f71fad74832a366a3c79f031fea1634b74bc3767cd23a9a2",
    "decomp_fn_10fde9d0.c":
        "a294025d422112731b848f7275d0096c8a4fe09fba0aa450af0355e5ce055d94",
    "decomp_fn_10fde270.c":
        "7cd5cf67facccad15370bcc889da13820c8717e3e23bc01476047ae18b509fed",
    "decomp_fn_10fde990.c":
        "61206fa96593302a9dee6fdbfc284aee7866240e48b95c4898887d226f709cb4",
    "decomp_fn_100d5150.c":
        "3da11b99e83f57c868b2dc84a80cbed69ba00ff31276cea23642a5c8afe1f014",
}

CANONICAL_ROWS = {
    "100e18c0": ("decomp_fn_100e18c0", "49", "100e18c0-100e18f0"),
    "100e92c0": ("decomp_fn_100e92c0", "116", "100e92c0-100e9333"),
    "100d6970": ("decomp_fn_100d6970", "335", "100d6970-100d6abe"),
    "10fde370": ("decomp_fn_10fde370", "22", "10fde370-10fde385"),
    "10fde9d0": ("decomp_fn_10fde9d0", "22", "10fde9d0-10fde9e5"),
    "10fde270": ("decomp_fn_10fde270", "38", "10fde270-10fde295"),
    "10fde990": ("decomp_fn_10fde990", "49", "10fde990-10fde9c0"),
    "100d5150": ("decomp_fn_100d5150", "3531", "100d5150-100d5f1a"),
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

    import_rva, import_size = struct.unpack_from("<II", data, optional + 104)
    return tuple(sections), import_rva, import_size


def read_rva(data: bytes, sections, rva: int, size: int):
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size in sections:
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"RVA 0x{rva:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"RVA 0x{rva:08x}")
    return data[offset:offset + size], name, offset


def read_va(data: bytes, sections, va: int, size: int):
    if va < IMAGE_BASE:
        raise ValueError(f"VA 0x{va:08x} precedes image base")
    return read_rva(data, sections, va - IMAGE_BASE, size)


def read_c_string_rva(data: bytes, sections, rva: int) -> str:
    _first, _section, offset = read_rva(data, sections, rva, 1)
    end = data.find(b"\0", offset, min(len(data), offset + 512))
    if end < 0:
        raise ValueError(f"unterminated string at RVA 0x{rva:08x}")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-ASCII string at RVA 0x{rva:08x}") from exc


def parse_import_iat(data: bytes, sections, import_rva: int, import_size: int):
    if import_rva == 0 or import_size < 20:
        raise ValueError("missing import directory")
    imports = {}
    for descriptor_index in range(min(import_size // 20, 4096)):
        descriptor, _section, _offset = read_rva(
            data, sections, import_rva + descriptor_index * 20, 20
        )
        values = struct.unpack("<IIIII", descriptor)
        original_thunk, stamp, chain, name_rva, first_thunk = values
        if values == (0, 0, 0, 0, 0):
            return imports
        dll_name = read_c_string_rva(data, sections, name_rva).lower()
        names_rva = original_thunk or first_thunk
        for thunk_index in range(65536):
            thunk_data, _section, _offset = read_rva(
                data, sections, names_rva + thunk_index * 4, 4
            )
            thunk = struct.unpack("<I", thunk_data)[0]
            if thunk == 0:
                break
            if thunk & 0x80000000:
                symbol = f"ordinal-{thunk & 0xffff}"
            else:
                symbol = read_c_string_rva(data, sections, thunk + 2)
            imports[IMAGE_BASE + first_thunk + thunk_index * 4] = (
                dll_name, symbol
            )
        else:
            raise ValueError(f"unterminated thunk table for {dll_name}")
    raise ValueError("unterminated import descriptor table")


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


class Startup100e92c0HandlerTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections, import_rva, import_size = parse_pe32(cls.dll)
        cls.imports = parse_import_iat(
            cls.dll, cls.sections, import_rva, import_size
        )

    def test_exact_116_byte_handler_and_boundaries(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(FUNCTION_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(body, FUNCTION_BYTES)
        self.assertEqual(len(body), 116)
        self.assertEqual(sha256(body), FUNCTION_SHA256)
        before, before_section, before_raw = read_va(
            self.dll, self.sections, FUNCTION_VA - 12, 12
        )
        after, after_section, after_raw = read_va(
            self.dll, self.sections, FUNCTION_VA + len(body), 12
        )
        self.assertEqual((before_section, before_raw), (".text", 0x000E86B4))
        self.assertEqual((after_section, after_raw), (".text", 0x000E8734))
        self.assertEqual(before, b"\xcc" * 12)
        self.assertEqual(after, b"\xcc" * 12)

    def test_all_direct_calls_and_short_branches_are_exact(self):
        observed_offsets = tuple(
            offset for offset, value in enumerate(FUNCTION_BYTES)
            if value == 0xE8
        )
        self.assertEqual(observed_offsets, DIRECT_CALL_OFFSETS)
        self.assertEqual(
            tuple(
                rel32_target(FUNCTION_BYTES, FUNCTION_VA, offset)
                for offset in DIRECT_CALL_OFFSETS
            ),
            DIRECT_CALL_TARGETS,
        )
        self.assertEqual(
            FUNCTION_BYTES[FIRST_FALSE_BRANCH_OFFSET], 0x74
        )
        self.assertEqual(
            FUNCTION_BYTES[SECOND_FALSE_BRANCH_OFFSET], 0x74
        )
        self.assertEqual(
            FUNCTION_BYTES[SUCCESS_JOIN_BRANCH_OFFSET], 0xEB
        )
        self.assertEqual(
            rel8_target(
                FUNCTION_BYTES, FUNCTION_VA, FIRST_FALSE_BRANCH_OFFSET
            ),
            FALLBACK_VA,
        )
        self.assertEqual(
            rel8_target(
                FUNCTION_BYTES, FUNCTION_VA, SECOND_FALSE_BRANCH_OFFSET
            ),
            FALLBACK_VA,
        )
        self.assertEqual(
            rel8_target(
                FUNCTION_BYTES, FUNCTION_VA, SUCCESS_JOIN_BRANCH_OFFSET
            ),
            FINAL_CALL_SETUP_VA,
        )

    def test_zero_state_getter_plumbing_and_fallback_are_exact(self):
        self.assertEqual(
            FUNCTION_BYTES[10:25],
            bytes.fromhex("0f57c0660f13442408660f13442410"),
        )
        self.assertEqual(
            FUNCTION_BYTES[43:58],
            bytes.fromhex("8d44241050e87b4fef008b308b7804"),
        )
        self.assertEqual(
            FUNCTION_BYTES[58:76],
            bytes.fromhex("8d44241450e88c56ef0083c4088b088b4004"),
        )
        self.assertEqual(
            FUNCTION_BYTES[78:94],
            bytes.fromhex("8b7c240c8b7424088b4424148b4c2410"),
        )
        # Both LEAs resolve to the same original local pair because the first
        # uncleaned pushed argument shifts ESP by four before the second LEA.
        first_base = 0
        first_local = first_base + 0x10
        second_base = first_base - 4
        second_local = second_base + 0x14
        self.assertEqual(first_local, second_local)

    def test_final_argument_order_and_al_only_publication_are_exact(self):
        self.assertEqual(FUNCTION_BYTES[94:103], bytes.fromhex("50515756e829befeff"))
        self.assertEqual(
            FUNCTION_BYTES[103:116],
            bytes.fromhex("83c410b0015f5e83c410c20400"),
        )
        # push EAX, ECX, EDI, ESI gives logical cdecl arguments
        # (ESI, EDI, ECX, EAX), exactly the two loaded getter pairs.
        self.assertEqual(FUNCTION_BYTES[94:98], bytes((0x50, 0x51, 0x57, 0x56)))
        self.assertNotIn(bytes.fromhex("b801000000"), FUNCTION_BYTES)
        self.assertEqual(DIRECT_CALL_OFFSETS[-1] + 5, 103)

    def test_vtable_constructor_mapping_and_indirect_reachability_are_exact(self):
        pair, section, raw_offset = read_va(
            self.dll, self.sections, VTABLE_PAIR_VA, len(VTABLE_PAIR_BYTES)
        )
        self.assertEqual((section, raw_offset), (".rdata", VTABLE_PAIR_RAW_OFFSET))
        self.assertEqual(pair, VTABLE_PAIR_BYTES)
        self.assertEqual(sha256(pair), VTABLE_PAIR_SHA256)
        self.assertEqual(struct.unpack("<II", pair), (CONSTRUCTOR_VA, FUNCTION_VA))

        constructor = CANONICAL / "decomp_fn_100e18c0.c"
        constructor_text = constructor.read_text(encoding="utf-8")
        self.assertEqual(
            sha256(constructor.read_bytes()), CANONICAL_HASHES[constructor.name]
        )
        self.assertIn(
            "*param_1 = &PTR_decomp_fn_100e18c0_1173f2ec;",
            constructor_text,
        )

        direct_refs = []
        for name, rva, _virtual_size, raw_offset, raw_size in self.sections:
            if name != ".text":
                continue
            text = self.dll[raw_offset:raw_offset + raw_size]
            base = IMAGE_BASE + rva
            for offset in range(len(text) - 4):
                if text[offset] not in (0xE8, 0xE9):
                    continue
                displacement = struct.unpack_from("<i", text, offset + 1)[0]
                if base + offset + 5 + displacement == FUNCTION_VA:
                    direct_refs.append(base + offset)
        self.assertEqual(direct_refs, [], "handler should be reached via vtable")

    def test_predicates_and_dependent_getter_results_are_exact(self):
        for va, expected in (
            (0x10FDE370, PREDICATE_370_BYTES),
            (0x10FDE9D0, PREDICATE_9D0_BYTES),
            (0x10FDE270, GETTER_270_BYTES),
            (0x10FDE990, GETTER_990_BYTES),
        ):
            body, section, raw_offset = read_va(
                self.dll, self.sections, va, len(expected)
            )
            authority = BODY_AUTHORITIES[f"{va:08x}"]
            self.assertEqual((section, raw_offset), (".text", authority[1]))
            self.assertEqual(body, expected)
            self.assertEqual(sha256(body), authority[2])

        self.assertEqual(
            self.imports[STEAM_CONTEXT_IAT_VA],
            ("steam_api.dll", "SteamInternal_ContextInit"),
        )
        self.assertEqual(PREDICATE_370_BYTES[-4:], bytes.fromhex("0f95c0c3"))
        self.assertEqual(PREDICATE_9D0_BYTES[-4:], bytes.fromhex("0f95c0c3"))
        self.assertEqual(
            GETTER_270_BYTES[-16:],
            bytes.fromhex("8b4c240489018bc1c7410400000000c3"),
        )
        self.assertEqual(
            GETTER_990_BYTES[-20:],
            bytes.fromhex("8b54240c8b08890a8b48048bc2894a0483c408c3"),
        )

    def test_all_callee_bodies_and_excluded_effect_boundaries_are_pinned(self):
        for entry, (size, raw_offset, expected_hash) in BODY_AUTHORITIES.items():
            body, section, observed_raw = read_va(
                self.dll, self.sections, int(entry, 16), size
            )
            self.assertEqual((section, observed_raw), (".text", raw_offset))
            self.assertEqual(len(body), size)
            self.assertEqual(sha256(body), expected_hash)

        prefix_text = (
            CANONICAL / "decomp_fn_100d6970.c"
        ).read_text(encoding="utf-8")
        for token in (
            "decomp_fn_116bc5fe(local_800,0x800)",
            "decomp_fn_10fde340(1)",
            "decomp_fn_10fdeb00()",
            "DAT_119ef8d5 = uVar10;",
        ):
            self.assertIn(token, prefix_text)

        suffix_text = (
            CANONICAL / "decomp_fn_100d5150.c"
        ).read_text(encoding="utf-8")
        for token in (
            "DAT_119ef8d7 = 1;",
            "CoCreateGuid((GUID *)&DAT_119f2de8);",
            "DAT_119f2dd8 = param_1;",
            "DAT_119f2ddc = param_2;",
            "DAT_119f2de0 = param_3;",
            "DAT_119f2de4 = param_4;",
            "GlobalMemoryStatusEx(&local_40);",
        ):
            self.assertIn(token, suffix_text)

    def test_canonical_rows_sources_and_handler_semantics_are_exact(self):
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

        handler_text = (
            CANONICAL / "decomp_fn_100e92c0.c"
        ).read_text(encoding="utf-8")
        for token in (
            "decomp_fn_100d6970();",
            "cVar1 = decomp_fn_10fde370();",
            "cVar1 = decomp_fn_10fde9d0();",
            "puVar2 = (undefined4 *)decomp_fn_10fde270(&local_8);",
            "puVar2 = (undefined4 *)decomp_fn_10fde990(&local_8);",
            "decomp_fn_100d5150(local_10,uStack_c,uVar4,uVar3);",
            "return 1;",
        ):
            self.assertIn(token, handler_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
