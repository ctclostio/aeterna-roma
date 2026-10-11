#!/usr/bin/env python3
"""Authenticate the injected transcript at original handler 0x100e9340.

The original PE is parsed strictly as data and never loaded or executed.  The
tests pin the complete unindexed handler, its vtable/constructor mapping, both
global virtual lookups, saved-receiver byte replacement, direct callees, and
final AL publication.  They also authenticate why the direct-call suffix is
not portable: 0x112e1830 owns allocator/TLS/platform singleton setup, while
unindexed 0x112cbbb0 mutates that singleton, writes TLS twice, and calls more
global machinery.  The x64 transcript injects derived values and records this
order; no recovered address is authorized as a native call target.
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
FUNCTION_VA = 0x100E9340
FUNCTION_BYTES = bytes.fromhex(
    "51"
    "8b0d40319f11"
    "81c174080000"
    "56"
    "6a12"
    "8b01"
    "ff500c"
    "8b0d40319f11"
    "81c174080000"
    "6a49"
    "8b30"
    "8b01"
    "ff501c"
    "8a00"
    "88442404"
    "e8bb841f01"
    "6a00"
    "ff742408"
    "8bc8"
    "56"
    "e82d281e01"
    "b001"
    "5e59"
    "c20400"
)
FUNCTION_SHA256 = "52f130537cbe5ce500544e8f55fc50daa848c9202bd515f11cb173a6a602d1b6"
FUNCTION_RAW_OFFSET = 0x000E8740
DIRECT_CALL_OFFSETS = (48, 62)
DIRECT_CALL_TARGETS = (0x112E1830, 0x112CBBB0)

GLOBAL_ROOT_VA = 0x119F3140
GLOBAL_SERVICE_OFFSET = 0x874
LOOKUP_DWORD_SELECTOR = 0x12
LOOKUP_BYTE_SELECTOR = 0x49

VTABLE_PAIR_VA = 0x1173F224
VTABLE_PAIR_BYTES = bytes.fromhex("00190e1040930e10")
VTABLE_PAIR_SHA256 = "a68ce6065bb6d0e257c3678a0cbbbfc4cc1b10565ca46f46a417162b09ffcf8d"
VTABLE_PAIR_RAW_OFFSET = 0x0173DC24
CONSTRUCTOR_VA = 0x100E1900

GETTER_VA = 0x112E1830
GETTER_SIZE = 290
GETTER_SHA256 = "64d02765657eae86676a99593cc1783853cab51a531931597a30b2218ca4edd2"
GETTER_RAW_OFFSET = 0x012E0C30

HELPER_VA = 0x112CBBB0
HELPER_BYTES = bytes.fromhex(
    "837c240400"
    "53"
    "8bd9"
    "0f9fc0"
    "6a00"
    "88430a"
    "ff35d01a0312"
    "ff15ccf27211"
    "6a00"
    "ff35d41a0312"
    "ff15ccf27211"
    "53"
    "ff742410"
    "8d4b09"
    "c7432c01000000"
    "ff742410"
    "e82ee60900"
    "68606d2c11"
    "894304"
    "e8217ae4fe"
    "83c404"
    "5b"
    "c20c00"
)
HELPER_SHA256 = "8cac67abb474a5043787387b354a6ec3171a9e14a261137c30b9a392464a5d28"
HELPER_RAW_OFFSET = 0x012CAFB0
HELPER_DIRECT_CALL_OFFSETS = (61, 74)
HELPER_DIRECT_CALL_TARGETS = (0x1136A220, 0x10113620)
HELPER_CALLBACK_IDENTITY = 0x112C6D60

CANONICAL_HASHES = {
    "decomp_fn_100e1900.c":
        "80138139e7d6b37a816ee00bdc17c657c14c43525cef94a15efab8c044347a21",
    "decomp_fn_10113620.c":
        "cb35339755a549966783f3dc1c20fc20b4500830480e63b127737d1ccedcf77d",
    "decomp_fn_112cbb60.c":
        "f24dce0f8023dfcae57e62ac1f5546ab30d7562c2653ceff2c32a5f9ef420e1c",
    "decomp_fn_112e1830.c":
        "e7bce72d37330bd463c5fd0e07fa326a90182f7d43e64a861aaf6266c485b23d",
}

CANONICAL_ROWS = {
    "100e1900": ("decomp_fn_100e1900", "279", "100e1900-100e1a16"),
    "10113620": ("decomp_fn_10113620", "17", "10113620-10113630"),
    "112cbb60": ("decomp_fn_112cbb60", "74", "112cbb60-112cbba9"),
    "112e1830": ("decomp_fn_112e1830", "290", "112e1830-112e1951"),
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
    raw, _section, offset = read_rva(data, sections, rva, 1)
    del raw
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
        original_thunk, stamp, chain, name_rva, first_thunk = struct.unpack(
            "<IIIII", descriptor
        )
        if (original_thunk, stamp, chain, name_rva, first_thunk) == (0, 0, 0, 0, 0):
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


class Startup100e9340HandlerTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections, import_rva, import_size = parse_pe32(cls.dll)
        cls.imports = parse_import_iat(
            cls.dll, cls.sections, import_rva, import_size
        )

    def test_exact_74_byte_handler_and_boundaries(self):
        body, section, raw_offset = read_va(
            self.dll, self.sections, FUNCTION_VA, len(FUNCTION_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(body, FUNCTION_BYTES)
        self.assertEqual(len(body), 74)
        self.assertEqual(sha256(body), FUNCTION_SHA256)
        before, before_section, before_raw = read_va(
            self.dll, self.sections, FUNCTION_VA - 12, 12
        )
        after, after_section, after_raw = read_va(
            self.dll, self.sections, FUNCTION_VA + len(body), 6
        )
        self.assertEqual((before_section, before_raw), (".text", 0x000E8734))
        self.assertEqual((after_section, after_raw), (".text", 0x000E878A))
        self.assertEqual(before, b"\xcc" * 12)
        self.assertEqual(after, b"\xcc" * 6)

    def test_global_virtual_lookups_and_result_loads_are_exact(self):
        self.assertEqual(
            FUNCTION_BYTES[1:13],
            bytes.fromhex("8b0d40319f1181c174080000"),
        )
        self.assertEqual(
            FUNCTION_BYTES[21:33],
            bytes.fromhex("8b0d40319f1181c174080000"),
        )
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 3)[0], GLOBAL_ROOT_VA)
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 23)[0], GLOBAL_ROOT_VA)
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 9)[0], GLOBAL_SERVICE_OFFSET)
        self.assertEqual(struct.unpack_from("<I", FUNCTION_BYTES, 29)[0], GLOBAL_SERVICE_OFFSET)

        self.assertEqual(
            FUNCTION_BYTES[14:21], bytes.fromhex("6a128b01ff500c")
        )
        self.assertEqual(
            FUNCTION_BYTES[33:44], bytes.fromhex("6a498b308b01ff501c8a00")
        )
        self.assertEqual(FUNCTION_BYTES[15], LOOKUP_DWORD_SELECTOR)
        self.assertEqual(FUNCTION_BYTES[34], LOOKUP_BYTE_SELECTOR)
        self.assertEqual(FUNCTION_BYTES[18:21], bytes.fromhex("ff500c"))
        self.assertEqual(FUNCTION_BYTES[39:42], bytes.fromhex("ff501c"))
        self.assertEqual(FUNCTION_BYTES[35:37], bytes.fromhex("8b30"))
        self.assertEqual(FUNCTION_BYTES[42:44], bytes.fromhex("8a00"))

    def test_saved_receiver_low_byte_replacement_and_helper_arguments(self):
        self.assertEqual(FUNCTION_BYTES[0:1], bytes.fromhex("51"))
        self.assertEqual(FUNCTION_BYTES[13:14], bytes.fromhex("56"))
        self.assertEqual(FUNCTION_BYTES[44:48], bytes.fromhex("88442404"))
        self.assertEqual(FUNCTION_BYTES[53:62], bytes.fromhex("6a00ff7424088bc856"))

        receiver = 0x12345678
        selected_byte = 0xA5
        patched_receiver = (receiver & 0xFFFFFF00) | selected_byte
        self.assertEqual(patched_receiver, 0x123456A5)
        self.assertEqual(
            (0xFFFFFFFF & 0xFFFFFF00) | 0,
            0xFFFFFF00,
        )
        # push 0, push patched saved-ECX dword, push ESI gives logical args
        # (selected_dword, patched_receiver, 0).  The original stack argument
        # remains below the return address and is never loaded.
        self.assertNotIn(bytes.fromhex("ff742410"), FUNCTION_BYTES)

    def test_direct_calls_and_al_publication_are_exact(self):
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
            FUNCTION_BYTES[67:74], bytes.fromhex("b0015e59c20400")
        )
        self.assertNotIn(
            bytes.fromhex("b801000000"),
            FUNCTION_BYTES,
            "only AL, not full EAX, is defined as one",
        )
        self.assertEqual(DIRECT_CALL_OFFSETS[-1] + 5, 67)

    def test_vtable_constructor_mapping_is_exact(self):
        pair, section, raw_offset = read_va(
            self.dll, self.sections, VTABLE_PAIR_VA, len(VTABLE_PAIR_BYTES)
        )
        self.assertEqual((section, raw_offset), (".rdata", VTABLE_PAIR_RAW_OFFSET))
        self.assertEqual(pair, VTABLE_PAIR_BYTES)
        self.assertEqual(sha256(pair), VTABLE_PAIR_SHA256)
        self.assertEqual(struct.unpack("<II", pair), (CONSTRUCTOR_VA, FUNCTION_VA))

        constructor = CANONICAL / "decomp_fn_100e1900.c"
        constructor_text = constructor.read_text(encoding="utf-8")
        self.assertEqual(
            sha256(constructor.read_bytes()),
            CANONICAL_HASHES[constructor.name],
        )
        self.assertIn(
            "*param_1 = &PTR_decomp_fn_100e1900_1173f224;",
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

    def test_singleton_getter_body_and_irreducible_effects_are_exact(self):
        getter, section, raw_offset = read_va(
            self.dll, self.sections, GETTER_VA, GETTER_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", GETTER_RAW_OFFSET))
        self.assertEqual(len(getter), GETTER_SIZE)
        self.assertEqual(sha256(getter), GETTER_SHA256)
        self.assertEqual(getter[:13], bytes.fromhex("a1682e031285c00f8514010000"))
        self.assertEqual(getter[-14:], bytes.fromhex("c705682e03120000000033c05fc3"))

        source = CANONICAL / "decomp_fn_112e1830.c"
        source_text = source.read_text(encoding="utf-8")
        self.assertEqual(sha256(source.read_bytes()), CANONICAL_HASHES[source.name])
        for token in (
            "decomp_fn_100d12b0(0x6c)",
            "TlsAlloc()",
            "GetCurrentThreadId()",
            "InitializeCriticalSectionAndSpinCount",
            "decomp_fn_100fcc80",
            "DAT_12032e68",
            "DAT_12031ad0",
            "DAT_12031ad4",
        ):
            self.assertIn(token, source_text)

        self.assertEqual(self.imports[0x1172F2C4][1], "TlsAlloc")
        self.assertEqual(self.imports[0x1172F224][1], "GetCurrentThreadId")
        self.assertEqual(
            self.imports[0x1172F1F8][1],
            "InitializeCriticalSectionAndSpinCount",
        )

    def test_unindexed_helper_body_tls_and_global_suffix_are_exact(self):
        helper, section, raw_offset = read_va(
            self.dll, self.sections, HELPER_VA, len(HELPER_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", HELPER_RAW_OFFSET))
        self.assertEqual(helper, HELPER_BYTES)
        self.assertEqual(len(helper), 86)
        self.assertEqual(sha256(helper), HELPER_SHA256)

        before, _section, _raw = read_va(
            self.dll, self.sections, HELPER_VA - 6, 6
        )
        after, _section, _raw = read_va(
            self.dll, self.sections, HELPER_VA + len(helper), 10
        )
        self.assertEqual(before, b"\xcc" * 6)
        self.assertEqual(after, b"\xcc" * 10)

        self.assertEqual(helper[0:16], bytes.fromhex("837c240400538bd90f9fc06a0088430a"))
        self.assertEqual(helper[16:28], bytes.fromhex("ff35d01a0312ff15ccf27211"))
        self.assertEqual(helper[28:42], bytes.fromhex("6a00ff35d41a0312ff15ccf27211"))
        self.assertEqual(self.imports[0x1172F2CC][1], "TlsSetValue")
        self.assertEqual(
            tuple(
                rel32_target(HELPER_BYTES, HELPER_VA, offset)
                for offset in HELPER_DIRECT_CALL_OFFSETS
            ),
            HELPER_DIRECT_CALL_TARGETS,
        )
        self.assertEqual(
            struct.unpack_from("<I", helper, 67)[0],
            HELPER_CALLBACK_IDENTITY,
        )
        self.assertEqual(helper[47:61], bytes.fromhex("8d4b09c7432c01000000ff742410"))
        self.assertEqual(helper[71:74], bytes.fromhex("894304"))
        self.assertEqual(helper[-7:], bytes.fromhex("83c4045bc20c00"))

        tls_source = CANONICAL / "decomp_fn_112cbb60.c"
        tls_text = tls_source.read_text(encoding="utf-8")
        self.assertEqual(
            sha256(tls_source.read_bytes()), CANONICAL_HASHES[tls_source.name]
        )
        self.assertIn("TlsSetValue(DAT_12031ad0,lpTlsValue);", tls_text)

        global_source = CANONICAL / "decomp_fn_10113620.c"
        global_text = global_source.read_text(encoding="utf-8")
        self.assertEqual(
            sha256(global_source.read_bytes()), CANONICAL_HASHES[global_source.name]
        )
        self.assertIn("_DAT_119f3eac = param_1;", global_text)
        self.assertIn("DAT_119f3d8a = 1;", global_text)

    def test_canonical_rows_and_discovery_gaps_are_exact(self):
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

        self.assertNotIn("100e9340", rows)
        self.assertEqual(rows["100e92c0"]["body_ranges"], "100e92c0-100e9333")
        self.assertEqual(rows["100e9390"]["body_ranges"], "100e9390-100e948a")

        self.assertNotIn("112cbbb0", rows)
        self.assertEqual(rows["112cbb60"]["body_ranges"], "112cbb60-112cbba9")
        self.assertEqual(rows["112cbc10"]["body_ranges"], "112cbc10-112cbe08")

        self.assertNotIn("1136a220", rows)
        self.assertEqual(rows["113697c0"]["body_ranges"], "113697c0-1136a21f")
        self.assertEqual(rows["1136a270"]["body_ranges"], "1136a270-1136a52d")

        self.assertNotIn("112c6d60", rows)
        self.assertEqual(rows["112c6ce0"]["body_ranges"], "112c6ce0-112c6d3f")
        self.assertEqual(rows["112c6d90"]["body_ranges"], "112c6d90-112c6f0b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
