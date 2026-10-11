#!/usr/bin/env python3
"""Authenticate the platform-bound prefix of original 0x100df270.

Both pinned PE32 images are parsed strictly as inert byte arrays.  Nothing in
this suite loads an image, resolves an operating-system symbol, or executes an
original address.  The original DLL is the ABI oracle; canonical C and the
launcher resource table are independently pinned cross-checks.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "Total War Rome II"
DLL = CORPUS / "empire.retail.dll"
LAUNCHER = CORPUS / "Rome2.exe"
INDEX = (
    ROOT / "src_canonical_out" / "empire.retail.dll" /
    "canonical_function_index.tsv"
)
CANONICAL = (
    ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
)

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
DLL_IMAGE_BASE = 0x10000000
DLL_PE_OFFSET = 0x190
DLL_IMPORT_RVA_SIZE = (0x0192F478, 0x208)
DLL_RESOURCE_RVA_SIZE = (0x02138000, 0x578)
DLL_SECTIONS = (
    (".text", 0x00001000, 0x0172D4EA, 0x00000400, 0x0172D600, 0x60000020),
    (".rdata", 0x0172F000, 0x00203174, 0x0172DA00, 0x00203200, 0x40000040),
    (".data", 0x01933000, 0x007F3C40, 0x01930C00, 0x000BC200, 0xC0000040),
    (".msvcjmc", 0x02127000, 0x0000D9DE, 0x019ECE00, 0x0000DA00, 0xC0000040),
    ("_RDATA", 0x02135000, 0x00002608, 0x019FA800, 0x00002800, 0x40000040),
    (".rsrc", 0x02138000, 0x00000578, 0x019FD000, 0x00000600, 0x40000040),
    (".reloc", 0x02139000, 0x000FA668, 0x019FD600, 0x000FA800, 0x42000040),
)

LAUNCHER_SIZE = 804_864
LAUNCHER_SHA256 = "332de1aac9303ce71dbee82fe2f8fcb9d2f82766ebd2e6943db6fe9dac30519d"
LAUNCHER_IMAGE_BASE = 0x00400000
LAUNCHER_PE_OFFSET = 0x120
LAUNCHER_RESOURCE_RVA_SIZE = (0x00132000, 0x997A8)
LAUNCHER_SECTIONS = (
    (".text", 0x00001000, 0x0001AB57, 0x00000400, 0x0001AC00, 0x60000020),
    (".rdata", 0x0001C000, 0x0000CDFA, 0x0001B000, 0x0000CE00, 0x40000040),
    (".data", 0x00029000, 0x00108D14, 0x00027E00, 0x00001600, 0xC0000040),
    (".rsrc", 0x00132000, 0x000997A8, 0x00029400, 0x00099800, 0x40000040),
    (".reloc", 0x001CC000, 0x00001ABC, 0x000C2C00, 0x00001C00, 0x42000040),
)

FUNCTION_VA = 0x100DF270
FUNCTION_SIZE = 640
FUNCTION_RAW_OFFSET = 0x000DE670
FUNCTION_SHA256 = "d5a89108422a8c8a07d7150501805b70cedf81686b2f6a7e105e6d39d3a725f7"

PREFIX_VA = FUNCTION_VA
PREFIX_END_VA = 0x100DF343
PREFIX_RAW_OFFSET = FUNCTION_RAW_OFFSET
PREFIX_BYTES = bytes.fromhex(
    "81ec0004000053558bac240c040000568b356cf67211578b55008bf9"
    "68000200008d8708040000895704506a6d52c70708f27311ffd6"
    "68000200008d5f08536a67ff7704ffd6"
    "536860f473118d442418680002000050e815ed000083c410"
    "8d442410506a016a00ff157cf17211898708080000"
    "e8984501003db70000007537"
    "807d2c007531"
    "5368a0f473118d442418680002000050e8d6ec000083c410"
    "8d4424106a106840f47311506a00ff159cf67211e82a350200"
    "8b35a8f672116a006854389f116a006a5effd6"
    "6a006a006a006a5dffd6"
)
PREFIX_SHA256 = "7d21f9b8d851f08196dbe6ae51dfc4a1743169ac320098979603a1c0f5a54dda"

CFG_BLOCKS = (
    (0x100DF270, 0x100DF2EF, 0x000DE670,
     "b915416ef4eb4d4dfc796e76cc96863df9dc36e15080cc6dfd5204ad618b26a6"),
    (0x100DF2EF, 0x100DF2F5, 0x000DE6EF,
     "491c29c2d0ea102e6d57f24c0d5b361686eb57241939996192a977b689dbf4e1"),
    (0x100DF2F5, 0x100DF326, 0x000DE6F5,
     "d2b4f569ee365b443f22e0d5de740730ed34086c9f981ec9321435ae3884c768"),
    (0x100DF326, 0x100DF343, 0x000DE726,
     "47d815e428da227d13b5e324bc1e1a0ae0b39c2d24c44fdd75c6c78523b0460e"),
)

DIRECT_CALLS = (
    (0x100DF2C6, 0x100EDFE0),
    (0x100DF2E3, 0x100F3880),
    (0x100DF305, 0x100EDFE0),
    (0x100DF321, 0x10102850),
)

IMPORT_IDENTITIES = {
    0x1172F17C: ("KERNEL32.dll", "CreateMutexW"),
    0x1172F1D8: ("KERNEL32.dll", "GetLastError"),
    0x1172F214: ("KERNEL32.dll", "GetCurrentProcess"),
    0x1172F21C: ("KERNEL32.dll", "TerminateProcess"),
    0x1172F66C: ("USER32.dll", "LoadStringW"),
    0x1172F69C: ("USER32.dll", "MessageBoxW"),
    0x1172F6A8: ("USER32.dll", "SystemParametersInfoW"),
}

SPI_TAIL_VA = 0x100DF326
SPI_TAIL_BYTES = bytes.fromhex(
    "8b35a8f67211"       # mov esi, [SystemParametersInfoW IAT]
    "6a00"               # fWinIni = 0
    "6854389f11"         # pvParam = original global 0x119f3854
    "6a00"               # uiParam = 0
    "6a5e"               # SPI_GETMOUSETRAILS
    "ffd6"               # call esi
    "6a00"               # fWinIni = 0
    "6a00"               # pvParam = NULL
    "6a00"               # uiParam = 0
    "6a5d"               # SPI_SETMOUSETRAILS
    "ffd6"               # call esi
)
SPI_TAIL_SHA256 = "47d815e428da227d13b5e324bc1e1a0ae0b39c2d24c44fdd75c6c78523b0460e"

HELPER_BODIES = {
    0x100DE0D0: (
        6, 0x000DD4D0, bytes.fromhex("b878309f11c3"),
        "31e9336a9a9b2dcb8354a28d881fdd62abbd4e08eb8d057318b785c04f2f279f",
    ),
    0x100EDFE0: (
        46, 0x000ED3E0,
        bytes.fromhex(
            "8d442410506a00ff742414ff742414ff742414e8d800ffffff7004ff30"
            "e81ee1590183c9ff83c41c85c00f48c1c3"
        ),
        "320d5542650ffe41b98030dedb416d2e9ca6e6dcb5fe8eaf59c62d77d61a692e",
    ),
    0x100F3880: (
        6, 0x000F2C80, bytes.fromhex("ff25d8f17211"),
        "37efc6d3f18411aceaaad3af6c1fe904856e95975f768eb262f1e62dbc1697df",
    ),
    0x10102850: (
        16, 0x00101C50,
        bytes.fromhex("6a00ff1514f2721150ff151cf27211c3"),
        "44afc37d13f0f2e4fc4ca260eb3bb7a2a84ae6e747eb4f1e295c296b9be952af",
    ),
    0x1168C120: (
        36, 0x0168B520,
        bytes.fromhex(
            "8bff558becff7520ff751cff7518ff7514ff7510ff750cff7508"
            "e8d9c5ffff83c41c5dc3"
        ),
        "455085d78d512322faa4d2b666521afee3c0ec5415d5917becc79bd633bf3900",
    ),
}

LITERALS = (
    (0x1173F440, 0x0173DE40,
     "Mutex error",
     "0852874ae53ba9395b0353e84928f99ff68211f97250e8c5ce56d34e93805ee9"),
    (0x1173F460, 0x0173DE60,
     "%s instance verification mutex",
     "27d4b227aa2df8c194ae21002c4a24d7e0591e4c12107245e0df862691cb9622"),
    (0x1173F4A0, 0x0173DEA0,
     "Another instance of %s is running.\nThis instance will terminate.",
     "8386f33ed228dfb9194d46af71f49253b21b058edf6c86f1acb4a8d9b6ce13ee"),
)

MIDDLE_VA = PREFIX_END_VA
MIDDLE_SIZE = 298
MIDDLE_RAW_OFFSET = 0x000DE743
MIDDLE_SHA256 = "a28d5aa15f78ba8ae4aac1738d5163d4cccf7d1d6d124eb0c117a6d09914beff"
MIDDLE_PREFIX_BYTES = bytes.fromhex("6a008d8f0c080000c707f4f27311")
SUFFIX_VA = 0x100DF46D

PARENT_PACKET_VA = 0x100ED454
PARENT_PACKET_BYTES = bytes.fromhex(
    "e857470000"         # call 0x100f1bb0; result is second argument
    "50"                 # push result
    "8d442438"           # packet identity
    "50"                 # push packet
    "8d4c246c"           # receiver identity in ECX
    "e8081effff"         # call 0x100df270
    "8d4c2428"
    "e84f480000"         # call 0x100f1cc0
)
PARENT_PACKET_RAW_OFFSET = 0x000EC854
PARENT_PACKET_SHA256 = "d5d1e05e59ce9530f514a209d763fcd30cf73c893821680c4074e1cffd21da6a"

RESTORE_WINDOWS = (
    (0x100E1A23, 0x000E0E23,
     bytes.fromhex(
         "6a006a00c70608f27311ff3554389f116a5dff15a8f67211"
         "ffb608080000ff1578f17211"
     ),
     "5b7fff90872da61b7224e98659c02997cf086732bdc19cf6ab6760425178476e"),
    (0x100E0765, 0x000DFB65,
     bytes.fromhex(
         "6a006a00c70708f27311ff3554389f116a5dff15a8f67211"
         "ffb708080000ff1578f17211"
     ),
     "fb577e0efccbe1d6f9aeded1843c53b8af6e60fe59a06b6927026a0741c1128b"),
)

INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
CANONICAL_HASHES = {
    "100de0d0": "64339f1be8adaedff00a6ccd1d9a4f0cdf0f1463b0c23963ca228715c9f2b6bf",
    "100df270": "9309918694adc92b151210f40eeb1965a144d68b24967a9aa160ecdf8517de72",
    "100e0650": "f0630c6fbb3a402c1cf17165b8deb79e81bdb0c3ef03e351c24939090ad3b85c",
    "100e1a20": "fdb0c74792528247415130cca1ce3d81e4800eb12b7a9dbb704e26a436c74ed4",
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
    "100edfe0": "4f17354521e41b775c64d3f4e7b344918a400e06accb8c8b0f12983847789eb0",
    "100f3880": "0435ea8703afc37c3f179ba39884a119717c00024968f891c26cb135fe426c45",
    "10102850": "ea30d526525f825e042c9f6745f500bfc51924ef85df9f94b06244eb523e832b",
    "1014d170": "e8beeafe648a778ef905c70b13ddc51124d67c01550d070f57f46b2aabe9f4bc",
    "1168c120": "4f35106042122cbe7378cbe4d68973d587d9037aaf8f91e40d43e555c854470e",
}
CANONICAL_ROWS = {
    "100de0d0": ("decomp_fn_100de0d0", "6", "100de0d0-100de0d5"),
    "100df270": ("decomp_fn_100df270", "640", "100df270-100df4ef"),
    "100e0650": ("decomp_fn_100e0650", "321", "100e0650-100e0790"),
    "100e1a20": ("decomp_fn_100e1a20", "72", "100e1a20-100e1a67"),
    "100ed3c0": ("decomp_fn_100ed3c0", "400", "100ed3c0-100ed54f"),
    "100edfe0": ("decomp_fn_100edfe0", "46", "100edfe0-100ee00d"),
    "100f3880": ("decomp_fn_100f3880", "6", "100f3880-100f3885"),
    "10102850": ("decomp_fn_10102850", "16", "10102850-1010285f"),
    "1014d170": ("decomp_fn_1014d170", "16", "1014d170-1014d17f"),
    "1168c120": ("decomp_fn_1168c120", "36", "1168c120-1168c143"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} lies outside the {len(data)}-byte input")


def parse_pe32(data: bytes) -> dict[str, object]:
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
        or optional_size < 0xE0
        or struct.unpack_from("<H", data, optional)[0] != 0x010B
    ):
        raise ValueError("image is not a bounded PE32 x86 image")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    directory_count = struct.unpack_from("<I", data, optional + 92)[0]
    if directory_count < 16:
        raise ValueError("PE32 image has an incomplete data-directory table")
    directories = tuple(
        struct.unpack_from("<II", data, optional + 96 + index * 8)
        for index in range(16)
    )

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
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append(
            (name, rva, virtual_size, raw_offset, raw_size, characteristics)
        )
    return {
        "pe_offset": pe_offset,
        "image_base": image_base,
        "sections": tuple(sections),
        "directories": directories,
    }


def read_rva(data: bytes, pe: dict[str, object], rva: int, size: int):
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size, _flags in pe["sections"]:
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"RVA 0x{rva:08x} has {len(matches)} raw mappings")
    name, raw_offset = matches[0]
    require_range(data, raw_offset, size, f"RVA 0x{rva:08x}")
    return data[raw_offset:raw_offset + size], name, raw_offset


def read_va(data: bytes, pe: dict[str, object], va: int, size: int):
    image_base = pe["image_base"]
    if va < image_base:
        raise ValueError(f"VA 0x{va:08x} precedes the image base")
    return read_rva(data, pe, va - image_base, size)


def read_c_string_rva(data: bytes, pe: dict[str, object], rva: int) -> str:
    _unit, _section, raw_offset = read_rva(data, pe, rva, 1)
    raw_end = None
    for _name, section_rva, _virtual_size, section_raw, raw_size, _flags in pe["sections"]:
        if section_rva <= rva < section_rva + raw_size:
            raw_end = section_raw + raw_size
            break
    if raw_end is None:
        raise ValueError(f"string RVA 0x{rva:08x} has no section")
    terminator = data.find(b"\0", raw_offset, raw_end)
    if terminator < 0:
        raise ValueError(f"unterminated string at RVA 0x{rva:08x}")
    try:
        return data[raw_offset:terminator].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-ASCII import string at RVA 0x{rva:08x}") from exc


def parse_imports(data: bytes, pe: dict[str, object]) -> dict[int, tuple[str, str]]:
    import_rva, import_size = pe["directories"][1]
    if import_rva == 0 or import_size < 20:
        raise ValueError("missing import directory")
    imports: dict[int, tuple[str, str]] = {}
    for descriptor_index in range(import_size // 20):
        descriptor, _section, _raw = read_rva(
            data, pe, import_rva + descriptor_index * 20, 20
        )
        original_thunk, timestamp, chain, name_rva, first_thunk = (
            struct.unpack("<IIIII", descriptor)
        )
        if not any((original_thunk, timestamp, chain, name_rva, first_thunk)):
            return imports
        dll_name = read_c_string_rva(data, pe, name_rva)
        lookup_rva = original_thunk or first_thunk
        for thunk_index in range(65_536):
            thunk_bytes, _section, _raw = read_rva(
                data, pe, lookup_rva + thunk_index * 4, 4
            )
            thunk = struct.unpack("<I", thunk_bytes)[0]
            if thunk == 0:
                break
            if thunk & 0x80000000:
                symbol = f"#{thunk & 0xffff}"
            else:
                symbol = read_c_string_rva(data, pe, thunk + 2)
            iat_va = pe["image_base"] + first_thunk + thunk_index * 4
            if iat_va in imports:
                raise ValueError(f"duplicate IAT address 0x{iat_va:08x}")
            imports[iat_va] = (dll_name, symbol)
        else:
            raise ValueError("unterminated import thunk table")
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


def iat_operand(body: bytes, instruction_offset: int, opcode: bytes) -> int:
    require_range(body, instruction_offset, len(opcode) + 4, "IAT instruction")
    if body[instruction_offset:instruction_offset + len(opcode)] != opcode:
        raise ValueError("unexpected IAT instruction opcode")
    return struct.unpack_from("<I", body, instruction_offset + len(opcode))[0]


def resource_directory_entries(blob: bytes, relative_offset: int):
    require_range(blob, relative_offset, 16, "resource directory")
    _flags, _timestamp, _major, _minor, named_count, id_count = (
        struct.unpack_from("<IIHHHH", blob, relative_offset)
    )
    count = named_count + id_count
    require_range(blob, relative_offset + 16, count * 8, "resource entries")
    return tuple(
        struct.unpack_from("<II", blob, relative_offset + 16 + index * 8)
        for index in range(count)
    )


def resource_id_entry(blob: bytes, relative_offset: int, wanted: int) -> int:
    matches = [
        value for name, value in resource_directory_entries(blob, relative_offset)
        if name == wanted
    ]
    if len(matches) != 1:
        raise ValueError(f"resource ID {wanted} has {len(matches)} entries")
    return matches[0]


class Startup100df270PlatformPrefixTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.dll_pe = parse_pe32(cls.dll)

        cls.launcher = LAUNCHER.read_bytes()
        if (
            len(cls.launcher) != LAUNCHER_SIZE
            or sha256(cls.launcher) != LAUNCHER_SHA256
        ):
            raise AssertionError("launcher differs from the pinned corpus")
        cls.launcher_pe = parse_pe32(cls.launcher)

    def test_original_pe_map_and_complete_640_byte_function_are_pinned(self):
        self.assertEqual(self.dll_pe["pe_offset"], DLL_PE_OFFSET)
        self.assertEqual(self.dll_pe["image_base"], DLL_IMAGE_BASE)
        self.assertEqual(self.dll_pe["sections"], DLL_SECTIONS)
        self.assertEqual(self.dll_pe["directories"][1], DLL_IMPORT_RVA_SIZE)
        self.assertEqual(self.dll_pe["directories"][2], DLL_RESOURCE_RVA_SIZE)

        body, section, raw_offset = read_va(
            self.dll, self.dll_pe, FUNCTION_VA, FUNCTION_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", FUNCTION_RAW_OFFSET))
        self.assertEqual(len(body), FUNCTION_SIZE)
        self.assertEqual(sha256(body), FUNCTION_SHA256)
        self.assertEqual(FUNCTION_VA + FUNCTION_SIZE, 0x100DF4F0)

    def test_exact_211_byte_prefix_and_four_cfg_blocks_are_pinned(self):
        prefix, section, raw_offset = read_va(
            self.dll, self.dll_pe, PREFIX_VA, len(PREFIX_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", PREFIX_RAW_OFFSET))
        self.assertEqual(prefix, PREFIX_BYTES)
        self.assertEqual(len(prefix), 211)
        self.assertEqual(sha256(prefix), PREFIX_SHA256)
        self.assertEqual(PREFIX_VA + len(prefix), PREFIX_END_VA)

        cursor = PREFIX_VA
        for start, end, expected_raw, expected_hash in CFG_BLOCKS:
            self.assertEqual(start, cursor)
            block, section, raw_offset = read_va(
                self.dll, self.dll_pe, start, end - start
            )
            self.assertEqual((section, raw_offset), (".text", expected_raw))
            self.assertEqual(
                block,
                PREFIX_BYTES[start - PREFIX_VA:end - PREFIX_VA],
            )
            self.assertEqual(sha256(block), expected_hash)
            cursor = end
        self.assertEqual(cursor, PREFIX_END_VA)

    def test_two_conditional_branches_form_the_exact_merge_cfg(self):
        first_offset = 0x100DF2ED - PREFIX_VA
        second_offset = 0x100DF2F3 - PREFIX_VA
        self.assertEqual(PREFIX_BYTES[first_offset], 0x75)
        self.assertEqual(PREFIX_BYTES[second_offset], 0x75)
        self.assertEqual(rel8_target(PREFIX_BYTES, PREFIX_VA, first_offset), 0x100DF326)
        self.assertEqual(rel8_target(PREFIX_BYTES, PREFIX_VA, second_offset), 0x100DF326)
        self.assertEqual(PREFIX_BYTES[0x78:0x7F], bytes.fromhex("3db70000007537"))
        self.assertEqual(PREFIX_BYTES[0x7F:0x85], bytes.fromhex("807d2c007531"))

        # The duplicate block has no jump at its end.  The direct helper has a
        # real RET, so failed TerminateProcess can fall through into the merge.
        self.assertEqual(PREFIX_BYTES[0xB1:0xB6], bytes.fromhex("e82a350200"))
        self.assertEqual(0x100DF326, 0x100DF321 + 5)

    def test_direct_and_imported_call_shapes_and_order_are_exact(self):
        observed_direct = tuple(
            PREFIX_VA + offset
            for offset, value in enumerate(PREFIX_BYTES)
            if value == 0xE8
        )
        self.assertEqual(observed_direct, tuple(site for site, _ in DIRECT_CALLS))
        for site, target in DIRECT_CALLS:
            self.assertEqual(
                rel32_target(PREFIX_BYTES, PREFIX_VA, site - PREFIX_VA), target
            )

        imports = parse_imports(self.dll, self.dll_pe)
        for address, expected in IMPORT_IDENTITIES.items():
            self.assertEqual(imports[address], expected)

        self.assertEqual(
            iat_operand(PREFIX_BYTES, 0x10, bytes.fromhex("8b35")),
            0x1172F66C,
        )
        self.assertEqual(
            [offset for offset in range(len(PREFIX_BYTES))
             if PREFIX_BYTES.startswith(bytes.fromhex("ffd6"), offset)],
            [0x34, 0x44, 0xC7, 0xD1],
        )
        self.assertEqual(
            iat_operand(PREFIX_BYTES, 0x67, bytes.fromhex("ff15")),
            0x1172F17C,
        )
        self.assertEqual(
            iat_operand(PREFIX_BYTES, 0xAB, bytes.fromhex("ff15")),
            0x1172F69C,
        )
        self.assertEqual(
            iat_operand(PREFIX_BYTES, 0xB6, bytes.fromhex("8b35")),
            0x1172F6A8,
        )
        observed_order = []
        for offset in range(len(PREFIX_BYTES)):
            site = PREFIX_VA + offset
            if PREFIX_BYTES[offset:offset + 1] == b"\xe8":
                observed_order.append(
                    (site, rel32_target(PREFIX_BYTES, PREFIX_VA, offset))
                )
            elif PREFIX_BYTES.startswith(bytes.fromhex("ff15"), offset):
                observed_order.append(
                    (site, iat_operand(PREFIX_BYTES, offset, bytes.fromhex("ff15")))
                )
            elif PREFIX_BYTES.startswith(bytes.fromhex("ffd6"), offset):
                active_iat = 0x1172F66C if site < 0x100DF326 else 0x1172F6A8
                observed_order.append((site, active_iat))
        self.assertEqual(
            tuple(observed_order),
            (
                (0x100DF2A4, 0x1172F66C),
                (0x100DF2B4, 0x1172F66C),
                (0x100DF2C6, 0x100EDFE0),
                (0x100DF2D7, 0x1172F17C),
                (0x100DF2E3, 0x100F3880),
                (0x100DF305, 0x100EDFE0),
                (0x100DF31B, 0x1172F69C),
                (0x100DF321, 0x10102850),
                (0x100DF337, 0x1172F6A8),
                (0x100DF341, 0x1172F6A8),
            ),
        )

    def test_packet_reads_three_writes_and_resource_endpoints_are_exact(self):
        self.assertEqual(PREFIX_BYTES[0x08:0x0F], bytes.fromhex("8bac240c040000"))
        self.assertEqual(PREFIX_BYTES[0x17:0x1A], bytes.fromhex("8b5500"))
        self.assertEqual(PREFIX_BYTES[0x7F:0x83], bytes.fromhex("807d2c00"))

        writes = (
            (0x100DF297, bytes.fromhex("895704"), 0x04),
            (0x100DF29E, bytes.fromhex("c70708f27311"), 0x00),
            (0x100DF2DD, bytes.fromhex("898708080000"), 0x808),
        )
        for site, expected, _destination in writes:
            offset = site - PREFIX_VA
            self.assertEqual(PREFIX_BYTES[offset:offset + len(expected)], expected)
        self.assertEqual(tuple(destination for _, _, destination in writes),
                         (0x04, 0x00, 0x808))

        self.assertEqual(PREFIX_BYTES[0x21:0x27], bytes.fromhex("8d8708040000"))
        self.assertEqual(PREFIX_BYTES[0x3B:0x3E], bytes.fromhex("8d5f08"))
        self.assertEqual(PREFIX_BYTES[0x2A:0x2E], bytes.fromhex("506a6d52"))
        self.assertEqual(PREFIX_BYTES[0x3E:0x44], bytes.fromhex("536a67ff7704"))
        self.assertEqual((0x408, 0x408 + 0x400), (0x408, 0x808))
        self.assertEqual((0x008, 0x008 + 0x400), (0x008, 0x408))
        self.assertEqual(0x808 + 4, 0x80C)

    def test_spi_tail_and_both_lifecycle_restore_windows_are_exact(self):
        tail, section, raw_offset = read_va(
            self.dll, self.dll_pe, SPI_TAIL_VA, len(SPI_TAIL_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", 0x000DE726))
        self.assertEqual(tail, SPI_TAIL_BYTES)
        self.assertEqual(sha256(tail), SPI_TAIL_SHA256)
        self.assertEqual(tail.count(bytes.fromhex("ffd6")), 2)
        self.assertIn(bytes.fromhex("6854389f11"), tail)
        self.assertIn(bytes.fromhex("6a5e"), tail)
        self.assertIn(bytes.fromhex("6a5d"), tail)

        for va, expected_raw, expected, expected_hash in RESTORE_WINDOWS:
            body, section, raw_offset = read_va(
                self.dll, self.dll_pe, va, len(expected)
            )
            self.assertEqual((section, raw_offset), (".text", expected_raw))
            self.assertEqual(body, expected)
            self.assertEqual(sha256(body), expected_hash)
            self.assertIn(bytes.fromhex("ff3554389f116a5d"), body)
            self.assertIn(bytes.fromhex("ff15a8f67211"), body)

    def test_direct_helper_bodies_include_a_returning_termination_helper(self):
        for va, (size, expected_raw, expected, expected_hash) in HELPER_BODIES.items():
            body, section, raw_offset = read_va(self.dll, self.dll_pe, va, size)
            self.assertEqual((section, raw_offset), (".text", expected_raw))
            self.assertEqual(body, expected)
            self.assertEqual(sha256(body), expected_hash)

        formatter = HELPER_BODIES[0x100EDFE0][2]
        self.assertEqual(rel32_target(formatter, 0x100EDFE0, 0x13), 0x100DE0D0)
        self.assertEqual(rel32_target(formatter, 0x100EDFE0, 0x1D), 0x1168C120)

        get_last_error = HELPER_BODIES[0x100F3880][2]
        self.assertEqual(iat_operand(get_last_error, 0, bytes.fromhex("ff25")),
                         0x1172F1D8)

        terminate = HELPER_BODIES[0x10102850][2]
        self.assertEqual(terminate[-1:], b"\xc3")
        self.assertEqual(iat_operand(terminate, 2, bytes.fromhex("ff15")),
                         0x1172F214)
        self.assertEqual(iat_operand(terminate, 9, bytes.fromhex("ff15")),
                         0x1172F21C)
        self.assertEqual(terminate[0:2], bytes.fromhex("6a00"))
        self.assertEqual(terminate[8:9], bytes.fromhex("50"))

    def test_three_wide_literal_byte_strings_are_exact(self):
        for va, expected_raw, text, expected_hash in LITERALS:
            expected = (text + "\0").encode("utf-16le")
            body, section, raw_offset = read_va(
                self.dll, self.dll_pe, va, len(expected)
            )
            self.assertEqual((section, raw_offset), (".rdata", expected_raw))
            self.assertEqual(body, expected)
            self.assertEqual(sha256(body), expected_hash)

    def test_adjacent_deterministic_middle_boundary_is_exact(self):
        middle, section, raw_offset = read_va(
            self.dll, self.dll_pe, MIDDLE_VA, MIDDLE_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", MIDDLE_RAW_OFFSET))
        self.assertEqual(sha256(middle), MIDDLE_SHA256)
        self.assertEqual(middle[:len(MIDDLE_PREFIX_BYTES)], MIDDLE_PREFIX_BYTES)
        self.assertEqual(MIDDLE_VA + MIDDLE_SIZE, SUFFIX_VA)
        self.assertEqual(
            rel32_target(middle, MIDDLE_VA, 0x100DF468 - MIDDLE_VA),
            0x1014D170,
        )
        self.assertEqual(PREFIX_END_VA, MIDDLE_VA)

    def test_parent_call_packet_and_receiver_setup_are_exact(self):
        packet, section, raw_offset = read_va(
            self.dll, self.dll_pe, PARENT_PACKET_VA, len(PARENT_PACKET_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", PARENT_PACKET_RAW_OFFSET))
        self.assertEqual(packet, PARENT_PACKET_BYTES)
        self.assertEqual(sha256(packet), PARENT_PACKET_SHA256)
        self.assertEqual(rel32_target(packet, PARENT_PACKET_VA, 0), 0x100F1BB0)
        self.assertEqual(
            rel32_target(packet, PARENT_PACKET_VA, 0x100ED463 - PARENT_PACKET_VA),
            FUNCTION_VA,
        )
        self.assertEqual(
            rel32_target(packet, PARENT_PACKET_VA, 0x100ED46C - PARENT_PACKET_VA),
            0x100F1CC0,
        )
        self.assertEqual(packet[5:15], bytes.fromhex("508d442438508d4c246c"))

    def test_launcher_resource_ids_67_and_6d_are_inertly_pinned(self):
        self.assertEqual(self.launcher_pe["pe_offset"], LAUNCHER_PE_OFFSET)
        self.assertEqual(self.launcher_pe["image_base"], LAUNCHER_IMAGE_BASE)
        self.assertEqual(self.launcher_pe["sections"], LAUNCHER_SECTIONS)
        self.assertEqual(
            self.launcher_pe["directories"][2], LAUNCHER_RESOURCE_RVA_SIZE
        )

        resource_rva, resource_size = self.launcher_pe["directories"][2]
        resource_blob, section, resource_raw = read_rva(
            self.launcher, self.launcher_pe, resource_rva, resource_size
        )
        self.assertEqual((section, resource_raw), (".rsrc", 0x00029400))

        type_entry = resource_id_entry(resource_blob, 0, 6)
        self.assertNotEqual(type_entry & 0x80000000, 0)
        block_entry = resource_id_entry(
            resource_blob, type_entry & 0x7FFFFFFF, 7
        )
        self.assertNotEqual(block_entry & 0x80000000, 0)
        language_entry = resource_id_entry(
            resource_blob, block_entry & 0x7FFFFFFF, 0x0409
        )
        self.assertEqual(language_entry & 0x80000000, 0)

        require_range(resource_blob, language_entry, 16, "resource data entry")
        data_rva, data_size, code_page, reserved = struct.unpack_from(
            "<IIII", resource_blob, language_entry
        )
        self.assertEqual((data_rva, data_size, code_page, reserved),
                         (0x001CB698, 138, 0, 0))
        block, section, block_raw = read_rva(
            self.launcher, self.launcher_pe, data_rva, data_size
        )
        self.assertEqual((section, block_raw), (".rsrc", 0x000C2A98))
        self.assertEqual(
            sha256(block),
            "169da1a5507d88f820a2bfb2e800a8942a799d052b4625cda847392974ebfdf8",
        )

        records = {}
        cursor = 0
        for index in range(16):
            start = cursor
            require_range(block, cursor, 2, "RT_STRING length")
            unit_count = struct.unpack_from("<H", block, cursor)[0]
            cursor += 2
            require_range(block, cursor, unit_count * 2, "RT_STRING payload")
            payload = block[cursor:cursor + unit_count * 2]
            cursor += unit_count * 2
            records[96 + index] = (start, block[start:cursor], payload)
        self.assertEqual(cursor, len(block))

        expected = {
            0x67: (
                0x0E, 0x000C2AA6, "Total War: ROME 2",
                "05472f692408b544d8c689c7ec86c1b79c3a7f2e9242c862f1907c41c376af25",
            ),
            0x6D: (
                0x78, 0x000C2B10, "ROME 2",
                "72ae02bf62f50e022ef2c172796d163be367c3d7fe75991cc65a1fb2862cfc4c",
            ),
        }
        for resource_id, (relative, raw, text, record_hash) in expected.items():
            observed_relative, record, payload = records[resource_id]
            self.assertEqual(observed_relative, relative)
            self.assertEqual(block_raw + observed_relative, raw)
            self.assertEqual(payload.decode("utf-16le"), text)
            self.assertEqual(record, struct.pack("<H", len(text)) + text.encode("utf-16le"))
            self.assertEqual(sha256(record), record_hash)

    def test_canonical_sources_index_rows_and_semantics_are_exact(self):
        index_bytes = INDEX.read_bytes()
        self.assertEqual(sha256(index_bytes), INDEX_SHA256)
        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                index_bytes.decode("utf-8").splitlines(), delimiter="\t"
            )
        }
        for entry, expected in CANONICAL_ROWS.items():
            row = rows[entry]
            self.assertEqual(
                (row["canonical_name"], row["size"], row["body_ranges"]),
                expected,
            )
            source = CANONICAL / f"decomp_fn_{entry}.c"
            self.assertEqual(sha256(source.read_bytes()), CANONICAL_HASHES[entry])

        function_text = (CANONICAL / "decomp_fn_100df270.c").read_text(
            encoding="utf-8"
        )
        for token in (
            "param_1[1] = hInstance;",
            "*param_1 = &PTR_decomp_fn_100e1a20_1173f208;",
            "LoadStringW(hInstance,0x6d",
            "LoadStringW((HINSTANCE)param_1[1],0x67",
            "CreateMutexW((LPSECURITY_ATTRIBUTES)0x0,1,local_400);",
            "DVar2 = decomp_fn_100f3880();",
            "(DVar2 == 0xb7)",
            "*(char *)(param_2 + 0xb) == '\\0'",
            "MessageBoxW((HWND)0x0,local_400,L\"Mutex error\",0x10);",
            "decomp_fn_10102850();",
            "SystemParametersInfoW(0x5e,0,&DAT_119f3854,0);",
            "SystemParametersInfoW(0x5d,0,(PVOID)0x0,0);",
        ):
            self.assertIn(token, function_text)

        terminate_text = (CANONICAL / "decomp_fn_10102850.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("hProcess = GetCurrentProcess();", terminate_text)
        self.assertIn("TerminateProcess(hProcess,uExitCode);", terminate_text)
        self.assertIn("return;", terminate_text)

        parent_text = (CANONICAL / "decomp_fn_100ed3c0.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("local_8ac = 0;", parent_text)
        self.assertIn("decomp_fn_100df270(&local_8d8,uVar5);", parent_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
