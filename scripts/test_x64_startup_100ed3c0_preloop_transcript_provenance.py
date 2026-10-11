#!/usr/bin/env python3
"""Authenticate the inert pre-loop portion of original x86 0x100ed3c0.

The original PE is parsed only as bytes.  No recovered address is loaded or
executed.  The admitted native implementations are pinned as narrower
references: in particular, the bounded 0x100f1bb0 port does not reproduce its
allocator-capable descriptor copy, and the composed 0x100df270 child never
runs the original platform calls.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
CANONICAL = (
    ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
)
INDEX = (
    ROOT / "src_canonical_out" / "empire.retail.dll" /
    "canonical_function_index.tsv"
)

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
PE_OFFSET = 0x190
IMAGE_BASE = 0x10000000
SIZE_OF_IMAGE = 0x02234000
SIZE_OF_HEADERS = 0x400
PE_DIRECTORIES = (
    (0x019265F0, 0x8E88),
    (0x0192F478, 0x208),
    (0x02138000, 0x578),
    (0, 0),
    (0, 0),
    (0x02139000, 0xFA668),
    (0x019232F0, 0x54),
    (0, 0),
    (0, 0),
    (0x01923410, 0x18),
    (0x01923348, 0x40),
    (0, 0),
    (0x0172F000, 0xA00),
    (0, 0),
    (0, 0),
    (0, 0),
)
PE_SECTIONS = (
    (".text", 0x00001000, 0x0172D4EA, 0x00000400, 0x0172D600, 0x60000020),
    (".rdata", 0x0172F000, 0x00203174, 0x0172DA00, 0x00203200, 0x40000040),
    (".data", 0x01933000, 0x007F3C40, 0x01930C00, 0x000BC200, 0xC0000040),
    (".msvcjmc", 0x02127000, 0x0000D9DE, 0x019ECE00, 0x0000DA00, 0xC0000040),
    ("_RDATA", 0x02135000, 0x00002608, 0x019FA800, 0x00002800, 0x40000040),
    (".rsrc", 0x02138000, 0x00000578, 0x019FD000, 0x00000600, 0x40000040),
    (".reloc", 0x02139000, 0x000FA668, 0x019FD600, 0x000FA800, 0x42000040),
)

PARENT_VA = 0x100ED3C0
PARENT_RAW_OFFSET = 0x000EC7C0
PARENT_SIZE = 400
PARENT_SHA256 = "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"

PRELOOP_VA = PARENT_VA
PRELOOP_END_VA = 0x100ED471
PRELOOP_RAW_OFFSET = PARENT_RAW_OFFSET
PRELOOP_BYTES = bytes.fromhex(
    "81ec0c0900008d4c2404c605c8319f1101c605c5319f1101c7042400000000"
    "e82c4800008d4c2410e8234800008b8424100900008d4c243c8944241c"
    "894424348b0424894424388d44240450c644242400c744242800000000"
    "e8824600008d442410508d4c244ce8744600008b44241c8d4c2428"
    "ffb42418090000894424588a4424248844245c8b44242889442460"
    "c644246400e857470000508d442438508d4c246ce8081effff"
    "8d4c2428e84f480000"
)
PRELOOP_SHA256 = "b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626"

EXCLUDED_VA = PRELOOP_END_VA
EXCLUDED_END_VA = 0x100ED550
EXCLUDED_RAW_OFFSET = 0x000EC871
EXCLUDED_BYTES = bytes.fromhex(
    "568d4c2468e8e5cbffff6a006a006884007411e867f61e016a00e8d090feff"
    "83c410e888681f016a008bc88b10ff52548d44242c50e805571f0183c404"
    "8b08898c24080900008b40048984240c0900008d4c2468e8f6f0ffff"
    "83f802744c83f80175ed8b9424d80800008b8424d40800008d34823bf27422"
    "0f1f80000000008b4efc83c6fc85c9740d8b016a01ff10"
    "8b9424d80800003bf275e5c78424d408000000000000e957ffffff"
    "8d4c2468e82c31ffff8d4c244ce8934700008d4c2440e88a470000"
    "8d4c2414e8814700008d4c2408e8784700005e81c40c090000c3"
)
EXCLUDED_SHA256 = "0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9"

# A fixed, standard-library-only partition.  This is deliberately not a
# general x86 decoder: every instruction boundary and byte is authenticated.
INSTRUCTION_PARTITION = (
    (0x100ED3C0, "81ec0c090000", "sub_frame_0x90c"),
    (0x100ED3C6, "8d4c2404", "triplet_a_receiver"),
    (0x100ED3CA, "c605c8319f1101", "store_global_119f31c8"),
    (0x100ED3D1, "c605c5319f1101", "store_global_119f31c5"),
    (0x100ED3D8, "c7042400000000", "zero_scratch"),
    (0x100ED3DF, "e82c480000", "call_100f1c10_a"),
    (0x100ED3E4, "8d4c2410", "triplet_b_receiver"),
    (0x100ED3E8, "e823480000", "call_100f1c10_b"),
    (0x100ED3ED, "8b842410090000", "read_entry_position_1"),
    (0x100ED3F4, "8d4c243c", "empty_copy_a_receiver"),
    (0x100ED3F8, "8944241c", "save_position_1"),
    (0x100ED3FC, "89442434", "packet_position_1"),
    (0x100ED400, "8b0424", "read_zero_scratch"),
    (0x100ED403, "89442438", "packet_zero_dword"),
    (0x100ED407, "8d442404", "triplet_a_address"),
    (0x100ED40B, "50", "push_triplet_a"),
    (0x100ED40C, "c644242400", "packet_zero_byte_a"),
    (0x100ED411, "c744242800000000", "packet_zero_dword_b"),
    (0x100ED419, "e882460000", "call_100f1aa0_a"),
    (0x100ED41E, "8d442410", "triplet_b_address"),
    (0x100ED422, "50", "push_triplet_b"),
    (0x100ED423, "8d4c244c", "empty_copy_b_receiver"),
    (0x100ED427, "e874460000", "call_100f1aa0_b"),
    (0x100ED42C, "8b44241c", "reload_position_1"),
    (0x100ED430, "8d4c2428", "descriptor_receiver"),
    (0x100ED434, "ffb42418090000", "push_entry_position_3"),
    (0x100ED43B, "89442458", "packet_position_1_copy"),
    (0x100ED43F, "8a442424", "read_packet_zero_byte_a"),
    (0x100ED443, "8844245c", "packet_zero_byte_copy"),
    (0x100ED447, "8b442428", "read_packet_zero_dword_b"),
    (0x100ED44B, "89442460", "packet_zero_dword_copy"),
    (0x100ED44F, "c644246400", "packet_zero_byte_b"),
    (0x100ED454, "e857470000", "call_100f1bb0"),
    (0x100ED459, "50", "push_descriptor"),
    (0x100ED45A, "8d442438", "packet_address"),
    (0x100ED45E, "50", "push_packet"),
    (0x100ED45F, "8d4c246c", "child_receiver"),
    (0x100ED463, "e8081effff", "call_100df270"),
    (0x100ED468, "8d4c2428", "cleanup_receiver"),
    (0x100ED46C, "e84f480000", "call_100f1cc0"),
)

DIRECT_CALLS = (
    (0x100ED3DF, 0x100F1C10),
    (0x100ED3E8, 0x100F1C10),
    (0x100ED419, 0x100F1AA0),
    (0x100ED427, 0x100F1AA0),
    (0x100ED454, 0x100F1BB0),
    (0x100ED463, 0x100DF270),
    (0x100ED46C, 0x100F1CC0),
)

OPERATION_ORDER = (
    "store_global_119f31c8",
    "store_global_119f31c5",
    "initialize_triplet_a_100f1c10",
    "initialize_triplet_b_100f1c10",
    "copy_empty_a_100f1aa0",
    "copy_empty_b_100f1aa0",
    "construct_bounded_descriptor_100f1bb0",
    "run_bounded_child_100df270",
    "cleanup_nonowning_100f1cc0",
)
OPERATION_SITES = (
    (0x100ED3CA, OPERATION_ORDER[0]),
    (0x100ED3D1, OPERATION_ORDER[1]),
    (0x100ED3DF, OPERATION_ORDER[2]),
    (0x100ED3E8, OPERATION_ORDER[3]),
    (0x100ED419, OPERATION_ORDER[4]),
    (0x100ED427, OPERATION_ORDER[5]),
    (0x100ED454, OPERATION_ORDER[6]),
    (0x100ED463, OPERATION_ORDER[7]),
    (0x100ED46C, OPERATION_ORDER[8]),
)

# This model names the bounded native substitutions attached to the raw sites.
# In particular, the original call at 0x100ed454 is not itself a bounded
# constructor: the admitted composition first measures zero units and then
# invokes the independent triplet writer.
SEMANTIC_MODEL = {
    "frame_size": 0x90C,
    "copy_a_receiver_sp_delta": 0,
    "copy_a_receiver_displacement": 0x3C,
    "copy_a_source_sp_delta": 0,
    "copy_a_source_displacement": 0x04,
    "copy_a_call_sp_delta": -4,
    "copy_b_source_sp_delta": 0,
    "copy_b_source_displacement": 0x10,
    "copy_b_receiver_sp_delta": -4,
    "copy_b_receiver_displacement": 0x4C,
    "copy_b_call_sp_delta": -4,
    "packet_lea_sp_delta": -4,
    "packet_lea_displacement": 0x38,
    "child_call_sp_delta": -8,
    "child_argument_order": ("packet", "descriptor"),
    "descriptor_plan": ("measure_zero_100f1bb0", "initialize_triplet_100f1c10"),
    "packet_padding_25_27_initialized": False,
    "frame_gap_61_63_initialized": False,
    "stop_va": 0x100ED471,
}

GLOBAL_STORES = (
    (0x100ED3CA, 0x119F31C8, 1),
    (0x100ED3D1, 0x119F31C5, 1),
)

# Offsets are relative to S = entry ESP - 0x90c after the frame allocation.
FRAME_SIZE = 0x90C
STACK_LAYOUT = {
    "scratch_zero": 0x00,
    "triplet_a": 0x04,
    "triplet_b": 0x10,
    "position_1_snapshot": 0x1C,
    "descriptor": 0x28,
    "packet": 0x34,
    "empty_copy_a": 0x3C,
    "empty_copy_b": 0x48,
    "child_receiver": 0x64,
}
TRIPLET_BYTES = 12
DESCRIPTOR_BYTES = 12
PACKET_BYTES = 0x2D
CHILD_RECEIVER_BYTES = 0x8A8

CALLEE_AUTHORITIES = {
    0x100F1C10: (23, 0x000F1010,
        "6c689fc50bf6bfcfb73dc23095cfc6c98a757df32867c8d8b77514129bb8a2a1"),
    0x100F1AA0: (32, 0x000F0EA0,
        "cec1214bba5a2c2c8c45487abf0da2412df9dcb634da206f6f6e74f6c619e92e"),
    0x100EF330: (124, 0x000EE730,
        "b343025d84a700b1a9e37ffcafc5222ad53a23643c1c99aede37ab1e2193b93d"),
    0x100F1BB0: (53, 0x000F0FB0,
        "94088db58e056bb26dba6ce27d33c6353afce3b9300dfa63810c813dd115b2eb"),
    0x100DF270: (640, 0x000DE670,
        "d5a89108422a8c8a07d7150501805b70cedf81686b2f6a7e105e6d39d3a725f7"),
    0x100F1CC0: (51, 0x000F10C0,
        "bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4"),
}
CALLEE_BYTES = {
    0x100F1C10: bytes.fromhex(
        "c701000000008bc1c7410400000000c741089040af11c3"
    ),
    0x100F1AA0: bytes.fromhex(
        "8b44240456578bf98b1089178b70088d04565056e877d8ffff8bc75f5ec20400"
    ),
    0x100EF330: bytes.fromhex(
        "578bf98b0789470485c0750bc747089040af115fc208005355568d04450a000000"
        "6a0050e827d900008b5c242033ed83c40833d28d700883e6fc8946fc8b442414"
        "2bd843897708d1eb3b4424180f47dd85db74152bf0668b088d40024266894c06fe"
        "3bd375f08b77088b0f66a18c40af116689044e5e5d5b5fc20800"
    ),
    0x100F1BB0: bytes.fromhex(
        "568b7424088bc6578bf9660f1f4400000fb71083c0026685d275f52bc683e802"
        "d1f889078d04465056e852d7ffff8bc75f5ec20400"
    ),
    0x100F1CC0: bytes.fromhex(
        "568b710881fe9040af11742585f674218b76fc85f6741a56e873310300a1b03e"
        "9f1183c40485c074086a0056ffd083c4085ec3"
    ),
}

CHILD_INTERVALS = (
    (0x100DF270, 211, 0x000DE670,
     "7d21f9b8d851f08196dbe6ae51dfc4a1743169ac320098979603a1c0f5a54dda"),
    (0x100DF343, 298, 0x000DE743,
     "a28d5aa15f78ba8ae4aac1738d5163d4cccf7d1d6d124eb0c117a6d09914beff"),
    (0x100DF46D, 131, 0x000DE86D,
     "27ee666d2327c9360be2f4175ee5ea58bf49e112a6a29af6760451d6a7341b75"),
)

CALLER_SOURCE_LOADS = (
    (0x100EDE68, 0x000ED268, bytes.fromhex("8b7508")),
    (0x100EDEC9, 0x000ED2C9, bytes.fromhex("8b7508")),
    (0x100EDECC, 0x000ED2CC, bytes.fromhex("8b7d10")),
)
CALLER_PACKETS = (
    (
        "handler_registered",
        0x100EDF20,
        0x000ED320,
        bytes.fromhex("ff752457ff750c56e893f4ffff"),
        bytes.fromhex(
            "ff752457ff750c56e893f4ffff6a01e89c5702006860650d10"
            "e8b271020083c418"
        ),
        "52227b99b8d956f8926eb0f02b0f3b8c62a229dee20653b5608dc81a96e41084",
    ),
    (
        "no_exception_handler",
        0x100EDF73,
        0x000ED373,
        bytes.fromhex("ff752457ff750c56e840f4ffff"),
        bytes.fromhex(
            "ff752457ff750c56e840f4ffff6a01e8495702006860650d10"
            "e85f71020083c418"
        ),
        "76a454a3f06c1c8de33f0b3b0ab432e059de9abca52b342b8cac0e9f50198d6a",
    ),
)

INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
CANONICAL_HASHES = {
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
    "100edd70": "ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34",
    "100f1c10": "ec3103cb0e6c9060bdb7a027949e496a9a4e81dc13ec5d3918638feeea071ed7",
    "100f1aa0": "42a3bfb8a5e82cd1cc46e40022641169bddbb0af62e42f3d1ea53ce98c7e0fd4",
    "100ef330": "cd306dafa21f1ceeaf16c4f66840cab347d12a264baaa80b690dba6f7ab58f3b",
    "100f1bb0": "97f290b71b7614457fb149f107899d69391b1e07f847a0b7448248cf8aa1fcc6",
    "100df270": "9309918694adc92b151210f40eeb1965a144d68b24967a9aa160ecdf8517de72",
    "100f1cc0": "8cd70d65677361ef62405e7621495b03ddb3901696a4a01c429ff609bc4b4a69",
}
CANONICAL_ROWS = {
    "100ed3c0": ("decomp_fn_100ed3c0", "400", "100ed3c0-100ed54f"),
    "100edd70": (
        "decomp_fn_100edd70", "535",
        "100edd70-100edf49,100edf73-100edfaf",
    ),
    "100f1c10": ("decomp_fn_100f1c10", "23", "100f1c10-100f1c26"),
    "100f1aa0": ("decomp_fn_100f1aa0", "32", "100f1aa0-100f1abf"),
    "100ef330": ("decomp_fn_100ef330", "124", "100ef330-100ef3ab"),
    "100f1bb0": ("decomp_fn_100f1bb0", "53", "100f1bb0-100f1be4"),
    "100df270": ("decomp_fn_100df270", "640", "100df270-100df4ef"),
    "100f1cc0": ("decomp_fn_100f1cc0", "51", "100f1cc0-100f1cf2"),
}

REFERENCE_HASHES = {
    "scripts/x64_startup_100ed3c0_abi_fixture.json":
        "d1f129b03e19fded78c19d8211f3a943a68004d2ff8c12a1530ce1f276a6f8d0",
    "scripts/test_x64_startup_100ed3c0_abi_provenance.py":
        "6a375973206129208d0af00bf81cdd0063494fdedbc08df1110fa74152850372",
    "docs/x64_startup_100ed3c0_abi_contract.md":
        "5c54c0efdc25b1d570e4e7f3329bcc477e5e0df6706a4e52b0f43e83b49d7859",
    "scripts/test_x64_startup_100f1c10_provenance.py":
        "258c44603f7df98867ed42626dc5b02b2fc9be259531c793533da7d5c8cd9e25",
    "scripts/test_x64_startup_100f1aa0_empty_provenance.py":
        "9705e7ec5e3a71762487b5d5dd15ddc4ba69e6fd13c9f79b9dc5f1194994ef30",
    "scripts/x64_startup_100f1aa0_empty_fixture.json":
        "434a0665d70907f2ab69c197796349e97ea84c48583f19c17aa78a793816a5ac",
    "scripts/test_x64_startup_safe_seams_provenance.py":
        "c388c1a032ffd0f14fcea173e6f40a9980b314c3a888d28196f7a278e0039bdf",
    "scripts/test_x64_startup_100df270_platform_prefix_transcript_provenance.py":
        "4e375c2d2c83485dcdd47fdf6cf9dc17f5dd5f1c95ec593665bca878d30be3f5",
    "scripts/test_x64_startup_100df270_headless_provenance.py":
        "6d15757a584cd972a7fb7e4cd3769bd7002066d2864229dc62bc26cd636bf5a4",
    "scripts/test_x64_startup_100df270_suffix_transcript_provenance.py":
        "917c38c1ea7ec9cc41c6d3b0689fdfcc099c8c1f1b52f0d78312fb02c3e29bcc",
}

ADMITTED_PORT_HASHES = {
    "port/x64_runtime/guest32.h":
        "64c2f0f9e140e830984c2233d130b78e6595b1ea75d7e3146962b4bbf1334fed",
    "port/x64_runtime/guest32.c":
        "307c662e2a8dffa6d8f88f579858a27eef97e304c9516c97a3c5e1aa72cf22a5",
    "port/x64_ported/ported_100f1c10_triplet.h":
        "52bdb41cb89833b4797bdb8560d56de7cfe537bb4dd0a86451799ba6b69d6c5b",
    "port/x64_ported/ported_100f1c10_triplet.c":
        "6acfa0acbc1f4cce9fa7fb8ed7e6886885f3336fcac1578de21d596fe623b822",
    "port/x64_ported/ported_100f1aa0_empty.h":
        "5882c7046053f1d55c9a540293a9b090cc66e8be0acae5beb241126108e67c19",
    "port/x64_ported/ported_100f1aa0_empty.c":
        "b1bd08f7b13983ebee9fcb66ce05f508dbaf5884992a47ea9b1d3e972328e9b6",
    "port/x64_ported/ported_100f1bb0_bounded.h":
        "c79db19633151de3f3edf182589b38c53c80c34f6c48d43f763a70cabd7c0f03",
    "port/x64_ported/ported_100f1bb0_bounded.c":
        "72161bbd683cad6439b7f26eb3ab549e0df64624009f52747b5faa78f8e46b92",
    "port/x64_ported/ported_100f1cc0_nonowning.h":
        "7edc2e2964335fd74a7f73a910a52cfcd7dc12b3980930385dd4e98cf098d130",
    "port/x64_ported/ported_100f1cc0_nonowning.c":
        "b3dbabd049b920722e0d2f1680e3b48535044ba34fe23be586caa51a5a5f3bac",
    "port/x64_ported/ported_100df270_platform_prefix_transcript.h":
        "a5f5f7c37053242ee0284c6b0dd437499253a9a05a5332bae78ead9527f99de9",
    "port/x64_ported/ported_100df270_platform_prefix_transcript.c":
        "e1d51964caf7d69399548b7716e5c4cfe0c3d6b59701c01bb7f88f89555ad55a",
    "port/x64_ported/ported_100df270_headless.h":
        "399fcb84a594fca51dda9d320bffa911864b6a5e9ed9e265b32b8078932c3d74",
    "port/x64_ported/ported_100df270_headless.c":
        "90402b6f61630b84457f95b18a5fb1aade7729fff2203569e4cb9b071b563bdd",
    "port/x64_ported/ported_100df270_suffix_transcript.h":
        "c340cb925096a87be9ee0a7edba3ef86af80a669de5ed5335c39032a54d782ff",
    "port/x64_ported/ported_100df270_suffix_transcript.c":
        "ee40bb59780e2f9a5f88116472a406393017f7049766be34acb45c172bd929f1",
}


class EvidenceError(ValueError):
    """A candidate differs from the bounded authenticated evidence."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if (
        offset < 0
        or size < 0
        or offset > len(data)
        or size > len(data) - offset
    ):
        raise EvidenceError(f"{label} lies outside the {len(data)}-byte input")


def require_authority(
    data: bytes, expected_size: int, expected_sha256: str, label: str
) -> None:
    if len(data) != expected_size:
        raise EvidenceError(f"{label} size changed")
    if sha256(data) != expected_sha256:
        raise EvidenceError(f"{label} SHA-256 changed")


def parse_pe32(data: bytes) -> dict[str, object]:
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise EvidenceError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise EvidenceError("missing PE signature")

    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if not 1 <= section_count <= 96:
        raise EvidenceError("implausible PE section count")
    require_range(data, optional, optional_size, "optional header")
    if optional_size < 0xE0:
        raise EvidenceError("truncated PE32 optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    size_of_image = struct.unpack_from("<I", data, optional + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional + 60)[0]
    directory_count = struct.unpack_from("<I", data, optional + 92)[0]
    if directory_count != 16:
        raise EvidenceError("PE32 data-directory count changed")
    directories = tuple(
        struct.unpack_from("<II", data, optional + 96 + index * 8)
        for index in range(directory_count)
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
            raise EvidenceError("non-ASCII PE section name") from exc
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
        "machine": machine,
        "magic": magic,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "directories": directories,
        "sections": tuple(sections),
    }


def read_va(data: bytes, pe: dict[str, object], va: int, size: int):
    image_base = pe["image_base"]
    if not isinstance(image_base, int) or va < image_base:
        raise EvidenceError(f"VA 0x{va:08x} precedes the image base")
    rva = va - image_base
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size, _flags in pe[
        "sections"
    ]:
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise EvidenceError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    name, raw_offset = matches[0]
    require_range(data, raw_offset, size, f"VA 0x{va:08x}")
    return data[raw_offset:raw_offset + size], name, raw_offset


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 5, f"rel32 at 0x{instruction_va:08x}")
    if body[offset] != 0xE8:
        raise EvidenceError(f"0x{instruction_va:08x} is not CALL rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


def rel8_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 2, f"rel8 at 0x{instruction_va:08x}")
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return instruction_va + 2 + displacement


def scan_high_esp_disp32(body: bytes, body_va: int):
    """Conservatively scan authenticated mod=disp32/SIB=[esp] references."""
    references = []
    for modrm_index in range(1, len(body) - 5):
        modrm = body[modrm_index]
        if (modrm & 0xC7) != 0x84 or body[modrm_index + 1] != 0x24:
            continue
        displacement = struct.unpack_from("<I", body, modrm_index + 2)[0]
        if not 0x900 <= displacement <= 0x1000:
            continue
        opcode = body[modrm_index - 1]
        if opcode not in (0x8B, 0x89, 0xFF):
            raise EvidenceError(
                f"unsupported high ESP-reference opcode at "
                f"0x{body_va + modrm_index - 1:08x}"
            )
        references.append((body_va + modrm_index - 1, opcode, displacement))
    return tuple(references)


def validate_instruction_partition(candidate: bytes) -> tuple[str, ...]:
    if len(candidate) != len(PRELOOP_BYTES):
        raise EvidenceError("pre-loop boundary changed")
    cursor = 0
    labels = []
    for va, encoded_hex, label in INSTRUCTION_PARTITION:
        encoded = bytes.fromhex(encoded_hex)
        if va != PRELOOP_VA + cursor:
            raise AssertionError("internal instruction partition is not contiguous")
        if candidate[cursor:cursor + len(encoded)] != encoded:
            raise EvidenceError(f"instruction changed at 0x{va:08x}")
        cursor += len(encoded)
        labels.append(label)
    if cursor != len(candidate):
        raise EvidenceError("instruction partition does not consume the pre-loop")
    return tuple(labels)


def validate_preloop_candidate(candidate: bytes) -> tuple[str, ...]:
    validate_instruction_partition(candidate)
    require_authority(candidate, 177, PRELOOP_SHA256, "pre-loop")

    for va, address, value in GLOBAL_STORES:
        offset = va - PRELOOP_VA
        instruction = candidate[offset:offset + 7]
        if instruction[:2] != b"\xc6\x05":
            raise EvidenceError(f"global store opcode changed at 0x{va:08x}")
        if struct.unpack_from("<I", instruction, 2)[0] != address:
            raise EvidenceError(f"global identity changed at 0x{va:08x}")
        if instruction[6] != value:
            raise EvidenceError(f"global byte value changed at 0x{va:08x}")

    observed_calls = tuple(
        (va, rel32_target(candidate, PRELOOP_VA, va))
        for va, _target in DIRECT_CALLS
    )
    if observed_calls != DIRECT_CALLS or candidate.count(b"\xe8") != 7:
        raise EvidenceError("pre-loop direct-call order changed")
    for forbidden in (b"\xff\x52\x54", b"\xff\x10", b"\xff\x15", b"\xff\xd6"):
        if forbidden in candidate:
            raise EvidenceError("indirect or platform call entered the pre-loop")

    labels_by_va = {va: label for va, label in OPERATION_SITES}
    operations = tuple(labels_by_va[va] for va, _label in OPERATION_SITES)
    if operations != OPERATION_ORDER:
        raise EvidenceError("nine-operation order changed")
    return operations


def validate_excluded_candidate(candidate: bytes) -> None:
    require_authority(candidate, 223, EXCLUDED_SHA256, "excluded loop")
    if candidate[0] != 0x56:
        raise EvidenceError("excluded loop no longer begins with push esi")
    if rel32_target(candidate, EXCLUDED_VA, 0x100ED476) != 0x100EA060:
        raise EvidenceError("first excluded loop call changed")
    if candidate[0x2D:0x30] != b"\xff\x52\x54":
        raise EvidenceError("first excluded indirect seam changed")
    if candidate[0x8D:0x8F] != b"\xff\x10":
        raise EvidenceError("second excluded indirect seam changed")


def validate_parent_candidate(candidate: bytes) -> None:
    require_authority(candidate, PARENT_SIZE, PARENT_SHA256, "full parent")
    if candidate[:177] != PRELOOP_BYTES or candidate[177:] != EXCLUDED_BYTES:
        raise EvidenceError("parent partition changed")
    validate_preloop_candidate(candidate[:177])
    validate_excluded_candidate(candidate[177:])


def validate_semantic_model(candidate: dict[str, object]) -> None:
    if set(candidate) != set(SEMANTIC_MODEL):
        raise EvidenceError("bounded semantic-model keys changed")
    if candidate["frame_size"] != 0x90C:
        raise EvidenceError("parent frame size changed")
    for key, expected in SEMANTIC_MODEL.items():
        if candidate[key] != expected:
            raise EvidenceError(f"bounded semantic-model field changed: {key}")
    if (
        candidate["copy_a_receiver_sp_delta"]
        + candidate["copy_a_receiver_displacement"] != 0x3C
        or candidate["copy_a_source_sp_delta"]
        + candidate["copy_a_source_displacement"] != 0x04
        or candidate["copy_a_call_sp_delta"] != -4
    ):
        raise EvidenceError("first empty-copy transient stack model changed")
    if (
        candidate["copy_b_source_sp_delta"]
        + candidate["copy_b_source_displacement"] != 0x10
        or candidate["copy_b_receiver_sp_delta"]
        + candidate["copy_b_receiver_displacement"] != 0x48
        or candidate["copy_b_call_sp_delta"] != -4
    ):
        raise EvidenceError("second empty-copy transient stack model changed")
    if (
        candidate["packet_lea_sp_delta"]
        + candidate["packet_lea_displacement"] != 0x34
        or candidate["child_call_sp_delta"] != -8
        or candidate["child_argument_order"] != ("packet", "descriptor")
    ):
        raise EvidenceError("child packet/descriptor stack model changed")
    if candidate["descriptor_plan"] != (
        "measure_zero_100f1bb0", "initialize_triplet_100f1c10"
    ):
        raise EvidenceError("bounded descriptor plan changed")
    if candidate["packet_padding_25_27_initialized"] is not False:
        raise EvidenceError("uninitialized packet padding was fabricated")
    if candidate["frame_gap_61_63_initialized"] is not False:
        raise EvidenceError("uninitialized pre-receiver frame gap was fabricated")
    if candidate["stop_va"] != PRELOOP_END_VA:
        raise EvidenceError("pre-loop hard stop changed")


def validate_caller_packet(candidate: bytes, start_va: int) -> None:
    if len(candidate) != 13:
        raise EvidenceError("caller packet size changed")
    if (
        candidate[0:3] != bytes.fromhex("ff7524")
        or candidate[3:4] != b"\x57"
        or candidate[4:7] != bytes.fromhex("ff750c")
        or candidate[7:8] != b"\x56"
    ):
        raise EvidenceError("caller push order changed")
    if rel32_target(candidate, start_va, start_va + 8) != PARENT_VA:
        raise EvidenceError("caller no longer targets 0x100ed3c0")


def mutated(data: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(data):
        raise ValueError("mutation offset outside input")
    result = bytearray(data)
    result[offset] ^= 0x01
    return bytes(result)


class Startup100ed3c0PreloopTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        require_authority(cls.dll, DLL_SIZE, DLL_SHA256, "original DLL")
        cls.pe = parse_pe32(cls.dll)

    def test_original_pe_map_and_full_parent_are_exact(self):
        self.assertEqual(self.pe["pe_offset"], PE_OFFSET)
        self.assertEqual(self.pe["machine"], 0x014C)
        self.assertEqual(self.pe["magic"], 0x010B)
        self.assertEqual(self.pe["image_base"], IMAGE_BASE)
        self.assertEqual(self.pe["size_of_image"], SIZE_OF_IMAGE)
        self.assertEqual(self.pe["size_of_headers"], SIZE_OF_HEADERS)
        self.assertEqual(self.pe["directories"], PE_DIRECTORIES)
        self.assertEqual(self.pe["sections"], PE_SECTIONS)

        body, section, raw_offset = read_va(
            self.dll, self.pe, PARENT_VA, PARENT_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", PARENT_RAW_OFFSET))
        self.assertEqual(body, PRELOOP_BYTES + EXCLUDED_BYTES)
        validate_parent_candidate(body)
        self.assertEqual(PARENT_VA + len(body), EXCLUDED_END_VA)

    def test_exact_177_byte_instruction_partition_is_contiguous(self):
        body, section, raw_offset = read_va(
            self.dll, self.pe, PRELOOP_VA, len(PRELOOP_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", PRELOOP_RAW_OFFSET))
        self.assertEqual(body, PRELOOP_BYTES)
        self.assertEqual(len(body), PRELOOP_END_VA - PRELOOP_VA)
        self.assertEqual(sha256(body), PRELOOP_SHA256)
        labels = validate_instruction_partition(body)
        self.assertEqual(len(labels), 40)
        self.assertEqual(
            sum(len(bytes.fromhex(encoded)) for _va, encoded, _label in
                INSTRUCTION_PARTITION),
            177,
        )

    def test_two_globals_and_seven_calls_form_exact_nine_operation_order(self):
        self.assertEqual(validate_preloop_candidate(PRELOOP_BYTES), OPERATION_ORDER)
        self.assertEqual(GLOBAL_STORES, (
            (0x100ED3CA, 0x119F31C8, 1),
            (0x100ED3D1, 0x119F31C5, 1),
        ))
        self.assertEqual(DIRECT_CALLS, (
            (0x100ED3DF, 0x100F1C10),
            (0x100ED3E8, 0x100F1C10),
            (0x100ED419, 0x100F1AA0),
            (0x100ED427, 0x100F1AA0),
            (0x100ED454, 0x100F1BB0),
            (0x100ED463, 0x100DF270),
            (0x100ED46C, 0x100F1CC0),
        ))

    def test_stack_and_argument_identities_are_exact(self):
        validate_semantic_model(dict(SEMANTIC_MODEL))
        self.assertEqual(PRELOOP_BYTES[:6], bytes.fromhex("81ec0c090000"))
        self.assertEqual(FRAME_SIZE, 0x90C)
        self.assertEqual(
            STACK_LAYOUT["triplet_a"] + TRIPLET_BYTES,
            STACK_LAYOUT["triplet_b"],
        )
        self.assertEqual(
            STACK_LAYOUT["descriptor"] + DESCRIPTOR_BYTES,
            STACK_LAYOUT["packet"],
        )
        self.assertEqual(
            STACK_LAYOUT["child_receiver"] + CHILD_RECEIVER_BYTES,
            FRAME_SIZE,
        )
        self.assertEqual(
            STACK_LAYOUT["empty_copy_a"] - STACK_LAYOUT["packet"], 0x08
        )
        self.assertEqual(
            STACK_LAYOUT["empty_copy_b"] - STACK_LAYOUT["packet"], 0x14
        )
        self.assertEqual(
            STACK_LAYOUT["packet"] + PACKET_BYTES,
            STACK_LAYOUT["child_receiver"] - 3,
        )
        # Packet bytes +0x25..+0x27 are internal padding, followed by the
        # initialized +0x28..+0x2c tail.  The packet ends at S+0x61; the
        # distinct frame bytes S+0x61..S+0x63 are the external gap before the
        # aligned receiver at S+0x64.  Neither three-byte interval is written.
        initialized_packet_ranges = (
            (0x00, 0x08),
            (0x08, 0x14),
            (0x14, 0x20),
            (0x20, 0x25),
            (0x28, 0x2D),
        )
        self.assertEqual(initialized_packet_ranges[3][1], 0x25)
        self.assertEqual(initialized_packet_ranges[4][0], 0x28)
        self.assertEqual(PACKET_BYTES, 0x2D)

        # S = E0 - 0x90c.  These are raw stack identities, not a native ABI.
        self.assertEqual(
            PRELOOP_BYTES[0x2D:0x34], bytes.fromhex("8b842410090000")
        )
        self.assertEqual(-FRAME_SIZE + 0x910, 4)  # entry position 1
        self.assertEqual(
            PRELOOP_BYTES[0x74:0x7B], bytes.fromhex("ffb42418090000")
        )
        self.assertEqual(-FRAME_SIZE + 0x918, 12)  # entry position 3

        # Both empty-copy sources are the immediately preceding triplets.
        # The first receiver is formed before its source push; the second is
        # formed after its source push, so (S-4)+0x4c is S+0x48.
        self.assertEqual(
            PRELOOP_BYTES[0x34:0x5E],
            bytes.fromhex(
                "8d4c243c8944241c894424348b0424894424388d44240450"
                "c644242400c744242800000000e882460000"
            ),
        )
        self.assertEqual(
            PRELOOP_BYTES[0x5E:0x6C],
            bytes.fromhex("8d442410508d4c244ce874460000"),
        )
        self.assertEqual(0 + 0x3C, STACK_LAYOUT["empty_copy_a"])
        self.assertEqual(0 + 0x04, STACK_LAYOUT["triplet_a"])
        self.assertEqual(0 + 0x10, STACK_LAYOUT["triplet_b"])
        self.assertEqual(-4 + 0x4C, STACK_LAYOUT["empty_copy_b"])

        # 0x100f1bb0 sees ECX=S+0x28 and entry position 3 (E0+0xc).
        self.assertEqual(
            PRELOOP_BYTES[0x70:0x7B], bytes.fromhex("8d4c2428ffb42418090000")
        )

        # The child sees ECX=S+0x64, stack position 1=S+0x34 (packet), and
        # stack position 2=S+0x28 (descriptor).  Its ret 8 restores ESP to S.
        self.assertEqual(
            PRELOOP_BYTES[0x99:0xA8],
            bytes.fromhex("508d442438508d4c246ce8081effff"),
        )
        self.assertEqual(-8 + 0x6C, STACK_LAYOUT["child_receiver"])
        self.assertEqual(-4 + 0x38, STACK_LAYOUT["packet"])
        # The descriptor was pushed first at S-4, then the packet at S-8.
        # The original child ret 8 restores S before cleanup receives S+0x28.
        self.assertEqual(
            PRELOOP_BYTES[0xA8:0xB1], bytes.fromhex("8d4c2428e84f480000")
        )

    def test_triplet_and_empty_copy_callee_semantics_are_pinned(self):
        triplet = CALLEE_BYTES[0x100F1C10]
        self.assertEqual(
            triplet,
            bytes.fromhex("c701000000008bc1c7410400000000c741089040af11c3"),
        )
        self.assertEqual(struct.unpack_from("<I", triplet, 2)[0], 0)
        self.assertEqual(struct.unpack_from("<I", triplet, 11)[0], 0)
        self.assertEqual(struct.unpack_from("<I", triplet, 18)[0], 0x11AF4090)
        self.assertEqual(triplet[6:8], b"\x8b\xc1")
        self.assertEqual(triplet[-1:], b"\xc3")

        wrapper = CALLEE_BYTES[0x100F1AA0]
        self.assertEqual(wrapper[8:15], bytes.fromhex("8b1089178b7008"))
        self.assertEqual(rel32_target(wrapper, 0x100F1AA0, 0x100F1AB4), 0x100EF330)
        self.assertEqual(wrapper[-3:], bytes.fromhex("c20400"))

        helper = CALLEE_BYTES[0x100EF330]
        empty_prefix = bytes.fromhex(
            "578bf98b0789470485c0750bc747089040af115fc20800"
        )
        self.assertEqual(helper[:23], empty_prefix)
        self.assertEqual(
            sha256(empty_prefix),
            "4453992ce0b1a2df255117ba5d3a67c837b9f9b582dbc178fd42d5cd65533db2",
        )
        self.assertEqual(rel8_target(helper, 0x100EF330, 0x100EF33A), 0x100EF347)
        self.assertEqual(rel32_target(helper, 0x100EF330, 0x100EF354), 0x100FCC80)

    def test_original_100f1bb0_and_bounded_descriptor_stop_are_pinned(self):
        body = CALLEE_BYTES[0x100F1BB0]
        scan = body[0x10:0x22]
        self.assertEqual(
            scan, bytes.fromhex("0fb71083c0026685d275f52bc683e802d1f8")
        )
        self.assertEqual(rel8_target(body, 0x100F1BB0, 0x100F1BC9), 0x100F1BC0)
        self.assertEqual(rel32_target(body, 0x100F1BB0, 0x100F1BD9), 0x100EF330)
        self.assertEqual(body[8:10], bytes.fromhex("8bf9"))  # EDI = ECX receiver
        self.assertEqual(body[-7:], bytes.fromhex("8bc75f5ec20400"))
        self.assertEqual(body[-3:], bytes.fromhex("c20400"))

        header = (
            ROOT / "port/x64_ported/ported_100f1bb0_bounded.h"
        ).read_text(encoding="utf-8")
        self.assertIn("ROME2_PORT_100F1BB0_MAX_UNITS UINT32_C(32768)", header)
        self.assertIn("0x100f1bc0-0x100f1bd1", header)
        self.assertIn("allocator-capable copy beginning at 0x100f1bd2", header)
        self.assertIn("is not called or modeled", header)

        # The admitted measure port cannot construct frame+0x28.  A bounded
        # nonowning parent composition must require a measured length of zero
        # and use the separately admitted triplet writer to create exactly
        # {0, 0, 0x11af4090}; nonempty original allocation remains excluded.
        self.assertEqual(TRIPLET_BYTES, DESCRIPTOR_BYTES)
        self.assertEqual(
            bytes.fromhex("00000000000000009040af11"),
            struct.pack("<III", 0, 0, 0x11AF4090),
        )

    def test_child_boundary_and_three_admitted_intervals_are_exact(self):
        child, section, raw_offset = read_va(
            self.dll, self.pe, 0x100DF270, 640
        )
        size, expected_raw, expected_hash = CALLEE_AUTHORITIES[0x100DF270]
        self.assertEqual((len(child), section, raw_offset), (size, ".text", expected_raw))
        self.assertEqual(sha256(child), expected_hash)
        self.assertEqual(child[-3:], bytes.fromhex("c20800"))
        # Child prologue saves four registers around its 0x400-byte frame.
        # With ESP=child-entry-0x408 at the load, +0x40c is position 1.
        self.assertEqual(
            child[:28],
            bytes.fromhex(
                "81ec0004000053558bac240c040000568b356cf67211578b55008bf9"
            ),
        )
        self.assertEqual(-0x408 + 0x40C, 4)
        self.assertEqual(child[0x1FD:0x204], bytes.fromhex("ffb42418040000"))
        self.assertEqual(-0x410 + 0x418, 8)

        cursor = 0x100DF270
        for va, interval_size, interval_raw, interval_hash in CHILD_INTERVALS:
            self.assertEqual(va, cursor)
            interval, section, raw_offset = read_va(
                self.dll, self.pe, va, interval_size
            )
            self.assertEqual((section, raw_offset), (".text", interval_raw))
            self.assertEqual(sha256(interval), interval_hash)
            self.assertEqual(interval, child[va - 0x100DF270:va - 0x100DF270 + interval_size])
            cursor += interval_size
        self.assertEqual(cursor, 0x100DF4F0)

        # The original child contains platform/indirect effects.  Only the
        # separately pinned injected/deterministic ports are admitted.
        self.assertIn(bytes.fromhex("ff157cf17211"), child[:211])
        self.assertIn(bytes.fromhex("ffd6"), child[:211])
        self.assertEqual(
            rel32_target(PRELOOP_BYTES, PRELOOP_VA, 0x100ED463), 0x100DF270
        )
        admitted_sources = b"".join(
            (ROOT / relative).read_bytes()
            for relative in (
                "port/x64_ported/ported_100df270_platform_prefix_transcript.c",
                "port/x64_ported/ported_100df270_headless.c",
                "port/x64_ported/ported_100df270_suffix_transcript.c",
            )
        )
        for forbidden in (
            b"LoadStringW", b"CreateMutexW", b"GetLastError", b"MessageBoxW",
            b"SystemParametersInfoW", b"TerminateProcess", b"GetCurrentProcess",
        ):
            self.assertNotIn(forbidden, admitted_sources)

    def test_nonowning_cleanup_and_owning_stop_line_are_exact(self):
        body = CALLEE_BYTES[0x100F1CC0]
        prefix = bytes.fromhex("568b710881fe9040af11742585f67421")
        self.assertEqual(body[:16], prefix)
        self.assertEqual(
            sha256(prefix),
            "520e0b8dca85eb186a400c043dcd137c68bbb3da2d1f6990ab2e86590caa9172",
        )
        self.assertEqual(rel8_target(body, 0x100F1CC0, 0x100F1CCA), 0x100F1CF1)
        self.assertEqual(rel8_target(body, 0x100F1CC0, 0x100F1CCE), 0x100F1CF1)
        self.assertEqual(rel32_target(body, 0x100F1CC0, 0x100F1CD8), 0x10124E50)
        self.assertEqual(body[0x2C:0x2E], b"\xff\xd0")
        self.assertEqual(body[-2:], b"\x5e\xc3")

        header = (
            ROOT / "port/x64_ported/ported_100f1cc0_nonowning.h"
        ).read_text(encoding="utf-8")
        self.assertIn("ROME2_PORT_100F1CC0_SENTINEL UINT32_C(0x11af4090)", header)
        self.assertIn("Null and the fixed guest sentinel return OK", header)
        self.assertIn("Every other value belongs to the excluded owning/callback path", header)

    def test_all_direct_callee_bodies_are_mapped_and_hash_pinned(self):
        for va, (size, expected_raw, expected_hash) in CALLEE_AUTHORITIES.items():
            body, section, raw_offset = read_va(self.dll, self.pe, va, size)
            self.assertEqual((section, raw_offset), (".text", expected_raw))
            self.assertEqual(sha256(body), expected_hash)
            if va in CALLEE_BYTES:
                self.assertEqual(body, CALLEE_BYTES[va])

    def test_excluded_loop_and_indirect_seams_are_a_hard_stop(self):
        tail, section, raw_offset = read_va(
            self.dll, self.pe, EXCLUDED_VA, len(EXCLUDED_BYTES)
        )
        self.assertEqual((section, raw_offset), (".text", EXCLUDED_RAW_OFFSET))
        self.assertEqual(tail, EXCLUDED_BYTES)
        validate_excluded_candidate(tail)
        self.assertEqual(EXCLUDED_END_VA - EXCLUDED_VA, 223)
        self.assertEqual(PRELOOP_END_VA, EXCLUDED_VA)
        self.assertNotIn(bytes.fromhex("ff5254"), PRELOOP_BYTES)
        self.assertNotIn(bytes.fromhex("ff10"), PRELOOP_BYTES)
        self.assertEqual(tail[0x2D:0x30], bytes.fromhex("ff5254"))
        self.assertEqual(tail[0x8D:0x8F], bytes.fromhex("ff10"))

    def test_both_original_callers_and_raw_abi_facts_are_exact(self):
        for va, expected_raw, expected in CALLER_SOURCE_LOADS:
            actual, section, raw_offset = read_va(
                self.dll, self.pe, va, len(expected)
            )
            self.assertEqual((section, raw_offset), (".text", expected_raw))
            self.assertEqual(actual, expected)

        for _branch, start, expected_raw, packet, window, window_hash in CALLER_PACKETS:
            actual, section, raw_offset = read_va(
                self.dll, self.pe, start, len(window)
            )
            self.assertEqual((section, raw_offset), (".text", expected_raw))
            self.assertEqual(actual, window)
            self.assertEqual(sha256(actual), window_hash)
            self.assertEqual(actual[:13], packet)
            validate_caller_packet(packet, start)
            self.assertEqual(actual[-3:], bytes.fromhex("83c418"))
            self.assertEqual(actual[13:15], bytes.fromhex("6a01"))
            self.assertEqual(actual[20:25], bytes.fromhex("6860650d10"))
            self.assertEqual(rel32_target(actual, start, start + 15), 0x101136D0)
            self.assertEqual(rel32_target(actual, start, start + 25), 0x101150F0)
            # Six pushed dwords are grouped: four for 0x100ed3c0 and one for
            # each later call.  The original parent has a bare ret, so the
            # caller removes all 24 bytes here.
            self.assertEqual(struct.unpack_from("<b", actual, 32)[0], 0x18)
            self.assertEqual(16 + 4 + 4, 0x18)

        # Machine push order is [ebp+0x24], edi, [ebp+0x0c], esi.  Callee
        # positions are the reverse: esi is position 1 and edi is position 3.
        self.assertEqual(CALLER_PACKETS[0][3][:8], bytes.fromhex("ff752457ff750c56"))
        self.assertEqual(CALLER_PACKETS[1][3][:8], bytes.fromhex("ff752457ff750c56"))
        self.assertEqual(CALLER_SOURCE_LOADS[1][2], bytes.fromhex("8b7508"))
        self.assertEqual(CALLER_SOURCE_LOADS[2][2], bytes.fromhex("8b7d10"))

        parent = PRELOOP_BYTES + EXCLUDED_BYTES
        high_references = scan_high_esp_disp32(parent, PARENT_VA)
        self.assertEqual(high_references, (
            (0x100ED3ED, 0x8B, 0x910),
            (0x100ED434, 0xFF, 0x918),
            (0x100ED4B0, 0x89, 0x908),
            (0x100ED4BA, 0x89, 0x90C),
        ))
        normalized = (
            -0x90C + 0x910,
            -0x90C + 0x918,
            -0x910 + 0x908,
            -0x910 + 0x90C,
        )
        self.assertEqual(normalized, (4, 12, -8, -4))
        # No position-2/4 read appears in this deliberately conservative
        # high-ESP disp32 decoder; this does not claim general x86 coverage.
        self.assertNotIn(8, normalized)
        self.assertNotIn(16, normalized)

    def test_canonical_sources_index_and_cross_checks_are_exact(self):
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
            source = CANONICAL / f"decomp_fn_{entry}.c"
            self.assertEqual(sha256(source.read_bytes()), CANONICAL_HASHES[entry])

        parent = (CANONICAL / "decomp_fn_100ed3c0.c").read_text(encoding="utf-8")
        ordered = (
            "DAT_119f31c8 = 1;",
            "DAT_119f31c5 = 1;",
            "decomp_fn_100f1c10(0);",
            "decomp_fn_100f1c10();",
            "decomp_fn_100f1aa0(local_908);",
            "decomp_fn_100f1aa0(local_8fc);",
            "uVar5 = decomp_fn_100f1bb0(param_3);",
            "decomp_fn_100df270(&local_8d8,uVar5);",
            "decomp_fn_100f1cc0();",
            "do {",
        )
        positions = [parent.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))

        caller = (CANONICAL / "decomp_fn_100edd70.c").read_text(encoding="utf-8")
        self.assertEqual(
            caller.count("decomp_fn_100ed3c0(param_1,param_2,param_3,param_8);"),
            2,
        )

    def test_reference_authorities_and_existing_admitted_ports_are_exact(self):
        for relative, expected_hash in {
            **REFERENCE_HASHES, **ADMITTED_PORT_HASHES
        }.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(sha256(data), expected_hash, relative)

        semantic_tokens = {
            "port/x64_ported/ported_100f1c10_triplet.h":
                "rome2_port_100f1c10_initialize_triplet",
            "port/x64_ported/ported_100f1aa0_empty.h":
                "rome2_port_100f1aa0_copy_empty_source",
            "port/x64_ported/ported_100f1bb0_bounded.h":
                "rome2_port_100f1bb0_measure_utf16",
            "port/x64_ported/ported_100f1cc0_nonowning.h":
                "rome2_port_100f1cc0_accept_nonowning_noop",
            "port/x64_ported/ported_100df270_platform_prefix_transcript.h":
                "rome2_port_100df270_run_platform_prefix_transcript",
            "port/x64_ported/ported_100df270_headless.h":
                "rome2_port_100df270_project_headless_empty_state",
            "port/x64_ported/ported_100df270_suffix_transcript.h":
                "rome2_port_100df270_run_suffix_transcript",
        }
        for relative, token in semantic_tokens.items():
            self.assertIn(token, (ROOT / relative).read_text(encoding="utf-8"))

    def test_reciprocal_preloop_boundary_instruction_and_order_mutants_fail(self):
        with self.assertRaises(EvidenceError):
            validate_preloop_candidate(PRELOOP_BYTES[:-1])
        with self.assertRaises(EvidenceError):
            validate_preloop_candidate(PRELOOP_BYTES + EXCLUDED_BYTES[:1])

        for va, encoded, _label in INSTRUCTION_PARTITION:
            offset = va - PRELOOP_VA
            self.assertGreater(len(bytes.fromhex(encoded)), 0)
            with self.assertRaises(EvidenceError, msg=f"0x{va:08x}"):
                validate_preloop_candidate(mutated(PRELOOP_BYTES, offset))

        for call_va, _target in DIRECT_CALLS:
            with self.assertRaises(EvidenceError, msg=f"rel32 0x{call_va:08x}"):
                validate_preloop_candidate(
                    mutated(PRELOOP_BYTES, call_va - PRELOOP_VA + 1)
                )
        for store_va, _address, _value in GLOBAL_STORES:
            for relative in (2, 6):
                with self.assertRaises(EvidenceError):
                    validate_preloop_candidate(
                        mutated(PRELOOP_BYTES, store_va - PRELOOP_VA + relative)
                    )

    def test_reciprocal_parent_tail_caller_callee_and_reference_mutants_fail(self):
        full = PRELOOP_BYTES + EXCLUDED_BYTES
        for offset in (0, 176, 177, 177 + 0x2D, 177 + 0x8D, 399):
            with self.assertRaises(EvidenceError):
                validate_parent_candidate(mutated(full, offset))

        for _branch, start, _raw, packet, _window, _hash in CALLER_PACKETS:
            for offset in (0, 3, 4, 7, 9):
                with self.assertRaises(EvidenceError):
                    validate_caller_packet(mutated(packet, offset), start)

        for va, (size, _raw, expected_hash) in CALLEE_AUTHORITIES.items():
            body, _section, _offset = read_va(self.dll, self.pe, va, size)
            with self.assertRaises(EvidenceError):
                require_authority(mutated(body, len(body) // 2), size, expected_hash,
                                  f"callee 0x{va:08x}")

        for relative, expected_hash in {
            **REFERENCE_HASHES, **ADMITTED_PORT_HASHES
        }.items():
            reference = (ROOT / relative).read_bytes()
            with self.assertRaises(EvidenceError, msg=relative):
                require_authority(
                    mutated(reference, len(reference) // 2),
                    len(reference),
                    expected_hash,
                    relative,
                )

    def test_reciprocal_semantic_model_mutants_fail(self):
        mutants = []
        for key, value in (
            ("copy_a_call_sp_delta", 0),
            ("copy_b_receiver_sp_delta", 0),
            ("packet_lea_sp_delta", -8),
            ("child_argument_order", ("descriptor", "packet")),
            ("descriptor_plan", ("measure_zero_100f1bb0",)),
            ("packet_padding_25_27_initialized", True),
            ("frame_gap_61_63_initialized", True),
            ("stop_va", 0x100ED472),
        ):
            mutant = dict(SEMANTIC_MODEL)
            mutant[key] = value
            mutants.append((key, mutant))
        for label, mutant in mutants:
            with self.assertRaises(EvidenceError, msg=label):
                validate_semantic_model(mutant)

        compensating_pairs = (
            ("packet_lea_sp_delta", -8, "packet_lea_displacement", 0x3C),
            ("copy_b_receiver_sp_delta", 0,
             "copy_b_receiver_displacement", 0x48),
            ("copy_a_receiver_sp_delta", -4,
             "copy_a_receiver_displacement", 0x40),
        )
        for first, first_value, second, second_value in compensating_pairs:
            mutant = dict(SEMANTIC_MODEL)
            mutant[first] = first_value
            mutant[second] = second_value
            with self.assertRaises(EvidenceError, msg=f"{first}+{second}"):
                validate_semantic_model(mutant)

    def test_oracle_uses_only_standard_library_and_has_no_write_calls(self):
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imports = set()
        forbidden_calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module is not None:
                    imports.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {
                    "write_bytes", "write_text", "unlink", "rename", "replace",
                    "mkdir", "rmdir", "touch",
                }:
                    forbidden_calls.add(node.func.attr)
        self.assertEqual(imports, {
            "__future__", "ast", "csv", "hashlib", "struct", "unittest",
            "pathlib",
        })
        self.assertEqual(forbidden_calls, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
