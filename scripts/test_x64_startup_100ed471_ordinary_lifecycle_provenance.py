#!/usr/bin/env python3
"""Authenticate the ordinary-domain lifecycle tail of x86 0x100ed3c0.

The original image is parsed only as bytes.  Nothing recovered from the PE is
loaded or executed.  The complete interval [0x100ed471,0x100ed550) is evidence;
an eventual native adapter may admit only its finite injected {0,2} projection.
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
CANONICAL_INDEX = (
    ROOT / "src_canonical_out" / "empire.retail.dll" /
    "canonical_function_index.tsv"
)
FUNCTION_INDEX = ROOT / "src_out" / "empire.retail.dll" / "function_index.txt"
SYMBOL_MAP = ROOT / "src_out" / "empire.retail.dll" / "symbol_map.txt"
RETURN_DOMAIN_ORACLE = ROOT / "scripts" / "test_x64_startup_100ec5c0_return_domain.py"
DOC = ROOT / "docs" / "x64_startup_100ed471_ordinary_lifecycle.md"

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
IMAGE_BASE = 0x10000000
TEXT_SECTION = (
    ".text", 0x00001000, 0x0172D4EA, 0x00000400, 0x0172D600,
    0x60000020,
)

PARENT_VA = 0x100ED3C0
PARENT_SIZE = 400
PARENT_RAW = 0x000EC7C0
PARENT_SHA256 = "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"
PRELOOP_SIZE = 177
PRELOOP_SHA256 = "b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626"

SLICE_VA = 0x100ED471
SLICE_END_VA = 0x100ED550
SLICE_RAW = 0x000EC871
SLICE_BYTES = bytes.fromhex(
    "568d4c2468e8e5cbffff6a006a006884007411e867f61e016a00e8d090feff"
    "83c410e888681f016a008bc88b10ff52548d44242c50e805571f0183c404"
    "8b08898c24080900008b40048984240c0900008d4c2468e8f6f0ffff"
    "83f802744c83f80175ed8b9424d80800008b8424d40800008d34823bf27422"
    "0f1f80000000008b4efc83c6fc85c9740d8b016a01ff10"
    "8b9424d80800003bf275e5c78424d408000000000000e957ffffff"
    "8d4c2468e82c31ffff8d4c244ce8934700008d4c2440e88a470000"
    "8d4c2414e8814700008d4c2408e8784700005e81c40c090000c3"
)
SLICE_SHA256 = "0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9"

# These four ranges are a contiguous, exact partition of the whole slice.
SPLITS = (
    (
        "iteration_setup_and_timestamp", 0x100ED471, 0x100ED4C1,
        0x000EC871,
        "ede782ca57dcfe346d62243bf817ab481b5a3dfa86adb168ac9c8b207e363733",
    ),
    (
        "poll_decision", 0x100ED4C1, 0x100ED4D4, 0x000EC8C1,
        "cbec5f0803aee5e4667fae58f23b30896440fae3bfbf06ad4fa97b359032c7bd",
    ),
    (
        "result_one_list_path", 0x100ED4D4, 0x100ED51B, 0x000EC8D4,
        "f325609f08094ee3703cf520a594fc4e821a5c00f462931d2997005f3a129019",
    ),
    (
        "terminal_cleanup", 0x100ED51B, 0x100ED550, 0x000EC91B,
        "218a4f1c55b348abc89d0a63b62c6fbacfd33c825a88c2073efd1976ecce6501",
    ),
)

# Fixed, standard-library-only instruction authority.  It is intentionally
# not a general decoder; every boundary and every byte is authenticated.
INSTRUCTION_PARTITION = (
    (0x100ED471, "56"),
    (0x100ED472, "8d4c2468"),
    (0x100ED476, "e8e5cbffff"),
    (0x100ED47B, "6a00"),
    (0x100ED47D, "6a00"),
    (0x100ED47F, "6884007411"),
    (0x100ED484, "e867f61e01"),
    (0x100ED489, "6a00"),
    (0x100ED48B, "e8d090feff"),
    (0x100ED490, "83c410"),
    (0x100ED493, "e888681f01"),
    (0x100ED498, "6a00"),
    (0x100ED49A, "8bc8"),
    (0x100ED49C, "8b10"),
    (0x100ED49E, "ff5254"),
    (0x100ED4A1, "8d44242c"),
    (0x100ED4A5, "50"),
    (0x100ED4A6, "e805571f01"),
    (0x100ED4AB, "83c404"),
    (0x100ED4AE, "8b08"),
    (0x100ED4B0, "898c2408090000"),
    (0x100ED4B7, "8b4004"),
    (0x100ED4BA, "8984240c090000"),
    (0x100ED4C1, "8d4c2468"),
    (0x100ED4C5, "e8f6f0ffff"),
    (0x100ED4CA, "83f802"),
    (0x100ED4CD, "744c"),
    (0x100ED4CF, "83f801"),
    (0x100ED4D2, "75ed"),
    (0x100ED4D4, "8b9424d8080000"),
    (0x100ED4DB, "8b8424d4080000"),
    (0x100ED4E2, "8d3482"),
    (0x100ED4E5, "3bf2"),
    (0x100ED4E7, "7422"),
    (0x100ED4E9, "0f1f8000000000"),
    (0x100ED4F0, "8b4efc"),
    (0x100ED4F3, "83c6fc"),
    (0x100ED4F6, "85c9"),
    (0x100ED4F8, "740d"),
    (0x100ED4FA, "8b01"),
    (0x100ED4FC, "6a01"),
    (0x100ED4FE, "ff10"),
    (0x100ED500, "8b9424d8080000"),
    (0x100ED507, "3bf2"),
    (0x100ED509, "75e5"),
    (0x100ED50B, "c78424d408000000000000"),
    (0x100ED516, "e957ffffff"),
    (0x100ED51B, "8d4c2468"),
    (0x100ED51F, "e82c31ffff"),
    (0x100ED524, "8d4c244c"),
    (0x100ED528, "e893470000"),
    (0x100ED52D, "8d4c2440"),
    (0x100ED531, "e88a470000"),
    (0x100ED536, "8d4c2414"),
    (0x100ED53A, "e881470000"),
    (0x100ED53F, "8d4c2408"),
    (0x100ED543, "e878470000"),
    (0x100ED548, "5e"),
    (0x100ED549, "81c40c090000"),
    (0x100ED54F, "c3"),
)

DIRECT_CALLS = (
    (0x100ED476, 0x100EA060),
    (0x100ED484, 0x112DCAF0),
    (0x100ED48B, 0x100D6560),
    (0x100ED493, 0x112E3D20),
    (0x100ED4A6, 0x112E2BB0),
    (0x100ED4C5, 0x100EC5C0),
    (0x100ED51F, 0x100E0650),
    (0x100ED528, 0x100F1CC0),
    (0x100ED531, 0x100F1CC0),
    (0x100ED53A, 0x100F1CC0),
    (0x100ED543, 0x100F1CC0),
)
INDIRECT_CALLS = (
    (0x100ED49E, bytes.fromhex("ff5254"), "returned_object_vtable_plus_0x54"),
    (0x100ED4FE, bytes.fromhex("ff10"), "result_one_list_element_vtable_slot_0"),
)

# Half-open blocks and their exact intraprocedural edges.  RETURN is a model
# sentinel, not an original address.
BASIC_BLOCKS = (
    (0x100ED471, 0x100ED472),
    (0x100ED472, 0x100ED4C1),
    (0x100ED4C1, 0x100ED4CF),
    (0x100ED4CF, 0x100ED4D4),
    (0x100ED4D4, 0x100ED4E9),
    (0x100ED4E9, 0x100ED4F0),
    (0x100ED4F0, 0x100ED4FA),
    (0x100ED4FA, 0x100ED507),
    (0x100ED507, 0x100ED50B),
    (0x100ED50B, 0x100ED51B),
    (0x100ED51B, 0x100ED550),
)
CFG_EDGES = (
    (0x100ED471, 0x100ED472, "fallthrough_after_single_saved_esi"),
    (0x100ED472, 0x100ED4C1, "fallthrough_to_poll"),
    (0x100ED4C1, 0x100ED51B, "poll_result_eq_2"),
    (0x100ED4C1, 0x100ED4CF, "poll_result_ne_2"),
    (0x100ED4CF, 0x100ED4C1, "poll_result_ne_1"),
    (0x100ED4CF, 0x100ED4D4, "poll_result_eq_1"),
    (0x100ED4D4, 0x100ED50B, "list_empty"),
    (0x100ED4D4, 0x100ED4E9, "list_nonempty"),
    (0x100ED4E9, 0x100ED4F0, "alignment_nop_fallthrough"),
    (0x100ED4F0, 0x100ED507, "list_element_null"),
    (0x100ED4F0, 0x100ED4FA, "list_element_nonnull"),
    (0x100ED4FA, 0x100ED507, "after_second_indirect"),
    (0x100ED507, 0x100ED4F0, "more_list_elements"),
    (0x100ED507, 0x100ED50B, "list_complete"),
    (0x100ED50B, 0x100ED472, "outer_iteration_backedge"),
    (0x100ED51B, "RETURN", "terminal_epilogue"),
)

FRAME_SIZE = 0x90C
STACK_MODEL = {
    "frame_base_esp_before_saved_esi": 0,
    "saved_esi_delta": -4,
    "receiver": 0x64,
    "timestamp_destination": 0x28,
    "timestamp_low_copy": 0x904,
    "timestamp_high_copy": 0x908,
    "result_one_list_count": 0x8D0,
    "result_one_list_base": 0x8D4,
    "cleanup_empty_copy_b": 0x48,
    "cleanup_empty_copy_a": 0x3C,
    "cleanup_triplet_b": 0x10,
    "cleanup_triplet_a": 0x04,
}
DIRECT_FRAME_WRITES = (
    (0x100ED4B0, 0x904, 4, "timestamp_low32"),
    (0x100ED4BA, 0x908, 4, "timestamp_high32"),
    (0x100ED50B, 0x8D0, 4, "result_one_only_zero_list_count"),
)
TERMINAL_CALL_ORDER = (
    (0x100ED51F, 0x100E0650, 0x64, "injected_terminal_teardown"),
    (0x100ED528, 0x100F1CC0, 0x48, "nonowning_empty_copy_b"),
    (0x100ED531, 0x100F1CC0, 0x3C, "nonowning_empty_copy_a"),
    (0x100ED53A, 0x100F1CC0, 0x10, "nonowning_triplet_b"),
    (0x100ED543, 0x100F1CC0, 0x04, "nonowning_triplet_a"),
)

DIRECT_TARGETS = {
    0x100EA060: (1123, 0x000E9460,
        "09c1cb2cf6a17887ac501d99bb482559cd79fd0188d3ac56de5453215fbf8f14"),
    0x112DCAF0: (996, 0x012DBEF0,
        "fcc0457ae9b69c4650b0cf307fee4129dd85f4882fb0e682a39858d9f88c9236"),
    0x100D6560: (1, 0x000D5960,
        "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e"),
    0x112E3D20: (139, 0x012E3120,
        "47ee84ed9073033bd595df3d6186df213ea51c1a9797f17a0508f478a590170c"),
    0x112E2BB0: (63, 0x012E1FB0,
        "251d40e34693d3e194186dfaea41282bf6e45abea9a679e5f78ec69f91b32dec"),
    0x100EC5C0: (1199, 0x000EB9C0,
        "bf1adcefe07251e80f2711a590dcc479071d845c00535ec57d5b0f7385e25e5e"),
    0x100E0650: (321, 0x000DFA50,
        "cc37f82a63911607181fa5157ee7f6b47dc8a8701c8c3bc7d19d6033a1b91c61"),
    0x100F1CC0: (51, 0x000F10C0,
        "bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4"),
}

LOG_LITERAL_VA = 0x11740084
LOG_LITERAL = b"Init completed\0"
LOG_LITERAL_SHA256 = "a09df435896c179127f7ca2551350dda3a4d0fbf17fec712e9ca1ff89a9a38a4"

GETTER_VA = 0x112E3D20
GETTER_BYTES_SHA256 = DIRECT_TARGETS[GETTER_VA][2]
CONSTRUCTOR_VA = 0x112A8FF0
CONSTRUCTOR_SIZE = 943
CONSTRUCTOR_RAW = 0x012A83F0
CONSTRUCTOR_SHA256 = "fe6d2f67d94c1cfb0949d245e1c03ee2378e556c18f868c181358e5b177b5df9"
CONSTRUCTOR_PREFIX = bytes.fromhex(
    "83ec105356578bf933db895c240c8d470cc70770788911"
)
CONSTRUCTOR_PREFIX_SHA256 = "7e6b4321335126c94515b46f2813fe2997e4e35d6200b35b1c0f94ef646dbe82"

STATIC_OBJECT_VA = 0x119E1004
STATIC_VTABLE_VA = 0x1189791C
DYNAMIC_VTABLE_VA = 0x11897870
VTABLE_WINDOW_SIZE = 0x58
STATIC_VTABLE_SHA256 = "afe0c9582963849f00439331f8ccad704a536fd9bca33512d5816a5a65a9fc8a"
DYNAMIC_VTABLE_SHA256 = "2771334cfd8bbe08bfced4735bbdae93c22cb5e8835a925d25282c6fb6699a99"
OBSERVED_SLOT54_CANDIDATES = (
    ("canonical_static_object", STATIC_VTABLE_VA, 0x100F3D00),
    ("constructor_written_dynamic_vtable", DYNAMIC_VTABLE_VA, 0x112E2CD0),
)
STATIC_CANDIDATE_BYTES = bytes.fromhex("c20400")
DYNAMIC_CANDIDATE_BYTES = bytes.fromhex("8a442404a28a1a0312c20400")

RETURN_FUNCTION_VA = 0x100EC5C0
RETURN_FUNCTION_SIZE = 1199
RETURN_FUNCTION_SHA256 = DIRECT_TARGETS[RETURN_FUNCTION_VA][2]
RETURN2_VA = 0x100EC68D
RETURN2_BYTES = bytes.fromhex("5f5e5db8020000005b81c4c4000000c3")
RETURN2_SHA256 = "6bafa6d887a759d262d93e0a373dcbb4d301346e8be85f55621b8a97e667606f"
FINAL_RETURN_VA = 0x100ECA35
FINAL_RETURN_BYTES = bytes.fromhex(
    "e8e6341d010fb6c05ff7d85e1bc05d83e0025b81c4c4000000c3"
)
FINAL_RETURN_SHA256 = "ed1c1041ab6570ae5cc61e6cedc8c4518eac6a49ccbba47d9e9f0b0becaa5edc"
TRAP_VA = 0x100ECA4F
TRAP_BYTES = bytes.fromhex(
    "8d44241450e857611f0183c4048bc8e89d601f01e89873590150e862120000cc"
)
TRAP_SHA256 = "0756cbe584a461d314d996199fe3c7dbb1635088e18718aaf4cd6ce6f60d544a"
RETURN_OPCODE_BYTE_POSITIONS = {
    0xC2: (),
    0xC3: (0x100EC69C, 0x100EC7F6, 0x100ECA4E),
    0xCA: (0x100EC872,),
    0xCB: (0x100EC80D,),
    0xCF: (0x100EC72D,),
}
EMBEDDED_OPCODE_INSTRUCTIONS = (
    (0x100EC72C, bytes.fromhex("e8cf631f01")),
    (0x100EC7F5, bytes.fromhex("8bc3")),
    (0x100EC80C, bytes.fromhex("8bcb")),
    (0x100EC871, bytes.fromhex("e8ca510100")),
)

CANONICAL_INDEX_SIZE = 8_344_450
CANONICAL_INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
FUNCTION_INDEX_SIZE = 2_148_494
FUNCTION_INDEX_SHA256 = "34be30433f3cea3e0baa9610afb42cc9122717a2cf63235710d7a9f6f9117591"
SYMBOL_MAP_SIZE = 2_893_153
SYMBOL_MAP_SHA256 = "620eb04ec899b0408de1dac9e8c67091b07bddbe2e49eddb90a62ce883fe450e"
RETURN_ORACLE_SIZE = 9_383
RETURN_ORACLE_SHA256 = "51e7a31e3b7fa96291a09dda74b586e4c831764fddbeb9527b5438df7c01e5ea"

CANONICAL_ROWS = {
    "100ed3c0": ("decomp_fn_100ed3c0", "FUN_100ed3c0", "400", "func", "100ed3c0-100ed54f"),
    "100ea060": ("decomp_fn_100ea060", "FUN_100ea060", "1123", "func", "100ea060-100ea4c2"),
    "112dcaf0": ("decomp_fn_112dcaf0", "FUN_112dcaf0", "996", "func", "112dcaf0-112dced3"),
    "100d6560": ("decomp_fn_100d6560", "guard_check_icall", "1", "func", "100d6560-100d6560"),
    "112e3d20": ("decomp_fn_112e3d20", "FUN_112e3d20", "139", "func", "112e3d20-112e3daa"),
    "112e2bb0": ("decomp_fn_112e2bb0", "FUN_112e2bb0", "63", "func", "112e2bb0-112e2bee"),
    "100ec5c0": ("decomp_fn_100ec5c0", "FUN_100ec5c0", "1199", "func", "100ec5c0-100eca6e"),
    "100e0650": ("decomp_fn_100e0650", "FUN_100e0650", "321", "func", "100e0650-100e0790"),
    "100f1cc0": ("decomp_fn_100f1cc0", "FUN_100f1cc0", "51", "func", "100f1cc0-100f1cf2"),
    "100f3d00": ("decomp_fn_100f3d00", "Serialize", "3", "func", "100f3d00-100f3d02"),
    "112a8ff0": ("decomp_fn_112a8ff0", "FUN_112a8ff0", "943", "func", "112a8ff0-112a932a,112a9334-112a93a7"),
}
CANONICAL_HASHES = {
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
    "100ea060": "39d5c6a5946bfabb3c14a878d71a4d4518c1b931a41fc6a4fa2e2497ea1894c0",
    "112dcaf0": "8c754ba0bbdb35d1e7766964ae12c30f34865678dfe74539d2ea32baf8c2e358",
    "100d6560": "b2dd76946e1873f4fa7ddeb7f0eae493a93649788f0946882777879a4e185bf6",
    "112e3d20": "3e5dfc0d84d325c1f90f91f6708fcff4628a37b147fc7f8e91027f6bd89d6a36",
    "112e2bb0": "724bba4fc0cf6c26d310ed455b6e9b8ab5b1664532d59c766564ae0dc5c759f1",
    "100ec5c0": "c4362bfb508004284f0f079a3367a8f2e8bb63c0b0610d94906d7eeac7f7689c",
    "100e0650": "f0630c6fbb3a402c1cf17165b8deb79e81bdb0c3ef03e351c24939090ad3b85c",
    "100f1cc0": "8cd70d65677361ef62405e7621495b03ddb3901696a4a01c429ff609bc4b4a69",
    "100f3d00": "29ad6898203dde3cf61b3e1d1d9c8c42e0c7ddf193499064b8042a709261175f",
    "112a8ff0": "a33234436a780b0241ae0e1cf489d26432d6328b3cb46d88b85ebdc576c56c6b",
}

HARD_EXCLUSIONS = (
    "execute_original_direct_callees",
    "dereference_original_first_indirect_receiver_or_vtable",
    "accept_poll_result_one",
    "accept_poll_result_outside_zero_or_two",
    "enter_result_one_list_path",
    "invoke_second_indirect_call",
    "follow_outer_iteration_backedge",
    "perform_unbounded_polling",
    "invoke_native_allocator_platform_or_process_global_effects",
)
INTENDED_MODEL = {
    "poll_domain": (0, 2),
    "poll_continue": 0,
    "poll_terminal": 2,
    "poll_budget_required": True,
    "terminal_result_required_within_budget": True,
    "poll_transcript_prevalidated": True,
    "result_one_admitted": False,
    "first_indirect_dispatch": "typed_injected_observer_only",
    "timestamp": "injected_uint64_copied_to_frame",
    "pre_poll_and_terminal_effects": "typed_injected_observers_only",
    "second_indirect_dispatch": "excluded",
    "terminal_cleanup": "four_admitted_nonowning_calls_in_original_order",
    "original_pc_execution": False,
    "candidate_target_set_exhaustive": False,
}


class EvidenceError(ValueError):
    """A candidate differs from the authenticated bounded evidence."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_authority(
    data: bytes, expected_size: int, expected_sha256: str, label: str
) -> None:
    if len(data) != expected_size:
        raise EvidenceError(f"{label} size changed")
    if sha256(data) != expected_sha256:
        raise EvidenceError(f"{label} SHA-256 changed")


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise EvidenceError(f"{label} lies outside the {len(data)}-byte input")


def parse_pe32(data: bytes) -> dict[str, object]:
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise EvidenceError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE header")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise EvidenceError("missing PE signature")
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
        or struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE
    ):
        raise EvidenceError("original image is not the pinned PE32 authority")
    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = table + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        flags = struct.unpack_from("<I", data, offset + 36)[0]
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append((name, rva, virtual_size, raw_offset, raw_size, flags))
    return {"machine": machine, "sections": tuple(sections)}


def read_va(data: bytes, pe: dict[str, object], va: int, size: int):
    if va < IMAGE_BASE:
        raise EvidenceError("VA precedes image base")
    rva = va - IMAGE_BASE
    matches = []
    for name, section_rva, _virtual_size, raw, raw_size, _flags in pe["sections"]:
        delta = rva - section_rva
        if delta >= 0 and size <= raw_size - delta:
            matches.append((name, raw + delta))
    if len(matches) != 1:
        raise EvidenceError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset:offset + size], name, offset


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 5, f"rel32 at 0x{instruction_va:08x}")
    if body[offset] in (0xE8, 0xE9):
        displacement_offset = offset + 1
        next_va = instruction_va + 5
    elif body[offset:offset + 2] in (b"\x0f\x84", b"\x0f\x85"):
        require_range(body, offset, 6, f"rel32 branch at 0x{instruction_va:08x}")
        displacement_offset = offset + 2
        next_va = instruction_va + 6
    else:
        raise EvidenceError(f"unsupported rel32 opcode at 0x{instruction_va:08x}")
    return next_va + struct.unpack_from("<i", body, displacement_offset)[0]


def rel8_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 2, f"rel8 at 0x{instruction_va:08x}")
    return instruction_va + 2 + struct.unpack_from("<b", body, offset + 1)[0]


def validate_instruction_partition(candidate: bytes) -> None:
    if len(candidate) != len(SLICE_BYTES):
        raise EvidenceError("lifecycle slice length changed")
    cursor = 0
    for va, encoded_hex in INSTRUCTION_PARTITION:
        encoded = bytes.fromhex(encoded_hex)
        if va != SLICE_VA + cursor:
            raise AssertionError("internal instruction partition is not contiguous")
        if candidate[cursor:cursor + len(encoded)] != encoded:
            raise EvidenceError(f"instruction changed at 0x{va:08x}")
        cursor += len(encoded)
    if cursor != len(candidate):
        raise EvidenceError("instruction partition does not consume the slice")


def validate_slice_candidate(candidate: bytes) -> None:
    require_authority(candidate, 223, SLICE_SHA256, "ordinary lifecycle slice")
    validate_instruction_partition(candidate)
    calls = tuple(
        (site, rel32_target(candidate, SLICE_VA, site))
        for site, _target in DIRECT_CALLS
    )
    if calls != DIRECT_CALLS:
        raise EvidenceError("direct-call sites or targets changed")
    for site, opcode, _shape in INDIRECT_CALLS:
        offset = site - SLICE_VA
        if candidate[offset:offset + len(opcode)] != opcode:
            raise EvidenceError(f"indirect-call shape changed at 0x{site:08x}")
    expected_branches = (
        (0x100ED4CD, 0x100ED51B),
        (0x100ED4D2, 0x100ED4C1),
        (0x100ED4E7, 0x100ED50B),
        (0x100ED4F8, 0x100ED507),
        (0x100ED509, 0x100ED4F0),
    )
    for site, target in expected_branches:
        if rel8_target(candidate, SLICE_VA, site) != target:
            raise EvidenceError(f"rel8 edge changed at 0x{site:08x}")
    if rel32_target(candidate, SLICE_VA, 0x100ED516) != 0x100ED472:
        raise EvidenceError("outer backedge changed")
    cursor = SLICE_VA
    for _name, start, end, _raw, expected_hash in SPLITS:
        if start != cursor:
            raise AssertionError("internal split authority is not contiguous")
        part = candidate[start - SLICE_VA:end - SLICE_VA]
        require_authority(part, end - start, expected_hash, f"split 0x{start:08x}")
        cursor = end
    if cursor != SLICE_END_VA:
        raise AssertionError("internal split authority does not cover slice")


def validate_stack_model(candidate: dict[str, int]) -> None:
    if candidate != STACK_MODEL:
        raise EvidenceError("normalized frame identities changed")
    if candidate["saved_esi_delta"] + 0x68 != candidate["receiver"]:
        raise EvidenceError("receiver normalization changed")
    if candidate["saved_esi_delta"] + 0x2C != candidate["timestamp_destination"]:
        raise EvidenceError("timestamp destination normalization changed")
    if candidate["saved_esi_delta"] + 0x908 != candidate["timestamp_low_copy"]:
        raise EvidenceError("timestamp low-copy normalization changed")
    if candidate["saved_esi_delta"] + 0x90C != candidate["timestamp_high_copy"]:
        raise EvidenceError("timestamp high-copy normalization changed")
    if candidate["timestamp_high_copy"] + 4 != FRAME_SIZE:
        raise EvidenceError("timestamp copies no longer end at frame endpoint")
    if candidate["saved_esi_delta"] + 0x8D4 != candidate["result_one_list_count"]:
        raise EvidenceError("list count normalization changed")
    if candidate["saved_esi_delta"] + 0x8D8 != candidate["result_one_list_base"]:
        raise EvidenceError("list base normalization changed")


def validate_cfg(blocks, edges) -> None:
    if tuple(blocks) != BASIC_BLOCKS or tuple(edges) != CFG_EDGES:
        raise EvidenceError("lifecycle CFG changed")
    if (0x100ED4CF, 0x100ED4D4, "poll_result_eq_1") not in edges:
        raise EvidenceError("result-one edge was erased from raw evidence")
    if (0x100ED50B, 0x100ED472, "outer_iteration_backedge") not in edges:
        raise EvidenceError("outer backedge was erased from raw evidence")


def validate_intended_model(model: dict[str, object], exclusions) -> None:
    if model != INTENDED_MODEL:
        raise EvidenceError("finite injected model changed")
    if tuple(exclusions) != HARD_EXCLUSIONS:
        raise EvidenceError("hard exclusions changed")
    if model["poll_domain"] != (0, 2):
        raise EvidenceError("poll domain widened")
    if not model["poll_budget_required"] or not model["terminal_result_required_within_budget"]:
        raise EvidenceError("unbounded or unterminated polling was admitted")
    if model["result_one_admitted"] or model["candidate_target_set_exhaustive"]:
        raise EvidenceError("unproved result or target claim was admitted")
    if model["second_indirect_dispatch"] != "excluded":
        raise EvidenceError("second indirect dispatch was admitted")
    if model["original_pc_execution"]:
        raise EvidenceError("original address execution was admitted")


def validate_return_domain(body: bytes) -> tuple[int, int]:
    require_authority(
        body, RETURN_FUNCTION_SIZE, RETURN_FUNCTION_SHA256, "0x100ec5c0"
    )
    return2 = body[RETURN2_VA - RETURN_FUNCTION_VA:
                   RETURN2_VA - RETURN_FUNCTION_VA + len(RETURN2_BYTES)]
    final = body[FINAL_RETURN_VA - RETURN_FUNCTION_VA:
                 FINAL_RETURN_VA - RETURN_FUNCTION_VA + len(FINAL_RETURN_BYTES)]
    trap = body[TRAP_VA - RETURN_FUNCTION_VA:
                TRAP_VA - RETURN_FUNCTION_VA + len(TRAP_BYTES)]
    if return2 != RETURN2_BYTES or sha256(return2) != RETURN2_SHA256:
        raise EvidenceError("constant-two epilogue changed")
    if final != FINAL_RETURN_BYTES or sha256(final) != FINAL_RETURN_SHA256:
        raise EvidenceError("masked final epilogue changed")
    if trap != TRAP_BYTES or sha256(trap) != TRAP_SHA256 or trap[-1] != 0xCC:
        raise EvidenceError("non-returning INT3 path changed")
    for site in (0x100EC5D3, 0x100EC5EE, 0x100EC946, 0x100EC96B):
        if rel32_target(body, RETURN_FUNCTION_VA, site) != RETURN2_VA:
            raise EvidenceError("constant-two predecessor changed")
    if rel8_target(body, RETURN_FUNCTION_VA, 0x100EC6DE) != RETURN2_VA:
        raise EvidenceError("short constant-two predecessor changed")
    if rel32_target(body, RETURN_FUNCTION_VA, 0x100EC978) != FINAL_RETURN_VA:
        raise EvidenceError("final ordinary-return predecessor changed")
    if rel32_target(body, RETURN_FUNCTION_VA, 0x100EC991) != TRAP_VA:
        raise EvidenceError("trap predecessor changed")
    for opcode, expected in RETURN_OPCODE_BYTE_POSITIONS.items():
        actual = tuple(
            RETURN_FUNCTION_VA + offset
            for offset, byte in enumerate(body)
            if byte == opcode
        )
        if actual != expected:
            raise EvidenceError(f"return-like opcode byte 0x{opcode:02x} changed")
    for va, encoded in EMBEDDED_OPCODE_INSTRUCTIONS:
        offset = va - RETURN_FUNCTION_VA
        if body[offset:offset + len(encoded)] != encoded:
            raise EvidenceError(f"embedded opcode instruction changed at 0x{va:08x}")
    if struct.unpack_from("<I", return2, 4)[0] != 2:
        raise EvidenceError("literal return two changed")
    mask_parts = tuple(
        final.index(part) for part in (
            bytes.fromhex("0fb6c0"), bytes.fromhex("f7d8"),
            bytes.fromhex("1bc0"), bytes.fromhex("83e002"),
        )
    )
    if mask_parts != tuple(sorted(mask_parts)):
        raise EvidenceError("zero-or-two Boolean mask changed")
    return (0, 2)


def mutated(data: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(data):
        raise ValueError("mutation offset outside input")
    result = bytearray(data)
    result[offset] ^= 1
    return bytes(result)


class Startup100ed471OrdinaryLifecycleProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        require_authority(cls.dll, DLL_SIZE, DLL_SHA256, "original DLL")
        cls.pe = parse_pe32(cls.dll)

    def test_original_pe_parent_and_whole_slice_are_exact(self):
        self.assertIn(TEXT_SECTION, self.pe["sections"])
        parent, section, raw = read_va(
            self.dll, self.pe, PARENT_VA, PARENT_SIZE
        )
        self.assertEqual((section, raw), (".text", PARENT_RAW))
        self.assertEqual(sha256(parent), PARENT_SHA256)
        self.assertEqual(sha256(parent[:PRELOOP_SIZE]), PRELOOP_SHA256)
        self.assertEqual(parent[PRELOOP_SIZE:], SLICE_BYTES)
        tail, section, raw = read_va(
            self.dll, self.pe, SLICE_VA, len(SLICE_BYTES)
        )
        self.assertEqual((section, raw), (".text", SLICE_RAW))
        self.assertEqual(tail, SLICE_BYTES)
        validate_slice_candidate(tail)
        self.assertEqual(SLICE_VA + len(tail), SLICE_END_VA)

    def test_four_split_ranges_are_contiguous_and_hash_pinned(self):
        cursor = SLICE_VA
        total = 0
        for _name, start, end, expected_raw, expected_hash in SPLITS:
            self.assertEqual(start, cursor)
            part, section, raw = read_va(self.dll, self.pe, start, end - start)
            self.assertEqual((section, raw), (".text", expected_raw))
            self.assertEqual(sha256(part), expected_hash)
            self.assertEqual(part, SLICE_BYTES[start - SLICE_VA:end - SLICE_VA])
            cursor = end
            total += len(part)
        self.assertEqual((cursor, total), (SLICE_END_VA, 223))

    def test_exact_sixty_instruction_partition_is_contiguous(self):
        validate_instruction_partition(SLICE_BYTES)
        self.assertEqual(len(INSTRUCTION_PARTITION), 60)
        self.assertEqual(
            sum(len(bytes.fromhex(encoded)) for _va, encoded in INSTRUCTION_PARTITION),
            len(SLICE_BYTES),
        )

    def test_eleven_direct_calls_and_two_indirect_shapes_are_exact(self):
        validate_slice_candidate(SLICE_BYTES)
        self.assertEqual(len(DIRECT_CALLS), 11)
        self.assertEqual(len({target for _site, target in DIRECT_CALLS}), 8)
        self.assertEqual(INDIRECT_CALLS[0][0:2], (0x100ED49E, b"\xff\x52\x54"))
        self.assertEqual(INDIRECT_CALLS[1][0:2], (0x100ED4FE, b"\xff\x10"))

    def test_exact_raw_cfg_has_poll_list_and_outer_backedges(self):
        validate_cfg(BASIC_BLOCKS, CFG_EDGES)
        self.assertEqual(rel8_target(SLICE_BYTES, SLICE_VA, 0x100ED4D2), 0x100ED4C1)
        self.assertEqual(rel8_target(SLICE_BYTES, SLICE_VA, 0x100ED509), 0x100ED4F0)
        self.assertEqual(rel32_target(SLICE_BYTES, SLICE_VA, 0x100ED516), 0x100ED472)

    def test_stack_frame_offsets_and_direct_writes_are_exact(self):
        validate_stack_model(dict(STACK_MODEL))
        self.assertEqual(SLICE_BYTES[0:1], b"\x56")
        self.assertEqual(SLICE_BYTES[-8:], bytes.fromhex("5e81c40c090000c3"))
        self.assertEqual(DIRECT_FRAME_WRITES, (
            (0x100ED4B0, 0x904, 4, "timestamp_low32"),
            (0x100ED4BA, 0x908, 4, "timestamp_high32"),
            (0x100ED50B, 0x8D0, 4, "result_one_only_zero_list_count"),
        ))
        self.assertEqual(
            SLICE_BYTES[0x3F:0x50],
            bytes.fromhex("898c24080900008b40048984240c090000"),
        )
        self.assertEqual(
            SLICE_BYTES[0x9A:0xA5], bytes.fromhex("c78424d408000000000000")
        )

    def test_terminal_teardown_and_four_cleanup_calls_are_ordered(self):
        self.assertEqual(
            tuple((site, target) for site, target, _offset, _label in TERMINAL_CALL_ORDER),
            DIRECT_CALLS[-5:],
        )
        self.assertEqual(
            tuple(offset for _site, _target, offset, _label in TERMINAL_CALL_ORDER),
            (0x64, 0x48, 0x3C, 0x10, 0x04),
        )
        sites = [SLICE_BYTES.index(bytes.fromhex(encoded)) for encoded in (
            "8d4c2468e82c31ffff", "8d4c244ce893470000",
            "8d4c2440e88a470000", "8d4c2414e881470000",
            "8d4c2408e878470000",
        )]
        self.assertEqual(sites, sorted(sites))

    def test_all_direct_target_bodies_are_pe_mapped_and_hash_pinned(self):
        for va, (size, expected_raw, expected_hash) in DIRECT_TARGETS.items():
            body, section, raw = read_va(self.dll, self.pe, va, size)
            self.assertEqual((section, raw), (".text", expected_raw))
            self.assertEqual(sha256(body), expected_hash)
        guard, _section, _raw = read_va(self.dll, self.pe, 0x100D6560, 1)
        self.assertEqual(guard, b"\xc3")
        cleanup, _section, _raw = read_va(self.dll, self.pe, 0x100F1CC0, 51)
        self.assertEqual(cleanup[-2:], b"\x5e\xc3")

    def test_log_literal_and_timestamp_copy_contract_are_exact(self):
        literal, section, raw = read_va(
            self.dll, self.pe, LOG_LITERAL_VA, len(LOG_LITERAL)
        )
        self.assertEqual((section, raw), (".rdata", 0x0173EA84))
        self.assertEqual(literal, LOG_LITERAL)
        self.assertEqual(sha256(literal), LOG_LITERAL_SHA256)
        timer, _section, _raw = read_va(self.dll, self.pe, 0x112E2BB0, 63)
        self.assertEqual(timer[-12:], bytes.fromhex("8b44241083c4048978045f89305ec3")[-12:])
        self.assertEqual(
            SLICE_BYTES[0x30:0x50],
            bytes.fromhex(
                "8d44242c50e805571f0183c4048b08898c24080900008b40048984240c090000"
            ),
        )

    def test_first_indirect_observed_candidates_are_pinned_not_exhaustive(self):
        getter, _section, _raw = read_va(self.dll, self.pe, GETTER_VA, 139)
        self.assertEqual(sha256(getter), GETTER_BYTES_SHA256)
        self.assertEqual(getter[0:5], bytes.fromhex("a1101f0312"))
        self.assertEqual(getter[0x49:0x4E], bytes.fromhex("b804109e11"))
        self.assertEqual(rel32_target(getter, GETTER_VA, 0x112E3D3E), CONSTRUCTOR_VA)
        self.assertEqual(rel32_target(getter, GETTER_VA, 0x112E3D88), CONSTRUCTOR_VA)

        constructor, section, raw = read_va(
            self.dll, self.pe, CONSTRUCTOR_VA, CONSTRUCTOR_SIZE
        )
        self.assertEqual((section, raw), (".text", CONSTRUCTOR_RAW))
        self.assertEqual(sha256(constructor), CONSTRUCTOR_SHA256)
        self.assertEqual(constructor[:len(CONSTRUCTOR_PREFIX)], CONSTRUCTOR_PREFIX)
        self.assertEqual(sha256(CONSTRUCTOR_PREFIX), CONSTRUCTOR_PREFIX_SHA256)
        self.assertEqual(struct.unpack_from("<I", CONSTRUCTOR_PREFIX, 19)[0], DYNAMIC_VTABLE_VA)

        static_object, section, raw = read_va(self.dll, self.pe, STATIC_OBJECT_VA, 4)
        self.assertEqual((section, raw), (".data", 0x019DEC04))
        self.assertEqual(struct.unpack("<I", static_object)[0], STATIC_VTABLE_VA)
        for _label, vtable, target in OBSERVED_SLOT54_CANDIDATES:
            window, section, _raw = read_va(
                self.dll, self.pe, vtable, VTABLE_WINDOW_SIZE
            )
            self.assertEqual(section, ".rdata")
            expected_hash = (
                STATIC_VTABLE_SHA256 if vtable == STATIC_VTABLE_VA
                else DYNAMIC_VTABLE_SHA256
            )
            self.assertEqual(sha256(window), expected_hash)
            self.assertEqual(struct.unpack_from("<I", window, 0x54)[0], target)

        static_target, section, raw = read_va(self.dll, self.pe, 0x100F3D00, 3)
        self.assertEqual((section, raw, static_target), (".text", 0x000F3100, STATIC_CANDIDATE_BYTES))
        dynamic_target, section, raw = read_va(self.dll, self.pe, 0x112E2CD0, 12)
        self.assertEqual((section, raw, dynamic_target), (".text", 0x012E20D0, DYNAMIC_CANDIDATE_BYTES))
        self.assertFalse(INTENDED_MODEL["candidate_target_set_exhaustive"])

    def test_100ec5c0_ordinary_return_domain_is_exactly_zero_or_two(self):
        body, section, raw = read_va(
            self.dll, self.pe, RETURN_FUNCTION_VA, RETURN_FUNCTION_SIZE
        )
        self.assertEqual((section, raw), (".text", 0x000EB9C0))
        self.assertEqual(validate_return_domain(body), (0, 2))
        self.assertEqual(rel32_target(SLICE_BYTES, SLICE_VA, 0x100ED4C5), RETURN_FUNCTION_VA)

    def test_result_one_list_path_and_second_indirect_are_ordinary_unreachable(self):
        domain = validate_return_domain(
            read_va(self.dll, self.pe, RETURN_FUNCTION_VA, RETURN_FUNCTION_SIZE)[0]
        )
        self.assertNotIn(1, domain)
        self.assertEqual(rel8_target(SLICE_BYTES, SLICE_VA, 0x100ED4CD), 0x100ED51B)
        self.assertEqual(rel8_target(SLICE_BYTES, SLICE_VA, 0x100ED4D2), 0x100ED4C1)
        result_one = SLICE_BYTES[0x63:0xAA]
        self.assertEqual(sha256(result_one), SPLITS[2][4])
        self.assertIn(b"\xff\x10", result_one)
        self.assertNotIn(b"\xff\x10", SLICE_BYTES[:0x63])
        self.assertNotIn(b"\xff\x10", SLICE_BYTES[0xAA:])

    def test_map_indexes_and_canonical_decomp_authorities_are_exact(self):
        require_authority(
            CANONICAL_INDEX.read_bytes(), CANONICAL_INDEX_SIZE,
            CANONICAL_INDEX_SHA256, "canonical index"
        )
        require_authority(
            FUNCTION_INDEX.read_bytes(), FUNCTION_INDEX_SIZE,
            FUNCTION_INDEX_SHA256, "function index"
        )
        require_authority(
            SYMBOL_MAP.read_bytes(), SYMBOL_MAP_SIZE, SYMBOL_MAP_SHA256,
            "symbol map"
        )
        rows = {
            row["entry"]: row for row in csv.DictReader(
                CANONICAL_INDEX.read_text(encoding="utf-8").splitlines(),
                delimiter="\t",
            )
        }
        for entry, expected in CANONICAL_ROWS.items():
            row = rows[entry]
            actual = (
                row["canonical_name"], row["original_name"], row["size"],
                row["kind"], row["body_ranges"],
            )
            self.assertEqual(actual, expected)
            source = CANONICAL / f"decomp_fn_{entry}.c"
            self.assertEqual(sha256(source.read_bytes()), CANONICAL_HASHES[entry])

        function_lines = set(FUNCTION_INDEX.read_text(encoding="utf-8").splitlines())
        symbol_lines = set(SYMBOL_MAP.read_text(encoding="utf-8").splitlines())
        for entry, (_canonical, original, size, kind, _ranges) in CANONICAL_ROWS.items():
            self.assertIn(f"0x{entry}\t{original}\t{size}\t{kind}", function_lines)
        self.assertIn(
            "100f3d00\tSerialize\tOC3Ent::Face::FxActorInstance::Serialize\t3\tfunc",
            symbol_lines,
        )
        # 0x112e2cd0 is authenticated raw code, but neither map calls it a
        # discovered function.  Do not manufacture a symbol or prototype.
        self.assertFalse(any(line.startswith("0x112e2cd0\t") for line in function_lines))
        self.assertFalse(any(line.startswith("112e2cd0\t") for line in symbol_lines))

    def test_canonical_parent_preserves_exact_lifecycle_order(self):
        parent = (CANONICAL / "decomp_fn_100ed3c0.c").read_text(encoding="utf-8")
        tokens = (
            "decomp_fn_100ea060();",
            'decomp_fn_112dcaf0("Init completed",0,0);',
            "decomp_fn_100d6560(0);",
            "piVar1 = (int *)decomp_fn_112e3d20();",
            "(**(code **)(*piVar1 + 0x54))(0);",
            "puVar2 = (undefined4 *)decomp_fn_112e2bb0(local_8e4);",
            "iVar3 = decomp_fn_100ec5c0();",
            "if (iVar3 == 2) {",
            "decomp_fn_100e0650();",
            "} while (iVar3 != 1);",
            "(*(code *)**(undefined4 **)*piVar1)(1);",
            "iStack_3c = 0;",
        )
        positions = [parent.index(token) for token in tokens]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(parent.count("decomp_fn_100f1cc0();"), 5)
        terminal_start = parent.index("decomp_fn_100e0650();")
        cleanup_positions = []
        cursor = terminal_start
        for _index in range(4):
            cursor = parent.index("decomp_fn_100f1cc0();", cursor + 1)
            cleanup_positions.append(cursor)
        self.assertEqual(cleanup_positions, sorted(cleanup_positions))
        self.assertLess(terminal_start, cleanup_positions[0])
        self.assertLess(cleanup_positions[-1], parent.index("return;", terminal_start))

    def test_existing_return_domain_oracle_is_pinned_and_cross_checked(self):
        data = RETURN_DOMAIN_ORACLE.read_bytes()
        require_authority(data, RETURN_ORACLE_SIZE, RETURN_ORACLE_SHA256, "return-domain oracle")
        text = data.decode("utf-8")
        for token in (
            'FUNCTION_VA = 0x100EC5C0',
            'FUNCTION_SIZE = 1199',
            f'FUNCTION_SHA256 = "{RETURN_FUNCTION_SHA256}"',
            'RETURN2_VA = 0x100EC68D',
            'FINAL_RETURN_VA = 0x100ECA35',
            'TRAP_VA = 0x100ECA4F',
            'PARENT_WINDOW_VA = 0x100ED4C1',
            'self.assertEqual(rel8_target(window, PARENT_WINDOW_VA, 0x100ED4D2), PARENT_WINDOW_VA)',
        ):
            self.assertIn(token, text)

    def test_finite_injected_model_and_hard_exclusions_fail_closed(self):
        validate_intended_model(dict(INTENDED_MODEL), HARD_EXCLUSIONS)
        self.assertEqual(INTENDED_MODEL["poll_domain"], (0, 2))
        self.assertTrue(INTENDED_MODEL["poll_transcript_prevalidated"])
        self.assertEqual(
            INTENDED_MODEL["terminal_cleanup"],
            "four_admitted_nonowning_calls_in_original_order",
        )

    def test_documentation_matches_authenticated_boundary_and_model(self):
        doc = DOC.read_text(encoding="utf-8")
        for token in (
            "[0x100ed471,0x100ed550)", SLICE_SHA256,
            SPLITS[0][4], SPLITS[1][4], SPLITS[2][4], SPLITS[3][4],
            "0x100ed49e", "0x100ed4fe", "{0,2}",
            "not an exhaustive target proof", "finite poll transcript",
            "0x100e0650 -> 0x100f1cc0(F+0x48) -> 0x100f1cc0(F+0x3c) ->",
        ):
            self.assertIn(token, doc)

    def test_reciprocal_instruction_call_branch_and_split_mutants_fail(self):
        for va, encoded in INSTRUCTION_PARTITION:
            self.assertGreater(len(bytes.fromhex(encoded)), 0)
            with self.assertRaises(EvidenceError, msg=f"instruction 0x{va:08x}"):
                validate_slice_candidate(mutated(SLICE_BYTES, va - SLICE_VA))
        for site, _target in DIRECT_CALLS:
            with self.assertRaises(EvidenceError, msg=f"call 0x{site:08x}"):
                validate_slice_candidate(mutated(SLICE_BYTES, site - SLICE_VA + 1))
        for site in (0x100ED4CD, 0x100ED4D2, 0x100ED4E7, 0x100ED4F8, 0x100ED509):
            with self.assertRaises(EvidenceError, msg=f"branch 0x{site:08x}"):
                validate_slice_candidate(mutated(SLICE_BYTES, site - SLICE_VA + 1))
        with self.assertRaises(EvidenceError):
            validate_slice_candidate(mutated(SLICE_BYTES, 0x100ED517 - SLICE_VA))

    def test_reciprocal_return_model_cfg_and_authority_mutants_fail(self):
        return_body = read_va(
            self.dll, self.pe, RETURN_FUNCTION_VA, RETURN_FUNCTION_SIZE
        )[0]
        for va in (RETURN2_VA + 4, FINAL_RETURN_VA + 17, TRAP_VA + len(TRAP_BYTES) - 1):
            with self.assertRaises(EvidenceError):
                validate_return_domain(mutated(return_body, va - RETURN_FUNCTION_VA))
        model_mutations = (
            ("poll_domain", (0, 1, 2)),
            ("poll_budget_required", False),
            ("terminal_result_required_within_budget", False),
            ("result_one_admitted", True),
            ("second_indirect_dispatch", "injected"),
            ("candidate_target_set_exhaustive", True),
            ("original_pc_execution", True),
        )
        for key, value in model_mutations:
            mutant = dict(INTENDED_MODEL)
            mutant[key] = value
            with self.assertRaises(EvidenceError, msg=key):
                validate_intended_model(mutant, HARD_EXCLUSIONS)
        edges = list(CFG_EDGES)
        edges.remove((0x100ED4CF, 0x100ED4D4, "poll_result_eq_1"))
        with self.assertRaises(EvidenceError):
            validate_cfg(BASIC_BLOCKS, edges)
        for va, (size, _raw, expected_hash) in DIRECT_TARGETS.items():
            body = read_va(self.dll, self.pe, va, size)[0]
            with self.assertRaises(EvidenceError):
                require_authority(mutated(body, len(body) // 2), size, expected_hash, hex(va))

    def test_oracle_uses_only_standard_library_and_has_no_write_calls(self):
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imports = set()
        forbidden_calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {
                    "write_bytes", "write_text", "unlink", "rename", "replace",
                    "mkdir", "rmdir", "touch",
                }:
                    forbidden_calls.add(node.func.attr)
        self.assertEqual(
            imports,
            {"__future__", "ast", "csv", "hashlib", "struct", "unittest", "pathlib"},
        )
        self.assertEqual(forbidden_calls, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
