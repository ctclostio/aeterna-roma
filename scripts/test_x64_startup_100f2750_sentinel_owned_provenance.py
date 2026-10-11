#!/usr/bin/env python3
"""Authenticate first-use persistent ownership at original 0x100f2750.

The original PE is parsed only as inert bytes.  No recovered instruction,
allocator, releaser, CRT registrar, destructor, or original address executes.
The finite model is an injected design boundary for a later native slice.
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
DOC = ROOT / "docs" / "x64_startup_100f2750_sentinel_owned.md"

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
IMAGE_BASE = 0x10000000
ADDRESS_SPACE_SIZE = 0x100000000
TEXT_SECTION = (
    ".text", 0x00001000, 0x0172D4EA, 0x00000400, 0x0172D600,
    0x60000020,
)
DATA_SECTION = (
    ".data", 0x01933000, 0x007F3C40, 0x01930C00, 0x000BC200,
    0xC0000040,
)

BODY_VA = 0x100F2750
BODY_SIZE = 157
BODY_RAW = 0x000F1B50
BODY_SHA256 = "bf302936751abe0c0d8d59c44a0f1903e1f427f4388fe85b397f73d692243744"
BODY_BYTES = bytes.fromhex(
    "83ec0c56578b7c24188bf18b073b460477283bfe747d8d04450200000050ff77"
    "08ff7608e8d7b65c018b0783c40c89068bc65f5e83c40cc204008b4f08894424"
    "088d044150518d4c2410e891cbffff8b44240889068b44240c8946048b7e088b"
    "44241089460881ff9040af11742585ff74218b7ffc85ff741a57e881260300a1"
    "b03e9f1183c40485c074086a0057ffd083c4085f8bc65e83c40cc20400"
)

REPLACEMENT_VA = 0x100F278A
REPLACEMENT_END = 0x100F27ED
REPLACEMENT_RAW = 0x000F1B8A
REPLACEMENT_BYTES = BODY_BYTES[REPLACEMENT_VA - BODY_VA:]
REPLACEMENT_SHA256 = (
    "a3202d7bd2e087f54099e3538f0f866d37e753abfbed186cc25708f65c590199"
)
FIRST_USE_COMMIT_END = 0x100F27BE
FIRST_USE_COMMIT_BYTES = REPLACEMENT_BYTES[:FIRST_USE_COMMIT_END - REPLACEMENT_VA]
FIRST_USE_COMMIT_SHA256 = (
    "5330cfe4cfc72298be8730653327985d50e435354ae996c6f9a43d8a766b4ccd"
)

HELPER_VA = 0x100EF330
HELPER_END = 0x100EF3AC
HELPER_RAW = 0x000EE730
HELPER_BYTES = bytes.fromhex(
    "578bf98b0789470485c0750bc747089040af115fc208005355568d04450a000000"
    "6a0050e827d900008b5c242033ed83c40833d28d700883e6fc8946fc8b442414"
    "2bd843897708d1eb3b4424180f47dd85db74152bf0668b088d40024266894c06fe"
    "3bd375f08b77088b0f66a18c40af116689044e5e5d5b5fc20800"
)
HELPER_SHA256 = "b343025d84a700b1a9e37ffcafc5222ad53a23643c1c99aede37ab1e2193b93d"

INIT_LEAF_VA = 0x100F1C10
INIT_LEAF_END = 0x100F1C27
INIT_LEAF_RAW = 0x000F1010
INIT_LEAF_BYTES = bytes.fromhex(
    "c701000000008bc1c7410400000000c741089040af11c3"
)
INIT_LEAF_SHA256 = (
    "6c689fc50bf6bfcfb73dc23095cfc6c98a757df32867c8d8b77514129bb8a2a1"
)

INIT_SITE_VA = 0x100E82E7
INIT_SITE_BYTES = bytes.fromhex("b9a03a9f11e81f990000")
INIT_SITE_SHA256 = (
    "0f871c86ab513335f740752f1011f490f24571f76e2e9fe77c44e88ff9b38701"
)
INIT_REGISTER_VA = INIT_SITE_VA
INIT_REGISTER_END = 0x100E8363
INIT_REGISTER_RAW = 0x000E76E7
INIT_REGISTER_BYTES = bytes.fromhex(
    "b9a03a9f11e81f9900000f57c066c705383a9f1100006880dc6d11c6053a3a9f"
    "11000f11053c3a9f11c705683a9f11000000000f1105583a9f11c7056c3a9f11"
    "00000000c605703a9f1100660f1305903a9f11c705983a9f1100000000c7059c"
    "3a9f110000000066c705ad3a9f110000c605af3a9f1100e887b55901"
)
INIT_REGISTER_SHA256 = (
    "485deab3aa21dafdaa4e3cc288d9a5a45b91b34099791572a324c5195a2fe15b"
)

DESTRUCTOR_VA = 0x116DDC80
DESTRUCTOR_END = 0x116DDCA8
DESTRUCTOR_RAW = 0x016DD080
DESTRUCTOR_BYTES = bytes.fromhex(
    "b9a03a9f11e83640a1feb9803a9f11e82c40a1feb9743a9f11e82240a1fe"
    "b94c3a9f11e91840a1fe"
)
DESTRUCTOR_SHA256 = (
    "8a601eaf8096b5c4eab87bd6af2fcbcb05242de6b9bb6e8537d1977dbf729faf"
)

ATEXIT_VA = 0x116838EA
ATEXIT_END = 0x116838FF
ATEXIT_RAW = 0x01682CEA
ATEXIT_BYTES = bytes.fromhex(
    "558becff7508e8c8fffffff7d8591bc0f7d8485dc3"
)
ATEXIT_SHA256 = "efae0e05a589276306c3c87f5a7eac21406f050c14251fdc660fa00f91ff430f"
ONEXIT_VA = 0x116838BD

CHILD_SUFFIX_VA = 0x100DF46D
CHILD_SUFFIX_RAW = 0x000DE86D
CHILD_SUFFIX_BYTES = bytes.fromhex(
    "ffb42418040000893d40319f11e8c18d00008d4868e8c93201008bcfe842b00000"
)
CHILD_SUFFIX_SHA256 = (
    "723bd9e4fdab4eaa8aa9ea40b1f6b01661d2d388c59dacf4ac8f488ca59ee8ed"
)

SOURCE_PARENT_VA = 0x100ED42C
SOURCE_PARENT_END = 0x100ED471
SOURCE_PARENT_RAW = 0x000EC82C
SOURCE_PARENT_BYTES = bytes.fromhex(
    "8b44241c8d4c2428ffb42418090000894424588a4424248844245c8b44242889"
    "442460c644246400e857470000508d442438508d4c246ce8081effff8d4c2428"
    "e84f480000"
)
SOURCE_PARENT_SHA256 = (
    "8be7ffb391c31778f273fcd94315254c837528f6a5bf0f37004d4513aeb4148d"
)

CLEANUP_VA = 0x100F1CC0
CLEANUP_BYTES = bytes.fromhex(
    "568b710881fe9040af11742585f674218b76fc85f6741a56e873310300a1b03e"
    "9f1183c40485c074086a0056ffd083c4085ec3"
)
CLEANUP_SHA256 = "bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4"
RELEASE_VA = 0x10124E50
ALLOCATOR_VA = 0x100FCC80
SOURCE_BUILDER_VA = 0x100F1BB0
CHILD_VA = 0x100DF270
FAST_OR_INIT_VA = 0x100E8240
FOLLOWING_VA = 0x100EA4D0
SOURCE_PARENT_VA_FULL = 0x100ED3C0

PERSISTENT_DESCRIPTOR = 0x119F3AA0
CRASH_RECORD = 0x119F3A38
PERSISTENT_DELTA = 0x68
EMPTY_SENTINEL = 0x11AF4090
MUTABLE_HOOK = 0x119F3EB0
PERSISTENT_LITERAL = struct.pack("<I", PERSISTENT_DESCRIPTOR)
PERSISTENT_LITERAL_RAW_OFFSETS = (0x000E76E8, 0x016DD081)
DESTRUCTOR_DESCRIPTORS = (
    0x119F3AA0,
    0x119F3A80,
    0x119F3A74,
    0x119F3A4C,
)

REPLACEMENT_INSTRUCTIONS = (
    (0x100F278A, "8b4f08"),
    (0x100F278D, "89442408"),
    (0x100F2791, "8d0441"),
    (0x100F2794, "50"),
    (0x100F2795, "51"),
    (0x100F2796, "8d4c2410"),
    (0x100F279A, "e891cbffff"),
    (0x100F279F, "8b442408"),
    (0x100F27A3, "8906"),
    (0x100F27A5, "8b44240c"),
    (0x100F27A9, "894604"),
    (0x100F27AC, "8b7e08"),
    (0x100F27AF, "8b442410"),
    (0x100F27B3, "894608"),
    (0x100F27B6, "81ff9040af11"),
    (0x100F27BC, "7425"),
    (0x100F27BE, "85ff"),
    (0x100F27C0, "7421"),
    (0x100F27C2, "8b7ffc"),
    (0x100F27C5, "85ff"),
    (0x100F27C7, "741a"),
    (0x100F27C9, "57"),
    (0x100F27CA, "e881260300"),
    (0x100F27CF, "a1b03e9f11"),
    (0x100F27D4, "83c404"),
    (0x100F27D7, "85c0"),
    (0x100F27D9, "7408"),
    (0x100F27DB, "6a00"),
    (0x100F27DD, "57"),
    (0x100F27DE, "ffd0"),
    (0x100F27E0, "83c408"),
    (0x100F27E3, "5f"),
    (0x100F27E4, "8bc6"),
    (0x100F27E6, "5e"),
    (0x100F27E7, "83c40c"),
    (0x100F27EA, "c20400"),
)

INIT_LEAF_INSTRUCTIONS = (
    (0x100F1C10, "c70100000000"),
    (0x100F1C16, "8bc1"),
    (0x100F1C18, "c7410400000000"),
    (0x100F1C1F, "c741089040af11"),
    (0x100F1C26, "c3"),
)

INIT_REGISTER_INSTRUCTIONS = (
    (0x100E82E7, "b9a03a9f11"),
    (0x100E82EC, "e81f990000"),
    (0x100E82F1, "0f57c0"),
    (0x100E82F4, "66c705383a9f110000"),
    (0x100E82FD, "6880dc6d11"),
    (0x100E8302, "c6053a3a9f1100"),
    (0x100E8309, "0f11053c3a9f11"),
    (0x100E8310, "c705683a9f1100000000"),
    (0x100E831A, "0f1105583a9f11"),
    (0x100E8321, "c7056c3a9f1100000000"),
    (0x100E832B, "c605703a9f1100"),
    (0x100E8332, "660f1305903a9f11"),
    (0x100E833A, "c705983a9f1100000000"),
    (0x100E8344, "c7059c3a9f1100000000"),
    (0x100E834E, "66c705ad3a9f110000"),
    (0x100E8357, "c605af3a9f1100"),
    (0x100E835E, "e887b55901"),
)

DESTRUCTOR_INSTRUCTIONS = (
    (0x116DDC80, "b9a03a9f11"),
    (0x116DDC85, "e83640a1fe"),
    (0x116DDC8A, "b9803a9f11"),
    (0x116DDC8F, "e82c40a1fe"),
    (0x116DDC94, "b9743a9f11"),
    (0x116DDC99, "e82240a1fe"),
    (0x116DDC9E, "b94c3a9f11"),
    (0x116DDCA3, "e91840a1fe"),
)

CHILD_SUFFIX_INSTRUCTIONS = (
    (0x100DF46D, "ffb42418040000"),
    (0x100DF474, "893d40319f11"),
    (0x100DF47A, "e8c18d0000"),
    (0x100DF47F, "8d4868"),
    (0x100DF482, "e8c9320100"),
    (0x100DF487, "8bcf"),
    (0x100DF489, "e842b00000"),
)

SOURCE_PARENT_INSTRUCTIONS = (
    (0x100ED42C, "8b44241c"),
    (0x100ED430, "8d4c2428"),
    (0x100ED434, "ffb42418090000"),
    (0x100ED43B, "89442458"),
    (0x100ED43F, "8a442424"),
    (0x100ED443, "8844245c"),
    (0x100ED447, "8b442428"),
    (0x100ED44B, "89442460"),
    (0x100ED44F, "c644246400"),
    (0x100ED454, "e857470000"),
    (0x100ED459, "50"),
    (0x100ED45A, "8d442438"),
    (0x100ED45E, "50"),
    (0x100ED45F, "8d4c246c"),
    (0x100ED463, "e8081effff"),
    (0x100ED468, "8d4c2428"),
    (0x100ED46C, "e84f480000"),
)

REPLACEMENT_BLOCKS = (
    (0x100F278A, 0x100F279F),
    (0x100F279F, 0x100F27BE),
    (0x100F27BE, 0x100F27C2),
    (0x100F27C2, 0x100F27C9),
    (0x100F27C9, 0x100F27D7),
    (0x100F27D7, 0x100F27DB),
    (0x100F27DB, 0x100F27E3),
    (0x100F27E3, REPLACEMENT_END),
)
REPLACEMENT_EDGES = (
    (0x100F278A, 0x100F279F, "helper_returned_normally"),
    (0x100F279F, 0x100F27E3, "old_payload_is_sentinel"),
    (0x100F279F, 0x100F27BE, "old_payload_not_sentinel"),
    (0x100F27BE, 0x100F27E3, "old_payload_null"),
    (0x100F27BE, 0x100F27C2, "old_payload_nonnull"),
    (0x100F27C2, 0x100F27E3, "old_raw_zero"),
    (0x100F27C2, 0x100F27C9, "old_raw_nonzero"),
    (0x100F27C9, 0x100F27D7, "release_returned"),
    (0x100F27D7, 0x100F27E3, "hook_null"),
    (0x100F27D7, 0x100F27DB, "hook_nonnull"),
    (0x100F27DB, 0x100F27E3, "hook_returned"),
    (0x100F27E3, "RETURN", "epilogue"),
)

CANONICAL_INDEX_SIZE = 8_344_450
CANONICAL_INDEX_SHA256 = (
    "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
)
CANONICAL_HASHES = {
    "100df270": "9309918694adc92b151210f40eeb1965a144d68b24967a9aa160ecdf8517de72",
    "100e8240": "aa030e847e3d0ab772c70c11a58d36c9a14680f3d5cf357f4b9066a9d53b551b",
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
    "100ef330": "cd306dafa21f1ceeaf16c4f66840cab347d12a264baaa80b690dba6f7ab58f3b",
    "100f1c10": "ec3103cb0e6c9060bdb7a027949e496a9a4e81dc13ec5d3918638feeea071ed7",
    "100f1cc0": "8cd70d65677361ef62405e7621495b03ddb3901696a4a01c429ff609bc4b4a69",
    "100f2750": "16c0b2bd1980f7c8870b9a74720c17df25b4f8a883e56f3ba2a4a5eff68f706b",
    "10124e50": "e866eb4e0e99eaa548d8c8d41e47a07defd1e0e5c594b7d6fa2c1cd2cd456225",
    "116838ea": "2271c42adcc0961b9eca6ed6fa115569785ac5b1ac94b8a58e9acbb93d7a7d23",
}
CANONICAL_ROWS = {
    "100df270": ("decomp_fn_100df270", "FUN_100df270", "640", "100df270-100df4ef"),
    "100e8240": ("decomp_fn_100e8240", "FUN_100e8240", "310", "100e8240-100e8375"),
    "100ed3c0": ("decomp_fn_100ed3c0", "FUN_100ed3c0", "400", "100ed3c0-100ed54f"),
    "100ef330": ("decomp_fn_100ef330", "FUN_100ef330", "124", "100ef330-100ef3ab"),
    "100f1c10": ("decomp_fn_100f1c10", "FUN_100f1c10", "23", "100f1c10-100f1c26"),
    "100f1cc0": ("decomp_fn_100f1cc0", "FUN_100f1cc0", "51", "100f1cc0-100f1cf2"),
    "100f2750": ("decomp_fn_100f2750", "FUN_100f2750", "157", "100f2750-100f27ec"),
    "10124e50": ("decomp_fn_10124e50", "FUN_10124e50", "1613", "10124e50-1012549c"),
    "116838ea": ("decomp_fn_116838ea", "_atexit", "21", "116838ea-116838fe"),
}

MAX_UNITS = 32_767
MAX_ALLOCATION_BYTES = MAX_UNITS * 2 + 10
DESTINATION_SENTINEL_DESCRIPTOR = (0, 0, EMPTY_SENTINEL)
DESTINATION_SENTINEL_OWNER = (0, 0, 0, 0, 0, 0, 0)

REGISTRATION_ORDER = (
    "VALIDATE_UNREGISTERED_SENTINEL_STATE",
    "REGISTER_TYPED_HOST_TEARDOWN",
    "PUBLISH_REGISTERED_SENTINEL",
)
FIRST_USE_SUCCESS_ORDER = (
    "VALIDATE_SOURCE_LIVE_AND_DESTINATION_REGISTERED_SENTINEL",
    "ALLOCATE_DISTINCT_DESTINATION_GRANT",
    "VALIDATE_GRANT_MAPPING_LAYOUT_DISJOINTNESS",
    "WRITE_DESTINATION_RAW_HEADER",
    "COPY_SOURCE_N_UNITS",
    "WRITE_DESTINATION_ZERO_TERMINATOR",
    "COMMIT_DESTINATION_DESCRIPTOR",
    "COMMIT_DESTINATION_OWNER_LIVE",
    "COMMIT_DESTINATION_RETURN_LAST",
)
INVALID_GRANT_ORDER = (
    "ALLOCATE_DESTINATION_GRANT",
    "VALIDATE_NONCOLLIDING_GRANT_REJECT",
    "RELEASE_EXACT_COMPENSATION",
)
TOKEN_COLLISION_ORDER = (
    "ALLOCATE_DESTINATION_GRANT",
    "DETECT_SOURCE_TOKEN_COLLISION",
    "RETURN_EFFECT_PROTOCOL_INVALID_WITHOUT_RELEASE",
)
TEARDOWN_ORDER = (
    "VALIDATE_REGISTERED_LIVE_OWNER_AND_DESCRIPTOR",
    "COMMIT_PERSISTENT_OWNER_CONSUMED",
    "RELEASE_EXACT_PERSISTENT_GRANT",
    "OPTIONAL_TYPED_RAW_ZERO_HOOK",
)

INTENDED_MODEL = {
    "source_length_domain": (1, MAX_UNITS),
    "maximum_allocation_bytes": MAX_ALLOCATION_BYTES,
    "persistent_guest_identity": PERSISTENT_DESCRIPTOR,
    "persistent_initial_descriptor": DESTINATION_SENTINEL_DESCRIPTOR,
    "persistent_initial_owner": DESTINATION_SENTINEL_OWNER,
    "lifecycle": "REGISTERED_SENTINEL_to_REGISTERED_LIVE_to_CONSUMED",
    "typed_teardown_registration_required_before_live": True,
    "native_atexit_registration": False,
    "source_owner_initial_phase": "LIVE",
    "persistent_owner_initial_phase": "NO_AUTHORITY",
    "owner_records": "separate_source_and_persistent",
    "source_token_transfer": False,
    "source_release_during_replacement": False,
    "source_mutation": False,
    "destination_allocation_count": 1,
    "destination_allocation_size": "checked_2n_plus_10",
    "destination_allocation_class": 0,
    "destination_token_policy": "globally_unique_one_shot_and_not_source_token",
    "token_collision": "EFFECT_PROTOCOL_INVALID_no_compensation_no_guest_output_mutation",
    "other_invalid_nonzero_grant": "exactly_one_exact_tuple_compensation",
    "compensation_hook": False,
    "sentinel_old_release_count": 0,
    "success_source_preservation": "descriptor_allocation_owner_byte_exact",
    "failure_preservation": "both_descriptors_allocations_owners_return_unchanged_except_context",
    "destination_commit": "header_payload_zero_descriptor_owner_return",
    "teardown_authority": "private_persistent_LIVE_owner",
    "teardown_payload_revalidation": False,
    "teardown_guest_mutation": False,
    "teardown_one_shot": True,
    "preallocated_route": False,
    "live_to_live_route": False,
    "original_pc_execution": False,
    "native_allocator_or_releaser": False,
    "mutable_global_hook_read": False,
    "parent_execution": False,
    "build_integration": "BUILD_TESTING_ONLY",
}

HARD_EXCLUSIONS = (
    "execute_original_100f2750_100ef330_100f1c10_100f1cc0_10124e50_or_116ddc80",
    "invoke_native_allocator_releaser_atexit_onexit_or_process_hook",
    "read_or_invoke_mutable_global_119f3eb0",
    "convert_guest_identity_to_native_pointer_or_function_pointer",
    "unchecked_guest32_size_alignment_host_or_alias_arithmetic",
    "unbounded_utf16_scan_or_original_fault_throw_unwind_behavior",
    "transfer_consume_release_or_mutate_source_owner_during_replacement",
    "accept_destination_token_equal_to_live_source_token",
    "compensate_a_source_token_collision",
    "release_or_read_metadata_before_the_old_sentinel",
    "publish_live_persistent_owner_without_typed_teardown_registration",
    "treat_guest_descriptor_or_metadata_as_release_authority",
    "release_persistent_owner_twice_or_hook_during_compensation",
    "admit_preallocated_or_live_to_live_replacement_route",
    "execute_100ed3c0_100df270_100e8240_or_100ea4d0",
    "add_cmake_headless_export_or_production_linkage",
)

DOC_SIZE = 12_022
DOC_SHA256 = "186606cf107b39340a01181505f4f1ffeb58d28c4fc1fffe7025970e3ae17b6a"


class EvidenceError(ValueError):
    """A candidate differs from the authenticated finite boundary."""


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


def read_va(
    data: bytes, pe: dict[str, object], va: int, size: int
) -> tuple[bytes, str, int]:
    if va < IMAGE_BASE or size < 0:
        raise EvidenceError("invalid VA request")
    rva = va - IMAGE_BASE
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size, _flags in pe["sections"]:
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise EvidenceError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset:offset + size], name, offset


def virtual_section(pe: dict[str, object], va: int, size: int):
    if va < IMAGE_BASE or size <= 0:
        raise EvidenceError("invalid virtual interval")
    rva = va - IMAGE_BASE
    matches = []
    for section in pe["sections"]:
        _name, section_rva, virtual_size, _raw_offset, _raw_size, _flags = section
        delta = rva - section_rva
        if delta >= 0 and delta <= virtual_size and size <= virtual_size - delta:
            matches.append((section, delta))
    if len(matches) != 1:
        raise EvidenceError(f"VA 0x{va:08x} has {len(matches)} virtual mappings")
    return matches[0]


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 5, f"rel32 at 0x{instruction_va:08x}")
    if body[offset] not in (0xE8, 0xE9):
        raise EvidenceError(f"0x{instruction_va:08x} is not E8/E9 rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


def short_jcc_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 2, f"short Jcc at 0x{instruction_va:08x}")
    if not 0x70 <= body[offset] <= 0x7F:
        raise EvidenceError(f"0x{instruction_va:08x} is not a short Jcc")
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return instruction_va + 2 + displacement


def require_partition(
    body: bytes, start: int, end: int, instructions: tuple[tuple[int, str], ...]
) -> None:
    cursor = start
    for va, encoded in instructions:
        chunk = bytes.fromhex(encoded)
        if va != cursor:
            raise EvidenceError(f"instruction partition gap at 0x{cursor:08x}")
        offset = va - start
        if body[offset:offset + len(chunk)] != chunk:
            raise EvidenceError(f"instruction changed at 0x{va:08x}")
        cursor += len(chunk)
    if cursor != end or len(body) != end - start:
        raise EvidenceError("instruction partition does not cover the interval")


def validate_replacement_candidate(candidate: bytes) -> None:
    require_authority(
        candidate, len(REPLACEMENT_BYTES), REPLACEMENT_SHA256, "replacement"
    )
    if candidate != REPLACEMENT_BYTES:
        raise EvidenceError("replacement bytes changed despite digest collision")
    require_partition(
        candidate, REPLACEMENT_VA, REPLACEMENT_END, REPLACEMENT_INSTRUCTIONS
    )
    if (
        rel32_target(candidate, REPLACEMENT_VA, 0x100F279A) != HELPER_VA
        or short_jcc_target(candidate, REPLACEMENT_VA, 0x100F27BC) != 0x100F27E3
        or rel32_target(candidate, REPLACEMENT_VA, 0x100F27CA) != RELEASE_VA
    ):
        raise EvidenceError("replacement call or first-use branch changed")


def validate_cfg(blocks, edges) -> None:
    if tuple(blocks) != REPLACEMENT_BLOCKS or tuple(edges) != REPLACEMENT_EDGES:
        raise EvidenceError("replacement CFG changed")


def allocation_layout(length_units: int, raw: int):
    if not 1 <= length_units <= MAX_UNITS or not 1 <= raw <= 0xFFFFFFFF:
        raise EvidenceError("allocation inputs outside the finite domain")
    size = length_units * 2 + 10
    if raw + size > ADDRESS_SPACE_SIZE:
        raise EvidenceError("raw allocation crosses the guest32 endpoint")
    payload = (raw + 8) & ~3
    header = payload - 4
    terminator = payload + length_units * 2
    end = terminator + 2
    if (
        payload > 0xFFFFFFFF
        or header < raw
        or end > raw + size
        or end > ADDRESS_SPACE_SIZE
    ):
        raise EvidenceError("authenticated helper layout is not contained")
    return size, header, payload, terminator, end


def validate_model(
    model: dict[str, object], exclusions,
    registration_order=REGISTRATION_ORDER,
    success_order=FIRST_USE_SUCCESS_ORDER,
    invalid_order=INVALID_GRANT_ORDER,
    collision_order=TOKEN_COLLISION_ORDER,
    teardown_order=TEARDOWN_ORDER,
) -> None:
    if model != INTENDED_MODEL:
        raise EvidenceError("finite intended model changed")
    if tuple(exclusions) != HARD_EXCLUSIONS:
        raise EvidenceError("hard exclusions changed")
    if tuple(registration_order) != REGISTRATION_ORDER:
        raise EvidenceError("registration order changed")
    if tuple(success_order) != FIRST_USE_SUCCESS_ORDER:
        raise EvidenceError("first-use success order changed")
    if tuple(invalid_order) != INVALID_GRANT_ORDER:
        raise EvidenceError("invalid-grant compensation order changed")
    if tuple(collision_order) != TOKEN_COLLISION_ORDER:
        raise EvidenceError("token-collision order changed")
    if tuple(teardown_order) != TEARDOWN_ORDER:
        raise EvidenceError("teardown order changed")
    if "RELEASE" in " ".join(TOKEN_COLLISION_ORDER[:-1]):
        raise EvidenceError("token collision acquired release authority")
    if TOKEN_COLLISION_ORDER[-1] != "RETURN_EFFECT_PROTOCOL_INVALID_WITHOUT_RELEASE":
        raise EvidenceError("token collision no-release status changed")


def mutated(data: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(data):
        raise EvidenceError("mutant offset outside body")
    candidate = bytearray(data)
    candidate[offset] ^= 1
    return bytes(candidate)


class Startup100f2750SentinelOwnedProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        require_authority(cls.dll, DLL_SIZE, DLL_SHA256, "original DLL")
        cls.pe = parse_pe32(cls.dll)

    def test_pe_sections_and_all_exact_windows_are_pinned(self):
        sections = {section[0]: section for section in self.pe["sections"]}
        self.assertEqual(sections[".text"], TEXT_SECTION)
        self.assertEqual(sections[".data"], DATA_SECTION)
        windows = (
            (BODY_VA, BODY_BYTES, BODY_RAW, BODY_SHA256, "100f2750 body"),
            (REPLACEMENT_VA, REPLACEMENT_BYTES, REPLACEMENT_RAW,
             REPLACEMENT_SHA256, "100f2750 replacement"),
            (HELPER_VA, HELPER_BYTES, HELPER_RAW, HELPER_SHA256,
             "100ef330 helper"),
            (INIT_LEAF_VA, INIT_LEAF_BYTES, INIT_LEAF_RAW, INIT_LEAF_SHA256,
             "100f1c10 initializer"),
            (INIT_REGISTER_VA, INIT_REGISTER_BYTES, INIT_REGISTER_RAW,
             INIT_REGISTER_SHA256, "100e82e7 init/register"),
            (DESTRUCTOR_VA, DESTRUCTOR_BYTES, DESTRUCTOR_RAW,
             DESTRUCTOR_SHA256, "116ddc80 destructor"),
            (ATEXIT_VA, ATEXIT_BYTES, ATEXIT_RAW, ATEXIT_SHA256,
             "116838ea atexit"),
            (CHILD_SUFFIX_VA, CHILD_SUFFIX_BYTES, CHILD_SUFFIX_RAW,
             CHILD_SUFFIX_SHA256, "100df270 suffix"),
            (SOURCE_PARENT_VA, SOURCE_PARENT_BYTES, SOURCE_PARENT_RAW,
             SOURCE_PARENT_SHA256, "100ed3c0 source parent"),
        )
        for va, expected, raw, digest, label in windows:
            actual, section, offset = read_va(self.dll, self.pe, va, len(expected))
            self.assertEqual((section, offset), (".text", raw), label)
            self.assertEqual(actual, expected, label)
            require_authority(actual, len(expected), digest, label)
        require_authority(
            FIRST_USE_COMMIT_BYTES, 52, FIRST_USE_COMMIT_SHA256,
            "first-use build/commit window",
        )
        cleanup, section, offset = read_va(
            self.dll, self.pe, CLEANUP_VA, len(CLEANUP_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000F10C0))
        self.assertEqual(cleanup, CLEANUP_BYTES)
        self.assertEqual(sha256(cleanup), CLEANUP_SHA256)

    def test_replacement_cfg_calls_commit_order_and_first_use_are_exact(self):
        validate_replacement_candidate(REPLACEMENT_BYTES)
        validate_cfg(REPLACEMENT_BLOCKS, REPLACEMENT_EDGES)
        require_partition(
            REPLACEMENT_BYTES, REPLACEMENT_VA, REPLACEMENT_END,
            REPLACEMENT_INSTRUCTIONS,
        )
        self.assertEqual(BODY_BYTES[0x0B:0x12], bytes.fromhex("8b073b46047728"))
        self.assertEqual(short_jcc_target(BODY_BYTES, BODY_VA, 0x100F2760),
                         REPLACEMENT_VA)
        self.assertEqual(BODY_BYTES[0x10], 0x77, "capacity branch is not JA")
        for count in (1, 2, 17, MAX_UNITS):
            self.assertGreater(count, DESTINATION_SENTINEL_DESCRIPTOR[1])
        order_tokens = (
            bytes.fromhex("8b4f08"),
            bytes.fromhex("8d0441"),
            bytes.fromhex("e891cbffff"),
            bytes.fromhex("8b4424088906"),
            bytes.fromhex("8b44240c894604"),
            bytes.fromhex("8b7e08"),
            bytes.fromhex("8b442410894608"),
            bytes.fromhex("81ff9040af117425"),
        )
        positions = [REPLACEMENT_BYTES.index(token) for token in order_tokens]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(rel32_target(
            REPLACEMENT_BYTES, REPLACEMENT_VA, 0x100F279A), HELPER_VA)
        self.assertEqual(short_jcc_target(
            REPLACEMENT_BYTES, REPLACEMENT_VA, 0x100F27BC), 0x100F27E3)
        self.assertNotIn(bytes.fromhex("e881260300"), FIRST_USE_COMMIT_BYTES)
        self.assertNotIn(bytes.fromhex("a1b03e9f11"), FIRST_USE_COMMIT_BYTES)
        self.assertNotIn(bytes.fromhex("ffd0"), FIRST_USE_COMMIT_BYTES)

    def test_helper_layout_allocation_and_copy_shape_are_exact(self):
        self.assertEqual(len(HELPER_BYTES), HELPER_END - HELPER_VA)
        self.assertEqual(rel32_target(HELPER_BYTES, HELPER_VA, 0x100EF354),
                         ALLOCATOR_VA)
        helper_tokens = (
            bytes.fromhex("8b07894704"),
            bytes.fromhex("8d04450a000000"),
            bytes.fromhex("6a0050e827d90000"),
            bytes.fromhex("8d700883e6fc"),
            bytes.fromhex("8946fc"),
            bytes.fromhex("897708"),
            bytes.fromhex("66894c06fe"),
            bytes.fromhex("66a18c40af116689044e"),
        )
        positions = [HELPER_BYTES.index(token) for token in helper_tokens]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(MAX_ALLOCATION_BYTES, 0x10008)
        for count in (1, 2, 17, MAX_UNITS):
            for residue in range(4):
                raw = 0x00100000 + residue
                size, header, payload, terminator, end = allocation_layout(
                    count, raw
                )
                self.assertEqual(size, count * 2 + 10)
                self.assertEqual(payload & 3, 0)
                self.assertEqual(header, payload - 4)
                self.assertEqual(terminator, payload + count * 2)
                self.assertLessEqual(end, raw + size)
        with self.assertRaises(EvidenceError):
            allocation_layout(0, 0x1000)
        with self.assertRaises(EvidenceError):
            allocation_layout(MAX_UNITS + 1, 0x1000)
        with self.assertRaises(EvidenceError):
            allocation_layout(1, 0xFFFFFFF8)

    def test_persistent_initializer_bss_identity_and_registration_are_exact(self):
        require_partition(
            INIT_LEAF_BYTES, INIT_LEAF_VA, INIT_LEAF_END,
            INIT_LEAF_INSTRUCTIONS,
        )
        require_partition(
            INIT_REGISTER_BYTES, INIT_REGISTER_VA, INIT_REGISTER_END,
            INIT_REGISTER_INSTRUCTIONS,
        )
        self.assertEqual(INIT_SITE_BYTES, INIT_REGISTER_BYTES[:10])
        self.assertEqual(sha256(INIT_SITE_BYTES), INIT_SITE_SHA256)
        self.assertEqual(rel32_target(
            INIT_REGISTER_BYTES, INIT_REGISTER_VA, 0x100E82EC), INIT_LEAF_VA)
        self.assertEqual(
            INIT_REGISTER_BYTES[0:5], b"\xb9" + PERSISTENT_LITERAL
        )
        self.assertEqual(
            INIT_REGISTER_BYTES[0x16:0x1B],
            b"\x68" + struct.pack("<I", DESTRUCTOR_VA),
        )
        self.assertEqual(rel32_target(
            INIT_REGISTER_BYTES, INIT_REGISTER_VA, 0x100E835E), ATEXIT_VA)
        between_push_and_call = tuple(
            bytes.fromhex(encoded)
            for va, encoded in INIT_REGISTER_INSTRUCTIONS
            if 0x100E8302 <= va < 0x100E835E
        )
        self.assertFalse(any(
            instruction[0] in {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                               0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
                               0x5E, 0x5F}
            or instruction.startswith(bytes.fromhex("83c4"))
            for instruction in between_push_and_call
        ))

        section, delta = virtual_section(
            self.pe, PERSISTENT_DESCRIPTOR, 12
        )
        self.assertEqual(section, DATA_SECTION)
        self.assertGreaterEqual(delta, DATA_SECTION[4])
        self.assertLessEqual(delta + 12, DATA_SECTION[2])
        with self.assertRaises(EvidenceError):
            read_va(self.dll, self.pe, PERSISTENT_DESCRIPTOR, 12)

        offsets = []
        cursor = 0
        while True:
            cursor = self.dll.find(PERSISTENT_LITERAL, cursor)
            if cursor < 0:
                break
            offsets.append(cursor)
            cursor += 1
        self.assertEqual(tuple(offsets), PERSISTENT_LITERAL_RAW_OFFSETS)
        self.assertEqual(DESTINATION_SENTINEL_DESCRIPTOR,
                         (0, 0, EMPTY_SENTINEL))

    def test_registered_destructor_cleans_persistent_first_and_is_native_only(self):
        require_partition(
            DESTRUCTOR_BYTES, DESTRUCTOR_VA, DESTRUCTOR_END,
            DESTRUCTOR_INSTRUCTIONS,
        )
        descriptors = tuple(
            struct.unpack_from("<I", DESTRUCTOR_BYTES, offset)[0]
            for offset in (1, 11, 21, 31)
        )
        self.assertEqual(descriptors, DESTRUCTOR_DESCRIPTORS)
        for site in (0x116DDC85, 0x116DDC8F, 0x116DDC99, 0x116DDCA3):
            self.assertEqual(
                rel32_target(DESTRUCTOR_BYTES, DESTRUCTOR_VA, site),
                CLEANUP_VA,
            )
        self.assertEqual(DESTRUCTOR_BYTES[0x23], 0xE9,
                         "last cleanup is not the authenticated tail jump")
        self.assertEqual(rel32_target(ATEXIT_BYTES, ATEXIT_VA, 0x116838F0),
                         ONEXIT_VA)
        self.assertEqual(ATEXIT_BYTES[-1:], b"\xc3")
        self.assertNotEqual(ATEXIT_VA, 0)
        self.assertFalse(INTENDED_MODEL["native_atexit_registration"])

    def test_child_derivation_and_separate_source_lifetime_are_exact(self):
        require_partition(
            CHILD_SUFFIX_BYTES, CHILD_SUFFIX_VA,
            CHILD_SUFFIX_VA + len(CHILD_SUFFIX_BYTES),
            CHILD_SUFFIX_INSTRUCTIONS,
        )
        self.assertEqual(rel32_target(
            CHILD_SUFFIX_BYTES, CHILD_SUFFIX_VA, 0x100DF47A), FAST_OR_INIT_VA)
        self.assertEqual(CHILD_SUFFIX_BYTES[0x12:0x15], bytes.fromhex("8d4868"))
        self.assertEqual(CRASH_RECORD + PERSISTENT_DELTA, PERSISTENT_DESCRIPTOR)
        self.assertEqual(rel32_target(
            CHILD_SUFFIX_BYTES, CHILD_SUFFIX_VA, 0x100DF482), BODY_VA)
        self.assertEqual(rel32_target(
            CHILD_SUFFIX_BYTES, CHILD_SUFFIX_VA, 0x100DF489), FOLLOWING_VA)

        require_partition(
            SOURCE_PARENT_BYTES, SOURCE_PARENT_VA, SOURCE_PARENT_END,
            SOURCE_PARENT_INSTRUCTIONS,
        )
        calls = (
            (0x100ED454, SOURCE_BUILDER_VA),
            (0x100ED463, CHILD_VA),
            (0x100ED46C, CLEANUP_VA),
        )
        for site, target in calls:
            self.assertEqual(
                rel32_target(SOURCE_PARENT_BYTES, SOURCE_PARENT_VA, site),
                target,
            )
        self.assertEqual([site for site, _target in calls],
                         sorted(site for site, _target in calls))
        self.assertEqual(INTENDED_MODEL["owner_records"],
                         "separate_source_and_persistent")
        self.assertFalse(INTENDED_MODEL["source_token_transfer"])
        self.assertFalse(INTENDED_MODEL["source_release_during_replacement"])

    def test_canonical_sources_and_index_rows_are_exact_cross_checks(self):
        for entry, digest in CANONICAL_HASHES.items():
            source = CANONICAL / f"decomp_fn_{entry}.c"
            self.assertEqual(sha256(source.read_bytes()), digest, entry)
        index = CANONICAL_INDEX.read_bytes()
        require_authority(
            index, CANONICAL_INDEX_SIZE, CANONICAL_INDEX_SHA256,
            "canonical function index",
        )
        rows = list(csv.DictReader(
            index.decode("utf-8").splitlines(), delimiter="\t"
        ))
        by_entry = {row["entry"]: row for row in rows}
        for entry, expected in CANONICAL_ROWS.items():
            row = by_entry[entry]
            self.assertEqual(
                (
                    row["canonical_name"], row["original_name"],
                    row["size"], row["body_ranges"],
                ),
                expected,
                entry,
            )
        replacement = (CANONICAL / "decomp_fn_100f2750.c").read_text(
            encoding="utf-8"
        )
        tokens = (
            "uVar1 = *param_2;",
            "if (param_1[1] < uVar1)",
            "decomp_fn_100ef330(param_2[2],param_2[2] + uVar1 * 2);",
            "*param_1 = uVar1;",
            "param_1[1] = local_8;",
            "puVar2 = (undefined2 *)param_1[2];",
            "param_1[2] = local_4;",
            "puVar2 != &DAT_11af4090",
        )
        positions = [replacement.index(token) for token in tokens]
        self.assertEqual(positions, sorted(positions))

    def test_finite_model_collision_compensation_and_teardown_are_fail_closed(self):
        validate_model(dict(INTENDED_MODEL), HARD_EXCLUSIONS)
        self.assertEqual(INTENDED_MODEL["source_length_domain"], (1, 32_767))
        self.assertEqual(INTENDED_MODEL["maximum_allocation_bytes"], 0x10008)
        self.assertEqual(INTENDED_MODEL["sentinel_old_release_count"], 0)
        self.assertEqual(
            INTENDED_MODEL["destination_token_policy"],
            "globally_unique_one_shot_and_not_source_token",
        )
        self.assertIn("no_compensation", INTENDED_MODEL["token_collision"])
        self.assertNotIn("RELEASE_EXACT_COMPENSATION", TOKEN_COLLISION_ORDER)
        self.assertEqual(INVALID_GRANT_ORDER.count(
            "RELEASE_EXACT_COMPENSATION"), 1)
        self.assertNotIn("HOOK", " ".join(INVALID_GRANT_ORDER))
        self.assertLess(
            TEARDOWN_ORDER.index("COMMIT_PERSISTENT_OWNER_CONSUMED"),
            TEARDOWN_ORDER.index("RELEASE_EXACT_PERSISTENT_GRANT"),
        )
        self.assertTrue(
            INTENDED_MODEL["typed_teardown_registration_required_before_live"]
        )
        self.assertFalse(INTENDED_MODEL["preallocated_route"])
        self.assertFalse(INTENDED_MODEL["live_to_live_route"])
        self.assertFalse(INTENDED_MODEL["original_pc_execution"])
        self.assertEqual(
            INTENDED_MODEL["build_integration"], "BUILD_TESTING_ONLY"
        )

    def test_documentation_matches_exact_evidence_and_collision_policy(self):
        doc = DOC.read_bytes()
        require_authority(doc, DOC_SIZE, DOC_SHA256, "focused evidence doc")
        text = doc.decode("utf-8")
        for token in (
            "No original address is executable",
            "`0x119f3aa0`",
            "`0x11af4090`",
            BODY_SHA256,
            REPLACEMENT_SHA256,
            HELPER_SHA256,
            INIT_REGISTER_SHA256,
            DESTRUCTOR_SHA256,
            "`2*N+10`",
            "`(raw+8)&~3`",
            "`SENTINEL -> LIVE`",
            "## Separate source and destination ownership",
            "differ from the still-`LIVE` source token",
            "`EFFECT_PROTOCOL_INVALID` with no compensating release",
            "Globally unique one-shot tokens",
            "`CONSUMED` before the exact injected release",
            "standalone `BUILD_TESTING` target",
            "no current input can reach that\nrollback",
            "Preallocated assignment and `LIVE -> LIVE` replacement",
        ):
            self.assertIn(token, text)

    def test_reciprocal_instruction_cfg_model_and_order_mutants_fail(self):
        mutant_count = 0
        for va, _encoded in REPLACEMENT_INSTRUCTIONS:
            with self.assertRaises(EvidenceError, msg=f"0x{va:08x}"):
                validate_replacement_candidate(
                    mutated(REPLACEMENT_BYTES, va - REPLACEMENT_VA)
                )
            mutant_count += 1
        for body, start, partition, end in (
            (INIT_LEAF_BYTES, INIT_LEAF_VA, INIT_LEAF_INSTRUCTIONS,
             INIT_LEAF_END),
            (INIT_REGISTER_BYTES, INIT_REGISTER_VA,
             INIT_REGISTER_INSTRUCTIONS, INIT_REGISTER_END),
            (DESTRUCTOR_BYTES, DESTRUCTOR_VA, DESTRUCTOR_INSTRUCTIONS,
             DESTRUCTOR_END),
            (CHILD_SUFFIX_BYTES, CHILD_SUFFIX_VA, CHILD_SUFFIX_INSTRUCTIONS,
             CHILD_SUFFIX_VA + len(CHILD_SUFFIX_BYTES)),
            (SOURCE_PARENT_BYTES, SOURCE_PARENT_VA, SOURCE_PARENT_INSTRUCTIONS,
             SOURCE_PARENT_END),
        ):
            for va, _encoded in partition:
                with self.assertRaises(EvidenceError, msg=f"0x{va:08x}"):
                    require_partition(mutated(body, va - start), start, end,
                                      partition)
                mutant_count += 1
        mutant_edges = list(REPLACEMENT_EDGES)
        mutant_edges.pop()
        with self.assertRaises(EvidenceError):
            validate_cfg(REPLACEMENT_BLOCKS, mutant_edges)
        mutant_count += 1
        mutant_blocks = list(REPLACEMENT_BLOCKS)
        mutant_blocks[1] = (mutant_blocks[1][0], mutant_blocks[1][1] - 1)
        with self.assertRaises(EvidenceError):
            validate_cfg(mutant_blocks, REPLACEMENT_EDGES)
        mutant_count += 1

        model_mutants = (
            ("source_length_domain", (0, MAX_UNITS)),
            ("persistent_guest_identity", PERSISTENT_DESCRIPTOR + 4),
            ("owner_records", "one_transferred_owner"),
            ("source_token_transfer", True),
            ("source_release_during_replacement", True),
            ("destination_allocation_count", 2),
            ("destination_token_policy", "token_may_equal_source"),
            ("token_collision", "compensate_then_fail"),
            ("other_invalid_nonzero_grant", "leak_then_fail"),
            ("compensation_hook", True),
            ("sentinel_old_release_count", 1),
            ("typed_teardown_registration_required_before_live", False),
            ("native_atexit_registration", True),
            ("preallocated_route", True),
            ("live_to_live_route", True),
            ("original_pc_execution", True),
            ("build_integration", "HEADLESS_OR_PRODUCTION"),
        )
        for key, value in model_mutants:
            candidate = dict(INTENDED_MODEL)
            candidate[key] = value
            with self.assertRaises(EvidenceError, msg=key):
                validate_model(candidate, HARD_EXCLUSIONS)
            mutant_count += 1
        for orders in (
            (REGISTRATION_ORDER[:-1], FIRST_USE_SUCCESS_ORDER,
             INVALID_GRANT_ORDER, TOKEN_COLLISION_ORDER, TEARDOWN_ORDER),
            (REGISTRATION_ORDER, FIRST_USE_SUCCESS_ORDER[:-1],
             INVALID_GRANT_ORDER, TOKEN_COLLISION_ORDER, TEARDOWN_ORDER),
            (REGISTRATION_ORDER, FIRST_USE_SUCCESS_ORDER,
             INVALID_GRANT_ORDER[:-1], TOKEN_COLLISION_ORDER, TEARDOWN_ORDER),
            (REGISTRATION_ORDER, FIRST_USE_SUCCESS_ORDER,
             INVALID_GRANT_ORDER,
             TOKEN_COLLISION_ORDER + ("RELEASE_EXACT_COMPENSATION",),
             TEARDOWN_ORDER),
            (REGISTRATION_ORDER, FIRST_USE_SUCCESS_ORDER,
             INVALID_GRANT_ORDER, TOKEN_COLLISION_ORDER,
             (
                 "VALIDATE_REGISTERED_LIVE_OWNER_AND_DESCRIPTOR",
                 "RELEASE_EXACT_PERSISTENT_GRANT",
                 "COMMIT_PERSISTENT_OWNER_CONSUMED",
                 "OPTIONAL_TYPED_RAW_ZERO_HOOK",
             )),
        ):
            with self.assertRaises(EvidenceError):
                validate_model(
                    dict(INTENDED_MODEL), HARD_EXCLUSIONS,
                    orders[0], orders[1], orders[2], orders[3], orders[4],
                )
            mutant_count += 1
        exclusions = list(HARD_EXCLUSIONS)
        exclusions.remove("compensate_a_source_token_collision")
        with self.assertRaises(EvidenceError):
            validate_model(dict(INTENDED_MODEL), exclusions)
        mutant_count += 1
        self.assertEqual(mutant_count, 115)

    def test_oracle_is_standard_library_only_and_performs_no_writes(self):
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
