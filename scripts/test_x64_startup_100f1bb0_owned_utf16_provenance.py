#!/usr/bin/env python3
"""Authenticate the owned UTF-16 descriptor and owning-cleanup evidence.

The original PE is parsed only as inert bytes.  No recovered instruction or
original address is executed.  The proposed native model is a finite injected
projection, not a recovered callable ABI.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
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
IMPORTS = ROOT / "pe_meta" / "empire.retail_imports.json"
DOC = ROOT / "docs" / "x64_startup_100f1bb0_owned_utf16.md"

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

WRAPPER_VA = 0x100F1BB0
WRAPPER_END = 0x100F1BE5
WRAPPER_RAW = 0x000F0FB0
WRAPPER_BYTES = bytes.fromhex(
    "568b7424088bc6578bf9660f1f4400000fb71083c0026685d275f52bc683e802"
    "d1f889078d04465056e852d7ffff8bc75f5ec20400"
)
WRAPPER_SHA256 = "94088db58e056bb26dba6ce27d33c6353afce3b9300dfa63810c813dd115b2eb"
SCAN_VA = 0x100F1BC0
SCAN_END = 0x100F1BD2
SCAN_SHA256 = "aba7a7430b421914b8b6d6c603995dbbc06c93b0b97de47d61bb633e889c5555"
WRAPPER_TAIL_SHA256 = (
    "57c02430751f1f92aeec0023ca4eff07d363e22d03c33047edad930f63874a64"
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
NONEMPTY_VA = 0x100EF347
NONEMPTY_BYTES = HELPER_BYTES[NONEMPTY_VA - HELPER_VA:]
NONEMPTY_SHA256 = "3eefe45e2edf1ac01217f8e6c2cacb641abf3487d2a5086a930d7e7b12b148e1"

CLEANUP_VA = 0x100F1CC0
CLEANUP_END = 0x100F1CF3
CLEANUP_RAW = 0x000F10C0
CLEANUP_BYTES = bytes.fromhex(
    "568b710881fe9040af11742585f674218b76fc85f6741a56e873310300a1b03e"
    "9f1183c40485c074086a0056ffd083c4085ec3"
)
CLEANUP_SHA256 = "bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4"
OWNING_CLEANUP_VA = 0x100F1CD0
OWNING_CLEANUP_END = 0x100F1CF1
OWNING_CLEANUP_SHA256 = (
    "f0b105a03ba3a9db83e64919dcf949d49226b575bc0d3d04df7884103e8dbcc1"
)

PARENT_VA = 0x100ED3C0
PARENT_SIZE = 400
PARENT_RAW = 0x000EC7C0
PARENT_SHA256 = "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"
PARENT_WINDOW_VA = 0x100ED42C
PARENT_WINDOW_END = 0x100ED471
PARENT_WINDOW_RAW = 0x000EC82C
PARENT_WINDOW_BYTES = bytes.fromhex(
    "8b44241c8d4c2428ffb42418090000894424588a4424248844245c8b44242889"
    "442460c644246400e857470000508d442438508d4c246ce8081effff8d4c2428"
    "e84f480000"
)
PARENT_WINDOW_SHA256 = (
    "8be7ffb391c31778f273fcd94315254c837528f6a5bf0f37004d4513aeb4148d"
)

ALLOCATOR_VA = 0x100FCC80
ALLOCATOR_SIZE = 380
ALLOCATOR_RAW = 0x000FC080
ALLOCATOR_SHA256 = (
    "da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8"
)
ALLOCATOR_CORE_VA = 0x100FCCA2
ALLOCATOR_CORE_END = 0x100FCD17
ALLOCATOR_CORE_SHA256 = (
    "81a52fc1ff30da841103502ffa1fdf18ec17d0f77db42b572945db5c290211d4"
)
ALLOCATOR_FAILURE_VA = 0x100FCCFF
ALLOCATOR_FAILURE_END = 0x100FCD17
ALLOCATOR_FAILURE_BYTES = bytes.fromhex(
    "8d4c241ce8484fffff68e83d92118d44242050e8da1e5c01"
)
ALLOCATOR_FAILURE_SHA256 = (
    "45100b02408c5367aee59bddde0c482df4f5ba0fcbcea2675ee2c30aaac3929b"
)
ALLOCATOR_HOOK_WINDOW_VA = 0x100FCCE6
ALLOCATOR_HOOK_WINDOW = bytes.fromhex(
    "a1b03e9f1185c074075756ffd083c408"
)
ALLOCATOR_HOOK_WINDOW_SHA256 = (
    "3b3c733a35be8150ff7d6b405c5294a5afef98de50fdafcef30a022471d76054"
)

RELEASE_VA = 0x10124E50
RELEASE_SIZE = 1613
RELEASE_RAW = 0x00124250
RELEASE_SHA256 = "6fa1eace89e5d98c429f6b1cbe487ce288afe0b204548a85b5df5a60df32ec96"
RELEASE_PREFIX = bytes.fromhex("83ec1c568b74242485f60f8423060000")
RELEASE_PREFIX_SHA256 = (
    "a7ec7a0d24d4750707702fef916002a0b746142b1a838a565a66023f2344988a"
)
RELEASE_EPILOGUE_VA = 0x1012546E
RELEASE_EPILOGUE = bytes.fromhex(
    "f605bca8af11025f5d5b740933c0b9c0a8af1187015e83c41cc3"
)
RELEASE_EPILOGUE_SHA256 = (
    "c823f7ae03dbb997054315af381f965e8d42d398a50d04eb664c75590411612b"
)

BAD_ALLOC_BUILDER = (
    0x100F1C50, 16, 0x000F1050,
    "4a6020de840331f31b19bf89452940f531ef1c808993ef14b50cb99f999f2991",
)
UNDERLYING_ALLOCATOR = (
    0x101254A0, 724, 0x001248A0,
    "e721483001ed6b5a44bf5eafe118265e35697027be745c8b9dc0f1c7ebab1cf2",
)
CXX_THROW = (
    0x116BEBF1, 109, 0x016BDFF1,
    "ee8234e0abd2474b5ded468c67803c4c7e69bb321afd503c024e6dee23a0443d",
)

TERMINATOR_SOURCE_VA = 0x11AF408C
EMPTY_SENTINEL_VA = 0x11AF4090
ALLOCATOR_HOOK_VA = 0x119F3EB0

WRAPPER_INSTRUCTIONS = (
    (0x100F1BB0, "56"),
    (0x100F1BB1, "8b742408"),
    (0x100F1BB5, "8bc6"),
    (0x100F1BB7, "57"),
    (0x100F1BB8, "8bf9"),
    (0x100F1BBA, "660f1f440000"),
    (0x100F1BC0, "0fb710"),
    (0x100F1BC3, "83c002"),
    (0x100F1BC6, "6685d2"),
    (0x100F1BC9, "75f5"),
    (0x100F1BCB, "2bc6"),
    (0x100F1BCD, "83e802"),
    (0x100F1BD0, "d1f8"),
    (0x100F1BD2, "8907"),
    (0x100F1BD4, "8d0446"),
    (0x100F1BD7, "50"),
    (0x100F1BD8, "56"),
    (0x100F1BD9, "e852d7ffff"),
    (0x100F1BDE, "8bc7"),
    (0x100F1BE0, "5f"),
    (0x100F1BE1, "5e"),
    (0x100F1BE2, "c20400"),
)

HELPER_INSTRUCTIONS = (
    (0x100EF330, "57"),
    (0x100EF331, "8bf9"),
    (0x100EF333, "8b07"),
    (0x100EF335, "894704"),
    (0x100EF338, "85c0"),
    (0x100EF33A, "750b"),
    (0x100EF33C, "c747089040af11"),
    (0x100EF343, "5f"),
    (0x100EF344, "c20800"),
    (0x100EF347, "53"),
    (0x100EF348, "55"),
    (0x100EF349, "56"),
    (0x100EF34A, "8d04450a000000"),
    (0x100EF351, "6a00"),
    (0x100EF353, "50"),
    (0x100EF354, "e827d90000"),
    (0x100EF359, "8b5c2420"),
    (0x100EF35D, "33ed"),
    (0x100EF35F, "83c408"),
    (0x100EF362, "33d2"),
    (0x100EF364, "8d7008"),
    (0x100EF367, "83e6fc"),
    (0x100EF36A, "8946fc"),
    (0x100EF36D, "8b442414"),
    (0x100EF371, "2bd8"),
    (0x100EF373, "43"),
    (0x100EF374, "897708"),
    (0x100EF377, "d1eb"),
    (0x100EF379, "3b442418"),
    (0x100EF37D, "0f47dd"),
    (0x100EF380, "85db"),
    (0x100EF382, "7415"),
    (0x100EF384, "2bf0"),
    (0x100EF386, "668b08"),
    (0x100EF389, "8d4002"),
    (0x100EF38C, "42"),
    (0x100EF38D, "66894c06fe"),
    (0x100EF392, "3bd3"),
    (0x100EF394, "75f0"),
    (0x100EF396, "8b7708"),
    (0x100EF399, "8b0f"),
    (0x100EF39B, "66a18c40af11"),
    (0x100EF3A1, "6689044e"),
    (0x100EF3A5, "5e"),
    (0x100EF3A6, "5d"),
    (0x100EF3A7, "5b"),
    (0x100EF3A8, "5f"),
    (0x100EF3A9, "c20800"),
)

CLEANUP_INSTRUCTIONS = (
    (0x100F1CC0, "56"),
    (0x100F1CC1, "8b7108"),
    (0x100F1CC4, "81fe9040af11"),
    (0x100F1CCA, "7425"),
    (0x100F1CCC, "85f6"),
    (0x100F1CCE, "7421"),
    (0x100F1CD0, "8b76fc"),
    (0x100F1CD3, "85f6"),
    (0x100F1CD5, "741a"),
    (0x100F1CD7, "56"),
    (0x100F1CD8, "e873310300"),
    (0x100F1CDD, "a1b03e9f11"),
    (0x100F1CE2, "83c404"),
    (0x100F1CE5, "85c0"),
    (0x100F1CE7, "7408"),
    (0x100F1CE9, "6a00"),
    (0x100F1CEB, "56"),
    (0x100F1CEC, "ffd0"),
    (0x100F1CEE, "83c408"),
    (0x100F1CF1, "5e"),
    (0x100F1CF2, "c3"),
)

PARENT_WINDOW_INSTRUCTIONS = (
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

DIRECT_CALLS = (
    (0x100F1BD9, HELPER_VA),
    (0x100EF354, ALLOCATOR_VA),
    (0x100F1CD8, RELEASE_VA),
)
PARENT_CALLS = (
    (0x100ED454, WRAPPER_VA),
    (0x100ED463, 0x100DF270),
    (0x100ED46C, CLEANUP_VA),
)

WRAPPER_BLOCKS = (
    (0x100F1BB0, 0x100F1BC0),
    (0x100F1BC0, 0x100F1BCB),
    (0x100F1BCB, WRAPPER_END),
)
WRAPPER_EDGES = (
    (0x100F1BB0, 0x100F1BC0, "enter_scan"),
    (0x100F1BC0, 0x100F1BC0, "loaded_unit_nonzero"),
    (0x100F1BC0, 0x100F1BCB, "loaded_unit_zero"),
    (0x100F1BCB, "RETURN", "helper_returned_normally"),
)
HELPER_BLOCKS = (
    (0x100EF330, 0x100EF33C),
    (0x100EF33C, 0x100EF347),
    (0x100EF347, 0x100EF380),
    (0x100EF380, 0x100EF384),
    (0x100EF384, 0x100EF386),
    (0x100EF386, 0x100EF396),
    (0x100EF396, 0x100EF399),
    (0x100EF399, HELPER_END),
)
HELPER_EDGES = (
    (0x100EF330, 0x100EF33C, "count_zero"),
    (0x100EF330, 0x100EF347, "count_nonzero"),
    (0x100EF33C, "RETURN", "empty_sentinel_return"),
    (0x100EF347, 0x100EF380, "allocator_returned_normally"),
    (0x100EF380, 0x100EF399, "derived_copy_count_zero"),
    (0x100EF380, 0x100EF384, "derived_copy_count_nonzero"),
    (0x100EF384, 0x100EF386, "copy_setup"),
    (0x100EF386, 0x100EF386, "more_units"),
    (0x100EF386, 0x100EF396, "copy_complete"),
    (0x100EF396, 0x100EF399, "reload_storage"),
    (0x100EF399, "RETURN", "terminator_written"),
)
CLEANUP_BLOCKS = (
    (0x100F1CC0, 0x100F1CCC),
    (0x100F1CCC, 0x100F1CD0),
    (0x100F1CD0, 0x100F1CD7),
    (0x100F1CD7, 0x100F1CE5),
    (0x100F1CE5, 0x100F1CE9),
    (0x100F1CE9, 0x100F1CF1),
    (0x100F1CF1, CLEANUP_END),
)
CLEANUP_EDGES = (
    (0x100F1CC0, 0x100F1CF1, "sentinel_storage"),
    (0x100F1CC0, 0x100F1CCC, "not_sentinel"),
    (0x100F1CCC, 0x100F1CF1, "null_storage"),
    (0x100F1CCC, 0x100F1CD0, "owning_storage"),
    (0x100F1CD0, 0x100F1CF1, "null_raw_metadata"),
    (0x100F1CD0, 0x100F1CD7, "nonzero_raw_metadata"),
    (0x100F1CD7, 0x100F1CE5, "release_returned"),
    (0x100F1CE5, 0x100F1CF1, "hook_null"),
    (0x100F1CE5, 0x100F1CE9, "hook_nonnull"),
    (0x100F1CE9, 0x100F1CF1, "hook_returned"),
    (0x100F1CF1, "RETURN", "epilogue"),
)

CANONICAL_INDEX_SIZE = 8_344_450
CANONICAL_INDEX_SHA256 = (
    "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
)
FUNCTION_INDEX_SIZE = 2_148_494
FUNCTION_INDEX_SHA256 = (
    "34be30433f3cea3e0baa9610afb42cc9122717a2cf63235710d7a9f6f9117591"
)
SYMBOL_MAP_SIZE = 2_893_153
SYMBOL_MAP_SHA256 = (
    "620eb04ec899b0408de1dac9e8c67091b07bddbe2e49eddb90a62ce883fe450e"
)
IMPORTS_SIZE = 12_719
IMPORTS_SHA256 = "507f76f26c32139d738c33a2ecdb889933cfa309aa5af05dd74af065993100f5"

CANONICAL_ROWS = {
    "100ed3c0": ("decomp_fn_100ed3c0", "FUN_100ed3c0", "400", "func", "100ed3c0-100ed54f"),
    "100ef330": ("decomp_fn_100ef330", "FUN_100ef330", "124", "func", "100ef330-100ef3ab"),
    "100f1bb0": ("decomp_fn_100f1bb0", "FUN_100f1bb0", "53", "func", "100f1bb0-100f1be4"),
    "100f1cc0": ("decomp_fn_100f1cc0", "FUN_100f1cc0", "51", "func", "100f1cc0-100f1cf2"),
    "100f1c50": ("decomp_fn_100f1c50", "FUN_100f1c50", "16", "func", "100f1c50-100f1c5f"),
    "100fcc80": ("decomp_fn_100fcc80", "FUN_100fcc80", "380", "func", "100fcc80-100fcdfb"),
    "10124e50": ("decomp_fn_10124e50", "FUN_10124e50", "1613", "func", "10124e50-1012549c"),
    "101254a0": ("decomp_fn_101254a0", "FUN_101254a0", "724", "func", "101254a0-10125773"),
    "116bebf1": ("decomp_fn_116bebf1", "__CxxThrowException@8", "109", "func", "116bebf1-116bec5d"),
}
CANONICAL_HASHES = {
    "100ed3c0": "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8",
    "100ef330": "cd306dafa21f1ceeaf16c4f66840cab347d12a264baaa80b690dba6f7ab58f3b",
    "100f1bb0": "97f290b71b7614457fb149f107899d69391b1e07f847a0b7448248cf8aa1fcc6",
    "100f1cc0": "8cd70d65677361ef62405e7621495b03ddb3901696a4a01c429ff609bc4b4a69",
    "100f1c50": "669b510bfc94b1a2d6b024279992a4bd7da5482ce095ba4ae391cbc76c26f786",
    "100fcc80": "9dbd299240f648438f3e5a9e0a1d55707790af16b4d95c58f190c0475a034e6f",
    "10124e50": "e866eb4e0e99eaa548d8c8d41e47a07defd1e0e5c594b7d6fa2c1cd2cd456225",
    "101254a0": "b48b43d6ffe2ce7a35c634551463d9a5796ff4968d9dd2c4b97adbcfdd276e73",
    "116bebf1": "48cbc01e514344ccd6433ff3897e3c15c1162aadee9d589a2ad9b6f6fa04530f",
}

DOC_SIZE = 12_836
DOC_SHA256 = "23750afdcbd4c5e106a1aba96791619311f74acdfe4353fe11fb619038374762"

MAX_SCAN_UNITS = 32_768
MAX_PAYLOAD_UNITS = MAX_SCAN_UNITS - 1
MAX_SOURCE_BYTES = MAX_SCAN_UNITS * 2
MAX_ALLOCATION_BYTES = MAX_PAYLOAD_UNITS * 2 + 10
EMPTY_OWNER_WORDS = (0, 0, 0, 0, 0, 0, 0)
INTENDED_MODEL = {
    "max_units_domain_including_terminator": (2, MAX_SCAN_UNITS),
    "payload_length_domain": (1, MAX_PAYLOAD_UNITS),
    "maximum_source_span_bytes": MAX_SOURCE_BYTES,
    "maximum_allocation_bytes": MAX_ALLOCATION_BYTES,
    "terminator_required_inside_max_units": True,
    "poll_or_retry_loops": False,
    "owner_initial_state": "canonical_all_zero_EMPTY",
    "descriptor_initial_state": "arbitrary_unowned_placement_scratch",
    "allocation_callback_count": 1,
    "allocation_size": "checked_2n_plus_10",
    "allocation_class": 0,
    "allocator_result": "DENIED_or_GRANT_{nonzero_token,raw_base_guest32}",
    "grant_out_initial_state": "canonical_all_zero",
    "allocation_backing": "exact_raw_span_contained_by_larger_heap_write_view",
    "effects_snapshot": "complete_before_first_callback_and_never_reread",
    "callback_contract": "total_nonreentrant_normal_return_no_borrow_retention",
    "callback_mutation": "declared_disjoint_context_span_only",
    "denied_grant": "no_release_and_no_guest_or_output_write",
    "granted_zero_token": "protocol_error_without_release_authority",
    "alias_policy": "source_descriptor_heap_effects_context_owner_grant_return_disjoint",
    "aligned_storage": "checked_(raw_plus_8)_and_0xfffffffc",
    "metadata": "raw_guest32_at_aligned_minus_4",
    "copy": "exactly_n_utf16le_units",
    "terminator": "literal_zero_independent_of_authenticated_bss_evidence",
    "post_grant_validation": "mapping_extent_alignment_aliases_before_any_guest_write",
    "invalid_nonzero_token_grant": "exactly_one_compensating_release_exact_tuple",
    "compensation_hook": False,
    "descriptor_commit": "{n,n,aligned}_after_heap_writes",
    "owner_success_state": "private_LIVE_exact_grant_and_layout",
    "return_commit": "guest_descriptor_identity_last",
    "build_failure_preservation": "descriptor_heap_owner_and_return_unchanged_except_effect_context",
    "cleanup_authority": "private_LIVE_owner_not_guest_metadata",
    "cleanup_validation": "descriptor_header_formula_full_extent_metadata_and_zero_terminator",
    "cleanup_payload_revalidation": False,
    "cleanup_consume_order": "CONSUMED_before_release_before_optional_hook",
    "cleanup_release": "exact_{token,raw_base,2n_plus_10,class_zero}_once",
    "cleanup_hook": "optional_predeclared_typed_(raw_base,0)_after_release",
    "consumed_owner_reuse": "ALREADY_CONSUMED_without_effect",
    "original_pc_execution": False,
    "native_allocator_execution": False,
    "native_releaser_execution": False,
    "mutable_global_hook_read": False,
    "parent_child_execution": "outside_this_slice",
}
HARD_EXCLUSIONS = (
    "execute_original_100f1bb0_100ef330_100fcc80_100f1cc0_or_10124e50",
    "unbounded_utf16_scan",
    "unchecked_32bit_size_alignment_or_guest_interval_arithmetic",
    "convert_guest_identity_to_native_pointer_or_function_pointer",
    "invoke_platform_heap_registry_virtual_memory_or_process_global_effects",
    "read_or_invoke_DAT_119f3eb0",
    "admit_original_fault_bad_alloc_throw_or_unwind_behavior",
    "accept_overlapping_source_descriptor_allocation_or_control_backings",
    "release_unverified_storage_minus_4_metadata",
    "treat_guest_metadata_or_descriptor_bytes_as_release_authority",
    "release_live_owner_more_than_once_or_hook_during_compensation",
    "require_cleanup_payload_bytes_to_equal_the_original_source",
    "execute_parent_100ed3c0_child_100df270_or_follow_100ed471",
)

BUILD_SUCCESS_ORDER = (
    "ALLOCATE_GRANT",
    "WRITE_RAW_HEADER",
    "COPY_N_UNITS",
    "WRITE_ZERO_TERMINATOR",
    "WRITE_DESCRIPTOR",
    "COMMIT_OWNER_LIVE",
    "COMMIT_DESCRIPTOR_RETURN",
)
INVALID_GRANT_ORDER = (
    "ALLOCATE_GRANT",
    "VALIDATE_GRANT_REJECT",
    "RELEASE_COMPENSATION",
)
CLEANUP_SUCCESS_ORDER = (
    "VALIDATE_LIVE_OWNER_AND_DESCRIPTOR",
    "COMMIT_OWNER_CONSUMED",
    "RELEASE_OWNED_GRANT",
    "OPTIONAL_AUTHENTICATED_HOOK",
)


class EvidenceError(ValueError):
    """A candidate differs from the authenticated evidence."""


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
    require_range(body, offset, 5, f"call at 0x{instruction_va:08x}")
    if body[offset] != 0xE8:
        raise EvidenceError(f"0x{instruction_va:08x} is not E8 rel32")
    return instruction_va + 5 + struct.unpack_from("<i", body, offset + 1)[0]


def rel8_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    require_range(body, offset, 2, f"branch at 0x{instruction_va:08x}")
    if body[offset] not in (0x74, 0x75):
        raise EvidenceError(f"0x{instruction_va:08x} is not admitted rel8 branch")
    return instruction_va + 2 + struct.unpack_from("<b", body, offset + 1)[0]


def validate_partition(
    candidate: bytes,
    start: int,
    partition: tuple[tuple[int, str], ...],
    expected_hash: str,
    label: str,
) -> None:
    require_authority(candidate, sum(
        len(bytes.fromhex(encoded)) for _va, encoded in partition
    ), expected_hash, label)
    cursor = 0
    for va, encoded_hex in partition:
        encoded = bytes.fromhex(encoded_hex)
        if va != start + cursor:
            raise AssertionError(f"internal {label} partition is not contiguous")
        if candidate[cursor:cursor + len(encoded)] != encoded:
            raise EvidenceError(f"{label} instruction changed at 0x{va:08x}")
        cursor += len(encoded)
    if cursor != len(candidate):
        raise EvidenceError(f"{label} partition does not consume candidate")


def validate_wrapper_candidate(candidate: bytes) -> None:
    validate_partition(
        candidate, WRAPPER_VA, WRAPPER_INSTRUCTIONS, WRAPPER_SHA256, "wrapper"
    )
    if rel8_target(candidate, WRAPPER_VA, 0x100F1BC9) != SCAN_VA:
        raise EvidenceError("UTF-16 scan backedge changed")
    if rel32_target(candidate, WRAPPER_VA, 0x100F1BD9) != HELPER_VA:
        raise EvidenceError("wrapper helper target changed")
    required = (
        bytes.fromhex("0fb71083c0026685d275f5"),
        bytes.fromhex("2bc683e802d1f88907"),
        bytes.fromhex("8d04465056"),
    )
    if any(fragment not in candidate for fragment in required):
        raise EvidenceError("scan, length, descriptor store, or argument shape changed")


def validate_helper_candidate(candidate: bytes) -> None:
    validate_partition(
        candidate, HELPER_VA, HELPER_INSTRUCTIONS, HELPER_SHA256, "helper"
    )
    if rel8_target(candidate, HELPER_VA, 0x100EF33A) != NONEMPTY_VA:
        raise EvidenceError("nonempty branch target changed")
    if rel32_target(candidate, HELPER_VA, 0x100EF354) != ALLOCATOR_VA:
        raise EvidenceError("allocator target changed")
    if rel8_target(candidate, HELPER_VA, 0x100EF382) != 0x100EF399:
        raise EvidenceError("zero-copy target changed")
    if rel8_target(candidate, HELPER_VA, 0x100EF394) != 0x100EF386:
        raise EvidenceError("copy-loop backedge changed")
    required = (
        bytes.fromhex("894704"),
        bytes.fromhex("8d04450a0000006a0050"),
        bytes.fromhex("8d700883e6fc8946fc"),
        bytes.fromhex("897708"),
        bytes.fromhex("2bd843897708d1eb3b4424180f47dd"),
        bytes.fromhex("668b088d40024266894c06fe3bd375f0"),
        bytes.fromhex("66a18c40af116689044e"),
    )
    if any(fragment not in candidate for fragment in required):
        raise EvidenceError("nonempty allocation, copy, or terminator semantics changed")


def validate_cleanup_candidate(candidate: bytes) -> None:
    validate_partition(
        candidate, CLEANUP_VA, CLEANUP_INSTRUCTIONS, CLEANUP_SHA256, "cleanup"
    )
    for site, target in (
        (0x100F1CCA, 0x100F1CF1),
        (0x100F1CCE, 0x100F1CF1),
        (0x100F1CD5, 0x100F1CF1),
        (0x100F1CE7, 0x100F1CF1),
    ):
        if rel8_target(candidate, CLEANUP_VA, site) != target:
            raise EvidenceError(f"cleanup branch changed at 0x{site:08x}")
    if rel32_target(candidate, CLEANUP_VA, 0x100F1CD8) != RELEASE_VA:
        raise EvidenceError("release target changed")
    if candidate[0x2C:0x2E] != b"\xff\xd0":
        raise EvidenceError("post-release callback shape changed")
    release = candidate.index(bytes.fromhex("56e873310300"))
    hook_load = candidate.index(bytes.fromhex("a1b03e9f11"))
    hook_call = candidate.index(bytes.fromhex("6a0056ffd0"))
    if not release < hook_load < hook_call:
        raise EvidenceError("release and optional hook order changed")


def validate_cfg(
    label: str,
    blocks: tuple[tuple[int, int], ...],
    edges: tuple[tuple[object, object, str], ...],
) -> None:
    expected = {
        "wrapper": (WRAPPER_BLOCKS, WRAPPER_EDGES),
        "helper": (HELPER_BLOCKS, HELPER_EDGES),
        "cleanup": (CLEANUP_BLOCKS, CLEANUP_EDGES),
    }
    if label not in expected or (blocks, edges) != expected[label]:
        raise EvidenceError(f"{label} exact CFG changed")
    starts = {start for start, _end in blocks}
    for source, target, _kind in edges:
        if source not in starts:
            raise EvidenceError(f"{label} CFG source is not a block")
        if target != "RETURN" and target not in starts:
            raise EvidenceError(f"{label} CFG target is not a block")


def allocation_layout(unit_count: int, raw: int) -> tuple[int, int, int, int]:
    if not 1 <= unit_count <= MAX_PAYLOAD_UNITS:
        raise EvidenceError("unit count exceeds finite model")
    allocation_size = unit_count * 2 + 10
    if raw == 0 or raw > 0xFFFFFFFF - 8:
        raise EvidenceError("raw+8 overflows guest32")
    if raw + allocation_size > ADDRESS_SPACE_SIZE:
        raise EvidenceError("allocation interval overflows guest32")
    aligned = (raw + 8) & 0xFFFFFFFC
    metadata = aligned - 4
    terminator_end = aligned + unit_count * 2 + 2
    if not raw <= metadata < aligned or terminator_end > raw + allocation_size:
        raise EvidenceError("allocation layout escapes exact 2N+10 backing")
    return allocation_size, aligned, metadata, terminator_end


def validate_intended_model(
    model: dict[str, object],
    exclusions,
    build_success_order=BUILD_SUCCESS_ORDER,
    invalid_grant_order=INVALID_GRANT_ORDER,
    cleanup_success_order=CLEANUP_SUCCESS_ORDER,
) -> None:
    if model != INTENDED_MODEL:
        raise EvidenceError("finite injected model changed")
    if tuple(exclusions) != HARD_EXCLUSIONS:
        raise EvidenceError("hard exclusions changed")
    if model["max_units_domain_including_terminator"] != (2, 32_768):
        raise EvidenceError("terminator-inclusive budget domain changed")
    if model["payload_length_domain"] != (1, 32_767):
        raise EvidenceError("nonempty payload domain changed")
    if model["maximum_source_span_bytes"] != 65_536:
        raise EvidenceError("maximum source span changed")
    if model["maximum_allocation_bytes"] != 0x10008:
        raise EvidenceError("maximum allocation request changed")
    if tuple(build_success_order) != BUILD_SUCCESS_ORDER:
        raise EvidenceError("successful build commit order changed")
    if tuple(invalid_grant_order) != INVALID_GRANT_ORDER:
        raise EvidenceError("invalid-grant compensation order changed")
    if tuple(cleanup_success_order) != CLEANUP_SUCCESS_ORDER:
        raise EvidenceError("owning cleanup consume/effect order changed")
    if EMPTY_OWNER_WORDS != (0, 0, 0, 0, 0, 0, 0):
        raise EvidenceError("canonical EMPTY owner changed")
    if invalid_grant_order.count("RELEASE_COMPENSATION") != 1:
        raise EvidenceError("invalid grant is not compensated exactly once")
    if any("HOOK" in event for event in invalid_grant_order):
        raise EvidenceError("compensation must not invoke the optional hook")
    if cleanup_success_order.index("COMMIT_OWNER_CONSUMED") > \
            cleanup_success_order.index("RELEASE_OWNED_GRANT"):
        raise EvidenceError("owner must be consumed before release")
    if cleanup_success_order.index("RELEASE_OWNED_GRANT") > \
            cleanup_success_order.index("OPTIONAL_AUTHENTICATED_HOOK"):
        raise EvidenceError("authenticated hook must follow release")
    if model["cleanup_payload_revalidation"]:
        raise EvidenceError("cleanup must not invent source/hash retention")
    if model["compensation_hook"]:
        raise EvidenceError("compensation must not emit the release hook")
    for key in (
        "terminator_required_inside_max_units", "allocation_callback_count",
    ):
        if not model[key]:
            raise EvidenceError(f"required model property is false: {key}")
    for key in (
        "original_pc_execution", "native_allocator_execution",
        "native_releaser_execution", "mutable_global_hook_read",
        "poll_or_retry_loops",
    ):
        if model[key]:
            raise EvidenceError(f"forbidden model property is true: {key}")


def mutated(data: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(data):
        raise ValueError("mutation offset outside candidate")
    result = bytearray(data)
    result[offset] ^= 1
    return bytes(result)


class Startup100f1bb0OwnedUtf16ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        require_authority(cls.dll, DLL_SIZE, DLL_SHA256, "original DLL")
        cls.pe = parse_pe32(cls.dll)

    def test_original_pe_and_all_core_bodies_are_exact(self):
        self.assertIn(TEXT_SECTION, self.pe["sections"])
        self.assertIn(DATA_SECTION, self.pe["sections"])
        for va, expected, raw, digest in (
            (WRAPPER_VA, WRAPPER_BYTES, WRAPPER_RAW, WRAPPER_SHA256),
            (HELPER_VA, HELPER_BYTES, HELPER_RAW, HELPER_SHA256),
            (CLEANUP_VA, CLEANUP_BYTES, CLEANUP_RAW, CLEANUP_SHA256),
            (PARENT_WINDOW_VA, PARENT_WINDOW_BYTES, PARENT_WINDOW_RAW,
             PARENT_WINDOW_SHA256),
        ):
            body, section, actual_raw = read_va(
                self.dll, self.pe, va, len(expected)
            )
            self.assertEqual((section, actual_raw), (".text", raw))
            self.assertEqual(body, expected)
            self.assertEqual(sha256(body), digest)
        parent, section, raw = read_va(
            self.dll, self.pe, PARENT_VA, PARENT_SIZE
        )
        self.assertEqual((section, raw), (".text", PARENT_RAW))
        self.assertEqual(sha256(parent), PARENT_SHA256)

    def test_exact_ninety_one_instruction_partition(self):
        validate_wrapper_candidate(WRAPPER_BYTES)
        validate_helper_candidate(HELPER_BYTES)
        validate_cleanup_candidate(CLEANUP_BYTES)
        validate_partition(
            PARENT_WINDOW_BYTES, PARENT_WINDOW_VA, PARENT_WINDOW_INSTRUCTIONS,
            PARENT_WINDOW_SHA256, "parent window",
        )
        self.assertEqual(
            len(WRAPPER_INSTRUCTIONS) + len(HELPER_INSTRUCTIONS) +
            len(CLEANUP_INSTRUCTIONS),
            91,
        )

    def test_wrapper_scan_length_store_arguments_and_call_are_exact(self):
        validate_wrapper_candidate(WRAPPER_BYTES)
        scan = WRAPPER_BYTES[SCAN_VA - WRAPPER_VA:SCAN_END - WRAPPER_VA]
        self.assertEqual(sha256(scan), SCAN_SHA256)
        tail = WRAPPER_BYTES[0x1B:]
        self.assertEqual(sha256(tail), WRAPPER_TAIL_SHA256)
        self.assertEqual(DIRECT_CALLS[0], (0x100F1BD9, HELPER_VA))
        self.assertEqual(WRAPPER_BYTES[-3:], bytes.fromhex("c20400"))
        validate_cfg("wrapper", WRAPPER_BLOCKS, WRAPPER_EDGES)

    def test_helper_allocation_size_alignment_and_metadata_are_exact(self):
        validate_helper_candidate(HELPER_BYTES)
        self.assertEqual(len(NONEMPTY_BYTES), 101)
        self.assertEqual(sha256(NONEMPTY_BYTES), NONEMPTY_SHA256)
        self.assertEqual(struct.unpack_from("<I", HELPER_BYTES, 0x1D)[0], 10)
        self.assertEqual(DIRECT_CALLS[1], (0x100EF354, ALLOCATOR_VA))
        validate_cfg("helper", HELPER_BLOCKS, HELPER_EDGES)
        for residue in range(4):
            raw = 0x2000 + residue
            size, aligned, metadata, terminator_end = allocation_layout(7, raw)
            self.assertEqual(size, 24)
            self.assertEqual(aligned & 3, 0)
            self.assertEqual(aligned - raw, 8 - residue)
            self.assertEqual(metadata, aligned - 4)
            self.assertLessEqual(terminator_end, raw + size)

    def test_copy_loop_count_and_zero_fill_terminator_are_exact(self):
        validate_helper_candidate(HELPER_BYTES)
        self.assertEqual(
            HELPER_BYTES[0x41:0x52],
            bytes.fromhex("2bd843897708d1eb3b4424180f47dd85db"),
        )
        self.assertEqual(
            HELPER_BYTES[0x56:0x66],
            bytes.fromhex("668b088d40024266894c06fe3bd375f0"),
        )
        self.assertEqual(
            HELPER_BYTES[0x69:0x75],
            bytes.fromhex("8b0f66a18c40af116689044e"),
        )
        data = next(section for section in self.pe["sections"] if section[0] == ".data")
        _name, rva, virtual_size, _raw, raw_size, flags = data
        delta = TERMINATOR_SOURCE_VA - IMAGE_BASE - rva
        self.assertEqual(delta, 0x1C108C)
        self.assertGreaterEqual(delta, raw_size)
        self.assertLessEqual(delta + 2, virtual_size)
        self.assertEqual(flags, 0xC0000040)
        self.assertEqual(EMPTY_SENTINEL_VA, TERMINATOR_SOURCE_VA + 4)

    def test_allocator_seam_and_bad_allocation_throw_boundary_are_exact(self):
        body, section, raw = read_va(
            self.dll, self.pe, ALLOCATOR_VA, ALLOCATOR_SIZE
        )
        self.assertEqual((section, raw), (".text", ALLOCATOR_RAW))
        self.assertEqual(sha256(body), ALLOCATOR_SHA256)
        core = body[ALLOCATOR_CORE_VA - ALLOCATOR_VA:
                    ALLOCATOR_CORE_END - ALLOCATOR_VA]
        self.assertEqual(sha256(core), ALLOCATOR_CORE_SHA256)
        failure = body[ALLOCATOR_FAILURE_VA - ALLOCATOR_VA:
                       ALLOCATOR_FAILURE_END - ALLOCATOR_VA]
        self.assertEqual(failure, ALLOCATOR_FAILURE_BYTES)
        self.assertEqual(sha256(failure), ALLOCATOR_FAILURE_SHA256)
        self.assertEqual(rel32_target(body, ALLOCATOR_VA, 0x100FCCB2), 0x101254A0)
        self.assertEqual(rel32_target(body, ALLOCATOR_VA, 0x100FCD03), 0x100F1C50)
        self.assertEqual(rel32_target(body, ALLOCATOR_VA, 0x100FCD12), 0x116BEBF1)
        self.assertEqual(body[0x3C:0x3F], bytes.fromhex("85f674"))
        self.assertEqual(body[0x71:0x73], bytes.fromhex("ffd0"))
        self.assertEqual(struct.unpack_from("<I", body, 0x67)[0], ALLOCATOR_HOOK_VA)
        hook_window = body[
            ALLOCATOR_HOOK_WINDOW_VA - ALLOCATOR_VA:
            ALLOCATOR_HOOK_WINDOW_VA - ALLOCATOR_VA +
            len(ALLOCATOR_HOOK_WINDOW)
        ]
        self.assertEqual(hook_window, ALLOCATOR_HOOK_WINDOW)
        self.assertEqual(sha256(hook_window), ALLOCATOR_HOOK_WINDOW_SHA256)
        self.assertEqual(hook_window[9:13], bytes.fromhex("5756ffd0"))
        for va, size, expected_raw, digest in (
            BAD_ALLOC_BUILDER, UNDERLYING_ALLOCATOR, CXX_THROW,
        ):
            target, target_section, target_raw = read_va(
                self.dll, self.pe, va, size
            )
            self.assertEqual((target_section, target_raw), (".text", expected_raw))
            self.assertEqual(sha256(target), digest)

    def test_owning_cleanup_release_then_optional_hook_is_exact(self):
        validate_cleanup_candidate(CLEANUP_BYTES)
        owning = CLEANUP_BYTES[
            OWNING_CLEANUP_VA - CLEANUP_VA:OWNING_CLEANUP_END - CLEANUP_VA
        ]
        self.assertEqual(len(owning), 33)
        self.assertEqual(sha256(owning), OWNING_CLEANUP_SHA256)
        self.assertEqual(owning[:5], bytes.fromhex("8b76fc85f6"))
        self.assertEqual(DIRECT_CALLS[2], (0x100F1CD8, RELEASE_VA))
        self.assertEqual(struct.unpack_from("<I", CLEANUP_BYTES, 0x1E)[0],
                         ALLOCATOR_HOOK_VA)
        self.assertEqual(CLEANUP_BYTES[0x29:0x2E], bytes.fromhex("6a0056ffd0"))
        validate_cfg("cleanup", CLEANUP_BLOCKS, CLEANUP_EDGES)

    def test_release_target_body_null_boundary_and_epilogue_are_pinned(self):
        body, section, raw = read_va(self.dll, self.pe, RELEASE_VA, RELEASE_SIZE)
        self.assertEqual((section, raw), (".text", RELEASE_RAW))
        self.assertEqual(sha256(body), RELEASE_SHA256)
        self.assertEqual(body[:len(RELEASE_PREFIX)], RELEASE_PREFIX)
        self.assertEqual(sha256(RELEASE_PREFIX), RELEASE_PREFIX_SHA256)
        self.assertEqual(
            body[RELEASE_EPILOGUE_VA - RELEASE_VA:
                 RELEASE_EPILOGUE_VA - RELEASE_VA + len(RELEASE_EPILOGUE)],
            RELEASE_EPILOGUE,
        )
        self.assertEqual(sha256(RELEASE_EPILOGUE), RELEASE_EPILOGUE_SHA256)

    def test_parent_construct_child_cleanup_context_and_offsets_are_exact(self):
        validate_partition(
            PARENT_WINDOW_BYTES, PARENT_WINDOW_VA, PARENT_WINDOW_INSTRUCTIONS,
            PARENT_WINDOW_SHA256, "parent window",
        )
        calls = tuple(
            (site, rel32_target(PARENT_WINDOW_BYTES, PARENT_WINDOW_VA, site))
            for site, _target in PARENT_CALLS
        )
        self.assertEqual(calls, PARENT_CALLS)
        self.assertEqual(
            PARENT_WINDOW_BYTES[4:15],
            bytes.fromhex("8d4c2428ffb42418090000"),
        )
        self.assertEqual(
            PARENT_WINDOW_BYTES[-9:], bytes.fromhex("8d4c2428e84f480000")
        )
        self.assertEqual(
            tuple(site for site, _target in PARENT_CALLS),
            tuple(sorted(site for site, _target in PARENT_CALLS)),
        )

    def test_canonical_maps_decomp_and_import_authorities_are_exact(self):
        for path, size, digest, label in (
            (CANONICAL_INDEX, CANONICAL_INDEX_SIZE, CANONICAL_INDEX_SHA256,
             "canonical index"),
            (FUNCTION_INDEX, FUNCTION_INDEX_SIZE, FUNCTION_INDEX_SHA256,
             "function index"),
            (SYMBOL_MAP, SYMBOL_MAP_SIZE, SYMBOL_MAP_SHA256, "symbol map"),
            (IMPORTS, IMPORTS_SIZE, IMPORTS_SHA256, "import manifest"),
        ):
            require_authority(path.read_bytes(), size, digest, label)
        rows = {
            row["entry"]: row for row in csv.DictReader(
                CANONICAL_INDEX.read_text(encoding="utf-8").splitlines(),
                delimiter="\t",
            )
        }
        for entry, expected in CANONICAL_ROWS.items():
            row = rows[entry]
            self.assertEqual(
                (
                    row["canonical_name"], row["original_name"], row["size"],
                    row["kind"], row["body_ranges"],
                ),
                expected,
            )
            self.assertEqual(
                sha256((CANONICAL / f"decomp_fn_{entry}.c").read_bytes()),
                CANONICAL_HASHES[entry],
            )
        allocator_source = (CANONICAL / "decomp_fn_100fcc80.c").read_text(
            encoding="utf-8"
        )
        for token in (
            "RegOpenKeyExW", "RegQueryValueExW", "GetProcessHeap",
            "HeapSetInformation", "decomp_fn_100f1c50();",
            "decomp_fn_116bebf1",
        ):
            self.assertIn(token, allocator_source)
        release_source = (CANONICAL / "decomp_fn_10124e50.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("VirtualQuery", release_source)
        self.assertIn("VirtualFree", release_source)
        imports = json.loads(IMPORTS.read_text(encoding="utf-8"))
        self.assertIn("RegOpenKeyExW", imports["ADVAPI32.dll"])
        self.assertIn("RegQueryValueExW", imports["ADVAPI32.dll"])
        self.assertIn("VirtualQuery", imports["KERNEL32.dll"])
        self.assertIn("VirtualFree", imports["KERNEL32.dll"])

    def test_canonical_sources_preserve_descriptor_and_cleanup_order(self):
        wrapper = (CANONICAL / "decomp_fn_100f1bb0.c").read_text(encoding="utf-8")
        helper = (CANONICAL / "decomp_fn_100ef330.c").read_text(encoding="utf-8")
        cleanup = (CANONICAL / "decomp_fn_100f1cc0.c").read_text(encoding="utf-8")
        parent = (CANONICAL / "decomp_fn_100ed3c0.c").read_text(encoding="utf-8")
        wrapper_tokens = (
            "} while (sVar1 != 0);", "*param_1 = iVar3;",
            "decomp_fn_100ef330(param_2,param_2 + iVar3);",
        )
        self.assertEqual(
            [wrapper.index(token) for token in wrapper_tokens],
            sorted(wrapper.index(token) for token in wrapper_tokens),
        )
        helper_tokens = (
            "param_1[1] = iVar2;", "iVar2 * 2 + 10",
            "iVar2 + 8U & 0xfffffffc", "*(int *)(uVar5 - 4) = iVar2;",
            "param_1[2] = uVar5;", "*(undefined2 *)(uVar5 + *param_1 * 2)",
        )
        self.assertEqual(
            [helper.index(token) for token in helper_tokens],
            sorted(helper.index(token) for token in helper_tokens),
        )
        cleanup_tokens = (
            "iVar2 = *(int *)(puVar1 + -2)", "decomp_fn_10124e50(iVar2);",
            "if (DAT_119f3eb0 != (code *)0x0)", "(*DAT_119f3eb0)(iVar2,0);",
        )
        self.assertEqual(
            [cleanup.index(token) for token in cleanup_tokens],
            sorted(cleanup.index(token) for token in cleanup_tokens),
        )
        parent_tokens = (
            "uVar5 = decomp_fn_100f1bb0(param_3);",
            "decomp_fn_100df270(&local_8d8,uVar5);",
            "decomp_fn_100f1cc0();",
        )
        self.assertEqual(
            [parent.index(token) for token in parent_tokens],
            sorted(parent.index(token) for token in parent_tokens),
        )

    def test_failure_exception_boundaries_and_finite_model_are_fail_closed(self):
        validate_intended_model(dict(INTENDED_MODEL), HARD_EXCLUSIONS)
        self.assertIn("unbounded_utf16_scan", HARD_EXCLUSIONS)
        self.assertIn("admit_original_fault_bad_alloc_throw_or_unwind_behavior",
                      HARD_EXCLUSIONS)
        self.assertEqual(INTENDED_MODEL["allocation_callback_count"], 1)
        self.assertEqual(INTENDED_MODEL["payload_length_domain"], (1, 32_767))
        self.assertEqual(INTENDED_MODEL["maximum_source_span_bytes"], 65_536)
        self.assertEqual(INTENDED_MODEL["maximum_allocation_bytes"], 0x10008)
        self.assertEqual(EMPTY_OWNER_WORDS, (0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(INVALID_GRANT_ORDER.count("RELEASE_COMPENSATION"), 1)
        self.assertNotIn("OPTIONAL_AUTHENTICATED_HOOK", INVALID_GRANT_ORDER)
        self.assertLess(
            CLEANUP_SUCCESS_ORDER.index("COMMIT_OWNER_CONSUMED"),
            CLEANUP_SUCCESS_ORDER.index("RELEASE_OWNED_GRANT"),
        )
        self.assertFalse(INTENDED_MODEL["original_pc_execution"])
        self.assertFalse(INTENDED_MODEL["native_allocator_execution"])
        self.assertFalse(INTENDED_MODEL["native_releaser_execution"])
        self.assertFalse(INTENDED_MODEL["cleanup_payload_revalidation"])
        for count in (1, 2, 17, MAX_PAYLOAD_UNITS):
            size, aligned, metadata, end = allocation_layout(count, 0x00100001)
            self.assertEqual(size, count * 2 + 10)
            self.assertEqual(metadata, aligned - 4)
            self.assertEqual(end, aligned + count * 2 + 2)
        for count in (0, MAX_PAYLOAD_UNITS + 1):
            with self.assertRaises(EvidenceError):
                allocation_layout(count, 0x1000)
        with self.assertRaises(EvidenceError):
            allocation_layout(1, 0xFFFFFFF8)

    def test_documentation_matches_exact_evidence_and_model(self):
        doc = DOC.read_bytes()
        require_authority(doc, DOC_SIZE, DOC_SHA256, "focused evidence doc")
        text = doc.decode("utf-8")
        for token in (
            "`0x100f1bb0 -> 0x100ef330`", WRAPPER_SHA256, HELPER_SHA256,
            NONEMPTY_SHA256, CLEANUP_SHA256, ALLOCATOR_SHA256, RELEASE_SHA256,
            "`2*N+10`", "`(raw+8)&~3`", "`storage-4`", "`[2,32768]`",
            "`[1,32767]`", "65,536", "`0x10008`",
            "canonical all-zero `EMPTY`",
            "compensating release", "`CONSUMED` before release",
            "0x100ed454", "0x100ed463", "0x100ed46c",
            "No original address is executable",
        ):
            self.assertIn(token, text)

    def test_reciprocal_instruction_call_branch_and_semantic_mutants_fail(self):
        mutant_count = 0
        validators = (
            (WRAPPER_BYTES, WRAPPER_VA, WRAPPER_INSTRUCTIONS,
             validate_wrapper_candidate),
            (HELPER_BYTES, HELPER_VA, HELPER_INSTRUCTIONS,
             validate_helper_candidate),
            (CLEANUP_BYTES, CLEANUP_VA, CLEANUP_INSTRUCTIONS,
             validate_cleanup_candidate),
        )
        for body, start, partition, validator in validators:
            for va, _encoded in partition:
                with self.assertRaises(EvidenceError, msg=f"0x{va:08x}"):
                    validator(mutated(body, va - start))
                mutant_count += 1
        for body, start, site, validator in (
            (WRAPPER_BYTES, WRAPPER_VA, 0x100F1BD9, validate_wrapper_candidate),
            (HELPER_BYTES, HELPER_VA, 0x100EF354, validate_helper_candidate),
            (CLEANUP_BYTES, CLEANUP_VA, 0x100F1CD8, validate_cleanup_candidate),
        ):
            with self.assertRaises(EvidenceError):
                validator(mutated(body, site - start + 1))
            mutant_count += 1
        for offset in (0x1D, 0x37, 0x3A, 0x6D, 0x71):
            with self.assertRaises(EvidenceError):
                validate_helper_candidate(mutated(HELPER_BYTES, offset))
            mutant_count += 1
        self.assertEqual(mutant_count, 99)

    def test_reciprocal_cfg_model_and_authority_mutants_fail(self):
        mutant_count = 0
        for label, blocks, edges in (
            ("wrapper", WRAPPER_BLOCKS, WRAPPER_EDGES),
            ("helper", HELPER_BLOCKS, HELPER_EDGES),
            ("cleanup", CLEANUP_BLOCKS, CLEANUP_EDGES),
        ):
            mutant_edges = list(edges)
            mutant_edges.pop()
            with self.assertRaises(EvidenceError):
                validate_cfg(label, blocks, tuple(mutant_edges))
            mutant_count += 1
        for key, value in (
            ("max_units_domain_including_terminator", (1, MAX_SCAN_UNITS)),
            ("payload_length_domain", (1, MAX_SCAN_UNITS)),
            ("maximum_source_span_bytes", 65_534),
            ("maximum_allocation_bytes", 0x1000A),
            ("owner_initial_state", "caller_supplied_LIVE"),
            ("descriptor_initial_state", "must_be_zero"),
            ("allocation_size", "unchecked_2n_plus_10"),
            ("allocation_callback_count", 2),
            ("allocation_backing", "must_equal_heap_view"),
            ("invalid_nonzero_token_grant", "leak_and_fail"),
            ("compensation_hook", True),
            ("cleanup_payload_revalidation", True),
            ("original_pc_execution", True),
            ("native_allocator_execution", True),
            ("native_releaser_execution", True),
            ("mutable_global_hook_read", True),
        ):
            model = dict(INTENDED_MODEL)
            model[key] = value
            with self.assertRaises(EvidenceError, msg=key):
                validate_intended_model(model, HARD_EXCLUSIONS)
            mutant_count += 1
        for build_order, invalid_order, cleanup_order in (
            (BUILD_SUCCESS_ORDER[:-1], INVALID_GRANT_ORDER,
             CLEANUP_SUCCESS_ORDER),
            (BUILD_SUCCESS_ORDER, INVALID_GRANT_ORDER[:-1],
             CLEANUP_SUCCESS_ORDER),
            (BUILD_SUCCESS_ORDER,
             INVALID_GRANT_ORDER + ("OPTIONAL_AUTHENTICATED_HOOK",),
             CLEANUP_SUCCESS_ORDER),
            (BUILD_SUCCESS_ORDER, INVALID_GRANT_ORDER,
             (
                 "VALIDATE_LIVE_OWNER_AND_DESCRIPTOR",
                 "RELEASE_OWNED_GRANT",
                 "COMMIT_OWNER_CONSUMED",
                 "OPTIONAL_AUTHENTICATED_HOOK",
             )),
        ):
            with self.assertRaises(EvidenceError):
                validate_intended_model(
                    dict(INTENDED_MODEL), HARD_EXCLUSIONS,
                    build_order, invalid_order, cleanup_order,
                )
            mutant_count += 1
        for va, size, _raw, digest in (
            (ALLOCATOR_VA, ALLOCATOR_SIZE, ALLOCATOR_RAW, ALLOCATOR_SHA256),
            (RELEASE_VA, RELEASE_SIZE, RELEASE_RAW, RELEASE_SHA256),
        ):
            body = read_va(self.dll, self.pe, va, size)[0]
            with self.assertRaises(EvidenceError):
                require_authority(mutated(body, size // 2), size, digest, hex(va))
            mutant_count += 1
        self.assertEqual(mutant_count, 25)

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
            {
                "__future__", "ast", "csv", "hashlib", "json", "struct",
                "unittest", "pathlib",
            },
        )
        self.assertEqual(forbidden_calls, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
