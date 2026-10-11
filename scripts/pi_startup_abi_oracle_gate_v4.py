#!/usr/bin/env python3
"""Closed-world semantic gate for startup-ABI O-stage oracle artifacts.

The transport schema cannot prove the meaning of free-form oracle prose.  The
calibration O-stage prompt assigns every test one or more exact ``KEY=TOKEN``
markers.  This gate requires the complete marker set, rejects unknown markers
and known contradictory prose, and requires each mutant description to equal
one exact ``EXACT_SINGLE_MUTATION: ...`` string.  A marker is a contract, not
an evidence source.

The CLI receives the O workspace root (the directory containing O01 through
O04).  It also verifies that every authority needed by the marker contract is
hash-pinned in the sibling frozen context manifests of a supervisor run.  The
gate is standard-library-only, deterministic, fail-closed, and read-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any


WORKERS = ("O01", "O02", "O03", "O04")
MAX_JSON_BYTES = 65536
MAX_CONFIG_JSON_BYTES = 131072
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TRUSTED_REPO_ROOT = Path(__file__).resolve().parent.parent
V3_SCHEMA_PATH = "scripts/pi_wave3_oracle_v3.schema.json"
V3_SCHEMA_SHA256 = "b318ef8c377de4304ef869c8fb92995ae59a295520227039eeb625c4853a0f35"
V3_SCHEMA_BYTE_COUNT = 2818
FROZEN_O_CONTRACT_SHA256 = (
    "6af3148a15cb0a9d94c4a649f8d57c07ed7203ec4f8359ba9fd818d6e03f12d2"
)
# This digest is the final v9 O-contract pin.  The O gate's own script hash is
# excluded from the projection to avoid a self-hash cycle and is checked live.
CONFIG_ROOT_KEYS = frozenset(
    {
        "$schema",
        "schema_version",
        "model",
        "milestone",
        "launch_stagger_milliseconds",
        "allowed_requirement_ids",
        "semantic_gates",
        "prompt_preamble",
        "stage_order",
        "stages",
        "workers",
    }
)
CONFIG_GLOBAL_PROJECTION_KEYS = (
    "$schema",
    "schema_version",
    "model",
    "milestone",
    "launch_stagger_milliseconds",
    "prompt_preamble",
    "stage_order",
)
O_STAGE_DEFINITION_KEYS = frozenset(
    {"id", "depends_on", "worker_count", "description"}
)
SEMANTIC_GATE_KEYS = frozenset(
    {"stage", "script", "script_sha256", "workspace_root"}
)
SEMANTIC_GATE_STAGE_ORDER = ("E", "O")
O_WORKER_CONFIG_KEYS = (
    "id",
    "role",
    "task",
    "tools",
    "thinking",
    "budget",
    "writable_dir",
    "context_files",
    "review_targets",
    "required_outputs",
)
O_STAGE_CONFIG_KEYS = frozenset(
    {"schema_version", "run_id", "config_sha256", "stage", "workers"}
)

ALLOWED_REQUIREMENT_IDS = frozenset(
    {
        "ABI-PROV-001",
        "ABI-CALL-001",
        "ABI-STACK-001",
        "ABI-REG-001",
        "ABI-RET-001",
        "ABI-ORACLE-001",
        "ABI-CONT-001",
        "ABI-NOGO-001",
    }
)
ROLE_REQUIRED_REQUIREMENTS = {
    "O01": frozenset({"ABI-PROV-001", "ABI-CALL-001", "ABI-RET-001"}),
    "O02": frozenset(
        {"ABI-STACK-001", "ABI-REG-001", "ABI-RET-001", "ABI-ORACLE-001"}
    ),
    "O03": frozenset(
        {"ABI-PROV-001", "ABI-ORACLE-001", "ABI-CONT-001", "ABI-NOGO-001"}
    ),
    "O04": frozenset(
        {"ABI-PROV-001", "ABI-ORACLE-001", "ABI-CONT-001", "ABI-NOGO-001"}
    ),
}


# These are the minimum machine-fact and containment authorities used by the
# marker contract.  The exact full context sets below form the trust boundary;
# every declared pin is resolved inside the repository and rehashed live.
REQUIRED_CONTEXT_AUTHORITIES: dict[str, tuple[str, ...]] = {
    "O01": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
    ),
    "O02": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
    ),
    "O03": (
        "Total War Rome II/empire.retail.dll",
        "docs/x64_startup_100f1aa0_empty_spec.md",
        "scripts/x64_startup_100f1aa0_empty_fixture.json",
        "scripts/test_x64_startup_100f1aa0_empty_provenance.py",
        "src_canonical_out/empire.retail.dll/canonical_function_index.tsv",
        "generated/canonical/0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70/references.tsv",
    ),
    "O04": (
        "CMakeLists.txt",
        "port/x64_bootstrap/empire_bootstrap.c",
        "port/x64_bootstrap/empire_bootstrap.def",
        "port/x64_probe/probe_exports.def",
        "port/x64_exports/export_manifest.tsv",
        "port/x64_exports/empire.retail.exports.def",
    ),
}

# Exact v9 context lists, in supervisor/config order.  The smaller role sets
# above remain part of the frozen marker contract; these full lists are the
# trust boundary used to validate context manifests.
FULL_V9_CONTEXT_AUTHORITIES: dict[str, tuple[str, ...]] = {
    "O01": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
        "scripts/test_x64_entry_policy_provenance.py",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100edd70.c",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c",
        "docs/x64_startup_100f1c10_spec.md",
        "docs/pi_startup_abi_oracle_mutation_contract_v3.md",
    ),
    "O02": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c",
        "src_canonical_out/empire.retail.dll/canonical_function_index.tsv",
        "docs/x64_startup_100f1c10_spec.md",
        "docs/pi_startup_abi_oracle_mutation_contract_v3.md",
    ),
    "O03": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
        "docs/x64_startup_100f1c10_spec.md",
        "docs/x64_startup_100f1aa0_empty_spec.md",
        "scripts/x64_startup_100f1aa0_empty_fixture.json",
        "scripts/test_x64_startup_100f1aa0_empty_provenance.py",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100f1aa0.c",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ef330.c",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100d6560.c",
        "src_canonical_out/empire.retail.dll/canonical_function_index.tsv",
        "generated/canonical/0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70/references.tsv",
        "docs/pi_startup_abi_oracle_mutation_contract_v3.md",
    ),
    "O04": (
        "docs/x64_startup_100ed3c0_abi_contract.md",
        "docs/x64_startup_100f1c10_spec.md",
        "docs/x64_startup_100f1aa0_empty_spec.md",
        "scripts/test_x64_startup_100f1c10_provenance.py",
        "CMakeLists.txt",
        "port/x64_bootstrap/empire_bootstrap.c",
        "port/x64_bootstrap/empire_bootstrap.def",
        "port/x64_probe/probe_exports.def",
        "port/x64_exports/export_manifest.tsv",
        "port/x64_exports/empire.retail.exports.def",
        "Total War Rome II/empire.retail.dll",
        "docs/pi_startup_abi_oracle_mutation_contract_v3.md",
    ),
}

AUTHORITY_SET_MARKERS = {
    worker_id: f"AUTHORITY_SET={worker_id}_PINNED_CONTEXT_V1"
    for worker_id in WORKERS
}
O04_PRODUCTION_AUTHORITIES_MARKER = "PRODUCTION_AUTHORITIES=" + "|".join(
    REQUIRED_CONTEXT_AUTHORITIES["O04"]
)


# Exact v8 prompt markers.  Several tests intentionally carry multiple
# independent markers because the transport schema has no fact array.
TEST_MARKERS: dict[str, dict[str, tuple[str, ...]]] = {
    "O01": {
        "O01.T1": (
            "RAW_PROVENANCE=COMPLETE_PINNED_PE_SLICES",
            AUTHORITY_SET_MARKERS["O01"],
        ),
        "O01.T2": (
            "PUSH_ORDER=P4_P3_P2_P1_MACHINE_ORDER",
            "STACK_READ_SCOPE=BOUNDED_DIRECT_ESP_DISP32_P1_P3_ONLY_P2_P4_UNREAD_ALTERNATE_ADDRESSING_UNEXCLUDED",
        ),
        "O01.T3": ("PRIOR_LOADS=OBSERVATIONS_NOT_DEF_USE",),
        "O01.T4": ("REL32_EQUATION=NEXT_VA_PLUS_SIGNED_REL32",),
        "O01.T5": ("CLEANUP=CALLER_GROUPED_24_CALLEE_0",),
        "O01.T6": ("TRUNCATION=FAIL_CLOSED_NO_PREFIX_ACCEPTANCE",),
        "O01.T7": ("BRANCH_IDENTITY=FULL_PACKET_AND_CONTINUATION_DIGESTS",),
        "O01.T8": ("PE_MAPPING=VALIDATE_HEADERS_BEFORE_VA_TRANSLATION",),
    },
    "O02": {
        "O02.T1": (
            "DECODE_COVERAGE=GAP_FREE_EXACT_400_BYTES_100ED3C0_TO_100ED550",
            "STACK_SCOPE=SPARSE_FIXTURE_ROWS_NOT_GLOBAL_FLOW",
            AUTHORITY_SET_MARKERS["O02"],
        ),
        "O02.T2": ("REL32_EQUATION=NEXT_VA_PLUS_SIGNED_REL32",),
        "O02.T3": (
            "REGISTER_SCOPE=ESI_SAVE_RESTORE_EAX_ECX_EDX_FLAGS_RETURN_UNSTABLE_OTHERS_UNPROVEN",
        ),
        "O02.T4": (
            "STACK_READ_SCOPE=DIRECT_ESP_DISP32_ONLY_ALTERNATE_ADDRESSING_UNEXCLUDED",
        ),
        "O02.T5": (
            "CFG_SHAPE=CYCLIC_EXIT_100ED4E7_TO_100ED50B_BACK_EDGES_100ED4D2_TO_100ED4C1__100ED509_TO_100ED4F0__100ED516_TO_100ED472",
        ),
        "O02.T6": ("GUEST_ADDRESSING=OPAQUE32_NO_HOST_POINTER",),
        "O02.T7": (
            "FORBIDDEN_INSTRUCTION_CASE=UD2_AT_100ED3C0_PLUS_FOUR_NOPS",
        ),
        "O02.T8": (
            "RETURN_CONTRACT=ONE_BARE_RET_CALLER_GROUPED_24_NO_DIRECT_POSITION4_READ",
        ),
    },
    "O03": {
        "O03.T1": (
            "RAW_BYTES_AUTHORITY=PINNED_PE_ONLY",
            "DERIVED_EXPECTATIONS_AUTHORITY=PINNED_FIXTURE_ONLY",
            "INDEX_AUTHORITY=IDENTITY_ONLY_NO_RAW_OFFSETS_OR_RAW_HASHES",
            "EMPTY_BODIES=PINNED_COMPLETE_HASHES",
            AUTHORITY_SET_MARKERS["O03"],
        ),
        "O03.T2": ("REL32_EQUATION=NEXT_VA_PLUS_SIGNED_REL32",),
        "O03.T3": ("ZERO_PREFIX=EXACT_23_BYTES_END_100EF347",),
        "O03.T4": ("EMPTY_STOP=JNE_TARGET_100EF347_EXCLUDED",),
        "O03.T5": (
            "ALLOCATOR_CALL=AUTHENTICATED_EXCLUSION_ONLY",
            "ALLOCATOR_SCAN_SCOPE=SELECTED_RAW_SLICE_AND_DECLARED_VERIFIER_OUTPUTS_ONLY",
        ),
        "O03.T6": (
            "PARENT_SITES=100ED419_AND_100ED427_TARGET_100F1AA0_PARENT_NO_GO",
        ),
        "O03.T7": (
            "GUEST_IDENTITY=11AF4090_OPAQUE32_NOT_POINTER",
            "GUEST_WIDTH=IDENTITY_AND_API_STORAGE_GUEST32_CHECKED_WIDER_TEMPORARIES_ALLOWED",
        ),
        "O03.T8": (
            "X86_RET=STACK_FACT_NOT_NATIVE_ABI",
            "NATIVE_DELEGATION=NONE_F1C10_TEST_ONLY_CORROBORATION",
        ),
    },
    "O04": {
        "O04.T1": (
            "PROVENANCE_SCOPE=PINNED_DECLARED_INPUTS_ONLY",
            AUTHORITY_SET_MARKERS["O04"],
        ),
        "O04.T2": ("REL32_EQUATION=NEXT_VA_PLUS_SIGNED_REL32",),
        "O04.T3": ("STACK_CONTRACT=E0_POSITIONS_AND_CALLER_GROUPED_CLEANUP",),
        "O04.T4": (
            "REGISTER_SCOPE=ESI_SAVE_RESTORE_EAX_ECX_EDX_FLAGS_RETURN_UNSTABLE_OTHERS_UNPROVEN",
        ),
        "O04.T5": (
            "MALFORMED_CASES=DISPOSABLE_WORKSPACE_COPIES_FAIL_CLOSED",
        ),
        "O04.T6": (
            "RECOVERED_IDENTIFIERS=INERT_DATA_ALLOWED_IMPORT_LOAD_LINK_EXECUTE_FORBIDDEN",
        ),
        "O04.T7": (
            "BUILD_TESTING_CHECK=BALANCED_SCOPE_EXACT_OWNERS_NO_ELSE_NO_OVERRIDE",
            "LEGACY_100D6560=PREEXISTING_NAMES_NOT_ABI_PROOF_NO_NEW_EXPOSURE",
            O04_PRODUCTION_AUTHORITIES_MARKER,
        ),
        "O04.T8": (
            "WRITE_OBSERVATION=DISPOSABLE_SANDBOX_DENY_OUTSIDE_AND_AUDIT_ATTEMPTS",
            "GUEST_IDENTITY=11AF4090_OPAQUE32_NOT_POINTER",
        ),
    },
}


# The whole description is closed-world.  It is not a prefix check: appended
# prose, "or" alternatives, and compound mutations all fail exact equality.
EXACT_MUTATION_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "O01": {
        "O01.M1": "EXACT_SINGLE_MUTATION: O01_M1_FLIP_HANDLER_PACKET_BYTE",
        "O01.M2": "EXACT_SINGLE_MUTATION: O01_M2_SWAP_PUSHES_3_AND_4",
        "O01.M3": "EXACT_SINGLE_MUTATION: O01_M3_PROMOTE_ESI_PRIOR_LOAD_TO_PROVEN",
        "O01.M4": "EXACT_SINGLE_MUTATION: O01_M4_USE_CALL_VA_AS_REL32_BASE",
        "O01.M5": "EXACT_SINGLE_MUTATION: O01_M5_REPLACE_BARE_RET_WITH_RET4",
        "O01.M6": "EXACT_SINGLE_MUTATION: O01_M6_TRUNCATE_HANDLER_PACKET_TO_12_BYTES",
        "O01.M7": "EXACT_SINGLE_MUTATION: O01_M7_SWAP_CONTINUATION_IDENTITY",
        "O01.M8": "EXACT_SINGLE_MUTATION: O01_M8_CORRUPT_PE_OPTIONAL_MAGIC",
    },
    "O02": {
        "O02.M1": "EXACT_SINGLE_MUTATION: O02_M1_TREAT_SPARSE_ROWS_AS_GLOBAL_FLOW",
        "O02.M2": "EXACT_SINGLE_MUTATION: O02_M2_USE_CALL_VA_AS_REL32_BASE",
        "O02.M3": "EXACT_SINGLE_MUTATION: O02_M3_MARK_EBX_STABLE",
        "O02.M4": "EXACT_SINGLE_MUTATION: O02_M4_REPLACE_100ED3ED_DISP_0910_WITH_091C_P4",
        "O02.M5": "EXACT_SINGLE_MUTATION: O02_M5_REPLACE_100ED4D2_75ED_WITH_9090",
        "O02.M6": "EXACT_SINGLE_MUTATION: O02_M6_USE_ZERO_ESP_DELTA_FOR_ALL_ROWS",
        "O02.M7": "EXACT_SINGLE_MUTATION: O02_M7_REPLACE_100ED3C0_81EC0C090000_WITH_0F0B90909090",
        "O02.M8": "EXACT_SINGLE_MUTATION: O02_M8_REPLACE_FINAL_C3_WITH_C20400",
    },
    "O03": {
        "O03.M1": "EXACT_SINGLE_MUTATION: O03_M1_TRUNCATE_100F1AA0_BODY_TO_31_BYTES",
        "O03.M2": "EXACT_SINGLE_MUTATION: O03_M2_RETARGET_100F1AB4_TO_100F1C10",
        "O03.M3": "EXACT_SINGLE_MUTATION: O03_M3_TRUNCATE_ZERO_PREFIX_TO_22_BYTES",
        "O03.M4": "EXACT_SINGLE_MUTATION: O03_M4_MOVE_STOP_TO_100EF348",
        "O03.M5": "EXACT_SINGLE_MUTATION: O03_M5_INCLUDE_ALLOCATOR_CALL_AT_100EF354",
        "O03.M6": "EXACT_SINGLE_MUTATION: O03_M6_DROP_PARENT_SITE_100ED427",
        "O03.M7": "EXACT_SINGLE_MUTATION: O03_M7_CAST_11AF4090_TO_HOST_POINTER",
        "O03.M8": "EXACT_SINGLE_MUTATION: O03_M8_PROMOTE_RET8_TO_NATIVE_ABI",
    },
    "O04": {
        "O04.M1": "EXACT_SINGLE_MUTATION: O04_M1_SKIP_ONE_PINNED_SOURCE_HASH",
        "O04.M2": "EXACT_SINGLE_MUTATION: O04_M2_USE_CALL_VA_AS_REL32_BASE",
        "O04.M3": "EXACT_SINGLE_MUTATION: O04_M3_TRUST_POSITIVE_DECOMPILER_STACK_NAME",
        "O04.M4": "EXACT_SINGLE_MUTATION: O04_M4_MARK_EBX_STABLE",
        "O04.M5": "EXACT_SINGLE_MUTATION: O04_M5_WARN_AND_ACCEPT_MALFORMED_PE",
        "O04.M6": "EXACT_SINGLE_MUTATION: O04_M6_ALLOW_ORIGINAL_DLL_LOAD_POLICY",
        "O04.M7": "EXACT_SINGLE_MUTATION: O04_M7_APPEND_PRODUCTION_CONSUMER_EDGE",
        "O04.M8": "EXACT_SINGLE_MUTATION: O04_M8_ATTEMPT_ONE_BYTE_WRITE_OUTSIDE_DISPOSABLE_WORKSPACE",
    },
}


# Closed-world v3 mutation rows.  These values are embedded deliberately: the
# semantic gate never trusts the mutable design document or calibration output
# as a runtime source of truth.
EXPECTED_MUTATION_RECORDS: dict[str, dict[str, Any]] = {
  "O01.M1": {
    "description": "EXACT_SINGLE_MUTATION: O01_M1_FLIP_HANDLER_PACKET_BYTE",
    "required_kill_code": "PACKET_OPCODE_MISMATCH_AT_0",
    "mutation": {
      "subject_kind": "authenticated_pe_packet_copy",
      "subject_path": "mutants/O01_M1/handler_packet.bin",
      "operation": "replace_bytes",
      "locus": "subject byte offset 0, length 1; original-PE raw offset 0x000ed320",
      "before": "ff",
      "after": "fe"
    }
  },
  "O01.M2": {
    "description": "EXACT_SINGLE_MUTATION: O01_M2_SWAP_PUSHES_3_AND_4",
    "required_kill_code": "PUSH_ORDER_SLOTS_3_4_SWAPPED",
    "mutation": {
      "subject_kind": "authenticated_pe_packet_copy",
      "subject_path": "mutants/O01_M2/handler_packet.bin",
      "operation": "replace_bytes",
      "locus": "subject byte offset 4, length 4; original-PE raw offset 0x000ed324",
      "before": "ff750c56",
      "after": "56ff750c"
    }
  },
  "O01.M3": {
    "description": "EXACT_SINGLE_MUTATION: O01_M3_PROMOTE_ESI_PRIOR_LOAD_TO_PROVEN",
    "required_kill_code": "UNSUPPORTED_ESI_DEF_USE_PROMOTION",
    "mutation": {
      "subject_kind": "derived_claim_record",
      "subject_path": "mutants/O01_M3/prior_loads.json",
      "operation": "json_replace",
      "locus": "/claims/esi_prior_load/status",
      "before": "\"observation\"",
      "after": "\"proven_def_use\""
    }
  },
  "O01.M4": {
    "description": "EXACT_SINGLE_MUTATION: O01_M4_USE_CALL_VA_AS_REL32_BASE",
    "required_kill_code": "REL32_TARGET_MISMATCH",
    "mutation": {
      "subject_kind": "derived_rel32_policy",
      "subject_path": "mutants/O01_M4/rel32.json",
      "operation": "json_replace",
      "locus": "/base_mode",
      "before": "\"NEXT_VA\"",
      "after": "\"CALL_VA\""
    }
  },
  "O01.M5": {
    "description": "EXACT_SINGLE_MUTATION: O01_M5_REPLACE_BARE_RET_WITH_RET4",
    "required_kill_code": "CALLEE_CLEANUP_4_NOT_0",
    "mutation": {
      "subject_kind": "authenticated_epilogue_slice",
      "subject_path": "mutants/O01_M5/epilogue.bin",
      "operation": "splice_bytes",
      "locus": "epilogue byte offset 7, remove length 1; callee-body offset 399; original-PE raw offset 0x000ec94f",
      "before": "c3",
      "after": "c20400"
    }
  },
  "O01.M6": {
    "description": "EXACT_SINGLE_MUTATION: O01_M6_TRUNCATE_HANDLER_PACKET_TO_12_BYTES",
    "required_kill_code": "HANDLER_PACKET_TRUNCATED_12_NOT_13",
    "mutation": {
      "subject_kind": "authenticated_pe_packet_copy",
      "subject_path": "mutants/O01_M6/handler_packet.bin",
      "operation": "delete_bytes",
      "locus": "subject byte offset 12, length 1; original-PE raw offset 0x000ed32c",
      "before": "ff",
      "after": "ABSENT"
    }
  },
  "O01.M7": {
    "description": "EXACT_SINGLE_MUTATION: O01_M7_SWAP_CONTINUATION_IDENTITY",
    "required_kill_code": "BRANCH_CONTINUATION_IDENTITIES_SWAPPED",
    "mutation": {
      "subject_kind": "derived_branch_digest_map",
      "subject_path": "mutants/O01_M7/branches.json",
      "operation": "json_replace",
      "locus": "/continuation_sha256_by_branch",
      "before": "{\"handler_registered\":\"16059cc15e0932ce776ddaeb4f7e5e991eb8fe6776f279d8b3dacc4238826954\",\"no_exception_handler\":\"2bb4e7d91eb623e2d1bb5e99c1c71431bd06fb60fb1ae5316da895dcdad3e7ba\"}",
      "after": "{\"handler_registered\":\"2bb4e7d91eb623e2d1bb5e99c1c71431bd06fb60fb1ae5316da895dcdad3e7ba\",\"no_exception_handler\":\"16059cc15e0932ce776ddaeb4f7e5e991eb8fe6776f279d8b3dacc4238826954\"}"
    }
  },
  "O01.M8": {
    "description": "EXACT_SINGLE_MUTATION: O01_M8_CORRUPT_PE_OPTIONAL_MAGIC",
    "required_kill_code": "UNSUPPORTED_OPTIONAL_MAGIC",
    "mutation": {
      "subject_kind": "disposable_full_pe_copy",
      "subject_path": "mutants/O01_M8/empire.retail.dll",
      "operation": "replace_bytes",
      "locus": "raw file offset 0x000001a8, length 2; e_lfanew 0x190 plus PE/COFF prefix length 0x18",
      "before": "0b01",
      "after": "5901"
    }
  },
  "O02.M1": {
    "description": "EXACT_SINGLE_MUTATION: O02_M1_TREAT_SPARSE_ROWS_AS_GLOBAL_FLOW",
    "required_kill_code": "SPARSE_ROWS_PROMOTED_TO_GLOBAL_FLOW",
    "mutation": {
      "subject_kind": "derived_decode_policy",
      "subject_path": "mutants/O02_M1/decode_policy.json",
      "operation": "json_replace",
      "locus": "/fixture_rows_semantics",
      "before": "\"LOCAL_OBSERVATIONS_ONLY\"",
      "after": "\"COMPLETE_INSTRUCTION_STREAM\""
    }
  },
  "O02.M2": {
    "description": "EXACT_SINGLE_MUTATION: O02_M2_USE_CALL_VA_AS_REL32_BASE",
    "required_kill_code": "REL32_TARGET_MISMATCH",
    "mutation": {
      "subject_kind": "derived_rel32_policy",
      "subject_path": "mutants/O02_M2/rel32.json",
      "operation": "json_replace",
      "locus": "/base_mode",
      "before": "\"NEXT_VA\"",
      "after": "\"CALL_VA\""
    }
  },
  "O02.M3": {
    "description": "EXACT_SINGLE_MUTATION: O02_M3_MARK_EBX_STABLE",
    "required_kill_code": "UNPROVEN_EBX_PROMOTED_STABLE",
    "mutation": {
      "subject_kind": "derived_register_contract",
      "subject_path": "mutants/O02_M3/registers.json",
      "operation": "json_replace",
      "locus": "/registers/ebx",
      "before": "\"UNPROVEN\"",
      "after": "\"STABLE\""
    }
  },
  "O02.M4": {
    "description": "EXACT_SINGLE_MUTATION: O02_M4_REPLACE_100ED3ED_DISP_0910_WITH_091C_P4",
    "required_kill_code": "DIRECT_POSITION_4_READ_AT_100ED3ED",
    "mutation": {
      "subject_kind": "authenticated_400_byte_body_copy",
      "subject_path": "mutants/O02_M4/body.bin",
      "operation": "replace_bytes",
      "locus": "body byte offset 48, length 2; original-PE raw offset 0x000ec7f0; operand VA 0x100ed3f0 in the instruction beginning at 0x100ed3ed",
      "before": "1009",
      "after": "1c09"
    }
  },
  "O02.M5": {
    "description": "EXACT_SINGLE_MUTATION: O02_M5_REPLACE_100ED4D2_75ED_WITH_9090",
    "required_kill_code": "MISSING_BACK_EDGE_100ED4D2_TO_100ED4C1",
    "mutation": {
      "subject_kind": "authenticated_400_byte_body_copy",
      "subject_path": "mutants/O02_M5/body.bin",
      "operation": "replace_bytes",
      "locus": "body byte offset 274, length 2; original-PE raw offset 0x000ec8d2",
      "before": "75ed",
      "after": "9090"
    }
  },
  "O02.M6": {
    "description": "EXACT_SINGLE_MUTATION: O02_M6_USE_ZERO_ESP_DELTA_FOR_ALL_ROWS",
    "required_kill_code": "ESP_DELTA_VECTOR_MISMATCH",
    "mutation": {
      "subject_kind": "derived_critical_row_vector",
      "subject_path": "mutants/O02_M6/esp_deltas.json",
      "operation": "json_replace",
      "locus": "/esp_delta_before",
      "before": "[0,-2316,-2316,-2316,-2320,-2320,-2320,-2320,-2320,-2320,-2320,-2316,0]",
      "after": "[0,0,0,0,0,0,0,0,0,0,0,0,0]"
    }
  },
  "O02.M7": {
    "description": "EXACT_SINGLE_MUTATION: O02_M7_REPLACE_100ED3C0_81EC0C090000_WITH_0F0B90909090",
    "required_kill_code": "FORBIDDEN_UD2_AT_ENTRY",
    "mutation": {
      "subject_kind": "authenticated_400_byte_body_copy",
      "subject_path": "mutants/O02_M7/body.bin",
      "operation": "replace_bytes",
      "locus": "body byte offset 0, length 6; original-PE raw offset 0x000ec7c0",
      "before": "81ec0c090000",
      "after": "0f0b90909090"
    }
  },
  "O02.M8": {
    "description": "EXACT_SINGLE_MUTATION: O02_M8_REPLACE_FINAL_C3_WITH_C20400",
    "required_kill_code": "CALLEE_CLEANUP_4_NOT_0",
    "mutation": {
      "subject_kind": "authenticated_epilogue_slice",
      "subject_path": "mutants/O02_M8/epilogue.bin",
      "operation": "splice_bytes",
      "locus": "epilogue byte offset 7, remove length 1; callee-body offset 399; original-PE raw offset 0x000ec94f",
      "before": "c3",
      "after": "c20400"
    }
  },
  "O03.M1": {
    "description": "EXACT_SINGLE_MUTATION: O03_M1_TRUNCATE_100F1AA0_BODY_TO_31_BYTES",
    "required_kill_code": "BODY_EXTENT_31_NOT_32",
    "mutation": {
      "subject_kind": "authenticated_100f1aa0_body_copy",
      "subject_path": "mutants/O03_M1/body.bin",
      "operation": "delete_bytes",
      "locus": "body byte offset 31, length 1; original-PE raw offset 0x000f0ebf",
      "before": "00",
      "after": "ABSENT"
    }
  },
  "O03.M2": {
    "description": "EXACT_SINGLE_MUTATION: O03_M2_RETARGET_100F1AB4_TO_100F1C10",
    "required_kill_code": "ORIGINAL_CALL_TARGET_NOT_100EF330",
    "mutation": {
      "subject_kind": "authenticated_100f1aa0_body_copy",
      "subject_path": "mutants/O03_M2/body.bin",
      "operation": "replace_bytes",
      "locus": "body byte offset 21, length 4; original-PE raw offset 0x000f0eb5; rel32 operand following E8 at body offset 20",
      "before": "77d8ffff",
      "after": "57010000"
    }
  },
  "O03.M3": {
    "description": "EXACT_SINGLE_MUTATION: O03_M3_TRUNCATE_ZERO_PREFIX_TO_22_BYTES",
    "required_kill_code": "ZERO_PREFIX_22_NOT_23",
    "mutation": {
      "subject_kind": "authenticated_zero_prefix_copy",
      "subject_path": "mutants/O03_M3/zero_prefix.bin",
      "operation": "delete_bytes",
      "locus": "prefix byte offset 22, length 1; original-PE raw offset 0x000ee746",
      "before": "00",
      "after": "ABSENT"
    }
  },
  "O03.M4": {
    "description": "EXACT_SINGLE_MUTATION: O03_M4_MOVE_STOP_TO_100EF348",
    "required_kill_code": "STOP_INCLUDES_JNE_TARGET_BYTE_100EF347",
    "mutation": {
      "subject_kind": "derived_slice_boundary_record",
      "subject_path": "mutants/O03_M4/empty_slice.json",
      "operation": "json_replace",
      "locus": "/va_end_exclusive",
      "before": "\"0x100ef347\"",
      "after": "\"0x100ef348\""
    }
  },
  "O03.M5": {
    "description": "EXACT_SINGLE_MUTATION: O03_M5_INCLUDE_ALLOCATOR_CALL_AT_100EF354",
    "required_kill_code": "ALLOCATOR_CALL_100EF354_INCLUDED",
    "mutation": {
      "subject_kind": "derived_slice_boundary_record",
      "subject_path": "mutants/O03_M5/empty_slice.json",
      "operation": "json_replace",
      "locus": "/va_end_exclusive",
      "before": "\"0x100ef347\"",
      "after": "\"0x100ef359\""
    }
  },
  "O03.M6": {
    "description": "EXACT_SINGLE_MUTATION: O03_M6_DROP_PARENT_SITE_100ED427",
    "required_kill_code": "PARENT_SITE_SET_MISSING_100ED427",
    "mutation": {
      "subject_kind": "disposable_empty_fixture_copy",
      "subject_path": "mutants/O03_M6/fixture.json",
      "operation": "json_remove",
      "locus": "/parent_window/calls/1",
      "before": "{\"va\":\"0x100ed427\",\"bytes\":\"e874460000\",\"next_va\":\"0x100ed42c\",\"rel32\":18036,\"target_va\":\"0x100f1aa0\"}",
      "after": "ABSENT"
    }
  },
  "O03.M7": {
    "description": "EXACT_SINGLE_MUTATION: O03_M7_CAST_11AF4090_TO_HOST_POINTER",
    "required_kill_code": "HOST_POINTER_CLASSIFICATION_FORBIDDEN",
    "mutation": {
      "subject_kind": "derived_guest_identity_classification",
      "subject_path": "mutants/O03_M7/guest_identity.json",
      "operation": "json_replace",
      "locus": "/classification",
      "before": "\"OPAQUE_GUEST32\"",
      "after": "\"HOST_POINTER\""
    }
  },
  "O03.M8": {
    "description": "EXACT_SINGLE_MUTATION: O03_M8_PROMOTE_RET8_TO_NATIVE_ABI",
    "required_kill_code": "NATIVE_ABI_PROMOTION_FORBIDDEN",
    "mutation": {
      "subject_kind": "derived_return_classification",
      "subject_path": "mutants/O03_M8/ret8.json",
      "operation": "json_replace",
      "locus": "/classification",
      "before": "\"X86_STACK_FACT_ONLY\"",
      "after": "\"NATIVE_ABI\""
    }
  },
  "O04.M1": {
    "description": "EXACT_SINGLE_MUTATION: O04_M1_SKIP_ONE_PINNED_SOURCE_HASH",
    "required_kill_code": "MISSING_PIN_port/x64_exports/export_manifest.tsv",
    "mutation": {
      "subject_kind": "disposable_pin_array",
      "subject_path": "mutants/O04_M1/pins.json",
      "operation": "json_remove",
      "locus": "/pins/8",
      "before": "{\"path\":\"port/x64_exports/export_manifest.tsv\",\"sha256\":\"e1df5a9e9e20c555a7d1d97a106b469e961c4abf88dcd03889c3a126d152b117\",\"byte_count\":116429}",
      "after": "ABSENT"
    }
  },
  "O04.M2": {
    "description": "EXACT_SINGLE_MUTATION: O04_M2_USE_CALL_VA_AS_REL32_BASE",
    "required_kill_code": "REL32_TARGET_MISMATCH",
    "mutation": {
      "subject_kind": "derived_rel32_policy",
      "subject_path": "mutants/O04_M2/rel32.json",
      "operation": "json_replace",
      "locus": "/caller_packets/0/base_mode",
      "before": "\"NEXT_VA\"",
      "after": "\"CALL_VA\""
    }
  },
  "O04.M3": {
    "description": "EXACT_SINGLE_MUTATION: O04_M3_TRUST_POSITIVE_DECOMPILER_STACK_NAME",
    "required_kill_code": "DECOMPILER_NAME_NOT_STACK_AUTHORITY",
    "mutation": {
      "subject_kind": "derived_stack_evidence_record",
      "subject_path": "mutants/O04_M3/stack_evidence.json",
      "operation": "json_replace",
      "locus": "/position_1/authority_kind",
      "before": "\"RAW_BYTES\"",
      "after": "\"DECOMPILER_NAME\""
    }
  },
  "O04.M4": {
    "description": "EXACT_SINGLE_MUTATION: O04_M4_MARK_EBX_STABLE",
    "required_kill_code": "UNPROVEN_EBX_PROMOTED_STABLE",
    "mutation": {
      "subject_kind": "derived_register_contract",
      "subject_path": "mutants/O04_M4/registers.json",
      "operation": "json_replace",
      "locus": "/registers/ebx",
      "before": "\"UNPROVEN\"",
      "after": "\"STABLE\""
    }
  },
  "O04.M5": {
    "description": "EXACT_SINGLE_MUTATION: O04_M5_WARN_AND_ACCEPT_MALFORMED_PE",
    "required_kill_code": "MALFORMED_PE_ACCEPTANCE_POLICY",
    "mutation": {
      "subject_kind": "derived_malformed_policy",
      "subject_path": "mutants/O04_M5/policy.json",
      "operation": "json_replace",
      "locus": "/malformed_policy",
      "before": "\"FAIL_CLOSED\"",
      "after": "\"WARN_AND_ACCEPT\""
    }
  },
  "O04.M6": {
    "description": "EXACT_SINGLE_MUTATION: O04_M6_ALLOW_ORIGINAL_DLL_LOAD_POLICY",
    "required_kill_code": "ORIGINAL_DLL_LOAD_POLICY_NOT_FORBIDDEN",
    "mutation": {
      "subject_kind": "derived_containment_policy",
      "subject_path": "mutants/O04_M6/policy.json",
      "operation": "json_replace",
      "locus": "/dll_load_policy",
      "before": "\"NO_LOAD\"",
      "after": "\"LOAD_ALLOWED\""
    }
  },
  "O04.M7": {
    "description": "EXACT_SINGLE_MUTATION: O04_M7_APPEND_PRODUCTION_CONSUMER_EDGE",
    "required_kill_code": "PRODUCTION_CONSUMER_EDGE_TO_EMPTY_RUNTIME",
    "mutation": {
      "subject_kind": "disposable_cmake_copy",
      "subject_path": "mutants/O04_M7/CMakeLists.txt",
      "operation": "insert_bytes",
      "locus": "byte offset 30474, remove length 0; EOF immediately after the final bytes 656e64696628290a, which encode endif() followed by LF",
      "before": "EMPTY",
      "after": "target_link_libraries(empire_retail_bootstrap PRIVATE rome2_startup_100f1aa0_empty_runtime)\n"
    }
  },
  "O04.M8": {
    "description": "EXACT_SINGLE_MUTATION: O04_M8_ATTEMPT_ONE_BYTE_WRITE_OUTSIDE_DISPOSABLE_WORKSPACE",
    "required_kill_code": "DENIED_OUTSIDE_WRITE_ATTEMPT",
    "mutation": {
      "subject_kind": "derived_guard_action",
      "subject_path": "mutants/O04_M8/sandbox.json",
      "operation": "json_replace",
      "locus": "/outside_write_action",
      "before": "{\"kind\":\"NONE\"}",
      "after": "{\"kind\":\"WRITE_BYTE\",\"relative_path\":\"../outside-sentinel.bin\",\"offset\":0,\"before\":\"a5\",\"after\":\"00\"}"
    }
  }
}

REQUIRED_KILL_CODES: dict[str, str] = {
    mutant_id: record["required_kill_code"]
    for mutant_id, record in EXPECTED_MUTATION_RECORDS.items()
}
EXACT_TEST_PROCEDURES: dict[str, str] = {
    f"{worker_id}.T{index}": (
        "Authenticate every declared pristine authority, run the unchanged checker, "
        "and require the pristine baseline to pass. Apply only "
        f"{worker_id}.M{index}'s exact structured mutation to its disposable subject, "
        "rerun the same unchanged checker, and require its assigned fail code."
    )
    for worker_id in WORKERS
    for index in range(1, 9)
}
EXACT_TEST_EXPECTATIONS: dict[str, str] = {
    f"{worker_id}.T{index}": (
        "PRISTINE_PASS; MUTANT_FAIL_CODE="
        + REQUIRED_KILL_CODES[f"{worker_id}.M{index}"]
    )
    for worker_id in WORKERS
    for index in range(1, 9)
}
KILL_CODE_MARKERS: dict[str, str] = {
    test_id: expected.split("; ", 1)[1]
    for test_id, expected in EXACT_TEST_EXPECTATIONS.items()
}


GATE_SOURCE_NAMES = frozenset(
    {
        "pi_startup_abi_oracle_gate.py",
        "test_pi_startup_abi_oracle_gate.py",
        "pi_startup_abi_oracle_gate_v2.py",
        "test_pi_startup_abi_oracle_gate_v2.py",
        "pi_startup_abi_oracle_gate_v3.py",
        "test_pi_startup_abi_oracle_gate_v3.py",
        "pi_startup_abi_oracle_gate_v4.py",
        "test_pi_startup_abi_oracle_gate_v4.py",
        "pi_startup_abi_oracle_mutation_contract_v3.md",
        "pi_wave3_oracle_v3.schema.json",
        "pi_wave3_startup_abi_v9.json",
    }
)
DOCUMENT_KEYS = frozenset({"worker_id", "stage", "tests", "mutants", "blockers"})
TEST_KEYS = frozenset(
    {"test_id", "requirement_ids", "description", "procedure", "expected", "mutant_ids"}
)
MUTANT_KEYS = frozenset(
    {"mutant_id", "critical", "description", "mutation", "expected_killer_ids"}
)
MUTATION_KEYS = frozenset(
    {"subject_kind", "subject_path", "operation", "locus", "before", "after"}
)
CONTEXT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "worker_id",
        "stage",
        "config_sha256",
        "stage_config_sha256",
        "generated_utc",
        "declared_inputs",
        "validation_schemas",
        "dependency_stage_manifests",
    }
)
PIN_KEYS = frozenset({"path", "sha256", "byte_count"})
STRUCTURED_MARKER_RE = re.compile(r"\b[A-Z][A-Z0-9_]*=[A-Za-z0-9_./|:-]+")

# A supervisor invokes this script in a fresh process.  The cache avoids
# repeatedly hashing shared 20-30 MB authorities in the in-process regression
# suite while each real CLI invocation still starts from an empty cache.
_LIVE_HASH_CACHE: dict[
    tuple[str, int, int, int, int, int], tuple[str, int]
] = {}


class _DuplicateJsonKey(ValueError):
    pass


class _NonFiniteJsonNumber(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise _NonFiniteJsonNumber(f"non-finite JSON number {value}")


def _finite_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise _NonFiniteJsonNumber(f"non-finite JSON number {value}")
    return result


def _normalized_text(value: Any) -> str:
    return re.sub(r"\s+", " ", value).strip().lower() if isinstance(value, str) else ""


def _resolve_contained_file(
    path: Path,
    containment_root: Path,
    label: str,
    issues: list[str],
    *,
    reject_symlink: bool = False,
) -> Path | None:
    if reject_symlink:
        try:
            if path.is_symlink():
                issues.append(f"{label}: artifact must not be a symlink")
                return None
        except OSError as exc:
            issues.append(f"{label}: cannot inspect artifact: {exc}")
            return None
    try:
        trusted_root = containment_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        issues.append(f"{label}: missing artifact: {exc}")
        return None
    if reject_symlink and path.is_symlink():
        issues.append(f"{label}: artifact must not be a symlink")
        return None
    if not resolved.is_relative_to(trusted_root):
        issues.append(f"{label}: path or symlink escapes its trusted root")
        return None
    if not resolved.is_file():
        issues.append(f"{label}: artifact is not a regular file")
        return None
    return resolved


def _read_stable_bytes(
    path: Path,
    label: str,
    issues: list[str],
    *,
    max_bytes: int,
) -> bytes | None:
    """Read one bounded file snapshot and reject an identity/content race."""

    try:
        before = _file_signature(path)
    except OSError as exc:
        issues.append(f"{label}: cannot stat artifact: {exc}")
        return None

    chunks: list[bytes] = []
    byte_count = 0
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            opened_identity = (
                int(opened.st_dev),
                int(opened.st_ino),
                int(opened.st_size),
                int(opened.st_mtime_ns),
            )
            if opened_identity != before[1:5]:
                issues.append(f"{label}: artifact changed before it was opened")
                return None
            while chunk := stream.read(min(65536, max_bytes + 1 - byte_count)):
                chunks.append(chunk)
                byte_count += len(chunk)
                if byte_count > max_bytes:
                    issues.append(f"{label}: JSON exceeds {max_bytes} bytes")
                    return None
        after = _file_signature(path)
    except OSError as exc:
        issues.append(f"{label}: cannot read artifact: {exc}")
        return None
    if after != before or byte_count != before[3]:
        issues.append(f"{label}: artifact changed while reading")
        return None
    return b"".join(chunks)


def _decode_json_object(
    raw: bytes, label: str, issues: list[str]
) -> dict[str, Any] | None:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        _NonFiniteJsonNumber,
    ) as exc:
        issues.append(f"{label}: invalid UTF-8 JSON: {exc}")
        return None
    if not isinstance(value, dict):
        issues.append(f"{label}: JSON root is not an object")
        return None
    return value


def _load_json_snapshot(
    path: Path,
    label: str,
    issues: list[str],
    *,
    containment_root: Path | None = None,
    reject_symlink: bool = False,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[dict[str, Any] | None, tuple[str, int] | None]:
    if containment_root is not None:
        resolved = _resolve_contained_file(
            path,
            containment_root,
            label,
            issues,
            reject_symlink=reject_symlink,
        )
        if resolved is None:
            return None, None
        path = resolved
    raw = _read_stable_bytes(path, label, issues, max_bytes=max_bytes)
    if raw is None:
        return None, None
    pin = (hashlib.sha256(raw).hexdigest(), len(raw))
    return _decode_json_object(raw, label, issues), pin


def _load_json(
    path: Path,
    label: str,
    issues: list[str],
    *,
    containment_root: Path | None = None,
    reject_symlink: bool = False,
) -> dict[str, Any] | None:
    value, _ = _load_json_snapshot(
        path,
        label,
        issues,
        containment_root=containment_root,
        reject_symlink=reject_symlink,
    )
    return value


def _safe_relative_repo_path(value: Any) -> tuple[bool, str]:
    if not isinstance(value, str) or not value:
        return False, "path is not a nonempty string"
    if "\\" in value:
        return False, "path contains a backslash"
    if "\x00" in value:
        return False, "path contains NUL"
    path = PurePosixPath(value)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", value):
        return False, "path is absolute"
    if any(part in {"", ".", ".."} for part in path.parts):
        return False, "path contains traversal or an empty segment"
    if str(path) != value:
        return False, "path is not in canonical POSIX spelling"
    return True, ""


def _resolve_repo_file(relative_path: Any, label: str, issues: list[str]) -> Path | None:
    safe, reason = _safe_relative_repo_path(relative_path)
    if not safe:
        issues.append(f"{label}: unsafe repository path: {reason}")
        return None
    candidate = TRUSTED_REPO_ROOT.joinpath(*PurePosixPath(relative_path).parts)
    return _resolve_contained_file(candidate, TRUSTED_REPO_ROOT, label, issues)


def _file_signature(path: Path) -> tuple[str, int, int, int, int, int]:
    stat = path.stat()
    return (
        str(path),
        int(stat.st_dev),
        int(stat.st_ino),
        int(stat.st_size),
        int(stat.st_mtime_ns),
        int(stat.st_ctime_ns),
    )


def _live_file_pin(path: Path, label: str, issues: list[str]) -> tuple[str, int] | None:
    try:
        before = _file_signature(path)
    except OSError as exc:
        issues.append(f"{label}: cannot stat live authority: {exc}")
        return None
    cached = _LIVE_HASH_CACHE.get(before)
    if cached is not None:
        return cached
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                byte_count += len(chunk)
        after = _file_signature(path)
    except OSError as exc:
        issues.append(f"{label}: cannot hash live authority: {exc}")
        return None
    if after != before or byte_count != before[3]:
        issues.append(f"{label}: live authority changed while hashing")
        return None
    result = (digest.hexdigest(), byte_count)
    _LIVE_HASH_CACHE[before] = result
    return result


def _resolve_state_absolute_path(
    value: Any,
    label: str,
    issues: list[str],
    *,
    expected: Path | None = None,
    containment_root: Path | None = None,
    file_required: bool = False,
    reject_symlink: bool = False,
) -> Path | None:
    if not isinstance(value, str) or not value:
        issues.append(f"{label}: path is not a nonempty string")
        return None
    if "\x00" in value:
        issues.append(f"{label}: path contains NUL")
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        issues.append(f"{label}: path is not absolute")
        return None
    if any(part in {".", ".."} for part in candidate.parts):
        issues.append(f"{label}: path contains traversal")
        return None
    if reject_symlink:
        try:
            if candidate.is_symlink():
                issues.append(f"{label}: path must not be a symlink")
                return None
        except OSError as exc:
            issues.append(f"{label}: cannot inspect path: {exc}")
            return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        issues.append(f"{label}: missing path: {exc}")
        return None
    if reject_symlink and candidate.is_symlink():
        issues.append(f"{label}: path must not be a symlink")
        return None
    if containment_root is not None:
        try:
            trusted_root = containment_root.resolve(strict=True)
        except OSError as exc:
            issues.append(f"{label}: trusted root is unavailable: {exc}")
            return None
        if not resolved.is_relative_to(trusted_root):
            issues.append(f"{label}: path escapes the trusted repository")
            return None
    if expected is not None:
        try:
            expected_resolved = expected.resolve(strict=True)
        except OSError as exc:
            issues.append(f"{label}: expected path is unavailable: {exc}")
            return None
        if resolved != expected_resolved:
            issues.append(f"{label}: path does not match the supervisor run")
            return None
    if file_required and not resolved.is_file():
        issues.append(f"{label}: path is not a regular file")
        return None
    if not file_required and not resolved.is_dir():
        issues.append(f"{label}: path is not a directory")
        return None
    return resolved


def _project_o_workers(
    workers: Any,
    label: str,
    issues: list[str],
    *,
    require_only_o_workers: bool = False,
) -> list[dict[str, Any]] | None:
    if not isinstance(workers, list):
        issues.append(f"{label}: workers is not an array")
        return None
    if require_only_o_workers:
        if len(workers) != len(WORKERS) or any(
            not isinstance(worker, dict) for worker in workers
        ):
            issues.append(
                f"{label}: workers must be exactly {','.join(WORKERS)} with no other entries"
            )
            return None
        relevant = workers
    else:
        relevant = [
            worker
            for worker in workers
            if isinstance(worker, dict)
            and (worker.get("stage") == "O" or worker.get("id") in WORKERS)
        ]
    ids = [worker.get("id") for worker in relevant]
    if ids != list(WORKERS):
        qualifier = "workers" if require_only_o_workers else "O workers"
        issues.append(
            f"{label}: {qualifier} are not exactly {','.join(WORKERS)} in order"
        )
        return None

    expected_keys = frozenset((*O_WORKER_CONFIG_KEYS, "stage"))
    projected: list[dict[str, Any]] = []
    for expected_id, worker in zip(WORKERS, relevant, strict=True):
        if set(worker) != expected_keys:
            issues.append(f"{label}: {expected_id} worker keys are not exact")
            return None
        if worker.get("id") != expected_id or worker.get("stage") != "O":
            issues.append(f"{label}: {expected_id} identity or stage is wrong")
            return None
        projected.append({key: worker.get(key) for key in O_WORKER_CONFIG_KEYS})
    return projected


def _canonical_o_contract_projection(
    config: Any, label: str, issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(config, dict):
        issues.append(f"{label}: config root is not an object")
        return None
    if set(config) != CONFIG_ROOT_KEYS:
        issues.append(f"{label}: config root keys are not exact")
        return None

    schema_version = config.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        issues.append(f"{label}: config schema_version is not exactly 1")
        return None
    for key in ("$schema", "model", "milestone", "prompt_preamble"):
        if not isinstance(config.get(key), str) or not config[key]:
            issues.append(f"{label}: config {key} is not a nonempty string")
            return None
    launch_stagger = config.get("launch_stagger_milliseconds")
    if not isinstance(launch_stagger, int) or isinstance(launch_stagger, bool):
        issues.append(
            f"{label}: config launch_stagger_milliseconds is not an integer"
        )
        return None
    stage_order = config.get("stage_order")
    if not isinstance(stage_order, list) or any(
        not isinstance(item, str) for item in stage_order
    ):
        issues.append(f"{label}: config stage_order is not a string array")
        return None

    allowed = config.get("allowed_requirement_ids")
    if (
        not isinstance(allowed, list)
        or any(not isinstance(item, str) for item in allowed)
        or len(set(allowed)) != len(allowed)
    ):
        issues.append(f"{label}: allowed_requirement_ids is not a unique string array")
        return None

    gates = config.get("semantic_gates")
    if not isinstance(gates, list):
        issues.append(f"{label}: semantic_gates is not an array")
        return None
    if len(gates) != len(SEMANTIC_GATE_STAGE_ORDER) or any(
        not isinstance(item, dict) for item in gates
    ):
        issues.append(
            f"{label}: semantic_gates must be exactly {','.join(SEMANTIC_GATE_STAGE_ORDER)} in order"
        )
        return None
    for expected_stage, gate in zip(SEMANTIC_GATE_STAGE_ORDER, gates, strict=True):
        if set(gate) != SEMANTIC_GATE_KEYS:
            issues.append(f"{label}: {expected_stage} semantic gate keys are not exact")
            return None
        if gate.get("stage") != expected_stage:
            issues.append(
                f"{label}: semantic_gates must be exactly {','.join(SEMANTIC_GATE_STAGE_ORDER)} in order"
            )
            return None
        gate_sha256 = gate.get("script_sha256")
        if (
            not isinstance(gate_sha256, str)
            or SHA256_RE.fullmatch(gate_sha256) is None
        ):
            issues.append(
                f"{label}: {expected_stage} semantic gate hash is not lowercase SHA-256"
            )
            return None

    o_gate = gates[1]
    script_sha256 = o_gate.get("script_sha256")
    gate_script = _resolve_repo_file(
        o_gate.get("script"), f"{label}: O semantic gate script", issues
    )
    if gate_script is None:
        return None
    if gate_script != Path(__file__).resolve():
        issues.append(f"{label}: O semantic gate script is not this v4 gate")
        return None
    gate_live = _live_file_pin(gate_script, f"{label}: O semantic gate script", issues)
    if gate_live is None:
        return None
    if script_sha256 != gate_live[0]:
        issues.append(f"{label}: O semantic gate hash does not match the live v4 gate")
        return None

    stages = config.get("stages")
    if not isinstance(stages, list):
        issues.append(f"{label}: stages is not an array")
        return None
    o_stages = [
        item for item in stages if isinstance(item, dict) and item.get("id") == "O"
    ]
    if len(o_stages) != 1:
        issues.append(f"{label}: config must contain exactly one O stage")
        return None
    o_stage = o_stages[0]
    if set(o_stage) != O_STAGE_DEFINITION_KEYS:
        issues.append(f"{label}: O stage keys are not exact")
        return None

    projected_workers = _project_o_workers(config.get("workers"), label, issues)
    if projected_workers is None:
        return None
    projection = {
        "config_globals": {
            key: config.get(key) for key in CONFIG_GLOBAL_PROJECTION_KEYS
        },
        "allowed_requirement_ids": allowed,
        "semantic_gates": [
            {
                key: gate.get(key)
                for key in ("stage", "script", "script_sha256", "workspace_root")
                if not (gate.get("stage") == "O" and key == "script_sha256")
            }
            for gate in gates
        ],
        "stage": {key: o_stage.get(key) for key in sorted(O_STAGE_DEFINITION_KEYS)},
        "workers": projected_workers,
    }
    canonical = json.dumps(
        projection,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != FROZEN_O_CONTRACT_SHA256:
        issues.append(f"{label}: O contract projection does not match the frozen contract")
        return None
    return projection


def _check_live_pin(
    item: dict[str, Any], label: str, issues: list[str]
) -> tuple[str, int] | None:
    path = _resolve_repo_file(item.get("path"), label, issues)
    if path is None:
        return None
    live = _live_file_pin(path, label, issues)
    if live is None:
        return None
    live_sha256, live_byte_count = live
    if item.get("sha256") != live_sha256:
        issues.append(f"{label}: SHA-256 does not match the live repository file")
    byte_count = item.get("byte_count")
    if (
        not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count != live_byte_count
    ):
        issues.append(f"{label}: byte_count does not match the live repository file")
    return live


def _valid_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


def _item_map(
    items: Any,
    id_key: str,
    expected_ids: tuple[str, ...],
    label: str,
    issues: list[str],
) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        issues.append(f"{label}: value is not an array")
        return {}
    if len(items) != 8:
        issues.append(f"{label}: count {len(items)} is not exactly 8")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            issues.append(f"{label}[{index}]: item is not an object")
            continue
        item_id = item.get(id_key)
        if not isinstance(item_id, str):
            issues.append(f"{label}[{index}]: {id_key} is not a string")
            continue
        if item_id in result:
            issues.append(f"{label}: duplicate ID {item_id}")
            continue
        result[item_id] = item
    expected = set(expected_ids)
    for item_id in sorted(set(result) - expected):
        issues.append(f"{label}: unknown ID {item_id}")
    for item_id in expected_ids:
        if item_id not in result:
            issues.append(f"{label}: missing required ID {item_id}")
    return result


def _semantic_text(test: dict[str, Any]) -> str:
    return "\n".join(
        value
        for key in ("description", "procedure", "expected")
        if isinstance((value := test.get(key)), str)
    )


def _has_substantive_description(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    ordinary = STRUCTURED_MARKER_RE.sub(" ", value)
    words = [
        word
        for word in re.findall(r"[A-Za-z][A-Za-z0-9'-]*", ordinary)
        if len(word) >= 3
    ]
    return len(words) >= 5 and sum(len(word) for word in words) >= 24


def _positive_contract_text(test: dict[str, Any]) -> str:
    """Return every byte of the free-form positive description.

    Procedure and result use exact closed-world control strings.  Therefore no
    mutation/failure keyword heuristic is needed, and no description clause is
    hidden from contradiction checks.
    """

    value = test.get("description")
    return value if isinstance(value, str) else ""


def _check_known_unsafe_prose(
    worker_id: str, test_id: str, test: dict[str, Any], issues: list[str]
) -> None:
    # Markers themselves contain concise negations.  Remove them before prose
    # checks so an exact corrected token cannot trigger its own red-team rule.
    normalized = _normalized_text(
        STRUCTURED_MARKER_RE.sub(" ", _positive_contract_text(test))
    )
    full_normalized = _normalized_text(
        STRUCTURED_MARKER_RE.sub(" ", _semantic_text(test))
    )
    checks: list[tuple[str, str]] = []

    if (worker_id, test_id) == ("O01", "O01.T2"):
        checks.extend(
            [
                (
                    r"(?:p2|position 2).{0,100}(?:p4|position 4).{0,100}(?:globally|all addressing|every addressing|entire body).{0,80}(?:unread|absent|never)",
                    "P2/P4 absence is asserted outside the bounded direct-ESP scan",
                ),
                (
                    r"(?:no|exclude[sd]?) (?:possible )?(?:alternate|indirect).{0,40}addressing",
                    "alternate addressing is incorrectly excluded",
                ),
                (
                    r"parameter two and parameter four are unconditionally absent everywhere",
                    "P2/P4 absence is asserted outside the bounded direct-ESP scan",
                ),
                (
                    r"never reads positions? 2 (?:and|or) 4",
                    "P2/P4 absence is asserted outside the bounded direct-ESP scan",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O02", "O02.T1"):
        checks.extend(
            [
                (
                    r"running esp delta forward through critical_instructions",
                    "sparse fixture rows are treated as global stack flow",
                ),
                (
                    r"all subsequent esp_delta_before",
                    "sparse fixture rows are treated as a complete instruction stream",
                ),
                (
                    r"(?:skip|allow|accept).{0,32}(?:gaps|undecoded bytes)",
                    "the complete 400-byte decode is allowed to contain gaps",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O02", "O02.T5"):
        checks.extend(
            [
                (r"\bacyclic(?:-in-the-analyzer)?\b", "CFG is incorrectly called acyclic"),
                (r"\b(?:only )?two (?:nested )?back edges\b", "CFG incorrectly has only two back edges"),
                (r"\bno cycles?\b", "CFG is incorrectly called cycle-free"),
                (r"\b(?:contains?|has) zero loops?\b", "CFG is incorrectly called loop-free"),
            ]
        )
    elif (worker_id, test_id) == ("O02", "O02.T7"):
        checks.extend(
            [
                (r"\bunassigned opcode pattern\b", "unsupported decode case is not reproducible"),
                (r"\bundefined opcodes?\b", "unsupported decode case is not exact bytes"),
                (r"\bsome unsupported (?:opcode|instruction)\b", "unsupported decode case is not exact bytes"),
            ]
        )
    elif test_id in {"O02.T3", "O04.T4"}:
        checks.extend(
            [
                (
                    r"\b(?:all|every) (?:other|remaining) registers?\b.{0,64}\b(?:unstable|not stable|clobbered)\b",
                    "register contract overclaims unclassified registers",
                ),
                (
                    r"\bonly ebx,? ebp,? esi,? edi\b",
                    "register contract invents broader preservation",
                ),
                (
                    r"\b(?:ebx|ebp|edi)\b.{0,32}\b(?:stable|preserved)\b",
                    "register contract invents an unproved stable register",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O03", "O03.T1"):
        checks.extend(
            [
                (
                    r"(?:index|index rows?).{0,100}(?:pins?|records?|contains?|supplies?|agree on).{0,80}(?:raw offsets?|raw hashes?|sha-?256|body hashes?)",
                    "canonical index is misattributed raw-offset or raw-hash authority",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O03", "O03.T5"):
        checks.extend(
            [
                (
                    r"\b(?:scan|grep).{0,100}(?:entire repository|all artifacts|canonical corpus|verification artifacts)\b",
                    "allocator scan is not bounded to declared artifacts",
                ),
                (
                    r"\bzero occurrences? (?:anywhere|globally|in the repository)\b",
                    "allocator absence is asserted outside the selected scope",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O03", "O03.T7"):
        checks.extend(
            [
                (
                    r"\b(?:no|never|forbid(?:s|den)?|reject(?:s|ed)?)\b.{0,48}\b(?:widen(?:ing|ed)?|64-bit temporar(?:y|ies)|uint64)\b",
                    "checked wider temporaries are incorrectly forbidden",
                ),
                (
                    r"\bevery (?:coordinate|cell|register).{0,80}\bexactly 32 bits\b",
                    "guest32 restraint is overextended to all temporaries",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O03", "O03.T8"):
        checks.extend(
            [
                (
                    r"\bdelegat(?:e|es|ed|ion|ing)\b.{0,100}\b(?:0x)?100f1c10\b",
                    "0x100f1c10 is incorrectly used as native delegation",
                ),
                (
                    r"\buses? (?:only )?(?:the )?(?:accepted )?(?:native )?(?:0x)?100f1c10 (?:port|implementation)\b",
                    "0x100f1c10 is incorrectly used as native delegation",
                ),
                (
                    r"\binvoke\b.{0,100}\b(?:0x)?100f1c10\b.{0,80}\bproduction\b",
                    "0x100f1c10 is incorrectly used as production native delegation",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O04", "O04.T6"):
        checks.extend(
            [
                (
                    r"\bno (?:symbol )?reference to (?:any )?recovered (?:symbol|identifier)s?\b",
                    "inert recovered identifiers are incorrectly forbidden",
                ),
                (
                    r"\boriginal empire\.retail\.dll\b.{0,80}\b(?:dynamically )?loaded\b.{0,40}\bexecuted\b",
                    "the original DLL is incorrectly allowed to load or execute",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O04", "O04.T7"):
        checks.extend(
            [
                (
                    r"\bsimulat(?:e|ed|ing)[^.;]{0,64}build_testing\b",
                    "BUILD_TESTING containment is an unscoped simulation",
                ),
                (
                    r"\b(?:0x)?100d6560[^.;]{0,140}(?:appears? nowhere|must be absent|zero occurrences?)\b",
                    "legacy 0x100d6560 names are incorrectly required to be absent",
                ),
                (
                    r"\bprivate no-op[^.;]{0,120}(?:exposes no|no) name or arity\b",
                    "legacy 0x100d6560 metadata is confused with ABI proof",
                ),
            ]
        )
    elif (worker_id, test_id) == ("O04", "O04.T8"):
        checks.extend(
            [
                (
                    r"\bdiff all outputs and workspace directory listings\b",
                    "outside-workspace writes are not observable",
                ),
                (
                    r"\bonly (?:diff|compare).{0,80}\bworkspace\b",
                    "outside-workspace writes are not observable",
                ),
                (
                    r"\bwrites? to (?:the )?repository root\b.{0,80}\bneed not be intercepted\b",
                    "repository writes are incorrectly allowed to escape observation",
                ),
            ]
        )

    if test_id in {"O01.T4", "O02.T2", "O03.T2", "O04.T2"}:
        checks.extend(
            [
                (
                    r"\bnext_va\s+(?:minus|subtract(?:s|ed|ing)?)\s+(?:the\s+)?(?:signed\s+)?rel32\b",
                    "rel32 uses subtraction instead of next-VA plus signed displacement",
                ),
                (
                    r"\b(?:compute|resolve|decode|base)[^.;]{0,80}\b(?:against|from|on|at) (?:its |the )?(?:call |instruction )?(?:address|va)\b",
                    "rel32 uses the instruction address instead of next VA",
                ),
                (
                    r"\bcall va (?:is|as) (?:the )?(?:rel32 )?base\b",
                    "rel32 uses the call VA instead of next VA",
                ),
                (
                    r"\badd (?:the )?signed displacement to (?:the )?call opcode(?:'s|s)? address\b",
                    "rel32 uses the call opcode address instead of next VA",
                ),
            ]
        )

    displaced_checks = (
        (
            r"\bcall va (?:is|as) (?:the )?(?:rel32 )?base\b",
            "description contains displaced rel32 contradiction",
        ),
    )
    for pattern, message in (*checks, *displaced_checks):
        if re.search(pattern, normalized):
            issues.append(f"{worker_id}: {test_id} {message}")

    generic_checks = (
        (
            r"\b(?:apply|perform|make)\b.{0,80}\b(?:assigned )?mutation\b.{0,100}\b(?:and also|as well as|plus)\b",
            "test procedure describes a compound mutation",
        ),
        (
            r"\b(?:do not|never|skip|omit)\b.{0,48}\b(?:run|execute|check|test)?\s*(?:any |the )?pristine baseline\b",
            "test procedure omits the pristine baseline",
        ),
        (
            r"\b(?:apply|perform|accept|use|make)\b.{0,64}\b(?:two|multiple|compound) (?:mutations|changes)\b",
            "test procedure describes a compound mutation",
        ),
        (
            r"\bpristine baseline\b.{0,64}\b(?:need not|is not required|may be skipped|is optional)\b",
            "test procedure omits the pristine baseline",
        ),
    )
    for pattern, message in generic_checks:
        if re.search(pattern, full_normalized):
            issues.append(f"{worker_id}: {test_id} {message}")


def _context_manifest_path(root: Path, worker_id: str) -> Path | None:
    if root.name == "oracle" and root.parent.name == "workspaces":
        return root.parent.parent / "context" / "O" / f"{worker_id}.json"
    return None


def _run_root_from_oracle_root(root: Path) -> Path | None:
    if root.name == "oracle" and root.parent.name == "workspaces":
        return root.parent.parent
    return None


def _check_pin_shape_and_live_file(
    item: Any,
    label: str,
    issues: list[str],
    *,
    allowed_paths: frozenset[str] | None = None,
) -> str | None:
    if not isinstance(item, dict):
        issues.append(f"{label}: pin is not an object")
        return None
    if set(item) != PIN_KEYS:
        issues.append(f"{label}: pin keys are not exact")
    authority = item.get("path")
    safe, reason = _safe_relative_repo_path(authority)
    if not safe:
        issues.append(f"{label}: unsafe repository path: {reason}")
        return authority if isinstance(authority, str) else None
    sha256 = item.get("sha256")
    if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
        issues.append(f"{label}: pin has invalid SHA-256")
    byte_count = item.get("byte_count")
    if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
        issues.append(f"{label}: pin has invalid byte_count")
    # Reject unexpected paths structurally without opening them.  Besides
    # reducing authority, this prevents a tiny manifest from selecting an
    # unrelated huge repository file merely to consume hashing time.
    if allowed_paths is None or authority in allowed_paths:
        _check_live_pin(item, label, issues)
    return authority


def _check_context_authorities(
    root: Path, worker_id: str, issues: list[str]
) -> dict[str, Any] | None:
    path = _context_manifest_path(root, worker_id)
    run_root = _run_root_from_oracle_root(root)
    if path is None or run_root is None:
        issues.append(f"{worker_id}: frozen context manifest is required")
        return None
    context = _load_json(
        path, f"{worker_id} context", issues, containment_root=run_root
    )
    if context is None:
        return None
    if set(context) != CONTEXT_KEYS:
        issues.append(f"{worker_id}: context keys are not exact")
    schema_version = context.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        issues.append(f"{worker_id}: context schema_version is not exactly 1")
    if context.get("worker_id") != worker_id:
        issues.append(f"{worker_id}: context worker_id does not match")
    if context.get("stage") != "O":
        issues.append(f"{worker_id}: context stage is not O")
    run_id = context.get("run_id")
    if not isinstance(run_id, str) or SAFE_RUN_ID_RE.fullmatch(run_id) is None:
        issues.append(f"{worker_id}: context run_id is unsafe")
    for key in ("config_sha256", "stage_config_sha256"):
        value = context.get(key)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            issues.append(f"{worker_id}: context {key} is not lowercase SHA-256")
    if not _valid_utc_timestamp(context.get("generated_utc")):
        issues.append(f"{worker_id}: context generated_utc is not a UTC timestamp")
    if context.get("dependency_stage_manifests") != []:
        issues.append(f"{worker_id}: context dependency_stage_manifests must be empty")

    declared = context.get("declared_inputs")
    if not isinstance(declared, list):
        issues.append(f"{worker_id}: context declared_inputs is not an array")
        declared = []

    declared_paths: list[str] = []
    seen_paths: set[str] = set()
    expected_paths = FULL_V9_CONTEXT_AUTHORITIES[worker_id]
    allowed_paths = frozenset(expected_paths)
    for index, item in enumerate(declared):
        authority = _check_pin_shape_and_live_file(
            item,
            f"{worker_id}: context declared_inputs[{index}]",
            issues,
            allowed_paths=allowed_paths,
        )
        if authority is None:
            continue
        declared_paths.append(authority)
        if authority in seen_paths:
            issues.append(f"{worker_id}: context has duplicate authority {authority}")
        seen_paths.add(authority)

    for authority in expected_paths:
        if authority not in seen_paths:
            issues.append(f"{worker_id}: required authority is undeclared: {authority}")
    for authority in sorted(seen_paths - set(expected_paths)):
        issues.append(f"{worker_id}: unexpected context authority: {authority}")
    if tuple(declared_paths) != expected_paths:
        issues.append(
            f"{worker_id}: declared_inputs are not the exact ordered v9 authority set"
        )

    schemas = context.get("validation_schemas")
    if not isinstance(schemas, list):
        issues.append(f"{worker_id}: context validation_schemas is not an array")
        schemas = []
    if len(schemas) != 1:
        issues.append(f"{worker_id}: context must contain exactly one validation schema")
    if schemas:
        schema = schemas[0]
        schema_path = _check_pin_shape_and_live_file(
            schema,
            f"{worker_id}: context validation_schemas[0]",
            issues,
            allowed_paths=frozenset({V3_SCHEMA_PATH}),
        )
        if schema_path != V3_SCHEMA_PATH:
            issues.append(f"{worker_id}: context validation schema is not exact v3")
        if isinstance(schema, dict):
            if schema.get("sha256") != V3_SCHEMA_SHA256:
                issues.append(f"{worker_id}: context v3 schema SHA-256 pin is wrong")
            if schema.get("byte_count") != V3_SCHEMA_BYTE_COUNT:
                issues.append(f"{worker_id}: context v3 schema byte_count pin is wrong")
    return context


def _check_context_coherence(
    root: Path, contexts: dict[str, dict[str, Any]], issues: list[str]
) -> None:
    run_root = _run_root_from_oracle_root(root)
    if run_root is None:
        issues.append("O: oracle root is not in the supervisor workspace layout")
        return
    expected_run_id = run_root.name
    if SAFE_RUN_ID_RE.fullmatch(expected_run_id) is None:
        issues.append("O: run directory name is unsafe")

    state = _load_json(
        run_root / "state.json",
        "O: supervisor state",
        issues,
        containment_root=run_root,
        reject_symlink=True,
    )
    if state is None:
        return
    for key in (
        "state_version",
        "run_id",
        "repository_root",
        "run_root",
        "config_path",
        "config_sha256",
        "stages",
    ):
        if key not in state:
            issues.append(f"O: supervisor state is missing relevant field {key}")
    state_version = state.get("state_version")
    if (
        not isinstance(state_version, int)
        or isinstance(state_version, bool)
        or state_version != 3
    ):
        issues.append("O: supervisor state_version is not exactly 3")
    state_run_id = state.get("run_id")
    if (
        not isinstance(state_run_id, str)
        or SAFE_RUN_ID_RE.fullmatch(state_run_id) is None
        or state_run_id != expected_run_id
    ):
        issues.append("O: supervisor state run_id does not match the run directory")
    _resolve_state_absolute_path(
        state.get("repository_root"),
        "O: supervisor state repository_root",
        issues,
        expected=TRUSTED_REPO_ROOT,
    )
    _resolve_state_absolute_path(
        state.get("run_root"),
        "O: supervisor state run_root",
        issues,
        expected=run_root,
    )

    state_config_sha256 = state.get("config_sha256")
    if (
        not isinstance(state_config_sha256, str)
        or SHA256_RE.fullmatch(state_config_sha256) is None
    ):
        issues.append("O: supervisor state config_sha256 is not lowercase SHA-256")
    config_path = _resolve_state_absolute_path(
        state.get("config_path"),
        "O: supervisor state config_path",
        issues,
        containment_root=TRUSTED_REPO_ROOT,
        file_required=True,
        reject_symlink=True,
    )
    config, live_config = (
        _load_json_snapshot(
            config_path,
            "O: live state-selected config",
            issues,
            containment_root=TRUSTED_REPO_ROOT,
            reject_symlink=True,
            max_bytes=MAX_CONFIG_JSON_BYTES,
        )
        if config_path is not None
        else (None, None)
    )
    if live_config is not None and state_config_sha256 != live_config[0]:
        issues.append(
            "O: supervisor state config_sha256 does not match the live state-selected config"
        )
    config_projection = (
        _canonical_o_contract_projection(
            config, "O: live state-selected config", issues
        )
        if config is not None
        else None
    )

    stages = state.get("stages")
    if not isinstance(stages, list):
        issues.append("O: supervisor state stages is not an array")
        o_stage_state = None
    else:
        o_stages = [
            item for item in stages if isinstance(item, dict) and item.get("id") == "O"
        ]
        if len(o_stages) != 1:
            issues.append("O: supervisor state must contain exactly one O stage")
            o_stage_state = None
        else:
            o_stage_state = o_stages[0]

    expected_stage_config_path = run_root / "stage-config" / "O.json"
    state_stage_sha256: Any = None
    stage_config_path: Path | None = None
    if o_stage_state is not None:
        for key in ("id", "stage_config_file", "stage_config_sha256"):
            if key not in o_stage_state:
                issues.append(f"O: supervisor O stage is missing relevant field {key}")
        state_stage_sha256 = o_stage_state.get("stage_config_sha256")
        if (
            not isinstance(state_stage_sha256, str)
            or SHA256_RE.fullmatch(state_stage_sha256) is None
        ):
            issues.append(
                "O: supervisor O stage stage_config_sha256 is not lowercase SHA-256"
            )
        stage_config_path = _resolve_state_absolute_path(
            o_stage_state.get("stage_config_file"),
            "O: supervisor O stage stage_config_file",
            issues,
            expected=expected_stage_config_path,
            containment_root=run_root,
            file_required=True,
            reject_symlink=True,
        )
    if stage_config_path is None:
        # Still report a missing live snapshot when the state record is absent or
        # malformed; this keeps the binding failure explicit and fail-closed.
        stage_config_path = _resolve_contained_file(
            expected_stage_config_path,
            run_root,
            "O: live O stage config",
            issues,
            reject_symlink=True,
        )

    stage_config, live_stage_config = (
        _load_json_snapshot(
            stage_config_path,
            "O: live O stage config",
            issues,
            containment_root=run_root,
            reject_symlink=True,
        )
        if stage_config_path is not None
        else (None, None)
    )
    if live_stage_config is not None and state_stage_sha256 != live_stage_config[0]:
        issues.append(
            "O: supervisor O stage hash does not match the live O stage config"
        )
    if stage_config is not None:
        if set(stage_config) != O_STAGE_CONFIG_KEYS:
            issues.append("O: live O stage config keys are not exact")
        schema_version = stage_config.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != 1
        ):
            issues.append("O: live O stage config schema_version is not exactly 1")
        if stage_config.get("run_id") != expected_run_id:
            issues.append("O: live O stage config run_id does not match the run directory")
        if stage_config.get("config_sha256") != state_config_sha256:
            issues.append(
                "O: live O stage config config_sha256 does not match supervisor state"
            )
        if live_config is not None and stage_config.get("config_sha256") != live_config[0]:
            issues.append(
                "O: live O stage config config_sha256 does not match the live state-selected config"
            )

        if (
            config_projection is not None
            and stage_config.get("stage") != config_projection["stage"]
        ):
            issues.append("O: live O stage definition does not match the selected config")

        stage_workers = _project_o_workers(
            stage_config.get("workers"),
            "O: live O stage config",
            issues,
            require_only_o_workers=True,
        )
        if (
            stage_workers is not None
            and config_projection is not None
            and stage_workers != config_projection["workers"]
        ):
            issues.append(
                "O: live O stage worker contract does not match the selected config"
            )

    first: dict[str, str] | None = None
    for worker_id in WORKERS:
        context = contexts.get(worker_id)
        if context is None:
            continue
        values = {
            "run_id": context.get("run_id"),
            "config_sha256": context.get("config_sha256"),
            "stage_config_sha256": context.get("stage_config_sha256"),
        }
        if values["run_id"] != expected_run_id:
            issues.append(f"{worker_id}: context run_id does not match the run directory")
        if values["config_sha256"] != state_config_sha256:
            issues.append(
                f"{worker_id}: context config_sha256 does not match supervisor state"
            )
        if live_config is not None and values["config_sha256"] != live_config[0]:
            issues.append(
                f"{worker_id}: context config_sha256 does not match live state-selected config"
            )
        if values["stage_config_sha256"] != state_stage_sha256:
            issues.append(
                f"{worker_id}: context stage_config_sha256 does not match supervisor state"
            )
        if (
            live_stage_config is not None
            and values["stage_config_sha256"] != live_stage_config[0]
        ):
            issues.append(
                f"{worker_id}: context stage_config_sha256 does not match live O stage config"
            )
        if first is None:
            first = values
        else:
            for key in ("run_id", "config_sha256", "stage_config_sha256"):
                if values[key] != first[key]:
                    issues.append(f"{worker_id}: context {key} is incoherent across O workers")


def check_oracle_root(root: Path) -> list[str]:
    """Return sorted deterministic violations for one O-stage workspace root."""

    root = root.resolve()
    issues: list[str] = []
    documents: dict[str, dict[str, Any]] = {}
    contexts: dict[str, dict[str, Any]] = {}

    try:
        children = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return [f"O: workspace root is unreadable: {exc}"]
    for child in children:
        if child.is_dir() and child.name.startswith("O") and child.name not in WORKERS:
            issues.append(f"O: unknown worker directory {child.name}")

    for worker_id in WORKERS:
        document = _load_json(
            root / worker_id / "oracle.json",
            worker_id,
            issues,
            containment_root=root,
        )
        if document is not None:
            documents[worker_id] = document
        context = _check_context_authorities(root, worker_id, issues)
        if context is not None:
            contexts[worker_id] = context

    _check_context_coherence(root, contexts, issues)

    stage_requirement_union: set[str] = set()
    for worker_id in WORKERS:
        document = documents.get(worker_id)
        if document is None:
            continue
        if set(document) != DOCUMENT_KEYS:
            issues.append(f"{worker_id}: document keys are not the exact oracle contract")
        if document.get("worker_id") != worker_id:
            issues.append(f"{worker_id}: worker_id does not match its directory")
        if document.get("stage") != "O":
            issues.append(f"{worker_id}: stage is not O")
        if document.get("blockers") != []:
            issues.append(f"{worker_id}: blockers must be an empty array")

        expected_tests = tuple(f"{worker_id}.T{index}" for index in range(1, 9))
        expected_mutants = tuple(f"{worker_id}.M{index}" for index in range(1, 9))
        tests = _item_map(
            document.get("tests"), "test_id", expected_tests, f"{worker_id} tests", issues
        )
        mutants = _item_map(
            document.get("mutants"),
            "mutant_id",
            expected_mutants,
            f"{worker_id} mutants",
            issues,
        )

        worker_requirements: set[str] = set()
        for index in range(1, 9):
            test_id = f"{worker_id}.T{index}"
            mutant_id = f"{worker_id}.M{index}"
            test = tests.get(test_id)
            mutant = mutants.get(mutant_id)
            if test is not None:
                if set(test) != TEST_KEYS:
                    issues.append(f"{worker_id}: {test_id} keys are not exact")
                requirements = test.get("requirement_ids")
                if not isinstance(requirements, list) or not requirements:
                    issues.append(
                        f"{worker_id}: {test_id} requirement_ids is not a nonempty array"
                    )
                else:
                    seen_requirements: set[str] = set()
                    for requirement in requirements:
                        if not isinstance(requirement, str):
                            issues.append(
                                f"{worker_id}: {test_id} has non-string requirement ID"
                            )
                            continue
                        if requirement in seen_requirements:
                            issues.append(
                                f"{worker_id}: {test_id} requirement_ids contains duplicate {requirement}"
                            )
                            continue
                        seen_requirements.add(requirement)
                        if requirement not in ALLOWED_REQUIREMENT_IDS:
                            issues.append(
                                f"{worker_id}: {test_id} has forbidden requirement {requirement}"
                            )
                        else:
                            worker_requirements.add(requirement)
                            stage_requirement_union.add(requirement)
                if test.get("mutant_ids") != [mutant_id]:
                    issues.append(f"{worker_id}: {test_id} must name only {mutant_id}")
                for key in ("description", "procedure", "expected"):
                    if not isinstance(test.get(key), str) or not test[key].strip():
                        issues.append(f"{worker_id}: {test_id} {key} is not a nonempty string")
                if not _has_substantive_description(test.get("description")):
                    issues.append(
                        f"{worker_id}: {test_id} description must include substantive ordinary-language semantics"
                    )

                expected_procedure = EXACT_TEST_PROCEDURES[test_id]
                if test.get("procedure") != expected_procedure:
                    issues.append(
                        f"{worker_id}: {test_id} procedure must equal exact paired control"
                    )
                expected_result = EXACT_TEST_EXPECTATIONS[test_id]
                if test.get("expected") != expected_result:
                    issues.append(
                        f"{worker_id}: {test_id} expected must equal exact paired result {expected_result}"
                    )

                semantic_text = _semantic_text(test)
                expected_markers = (
                    *TEST_MARKERS[worker_id][test_id],
                    KILL_CODE_MARKERS[test_id],
                )
                raw_found_markers = STRUCTURED_MARKER_RE.findall(semantic_text)
                # Natural prose may put one sentence-final period immediately
                # after an exact token.  The regex deliberately admits periods
                # inside paths, so remove exactly one trailing period only when
                # doing so produces this test's complete expected marker.
                found_markers = [
                    marker[:-1]
                    if marker.endswith(".") and marker[:-1] in expected_markers
                    else marker
                    for marker in raw_found_markers
                ]
                for marker in expected_markers:
                    if found_markers.count(marker) != 1:
                        issues.append(
                            f"{worker_id}: {test_id} must contain marker exactly once: {marker}"
                        )
                for marker in sorted(set(found_markers) - set(expected_markers)):
                    issues.append(f"{worker_id}: {test_id} has unknown marker {marker}")
                _check_known_unsafe_prose(worker_id, test_id, test, issues)

            if mutant is not None:
                if set(mutant) != MUTANT_KEYS:
                    issues.append(f"{worker_id}: {mutant_id} keys are not exact")
                if mutant.get("expected_killer_ids") != [test_id]:
                    issues.append(f"{worker_id}: {mutant_id} must name only {test_id}")
                if mutant.get("critical") is not True:
                    issues.append(f"{worker_id}: {mutant_id} critical must be true")
                expected_record = EXPECTED_MUTATION_RECORDS[mutant_id]
                expected_description = expected_record["description"]
                if mutant.get("description") != expected_description:
                    issues.append(
                        f"{worker_id}: {mutant_id} description must equal exact single mutation {expected_description}"
                    )
                mutation = mutant.get("mutation")
                if not isinstance(mutation, dict):
                    issues.append(f"{worker_id}: {mutant_id} mutation is not an object")
                else:
                    if set(mutation) != MUTATION_KEYS:
                        issues.append(
                            f"{worker_id}: {mutant_id} mutation keys are not exact"
                        )
                    expected_mutation = expected_record["mutation"]
                    for field in sorted(MUTATION_KEYS):
                        if mutation.get(field) != expected_mutation[field]:
                            issues.append(
                                f"{worker_id}: {mutant_id} mutation.{field} must equal frozen contract"
                            )

        missing_role = ROLE_REQUIRED_REQUIREMENTS[worker_id] - worker_requirements
        for requirement in sorted(missing_role):
            issues.append(f"{worker_id}: role coverage is missing {requirement}")

        serialized = json.dumps(document, sort_keys=True).lower()
        for source_name in GATE_SOURCE_NAMES:
            if source_name.lower() in serialized:
                issues.append(
                    f"{worker_id}: semantic gate is cited as oracle evidence: {source_name}"
                )

    missing_stage = ALLOWED_REQUIREMENT_IDS - stage_requirement_union
    for requirement in sorted(missing_stage):
        issues.append(f"O: stage requirement union is missing {requirement}")

    return sorted(set(issues))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("oracle_root", type=Path)
    args = parser.parse_args(argv)
    issues = check_oracle_root(args.oracle_root)
    if issues:
        for issue in issues:
            print(f"FAIL {issue}")
        return 1
    print("startup ABI oracle semantic gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
