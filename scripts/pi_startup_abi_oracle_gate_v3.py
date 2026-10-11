#!/usr/bin/env python3
"""Closed-world semantic gate for startup-ABI O-stage oracle artifacts.

The transport schema cannot prove the meaning of free-form oracle prose.  The
v8 O-stage prompt therefore assigns every test one or more exact ``KEY=TOKEN``
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
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any


WORKERS = ("O01", "O02", "O03", "O04")
MAX_JSON_BYTES = 65536
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TRUSTED_REPO_ROOT = Path(__file__).resolve().parent.parent
V2_SCHEMA_PATH = "scripts/pi_wave3_oracle_v2.schema.json"
V2_SCHEMA_SHA256 = "5246f35def1c3b9812963058b29f001391feb9d808d2cb5b05d3cd0a497437f8"
V2_SCHEMA_BYTE_COUNT = 2171
FROZEN_O_CONTRACT_SHA256 = (
    "9dce48b05832aeaf6db83869c203c8ec177be428559f67d3588ee61a9a205f1f"
)
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

# Exact v8 context lists, in supervisor/config order.  The smaller role sets
# above remain part of the frozen marker contract; these full lists are the
# trust boundary used to validate context manifests.
FULL_V8_CONTEXT_AUTHORITIES: dict[str, tuple[str, ...]] = {
    "O01": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
        "scripts/test_x64_entry_policy_provenance.py",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100edd70.c",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c",
        "docs/x64_startup_100f1c10_spec.md",
    ),
    "O02": (
        "Total War Rome II/empire.retail.dll",
        "scripts/x64_startup_100ed3c0_abi_fixture.json",
        "scripts/test_x64_startup_100ed3c0_abi_provenance.py",
        "docs/x64_startup_100ed3c0_abi_contract.md",
        "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c",
        "src_canonical_out/empire.retail.dll/canonical_function_index.tsv",
        "docs/x64_startup_100f1c10_spec.md",
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
            "UNSUPPORTED_CASE=REPLACE_100ED3C0_81EC0C090000_WITH_0F0B90909090",
            "TRUNCATION_CASE=DROP_FINAL_C3_BODY_SIZE_399",
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
        "O04.M6": "EXACT_SINGLE_MUTATION: O04_M6_LOAD_ORIGINAL_DLL",
        "O04.M7": "EXACT_SINGLE_MUTATION: O04_M7_MOVE_EMPTY_TARGET_OUTSIDE_BUILD_TESTING",
        "O04.M8": "EXACT_SINGLE_MUTATION: O04_M8_WRITE_ONE_BYTE_OUTSIDE_DISPOSABLE_WORKSPACE",
    },
}


GATE_SOURCE_NAMES = frozenset(
    {
        "pi_startup_abi_oracle_gate.py",
        "test_pi_startup_abi_oracle_gate.py",
        "pi_startup_abi_oracle_gate_v2.py",
        "test_pi_startup_abi_oracle_gate_v2.py",
        "pi_startup_abi_oracle_gate_v3.py",
        "test_pi_startup_abi_oracle_gate_v3.py",
    }
)
DOCUMENT_KEYS = frozenset({"worker_id", "stage", "tests", "mutants", "blockers"})
TEST_KEYS = frozenset(
    {"test_id", "requirement_ids", "description", "procedure", "expected", "mutant_ids"}
)
MUTANT_KEYS = frozenset(
    {"mutant_id", "critical", "description", "expected_killer_ids"}
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


def _load_json(
    path: Path,
    label: str,
    issues: list[str],
    *,
    containment_root: Path | None = None,
    reject_symlink: bool = False,
) -> dict[str, Any] | None:
    if containment_root is not None:
        resolved = _resolve_contained_file(
            path,
            containment_root,
            label,
            issues,
            reject_symlink=reject_symlink,
        )
        if resolved is None:
            return None
        path = resolved
    try:
        raw = path.read_bytes()
    except OSError as exc:
        issues.append(f"{label}: missing artifact: {exc}")
        return None
    if len(raw) > MAX_JSON_BYTES:
        issues.append(f"{label}: JSON exceeds {MAX_JSON_BYTES} bytes")
        return None
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
    workers: Any, label: str, issues: list[str]
) -> list[dict[str, Any]] | None:
    if not isinstance(workers, list):
        issues.append(f"{label}: workers is not an array")
        return None
    relevant = [
        worker
        for worker in workers
        if isinstance(worker, dict)
        and (worker.get("stage") == "O" or worker.get("id") in WORKERS)
    ]
    ids = [worker.get("id") for worker in relevant]
    if ids != list(WORKERS):
        issues.append(f"{label}: O workers are not exactly {','.join(WORKERS)} in order")
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
    o_gates = [
        item for item in gates if isinstance(item, dict) and item.get("stage") == "O"
    ]
    if len(o_gates) != 1:
        issues.append(f"{label}: config must contain exactly one O semantic gate")
        return None
    o_gate = o_gates[0]
    if set(o_gate) != {"stage", "script", "script_sha256", "workspace_root"}:
        issues.append(f"{label}: O semantic gate keys are not exact")
        return None
    script_sha256 = o_gate.get("script_sha256")
    if not isinstance(script_sha256, str) or SHA256_RE.fullmatch(script_sha256) is None:
        issues.append(f"{label}: O semantic gate hash is not lowercase SHA-256")
        return None
    gate_script = _resolve_repo_file(
        o_gate.get("script"), f"{label}: O semantic gate script", issues
    )
    if gate_script is None:
        return None
    if gate_script != Path(__file__).resolve():
        issues.append(f"{label}: O semantic gate script is not this v3 gate")
        return None
    gate_live = _live_file_pin(gate_script, f"{label}: O semantic gate script", issues)
    if gate_live is None:
        return None
    if script_sha256 != gate_live[0]:
        issues.append(f"{label}: O semantic gate hash does not match the live v3 gate")
        return None

    projected_workers = _project_o_workers(config.get("workers"), label, issues)
    if projected_workers is None:
        return None
    projection = {
        "allowed_requirement_ids": allowed,
        "semantic_gate": {
            "stage": o_gate.get("stage"),
            "script": o_gate.get("script"),
            "workspace_root": o_gate.get("workspace_root"),
        },
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


def _positive_contract_text(test: dict[str, Any]) -> str:
    """Return prose that asserts the pristine contract, not a killed mutant.

    Oracle procedures necessarily describe the bad value installed in their
    paired negative control.  Treating that quoted mutation as a positive
    claim rejects exactly the adversarial test the contract requires.  Keep
    descriptions and affirmative/pristine clauses, but omit explicitly
    mutation-scoped or fail/reject clauses from fact-contradiction scans.
    Generic mutation-integrity checks still inspect the complete text.
    """

    kept: list[str] = []
    for key in ("description", "procedure", "expected"):
        value = test.get(key)
        if not isinstance(value, str):
            continue
        clauses = re.split(r"(?<=[.;!?])\s+|(?=\b\d+[.)]\s+)", value)
        for clause in clauses:
            normalized = _normalized_text(clause)
            if re.search(r"\bmutat(?:e|ed|ion|ions)\b|\bmutants?\b", normalized):
                continue
            if (
                "pristine" not in normalized
                and re.search(r"\b(?:fail(?:s|ed)?|reject(?:s|ed)?|kills?)\b", normalized)
            ):
                continue
            kept.append(clause)
    return "\n".join(kept)


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

    for pattern, message in checks:
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
    expected_paths = FULL_V8_CONTEXT_AUTHORITIES[worker_id]
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
            f"{worker_id}: declared_inputs are not the exact ordered v8 authority set"
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
            allowed_paths=frozenset({V2_SCHEMA_PATH}),
        )
        if schema_path != V2_SCHEMA_PATH:
            issues.append(f"{worker_id}: context validation schema is not exact v2")
        if isinstance(schema, dict):
            if schema.get("sha256") != V2_SCHEMA_SHA256:
                issues.append(f"{worker_id}: context v2 schema SHA-256 pin is wrong")
            if schema.get("byte_count") != V2_SCHEMA_BYTE_COUNT:
                issues.append(f"{worker_id}: context v2 schema byte_count pin is wrong")
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
    live_config = (
        _live_file_pin(config_path, "O: live state-selected config", issues)
        if config_path is not None
        else None
    )
    if live_config is not None and state_config_sha256 != live_config[0]:
        issues.append(
            "O: supervisor state config_sha256 does not match the live state-selected config"
        )
    config = (
        _load_json(
            config_path,
            "O: live state-selected config",
            issues,
            containment_root=TRUSTED_REPO_ROOT,
            reject_symlink=True,
        )
        if config_path is not None
        else None
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

    live_stage_config = (
        _live_file_pin(stage_config_path, "O: live O stage config", issues)
        if stage_config_path is not None
        else None
    )
    if live_stage_config is not None and state_stage_sha256 != live_stage_config[0]:
        issues.append(
            "O: supervisor O stage hash does not match the live O stage config"
        )
    stage_config = (
        _load_json(
            stage_config_path,
            "O: live O stage config",
            issues,
            containment_root=run_root,
            reject_symlink=True,
        )
        if stage_config_path is not None
        else None
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

        config_o_stage: dict[str, Any] | None = None
        if config is not None:
            config_stages = config.get("stages")
            if not isinstance(config_stages, list):
                issues.append("O: live state-selected config stages is not an array")
            else:
                matches = [
                    item
                    for item in config_stages
                    if isinstance(item, dict) and item.get("id") == "O"
                ]
                if len(matches) != 1:
                    issues.append(
                        "O: live state-selected config must contain exactly one O stage"
                    )
                else:
                    config_o_stage = matches[0]
        if config_o_stage is not None and stage_config.get("stage") != config_o_stage:
            issues.append("O: live O stage definition does not match the selected config")

        stage_workers = _project_o_workers(
            stage_config.get("workers"), "O: live O stage config", issues
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

                semantic_text = _semantic_text(test)
                expected_markers = TEST_MARKERS[worker_id][test_id]
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
                expected_mutation = EXACT_MUTATION_DESCRIPTIONS[worker_id][mutant_id]
                if mutant.get("description") != expected_mutation:
                    issues.append(
                        f"{worker_id}: {mutant_id} description must equal exact single mutation {expected_mutation}"
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
