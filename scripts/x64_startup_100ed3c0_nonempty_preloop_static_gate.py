#!/usr/bin/env python3
"""Fail-closed gate for the bounded nonempty 0x100ed3c0 parent composition."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100ed3c0_run_nonempty_preloop"
LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"
TEST_TARGET = "rome2_startup_100ed3c0_nonempty_preloop_tests"
COMPOSITION_LIBRARY = "rome2_startup_100ed3c0_nonempty_lifecycle_runtime"
EXPECTED_CTEST_COUNT = 194

EXPECTED_HEADER_BYTES = 5_544
EXPECTED_HEADER_SHA256 = (
    "6b36577a24aee25fe253afbf6fc3c8df66abc2b37d3df48b960cdf6e3a64a6f5"
)
EXPECTED_SOURCE_BYTES = 57_967
EXPECTED_SOURCE_SHA256 = (
    "17f8c4828490235d4734d734e3222be2c47ac9763bd69871b1e7cd2744fcae6f"
)
EXPECTED_TEST_BYTES = 60_502
EXPECTED_TEST_SHA256 = (
    "3f79ef5062a2e89fe195588a7a067ace263a978d574da4664cc4687163b2a49a"
)
EXPECTED_PROVENANCE_BYTES = 9_741
EXPECTED_PROVENANCE_SHA256 = (
    "905c2a110b37ad237bdbf6075defb0be012354b216a3cbda96dd1c52808bbdf2"
)
EXPECTED_DOC_BYTES = 6_884
EXPECTED_DOC_SHA256 = (
    "4c9ba359c3c71e8f390bd3d3bfaf99d6c7c96fe9090b5046fd570515348ff3e8"
)
EXPECTED_CMAKE_BYTES = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

STEP_KINDS = (
    "ROME2_100ED3C0_NONEMPTY_STEP_WRITE_GLOBAL_119F31C8",
    "ROME2_100ED3C0_NONEMPTY_STEP_WRITE_GLOBAL_119F31C5",
    "ROME2_100ED3C0_NONEMPTY_STEP_INIT_TRIPLET0",
    "ROME2_100ED3C0_NONEMPTY_STEP_INIT_TRIPLET1",
    "ROME2_100ED3C0_NONEMPTY_STEP_COPY_EMPTY0",
    "ROME2_100ED3C0_NONEMPTY_STEP_COPY_EMPTY1",
    "ROME2_100ED3C0_NONEMPTY_STEP_BUILD_OWNED_DESCRIPTOR",
    "ROME2_100ED3C0_NONEMPTY_STEP_RUN_100DF270",
    "ROME2_100ED3C0_NONEMPTY_STEP_CLEANUP_OWNED_DESCRIPTOR",
)

BUILD_CALL = "rome2_port_100f1bb0_build_owned_utf16"
PREFIX_CALL = "rome2_port_100df270_run_platform_prefix_transcript"
MIDDLE_CALL = "rome2_port_100df270_project_headless_empty_state"
DELEGATED_SUFFIX_CALL = (
    "rome2_port_100df270_run_suffix_transcript_delegated"
)
NONDELEGATED_SUFFIX_CALL = "rome2_port_100df270_run_suffix_transcript"
FIRST_USE_CALL = "rome2_port_100f2750_first_use_owned"
CLEANUP_CALL = "rome2_port_100f1cc0_cleanup_owned_utf16"

CMAKE_FILES = (
    "ported_100ed3c0_nonempty_preloop.h",
    "ported_100ed3c0_nonempty_preloop.c",
    "test_startup_100ed3c0_nonempty_preloop.c",
    "test_x64_startup_100ed3c0_nonempty_preloop_provenance.py",
    "test_x64_startup_100ed3c0_nonempty_preloop_static_gate.py",
    "x64_startup_100ed3c0_nonempty_preloop_static_gate.py",
    "x64_startup_100ed3c0_nonempty_preloop.md",
)

CMAKE_TESTS = (
    "startup_100ed3c0_nonempty_preloop_provenance",
    "startup_100ed3c0_nonempty_preloop_static_gate_unit",
    "startup_100ed3c0_nonempty_preloop_static_gate",
    "startup_100ed3c0_nonempty_preloop_runtime",
    "startup_100ed3c0_nonempty_preloop_post_pe_gate",
    "x64_bootstrap_load_after_startup_100ed3c0_nonempty_preloop",
)

CHILD_LIBRARIES = (
    "rome2_startup_100f1c10_runtime",
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100df270_platform_prefix_transcript_runtime",
    "rome2_startup_100df270_suffix_transcript_runtime",
    "rome2_startup_100f1bb0_owned_utf16_runtime",
    "rome2_startup_100f2750_sentinel_owned_runtime",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetProcAddress", "GetProcessHeap", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "MessageBoxA",
    "MessageBoxW", "TerminateProcess", "VirtualAlloc", "VirtualFree",
    "_atexit", "_onexit", "atexit", "calloc", "dlopen", "dlsym",
    "free", "malloc", "realloc", "system",
}

BANNED_ORIGINAL_ADDRESS_TOKENS = {
    "0x100df270", "0x100ed3c0", "0x100ed471", "0x100f1aa0",
    "0x100f1bb0", "0x100f1c10", "0x100f1cc0", "0x100f2750",
    "0x119f31c5", "0x119f31c8", "0x119f3aa0",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _check_exact(
    text: str,
    expected_bytes: int,
    expected_hash: str,
    label: str,
    findings: list[str],
) -> None:
    encoded = text.encode("utf-8")
    if len(encoded) != expected_bytes:
        findings.append(f"{label} byte count changed")
    if _sha256(encoded) != expected_hash:
        findings.append(f"{label} SHA-256 changed")


def _function_body(code: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}\s*\([^;]*\)\s*\{{", code, re.S)
    if match is None:
        return None
    start = code.find("{", match.start())
    depth = 0
    for index in range(start, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[start + 1:index]
    return None


def _call_count(code: str, name: str) -> int:
    return len(re.findall(rf"\b{re.escape(name)}\s*\(", code))


def _require_in_order(
    text: str,
    tokens: tuple[str, ...],
    findings: list[str],
    message: str,
) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            findings.append(message)
            return
        cursor = position + len(token)


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def inspect_header_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_HEADER_BYTES, EXPECTED_HEADER_SHA256, "header", findings
    )
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)
    required = (
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_STEP_COUNTUINT32_C(9)",
         "header must freeze exactly nine parent steps"),
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_MIN_TEXT_UNITSUINT32_C(2)",
         "header minimum must require one nonzero UTF-16 unit plus terminator"),
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_MAX_TEXT_UNITS\\"
         "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
         "header maximum text bound changed"),
        ("uint64_tcontext_byte_count;", "parent callback span is missing"),
        ("uint64_tchild_prefix_context_byte_count;",
         "prefix callback span is missing"),
        ("uint64_tchild_suffix_context_byte_count;",
         "suffix callback span is missing"),
        ("rome2_100f1bb0_owned_effectstemporary_owned;",
         "temporary owned effects are missing"),
        ("rome2_100f1bb0_owned_effectspersistent_owned;",
         "persistent owned effects are missing"),
        ("rome2_100f1bb0_owned_owner*temporary_owner,",
         "caller-visible temporary owner is required"),
        ("rome2_100f1bb0_owned_owner*persistent_owner,",
         "caller-visible persistent owner is required"),
        ("rome2_100f2750_first_use_lifecycle*lifecycle,",
         "caller-visible lifecycle is required"),
        ("rome2_100ed3c0_preloop_result*result_out);",
         "bounded result API changed"),
    )
    for fragment, message in required:
        if compact.count(fragment) != 1:
            findings.append(message)

    for ordinal, kind in enumerate(STEP_KINDS, 1):
        if compact.count(f"{kind}={ordinal}") != 1:
            findings.append(f"parent step ordinal changed: {kind}")
    if _call_count(code, FUNCTION) != 1:
        findings.append("header must declare exactly one typed nonempty API")
    if (
        "constrome2_100f1bb0_owned_owner*temporary_owner," in compact
        or "constrome2_100f1bb0_owned_owner*persistent_owner," in compact
        or "constrome2_100f2750_first_use_lifecycle*lifecycle," in compact
    ):
        findings.append("caller-visible ownership controls must be mutable")

    contract_compact = re.sub(r"[\s*]+", "", text)
    contract_tokens = (
        "partially overlapping spans are rejected",
        "temporary_owner LIVE",
        "persistent owner LIVE",
        "performs no implicit rollback",
        "result_out is committed only after successful temporary cleanup",
        "Owned status values are propagated exactly",
        "performs no guest/native pointer cast",
    )
    for token in contract_tokens:
        if re.sub(r"[\s*]+", "", token) not in contract_compact:
            findings.append(f"header ownership/containment contract changed: {token}")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_SOURCE_BYTES, EXPECTED_SOURCE_SHA256, "source", findings
    )
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)

    for identifier in BANNED_IDENTIFIERS:
        if re.search(rf"\b{re.escape(identifier)}\b", code):
            findings.append(
                f"forbidden native/original identifier in source: {identifier}"
            )
    if re.search(r"\b(?:decomp_fn_|FUN_|DAT_)[A-Za-z0-9_]*", code):
        findings.append("source must not reference recovered/original identifiers")
    lowered = code.lower()
    for token in BANNED_ORIGINAL_ADDRESS_TOKENS:
        if token in lowered:
            findings.append(f"source embeds forbidden original address: {token}")
    if re.search(r"\([^)]*\*[^)]*\)\s*(?:guest_|argument_position3_text)", code):
        findings.append("source performs a guest/native pointer cast")

    constants = (
        ("ROME2_100ED3C0_NONEMPTY_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "32-bit guest address-space bound changed"),
        ("ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT11U",
         "external control cardinality changed"),
        ("ROME2_100ED3C0_NONEMPTY_BACKING_COUNT6U",
         "six-view backing cardinality changed"),
        ("ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT5U",
         "five callback-context spans are required"),
        ("state.effects=*effects;", "effects must be snapshotted once"),
        ("private_span.byte_count=sizeof(state);",
         "private transaction state is not protected"),
        ("state.allocation_bytes=state.text_length*UINT32_C(2)+UINT32_C(10);",
         "exact 2*N+10 allocation formula changed"),
        ("frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET]="
         "UINT8_C(0);", "packet +0x2c flag must be literal zero"),
    )
    for fragment, message in constants:
        if compact.count(fragment) != 1:
            findings.append(message)
    body = _function_body(code, FUNCTION)
    if body is None:
        findings.append("typed nonempty parent definition is missing")
        return sorted(set(findings))
    body_compact = _compact(body)
    if compact.count(
        "ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET]=UINT8_C(0);"
    ) != 2:
        findings.append("preview and committed packet +0x2c flags must be zero")
    if body_compact.count("state.effects=*effects;") != 1:
        findings.append("effects snapshot count changed")
    snapshot_position = body_compact.find("state.effects=*effects;")
    if snapshot_position < 0 or "effects->" in body_compact[snapshot_position:]:
        findings.append("live effects are reread after snapshot")

    expected_calls = {
        BUILD_CALL: 2,
        PREFIX_CALL: 2,
        MIDDLE_CALL: 2,
        DELEGATED_SUFFIX_CALL: 2,
        FIRST_USE_CALL: 1,
        CLEANUP_CALL: 1,
    }
    for name, expected in expected_calls.items():
        count = _call_count(code, name)
        if count != expected:
            findings.append(
                f"admitted child call count changed: {name} ({count} != {expected})"
            )
    if _call_count(code, NONDELEGATED_SUFFIX_CALL) != 0:
        findings.append("nonempty parent must use only the delegated suffix")
    if _call_count(code, "rome2_port_100f1c10_initialize_triplet") != 4:
        findings.append("two preflight and two committed triplet calls are required")
    if _call_count(code, "rome2_port_100f1aa0_copy_empty_source") != 4:
        findings.append("two preflight and two committed empty-copy calls are required")

    for kind in STEP_KINDS:
        if body_compact.count(kind) != 1:
            findings.append(f"parent operation missing or duplicated: {kind}")
    if body_compact.count("state.effects.emit_step(state.effects.context,step);") != 9:
        findings.append("parent must emit exactly nine ordered steps")

    actual_anchor = body_compact.find(
        "frame_bytes=state.frame_view.host_base+"
        "(size_t)state.frame_span.view_offset;"
    )
    if actual_anchor < 0:
        findings.append("committed parent boundary is missing")
    else:
        committed = body_compact[actual_anchor:]
        sequence = (
            STEP_KINDS[0], STEP_KINDS[1], STEP_KINDS[2],
            "rome2_port_100f1c10_initialize_triplet(",
            STEP_KINDS[3], "rome2_port_100f1c10_initialize_triplet(",
            STEP_KINDS[4], "rome2_port_100f1aa0_copy_empty_source(",
            STEP_KINDS[5], "rome2_port_100f1aa0_copy_empty_source(",
            STEP_KINDS[6], f"{BUILD_CALL}(", STEP_KINDS[7],
            f"{PREFIX_CALL}(", f"{MIDDLE_CALL}(",
            f"{DELEGATED_SUFFIX_CALL}(", STEP_KINDS[8], f"{CLEANUP_CALL}(",
            "result_out->child_receiver=state.guest_receiver;",
            "result_out->child_packet=state.guest_packet;",
            "result_out->child_argument=state.guest_descriptor;",
            "result_out->next_original_pc=ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;",
        )
        _require_in_order(
            committed, sequence, findings,
            "nine-step admitted-child commit order or hard stop changed",
        )
        if re.search(r"\b(?:for|while|do|goto)\b", committed):
            findings.append("committed parent interval must remain straight-line")
        if "ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET]=" in committed:
            findings.append("owned descriptor must not be pre-zeroed")

    preflight = body_compact[:actual_anchor] if actual_anchor >= 0 else body_compact
    preflight_tokens = (
        "state.owned_deny_effects.allocate="
        "rome2_100ed3c0_nonempty_deny_allocate;",
        f"{BUILD_CALL}(",
        "memcpy(state.frame_preview,",
        f"{PREFIX_CALL}(", f"{MIDDLE_CALL}(", f"{DELEGATED_SUFFIX_CALL}(",
    )
    _require_in_order(
        preflight, preflight_tokens, findings,
        "deterministic private preflight sequence changed",
    )
    if "state.effects.emit_step(" in preflight:
        findings.append("preflight must complete before the first parent observer")

    entry_fragments = (
        ("!rome2_100ed3c0_nonempty_owner_is_empty("
         "&state.temporary_owner_initial)",
         "temporary owner must enter canonical EMPTY"),
        ("!rome2_100ed3c0_nonempty_owner_is_empty("
         "&state.persistent_owner_initial)",
         "persistent owner must enter canonical EMPTY"),
        ("state.lifecycle_initial.phase!="
         "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL",
         "lifecycle must enter REGISTERED_SENTINEL"),
        ("rome2_100ed3c0_nonempty_read_u32_le("
         "persistent_descriptor_bytes)!=UINT32_C(0)",
         "persistent descriptor count must enter zero"),
        ("rome2_100ed3c0_nonempty_read_u32_le("
         "persistent_descriptor_bytes+4U)!=UINT32_C(0)",
         "persistent descriptor capacity must enter zero"),
        ("rome2_100ed3c0_nonempty_read_u32_le("
         "persistent_descriptor_bytes+8U)!="
         "ROME2_PORT_100F2750_FIRST_USE_SENTINEL",
         "persistent descriptor sentinel authority changed"),
    )
    for fragment, message in entry_fragments:
        if body_compact.count(fragment) != 1:
            findings.append(message)

    rollback_fragments = (
        ("*temporary_owner=state.temporary_owner_initial;", 1,
         "temporary allocation failure rollback changed"),
        ("*persistent_owner=state.persistent_owner_initial;", 4,
         "pre-first-use persistent owner rollback changed"),
        ("*lifecycle=state.lifecycle_initial;", 4,
         "pre-first-use lifecycle rollback changed"),
    )
    for fragment, expected, message in rollback_fragments:
        if body_compact.count(fragment) != expected:
            findings.append(message)

    preflight_assertions = (
        ("state.deny_context.call_count!=UINT32_C(1)",
         "deny preflight must allocate exactly once"),
        ("state.deny_context.release_count!=UINT32_C(0)",
         "deny preflight must release zero times"),
        ("state.deny_context.requested_bytes!=state.allocation_bytes",
         "deny preflight byte request changed"),
        ("state.deny_context.requested_class!="
         "ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS",
         "deny preflight allocation class changed"),
        ("!rome2_100ed3c0_nonempty_owner_is_empty(&state.preflight_owner)",
         "deny preflight owner preservation changed"),
        ("state.preflight_return.value!=UINT32_C(0xdeadbeef)",
         "deny preflight return preservation changed"),
    )
    for fragment, message in preflight_assertions:
        if body_compact.count(fragment) != 1:
            findings.append(message)

    text_capacity_fragments = (
        ("state.text_length==UINT32_C(0)",
         "nonempty text lower bound changed"),
        ("state.text_length>=text_max_units",
         "text terminator budget check changed"),
        ("state.text_length>=ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
         "owned text upper bound changed"),
    )
    for fragment, message in text_capacity_fragments:
        if body_compact.count(fragment) != 1:
            findings.append(message)
    capacity_calls = (
        "rome2_100ed3c0_nonempty_validate_heap_capacity("
        "&state.temporary_heap_view,state.allocation_bytes);",
        "rome2_100ed3c0_nonempty_validate_heap_capacity("
        "&state.persistent_heap_view,state.allocation_bytes);",
    )
    if any(body_compact.count(call) != 1 for call in capacity_calls):
        findings.append("both temporary and persistent heap capacities are required")

    delegate_fragments = (
        ("state.owned_delegate_context.expected_destination.value="
         "ROME2_PORT_100F2750_FIRST_USE_DESTINATION;",
         "owned delegate destination binding changed"),
        ("state.owned_delegate_context.expected_source=state.guest_descriptor;",
         "owned delegate source binding changed"),
        ("state.owned_delegate_context.call_count==UINT32_C(1)&&"
         "state.owned_delegate_context.owned_status!=",
         "exact-status path must require exactly one delegate call"),
    )
    for fragment, message in delegate_fragments:
        if body_compact.count(fragment) != 1:
            findings.append(message)
    if compact.count("state->guest_return.value!=guest_destination.value") != 1:
        findings.append("first-use return identity authentication changed")

    build_step = (
        "step.argument_count=UINT32_C(3);"
        "step.argument0=rome2_100ed3c0_nonempty_make_value("
        "ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,"
        "state.guest_descriptor.value);"
        "step.argument1=rome2_100ed3c0_nonempty_make_value("
        "ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY,"
        "argument_position3_text.value);"
        "step.argument2=rome2_100ed3c0_nonempty_make_value("
        "ROME2_100ED3C0_PRELOOP_VALUE_SCALAR,state.text_length);"
    )
    if body_compact.count(build_step) != 1:
        findings.append("owned-build step must expose descriptor, text, and exact N")

    owner_fragments = (
        ("*temporary_owner=state.temporary_owner_work;",
         6, "caller-visible temporary ownership publication changed"),
        ("*persistent_owner=state.persistent_owner_work;",
         4, "persistent ownership publication changed"),
        ("*lifecycle=state.lifecycle_work;",
         4, "lifecycle publication changed"),
        ("returnstate.owned_delegate_context.owned_status;",
         1, "delegated owned status must propagate exactly"),
        ("&state.effects.temporary_owned,temporary_owner);",
         1, "cleanup must consume the caller-visible temporary owner"),
        ("*state->persistent_owner_external=*state->persistent_owner_work;",
         1, "successful first-use owner must publish before suffix tail"),
        ("*state->lifecycle_external=*state->lifecycle_work;",
         1, "successful first-use lifecycle must publish before suffix tail"),
    )
    for fragment, expected, message in owner_fragments:
        if body_compact.count(fragment) != expected and compact.count(fragment) != expected:
            findings.append(message)

    result_writes = (
        "result_out->child_receiver=state.guest_receiver;",
        "result_out->child_packet=state.guest_packet;",
        "result_out->child_argument=state.guest_descriptor;",
        "result_out->next_original_pc=ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;",
    )
    cleanup_position = body_compact.rfind(f"{CLEANUP_CALL}(")
    for write in result_writes:
        if body_compact.count(write) != 1:
            findings.append("bounded result fields must commit exactly once")
        elif body_compact.find(write) < cleanup_position:
            findings.append("bounded result committed before temporary cleanup")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_TEST_BYTES, EXPECTED_TEST_SHA256, "runtime", findings)
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)
    raw_compact = _compact(text)
    if compact.count("#defineTEST_EXPECTED_CASESUINT32_C(48)") != 1:
        findings.append("runtime must freeze exactly 48 cases")
    for group in (
        "test_success_matrix", "test_tier0_failures",
        "test_temporary_failures", "test_persistent_failures",
    ):
        if _call_count(code, group) != 2:
            findings.append(f"runtime group definition/registry changed: {group}")
    main = _function_body(code, "main")
    if main is None:
        findings.append("runtime main registry is missing")
    else:
        _require_in_order(
            _compact(main),
            tuple(f"failed|={group}();" for group in (
                "test_success_matrix", "test_tier0_failures",
                "test_temporary_failures", "test_persistent_failures",
            )),
            findings,
            "runtime four-group registry order changed",
        )
    matrix_fragments = (
        ("temporary_residue<UINT32_C(4)", "four temporary residues are required"),
        ("persistent_residue<UINT32_C(4)", "four persistent residues are required"),
        ('"minimumN=1"', "minimum N=1 success case is missing"),
        ('"maximumN=32767"', "maximum N=32767 success case is missing"),
        ('"effectssnapshot"', "effects snapshot adversary is missing"),
        ('"persistenttokencollision"', "persistent token collision case is missing"),
        ('"explicitcleanupofthetorntemporaryownerfailed"',
         "escaped temporary cleanup proof is missing"),
        ('"theregistered-sentinelno-effectteardownchanged"',
         "sentinel no-effect teardown proof is missing"),
        ('"arepeatedteardownemittedaneffectorchangedstatus"',
         "repeat teardown proof is missing"),
        ("test_case_count==TEST_EXPECTED_CASES",
         "runtime cardinality assertion is missing"),
    )
    for fragment, message in matrix_fragments:
        if fragment not in raw_compact:
            findings.append(message)
    for event in (
        "TEST_EVENT_PARENT_BASE", "TEST_EVENT_PREFIX_BASE",
        "TEST_EVENT_SUFFIX_BASE", "TEST_EVENT_ALLOCATE_TEMPORARY",
        "TEST_EVENT_ALLOCATE_PERSISTENT", "TEST_EVENT_RELEASE_TEMPORARY",
        "TEST_EVENT_RELEASE_PERSISTENT", "TEST_EVENT_HOOK_TEMPORARY",
        "TEST_EVENT_HOOK_PERSISTENT",
    ):
        if compact.count(f"#define{event}UINT32_C(") != 1:
            findings.append(f"total-order recorder event is missing: {event}")
    if re.search(r"\b(?:decomp_fn_|FUN_)[A-Za-z0-9_]*\s*\(", code):
        findings.append("runtime must never execute an original function")
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_PROVENANCE_BYTES, EXPECTED_PROVENANCE_SHA256,
        "provenance", findings,
    )
    required = (
        "PRELOOP_SIZE = 177",
        'PRELOOP_SHA256 = "b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626"',
        "EXCLUDED_SIZE = 223",
        '"port/x64_ported/ported_100ed3c0_nonempty_preloop.c"',
        '"17f8c4828490235d4734d734e3222be2c47ac9763bd69871b1e7cd2744fcae6f"',
        "test_reciprocal_boundary_and_authority_mutants_fail",
        "test_oracle_is_standard_library_only_and_read_only",
    )
    for token in required:
        if token not in text:
            findings.append(f"provenance authority/boundary token changed: {token}")
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC_BYTES, EXPECTED_DOC_SHA256, "doc", findings)
    compact = _compact(text)
    for token in (
        "[0x100ed3c0,0x100ed471)",
        "build the nonempty owned UTF-16 descriptor",
        "prefix and deterministic middle",
        "run its delegated suffix",
        "clean up only the temporary owner",
        "48 cases",
        "all 16 temporary/persistent raw-residue pairs",
        "selector marker and parent result uncommitted",
        "BUILD_TESTING",
        "either production binary",
    ):
        if _compact(token) not in compact:
            findings.append(f"documentation contract changed: {token}")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    found: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, re.I):
            stack.append((index, bool(re.match(
                r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, re.I
            ))))
        elif re.match(r"endif(?:\s*\([^)]*\))?\s*$", stripped, re.I):
            if not stack:
                return None
            start, is_build_testing = stack.pop()
            if is_build_testing:
                found.append((start, index))
    if stack or len(found) != 1:
        return None
    return found[0]


def _link_commands(text: str) -> list[list[str]]:
    commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    return [re.split(r"\s+", command.strip()) for command in commands]


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_CMAKE_BYTES, EXPECTED_CMAKE_SHA256, "CMake", findings
    )
    count = len(re.findall(r"^\s*add_test\s*\(", text, re.I | re.M))
    if count != EXPECTED_CTEST_COUNT:
        findings.append(
            f"CMake total must be exactly {EXPECTED_CTEST_COUNT} CTests"
        )
    if re.search(r"\b(?:set|option)\s*\(\s*BUILD_TESTING\b", text, re.I):
        findings.append("CMake must not override BUILD_TESTING")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        findings.append("one balanced if(BUILD_TESTING) block is required")
        return sorted(set(findings))
    start, end = bounds
    for token in (*CMAKE_FILES, *CMAKE_TESTS, LIBRARY, TEST_TARGET):
        positions = [i for i, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake nonempty token is missing: {token}")
        elif any(i <= start or i >= end for i in positions):
            findings.append(f"CMake nonempty token escapes BUILD_TESTING: {token}")

    scoped = _compact("\n".join(lines[start + 1:end]))
    required = (
        (f"add_library({LIBRARY}STATIC"
         '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_preloop.h"'
         '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_preloop.c")',
         "CMake nonempty library must be exact static and test-only"),
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "CMake nonempty C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "CMake nonempty hardened compile options changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_nonempty_preloop.c")',
         "CMake nonempty runtime executable changed"),
        (f"rome2_configure_x64_target({TEST_TARGET})",
         "CMake nonempty runtime x64 configuration changed"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "CMake nonempty runtime link changed"),
    )
    for fragment, message in required:
        if scoped.count(fragment) != 1:
            findings.append(message)

    commands = _link_commands(text)
    expected_own = [LIBRARY, "PUBLIC", "rome2_guest32_runtime", "PRIVATE",
                    *CHILD_LIBRARIES]
    own = [words for words in commands if words and words[0] == LIBRARY]
    if own != [expected_own]:
        findings.append("CMake nonempty exact child dependency list changed")
    consumers = [
        words[0] for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if set(consumers) != {TEST_TARGET, COMPOSITION_LIBRARY} or len(consumers) != 2:
        findings.append(
            "CMake nonempty consumers must be exactly its standalone runtime "
            "test and whole-parent composition"
        )
    if re.search(
        rf"target_link_libraries\s*\(\s*rome2_headless64[^)]*\b"
        rf"{re.escape(LIBRARY)}\b", text, re.I | re.S
    ):
        findings.append("test-only nonempty library escaped into headless")

    for name in CMAKE_TESTS:
        if scoped.count(f"add_test(NAME{name}COMMAND") != 1:
            findings.append(f"CMake nonempty CTest registration changed: {name}")
    gate_start = scoped.find(
        "add_test(NAMEstartup_100ed3c0_nonempty_preloop_static_gateCOMMAND"
    )
    gate_end = scoped.find("add_test(", gate_start + 1)
    gate_scope = scoped[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        "--header", "--source", "--test", "--provenance", "--doc",
        "--cmake", "--headless", "--export-manifest", "--export-contract",
        "--legacy-def", "--bootstrap-def", "--probe-def",
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"CMake static-gate argument changed: {argument}")

    fixture_requirements = (
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_preloop_provenance_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_preloop_static_tool_verified",
        "FIXTURES_REQUIREDstartup_100ed3c0_nonempty_preloop_static_tool_verified"
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_preloop_static_verified",
        "startup_100df270_suffix_transcript_reload_verified;"
        "startup_100f1bb0_owned_utf16_runtime_verified;"
        "startup_100f2750_sentinel_owned_runtime_verified;"
        "startup_100ed3c0_nonempty_preloop_provenance_verified;"
        "startup_100ed3c0_nonempty_preloop_static_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_preloop_runtime_verified",
        "startup_100ed3c0_nonempty_preloop_runtime_verified;"
        "entry_policy_probe_pe_tool_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_preloop_post_verified",
        "x64_bootstrap_pre_verified;"
        "startup_100ed3c0_nonempty_preloop_post_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_preloop_reload_verified",
    )
    for fragment in fixture_requirements:
        if fragment not in scoped:
            findings.append(f"CMake nonempty fixture chain changed: {fragment}")
    return sorted(set(findings))


def inspect_production_text(text: str) -> list[str]:
    lowered = text.lower()
    findings: list[str] = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(),
        "ported_100ed3c0_nonempty_preloop",
        "100ed3c0_nonempty_preloop",
        "100ed3c0-nonempty-preloop",
    ):
        if token in lowered:
            findings.append(f"test-only nonempty token escaped production: {token}")
    return sorted(set(findings))


def _inspect_path(path: pathlib.Path, inspector) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspector(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument("--provenance", type=pathlib.Path, required=True)
    parser.add_argument("--doc", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--export-contract", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--bootstrap-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "runtime": (args.test, inspect_test_text),
        "provenance": (args.provenance, inspect_provenance_text),
        "doc": (args.doc, inspect_doc_text),
        "cmake": (args.cmake, inspect_cmake_text),
        "headless": (args.headless, inspect_production_text),
        "export_manifest": (args.export_manifest, inspect_production_text),
        "export_contract": (args.export_contract, inspect_production_text),
        "legacy_def": (args.legacy_def, inspect_production_text),
        "bootstrap_def": (args.bootstrap_def, inspect_production_text),
        "probe_def": (args.probe_def, inspect_production_text),
    }
    report: dict[str, list[str]] = {}
    for label, (path, inspector) in requested.items():
        findings = _inspect_path(path, inspector)
        if findings:
            report[label] = findings
    if report:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print("100ed3c0 nonempty preloop static gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
