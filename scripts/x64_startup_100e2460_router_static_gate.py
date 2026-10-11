#!/usr/bin/env python3
"""Fail-closed source gate for the bounded 0x100e2460 route selector."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e2460_run_router"
LIBRARY = "rome2_startup_100e2460_router_runtime"
TEST_TARGET = "rome2_startup_100e2460_router_tests"
SIX_APPEND_TEST_TARGET = "rome2_startup_100e2460_router_six_append_tests"
HEADLESS = "rome2_headless64"
PREALLOCATED_LIBRARY = "rome2_startup_100e2460_preallocated_branch_runtime"
CAPACITY_ZERO_LIBRARY = "rome2_startup_100e2460_capacity_zero_branch_runtime"
GROWTH_LIBRARY = "rome2_startup_100e2460_growth_branch_runtime"
HANDLER_8D00_FUNCTION = "rome2_port_100e8d00_run_handler_transcript"
HANDLER_85D0_FUNCTION = "rome2_port_100e85d0_normal_adapter"
HANDLER_8580_FUNCTION = "rome2_port_100e8580_run_handler_transcript"
OUTER_FUNCTION = "rome2_port_100ea4d0_run_injected"
HANDLER_9340_FUNCTION = "rome2_port_100e9340_run_handler_transcript"
HANDLER_92C0_FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
HANDLER_87A0_FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
PLATFORM_PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
HANDLER_8D00_LIBRARY = "rome2_startup_100e8d00_handler_transcript_runtime"
HANDLER_85D0_LIBRARY = "rome2_startup_100e85d0_normal_adapter_runtime"
HANDLER_8580_LIBRARY = "rome2_startup_100e8580_handler_transcript_runtime"
OUTER_LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
HANDLER_9340_LIBRARY = "rome2_startup_100e9340_handler_transcript_runtime"
HANDLER_92C0_LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
HANDLER_87A0_LIBRARY = "rome2_startup_100e87a0_handler_transcript_runtime"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PLATFORM_PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"
MIDDLE_FUNCTION = "rome2_port_100df270_project_headless_empty_state"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"

EXPECTED_CTEST_COUNT = 192
EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_SIZE = 182959
EXPECTED_CMAKE_SHA256 = (
    "3e7dda18a4e170f7d68a73f121ff5f4a40e58c854047e730a9608984b9589674"
)

EXPECTED_HEADER_TOKEN_SHA256 = (
    "465d9ef422f841136ef361b51066c6ac78688a50b462c50875b4a08ca625e81d"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "e225e18e3762153ce86964db722d0b5694522cda0d970c56920f9dca2b0f88e5"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "366d0658ee59344da776f7ef7f6cd8126223921672c353521df5ae148d8ad88a"
)
EXPECTED_SIX_APPEND_TEST_TOKEN_SHA256 = (
    "17cf174cdcfd30b40f76db08c48232c1c0308a4c9a22dcd5ef6257f587095628"
)
EXPECTED_ROUTER_PROVENANCE_SHA256 = (
    "6b6c4ea67144a11948eca262ea55958030001ddb4dc1242dc53efdf9f6ad132a"
)

ROUTER_TEST_NAMES = (
    "startup_100e2460_router_provenance",
    "startup_100e2460_router_static_gate_unit",
    "startup_100e2460_router_static_gate",
    "startup_100e2460_router_runtime",
    "startup_100e2460_router_six_append_runtime",
    "startup_100e2460_router_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e2460_router",
)

HEADLESS_LINK_LIBRARIES = (
    "rome2_guest32_runtime",
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100f2750_nonalloc_runtime",
    "rome2_startup_100e8240_fastpath_runtime",
    "rome2_startup_100e2460_append_prefix_runtime",
    PREALLOCATED_LIBRARY,
    CAPACITY_ZERO_LIBRARY,
    GROWTH_LIBRARY,
    LIBRARY,
    HANDLER_8D00_LIBRARY,
    HANDLER_85D0_LIBRARY,
    HANDLER_8580_LIBRARY,
    OUTER_LIBRARY,
    HANDLER_9340_LIBRARY,
    HANDLER_92C0_LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PLATFORM_PREFIX_LIBRARY,
    PARENT_LIBRARY,
    LIFECYCLE_LIBRARY,
)

FINAL_HEADLESS_TOKENS = (
    "initializer-handler-100e8d00=injected-transcript-complete",
    "initializer-handler-100e85d0=effect-free-complete",
    "initializer-handler-100e8580=injected-transcript-complete",
    "initializer-100ea4d0=injected-complete",
    "initializer-handler-100e9340=injected-transcript-complete",
    "initializer-handler-100e92c0=injected-transcript-complete",
    "initializer-handler-100e87a0=injected-transcript-complete",
    "startup-100df270-suffix=injected-transcript-complete",
    "startup-100df270-platform-prefix=injected-call-shape-complete",
    "startup-100ed3c0-empty-preloop=injected-composition-complete",
    "startup-100ed471-ordinary-lifecycle=injected-bounded-complete",
)

HEADLESS_REQUIRED_TOKENS = (
    "initializer-router=injected-complete",
    "initializer-growth=injected-complete",
    "growth-allocator=injected-16-byte",
    "growth-release=injected-old-backing",
    "native-release=not-run",
    "platform-effects=not-run",
    "native-allocator=not-run",
    "initializer-dispatch=injected-complete",
    "queue-drain=injected-bounded-complete",
    "gameplay=not-linked",
    *FINAL_HEADLESS_TOKENS,
)

FINAL_HEADLESS_CALLS = (
    (FUNCTION, 1),
    (HANDLER_8D00_FUNCTION, 2),
    (HANDLER_85D0_FUNCTION, 2),
    (HANDLER_8580_FUNCTION, 2),
    (OUTER_FUNCTION, 1),
    (HANDLER_9340_FUNCTION, 2),
    (HANDLER_92C0_FUNCTION, 2),
    (HANDLER_87A0_FUNCTION, 2),
    (SUFFIX_FUNCTION, 0),
    (PLATFORM_PREFIX_FUNCTION, 0),
    (MIDDLE_FUNCTION, 0),
    (PARENT_FUNCTION, 1),
    (LIFECYCLE_FUNCTION, 1),
)

BANNED_IDENTIFIERS = {
    "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "FreeLibrary", "GetMessageA", "GetMessageW",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "PeekMessageA",
    "PeekMessageW", "PostMessageA", "PostMessageW", "SendMessageA",
    "SendMessageW", "TranslateMessage", "VirtualAlloc", "VirtualFree",
    "calloc", "dlopen", "dlsym", "free", "malloc", "realloc",
}

BANNED_ADDRESS_TOKENS = {"100fcc50", "100fcc80", "1172f670"}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT64_C", "if", "return", "sizeof", FUNCTION,
    "rome2_100e2460_router_control_objects_overlap",
    "rome2_100e2460_router_host_objects_overlap",
    "rome2_100e2460_router_read_selector",
    "rome2_100e2460_router_read_u32_le",
    "rome2_100e2460_router_spans_overlap",
    "rome2_100e2460_router_validate_interval",
    "rome2_100e2460_router_validate_object",
    "rome2_port_100e2460_run_preallocated_branch",
    "rome2_port_100e2460_run_capacity_zero_branch",
    "rome2_port_100e2460_run_growth_branch",
}


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _token_digest(code: str) -> str:
    return hashlib.sha256(_compact(code).encode("utf-8")).hexdigest()


def _require_once(
    compact: str, fragment: str, findings: list[str], message: str
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_HEADER_TOKEN_SHA256:
        findings.append("header executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_growth_branch.h"]:
        findings.append("router header must reuse only the growth superset contract")
    declaration = (
        "rome2_100e2460_branch_status" + FUNCTION + "("
        "constrome2_guest_write_view*state_view,"
        "constrome2_guest_read_view*vtable_view,"
        "rome2_guest_addr32guest_vector,"
        "rome2_guest_addr32guest_handler,"
        "rome2_guest_addr32guest_argument,"
        "constrome2_100e2460_growth_effects*effects,"
        "uint32_tmax_peek_calls,uint8_t*return_al_out);"
    )
    _require_once(compact, declaration, findings, "public router API contract changed")
    lowered = " ".join(text.lower().split())
    for phrase in (
        "count < capacity",
        "capacity == 0",
        "count > capacity reaches the growth",
        "zero capacity with nonzero count reaches the capacity-zero",
        "full growth superset",
        "snapshotted",
        "callbacks may be null",
        "initialized, valid c representation",
        "exclusive, non-reentrant borrow",
        "no native allocation",
        "guest-to-host pointer cast",
    ):
        if phrase not in lowered:
            findings.append(f"router safety/selection contract is missing: {phrase}")
    if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append("DLL import/export annotation is forbidden")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_SOURCE_TOKEN_SHA256:
        findings.append("source executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_router.h", "limits.h"]:
        findings.append("source include set or order changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden allocation/release/platform identifier: {token}")
    lowered = code.lower()
    for address in sorted(BANNED_ADDRESS_TOKENS):
        if address in lowered:
            findings.append(f"excluded recovered address token: {address}")
    if re.search(r"\b(?:extern|volatile|__declspec)\b", code):
        findings.append("extern/volatile/DLL storage is forbidden")
    if re.search(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uint64_t|uintptr_t|intptr_t)\s*\*+\s*\)\s*"
        r"[^;\n]{0,128}\b(?:guest_vector|guest_handler|guest_argument)\b",
        code,
    ):
        findings.append("guest identity is converted to a native pointer")
    if re.search(
        r"\(\s*(?:uintptr_t|intptr_t)\s*\)\s*"
        r"[^;\n]{0,128}\b(?:guest_vector|guest_handler|guest_argument)\b",
        code,
    ):
        findings.append("guest identity is converted to a native address")
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    for call in sorted(calls - ALLOWED_CALL_EXPRESSIONS):
        findings.append(f"unexpected call expression: {call}")
    if len(re.findall(
        r"\brome2_100e2460_branch_status\s+" + re.escape(FUNCTION) + r"\s*\(",
        code,
    )) != 1:
        findings.append("exactly one router definition is required")

    constants = (
        ("#defineROME2_100E2460_ROUTER_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest address-space constant changed"),
        ("#defineROME2_100E2460_ROUTER_SELECTION_BYTESUINT64_C(12)",
         "selector span width changed"),
    )
    for fragment, message in constants:
        _require_once(compact, fragment, findings, message)

    if compact.count("rome2_100e2460_router_spans_overlap(") != 12:
        findings.append("full control/host alias matrix changed")
    for pair in (
        "(uint64_t)(uintptr_t)state_view,sizeof(*state_view),"
        "(uint64_t)(uintptr_t)vtable_view,sizeof(*vtable_view)",
        "(uint64_t)(uintptr_t)state_view,sizeof(*state_view),"
        "(uint64_t)(uintptr_t)effects,sizeof(*effects)",
        "(uint64_t)(uintptr_t)vtable_view,sizeof(*vtable_view),"
        "(uint64_t)(uintptr_t)effects,sizeof(*effects)",
        "(uint64_t)(uintptr_t)return_al_out,sizeof(*return_al_out),"
        "(uint64_t)(uintptr_t)effects,sizeof(*effects)",
        "(uint64_t)(uintptr_t)state_view->host_base,state_view->byte_count,"
        "(uint64_t)(uintptr_t)effects,sizeof(*effects)",
        "(uint64_t)(uintptr_t)vtable_view->host_base,vtable_view->byte_count,"
        "(uint64_t)(uintptr_t)return_al_out,sizeof(*return_al_out)",
    ):
        if compact.count(pair) != 1:
            findings.append(f"router pairwise alias validation changed: {pair[:64]}")

    selector = (
        ("if(guest_vector.value==0){returnROME2_100E2460_BRANCH_NULL_ADDRESS;}",
         "selector null-address precedence changed"),
        ("if(guest_vector.value>UINT32_MAX-(uint32_t)("
         "ROME2_100E2460_ROUTER_SELECTION_BYTES-UINT64_C(1))){"
         "returnROME2_100E2460_BRANCH_RANGE_OVERFLOW;}",
         "selector checked guest32 end changed"),
        ("if(guest_vector.value<state_view->guest_base){"
         "returnROME2_100E2460_BRANCH_OUT_OF_RANGE;}",
         "selector lower-bound check changed"),
        ("if(vector_offset>state_view->byte_count||"
         "ROME2_100E2460_ROUTER_SELECTION_BYTES>"
         "state_view->byte_count-vector_offset||"
         "vector_offset>(uint64_t)SIZE_MAX){"
         "returnROME2_100E2460_BRANCH_OUT_OF_RANGE;}",
         "selector mapping/host-offset checks changed"),
        ("*capacity_out=rome2_100e2460_router_read_u32_le(vector+4);"
         "*count_out=rome2_100e2460_router_read_u32_le(vector+8);",
         "capacity/count selector offsets changed"),
    )
    for fragment, message in selector:
        _require_once(compact, fragment, findings, message)

    marker = "rome2_100e2460_branch_status" + FUNCTION + "("
    start = compact.find(marker)
    body = compact[start:] if start >= 0 else ""
    validation_fragments = (
        "rome2_100e2460_router_validate_object(state_view,sizeof(*state_view))",
        "rome2_100e2460_router_validate_object(vtable_view,sizeof(*vtable_view))",
        "rome2_100e2460_router_validate_object(effects,sizeof(*effects))",
        "rome2_100e2460_router_validate_object(return_al_out,sizeof(*return_al_out))",
        "rome2_100e2460_router_control_objects_overlap("
        "state_view,vtable_view,effects,return_al_out)",
        "rome2_100e2460_router_validate_interval(state_view->host_base,"
        "state_view->guest_base,state_view->byte_count)",
        "rome2_100e2460_router_validate_interval(vtable_view->host_base,"
        "vtable_view->guest_base,vtable_view->byte_count)",
        "rome2_100e2460_router_host_objects_overlap("
        "state_view,vtable_view,effects,return_al_out)",
        "effects_snapshot=*effects;",
        "rome2_100e2460_router_read_selector("
        "state_view,guest_vector,&capacity,&count)",
    )
    previous = -1
    for fragment in validation_fragments:
        position = body.find(fragment)
        if position < 0:
            findings.append(f"router validation/snapshot stage changed: {fragment[:64]}")
        elif position <= previous:
            findings.append("router validation, snapshot, and selector order changed")
        previous = max(previous, position)

    preallocated_call = (
        "if(count<capacity){return"
        "rome2_port_100e2460_run_preallocated_branch("
        "state_view,vtable_view,guest_vector,guest_handler,guest_argument,"
        "&effects_snapshot.tail_effects,max_peek_calls,return_al_out);}"
    )
    zero_call = (
        "if(capacity==0){zero_effects.tail_effects=effects_snapshot.tail_effects;"
        "zero_effects.allocate=effects_snapshot.allocate;return"
        "rome2_port_100e2460_run_capacity_zero_branch("
        "state_view,vtable_view,guest_vector,guest_handler,guest_argument,"
        "&zero_effects,max_peek_calls,return_al_out);}"
    )
    growth_call = (
        "returnrome2_port_100e2460_run_growth_branch("
        "state_view,vtable_view,guest_vector,guest_handler,guest_argument,"
        "&effects_snapshot,max_peek_calls,return_al_out);"
    )
    for fragment, message in (
        (preallocated_call, "unsigned preallocated selection/delegate changed"),
        (zero_call, "capacity-zero adapter/delegate changed"),
        (growth_call, "nonzero-growth delegate changed"),
    ):
        _require_once(body, fragment, findings, message)
    positions = [body.find(preallocated_call), body.find(zero_call), body.find(growth_call)]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        findings.append("three-way route order changed")
    for delegate in (
        "rome2_port_100e2460_run_preallocated_branch(",
        "rome2_port_100e2460_run_capacity_zero_branch(",
        "rome2_port_100e2460_run_growth_branch(",
    ):
        if body.count(delegate) != 1:
            findings.append(f"route delegate must occur exactly once: {delegate[:-1]}")
    if "zero_effects.release" in body:
        findings.append("capacity-zero adapter must not expose inactive release")
    if re.search(
        r"(?:allocate|release|dispatch|peek)\s*==\s*NULL|"
        r"NULL\s*==\s*(?:[^;\n]{0,80})(?:allocate|release|dispatch|peek)",
        code,
    ):
        findings.append("router must not reject route-inactive null callbacks")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_router.h", "stdint.h", "stdio.h", "string.h"]:
        findings.append("runtime include set or order changed")
    if compact.count(FUNCTION + "(") != 5:
        findings.append("runtime router invocation boundary changed")
    for delegate in (
        "rome2_port_100e2460_run_preallocated_branch(",
        "rome2_port_100e2460_run_capacity_zero_branch(",
        "rome2_port_100e2460_run_growth_branch(",
    ):
        if delegate in compact:
            findings.append(f"runtime oracle bypasses router via delegate: {delegate[:-1]}")
    functions = (
        "rome2_test_preallocated_route",
        "rome2_test_unsigned_preallocated_route",
        "rome2_test_capacity_zero_route",
        "rome2_test_growth_route",
        "rome2_test_inactive_callbacks_are_route_specific",
        "rome2_test_drain_limit_all_routes",
        "rome2_test_invalid_allocation_partial_commits",
        "rome2_test_malformed_count_capacity_states",
        "rome2_test_descriptor_and_output_failures",
        "rome2_test_method_alias_failures",
    )
    for function in functions:
        if len(re.findall(r"\b" + re.escape(function) + r"\s*\(", code)) != 2:
            findings.append(f"runtime route/edge oracle missing or duplicated: {function}")
    for label in (
        "count below capacity selects preallocated",
        "high-bit capacity comparison is unsigned",
        "zero capacity selects allocation route",
        "equal nonzero count selects growth",
        "preallocated accepts null inactive allocation callbacks",
        "capacity-zero accepts null inactive release callback",
        "preallocated drain-limit propagation",
        "capacity-zero drain-limit propagation",
        "growth drain-limit propagation",
        "capacity-zero invalid allocation commit",
        "growth invalid allocation commit",
        "count greater than capacity rejected",
        "zero capacity nonzero count rejected",
        "output aliases state descriptor",
        "output aliases mapped state bytes",
        "method logically aliases count write",
        "method physically aliases count write",
    ):
        if text.count(label) != 1:
            findings.append(f"runtime diagnostic/coverage case changed: {label}")
    for fragment, count, message in (
        ("ROME2_100E2460_BRANCH_DRAIN_LIMIT", 3,
         "runtime all-route drain-limit coverage changed"),
        ("ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID", 2,
         "runtime partial-commit allocation coverage changed"),
        ("fixture.effects.release=NULL;", 2,
         "runtime inactive release-null oracle changed"),
        ("fixture.effects.allocate=NULL;", 1,
         "runtime inactive allocate-null oracle changed"),
        ("UINT32_C(0x80000000)", 2,
         "runtime unsigned high-bit selector oracle changed"),
    ):
        if compact.count(fragment) != count:
            findings.append(message)
    if text.count("startup 100e2460 router tests: pass") != 1:
        findings.append("runtime pass token changed")
    return sorted(set(findings))


def inspect_six_append_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_SIX_APPEND_TEST_TOKEN_SHA256:
        findings.append("six-append runtime executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_router.h", "stdint.h", "stdio.h", "string.h"]:
        findings.append("six-append runtime include set or order changed")
    if compact.count(FUNCTION + "(") != 1:
        findings.append("six-append runtime must execute only the router boundary")
    for delegate in (
        "rome2_port_100e2460_run_preallocated_branch(",
        "rome2_port_100e2460_run_capacity_zero_branch(",
        "rome2_port_100e2460_run_growth_branch(",
    ):
        if delegate in compact:
            findings.append(f"six-append oracle bypasses router via delegate: {delegate[:-1]}")
    for fragment, message in (
        ("#defineROME2_TEST_APPEND_COUNT6", "six-append count oracle changed"),
        ("#defineROME2_TEST_ALLOCATION_COUNT4", "six-append allocation count changed"),
        ("staticconstuint32_trome2_test_allocation_bytes["
         "ROME2_TEST_ALLOCATION_COUNT]={4,8,16,32};",
         "six-append allocation-size progression changed"),
        ("staticconstuint32_trome2_test_allocation_capacity["
         "ROME2_TEST_ALLOCATION_COUNT]={1,2,4,8};",
         "six-append capacity progression changed"),
        ("rome2_test_events_are_exact(", "six-append exact effect trace missing"),
        ("rome2_test_final_observations_are_exact(",
         "six-append final-state oracle missing"),
    ):
        if fragment not in compact:
            findings.append(message)
    for event, count, message in (
        ("ROME2_TEST_EVENT_ALLOCATE", 6, "six-append allocate trace changed"),
        ("ROME2_TEST_EVENT_RELEASE", 5, "six-append release trace changed"),
        ("ROME2_TEST_EVENT_DISPATCH", 8, "six-append dispatch trace changed"),
        ("ROME2_TEST_EVENT_PEEK", 8, "six-append Peek trace changed"),
    ):
        if compact.count(event) != count:
            findings.append(message)
    if text.count("startup 100e2460 router six-append tests: pass") != 1:
        findings.append("six-append runtime pass token changed")
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"router provenance is not strict UTF-8: {error}"]
    if hashlib.sha256(data).hexdigest() != EXPECTED_ROUTER_PROVENANCE_SHA256:
        findings.append("router provenance authority digest changed")
    for token in (
        "AUTHORITY_PATHS", "AUTHORITY_SHA256", "ENTRY_BYTES",
        "PREALLOCATED_BYTES", "CAPACITY_DISCRIMINATOR_BYTES",
        "CAPACITY_ZERO_BYTES", "GROWTH_SHA256", "TAIL_SHA256",
        "recovered_original_route",
        "test_all_three_branch_authorities_are_source_pinned_and_consistent",
        "test_exact_original_function_partition_and_raw_offsets",
        "test_selection_cfg_edges_and_common_tail_convergence_are_exact",
        "test_unsigned_selection_truth_table_is_exact",
        "test_canonical_main_authority_is_exact",
    ):
        if text.count(token) < 1:
            findings.append(f"router provenance token missing: {token}")
    for digest in (
        "b3d9dd5ca5e354e94fc06072e4e98c3d3312bde47a9399cd660f946fb6c2ef4c",
        "1d4d94bd1c5980f0beaae91bd9afce9a5886ee1e6761feed3bae37b66665988f",
        "810aa11e28e2eb90dda9af231f5335b9f74dac868baa57b1e3c197d949e20441",
        "eaffd54cc6a4ef00daddf63b4d6ce8ac4f6cb49807976bb0a0e5f94d09f73b0e",
    ):
        if text.count(digest) != 1:
            findings.append(f"router source-pinned branch authority changed: {digest[:16]}")
    normalized = " ".join(text.split())
    for phrase in (
        "machine and canonical-corpus facts only",
        "none is claimed to be proved by these x86 bytes",
    ):
        if phrase not in normalized:
            findings.append(f"router evidence/policy boundary missing: {phrase}")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless frozen size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    if text.count('#include "ported_100e2460_router.h"') != 1:
        findings.append("headless router include is missing or duplicated")
    if code.count(FUNCTION + "(") != 1:
        findings.append("headless must execute the router exactly once")
    for called_function, expected_count in FINAL_HEADLESS_CALLS:
        if code.count(called_function + "(") != expected_count:
            findings.append(
                "headless final composition call-site count changed: "
                f"{called_function} != {expected_count}"
            )
    compact = _compact(code)
    if compact.count(
        "++context->bad_observations;returnUINT32_C(0);"
    ) != 2:
        findings.append("headless unknown-method fallbacks must fail closed")
    for token in HEADLESS_REQUIRED_TOKENS:
        if text.count(token) != 1:
            findings.append(f"headless router boundary report changed: {token}")
    final_token_positions = [text.find(token) for token in FINAL_HEADLESS_TOKENS]
    if any(position < 0 for position in final_token_positions) or any(
        left >= right
        for left, right in zip(final_token_positions, final_token_positions[1:])
    ):
        findings.append("headless final handler token tail order changed")
    for forbidden in (
        "router=native", "initializer-router=native",
        "growth-allocator=native", "growth-release=native",
        "native-release=executed", "initializer-dispatch=native",
        "queue-drain=native", "platform-effects=executed",
    ):
        if forbidden in text:
            findings.append(f"headless falsely claims excluded native behavior: {forbidden}")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"headless directly references forbidden native API: {token}")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, flags=re.I):
            stack.append((index, bool(re.match(
                r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, flags=re.I
            ))))
        elif re.match(r"endif\s*(?:\([^)]*\))?\s*$", stripped, flags=re.I):
            if not stack:
                return None
            block_start, is_build_testing = stack.pop()
            if is_build_testing:
                return block_start, index
    return None


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_CMAKE_SIZE:
        findings.append("CMake frozen size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_CMAKE_SHA256:
        findings.append("CMake exact digest changed")
    if len(re.findall(r"^\s*add_test\s*\(", text, flags=re.I | re.M)) != (
        EXPECTED_CTEST_COUNT
    ):
        findings.append("CMake total must remain exactly 192 CTests")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped_tokens = (
        LIBRARY, TEST_TARGET, SIX_APPEND_TEST_TARGET, SUFFIX_LIBRARY,
        PLATFORM_PREFIX_LIBRARY,
        "ported_100e2460_router.h",
        "ported_100e2460_router.c", "test_startup_100e2460_router.c",
        "test_startup_100e2460_router_six_append.c",
        "test_x64_startup_100e2460_router_provenance.py",
        "test_x64_startup_100e2460_router_static_gate.py",
        "x64_startup_100e2460_router_static_gate.py", *ROUTER_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake router token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake router token escapes BUILD_TESTING: {token}")
    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("router must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("router library must not be shared")
    if f"add_executable({TEST_TARGET}" not in compact:
        findings.append("router runtime-test executable is missing")
    if f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})" not in compact:
        findings.append("dedicated router test must link only its static library")
    if f"add_executable({SIX_APPEND_TEST_TARGET}" not in compact:
        findings.append("router six-append runtime-test executable is missing")
    if f"target_link_libraries({SIX_APPEND_TEST_TARGET}PRIVATE{LIBRARY})" not in compact:
        findings.append("dedicated router six-append test must link only its static library")
    exact_dependencies = (
        f"target_link_libraries({LIBRARY}PRIVATE{PREALLOCATED_LIBRARY}"
        f"{CAPACITY_ZERO_LIBRARY}{GROWTH_LIBRARY})"
    )
    if compact.count(exact_dependencies) != 1:
        findings.append("router exact three-delegate dependency list changed")
    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands
        if LIBRARY in command
        and re.split(r"\s+", command.strip(), maxsplit=1)[0] != LIBRARY
    ]
    if sorted(consumers) != sorted((
        TEST_TARGET, SIX_APPEND_TEST_TARGET, HEADLESS, OUTER_LIBRARY,
    )):
        findings.append("router library has an unexpected consumer/dependency")
    exact_outer_dependency = (
        f"target_link_libraries({OUTER_LIBRARY}PRIVATE{LIBRARY})"
    )
    if compact.count(exact_outer_dependency) != 1:
        findings.append("outer initializer must depend only on the router")
    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append("exact headless admitted-slice link list changed")

    gate_start = compact.find("add_test(NAMEstartup_100e2460_router_static_gateCOMMAND")
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_router.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_router.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_router.c"',
        '--six-append-test"${ROME2_GUEST32_RUNTIME_DIR}/'
        'test_startup_100e2460_router_six_append.c"',
        '--router-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e2460_router_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"router static-gate argument changed: {argument[:72]}")
    for test_name in ROUTER_TEST_NAMES:
        if len(re.findall(r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact)) != 1:
            findings.append(f"router CTest missing or duplicated: {test_name}")
    fixture_blocks = (
        "set_tests_properties(startup_100e2460_router_provenancePROPERTIES"
        "FIXTURES_SETUPstartup_100e2460_router_provenance_verified)",
        "set_tests_properties(startup_100e2460_router_static_gate_unitPROPERTIES"
        "FIXTURES_SETUPstartup_100e2460_router_static_tool_verified)",
        "set_tests_properties(startup_100e2460_router_static_gatePROPERTIES"
        "FIXTURES_REQUIREDstartup_100e2460_router_static_tool_verified"
        "FIXTURES_SETUPstartup_100e2460_router_static_verified)",
        "set_tests_properties(startup_100e2460_router_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e2460_growth_branch_reload_verified;"
        "startup_100e2460_router_provenance_verified;"
        "startup_100e2460_router_static_verified\""
        "FIXTURES_SETUPstartup_100e2460_router_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e2460_router_six_append_runtime"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e2460_router_runtime_verified"
        "FIXTURES_SETUPstartup_100e2460_router_six_append_runtime_verified"
        "TIMEOUT90)",
        "set_tests_properties(startup_100e2460_router_post_pe_gatePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e2460_router_six_append_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e2460_router_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e2460_router"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e2460_router_post_verified\""
        "FIXTURES_SETUPstartup_100e2460_router_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        "entry_policy_static_verified;startup_100ed471_ordinary_lifecycle_reload_verified\""
        "TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"router fixture-chain block changed: {block[:76]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e2460_router",
        "ported_100e2460_router", "100e2460_router",
    ):
        if token in lowered:
            findings.append(f"test-only router token escaped exports: {token}")
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
    parser.add_argument("--six-append-test", type=pathlib.Path, required=True)
    parser.add_argument("--router-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        provenance = args.router_provenance.resolve(strict=True).read_bytes()
    except OSError as error:
        provenance_findings = [f"cannot read router provenance: {error}"]
    else:
        provenance_findings = inspect_provenance_bytes(provenance)
    checks = {
        "header": _inspect_path(args.header.resolve(strict=True), inspect_header_text),
        "source": _inspect_path(args.source.resolve(strict=True), inspect_source_text),
        "test": _inspect_path(args.test.resolve(strict=True), inspect_test_text),
        "six_append_test": _inspect_path(
            args.six_append_test.resolve(strict=True), inspect_six_append_test_text
        ),
        "router_provenance": provenance_findings,
        "headless": _inspect_path(args.headless.resolve(strict=True), inspect_headless_text),
        "cmake": _inspect_path(args.cmake.resolve(strict=True), inspect_cmake_text),
        "export_manifest": _inspect_path(args.export_manifest.resolve(strict=True), inspect_exports_text),
        "legacy_def": _inspect_path(args.legacy_def.resolve(strict=True), inspect_exports_text),
        "probe_def": _inspect_path(args.probe_def.resolve(strict=True), inspect_exports_text),
    }
    paths = {
        "header": args.header, "source": args.source, "test": args.test,
        "six_append_test": args.six_append_test,
        "router_provenance": args.router_provenance, "headless": args.headless,
        "cmake": args.cmake, "export_manifest": args.export_manifest,
        "legacy_def": args.legacy_def, "probe_def": args.probe_def,
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, findings in checks.items():
        total += len(findings)
        report["files"][label] = {
            "path": str(paths[label].resolve(strict=True)),
            "findings": findings,
        }
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
