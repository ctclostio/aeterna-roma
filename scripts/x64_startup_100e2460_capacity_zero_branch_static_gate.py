#!/usr/bin/env python3
"""Fail-closed source/link gate for the 0x100e2460 capacity-zero branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e2460_run_capacity_zero_branch"
PREALLOCATED_FUNCTION = "rome2_port_100e2460_run_preallocated_branch"
LIBRARY = "rome2_startup_100e2460_capacity_zero_branch_runtime"
PREALLOCATED_LIBRARY = "rome2_startup_100e2460_preallocated_branch_runtime"
TEST_TARGET = "rome2_startup_100e2460_capacity_zero_branch_tests"
HEADLESS = "rome2_headless64"
GROWTH_LIBRARY = "rome2_startup_100e2460_growth_branch_runtime"
ROUTER_LIBRARY = "rome2_startup_100e2460_router_runtime"
ROUTER_FUNCTION = "rome2_port_100e2460_run_router"
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
    "ce8e4580b0e294eb562307c5fe86b54b7d3d519369f2abb3568804b2684d9196"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "1c97bc652c4ac9f004f2746a85597bd5ac06b3270e03ab7545d8590c5a3cc836"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "c41dff7576f0f178fe5aeba4d6f6ea5c14a02b2655581e4d53a42cf3d172c47a"
)
EXPECTED_PREALLOCATED_PROVENANCE_SHA256 = (
    "1d4d94bd1c5980f0beaae91bd9afce9a5886ee1e6761feed3bae37b66665988f"
)
EXPECTED_CAPACITY_ZERO_PROVENANCE_SHA256 = (
    "810aa11e28e2eb90dda9af231f5335b9f74dac868baa57b1e3c197d949e20441"
)

BANNED_IDENTIFIERS = {
    "CreateProcessA",
    "CreateProcessW",
    "DispatchMessageA",
    "DispatchMessageW",
    "FreeLibrary",
    "GetMessageA",
    "GetMessageW",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "GetProcAddress",
    "HeapAlloc",
    "HeapFree",
    "LoadLibraryA",
    "LoadLibraryW",
    "PeekMessageA",
    "PeekMessageW",
    "PostMessageA",
    "PostMessageW",
    "SendMessageA",
    "SendMessageW",
    "TranslateMessage",
    "VirtualAlloc",
    "VirtualFree",
    "calloc",
    "dlopen",
    "dlsym",
    "free",
    "malloc",
    "realloc",
}

BANNED_ADDRESS_TOKENS = {
    "100d12b0",  # unrelated allocator used by the excluded sibling route
    "100fcc50",  # original free helper
    "100fcc80",  # original native allocation helper
    "1172f670",  # native PeekMessageW IAT cell
}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT32_C",
    "UINT64_C",
    "allocate",
    "for",
    "if",
    "return",
    "sizeof",
    FUNCTION,
    PREALLOCATED_FUNCTION,
    "rome2_100e2460_zero_cell_overlaps_vector_writes",
    "rome2_100e2460_zero_control_objects_overlap",
    "rome2_100e2460_zero_host_objects_overlap",
    "rome2_100e2460_zero_plan_precommit",
    "rome2_100e2460_zero_read_u32_le",
    "rome2_100e2460_zero_resolve_cell",
    "rome2_100e2460_zero_result_aliases_borrowed_cells",
    "rome2_100e2460_zero_spans_overlap",
    "rome2_100e2460_zero_validate_interval",
    "rome2_100e2460_zero_validate_object",
    "rome2_100e2460_zero_write_u32_le",
}

BRANCH_TEST_NAMES = (
    "startup_100e2460_capacity_zero_branch_provenance",
    "startup_100e2460_capacity_zero_branch_static_gate_unit",
    "startup_100e2460_capacity_zero_branch_static_gate",
    "startup_100e2460_capacity_zero_branch_runtime",
    "startup_100e2460_capacity_zero_branch_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e2460_capacity_zero_branch",
)

TEST_CASE_LABELS = (
    "capacity zero allocates before empty queue tail",
    "any nonzero Peek result continues and returns low ff",
    "false on final budget call publishes zero AL",
    "opaque zero dispatch argument is preserved",
    "unaligned allocation result is byte-addressable",
    "allocation cell ends exactly at state view end",
    "allocation cell ends exactly at vector start",
    "allocation cell begins exactly at vector end",
    "one-call drain limit",
    "null allocation result",
    "allocation result below state view",
    "allocation result guest end overflows",
    "allocation result is truncated at view end",
    "allocation result overlaps vector by one byte",
    "allocation result aliases handler cell",
    "allocation result logically aliases method cell",
    "allocation result physically aliases method cell",
    "null allocation adapter",
    "null dispatch adapter",
    "null Peek adapter",
    "zero drain budget",
    "nonzero capacity is another route",
    "zero capacity with nonzero count is unsafe",
    "zero capacity with maximum count is unsafe",
    "nonzero old backing violates ownership invariant",
    "handler aliases pending capacity write",
    "handler aliases pending count write",
    "handler aliases pending backing write",
    "method logically aliases capacity write",
    "method physically aliases count write",
    "return byte aliases state bytes",
    "return byte aliases vtable bytes",
    "return byte aliases effects table",
    "state and vtable descriptors alias",
    "state descriptor and effects alias",
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
    LIBRARY,
    GROWTH_LIBRARY,
    ROUTER_LIBRARY,
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
FINAL_HEADLESS_CALLS = (
    (ROUTER_FUNCTION, 1),
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
    compact: str,
    fragment: str,
    findings: list[str],
    message: str,
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
    if includes != ["ported_100e2460_preallocated_branch.h"]:
        findings.append("header must reuse only the admitted preallocated contract")

    required = (
        (
            "#defineROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES"
            "UINT32_C(4)",
            "four-byte allocation contract changed",
        ),
        (
            "#defineROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS"
            "UINT32_C(0)",
            "allocation-class-zero contract changed",
        ),
        (
            "typedefrome2_guest_addr32(*rome2_100e2460_allocate_effect_fn)("
            "void*context,uint32_tbyte_count,uint32_tallocation_class);",
            "total guest32 allocator adapter contract changed",
        ),
        (
            "typedefstructrome2_100e2460_capacity_zero_effects{"
            "rome2_100e2460_effectstail_effects;"
            "rome2_100e2460_allocate_effect_fnallocate;}"
            "rome2_100e2460_capacity_zero_effects;",
            "capacity-zero effect-table contract changed",
        ),
        (
            "rome2_100e2460_branch_status" + FUNCTION + "("
            "constrome2_guest_write_view*state_view,"
            "constrome2_guest_read_view*vtable_view,"
            "rome2_guest_addr32guest_vector,"
            "rome2_guest_addr32guest_handler,"
            "rome2_guest_addr32guest_argument,"
            "constrome2_100e2460_capacity_zero_effects*effects,"
            "uint32_tmax_peek_calls,uint8_t*return_al_out);",
            "public capacity-zero API contract changed",
        ),
    )
    for fragment, message in required:
        _require_once(compact, fragment, findings, message)

    lowered = text.lower()
    for phrase in (
        "total semantic adapter",
        "guest32 identity",
        "never cast",
        "may mutate only its context",
        "capacity=1, allocate(context,4,0)",
        "allocation_result_invalid",
        "backing, count, return_al_out",
        "ownership-safety",
    ):
        if phrase not in lowered:
            findings.append(f"header safety/effect contract is missing: {phrase}")
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
    if includes != ["ported_100e2460_capacity_zero_branch.h", "limits.h"]:
        findings.append("source include set or order changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")

    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden allocation/platform/dynamic identifier: {token}")
    lowered = code.lower()
    for address in sorted(BANNED_ADDRESS_TOKENS):
        if address in lowered:
            findings.append(f"excluded recovered address token: {address}")
    if re.search(r"\b(?:extern|volatile|__declspec)\b", code):
        findings.append("extern/volatile/DLL storage is forbidden")

    guest_pointer_cast = re.compile(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uint64_t|uintptr_t|intptr_t)\s*\*+\s*\)"
        r"\s*[^;\n]{0,128}\bvalue\b"
    )
    guest_native_integer = re.compile(
        r"\(\s*(?:uintptr_t|intptr_t)\s*\)\s*[^;\n]{0,128}\bvalue\b"
    )
    if guest_pointer_cast.search(code) or guest_native_integer.search(code):
        findings.append("guest identity is converted to a native pointer/address")
    if re.search(
        r"(?:uint32_t|unsigned\s+(?:int|long))\s+[A-Za-z_]\w*\s*=\s*"
        r"(?:\([^)]*\)\s*)?[^;\n]*host_base",
        code,
    ):
        findings.append("native host address is truncated to 32 bits")

    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    for call in sorted(calls - ALLOWED_CALL_EXPRESSIONS):
        findings.append(f"unexpected call expression: {call}")

    constants = (
        (
            "#defineROME2_100E2460_ZERO_ADDRESS_SPACE_SIZE"
            "UINT64_C(0x100000000)",
            "guest address-space constant changed",
        ),
        (
            "#defineROME2_100E2460_ZERO_CELL_BYTESUINT64_C(4)",
            "guest cell width changed",
        ),
    )
    for fragment, message in constants:
        _require_once(compact, fragment, findings, message)
    if len(re.findall(
        r"\brome2_100e2460_branch_status\s+" + re.escape(FUNCTION) + r"\s*\(",
        code,
    )) != 1:
        findings.append("exactly one capacity-zero branch definition is required")
    if compact.count("rome2_100e2460_zero_spans_overlap(") != 25:
        findings.append("required pre/postcommit alias-check matrix changed")

    validation_fragments = (
        (
            "if(cell.value==0){returnROME2_100E2460_BRANCH_NULL_ADDRESS;}",
            "allocation-result null validation changed",
        ),
        (
            "if(cell.value>UINT32_MAX-UINT32_C(3)){"
            "returnROME2_100E2460_BRANCH_RANGE_OVERFLOW;}",
            "allocation-result guest32 overflow validation changed",
        ),
        (
            "if(cell.value<guest_base){"
            "returnROME2_100E2460_BRANCH_OUT_OF_RANGE;}",
            "allocation-result lower-bound validation changed",
        ),
        (
            "if(offset>byte_count||ROME2_100E2460_ZERO_CELL_BYTES>"
            "byte_count-offset||offset>(uint64_t)SIZE_MAX){"
            "returnROME2_100E2460_BRANCH_OUT_OF_RANGE;}",
            "allocation-result mapped-cell/host-range validation changed",
        ),
        (
            "if(capacity!=0||count!=0||backing!=0){"
            "returnROME2_100E2460_BRANCH_BAD_ARGUMENT;}",
            "safe capacity/count/backing entry predicate changed",
        ),
        (
            "plan->capacity_offset=plan->vector_offset+UINT64_C(4);"
            "plan->count_offset=plan->vector_offset+UINT64_C(8);"
            "plan->backing_offset=plan->vector_offset+UINT64_C(12);",
            "vector field layout changed",
        ),
        (
            "plan->method_cell.value=vtable_identity.value+UINT32_C(4);",
            "handler/vtable +4 resolution changed",
        ),
        (
            "if(rome2_100e2460_zero_read_u32_le(vtable_view->host_base+"
            "(size_t)plan->method_offset)==0){"
            "returnROME2_100E2460_BRANCH_NULL_ADDRESS;}",
            "precommit method-identity validation changed",
        ),
    )
    for fragment, message in validation_fragments:
        _require_once(compact, fragment, findings, message)

    result_aliases = (
        (
            "allocation_offset,ROME2_100E2460_ZERO_CELL_BYTES,"
            "plan->vector_offset,ROME2_PORT_100E2460_VECTOR_BYTES",
            "allocation result must be disjoint from the entire vector",
        ),
        (
            "allocation_offset,ROME2_100E2460_ZERO_CELL_BYTES,"
            "plan->handler_offset,ROME2_100E2460_ZERO_CELL_BYTES",
            "allocation result must be disjoint from the handler cell",
        ),
        (
            "(uint64_t)allocation.value,ROME2_100E2460_ZERO_CELL_BYTES,"
            "(uint64_t)plan->method_cell.value,ROME2_100E2460_ZERO_CELL_BYTES",
            "allocation result must be logically disjoint from the method cell",
        ),
        (
            "(uintptr_t)state_view->host_base+allocation_offset,"
            "ROME2_100E2460_ZERO_CELL_BYTES,"
            "(uintptr_t)vtable_view->host_base+plan->method_offset,"
            "ROME2_100E2460_ZERO_CELL_BYTES",
            "allocation result must be physically disjoint from the method cell",
        ),
    )
    for fragment, message in result_aliases:
        _require_once(compact, fragment, findings, message)

    precommit_aliases = (
        (
            "rome2_100e2460_zero_control_objects_overlap("
            "state_view,vtable_view,effects,return_al_out)",
            "control-object alias validation changed",
        ),
        (
            "rome2_100e2460_zero_host_objects_overlap("
            "state_view,vtable_view,effects,return_al_out)",
            "host/control alias validation changed",
        ),
        (
            "rome2_100e2460_zero_cell_overlaps_vector_writes("
            "plan->handler_offset,plan)",
            "handler/pending-write alias validation changed",
        ),
        (
            "(uint64_t)state_view->guest_base+plan->capacity_offset",
            "method/pending-write logical alias validation changed",
        ),
        (
            "(uintptr_t)state_view->host_base+plan->capacity_offset",
            "method/pending-write physical alias validation changed",
        ),
    )
    for fragment, message in precommit_aliases:
        if fragment not in compact:
            findings.append(message)

    function_marker = "rome2_100e2460_branch_status" + FUNCTION + "("
    function_start = compact.find(function_marker)
    body = compact[function_start:] if function_start >= 0 else ""
    semantic_fragments = (
        (
            "if(allocate==NULL||effects->tail_effects.dispatch==NULL||"
            "effects->tail_effects.peek==NULL||max_peek_calls==0){"
            "returnROME2_100E2460_BRANCH_BAD_ARGUMENT;}",
            "total effect-adapter/budget validation changed",
        ),
        (
            "status=rome2_100e2460_zero_plan_precommit("
            "state_view,vtable_view,guest_vector,guest_handler,&plan);",
            "precommit plan validation changed",
        ),
        (
            "rome2_100e2460_zero_write_u32_le(state_view->host_base+"
            "(size_t)plan.capacity_offset,UINT32_C(1));",
            "capacity=1 publication changed",
        ),
        (
            "allocation=allocate(context,"
            "ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES,"
            "ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS);",
            "total allocate(4,0) invocation changed",
        ),
        (
            "status=rome2_100e2460_zero_resolve_cell("
            "state_view->guest_base,state_view->byte_count,allocation,"
            "&allocation_offset);",
            "post-effect allocation-result resolution changed",
        ),
        (
            "if(status!=ROME2_100E2460_BRANCH_OK||"
            "rome2_100e2460_zero_result_aliases_borrowed_cells("
            "state_view,vtable_view,&plan,allocation,allocation_offset)){"
            "returnROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID;}",
            "dedicated invalid-allocation partial-commit result changed",
        ),
        (
            "rome2_100e2460_zero_write_u32_le(state_view->host_base+"
            "(size_t)plan.backing_offset,allocation.value);",
            "backing publication changed",
        ),
        (
            "return" + PREALLOCATED_FUNCTION + "(state_view,vtable_view,"
            "guest_vector,guest_handler,guest_argument,"
            "&effects->tail_effects,max_peek_calls,return_al_out);",
            "preallocated branch reuse/composition changed",
        ),
    )
    for fragment, message in semantic_fragments:
        _require_once(body, fragment, findings, message)

    ordered = tuple(fragment for fragment, _message in semantic_fragments[1:])
    previous = -1
    for fragment in ordered:
        position = body.find(fragment)
        if position < 0:
            continue
        if position <= previous:
            findings.append(
                "prevalidate/capacity/allocate/validate/backing/tail effect order changed"
            )
            break
        previous = position
    if body.count("allocation=allocate(") != 1:
        findings.append("allocator effect must execute exactly once")
    if body.count("plan.capacity_offset,UINT32_C(1)") != 1:
        findings.append("capacity must be committed exactly once")
    if body.count("plan.backing_offset,allocation.value") != 1:
        findings.append("backing must be committed exactly once after validation")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if not EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime-test executable-token digest is not pinned")
    elif _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime-test executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e2460_capacity_zero_branch.h",
        "stdint.h",
        "stdio.h",
        "string.h",
    ]:
        findings.append("runtime-test include set or order changed")
    if code.count(FUNCTION + "(") < 4:
        findings.append("runtime test does not exercise enough branch outcomes")
    for label in TEST_CASE_LABELS:
        if text.count(f'"{label}"') < 1:
            findings.append(f"required runtime case missing: {label}")
    for token in (
        "PeekMessageW",
        "GetProcAddress",
        "LoadLibraryW",
        "malloc",
        "HeapAlloc",
        "100d12b0",
        "100fcc50",
        "100fcc80",
        "1172f670",
    ):
        if token.lower() in code.lower():
            findings.append(f"runtime test references excluded native behavior: {token}")
    required = (
        ("ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID", 1,
         "runtime oracle does not pin invalid-allocation status"),
        ("ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES", 2,
         "runtime oracle does not pin four-byte allocation"),
        ("ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS", 2,
         "runtime oracle does not pin allocation class zero"),
        ("allocate_calls", 4,
         "runtime oracle does not pin allocator call count"),
        ("dispatch_calls", 4,
         "runtime oracle does not pin dispatch suppression/order"),
        ("peek_calls", 4,
         "runtime oracle does not pin Peek suppression/order"),
        ("memcmp", 2,
         "runtime oracle does not compare complete state snapshots"),
    )
    for token, minimum, message in required:
        if compact.count(token) < minimum:
            findings.append(message)
    oracle_fragments = (
        (
            "context->trace[0]!=ROME2_TEST_EVENT_ALLOCATE||"
            "context->trace[1]!=ROME2_TEST_EVENT_DISPATCH",
            3,
            "runtime effect-order oracle changed",
        ),
        (
            "context->state_bytes,context->vector_offset+4)!=1",
            2,
            "runtime allocator capacity-before-effect oracle changed",
        ),
        (
            "context->state_bytes,context->vector_offset+8)!=0",
            1,
            "runtime allocator pre-count oracle changed",
        ),
        (
            "context->state_bytes,context->vector_offset+12)!=0",
            1,
            "runtime allocator pre-backing oracle changed",
        ),
        (
            "rome2_test_put_u32(expected_state.bytes,"
            "ROME2_TEST_VECTOR_OFFSET+4,1);",
            3,
            "runtime exact capacity commit oracle changed",
        ),
        (
            "rome2_test_put_u32(expected_state.bytes,"
            "ROME2_TEST_VECTOR_OFFSET+8,1);",
            2,
            "runtime exact count commit oracle changed",
        ),
        (
            "fixture->context.allocate_calls!=1||"
            "fixture->context.dispatch_calls!=0||"
            "fixture->context.peek_calls!=0",
            1,
            "runtime invalid-result callback boundary changed",
        ),
        (
            "if(result!=UINT8_C(0xc7)||",
            2,
            "runtime invalid-result output-preservation oracle changed",
        ),
        (
            "memcmp(&fixture->state,&expected_state,sizeof(fixture->state))!=0",
            1,
            "runtime invalid-result full-state oracle changed",
        ),
        (
            "fixture->context.allocate_calls!=0||"
            "fixture->context.dispatch_calls!=0||"
            "fixture->context.peek_calls!=0",
            1,
            "runtime precommit callback-suppression oracle changed",
        ),
    )
    for fragment, expected_count, message in oracle_fragments:
        if compact.count(fragment) != expected_count:
            findings.append(message)
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes, *, label: str) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"{label} provenance is not strict UTF-8: {error}"]
    expected = {
        "preallocated": EXPECTED_PREALLOCATED_PROVENANCE_SHA256,
        "capacity-zero": EXPECTED_CAPACITY_ZERO_PROVENANCE_SHA256,
    }[label]
    if hashlib.sha256(data).hexdigest() != expected:
        findings.append(f"{label} provenance authority digest changed")
    if label == "preallocated":
        for token in (
            "BASE_PROVENANCE_SHA256",
            "COUNT_DISPATCH_BYTES",
            "PUMP_SAVE_BYTES",
            "EPILOGUE_BYTES",
            "PREALLOCATED_BYTES_SHA256",
        ):
            if text.count(token) < 1:
                findings.append(f"preallocated provenance token missing: {token}")
    else:
        for token in (
            "BASE_PROVENANCE_SHA256",
            "ENTRY_PREDICATE_BYTES",
            "ZERO_DISCRIMINATOR_BYTES",
            "ZERO_BODY_BYTES",
            "ZERO_WINDOW_SHA256",
            "EXECUTED_ROUTE_SHA256",
            "ALLOCATOR_SHA256",
            "ALLOCATOR_ARGUMENT_BYTES",
            "ALLOCATOR_RESULT_BYTES",
            "ALLOCATOR_NULL_PATH_BYTES",
            "test_allocator_arguments_cdecl_cleanup_and_mutation_order_are_exact",
            "test_allocator_normal_return_and_null_throw_boundary_are_exact",
        ):
            if text.count(token) < 1:
                findings.append(f"capacity-zero provenance token missing: {token}")
        if "push zero, then size 4" not in text:
            findings.append("capacity-zero provenance no longer authenticates (4,0)")
        if "capacity=1 must precede allocator" not in text:
            findings.append("capacity-zero provenance no longer authenticates effect order")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless frozen size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    compact = _compact(code)
    if text.count('#include "ported_100e2460_capacity_zero_branch.h"') != 1:
        findings.append("headless capacity-zero include is missing or duplicated")
    if code.count(FUNCTION + "(") != 1:
        findings.append("headless must execute the capacity-zero branch exactly once")
    for called_function, expected_count in FINAL_HEADLESS_CALLS:
        if code.count(called_function + "(") != expected_count:
            findings.append(
                "headless final composition call-site count changed: "
                f"{called_function} != {expected_count}"
            )
    if compact.count(
        "++context->bad_observations;returnUINT32_C(0);"
    ) != 2:
        findings.append("headless unknown-method fallbacks must fail closed")
    for token in (
        "initializer-append=preallocated-prefix",
        "initializer-branch=preallocated-complete",
        "initializer-capacity-zero=injected-complete",
        "initializer-growth=injected-complete",
        "initializer-router=injected-complete",
        "platform-effects=not-run",
        "allocator=injected-4-byte",
        "native-allocator=not-run",
        "growth-allocator=injected-16-byte",
        "growth-release=injected-old-backing",
        "native-release=not-run",
        "initializer-dispatch=injected-complete",
        "queue-drain=injected-bounded-complete",
        "gameplay=not-linked",
        *FINAL_HEADLESS_TOKENS,
    ):
        if text.count(token) != 1:
            findings.append(f"headless capacity-zero boundary report changed: {token}")
    final_token_positions = [text.find(token) for token in FINAL_HEADLESS_TOKENS]
    if any(position < 0 for position in final_token_positions) or any(
        left >= right
        for left, right in zip(final_token_positions, final_token_positions[1:])
    ):
        findings.append("headless final handler token tail order changed")
    for forbidden in (
        "initializer-dispatch=executed",
        "initializer-dispatch=native",
        "queue-drain=executed",
        "queue-drain=native",
        "native-allocator=executed",
        "native-release=executed",
        "platform-effects=executed",
    ):
        if forbidden in text:
            findings.append(f"headless falsely claims excluded native behavior: {forbidden}")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"headless directly references forbidden native API: {token}")

    headless_semantics = (
        (
            "byte_count!=ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES",
            "headless allocator no longer observes four-byte request",
        ),
        (
            "allocation_class!="
            "ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS",
            "headless allocator no longer observes class zero",
        ),
        (
            "capacity!=1||count!=0||backing!=0",
            "headless allocator no longer observes capacity-before-allocation",
        ),
        (
            "zero_effect_context.allocation_calls!=1",
            "headless allocator call-count oracle changed",
        ),
        (
            "zero_effect_context.effect_order!=4||"
            "zero_effect_context.allocation_order!=1||"
            "zero_effect_context.dispatch_order!=2||"
            "zero_effect_context.first_peek_order!=3",
            "headless allocation/dispatch/Peek order oracle changed",
        ),
        (
            "ROME2_HEADLESS_ZERO_VECTOR_OFFSET+4)!=1",
            "headless final capacity oracle changed",
        ),
        (
            "ROME2_HEADLESS_ZERO_VECTOR_OFFSET+8)!=1",
            "headless final count oracle changed",
        ),
        (
            "ROME2_HEADLESS_ZERO_VECTOR_OFFSET+12)!="
            "zero_effect_context.expected_allocation",
            "headless final backing oracle changed",
        ),
        (
            "ROME2_HEADLESS_ZERO_ALLOCATION_OFFSET)!="
            "zero_effect_context.expected_receiver",
            "headless final element oracle changed",
        ),
    )
    for fragment, message in headless_semantics:
        if fragment not in compact:
            findings.append(message)
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
            start, is_build_testing = stack.pop()
            if is_build_testing:
                return start, index
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
        LIBRARY,
        ROUTER_LIBRARY,
        SUFFIX_LIBRARY,
        PLATFORM_PREFIX_LIBRARY,
        TEST_TARGET,
        "ported_100e2460_capacity_zero_branch.h",
        "ported_100e2460_capacity_zero_branch.c",
        "test_startup_100e2460_capacity_zero_branch.c",
        "test_x64_startup_100e2460_capacity_zero_branch_provenance.py",
        "test_x64_startup_100e2460_capacity_zero_branch_static_gate.py",
        "x64_startup_100e2460_capacity_zero_branch_static_gate.py",
        *BRANCH_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake capacity-zero token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake capacity-zero token escapes BUILD_TESTING: {token}")

    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("capacity-zero branch must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("capacity-zero branch library must not be shared")
    if f"add_executable({TEST_TARGET}" not in compact:
        findings.append("capacity-zero runtime-test executable is missing")
    if (
        f"target_link_libraries({LIBRARY}PRIVATE{PREALLOCATED_LIBRARY})"
        not in compact
    ):
        findings.append("capacity-zero library must depend only on preallocated branch")
    if f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})" not in compact:
        findings.append("dedicated capacity-zero test must link its static library")

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands if LIBRARY in command
    ]
    if sorted(consumers) != sorted((LIBRARY, TEST_TARGET, HEADLESS, ROUTER_LIBRARY)):
        findings.append("capacity-zero library has an unexpected consumer/dependency")
    for command in link_commands:
        if LIBRARY not in command:
            continue
        consumer = re.split(r"\s+", command.strip(), maxsplit=1)[0]
        if consumer not in {LIBRARY, TEST_TARGET, HEADLESS, ROUTER_LIBRARY}:
            findings.append("capacity-zero library escaped test-only consumers")
        if (
            consumer == ROUTER_LIBRARY
            and _compact(command) != (
                f"{ROUTER_LIBRARY}PRIVATE{PREALLOCATED_LIBRARY}"
                f"{LIBRARY}{GROWTH_LIBRARY}"
            )
        ):
            findings.append("router dependency set or order changed")
        if any(token in command for token in (
            "empire_retail_bootstrap",
            "empire_bootstrap_smoke",
            "rome2_guest32_probe",
            "empire_retail64",
        )):
            findings.append("capacity-zero branch is linked to production/probe code")

    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE" +
        "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append("exact headless admitted-slice link list changed")
    exact_router_link = (
        f"target_link_libraries({ROUTER_LIBRARY}PRIVATE{PREALLOCATED_LIBRARY}"
        f"{LIBRARY}{GROWTH_LIBRARY})"
    )
    if compact.count(exact_router_link) != 1:
        findings.append("router dependency set or order changed")

    gate_start = compact.find(
        "add_test(NAMEstartup_100e2460_capacity_zero_branch_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    gate_arguments = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_capacity_zero_branch.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_capacity_zero_branch.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_capacity_zero_branch.c"',
        '--preallocated-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"',
        '--capacity-zero-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_capacity_zero_branch_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    )
    for argument in gate_arguments:
        if gate_scope.count(argument) != 1:
            findings.append(f"capacity-zero static-gate argument changed: {argument[:72]}")

    for test_name in BRANCH_TEST_NAMES:
        if len(re.findall(
            r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact
        )) != 1:
            findings.append(f"capacity-zero CTest missing or duplicated: {test_name}")

    fixture_blocks = (
        "set_tests_properties(startup_100e2460_capacity_zero_branch_provenance"
        "PROPERTIESFIXTURES_SETUP"
        "startup_100e2460_capacity_zero_branch_provenance_verified)",
        "set_tests_properties(startup_100e2460_capacity_zero_branch_static_gate_unit"
        "PROPERTIESFIXTURES_SETUP"
        "startup_100e2460_capacity_zero_branch_static_tool_verified)",
        "set_tests_properties(startup_100e2460_capacity_zero_branch_static_gate"
        "PROPERTIESFIXTURES_REQUIRED"
        "startup_100e2460_capacity_zero_branch_static_tool_verified"
        "FIXTURES_SETUPstartup_100e2460_capacity_zero_branch_static_verified)",
        "set_tests_properties(startup_100e2460_capacity_zero_branch_runtime"
        "PROPERTIESFIXTURES_REQUIRED"
        '"startup_100e2460_preallocated_branch_reload_verified;'
        'startup_100e2460_capacity_zero_branch_provenance_verified;'
        'startup_100e2460_capacity_zero_branch_static_verified"'
        "FIXTURES_SETUPstartup_100e2460_capacity_zero_branch_runtime_verified"
        "TIMEOUT90)",
        "set_tests_properties(startup_100e2460_capacity_zero_branch_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED"
        '"startup_100e2460_capacity_zero_branch_runtime_verified;'
        'entry_policy_probe_pe_tool_verified"'
        "FIXTURES_SETUPstartup_100e2460_capacity_zero_branch_post_verified)",
        "set_tests_properties("
        "x64_bootstrap_load_after_startup_100e2460_capacity_zero_branch"
        "PROPERTIESFIXTURES_REQUIRED"
        '"x64_bootstrap_pre_verified;'
        'startup_100e2460_capacity_zero_branch_post_verified"'
        "FIXTURES_SETUPstartup_100e2460_capacity_zero_branch_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED"
        '"entry_policy_provenance_verified;entry_policy_static_verified;'
        'startup_100ed471_ordinary_lifecycle_reload_verified"'
        "TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"capacity-zero fixture-chain block changed: {block[:76]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(),
        LIBRARY.lower(),
        "rome2_100e2460_capacity_zero_effects",
        "rome2_100e2460_allocate_effect_fn",
        "capacity_zero_branch",
    ):
        if token in lowered:
            findings.append(f"test-only capacity-zero token escaped exports: {token}")
    return sorted(set(findings))


def _inspect_path(path: pathlib.Path, inspector) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspector(text)


def _inspect_provenance_path(path: pathlib.Path, *, label: str) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError as error:
        return [f"cannot read provenance authority: {error}"]
    return inspect_provenance_bytes(data, label=label)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument("--preallocated-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--capacity-zero-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks = {
        "header": _inspect_path(args.header.resolve(strict=True), inspect_header_text),
        "source": _inspect_path(args.source.resolve(strict=True), inspect_source_text),
        "test": _inspect_path(args.test.resolve(strict=True), inspect_test_text),
        "preallocated_provenance": _inspect_provenance_path(
            args.preallocated_provenance.resolve(strict=True), label="preallocated"
        ),
        "capacity_zero_provenance": _inspect_provenance_path(
            args.capacity_zero_provenance.resolve(strict=True), label="capacity-zero"
        ),
        "headless": _inspect_path(
            args.headless.resolve(strict=True), inspect_headless_text
        ),
        "cmake": _inspect_path(args.cmake.resolve(strict=True), inspect_cmake_text),
        "export_manifest": _inspect_path(
            args.export_manifest.resolve(strict=True), inspect_exports_text
        ),
        "legacy_def": _inspect_path(
            args.legacy_def.resolve(strict=True), inspect_exports_text
        ),
        "probe_def": _inspect_path(
            args.probe_def.resolve(strict=True), inspect_exports_text
        ),
    }
    paths = {
        "header": args.header,
        "source": args.source,
        "test": args.test,
        "preallocated_provenance": args.preallocated_provenance,
        "capacity_zero_provenance": args.capacity_zero_provenance,
        "headless": args.headless,
        "cmake": args.cmake,
        "export_manifest": args.export_manifest,
        "legacy_def": args.legacy_def,
        "probe_def": args.probe_def,
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
