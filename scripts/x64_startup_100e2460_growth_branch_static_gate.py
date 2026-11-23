#!/usr/bin/env python3
"""Fail-closed source gate for the safe 0x100e2460 growth branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e2460_run_growth_branch"
LIBRARY = "rome2_startup_100e2460_growth_branch_runtime"
TEST_TARGET = "rome2_startup_100e2460_growth_branch_tests"
HEADLESS = "rome2_headless64"
PREALLOCATED_LIBRARY = "rome2_startup_100e2460_preallocated_branch_runtime"
CAPACITY_ZERO_LIBRARY = "rome2_startup_100e2460_capacity_zero_branch_runtime"
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
EXPECTED_CTEST_COUNT = 194
EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_SIZE = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "c7b1d382ebe531307fc04dceb660efe0306a8d754149b26f05a91006cb9fd0ab"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "0a94460671f889612daa37d149ee779db2bdcfb94b35503d8cfba28497d095f0"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "ea89a7a7878b21b7f80e3a97c57d478876a7371025e3860473d365d3ef8372a2"
)
EXPECTED_GROWTH_PROVENANCE_SHA256 = (
    "eaffd54cc6a4ef00daddf63b4d6ce8ac4f6cb49807976bb0a0e5f94d09f73b0e"
)

BRANCH_TEST_NAMES = (
    "startup_100e2460_growth_branch_provenance",
    "startup_100e2460_growth_branch_static_gate_unit",
    "startup_100e2460_growth_branch_static_gate",
    "startup_100e2460_growth_branch_runtime",
    "startup_100e2460_growth_branch_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e2460_growth_branch",
)

HEADLESS_LINK_LIBRARIES = (
    "rome2_guest32_runtime",
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100f2750_nonalloc_runtime",
    "rome2_startup_100e8240_fastpath_runtime",
    "rome2_startup_100e2460_append_prefix_runtime",
    "rome2_startup_100e2460_preallocated_branch_runtime",
    "rome2_startup_100e2460_capacity_zero_branch_runtime",
    LIBRARY,
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

TEST_CASE_LABELS = (
    "capacity one grows, copies, releases, and drains",
    "capacity greater than one preserves spare cells and nonzero Peek",
    "opaque zero argument and zero low AL are preserved",
    "unaligned new span is byte-addressable",
    "new span ends exactly at state view end",
    "new span begins exactly at vector end",
    "one-call DRAIN_LIMIT keeps growth and effects committed",
    "null growth allocation result",
    "growth allocation result below state view",
    "growth allocation result guest span overflows",
    "growth allocation result is truncated at view end",
    "growth allocation result overlaps vector by one byte",
    "growth allocation result aliases old span",
    "growth allocation result aliases handler",
    "growth allocation result logically aliases method",
    "growth allocation result physically aliases method",
    "zero capacity belongs to capacity-zero route",
    "count below capacity belongs to preallocated route",
    "count above capacity is malformed growth state",
    "maximum safe capacity reaches old-span validation",
    "capacity above safe doubled-byte boundary",
    "growth vector and old span alias",
    "growth vector and method logically alias",
    "growth vector and method physically alias",
    "growth old span and method logically alias",
    "growth old span and method physically alias",
    "growth handler and method logically alias",
    "growth handler and method physically alias",
    "growth state and vtable descriptors alias",
    "growth state descriptor and effects alias",
    "growth output aliases effects table",
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
    "100fcc50",
    "100fcc80",
    "1172f670",
}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT32_C",
    "UINT64_C",
    "allocate",
    "dispatch",
    "for",
    "if",
    "peek",
    "release",
    "return",
    "sizeof",
    FUNCTION,
    "rome2_100e2460_growth_control_objects_overlap",
    "rome2_100e2460_growth_host_objects_overlap",
    "rome2_100e2460_growth_mapped_spans_alias",
    "rome2_100e2460_growth_plan_has_alias",
    "rome2_100e2460_growth_plan_precommit",
    "rome2_100e2460_growth_read_u32_le",
    "rome2_100e2460_growth_resolve_span",
    "rome2_100e2460_growth_result_aliases_plan",
    "rome2_100e2460_growth_spans_overlap",
    "rome2_100e2460_growth_validate_interval",
    "rome2_100e2460_growth_validate_object",
    "rome2_100e2460_growth_write_u32_le",
}


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _compact(text: str) -> str:
    return "".join(text.split())


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
    if includes != ["ported_100e2460_capacity_zero_branch.h"]:
        findings.append("growth header must reuse only the capacity-zero contract")

    required = (
        (
            "#defineROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASSUINT32_C(0)",
            "growth allocation-class-zero contract changed",
        ),
        (
            "#defineROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY"
            "\\UINT32_C(0x1fffffff)",
            "maximum safe old-capacity contract changed",
        ),
        (
            "typedefvoid(*rome2_100e2460_release_effect_fn)("
            "void*context,rome2_guest_addr32allocation);",
            "total guest32 release adapter contract changed",
        ),
        (
            "typedefstructrome2_100e2460_growth_effects{"
            "rome2_100e2460_effectstail_effects;"
            "rome2_100e2460_allocate_effect_fnallocate;"
            "rome2_100e2460_release_effect_fnrelease;}"
            "rome2_100e2460_growth_effects;",
            "growth effect-table contract changed",
        ),
        (
            "rome2_100e2460_branch_status" + FUNCTION + "("
            "constrome2_guest_write_view*state_view,"
            "constrome2_guest_read_view*vtable_view,"
            "rome2_guest_addr32guest_vector,"
            "rome2_guest_addr32guest_handler,"
            "rome2_guest_addr32guest_argument,"
            "constrome2_100e2460_growth_effects*effects,"
            "uint32_tmax_peek_calls,uint8_t*return_al_out);",
            "public growth API contract changed",
        ),
    )
    for fragment, message in required:
        _require_once(compact, fragment, findings, message)

    lowered = text.lower()
    for phrase in (
        "capacity > 0",
        "count == capacity",
        "uint32_max/8",
        "store doubled capacity",
        "allocate(new_capacity*4, 0)",
        "ascending order",
        "release the old backing",
        "allocation_result_invalid",
        "only the doubled-capacity store",
        "by-value guest_handler identity",
        "self-alias route is unrepresentable and excluded",
        "exclusive, non-reentrant borrow",
        "snapshotted before the first commit",
        "no native allocator",
        "guest-to-host pointer",
    ):
        if phrase not in lowered:
            findings.append(f"growth safety/effect contract is missing: {phrase}")
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
    if includes != ["ported_100e2460_growth_branch.h", "limits.h"]:
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
    if compact.count("rome2_100e2460_growth_spans_overlap(") != 14:
        findings.append("low-level logical/physical alias matrix changed")
    if compact.count("rome2_100e2460_growth_mapped_spans_alias(") != 11:
        findings.append("mapped-span pairwise alias matrix changed")
    if len(re.findall(
        r"\brome2_100e2460_branch_status\s+" + re.escape(FUNCTION) + r"\s*\(",
        code,
    )) != 1:
        findings.append("exactly one growth-branch definition is required")

    constants = (
        (
            "#defineROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE"
            "UINT64_C(0x100000000)",
            "guest address-space constant changed",
        ),
        (
            "#defineROME2_100E2460_GROWTH_CELL_BYTESUINT64_C(4)",
            "guest cell width changed",
        ),
    )
    for fragment, message in constants:
        _require_once(compact, fragment, findings, message)

    span_validation = (
        (
            "if(span_out==NULL||span_byte_count==0){"
            "returnROME2_100E2460_BRANCH_BAD_ARGUMENT;}",
            "nonempty output-span validation changed",
        ),
        (
            "if(guest_start.value==0){"
            "returnROME2_100E2460_BRANCH_NULL_ADDRESS;}",
            "full-span null validation changed",
        ),
        (
            "if(span_byte_count>ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE||"
            "span_byte_count>ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE-"
            "(uint64_t)guest_start.value){"
            "returnROME2_100E2460_BRANCH_RANGE_OVERFLOW;}",
            "full-span guest-overflow validation changed",
        ),
        (
            "if(offset>view_byte_count||span_byte_count>view_byte_count-offset||"
            "offset>(uint64_t)SIZE_MAX){"
            "returnROME2_100E2460_BRANCH_OUT_OF_RANGE;}",
            "full-span mapping/host-offset validation changed",
        ),
        (
            "span_out->host_start=(uintptr_t)host_base+(uintptr_t)offset;",
            "mapped host-span derivation changed",
        ),
    )
    for fragment, message in span_validation:
        _require_once(compact, fragment, findings, message)

    mapped_alias = (
        "returnrome2_100e2460_growth_spans_overlap("
        "first->guest_start,first->byte_count,second->guest_start,"
        "second->byte_count)||rome2_100e2460_growth_spans_overlap("
        "(uint64_t)first->host_start,first->byte_count,"
        "(uint64_t)second->host_start,second->byte_count);"
    )
    _require_once(
        compact,
        mapped_alias,
        findings,
        "mapped spans must be both logically and physically disjoint",
    )

    precommit = (
        (
            "if(plan->capacity==0||plan->count!=plan->capacity){"
            "returnROME2_100E2460_BRANCH_BAD_ARGUMENT;}",
            "capacity>0 and count==capacity entry predicate changed",
        ),
        (
            "if(plan->old_backing.value==0){"
            "returnROME2_100E2460_BRANCH_NULL_ADDRESS;}",
            "nonzero old-backing predicate changed",
        ),
        (
            "if(plan->capacity>"
            "ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY){"
            "returnROME2_100E2460_BRANCH_RANGE_OVERFLOW;}",
            "checked maximum-capacity rejection changed",
        ),
        (
            "plan->new_capacity=plan->capacity*UINT32_C(2);"
            "plan->allocation_bytes=plan->new_capacity*UINT32_C(4);",
            "checked doubled-capacity/allocation arithmetic changed",
        ),
        (
            "old_byte_count=(uint64_t)plan->count*"
            "ROME2_100E2460_GROWTH_CELL_BYTES;",
            "old mapped-span extent changed",
        ),
        (
            "plan->method_identity.value=rome2_100e2460_growth_read_u32_le("
            "vtable_view->host_base+(size_t)plan->method.view_offset);",
            "prevalidated method identity read changed",
        ),
        (
            "if(plan->method_identity.value==0){"
            "returnROME2_100E2460_BRANCH_NULL_ADDRESS;}",
            "nonzero method-identity validation changed",
        ),
    )
    for fragment, message in precommit:
        _require_once(compact, fragment, findings, message)

    plan_alias_pairs = (
        "&plan->vector,&plan->old_buffer",
        "&plan->vector,&plan->handler",
        "&plan->vector,&plan->method",
        "&plan->old_buffer,&plan->handler",
        "&plan->old_buffer,&plan->method",
        "&plan->handler,&plan->method",
    )
    for pair in plan_alias_pairs:
        if compact.count(pair) != 1:
            findings.append(f"precommit pairwise disjointness changed: {pair}")
    result_alias_pairs = (
        "allocation,&plan->vector",
        "allocation,&plan->old_buffer",
        "allocation,&plan->handler",
        "allocation,&plan->method",
    )
    for pair in result_alias_pairs:
        if compact.count(pair) != 1:
            findings.append(f"new full-span disjointness changed: {pair}")

    marker = "rome2_100e2460_branch_status" + FUNCTION + "("
    start = compact.find(marker)
    body = compact[start:] if start >= 0 else ""
    snapshot = (
        "effects_snapshot=*effects;"
        "allocate=effects_snapshot.allocate;"
        "release=effects_snapshot.release;"
        "dispatch=effects_snapshot.tail_effects.dispatch;"
        "peek=effects_snapshot.tail_effects.peek;"
        "context=effects_snapshot.tail_effects.context;"
    )
    semantic_fragments = (
        (snapshot, "callback/context snapshot changed"),
        (
            "if(allocate==NULL||release==NULL||dispatch==NULL||peek==NULL||"
            "max_peek_calls==0){returnROME2_100E2460_BRANCH_BAD_ARGUMENT;}",
            "total callback and nonzero drain-budget validation changed",
        ),
        (
            "status=rome2_100e2460_growth_plan_precommit("
            "state_view,vtable_view,guest_vector,guest_handler,&plan);",
            "precommit growth plan changed",
        ),
        (
            "rome2_100e2460_growth_write_u32_le(state_view->host_base+"
            "(size_t)plan.capacity_offset,plan.new_capacity);",
            "doubled-capacity publication changed",
        ),
        (
            "allocation=allocate(context,plan.allocation_bytes,"
            "ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS);",
            "total allocate(new_capacity*4,0) call changed",
        ),
        (
            "status=rome2_100e2460_growth_resolve_span("
            "state_view->host_base,state_view->guest_base,"
            "state_view->byte_count,allocation,plan.allocation_bytes,"
            "&allocation_span);",
            "post-effect full new-span validation changed",
        ),
        (
            "if(status!=ROME2_100E2460_BRANCH_OK||"
            "rome2_100e2460_growth_result_aliases_plan("
            "&allocation_span,&plan)){return"
            "ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID;}",
            "capacity-only invalid-allocation partial-commit result changed",
        ),
        (
            "rome2_100e2460_growth_write_u32_le(state_view->host_base+"
            "(size_t)plan.backing_offset,allocation.value);",
            "new-backing publication changed",
        ),
        (
            "for(cell_index=0;cell_index<plan.count;++cell_index){",
            "ascending exact-count copy loop changed",
        ),
        (
            "cell_value=rome2_100e2460_growth_read_u32_le("
            "state_view->host_base+(size_t)(plan.old_buffer.view_offset+"
            "cell_displacement));",
            "old-buffer copy read changed",
        ),
        (
            "rome2_100e2460_growth_write_u32_le(state_view->host_base+"
            "(size_t)(allocation_span.view_offset+cell_displacement),"
            "cell_value);",
            "new-buffer copy write changed",
        ),
        (
            "rome2_100e2460_growth_write_u32_le(state_view->host_base+"
            "(size_t)(allocation_span.view_offset+(uint64_t)plan.count*"
            "ROME2_100E2460_GROWTH_CELL_BYTES),guest_handler.value);",
            "by-value normal-route append changed",
        ),
        (
            "release(context,plan.old_backing);",
            "total release(old_backing) call changed",
        ),
        (
            "rome2_100e2460_growth_write_u32_le(state_view->host_base+"
            "(size_t)plan.count_offset,plan.count+UINT32_C(1));",
            "count increment publication changed",
        ),
        (
            "dispatch_eax=dispatch(context,guest_handler,"
            "plan.method_identity,guest_argument);",
            "dispatch receiver/method/argument shape changed",
        ),
        ("saved_al=(uint8_t)dispatch_eax;", "dispatch low-AL save changed"),
        ("null_identity.value=0;", "Peek null identities changed"),
        (
            "for(peek_calls=0;peek_calls<max_peek_calls;++peek_calls){",
            "bounded at-least-once Peek loop changed",
        ),
        (
            "peek_eax=peek(context,null_identity,null_identity,UINT32_C(0),"
            "UINT32_C(0),ROME2_PORT_100E2460_PM_REMOVE);",
            "Peek-shaped argument tuple changed",
        ),
        (
            "if(peek_eax==0){*return_al_out=saved_al;"
            "returnROME2_100E2460_BRANCH_OK;}",
            "terminating-false low-AL publication changed",
        ),
        (
            "returnROME2_100E2460_BRANCH_DRAIN_LIMIT;",
            "bounded drain-limit result changed",
        ),
    )
    for fragment, message in semantic_fragments:
        _require_once(body, fragment, findings, message)

    ordered = tuple(fragment for fragment, _message in semantic_fragments)
    previous = -1
    for fragment in ordered:
        position = body.find(fragment)
        if position < 0:
            continue
        if position <= previous:
            findings.append(
                "snapshot/prevalidate/capacity/allocate/validate/backing/copy/"
                "append/release/count/dispatch/Peek order changed"
            )
            break
        previous = position

    if body.count("allocation=allocate(") != 1:
        findings.append("allocation effect must execute exactly once")
    if body.count("release(context,plan.old_backing);") != 1:
        findings.append("old-backing release effect must execute exactly once")
    if body.count("*return_al_out=") != 1:
        findings.append("return AL must be published exactly once")
    if body.count("effects->") != 0:
        findings.append("callbacks or context are reread after the snapshot")
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
        "ported_100e2460_growth_branch.h",
        "stdint.h",
        "stdio.h",
        "string.h",
    ]:
        findings.append("runtime-test include set or order changed")
    if code.count(FUNCTION + "(") < 3:
        findings.append("runtime test does not exercise enough branch outcomes")
    for label in TEST_CASE_LABELS:
        if text.count(f'"{label}"') < 1:
            findings.append(f"required runtime case missing: {label}")
    for token in (
        "PeekMessageW",
        "GetProcAddress",
        "LoadLibraryW",
        "HeapAlloc",
        "HeapFree",
        "malloc",
        "free",
        "100fcc50",
        "100fcc80",
        "1172f670",
    ):
        if token.lower() in code.lower():
            findings.append(f"runtime test references excluded native behavior: {token}")
    required = (
        (
            "_Static_assert("
            "ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY=="
            "UINT32_C(0x1fffffff)",
            "runtime safe-capacity boundary oracle changed",
        ),
        (
            "_Static_assert(sizeof(rome2_guest_addr32)==4",
            "runtime by-value guest32 width oracle changed",
        ),
        (
            "context->trace[0]!=ROME2_TEST_EVENT_ALLOCATE||"
            "context->allocate_calls!=1||context->release_calls!=0||"
            "context->dispatch_calls!=0||context->peek_calls!=0",
            "runtime capacity-before-allocation effect oracle changed",
        ),
        (
            "byte_count!=context->expected_allocation_bytes||"
            "allocation_class!="
            "ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS",
            "runtime allocation bytes/class oracle changed",
        ),
        (
            "context->state_bytes,context->vector_offset+4)!="
            "context->new_capacity",
            "runtime doubled-capacity visibility oracle changed",
        ),
        (
            "context->state_bytes,context->vector_offset+8)!="
            "context->old_capacity",
            "runtime pre-release count oracle changed",
        ),
        (
            "context->trace[0]!=ROME2_TEST_EVENT_ALLOCATE||"
            "context->trace[1]!=ROME2_TEST_EVENT_RELEASE",
            "runtime allocate-before-release oracle changed",
        ),
        (
            "allocation.value!=context->expected_old_backing||"
            "!rome2_test_growth_storage_is_ready(context,0)",
            "runtime release(old) after copy/append oracle changed",
        ),
        (
            "context->trace[2]!=ROME2_TEST_EVENT_DISPATCH||"
            "context->allocate_calls!=1||context->release_calls!=1||"
            "context->dispatch_calls!=1||context->peek_calls!=0",
            "runtime release-before-dispatch oracle changed",
        ),
        (
            "!rome2_test_growth_storage_is_ready(context,1)",
            "runtime count-before-dispatch/Peek storage oracle changed",
        ),
        (
            "context->trace[0]!=ROME2_TEST_EVENT_ALLOCATE||"
            "context->trace[1]!=ROME2_TEST_EVENT_RELEASE||"
            "context->trace[2]!=ROME2_TEST_EVENT_DISPATCH",
            "runtime complete effect-order oracle changed",
        ),
        (
            "memcmp(&fixture.state,&expected_state,sizeof(fixture.state))!=0",
            "runtime exact successful guest-state oracle changed",
        ),
        (
            "label,status,ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID",
            "runtime invalid-allocation status oracle changed",
        ),
        (
            "rome2_test_put_u32(expected_state.bytes,"
            "ROME2_TEST_VECTOR_OFFSET+4,fixture->context.new_capacity);",
            "runtime capacity-only partial-commit oracle changed",
        ),
        (
            "fixture->context.allocate_calls!=1||"
            "fixture->context.release_calls!=0||"
            "fixture->context.dispatch_calls!=0||"
            "fixture->context.peek_calls!=0",
            "runtime invalid-result callback boundary changed",
        ),
        (
            "memcmp(fixture,&snapshot,sizeof(*fixture))!=0",
            "runtime precommit full-fixture preservation oracle changed",
        ),
        (
            "sizeof(by_value_handler)!=4||by_value_handler.value!=",
            "runtime native-stack self-alias exclusion oracle changed",
        ),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)
    exact_runtime_oracles = (
        (
            "context->trace[0]!=ROME2_TEST_EVENT_ALLOCATE||"
            "context->trace[1]!=ROME2_TEST_EVENT_RELEASE",
            2,
            "runtime allocate-before-release oracle changed",
        ),
        (
            "context->trace[0]!=ROME2_TEST_EVENT_ALLOCATE||"
            "context->trace[1]!=ROME2_TEST_EVENT_RELEASE||"
            "context->trace[2]!=ROME2_TEST_EVENT_DISPATCH",
            1,
            "runtime complete effect-order oracle changed",
        ),
        (
            "!rome2_test_growth_storage_is_ready(context,0)",
            1,
            "runtime release(old) after copy/append oracle changed",
        ),
    )
    for fragment, expected_count, message in exact_runtime_oracles:
        if compact.count(fragment) != expected_count:
            findings.append(message)
    if "source-stack self-alias route excluded by by-value contract" not in text:
        findings.append("runtime by-value source-boundary diagnostic changed")
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"growth provenance is not strict UTF-8: {error}"]
    if hashlib.sha256(data).hexdigest() != EXPECTED_GROWTH_PROVENANCE_SHA256:
        findings.append("growth provenance authority digest changed")
    for token in (
        "BASE_PROVENANCE_SHA256",
        "ENTRY_PREDICATE_BYTES",
        "GROWTH_DISCRIMINATOR_BYTES",
        "GROWTH_RESIZE_BYTES",
        "GROWTH_COPY_BYTES",
        "GROWTH_SOURCE_ALIAS_BYTES",
        "GROWTH_FREE_BYTES",
        "GROWTH_BODY_SHA256",
        "EXECUTED_GROWTH_ROUTE_SHA256",
        "ALLOCATOR_ARGUMENT_BYTES",
        "FREE_BYTES",
        "recovered_resize_machine_semantics",
        "test_doubled_capacity_signed_and_overflow_behavior_is_exact",
        "test_old_buffer_copy_loop_and_reloaded_count_are_exact",
        "test_source_alias_branch_and_old_buffer_free_are_exact",
        "test_common_dispatch_and_peek_tail_is_exact",
        "test_canonical_rows_and_files_for_relied_boundaries_are_exact",
    ):
        if text.count(token) < 1:
            findings.append(f"growth provenance token missing: {token}")
    for phrase in (
        "facts from the pinned x86 image",
        "does not declare the recovered growth route safe",
        "port decisions",
    ):
        if phrase not in text:
            findings.append(f"growth evidence/policy boundary missing: {phrase}")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless frozen size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    compact = _compact(code)
    if text.count('#include "ported_100e2460_growth_branch.h"') != 1:
        findings.append("headless growth include is missing or duplicated")
    if code.count(FUNCTION + "(") != 1:
        findings.append("headless must execute the growth branch exactly once")
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
        "initializer-growth=injected-complete",
        "initializer-router=injected-complete",
        "growth-allocator=injected-16-byte",
        "growth-release=injected-old-backing",
        "native-release=not-run",
        "platform-effects=not-run",
        "native-allocator=not-run",
        "initializer-dispatch=injected-complete",
        "queue-drain=injected-bounded-complete",
        "gameplay=not-linked",
        *FINAL_HEADLESS_TOKENS,
    ):
        if text.count(token) != 1:
            findings.append(f"headless growth boundary report changed: {token}")
    final_token_positions = [text.find(token) for token in FINAL_HEADLESS_TOKENS]
    if any(position < 0 for position in final_token_positions) or any(
        left >= right
        for left, right in zip(final_token_positions, final_token_positions[1:])
    ):
        findings.append("headless final handler token tail order changed")
    for forbidden in (
        "growth-allocator=native",
        "growth-release=native",
        "native-release=executed",
        "growth-release=executed-native",
        "initializer-dispatch=native",
        "queue-drain=native",
        "platform-effects=executed",
    ):
        if forbidden in text:
            findings.append(f"headless falsely claims excluded native behavior: {forbidden}")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"headless directly references forbidden native API: {token}")

    semantics = (
        (
            "byte_count!=ROME2_HEADLESS_GROWTH_ALLOCATION_BYTES",
            "headless growth allocation-byte oracle changed",
        ),
        (
            "allocation_class!="
            "ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS",
            "headless growth allocation-class oracle changed",
        ),
        (
            "capacity!=4||count!=2||"
            "backing!=context->expected_old_backing",
            "headless growth capacity-before-allocation oracle changed",
        ),
        (
            "context->allocation_calls!=1||context->allocation_order!=1||"
            "context->release_calls!=1||context->release_order!=2",
            "headless growth allocation/release order oracle changed",
        ),
        (
            "allocation.value!=context->expected_old_backing||"
            "capacity!=4||count!=2||"
            "backing!=context->expected_allocation",
            "headless release old-backing/state oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET+8)!="
            "context->expected_receiver",
            "headless release by-value append oracle changed",
        ),
        (
            "context->dispatch_calls!=1||context->dispatch_order!=3||"
            "context->peek_calls!=0||capacity!=4||count!=3",
            "headless release-before-count-before-dispatch oracle changed",
        ),
        (
            "context->peek_calls>2||context->first_peek_order!=4||"
            "context->effect_order!=UINT32_C(3)+context->peek_calls",
            "headless bounded Peek order oracle changed",
        ),
        (
            "growth_effect_context.effect_order!=5||"
            "growth_effect_context.allocation_order!=1||"
            "growth_effect_context.release_order!=2||"
            "growth_effect_context.dispatch_order!=3||"
            "growth_effect_context.first_peek_order!=4",
            "headless complete growth effect-order oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_VECTOR_OFFSET+4)!=4",
            "headless final growth capacity oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_VECTOR_OFFSET+8)!=3",
            "headless final growth count oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_VECTOR_OFFSET+12)!="
            "growth_effect_context.expected_allocation",
            "headless final growth backing oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET)!="
            "ROME2_HEADLESS_GROWTH_OLD_CELL_A",
            "headless final first copied-cell oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET+4)!="
            "ROME2_HEADLESS_GROWTH_OLD_CELL_B",
            "headless final second copied-cell oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET+8)!="
            "growth_effect_context.expected_receiver",
            "headless final appended-handler oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET+12)!="
            "UINT32_C(0xcccccccc)",
            "headless final spare-cell oracle changed",
        ),
    )
    for fragment, message in semantics:
        if fragment not in compact:
            findings.append(message)
    exact_headless_oracles = (
        (
            "context->allocation_calls!=1||context->allocation_order!=1||"
            "context->release_calls!=1||context->release_order!=2",
            3,
            "headless growth allocation/release order oracle changed",
        ),
        (
            "ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET+4)!="
            "ROME2_HEADLESS_GROWTH_OLD_CELL_B",
            3,
            "headless final second copied-cell oracle changed",
        ),
    )
    for fragment, expected_count, message in exact_headless_oracles:
        if compact.count(fragment) != expected_count:
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
        findings.append("CMake total must remain exactly 194 CTests")
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
        "ported_100e2460_growth_branch.h",
        "ported_100e2460_growth_branch.c",
        "test_startup_100e2460_growth_branch.c",
        "test_x64_startup_100e2460_growth_branch_provenance.py",
        "test_x64_startup_100e2460_growth_branch_static_gate.py",
        "x64_startup_100e2460_growth_branch_static_gate.py",
        *BRANCH_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake growth token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake growth token escapes BUILD_TESTING: {token}")

    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("growth branch must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("growth branch library must not be shared")
    if f"add_executable({TEST_TARGET}" not in compact:
        findings.append("growth runtime-test executable is missing")
    if f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})" not in compact:
        findings.append("dedicated growth test must link its static library")

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands if LIBRARY in command
    ]
    if sorted(consumers) != sorted((TEST_TARGET, HEADLESS, ROUTER_LIBRARY)):
        findings.append("growth library has an unexpected consumer/dependency")
    for command in link_commands:
        if LIBRARY not in command:
            continue
        consumer = re.split(r"\s+", command.strip(), maxsplit=1)[0]
        if consumer not in {TEST_TARGET, HEADLESS, ROUTER_LIBRARY}:
            findings.append("growth library escaped exact test-only consumers")
        if (
            consumer == ROUTER_LIBRARY
            and _compact(command) != (
                f"{ROUTER_LIBRARY}PRIVATE{PREALLOCATED_LIBRARY}"
                f"{CAPACITY_ZERO_LIBRARY}{LIBRARY}"
            )
        ):
            findings.append("router dependency set or order changed")
        if any(token in command for token in (
            "empire_retail_bootstrap",
            "empire_bootstrap_smoke",
            "rome2_guest32_probe",
            "empire_retail64",
        )):
            findings.append("growth branch is linked to production/probe code")
    if any(
        re.split(r"\s+", command.strip(), maxsplit=1)[0] == LIBRARY
        for command in link_commands
    ):
        findings.append("growth core must have no unnecessary link dependency")

    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append("exact headless admitted-slice link list changed")
    exact_router_link = (
        f"target_link_libraries({ROUTER_LIBRARY}PRIVATE{PREALLOCATED_LIBRARY}"
        f"{CAPACITY_ZERO_LIBRARY}{LIBRARY})"
    )
    if compact.count(exact_router_link) != 1:
        findings.append("router dependency set or order changed")

    gate_start = compact.find(
        "add_test(NAMEstartup_100e2460_growth_branch_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    gate_arguments = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_growth_branch.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_growth_branch.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_growth_branch.c"',
        '--growth-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_growth_branch_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    )
    for argument in gate_arguments:
        if gate_scope.count(argument) != 1:
            findings.append(f"growth static-gate argument changed: {argument[:72]}")

    for test_name in BRANCH_TEST_NAMES:
        if len(re.findall(
            r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact
        )) != 1:
            findings.append(f"growth CTest missing or duplicated: {test_name}")

    fixture_blocks = (
        "set_tests_properties(startup_100e2460_growth_branch_provenance"
        "PROPERTIESFIXTURES_SETUP"
        "startup_100e2460_growth_branch_provenance_verified)",
        "set_tests_properties(startup_100e2460_growth_branch_static_gate_unit"
        "PROPERTIESFIXTURES_SETUP"
        "startup_100e2460_growth_branch_static_tool_verified)",
        "set_tests_properties(startup_100e2460_growth_branch_static_gate"
        "PROPERTIESFIXTURES_REQUIRED"
        "startup_100e2460_growth_branch_static_tool_verified"
        "FIXTURES_SETUPstartup_100e2460_growth_branch_static_verified)",
        "set_tests_properties(startup_100e2460_growth_branch_runtime"
        "PROPERTIESFIXTURES_REQUIRED"
        '"startup_100e2460_capacity_zero_branch_reload_verified;'
        'startup_100e2460_growth_branch_provenance_verified;'
        'startup_100e2460_growth_branch_static_verified"'
        "FIXTURES_SETUPstartup_100e2460_growth_branch_runtime_verified"
        "TIMEOUT90)",
        "set_tests_properties(startup_100e2460_growth_branch_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED"
        '"startup_100e2460_growth_branch_runtime_verified;'
        'entry_policy_probe_pe_tool_verified"'
        "FIXTURES_SETUPstartup_100e2460_growth_branch_post_verified)",
        "set_tests_properties("
        "x64_bootstrap_load_after_startup_100e2460_growth_branch"
        "PROPERTIESFIXTURES_REQUIRED"
        '"x64_bootstrap_pre_verified;'
        'startup_100e2460_growth_branch_post_verified"'
        "FIXTURES_SETUPstartup_100e2460_growth_branch_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED"
        '"entry_policy_provenance_verified;entry_policy_static_verified;'
        'startup_100ed471_ordinary_lifecycle_reload_verified"'
        "TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"growth fixture-chain block changed: {block[:76]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(),
        LIBRARY.lower(),
        "rome2_100e2460_growth_effects",
        "rome2_100e2460_release_effect_fn",
        "growth_branch",
    ):
        if token in lowered:
            findings.append(f"test-only growth token escaped exports: {token}")
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
    parser.add_argument("--growth-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        provenance = args.growth_provenance.resolve(strict=True).read_bytes()
    except OSError as error:
        provenance_findings = [f"cannot read growth provenance: {error}"]
    else:
        provenance_findings = inspect_provenance_bytes(provenance)
    checks = {
        "header": _inspect_path(args.header.resolve(strict=True), inspect_header_text),
        "source": _inspect_path(args.source.resolve(strict=True), inspect_source_text),
        "test": _inspect_path(args.test.resolve(strict=True), inspect_test_text),
        "growth_provenance": provenance_findings,
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
        "growth_provenance": args.growth_provenance,
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
