#!/usr/bin/env python3
"""Fail-closed source/link gate for the complete 0x100e2460 preallocated branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e2460_run_preallocated_branch"
PREFIX_FUNCTION = "rome2_port_100e2460_append_preallocated_prefix"
LIBRARY = "rome2_startup_100e2460_preallocated_branch_runtime"
PREFIX_LIBRARY = "rome2_startup_100e2460_append_prefix_runtime"
TEST_TARGET = "rome2_startup_100e2460_preallocated_branch_tests"
HEADLESS = "rome2_headless64"
CAPACITY_ZERO_LIBRARY = "rome2_startup_100e2460_capacity_zero_branch_runtime"
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

EXPECTED_CTEST_COUNT = 194
EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_SIZE = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

HEADLESS_LINK_LIBRARIES = (
    "rome2_guest32_runtime",
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100f2750_nonalloc_runtime",
    "rome2_startup_100e8240_fastpath_runtime",
    PREFIX_LIBRARY,
    LIBRARY,
    CAPACITY_ZERO_LIBRARY,
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

EXPECTED_HEADER_TOKEN_SHA256 = (
    "751d3c71642a95a502cdb087ad7036e6882bd65257be857df6cb5a9963a5a2db"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "bbe4aa622e84059a3d4840c3431bb6834bce42e0232c7d763eb40d720db5b0db"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "cb6bdafddacd1074d67c8b59142ed3314edd5914273f466c9f191e863290170d"
)
EXPECTED_APPEND_PROVENANCE_SHA256 = (
    "b3d9dd5ca5e354e94fc06072e4e98c3d3312bde47a9399cd660f946fb6c2ef4c"
)
EXPECTED_BRANCH_PROVENANCE_SHA256 = (
    "1d4d94bd1c5980f0beaae91bd9afce9a5886ee1e6761feed3bae37b66665988f"
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
    "100d12b0",  # excluded allocator
    "100e247d",  # start of excluded growth body
    "100fcc50",  # excluded free helper
    "100fcc80",  # excluded allocation helper
    "1172f670",  # native PeekMessageW IAT cell
}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT32_C",
    "UINT64_C",
    "dispatch",
    "for",
    "if",
    "peek",
    "return",
    "sizeof",
    "switch",
    FUNCTION,
    PREFIX_FUNCTION,
    "rome2_100e2460_map_guest_status",
    "rome2_100e2460_plan_append",
    "rome2_100e2460_read_u32_le",
    "rome2_100e2460_resolve_cell",
    "rome2_100e2460_spans_overlap",
    "rome2_100e2460_validate_interval",
    "rome2_100e2460_validate_object",
}

TEST_CASE_LABELS = (
    "empty queue still probes once and returns low AL",
    "any nonzero BOOL continues through true true false",
    "false on final allowed probe succeeds with zero AL",
    "append ends exactly at vector start",
    "append begins exactly at vector end",
    "drain limit keeps committed effects",
    "one-call drain limit keeps committed effects",
    "null state view",
    "null vtable view",
    "null effects",
    "null result",
    "null dispatch adapter",
    "null peek adapter",
    "zero drain budget",
    "null state host",
    "null vtable host",
    "null vector",
    "vector end overflow",
    "vector below state view",
    "truncated vector",
    "state guest end overflow",
    "vtable guest end overflow",
    "state host end overflow",
    "vtable host end overflow",
    "growth route rejected",
    "null backing",
    "backing below state view",
    "scaled append index overflow",
    "append address overflow",
    "append cell outside state view",
    "truncated append cell",
    "append aliases vector",
    "null handler",
    "handler below state view",
    "truncated handler cell",
    "handler aliases pending count write",
    "handler aliases pending append write",
    "null vtable identity",
    "vtable plus four overflow",
    "method cell below vtable view",
    "truncated vtable method cell",
    "null method identity",
    "method cell logically aliases append write",
    "method cell physically aliases append write",
    "method cell logically aliases count write",
    "method cell physically aliases count write",
    "return byte aliases state view",
    "return byte aliases vtable view",
    "return byte aliases effects table",
    "return byte aliases state descriptor",
    "return byte aliases vtable descriptor",
    "state and vtable descriptors alias",
    "state descriptor and effects alias",
    "vtable descriptor and effects alias",
    "state descriptor aliases state bytes",
    "vtable descriptor aliases state bytes",
    "effects table aliases state bytes",
)

BRANCH_TEST_NAMES = (
    "startup_100e2460_preallocated_branch_provenance",
    "startup_100e2460_preallocated_branch_static_gate_unit",
    "startup_100e2460_preallocated_branch_static_gate",
    "startup_100e2460_preallocated_branch_runtime",
    "startup_100e2460_preallocated_branch_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e2460_preallocated_branch",
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


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_HEADER_TOKEN_SHA256:
        findings.append("header executable-token digest changed")

    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_append_prefix.h"]:
        findings.append("header must reuse only the admitted append-prefix contract")
    if compact.count(
        "#defineROME2_PORT_100E2460_PM_REMOVEUINT32_C(1)"
    ) != 1:
        findings.append("PM_REMOVE constant changed")

    required = (
        "typedefuint32_t(*rome2_100e2460_dispatch_effect_fn)("
        "void*context,rome2_guest_addr32receiver,rome2_guest_addr32method,"
        "rome2_guest_addr32argument);",
        "typedefuint32_t(*rome2_100e2460_peek_effect_fn)("
        "void*context,rome2_guest_addr32message,rome2_guest_addr32window,"
        "uint32_tfilter_min,uint32_tfilter_max,uint32_tremove_flags);",
        "typedefstructrome2_100e2460_effects{void*context;"
        "rome2_100e2460_dispatch_effect_fndispatch;"
        "rome2_100e2460_peek_effect_fnpeek;}rome2_100e2460_effects;",
        "rome2_100e2460_branch_status"
        "rome2_port_100e2460_run_preallocated_branch("
        "constrome2_guest_write_view*state_view,"
        "constrome2_guest_read_view*vtable_view,"
        "rome2_guest_addr32guest_vector,rome2_guest_addr32guest_handler,"
        "rome2_guest_addr32guest_argument,"
        "constrome2_100e2460_effects*effects,uint32_tmax_peek_calls,"
        "uint8_t*return_al_out);",
    )
    for fragment in required:
        if compact.count(fragment) != 1:
            findings.append(f"public effect/API contract changed: {fragment[:68]}")

    for status in (
        "ROME2_100E2460_BRANCH_OK=ROME2_GUEST_OK",
        "ROME2_100E2460_BRANCH_BAD_ARGUMENT=ROME2_GUEST_BAD_ARGUMENT",
        "ROME2_100E2460_BRANCH_NULL_ADDRESS=ROME2_GUEST_NULL_ADDRESS",
        "ROME2_100E2460_BRANCH_RANGE_OVERFLOW=ROME2_GUEST_RANGE_OVERFLOW",
        "ROME2_100E2460_BRANCH_OUT_OF_RANGE=ROME2_GUEST_OUT_OF_RANGE",
        "ROME2_100E2460_BRANCH_DRAIN_LIMIT=5",
        "ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID=6",
    ):
        if compact.count(status) != 1:
            findings.append(f"branch status contract changed: {status}")

    lowered = text.lower()
    for phrase in (
        "never cast",
        "native function pointer",
        "validation completes",
        "before the existing append prefix commits",
        "finite drain bound",
        "return_al_out remains unchanged",
        "safety divergences",
    ):
        if phrase not in lowered:
            findings.append(f"header safety contract is missing: {phrase}")
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
    if includes != ["ported_100e2460_preallocated_branch.h", "limits.h"]:
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
    if compact.count(
        "#defineROME2_100E2460_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)"
    ) != 1:
        findings.append("guest address-space constant changed")
    if compact.count("#defineROME2_100E2460_CELL_BYTESUINT64_C(4)") != 1:
        findings.append("guest cell width changed")
    if len(re.findall(
        r"\brome2_100e2460_branch_status\s+" + re.escape(FUNCTION) + r"\s*\(",
        code,
    )) != 1:
        findings.append("exactly one preallocated-branch definition is required")

    if compact.count(
        "if(count>=capacity){returnROME2_100E2460_BRANCH_BAD_ARGUMENT;}"
    ) != 1:
        findings.append("unsigned count < capacity branch changed")
    if compact.count(
        "displacement=(uint64_t)count*UINT64_C(4);"
    ) != 1:
        findings.append("scale-4 append calculation changed")
    if compact.count("rome2_100e2460_spans_overlap(") != 19:
        findings.append("required precommit alias-check matrix changed")

    required_alias_fragments = (
        "(uintptr_t)state_view,sizeof(*state_view),(uintptr_t)vtable_view,"
        "sizeof(*vtable_view)",
        "(uintptr_t)state_view->host_base,state_view->byte_count,"
        "(uintptr_t)return_al_out,sizeof(*return_al_out)",
        "handler_offset,ROME2_100E2460_CELL_BYTES,plan.append_offset,"
        "ROME2_100E2460_CELL_BYTES",
        "handler_offset,ROME2_100E2460_CELL_BYTES,plan.count_offset,"
        "ROME2_100E2460_CELL_BYTES",
        "(uint64_t)method_cell.value,ROME2_100E2460_CELL_BYTES,"
        "(uint64_t)state_view->guest_base+plan.append_offset,"
        "ROME2_100E2460_CELL_BYTES",
        "(uintptr_t)vtable_view->host_base+method_offset,"
        "ROME2_100E2460_CELL_BYTES,(uintptr_t)state_view->host_base+"
        "plan.count_offset,ROME2_100E2460_CELL_BYTES",
    )
    for fragment in required_alias_fragments:
        if compact.count(fragment) != 1:
            findings.append(f"required alias check changed: {fragment[:64]}")

    validation_order = (
        "status=rome2_100e2460_validate_object(state_view,sizeof(*state_view));",
        "status=rome2_100e2460_validate_object(return_al_out,"
        "sizeof(*return_al_out));",
        "if(rome2_100e2460_spans_overlap((uintptr_t)state_view,"
        "sizeof(*state_view),(uintptr_t)vtable_view,sizeof(*vtable_view))",
        "status=rome2_100e2460_validate_interval(state_view->host_base,"
        "state_view->guest_base,state_view->byte_count);",
        "status=rome2_100e2460_validate_interval(vtable_view->host_base,"
        "vtable_view->guest_base,vtable_view->byte_count);",
        "if(rome2_100e2460_spans_overlap((uintptr_t)state_view->host_base,"
        "state_view->byte_count,(uintptr_t)state_view,sizeof(*state_view))",
        "dispatch=effects->dispatch;",
        "status=rome2_100e2460_plan_append(state_view,guest_vector,&plan);",
    )
    previous = -1
    for fragment in validation_order:
        position = compact.find(fragment)
        if position < 0 or position <= previous:
            findings.append("control-object alias validation order changed")
            break
        previous = position

    required_machine_fragments = (
        "vtable_identity.value=rome2_100e2460_read_u32_le("
        "state_view->host_base+(size_t)handler_offset);",
        "if(vtable_identity.value>UINT32_MAX-UINT32_C(4)){"
        "returnROME2_100E2460_BRANCH_RANGE_OVERFLOW;}",
        "method_cell.value=vtable_identity.value+UINT32_C(4);",
        "method_identity.value=rome2_100e2460_read_u32_le("
        "vtable_view->host_base+(size_t)method_offset);",
    )
    for fragment in required_machine_fragments:
        if compact.count(fragment) != 1:
            findings.append(f"handler/vtable +4 resolution changed: {fragment[:64]}")

    prefix_call = (
        "append_status=rome2_port_100e2460_append_preallocated_prefix("
        "state_view,guest_vector,guest_handler);"
    )
    dispatch_call = (
        "dispatch_eax=dispatch(context,guest_handler,method_identity,"
        "guest_argument);"
    )
    bounded_loop = (
        "for(peek_calls=0;peek_calls<max_peek_calls;++peek_calls){"
    )
    peek_call = (
        "peek_eax=peek(context,null_identity,null_identity,UINT32_C(0),"
        "UINT32_C(0),ROME2_PORT_100E2460_PM_REMOVE);"
    )
    publish = (
        "if(peek_eax==0){*return_al_out=saved_al;"
        "returnROME2_100E2460_BRANCH_OK;}"
    )
    semantic_fragments = (
        (prefix_call, "append-prefix composition changed"),
        (
            "if(append_status!=ROME2_GUEST_OK){return"
            "rome2_100e2460_map_guest_status(append_status);}",
            "append-prefix status handling changed",
        ),
        (dispatch_call, "dispatch receiver/method/argument shape changed"),
        ("saved_al=(uint8_t)dispatch_eax;", "dispatch low-AL save changed"),
        ("null_identity.value=0;", "Peek-shaped null identities changed"),
        (bounded_loop, "finite Peek-shaped loop bound changed"),
        (peek_call, "Peek-shaped argument tuple changed"),
        (publish, "terminating-zero AL publish semantics changed"),
        (
            "returnROME2_100E2460_BRANCH_DRAIN_LIMIT;",
            "finite drain-limit result changed",
        ),
    )
    for fragment, message in semantic_fragments:
        if compact.count(fragment) != 1:
            findings.append(message)
    if compact.count("*return_al_out=") != 1:
        findings.append("return AL must be published exactly once")

    ordered = (
        "status=rome2_100e2460_plan_append(state_view,guest_vector,&plan);",
        "vtable_identity.value=rome2_100e2460_read_u32_le(",
        "method_cell.value=vtable_identity.value+UINT32_C(4);",
        "method_identity.value=rome2_100e2460_read_u32_le(",
        prefix_call,
        dispatch_call,
        "saved_al=(uint8_t)dispatch_eax;",
        bounded_loop,
        peek_call,
        publish,
        "returnROME2_100E2460_BRANCH_DRAIN_LIMIT;",
    )
    previous = -1
    for fragment in ordered:
        position = compact.find(fragment)
        if position < 0:
            continue
        if position <= previous:
            findings.append("validation/append/dispatch/drain/AL effect order changed")
            break
        previous = position
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime-test executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e2460_preallocated_branch.h",
        "stdint.h",
        "stdio.h",
        "string.h",
    ]:
        findings.append("runtime-test include set or order changed")
    for label in TEST_CASE_LABELS:
        if text.count(f'"{label}"') != 1:
            findings.append(f"required runtime case missing or duplicated: {label}")
    if code.count(FUNCTION + "(") < 5:
        findings.append("runtime test does not exercise branch outcomes")
    for token in (
        "PeekMessageW",
        "GetProcAddress",
        "LoadLibraryW",
        "100d12b0",
        "100fcc50",
        "100fcc80",
        "1172f670",
    ):
        if token.lower() in code.lower():
            findings.append(f"runtime test references excluded native behavior: {token}")
    required_oracles = {
        "expected_state=fixture.state;": 3,
        "expected_vtables=fixture.vtables;": 2,
        "memcmp(&fixture.state,&expected_state,sizeof(fixture.state))": 3,
        "memcmp(&fixture.vtables,&expected_vtables,sizeof(fixture.vtables))": 2,
        "fixture.context.trace[0]!=1": 3,
        "fixture.context.trace[index]!=2": 2,
        "result!=UINT8_C(0xc7)": 2,
        "memcmp(&fixture->state,&state_snapshot,sizeof(fixture->state))": 1,
        "fixture->context.trace_count!=0": 1,
    }
    for oracle, expected_count in required_oracles.items():
        if compact.count(oracle) != expected_count:
            findings.append(f"independent runtime oracle changed: {oracle[:64]}")
    return sorted(set(findings))


def inspect_provenance_bytes(
    data: bytes,
    *,
    expected_sha256: str,
    label: str,
) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"{label} provenance is not strict UTF-8: {error}"]
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        findings.append(f"{label} provenance authority digest changed")
    if label == "append-prefix":
        for token in (
            "FUNCTION_SHA256",
            "CONTROL_SHA256",
            "EXCLUDED_SHA256",
            "TAIL_SHA256",
            "PEEK_MESSAGE_IAT_VA",
        ):
            if text.count(token) < 1:
                findings.append(f"append-prefix provenance token missing: {token}")
    elif label == "preallocated-branch":
        for token in (
            "BASE_PROVENANCE_SHA256",
            "COUNT_DISPATCH_BYTES",
            "PUMP_SAVE_BYTES",
            "EPILOGUE_BYTES",
            "PREALLOCATED_BYTES_SHA256",
            "test_peek_message_shape_import_and_loop_polarity_are_exact",
        ):
            if text.count(token) < 1:
                findings.append(f"branch provenance token missing: {token}")
        if EXPECTED_APPEND_PROVENANCE_SHA256 not in text:
            findings.append("branch provenance no longer pins append authority")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless frozen size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    if text.count('#include "ported_100e2460_preallocated_branch.h"') != 1:
        findings.append("headless preallocated-branch include is missing or duplicated")
    if code.count(FUNCTION + "(") != 1:
        findings.append("headless must execute the preallocated branch exactly once")
    for called_function, expected_count in FINAL_HEADLESS_CALLS:
        if code.count(called_function + "(") != expected_count:
            findings.append(
                "headless final composition call-site count changed: "
                f"{called_function} != {expected_count}"
            )
    if _compact(code).count(
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
            findings.append(f"headless branch boundary report changed: {token}")
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
        "allocator=executed",
        "native-release=executed",
        "platform-effects=executed",
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
        CAPACITY_ZERO_LIBRARY,
        ROUTER_LIBRARY,
        SUFFIX_LIBRARY,
        PLATFORM_PREFIX_LIBRARY,
        TEST_TARGET,
        "ported_100e2460_preallocated_branch.h",
        "ported_100e2460_preallocated_branch.c",
        "test_startup_100e2460_preallocated_branch.c",
        "test_x64_startup_100e2460_preallocated_branch_provenance.py",
        "test_x64_startup_100e2460_preallocated_branch_static_gate.py",
        "x64_startup_100e2460_preallocated_branch_static_gate.py",
        *BRANCH_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake branch token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake branch token escapes BUILD_TESTING: {token}")

    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("preallocated branch must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("preallocated branch library must not be shared")
    if f"add_executable({TEST_TARGET}" not in compact:
        findings.append("preallocated-branch runtime-test executable is missing")
    if (
        f"target_link_libraries({LIBRARY}PRIVATE{PREFIX_LIBRARY})"
        not in compact
    ):
        findings.append("branch library must depend only on the append-prefix library")
    if f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})" not in compact:
        findings.append("dedicated branch test must link the branch library")
    if (
        f"target_link_libraries({CAPACITY_ZERO_LIBRARY}PRIVATE{LIBRARY})"
        not in compact
    ):
        findings.append(
            "capacity-zero branch must depend exactly on the preallocated branch"
        )

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands if LIBRARY in command
    ]
    if sorted(consumers) != sorted(
        (LIBRARY, TEST_TARGET, HEADLESS, CAPACITY_ZERO_LIBRARY, ROUTER_LIBRARY)
    ):
        findings.append("preallocated-branch library has an unexpected consumer/dependency")
    headless_links = [
        command for command in link_commands
        if re.split(r"\s+", command.strip(), maxsplit=1)[0] == HEADLESS
    ]
    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append("exact headless admitted-slice link list changed")
    exact_router_link = (
        f"target_link_libraries({ROUTER_LIBRARY}PRIVATE{LIBRARY}"
        f"{CAPACITY_ZERO_LIBRARY}{GROWTH_LIBRARY})"
    )
    if compact.count(exact_router_link) != 1:
        findings.append("router dependency set or order changed")
    if len(headless_links) != 1 or headless_links[0].count(LIBRARY) != 1:
        findings.append("headless must link the branch library exactly once")
    for command in link_commands:
        if LIBRARY not in command:
            continue
        consumer = re.split(r"\s+", command.strip(), maxsplit=1)[0]
        if consumer not in {
            LIBRARY, TEST_TARGET, HEADLESS, CAPACITY_ZERO_LIBRARY,
            ROUTER_LIBRARY,
        }:
            findings.append("preallocated-branch library escaped test-only consumers")
        if (
            consumer == CAPACITY_ZERO_LIBRARY
            and _compact(command)
            != f"{CAPACITY_ZERO_LIBRARY}PRIVATE{LIBRARY}"
        ):
            findings.append("capacity-zero successor dependency changed")
        if (
            consumer == ROUTER_LIBRARY
            and _compact(command) != (
                f"{ROUTER_LIBRARY}PRIVATE{LIBRARY}"
                f"{CAPACITY_ZERO_LIBRARY}{GROWTH_LIBRARY}"
            )
        ):
            findings.append("router dependency set or order changed")
        if any(token in command for token in (
            "empire_retail_bootstrap",
            "empire_bootstrap_smoke",
            "rome2_guest32_probe",
            "empire_retail64",
        )):
            findings.append("preallocated branch is linked to production/probe code")

    gate_start = compact.find(
        "add_test(NAMEstartup_100e2460_preallocated_branch_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    gate_arguments = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_preallocated_branch.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_preallocated_branch.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_preallocated_branch.c"',
        '--append-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_append_prefix_provenance.py"',
        '--branch-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    )
    for argument in gate_arguments:
        if gate_scope.count(argument) != 1:
            findings.append(f"branch static-gate argument changed: {argument[:72]}")

    for test_name in BRANCH_TEST_NAMES:
        if len(re.findall(
            r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact
        )) != 1:
            findings.append(f"branch CTest missing or duplicated: {test_name}")

    fixture_blocks = (
        "set_tests_properties(startup_100e2460_preallocated_branch_provenance"
        "PROPERTIESFIXTURES_SETUP"
        "startup_100e2460_preallocated_branch_provenance_verified)",
        "set_tests_properties(startup_100e2460_preallocated_branch_static_gate_unit"
        "PROPERTIESFIXTURES_SETUP"
        "startup_100e2460_preallocated_branch_static_tool_verified)",
        "set_tests_properties(startup_100e2460_preallocated_branch_static_gate"
        "PROPERTIESFIXTURES_REQUIRED"
        "startup_100e2460_preallocated_branch_static_tool_verified"
        "FIXTURES_SETUPstartup_100e2460_preallocated_branch_static_verified)",
        "set_tests_properties(startup_100e2460_preallocated_branch_runtime"
        "PROPERTIESFIXTURES_REQUIRED"
        '"startup_100e2460_append_prefix_reload_verified;'
        'startup_100e2460_preallocated_branch_provenance_verified;'
        'startup_100e2460_preallocated_branch_static_verified"'
        "FIXTURES_SETUPstartup_100e2460_preallocated_branch_runtime_verified"
        "TIMEOUT90)",
        "set_tests_properties(startup_100e2460_preallocated_branch_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED"
        '"startup_100e2460_preallocated_branch_runtime_verified;'
        'entry_policy_probe_pe_tool_verified"'
        "FIXTURES_SETUPstartup_100e2460_preallocated_branch_post_verified)",
        "set_tests_properties("
        "x64_bootstrap_load_after_startup_100e2460_preallocated_branch"
        "PROPERTIESFIXTURES_REQUIRED"
        '"x64_bootstrap_pre_verified;'
        'startup_100e2460_preallocated_branch_post_verified"'
        "FIXTURES_SETUPstartup_100e2460_preallocated_branch_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED"
        '"entry_policy_provenance_verified;entry_policy_static_verified;'
        'startup_100ed471_ordinary_lifecycle_reload_verified"'
        "TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"branch fixture-chain block changed: {block[:76]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(),
        LIBRARY.lower(),
        "rome2_100e2460_effects",
        "rome2_100e2460_branch_status",
        "preallocated_branch",
    ):
        if token in lowered:
            findings.append(f"test-only preallocated-branch token escaped exports: {token}")
    return sorted(set(findings))


def _inspect_path(path: pathlib.Path, inspector) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspector(text)


def _inspect_provenance_path(
    path: pathlib.Path,
    *,
    expected_sha256: str,
    label: str,
) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError as error:
        return [f"cannot read provenance authority: {error}"]
    return inspect_provenance_bytes(
        data, expected_sha256=expected_sha256, label=label
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument("--append-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--branch-provenance", type=pathlib.Path, required=True)
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
        "append_provenance": _inspect_provenance_path(
            args.append_provenance.resolve(strict=True),
            expected_sha256=EXPECTED_APPEND_PROVENANCE_SHA256,
            label="append-prefix",
        ),
        "branch_provenance": _inspect_provenance_path(
            args.branch_provenance.resolve(strict=True),
            expected_sha256=EXPECTED_BRANCH_PROVENANCE_SHA256,
            label="preallocated-branch",
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
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, findings in checks.items():
        path = getattr(args, label, None)
        if label == "append_provenance":
            path = args.append_provenance
        elif label == "branch_provenance":
            path = args.branch_provenance
        total += len(findings)
        report["files"][label] = {
            "path": str(path.resolve(strict=True)),
            "findings": findings,
        }
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
