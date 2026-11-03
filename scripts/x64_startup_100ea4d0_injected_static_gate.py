#!/usr/bin/env python3
"""Fail-closed source and containment gate for injected original 0x100ea4d0."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100ea4d0_run_injected"
ROUTER_FUNCTION = "rome2_port_100e2460_run_router"
HANDLER_8D00_FUNCTION = "rome2_port_100e8d00_run_handler_transcript"
HANDLER_85D0_FUNCTION = "rome2_port_100e85d0_normal_adapter"
HANDLER_8580_FUNCTION = "rome2_port_100e8580_run_handler_transcript"
HANDLER_9340_FUNCTION = "rome2_port_100e9340_run_handler_transcript"
HANDLER_92C0_FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
HANDLER_87A0_FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
TEST_TARGET = "rome2_startup_100ea4d0_injected_tests"
HEADLESS = "rome2_headless64"
ROUTER_LIBRARY = "rome2_startup_100e2460_router_runtime"
HANDLER_8D00_LIBRARY = "rome2_startup_100e8d00_handler_transcript_runtime"
HANDLER_85D0_LIBRARY = "rome2_startup_100e85d0_normal_adapter_runtime"
HANDLER_8580_LIBRARY = "rome2_startup_100e8580_handler_transcript_runtime"
HANDLER_9340_LIBRARY = "rome2_startup_100e9340_handler_transcript_runtime"
HANDLER_92C0_LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
HANDLER_87A0_LIBRARY = "rome2_startup_100e87a0_handler_transcript_runtime"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"

EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_ADD_TEST_COUNT = 194
EXPECTED_CMAKE_SIZE = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

# These are rotated only after the owner freezes the core/runtime corpus.
EXPECTED_HEADER_SHA256 = (
    "80669043ac53296c039bd0eb3c3e68d3da9af147646bbb86d6ec11ec45b6a09c"
)
EXPECTED_SOURCE_SHA256 = (
    "04f6953a898a29daea0afeef5907c18f254b9bc1b367a6fdc86e968b94d276c3"
)
EXPECTED_TEST_SHA256 = (
    "7112b50b018f39c16c1e82dc066b294e901354db18a4e9952c7b13c0c31604c9"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "d27a0b0fb642ef06f50a47bf310a84eee049a876b7986e07e6575065f75884ca"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "37c44b81115121ee4a21b3ecabcea378aea7645a420ab4ead3e5e7e3cda97763"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "88ad7758c68c9a7ce6794a95f25ee04d122459adcb94fdacf5a55c0cb5992528"
)
EXPECTED_EXECUTABLE_PROVENANCE_SHA256 = (
    "1726b46ce515c441b5f52096f565d5949999b5526af2643816f949bf37421e67"
)
EXPECTED_EVIDENCE_PROVENANCE_SHA256 = (
    "8cb4a70f52f3afb45a2fbf3ed60eee45548fa35ba2c7f113871e5bc1c0444b63"
)

OUTER_TEST_NAMES = (
    "startup_100ea4d0_executable_provenance",
    "startup_100ea4d0_injected_static_gate_unit",
    "startup_100ea4d0_injected_static_gate",
    "startup_100ea4d0_injected_runtime",
    "startup_100ea4d0_injected_post_pe_gate",
    "x64_bootstrap_load_after_startup_100ea4d0_injected",
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
    "rome2_startup_100e2460_growth_branch_runtime",
    ROUTER_LIBRARY,
    HANDLER_8D00_LIBRARY,
    HANDLER_85D0_LIBRARY,
    HANDLER_8580_LIBRARY,
    LIBRARY,
    HANDLER_9340_LIBRARY,
    HANDLER_92C0_LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    "rome2_startup_100ed471_ordinary_lifecycle_runtime",
)

HEADLESS_COMPLETION_TOKENS = (
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

HEADLESS_SAFETY_TOKENS = (
    "initializer-router=injected-complete",
    "growth-allocator=injected-16-byte",
    "growth-release=injected-old-backing",
    "native-release=not-run",
    "platform-effects=not-run",
    "native-allocator=not-run",
    "gameplay=not-linked",
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


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _token_digest(code: str) -> str:
    return _sha256(_compact(code).encode("utf-8"))


def _require_once(
    compact: str, fragment: str, findings: list[str], message: str
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_HEADER_SHA256:
        findings.append("header exact digest changed")
    if _token_digest(code) != EXPECTED_HEADER_TOKEN_SHA256:
        findings.append("header executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_router.h"]:
        findings.append("outer header must reuse only the router superset contract")
    for fragment, message in (
        ("#defineROME2_PORT_100EA4D0_REGISTRATION_COUNTUINT32_C(6)",
         "registration count changed"),
        ("#defineROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTESUINT32_C(4)",
         "handler allocation width changed"),
        ("#defineROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASSUINT32_C(0)",
         "handler allocation class changed"),
        ("#defineROME2_PORT_100EA4D0_ARGUMENT_OFFSETUINT32_C(0x824)",
         "derived argument offset changed"),
        ("#defineROME2_PORT_100EA4D0_VECTOR_OFFSETUINT32_C(0x854)",
         "derived vector offset changed"),
    ):
        _require_once(compact, fragment, findings, message)
    status_enum = (
        "typedefenumrome2_100ea4d0_status{"
        "ROME2_100EA4D0_OK=ROME2_GUEST_OK,"
        "ROME2_100EA4D0_BAD_ARGUMENT=ROME2_GUEST_BAD_ARGUMENT,"
        "ROME2_100EA4D0_NULL_ADDRESS=ROME2_GUEST_NULL_ADDRESS,"
        "ROME2_100EA4D0_RANGE_OVERFLOW=ROME2_GUEST_RANGE_OVERFLOW,"
        "ROME2_100EA4D0_OUT_OF_RANGE=ROME2_GUEST_OUT_OF_RANGE,"
        "ROME2_100EA4D0_ALLOCATION_RESULT_INVALID=5,"
        "ROME2_100EA4D0_ROUTER_FAILED=6,"
        "ROME2_100EA4D0_ROUTER_RETURNED_ZERO=7,"
        "ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED=8}rome2_100ea4d0_status;"
    )
    _require_once(compact, status_enum, findings, "outer status/commit contract changed")
    callback = (
        "typedefrome2_guest_addr32(*rome2_100ea4d0_handler_allocate_effect_fn)("
        "void*context,uint32_tbyte_count,uint32_tallocation_class);"
    )
    _require_once(compact, callback, findings, "typed outer allocator contract changed")
    effects = (
        "typedefstructrome2_100ea4d0_effects{void*allocation_context;"
        "rome2_100ea4d0_handler_allocate_effect_fnallocate_handler;"
        "rome2_100e2460_growth_effectsrouter_effects;}"
        "rome2_100ea4d0_effects;"
    )
    _require_once(compact, effects, findings, "full outer effects layout changed")
    declaration = (
        "rome2_100ea4d0_status" + FUNCTION + "("
        "constrome2_guest_write_view*state_view,"
        "constrome2_guest_read_view*vtable_view,"
        "rome2_guest_addr32guest_receiver,"
        "constrome2_100ea4d0_effects*effects,uint32_tmax_peek_calls);"
    )
    _require_once(compact, declaration, findings, "public outer API changed")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "receiver remains an opaque guest32 identity",
        "checked arithmetic derives",
        "full outer effects object",
        "control/host aliases",
        "total outer",
        "allocation callback",
        "nonzero peek budget",
        "complete effects",
        "snapshotted",
        "six iterations",
        "allocate_handler(allocation_context,4,0)",
        "logical or physical alias",
        "complete current capacity*4 backing span",
        "earlier handler allocation",
        "handler_graph_corrupted",
        "router success with a zero",
        "prefix-committing",
        "exclusive non-reentrant borrow",
        "no original/native allocator",
        "guest-derived function pointer",
    ):
        if phrase not in normalized:
            findings.append(f"outer safety/commit contract is missing: {phrase}")
    if re.search(r"\b(?:__declspec|dllexport|dllimport|extern)\b", code, re.I):
        findings.append("native import/export linkage is forbidden")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_SOURCE_SHA256:
        findings.append("source exact digest changed")
    if _token_digest(code) != EXPECTED_SOURCE_TOKEN_SHA256:
        findings.append("source executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100ea4d0_injected.h", "limits.h"]:
        findings.append("source include set or order changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden native allocation/platform identifier: {token}")
    if re.search(r"\b(?:extern|volatile|__declspec|__asm|asm)\b", code):
        findings.append("native/original linkage or assembly is forbidden")
    for address in ("100d12b0", "100fcc80"):
        if address in code.lower():
            findings.append(f"original allocator address must remain unlinked: {address}")
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    allowed_calls = {
        "if", "for", "return", "sizeof", "UINT32_C", "UINT64_C", FUNCTION,
        "allocate_handler", ROUTER_FUNCTION,
        "rome2_100ea4d0_write_u32_le", "rome2_100ea4d0_read_u32_le",
        "rome2_100ea4d0_spans_overlap", "rome2_100ea4d0_mapped_spans_alias",
        "rome2_100ea4d0_validate_object", "rome2_100ea4d0_validate_interval",
        "rome2_100ea4d0_resolve_span", "rome2_100ea4d0_control_objects_overlap",
        "rome2_100ea4d0_host_objects_overlap", "rome2_100ea4d0_handler_aliases",
        "rome2_100ea4d0_resolve_current_backing",
        "rome2_100ea4d0_handler_graph_is_exact",
    }
    for call in sorted(calls - allowed_calls):
        findings.append(f"unexpected call expression: {call}")
    if re.search(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uint64_t|uintptr_t|intptr_t)\s*\*+\s*\)\s*"
        r"[^;\n]{0,128}\bguest_(?:receiver|argument|vector|handler)\b",
        code,
    ):
        findings.append("guest identity is converted to a native pointer")
    if compact.count(FUNCTION + "(") != 1:
        findings.append("exactly one outer definition is required")
    if compact.count(ROUTER_FUNCTION + "(") != 1:
        findings.append("outer must invoke only one unified router call site")
    vtables = (
        "staticconstuint32_trome2_100ea4d0_vtables["
        "ROME2_PORT_100EA4D0_REGISTRATION_COUNT]={"
        "UINT32_C(0x1173f20c),UINT32_C(0x1173f214),"
        "UINT32_C(0x1173f21c),UINT32_C(0x1173f224),"
        "UINT32_C(0x1173f2ec),UINT32_C(0x1173f2dc),};"
    )
    _require_once(compact, vtables, findings, "authenticated six-vtable order changed")
    for fragment, message in (
        ("capacity=rome2_100ea4d0_read_u32_le(vector_bytes+4);"
         "if(capacity==0){*has_backing_out=0;returnROME2_100EA4D0_OK;}",
         "current backing zero-capacity route changed"),
        ("backing_byte_count=(uint64_t)capacity*UINT64_C(4);",
         "full capacity-sized backing span changed"),
        ("rome2_100ea4d0_mapped_spans_alias(handler,vector)||"
         "rome2_100ea4d0_mapped_spans_alias(handler,argument)||"
         "rome2_100ea4d0_mapped_spans_alias(handler,vtable_interval)||"
         "(has_backing&&rome2_100ea4d0_mapped_spans_alias(handler,backing))",
         "handler vector/argument/vtable/backing alias envelope changed"),
        ("for(index=0;index<earlier_count;++index){"
         "if(rome2_100ea4d0_mapped_spans_alias("
         "handler,&earlier_handlers[index])){return1;}}",
         "earlier-handler alias rejection changed"),
        ("rome2_100ea4d0_vtables[index]){return0;}",
         "post-router handler graph audit changed"),
    ):
        if fragment not in compact:
            findings.append(message)
    marker = "rome2_100ea4d0_status" + FUNCTION + "("
    start = compact.find(marker)
    body = compact[start:] if start >= 0 else ""
    ordered = (
        "rome2_100ea4d0_validate_object(state_view,sizeof(*state_view))",
        "rome2_100ea4d0_validate_object(vtable_view,sizeof(*vtable_view))",
        "rome2_100ea4d0_validate_object(effects,sizeof(*effects))",
        "rome2_100ea4d0_control_objects_overlap(state_view,vtable_view,effects)",
        "rome2_100ea4d0_validate_interval(state_view->host_base,"
        "state_view->guest_base,state_view->byte_count)",
        "rome2_100ea4d0_validate_interval(vtable_view->host_base,"
        "vtable_view->guest_base,vtable_view->byte_count)",
        "rome2_100ea4d0_host_objects_overlap(state_view,vtable_view,effects)",
        "max_peek_calls==0",
        "guest_receiver.value==0",
        "UINT32_MAX-ROME2_PORT_100EA4D0_ARGUMENT_OFFSET",
        "guest_receiver.value+ROME2_PORT_100EA4D0_ARGUMENT_OFFSET",
        "UINT32_MAX-ROME2_PORT_100EA4D0_VECTOR_OFFSET",
        "guest_receiver.value+ROME2_PORT_100EA4D0_VECTOR_OFFSET",
        "guest_vector,ROME2_PORT_100E2460_VECTOR_BYTES,&vector",
        "guest_argument,UINT64_C(4),&argument",
        "rome2_100ea4d0_mapped_spans_alias(&vector,&vtable_interval)",
        "effects_snapshot=*effects;",
        "allocate_handler=effects_snapshot.allocate_handler;",
        "allocation_context=effects_snapshot.allocation_context;",
        "allocate_handler==NULL",
        "for(registration_index=0;registration_index<"
        "ROME2_PORT_100EA4D0_REGISTRATION_COUNT;++registration_index)",
    )
    previous = -1
    for fragment in ordered:
        position = body.find(fragment)
        if position < 0:
            findings.append(f"outer validation/derivation stage changed: {fragment[:72]}")
        elif position <= previous:
            findings.append("outer validation, derivation, and snapshot order changed")
        previous = max(previous, position)
    snapshot_stages = (
        body.find("effects_snapshot=*effects;"),
        body.find("allocate_handler=effects_snapshot.allocate_handler;"),
        body.find("allocation_context=effects_snapshot.allocation_context;"),
        body.find("if(allocate_handler==NULL){returnROME2_100EA4D0_BAD_ARGUMENT;}"),
    )
    if any(position < 0 for position in snapshot_stages) or snapshot_stages != tuple(
        sorted(snapshot_stages)
    ):
        findings.append("full effects snapshot order/local callback validation changed")
    loop_fragments = (
        ("guest_handler=allocate_handler(allocation_context,"
         "ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES,"
         "ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS);",
         "total injected handler allocation call changed"),
        ("guest_handler,ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES,&handler",
         "post-allocation four-byte guest validation changed"),
        ("rome2_100ea4d0_resolve_current_backing("
         "state_view,&vector,&backing,&has_backing)",
         "post-allocation full backing validation changed"),
        ("rome2_100ea4d0_handler_aliases(&handler,&vector,&argument,"
         "&vtable_interval,&backing,has_backing,handlers,registration_index)",
         "post-allocation alias rejection changed"),
        ("handlers[registration_index]=handler;",
         "handler prefix record changed"),
        ("rome2_100ea4d0_write_u32_le(state_view->host_base+"
         "(size_t)handler.view_offset,rome2_100ea4d0_vtables[registration_index]);",
         "vtable partial commit changed"),
        ("router_al=0;", "router AL sentinel changed"),
        (ROUTER_FUNCTION + "(state_view,vtable_view,guest_vector,guest_handler,"
         "guest_argument,&effects_snapshot.router_effects,max_peek_calls,&router_al)",
         "unified router argument composition changed"),
        ("if(!rome2_100ea4d0_handler_graph_is_exact("
         "state_view,handlers,registration_index+UINT32_C(1))){"
         "returnROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED;}",
         "post-router handler graph audit changed"),
        ("if(router_status!=ROME2_100E2460_BRANCH_OK){"
         "returnROME2_100EA4D0_ROUTER_FAILED;}",
         "router failure mapping changed"),
        ("if(router_al==0){returnROME2_100EA4D0_ROUTER_RETURNED_ZERO;}",
         "zero-AL failure mapping changed"),
        ("returnROME2_100EA4D0_OK;", "six-registration success status changed"),
    )
    positions = []
    for fragment, message in loop_fragments:
        position = body.find(fragment)
        positions.append(position)
        if position < 0:
            findings.append(message)
    if any(position < 0 for position in positions) or positions != sorted(positions):
        findings.append("allocate/validate/store/router/audit order changed")
    if "effects->router_effects" in body:
        findings.append("router effects must come from the pre-effect snapshot")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_TEST_SHA256:
        findings.append("runtime exact digest changed")
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100ea4d0_injected.h", "stdint.h", "stdio.h", "string.h"
    ]:
        findings.append("runtime include set or order changed")
    if compact.count(FUNCTION + "(") != 3:
        findings.append("runtime outer invocation boundary changed")
    if ROUTER_FUNCTION + "(" in compact:
        findings.append("runtime oracle bypasses the outer composition boundary")
    for function in (
        "rome2_test_six_registration_success",
        "rome2_test_receiver_and_vector_precommit_failures",
        "rome2_test_first_allocation_result_failures",
        "rome2_test_duplicate_allocation_commits_prefix_only",
        "rome2_test_router_failure_commits_current_handler_store",
        "rome2_test_router_drain_and_zero_al_commits",
        "rome2_test_router_storage_corrupts_earlier_handler",
    ):
        if len(re.findall(r"\b" + re.escape(function) + r"\s*\(", code)) != 2:
            findings.append(f"runtime oracle missing or duplicated: {function}")
    for fragment, message in (
        ("#defineROME2_TEST_HANDLER_COUNT6", "runtime six-handler count changed"),
        ("#defineROME2_TEST_BACKING_COUNT4", "runtime backing progression changed"),
        ("staticconstuint32_trome2_test_vtables[ROME2_TEST_HANDLER_COUNT]={"
         "UINT32_C(0x1173f20c),UINT32_C(0x1173f214),"
         "UINT32_C(0x1173f21c),UINT32_C(0x1173f224),"
         "UINT32_C(0x1173f2ec),UINT32_C(0x1173f2dc),};",
         "runtime vtable order oracle changed"),
        ("staticconstuint32_trome2_test_methods[ROME2_TEST_HANDLER_COUNT]={"
         "UINT32_C(0x100e8d00),UINT32_C(0x100e85d0),"
         "UINT32_C(0x100e8580),UINT32_C(0x100e9340),"
         "UINT32_C(0x100e92c0),UINT32_C(0x100e87a0),};",
         "runtime method order oracle changed"),
        ("staticconstuint32_twanted_events[25]={1,2,4,5,1,2,3,4,5,"
         "1,2,3,4,5,1,4,5,1,2,3,4,5,1,4,5,};",
         "runtime six-registration effect trace changed"),
        ("fixture.context.handler_calls!=6", "runtime six allocations changed"),
        ("fixture.context.backing_calls!=4", "runtime growth count changed"),
        ("fixture.context.release_calls!=3", "runtime release count changed"),
        ("fixture.context.dispatch_calls!=6", "runtime dispatch count changed"),
        ("fixture.context.peek_calls!=6", "runtime Peek count changed"),
        ("!rome2_test_prefix_is_exact(&fixture.context,6)",
         "runtime final prefix oracle changed"),
    ):
        if fragment not in compact:
            findings.append(message)
    labels = (
        "six registrations and exact effect trace",
        "handler allocation/store/dispatch order",
        "null receiver is precommit",
        "receiver-derived vector overflow is precommit",
        "vector logical vtable alias is precommit",
        "vector physical vtable alias is precommit",
        "zero Peek budget is precommit",
        "null outer allocator is precommit",
        "null handler allocation result",
        "handler allocation aliases vector",
        "handler allocation aliases argument cell",
        "handler allocation logically aliases vtable",
        "handler allocation physically aliases vtable",
        "duplicate allocation preserves prior prefix",
        "handler allocation aliases active backing",
        "router failure keeps allocation and vtable store",
        "invalid active backing fails after allocation before store",
        "missing method fails after vtable store",
        "router drain limit keeps current commits",
        "zero router AL replaces original null trap",
        "router storage alias triggers handler graph corruption status",
    )
    for label in labels:
        if text.count(label) != 1:
            findings.append(f"runtime semantic coverage case changed: {label}")
    for status, minimum, message in (
        ("ROME2_100EA4D0_ALLOCATION_RESULT_INVALID", 8,
         "allocation-result partial-commit coverage weakened"),
        ("ROME2_100EA4D0_ROUTER_FAILED", 3,
         "router failure partial-commit coverage weakened"),
        ("ROME2_100EA4D0_ROUTER_RETURNED_ZERO", 1,
         "zero-router-AL coverage weakened"),
        ("ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED", 1,
         "handler graph audit coverage weakened"),
    ):
        if compact.count(status) < minimum:
            findings.append(message)
    if text.count("startup 100ea4d0 injected tests: pass") != 1:
        findings.append("runtime pass token changed")
    return sorted(set(findings))


def inspect_executable_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"executable provenance is not strict UTF-8: {error}"]
    if _sha256(data) != EXPECTED_EXECUTABLE_PROVENANCE_SHA256:
        findings.append("executable provenance authority digest changed")
    for token in (
        "AUTHORITY", "AUTHORITY_SHA256", "ARGUMENT_OFFSET", "VECTOR_OFFSET",
        "DERIVATION_BYTES", "ROUTER_PRELUDE_BYTES", "VTABLE_SLOT4_TARGETS",
        "VTABLE_RECORD_BYTES", "VTABLE_RECORD_RAW_OFFSETS",
        "load_pinned_authority", "test_evidence_authority_is_source_pinned",
        "test_exact_body_and_checked_receiver_derivations_are_pinned",
        "test_six_allocate_store_router_sequences_are_exact",
        "test_vtable_slot_plus_four_targets_are_exact",
        "test_canonical_entry_and_policy_boundary_are_exact",
    ):
        if text.count(token) < 1:
            findings.append(f"executable provenance token missing: {token}")
    for authority in (
        EXPECTED_EVIDENCE_PROVENANCE_SHA256,
        "582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3",
        "8db72408000081c754080000",
        "56508bcf",
        "100E8D00", "100E85D0", "100E8580", "100E9340", "100E92C0",
        "100E87A0",
    ):
        if text.count(authority) < 1:
            findings.append(f"executable provenance authority changed: {authority[:16]}")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "source-pins the earlier evidence-only authority",
        "six original allocator calls",
        "receiver-derived argument/vector values",
        "router-call order",
    ):
        if phrase not in normalized:
            findings.append(f"executable evidence/port-policy boundary missing: {phrase}")
    for phrase in (
        "does not prove the x64 port's injected callbacks",
        "port decisions",
    ):
        if text.lower().count(phrase) != 2:
            findings.append(f"executable evidence/port-policy boundary missing: {phrase}")
    return sorted(set(findings))


def inspect_evidence_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"evidence provenance is not strict UTF-8: {error}"]
    if _sha256(data) != EXPECTED_EVIDENCE_PROVENANCE_SHA256:
        findings.append("evidence provenance authority digest changed")
    for token in (
        "EA4D0_VA", "EA4D0_SIZE", "EA4D0_SHA256", "ALLOCATOR_VA",
        "ALLOCATOR_WRAPPER_BYTES", "CORE_ALLOCATOR_VA", "INITIALIZER_VA",
        "VTABLE_IMMEDIATES", "ALLOC_CALL_OFFSETS", "INITIALIZER_CALL_OFFSETS",
        "PUSH4_OFFSETS", "NULL_CHECK_OFFSETS", "VTABLE_STORE_OFFSETS",
        "test_canonical_decompilation_is_pinned", "test_allocator_wrapper_is_pinned",
        "test_entry_window_is_exact",
        "test_every_invocation_allocates_and_normal_return_builds_six_nodes",
    ):
        if text.count(token) < 1:
            findings.append(f"evidence provenance token missing: {token}")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "admits no read-only executable port",
        "every invocation reaches the 4-byte allocator",
        "six times",
        "future executable port cannot be introduced silently",
    ):
        if phrase not in normalized:
            findings.append(f"evidence authority boundary missing: {phrase}")
    return sorted(set(findings))


def _assigned_calls(code: str, function: str) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    prefix = re.compile(
        r"\b(?P<status>[A-Za-z_]\w*)\s*=\s*" + re.escape(function) + r"\s*\("
    )
    for match in prefix.finditer(code):
        depth = 1
        index = match.end()
        while index < len(code) and depth:
            if code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
            index += 1
        semicolon = re.match(r"\s*;", code[index:]) if depth == 0 else None
        if semicolon is not None:
            matches.append((match.group("status"), index + semicolon.end()))
    return matches


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    if len(text.encode("utf-8")) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless exact size changed")
    if _sha256(text.encode("utf-8")) != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    include_order = (
        '#include "ported_100e2460_router.h"\n'
        '#include "ported_100e8d00_handler_transcript.h"\n'
        '#include "ported_100e85d0_normal_adapter.h"\n'
        '#include "ported_100e8580_handler_transcript.h"\n'
        '#include "ported_100e9340_handler_transcript.h"\n'
        '#include "ported_100e92c0_handler_transcript.h"\n'
        '#include "ported_100e87a0_handler_transcript.h"\n'
        '#include "ported_100ea4d0_injected.h"'
    )
    if text.count(include_order) != 1:
        findings.append("headless include order must end router, handlers, outer")
    prefix_include = text.find(
        '#include "ported_100df270_platform_prefix_transcript.h"'
    )
    suffix_include = text.find(
        '#include "ported_100df270_suffix_transcript.h"'
    )
    router_include = text.find('#include "ported_100e2460_router.h"')
    if not (0 <= prefix_include < suffix_include < router_include):
        findings.append(
            "headless platform-prefix/suffix includes must precede router composition"
        )
    for function, count in (
        (ROUTER_FUNCTION, 1),
        (HANDLER_8D00_FUNCTION, 2),
        (HANDLER_85D0_FUNCTION, 2),
        (HANDLER_8580_FUNCTION, 2),
        (FUNCTION, 1),
        (HANDLER_9340_FUNCTION, 2),
        (HANDLER_92C0_FUNCTION, 2),
        (HANDLER_87A0_FUNCTION, 2),
        (SUFFIX_FUNCTION, 0),
        (PREFIX_FUNCTION, 0),
        (PARENT_FUNCTION, 1),
        (LIFECYCLE_FUNCTION, 1),
    ):
        if code.count(function + "(") != count:
            findings.append(
                f"headless composition call-site count changed: {function} != {count}"
            )
    outer_calls = _assigned_calls(code, FUNCTION)
    if len(outer_calls) != 1:
        findings.append("headless outer result must be captured once")
    else:
        status_name, call_end = outer_calls[0]
        suffix = code[call_end:call_end + 1200]
        if re.search(
            r"\bif\s*\([^)]*\b" + re.escape(status_name)
            + r"\s*!=\s*ROME2_100EA4D0_OK\b",
            suffix,
            flags=re.S,
        ) is None:
            findings.append("headless must reject a non-OK outer result")
    for token in HEADLESS_COMPLETION_TOKENS + HEADLESS_SAFETY_TOKENS:
        if text.count(token) != 1:
            findings.append(f"headless outer boundary report changed: {token}")
    completion_positions = [text.find(token) for token in HEADLESS_COMPLETION_TOKENS]
    if any(position < 0 for position in completion_positions) or any(
        left >= right
        for left, right in zip(completion_positions, completion_positions[1:])
    ):
        findings.append("headless final handler/suffix/platform-prefix token order changed")
    if "0x600000b1" in code.lower():
        findings.append("headless unknown-method fallback must fail closed")
    for forbidden in (
        "initializer-100ea4d0=native", "initializer-100ea4d0=not-linked",
        "initializer-handler-100e8d00=native",
        "initializer-handler-100e85d0=native",
        "initializer-handler-100e8580=native",
        "initializer-handler-100e9340=native",
        "initializer-handler-100e92c0=native",
        "initializer-handler-100e87a0=native",
        "startup-100df270-suffix=native",
        "startup-100df270-suffix=not-linked",
        "startup-100df270-platform-prefix=native",
        "startup-100df270-platform-prefix=not-linked",
        "native-release=executed", "platform-effects=executed",
    ):
        if forbidden in text:
            findings.append(f"headless falsely claims excluded behavior: {forbidden}")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"headless directly references forbidden native API: {token}")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    found: list[tuple[int, int]] = []
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
                found.append((block_start, index))
    if stack or len(found) != 1:
        return None
    return found[0]


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_CMAKE_SIZE:
        findings.append("CMake exact size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_CMAKE_SHA256:
        findings.append("CMake exact digest changed")
    if len(re.findall(r"\badd_test\s*\(", text)) != EXPECTED_CMAKE_ADD_TEST_COUNT:
        findings.append("CMake add_test declaration count must remain 194")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped_tokens = (
        LIBRARY, TEST_TARGET, "ported_100ea4d0_injected.h",
        "ported_100ea4d0_injected.c", "test_startup_100ea4d0_injected.c",
        "test_x64_startup_100ea4d0_executable_provenance.py",
        "test_x64_startup_100ea4d0_evidence_provenance.py",
        "test_x64_startup_100ea4d0_injected_static_gate.py",
        "x64_startup_100ea4d0_injected_static_gate.py", *OUTER_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake outer token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake outer token escapes BUILD_TESTING: {token}")
    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)
    exact_library = (
        f'add_library({LIBRARY}STATIC'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.c")'
    )
    if compact.count(exact_library) != 1:
        findings.append("outer must be an exact BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("outer library must not be shared")
    for fragment, message in (
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "outer C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})", "outer hardening changed"),
        (f"target_include_directories({LIBRARY}PUBLIC"
         '"${ROME2_GUEST32_RUNTIME_DIR}"'
         '"${ROME2_GUEST32_PORTED_DIR}")', "outer include containment changed"),
        (f"target_link_libraries({LIBRARY}PRIVATE{ROUTER_LIBRARY})",
         "outer must depend only on the unified router"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ea4d0_injected.c")',
         "outer runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated outer test must link only its static library"),
    ):
        if compact.count(fragment) != 1:
            findings.append(message)
    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands
        if LIBRARY in command
        and re.split(r"\s+", command.strip(), maxsplit=1)[0] != LIBRARY
    ]
    if sorted(consumers) != sorted((TEST_TARGET, HEADLESS)):
        findings.append("outer library has an unexpected consumer/dependency")
    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append(
            "exact headless link tail must end outer, 9340, 92c0, 87a0, "
            "suffix, platform-prefix"
        )

    gate_start = compact.find("add_test(NAMEstartup_100ea4d0_injected_static_gateCOMMAND")
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ea4d0_injected.c"',
        '--executable-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100ea4d0_executable_provenance.py"',
        '--evidence-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100ea4d0_evidence_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"outer static-gate argument changed: {argument[:76]}")
    for test_name in OUTER_TEST_NAMES:
        if len(re.findall(r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact)) != 1:
            findings.append(f"outer CTest missing or duplicated: {test_name}")
    fixture_blocks = (
        "set_tests_properties(startup_100ea4d0_executable_provenancePROPERTIES"
        "FIXTURES_SETUPstartup_100ea4d0_executable_provenance_verified)",
        "set_tests_properties(startup_100ea4d0_injected_static_gate_unitPROPERTIES"
        "FIXTURES_SETUPstartup_100ea4d0_injected_static_tool_verified)",
        "set_tests_properties(startup_100ea4d0_injected_static_gatePROPERTIES"
        "FIXTURES_REQUIREDstartup_100ea4d0_injected_static_tool_verified"
        "FIXTURES_SETUPstartup_100ea4d0_injected_static_verified)",
        "set_tests_properties(startup_100ea4d0_injected_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e8580_handler_transcript_reload_verified;"
        "startup_100ea4d0_executable_provenance_verified;"
        "startup_100ea4d0_injected_static_verified\""
        "FIXTURES_SETUPstartup_100ea4d0_injected_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100ea4d0_injected_post_pe_gatePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100ea4d0_injected_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100ea4d0_injected_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100ea4d0_injected"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100ea4d0_injected_post_verified\""
        "FIXTURES_SETUPstartup_100ea4d0_injected_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        "entry_policy_static_verified;"
        "startup_100ed471_ordinary_lifecycle_reload_verified\""
        "TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"outer fixture-chain block changed: {block[:78]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100ea4d0_injected",
        "ported_100ea4d0_injected", "100ea4d0_injected",
    ):
        if token in lowered:
            findings.append(f"test-only outer token escaped exports: {token}")
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
    parser.add_argument("--executable-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-provenance", type=pathlib.Path, required=True)
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
        "headless": _inspect_path(args.headless.resolve(strict=True), inspect_headless_text),
        "cmake": _inspect_path(args.cmake.resolve(strict=True), inspect_cmake_text),
        "export_manifest": _inspect_path(
            args.export_manifest.resolve(strict=True), inspect_exports_text
        ),
        "legacy_def": _inspect_path(args.legacy_def.resolve(strict=True), inspect_exports_text),
        "probe_def": _inspect_path(args.probe_def.resolve(strict=True), inspect_exports_text),
    }
    provenance_paths = (
        ("executable_provenance", args.executable_provenance,
         inspect_executable_provenance_bytes),
        ("evidence_provenance", args.evidence_provenance,
         inspect_evidence_provenance_bytes),
    )
    for label, path, inspector in provenance_paths:
        try:
            data = path.resolve(strict=True).read_bytes()
        except OSError as error:
            checks[label] = [f"cannot read {label}: {error}"]
        else:
            checks[label] = inspector(data)
    paths = {
        "header": args.header, "source": args.source, "test": args.test,
        "executable_provenance": args.executable_provenance,
        "evidence_provenance": args.evidence_provenance,
        "headless": args.headless, "cmake": args.cmake,
        "export_manifest": args.export_manifest, "legacy_def": args.legacy_def,
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
