#!/usr/bin/env python3
"""Fail-closed source and integration gate for original handler 0x100e87a0."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
LIBRARY = "rome2_startup_100e87a0_handler_transcript_runtime"
TEST_TARGET = "rome2_startup_100e87a0_handler_transcript_tests"
HEADLESS = "rome2_headless64"
PREDECESSOR_LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"

EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_ADD_TEST_COUNT = 192
EXPECTED_CMAKE_SIZE = 182959
EXPECTED_CMAKE_SHA256 = (
    "3e7dda18a4e170f7d68a73f121ff5f4a40e58c854047e730a9608984b9589674"
)

EXPECTED_HEADER_SHA256 = (
    "a5383761f2e0c332cc14655c2f51b7fe750d8429988a289aad32367d8435cc9f"
)
EXPECTED_SOURCE_SHA256 = (
    "2c0563c48b80d587ad3405f80203ed2d6a79258e9cde562286e786e6f50004ac"
)
EXPECTED_TEST_SHA256 = (
    "601e1466be3bbb590c4c64c8286d889373ce69aa7983d6ac19fe3031399fbab3"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "7d3fe9ac2d60b5e7f85163cb4961784e02dac4e9e0d31fc29bdda9d37936d97d"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "b7c2c79ffe1d358a38fd8c6c9500c73f80e66d4d77eaf35e03995552b72d2b62"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "a91a452eb31db36d3ecfcf48ad0e37fd1a5f0c3e080fe4965f2df18cd2757f0e"
)
EXPECTED_PROVENANCE_SHA256 = (
    "20973ba2220e109b7ff2a3a042c8c8b2f827371f64d35492416bb4f350aa9865"
)

TRANSCRIPT_TEST_NAMES = (
    "startup_100e87a0_handler_transcript_provenance",
    "startup_100e87a0_handler_transcript_static_gate_unit",
    "startup_100e87a0_handler_transcript_static_gate",
    "startup_100e87a0_handler_transcript_runtime",
    "startup_100e87a0_handler_transcript_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e87a0_handler_transcript",
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
    "rome2_startup_100e2460_router_runtime",
    "rome2_startup_100e8d00_handler_transcript_runtime",
    "rome2_startup_100e85d0_normal_adapter_runtime",
    "rome2_startup_100e8580_handler_transcript_runtime",
    "rome2_startup_100ea4d0_injected_runtime",
    "rome2_startup_100e9340_handler_transcript_runtime",
    PREDECESSOR_LIBRARY,
    LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    "rome2_startup_100ed471_ordinary_lifecycle_runtime",
)
PREDECESSOR_RELOAD_FIXTURE = (
    "startup_100e92c0_handler_transcript_reload_verified"
)
OWN_RELOAD_FIXTURE = "startup_100e87a0_handler_transcript_reload_verified"
TERMINAL_RELOAD_FIXTURE = (
    "startup_100ed471_ordinary_lifecycle_reload_verified"
)

STATUS_TOKENS = (
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

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "EnterCriticalSection", "FreeLibrary",
    "GetCurrentThreadId", "GetMessageA", "GetMessageW", "GetProcAddress",
    "GlobalMemoryStatusEx", "HeapAlloc", "HeapFree", "LoadLibraryA",
    "LoadLibraryW", "PeekMessageA", "PeekMessageW", "PostMessageA",
    "PostMessageW", "RegOpenKeyExW", "SendMessageA", "SendMessageW",
    "SteamInternal_ContextInit", "TlsAlloc", "TlsFree", "TlsGetValue",
    "TlsSetValue", "TranslateMessage", "VirtualAlloc", "VirtualFree",
    "calloc", "dlopen", "dlsym", "free", "malloc", "realloc", "system",
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
    compact: str,
    fragment: str,
    findings: list[str],
    message: str,
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def _banned_findings(code: str) -> list[str]:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    findings = [
        f"forbidden native/allocator/platform identifier: {identifier}"
        for identifier in sorted(BANNED_IDENTIFIERS & identifiers)
    ]
    if re.search(r"\b_?DAT_[0-9A-Fa-f]+\b", code):
        findings.append("original process-global identifier is forbidden")
    return findings


def _function_body(code: str, function: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(function)}\s*\([^;]*?\)\s*\{{", code, flags=re.S
    )
    if match is None:
        return None
    opening = code.find("{", match.start())
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[opening + 1:index]
    return None


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
    if includes != ["ported_100f1c10_triplet.h"]:
        findings.append("header must reuse only the bounded guest write-view contract")

    required_macros = (
        ("#defineROME2_PORT_100E87A0_ALUINT8_C(1)", "AL constant changed"),
        ("#defineROME2_PORT_100E87A0_LISTENER_BYTESUINT32_C(4)",
         "four-byte listener allocation changed"),
        ("#defineROME2_PORT_100E87A0_ALLOCATION_CLASSUINT32_C(0)",
         "allocation class changed"),
        ("#defineROME2_PORT_100E87A0_LISTENER_VTABLEUINT32_C(0x1173ff28)",
         "listener vtable identity changed"),
        ("#defineROME2_PORT_100E87A0_LOG_LEVELUINT32_C(6)",
         "FaceFX log level changed"),
        ("#defineROME2_PORT_100E87A0_POLICY_TYPEUINT32_C(2)",
         "policy type changed"),
        ("#defineROME2_PORT_100E87A0_POLICY_TRACK_ALLOCATIONSUINT32_C(1)",
         "policy tracking flag changed"),
        ("#defineROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY"
         "UINT32_C(0x100d12b0)", "policy allocator identity changed"),
        ("#defineROME2_PORT_100E87A0_POLICY_ALLOCATE_DEBUG_IDENTITY"
         "UINT32_C(0x100e2190)", "policy debug allocator identity changed"),
        ("#defineROME2_PORT_100E87A0_POLICY_FREE_IDENTITY"
         "UINT32_C(0x100e21a0)", "policy free identity changed"),
    )
    for fragment, message in required_macros:
        _require_once(compact, fragment, findings, message)

    status_type = (
        "typedefenumrome2_100e87a0_status{"
        "ROME2_100E87A0_OK=ROME2_GUEST_OK,"
        "ROME2_100E87A0_BAD_ARGUMENT=ROME2_GUEST_BAD_ARGUMENT,"
        "ROME2_100E87A0_NULL_ADDRESS=ROME2_GUEST_NULL_ADDRESS,"
        "ROME2_100E87A0_RANGE_OVERFLOW=ROME2_GUEST_RANGE_OVERFLOW,"
        "ROME2_100E87A0_OUT_OF_RANGE=ROME2_GUEST_OUT_OF_RANGE,"
        "ROME2_100E87A0_ALLOCATION_RESULT_INVALID=5}rome2_100e87a0_status;"
    )
    _require_once(compact, status_type, findings, "prefix-commit status mapping changed")
    policy_type = (
        "typedefstructrome2_100e87a0_memory_policy{"
        "uint32_tallocation_type;uint32_ttrack_allocations;"
        "uint32_tallocate_identity;uint32_tallocate_debug_identity;"
        "uint32_tfree_identity;}rome2_100e87a0_memory_policy;"
    )
    _require_once(compact, policy_type, findings, "typed five-field policy changed")
    _require_once(
        compact,
        "_Static_assert(sizeof(rome2_100e87a0_memory_policy)==20U,"
        ");",
        findings,
        "20-byte portable policy invariant changed",
    )
    callbacks = (
        "typedefrome2_guest_addr32(*rome2_100e87a0_allocate_effect_fn)("
        "void*context,uint32_tbyte_count,uint32_tallocation_class);",
        "typedefvoid(*rome2_100e87a0_publish_effect_fn)("
        "void*context,rome2_guest_addr32listener);",
        "typedefvoid(*rome2_100e87a0_facefx_startup_effect_fn)("
        "void*context,rome2_100e87a0_memory_policypolicy,"
        "rome2_guest_addr32listener,uint32_tlog_level);",
    )
    for index, callback in enumerate(callbacks, 1):
        _require_once(compact, callback, findings, f"typed effect callback {index} changed")
    effects_type = (
        "typedefstructrome2_100e87a0_effects{"
        "rome2_100e87a0_allocate_effect_fnallocate_listener;"
        "rome2_100e87a0_publish_effect_fnpublish_listener;"
        "rome2_100e87a0_facefx_startup_effect_fnstartup_facefx;"
        "void*context;}rome2_100e87a0_effects;"
    )
    _require_once(compact, effects_type, findings, "complete typed effects layout changed")
    declaration = (
        "rome2_100e87a0_status" + FUNCTION + "("
        "constrome2_guest_write_view*state_view,"
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100e87a0_effects*effects,uint8_t*return_al_out);"
    )
    _require_once(compact, declaration, findings, "public bounded transcript API changed")
    findings.extend(_banned_findings(code))
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
    if includes != [
        "ported_100e87a0_handler_transcript.h", "limits.h", "stddef.h",
        "stdint.h",
    ]:
        findings.append("source include containment changed")
    findings.extend(_banned_findings(code))
    if "#pragmacomment(lib" in compact.lower():
        findings.append("native library autolinking is forbidden")

    validations = (
        ("status=rome2_100e87a0_validate_object(state_view,sizeof(*state_view));",
         "state descriptor validation changed"),
        ("status=rome2_100e87a0_validate_object(effects,sizeof(*effects));",
         "effects descriptor validation changed"),
        ("status=rome2_100e87a0_validate_object(return_al_out,"
         "sizeof(*return_al_out));", "AL output validation changed"),
        ("(uintptr_t)state_view%_Alignof(rome2_guest_write_view)!=0U||"
         "(uintptr_t)effects%_Alignof(rome2_100e87a0_effects)!=0U||"
         "rome2_100e87a0_control_objects_overlap(state_view,effects,return_al_out)",
         "control alignment/pairwise-alias validation changed"),
        ("state_snapshot=*state_view;", "complete state-view snapshot changed"),
        ("status=rome2_100e87a0_validate_interval(&state_snapshot);",
         "state guest/host interval validation changed"),
        ("rome2_100e87a0_host_interval_overlaps_controls(&state_snapshot,"
         "state_view,effects,return_al_out)",
         "state host/control physical-alias validation changed"),
        ("effects_snapshot=*effects;", "complete effects snapshot changed"),
        ("effects_snapshot.allocate_listener==NULL||"
         "effects_snapshot.publish_listener==NULL||"
         "effects_snapshot.startup_facefx==NULL||"
         "effects_snapshot.context==NULL", "total callback/context validation changed"),
    )
    for fragment, message in validations:
        if fragment not in compact:
            findings.append(message)

    interval_fragments = (
        "view->host_base==NULL",
        "view->byte_count>ROME2_100E87A0_ADDRESS_SPACE_SIZE||"
        "(uint64_t)view->guest_base+view->byte_count>"
        "ROME2_100E87A0_ADDRESS_SPACE_SIZE",
        "view->byte_count-UINT64_C(1)>(uint64_t)(UINTPTR_MAX-host_address)",
        "listener.value==0",
        "ROME2_PORT_100E87A0_LISTENER_BYTES>"
        "ROME2_100E87A0_ADDRESS_SPACE_SIZE-(uint64_t)listener.value",
        "listener.value<view->guest_base",
        "offset>view->byte_count||ROME2_PORT_100E87A0_LISTENER_BYTES>"
        "view->byte_count-offset||offset>(uint64_t)SIZE_MAX",
    )
    for fragment in interval_fragments:
        if fragment not in compact:
            findings.append(f"guest/host span validation changed: {fragment[:64]}")

    policy = (
        "policy.allocation_type=ROME2_PORT_100E87A0_POLICY_TYPE;"
        "policy.track_allocations=ROME2_PORT_100E87A0_POLICY_TRACK_ALLOCATIONS;"
        "policy.allocate_identity=ROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY;"
        "policy.allocate_debug_identity="
        "ROME2_PORT_100E87A0_POLICY_ALLOCATE_DEBUG_IDENTITY;"
        "policy.free_identity=ROME2_PORT_100E87A0_POLICY_FREE_IDENTITY;"
        "returnpolicy;"
    )
    _require_once(compact, policy, findings, "exact typed FaceFX policy changed")
    route = (
        "(void)guest_receiver;(void)guest_argument;"
        "policy=rome2_100e87a0_policy();"
        "listener=effects_snapshot.allocate_listener(effects_snapshot.context,"
        "ROME2_PORT_100E87A0_LISTENER_BYTES,"
        "ROME2_PORT_100E87A0_ALLOCATION_CLASS);"
        "if(listener.value!=0){"
        "status=rome2_100e87a0_resolve_listener(&state_snapshot,listener,"
        "&listener_span);"
        "if(status!=ROME2_100E87A0_OK){"
        "returnROME2_100E87A0_ALLOCATION_RESULT_INVALID;}"
        "rome2_100e87a0_write_u32_le(state_snapshot.host_base+"
        "(size_t)listener_span.view_offset,"
        "ROME2_PORT_100E87A0_LISTENER_VTABLE);}"
        "effects_snapshot.publish_listener(effects_snapshot.context,listener);"
        "effects_snapshot.startup_facefx(effects_snapshot.context,policy,"
        "listener,ROME2_PORT_100E87A0_LOG_LEVEL);"
        "*return_al_out=ROME2_PORT_100E87A0_AL;"
        "returnROME2_100E87A0_OK;"
    )
    if route not in compact:
        findings.append("allocate/store/publish/FaceFX/AL prefix-commit route changed")
    for fragment, expected, message in (
        ("effects_snapshot.allocate_listener(", 1, "allocator effect count changed"),
        ("effects_snapshot.publish_listener(", 1, "publication effect count changed"),
        ("effects_snapshot.startup_facefx(", 1, "FaceFX effect count changed"),
        ("*return_al_out=ROME2_PORT_100E87A0_AL;", 1, "AL publication count changed"),
    ):
        if compact.count(fragment) != expected:
            findings.append(message)

    snapshot_position = compact.find("effects_snapshot=*effects;")
    allocation_position = compact.find("effects_snapshot.allocate_listener(")
    store_position = compact.find("rome2_100e87a0_write_u32_le(", allocation_position)
    publish_position = compact.find("effects_snapshot.publish_listener(")
    startup_position = compact.find("effects_snapshot.startup_facefx(")
    output_position = compact.find("*return_al_out=ROME2_PORT_100E87A0_AL;")
    if not (
        0 <= snapshot_position < allocation_position < store_position <
        publish_position < startup_position < output_position
    ):
        findings.append("snapshot/effect/store/publication order changed")
    main_body = _function_body(code, FUNCTION)
    if main_body is None:
        findings.append("public transcript definition is missing")
    elif "effects->" in main_body or "state_view->" in main_body:
        findings.append("callbacks and state must be read only from snapshots")
    if code.count("guest_receiver") != 2 or code.count("guest_argument") != 2:
        findings.append("receiver and argument must remain opaque and ignored")
    if re.search(
        r"\([^)]*\*[^)]*\)\s*(?:guest_receiver|guest_argument|listener)", code
    ):
        findings.append("guest identities must never be cast to host pointers")
    for target in (
        "100d12b0", "100e2190", "100e21a0", "100fcc80", "100fcc50",
        "10ed67a0", "100d6560",
    ):
        if re.search(rf"\b(?:FUN_|decomp_fn_)?{target}\s*\(", code, flags=re.I):
            findings.append(f"recovered/native call is forbidden: {target}")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_TEST_SHA256:
        findings.append("runtime oracle exact digest changed")
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime oracle executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e87a0_handler_transcript.h", "stdint.h", "stdio.h",
        "string.h",
    ]:
        findings.append("runtime oracle include containment changed")
    findings.extend(_banned_findings(code))

    required = (
        ("#defineTEST_MEMORY_BYTES160U", "runtime bounded memory size changed"),
        ("#defineTEST_GUEST_BASEUINT32_C(0x24000000)",
         "runtime guest base changed"),
        ("#defineTEST_OUTPUT_SENTINELUINT8_C(0xa6)",
         "runtime unpublished-AL sentinel changed"),
        ("byte_count!=UINT32_C(4)||allocation_class!=UINT32_C(0)",
         "runtime allocator argument oracle changed"),
        ("*context->return_al!=TEST_OUTPUT_SENTINEL",
         "callbacks must observe unpublished AL"),
        ("test_read_u32_le(context->memory->bytes+offset)!="
         "UINT32_C(0x1173ff28)", "runtime vtable-before-publication oracle changed"),
        ("policy.allocation_type!=UINT32_C(2)||"
         "policy.track_allocations!=UINT32_C(1)||"
         "policy.allocate_identity!=UINT32_C(0x100d12b0)||"
         "policy.allocate_debug_identity!=UINT32_C(0x100e2190)||"
         "policy.free_identity!=UINT32_C(0x100e21a0)||"
         "level!=UINT32_C(6)", "runtime exact FaceFX policy oracle changed"),
        ("fixture.context.allocation_result.value=UINT32_C(0);"
         "fixture.view.byte_count=UINT64_C(0);",
         "runtime null-allocation normal route changed"),
        ("fixture.view.guest_base=UINT32_C(0xfffffffc);"
         "fixture.view.byte_count=UINT64_C(4);"
         "fixture.context.allocation_result.value=UINT32_C(0xfffffffc);",
         "runtime guest address-space end case changed"),
        ("fixture.context.mutate_caller_effects=1;",
         "runtime complete-effects snapshot mutant changed"),
        ("TEST_GUEST_BASE-UINT32_C(1),"
         "TEST_GUEST_BASE+TEST_MEMORY_BYTES-UINT32_C(2),"
         "TEST_GUEST_BASE+TEST_MEMORY_BYTES,UINT32_C(0xfffffffe)",
         "runtime four invalid allocation results changed"),
        ("status==ROME2_100E87A0_ALLOCATION_RESULT_INVALID",
         "runtime allocation-result status oracle changed"),
        ("fixture.context.allocation_calls==UINT32_C(1)&&"
         "fixture.context.publication_calls==UINT32_C(0)&&"
         "fixture.context.startup_calls==UINT32_C(0)&&"
         "fixture.context.effect_order==UINT32_C(1)",
         "runtime allocation-only prefix oracle changed"),
        ("&fixture.effects,(uint8_t*)&fixture.effects);",
         "runtime effects/output alias case changed"),
        ("(constrome2_100e87a0_effects*)&fixture.view",
         "runtime view/effects alias case changed"),
        ("fixture.view.host_base=(uint8_t*)&fixture.effects",
         "runtime guest-host/effects alias case changed"),
        ("raw_effects+1U", "runtime misaligned-effects case changed"),
        ("fixture.effects.allocate_listener=NULL", "runtime null allocator case changed"),
        ("fixture.effects.publish_listener=NULL", "runtime null publisher case changed"),
        ("fixture.effects.startup_facefx=NULL", "runtime null FaceFX case changed"),
        ("fixture.effects.context=NULL", "runtime null context case changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)
    coverage = (
        "test_success_nonnull_is_exact",
        "test_null_allocation_is_normal",
        "test_guest_end_boundary_is_admitted",
        "test_snapshot_precedes_first_effect",
        "test_invalid_allocation_prefix_is_exact",
        "test_validation_failures_have_no_effect",
    )
    for function in coverage:
        if compact.count(function + "(") != 2:
            findings.append(f"runtime coverage function changed: {function}")
    if compact.count(FUNCTION + "(") != 18:
        findings.append("runtime transcript call coverage changed")
    if text.count("100e87a0 handler transcript runtime: 9/9 cases passed") != 1:
        findings.append("runtime success marker changed")
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    if _sha256(data) != EXPECTED_PROVENANCE_SHA256:
        findings.append("provenance exact digest changed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return findings + [f"provenance is not strict UTF-8: {error}"]
    compact = _compact(text)
    required = (
        "FUNCTION_VA=0x100E87A0",
        'FUNCTION_SHA256="0917917b3f65047b219059555acfb913b8cd9f91ccf6908e8295619d0dea710d"',
        "FUNCTION_RAW_OFFSET=0x000E7BA0",
        "DIRECT_CALL_OFFSETS=(6,50,85,96)",
        "DIRECT_CALL_TARGETS=(0x10ED3D90,0x100D12B0,0x10ED67A0,0x100D6560)",
        "REGISTERED_VTABLE_PAIR_VA=0x1173F2DC",
        'REGISTERED_VTABLE_PAIR_BYTES=bytes.fromhex("70140e10a0870e10")',
        "LISTENER_VTABLE_VA=0x1173FF28",
        'LISTENER_VTABLE_BYTES=bytes.fromhex("40140e10c0220e1010140e10")',
        "GLOBAL_LISTENER_VA=0x119F3858",
        "POLICY_CONSTRUCTOR_VA=0x10ED3D90",
        "ALLOCATE_WRAPPER_VA=0x100D12B0",
        "ALLOCATOR_VA=0x100FCC80",
        "ALLOCATE_DEBUG_VA=0x100E2190",
        "FREE_CALLBACK_VA=0x100E21A0",
        "FREE_HELPER_VA=0x100FCC50",
        "FACEFX_STARTUP_VA=0x10ED67A0",
        "NOOP_DESTRUCTOR_VA=0x100D6560",
        'self.assertEqual(rel8_target(body,FUNCTION_VA,60,0x74),0x100E87E6)',
        'self.assertEqual(rel8_target(body,FUNCTION_VA,68,0xEB),0x100E87E8)',
        "machineevidenceonly",
        "portdecisions",
        "nox86address",
    )
    for fragment in required:
        if fragment not in compact:
            findings.append(f"provenance authority marker changed: {fragment[:72]}")
    if len(re.findall(r"^\s+def test_", text, flags=re.MULTILINE)) != 7:
        findings.append("provenance must retain seven independent assertions")
    for banned in ("ctypes", "subprocess", "WinDLL", "CDLL"):
        if banned in text:
            findings.append(f"provenance must remain data-only: {banned}")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless exact size changed")
    if _sha256(encoded) != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    includes = (
        "ported_100df270_platform_prefix_transcript.h",
        "ported_100df270_suffix_transcript.h",
        "ported_100e2460_router.h",
        "ported_100e8d00_handler_transcript.h",
        "ported_100e85d0_normal_adapter.h",
        "ported_100e8580_handler_transcript.h",
        "ported_100e9340_handler_transcript.h",
        "ported_100e92c0_handler_transcript.h",
        "ported_100e87a0_handler_transcript.h",
        "ported_100ea4d0_injected.h",
    )
    positions = [text.find(f'#include "{name}"') for name in includes]
    if any(position < 0 for position in positions) or any(
        left >= right for left, right in zip(positions, positions[1:])
    ):
        findings.append("headless include order must end router/handlers/87a0/outer")

    if compact.count(SUFFIX_FUNCTION + "(") != 0:
        findings.append("headless must not duplicate the composed suffix transcript")
    if compact.count(PREFIX_FUNCTION + "(") != 0:
        findings.append("headless must not duplicate the composed platform-prefix transcript")
    if compact.count(PARENT_FUNCTION + "(") != 1:
        findings.append("headless must execute the empty-preloop parent exactly once")
    if compact.count(LIFECYCLE_FUNCTION + "(") != 1:
        findings.append("headless must execute the ordinary lifecycle exactly once")

    call = (
        "handler_87a0_status=" + FUNCTION + "(context->state_view,receiver,"
        "argument,&context->handler_87a0_effects,&handler_al);"
    )
    if compact.count(FUNCTION + "(") != 2 or compact.count(call) != 2:
        findings.append("headless must execute the exact 100e87a0 call twice")
    router_dispatch = _function_body(code, "rome2_headless_router_dispatch")
    outer_dispatch = _function_body(code, "rome2_headless_outer_dispatch")
    if router_dispatch is None or _compact(router_dispatch).count(call) != 1:
        findings.append("standalone router dispatch must call 100e87a0 exactly once")
    if outer_dispatch is None or _compact(outer_dispatch).count(call) != 1:
        findings.append("injected outer dispatch must call 100e87a0 exactly once")

    callback_fragments = (
        ("byte_count!=ROME2_PORT_100E87A0_LISTENER_BYTES||"
         "allocation_class!=ROME2_PORT_100E87A0_ALLOCATION_CLASS",
         "headless allocation argument oracle changed"),
        ("context->allocation_calls!=UINT32_C(1)||"
         "context->effect_order!=UINT32_C(1)",
         "headless allocation order oracle changed"),
        ("context->publish_calls!=UINT32_C(1)||"
         "context->allocation_calls!=UINT32_C(1)||"
         "context->effect_order!=UINT32_C(2)",
         "headless publication order oracle changed"),
        ("context->startup_calls!=UINT32_C(1)||"
         "context->publish_calls!=UINT32_C(1)||"
         "context->effect_order!=UINT32_C(3)",
         "headless FaceFX order oracle changed"),
        ("policy.allocation_type!=ROME2_PORT_100E87A0_POLICY_TYPE||"
         "policy.track_allocations!="
         "ROME2_PORT_100E87A0_POLICY_TRACK_ALLOCATIONS||"
         "policy.allocate_identity!="
         "ROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY||"
         "policy.allocate_debug_identity!="
         "ROME2_PORT_100E87A0_POLICY_ALLOCATE_DEBUG_IDENTITY||"
         "policy.free_identity!=ROME2_PORT_100E87A0_POLICY_FREE_IDENTITY",
         "headless typed policy oracle changed"),
        ("*context->return_al!=UINT8_C(0xcc)",
         "headless callbacks must observe unpublished AL"),
        ("ROME2_HEADLESS_87A0_LISTENER_SENTINEL",
         "headless listener sentinel changed"),
    )
    for fragment, message in callback_fragments:
        if fragment not in compact:
            findings.append(message)

    for prefix in ("router_effect_context", "outer_effect_context"):
        wiring = (
            f"{prefix}.handler_87a0_effects.allocate_listener="
            "rome2_headless_87a0_allocate;"
            f"{prefix}.handler_87a0_effects.publish_listener="
            "rome2_headless_87a0_publish;"
            f"{prefix}.handler_87a0_effects.startup_facefx="
            "rome2_headless_87a0_startup;"
            f"{prefix}.handler_87a0_effects.context="
            f"&{prefix}.handler_87a0_context;"
        )
        if wiring not in compact:
            findings.append(f"headless {prefix} injected-effect wiring changed")
        completion = (
            f"{prefix}.handler_87a0_context.allocation_calls!=1||"
            f"{prefix}.handler_87a0_context.publish_calls!=1||"
            f"{prefix}.handler_87a0_context.startup_calls!=1||"
            f"{prefix}.handler_87a0_context.effect_order!=3||"
            f"{prefix}.handler_87a0_context.bad_observations!=0"
        )
        if completion not in compact:
            findings.append(f"headless {prefix} three-effect completion oracle changed")
    dispatch_check = (
        "handler_87a0_status!=ROME2_100E87A0_OK||"
        "handler_al!=ROME2_PORT_100E87A0_AL||"
        "context->handler_87a0_calls!=UINT32_C(1)||"
        "context->handler_87a0_context.bad_observations!=UINT32_C(0)"
    )
    if compact.count(dispatch_check) != 2:
        findings.append("headless two 100e87a0 status/AL/call checks changed")
    if compact.count("context->handler_87a0_context.return_al=&handler_al;") != 2:
        findings.append("headless two unpublished-AL captures changed")
    if compact.count("context->handler_87a0_context.return_al=NULL;") != 2:
        findings.append("headless two AL capture releases changed")
    if "0x600000b1" in compact.lower():
        findings.append("headless unknown-method fallback must fail closed")

    token_positions = []
    for token in STATUS_TOKENS:
        if text.count(token) != 1:
            findings.append(f"headless truthful status token changed: {token}")
        token_positions.append(text.find(token))
    if any(position < 0 for position in token_positions) or any(
        left >= right for left, right in zip(token_positions, token_positions[1:])
    ):
        findings.append("headless original-order handler/outer token sequence changed")
    for forbidden in (
        "initializer-handler-100e87a0=native",
        "initializer-handler-100e87a0=not-linked",
        "initializer-100ea4d0=native",
        "startup-100df270-suffix=native",
        "startup-100df270-suffix=not-linked",
        "startup-100df270-platform-prefix=native",
        "startup-100df270-platform-prefix=not-linked",
    ):
        if forbidden in text:
            findings.append(f"headless reports forbidden native state: {forbidden}")
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
        findings.append("CMake add_test declaration count must remain 192")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped_tokens = (
        LIBRARY, TEST_TARGET,
        "ported_100e87a0_handler_transcript.h",
        "ported_100e87a0_handler_transcript.c",
        "test_startup_100e87a0_handler_transcript.c",
        "test_x64_startup_100e87a0_handler_transcript_provenance.py",
        "test_x64_startup_100e87a0_handler_transcript_static_gate.py",
        "x64_startup_100e87a0_handler_transcript_static_gate.py",
        *TRANSCRIPT_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake transcript token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake transcript token escapes BUILD_TESTING: {token}")
    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)

    exact_library = (
        f"add_library({LIBRARY}STATIC"
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.c")'
    )
    if compact.count(exact_library) != 1:
        findings.append("transcript must be an exact BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("transcript library must not be shared")
    cmake_fragments = (
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "transcript C17 requirement changed"),
        (f"target_compile_definitions({LIBRARY}PRIVATEWIN32_LEAN_AND_MEAN"
         "NOMINMAXWINVER=0x0602_WIN32_WINNT=0x0602)",
         "transcript compile-definition containment changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "transcript hardened compile options changed"),
        (f"target_include_directories({LIBRARY}PUBLIC"
         '"${ROME2_GUEST32_RUNTIME_DIR}"'
         '"${ROME2_GUEST32_PORTED_DIR}")',
         "transcript include containment changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e87a0_handler_transcript.c")',
         "transcript runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated runtime test must link only its transcript library"),
    )
    for fragment, message in cmake_fragments:
        if compact.count(fragment) != 1:
            findings.append(message)

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    own_dependencies = [
        command for command in link_commands
        if re.split(r"\s+", command.strip(), maxsplit=1)[0] == LIBRARY
    ]
    if own_dependencies:
        findings.append("transcript core must have no link dependencies")
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands
        if LIBRARY in command
        and re.split(r"\s+", command.strip(), maxsplit=1)[0] != LIBRARY
    ]
    if sorted(consumers) != sorted((TEST_TARGET, HEADLESS)):
        findings.append("transcript library has an unexpected consumer/dependency")
    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append("exact headless final link composition changed")

    gate_start = compact.find(
        "add_test(NAMEstartup_100e87a0_handler_transcript_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e87a0_handler_transcript.c"',
        '--transcript-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e87a0_handler_transcript_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"transcript static-gate argument changed: {argument[:76]}")
    for test_name in TRANSCRIPT_TEST_NAMES:
        count = len(re.findall(
            r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact
        ))
        if count != 1:
            findings.append(f"transcript CTest missing or duplicated: {test_name}")

    fixture_blocks = (
        "set_tests_properties(startup_100e87a0_handler_transcript_provenance"
        "PROPERTIESFIXTURES_SETUPstartup_100e87a0_handler_transcript_provenance_verified)",
        "set_tests_properties(startup_100e87a0_handler_transcript_static_gate_unit"
        "PROPERTIESFIXTURES_SETUPstartup_100e87a0_handler_transcript_static_tool_verified)",
        "set_tests_properties(startup_100e87a0_handler_transcript_static_gate"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e87a0_handler_transcript_static_tool_verified"
        "FIXTURES_SETUPstartup_100e87a0_handler_transcript_static_verified)",
        "set_tests_properties(startup_100e87a0_handler_transcript_runtimePROPERTIES"
        f"FIXTURES_REQUIRED\"{PREDECESSOR_RELOAD_FIXTURE};"
        "startup_100e87a0_handler_transcript_provenance_verified;"
        "startup_100e87a0_handler_transcript_static_verified\""
        "FIXTURES_SETUPstartup_100e87a0_handler_transcript_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e87a0_handler_transcript_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED\""
        "startup_100e87a0_handler_transcript_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e87a0_handler_transcript_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e87a0_handler_transcript"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e87a0_handler_transcript_post_verified\""
        f"FIXTURES_SETUP{OWN_RELOAD_FIXTURE})",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        f"entry_policy_static_verified;{TERMINAL_RELOAD_FIXTURE}\"TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"transcript fixture-chain block changed: {block[:82]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e87a0_handler_transcript",
        "ported_100e87a0_handler_transcript", "100e87a0_handler_transcript",
    ):
        if token in lowered:
            findings.append(f"test-only transcript token escaped exports: {token}")
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
    parser.add_argument("--transcript-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = {
        "header": args.header,
        "source": args.source,
        "test": args.test,
        "transcript_provenance": args.transcript_provenance,
        "headless": args.headless,
        "cmake": args.cmake,
        "export_manifest": args.export_manifest,
        "legacy_def": args.legacy_def,
        "probe_def": args.probe_def,
    }
    try:
        provenance = args.transcript_provenance.resolve(strict=True).read_bytes()
    except OSError as error:
        provenance_findings = [f"cannot read transcript provenance: {error}"]
    else:
        provenance_findings = inspect_provenance_bytes(provenance)
    checks = {
        "header": _inspect_path(args.header.resolve(strict=True), inspect_header_text),
        "source": _inspect_path(args.source.resolve(strict=True), inspect_source_text),
        "test": _inspect_path(args.test.resolve(strict=True), inspect_test_text),
        "transcript_provenance": provenance_findings,
        "headless": _inspect_path(args.headless.resolve(strict=True), inspect_headless_text),
        "cmake": _inspect_path(args.cmake.resolve(strict=True), inspect_cmake_text),
        "export_manifest": _inspect_path(
            args.export_manifest.resolve(strict=True), inspect_exports_text
        ),
        "legacy_def": _inspect_path(args.legacy_def.resolve(strict=True), inspect_exports_text),
        "probe_def": _inspect_path(args.probe_def.resolve(strict=True), inspect_exports_text),
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
