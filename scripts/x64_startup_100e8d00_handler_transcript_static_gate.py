#!/usr/bin/env python3
"""Fail-closed source and containment gate for original 0x100e8d00."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e8d00_run_handler_transcript"
NORMAL_ADAPTER_FUNCTION = "rome2_port_100e85d0_normal_adapter"
ROUTER_FUNCTION = "rome2_port_100e2460_run_router"
FINAL_TRANSCRIPT_FUNCTION = "rome2_port_100e8580_run_handler_transcript"
OUTER_INITIALIZER_FUNCTION = "rome2_port_100ea4d0_run_injected"
HANDLER_9340_FUNCTION = "rome2_port_100e9340_run_handler_transcript"
HANDLER_92C0_FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
HANDLER_87A0_FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIBRARY = "rome2_startup_100e8d00_handler_transcript_runtime"
TEST_TARGET = "rome2_startup_100e8d00_handler_transcript_tests"
HEADLESS = "rome2_headless64"
ROUTER_LIBRARY = "rome2_startup_100e2460_router_runtime"
NORMAL_ADAPTER_LIBRARY = "rome2_startup_100e85d0_normal_adapter_runtime"
FINAL_TRANSCRIPT_LIBRARY = "rome2_startup_100e8580_handler_transcript_runtime"
OUTER_INITIALIZER_LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
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

EXPECTED_HEADER_SHA256 = (
    "3f468a6377c6284942cfc01bd85006617514425bc15d0c4b8a84c2a82eaebf56"
)
EXPECTED_SOURCE_SHA256 = (
    "92a35730a2f9b3d6154405fee73bf2d6aeb9c48c1195f7aee6730aac096823ec"
)
EXPECTED_TEST_SHA256 = (
    "0fdcf3c203872d87d35587e7dc439dccaf9a57a945ad823f7ebea59fb8e12b68"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "44ce245416df21334f515b27a48674976e2ec3def559038cf835707806e5c588"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "b03638492a5f5e6c09352ef5ebe3bf56d809798016d1c1e5de4cd9c41068f902"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "c9e95c6c439e7dc4f14c39803bae8b07add3360d03de62c6a038ada9e8a63998"
)
EXPECTED_PROVENANCE_SHA256 = (
    "435d7596843138fc34ec3c0bf452dd8f7df8a32e48c8d65265f965ea2f3be2e4"
)

TRANSCRIPT_TEST_NAMES = (
    "startup_100e8d00_handler_transcript_provenance",
    "startup_100e8d00_handler_transcript_static_gate_unit",
    "startup_100e8d00_handler_transcript_static_gate",
    "startup_100e8d00_handler_transcript_runtime",
    "startup_100e8d00_handler_transcript_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e8d00_handler_transcript",
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
    LIBRARY,
    NORMAL_ADAPTER_LIBRARY,
    FINAL_TRANSCRIPT_LIBRARY,
    OUTER_INITIALIZER_LIBRARY,
    HANDLER_9340_LIBRARY,
    HANDLER_92C0_LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    "rome2_startup_100ed471_ordinary_lifecycle_runtime",
)

HEADLESS_REQUIRED_TOKENS = (
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

STEP_FRAGMENTS = (
    (
        "ROME2_100E8D00_STEP_CALL_10CB6160", "UINT32_C(2)",
        "UINT32_C(0)", "UINT32_C(1)",
    ),
    (
        "ROME2_100E8D00_STEP_CALL_10115D40", "UINT32_C(1)",
        "UINT32_C(0)", "UINT32_C(0)",
    ),
    (
        "ROME2_100E8D00_STEP_CALL_112DC9F0", "UINT32_C(2)",
        "ROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY", "UINT32_C(0)",
    ),
    (
        "ROME2_100E8D00_STEP_CALL_101150A0", "UINT32_C(1)",
        "UINT32_C(1)", "UINT32_C(0)",
    ),
    (
        "ROME2_100E8D00_STEP_CALL_101151D0", "UINT32_C(1)",
        "UINT32_C(0)", "UINT32_C(0)",
    ),
    (
        "ROME2_100E8D00_STEP_CALL_112E2CB0", "UINT32_C(0)",
        "UINT32_C(0)", "UINT32_C(0)",
    ),
)


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
    if includes != ["guest32.h"]:
        findings.append("transcript header must reuse only the guest32 contract")
    for fragment, message in (
        ("#defineROME2_PORT_100E8D00_ALUINT8_C(1)",
         "transcript AL constant changed"),
        ("#defineROME2_PORT_100E8D00_STEP_COUNTUINT32_C(6)",
         "transcript step count changed"),
        ("#defineROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY"
         "UINT32_C(0x1173fb44)", "PRE_DB_APP_INIT identity changed"),
    ):
        _require_once(compact, fragment, findings, message)
    targets = (
        ("10CB6160", "0x10cb6160"), ("10115D40", "0x10115d40"),
        ("112DC9F0", "0x112dc9f0"), ("101150A0", "0x101150a0"),
        ("101151D0", "0x101151d0"), ("112E2CB0", "0x112e2cb0"),
    )
    for suffix, value in targets:
        _require_once(
            compact,
            f"#defineROME2_PORT_100E8D00_TARGET_{suffix}UINT32_C({value})",
            findings,
            f"typed target identity changed: {suffix}",
        )
    enum_body = (
        "typedefenumrome2_100e8d00_step_kind{"
        "ROME2_100E8D00_STEP_CALL_10CB6160=1,"
        "ROME2_100E8D00_STEP_CALL_10115D40=2,"
        "ROME2_100E8D00_STEP_CALL_112DC9F0=3,"
        "ROME2_100E8D00_STEP_CALL_101150A0=4,"
        "ROME2_100E8D00_STEP_CALL_101151D0=5,"
        "ROME2_100E8D00_STEP_CALL_112E2CB0=6}"
        "rome2_100e8d00_step_kind;"
    )
    _require_once(compact, enum_body, findings, "typed six-step order changed")
    step_type = (
        "typedefstructrome2_100e8d00_step{"
        "rome2_100e8d00_step_kindkind;uint32_targument_count;"
        "uint32_targument0;uint32_targument1;}rome2_100e8d00_step;"
    )
    _require_once(compact, step_type, findings, "typed step layout changed")
    callback_type = (
        "typedefvoid(*rome2_100e8d00_emit_step_fn)("
        "void*context,rome2_100e8d00_stepstep);"
    )
    _require_once(
        compact, callback_type, findings, "by-value typed callback contract changed"
    )
    effects_type = (
        "typedefstructrome2_100e8d00_transcript_effects{"
        "rome2_100e8d00_emit_step_fnemit_step;void*context;}"
        "rome2_100e8d00_transcript_effects;"
    )
    _require_once(compact, effects_type, findings, "effects layout changed")
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100e8d00_transcript_effects*effects,uint8_t*return_al_out);"
    )
    _require_once(compact, declaration, findings, "public transcript API changed")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "required to be total and nonreentrant",
        "does not call this adapter recursively",
        "does not",
        "retain borrowed host objects",
        "does not modify return_al_out",
        "step",
        "is passed by value",
        "snapshots both callback",
        "and context before emitting the first step",
        "opaque guest identities; every",
        "32-bit pattern is accepted",
        "must not overlap",
        "validation failure emits nothing",
        "publishes al=1 only after",
        "the sixth callback returns",
        "no allocation, platform or",
        "original-image call",
        "guest/native pointer cast",
    ):
        if phrase not in normalized:
            findings.append(f"transcript safety/effect contract is missing: {phrase}")
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
    if includes != [
        "ported_100e8d00_handler_transcript.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include set or order changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden allocation/platform identifier: {token}")
    if re.search(r"\b(?:extern|volatile|__declspec|__asm|asm)\b", code):
        findings.append("native/original linkage or assembly is forbidden")
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    allowed_calls = {
        "if", "sizeof", "UINT32_C", FUNCTION, "rome2_100e8d00_validate_object",
        "rome2_100e8d00_ranges_overlap", "emit_step",
    }
    for call in sorted(calls - allowed_calls):
        findings.append(f"unexpected call expression: {call}")
    if re.search(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uint64_t|uintptr_t|intptr_t)\s*\*+\s*\)\s*"
        r"[^;\n]{0,128}\bguest_(?:receiver|argument)\b",
        code,
    ):
        findings.append("opaque guest identity is converted to a native pointer")
    if re.search(
        r"\(\s*(?:uintptr_t|intptr_t)\s*\)\s*"
        r"[^;\n]{0,128}\bguest_(?:receiver|argument)\b",
        code,
    ):
        findings.append("opaque guest identity is converted to a native address")
    if compact.count(FUNCTION + "(") != 1:
        findings.append("exactly one transcript definition is required")
    for fragment, message in (
        ("if(object==NULL||size==0U){returnROME2_GUEST_BAD_ARGUMENT;}",
         "object null/zero-size validation changed"),
        ("start=(uintptr_t)object;if(size>UINTPTR_MAX-start){"
         "returnROME2_GUEST_RANGE_OVERFLOW;}",
         "object numeric-span validation changed"),
        ("returnleft_start<right_end&&right_start<left_end;",
         "host-span overlap predicate changed"),
    ):
        _require_once(compact, fragment, findings, message)
    marker = "rome2_guest_status" + FUNCTION + "("
    start = compact.find(marker)
    body = compact[start:] if start >= 0 else ""
    validation = (
        "status=rome2_100e8d00_validate_object(effects,sizeof(*effects));",
        "if(status!=ROME2_GUEST_OK){returnstatus;}",
        "status=rome2_100e8d00_validate_object(return_al_out,"
        "sizeof(*return_al_out));",
        "if(rome2_100e8d00_ranges_overlap(effects,sizeof(*effects),"
        "return_al_out,sizeof(*return_al_out))){"
        "returnROME2_GUEST_BAD_ARGUMENT;}",
        "effects_snapshot=*effects;",
        "if(effects_snapshot.emit_step==NULL||"
        "effects_snapshot.context==NULL){returnROME2_GUEST_BAD_ARGUMENT;}",
        "(void)guest_receiver;(void)guest_argument;",
    )
    previous = -1
    for fragment in validation:
        position = body.find(fragment)
        if position < 0:
            findings.append(f"validation/snapshot stage changed: {fragment[:70]}")
        elif position <= previous:
            findings.append("validation and snapshot-before-effect order changed")
        previous = max(previous, position)
    step_positions = []
    for index, (kind, count, argument0, argument1) in enumerate(STEP_FRAGMENTS, 1):
        fragment = (
            f"step.kind={kind};step.argument_count={count};"
            f"step.argument0={argument0};step.argument1={argument1};"
            "effects_snapshot.emit_step(effects_snapshot.context,step);"
        )
        position = body.find(fragment)
        step_positions.append(position)
        if body.count(fragment) != 1:
            findings.append(f"typed effect {index} order/arguments changed")
    if any(position < 0 for position in step_positions) or step_positions != sorted(
        step_positions
    ):
        findings.append("six typed effects are not emitted in authenticated order")
    snapshot_position = body.find("effects_snapshot=*effects;")
    if step_positions and (
        snapshot_position < 0
        or step_positions[0] < 0
        or snapshot_position >= step_positions[0]
    ):
        findings.append("callback/context snapshot must precede the first effect")
    if body.count(
        "effects_snapshot.emit_step(effects_snapshot.context,step);"
    ) != 6:
        findings.append("exactly six snapshotted effects are required")
    publication = (
        "*return_al_out=ROME2_PORT_100E8D00_AL;returnROME2_GUEST_OK;"
    )
    publication_position = body.find(publication)
    if body.count(publication) != 1:
        findings.append("AL=1 success publication changed")
    if not step_positions or publication_position <= step_positions[-1]:
        findings.append("AL must be published only after the sixth effect returns")
    if compact.count("*return_al_out=") != 1:
        findings.append("output must be written exactly once")
    if ".value" in code or re.search(
        r"\bguest_(?:receiver|argument)\s*(?:==|!=|<|>|\[)", code
    ):
        findings.append("opaque handler inputs must not be inspected")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    raw_compact = _compact(text)
    if _sha256(text.encode("utf-8")) != EXPECTED_TEST_SHA256:
        findings.append("runtime exact digest changed")
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e8d00_handler_transcript.h", "stdint.h", "stdio.h",
        "string.h",
    ]:
        findings.append("runtime include set or order changed")
    if compact.count(FUNCTION + "(") != 8:
        findings.append("runtime transcript invocation boundary changed")
    for fragment, message in (
        ("#defineROME2_TEST_EXPECTED_STEP_COUNTUINT32_C(6)",
         "runtime expected step count changed"),
        ("_Static_assert(ROME2_PORT_100E8D00_AL==UINT8_C(1)",
         "runtime AL contract assertion changed"),
        ("_Static_assert(ROME2_PORT_100E8D00_STEP_COUNT==UINT32_C(6)",
         "runtime six-step assertion changed"),
        ("trace->effects.emit_step=rome2_test_trap_callback;"
         "trace->effects.context=&trace->decoy_context;",
         "runtime callback/context snapshot oracle changed"),
        ("trace->return_al==NULL||*trace->return_al!=ROME2_TEST_SENTINEL",
         "runtime AL-after-sixth oracle changed"),
        ("trace.observed_count!=ROME2_TEST_EXPECTED_STEP_COUNT",
         "runtime exact effect-count oracle changed"),
        ("trace.callback_failures!=UINT32_C(0)||"
         "trace.trap_count!=UINT32_C(0)",
         "runtime snapshot/publication result oracle changed"),
    ):
        if fragment not in compact:
            findings.append(message)
    expected_steps = (
        ("ROME2_100E8D00_STEP_CALL_10CB6160", "UINT32_C(2)",
         "UINT32_C(0)", "UINT32_C(1)"),
        ("ROME2_100E8D00_STEP_CALL_10115D40", "UINT32_C(1)",
         "UINT32_C(0)", "UINT32_C(0)"),
        ("ROME2_100E8D00_STEP_CALL_112DC9F0", "UINT32_C(2)",
         "UINT32_C(0x1173fb44)", "UINT32_C(0)"),
        ("ROME2_100E8D00_STEP_CALL_101150A0", "UINT32_C(1)",
         "UINT32_C(1)", "UINT32_C(0)"),
        ("ROME2_100E8D00_STEP_CALL_101151D0", "UINT32_C(1)",
         "UINT32_C(0)", "UINT32_C(0)"),
        ("ROME2_100E8D00_STEP_CALL_112E2CB0", "UINT32_C(0)",
         "UINT32_C(0)", "UINT32_C(0)"),
    )
    previous = -1
    for index, fields in enumerate(expected_steps, 1):
        fragment = "{" + ",".join(fields) + "}"
        position = raw_compact.find(fragment)
        if position < 0:
            findings.append(f"independent typed effect oracle {index} changed")
        elif position <= previous:
            findings.append("independent typed effect oracle order changed")
        previous = max(previous, position)
    for label, count in (
        ("zero/max opaque identities", 1), ("distinct opaque identities", 1),
        ("null effects", 2), ("null callback", 4),
        ("null callback context", 2), ("null AL output", 2),
        ("effects/output alias", 2), ("effects numeric range overflow", 1),
        ("AL output numeric range overflow", 1),
    ):
        if text.count(label) != count:
            findings.append(f"runtime coverage label missing: {label}")
    for fragment, message in (
        ("(uint8_t*)(void*)&trace.effects", "runtime effects/output alias oracle changed"),
        ("UINTPTR_MAX-(uintptr_t)sizeof(rome2_100e8d00_transcript_effects)"
         "+(uintptr_t)2", "runtime effects overflow oracle changed"),
        ("(uint8_t*)(uintptr_t)UINTPTR_MAX",
         "runtime output overflow oracle changed"),
    ):
        if fragment not in compact:
            findings.append(message)
    opaque_success = (
        'failures+=rome2_test_success_case("zero/maxopaqueidentities",'
        "rome2_test_guest(UINT32_C(0)),rome2_test_guest(UINT32_MAX));"
    )
    if raw_compact.count(opaque_success) != 1:
        findings.append("runtime opaque all-bit identity oracle changed")
    if text.count("100e8d00 handler transcript: ok") != 1:
        findings.append("runtime pass token changed")
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"transcript provenance is not strict UTF-8: {error}"]
    if _sha256(data) != EXPECTED_PROVENANCE_SHA256:
        findings.append("transcript provenance authority digest changed")
    for token in (
        "DLL_SHA256", "INDEX_SHA256", "FUNCTION_VA", "FUNCTION_BYTES",
        "FUNCTION_SHA256", "FUNCTION_RAW_OFFSET", "CALL_OFFSETS",
        "CALL_TARGETS", "RAW_PUSH_GROUPS", "CALLEE_ARGUMENTS",
        "PRE_DB_APP_INIT_VA", "PRE_DB_APP_INIT_BYTES",
        "PRE_DB_APP_INIT_SHA256", "PRE_DB_APP_INIT_RAW_OFFSET",
        "VTABLE_PAIR_VA", "VTABLE_PAIR_BYTES", "VTABLE_PAIR_SHA256",
        "VTABLE_PAIR_RAW_OFFSET", "CANONICAL_HASHES", "CANONICAL_ROWS",
        "test_exact_55_byte_handler_body",
        "test_all_six_direct_call_targets_are_exact",
        "test_raw_push_order_and_callee_arguments_are_exact",
        "test_complete_instruction_shape_ignores_handler_inputs",
        "test_pre_db_app_init_identity_and_bytes_are_exact",
        "test_vtable_method_identity_is_exact",
        "test_canonical_callee_authority_and_known_gaps_are_exact",
    ):
        if text.count(token) < 1:
            findings.append(f"transcript provenance token missing: {token}")
    for authority in (
        "721c0a9b4df58497dd3362758ecbb2f73be24e5223bbad3faf01b3442811b3fe",
        "b9e1501a299ac770d9d93afc12907cf7a7e21280553b2e56c0d1abf4cfda7909",
        "492887edb7260c8a514ea97b3b158276f1d27b20599980dfb0e50157b0449dea",
        "6f6a4d093c84226eed472b7ed32ad1c130bf532d65517873393a6cd181706d11",
        "f93c1c5f6f6f3471cc2aa088813982e6edba623190a7dccc6466230e5dbb3c54",
        "32bb470e183e00c59c0b387f9f88aa2c6316316c4da5b6c4b3921f09cb099eed",
        "1db91c95142252eaf43349c6b57327d27f5e527ccac979d5fe1138e201c944b1",
    ):
        if text.count(authority) != 1:
            findings.append(f"transcript machine/canonical authority changed: {authority[:16]}")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "parsed strictly as data and is never loaded or executed",
        "all six direct call targets",
        "raw push order and callee-visible argument identities",
        "pre_db_app_init object",
        "deferred stack cleanup",
        "al publication ordering",
        "nothing here authorizes native linkage to any recovered address",
    ):
        if phrase not in normalized:
            findings.append(f"transcript evidence/port-policy boundary missing: {phrase}")
    return sorted(set(findings))


def _assigned_calls(code: str, function: str) -> list[tuple[str, str, int]]:
    matches: list[tuple[str, str, int]] = []
    prefix = re.compile(
        r"\b(?P<status>[A-Za-z_]\w*)\s*=\s*" + re.escape(function) + r"\s*\("
    )
    for match in prefix.finditer(code):
        depth = 1
        index = match.end()
        quote: str | None = None
        escaped = False
        while index < len(code) and depth:
            character = code[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
            elif character in ('"', "'"):
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            index += 1
        semicolon_match = re.match(r"\s*;", code[index:]) if depth == 0 else None
        if semicolon_match is None:
            continue
        call_end = index + semicolon_match.end()
        matches.append((match.group("status"), code[match.end():index - 1], call_end))
    return matches


def _check_headless_call(
    code: str,
    function: str,
    al_constant: str,
    require_step_count: bool,
    expected_count: int,
) -> list[str]:
    findings: list[str] = []
    calls = _assigned_calls(code, function)
    if len(calls) != expected_count:
        return [
            f"headless result for {function} must be captured {expected_count} times"
        ]
    for status_name, arguments, call_end in calls:
        output_match = re.search(
            r",\s*&(?P<output>[A-Za-z_]\w*)\s*$", arguments, flags=re.S
        )
        if output_match is None:
            findings.append(f"headless {function} call must use a dedicated AL output")
            continue
        output_name = output_match.group("output")
        suffix = code[call_end:call_end + 1000]
        condition_match = re.search(r"\bif\s*\((.*?)\)\s*\{", suffix, flags=re.S)
        condition = _compact(condition_match.group(1)) if condition_match else ""
        if (
            f"{status_name}!=ROME2_GUEST_OK" not in condition
            or f"{output_name}!={al_constant}" not in condition
        ):
            findings.append(f"headless must check {function} status and exact AL")
    if require_step_count and re.search(
        r"\b[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)+\s*!=\s*"
        r"ROME2_PORT_100E8D00_STEP_COUNT\b|"
        r"\b[A-Za-z_]\w*\s*!=\s*ROME2_PORT_100E8D00_STEP_COUNT\b",
        code,
    ) is None:
        findings.append("headless must check the exact six-effect transcript count")
    return findings


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
        findings.append(
            "headless include order must be router, all six handlers, outer"
        )
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
        (ROUTER_FUNCTION, 1), (FUNCTION, 2), (NORMAL_ADAPTER_FUNCTION, 2),
        (FINAL_TRANSCRIPT_FUNCTION, 2), (OUTER_INITIALIZER_FUNCTION, 1),
        (HANDLER_9340_FUNCTION, 2), (HANDLER_92C0_FUNCTION, 2),
        (HANDLER_87A0_FUNCTION, 2), (SUFFIX_FUNCTION, 0),
        (PREFIX_FUNCTION, 0), (PARENT_FUNCTION, 1),
        (LIFECYCLE_FUNCTION, 1),
    ):
        if code.count(function + "(") != count:
            findings.append(
                f"headless final composition call-site count changed: {function} != {count}"
            )
    findings.extend(_check_headless_call(
        code, FUNCTION, "ROME2_PORT_100E8D00_AL", True, 2
    ))
    findings.extend(_check_headless_call(
        code, NORMAL_ADAPTER_FUNCTION, "ROME2_PORT_100E85D0_NORMAL_AL", False, 2
    ))
    for token in HEADLESS_REQUIRED_TOKENS:
        if text.count(token) != 1:
            findings.append(f"headless transcript boundary report changed: {token}")
    final_sequence = (
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
    )
    positions = [text.find(token) for token in final_sequence]
    if any(position < 0 for position in positions) or any(
        left >= right for left, right in zip(positions, positions[1:])
    ):
        findings.append("headless final handler/suffix/platform-prefix token order changed")
    if "0x600000b1" in code.lower():
        findings.append("headless unknown-method fallback must fail closed")
    for forbidden in (
        "initializer-handler-100e8d00=native",
        "initializer-handler-100e8d00=not-linked",
        "initializer-handler-100e85d0=native",
        "initializer-handler-100e85d0=not-linked",
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
        LIBRARY, TEST_TARGET, "ported_100e8d00_handler_transcript.h",
        "ported_100e8d00_handler_transcript.c",
        "test_startup_100e8d00_handler_transcript.c",
        "test_x64_startup_100e8d00_handler_transcript_provenance.py",
        "test_x64_startup_100e8d00_handler_transcript_static_gate.py",
        "x64_startup_100e8d00_handler_transcript_static_gate.py",
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
        f'add_library({LIBRARY}STATIC'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.c")'
    )
    if compact.count(exact_library) != 1:
        findings.append("transcript must be an exact BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("transcript library must not be shared")
    for fragment, message in (
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "transcript C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "transcript hardened compile options changed"),
        (f"target_include_directories({LIBRARY}PUBLIC"
         '"${ROME2_GUEST32_RUNTIME_DIR}"'
         '"${ROME2_GUEST32_PORTED_DIR}")',
         "transcript include containment changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8d00_handler_transcript.c")',
         "transcript runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated transcript test must link only its static library"),
    ):
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
        findings.append(
            "exact headless link tail must end outer, 9340, 92c0, 87a0, "
            "suffix, platform-prefix"
        )

    gate_start = compact.find(
        "add_test(NAMEstartup_100e8d00_handler_transcript_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8d00_handler_transcript.c"',
        '--transcript-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e8d00_handler_transcript_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"transcript static-gate argument changed: {argument[:76]}")
    for test_name in TRANSCRIPT_TEST_NAMES:
        if len(re.findall(r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact)) != 1:
            findings.append(f"transcript CTest missing or duplicated: {test_name}")
    fixture_blocks = (
        "set_tests_properties(startup_100e8d00_handler_transcript_provenance"
        "PROPERTIESFIXTURES_SETUPstartup_100e8d00_handler_transcript_provenance_verified)",
        "set_tests_properties(startup_100e8d00_handler_transcript_static_gate_unit"
        "PROPERTIESFIXTURES_SETUPstartup_100e8d00_handler_transcript_static_tool_verified)",
        "set_tests_properties(startup_100e8d00_handler_transcript_static_gate"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e8d00_handler_transcript_static_tool_verified"
        "FIXTURES_SETUPstartup_100e8d00_handler_transcript_static_verified)",
        "set_tests_properties(startup_100e8d00_handler_transcript_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e2460_router_reload_verified;"
        "startup_100e8d00_handler_transcript_provenance_verified;"
        "startup_100e8d00_handler_transcript_static_verified\""
        "FIXTURES_SETUPstartup_100e8d00_handler_transcript_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e8d00_handler_transcript_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED\""
        "startup_100e8d00_handler_transcript_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e8d00_handler_transcript_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e8d00_handler_transcript"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e8d00_handler_transcript_post_verified\""
        "FIXTURES_SETUPstartup_100e8d00_handler_transcript_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        "entry_policy_static_verified;"
        "startup_100ed471_ordinary_lifecycle_reload_verified\"TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"transcript fixture-chain block changed: {block[:78]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e8d00_handler_transcript",
        "ported_100e8d00_handler_transcript", "100e8d00_handler_transcript",
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
