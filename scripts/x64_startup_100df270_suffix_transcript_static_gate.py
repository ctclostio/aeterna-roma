#!/usr/bin/env python3
"""Fail-closed source/containment gate for the 0x100df270 suffix transcript."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100df270_run_suffix_transcript"
DELEGATED_FUNCTION = "rome2_port_100df270_run_suffix_transcript_delegated"
LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
TEST_TARGET = "rome2_startup_100df270_suffix_transcript_tests"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
NONEMPTY_PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"

# Filled from the frozen payloads.  Exact and comment-insensitive digests are
# deliberately independent: neither semantic code nor its stated boundary may
# drift silently.
EXPECTED_HEADER_SHA256 = (
    "c340cb925096a87be9ee0a7edba3ef86af80a669de5ed5335c39032a54d782ff"
)
EXPECTED_SOURCE_SHA256 = (
    "ee40bb59780e2f9a5f88116472a406393017f7049766be34acb45c172bd929f1"
)
EXPECTED_TEST_SHA256 = (
    "290c6fe7c579cc311279d8671b072ef21088af1fcb14550383c46e4341dbdcbf"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "f331bbd2bc336a0266cd4ab0e61266d637351238f1168aef985fdd460f4fc838"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "50aaf9eed1ca0a151077c895a640a7ab038103d4f82f20138b6041676b5c296c"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "f0f4bc91e0e2fdf03c41c714a2040265bdb80e57e90cde33b720adfacfca3a56"
)
EXPECTED_PROVENANCE_SHA256 = (
    "917c38c1ea7ec9cc41c6d3b0689fdfcc099c8c1f1b52f0d78312fb02c3e29bcc"
)

STEP_KINDS = (
    "ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER",
    "ROME2_100DF270_SUFFIX_STEP_CALL_100E8240",
    "ROME2_100DF270_SUFFIX_STEP_CALL_100F2750",
    "ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0",
    "ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST",
    "ROME2_100DF270_SUFFIX_STEP_CALL_101046D0",
    "ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND",
    "ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "EnterCriticalSection", "FreeLibrary",
    "GetCurrentThreadId", "GetLastError", "GetMessageA", "GetMessageW",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "LoadStringA",
    "LoadStringW", "MessageBoxA", "MessageBoxW", "PeekMessageA",
    "PeekMessageW", "PostMessageA", "PostMessageW", "RegOpenKeyExW",
    "SendMessageA", "SendMessageW", "SteamInternal_ContextInit",
    "SystemParametersInfoA", "SystemParametersInfoW", "TlsAlloc", "TlsFree",
    "TlsGetValue", "TlsSetValue", "TranslateMessage", "VirtualAlloc",
    "VirtualFree", "calloc", "dlopen", "dlsym", "free", "malloc",
    "realloc", "system",
}

CMAKE_FILES = (
    "ported_100df270_suffix_transcript.h",
    "ported_100df270_suffix_transcript.c",
    "test_startup_100df270_suffix_transcript.c",
    "test_x64_startup_100df270_suffix_transcript_provenance.py",
    "test_x64_startup_100df270_suffix_transcript_static_gate.py",
    "x64_startup_100df270_suffix_transcript_static_gate.py",
)
CMAKE_TESTS = (
    "startup_100df270_suffix_transcript_provenance",
    "startup_100df270_suffix_transcript_static_gate_unit",
    "startup_100df270_suffix_transcript_static_gate",
    "startup_100df270_suffix_transcript_runtime",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _token_digest(code: str) -> str:
    return _sha256(_compact(code).encode("utf-8"))


def _check_digest(
    text: str,
    code: str,
    expected_exact: str,
    expected_tokens: str,
    label: str,
    findings: list[str],
) -> None:
    if expected_exact and _sha256(text.encode("utf-8")) != expected_exact:
        findings.append(f"{label} exact digest changed")
    if expected_tokens and _token_digest(code) != expected_tokens:
        findings.append(f"{label} executable-token digest changed")


def _require_once(
    compact: str,
    fragment: str,
    findings: list[str],
    message: str,
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def _require_in_order(
    compact: str,
    fragments: tuple[str, ...],
    findings: list[str],
    message: str,
) -> None:
    cursor = -1
    for fragment in fragments:
        position = compact.find(fragment, cursor + 1)
        if position < 0 or position <= cursor:
            findings.append(message)
            return
        cursor = position


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


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


def _banned_findings(code: str, *, source: bool) -> list[str]:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    findings = [
        f"forbidden native/allocator/platform identifier: {identifier}"
        for identifier in sorted(BANNED_IDENTIFIERS & identifiers)
    ]
    if re.search(r"\b_?DAT_[0-9A-Fa-f]+\b", code):
        findings.append("original process-global identifier is forbidden")
    if re.search(r"\b(?:decomp_fn|FUN|sub)_[0-9A-Fa-f]+\b", code):
        findings.append("recovered/native implementation call is forbidden")
    if source:
        if "#pragmacomment(lib" in _compact(code).lower():
            findings.append("native library autolinking is forbidden")
        guest_pointer_cast = re.compile(
            r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|"
            r"uint16_t|uint32_t|uintptr_t)\s*\*+\s*\)\s*"
            r"(?:\(?\s*)?(?:guest_[A-Za-z_]\w*|[^;\n]{0,64}\.value\b)"
        )
        if guest_pointer_cast.search(code):
            findings.append("guest identities must not become native pointers")
        if re.search(
            r"\(\s*(?:uintptr_t|size_t)\s*\)\s*"
            r"(?:guest_[A-Za-z_]\w*|[^;\n]{0,64}\.value\b)",
            code,
        ):
            findings.append("guest identities must not become host integers")
        if re.search(
            r"\bROME2_PORT_100DF270_SUFFIX_TARGET_[A-F0-9]+\b", code
        ):
            findings.append("original target identities must not enter executable source")
        for target in (
            "0x100e8240", "0x100f2750", "0x100ea4d0", "0x100d7cb0",
            "0x101046d0", "0x119f3140", "0x1173dc18",
        ):
            if target in code.lower():
                findings.append(
                    f"raw original address must remain header/evidence data: {target}"
                )
        if re.search(
            r"\(\s*(?:void|int|uint\d+_t|rome2_guest_status)\s*"
            r"\(\s*\*\s*\)\s*\([^)]*\)\s*\)",
            code,
        ):
            findings.append("native function-pointer construction is forbidden")
        for match in re.finditer(
            r"(?m)^[ \t]*(?:static\s+)?(?:const\s+)?"
            r"(?:char|int|unsigned|size_t|uintptr_t|uint(?:8|16|32|64)_t|"
            r"rome2_guest_addr32)\s+[A-Za-z_]\w*(?:\s*\[[^]]*\])?"
            r"\s*(?:=[^;]*)?;",
            code,
        ):
            prefix = code[:match.start()]
            if prefix.count("{") == prefix.count("}"):
                findings.append("file-scope process data is forbidden")
                break
    return findings


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_digest(
        text, code, EXPECTED_HEADER_SHA256, EXPECTED_HEADER_TOKEN_SHA256,
        "header", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100f1c10_triplet.h"]:
        findings.append("header must reuse only the bounded guest write-view contract")

    macros = (
        ("ROME2_PORT_100DF270_SUFFIX_ALREADY_MARKED_STEP_COUNT", "7",
         "already-marked seven-step count changed"),
        ("ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT", "11",
         "mismatch eleven-step count changed"),
        ("ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER", "0x119f3140",
         "global receiver evidence identity changed"),
        ("ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET", "0x874",
         "owner +0x874 offset changed"),
        ("ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET", "0x68",
         "100e8240 result +0x68 offset changed"),
        ("ROME2_PORT_100DF270_SUFFIX_SELECTOR", "2",
         "selector-2 constant changed"),
        ("ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER", "0x4e3b",
         "final marker changed"),
        ("ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD", "0x119f3a38",
         "completed 100e8240 crash-record identity changed"),
        ("ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE", "0x1173dc18",
         "selector-query vtable identity changed"),
        ("ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET", "0x0c",
         "selector-query virtual slot +0x0c changed"),
    )
    for name, value, message in macros:
        _require_once(
            compact, f"#define{name}UINT32_C({value})", findings, message
        )
    for target in ("100E8240", "100F2750", "100EA4D0", "100D7CB0", "101046D0"):
        _require_once(
            compact,
            f"#defineROME2_PORT_100DF270_SUFFIX_TARGET_{target}"
            f"UINT32_C(0x{target.lower()})",
            findings,
            f"callee evidence identity changed: {target.lower()}",
        )

    enum_type = (
        "typedefenumrome2_100df270_suffix_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100df270_suffix_step_kind;"
    )
    _require_once(compact, enum_type, findings, "typed eight-kind order changed")
    step_type = (
        "typedefstructrome2_100df270_suffix_step{"
        "rome2_100df270_suffix_step_kindkind;uint32_targument_count;"
        "uint32_targument0;uint32_targument1;uint32_tresult_count;"
        "uint32_tresult0;uint32_tdispatch_vtable;"
        "uint32_tdispatch_slot_offset;uint32_tobserved_value;}"
        "rome2_100df270_suffix_step;"
    )
    _require_once(
        compact, step_type, findings,
        "typed argument/result/observed-value step layout changed",
    )
    callback_type = (
        "typedefvoid(*rome2_100df270_suffix_emit_step_fn)("
        "void*context,rome2_100df270_suffix_stepstep);"
    )
    _require_once(compact, callback_type, findings, "by-value callback contract changed")
    effects_type = (
        "typedefstructrome2_100df270_suffix_effects{"
        "rome2_100df270_suffix_emit_step_fnemit_step;void*context;"
        "rome2_guest_addr32result_100e8240;"
        "rome2_guest_addr32first_selector_result;"
        "rome2_guest_addr32second_selector_result;}"
        "rome2_100df270_suffix_effects;"
    )
    _require_once(
        compact, effects_type, findings,
        "complete injected-result effects layout changed",
    )
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "constrome2_guest_write_view*state_view,"
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100df270_suffix_effects*effects,"
        "rome2_guest_addr32*return_receiver_out);"
    )
    _require_once(compact, declaration, findings, "public bounded suffix API changed")
    delegate_callback = (
        "typedefrome2_guest_status"
        "(*rome2_100df270_suffix_execute_100f2750_fn)("
        "void*context,rome2_guest_addr32guest_destination,"
        "rome2_guest_addr32guest_source);"
    )
    _require_once(
        compact, delegate_callback, findings,
        "typed status-returning 100f2750 delegate callback changed",
    )
    delegate_type = (
        "typedefstructrome2_100df270_suffix_100f2750_delegate{"
        "rome2_100df270_suffix_execute_100f2750_fnexecute;"
        "void*context;uint64_tcontext_byte_count;}"
        "rome2_100df270_suffix_100f2750_delegate;"
    )
    _require_once(
        compact, delegate_type, findings,
        "typed 100f2750 delegate descriptor layout changed",
    )
    delegated_declaration = (
        "rome2_guest_status" + DELEGATED_FUNCTION + "("
        "constrome2_guest_write_view*state_view,"
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100df270_suffix_effects*effects,"
        "constrome2_100df270_suffix_100f2750_delegate*delegate,"
        "rome2_guest_addr32*return_receiver_out);"
    )
    _require_once(
        compact, delegated_declaration, findings,
        "public delegated suffix API changed",
    )
    findings.extend(_banned_findings(code, source=False))
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_digest(
        text, code, EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_TOKEN_SHA256,
        "source", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    allowed_includes = {
        "ported_100df270_suffix_transcript.h", "limits.h", "stddef.h",
        "stdint.h",
    }
    if (
        not includes
        or includes[0] != "ported_100df270_suffix_transcript.h"
        or set(includes) - allowed_includes
        or len(includes) != len(set(includes))
    ):
        findings.append("source include containment changed")
    findings.extend(_banned_findings(code, source=True))

    helper_contracts = (
        ("#defineROME2_100DF270_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest32 address-space ceiling changed"),
        ("#defineROME2_100DF270_RESULT_CELL_BYTESUINT64_C(4)",
         "selector result must remain a four-byte cell"),
        ("typedefstructrome2_100df270_span{uint64_tguest_start;"
         "uintptr_thost_start;uint64_tbyte_count;uint64_tview_offset;}"
         "rome2_100df270_span;", "checked mapped-span layout changed"),
        ("view->host_base==NULL", "state host-base validation changed"),
        ("view->byte_count>ROME2_100DF270_ADDRESS_SPACE_SIZE||"
         "(uint64_t)view->guest_base+view->byte_count>"
         "ROME2_100DF270_ADDRESS_SPACE_SIZE",
         "guest interval overflow validation changed"),
        ("view->byte_count-UINT64_C(1)>"
         "(uint64_t)(UINTPTR_MAX-host_address)",
         "host interval overflow validation changed"),
        ("guest_cell.value==0", "selector-result null validation changed"),
        ("ROME2_100DF270_RESULT_CELL_BYTES>"
         "ROME2_100DF270_ADDRESS_SPACE_SIZE-(uint64_t)guest_cell.value",
         "selector-result guest overflow validation changed"),
        ("guest_cell.value<view->guest_base",
         "selector-result lower-bound validation changed"),
        ("offset>view->byte_count||ROME2_100DF270_RESULT_CELL_BYTES>"
         "view->byte_count-offset||offset>(uint64_t)SIZE_MAX",
         "complete selector-result span validation changed"),
        ("span_out->guest_start=(uint64_t)guest_cell.value;"
         "span_out->host_start=(uintptr_t)view->host_base+(uintptr_t)offset;"
         "span_out->byte_count=ROME2_100DF270_RESULT_CELL_BYTES;"
         "span_out->view_offset=offset;",
         "selector-result span projection changed"),
        ("step->dispatch_vtable=UINT32_C(0);"
         "step->dispatch_slot_offset=UINT32_C(0);"
         "step->observed_value=UINT32_C(0);",
         "step vtable/slot/observed clearing changed"),
    )
    for fragment, message in helper_contracts:
        if fragment not in compact:
            findings.append(message)
    read_helper = (
        "return(uint32_t)bytes[0]|((uint32_t)bytes[1]<<8)|"
        "((uint32_t)bytes[2]<<16)|((uint32_t)bytes[3]<<24);"
    )
    if compact.count(read_helper) != 1:
        findings.append("unaligned-safe little-endian marker read changed")
    write_helper = (
        "bytes[0]=(uint8_t)value;bytes[1]=(uint8_t)(value>>8);"
        "bytes[2]=(uint8_t)(value>>16);bytes[3]=(uint8_t)(value>>24);"
    )
    if compact.count(write_helper) != 1:
        findings.append("unaligned-safe little-endian marker write changed")

    delegated_helper_contracts = (
        (
            "rome2_100df270_delegated_controls_overlap",
            "returnrome2_100df270_control_objects_overlap(state_view,effects,"
            "return_receiver_out)||rome2_100df270_ranges_overlap((uint64_t)"
            "(uintptr_t)delegate,sizeof(*delegate),(uint64_t)(uintptr_t)"
            "state_view,sizeof(*state_view))||rome2_100df270_ranges_overlap("
            "(uint64_t)(uintptr_t)delegate,sizeof(*delegate),(uint64_t)"
            "(uintptr_t)effects,sizeof(*effects))||"
            "rome2_100df270_ranges_overlap((uint64_t)(uintptr_t)delegate,"
            "sizeof(*delegate),(uint64_t)(uintptr_t)return_receiver_out,"
            "sizeof(*return_receiver_out));",
            "delegated control pairwise-disjointness helper changed",
        ),
        (
            "rome2_100df270_delegated_state_overlaps_controls",
            "returnrome2_100df270_host_interval_overlaps_controls(view,"
            "state_view,effects,return_receiver_out)||"
            "rome2_100df270_ranges_overlap((uint64_t)(uintptr_t)"
            "view->host_base,view->byte_count,(uint64_t)(uintptr_t)delegate,"
            "sizeof(*delegate));",
            "delegated state-backing disjointness helper changed",
        ),
        (
            "rome2_100df270_validate_delegate_context",
            "uint64_tcontext_start;if(delegate_snapshot->execute==NULL||"
            "delegate_snapshot->context==NULL||"
            "delegate_snapshot->context_byte_count==0){"
            "returnROME2_GUEST_BAD_ARGUMENT;}context_start=(uint64_t)"
            "(uintptr_t)delegate_snapshot->context;if(delegate_snapshot->"
            "context_byte_count-UINT64_C(1)>(uint64_t)(UINTPTR_MAX-"
            "(uintptr_t)delegate_snapshot->context)){"
            "returnROME2_GUEST_RANGE_OVERFLOW;}if("
            "rome2_100df270_ranges_overlap(context_start,delegate_snapshot->"
            "context_byte_count,(uint64_t)(uintptr_t)view->host_base,"
            "view->byte_count)||rome2_100df270_ranges_overlap(context_start,"
            "delegate_snapshot->context_byte_count,(uint64_t)(uintptr_t)"
            "state_view,sizeof(*state_view))||rome2_100df270_ranges_overlap("
            "context_start,delegate_snapshot->context_byte_count,(uint64_t)"
            "(uintptr_t)effects,sizeof(*effects))||"
            "rome2_100df270_ranges_overlap(context_start,delegate_snapshot->"
            "context_byte_count,(uint64_t)(uintptr_t)delegate_control,"
            "sizeof(*delegate_control))||rome2_100df270_ranges_overlap("
            "context_start,delegate_snapshot->context_byte_count,(uint64_t)"
            "(uintptr_t)return_receiver_out,sizeof(*return_receiver_out))){"
            "returnROME2_GUEST_BAD_ARGUMENT;}returnROME2_GUEST_OK;",
            "delegated context authority helper changed",
        ),
    )
    for helper_name, expected_body, message in delegated_helper_contracts:
        helper_body = _function_body(code, helper_name)
        if helper_body is None or _compact(helper_body) != expected_body:
            findings.append(message)

    body = _function_body(code, FUNCTION)
    if body is None:
        findings.append("bounded suffix function definition is missing")
        return sorted(set(findings))
    function = _compact(body)

    required_tokens = (
        ("status=rome2_100df270_validate_object(state_view,sizeof(*state_view));",
         "state descriptor validation changed"),
        ("status=rome2_100df270_validate_object(effects,sizeof(*effects));",
         "effects descriptor validation changed"),
        ("status=rome2_100df270_validate_object(return_receiver_out,"
         "sizeof(*return_receiver_out));",
         "receiver output validation changed"),
        ("(uintptr_t)state_view%_Alignof(rome2_guest_write_view)!=0U||"
         "(uintptr_t)effects%_Alignof(rome2_100df270_suffix_effects)!=0U||"
         "(uintptr_t)return_receiver_out%_Alignof(rome2_guest_addr32)!=0U||"
         "rome2_100df270_control_objects_overlap(state_view,effects,"
         "return_receiver_out)",
         "control alignment/pairwise-alias validation changed"),
        ("state_snapshot=*state_view;", "complete state-view snapshot changed"),
        ("if(rome2_100df270_host_interval_overlaps_controls(&state_snapshot,"
         "state_view,effects,return_receiver_out))",
         "state host interval/control physical-alias validation changed"),
        ("effects_snapshot=*effects;", "complete effects snapshot changed"),
        ("rome2_guest_add_checked(guest_receiver,"
         "ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,",
         "checked receiver +0x874 derivation changed"),
        ("rome2_guest_add_checked(effects_snapshot.result_100e8240,"
         "ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,",
         "checked 100e8240 result +0x68 derivation changed"),
        ("effects_snapshot.emit_step==NULL", "callback validation changed"),
        ("effects_snapshot.context==NULL", "context validation changed"),
        ("effects_snapshot.result_100e8240.value==0",
         "zero 100e8240 result status validation changed"),
        ("effects_snapshot.result_100e8240.value!="
         "ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD",
         "completed-route crash-record result validation changed"),
        ("status=rome2_100df270_resolve_result_cell(&state_snapshot,"
         "effects_snapshot.first_selector_result,&first_result_span);",
         "first selector result mapping changed"),
        ("status=rome2_100df270_resolve_result_cell(&state_snapshot,"
         "effects_snapshot.second_selector_result,&second_result_span);",
         "second selector result mapping changed"),
        ("first_result_value=rome2_100df270_read_u32_le("
         "state_snapshot.host_base+(size_t)first_result_span.view_offset);",
         "pre-callback first marker snapshot changed"),
    )
    for fragment, message in required_tokens:
        if fragment not in function:
            findings.append(message)

    # The two selector identities must be resolved independently before the
    # first callback.  Logical/physical aliasing between those two spans is
    # intentionally allowed, but each complete four-byte mapping is required.
    first_emit = function.find("effects_snapshot.emit_step(")
    if first_emit < 0:
        findings.append("transcript never emits an injected step")
    for fragment, message in (
        ("first_selector_result", "first selector span handling changed"),
        ("second_selector_result", "second selector span handling changed"),
        ("first_result_value", "first marker must be snapshotted before callbacks"),
    ):
        positions = [match.start() for match in re.finditer(fragment, function)]
        if not positions or first_emit < 0 or not any(position < first_emit for position in positions):
            findings.append(message)

    validation_markers = (
        "validate_object(state_view",
        "validate_object(effects",
        "validate_object(return_receiver_out",
        "validate_interval(&state_snapshot)",
        "control_objects_overlap(",
        "host_interval_overlaps_controls(",
        "rome2_guest_add_checked(effects_snapshot.result_100e8240,",
        "rome2_guest_add_checked(guest_receiver,",
        "resolve_result_cell(",
        "first_result_value=",
    )
    for marker in validation_markers:
        position = function.find(marker)
        if position < 0 or (first_emit >= 0 and position >= first_emit):
            findings.append(f"pre-callback validation/snapshot changed: {marker}")
    _require_in_order(
        function,
        (
            "status=rome2_100df270_validate_object(state_view,sizeof(*state_view));",
            "status=rome2_100df270_validate_object(effects,sizeof(*effects));",
            "status=rome2_100df270_validate_object(return_receiver_out,",
            "rome2_100df270_control_objects_overlap(",
            "state_snapshot=*state_view;",
            "status=rome2_100df270_validate_interval(&state_snapshot);",
            "rome2_100df270_host_interval_overlaps_controls(",
            "effects_snapshot=*effects;",
            "effects_snapshot.emit_step==NULL",
            "effects_snapshot.result_100e8240.value!=",
            "rome2_guest_add_checked(effects_snapshot.result_100e8240,",
            "rome2_guest_add_checked(guest_receiver,",
            "effects_snapshot.first_selector_result,",
            "effects_snapshot.second_selector_result,",
            "first_result_value=rome2_100df270_read_u32_le(",
            "effects_snapshot.emit_step(",
        ),
        findings,
        "complete validation/snapshot sequence must precede every callback",
    )

    # Pin the complete field payload of every baseline step.  This preserves
    # the single pending argument reused across 0x100e8240/0x100f2750 and the
    # vtable/slot evidence attached to both injected virtual queries.
    step_blocks = (
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER;"
        "step.argument_count=UINT32_C(2);"
        "step.argument0=ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER;"
        "step.argument1=guest_receiver.value;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_CALL_100E8240;"
        "step.argument_count=UINT32_C(1);step.argument0=guest_argument.value;"
        "step.result_count=UINT32_C(1);"
        "step.result0=effects_snapshot.result_100e8240.value;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_CALL_100F2750;"
        "step.argument_count=UINT32_C(2);"
        "step.argument0=adjusted_100e8240_result.value;"
        "step.argument1=guest_argument.value;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0;"
        "step.argument_count=UINT32_C(1);step.argument0=guest_receiver.value;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST;"
        "step.argument_count=UINT32_C(2);step.argument0=owner_field.value;"
        "step.argument1=ROME2_PORT_100DF270_SUFFIX_SELECTOR;"
        "step.result_count=UINT32_C(1);"
        "step.result0=effects_snapshot.first_selector_result.value;"
        "step.dispatch_vtable=ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;"
        "step.dispatch_slot_offset="
        "ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET;"
        "step.observed_value=first_result_value;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND;"
        "step.argument_count=UINT32_C(2);step.argument0=owner_field.value;"
        "step.argument1=ROME2_PORT_100DF270_SUFFIX_SELECTOR;"
        "step.result_count=UINT32_C(1);"
        "step.result0=effects_snapshot.second_selector_result.value;"
        "step.dispatch_vtable=ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;"
        "step.dispatch_slot_offset="
        "ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_clear_step(&step);"
        "step.kind=ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER;"
        "step.argument_count=UINT32_C(2);"
        "step.argument0=effects_snapshot.second_selector_result.value;"
        "step.argument1=ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
    )
    for index, block in enumerate(step_blocks, 1):
        if function.count(block) != 1:
            findings.append(f"exact baseline step payload changed: {index}")
    _require_in_order(
        function, step_blocks, findings,
        "seven-step baseline chronological order changed",
    )

    conditional_body = _function_body(
        code, "rome2_100df270_emit_conditional_call"
    )
    conditional_compact = _compact(conditional_body or "")
    conditional_helper = (
        "rome2_100df270_clear_step(step);"
        "step->kind=ROME2_100DF270_SUFFIX_STEP_CALL_101046D0;"
        "step->argument_count=UINT32_C(1);step->argument0=argument;"
        "effects->emit_step(effects->context,*step);"
    )
    if conditional_compact != conditional_helper:
        findings.append("typed conditional-call helper changed")
    conditional_route = (
        "if(first_result_value!=ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER){"
        "rome2_100df270_emit_conditional_call(&effects_snapshot,&step,"
        "UINT32_C(0x2d));"
        "rome2_100df270_emit_conditional_call(&effects_snapshot,&step,"
        "UINT32_C(0x12));"
        "rome2_100df270_emit_conditional_call(&effects_snapshot,&step,"
        "UINT32_C(0x16));"
        "rome2_100df270_emit_conditional_call(&effects_snapshot,&step,"
        "UINT32_C(0x21));}"
    )
    if function.count(conditional_route) != 1:
        findings.append("mismatch-only exact four-call route changed")

    # Marker storage is an explicit byte-wise guest write.  It occurs after
    # the second virtual-query callback and before the final store callback;
    # the receiver output is committed only after that final callback.
    second_kind = function.find(f"step.kind={STEP_KINDS[6]}")
    store_kind = function.find(f"step.kind={STEP_KINDS[7]}")
    marker_write_candidates = [
        function.find("write_u32_le(", second_kind + 1),
        function.find("write_marker(", second_kind + 1),
    ]
    marker_write = min((value for value in marker_write_candidates if value >= 0), default=-1)
    output_writes = [
        match.start() for match in re.finditer(
            r"(?:\*return_receiver_out|return_receiver_out->value)=", function
        )
    ]
    last_emit = function.rfind("effects_snapshot.emit_step(")
    if not (0 <= second_kind < marker_write < store_kind <= last_emit):
        findings.append("second query, marker write, and final callback order changed")
    if len(output_writes) != 1 or output_writes[0] <= last_emit:
        findings.append("receiver output must commit once after the final callback")

    if function.count("ROME2_PORT_100DF270_SUFFIX_ALREADY_MARKED_STEP_COUNT"):
        findings.append("implementation must not fabricate route completion from a count")

    delegated_body = _function_body(code, DELEGATED_FUNCTION)
    if delegated_body is None:
        findings.append("delegated suffix function definition is missing")
        return sorted(set(findings))
    delegated = _compact(delegated_body)
    delegated_required = (
        ("status=rome2_100df270_validate_object(state_view,sizeof(*state_view));",
         "delegated state descriptor validation changed"),
        ("status=rome2_100df270_validate_object(effects,sizeof(*effects));",
         "delegated effects descriptor validation changed"),
        ("status=rome2_100df270_validate_object(delegate,sizeof(*delegate));",
         "delegate descriptor validation changed"),
        ("status=rome2_100df270_validate_object(return_receiver_out,"
         "sizeof(*return_receiver_out));",
         "delegated receiver output validation changed"),
        ("(uintptr_t)delegate%"
         "_Alignof(rome2_100df270_suffix_100f2750_delegate)!=0U",
         "delegate alignment validation changed"),
        ("rome2_100df270_delegated_controls_overlap(state_view,effects,"
         "delegate,return_receiver_out)",
         "delegate control disjointness changed"),
        ("rome2_100df270_delegated_state_overlaps_controls(&state_snapshot,"
         "state_view,effects,delegate,return_receiver_out)",
         "delegate/state-backing disjointness changed"),
        ("state_snapshot=*state_view;",
         "delegated complete state-view snapshot changed"),
        ("status=rome2_100df270_validate_interval(&state_snapshot);",
         "delegated state interval validation changed"),
        ("effects_snapshot=*effects;",
         "delegated complete effects snapshot changed"),
        ("delegate_snapshot=*delegate;",
         "complete delegate snapshot changed"),
        ("status=rome2_100df270_validate_delegate_context(&delegate_snapshot,"
         "delegate,&state_snapshot,state_view,effects,return_receiver_out);",
         "delegate context validation changed"),
        ("status=delegate_snapshot.execute(delegate_snapshot.context,"
         "adjusted_100e8240_result,guest_argument);",
         "typed delegate invocation changed"),
        ("effects_snapshot.emit_step==NULL||effects_snapshot.context==NULL",
         "delegated observer validation changed"),
        ("effects_snapshot.result_100e8240.value==0",
         "delegated zero 100e8240 result validation changed"),
        ("effects_snapshot.result_100e8240.value!="
         "ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD",
         "delegated crash-record identity validation changed"),
        ("rome2_guest_add_checked(effects_snapshot.result_100e8240,"
         "ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,",
         "delegated checked result +0x68 derivation changed"),
        ("rome2_guest_add_checked(guest_receiver,"
         "ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,",
         "delegated checked receiver +0x874 derivation changed"),
        ("effects_snapshot.first_selector_result,&first_result_span);",
         "delegated first selector mapping changed"),
        ("effects_snapshot.second_selector_result,&second_result_span);",
         "delegated second selector mapping changed"),
    )
    for fragment, message in delegated_required:
        if fragment not in delegated:
            findings.append(message)
    if delegated.count("delegate_snapshot.execute(") != 1:
        findings.append("typed delegate must execute exactly once")
    if "delegate_snapshot.execute(" in function:
        findings.append("baseline transcript must remain observation-only")
    _require_in_order(
        delegated,
        (
            "status=rome2_100df270_validate_object(state_view,sizeof(*state_view));",
            "status=rome2_100df270_validate_object(effects,sizeof(*effects));",
            "status=rome2_100df270_validate_object(delegate,sizeof(*delegate));",
            "status=rome2_100df270_validate_object(return_receiver_out,",
            "rome2_100df270_delegated_controls_overlap(",
            "state_snapshot=*state_view;",
            "status=rome2_100df270_validate_interval(&state_snapshot);",
            "rome2_100df270_delegated_state_overlaps_controls(",
            "effects_snapshot=*effects;",
            "effects_snapshot.emit_step==NULL||effects_snapshot.context==NULL",
            "effects_snapshot.result_100e8240.value!=",
            "delegate_snapshot=*delegate;",
            "rome2_100df270_validate_delegate_context(",
            "rome2_guest_add_checked(effects_snapshot.result_100e8240,",
            "rome2_guest_add_checked(guest_receiver,",
            "effects_snapshot.first_selector_result,",
            "effects_snapshot.second_selector_result,",
            "first_result_value=rome2_100df270_read_u32_le(",
            "effects_snapshot.emit_step(",
        ),
        findings,
        "delegated validation/snapshot sequence must precede every callback",
    )
    for index, block in enumerate(step_blocks, 1):
        if delegated.count(block) != 1:
            findings.append(f"exact delegated step payload changed: {index}")
    _require_in_order(
        delegated, step_blocks, findings,
        "seven-step delegated chronological order changed",
    )
    if delegated.count(conditional_route) != 1:
        findings.append("delegated mismatch-only exact four-call route changed")
    _require_in_order(
        delegated,
        (
            "delegate_snapshot=*delegate;",
            "first_result_value=rome2_100df270_read_u32_le(",
            "step.kind=ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER;",
            "step.kind=ROME2_100DF270_SUFFIX_STEP_CALL_100E8240;",
            "step.kind=ROME2_100DF270_SUFFIX_STEP_CALL_100F2750;",
            "effects_snapshot.emit_step(effects_snapshot.context,step);"
            "status=delegate_snapshot.execute(",
            "if(status!=ROME2_GUEST_OK){returnstatus;}",
            "step.kind=ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0;",
            "step.kind=ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND;",
            "rome2_100df270_write_u32_le(",
            "step.kind=ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER;",
            "return_receiver_out->value=guest_receiver.value;",
        ),
        findings,
        "delegated emit-execute-stop-resume order changed",
    )
    delegated_output_writes = [
        match.start() for match in re.finditer(
            r"(?:\*return_receiver_out|return_receiver_out->value)=", delegated
        )
    ]
    delegated_last_emit = delegated.rfind("effects_snapshot.emit_step(")
    if (
        len(delegated_output_writes) != 1 or
        delegated_output_writes[0] <= delegated_last_emit
    ):
        findings.append("delegated receiver output must commit after its final callback")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_digest(
        text, code, EXPECTED_TEST_SHA256, EXPECTED_TEST_TOKEN_SHA256,
        "runtime test", findings,
    )
    if '#include "ported_100df270_suffix_transcript.h"' not in text:
        findings.append("runtime test must include only the public suffix contract")
    required = (
        ("ROME2_PORT_100DF270_SUFFIX_ALREADY_MARKED_STEP_COUNT",
         "seven-step success oracle missing"),
        ("ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT",
         "eleven-step mismatch oracle missing"),
        ("ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER",
         "final marker oracle missing"),
        ("ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET",
         "checked owner boundary oracle missing"),
        ("ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET",
         "checked result boundary oracle missing"),
        ("0x119f3aa0", "exact checked crash-record +0x68 oracle missing"),
        ("0xfffff78c", "receiver +0x874 overflow oracle missing"),
        ("mutate_effects_after_first", "effects snapshot mutant is missing"),
        ("first_selector_result", "first selector span oracle missing"),
        ("second_selector_result", "second selector span oracle missing"),
        ("is_final?trace->final_memory.bytes:trace->baseline_memory.bytes",
         "marker-before-final-callback memory oracle missing"),
        ("trace->return_receiver->value!=TEST_RETURN_SENTINEL",
         "output-after-final-callback oracle missing"),
        ("test_first_offset,test_first_offset",
         "same-cell selector alias success oracle missing"),
        ("0x119f3a39",
         "wrong completed-result rejection oracle missing"),
        ("rome2_port_100df270_run_suffix_transcript_delegated",
         "delegated suffix runtime oracle missing"),
        ("mutate_delegate_after_first",
         "delegate snapshot runtime mutant is missing"),
        ("delegate_call_count==UINT32_C(1)",
         "exact one-shot delegate runtime oracle missing"),
        ("trace.call_count==UINT32_C(3)",
         "delegate failure committed-prefix runtime oracle missing"),
        ("fixture.delegate.context=fixture.memory.bytes",
         "delegate context/state disjointness runtime oracle missing"),
        ("delegated_status="
         "rome2_port_100df270_run_suffix_transcript_delegated(",
         "baseline failures are not mirrored through the delegated entry"),
        ("test_run_delegated_success(,UINT32_C(0x11223344),"
         "TEST_FIRST_OFFSET,0,0)",
         "delegated same-cell selector alias success oracle missing"),
        ("test_run_delegated_success(,UINT32_C(0x0badc0de),"
         "TEST_SECOND_OFFSET,1,0)",
         "delegated effects snapshot runtime oracle missing"),
        ("&fixture.delegate,(rome2_guest_addr32*)(void*)&fixture.delegate",
         "delegate descriptor/output alias oracle missing"),
    )
    lowered = compact.lower()
    for fragment, message in required:
        if fragment.lower() not in lowered:
            findings.append(message)
    if lowered.count("0x119f3aa0") != 3:
        findings.append("exact checked crash-record +0x68 oracle count changed")
    if compact.count("delegate_call_count==UINT32_C(1)") != 2:
        findings.append("exact one-shot delegate runtime oracle count changed")
    case_inventory = (
        ("failed|=test_run_success(", 4,
         "baseline success case inventory changed"),
        ("returntest_run_success(", 1,
         "baseline effects-snapshot case inventory changed"),
        ("failed|=test_expect_precommit_failure(", 25,
         "shared baseline/delegated precommit case inventory changed"),
        ("failed|=test_run_delegated_success(", 5,
         "delegated success case inventory changed"),
        ("failed|=test_delegated_failure_is_exact_committed_prefix();", 1,
         "delegated committed-prefix case inventory changed"),
        ("failed|=test_expect_delegated_validation_failure(", 15,
         "delegate-specific boundary case inventory changed"),
    )
    for fragment, expected_count, message in case_inventory:
        if compact.count(fragment) != expected_count:
            findings.append(message)
    for kind in STEP_KINDS:
        if kind not in compact:
            findings.append(f"runtime typed-step oracle missing: {kind}")
    if not re.search(r"\b(?:[1-9][0-9]*)/[1-9][0-9]* cases passed\b", text):
        findings.append("runtime success marker changed")
    total_cases = (
        compact.count("failed|=test_run_success(") +
        compact.count("returntest_run_success(") +
        2 * compact.count("failed|=test_expect_precommit_failure(") +
        compact.count("failed|=test_run_delegated_success(") +
        compact.count(
            "failed|=test_delegated_failure_is_exact_committed_prefix();"
        ) +
        compact.count("failed|=test_expect_delegated_validation_failure(")
    )
    if total_cases != 76:
        findings.append("runtime case total is not structurally 76")
    if "76/76 cases passed" not in text:
        findings.append("expanded delegated runtime success marker missing")
    findings.extend(_banned_findings(code, source=False))
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings = []
    if _sha256(data) != EXPECTED_PROVENANCE_SHA256:
        findings.append("suffix provenance exact digest changed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"suffix provenance is not UTF-8: {error}"]
    compact = _compact(text)
    markers = (
        "SUFFIX_VA=0x100DF46D",
        "SUFFIX_END_VA=0x100DF4F0",
        "SUFFIX_RAW_OFFSET=0x000DE86D",
        'SUFFIX_SHA256="27ee666d2327c9360be2f4175ee5ea58bf49e112a6a29af6760451d6a7341b75"',
        "GLOBAL_RECEIVER_VA=0x119F3140",
        "OWNER_VTABLE_FIELD_OFFSET=0x874",
        "SELECTOR=2",
        "FINAL_MARKER=0x4E3B",
        "DIRECT_CALL_OFFSETS=(0x0D,0x15,0x1C,0x3E,0x45,0x4C,0x53)",
        "DIRECT_CALL_TARGETS=(0x100E8240,0x100F2750,0x100EA4D0,"
        "0x101046D0,0x101046D0,0x101046D0,0x101046D0,)",
        "OWNER_VTABLE_VA=0x1173DC18",
        "SELECTOR_VIRTUAL_TARGET=0x100D7CB0",
        "CRASH_RECORD_RETURN_VA=0x100E825F",
        'CRASH_RECORD_RETURN_BYTES=bytes.fromhex("b8383a9f1183c40cc3")',
        "CRASH_RECORD_IDENTITY=0x119F3A38",
        "CRASH_RECORD_EARLY_REJOIN_VA=0x100E827C",
        "CRASH_RECORD_FINAL_REJOIN_VA=0x100E8371",
        "CONDITIONAL_ARGUMENTS=(0x2D,0x12,0x16,0x21)",
        "EPILOGUE_OFFSET=0x74",
    )
    for marker in markers:
        if marker not in compact:
            findings.append(f"provenance authority marker changed: {marker[:76]}")
    if len(re.findall(r"^\s+def test_", text, flags=re.MULTILINE)) != 9:
        findings.append("provenance must retain nine independent assertions")
    for banned in ("ctypes", "subprocess", "WinDLL", "CDLL", "os.system"):
        if banned in text:
            findings.append(f"provenance must remain data-only: {banned}")
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
    """Allow an absent slice; once introduced, require complete containment."""
    slice_tokens = (LIBRARY, TEST_TARGET, *CMAKE_FILES, *CMAKE_TESTS)
    present = [token for token in slice_tokens if token in text]
    if not present:
        return []
    findings: list[str] = []
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    for token in slice_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake suffix token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake suffix token escapes BUILD_TESTING: {token}")
    scoped = _compact("\n".join(lines[start + 1:end]))
    exact_library = (
        f"add_library({LIBRARY}STATIC"
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100df270_suffix_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100df270_suffix_transcript.c")'
    )
    if scoped.count(exact_library) != 1:
        findings.append("suffix must be an exact BUILD_TESTING-only static library")
    for fragment, message in (
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "suffix C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "suffix hardened compile options changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_suffix_transcript.c")',
         "suffix runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated runtime test must link only its suffix library"),
        (f"target_link_libraries({LIBRARY}PUBLICrome2_guest32_runtime)",
         "suffix core must link exactly its shared guest32 dependency"),
    ):
        if scoped.count(fragment) != 1:
            findings.append(message)
    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = []
    own_dependencies = []
    for command in link_commands:
        words = re.split(r"\s+", command.strip())
        if not words:
            continue
        target = words[0]
        if target == LIBRARY:
            own_dependencies.append(words)
        elif LIBRARY in words:
            consumers.append(target)
    if own_dependencies != [[LIBRARY, "PUBLIC", "rome2_guest32_runtime"]]:
        findings.append(
            "suffix core dependency must be exactly PUBLIC rome2_guest32_runtime"
        )
    allowed_consumers = {
        TEST_TARGET, "rome2_headless64", PARENT_LIBRARY,
        NONEMPTY_PARENT_LIBRARY,
    }
    if set(consumers) != allowed_consumers:
        findings.append("suffix library has an unexpected or missing consumer")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(),
        "rome2_100df270_suffix_transcript",
        "ported_100df270_suffix_transcript",
        "100df270_suffix_transcript",
    ):
        if token in lowered:
            findings.append(f"test-only suffix token escaped exports: {token}")
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
    parser.add_argument("--cmake", type=pathlib.Path)
    parser.add_argument("--export-manifest", type=pathlib.Path)
    parser.add_argument("--legacy-def", type=pathlib.Path)
    parser.add_argument("--probe-def", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "test": (args.test, inspect_test_text),
    }
    for label, path in (
        ("cmake", args.cmake),
        ("export_manifest", args.export_manifest),
        ("legacy_def", args.legacy_def),
        ("probe_def", args.probe_def),
    ):
        if path is not None:
            requested[label] = (
                path,
                inspect_cmake_text if label == "cmake" else inspect_exports_text,
            )
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, (path, inspector) in requested.items():
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            findings = [f"cannot resolve file: {error}"]
            resolved = path.resolve()
        else:
            findings = _inspect_path(resolved, inspector)
        total += len(findings)
        report["files"][label] = {
            "path": str(resolved),
            "findings": findings,
        }
    try:
        provenance_path = args.transcript_provenance.resolve(strict=True)
        provenance_findings = inspect_provenance_bytes(provenance_path.read_bytes())
    except OSError as error:
        provenance_path = args.transcript_provenance.resolve()
        provenance_findings = [f"cannot read transcript provenance: {error}"]
    total += len(provenance_findings)
    report["files"]["transcript_provenance"] = {
        "path": str(provenance_path),
        "findings": provenance_findings,
    }
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
