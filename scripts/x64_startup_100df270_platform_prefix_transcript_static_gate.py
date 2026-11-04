#!/usr/bin/env python3
"""Fail-closed containment gate for the 0x100df270 platform-prefix transcript."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"
TEST_TARGET = "rome2_startup_100df270_platform_prefix_transcript_tests"
HEADLESS_TARGET = "rome2_headless64"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
NONEMPTY_PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
HEADLESS_TOKEN = (
    "startup-100df270-platform-prefix=injected-call-shape-complete"
)
TERMINAL_FIXTURE = (
    "startup_100df270_platform_prefix_transcript_reload_verified"
)
PREDECESSOR_FIXTURE = "startup_100df270_suffix_transcript_reload_verified"
COMPOSED_TERMINAL_FIXTURE = "startup_100ed471_ordinary_lifecycle_reload_verified"
EXPECTED_CTEST_COUNT = 194
EXPECTED_CMAKE_SIZE = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

EXPECTED_HEADER_SHA256 = (
    "a5f5f7c37053242ee0284c6b0dd437499253a9a05a5332bae78ead9527f99de9"
)
EXPECTED_SOURCE_SHA256 = (
    "e1d51964caf7d69399548b7716e5c4cfe0c3d6b59701c01bb7f88f89555ad55a"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "64822bfafd6fb2b4040128e53f0c99c5bf6bc3de60ffd71b0c98caca94b01ae1"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "b7f4578afd44d3de500b667062d0cd136e513db44a2ba22710648e63e35d4966"
)

STEP_KINDS = (
    "ROME2_100DF270_PREFIX_STEP_LOAD_TITLE",
    "ROME2_100DF270_PREFIX_STEP_LOAD_NAME",
    "ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME",
    "ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX",
    "ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR",
    "ROME2_100DF270_PREFIX_STEP_FORMAT_DUPLICATE_MESSAGE",
    "ROME2_100DF270_PREFIX_STEP_SHOW_DUPLICATE_MESSAGE",
    "ROME2_100DF270_PREFIX_STEP_TERMINATE_PROCESS",
    "ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS",
    "ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS",
)

VALUE_KINDS = (
    "ROME2_100DF270_PREFIX_VALUE_NONE",
    "ROME2_100DF270_PREFIX_VALUE_SCALAR",
    "ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY",
    "ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY",
    "ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER",
    "ROME2_100DF270_PREFIX_VALUE_OPAQUE32",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "EnterCriticalSection", "ExitProcess", "FreeLibrary",
    "GetCurrentThreadId", "GetLastError", "GetMessageA", "GetMessageW",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "LoadStringA", "LoadStringW",
    "MessageBoxA", "MessageBoxW", "PeekMessageA", "PeekMessageW",
    "PostMessageA", "PostMessageW", "RegOpenKeyExW", "SendMessageA",
    "SendMessageW", "SteamInternal_ContextInit", "SystemParametersInfoA",
    "SystemParametersInfoW", "TerminateProcess", "TlsAlloc", "TlsFree",
    "TlsGetValue", "TlsSetValue", "TranslateMessage", "VirtualAlloc",
    "VirtualFree", "calloc", "dlopen", "dlsym", "free", "malloc",
    "realloc", "system", "wcslen", "wcscpy", "swprintf",
}

CMAKE_FILES = (
    "ported_100df270_platform_prefix_transcript.h",
    "ported_100df270_platform_prefix_transcript.c",
    "test_startup_100df270_platform_prefix_transcript.c",
    "test_x64_startup_100df270_platform_prefix_transcript_provenance.py",
    "test_x64_startup_100df270_platform_prefix_transcript_static_gate.py",
    "x64_startup_100df270_platform_prefix_transcript_static_gate.py",
)

CMAKE_TESTS = (
    "startup_100df270_platform_prefix_transcript_provenance",
    "startup_100df270_platform_prefix_transcript_static_gate_unit",
    "startup_100df270_platform_prefix_transcript_static_gate",
    "startup_100df270_platform_prefix_transcript_runtime",
    "startup_100df270_platform_prefix_transcript_post_pe_gate",
    "x64_bootstrap_load_after_startup_100df270_platform_prefix_transcript",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return "".join(text.split())


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
    if _sha256(text.encode("utf-8")) != expected_exact:
        findings.append(f"{label} exact digest changed")
    if _token_digest(code) != expected_tokens:
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


def _banned_findings(text: str, code: str, *, source: bool) -> list[str]:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    findings = [
        f"forbidden native/allocator/platform identifier: {identifier}"
        for identifier in sorted(BANNED_IDENTIFIERS & identifiers)
    ]
    if re.search(r"\b_?DAT_[0-9A-Fa-f]+\b", code):
        findings.append("original process-global identifier is forbidden")
    if re.search(r"\b(?:decomp_fn|FUN|sub)_[0-9A-Fa-f]+\b", code):
        findings.append("recovered/native implementation call is forbidden")
    if not source:
        return findings

    compact = _compact(code).lower()
    if "#pragmacomment(lib" in compact:
        findings.append("native library autolinking is forbidden")
    if re.search(r"(?:^|[^A-Za-z0-9_])(?:L|u|U|u8)?\s*\"", "\n".join(
        line for line in text.splitlines()
        if not re.match(r"\s*#\s*include\b", line)
    )):
        findings.append("native/local strings must not be fabricated")
    if re.search(r"\bwchar_t\b", code):
        findings.append("native/local wide strings must not be fabricated")
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
    if re.search(r"\bROME2_PORT_100DF270_PREFIX_TARGET_[A-F0-9]+\b", code):
        findings.append("original target identities must not enter executable source")
    for target in (
        "0x100edfe0", "0x100f3880", "0x10102850", "0x1172f66c",
        "0x1172f17c", "0x1172f69c", "0x1172f6a8", "0x1173f208",
        "0x1173f460", "0x1173f4a0", "0x1173f440", "0x119f3854",
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
        r"(?:char|wchar_t|int|unsigned|size_t|uintptr_t|"
        r"uint(?:8|16|32|64)_t|rome2_guest_addr32)\s+[A-Za-z_]\w*"
        r"(?:\s*\[[^]]*\])?\s*(?:=[^;]*)?;",
        code,
    ):
        prefix = code[:match.start()]
        if prefix.count("{") == prefix.count("}"):
            findings.append("file-scope process/string data is forbidden")
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
        ("ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT", "7",
         "normal seven-step count changed"),
        ("ROME2_PORT_100DF270_PREFIX_DUPLICATE_STEP_COUNT", "10",
         "duplicate ten-step count changed"),
        ("ROME2_PORT_100DF270_PREFIX_RECEIVER_BYTES", "0x80c",
         "receiver 0x80c-byte span changed"),
        ("ROME2_PORT_100DF270_PREFIX_PACKET_BYTES", "0x2d",
         "packet 0x2d-byte span changed"),
        ("ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET", "0x04",
         "receiver instance +0x04 offset changed"),
        ("ROME2_PORT_100DF270_PREFIX_NAME_OFFSET", "0x08",
         "receiver name +0x08 offset changed"),
        ("ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET", "0x408",
         "receiver title +0x408 offset changed"),
        ("ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET", "0x808",
         "receiver mutex +0x808 offset changed"),
        ("ROME2_PORT_100DF270_PREFIX_ALLOW_DUPLICATE_OFFSET", "0x2c",
         "packet duplicate-policy +0x2c offset changed"),
        ("ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE", "0x1173f208",
         "initial vtable identity changed"),
        ("ROME2_PORT_100DF270_PREFIX_MUTEX_FORMAT", "0x1173f460",
         "mutex-format identity changed"),
        ("ROME2_PORT_100DF270_PREFIX_DUPLICATE_FORMAT", "0x1173f4a0",
         "duplicate-format identity changed"),
        ("ROME2_PORT_100DF270_PREFIX_MUTEX_CAPTION", "0x1173f440",
         "mutex-caption identity changed"),
        ("ROME2_PORT_100DF270_PREFIX_MOUSE_TRAILS_GLOBAL", "0x119f3854",
         "mouse-trails global identity changed"),
        ("ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE", "0x6d",
         "title resource ID changed"),
        ("ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME", "0x67",
         "name resource ID changed"),
        ("ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY", "0x200",
         "UTF-16 capacity changed"),
        ("ROME2_PORT_100DF270_PREFIX_ERROR_ALREADY_EXISTS", "0xb7",
         "ERROR_ALREADY_EXISTS value changed"),
        ("ROME2_PORT_100DF270_PREFIX_SPI_GETMOUSETRAILS", "0x5e",
         "GETMOUSETRAILS action changed"),
        ("ROME2_PORT_100DF270_PREFIX_SPI_SETMOUSETRAILS", "0x5d",
         "SETMOUSETRAILS action changed"),
        ("ROME2_PORT_100DF270_PREFIX_MESSAGEBOX_FLAGS", "0x10",
         "message-box flags changed"),
        ("ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID", "1",
         "local-buffer identity changed"),
    )
    for name, value, message in macros:
        _require_once(compact, f"#define{name}UINT32_C({value})", findings, message)

    evidence = (
        ("IAT_LOADSTRINGW", "0x1172f66c"),
        ("IAT_CREATEMUTEXW", "0x1172f17c"),
        ("IAT_MESSAGEBOXW", "0x1172f69c"),
        ("IAT_SYSTEMPARAMETERSINFOW", "0x1172f6a8"),
        ("TARGET_100EDFE0", "0x100edfe0"),
        ("TARGET_100F3880", "0x100f3880"),
        ("TARGET_10102850", "0x10102850"),
    )
    for suffix, value in evidence:
        _require_once(
            compact,
            f"#defineROME2_PORT_100DF270_PREFIX_{suffix}UINT32_C({value})",
            findings,
            f"callee evidence identity changed: {suffix.lower()}",
        )

    step_enum = (
        "typedefenumrome2_100df270_prefix_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100df270_prefix_step_kind;"
    )
    _require_once(compact, step_enum, findings, "typed ten-kind step order changed")
    value_enum = (
        "typedefenumrome2_100df270_prefix_value_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(VALUE_KINDS))
        + "}rome2_100df270_prefix_value_kind;"
    )
    _require_once(compact, value_enum, findings, "typed six-kind value domain changed")
    value_type = (
        "typedefstructrome2_100df270_prefix_value{"
        "rome2_100df270_prefix_value_kindkind;uint32_tvalue;}"
        "rome2_100df270_prefix_value;"
    )
    _require_once(compact, value_type, findings, "typed value layout changed")
    step_type = (
        "typedefstructrome2_100df270_prefix_step{"
        "rome2_100df270_prefix_step_kindkind;uint32_targument_count;"
        "rome2_100df270_prefix_valueargument0;"
        "rome2_100df270_prefix_valueargument1;"
        "rome2_100df270_prefix_valueargument2;"
        "rome2_100df270_prefix_valueargument3;uint32_tresult_count;"
        "rome2_100df270_prefix_valueresult0;}rome2_100df270_prefix_step;"
    )
    _require_once(compact, step_type, findings, "typed step payload layout changed")
    callback_type = (
        "typedefvoid(*rome2_100df270_prefix_emit_step_fn)("
        "void*context,rome2_100df270_prefix_stepstep);"
    )
    _require_once(compact, callback_type, findings, "by-value callback contract changed")
    effects_type = (
        "typedefstructrome2_100df270_prefix_effects{"
        "rome2_100df270_prefix_emit_step_fnemit_step;void*context;"
        "uint32_tcreated_mutex;uint32_tlast_error;}"
        "rome2_100df270_prefix_effects;"
    )
    _require_once(compact, effects_type, findings, "injected effects layout changed")
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "constrome2_guest_write_view*state_view,"
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_packet,"
        "constrome2_100df270_prefix_effects*effects,"
        "rome2_guest_addr32*return_receiver_out);"
    )
    _require_once(compact, declaration, findings, "public bounded prefix API changed")
    findings.extend(_banned_findings(text, code, source=False))
    return sorted(set(findings))


def _value(kind: str, value: str) -> str:
    return (
        "rome2_100df270_prefix_make_value("
        f"ROME2_100DF270_PREFIX_VALUE_{kind},{value})"
    )


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
    allowed = {
        "ported_100df270_platform_prefix_transcript.h", "limits.h",
        "stddef.h", "stdint.h",
    }
    if (
        not includes
        or includes[0] != "ported_100df270_platform_prefix_transcript.h"
        or set(includes) - allowed
        or len(includes) != len(set(includes))
    ):
        findings.append("source include containment changed")
    findings.extend(_banned_findings(text, code, source=True))

    helper_contracts = (
        ("#defineROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest32 address-space ceiling changed"),
        ("typedefstructrome2_100df270_prefix_span{uint64_tguest_start;"
         "uintptr_thost_start;uint64_tbyte_count;uint64_tview_offset;}"
         "rome2_100df270_prefix_span;", "checked mapped-span layout changed"),
        ("view->host_base==NULL", "state host-base validation changed"),
        ("view->byte_count>ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE||"
         "(uint64_t)view->guest_base+view->byte_count>"
         "ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE",
         "guest interval overflow validation changed"),
        ("view->byte_count-UINT64_C(1)>"
         "(uint64_t)(UINTPTR_MAX-host_address)",
         "host interval overflow validation changed"),
        ("guest_start.value==0", "guest-span null validation changed"),
        ("(uint64_t)byte_count>ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE-"
         "(uint64_t)guest_start.value", "guest-span overflow validation changed"),
        ("guest_start.value<view->guest_base",
         "guest-span lower-bound validation changed"),
        ("offset>view->byte_count||(uint64_t)byte_count>"
         "view->byte_count-offset||offset>(uint64_t)SIZE_MAX",
         "complete guest-span validation changed"),
        ("span_out->guest_start=(uint64_t)guest_start.value;"
         "span_out->host_start=(uintptr_t)view->host_base+(uintptr_t)offset;"
         "span_out->byte_count=(uint64_t)byte_count;span_out->view_offset=offset;",
         "guest-span projection changed"),
        ("step->argument0=rome2_100df270_prefix_make_value("
         "ROME2_100DF270_PREFIX_VALUE_NONE,UINT32_C(0));"
         "step->argument1=step->argument0;step->argument2=step->argument0;"
         "step->argument3=step->argument0;step->result_count=UINT32_C(0);"
         "step->result0=step->argument0;", "typed step clearing changed"),
    )
    for fragment, message in helper_contracts:
        if fragment not in compact:
            findings.append(message)
    read_helper = (
        "return(uint32_t)bytes[0]|((uint32_t)bytes[1]<<8)|"
        "((uint32_t)bytes[2]<<16)|((uint32_t)bytes[3]<<24);"
    )
    write_helper = (
        "bytes[0]=(uint8_t)value;bytes[1]=(uint8_t)(value>>8);"
        "bytes[2]=(uint8_t)(value>>16);bytes[3]=(uint8_t)(value>>24);"
    )
    if compact.count(read_helper) != 1:
        findings.append("unaligned-safe packet instance read changed")
    if compact.count(write_helper) != 1:
        findings.append("unaligned-safe deterministic state write changed")

    body = _function_body(code, FUNCTION)
    if body is None:
        findings.append("bounded platform-prefix function definition is missing")
        return sorted(set(findings))
    function = _compact(body)

    required = (
        ("status=rome2_100df270_prefix_validate_object(state_view,sizeof(*state_view));",
         "state descriptor validation changed"),
        ("status=rome2_100df270_prefix_validate_object(effects,sizeof(*effects));",
         "effects descriptor validation changed"),
        ("status=rome2_100df270_prefix_validate_object(return_receiver_out,"
         "sizeof(*return_receiver_out));", "receiver output validation changed"),
        ("(uintptr_t)state_view%_Alignof(rome2_guest_write_view)!=0U||"
         "(uintptr_t)effects%_Alignof(rome2_100df270_prefix_effects)!=0U||"
         "(uintptr_t)return_receiver_out%_Alignof(rome2_guest_addr32)!=0U||"
         "rome2_100df270_prefix_controls_overlap(state_view,effects,"
         "return_receiver_out)", "control alignment/disjointness changed"),
        ("state_snapshot=*state_view;", "state-view snapshot changed"),
        ("if(rome2_100df270_prefix_backing_overlaps_controls(&state_snapshot,"
         "state_view,effects,return_receiver_out)",
         "backing/control physical disjointness changed"),
        ("effects_snapshot=*effects;", "effects snapshot changed"),
        ("effects_snapshot.emit_step==NULL||effects_snapshot.context==NULL",
         "callback/context validation changed"),
        ("guest_receiver,ROME2_PORT_100DF270_PREFIX_RECEIVER_BYTES,"
         "&receiver_span", "complete receiver-span validation changed"),
        ("guest_packet,ROME2_PORT_100DF270_PREFIX_PACKET_BYTES,&packet_span",
         "complete packet-span validation changed"),
        ("receiver_span.guest_start,receiver_span.byte_count,"
         "packet_span.guest_start,packet_span.byte_count",
         "receiver/packet logical disjointness changed"),
        ("(uint64_t)receiver_span.host_start,receiver_span.byte_count,"
         "(uint64_t)packet_span.host_start,packet_span.byte_count",
         "receiver/packet physical disjointness changed"),
        ("rome2_guest_add_checked(guest_receiver,"
         "ROME2_PORT_100DF270_PREFIX_NAME_OFFSET,&guest_name)",
         "checked receiver +0x08 derivation changed"),
        ("rome2_guest_add_checked(guest_receiver,"
         "ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET,&guest_title)",
         "checked receiver +0x408 derivation changed"),
        ("rome2_guest_add_checked(guest_receiver,"
         "ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,&guest_mutex)",
         "checked receiver +0x808 derivation changed"),
        ("instance_value=rome2_100df270_prefix_read_u32_le("
         "state_snapshot.host_base+(size_t)packet_span.view_offset);",
         "packet instance snapshot changed"),
        ("allow_duplicate=state_snapshot.host_base["
         "(size_t)packet_span.view_offset+"
         "(size_t)ROME2_PORT_100DF270_PREFIX_ALLOW_DUPLICATE_OFFSET];",
         "packet duplicate-policy snapshot changed"),
    )
    for fragment, message in required:
        if fragment not in function:
            findings.append(message)

    first_emit = function.find("effects_snapshot.emit_step(")
    if first_emit < 0:
        findings.append("transcript never emits an injected step")
    validation_markers = (
        "validate_object(state_view", "validate_object(effects",
        "validate_object(return_receiver_out", "controls_overlap(",
        "state_snapshot=*state_view", "validate_interval(&state_snapshot)",
        "backing_overlaps_controls(", "effects_snapshot=*effects",
        "resolve_span(&state_snapshot,guest_receiver",
        "resolve_span(&state_snapshot,guest_packet", "ranges_overlap(",
        "rome2_guest_add_checked(guest_receiver", "instance_value=",
        "allow_duplicate=",
    )
    for marker in validation_markers:
        position = function.find(marker)
        if position < 0 or (first_emit >= 0 and position >= first_emit):
            findings.append(f"pre-callback validation/snapshot changed: {marker}")
    _require_in_order(
        function,
        (
            "validate_object(state_view", "validate_object(effects",
            "validate_object(return_receiver_out", "controls_overlap(",
            "state_snapshot=*state_view", "validate_interval(&state_snapshot)",
            "backing_overlaps_controls(", "effects_snapshot=*effects",
            "resolve_span(&state_snapshot,guest_receiver",
            "resolve_span(&state_snapshot,guest_packet", "ranges_overlap(",
            "rome2_guest_add_checked(guest_receiver,"
            "ROME2_PORT_100DF270_PREFIX_NAME_OFFSET",
            "rome2_guest_add_checked(guest_receiver,"
            "ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET",
            "rome2_guest_add_checked(guest_receiver,"
            "ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET",
            "instance_value=", "allow_duplicate=", "write_u32_le(",
            "effects_snapshot.emit_step(",
        ),
        findings,
        "complete validation/snapshot and initial writes must precede callbacks",
    )

    step_blocks = (
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_LOAD_TITLE);step.argument_count=UINT32_C(4);"
        "step.argument0=" + _value("OPAQUE32", "instance_value") + ";"
        "step.argument1=" + _value(
            "SCALAR", "ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE"
        ) + ";step.argument2=" + _value("GUEST_IDENTITY", "guest_title.value") + ";"
        "step.argument3=" + _value(
            "SCALAR", "ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY"
        ) + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_LOAD_NAME);step.argument_count=UINT32_C(4);"
        "step.argument0=" + _value("OPAQUE32", "instance_value") + ";"
        "step.argument1=" + _value(
            "SCALAR", "ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME"
        ) + ";step.argument2=" + _value("GUEST_IDENTITY", "guest_name.value") + ";"
        "step.argument3=" + _value(
            "SCALAR", "ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY"
        ) + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME);"
        "step.argument_count=UINT32_C(4);step.argument0="
        + _value("LOCAL_BUFFER", "ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID")
        + ";step.argument1="
        + _value("SCALAR", "ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY")
        + ";step.argument2="
        + _value("ORIGINAL_IDENTITY", "ROME2_PORT_100DF270_PREFIX_MUTEX_FORMAT")
        + ";step.argument3=" + _value("GUEST_IDENTITY", "guest_name.value")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX);"
        "step.argument_count=UINT32_C(3);step.argument0="
        + _value("SCALAR", "UINT32_C(0)") + ";step.argument1="
        + _value("SCALAR", "UINT32_C(1)") + ";step.argument2="
        + _value("LOCAL_BUFFER", "ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID")
        + ";step.result_count=UINT32_C(1);step.result0="
        + _value("OPAQUE32", "effects_snapshot.created_mutex")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR);"
        "step.result_count=UINT32_C(1);step.result0="
        + _value("SCALAR", "effects_snapshot.last_error")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS);"
        "step.argument_count=UINT32_C(4);step.argument0="
        + _value("SCALAR", "ROME2_PORT_100DF270_PREFIX_SPI_GETMOUSETRAILS")
        + ";step.argument1=" + _value("SCALAR", "UINT32_C(0)")
        + ";step.argument2="
        + _value(
            "ORIGINAL_IDENTITY",
            "ROME2_PORT_100DF270_PREFIX_MOUSE_TRAILS_GLOBAL",
        )
        + ";step.argument3=" + _value("SCALAR", "UINT32_C(0)")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS);"
        "step.argument_count=UINT32_C(4);step.argument0="
        + _value("SCALAR", "ROME2_PORT_100DF270_PREFIX_SPI_SETMOUSETRAILS")
        + ";step.argument1=" + _value("SCALAR", "UINT32_C(0)")
        + ";step.argument2=" + _value("SCALAR", "UINT32_C(0)")
        + ";step.argument3=" + _value("SCALAR", "UINT32_C(0)")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);",
    )
    for index, block in enumerate(step_blocks, 1):
        if function.count(block) != 1:
            findings.append(f"exact normal-route step payload changed: {index}")
    _require_in_order(
        function, step_blocks, findings, "normal seven-step chronological order changed"
    )

    duplicate_block = (
        "if(effects_snapshot.last_error=="
        "ROME2_PORT_100DF270_PREFIX_ERROR_ALREADY_EXISTS&&"
        "allow_duplicate==UINT8_C(0)){"
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_FORMAT_DUPLICATE_MESSAGE);"
        "step.argument_count=UINT32_C(4);step.argument0="
        + _value("LOCAL_BUFFER", "ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID")
        + ";step.argument1="
        + _value("SCALAR", "ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY")
        + ";step.argument2="
        + _value(
            "ORIGINAL_IDENTITY", "ROME2_PORT_100DF270_PREFIX_DUPLICATE_FORMAT"
        )
        + ";step.argument3=" + _value("GUEST_IDENTITY", "guest_name.value")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);"
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_SHOW_DUPLICATE_MESSAGE);"
        "step.argument_count=UINT32_C(4);step.argument0="
        + _value("SCALAR", "UINT32_C(0)") + ";step.argument1="
        + _value("LOCAL_BUFFER", "ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID")
        + ";step.argument2="
        + _value("ORIGINAL_IDENTITY", "ROME2_PORT_100DF270_PREFIX_MUTEX_CAPTION")
        + ";step.argument3="
        + _value("SCALAR", "ROME2_PORT_100DF270_PREFIX_MESSAGEBOX_FLAGS")
        + ";effects_snapshot.emit_step(effects_snapshot.context,step);"
        "rome2_100df270_prefix_clear_step(&step,"
        "ROME2_100DF270_PREFIX_STEP_TERMINATE_PROCESS);"
        "effects_snapshot.emit_step(effects_snapshot.context,step);}"
    )
    if function.count(duplicate_block) != 1:
        findings.append("duplicate-only exact three-step route changed")

    first_emit = function.find("effects_snapshot.emit_step(")
    first_write = function.find("rome2_100df270_prefix_write_u32_le(")
    second_write = function.find("rome2_100df270_prefix_write_u32_le(", first_write + 1)
    create_kind = function.find(
        "ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX"
    )
    create_emit = function.find("effects_snapshot.emit_step(", create_kind)
    mutex_write = function.find(
        "rome2_100df270_prefix_write_u32_le(", second_write + 1
    )
    last_error_kind = function.find(
        "ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR"
    )
    last_emit = function.rfind("effects_snapshot.emit_step(")
    output_writes = [
        match.start() for match in re.finditer(
            r"(?:\*return_receiver_out|return_receiver_out->value)=", function
        )
    ]
    if not (0 <= first_write < second_write < first_emit):
        findings.append("instance/vtable writes must precede the first callback")
    initial_writes = (
        "rome2_100df270_prefix_write_u32_le("
        "state_snapshot.host_base+(size_t)receiver_span.view_offset+"
        "(size_t)ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET,instance_value);"
        "rome2_100df270_prefix_write_u32_le("
        "state_snapshot.host_base+(size_t)receiver_span.view_offset,"
        "ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE);"
    )
    if function.count(initial_writes) != 1:
        findings.append("exact initial instance/vtable state writes changed")
    mutex_write_block = (
        "rome2_100df270_prefix_write_u32_le("
        "state_snapshot.host_base+(size_t)receiver_span.view_offset+"
        "(size_t)ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,"
        "effects_snapshot.created_mutex);"
    )
    if function.count(mutex_write_block) != 1:
        findings.append("exact injected mutex state write changed")
    if not (0 <= create_kind < create_emit < mutex_write < last_error_kind):
        findings.append("CREATE callback, mutex write, and last-error order changed")
    if len(output_writes) != 1 or output_writes[0] <= last_emit:
        findings.append("receiver output must commit once after the final callback")
    if function.count("return_receiver_out->value=guest_receiver.value;") != 1:
        findings.append("receiver output value changed")
    if function.count("effects->") != 0:
        findings.append("live effects must not be reread after snapshot")
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


def _link_commands(text: str) -> list[list[str]]:
    commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    return [re.split(r"\s+", command.strip()) for command in commands]


def inspect_cmake_text(text: str) -> list[str]:
    """Require the complete BUILD_TESTING-only integration; absence is failure."""
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_CMAKE_SIZE:
        findings.append("CMake byte size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_CMAKE_SHA256:
        findings.append("CMake exact digest changed")
    if len(re.findall(r"\badd_test\s*\(", text)) != EXPECTED_CTEST_COUNT:
        findings.append("CMake add_test declaration count must remain 194")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    slice_tokens = (LIBRARY, TEST_TARGET, *CMAKE_FILES, *CMAKE_TESTS)
    for token in slice_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake platform-prefix token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(
                f"CMake platform-prefix token escapes BUILD_TESTING: {token}"
            )
    scoped = _compact("\n".join(lines[start + 1:end]))
    exact_library = (
        f"add_library({LIBRARY}STATIC"
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100df270_platform_prefix_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100df270_platform_prefix_transcript.c")'
    )
    requirements = (
        (exact_library, "platform-prefix must be an exact static test-only library"),
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "platform-prefix C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "platform-prefix hardened compile options changed"),
        (f"target_link_libraries({LIBRARY}PUBLICrome2_guest32_runtime)",
         "platform-prefix core shared guest32 dependency changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_platform_prefix_transcript.c")',
         "platform-prefix runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated runtime test must link only its platform-prefix library"),
    )
    for fragment, message in requirements:
        if scoped.count(fragment) != 1:
            findings.append(message)
    gate_inputs = (
        ('--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
         "platform-prefix gate must inspect the headless consumer"),
        ('--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/'
         'export_manifest.tsv"',
         "platform-prefix gate must inspect the export manifest"),
        ('--export-contract"${CMAKE_CURRENT_SOURCE_DIR}/docs/'
         'x64_export_contract.md"',
         "platform-prefix gate must inspect the export contract"),
        ('--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/'
         'empire.retail.exports.def"',
         "platform-prefix gate must inspect the legacy DEF"),
        ('--bootstrap-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/'
         'empire_bootstrap.def"',
         "platform-prefix gate must inspect the bootstrap DEF"),
        ('--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/'
         'probe_exports.def"',
         "platform-prefix gate must inspect the probe DEF"),
    )
    for fragment, message in gate_inputs:
        if fragment not in scoped:
            findings.append(message)

    commands = _link_commands(text)
    own_dependencies = [words for words in commands if words and words[0] == LIBRARY]
    consumers = [
        words[0] for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if own_dependencies != [[LIBRARY, "PUBLIC", "rome2_guest32_runtime"]]:
        findings.append(
            "platform-prefix dependency must be exactly PUBLIC rome2_guest32_runtime"
        )
    if set(consumers) != {
        TEST_TARGET, HEADLESS_TARGET, PARENT_LIBRARY, NONEMPTY_PARENT_LIBRARY,
    }:
        findings.append(
            "platform-prefix library consumers must be exactly runtime test, "
            "headless, empty-preloop parent, and nonempty parent"
        )

    headless_commands = [
        words for words in commands if words and words[0] == HEADLESS_TARGET
    ]
    if len(headless_commands) != 1:
        findings.append("headless must have one direct link command")
    else:
        words = headless_commands[0]
        try:
            suffix_index = words.index(
                "rome2_startup_100df270_suffix_transcript_runtime"
            )
            prefix_index = words.index(LIBRARY)
            parent_index = words.index(PARENT_LIBRARY)
            lifecycle_index = words.index(LIFECYCLE_LIBRARY)
        except ValueError:
            findings.append(
                "headless suffix-to-prefix-to-parent direct link tail is missing"
            )
        else:
            if (
                prefix_index != suffix_index + 1
                or parent_index != prefix_index + 1
                or lifecycle_index != parent_index + 1
                or lifecycle_index != len(words) - 1
            ):
                findings.append(
                    "platform-prefix must precede the parent and final lifecycle links after suffix"
                )

    fixture_requirements = (
        (
            "startup_100df270_platform_prefix_transcript_runtimePROPERTIES"
            "FIXTURES_REQUIRED\"" + PREDECESSOR_FIXTURE + ";"
            "startup_100df270_platform_prefix_transcript_provenance_verified;"
            "startup_100df270_platform_prefix_transcript_static_verified\""
            "FIXTURES_SETUPstartup_100df270_platform_prefix_transcript_runtime_verified",
            "prefix runtime fixture must follow suffix reload plus its own gates",
        ),
        (
            "startup_100df270_platform_prefix_transcript_post_pe_gatePROPERTIES"
            "FIXTURES_REQUIRED\"startup_100df270_platform_prefix_transcript_runtime_verified;"
            "entry_policy_probe_pe_tool_verified\""
            "FIXTURES_SETUPstartup_100df270_platform_prefix_transcript_post_verified",
            "prefix post-PE fixture chain changed",
        ),
        (
            "x64_bootstrap_load_after_startup_100df270_platform_prefix_transcript"
            "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
            "startup_100df270_platform_prefix_transcript_post_verified\""
            "FIXTURES_SETUP" + TERMINAL_FIXTURE,
            "prefix terminal reload fixture chain changed",
        ),
    )
    for fragment, message in fixture_requirements:
        if fragment not in scoped:
            findings.append(message)
    if (
        'FIXTURES_REQUIRED"entry_policy_provenance_verified;'
        'entry_policy_static_verified;' + COMPOSED_TERMINAL_FIXTURE + '"'
        not in scoped
    ):
        findings.append("composed lifecycle must require parent terminal fixture")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    include = '#include "ported_100df270_platform_prefix_transcript.h"'
    if text.count(include) != 1:
        findings.append("headless platform-prefix public include is missing or duplicated")
    if re.search(rf"\b{re.escape(FUNCTION)}\s*\(", code):
        findings.append("headless must not call the composed platform-prefix child directly")
    if len(re.findall(rf"\b{re.escape(PARENT_FUNCTION)}\s*\(", code)) != 1:
        findings.append("headless must call the empty-preloop parent exactly once")
    if len(re.findall(rf"\b{re.escape(LIFECYCLE_FUNCTION)}\s*\(", code)) != 1:
        findings.append("headless must call the ordinary lifecycle exactly once")
    if text.count(HEADLESS_TOKEN) != 1:
        findings.append("headless platform-prefix completion token is missing or duplicated")
    suffix_token = "startup-100df270-suffix=injected-transcript-complete"
    suffix_position = text.find(suffix_token)
    prefix_position = text.find(HEADLESS_TOKEN)
    if suffix_position < 0 or prefix_position <= suffix_position:
        findings.append("headless platform-prefix token must follow the suffix token")
    parent_token = "startup-100ed3c0-empty-preloop=injected-composition-complete"
    parent_position = text.find(parent_token)
    if parent_position <= prefix_position:
        findings.append("headless parent token must follow the platform-prefix token")
    lifecycle_token = "startup-100ed471-ordinary-lifecycle=injected-bounded-complete"
    if text.find(lifecycle_token) <= parent_position:
        findings.append("headless lifecycle token must follow the parent token")
    if compact.count("ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT") < 1:
        findings.append("headless normal seven-step oracle is missing")
    normal_kinds = STEP_KINDS[:5] + STEP_KINDS[8:]
    for kind in normal_kinds:
        if kind not in compact:
            findings.append(f"headless typed-step oracle missing: {kind}")
    findings.extend(_banned_findings(text, code, source=False))
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(),
        "rome2_100df270_prefix", "ported_100df270_platform_prefix",
        "100df270_platform_prefix", "platform-prefix-transcript",
    ):
        if token in lowered:
            findings.append(f"test-only platform-prefix token escaped exports: {token}")
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
    # The runtime and independent provenance have their own CTests.  Accept
    # their paths because the integrated invocation supplies them, while this
    # gate remains scoped to core source and containment surfaces.
    parser.add_argument("--test", type=pathlib.Path)
    parser.add_argument("--transcript-provenance", type=pathlib.Path)
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
        "cmake": (args.cmake, inspect_cmake_text),
        "headless": (args.headless, inspect_headless_text),
        "export_manifest": (args.export_manifest, inspect_exports_text),
        "export_contract": (args.export_contract, inspect_exports_text),
        "legacy_def": (args.legacy_def, inspect_exports_text),
        "bootstrap_def": (args.bootstrap_def, inspect_exports_text),
        "probe_def": (args.probe_def, inspect_exports_text),
    }
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
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
