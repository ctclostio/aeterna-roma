#!/usr/bin/env python3
"""Fail-closed containment gate for the 0x100ed3c0 empty pre-loop adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
TEST_TARGET = "rome2_startup_100ed3c0_empty_preloop_tests"
HEADLESS_TARGET = "rome2_headless64"
HEADLESS_TOKEN = "startup-100ed3c0-empty-preloop=injected-composition-complete"
LIFECYCLE_TOKEN = "startup-100ed471-ordinary-lifecycle=injected-bounded-complete"
PREDECESSOR_FIXTURE = "startup_100df270_platform_prefix_transcript_reload_verified"
PARENT_RELOAD_FIXTURE = "startup_100ed3c0_empty_preloop_reload_verified"
TERMINAL_FIXTURE = "startup_100ed471_ordinary_lifecycle_reload_verified"
EXPECTED_CTEST_COUNT = 194

EXPECTED_HEADER_SHA256 = (
    "8e0b4f400cfd5318fe9b898e11eda878cd56890670d9bb68d81a846110cba6d2"
)
EXPECTED_SOURCE_SHA256 = (
    "3fe47efd083eb28aa04b98f1307b25402f95361f5880c7079b9861184d7b617c"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "383f6cba33ea660f4a416ecb99fd1ef91035200ae6423eb164e134294d20b2c6"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "4b9c2f0cc428be4cb846d6a32ab5d133cdd889f8e0d9414f990ee5b691a4c9cb"
)
EXPECTED_PROVENANCE_SHA256 = (
    "8daac04b62793018719e97ca0ee13b8599f7d39727251f536bc6938a928b40e3"
)
EXPECTED_PROVENANCE_BYTES = 51944

REPRO_ON = "out/repro-100edd70-entry-decision-verified-on"
REPRO_OFF = "out/repro-100edd70-entry-decision-verified-off"
EXPECTED_REPRO_MANIFEST_BYTES = 6_586
EXPECTED_REPRO_MANIFEST_SHA256 = (
    "a2f5aa6ca882ad8a7e9b7fb06359b1cd0f4f2f79d8859637fc9e75c8006f4a4b"
)
EXPECTED_REPRO_VERIFIER_BYTES = 27845
EXPECTED_REPRO_VERIFIER_SHA256 = (
    "f0864d4ae529e5f623aa88257a425fd74c4a377e20aceab0f0c415385c012127"
)

STEP_KINDS = (
    "ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C8",
    "ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C5",
    "ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0",
    "ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1",
    "ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY0",
    "ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY1",
    "ROME2_100ED3C0_PRELOOP_STEP_BUILD_EMPTY_DESCRIPTOR",
    "ROME2_100ED3C0_PRELOOP_STEP_RUN_100DF270",
    "ROME2_100ED3C0_PRELOOP_STEP_CLEANUP_DESCRIPTOR",
)

VALUE_KINDS = (
    "ROME2_100ED3C0_PRELOOP_VALUE_NONE",
    "ROME2_100ED3C0_PRELOOP_VALUE_SCALAR",
    "ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY",
    "ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY",
    "ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY",
    "ROME2_100ED3C0_PRELOOP_VALUE_OPAQUE32",
)

CHILD_LIBRARIES = (
    "rome2_startup_100f1c10_runtime",
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100df270_suffix_transcript_runtime",
    "rome2_startup_100df270_platform_prefix_transcript_runtime",
)

CMAKE_FILES = (
    "ported_100ed3c0_empty_preloop.h",
    "ported_100ed3c0_empty_preloop.c",
    "test_startup_100ed3c0_empty_preloop.c",
    "test_x64_startup_100ed3c0_preloop_transcript_provenance.py",
    "test_x64_startup_100ed3c0_empty_preloop_static_gate.py",
    "x64_startup_100ed3c0_empty_preloop_static_gate.py",
)

CMAKE_TESTS = (
    "startup_100ed3c0_empty_preloop_provenance",
    "startup_100ed3c0_empty_preloop_static_gate_unit",
    "startup_100ed3c0_empty_preloop_static_gate",
    "startup_100ed3c0_empty_preloop_runtime",
    "startup_100ed3c0_empty_preloop_post_pe_gate",
    "x64_bootstrap_load_after_startup_100ed3c0_empty_preloop",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetLastError", "GetProcAddress", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "LoadStringA",
    "LoadStringW", "MessageBoxA", "MessageBoxW", "RegOpenKeyExW",
    "SteamInternal_ContextInit", "SystemParametersInfoA",
    "SystemParametersInfoW", "TerminateProcess", "TlsAlloc", "TlsFree",
    "TlsGetValue", "TlsSetValue", "VirtualAlloc", "VirtualFree", "calloc",
    "dlopen", "dlsym", "free", "malloc", "realloc", "system", "wcslen",
    "wcscpy", "swprintf",
}


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
    if re.search(
        r"\(\s*(?:void|int|uint\d+_t|rome2_guest_status)\s*"
        r"\(\s*\*\s*\)\s*\([^)]*\)\s*\)",
        code,
    ):
        findings.append("native function-pointer construction is forbidden")
    for target in (
        "0x100ed3c0", "0x100ed471", "0x100ed550", "0x119f31c8",
        "0x119f31c5", "0x100f1c10", "0x100f1aa0", "0x100f1bb0",
        "0x100df270", "0x100f1cc0",
    ):
        if target in compact:
            findings.append(
                f"raw original address must remain header/provenance data: {target}"
            )
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
    expected_includes = [
        "ported_100df270_headless.h",
        "ported_100df270_platform_prefix_transcript.h",
        "ported_100df270_suffix_transcript.h",
        "ported_100f1aa0_empty.h",
        "ported_100f1bb0_bounded.h",
        "ported_100f1cc0_nonowning.h",
    ]
    if includes != expected_includes:
        findings.append("header admitted-child include set or order changed")

    macros = (
        ("PRELOOP_STEP_COUNT", "9", "exact nine-operation count changed"),
        ("PRELOOP_START_PC", "0x100ed3c0", "pre-loop start boundary changed"),
        ("PRELOOP_FRAME_BYTES", "0x90c", "exact 0x90c frame changed"),
        ("PRELOOP_TEXT_UNITS", "1", "empty-input max_units=1 contract changed"),
        ("PRELOOP_ZERO_OFFSET", "0x00", "scratch zero offset changed"),
        ("PRELOOP_TRIPLET0_OFFSET", "0x04", "triplet0 +0x04 changed"),
        ("PRELOOP_TRIPLET1_OFFSET", "0x10", "triplet1 +0x10 changed"),
        ("PRELOOP_ARGUMENT_COPY_OFFSET", "0x1c", "argument copy +0x1c changed"),
        ("PRELOOP_DESCRIPTOR_OFFSET", "0x28", "descriptor +0x28 changed"),
        ("PRELOOP_PACKET_OFFSET", "0x34", "packet +0x34 changed"),
        ("PRELOOP_COPY0_OFFSET", "0x3c", "empty copy0 +0x3c changed"),
        ("PRELOOP_COPY1_OFFSET", "0x48", "empty copy1 +0x48 changed"),
        ("PRELOOP_PACKET_ARGUMENT_OFFSET", "0x54", "packet argument offset changed"),
        ("PRELOOP_PACKET_BYTE_OFFSET", "0x58", "packet byte offset changed"),
        ("PRELOOP_PACKET_DWORD_OFFSET", "0x5c", "packet dword offset changed"),
        ("PRELOOP_PACKET_FLAG_OFFSET", "0x60", "packet flag offset changed"),
        ("PRELOOP_RECEIVER_OFFSET", "0x64", "child receiver +0x64 changed"),
        ("PRELOOP_GLOBAL_119F31C8", "0x119f31c8", "first global identity changed"),
        ("PRELOOP_GLOBAL_119F31C5", "0x119f31c5", "second global identity changed"),
        ("PRELOOP_NEXT_PC", "0x100ed471", "hard-stop boundary changed"),
    )
    for suffix, value, message in macros:
        _require_once(
            compact,
            f"#defineROME2_PORT_100ED3C0_{suffix}UINT32_C({value})",
            findings,
            message,
        )

    targets = (
        ("100F1C10", "0x100f1c10"),
        ("100F1AA0", "0x100f1aa0"),
        ("100F1BB0", "0x100f1bb0"),
        ("100DF270", "0x100df270"),
        ("100F1CC0", "0x100f1cc0"),
    )
    for suffix, value in targets:
        _require_once(
            compact,
            f"#defineROME2_PORT_100ED3C0_PRELOOP_TARGET_{suffix}UINT32_C({value})",
            findings,
            f"provenance callee identity changed: {suffix.lower()}",
        )

    step_enum = (
        "typedefenumrome2_100ed3c0_preloop_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100ed3c0_preloop_step_kind;"
    )
    _require_once(compact, step_enum, findings, "typed nine-kind operation order changed")
    value_enum = (
        "typedefenumrome2_100ed3c0_preloop_value_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(VALUE_KINDS))
        + "}rome2_100ed3c0_preloop_value_kind;"
    )
    _require_once(compact, value_enum, findings, "typed six-kind value domain changed")
    effects_type = (
        "typedefstructrome2_100ed3c0_preloop_effects{"
        "rome2_100ed3c0_preloop_emit_step_fnemit_step;void*context;"
        "rome2_100df270_prefix_effectschild_prefix;"
        "rome2_100df270_suffix_effectschild_suffix;}"
        "rome2_100ed3c0_preloop_effects;"
    )
    _require_once(compact, effects_type, findings, "parent plus child effects layout changed")
    result_type = (
        "typedefstructrome2_100ed3c0_preloop_result{"
        "rome2_guest_addr32child_receiver;rome2_guest_addr32child_packet;"
        "rome2_guest_addr32child_argument;uint32_tnext_original_pc;}"
        "rome2_100ed3c0_preloop_result;"
    )
    _require_once(compact, result_type, findings, "bounded result layout changed")
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "constrome2_guest_write_view*frame_view,rome2_guest_addr32guest_frame,"
        "uint32_targument_position1,constrome2_guest_read_view*text_view,"
        "rome2_guest_addr32argument_position3_text,uint32_ttext_max_units,"
        "constrome2_guest_write_view*selector_view,"
        "constrome2_100ed3c0_preloop_effects*effects,"
        "rome2_100ed3c0_preloop_result*result_out);"
    )
    _require_once(compact, declaration, findings, "public bounded pre-loop API changed")
    findings.extend(_banned_findings(text, code, source=False))
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_PROVENANCE_BYTES:
        findings.append("pre-loop provenance byte count changed")
    if _sha256(encoded) != EXPECTED_PROVENANCE_SHA256:
        findings.append("pre-loop provenance exact digest changed")
    compact = _compact(text)
    authorities = (
        ("PARENT_VA=0x100ED3C0", "parent entry authority changed"),
        ("PARENT_SIZE=400", "parent 400-byte authority changed"),
        ("PRELOOP_VA=PARENT_VA", "pre-loop start authority changed"),
        ("PRELOOP_END_VA=0x100ED471", "pre-loop hard stop changed"),
        ("PRELOOP_RAW_OFFSET=PARENT_RAW_OFFSET", "pre-loop raw offset changed"),
        ("PRELOOP_SHA256=\"b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626\"",
         "authenticated 177-byte pre-loop hash changed"),
        ("EXCLUDED_VA=PRELOOP_END_VA", "excluded loop boundary changed"),
        ("EXCLUDED_END_VA=0x100ED550", "excluded parent end changed"),
        ("EXCLUDED_SHA256=\"0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9\"",
         "excluded 223-byte loop hash changed"),
        ("FRAME_SIZE=0x90C", "provenance frame size changed"),
        ("\"stop_va\":0x100ED471", "semantic-model stop changed"),
        ("require_authority(candidate,177,PRELOOP_SHA256,\"pre-loop\")",
         "exact 177-byte boundary check changed"),
        ("self.assertNotIn(bytes.fromhex(\"ff5254\"),PRELOOP_BYTES)",
         "indirect-call exclusion changed"),
        ("self.assertNotIn(bytes.fromhex(\"ff10\"),PRELOOP_BYTES)",
         "loop indirect-call exclusion changed"),
    )
    for fragment, message in authorities:
        if fragment not in compact:
            findings.append(message)
    operation_fragments = tuple(f'\"{operation}\"' for operation in (
        "store_global_119f31c8", "store_global_119f31c5",
        "initialize_triplet_a_100f1c10", "initialize_triplet_b_100f1c10",
        "copy_empty_a_100f1aa0", "copy_empty_b_100f1aa0",
        "construct_bounded_descriptor_100f1bb0",
        "run_bounded_child_100df270", "cleanup_nonowning_100f1cc0",
    ))
    _require_in_order(
        compact,
        operation_fragments,
        findings,
        "provenance exact nine-operation order changed",
    )
    for fragment in operation_fragments:
        if compact.count(fragment) < 1:
            findings.append(f"provenance nine-operation order missing: {fragment}")
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
    allowed = {
        "ported_100ed3c0_empty_preloop.h", "stddef.h", "stdint.h", "string.h",
    }
    if (
        not includes
        or includes[0] != "ported_100ed3c0_empty_preloop.h"
        or set(includes) - allowed
        or len(includes) != len(set(includes))
    ):
        findings.append("source include containment changed")
    findings.extend(_banned_findings(text, code, source=True))

    helper_contracts = (
        ("#defineROME2_100ED3C0_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest32 address-space ceiling changed"),
        ("#defineROME2_100ED3C0_EXTERNAL_CONTROL_COUNT5U",
         "five external controls changed"),
        ("#defineROME2_100ED3C0_PRIVATE_CONTROL_COUNT16U",
         "sixteen private preflight controls changed"),
        ("view_byte_count-offset||offset>(uint64_t)SIZE_MAX",
         "complete checked span projection changed"),
        ("returnrome2_guest_add_checked(base,offset,result);",
         "derived identities must use checked 32-bit addition"),
        ("frame[ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET]=UINT8_C(0);",
         "packet byte staging changed"),
        ("frame[ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET]=UINT8_C(0);",
         "packet flag staging changed"),
    )
    for fragment, message in helper_contracts:
        if fragment not in compact:
            findings.append(message)

    body = _function_body(code, FUNCTION)
    if body is None:
        findings.append("bounded empty pre-loop function definition is missing")
        return sorted(set(findings))
    function = _compact(body)

    validation = (
        ("status=rome2_100ed3c0_validate_object(frame_view,sizeof(*frame_view));",
         "frame-view descriptor validation changed"),
        ("status=rome2_100ed3c0_validate_object(text_view,sizeof(*text_view));",
         "text-view descriptor validation changed"),
        ("status=rome2_100ed3c0_validate_object(selector_view,sizeof(*selector_view));",
         "separate selector-view descriptor validation changed"),
        ("status=rome2_100ed3c0_validate_object(effects,sizeof(*effects));",
         "effects descriptor validation changed"),
        ("status=rome2_100ed3c0_validate_object(result_out,sizeof(*result_out));",
         "result descriptor validation changed"),
        ("frame_snapshot=*frame_view;text_snapshot=*text_view;"
         "selector_snapshot=*selector_view;", "three-view snapshot order changed"),
        ("frame_snapshot.guest_base!=guest_frame.value||"
         "frame_snapshot.byte_count!=ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES",
         "frame must be exact-base and exact 0x90c bytes"),
        ("if(rome2_100ed3c0_backings_overlap(backings,3U)||"
         "rome2_100ed3c0_backings_overlap_controls(backings,3U,controls,"
         "ROME2_100ED3C0_EXTERNAL_CONTROL_COUNT)",
         "pairwise backing/external-control disjointness changed"),
        ("rome2_100ed3c0_backings_overlap_controls(backings,3U,private_controls,"
         "ROME2_100ED3C0_PRIVATE_CONTROL_COUNT)",
         "backing/private-preflight-control disjointness changed"),
        ("private_controls[8].start=(uint64_t)(uintptr_t)&preview_return;"
         "private_controls[8].byte_count=sizeof(preview_return);",
         "preview output must be a protected private control"),
        ("text_max_units!=ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS",
         "max_units must be exactly one"),
        ("rome2_port_100f1bb0_measure_utf16(&text_snapshot,"
         "argument_position3_text,text_max_units,&text_length)",
         "bounded UTF-16 measurement changed"),
        ("text_length!=UINT32_C(0)", "nonempty input must fail closed"),
    )
    for fragment, message in validation:
        if fragment not in function:
            findings.append(message)

    resolve_offsets = (
        "TRIPLET0", "TRIPLET1", "ARGUMENT_COPY", "ZERO_BYTE", "ZERO_DWORD",
        "DESCRIPTOR", "PACKET", "COPY0", "COPY1", "PACKET_ARGUMENT",
        "PACKET_BYTE", "PACKET_DWORD", "PACKET_FLAG", "RECEIVER",
    )
    for suffix in resolve_offsets:
        token = f"ROME2_PORT_100ED3C0_PRELOOP_{suffix}_OFFSET"
        if function.count(token) < 1:
            findings.append(f"checked frame identity missing: {suffix.lower()}")
    if function.count("rome2_100ed3c0_add(") != 16:
        findings.append("all sixteen derived guest identities must be checked")

    span_requirements = (
        ("guest_frame,ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES,&frame_span",
         "complete exact frame-span validation changed"),
        ("argument_position3_text,UINT32_C(2),&text_unit_span",
         "first UTF-16 unit span changed"),
        ("effects_snapshot.child_suffix.first_selector_result,UINT32_C(4),"
         "&first_selector_span", "first separate selector result span changed"),
        ("effects_snapshot.child_suffix.second_selector_result,UINT32_C(4),"
         "&second_selector_span", "second separate selector result span changed"),
        ("rome2_100ed3c0_span_overlaps(&frame_span,&text_unit_span)||"
         "rome2_100ed3c0_span_overlaps(&frame_span,&first_selector_span)||"
         "rome2_100ed3c0_span_overlaps(&frame_span,&second_selector_span)||"
         "rome2_100ed3c0_span_overlaps(&text_unit_span,&first_selector_span)||"
         "rome2_100ed3c0_span_overlaps(&text_unit_span,&second_selector_span)",
         "logical/physical frame-text-selector disjointness changed"),
    )
    for fragment, message in span_requirements:
        if fragment not in function:
            findings.append(message)

    api_counts = (
        ("rome2_port_100f1bb0_measure_utf16(", 1,
         "one bounded empty-input measurement is required"),
        ("rome2_port_100f1c10_initialize_triplet(", 6,
         "three preview and three actual admitted triplet writes are required"),
        ("rome2_port_100f1aa0_copy_empty_source(", 4,
         "two preview and two actual admitted empty copies are required"),
        ("rome2_port_100df270_run_platform_prefix_transcript(", 2,
         "child prefix must run once in preflight and once in commit"),
        ("rome2_port_100df270_project_headless_empty_state(", 2,
         "child middle must run once in preflight and once in commit"),
        ("rome2_port_100df270_run_suffix_transcript(", 2,
         "child suffix must run once in preflight and once in commit"),
        ("rome2_port_100f1cc0_accept_nonowning_noop(", 1,
         "one admitted nonowning cleanup is required"),
    )
    for token, count, message in api_counts:
        if function.count(token) != count:
            findings.append(message)

    preflight_order = (
        "text_max_units!=ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS",
        "rome2_port_100f1bb0_measure_utf16(",
        "memcpy(frame_preview,",
        "rome2_port_100f1c10_initialize_triplet(&frame_preview_view,guest_triplet0,",
        "rome2_port_100f1aa0_copy_empty_source(&frame_preview_view,guest_copy0,",
        "rome2_port_100df270_run_platform_prefix_transcript(&frame_preview_view,",
        "rome2_port_100df270_project_headless_empty_state(&frame_preview_view,",
        "rome2_port_100df270_run_suffix_transcript(&selector_preview_view,",
        "frame_bytes=frame_snapshot.host_base+(size_t)frame_span.view_offset;",
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
    )
    _require_in_order(
        function, preflight_order, findings,
        "unified leaf/prefix/middle/suffix preflight must precede every effect/write",
    )
    if (
        function.count(
            "rome2_port_100df270_run_suffix_transcript(&selector_preview_view,"
        ) != 1
        or function.count(
            "rome2_port_100df270_run_suffix_transcript(&selector_snapshot,"
        ) != 1
    ):
        findings.append("suffix preflight/commit must use separate selector views")

    if function.count("effects_snapshot.emit_step(effects_snapshot.context,step);") != 9:
        findings.append("exactly nine parent operations must be emitted")
    step_fragments = tuple(
        f"rome2_100ed3c0_clear_step(&step,{kind});" for kind in STEP_KINDS
    )
    _require_in_order(
        function, step_fragments, findings,
        "exact typed nine-operation parent order changed",
    )
    for fragment, kind in zip(step_fragments, STEP_KINDS):
        if function.count(fragment) != 1:
            findings.append(f"parent operation missing or duplicated: {kind}")

    commit_order = (
        step_fragments[0], step_fragments[1], step_fragments[2],
        "rome2_port_100f1c10_initialize_triplet(&frame_snapshot,guest_triplet0,",
        step_fragments[3],
        "rome2_port_100f1c10_initialize_triplet(&frame_snapshot,guest_triplet1,",
        step_fragments[4],
        "rome2_port_100f1aa0_copy_empty_source(&frame_snapshot,guest_copy0,",
        step_fragments[5],
        "rome2_port_100f1aa0_copy_empty_source(&frame_snapshot,guest_copy1,",
        step_fragments[6],
        "rome2_port_100f1c10_initialize_triplet(&frame_snapshot,guest_descriptor,",
        step_fragments[7],
        "rome2_port_100df270_run_platform_prefix_transcript(&frame_snapshot,",
        "rome2_port_100df270_project_headless_empty_state(&frame_snapshot,",
        "rome2_port_100df270_run_suffix_transcript(&selector_snapshot,",
        step_fragments[8],
        "rome2_port_100f1cc0_accept_nonowning_noop(",
        "result_out->child_receiver=guest_receiver;",
        "result_out->next_original_pc=ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;",
    )
    _require_in_order(
        function, commit_order, findings,
        "nine-step admitted-child commit sequence or hard stop changed",
    )
    outputs = (
        "result_out->child_receiver=guest_receiver;",
        "result_out->child_packet=guest_packet;",
        "result_out->child_argument=guest_descriptor;",
        "result_out->next_original_pc=ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;",
    )
    for output in outputs:
        if function.count(output) != 1:
            findings.append("bounded result must commit exactly once after cleanup")
    if re.search(r"\b(?:for|while|do|goto)\b", body):
        findings.append("pre-loop adapter must remain straight-line and stop before loop")
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
    """Require the complete BUILD_TESTING-only integration; absence fails."""
    findings: list[str] = []
    if len(re.findall(r"^\s*add_test\s*\(", text, flags=re.I | re.M)) != (
        EXPECTED_CTEST_COUNT
    ):
        findings.append("CMake total must be exactly 194 CTests")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return sorted(set(findings + ["one balanced if(BUILD_TESTING) block is required"]))
    start, end = bounds
    for token in (LIBRARY, TEST_TARGET, *CMAKE_FILES, *CMAKE_TESTS):
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake empty-preloop token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake empty-preloop token escapes BUILD_TESTING: {token}")
    scoped = _compact("\n".join(lines[start + 1:end]))
    exact_library = (
        f"add_library({LIBRARY}STATIC"
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.c")'
    )
    requirements = (
        (exact_library, "empty-preloop must be an exact static test-only library"),
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "empty-preloop C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE${{ROME2_HARDENED_COMPILE_OPTIONS}})",
         "empty-preloop hardened compile options changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_empty_preloop.c")',
         "empty-preloop runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated runtime test must link only its empty-preloop library"),
    )
    for fragment, message in requirements:
        if scoped.count(fragment) != 1:
            findings.append(message)

    commands = _link_commands(text)
    expected_dependency = [
        LIBRARY, "PUBLIC", "rome2_guest32_runtime", "PRIVATE", *CHILD_LIBRARIES,
    ]
    own = [words for words in commands if words and words[0] == LIBRARY]
    if own != [expected_dependency]:
        findings.append("empty-preloop exact guest32/public and child/private dependencies changed")
    consumers = [
        words[0] for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if set(consumers) != {TEST_TARGET, HEADLESS_TARGET}:
        findings.append("empty-preloop consumers must be exactly runtime test and headless")
    headless = [words for words in commands if words and words[0] == HEADLESS_TARGET]
    if len(headless) != 1 or headless[0][-2:] != [LIBRARY, LIFECYCLE_LIBRARY]:
        findings.append("empty-preloop and lifecycle must be the final direct headless links")

    gate_start = scoped.find(
        "add_test(NAMEstartup_100ed3c0_empty_preloop_static_gateCOMMAND"
    )
    gate_end = scoped.find("add_test(", gate_start + 1)
    gate_scope = scoped[gate_start:gate_end] if gate_start >= 0 else ""
    gate_args = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_empty_preloop.c"',
        '--preloop-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100ed3c0_preloop_transcript_provenance.py"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--export-contract"${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--bootstrap-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
        '--repro-manifest"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'x64_reproducible_build_v2_manifest.json"',
        '--repro-verifier"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_reproducible_build_v2.py"',
    )
    for argument in gate_args:
        if gate_scope.count(argument) != 1:
            findings.append(f"empty-preloop static-gate argument changed: {argument[:76]}")

    fixture_requirements = (
        ("startup_100ed3c0_empty_preloop_provenancePROPERTIES"
         "FIXTURES_SETUPstartup_100ed3c0_empty_preloop_provenance_verified",
         "pre-loop provenance fixture changed"),
        ("startup_100ed3c0_empty_preloop_static_gate_unitPROPERTIES"
         "FIXTURES_SETUPstartup_100ed3c0_empty_preloop_static_tool_verified",
         "empty-preloop reciprocal-tool fixture changed"),
        ("startup_100ed3c0_empty_preloop_static_gatePROPERTIES"
         "FIXTURES_REQUIREDstartup_100ed3c0_empty_preloop_static_tool_verified"
         "FIXTURES_SETUPstartup_100ed3c0_empty_preloop_static_verified",
         "empty-preloop live static fixture changed"),
        ("startup_100ed3c0_empty_preloop_runtimePROPERTIESFIXTURES_REQUIRED\""
         + PREDECESSOR_FIXTURE + ";"
         "startup_100ed3c0_empty_preloop_provenance_verified;"
         "startup_100ed3c0_empty_preloop_static_verified\""
         "FIXTURES_SETUPstartup_100ed3c0_empty_preloop_runtime_verified",
         "empty-preloop runtime must follow prefix reload plus its own gates"),
        ("startup_100ed3c0_empty_preloop_post_pe_gatePROPERTIES"
         "FIXTURES_REQUIRED\"startup_100ed3c0_empty_preloop_runtime_verified;"
         "entry_policy_probe_pe_tool_verified\""
         "FIXTURES_SETUPstartup_100ed3c0_empty_preloop_post_verified",
         "empty-preloop post-PE fixture changed"),
        ("x64_bootstrap_load_after_startup_100ed3c0_empty_preloopPROPERTIES"
         "FIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
         "startup_100ed3c0_empty_preloop_post_verified\"FIXTURES_SETUP"
         + PARENT_RELOAD_FIXTURE,
         "empty-preloop terminal reload fixture changed"),
    )
    for fragment, message in fixture_requirements:
        if fragment not in scoped:
            findings.append(message)
    if (
        'FIXTURES_REQUIRED"entry_policy_provenance_verified;entry_policy_static_verified;'
        + TERMINAL_FIXTURE + '"' not in scoped
    ):
        findings.append("composed lifecycle must require empty-preloop terminal fixture")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    include = '#include "ported_100ed3c0_empty_preloop.h"'
    if text.count(include) != 1:
        findings.append("headless empty-preloop public include is missing or duplicated")
    if len(re.findall(rf"\b{re.escape(FUNCTION)}\s*\(", code)) != 1:
        findings.append("headless must call the empty-preloop adapter exactly once")
    if len(re.findall(rf"\b{re.escape(LIFECYCLE_FUNCTION)}\s*\(", code)) != 1:
        findings.append("headless must call the ordinary lifecycle exactly once")
    if text.count(HEADLESS_TOKEN) != 1:
        findings.append("headless empty-preloop completion token is missing or duplicated")
    if text.count(LIFECYCLE_TOKEN) != 1:
        findings.append("headless lifecycle completion token is missing or duplicated")
    prefix_token = "startup-100df270-platform-prefix=injected-call-shape-complete"
    if text.find(prefix_token) < 0 or text.find(HEADLESS_TOKEN) <= text.find(prefix_token):
        findings.append("headless empty-preloop token must follow the child prefix token")
    if text.find(LIFECYCLE_TOKEN) <= text.find(HEADLESS_TOKEN):
        findings.append("headless lifecycle token must follow the empty-preloop token")
    for token, message in (
        ("ROME2_PORT_100ED3C0_PRELOOP_STEP_COUNT", "nine-step oracle is missing"),
        ("ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES", "0x90c frame oracle is missing"),
        ("ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS", "max_units=1 oracle is missing"),
        ("ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC", "hard-stop oracle is missing"),
    ):
        if token not in compact:
            findings.append(f"headless {message}")
    for kind in STEP_KINDS:
        if kind not in compact:
            findings.append(f"headless typed parent-step oracle missing: {kind}")
    for child in (
        "rome2_port_100df270_run_platform_prefix_transcript",
        "rome2_port_100df270_project_headless_empty_state",
        "rome2_port_100df270_run_suffix_transcript",
    ):
        if len(re.findall(rf"\b{re.escape(child)}\s*\(", code)) != 0:
            findings.append("headless must not duplicate child execution outside adapter")
    findings.extend(_banned_findings(text, code, source=False))
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100ed3c0_preloop",
        "ported_100ed3c0_empty_preloop", "100ed3c0_empty_preloop",
        "100ed3c0-empty-preloop",
    ):
        if token in lowered:
            findings.append(f"test-only empty-preloop token escaped exports: {token}")
    return sorted(set(findings))


def inspect_repro_manifest_text(text: str) -> list[str]:
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_REPRO_MANIFEST_BYTES:
        findings.append("repro manifest exact size changed")
    if _sha256(encoded) != EXPECTED_REPRO_MANIFEST_SHA256:
        findings.append("repro manifest exact digest changed")
    try:
        manifest = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        return [f"repro manifest is not strict JSON: {error}"]
    try:
        matrix = manifest["build_contract"]["testing_matrix"]
        actual = [
            (
                row["path"], row["build_testing"],
                row["external_flag_overrides"], row["verified_hash_pair"],
            )
            for row in matrix
        ]
    except (KeyError, TypeError):
        findings.append("repro manifest testing matrix is malformed")
        actual = []
    expected = [
        ("out/x64-bootstrap", True, False, True),
        (REPRO_ON, True, False, True),
        (REPRO_OFF, False, False, True),
    ]
    if actual != expected:
        findings.append("repro manifest exact empty-preloop ON/OFF matrix changed")
    try:
        artifacts = manifest["reproducible_v2"]["artifacts"]
        pins = {row["role"]: (row["sha256"], row["byte_count"]) for row in artifacts}
    except (KeyError, TypeError):
        findings.append("repro manifest artifact pins are malformed")
        pins = {}
    if pins != {
        "dll": (
            "ea6eabe0e510ac9593bb4aeac8ae6123dfe050ac08c9f2067115dbef9fd63930",
            107520,
        ),
        "host": (
            "fdcdb90111cbc0cc5301bccd6f96f15566cefd9be93f9a2714c73d9c02afa320",
            144384,
        ),
    }:
        findings.append("production DLL/host reproducibility pins changed")
    inputs = manifest.get("inputs", []) if isinstance(manifest, dict) else []
    cmake = [row for row in inputs if isinstance(row, dict) and row.get("path") == "CMakeLists.txt"]
    if len(cmake) != 1 or not re.fullmatch(r"[0-9a-f]{64}", str(cmake[0].get("sha256", ""))):
        findings.append("repro manifest must contain one lowercase CMake digest pin")
    elif not isinstance(cmake[0].get("byte_count"), int) or cmake[0]["byte_count"] <= 0:
        findings.append("repro manifest CMake byte-count pin is invalid")
    return sorted(set(findings))


def inspect_repro_verifier_text(text: str) -> list[str]:
    compact = _compact(text)
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_REPRO_VERIFIER_BYTES:
        findings.append("repro verifier exact size changed")
    if _sha256(encoded) != EXPECTED_REPRO_VERIFIER_SHA256:
        findings.append("repro verifier exact digest changed")
    for token, message in (
        (f'(\"{REPRO_ON}\",True,False,True)', "repro verifier ON matrix changed"),
        (f'(\"{REPRO_OFF}\",False,False,True)', "repro verifier OFF matrix changed"),
        ('\"startup_100ed3c0_empty_preloop_post_pe_gate\"',
         "repro verifier active PE-gate set lacks empty-preloop"),
        ('\"startup_100ed471_ordinary_lifecycle_post_pe_gate\"',
         "repro verifier active PE-gate set lacks ordinary lifecycle"),
        ('\"rome2_startup_100ed3c0_empty_preloop_runtime\"',
         "repro verifier current runtime target is missing"),
        ('\"rome2_startup_100ed3c0_empty_preloop_tests\"',
         "repro verifier current test target is missing"),
        ('\"rome2_startup_100ed471_ordinary_lifecycle_runtime\"',
         "repro verifier lifecycle runtime target is missing"),
        ('\"rome2_startup_100ed471_ordinary_lifecycle_tests\"',
         "repro verifier lifecycle test target is missing"),
    ):
        if compact.count(token) != 1:
            findings.append(message)
    return sorted(set(findings))


def inspect_repro_cmake_pin(
    manifest_text: str,
    verifier_text: str,
    cmake_text: str,
) -> list[str]:
    findings: list[str] = []
    digest = _sha256(cmake_text.encode("utf-8"))
    size = len(cmake_text.encode("utf-8"))
    try:
        manifest = json.loads(manifest_text)
        pin = next(
            row for row in manifest["inputs"] if row.get("path") == "CMakeLists.txt"
        )
    except (json.JSONDecodeError, KeyError, StopIteration, TypeError):
        return ["cannot compare live CMake with repro manifest pin"]
    if pin.get("sha256") != digest or pin.get("byte_count") != size:
        findings.append("repro manifest CMake pin differs from live integration")
    expected_tuple = f'\"{digest}\",{size},'
    if expected_tuple not in _compact(verifier_text):
        findings.append("repro verifier CMake pin differs from live integration")
    return findings


def _inspect_path(path: pathlib.Path, inspector) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspector(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path)
    parser.add_argument("--preloop-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--export-contract", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--bootstrap-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    parser.add_argument("--repro-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--repro-verifier", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "preloop_provenance": (args.preloop_provenance, inspect_provenance_text),
        "cmake": (args.cmake, inspect_cmake_text),
        "headless": (args.headless, inspect_headless_text),
        "export_manifest": (args.export_manifest, inspect_exports_text),
        "export_contract": (args.export_contract, inspect_exports_text),
        "legacy_def": (args.legacy_def, inspect_exports_text),
        "bootstrap_def": (args.bootstrap_def, inspect_exports_text),
        "probe_def": (args.probe_def, inspect_exports_text),
        "repro_manifest": (args.repro_manifest, inspect_repro_manifest_text),
        "repro_verifier": (args.repro_verifier, inspect_repro_verifier_text),
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    texts: dict[str, str] = {}
    for label, (path, inspector) in requested.items():
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            findings = [f"cannot resolve file: {error}"]
            resolved = path.resolve()
        else:
            raw, decode_findings = _decode_utf8(resolved)
            if raw is None:
                findings = decode_findings
            else:
                texts[label] = raw
                findings = inspector(raw)
        total += len(findings)
        report["files"][label] = {"path": str(resolved), "findings": findings}
    if {"repro_manifest", "repro_verifier", "cmake"} <= texts.keys():
        findings = inspect_repro_cmake_pin(
            texts["repro_manifest"], texts["repro_verifier"], texts["cmake"]
        )
        total += len(findings)
        report["files"]["repro_cmake_pin"] = {"findings": findings}
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
