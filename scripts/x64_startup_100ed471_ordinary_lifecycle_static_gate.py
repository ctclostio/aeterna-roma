#!/usr/bin/env python3
"""Fail-closed source gate for the injected 0x100ed471 lifecycle slice."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
TEST_TARGET = "rome2_startup_100ed471_ordinary_lifecycle_tests"
HEADLESS_TARGET = "rome2_headless64"
COMPOSITION_LIBRARY = "rome2_startup_100ed3c0_nonempty_lifecycle_runtime"
HEADLESS_TOKEN = "startup-100ed471-ordinary-lifecycle=injected-bounded-complete"
PREDECESSOR_FIXTURE = "startup_100ed3c0_empty_preloop_reload_verified"
TERMINAL_FIXTURE = "startup_100ed471_ordinary_lifecycle_reload_verified"
EXPECTED_CTEST_COUNT = 192

REPRO_ON = "out/repro-100edd70-entry-decision-verified-on"
REPRO_OFF = "out/repro-100edd70-entry-decision-verified-off"

EXPECTED_HEADER_BYTES = 6_362
EXPECTED_HEADER_SHA256 = (
    "c085cb6afe916a3c0399f63b971256ea5e7e01aeb6456bc7f5940115070aecba"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "2f43c5bc64c1ae7b7747d0391f38f1e9ce1940a048184cf8c361bd4ab60880a7"
)
EXPECTED_SOURCE_BYTES = 21_022
EXPECTED_SOURCE_SHA256 = (
    "167942ade0a8fc003e9fa34d79da435c24e370a0acb7dfc722b18d80e78a0236"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "bb1bd9089516c89e33b19400c3b0ea3eaca3da7923002420274155655ebd8ab4"
)
EXPECTED_PROVENANCE_BYTES = 43_449
EXPECTED_PROVENANCE_SHA256 = (
    "fc433827064f1d86d69c981eed50feb48160dddd01f65019a34ec6a746f476f5"
)
EXPECTED_DOC_BYTES = 7_910
EXPECTED_DOC_SHA256 = (
    "206313658b2160a439f160a86279ae58bffea1b4cbfe7908b744a4cf7f7f1a34"
)
EXPECTED_TEST_BYTES = 52_053
EXPECTED_TEST_SHA256 = (
    "4a4d9b60861ab80df8a3da4a3b2718dd27d77a74bbbe0078c02a07c4d0043661"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "b34400790f1091d3735fcf0d2a7ef4cc761a184405acba9d7e987eb961510b69"
)
EXPECTED_CMAKE_BYTES = 182_959
EXPECTED_CMAKE_SHA256 = (
    "3e7dda18a4e170f7d68a73f121ff5f4a40e58c854047e730a9608984b9589674"
)
EXPECTED_HEADLESS_BYTES = 163_368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_HEADLESS_TOKEN_SHA256 = (
    "07aa2c02db60b37064c0ad420d391ebefc19454f7608956dd0916aecbce43ed9"
)
EXPECTED_REPRO_MANIFEST_BYTES = 6_409
EXPECTED_REPRO_MANIFEST_SHA256 = (
    "d861510a03710e2f2bb49f6eacd5e088f71c637b28369092e11e6f32ac2b24cd"
)
EXPECTED_REPRO_VERIFIER_BYTES = 27_845
EXPECTED_REPRO_VERIFIER_SHA256 = (
    "0a1b9c7d6981cc9fd0dd9df0673a499a01833c60ee7b76572123a6af7ae69193"
)

CMAKE_FILES = (
    "ported_100ed471_ordinary_lifecycle.h",
    "ported_100ed471_ordinary_lifecycle.c",
    "test_startup_100ed471_ordinary_lifecycle.c",
    "test_x64_startup_100ed471_ordinary_lifecycle_provenance.py",
    "test_x64_startup_100ed471_ordinary_lifecycle_static_gate.py",
    "x64_startup_100ed471_ordinary_lifecycle_static_gate.py",
    "x64_startup_100ed471_ordinary_lifecycle.md",
)

CMAKE_TESTS = (
    "startup_100ed471_ordinary_lifecycle_provenance",
    "startup_100ed471_ordinary_lifecycle_static_gate_unit",
    "startup_100ed471_ordinary_lifecycle_static_gate",
    "startup_100ed471_ordinary_lifecycle_runtime",
    "startup_100ed471_ordinary_lifecycle_post_pe_gate",
    "x64_bootstrap_load_after_startup_100ed471_ordinary_lifecycle",
)

STEP_KINDS = (
    "ROME2_100ED471_STEP_CALL_100EA060",
    "ROME2_100ED471_STEP_CALL_112DCAF0",
    "ROME2_100ED471_STEP_CALL_100D6560",
    "ROME2_100ED471_STEP_CALL_112E3D20",
    "ROME2_100ED471_STEP_INDIRECT_SLOT_54",
    "ROME2_100ED471_STEP_CALL_112E2BB0",
    "ROME2_100ED471_STEP_CALL_100EC5C0",
    "ROME2_100ED471_STEP_CALL_100E0650",
    "ROME2_100ED471_STEP_CALL_100F1CC0",
)

HEADER_MACROS = (
    ("START_PC", "0x100ed471", "slice start boundary changed"),
    ("POLL_PC", "0x100ed4c1", "poll boundary changed"),
    ("RETURN_PC", "0x100ed550", "return boundary changed"),
    ("FRAME_BYTES", "0x90c", "exact frame size changed"),
    ("MAX_POLL_CALLS", "64", "fixed 64-result transcript bound changed"),
    ("RECEIVER_OFFSET", "0x64", "receiver offset changed"),
    ("TIMESTAMP_OFFSET", "0x28", "timestamp destination changed"),
    ("TIMESTAMP_COPY_OFFSET", "0x904", "timestamp copy offset changed"),
    ("CLEANUP0_OFFSET", "0x48", "cleanup0 offset changed"),
    ("CLEANUP1_OFFSET", "0x3c", "cleanup1 offset changed"),
    ("CLEANUP2_OFFSET", "0x10", "cleanup2 offset changed"),
    ("CLEANUP3_OFFSET", "0x04", "cleanup3 offset changed"),
    ("LOG_MESSAGE", "0x11740084", "log identity changed"),
    ("DISPATCH_SLOT_OFFSET", "0x54", "dispatch slot changed"),
    ("LOCAL_VTABLE", "0x11897870", "local vtable allowlist changed"),
    ("LOCAL_METHOD", "0x112e2cd0", "local method allowlist changed"),
    ("FALLBACK_OBJECT", "0x119e1004", "fallback object allowlist changed"),
    ("FALLBACK_VTABLE", "0x1189791c", "fallback vtable allowlist changed"),
    ("FALLBACK_METHOD", "0x100f3d00", "fallback method allowlist changed"),
)

TARGET_MACROS = (
    ("100EA060", "0x100ea060"),
    ("112DCAF0", "0x112dcaf0"),
    ("100D6560", "0x100d6560"),
    ("112E3D20", "0x112e3d20"),
    ("112E2BB0", "0x112e2bb0"),
    ("100EC5C0", "0x100ec5c0"),
    ("100E0650", "0x100e0650"),
    ("100F1CC0", "0x100f1cc0"),
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
    "dlopen", "dlsym", "free", "malloc", "memcpy", "memmove", "realloc",
    "system", "wcslen", "wcscpy", "swprintf",
}

ALLOWED_SOURCE_CALLS = {
    "UINT32_C", "UINT64_C", "_Alignof", "emit_step", "for", "if",
    "return", "rome2_100ed471_add", "rome2_100ed471_clear_step",
    "rome2_100ed471_context_overlaps", "rome2_100ed471_controls_overlap",
    "rome2_100ed471_empty_descriptor", "rome2_100ed471_ranges_overlap",
    "rome2_100ed471_read_u32_le", "rome2_100ed471_span_overlaps_controls",
    "rome2_100ed471_validate_interval", "rome2_100ed471_validate_object",
    "rome2_100ed471_write_u32_le", "rome2_guest_add_checked",
    "rome2_guest_read_addr32_le", FUNCTION,
    "rome2_port_100f1cc0_accept_nonowning_noop", "sizeof",
}

RAW_SOURCE_ADDRESS_TOKENS = (
    "0x100ed471", "0x100ed4c1", "0x100ed550", "0x100ea060",
    "0x112dcaf0", "0x100d6560", "0x112e3d20", "0x112e2bb0",
    "0x100ec5c0", "0x100e0650", "0x100f1cc0", "0x11740084",
    "0x11897870", "0x112e2cd0", "0x119e1004", "0x1189791c",
    "0x100f3d00",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _token_digest(code: str) -> str:
    return _sha256(_compact(code).encode("utf-8"))


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _check_exact(
    text: str,
    expected_bytes: int,
    expected_hash: str,
    label: str,
    findings: list[str],
) -> None:
    encoded = text.encode("utf-8")
    if len(encoded) != expected_bytes:
        findings.append(f"{label} byte count changed")
    if _sha256(encoded) != expected_hash:
        findings.append(f"{label} exact digest changed")


def _check_c_digest(
    text: str,
    code: str,
    expected_bytes: int,
    expected_exact: str,
    expected_tokens: str,
    label: str,
    findings: list[str],
) -> None:
    _check_exact(text, expected_bytes, expected_exact, label, findings)
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


def _banned_source_findings(code: str) -> list[str]:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    findings = [
        f"forbidden native/allocator/platform identifier: {name}"
        for name in sorted(BANNED_IDENTIFIERS & identifiers)
    ]
    if re.search(r"\b_?DAT_[0-9A-Fa-f]+\b", code):
        findings.append("original process-global identifier is forbidden")
    if re.search(r"\b(?:decomp_fn|FUN|sub)_[0-9A-Fa-f]+\b", code):
        findings.append("recovered/native implementation call is forbidden")
    if re.search(r"\b(?:__declspec|dllexport|dllimport|volatile|_Thread_local)\b", code):
        findings.append("DLL/volatile/thread-local storage is forbidden")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")

    lowered = code.lower()
    for address in RAW_SOURCE_ADDRESS_TOKENS:
        if address in lowered:
            findings.append(
                f"raw original address must remain header/provenance data: {address}"
            )

    guest_pointer_cast = re.compile(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uintptr_t)\s*\*+\s*\)\s*(?:\(?\s*)?"
        r"(?:guest_[A-Za-z_]\w*|dispatch_[A-Za-z_]\w*\.value|[^;\n]{0,48}\.value)"
    )
    if guest_pointer_cast.search(code):
        findings.append("guest identities must not become native pointers")
    if re.search(
        r"\(\s*(?:uintptr_t|size_t)\s*\)\s*(?:\(?\s*)?"
        r"(?:[^&;\n]{0,48}\.value)", code,
    ):
        findings.append("guest identities must not become host integers")
    if re.search(
        r"\(\s*(?:void|int|uint\d+_t|rome2_guest_status)\s*"
        r"\(\s*\*\s*\)\s*\([^)]*\)\s*\)",
        code,
    ):
        findings.append("native function-pointer construction is forbidden")

    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    unexpected = calls - ALLOWED_SOURCE_CALLS
    missing = ALLOWED_SOURCE_CALLS - calls
    for call in sorted(unexpected):
        findings.append(f"unexpected native/helper call expression: {call}")
    if missing:
        findings.append("source exact call-expression allowlist changed")
    return findings


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_HEADER_BYTES, EXPECTED_HEADER_SHA256,
        EXPECTED_HEADER_TOKEN_SHA256, "header", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100f1c10_triplet.h", "ported_100f1cc0_nonowning.h"]:
        findings.append("header admitted include set or order changed")

    for suffix, value, message in HEADER_MACROS:
        _require_once(
            compact,
            f"#defineROME2_PORT_100ED471_{suffix}UINT32_C({value})",
            findings,
            message,
        )
    for suffix, value in TARGET_MACROS:
        _require_once(
            compact,
            f"#defineROME2_PORT_100ED471_TARGET_{suffix}UINT32_C({value})",
            findings,
            f"direct-call provenance identity changed: {suffix.lower()}",
        )

    enum = (
        "typedefenumrome2_100ed471_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100ed471_step_kind;"
    )
    _require_once(compact, enum, findings, "typed nine-kind transcript order changed")
    step = (
        "typedefstructrome2_100ed471_step{rome2_100ed471_step_kindkind;"
        "uint32_targument_count;uint32_targument0;uint32_targument1;"
        "uint32_targument2;uint32_tresult_count;uint32_tresult0;"
        "uint32_tresult1;uint32_tdispatch_vtable;"
        "uint32_tdispatch_slot_offset;uint32_tdispatch_target;}"
        "rome2_100ed471_step;"
    )
    _require_once(compact, step, findings, "pointer-free transcript step layout changed")
    callback = (
        "typedefvoid(*rome2_100ed471_emit_step_fn)(void*context,"
        "rome2_100ed471_stepstep);"
    )
    _require_once(compact, callback, findings, "typed injected observer signature changed")
    effects = (
        "typedefstructrome2_100ed471_lifecycle_effects{"
        "rome2_100ed471_emit_step_fnemit_step;void*context;"
        "uint32_ttimestamp_low;uint32_ttimestamp_high;"
        "uint32_tpoll_result_count;"
        "uint32_tpoll_results[ROME2_PORT_100ED471_MAX_POLL_CALLS];}"
        "rome2_100ed471_lifecycle_effects;"
    )
    _require_once(compact, effects, findings, "fixed poll transcript effects layout changed")
    result = (
        "typedefstructrome2_100ed471_lifecycle_result{"
        "rome2_guest_addr32dispatch_receiver;rome2_guest_addr32dispatch_vtable;"
        "rome2_guest_addr32dispatch_target;uint32_tpoll_calls;"
        "uint32_tterminal_poll_result;uint32_ttimestamp_low;"
        "uint32_ttimestamp_high;uint32_treturn_original_pc;}"
        "rome2_100ed471_lifecycle_result;"
    )
    _require_once(compact, result, findings, "bounded lifecycle result layout changed")
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "constrome2_guest_write_view*frame_view,rome2_guest_addr32guest_frame,"
        "constrome2_guest_read_view*dispatch_view,"
        "rome2_guest_addr32dispatch_receiver,uint32_tmax_poll_calls,"
        "constrome2_100ed471_lifecycle_effects*effects,"
        "rome2_100ed471_lifecycle_result*result_out);"
    )
    _require_once(compact, declaration, findings, "public lifecycle API changed")
    if (
        "For CALL_112E2BB0,\n * result0/result1 are the injected low/high "
        "dwords written through argument0;" not in text
    ):
        findings.append("through-pointer timestamp result contract changed")
    if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append("DLL import/export annotation is forbidden")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_SOURCE_BYTES, EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_TOKEN_SHA256, "source", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100ed471_ordinary_lifecycle.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include containment changed")
    findings.extend(_banned_source_findings(code))

    helper_contracts = (
        ("#defineROME2_100ED471_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest32 address-space ceiling changed"),
        ("#defineROME2_100ED471_EXTERNAL_CONTROL_COUNT4U",
         "four external controls changed"),
        ("#defineROME2_100ED471_PRIVATE_CONTROL_COUNT18U",
         "eighteen private controls changed"),
        ("#defineROME2_100ED471_CLEANUP_COUNT4U",
         "four-cleanup count changed"),
        ("returnrome2_guest_add_checked(base,offset,result);",
         "derived identities must use checked 32-bit addition"),
        ("byte_count>ROME2_100ED471_ADDRESS_SPACE_SIZE||"
         "(uint64_t)guest_base+byte_count>ROME2_100ED471_ADDRESS_SPACE_SIZE",
         "guest interval bound changed"),
        ("byte_count-UINT64_C(1)>(uint64_t)(UINTPTR_MAX-host_address)",
         "host endpoint overflow check changed"),
    )
    for fragment, message in helper_contracts:
        if fragment not in compact:
            findings.append(message)

    body = _function_body(code, FUNCTION)
    if body is None:
        findings.append("bounded lifecycle function definition is missing")
        return sorted(set(findings))
    function = _compact(body)

    preflight_order = (
        "status=rome2_100ed471_validate_object(frame_view,sizeof(*frame_view));",
        "status=rome2_100ed471_validate_object(dispatch_view,sizeof(*dispatch_view));",
        "status=rome2_100ed471_validate_object(effects,sizeof(*effects));",
        "status=rome2_100ed471_validate_object(result_out,sizeof(*result_out));",
        "if((uintptr_t)frame_view%_Alignof(rome2_guest_write_view)!=0U||",
        "controls[0].start=(uint64_t)(uintptr_t)frame_view;",
        "if(rome2_100ed471_controls_overlap(controls,"
        "ROME2_100ED471_EXTERNAL_CONTROL_COUNT))",
        "frame_snapshot=*frame_view;dispatch_snapshot=*dispatch_view;"
        "effects_snapshot=*effects;dispatch_receiver_snapshot=dispatch_receiver;"
        "result_destination=result_out;",
        "status=rome2_100ed471_validate_interval(frame_snapshot.host_base,"
        "frame_snapshot.guest_base,frame_snapshot.byte_count);",
        "status=rome2_100ed471_validate_interval(dispatch_snapshot.host_base,"
        "dispatch_snapshot.guest_base,dispatch_snapshot.byte_count);",
        "if(guest_frame.value==UINT32_C(0)||"
        "dispatch_receiver_snapshot.value==UINT32_C(0)||"
        "frame_snapshot.guest_base!=guest_frame.value||"
        "frame_snapshot.byte_count!=ROME2_PORT_100ED471_FRAME_BYTES||",
        "for(poll_index=UINT32_C(0);poll_index<"
        "effects_snapshot.poll_result_count;++poll_index)",
        "if(rome2_100ed471_ranges_overlap(frame_backing.start,",
        "private_controls[0].start=(uint64_t)(uintptr_t)&frame_snapshot;",
        "if(rome2_100ed471_span_overlaps_controls(&frame_backing,"
        "private_controls,ROME2_100ED471_PRIVATE_CONTROL_COUNT)||",
        "context_point.start=(uint64_t)(uintptr_t)effects_snapshot.context;",
        "status=rome2_guest_read_addr32_le(&dispatch_snapshot,"
        "dispatch_receiver_snapshot,&dispatch_vtable);",
        "status=rome2_100ed471_add(dispatch_vtable,"
        "ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET,&dispatch_slot);",
        "status=rome2_guest_read_addr32_le(&dispatch_snapshot,dispatch_slot,"
        "&dispatch_target);",
        "if(!((dispatch_vtable.value==ROME2_PORT_100ED471_LOCAL_VTABLE&&",
        "status=rome2_100ed471_add(guest_frame,"
        "ROME2_PORT_100ED471_RECEIVER_OFFSET,&guest_receiver);",
        "frame=frame_snapshot.host_base;",
        "if(!rome2_100ed471_empty_descriptor(frame,"
        "cleanup_offsets[cleanup_index]))",
        "rome2_100ed471_clear_step(&step,"
        "ROME2_100ED471_STEP_CALL_100EA060);",
    )
    _require_in_order(
        function, preflight_order, findings,
        "unified validation-before-effects order changed",
    )

    validation_fragments = (
        ("max_poll_calls==UINT32_C(0)||max_poll_calls>"
         "ROME2_PORT_100ED471_MAX_POLL_CALLS",
         "positive bounded max_poll_calls check changed"),
        ("effects_snapshot.poll_result_count==UINT32_C(0)||"
         "effects_snapshot.poll_result_count>max_poll_calls",
         "poll result count/budget check changed"),
        ("constuint32_texpected=poll_index+UINT32_C(1)=="
         "effects_snapshot.poll_result_count?UINT32_C(2):UINT32_C(0);",
         "exact zero-star-terminal-two transcript changed"),
        ("if(effects_snapshot.poll_results[poll_index]!=expected){"
         "returnROME2_GUEST_BAD_ARGUMENT;}",
         "poll transcript prevalidation changed"),
        ("rome2_100ed471_ranges_overlap((uint64_t)frame_snapshot.guest_base,"
         "frame_snapshot.byte_count,(uint64_t)dispatch_snapshot.guest_base,"
         "dispatch_snapshot.byte_count)",
         "logical guest-view disjointness changed"),
        ("rome2_100ed471_context_overlaps(effects_snapshot.context,"
         "&frame_backing,&dispatch_backing,controls,"
         "ROME2_100ED471_EXTERNAL_CONTROL_COUNT)",
         "external context disjointness changed"),
        ("rome2_100ed471_span_overlaps_controls(&context_point,"
         "private_controls,ROME2_100ED471_PRIVATE_CONTROL_COUNT)",
         "context/private-local disjointness changed"),
    )
    for fragment, message in validation_fragments:
        if fragment not in function:
            findings.append(message)
    if "effects->" in function:
        findings.append("effects must be snapshotted before observer use")

    for index in range(18):
        if function.count(f"private_controls[{index}].start=") != 1 or function.count(
            f"private_controls[{index}].byte_count="
        ) != 1:
            findings.append(f"private-local alias protection changed: slot {index}")
    for index in range(4):
        if len(re.findall(
            rf"(?<!private_)controls\[{index}\]\.start=", function
        )) != 1 or len(re.findall(
            rf"(?<!private_)controls\[{index}\]\.byte_count=", function
        )) != 1:
            findings.append(f"external-control alias protection changed: slot {index}")

    dispatch_allowlist = (
        "if(!((dispatch_vtable.value==ROME2_PORT_100ED471_LOCAL_VTABLE&&"
        "dispatch_target.value==ROME2_PORT_100ED471_LOCAL_METHOD)||"
        "(dispatch_receiver_snapshot.value=="
        "ROME2_PORT_100ED471_FALLBACK_OBJECT&&"
        "dispatch_vtable.value==ROME2_PORT_100ED471_FALLBACK_VTABLE&&"
        "dispatch_target.value==ROME2_PORT_100ED471_FALLBACK_METHOD))){"
        "returnROME2_GUEST_BAD_ARGUMENT;}"
    )
    if function.count(dispatch_allowlist) != 1:
        findings.append("exact dispatch pair allowlist changed")
    if function.count("rome2_guest_read_addr32_le(") != 2:
        findings.append("dispatch must use exactly two checked guest32 reads")
    if function.count("rome2_100ed471_add(") != 5:
        findings.append(
            "five checked-add sites must cover all eight derived guest identities"
        )
    derived_adds = (
        ("rome2_100ed471_add(dispatch_vtable,"
         "ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET,&dispatch_slot)",
         "checked dispatch-slot identity changed"),
        ("rome2_100ed471_add(guest_frame,"
         "ROME2_PORT_100ED471_RECEIVER_OFFSET,&guest_receiver)",
         "checked receiver identity changed"),
        ("rome2_100ed471_add(guest_frame,"
         "ROME2_PORT_100ED471_TIMESTAMP_OFFSET,&guest_timestamp)",
         "checked timestamp identity changed"),
        ("rome2_100ed471_add(guest_frame,"
         "ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET,&guest_timestamp_copy)",
         "checked timestamp-copy identity changed"),
        ("rome2_100ed471_add(guest_frame,cleanup_offsets[cleanup_index],"
         "&guest_cleanup[cleanup_index])",
         "checked cleanup identities changed"),
    )
    for fragment, message in derived_adds:
        if fragment not in function:
            findings.append(message)

    setup_order = tuple(
        f"rome2_100ed471_clear_step(&step,{kind});" for kind in STEP_KINDS[:6]
    )
    _require_in_order(
        function, setup_order, findings, "six setup transcript steps changed order"
    )
    if function.count("effects_snapshot.emit_step(effects_snapshot.context,step);") != 9:
        findings.append("exact nine source emission sites changed")

    timestamp_order = (
        "rome2_100ed471_clear_step(&step,"
        "ROME2_100ED471_STEP_CALL_112E2BB0);",
        "step.result0=effects_snapshot.timestamp_low;",
        "step.result1=effects_snapshot.timestamp_high;",
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100ed471_write_u32_le(frame+"
        "ROME2_PORT_100ED471_TIMESTAMP_OFFSET,effects_snapshot.timestamp_low);",
        "rome2_100ed471_write_u32_le(frame+"
        "ROME2_PORT_100ED471_TIMESTAMP_OFFSET+UINT32_C(4),"
        "effects_snapshot.timestamp_high);",
        "rome2_100ed471_write_u32_le(frame+"
        "ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET,"
        "effects_snapshot.timestamp_low);",
        "rome2_100ed471_write_u32_le(frame+"
        "ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET+UINT32_C(4),"
        "effects_snapshot.timestamp_high);",
        "for(poll_index=UINT32_C(0);poll_index<"
        "effects_snapshot.poll_result_count;++poll_index)",
    )
    _require_in_order(
        function, timestamp_order, findings, "timestamp event/write/poll order changed"
    )
    if function.count("rome2_100ed471_write_u32_le(") != 4:
        findings.append("timestamp must perform exactly four checked byte writes")

    poll_shape = (
        "rome2_100ed471_clear_step(&step,"
        "ROME2_100ED471_STEP_CALL_100EC5C0);"
        "step.argument_count=UINT32_C(1);step.argument0=guest_receiver.value;"
        "step.result_count=UINT32_C(1);"
        "step.result0=effects_snapshot.poll_results[poll_index];"
        "effects_snapshot.emit_step(effects_snapshot.context,step);"
    )
    _require_once(function, poll_shape, findings, "poll event transcript shape changed")

    cleanup_array = (
        "staticconstuint32_tcleanup_offsets[ROME2_100ED471_CLEANUP_COUNT]={"
        "ROME2_PORT_100ED471_CLEANUP0_OFFSET,"
        "ROME2_PORT_100ED471_CLEANUP1_OFFSET,"
        "ROME2_PORT_100ED471_CLEANUP2_OFFSET,"
        "ROME2_PORT_100ED471_CLEANUP3_OFFSET};"
    )
    if cleanup_array not in function:
        findings.append("terminal cleanup offset order changed")
    if function.count("rome2_port_100f1cc0_accept_nonowning_noop(") != 2:
        findings.append("preflight and committed nonowning cleanup checks changed")
    terminal_order = (
        "rome2_100ed471_clear_step(&step,"
        "ROME2_100ED471_STEP_CALL_100E0650);",
        "for(cleanup_index=0U;cleanup_index<ROME2_100ED471_CLEANUP_COUNT;"
        "++cleanup_index)",
        "rome2_100ed471_clear_step(&step,"
        "ROME2_100ED471_STEP_CALL_100F1CC0);",
        "step.argument0=guest_cleanup[cleanup_index].value;",
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "status=rome2_port_100f1cc0_accept_nonowning_noop(",
        "result.dispatch_receiver=dispatch_receiver_snapshot;",
    )
    _require_in_order(
        function, terminal_order, findings, "terminal teardown/cleanup/result order changed"
    )

    result_order = (
        "result.dispatch_receiver=dispatch_receiver_snapshot;",
        "result.dispatch_vtable=dispatch_vtable;",
        "result.dispatch_target=dispatch_target;",
        "result.poll_calls=effects_snapshot.poll_result_count;",
        "result.terminal_poll_result=UINT32_C(2);",
        "result.timestamp_low=effects_snapshot.timestamp_low;",
        "result.timestamp_high=effects_snapshot.timestamp_high;",
        "result.return_original_pc=ROME2_PORT_100ED471_RETURN_PC;",
        "*result_destination=result;",
        "returnROME2_GUEST_OK;",
    )
    _require_in_order(function, result_order, findings, "result-last commit order changed")
    if (
        function.count("*result_destination=result;") != 1
        or "result_out->" in function
        or len(re.findall(r"(?<!\.)\bdispatch_receiver\b", body)) != 1
        or len(re.findall(r"\bresult_out\b", body)) != 6
    ):
        findings.append("result output must commit exactly once and last")

    first_emit = function.find("effects_snapshot.emit_step(")
    first_write = function.find("rome2_100ed471_write_u32_le(")
    dispatch_check = function.find(dispatch_allowlist)
    descriptor_check = function.find("if(!rome2_100ed471_empty_descriptor(")
    if not (
        dispatch_check >= 0 and descriptor_check > dispatch_check
        and first_emit > descriptor_check and first_write > first_emit
    ):
        findings.append("validation must finish before first effect or frame write")
    if re.search(r"\bwhile\s*\(", body):
        findings.append("unbounded while loop is forbidden")
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_PROVENANCE_BYTES, EXPECTED_PROVENANCE_SHA256,
        "ordinary-lifecycle provenance", findings,
    )
    compact = _compact(text)
    fragments = (
        ("SLICE_VA=0x100ED471", "provenance slice start changed"),
        ("SLICE_END_VA=0x100ED550", "provenance slice end changed"),
        ("SLICE_RAW=0x000EC871", "provenance raw mapping changed"),
        ("SLICE_SHA256=\"0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93d"
         "fa7c259f9d36bd9\"", "provenance slice hash changed"),
        ("\"poll_domain\":(0,2)", "ordinary poll domain changed"),
        ("\"poll_budget_required\":True", "finite poll budget proof changed"),
        ("\"terminal_result_required_within_budget\":True",
         "terminal-two requirement changed"),
        ("\"poll_transcript_prevalidated\":True",
         "prevalidated transcript proof changed"),
        ("\"result_one_admitted\":False", "result-one exclusion changed"),
        ("\"second_indirect_dispatch\":\"excluded\"",
         "second indirect exclusion changed"),
        ("\"candidate_target_set_exhaustive\":False",
         "candidate non-exhaustiveness proof changed"),
        ("DIRECT_FRAME_WRITES=(", "direct frame-write authority changed"),
        ("TERMINAL_CALL_ORDER=(", "terminal cleanup authority changed"),
    )
    for fragment, message in fragments:
        if fragment not in compact:
            findings.append(message)
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC_BYTES, EXPECTED_DOC_SHA256, "lifecycle doc", findings)
    compact = _compact(text)
    fragments = (
        ("`[0x100ed471,0x100ed550)`", "documented byte boundary changed"),
        ("ordinarydomainisexactly`{0,2}`", "documented ordinary domain changed"),
        ("notanexhaustivetargetproof", "candidate caveat changed"),
        ("Preflightafinitepolltranscript", "finite transcript contract changed"),
        ("Rejectresult`1`", "result-one rejection changed"),
        ("Validationmustcompletebeforethefirstobservereventorframewrite",
         "documented fail-closed order changed"),
    )
    for fragment, message in fragments:
        if fragment not in compact:
            findings.append(message)
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_TEST_BYTES, EXPECTED_TEST_SHA256,
        EXPECTED_TEST_TOKEN_SHA256, "runtime oracle", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100ed471_ordinary_lifecycle.h", "stddef.h", "stdint.h",
        "stdio.h", "string.h",
    ]:
        findings.append("runtime oracle include set or order changed")

    macro_fragments = (
        ("#defineTEST_FRAME_BYTESUINT32_C(0x90c)", "runtime frame oracle changed"),
        ("#defineTEST_SETUP_STEPSUINT32_C(6)", "six setup-step oracle changed"),
        ("#defineTEST_TERMINAL_STEPSUINT32_C(5)", "five terminal-step oracle changed"),
        ("ROME2_PORT_100ED471_MAX_POLL_CALLS==UINT32_C(64)",
         "64-poll runtime ceiling changed"),
        ("ROME2_PORT_100ED471_START_PC==UINT32_C(0x100ed471)&&"
         "ROME2_PORT_100ED471_POLL_PC==UINT32_C(0x100ed4c1)&&"
         "ROME2_PORT_100ED471_RETURN_PC==UINT32_C(0x100ed550)",
         "runtime boundary oracle changed"),
        ("ROME2_PORT_100ED471_LOCAL_VTABLE==UINT32_C(0x11897870)&&"
         "ROME2_PORT_100ED471_LOCAL_METHOD==UINT32_C(0x112e2cd0)&&",
         "runtime dispatch allowlist oracle changed"),
    )
    for fragment, message in macro_fragments:
        if fragment not in compact:
            findings.append(message)

    expected_builder = _function_body(code, "test_build_expected_steps")
    if expected_builder is None:
        findings.append("expected transcript builder is missing")
    else:
        builder = _compact(expected_builder)
        _require_in_order(
            builder,
            tuple(STEP_KINDS),
            findings,
            "runtime expected transcript step order changed",
        )
        builder_fragments = (
            ("expected[5].result0=timestamp_low;"
             "expected[5].result1=timestamp_high;",
             "through-pointer timestamp result oracle changed"),
            ("for(index=UINT32_C(0);index<poll_result_count;++index)",
             "runtime variable poll transcript changed"),
            ("expected[cursor].result0=poll_results[index];",
             "runtime poll result oracle changed"),
            ("guest_frame.value+cleanup_offsets[index]",
             "runtime cleanup identity oracle changed"),
        )
        for fragment, message in builder_fragments:
            if fragment not in builder:
                findings.append(message)

    required_test_groups = (
        "test_local_success_routes", "test_fallback_success",
        "test_frame_end_boundary_success", "test_effect_snapshot",
        "test_maximum_poll_budget", "test_poll_transcript_preflight_failures",
        "test_basic_preflight_failures", "test_numeric_range_failures",
        "test_descriptor_failures", "test_dispatch_failures",
        "test_alignment_failures", "test_alias_failures",
    )
    main = _function_body(code, "main")
    if main is None:
        findings.append("runtime oracle main is missing")
    else:
        _require_in_order(
            _compact(main),
            tuple(f"failed|={name}();" for name in required_test_groups),
            findings,
            "runtime test-group order or coverage changed",
        )
    for name in required_test_groups:
        if _function_body(code, name) is None:
            findings.append(f"runtime test group is missing: {name}")

    required_failure_labels = (
        "empty poll transcript",
        "ordinary-unreachable result one is rejected precommit",
        "unsupported result three", "zero-only transcript exhausts budget",
        "terminal two has a trailing result",
        "transcript count exceeds explicit budget", "null dispatch receiver",
        "mixed local vtable and fallback method",
        "fallback pair requires fixed fallback object",
        "frame and dispatch physical backings overlap",
        "frame and dispatch guest intervals overlap",
        "emitter context aliases effects control",
    )
    for label in required_failure_labels:
        if f'"{label}"' not in text:
            findings.append(f"runtime adversarial coverage changed: {label}")
    runtime_contracts = (
        ("fixture->effects.poll_results[index]=value;"
         "fixture->trace.expected_poll_results[index]=value;",
         "runtime fixed transcript initialization changed"),
        ("trace->caller_effects->poll_results[0]=UINT32_C(1);",
         "runtime effect-snapshot adversary changed"),
        ("memcmp(&fixture->frame,&frame_snapshot,sizeof(frame_snapshot))==0",
         "runtime failure frame-preservation oracle changed"),
        ("memcmp(&fixture->result,&result_snapshot,sizeof(result_snapshot))==0",
         "runtime failure result-preservation oracle changed"),
    )
    for fragment, message in runtime_contracts:
        if fragment not in compact:
            findings.append(message)
    if compact.count(FUNCTION + "(") != 6:
        findings.append("runtime lifecycle invocation coverage changed")
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
    """Require the exact BUILD_TESTING-only lifecycle integration."""
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_CMAKE_BYTES, EXPECTED_CMAKE_SHA256, "CMake", findings
    )
    if len(re.findall(r"^\s*add_test\s*\(", text, flags=re.I | re.M)) != (
        EXPECTED_CTEST_COUNT
    ):
        findings.append("CMake total must be exactly 192 CTests")

    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return sorted(set(findings + [
            "one balanced if(BUILD_TESTING) block is required"
        ]))
    start, end = bounds
    for token in (LIBRARY, TEST_TARGET, *CMAKE_FILES, *CMAKE_TESTS):
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake ordinary-lifecycle token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(
                f"CMake ordinary-lifecycle token escapes BUILD_TESTING: {token}"
            )

    scoped = _compact("\n".join(lines[start + 1:end]))
    requirements = (
        (
            f"add_library({LIBRARY}STATIC"
            '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed471_ordinary_lifecycle.h"'
            '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed471_ordinary_lifecycle.c")',
            "ordinary lifecycle must be an exact static test-only library",
        ),
        (
            f"target_compile_features({LIBRARY}PUBLICc_std_17)",
            "ordinary-lifecycle C17 requirement changed",
        ),
        (
            f"target_compile_options({LIBRARY}PRIVATE"
            "${ROME2_HARDENED_COMPILE_OPTIONS})",
            "ordinary-lifecycle hardened compile options changed",
        ),
        (
            f"target_include_directories({LIBRARY}PUBLIC"
            '"${ROME2_GUEST32_RUNTIME_DIR}"'
            '"${ROME2_GUEST32_PORTED_DIR}")',
            "ordinary-lifecycle public include surface changed",
        ),
        (
            f"add_executable({TEST_TARGET}"
            '"${ROME2_GUEST32_RUNTIME_DIR}/'
            'test_startup_100ed471_ordinary_lifecycle.c")',
            "ordinary-lifecycle runtime-test executable is missing",
        ),
        (
            f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
            "dedicated runtime test must link only its lifecycle library",
        ),
    )
    for fragment, message in requirements:
        if scoped.count(fragment) != 1:
            findings.append(message)

    commands = _link_commands(text)
    expected_dependency = [
        LIBRARY, "PUBLIC", "rome2_guest32_runtime",
        "PRIVATE", "rome2_startup_safe_seams_runtime",
    ]
    own = [words for words in commands if words and words[0] == LIBRARY]
    if own != [expected_dependency]:
        findings.append(
            "ordinary-lifecycle exact guest32/public and safe-seam/private "
            "dependencies changed"
        )
    consumers = [
        words[0] for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if (
        set(consumers) != {TEST_TARGET, HEADLESS_TARGET, COMPOSITION_LIBRARY}
        or len(consumers) != 3
    ):
        findings.append(
            "ordinary-lifecycle consumers must be exactly runtime test, "
            "headless, and whole-parent composition"
        )
    headless = [
        words for words in commands if words and words[0] == HEADLESS_TARGET
    ]
    if len(headless) != 1 or headless[0][-1:] != [LIBRARY]:
        findings.append("ordinary lifecycle must be the final direct headless link")

    for name in CMAKE_TESTS:
        if scoped.count(f"add_test(NAME{name}COMMAND") != 1:
            findings.append(f"ordinary-lifecycle CTest registration changed: {name}")

    gate_start = scoped.find(
        "add_test(NAMEstartup_100ed471_ordinary_lifecycle_static_gateCOMMAND"
    )
    gate_end = scoped.find("add_test(", gate_start + 1)
    gate_scope = scoped[gate_start:gate_end] if gate_start >= 0 else ""
    gate_args = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/'
        'ported_100ed471_ordinary_lifecycle.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/'
        'ported_100ed471_ordinary_lifecycle.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/'
        'test_startup_100ed471_ordinary_lifecycle.c"',
        '--lifecycle-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100ed471_ordinary_lifecycle_provenance.py"',
        '--doc"${CMAKE_CURRENT_SOURCE_DIR}/docs/'
        'x64_startup_100ed471_ordinary_lifecycle.md"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/'
        'export_manifest.tsv"',
        '--export-contract"${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/'
        'empire.retail.exports.def"',
        '--bootstrap-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/'
        'empire_bootstrap.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
        '--repro-manifest"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'x64_reproducible_build_v2_manifest.json"',
        '--repro-verifier"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_reproducible_build_v2.py"',
    )
    for argument in gate_args:
        if gate_scope.count(argument) != 1:
            findings.append(
                f"ordinary-lifecycle static-gate argument changed: {argument[:76]}"
            )

    fixture_requirements = (
        (
            "startup_100ed471_ordinary_lifecycle_provenancePROPERTIES"
            "FIXTURES_SETUPstartup_100ed471_ordinary_lifecycle_provenance_verified",
            "ordinary-lifecycle provenance fixture changed",
        ),
        (
            "startup_100ed471_ordinary_lifecycle_static_gate_unitPROPERTIES"
            "FIXTURES_SETUPstartup_100ed471_ordinary_lifecycle_static_tool_verified",
            "ordinary-lifecycle reciprocal-tool fixture changed",
        ),
        (
            "startup_100ed471_ordinary_lifecycle_static_gatePROPERTIES"
            "FIXTURES_REQUIREDstartup_100ed471_ordinary_lifecycle_static_tool_verified"
            "FIXTURES_SETUPstartup_100ed471_ordinary_lifecycle_static_verified",
            "ordinary-lifecycle live static fixture changed",
        ),
        (
            "startup_100ed471_ordinary_lifecycle_runtimePROPERTIES"
            "FIXTURES_REQUIRED\"" + PREDECESSOR_FIXTURE + ";"
            "startup_100ed471_ordinary_lifecycle_provenance_verified;"
            "startup_100ed471_ordinary_lifecycle_static_verified\""
            "FIXTURES_SETUPstartup_100ed471_ordinary_lifecycle_runtime_verified",
            "ordinary-lifecycle runtime must follow parent reload and its own gates",
        ),
        (
            "startup_100ed471_ordinary_lifecycle_post_pe_gatePROPERTIES"
            "FIXTURES_REQUIRED\"startup_100ed471_ordinary_lifecycle_runtime_verified;"
            "entry_policy_probe_pe_tool_verified\""
            "FIXTURES_SETUPstartup_100ed471_ordinary_lifecycle_post_verified",
            "ordinary-lifecycle post-PE fixture changed",
        ),
        (
            "x64_bootstrap_load_after_startup_100ed471_ordinary_lifecyclePROPERTIES"
            "FIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
            "startup_100ed471_ordinary_lifecycle_post_verified\""
            "FIXTURES_SETUP" + TERMINAL_FIXTURE,
            "ordinary-lifecycle terminal reload fixture changed",
        ),
    )
    for fragment, message in fixture_requirements:
        if fragment not in scoped:
            findings.append(message)
    if (
        'FIXTURES_REQUIRED"entry_policy_provenance_verified;'
        'entry_policy_static_verified;' + TERMINAL_FIXTURE + '"' not in scoped
    ):
        findings.append(
            "composed headless lifecycle must require ordinary-lifecycle terminal fixture"
        )
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_HEADLESS_BYTES, EXPECTED_HEADLESS_SHA256,
        EXPECTED_HEADLESS_TOKEN_SHA256, "headless", findings,
    )
    include = '#include "ported_100ed471_ordinary_lifecycle.h"'
    if text.count(include) != 1:
        findings.append("headless lifecycle public include is missing or duplicated")
    if len(re.findall(rf"\b{re.escape(FUNCTION)}\s*\(", code)) != 1:
        findings.append("headless must call the lifecycle adapter exactly once")
    if text.count(HEADLESS_TOKEN) != 1:
        findings.append("headless lifecycle completion token is missing or duplicated")
    prefix_token = "startup-100ed3c0-empty-preloop=injected-composition-complete"
    if text.find(prefix_token) < 0 or text.find(HEADLESS_TOKEN) <= text.find(prefix_token):
        findings.append("headless lifecycle token must follow the admitted parent token")

    macro_fragments = (
        ("#defineROME2_HEADLESS_LIFECYCLE_POLL_COUNTUINT32_C(3)",
         "headless exact three-result poll count changed"),
        ("#defineROME2_HEADLESS_LIFECYCLE_STEP_COUNTUINT32_C(14)",
         "headless exact fourteen-event count changed"),
        ("#defineROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOWUINT32_C(0x89abcdef)",
         "headless timestamp-low oracle changed"),
        ("#defineROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGHUINT32_C(0x01234567)",
         "headless timestamp-high oracle changed"),
    )
    for fragment, message in macro_fragments:
        if fragment not in compact:
            findings.append(message)

    result_helper = _function_body(
        code, "rome2_headless_lifecycle_result_is_uncommitted"
    )
    if result_helper is None:
        findings.append("headless result-last observer is missing")
    else:
        result_compact = _compact(result_helper)
        for field in (
            "dispatch_receiver.value", "dispatch_vtable.value",
            "dispatch_target.value", "poll_calls", "terminal_poll_result",
            "timestamp_low", "timestamp_high", "return_original_pc",
        ):
            if f"result->{field}==ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL" not in (
                result_compact
            ):
                findings.append(f"headless result-last sentinel changed: {field}")

    step_helper = _function_body(code, "rome2_headless_lifecycle_step_is_exact")
    if step_helper is None:
        findings.append("headless fourteen-event oracle is missing")
    else:
        step_compact = _compact(step_helper)
        _require_in_order(
            step_compact, tuple(STEP_KINDS), findings,
            "headless setup/poll/teardown/cleanup event order changed",
        )
        for fragment, message in (
            ("case6:case7:case8:", "headless exact three-poll event shape changed"),
            ("expected.result0=index==UINT32_C(8)?UINT32_C(2):UINT32_C(0);",
             "headless exact 0,0,2 event transcript changed"),
            ("expected.argument0=frame+cleanup_offsets[index-UINT32_C(10)];",
             "headless terminal cleanup order changed"),
        ):
            if fragment not in step_compact:
                findings.append(message)

    emit_helper = _function_body(code, "rome2_headless_lifecycle_emit")
    if emit_helper is None:
        findings.append("headless lifecycle observer is missing")
    else:
        emit_compact = _compact(emit_helper)
        for fragment, message in (
            ("!rome2_headless_lifecycle_result_is_uncommitted(trace->result)",
             "headless result-last observation changed"),
            ("!rome2_headless_lifecycle_step_is_exact(step,index)",
             "headless exact-event observation changed"),
            ("!timestamp_is_exact", "headless timestamp write-order observation changed"),
        ):
            if fragment not in emit_compact:
                findings.append(message)

    main_body = _function_body(code, "main")
    if main_body is None:
        findings.append("headless main is missing")
    else:
        main_compact = _compact(main_body)
        lifecycle_sequence = (
            "lifecycle_effects.poll_result_count="
            "ROME2_HEADLESS_LIFECYCLE_POLL_COUNT;",
            "lifecycle_effects.poll_results[0]=UINT32_C(0);",
            "lifecycle_effects.poll_results[1]=UINT32_C(0);",
            "lifecycle_effects.poll_results[2]=UINT32_C(2);",
            "status=" + FUNCTION + "(",
            "lifecycle_trace.steps!=ROME2_HEADLESS_LIFECYCLE_STEP_COUNT",
            "lifecycle_result.terminal_poll_result!=UINT32_C(2)",
            "lifecycle_result.return_original_pc!="
            "ROME2_PORT_100ED471_RETURN_PC",
        )
        _require_in_order(
            main_compact, lifecycle_sequence, findings,
            "headless bounded lifecycle invocation/result sequence changed",
        )
        timestamp_checks = (
            "ROME2_PORT_100ED471_TIMESTAMP_OFFSET)!="
            "ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW",
            "ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET)!="
            "ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW",
        )
        for fragment in timestamp_checks:
            if fragment not in main_compact:
                findings.append("headless timestamp destination checks changed")

    for original_call in (
        "decomp_fn_100ea060", "decomp_fn_112dcaf0", "decomp_fn_100d6560",
        "decomp_fn_112e3d20", "decomp_fn_112e2bb0", "decomp_fn_100ec5c0",
        "decomp_fn_100e0650", "decomp_fn_100f1cc0",
    ):
        if original_call in code:
            findings.append("headless must not execute original lifecycle callees")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings: list[str] = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), TEST_TARGET.lower(),
        "ported_100ed471_ordinary_lifecycle", "100ed471_ordinary_lifecycle",
        "100ed471-ordinary-lifecycle",
    ):
        if token in lowered:
            findings.append(f"test-only ordinary-lifecycle token escaped exports: {token}")
    return sorted(set(findings))


def inspect_repro_manifest_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_REPRO_MANIFEST_BYTES, EXPECTED_REPRO_MANIFEST_SHA256,
        "repro manifest", findings,
    )
    try:
        manifest = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        return sorted(set(findings + [f"repro manifest is not strict JSON: {error}"]))
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
        findings.append("repro manifest exact ordinary-lifecycle ON/OFF matrix changed")
    try:
        artifacts = manifest["reproducible_v2"]["artifacts"]
        pins = {
            row["role"]: (row["path"], row["sha256"], row["byte_count"])
            for row in artifacts
        }
    except (KeyError, TypeError):
        findings.append("repro manifest artifact pins are malformed")
        pins = {}
    if pins != {
        "dll": (
            "out/x64-bootstrap/empire.retail64.dll",
            "ea6eabe0e510ac9593bb4aeac8ae6123dfe050ac08c9f2067115dbef9fd63930",
            107520,
        ),
        "host": (
            "out/x64-bootstrap/rome2_host64.exe",
            "fdcdb90111cbc0cc5301bccd6f96f15566cefd9be93f9a2714c73d9c02afa320",
            144384,
        ),
    }:
        findings.append("production DLL/host reproducibility pins changed")
    inputs = manifest.get("inputs", []) if isinstance(manifest, dict) else []
    cmake = [
        row for row in inputs
        if isinstance(row, dict) and row.get("path") == "CMakeLists.txt"
    ]
    if len(cmake) != 1 or cmake[0].get("sha256") != EXPECTED_CMAKE_SHA256:
        findings.append("repro manifest CMake digest pin changed")
    elif cmake[0].get("byte_count") != EXPECTED_CMAKE_BYTES:
        findings.append("repro manifest CMake byte-count pin changed")
    return sorted(set(findings))


def inspect_repro_verifier_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_REPRO_VERIFIER_BYTES, EXPECTED_REPRO_VERIFIER_SHA256,
        "repro verifier", findings,
    )
    compact = _compact(text)
    for token, message in (
        (f'("{REPRO_ON}",True,False,True)', "repro verifier ON matrix changed"),
        (f'("{REPRO_OFF}",False,False,True)', "repro verifier OFF matrix changed"),
        ('"startup_100ed471_ordinary_lifecycle_post_pe_gate"',
         "repro verifier active PE-gate set lacks ordinary lifecycle"),
        (f'"{LIBRARY}"', "repro verifier current lifecycle runtime target is missing"),
        (f'"{TEST_TARGET}"', "repro verifier current lifecycle test target is missing"),
        (f'"{EXPECTED_CMAKE_SHA256}",{EXPECTED_CMAKE_BYTES},',
         "repro verifier CMake pin changed"),
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
            row for row in manifest["inputs"]
            if row.get("path") == "CMakeLists.txt"
        )
    except (json.JSONDecodeError, KeyError, StopIteration, TypeError):
        return ["cannot compare live CMake with repro manifest pin"]
    if pin.get("sha256") != digest or pin.get("byte_count") != size:
        findings.append("repro manifest CMake pin differs from live integration")
    expected_tuple = f'"{digest}",{size},'
    if expected_tuple not in _compact(verifier_text):
        findings.append("repro verifier CMake pin differs from live integration")
    return findings


def inspect_header(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    return findings if text is None else inspect_header_text(text)


def inspect_source(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    return findings if text is None else inspect_source_text(text)


def inspect_provenance(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    return findings if text is None else inspect_provenance_text(text)


def inspect_doc(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    return findings if text is None else inspect_doc_text(text)


def inspect_test(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    return findings if text is None else inspect_test_text(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument(
        "--lifecycle-provenance", "--provenance",
        dest="lifecycle_provenance", type=pathlib.Path, required=True,
    )
    parser.add_argument("--doc", type=pathlib.Path, required=True)
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
    checks = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "test": (args.test, inspect_test_text),
        "provenance": (args.lifecycle_provenance, inspect_provenance_text),
        "doc": (args.doc, inspect_doc_text),
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
    for label, (path, inspector) in checks.items():
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            resolved = path.resolve()
            findings = [f"cannot resolve input: {error}"]
        else:
            text, decode_findings = _decode_utf8(resolved)
            if text is None:
                findings = decode_findings
            else:
                texts[label] = text
                findings = inspector(text)
        total += len(findings)
        report["files"][label] = {
            "path": str(resolved), "findings": findings,
        }
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
