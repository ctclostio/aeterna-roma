#!/usr/bin/env python3
"""Fail-closed source gate for the injected owned UTF-16 lifecycle slice."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


BUILD_FUNCTION = "rome2_port_100f1bb0_build_owned_utf16"
CLEANUP_FUNCTION = "rome2_port_100f1cc0_cleanup_owned_utf16"
LIBRARY = "rome2_startup_100f1bb0_owned_utf16_runtime"
TEST_TARGET = "rome2_startup_100f1bb0_owned_utf16_tests"
SUCCESSOR_LIBRARY = "rome2_startup_100f2750_sentinel_owned_runtime"
PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"

# Frozen after the BUILD_TESTING-only integration landed.
EXPECTED_CTEST_COUNT = 194
EXPECTED_CMAKE_BYTES = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

EXPECTED_HEADER_BYTES = 6_420
EXPECTED_HEADER_SHA256 = (
    "f884d1ac2917fa8d132b2db30f19f6508844fb196bcc1bf72f77e577554fc4c9"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "964d48ed63f403e91cb296a9aa3fa0dd00d7bb8ec678c66cb0772c316f4a1804"
)
EXPECTED_SOURCE_BYTES = 38_760
EXPECTED_SOURCE_SHA256 = (
    "9c6b6aa9eca21e8204834816ee0cb70e445d517f91f1819422cc70cc36f33bfa"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "9107eae4638b8ecf63d97f13ba8238fc3808f373597bea23548c67be889baeb1"
)
EXPECTED_PROVENANCE_BYTES = 49_683
EXPECTED_PROVENANCE_SHA256 = (
    "797164ae31c0b3a6496810d70ba642b3e20025901f7bd813aa97c0c8b403d628"
)
EXPECTED_DOC_BYTES = 12_836
EXPECTED_DOC_SHA256 = (
    "23750afdcbd4c5e106a1aba96791619311f74acdfe4353fe11fb619038374762"
)

EXPECTED_TEST_BYTES = 93_839
EXPECTED_TEST_SHA256 = (
    "c867fa9b5c5fbcf803ec992b2553e9bf595ee04117af18b9fd81c3a8797d2cc2"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "d84e5bec49037951e4300ffadfdc8be78fc711eb337c371dcb603a13922d0648"
)

CMAKE_FILES = (
    "ported_100f1bb0_owned_utf16.h",
    "ported_100f1bb0_owned_utf16.c",
    "test_startup_100f1bb0_owned_utf16.c",
    "test_x64_startup_100f1bb0_owned_utf16_provenance.py",
    "test_x64_startup_100f1bb0_owned_utf16_static_gate.py",
    "x64_startup_100f1bb0_owned_utf16_static_gate.py",
    "x64_startup_100f1bb0_owned_utf16.md",
)

CMAKE_TESTS = (
    "startup_100f1bb0_owned_utf16_provenance",
    "startup_100f1bb0_owned_utf16_static_gate_unit",
    "startup_100f1bb0_owned_utf16_static_gate",
    "startup_100f1bb0_owned_utf16_runtime",
)

PREDECESSOR_FIXTURE = "startup_100ed471_ordinary_lifecycle_reload_verified"

RUNTIME_GROUPS = (
    "test_success_alignment_residues_and_cleanup",
    "test_success_maximum_length_and_guest_endpoint",
    "test_first_terminator_and_optional_hook",
    "test_allocation_denial_and_protocol_failures",
    "test_invalid_allocation_results_are_compensated",
    "test_basic_build_preflight_failures",
    "test_owner_and_text_preflight_failures",
    "test_build_range_failures",
    "test_build_alignment_failures",
    "test_build_alias_failures",
    "test_touching_guest_view_boundaries",
    "test_heap_feasibility_preflight",
    "test_cleanup_owner_identity_failures",
    "test_cleanup_basic_range_and_alias_failures",
    "test_cleanup_alignment_failures",
    "test_cleanup_does_not_require_allocator",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetLastError", "GetProcAddress", "GetProcessHeap",
    "HeapAlloc", "HeapFree", "HeapSetInformation", "LoadLibraryA",
    "LoadLibraryW", "MessageBoxA", "MessageBoxW", "RegOpenKeyExW",
    "RegQueryValueExW", "TerminateProcess", "TlsAlloc", "TlsFree",
    "TlsGetValue", "TlsSetValue", "VirtualAlloc", "VirtualFree",
    "VirtualQuery", "calloc", "dlopen", "dlsym", "free", "malloc",
    "memcpy", "memmove", "realloc", "system", "wcslen", "wcscpy",
}

BANNED_ORIGINAL_IDENTIFIERS = {
    "decomp_fn_100ef330", "decomp_fn_100f1bb0", "decomp_fn_100f1cc0",
    "decomp_fn_100fcc80", "decomp_fn_10124e50", "FUN_100ef330",
    "FUN_100f1bb0", "FUN_100f1cc0", "FUN_100fcc80", "FUN_10124e50",
}

BANNED_ORIGINAL_ADDRESS_TOKENS = {
    "0x100ef330", "0x100f1bb0", "0x100f1cc0", "0x100fcc80",
    "0x10124e50", "0x119f3eb0",
}

ALLOWED_SOURCE_CALLS = {
    "UINT32_C", "UINT64_C", "UINT8_C", "_Alignof", "for", "if",
    "return", "sizeof", "allocate", "release", "release_hook",
    BUILD_FUNCTION, CLEANUP_FUNCTION,
    "rome2_100f1bb0_owned_compensate_grant",
    "rome2_100f1bb0_owned_grant_is_zero",
    "rome2_100f1bb0_owned_host_spans_overlap",
    "rome2_100f1bb0_owned_owner_is_empty",
    "rome2_100f1bb0_owned_ranges_overlap",
    "rome2_100f1bb0_owned_read_u32_le",
    "rome2_100f1bb0_owned_resolve_span",
    "rome2_100f1bb0_owned_scan_nonempty_text",
    "rome2_100f1bb0_owned_span_is_contained",
    "rome2_100f1bb0_owned_span_sets_overlap",
    "rome2_100f1bb0_owned_validate_build_backings",
    "rome2_100f1bb0_owned_validate_build_controls",
    "rome2_100f1bb0_owned_validate_cleanup_backings",
    "rome2_100f1bb0_owned_validate_cleanup_controls",
    "rome2_100f1bb0_owned_validate_host_interval",
    "rome2_100f1bb0_owned_validate_object",
    "rome2_100f1bb0_owned_validate_view",
    "rome2_100f1bb0_owned_views_logically_overlap",
    "rome2_100f1bb0_owned_write_u32_le",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return "".join(text.split())


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
    if expected_bytes <= 0 or len(expected_hash) != 64:
        findings.append(f"{label} exact pin is not frozen")
        return
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
    if len(expected_tokens) != 64:
        findings.append(f"{label} executable-token pin is not frozen")
    elif _token_digest(code) != expected_tokens:
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


def _struct_body(code: str, name: str) -> str | None:
    match = re.search(
        rf"typedef\s+struct\s+{re.escape(name)}\s*\{{(?P<body>.*?)\}}\s*"
        rf"{re.escape(name)}\s*;",
        code,
        flags=re.S,
    )
    return None if match is None else match.group("body")


def _reject_unsafe_c(code: str, findings: list[str]) -> None:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for name in sorted((BANNED_IDENTIFIERS | BANNED_ORIGINAL_IDENTIFIERS) & identifiers):
        findings.append(f"forbidden original/allocation/platform identifier: {name}")
    lowered = code.lower()
    for address in sorted(BANNED_ORIGINAL_ADDRESS_TOKENS):
        if address in lowered:
            findings.append(f"forbidden original-address token: {address}")
    if re.search(r"\b(?:extern|volatile|__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append("external/volatile/DLL storage is forbidden")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.M):
        findings.append("pragmas and warning suppression are forbidden")
    guest_pointer_cast = re.compile(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uint64_t|uintptr_t|intptr_t)\s*\*+\s*\)"
        r"\s*[^;\n]{0,160}\b(?:value|guest_start|guest_base)\b"
    )
    guest_native_integer = re.compile(
        r"\(\s*(?:uintptr_t|intptr_t|size_t)\s*\)\s*[^;\n]{0,160}"
        r"\b(?:\.value|guest_start|guest_base)\b"
    )
    if guest_pointer_cast.search(code) or guest_native_integer.search(code):
        findings.append("guest identity is converted to a native pointer/address")
    if re.search(
        r"(?:uint32_t|unsigned\s+(?:int|long))\s+[A-Za-z_]\w*\s*=\s*"
        r"(?:\([^)]*\)\s*)?[^;\n]*host_base",
        code,
    ):
        findings.append("native host address is truncated to guest32")


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_HEADER_BYTES, EXPECTED_HEADER_SHA256,
        EXPECTED_HEADER_TOKEN_SHA256, "header", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.M
    )
    if includes != ["ported_100f1c10_triplet.h"]:
        findings.append("header include set or order changed")
    _reject_unsafe_c(code, findings)

    required = (
        ("#defineROME2_PORT_100F1BB0_OWNED_MAX_UNITSUINT32_C(32768)",
         "32768-unit public bound changed"),
        ("#defineROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASSUINT32_C(0)",
         "allocation class zero changed"),
        ("#defineROME2_PORT_100F1BB0_OWNED_OWNER_LIVEUINT32_C(1)",
         "LIVE owner phase changed"),
        ("#defineROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMEDUINT32_C(2)",
         "CONSUMED owner phase changed"),
        (
            "typedefenumrome2_100f1bb0_owned_grant_result{"
            "ROME2_100F1BB0_OWNED_GRANT_DENIED=0,"
            "ROME2_100F1BB0_OWNED_GRANT_GRANTED=1}"
            "rome2_100f1bb0_owned_grant_result;",
            "two-result grant discriminator changed",
        ),
        (
            "typedefstructrome2_100f1bb0_owned_grant{uint64_ttoken;"
            "rome2_guest_addr32raw_base;uint32_treserved;}"
            "rome2_100f1bb0_owned_grant;",
            "grant token/raw/reserved layout changed",
        ),
        (
            "typedefstructrome2_100f1bb0_owned_owner{uint64_ttoken;"
            "rome2_guest_addr32raw_base;rome2_guest_addr32payload;"
            "uint32_tallocation_bytes;uint32_tlength_units;uint32_tphase;"
            "uint32_treserved;}rome2_100f1bb0_owned_owner;",
            "private owner layout changed",
        ),
        ("_Static_assert(sizeof(rome2_100f1bb0_owned_grant)==16U,",
         "16-byte grant ABI assertion changed"),
        ("_Static_assert(sizeof(rome2_100f1bb0_owned_owner)==32U,",
         "32-byte owner ABI assertion changed"),
        (
            "typedefrome2_100f1bb0_owned_grant_result"
            "(*rome2_100f1bb0_owned_allocate_effect_fn)(void*context,"
            "uint32_tbyte_count,uint32_tallocation_class,"
            "rome2_100f1bb0_owned_grant*grant_out);",
            "allocator grant callback ABI changed",
        ),
        (
            "typedefvoid(*rome2_100f1bb0_owned_release_effect_fn)("
            "void*context,uint64_ttoken,rome2_guest_addr32raw_base,"
            "uint32_tbyte_count,uint32_tallocation_class);",
            "release callback exact-tuple ABI changed",
        ),
        (
            "typedefvoid(*rome2_100f1bb0_owned_release_hook_effect_fn)("
            "void*context,rome2_guest_addr32raw_base,uint32_tzero_argument);",
            "optional release-hook ABI changed",
        ),
        (
            "typedefstructrome2_100f1bb0_owned_effects{"
            "rome2_100f1bb0_owned_allocate_effect_fnallocate;"
            "rome2_100f1bb0_owned_release_effect_fnrelease;"
            "rome2_100f1bb0_owned_release_hook_effect_fnrelease_hook;"
            "void*context;uint64_tcontext_byte_count;}"
            "rome2_100f1bb0_owned_effects;",
            "snapshottable effect table changed",
        ),
        (
            "rome2_100f1bb0_owned_status" + BUILD_FUNCTION + "("
            "constrome2_guest_write_view*descriptor_view,"
            "rome2_guest_addr32guest_descriptor,"
            "constrome2_guest_read_view*text_view,"
            "rome2_guest_addr32guest_text,uint32_tmax_units,"
            "constrome2_guest_write_view*heap_view,"
            "constrome2_100f1bb0_owned_effects*effects,"
            "rome2_100f1bb0_owned_owner*owner_out,"
            "rome2_guest_addr32*guest_return_out);",
            "public owned-build API changed",
        ),
        (
            "rome2_100f1bb0_owned_status" + CLEANUP_FUNCTION + "("
            "constrome2_guest_write_view*descriptor_view,"
            "rome2_guest_addr32guest_descriptor,"
            "constrome2_guest_write_view*heap_view,"
            "constrome2_100f1bb0_owned_effects*effects,"
            "rome2_100f1bb0_owned_owner*owner);",
            "public owning-cleanup API changed",
        ),
    )
    for fragment, message in required:
        _require_once(compact, fragment, findings, message)

    status_values = (
        "ROME2_100F1BB0_OWNED_OK=ROME2_GUEST_OK,"
        "ROME2_100F1BB0_OWNED_BAD_ARGUMENT=ROME2_GUEST_BAD_ARGUMENT,"
        "ROME2_100F1BB0_OWNED_NULL_ADDRESS=ROME2_GUEST_NULL_ADDRESS,"
        "ROME2_100F1BB0_OWNED_RANGE_OVERFLOW=ROME2_GUEST_RANGE_OVERFLOW,"
        "ROME2_100F1BB0_OWNED_OUT_OF_RANGE=ROME2_GUEST_OUT_OF_RANGE,"
        "ROME2_100F1BB0_OWNED_ALLOCATION_DENIED=5,"
        "ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID=6,"
        "ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID=7,"
        "ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID=8,"
        "ROME2_100F1BB0_OWNED_ALREADY_CONSUMED=9"
    )
    if status_values not in compact:
        findings.append("ten-value status domain changed")

    for structure in (
        "rome2_100f1bb0_owned_grant", "rome2_100f1bb0_owned_owner",
    ):
        body = _struct_body(code, structure)
        if body is None or "*" in body:
            findings.append(f"{structure} must remain pointer-free private authority")

    lowered = "".join(text.lower().replace("*", "").split())
    for phrase in (
        "one-shotownershiprecord", "canonicalall-zeroempty",
        "containingarena", "arbitrarybytes", "consumedbefore",
        "anycallback-writtennonzerotokenisfreshone-shotreleaseauthority",
        "guestpayload-4isevidence,neverauthority",
        "originalallocatorandeveryoriginaladdressremaininert",
    ):
        if phrase not in lowered:
            findings.append(f"ownership/effect contract is missing: {phrase}")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_SOURCE_BYTES, EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_TOKEN_SHA256, "source", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.M
    )
    if includes != [
        "ported_100f1bb0_owned_utf16.h", "limits.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include set or order changed")
    _reject_unsafe_c(code, findings)
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    for call in sorted(calls - ALLOWED_SOURCE_CALLS):
        findings.append(f"unexpected source call expression: {call}")

    for function in (BUILD_FUNCTION, CLEANUP_FUNCTION):
        if len(re.findall(
            rf"\brome2_100f1bb0_owned_status\s+{re.escape(function)}\s*\(",
            code,
        )) != 1:
            findings.append(f"exactly one {function} definition is required")

    constants = (
        ("#defineROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest address-space constant changed"),
        ("#defineROME2_100F1BB0_OWNED_DESCRIPTOR_BYTESUINT32_C(12)",
         "12-byte descriptor extent changed"),
        ("#defineROME2_100F1BB0_OWNED_HEADER_BYTESUINT32_C(4)",
         "four-byte hidden header changed"),
        ("#defineROME2_100F1BB0_OWNED_UNIT_BYTESUINT32_C(2)",
         "UTF-16 unit width changed"),
        ("#defineROME2_100F1BB0_OWNED_ALLOCATION_OVERHEADUINT32_C(10)",
         "2N+10 allocation overhead changed"),
        ("#defineROME2_100F1BB0_OWNED_PAYLOAD_BIASUINT32_C(8)",
         "raw-plus-eight alignment bias changed"),
        ("#defineROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT6U",
         "six build controls changed"),
        ("#defineROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT3U",
         "three build backings changed"),
        ("#defineROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT4U",
         "four cleanup controls changed"),
        ("#defineROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT2U",
         "two cleanup backings changed"),
    )
    for fragment, message in constants:
        _require_once(compact, fragment, findings, message)

    validation_fragments = (
        (
            "if(object==NULL||byte_count==0U){"
            "returnROME2_100F1BB0_OWNED_BAD_ARGUMENT;}address=(uintptr_t)object;"
            "if(byte_count-1U>UINTPTR_MAX-address){"
            "returnROME2_100F1BB0_OWNED_RANGE_OVERFLOW;}",
            "control object/null/host-endpoint validation changed",
        ),
        (
            "if(byte_count>ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE||"
            "(uint64_t)guest_base+byte_count>"
            "ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE){"
            "returnROME2_100F1BB0_OWNED_RANGE_OVERFLOW;}",
            "guest view endpoint validation changed",
        ),
        (
            "if(byte_count!=0&&byte_count-UINT64_C(1)>"
            "(uint64_t)(UINTPTR_MAX-host_address)){"
            "returnROME2_100F1BB0_OWNED_RANGE_OVERFLOW;}",
            "view host endpoint validation changed",
        ),
        (
            "if((uint64_t)span_byte_count>"
            "ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE-"
            "(uint64_t)guest_start.value){"
            "returnROME2_100F1BB0_OWNED_RANGE_OVERFLOW;}",
            "resolved-span guest32 overflow validation changed",
        ),
        (
            "if(offset>view_byte_count||(uint64_t)span_byte_count>"
            "view_byte_count-offset||offset>(uint64_t)SIZE_MAX){"
            "returnROME2_100F1BB0_OWNED_OUT_OF_RANGE;}",
            "resolved-span mapping/host-offset validation changed",
        ),
        (
            "span_out->host_start=(uint64_t)(uintptr_t)host_base+offset;",
            "checked mapped host-span derivation changed",
        ),
        (
            "inner->guest_start-outer->guest_start<=outer->byte_count&&"
            "inner->byte_count<=outer->byte_count-(inner->guest_start-"
            "outer->guest_start)&&inner->host_start-outer->host_start<="
            "outer->byte_count&&inner->byte_count<=outer->byte_count-("
            "inner->host_start-outer->host_start);",
            "logical-and-physical containment proof changed",
        ),
    )
    for fragment, message in validation_fragments:
        if fragment not in compact:
            findings.append(message)

    scan_body = _function_body(code, "rome2_100f1bb0_owned_scan_nonempty_text")
    if scan_body is None:
        findings.append("bounded nonempty scanner is missing")
    else:
        scan = _compact(scan_body)
        scan_fragments = (
            ("max_units<UINT32_C(2)||max_units>"
             "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
             "scanner [2,32768] bound changed"),
            ("for(index=0;index<max_units;++index)",
             "finite terminator-inclusive scan changed"),
            ("guest_unit=(uint64_t)guest_text.value+(uint64_t)index*"
             "ROME2_100F1BB0_OWNED_UNIT_BYTES;",
             "checked UTF-16 address derivation changed"),
            ("if(guest_unit>UINT32_MAX-UINT32_C(1))",
             "UTF-16 guest endpoint guard changed"),
            ("if(unit==0){if(index==0){return"
             "ROME2_100F1BB0_OWNED_BAD_ARGUMENT;}source_bytes=(index+"
             "UINT32_C(1))*ROME2_100F1BB0_OWNED_UNIT_BYTES;"
             "*length_out=index;",
             "first-zero/nonempty/source-span semantics changed"),
            ("returnROME2_100F1BB0_OWNED_OUT_OF_RANGE;",
             "missing terminator failure changed"),
        )
        for fragment, message in scan_fragments:
            if fragment not in scan:
                findings.append(message)

    owner_empty_body = _function_body(code, "rome2_100f1bb0_owned_owner_is_empty")
    expected_owner_empty = (
        "returnowner->token==UINT64_C(0)&&"
        "owner->raw_base.value==UINT32_C(0)&&"
        "owner->payload.value==UINT32_C(0)&&"
        "owner->allocation_bytes==UINT32_C(0)&&"
        "owner->length_units==UINT32_C(0)&&"
        "owner->phase==UINT32_C(0)&&owner->reserved==UINT32_C(0);"
    )
    if owner_empty_body is None or _compact(owner_empty_body) != expected_owner_empty:
        findings.append("canonical all-zero EMPTY owner validation changed")
    grant_zero_body = _function_body(code, "rome2_100f1bb0_owned_grant_is_zero")
    expected_grant_zero = (
        "returngrant->token==UINT64_C(0)&&"
        "grant->raw_base.value==UINT32_C(0)&&grant->reserved==UINT32_C(0);"
    )
    if grant_zero_body is None or _compact(grant_zero_body) != expected_grant_zero:
        findings.append("canonical all-zero allocator grant validation changed")

    compensate_body = _function_body(code, "rome2_100f1bb0_owned_compensate_grant")
    if compensate_body is None:
        findings.append("grant compensation helper is missing")
    else:
        compensation = _compact(compensate_body)
        expected = (
            "if(state->grant.token!=UINT64_C(0)){state->effects.release("
            "state->effects.context,state->grant.token,state->grant.raw_base,"
            "state->allocation_bytes,"
            "ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);}"
        )
        if compensation != expected:
            findings.append("nonzero-token compensation exact tuple changed")
        if "release_hook" in compensation:
            findings.append("grant compensation must never invoke the hook")

    build_body = _function_body(code, BUILD_FUNCTION)
    if build_body is None:
        findings.append("owned UTF-16 build body is missing")
    else:
        build = _compact(build_body)
        preflight_order = (
            "rome2_100f1bb0_owned_build_privatestate={0};",
            "rome2_100f1bb0_owned_validate_build_controls(",
            "state.descriptor_view=*descriptor_view;",
            "state.effects=*effects;",
            "rome2_100f1bb0_owned_validate_host_interval(",
            "rome2_100f1bb0_owned_owner_is_empty(&state.owner_initial)",
            "rome2_100f1bb0_owned_validate_build_backings(&state)",
            "rome2_100f1bb0_owned_scan_nonempty_text(",
            "state.grant_result=state.effects.allocate(",
        )
        _require_in_order(
            build, preflight_order, findings,
            "validation/snapshot/scan must precede the sole allocator effect",
        )
        build_required = (
            ("state.payload_bytes=state.length_units*"
             "ROME2_100F1BB0_OWNED_UNIT_BYTES;state.allocation_bytes="
             "state.payload_bytes+ROME2_100F1BB0_OWNED_ALLOCATION_OVERHEAD;",
             "checked 2N+10 request formula changed"),
            ("state.heap_available_bytes=state.heap_view.byte_count;"
             "if(state.heap_view.guest_base==UINT32_C(0)){"
             "if(state.heap_available_bytes==UINT64_C(0)){return"
             "ROME2_100F1BB0_OWNED_OUT_OF_RANGE;}"
             "--state.heap_available_bytes;}if(state.heap_available_bytes<"
             "(uint64_t)state.allocation_bytes){return"
             "ROME2_100F1BB0_OWNED_OUT_OF_RANGE;}",
             "pre-effect heap capacity proof changed"),
            ("state.grant_result=state.effects.allocate(state.effects.context,"
             "state.allocation_bytes,"
             "ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,&state.grant);",
             "one allocator grant call/arguments changed"),
            ("if(state.grant_result==ROME2_100F1BB0_OWNED_GRANT_DENIED){"
             "if(rome2_100f1bb0_owned_grant_is_zero(&state.grant)){return"
             "ROME2_100F1BB0_OWNED_ALLOCATION_DENIED;}"
             "rome2_100f1bb0_owned_compensate_grant(&state);return"
             "ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;}",
             "denied/dirty-grant compensation policy changed"),
            ("if(state.grant_result!=ROME2_100F1BB0_OWNED_GRANT_GRANTED||"
             "state.grant.token==UINT64_C(0)||state.grant.reserved!=0){"
             "rome2_100f1bb0_owned_compensate_grant(&state);return"
             "ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;}",
             "grant discriminator/token/reserved validation changed"),
            ("state.payload_value=((uint64_t)state.grant.raw_base.value+"
             "ROME2_100F1BB0_OWNED_PAYLOAD_BIAS)&~UINT64_C(3);",
             "(raw+8)&~3 alignment formula changed"),
            ("state.header_identity.value=state.payload_identity.value-"
             "ROME2_100F1BB0_OWNED_HEADER_BYTES;",
             "payload-minus-four header identity changed"),
            ("state.terminator_value=state.payload_value+(uint64_t)"
             "state.payload_bytes;",
             "payload-plus-2N terminator identity changed"),
            ("rome2_100f1bb0_owned_span_is_contained(&state.allocation,"
             "&state.header)",
             "hidden header containment check changed"),
            ("rome2_100f1bb0_owned_span_is_contained(&state.allocation,"
             "&state.payload)",
             "payload containment check changed"),
            ("rome2_100f1bb0_owned_span_is_contained(&state.allocation,"
             "&state.terminator)",
             "terminator containment check changed"),
        )
        for fragment, message in build_required:
            if fragment not in build:
                findings.append(message)
        if build.count("state.effects.allocate(") != 1:
            findings.append("build must invoke the allocator exactly once")
        if build.count("rome2_100f1bb0_owned_compensate_grant(&state);") != 7:
            findings.append("seven fail-closed compensation sites changed")

        commit_order = (
            "rome2_100f1bb0_owned_write_u32_le(state.heap_view.host_base+"
            "(size_t)state.header.view_offset,state.grant.raw_base.value);",
            "for(state.copy_index=0;state.copy_index<state.payload_bytes;"
            "++state.copy_index)",
            "state.heap_view.host_base[(size_t)state.terminator.view_offset]="
            "UINT8_C(0);",
            "state.heap_view.host_base[(size_t)state.terminator.view_offset+1U]="
            "UINT8_C(0);",
            "state.owner_commit.token=state.grant.token;",
            "state.owner_commit.phase=ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;",
            "*owner_out=state.owner_commit;",
            "*guest_return_out=guest_descriptor;",
            "returnROME2_100F1BB0_OWNED_OK;",
        )
        _require_in_order(
            build, commit_order, findings,
            "header/copy/zero/descriptor/LIVE/return commit order changed",
        )
        for offset, value, message in (
            ("", "state.length_units", "descriptor length field zero changed"),
            ("+4U", "state.length_units", "descriptor length field four changed"),
            ("+8U", "state.payload_identity.value", "descriptor payload field changed"),
        ):
            fragment = (
                "rome2_100f1bb0_owned_write_u32_le("
                "state.descriptor_view.host_base+(size_t)"
                f"state.descriptor.view_offset{offset},{value});"
            )
            if fragment not in build:
                findings.append(message)

    alias_fragments = (
        ("state->controls[0].start=(uint64_t)(uintptr_t)descriptor_view;"
         "state->controls[0].byte_count=sizeof(*descriptor_view);",
         "descriptor-view control alias protection changed"),
        ("state->controls[1].start=(uint64_t)(uintptr_t)text_view;"
         "state->controls[1].byte_count=sizeof(*text_view);",
         "text-view build control alias protection changed"),
        ("state->controls[2].start=(uint64_t)(uintptr_t)heap_view;"
         "state->controls[2].byte_count=sizeof(*heap_view);",
         "heap-view build control alias protection changed"),
        ("state->controls[3].start=(uint64_t)(uintptr_t)effects;"
         "state->controls[3].byte_count=sizeof(*effects);",
         "effects build control alias protection changed"),
        ("state->controls[4].start=(uint64_t)(uintptr_t)owner_out;"
         "state->controls[4].byte_count=sizeof(*owner_out);",
         "owner-output control alias protection changed"),
        ("state->controls[5].start=(uint64_t)(uintptr_t)guest_return_out;",
         "build control slot 5/return alias protection changed"),
        ("state->private_span.start=(uint64_t)(uintptr_t)state;",
         "private-local alias protection changed"),
        ("state->backings[2].start=(uint64_t)(uintptr_t)"
         "state->heap_view.host_base;",
         "heap backing alias protection changed"),
        ("state->context.start=(uint64_t)(uintptr_t)state->effects.context;",
         "effect-context alias protection changed"),
        ("rome2_100f1bb0_owned_views_logically_overlap("
         "state->descriptor_view.guest_base,state->descriptor_view.byte_count,"
         "state->text_view.guest_base,state->text_view.byte_count)",
         "descriptor/text logical alias rejection changed"),
        ("rome2_100f1bb0_owned_views_logically_overlap("
         "state->descriptor_view.guest_base,state->descriptor_view.byte_count,"
         "state->heap_view.guest_base,state->heap_view.byte_count)",
         "descriptor/heap logical alias rejection changed"),
        ("rome2_100f1bb0_owned_views_logically_overlap("
         "state->text_view.guest_base,state->text_view.byte_count,"
         "state->heap_view.guest_base,state->heap_view.byte_count)",
         "text/heap logical alias rejection changed"),
    )
    for fragment, message in alias_fragments:
        if fragment not in compact:
            findings.append(message)
    if compact.count(
        "state->private_span.start=(uint64_t)(uintptr_t)state;"
        "state->private_span.byte_count=sizeof(*state);"
    ) != 2:
        findings.append("both build and cleanup private-local alias spans are required")
    if compact.count(
        "state->context.start=(uint64_t)(uintptr_t)state->effects.context;"
        "state->context.byte_count=state->effects.context_byte_count;"
    ) != 2:
        findings.append("both build and cleanup effect-context alias spans are required")
    for fragment, expected_count, message in (
        ("rome2_100f1bb0_owned_host_spans_overlap(", 5,
         "four host-span pairwise alias matrices changed"),
        ("rome2_100f1bb0_owned_span_sets_overlap(", 13,
         "twelve cross-set alias matrices changed"),
        ("rome2_100f1bb0_owned_views_logically_overlap(", 5,
         "four logical guest-view alias checks changed"),
        ("rome2_100f1bb0_owned_span_is_contained(", 6,
         "five raw-allocation containment checks changed"),
    ):
        if compact.count(fragment) != expected_count:
            findings.append(message)
    cleanup_alias_fragments = (
        ("state->controls[1].start=(uint64_t)(uintptr_t)heap_view;"
         "state->controls[1].byte_count=sizeof(*heap_view);",
         "heap-view cleanup control alias protection changed"),
        ("state->controls[2].start=(uint64_t)(uintptr_t)effects;"
         "state->controls[2].byte_count=sizeof(*effects);",
         "effects cleanup control alias protection changed"),
        ("state->controls[3].start=(uint64_t)(uintptr_t)owner;"
         "state->controls[3].byte_count=sizeof(*owner);",
         "owner cleanup control alias protection changed"),
        ("state->backings[0].start=(uint64_t)(uintptr_t)"
         "state->descriptor_view.host_base;state->backings[0].byte_count="
         "state->descriptor_view.byte_count;",
         "descriptor backing alias protection changed"),
        ("state->backings[1].start=(uint64_t)(uintptr_t)"
         "state->text_view.host_base;state->backings[1].byte_count="
         "state->text_view.byte_count;",
         "text backing alias protection changed"),
        ("state->backings[2].start=(uint64_t)(uintptr_t)"
         "state->heap_view.host_base;state->backings[2].byte_count="
         "state->heap_view.byte_count;",
         "build heap backing alias protection changed"),
        ("state->backings[1].start=(uint64_t)(uintptr_t)"
         "state->heap_view.host_base;state->backings[1].byte_count="
         "state->heap_view.byte_count;",
         "cleanup heap backing alias protection changed"),
    )
    for fragment, message in cleanup_alias_fragments:
        if fragment not in compact:
            findings.append(message)

    cleanup_body = _function_body(code, CLEANUP_FUNCTION)
    if cleanup_body is None:
        findings.append("owning cleanup body is missing")
    else:
        cleanup = _compact(cleanup_body)
        cleanup_required = (
            ("if(state.owner.phase=="
             "ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED){return"
             "ROME2_100F1BB0_OWNED_ALREADY_CONSUMED;}",
             "already-CONSUMED no-effect decision changed"),
            ("state.owner.phase!=ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE||"
             "state.owner.token==UINT64_C(0)||"
             "state.owner.raw_base.value==UINT32_C(0)||"
             "state.owner.payload.value==UINT32_C(0)||"
             "state.owner.reserved!=UINT32_C(0)||"
             "state.owner.length_units==UINT32_C(0)||"
             "state.owner.length_units>="
             "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
             "LIVE private-owner authority validation changed"),
            ("state.expected_payload_bytes=state.owner.length_units*"
             "ROME2_100F1BB0_OWNED_UNIT_BYTES;"
             "state.expected_allocation_bytes=state.expected_payload_bytes+"
             "ROME2_100F1BB0_OWNED_ALLOCATION_OVERHEAD;",
             "cleanup 2N+10 formula changed"),
            ("state.expected_payload=((uint64_t)state.owner.raw_base.value+"
             "ROME2_100F1BB0_OWNED_PAYLOAD_BIAS)&~UINT64_C(3);",
             "cleanup aligned payload formula changed"),
            ("state.owner.allocation_bytes!=state.expected_allocation_bytes",
             "cleanup allocation extent check changed"),
            ("state.owner.payload.value!=(uint32_t)state.expected_payload",
             "cleanup payload identity check changed"),
            ("rome2_100f1bb0_owned_read_u32_le(state.descriptor_bytes)!="
             "state.owner.length_units",
             "cleanup descriptor length validation changed"),
            ("rome2_100f1bb0_owned_read_u32_le(state.descriptor_bytes+8U)!="
             "state.owner.payload.value",
             "cleanup descriptor payload validation changed"),
            ("state.owner.raw_base.value||"
             "state.heap_view.host_base[(size_t)state.terminator.view_offset]"
             "!=UINT8_C(0)||state.heap_view.host_base[(size_t)"
             "state.terminator.view_offset+1U]!=UINT8_C(0)",
             "cleanup hidden-header/zero-terminator validation changed"),
        )
        for fragment, message in cleanup_required:
            if fragment not in cleanup:
                findings.append(message)
        cleanup_order = (
            "owner->phase=ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;",
            "state.effects.release(state.effects.context,state.owner.token,"
            "state.owner.raw_base,state.owner.allocation_bytes,"
            "ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);",
            "if(state.effects.release_hook!=NULL)",
            "state.effects.release_hook(state.effects.context,"
            "state.owner.raw_base,UINT32_C(0));",
            "returnROME2_100F1BB0_OWNED_OK;",
        )
        _require_in_order(
            cleanup, cleanup_order, findings,
            "CONSUMED-before-release-before-optional-hook order changed",
        )
        if cleanup.count("state.effects.release(") != 1:
            findings.append("cleanup must release the LIVE grant exactly once")
        if cleanup.count("owner->phase=") != 1:
            findings.append("cleanup may mutate only the owner phase once")
        if "state.source" in cleanup or "payload.view_offset" in cleanup:
            findings.append("cleanup must not invent payload/source revalidation")

    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_PROVENANCE_BYTES, EXPECTED_PROVENANCE_SHA256,
        "owned UTF-16 provenance", findings,
    )
    required = (
        "WRAPPER_SHA256", "HELPER_SHA256", "NONEMPTY_SHA256",
        "CLEANUP_SHA256", "ALLOCATOR_SHA256", "RELEASE_SHA256",
        '"payload_length_domain": (1, MAX_PAYLOAD_UNITS)',
        '"maximum_allocation_bytes": MAX_ALLOCATION_BYTES',
        '"invalid_nonzero_token_grant": "exactly_one_compensating_release_exact_tuple"',
        '"cleanup_consume_order": "CONSUMED_before_release_before_optional_hook"',
        "self.assertEqual(mutant_count, 99)",
        "self.assertEqual(mutant_count, 25)",
    )
    for token in required:
        if token not in text:
            findings.append(f"provenance contract token changed: {token[:48]}")
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC_BYTES, EXPECTED_DOC_SHA256,
                 "owned UTF-16 doc", findings)
    for phrase in (
        "No original address is executable.",
        "`0x100f1bb0 -> 0x100ef330`", "`2*N+10`", "`(raw+8)&~3`",
        "canonical all-zero `EMPTY`", "exactly one compensating release",
        "private `LIVE`", "commits `CONSUMED` before release",
        "does not compare payload bytes",
    ):
        if phrase not in text:
            findings.append(f"owned UTF-16 doc contract is missing: {phrase}")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_TEST_BYTES, EXPECTED_TEST_SHA256,
        EXPECTED_TEST_TOKEN_SHA256, "runtime oracle", findings,
    )
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.M
    )
    if includes != [
        "ported_100f1bb0_owned_utf16.h", "stddef.h", "stdint.h",
        "stdio.h", "string.h",
    ]:
        findings.append("runtime include set or order changed")
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for name in sorted((BANNED_IDENTIFIERS | BANNED_ORIGINAL_IDENTIFIERS) & identifiers):
        if name not in {"memcpy", "memcmp"}:
            findings.append(f"runtime invokes forbidden original/platform API: {name}")
    required = (
        ("ROME2_PORT_100F1BB0_OWNED_MAX_UNITS==UINT32_C(32768)",
         "runtime 32768-unit bound assertion changed"),
        ("sizeof(rome2_100f1bb0_owned_grant)==16U&&"
         "sizeof(rome2_100f1bb0_owned_owner)==32U",
         "runtime grant/owner ABI assertion changed"),
        ("grant_out->token!=UINT64_C(0)||grant_out->raw_base.value!="
         "UINT32_C(0)||grant_out->reserved!=UINT32_C(0)",
         "runtime zeroed-grant observation changed"),
        ("context->observed_owner->phase!=context->expected_owner_phase",
         "runtime CONSUMED-before-release observation changed"),
        ("context->events[0]!=TEST_EVENT_RELEASE||"
         "context->events[1]!=TEST_EVENT_HOOK",
         "runtime release-before-hook observation changed"),
        ("TEST_MAX_LENGTH*UINT32_C(2)+UINT32_C(10)",
         "runtime maximum 2N+10 formula changed"),
        ("(uint64_t)raw+(uint64_t)allocation_bytes=="
         "(UINT64_C(1)<<32)",
         "runtime exact guest32 endpoint case changed"),
        ("expected_owner.phase=ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;",
         "runtime cleanup phase-only expectation changed"),
        ("fixture->context.hook_calls==UINT32_C(0)",
         "runtime compensation-without-hook check changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)
    if compact.count(
        "grant_out->token!=UINT64_C(0)||grant_out->raw_base.value!="
        "UINT32_C(0)||grant_out->reserved!=UINT32_C(0)"
    ) != 1:
        findings.append("runtime must observe one canonical zero grant")
    if compact.count(
        "context->observed_owner->phase!=context->expected_owner_phase"
    ) != 2:
        findings.append("runtime must observe CONSUMED in release and hook")
    preservation = (
        ("memcmp(&fixture->owner,&test_snapshot_storage.owner,"
         "sizeof(fixture->owner))==0", "runtime owner-preservation proof changed"),
        ("fixture->guest_return.value=="
         "test_snapshot_storage.guest_return.value",
         "runtime return-preservation proof changed"),
        ("if(expect_context_unchanged){failed|=test_expect(memcmp("
         "&fixture->context,&test_snapshot_storage.context,"
         "sizeof(fixture->context))==0,case_name,);}",
         "runtime preflight context-preservation proof changed"),
        ("fixture->context.release_calls==expected_release_calls&&"
         "fixture->context.hook_calls==UINT32_C(0)&&"
         "fixture->context.event_count==UINT32_C(1)+expected_release_calls",
         "runtime compensation-without-hook transcript changed"),
    )
    for fragment, message in preservation:
        if fragment not in compact:
            findings.append(message)
    for case in (
        "length-one raw alignment residue %u",
        "maximum length ending exactly at 2^32",
        "first terminator wins with trailing source units",
        "cleanup permits mutable payload and absent optional hook",
        "a consumed owner was not rejected",
        "explicit allocation denial",
        "invalid allocation-result discriminator",
        "denial carrying a nonzero-token grant",
        "granted result without authority token",
        "granted result with nonzero reserved field",
        "raw allocation truncated by heap arena",
        "raw-plus-eight reaches guest endpoint",
        "preflight failure invoked an effect",
        "owner phase must begin zero",
        "descriptor truncated to %u of 12 bytes",
        "terminator absent from declared budget",
        "descriptor span crosses guest endpoint",
        "misaligned descriptor-view control",
        "owner and return outputs alias",
        "descriptor and text host backings overlap",
        "descriptor and heap guest intervals overlap",
        "bounded context aliases owner control",
        "nonnull-base heap arena has %u of %u required bytes",
        "base-zero heap loses one byte to the null identity",
        "consumed owner is one-shot",
        "owner allocation size differs from formula",
        "descriptor payload differs from owner",
        "owned terminator is not literal zero",
        "cleanup descriptor and heap host backings overlap",
        "cleanup descriptor and heap guest intervals overlap",
        "cleanup context aliases owner control",
        "misaligned cleanup owner",
        "cleanup uses only release-side effects",
    ):
        if case not in text:
            findings.append(f"runtime reciprocal case missing: {case}")
    if re.search(r"\b(?:decomp_fn_|FUN_)[A-Za-z0-9_]*\s*\(", code):
        findings.append("runtime must never execute an original function")
    main_body = _function_body(code, "main")
    if main_body is None:
        findings.append("runtime main registry is missing")
    else:
        main = _compact(main_body)
        _require_in_order(
            main,
            tuple(f"failures+={group}();" for group in RUNTIME_GROUPS),
            findings,
            "runtime 16-group registry/order changed",
        )
        if sum(main.count(f"failures+={group}();") for group in RUNTIME_GROUPS) != 16:
            findings.append("runtime must invoke all sixteen groups exactly once")
    for group in RUNTIME_GROUPS:
        if len(re.findall(rf"\bstatic\s+int\s+{re.escape(group)}\s*\(", code)) != 1:
            findings.append(f"runtime group definition changed: {group}")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    selected: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, re.I):
            stack.append((
                index,
                bool(re.match(r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, re.I)),
            ))
        elif re.match(r"endif(?:\s*\([^)]*\))?\s*$", stripped, re.I):
            if not stack:
                return None
            start, is_build_testing = stack.pop()
            if is_build_testing:
                selected.append((start, index))
    if stack or len(selected) != 1:
        return None
    return selected[0]


def _link_commands(text: str) -> list[list[str]]:
    commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    return [re.split(r"\s+", command.strip()) for command in commands]


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_CMAKE_BYTES, EXPECTED_CMAKE_SHA256,
                 "CMake", findings)
    if len(re.findall(r"^\s*add_test\s*\(", text, flags=re.I | re.M)) != (
        EXPECTED_CTEST_COUNT
    ):
        findings.append(
            f"CMake total must be exactly {EXPECTED_CTEST_COUNT} CTests"
        )
    if re.search(r"\b(?:set|option)\s*\(\s*BUILD_TESTING\b", text, re.I):
        findings.append("CMake must not override BUILD_TESTING")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        findings.append("one balanced if(BUILD_TESTING) block is required")
        return sorted(set(findings))
    start, end = bounds
    for token in CMAKE_FILES + CMAKE_TESTS + (LIBRARY, TEST_TARGET):
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake owned-UTF16 token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake owned-UTF16 token escapes BUILD_TESTING: {token}")

    scoped = _compact("\n".join(lines[start + 1:end]))
    required = (
        (
            f"add_library({LIBRARY}STATIC"
            '"${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_owned_utf16.h"'
            '"${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_owned_utf16.c")',
            "CMake owned-UTF16 library must be exact static and test-only",
        ),
        (
            f"target_compile_features({LIBRARY}PUBLICc_std_17)",
            "CMake owned-UTF16 C17 requirement changed",
        ),
        (
            f"target_compile_options({LIBRARY}PRIVATE"
            "${ROME2_HARDENED_COMPILE_OPTIONS})",
            "CMake owned-UTF16 hardened compile options changed",
        ),
        (
            f"target_include_directories({LIBRARY}PUBLIC"
            '"${ROME2_GUEST32_RUNTIME_DIR}"'
            '"${ROME2_GUEST32_PORTED_DIR}")',
            "CMake owned-UTF16 include surface changed",
        ),
        (
            f"add_executable({TEST_TARGET}"
            '"${ROME2_GUEST32_RUNTIME_DIR}/'
            'test_startup_100f1bb0_owned_utf16.c")',
            "CMake owned-UTF16 runtime executable changed",
        ),
        (
            f"rome2_configure_x64_target({TEST_TARGET})",
            "CMake owned-UTF16 runtime x64 configuration changed",
        ),
        (
            f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
            "CMake owned-UTF16 runtime link changed",
        ),
    )
    for fragment, message in required:
        if scoped.count(fragment) != 1:
            findings.append(message)

    commands = _link_commands(text)
    own = [words for words in commands if words and words[0] == LIBRARY]
    if own != [[LIBRARY, "PUBLIC", "rome2_guest32_runtime"]]:
        findings.append(
            "CMake owned-UTF16 library dependency must be exactly guest32/public"
        )
    consumers = [
        words[0] for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if consumers != [TEST_TARGET, SUCCESSOR_LIBRARY, PARENT_LIBRARY]:
        findings.append(
            "CMake owned-UTF16 consumers must be exactly its standalone runtime "
            "test, sentinel-owned successor, and nonempty parent"
        )

    for name in CMAKE_TESTS:
        if scoped.count(f"add_test(NAME{name}COMMAND") != 1:
            findings.append(f"CMake owned-UTF16 CTest registration changed: {name}")

    gate_start = scoped.find(
        "add_test(NAMEstartup_100f1bb0_owned_utf16_static_gateCOMMAND"
    )
    gate_end = scoped.find("add_test(", gate_start + 1)
    gate_scope = scoped[gate_start:gate_end] if gate_start >= 0 else ""
    gate_args = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/'
        'ported_100f1bb0_owned_utf16.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/'
        'ported_100f1bb0_owned_utf16.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/'
        'test_startup_100f1bb0_owned_utf16.c"',
        '--owned-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100f1bb0_owned_utf16_provenance.py"',
        '--doc"${CMAKE_CURRENT_SOURCE_DIR}/docs/'
        'x64_startup_100f1bb0_owned_utf16.md"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
    )
    for argument in gate_args:
        if gate_scope.count(argument) != 1:
            findings.append(
                f"CMake owned-UTF16 static-gate argument changed: {argument[:76]}"
            )

    fixtures = (
        (
            "startup_100f1bb0_owned_utf16_provenancePROPERTIES"
            "FIXTURES_SETUPstartup_100f1bb0_owned_utf16_provenance_verified",
            "CMake owned-UTF16 provenance fixture changed",
        ),
        (
            "startup_100f1bb0_owned_utf16_static_gate_unitPROPERTIES"
            "FIXTURES_SETUPstartup_100f1bb0_owned_utf16_static_tool_verified",
            "CMake owned-UTF16 reciprocal-tool fixture changed",
        ),
        (
            "startup_100f1bb0_owned_utf16_static_gatePROPERTIES"
            "FIXTURES_REQUIREDstartup_100f1bb0_owned_utf16_static_tool_verified"
            "FIXTURES_SETUPstartup_100f1bb0_owned_utf16_static_verified",
            "CMake owned-UTF16 live-static fixture changed",
        ),
        (
            "startup_100f1bb0_owned_utf16_runtimePROPERTIES"
            "FIXTURES_REQUIRED\"" + PREDECESSOR_FIXTURE + ";"
            "startup_100f1bb0_owned_utf16_provenance_verified;"
            "startup_100f1bb0_owned_utf16_static_verified\""
            "FIXTURES_SETUPstartup_100f1bb0_owned_utf16_runtime_verified"
            "TIMEOUT90",
            "CMake owned-UTF16 runtime fixture chain changed",
        ),
    )
    for fragment, message in fixtures:
        if scoped.count(fragment) != 1:
            findings.append(message)
    return sorted(set(findings))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument("--owned-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--doc", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "runtime": (args.test, inspect_test_text),
        "provenance": (args.owned_provenance, inspect_provenance_text),
        "doc": (args.doc, inspect_doc_text),
        "CMake": (args.cmake, inspect_cmake_text),
    }
    failed = False
    for label, (path, inspector) in checks.items():
        text, findings = _decode_utf8(path)
        if text is not None:
            findings.extend(inspector(text))
        for finding in sorted(set(findings)):
            print(f"{path}: {label}: {finding}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
