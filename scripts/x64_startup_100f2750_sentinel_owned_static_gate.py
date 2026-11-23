#!/usr/bin/env python3
"""Fail-closed gate for the injected 0x100f2750 sentinel-owned lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


REGISTER_FUNCTION = "rome2_port_100f2750_register_first_use_owned"
BUILD_FUNCTION = "rome2_port_100f2750_first_use_owned"
TEARDOWN_FUNCTION = "rome2_port_100f2750_teardown_first_use_owned"
DELEGATE_BUILD = "rome2_port_100f1bb0_build_owned_utf16"
DELEGATE_CLEANUP = "rome2_port_100f1cc0_cleanup_owned_utf16"
LIBRARY = "rome2_startup_100f2750_sentinel_owned_runtime"
TEST_TARGET = "rome2_startup_100f2750_sentinel_owned_tests"
PREDECESSOR_FIXTURE = "startup_100f1bb0_owned_utf16_runtime_verified"
PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"

# Frozen after the standalone BUILD_TESTING-only target and fixture chain were
# admitted.  Any later CMake change must be consciously re-audited and re-pinned.
EXPECTED_CTEST_COUNT = 194
EXPECTED_CMAKE_BYTES = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)
EXPECTED_HEADER_BYTES = 4_603
EXPECTED_HEADER_SHA256 = (
    "4e766b3bec926adadde9e60dfb04e4459cfa33d22be6ec9295b5b77fdabbf86d"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "b8b084312f3c2d90991e09dd304caf391df38a54bc1302c69cac0707befb4266"
)
EXPECTED_SOURCE_BYTES = 56_125
EXPECTED_SOURCE_SHA256 = (
    "607fe4812f7dbd19196ed653be4d4a0fabe0e1740c8ad5d86fc6193a7b566b21"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "badaccc88fc79d953e9500b882ca3b0d0523533527ecae668b275c4bf2c6cf6c"
)
EXPECTED_TEST_BYTES = 71_106
EXPECTED_TEST_SHA256 = (
    "2841117daab70e293c29d714ac05a035a9245cf8d1eb1ad2f4c80efd0a79fddd"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "1b7546f286e06daf77c74aa0232bf09f8279843e8ac159ee0df42bbc2692181f"
)

EXPECTED_PROVENANCE_BYTES = 43_941
EXPECTED_PROVENANCE_SHA256 = (
    "595667f61b49688d49d8eb0bc2e47adf687959b5d74428630987ca0cc2b6497b"
)
EXPECTED_DOC_BYTES = 12_022
EXPECTED_DOC_SHA256 = (
    "186606cf107b39340a01181505f4f1ffeb58d28c4fc1fffe7025970e3ae17b6a"
)

CMAKE_FILES = (
    "ported_100f2750_first_use_owned.h",
    "ported_100f2750_first_use_owned.c",
    "test_startup_100f2750_sentinel_owned.c",
    "test_x64_startup_100f2750_sentinel_owned_provenance.py",
    "test_x64_startup_100f2750_sentinel_owned_static_gate.py",
    "x64_startup_100f2750_sentinel_owned_static_gate.py",
    "x64_startup_100f2750_sentinel_owned.md",
)
CMAKE_TESTS = (
    "startup_100f2750_sentinel_owned_provenance",
    "startup_100f2750_sentinel_owned_static_gate_unit",
    "startup_100f2750_sentinel_owned_static_gate",
    "startup_100f2750_sentinel_owned_runtime",
)

RUNTIME_GROUPS = (
    "test_registration_contract",
    "test_success_residues_and_maximum",
    "test_allocation_failures",
    "test_source_authentication_failures",
    "test_preflight_failures",
    "test_teardown_contract",
    "test_teardown_validation_failures",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetLastError", "GetProcAddress", "GetProcessHeap",
    "HeapAlloc", "HeapFree", "HeapSetInformation", "LoadLibraryA",
    "LoadLibraryW", "MessageBoxA", "MessageBoxW", "RegOpenKeyExW",
    "RegQueryValueExW", "TerminateProcess", "TlsAlloc", "TlsFree",
    "TlsGetValue", "TlsSetValue", "VirtualAlloc", "VirtualFree",
    "VirtualQuery", "_atexit", "_onexit", "atexit", "calloc", "dlopen",
    "dlsym", "free", "malloc", "memcpy", "memmove", "realloc", "system",
    "wcslen", "wcscpy",
}
BANNED_ORIGINAL_IDENTIFIERS = {
    "decomp_fn_100df270", "decomp_fn_100e8240", "decomp_fn_100ed3c0",
    "decomp_fn_100ef330", "decomp_fn_100f1c10", "decomp_fn_100f1cc0",
    "decomp_fn_100f2750", "decomp_fn_10124e50", "decomp_fn_116838ea",
    "FUN_100df270", "FUN_100e8240", "FUN_100ed3c0", "FUN_100ef330",
    "FUN_100f1c10", "FUN_100f1cc0", "FUN_100f2750", "FUN_10124e50",
}
BANNED_ORIGINAL_ADDRESS_TOKENS = {
    "0x100df270", "0x100e8240", "0x100ed3c0", "0x100ef330",
    "0x100f1c10", "0x100f1cc0", "0x100f2750", "0x10124e50",
    "0x116838ea", "0x116ddc80", "0x119f3eb0",
}

ALLOWED_SOURCE_CALLS = {
    "UINT8_C", "UINT32_C", "UINT64_C", "_Alignof", "for", "if",
    "return", "sizeof", "allocate", "release",
    REGISTER_FUNCTION, BUILD_FUNCTION, TEARDOWN_FUNCTION,
    DELEGATE_CLEANUP,
    "rome2_100f2750_first_use_authenticate_temporary",
    "rome2_100f2750_first_use_compensate_grant",
    "rome2_100f2750_first_use_grant_is_zero",
    "rome2_100f2750_first_use_host_spans_overlap",
    "rome2_100f2750_first_use_lifecycle_is_empty",
    "rome2_100f2750_first_use_owner_is_empty",
    "rome2_100f2750_first_use_ranges_overlap",
    "rome2_100f2750_first_use_read_u32_le",
    "rome2_100f2750_first_use_resolve_span",
    "rome2_100f2750_first_use_span_is_contained",
    "rome2_100f2750_first_use_span_sets_overlap",
    "rome2_100f2750_first_use_validate_backings",
    "rome2_100f2750_first_use_validate_controls",
    "rome2_100f2750_first_use_validate_host_interval",
    "rome2_100f2750_first_use_validate_object",
    "rome2_100f2750_first_use_validate_view",
    "rome2_100f2750_first_use_views_logically_overlap",
    "rome2_100f2750_first_use_write_u32_le",
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


def _function_body(code: str, function: str) -> str | None:
    matches = list(re.finditer(rf"\b{re.escape(function)}\s*\(", code))
    for match in matches:
        open_paren = code.find("(", match.start())
        depth = 0
        close_paren = -1
        for index in range(open_paren, len(code)):
            if code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren < 0:
            continue
        open_brace = close_paren + 1
        while open_brace < len(code) and code[open_brace].isspace():
            open_brace += 1
        if open_brace >= len(code) or code[open_brace] != "{":
            continue
        depth = 0
        for index in range(open_brace, len(code)):
            if code[index] == "{":
                depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0:
                    return code[open_brace + 1:index]
    return None


def _require_in_order(
    compact: str,
    fragments: tuple[str, ...],
    findings: list[str],
    message: str,
) -> None:
    cursor = -1
    for fragment in fragments:
        cursor = compact.find(fragment, cursor + 1)
        if cursor < 0:
            findings.append(message)
            return


def _reject_unsafe_c(code: str, label: str, findings: list[str]) -> None:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for identifier in sorted((BANNED_IDENTIFIERS | BANNED_ORIGINAL_IDENTIFIERS) & identifiers):
        findings.append(f"{label} forbidden native/original identifier: {identifier}")
    lowered = code.lower()
    for token in sorted(BANNED_ORIGINAL_ADDRESS_TOKENS):
        if token in lowered:
            findings.append(f"{label} embeds forbidden original address: {token}")
    if re.search(r"\b(?:extern|volatile)\b|#\s*pragma", code):
        findings.append(f"{label} must not use extern, volatile, or pragmas")
    if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append(f"{label} must remain non-exported and test-only")


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code).replace("\\", "")
    _check_c_digest(
        text, code, EXPECTED_HEADER_BYTES, EXPECTED_HEADER_SHA256,
        EXPECTED_HEADER_TOKEN_SHA256, "header", findings,
    )
    _reject_unsafe_c(code, "header", findings)
    if text.count('#include "ported_100f1bb0_owned_utf16.h"') != 1:
        findings.append("header must inherit exactly the owned-UTF16 typed contract")
    macros = (
        ("#defineROME2_PORT_100F2750_FIRST_USE_DESTINATIONUINT32_C(0x119f3aa0)",
         "fixed persistent descriptor identity changed"),
        ("#defineROME2_PORT_100F2750_FIRST_USE_SENTINELUINT32_C(0x11af4090)",
         "exact empty-sentinel identity changed"),
        ("#defineROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_EMPTYUINT32_C(0)",
         "canonical lifecycle EMPTY value changed"),
        ("#defineROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINELUINT32_C(1)",
         "REGISTERED_SENTINEL lifecycle value changed"),
        ("#defineROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVEUINT32_C(2)",
         "REGISTERED_LIVE lifecycle value changed"),
        ("#defineROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMEDUINT32_C(3)",
         "CONSUMED lifecycle value changed"),
    )
    for fragment, message in macros:
        if fragment not in compact:
            findings.append(message)
    lifecycle = (
        "typedefstructrome2_100f2750_first_use_lifecycle{"
        "uint32_tphase;uint32_treserved;}"
        "rome2_100f2750_first_use_lifecycle;"
    )
    if lifecycle not in compact:
        findings.append("pointer-free phase/reserved lifecycle layout changed")
    if "_Static_assert(sizeof(rome2_100f2750_first_use_lifecycle)==8U," not in compact:
        findings.append("eight-byte lifecycle ABI assertion changed")

    signatures = (
        (
            "rome2_100f1bb0_owned_status" + REGISTER_FUNCTION + "("
            "constrome2_guest_write_view*persistent_descriptor_view,"
            "constrome2_100f1bb0_owned_owner*persistent_owner,"
            "rome2_100f2750_first_use_lifecycle*lifecycle_out);",
            "exact typed registration API changed",
        ),
        (
            "rome2_100f1bb0_owned_status" + BUILD_FUNCTION + "("
            "constrome2_guest_write_view*persistent_descriptor_view,"
            "constrome2_guest_write_view*temporary_descriptor_view,"
            "rome2_guest_addr32guest_temporary_descriptor,"
            "constrome2_guest_write_view*temporary_heap_view,"
            "constrome2_guest_write_view*persistent_heap_view,"
            "constrome2_100f1bb0_owned_effects*effects,"
            "constrome2_100f1bb0_owned_owner*temporary_owner,"
            "rome2_100f1bb0_owned_owner*persistent_owner_out,"
            "rome2_100f2750_first_use_lifecycle*lifecycle,"
            "rome2_guest_addr32*guest_return_out);",
            "exact sentinel-to-live API changed",
        ),
        (
            "rome2_100f1bb0_owned_status" + TEARDOWN_FUNCTION + "("
            "constrome2_guest_write_view*persistent_descriptor_view,"
            "constrome2_guest_write_view*persistent_heap_view,"
            "constrome2_100f1bb0_owned_effects*effects,"
            "rome2_100f1bb0_owned_owner*persistent_owner,"
            "rome2_100f2750_first_use_lifecycle*lifecycle);",
            "exact one-shot teardown API changed",
        ),
    )
    for fragment, message in signatures:
        if compact.count(fragment) != 1:
            findings.append(message)
    comment_tokens = (
        "canonical all-zero representation is unregistered",
        "without calling a native",
        "Success changes only lifecycle_out",
        "temporary\n * descriptor and its private LIVE owner remain borrowed and unchanged",
        "every control, backing, callback context, guest interval, and output is",
        "2*N+10 bytes in allocation class zero",
        "protocol error with no\n * release",
        "REGISTERED_SENTINEL lifecycle with canonical EMPTY owner",
        "advances the lifecycle to CONSUMED",
        "consumes the owner before release",
        "Guest bytes remain unchanged",
        "ALREADY_CONSUMED without another effect",
    )
    for token in comment_tokens:
        if token not in text:
            findings.append(f"header lifecycle contract changed: {token[:64]}")
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_PROVENANCE_BYTES, EXPECTED_PROVENANCE_SHA256,
        "sentinel-owned provenance", findings,
    )
    tokens = (
        "MAX_UNITS = 32_767",
        "MAX_ALLOCATION_BYTES = MAX_UNITS * 2 + 10",
        "DESTINATION_SENTINEL_DESCRIPTOR = (0, 0, EMPTY_SENTINEL)",
        '"REGISTER_TYPED_HOST_TEARDOWN"',
        '"PUBLISH_REGISTERED_SENTINEL"',
        '"ALLOCATE_DISTINCT_DESTINATION_GRANT"',
        '"COMMIT_DESTINATION_DESCRIPTOR"',
        '"COMMIT_DESTINATION_OWNER_LIVE"',
        '"COMMIT_DESTINATION_RETURN_LAST"',
        '"RETURN_EFFECT_PROTOCOL_INVALID_WITHOUT_RELEASE"',
        '"COMMIT_PERSISTENT_OWNER_CONSUMED"',
        '"RELEASE_EXACT_PERSISTENT_GRANT"',
        '"REGISTERED_SENTINEL_to_REGISTERED_LIVE_to_CONSUMED"',
        '"build_integration": "BUILD_TESTING_ONLY"',
        '"separate_source_and_persistent"',
        '"compensate_a_source_token_collision"',
        "self.assertEqual(mutant_count, 115)",
    )
    for token in tokens:
        if token not in text:
            findings.append(f"sentinel-owned provenance contract changed: {token}")
    if text.count('"compensate_a_source_token_collision"') != 2:
        findings.append(
            "sentinel-owned provenance must carry both collision exclusion witnesses"
        )
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC_BYTES, EXPECTED_DOC_SHA256, "doc", findings)
    tokens = (
        "No original address is executable",
        "`0x119f3aa0`",
        "`0x11af4090`",
        "`2*N+10`",
        "`(raw+8)&~3`",
        "`REGISTERED_SENTINEL -> REGISTERED_LIVE -> CONSUMED`",
        "## Separate source and destination ownership",
        "differ from the still-`LIVE` source token",
        "`EFFECT_PROTOCOL_INVALID` with no compensating release",
        "Every other malformed nonzero-token grant",
        "persistent descriptor, both owners, both allocations, and return slot remain",
        "persistent `LIVE`\nowner, then destination return",
        "commits\n`CONSUMED` before the exact injected release",
        "standalone `BUILD_TESTING` target",
        "no current input can reach that\nrollback",
        "Preallocated assignment and `LIVE -> LIVE` replacement",
        "bounded nonempty pre-loop composition of\n`0x100ed3c0`",
    )
    for token in tokens:
        if token not in text:
            findings.append(f"doc sentinel-owned contract changed: {token[:72]}")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_SOURCE_BYTES, EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_TOKEN_SHA256, "source", findings,
    )
    _reject_unsafe_c(code, "source", findings)

    includes = re.findall(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", text, re.M)
    if includes != [
        "ported_100f2750_first_use_owned.h", "limits.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include surface changed")
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    unexpected = sorted(calls - ALLOWED_SOURCE_CALLS)
    if unexpected:
        findings.append(f"source call surface changed: {', '.join(unexpected)}")
    if DELEGATE_BUILD in calls or DELEGATE_BUILD in code:
        findings.append("sentinel-owned build must not delegate to the scanning builder")
    if re.search(r"\b(?:scan|strlen|wcslen)\w*\b", code, re.I):
        findings.append("sentinel-owned build must not scan for a terminator")
    if re.search(
        r"\(\s*(?:void|char|wchar_t|uint8_t|uint16_t|uint32_t|uintptr_t)\s*\*\s*\)"
        r"\s*[^;\n]{0,180}\b(?:value|guest_start|guest_base)\b",
        code,
    ):
        findings.append("source converts a guest identity into a native pointer")
    if re.search(
        r"\(\s*(?:uintptr_t|intptr_t|size_t)\s*\)\s*[^;\n]{0,180}\.value\b",
        code,
    ):
        findings.append("source converts a guest identity into a host integer address")

    constants = (
        ("#defineROME2_100F2750_FIRST_USE_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)",
         "guest32 address-space bound changed"),
        ("#defineROME2_100F2750_FIRST_USE_DESCRIPTOR_BYTESUINT32_C(12)",
         "descriptor extent changed"),
        ("#defineROME2_100F2750_FIRST_USE_HEADER_BYTESUINT32_C(4)",
         "hidden-header extent changed"),
        ("#defineROME2_100F2750_FIRST_USE_UNIT_BYTESUINT32_C(2)",
         "UTF-16 unit extent changed"),
        ("#defineROME2_100F2750_FIRST_USE_ALLOCATION_OVERHEADUINT32_C(10)",
         "2*N+10 overhead changed"),
        ("#defineROME2_100F2750_FIRST_USE_PAYLOAD_BIASUINT32_C(8)",
         "payload alignment bias changed"),
        ("#defineROME2_100F2750_FIRST_USE_CONTROL_COUNT9U",
         "first-use control-slot count changed"),
        ("#defineROME2_100F2750_FIRST_USE_BACKING_COUNT4U",
         "first-use backing count changed"),
        ("#defineROME2_100F2750_FIRST_USE_PRIVATE_COUNT1U",
         "first-use private-span count changed"),
        ("#defineROME2_100F2750_FIRST_USE_REGISTER_CONTROL_COUNT3U",
         "registration control-slot count changed"),
        ("#defineROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT5U",
         "teardown control-slot count changed"),
        ("#defineROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT2U",
         "teardown backing count changed"),
    )
    for fragment, message in constants:
        if fragment not in compact:
            findings.append(message)

    private_tokens = (
        "rome2_100f1bb0_owned_ownertemporary_owner;",
        "rome2_100f1bb0_owned_ownerpersistent_owner_initial;",
        "rome2_100f2750_first_use_lifecyclelifecycle_initial;",
        "rome2_100f1bb0_owned_grantgrant;",
        "rome2_100f1bb0_owned_grant_resultgrant_result;",
        "rome2_100f1bb0_owned_ownerpersistent_owner_commit;",
        "rome2_100f2750_first_use_spanpersistent_allocation;",
        "rome2_100f2750_first_use_spantemporary_allocation;",
        "uint32_tcopy_index;",
    )
    for token in private_tokens:
        if token not in compact:
            findings.append(f"first-use private transaction state changed: {token}")
    for forbidden in (
        "rome2_100f2750_first_use_call_private", "wrapped_effects",
        "return_commit", "source_text_view", "allocate_bridge", "release_bridge",
    ):
        if forbidden in code:
            findings.append(f"obsolete delegated-build private surface remains: {forbidden}")

    owner_empty = _function_body(code, "rome2_100f2750_first_use_owner_is_empty")
    if owner_empty is None:
        findings.append("canonical EMPTY owner predicate is missing")
    else:
        expected = (
            "returnowner->token==UINT64_C(0)&&owner->raw_base.value==UINT32_C(0)&&"
            "owner->payload.value==UINT32_C(0)&&owner->allocation_bytes==UINT32_C(0)&&"
            "owner->length_units==UINT32_C(0)&&owner->phase==UINT32_C(0)&&"
            "owner->reserved==UINT32_C(0);"
        )
        if _compact(owner_empty) != expected:
            findings.append("canonical EMPTY owner predicate changed")
    lifecycle_empty = _function_body(
        code, "rome2_100f2750_first_use_lifecycle_is_empty"
    )
    if lifecycle_empty is None or _compact(lifecycle_empty) != (
        "returnlifecycle->phase=="
        "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_EMPTY&&"
        "lifecycle->reserved==UINT32_C(0);"
    ):
        findings.append("canonical EMPTY lifecycle predicate changed")
    grant_zero = _function_body(code, "rome2_100f2750_first_use_grant_is_zero")
    if grant_zero is None or _compact(grant_zero) != (
        "returngrant->token==UINT64_C(0)&&"
        "grant->raw_base.value==UINT32_C(0)&&grant->reserved==UINT32_C(0);"
    ):
        findings.append("canonical zero-grant predicate changed")

    compensate = _function_body(code, "rome2_100f2750_first_use_compensate_grant")
    if compensate is None:
        findings.append("exact malformed-grant compensation helper is missing")
    else:
        compensate_compact = _compact(compensate)
        required_compensation = (
            "if(state->grant.token!=UINT64_C(0)){state->effects.release("
            "state->effects.context,state->grant.token,state->grant.raw_base,"
            "state->allocation_bytes,ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);}" 
        )
        if compensate_compact != required_compensation:
            findings.append("compensation must release one exact nonzero-token tuple")
        if "release_hook(" in compensate_compact:
            findings.append("malformed-grant compensation must never invoke the hook")

    controls = _function_body(code, "rome2_100f2750_first_use_validate_controls")
    if controls is None:
        findings.append("first-use control/private alias validator is missing")
    else:
        controls_compact = _compact(controls)
        slots = (
            (0, "persistent_descriptor_view"), (1, "temporary_descriptor_view"),
            (2, "temporary_heap_view"), (3, "persistent_heap_view"),
            (4, "effects"), (5, "temporary_owner"),
            (6, "persistent_owner_out"), (7, "lifecycle"),
            (8, "guest_return_out"),
        )
        for index, name in slots:
            fragment = (
                f"state->controls[{index}].start=(uint64_t)(uintptr_t){name};"
                f"state->controls[{index}].byte_count=sizeof(*{name});"
            )
            if fragment not in controls_compact:
                findings.append(f"first-use protected control slot changed: {name}")
        for fragment, message in (
            ("state->private_spans[0].start=(uint64_t)(uintptr_t)state;"
             "state->private_spans[0].byte_count=sizeof(*state);",
             "first-use private state is not protected"),
            ("rome2_100f2750_first_use_host_spans_overlap(state->controls,"
             "ROME2_100F2750_FIRST_USE_CONTROL_COUNT)",
             "first-use controls are not pairwise disjoint"),
            ("rome2_100f2750_first_use_host_spans_overlap(state->private_spans,"
             "ROME2_100F2750_FIRST_USE_PRIVATE_COUNT)",
             "first-use private spans are not pairwise disjoint"),
            ("rome2_100f2750_first_use_span_sets_overlap(state->controls,"
             "ROME2_100F2750_FIRST_USE_CONTROL_COUNT,state->private_spans,"
             "ROME2_100F2750_FIRST_USE_PRIVATE_COUNT)",
             "first-use controls/private spans are not disjoint"),
        ):
            if fragment not in controls_compact:
                findings.append(message)

    backings = _function_body(code, "rome2_100f2750_first_use_validate_backings")
    if backings is None:
        findings.append("first-use backing/context alias validator is missing")
    else:
        backing_compact = _compact(backings)
        backing_names = (
            "persistent_descriptor_view", "temporary_descriptor_view",
            "temporary_heap_view", "persistent_heap_view",
        )
        for index, name in enumerate(backing_names):
            if (
                f"state->backings[{index}].start=(uint64_t)(uintptr_t)"
                f"state->{name}.host_base;state->backings[{index}].byte_count="
                f"state->{name}.byte_count;"
            ) not in backing_compact:
                findings.append(f"first-use complete backing slot changed: {name}")
        matrix = (
            ("state->backings,ROME2_100F2750_FIRST_USE_BACKING_COUNT)",
             "first-use backings are not pairwise disjoint"),
            ("state->backings,ROME2_100F2750_FIRST_USE_BACKING_COUNT,"
             "state->controls,ROME2_100F2750_FIRST_USE_CONTROL_COUNT)",
             "first-use backings/controls are not disjoint"),
            ("state->backings,ROME2_100F2750_FIRST_USE_BACKING_COUNT,"
             "&state->context,1U)",
             "first-use backings/context are not disjoint"),
            ("state->backings,ROME2_100F2750_FIRST_USE_BACKING_COUNT,"
             "state->private_spans,ROME2_100F2750_FIRST_USE_PRIVATE_COUNT)",
             "first-use backings/private state are not disjoint"),
            ("state->controls,ROME2_100F2750_FIRST_USE_CONTROL_COUNT,"
             "&state->context,1U)",
             "first-use controls/context are not disjoint"),
            ("&state->context,1U,state->private_spans,"
             "ROME2_100F2750_FIRST_USE_PRIVATE_COUNT)",
             "first-use context/private state are not disjoint"),
        )
        for fragment, message in matrix:
            if fragment not in backing_compact:
                findings.append(message)
        if backing_compact.count("rome2_100f2750_first_use_views_logically_overlap(") != 6:
            findings.append("four first-use guest views must be pairwise disjoint")

    authenticate = _function_body(
        code, "rome2_100f2750_first_use_authenticate_temporary"
    )
    if authenticate is None:
        findings.append("temporary LIVE-owner authenticator is missing")
    else:
        auth = _compact(authenticate)
        for fragment, message in (
            ("state->temporary_owner.phase!="
             "ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
             "temporary owner must be LIVE"),
            ("state->temporary_owner.length_units==UINT32_C(0)||"
             "state->temporary_owner.length_units>="
             "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
             "temporary owner N must be exactly 1..32767"),
            ("state->payload_bytes=state->temporary_owner.length_units*"
             "ROME2_100F2750_FIRST_USE_UNIT_BYTES;",
             "temporary exact 2*N payload formula changed"),
            ("state->allocation_bytes=state->payload_bytes+"
             "ROME2_100F2750_FIRST_USE_ALLOCATION_OVERHEAD;",
             "temporary exact 2*N+10 formula changed"),
            ("((uint64_t)state->temporary_owner.raw_base.value+"
             "ROME2_100F2750_FIRST_USE_PAYLOAD_BIAS)&~UINT64_C(3)",
             "temporary aligned payload formula changed"),
            ("rome2_100f2750_first_use_read_u32_le(descriptor_bytes)!=state->"
             "temporary_owner.length_units",
             "temporary descriptor count authentication changed"),
            ("rome2_100f2750_first_use_read_u32_le(descriptor_bytes+4U)!=state->"
             "temporary_owner.length_units",
             "temporary descriptor capacity authentication changed"),
            ("rome2_100f2750_first_use_read_u32_le(descriptor_bytes+8U)!=state->"
             "temporary_owner.payload.value",
             "temporary descriptor payload authentication changed"),
            ("(size_t)state->temporary_terminator.view_offset] !=UINT8_C(0)",
             "temporary low terminator byte authentication changed"),
            ("(size_t)state->temporary_terminator.view_offset+1U]!=UINT8_C(0)",
             "temporary high terminator byte authentication changed"),
        ):
            if fragment.replace(" ", "") not in auth:
                findings.append(message)
        if auth.count("rome2_100f2750_first_use_span_is_contained(") != 3:
            findings.append("temporary header/payload/terminator containment changed")

    register = _function_body(code, REGISTER_FUNCTION)
    if register is None:
        findings.append("typed registration implementation is missing")
    else:
        reg = _compact(register)
        for index, name in enumerate(
            ("persistent_descriptor_view", "persistent_owner", "lifecycle_out")
        ):
            fragment = (
                f"state.controls[{index}].start=(uint64_t)(uintptr_t){name};"
                f"state.controls[{index}].byte_count=sizeof(*{name});"
            )
            if fragment not in reg:
                findings.append(f"registration protected control slot changed: {name}")
        reg_order = (
            "rome2_100f2750_first_use_validate_object(persistent_descriptor_view,",
            "rome2_100f2750_first_use_validate_object(persistent_owner,",
            "rome2_100f2750_first_use_validate_object(lifecycle_out,",
            "rome2_100f2750_first_use_host_spans_overlap(state.controls,",
            "state.descriptor_view=*persistent_descriptor_view;",
            "state.owner=*persistent_owner;",
            "state.lifecycle=*lifecycle_out;",
            "rome2_100f2750_first_use_validate_view(",
            "rome2_100f2750_first_use_span_sets_overlap(&state.backing,",
            "!rome2_100f2750_first_use_owner_is_empty(&state.owner)",
            "||!rome2_100f2750_first_use_lifecycle_is_empty(&state.lifecycle)",
            "rome2_100f2750_first_use_resolve_span(",
            "rome2_100f2750_first_use_read_u32_le(descriptor_bytes)",
            "lifecycle_out->phase="
            "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL;",
            "returnROME2_100F1BB0_OWNED_OK;",
        )
        _require_in_order(reg, reg_order, findings, "registration validation/commit order changed")
        if reg.count("lifecycle_out->phase=") != 1:
            findings.append("registration must publish REGISTERED_SENTINEL exactly once")
        if any(token in reg for token in (".allocate(", ".release(", DELEGATE_CLEANUP)):
            findings.append("typed registration must be allocation/release/cleanup free")

    build = _function_body(code, BUILD_FUNCTION)
    if build is None:
        findings.append("sentinel-to-live implementation is missing")
    else:
        build_compact = _compact(build)
        if build_compact.count("state.effects.allocate(") != 1:
            findings.append("sentinel-to-live must make exactly one injected allocation")
        first_effect = build_compact.find("state.effects.allocate(")
        required_preflight = (
            "rome2_100f2750_first_use_validate_controls(",
            "state.persistent_descriptor_view=*persistent_descriptor_view;",
            "state.lifecycle_initial=*lifecycle;",
            "rome2_100f2750_first_use_validate_backings(&state)",
            "rome2_100f2750_first_use_owner_is_empty(&state.persistent_owner_initial)",
            "state.lifecycle_initial.phase!="
            "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL",
            "ROME2_PORT_100F2750_FIRST_USE_SENTINEL",
            "rome2_100f2750_first_use_authenticate_temporary(",
            "state.persistent_available_bytes<",
        )
        for fragment in required_preflight:
            position = build_compact.find(fragment)
            if position < 0 or (first_effect >= 0 and position >= first_effect):
                findings.append(f"pre-allocation validation changed: {fragment[:64]}")
        capacity_check = (
            "state.persistent_available_bytes="
            "state.persistent_heap_view.byte_count;"
            "if(state.persistent_heap_view.guest_base==UINT32_C(0)){"
            "if(state.persistent_available_bytes==UINT64_C(0)){return"
            "ROME2_100F1BB0_OWNED_OUT_OF_RANGE;}"
            "--state.persistent_available_bytes;}"
            "if(state.persistent_available_bytes<(uint64_t)"
            "state.allocation_bytes){return"
            "ROME2_100F1BB0_OWNED_OUT_OF_RANGE;}"
        )
        if capacity_check not in build_compact:
            findings.append("pre-allocation persistent-heap feasibility changed")
        if first_effect < 0:
            first_effect = len(build_compact)

        collision = (
            "if(state.grant.token==state.temporary_owner.token){return"
            "ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;}"
        )
        collision_pos = build_compact.find(collision)
        denial_pos = build_compact.find(
            "if(state.grant_result==ROME2_100F1BB0_OWNED_GRANT_DENIED)"
        )
        if collision_pos < first_effect or denial_pos < collision_pos:
            findings.append("source-token collision must fail immediately without compensation")
        if collision_pos >= 0:
            collision_body = collision[collision.find("{") + 1:collision.rfind("}")]
            if "compensate" in collision_body or "release" in collision_body:
                findings.append("source-token collision must not acquire release authority")

        if build_compact.count("rome2_100f2750_first_use_compensate_grant(&state);") != 7:
            findings.append("every other malformed nonzero grant needs exact compensation")
        grant_order = (
            "state.grant_result=state.effects.allocate(",
            collision,
            "if(state.grant_result==ROME2_100F1BB0_OWNED_GRANT_DENIED)",
            "if(state.grant_result!=ROME2_100F1BB0_OWNED_GRANT_GRANTED||",
            "if(state.grant.raw_base.value==UINT32_C(0))",
            "rome2_100f2750_first_use_resolve_span(",
            "state.persistent_payload_value=",
            "state.persistent_terminator_value=",
        )
        _require_in_order(
            build_compact, grant_order, findings,
            "allocation/grant/collision/validation order changed",
        )
        if build_compact.count("rome2_100f2750_first_use_span_is_contained(") < 3:
            findings.append("destination header/payload/terminator containment changed")
        for fragment, message in (
            ("rome2_100f2750_first_use_ranges_overlap("
             "state.persistent_allocation.guest_start,"
             "state.persistent_allocation.byte_count,"
             "state.temporary_allocation.guest_start,"
             "state.temporary_allocation.byte_count)",
             "source/destination guest allocations must be disjoint"),
            ("rome2_100f2750_first_use_ranges_overlap("
             "state.persistent_allocation.host_start,"
             "state.persistent_allocation.byte_count,"
             "state.temporary_allocation.host_start,"
             "state.temporary_allocation.byte_count)",
             "source/destination host allocations must be disjoint"),
        ):
            if fragment not in build_compact:
                findings.append(message)

        exact_copy = (
            "for(state.copy_index=UINT32_C(0);"
            "state.copy_index<state.payload_bytes;++state.copy_index){"
            "state.persistent_heap_view.host_base[(size_t)"
            "state.persistent_payload.view_offset+state.copy_index]="
            "state.temporary_heap_view.host_base[(size_t)"
            "state.temporary_payload.view_offset+state.copy_index];}"
        )
        if exact_copy not in build_compact:
            findings.append("direct copy must preserve exactly opaque 2*N source bytes")
        write_order = (
            "rome2_100f2750_first_use_write_u32_le("
            "state.persistent_heap_view.host_base+"
            "(size_t)state.persistent_header.view_offset,state.grant.raw_base.value);",
            exact_copy,
            "state.persistent_heap_view.host_base["
            "(size_t)state.persistent_terminator.view_offset]=UINT8_C(0);",
            "state.persistent_heap_view.host_base["
            "(size_t)state.persistent_terminator.view_offset+1U]=UINT8_C(0);",
            "rome2_100f2750_first_use_write_u32_le("
            "state.persistent_descriptor_view.host_base+"
            "(size_t)state.persistent_descriptor.view_offset,"
            "state.temporary_owner.length_units);",
            "rome2_100f2750_first_use_write_u32_le("
            "state.persistent_descriptor_view.host_base+"
            "(size_t)state.persistent_descriptor.view_offset+4U,"
            "state.temporary_owner.length_units);",
            "rome2_100f2750_first_use_write_u32_le("
            "state.persistent_descriptor_view.host_base+"
            "(size_t)state.persistent_descriptor.view_offset+8U,"
            "state.persistent_payload_identity.value);",
            "*persistent_owner_out=state.persistent_owner_commit;",
            "lifecycle->phase="
            "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;",
            "*guest_return_out=persistent_descriptor_identity;",
            "returnROME2_100F1BB0_OWNED_OK;",
        )
        _require_in_order(
            build_compact, write_order, findings,
            "header/copy/zero/descriptor/owner/lifecycle/return commit order changed",
        )
        first_write = build_compact.find(write_order[0])
        if first_write >= 0:
            commit_tail = build_compact[first_write:]
            if "if(" in commit_tail or commit_tail.count("returnROME2_") != 1:
                findings.append("no fallible operation may follow the first guest write")
        owner_fields = (
            "token=state.grant.token", "raw_base=state.grant.raw_base",
            "payload=state.persistent_payload_identity",
            "allocation_bytes=state.allocation_bytes",
            "length_units=state.temporary_owner.length_units",
            "phase=ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
            "reserved=UINT32_C(0)",
        )
        for field in owner_fields:
            if f"state.persistent_owner_commit.{field};" not in build_compact:
                findings.append(f"persistent LIVE owner commit changed: {field}")
        if "temporary_owner->" in build_compact or DELEGATE_CLEANUP in build_compact:
            findings.append("first-use replacement must not mutate or consume source ownership")

    teardown = _function_body(code, TEARDOWN_FUNCTION)
    if teardown is None:
        findings.append("registered one-shot teardown implementation is missing")
    else:
        td = _compact(teardown)
        for index, name in enumerate((
            "persistent_descriptor_view", "persistent_heap_view", "effects",
            "persistent_owner", "lifecycle",
        )):
            fragment = (
                f"state.controls[{index}].start=(uint64_t)(uintptr_t){name};"
                f"state.controls[{index}].byte_count=sizeof(*{name});"
            )
            if fragment not in td:
                findings.append(f"teardown protected control slot changed: {name}")
        for fragment, message in (
            ("state.backings[0].start=(uint64_t)(uintptr_t)"
             "state.descriptor_view.host_base;state.backings[0].byte_count="
             "state.descriptor_view.byte_count;",
             "teardown descriptor backing is not protected"),
            ("state.backings[1].start=(uint64_t)(uintptr_t)"
             "state.heap_view.host_base;state.backings[1].byte_count="
             "state.heap_view.byte_count;",
             "teardown heap backing is not protected"),
            ("state.lifecycle.phase=="
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED){return"
             "ROME2_100F1BB0_OWNED_ALREADY_CONSUMED;}",
             "repeated teardown must be effect-free ALREADY_CONSUMED"),
        ):
            if fragment not in td:
                findings.append(message)
        sentinel_branch = (
            "if(state.lifecycle.phase=="
            "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL){"
        )
        sentinel_pos = td.find(sentinel_branch)
        live_pos = td.find(
            "if(state.lifecycle.phase!="
            "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE||"
        )
        if sentinel_pos < 0 or live_pos <= sentinel_pos:
            findings.append("teardown must distinguish registered sentinel before live")
        if sentinel_pos >= 0 and live_pos > sentinel_pos:
            sentinel = td[sentinel_pos:live_pos]
            for fragment in (
                "!rome2_100f2750_first_use_owner_is_empty(&state.owner)",
                "ROME2_PORT_100F2750_FIRST_USE_SENTINEL",
                "lifecycle->phase="
                "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;",
                "returnROME2_100F1BB0_OWNED_OK;",
            ):
                if fragment not in sentinel:
                    findings.append("registered-sentinel no-effect teardown changed")
            if any(token in sentinel for token in (".release(", DELEGATE_CLEANUP)):
                findings.append("registered-sentinel teardown must emit no effect")
        if "persistent_payload" in td:
            findings.append("teardown must not revalidate unretained payload bytes")
        for fragment, message in (
            ("state.owner.length_units==UINT32_C(0)||state.owner.length_units>="
             "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
             "teardown owner length domain changed"),
            ("state.expected_payload_bytes=state.owner.length_units*"
             "ROME2_100F2750_FIRST_USE_UNIT_BYTES;",
             "teardown exact 2*N formula changed"),
            ("state.expected_allocation_bytes=state.expected_payload_bytes+"
             "ROME2_100F2750_FIRST_USE_ALLOCATION_OVERHEAD;",
             "teardown exact 2*N+10 formula changed"),
            ("lifecycle->phase="
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;"
             "state.status=" + DELEGATE_CLEANUP + "(",
             "lifecycle must become CONSUMED before exact owned cleanup"),
            ("&state.descriptor_view,persistent_descriptor_identity,"
             "&state.heap_view,&state.effects,persistent_owner);",
             "teardown owned-cleanup argument tuple changed"),
            ("if(state.status!=ROME2_100F1BB0_OWNED_OK){lifecycle->phase="
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;}"
             "returnstate.status;",
             "teardown failure rollback/result changed"),
        ):
            if fragment not in td:
                findings.append(message)
        if td.count(DELEGATE_CLEANUP + "(") != 1:
            findings.append("teardown must delegate exactly once to owned cleanup")
        if ".allocate(" in td or ".release(" in td or "release_hook(" in td:
            findings.append("teardown effects must occur only through owned cleanup")

    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    _check_c_digest(
        text, code, EXPECTED_TEST_BYTES, EXPECTED_TEST_SHA256,
        EXPECTED_TEST_TOKEN_SHA256, "runtime oracle", findings,
    )
    includes = re.findall(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", text, re.M)
    if includes != [
        "ported_100f2750_first_use_owned.h", "stddef.h", "stdint.h",
        "stdio.h", "string.h",
    ]:
        findings.append("runtime include surface changed")
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for identifier in sorted(BANNED_ORIGINAL_IDENTIFIERS & identifiers):
        findings.append(f"runtime invokes or names original code: {identifier}")
    for token in sorted(
        BANNED_ORIGINAL_ADDRESS_TOKENS - {"0x100f2750"}
    ):
        if token in code.lower():
            findings.append(f"runtime embeds forbidden original address: {token}")

    assertions = (
        ("ROME2_PORT_100F2750_FIRST_USE_DESTINATION==UINT32_C(0x119f3aa0)",
         "runtime fixed destination assertion changed"),
        ("ROME2_PORT_100F2750_FIRST_USE_SENTINEL==UINT32_C(0x11af4090)",
         "runtime sentinel assertion changed"),
        ("ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL=="
         "UINT32_C(1)", "runtime REGISTERED_SENTINEL assertion changed"),
        ("ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE=="
         "UINT32_C(2)", "runtime REGISTERED_LIVE assertion changed"),
        ("ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED==UINT32_C(3)",
         "runtime CONSUMED assertion changed"),
        ("sizeof(rome2_100f2750_first_use_lifecycle)==8U",
         "runtime lifecycle ABI assertion changed"),
        ("sizeof(rome2_100f1bb0_owned_owner)==32U",
         "runtime owner ABI assertion changed"),
    )
    for fragment, message in assertions:
        if fragment not in compact:
            findings.append(message)

    control_observer = _function_body(code, "test_controls_match_before")
    if control_observer is None:
        findings.append("runtime validation-before-effects observer is missing")
    else:
        observer = _compact(control_observer)
        for field in (
            "observed_persistent_descriptor", "observed_temporary_descriptor",
            "observed_temporary_owner", "observed_persistent_owner",
            "observed_lifecycle", "observed_return",
        ):
            if field not in observer:
                findings.append(f"runtime pre-effect observer omits {field}")
        observer_comparisons = (
            "memcmp(context->observed_persistent_descriptor,"
            "context->persistent_descriptor_before,"
            "sizeof(context->persistent_descriptor_before))==0",
            "memcmp(context->observed_temporary_descriptor,"
            "context->temporary_descriptor_before,"
            "sizeof(context->temporary_descriptor_before))==0",
            "memcmp(context->observed_temporary_owner,"
            "&context->temporary_owner_before,"
            "sizeof(context->temporary_owner_before))==0",
            "memcmp(context->observed_persistent_owner,"
            "&context->persistent_owner_before,"
            "sizeof(context->persistent_owner_before))==0",
            "memcmp(context->observed_lifecycle,&context->lifecycle_before,"
            "sizeof(context->lifecycle_before))==0",
        )
        if (
            observer.count("memcmp(") != 5
            or any(fragment not in observer for fragment in observer_comparisons)
            or "context->observed_return->value==context->return_before.value"
            not in observer
        ):
            findings.append("runtime must observe descriptors/owners/lifecycle/return unchanged")

    allocate = _function_body(code, "test_allocate")
    if allocate is None:
        findings.append("runtime injected allocator observer is missing")
    else:
        allocator = _compact(allocate)
        for fragment, message in (
            ("context->event_count!=UINT32_C(1)",
             "runtime allocation must be the first observer event"),
            ("context->release_calls!=UINT32_C(0)",
             "runtime allocation must precede release"),
            ("context->hook_calls!=UINT32_C(0)",
             "runtime allocation must precede hook"),
            ("grant_out->token!=UINT64_C(0)",
             "runtime allocator must receive a zeroed grant"),
            ("byte_count!=context->expected_bytes",
             "runtime exact allocation-size observation changed"),
            ("allocation_class!="
             "ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS",
             "runtime class-zero observation changed"),
            ("!test_controls_match_before(context)",
             "runtime allocation must observe validation-before-effects"),
        ):
            if fragment not in allocator:
                findings.append(message)

    release = _function_body(code, "test_release")
    hook = _function_body(code, "test_release_hook")
    if release is None or hook is None:
        findings.append("runtime release/hook order observers are missing")
    else:
        released = _compact(release)
        hooked = _compact(hook)
        for fragment, message in (
            ("context->expected_release_mode==TEST_RELEASE_COMPENSATE",
             "runtime compensation observer is missing"),
            ("context->events[0]!=TEST_EVENT_ALLOCATE||"
             "context->events[1]!=TEST_EVENT_RELEASE",
             "runtime compensation allocate-before-release order changed"),
            ("!test_controls_match_before(context)",
             "runtime compensation must observe no guest/output mutation"),
            ("context->expected_release_mode==TEST_RELEASE_TEARDOWN",
             "runtime teardown release observer is missing"),
            ("context->observed_persistent_owner->phase!="
             "ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED",
             "runtime teardown must observe owner CONSUMED before release"),
            ("context->observed_lifecycle->phase!="
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED",
             "runtime teardown must observe lifecycle CONSUMED before release"),
        ):
            if fragment not in released:
                findings.append(message)
        for fragment, message in (
            ("context->events[0]!=TEST_EVENT_RELEASE||"
             "context->events[1]!=TEST_EVENT_HOOK",
             "runtime release-before-hook order changed"),
            ("zero_argument!=UINT32_C(0)",
             "runtime teardown hook raw-zero tuple changed"),
            ("context->observed_persistent_owner->phase!="
             "ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED",
             "runtime hook must observe owner CONSUMED"),
            ("context->observed_lifecycle->phase!="
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED",
             "runtime hook must observe lifecycle CONSUMED"),
        ):
            if fragment not in hooked:
                findings.append(message)

    prepare = _function_body(code, "test_prepare_ready")
    if prepare is None:
        findings.append("runtime source-owner/registration preparation is missing")
    else:
        prepared = _compact(prepare)
        _require_in_order(
            prepared,
            (
                "rome2_port_100f1bb0_build_owned_utf16(",
                "rome2_port_100f2750_register_first_use_owned(",
                "fixture->lifecycle.phase!="
                "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL",
                "fixture->context.grant.token=TEST_DESTINATION_TOKEN;",
                "test_set_observer(fixture,TEST_OBSERVE_BUILD);",
            ),
            findings,
            "runtime must register the sentinel before destination allocation setup",
        )

    success = _function_body(code, "test_verify_first_use_success")
    if success is None:
        findings.append("runtime exact success oracle is missing")
    else:
        successful = _compact(success)
        for fragment, message in (
            ("fixture->context.observed_allocate_bytes=="
             "fixture->length_units*UINT32_C(2)+UINT32_C(10)",
             "runtime exact 2*N+10 request oracle changed"),
            ("index<fixture->length_units;++index",
             "runtime exact N-unit copy oracle changed"),
            ("fixture->length_units*UINT32_C(2))==UINT16_C(0)",
             "runtime literal zero terminator oracle changed"),
            ("memcmp(&fixture->temporary_descriptor,",
             "runtime temporary descriptor preservation oracle changed"),
            ("memcmp(&fixture->temporary_heap,",
             "runtime temporary allocation preservation oracle changed"),
            ("memcmp(&fixture->temporary_owner,",
             "runtime temporary owner preservation oracle changed"),
            ("fixture->persistent_owner.phase=="
             "ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
             "runtime persistent LIVE-owner oracle changed"),
            ("fixture->lifecycle.phase=="
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE",
             "runtime REGISTERED_LIVE oracle changed"),
            ("fixture->guest_return.value=="
             "ROME2_PORT_100F2750_FIRST_USE_DESTINATION",
             "runtime fixed return oracle changed"),
        ):
            if fragment not in successful:
                findings.append(message)

    preservation = _function_body(code, "test_expect_preserved")
    if preservation is None:
        findings.append("runtime failure-preservation oracle is missing")
    else:
        preserved = _compact(preservation)
        for token in (
            "persistent_descriptor", "temporary_descriptor", "text",
            "temporary_heap", "persistent_heap", "temporary_owner",
            "persistent_owner", "lifecycle", "guest_return",
            "expect_context_unchanged",
        ):
            if token not in preserved:
                findings.append(f"runtime failure preservation omits {token}")
        preserved_bytes = (
            "memcmp(&fixture->persistent_descriptor,"
            "&before->persistent_descriptor,sizeof(fixture->persistent_descriptor))==0",
            "memcmp(&fixture->temporary_descriptor,"
            "&before->temporary_descriptor,sizeof(fixture->temporary_descriptor))==0",
            "memcmp(&fixture->text,&before->text,sizeof(fixture->text))==0",
            "memcmp(&fixture->temporary_heap,&before->temporary_heap,"
            "sizeof(fixture->temporary_heap))==0",
            "memcmp(&fixture->persistent_heap,&before->persistent_heap,"
            "sizeof(fixture->persistent_heap))==0",
            "memcmp(&fixture->temporary_owner,&before->temporary_owner,"
            "sizeof(fixture->temporary_owner))==0",
            "memcmp(&fixture->persistent_owner,&before->persistent_owner,"
            "sizeof(fixture->persistent_owner))==0",
            "memcmp(&fixture->lifecycle,&before->lifecycle,"
            "sizeof(fixture->lifecycle))==0",
            "fixture->guest_return.value==before->guest_return.value",
            "memcmp(&fixture->context,&before->context,"
            "sizeof(fixture->context))==0",
        )
        if any(fragment not in preserved for fragment in preserved_bytes):
            findings.append("runtime exact failure-preservation matrix changed")

    case_tokens = (
        '"valid registration"', '"repeat registration"',
        '"source raw residue %u / destination raw residue %u"',
        '"minimum finite owned payload"',
        '"maximum finite owned payload"',
        '"opaque source units include an interior zero"',
        '"canonical destination allocation denial"',
        '"denial with destination authority"',
        '"invalid destination result with authority"',
        '"granted destination without authority"',
        '"dirty granted destination"', '"null destination raw identity"',
        '"destination guest endpoint overflow"',
        '"live source token collision"',
        '"denied destination with live source token collision"',
        '"temporary owner is not LIVE"',
        '"zero-length temporary owner"',
        '"out-of-domain temporary owner length"',
        '"temporary descriptor length mismatch"',
        '"temporary hidden header mismatch"',
        '"temporary terminator mismatch"',
        '"missing registration"', '"bad registered sentinel state"',
        '"persistent heap cannot satisfy exact request"',
        '"temporary descriptor guest range overflow"',
        '"persistent heap guest range overflow"',
        '"zero-based persistent heap lacks a usable first byte"',
        '"physical backing alias"', '"logical guest-view alias"',
        '"backing overlaps lifecycle control"',
        '"callback context overlaps backing"',
        '"owner controls alias"', '"null lifecycle control"',
        '"registered LIVE teardown"', '"repeat registered teardown"',
        '"registered sentinel teardown"',
        '"teardown descriptor mismatch"',
        '"teardown hidden header mismatch"',
        '"teardown lifecycle mismatch"',
        '"teardown callback context overlaps control"',
        '"teardown null callback context"',
        '"teardown empty callback context"',
        '"teardown null release effect"',
        '"teardown controls alias"',
        '"null teardown descriptor view"', '"null teardown heap view"',
        '"null teardown effects"', '"null teardown owner"',
    )
    for token in case_tokens:
        if token not in text:
            findings.append(f"runtime reciprocal case is missing: {token}")

    main = _function_body(code, "main")
    if main is None:
        findings.append("runtime main is missing")
    else:
        main_compact = _compact(main)
        expected_calls = tuple(f"failed|={group}();" for group in RUNTIME_GROUPS)
        _require_in_order(
            main_compact, expected_calls, findings,
            "runtime seven-group registry order changed",
        )
        for group in RUNTIME_GROUPS:
            if main_compact.count(f"{group}();") != 1:
                findings.append(f"runtime must call each group exactly once: {group}")
            if len(re.findall(rf"\bstatic\s+int\s+{re.escape(group)}\s*\(", code)) != 1:
                findings.append(f"runtime group definition changed: {group}")
        if (
            '"100f2750 first-use owned runtime checks passed (%u cases)\\n"'
            not in text
            or "printf(,(unsignedint)test_case_count)" not in main_compact
        ):
            findings.append("runtime completion/cardinality report changed")
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
    _check_exact(
        text, EXPECTED_CMAKE_BYTES, EXPECTED_CMAKE_SHA256, "CMake", findings
    )
    count = len(re.findall(r"^\s*add_test\s*\(", text, flags=re.I | re.M))
    if count != EXPECTED_CTEST_COUNT:
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
            findings.append(f"CMake sentinel-owned token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(
                f"CMake sentinel-owned token escapes BUILD_TESTING: {token}"
            )

    scoped = _compact("\n".join(lines[start + 1:end]))
    required = (
        (
            f"add_library({LIBRARY}STATIC"
            '"${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_first_use_owned.h"'
            '"${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_first_use_owned.c")',
            "CMake sentinel-owned library must be exact static and test-only",
        ),
        (
            f"target_compile_features({LIBRARY}PUBLICc_std_17)",
            "CMake sentinel-owned C17 requirement changed",
        ),
        (
            f"target_compile_options({LIBRARY}PRIVATE"
            "${ROME2_HARDENED_COMPILE_OPTIONS})",
            "CMake sentinel-owned hardened compile options changed",
        ),
        (
            f"target_include_directories({LIBRARY}PUBLIC"
            '"${ROME2_GUEST32_RUNTIME_DIR}"'
            '"${ROME2_GUEST32_PORTED_DIR}")',
            "CMake sentinel-owned include surface changed",
        ),
        (
            f"add_executable({TEST_TARGET}"
            '"${ROME2_GUEST32_RUNTIME_DIR}/'
            'test_startup_100f2750_sentinel_owned.c")',
            "CMake sentinel-owned runtime executable changed",
        ),
        (
            f"rome2_configure_x64_target({TEST_TARGET})",
            "CMake sentinel-owned runtime x64 configuration changed",
        ),
        (
            f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
            "CMake sentinel-owned runtime link changed",
        ),
    )
    for fragment, message in required:
        if scoped.count(fragment) != 1:
            findings.append(message)

    commands = _link_commands(text)
    dependency = "rome2_startup_100f1bb0_owned_utf16_runtime"
    own = [words for words in commands if words and words[0] == LIBRARY]
    if own != [[LIBRARY, "PUBLIC", dependency]]:
        findings.append(
            "CMake sentinel-owned dependency must be exactly owned-UTF16/public"
        )
    consumers = [
        words[0]
        for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if consumers != [TEST_TARGET, PARENT_LIBRARY]:
        findings.append(
            "CMake sentinel-owned consumers must be its test and nonempty parent"
        )

    for name in CMAKE_TESTS:
        if scoped.count(f"add_test(NAME{name}COMMAND") != 1:
            findings.append(
                f"CMake sentinel-owned CTest registration changed: {name}"
            )

    gate_start = scoped.find(
        "add_test(NAMEstartup_100f2750_sentinel_owned_static_gateCOMMAND"
    )
    gate_end = scoped.find("add_test(", gate_start + 1)
    gate_scope = scoped[gate_start:gate_end] if gate_start >= 0 else ""
    gate_args = (
        '--header"${ROME2_GUEST32_PORTED_DIR}/'
        'ported_100f2750_first_use_owned.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/'
        'ported_100f2750_first_use_owned.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/'
        'test_startup_100f2750_sentinel_owned.c"',
        '--sentinel-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100f2750_sentinel_owned_provenance.py"',
        '--doc"${CMAKE_CURRENT_SOURCE_DIR}/docs/'
        'x64_startup_100f2750_sentinel_owned.md"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
    )
    for argument in gate_args:
        if gate_scope.count(argument) != 1:
            findings.append(
                f"CMake sentinel-owned static-gate argument changed: {argument[:76]}"
            )

    fixtures = (
        (
            "startup_100f2750_sentinel_owned_provenancePROPERTIES"
            "FIXTURES_SETUPstartup_100f2750_sentinel_owned_provenance_verified",
            "CMake sentinel-owned provenance fixture changed",
        ),
        (
            "startup_100f2750_sentinel_owned_static_gate_unitPROPERTIES"
            "FIXTURES_SETUPstartup_100f2750_sentinel_owned_static_tool_verified",
            "CMake sentinel-owned reciprocal-tool fixture changed",
        ),
        (
            "startup_100f2750_sentinel_owned_static_gatePROPERTIES"
            "FIXTURES_REQUIREDstartup_100f2750_sentinel_owned_static_tool_verified"
            "FIXTURES_SETUPstartup_100f2750_sentinel_owned_static_verified",
            "CMake sentinel-owned live-static fixture changed",
        ),
        (
            "startup_100f2750_sentinel_owned_runtimePROPERTIES"
            "FIXTURES_REQUIRED\"" + PREDECESSOR_FIXTURE + ";"
            "startup_100f2750_sentinel_owned_provenance_verified;"
            "startup_100f2750_sentinel_owned_static_verified\""
            "FIXTURES_SETUPstartup_100f2750_sentinel_owned_runtime_verified"
            "TIMEOUT90",
            "CMake sentinel-owned runtime fixture chain changed",
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
    parser.add_argument(
        "--sentinel-provenance", type=pathlib.Path, required=True
    )
    parser.add_argument("--doc", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "runtime": (args.test, inspect_test_text),
        "provenance": (
            args.sentinel_provenance, inspect_provenance_text,
        ),
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
