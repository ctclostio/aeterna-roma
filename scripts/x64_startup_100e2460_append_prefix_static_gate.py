#!/usr/bin/env python3
"""Fail-closed source/link gate for the 0x100e2460 append prefix."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e2460_append_preallocated_prefix"
LIBRARY = "rome2_startup_100e2460_append_prefix_runtime"
TEST_TARGET = "rome2_startup_100e2460_append_prefix_tests"
HEADLESS = "rome2_headless64"

ROUTER_FUNCTION = "rome2_port_100e2460_run_router"
HANDLER_8D00_FUNCTION = "rome2_port_100e8d00_run_handler_transcript"
HANDLER_85D0_FUNCTION = "rome2_port_100e85d0_normal_adapter"
HANDLER_8580_FUNCTION = "rome2_port_100e8580_run_handler_transcript"
OUTER_FUNCTION = "rome2_port_100ea4d0_run_injected"
HANDLER_9340_FUNCTION = "rome2_port_100e9340_run_handler_transcript"
HANDLER_92C0_FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
HANDLER_87A0_FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PLATFORM_PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PLATFORM_PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"
MIDDLE_FUNCTION = "rome2_port_100df270_project_headless_empty_state"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"

EXPECTED_CTEST_COUNT = 192
EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_SIZE = 182959
EXPECTED_CMAKE_SHA256 = (
    "3e7dda18a4e170f7d68a73f121ff5f4a40e58c854047e730a9608984b9589674"
)

FINAL_HEADLESS_LIBRARIES = (
    "rome2_startup_100e8d00_handler_transcript_runtime",
    "rome2_startup_100e85d0_normal_adapter_runtime",
    "rome2_startup_100e8580_handler_transcript_runtime",
    "rome2_startup_100ea4d0_injected_runtime",
    "rome2_startup_100e9340_handler_transcript_runtime",
    "rome2_startup_100e92c0_handler_transcript_runtime",
    "rome2_startup_100e87a0_handler_transcript_runtime",
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

EXPECTED_HEADER_TOKEN_SHA256 = "e9d57e8c0f4147c8bb291a2001eeb9b8ae0228af596964b80808d9afa3d0141c"
EXPECTED_SOURCE_TOKEN_SHA256 = "bf13e42c2cb23ba4729cd65726690cf7c749d1573a40a36bbfdd28a6e6a025f7"
EXPECTED_TEST_TOKEN_SHA256 = "661d574231973a28a5010a334e280792a85b97ab40f94fd188c09358fbf5313c"
EXPECTED_HEADLESS_TOKEN_SHA256 = "07aa2c02db60b37064c0ad420d391ebefc19454f7608956dd0916aecbce43ed9"

BANNED_IDENTIFIERS = {
    "CreateProcessA",
    "CreateProcessW",
    "DispatchMessageA",
    "DispatchMessageW",
    "ExitProcess",
    "GetMessageA",
    "GetMessageW",
    "PeekMessageA",
    "PeekMessageW",
    "PostMessageA",
    "PostMessageW",
    "SendMessageA",
    "SendMessageW",
    "TranslateMessage",
    "VirtualAlloc",
    "VirtualFree",
    "abort",
    "calloc",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "realloc",
}

BANNED_ADDRESS_TOKENS = {
    "100d12b0",
    "100e8240",
    "100ea060",
    "100ea4d0",
    "100fcc50",
    "100fcc80",
    "1172f670",
    "1173f20c",
}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT32_C",
    "UINT64_C",
    "if",
    "return",
    "sizeof",
    FUNCTION,
    "rome2_100e2460_read_u32_le",
    "rome2_100e2460_spans_overlap",
    "rome2_100e2460_write_u32_le",
}

TEST_CASE_LABELS = (
    "ordinary preallocated append",
    "append fills final capacity slot",
    "zero-count append stores null element bits",
    "append slot immediately precedes vector",
    "append slot immediately follows vector",
    "slot ends exactly at view end",
    "slot ends at guest address-space end",
    "maximum capacity remains unchanged",
    "count equals capacity rejects growth route",
    "count above capacity rejects malformed growth route",
    "zero capacity rejects allocator route",
    "branch rejection precedes null backing",
    "null vector",
    "vector header guest overflow",
    "truncated vector header",
    "null backing",
    "scaled index guest overflow",
    "backing plus scaled index guest overflow",
    "truncated append slot",
    "append slot aliases vector self cell",
    "append slot aliases capacity cell",
    "append slot aliases count cell",
    "append slot aliases backing cell",
    "unaligned append slot overlaps vector",
    "guest view end overflow",
    "view descriptor aliases guest bytes",
    "host numeric range overflow",
    "null view",
    "null host base",
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
    if includes != ["ported_100f1c10_triplet.h"]:
        findings.append("header must reuse only the admitted guest write-view contract")
    declaration = (
        "rome2_guest_status"
        "rome2_port_100e2460_append_preallocated_prefix("
        "constrome2_guest_write_view*view,"
        "rome2_guest_addr32guest_vector,"
        "rome2_guest_addr32guest_element);"
    )
    if compact.count(declaration) != 1:
        findings.append("exact append-prefix declaration is missing or duplicated")
    for constant in (
        "#defineROME2_PORT_100E2460_VECTOR_BYTESUINT32_C(0x10)",
        "#defineROME2_PORT_100E2460_ELEMENT_BYTESUINT32_C(4)",
    ):
        if compact.count(constant) != 1:
            findings.append(f"public span constant changed: {constant}")
    lowered = text.lower()
    for phrase in (
        "not a completed call to 0x100e2460",
        "vtable-slot-4 dispatch",
        "peekmessagew",
        "success writes exactly two",
    ):
        if phrase not in lowered:
            findings.append(f"header exclusion contract is missing: {phrase}")
    if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append("DLL import/export annotation is forbidden")
    if re.search(r"\b(?:uintptr_t|intptr_t|void\s*\*)\b", code):
        findings.append("native pointer-shaped public fields are forbidden")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_SOURCE_TOKEN_SHA256:
        findings.append("source executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e2460_append_prefix.h", "limits.h"]:
        findings.append("source include set or order changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")

    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden allocation/platform identifier: {token}")
    lowered = code.lower()
    for address in sorted(BANNED_ADDRESS_TOKENS):
        if address in lowered:
            findings.append(f"excluded recovered address token: {address}")
    if re.search(r"\b(?:extern|volatile|__declspec)\b", code):
        findings.append("extern/volatile/DLL storage is forbidden")
    if re.search(r"\(\s*(?:uint8_t|void|uintptr_t)\s*\*\s*\)\s*[^;\n]*\.value", code):
        findings.append("guest coordinate is converted to a native pointer")
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
        "#defineROME2_GUEST_ADDRESS_SPACE_SIZEUINT64_C(0x100000000)"
    ) != 1:
        findings.append("guest address-space constant changed")
    definition = re.compile(
        r"\brome2_guest_status\s+" + re.escape(FUNCTION) + r"\s*\("
    )
    if len(definition.findall(code)) != 1:
        findings.append("exactly one append-prefix definition is required")

    ordered = (
        "if(view==NULL||view->host_base==NULL){returnROME2_GUEST_BAD_ARGUMENT;}",
        "if(view->byte_count>ROME2_GUEST_ADDRESS_SPACE_SIZE||"
        "(uint64_t)view->guest_base+view->byte_count>"
        "ROME2_GUEST_ADDRESS_SPACE_SIZE){returnROME2_GUEST_RANGE_OVERFLOW;}",
        "host_address=(uintptr_t)view->host_base;",
        "view_address=(uintptr_t)view;",
        "if(guest_vector.value==0){returnROME2_GUEST_NULL_ADDRESS;}",
        "vector_offset=(uint64_t)guest_vector.value-(uint64_t)view->guest_base;",
        "capacity=rome2_100e2460_read_u32_le(vector+4);",
        "count=rome2_100e2460_read_u32_le(vector+8);",
        "backing_guest=rome2_100e2460_read_u32_le(vector+12);",
        "if(count>=capacity){returnROME2_GUEST_BAD_ARGUMENT;}",
        "if(backing_guest==0){returnROME2_GUEST_NULL_ADDRESS;}",
        "element_displacement=(uint64_t)count*UINT64_C(4);",
        "append_guest=(uint64_t)backing_guest+element_displacement;",
        "append_offset=append_guest-(uint64_t)view->guest_base;",
        "if(rome2_100e2460_spans_overlap("
        "vector_offset,ROME2_PORT_100E2460_VECTOR_BYTES,append_offset,"
        "ROME2_PORT_100E2460_ELEMENT_BYTES)){returnROME2_GUEST_BAD_ARGUMENT;}",
        "append_cell=view->host_base+(size_t)append_offset;",
        "count_cell=view->host_base+(size_t)vector_offset+8;",
        "rome2_100e2460_write_u32_le(append_cell,guest_element.value);",
        "rome2_100e2460_write_u32_le(count_cell,count+UINT32_C(1));",
        "returnROME2_GUEST_OK;",
    )
    previous = -1
    for fragment in ordered:
        position = compact.find(fragment)
        if position < 0:
            findings.append(f"required boundary fragment missing: {fragment[:64]}")
            continue
        if position <= previous:
            findings.append("validation or two-cell commit order changed")
        previous = position

    required_checks = (
        "view->byte_count-UINT64_C(1)>(uint64_t)(UINTPTR_MAX-host_address)",
        "sizeof(*view)-1>UINTPTR_MAX-view_address",
        "view_address-host_address)<view->byte_count",
        "UINT32_MAX-(ROME2_PORT_100E2460_VECTOR_BYTES-UINT32_C(1))",
        "ROME2_PORT_100E2460_VECTOR_BYTES>view->byte_count-vector_offset",
        "element_displacement>UINT32_MAX",
        "append_guest>UINT32_MAX",
        "ROME2_PORT_100E2460_ELEMENT_BYTES>view->byte_count-append_offset",
    )
    for check in required_checks:
        if compact.count(check) != 1:
            findings.append(f"required range/alias check changed: {check[:64]}")
    if compact.count("rome2_100e2460_write_u32_le(") != 3:
        findings.append("source must define one writer and make exactly two commits")
    if compact.count("guest_element.value") != 1:
        findings.append("opaque element bits must be consumed exactly once")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime-test executable-token digest changed")
    for label in TEST_CASE_LABELS:
        if text.count(f'"{label}"') != 1:
            findings.append(f"required runtime case missing or duplicated: {label}")
    if code.count(FUNCTION + "(") < 4:
        findings.append("runtime test does not exercise success and failure paths")
    for token in ("PeekMessageW", "100fcc80", "100fcc50"):
        if token.lower() in code.lower():
            findings.append(f"runtime test references excluded behavior: {token}")
    for oracle in (
        "memcpy(expected.bytes,actual.bytes,sizeof(expected.bytes));",
        "rome2_test_put_u32(expected.bytes,(size_t)append_offset,element);",
        "memcmp(actual.bytes,expected.bytes,sizeof(actual.bytes))",
        "memcmp(memory->bytes,snapshot.bytes,sizeof(memory->bytes))",
    ):
        if oracle not in _compact(code):
            findings.append(f"independent byte oracle fragment missing: {oracle[:58]}")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless frozen size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    if _token_digest(code) != EXPECTED_HEADLESS_TOKEN_SHA256:
        findings.append("headless executable-token digest changed")
    if text.count('#include "ported_100e2460_append_prefix.h"') != 1:
        findings.append("headless append-prefix include is missing or duplicated")
    if code.count(FUNCTION + "(") != 1:
        findings.append("headless must execute the append prefix exactly once")
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
        *FINAL_HEADLESS_TOKENS,
    ):
        if text.count(token) != 1:
            findings.append(f"headless boundary report changed: {token}")
    final_token_positions = [text.find(token) for token in FINAL_HEADLESS_TOKENS]
    if any(position < 0 for position in final_token_positions) or any(
        left >= right
        for left, right in zip(final_token_positions, final_token_positions[1:])
    ):
        findings.append("headless final handler token tail order changed")
    for forbidden in (
        "initializer-dispatch=not-linked",
        "initializer-dispatch=executed",
        "allocator=executed",
        "native-release=executed",
        "queue-drain=not-run",
        "queue-drain=executed",
    ):
        if forbidden in text:
            findings.append(f"headless falsely claims excluded behavior: {forbidden}")
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
        findings.append("CMake total must remain exactly 192 CTests")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped_tokens = (
        LIBRARY,
        SUFFIX_LIBRARY,
        PLATFORM_PREFIX_LIBRARY,
        TEST_TARGET,
        "ported_100e2460_append_prefix.h",
        "ported_100e2460_append_prefix.c",
        "test_startup_100e2460_append_prefix.c",
        "startup_100e2460_append_prefix_provenance",
        "startup_100e2460_append_prefix_static_gate",
        "startup_100e2460_append_prefix_runtime",
        "startup_100e2460_append_prefix_post_pe_gate",
        "x64_bootstrap_load_after_startup_100e2460_append_prefix",
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake token escapes BUILD_TESTING: {token}")
    compact = _compact("\n".join(lines[start + 1:end]))
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("append-prefix port must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("append-prefix library must not be shared")
    if f"add_executable({TEST_TARGET}" not in compact:
        findings.append("append-prefix runtime-test executable is missing")
    if (
        f"target_link_libraries({LIBRARY}PRIVATErome2_guest32_runtime)"
        not in compact
    ):
        findings.append("append-prefix library must depend only on guest32 runtime")
    if f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})" not in compact:
        findings.append("dedicated test must link the append-prefix library")
    expected_headless = (
        "target_link_libraries(rome2_headless64PRIVATE"
        "rome2_guest32_runtime"
        "rome2_startup_100f1aa0_empty_runtime"
        "rome2_startup_safe_seams_runtime"
        "rome2_startup_100df270_headless_runtime"
        "rome2_startup_100f2750_nonalloc_runtime"
        "rome2_startup_100e8240_fastpath_runtime"
        "rome2_startup_100e2460_append_prefix_runtime"
        "rome2_startup_100e2460_preallocated_branch_runtime"
        "rome2_startup_100e2460_capacity_zero_branch_runtime"
        "rome2_startup_100e2460_growth_branch_runtime"
        "rome2_startup_100e2460_router_runtime"
        + "".join(FINAL_HEADLESS_LIBRARIES)
        + ")"
    )
    if expected_headless not in compact:
        findings.append("headless admitted-library composition changed")
    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands if LIBRARY in command
    ]
    if sorted(consumers) != sorted((
        LIBRARY,
        TEST_TARGET,
        HEADLESS,
        "rome2_startup_100e2460_preallocated_branch_runtime",
    )):
        findings.append("append-prefix library has an unexpected consumer/dependency")
    for command in link_commands:
        if LIBRARY not in command:
            continue
        consumer = re.split(r"\s+", command.strip(), maxsplit=1)[0]
        if consumer not in {
            LIBRARY,
            TEST_TARGET,
            HEADLESS,
            "rome2_startup_100e2460_preallocated_branch_runtime",
        }:
            findings.append("append-prefix library escaped its test-only consumers")
        if (
            consumer == "rome2_startup_100e2460_preallocated_branch_runtime"
            and _compact(command) != (
                "rome2_startup_100e2460_preallocated_branch_runtime"
                "PRIVATErome2_startup_100e2460_append_prefix_runtime"
            )
        ):
            findings.append("append-prefix successor dependency changed")
        if any(token in command for token in (
            "empire_retail_bootstrap", "empire_bootstrap_smoke",
            "rome2_guest32_probe", "empire_retail64",
        )):
            findings.append("append-prefix library is linked to production/probe code")
    fixture_fragments = (
        "startup_100e8240_fastpath_reload_verified;"
        "startup_100e2460_append_prefix_provenance_verified;"
        "startup_100e2460_append_prefix_static_verified",
    )
    for fragment in fixture_fragments:
        if _compact(fragment) not in compact:
            findings.append(f"append-prefix fixture-chain edge missing: {fragment}")
    expected_fixture_blocks = (
        (
            "set_tests_properties(startup_100e2460_append_prefix_post_pe_gate"
            "PROPERTIESFIXTURES_REQUIRED"
            '"startup_100e2460_append_prefix_runtime_verified;'
            'entry_policy_probe_pe_tool_verified"'
            "FIXTURES_SETUPstartup_100e2460_append_prefix_post_verified)"
        ),
        (
            "set_tests_properties("
            "x64_bootstrap_load_after_startup_100e2460_append_prefixPROPERTIES"
            "FIXTURES_REQUIRED"
            '"x64_bootstrap_pre_verified;'
            'startup_100e2460_append_prefix_post_verified"'
            "FIXTURES_SETUPstartup_100e2460_append_prefix_reload_verified)"
        ),
        (
            "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
            "FIXTURES_REQUIRED"
            '"entry_policy_provenance_verified;entry_policy_static_verified;'
            'startup_100ed471_ordinary_lifecycle_reload_verified"'
            "TIMEOUT90)"
        ),
    )
    for block in expected_fixture_blocks:
        if compact.count(block) != 1:
            findings.append(
                "append-prefix post/reload/headless fixture block changed"
            )
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "ported_100e2460", "100e2460"
    ):
        if token in lowered:
            findings.append(f"test-only append-prefix token escaped exports: {token}")
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
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks = {
        "header": (args.header, inspect_header_text),
        "source": (args.source, inspect_source_text),
        "test": (args.test, inspect_test_text),
        "headless": (args.headless, inspect_headless_text),
        "cmake": (args.cmake, inspect_cmake_text),
        "export_manifest": (args.export_manifest, inspect_exports_text),
        "legacy_def": (args.legacy_def, inspect_exports_text),
        "probe_def": (args.probe_def, inspect_exports_text),
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, (path, inspector) in checks.items():
        resolved = path.resolve(strict=True)
        findings = _inspect_path(resolved, inspector)
        total += len(findings)
        report["files"][label] = {
            "path": str(resolved), "findings": findings
        }
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
