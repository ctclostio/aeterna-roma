#!/usr/bin/env python3
"""Fail-closed source and containment gate for original 0x100e85d0."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e85d0_normal_adapter"
ROUTER_FUNCTION = "rome2_port_100e2460_run_router"
HANDLER_8D00_FUNCTION = "rome2_port_100e8d00_run_handler_transcript"
HANDLER_8580_FUNCTION = "rome2_port_100e8580_run_handler_transcript"
OUTER_INITIALIZER_FUNCTION = "rome2_port_100ea4d0_run_injected"
HANDLER_9340_FUNCTION = "rome2_port_100e9340_run_handler_transcript"
HANDLER_92C0_FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
HANDLER_87A0_FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIBRARY = "rome2_startup_100e85d0_normal_adapter_runtime"
TEST_TARGET = "rome2_startup_100e85d0_normal_adapter_tests"
HEADLESS = "rome2_headless64"
ROUTER_LIBRARY = "rome2_startup_100e2460_router_runtime"
TRANSCRIPT_LIBRARY = "rome2_startup_100e8d00_handler_transcript_runtime"
FINAL_TRANSCRIPT_LIBRARY = "rome2_startup_100e8580_handler_transcript_runtime"
OUTER_INITIALIZER_LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
HANDLER_9340_LIBRARY = "rome2_startup_100e9340_handler_transcript_runtime"
HANDLER_92C0_LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
HANDLER_87A0_LIBRARY = "rome2_startup_100e87a0_handler_transcript_runtime"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"

EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_ADD_TEST_COUNT = 194
EXPECTED_CMAKE_SIZE = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

EXPECTED_HEADER_TOKEN_SHA256 = (
    "48a3a91bd0477e92c6e79fef0354c076f5e5a266b211d89867aaf75c1230314d"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "9fd4f7368762f08b5dd265463f195c89abb928973f6b14ceb1519b4cfec4d9d8"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "c6a7760177ebdda403b2e2803438fc9455d99570e3732d9e7ae955b0c96cf02f"
)
EXPECTED_PROVENANCE_SHA256 = (
    "d5af61845906a2c5ecbd889de91243f934ea28f86f71e7c9ceff3ccba6aba583"
)

ADAPTER_TEST_NAMES = (
    "startup_100e85d0_normal_adapter_provenance",
    "startup_100e85d0_normal_adapter_static_gate_unit",
    "startup_100e85d0_normal_adapter_static_gate",
    "startup_100e85d0_normal_adapter_runtime",
    "startup_100e85d0_normal_adapter_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e85d0_normal_adapter",
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
    TRANSCRIPT_LIBRARY,
    LIBRARY,
    FINAL_TRANSCRIPT_LIBRARY,
    OUTER_INITIALIZER_LIBRARY,
    HANDLER_9340_LIBRARY,
    HANDLER_92C0_LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    LIFECYCLE_LIBRARY,
)

HEADLESS_REQUIRED_TOKENS = (
    "initializer-handler-100e85d0=effect-free-complete",
    "initializer-handler-100e8d00=injected-transcript-complete",
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

EFFECT_TOKENS = {
    "allocate", "allocator", "callback", "context", "dispatch", "effects",
    "peek", "release", "state_view", "vtable_view",
}


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _token_digest(code: str) -> str:
    return hashlib.sha256(_compact(code).encode("utf-8")).hexdigest()


def _require_once(
    compact: str, fragment: str, findings: list[str], message: str
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_HEADER_TOKEN_SHA256:
        findings.append("header executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["guest32.h"]:
        findings.append("adapter header must reuse only the guest32 contract")
    _require_once(
        compact,
        "#defineROME2_PORT_100E85D0_NORMAL_ALUINT8_C(1)",
        findings,
        "normal AL constant must be exactly one",
    )
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "rome2_guest_addr32guest_receiver,"
        "rome2_guest_addr32guest_argument,uint8_t*return_al_out);"
    )
    _require_once(compact, declaration, findings, "public adapter API changed")
    if compact.count(FUNCTION + "(") != 1:
        findings.append("exactly one public adapter declaration is required")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "opaque values",
        "every guest32 bit",
        "pattern, including zero",
        "without dereference or validation",
        "required borrowed one-byte result object",
        "null output",
        "fails with bad_argument",
        "success publishes exactly one",
        "no guest,",
        "context, allocator, platform",
        "does not call or link the original helper",
        "bounded, allocation-free, reentrant, and thread-safe",
    ):
        if phrase not in normalized:
            findings.append(f"adapter effect/identity contract is missing: {phrase}")
    if re.search(r"\b(?:__declspec|dllexport|dllimport|extern)\b", code, re.I):
        findings.append("native import/export linkage is forbidden")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _token_digest(code) != EXPECTED_SOURCE_TOKEN_SHA256:
        findings.append("source executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100e85d0_normal_adapter.h"]:
        findings.append("source include boundary changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden allocation/platform identifier: {token}")
    for token in sorted(tokens & EFFECT_TOKENS):
        findings.append(f"effect/callback state is forbidden: {token}")
    if re.search(r"\b(?:extern|volatile|__declspec|__asm|asm)\b", code):
        findings.append("native/original linkage or assembly is forbidden")
    if "100d6560" in code.lower():
        findings.append("authenticated no-op helper must be elided, not linked")
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
    for call in sorted(calls - {"if", FUNCTION}):
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
    exact_definition = (
        "rome2_guest_status" + FUNCTION + "("
        "rome2_guest_addr32guest_receiver,"
        "rome2_guest_addr32guest_argument,uint8_t*return_al_out){"
        "if(return_al_out==NULL){returnROME2_GUEST_BAD_ARGUMENT;}"
        "(void)guest_receiver;(void)guest_argument;"
        "*return_al_out=ROME2_PORT_100E85D0_NORMAL_AL;"
        "returnROME2_GUEST_OK;}"
    )
    _require_once(
        compact,
        exact_definition,
        findings,
        "null-fail-closed/effect-free adapter body changed",
    )
    if compact.count(FUNCTION + "(") != 1:
        findings.append("exactly one adapter definition is required")
    if compact.count("*return_al_out=") != 1:
        findings.append("adapter must publish AL exactly once")
    if ".value" in code or "->" in code or re.search(
        r"\bguest_(?:receiver|argument)\s*(?:==|!=|<|>|\[)", code
    ):
        findings.append("opaque guest identities must not be inspected")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    raw_compact = _compact(text)
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e85d0_normal_adapter.h", "stdint.h", "stdio.h"
    ]:
        findings.append("runtime include set or order changed")
    if compact.count(FUNCTION + "(") != 3:
        findings.append("runtime adapter invocation boundary changed")
    for function in (
        "rome2_100e85d0_test_identity_domain",
        "rome2_100e85d0_test_null_output_fails_closed",
        "rome2_100e85d0_test_repeatability",
    ):
        if len(re.findall(r"\b" + re.escape(function) + r"\s*\(", code)) != 2:
            findings.append(f"runtime oracle missing or duplicated: {function}")
    for label in (
        "both identities null",
        "ordinary identities",
        "receiver high bit",
        "argument high bit",
        "all bits set",
        "distinct opaque bits",
    ):
        if text.count(label) != 1:
            findings.append(f"opaque identity-domain case changed: {label}")
    for fragment, message in (
        ("{\"bothidentitiesnull\",UINT32_C(0),UINT32_C(0)}",
         "zero-bit-pattern identity oracle changed"),
        ("{\"receiverhighbit\",UINT32_C(0x80000000),UINT32_C(1)}",
         "receiver high-bit identity oracle changed"),
        ("{\"argumenthighbit\",UINT32_C(1),UINT32_C(0x80000000)}",
         "argument high-bit identity oracle changed"),
        ("{\"allbitsset\",UINT32_MAX,UINT32_MAX}",
         "all-bit identity oracle changed"),
    ):
        if fragment not in raw_compact:
            findings.append(message)
    for fragment, message in (
        ("if(status!=ROME2_GUEST_OK)", "success status oracle changed"),
        ("if(guard.output!=UINT8_C(1))", "exact AL=1 oracle changed"),
        ("if(guard.before!=UINT8_C(0x3c)||guard.after!=UINT8_C(0xc3))",
         "one-byte output guard oracle changed"),
        ("NULL);if(status==ROME2_GUEST_BAD_ARGUMENT){return0;}",
         "null-output fail-closed oracle changed"),
        ("for(iteration=0;iteration<UINT32_C(65536);++iteration)",
         "bounded repeatability oracle changed"),
    ):
        if fragment not in compact:
            findings.append(message)
    if text.count("startup 100e85d0 normal adapter tests: pass") != 1:
        findings.append("runtime pass token changed")
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"runtime directly invokes forbidden native API: {token}")
    if "100d6560" in code.lower():
        findings.append("runtime must not invoke the original no-op helper")
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"adapter provenance is not strict UTF-8: {error}"]
    if hashlib.sha256(data).hexdigest() != EXPECTED_PROVENANCE_SHA256:
        findings.append("adapter provenance authority digest changed")
    for token in (
        "DLL_SHA256", "INDEX_SHA256", "FUNCTION_VA", "FUNCTION_BYTES",
        "FUNCTION_SHA256", "FUNCTION_RAW_OFFSET", "NOOP_VA", "NOOP_BYTES",
        "NOOP_SHA256", "NOOP_RAW_OFFSET", "NOOP_CANONICAL_SHA256",
        "VTABLE_PAIR_VA", "VTABLE_PAIR_BYTES", "VTABLE_PAIR_SHA256",
        "VTABLE_PAIR_RAW_OFFSET", "rel32_target",
        "test_exact_15_byte_handler_body",
        "test_only_call_targets_the_exact_one_byte_ret",
        "test_stack_shape_al_one_and_ret4_are_exact",
        "test_vtable_method_identity_is_exact",
        "test_noop_canonical_authority_is_exact",
    ):
        if text.count(token) < 1:
            findings.append(f"adapter provenance token missing: {token}")
    for authority in (
        "6a00e889dffeff83c404b001c20400",
        "1bf8d344edb832e512961f8bbafeb5f9a04cceb1e70cbf31d758151c6df970ff",
        "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e",
        "b2dd76946e1873f4fa7ddeb7f0eae493a93649788f0946882777879a4e185bf6",
        "a28eae14e25dad6de1bfce2611db689b66661af348650307a08ed3e03258788d",
    ):
        if text.count(authority) != 1:
            findings.append(f"adapter machine/canonical authority changed: {authority[:16]}")
    normalized = " ".join(text.lower().split())
    for phrase in (
        "parsed strictly as data and never loaded or executed",
        "one ignored zero argument to a one-byte ret helper",
        "al=1, and ret 4",
        "do not establish a native x64 abi",
        "or authorize linking either recovered address into the port",
    ):
        if phrase not in normalized:
            findings.append(f"adapter evidence/port-policy boundary missing: {phrase}")
    return sorted(set(findings))


def _assigned_calls(code: str) -> list[tuple[str, str, int]]:
    """Return (result name, raw argument text, end offset) for bounded calls."""
    matches: list[tuple[str, str, int]] = []
    prefix = re.compile(
        r"\b(?P<status>[A-Za-z_]\w*)\s*=\s*" + re.escape(FUNCTION) + r"\s*\("
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
        if depth != 0 or not re.match(r"\s*;", code[index:]):
            continue
        semicolon = index + re.match(r"\s*;", code[index:]).end()
        matches.append((match.group("status"), code[match.end():index - 1], semicolon))
    return matches


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    if len(text.encode("utf-8")) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless exact size changed")
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    include_pair = (
        '#include "ported_100e2460_router.h"\n'
        '#include "ported_100e8d00_handler_transcript.h"\n'
        '#include "ported_100e85d0_normal_adapter.h"\n'
        '#include "ported_100e8580_handler_transcript.h"\n'
        '#include "ported_100e9340_handler_transcript.h"\n'
        '#include "ported_100e92c0_handler_transcript.h"\n'
        '#include "ported_100e87a0_handler_transcript.h"\n'
        '#include "ported_100ea4d0_injected.h"'
    )
    if text.count(include_pair) != 1:
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
        (ROUTER_FUNCTION, 1), (HANDLER_8D00_FUNCTION, 2), (FUNCTION, 2),
        (HANDLER_8580_FUNCTION, 2), (OUTER_INITIALIZER_FUNCTION, 1),
        (HANDLER_9340_FUNCTION, 2), (HANDLER_92C0_FUNCTION, 2),
        (HANDLER_87A0_FUNCTION, 2), (SUFFIX_FUNCTION, 0),
        (PREFIX_FUNCTION, 0), (PARENT_FUNCTION, 1),
        (LIFECYCLE_FUNCTION, 1),
    ):
        if code.count(function + "(") != count:
            findings.append(
                f"headless final composition call-site count changed: {function} != {count}"
            )
    calls = _assigned_calls(code)
    if len(calls) != 2:
        findings.append("headless adapter result must be captured twice")
    else:
        for status_name, arguments, call_end in calls:
            output_match = re.search(
                r",\s*&(?P<output>[A-Za-z_]\w*)\s*$", arguments, re.S
            )
            if output_match is None:
                findings.append("headless adapter must receive a dedicated AL output")
                continue
            output_name = output_match.group("output")
            suffix = code[call_end:call_end + 700]
            condition_match = re.search(r"\bif\s*\((.*?)\)\s*\{", suffix, re.S)
            condition = _compact(condition_match.group(1)) if condition_match else ""
            if (
                f"{status_name}!=ROME2_GUEST_OK" not in condition
                or f"{output_name}!=ROME2_PORT_100E85D0_NORMAL_AL" not in condition
            ):
                findings.append("headless must check adapter status and exact AL result")
    for token in HEADLESS_REQUIRED_TOKENS:
        if text.count(token) != 1:
            findings.append(f"headless adapter boundary report changed: {token}")
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
        "startup-100ed471-ordinary-lifecycle=injected-bounded-complete",
    )
    positions = [text.find(token) for token in final_sequence]
    if any(position < 0 for position in positions) or any(
        left >= right for left, right in zip(positions, positions[1:])
    ):
        findings.append("headless final handler/suffix/platform-prefix token order changed")
    if "0x600000b1" in code.lower():
        findings.append("headless unknown-method fallback must fail closed")
    for forbidden in (
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
        LIBRARY, TEST_TARGET, "ported_100e85d0_normal_adapter.h",
        "ported_100e85d0_normal_adapter.c",
        "test_startup_100e85d0_normal_adapter.c",
        "test_x64_startup_100e85d0_normal_adapter_provenance.py",
        "test_x64_startup_100e85d0_normal_adapter_static_gate.py",
        "x64_startup_100e85d0_normal_adapter_static_gate.py",
        *ADAPTER_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake adapter token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake adapter token escapes BUILD_TESTING: {token}")
    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)
    exact_library = (
        f'add_library({LIBRARY}STATIC'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.c")'
    )
    if compact.count(exact_library) != 1:
        findings.append("adapter must be an exact BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("adapter library must not be shared")
    for fragment, message in (
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "adapter C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "adapter hardened compile options changed"),
        (f"target_include_directories({LIBRARY}PUBLIC"
         '"${ROME2_GUEST32_RUNTIME_DIR}"'
         '"${ROME2_GUEST32_PORTED_DIR}")',
         "adapter include containment changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e85d0_normal_adapter.c")',
         "adapter runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated adapter test must link only its static library"),
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
        findings.append("effect-free adapter must have no link dependencies")
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands
        if LIBRARY in command
        and re.split(r"\s+", command.strip(), maxsplit=1)[0] != LIBRARY
    ]
    if sorted(consumers) != sorted((TEST_TARGET, HEADLESS)):
        findings.append("adapter library has an unexpected consumer/dependency")
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
        "add_test(NAMEstartup_100e85d0_normal_adapter_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e85d0_normal_adapter.c"',
        '--adapter-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e85d0_normal_adapter_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"adapter static-gate argument changed: {argument[:76]}")
    for test_name in ADAPTER_TEST_NAMES:
        if len(re.findall(r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact)) != 1:
            findings.append(f"adapter CTest missing or duplicated: {test_name}")
    fixture_blocks = (
        "set_tests_properties(startup_100e85d0_normal_adapter_provenance"
        "PROPERTIESFIXTURES_SETUPstartup_100e85d0_normal_adapter_provenance_verified)",
        "set_tests_properties(startup_100e85d0_normal_adapter_static_gate_unit"
        "PROPERTIESFIXTURES_SETUPstartup_100e85d0_normal_adapter_static_tool_verified)",
        "set_tests_properties(startup_100e85d0_normal_adapter_static_gate"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e85d0_normal_adapter_static_tool_verified"
        "FIXTURES_SETUPstartup_100e85d0_normal_adapter_static_verified)",
        "set_tests_properties(startup_100e85d0_normal_adapter_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e8d00_handler_transcript_reload_verified;"
        "startup_100e85d0_normal_adapter_provenance_verified;"
        "startup_100e85d0_normal_adapter_static_verified\""
        "FIXTURES_SETUPstartup_100e85d0_normal_adapter_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e85d0_normal_adapter_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED\""
        "startup_100e85d0_normal_adapter_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e85d0_normal_adapter_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e85d0_normal_adapter"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e85d0_normal_adapter_post_verified\""
        "FIXTURES_SETUPstartup_100e85d0_normal_adapter_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        "entry_policy_static_verified;"
        "startup_100ed471_ordinary_lifecycle_reload_verified\"TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"adapter fixture-chain block changed: {block[:78]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e85d0_normal_adapter",
        "ported_100e85d0_normal_adapter", "100e85d0_normal_adapter",
    ):
        if token in lowered:
            findings.append(f"test-only adapter token escaped exports: {token}")
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
    parser.add_argument("--adapter-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        provenance = args.adapter_provenance.resolve(strict=True).read_bytes()
    except OSError as error:
        provenance_findings = [f"cannot read adapter provenance: {error}"]
    else:
        provenance_findings = inspect_provenance_bytes(provenance)
    checks = {
        "header": _inspect_path(args.header.resolve(strict=True), inspect_header_text),
        "source": _inspect_path(args.source.resolve(strict=True), inspect_source_text),
        "test": _inspect_path(args.test.resolve(strict=True), inspect_test_text),
        "adapter_provenance": provenance_findings,
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
        "adapter_provenance": args.adapter_provenance,
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
