#!/usr/bin/env python3
"""Fail-closed gate for the whole nonempty 0x100ed3c0 lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100ed3c0_run_nonempty_lifecycle"
PRELOOP_FUNCTION = "rome2_port_100ed3c0_run_nonempty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIBRARY = "rome2_startup_100ed3c0_nonempty_lifecycle_runtime"
TEST_TARGET = "rome2_startup_100ed3c0_nonempty_lifecycle_tests"
CALLER_LIBRARY = "rome2_startup_100edd70_caller_closure_runtime"
PRELOOP_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
EXPECTED_CTEST_COUNT = 194

EXPECTED_HEADER_BYTES = 4_111
EXPECTED_HEADER_SHA256 = (
    "3c517d37787001ea4838a00e413c8124e08e9fecae749c767d8395de76915791"
)
EXPECTED_SOURCE_BYTES = 28_612
EXPECTED_SOURCE_SHA256 = (
    "7abf65d7c510d17c45a59213be0e9176e4db76947cef436cfd542b03e8777b4d"
)
EXPECTED_TEST_BYTES = 60_045
EXPECTED_TEST_SHA256 = (
    "921681d86eec2285095c97603652c5f0486776290c580ed19c1251c4ae5efcaa"
)
EXPECTED_PROVENANCE_BYTES = 8_308
EXPECTED_PROVENANCE_SHA256 = (
    "e8353d50bce692498e22cab73e25320b66565cc9775dc1fcab5eb83b65dd9eba"
)
EXPECTED_DOC_BYTES = 6_922
EXPECTED_DOC_SHA256 = (
    "1dd19766d03b4dad226007e75d42d9ea1b4f0a3a6ab52c92b37981f078c73eb6"
)
EXPECTED_CMAKE_BYTES = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

CMAKE_FILES = (
    "ported_100ed3c0_nonempty_lifecycle.h",
    "ported_100ed3c0_nonempty_lifecycle.c",
    "test_startup_100ed3c0_nonempty_lifecycle.c",
    "test_x64_startup_100ed3c0_nonempty_lifecycle_provenance.py",
    "test_x64_startup_100ed3c0_nonempty_lifecycle_static_gate.py",
    "x64_startup_100ed3c0_nonempty_lifecycle_static_gate.py",
    "x64_startup_100ed3c0_nonempty_lifecycle.md",
)

CMAKE_TESTS = (
    "startup_100ed3c0_nonempty_lifecycle_provenance",
    "startup_100ed3c0_nonempty_lifecycle_static_gate_unit",
    "startup_100ed3c0_nonempty_lifecycle_static_gate",
    "startup_100ed3c0_nonempty_lifecycle_runtime",
    "startup_100ed3c0_nonempty_lifecycle_post_pe_gate",
    "x64_bootstrap_load_after_startup_100ed3c0_nonempty_lifecycle",
)

BANNED_DIRECT_CALLS = (
    "rome2_port_100f1bb0_build_owned_utf16",
    "rome2_port_100df270_run_platform_prefix_transcript",
    "rome2_port_100df270_project_headless_empty_state",
    "rome2_port_100df270_run_suffix_transcript_delegated",
    "rome2_port_100f2750_first_use_owned",
    "rome2_port_100f1cc0_cleanup_owned_utf16",
    "rome2_port_100f2750_register_first_use_owned",
    "rome2_port_100f2750_teardown_first_use_owned",
)

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateFileA", "CreateFileW", "CreateMutexA",
    "CreateMutexW", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetProcAddress", "GetProcessHeap", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "MessageBoxA",
    "MessageBoxW", "TerminateProcess", "VirtualAlloc", "VirtualFree",
    "_atexit", "_onexit", "atexit", "calloc", "dlopen", "dlsym",
    "free", "malloc", "realloc", "system",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return "".join(text.split())


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
        findings.append(f"{label} SHA-256 changed")


def _call_count(code: str, name: str) -> int:
    return len(re.findall(rf"\b{re.escape(name)}\s*\(", code))


def _require_in_order(
    text: str,
    tokens: tuple[str, ...],
    findings: list[str],
    message: str,
) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            findings.append(message)
            return
        cursor = position + len(token)


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def inspect_header_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_HEADER_BYTES, EXPECTED_HEADER_SHA256, "header", findings
    )
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)
    required = (
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_START_PC"
         "UINT32_C(0x100ed3c0)", "whole start identity changed"),
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC"
         "UINT32_C(0x100ed550)", "whole return identity changed"),
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES"
         "UINT32_C(0x90c)", "whole frame size changed"),
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_MISMATCH_PRELOOP_EVENTS"
         "\\UINT32_C(31)", "preloop event cardinality changed"),
        ("#defineROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FIXED_TAIL_EVENTS"
         "UINT32_C(11)", "lifecycle event cardinality changed"),
        ("rome2_100ed3c0_nonempty_effectspreloop;",
         "preloop effects embedding changed"),
        ("rome2_100ed471_lifecycle_effectsordinary;",
         "ordinary effects embedding changed"),
        ("uint64_tordinary_context_byte_count;",
         "ordinary callback span is missing"),
        ("rome2_100ed3c0_preloop_resultpreloop;",
         "preloop result embedding changed"),
        ("rome2_100ed471_lifecycle_resultordinary;",
         "ordinary result embedding changed"),
    )
    for fragment, message in required:
        if compact.count(fragment) != 1:
            findings.append(message)
    if _call_count(code, FUNCTION) != 1:
        findings.append("header must declare exactly one typed whole-parent API")
    contract = "".join(text.replace("*", "").split())
    for token in (
        "private scratch frame",
        "exactly one nonempty-preloop call",
        "exactly one ordinary-lifecycle call",
        "combined result commits once and last",
        "performs no rollback",
        "persistent authority remains live for explicit teardown",
        "performs no guest/native pointer cast",
    ):
        if _compact(token) not in contract:
            findings.append(f"header composition contract changed: {token}")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text, EXPECTED_SOURCE_BYTES, EXPECTED_SOURCE_SHA256, "source", findings
    )
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)

    for identifier in BANNED_IDENTIFIERS:
        if re.search(rf"\b{re.escape(identifier)}\b", code):
            findings.append(f"forbidden native identifier in source: {identifier}")
    if re.search(r"\b(?:decomp_fn_|FUN_|DAT_)[A-Za-z0-9_]*", code):
        findings.append("source must not reference recovered/original identifiers")
    for name in BANNED_DIRECT_CALLS:
        if _call_count(code, name) != 0:
            findings.append(f"whole parent must not bypass admitted children: {name}")
    if _call_count(code, PRELOOP_FUNCTION) != 1:
        findings.append("source must call the admitted nonempty child exactly once")
    if _call_count(code, LIFECYCLE_FUNCTION) != 2:
        findings.append("source must call lifecycle exactly twice: preview and real")

    _require_in_order(
        code,
        (
            "guest_status = rome2_port_100ed471_run_ordinary_lifecycle(",
            "owned_status = rome2_port_100ed3c0_run_nonempty_preloop(",
            "guest_status = rome2_port_100ed471_run_ordinary_lifecycle(",
            "*result_out = state.combined_result;",
        ),
        findings,
        "preview, preloop, lifecycle, and final commit order changed",
    )

    required = (
        ("#defineROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT12U",
         "exact twelve-control alias universe changed"),
        ("#defineROME2_100ED3C0_LIFECYCLE_BACKING_COUNT7U",
         "exact seven-backing alias universe changed"),
        ("#defineROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT6U",
         "exact six-context alias universe changed"),
        ("ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES=="
         "ROME2_PORT_100ED471_FRAME_BYTES",
         "shared exact-frame assertion changed"),
        ("ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC=="
         "ROME2_PORT_100ED471_START_PC",
         "exact seam assertion changed"),
        ("ROME2_PORT_100ED471_RETURN_PC=="
         "ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC",
         "exact return assertion changed"),
        ("state.preview_effects.emit_step="
         "rome2_100ed3c0_lifecycle_preview_emit;",
         "preview must use its private observer"),
        ("state.preview_effects.context=&state.preview_trace;",
         "preview observer context must remain private"),
        ("&state.preview_frame_view,guest_frame,&state.dispatch_view,"
         "dispatch_receiver,max_poll_calls,&state.preview_effects,"
         "&state.preview_result);",
         "private lifecycle preview call changed"),
        ("&state.effects.preloop,temporary_owner,persistent_owner,lifecycle,"
         "&state.preloop_result);",
         "real nonempty child call must retain private result"),
        ("&state.effects.ordinary,&state.ordinary_result);",
         "real lifecycle child call must retain private result"),
        ("state.combined_result.preloop=state.preloop_result;",
         "combined preloop result staging changed"),
        ("state.combined_result.ordinary=state.ordinary_result;",
         "combined lifecycle result staging changed"),
    )
    for fragment, message in required:
        if compact.count(fragment) != 1:
            findings.append(message)

    cleanup_assertions = (
        "ROME2_PORT_100ED471_CLEANUP0_OFFSET=="
        "ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET",
        "ROME2_PORT_100ED471_CLEANUP1_OFFSET=="
        "ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET",
        "ROME2_PORT_100ED471_CLEANUP2_OFFSET=="
        "ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET",
        "ROME2_PORT_100ED471_CLEANUP3_OFFSET=="
        "ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET",
    )
    for fragment in cleanup_assertions:
        if compact.count(fragment) != 1:
            findings.append("cleanup-to-preloop seam assertion changed")

    snapshots = (
        "state.frame_view=*frame_view;",
        "state.text_view=*text_view;",
        "state.selector_view=*selector_view;",
        "state.temporary_heap_view=*temporary_heap_view;",
        "state.persistent_descriptor_view=*persistent_descriptor_view;",
        "state.persistent_heap_view=*persistent_heap_view;",
        "state.dispatch_view=*dispatch_view;",
        "state.effects=*effects;",
    )
    for fragment in snapshots:
        if compact.count(fragment) != 1:
            findings.append(f"complete input snapshot changed: {fragment}")

    if compact.count("*result_out=state.combined_result;") != 1 or (
        "result_out->" in code
    ):
        findings.append("combined result must commit exactly once and last")
    if compact.count(
        "temporary_owner->phase!=ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED"
    ) != 1:
        findings.append("temporary ownership seam check changed")
    if compact.count(
        "persistent_owner->phase!=ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE"
    ) != 1:
        findings.append("persistent ownership seam check changed")
    if compact.count(
        "lifecycle->phase!="
        "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE"
    ) != 1:
        findings.append("lifecycle ownership seam check changed")
    if "contexts[first].start!=contexts[second].start||" not in compact or (
        "contexts[first].byte_count!=contexts[second].byte_count" not in compact
    ):
        findings.append("contexts must remain exact-identical or disjoint")
    if re.search(
        r"\([^)]*\*\)\s*(?:guest_frame|dispatch_receiver|"
        r"argument_position3_text)(?:\.value)?\b",
        code,
    ):
        findings.append("guest/native pointer cast found")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_TEST_BYTES, EXPECTED_TEST_SHA256, "runtime", findings)
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)
    raw_compact = _compact(text)
    if compact.count("#defineTEST_EXPECTED_CASESUINT32_C(36)") != 1:
        findings.append("runtime must retain exactly 36 cases")
    if compact.count("expected_count==UINT32_C(42)+"
                     "fixture->trace.expected_poll_count") != 1:
        findings.append("runtime 42+P total event formula changed")
    for fragment, message in (
        ('"N1immediateterminal",1U,1U', "P=1 success case changed"),
        ('"canonicalN3pollthree",3U,3U', "P=3 success case changed"),
        ('"maximumpolltranscript",3U,64U', "P=64 success case changed"),
        ('"fallbackdispatch"', "fallback dispatch case is missing"),
        ('"combinedeffectssnapshot"', "effects snapshot adversary is missing"),
        ('"maximumtext",32767U', "N=32767 case is missing"),
        ('"crossresiduepair"', "cross-residue case is missing"),
        ('"exactframeendpoint"', "exact frame endpoint case is missing"),
        ('"ordinarycontextoverlapseffectscontrol"',
         "context-to-control alias case is missing"),
        ('"lifecyclecontrolaliasesdescriptorbacking"',
         "control-to-backing alias case is missing"),
        ('failed|=test_tier0_cases();', "Tier-0 group registry changed"),
        ('failed|=test_effect_failures();', "effect-failure group registry changed"),
        ('test_case_count==TEST_EXPECTED_CASES', "runtime case-count check changed"),
        ('"thecombinedtotalorderchanged"', "shared total-order proof is missing"),
        ('"thedescriptor-to-timestamphandoffchanged"',
         "descriptor/timestamp seam proof is missing"),
        ('"persistentteardowndidnotconsumeexactlyonce"',
         "persistent teardown proof is missing"),
        ('"repeatedpersistentteardownemittedaneffect"',
         "repeat teardown proof is missing"),
        ('"registeredsentinelteardownemittedaneffect"',
         "registered-sentinel teardown proof is missing"),
        ('"persistenttokencollision"', "token collision case is missing"),
        ('"temporarydenialwithtoken"', "temporary compensation case is missing"),
        ('"persistentmalformedgrant"', "persistent compensation case is missing"),
        ('test_result_is_sentinel(&fixture->trace)',
         "failure result-sentinel checks are missing"),
    ):
        if fragment not in raw_compact:
            findings.append(message)
    if text.count('"persistent token collision"') != 3:
        findings.append("token collision case count changed")
    if compact.count("test_result_is_sentinel(&fixture->trace)") != 5:
        findings.append("failure result-sentinel check count changed")
    for identifier in BANNED_IDENTIFIERS:
        if re.search(rf"\b{re.escape(identifier)}\b", code):
            findings.append(f"forbidden native identifier in runtime: {identifier}")
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(
        text,
        EXPECTED_PROVENANCE_BYTES,
        EXPECTED_PROVENANCE_SHA256,
        "provenance",
        findings,
    )
    compact = _compact(text)
    for token in (
        "PARENT_RAW_OFFSET=0x000EC7C0",
        "PARENT_SIZE=400",
        f'PARENT_SHA256="b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"',
        "PRELOOP_SIZE=177",
        "LIFECYCLE_SIZE=223",
        "validate_parent(parent)",
        "test_admitted_children_are_frozen",
        "test_whole_composition_artifacts_are_one_coherent_snapshot",
        "test_reciprocal_boundary_and_authority_mutants_fail",
        "test_oracle_is_standard_library_only_and_read_only",
    ):
        if token not in compact:
            findings.append(f"provenance boundary/authority token changed: {token}")
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC_BYTES, EXPECTED_DOC_SHA256, "doc", findings)
    compact = _compact(text)
    for token in (
        "[0x100ed3c0,0x100ed550)",
        "exact400-bytebody",
        "private lifecycle preview",
        "exactly one nonempty-preloop call",
        "exactly one ordinary-lifecycle call",
        "seven guest backings",
        "Twelve public control objects",
        "Six callback contexts",
        "42+P",
        "exactly36cases",
        "exactly two test-only consumers",
        "BUILD_TESTING",
        "production target",
    ):
        if _compact(token) not in compact:
            findings.append(f"documentation contract changed: {token}")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    found: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, re.I):
            stack.append((index, bool(re.match(
                r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, re.I
            ))))
        elif re.match(r"endif(?:\s*\([^)]*\))?\s*$", stripped, re.I):
            if not stack:
                return None
            start, is_build_testing = stack.pop()
            if is_build_testing:
                found.append((start, index))
    if stack or len(found) != 1:
        return None
    return found[0]


def _link_commands(text: str) -> list[list[str]]:
    commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    return [re.split(r"\s+", command.strip()) for command in commands]


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_CMAKE_BYTES, EXPECTED_CMAKE_SHA256, "CMake", findings)
    count = len(re.findall(r"^\s*add_test\s*\(", text, re.I | re.M))
    if count != EXPECTED_CTEST_COUNT:
        findings.append(f"CMake total must be exactly {EXPECTED_CTEST_COUNT} CTests")
    if re.search(r"\b(?:set|option)\s*\(\s*BUILD_TESTING\b", text, re.I):
        findings.append("CMake must not override BUILD_TESTING")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        findings.append("one balanced if(BUILD_TESTING) block is required")
        return sorted(set(findings))
    start, end = bounds
    for token in (*CMAKE_FILES, *CMAKE_TESTS, LIBRARY, TEST_TARGET):
        positions = [i for i, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake whole-parent token is missing: {token}")
        elif any(i <= start or i >= end for i in positions):
            findings.append(f"CMake whole-parent token escapes BUILD_TESTING: {token}")

    scoped = _compact("\n".join(lines[start + 1:end]))
    required = (
        (f"add_library({LIBRARY}STATIC"
         '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_lifecycle.h"'
         '"${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_lifecycle.c")',
         "whole-parent library must be exact static and test-only"),
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "whole-parent C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "whole-parent hardened compile options changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_nonempty_lifecycle.c")',
         "whole-parent runtime executable changed"),
        (f"rome2_configure_x64_target({TEST_TARGET})",
         "whole-parent runtime x64 configuration changed"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "whole-parent runtime link changed"),
    )
    for fragment, message in required:
        if scoped.count(fragment) != 1:
            findings.append(message)

    commands = _link_commands(text)
    own = [words for words in commands if words and words[0] == LIBRARY]
    expected = [[
        LIBRARY, "PUBLIC", "rome2_guest32_runtime", "PRIVATE",
        PRELOOP_LIBRARY, LIFECYCLE_LIBRARY,
    ]]
    if own != expected:
        findings.append("whole-parent exact two-child dependency list changed")
    consumers = [
        words[0] for words in commands
        if words and words[0] != LIBRARY and LIBRARY in words
    ]
    if consumers != [TEST_TARGET, CALLER_LIBRARY]:
        findings.append("whole parent must have exactly two test-only consumers")

    for name in CMAKE_TESTS:
        if scoped.count(f"add_test(NAME{name}COMMAND") != 1:
            findings.append(f"whole-parent CTest registration changed: {name}")
    gate_start = scoped.find(
        "add_test(NAMEstartup_100ed3c0_nonempty_lifecycle_static_gateCOMMAND"
    )
    gate_end = scoped.find("add_test(", gate_start + 1)
    gate_scope = scoped[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        "--header", "--source", "--test", "--provenance", "--doc",
        "--cmake", "--headless", "--export-manifest", "--export-contract",
        "--legacy-def", "--bootstrap-def", "--probe-def",
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"whole-parent static-gate argument changed: {argument}")

    fixtures = (
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_lifecycle_provenance_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_lifecycle_static_tool_verified",
        "FIXTURES_REQUIREDstartup_100ed3c0_nonempty_lifecycle_static_tool_verified"
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_lifecycle_static_verified",
        "startup_100ed3c0_nonempty_preloop_reload_verified;"
        "startup_100ed471_ordinary_lifecycle_reload_verified;"
        "startup_100ed3c0_nonempty_lifecycle_provenance_verified;"
        "startup_100ed3c0_nonempty_lifecycle_static_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_lifecycle_runtime_verified",
        "startup_100ed3c0_nonempty_lifecycle_runtime_verified;"
        "entry_policy_probe_pe_tool_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_lifecycle_post_verified",
        "x64_bootstrap_pre_verified;"
        "startup_100ed3c0_nonempty_lifecycle_post_verified",
        "FIXTURES_SETUPstartup_100ed3c0_nonempty_lifecycle_reload_verified",
    )
    for fragment in fixtures:
        if fragment not in scoped:
            findings.append(f"whole-parent fixture chain changed: {fragment}")
    return sorted(set(findings))


def inspect_production_text(text: str) -> list[str]:
    lowered = text.lower()
    findings: list[str] = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(),
        "ported_100ed3c0_nonempty_lifecycle",
        "100ed3c0_nonempty_lifecycle",
        "100ed3c0-nonempty-lifecycle",
    ):
        if token in lowered:
            findings.append(f"test-only whole-parent token escaped production: {token}")
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
    parser.add_argument("--provenance", type=pathlib.Path, required=True)
    parser.add_argument("--doc", type=pathlib.Path, required=True)
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
        "runtime": (args.test, inspect_test_text),
        "provenance": (args.provenance, inspect_provenance_text),
        "doc": (args.doc, inspect_doc_text),
        "cmake": (args.cmake, inspect_cmake_text),
        "headless": (args.headless, inspect_production_text),
        "export_manifest": (args.export_manifest, inspect_production_text),
        "export_contract": (args.export_contract, inspect_production_text),
        "legacy_def": (args.legacy_def, inspect_production_text),
        "bootstrap_def": (args.bootstrap_def, inspect_production_text),
        "probe_def": (args.probe_def, inspect_production_text),
    }
    report: dict[str, list[str]] = {}
    for label, (path, inspector) in requested.items():
        findings = _inspect_path(path, inspector)
        if findings:
            report[label] = findings
    if report:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print("100ed3c0 nonempty lifecycle static gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
