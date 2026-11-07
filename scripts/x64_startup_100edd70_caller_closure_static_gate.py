#!/usr/bin/env python3
"""Fail-closed static gate for the exact 0x100edd70 caller closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100edd70_run_caller_closure"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_nonempty_lifecycle"
SELECTOR_FUNCTION = "rome2_port_100edd70_select_invalid_parameter_policy"
LIBRARY = "rome2_startup_100edd70_caller_closure_runtime"
TEST_TARGET = "rome2_startup_100edd70_caller_closure_tests"
PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_lifecycle_runtime"
PARENT_TEST_TARGET = "rome2_startup_100ed3c0_nonempty_lifecycle_tests"
ENTRY_LIBRARY = "rome2_startup_100edd70_entry_decision_runtime"
EXPECTED_CTEST_COUNT = 194

EXPECTED_HEADER = (
    6_200, "5b5487efdeafeb2685c020853a12c90c438b776697baab752a5f06bcc5024490"
)
EXPECTED_SOURCE = (
    24_737, "26f9c039697975a6a65924287a02126939479d2d3e77ae0758b948a804151340"
)
EXPECTED_TEST = (
    77_077, "846111a16d24999bf546dc289ef7a38e58fc1a6deda1b874eb5361c7a3c76191"
)
EXPECTED_PROVENANCE = (
    12_320, "cd31bfd55e5fc138f2ef1f78983b354fcff971d8a1cc814ef260509be8bd9ae1"
)
EXPECTED_DOC = (
    7_356, "61018245756ff1b25ffd8eade08c4cfeba5eb44bf4ce258c4acfa493081664e3"
)
EXPECTED_CMAKE = (
    185_731, "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

CMAKE_FILES = (
    "ported_100edd70_caller_closure.h",
    "ported_100edd70_caller_closure.c",
    "test_startup_100edd70_caller_closure.c",
    "test_x64_startup_100edd70_caller_closure_provenance.py",
    "test_x64_startup_100edd70_caller_closure_static_gate.py",
    "x64_startup_100edd70_caller_closure_static_gate.py",
    "x64_startup_100edd70_caller_closure.md",
)
CMAKE_TESTS = (
    "startup_100edd70_caller_closure_provenance",
    "startup_100edd70_caller_closure_static_gate_unit",
    "startup_100edd70_caller_closure_static_gate",
    "startup_100edd70_caller_closure_runtime",
    "startup_100edd70_caller_closure_post_pe_gate",
    "x64_bootstrap_load_after_startup_100edd70_caller_closure",
)

BANNED_IDENTIFIERS = {
    "CoUninitialize", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetProcAddress", "GetProcessHeap", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "TerminateProcess",
    "VirtualAlloc", "VirtualFree", "_atexit", "_onexit", "atexit",
    "calloc", "dlopen", "dlsym", "free", "malloc", "realloc", "system",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _check_exact(
    text: str, expected: tuple[int, str], label: str, findings: list[str]
) -> None:
    data = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    if len(data) != expected[0]:
        findings.append(f"{label} byte count changed")
    if _sha256(data) != expected[1]:
        findings.append(f"{label} SHA-256 changed")


def _call_count(code: str, name: str) -> int:
    return len(re.findall(rf"\b{re.escape(name)}\s*\(", code))


def _require_order(
    text: str, tokens: tuple[str, ...], findings: list[str], message: str
) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            findings.append(message)
            return
        cursor = position + len(token)


def inspect_header_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_HEADER, "header", findings)
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)
    required = (
        "ROME2_PORT_100EDD70_HANDLER_WINDOW_START_PCUINT32_C(0x100edf20)",
        "ROME2_PORT_100EDD70_HANDLER_HARD_STOP_PCUINT32_C(0x100edf41)",
        "ROME2_PORT_100EDD70_SKIP_WINDOW_START_PCUINT32_C(0x100edf73)",
        "ROME2_PORT_100EDD70_SKIP_HARD_STOP_PCUINT32_C(0x100edf94)",
        "ROME2_PORT_100EDD70_KEEPER_BYTE_TARGETUINT32_C(0x101136d0)",
        "ROME2_PORT_100EDD70_KEEPER_DWORD_TARGETUINT32_C(0x101150f0)",
        "ROME2_PORT_100EDD70_KEEPER_BYTE_VALUEUINT32_C(1)",
        "ROME2_PORT_100EDD70_KEEPER_DWORD_VALUEUINT32_C(0x100d6560)",
        "ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTESUINT32_C(24)",
        "ROME2_PORT_100EDD70_CONTINUATION_STEP_COUNTUINT32_C(3)",
        "rome2_100ed3c0_nonempty_lifecycle_resultparent;",
        "rome2_100edd70_caller_pushpushes[ROME2_PORT_100EDD70_CALLER_PUSH_COUNT];",
    )
    for token in required:
        if compact.count(token) != 1:
            findings.append(f"header caller contract changed: {token}")
    if _call_count(code, FUNCTION) != 1:
        findings.append("header must declare exactly one caller-closure API")
    contract = _compact(re.sub(r"[*/]", "", text))
    for token in (
        "thirteen-control,seven-backing,seven-context",
        "parentisinvokedexactlyonce",
        "nocontinuationeventisemitted",
        "combinedresultonceandlast",
        "noguestnativepointercast",
    ):
        if token not in contract:
            findings.append(f"header transaction contract changed: {token}")
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_SOURCE, "source", findings)
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)
    for identifier in BANNED_IDENTIFIERS:
        if re.search(rf"\b{re.escape(identifier)}\b", code):
            findings.append(f"forbidden native identifier: {identifier}")
    if re.search(r"\b(?:decomp_fn_|FUN_|DAT_)[A-Za-z0-9_]*", code):
        findings.append("recovered/original identifier escaped into source")
    if _call_count(code, PARENT_FUNCTION) != 1:
        findings.append("parent must be called exactly once")
    if _call_count(code, SELECTOR_FUNCTION) != 0:
        findings.append("caller closure must not invoke the selector")
    for token, message in (
        ("#defineROME2_100EDD70_CLOSURE_CONTROL_COUNT13U",
         "exact thirteen-control universe changed"),
        ("#defineROME2_100EDD70_CLOSURE_BACKING_COUNT7U",
         "exact seven-backing universe changed"),
        ("#defineROME2_100EDD70_CLOSURE_CONTEXT_COUNT7U",
         "exact seven-context universe changed"),
        ("state.parent_effects=*parent_effects;", "parent effects snapshot changed"),
        ("state.continuation_effects=*continuation_effects;",
         "continuation effects snapshot changed"),
        ("contexts[first].start!=contexts[second].start||",
         "identical-or-disjoint context rule changed"),
        ("temporary_owner->phase!=ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED",
         "temporary ownership seam changed"),
        ("persistent_owner->phase!=ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
         "persistent ownership seam changed"),
        ("*result_out=state.combined_result;", "result-last commit changed"),
    ):
        if compact.count(token) != 1:
            findings.append(message)
    if compact.count("state.continuation_effects.emit_step(") != 3:
        findings.append("continuation must emit exactly three steps")
    if compact.count("*result_out=state.combined_result;") != 1 or "result_out->" in code:
        findings.append("combined result must commit exactly once")
    _require_order(
        code,
        (
            "state.parent_effects = *parent_effects;",
            "state.continuation_effects = *continuation_effects;",
            "status = rome2_port_100ed3c0_run_nonempty_lifecycle(",
            "ROME2_100EDD70_CALLER_STEP_KEEPER_BYTE_STORE",
            "ROME2_100EDD70_CALLER_STEP_KEEPER_DWORD_STORE",
            "ROME2_100EDD70_CALLER_STEP_CLEANUP_24",
            "*result_out = state.combined_result;",
        ),
        findings,
        "snapshot, parent, keepers, cleanup, result order changed",
    )
    if re.search(
        r"\([^)]*\*\)\s*(?:guest_frame|dispatch_receiver|"
        r"caller_position3_text)(?:\.value)?\b",
        code,
    ):
        findings.append("guest/native pointer cast found")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_TEST, "runtime", findings)
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(text)
    required = (
        ("#defineTEST_EXPECTED_CASESUINT32_C(54)", "runtime must retain 54 cases"),
        ("expected_count==UINT32_C(45)+fixture->trace.expected_poll_count",
         "45+P event formula changed"),
        ('"handlercallerpacket"', "handler policy success is missing"),
        ('"skip-handlercallerpacket"', "skip policy success is missing"),
        ('"maximumpolltranscript"', "P=64 success is missing"),
        ('"combinedeffectssnapshot"', "snapshot mutation adversary is missing"),
        ("failed|=test_tier0_cases();", "parent Tier-0 registry changed"),
        ("failed|=test_caller_tier0_cases();", "caller Tier-0 registry changed"),
        ("failed|=test_effect_failures();", "prefix-failure registry changed"),
        ("failed|=test_teardown_cases();", "teardown registry changed"),
        ('"invalidpolicy"', "invalid policy rejection is missing"),
        ('"partialcontinuationcontextoverlap"', "partial context case is missing"),
        ('"continuationcontextoverlapsresult"', "context/result case is missing"),
        ('"nullresult"', "null-result case is missing"),
        ("test_case_count==TEST_EXPECTED_CASES", "case registry assertion changed"),
    )
    for token, message in required:
        if token not in compact:
            findings.append(message)
    for identifier in BANNED_IDENTIFIERS:
        if re.search(rf"\b{re.escape(identifier)}\b", code):
            findings.append(f"forbidden native identifier in runtime: {identifier}")
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_PROVENANCE, "provenance", findings)
    compact = _compact(text)
    for token in (
        '"start":0x100EDF20', '"start":0x100EDF73',
        '0x101136D0:', '0x101150F0:', '0x100EDF05:',
        '0x100EDF41:', '0x100EDF94:', '0x100D6560:',
        "test_both_windows_calls_continuations_and_cleanup_are_exact",
        "test_keeper_leaves_and_rel32_targets_are_exact",
        "test_excluded_registration_epilogues_and_guard_node_are_pinned",
        "test_frozen_children_and_new_artifacts_are_one_snapshot",
        "test_reciprocal_window_and_authority_mutants_fail",
        "test_oracle_is_standard_library_only_and_read_only",
    ):
        if token not in compact:
            findings.append(f"provenance authority changed: {token}")
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC, "doc", findings)
    compact = _compact(text)
    for token in (
        "[0x100edf20,0x100edf41)", "[0x100edf73,0x100edf94)",
        "exact400-byteparent", "thirteen-control,seven-backing,seven-context",
        "calledexactlyonce", "exactlythreeby-valuesteps", "45+P",
        "exactly54cases", "STATICEXCLUDE_FROM_ALL", "180to186",
        "notlinkedintoeitherproductionDLLortheheadlessexecutable",
    ):
        if token not in compact:
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
            start, is_testing = stack.pop()
            if is_testing:
                found.append((start, index))
    if stack or len(found) != 1:
        return None
    return found[0]


def _link_commands(text: str) -> list[list[str]]:
    commands = re.findall(r"target_link_libraries\s*\((.*?)\)", text, re.I | re.S)
    return [re.split(r"\s+", command.strip()) for command in commands]


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_CMAKE, "CMake", findings)
    if len(re.findall(r"^\s*add_test\s*\(", text, re.I | re.M)) != EXPECTED_CTEST_COUNT:
        findings.append("CMake must contain exactly 194 CTests")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        findings.append("one balanced if(BUILD_TESTING) block is required")
        return sorted(set(findings))
    start, end = bounds
    for token in (*CMAKE_FILES, *CMAKE_TESTS, LIBRARY, TEST_TARGET):
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake caller-closure token missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake caller-closure token escapes BUILD_TESTING: {token}")
    scoped = _compact("\n".join(lines[start + 1:end]))
    for token, message in (
        (f"add_library({LIBRARY}STATICEXCLUDE_FROM_ALL",
         "caller library must be static, excluded, and test-only"),
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "caller library C17 contract changed"),
        (f"target_compile_options({LIBRARY}PRIVATE${{ROME2_HARDENED_COMPILE_OPTIONS}})",
         "caller hardened compile options changed"),
        (f"target_link_libraries({LIBRARY}PUBLICrome2_guest32_runtimePRIVATE{PARENT_LIBRARY})",
         "caller parent dependency changed"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "caller test dependency changed"),
        ("FIXTURES_SETUPstartup_100edd70_caller_closure_reload_verified",
         "caller fixture chain changed"),
    ):
        if token not in scoped:
            findings.append(message)
    commands = _link_commands(text)
    binder_consumers = {
        command[0] for command in commands if LIBRARY in command[1:]
    }
    if binder_consumers != {TEST_TARGET, ENTRY_LIBRARY}:
        findings.append("caller library must have exactly two test-only consumers")
    parent_consumers = {
        command[0] for command in commands if PARENT_LIBRARY in command[1:]
    }
    if parent_consumers != {PARENT_TEST_TARGET, LIBRARY}:
        findings.append("whole parent must have exactly two test-only consumers")
    return sorted(set(findings))


def inspect_production_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), TEST_TARGET.lower(),
        "100edd70_caller_closure", "100edd70-caller-closure",
    ):
        if token in lowered:
            findings.append(f"test-only caller-closure token escaped production: {token}")
    return sorted(set(findings))


def _decode(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _inspect(path: pathlib.Path, inspector) -> list[str]:
    text, findings = _decode(path)
    return findings if text is None else inspector(text)


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
    report = {}
    for label, (path, inspector) in requested.items():
        findings = _inspect(path, inspector)
        if findings:
            report[label] = findings
    if report:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print("100edd70 caller closure static gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
