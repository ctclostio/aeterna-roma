#!/usr/bin/env python3
"""Fail-closed static gate for the exact 0x100edd70 entry decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100edd70_run_selected_route"
SELECTOR_FUNCTION = "rome2_port_100edd70_select_invalid_parameter_policy"
CHILD_FUNCTION = "rome2_port_100edd70_run_caller_closure"
LIBRARY = "rome2_startup_100edd70_entry_decision_runtime"
TEST_TARGET = "rome2_startup_100edd70_entry_decision_tests"
CHILD_LIBRARY = "rome2_startup_100edd70_caller_closure_runtime"
CHILD_TEST_TARGET = "rome2_startup_100edd70_caller_closure_tests"
EXPECTED_CTEST_COUNT = 194

EXPECTED_HEADER = (
    5_103, "64b9204fbe3bc11d81c5a15c8faec5b3e3e737e5c926cd40bf9b309bd472995d"
)
EXPECTED_SOURCE = (
    27_463, "d4cd6f3633cee6ef3584787bf8e609fb6dcf4a1156d957924d49076788f419db"
)
EXPECTED_TEST = (
    35_819, "edb849e2fa7d1a4e2acc5d89b2a65a57d6200fa4bcb193403fddb523486e7a60"
)
EXPECTED_PROVENANCE = (
    17_721, "0b153a839a67b7ce7bc23ba0e93abedc3c8c5426b41b97c11141573453a4b023"
)
EXPECTED_DOC = (
    6_927, "5d6389deb0619adbad84c8351be53c75f57f98e466307961eb68e2a13ad3738d"
)
EXPECTED_CMAKE = (
    185_731, "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

CMAKE_FILES = (
    "ported_100edd70_entry_decision.h",
    "ported_100edd70_entry_decision.c",
    "test_startup_100edd70_entry_decision.c",
    "test_x64_startup_100edd70_entry_decision_provenance.py",
    "test_x64_startup_100edd70_entry_decision_static_gate.py",
    "x64_startup_100edd70_entry_decision_static_gate.py",
    "x64_startup_100edd70_entry_decision.md",
)
CMAKE_TESTS = (
    "startup_100edd70_entry_decision_provenance",
    "startup_100edd70_entry_decision_static_gate_unit",
    "startup_100edd70_entry_decision_static_gate",
    "startup_100edd70_entry_decision_runtime",
    "startup_100edd70_entry_decision_post_pe_gate",
    "x64_bootstrap_load_after_startup_100edd70_entry_decision",
)

BANNED_IDENTIFIERS = {
    "CoUninitialize", "CreateProcessA", "CreateProcessW", "ExitProcess",
    "FreeLibrary", "GetProcAddress", "GetProcessHeap", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "RaiseException",
    "TerminateProcess", "VirtualAlloc", "VirtualFree",
    "__set_invalid_parameter_handler", "_atexit", "_onexit", "atexit",
    "calloc", "dlopen", "dlsym", "free", "malloc", "realloc", "system",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact(text: str) -> str:
    return "".join(text.split())


def _check_exact(
    text: str, expected: tuple[int, str], label: str, findings: list[str]
) -> None:
    data = text.encode("utf-8")
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
        "ROME2_PORT_100EDD70_SELECTOR_START_PCUINT32_C(0x100edecc)",
        "ROME2_PORT_100EDD70_SELECTOR_END_PCUINT32_C(0x100edf05)",
        "ROME2_PORT_100EDD70_REGISTRATION_START_PCUINT32_C(0x100edf05)",
        "ROME2_PORT_100EDD70_REGISTRATION_END_PCUINT32_C(0x100edf20)",
        "ROME2_PORT_100EDD70_REGISTRATION_PUSH_PCUINT32_C(0x100edf05)",
        "ROME2_PORT_100EDD70_REGISTRATION_CALL_PCUINT32_C(0x100edf0a)",
        "ROME2_PORT_100EDD70_REGISTRATION_CALLEE_PCUINT32_C(0x11687a4a)",
        "ROME2_PORT_100EDD70_REGISTRATION_HANDLER_ARGUMENTUINT32_C(0x100ee5d0)",
        "ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_PCUINT32_C(0x100edf0f)",
        "ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20_PCUINT32_C(0x100edf12)",
        "ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04_PCUINT32_C(0x100edf19)",
        "ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNTUINT32_C(4)",
        "rome2_100edd70_caller_closure_resultchild;",
    )
    for token in required:
        if compact.count(token) != 1:
            findings.append(f"header entry-decision contract changed: {token}")
    if _call_count(code, FUNCTION) != 1:
        findings.append("header must declare exactly one selected-route API")
    if re.search(r"\bcommand_line\b", code):
        findings.append("the selector identity must be structural, not redundant")
    contract = _compact(text.replace("*", "").replace("/", ""))
    for token in (
        "fourteen-control,seven-backing,eight-context",
        "statefulpass-throughcontrols",
        "faithfulcommittedprefixwithoutrollback",
        "combinedresultonceandlast",
        "Neither0x11687a4anor0x100ee5d0isexecuted",
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
    if _call_count(code, SELECTOR_FUNCTION) != 1:
        findings.append("selector must be called exactly once")
    if _call_count(code, CHILD_FUNCTION) != 1:
        findings.append("caller closure must be called exactly once")
    required = (
        ("#defineROME2_100EDD70_ENTRY_CONTROL_COUNT14U",
         "exact fourteen-control universe changed"),
        ("#defineROME2_100EDD70_ENTRY_BACKING_COUNT7U",
         "exact seven-backing universe changed"),
        ("#defineROME2_100EDD70_ENTRY_CONTEXT_COUNT8U",
         "exact eight-context universe changed"),
        ("state.parent_effects=*parent_effects;", "parent snapshot changed"),
        ("state.continuation_effects=*continuation_effects;",
         "continuation snapshot changed"),
        ("state.registration_effects=*registration_effects;",
         "registration snapshot changed"),
        ("contexts[first].start!=contexts[second].start||",
         "identical-or-disjoint context rule changed"),
        ("status=rome2_100edd70_entry_validate_ownership_prestate(",
         "ownership preflight changed"),
        ("state.registration[0]=rome2_100edd70_entry_make_step(",
         "registration call record changed"),
        ("state.registration[1]=rome2_100edd70_entry_make_step(",
         "registration cleanup record changed"),
        ("state.registration[2]=rome2_100edd70_entry_make_step(",
         "first registration store changed"),
        ("state.registration[3]=rome2_100edd70_entry_make_step(",
         "second registration store changed"),
        ("*result_out=state.combined_result;", "result-last commit changed"),
    )
    for token, message in required:
        if compact.count(token) != 1:
            findings.append(message)
    if compact.count("*result_out=state.combined_result;") != 1 or "result_out->" in code:
        findings.append("combined result must commit exactly once")
    if "command_line" in code:
        findings.append("redundant command-line input escaped into source")
    _require_order(
        code,
        (
            "state.registration_effects = *registration_effects;",
            "guest_status = rome2_port_100edd70_select_invalid_parameter_policy(",
            "state.registration[0] = rome2_100edd70_entry_make_step(",
            "state.registration_effects.emit_step(",
            "status = rome2_port_100edd70_run_caller_closure(",
            "state.combined_result.child = state.child_result;",
            "*result_out = state.combined_result;",
        ),
        findings,
        "snapshot, selector, registration, child, result order changed",
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
        ("#defineENTRY_TEST_EXPECTED_CASESUINT32_C(44)",
         "runtime must retain 44 outer cases"),
        ("expected_count==UINT32_C(45)+poll_count+registration_count",
         "45+P+R event formula changed"),
        ('"skipP1"', "skip P=1 case is missing"),
        ('"skipP3"', "skip P=3 case is missing"),
        ('"skipP64"', "skip P=64 case is missing"),
        ('"installP1"', "install P=1 case is missing"),
        ('"installP3"', "install P=3 case is missing"),
        ('"installP64"', "install P=64 case is missing"),
        ('"registrationeffectssnapshot"', "registration mutation case is missing"),
        ('"childeffectssnapshotthroughroute"', "child mutation case is missing"),
        ('"installF1temporarydenial"', "F1 prefix case is missing"),
        ('"installF5tokencollision"', "F5 prefix case is missing"),
        ('"skipF1temporarydenial"', "skip prefix case is missing"),
        ('"installcommitted-prefixchilddenial"',
         "deterministic child-prefix case is missing"),
        ('"identicalsharedrecorder"', "identical context case is missing"),
        ('"registrationcontextoverlapsresult"', "context/control case is missing"),
        ("entry_case_count==ENTRY_TEST_EXPECTED_CASES",
         "outer case registry assertion changed"),
        ("failed=rome2_caller_closure_regression_main();",
         "admitted child regression reuse changed"),
    )
    for token, message in required:
        if token not in compact:
            findings.append(message)
    return sorted(set(findings))


def inspect_provenance_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_PROVENANCE, "provenance", findings)
    compact = _compact(text)
    for token in (
        "0x100EDF05", 'bytes.fromhex("83c404")',
        "0x100EDF12", "0x100EDF19", "0x11687A4A", "0x100EE5D0",
        "test_selector_and_registration_control_flow_are_exact",
        "test_registration_callee_and_handler_identity_are_inert_and_exact",
        "test_excluded_tails_converge_only_on_the_common_epilogue",
        "test_admitted_selector_and_caller_snapshots_are_exact",
        "test_reciprocal_evidence_mutants_fail_and_oracle_is_read_only",
    ):
        if token not in compact:
            findings.append(f"provenance authority changed: {token}")
    return sorted(set(findings))


def inspect_doc_text(text: str) -> list[str]:
    findings: list[str] = []
    _check_exact(text, EXPECTED_DOC, "doc", findings)
    compact = _compact(text)
    for token in (
        "[0x100edecc,0x100edf05)", "[0x100edf05,0x100edf20)",
        "[0x100edf20,0x100edf41)", "[0x100edf73,0x100edf94)",
        "fourteencontrols", "sevenpairwisehost-and-guest-disjointbackingintervals",
        "eightcallbackcontextspans", "45+P", "49+P", "50|52|113",
        "12/13/24/25/24", "exactly44cases", "from186to194",
        "STATICEXCLUDE_FROM_ALL", "assignedexactlyonceandlast",
        "DONE-20260901-selector-to-caller-route",
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
            findings.append(f"CMake entry-decision token missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake entry-decision token escapes BUILD_TESTING: {token}")
    scoped = _compact("\n".join(lines[start + 1:end]))
    for token, message in (
        (f"add_library({LIBRARY}STATICEXCLUDE_FROM_ALL",
         "entry library must be static, excluded, and test-only"),
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "entry library C17 contract changed"),
        (f"target_compile_options({LIBRARY}PRIVATE${{ROME2_HARDENED_COMPILE_OPTIONS}})",
         "entry hardened compile options changed"),
        (f"target_link_libraries({LIBRARY}PUBLICrome2_guest32_runtimePRIVATE{CHILD_LIBRARY})",
         "entry child dependency changed"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "entry test dependency changed"),
        ("FIXTURES_SETUPstartup_100edd70_entry_decision_reload_verified",
         "entry fixture chain changed"),
    ):
        if token not in scoped:
            findings.append(message)
    commands = _link_commands(text)
    entry_consumers = {command[0] for command in commands if LIBRARY in command[1:]}
    if entry_consumers != {TEST_TARGET}:
        findings.append("entry library must have exactly one test consumer")
    child_consumers = {
        command[0] for command in commands if CHILD_LIBRARY in command[1:]
    }
    if child_consumers != {CHILD_TEST_TARGET, LIBRARY}:
        findings.append("caller closure must have exactly two test-only consumers")
    return sorted(set(findings))


def inspect_production_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), TEST_TARGET.lower(),
        "100edd70_entry_decision", "100edd70-entry-decision",
    ):
        if token in lowered:
            findings.append(f"test-only entry-decision token escaped production: {token}")
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
    print("100edd70 entry decision static gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
