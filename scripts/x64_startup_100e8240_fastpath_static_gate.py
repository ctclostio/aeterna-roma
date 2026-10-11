#!/usr/bin/env python3
"""Fail-closed source/link gate for the bounded 0x100e8240 no-crash fast path."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


LIBRARY = "rome2_startup_100e8240_fastpath_runtime"
TEST_TARGET = "rome2_startup_100e8240_fastpath_tests"
HEADLESS = "rome2_headless64"
FUNCTION = "rome2_port_100e8240_crash_record_fastpath"
ROUTER_FUNCTION = "rome2_port_100e2460_run_router"
HANDLER_8D00_FUNCTION = "rome2_port_100e8d00_run_handler_transcript"
HANDLER_85D0_FUNCTION = "rome2_port_100e85d0_normal_adapter"
HANDLER_8580_FUNCTION = "rome2_port_100e8580_run_handler_transcript"
OUTER_FUNCTION = "rome2_port_100ea4d0_run_injected"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_CMAKE_ADD_TEST_COUNT = 192

EXPECTED_SHA256 = {
    "header": "4c76de0ab7388e73128d245f960f4678dfdbab3dd227807bcb9d9a8e549d535f",
    "source": "304fd049db8e07e637897c88d41b2bf69096ca66c0b31c038c54502f723cb620",
    "test": "cb4d6f4a30d3195247f9179f8cfb020220d01b944a0e92d32c078a086a62dbba",
    "headless": "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494",
}

BANNED_IDENTIFIERS = {
    "CreateProcessA",
    "CreateProcessW",
    "ExitProcess",
    "FreeLibrary",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "VirtualAlloc",
    "VirtualFree",
    "calloc",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "realloc",
}

# Excluded crash-handler/crash-file targets and crash-record data cells that
# the read-only fast path must never reference.
EXCLUDED_TOKENS = (
    "100ea4d0",
    "11683a32",
    "100f1bb0",
    "10120d90",
    "100e1050",
    "100f1cc0",
    "116838ea",
    "116839e8",
    "119f3a4c",
    "119f3a68",
    "119f3a90",
    "119f3a98",
    "119f3aad",
    "119f3aaf",
)

ALLOWED_SOURCE_CALLS = {
    "UINT32_C",
    "UINT64_C",
    "if",
    "rome2_100e8240_read_u32_le",
    "rome2_100e8240_signed_le",
    "rome2_100e8240_spans_overlap",
    FUNCTION,
    "return",
    "sizeof",
}

REQUIRED_SOURCE_FRAGMENTS = (
    "(first^UINT32_C(0x80000000))<=(second^UINT32_C(0x80000000));",
    "if(view==NULL||guest_record_out==NULL||view->host_base==NULL)"
    "{returnROME2_GUEST_BAD_ARGUMENT;}",
    "(uint64_t)view->guest_base+view->byte_count>"
    "ROME2_GUEST_ADDRESS_SPACE_SIZE",
    "view->byte_count-UINT64_C(1)>(uint64_t)(UINTPTR_MAX-host_address)",
    "sizeof(*guest_record_out)-1>UINTPTR_MAX-output_address",
    "sizeof(*view)-1>UINTPTR_MAX-view_address",
    "(uint64_t)(output_address-host_address)<view->byte_count",
    "output_address-view_address<sizeof(*view)",
    "(uint64_t)(view_address-host_address)<view->byte_count",
    "host_address-view_address<sizeof(*view)",
    "guest_tls_vector.value==0||guest_tls_index_cell.value==0"
    "||guest_threshold_cell.value==0",
    "guest_tls_index_cell.value<view->guest_base"
    "||guest_threshold_cell.value<view->guest_base",
    "index_offset>view->byte_count"
    "||ROME2_PORT_100E8240_CELL_BYTES>view->byte_count-index_offset"
    "||index_offset>(uint64_t)SIZE_MAX",
    "tls_index>ROME2_PORT_100E8240_MAX_TLS_INDEX",
    "slot_displacement=tls_index*UINT32_C(4);",
    "guest_tls_vector.value>UINT32_MAX-slot_displacement",
    "slot_guest=guest_tls_vector.value+slot_displacement;",
    "slot_guest<view->guest_base",
    "tls_data==0",
    "tls_data<view->guest_base",
    "tls_data>UINT32_MAX-UINT32_C(4)",
    "(uint64_t)tls_data+UINT64_C(4)-(uint64_t)view->guest_base",
    "if(rome2_100e8240_signed_le(threshold,tls_value))"
    "{guest_record_out->value=ROME2_PORT_100E8240_CRASH_RECORD;"
    "returnROME2_GUEST_OK;}"
    "returnROME2_GUEST_BAD_ARGUMENT;}",
)

TEST_CASE_LABELS = (
    "tls value above threshold",
    "tls value equal to threshold",
    "negative tls value above negative threshold",
    "nonzero tls index slot",
    "cross-sign signed accept",
    "excluded crash route rejected",
    "negative tls value below negative threshold rejected",
    "cross-sign signed reject",
    "null tls vector",
    "null tls index cell",
    "null threshold cell",
    "tls index cell below view",
    "threshold cell below view",
    "truncated tls index cell",
    "truncated threshold cell",
    "overlapping index and threshold cells",
    "tls index overflow rejected",
    "tls vector slot overflow rejected",
    "tls slot below view",
    "truncated tls slot cell",
    "tls slot aliases index cell",
    "tls slot aliases threshold cell",
    "null tls data",
    "tls data below view",
    "tls data overflow rejected",
    "truncated tls value cell",
    "tls value aliases index cell",
    "tls value aliases slot cell",
    "tls value aliases threshold cell",
    "guest view end overflow",
    "output aliases guest view",
    "output aliases view descriptor",
    "view descriptor aliases guest bytes",
    "guest bytes begin inside view descriptor",
    "host numeric range overflow",
    "null view",
    "null output",
    "null host base",
    "ROME2_PORT_100E8240_CRASH_RECORD",
)


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _decode(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def inspect_payload_text(label: str, text: str) -> list[str]:
    findings: list[str] = []
    if label == "headless" and len(text.encode("utf-8")) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless exact size changed")
    if _sha256(text) != EXPECTED_SHA256[label]:
        findings.append(f"{label} SHA-256 changed")
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)

    if label == "header":
        if compact.count(
            "#defineROME2_PORT_100E8240_CRASH_RECORDUINT32_C(0x119f3a38)"
        ) != 1:
            findings.append("crash-record identity changed")
        declaration = (
            "rome2_guest_status" + FUNCTION + "("
            "constrome2_guest_read_view*view,"
            "rome2_guest_addr32guest_tls_vector,"
            "rome2_guest_addr32guest_tls_index_cell,"
            "rome2_guest_addr32guest_threshold_cell,"
            "rome2_guest_addr32*guest_record_out);"
        )
        if compact.count(declaration) != 1:
            findings.append("exact fast-path declaration changed")
        includes = re.findall(
            r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, re.MULTILINE
        )
        if includes != ["guest32.h"]:
            findings.append("header must reuse only the guest read-view contract")
        if re.search(r"\b(?:uintptr_t|intptr_t|void\s*\*)\b", code):
            findings.append("public API exposes a native pointer-shaped scalar")
    elif label == "source":
        tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
        for token in sorted(tokens & BANNED_IDENTIFIERS):
            findings.append(f"forbidden platform/allocation identifier: {token}")
        for token in EXCLUDED_TOKENS:
            if token in code.lower():
                findings.append(f"excluded crash route is referenced: {token}")
        if re.search(r"\b(?:extern|volatile|__declspec)\b", code):
            findings.append("external/global/volatile/DLL storage is forbidden")
        if re.search(
            r"\([^)]*\*[^)]*\)\s*[^;\n]*guest_(?:tls_vector|tls_index_cell"
            r"|threshold_cell)\s*\.\s*value",
            code,
        ):
            findings.append("guest cell identity is cast to a native pointer")

        calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
        for call in sorted(calls - ALLOWED_SOURCE_CALLS):
            findings.append(f"unexpected source call expression: {call}")

        previous = -1
        for fragment in REQUIRED_SOURCE_FRAGMENTS:
            position = compact.find(fragment)
            if position < 0:
                findings.append(
                    f"required fast-path fragment changed: {fragment[:62]}"
                )
            elif position <= previous:
                findings.append("validation or commit order changed")
            previous = max(previous, position)
        if compact.count("rome2_100e8240_spans_overlap(") != 7:
            findings.append("pairwise-disjoint cell checks changed")
        if compact.count("guest_record_out->value=") != 1:
            findings.append("only the admitted fast path may write the output")
        if (
            compact.count(
                "if(rome2_100e8240_signed_le(threshold,tls_value))"
            ) != 1
        ):
            findings.append("signed branch direction changed")
    elif label == "test":
        for token in TEST_CASE_LABELS:
            if token not in text:
                findings.append(f"runtime reciprocal case missing: {token}")
        if FUNCTION not in code:
            findings.append("runtime test does not exercise the fast path")
    elif label == "headless":
        required_code = (
            "fastpath_tls_vector.value=ROME2_HEADLESS_FASTPATH_GUEST_BASE+"
            "ROME2_HEADLESS_FASTPATH_TLS_VECTOR_OFFSET;",
            "status=" + FUNCTION + "(&fastpath_view,fastpath_tls_vector,"
            "fastpath_index_cell,fastpath_threshold_cell,&fastpath_record);",
            "fastpath_record.value!=UINT32_C(0x119f3a38)",
        )
        for fragment in required_code:
            if compact.count(fragment) != 1:
                findings.append(
                    f"headless fast-path integration changed: {fragment[:62]}"
                )
        required_text = (
            '#include "ported_100e8240_fastpath.h"',
            '"crash-record=fast-path-no-crash;"',
            '"initializer-branch=preallocated-complete;"',
            '"initializer-capacity-zero=injected-complete;"',
            '"initializer-growth=injected-complete;"',
            '"initializer-router=injected-complete;"',
            '"initializer-handler-100e8d00=injected-transcript-complete;"',
            '"initializer-handler-100e85d0=effect-free-complete;"',
            '"initializer-handler-100e8580=injected-transcript-complete;"',
            '"initializer-100ea4d0=injected-complete;"',
            '"initializer-handler-100e9340=injected-transcript-complete;"',
            '"initializer-handler-100e92c0=injected-transcript-complete;"',
            '"initializer-handler-100e87a0=injected-transcript-complete;"',
            '"startup-100df270-suffix=injected-transcript-complete;"',
            '"startup-100df270-platform-prefix=injected-call-shape-complete;"',
            '"startup-100ed3c0-empty-preloop=injected-composition-complete;"',
            '"startup-100ed471-ordinary-lifecycle=injected-bounded-complete;"',
            '"platform-effects=not-run;"',
            '"allocator=injected-4-byte;native-allocator=not-run;"',
            '"growth-allocator=injected-16-byte;"',
            '"growth-release=injected-old-backing;native-release=not-run;"',
            '"initializer-dispatch=injected-complete;"',
            '"queue-drain=injected-bounded-complete;gameplay=not-linked\\n"',
        )
        for fragment in required_text:
            if text.count(fragment) != 1:
                findings.append(
                    f"headless fast-path integration changed: {fragment[:62]}"
                )
        for function, count in (
            (ROUTER_FUNCTION, 1),
            (HANDLER_8D00_FUNCTION, 2),
            (HANDLER_85D0_FUNCTION, 2),
            (HANDLER_8580_FUNCTION, 2),
            (OUTER_FUNCTION, 1),
            ("rome2_port_100e9340_run_handler_transcript", 2),
            ("rome2_port_100e92c0_run_handler_transcript", 2),
            ("rome2_port_100e87a0_run_handler_transcript", 2),
            ("rome2_port_100df270_run_suffix_transcript", 0),
            ("rome2_port_100df270_run_platform_prefix_transcript", 0),
            (PARENT_FUNCTION, 1),
            (LIFECYCLE_FUNCTION, 1),
        ):
            if code.count(function + "(") != count:
                findings.append(
                    "headless successor call-site count changed: "
                    f"{function} != {count}"
                )

    if label != "test":
        if re.search(r"^\s*#\s*pragma\b", code, re.MULTILINE):
            findings.append("pragma or warning suppression is forbidden")
        if re.search(r"\b(?:dllexport|dllimport)\b", code, re.I):
            findings.append("DLL annotation is forbidden")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, re.I):
            stack.append(
                (index, bool(re.match(r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, re.I)))
            )
        elif re.match(r"endif(?:\s*\([^)]*\))?\s*$", stripped, re.I):
            if not stack:
                return None
            start, selected = stack.pop()
            if selected:
                return start, index
    return None


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    if len(re.findall(r"\badd_test\s*\(", text)) != EXPECTED_CMAKE_ADD_TEST_COUNT:
        findings.append("CMake add_test declaration count must remain 192")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped = (
        LIBRARY,
        TEST_TARGET,
        "ported_100e8240_fastpath.h",
        "ported_100e8240_fastpath.c",
        "test_startup_100e8240_fastpath.c",
        "startup_100e8240_fastpath_provenance",
        "startup_100e8240_fastpath_static_gate",
        "startup_100e8240_fastpath_runtime",
        "startup_100e8240_fastpath_post_pe_gate",
        "x64_bootstrap_load_after_startup_100e8240_fastpath",
        "startup_100ea4d0_evidence_provenance",
    )
    for token in scoped:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake token missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake token escapes BUILD_TESTING: {token}")

    compact = _compact("\n".join(lines[start + 1 : end]))
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("fast-path port must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("fast-path library must not be shared")
    static_gate_routes = [
        command
        for command in re.findall(r"add_test\s*\((.*?)\)", text, re.I | re.S)
        if re.search(
            r"\bNAME\s+startup_100e8240_fastpath_static_gate\b",
            command,
            re.I,
        )
    ]
    if (
        len(static_gate_routes) != 1
        or '--headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"'
            not in static_gate_routes[0]
    ):
        findings.append("headless integration is not routed through the static gate")
    expected_headless = (
        f"target_link_libraries({HEADLESS}PRIVATE"
        "rome2_guest32_runtime"
        "rome2_startup_100f1aa0_empty_runtime"
        "rome2_startup_safe_seams_runtime"
        "rome2_startup_100df270_headless_runtime"
        "rome2_startup_100f2750_nonalloc_runtime"
        f"{LIBRARY}"
        "rome2_startup_100e2460_append_prefix_runtime"
        "rome2_startup_100e2460_preallocated_branch_runtime"
        "rome2_startup_100e2460_capacity_zero_branch_runtime"
        "rome2_startup_100e2460_growth_branch_runtime"
        "rome2_startup_100e2460_router_runtime"
        "rome2_startup_100e8d00_handler_transcript_runtime"
        "rome2_startup_100e85d0_normal_adapter_runtime"
        "rome2_startup_100e8580_handler_transcript_runtime"
        "rome2_startup_100ea4d0_injected_runtime"
        "rome2_startup_100e9340_handler_transcript_runtime"
        "rome2_startup_100e92c0_handler_transcript_runtime"
        "rome2_startup_100e87a0_handler_transcript_runtime"
        "rome2_startup_100df270_suffix_transcript_runtime"
        "rome2_startup_100df270_platform_prefix_transcript_runtime"
        f"{PARENT_LIBRARY}"
        f"{LIFECYCLE_LIBRARY})"
    )
    if expected_headless not in compact:
        findings.append("headless composition differs from the admitted slices")

    links = [
        _compact(command)
        for command in re.findall(
            r"target_link_libraries\s*\((.*?)\)", text, re.I | re.S
        )
        if LIBRARY in command
    ]
    expected_links = {
        f"{LIBRARY}PRIVATErome2_guest32_runtime",
        f"{TEST_TARGET}PRIVATE{LIBRARY}",
        (
            f"{HEADLESS}PRIVATErome2_guest32_runtime"
            "rome2_startup_100f1aa0_empty_runtime"
            "rome2_startup_safe_seams_runtime"
            "rome2_startup_100df270_headless_runtime"
            "rome2_startup_100f2750_nonalloc_runtime"
            f"{LIBRARY}"
            "rome2_startup_100e2460_append_prefix_runtime"
            "rome2_startup_100e2460_preallocated_branch_runtime"
            "rome2_startup_100e2460_capacity_zero_branch_runtime"
            "rome2_startup_100e2460_growth_branch_runtime"
            "rome2_startup_100e2460_router_runtime"
            "rome2_startup_100e8d00_handler_transcript_runtime"
            "rome2_startup_100e85d0_normal_adapter_runtime"
            "rome2_startup_100e8580_handler_transcript_runtime"
            "rome2_startup_100ea4d0_injected_runtime"
            "rome2_startup_100e9340_handler_transcript_runtime"
            "rome2_startup_100e92c0_handler_transcript_runtime"
            "rome2_startup_100e87a0_handler_transcript_runtime"
            "rome2_startup_100df270_suffix_transcript_runtime"
            "rome2_startup_100df270_platform_prefix_transcript_runtime"
            f"{PARENT_LIBRARY}"
            f"{LIFECYCLE_LIBRARY}"
        ),
    }
    if set(links) != expected_links or len(links) != len(expected_links):
        findings.append("fast-path port has an unexpected consumer or dependency")
    for command in links:
        if any(
            target in command
            for target in (
                "empire_retail_bootstrap",
                "empire_bootstrap_smoke",
                "rome2_guest32_probe",
            )
        ):
            findings.append("fast-path port escaped into production/probe linkage")

    expected_fixture_fragments = (
        (
            "add_test(NAMEstartup_100e8240_fastpath_post_pe_gateCOMMAND"
            "Python3::Interpreter-B"
            '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'x64_entry_policy_probe_pe_gate_v2.py"'
            '--dll"$<TARGET_FILE:rome2_guest32_probe>"'
            '--host"$<TARGET_FILE:rome2_guest32_probe_host>"'
            '--bootstrap-dll"$<TARGET_FILE:empire_retail_bootstrap>"'
            '--bootstrap-host"$<TARGET_FILE:empire_bootstrap_smoke>")'
        ),
        (
            "add_test(NAMEx64_bootstrap_load_after_startup_100e8240_fastpath"
            'COMMAND"$<TARGET_FILE:empire_bootstrap_smoke>"'
            '"$<TARGET_FILE:empire_retail_bootstrap>")'
        ),
        (
            "set_tests_properties(startup_100e8240_fastpath_runtimePROPERTIES"
            "FIXTURES_REQUIRED"
            '"startup_100f2750_nonalloc_post_verified;'
            "startup_100e8240_fastpath_provenance_verified;"
            "startup_100ea4d0_evidence_verified;"
            'startup_100e8240_fastpath_static_verified"'
            "FIXTURES_SETUPstartup_100e8240_fastpath_runtime_verifiedTIMEOUT90)"
        ),
        (
            "set_tests_properties(startup_100e8240_fastpath_post_pe_gate"
            "PROPERTIESFIXTURES_REQUIRED"
            '"startup_100e8240_fastpath_runtime_verified;'
            'entry_policy_probe_pe_tool_verified"'
            "FIXTURES_SETUPstartup_100e8240_fastpath_post_verified)"
        ),
        (
            "set_tests_properties("
            "x64_bootstrap_load_after_startup_100e8240_fastpathPROPERTIES"
            "FIXTURES_REQUIRED"
            '"x64_bootstrap_pre_verified;'
            'startup_100e8240_fastpath_post_verified"'
            "FIXTURES_SETUPstartup_100e8240_fastpath_reload_verified)"
        ),
        (
            "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
            "FIXTURES_REQUIRED"
            '"entry_policy_provenance_verified;entry_policy_static_verified;'
            'startup_100ed471_ordinary_lifecycle_reload_verified"'
            "TIMEOUT90)"
        ),
    )
    for fragment in expected_fixture_fragments:
        if compact.count(fragment) != 1:
            findings.append(
                "fast-path lifecycle fixture or post-build route changed"
            )
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (FUNCTION.lower(), LIBRARY.lower(), "ported_100e8240_fastpath"):
        if token in lowered:
            findings.append(f"test-only fast-path port escaped into exports: {token}")
    return sorted(set(findings))


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
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, path, inspector in (
        ("header", args.header, lambda text: inspect_payload_text("header", text)),
        ("source", args.source, lambda text: inspect_payload_text("source", text)),
        ("test", args.test, lambda text: inspect_payload_text("test", text)),
        (
            "headless",
            args.headless,
            lambda text: inspect_payload_text("headless", text),
        ),
        ("cmake", args.cmake, inspect_cmake_text),
        ("export_manifest", args.export_manifest, inspect_exports_text),
        ("legacy_def", args.legacy_def, inspect_exports_text),
        ("probe_def", args.probe_def, inspect_exports_text),
    ):
        text, findings = _decode(path.resolve(strict=True))
        if text is not None:
            findings.extend(inspector(text))
        findings = sorted(set(findings))
        total += len(findings)
        report["files"][label] = {
            "path": str(path.resolve()),
            "findings": findings,
        }
    if total:
        report["status"] = "fail"
    report["finding_count"] = total
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "fail", "error": str(error)}, sort_keys=True))
        raise SystemExit(2)
