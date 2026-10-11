#!/usr/bin/env python3
"""Fail-closed source/link gate for the bounded 0x100f2750 short-copy slice."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


LIBRARY = "rome2_startup_100f2750_nonalloc_runtime"
TEST_TARGET = "rome2_startup_100f2750_nonalloc_tests"
HEADLESS = "rome2_headless64"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
FUNCTION = "rome2_port_100f2750_copy_nonallocating_short"
EXPECTED_CMAKE_ADD_TEST_COUNT = 192

EXPECTED_SHA256 = {
    "header": "eb3b0ae844a4607367c26359f7ef6bb851f79560ad80a255a7410da82367e1b9",
    "source": "be39db3e950abd07d38197f2faf8659deaac30515bcc5b33e19a95c4ca1ec11a",
    "test": "5153624a2d22aa251abd5a7c09376e770185aa65920ab80cc1b316e4202a0769",
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

ALLOWED_SOURCE_CALLS = {
    "UINT64_C",
    "for",
    "if",
    FUNCTION,
    "rome2_100f2750_read_u32_le",
    "rome2_100f2750_spans_overlap",
    "rome2_100f2750_write_u32_le",
    "return",
    "sizeof",
}


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
    if _sha256(text) != EXPECTED_SHA256[label]:
        findings.append(f"{label} SHA-256 changed")
    code, sanitize_findings = sanitize_c(text)
    findings.extend(sanitize_findings)
    compact = _compact(code)

    if label == "header":
        if compact.count(
            "#defineROME2_PORT_100F2750_MAX_UNITSUINT32_C(15)"
        ) != 1:
            findings.append("short-copy unit ceiling changed")
        declaration = (
            "rome2_guest_status" + FUNCTION + "("
            "constrome2_guest_write_view*view,"
            "rome2_guest_addr32guest_destination_descriptor,"
            "rome2_guest_addr32guest_source_descriptor,"
            "uint32_tmax_units,"
            "rome2_guest_addr32*guest_return_out);"
        )
        if compact.count(declaration) != 1:
            findings.append("exact bounded short-copy declaration changed")
        includes = re.findall(
            r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, re.MULTILINE
        )
        if includes != ["ported_100f1c10_triplet.h"]:
            findings.append("header must reuse only the guest write-view contract")
        if re.search(r"\b(?:uintptr_t|intptr_t|void\s*\*)\b", code):
            findings.append("public API exposes a native pointer-shaped scalar")
    elif label == "source":
        tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
        for token in sorted(tokens & BANNED_IDENTIFIERS):
            findings.append(f"forbidden platform/allocation identifier: {token}")
        for token in (
            "100ef330",
            "10124e50",
            "116be104",
            "119ebd90",
            "119f3eb0",
        ):
            if token in code.lower():
                findings.append(f"excluded recovered route is referenced: {token}")
        if re.search(r"\b(?:extern|volatile|__declspec)\b", code):
            findings.append("external/global/volatile/DLL storage is forbidden")
        if re.search(
            r"\([^)]*\*[^)]*\)\s*[^;\n]*guest_(?:destination|source)"
            r"_descriptor\s*\.\s*value",
            code,
        ):
            findings.append("guest descriptor identity is cast to a native pointer")

        calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
        for call in sorted(calls - ALLOWED_SOURCE_CALLS):
            findings.append(f"unexpected source call expression: {call}")

        required = (
            "#defineROME2_PORT_100F2750_DESCRIPTOR_BYTESUINT64_C(12)",
            "max_units==0||max_units>ROME2_PORT_100F2750_MAX_UNITS",
            "ROME2_PORT_100F2750_DESCRIPTOR_BYTES>"
            "view->byte_count-destination_descriptor_offset",
            "ROME2_PORT_100F2750_DESCRIPTOR_BYTES>"
            "view->byte_count-source_descriptor_offset",
            "if(destination_descriptor_offset!=source_descriptor_offset&&"
            "rome2_100f2750_spans_overlap(",
            "source_count=rome2_100f2750_read_u32_le(source_descriptor);",
            "destination_capacity=rome2_100f2750_read_u32_le("
            "destination_descriptor+4);",
            "if(source_count>=max_units||destination_capacity<source_count)"
            "{returnROME2_GUEST_BAD_ARGUMENT;}",
            "if(destination_descriptor_offset==source_descriptor_offset)"
            "{guest_return_out->value=guest_destination_descriptor.value;"
            "returnROME2_GUEST_OK;}",
            "copy_bytes=((uint64_t)source_count+UINT64_C(1))*UINT64_C(2);",
            "copy_bytes>view->byte_count-destination_payload_offset",
            "copy_bytes>view->byte_count-source_payload_offset",
            "for(index=0;index<(size_t)copy_bytes;++index)"
            "{destination_payload[index]=source_payload[index];}",
            "rome2_100f2750_write_u32_le(destination_descriptor,source_count);"
            "guest_return_out->value=guest_destination_descriptor.value;"
            "returnROME2_GUEST_OK;",
        )
        previous = -1
        for fragment in required:
            position = compact.find(fragment)
            if position < 0:
                findings.append(f"required short-copy fragment changed: {fragment[:62]}")
            elif position <= previous:
                findings.append("validation, copy, or commit order changed")
            previous = max(previous, position)
        if compact.count("rome2_100f2750_spans_overlap(") != 7:
            findings.append("descriptor/payload disjointness checks changed")
        if compact.count("guest_return_out->value=") != 2:
            findings.append("only the two successful routes may write the output")
        if compact.count("destination_payload[index]=source_payload[index]") != 1:
            findings.append("short payload must have exactly one scalar copy loop")
    elif label == "test":
        for token in (
            "zero-count two-byte copy",
            "ordinary unterminated final-unit copy",
            "thirty-byte helper-boundary copy",
            "identical descriptor no-op",
            "payload adjacency accepted",
            "count equals external bound",
            "allocation branch rejected",
            "identical descriptor allocation branch rejected",
            "overlapping descriptors",
            "overlapping payloads",
            "payload overlaps destination descriptor",
            "destination payload overlaps source descriptor",
            "source payload overlaps destination descriptor",
            "guest view end overflow",
            "output aliases guest view",
            "output aliases view descriptor",
            "view descriptor aliases guest bytes",
            "host numeric range overflow",
        ):
            if token not in text:
                findings.append(f"runtime reciprocal case missing: {token}")
        if FUNCTION not in code:
            findings.append("runtime test does not exercise the short-copy port")

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
        "ported_100f2750_nonalloc.h",
        "ported_100f2750_nonalloc.c",
        "test_startup_100f2750_nonalloc.c",
        "startup_100f2750_nonalloc_provenance",
        "startup_100f2750_nonalloc_static_gate",
        "startup_100f2750_nonalloc_runtime",
    )
    for token in scoped:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake token missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake token escapes BUILD_TESTING: {token}")

    compact = _compact("\n".join(lines[start + 1 : end]))
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("short-copy port must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("short-copy library must not be shared")
    expected_headless = (
        f"target_link_libraries({HEADLESS}PRIVATE"
        "rome2_guest32_runtime"
        "rome2_startup_100f1aa0_empty_runtime"
        "rome2_startup_safe_seams_runtime"
        "rome2_startup_100df270_headless_runtime"
        f"{LIBRARY}"
        "rome2_startup_100e8240_fastpath_runtime"
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
        f"{PARENT_LIBRARY}{LIFECYCLE_LIBRARY})"
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
            f"{LIBRARY}"
            "rome2_startup_100e8240_fastpath_runtime"
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
            f"{PARENT_LIBRARY}{LIFECYCLE_LIBRARY}"
        ),
    }
    if set(links) != expected_links or len(links) != len(expected_links):
        findings.append("short-copy port has an unexpected consumer or dependency")
    for command in links:
        if any(
            target in command
            for target in (
                "empire_retail_bootstrap",
                "empire_bootstrap_smoke",
                "rome2_guest32_probe",
            )
        ):
            findings.append("short-copy port escaped into production/probe linkage")
    expected_headless_fixture = (
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED"
        '"entry_policy_provenance_verified;entry_policy_static_verified;'
        'startup_100ed471_ordinary_lifecycle_reload_verified"'
        "TIMEOUT90)"
    )
    if compact.count(expected_headless_fixture) != 1:
        findings.append("headless harness must depend on the final handler reload fixture")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (FUNCTION.lower(), LIBRARY.lower(), "ported_100f2750_nonalloc"):
        if token in lowered:
            findings.append(f"test-only short-copy port escaped into exports: {token}")
    return sorted(set(findings))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
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
