#!/usr/bin/env python3
"""Fail-closed source/link gate for bounded 100f1bb0 and 100f1cc0 seams."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys


SAFE_LIBRARY = "rome2_startup_safe_seams_runtime"
SAFE_TEST = "rome2_startup_safe_seams_tests"
HEADLESS = "rome2_headless64"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
NONEMPTY_PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
MEASURE = "rome2_port_100f1bb0_measure_utf16"
NOOP = "rome2_port_100f1cc0_accept_nonowning_noop"
EXPECTED_CMAKE_ADD_TEST_COUNT = 192

EXPECTED_SHA256 = {
    "measure_header": "c79db19633151de3f3edf182589b38c53c80c34f6c48d43f763a70cabd7c0f03",
    "measure_source": "72161bbd683cad6439b7f26eb3ab549e0df64624009f52747b5faa78f8e46b92",
    "noop_header": "7edc2e2964335fd74a7f73a910a52cfcd7dc12b3980930385dd4e98cf098d130",
    "noop_source": "b3dbabd049b920722e0d2f1680e3b48535044ba34fe23be586caa51a5a5f3bac",
    "test": "d9030646ec6367bffb5f19771e51279e47d7adfd3858868397b3ebc6cb8b252c",
}

BANNED_SOURCE_TOKENS = {
    "CreateProcessA",
    "CreateProcessW",
    "FreeLibrary",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "VirtualAlloc",
    "VirtualFree",
    "calloc",
    "entry_point",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "realloc",
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
    compact = _compact(text)

    if label == "measure_header":
        if compact.count("#defineROME2_PORT_100F1BB0_MAX_UNITSUINT32_C(32768)") != 1:
            findings.append("bounded measure cap changed")
        if compact.count(MEASURE + "(") != 1:
            findings.append("bounded measure declaration changed")
        if re.search(r"\b(?:uintptr_t|intptr_t|void\s*\*)\b", text):
            findings.append("measure API exposes a native pointer-shaped scalar")
    elif label == "measure_source":
        if compact.count(MEASURE + "(") != 1:
            findings.append("bounded measure definition changed")
        required = (
            "if(length_out==NULL||max_units==0||max_units>"
            "ROME2_PORT_100F1BB0_MAX_UNITS){returnROME2_GUEST_BAD_ARGUMENT;}",
            "for(index=0;index<max_units;++index)",
            "rome2_guest_read_u16_le(view,cursor,&unit)",
            "if(unit==0){*length_out=index;returnROME2_GUEST_OK;}",
            "rome2_guest_add_checked(cursor,UINT32_C(2),&cursor)",
            "returnROME2_GUEST_OUT_OF_RANGE;",
        )
        for fragment in required:
            if compact.count(fragment) != 1:
                findings.append(f"measure boundary fragment changed: {fragment[:52]}")
        if compact.count("*length_out=") != 1:
            findings.append("measure output must be written only on success")
    elif label == "noop_header":
        if compact.count(
            "#defineROME2_PORT_100F1CC0_SENTINELUINT32_C(0x11af4090)"
        ) != 1:
            findings.append("nonowning sentinel changed")
        if compact.count(NOOP + "(") != 1:
            findings.append("nonowning declaration changed")
    elif label == "noop_source":
        if compact.count(NOOP + "(") != 1:
            findings.append("nonowning definition changed")
        expected = (
            "if(guest_storage.value==0||guest_storage.value=="
            "ROME2_PORT_100F1CC0_SENTINEL){returnROME2_GUEST_OK;}"
            "returnROME2_GUEST_BAD_ARGUMENT;"
        )
        if expected not in compact:
            findings.append("nonowning exact null/sentinel decision changed")
        if re.search(r"\([^)]*\*[^)]*\)\s*guest_storage\s*\.\s*value", text):
            findings.append("nonowning guest identity is cast to a native pointer")
    elif label == "test":
        for token in (
            "terminator outside bound",
            "cursor overflow",
            "sentinel nonowning value",
            "arbitrary owning value",
        ):
            if token not in text:
                findings.append(f"runtime reciprocal case missing: {token}")

    if label != "test":
        tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
        for token in sorted(tokens & BANNED_SOURCE_TOKENS):
            findings.append(f"forbidden platform/allocation token: {token}")
        if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", text, re.I):
            findings.append("DLL annotation is forbidden")
        if re.search(r"^\s*#\s*pragma\b", text, re.M):
            findings.append("pragma or warning suppression is forbidden")
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
    if re.search(r"\b(?:set|option)\s*\(\s*BUILD_TESTING\b", text, re.I):
        findings.append("CMake must not override BUILD_TESTING")

    scoped = (
        SAFE_LIBRARY,
        SAFE_TEST,
        "ported_100f1bb0_bounded.h",
        "ported_100f1bb0_bounded.c",
        "ported_100f1cc0_nonowning.h",
        "ported_100f1cc0_nonowning.c",
        "test_startup_safe_seams.c",
        "startup_safe_seams_provenance",
        "startup_safe_seams_static_gate",
        "startup_safe_seams_runtime",
    )
    for token in scoped:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake token missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake token escapes BUILD_TESTING: {token}")

    compact = _compact("\n".join(lines[start + 1 : end]))
    if f"add_library({SAFE_LIBRARY}STATIC" not in compact:
        findings.append("safe seams must be one BUILD_TESTING-only static library")
    if f"add_library({SAFE_LIBRARY}SHARED" in compact:
        findings.append("safe seams library must not be shared")
    required_links = {
        f"{SAFE_LIBRARY}PRIVATErome2_guest32_runtime",
        f"{SAFE_TEST}PRIVATE{SAFE_LIBRARY}",
        (
            f"{HEADLESS}PRIVATErome2_guest32_runtime"
            "rome2_startup_100f1aa0_empty_runtime"
            f"{SAFE_LIBRARY}"
            "rome2_startup_100df270_headless_runtime"
            "rome2_startup_100f2750_nonalloc_runtime"
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
        (
            f"{PARENT_LIBRARY}PUBLICrome2_guest32_runtimePRIVATE"
            "rome2_startup_100f1c10_runtime"
            "rome2_startup_100f1aa0_empty_runtime"
            f"{SAFE_LIBRARY}"
            "rome2_startup_100df270_headless_runtime"
            "rome2_startup_100df270_suffix_transcript_runtime"
            "rome2_startup_100df270_platform_prefix_transcript_runtime"
        ),
        (
            f"{LIFECYCLE_LIBRARY}PUBLICrome2_guest32_runtimePRIVATE"
            f"{SAFE_LIBRARY}"
        ),
        (
            f"{NONEMPTY_PARENT_LIBRARY}PUBLICrome2_guest32_runtimePRIVATE"
            "rome2_startup_100f1c10_runtime"
            "rome2_startup_100f1aa0_empty_runtime"
            f"{SAFE_LIBRARY}"
            "rome2_startup_100df270_headless_runtime"
            "rome2_startup_100df270_platform_prefix_transcript_runtime"
            "rome2_startup_100df270_suffix_transcript_runtime"
            "rome2_startup_100f1bb0_owned_utf16_runtime"
            "rome2_startup_100f2750_sentinel_owned_runtime"
        ),
    }
    commands = [
        _compact(command)
        for command in re.findall(
            r"target_link_libraries\s*\((.*?)\)", text, re.I | re.S
        )
        if SAFE_LIBRARY in command
    ]
    if set(commands) != required_links or len(commands) != len(required_links):
        findings.append("safe seams have an unexpected consumer or dependency")
    for command in commands:
        if any(
            target in command
            for target in (
                "empire_retail_bootstrap",
                "empire_bootstrap_smoke",
                "rome2_guest32_probe",
            )
        ):
            findings.append("safe seams escaped into production/probe linkage")
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
    for token in ("100f1bb0", "100f1cc0", MEASURE.lower(), NOOP.lower(), SAFE_LIBRARY):
        if token in lowered:
            findings.append(f"test-only safe-seam token escaped into exports: {token}")
    return sorted(set(findings))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure-header", type=pathlib.Path, required=True)
    parser.add_argument("--measure-source", type=pathlib.Path, required=True)
    parser.add_argument("--noop-header", type=pathlib.Path, required=True)
    parser.add_argument("--noop-source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payloads = {
        "measure_header": args.measure_header,
        "measure_source": args.measure_source,
        "noop_header": args.noop_header,
        "noop_source": args.noop_source,
        "test": args.test,
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, path in payloads.items():
        text, findings = _decode(path.resolve(strict=True))
        if text is not None:
            findings.extend(inspect_payload_text(label, text))
        findings = sorted(set(findings))
        total += len(findings)
        report["files"][label] = {"path": str(path.resolve()), "findings": findings}

    for label, path, inspector in (
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
        report["files"][label] = {"path": str(path.resolve()), "findings": findings}

    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
