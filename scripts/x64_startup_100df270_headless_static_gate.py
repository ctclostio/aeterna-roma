#!/usr/bin/env python3
"""Fail-closed source/link gate for the bounded 100df270 headless projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


LIBRARY = "rome2_startup_100df270_headless_runtime"
TEST_TARGET = "rome2_startup_100df270_headless_tests"
HEADLESS = "rome2_headless64"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
NONEMPTY_PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
FUNCTION = "rome2_port_100df270_project_headless_empty_state"
EXPECTED_CMAKE_ADD_TEST_COUNT = 194

EXPECTED_SHA256 = {
    "header": "399fcb84a594fca51dda9d320bffa911864b6a5e9ed9e265b32b8078932c3d74",
    "source": "90402b6f61630b84457f95b18a5fb1aade7729fff2203569e4cb9b071b563bdd",
    "test": "f439f5d4212d12dd15d917ba7aa145460972ee3e9398b02ab71ba4e096c85205",
}

BANNED_IDENTIFIERS = {
    "CreateMutexA",
    "CreateMutexW",
    "ExitProcess",
    "GetLastError",
    "LoadStringA",
    "LoadStringW",
    "MessageBoxA",
    "MessageBoxW",
    "SystemParametersInfoA",
    "SystemParametersInfoW",
    "TerminateProcess",
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
    "FUNCTION",
    "UINT32_C",
    "UINT64_C",
    "if",
    "rome2_port_100df270_project_headless_empty_state",
    "rome2_read_u32_le",
    "rome2_write_empty_sequence",
    "rome2_write_u32_le",
    "return",
    "sizeof",
}


def _compact(text: str) -> str:
    return "".join(text.split())


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
            "#defineROME2_PORT_100DF270_OBJECT_BYTESUINT32_C(0x8a8)"
        ) != 1:
            findings.append("object span changed")
        if compact.count(
            "#defineROME2_PORT_100DF270_PACKET_BYTESUINT32_C(0x2d)"
        ) != 1:
            findings.append("packet span changed")
        declaration = (
            "rome2_guest_status" + FUNCTION + "("
            "constrome2_guest_write_view*view,"
            "rome2_guest_addr32guest_object,"
            "rome2_guest_addr32guest_packet,"
            "rome2_guest_addr32*guest_return_out);"
        )
        if compact.count(declaration) != 1:
            findings.append("exact projection declaration changed")
        if re.search(r"\b(?:uintptr_t|intptr_t|void\s*\*)\b", code):
            findings.append("public API exposes a native pointer-shaped scalar")
    elif label == "source":
        tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
        for token in sorted(tokens & BANNED_IDENTIFIERS):
            findings.append(f"forbidden platform/allocation identifier: {token}")
        for token in (
            "119f3140",
            "119f3854",
            "100e8240",
            "100ea4d0",
            "100f2750",
            "10102850",
            "101046d0",
        ):
            if token in code.lower():
                findings.append(f"excluded recovered target is referenced: {token}")
        if re.search(r"\b(?:extern|volatile|__declspec)\b", code):
            findings.append("external/global/volatile/DLL storage is forbidden")
        if re.search(
            r"\([^)]*\*[^)]*\)\s*[^;\n]*(?:guest_object|guest_packet)"
            r"\s*\.\s*value",
            code,
        ):
            findings.append("guest identity is converted to a native pointer")

        calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
        for call in sorted(calls - ALLOWED_SOURCE_CALLS):
            findings.append(f"unexpected source call expression: {call}")
        required = (
            "if(view==NULL||guest_return_out==NULL||view->host_base==NULL)"
            "{returnROME2_GUEST_BAD_ARGUMENT;}",
            "ROME2_PORT_100DF270_OBJECT_BYTES>view->byte_count-object_offset",
            "ROME2_PORT_100DF270_PACKET_BYTES>view->byte_count-packet_offset",
            "object_offset-packet_offset<ROME2_PORT_100DF270_PACKET_BYTES",
            "packet_offset-object_offset<ROME2_PORT_100DF270_OBJECT_BYTES",
            "if(rome2_read_u32_le(packet+0x08)!=0||"
            "rome2_read_u32_le(packet+0x14)!=0)"
            "{returnROME2_GUEST_BAD_ARGUMENT;}",
            "rome2_write_u32_le(object,0x000,"
            "ROME2_PORT_100DF270_RUNTIME_VTABLE);",
            "rome2_write_empty_sequence(object,0x82c);",
            "rome2_write_empty_sequence(object,0x838);",
            "rome2_write_u32_le(object,0x854,guest_object.value);",
            "rome2_write_u32_le(object,0x864,guest_object.value);",
            "rome2_write_u32_le(object,0x874,"
            "ROME2_PORT_100DF270_DISPATCH_VTABLE);",
            "rome2_write_u32_le(object,0x898,UINT32_MAX);",
            "guest_return_out->value=guest_object.value;"
            "returnROME2_GUEST_OK;",
        )
        previous = -1
        for fragment in required:
            position = compact.find(fragment)
            if position < 0:
                findings.append(f"required projection fragment changed: {fragment[:60]}")
            elif position <= previous:
                findings.append("validation or deterministic-write order changed")
            previous = max(previous, position)
        for offset in ("0x004", "0x808", "0x818", "0x884", "0x890"):
            if offset in code:
                findings.append(f"excluded object hole is referenced: {offset}")
        if compact.count("guest_return_out->value=") != 1:
            findings.append("return output must be written exactly once on success")
        if compact.count("ROME2_PORT_100DF270_EMPTY_SENTINEL") != 2:
            findings.append("empty sentinel definition/use count changed")
    elif label == "test":
        for token in (
            "exact deterministic projection",
            "excluded holes changed",
            "first descriptor nonempty",
            "second descriptor nonempty",
            "packet overlaps object",
            "packet one byte short",
            "guest view overflow",
            "output aliases view bytes",
            "output aliases view structure",
        ):
            if token not in text:
                findings.append(f"runtime reciprocal case missing: {token}")
        if FUNCTION not in code:
            findings.append("runtime test does not exercise the projection")

    if label != "test":
        if re.search(r"^\s*#\s*pragma\b", code, re.M):
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
        findings.append("CMake add_test declaration count must remain 194")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped = (
        LIBRARY,
        TEST_TARGET,
        "ported_100df270_headless.h",
        "ported_100df270_headless.c",
        "test_startup_100df270_headless.c",
        "startup_100df270_headless_provenance",
        "startup_100df270_headless_static_gate",
        "startup_100df270_headless_runtime",
    )
    for token in scoped:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake token missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake token escapes BUILD_TESTING: {token}")

    compact = _compact("\n".join(lines[start + 1 : end]))
    if f"add_library({LIBRARY}STATIC" not in compact:
        findings.append("projection must be a BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("projection library must not be shared")
    expected_headless = (
        f"target_link_libraries({HEADLESS}PRIVATE"
        "rome2_guest32_runtime"
        "rome2_startup_100f1aa0_empty_runtime"
        "rome2_startup_safe_seams_runtime"
        f"{LIBRARY}"
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
            f"{LIBRARY}"
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
            f"{PARENT_LIBRARY}"
            f"{LIFECYCLE_LIBRARY}"
        ),
        (
            f"{PARENT_LIBRARY}PUBLICrome2_guest32_runtimePRIVATE"
            "rome2_startup_100f1c10_runtime"
            "rome2_startup_100f1aa0_empty_runtime"
            "rome2_startup_safe_seams_runtime"
            f"{LIBRARY}"
            "rome2_startup_100df270_suffix_transcript_runtime"
            "rome2_startup_100df270_platform_prefix_transcript_runtime"
        ),
        (
            f"{NONEMPTY_PARENT_LIBRARY}PUBLICrome2_guest32_runtimePRIVATE"
            "rome2_startup_100f1c10_runtime"
            "rome2_startup_100f1aa0_empty_runtime"
            "rome2_startup_safe_seams_runtime"
            f"{LIBRARY}"
            "rome2_startup_100df270_platform_prefix_transcript_runtime"
            "rome2_startup_100df270_suffix_transcript_runtime"
            "rome2_startup_100f1bb0_owned_utf16_runtime"
            "rome2_startup_100f2750_sentinel_owned_runtime"
        ),
    }
    if set(links) != expected_links or len(links) != len(expected_links):
        findings.append("projection has an unexpected consumer or dependency")
    for command in links:
        if any(
            target in command
            for target in (
                "empire_retail_bootstrap",
                "empire_bootstrap_smoke",
                "rome2_guest32_probe",
            )
        ):
            findings.append("projection escaped into production/probe linkage")
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
    for token in (FUNCTION.lower(), LIBRARY.lower(), "ported_100df270_headless"):
        if token in lowered:
            findings.append(f"test-only projection escaped into exports: {token}")
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
    payloads = {"header": args.header, "source": args.source, "test": args.test}
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, path in payloads.items():
        text, findings = _decode(path.resolve(strict=True))
        if text is not None:
            findings.extend(inspect_payload_text(label, text))
        findings = sorted(set(findings))
        total += len(findings)
        report["files"][label] = {
            "path": str(path.resolve()),
            "findings": findings,
        }
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
