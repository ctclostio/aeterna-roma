#!/usr/bin/env python3
"""Fail-closed containment gate for the empty-only 0x100f1aa0 native slice."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


TARGET_FUNCTION = "rome2_port_100f1aa0_copy_empty_source"
TARGET_LIBRARY = "rome2_startup_100f1aa0_empty_runtime"
TARGET_TEST = "rome2_startup_100f1aa0_empty_tests"
TARGET_HEADLESS = "rome2_headless64"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
NONEMPTY_PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"
DELEGATE_FUNCTION = "rome2_port_100f1c10_initialize_triplet"
DELEGATE_LIBRARY = "rome2_startup_100f1c10_runtime"
EXPECTED_CMAKE_ADD_TEST_COUNT = 192

EXPECTED_HEADER_TOKEN_SHA256 = (
    "559d6e1f552f3b05b9419d9e8a92397b697de0a6baa57b04c5d53d985787a9bb"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "3e04be013398069a5c6a19c11f582d2d7c348793ebae246651eb0a56eacccf07"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "d567e60abe65b8ef9b85e213164631b88455d907505a3daa55711e2e9d8fba70"
)

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
    "entry_point",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "realloc",
}

BANNED_ADDRESS_TOKENS = {
    "100ed3c0",
    "100ef330",
    "100f1bb0",
    "100f1cc0",
    "100fcc80",
    "10124e50",
}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT64_C",
    "if",
    "sizeof",
    TARGET_FUNCTION,
    DELEGATE_FUNCTION,
}

REQUIRED_ORDERED_FRAGMENTS = (
    "if(view==NULL||guest_return_out==NULL||view->host_base==NULL){"
    "returnROME2_GUEST_BAD_ARGUMENT;}",
    "if(view->byte_count>ROME2_GUEST_ADDRESS_SPACE_SIZE||"
    "(uint64_t)view->guest_base+view->byte_count>"
    "ROME2_GUEST_ADDRESS_SPACE_SIZE){returnROME2_GUEST_RANGE_OVERFLOW;}",
    "host_address=(uintptr_t)view->host_base;",
    "output_address=(uintptr_t)guest_return_out;",
    "view_address=(uintptr_t)view;",
    "if(guest_destination.value==0||guest_source.value==0){"
    "returnROME2_GUEST_NULL_ADDRESS;}",
    "if(guest_destination.value<view->guest_base||"
    "guest_source.value<view->guest_base){returnROME2_GUEST_OUT_OF_RANGE;}",
    "destination_offset=(uint64_t)guest_destination.value-"
    "(uint64_t)view->guest_base;",
    "source_offset=(uint64_t)guest_source.value-"
    "(uint64_t)view->guest_base;",
    "source_bytes=view->host_base+(size_t)source_offset;",
    "source_count=(uint32_t)source_bytes[0]|"
    "((uint32_t)source_bytes[1]<<8)|"
    "((uint32_t)source_bytes[2]<<16)|"
    "((uint32_t)source_bytes[3]<<24);",
    "if(source_count!=0){returnROME2_GUEST_BAD_ARGUMENT;}",
    "returnrome2_port_100f1c10_initialize_triplet("
    "view,guest_destination,guest_return_out);",
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
        findings.append("header must reuse only the accepted triplet contract")
    declaration = (
        "rome2_guest_statusrome2_port_100f1aa0_copy_empty_source("
        "constrome2_guest_write_view*view,"
        "rome2_guest_addr32guest_destination,"
        "rome2_guest_addr32guest_source,"
        "rome2_guest_addr32*guest_return_out);"
    )
    if compact.count(declaration) != 1:
        findings.append("exact empty-only declaration is missing or duplicated")
    if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append("DLL import/export annotation is forbidden")
    if re.search(r"\b(?:uintptr_t|intptr_t|void\s*\*)\b", code):
        findings.append("native pointer-shaped API fields are forbidden")
    return sorted(set(findings))


def inspect_header(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_header_text(text)


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)

    if _token_digest(code) != EXPECTED_SOURCE_TOKEN_SHA256:
        findings.append("source executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["ported_100f1aa0_empty.h", "limits.h"]:
        findings.append("source include set or order changed")
    if re.search(r"^\s*#\s*pragma\b", code, flags=re.MULTILINE):
        findings.append("pragmas and warning suppression are forbidden")

    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden allocation/platform/helper identifier: {token}")
    lowered = code.lower()
    for address in sorted(BANNED_ADDRESS_TOKENS):
        if address in lowered:
            findings.append(f"forbidden recovered address token: {address}")
    if re.search(r"\b(?:static|extern|volatile|__declspec)\b", code):
        findings.append("global/static/volatile/DLL storage is forbidden")
    if re.search(
        r"\([^)]*\*[^)]*\)\s*[^;\n]*(?:guest_destination|guest_source)"
        r"\s*\.\s*value",
        code,
    ):
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
    if compact.count("#defineROME2_EMPTY_SEQUENCE_BYTESUINT64_C(12)") != 1:
        findings.append("source and destination spans must remain 12 bytes")

    definition_pattern = re.compile(
        r"\brome2_guest_status\s+" + re.escape(TARGET_FUNCTION) + r"\s*\("
    )
    if len(definition_pattern.findall(code)) != 1:
        findings.append("exactly one empty-only definition is required")

    previous = -1
    for fragment in REQUIRED_ORDERED_FRAGMENTS:
        position = compact.find(fragment)
        if position < 0:
            findings.append(f"required boundary fragment missing: {fragment[:58]}")
            continue
        if position <= previous:
            findings.append("validation, source read, and delegation order changed")
        previous = position

    required_checks = (
        "view->byte_count-UINT64_C(1)>(uint64_t)(UINTPTR_MAX-host_address)",
        "sizeof(*guest_return_out)-1>UINTPTR_MAX-output_address",
        "sizeof(*view)-1>UINTPTR_MAX-view_address",
        "output_address-host_address)<view->byte_count",
        "output_address-view_address<sizeof(*view)",
        "view_address-host_address)<view->byte_count",
        "ROME2_EMPTY_SEQUENCE_BYTES>view->byte_count-destination_offset",
        "ROME2_EMPTY_SEQUENCE_BYTES>view->byte_count-source_offset",
        "destination_offset-source_offset<ROME2_EMPTY_SEQUENCE_BYTES",
        "source_offset-destination_offset<ROME2_EMPTY_SEQUENCE_BYTES",
    )
    for check in required_checks:
        if compact.count(check) != 1:
            findings.append(f"required range/alias check changed: {check[:58]}")

    source_reads = [int(index) for index in re.findall(
        r"source_bytes\s*\[\s*(\d+)\s*\]", code
    )]
    if source_reads != [0, 1, 2, 3]:
        findings.append("only the four little-endian count bytes may be read")
    if re.search(r"(?:source_bytes|view\s*->\s*host_base)\s*\[[^]]+\]\s*=", code):
        findings.append("wrapper must not write the shared view directly")
    if re.search(r"guest_return_out\s*->", code):
        findings.append("wrapper must delegate the output write")
    if compact.count(DELEGATE_FUNCTION + "(") != 1:
        findings.append("accepted triplet implementation must be called exactly once")
    if compact.count("if(source_count!=0)") != 1:
        findings.append("nonzero counts must be rejected exactly once")
    if not compact.endswith(
        "returnrome2_port_100f1c10_initialize_triplet("
        "view,guest_destination,guest_return_out);}" 
    ):
        findings.append("delegate must be the only successful terminal action")
    return sorted(set(findings))


def inspect_source(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_source_text(text)


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)

    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime-test executable-token digest changed")
    oracle_match = re.search(
        r"rome2_triplet_oracle\s*\[\s*12\s*\]\s*=\s*\{([^}]*)\}",
        code,
        flags=re.S,
    )
    expected = [0, 0, 0, 0, 0, 0, 0, 0, 0x90, 0x40, 0xAF, 0x11]
    if oracle_match is None:
        findings.append("independent literal 12-byte runtime oracle is missing")
    else:
        values = [
            int(token, 0)
            for token in re.findall(r"0[xX][0-9A-Fa-f]+|\b\d+\b", oracle_match.group(1))
        ]
        if values != expected:
            findings.append("runtime oracle differs from the exact literal triplet")
    if DELEGATE_FUNCTION in code:
        findings.append("runtime oracle/test must not call the accepted delegate directly")
    if TARGET_FUNCTION not in code:
        findings.append("runtime test does not exercise the empty-only wrapper")
    for address in ("100ef330", "100fcc80", "100ed3c0"):
        if address in code.lower():
            findings.append(f"runtime test references forbidden recovered address: {address}")
    return sorted(set(findings))


def inspect_test(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_test_text(text)


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, flags=re.I):
            stack.append((index, bool(re.match(
                r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, flags=re.I
            ))))
        elif re.match(r"endif\s*\(", stripped, flags=re.I) or re.match(
            r"endif\s*$", stripped, flags=re.I
        ):
            if not stack:
                return None
            start, is_build_testing = stack.pop()
            if is_build_testing:
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
        findings.append("CMakeLists must not override BUILD_TESTING")
    if any(
        re.match(r"\s*else(?:if)?\s*\(", line, flags=re.I)
        or re.match(r"\s*else(?:if)?\s*$", line, flags=re.I)
        for line in lines[start + 1 : end]
    ):
        findings.append("BUILD_TESTING empty-path region must not contain else/elseif")

    scoped_tokens = (
        TARGET_LIBRARY,
        TARGET_TEST,
        TARGET_HEADLESS,
        "ported_100f1aa0_empty.c",
        "ported_100f1aa0_empty.h",
        "test_startup_100f1aa0_empty.c",
        "startup_100f1aa0_empty_provenance",
        "startup_100f1aa0_empty_static_gate",
        "startup_100f1aa0_empty_runtime",
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake token escapes BUILD_TESTING: {token}")

    compact = _compact("\n".join(lines[start + 1 : end]))
    if (
        f"add_library({TARGET_LIBRARY}STATIC" not in compact
        or f"add_library({TARGET_LIBRARY}SHARED" in compact
    ):
        findings.append("empty-path port must be a BUILD_TESTING-only static library")
    if f"add_executable({TARGET_TEST}" not in compact:
        findings.append("empty-path runtime test executable is missing")
    if (
        f"target_link_libraries({TARGET_LIBRARY}PRIVATE{DELEGATE_LIBRARY})"
        not in compact
    ):
        findings.append("empty-path library must delegate only to accepted triplet library")
    if f"target_link_libraries({TARGET_TEST}PRIVATE{TARGET_LIBRARY})" not in compact:
        findings.append("empty-path library must link only to its dedicated test host")
    expected_headless_link = (
        f"target_link_libraries({TARGET_HEADLESS}PRIVATE"
        f"rome2_guest32_runtime{TARGET_LIBRARY}"
        "rome2_startup_safe_seams_runtime"
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
        f"{PARENT_LIBRARY}{LIFECYCLE_LIBRARY})"
    )
    if expected_headless_link not in compact:
        findings.append("headless harness must compose only the admitted guest32 slices")
    expected_headless_fixture = (
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED"
        '"entry_policy_provenance_verified;entry_policy_static_verified;'
        'startup_100ed471_ordinary_lifecycle_reload_verified"'
        "TIMEOUT90)"
    )
    if compact.count(expected_headless_fixture) != 1:
        findings.append("headless harness must depend on the final handler reload fixture")

    commands = re.findall(
        r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)", text, flags=re.I | re.S
    )
    for filename, expected_command, expected_owner in (
        ("ported_100f1aa0_empty.c", "add_library", TARGET_LIBRARY),
        ("ported_100f1aa0_empty.h", "add_library", TARGET_LIBRARY),
        ("test_startup_100f1aa0_empty.c", "add_executable", TARGET_TEST),
    ):
        owners = [
            (name.lower(), body)
            for name, body in commands
            if filename in body
            and not (
                name.lower() == "add_test"
                and "startup_100f1aa0_empty_static_gate" in body
            )
        ]
        if len(owners) != 1:
            findings.append(f"{filename} must have exactly one source owner")
        elif owners[0][0] != expected_command or expected_owner not in owners[0][1]:
            findings.append(f"{filename} has a forbidden CMake source owner")

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    wrapper_links = [command for command in link_commands if TARGET_LIBRARY in command]
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in wrapper_links
    ]
    if sorted(consumers) != sorted(
        (
            TARGET_LIBRARY, TARGET_TEST, TARGET_HEADLESS, PARENT_LIBRARY,
            NONEMPTY_PARENT_LIBRARY,
        )
    ):
        findings.append("empty-path library has an unexpected link consumer or dependency")
    for command in link_commands:
        consumer = re.split(r"\s+", command.strip(), maxsplit=1)[0]
        if (
            TARGET_LIBRARY in command
            and consumer not in (
                TARGET_HEADLESS, PARENT_LIBRARY, NONEMPTY_PARENT_LIBRARY
            )
            and any(
            target in command
            for target in (
                "empire_retail_bootstrap",
                "empire_bootstrap_smoke",
                "rome2_guest32_probe",
                "rome2_guest32_runtime",
            )
            )
        ):
            findings.append("empty-path library is linked to production/probe code")
        if TARGET_LIBRARY in command and consumer == TARGET_HEADLESS:
            normalized = _compact(command)
            if normalized != (
                f"{TARGET_HEADLESS}PRIVATE"
                f"rome2_guest32_runtime{TARGET_LIBRARY}"
                "rome2_startup_safe_seams_runtime"
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
            ):
                findings.append("headless harness has an unexpected link dependency")
    return sorted(set(findings))


def inspect_cmake(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_cmake_text(text)


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        TARGET_FUNCTION.lower(),
        TARGET_LIBRARY.lower(),
        "ported_100f1aa0_empty",
        "100f1aa0",
    ):
        if token in lowered:
            findings.append(f"test-only empty-path token escaped into exports: {token}")
    return sorted(set(findings))


def inspect_exports(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_exports_text(text)


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
    checks = {
        "header": (args.header, inspect_header),
        "source": (args.source, inspect_source),
        "test": (args.test, inspect_test),
        "cmake": (args.cmake, inspect_cmake),
        "export_manifest": (args.export_manifest, inspect_exports),
        "legacy_def": (args.legacy_def, inspect_exports),
        "probe_def": (args.probe_def, inspect_exports),
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, (path, inspector) in checks.items():
        resolved = path.resolve(strict=True)
        findings = inspector(resolved)
        total += len(findings)
        report["files"][label] = {
            "path": str(resolved),
            "findings": findings,
        }
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
