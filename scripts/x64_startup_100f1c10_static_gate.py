#!/usr/bin/env python3
"""Fail-closed source and build-containment gate for startup leaf 0x100f1c10."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


TARGET_FUNCTION = "rome2_port_100f1c10_initialize_triplet"
TARGET_LIBRARY = "rome2_startup_100f1c10_runtime"
TARGET_TEST = "rome2_startup_100f1c10_tests"
BOUNDED_DELEGATE_LIBRARY = "rome2_startup_100f1aa0_empty_runtime"
PARENT_LIBRARY = "rome2_startup_100ed3c0_empty_preloop_runtime"
NONEMPTY_PARENT_LIBRARY = "rome2_startup_100ed3c0_nonempty_preloop_runtime"

EXPECTED_HEADER_TOKEN_SHA256 = (
    "ab9b018af6e3b073c1c1cf8bf1bb29e4d381a2f7147432b1c6851554a23d7e60"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "54b1d06fcc806b9b2b2006782b7db18e6c6d21b09612704565d689f47513baec"
)

EXPECTED_STORES = {
    0: "0",
    1: "0",
    2: "0",
    3: "0",
    4: "0",
    5: "0",
    6: "0",
    7: "0",
    8: "UINT8_C(0x90)",
    9: "UINT8_C(0x40)",
    10: "UINT8_C(0xaf)",
    11: "UINT8_C(0x11)",
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
    "entry_point",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "realloc",
}

BANNED_ADDRESS_TOKENS = {
    "100e81a0",
    "100ed3c0",
    "100edd70",
    "1093c450",
}

ALLOWED_CALL_EXPRESSIONS = {
    "UINT64_C",
    "UINT8_C",
    "if",
    "sizeof",
    TARGET_FUNCTION,
}

REQUIRED_ORDERED_FRAGMENTS = (
    "if(view==NULL||guest_return_out==NULL||view->host_base==NULL){"
    "returnROME2_GUEST_BAD_ARGUMENT;}",
    "if(view->byte_count>ROME2_GUEST_ADDRESS_SPACE_SIZE||"
    "(uint64_t)view->guest_base+view->byte_count>"
    "ROME2_GUEST_ADDRESS_SPACE_SIZE){returnROME2_GUEST_RANGE_OVERFLOW;}",
    "host_address=(uintptr_t)view->host_base;",
    "if(view->byte_count!=0&&view->byte_count-UINT64_C(1)>"
    "(uint64_t)(UINTPTR_MAX-host_address)){"
    "returnROME2_GUEST_RANGE_OVERFLOW;}",
    "output_address=(uintptr_t)guest_return_out;",
    "if(sizeof(*guest_return_out)-1>UINTPTR_MAX-output_address){"
    "returnROME2_GUEST_RANGE_OVERFLOW;}",
    "if(view->byte_count!=0&&((output_address>=host_address&&"
    "(uint64_t)(output_address-host_address)<view->byte_count)||"
    "(host_address>output_address&&host_address-output_address<"
    "sizeof(*guest_return_out)))){returnROME2_GUEST_BAD_ARGUMENT;}",
    "if(guest_destination.value==0){returnROME2_GUEST_NULL_ADDRESS;}",
    "if(guest_destination.value<view->guest_base){"
    "returnROME2_GUEST_OUT_OF_RANGE;}",
    "offset=(uint64_t)guest_destination.value-(uint64_t)view->guest_base;",
    "if(offset>view->byte_count||ROME2_STARTUP_TRIPLET_BYTES>"
    "view->byte_count-offset||offset>(uint64_t)SIZE_MAX){"
    "returnROME2_GUEST_OUT_OF_RANGE;}",
    "destination=view->host_base+(size_t)offset;",
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

    expected_view = (
        "typedefstructrome2_guest_write_view{uint8_t*host_base;"
        "uint32_tguest_base;uint64_tbyte_count;}rome2_guest_write_view;"
    )
    if expected_view not in compact:
        findings.append("write-view layout or fixed-width fields changed")

    expected_declaration = (
        "rome2_guest_statusrome2_port_100f1c10_initialize_triplet("
        "constrome2_guest_write_view*view,"
        "rome2_guest_addr32guest_destination,"
        "rome2_guest_addr32*guest_return_out);"
    )
    if compact.count(expected_declaration) != 1:
        findings.append("exact leaf declaration is missing or duplicated")

    if "sizeof(((rome2_guest_write_view*)0)->guest_base)==4" not in compact:
        findings.append("guest-base width assertion is missing")
    if re.search(r"\b(?:__declspec|dllexport|dllimport)\b", code, re.I):
        findings.append("DLL import/export annotation is forbidden")
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
    if includes != ["ported_100f1c10_triplet.h", "limits.h"]:
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
        r"\([^)]*\*[^)]*\)\s*[^;\n]*guest_destination\s*\.\s*value",
        code,
    ):
        findings.append("guest destination is converted to a native pointer")
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
    if compact.count("#defineROME2_STARTUP_TRIPLET_BYTESUINT64_C(12)") != 1:
        findings.append("triplet span is not exactly 12 bytes")

    definition_pattern = re.compile(
        r"\brome2_guest_status\s+" + re.escape(TARGET_FUNCTION) + r"\s*\("
    )
    if len(definition_pattern.findall(code)) != 1:
        findings.append("exactly one leaf definition is required")

    previous = -1
    for fragment in REQUIRED_ORDERED_FRAGMENTS:
        position = compact.find(fragment)
        if position < 0:
            findings.append(f"required validation fragment missing: {fragment[:56]}")
            continue
        if position <= previous:
            findings.append("validation and destination derivation order changed")
        previous = position

    store_matches = re.findall(
        r"destination\s*\[\s*(\d+)\s*\]\s*=\s*([^;]+);", code
    )
    observed_stores: list[tuple[int, str]] = []
    for raw_index, raw_value in store_matches:
        index = int(raw_index, 10)
        value = _compact(raw_value)
        if any(prior_index == index for prior_index, _ in observed_stores):
            findings.append(f"destination byte {index} is written more than once")
        observed_stores.append((index, value))
    if observed_stores != list(EXPECTED_STORES.items()):
        findings.append("destination stores differ from the exact 12-byte oracle")
    if len(store_matches) != 12:
        findings.append("exactly twelve destination byte stores are required")

    output_matches = re.findall(
        r"guest_return_out\s*->\s*value\s*=\s*([^;]+);", code
    )
    if [_compact(value) for value in output_matches] != [
        "guest_destination.value"
    ]:
        findings.append("output must be assigned the guest destination exactly once")

    first_store = compact.find("destination[0]=0;")
    last_store = compact.find("destination[11]=UINT8_C(0x11);")
    output_store = compact.find(
        "guest_return_out->value=guest_destination.value;"
    )
    ok_return = compact.find("returnROME2_GUEST_OK;")
    if not (
        previous >= 0
        and first_store > previous
        and last_store > first_store
        and output_store > last_store
        and ok_return > output_store
    ):
        findings.append("mutation/output/success ordering changed")

    return sorted(set(findings))


def inspect_source(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_source_text(text)


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
        findings.append("BUILD_TESTING leaf region must not contain else/elseif")

    scoped_tokens = (
        TARGET_LIBRARY,
        TARGET_TEST,
        "ported_100f1c10_triplet.c",
        "ported_100f1c10_triplet.h",
        "test_startup_100f1c10.c",
        "startup_100f1c10_provenance",
        "startup_100f1c10_static_gate",
        "startup_100f1c10_runtime",
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
        findings.append("leaf must be a separate BUILD_TESTING-only static library")
    if f"add_executable({TARGET_TEST}" not in compact:
        findings.append("leaf runtime test executable is missing")

    commands = re.findall(
        r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)", text, flags=re.I | re.S
    )
    for filename, expected_command, expected_owner in (
        (
            "ported_100f1c10_triplet.c",
            "add_library",
            TARGET_LIBRARY,
        ),
        (
            "ported_100f1c10_triplet.h",
            "add_library",
            TARGET_LIBRARY,
        ),
        (
            "test_startup_100f1c10.c",
            "add_executable",
            TARGET_TEST,
        ),
    ):
        owners = [
            (name.lower(), body)
            for name, body in commands
            if filename in body
            and not (
                name.lower() == "add_test"
                and "startup_100f1c10_static_gate" in body
            )
        ]
        if len(owners) != 1:
            findings.append(f"{filename} must have exactly one source owner")
        elif owners[0][0] != expected_command or expected_owner not in owners[0][1]:
            findings.append(f"{filename} has a forbidden CMake source owner")

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    leaf_links = [command for command in link_commands if TARGET_LIBRARY in command]
    leaf_consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in leaf_links
    ]
    if sorted(leaf_consumers) != sorted(
        (
            TARGET_TEST, BOUNDED_DELEGATE_LIBRARY, PARENT_LIBRARY,
            NONEMPTY_PARENT_LIBRARY,
        )
    ):
        findings.append(
            "leaf library consumers must be its dedicated test and bounded "
            "empty-path delegate, authenticated empty-preloop parent, and "
            "nonempty parent"
        )
    for command in link_commands:
        consumer = re.split(r"\s+", command.strip(), maxsplit=1)[0]
        if (
            TARGET_LIBRARY in command
            and consumer not in (
                TARGET_TEST,
                BOUNDED_DELEGATE_LIBRARY,
                PARENT_LIBRARY,
                NONEMPTY_PARENT_LIBRARY,
            )
            and any(
            target in command
            for target in (
                "empire_retail_bootstrap",
                "rome2_guest32_probe",
                "rome2_guest32_runtime",
            )
            )
        ):
            findings.append("leaf library is linked outside its isolated test host")

    return sorted(set(findings))


def inspect_cmake(path: pathlib.Path) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspect_cmake_text(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks = {
        "header": (args.header, inspect_header),
        "source": (args.source, inspect_source),
        "cmake": (args.cmake, inspect_cmake),
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
