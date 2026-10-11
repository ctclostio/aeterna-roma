#!/usr/bin/env python3
"""Token-aware hard-rejection gate for isolated entry-policy candidates."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


BANNED_IDENTIFIERS = {
    "wchar_t",
    "wint_t",
    "wcscmp",
    "wcsncmp",
    "wcscpy",
    "wcscat",
    "wcslen",
    "wmemcmp",
    "wmemchr",
    "lstrcmpW",
    "lstrcmpiW",
    "lstrlenW",
    "_wcsicmp",
    "_wcsnicmp",
}

BANNED_POLICY_CALLS = {
    "strcmp",
    "strncmp",
    "strlen",
    "strnlen",
    "memcmp",
    "memchr",
}


def sanitize_c(text: str) -> tuple[str, list[str]]:
    """Remove comments and literal bodies while retaining code positions."""
    output: list[str] = []
    findings: list[str] = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        following = text[index + 1] if index + 1 < length else ""
        if char == "/" and following == "/":
            output.extend("  ")
            index += 2
            while index < length and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and following == "*":
            output.extend("  ")
            index += 2
            closed = False
            while index < length:
                if index + 1 < length and text[index : index + 2] == "*/":
                    output.extend("  ")
                    index += 2
                    closed = True
                    break
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
            if not closed:
                findings.append("unterminated block comment")
            continue

        prefix_length = 0
        if text.startswith('u8"', index):
            prefix_length = 2
        elif char in "LuU" and following in "\"'":
            prefix_length = 1
            if char == "L":
                findings.append("native wide literal")

        quote_index = index + prefix_length
        if quote_index < length and text[quote_index] in "\"'":
            quote = text[quote_index]
            for _ in range(prefix_length + 1):
                output.append(" ")
            index = quote_index + 1
            escaped = False
            closed = False
            while index < length:
                literal_char = text[index]
                output.append("\n" if literal_char == "\n" else " ")
                index += 1
                if escaped:
                    escaped = False
                elif literal_char == "\\":
                    escaped = True
                elif literal_char == quote:
                    closed = True
                    break
            if not closed:
                findings.append("unterminated string or character literal")
            continue

        output.append(char)
        index += 1
    return "".join(output), findings


def identifiers(code: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_]\w*\b", code))


def inspect_source(
    path: pathlib.Path,
    *,
    policy: bool,
    require_checked_add: bool | None = None,
) -> list[str]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        return [f"not UTF-8: {error}"]

    code, findings = sanitize_c(text)
    tokens = identifiers(code)
    for token in sorted(tokens & BANNED_IDENTIFIERS):
        findings.append(f"forbidden native-wide identifier: {token}")

    if re.search(r"\(\s*(?:const\s+)?uint16_t\s*\*\s*\)", code):
        findings.append("native uint16_t pointer cast can violate alignment/endianness")

    guest_pointer_cast = re.compile(
        r"\(\s*(?:const\s+)?(?:void|char|unsigned\s+char|uint8_t|uint16_t|"
        r"uint32_t|uintptr_t)\s*\*?\s*\)\s*[^;\n]{0,96}\bvalue\b"
    )
    if guest_pointer_cast.search(code):
        findings.append("pointer or host integer derived from a guest .value field")

    truncated_host = re.compile(
        r"(?:uint32_t|unsigned\s+(?:int|long))\s+[A-Za-z_]\w*\s*=\s*"
        r"(?:\([^)]*\)\s*)?[^;\n]*host_base"
    )
    if truncated_host.search(code):
        findings.append("host_base is stored through a 32-bit integer")

    if policy:
        if require_checked_add is None:
            require_checked_add = True
        for token in sorted(tokens & BANNED_POLICY_CALLS):
            findings.append(f"forbidden native string/memory comparison: {token}")
        if re.search(
            r"\b[A-Za-z_]\w*\s*\.\s*value\s*(?:\+\+|--|\+=|-=|\+|-)",
            code,
        ):
            findings.append("direct guest-address arithmetic in policy source")
        if require_checked_add and "rome2_guest_add_checked" not in tokens:
            findings.append("policy source never calls rome2_guest_add_checked")
        if "main" in tokens:
            findings.append("production policy source defines a test/program entry point")

    return sorted(set(findings))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guest-h", type=pathlib.Path, required=True)
    parser.add_argument("--guest-c", type=pathlib.Path, required=True)
    parser.add_argument("--policy-h", type=pathlib.Path, required=True)
    parser.add_argument("--policy-c", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = {
        "guest_h": (args.guest_h, False, False),
        "guest_c": (args.guest_c, False, False),
        "policy_h": (args.policy_h, True, False),
        "policy_c": (args.policy_c, True, True),
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total_findings = 0
    for label, (path, is_policy, require_checked_add) in paths.items():
        resolved = path.resolve(strict=True)
        file_findings = inspect_source(
            resolved,
            policy=is_policy,
            require_checked_add=require_checked_add,
        )
        total_findings += len(file_findings)
        report["files"][label] = {
            "path": str(resolved),
            "findings": file_findings,
        }
    if total_findings:
        report["status"] = "fail"
    report["finding_count"] = total_findings
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total_findings == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
