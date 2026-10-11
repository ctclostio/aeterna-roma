#!/usr/bin/env python3
"""Verify the x64 entry-policy probe link-map containment boundary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence


REQUIRED_SYMBOL_ORIGINS = (
    ("Rome2Guest32ProbeAbiVersion", r"(?:^|\s)probe_dll\.c\.obj(?:\s|$)"),
    ("Rome2Guest32ProbeSelectEntryPolicy", r"(?:^|\s)probe_dll\.c\.obj(?:\s|$)"),
    (
        "rome2_port_100edd70_select_invalid_parameter_policy",
        r"rome2_guest32_runtime(?:\.lib)?\s*(?::|\()\s*"
        r"ported_100edd70_policy\.c\.obj\)?(?:\s|$)",
    ),
    (
        "rome2_guest_read_u16_le",
        r"rome2_guest32_runtime(?:\.lib)?\s*(?::|\()\s*"
        r"guest32\.c\.obj\)?(?:\s|$)",
    ),
)
EXPECTED_RUNTIME_MEMBERS = {
    "ported_100edd70_policy.c.obj",
    "guest32.c.obj",
}
FORBIDDEN_MARKERS = (
    "ported_1093c450",
    "rome2_port_1093c450",
    "decomp_fn_1093c450",
    "100e81a0",
    "100ed3c0",
)
MAX_MAP_BYTES = 64 * 1024 * 1024


def _inspect(text: str) -> list[str]:
    failures: list[str] = []
    lowered = text.casefold()

    lines = text.splitlines()
    for symbol, origin_pattern in REQUIRED_SYMBOL_ORIGINS:
        symbol_pattern = re.compile(
            rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])"
        )
        symbol_lines = [line for line in lines if symbol_pattern.search(line)]
        if not symbol_lines:
            failures.append(f"required linked symbol is absent: {symbol}")
        elif not any(re.search(origin_pattern, line, re.IGNORECASE) for line in symbol_lines):
            failures.append(
                f"required linked symbol has the wrong object origin: {symbol}"
            )

    runtime_member_pattern = re.compile(
        r"rome2_guest32_runtime(?:\.lib)?\s*(?::|\()\s*"
        r"([A-Za-z0-9_.-]+\.obj)\)?",
        re.IGNORECASE,
    )
    actual_runtime_members = {
        match.group(1).casefold() for match in runtime_member_pattern.finditer(text)
    }
    expected_runtime_members = {member.casefold() for member in EXPECTED_RUNTIME_MEMBERS}
    if actual_runtime_members != expected_runtime_members:
        failures.append(
            "runtime archive membership is not exact: expected "
            f"{sorted(expected_runtime_members)}, found {sorted(actual_runtime_members)}"
        )

    for marker in FORBIDDEN_MARKERS:
        if marker.casefold() in lowered:
            failures.append(f"unrelated or forbidden slice reached the link map: {marker}")

    return failures


def _read_map(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"not a regular link map: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_MAP_BYTES:
        raise ValueError(f"link-map size outside gate bounds: {size} bytes")
    data = path.read_bytes()
    if b"\0" in data:
        raise ValueError("link map contains a NUL byte")
    try:
        return data.decode("utf-8-sig", "strict")
    except UnicodeDecodeError:
        return data.decode("cp1252", "strict")


def _self_test() -> None:
    good = """
rome2_guest32_probe64
Rome2Guest32ProbeAbiVersion probe_dll.c.obj
Rome2Guest32ProbeSelectEntryPolicy probe_dll.c.obj
rome2_port_100edd70_select_invalid_parameter_policy rome2_guest32_runtime:ported_100edd70_policy.c.obj
rome2_guest_read_u16_le rome2_guest32_runtime:guest32.c.obj
"""
    assert _inspect(good) == []

    missing = good.replace("rome2_guest_read_u16_le", "missing_helper")
    assert any("rome2_guest_read_u16_le" in item for item in _inspect(missing))

    unrelated = good + "\nrome2_guest32_runtime:ported_1093c450.c.obj\n"
    assert any("ported_1093c450" in item for item in _inspect(unrelated))

    detached = good.replace(
        "rome2_port_100edd70_select_invalid_parameter_policy "
        "rome2_guest32_runtime:ported_100edd70_policy.c.obj",
        "rome2_port_100edd70_select_invalid_parameter_policy wrong_stub.c.obj\n"
        "unused rome2_guest32_runtime:ported_100edd70_policy.c.obj",
    )
    assert any("wrong object origin" in item for item in _inspect(detached))

    extra_member = good + "\nextra rome2_guest32_runtime:unrelated.c.obj\n"
    assert any("membership is not exact" in item for item in _inspect(extra_member))
    print("probe containment gate self-test passed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--map", type=Path, help="MSVC link map for the probe DLL")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.self_test:
        if args.map is not None:
            parser.error("--self-test cannot be combined with --map")
        _self_test()
        return 0
    if args.map is None:
        parser.error("--map is required unless --self-test is used")

    failures = _inspect(_read_map(args.map))
    print(
        json.dumps(
            {
                "gate": "x64_entry_policy_probe_containment_v1",
                "map": str(args.map),
                "passed": not failures,
                "failures": failures,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"probe containment gate infrastructure failure: {exc}", file=sys.stderr)
        raise SystemExit(2)
