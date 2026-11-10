#!/usr/bin/env python3
"""Milestone-specific semantic gate for startup ABI evidence artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any


WORKERS = ("E01", "E02", "E03", "E04")
SEMANTIC_GATE_SOURCE_NAMES = {
    "pi_startup_abi_evidence_gate.py",
    "pi_startup_abi_evidence_gate_v2.py",
}
E04_REQUIRED_CONCLUSIONS = (
    "The smallest independently portable slice is the empty-only 0x100f1aa0 slice.",
    "0x11af4090 is a 32-bit guest identity and is never a native pointer.",
)
EXACT_CONCLUSIONS = {
    "E01": (
        "The two authenticated caller packets place ESI at P1, [EBP+0x0c] at "
        "P2, EDI at P3, and [EBP+0x24] at P4; grouped caller cleanup is 24 "
        "bytes and the convention name remains unfrozen."
    ),
    "E02": (
        "Within the bounded direct ESP+disp32 audit, P1 and P3 are each read "
        "once, P2 and P4 are unread, and alternate addressing remains unexcluded."
    ),
    "E03": (
        "The authenticated frame has one bare ret with no callee cleanup; caller "
        "cleanup is grouped, the return value is unspecified and ignored by both "
        "callers, and termination is not guaranteed."
    ),
    "E04": (
        "The smallest independently portable slice is the empty-only 0x100f1aa0 "
        "slice. The full allocator, unbounded scan, owning release, and "
        "platform-bound paths are NO-GO. 0x11af4090 is a 32-bit guest identity "
        "and is never a native pointer."
    ),
}
EXACT_CLAIMS = {
    "E01": {
        "E01.cleanup-mechanics": "CALLER_CLEANUP_GROUPED_24;CALLEE_CLEANUP_0",
        "E01.convention-restraint": "CONVENTION_NAME_NOT_FROZEN",
        "E01.packet-slot-order": (
            "P1_ESI;P2_EBP_PLUS_0C;P3_EDI;P4_EBP_PLUS_24"
        ),
        "E01.prior-load-restraint": "ESI_EDI_PRIOR_LOADS_NOT_FULL_DEF_USE",
        "E01.handler-packet-rows": (
            "0x100EDF20_FF7524;0x100EDF23_57;0x100EDF24_FF750C;"
            "0x100EDF27_56;0x100EDF28_E893F4FFFF"
        ),
        "E01.no-handler-packet-rows": (
            "0x100EDF73_FF7524;0x100EDF76_57;0x100EDF77_FF750C;"
            "0x100EDF7A_56;0x100EDF7B_E840F4FFFF"
        ),
        "E01.handler-window-sha256": (
            "HANDLER_WINDOW_SHA256_"
            "52227B99B8D956F8926EB0F02B0F3B8C62A229DEE20653B5608DC81A96E41084"
        ),
        "E01.no-handler-window-sha256": (
            "NO_HANDLER_WINDOW_SHA256_"
            "76A454A3F06C1C8DE33F0B3B0AB432E059DE9ABCA52B342B8CAC0E9F50198D6A"
        ),
    },
    "E02": {
        "E02.entry-layout": (
            "RETURN_E0;P1_E0_PLUS_4;P2_E0_PLUS_8;"
            "P3_E0_PLUS_12;P4_E0_PLUS_16"
        ),
        "E02.consumed-positions": (
            "READ_P1_ONCE;READ_P3_ONCE;P2_UNREAD;P4_UNREAD"
        ),
        "E02.local-access-rows": (
            "0x100ED4B0_898C2408090000_E0_MINUS_8_WRITE;"
            "0x100ED4BA_8984240C090000_E0_MINUS_4_WRITE;"
            "0x100ED4D4_8B9424D8080000_E0_MINUS_56_READ;"
            "0x100ED4DB_8B8424D4080000_E0_MINUS_60_READ;"
            "0x100ED500_8B9424D8080000_E0_MINUS_56_READ;"
            "0x100ED50B_C78424D408000000000000_E0_MINUS_60_WRITE"
        ),
        "E02.scan-restraint": (
            "DIRECT_ESP_DISP32_SCAN_ONLY;LOWER_BOUND_2304_IS_CONSERVATIVE;"
            "UPPER_BOUND_4096_NOT_EXHAUSTIVE;ALTERNATE_ADDRESSING_NOT_EXCLUDED"
        ),
        "E02.position-1-read": "0X100ED3ED_READS_E0_PLUS_4_CALLER_POSITION_1",
        "E02.position-3-read": "0X100ED434_READS_E0_PLUS_12_CALLER_POSITION_3",
    },
    "E03": {
        "E03.frame-boundary-rows": (
            "0x100ED3C0_81EC0C090000_ESP_0_TO_MINUS_2316;"
            "0x100ED471_56_ESP_MINUS_2316_TO_MINUS_2320;"
            "0x100ED548_5E_ESP_MINUS_2320_TO_MINUS_2316;"
            "0x100ED549_81C40C090000_ESP_MINUS_2316_TO_0;"
            "0x100ED54F_C3_RET_IMMEDIATE_0"
        ),
        "E03.local-frame-rows": (
            "0x100ED4B0_898C2408090000_E0_MINUS_8_WRITE;"
            "0x100ED4BA_8984240C090000_E0_MINUS_4_WRITE;"
            "0x100ED4D4_8B9424D8080000_E0_MINUS_56_READ;"
            "0x100ED4DB_8B8424D4080000_E0_MINUS_60_READ;"
            "0x100ED500_8B9424D8080000_E0_MINUS_56_READ;"
            "0x100ED50B_C78424D408000000000000_E0_MINUS_60_WRITE"
        ),
        "E03.transient-stack": (
            "0x100ED434_FFB42418090000_STACK_EFFECT_NEG_4;"
            "0x100ED471_ESP_DELTA_BEFORE_NEG_2316;"
            "RECOVERY_MECHANISM_NOT_AUTHENTICATED"
        ),
        "E03.caller-continuation-rows": (
            "0x100EDF2D_6A01;0x100EDF2F_E89C570200;"
            "0x100EDF34_6860650D10;0x100EDF39_E8B2710200;"
            "0x100EDF3E_83C418;0x100EDF80_6A01;"
            "0x100EDF82_E849570200;0x100EDF87_6860650D10;"
            "0x100EDF8C_E85F710200;0x100EDF91_83C418"
        ),
        "E03.entry-position-rows": (
            "0x100ED3ED_8B842410090000_E0_PLUS_4_CALLER_POSITION_1_READ;"
            "0x100ED434_FFB42418090000_E0_PLUS_12_CALLER_POSITION_3_READ"
        ),
        "E03.indirect-seams": "0x100ED49E_FF5254;0x100ED4FE_FF10",
        "E03.return-value-contract": "RETURN_VALUE_UNSPECIFIED",
        "E03.caller-return-use": "RETURN_VALUE_IGNORED_BY_CALLERS",
        "E03.termination-contract": "TERMINATION_NOT_GUARANTEED",
        "E03.canonical-return-count": "ONE_BARE_RETURN",
        "E03.caller-packet-call-sites": (
            "CALL_SITES_0X100EDF28_AND_0X100EDF7B_TARGET_0X100ED3C0"
        ),
        "E03.canonical-parameter-observation": (
            "CANONICAL_BODY_REFERENCES_PARAM_1_AND_PARAM_3_ONLY;"
            "PARAM_2_UNUSED_AFTER_DECLARATION"
        ),
    },
    "E04": {
        "E04.empty-copy-decision": "GO_EMPTY_ONLY",
        "E04.full-copy-decision": "NO_GO_FULL_FUNCTION_ALLOCATOR_PATH",
        "E04.string-scan-decision": "NO_GO_UNBOUNDED_SCAN",
        "E04.release-decision": "NO_GO_OWNING_RELEASE_CALLBACK_PATH",
        "E04.platform-decision": "NO_GO_PLATFORM_BOUND",
        "E04.f1aa0-call-boundary": (
            "CALLS_100EF330_WITH_PARAM2_INDEX_2_AND_"
            "PARAM2_INDEX_2_PLUS_IVAR1_TIMES_2"
        ),
        "E04.allocation-header-store": (
            "UVAR5_MINUS_4_STORES_100FCC80_RETURN_IVAR2"
        ),
        "E04.release-header-load": (
            "PUVAR1_MINUS_2_LOADS_IVAR2;"
            "IVAR2_NONZERO_GATES_10124E50_CALL;"
            "IVAR2_PASSED_TO_10124E50"
        ),
        "E04.release-callee-audit": (
            "10124E50_REQUIRES_SEPARATE_NATIVE_RELEASE_DESIGN"
        ),
        "E04.platform-visible-calls": (
            "LOADSTRINGW;CREATEMUTEXW;MESSAGEBOXW;SYSTEMPARAMETERSINFOW"
        ),
        "E04.allocator-visible-heap-call": (
            "100FCC80_DIRECTLY_CALLS_GETPROCESSHEAP"
        ),
        "E04.guest-identity-restraint": (
            "0X11AF4090_GUEST_IDENTITY_NOT_NATIVE_POINTER"
        ),
    },
}

CLAIM_COUNT_RANGES = {
    "E01": (8, 8),
    "E02": (6, 6),
    "E03": (12, 12),
    "E04": (12, 12),
}

EXPECTED_INFERENCE = {
    fact_id: False
    for worker_claims in EXACT_CLAIMS.values()
    for fact_id in worker_claims
}
EXPECTED_INFERENCE.update({
    "E02.scan-restraint": True,
    "E03.transient-stack": True,
    "E03.return-value-contract": True,
    "E03.caller-return-use": True,
    "E03.termination-contract": True,
    "E04.empty-copy-decision": True,
    "E04.full-copy-decision": True,
    "E04.string-scan-decision": True,
    "E04.release-decision": True,
    "E04.platform-decision": True,
    "E04.release-callee-audit": True,
})

EXPECTED_SOURCES = {
    "E01.cleanup-mechanics": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.convention-restraint": "docs/x64_startup_100ed3c0_abi_contract.md",
    "E01.packet-slot-order": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.prior-load-restraint": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.handler-packet-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.no-handler-packet-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.handler-window-sha256": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.no-handler-window-sha256": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.entry-layout": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.consumed-positions": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.local-access-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.scan-restraint": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.position-1-read": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.position-3-read": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.local-frame-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.frame-boundary-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.transient-stack": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.caller-continuation-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.entry-position-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.indirect-seams": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.return-value-contract": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ed3c0.c"
    ),
    "E03.caller-return-use": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100edd70.c"
    ),
    "E03.termination-contract": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ed3c0.c"
    ),
    "E03.canonical-return-count": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ed3c0.c"
    ),
    "E03.caller-packet-call-sites": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.canonical-parameter-observation": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ed3c0.c"
    ),
    "E04.empty-copy-decision": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ef330.c"
    ),
    "E04.full-copy-decision": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ef330.c"
    ),
    "E04.string-scan-decision": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100f1bb0.c"
    ),
    "E04.release-decision": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100f1cc0.c"
    ),
    "E04.platform-decision": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100df270.c"
    ),
    "E04.f1aa0-call-boundary": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100f1aa0.c"
    ),
    "E04.allocation-header-store": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100ef330.c"
    ),
    "E04.release-header-load": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100f1cc0.c"
    ),
    "E04.release-callee-audit": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_10124e50.c"
    ),
    "E04.platform-visible-calls": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100df270.c"
    ),
    "E04.allocator-visible-heap-call": (
        "src_canonical_out/empire.retail.dll/canonical_decomp/"
        "decomp_fn_100fcc80.c"
    ),
    "E04.guest-identity-restraint": "docs/x64_startup_100ed3c0_abi_contract.md",
}


def _load_document(path: Path, worker_id: str, issues: list[str]) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        issues.append(f"{worker_id}: cannot read {path}: {exc}")
        return None
    if not raw:
        issues.append(f"{worker_id}: evidence.json is empty")
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        issues.append(f"{worker_id}: invalid UTF-8 JSON: {exc}")
        return None
    if not isinstance(document, dict):
        issues.append(f"{worker_id}: document is not a JSON object")
        return None
    return document


def _claim_map(
    document: dict[str, Any], worker_id: str, issues: list[str]
) -> dict[str, dict[str, Any]]:
    claims = document.get("claims")
    if not isinstance(claims, list):
        issues.append(f"{worker_id}: claims is not an array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            issues.append(f"{worker_id}: claims[{index}] is not an object")
            continue
        fact_id = claim.get("fact_id")
        if not isinstance(fact_id, str) or not fact_id:
            issues.append(f"{worker_id}: claims[{index}] has no string fact_id")
            continue
        if not fact_id.startswith(worker_id + "."):
            issues.append(
                f"{worker_id}: claims[{index}] fact_id is outside the worker prefix"
            )
        if fact_id in result:
            issues.append(f"{worker_id}: duplicate fact_id {fact_id}")
            continue
        value = claim.get("value")
        if not isinstance(value, str) or not value:
            issues.append(f"{worker_id}: {fact_id} value is not a nonempty string")
        result[fact_id] = claim
    return result


@lru_cache(maxsize=128)
def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extractor_recipe_issue(claim: dict[str, Any]) -> str | None:
    """Validate one reproducible Pi read/grep recipe without executing it."""

    recipe = claim.get("extractor_command")
    if not isinstance(recipe, str) or "\n" in recipe or "\r" in recipe:
        return "extractor_command is not one single-line structured Pi recipe"
    match = re.fullmatch(r"(read|grep) (\{.*\})", recipe)
    if match is None:
        return "extractor_command must be exactly read {...} or grep {...}"
    try:
        arguments = json.loads(match.group(2))
    except json.JSONDecodeError:
        return "extractor_command argument object is not valid JSON"
    if not isinstance(arguments, dict):
        return "extractor_command arguments are not a JSON object"

    tool_name = match.group(1)
    required_keys = {
        "read": {"path", "offset", "limit"},
        "grep": {"path", "pattern", "literal", "limit"},
    }[tool_name]
    optional_keys = {"read": set(), "grep": {"ignoreCase", "limit"}}[tool_name]
    if not required_keys.issubset(arguments) or set(arguments) - (
        required_keys | optional_keys
    ):
        return "extractor_command does not have the required exact Pi arguments"
    path = arguments.get("path")
    source_path = claim.get("source_path")
    if not isinstance(path, str) or not isinstance(source_path, str):
        return "extractor_command and claim require string source paths"
    normalized_path = path.replace("\\", "/")
    normalized_source = source_path.replace("\\", "/")
    path_parts = normalized_path.split("/")
    source_parts = normalized_source.split("/")
    absolute_path = bool(
        normalized_path.startswith("/")
        or normalized_path.startswith("//")
        or re.match(r"^[A-Za-z]:/", normalized_path)
    )
    exact_relative = normalized_path == normalized_source
    absolute_suffix = absolute_path and normalized_path.endswith(
        "/" + normalized_source
    )
    if (
        ".." in path_parts
        or ".." in source_parts
        or not (exact_relative or absolute_suffix)
    ):
        return "extractor_command path is not the exact source_path or an absolute suffix"

    repository_root = Path(__file__).resolve().parent.parent
    canonical_source = repository_root.joinpath(*source_parts)
    try:
        canonical_source = canonical_source.resolve(strict=True)
        canonical_source.relative_to(repository_root)
    except (OSError, ValueError):
        return "claim source_path does not resolve to a repository file"
    if not canonical_source.is_file():
        return "claim source_path does not resolve to a repository file"
    if exact_relative:
        recipe_target = canonical_source
    else:
        try:
            recipe_target = Path(path).resolve(strict=True)
        except OSError:
            return "absolute extractor_command path does not exist"
        if not recipe_target.is_file():
            return "absolute extractor_command path is not a file"
        if _file_sha256(str(recipe_target)) != _file_sha256(str(canonical_source)):
            return "absolute extractor_command path is not an exact source copy"
    if tool_name == "grep" and (
        not isinstance(arguments.get("pattern"), str)
        or not arguments["pattern"].strip()
        or arguments.get("literal") is not True
    ):
        return "grep extractor_command requires a nonempty literal pattern"
    for numeric_name in ("offset", "limit"):
        if numeric_name in arguments and (
            not isinstance(arguments[numeric_name], int)
            or isinstance(arguments[numeric_name], bool)
            or arguments[numeric_name] < 0
        ):
            return f"extractor_command {numeric_name} is not a nonnegative integer"
    if tool_name == "read" and not (1 <= arguments["limit"] <= 20000):
        return "read extractor_command limit is outside 1-20000"
    if tool_name == "read" and arguments["offset"] >= recipe_target.stat().st_size:
        return "read extractor_command offset is at or beyond end of source"
    if claim.get("fact_id") in EXPECTED_SOURCES and (
        tool_name != "read"
        or arguments["offset"] != 0
        or arguments["limit"] < recipe_target.stat().st_size
    ):
        return "frozen fact extractor_command must read its complete source from offset 0"
    if tool_name == "grep" and "limit" in arguments and not (
        1 <= arguments["limit"] <= 1000
    ):
        return "grep extractor_command limit is outside 1-1000"
    for boolean_name in ("literal", "ignoreCase"):
        if boolean_name in arguments and not isinstance(arguments[boolean_name], bool):
            return f"extractor_command {boolean_name} is not boolean"
    return None


def _has_positive_convention_label(text: str, label: str) -> bool:
    """Reject affirmative convention labels while allowing explicit restraint."""

    lowered = text.lower()
    for match in re.finditer(rf"\b{re.escape(label)}\b", lowered):
        left = max(
            lowered.rfind(".", 0, match.start()),
            lowered.rfind(";", 0, match.start()),
            lowered.rfind("\n", 0, match.start()),
        )
        right_candidates = [
            position
            for position in (
                lowered.find(".", match.end()),
                lowered.find(";", match.end()),
                lowered.find("\n", match.end()),
            )
            if position >= 0
        ]
        right = min(right_candidates) if right_candidates else len(lowered)
        clause = lowered[left + 1 : right]
        negative_before = re.search(
            rf"\b(?:not|no|never|without)\b[^.;\n]{{0,48}}\b{re.escape(label)}\b",
            clause,
        )
        negative_after = re.search(
            rf"\b{re.escape(label)}\b[^.;\n]{{0,64}}\b(?:not|never)\s+"
            r"(?:frozen|proven|established|inferred|named)",
            clause,
        )
        restraint_after = re.search(
            rf"\b{re.escape(label)}\b[^.;\n]{{0,64}}\b"
            r"(?:unfrozen|unknown|unresolved|undetermined|unassigned)\b",
            clause,
        )
        if (
            negative_before
            or negative_after
            or restraint_after
            or "convention_name_not_frozen" in clause
        ):
            continue
        return True
    return False


def _semantic_clauses(
    document: dict[str, Any], claims: dict[str, dict[str, Any]]
) -> list[str]:
    """Return only human conclusions and claim values, split into local clauses."""

    clauses: list[str] = []
    conclusion = document.get("conclusion")
    if isinstance(conclusion, str):
        clauses.extend(re.split(r"[.\r\n]+", conclusion))
    for claim in claims.values():
        value = claim.get("value")
        if isinstance(value, str):
            clauses.extend(re.split(r"[.;\r\n]+", value))
    return [clause.strip().lower() for clause in clauses if clause.strip()]


def _occurrence_is_negated(clause: str, start: int) -> bool:
    """Recognize nearby grammatical negation before one semantic term."""

    prefix = clause[max(0, start - 72) : start]
    return bool(
        re.search(
            r"(?:\b(?:not|never|no|without|cannot|can't|isn't|wasn't|weren't)\b|"
            r"\b(?:do|does|did|is|was|were|are|can)\s+not\b|"
            r"\b(?:rather\s+than|instead\s+of|misstated\s+as|"
            r"incorrectly\s+(?:called|classified|labeled)\s+as)\b)"
            r"(?:\W+\w+){0,4}\W*$",
            prefix,
        )
    )


def _has_affirmative_pattern(clause: str, pattern: str) -> bool:
    """Return whether a regex term occurs without nearby grammatical negation."""

    return any(
        not _occurrence_is_negated(clause, match.start())
        for match in re.finditer(pattern, clause)
    )


def _has_affirmative_address_term(
    clauses: list[str], address: str, term_pattern: str
) -> bool:
    return any(
        address in clause and _has_affirmative_pattern(clause, term_pattern)
        for clause in clauses
    )


def _has_affirmative_go_for_address(clause: str, address: str) -> bool:
    if address not in clause:
        return False
    for match in re.finditer(r"\bgo\b", clause):
        prefix = clause[max(0, match.start() - 32) : match.start()]
        if re.search(
            r"(?:\bno[-_ ]?|\b(?:do|does|did)\s+not\s+|"
            r"\bnever\s+|\bnot\s+)\Z",
            prefix,
        ):
            continue
        return True
    return False


def _has_affirmative_two_bare_returns(text: str) -> bool:
    """Reject the known two-return overclaim while permitting explicit negation."""

    lowered = text.lower()
    pattern = re.compile(
        r"\b(?:two|2|both)\s+(?:bare\s+)?"
        r"(?:[\"'`]?\s*return\s*;?\s*[\"'`]?\s+"
        r"(?:exit\s+)?statements?|returns?)\b"
    )
    for match in pattern.finditer(lowered):
        left = max(
            lowered.rfind(".", 0, match.start()),
            lowered.rfind(";", 0, match.start()),
            lowered.rfind("\n", 0, match.start()),
        )
        prefix = lowered[left + 1 : match.start()]
        if re.search(
            r"\b(?:not|never|incorrect(?:ly)?|wrong(?:ly)?|rather\s+than)\b"
            r"[^.;\n]{0,24}$",
            prefix,
        ):
            continue
        return True
    return False


def check_evidence_root(root: Path) -> list[str]:
    """Return deterministic semantic-contract violations for one E-stage root."""

    issues: list[str] = []
    documents: dict[str, dict[str, Any]] = {}
    claims_by_worker: dict[str, dict[str, dict[str, Any]]] = {}
    for worker_id in WORKERS:
        path = root / worker_id / "evidence.json"
        document = _load_document(path, worker_id, issues)
        if document is None:
            continue
        documents[worker_id] = document
        if document.get("worker_id") != worker_id:
            issues.append(f"{worker_id}: worker_id does not match its directory")
        if document.get("stage") != "E":
            issues.append(f"{worker_id}: stage is not E")
        if document.get("blockers") != []:
            issues.append(f"{worker_id}: blockers must be an empty array")
        claims_by_worker[worker_id] = _claim_map(document, worker_id, issues)

        conclusion = document.get("conclusion")
        normalized_conclusion = (
            " ".join(conclusion.split())
            if isinstance(conclusion, str)
            else None
        )
        normalized_expected = re.sub(
            r"\s+", " ", EXACT_CONCLUSIONS[worker_id]
        ).strip()
        if normalized_conclusion != normalized_expected:
            issues.append(f"{worker_id}: conclusion is not the frozen semantic conclusion")

    for worker_id, required in EXACT_CLAIMS.items():
        claims = claims_by_worker.get(worker_id, {})
        for fact_id in claims:
            if fact_id not in required:
                issues.append(f"{worker_id}: unknown fact {fact_id} is not admitted")
        for fact_id, expected in required.items():
            claim = claims.get(fact_id)
            if claim is None:
                issues.append(f"{worker_id}: missing required fact {fact_id}")
            elif claim.get("value") != expected:
                issues.append(
                    f"{worker_id}: {fact_id} value is not the frozen semantic token"
                )

    for worker_id, bounds in CLAIM_COUNT_RANGES.items():
        claims = claims_by_worker.get(worker_id, {})
        if not (bounds[0] <= len(claims) <= bounds[1]):
            issues.append(
                f"{worker_id}: claim count {len(claims)} is outside "
                f"{bounds[0]}-{bounds[1]}"
            )

    for worker_id, claims in claims_by_worker.items():
        for fact_id, claim in claims.items():
            if claim.get("kind") != "contract":
                issues.append(f"{worker_id}: {fact_id} kind must be contract")
            if claim.get("locator") != "complete source":
                issues.append(
                    f"{worker_id}: {fact_id} locator must be complete source"
                )
            recipe_issue = _extractor_recipe_issue(claim)
            if recipe_issue is not None:
                issues.append(f"{worker_id}: {fact_id} {recipe_issue}")
            source_path = claim.get("source_path")
            if isinstance(source_path, str):
                source_name = source_path.replace("\\", "/").rsplit("/", 1)[-1]
                if source_name.lower() in SEMANTIC_GATE_SOURCE_NAMES:
                    issues.append(
                        f"{worker_id}: {fact_id} cites a semantic gate as evidence"
                    )

    for fact_id, expected_inference in EXPECTED_INFERENCE.items():
        worker_id = fact_id.split(".", 1)[0]
        claim = claims_by_worker.get(worker_id, {}).get(fact_id)
        if claim is not None and claim.get("inference") is not expected_inference:
            issues.append(
                f"{worker_id}: {fact_id} inference must be "
                f"{str(expected_inference).lower()}"
            )

    for fact_id, expected_source in EXPECTED_SOURCES.items():
        worker_id = fact_id.split(".", 1)[0]
        claim = claims_by_worker.get(worker_id, {}).get(fact_id)
        if claim is not None and claim.get("source_path") != expected_source:
            issues.append(f"{worker_id}: {fact_id} is not sourced to {expected_source}")

    e01 = documents.get("E01")
    if e01 is not None:
        text = ". ".join(
            _semantic_clauses(e01, claims_by_worker.get("E01", {}))
        )
        if _has_positive_convention_label(text, "stdcall"):
            issues.append("E01: affirmative stdcall label is forbidden at this boundary")

    e02 = documents.get("E02")
    if e02 is not None:
        clauses = _semantic_clauses(e02, claims_by_worker.get("E02", {}))
        semantic_text = ". ".join(clauses)
        text = semantic_text.replace(" ", "")
        bad_layouts = (
            "returnaddressate0+4",
            "e0+4isthereturnaddress",
            "returnaddress/callerposition1",
            "returnaddressslotat+4",
        )
        if any(pattern in text for pattern in bad_layouts):
            issues.append("E02: entry E0+4 was misclassified as the return address")
        if "undefined4fun_100ed3c0(" in text:
            issues.append("E02: canonical return declaration was misstated as undefined4")
        if _has_affirmative_address_term(
            clauses, "0x100ed50b", r"\breads?\b"
        ):
            issues.append("E02: 0x100ed50b was misstated as a read")
        scan_overclaim = any(
            _has_affirmative_pattern(
                clause,
                r"\b(?:provably\s+)?covers?\s+all\s+entry[- ]stack\s+candidates\b",
            )
            for clause in clauses
        )
        if scan_overclaim:
            issues.append("E02: bounded direct-ESP scan coverage was overstated")
        cross_source_merge = any(
            "p2_unread" in clause
            and _has_affirmative_pattern(clause, r"\bconsistent\s+with\b")
            for clause in clauses
        )
        if cross_source_merge:
            issues.append("E02: canonical variable observation was merged with machine inference")

    e03 = documents.get("E03")
    if e03 is not None:
        clauses = _semantic_clauses(e03, claims_by_worker.get("E03", {}))
        text = ". ".join(clauses)
        for label in ("cdecl", "stdcall"):
            if _has_positive_convention_label(text, label):
                issues.append(
                    f"E03: {label}-style inference is forbidden at this boundary"
                )
        if _has_affirmative_two_bare_returns(text):
            issues.append("E03: canonical body was misstated as having two bare returns")
        if _has_affirmative_address_term(clauses, "0x100ed434", r"\blocal\b"):
            issues.append("E03: 0x100ed434 was misclassified as a local operand")

    e04 = documents.get("E04")
    if e04 is not None:
        conclusion = e04.get("conclusion")
        if not isinstance(conclusion, str):
            issues.append("E04: conclusion is not a string")
        else:
            normalized = re.sub(r"\s+", " ", conclusion.strip()).lower()
            required_empty = E04_REQUIRED_CONCLUSIONS[0].lower()
            required_guest = E04_REQUIRED_CONCLUSIONS[1].lower()
            if required_empty not in normalized:
                issues.append("E04: conclusion does not select the empty 0x100f1aa0 slice")
            clauses = [
                clause.strip()
                for clause in re.split(r"[.;\r\n]+", normalized)
                if clause.strip()
            ]
            if any(
                _has_affirmative_go_for_address(clause, address)
                for clause in clauses
                for address in ("0x100f1bb0", "0x100f1cc0", "0x100df270")
            ):
                issues.append("E04: conclusion recommends an unsafe full-function path")
            if "preceding count field" in normalized:
                issues.append("E04: allocator/base bookkeeping was mislabeled as a count field")
            if required_guest not in normalized:
                issues.append("E04: conclusion omits the guest-identity/native-pointer restraint")
            guest_contradiction = any(
                "0x11af4090" in clause
                and "guest identity" in clause
                and not _has_affirmative_pattern(clause, r"\bguest\s+identity\b")
                for clause in clauses
            )
            native_pointer_contradiction = any(
                "0x11af4090" in clause
                and (
                    "not merely a native pointer" in clause
                    or _has_affirmative_pattern(clause, r"\bnative\s+pointer\b")
                )
                for clause in clauses
            )
            if guest_contradiction or native_pointer_contradiction:
                issues.append("E04: conclusion contradicts the guest/native identity restraint")
        e04_claims = claims_by_worker.get("E04", {})
        release_source = (
            "src_canonical_out/empire.retail.dll/canonical_decomp/"
            "decomp_fn_10124e50.c"
        )
        if not any(
            claim.get("source_path") == release_source
            for claim in e04_claims.values()
        ):
            issues.append("E04: no claim audits the admitted release callee 0x10124e50")
        platform_source = (
            "src_canonical_out/empire.retail.dll/canonical_decomp/"
            "decomp_fn_100df270.c"
        )
        for fact_id, claim in e04_claims.items():
            claim_text = json.dumps(claim, sort_keys=True).lower()
            if (
                claim.get("source_path") == platform_source
                and "getprocessheap" in claim_text
            ):
                issues.append(
                    f"E04: {fact_id} attributes GetProcessHeap to decomp_fn_100df270.c"
                )
        semantic_text = ". ".join(
            _semantic_clauses(e04, claims_by_worker.get("E04", {}))
        )
        if "both its empty and nonempty behavior are decided inside" in semantic_text:
            issues.append("E04: 0x100f1aa0-to-0x100ef330 boundary was overstated")
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root", type=Path)
    args = parser.parse_args(argv)
    issues = check_evidence_root(args.evidence_root.resolve())
    if issues:
        for issue in issues:
            print(f"FAIL {issue}")
        return 1
    print("startup ABI evidence semantic gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
