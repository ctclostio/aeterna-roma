#!/usr/bin/env python3
"""Milestone-specific semantic gate for startup ABI evidence artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


WORKERS = ("E01", "E02", "E03", "E04")
EXACT_CLAIMS = {
    "E01": {
        "E01.cleanup-mechanics": "CALLER_CLEANUP_GROUPED_24;CALLEE_CLEANUP_0",
        "E01.convention-restraint": "CONVENTION_NAME_NOT_FROZEN",
        "E01.packet-slot-order": (
            "P1_ESI;P2_EBP_PLUS_0C;P3_EDI;P4_EBP_PLUS_24"
        ),
        "E01.prior-load-restraint": "ESI_EDI_PRIOR_LOADS_NOT_FULL_DEF_USE",
    },
    "E02": {
        "E02.entry-layout": (
            "RETURN_E0;P1_E0_PLUS_4;P2_E0_PLUS_8;"
            "P3_E0_PLUS_12;P4_E0_PLUS_16"
        ),
        "E02.consumed-positions": (
            "READ_P1_ONCE;READ_P3_ONCE;P2_UNREAD;P4_UNREAD"
        ),
    },
    "E03": {
        "E03.local-frame-rows": (
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
        "E03.indirect-seams": "0x100ED49E_FF5254;0x100ED4FE_FF10",
        "E03.return-value-contract": "RETURN_VALUE_UNSPECIFIED",
        "E03.caller-return-use": "RETURN_VALUE_IGNORED_BY_CALLERS",
        "E03.termination-contract": "TERMINATION_NOT_GUARANTEED",
        "E03.canonical-return-count": "ONE_BARE_RETURN",
    },
    "E04": {
        "E04.empty-copy-decision": "GO_EMPTY_ONLY",
        "E04.full-copy-decision": "NO_GO_FULL_FUNCTION_ALLOCATOR_PATH",
        "E04.string-scan-decision": "NO_GO_UNBOUNDED_SCAN",
        "E04.release-decision": "NO_GO_OWNING_RELEASE_CALLBACK_PATH",
        "E04.platform-decision": "NO_GO_PLATFORM_BOUND",
    },
}

EXPECTED_SOURCES = {
    "E01.cleanup-mechanics": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.convention-restraint": "docs/x64_startup_100ed3c0_abi_contract.md",
    "E01.packet-slot-order": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E01.prior-load-restraint": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.entry-layout": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E02.consumed-positions": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.local-frame-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.transient-stack": "scripts/x64_startup_100ed3c0_abi_fixture.json",
    "E03.caller-continuation-rows": "scripts/x64_startup_100ed3c0_abi_fixture.json",
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
        if fact_id in result:
            issues.append(f"{worker_id}: duplicate fact_id {fact_id}")
            continue
        value = claim.get("value")
        if not isinstance(value, str) or not value:
            issues.append(f"{worker_id}: {fact_id} value is not a nonempty string")
        result[fact_id] = claim
    return result


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
        if negative_before or negative_after or "convention_name_not_frozen" in clause:
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
        claims_by_worker[worker_id] = _claim_map(document, worker_id, issues)

    for worker_id, required in EXACT_CLAIMS.items():
        claims = claims_by_worker.get(worker_id, {})
        for fact_id, expected in required.items():
            claim = claims.get(fact_id)
            if claim is None:
                issues.append(f"{worker_id}: missing required fact {fact_id}")
            elif claim.get("value") != expected:
                issues.append(
                    f"{worker_id}: {fact_id} value is not the frozen semantic token"
                )

    for fact_id, expected_source in EXPECTED_SOURCES.items():
        worker_id = fact_id.split(".", 1)[0]
        claim = claims_by_worker.get(worker_id, {}).get(fact_id)
        if claim is not None and claim.get("source_path") != expected_source:
            issues.append(f"{worker_id}: {fact_id} is not sourced to {expected_source}")

    e01 = documents.get("E01")
    if e01 is not None:
        text = json.dumps(e01, sort_keys=True).lower()
        if _has_positive_convention_label(text, "stdcall"):
            issues.append("E01: affirmative stdcall label is forbidden at this boundary")

    e02 = documents.get("E02")
    if e02 is not None:
        text = json.dumps(e02, sort_keys=True).lower().replace(" ", "")
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

    e03 = documents.get("E03")
    if e03 is not None:
        text = json.dumps(e03, sort_keys=True).lower()
        required_raw_tokens = (
            "81ec0c090000",
            "0x100ed434",
            "0x100ed471",
            "0x100ed4d4",
            "0x100ed4db",
            "0x100ed500",
            "0x100ed50b",
            "0x100ed548",
            "81c40c090000",
            "0x100ed54f",
            "0x100edf2d",
            "0x100edf2f",
            "0x100edf34",
            "0x100edf39",
            "0x100edf3e",
            "0x100edf80",
            "0x100edf82",
            "0x100edf87",
            "0x100edf8c",
            "0x100edf91",
        )
        for token in required_raw_tokens:
            if token not in text:
                issues.append(f"E03: missing frame/return evidence token {token}")
        if "cdecl-style" in text or re.search(r"consistent with[^.\n]*cdecl", text):
            issues.append("E03: cdecl-style inference is forbidden at this boundary")
        if _has_affirmative_two_bare_returns(text):
            issues.append("E03: canonical body was misstated as having two bare returns")

    e04 = documents.get("E04")
    if e04 is not None:
        conclusion = e04.get("conclusion")
        if not isinstance(conclusion, str):
            issues.append("E04: conclusion is not a string")
        else:
            normalized = conclusion.lower()
            if "empty" not in normalized or "0x100f1aa0" not in normalized:
                issues.append("E04: conclusion does not select the empty 0x100f1aa0 slice")
            affirmative = re.sub(r"\bno[-_ ]?go\b", "deferred", normalized)
            unsafe_go = re.search(
                r"\bgo\b[^.\n]*(?:0x100f1bb0|0x100f1cc0|0x100df270)",
                affirmative,
            )
            if unsafe_go:
                issues.append("E04: conclusion recommends an unsafe full-function path")
            if "preceding count field" in normalized:
                issues.append("E04: allocator/base bookkeeping was mislabeled as a count field")
            if not (
                "0x11af4090" in normalized
                and "guest identity" in normalized
                and "native pointer" in normalized
                and re.search(r"(?:never|not)[^.\n]{0,48}native pointer", normalized)
            ):
                issues.append("E04: conclusion omits the guest-identity/native-pointer restraint")
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
