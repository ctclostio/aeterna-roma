#!/usr/bin/env python3
"""Reciprocal tests for the startup ABI evidence semantic gate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from pi_startup_abi_evidence_gate import (
    EXACT_CLAIMS,
    EXPECTED_SOURCES,
    WORKERS,
    check_evidence_root,
)


FIXTURE_SOURCE = "scripts/x64_startup_100ed3c0_abi_fixture.json"
GATE_SOURCE = "scripts/pi_startup_abi_evidence_gate.py"
CALLEE_SOURCE = (
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c"
)
CALLER_SOURCE = (
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100edd70.c"
)
EMPTY_SOURCE = (
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ef330.c"
)
RELEASE_SOURCE = (
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10124e50.c"
)


def valid_documents():
    documents = {}
    for worker_id in WORKERS:
        claims = []
        for fact_id, value in EXACT_CLAIMS[worker_id].items():
            source_path = EXPECTED_SOURCES.get(fact_id, FIXTURE_SOURCE)
            claims.append(
                {
                    "fact_id": fact_id,
                    "kind": "contract",
                    "value": value,
                    "source_path": source_path,
                    "source_sha256": "0" * 64,
                    "locator": "fixture",
                    "extractor_command": "read fixture",
                    "inference": False,
                }
            )
        conclusion = "bounded evidence accepted"
        if worker_id == "E03":
            conclusion += (
                " 81ec0c090000 0x100ed471 0x100ed548 "
                "81c40c090000 0x100ed54f"
            )
        if worker_id == "E04":
            claims.append(
                {
                    "fact_id": "E04.release-callee-audit",
                    "kind": "callee-audit",
                    "value": "0x10124e50 is the admitted release callee",
                    "source_path": RELEASE_SOURCE,
                    "source_sha256": "0" * 64,
                    "locator": "callee",
                    "extractor_command": "read callee",
                    "inference": False,
                }
            )
            conclusion = (
                "Select only the empty 0x100f1aa0 slice; all full functions are "
                "NO-GO. 0x11af4090 is a guest identity, never a native pointer."
            )
        documents[worker_id] = {
            "worker_id": worker_id,
            "stage": "E",
            "conclusion": conclusion,
            "claims": claims,
            "blockers": [],
        }
    return documents


class SemanticGateTests(unittest.TestCase):
    def run_gate(self, documents, malformed_worker=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for worker_id, document in documents.items():
                directory = root / worker_id
                directory.mkdir(parents=True)
                path = directory / "evidence.json"
                if worker_id == malformed_worker:
                    path.write_text('{"broken": )', encoding="utf-8")
                else:
                    path.write_text(
                        json.dumps(document, sort_keys=True), encoding="utf-8"
                    )
            return check_evidence_root(root)

    def test_accepts_exact_contract(self):
        self.assertEqual(self.run_gate(valid_documents()), [])

    def test_rejects_malformed_json(self):
        issues = self.run_gate(valid_documents(), malformed_worker="E03")
        self.assertTrue(any("E03: invalid UTF-8 JSON" in issue for issue in issues))

    def test_rejects_missing_required_fact(self):
        documents = valid_documents()
        documents["E01"]["claims"] = documents["E01"]["claims"][1:]
        issues = self.run_gate(documents)
        self.assertTrue(any("E01.cleanup-mechanics" in issue for issue in issues))

    def test_rejects_nested_value(self):
        documents = valid_documents()
        documents["E03"]["claims"][0]["value"] = {"not": "a string"}
        issues = self.run_gate(documents)
        self.assertTrue(any("value is not a nonempty string" in issue for issue in issues))

    def test_rejects_stdcall_label(self):
        documents = valid_documents()
        documents["E01"]["conclusion"] = "stdcall-style caller cleanup"
        issues = self.run_gate(documents)
        self.assertIn(
            "E01: affirmative stdcall label is forbidden at this boundary", issues
        )

    def test_accepts_negative_stdcall_restraint(self):
        documents = valid_documents()
        documents["E01"]["conclusion"] = (
            "The boundary is not stdcall-style; its convention name is not frozen."
        )
        self.assertEqual(self.run_gate(documents), [])

    def test_rejects_ambiguous_register_slot_restraint(self):
        documents = valid_documents()
        for claim in documents["E01"]["claims"]:
            if claim["fact_id"] == "E01.prior-load-restraint":
                claim["value"] = "REGISTER_TO_CALLEE_POSITION_MAPPING_UNASSERTED"
        issues = self.run_gate(documents)
        self.assertTrue(any("E01.prior-load-restraint" in issue for issue in issues))

    def test_rejects_return_address_at_plus_four(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] = "The return address at E0+4 is read."
        issues = self.run_gate(documents)
        self.assertIn(
            "E02: entry E0+4 was misclassified as the return address", issues
        )

    def test_rejects_false_canonical_return_declaration(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] = (
            "Canonical declares undefined4 FUN_100ed3c0(undefined4 param_1)."
        )
        issues = self.run_gate(documents)
        self.assertIn(
            "E02: canonical return declaration was misstated as undefined4", issues
        )

    def test_rejects_missing_frame_raw_token(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] = documents["E03"]["conclusion"].replace(
            "0x100ed548", "restore-esi"
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("0x100ed548" in issue for issue in issues))

    def test_rejects_missing_each_required_e03_audit_fact(self):
        required = (
            "E03.local-frame-rows",
            "E03.transient-stack",
            "E03.caller-continuation-rows",
            "E03.canonical-return-count",
        )
        for fact_id in required:
            with self.subTest(fact_id=fact_id):
                documents = valid_documents()
                documents["E03"]["claims"] = [
                    claim
                    for claim in documents["E03"]["claims"]
                    if claim["fact_id"] != fact_id
                ]
                issues = self.run_gate(documents)
                self.assertTrue(any(fact_id in issue for issue in issues))

    def test_rejects_modified_e03_local_row_value(self):
        documents = valid_documents()
        for claim in documents["E03"]["claims"]:
            if claim["fact_id"] == "E03.local-frame-rows":
                claim["value"] = claim["value"].replace(
                    "E0_MINUS_60_WRITE", "E0_MINUS_60_READ"
                )
        issues = self.run_gate(documents)
        self.assertTrue(any("E03.local-frame-rows" in issue for issue in issues))

    def test_rejects_wrong_e03_audit_source(self):
        required_fixture_facts = (
            "E03.local-frame-rows",
            "E03.transient-stack",
            "E03.caller-continuation-rows",
        )
        for fact_id in required_fixture_facts:
            with self.subTest(fact_id=fact_id):
                documents = valid_documents()
                for claim in documents["E03"]["claims"]:
                    if claim["fact_id"] == fact_id:
                        claim["source_path"] = CALLEE_SOURCE
                issues = self.run_gate(documents)
                self.assertTrue(any(f"{fact_id} is not sourced" in issue for issue in issues))

    def test_rejects_two_bare_returns_claim(self):
        documents = valid_documents()
        for claim in documents["E03"]["claims"]:
            if claim["fact_id"] == "E03.canonical-return-count":
                claim["value"] = "TWO_BARE_RETURNS"
        issues = self.run_gate(documents)
        self.assertTrue(any("E03.canonical-return-count" in issue for issue in issues))

    def test_rejects_two_bare_returns_contradiction_elsewhere(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] += (
            " Locator: the two bare 'return;' exit statements."
        )
        issues = self.run_gate(documents)
        self.assertIn(
            "E03: canonical body was misstated as having two bare returns", issues
        )

    def test_accepts_explicit_two_return_negation(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] += (
            " There is one bare return, not two bare return statements."
        )
        self.assertEqual(self.run_gate(documents), [])

    def test_rejects_bundled_return_boundary_in_place_of_atomic_claims(self):
        documents = valid_documents()
        documents["E03"]["claims"] = [
            claim
            for claim in documents["E03"]["claims"]
            if not claim["fact_id"].startswith("E03.return-")
            and claim["fact_id"] != "E03.caller-return-use"
            and claim["fact_id"] != "E03.termination-contract"
        ]
        documents["E03"]["claims"].append(
            {
                "fact_id": "E03.return-boundary",
                "kind": "contract",
                "value": (
                    "RETURN_VALUE_UNSPECIFIED_AND_IGNORED;"
                    "TERMINATION_NOT_GUARANTEED"
                ),
                "source_path": CALLEE_SOURCE,
                "source_sha256": "0" * 64,
                "locator": "callee",
                "extractor_command": "read callee",
                "inference": True,
            }
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("E03.return-value-contract" in issue for issue in issues))
        self.assertTrue(any("E03.caller-return-use" in issue for issue in issues))
        self.assertTrue(any("E03.termination-contract" in issue for issue in issues))

    def test_rejects_wrong_atomic_return_source(self):
        documents = valid_documents()
        for claim in documents["E03"]["claims"]:
            if claim["fact_id"] == "E03.caller-return-use":
                claim["source_path"] = CALLEE_SOURCE
        issues = self.run_gate(documents)
        self.assertTrue(any("E03.caller-return-use is not sourced" in issue for issue in issues))

    def test_rejects_cdecl_style_inference(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] += " Mechanics are consistent with cdecl-style x86."
        issues = self.run_gate(documents)
        self.assertIn("E03: cdecl-style inference is forbidden at this boundary", issues)

    def test_rejects_unsafe_go_conclusion(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "GO for 0x100f1aa0, 0x100f1bb0, and 0x100f1cc0."
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("unsafe full-function" in issue for issue in issues))

    def test_accepts_empty_go_with_explicit_unsafe_no_go_clauses(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "GO: empty-only 0x100f1aa0 to 0x100ef330. "
            "NO-GO: 0x100f1bb0, 0x100f1cc0, and 0x100df270. "
            "0x11af4090 is a guest identity and never a native pointer."
        )
        self.assertEqual(self.run_gate(documents), [])

    def test_rejects_missing_release_callee_audit(self):
        documents = valid_documents()
        documents["E04"]["claims"] = [
            claim
            for claim in documents["E04"]["claims"]
            if claim["fact_id"] != "E04.release-callee-audit"
        ]
        issues = self.run_gate(documents)
        self.assertIn("E04: no claim audits the admitted release callee 0x10124e50", issues)

    def test_rejects_missing_guest_identity_restraint(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = "Select only the empty 0x100f1aa0 slice."
        issues = self.run_gate(documents)
        self.assertIn(
            "E04: conclusion omits the guest-identity/native-pointer restraint", issues
        )

    def test_rejects_bookkeeping_count_mislabel(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] += " The preceding count field is zero."
        issues = self.run_gate(documents)
        self.assertIn(
            "E04: allocator/base bookkeeping was mislabeled as a count field", issues
        )

    def test_rejects_getprocessheap_attributed_to_platform_callee(self):
        documents = valid_documents()
        documents["E04"]["claims"].append(
            {
                "fact_id": "E04.false-platform-detail",
                "kind": "platform",
                "value": "decomp_fn_100df270 calls GetProcessHeap",
                "source_path": (
                    "src_canonical_out/empire.retail.dll/canonical_decomp/"
                    "decomp_fn_100df270.c"
                ),
                "source_sha256": "0" * 64,
                "locator": "callee",
                "extractor_command": "read callee",
                "inference": False,
            }
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("attributes GetProcessHeap" in issue for issue in issues))

    def test_rejects_wrong_empty_branch_source(self):
        documents = valid_documents()
        for claim in documents["E04"]["claims"]:
            if claim["fact_id"] == "E04.empty-copy-decision":
                claim["source_path"] = FIXTURE_SOURCE
        issues = self.run_gate(documents)
        self.assertTrue(any("E04.empty-copy-decision is not sourced" in issue for issue in issues))

    def test_rejects_wrong_no_go_decision_source(self):
        documents = valid_documents()
        for claim in documents["E04"]["claims"]:
            if claim["fact_id"] == "E04.release-decision":
                claim["source_path"] = EMPTY_SOURCE
        issues = self.run_gate(documents)
        self.assertTrue(any("E04.release-decision is not sourced" in issue for issue in issues))

    def test_rejects_admission_gate_as_machine_fact_source(self):
        documents = valid_documents()
        for claim in documents["E01"]["claims"]:
            if claim["fact_id"] == "E01.cleanup-mechanics":
                claim["source_path"] = GATE_SOURCE
        issues = self.run_gate(documents)
        self.assertTrue(any("E01.cleanup-mechanics is not sourced" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main(verbosity=2)
