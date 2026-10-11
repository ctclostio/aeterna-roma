#!/usr/bin/env python3
"""Reciprocal tests for the startup ABI evidence semantic gate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from pi_startup_abi_evidence_gate_v2 import (
    CLAIM_COUNT_RANGES,
    EXACT_CLAIMS,
    EXACT_CONCLUSIONS,
    EXPECTED_INFERENCE,
    EXPECTED_SOURCES,
    WORKERS,
    check_evidence_root,
)


FIXTURE_SOURCE = "scripts/x64_startup_100ed3c0_abi_fixture.json"
GATE_SOURCE = "scripts/pi_startup_abi_evidence_gate_v2.py"
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
def read_recipe(source_path):
    return "read " + json.dumps(
        {"path": source_path, "offset": 0, "limit": 20000},
        separators=(",", ":"),
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
                    "locator": "complete source",
                    "extractor_command": read_recipe(source_path),
                    "inference": EXPECTED_INFERENCE[fact_id],
                }
            )
        minimum_claims = CLAIM_COUNT_RANGES[worker_id][0]
        if len(claims) != minimum_claims:
            raise AssertionError(
                f"{worker_id} fixture has {len(claims)} claims, expected {minimum_claims}"
            )
        documents[worker_id] = {
            "worker_id": worker_id,
            "stage": "E",
            "conclusion": EXACT_CONCLUSIONS[worker_id],
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

    def test_accepts_whitespace_normalized_frozen_conclusion(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] = documents["E03"]["conclusion"].replace(
            "; caller", ";\ncaller"
        )
        self.assertEqual(self.run_gate(documents), [])

    def test_rejects_red_team_conclusion_bypasses(self):
        mutations = {
            "E01": "This boundary is cdecl and the ESI source is [EBP+8].",
            "E02": (
                "0x100ed50b loads E0-60; the scan is exhaustive and canonical "
                "param_2 corroborates P2_UNREAD."
            ),
            "E03": (
                "0x100ed434 belongs to the callee frame; a pair of bare return "
                "statements always terminates and callers inspect EAX."
            ),
            "E04": "It is false that " + EXACT_CONCLUSIONS["E04"],
        }
        for worker_id, conclusion in mutations.items():
            with self.subTest(worker_id=worker_id):
                documents = valid_documents()
                documents[worker_id]["conclusion"] = conclusion
                self.assertIn(
                    f"{worker_id}: conclusion is not the frozen semantic conclusion",
                    self.run_gate(documents),
                )

    def test_rejects_malformed_json(self):
        issues = self.run_gate(valid_documents(), malformed_worker="E03")
        self.assertTrue(any("E03: invalid UTF-8 JSON" in issue for issue in issues))

    def test_rejects_missing_required_fact(self):
        documents = valid_documents()
        documents["E01"]["claims"] = documents["E01"]["claims"][1:]
        issues = self.run_gate(documents)
        self.assertTrue(any("E01.cleanup-mechanics" in issue for issue in issues))

    def test_rejects_unknown_padding_even_at_exact_count(self):
        documents = valid_documents()
        documents["E01"]["claims"][-1] = {
            "fact_id": "E01.meaningless-padding",
            "kind": "bounded-detail",
            "value": "X",
            "source_path": FIXTURE_SOURCE,
            "source_sha256": "0" * 64,
            "locator": "fixture",
            "extractor_command": read_recipe(FIXTURE_SOURCE),
            "inference": False,
        }
        issues = self.run_gate(documents)
        self.assertTrue(any("unknown fact E01.meaningless-padding" in issue for issue in issues))
        self.assertTrue(any("E01.no-handler-window-sha256" in issue for issue in issues))

    def test_rejects_nested_value(self):
        documents = valid_documents()
        documents["E03"]["claims"][0]["value"] = {"not": "a string"}
        issues = self.run_gate(documents)
        self.assertTrue(any("value is not a nonempty string" in issue for issue in issues))

    def test_rejects_semantic_text_in_frozen_metadata(self):
        mutations = (
            ("kind", "TWO_BARE_RETURNS", "kind must be contract"),
            (
                "locator",
                "0x100ed434 is a local and callers inspect EAX",
                "locator must be complete source",
            ),
        )
        for field, value, expected in mutations:
            with self.subTest(field=field):
                documents = valid_documents()
                documents["E03"]["claims"][0][field] = value
                self.assertTrue(
                    any(expected in issue for issue in self.run_gate(documents))
                )

    def test_rejects_semantic_text_in_blockers(self):
        documents = valid_documents()
        documents["E04"]["blockers"] = [
            "0x100f1bb0 is safe to port despite the frozen conclusion"
        ]
        self.assertIn(
            "E04: blockers must be an empty array",
            self.run_gate(documents),
        )

    def test_rejects_stdcall_label(self):
        documents = valid_documents()
        documents["E01"]["conclusion"] = "stdcall-style caller cleanup"
        issues = self.run_gate(documents)
        self.assertIn(
            "E01: affirmative stdcall label is forbidden at this boundary", issues
        )

    def test_rejects_unfrozen_negative_stdcall_paraphrase(self):
        documents = valid_documents()
        documents["E01"]["conclusion"] = (
            "The boundary is not stdcall-style; its convention name is not frozen."
        )
        self.assertIn(
            "E01: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

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

    def test_rejects_modified_frame_boundary_fact(self):
        documents = valid_documents()
        for claim in documents["E03"]["claims"]:
            if claim["fact_id"] == "E03.frame-boundary-rows":
                claim["value"] = claim["value"].replace(
                    "ESP_MINUS_2320_TO_MINUS_2316", "ESP_MINUS_2320_TO_ZERO"
                )
        issues = self.run_gate(documents)
        self.assertTrue(any("E03.frame-boundary-rows" in issue for issue in issues))

    def test_rejects_missing_each_required_e03_audit_fact(self):
        required = (
            "E03.frame-boundary-rows",
            "E03.local-frame-rows",
            "E03.transient-stack",
            "E03.caller-continuation-rows",
            "E03.entry-position-rows",
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
            "E03.frame-boundary-rows",
            "E03.local-frame-rows",
            "E03.transient-stack",
            "E03.caller-continuation-rows",
            "E03.entry-position-rows",
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

    def test_rejects_unfrozen_two_return_negation_paraphrase(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] += (
            " There is one bare return, not two bare return statements."
        )
        self.assertIn(
            "E03: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

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

    def test_rejects_unfrozen_convention_paraphrase(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] += " cdecl/stdcall names remain unfrozen."
        self.assertIn(
            "E03: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

    def test_rejects_e02_local_write_misstated_as_read(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += (
            " The reads at 0x100ed4db and 0x100ed50b touch E0-60."
        )
        issues = self.run_gate(documents)
        self.assertIn("E02: 0x100ed50b was misstated as a read", issues)

    def test_rejects_unfrozen_e02_local_write_paraphrase(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += " 0x100ed50b is a write."
        self.assertIn(
            "E02: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

    def test_rejects_unfrozen_e02_not_read_paraphrase(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += " 0x100ed50b is never a read."
        self.assertIn(
            "E02: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

    def test_rejects_e02_scan_coverage_overclaim(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += (
            " The bounded scan provably covers all entry-stack candidates."
        )
        issues = self.run_gate(documents)
        self.assertIn("E02: bounded direct-ESP scan coverage was overstated", issues)

    def test_rejects_unfrozen_negated_scan_paraphrase(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += (
            " The bounded scan does not cover all entry-stack candidates."
        )
        self.assertIn(
            "E02: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

    def test_rejects_e02_cross_source_consistency_claim(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += (
            " Canonical param_2 absence is consistent with the machine finding P2_UNREAD."
        )
        issues = self.run_gate(documents)
        self.assertIn(
            "E02: canonical variable observation was merged with machine inference",
            issues,
        )

    def test_rejects_unfrozen_cross_source_restraint_paraphrase(self):
        documents = valid_documents()
        documents["E02"]["conclusion"] += (
            " Canonical absence is not claimed consistent with P2_UNREAD."
        )
        self.assertIn(
            "E02: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

    def test_rejects_e03_caller_position_as_local(self):
        documents = valid_documents()
        documents["E03"]["conclusion"] += (
            " At 0x100ed434 the source is a local dword."
        )
        issues = self.run_gate(documents)
        self.assertIn("E03: 0x100ed434 was misclassified as a local operand", issues)

    def test_rejects_unfrozen_e03_not_local_paraphrase(self):
        for wording in ("not a local", "never a local"):
            with self.subTest(wording=wording):
                documents = valid_documents()
                documents["E03"]["conclusion"] += f" 0x100ed434 is {wording}."
                self.assertIn(
                    "E03: conclusion is not the frozen semantic conclusion",
                    self.run_gate(documents),
                )

    def test_rejects_wrong_required_inference_flag(self):
        documents = valid_documents()
        for claim in documents["E04"]["claims"]:
            if claim["fact_id"] == "E04.release-callee-audit":
                claim["inference"] = False
        issues = self.run_gate(documents)
        self.assertTrue(any("E04.release-callee-audit inference" in issue for issue in issues))

    def test_inference_map_is_exhaustive(self):
        all_exact_facts = {
            fact_id
            for worker_claims in EXACT_CLAIMS.values()
            for fact_id in worker_claims
        }
        self.assertEqual(set(EXPECTED_INFERENCE), all_exact_facts)

    def test_rejects_direct_fact_marked_as_inference(self):
        documents = valid_documents()
        for claim in documents["E04"]["claims"]:
            if claim["fact_id"] == "E04.guest-identity-restraint":
                claim["inference"] = True
        issues = self.run_gate(documents)
        self.assertTrue(
            any("E04.guest-identity-restraint inference" in issue for issue in issues)
        )

    def test_rejects_role_specific_claim_count(self):
        documents = valid_documents()
        template = copy.deepcopy(documents["E04"]["claims"][-1])
        while len(documents["E04"]["claims"]) <= 14:
            clone = copy.deepcopy(template)
            clone["fact_id"] = f"E04.extra-{len(documents['E04']['claims'])}"
            documents["E04"]["claims"].append(clone)
        issues = self.run_gate(documents)
        self.assertTrue(any("E04: claim count 15 is outside 12-12" in issue for issue in issues))

    def test_rejects_pseudo_extractor_recipe(self):
        documents = valid_documents()
        documents["E02"]["claims"][0]["extractor_command"] = (
            "grep --literal fixture then read same file"
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("E02.entry-layout extractor_command" in issue for issue in issues))

    def test_rejects_incomplete_or_unsafe_extractor_recipes(self):
        bad_recipes = {
            "path-only read": 'read {"path":"' + FIXTURE_SOURCE + '"}',
            "zero read": (
                'read {"path":"' + FIXTURE_SOURCE + '","offset":0,"limit":0}'
            ),
            "empty grep": (
                'grep {"path":"' + FIXTURE_SOURCE
                + '","pattern":"","literal":true,"limit":10}'
            ),
            "whitespace grep": (
                'grep {"path":"' + FIXTURE_SOURCE
                + '","pattern":"   ","literal":true,"limit":10}'
            ),
            "nonliteral grep": (
                'grep {"path":"' + FIXTURE_SOURCE
                + '","pattern":"entry","literal":false,"limit":10}'
            ),
            "unbounded grep": (
                'grep {"path":"' + FIXTURE_SOURCE
                + '","pattern":"entry","literal":true}'
            ),
            "partial full-source read": (
                'read {"path":"' + FIXTURE_SOURCE
                + '","offset":0,"limit":1}'
            ),
            "offset beyond eof": (
                'read {"path":"' + FIXTURE_SOURCE
                + '","offset":999999,"limit":1}'
            ),
            "traversal": (
                'read {"path":"X:/decompilation/tmp/../' + FIXTURE_SOURCE
                + '","offset":0,"limit":10}'
            ),
            "suffix confusion": (
                'read {"path":"evil' + FIXTURE_SOURCE
                + '","offset":0,"limit":10}'
            ),
            "relative prefix confusion": (
                'read {"path":"evil/' + FIXTURE_SOURCE
                + '","offset":0,"limit":10}'
            ),
            "unrelated absolute suffix": (
                'read {"path":"X:/definitely-not-the-workspace/' + FIXTURE_SOURCE
                + '","offset":0,"limit":20000}'
            ),
        }
        for label, recipe in bad_recipes.items():
            with self.subTest(label=label):
                documents = valid_documents()
                documents["E02"]["claims"][0]["extractor_command"] = recipe
                issues = self.run_gate(documents)
                self.assertTrue(
                    any(
                        "E02.entry-layout" in issue and "extractor_command" in issue
                        for issue in issues
                    )
                )

    def test_rejects_partial_grep_for_frozen_fact(self):
        documents = valid_documents()
        documents["E02"]["claims"][0]["extractor_command"] = (
            'grep {"path":"X:/decompilation/'
            + FIXTURE_SOURCE
            + '","pattern":"entry_stack_positions","literal":true,"limit":10}'
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("must read its complete source" in issue for issue in issues))

    def test_accepts_absolute_structured_read_recipe(self):
        documents = valid_documents()
        documents["E02"]["claims"][0]["extractor_command"] = (
            'read {"path":"X:/decompilation/'
            + FIXTURE_SOURCE
            + '","offset":0,"limit":20000}'
        )
        self.assertEqual(self.run_gate(documents), [])

    def test_rejects_unsafe_go_conclusion(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "GO for 0x100f1aa0, 0x100f1bb0, and 0x100f1cc0."
        )
        issues = self.run_gate(documents)
        self.assertTrue(any("unsafe full-function" in issue for issue in issues))

    def test_rejects_unfrozen_safe_e04_paraphrase(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "The smallest independently portable slice is the empty-only "
            "0x100f1aa0 slice. Do not GO with 0x100f1bb0, 0x100f1cc0, or "
            "0x100df270. 0x11af4090 is a 32-bit guest identity and is never "
            "a native pointer."
        )
        self.assertIn(
            "E04: conclusion is not the frozen semantic conclusion",
            self.run_gate(documents),
        )

    def test_rejects_address_before_unsafe_go(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] += " 0x100f1bb0 is GO."
        issues = self.run_gate(documents)
        self.assertIn("E04: conclusion recommends an unsafe full-function path", issues)

    def test_rejects_rejection_of_empty_slice(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "Reject the empty 0x100f1aa0 slice. "
            "0x11af4090 is a 32-bit guest identity and is never a native pointer."
        )
        issues = self.run_gate(documents)
        self.assertIn(
            "E04: conclusion does not select the empty 0x100f1aa0 slice", issues
        )

    def test_rejects_guest_identity_negation(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "The smallest independently portable slice is the empty-only "
            "0x100f1aa0 slice. 0x11af4090 is not a guest identity and is never "
            "a native pointer."
        )
        issues = self.run_gate(documents)
        self.assertIn(
            "E04: conclusion contradicts the guest/native identity restraint", issues
        )

    def test_rejects_not_merely_native_pointer(self):
        documents = valid_documents()
        documents["E04"]["conclusion"] = (
            "The smallest independently portable slice is the empty-only "
            "0x100f1aa0 slice. 0x11af4090 is a 32-bit guest identity and is "
            "not merely a native pointer."
        )
        issues = self.run_gate(documents)
        self.assertIn(
            "E04: conclusion contradicts the guest/native identity restraint", issues
        )

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

    def test_rejects_any_semantic_gate_as_optional_claim_source(self):
        for gate_source in (
            "scripts/pi_startup_abi_evidence_gate.py",
            "scripts/pi_startup_abi_evidence_gate_v2.py",
        ):
            with self.subTest(gate_source=gate_source):
                documents = valid_documents()
                documents["E01"]["claims"].append(
                    {
                        "fact_id": "E01.optional-gate-derived",
                        "kind": "bounded-detail",
                        "value": "OPTIONAL_GATE_DERIVED_DETAIL",
                        "source_path": gate_source,
                        "source_sha256": "0" * 64,
                        "locator": "constant",
                        "extractor_command": read_recipe(gate_source),
                        "inference": False,
                    }
                )
                issues = self.run_gate(documents)
                self.assertIn(
                    "E01: E01.optional-gate-derived cites a semantic gate as evidence",
                    issues,
                )

    def test_rejects_foreign_fact_id_prefix(self):
        documents = valid_documents()
        documents["E01"]["claims"][-1]["fact_id"] = "E02.foreign-detail"
        issues = self.run_gate(documents)
        self.assertTrue(any("fact_id is outside the worker prefix" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main(verbosity=2)
