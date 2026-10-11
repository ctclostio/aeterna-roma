#!/usr/bin/env python3
"""Regression and red-team tests for pi_startup_abi_oracle_gate_v2.py."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import pi_startup_abi_oracle_gate_v2 as gate  # noqa: E402


@lru_cache(maxsize=None)
def _pin_values(authority: str) -> tuple[str, int]:
    path = REPO_ROOT.joinpath(*Path(authority).parts)
    if not path.is_file():
        raise unittest.SkipTest(
            "declared authority is absent from this checkout: " + authority
        )
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _pin(authority: str) -> dict[str, Any]:
    sha256, byte_count = _pin_values(authority)
    return {
        "path": authority,
        "sha256": sha256,
        "byte_count": byte_count,
    }


def _baseline_document(worker_id: str) -> dict[str, Any]:
    role_requirements = sorted(gate.ROLE_REQUIRED_REQUIREMENTS[worker_id])
    tests: list[dict[str, Any]] = []
    mutants: list[dict[str, Any]] = []
    for index in range(1, 9):
        test_id = f"{worker_id}.T{index}"
        mutant_id = f"{worker_id}.M{index}"
        requirements = role_requirements if index == 1 else [role_requirements[0]]
        tests.append(
            {
                "test_id": test_id,
                "requirement_ids": requirements,
                "description": " ".join(gate.TEST_MARKERS[worker_id][test_id]),
                "procedure": "Read the declared pinned inputs without executing guest code.",
                "expected": "The pristine baseline passes and the paired exact mutant fails.",
                "mutant_ids": [mutant_id],
            }
        )
        mutants.append(
            {
                "mutant_id": mutant_id,
                "critical": True,
                "description": gate.EXACT_MUTATION_DESCRIPTIONS[worker_id][mutant_id],
                "expected_killer_ids": [test_id],
            }
        )
    return {
        "worker_id": worker_id,
        "stage": "O",
        "tests": tests,
        "mutants": mutants,
        "blockers": [],
    }


class OracleGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_root = Path(self.temporary.name) / "run"
        self.oracle_root = self.run_root / "workspaces" / "oracle"
        self.context_root = self.run_root / "context" / "O"
        self._write_baseline()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _write_baseline(self) -> None:
        stage_config_path = self.run_root / "stage-config" / "O.json"
        self._write_json(stage_config_path, {"stage": "O", "workers": list(gate.WORKERS)})
        stage_config_sha256 = hashlib.sha256(stage_config_path.read_bytes()).hexdigest()
        config_sha256, _ = _pin_values(gate.V5_CONFIG_PATH)
        for worker_id in gate.WORKERS:
            self._write_json(
                self.oracle_root / worker_id / "oracle.json",
                _baseline_document(worker_id),
            )
            context = {
                "schema_version": 1,
                "run_id": self.run_root.name,
                "worker_id": worker_id,
                "stage": "O",
                "config_sha256": config_sha256,
                "stage_config_sha256": stage_config_sha256,
                "generated_utc": "2026-08-26T12:00:00+00:00",
                "declared_inputs": [
                    _pin(authority)
                    for authority in gate.FULL_V5_CONTEXT_AUTHORITIES[worker_id]
                ],
                "validation_schemas": [_pin(gate.V2_SCHEMA_PATH)],
                "dependency_stage_manifests": [],
            }
            self._write_json(self.context_root / f"{worker_id}.json", context)

    def _document(self, worker_id: str) -> dict[str, Any]:
        return json.loads(
            (self.oracle_root / worker_id / "oracle.json").read_text(encoding="utf-8")
        )

    def _save_document(self, worker_id: str, document: dict[str, Any]) -> None:
        self._write_json(self.oracle_root / worker_id / "oracle.json", document)

    def _context(self, worker_id: str) -> dict[str, Any]:
        return json.loads(
            (self.context_root / f"{worker_id}.json").read_text(encoding="utf-8")
        )

    def _save_context(self, worker_id: str, context: dict[str, Any]) -> None:
        self._write_json(self.context_root / f"{worker_id}.json", context)

    def _test(self, document: dict[str, Any], test_id: str) -> dict[str, Any]:
        return next(item for item in document["tests"] if item["test_id"] == test_id)

    def _mutant(self, document: dict[str, Any], mutant_id: str) -> dict[str, Any]:
        return next(
            item for item in document["mutants"] if item["mutant_id"] == mutant_id
        )

    def _issues(self) -> list[str]:
        return gate.check_oracle_root(self.oracle_root)

    def _assert_rejected(self, fragment: str) -> None:
        issues = self._issues()
        self.assertTrue(issues, "mutated fixture unexpectedly passed")
        self.assertTrue(
            any(fragment in issue for issue in issues),
            f"missing issue fragment {fragment!r} in:\n" + "\n".join(issues),
        )

    def test_corrected_closed_world_baseline_passes(self) -> None:
        self.assertEqual(self._issues(), [])

    def test_gate_contract_is_aligned_with_live_v5_config_and_v2_schema(self) -> None:
        config = json.loads((REPO_ROOT / gate.V5_CONFIG_PATH).read_text(encoding="utf-8"))
        workers = {
            worker["id"]: worker
            for worker in config["workers"]
            if worker.get("stage") == "O"
        }
        self.assertEqual(set(workers), set(gate.WORKERS))
        for worker_id in gate.WORKERS:
            self.assertEqual(
                tuple(workers[worker_id]["context_files"]),
                gate.FULL_V5_CONTEXT_AUTHORITIES[worker_id],
            )
            task = workers[worker_id]["task"]
            for markers in gate.TEST_MARKERS[worker_id].values():
                for marker in markers:
                    self.assertEqual(task.count(marker), 1, (worker_id, marker))
            for description in gate.EXACT_MUTATION_DESCRIPTIONS[worker_id].values():
                self.assertEqual(task.count(description), 1, (worker_id, description))

        schema = (REPO_ROOT / gate.V2_SCHEMA_PATH).read_bytes()
        self.assertEqual(hashlib.sha256(schema).hexdigest(), gate.V2_SCHEMA_SHA256)
        self.assertEqual(len(schema), gate.V2_SCHEMA_BYTE_COUNT)

    def test_result_is_deterministic_and_gate_is_read_only(self) -> None:
        files = sorted(path for path in self.run_root.rglob("*") if path.is_file())
        before = {
            path.relative_to(self.run_root).as_posix():
            (path.read_bytes(), path.stat().st_mtime_ns)
            for path in files
        }
        first = self._issues()
        second = self._issues()
        after = {
            path.relative_to(self.run_root).as_posix():
            (path.read_bytes(), path.stat().st_mtime_ns)
            for path in files
        }
        self.assertEqual(first, [])
        self.assertEqual(second, first)
        self.assertEqual(after, before)

    def test_every_corrected_test_marker_is_independently_required(self) -> None:
        for worker_id, worker_markers in gate.TEST_MARKERS.items():
            for test_id, markers in worker_markers.items():
                for marker in markers:
                    with self.subTest(worker=worker_id, test=test_id, marker=marker):
                        self._write_baseline()
                        document = self._document(worker_id)
                        test = self._test(document, test_id)
                        test["description"] = test["description"].replace(marker, "", 1)
                        self._save_document(worker_id, document)
                        self._assert_rejected(
                            f"{test_id} must contain marker exactly once: {marker}"
                        )

    def test_every_marker_rejects_duplicate_occurrence(self) -> None:
        for worker_id, worker_markers in gate.TEST_MARKERS.items():
            for test_id, markers in worker_markers.items():
                for marker in markers:
                    with self.subTest(worker=worker_id, test=test_id, marker=marker):
                        self._write_baseline()
                        document = self._document(worker_id)
                        self._test(document, test_id)["expected"] += " " + marker
                        self._save_document(worker_id, document)
                        self._assert_rejected(
                            f"{test_id} must contain marker exactly once: {marker}"
                        )

    def test_unknown_structured_marker_is_rejected(self) -> None:
        document = self._document("O01")
        self._test(document, "O01.T1")["procedure"] += " INVENTED_FACT=YES"
        self._save_document("O01", document)
        self._assert_rejected("O01.T1 has unknown marker INVENTED_FACT=YES")

    def test_every_mutant_description_is_an_exact_single_mutation(self) -> None:
        for worker_id, descriptions in gate.EXACT_MUTATION_DESCRIPTIONS.items():
            for mutant_id, description in descriptions.items():
                with self.subTest(worker=worker_id, mutant=mutant_id):
                    self._write_baseline()
                    document = self._document(worker_id)
                    self._mutant(document, mutant_id)["description"] = (
                        description + " or make a second change"
                    )
                    self._save_document(worker_id, document)
                    self._assert_rejected(
                        f"{mutant_id} description must equal exact single mutation"
                    )

    def test_mutant_prefix_without_exact_assigned_token_is_rejected(self) -> None:
        document = self._document("O03")
        self._mutant(document, "O03.M2")["description"] = (
            "EXACT_SINGLE_MUTATION: A_DIFFERENT_CHANGE"
        )
        self._save_document("O03", document)
        self._assert_rejected("O03.M2 description must equal exact single mutation")

    def test_all_mutants_must_be_critical(self) -> None:
        for invalid in (False, 1, "true", None):
            with self.subTest(invalid=invalid):
                self._write_baseline()
                document = self._document("O04")
                self._mutant(document, "O04.M4")["critical"] = invalid
                self._save_document("O04", document)
                self._assert_rejected("O04.M4 critical must be true")

    def test_document_identity_stage_keys_and_empty_blockers_are_exact(self) -> None:
        mutations = (
            ("worker_id", "O99", "worker_id does not match"),
            ("stage", "I", "stage is not O"),
            ("blockers", ["uncertain"], "blockers must be an empty array"),
        )
        for key, value, fragment in mutations:
            with self.subTest(key=key):
                self._write_baseline()
                document = self._document("O01")
                document[key] = value
                self._save_document("O01", document)
                self._assert_rejected(fragment)

        self._write_baseline()
        document = self._document("O01")
        document["extra"] = True
        self._save_document("O01", document)
        self._assert_rejected("document keys are not the exact oracle contract")

    def test_test_and_mutant_item_keys_are_exact(self) -> None:
        for collection, item_id, fragment in (
            ("tests", "O01.T1", "O01.T1 keys are not exact"),
            ("mutants", "O01.M1", "O01.M1 keys are not exact"),
        ):
            with self.subTest(collection=collection):
                self._write_baseline()
                document = self._document("O01")
                document[collection][0]["extra"] = item_id
                self._save_document("O01", document)
                self._assert_rejected(fragment)

    def test_test_ids_are_exact_eight_unique_closed_world_ids(self) -> None:
        cases = (
            (lambda tests: tests.pop(), "count 7 is not exactly 8"),
            (
                lambda tests: tests.__setitem__(
                    0, {**tests[0], "test_id": "O01.T1.suffix"}
                ),
                "unknown ID O01.T1.suffix",
            ),
            (
                lambda tests: tests.__setitem__(
                    1, {**tests[1], "test_id": "O01.T1"}
                ),
                "duplicate ID O01.T1",
            ),
        )
        for mutation, fragment in cases:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                document = self._document("O01")
                mutation(document["tests"])
                self._save_document("O01", document)
                self._assert_rejected(fragment)

    def test_mutant_ids_are_exact_eight_unique_closed_world_ids(self) -> None:
        cases = (
            (lambda mutants: mutants.pop(), "count 7 is not exactly 8"),
            (
                lambda mutants: mutants.__setitem__(
                    0, {**mutants[0], "mutant_id": "O02.M1.suffix"}
                ),
                "unknown ID O02.M1.suffix",
            ),
            (
                lambda mutants: mutants.__setitem__(
                    1, {**mutants[1], "mutant_id": "O02.M1"}
                ),
                "duplicate ID O02.M1",
            ),
        )
        for mutation, fragment in cases:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                document = self._document("O02")
                mutation(document["mutants"])
                self._save_document("O02", document)
                self._assert_rejected(fragment)

    def test_pairing_is_exact_and_reciprocal(self) -> None:
        document = self._document("O01")
        self._test(document, "O01.T1")["mutant_ids"] = ["O01.M2"]
        self._save_document("O01", document)
        self._assert_rejected("O01.T1 must name only O01.M1")

        self._write_baseline()
        document = self._document("O01")
        self._mutant(document, "O01.M1")["expected_killer_ids"] = ["O01.T2"]
        self._save_document("O01", document)
        self._assert_rejected("O01.M1 must name only O01.T1")

    def test_test_prose_fields_must_be_nonempty_strings(self) -> None:
        for key, value in (("description", ""), ("procedure", []), ("expected", None)):
            with self.subTest(key=key):
                self._write_baseline()
                document = self._document("O01")
                self._test(document, "O01.T8")[key] = value
                self._save_document("O01", document)
                self._assert_rejected(f"O01.T8 {key} is not a nonempty string")

    def test_requirement_ids_are_nonempty_unique_strings_from_allowlist(self) -> None:
        cases = (
            ([], "requirement_ids is not a nonempty array"),
            (
                ["ABI-PROV-001", "ABI-PROV-001"],
                "requirement_ids contains duplicate ABI-PROV-001",
            ),
            (["ST2-ORACLE-001"], "has forbidden requirement ST2-ORACLE-001"),
            ([7], "has non-string requirement ID"),
        )
        for value, fragment in cases:
            with self.subTest(value=value):
                self._write_baseline()
                document = self._document("O01")
                self._test(document, "O01.T2")["requirement_ids"] = value
                self._save_document("O01", document)
                self._assert_rejected(fragment)

    def test_each_role_must_cover_every_assigned_requirement(self) -> None:
        for worker_id, requirements in gate.ROLE_REQUIRED_REQUIREMENTS.items():
            for missing in requirements:
                with self.subTest(worker=worker_id, missing=missing):
                    self._write_baseline()
                    document = self._document(worker_id)
                    for test in document["tests"]:
                        test["requirement_ids"] = [
                            item for item in test["requirement_ids"] if item != missing
                        ] or [next(iter(requirements - {missing}))]
                    self._save_document(worker_id, document)
                    self._assert_rejected(f"role coverage is missing {missing}")

    def test_gate_sources_cannot_be_cited_as_evidence(self) -> None:
        for source_name in sorted(gate.GATE_SOURCE_NAMES):
            with self.subTest(source=source_name):
                self._write_baseline()
                document = self._document("O03")
                self._test(document, "O03.T4")["procedure"] += " " + source_name
                self._save_document("O03", document)
                self._assert_rejected("semantic gate is cited as oracle evidence")

    def test_every_required_context_authority_is_independently_enforced(self) -> None:
        for worker_id, authorities in gate.FULL_V5_CONTEXT_AUTHORITIES.items():
            for authority in authorities:
                with self.subTest(worker=worker_id, authority=authority):
                    self._write_baseline()
                    context = self._context(worker_id)
                    context["declared_inputs"] = [
                        item
                        for item in context["declared_inputs"]
                        if item["path"] != authority
                    ]
                    self._save_context(worker_id, context)
                    self._assert_rejected(f"required authority is undeclared: {authority}")

    def test_context_manifest_identity_and_stage_are_exact(self) -> None:
        for key, value, fragment in (
            ("worker_id", "O99", "context worker_id does not match"),
            ("stage", "E", "context stage is not O"),
        ):
            with self.subTest(key=key):
                self._write_baseline()
                context = self._context("O02")
                context[key] = value
                self._save_context("O02", context)
                self._assert_rejected(fragment)

    def test_context_pins_require_unique_path_sha256_and_byte_count(self) -> None:
        mutations = (
            (
                lambda context: context["declared_inputs"][0].__setitem__("sha256", "ABC"),
                "pin has invalid SHA-256",
            ),
            (
                lambda context: context["declared_inputs"][0].__setitem__("byte_count", -1),
                "pin has invalid byte_count",
            ),
            (
                lambda context: context["declared_inputs"].append(
                    copy.deepcopy(context["declared_inputs"][0])
                ),
                "context has duplicate authority",
            ),
        )
        for mutation, fragment in mutations:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                context = self._context("O03")
                mutation(context)
                self._save_context("O03", context)
                self._assert_rejected(fragment)

    def test_missing_or_malformed_context_fails_closed(self) -> None:
        (self.context_root / "O04.json").unlink()
        self._assert_rejected("O04 context: missing artifact")

        self._write_baseline()
        (self.context_root / "O04.json").write_text("{", encoding="utf-8")
        self._assert_rejected("O04 context: invalid UTF-8 JSON")

        self._write_baseline()
        context = self._context("O04")
        context["declared_inputs"] = "not-an-array"
        self._save_context("O04", context)
        self._assert_rejected("context declared_inputs is not an array")

    def test_missing_or_malformed_oracle_fails_closed(self) -> None:
        (self.oracle_root / "O02" / "oracle.json").unlink()
        self._assert_rejected("O02: missing artifact")

        self._write_baseline()
        (self.oracle_root / "O02" / "oracle.json").write_text("{", encoding="utf-8")
        self._assert_rejected("O02: invalid UTF-8 JSON")

    def test_duplicate_json_object_keys_are_rejected(self) -> None:
        path = self.oracle_root / "O01" / "oracle.json"
        raw = path.read_text(encoding="utf-8")
        raw = raw.replace(
            '"worker_id": "O01"',
            '"worker_id": "O01", "worker_id": "O01"',
            1,
        )
        path.write_text(raw, encoding="utf-8")
        self._assert_rejected("duplicate object key 'worker_id'")

    def test_oversized_json_is_rejected(self) -> None:
        path = self.oracle_root / "O01" / "oracle.json"
        path.write_bytes(path.read_bytes() + b" " * gate.MAX_JSON_BYTES)
        self._assert_rejected(f"JSON exceeds {gate.MAX_JSON_BYTES} bytes")

    def test_unknown_worker_directory_is_rejected(self) -> None:
        (self.oracle_root / "O99").mkdir()
        self._assert_rejected("unknown worker directory O99")

    def test_wrong_root_layout_cannot_bypass_frozen_context(self) -> None:
        loose_root = Path(self.temporary.name) / "loose"
        for worker_id in gate.WORKERS:
            self._write_json(loose_root / worker_id / "oracle.json", _baseline_document(worker_id))
        issues = gate.check_oracle_root(loose_root)
        for worker_id in gate.WORKERS:
            self.assertIn(f"{worker_id}: frozen context manifest is required", issues)

    def test_known_contradictory_prose_is_rejected_with_markers_retained(self) -> None:
        cases = (
            ("O01", "O01.T2", "P2 and P4 are globally unread under every addressing mode.", "outside the bounded direct-ESP scan"),
            ("O01", "O01.T2", "Parameter two and parameter four are unconditionally absent everywhere.", "outside the bounded direct-ESP scan"),
            ("O01", "O01.T2", "No alternate addressing is possible.", "alternate addressing is incorrectly excluded"),
            ("O02", "O02.T1", "Recompute the running ESP delta forward through critical_instructions.", "sparse fixture rows are treated as global stack flow"),
            ("O02", "O02.T1", "Allow undecoded bytes and skip gaps.", "complete 400-byte decode is allowed to contain gaps"),
            ("O02", "O02.T5", "The CFG is acyclic-in-the-analyzer.", "CFG is incorrectly called acyclic"),
            ("O02", "O02.T5", "There are only two nested back edges.", "CFG incorrectly has only two back edges"),
            ("O02", "O02.T5", "The control-flow graph contains zero loops.", "CFG is incorrectly called loop-free"),
            ("O02", "O02.T7", "Replace an unassigned opcode pattern.", "unsupported decode case is not reproducible"),
            ("O02", "O02.T3", "Every remaining register is unstable.", "register contract overclaims unclassified registers"),
            ("O02", "O02.T3", "EBX is stable.", "unproved stable register"),
            ("O03", "O03.T1", "The index rows agree on raw offsets and SHA-256 body hashes.", "misattributed raw-offset or raw-hash authority"),
            ("O03", "O03.T5", "Scan all artifacts for allocator symbols.", "allocator scan is not bounded"),
            ("O03", "O03.T7", "Never use a 64-bit temporary.", "wider temporaries are incorrectly forbidden"),
            ("O03", "O03.T8", "Delegation uses only 0x100f1c10.", "incorrectly used as native delegation"),
            ("O03", "O03.T8", "Invoke the accepted native 100f1c10 port from production.", "production native delegation"),
            ("O04", "O04.T2", "Compute rel32 against the instruction address.", "instruction address instead of next VA"),
            ("O04", "O04.T4", "All other registers are not stable.", "register contract overclaims"),
            ("O04", "O04.T6", "No symbol reference to any recovered identifier is allowed.", "inert recovered identifiers are incorrectly forbidden"),
            ("O04", "O04.T6", "The original empire.retail.dll may be dynamically loaded and executed.", "original DLL is incorrectly allowed"),
            ("O04", "O04.T7", "Simulate BUILD_TESTING off.", "BUILD_TESTING containment is an unscoped simulation"),
            ("O04", "O04.T7", "0x100d6560 must be absent everywhere.", "legacy 0x100d6560 names are incorrectly required to be absent"),
            ("O04", "O04.T8", "Diff all outputs and workspace directory listings.", "outside-workspace writes are not observable"),
            ("O04", "O04.T8", "Writes to the repository root need not be intercepted.", "repository writes are incorrectly allowed"),
        )
        for worker_id, test_id, prose, fragment in cases:
            with self.subTest(worker=worker_id, test=test_id, prose=prose):
                self._write_baseline()
                document = self._document(worker_id)
                self._test(document, test_id)["procedure"] += " " + prose
                self._save_document(worker_id, document)
                self._assert_rejected(fragment)

    def test_wrong_rel32_equations_are_rejected_for_every_role(self) -> None:
        for worker_id, test_id in (
            ("O01", "O01.T4"),
            ("O02", "O02.T2"),
            ("O03", "O03.T2"),
            ("O04", "O04.T2"),
        ):
            for prose in (
                "Use next_va minus rel32.",
                "Compute rel32 against the instruction address.",
                "Call VA is the rel32 base.",
                "Add the signed displacement to the call opcode's address.",
            ):
                with self.subTest(worker=worker_id, prose=prose):
                    self._write_baseline()
                    document = self._document(worker_id)
                    self._test(document, test_id)["procedure"] += " " + prose
                    self._save_document(worker_id, document)
                    self._assert_rejected("rel32 uses")

    def test_one_sentence_period_after_every_exact_marker_is_accepted(self) -> None:
        for worker_id, worker_markers in gate.TEST_MARKERS.items():
            for test_id, markers in worker_markers.items():
                for marker in markers:
                    with self.subTest(worker=worker_id, test=test_id, marker=marker):
                        self._write_baseline()
                        document = self._document(worker_id)
                        test = self._test(document, test_id)
                        test["description"] = test["description"].replace(
                            marker, marker + ".", 1
                        )
                        self._save_document(worker_id, document)
                        self.assertEqual(self._issues(), [])

    def test_marker_sentence_period_normalization_has_exact_boundaries(self) -> None:
        marker = gate.TEST_MARKERS["O04"]["O04.T7"][-1]
        for suffix in ("..", ".EXTRA", "X."):
            with self.subTest(suffix=suffix):
                self._write_baseline()
                document = self._document("O04")
                test = self._test(document, "O04.T7")
                test["description"] = test["description"].replace(
                    marker, marker + suffix, 1
                )
                self._save_document("O04", document)
                self._assert_rejected("O04.T7 must contain marker exactly once")

    def test_compound_mutation_and_no_pristine_baseline_prose_are_rejected(self) -> None:
        for prose, fragment in (
            (
                "Apply the assigned mutation and also corrupt the PE magic.",
                "test procedure describes a compound mutation",
            ),
            (
                "Do not run any pristine baseline.",
                "test procedure omits the pristine baseline",
            ),
            (
                "Apply multiple changes to the disposable body.",
                "test procedure describes a compound mutation",
            ),
            (
                "The pristine baseline is optional.",
                "test procedure omits the pristine baseline",
            ),
        ):
            with self.subTest(prose=prose):
                self._write_baseline()
                document = self._document("O01")
                self._test(document, "O01.T1")["procedure"] += " " + prose
                self._save_document("O01", document)
                self._assert_rejected(fragment)

    def test_nonfinite_json_numbers_fail_closed_in_oracle_and_context(self) -> None:
        for token in ("NaN", "Infinity", "-Infinity", "1e9999"):
            for target in ("oracle", "context"):
                with self.subTest(token=token, target=target):
                    self._write_baseline()
                    path = (
                        self.oracle_root / "O01" / "oracle.json"
                        if target == "oracle"
                        else self.context_root / "O01.json"
                    )
                    raw = path.read_text(encoding="utf-8")
                    if target == "oracle":
                        raw = raw.replace('"stage": "O"', f'"stage": {token}', 1)
                    else:
                        raw = raw.replace('"schema_version": 1', f'"schema_version": {token}', 1)
                    path.write_text(raw, encoding="utf-8")
                    self._assert_rejected("non-finite JSON number")

    def test_context_manifest_keys_schema_and_dependency_contract_are_exact(self) -> None:
        cases = (
            (
                lambda context: context.__setitem__("extra", True),
                "context keys are not exact",
            ),
            (
                lambda context: context.__setitem__("schema_version", True),
                "context schema_version is not exactly 1",
            ),
            (
                lambda context: context.__setitem__(
                    "generated_utc", "2026-08-26T12:00:00"
                ),
                "context generated_utc is not a UTC timestamp",
            ),
            (
                lambda context: context.__setitem__(
                    "dependency_stage_manifests", [{"stage": "E"}]
                ),
                "dependency_stage_manifests must be empty",
            ),
        )
        for mutation, fragment in cases:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                context = self._context("O01")
                mutation(context)
                self._save_context("O01", context)
                self._assert_rejected(fragment)

    def test_context_requires_exact_full_ordered_v5_authority_set(self) -> None:
        for mutation, fragment in (
            (
                lambda items: items.append(_pin(gate.V5_CONFIG_PATH)),
                "unexpected context authority",
            ),
            (
                lambda items: items.__setitem__(slice(0, 2), list(reversed(items[:2]))),
                "not the exact ordered v5 authority set",
            ),
        ):
            with self.subTest(fragment=fragment):
                self._write_baseline()
                context = self._context("O02")
                mutation(context["declared_inputs"])
                self._save_context("O02", context)
                self._assert_rejected(fragment)

    def test_context_pin_keys_and_live_hashes_cannot_be_fabricated(self) -> None:
        cases = (
            (
                lambda item: item.__setitem__("extra", "field"),
                "pin keys are not exact",
            ),
            (
                lambda item: item.__setitem__("sha256", "0" * 64),
                "SHA-256 does not match the live repository file",
            ),
            (
                lambda item: item.__setitem__("byte_count", item["byte_count"] + 1),
                "byte_count does not match the live repository file",
            ),
        )
        for mutation, fragment in cases:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                context = self._context("O03")
                mutation(context["declared_inputs"][0])
                self._save_context("O03", context)
                self._assert_rejected(fragment)

    def test_context_rejects_traversal_absolute_and_backslash_paths(self) -> None:
        unsafe_paths = (
            "../CMakeLists.txt",
            "/CMakeLists.txt",
            "C:/Windows/System32/kernel32.dll",
            "port\\x64_bootstrap\\empire_bootstrap.c",
            "docs//x64_startup_100ed3c0_abi_contract.md",
        )
        for unsafe in unsafe_paths:
            with self.subTest(path=unsafe):
                self._write_baseline()
                context = self._context("O04")
                context["declared_inputs"][0]["path"] = unsafe
                self._save_context("O04", context)
                self._assert_rejected("unsafe repository path")

    def test_context_provenance_is_safe_live_and_coherent_across_workers(self) -> None:
        cases = (
            (
                "run_id",
                "different-safe-run",
                "context run_id does not match the run directory",
            ),
            (
                "run_id",
                "../unsafe",
                "context run_id is unsafe",
            ),
            (
                "config_sha256",
                "0" * 64,
                "config_sha256 does not match live v5 config",
            ),
            (
                "stage_config_sha256",
                "0" * 64,
                "stage_config_sha256 does not match live O stage config",
            ),
        )
        for key, value, fragment in cases:
            with self.subTest(key=key, value=value):
                self._write_baseline()
                context = self._context("O02")
                context[key] = value
                self._save_context("O02", context)
                self._assert_rejected(fragment)
                if value != "../unsafe":
                    self._assert_rejected(f"context {key} is incoherent across O workers")

    def test_live_stage_config_is_required_and_hash_pinned(self) -> None:
        stage_config = self.run_root / "stage-config" / "O.json"
        stage_config.unlink()
        self._assert_rejected("O: live O stage config: missing artifact")

        self._write_baseline()
        stage_config.write_text('{"changed":true}\n', encoding="utf-8")
        self._assert_rejected("stage_config_sha256 does not match live O stage config")

    def test_validation_schema_is_exact_v2_with_live_pin(self) -> None:
        cases = (
            (
                lambda schema: schema.__setitem__("path", "scripts/pi_wave3_oracle.schema.json"),
                "validation schema is not exact v2",
            ),
            (
                lambda schema: schema.__setitem__("sha256", "0" * 64),
                "v2 schema SHA-256 pin is wrong",
            ),
            (
                lambda schema: schema.__setitem__("byte_count", 0),
                "v2 schema byte_count pin is wrong",
            ),
        )
        for mutation, fragment in cases:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                context = self._context("O04")
                mutation(context["validation_schemas"][0])
                self._save_context("O04", context)
                self._assert_rejected(fragment)

        self._write_baseline()
        context = self._context("O04")
        context["validation_schemas"].append(_pin(gate.V2_SCHEMA_PATH))
        self._save_context("O04", context)
        self._assert_rejected("must contain exactly one validation schema")

    def test_oracle_and_context_symlink_escapes_are_rejected_when_supported(self) -> None:
        external_oracle = Path(self.temporary.name) / "external-oracle.json"
        self._write_json(external_oracle, _baseline_document("O01"))
        oracle_path = self.oracle_root / "O01" / "oracle.json"
        oracle_path.unlink()
        try:
            oracle_path.symlink_to(external_oracle)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self._assert_rejected("path or symlink escapes its trusted root")

        oracle_path.unlink()
        self._write_baseline()
        external_context = Path(self.temporary.name) / "external-context.json"
        external_context.write_bytes((self.context_root / "O01.json").read_bytes())
        context_path = self.context_root / "O01.json"
        context_path.unlink()
        context_path.symlink_to(external_context)
        self._assert_rejected("path or symlink escapes its trusted root")

    def test_actual_r10_artifacts_are_rejected_for_all_four_workers(self) -> None:
        r10_root = (
            REPO_ROOT
            / "out"
            / "pi-swarm"
            / "20260825-startup-abi-wave3-r10"
            / "workspaces"
            / "oracle"
        )
        self.assertTrue(r10_root.is_dir(), f"missing frozen r10 fixture: {r10_root}")
        issues = gate.check_oracle_root(r10_root)
        self.assertTrue(issues)
        for worker_id in gate.WORKERS:
            with self.subTest(worker=worker_id):
                self.assertTrue(
                    any(issue.startswith(worker_id + ":") for issue in issues),
                    "\n".join(issues),
                )
                self.assertTrue(
                    any(
                        issue.startswith(worker_id + ":")
                        and "description must equal exact single mutation" in issue
                        for issue in issues
                    ),
                    "\n".join(issues),
                )

        expected_defect_fragments = (
            "O01.T2 P2/P4 absence is asserted outside the bounded direct-ESP scan",
            "O01: required authority is undeclared: Total War Rome II/empire.retail.dll",
            "O01.M1 description must equal exact single mutation",
            "O02.T1 sparse fixture rows are treated as global stack flow",
            "O02.T2 rel32 uses subtraction instead of next-VA plus signed displacement",
            "O02.T3 register contract invents broader preservation",
            "O02.T5 CFG incorrectly has only two back edges",
            "O02.T5 CFG is incorrectly called acyclic",
            "DECODE_COVERAGE=GAP_FREE_EXACT_400_BYTES_100ED3C0_TO_100ED550",
            "O02.T7 unsupported decode case is not reproducible",
            "O03: required authority is undeclared: Total War Rome II/empire.retail.dll",
            "O03.T1 canonical index is misattributed raw-offset or raw-hash authority",
            "O03.T5 allocator scan is not bounded to declared artifacts",
            "O03.T7 checked wider temporaries are incorrectly forbidden",
            "O03.T8 0x100f1c10 is incorrectly used as native delegation",
            "O03.M1 description must equal exact single mutation",
            "O04.T2 rel32 uses the instruction address instead of next VA",
            "O04.T4 register contract overclaims unclassified registers",
            "O04.T6 inert recovered identifiers are incorrectly forbidden",
            "O04.T7 BUILD_TESTING containment is an unscoped simulation",
            "O04.T7 legacy 0x100d6560 names are incorrectly required to be absent",
            "O04.T8 outside-workspace writes are not observable",
            "O04: required authority is undeclared: port/x64_bootstrap/empire_bootstrap.def",
            "O04: required authority is undeclared: port/x64_probe/probe_exports.def",
            "O04: required authority is undeclared: port/x64_exports/export_manifest.tsv",
            "O04: required authority is undeclared: port/x64_exports/empire.retail.exports.def",
        )
        for fragment in expected_defect_fragments:
            with self.subTest(r10_defect=fragment):
                self.assertTrue(
                    any(fragment in issue for issue in issues),
                    f"r10 did not expose {fragment!r}:\n" + "\n".join(issues),
                )

    def test_cli_exit_and_output_are_deterministic(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = gate.main([str(self.oracle_root)])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "startup ABI oracle semantic gate passed\n")

        document = self._document("O01")
        document["blockers"] = ["blocked"]
        self._save_document("O01", document)
        first = io.StringIO()
        second = io.StringIO()
        with contextlib.redirect_stdout(first):
            first_result = gate.main([str(self.oracle_root)])
        with contextlib.redirect_stdout(second):
            second_result = gate.main([str(self.oracle_root)])
        self.assertEqual(first_result, 1)
        self.assertEqual(second_result, 1)
        self.assertEqual(second.getvalue(), first.getvalue())
        self.assertIn("FAIL O01: blockers must be an empty array", first.getvalue())

    def test_unreadable_or_missing_root_fails_closed(self) -> None:
        missing = Path(self.temporary.name) / "does-not-exist"
        issues = gate.check_oracle_root(missing)
        self.assertEqual(len(issues), 1)
        self.assertIn("workspace root is unreadable", issues[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
