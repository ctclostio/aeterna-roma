#!/usr/bin/env python3
"""Regression and red-team tests for pi_startup_abi_oracle_gate_v4.py."""

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
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
V8_CONFIG_PATH = "scripts/pi_wave3_startup_abi_v8.json"
V9_CONFIG_PATH = "scripts/pi_wave3_startup_abi_v9.json"
BASELINE_DESCRIPTION_PROSE = {
    "O01": "Authenticated raw caller and callee evidence must satisfy the assigned calling-contract invariant.",
    "O02": "Complete static body analysis must satisfy the assigned decode, stack, and control-flow invariant.",
    "O03": "Authenticated empty-path evidence must satisfy the assigned boundary and containment invariant.",
    "O04": "Pinned provenance and production inputs must satisfy the assigned containment invariant.",
}
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import pi_startup_abi_oracle_gate_v4 as gate  # noqa: E402


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
                "description": (
                    BASELINE_DESCRIPTION_PROSE[worker_id]
                    + " "
                    + " ".join(gate.TEST_MARKERS[worker_id][test_id])
                ),
                "procedure": gate.EXACT_TEST_PROCEDURES[test_id],
                "expected": gate.EXACT_TEST_EXPECTATIONS[test_id],
                "mutant_ids": [mutant_id],
            }
        )
        mutants.append(
            {
                "mutant_id": mutant_id,
                "critical": True,
                "description": gate.EXACT_MUTATION_DESCRIPTIONS[worker_id][mutant_id],
                "mutation": copy.deepcopy(
                    gate.EXPECTED_MUTATION_RECORDS[mutant_id]["mutation"]
                ),
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
        out_root = REPO_ROOT / "out"
        out_root.mkdir(parents=True, exist_ok=True)
        self.config_temporary = tempfile.TemporaryDirectory(
            prefix="oracle-gate-v4-config-", dir=out_root
        )
        self.config_path = Path(self.config_temporary.name) / "calibration-config.json"
        calibration = json.loads(
            (REPO_ROOT / V9_CONFIG_PATH).read_text(encoding="utf-8")
        )
        o_gate = next(
            item for item in calibration["semantic_gates"] if item["stage"] == "O"
        )
        o_gate["script"] = "scripts/pi_startup_abi_oracle_gate_v4.py"
        o_gate["script_sha256"] = hashlib.sha256(
            Path(gate.__file__).read_bytes()
        ).hexdigest()
        self.config_path.write_text(
            json.dumps(calibration, indent=2) + "\n", encoding="utf-8"
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.run_root = Path(self.temporary.name) / "run"
        self.oracle_root = self.run_root / "workspaces" / "oracle"
        self.context_root = self.run_root / "context" / "O"
        self._write_baseline()

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.config_temporary.cleanup()

    def _write_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _write_baseline(self) -> None:
        config_path = self.config_path.resolve()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config_sha256 = hashlib.sha256(config_path.read_bytes()).hexdigest()
        o_stage = next(item for item in config["stages"] if item["id"] == "O")
        o_workers = [item for item in config["workers"] if item["stage"] == "O"]
        stage_config_path = self.run_root / "stage-config" / "O.json"
        self._write_json(
            stage_config_path,
            {
                "schema_version": 1,
                "run_id": self.run_root.name,
                "config_sha256": config_sha256,
                "stage": o_stage,
                "workers": o_workers,
            },
        )
        stage_config_sha256 = hashlib.sha256(stage_config_path.read_bytes()).hexdigest()
        self._write_json(
            self.run_root / "state.json",
            {
                "state_version": 3,
                "run_id": self.run_root.name,
                "repository_root": str(REPO_ROOT.resolve()),
                "run_root": str(self.run_root.resolve()),
                "config_path": str(config_path),
                "config_sha256": config_sha256,
                "stages": [
                    {
                        "id": "O",
                        "stage_config_file": str(stage_config_path.resolve()),
                        "stage_config_sha256": stage_config_sha256,
                    }
                ],
            },
        )
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
                    for authority in gate.FULL_V9_CONTEXT_AUTHORITIES[worker_id]
                ],
                "validation_schemas": [_pin(gate.V3_SCHEMA_PATH)],
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

    def _state(self) -> dict[str, Any]:
        return json.loads((self.run_root / "state.json").read_text(encoding="utf-8"))

    def _save_state(self, state: dict[str, Any]) -> None:
        self._write_json(self.run_root / "state.json", state)

    def _stage_config(self) -> dict[str, Any]:
        return json.loads(
            (self.run_root / "stage-config" / "O.json").read_text(encoding="utf-8")
        )

    def _save_stage_config(self, stage_config: dict[str, Any]) -> str:
        path = self.run_root / "stage-config" / "O.json"
        self._write_json(path, stage_config)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _rebind_stage_hash(self, stage_sha256: str) -> None:
        state = self._state()
        state["stages"][0]["stage_config_sha256"] = stage_sha256
        self._save_state(state)
        for worker_id in gate.WORKERS:
            context = self._context(worker_id)
            context["stage_config_sha256"] = stage_sha256
            self._save_context(worker_id, context)

    def _rebind_config_hash(self, config_path: Path, config_sha256: str) -> None:
        state = self._state()
        state["config_path"] = str(config_path.resolve())
        state["config_sha256"] = config_sha256
        self._save_state(state)
        stage_config = self._stage_config()
        stage_config["config_sha256"] = config_sha256
        stage_sha256 = self._save_stage_config(stage_config)
        state = self._state()
        state["stages"][0]["stage_config_sha256"] = stage_sha256
        self._save_state(state)
        for worker_id in gate.WORKERS:
            context = self._context(worker_id)
            context["config_sha256"] = config_sha256
            context["stage_config_sha256"] = stage_sha256
            self._save_context(worker_id, context)

    def _bind_selected_config(
        self, config_path: Path, config: dict[str, Any]
    ) -> None:
        self._write_json(config_path, config)
        config_sha256 = hashlib.sha256(config_path.read_bytes()).hexdigest()
        o_stage = next(item for item in config["stages"] if item.get("id") == "O")
        o_workers = [
            item for item in config["workers"] if item.get("stage") == "O"
        ]

        state = self._state()
        state["config_path"] = str(config_path.resolve())
        state["config_sha256"] = config_sha256
        stage_config = self._stage_config()
        stage_config["config_sha256"] = config_sha256
        stage_config["stage"] = o_stage
        stage_config["workers"] = o_workers
        stage_sha256 = self._save_stage_config(stage_config)
        state["stages"][0]["stage_config_sha256"] = stage_sha256
        self._save_state(state)
        for worker_id in gate.WORKERS:
            context = self._context(worker_id)
            context["config_sha256"] = config_sha256
            context["stage_config_sha256"] = stage_sha256
            self._save_context(worker_id, context)

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

    def test_gate_contract_is_aligned_with_v9_contexts_and_v3_schema(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        v9_config = json.loads(
            (REPO_ROOT / V9_CONFIG_PATH).read_text(encoding="utf-8")
        )
        workers = {
            worker["id"]: worker
            for worker in v9_config["workers"]
            if worker.get("stage") == "O"
        }
        self.assertEqual(set(workers), set(gate.WORKERS))
        for worker_id in gate.WORKERS:
            self.assertEqual(
                tuple(workers[worker_id]["context_files"]),
                gate.FULL_V9_CONTEXT_AUTHORITIES[worker_id],
            )
            task = workers[worker_id]["task"]
            for markers in gate.TEST_MARKERS[worker_id].values():
                for marker in markers:
                    self.assertEqual(task.count(marker), 1, (worker_id, marker))
            for description in gate.EXACT_MUTATION_DESCRIPTIONS[worker_id].values():
                self.assertEqual(task.count(description), 1, (worker_id, description))

        self.assertEqual(
            [item["stage"] for item in config["semantic_gates"]], ["E", "O"]
        )
        source_v8 = json.loads(
            (REPO_ROOT / V8_CONFIG_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(
            config["semantic_gates"][0], source_v8["semantic_gates"][0]
        )
        o_gates = [item for item in config["semantic_gates"] if item["stage"] == "O"]
        self.assertEqual(len(o_gates), 1)
        self.assertEqual(
            o_gates[0]["script"], "scripts/pi_startup_abi_oracle_gate_v4.py"
        )
        self.assertEqual(o_gates[0]["workspace_root"], "oracle")
        self.assertEqual(
            o_gates[0]["script_sha256"],
            hashlib.sha256(Path(gate.__file__).read_bytes()).hexdigest(),
        )
        projection_issues: list[str] = []
        projection = gate._canonical_o_contract_projection(
            config, "test config", projection_issues
        )
        self.assertIsNotNone(projection)
        self.assertEqual(projection_issues, [])
        assert projection is not None
        self.assertEqual(
            projection["semantic_gates"][0], config["semantic_gates"][0]
        )
        self.assertEqual(
            set(projection["semantic_gates"][1]),
            {"stage", "script", "workspace_root"},
        )

        schema = (REPO_ROOT / gate.V3_SCHEMA_PATH).read_bytes()
        self.assertEqual(hashlib.sha256(schema).hexdigest(), gate.V3_SCHEMA_SHA256)
        self.assertEqual(len(schema), gate.V3_SCHEMA_BYTE_COUNT)

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

    def test_marker_only_descriptions_are_rejected_for_all_32_tests(self) -> None:
        for worker_id in gate.WORKERS:
            document = self._document(worker_id)
            for test in document["tests"]:
                test["description"] = " ".join(
                    gate.TEST_MARKERS[worker_id][test["test_id"]]
                )
            self._save_document(worker_id, document)
        issues = self._issues()
        for worker_id in gate.WORKERS:
            for index in range(1, 9):
                test_id = f"{worker_id}.T{index}"
                with self.subTest(test=test_id):
                    self.assertTrue(
                        any(
                            f"{test_id} description must include substantive ordinary-language semantics"
                            in issue
                            for issue in issues
                        ),
                        "\n".join(issues),
                    )

    def test_all_32_frozen_mutation_records_are_complete_and_consistent(self) -> None:
        expected_ids = [
            f"O{worker:02d}.M{index}"
            for worker in range(1, 5)
            for index in range(1, 9)
        ]
        self.assertEqual(list(gate.EXPECTED_MUTATION_RECORDS), expected_ids)
        self.assertEqual(set(gate.REQUIRED_KILL_CODES), set(expected_ids))
        for mutant_id, record in gate.EXPECTED_MUTATION_RECORDS.items():
            worker_id = mutant_id.split(".", 1)[0]
            self.assertEqual(
                record["description"],
                gate.EXACT_MUTATION_DESCRIPTIONS[worker_id][mutant_id],
            )
            self.assertEqual(set(record["mutation"]), gate.MUTATION_KEYS)
            self.assertEqual(
                gate.REQUIRED_KILL_CODES[mutant_id], record["required_kill_code"]
            )

    def test_every_field_of_all_32_mutations_is_independently_bound(self) -> None:
        for field in sorted(gate.MUTATION_KEYS):
            with self.subTest(field=field):
                self._write_baseline()
                for worker_id in gate.WORKERS:
                    document = self._document(worker_id)
                    for mutant in document["mutants"]:
                        mutant["mutation"][field] += "__CHANGED"
                    self._save_document(worker_id, document)
                issues = self._issues()
                for worker_id in gate.WORKERS:
                    for index in range(1, 9):
                        mutant_id = f"{worker_id}.M{index}"
                        self.assertTrue(
                            any(
                                f"{mutant_id} mutation.{field} must equal frozen contract"
                                in issue
                                for issue in issues
                            ),
                            f"{mutant_id}.{field} was not bound:\n" + "\n".join(issues),
                        )

    def test_mutation_object_shape_and_cross_row_swaps_are_rejected(self) -> None:
        for invalid in (None, [], "mutation"):
            with self.subTest(invalid=invalid):
                self._write_baseline()
                document = self._document("O01")
                self._mutant(document, "O01.M1")["mutation"] = invalid
                self._save_document("O01", document)
                self._assert_rejected("O01.M1 mutation is not an object")

        self._write_baseline()
        for worker_id in gate.WORKERS:
            document = self._document(worker_id)
            original = [copy.deepcopy(item["mutation"]) for item in document["mutants"]]
            for index, mutant in enumerate(document["mutants"]):
                mutant["mutation"] = original[(index + 1) % len(original)]
            self._save_document(worker_id, document)
        issues = self._issues()
        for worker_id in gate.WORKERS:
            for index in range(1, 9):
                mutant_id = f"{worker_id}.M{index}"
                with self.subTest(swapped=mutant_id):
                    self.assertTrue(
                        any(f"{mutant_id} mutation." in issue for issue in issues),
                        "\n".join(issues),
                    )

    def test_exact_procedure_and_expected_grammar_bind_all_32_pairs(self) -> None:
        for key in ("procedure", "expected"):
            with self.subTest(field=key):
                self._write_baseline()
                for worker_id in gate.WORKERS:
                    document = self._document(worker_id)
                    for test in document["tests"]:
                        test[key] += " "
                    self._save_document(worker_id, document)
                issues = self._issues()
                for worker_id in gate.WORKERS:
                    for index in range(1, 9):
                        test_id = f"{worker_id}.T{index}"
                        expected_fragment = (
                            f"{test_id} procedure must equal exact paired control"
                            if key == "procedure"
                            else f"{test_id} expected must equal exact paired result"
                        )
                        self.assertTrue(
                            any(expected_fragment in issue for issue in issues),
                            f"{test_id}.{key} was not bound:\n" + "\n".join(issues),
                        )

    def test_displaced_negative_control_contradiction_is_rejected(self) -> None:
        document = self._document("O01")
        test = self._test(document, "O01.T1")
        test["description"] += (
            " A displaced mutation clause says the mutant must FAIL because call VA "
            "is the rel32 base."
        )
        self._save_document("O01", document)
        self._assert_rejected("description contains displaced rel32 contradiction")

    def test_high_risk_mutation_rows_have_exact_audited_values(self) -> None:
        records = gate.EXPECTED_MUTATION_RECORDS
        self.assertEqual(records["O02.M4"]["mutation"]["locus"].split(",", 1)[0], "body byte offset 48")
        self.assertEqual(records["O02.M4"]["mutation"]["before"], "1009")
        self.assertEqual(records["O02.M4"]["mutation"]["after"], "1c09")
        self.assertEqual(records["O02.M7"]["mutation"]["before"], "81ec0c090000")
        self.assertEqual(records["O02.M7"]["mutation"]["after"], "0f0b90909090")
        self.assertTrue(records["O03.M2"]["mutation"]["locus"].startswith("body byte offset 21,"))
        self.assertEqual(
            records["O04.M6"]["description"],
            "EXACT_SINGLE_MUTATION: O04_M6_ALLOW_ORIGINAL_DLL_LOAD_POLICY",
        )
        insertion = records["O04.M7"]["mutation"]["after"].encode("utf-8")
        self.assertEqual(len(insertion), 92)
        self.assertEqual(
            hashlib.sha256(insertion).hexdigest(),
            "cd25de825260c0f1931dd6dc230ad5330d60f3644dccd381c0e958f12e609101",
        )
        self.assertEqual(
            records["O04.M8"]["description"],
            "EXACT_SINGLE_MUTATION: O04_M8_ATTEMPT_ONE_BYTE_WRITE_OUTSIDE_DISPOSABLE_WORKSPACE",
        )

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
        for worker_id, authorities in gate.FULL_V9_CONTEXT_AUTHORITIES.items():
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
                self._test(document, test_id)["description"] += " " + prose
                self._save_document(worker_id, document)
                self._assert_rejected(fragment)

    def test_negative_language_in_description_is_not_suppressed(self) -> None:
        snippets = {
            "O01.T4": (
                "Apply the mutation and it must FAIL because call VA is the rel32 base.",
                "rel32 uses the call VA instead of next VA",
            ),
            "O02.T1": (
                "The mutation must FAIL even though the complete checker accepts gaps.",
                "complete 400-byte decode is allowed to contain gaps",
            ),
            "O02.T3": (
                "The mutation must FAIL because EBX is stable.",
                "unproved stable register",
            ),
        }
        for test_id, (snippet, fragment) in snippets.items():
            with self.subTest(test=test_id):
                self._write_baseline()
                worker_id = test_id.split(".", 1)[0]
                document = self._document(worker_id)
                self._test(document, test_id)["description"] += " " + snippet
                self._save_document(worker_id, document)
                self._assert_rejected(fragment)

    def test_pristine_positive_contradictions_remain_rejected(self) -> None:
        cases = (
            (
                "O01.T4",
                "On the pristine baseline, the call VA is the rel32 base.",
                "rel32 uses the call VA instead of next VA",
            ),
            (
                "O02.T1",
                "The pristine checker accepts gaps in the complete decode.",
                "complete 400-byte decode is allowed to contain gaps",
            ),
            (
                "O02.T3",
                "On pristine input EBX is stable and preserved.",
                "register contract invents an unproved stable register",
            ),
        )
        for test_id, prose, fragment in cases:
            with self.subTest(test=test_id):
                self._write_baseline()
                worker_id = test_id.split(".", 1)[0]
                document = self._document(worker_id)
                self._test(document, test_id)["description"] += " " + prose
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
                    self._test(document, test_id)["description"] += " " + prose
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

    def test_context_requires_exact_full_ordered_v9_authority_set(self) -> None:
        for mutation, fragment in (
            (
                lambda items: items.append(_pin(V8_CONFIG_PATH)),
                "unexpected context authority",
            ),
            (
                lambda items: items.__setitem__(slice(0, 2), list(reversed(items[:2]))),
                "not the exact ordered v9 authority set",
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
                "config_sha256 does not match live state-selected config",
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

    def test_coherent_v7_context_hash_cannot_bypass_live_v8_binding(self) -> None:
        v7_hash, _ = _pin_values("scripts/pi_wave3_startup_abi_v7.json")
        for worker_id in gate.WORKERS:
            context = self._context(worker_id)
            context["config_sha256"] = v7_hash
            self._save_context(worker_id, context)
        self._assert_rejected(
            "context config_sha256 does not match live state-selected config"
        )

    def test_state_selected_config_is_not_hardcoded_to_the_v8_filename(self) -> None:
        out_root = REPO_ROOT / "out"
        with tempfile.TemporaryDirectory(prefix="oracle-gate-v3-", dir=out_root) as name:
            copied_config = Path(name) / "renamed-config.json"
            copied_config.write_bytes(self.config_path.read_bytes())
            copied_hash = hashlib.sha256(copied_config.read_bytes()).hexdigest()
            self._rebind_config_hash(copied_config, copied_hash)
            self.assertEqual(self._issues(), [])

    def test_reciprocal_v7_substitution_reaches_frozen_contract_rejection(self) -> None:
        v7_path = (REPO_ROOT / "scripts/pi_wave3_startup_abi_v7.json").resolve()
        v7_config = json.loads(v7_path.read_text(encoding="utf-8"))
        v7_hash = hashlib.sha256(v7_path.read_bytes()).hexdigest()
        state = self._state()
        state["config_path"] = str(v7_path)
        state["config_sha256"] = v7_hash
        stage_config = self._stage_config()
        stage_config["config_sha256"] = v7_hash
        stage_config["stage"] = next(
            item for item in v7_config["stages"] if item["id"] == "O"
        )
        stage_config["workers"] = [
            item for item in v7_config["workers"] if item["stage"] == "O"
        ]
        stage_hash = self._save_stage_config(stage_config)
        state["stages"][0]["stage_config_sha256"] = stage_hash
        self._save_state(state)
        for worker_id in gate.WORKERS:
            context = self._context(worker_id)
            context["config_sha256"] = v7_hash
            context["stage_config_sha256"] = stage_hash
            self._save_context(worker_id, context)
        self._assert_rejected("O semantic gate script is not this v4 gate")

    def test_reciprocal_selected_config_tamper_reaches_projection_rejection(self) -> None:
        out_root = REPO_ROOT / "out"
        with tempfile.TemporaryDirectory(prefix="oracle-gate-v3-", dir=out_root) as name:
            config_path = Path(name) / "tampered-config.json"
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
            next(item for item in config["workers"] if item["id"] == "O01")[
                "role"
            ] = "tampered_role"
            self._write_json(config_path, config)
            config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()

            state = self._state()
            state["config_path"] = str(config_path.resolve())
            state["config_sha256"] = config_hash
            stage_config = self._stage_config()
            stage_config["config_sha256"] = config_hash
            stage_config["workers"] = [
                item for item in config["workers"] if item["stage"] == "O"
            ]
            stage_hash = self._save_stage_config(stage_config)
            state["stages"][0]["stage_config_sha256"] = stage_hash
            self._save_state(state)
            for worker_id in gate.WORKERS:
                context = self._context(worker_id)
                context["config_sha256"] = config_hash
                context["stage_config_sha256"] = stage_hash
                self._save_context(worker_id, context)
            self._assert_rejected(
                "O contract projection does not match the frozen contract"
            )

    def test_reciprocal_global_and_o_stage_tampering_is_rejected(self) -> None:
        baseline = json.loads(self.config_path.read_text(encoding="utf-8"))

        def o_stage(config: dict[str, Any]) -> dict[str, Any]:
            return next(item for item in config["stages"] if item["id"] == "O")

        def semantic_gate(
            config: dict[str, Any], stage: str
        ) -> dict[str, Any]:
            return next(
                item for item in config["semantic_gates"] if item["stage"] == stage
            )

        cases = (
            (
                "root extra key",
                lambda c: c.__setitem__("unfrozen_root_value", True),
                "config root keys are not exact",
            ),
            (
                "schema path",
                lambda c: c.__setitem__("$schema", "scripts/other.schema.json"),
                "O contract projection does not match the frozen contract",
            ),
            (
                "schema version",
                lambda c: c.__setitem__("schema_version", 2),
                "config schema_version is not exactly 1",
            ),
            (
                "model",
                lambda c: c.__setitem__("model", "llamacpp-local/qwen3.8-27b-q4-dflash2"),
                "O contract projection does not match the frozen contract",
            ),
            (
                "milestone",
                lambda c: c.__setitem__("milestone", "changed-milestone"),
                "O contract projection does not match the frozen contract",
            ),
            (
                "launch stagger",
                lambda c: c.__setitem__(
                    "launch_stagger_milliseconds",
                    c["launch_stagger_milliseconds"] + 1,
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "prompt preamble",
                lambda c: c.__setitem__(
                    "prompt_preamble", c["prompt_preamble"] + " changed"
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "stage order",
                lambda c: c["stage_order"].reverse(),
                "O contract projection does not match the frozen contract",
            ),
            (
                "O dependency",
                lambda c: o_stage(c)["depends_on"].append("E"),
                "O contract projection does not match the frozen contract",
            ),
            (
                "O worker count",
                lambda c: o_stage(c).__setitem__("worker_count", 3),
                "O contract projection does not match the frozen contract",
            ),
            (
                "O description",
                lambda c: o_stage(c).__setitem__(
                    "description", o_stage(c)["description"] + " changed"
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "O stage extra key",
                lambda c: o_stage(c).__setitem__("unfrozen", True),
                "O stage keys are not exact",
            ),
        )
        for name, mutation, fragment in cases:
            with self.subTest(field=name):
                self._write_baseline()
                config = copy.deepcopy(baseline)
                mutation(config)
                selected = Path(self.config_temporary.name) / "selected-tamper.json"
                self._bind_selected_config(selected, config)
                self._assert_rejected(fragment)

    def test_reciprocal_complete_semantic_gate_array_is_frozen(self) -> None:
        baseline = json.loads(self.config_path.read_text(encoding="utf-8"))

        def semantic_gate(
            config: dict[str, Any], stage: str
        ) -> dict[str, Any]:
            return next(
                item for item in config["semantic_gates"] if item["stage"] == stage
            )

        cases = (
            (
                "E path",
                lambda c: semantic_gate(c, "E").__setitem__(
                    "script", "scripts/changed_e_gate.py"
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "E hash",
                lambda c: semantic_gate(c, "E").__setitem__(
                    "script_sha256", "0" * 64
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "E workspace",
                lambda c: semantic_gate(c, "E").__setitem__(
                    "workspace_root", "changed-evidence"
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "reordered",
                lambda c: c["semantic_gates"].reverse(),
                "semantic_gates must be exactly E,O in order",
            ),
            (
                "extra",
                lambda c: c["semantic_gates"].append(
                    copy.deepcopy(c["semantic_gates"][0])
                ),
                "semantic_gates must be exactly E,O in order",
            ),
            (
                "O workspace",
                lambda c: semantic_gate(c, "O").__setitem__(
                    "workspace_root", "changed-oracle"
                ),
                "O contract projection does not match the frozen contract",
            ),
            (
                "O live hash",
                lambda c: semantic_gate(c, "O").__setitem__(
                    "script_sha256", "0" * 64
                ),
                "O semantic gate hash does not match the live v4 gate",
            ),
            (
                "O extra field",
                lambda c: semantic_gate(c, "O").__setitem__("extra", True),
                "O semantic gate keys are not exact",
            ),
        )
        for name, mutation, fragment in cases:
            with self.subTest(case=name):
                self._write_baseline()
                config = copy.deepcopy(baseline)
                mutation(config)
                selected = Path(self.config_temporary.name) / "selected-gates.json"
                self._bind_selected_config(selected, config)
                self._assert_rejected(fragment)

    def test_reciprocal_stage_snapshot_tamper_is_rejected(self) -> None:
        calibration = json.loads(self.config_path.read_text(encoding="utf-8"))
        e01 = copy.deepcopy(
            next(item for item in calibration["workers"] if item["id"] == "E01")
        )
        cases = (
            (
                "worker field",
                lambda stage: stage["workers"][0].__setitem__(
                    "task", stage["workers"][0]["task"] + " tampered"
                ),
                "live O stage worker contract does not match the selected config",
            ),
            (
                "appended E worker",
                lambda stage: stage["workers"].append(copy.deepcopy(e01)),
                "workers must be exactly O01,O02,O03,O04 with no other entries",
            ),
            (
                "appended non-object",
                lambda stage: stage["workers"].append(None),
                "workers must be exactly O01,O02,O03,O04 with no other entries",
            ),
            (
                "reordered workers",
                lambda stage: stage["workers"].reverse(),
                "workers are not exactly O01,O02,O03,O04 in order",
            ),
            (
                "extra worker key",
                lambda stage: stage["workers"][0].__setitem__("unfrozen", True),
                "worker keys are not exact",
            ),
        )
        for name, mutation, fragment in cases:
            with self.subTest(case=name):
                self._write_baseline()
                stage_config = self._stage_config()
                mutation(stage_config)
                stage_hash = self._save_stage_config(stage_config)
                self._rebind_stage_hash(stage_hash)
                self._assert_rejected(fragment)

    def test_supervisor_state_relevant_fields_are_exact(self) -> None:
        cases = (
            (
                lambda state: state.__setitem__("state_version", True),
                "state_version is not exactly 3",
            ),
            (
                lambda state: state.__setitem__("run_id", "other-run"),
                "state run_id does not match the run directory",
            ),
            (
                lambda state: state.__setitem__("repository_root", str(self.run_root)),
                "repository_root: path does not match",
            ),
            (
                lambda state: state.__setitem__("run_root", str(REPO_ROOT)),
                "state run_root: path does not match",
            ),
            (
                lambda state: state.__setitem__("config_sha256", "0" * 64),
                "state config_sha256 does not match the live state-selected config",
            ),
            (
                lambda state: state["stages"].append(copy.deepcopy(state["stages"][0])),
                "state must contain exactly one O stage",
            ),
        )
        for mutation, fragment in cases:
            with self.subTest(fragment=fragment):
                self._write_baseline()
                state = self._state()
                mutation(state)
                self._save_state(state)
                self._assert_rejected(fragment)

        for key in (
            "state_version",
            "run_id",
            "repository_root",
            "run_root",
            "config_path",
            "config_sha256",
            "stages",
        ):
            with self.subTest(missing=key):
                self._write_baseline()
                state = self._state()
                del state[key]
                self._save_state(state)
                self._assert_rejected(f"missing relevant field {key}")

    def test_state_config_path_rejects_traversal_and_escape(self) -> None:
        unsafe_paths = (
            str(REPO_ROOT / "scripts" / ".." / "scripts" / Path(V8_CONFIG_PATH).name),
            str((self.run_root / "stage-config" / "O.json").resolve()),
            V8_CONFIG_PATH,
        )
        expected = (
            "path contains traversal",
            "path escapes the trusted repository",
            "path is not absolute",
        )
        for unsafe, fragment in zip(unsafe_paths, expected, strict=True):
            with self.subTest(path=unsafe):
                self._write_baseline()
                state = self._state()
                state["config_path"] = unsafe
                self._save_state(state)
                self._assert_rejected(f"supervisor state config_path: {fragment}")

    def test_state_json_must_not_be_a_symlink_even_within_run(self) -> None:
        state_path = self.run_root / "state.json"
        alternate = self.run_root / "state-copy.json"
        alternate.write_bytes(state_path.read_bytes())
        state_path.unlink()
        try:
            state_path.symlink_to(alternate)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self._assert_rejected("supervisor state: artifact must not be a symlink")

    def test_state_selected_config_must_not_be_a_symlink(self) -> None:
        out_root = REPO_ROOT / "out"
        with tempfile.TemporaryDirectory(prefix="oracle-gate-v3-", dir=out_root) as name:
            link = Path(name) / "config-link.json"
            try:
                link.symlink_to(self.config_path.resolve())
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            state = self._state()
            state["config_path"] = str(link)
            self._save_state(state)
            self._assert_rejected("state config_path: path must not be a symlink")

    def test_frozen_o_contract_projection_rejects_every_effective_field(self) -> None:
        baseline = json.loads(self.config_path.read_text(encoding="utf-8"))

        def worker(config: dict[str, Any], worker_id: str = "O01") -> dict[str, Any]:
            return next(item for item in config["workers"] if item["id"] == worker_id)

        def o_stage(config: dict[str, Any]) -> dict[str, Any]:
            return next(item for item in config["stages"] if item["id"] == "O")

        def semantic_gate(
            config: dict[str, Any], stage: str
        ) -> dict[str, Any]:
            return next(
                item for item in config["semantic_gates"] if item["stage"] == stage
            )

        mutations = (
            ("root keys", lambda c: c.__setitem__("extra", True)),
            ("schema path", lambda c: c.__setitem__("$schema", "changed")),
            ("schema version", lambda c: c.__setitem__("schema_version", 2)),
            ("model", lambda c: c.__setitem__("model", "changed")),
            ("milestone", lambda c: c.__setitem__("milestone", "changed")),
            (
                "launch stagger",
                lambda c: c.__setitem__(
                    "launch_stagger_milliseconds",
                    c["launch_stagger_milliseconds"] + 1,
                ),
            ),
            (
                "prompt preamble",
                lambda c: c.__setitem__(
                    "prompt_preamble", c["prompt_preamble"] + " changed"
                ),
            ),
            ("stage order", lambda c: c["stage_order"].reverse()),
            ("allowed requirements", lambda c: c["allowed_requirement_ids"].reverse()),
            (
                "E gate stage",
                lambda c: semantic_gate(c, "E").__setitem__("stage", "I"),
            ),
            (
                "E gate path",
                lambda c: semantic_gate(c, "E").__setitem__(
                    "script", "scripts/changed_e_gate.py"
                ),
            ),
            (
                "E gate hash",
                lambda c: semantic_gate(c, "E").__setitem__(
                    "script_sha256", "0" * 64
                ),
            ),
            (
                "E gate workspace",
                lambda c: semantic_gate(c, "E").__setitem__(
                    "workspace_root", "changed-evidence"
                ),
            ),
            ("gate order", lambda c: c["semantic_gates"].reverse()),
            (
                "extra gate",
                lambda c: c["semantic_gates"].append(
                    copy.deepcopy(c["semantic_gates"][0])
                ),
            ),
            (
                "O gate path",
                lambda c: semantic_gate(c, "O").__setitem__(
                    "script", "scripts/pi_startup_abi_oracle_gate_v2.py"
                ),
            ),
            (
                "O gate workspace",
                lambda c: semantic_gate(c, "O").__setitem__(
                    "workspace_root", "evidence"
                ),
            ),
            (
                "O gate keys",
                lambda c: semantic_gate(c, "O").__setitem__("extra", True),
            ),
            ("O dependency", lambda c: o_stage(c)["depends_on"].append("E")),
            ("O worker count", lambda c: o_stage(c).__setitem__("worker_count", 3)),
            (
                "O description",
                lambda c: o_stage(c).__setitem__(
                    "description", o_stage(c)["description"] + " changed"
                ),
            ),
            ("O stage keys", lambda c: o_stage(c).__setitem__("extra", True)),
            ("worker id", lambda c: worker(c).__setitem__("id", "O09")),
            ("role", lambda c: worker(c).__setitem__("role", "changed")),
            ("task", lambda c: worker(c).__setitem__("task", worker(c)["task"] + " changed")),
            ("tools", lambda c: worker(c)["tools"].append("edit")),
            ("thinking", lambda c: worker(c).__setitem__("thinking", "low")),
            ("budget", lambda c: worker(c)["budget"].__setitem__("max_tokens", 1)),
            ("writable", lambda c: worker(c).__setitem__("writable_dir", "oracle/O02")),
            ("context", lambda c: worker(c)["context_files"].reverse()),
            ("review context", lambda c: worker(c)["review_targets"].append("O02")),
            ("output", lambda c: worker(c)["required_outputs"][0].__setitem__("path", "other.json")),
        )
        for name, mutation in mutations:
            with self.subTest(field=name):
                config = copy.deepcopy(baseline)
                mutation(config)
                issues: list[str] = []
                self.assertIsNone(
                    gate._canonical_o_contract_projection(config, "test config", issues)
                )
                self.assertTrue(issues, f"{name} tamper unexpectedly passed")

    def test_o_gate_hash_is_live_checked_but_excluded_from_projection_digest(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        o_gate = next(item for item in config["semantic_gates"] if item["stage"] == "O")
        o_gate["script_sha256"] = "0" * 64
        issues: list[str] = []
        self.assertIsNone(
            gate._canonical_o_contract_projection(config, "test config", issues)
        )
        self.assertTrue(any("does not match the live v4 gate" in issue for issue in issues))

    def test_live_stage_config_is_required_and_hash_pinned(self) -> None:
        stage_config = self.run_root / "stage-config" / "O.json"
        stage_config.unlink()
        self._assert_rejected("O: live O stage config: missing artifact")

        self._write_baseline()
        stage_config.write_text('{"changed":true}\n', encoding="utf-8")
        self._assert_rejected("stage_config_sha256 does not match live O stage config")

    def test_config_and_stage_hash_and_parse_use_one_content_open(self) -> None:
        config_path = self.config_path.resolve()
        stage_path = (self.run_root / "stage-config" / "O.json").resolve()
        opens = {config_path: 0, stage_path: 0}
        original_open = Path.open

        def counted_open(path: Path, *args: Any, **kwargs: Any):
            mode = args[0] if args else kwargs.get("mode", "r")
            resolved = path.resolve()
            if resolved in opens and mode == "rb":
                opens[resolved] += 1
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", new=counted_open):
            self.assertEqual(self._issues(), [])
        self.assertEqual(opens[config_path], 1)
        self.assertEqual(opens[stage_path], 1)

    def test_json_snapshot_digest_covers_parsed_bytes_and_rejects_a_race(self) -> None:
        snapshot_root = self.run_root / "snapshot-test"
        snapshot_root.mkdir(parents=True, exist_ok=True)
        target = snapshot_root / "document.json"
        original = b'{"value":1}\n'
        target.write_bytes(original)

        issues: list[str] = []
        document, pin = gate._load_json_snapshot(
            target,
            "snapshot",
            issues,
            containment_root=snapshot_root,
        )
        self.assertEqual(issues, [])
        self.assertEqual(document, {"value": 1})
        self.assertEqual(pin, (hashlib.sha256(original).hexdigest(), len(original)))

        real_signature = gate._file_signature
        calls = 0

        def racing_signature(path: Path):
            nonlocal calls
            if path == target.resolve():
                calls += 1
                if calls == 2:
                    target.write_bytes(b'{"value":222222}\n')
            return real_signature(path)

        race_issues: list[str] = []
        with mock.patch.object(gate, "_file_signature", new=racing_signature):
            raced_document, raced_pin = gate._load_json_snapshot(
                target,
                "snapshot",
                race_issues,
                containment_root=snapshot_root,
            )
        self.assertIsNone(raced_document)
        self.assertIsNone(raced_pin)
        self.assertTrue(
            any("artifact changed while reading" in issue for issue in race_issues),
            race_issues,
        )

    def test_validation_schema_is_exact_v3_with_live_pin(self) -> None:
        cases = (
            (
                lambda schema: schema.__setitem__("path", "scripts/pi_wave3_oracle.schema.json"),
                "validation schema is not exact v3",
            ),
            (
                lambda schema: schema.__setitem__("sha256", "0" * 64),
                "v3 schema SHA-256 pin is wrong",
            ),
            (
                lambda schema: schema.__setitem__("byte_count", 0),
                "v3 schema byte_count pin is wrong",
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
        context["validation_schemas"].append(_pin(gate.V3_SCHEMA_PATH))
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

        expected_defect_fragments = tuple(
            fragment
            for worker_id in gate.WORKERS
            for fragment in (
                f"{worker_id}.M1 mutation is not an object",
                f"{worker_id}.T1 procedure must equal exact paired control",
                f"{worker_id}.T1 expected must equal exact paired result",
                "context validation schema is not exact v3",
                "docs/pi_startup_abi_oracle_mutation_contract_v3.md",
            )
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
