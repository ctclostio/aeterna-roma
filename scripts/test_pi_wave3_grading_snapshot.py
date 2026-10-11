#!/usr/bin/env python3
"""Focused stdlib tests for pi_wave3_grading_snapshot.py."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pi_wave3_grading_snapshot import (
    inspect_json_artifact,
    snapshot_run,
    validate_json_schema,
)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SnapshotFixture:
    def __init__(self, root: Path) -> None:
        self.repository = root / "repository"
        self.run = self.repository / "out" / "pi-swarm" / "fixture-run"
        self.scripts = self.repository / "scripts"
        self.run.mkdir(parents=True)
        self.scripts.mkdir(parents=True)

        self.schema = self.scripts / "report.schema.json"
        write_json(
            self.schema,
            {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "additionalProperties": False,
                "required": ["worker_id", "stage", "claims"],
                "properties": {
                    "worker_id": {"type": "string", "pattern": "^E[0-9]{2}$"},
                    "stage": {"const": "E"},
                    "claims": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"type": "string", "minLength": 1},
                    },
                },
            },
        )
        required_output = {
            "name": "evidence",
            "source": "report",
            "format": "json",
            "schema": "scripts/report.schema.json",
            "max_bytes": 10000,
        }
        config = {
            "workers": [
                {"id": worker_id, "required_outputs": [required_output]}
                for worker_id in ("E01", "E02", "E03", "E04", "O01")
            ]
        }
        self.config = self.scripts / "fixture-config.json"
        write_json(self.config, config)

        reports = self.run / "reports" / "E"
        sessions = self.run / "sessions" / "E"
        contexts = self.run / "context" / "E"
        reports.mkdir(parents=True)
        sessions.mkdir(parents=True)
        contexts.mkdir(parents=True)

        workers = []
        for worker_id, status, attempt in (
            ("E01", "running", 1),
            ("E02", "running", 1),
            ("E03", "stopped", 1),
            ("E04", "launch_failed", 1),
            ("O01", "pending", 0),
        ):
            stage = worker_id[0]
            report = self.run / "reports" / stage / f"{worker_id}.json"
            exit_file = self.run / "reports" / stage / f"{worker_id}.exit.txt"
            session_directory = self.run / "sessions" / stage
            context = self.run / "context" / stage / f"{worker_id}.json"
            workers.append(
                {
                    "id": worker_id,
                    "stage": stage,
                    "role": f"role-{worker_id}",
                    "status": status,
                    "attempt": attempt,
                    "pid": None,
                    "process_start_utc": "2026-08-24T00:00:00Z" if attempt else None,
                    "started_utc": "2026-08-24T00:00:00Z" if attempt else None,
                    "stopped_utc": "2026-08-24T00:00:09Z" if status == "stopped" else None,
                    "session_id": f"fixture-{worker_id}" if attempt and worker_id != "E04" else None,
                    "session_directory": str(session_directory) if attempt else None,
                    "context_manifest": str(context) if attempt and worker_id != "E04" else None,
                    "workspace_dir": None,
                    "output_file": str(report) if attempt else None,
                    "exit_file": str(exit_file) if attempt else None,
                    "budget": {"max_tokens": 100},
                }
            )
            if attempt and worker_id != "E04":
                write_json(
                    context,
                    {
                        "validation_schemas": [
                            {
                                "path": "scripts/report.schema.json",
                                "sha256": sha256(self.schema),
                            }
                        ]
                    },
                )

        write_json(reports / "E01.json", {"worker_id": "E01", "stage": "E", "claims": ["ok"]})
        (reports / "E01.exit.txt").write_text("0\n", encoding="utf-8")
        write_json(reports / "E02.json", {"worker_id": "wrong", "stage": "E", "claims": []})
        (reports / "E02.exit.txt").write_text("17\n", encoding="utf-8")
        (reports / "E03.json").write_text('{"worker_id": "E03" trailing', encoding="utf-8")

        self._write_session(sessions, "E01", 18, 10, 3, 5, tool=True)
        self._write_session(sessions, "E02", 7, 4, 2, 1)
        self._write_session(sessions, "E03", 4, 2, 1, 1, malformed=True)

        state = {
            "state_version": 1,
            "run_id": "fixture-run",
            "repository_root": str(self.repository),
            "run_root": str(self.run),
            "model": "openrouter/stealth/ox-alpha",
            "config_path": str(self.config),
            "config_sha256": sha256(self.config),
            "total_token_budget": 500,
            "created_utc": "2026-08-24T00:00:00Z",
            "updated_utc": "2026-08-24T00:00:10Z",
            "stages": [
                {"id": "E", "stage_config_file": None, "stage_config_sha256": None},
                {"id": "O", "stage_config_file": None, "stage_config_sha256": None},
            ],
            "workers": workers,
        }
        write_json(self.run / "state.json", state)

    def _write_session(
        self,
        directory: Path,
        worker_id: str,
        total: int,
        input_tokens: int,
        output_tokens: int,
        cache: int,
        *,
        tool: bool = False,
        malformed: bool = False,
    ) -> None:
        session_id = f"fixture-{worker_id}"
        path = directory / f"2026-08-24T00-00-00Z_{session_id}.jsonl"
        content = [{"type": "session", "timestamp": "2026-08-24T00:00:00Z"}]
        blocks = [{"type": "toolCall", "name": "read"}] if tool else []
        content.append(
            {
                "type": "message",
                "timestamp": "2026-08-24T00:00:05Z",
                "message": {
                    "role": "assistant",
                    "content": blocks,
                    "usage": {
                        "totalTokens": total,
                        "input": input_tokens,
                        "output": output_tokens,
                        "cacheRead": cache,
                        "reasoning": 0,
                    },
                },
            }
        )
        lines = [json.dumps(item) for item in content]
        if malformed:
            lines.append("{not-json")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


class GradingSnapshotTests(unittest.TestCase):
    def test_failure_inclusive_snapshot_and_aggregate_denominators(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SnapshotFixture(Path(temporary))
            payload = snapshot_run(fixture.run, generated_utc="2026-08-24T01:00:00Z")

            self.assertEqual(payload["format"], "pi-wave3-grading-snapshot-v1")
            self.assertEqual([row["id"] for row in payload["workers"]], ["E01", "E02", "E03", "E04", "O01"])
            rows = {row["id"]: row for row in payload["workers"]}
            self.assertEqual(rows["E01"]["status"], "completed")
            self.assertEqual(rows["E01"]["exit_code"], 0)
            self.assertTrue(rows["E01"]["report_exact_json"])
            self.assertTrue(rows["E01"]["report_schema_valid"])
            self.assertEqual(rows["E01"]["session"]["tool_calls"], 1)

            self.assertEqual(rows["E02"]["status"], "failed")
            self.assertEqual(rows["E02"]["exit_code"], 17)
            self.assertTrue(rows["E02"]["report_exact_json"])
            self.assertFalse(rows["E02"]["report_schema_valid"])
            self.assertFalse(rows["E02"]["report_identity_valid"])

            self.assertEqual(rows["E03"]["status"], "stopped")
            self.assertFalse(rows["E03"]["report_exact_json"])
            self.assertFalse(rows["E03"]["session"]["jsonl_valid"])
            self.assertEqual(rows["E03"]["session"]["total_tokens"], 4)
            self.assertEqual(rows["E04"]["status"], "launch_failed")
            self.assertEqual(rows["O01"]["status"], "pending")

            aggregate = payload["aggregates"]["run"]
            self.assertEqual(aggregate["counts"]["workers"], 5)
            self.assertEqual(aggregate["counts"]["attempted_workers"], 4)
            self.assertEqual(aggregate["totals"]["total_tokens"], 29)
            self.assertEqual(aggregate["means_per_worker"]["total_tokens"], 5.8)
            self.assertEqual(aggregate["means_per_attempted_worker"]["total_tokens"], 7.25)
            self.assertEqual(aggregate["counts"]["malformed_session_workers"], 1)
            self.assertEqual(payload["aggregates"]["stages"]["E"]["counts"]["workers"], 4)

    def test_schema_subset_resolves_refs_and_reports_unsupported_keywords(self) -> None:
        schema = {
            "type": "object",
            "required": ["file"],
            "properties": {"file": {"$ref": "#/definitions/file"}},
            "additionalProperties": False,
            "definitions": {
                "file": {
                    "type": "object",
                    "required": ["bytes"],
                    "properties": {"bytes": {"type": "integer", "minimum": 0}},
                    "additionalProperties": False,
                }
            },
        }
        valid, errors, unsupported = validate_json_schema({"file": {"bytes": 3}}, schema)
        self.assertTrue(valid)
        self.assertEqual(errors, [])
        self.assertEqual(unsupported, [])
        valid, errors, unsupported = validate_json_schema({"file": {"bytes": -1}}, schema)
        self.assertFalse(valid)
        self.assertIn("less than minimum", errors[0])
        valid, _, unsupported = validate_json_schema("x", {"type": "string", "format": "email"})
        self.assertIsNone(valid)
        self.assertEqual(unsupported, ["format"])

    def test_exact_json_rejects_bom_array_and_trailing_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = {
                "object.json": (b"  {\"ok\": true}\n", True, True),
                "array.json": (b"[]\n", True, False),
                "bom.json": (b"\xef\xbb\xbf{\"ok\": true}\n", False, False),
                "nan.json": (b"{\"value\": NaN}\n", False, False),
                "trailing.json": (b"{\"ok\": true} noise", False, False),
            }
            for name, (raw, syntax, exact) in cases.items():
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(raw)
                    result, _ = inspect_json_artifact(path, root, name=name, source="test")
                    self.assertEqual(result["json_syntax_valid"], syntax)
                    self.assertEqual(result["exact_json_document"], exact)


if __name__ == "__main__":
    unittest.main()
