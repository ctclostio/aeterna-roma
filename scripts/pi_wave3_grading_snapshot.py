#!/usr/bin/env python3
"""Create a read-only, failure-inclusive grading snapshot for a Pi wave-3 run.

The wave-3 supervisor intentionally refuses to publish a stage manifest until
every worker passes its gates.  That is the right acceptance policy, but a poor
source for evaluation statistics: stopped, failed, and malformed workers would
otherwise disappear.  This tool reads ``state.json`` plus whatever artifacts
exist and emits one JSON document containing all configured workers.

No stage has to be complete or valid.  The tool never writes inside the run
unless the caller explicitly chooses such a path with ``--output``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


FORMAT = "pi-wave3-grading-snapshot-v1"
STAGES = ("E", "O", "I", "R", "G")
GRADE_AXES: dict[str, dict[str, Any]] = {
    "central_correctness": {
        "kind": "score",
        "minimum": 0,
        "maximum": 100,
        "description": "Supervisor-owned external-oracle correctness score.",
    },
    "code_quality": {
        "kind": "score",
        "minimum": 0,
        "maximum": 100,
        "description": "Supervisor-owned maintainability and containment score.",
    },
    "verbatim_acceptance": {
        "kind": "boolean",
        "description": "Whether the worker artifact was acceptable verbatim.",
    },
}
AGGREGATE_FIELDS = (
    "report_bytes",
    "session_bytes",
    "total_tokens",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "reasoning_tokens",
    "assistant_turns",
    "user_turns",
    "tool_result_turns",
    "tool_calls",
    "tool_errors",
    "wall_time_seconds",
)
SCHEMA_ANNOTATIONS = {
    "$schema",
    "$id",
    "title",
    "description",
    "default",
    "examples",
    "definitions",
}
SCHEMA_KEYWORDS = {
    "$ref",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
}


class SnapshotError(RuntimeError):
    """A fatal error that prevents enumerating the run."""


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _iso_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _display_path(path: Path | None, run_root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(run_root.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _path_from_state(value: Any, base: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    return path if path.is_absolute() else base / path


def _strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant {value!r}")

    return json.loads(text, parse_constant=reject_constant)


def _read_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return _strict_json_loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _json_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_equal(left: Any, right: Any) -> bool:
    return type(left) is type(right) and _json_key(left) == _json_key(right)


def _json_pointer(document: Any, reference: str) -> Any:
    if not reference.startswith("#"):
        raise ValueError("only local JSON Schema references are supported")
    if reference == "#":
        return document
    if not reference.startswith("#/"):
        raise ValueError("invalid local JSON pointer")
    current = document
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise ValueError("JSON pointer traverses a scalar")
    return current


def _type_matches(instance: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "null":
        return instance is None
    return False


def validate_json_schema(
    instance: Any, schema: Any
) -> tuple[bool | None, list[str], list[str]]:
    """Validate the Draft-07 subset used by wave-3 output schemas.

    The third return value lists unsupported schema keywords.  In that case the
    validity result is ``None`` rather than an overconfident partial verdict.
    """

    errors: list[str] = []
    unsupported: set[str] = set()

    def visit(value: Any, rule: Any, location: str, root: Any) -> None:
        if isinstance(rule, bool):
            if not rule:
                errors.append(f"{location}: rejected by false schema")
            return
        if not isinstance(rule, dict):
            errors.append(f"{location}: schema node is not an object or boolean")
            return

        for keyword in rule:
            if keyword not in SCHEMA_KEYWORDS and keyword not in SCHEMA_ANNOTATIONS:
                unsupported.add(keyword)

        if "$ref" in rule:
            reference = rule["$ref"]
            try:
                target = _json_pointer(root, reference)
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                errors.append(f"{location}: unresolved $ref {reference!r}: {exc}")
                return
            visit(value, target, location, root)
            return

        expected = rule.get("type")
        if expected is not None:
            choices = expected if isinstance(expected, list) else [expected]
            if not choices or not all(isinstance(item, str) for item in choices):
                errors.append(f"{location}: invalid type declaration")
                return
            if not any(_type_matches(value, item) for item in choices):
                errors.append(
                    f"{location}: expected type {expected!r}, found {type(value).__name__}"
                )
                return

        if "const" in rule and not _json_equal(value, rule["const"]):
            errors.append(f"{location}: value does not equal const")
        if "enum" in rule:
            choices = rule["enum"]
            if not isinstance(choices, list) or not any(
                _json_equal(value, choice) for choice in choices
            ):
                errors.append(f"{location}: value is not in enum")

        if isinstance(value, dict):
            required = rule.get("required", [])
            if isinstance(required, list):
                for name in required:
                    if isinstance(name, str) and name not in value:
                        errors.append(f"{location}: missing required property {name!r}")
            elif "required" in rule:
                errors.append(f"{location}: required is not an array")
            properties = rule.get("properties", {})
            if not isinstance(properties, dict):
                errors.append(f"{location}: properties is not an object")
                properties = {}
            for name, child_rule in properties.items():
                if name in value:
                    visit(value[name], child_rule, f"{location}/{name}", root)
            additional = rule.get("additionalProperties", True)
            for name in value.keys() - properties.keys():
                if additional is False:
                    errors.append(f"{location}: additional property {name!r} is forbidden")
                elif isinstance(additional, (dict, bool)):
                    visit(value[name], additional, f"{location}/{name}", root)
                else:
                    errors.append(f"{location}: invalid additionalProperties declaration")

        if isinstance(value, list):
            if isinstance(rule.get("minItems"), int) and len(value) < rule["minItems"]:
                errors.append(f"{location}: fewer than minItems")
            if isinstance(rule.get("maxItems"), int) and len(value) > rule["maxItems"]:
                errors.append(f"{location}: more than maxItems")
            if rule.get("uniqueItems") is True:
                keys = [_json_key(item) for item in value]
                if len(keys) != len(set(keys)):
                    errors.append(f"{location}: array items are not unique")
            if "items" in rule:
                child_rule = rule["items"]
                if isinstance(child_rule, list):
                    unsupported.add("tuple-form-items")
                else:
                    for index, item in enumerate(value):
                        visit(item, child_rule, f"{location}/{index}", root)

        if isinstance(value, str):
            if isinstance(rule.get("minLength"), int) and len(value) < rule["minLength"]:
                errors.append(f"{location}: shorter than minLength")
            if isinstance(rule.get("maxLength"), int) and len(value) > rule["maxLength"]:
                errors.append(f"{location}: longer than maxLength")
            if "pattern" in rule:
                try:
                    if re.search(str(rule["pattern"]), value) is None:
                        errors.append(f"{location}: string does not match pattern")
                except re.error as exc:
                    unsupported.add(f"invalid-pattern:{exc}")

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if isinstance(rule.get("minimum"), (int, float)) and value < rule["minimum"]:
                errors.append(f"{location}: less than minimum")
            if isinstance(rule.get("maximum"), (int, float)) and value > rule["maximum"]:
                errors.append(f"{location}: greater than maximum")

    visit(instance, schema, "$", schema)
    unsupported_list = sorted(unsupported)
    valid: bool | None = None if unsupported_list else not errors
    return valid, errors[:100], unsupported_list


def inspect_json_artifact(
    path: Path | None,
    run_root: Path,
    *,
    name: str,
    source: str,
    schema_path: Path | None = None,
    schema_label: str | None = None,
    frozen_schema_sha256: str | None = None,
) -> tuple[dict[str, Any], Any | None]:
    """Inspect one artifact without allowing a bad file to abort the snapshot."""

    result: dict[str, Any] = {
        "name": name,
        "source": source,
        "path": _display_path(path, run_root),
        "exists": False,
        "bytes": 0,
        "sha256": None,
        "modified_utc": None,
        "json_syntax_valid": None,
        "exact_json_document": None,
        "json_root_type": None,
        "json_error": None,
        "schema": {
            "path": schema_label,
            "exists": False if schema_path is not None else None,
            "sha256": None,
            "frozen_sha256": frozen_schema_sha256,
            "hash_matches_frozen": None,
            "validator": "builtin-draft7-wave3-subset",
            "supported": None,
            "valid": None,
            "errors": [],
            "unsupported_keywords": [],
        },
    }
    if path is None:
        result["json_error"] = "artifact path is unavailable"
        return result, None
    try:
        raw = path.read_bytes()
        stat = path.stat()
    except (OSError, ValueError) as exc:
        result["json_error"] = f"{type(exc).__name__}: {exc}"
        return result, None

    result.update(
        {
            "exists": True,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "modified_utc": datetime.fromtimestamp(
                stat.st_mtime, timezone.utc
            ).isoformat().replace("+00:00", "Z"),
        }
    )
    document: Any | None = None
    try:
        text = raw.decode("utf-8", errors="strict")
        document = _strict_json_loads(text)
        stripped = text.strip()
        result["json_syntax_valid"] = True
        result["json_root_type"] = (
            "object"
            if isinstance(document, dict)
            else "array"
            if isinstance(document, list)
            else "scalar"
        )
        result["exact_json_document"] = (
            isinstance(document, dict)
            and bool(stripped)
            and stripped.startswith("{")
            and stripped.endswith("}")
            and not raw.startswith(b"\xef\xbb\xbf")
        )
    except (UnicodeError, ValueError) as exc:
        result["json_syntax_valid"] = False
        result["exact_json_document"] = False
        result["json_error"] = f"{type(exc).__name__}: {exc}"

    schema_result = result["schema"]
    schema_document: Any | None = None
    if schema_path is not None:
        try:
            schema_raw = schema_path.read_bytes()
            schema_result["exists"] = True
            schema_result["sha256"] = hashlib.sha256(schema_raw).hexdigest()
            if frozen_schema_sha256 is not None:
                schema_result["hash_matches_frozen"] = (
                    schema_result["sha256"] == frozen_schema_sha256
                )
            schema_document = _strict_json_loads(schema_raw.decode("utf-8", errors="strict"))
        except (OSError, UnicodeError, ValueError) as exc:
            schema_result["errors"] = [f"schema read failed: {type(exc).__name__}: {exc}"]
    if schema_document is not None and document is not None:
        valid, errors, unsupported = validate_json_schema(document, schema_document)
        schema_result["supported"] = not unsupported
        schema_result["valid"] = valid
        schema_result["errors"] = errors
        schema_result["unsupported_keywords"] = unsupported
    elif schema_document is not None:
        schema_result["supported"] = True
        schema_result["valid"] = False
        schema_result["errors"] = ["artifact is not valid JSON"]
    return result, document


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _number(value: Any) -> int:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return int(value)
    return 0


def _session_file_metrics(path: Path, run_root: Path) -> dict[str, Any]:
    counts = Counter()
    tools = Counter()
    first: datetime | None = None
    last: datetime | None = None
    parse_errors: list[dict[str, Any]] = []
    invalid_timestamps = 0
    try:
        raw = path.read_bytes()
        modified = _iso_mtime(path)
    except (OSError, UnicodeError) as exc:
        return {
            "path": _display_path(path, run_root),
            "exists": False,
            "bytes": 0,
            "sha256": None,
            "modified_utc": None,
            "jsonl_valid": False,
            "parse_errors": [{"line": None, "error": f"{type(exc).__name__}: {exc}"}],
            "record_count": 0,
            "message_records": 0,
            "assistant_turns": 0,
            "user_turns": 0,
            "tool_result_turns": 0,
            "tool_calls": 0,
            "tool_errors": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 0,
            "first_timestamp_utc": None,
            "last_timestamp_utc": None,
            "wall_time_seconds": None,
            "invalid_timestamp_count": 0,
            "tool_breakdown": {},
        }

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        parse_errors.append({"line": None, "error": f"UnicodeError: {exc}"})
        text = ""
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = _strict_json_loads(line)
        except ValueError as exc:
            parse_errors.append(
                {"line": line_number, "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        if not isinstance(record, dict):
            parse_errors.append({"line": line_number, "error": "record is not an object"})
            continue
        counts["record_count"] += 1
        timestamp_value = record.get("timestamp")
        if timestamp_value is not None:
            instant = _parse_timestamp(timestamp_value)
            if instant is None:
                invalid_timestamps += 1
            else:
                first = instant if first is None else min(first, instant)
                last = instant if last is None else max(last, instant)
        if record.get("type") != "message":
            continue
        message = record.get("message")
        if not isinstance(message, dict):
            continue
        counts["message_records"] += 1
        role = message.get("role")
        if role == "assistant":
            counts["assistant_turns"] += 1
            usage = message.get("usage")
            if isinstance(usage, dict):
                counts["input_tokens"] += _number(usage.get("input"))
                counts["output_tokens"] += _number(usage.get("output"))
                counts["cache_read_tokens"] += _number(usage.get("cacheRead"))
                counts["reasoning_tokens"] += _number(usage.get("reasoning"))
                counts["total_tokens"] += _number(usage.get("totalTokens"))
            content = message.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "toolCall":
                        name = str(block.get("name") or "unknown")
                        tools[name] += 1
        elif role == "user":
            counts["user_turns"] += 1
        elif role == "toolResult":
            counts["tool_result_turns"] += 1
            if message.get("isError") is True:
                counts["tool_errors"] += 1

    wall = (last - first).total_seconds() if first is not None and last is not None else None
    return {
        "path": _display_path(path, run_root),
        "exists": True,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "modified_utc": modified,
        "jsonl_valid": not parse_errors,
        "parse_errors": parse_errors[:50],
        "record_count": counts["record_count"],
        "message_records": counts["message_records"],
        "assistant_turns": counts["assistant_turns"],
        "user_turns": counts["user_turns"],
        "tool_result_turns": counts["tool_result_turns"],
        "tool_calls": sum(tools.values()),
        "tool_errors": counts["tool_errors"],
        "input_tokens": counts["input_tokens"],
        "output_tokens": counts["output_tokens"],
        "cache_read_tokens": counts["cache_read_tokens"],
        "reasoning_tokens": counts["reasoning_tokens"],
        "total_tokens": counts["total_tokens"],
        "first_timestamp_utc": first.isoformat().replace("+00:00", "Z") if first else None,
        "last_timestamp_utc": last.isoformat().replace("+00:00", "Z") if last else None,
        "wall_time_seconds": wall,
        "invalid_timestamp_count": invalid_timestamps,
        "tool_breakdown": dict(sorted(tools.items())),
    }


def inspect_session(run_root: Path, worker: Mapping[str, Any]) -> dict[str, Any]:
    session_id = worker.get("session_id")
    directory = _path_from_state(worker.get("session_directory"), run_root)
    candidates: list[Path] = []
    if isinstance(session_id, str) and session_id:
        suffix = f"_{session_id}.jsonl"
        if directory is not None and directory.is_dir():
            try:
                candidates.extend(
                    path for path in directory.iterdir() if path.is_file() and path.name.endswith(suffix)
                )
            except OSError:
                pass
        if not candidates:
            session_root = run_root / "sessions"
            if session_root.is_dir():
                try:
                    candidates.extend(
                        path
                        for path in session_root.rglob("*.jsonl")
                        if path.is_file() and path.name.endswith(suffix)
                    )
                except OSError:
                    pass
    unique = sorted({str(path.resolve()): path for path in candidates}.values(), key=str)
    files = [_session_file_metrics(path, run_root) for path in unique]
    first_values = [
        instant
        for instant in (_parse_timestamp(item["first_timestamp_utc"]) for item in files)
        if instant is not None
    ]
    last_values = [
        instant
        for instant in (_parse_timestamp(item["last_timestamp_utc"]) for item in files)
        if instant is not None
    ]
    first = min(first_values) if first_values else None
    last = max(last_values) if last_values else None
    additive = (
        "bytes",
        "record_count",
        "message_records",
        "assistant_turns",
        "user_turns",
        "tool_result_turns",
        "tool_calls",
        "tool_errors",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "reasoning_tokens",
        "total_tokens",
        "invalid_timestamp_count",
    )
    totals = {name: sum(_number(item.get(name)) for item in files) for name in additive}
    tool_breakdown = Counter()
    for item in files:
        tool_breakdown.update(item.get("tool_breakdown", {}))
    return {
        "session_id": session_id if isinstance(session_id, str) else None,
        "directory": _display_path(directory, run_root),
        "match_count": len(files),
        "present": bool(files),
        "ambiguous": len(files) > 1,
        "jsonl_valid": all(item["jsonl_valid"] for item in files) if files else None,
        "files": files,
        **totals,
        "session_bytes": totals["bytes"],
        "first_timestamp_utc": first.isoformat().replace("+00:00", "Z") if first else None,
        "last_timestamp_utc": last.isoformat().replace("+00:00", "Z") if last else None,
        "wall_time_seconds": (last - first).total_seconds() if first and last else None,
        "tool_breakdown": dict(sorted(tool_breakdown.items())),
    }


def _parse_exit(path: Path | None, run_root: Path) -> dict[str, Any]:
    result = {
        "path": _display_path(path, run_root),
        "exists": False,
        "valid": None,
        "code": None,
        "error": None,
    }
    if path is None:
        return result
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    result["exists"] = True
    try:
        result["code"] = int(text, 10)
        result["valid"] = True
    except ValueError as exc:
        result["valid"] = False
        result["error"] = f"ValueError: {exc}"
    return result


def _load_worker_configs(
    state: Mapping[str, Any], run_root: Path
) -> tuple[dict[str, Mapping[str, Any]], list[dict[str, Any]]]:
    configs: dict[str, Mapping[str, Any]] = {}
    sources: list[dict[str, Any]] = []

    config_path = _path_from_state(state.get("config_path"), run_root)
    if config_path is not None:
        entry: dict[str, Any] = {
            "kind": "run_config",
            "path": _display_path(config_path, run_root),
            "exists": config_path.is_file(),
            "sha256": None,
            "expected_sha256": state.get("config_sha256"),
            "hash_matches": None,
            "json_valid": None,
            "used": False,
            "error": None,
        }
        if config_path.is_file():
            try:
                entry["sha256"] = _sha256(config_path)
                entry["hash_matches"] = entry["sha256"] == entry["expected_sha256"]
                document, error = _read_json(config_path)
                entry["json_valid"] = error is None
                entry["error"] = error
                if error is None and entry["hash_matches"] and isinstance(document, dict):
                    workers = document.get("workers")
                    if isinstance(workers, list):
                        for worker in workers:
                            if isinstance(worker, dict) and isinstance(worker.get("id"), str):
                                configs[worker["id"]] = worker
                        entry["used"] = True
            except OSError as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
        sources.append(entry)

    stage_states = state.get("stages")
    if isinstance(stage_states, list):
        for stage_state in stage_states:
            if not isinstance(stage_state, dict):
                continue
            stage_path = _path_from_state(stage_state.get("stage_config_file"), run_root)
            if stage_path is None:
                continue
            entry = {
                "kind": "frozen_stage_config",
                "stage": stage_state.get("id"),
                "path": _display_path(stage_path, run_root),
                "exists": stage_path.is_file(),
                "sha256": None,
                "expected_sha256": stage_state.get("stage_config_sha256"),
                "hash_matches": None,
                "json_valid": None,
                "used": False,
                "error": None,
            }
            if stage_path.is_file():
                try:
                    entry["sha256"] = _sha256(stage_path)
                    entry["hash_matches"] = entry["sha256"] == entry["expected_sha256"]
                    document, error = _read_json(stage_path)
                    entry["json_valid"] = error is None
                    entry["error"] = error
                    if error is None and entry["hash_matches"] and isinstance(document, dict):
                        workers = document.get("workers")
                        if isinstance(workers, list):
                            for worker in workers:
                                if isinstance(worker, dict) and isinstance(worker.get("id"), str):
                                    configs[worker["id"]] = worker
                            entry["used"] = True
                except OSError as exc:
                    entry["error"] = f"{type(exc).__name__}: {exc}"
            sources.append(entry)
    return configs, sources


def _frozen_schema_hashes(
    worker: Mapping[str, Any], run_root: Path
) -> dict[str, str]:
    manifest_path = _path_from_state(worker.get("context_manifest"), run_root)
    if manifest_path is None or not manifest_path.is_file():
        return {}
    manifest, error = _read_json(manifest_path)
    if error is not None or not isinstance(manifest, dict):
        return {}
    result: dict[str, str] = {}
    schemas = manifest.get("validation_schemas")
    if isinstance(schemas, list):
        for entry in schemas:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and isinstance(entry.get("sha256"), str)
            ):
                result[entry["path"].replace("\\", "/")] = entry["sha256"]
    return result


def _observed_status(state_status: str, attempt: int, exit_info: Mapping[str, Any]) -> str:
    if state_status == "stopped":
        return "stopped"
    if exit_info.get("valid") is True:
        if exit_info.get("code") == 0:
            return "validated" if state_status == "validated" else "completed"
        return "failed"
    if exit_info.get("exists"):
        return "failed"
    if state_status in {"pending", "launch_failed"}:
        return state_status
    if attempt <= 0:
        return "pending"
    return "incomplete"


def _artifact_path(
    output: Mapping[str, Any], worker: Mapping[str, Any], run_root: Path
) -> Path | None:
    if output.get("source") == "report":
        return _path_from_state(worker.get("output_file"), run_root)
    workspace = _path_from_state(worker.get("workspace_dir"), run_root)
    relative = output.get("path")
    if workspace is None or not isinstance(relative, str) or not relative:
        return None
    return workspace / relative


def summarize_worker(
    run_root: Path,
    repository_root: Path,
    worker: Mapping[str, Any],
    worker_config: Mapping[str, Any] | None,
) -> dict[str, Any]:
    worker_id = str(worker.get("id") or "")
    stage = str(worker.get("stage") or "")
    state_status = str(worker.get("status") or "unknown")
    attempt = _number(worker.get("attempt"))
    exit_info = _parse_exit(_path_from_state(worker.get("exit_file"), run_root), run_root)
    session = inspect_session(run_root, worker)
    captured_path = _path_from_state(worker.get("output_file"), run_root)
    captured, _ = inspect_json_artifact(
        captured_path,
        run_root,
        name="captured_output",
        source="report_capture",
    )

    frozen_hashes = _frozen_schema_hashes(worker, run_root)
    artifacts: list[dict[str, Any]] = []
    primary: dict[str, Any] | None = None
    if worker_config is not None and isinstance(worker_config.get("required_outputs"), list):
        for output in worker_config["required_outputs"]:
            if not isinstance(output, dict):
                continue
            schema_label = output.get("schema") if isinstance(output.get("schema"), str) else None
            normalized_schema = schema_label.replace("\\", "/") if schema_label else None
            schema_path = repository_root / schema_label if schema_label else None
            artifact, _ = inspect_json_artifact(
                _artifact_path(output, worker, run_root),
                run_root,
                name=str(output.get("name") or "unnamed"),
                source=str(output.get("source") or "unknown"),
                schema_path=schema_path,
                schema_label=normalized_schema,
                frozen_schema_sha256=frozen_hashes.get(normalized_schema or ""),
            )
            artifacts.append(artifact)
            if primary is None and schema_label is not None:
                primary = artifact
    if primary is None:
        primary = captured

    document_worker_id = None
    document_stage = None
    if primary["exists"] and primary["json_syntax_valid"]:
        primary_path = _path_from_state(worker.get("output_file"), run_root)
        if primary["source"] != "report":
            for output in worker_config.get("required_outputs", []) if worker_config else []:
                if isinstance(output, dict) and str(output.get("name")) == primary["name"]:
                    primary_path = _artifact_path(output, worker, run_root)
                    break
        if primary_path is not None:
            document, _ = _read_json(primary_path)
            if isinstance(document, dict):
                document_worker_id = document.get("worker_id")
                document_stage = document.get("stage")

    identity_valid: bool | None = None
    if document_worker_id is not None or document_stage is not None:
        identity_valid = (
            (document_worker_id is None or document_worker_id == worker_id)
            and (document_stage is None or document_stage == stage)
        )

    session_wall = session.get("wall_time_seconds")
    state_started = _parse_timestamp(worker.get("started_utc"))
    state_stopped = _parse_timestamp(worker.get("stopped_utc"))
    state_wall = (
        max(0.0, (state_stopped - state_started).total_seconds())
        if state_started is not None and state_stopped is not None
        else None
    )
    wall_time = session_wall if session_wall is not None else state_wall
    metrics = {
        "report_bytes": _number(primary.get("bytes")),
        "session_bytes": _number(session.get("session_bytes")),
        "total_tokens": _number(session.get("total_tokens")),
        "input_tokens": _number(session.get("input_tokens")),
        "output_tokens": _number(session.get("output_tokens")),
        "cache_read_tokens": _number(session.get("cache_read_tokens")),
        "reasoning_tokens": _number(session.get("reasoning_tokens")),
        "assistant_turns": _number(session.get("assistant_turns")),
        "user_turns": _number(session.get("user_turns")),
        "tool_result_turns": _number(session.get("tool_result_turns")),
        "tool_calls": _number(session.get("tool_calls")),
        "tool_errors": _number(session.get("tool_errors")),
        "wall_time_seconds": wall_time,
    }
    return {
        "id": worker_id,
        "stage": stage,
        "role": worker.get("role"),
        "status": _observed_status(state_status, attempt, exit_info),
        "state_status": state_status,
        "attempt": attempt,
        "pid": worker.get("pid"),
        "exit_code": exit_info["code"],
        "exit": exit_info,
        "timestamps": {
            "process_start_utc": worker.get("process_start_utc"),
            "started_utc": worker.get("started_utc"),
            "stopped_utc": worker.get("stopped_utc"),
            "session_first_utc": session.get("first_timestamp_utc"),
            "session_last_utc": session.get("last_timestamp_utc"),
        },
        "wall_time_seconds": wall_time,
        "report_bytes": metrics["report_bytes"],
        "report_exact_json": primary.get("exact_json_document"),
        "report_schema_valid": primary.get("schema", {}).get("valid"),
        "report_identity_valid": identity_valid,
        "report": primary,
        "captured_output": captured,
        "artifacts": artifacts,
        "session": session,
        "metrics": metrics,
        "budget": worker.get("budget"),
        "grades": {
            "central_correctness": None,
            "code_quality": None,
            "verbatim_acceptance": None,
            "notes": [],
        },
    }


def _mean(rows: Sequence[Mapping[str, Any]], field: str) -> float | None:
    if not rows:
        return None
    total = sum(float(row.get("metrics", {}).get(field) or 0) for row in rows)
    return round(total / len(rows), 6)


def aggregate_workers(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    attempted = [row for row in rows if _number(row.get("attempt")) > 0]
    totals: dict[str, int | float] = {}
    for field in AGGREGATE_FIELDS:
        total = sum(float(row.get("metrics", {}).get(field) or 0) for row in rows)
        totals[field] = int(total) if total.is_integer() else round(total, 6)
    state_counts = Counter(str(row.get("state_status")) for row in rows)
    observed_counts = Counter(str(row.get("status")) for row in rows)
    graded_counts = {
        axis: sum(row.get("grades", {}).get(axis) is not None for row in rows)
        for axis in GRADE_AXES
    }
    grade_means: dict[str, float | None] = {}
    for axis, definition in GRADE_AXES.items():
        values = [
            row.get("grades", {}).get(axis)
            for row in rows
            if isinstance(row.get("grades", {}).get(axis), (int, float))
            and not isinstance(row.get("grades", {}).get(axis), bool)
        ]
        grade_means[axis] = round(sum(values) / len(values), 6) if values else None
    return {
        "counts": {
            "workers": len(rows),
            "attempted_workers": len(attempted),
            "unattempted_workers": len(rows) - len(attempted),
            "exit_observed_workers": sum(row.get("exit_code") is not None for row in rows),
            "zero_exit_workers": sum(row.get("exit_code") == 0 for row in rows),
            "nonzero_exit_workers": sum(
                row.get("exit_code") is not None and row.get("exit_code") != 0 for row in rows
            ),
            "report_present_workers": sum(bool(row.get("report", {}).get("exists")) for row in rows),
            "exact_json_report_workers": sum(row.get("report_exact_json") is True for row in rows),
            "schema_valid_report_workers": sum(row.get("report_schema_valid") is True for row in rows),
            "schema_invalid_report_workers": sum(row.get("report_schema_valid") is False for row in rows),
            "session_present_workers": sum(bool(row.get("session", {}).get("present")) for row in rows),
            "malformed_session_workers": sum(
                row.get("session", {}).get("jsonl_valid") is False for row in rows
            ),
            "state_status": dict(sorted(state_counts.items())),
            "observed_status": dict(sorted(observed_counts.items())),
            "graded": graded_counts,
        },
        "totals": totals,
        "means_per_worker": {field: _mean(rows, field) for field in AGGREGATE_FIELDS},
        "means_per_attempted_worker": {
            field: _mean(attempted, field) for field in AGGREGATE_FIELDS
        },
        "grade_means": grade_means,
        "mean_policy": {
            "per_worker": "All state workers; missing artifacts and metrics contribute zero.",
            "per_attempted_worker": "All workers with attempt > 0, including failed, stopped, and malformed workers; missing metrics contribute zero.",
        },
    }


def snapshot_run(run_root: Path, *, generated_utc: str | None = None) -> dict[str, Any]:
    run_root = run_root.resolve()
    state_path = run_root / "state.json"
    try:
        state_raw = state_path.read_bytes()
        state = _strict_json_loads(state_raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SnapshotError(f"cannot read {state_path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(state, dict):
        raise SnapshotError(f"{state_path} does not contain a JSON object")
    state_workers = state.get("workers")
    if not isinstance(state_workers, list):
        raise SnapshotError(f"{state_path} has no workers array")
    workers = [worker for worker in state_workers if isinstance(worker, dict)]
    malformed_state_workers = len(state_workers) - len(workers)
    repository_root = _path_from_state(state.get("repository_root"), run_root) or run_root.parent.parent
    worker_configs, config_sources = _load_worker_configs(state, run_root)
    rows = [
        summarize_worker(run_root, repository_root, worker, worker_configs.get(str(worker.get("id"))))
        for worker in workers
    ]
    rows.sort(key=lambda row: (STAGES.index(row["stage"]) if row["stage"] in STAGES else 99, row["id"]))

    state_stage_order: list[str] = []
    if isinstance(state.get("stages"), list):
        for item in state["stages"]:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                state_stage_order.append(item["id"])
    for row in rows:
        if row["stage"] not in state_stage_order:
            state_stage_order.append(row["stage"])
    stages = {
        stage: aggregate_workers([row for row in rows if row["stage"] == stage])
        for stage in state_stage_order
    }
    return {
        "format": FORMAT,
        "generated_utc": generated_utc or _utc_now_text(),
        "grading_axes": GRADE_AXES,
        "run": {
            "run_id": state.get("run_id") or run_root.name,
            "run_root": str(run_root),
            "state_path": str(state_path),
            "state_sha256": hashlib.sha256(state_raw).hexdigest(),
            "state_version": state.get("state_version"),
            "model": state.get("model"),
            "created_utc": state.get("created_utc"),
            "updated_utc": state.get("updated_utc"),
            "configured_token_budget": state.get("total_token_budget"),
            "malformed_state_worker_entries": malformed_state_workers,
            "config_sources": config_sources,
        },
        "workers": rows,
        "aggregates": {"stages": stages, "run": aggregate_workers(rows)},
    }


def resolve_run(value: str, swarm_root: Path) -> Path:
    supplied = Path(value)
    if supplied.is_dir() or supplied.is_absolute() or len(supplied.parts) > 1:
        return supplied.resolve()
    return (swarm_root / supplied).resolve()


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    repository_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="Run ID below out/pi-swarm, or a run directory path")
    parser.add_argument(
        "--swarm-root",
        type=Path,
        default=repository_root / "out" / "pi-swarm",
        help="Root used when RUN is an ID (default: repository out/pi-swarm)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write atomically to this path; default is stdout and never mutates the run",
    )
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")
    args = parser.parse_args(argv)
    try:
        payload = snapshot_run(resolve_run(args.run, args.swarm_root))
    except SnapshotError as exc:
        parser.error(str(exc))
    if args.compact:
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    else:
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(text)
    else:
        _write_atomic(args.output.resolve(), text)
        print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
