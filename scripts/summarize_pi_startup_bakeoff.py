#!/usr/bin/env python3
"""Summarize only the continuation segment of a Pi startup-audit bake-off."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import stat
import tempfile
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Iterable


FORMAT = "pi-startup-bakeoff-metrics-v1"
EXPECTED_WORKER_IDS = tuple(f"w{number:02d}" for number in range(1, 21))
REQUIRED_CANDIDATE_FILES = (
    "README.md",
    "gen_startup_audit.py",
    "test_gen_startup_audit.py",
)
TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "total_tokens",
)
TSV_FIELDS = (
    "id",
    "session_id",
    "session_file",
    "session_match_count",
    "continuation_user_ordinal",
    "segment_start_strategy",
    "segment_started_at",
    "segment_ended_at",
    "wall_duration_seconds",
    "exit_state",
    "exit_code",
    "assistant_turns",
    "tool_calls",
    "tool_errors",
    *TOKEN_FIELDS,
    "reported_cost_usd",
    "session_bytes",
    "segment_bytes",
    "segment_records",
    "session_parse_errors",
    "segment_parse_errors",
    "report_bytes",
    "error_log_bytes",
    "candidate_state",
    "candidate_file_count",
    "candidate_bytes",
    "candidate_lines",
    "candidate_symlink_count",
    "candidate_scan_errors",
    "required_file_count",
    "missing_required_files",
    "extra_candidate_files",
    "candidate_file_paths",
    "write_actions_seen",
    "inside_write_actions",
    "outside_write_actions",
    "outside_temp_write_actions",
    "outside_non_temp_write_actions",
    "unresolved_write_actions",
    "outside_write_evidence",
    "unresolved_write_evidence",
    "tool_breakdown",
    "warnings",
)

_WINDOWS_ENV = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_UNRESOLVED_PATH = re.compile(r"[$*?]|\[[^]]*\]")
_QUOTED_OR_BARE = r'(?P<target>"[^"\r\n]+"|\'[^\'\r\n]+\'|[^\s;&|]+)'
_SHELL_CD = re.compile(
    r"(?im)(?:^|[;|{}\r\n])\s*(?:Set-Location|cd)\s+"
    r"(?:(?:-LiteralPath|-Path)\s+)?" + _QUOTED_OR_BARE
)
_SHELL_OUTPUT_OPTION = re.compile(
    r"(?i)(?<!\S)(?:--output(?:-dir)?|--out-dir|-o)(?:\s+|=)" + _QUOTED_OR_BARE
)
_SHELL_MUTATION = re.compile(
    r"(?im)(?:^|[;|{}\r\n])\s*&?\s*"
    r"(?P<verb>Set-Content|Add-Content|Clear-Content|Out-File|New-Item|"
    r"Remove-Item|Rename-Item|Move-Item|Copy-Item|rm|del|erase|mkdir|md|mv|move|cp|copy)"
    r"\b(?P<tail>[^;|{}\r\n]*)"
)
_PATH_METHOD_WRITE = re.compile(
    r"(?i)Path\(\s*[rubf]*([\"'])(?P<target>.+?)\1\s*\)\."
    r"(?:write_text|write_bytes|touch|unlink|rename|replace)\b"
)
_OPEN_WRITE = re.compile(
    r"(?i)open\(\s*[rubf]*([\"'])(?P<target>.+?)\1\s*,\s*"
    r"([\"'])(?P<mode>[^\"']*[wax+][^\"']*)\3"
)
_OS_WRITE = re.compile(
    r"(?i)os\.(?:remove|unlink|mkdir|makedirs|rmdir|removedirs|rename|replace)"
    r"\(\s*[rubf]*([\"'])(?P<target>.+?)\1"
)
_PATCH_PATH = re.compile(r"(?m)^\*\*\* (?:Add|Update|Delete) File:\s*(?P<target>.+?)\s*$")
_TOKEN = re.compile(r'"[^"\r\n]*"|\'[^\'\r\n]*\'|\S+')


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_root",
        type=Path,
        help="Bake-off run root containing workers.json and candidates/",
    )
    parser.add_argument(
        "prior_wave_session_root",
        type=Path,
        help="Prior wave's sessions directory, or its parent run directory",
    )
    return parser.parse_args(argv)


def worker_sort_key(worker_id: str) -> tuple[int, str]:
    match = re.fullmatch(r"w(\d+)", worker_id, re.IGNORECASE)
    return (int(match.group(1)), worker_id.casefold()) if match else (10**9, worker_id.casefold())


def resolve_metadata_path(value: object, default: Path, base: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        return default.resolve(strict=False)
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve(strict=False)


def load_worker_metadata(run_root: Path) -> tuple[dict[str, dict[str, object]], list[str]]:
    path = run_root / "workers.json"
    warnings: list[str] = []
    records: list[object] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload if isinstance(payload, list) else [payload]
    except FileNotFoundError:
        warnings.append(f"missing worker metadata: {path}")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        warnings.append(f"could not read worker metadata: {exc}")

    workers: dict[str, dict[str, object]] = {}
    for position, raw in enumerate(records, 1):
        if not isinstance(raw, dict):
            warnings.append(f"workers.json item {position} is not an object")
            continue
        worker_id = raw.get("id")
        if not isinstance(worker_id, str) or not re.fullmatch(r"w\d+", worker_id, re.IGNORECASE):
            warnings.append(f"workers.json item {position} has an invalid id")
            continue
        worker_id = worker_id.lower()
        if worker_id in workers:
            warnings.append(f"duplicate worker metadata for {worker_id}; kept first item")
            continue
        workers[worker_id] = raw
    return workers, warnings


def sessions_directory(root: Path) -> Path:
    root = root.resolve(strict=False)
    nested = root / "sessions"
    return nested if nested.is_dir() else root


def find_session_files(session_root: Path, session_id: str, worker_id: str) -> list[Path]:
    if not session_root.is_dir():
        return []
    matches: list[Path] = []
    if session_id:
        matches.extend(session_root.glob(f"*_{session_id}.jsonl"))
    if not matches:
        suffix = f"-{worker_id}.jsonl".casefold()
        matches.extend(path for path in session_root.glob("*.jsonl") if path.name.casefold().endswith(suffix))
    unique = {str(path.resolve(strict=False)).casefold(): path.resolve(strict=False) for path in matches}
    return sorted(unique.values(), key=lambda path: path.name.casefold())


def message_text(message: dict[str, object]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    pieces = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            pieces.append(str(block["text"]))
    return "\n".join(pieces)


def normalized_marker(value: Path | str) -> str:
    return str(value).replace("\\", "/").casefold()


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def numeric_token(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def decimal_cost(value: object) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return Decimal(0)
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return Decimal(0)


def unwrap_path_token(value: str) -> str:
    token = value.strip().rstrip(",)")
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        token = token[1:-1]
    return token.strip()


def expand_powershell_environment(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        return os.environ.get(name, match.group(0))

    return os.path.expandvars(_WINDOWS_ENV.sub(replace, value))


def resolve_observed_path(value: str, base: Path) -> tuple[Path | None, str]:
    token = expand_powershell_environment(unwrap_path_token(value))
    if not token:
        return None, "empty path"
    if token.startswith("-") or _UNRESOLVED_PATH.search(token):
        return None, "path contains an option, wildcard, or unresolved variable"
    try:
        path = Path(token).expanduser()
        if not path.is_absolute():
            path = base / path
        return path.resolve(strict=False), ""
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"could not normalize path: {exc}"


def path_is_within(path: Path, directory: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(path)), os.path.normcase(str(directory)))) == os.path.normcase(
            str(directory)
        )
    except ValueError:
        return False


def path_is_os_temp(path: Path) -> bool:
    roots = {tempfile.gettempdir()}
    roots.update(value for name in ("TEMP", "TMP", "TMPDIR") if (value := os.environ.get(name)))
    for raw_root in roots:
        try:
            if path_is_within(path, Path(raw_root).resolve(strict=False)):
                return True
        except (OSError, RuntimeError, ValueError):
            continue
    return False


def positional_tokens(tail: str) -> list[str]:
    tokens = [unwrap_path_token(match.group(0)) for match in _TOKEN.finditer(tail)]
    positional: list[str] = []
    index = 0
    options_with_values = {
        "-encoding",
        "-filter",
        "-include",
        "-exclude",
        "-itemtype",
        "-value",
        "-whatif",
        "-confirm",
    }
    path_options = {"-path", "-literalpath", "-destination", "-dest", "-outfile"}
    while index < len(tokens):
        token = tokens[index]
        lowered = token.casefold()
        if lowered in path_options:
            index += 2
            continue
        if lowered in options_with_values:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        positional.append(token)
        index += 1
    return positional


def explicit_option_paths(tail: str, options: Iterable[str]) -> list[tuple[str, str]]:
    alternation = "|".join(re.escape(option) for option in options)
    pattern = re.compile(rf"(?i)(?:{alternation})\s+{_QUOTED_OR_BARE}")
    return [("shell_option", match.group("target")) for match in pattern.finditer(tail)]


def shell_redirection_paths(command: str) -> list[str]:
    """Extract PowerShell redirection targets while ignoring quoted source text."""
    targets: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command):
        character = command[index]
        if character == "`":
            index += 2
            continue
        if quote is not None:
            if character == quote:
                if quote == "'" and index + 1 < len(command) and command[index + 1] == "'":
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if character in "\"'":
            quote = character
            index += 1
            continue
        if character != ">" or (index + 1 < len(command) and command[index + 1] in ">&"):
            index += 1
            continue
        index += 2 if index + 1 < len(command) and command[index + 1] == ">" else 1
        while index < len(command) and command[index].isspace():
            index += 1
        if index >= len(command) or command[index] == "&":
            continue
        match = _TOKEN.match(command, index)
        if match is not None:
            targets.append(match.group(0))
            index = match.end()
    return targets


def extract_shell_write_targets(command: str, default_base: Path) -> tuple[list[tuple[str, str, Path]], int]:
    """Return revealed write targets and a count of unresolvable write actions."""
    base = default_base
    for match in _SHELL_CD.finditer(command):
        resolved, _ = resolve_observed_path(match.group("target"), base)
        if resolved is not None:
            base = resolved

    raw_targets: list[tuple[str, str]] = []
    raw_targets.extend(("shell_output_option", match.group("target")) for match in _SHELL_OUTPUT_OPTION.finditer(command))
    raw_targets.extend(("shell_redirect", target) for target in shell_redirection_paths(command))
    raw_targets.extend(("python_path_method", match.group("target")) for match in _PATH_METHOD_WRITE.finditer(command))
    raw_targets.extend(("python_open_write", match.group("target")) for match in _OPEN_WRITE.finditer(command))
    raw_targets.extend(("python_os_mutation", match.group("target")) for match in _OS_WRITE.finditer(command))

    unresolved_actions = 0
    for match in _SHELL_MUTATION.finditer(command):
        verb = match.group("verb").casefold()
        tail = match.group("tail")
        command_targets: list[tuple[str, str]] = []
        if verb in {"copy-item", "cp", "copy"}:
            command_targets.extend(explicit_option_paths(tail, ("-Destination", "-Dest")))
            positional = positional_tokens(tail)
            if len(positional) >= 2:
                command_targets.append((f"shell_{verb}_destination", positional[1]))
        elif verb in {"move-item", "rename-item", "mv", "move"}:
            command_targets.extend(explicit_option_paths(tail, ("-Path", "-LiteralPath", "-Destination", "-Dest")))
            positional = positional_tokens(tail)
            command_targets.extend((f"shell_{verb}_operand", token) for token in positional[:2])
        else:
            command_targets.extend(explicit_option_paths(tail, ("-Path", "-LiteralPath", "-OutFile")))
            positional = positional_tokens(tail)
            if positional:
                command_targets.append((f"shell_{verb}_target", positional[0]))
        if not command_targets:
            unresolved_actions += 1
        raw_targets.extend(command_targets)

    resolved_targets: list[tuple[str, str, Path]] = []
    seen: set[tuple[str, str]] = set()
    for source, raw_target in raw_targets:
        resolved, _ = resolve_observed_path(raw_target, base)
        if resolved is None:
            unresolved_actions += 1
            continue
        key = (source, os.path.normcase(str(resolved)))
        if key in seen:
            continue
        seen.add(key)
        resolved_targets.append((source, unwrap_path_token(raw_target), resolved))
    return resolved_targets, unresolved_actions


def tool_write_observations(
    tool_name: str,
    arguments: object,
    candidate_dir: Path,
    workspace_root: Path,
    session_line: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    inside: list[dict[str, object]] = []
    outside: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []
    lowered = tool_name.casefold()
    args = arguments if isinstance(arguments, dict) else {}
    targets: list[tuple[str, str, Path]] = []

    if lowered in {"write", "edit", "write_file", "edit_file"}:
        raw_path = next((args[key] for key in ("path", "file_path", "filePath") if isinstance(args.get(key), str)), None)
        if raw_path is None:
            unresolved.append({"line": session_line, "tool": tool_name, "reason": "write/edit call has no path"})
        else:
            resolved, reason = resolve_observed_path(raw_path, workspace_root)
            if resolved is None:
                unresolved.append({"line": session_line, "tool": tool_name, "target": raw_path, "reason": reason})
            else:
                targets.append(("tool_path", raw_path, resolved))
    elif lowered in {"apply_patch", "patch"}:
        patch_text = args.get("patch") or args.get("input")
        if not isinstance(patch_text, str) and isinstance(arguments, str):
            patch_text = arguments
        if isinstance(patch_text, str):
            patch_targets = [match.group("target") for match in _PATCH_PATH.finditer(patch_text)]
            if not patch_targets:
                unresolved.append({"line": session_line, "tool": tool_name, "reason": "patch call has no recognized file header"})
            for raw_path in patch_targets:
                resolved, reason = resolve_observed_path(raw_path, workspace_root)
                if resolved is None:
                    unresolved.append({"line": session_line, "tool": tool_name, "target": raw_path, "reason": reason})
                else:
                    targets.append(("patch_header", raw_path, resolved))
    elif lowered in {"powershell", "shell", "exec", "exec_command"}:
        command = next((args[key] for key in ("command", "cmd") if isinstance(args.get(key), str)), None)
        if command is not None:
            shell_targets, unresolved_count = extract_shell_write_targets(command, workspace_root)
            targets.extend(shell_targets)
            for _ in range(unresolved_count):
                unresolved.append(
                    {"line": session_line, "tool": tool_name, "reason": "shell mutation target could not be resolved"}
                )

    for source, raw_target, resolved in targets:
        evidence = {
            "line": session_line,
            "tool": tool_name,
            "source": source,
            "target": raw_target,
            "resolved": str(resolved),
        }
        if path_is_within(resolved, candidate_dir):
            inside.append(evidence)
        else:
            evidence["outside_class"] = "os_temp" if path_is_os_temp(resolved) else "other"
            outside.append(evidence)
    return inside, outside, unresolved


def scan_candidate(candidate_dir: Path) -> dict[str, object]:
    result: dict[str, object] = {
        "candidate_state": "missing",
        "candidate_file_count": 0,
        "candidate_bytes": 0,
        "candidate_lines": 0,
        "candidate_symlink_count": 0,
        "candidate_scan_errors": 0,
        "required_file_count": 0,
        "missing_required_files": list(REQUIRED_CANDIDATE_FILES),
        "extra_candidate_files": [],
        "candidate_file_paths": [],
    }
    if not candidate_dir.is_dir():
        return result

    result["candidate_state"] = "present"
    files: list[dict[str, object]] = []
    scan_errors = 0
    try:
        walker = os.walk(candidate_dir, topdown=True, followlinks=False)
        for directory, subdirectories, filenames in walker:
            subdirectories.sort(key=str.casefold)
            filenames.sort(key=str.casefold)
            for filename in filenames:
                path = Path(directory) / filename
                relative = path.relative_to(candidate_dir).as_posix()
                try:
                    metadata = path.lstat()
                    is_symlink = stat.S_ISLNK(metadata.st_mode)
                    if not is_symlink and not stat.S_ISREG(metadata.st_mode):
                        continue
                    line_count = 0
                    if not is_symlink:
                        final_byte = b""
                        with path.open("rb") as stream:
                            while chunk := stream.read(1024 * 1024):
                                line_count += chunk.count(b"\n")
                                final_byte = chunk[-1:]
                        if metadata.st_size and final_byte != b"\n":
                            line_count += 1
                    files.append(
                        {
                            "path": relative,
                            "bytes": metadata.st_size,
                            "lines": line_count,
                            "symlink": is_symlink,
                        }
                    )
                except (OSError, RuntimeError, ValueError):
                    scan_errors += 1
    except (OSError, RuntimeError):
        scan_errors += 1

    files.sort(key=lambda item: str(item["path"]).casefold())
    paths = [str(item["path"]) for item in files]
    present_top_level = {path for path in paths if "/" not in path}
    missing = [name for name in REQUIRED_CANDIDATE_FILES if name not in present_top_level]
    extras = [path for path in paths if path not in REQUIRED_CANDIDATE_FILES]
    result.update(
        {
            "candidate_file_count": len(files),
            "candidate_bytes": sum(int(item["bytes"]) for item in files),
            "candidate_lines": sum(int(item["lines"]) for item in files),
            "candidate_symlink_count": sum(bool(item["symlink"]) for item in files),
            "candidate_scan_errors": scan_errors,
            "required_file_count": len(REQUIRED_CANDIDATE_FILES) - len(missing),
            "missing_required_files": missing,
            "extra_candidate_files": extras,
            "candidate_file_paths": paths,
        }
    )
    return result


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def read_exit_state(path: Path) -> tuple[str, int | None, str | None]:
    try:
        content = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "incomplete", None, None
    except (OSError, UnicodeError) as exc:
        return "malformed", None, f"could not read exit file: {exc}"
    try:
        code = int(content)
    except ValueError:
        return "malformed", None, "exit file does not contain an integer"
    return ("success" if code == 0 else "failed"), code, None


def blank_session_metrics() -> dict[str, object]:
    return {
        "continuation_user_ordinal": "",
        "segment_start_strategy": "missing",
        "segment_started_at": "",
        "segment_ended_at": "",
        "wall_duration_seconds": 0,
        "assistant_turns": 0,
        "tool_calls": 0,
        "tool_errors": 0,
        **{field: 0 for field in TOKEN_FIELDS},
        "reported_cost_usd": "0.00000000",
        "session_bytes": 0,
        "segment_bytes": 0,
        "segment_records": 0,
        "session_parse_errors": 0,
        "segment_parse_errors": 0,
        "tool_breakdown": {},
        "write_actions_seen": 0,
        "inside_write_actions": 0,
        "outside_write_actions": 0,
        "outside_temp_write_actions": 0,
        "outside_non_temp_write_actions": 0,
        "unresolved_write_actions": 0,
        "outside_write_evidence": [],
        "unresolved_write_evidence": [],
        "warnings": [],
    }


def summarize_session(
    session_path: Path,
    worker: dict[str, object],
    candidate_dir: Path,
    workspace_root: Path,
) -> dict[str, object]:
    summary = blank_session_metrics()
    records: list[tuple[int, int, dict[str, object]]] = []
    parse_error_lines: list[int] = []
    raw_line_sizes: dict[int, int] = {}
    try:
        with session_path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                raw_line_sizes[line_number] = len(raw_line)
                try:
                    record = json.loads(raw_line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    parse_error_lines.append(line_number)
                    continue
                if not isinstance(record, dict):
                    parse_error_lines.append(line_number)
                    continue
                records.append((line_number, len(raw_line), record))
        summary["session_bytes"] = session_path.stat().st_size
    except OSError as exc:
        summary["warnings"].append(f"could not read session: {exc}")
        return summary

    user_records: list[tuple[int, int, dict[str, object], str]] = []
    prompt_marker = normalized_marker(str(worker.get("prompt_file") or ""))
    candidate_marker = normalized_marker(candidate_dir)
    for record_index, (line_number, _, record) in enumerate(records):
        if record.get("type") != "message" or not isinstance(record.get("message"), dict):
            continue
        message = record["message"]
        if message.get("role") != "user":
            continue
        user_records.append((record_index, line_number, record, normalized_marker(message_text(message))))

    selected: tuple[int, int, dict[str, object], str] | None = None
    strategy = "missing"
    for ordinal, candidate in enumerate(user_records, 1):
        text = candidate[3]
        if ordinal >= 2 and ((prompt_marker and prompt_marker in text) or candidate_marker in text):
            selected = candidate
            strategy = "bakeoff_prompt_match"
            break
    if selected is None and len(user_records) >= 2:
        selected = user_records[1]
        strategy = "second_user_fallback"
    if selected is None:
        summary["warnings"].append("continued segment not found: fewer than two user prompts")
        summary["session_parse_errors"] = len(parse_error_lines)
        return summary

    selected_record_index = selected[0]
    selected_line = selected[1]
    ordinal = user_records.index(selected) + 1
    segment = records[selected_record_index:]
    summary["continuation_user_ordinal"] = ordinal
    summary["segment_start_strategy"] = strategy
    summary["segment_records"] = len(segment)
    summary["segment_bytes"] = sum(size for line_number, size in raw_line_sizes.items() if line_number >= selected_line)
    summary["session_parse_errors"] = len(parse_error_lines)
    summary["segment_parse_errors"] = sum(line >= selected_line for line in parse_error_lines)

    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    invalid_timestamps = 0
    tools: Counter[str] = Counter()
    usage: Counter[str] = Counter()
    cost = Decimal(0)
    inside_writes: list[dict[str, object]] = []
    outside_writes: list[dict[str, object]] = []
    unresolved_writes: list[dict[str, object]] = []

    usage_mapping = (
        ("input", "input_tokens"),
        ("output", "output_tokens"),
        ("cacheRead", "cache_read_tokens"),
        ("cacheWrite", "cache_write_tokens"),
        ("reasoning", "reasoning_tokens"),
    )
    for line_number, _, record in segment:
        timestamp_value = record.get("timestamp")
        timestamp = parse_timestamp(timestamp_value)
        if isinstance(timestamp_value, str) and timestamp is None:
            invalid_timestamps += 1
        if timestamp is not None:
            first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
            last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
        if record.get("type") != "message" or not isinstance(record.get("message"), dict):
            continue
        message = record["message"]
        role = message.get("role")
        if role == "assistant":
            summary["assistant_turns"] = int(summary["assistant_turns"]) + 1
            raw_usage = message.get("usage")
            if isinstance(raw_usage, dict):
                component_total = 0
                for source, target in usage_mapping:
                    value = numeric_token(raw_usage.get(source))
                    if value is not None:
                        usage[target] += value
                        component_total += value
                total = numeric_token(raw_usage.get("totalTokens"))
                usage["total_tokens"] += total if total is not None else component_total
                raw_cost = raw_usage.get("cost")
                if isinstance(raw_cost, dict):
                    cost += decimal_cost(raw_cost.get("total"))
            content = message.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "toolCall":
                        continue
                    tool_name = str(block.get("name") or "unknown")
                    tools[tool_name] += 1
                    inside, outside, unresolved = tool_write_observations(
                        tool_name,
                        block.get("arguments"),
                        candidate_dir,
                        workspace_root,
                        line_number,
                    )
                    inside_writes.extend(inside)
                    outside_writes.extend(outside)
                    unresolved_writes.extend(unresolved)
        elif role == "toolResult" and message.get("isError") is True:
            summary["tool_errors"] = int(summary["tool_errors"]) + 1

    summary.update({field: usage[field] for field in TOKEN_FIELDS})
    summary["reported_cost_usd"] = f"{cost:.8f}"
    summary["tool_breakdown"] = dict(sorted(tools.items(), key=lambda item: item[0].casefold()))
    summary["tool_calls"] = sum(tools.values())
    summary["inside_write_actions"] = len(inside_writes)
    summary["outside_write_actions"] = len(outside_writes)
    summary["outside_temp_write_actions"] = sum(item.get("outside_class") == "os_temp" for item in outside_writes)
    summary["outside_non_temp_write_actions"] = sum(
        item.get("outside_class") != "os_temp" for item in outside_writes
    )
    summary["unresolved_write_actions"] = len(unresolved_writes)
    summary["write_actions_seen"] = len(inside_writes) + len(outside_writes) + len(unresolved_writes)
    summary["outside_write_evidence"] = outside_writes
    summary["unresolved_write_evidence"] = unresolved_writes
    summary["segment_started_at"] = format_timestamp(first_timestamp)
    summary["segment_ended_at"] = format_timestamp(last_timestamp)
    if first_timestamp is not None and last_timestamp is not None:
        summary["wall_duration_seconds"] = round((last_timestamp - first_timestamp).total_seconds(), 3)
    if invalid_timestamps:
        summary["warnings"].append(f"{invalid_timestamps} records had invalid timestamps")
    if ordinal != 2:
        summary["warnings"].append(f"bake-off continuation is user prompt {ordinal}, not prompt 2")
    return summary


def infer_workspace_root(run_root: Path) -> Path:
    # Expected layout is <workspace>/out/pi-swarm/<run>. Falling back to the
    # current directory is less useful and can misclassify relative tool paths.
    if run_root.parent.name.casefold() == "pi-swarm" and run_root.parent.parent.name.casefold() == "out":
        return run_root.parent.parent.parent.resolve(strict=False)
    return run_root.parent.resolve(strict=False)


def summarize_worker(
    run_root: Path,
    session_root: Path,
    worker_id: str,
    worker: dict[str, object],
    workspace_root: Path,
) -> dict[str, object]:
    session_id = str(worker.get("session_id") or "")
    candidate_dir = resolve_metadata_path(
        worker.get("candidate_dir"), run_root / "candidates" / worker_id, run_root
    )
    prompt_file = resolve_metadata_path(worker.get("prompt_file"), run_root / "prompts" / f"{worker_id}.md", run_root)
    exit_file = resolve_metadata_path(worker.get("exit_file"), run_root / "reports" / f"{worker_id}.exit.txt", run_root)
    report_file = resolve_metadata_path(worker.get("output_file"), run_root / "reports" / f"{worker_id}.md", run_root)
    error_file = resolve_metadata_path(worker.get("error_file"), run_root / "reports" / f"{worker_id}.err.txt", run_root)
    normalized_worker = dict(worker)
    normalized_worker["prompt_file"] = str(prompt_file)

    matches = find_session_files(session_root, session_id, worker_id)
    session_path = matches[-1] if matches else None
    session_metrics = (
        summarize_session(session_path, normalized_worker, candidate_dir, workspace_root)
        if session_path is not None
        else blank_session_metrics()
    )
    warnings = list(session_metrics.pop("warnings"))
    if not matches:
        warnings.append("no matching Pi session JSONL")
    elif len(matches) > 1:
        warnings.append(f"found {len(matches)} sessions; selected lexicographically last")

    exit_state, exit_code, exit_warning = read_exit_state(exit_file)
    if exit_warning:
        warnings.append(exit_warning)
    row: dict[str, object] = {
        "id": worker_id,
        "session_id": session_id,
        "session_file": str(session_path) if session_path is not None else "",
        "session_match_count": len(matches),
        **session_metrics,
        "exit_state": exit_state,
        "exit_code": exit_code,
        "report_bytes": file_size(report_file),
        "error_log_bytes": file_size(error_file),
        **scan_candidate(candidate_dir),
        "warnings": warnings,
    }
    return row


def tsv_value(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return value


def render_tsv(rows: list[dict[str, object]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=TSV_FIELDS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: tsv_value(row.get(field)) for field in TSV_FIELDS})
    return stream.getvalue()


def atomic_write(path: Path, content: str) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def build_totals(rows: list[dict[str, object]]) -> dict[str, object]:
    total_cost = sum((Decimal(str(row["reported_cost_usd"])) for row in rows), Decimal(0))
    totals: dict[str, object] = {
        "workers": len(rows),
        "successful_workers": sum(row["exit_state"] == "success" for row in rows),
        "failed_workers": sum(row["exit_state"] == "failed" for row in rows),
        "incomplete_workers": sum(row["exit_state"] in {"incomplete", "malformed"} for row in rows),
        "workers_with_sessions": sum(int(row["session_match_count"]) > 0 for row in rows),
        "workers_with_segments": sum(bool(row["segment_started_at"]) for row in rows),
        "assistant_turns": sum(int(row["assistant_turns"]) for row in rows),
        "tool_calls": sum(int(row["tool_calls"]) for row in rows),
        "tool_errors": sum(int(row["tool_errors"]) for row in rows),
        **{field: sum(int(row[field]) for row in rows) for field in TOKEN_FIELDS},
        "reported_cost_usd": f"{total_cost:.8f}",
        "candidate_file_count": sum(int(row["candidate_file_count"]) for row in rows),
        "candidate_bytes": sum(int(row["candidate_bytes"]) for row in rows),
        "candidate_lines": sum(int(row["candidate_lines"]) for row in rows),
        "outside_write_actions": sum(int(row["outside_write_actions"]) for row in rows),
        "outside_temp_write_actions": sum(int(row["outside_temp_write_actions"]) for row in rows),
        "outside_non_temp_write_actions": sum(int(row["outside_non_temp_write_actions"]) for row in rows),
        "unresolved_write_actions": sum(int(row["unresolved_write_actions"]) for row in rows),
        "workers_with_outside_writes": sum(int(row["outside_write_actions"]) > 0 for row in rows),
        "workers_with_non_temp_outside_writes": sum(
            int(row["outside_non_temp_write_actions"]) > 0 for row in rows
        ),
        "max_wall_duration_seconds": max((float(row["wall_duration_seconds"]) for row in rows), default=0),
    }
    return totals


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_root = args.run_root.resolve(strict=False)
    if not run_root.is_dir():
        raise SystemExit(f"error: bake-off run root is not a directory: {run_root}")
    session_root = sessions_directory(args.prior_wave_session_root)
    workspace_root = infer_workspace_root(run_root)
    worker_metadata, metadata_warnings = load_worker_metadata(run_root)

    worker_ids = sorted(set(EXPECTED_WORKER_IDS) | set(worker_metadata), key=worker_sort_key)
    rows = [
        summarize_worker(run_root, session_root, worker_id, worker_metadata.get(worker_id, {}), workspace_root)
        for worker_id in worker_ids
    ]
    totals = build_totals(rows)
    payload = {
        "format": FORMAT,
        "run_root": str(run_root),
        "session_root": str(session_root),
        "workspace_root": str(workspace_root),
        "metadata_warnings": metadata_warnings,
        "rows": rows,
        "totals": totals,
    }

    tsv_path = run_root / "bakeoff_metrics.tsv"
    json_path = run_root / "bakeoff_metrics.json"
    atomic_write(tsv_path, render_tsv(rows))
    atomic_write(json_path, json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
    print(
        f"workers={totals['workers']} successful={totals['successful_workers']} "
        f"segments={totals['workers_with_segments']} tokens={totals['total_tokens']} "
        f"cost_usd={totals['reported_cost_usd']} outside_writes={totals['outside_write_actions']}"
    )
    print(f"tsv={tsv_path}")
    print(f"json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
