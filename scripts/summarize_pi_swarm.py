#!/usr/bin/env python3
"""Summarize token, tool, timing, and process metrics for a Pi swarm run."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


FIELDS = (
    "id",
    "kind",
    "address",
    "exit_code",
    "duration_seconds",
    "assistant_turns",
    "tool_calls",
    "tool_errors",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "reasoning_tokens",
    "total_tokens",
    "reported_cost_usd",
    "report_bytes",
    "session_bytes",
    "tool_breakdown",
)


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def summarize_worker(run_root: Path, worker: dict[str, object]) -> dict[str, object]:
    session_id = str(worker["session_id"])
    matches = sorted((run_root / "sessions").glob(f"*_{session_id}.jsonl"))
    if len(matches) != 1:
        raise RuntimeError(f"{worker['id']}: expected one session, found {len(matches)}")
    session_path = matches[0]
    first: datetime | None = None
    last: datetime | None = None
    assistant_turns = 0
    tool_errors = 0
    tools: Counter[str] = Counter()
    usage = Counter()
    reported_cost = 0.0

    with session_path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{session_path}:{number}: {exc}") from exc
            timestamp = record.get("timestamp")
            if isinstance(timestamp, str):
                instant = parse_timestamp(timestamp)
                first = instant if first is None else min(first, instant)
                last = instant if last is None else max(last, instant)
            if record.get("type") != "message":
                continue
            message = record.get("message")
            if not isinstance(message, dict):
                continue
            role = message.get("role")
            if role == "assistant":
                assistant_turns += 1
                raw_usage = message.get("usage")
                if isinstance(raw_usage, dict):
                    for source, target in (
                        ("input", "input_tokens"),
                        ("output", "output_tokens"),
                        ("cacheRead", "cache_read_tokens"),
                        ("reasoning", "reasoning_tokens"),
                        ("totalTokens", "total_tokens"),
                    ):
                        value = raw_usage.get(source, 0)
                        if isinstance(value, (int, float)):
                            usage[target] += int(value)
                    cost = raw_usage.get("cost")
                    if isinstance(cost, dict) and isinstance(cost.get("total"), (int, float)):
                        reported_cost += float(cost["total"])
                content = message.get("content")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "toolCall":
                            tools[str(block.get("name", "unknown"))] += 1
            elif role == "toolResult" and message.get("isError") is True:
                tool_errors += 1

    exit_path = Path(str(worker["exit_file"]))
    exit_code = int(exit_path.read_text(encoding="utf-8").strip())
    report_path = Path(str(worker["output_file"]))
    duration = int((last - first).total_seconds()) if first is not None and last is not None else 0
    return {
        "id": str(worker["id"]),
        "kind": str(worker["kind"]),
        "address": str(worker.get("address") or ""),
        "exit_code": exit_code,
        "duration_seconds": duration,
        "assistant_turns": assistant_turns,
        "tool_calls": sum(tools.values()),
        "tool_errors": tool_errors,
        **{name: usage[name] for name in (
            "input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens", "total_tokens"
        )},
        "reported_cost_usd": f"{reported_cost:.8f}",
        "report_bytes": report_path.stat().st_size,
        "session_bytes": session_path.stat().st_size,
        "tool_breakdown": ",".join(f"{name}:{tools[name]}" for name in sorted(tools)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_root", type=Path)
    args = parser.parse_args()
    run_root = args.run_root.resolve()
    workers = json.loads((run_root / "workers.json").read_text(encoding="utf-8"))
    if not isinstance(workers, list):
        workers = [workers]
    rows = [summarize_worker(run_root, worker) for worker in workers]
    rows.sort(key=lambda row: row["id"])

    tsv_path = run_root / "worker_metrics.tsv"
    with tsv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    totals = {
        "workers": len(rows),
        "successful_workers": sum(row["exit_code"] == 0 for row in rows),
        "assistant_turns": sum(int(row["assistant_turns"]) for row in rows),
        "tool_calls": sum(int(row["tool_calls"]) for row in rows),
        "tool_errors": sum(int(row["tool_errors"]) for row in rows),
        "input_tokens": sum(int(row["input_tokens"]) for row in rows),
        "output_tokens": sum(int(row["output_tokens"]) for row in rows),
        "cache_read_tokens": sum(int(row["cache_read_tokens"]) for row in rows),
        "reasoning_tokens": sum(int(row["reasoning_tokens"]) for row in rows),
        "total_tokens": sum(int(row["total_tokens"]) for row in rows),
        "reported_cost_usd": f"{sum(float(row['reported_cost_usd']) for row in rows):.8f}",
        "max_worker_duration_seconds": max((int(row["duration_seconds"]) for row in rows), default=0),
    }
    payload = {"format": "pi-swarm-metrics-v1", "rows": rows, "totals": totals}
    json_path = run_root / "worker_metrics.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"workers={totals['workers']} successful={totals['successful_workers']} "
          f"tokens={totals['total_tokens']} cost_usd={totals['reported_cost_usd']}")
    print(f"tsv={tsv_path}")
    print(f"json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
