"""Verifies one batch of functions end to end (docs/lifted_tier.md, "Driver and ledger").

verify_batch lifts the functions, builds their runner, runs the reference
debugger and then the runner on the same job file, compares the result lines
and classifies every function. driver.py runs it in a worker pool; everything
that decides a function's status lives here, so this file is part of the hash
that keys finished batches.

Trial comparison:

  comparable  both sides report LM_S_OK
  matched     comparable, and terminal kind, a, b, digest and steps are equal
  excluded    any other status pair (the documented exclusion rules)

The runner is only given the trials the reference finished with LM_S_OK; the
others are excluded whatever the lifted side would report.

Step mode is used twice. A function with fewer than MIN_COMPARABLE comparable
fast trials has all its seeds re-run in step mode. A fast trial that does not
match is re-run in step mode as well: the reference's fast mode has documented
differences from the model (bytes outside the body on the body's own pages),
which step mode does not have. When the step trial of the same seed ends at a
real terminal, not at the step budget, and matches, the fast difference is the
reference's and the trial counts as matched in step mode. Otherwise the
mismatch stands.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import build_batch
import toolchain
from image import ROOT, flat_image_path
from meta import seed_for

FAST, STEP = 0, 1
S_OK, S_TIMEOUT, S_FOREIGN, S_BUDGET, S_UNSUPPORTED, S_HARNESS = range(6)
T_LEAVE, T_FAULT, T_EXC, T_STEP = 1, 2, 3, 4
TERMINAL_NAMES = {T_LEAVE: "leave", T_FAULT: "fault", T_EXC: "exc", T_STEP: "step"}
EXCLUSIONS = {
    ("ref", S_TIMEOUT): "ref_timeout",
    ("ref", S_HARNESS): "ref_harness",
    ("lift", S_FOREIGN): "lift_foreign",
    ("lift", S_BUDGET): "lift_budget",
    ("lift", S_UNSUPPORTED): "lift_unsupported",
    ("lift", S_HARNESS): "lift_harness",
}
MIN_COMPARABLE = 8
RESULT_NAME = "result.json"

REF_DIR = ROOT / "generated" / "lifted" / "ref"
REF_DBG = REF_DIR / "ref_dbg.exe"

# Sources whose content decides a batch result. A finished batch is reused only
# while all of them, the image and the contract tables are unchanged.
TOOL_SOURCES = (
    "port/lifted_runtime/lift_model.h",
    "port/lifted_runtime/lift_rt.h",
    "port/lifted_runtime/lift_rt.c",
    "port/lifted_runtime/lift_main.c",
    "tests/lift_ref/ref_dbg.c",
    "tests/lift_ref/ref_child.c",
    "scripts/lift/image.py",
    "scripts/lift/meta.py",
    "scripts/lift/lifter.py",
    "scripts/lift/build_batch.py",
    "scripts/lift/build_ref.py",
    "scripts/lift/toolchain.py",
    "scripts/lift/batch_verify.py",
    "scripts/lift/ops/*.py",
)
TOOL_INPUTS = (
    "work/binary_contracts/function_contracts_part1.tsv",
    "work/binary_contracts/function_contracts_part2.tsv",
)
# The columns of the contract tables this tier reads (image.load_functions). The
# other columns change with every handwritten layer and decide nothing here.
TOOL_INPUT_COLUMNS = ("address", "body_ranges", "sha256", "callee_pop_bytes", "return_type")


@dataclass(frozen=True)
class Params:
    seeds: int = 16             # fast trials per function, seed_for(address, 0..seeds-1)
    step_budget: int = 4000     # step-mode retry of a function with too few comparable fast trials
    confirm_budget: int = 100000  # step-mode re-run of a fast trial that did not match
    timeout_ms: int = 50        # reference wall-clock limit per fast trial


def _file_digest(path: Path) -> str:
    # Line endings are normalised so a CRLF working copy hashes like an LF one.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _table_digest(path: Path) -> str:
    """sha256 over TOOL_INPUT_COLUMNS of a contract table, one tab-joined line per row."""
    h = hashlib.sha256()
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            h.update(("\t".join(row[c] for c in TOOL_INPUT_COLUMNS) + "\n").encode())
    return h.hexdigest()


def source_hashes() -> dict[str, str]:
    """sha256 of every tool source and, over the columns read, of every input table, by repository path."""
    out = {}
    for pattern in TOOL_SOURCES:
        for path in sorted(ROOT.glob(pattern)):
            out[path.relative_to(ROOT).as_posix()] = _file_digest(path)
    for name in TOOL_INPUTS:
        out[name] = _table_digest(ROOT / name)
    return out


def tool_hash(image_sha256: str) -> str:
    h = hashlib.sha256()
    for name, digest in sorted(source_hashes().items()):
        h.update(f"{name} {digest}\n".encode())
    h.update(f"image {image_sha256}\n".encode())
    return h.hexdigest()


def batch_key(tools: str, entries: list[int], params: Params) -> str:
    h = hashlib.sha256()
    h.update(tools.encode())
    h.update(json.dumps(asdict(params), sort_keys=True).encode())
    h.update(",".join(f"{e:x}" for e in entries).encode())
    return h.hexdigest()


# ---- result lines -------------------------------------------------------------


@dataclass(frozen=True)
class Line:
    status: int
    tkind: int
    a: int
    b: int
    digest: str
    steps: int
    text: str

    @property
    def record(self) -> tuple:
        return self.tkind, self.a, self.b, self.digest, self.steps


def read_results(path: Path) -> dict[tuple[int, int, int], Line]:
    """Result file -> {(entry, seed, mode): Line}."""
    out = {}
    for text in path.read_text(encoding="ascii").splitlines():
        entry, seed, mode, status, tkind, a, b, digest, steps = text.split()
        out[(int(entry, 16), int(seed, 16), int(mode))] = Line(
            int(status), int(tkind), int(a, 16), int(b, 16), digest, int(steps), text)
    return out


def compare(ref: Line | None, lift: Line | None) -> str:
    """'match', 'mismatch', or the exclusion reason of one trial."""
    if ref is None:
        return "ref_missing"
    if ref.status != S_OK:
        return EXCLUSIONS.get(("ref", ref.status), "ref_status")
    if lift is None:
        return "lift_missing"
    if lift.status != S_OK:
        return EXCLUSIONS.get(("lift", lift.status), "lift_status")
    return "match" if ref.record == lift.record else "mismatch"


def read_coverage(path: Path) -> dict[tuple[int, int, int], int]:
    """Coverage file -> {(entry, seed, mode): bitmap as an integer, bit k = k-th instruction}."""
    out = {}
    if not path.exists():
        return out
    for text in path.read_text(encoding="ascii").splitlines():
        p = text.split()
        if p[0] == "T":
            bitmap = int.from_bytes(bytes.fromhex(p[6]), "little") if len(p) > 6 else 0
            out[(int(p[1], 16), int(p[2], 16), int(p[3]))] = bitmap
    return out


# ---- job files ------------------------------------------------------------------


def split_jobs(text: str) -> dict[int, list[str]]:
    """Job file -> {entry: its description lines, without trials and the closing E}."""
    out: dict[int, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("F "):
            cur = out.setdefault(int(line.split()[1], 16), [line])
        elif line and line[0] not in "TE" and cur is not None:
            cur.append(line)
    return out


def job_text(heads: dict[int, list[str]], trials: dict[int, list[tuple[int, int, int]]]) -> str:
    out = []
    for entry in sorted(trials):
        if trials[entry]:
            out += heads[entry]
            out += [f"T {seed:x} {mode} {budget}" for seed, mode, budget in trials[entry]]
            out.append("E")
    return "".join(line + "\n" for line in out)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="ascii", newline="\n")


class ToolError(RuntimeError):
    pass


def _run(cmd: list, what: str) -> tuple[str, float]:
    t0 = time.perf_counter()
    proc = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if proc.returncode != 0:
        raise ToolError(f"{what} exited with {proc.returncode}: {proc.stderr.strip()[-600:]}")
    return proc.stderr, time.perf_counter() - t0


def run_pair(out_dir: Path, tag: str, runner: Path, heads: dict[int, list[str]],
             trials: dict[int, list[tuple[int, int, int]]], timeout_ms: int, timings: dict[str, float]):
    """Runs the reference, then the runner on the trials the reference finished.

    Returns (reference lines, lifted lines, coverage), each keyed by (entry, seed, mode).
    """
    image = flat_image_path()
    jobs, env = out_dir / f"jobs_{tag}.txt", out_dir / "env.txt"
    ref_out, lift_out, cov = out_dir / f"ref_{tag}.out", out_dir / f"lift_{tag}.out", out_dir / f"lift_{tag}.cov"
    _write(jobs, job_text(heads, trials))
    _, timings[f"ref_{tag}"] = _run([REF_DBG, "--image", image, "--jobs", jobs, "--out", ref_out, "--env", env,
                                    "--timeout-ms", timeout_ms], "ref_dbg")
    ref = read_results(ref_out)
    todo = {entry: [t for t in ts if (line := ref.get((entry, t[0], t[1]))) is not None and line.status == S_OK]
            for entry, ts in trials.items()}
    lift_jobs = out_dir / f"jobs_{tag}_lift.txt"
    _write(lift_jobs, job_text(heads, todo))
    _, timings[f"lift_{tag}"] = _run([runner, "--image", image, "--jobs", lift_jobs, "--env", env, "--out", lift_out,
                                     "--cov", cov], "runner")
    return ref, read_results(lift_out), read_coverage(cov)


# ---- classification ---------------------------------------------------------------


def describe(line: Line | None) -> str:
    if line is None:
        return "none"
    if line.status != S_OK:
        return f"status{line.status}"
    return f"{TERMINAL_NAMES.get(line.tkind, line.tkind)}({line.a:x},{line.b:x})"


def classify(entry: int, info: build_batch.FunctionInfo, seeds: list[int], fast: dict[int, str], step: dict[int, str],
             step_ended_at_budget: set[int]) -> dict:
    """Status of one function from its per-seed comparison outcomes.

    fast and step map a seed to 'match', 'mismatch' or an exclusion reason;
    step holds only the seeds that were run in step mode.
    """
    # A fast difference is the reference's when the same seed, stepped to a real terminal, matches.
    resolved = {s for s in seeds if fast.get(s) == "mismatch" and step.get(s) == "match" and s not in step_ended_at_budget}
    fast_mismatch = [s for s in seeds if fast.get(s) == "mismatch" and s not in resolved]
    step_mismatch = [s for s in seeds if step.get(s) == "mismatch"]
    fast_matched = sum(1 for s in seeds if fast.get(s) == "match")
    step_matched = sum(1 for s in seeds if step.get(s) == "match")
    step_comparable = step_matched + len(step_mismatch)
    excluded = collections.Counter(v for v in fast.values() if v not in ("match", "mismatch"))
    excluded_step = collections.Counter(v for v in step.values() if v not in ("match", "mismatch"))

    notes = []
    if info.unsupported:
        status = "unsupported"
        names = sorted({mnemonic for _, mnemonic, _, _ in info.unsupported})
        notes.append("untranslated: " + ",".join(names))
    elif fast_mismatch or step_mismatch:
        status = "mismatch"
    elif fast_matched + len(resolved) >= MIN_COMPARABLE:
        status = "verified"
    elif step_matched >= MIN_COMPARABLE:
        status = "verified"
    else:
        status = "uncomparable"

    # The mode whose trials carry the claim: fast unless too few fast trials were comparable.
    if fast_matched + len(resolved) + len(fast_mismatch) >= MIN_COMPARABLE or not step:
        mode = "fast"
        trials = fast_matched + len(resolved) + len(fast_mismatch)
        matched = fast_matched + len(resolved)
    else:
        mode = "step"
        trials, matched = step_comparable, step_matched
    if resolved:
        notes.append(f"{len(resolved)} fast trials differ only in the reference's fast mode (equal in step mode)")
    if status in ("mismatch", "unsupported") and (fast_mismatch or step_mismatch):
        notes.append(f"mismatching trials: fast {len(fast_mismatch)}, step {len(step_mismatch)}")
    if status == "uncomparable":
        why = excluded_step if step else excluded
        notes.append("excluded: " + ",".join(f"{k}={n}" for k, n in sorted(why.items())))
    return {
        "address": f"{entry:08x}",
        "lift_sha256": info.lift_sha256,
        "status": status,
        "mode": mode,
        "trials": trials,
        "matched": matched,
        "insn_total": info.n_insn,
        "insn_covered": 0,
        "note": "; ".join(notes),
        "excluded_fast": dict(sorted(excluded.items())),
        "excluded_step": dict(sorted(excluded_step.items())),
        "resolved_in_step": len(resolved),
        "unsupported": [[f"{addr:08x}", mnemonic, reason] for addr, mnemonic, _, reason in info.unsupported],
        "mismatches": [],
        "_resolved": resolved,
    }


def verify_batch(name: str, entries: list[int], out_dir: Path, params: Params, key: str, tools: str,
                 keep: bool = False) -> dict:
    """Runs the whole pipeline for one batch and writes out_dir/result.json. Returns the result."""
    out_dir = Path(out_dir)
    t_start = time.perf_counter()
    result = {"name": name, "key": key, "tool_hash": tools, "params": asdict(params), "n_functions": len(entries),
              "error": "", "functions": []}
    timings: dict[str, float] = {}
    try:
        seeds = {e: [seed_for(e, i) for i in range(params.seeds)] for e in entries}
        fast_trials = {e: [(s, FAST, 0) for s in seeds[e]] for e in entries}
        batch = build_batch.build_batch(entries, out_dir, fast_trials, jobs=1)
        timings.update(batch.timings)
        heads = split_jobs(batch.job_file.read_text(encoding="ascii"))

        ref, lift, cov = run_pair(out_dir, "fast", batch.runner, heads, fast_trials, params.timeout_ms, timings)
        fast = {e: {s: compare(ref.get((e, s, FAST)), lift.get((e, s, FAST))) for s in seeds[e]} for e in entries}

        step_trials: dict[int, list[tuple[int, int, int]]] = {}
        for e in entries:
            outcome = fast[e]
            differing = [s for s in seeds[e] if outcome[s] == "mismatch"]
            comparable = sum(1 for v in outcome.values() if v in ("match", "mismatch"))
            retry = seeds[e] if comparable < MIN_COMPARABLE else differing
            if retry:
                step_trials[e] = [(s, STEP, params.confirm_budget if s in differing else params.step_budget)
                                  for s in retry]
        ref_s: dict = {}
        lift_s: dict = {}
        cov_s: dict = {}
        if step_trials:
            ref_s, lift_s, cov_s = run_pair(out_dir, "step", batch.runner, heads, step_trials, params.timeout_ms,
                                            timings)

        for e in entries:
            stepped = [s for s, _, _ in step_trials.get(e, [])]
            step = {s: compare(ref_s.get((e, s, STEP)), lift_s.get((e, s, STEP))) for s in stepped}
            at_budget = {s for s in stepped if (line := ref_s.get((e, s, STEP))) is not None and line.status == S_OK
                         and line.tkind == T_STEP}
            row = classify(e, batch.functions[e], seeds[e], fast[e], step, at_budget)
            resolved = row.pop("_resolved")
            covered = 0
            for s in seeds[e]:
                if fast[e][s] == "match":
                    covered |= cov.get((e, s, FAST), 0)
                elif fast[e][s] == "mismatch" and s not in resolved:
                    row["mismatches"].append({"seed": f"{s:x}", "mode": FAST, "ref": ref[(e, s, FAST)].text,
                                              "lift": lift[(e, s, FAST)].text})
                if step.get(s) == "match":
                    covered |= cov_s.get((e, s, STEP), 0)
                elif step.get(s) == "mismatch":
                    row["mismatches"].append({"seed": f"{s:x}", "mode": STEP, "ref": ref_s[(e, s, STEP)].text,
                                              "lift": lift_s[(e, s, STEP)].text})
            row["insn_covered"] = covered.bit_count()
            if row["mismatches"] and row["status"] == "mismatch":
                first = row["mismatches"][0]
                k = (e, int(first["seed"], 16), first["mode"])
                r, l = (ref, lift) if first["mode"] == FAST else (ref_s, lift_s)
                row["note"] = "; ".join(filter(None, [
                    f"seed {first['seed']} {'fast' if first['mode'] == FAST else 'step'}: "
                    f"ref {describe(r[k])} lift {describe(l[k])}", row["note"]]))
            result["functions"].append(row)
        result["trials"] = {"ref_fast": len(ref), "lift_fast": len(lift), "ref_step": len(ref_s),
                            "lift_step": len(lift_s),
                            "ref_fast_timeouts": sum(1 for v in ref.values() if v.status == S_TIMEOUT)}
    except (toolchain.BuildError, ToolError, OSError, ValueError, KeyError) as error:
        result["error"] = f"{type(error).__name__}: {str(error)[:2000]}"
    timings["total"] = time.perf_counter() - t_start
    result["timings"] = {k: round(v, 3) for k, v in timings.items()}
    result["finished"] = time.time()
    if not keep:
        for pattern in ("batch*.c", "batch*.obj", "batch.h", "runner.exe", "runner.pdb"):
            for path in out_dir.glob(pattern):
                path.unlink(missing_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write(out_dir / RESULT_NAME, json.dumps(result, indent=1) + "\n")
    return result
