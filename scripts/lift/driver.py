"""Driver of the lifted tier: verifies functions in batches and writes the ledger.

    python scripts/lift/driver.py run --smallest 4000 --stride 3000
    python scripts/lift/driver.py run --all
    python scripts/lift/driver.py report
    python scripts/lift/driver.py mismatches
    python scripts/lift/driver.py ledger

run        selects functions, splits them into batches and verifies each batch
           in a worker pool (batch_verify.verify_batch). A batch directory is
           generated/lifted/batches/<key>/, where the key hashes the tool
           sources, the image, the trial parameters and the function list, so
           a finished batch is skipped until one of those changes. Functions
           left with too few comparable trials get a second round with more
           seeds.
report     counts, throughput, untranslated instructions and coverage over the
           batch results that belong to the current tools and parameters.
mismatches traces the first mismatching trial of every mismatching function on
           both sides and groups the functions by where the traces part.
ledger     merges the batch results into port/lifted/ledger_part{1,2}.tsv and
           port/lifted/manifest.json.
clean      removes batch directories written by other tool versions.

See docs/lifted_tier.md, "Driver and ledger".
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capstone  # noqa: E402

import batch_verify as bv  # noqa: E402
import build_batch  # noqa: E402
import build_ref  # noqa: E402
import toolchain  # noqa: E402
from image import CONTRACTS, GENERATED, IMAGE_BASE, ROOT, flat_image_path, function_index, load_functions, load_image  # noqa: E402

BATCHES = GENERATED / "batches"
LEDGER_DIR = ROOT / "port" / "lifted"
LEDGER_COLUMNS = ("address", "bytes_sha256", "lift_sha256", "status", "mode", "trials", "matched", "insn_total",
                  "insn_covered", "note")
STATUSES = ("verified", "mismatch", "unsupported", "uncomparable", "untested")
MODEL_HEADER = ROOT / "port" / "lifted_runtime" / "lift_model.h"
RETRY_SEEDS = 64


# ---- selection ----------------------------------------------------------------


def add_selection(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("function selection (the union of everything given)")
    g.add_argument("--all", action="store_true", help="every function of the inventory")
    g.add_argument("--index", nargs=2, type=int, metavar=("START", "COUNT"),
                   help="COUNT functions from index START of the address-ordered inventory")
    g.add_argument("--addr", nargs=2, metavar=("LO", "HI"), help="functions with LO <= address < HI (hex)")
    g.add_argument("--list", type=Path, metavar="FILE", help="file with one hex entry address per line")
    g.add_argument("--entries", nargs="+", metavar="HEX", help="entry addresses")
    g.add_argument("--smallest", type=int, metavar="N", help="the N functions with the fewest body bytes")
    g.add_argument("--stride", type=int, metavar="N",
                   help="N functions at a fixed stride over the address-ordered inventory")


def select(args) -> list[int]:
    functions = load_functions()
    index = function_index()
    chosen: set[int] = set()
    if args.all:
        chosen.update(f.addr for f in functions)
    if args.index:
        start, count = args.index
        chosen.update(f.addr for f in functions[start:start + count])
    if args.addr:
        lo, hi = (int(v, 16) for v in args.addr)
        chosen.update(f.addr for f in functions if lo <= f.addr < hi)
    named = [int(e, 16) for e in args.entries or []]
    if args.list:
        for line in args.list.read_text(encoding="ascii").splitlines():
            line = line.split("#")[0].strip()
            if line:
                named.append(int(line.split()[0], 16))
    unknown = [e for e in named if e not in index]
    if unknown:
        raise SystemExit("not a function entry: " + " ".join(f"{e:x}" for e in unknown[:20]))
    chosen.update(named)
    if args.smallest:
        chosen.update(f.addr for f in sorted(functions, key=lambda f: (f.size, f.addr))[:args.smallest])
    if args.stride:
        n = min(args.stride, len(functions))
        chosen.update(functions[k * len(functions) // n].addr for k in range(n))
    return sorted(chosen)


# ---- parameters and batch results ------------------------------------------------


def add_params(ap: argparse.ArgumentParser) -> None:
    d = bv.Params()
    g = ap.add_argument_group("trial parameters (part of a batch's identity)")
    g.add_argument("--seeds", type=int, default=d.seeds, help=f"fast trials per function (default {d.seeds})")
    g.add_argument("--step-budget", type=int, default=d.step_budget,
                   help=f"step budget of the step-mode retry (default {d.step_budget})")
    g.add_argument("--confirm-budget", type=int, default=d.confirm_budget,
                   help=f"step budget when a differing fast trial is re-run (default {d.confirm_budget})")
    g.add_argument("--timeout-ms", type=int, default=d.timeout_ms,
                   help=f"reference wall-clock limit per fast trial (default {d.timeout_ms})")
    g.add_argument("--retry-seeds", type=int, default=RETRY_SEEDS,
                   help="fast trials per function in the second round, which functions with too few comparable "
                        f"trials get (default {RETRY_SEEDS}; 0 for no second round)")


def params_of(args) -> bv.Params:
    return bv.Params(seeds=args.seeds, step_budget=args.step_budget, confirm_budget=args.confirm_budget,
                     timeout_ms=args.timeout_ms)


def image_sha256() -> str:
    return hashlib.sha256(flat_image_path().read_bytes()).hexdigest()


def retry_params(params: bv.Params, retry_seeds: int) -> bv.Params | None:
    """Parameters of the second round, or None when there is none."""
    return replace(params, seeds=retry_seeds) if retry_seeds > params.seeds else None


def current_results(tools: str, params: bv.Params, retry_seeds: int) -> list[dict]:
    """Batch results written by the current tools with these parameters, in merge order."""
    wanted = [asdict(p) for p in (params, retry_params(params, retry_seeds)) if p is not None]
    out = []
    for path in BATCHES.glob(f"*/{bv.RESULT_NAME}"):
        try:
            result = json.loads(path.read_text(encoding="ascii"))
        except (OSError, ValueError):
            continue
        if result.get("tool_hash") == tools and result.get("params") in wanted and not result.get("error"):
            result["dir"] = str(path.parent)
            out.append(result)
    return merge_order(out)


def merge_order(results: list[dict]) -> list[dict]:
    """First round before second round, older before newer."""
    return sorted(results, key=lambda r: (r["params"]["seeds"], r.get("finished", 0.0)))


def rows_by_address(results: list[dict]) -> dict[int, dict]:
    """Function rows of batch results given in merge order, each with the seeds it was run with.

    A later result replaces an earlier one, except that a mismatch is never replaced.
    """
    rows: dict[int, dict] = {}
    for result in results:
        for row in result["functions"]:
            addr = int(row["address"], 16)
            if addr not in rows or rows[addr]["status"] != "mismatch":
                rows[addr] = {**row, "seeds": result["params"]["seeds"]}
    return rows


# ---- run -------------------------------------------------------------------------


def _worker(task):
    name, entries, out_dir, params, key, tools, keep = task
    return bv.verify_batch(name, entries, Path(out_dir), params, key, tools, keep=keep)


def prepare_tools() -> None:
    """Builds what every batch shares, so the workers find it ready."""
    build_ref.build()
    toolchain.build_runtime_objs(build_batch.RUNTIME_OBJ_DIR)
    flat_image_path()


def run_batches(entries: list[int], params: bv.Params, tools: str, args) -> tuple[list[dict], list[dict]]:
    """Verifies the entries in batches. Returns the results reused and the results newly made."""
    tasks, done = [], []
    for n in range(0, len(entries), args.batch_size):
        chunk = entries[n:n + args.batch_size]
        key = bv.batch_key(tools, chunk, params)
        out_dir = BATCHES / key[:16]
        previous = out_dir / bv.RESULT_NAME
        if previous.exists() and not args.force:
            try:
                result = json.loads(previous.read_text(encoding="ascii"))
            except ValueError:
                result = {}
            if result.get("key") == key and not result.get("error"):
                done.append(result)
                continue
        tasks.append((f"{chunk[0]:08x}+{len(chunk)}", chunk, str(out_dir), params, key, tools, args.keep))
    print(f"{len(entries)} functions in {len(tasks) + len(done)} batches; {len(done)} batches already finished, "
          f"{len(tasks)} to run with {args.workers} workers", flush=True)

    fresh = []
    if tasks:
        with concurrent.futures.ProcessPoolExecutor(max_workers=min(args.workers, len(tasks))) as pool:
            for k, future in enumerate(concurrent.futures.as_completed([pool.submit(_worker, t) for t in tasks]), 1):
                result = future.result()
                fresh.append(result)
                counts = collections.Counter(row["status"] for row in result["functions"])
                state = result["error"] or ", ".join(f"{s} {counts[s]}" for s in STATUSES if counts[s])
                print(f"[{k}/{len(tasks)}] {result['name']} {result['timings']['total']:.1f}s: {state}", flush=True)
    return done, fresh


def cmd_run(args) -> int:
    entries = select(args)
    if not entries:
        raise SystemExit("no functions selected")
    params = params_of(args)
    prepare_tools()
    tools = bv.tool_hash(image_sha256())
    BATCHES.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    done, fresh = run_batches(entries, params, tools, args)
    ran = sum(r["n_functions"] for r in fresh if not r["error"])
    # Second round: the same functions with more seeds, of which the first are the seeds already
    # run. What a verified function has to show stays the same.
    again = retry_params(params, args.retry_seeds)
    short = sorted(addr for addr, row in rows_by_address([r for r in done + fresh if not r["error"]]).items()
                   if row["status"] == "uncomparable")
    if again is not None and short:
        print(f"second round with {again.seeds} seeds for {len(short)} functions short of comparable trials",
              flush=True)
        done2, fresh2 = run_batches(short, again, tools, args)
        done, fresh = done + done2, fresh + fresh2
    wall = time.perf_counter() - t0

    summary = summarize(merge_order([r for r in done + fresh if not r["error"]]))
    summary["run"] = {"functions_selected": len(entries), "batches_run": len(fresh), "batches_reused": len(done),
                      "functions_run": ran, "wall_seconds": round(wall, 2), "workers": args.workers,
                      "batch_size": args.batch_size, "second_round_functions": len(short) if again else 0}
    if ran and wall > 0:
        per_minute = ran / wall * 60.0
        summary["run"]["functions_per_minute"] = round(per_minute, 1)
        summary["run"]["projected_minutes_all"] = round(len(load_functions()) / per_minute, 1)
    (BATCHES / "last_run.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="ascii", newline="\n")
    print_summary(summary)
    failed = [r for r in fresh if r["error"]]
    for r in failed[:10]:
        print(f"batch {r['name']} failed: {r['error'][:600]}", file=sys.stderr)
    return 1 if failed else 0


def summarize(results: list[dict]) -> dict:
    """Totals over error-free batch results given in merge order."""
    rows = rows_by_address(results)
    status = collections.Counter(row["status"] for row in rows.values())
    time_by = collections.Counter()
    trials_by = collections.Counter()
    for r in results:
        for k, v in r.get("timings", {}).items():
            time_by[k] += v
        for k, v in r.get("trials", {}).items():
            trials_by[k] += v
    blocked = collections.Counter()
    for row in rows.values():
        for mnemonic in {u[1] for u in row["unsupported"]}:
            blocked[mnemonic] += 1
    coverage = collections.Counter()
    for row in rows.values():
        if row["status"] == "verified":
            coverage[coverage_bucket(row["insn_covered"], row["insn_total"])] += 1
    excluded = collections.Counter()
    resolved = 0
    for row in rows.values():
        for k, v in row["excluded_fast"].items():
            excluded[k] += v
        resolved += row["resolved_in_step"]

    def rate(trials: str, seconds: str) -> float:
        return round(trials_by[trials] / time_by[seconds], 1) if time_by[seconds] > 0 else 0.0

    return {
        "functions": len(rows),
        "status": {s: status[s] for s in STATUSES if status[s]},
        "mode": dict(collections.Counter(row["mode"] for row in rows.values() if row["status"] == "verified")),
        "verified_by_seeds": dict(sorted(collections.Counter(
            str(row["seeds"]) for row in rows.values() if row["status"] == "verified").items())),
        "trials": dict(trials_by),
        "seconds": {k: round(v, 1) for k, v in sorted(time_by.items())},
        "trials_per_second": {"ref_fast": rate("ref_fast", "ref_fast"), "lift_fast": rate("lift_fast", "lift_fast"),
                              "ref_step": rate("ref_step", "ref_step"), "lift_step": rate("lift_step", "lift_step")},
        "excluded_fast_trials": dict(sorted(excluded.items())),
        "fast_trials_resolved_in_step": resolved,
        "unsupported_mnemonics_by_functions": dict(blocked.most_common()),
        "coverage_of_verified": {b: coverage[b] for b in COVERAGE_BUCKETS if coverage[b]},
    }


COVERAGE_BUCKETS = tuple(f"{lo}-{lo + 9}%" for lo in range(0, 100, 10)) + ("100%",)


def coverage_bucket(covered: int, total: int) -> str:
    if total == 0 or covered >= total:
        return "100%"
    return COVERAGE_BUCKETS[covered * 10 // total]


def print_summary(summary: dict) -> None:
    print(f"functions: {summary['functions']}  " + "  ".join(f"{k} {v}" for k, v in summary["status"].items()))
    print("verified by mode: " + (", ".join(f"{k} {v}" for k, v in sorted(summary["mode"].items())) or "none")
          + "; by seeds per function: "
          + (", ".join(f"{k}: {v}" for k, v in summary["verified_by_seeds"].items()) or "none"))
    print("trials: " + ", ".join(f"{k} {v}" for k, v in sorted(summary["trials"].items())))
    print("trials per second: " + ", ".join(f"{k} {v}" for k, v in summary["trials_per_second"].items()))
    print("seconds by stage (summed over batches): " + ", ".join(f"{k} {v}" for k, v in summary["seconds"].items()))
    print("excluded fast trials: " + (", ".join(f"{k} {v}" for k, v in summary["excluded_fast_trials"].items()) or "none"))
    print(f"fast trials resolved in step mode: {summary['fast_trials_resolved_in_step']}")
    print("untranslated mnemonics (functions blocked): "
          + (", ".join(f"{k} {v}" for k, v in summary["unsupported_mnemonics_by_functions"].items()) or "none"))
    print("coverage of verified functions: " + ", ".join(f"{k} {v}" for k, v in summary["coverage_of_verified"].items()))
    run = summary.get("run")
    if run:
        print(f"run: {run['functions_run']} functions in {run['batches_run']} batches, {run['wall_seconds']} s wall, "
              f"{run['workers']} workers; {run['batches_reused']} batches reused; "
              f"{run['second_round_functions']} functions in the second round")
        if "functions_per_minute" in run:
            print(f"throughput: {run['functions_per_minute']} functions/minute; all {len(load_functions())} "
                  f"functions: about {run['projected_minutes_all']} minutes")


def cmd_report(args) -> int:
    params = params_of(args)
    results = current_results(bv.tool_hash(image_sha256()), params, args.retry_seeds)
    if not results:
        print("no batch results for the current tools and parameters")
        return 1
    summary = summarize(results)
    print_summary(summary)
    rows = rows_by_address(results)
    for status in ("mismatch", "uncomparable", "unsupported"):
        listed = [row for _, row in sorted(rows.items()) if row["status"] == status]
        if listed and (args.verbose or status == "mismatch"):
            print(f"{status} ({len(listed)}):")
            for row in listed[:args.limit]:
                print(f"  {row['address']} {row['mode']} {row['matched']}/{row['trials']} {row['note']}")
    return 0


# ---- mismatches --------------------------------------------------------------------


def trace_sections(text: str) -> dict[int, list[str]]:
    """Trace output -> {mode: lines of that trial}. Page lines are left out:
    when a page materialises is a detail of each side, not part of the trial."""
    out: dict[int, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("trial "):
            cur = out.setdefault(int(line.split()[3]), [])
        if cur is not None and not line.startswith("page "):
            cur.append(line)
    return out


def first_difference(ref: list[str], lift: list[str]) -> int | None:
    for i, (a, b) in enumerate(zip(ref, lift)):
        if a != b:
            return i
    return None if len(ref) == len(lift) else min(len(ref), len(lift))


def differing_field(a: str, b: str) -> str:
    """Name of the first field in which two trace lines of the same kind differ."""
    ta, tb = a.split(), b.split()
    if not ta or not tb:
        return "missing line"
    if ta[0] != tb[0]:
        return f"{ta[0]} vs {tb[0]}"
    kind = ta[0]
    if kind == "mem":
        return "mem"
    if re.fullmatch(r"(st|xmm)\d", kind):
        return kind
    for k, (x, y) in enumerate(zip(ta[1:], tb[1:]), 1):
        if x != y:
            if "=" in x:
                name = x.split("=", 1)[0]
            else:
                name = {("step", 1): "count", ("step", 2): "eip"}.get((kind, k), f"field{k}")
            return f"{kind}.{name}"
    return f"{kind}.length"


def _decoder() -> capstone.Cs:
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def instruction_at(md: capstone.Cs, addr: int) -> tuple[str, str]:
    image = load_image()
    off = addr - IMAGE_BASE
    if 0 <= off < len(image):
        for ins in md.disasm(image[off:off + 16], addr, 1):
            return ins.mnemonic, f"{ins.mnemonic} {ins.op_str}".strip()
    return "?", "?"


def locate(md: capstone.Cs, ref: list[str], lift: list[str]) -> tuple[str, str, str] | None:
    """(mnemonic, field, detail) of the first difference between two traces of a trial, or None."""
    i = first_difference(ref, lift)
    if i is None:
        return None
    a = ref[i] if i < len(ref) else ""
    b = lift[i] if i < len(lift) else ""
    field = differing_field(a, b)
    # The instruction that ran last: the step line before the difference. A fast
    # trace has no step lines; a fault or exception terminal names its instruction.
    addr = None
    for line in reversed(ref[:i]):
        if line.startswith("step "):
            addr = int(line.split()[2], 16)
            break
    if addr is None:
        for line in (a, b):
            m = re.match(r"term kind=([23]) a=([0-9a-f]+)", line)
            if m:
                addr = int(m.group(2), 16)
                break
    mnemonic, text = instruction_at(md, addr) if addr is not None else ("?", "?")
    where = f"{addr:08x} {text}" if addr is not None else "unknown instruction"
    return mnemonic, field, f"{where}\n      ref  {a[:230]}\n      lift {b[:230]}"


def _trace_one(task):
    entry, seed, runner, jobs, work = task
    image = flat_image_path()
    tag = f"{entry:08x}_{seed:x}"
    env = work / f"{tag}.env"
    ref = subprocess.run([str(bv.REF_DBG), "--image", str(image), "--jobs", str(jobs), "--out", str(work / f"{tag}.ref.out"),
                          "--env", str(env), "--trace", f"{entry:x}", f"{seed:x}"],
                         capture_output=True, text=True)
    lift = subprocess.run([str(runner), "--image", str(image), "--jobs", str(jobs), "--env", str(env),
                           "--out", str(work / f"{tag}.lift.out"), "--trace", f"{entry:x}", f"{seed:x}"],
                          capture_output=True, text=True)
    (work / f"{tag}.ref.trace").write_text(ref.stdout, encoding="ascii", newline="\n")
    (work / f"{tag}.lift.trace").write_text(lift.stdout, encoding="ascii", newline="\n")
    return entry, seed, ref.stdout, lift.stdout


def cmd_mismatches(args) -> int:
    params = params_of(args)
    prepare_tools()
    results = current_results(bv.tool_hash(image_sha256()), params, args.retry_seeds)
    rows = rows_by_address(results)
    wanted = {int(e, 16) for e in args.entries} if args.entries else None
    targets = []
    for addr, row in sorted(rows.items()):
        if row["mismatches"] and (wanted is None or addr in wanted):
            first = row["mismatches"][0]
            targets.append((addr, int(first["seed"], 16), first["mode"]))
    if not targets:
        print("no mismatching functions in the current batch results")
        return 0
    targets = targets[:args.limit]
    work = BATCHES / "_trace"
    shutil.rmtree(work, ignore_errors=True)
    # Both modes are traced: a step trace attributes the difference to an
    # instruction, and a difference that only exists in fast mode shows as such.
    trials = {addr: ([(seed, bv.FAST, 0)] if mode == bv.FAST else []) + [(seed, bv.STEP, args.trace_budget)]
              for addr, seed, mode in targets}
    batch = build_batch.build_batch(list(trials), work, trials)

    md = _decoder()
    clusters: dict[tuple[str, str], list] = collections.defaultdict(list)
    tasks = [(addr, seed, batch.runner, batch.job_file, work) for addr, seed, _ in targets]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for entry, seed, ref_text, lift_text in pool.map(_trace_one, tasks):
            ref, lift = trace_sections(ref_text), trace_sections(lift_text)
            found = None
            if bv.STEP in ref and bv.STEP in lift:
                found = locate(md, ref[bv.STEP], lift[bv.STEP])
            if found is None and bv.FAST in ref and bv.FAST in lift:
                found = locate(md, ref[bv.FAST], lift[bv.FAST])
                if found is not None:
                    found = (found[0], found[1] + " (fast mode only)", found[2])
            if found is None:
                found = ("?", "no difference when traced", "the traced trials agree; the batch result does not")
            clusters[(found[0], found[1])].append((entry, seed, found[2]))

    print(f"{len(targets)} mismatching functions in {len(clusters)} clusters (traces in {work})")
    for (mnemonic, field), members in sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"\n{len(members)} functions: last instruction '{mnemonic}', first difference in {field}")
        for entry, seed, detail in members[:args.examples]:
            print(f"    {entry:08x} seed {seed:x}: {detail}")
    return 0


# ---- ledger ------------------------------------------------------------------------


def part_boundary() -> int:
    """First address of the second contract table; the ledger is split at the same place."""
    with open(CONTRACTS / "function_contracts_part2.tsv", newline="", encoding="utf-8") as fh:
        return min(int(r["address"], 16) for r in csv.DictReader(fh, delimiter="\t"))


def model_version() -> int:
    m = re.search(r"#define\s+LM_MODEL_VERSION\s+(\d+)u", MODEL_HEADER.read_text(encoding="ascii"))
    if m is None:
        raise SystemExit("LM_MODEL_VERSION not found in lift_model.h")
    return int(m.group(1))


def cpu_brand() -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            return " ".join(str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).split())
    except (ImportError, OSError):
        return platform.processor()


def msvc_version() -> str:
    try:
        banner = toolchain.run_tool(["cl"], cwd=GENERATED)
    except toolchain.BuildError as error:
        banner = str(error)
    m = re.search(r"Version (\d+(?:\.\d+)+)", banner)
    return m.group(1) if m else "unknown"


def cmd_ledger(args) -> int:
    params = params_of(args)
    image_hash = image_sha256()
    tools = bv.tool_hash(image_hash)
    rows = rows_by_address(current_results(tools, params, args.retry_seeds))
    functions = load_functions()
    boundary = part_boundary()
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)

    parts: dict[str, list[str]] = {"ledger_part1.tsv": [], "ledger_part2.tsv": []}
    status = collections.Counter()
    modes = collections.Counter()
    seeds = collections.Counter()
    coverage = collections.Counter()
    trials = matched = insn_total = insn_covered = full = 0
    for fn in functions:
        row = rows.get(fn.addr)
        if row is None:
            fields = [f"{fn.addr:08x}", fn.sha256, "", "untested", "", "0", "0", "0", "0", ""]
            status["untested"] += 1
        else:
            note = " ".join(row["note"].split())
            if row["seeds"] != params.seeds:
                note = "; ".join(filter(None, [f"{row['seeds']} seeds", note]))
            seeds[str(row["seeds"])] += 1
            fields = [row["address"], fn.sha256, row["lift_sha256"], row["status"], row["mode"], str(row["trials"]),
                      str(row["matched"]), str(row["insn_total"]), str(row["insn_covered"]), note]
            status[row["status"]] += 1
            if row["status"] == "verified":
                modes[row["mode"]] += 1
                coverage[coverage_bucket(row["insn_covered"], row["insn_total"])] += 1
                trials += row["trials"]
                matched += row["matched"]
                insn_covered += row["insn_covered"]
                full += row["insn_covered"] == row["insn_total"]
            insn_total += row["insn_total"]
        # An empty field is written as "-" so no line ends in a tab.
        parts["ledger_part1.tsv" if fn.addr < boundary else "ledger_part2.tsv"].append(
            "\t".join(f or "-" for f in fields))

    manifest_parts = {}
    for name, lines in parts.items():
        text = "\t".join(LEDGER_COLUMNS) + "\n" + "".join(line + "\n" for line in lines)
        (LEDGER_DIR / name).write_text(text, encoding="ascii", newline="\n")
        manifest_parts[name] = {"rows": len(lines), "sha256": hashlib.sha256(text.encode("ascii")).hexdigest()}
    manifest = {
        "model_version": model_version(),
        "functions": len(functions),
        "status_counts": {s: status[s] for s in STATUSES},
        "verified_by_mode": {m: modes[m] for m in ("fast", "step")},
        "verified_trials": {"comparable": trials, "matched": matched},
        "coverage_histogram_of_verified": {b: coverage[b] for b in COVERAGE_BUCKETS},
        "instructions": {"total": insn_total, "covered_in_verified": insn_covered,
                         "verified_functions_fully_covered": full},
        "trial_parameters": {"seeds_per_function": params.seeds, "second_round_seeds": args.retry_seeds,
                             "functions_by_seeds": dict(sorted(seeds.items())),
                             "min_comparable_trials": bv.MIN_COMPARABLE,
                             "step_budget": params.step_budget, "confirm_budget": params.confirm_budget,
                             "reference_timeout_ms": params.timeout_ms},
        "reference_cpu": cpu_brand(),
        "tools": {"python": platform.python_version(), "capstone": capstone.__version__, "msvc": msvc_version()},
        "tool_hash": tools,
        "image_sha256": image_hash,
        "tool_sources": bv.source_hashes(),
        "ledger": manifest_parts,
    }
    (LEDGER_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="ascii", newline="\n")
    print(f"{LEDGER_DIR}: " + ", ".join(f"{s} {status[s]}" for s in STATUSES))
    return 0


def cmd_clean(args) -> int:
    tools = bv.tool_hash(image_sha256())
    removed = 0
    for path in BATCHES.glob(f"*/{bv.RESULT_NAME}"):
        try:
            stale = json.loads(path.read_text(encoding="ascii")).get("tool_hash") != tools
        except (OSError, ValueError):
            stale = True
        if stale:
            shutil.rmtree(path.parent, ignore_errors=True)
            removed += 1
    print(f"removed {removed} batch directories of other tool versions")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="verify the selected functions")
    add_selection(run)
    add_params(run)
    run.add_argument("--batch-size", type=int, default=400, help="functions per batch (default 400)")
    run.add_argument("--workers", type=int, default=24, help="batches verified in parallel (default 24)")
    run.add_argument("--force", action="store_true", help="run batches again even when they are finished")
    run.add_argument("--keep", action="store_true", help="keep generated C, objects and runner of every batch")
    run.set_defaults(fn=cmd_run)

    report = sub.add_parser("report", help="summarise the current batch results")
    add_params(report)
    report.add_argument("--verbose", action="store_true", help="list uncomparable and unsupported functions too")
    report.add_argument("--limit", type=int, default=200, help="rows listed per status (default 200)")
    report.set_defaults(fn=cmd_report)

    mism = sub.add_parser("mismatches", help="trace mismatching functions and cluster them")
    add_params(mism)
    mism.add_argument("--entries", nargs="+", metavar="HEX", help="only these functions")
    mism.add_argument("--limit", type=int, default=400, help="functions traced at most (default 400)")
    mism.add_argument("--examples", type=int, default=3, help="examples printed per cluster (default 3)")
    mism.add_argument("--trace-budget", type=int, default=20000, help="step budget of the traced trial (default 20000)")
    mism.add_argument("--workers", type=int, default=12, help="traces run in parallel (default 12)")
    mism.set_defaults(fn=cmd_mismatches)

    ledger = sub.add_parser("ledger", help="write port/lifted/ledger_part*.tsv and manifest.json")
    add_params(ledger)
    ledger.set_defaults(fn=cmd_ledger)

    clean = sub.add_parser("clean", help="remove batch directories of other tool versions")
    clean.set_defaults(fn=cmd_clean)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
