"""Builds the lifted runner for one batch of functions.

    python scripts/lift/build_batch.py --out generated/lifted/batches/b000 --slice 0 2000 --seeds 8
    python scripts/lift/build_batch.py --out generated/lifted/batches/one --entries 10001000 100010a0

Writes into the output directory (which must be under generated/lifted/):

    batch.h          thunk declarations shared by the generated sources
    batch.c          thunk bytes, function table, thunk table
    batch_fNNN.c     lifted functions, split so the parts compile in parallel
    jobs.txt         job file for both the reference and the runner
    functions.tsv    entry, instruction count, sha256 of the generated C, unsupported count
    unsupported.tsv  every instruction that was not translated
    runner.exe       batch + port/lifted_runtime, x64

As a module: build_batch(entries, out_dir, trials) and lift_many(entries).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from multiprocessing import Pool
from pathlib import Path

import toolchain
from image import GENERATED, function_index, load_functions
from lifter import function_name, lift_function
from meta import build_meta, job_lines, seed_for

PART_INSNS = 30000    # instructions per generated source file
POOL_THRESHOLD = 400  # functions below which lifting stays in this process
RUNTIME_OBJ_DIR = GENERATED / "runtime"


@dataclass
class FunctionInfo:
    entry: int
    n_insn: int
    lift_sha256: str
    unsupported: list[tuple[int, str, str, str]]  # (addr, mnemonic, hex bytes, reason)


@dataclass
class Batch:
    out_dir: Path
    runner: Path | None
    job_file: Path
    unsupported_report: Path
    functions: dict[int, FunctionInfo] = field(default_factory=dict)
    n_thunks: int = 0
    timings: dict[str, float] = field(default_factory=dict)  # seconds: lift, write, compile, link


def default_meta(entry: int):
    return build_meta(function_index()[entry])


def _lift_one(task):
    entry, trials, keep_code = task
    meta = default_meta(entry)
    lifted = lift_function(meta)
    lines = job_lines(meta, trials) if trials is not None else None
    if not keep_code:
        lifted.code = ""
        lifted.addrs = []
    return lifted, lines


def lift_many(entries, trials=None, jobs: int | None = None, keep_code: bool = True, meta_for=None):
    """Yields (Lifted, job lines or None) per entry, in order.

    trials maps an entry to its [(seed, mode, budget)] list. Large inputs are
    spread over worker processes; meta_for (entry -> Meta) replaces the
    contract-table lookup and keeps the work in this process.
    """
    entries = list(entries)
    if jobs is None:
        jobs = min(os.cpu_count() or 1, 16) if len(entries) >= POOL_THRESHOLD else 1
    if meta_for is not None or jobs <= 1:
        for entry in entries:
            meta = (meta_for or default_meta)(entry)
            lifted = lift_function(meta)
            yield lifted, (job_lines(meta, trials.get(entry, [])) if trials is not None else None)
        return
    tasks = [(entry, trials.get(entry, []) if trials is not None else None, keep_code) for entry in entries]
    with Pool(jobs) as pool:
        yield from pool.imap(_lift_one, tasks, chunksize=max(1, min(64, len(tasks) // (jobs * 8))))


def _thunk_definition(name: str, code: bytes) -> str:
    return f"LIFT_THUNK({name}) = {{{','.join(f'0x{b:02x}' for b in code)}}};"


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="ascii", newline="\n")


def build_batch(entries, out_dir: Path, trials, *, jobs: int | None = None, build: bool = True, meta_for=None,
                part_insns: int = PART_INSNS) -> Batch:
    """Lifts the functions, writes the batch sources and job file, builds runner.exe.

    trials: {entry: [(seed, mode, budget), ...]}; mode 0 = fast, 1 = step.
    """
    out_dir = Path(out_dir).resolve()
    if GENERATED.resolve() not in out_dir.parents:
        raise ValueError(f"{out_dir} is not under {GENERATED}")
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in list(out_dir.glob("batch_f*.c")) + list(out_dir.glob("batch*.obj")):
        stale.unlink()
    batch = Batch(out_dir=out_dir, runner=None, job_file=out_dir / "jobs.txt",
                  unsupported_report=out_dir / "unsupported.tsv")
    entries = sorted(set(entries))
    trials = trials if trials is not None else {}

    t0 = time.perf_counter()
    thunks: dict[str, tuple[bytes, int]] = {}
    parts: list[list[str]] = [[]]
    part_load = 0
    jobs_text: list[str] = []
    for lifted, lines in lift_many(entries, trials, jobs, meta_for=meta_for):
        for name, (code, flags) in lifted.thunks.items():
            if thunks.setdefault(name, (code, flags)) != (code, flags):
                raise AssertionError(f"thunk name {name} stands for two different thunks")
        if part_load >= part_insns:
            parts.append([])
            part_load = 0
        parts[-1].append(lifted.code)
        part_load += lifted.n_insn
        jobs_text += lines
        batch.functions[lifted.entry] = FunctionInfo(
            entry=lifted.entry, n_insn=lifted.n_insn, lift_sha256=hashlib.sha256(lifted.code.encode("ascii")).hexdigest(),
            unsupported=lifted.unsupported)
    batch.n_thunks = len(thunks)
    batch.timings["lift"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    names = sorted(thunks)
    _write(out_dir / "batch.h", "\n".join(
        ["/* Generated by scripts/lift/build_batch.py. */", "#include \"lift_rt.h\""]
        + [f"LIFT_THUNK_DECL({name});" for name in names]) + "\n")
    sources = ["batch.c"]
    for n, part in enumerate(parts):
        name = f"batch_f{n:03d}.c"
        _write(out_dir / name, "#include \"batch.h\"\n\n" + "\n".join(part))
        sources.append(name)
    # A table cannot be empty in C; the counts say how many entries are real.
    table = ["#include \"batch.h\"", ""]
    table += [_thunk_definition(name, thunks[name][0]) for name in names]
    table += [""] + [f"void {function_name(e)}(lift_ctx *c);" for e in entries]
    table += ["", "const lift_fn_entry lift_batch_fns[] = {"]
    table += [f"    {{0x{e:08x}u, {function_name(e)}, {batch.functions[e].n_insn}u}}," for e in entries] or ["    {0u, 0, 0u},"]
    table += ["};", f"const uint32_t lift_batch_fn_count = {len(entries)}u;", "", "const lift_thunk_desc lift_batch_thunks[] = {"]
    table += [f"    {{{name}, {len(thunks[name][0])}u, 0x{thunks[name][1]:02x}u}}," for name in names] or ["    {0, 0u, 0u},"]
    table += ["};", f"const uint32_t lift_batch_thunk_count = {len(names)}u;"]
    _write(out_dir / "batch.c", "\n".join(table) + "\n")
    _write(batch.job_file, "".join(line + "\n" for line in jobs_text))
    _write(out_dir / "functions.tsv", "entry\tn_insn\tlift_sha256\tn_unsupported\n" + "".join(
        f"{f.entry:08x}\t{f.n_insn}\t{f.lift_sha256}\t{len(f.unsupported)}\n" for f in batch.functions.values()))
    _write(batch.unsupported_report, "entry\taddress\tmnemonic\tbytes\treason\n" + "".join(
        f"{f.entry:08x}\t{addr:08x}\t{mnemonic}\t{raw}\t{reason}\n"
        for f in batch.functions.values() for addr, mnemonic, raw, reason in f.unsupported))
    batch.timings["write"] = time.perf_counter() - t0

    if build:
        t0 = time.perf_counter()
        runtime = toolchain.build_runtime_objs(RUNTIME_OBJ_DIR)
        toolchain.run_tool(["cl", *toolchain.GENERATED_CFLAGS, "/MP", "/c", f"/I{toolchain.RUNTIME_DIR}", *sources],
                           cwd=out_dir)
        batch.timings["compile"] = time.perf_counter() - t0
        t0 = time.perf_counter()
        batch.runner = out_dir / "runner.exe"
        toolchain.link_exe(batch.runner, runtime + [out_dir / (Path(s).stem + ".obj") for s in sources],
                           stack=toolchain.RUNNER_STACK)
        batch.timings["link"] = time.perf_counter() - t0
    return batch


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, type=Path, help="output directory under generated/lifted/")
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument("--entries", nargs="+", metavar="HEX", help="function entry addresses")
    what.add_argument("--slice", nargs=2, type=int, metavar=("START", "COUNT"),
                      help="COUNT functions starting at index START of the address-ordered inventory")
    ap.add_argument("--seeds", type=int, default=8, help="trials per function (default 8)")
    ap.add_argument("--step-budget", type=int, default=0, help="run the trials in step mode with this budget")
    ap.add_argument("--jobs", type=int, default=None, help="lifter processes (default: by batch size)")
    ap.add_argument("--no-build", action="store_true", help="write the sources and job file only")
    args = ap.parse_args(argv)

    if args.entries:
        entries = [int(e, 16) for e in args.entries]
        unknown = [e for e in entries if e not in function_index()]
        if unknown:
            ap.error("not a function entry: " + " ".join(f"{e:x}" for e in unknown))
    else:
        start, count = args.slice
        entries = [f.addr for f in load_functions()[start:start + count]]
    mode, budget = (1, args.step_budget) if args.step_budget else (0, 0)
    trials = {e: [(seed_for(e, n), mode, budget) for n in range(args.seeds)] for e in entries}
    try:
        batch = build_batch(entries, args.out, trials, jobs=args.jobs, build=not args.no_build)
    except toolchain.BuildError as error:
        print(str(error)[:4000], file=sys.stderr)
        return 1
    n_insn = sum(f.n_insn for f in batch.functions.values())
    clean = sum(1 for f in batch.functions.values() if not f.unsupported)
    print(f"{len(batch.functions)} functions, {n_insn} instructions, {batch.n_thunks} thunks, "
          f"{clean} fully translated; " + ", ".join(f"{k} {v:.2f}s" for k, v in batch.timings.items()))
    if batch.runner:
        print(batch.runner)
    return 0


if __name__ == "__main__":
    sys.exit(main())
