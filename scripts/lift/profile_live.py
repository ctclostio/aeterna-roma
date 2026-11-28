"""Profiles a live run: which lifted functions, shims and modules the time goes to.

    python scripts/lift/profile_live.py [--root <checkout>] [--seconds N] [--top N] [-- arguments for live.exe]

Samples a live.exe of its own (scripts/lift/live_private.py) on a copy of <checkout>'s lifted.dll (default: this
checkout) with port/lifted_live/live_profile.c, so the working build can be rebuilt and run meanwhile. The
copy, the game's profile folder for this run and the results are in generated/lifted/live_profile/:

    samples.tsv         one line per look at a running thread (live_profile.c describes it)
    last_run.txt        what live.exe printed
    hot_functions.tsv   lifted functions by processor time: guest address, cycles, of those in helpers, cumulative share

Every share is of processor time (the cycles of the lines), so a thread that only waits counts for nothing.

    python scripts/lift/profile_live.py --report    sum up the samples.tsv that is there, without running
"""
from __future__ import annotations

import argparse
import collections
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_private  # noqa: E402
import toolchain  # noqa: E402
from image import GENERATED, ROOT  # noqa: E402

OUT = GENERATED / "live_profile"
RUN = OUT / "run"


def build_profiler(root: Path) -> Path:
    exe = OUT / "live_profile.exe"
    toolchain.run_tool(["cl", *toolchain.RUNTIME_CFLAGS, f"/I{root / 'port' / 'lifted_live'}", f"/I{root / 'port' / 'lifted_runtime'}",
                        f"/Fo{OUT}\\", f"/Fe{exe}", str(ROOT / "port" / "lifted_live" / "live_profile.c"), "/link", "/INCREMENTAL:NO"],
                       cwd=OUT)
    return exe


def report(top: int) -> None:
    by_kind: collections.Counter = collections.Counter()
    by_thread: collections.Counter = collections.Counter()
    guest: collections.Counter = collections.Counter()
    helper: collections.Counter = collections.Counter()
    other: collections.Counter = collections.Counter()
    last_ms = looks = 0
    for line in (OUT / "samples.tsv").read_text(encoding="utf-8", errors="replace").splitlines():
        if line.count("\t") != 4 or not line.rsplit("\t", 1)[1].isdigit():
            continue  # the line being written when the run was ended
        ms, tid, kind, name, cycles = line.split("\t")
        weight = int(cycles)
        last_ms = int(ms)
        looks += 1
        by_kind[kind] += weight
        by_thread[tid] += weight
        if kind in "GH":
            guest[name] += weight
            helper[name] += weight if kind == "H" else 0
        else:
            other[(kind, name)] += weight
    total = sum(by_kind.values())
    if not total:
        print("no samples")
        return
    share = lambda n: f"{100.0 * n / total:5.1f}%"  # noqa: E731
    print(f"{looks} looks at running threads over {last_ms / 1000.0:.0f} s, {len(by_thread)} threads; the busiest used "
          + ", ".join(f"{share(n).strip()}" for _, n in by_thread.most_common(4)) + " of the processor time")
    print(f"lifted code {share(by_kind['G'] + by_kind['H'])} (its own instructions {share(by_kind['G'])}, helpers it calls "
          f"{share(by_kind['H'])}), runner and shims {share(by_kind['R'])}, elsewhere {share(by_kind['M'])}")
    rows, running = [], 0
    for name, n in guest.most_common():
        running += n
        rows.append((name, n, helper[name], running))
    (OUT / "hot_functions.tsv").write_text(
        "entry\tcycles\tin_helpers\tcumulative_share_of_lifted\n"
        + "".join(f"{name}\t{n}\t{h}\t{cum / max(1, sum(guest.values())):.4f}\n" for name, n, h, cum in rows),
        encoding="utf-8", newline="\n")
    lifted = sum(guest.values())
    for limit in (10, 100, 1000):
        print(f"  the {limit} busiest lifted functions: {100.0 * sum(n for _, n in guest.most_common(limit)) / max(1, lifted):.1f}% of "
              f"lifted time" + (f" ({len(guest)} functions sampled)" if limit == 1000 else ""))
    print(f"top {top} lifted functions (share of all processor time, of it in helpers):")
    for name, n, h, _ in rows[:top]:
        print(f"  {name}  {share(n)}  {100.0 * h / n:3.0f}%")
    print(f"top {top} outside lifted code:")
    for (kind, name), n in other.most_common(top):
        print(f"  {share(n)}  {'runner ' if kind == 'R' else 'module '}{name}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", type=Path, default=ROOT, help="checkout whose generated/lifted/live build is profiled")
    ap.add_argument("--seconds", type=int, default=900, help="end the run after this long")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--report", action="store_true", help="only sum up the samples already taken")
    ap.add_argument("live_args", nargs="*", help="arguments passed to live.exe (after --)")
    args = ap.parse_args(argv)
    if args.report:
        report(args.top)
        return 0
    root = args.root.resolve()
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        live_private.snapshot(root, RUN)
        live_private.build(root, RUN)
        profiler = build_profiler(root)
    except toolchain.BuildError as error:
        print(str(error)[-4000:], file=sys.stderr)
        return 1
    command = [str(profiler), str(OUT / "samples.tsv"), str(RUN / "lifted.dll"), str(RUN / "live.exe"), "--image", str(RUN / "image.bin"),
               "--game-dir", str(root / "Total War Rome II"), "--profile", str(OUT / "profile"), *args.live_args]
    if not (OUT / "profile").exists():  # start from the preferences the build's own runs use
        shutil.copytree(root / "generated" / "lifted" / "live" / "profile", OUT / "profile")
    with open(OUT / "last_run.txt", "w", encoding="utf-8", newline="\n") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            proc.wait(timeout=args.seconds)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)  # live.exe with it
            proc.wait()
            print(f"the run was ended after {args.seconds} s")
    report(args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
