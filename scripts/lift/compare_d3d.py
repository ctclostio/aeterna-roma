"""Compares two records of a program's Direct3D calls.

    python scripts/lift/compare_d3d.py <record> <record>

A record has one line per call a program makes,

    <thread> <Interface>::<Method>(<arguments>) = <result>

with everything that differs from run to run for no reason of the program's left out (addresses are `*`, handles
`h`), and threads numbered in the order of their first call. Two runs that make the same calls give the same
lines, so the first line that differs is where the runs part. Two things write such records, and a comparison
is between two of the same kind:

  - the Direct3D bridge, when ROME2_D3D11_TRACE names a file (port/lifted_live/d3d11_bridge.c, section 6):
    every call the lifted game makes;
  - scripts/lift/watch_d3d.py, from Windows' event tracing: the DXGI calls and Direct3D 11 resources of any
    program, the original game included, watched from outside.

Threads run side by side, so the lines of different threads interleave differently in every run: each thread's
lines are compared as a sequence of their own. Exit code 1 when a thread's sequences differ.

A watched record of the original 32-bit game against a watched record of the lifted run is what makes this the
check that start-up has in compare_orig.py. The original has not been watched yet.
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

CONTEXT = 3


def read(path: Path) -> dict[str, list[str]]:
    threads: dict[str, list[str]] = collections.defaultdict(list)
    for text in path.read_text(encoding="utf-8", errors="replace").splitlines():
        thread, _, call = text.partition(" ")
        threads[thread].append(call)
    return threads


def compare(a: dict[str, list[str]], b: dict[str, list[str]], names=("first", "second")) -> list[str]:
    """One paragraph per thread whose calls differ."""
    out = []
    for thread in sorted(set(a) | set(b), key=lambda t: (len(t), t)):
        x, y = a.get(thread, []), b.get(thread, [])
        if x == y:
            continue
        at = next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
        lines = [f"thread {thread}: the same for {at:,} calls, then ({len(x):,} calls in the {names[0]}, {len(y):,} in the {names[1]}):"]
        lines += [f"      {call}" for call in x[max(0, at - CONTEXT):at]]
        lines += [f"  {names[0]:>6}: {x[at] if at < len(x) else '(no more calls)'}", f"  {names[1]:>6}: {y[at] if at < len(y) else '(no more calls)'}"]
        out.append("\n".join(lines))
    return out


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    a, b = (read(Path(p)) for p in args)
    differences = compare(a, b)
    total = lambda r: sum(len(v) for v in r.values())  # noqa: E731
    print(f"{total(a):,} calls on {len(a)} threads against {total(b):,} calls on {len(b)} threads")
    print("\n".join(differences) if differences else "every thread makes the same calls in both")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
