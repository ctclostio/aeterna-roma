"""One command for the live tier's checks.

    python scripts/lift/gate.py            every step
    python scripts/lift/gate.py --quick    the steps that need neither the game nor the built tier (what CI runs)
    python scripts/lift/gate.py --record   also write the ladder the run gives (port/lifted_live/milestones.json, README)

Steps, cheapest first; a failed step does not keep the later ones from running, and the exit code is 1 when any
failed:

    ledger    python -m unittest scripts/test_lift_ledger.py scripts/test_live_milestones.py
              the committed lifted-tier ledger and milestone ladder agree with the README
    bridge    scripts/lift/gen_d3d11_bridge.py --test
              the Direct3D bridge against the SDK headers and, end to end, against WARP
    fast-rt   scripts/lift/check_fast_rt.py
              the inline runtime header the live build gives its hottest functions (port/lifted_live/fast_inc/lift_rt.h)
              against lift_rt.c: every function it replaces, run on the same inputs, must leave the same state
    start-up  scripts/lift/compare_orig.py
              the lifted DLL start-up against the original DLL in a 32-bit process; fails when the import calls or
              the DLL entry result differ
    run       scripts/lift/build_live.py --run
              builds and runs the game from entry_point. The run ends at a STOP until the port is complete, so its
              exit code is not the verdict: the step fails when a rung of the committed milestone ladder is no
              longer reached.

start-up and run need the game image and the built tier and are skipped, visibly, without them; fast-rt needs
neither and is skipped the same way in a checkout that has no such header. The game allows one instance of
itself: do not run this while another live.exe of the same checkout is running.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fast_rt  # noqa: E402
import milestones  # noqa: E402
from image import GENERATED, IMAGE_PATH, ROOT  # noqa: E402

LIFT = Path(__file__).resolve().parent


def command(*args: str) -> tuple[bool, str]:
    proc = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, errors="replace")
    text = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, text


def step_ledger() -> tuple[bool, str]:
    ok, text = command("-m", "unittest", "scripts/test_lift_ledger.py", "scripts/test_live_milestones.py")
    return ok, text.splitlines()[-1] if ok else text[-3000:]


def step_bridge() -> tuple[bool, str]:
    ok, text = command(str(LIFT / "gen_d3d11_bridge.py"), "--test")
    return ok, "\n".join(line for line in text.splitlines() if "checks passed" in line or "NOT CHECKED" in line) if ok else text[-3000:]


def step_fast_rt() -> tuple[bool, str]:
    ok, text = command(str(LIFT / "check_fast_rt.py"))
    return ok, text.splitlines()[-1] if ok else "\n".join(line for line in text.splitlines() if ": checked " not in line)[-3000:]


def step_startup() -> tuple[bool, str]:
    ok, text = command(str(LIFT / "compare_orig.py"))
    if not ok:
        return False, text[-3000:]
    return milestones.startup_check(ROOT)


def step_run(record: bool) -> tuple[bool, str]:
    _, text = command(str(LIFT / "build_live.py"), "--run")  # ends at a STOP: see the module text
    before = json.loads(milestones.LADDER.read_text(encoding="utf-8"))
    after = milestones.build(ROOT)
    lost = [f"{b['title']} ({'compared' if b['compared'] and not a['compared'] else 'reached'} before)"
            for b, a in zip(before["rungs"], after["rungs"]) if (b["reached"] and not a["reached"]) or (b["compared"] and not a["compared"])]
    gained = [a["title"] for b, a in zip(before["rungs"], after["rungs"]) if a["reached"] and not b["reached"]]
    if record and not lost:
        milestones.main([])
    report = [f"stopped at: {after['run']['stopped_at']}", f"reached: {', '.join(r['title'] for r in after['rungs'] if r['reached']) or 'nothing'}"]
    report += [f"new: {', '.join(gained)}" + ("" if record else " (not recorded: run with --record)")] if gained else []
    report += [f"LOST: {', '.join(lost)}"] if lost else []
    return not lost, "\n".join(report) if after["run"]["stopped_at"] or after["rungs"][0]["reached"] else text[-3000:]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true", help="only the steps that need neither the game nor the built tier")
    ap.add_argument("--record", action="store_true", help="write the milestone ladder the run gives")
    args = ap.parse_args(argv)
    built = IMAGE_PATH.exists() and (GENERATED / "live" / "core").exists()
    why = "--quick" if args.quick else "" if built else "no game image or no built tier in this checkout"
    no_header = "" if check_fast_rt.header_path(ROOT).exists() else f"no {check_fast_rt.HEADER.as_posix()} in this checkout"
    steps = [("ledger", step_ledger, ""), ("bridge", step_bridge, ""), ("fast-rt", step_fast_rt, no_header),
             ("start-up", step_startup, why), ("run", lambda: step_run(args.record), why)]
    failed = []
    for name, fn, skip in steps:
        if skip:
            print(f"SKIPPED  {name}: {skip}", flush=True)
            continue
        t0 = time.perf_counter()
        ok, text = fn()
        print(f"{'ok      ' if ok else 'FAILED  '} {name} ({time.perf_counter() - t0:.0f} s)\n" + "\n".join("    " + line for line in text.splitlines()),
              flush=True)
        if not ok:
            failed.append(name)
    print("gate: " + (f"FAILED: {', '.join(failed)}" if failed else "passed" + (" (steps skipped)" if why or no_header else "")))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
