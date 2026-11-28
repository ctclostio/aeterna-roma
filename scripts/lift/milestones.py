"""The live x64 run's milestone ladder: how far into the game the lifted process gets, and how much of that
is compared with the original.

    python scripts/lift/milestones.py [--root <checkout>] [--records <dir>]   rewrite the ladder from <checkout>'s last run
    python scripts/lift/milestones.py --check                                 the README row is the one the ladder gives

A rung is REACHED when the last run of live.exe (build_live.py --run: generated/lifted/live/last_run.txt) shows
what the rung's rule below names: a line the runner prints, a line the game prints, or a count in the runner's
"imports called" list. A rung is COMPARED when it is reached and a check of the lifted run against the original
32-bit game passes there. The axis counts compared rungs: a rung the run merely gets to is not held.

DLL init is checked by compare_orig.py's record of start-up. The three Direct3D rungs (adapter enumeration, device,
first Present) are checked by two records of DXGI calls and Direct3D 11 resources watched from outside, in the form
scripts/lift/watch_d3d.py writes: original.txt of the original game and lifted.txt of the lifted run, in
generated/lifted/d3d_watch/ of this checkout or the folder --records names. Each rung takes the lines of both records
up to its marker line and compare_d3d.py compares them thread by thread. Without both records, without the marker in
both, or (adapter enumeration) without an adapter before the device in both, the rung is not compared and says why.

The ladder is port/lifted_live/milestones.json and one row of the README status table. It is an axis of its
own: nothing it says moves another row. scripts/test_live_milestones.py holds the row to the file.

Rules are only written for what a run is known to show. Nothing is known yet that shows a battle running (the
checksum lines the game prints while one is being loaded do not), so that rung has no rule, cannot be reached,
and says so.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import compare_d3d

ROOT = Path(__file__).resolve().parents[2]
LADDER = ROOT / "port" / "lifted_live" / "milestones.json"
README = ROOT / "README.md"
ROW = re.compile(r"(?m)^\| Live x64 run milestones \|.*$")
AFTER = re.compile(r"(?m)^\| Lifted C differential tests \|.*$")  # the row goes under the lifted tier's own

# The two watched records the Direct3D rungs are compared by (<records>/<name>.txt), and what records them.
RECORDS = ROOT / "generated" / "lifted" / "d3d_watch"
WATCHED = (("original", "the original game"), ("lifted", "the lifted run"))
WATCH = "python scripts/lift/watch_game.py"

# A Direct3D rung's part of a watched record: the lines of the file before (False) or through (True) the first line
# whose call begins with the marker, as scripts/lift/watch_d3d.py writes it. The parts are nested, as the rungs are.
BEFORE_DEVICE, THROUGH_DEVICE = ("create Device(", False), ("create Device(", True)
THROUGH_PRESENT = ("IDXGISwapChain::Present(", True)
ADAPTER = "create Adapter("  # what the part before the device must hold in both records to stand for the enumeration


def line(pattern: str):
    """A line of the run log."""
    def rule(log: str, calls: dict[str, int]) -> str | None:
        found = re.search(pattern, log, re.M)
        return found.group(0).strip()[:160] if found else None
    return rule


def called(*names: str, prefix: str = ""):
    """Imports or COM slots (interface#slot) the guest called, by the runner's count."""
    def rule(log: str, calls: dict[str, int]) -> str | None:
        hits = {n: c for n, c in calls.items() if c and (n in names or (prefix and n.startswith(prefix)))}
        return ", ".join(f"{n} called {c:,} times" for n, c in sorted(hits.items())[:4]) or None
    return rule


# (id, title, what reaching it means, rule, comparison check)
RUNGS = (
    ("dll_init", "DLL init", "the lifted DLL entry returns 1 for DLL_PROCESS_ATTACH: CRT start-up and the static initializers ran",
     line(r"^REACHED: DLL entry returned 1 for DLL_PROCESS_ATTACH.*$"), "start-up"),
    ("entry_point", "entry_point", "the runner, standing in for Rome2.exe, calls the DLL's entry_point export (0x100edd70)",
     line(r"^launcher: blocks .*$"), None),
    ("vfs", "VFS", "the game logs \"Finished VFS load_release\" (its own wording)",
     line(r"^guest: PRE_DB_APP_INIT: Done Finished VFS load_release.*$"), None),
    ("adapters", "adapter enumeration", "the game enumerates display adapters through DXGI",
     called("IDXGIFactory#7", "IDXGIFactory1#12"), BEFORE_DEVICE),
    ("device", "device", "the game calls methods of a Direct3D 11 device",
     called(prefix="ID3D11Device#"), THROUGH_DEVICE),
    ("window", "window", "the game creates its window",
     called("CreateWindowExA", "CreateWindowExW"), None),
    ("present", "first Present", "the game presents a frame (IDXGISwapChain::Present, slot 8)",
     called("IDXGISwapChain#8"), THROUGH_PRESENT),
    # The game's banner, printed once, when a pass of its main loop first runs to the end (0x100ec9e2 in the loop's function 0x100ec5c0,
    # behind a flag byte cleared there; the text begins with newlines, so "guest: " stays on the line above). That pass has opened the
    # start-up state (0x100d81c0) and returned with it on the state stack. The banner itself is blind to which state that is: it is the
    # front end (built by 0x10eb2740, named L"Front end") because the start-up mode is L"front_end" unless a game_startup_mode command
    # changes it (default set at 0x100e3202), and the runner passes no command line. It does not show the menu drawn: a saved frame does.
    ("menu", "menu", "the front end is up", line(r"^\*\*\*  TIME TO FIRST FRAME: \d+seconds$"), None),
    # No rule. The game's "- BMD checksum ---" lines (text at 0x117e4754) are not one: the runs that print them have clicked the
    # menu's Start Prologue and the last frame they save is a loading screen. That is a battle being loaded, not one running.
    ("battle", "battle", "a battle runs", None, None),
)


def startup_check(root: Path) -> tuple[bool, str]:
    """Rung 1's comparison: compare_orig.py's record of the lifted start-up against the original DLL's."""
    path = root / "port" / "lifted_live" / "verify_init.json"
    if not path.exists():
        return False, "compare_orig.py has not been run"
    v = json.loads(path.read_text(encoding="utf-8"))
    calls, entry, memory = v["calls"], v["entry_result"], v["memory"]
    passed = bool(calls["identical"]) and entry["original"] == entry["lifted"]
    return passed, (f"compare_orig.py: {calls['lifted_calls']:,} import calls against the original's {calls['original_calls']:,}, "
                    f"{'identical' if calls['identical'] else 'different'}; DLL entry result {entry['lifted']} against {entry['original']}; "
                    f"{memory['different']:,} of {memory['dwords']:,} dwords of the writable sections differ unexplained")


def part(lines: list[str], marker: str, through: bool) -> list[str] | None:
    """The lines of a record before, or through, the first whose call begins with the marker; None without one."""
    for i, text in enumerate(lines):
        if text.partition(" ")[2].startswith(marker):
            return lines[:i + 1 if through else i]
    return None


def d3d_check(records: Path, marker: str, through: bool) -> tuple[bool, str]:
    """A Direct3D rung's comparison: its part of the lifted run's watched record against the same part of the original's.
    The part is cut in the order of the file and compared thread by thread, so a line another thread writes before the
    marker in one run and after it in the other counts as a difference."""
    paths = [(records / f"{name}.txt", f"{who} ({name}.txt)") for name, who in WATCHED]
    missing = [whose for path, whose in paths if not path.is_file()]
    if missing:
        return False, f"not compared: no watched record of {' or of '.join(missing)}; to record one: {WATCH}"
    parts = [part(path.read_text(encoding="utf-8", errors="replace").splitlines(), marker, through) for path, _ in paths]
    unmarked = [whose for (_, whose), lines in zip(paths, parts) if lines is None]
    if unmarked:
        return False, f"not compared: no \"{marker}\" line in the watched record of {' or of '.join(unmarked)}"
    original, lifted = parts
    if not through:  # the part before the device is the adapter enumeration only if it shows an adapter: a trace begun late does not
        blind = [whose for (_, whose), lines in zip(paths, parts) if not any(t.partition(" ")[2].startswith(ADAPTER) for t in lines)]
        if blind:
            return False, f"not compared: no \"{ADAPTER}\" line before the first \"{marker}\" line in the watched record of {' or of '.join(blind)}"
    text = (f"compare_d3d.py on the watched records {'through' if through else 'before'} the first \"{marker}\" line: "
            f"{len(lifted):,} lines of the lifted run against the original's {len(original):,}, ")
    different = compare_d3d.differences(compare_d3d.by_thread(original), compare_d3d.by_thread(lifted))
    if not different:
        return True, text + "every thread's the same"
    thread, at, x, y = different[0]
    call = lambda calls: calls[at] if at < len(calls) else "(no more calls)"  # noqa: E731
    return False, text + (f"threads that differ: {len(different)}; thread {thread} is the same for {at:,} calls, "
                          f"then original: {call(x)} | lifted: {call(y)}")


def build(root: Path, records: Path = RECORDS) -> dict:
    log_path = root / "generated" / "lifted" / "live" / "last_run.txt"
    log = log_path.read_text(encoding="utf-8", errors="replace")
    calls: dict[str, int] = {}
    for listing in re.findall(r"^imports called: (.*)$", log, re.M):
        for name, count in re.findall(r"(\S+)=(\d+)", listing):
            calls[name] = calls.get(name, 0) + int(count)
    stop = re.search(r"^STOP: (.*)$", log, re.M)
    insns = re.search(r"^instructions executed:\s+(\d+)", log, re.M)
    rungs, held = [], True
    for key, title, meaning, rule, check in RUNGS:
        evidence = rule(log, calls) if rule else None
        reached = held and evidence is not None  # a ladder: nothing counts above the first rung not reached
        held = reached
        passed, comparison = False, "none yet"
        if check == "start-up":
            passed, comparison = startup_check(root)
        elif check:
            passed, comparison = d3d_check(records, *check)
        if passed and not reached:
            comparison += "; not counted: the last run does not reach this rung"
        rungs.append({"id": key, "title": title, "means": meaning,
                      "rule": "none yet: what in a run shows this is not identified" if rule is None else "see scripts/lift/milestones.py",
                      "reached": reached, "evidence": evidence, "compared": passed and reached, "comparison": comparison})
    return {"run": {"instructions_executed": int(insns.group(1)) if insns else None, "stopped_at": stop.group(1) if stop else None},
            "rungs": rungs}


def row(ladder: dict) -> str:
    rungs = ladder["rungs"]
    reached, compared = [r for r in rungs if r["reached"]], [r for r in rungs if r["compared"]]
    names = lambda rs: ", ".join(r["title"] for r in rs) if rs else "none"  # noqa: E731
    next_up = next((r["title"] for r in rungs if not r["reached"]), None)
    return (
        f"| Live x64 run milestones | {len(compared)} / {len(rungs)} rungs ({100 * len(compared) / len(rungs):.1f}%) | "
        f"The lifted tier run as a real x64 process (`port/lifted_live/`), on a ladder of its own: "
        f"{' → '.join(r['title'] for r in rungs)}. A rung counts when the run reaches it and a comparison with the original "
        f"32-bit game passes there. Compared: {names(compared)}. Reached by the last run without a comparison yet: "
        f"{names([r for r in reached if not r['compared']])}. "
        + (f"Next rung: {next_up}. " if next_up else "")
        + "See `port/lifted_live/milestones.json` and `scripts/lift/milestones.py`. |"
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", type=Path, default=ROOT, help="checkout whose last run and start-up comparison are read")
    ap.add_argument("--records", type=Path, default=RECORDS, help="folder of the watched records original.txt and lifted.txt")
    ap.add_argument("--check", action="store_true", help="only check that the README row is the ladder's")
    args = ap.parse_args(argv)
    readme = README.read_text(encoding="utf-8")
    if args.check:
        ladder = json.loads(LADDER.read_text(encoding="utf-8"))
        found = ROW.search(readme)
        if not found or found.group(0) != row(ladder):
            print("README.md: the 'Live x64 run milestones' row is not the one port/lifted_live/milestones.json gives", file=sys.stderr)
            return 1
        return 0
    ladder = build(args.root.resolve(), args.records)
    LADDER.write_text(json.dumps(ladder, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    text = row(ladder)
    if ROW.search(readme):
        readme = ROW.sub(lambda _: text, readme)
    else:
        under = AFTER.search(readme)
        if not under:
            print("README.md: no status row to put the ladder under", file=sys.stderr)
            return 1
        readme = readme[:under.end()] + "\n" + text + readme[under.end():]
    README.write_text(readme, encoding="utf-8", newline="\n")
    for r in ladder["rungs"]:
        print(f"{'compared' if r['compared'] else 'reached ' if r['reached'] else '-       '}  {r['title']:20s} {r['evidence'] or ''}"[:150])
    return 0


if __name__ == "__main__":
    sys.exit(main())
