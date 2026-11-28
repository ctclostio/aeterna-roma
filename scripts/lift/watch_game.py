"""Watches the next launch of a program by its name and gathers its Direct3D record: no trace has to be started first.

    python scripts/lift/watch_game.py arm          from now on a process named Rome2.exe is recorded whenever one runs
    python scripts/lift/watch_game.py collect      after it has run and ended: writes generated/lifted/d3d_watch/original.txt
    python scripts/lift/watch_game.py status       what is open, what is running
    python scripts/lift/watch_game.py disarm       stop recording without decoding
    python scripts/lift/watch_game.py wait         the monitor: arms, and collects by itself every time the program has ended
    python scripts/lift/watch_game.py install      have Windows start that monitor at every logon (uninstall removes it)
    python scripts/lift/watch_game.py selftest     the whole flow on a stand-in program

    --exe live.exe      any verb: another program than Rome2.exe (live.exe is the lifted runner)

All of it needs an elevated prompt. Standard library only.

WHAT IT DOES TO THE WATCHED PROGRAM. It watches from outside: dxgi.dll and d3d11.dll report what they are
asked to do to Windows' own event tracing whenever a trace session asks, and `arm` opens such a session, scoped by
Windows to programs with that file name (scripts/lift/etw_scope.py). Nothing is loaded into the game, no file of the
game or in its folder is touched, read or written, and the game is started no differently: by whoever starts it, as
always; this tool never starts it. The monitor also looks at the process list for the name, and holds a handle to the
process that allows waiting for its end and asking its bitness, the path of its image and when it started, and nothing
else (no access to its memory). What does change inside the program is what Windows changes for any trace session:
the event writing of the program's own dxgi.dll and d3d11.dll is switched on. That costs it time in every DXGI call
(0.02 microseconds became 0.3 to 0.6 in a stand-in) and a program that looks can see it (a stand-in that registered a
provider under DXGI's id was told by Windows that a session had switched it on); whether the game looks is not checked.

WHAT STAYS ON THE MACHINE, and how to see and remove it.
  - A trace session held by the Windows kernel, aeterna_watch_<name> (aeterna_watch_rome2). It records the DXGI and
    Direct3D 11 events of programs named <name>.exe and of no other program, so nothing until one runs and uses
    Direct3D; armed and idle it costs two 256 KiB buffers and a 262,144-byte file. Nothing limits that file: a
    stand-in's events took 9 to 23 bytes each in it and about 1 KB each in the decoded form, which exists while
    `collect` works; how many events the game writes in an hour is not known. It belongs to no process: it stays
    until `collect`, `disarm` or a restart of the machine. See it with `status` or `logman query -ets`; remove it
    with `disarm` or `logman stop aeterna_watch_<name> -ets`.
  - Files in generated/lifted/d3d_watch/ (git-ignored): the traces <role>_<date>_<time>.etl, kept (compressed; a new
    name at every arming, because Windows replaces an existing trace file without a word; one that recorded nothing,
    262,144 bytes, stays until the next `collect` or monitor deletes it); the records below; and monitor.log. <role> is "original" for Rome2.exe, "lifted" for
    live.exe, else the name without .exe in lower case.
  - Only after `install`: the scheduled task aeterna_game_watch, which runs `wait` under pythonw at every logon of
    the user who installed it, with the highest run level. See it with `Get-ScheduledTask aeterna_game_watch`
    (`status` does not show it); remove it with `uninstall`, which also ends its monitor. The session stays until
    `disarm`. The task runs this file, with administrator rights and without asking, as it is at each logon: on this
    machine any program of any user may change the files in scripts/lift/ (icacls: Modify for Authenticated Users),
    and what it puts there then runs with those rights. The task names this checkout's path: with the file gone
    pythonw ends with exit code 2 (run by hand, not as the task) and nothing is watched. The task keeps Task
    Scheduler's default priority, 7, which its documentation gives as below normal.
  - While the monitor sees the program running: a second session, aeterna_watch_<name>_files (below).

THE RECORD. `collect` refuses while a process of that name runs (a compressed trace cannot be decoded before its
session has stopped). Otherwise it stops the session, arms again with a new file unless --no-rearm (so the launch
after this one is recorded too), decodes the trace with tracerpt, lists the processes in it (process id, bitness,
events, first and last event), and writes the record of the one with the most events, or of --pid, to <role>.txt and
to <role>_<date>_<time>.txt beside its trace, which no later run overwrites. The record of another process of a kept
trace: `python scripts/lift/watch_d3d.py write <record> --etl <trace> --pid <pid>` (it names the trace's processes
when the pid is not one of them). What a record holds and does not hold is in scripts/lift/watch_d3d.py: the DXGI
calls and the Direct3D 11 devices, contexts, buffers and textures created, not draws, state, shaders or views; a
32-bit and a 64-bit program making the same calls give the same record.
A trace that was left without a record (the monitor was ended while it decoded, the machine was restarted with the
session open, `disarm`) is not lost: `collect`, and the monitor when it starts, first go through the traces in the
folder that no session writes and that have no record, oldest first. Each that holds a run gets its dated record,
and <role>.txt too unless the folder has the dated record of a later trace; each that holds nothing of the program
is deleted (every arming that no run followed leaves one); one that tracerpt cannot read stays, with <trace>.err
beside it saying why, and is not tried again. `status` lists them.
A process the monitor did not see alive has its bitness read from its events; when they do not tell it (listed as
??-bit: no first DXGI call in the trace, say) the record is read as a 64-bit program's and `collect` says so.
When original.txt and lifted.txt both exist, `collect` runs scripts/lift/compare_d3d.py on them and prints the
beginning of what it says.

THE MONITOR. `wait` arms (or takes over the open session), waits for a process of the name (one look at the process
list every 0.25 s: over a minute it used 1.7% of one processor while it waited and 1.5% while the program ran, its
handles and memory did not grow and a look logs nothing), notes each such process's id and bitness, waits until all
have ended and none has appeared for 10 seconds (a launcher may start the program again), does what `collect` does,
and waits again with a new trace file, until it is ended. A run it did not see, over between two looks or made while
the session was open and no monitor ran, is collected as well: it shows as events in the trace. What it prints also
goes to monitor.log with the time, and under pythonw only there. One monitor for each watched name: a second one says
so and ends. When the monitor is ended while armed, however it is ended, the session stays open and goes on
recording, and a later `collect` or the next monitor works as if there had been no monitor. `disarm` beside a running
monitor is undone by it within a second: end the monitor first.

THE FILES THE PROGRAM OPENS. While it sees the program running, and for at most --files-seconds (600; 0: never), the
monitor records which files are opened: Microsoft-Windows-Kernel-File, event 12. That provider cannot be scoped to a
program, so the session aeterna_watch_<name>_files records every program's opens (it closes itself at 256 MB should
nobody be left to stop it). After the Direct3D record is written, only the lines of the watched processes are
kept, in <role>_files.txt and <role>_<date>_<time>_files.txt, and the raw trace and its decoded form, which hold other
programs' file names, are deleted, also when decoding it or the Direct3D trace fails or the run fails otherwise (each
was made to fail once). A monitor that is ended while the program runs leaves the session open: it goes on recording
every program's opens until it is stopped or its file is full. One that is ended while it decodes leaves the raw trace
and what is decoded of it (377 MB once, for 18 seconds in which a test opened 250,000 files). `status` shows all of
these; `arm`, `collect` (also when it refuses), `disarm` and the next monitor stop the session and delete them.
The lines are kept by process id, so the monitor keeps its handle to a watched process that has ended until the
recording of file opens has stopped: Windows gives a process id to no other process meanwhile. (Without that, another
program got the ended probe's id 4.9 s later, after 1,689 process starts, and its opens were in the list; with a
handle kept, none of 4,072 processes started in 12 s got the id, and one of the next 1,008 did once it was closed.)
Not covered: a later process of the name whose id another program had earlier in the same recording.
A line is "<thread> <path>" in the order of the opens, threads numbered by their first line here (not as in the
Direct3D record), the path relative to the program's own folder when it is under it and with its drive letter
otherwise. An open that failed is there like any other and is not marked: event 12 is written when the open is asked
for and holds no result. (The result is in event 24, which Windows writes for every file operation of every program:
172,395 of them beside 34,393 opens in ten seconds on this machine. It is not recorded.)
It misses the opens between the program's start and the moment the session records: 0.03 to 0.22 s in ten runs here
(the wait for the next look at the process list, then opening the session); what the program opens before that is
not in the list. A run the monitor did not see has no list. Errors in this part are logged and never stop the
Direct3D record.

NOT CHECKED. The original game has never been watched: everything here was run on port/lifted_live/test_d3d_probe.c,
built 32-bit and 64-bit (`selftest`), on Windows 11 build 26300. So it is not known that the game's Direct3D calls
come from a process named Rome2.exe, nor that they go to DXGI and Direct3D 11 (the README names a Direct3D 9 renderer
as well; a run that leaves no event of the two providers gives no record). Whether a Steam overlay or other software
that runs inside the game's process adds its own Direct3D resources to the game's record is not known. Whether Windows
lets the monitor open the game's process is not known either. If it does not (run with a probe that put an empty
access list on its own process, the monitor's debug privilege off): the record is collected once no process of the
name is left, the monitor logs two lines every ten seconds until then, and no list of files is written. (With the
debug privilege on, as it was in the shell these tests ran in, the monitor opened that process all the same.)
`install` was run once, under the selftest's task name: the task was registered as it prints, started with
Start-ScheduledTask, its monitor collected a run of the probe, and `uninstall` removed it. Not run: `install` under
its real task name and a logon that starts the task; a restart, sleep or logoff with the session open, and whether the
trace file of a session that a restart ended can be decoded (by the code, the next `collect` or monitor tries it and
leaves <trace>.err when it cannot); a prompt of a user without
administrator rights (run instead: a process whose token has the Administrators group for denying only, in which
every verb that needs a session ends with Windows' error 5 and "this needs an elevated prompt"); the file-open session
reaching 256 MB (with the limit at 1 MB it closed itself, and the monitor wrote its list all the same); a file-open
trace of more than a minute, whose decoded form is about 1.5 KB an event (575 to 3,400 opens a second were seen here)
and exists until its lines are written.
"""
from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

import etw_scope as etw
import toolchain
import watch_d3d

HERE = Path(__file__).resolve().parent
ROLES = {"rome2.exe": "original", "live.exe": "lifted"}  # the records scripts/lift/milestones.py compares
PROBE = "test_d3d_probe.exe"
POLL = 0.25         # seconds between two looks at the process list
QUIET = 10.0        # seconds without a process of the name before a run is over
FILES_MAX_MB = 256  # the file-open session closes itself at this size
PYTHON, PYTHONW = (Path(sys.executable).with_name(name) for name in ("python.exe", "pythonw.exe"))
LOG: Path | None = None  # the monitor's log


class Watch:
    """The names that go with one watched executable."""

    def __init__(self, exe: str, selftest: bool = False):
        stem = exe[:-4].lower()
        self.exe = exe
        self.role = ROLES.get(exe.lower(), stem)
        self.out = watch_d3d.OUT.with_name("d3d_watch_selftest") if selftest else watch_d3d.OUT
        self.prefix = "aeterna_selftest_" if selftest else "aeterna_watch_"
        self.session = self.prefix + stem
        self.files_session = self.session + "_files"
        self.monitor = f"Global\\{self.session}_monitor"  # a mutex: one monitor for each watched name
        self.task = "aeterna_game_watch" + ("_selftest" if selftest else "")
        self.options = (["--exe", exe] if exe.lower() != "rome2.exe" else []) + (["--selftest"] if selftest else [])

    def command(self, verb: str) -> str:
        return " ".join(["python scripts/lift/watch_game.py", verb, *self.options])


def say(text: str) -> None:
    """Prints. The monitor's lines also go to its log with the time; under pythonw there is no console and print does nothing.
    A log that cannot be written loses the lines and nothing else: held open by another program that shares it for
    reading only, it ended the monitor at its next line."""
    print(text, flush=True)
    if LOG:
        try:
            with open(LOG, "a", encoding="utf-8", newline="\n") as log:
                log.writelines(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n" for line in text.splitlines())
        except OSError:
            pass


def fresh(folder: Path, role: str) -> Path:
    """<folder>/<role>_<date>_<time>, with a counter behind it when needed: a name under which the folder has no trace,
    record or file list yet. StartTraceW replaces an existing trace file without a word, and a dated record stays."""
    stamp, n = time.strftime("%Y%m%d_%H%M%S"), 1
    base = folder / f"{role}_{stamp}"
    while any(Path(f"{base}{suffix}").exists() for suffix in (".etl", ".txt", "_files.txt")):
        n += 1
        base = folder / f"{role}_{stamp}_{n}"
    return base


def arm(w: Watch) -> None:
    """Opens the scoped session with a new trace file, or leaves the open one as it is."""
    props = etw.query_session(w.session)
    if props:
        say(f"{w.session} is already open and is left as it is; it writes to {props.LogFileName}")
        return
    w.out.mkdir(parents=True, exist_ok=True)
    etl = f"{fresh(w.out, w.role)}.etl"
    handle = etw.start_session(w.session, etl)
    try:
        for provider in (etw.DXGI, etw.DIRECT3D11):
            etw.enable_provider(handle, provider, exe_name=w.exe)
    except Exception:
        etw.stop_session(w.session)  # never leave a half-configured session open
        raise
    say(f"armed: the kernel trace session {w.session} writes to {etl}")


def arm_verb(w: Watch) -> int:
    arm(w)
    say(f"In place now: a trace session held by the Windows kernel, with no process of this tool running. It records the DXGI and Direct3D 11\n"
        f"events of programs named {w.exe} and of no other program: nothing until one runs and uses Direct3D. It stays until\n"
        f"`{w.command('collect')}`, `{w.command('disarm')}` or a restart of the machine. To see it: logman query -ets")
    running = etw.find_processes(w.exe)
    if running:
        say(f"warning: {w.exe} is running already (pid {', '.join(map(str, running))}): it is recorded only from the moment the session was opened")
    lifted = etw.find_processes("live.exe") if w.role == "original" else []
    if lifted:
        say(f"warning: live.exe is running (pid {', '.join(map(str, lifted))}). port/lifted_live/private_instance.h: the game allows one instance "
            "of itself; it creates a named mutex and leaves when the name already exists")
    return 0


def status(w: Watch) -> int:
    props = etw.flush_session(w.session)  # so that the file is as long as the trace is now
    if props:
        say(f"session {w.session}: open; file {props.LogFileName} ({os.path.getsize(props.LogFileName):,} bytes); events lost {props.p.EventsLost}")
    else:
        say(f"session {w.session}: not open")
    running = etw.find_processes(w.exe)
    say(f"{w.exe}: " + ("running, pid " + ", ".join(map(str, running)) if running else "not running"))
    monitored = etw.claimed(w.monitor)
    say(f"monitor (`wait`): {'running' if monitored else 'not running'}")
    left = uncollected(w)
    if left:
        say("traces without a record: " + ", ".join(f"{etl.name} ({etl.stat().st_size:,} bytes)" for etl in left)
            + f"; `{w.command('collect')}` or the next monitor writes the record of each that holds a run")
    files, raw = etw.query_session(w.files_session), raw_files(w)
    if files or raw:
        say(f"file opens of every program: session {w.files_session} {'open and recording' if files else 'not open'}; on disk: "
            + (", ".join(f"{path.name} ({path.stat().st_size:,} bytes)" for path in raw) or "nothing")
            + ("; the monitor removes them when it has written its list" if monitored
               else f"; a monitor that was ended left them: `{w.command('disarm')}`, `arm`, `collect` or the next monitor removes them"))
    others = [name for name, _ in etw.list_sessions(w.prefix) if name not in (w.session, w.files_session)]
    if others:
        say("other sessions of this tool that are open: " + ", ".join(others))
    return 0


def compare(folder: Path) -> int:
    """Runs scripts/lift/compare_d3d.py on the folder's original.txt and lifted.txt and prints the beginning of what it
    says. As a child process: it is a tool of its own, with its own exit code (1: the records differ)."""
    original, lifted = folder / "original.txt", folder / "lifted.txt"
    run = subprocess.run([str(PYTHON), str(HERE / "compare_d3d.py"), str(original), str(lifted)], capture_output=True, text=True, errors="replace",
                         creationflags=subprocess.CREATE_NO_WINDOW)
    said = (run.stdout + run.stderr).strip().splitlines()
    say(f"compare_d3d.py original.txt lifted.txt: exit code {run.returncode}\n" + "\n".join("  " + line[:240] for line in said[:12]))
    if len(said) > 12:
        say(f"  ... and {len(said) - 12} more lines: python scripts/lift/compare_d3d.py {original} {lifted}")
    return run.returncode


def collect(w: Watch, pid: int | None = None, rearm: bool = True, known: dict[int, int] | None = None) -> int:
    """Stops the session and writes the record of one process from its trace, after the records of traces that were
    left without one. `known`: the bitness of the processes a monitor saw alive (IsWow64Process2), which goes before
    what their events say."""
    recovered = recover(w)
    running = etw.find_processes(w.exe)
    if running:
        say(f"{w.exe} is still running (pid {', '.join(map(str, running))}): a trace cannot be decoded before its session has stopped, and "
            f"stopping it now would cut the record short. {w.session} is left as it is; collect when the program has ended.")
        return 1
    final = etw.stop_session(w.session)
    if final is None:
        say(f"{w.session} is not open: there is nothing {'more ' if recovered else ''}to collect")
        return 0 if recovered else 1
    etl = Path(final.LogFileName)
    say(f"stopped {w.session}; its trace is {etl} ({etl.stat().st_size:,} bytes)")
    if rearm:
        arm(w)  # before the decoding, which takes its time: the launch after this one is recorded too
    return 0 if write_record(w, etl, pid, known, final.p.EventsLost) else 1


def uncollected(w: Watch) -> list[Path]:
    """The traces in the folder that no session writes and that have no record, oldest first: the tool was ended, or
    the machine restarted, after a session stopped and before its record was written; `disarm` leaves one; and so
    does every arming that no run followed."""
    props = etw.query_session(w.session)
    current = Path(props.LogFileName) if props else None
    return sorted(etl for etl in w.out.glob(f"{w.role}_*.etl")
                  if not etl.stem.endswith("_files") and etl != current
                  and not etl.with_suffix(".txt").exists() and not etl.with_suffix(".err").exists())


def recover(w: Watch) -> int:
    """Writes the records of the uncollected traces and returns how many it wrote. <role>.txt is written from one only
    when the folder has no dated record of a later trace. A trace that holds nothing of the program is deleted. One
    that cannot be decoded stays, with a file <trace>.err beside it that says why, and is not tried again."""
    written = 0
    for etl in uncollected(w):
        later = any(path.stem > etl.stem for path in w.out.glob(f"{w.role}_*.txt") if not path.stem.endswith("_files"))
        say(f"a trace without a record: {etl} ({etl.stat().st_size:,} bytes)")
        try:
            if write_record(w, etl, None, None, 0, latest=not later):
                written += 1
            else:
                etl.unlink()
                say(f"deleted {etl.name}: it holds nothing of {w.exe}")
        except (Exception, SystemExit) as error:  # SystemExit: tracerpt failed, or the trace is not a whole one
            etl.with_suffix(".xml").unlink(missing_ok=True)
            etl.with_suffix(".err").write_text(f"{error}\n", encoding="utf-8", newline="\n")
            say(f"{etl.name} could not be decoded and stays as it is; {etl.with_suffix('.err').name} says why: {error}")
    return written


def write_record(w: Watch, etl: Path, pid: int | None, known: dict[int, int] | None, lost_by_session: int, latest: bool = True) -> bool:
    """Decodes a trace whose session has stopped and writes the record of one process: the dated copy beside the trace
    and, when `latest`, <role>.txt. False, and nothing written, when the trace holds no event of such a process."""
    types = watch_d3d.schema()
    seen, _, lost = watch_d3d.processes(etl, types)
    bits = {p: (known or {}).get(int(p)) or mine["bits"] for p, mine in seen.items()}
    for p, mine in sorted(seen.items(), key=lambda item: -item[1]["events"]):
        say(f"  pid {p:>6}  {bits[p] or '??'}-bit  {mine['events']:9,} events  {mine['first'][:23]} to {mine['last'][:23]}"
            + (f"  (its events say {mine['bits']}-bit)" if mine["bits"] not in (0, bits[p]) else ""))
    chosen = str(pid) if pid else max(seen, key=lambda p: seen[p]["events"], default="")
    if chosen not in seen:
        etl.with_suffix(".xml").unlink()
        say((f"pid {pid} is not among them" if pid else f"the trace holds no DXGI or Direct3D 11 event of a program named {w.exe}")
            + ": no record written")
        return False
    if not bits[chosen]:
        say(f"the events of pid {chosen} do not tell whether it is a 32-bit or a 64-bit program (scripts/lift/watch_d3d.py, Bitness): "
            "its record is read as a 64-bit program's")
    lines, unknown = watch_d3d.record(etl, chosen, types, bits[chosen])
    etl.with_suffix(".xml").unlink()
    record, dated = w.out / f"{w.role}.txt", etl.with_suffix(".txt")
    for path in (record, dated) if latest else (dated,):
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    say(f"{record if latest else dated}: {len(lines):,} lines from the {seen[chosen]['events']:,} events of pid {chosen}"
        + (f"; the copy that stays: {dated.name}" if latest else f"; {record.name} is of a later run and is left as it is"))
    say(f"events lost: {max(lost, lost_by_session)}; events the manifests do not describe: {unknown}")
    if len(seen) > 1:
        say(f"another process's record: python scripts/lift/watch_d3d.py write <record> --etl {etl} --pid <pid>")
    if latest and w.role in ROLES.values() and (w.out / "original.txt").exists() and (w.out / "lifted.txt").exists():
        compare(w.out)
    return True


def raw_files(w: Watch) -> list[Path]:
    """The raw traces of file opens in the folder and their decoded forms, whole or begun: every program's file names."""
    return [path for path in w.out.glob("*_files.*") if path.name.startswith(w.role + "_") and path.suffix in (".etl", ".xml")]


def drop_files(w: Watch) -> None:
    """Stops the file-open session if it is open and deletes the raw traces of file opens: what a monitor that was
    ended while the program ran has left. They hold other programs' file names, and nobody knows which lines to keep."""
    if etw.stop_session(w.files_session):
        say(f"stopped {w.files_session}, which a monitor that has ended left open")
    for path in raw_files(w):
        path.unlink()
        say(f"deleted {path}")


def disarm(w: Watch) -> int:
    if etw.claimed(w.monitor):
        say("warning: the monitor (`wait`) is running and arms again within a second: end it first")
    final = etw.stop_session(w.session)
    say(f"stopped {w.session} without decoding; its trace file stays: {final.LogFileName}" if final else f"{w.session} is not open")
    return 0


def file_path(name: str, folder: str, drives: dict[str, str]) -> str:
    r"""A file as the kernel names it (\Device\HarddiskVolume5\dir\file), as a line shows it: relative to the program's
    folder (named the kernel's way too) when it is under it, else with the device turned into its drive letter, and
    unchanged when no drive has that device."""
    if folder and name.lower().startswith(folder.lower() + "\\"):
        return name[len(folder) + 1:]
    for device, letter in drives.items():
        if name.lower().startswith(device.lower() + "\\"):
            return letter + name[len(device):]
    return name


def file_lines(events, folders: dict[int, str], drives: dict[str, str]) -> list[str]:
    """One line for each file a watched process asked to open, in the trace's order: "<thread> <path>", threads
    numbered by their first line. events: a trace of Microsoft-Windows-Kernel-File as tracerpt decodes it, every
    program's; folders: the watched processes' folders by process id; no other process's event gives a line."""
    threads: dict[tuple[str, str], int] = {}
    lines = []
    for event in events:
        where = re.search(r'<Execution ProcessID="(\d+)" ThreadID="(\d+)"', event)
        name = re.search(r'<Data Name="FileName">([^<]*)</Data>', event)
        if (where and name and int(where.group(1)) in folders and 'Provider Name="Microsoft-Windows-Kernel-File"' in event
                and watch_d3d.field(event, "EventID") == "12"):
            number = threads.setdefault(where.groups(), len(threads) + 1)
            lines.append(f"{number} {file_path(html.unescape(name.group(1)), folders[int(where.group(1))], drives)}")
    return lines


def guarded(action, *args):
    """A step of the record of file opens. That record must never endanger the Direct3D one: an error is logged and the
    monitor carries on."""
    try:
        return action(*args)
    except (Exception, SystemExit) as error:  # SystemExit: a tool of Windows that failed (watch_d3d.tool)
        say(f"the record of file opens: {action.__name__} failed, carrying on: {type(error).__name__}: {error}")
        return None


def start_files(w: Watch, handle: int, pid: int) -> Path:
    """Opens the system-wide session of file opens; returns its raw trace, named after the Direct3D trace."""
    raw = Path(etw.query_session(w.session).LogFileName[:-4] + "_files.etl")
    session = etw.start_session(w.files_session, str(raw), FILES_MAX_MB)
    try:
        etw.enable_provider(session, etw.KERNEL_FILE, etw.FILE_CREATE)
    except Exception:
        etw.stop_session(w.files_session)
        raise
    say(f"file opens are recorded from {etw.process_age(handle):.3f} s after pid {pid} started "
        f"({w.files_session}: every program's, until the lines are written)")
    return raw


def stop_files(w: Watch, why: str) -> None:
    final = etw.stop_session(w.files_session)
    say(f"the recording of file opens ended {why}"
        + (f"; events lost {final.p.EventsLost}" if final else f"; its session had closed itself at {FILES_MAX_MB} MB"))


def write_files(w: Watch, raw: Path, folders: dict[int, str]) -> None:
    """<role>_files.txt and its dated copy from the raw trace, which is deleted with its decoded form whatever happens."""
    events = watch_d3d.events(raw)
    try:
        lines = file_lines(events, folders, etw.drive_devices())
    finally:
        events.close()  # lets go of the decoded file
        raw.unlink(missing_ok=True)
        raw.with_suffix(".xml").unlink(missing_ok=True)
    listed = w.out / f"{w.role}_files.txt"
    for path in (listed, raw.with_suffix(".txt")):
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    say(f"{listed}: {len(lines):,} files opened by pid {', '.join(map(str, folders))}; the copy that stays: {raw.with_suffix('.txt').name}; "
        "the raw trace and its decoded form are deleted")


def watch_run(w: Watch, files_seconds: int) -> tuple[dict[int, int], dict[int, str], Path | None]:
    """One run of the program: waits for a process named w.exe, then until every such process has ended and none has
    appeared for QUIET seconds. Returns the processes' bitness and folders by process id, and the raw trace of file
    opens when one was recorded. While it waits for the first process it arms again if the session is gone, and takes
    events in the trace for a run it did not see: one over between two looks, or made before this monitor waited."""
    handles: dict[int, int] = {}
    ended: list[int] = []  # the handles of processes that have ended, kept while file opens are recorded
    bits: dict[int, int] = {}
    folders: dict[int, str] = {}
    raw, files_end, last_alive = None, 0.0, 0.0  # files_end: when the file-open session is to stop; 0 while none is open
    unseen = False
    try:
        while handles or not (bits or unseen) or time.monotonic() - last_alive < QUIET:
            for pid in etw.find_processes(w.exe):
                handle = None if pid in handles else etw.open_process(pid, w.exe)
                if handle:
                    handles[pid], bits[pid], folders[pid] = handle, etw.process_bits(handle), os.path.dirname(etw.image_path(handle))
                    say(f"pid {pid} of {w.exe} is running, {bits[pid]}-bit")
                    if files_seconds and raw is None:
                        raw = guarded(start_files, w, handle, pid)
                        files_end = time.monotonic() + files_seconds if raw else 0.0
            if files_end and time.monotonic() >= files_end:
                guarded(stop_files, w, f"after {files_seconds} s")
                files_end = 0.0
            if not handles:
                if not (bits or unseen):
                    props = etw.query_session(w.session)
                    if not props:
                        arm(w)
                    elif props.p.BuffersWritten > 1:  # an armed session that has recorded nothing has written its first buffer only
                        unseen, last_alive = True, time.monotonic()
                        say(f"the trace holds events of a run of {w.exe} that this monitor did not see")
                time.sleep(POLL)
            for pid, handle in list(handles.items()):
                if etw.wait_exit(handle, int(POLL * 1000)):
                    ended.append(handles.pop(pid))
                    say(f"pid {pid} ended")
                last_alive = time.monotonic()
            while ended and not files_end:  # Windows gives a process id to no other process while a handle to its last owner is open,
                etw.close_handle(ended.pop())  # and the list of files is kept by process id
    finally:
        if files_end:
            guarded(stop_files, w, "with the program")
        for handle in (*handles.values(), *ended):
            etw.close_handle(handle)
    return bits, folders, raw


def monitor(w: Watch, files_seconds: int) -> int:
    global LOG
    if etw.claim(w.monitor) is None:  # held until this process ends, however it ends
        say(f"a monitor for {w.exe} is already running; this one ends")
        return 1
    w.out.mkdir(parents=True, exist_ok=True)
    LOG = w.out / "monitor.log"
    say(f"monitor for {w.exe} started, pid {os.getpid()}")
    try:
        arm(w)  # a failure here ends the monitor: without the session it has nothing to wait for
        try:
            recover(w)  # what a monitor that was ended while it decoded, or a restart of the machine, left without a record
        except (Exception, SystemExit):
            say("the traces without a record were not all collected; carrying on:\n" + traceback.format_exc())
        while True:
            try:
                # What a monitor that was ended, or the run before this one when it failed, has left of every program's file opens.
                # Guarded: a decoded form that a tracerpt without its monitor was still writing could not be deleted, which ended the next monitor.
                guarded(drop_files, w)
                bits, folders, raw = watch_run(w, files_seconds)
                try:
                    collect(w, known=bits)
                finally:  # also when the Direct3D record fails: the raw trace of file opens must not stay
                    if raw:
                        guarded(write_files, w, raw, folders)
            except (Exception, SystemExit):
                say("this run was not collected; carrying on:\n" + traceback.format_exc())
                time.sleep(QUIET)  # a failure that repeats must not spin
    except BaseException:
        say(f"monitor ended: {traceback.format_exc().strip().splitlines()[-1]}. A session that is open stays open: `collect` and `disarm` still work.")
        raise


def quoted(text: str) -> str:
    """A PowerShell string literal."""
    return "'" + text.replace("'", "''") + "'"


def task(w: Watch) -> str:
    """The scheduled task as the Task Scheduler holds it; nothing when there is none."""
    return watch_d3d.powershell(f"""
$t = Get-ScheduledTask -TaskName {quoted(w.task)} -ErrorAction SilentlyContinue
if ($t) {{
  "  task      $($t.TaskPath)$($t.TaskName) ($($t.State))"
  "  runs      $($t.Actions[0].Execute) $($t.Actions[0].Arguments)"
  "  in        $($t.Actions[0].WorkingDirectory)"
  "  trigger   $($t.Triggers[0].CimClass.CimClassName) for $($t.Triggers[0].UserId)"
  "  as        $($t.Principal.UserId), logon type $($t.Principal.LogonType), run level $($t.Principal.RunLevel)"
  "  settings  execution time limit $($t.Settings.ExecutionTimeLimit); start on batteries: $(-not $t.Settings.DisallowStartIfOnBatteries); " +
    "stop when going on batteries: $($t.Settings.StopIfGoingOnBatteries); a second instance: $($t.Settings.MultipleInstances)"
}}
exit 0  # no such task is an answer, not a failure""").rstrip()


def install(w: Watch, files_seconds: int) -> int:
    if task(w):
        say(f"the scheduled task {w.task} exists already and is left as it is:\n{task(w)}")
        return 1
    arguments = subprocess.list2cmdline([str(Path(__file__).resolve()), "wait", *w.options, "--files-seconds", str(files_seconds)])
    watch_d3d.powershell(f"""
$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute {quoted(str(PYTHONW))} -Argument {quoted(arguments)} -WorkingDirectory {quoted(str(watch_d3d.ROOT))}
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$description = {quoted(f"Watches {w.exe} from outside with Windows event tracing (scripts/lift/watch_game.py). To remove: {w.command('uninstall')}")}
Register-ScheduledTask -TaskName {quoted(w.task)} -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description | Out-Null
""")
    say(f"created the scheduled task (as the Task Scheduler now holds it):\n{task(w)}\n"
        f"It starts the monitor at the next logon; to start it now: Start-ScheduledTask -TaskName {w.task}\n"
        "It runs that file as it is at each logon, with administrator rights and without asking: whoever can change the file gets them.\n"
        f"To remove it: {w.command('uninstall')}   (or: Unregister-ScheduledTask -TaskName {w.task} -Confirm:$false)")
    return 0


def uninstall(w: Watch) -> int:
    if not task(w):
        say(f"there is no scheduled task {w.task}")
        return 1
    watch_d3d.powershell(f"$ErrorActionPreference = 'Stop'; Stop-ScheduledTask -TaskName {quoted(w.task)}; "
                         f"Unregister-ScheduledTask -TaskName {quoted(w.task)} -Confirm:$false")
    left = task(w)
    say(f"the scheduled task {w.task} is STILL THERE:\n{left}" if left else f"the scheduled task {w.task} is removed")
    ended = time.monotonic() + 5
    while etw.claimed(w.monitor) and time.monotonic() < ended:
        time.sleep(0.2)
    if etw.claimed(w.monitor):
        say(f"a monitor for {w.exe} is still running: it was not started by the task; end its process")
    else:
        say(f"no monitor for {w.exe} is running")
        drop_files(w)
    if etw.query_session(w.session):
        say(f"{w.session} is still open and goes on recording {w.exe}; to stop it: {w.command('disarm')}")
    return 1 if left else 0


def selftest() -> int:
    """The whole flow on port/lifted_live/test_d3d_probe.c, built 32-bit and 64-bit under one file name, with the
    selftest's own session names and folder (generated/lifted/d3d_watch_selftest/, emptied first). Every verb is run
    as a command, the monitor under pythonw. Reports each step; 1 when one failed. Leaves no session and no monitor."""
    w = Watch(PROBE, selftest=True)
    script = str(Path(__file__).resolve())
    failed: list[str] = []

    def check(what: str, ok, detail: str = "") -> None:
        say(f"{'ok    ' if ok else 'FAILED'}  {what}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            failed.append(what)

    def verb(*args: str) -> tuple[int, str]:
        run = subprocess.run([str(PYTHON), script, *args, *w.options], capture_output=True, text=True, errors="replace")
        say("\n".join(f"          | {line}" for line in (run.stdout + run.stderr).splitlines()))
        return run.returncode, run.stdout + run.stderr

    def probe(arch: str, *args: str) -> subprocess.Popen:
        return subprocess.Popen([str(w.out / arch / PROBE), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def ran(proc: subprocess.Popen) -> bool:
        out = proc.communicate(timeout=120)[0]
        return proc.returncode == 0 and out.rstrip().endswith("done")

    def until(condition, seconds: float) -> bool:
        ended = time.monotonic() + seconds
        while not condition() and time.monotonic() < ended:
            time.sleep(0.2)
        return bool(condition())

    def trace() -> str:
        props = etw.query_session(w.session)
        return props.LogFileName if props else ""

    def text(path: Path) -> str:
        return path.read_text(encoding="utf-8") if path.exists() else ""

    if etw.claimed(w.monitor):
        say("a selftest monitor is running: end it first")
        return 1
    for name, _ in etw.list_sessions(w.session):  # what a selftest that was interrupted left
        etw.stop_session(name)
    shutil.rmtree(w.out, ignore_errors=True)
    for arch in ("x64", "x86"):
        (w.out / arch).mkdir(parents=True)
        try:
            toolchain.run_tool(["cl", *toolchain.RUNTIME_CFLAGS, f"/Fo{w.out / arch / 'test_d3d_probe.obj'}", f"/Fe{w.out / arch / PROBE}",
                                str(watch_d3d.ROOT / "port" / "lifted_live" / "test_d3d_probe.c"),
                                "/link", "d3d11.lib", "dxgi.lib", "dxguid.lib", "user32.lib"], cwd=w.out / arch, arch=arch)
        except toolchain.BuildError as error:
            say(f"FAILED  build {arch}: {str(error)[-2000:]}")
            return 1
    say(f"ok      built {PROBE} as x64 and as x86 under {w.out}")
    record, listed, log = w.out / f"{w.role}.txt", w.out / f"{w.role}_files.txt", w.out / "monitor.log"
    child = None
    try:
        code, said = verb("arm")
        first = trace()
        check("arm opens the session", code == 0 and first and "armed" in said, said)
        if not first:
            say("selftest: without a session nothing else can be checked")
            return 1
        code, said = verb("arm")
        check("a second arm leaves the open session and its file", code == 0 and "already open" in said and trace() == first)
        code, said = verb("status")
        check("status: open, nothing running, no monitor", code == 0 and f"{w.session}: open" in said and "not running" in said, said)

        held = probe("x64", "--start-ms", "3000")
        code, said = verb("collect")
        check("collect refuses while the program runs, and changes nothing", code == 1 and "still running" in said and trace() == first)
        check("the 64-bit probe ran", ran(held))
        code, said = verb("collect")
        record64 = text(record)
        check("collect writes the 64-bit probe's record", code == 0 and record64 and "64-bit" in said, said)
        check("its dated copy is beside the trace, the trace is kept, the decoded form is deleted",
              text(Path(first).with_suffix(".txt")) == record64 and Path(first).exists() and not Path(first).with_suffix(".xml").exists())
        second = trace()
        check("collect armed again with a new trace file", second and second != first)

        check("the 32-bit probe ran", ran(probe("x86")))
        code, said = verb("collect")
        record32 = text(record)
        check("collect writes the 32-bit probe's record", code == 0 and record32 and "32-bit" in said, said)
        lines = record64.splitlines()
        check(f"the 32-bit and the 64-bit record are identical ({len(lines)} lines, {len({line.split()[0] for line in lines})} threads)",
              record32 == record64 and len(lines) > 40)
        for role, same in (("original", record64), ("lifted", record32)):
            (w.out / "compare").mkdir(exist_ok=True)
            (w.out / "compare" / f"{role}.txt").write_text(same, encoding="utf-8", newline="\n")
        check("compare_d3d.py, run on the two as original.txt and lifted.txt, finds them the same", compare(w.out / "compare") == 0)

        adopted = trace()
        record.unlink()
        check("the 64-bit probe ran before any monitor", ran(probe("x64")))
        child = subprocess.Popen([str(PYTHONW), script, "wait", *w.options, "--files-seconds", "30"])
        check("the monitor starts under pythonw and takes over the open session",
              until(lambda: "already open" in text(log), 20) and etw.claimed(w.monitor) and trace() == adopted, text(log))
        code, said = verb("wait")
        check("a second monitor says so and ends", code == 1 and "already running" in said)
        code, said = verb("status")
        check("status: the monitor is running", "monitor (`wait`): running" in said)
        check("the monitor collects the run it did not see",
              until(lambda: text(log).count("events lost:") == 1, 60) and text(record) == record64, text(log))
        third = trace()
        check("and arms again with a new trace file", third and third != adopted)

        data = w.out / "x86" / "data"
        data.mkdir()
        for name in ("a.txt", "b.txt"):
            (data / name).write_text(name)
        outside = Path(os.environ["SystemRoot"]) / "win.ini"
        opened = [data / "b.txt", data / "a.txt", data / "missing.txt", outside]
        record.unlink(missing_ok=True)
        check("the 32-bit probe ran under the monitor",
              ran(probe("x86", "--start-ms", "1500", *(arg for path in opened for arg in ("--open", str(path))))))
        check("the monitor writes the record and the list of files by itself", until(lambda: text(log).count("are deleted") == 1, 120), text(log))
        check("the monitor's record is identical to the others", text(record) == record64)
        lines = [line.split(" ", 1) for line in text(listed).splitlines()]
        expected = ["data\\b.txt", "data\\a.txt", "data\\missing.txt", str(outside).lower()]
        mine = [(thread, path) for thread, path in lines if path in expected[:3] or path.lower() == expected[3]]
        check(f"the list of files ({len(lines)} lines) holds the probe's four opens in order, on one thread, "
              "relative to its folder or with a drive letter",
              [path.lower() for _, path in mine] == [path.lower() for path in expected] and len({thread for thread, _ in mine}) == 1, str(mine))
        raw_left = lambda: [p.name for p in w.out.glob("*_files.*") if p.suffix != ".txt"]  # noqa: E731
        check("the raw trace of file opens and its decoded form are deleted and its session is closed",
              not raw_left() and not etw.query_session(w.files_session), str(raw_left()))
        check("the monitor armed again with a new trace file", trace() and trace() != third)

        record.unlink(missing_ok=True)
        held = probe("x64", "--start-ms", "8000")
        recording = until(lambda: etw.query_session(w.files_session), 10)
        child.terminate()  # TerminateProcess: none of the monitor's code runs
        child.wait(30)
        check("the monitor is ended while the program runs; both sessions stay open",
              recording and until(lambda: not etw.claimed(w.monitor), 10) and trace() and etw.query_session(w.files_session))
        say("\n".join(f"          | {line}" for line in text(log).splitlines()))
        code, said = verb("status")
        check("status tells of the file-open session that is left recording and of its raw trace",
              "open and recording" in said and "_files.etl" in said)
        code, said = verb("collect")
        check("collect refuses while the program runs, but stops the file-open session the monitor left and deletes its raw trace",
              code == 1 and "still running" in said and trace() and not etw.query_session(w.files_session) and not raw_left(), str(raw_left()))
        check("the 64-bit probe ran on with no monitor", ran(held))
        code, said = verb("collect", "--no-rearm")
        check("a later collect still works, and --no-rearm leaves the session closed", code == 0 and text(record) == record64 and not trace(), said)

        code, said = verb("arm")
        last = trace()
        code, said = verb("disarm")
        check("disarm stops the session and leaves its trace file", code == 0 and last and not trace() and Path(last).exists() and last in said)

        code, said = verb("arm")
        cut = trace()
        check("the 64-bit probe ran, and its session is stopped with no record written, as a monitor ended while decoding leaves it",
              ran(probe("x64")) and etw.stop_session(w.session) is not None and not trace())
        broken = w.out / f"{w.role}_19990101_000000.etl"  # the first trace cut to 60% of its length: tracerpt finds no event in such a file
        whole = Path(first).read_bytes()
        broken.write_bytes(whole[:len(whole) * 6 // 10])
        record.unlink(missing_ok=True)
        code, said = verb("status")
        check("status lists the traces without a record", all(Path(name).name in said for name in (cut, last, broken)), said)
        code, said = verb("collect")
        check("collect writes the record of the trace that was left without one, with no session open",
              code == 0 and text(record) == record64 and text(Path(cut).with_suffix(".txt")) == record64 and not trace(), said)
        check("it deletes the trace that holds nothing of the program", not Path(last).exists())
        check("it leaves the trace that cannot be decoded, with a file beside it that says why",
              broken.exists() and text(broken.with_suffix(".err")).strip() and not broken.with_suffix(".xml").exists(), text(broken.with_suffix(".err")))
        code, said = verb("collect")
        check("a second collect has nothing to collect and does not try that trace again", code == 1 and broken.name not in said, said)
    finally:
        if child and child.poll() is None:
            child.kill()
        for name, _ in etw.list_sessions(w.session):
            etw.stop_session(name)
    check("no selftest session is open", not etw.list_sessions("aeterna_selftest"), str(etw.list_sessions("aeterna_selftest")))
    check("no selftest monitor is running", not etw.claimed(w.monitor))
    say(f"selftest: {len(failed)} of its checks failed" + "".join(f"\n  {what}" for what in failed) if failed else "selftest: every check passed")
    return 1 if failed else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("verb", choices=("arm", "status", "collect", "disarm", "wait", "install", "uninstall", "selftest"))
    ap.add_argument("--exe", default="Rome2.exe", help="the watched program's file name (default Rome2.exe; live.exe is the lifted runner)")
    ap.add_argument("--pid", type=int, help="collect: write this process's record instead of that of the one with the most events")
    ap.add_argument("--no-rearm", action="store_true", help="collect: leave the session closed afterwards")
    ap.add_argument("--files-seconds", type=int, default=600, help="wait, install: how long a run's file opens are recorded (0: not at all)")
    ap.add_argument("--selftest", action="store_true", help="the selftest's session names, folder and task name instead of the real ones")
    args = ap.parse_args(argv)
    if args.verb == "selftest":
        return selftest()
    if not re.fullmatch(r'[^\\/:*?"<>|;]+\.exe', args.exe, re.I):
        ap.error("--exe is a file name ending in .exe, with no folder and no wildcard: Windows accepts a name that matches nothing and records nothing")
    w = Watch(args.exe, args.selftest)
    verbs = {"arm": lambda: arm_verb(w), "status": lambda: status(w), "collect": lambda: collect(w, args.pid, not args.no_rearm),
             "disarm": lambda: disarm(w), "wait": lambda: monitor(w, args.files_seconds), "install": lambda: install(w, args.files_seconds),
             "uninstall": lambda: uninstall(w)}
    try:
        if args.verb in ("arm", "collect", "disarm") and not etw.claimed(w.monitor):
            guarded(drop_files, w)  # with no monitor left, nobody else ends a recording of every program's file opens
        return verbs[args.verb]()
    except etw.TraceError as error:
        say(f"{error}" + ("\nthis needs an elevated prompt" if error.code == etw.ERROR_ACCESS_DENIED else ""))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
