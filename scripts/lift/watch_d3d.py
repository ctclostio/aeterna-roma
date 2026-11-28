"""Watches a program's DXGI and Direct3D 11 use from outside, with Windows' own event tracing.

    python scripts/lift/watch_d3d.py start                              in an elevated prompt
    ... run the program and use it: the original game, or live.exe ...
    python scripts/lift/watch_d3d.py stop                               ends the trace, lists the programs seen
    python scripts/lift/watch_d3d.py write <record> --process <name>    (or --pid N)

dxgi.dll and d3d11.dll report what they are asked to do to Event Tracing for Windows (the providers
Microsoft-Windows-DXGI and Microsoft-Windows-Direct3D11) whenever a trace session asks for it. `start` opens such
a session with logman and `stop` closes it; tracerpt decodes the file. Both are parts of Windows. Nothing is
loaded into the watched program, none of its files are touched and it is not started any differently. What does
change inside it is what Windows changes for any trace session: the event writing of the program's own dxgi.dll
and d3d11.dll is switched on. Measured with stand-in programs on Windows 11 build 26300: a DXGI call that took
0.02 microseconds took 0.3 (64-bit) to 0.6 (32-bit) while watched, and a program that registers a provider under
DXGI's id itself is told by Windows that a session has switched it on, so a program that looks can tell that it
is watched. Whether the original game looks is not checked.

The session sees every program on the machine that uses Direct3D while it is open; a record is written for one of
them and the trace file stays on this machine (generated/lifted/d3d_watch/).
scripts/lift/watch_game.py watches one program by its name without a trace being started by hand first, and writes
its records with this module.

What the two providers report, as seen on Windows 11 build 26300 with an x64 program:

    DXGI          CreateDXGIFactory and CreateDXGIFactory1, and the methods of IDXGIFactory, IDXGIAdapter,
                  IDXGIOutput and IDXGISwapChain, each with its arguments and its result; the factory, adapter,
                  output and swap chain objects created. Not the methods DXGI 1.1 added (EnumAdapters1,
                  IsCurrent): of those only the adapters they create show.
    Direct3D 11   every device (creation flags, feature level), context, buffer and texture created, the last
                  two with their whole description. Not draws, state, shaders, views or Map.

So this compares what a run asks of DXGI and which resources it creates, not what it draws. For the calls the
providers leave out, the lifted game's own record is the bridge's ROME2_D3D11_TRACE; the original game has none.

The record is in the form scripts/lift/compare_d3d.py compares, one line per call or object in the order of each
thread, threads numbered by their first line:

    <thread> IDXGISwapChain::Present(SyncInterval=1 dwFlags=0) = 0
    <thread> create Texture2D(Usage=0 Width=1920 Height=1080 ...)

Left out of a line, because it belongs to one run or one machine and not to what the program asked: pointers
(`*`, or 0 for a null one), handles and versions (`h`), and blocks of bytes (their length only, but a swap chain
description is decoded and its window handle dropped). Calls DXGI makes itself while it answers a call are left
out too.

A 32-bit and a 64-bit program making the same calls give identical records, which is what comparing the 32-bit
original with the 64-bit lifted run needs. What was compared, on Windows 11 build 26300: one source,
port/lifted_live/test_d3d_probe.c, built as a 32-bit and as a 64-bit program and watched
(`python scripts/lift/watch_game.py selftest` repeats it). The two sets of DLLs wrote the same events in the same
order, with these differences, each of which is taken out here:

  - Bitness. A record is written for a 32-bit or a 64-bit process, and which it is is read from the process's own
    events, by two signs. A field the manifests type as a pointer that holds 2^32 or more makes the process 64-bit:
    none did in the 32-bit program's events, nearly all did in the 64-bit program's. (The lifted live.exe, a 64-bit
    process whose guest pointers are below 2^32, is told correctly: its DXGI objects are above.) An event whose data
    is shorter or longer than its manifest says (ODD) makes a process without such a pointer 32-bit: the 32-bit
    dxgi.dll writes the start events of nine calls so, among them CreateDXGIFactory, CreateDXGIFactory1,
    CreateSwapChain and MakeWindowAssociation, in each of 22 runs of the 32-bit probe, and no event of a 64-bit
    process (over 70,000 of the probe and of other programs) is so. Small pointers alone do not make a process 32-bit: the
    same probe linked /LARGEADDRESSAWARE:NO is a 64-bit program with every pointer below 2^32, and read as a 32-bit
    one it gave five wrong lines. A process with neither sign (one watched from the middle of its run, say) is of
    unknown bitness: its record is read as a 64-bit program's and the tools say so. By what was seen that reading
    can be wrong in one line only, the ppAdapter of CreateSoftwareAdapter, when the process is a 32-bit one after
    all: its CreateSwapChain or MakeWindowAssociation would have told. A caller that knows the bitness passes it to
    record().
  - IDXGIFactory::CreateSwapChain. Both builds log 72 bytes for pDesc. A 32-bit program's DXGI_SWAP_CHAIN_DESC is
    the first 60 (the last 12 are whatever follows it in the caller's memory), so the layout follows the bitness.
    IDXGISwapChain::GetDesc logs its pDesc before the call has filled it: only its length is shown, as before.
  - IDXGIFactory::MakeWindowAssociation and IDXGIFactory::CreateSoftwareAdapter. Where the manifest declares one
    8-byte field (hWnd, hModule) the 32-bit dxgi.dll writes 4 bytes of it and then the 4 bytes of the next field
    (Flags, ppAdapter), so the decoder gives one field holding next << 32 | value. It then finds no Flags at all,
    and gives ppAdapter a value that is not the program's: 0 in nine runs, four of which passed 0x12345678, and
    not 0 in three which passed null. For a 32-bit process the 8-byte field is split back into the two (MERGED).
  - IDXGISwapChain::GetFullscreenState called with no ppTarget: the 64-bit DLL logs a value that is not zero, the
    32-bit one logs 0. The field is left out of the line (UNALIKE).

Not compared: the DXGI methods the probe does not call (it calls the ones a line of its record names), programs
with more than two threads, and the original game, which has never been watched.
"""
from __future__ import annotations

import argparse
import base64
import collections
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "generated" / "lifted" / "d3d_watch"
SESSION = "aeterna_d3d_watch"
PROVIDERS = ("Microsoft-Windows-DXGI", "Microsoft-Windows-Direct3D11")
PROCESSES = "Microsoft-Windows-Kernel-Process"  # keyword 0x10: a process starting, with its image name
OBJECTS = {"Factory", "Adapter", "Output", "SwapChain", "Device", "Context", "CommandList", "Buffer", "Texture1D", "Texture2D", "Texture3D"}
# call -> (an 8-byte field, the field after it): the 32-bit dxgi.dll writes the two as 4 bytes each, which decode as one.
MERGED = {"IDXGIFactory_MakeWindowAssociation": ("hWnd", "Flags"), "IDXGIFactory_CreateSoftwareAdapter": ("hModule", "ppAdapter")}
# (call, field) the 32-bit and the 64-bit dxgi.dll report differently for the same call: left out of the line.
UNALIKE = {("IDXGISwapChain_GetFullscreenState", "ppTarget")}
# tracerpt's mark on a field of an event whose data is shorter (win:ErrorLessData) or longer (win:ErrorMoreData) than its manifest says.
ODD = 'Type="win:Error'
EVENT = re.compile(r"<Event .*?</Event>", re.S)
DATA = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
SCHEMA_SCRIPT = r"""
foreach ($n in 'PROVIDERS') {
  $p = Get-WinEvent -ListProvider $n
  $t = @{}
  $p.Tasks | ForEach-Object { $t[$_.Value] = $_.Name }
  $p.Events | ForEach-Object {
    $f = ([regex]::Matches($_.Template, 'name="(\w+)" inType="win:(\w+)"') | ForEach-Object { $_.Groups[1].Value + ':' + $_.Groups[2].Value }) -join ' '
    "$n`t$($_.Id)`t$($_.Version)`t$($t[$_.Task.Value])`t$f"
  }
}
"""


def tool(*command: str) -> str:
    """Runs a part of Windows and returns what it printed. No console window is opened for it (a caller may have none)."""
    proc = subprocess.run(command, capture_output=True, text=True, errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
    if proc.returncode != 0:
        raise SystemExit(f"{' '.join(command[:3])} ...: {(proc.stdout + proc.stderr).strip()[-600:]}")
    return proc.stdout


def powershell(script: str) -> str:
    """Runs a PowerShell script. An error that ends it comes as its plain message, and no progress records are written
    (PowerShell writes both as XML when its output is not a console)."""
    script = "$ProgressPreference = 'SilentlyContinue'\ntrap { [Console]::Error.WriteLine(\"$_\"); exit 1 }\n" + script
    return tool("powershell", "-NoProfile", "-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode())


def schema() -> dict[tuple[str, str, str], tuple[str, dict[str, str]]]:
    """(provider, event id, version) -> (task name, field -> type), from the providers' manifests on this machine."""
    text = powershell(SCHEMA_SCRIPT.replace("PROVIDERS", "','".join(PROVIDERS)))
    out = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            out[tuple(parts[:3])] = (parts[3], dict(f.split(":") for f in parts[4].split()))
    if not out:
        raise SystemExit("the DXGI and Direct3D 11 event providers list no events on this machine")
    return out


def swap_chain(data: bytes, bits: int) -> str:
    """DXGI_SWAP_CHAIN_DESC as a 32-bit (60 bytes) or a 64-bit (72 bytes) program lays it out, without OutputWindow.
    The length does not tell which: 72 bytes are logged for both."""
    tail = 48 if bits == 32 else 56  # Windowed, SwapEffect and Flags follow OutputWindow: 4 bytes at 44, or 8 at 48
    if len(data) not in (60, 72) or len(data) < tail + 12:
        return f"{len(data)} bytes"
    names = ("Width", "Height", "RefreshNumerator", "RefreshDenominator", "Format", "ScanlineOrdering", "Scaling", "SampleCount",
             "SampleQuality", "BufferUsage", "BufferCount")
    tail = struct.unpack_from("<3I", data, tail)
    values = dict(zip(names, struct.unpack_from("<11I", data)), Windowed=tail[0], SwapEffect=tail[1], Flags=tail[2])
    return "{" + " ".join(f"{k}={v}" for k, v in values.items()) + "}"


def shown(task: str, name: str, kind: str, value: str, bits: int) -> str:
    value = value.strip()
    if kind == "Pointer":
        return "0" if int(value, 16) == 0 else "*"
    if kind == "Binary":
        data = bytes.fromhex(value[2:] if value.lower().startswith("0x") else value)
        return swap_chain(data, bits) if task == "IDXGIFactory_CreateSwapChain" and name == "pDesc" else f"{len(data)} bytes"
    if kind in ("UInt32", "Int32", "UInt16", "UInt8", "Boolean", "GUID", "UnicodeString", "AnsiString"):
        return "h" if value.lower().startswith("0x") or "Handle" in name else value  # kernel handles are numbers too
    return "h"  # HexInt32, HexInt64, UInt64: handles, driver versions, times


def events(etl: Path):
    """The trace's events as tracerpt decodes them, one XML element at a time (a long trace is gigabytes of XML).
    The decoded file stays beside the trace and is read again while it is not the older of the two. tracerpt writes
    it under another name first: a decoding that was killed at 22 MB of 56 left a file that the next call read as
    the whole trace, 5,701 record lines of 18,073."""
    xml = etl.with_suffix(".xml")
    if not xml.exists() or xml.stat().st_mtime < etl.stat().st_mtime:
        part = etl.with_suffix(".part.xml")
        try:
            tool("tracerpt", str(etl), "-o", str(part), "-of", "XML", "-lr", "-y")
            part.replace(xml)
        finally:
            part.unlink(missing_ok=True)
    with open(xml, "rb") as raw:
        encoding = "utf-16" if raw.read(2) in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    with open(xml, encoding=encoding, errors="replace") as text:
        rest = ""
        while chunk := text.read(1 << 24):
            rest += chunk
            end = 0
            for found in EVENT.finditer(rest):
                yield found.group(0)
                end = found.end()
            rest = rest[end:]


def field(event: str, tag: str) -> str:
    found = re.search(rf"<{tag}>([^<]*)</{tag}>", event)
    return found.group(1) if found else ""


def processes(etl: Path, types: dict | None = None) -> tuple[dict[str, dict], dict[str, str], int]:
    """What the trace holds of each process, by process id: {"events": how many events of the two providers, "first"
    and "last": the times of the first and the last of them, "bits": 32, 64 or 0}; the image names of the processes
    started during the trace; and how many events the session lost.

    Events are counted by provider: the trace's own header events carry the id of whoever opened the session.
    bits is decided from the process's events when `types` (schema()) is given: 64 once a field the manifests type
    as a pointer holds 2^32 or more; 32 when none does and an event is ODD; else 0, not known (see the module
    docstring). The fields of MERGED do not count: a 32-bit process's events do not hold them as the manifests say.
    Ends with a message when the decoded trace holds no event at all: tracerpt gave that, with exit code 0, for a
    trace cut to 60% of its length, and a record written from it would be an empty one.
    """
    seen: dict[str, dict] = {}
    names: dict[str, str] = {}
    lost = 0
    event = None
    for event in events(etl):
        if not lost and "EventsLost" in event:
            lost = int(re.search(r'<Data Name="EventsLost">\s*(\d+)', event).group(1))
        provider = re.search(r'<Provider Name="([^"]+)"', event)
        if provider and provider.group(1) == PROCESSES and field(event, "EventID") == "1":
            data = dict(DATA.findall(event))
            if "ImageName" in data and "ProcessID" in data:
                names[data["ProcessID"].strip()] = data["ImageName"].replace("\\", "/").rsplit("/", 1)[-1]
        elif provider and provider.group(1) in PROVIDERS:
            when = re.search(r'<TimeCreated SystemTime="([^"]*)"', event).group(1)
            mine = seen.setdefault(re.search(r'<Execution ProcessID="(\d+)"', event).group(1), {"events": 0, "bits": 0, "first": when})
            mine["events"] += 1
            mine["last"] = when
            if types and mine["bits"] != 64:
                task, kinds = types.get((provider.group(1), field(event, "EventID"), field(event, "Version")), ("", {}))
                if any(int(value, 16) >> 32 for name, value in DATA.findall(event)
                       if kinds.get(name) == "Pointer" and name not in MERGED.get(task, ())):
                    mine["bits"] = 64
                elif ODD in event:
                    mine["bits"] = 32
    if event is None:  # a trace that recorded nothing still holds its own header events
        raise SystemExit(f"{etl}: tracerpt found no event in it, not even the trace's own header: it is not a whole trace (it was cut "
                         "short, or its session has not stopped). tracerpt reports success for such a file.")
    return seen, names, lost


def record(etl: Path, pid: str, types: dict, bits: int) -> tuple[list[str], int]:
    """The record lines of one process, and how many of its events have no description in the manifests.
    bits: 32 for a 32-bit process, as processes() decides it or as the caller knows it; 0 (not known) is read as 64."""
    threads: dict[str, int] = {}
    open_calls: dict[str, list[tuple[str, str] | None]] = collections.defaultdict(list)  # thread -> calls begun
    lines, unknown = [], 0
    mine = f'ProcessID="{pid}"'
    for event in events(etl):
        if mine not in event:
            continue
        provider = re.search(r'<Provider Name="([^"]+)"', event)
        where = re.search(r'<Execution ProcessID="(\d+)" ThreadID="(\d+)"', event)
        if not provider or provider.group(1) not in PROVIDERS or not where or where.group(1) != pid:
            continue
        known = types.get((provider.group(1), field(event, "EventID"), field(event, "Version")))
        if known is None:
            unknown += 1
            continue
        task, kinds = known
        opcode, tid = field(event, "Opcode"), where.group(2)
        data = DATA.findall(event)
        if bits == 32 and task in MERGED and opcode == "1":
            low, high = MERGED[task]
            merged = int(dict(data)[low])  # high << 32 | low: see the module docstring
            data = [pair for pair in data if pair[0] not in (low, high)] + [
                (low, str(merged & 0xFFFFFFFF)), (high, f"{merged >> 32:#x}" if kinds[high] == "Pointer" else str(merged >> 32))]
        args = " ".join(f"{name}={shown(task, name, kinds.get(name, ''), value, bits)}" for name, value in data
                        if name != "pThis" and (task, name) not in UNALIKE)
        number = lambda: threads.setdefault(tid, len(threads) + 1)  # noqa: E731
        if "_" in task or task.startswith("CreateDXGIFactory"):  # a call: one event when it begins, one when it returns
            stack = open_calls[tid]
            if opcode == "1":
                stack.append((task.replace("_", "::", 1), args) if not stack else None)  # None: DXGI's own call inside one
            elif opcode == "2" and stack:
                begun = stack.pop()
                if begun is not None:
                    result = dict(data).get("m_Ret", "").strip()
                    lines.append(f"{number()} {begun[0]}({begun[1]})" + (f" = {int(result):x}" if result.isdigit() else ""))
        elif task in OBJECTS and opcode == "1":  # also the ones a call creates, as a swap chain's back buffer
            lines.append(f"{number()} create {task}({args})")
    return lines, unknown


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("verb", choices=("start", "stop", "write"))
    ap.add_argument("record", nargs="?", type=Path, help="write: the record file")
    ap.add_argument("--etl", type=Path, default=OUT / "watch.etl", help="the trace file")
    ap.add_argument("--process", help="write: the watched program's image name, as Rome2.exe or live.exe")
    ap.add_argument("--pid", help="write: its process id, for a program that was running before the trace began")
    args = ap.parse_args(argv)
    if args.verb == "start":
        args.etl.parent.mkdir(parents=True, exist_ok=True)
        args.etl.unlink(missing_ok=True)
        args.etl.with_suffix(".xml").unlink(missing_ok=True)
        tool("logman", "start", SESSION, "-p", PROVIDERS[0], "0xffffffffffffffff", "0xff", "-o", str(args.etl), "-bs", "1024", "-nb", "64", "512",
             "-ets")
        tool("logman", "update", SESSION, "-p", PROVIDERS[1], "0xffffffffffffffff", "0xff", "-ets")
        tool("logman", "update", SESSION, "-p", PROCESSES, "0x10", "0xff", "-ets")
        print(f"watching; run the program, then: python scripts/lift/watch_d3d.py stop\n{args.etl}")
        return 0
    if args.verb == "stop":
        tool("logman", "stop", SESSION, "-ets")
    if not args.etl.exists():
        raise SystemExit(f"{args.etl}: no trace; run start first")
    if args.verb == "write" and (args.record is None or not (args.process or args.pid)):
        ap.error("write needs a record file and --process or --pid")
    types = schema() if args.verb == "write" else None
    seen, names, lost = processes(args.etl, types)
    if lost:
        print(f"WARNING: the trace lost {lost} events; the record has gaps")
    if args.verb == "stop":
        for pid, mine in sorted(seen.items(), key=lambda item: -item[1]["events"]):
            print(f"{mine['events']:9,} events  pid {pid:>6}  {names.get(pid, '(running before the trace began)')}")
        print("next: python scripts/lift/watch_d3d.py write <record> --process <name>")
        return 0
    wanted = [pid for pid in ([args.pid] if args.pid else [p for p, name in names.items() if name.lower() == args.process.lower()]) if pid in seen]
    if len(wanted) != 1:  # also a process id the trace does not hold: its record would be an empty file
        raise SystemExit(f"the trace holds the DXGI or Direct3D 11 events of {len(wanted)} processes "
                         + (f"with the id {args.pid}" if args.pid else f"named {args.process}") + "; name one of its processes with --pid "
                         "(a trace of watch_game.py holds no names): "
                         + (", ".join(f"{pid} ({names.get(pid, 'no name')}, {mine['events']:,} events)" for pid, mine in seen.items())
                            or "it has none"))
    mine = seen[wanted[0]]
    lines, unknown = record(args.etl, wanted[0], types, mine["bits"])
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{args.record}: {len(lines):,} lines from {mine['events']:,} events of pid {wanted[0]}"
          + (f" ({mine['bits']}-bit)" if mine["bits"] else " (its events do not tell its bitness: read as a 64-bit program's)")
          + (f"; {unknown} events the manifests do not describe were left out" if unknown else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
