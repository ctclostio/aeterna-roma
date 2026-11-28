"""Watches a program's DXGI and Direct3D 11 use from outside, with Windows' own event tracing.

    python scripts/lift/watch_d3d.py start                              in an elevated prompt
    ... run the program and use it: the original game, or live.exe ...
    python scripts/lift/watch_d3d.py stop                               ends the trace, lists the programs seen
    python scripts/lift/watch_d3d.py write <record> --process <name>    (or --pid N)

dxgi.dll and d3d11.dll report what they are asked to do to Event Tracing for Windows (the providers
Microsoft-Windows-DXGI and Microsoft-Windows-Direct3D11) whenever a trace session asks for it. `start` opens such
a session with logman and `stop` closes it; tracerpt decodes the file. Both are parts of Windows. Nothing is
loaded into the watched program, none of its files are touched and it is not started any differently: it cannot
tell that it is watched. The session sees every program on the machine that uses Direct3D while it is open; a
record is written for one of them and the trace file stays on this machine (generated/lifted/d3d_watch/).

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
out too. A 32-bit and a 64-bit program asking for the same things give the same lines; that the 32-bit dxgi.dll
and d3d11.dll report the same events has not been checked yet (no 32-bit program has been watched).
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
EVENT = re.compile(r"<Event .*?</Event>", re.S)
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
    proc = subprocess.run(command, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise SystemExit(f"{' '.join(command[:3])} ...: {(proc.stdout + proc.stderr).strip()[-600:]}")
    return proc.stdout


def schema() -> dict[tuple[str, str, str], tuple[str, dict[str, str]]]:
    """(provider, event id, version) -> (task name, field -> type), from the providers' manifests on this machine."""
    script = SCHEMA_SCRIPT.replace("PROVIDERS", "','".join(PROVIDERS))
    text = tool("powershell", "-NoProfile", "-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode())
    out = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            out[tuple(parts[:3])] = (parts[3], dict(f.split(":") for f in parts[4].split()))
    if not out:
        raise SystemExit("the DXGI and Direct3D 11 event providers list no events on this machine")
    return out


def swap_chain(data: bytes) -> str:
    """DXGI_SWAP_CHAIN_DESC as a 32-bit (60 bytes) or 64-bit (72 bytes) program lays it out, without OutputWindow."""
    if len(data) not in (60, 72):
        return f"{len(data)} bytes"
    names = ("Width", "Height", "RefreshNumerator", "RefreshDenominator", "Format", "ScanlineOrdering", "Scaling", "SampleCount",
             "SampleQuality", "BufferUsage", "BufferCount")
    tail = struct.unpack_from("<3I", data, 48 if len(data) == 60 else 56)
    values = dict(zip(names, struct.unpack_from("<11I", data)), Windowed=tail[0], SwapEffect=tail[1], Flags=tail[2])
    return "{" + " ".join(f"{k}={v}" for k, v in values.items()) + "}"


def shown(task: str, name: str, kind: str, value: str) -> str:
    value = value.strip()
    if kind == "Pointer":
        return "0" if int(value, 16) == 0 else "*"
    if kind == "Binary":
        data = bytes.fromhex(value[2:] if value.lower().startswith("0x") else value)
        return swap_chain(data) if task == "IDXGIFactory_CreateSwapChain" and name == "pDesc" else f"{len(data)} bytes"
    if kind in ("UInt32", "Int32", "UInt16", "UInt8", "Boolean", "GUID", "UnicodeString", "AnsiString"):
        return "h" if value.lower().startswith("0x") or "Handle" in name else value  # kernel handles are numbers too
    return "h"  # HexInt32, HexInt64, UInt64: handles, driver versions, times


def read_trace(etl: Path) -> str:
    xml = etl.with_suffix(".xml")
    if not xml.exists() or xml.stat().st_mtime < etl.stat().st_mtime:
        tool("tracerpt", str(etl), "-o", str(xml), "-of", "XML", "-lr", "-y")
    data = xml.read_bytes()
    return data.decode("utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8", errors="replace")


def field(event: str, tag: str) -> str:
    found = re.search(rf"<{tag}>([^<]*)</{tag}>", event)
    return found.group(1) if found else ""


def processes(text: str) -> tuple[collections.Counter, dict[str, str]]:
    """Events of the two providers by process id, and the image names of the processes started during the trace."""
    counts: collections.Counter = collections.Counter()
    names: dict[str, str] = {}
    for found in EVENT.finditer(text):
        event = found.group(0)
        provider = re.search(r'<Provider Name="([^"]+)"', event)
        if provider and provider.group(1) == PROCESSES and field(event, "EventID") == "1":
            data = dict(re.findall(r'<Data Name="([^"]+)">([^<]*)</Data>', event))
            if "ImageName" in data and "ProcessID" in data:
                names[data["ProcessID"].strip()] = data["ImageName"].replace("\\", "/").rsplit("/", 1)[-1]
        elif provider and provider.group(1) in PROVIDERS:
            counts[re.search(r'<Execution ProcessID="(\d+)"', event).group(1)] += 1
    return counts, names


def record(text: str, pid: str, types: dict) -> tuple[list[str], int]:
    """The record lines of one process, and how many of its events have no description in the manifests."""
    threads: dict[str, int] = {}
    open_calls: dict[str, list[tuple[str, str] | None]] = collections.defaultdict(list)  # thread -> calls begun
    lines, unknown = [], 0
    for found in EVENT.finditer(text):
        event = found.group(0)
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
        data = re.findall(r'<Data Name="([^"]+)">([^<]*)</Data>', event)
        args = " ".join(f"{name}={shown(task, name, kinds.get(name, ''), value)}" for name, value in data if name != "pThis")
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
    text = read_trace(args.etl)
    counts, names = processes(text)
    lost = re.search(r'<Data Name="EventsLost">\s*(\d+)', text)
    if lost and int(lost.group(1)):
        print(f"WARNING: the trace lost {lost.group(1)} events; the record has gaps")
    if args.verb == "stop":
        for pid, n in counts.most_common():
            print(f"{n:9,} events  pid {pid:>6}  {names.get(pid, '(running before the trace began)')}")
        print("next: python scripts/lift/watch_d3d.py write <record> --process <name>")
        return 0
    if args.record is None or not (args.process or args.pid):
        ap.error("write needs a record file and --process or --pid")
    wanted = [args.pid] if args.pid else [pid for pid, name in names.items() if name.lower() == args.process.lower() and counts[pid]]
    if len(wanted) != 1:
        raise SystemExit(f"{len(wanted)} processes named {args.process} used Direct3D during the trace; name one with --pid: "
                         + ", ".join(f"{pid} ({counts[pid]:,} events)" for pid in wanted))
    lines, unknown = record(text, wanted[0], schema())
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{args.record}: {len(lines):,} lines from {counts[wanted[0]]:,} events of pid {wanted[0]}"
          + (f"; {unknown} events the manifests do not describe were left out" if unknown else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
