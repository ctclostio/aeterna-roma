#!/usr/bin/env python3
"""scripts/lift/watch_game.py and the records scripts/lift/watch_d3d.py writes for it, as far as they can be tested
with no elevation, no trace session and no Direct3D: record lines for a 32-bit and a 64-bit process, the bitness
decision, the names of sessions, records and trace files, and the lines of the list of opened files.

The events are real. They are copied from traces of stand-in programs decoded by tracerpt on Windows 11 build 26300,
each without its RenderingInfo element and without indentation, and arranged shortly (a call's start and return
events without the events between them):

  - D3D_EVENTS: the same four moments of a 64-bit run (process 29328) and a 32-bit run (process 16228) of one probe
    in one trace: an adapter object being created, and the calls IDXGIFactory::CreateSwapChain,
    IDXGIFactory::MakeWindowAssociation and IDXGISwapChain::GetFullscreenState. Before them the trace's own header
    event, written under the process id of whoever opened the session (25360), with only its EventsLost field (the
    others describe the machine). After them IDXGIFactory::CreateSoftwareAdapter from a 64-bit and a 32-bit run of
    port/lifted_live/test_d3d_probe.c, whose adapter pointer holds 0x12345678 before that call (processes 21628 and
    26464), and IDXGIFactory::CreateSwapChain and IDXGIFactory::MakeWindowAssociation from a run of that probe built
    64-bit with /LARGEADDRESSAWARE:NO (process 26568): a 64-bit program with every pointer below 2^32.
  - FILE_EVENTS: five files opened by one such program (process 28152, two threads) and one by another (23924).

TYPES is what watch_d3d.schema() gave for these events on that machine. Expected lines of 64-bit processes are the
ones the committed watch_d3d.py wrote for these traces, but for the field it now leaves out. Two tests change one
value of a real event, and say which: no trace here lost an event or holds another event of the file provider. Two
put a function in the place of a part of Windows, and say which: tracerpt, and the PowerShell that reads the manifests.
"""
from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lift"))
import watch_d3d  # noqa: E402
import watch_game  # noqa: E402

DXGI = "Microsoft-Windows-DXGI"
TYPES = {
    (DXGI, "4", "0"): ("Adapter", {"pIDXGIAdapter": "Pointer", "pIDXGIFactory": "Pointer", "KMTAdapterHandle": "UInt32", "ThunkDLLHandle": "Pointer",
                                   "SharedResources": "Boolean"}),
    (DXGI, "184", "0"): ("IDXGISwapChain_GetFullscreenState", {"pThis": "Pointer", "pbFullscreen": "UInt32", "ppTarget": "Pointer"}),
    (DXGI, "185", "0"): ("IDXGISwapChain_GetFullscreenState", {"m_Ret": "UInt32"}),
    (DXGI, "214", "0"): ("IDXGIFactory_MakeWindowAssociation", {"pThis": "Pointer", "hWnd": "UInt64", "Flags": "UInt32"}),
    (DXGI, "215", "0"): ("IDXGIFactory_MakeWindowAssociation", {"m_Ret": "UInt32"}),
    (DXGI, "218", "0"): ("IDXGIFactory_CreateSwapChain", {"pThis": "Pointer", "pDevice": "Pointer", "pDesc": "Binary", "ppSwapChain": "Pointer"}),
    (DXGI, "219", "0"): ("IDXGIFactory_CreateSwapChain", {"m_Ret": "UInt32"}),
    (DXGI, "220", "0"): ("IDXGIFactory_CreateSoftwareAdapter", {"pThis": "Pointer", "hModule": "UInt64", "ppAdapter": "Pointer"}),
    (DXGI, "221", "0"): ("IDXGIFactory_CreateSoftwareAdapter", {"m_Ret": "UInt32"}),
}
OPENER, PID64, PID32, SOFT64, SOFT32, LOW64 = "25360", "29328", "16228", "21628", "26464", "26568"
ADAPTER = "1 create Adapter(pIDXGIAdapter=* pIDXGIFactory=* KMTAdapterHandle=h ThunkDLLHandle=* SharedResources=true)"
SWAP_CHAIN = ("1 IDXGIFactory::CreateSwapChain(pDevice=* pDesc={Width=320 Height=240 RefreshNumerator=60 RefreshDenominator=1 Format=28 ScanlineOrdering=0 "
              "Scaling=0 SampleCount=1 SampleQuality=0 BufferUsage=32 BufferCount=1 Windowed=1 SwapEffect=0 Flags=0} ppSwapChain=0) = 0")
RECORD = [ADAPTER, SWAP_CHAIN, "1 IDXGIFactory::MakeWindowAssociation(hWnd=h Flags=2) = 0", "1 IDXGISwapChain::GetFullscreenState(pbFullscreen=0) = 0"]
# What the committed watch_d3d.py wrote for the 32-bit process, and the new one still does when told it is 64-bit.
RECORD_32_READ_AS_64 = [ADAPTER, SWAP_CHAIN.replace("Windowed=1 SwapEffect=0 Flags=0", "Windowed=0 SwapEffect=800 Flags=600"),
                        "1 IDXGIFactory::MakeWindowAssociation(hWnd=h) = 0", "1 IDXGISwapChain::GetFullscreenState(pbFullscreen=0) = 0"]

D3D_EVENTS = r"""
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Guid="{9e814aad-3204-11d2-9a82-006008a86939}" />
<EventID>0</EventID>
<Version>2</Version>
<Level>0</Level>
<Task>0</Task>
<Opcode>0</Opcode>
<Keywords>0x0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.398151100-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="25360" ThreadID="16092" ProcessorID="0" KernelTime="0" UserTime="45" />
<Channel />
<Computer />
</System>
<EventData>
<Data Name="EventsLost">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>4</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>3</Task>
<Opcode>1</Opcode>
<Keywords>0x8000000000000001</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.421351300-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="15" UserTime="0" />
<Channel>Microsoft-Windows-DXGI/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="pIDXGIAdapter">0x2CCC0C53CC0</Data>
<Data Name="pIDXGIFactory">0x2CCC0C42A50</Data>
<Data Name="KMTAdapterHandle">1073742656</Data>
<Data Name="ThunkDLLHandle">0x7FFF09070000</Data>
<Data Name="SharedResources">true</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>218</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>100</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.584030400-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="75" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x2CCC0C42A50</Data>
<Data Name="pDevice">0x2CCC2DE3BB0</Data>
<Data Name="pDesc">0x40010000F00000003C000000010000001C00000000000000000000000100000000000000200000000100000000000000EA0866000000000001000000000000000000000000000000</Data>
<Data Name="ppSwapChain">0x0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>219</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>100</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.584770000-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="75" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>214</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>98</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.584778400-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="75" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x2CCC0C42A50</Data>
<Data Name="hWnd">6686954</Data>
<Data Name="Flags">       2</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>215</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>98</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.584779100-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="75" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>184</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>83</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.584783000-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="75" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x2CCC2C87AA0</Data>
<Data Name="pbFullscreen">       0</Data>
<Data Name="ppTarget">0x7FF7654E6732</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>185</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>83</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.584783300-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="29328" ThreadID="24484" ProcessorID="0" KernelTime="75" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>4</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>3</Task>
<Opcode>1</Opcode>
<Keywords>0x8000000000000001</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:36.850840100-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="0" UserTime="15" />
<Channel>Microsoft-Windows-DXGI/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="pIDXGIAdapter">0x129C2E8</Data>
<Data Name="pIDXGIFactory">0x128F930</Data>
<Data Name="KMTAdapterHandle">1073742656</Data>
<Data Name="ThunkDLLHandle">0x77060000</Data>
<Data Name="SharedResources">true</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>218</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>100</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:37.009544300-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="75" UserTime="105" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x128F930</Data>
<Data Name="pDevice">0x1347B5C</Data>
<Data Name="pDesc">0x40010000F00000003C000000010000001C000000000000000000000001000000000000002000000001000000EA086800010000000000000000000000200300005802000000000000</Data>
<Data Name="ppSwapChain">0x0</Data>
<Data Name="win:ExtraPayload" Type="win:ErrorMoreData">0x74EEEF00</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>219</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>100</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:37.010628500-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="75" UserTime="105" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>214</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>98</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:37.010670800-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="75" UserTime="105" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x128F930</Data>
<Data Name="hWnd">8596752618</Data>
<Data Name="Flags" Type="win:ErrorLessData"></Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>215</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>98</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:37.010672100-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="75" UserTime="105" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>184</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>83</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:37.010679000-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="75" UserTime="105" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x7ADC380</Data>
<Data Name="pbFullscreen">       0</Data>
<Data Name="ppTarget">0x0</Data>
<Data Name="win:ExtraPayload" Type="win:ErrorMoreData">0x00000000</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>185</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>83</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:37.010679600-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="16228" ThreadID="4832" ProcessorID="0" KernelTime="75" UserTime="105" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>220</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>101</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:36:58.012686200-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="21628" ThreadID="7876" ProcessorID="0" KernelTime="90" UserTime="45" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x16E35462270</Data>
<Data Name="hModule">140731584151552</Data>
<Data Name="ppAdapter">0x12345678</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>221</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>101</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:36:58.012781600-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="21628" ThreadID="7876" ProcessorID="0" KernelTime="90" UserTime="45" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>220</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>101</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:36:58.641523300-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="26464" ThreadID="27704" ProcessorID="0" KernelTime="30" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0xA7BFB0</Data>
<Data Name="hModule">1311768466626379776</Data>
<Data Name="ppAdapter">0x0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>221</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>101</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:36:58.641651100-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="26464" ThreadID="27704" ProcessorID="0" KernelTime="30" UserTime="75" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>218</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>100</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:56:21.087102000-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="26568" ThreadID="25032" ProcessorID="0" KernelTime="45" UserTime="90" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x1119BD0</Data>
<Data Name="pDevice">0x5AD2C30</Data>
<Data Name="pDesc">0x40010000F00000003C000000010000001C000000000000000000000001000000000000002000000002000000000000005403F9000000000001000000010000000200000000000000</Data>
<Data Name="ppSwapChain">0x0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>219</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>100</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:56:21.088025200-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="26568" ThreadID="25032" ProcessorID="0" KernelTime="45" UserTime="90" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>214</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>98</Task>
<Opcode>1</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:56:21.088031900-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="26568" ThreadID="25032" ProcessorID="0" KernelTime="45" UserTime="90" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="pThis">0x1119BD0</Data>
<Data Name="hWnd">16319316</Data>
<Data Name="Flags">       3</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-DXGI" Guid="{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" />
<EventID>215</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>98</Task>
<Opcode>2</Opcode>
<Keywords>0x4000000000000000</Keywords>
<TimeCreated SystemTime="2026-11-27T22:56:21.088036000-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="26568" ThreadID="25032" ProcessorID="0" KernelTime="45" UserTime="90" />
<Channel>Microsoft-Windows-DXGI/Logging</Channel>
<Computer />
</System>
<EventData>
<Data Name="m_Ret">       0</Data>
</EventData>
</Event>
"""

FILE_EVENTS = r"""
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />
<EventID>12</EventID>
<Version>1</Version>
<Level>4</Level>
<Task>12</Task>
<Opcode>0</Opcode>
<Keywords>0x80000000000000A0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:45.250926100-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="23924" ThreadID="24388" ProcessorID="0" KernelTime="0" UserTime="0" />
<Channel>Microsoft-Windows-Kernel-File/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="Irp">0xFFFFA7842C372138</Data>
<Data Name="FileObject">0xFFFFA7843C15F1E0</Data>
<Data Name="IssuingThreadId">   24388</Data>
<Data Name="CreateOptions">0x1000060</Data>
<Data Name="CreateAttributes">0x80</Data>
<Data Name="ShareAccess">0x1</Data>
<Data Name="FileName">\Device\HarddiskVolume5\Sandbox\aeterna-d3d11\generated\lifted\etw_research\out\probe_b.txt</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />
<EventID>12</EventID>
<Version>1</Version>
<Level>4</Level>
<Task>12</Task>
<Opcode>0</Opcode>
<Keywords>0x80000000000000A0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:45.266441400-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="28152" ThreadID="26144" ProcessorID="0" KernelTime="0" UserTime="0" />
<Channel>Microsoft-Windows-Kernel-File/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="Irp">0xFFFFA7842FC580F8</Data>
<Data Name="FileObject">0xFFFFA7845D8A5350</Data>
<Data Name="IssuingThreadId">   26144</Data>
<Data Name="CreateOptions">0x1000060</Data>
<Data Name="CreateAttributes">0x80</Data>
<Data Name="ShareAccess">0x1</Data>
<Data Name="FileName">\Device\HarddiskVolume5\Sandbox\aeterna-d3d11\generated\lifted\etw_research\out\probe_b.txt</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />
<EventID>12</EventID>
<Version>1</Version>
<Level>4</Level>
<Task>12</Task>
<Opcode>0</Opcode>
<Keywords>0x80000000000000A0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:45.266557600-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="28152" ThreadID="26144" ProcessorID="0" KernelTime="0" UserTime="0" />
<Channel>Microsoft-Windows-Kernel-File/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="Irp">0xFFFFA7842FC580F8</Data>
<Data Name="FileObject">0xFFFFA7845D8A3A50</Data>
<Data Name="IssuingThreadId">   26144</Data>
<Data Name="CreateOptions">0x1000060</Data>
<Data Name="CreateAttributes">0x80</Data>
<Data Name="ShareAccess">0x1</Data>
<Data Name="FileName">\Device\HarddiskVolume5\Sandbox\aeterna-d3d11\generated\lifted\etw_research\out\probe_missing.txt</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />
<EventID>12</EventID>
<Version>1</Version>
<Level>4</Level>
<Task>12</Task>
<Opcode>0</Opcode>
<Keywords>0x80000000000000A0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:45.266767000-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="28152" ThreadID="26144" ProcessorID="0" KernelTime="0" UserTime="0" />
<Channel>Microsoft-Windows-Kernel-File/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="Irp">0xFFFFA7842FC580F8</Data>
<Data Name="FileObject">0xFFFFA7845D8A9360</Data>
<Data Name="IssuingThreadId">   26144</Data>
<Data Name="CreateOptions">0x1000060</Data>
<Data Name="CreateAttributes">0x80</Data>
<Data Name="ShareAccess">0x7</Data>
<Data Name="FileName">\Device\HarddiskVolume5\Sandbox\aeterna-d3d11\generated\lifted\etw_research\aeterna_named64.exe</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />
<EventID>12</EventID>
<Version>1</Version>
<Level>4</Level>
<Task>12</Task>
<Opcode>0</Opcode>
<Keywords>0x80000000000000A0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:45.266954700-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="28152" ThreadID="26144" ProcessorID="0" KernelTime="0" UserTime="0" />
<Channel>Microsoft-Windows-Kernel-File/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="Irp">0xFFFFA7842FC580F8</Data>
<Data Name="FileObject">0xFFFFA7845D8A83C0</Data>
<Data Name="IssuingThreadId">   26144</Data>
<Data Name="CreateOptions">0x1204000</Data>
<Data Name="CreateAttributes">0x0</Data>
<Data Name="ShareAccess">0x7</Data>
<Data Name="FileName">\Device\HarddiskVolume3\WINDOWS\SYSTEM32\dxcore.dll</Data>
</EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />
<EventID>12</EventID>
<Version>1</Version>
<Level>4</Level>
<Task>12</Task>
<Opcode>0</Opcode>
<Keywords>0x80000000000000A0</Keywords>
<TimeCreated SystemTime="2026-11-27T21:54:45.281428300-07:00" />
<Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
<Execution ProcessID="28152" ThreadID="6368" ProcessorID="0" KernelTime="0" UserTime="0" />
<Channel>Microsoft-Windows-Kernel-File/Analytic</Channel>
<Computer />
</System>
<EventData>
<Data Name="Irp">0xFFFFA7842C372138</Data>
<Data Name="FileObject">0xFFFFA7843C16DAB0</Data>
<Data Name="IssuingThreadId">    6368</Data>
<Data Name="CreateOptions">0x1204000</Data>
<Data Name="CreateAttributes">0x0</Data>
<Data Name="ShareAccess">0x7</Data>
<Data Name="FileName">\Device\HarddiskVolume3\WINDOWS\SYSTEM32\VERSION.dll</Data>
</EventData>
</Event>
"""
FOLDER = r"\Device\HarddiskVolume5\Sandbox\aeterna-d3d11\generated\lifted\etw_research"  # the folder of process 28152's image
DRIVES = {r"\Device\HarddiskVolume3": "C:", r"\Device\HarddiskVolume5": "X:"}             # as etw_scope.drive_devices() gave them


class RecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = tempfile.TemporaryDirectory()
        cls.etl = Path(cls.folder.name) / "trace.etl"
        cls.etl.write_bytes(b"")  # watch_d3d.events() reads the decoded file beside a trace when it is not the older one
        cls.etl.with_suffix(".xml").write_text(f"<Events>{D3D_EVENTS}</Events>", encoding="utf-8")
        cls.seen, _, cls.lost = watch_d3d.processes(cls.etl, TYPES)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def lines(self, pid: str, bits: int) -> list[str]:
        lines, unknown = watch_d3d.record(self.etl, pid, TYPES, bits)
        self.assertEqual(unknown, 0)
        return lines

    def test_events_are_counted_by_provider(self) -> None:
        self.assertIn(f'ProcessID="{OPENER}"', D3D_EVENTS)
        self.assertEqual({pid: mine["events"] for pid, mine in self.seen.items()}, {PID64: 7, PID32: 7, SOFT64: 2, SOFT32: 2, LOW64: 4})
        self.assertEqual(self.lost, 0)
        self.assertLess(self.seen[PID64]["first"], self.seen[PID64]["last"])

    def trace(self, name: str, events: str) -> Path:
        etl = Path(self.folder.name) / f"{name}.etl"
        etl.write_bytes(b"")
        etl.with_suffix(".xml").write_text(f"<Events>{events}</Events>", encoding="utf-8")
        return etl

    def test_the_events_lost_are_read_from_the_trace_s_header(self) -> None:
        # No trace here lost an event: the 0 of the real header event is replaced.
        lost = self.trace("lost", D3D_EVENTS.replace('<Data Name="EventsLost">       0</Data>', '<Data Name="EventsLost">      17</Data>'))
        self.assertEqual(watch_d3d.processes(lost, TYPES)[2], 17)

    def test_a_decoded_trace_without_any_event_is_refused(self) -> None:
        # What tracerpt wrote, with exit code 0, for a trace cut to 60% of its length: no event, not even the header.
        with self.assertRaises(SystemExit) as refused:
            watch_d3d.processes(self.trace("cut", "\n"), TYPES)
        self.assertIn("not a whole trace", str(refused.exception))

    def test_a_decoding_that_fails_leaves_no_decoded_file_to_be_taken_for_the_whole(self) -> None:
        # In tracerpt's place: a function that writes the beginning of the decoded form and fails, then one that writes all of it.
        etl = Path(self.folder.name) / "cut_decoding.etl"
        etl.write_bytes(b"")
        whole = f"<Events>{D3D_EVENTS}</Events>"

        def tracerpt(fails: bool):
            def run(*command: str) -> str:
                Path(command[command.index("-o") + 1]).write_text(whole[:len(whole) // 2] if fails else whole, encoding="utf-8")
                if fails:
                    raise SystemExit("tracerpt ...")
                return ""
            return run
        with mock.patch.object(watch_d3d, "tool", tracerpt(fails=True)), self.assertRaises(SystemExit):
            list(watch_d3d.events(etl))
        self.assertEqual([path.name for path in Path(self.folder.name).glob("cut_decoding*")], ["cut_decoding.etl"])
        with mock.patch.object(watch_d3d, "tool", tracerpt(fails=False)):
            self.assertEqual(len(list(watch_d3d.events(etl))), len(watch_d3d.EVENT.findall(D3D_EVENTS)))
        self.assertEqual(sorted(path.name for path in Path(self.folder.name).glob("cut_decoding*")), ["cut_decoding.etl", "cut_decoding.xml"])

    def test_write_refuses_a_process_the_trace_does_not_hold_and_names_the_ones_it_holds(self) -> None:
        record = Path(self.folder.name) / "record.txt"
        with mock.patch.object(watch_d3d, "schema", return_value=TYPES):  # in the place of the manifests' PowerShell
            with self.assertRaises(SystemExit) as refused:
                watch_d3d.main(["write", str(record), "--etl", str(self.etl), "--pid", "1"])
            self.assertIn(f"{PID32} (no name, 7 events)", str(refused.exception))
            self.assertFalse(record.exists(), "not an empty record")
            with self.assertRaises(SystemExit) as refused:
                watch_d3d.main(["write", str(record), "--etl", str(self.etl), "--process", "probe.exe"])
            self.assertIn("0 processes named probe.exe", str(refused.exception), "a trace scoped to one program holds no names")
            with contextlib.redirect_stdout(io.StringIO()) as said:
                self.assertEqual(watch_d3d.main(["write", str(record), "--etl", str(self.etl), "--pid", PID32]), 0)
        self.assertEqual(record.read_text(encoding="utf-8").splitlines(), RECORD)
        self.assertIn("(32-bit)", said.getvalue())

    def test_bitness_is_decided_from_a_process_s_own_events(self) -> None:
        self.assertEqual({pid: mine["bits"] for pid, mine in self.seen.items()}, {PID64: 64, PID32: 32, SOFT64: 64, SOFT32: 0, LOW64: 0},
                         "SOFT32: two events of a 32-bit process, neither of a length that tells; LOW64: no pointer of 2^32 or more")
        self.assertEqual({mine["bits"] for mine in watch_d3d.processes(self.etl)[0].values()}, {0}, "without the manifests' types it is not decided")

    def test_small_pointers_alone_do_not_make_a_process_32_bit(self) -> None:
        low64 = [SWAP_CHAIN.replace("BufferCount=1 Windowed=1 SwapEffect=0 Flags=0", "BufferCount=2 Windowed=1 SwapEffect=1 Flags=2"),
                 "1 IDXGIFactory::MakeWindowAssociation(hWnd=h Flags=3) = 0"]
        self.assertEqual(self.lines(LOW64, self.seen[LOW64]["bits"]), low64, "bitness not known: read as a 64-bit program's")
        self.assertEqual(self.lines(LOW64, 64), low64)
        self.assertNotEqual(self.lines(LOW64, 32), low64, "what taking it for a 32-bit process gave")

    def test_events_the_manifests_do_not_describe_are_counted_and_left_out(self) -> None:
        lines, unknown = watch_d3d.record(self.etl, PID64, {key: value for key, value in TYPES.items() if key != (DXGI, "4", "0")}, 64)
        self.assertEqual((lines, unknown), (RECORD[1:], 1))

    def test_a_32_bit_and_a_64_bit_process_give_the_same_record(self) -> None:
        self.assertEqual(self.lines(PID64, 64), RECORD)
        self.assertEqual(self.lines(PID32, 32), RECORD)

    def test_the_differences_show_when_a_32_bit_process_is_read_as_64_bit(self) -> None:
        self.assertEqual(self.lines(PID32, 64), RECORD_32_READ_AS_64)

    def test_the_two_dlls_report_these_fields_differently(self) -> None:
        def data(pid: str, name: str) -> list[str]:
            return [value for event in watch_d3d.events(self.etl) if f'ProcessID="{pid}"' in event
                    for field, value in watch_d3d.DATA.findall(event) if field == name]
        self.assertEqual(data(PID64, "hWnd"), ["6686954"])
        self.assertEqual(data(PID64, "Flags"), ["       2"])
        self.assertEqual(data(PID32, "hWnd"), [str(2 << 32 | 6818026)], "Flags << 32 | window")
        self.assertEqual(data(PID32, "Flags"), [], "the decoder finds no bytes left for it")
        self.assertEqual([len(value) for pid in (PID64, PID32) for value in data(pid, "pDesc")], [2 + 2 * 72] * 2, "72 bytes logged by both")
        self.assertEqual(data(PID32, "ppTarget"), ["0x0"])
        self.assertNotEqual(int(data(PID64, "ppTarget")[0], 16), 0)
        self.assertEqual(data(SOFT64, "ppAdapter"), ["0x12345678"], "what the probe's adapter pointer held before the call")
        self.assertEqual([int(value) >> 32 for value in data(SOFT32, "hModule")], [0x12345678], "ppAdapter << 32 | module")
        self.assertEqual(data(SOFT32, "ppAdapter"), ["0x0"], "not the program's")

    def test_create_software_adapter_gives_the_same_line(self) -> None:
        line = "1 IDXGIFactory::CreateSoftwareAdapter(hModule=h ppAdapter=*) = 0"
        self.assertEqual(self.lines(SOFT64, 64), [line])
        self.assertEqual(self.lines(SOFT32, 32), [line])
        self.assertEqual(self.lines(SOFT32, 64), [line.replace("*", "0")], "read as 64-bit, the pointer is lost")

    def test_a_description_shorter_than_its_layout_is_not_decoded(self) -> None:
        logged = next(value for event in watch_d3d.events(self.etl) if f'ProcessID="{PID32}"' in event
                      for field, value in watch_d3d.DATA.findall(event) if field == "pDesc")
        desc = bytes.fromhex(logged[2:])[:60]  # the 32-bit DXGI_SWAP_CHAIN_DESC without what follows it
        self.assertIn("Windowed=1 SwapEffect=0 Flags=0}", watch_d3d.swap_chain(desc, 32))
        self.assertEqual(watch_d3d.swap_chain(desc, 64), "60 bytes")


class NamingTests(unittest.TestCase):
    def test_roles_and_sessions(self) -> None:
        original, lifted, other = watch_game.Watch("Rome2.exe"), watch_game.Watch("live.exe"), watch_game.Watch("Some_Tool.EXE")
        self.assertEqual((original.role, original.session, original.files_session), ("original", "aeterna_watch_rome2", "aeterna_watch_rome2_files"))
        self.assertEqual((lifted.role, lifted.session), ("lifted", "aeterna_watch_live"))
        self.assertEqual((other.role, other.session), ("some_tool", "aeterna_watch_some_tool"))
        self.assertEqual({w.out for w in (original, lifted, other)}, {watch_d3d.OUT})
        self.assertEqual({w.task for w in (original, lifted, other)}, {"aeterna_game_watch"})
        self.assertEqual((original.options, lifted.options), ([], ["--exe", "live.exe"]))
        self.assertEqual(len({w.monitor for w in (original, lifted, other)}), 3)

    def test_the_selftest_shares_no_name_with_the_real_thing(self) -> None:
        real, test = watch_game.Watch(watch_game.PROBE), watch_game.Watch(watch_game.PROBE, selftest=True)
        self.assertEqual((test.session, test.task, test.role), ("aeterna_selftest_test_d3d_probe", "aeterna_game_watch_selftest", "test_d3d_probe"))
        self.assertEqual(test.out, watch_d3d.OUT.parent / "d3d_watch_selftest")
        for name in ("session", "files_session", "monitor", "task", "out"):
            self.assertNotEqual(getattr(real, name), getattr(test, name), name)
        self.assertEqual(test.options, ["--exe", watch_game.PROBE, "--selftest"])

    def test_a_trace_or_record_name_is_never_one_in_use(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            taken = []
            for suffix in (".etl", ".txt", "_files.txt", ".etl"):
                base = watch_game.fresh(Path(folder), "original")
                self.assertRegex(base.name, r"^original_\d{8}_\d{6}(_\d+)?$")
                self.assertNotIn(base, taken)
                taken.append(base)
                Path(f"{base}{suffix}").write_bytes(b"")

    def test_a_name_the_filter_would_not_match_is_refused(self) -> None:
        for name in ("Rome2", "*.exe", "games\\Rome2.exe", "C:/games/Rome2.exe", "a.exe;b.exe", ".exe"):
            with self.subTest(name=name):
                with contextlib.redirect_stderr(io.StringIO()) as said, self.assertRaises(SystemExit):
                    watch_game.main(["status", "--exe", name])
                self.assertIn("--exe is a file name", said.getvalue())

    def test_the_monitor_s_lines_reach_its_log_with_no_console(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            watch_game.LOG = Path(folder) / "monitor.log"
            try:
                with contextlib.redirect_stdout(None):  # as under pythonw
                    watch_game.say("one\ntwo")
            finally:
                watch_game.LOG = None
            logged = (Path(folder) / "monitor.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual([re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", "", line) for line in logged], ["one", "two"])
        self.assertTrue(all(re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", line) for line in logged))

    def test_a_log_that_cannot_be_written_does_not_end_the_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            watch_game.LOG = Path(folder)  # a folder: it cannot be opened for writing, like a log another program holds
            try:
                with contextlib.redirect_stdout(None):
                    watch_game.say("one")
            finally:
                watch_game.LOG = None


class FileLineTests(unittest.TestCase):
    EVENTS = watch_d3d.EVENT.findall(FILE_EVENTS)

    def test_only_the_watched_process_s_opens_in_order_with_threads_numbered(self) -> None:
        self.assertEqual(len(self.EVENTS), 6)
        self.assertEqual(watch_game.file_lines(self.EVENTS, {28152: FOLDER}, DRIVES),
                         [r"1 out\probe_b.txt", r"1 out\probe_missing.txt", "1 aeterna_named64.exe", r"1 C:\WINDOWS\SYSTEM32\dxcore.dll",
                          r"2 C:\WINDOWS\SYSTEM32\VERSION.dll"])

    def test_two_watched_processes_share_the_numbering(self) -> None:
        lines = watch_game.file_lines(self.EVENTS, {28152: FOLDER, 23924: FOLDER}, DRIVES)
        self.assertEqual(len(lines), 6)
        self.assertEqual(sorted({line.split()[0] for line in lines}), ["1", "2", "3"])
        self.assertEqual(sum(line.endswith(r"out\probe_b.txt") for line in lines), 2)

    def test_no_watched_process_no_line(self) -> None:
        self.assertEqual(watch_game.file_lines(self.EVENTS, {1: FOLDER}, DRIVES), [])

    def test_only_event_12_gives_a_line(self) -> None:
        # The trace holds no other event of the provider: the id of the watched process's second open is replaced.
        events = [event.replace("<EventID>12</EventID>", "<EventID>24</EventID>") if "probe_missing" in event else event for event in self.EVENTS]
        self.assertEqual(len(watch_game.file_lines(events, {28152: FOLDER}, DRIVES)), 4)

    def test_paths(self) -> None:
        inside, outside = FOLDER + r"\out\probe_b.txt", r"\Device\HarddiskVolume3\WINDOWS\SYSTEM32\dxcore.dll"
        self.assertEqual(watch_game.file_path(inside, FOLDER, DRIVES), r"out\probe_b.txt")
        self.assertEqual(watch_game.file_path(inside.upper(), FOLDER, DRIVES), r"OUT\PROBE_B.TXT", "names are compared without case")
        self.assertEqual(watch_game.file_path(inside, "", DRIVES), r"X:\Sandbox\aeterna-d3d11\generated\lifted\etw_research\out\probe_b.txt")
        self.assertEqual(watch_game.file_path(FOLDER + "2\\file", FOLDER, DRIVES), r"X:\Sandbox\aeterna-d3d11\generated\lifted\etw_research2\file",
                         "a folder whose name merely begins the same is not the program's")
        self.assertEqual(watch_game.file_path(outside, FOLDER, DRIVES), r"C:\WINDOWS\SYSTEM32\dxcore.dll")
        self.assertEqual(watch_game.file_path(outside, FOLDER, {r"\Device\HarddiskVolume30": "Q:"}), outside, "no drive has that device")
        self.assertEqual(watch_game.file_path(r"\Device\HarddiskVolume30\file", FOLDER, DRIVES), r"\Device\HarddiskVolume30\file",
                         "a device whose name merely begins the same is not the drive's")


if __name__ == "__main__":
    unittest.main()
