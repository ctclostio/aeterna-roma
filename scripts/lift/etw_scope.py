"""Event Tracing for Windows sessions scoped to one executable name, and the process calls scripts/lift/watch_game.py needs.

logman and the EventTracingManagement PowerShell cmdlets cannot scope a provider to a program, so this calls advapi32
directly: StartTraceW opens a session, EnableTraceEx2 enables a provider in it with an EVENT_FILTER_DESCRIPTOR of type
EVENT_FILTER_TYPE_EXECUTABLE_NAME, ControlTraceW queries, flushes and stops it. Structures and constants are those of
the Windows SDK 10.0.26100.0 headers shared/evntrace.h, shared/evntprov.h, shared/wmistr.h, um/tlhelp32.h and
um/wow64apiset.h; the layouts below are the 64-bit ones and their sizes are asserted. Standard library only.

A session belongs to the kernel, not to the process that opened it: it stays open when that process ends, until it is
stopped by name or the machine restarts. Opening, querying and stopping one need an elevated prompt.

Measured on Windows 11 build 26300 with stand-in programs (port/lifted_live/test_d3d_probe.c and its predecessor):

  - The name filter works for the user-mode providers Microsoft-Windows-DXGI and Microsoft-Windows-Direct3D11: the
    named program's events are all there from its first DXGI call, no other program's are. A process of that name
    already running when the session opens is recorded from that moment on.
  - The name is the image file name with its extension, compared without case: no folder, no wildcard. A name that
    matches nothing is accepted and records nothing.
  - The kernel-mode provider Microsoft-Windows-Kernel-File ignores the filter and reports every program.
  - The session settings here (256 KiB buffers shared by all processors, at most 256 of them, a compressed sequential
    file, a flush every second) lost nothing when 8 threads wrote 320,251 events in a third of a second. An idle
    session holds 2 buffers and a 262,144-byte file.
  - A compressed file cannot be decoded until its session has stopped: tracerpt reports success and no events.
  - StartTraceW replaces an existing trace file without a word: every session needs a new file name.

What `python scripts/lift/watch_game.py selftest` exercises of this file, and what no run has, is listed at its end.
"""
from __future__ import annotations

import ctypes
import os
import time
import uuid
from ctypes import wintypes

if ctypes.sizeof(ctypes.c_void_p) != 8:
    raise ImportError("etw_scope.py needs a 64-bit Python: the structure layouts here are the 64-bit ones")

ULONG = ctypes.c_uint32
ULONG64 = ctypes.c_uint64

# shared/evntprov.h
EVENT_FILTER_TYPE_EXECUTABLE_NAME = 0x80000008
# shared/evntrace.h
EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001
EVENT_TRACE_COMPRESSED_MODE = 0x04000000             # the file is compressed; tracerpt reads it like any other
EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000  # one set of buffers for all processors
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_FLUSH = 3
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
ENABLE_TRACE_PARAMETERS_VERSION_2 = 2
# shared/wmistr.h
WNODE_FLAG_TRACED_GUID = 0x00020000
# shared/winerror.h
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_MORE_DATA = 234
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
# um/tlhelp32.h, um/winnt.h, um/winbase.h
TH32CS_SNAPPROCESS = 0x00000002
SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_NAME_NATIVE = 0x00000001
IMAGE_FILE_MACHINE_UNKNOWN = 0
WAIT_OBJECT_0 = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Providers, as `logman query providers <name>` gives their ids.
DXGI = "{CA11C036-0102-4A2D-A6AD-F03CFED5D3C9}"         # Microsoft-Windows-DXGI
DIRECT3D11 = "{DB6F6DDB-AC77-4E88-8253-819DF9BBF140}"   # Microsoft-Windows-Direct3D11
KERNEL_FILE = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"  # Microsoft-Windows-Kernel-File
FILE_CREATE = 0x80                                      # its keyword KERNEL_FILE_KEYWORD_CREATE: event 12, a file being opened
ALL_KEYWORDS = 0xFFFFFFFFFFFFFFFF
ALL_LEVELS = 0xFF


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class WNODE_HEADER(ctypes.Structure):  # shared/wmistr.h; 48 bytes
    _fields_ = [("BufferSize", ULONG), ("ProviderId", ULONG), ("HistoricalContext", ULONG64), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ClientContext", ULONG), ("Flags", ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):  # shared/evntrace.h; 120 bytes
    _fields_ = [("Wnode", WNODE_HEADER),
                ("BufferSize", ULONG), ("MinimumBuffers", ULONG), ("MaximumBuffers", ULONG), ("MaximumFileSize", ULONG),
                ("LogFileMode", ULONG), ("FlushTimer", ULONG), ("EnableFlags", ULONG), ("AgeLimit", ctypes.c_int32),
                ("NumberOfBuffers", ULONG), ("FreeBuffers", ULONG), ("EventsLost", ULONG), ("BuffersWritten", ULONG),
                ("LogBuffersLost", ULONG), ("RealTimeBuffersLost", ULONG), ("LoggerThreadId", wintypes.HANDLE),
                ("LogFileNameOffset", ULONG), ("LoggerNameOffset", ULONG)]


class Properties(ctypes.Structure):
    """EVENT_TRACE_PROPERTIES and, behind it, the two strings it refers to by offset."""
    _fields_ = [("p", EVENT_TRACE_PROPERTIES), ("LoggerName", ctypes.c_wchar * 1024), ("LogFileName", ctypes.c_wchar * 1024)]


class EVENT_FILTER_DESCRIPTOR(ctypes.Structure):  # shared/evntprov.h; 16 bytes
    _fields_ = [("Ptr", ULONG64), ("Size", ULONG), ("Type", ULONG)]


class ENABLE_TRACE_PARAMETERS(ctypes.Structure):  # shared/evntrace.h, version 2; 48 bytes
    _fields_ = [("Version", ULONG), ("EnableProperty", ULONG), ("ControlFlags", ULONG), ("SourceId", GUID),
                ("EnableFilterDesc", ctypes.POINTER(EVENT_FILTER_DESCRIPTOR)), ("FilterDescCount", ULONG)]


class PROCESSENTRY32W(ctypes.Structure):  # um/tlhelp32.h
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


assert ctypes.sizeof(WNODE_HEADER) == 48 and ctypes.sizeof(EVENT_TRACE_PROPERTIES) == 120
assert ctypes.sizeof(EVENT_FILTER_DESCRIPTOR) == 16 and ctypes.sizeof(ENABLE_TRACE_PARAMETERS) == 48

advapi32 = ctypes.WinDLL("advapi32")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32.StartTraceW.argtypes = [ctypes.POINTER(ULONG64), wintypes.LPCWSTR, ctypes.POINTER(Properties)]
advapi32.StartTraceW.restype = ULONG
advapi32.EnableTraceEx2.argtypes = [ULONG64, ctypes.POINTER(GUID), ULONG, ctypes.c_ubyte, ULONG64, ULONG64, ULONG,
                                    ctypes.POINTER(ENABLE_TRACE_PARAMETERS)]
advapi32.EnableTraceEx2.restype = ULONG
advapi32.ControlTraceW.argtypes = [ULONG64, wintypes.LPCWSTR, ctypes.POINTER(Properties), ULONG]
advapi32.ControlTraceW.restype = ULONG
advapi32.QueryAllTracesW.argtypes = [ctypes.POINTER(ctypes.POINTER(Properties)), ULONG, ctypes.POINTER(ULONG)]
advapi32.QueryAllTracesW.restype = ULONG
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ULONG64)] * 4  # FILETIME: 100 ns units since 1601
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenMutexW.restype = wintypes.HANDLE
kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]


class TraceError(OSError):
    def __init__(self, what: str, code: int):
        super().__init__(code, f"{what}: {ctypes.FormatError(code).strip()} (error {code})")
        self.code = code


def _properties() -> Properties:
    props = Properties()
    props.p.Wnode.BufferSize = ctypes.sizeof(props)
    props.p.LoggerNameOffset = Properties.LoggerName.offset
    props.p.LogFileNameOffset = Properties.LogFileName.offset
    return props


def start_session(name: str, etl: str, max_file_mb: int = 0) -> int:
    """Opens a session that writes to the file `etl` (REPLACED if it exists) and returns its id for enable_provider.

    Nothing is recorded until a provider is enabled. max_file_mb: the session closes itself when its file has
    reached this size (0: no limit). TraceError.code is ERROR_ALREADY_EXISTS when a session of this name is open
    and ERROR_ACCESS_DENIED when the prompt is not elevated.
    """
    props = _properties()
    props.p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    props.p.Wnode.ClientContext = 1  # time stamps from the performance counter
    props.p.BufferSize = 256         # KiB
    props.p.MaximumBuffers = 256     # what the session may grow to in a burst; Windows' own choice (24) was too few
    props.p.MaximumFileSize = max_file_mb
    props.p.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING | EVENT_TRACE_COMPRESSED_MODE
    props.p.FlushTimer = 1           # seconds an event may wait in a buffer that is not full
    props.LogFileName = os.path.abspath(etl)
    handle = ULONG64(0)
    status = advapi32.StartTraceW(ctypes.byref(handle), name, ctypes.byref(props))
    if status:
        raise TraceError(f"StartTraceW({name})", status)
    return handle.value


def enable_provider(handle: int, provider: str, keywords: int = ALL_KEYWORDS, exe_name: str = "") -> None:
    """Enables a provider in the session, for every program or only for those whose image file has this name.

    exe_name: the file name with its extension and without a folder ("Rome2.exe"), compared without case. Windows
    leaves the provider switched off in every other program. Kernel-mode providers ignore the filter.
    """
    params = ENABLE_TRACE_PARAMETERS()
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2
    if exe_name:
        text = ctypes.create_unicode_buffer(exe_name)  # the filter's data: the name with its NUL
        descriptor = EVENT_FILTER_DESCRIPTOR(ctypes.addressof(text), ctypes.sizeof(text), EVENT_FILTER_TYPE_EXECUTABLE_NAME)
        params.EnableFilterDesc = ctypes.pointer(descriptor)
        params.FilterDescCount = 1
    source = GUID.from_buffer_copy(uuid.UUID(provider).bytes_le)
    status = advapi32.EnableTraceEx2(handle, ctypes.byref(source), EVENT_CONTROL_CODE_ENABLE_PROVIDER, ALL_LEVELS, keywords, 0, 0,
                                     ctypes.byref(params))
    if status:
        raise TraceError(f"EnableTraceEx2({provider})", status)


def _control(name: str, code: int) -> Properties | None:
    props = _properties()
    status = advapi32.ControlTraceW(0, name, ctypes.byref(props), code)
    if status == ERROR_WMI_INSTANCE_NOT_FOUND:
        return None
    if status and status != ERROR_MORE_DATA:  # ERROR_MORE_DATA: done, but a name did not fit the buffer
        raise TraceError(f"ControlTraceW({name}, {code})", status)
    return props


def query_session(name: str) -> Properties | None:
    """The session's file (LogFileName) and counters (p.EventsLost, p.BuffersWritten); None when no such session is open."""
    return _control(name, EVENT_TRACE_CONTROL_QUERY)


def flush_session(name: str) -> Properties | None:
    """Writes the session's waiting events to its file now; returns what query_session does."""
    return _control(name, EVENT_TRACE_CONTROL_FLUSH)


def stop_session(name: str) -> Properties | None:
    """Closes the session and its file; the counters returned are final. None when no such session is open."""
    return _control(name, EVENT_TRACE_CONTROL_STOP)


def list_sessions(prefix: str) -> list[tuple[str, str]]:
    """(name, file) of every open session whose name begins with the prefix, compared without case."""
    blocks = [_properties() for _ in range(256)]
    pointers = (ctypes.POINTER(Properties) * len(blocks))(*(ctypes.pointer(b) for b in blocks))
    count = ULONG(0)
    status = advapi32.QueryAllTracesW(pointers, len(blocks), ctypes.byref(count))
    if status and status != ERROR_MORE_DATA:
        raise TraceError("QueryAllTracesW", status)
    return [(b.LoggerName, b.LogFileName) for b in blocks[:count.value] if b.LoggerName.lower().startswith(prefix.lower())]


def find_processes(exe_name: str) -> list[int]:
    """The ids of the running processes whose image file has this name (compared without case)."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (None, INVALID_HANDLE_VALUE):
        raise ctypes.WinError(ctypes.get_last_error())
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    found, wanted = [], exe_name.lower()
    more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
    while more:
        if entry.szExeFile.lower() == wanted:
            found.append(entry.th32ProcessID)
        more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    kernel32.CloseHandle(snapshot)
    return found


def image_path(handle: int) -> str:
    r"""The process's image file as the kernel names it (\Device\HarddiskVolume5\folder\name.exe), which is how
    Microsoft-Windows-Kernel-File names files too; empty when Windows does not tell."""
    path = ctypes.create_unicode_buffer(1024)
    size = wintypes.DWORD(len(path))
    return path.value if kernel32.QueryFullProcessImageNameW(handle, PROCESS_NAME_NATIVE, path, ctypes.byref(size)) else ""


def open_process(pid: int, exe_name: str) -> int | None:
    """A handle to wait on and ask about (close it with close_handle), or None when the process is gone or its id
    now belongs to another program. The handle allows nothing else: no access to the process's memory."""
    handle = kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle and os.path.basename(image_path(handle)).lower() != exe_name.lower():
        kernel32.CloseHandle(handle)
        return None
    return handle


def close_handle(handle: int) -> None:
    kernel32.CloseHandle(handle)


def process_bits(handle: int) -> int:
    """32 for a 32-bit program on 64-bit Windows, else 64 (IsWow64Process2)."""
    machine, native = ctypes.c_ushort(0), ctypes.c_ushort(0)
    if not kernel32.IsWow64Process2(handle, ctypes.byref(machine), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    return 64 if machine.value == IMAGE_FILE_MACHINE_UNKNOWN else 32


def process_age(handle: int) -> float:
    """Seconds since the process was created."""
    created, ended, kernel, user = (ULONG64(0) for _ in range(4))
    if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(ended), ctypes.byref(kernel), ctypes.byref(user)):
        raise ctypes.WinError(ctypes.get_last_error())
    return time.time() - (created.value - 116444736000000000) / 1e7  # 1601 to 1970 in 100 ns units


def wait_exit(handle: int, milliseconds: int) -> bool:
    """True when the process has ended; waits at most this long without using the processor."""
    return kernel32.WaitForSingleObject(handle, milliseconds) == WAIT_OBJECT_0


def claim(name: str) -> int | None:
    """Creates the named mutex and returns its handle, or None when it exists: one holder at a time on this machine.
    Windows removes the mutex when the holder's process ends, however it ends."""
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, False, name)
    if handle and ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def claimed(name: str) -> bool:
    """Whether some process holds the mutex of this name."""
    handle = kernel32.OpenMutexW(SYNCHRONIZE, False, name)
    if handle:
        kernel32.CloseHandle(handle)
    return bool(handle)


def drive_devices() -> dict[str, str]:
    r"""Device -> drive letter for every drive that has a letter, as \Device\HarddiskVolume5 -> X: (QueryDosDeviceW):
    the way back from the kernel's name of a file to the one a user reads."""
    out = {}
    target = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if kernel32.QueryDosDeviceW(letter + ":", target, len(target)):
            out[target.value] = letter + ":"
    return out


# What `python scripts/lift/watch_game.py selftest` exercises here (Windows 11 build 26300, elevated, Python 3.15):
#   start_session without a size limit and with one that is not reached; enable_provider with a name (DXGI,
#   Direct3D 11) and without (Kernel-File, FILE_CREATE); query_session, flush_session and stop_session of an open
#   session, query_session and stop_session of one that is not; list_sessions; find_processes with and without a
#   match; open_process, image_path, process_bits (a 32-bit and a 64-bit program), process_age, wait_exit (ended
#   and not), close_handle; claim (free and held), claimed (held and not); drive_devices.
# By hand: a session with a limit of 1 MB closed itself at 1,039,620 bytes and its file was decoded (23,064
#   events); open_process gave None for a process id of another name, for one that does not exist and for a
#   process Windows refused to open (an empty access list on it, the caller's debug privilege off). In a process
#   whose token has the Administrators group for denying only: start_session, and query_session, flush_session and
#   stop_session of an open session, raised TraceError with ERROR_ACCESS_DENIED; query_session and stop_session of
#   a session that is not open gave None, and find_processes and claimed worked.
# No run has: raised a TraceError for a session name in use; met ERROR_MORE_DATA, more than 256 open sessions or
#   a process Windows opens but refuses to tell about; imported this in a 32-bit Python.
