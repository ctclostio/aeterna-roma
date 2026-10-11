#!/usr/bin/env python3
"""Supervisor-owned binary gate for the frozen guest32 dynamic probe.

This gate intentionally uses only the Python standard library.  It does not
load either artifact.  It parses their PE structures as inert bytes, validates
the frozen architecture/export/import/hardening contract, and authenticates
the pre-existing bootstrap artifacts by SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


EXPECTED_DLL_NAME = "rome2_guest32_probe64.dll"
EXPECTED_HOST_NAME = "rome2_guest32_probe_host64.exe"
EXPECTED_EXPORTS = (
    "Rome2Guest32ProbeAbiVersion",
    "Rome2Guest32ProbeSelectEntryPolicy",
)
EXPECTED_BOOTSTRAP_DLL_SHA256 = (
    "fa4c0584790894e85a60427e0cb6adbf1266d14ddc321c122206365bdca8e3a0"
)
EXPECTED_BOOTSTRAP_HOST_SHA256 = (
    "007b75d58e6cb6890d98b102f07fd2be353423c4f31af41f11c366679a567708"
)

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_32BIT_MACHINE = 0x0100
IMAGE_FILE_DLL = 0x2000
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
REQUIRED_DLL_CHARACTERISTICS = (
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    | IMAGE_DLLCHARACTERISTICS_GUARD_CF
)

IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400
IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x01
IMAGE_SCN_MEM_EXECUTE = 0x20000000

MAX_IMAGE_BYTES = 512 * 1024 * 1024
MAX_TABLE_ITEMS = 65536
MAX_STRING_BYTES = 4096


class GateFailure(Exception):
    """A deterministic malformed-image or policy failure."""


@dataclass(frozen=True)
class DataDirectory:
    rva: int
    size: int


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class Export:
    name: str
    ordinal: int
    rva: int
    forwarded: bool


@dataclass(frozen=True)
class Import:
    module: str
    symbol: str
    delayed: bool


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class PEImage:
    """Bounds-checked PE32+ reader."""

    def __init__(self, path: Path, data: bytes):
        self.path = path
        self.data = data
        self.machine = 0
        self.coff_characteristics = 0
        self.optional_magic = 0
        self.image_base = 0
        self.size_of_headers = 0
        self.subsystem = 0
        self.dll_characteristics = 0
        self.directories: list[DataDirectory] = []
        self.sections: list[Section] = []
        self._parse_headers()

    @classmethod
    def from_path(cls, path: Path) -> "PEImage":
        if not path.is_file() or path.is_symlink():
            raise GateFailure(f"not a regular artifact file: {path}")
        size = path.stat().st_size
        if size <= 0 or size > MAX_IMAGE_BYTES:
            raise GateFailure(f"artifact size outside gate bounds: {path} ({size} bytes)")
        return cls(path, path.read_bytes())

    def _range(self, offset: int, size: int, label: str) -> None:
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise GateFailure(
                f"{self.path.name}: {label} is outside the file "
                f"(offset={offset:#x}, size={size:#x})"
            )

    def _unpack(self, fmt: str, offset: int, label: str) -> tuple[int, ...]:
        size = struct.calcsize(fmt)
        self._range(offset, size, label)
        return struct.unpack_from(fmt, self.data, offset)

    def u16(self, offset: int, label: str) -> int:
        return self._unpack("<H", offset, label)[0]

    def u32(self, offset: int, label: str) -> int:
        return self._unpack("<I", offset, label)[0]

    def u64(self, offset: int, label: str) -> int:
        return self._unpack("<Q", offset, label)[0]

    def _parse_headers(self) -> None:
        self._range(0, 0x40, "DOS header")
        if self.data[:2] != b"MZ":
            raise GateFailure(f"{self.path.name}: missing MZ signature")
        pe_offset = self.u32(0x3C, "e_lfanew")
        self._range(pe_offset, 24, "PE signature and COFF header")
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise GateFailure(f"{self.path.name}: missing PE signature")

        coff = pe_offset + 4
        (
            self.machine,
            section_count,
            _timestamp,
            _symbol_offset,
            _symbol_count,
            optional_size,
            self.coff_characteristics,
        ) = self._unpack("<HHIIIHH", coff, "COFF header")
        if section_count <= 0 or section_count > 96:
            raise GateFailure(f"{self.path.name}: unreasonable section count {section_count}")
        if optional_size < 112:
            raise GateFailure(f"{self.path.name}: truncated PE32+ optional header")

        optional = coff + 20
        self._range(optional, optional_size, "optional header")
        self.optional_magic = self.u16(optional, "optional-header magic")
        self.image_base = self.u64(optional + 24, "image base")
        self.size_of_headers = self.u32(optional + 60, "SizeOfHeaders")
        self.subsystem = self.u16(optional + 68, "subsystem")
        self.dll_characteristics = self.u16(optional + 70, "DllCharacteristics")
        directory_count = self.u32(optional + 108, "NumberOfRvaAndSizes")
        available_directories = (optional_size - 112) // 8
        if directory_count > available_directories:
            raise GateFailure(f"{self.path.name}: data-directory array is truncated")
        if directory_count > 64:
            raise GateFailure(f"{self.path.name}: unreasonable data-directory count")
        for index in range(directory_count):
            rva, size = self._unpack(
                "<II", optional + 112 + index * 8, f"data directory {index}"
            )
            self.directories.append(DataDirectory(rva, size))

        section_table = optional + optional_size
        self._range(section_table, section_count * 40, "section table")
        for index in range(section_count):
            offset = section_table + index * 40
            raw_name = self.data[offset : offset + 8].split(b"\0", 1)[0]
            try:
                name = raw_name.decode("ascii", "strict")
            except UnicodeDecodeError as exc:
                raise GateFailure(f"{self.path.name}: non-ASCII section name") from exc
            virtual_size, virtual_address, raw_size, raw_offset = self._unpack(
                "<IIII", offset + 8, f"section {index} extent"
            )
            characteristics = self.u32(offset + 36, f"section {index} characteristics")
            if raw_size:
                self._range(raw_offset, raw_size, f"section {name} raw data")
            self.sections.append(
                Section(
                    name,
                    virtual_address,
                    virtual_size,
                    raw_offset,
                    raw_size,
                    characteristics,
                )
            )

    def directory(self, index: int) -> DataDirectory:
        if index >= len(self.directories):
            return DataDirectory(0, 0)
        return self.directories[index]

    def rva_to_offset(self, rva: int, size: int, label: str) -> int:
        if rva < self.size_of_headers:
            if size > self.size_of_headers - rva:
                raise GateFailure(
                    f"{self.path.name}: {label} crosses the PE-header boundary"
                )
            self._range(rva, size, label)
            return rva
        matches: list[int] = []
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta > section.raw_size or size > section.raw_size - delta:
                    raise GateFailure(
                        f"{self.path.name}: {label} falls in virtual-only section data"
                    )
                matches.append(section.raw_offset + delta)
        if len(matches) != 1:
            raise GateFailure(
                f"{self.path.name}: {label} RVA {rva:#x} maps to {len(matches)} sections"
            )
        self._range(matches[0], size, label)
        return matches[0]

    def section_for_rva(self, rva: int) -> Section | None:
        matches = [
            section
            for section in self.sections
            if section.virtual_address
            <= rva
            < section.virtual_address + max(section.virtual_size, section.raw_size)
        ]
        return matches[0] if len(matches) == 1 else None

    def c_string(self, rva: int, label: str) -> str:
        offset = self.rva_to_offset(rva, 1, label)
        end_limit = min(len(self.data), offset + MAX_STRING_BYTES)
        end = self.data.find(b"\0", offset, end_limit)
        if end < 0:
            raise GateFailure(f"{self.path.name}: unterminated {label}")
        try:
            return self.data[offset:end].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise GateFailure(f"{self.path.name}: non-ASCII {label}") from exc

    def exports(self) -> tuple[str | None, list[Export], int, int]:
        directory = self.directory(0)
        if not directory.rva and not directory.size:
            return None, [], 0, 0
        if not directory.rva or directory.size < 40:
            raise GateFailure(f"{self.path.name}: malformed export directory")
        offset = self.rva_to_offset(directory.rva, 40, "export directory")
        (
            _characteristics,
            _timestamp,
            _major,
            _minor,
            module_name_rva,
            ordinal_base,
            function_count,
            name_count,
            functions_rva,
            names_rva,
            ordinals_rva,
        ) = self._unpack("<IIHHIIIIIII", offset, "export directory")
        if function_count > MAX_TABLE_ITEMS or name_count > MAX_TABLE_ITEMS:
            raise GateFailure(f"{self.path.name}: unreasonable export table size")
        function_offset = self.rva_to_offset(
            functions_rva, function_count * 4, "export address table"
        )
        name_offset = self.rva_to_offset(names_rva, name_count * 4, "export name table")
        ordinal_offset = self.rva_to_offset(
            ordinals_rva, name_count * 2, "export ordinal table"
        )
        functions = [self.u32(function_offset + i * 4, "export RVA") for i in range(function_count)]
        result: list[Export] = []
        for index in range(name_count):
            name_rva = self.u32(name_offset + index * 4, "export-name RVA")
            ordinal_index = self.u16(ordinal_offset + index * 2, "export ordinal")
            if ordinal_index >= function_count:
                raise GateFailure(f"{self.path.name}: export ordinal is outside the table")
            function_rva = functions[ordinal_index]
            forwarded = directory.rva <= function_rva < directory.rva + directory.size
            result.append(
                Export(
                    self.c_string(name_rva, "export name"),
                    ordinal_base + ordinal_index,
                    function_rva,
                    forwarded,
                )
            )
        return (
            self.c_string(module_name_rva, "export module name"),
            result,
            function_count,
            name_count,
        )

    def _thunks(self, table_rva: int, module: str, delayed: bool) -> list[Import]:
        result: list[Import] = []
        for index in range(MAX_TABLE_ITEMS):
            offset = self.rva_to_offset(table_rva + index * 8, 8, "import thunk")
            value = self.u64(offset, "import thunk")
            if value == 0:
                return result
            if value & (1 << 63):
                symbol = f"#{value & 0xFFFF}"
            else:
                name_offset = self.rva_to_offset(value, 3, "import-by-name")
                symbol = self.c_string(value + 2, "import symbol")
                self.u16(name_offset, "import hint")
            result.append(Import(module, symbol, delayed))
        raise GateFailure(f"{self.path.name}: unterminated import thunk table")

    def imports(self) -> list[Import]:
        result: list[Import] = []
        regular = self.directory(1)
        if regular.rva or regular.size:
            if not regular.rva or regular.size < 20:
                raise GateFailure(f"{self.path.name}: malformed import directory")
            for index in range(min(MAX_TABLE_ITEMS, regular.size // 20 + 1)):
                offset = self.rva_to_offset(
                    regular.rva + index * 20, 20, "import descriptor"
                )
                original, timestamp, forwarder, name_rva, first_thunk = self._unpack(
                    "<IIIII", offset, "import descriptor"
                )
                if not any((original, timestamp, forwarder, name_rva, first_thunk)):
                    break
                if not name_rva or not first_thunk:
                    raise GateFailure(f"{self.path.name}: malformed import descriptor")
                module = self.c_string(name_rva, "import module")
                result.extend(self._thunks(original or first_thunk, module, False))
            else:
                raise GateFailure(f"{self.path.name}: unterminated import descriptor table")

        delayed = self.directory(13)
        if delayed.rva or delayed.size:
            if not delayed.rva or delayed.size < 32:
                raise GateFailure(f"{self.path.name}: malformed delay-import directory")
            for index in range(min(MAX_TABLE_ITEMS, delayed.size // 32 + 1)):
                offset = self.rva_to_offset(
                    delayed.rva + index * 32, 32, "delay-import descriptor"
                )
                fields = self._unpack("<IIIIIIII", offset, "delay-import descriptor")
                if not any(fields):
                    break
                attributes, name_value, _handle, _iat, int_value, _bound, _unload, _stamp = fields
                uses_rvas = bool(attributes & 1)
                if not uses_rvas:
                    if name_value < self.image_base or int_value < self.image_base:
                        raise GateFailure(f"{self.path.name}: invalid delay-import VA")
                    name_value -= self.image_base
                    int_value -= self.image_base
                module = self.c_string(name_value, "delay-import module")
                result.extend(self._thunks(int_value, module, True))
            else:
                raise GateFailure(f"{self.path.name}: unterminated delay-import table")
        return result

    def load_config(self) -> tuple[int, int]:
        directory = self.directory(10)
        if not directory.rva or directory.size < 148:
            raise GateFailure(f"{self.path.name}: missing complete x64 load-config directory")
        offset = self.rva_to_offset(directory.rva, 148, "load-config directory")
        declared_size = self.u32(offset, "load-config size")
        if declared_size < 148 or directory.size < 148:
            raise GateFailure(f"{self.path.name}: load-config directory lacks CFG fields")
        security_cookie = self.u64(offset + 88, "load-config security cookie")
        guard_flags = self.u32(offset + 144, "load-config GuardFlags")
        return security_cookie, guard_flags

    def cet_compatible(self) -> bool:
        directory = self.directory(6)
        if not directory.rva or directory.size < 28 or directory.size % 28:
            return False
        count = directory.size // 28
        if count > MAX_TABLE_ITEMS:
            raise GateFailure(f"{self.path.name}: unreasonable debug-directory count")
        offset = self.rva_to_offset(directory.rva, directory.size, "debug directory")
        for index in range(count):
            entry = offset + index * 28
            debug_type = self.u32(entry + 12, "debug type")
            data_size = self.u32(entry + 16, "debug data size")
            data_rva = self.u32(entry + 20, "debug data RVA")
            raw_offset = self.u32(entry + 24, "debug data file offset")
            if debug_type != IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS or data_size < 1:
                continue
            if raw_offset:
                self._range(raw_offset, data_size, "extended DLL characteristics")
                data_offset = raw_offset
            elif data_rva:
                data_offset = self.rva_to_offset(
                    data_rva, data_size, "extended DLL characteristics"
                )
            else:
                continue
            if self.data[data_offset] & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT:
                return True
        return False


ALLOWED_IMPORT_MODULES = {
    "kernel32.dll",
    "kernelbase.dll",
    "ucrtbase.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
}
ALLOWED_APISET_MODULE = re.compile(r"^(?:api|ext)-ms-win-(?:core|crt)-[a-z0-9-]+\.dll$")
FORBIDDEN_IMPORT_SYMBOLS = (
    re.compile(r"^Reg[A-Z]"),
    re.compile(r"^(?:Co|Ole)(?:Initialize|Create|Get|Set|Register|Revoke|Uninitialize)"),
    re.compile(
        r"^(?:CreateProcess|OpenProcess|CreateRemoteThread|CreateRemoteThreadEx|"
        r"ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualProtectEx|"
        r"SetThreadContext|QueueUserAPC|WinExec|ShellExecute|SetWindowsHookEx)"
    ),
    re.compile(r"^(?:WSA|socket$|connect$|listen$|accept$|send$|recv$|WinHttp|Internet)"),
)
FORBIDDEN_BINARY_MARKERS = (
    b"empire.retail.dll",
    b"Total War Rome II",
    b"entry_point",
    b"Rome2PortAbiVersion",
    b"Rome2PortCanonicalFingerprint",
    b"Rome2PortStatus",
    b"ported_1093c450",
    b"rome2_port_1093c450",
    b"100e81a0",
    b"100ed3c0",
    b"steam_api",
    b"bink",
    b"miles",
)


def _module_allowed(module: str) -> bool:
    lowered = module.casefold()
    return lowered in ALLOWED_IMPORT_MODULES or bool(ALLOWED_APISET_MODULE.fullmatch(lowered))


def _check_imports(image: PEImage, role: str, failures: list[str]) -> list[Import]:
    try:
        imports = image.imports()
    except GateFailure as exc:
        failures.append(str(exc))
        return []
    for item in imports:
        if not _module_allowed(item.module):
            failures.append(
                f"{image.path.name}: {role} imports non-allowlisted module {item.module}"
            )
        if item.symbol.startswith("#"):
            failures.append(
                f"{image.path.name}: ordinal import is not auditable: {item.module}!{item.symbol}"
            )
        for pattern in FORBIDDEN_IMPORT_SYMBOLS:
            if pattern.search(item.symbol):
                failures.append(
                    f"{image.path.name}: forbidden surface imported: "
                    f"{item.module}!{item.symbol}"
                )
                break
    names = {item.symbol for item in imports}
    if role == "host":
        if not ({"LoadLibraryExA", "LoadLibraryExW"} & names):
            failures.append(f"{image.path.name}: host does not import LoadLibraryExA/W")
        for required in ("GetProcAddress", "FreeLibrary"):
            if required not in names:
                failures.append(f"{image.path.name}: host does not import {required}")
    # Normal static CRT startup itself imports several loader and filesystem
    # functions (the frozen bootstrap provides the toolchain baseline).  Their
    # presence cannot prove user-code behavior, so the binary gate limits those
    # surfaces by module allowlist while hidden_static_gate.py rejects direct
    # probe-source calls.
    return imports


def _check_image(path: Path, role: str) -> tuple[list[str], dict[str, object]]:
    failures: list[str] = []
    summary: dict[str, object] = {"path": str(path), "role": role}
    try:
        image = PEImage.from_path(path)
    except (OSError, GateFailure) as exc:
        return [str(exc)], summary

    summary.update(
        {
            "sha256": _sha256(path),
            "machine": f"0x{image.machine:04x}",
            "optional_magic": f"0x{image.optional_magic:03x}",
            "dll_characteristics": f"0x{image.dll_characteristics:04x}",
        }
    )
    expected_name = EXPECTED_DLL_NAME if role == "dll" else EXPECTED_HOST_NAME
    if path.name.casefold() != expected_name.casefold():
        failures.append(f"{path.name}: artifact name must be {expected_name}")
    if image.machine != IMAGE_FILE_MACHINE_AMD64:
        failures.append(f"{path.name}: Machine is not AMD64 (0x8664)")
    if image.optional_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        failures.append(f"{path.name}: image is not PE32+")
    if image.subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI:
        failures.append(f"{path.name}: subsystem is not Windows CUI")
    if not image.coff_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE:
        failures.append(f"{path.name}: image lacks executable-image characteristic")
    if not image.coff_characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE:
        failures.append(f"{path.name}: image is not large-address aware")
    if image.coff_characteristics & IMAGE_FILE_32BIT_MACHINE:
        failures.append(f"{path.name}: image carries the 32-bit-machine characteristic")
    is_dll = bool(image.coff_characteristics & IMAGE_FILE_DLL)
    if is_dll != (role == "dll"):
        failures.append(f"{path.name}: DLL/EXE COFF identity does not match its role")
    missing_hardening = REQUIRED_DLL_CHARACTERISTICS & ~image.dll_characteristics
    if missing_hardening:
        failures.append(
            f"{path.name}: missing required DllCharacteristics bits 0x{missing_hardening:04x}"
        )
    if not image.directory(5).rva or not image.directory(5).size:
        failures.append(f"{path.name}: base-relocation directory is absent")
    if image.directory(14).rva or image.directory(14).size:
        failures.append(f"{path.name}: managed/COM descriptor is forbidden")
    try:
        security_cookie, guard_flags = image.load_config()
        summary["guard_flags"] = f"0x{guard_flags:08x}"
        if not security_cookie:
            failures.append(f"{path.name}: load config has no /GS security cookie")
        if not guard_flags & IMAGE_GUARD_CF_INSTRUMENTED:
            failures.append(f"{path.name}: load config does not prove CFG instrumentation")
        if guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT:
            summary["cfg_function_table"] = "present"
        else:
            summary["cfg_function_table"] = "not-required-or-empty"
    except GateFailure as exc:
        failures.append(str(exc))
    try:
        cet = image.cet_compatible()
        summary["cet_compatible"] = cet
        if not cet:
            failures.append(f"{path.name}: /CETCOMPAT metadata is absent")
    except GateFailure as exc:
        failures.append(str(exc))

    try:
        export_module, exports, function_count, name_count = image.exports()
        summary["exports"] = sorted(item.name for item in exports)
        if role == "dll":
            actual = tuple(sorted(item.name for item in exports))
            if actual != tuple(sorted(EXPECTED_EXPORTS)):
                failures.append(
                    f"{path.name}: named exports must be exactly {', '.join(EXPECTED_EXPORTS)}"
                )
            if function_count != 2 or name_count != 2 or len(exports) != 2:
                failures.append(f"{path.name}: ordinal-only, null, duplicate, or extra exports exist")
            if len({item.ordinal for item in exports}) != len(exports):
                failures.append(f"{path.name}: exported names do not map one-to-one to functions")
            if len({item.rva for item in exports}) != len(exports):
                failures.append(f"{path.name}: exported names share a function RVA")
            for item in exports:
                if item.forwarded:
                    failures.append(f"{path.name}: forwarded export is forbidden: {item.name}")
                if not item.rva:
                    failures.append(f"{path.name}: null export RVA: {item.name}")
                section = image.section_for_rva(item.rva)
                if section is None or not section.characteristics & IMAGE_SCN_MEM_EXECUTE:
                    failures.append(f"{path.name}: export is not backed by executable code: {item.name}")
            accepted_module_names = {
                EXPECTED_DLL_NAME.casefold(),
                Path(EXPECTED_DLL_NAME).stem.casefold(),
            }
            if export_module is None or export_module.casefold() not in accepted_module_names:
                failures.append(f"{path.name}: export-directory module name is not frozen DLL name")
        elif function_count or name_count or exports:
            failures.append(f"{path.name}: host executable must not export symbols")
    except GateFailure as exc:
        failures.append(str(exc))

    imports = _check_imports(image, role, failures)
    summary["imports"] = sorted(
        f"{item.module}!{item.symbol}{' (delay)' if item.delayed else ''}" for item in imports
    )
    lowered = image.data.lower()
    for marker in FORBIDDEN_BINARY_MARKERS:
        if marker.lower() in lowered:
            failures.append(
                f"{path.name}: forbidden original/middleware/legacy marker present: "
                f"{marker.decode('ascii')}"
            )
        wide = b"".join(bytes((byte, 0)) for byte in marker.lower())
        if wide in lowered:
            failures.append(
                f"{path.name}: forbidden UTF-16 original/middleware/legacy marker present: "
                f"{marker.decode('ascii')}"
            )
    return failures, summary


def _authenticate(path: Path, expected: str, label: str, failures: list[str]) -> dict[str, object]:
    result: dict[str, object] = {"path": str(path), "label": label}
    if not path.is_file() or path.is_symlink():
        failures.append(f"{label}: not a regular file: {path}")
        return result
    actual = _sha256(path)
    result["sha256"] = actual
    if actual != expected:
        failures.append(f"{label}: SHA-256 changed (expected {expected}, found {actual})")
    return result


def _build_synthetic_export_pe(
    names: Sequence[str], forwarded: bool = False, shared_rva: bool = False
) -> bytes:
    """Build a tiny inert PE fixture used only to self-test export parsing."""
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        IMAGE_FILE_MACHINE_AMD64,
        1,
        0,
        0,
        0,
        0xF0,
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    struct.pack_into("<I", data, optional + 16, 0x1020)
    struct.pack_into("<Q", data, optional + 24, 0x180000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", data, optional + 68, 3, REQUIRED_DLL_CHARACTERISTICS)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112, 0x1100, 0x300)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)

    export_offset = 0x300
    count = len(names)
    function_rva = 0x1140
    name_table_rva = 0x1180
    ordinal_table_rva = 0x11C0
    module_rva = 0x1200
    strings_rva = 0x1240
    struct.pack_into(
        "<IIHHIIIIIII",
        data,
        export_offset,
        0,
        0,
        0,
        0,
        module_rva,
        1,
        count,
        count,
        function_rva,
        name_table_rva,
        ordinal_table_rva,
    )
    module_offset = 0x200 + (module_rva - 0x1000)
    data[module_offset : module_offset + len(EXPECTED_DLL_NAME) + 1] = (
        EXPECTED_DLL_NAME.encode("ascii") + b"\0"
    )
    cursor_rva = strings_rva
    for index, name in enumerate(names):
        function = 0x1500 if shared_rva else 0x1500 + index * 0x10
        if forwarded and index == 0:
            function = 0x13D0
        struct.pack_into("<I", data, 0x200 + function_rva - 0x1000 + index * 4, function)
        struct.pack_into("<I", data, 0x200 + name_table_rva - 0x1000 + index * 4, cursor_rva)
        struct.pack_into("<H", data, 0x200 + ordinal_table_rva - 0x1000 + index * 2, index)
        cursor = 0x200 + cursor_rva - 0x1000
        encoded = name.encode("ascii") + b"\0"
        data[cursor : cursor + len(encoded)] = encoded
        cursor_rva += len(encoded)
    if forwarded:
        forward_offset = 0x200 + 0x13D0 - 0x1000
        data[forward_offset : forward_offset + 15] = b"other.Target\0\0\0"
    return bytes(data)


def _self_test() -> None:
    fixture = PEImage(Path("synthetic.dll"), _build_synthetic_export_pe(EXPECTED_EXPORTS))
    module, exports, functions, names = fixture.exports()
    assert module == EXPECTED_DLL_NAME
    assert functions == names == 2
    assert tuple(sorted(item.name for item in exports)) == tuple(sorted(EXPECTED_EXPORTS))
    assert not any(item.forwarded for item in exports)

    mutant = PEImage(
        Path("synthetic-extra.dll"),
        _build_synthetic_export_pe((*EXPECTED_EXPORTS, "LegacyAlias")),
    )
    assert mutant.exports()[2:] == (3, 3)
    forwarder = PEImage(
        Path("synthetic-forwarder.dll"),
        _build_synthetic_export_pe(EXPECTED_EXPORTS, forwarded=True),
    )
    assert any(item.forwarded for item in forwarder.exports()[1])
    shared = PEImage(
        Path("synthetic-shared-rva.dll"),
        _build_synthetic_export_pe(EXPECTED_EXPORTS, shared_rva=True),
    )
    assert len({item.rva for item in shared.exports()[1]}) == 1
    assert _module_allowed("KERNEL32.dll")
    assert _module_allowed("api-ms-win-crt-runtime-l1-1-0.dll")
    assert not _module_allowed("winhttp.dll")
    assert any(pattern.search("CreateProcessW") for pattern in FORBIDDEN_IMPORT_SYMBOLS)
    assert any(pattern.search("WriteProcessMemory") for pattern in FORBIDDEN_IMPORT_SYMBOLS)
    try:
        PEImage(Path("truncated.dll"), b"MZ")
    except GateFailure:
        pass
    else:
        raise AssertionError("truncated PE mutant was accepted")
    print("hidden PE gate self-test passed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, help=f"path to {EXPECTED_DLL_NAME}")
    parser.add_argument("--host", type=Path, help=f"path to {EXPECTED_HOST_NAME}")
    parser.add_argument("--bootstrap-dll", type=Path, help="frozen empire.retail64.dll")
    parser.add_argument("--bootstrap-host", type=Path, help="frozen rome2_host64.exe")
    parser.add_argument("--self-test", action="store_true", help="run synthetic parser mutants")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.self_test:
        if any((args.dll, args.host, args.bootstrap_dll, args.bootstrap_host)):
            parser.error("--self-test cannot be combined with artifact paths")
        _self_test()
        return 0
    missing = [
        option
        for option, value in (
            ("--dll", args.dll),
            ("--host", args.host),
            ("--bootstrap-dll", args.bootstrap_dll),
            ("--bootstrap-host", args.bootstrap_host),
        )
        if value is None
    ]
    if missing:
        parser.error("required arguments: " + ", ".join(missing))

    failures: list[str] = []
    dll_failures, dll_summary = _check_image(args.dll, "dll")
    host_failures, host_summary = _check_image(args.host, "host")
    failures.extend(dll_failures)
    failures.extend(host_failures)
    bootstrap = [
        _authenticate(
            args.bootstrap_dll,
            EXPECTED_BOOTSTRAP_DLL_SHA256,
            "bootstrap DLL",
            failures,
        ),
        _authenticate(
            args.bootstrap_host,
            EXPECTED_BOOTSTRAP_HOST_SHA256,
            "bootstrap host",
            failures,
        ),
    ]
    result = {
        "gate": "hidden_pe_gate_v1",
        "passed": not failures,
        "artifacts": [dll_summary, host_summary],
        "bootstrap": bootstrap,
        "failures": failures,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, GateFailure, AssertionError) as exc:
        print(f"hidden PE gate infrastructure failure: {exc}", file=sys.stderr)
        raise SystemExit(2)

