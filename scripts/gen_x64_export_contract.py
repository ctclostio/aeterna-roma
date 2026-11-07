#!/usr/bin/env python3
"""Extract and verify the lossless Rome II DLL export contract.

The PE export directory is authoritative for ordinals, names, and RVAs.  The
canonical Ghidra indices are used as an exact join: every exported address must
resolve to one canonical function or data symbol, and the PE section flags must
agree with that classification.

This script intentionally emits only a manifest and a linker-definition
blueprint.  It does not invent prototypes, storage, or executable stubs.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import string
import struct
import sys
import tempfile
from typing import Iterable, Mapping, Sequence


SCHEMA = "rome2-x64-export-contract-v1"
MANIFEST_NAME = "export_manifest.tsv"
DEF_NAME = "empire.retail.exports.def"
METADATA_NAME = "export_contract.json"

REAL_DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
REAL_FUNCTION_INDEX_SHA256 = "bf2229bc61da7aa56fb5fa79844cc4ef25ec9df0a6428487ede4959145b2b244"
REAL_DATA_INDEX_SHA256 = "7fe15fe708fd4c87dbb2142f50a7a7bae1db730138807b9637b74cd66f974adb"
REAL_SNAPSHOT_SHA256 = "c33b7dc26fae0f04f4f6de4fa186c282eb0559f7f218730e360e64570fedf972"
REAL_MAPPING_FINGERPRINT = "f0caa97fbcb663124542c80eaebc440031e3d65708ec0630678beb77d85a884a"

FUNCTION_HEADER = (
    "entry",
    "canonical_name",
    "original_name",
    "original_qualified_name",
    "symbol_id",
    "namespace_id",
    "source_type",
    "signature",
    "size",
    "kind",
    "body_ranges",
    "direct_thunk_target",
    "resolved_thunk_target",
)
DATA_HEADER = (
    "address",
    "canonical_name",
    "original_name",
    "original_qualified_name",
    "symbol_id",
    "namespace_id",
    "source_type",
    "symbol_type",
    "data_type_path",
    "data_type_length",
    "code_unit_length",
)
SNAPSHOT_HEADER = (
    "format",
    "executable_sha256",
    "mapping_fingerprint",
    "functions",
    "data_symbols",
)
MANIFEST_HEADER = (
    "ordinal",
    "eat_index",
    "name_hint",
    "export_name",
    "name_rva",
    "target_rva",
    "target_va",
    "target_section",
    "target_section_characteristics",
    "target_kind",
    "target_symbol",
    "canonical_name",
    "canonical_symbol_id",
    "canonical_source_type",
    "canonical_original_qualified_name",
)

IMAGE_FILE_MACHINE_I386 = 0x014C
PE32_MAGIC = 0x010B
IMAGE_SCN_MEM_EXECUTE = 0x20000000


class ContractError(ValueError):
    """An input cannot represent the reviewed export contract."""


@dataclasses.dataclass(frozen=True)
class InputPolicy:
    dll_sha256: str
    function_index_sha256: str
    data_index_sha256: str
    snapshot_sha256: str
    executable_sha256: str
    mapping_fingerprint: str
    function_rows: int
    data_rows: int
    export_rows: int | None = None
    ordinal_base: int | None = None
    dll_name: str | None = None
    machine: int = IMAGE_FILE_MACHINE_I386
    optional_magic: int = PE32_MAGIC


REAL_POLICY = InputPolicy(
    dll_sha256=REAL_DLL_SHA256,
    function_index_sha256=REAL_FUNCTION_INDEX_SHA256,
    data_index_sha256=REAL_DATA_INDEX_SHA256,
    snapshot_sha256=REAL_SNAPSHOT_SHA256,
    executable_sha256=REAL_DLL_SHA256,
    mapping_fingerprint=REAL_MAPPING_FINGERPRINT,
    function_rows=81280,
    data_rows=2750,
    export_rows=522,
    ordinal_base=1,
    dll_name="empire.retail.dll",
)


@dataclasses.dataclass(frozen=True)
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclasses.dataclass(frozen=True)
class PeExport:
    ordinal: int
    eat_index: int
    name_hint: int
    name: str
    name_rva: int
    rva: int
    section: Section


@dataclasses.dataclass(frozen=True)
class PeInfo:
    machine: int
    optional_magic: int
    image_base: int
    size_of_image: int
    size_of_headers: int
    coff_timestamp: int
    export_characteristics: int
    export_timestamp: int
    export_major_version: int
    export_minor_version: int
    dll_name: str
    export_rva: int
    export_size: int
    ordinal_base: int
    function_count: int
    name_count: int
    eat_rva: int
    name_table_rva: int
    ordinal_table_rva: int
    sections: tuple[Section, ...]
    exports: tuple[PeExport, ...]


@dataclasses.dataclass(frozen=True)
class ContractRow:
    ordinal: int
    eat_index: int
    name_hint: int
    export_name: str
    name_rva: int
    target_rva: int
    target_va: int
    target_section: str
    target_section_characteristics: int
    target_kind: str
    target_symbol: str
    canonical_name: str
    canonical_symbol_id: str
    canonical_source_type: str
    canonical_original_qualified_name: str


@dataclasses.dataclass(frozen=True)
class ArtifactSet:
    manifest: bytes
    def_blueprint: bytes
    metadata: bytes
    rows: tuple[ContractRow, ...]
    pe: PeInfo

    def by_name(self) -> dict[str, bytes]:
        return {
            MANIFEST_NAME: self.manifest,
            DEF_NAME: self.def_blueprint,
            METADATA_NAME: self.metadata,
        }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expect_hash(label: str, data: bytes, expected: str) -> str:
    actual = sha256_bytes(data)
    if actual != expected.lower():
        raise ContractError(
            f"{label} source hash drift: expected {expected.lower()}, got {actual}"
        )
    return actual


def _checked_range(data: bytes, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ContractError(
            f"truncated {label}: offset=0x{offset:x}, size=0x{size:x}, file=0x{len(data):x}"
        )
    return memoryview(data)[offset : offset + size]


def _unpack_from(fmt: str, data: bytes, offset: int, label: str) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, _checked_range(data, offset, size, label))


class _PeView:
    def __init__(self, data: bytes, sections: Sequence[Section], size_of_headers: int):
        self.data = data
        self.sections = tuple(sections)
        self.size_of_headers = size_of_headers

    def rva_offset(self, rva: int, size: int, label: str) -> int:
        if not 0 <= rva <= 0xFFFFFFFF or size < 0 or size > 0x100000000 - rva:
            raise ContractError(f"invalid RVA range for {label}: 0x{rva:x}+0x{size:x}")
        if rva < self.size_of_headers:
            if size <= self.size_of_headers - rva and size <= len(self.data) - rva:
                return rva
            raise ContractError(f"truncated header RVA for {label}: 0x{rva:08x}+0x{size:x}")

        matches = [
            section
            for section in self.sections
            if section.virtual_address <= rva
            and rva - section.virtual_address < section.mapped_size
        ]
        if len(matches) != 1:
            raise ContractError(
                f"RVA for {label} maps to {len(matches)} sections: 0x{rva:08x}"
            )
        section = matches[0]
        delta = rva - section.virtual_address
        if delta > section.raw_size or size > section.raw_size - delta:
            raise ContractError(
                f"RVA for {label} has no complete raw backing in {section.name}: "
                f"0x{rva:08x}+0x{size:x}"
            )
        offset = section.raw_offset + delta
        _checked_range(self.data, offset, size, label)
        return offset

    def section_for_rva(self, rva: int, label: str) -> Section:
        matches = [
            section
            for section in self.sections
            if section.virtual_address <= rva
            and rva - section.virtual_address < section.mapped_size
        ]
        if len(matches) != 1:
            raise ContractError(
                f"target RVA for {label} maps to {len(matches)} sections: 0x{rva:08x}"
            )
        return matches[0]

    def c_string(self, rva: int, label: str) -> bytes:
        offset = self.rva_offset(rva, 1, label)
        # A string may not cross its raw section boundary.  Header strings are
        # similarly bounded by SizeOfHeaders.
        if rva < self.size_of_headers:
            limit = min(self.size_of_headers, len(self.data))
        else:
            section = self.section_for_rva(rva, label)
            limit = min(section.raw_offset + section.raw_size, len(self.data))
        end = self.data.find(b"\0", offset, limit)
        if end < 0:
            raise ContractError(f"unterminated {label} at RVA 0x{rva:08x}")
        return self.data[offset:end]


def _decode_export_name(raw: bytes, label: str, *, dll_name: bool = False) -> str:
    if not raw:
        raise ContractError(f"empty {label}")
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ContractError(f"non-ASCII {label} cannot be represented losslessly in a DEF") from exc
    allowed = set(string.ascii_letters + string.digits + ("._-" if dll_name else "_?$@"))
    unsupported = sorted(set(value) - allowed)
    if unsupported:
        rendered = " ".join(f"0x{ord(ch):02x}" for ch in unsupported)
        raise ContractError(
            f"unsupported DEF character in {label}: {rendered} in {value!r}"
        )
    return value


def parse_pe_exports(data: bytes) -> PeInfo:
    if bytes(_checked_range(data, 0, 64, "DOS header"))[:2] != b"MZ":
        raise ContractError("not an MZ executable")
    (pe_offset,) = _unpack_from("<I", data, 0x3C, "DOS e_lfanew")
    if bytes(_checked_range(data, pe_offset, 4, "PE signature")) != b"PE\0\0":
        raise ContractError("invalid PE signature")

    coff = pe_offset + 4
    machine, section_count, timestamp, _, _, optional_size, _ = _unpack_from(
        "<HHIIIHH", data, coff, "COFF header"
    )
    optional = coff + 20
    optional_bytes = _checked_range(data, optional, optional_size, "optional header")
    if len(optional_bytes) < 96 + 8:
        raise ContractError(f"optional header is too small: {len(optional_bytes)}")
    (magic,) = struct.unpack_from("<H", optional_bytes, 0)
    if magic != PE32_MAGIC:
        raise ContractError(f"expected PE32 optional header, got magic 0x{magic:04x}")
    (image_base,) = struct.unpack_from("<I", optional_bytes, 28)
    (size_of_image,) = struct.unpack_from("<I", optional_bytes, 56)
    (size_of_headers,) = struct.unpack_from("<I", optional_bytes, 60)
    (directory_count,) = struct.unpack_from("<I", optional_bytes, 92)
    if directory_count < 1:
        raise ContractError("PE has no export data directory")
    export_rva, export_size = struct.unpack_from("<II", optional_bytes, 96)
    if export_rva == 0 or export_size < 40:
        raise ContractError("PE has no complete export directory")

    section_table = optional + optional_size
    _checked_range(data, section_table, section_count * 40, "section table")
    sections: list[Section] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = bytes(_checked_range(data, offset, 8, f"section {index} name"))
        try:
            name = raw_name.rstrip(b"\0").decode("ascii")
        except UnicodeDecodeError as exc:
            raise ContractError(f"non-ASCII section {index} name") from exc
        virtual_size, virtual_address, raw_size, raw_offset = _unpack_from(
            "<IIII", data, offset + 8, f"section {index} layout"
        )
        (characteristics,) = _unpack_from(
            "<I", data, offset + 36, f"section {index} characteristics"
        )
        if raw_size:
            _checked_range(data, raw_offset, raw_size, f"section {name} raw data")
        sections.append(
            Section(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_offset=raw_offset,
                characteristics=characteristics,
            )
        )

    view = _PeView(data, sections, size_of_headers)
    export_offset = view.rva_offset(export_rva, 40, "export directory")
    (
        export_characteristics,
        export_timestamp,
        export_major_version,
        export_minor_version,
        dll_name_rva,
        ordinal_base,
        function_count,
        name_count,
        eat_rva,
        name_table_rva,
        ordinal_table_rva,
    ) = _unpack_from("<IIHHIIIIIII", data, export_offset, "export directory")
    if function_count == 0:
        raise ContractError("export address table is empty")
    if name_count == 0:
        raise ContractError("export name table is empty")
    if function_count > len(data) // 4 or name_count > len(data) // 2:
        raise ContractError("implausibly large export table")

    dll_name = _decode_export_name(
        view.c_string(dll_name_rva, "export DLL name"), "DLL name", dll_name=True
    )
    eat_offset = view.rva_offset(eat_rva, function_count * 4, "export address table")
    name_offset = view.rva_offset(name_table_rva, name_count * 4, "export name table")
    ordinal_offset = view.rva_offset(
        ordinal_table_rva, name_count * 2, "export ordinal table"
    )
    eat = struct.unpack(
        f"<{function_count}I",
        _checked_range(data, eat_offset, function_count * 4, "export address table"),
    )
    name_rvas = struct.unpack(
        f"<{name_count}I",
        _checked_range(data, name_offset, name_count * 4, "export name table"),
    )
    name_ordinals = struct.unpack(
        f"<{name_count}H",
        _checked_range(data, ordinal_offset, name_count * 2, "export ordinal table"),
    )

    names_by_eat: dict[int, tuple[int, str]] = {}
    seen_names: set[str] = set()
    previous_name_bytes: bytes | None = None
    for hint, (name_rva, eat_index) in enumerate(zip(name_rvas, name_ordinals)):
        if eat_index >= function_count:
            raise ContractError(
                f"name hint {hint} references EAT index {eat_index}, outside {function_count} slots"
            )
        raw_name = view.c_string(name_rva, f"export name hint {hint}")
        name = _decode_export_name(raw_name, f"export name hint {hint}")
        if previous_name_bytes is not None and raw_name <= previous_name_bytes:
            raise ContractError("export name table is not strictly byte-sorted")
        previous_name_bytes = raw_name
        if name in seen_names:
            raise ContractError(f"duplicate export name: {name}")
        seen_names.add(name)
        if eat_index in names_by_eat:
            other_hint, other_name = names_by_eat[eat_index]
            raise ContractError(
                f"EAT index {eat_index} has multiple names: hints {other_hint} "
                f"({other_name}) and {hint} ({name})"
            )
        names_by_eat[eat_index] = (hint, name)

    exports: list[PeExport] = []
    forwarder_end = export_rva + export_size
    if forwarder_end > 0x100000000:
        raise ContractError("export directory RVA range overflows")
    for eat_index, rva in enumerate(eat):
        ordinal = ordinal_base + eat_index
        if rva == 0:
            raise ContractError(f"hole at export ordinal {ordinal} (EAT index {eat_index})")
        if eat_index not in names_by_eat:
            raise ContractError(f"unnamed export ordinal {ordinal} (EAT index {eat_index})")
        hint, name = names_by_eat[eat_index]
        name_rva = name_rvas[hint]
        if export_rva <= rva < forwarder_end:
            forwarder = view.c_string(rva, f"forwarder at ordinal {ordinal}")
            try:
                rendered_forwarder = forwarder.decode("ascii")
            except UnicodeDecodeError:
                rendered_forwarder = repr(forwarder)
            raise ContractError(
                f"forwarder export is not supported at ordinal {ordinal}: {rendered_forwarder}"
            )
        section = view.section_for_rva(rva, f"export ordinal {ordinal}")
        exports.append(
            PeExport(
                ordinal=ordinal,
                eat_index=eat_index,
                name_hint=hint,
                name=name,
                name_rva=name_rva,
                rva=rva,
                section=section,
            )
        )

    if len(names_by_eat) != function_count or name_count != function_count:
        # The per-slot checks above give precise errors; this additionally locks
        # the lossless one-name-per-ordinal contract.
        raise ContractError(
            f"unnamed or multiply named exports: functions={function_count}, names={name_count}"
        )
    exports.sort(key=lambda item: item.ordinal)
    return PeInfo(
        machine=machine,
        optional_magic=magic,
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        coff_timestamp=timestamp,
        export_characteristics=export_characteristics,
        export_timestamp=export_timestamp,
        export_major_version=export_major_version,
        export_minor_version=export_minor_version,
        dll_name=dll_name,
        export_rva=export_rva,
        export_size=export_size,
        ordinal_base=ordinal_base,
        function_count=function_count,
        name_count=name_count,
        eat_rva=eat_rva,
        name_table_rva=name_table_rva,
        ordinal_table_rva=ordinal_table_rva,
        sections=tuple(sections),
        exports=tuple(exports),
    )


def _read_tsv(
    data: bytes, expected_header: Sequence[str], label: str
) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{label} is not strict UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t")
    if tuple(reader.fieldnames or ()) != tuple(expected_header):
        raise ContractError(
            f"{label} schema drift: expected {tuple(expected_header)!r}, "
            f"got {tuple(reader.fieldnames or ())!r}"
        )
    rows: list[dict[str, str]] = []
    try:
        for line_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise ContractError(f"malformed {label} row {line_number}")
            rows.append(row)
    except csv.Error as exc:
        raise ContractError(f"malformed {label}: {exc}") from exc
    return rows


def _canonical_map(
    rows: Iterable[dict[str, str]], address_column: str, prefix: str, label: str
) -> dict[int, dict[str, str]]:
    result: dict[int, dict[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        address_text = row[address_column]
        if len(address_text) != 8 or address_text != address_text.lower():
            raise ContractError(f"invalid {label} address at row {row_number}: {address_text!r}")
        try:
            address = int(address_text, 16)
        except ValueError as exc:
            raise ContractError(
                f"invalid {label} address at row {row_number}: {address_text!r}"
            ) from exc
        expected_name = f"{prefix}{address_text}"
        if row["canonical_name"] != expected_name:
            raise ContractError(
                f"canonical name mismatch at {label} row {row_number}: "
                f"expected {expected_name}, got {row['canonical_name']}"
            )
        if address in result:
            raise ContractError(f"duplicate {label} address: {address_text}")
        result[address] = row
    return result


def _parse_snapshot(
    data: bytes, policy: InputPolicy
) -> dict[str, str]:
    rows = _read_tsv(data, SNAPSHOT_HEADER, "canonical snapshot")
    if len(rows) != 1:
        raise ContractError(f"canonical snapshot must have exactly one row, got {len(rows)}")
    row = rows[0]
    expected = {
        "format": "canonical-address-v2",
        "executable_sha256": policy.executable_sha256,
        "mapping_fingerprint": policy.mapping_fingerprint,
        "functions": str(policy.function_rows),
        "data_symbols": str(policy.data_rows),
    }
    for field, value in expected.items():
        if row[field] != value:
            raise ContractError(
                f"canonical snapshot {field} drift: expected {value}, got {row[field]}"
            )
    return row


def _tsv_bytes(rows: Sequence[ContractRow]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(MANIFEST_HEADER)
    for row in rows:
        writer.writerow(
            (
                row.ordinal,
                row.eat_index,
                row.name_hint,
                row.export_name,
                f"{row.name_rva:08x}",
                f"{row.target_rva:08x}",
                f"{row.target_va:08x}",
                row.target_section,
                f"{row.target_section_characteristics:08x}",
                row.target_kind,
                row.target_symbol,
                row.canonical_name,
                row.canonical_symbol_id,
                row.canonical_source_type,
                row.canonical_original_qualified_name,
            )
        )
    return output.getvalue().encode("utf-8")


def _def_bytes(rows: Sequence[ContractRow], dll_sha256: str, dll_name: str) -> bytes:
    lines = [
        f"; {SCHEMA}",
        "; Generated from the original PE export directory; do not hand-edit.",
        f"; source_sha256={dll_sha256}",
        "; Targets are declarations only. Implementations/storage are deliberately absent.",
        f"LIBRARY {dll_name}",
        "EXPORTS",
    ]
    for row in rows:
        suffix = " DATA" if row.target_kind == "data" else ""
        lines.append(
            f"    {row.export_name}={row.target_symbol} @{row.ordinal}{suffix}"
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def build_artifacts(
    *,
    dll_bytes: bytes,
    function_index_bytes: bytes,
    data_index_bytes: bytes,
    snapshot_bytes: bytes,
    policy: InputPolicy,
    generator_sha256: str,
    input_labels: Mapping[str, str],
) -> ArtifactSet:
    dll_sha = _expect_hash("DLL", dll_bytes, policy.dll_sha256)
    function_sha = _expect_hash(
        "canonical function index", function_index_bytes, policy.function_index_sha256
    )
    data_sha = _expect_hash(
        "canonical data index", data_index_bytes, policy.data_index_sha256
    )
    snapshot_sha = _expect_hash(
        "canonical snapshot", snapshot_bytes, policy.snapshot_sha256
    )
    snapshot = _parse_snapshot(snapshot_bytes, policy)

    function_rows = _read_tsv(
        function_index_bytes, FUNCTION_HEADER, "canonical function index"
    )
    data_rows = _read_tsv(data_index_bytes, DATA_HEADER, "canonical data index")
    if len(function_rows) != policy.function_rows:
        raise ContractError(
            f"canonical function row-count drift: expected {policy.function_rows}, "
            f"got {len(function_rows)}"
        )
    if len(data_rows) != policy.data_rows:
        raise ContractError(
            f"canonical data row-count drift: expected {policy.data_rows}, got {len(data_rows)}"
        )
    functions = _canonical_map(
        function_rows, "entry", "decomp_fn_", "canonical function"
    )
    data_symbols = _canonical_map(
        data_rows, "address", "decomp_g_", "canonical data"
    )

    pe = parse_pe_exports(dll_bytes)
    if pe.machine != policy.machine:
        raise ContractError(
            f"PE machine drift: expected 0x{policy.machine:04x}, got 0x{pe.machine:04x}"
        )
    if pe.optional_magic != policy.optional_magic:
        raise ContractError(
            f"PE optional-header drift: expected 0x{policy.optional_magic:04x}, "
            f"got 0x{pe.optional_magic:04x}"
        )
    if policy.export_rows is not None and len(pe.exports) != policy.export_rows:
        raise ContractError(
            f"export row-count drift: expected {policy.export_rows}, got {len(pe.exports)}"
        )
    if policy.ordinal_base is not None and pe.ordinal_base != policy.ordinal_base:
        raise ContractError(
            f"export ordinal-base drift: expected {policy.ordinal_base}, got {pe.ordinal_base}"
        )
    if policy.dll_name is not None and pe.dll_name != policy.dll_name:
        raise ContractError(
            f"export DLL-name drift: expected {policy.dll_name}, got {pe.dll_name}"
        )

    contract_rows: list[ContractRow] = []
    for export in pe.exports:
        target_va = pe.image_base + export.rva
        if target_va > 0xFFFFFFFF:
            raise ContractError(
                f"PE32 target VA overflows 32 bits at ordinal {export.ordinal}: 0x{target_va:x}"
            )
        function = functions.get(target_va)
        data_symbol = data_symbols.get(target_va)
        if (function is None) == (data_symbol is None):
            matches = int(function is not None) + int(data_symbol is not None)
            raise ContractError(
                f"canonical join miss/ambiguity at ordinal {export.ordinal} "
                f"({export.name}), VA 0x{target_va:08x}: {matches} matches"
            )
        section_is_executable = bool(export.section.characteristics & IMAGE_SCN_MEM_EXECUTE)
        if function is not None:
            if not section_is_executable:
                raise ContractError(
                    f"canonical function at ordinal {export.ordinal} is in non-executable "
                    f"section {export.section.name}"
                )
            canonical = function
            kind = "code"
        else:
            if section_is_executable:
                raise ContractError(
                    f"canonical data at ordinal {export.ordinal} is in executable "
                    f"section {export.section.name}"
                )
            assert data_symbol is not None
            canonical = data_symbol
            kind = "data"
        target_symbol = f"rome2_export_{kind}_{target_va:08x}"
        contract_rows.append(
            ContractRow(
                ordinal=export.ordinal,
                eat_index=export.eat_index,
                name_hint=export.name_hint,
                export_name=export.name,
                name_rva=export.name_rva,
                target_rva=export.rva,
                target_va=target_va,
                target_section=export.section.name,
                target_section_characteristics=export.section.characteristics,
                target_kind=kind,
                target_symbol=target_symbol,
                canonical_name=canonical["canonical_name"],
                canonical_symbol_id=canonical["symbol_id"],
                canonical_source_type=canonical["source_type"],
                canonical_original_qualified_name=canonical["original_qualified_name"],
            )
        )

    rows = tuple(sorted(contract_rows, key=lambda row: row.ordinal))
    if any(right.ordinal <= left.ordinal for left, right in zip(rows, rows[1:])):
        raise ContractError("contract ordinals are not strictly increasing")
    manifest = _tsv_bytes(rows)
    def_blueprint = _def_bytes(rows, dll_sha, pe.dll_name)
    target_counts: dict[str, int] = {}
    for row in rows:
        target_counts[row.target_symbol] = target_counts.get(row.target_symbol, 0) + 1
    code_rows = sum(row.target_kind == "code" for row in rows)
    data_contract_rows = len(rows) - code_rows
    unique_code = len({row.target_symbol for row in rows if row.target_kind == "code"})
    unique_data = len({row.target_symbol for row in rows if row.target_kind == "data"})

    metadata_object = {
        "artifacts": {
            DEF_NAME: {
                "bytes": len(def_blueprint),
                "sha256": sha256_bytes(def_blueprint),
            },
            MANIFEST_NAME: {
                "bytes": len(manifest),
                "sha256": sha256_bytes(manifest),
            },
        },
        "contract": {
            "alias_rows_beyond_unique_targets": len(rows) - len(target_counts),
            "code_rows": code_rows,
            "data_rows": data_contract_rows,
            "duplicate_target_groups": sum(count > 1 for count in target_counts.values()),
            "first_ordinal": rows[0].ordinal,
            "last_ordinal": rows[-1].ordinal,
            "rows": len(rows),
            "unique_code_targets": unique_code,
            "unique_data_targets": unique_data,
            "unique_targets": len(target_counts),
        },
        "generator": {
            "path": input_labels["generator"],
            "sha256": generator_sha256,
        },
        "inputs": {
            "canonical_data_index": {
                "path": input_labels["data_index"],
                "rows": len(data_rows),
                "sha256": data_sha,
            },
            "canonical_function_index": {
                "path": input_labels["function_index"],
                "rows": len(function_rows),
                "sha256": function_sha,
            },
            "canonical_snapshot": {
                "executable_sha256": snapshot["executable_sha256"],
                "mapping_fingerprint": snapshot["mapping_fingerprint"],
                "path": input_labels["snapshot"],
                "sha256": snapshot_sha,
            },
            "original_dll": {
                "bytes": len(dll_bytes),
                "path": input_labels["dll"],
                "sha256": dll_sha,
            },
        },
        "pe_export_directory": {
            "address_of_functions_rva": f"{pe.eat_rva:08x}",
            "address_of_name_ordinals_rva": f"{pe.ordinal_table_rva:08x}",
            "address_of_names_rva": f"{pe.name_table_rva:08x}",
            "characteristics": f"{pe.export_characteristics:08x}",
            "coff_timestamp": f"{pe.coff_timestamp:08x}",
            "dll_name": pe.dll_name,
            "export_timestamp": f"{pe.export_timestamp:08x}",
            "export_rva": f"{pe.export_rva:08x}",
            "export_size": pe.export_size,
            "function_count": pe.function_count,
            "image_base": f"{pe.image_base:08x}",
            "machine": f"{pe.machine:04x}",
            "name_count": pe.name_count,
            "ordinal_base": pe.ordinal_base,
            "size_of_image": pe.size_of_image,
            "version": f"{pe.export_major_version}.{pe.export_minor_version}",
        },
        "schema": SCHEMA,
    }
    metadata = (
        json.dumps(metadata_object, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("ascii")
    return ArtifactSet(
        manifest=manifest,
        def_blueprint=def_blueprint,
        metadata=metadata,
        rows=rows,
        pe=pe,
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as handle:
            temporary_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _check_outputs(out_dir: Path, artifacts: Mapping[str, bytes]) -> None:
    mismatches: list[str] = []
    for name, expected in artifacts.items():
        path = out_dir / name
        try:
            actual = path.read_bytes()
        except FileNotFoundError:
            mismatches.append(f"missing {path}")
            continue
        if actual != expected:
            mismatches.append(
                f"{path}: expected sha256 {sha256_bytes(expected)}, "
                f"got {sha256_bytes(actual)}"
            )
    if mismatches:
        raise ContractError("output byte-identity check failed:\n  " + "\n  ".join(mismatches))


def _relative_label(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    canonical_dir = repo_root / "src_canonical_out" / "empire.retail.dll"
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--dll", type=Path, default=repo_root / "Total War Rome II" / "empire.retail.dll"
    )
    parser.add_argument("--canonical-dir", type=Path, default=canonical_dir)
    parser.add_argument("--out-dir", type=Path, default=repo_root / "port" / "x64_exports")
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate inputs and require every generated artifact to be byte-identical",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parent.parent
    dll_path = args.dll.resolve()
    canonical_dir = args.canonical_dir.resolve()
    out_dir = args.out_dir.resolve()
    function_path = canonical_dir / "canonical_function_index.tsv"
    data_path = canonical_dir / "canonical_data_index.tsv"
    snapshot_path = canonical_dir / "canonical_snapshot.tsv"
    generator_path = Path(__file__).resolve()

    try:
        artifacts = build_artifacts(
            dll_bytes=dll_path.read_bytes(),
            function_index_bytes=function_path.read_bytes(),
            data_index_bytes=data_path.read_bytes(),
            snapshot_bytes=snapshot_path.read_bytes(),
            policy=REAL_POLICY,
            generator_sha256=sha256_bytes(generator_path.read_bytes()),
            input_labels={
                "dll": _relative_label(dll_path, repo_root),
                "function_index": _relative_label(function_path, repo_root),
                "data_index": _relative_label(data_path, repo_root),
                "snapshot": _relative_label(snapshot_path, repo_root),
                "generator": _relative_label(generator_path, repo_root),
            },
        )
        outputs = artifacts.by_name()
        if args.check:
            _check_outputs(out_dir, outputs)
            action = "checked"
        else:
            # Metadata is the commit record, so publish it last.
            for name in (MANIFEST_NAME, DEF_NAME, METADATA_NAME):
                _atomic_write(out_dir / name, outputs[name])
            action = "wrote"
    except (ContractError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    code_rows = sum(row.target_kind == "code" for row in artifacts.rows)
    data_rows = len(artifacts.rows) - code_rows
    unique_targets = len({row.target_symbol for row in artifacts.rows})
    print(
        f"{action} {len(outputs)} artifacts in {out_dir}: "
        f"rows={len(artifacts.rows)}, code={code_rows}, data={data_rows}, "
        f"unique_targets={unique_targets}"
    )
    for name in (MANIFEST_NAME, DEF_NAME, METADATA_NAME):
        print(f"  {name}: {len(outputs[name])} bytes, sha256={sha256_bytes(outputs[name])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
