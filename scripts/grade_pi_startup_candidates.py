#!/usr/bin/env python3
"""Independent oracle for the Pi startup-audit code bake-off.

The candidate's own tests and summary are evidence, never the oracle.  This
runner reconstructs the expected slot inventory directly from the pinned x86
PE and canonical function index, then exercises every submission in an
isolated temporary directory.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "pi-startup-candidate-oracle-v1"
AUDIT_SCHEMA = "rome2-startup-audit-v1"
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
IMAGE_BASE = 0x10000000
IMAGE_FILE_MACHINE_I386 = 0x014C
PE32_MAGIC = 0x010B
IMAGE_SCN_MEM_EXECUTE = 0x20000000
OWNED_OUTPUTS = ("startup_slots.tsv", "startup_summary.json")
SUBMISSION_FILES = ("README.md", "gen_startup_audit.py", "test_gen_startup_audit.py")
TSV_HEADER = (
    "table\tslot_index\tslot_va\traw_target_va\tis_null\ttarget_rva\t"
    "target_section\ttarget_executable\texact_canonical_entry\t"
    "exact_canonical_name\texact_join"
)
TABLE_SPECS = (
    {
        "id": "initterm_e_int",
        "start_va": 0x11739430,
        "end_va": 0x11739450,
        "signature": "int(void)",
        "slot_count": 8,
        "null_count": 1,
        "nonzero_count": 7,
        "unique_nonzero_count": 7,
        "exact_join_count": 1,
        "unresolved_exact_count": 6,
        "null_indices": [0],
    },
    {
        "id": "initterm_void",
        "start_va": 0x1172FA04,
        "end_va": 0x1173942C,
        "signature": "void(void)",
        "slot_count": 9866,
        "null_count": 1,
        "nonzero_count": 9865,
        "unique_nonzero_count": 9865,
        "exact_join_count": 1110,
        "unresolved_exact_count": 8755,
        "null_indices": [0],
    },
)


class OracleError(RuntimeError):
    """A pinned oracle input or invariant is invalid."""


class DuplicateJsonKey(ValueError):
    """A JSON object contains a duplicate key."""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class ParsedPe:
    data: bytes
    image_base: int
    sections: tuple[Section, ...]


@dataclass(frozen=True)
class TableEvidence:
    table_id: str
    start_va: int
    end_va: int
    signature: str
    raw_values: tuple[int, ...]
    null_indices: tuple[int, ...]
    unique_nonzero_count: int
    exact_join_count: int


@dataclass(frozen=True)
class ExpectedEvidence:
    dll_bytes: int
    dll_sha256: str
    index_bytes: int
    index_sha256: str
    slots_bytes: bytes
    slots_sha256: str
    slot_rows: int
    tables: tuple[TableEvidence, ...]


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hex8(value: int) -> str:
    return f"{value:08x}"


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise OracleError(f"{label} is outside the {len(data)}-byte file")


def u16(data: bytes, offset: int, label: str) -> int:
    require_range(data, offset, 2, label)
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int, label: str) -> int:
    require_range(data, offset, 4, label)
    return struct.unpack_from("<I", data, offset)[0]


def ranges_overlap(first: tuple[int, int], second: tuple[int, int]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


def parse_pe(data: bytes) -> ParsedPe:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise OracleError("DLL is not an MZ image")
    pe_offset = u32(data, 0x3C, "DOS e_lfanew")
    require_range(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise OracleError("DLL has no PE signature at e_lfanew")

    coff = pe_offset + 4
    machine = u16(data, coff, "COFF Machine")
    section_count = u16(data, coff + 2, "COFF NumberOfSections")
    optional_size = u16(data, coff + 16, "COFF SizeOfOptionalHeader")
    if machine != IMAGE_FILE_MACHINE_I386:
        raise OracleError(f"DLL Machine is 0x{machine:04x}, expected 0x014c")
    if not 1 <= section_count <= 96:
        raise OracleError(f"implausible PE section count: {section_count}")

    optional = coff + 20
    require_range(data, optional, optional_size, "PE optional header")
    if optional_size < 96:
        raise OracleError("PE optional header is too short for PE32 fields")
    magic = u16(data, optional, "optional-header Magic")
    if magic != PE32_MAGIC:
        raise OracleError(f"DLL optional-header Magic is 0x{magic:04x}, expected 0x010b")
    image_base = u32(data, optional + 28, "PE32 ImageBase")
    if image_base != IMAGE_BASE:
        raise OracleError(f"DLL ImageBase is 0x{image_base:08x}, expected 0x10000000")

    section_table = optional + optional_size
    require_range(data, section_table, section_count * 40, "PE section table")
    sections: list[Section] = []
    for index in range(section_count):
        offset = section_table + index * 40
        name_bytes = data[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise OracleError(f"section {index} has a non-ASCII name") from exc
        if not name:
            raise OracleError(f"section {index} has an empty name")
        virtual_size = u32(data, offset + 8, f"section {index} VirtualSize")
        virtual_address = u32(data, offset + 12, f"section {index} VirtualAddress")
        raw_size = u32(data, offset + 16, f"section {index} SizeOfRawData")
        raw_offset = u32(data, offset + 20, f"section {index} PointerToRawData")
        characteristics = u32(data, offset + 36, f"section {index} Characteristics")
        if raw_size:
            require_range(data, raw_offset, raw_size, f"section {name} raw data")
            if virtual_address + raw_size > 0x100000000:
                raise OracleError(f"section {name} raw-backed RVA range overflows")
        sections.append(
            Section(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=characteristics,
            )
        )

    raw_sections = [section for section in sections if section.raw_size]
    for left_index, left in enumerate(raw_sections):
        left_raw = (left.raw_offset, left.raw_offset + left.raw_size)
        left_rva = (left.virtual_address, left.virtual_address + left.raw_size)
        for right in raw_sections[left_index + 1 :]:
            right_raw = (right.raw_offset, right.raw_offset + right.raw_size)
            right_rva = (right.virtual_address, right.virtual_address + right.raw_size)
            if ranges_overlap(left_raw, right_raw):
                raise OracleError(f"raw section ranges overlap: {left.name} and {right.name}")
            if ranges_overlap(left_rva, right_rva):
                raise OracleError(
                    f"raw-backed virtual section ranges overlap: {left.name} and {right.name}"
                )
    return ParsedPe(data=data, image_base=image_base, sections=tuple(sections))


def map_raw(pe: ParsedPe, va: int, size: int, label: str) -> tuple[Section, int]:
    if va < pe.image_base:
        raise OracleError(f"{label} VA 0x{va:08x} is below ImageBase")
    rva = va - pe.image_base
    matches: list[tuple[Section, int]] = []
    for section in pe.sections:
        delta = rva - section.virtual_address
        if delta >= 0 and size <= section.raw_size - delta:
            matches.append((section, section.raw_offset + delta))
    if len(matches) != 1:
        raise OracleError(
            f"{label} VA 0x{va:08x} maps to {len(matches)} raw-backed sections"
        )
    section, offset = matches[0]
    require_range(pe.data, offset, size, label)
    return section, offset


def parse_function_index(data: bytes) -> dict[int, tuple[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OracleError("function index is not valid UTF-8") from exc
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    if reader.fieldnames is None:
        raise OracleError("function index has no header")
    if len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise OracleError("function index has duplicate header fields")
    for required in ("entry", "canonical_name"):
        if required not in reader.fieldnames:
            raise OracleError(f"function index header lacks {required!r}")

    result: dict[int, tuple[str, str]] = {}
    for line_number, row in enumerate(reader, 2):
        if None in row:
            raise OracleError(f"function index line {line_number} has extra columns")
        entry = row.get("entry")
        name = row.get("canonical_name")
        if entry is None or re.fullmatch(r"[0-9a-f]{8}", entry) is None:
            raise OracleError(f"function index line {line_number} has invalid entry {entry!r}")
        if not name or "\t" in name or "\r" in name or "\n" in name:
            raise OracleError(f"function index line {line_number} has invalid canonical_name")
        numeric = int(entry, 16)
        if numeric in result:
            raise OracleError(f"function index contains duplicate entry {entry}")
        result[numeric] = (entry, name)
    return result


def build_expected(dll_path: Path, index_path: Path) -> ExpectedEvidence:
    dll_data = dll_path.read_bytes()
    index_data = index_path.read_bytes()
    dll_hash = sha256_bytes(dll_data)
    index_hash = sha256_bytes(index_data)
    if dll_hash != DLL_SHA256:
        raise OracleError(f"DLL SHA-256 is {dll_hash}, expected {DLL_SHA256}")
    if index_hash != INDEX_SHA256:
        raise OracleError(f"function-index SHA-256 is {index_hash}, expected {INDEX_SHA256}")

    pe = parse_pe(dll_data)
    functions = parse_function_index(index_data)
    lines = [TSV_HEADER]
    tables: list[TableEvidence] = []

    for spec in TABLE_SPECS:
        start_va = int(spec["start_va"])
        end_va = int(spec["end_va"])
        if end_va <= start_va or (end_va - start_va) % 4:
            raise OracleError(f"oracle table range is invalid: {spec['id']}")
        raw_values: list[int] = []
        null_indices: list[int] = []
        exact_count = 0
        for slot_index, slot_va in enumerate(range(start_va, end_va, 4)):
            _, raw_offset = map_raw(pe, slot_va, 4, f"{spec['id']} slot {slot_index}")
            target = u32(pe.data, raw_offset, f"{spec['id']} slot {slot_index}")
            raw_values.append(target)
            if target == 0:
                null_indices.append(slot_index)
                cells = [
                    str(spec["id"]),
                    str(slot_index),
                    hex8(slot_va),
                    "00000000",
                    "yes",
                    "",
                    "",
                    "no",
                    "",
                    "",
                    "no",
                ]
            else:
                section, _ = map_raw(pe, target, 1, f"{spec['id']} target {slot_index}")
                executable = bool(section.characteristics & IMAGE_SCN_MEM_EXECUTE)
                if not executable:
                    raise OracleError(
                        f"{spec['id']} target {slot_index} 0x{target:08x} is not executable"
                    )
                joined = functions.get(target)
                if joined is not None:
                    exact_count += 1
                cells = [
                    str(spec["id"]),
                    str(slot_index),
                    hex8(slot_va),
                    hex8(target),
                    "no",
                    hex8(target - pe.image_base),
                    section.name,
                    "yes",
                    joined[0] if joined else "",
                    joined[1] if joined else "",
                    "yes" if joined else "no",
                ]
            if any("\t" in cell or "\r" in cell or "\n" in cell for cell in cells):
                raise OracleError(f"oracle TSV cell contains a delimiter in {spec['id']}")
            lines.append("\t".join(cells))

        nonzero = [value for value in raw_values if value]
        evidence = TableEvidence(
            table_id=str(spec["id"]),
            start_va=start_va,
            end_va=end_va,
            signature=str(spec["signature"]),
            raw_values=tuple(raw_values),
            null_indices=tuple(null_indices),
            unique_nonzero_count=len(set(nonzero)),
            exact_join_count=exact_count,
        )
        actual = {
            "slot_count": len(raw_values),
            "null_count": len(null_indices),
            "nonzero_count": len(nonzero),
            "unique_nonzero_count": evidence.unique_nonzero_count,
            "exact_join_count": exact_count,
            "unresolved_exact_count": len(nonzero) - exact_count,
            "null_indices": list(null_indices),
        }
        for key, expected_value in spec.items():
            if key in actual and actual[key] != expected_value:
                raise OracleError(
                    f"{spec['id']} {key} is {actual[key]!r}, expected {expected_value!r}"
                )
        if not raw_values or raw_values[-1] == 0:
            raise OracleError(f"{spec['id']} last slot is unexpectedly null")
        tables.append(evidence)

    slots_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    return ExpectedEvidence(
        dll_bytes=len(dll_data),
        dll_sha256=dll_hash,
        index_bytes=len(index_data),
        index_sha256=index_hash,
        slots_bytes=slots_bytes,
        slots_sha256=sha256_bytes(slots_bytes),
        slot_rows=len(lines) - 1,
        tables=tuple(tables),
    )


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey(key)
        result[key] = value
    return result


def parse_json_strict(raw: bytes) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is not permitted")
    text = raw.decode("utf-8")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(
        text,
        object_pairs_hook=duplicate_rejecting_object,
        parse_constant=reject_constant,
    )


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def value_equal(actual: Any, expected: Any) -> bool:
    if isinstance(expected, int) and isinstance(actual, bool):
        return False
    return actual == expected


def semantic_leaves(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from semantic_leaves(child, path + (normalized_key(str(key)),))
    elif isinstance(value, list):
        for child in value:
            yield from semantic_leaves(child, path + ("item",))
    else:
        yield path, value


def semantic_objects(
    value: Any,
    path: tuple[str, ...] = (),
) -> Iterable[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from semantic_objects(child, path + (normalized_key(str(key)),))
    elif isinstance(value, list):
        for child in value:
            yield from semantic_objects(child, path + ("item",))


def _semantic_containers(
    value: Any,
    path: tuple[str, ...] = (),
) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + (normalized_key(str(key)),)
            if isinstance(child, (dict, list)):
                yield child_path, child
            yield from _semantic_containers(child, child_path)
    elif isinstance(value, list):
        for child in value:
            yield from _semantic_containers(child, path + ("item",))


def has_semantic_value(
    value: Any,
    aliases: Sequence[str],
    expected: Any,
) -> bool:
    wanted_keys = {normalized_key(alias) for alias in aliases}
    for path, actual in semantic_leaves(value):
        if path and path[-1] in wanted_keys and value_equal(actual, expected):
            return True
    for path, actual in _semantic_containers(value):
        if path and path[-1] in wanted_keys and value_equal(actual, expected):
            return True
    return False


def path_has_any(path: Sequence[str], fragments: Sequence[str]) -> bool:
    wanted = tuple(normalized_key(fragment) for fragment in fragments)
    return any(any(fragment in component for fragment in wanted) for component in path)


def find_contextual_value(
    document: Any,
    expected: Any,
    key_fragments: Sequence[str],
    context_fragments: Sequence[str],
) -> bool:
    for path, actual in semantic_leaves(document):
        if not path or not value_equal(actual, expected):
            continue
        if not path_has_any(path[-1:], key_fragments):
            continue
        if not context_fragments or path_has_any(path, context_fragments):
            return True
    return False


def normalized_signature(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.casefold().replace("__cdecl", "")
    normalized = "".join(normalized.split())
    normalized = normalized.replace("(*)", "").replace("(**)", "")
    return normalized


def looks_absolute(value: str) -> bool:
    return (
        PureWindowsPath(value).is_absolute()
        or PurePosixPath(value).is_absolute()
        or re.match(r"^[A-Za-z]:[\\/]", value) is not None
        or value.startswith("\\\\")
    )


def walk_json(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key in sorted(value):
            yield from walk_json(value[key], f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_json(item, f"{path}[{index}]")


def validate_summary(
    raw: bytes,
    expected: ExpectedEvidence,
    generator_sha256: str,
    candidate_slots_sha256: str,
) -> tuple[dict[str, bool], list[str]]:
    flags = {
        "json_parse": False,
        "canonical_format": False,
        "schema": False,
        "input_evidence": False,
        "generator_hash": False,
        "slots_evidence": False,
        "invocation_order": False,
        "table_evidence": False,
        "combined_totals": False,
        "evidence_only": False,
    }
    issues: list[str] = []
    try:
        document = parse_json_strict(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, DuplicateJsonKey) as exc:
        issues.append(f"summary JSON parse failed: {exc}")
        return flags, issues
    if not isinstance(document, dict):
        issues.append("summary root is not an object")
        return flags, issues
    flags["json_parse"] = True

    canonical = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )
    flags["canonical_format"] = raw == canonical
    if not flags["canonical_format"]:
        issues.append("summary is not sorted two-space JSON with exactly one LF newline")

    # The prose contract fixes semantics but deliberately does not prescribe a
    # JSON member layout.  Locate evidence by contextual key meaning anywhere
    # in the document instead of privileging one candidate's nesting scheme.
    flags["schema"] = find_contextual_value(
        document, AUDIT_SCHEMA, ("schema", "format"), ()
    )
    if not flags["schema"]:
        issues.append(f"summary does not identify schema {AUDIT_SCHEMA}")

    input_checks = []
    for label, context, byte_count, digest in (
        ("DLL", ("dll", "image", "binary"), expected.dll_bytes, expected.dll_sha256),
        (
            "function index",
            ("functionindex", "canonicalindex", "index"),
            expected.index_bytes,
            expected.index_sha256,
        ),
    ):
        size_ok = find_contextual_value(
            document,
            byte_count,
            ("bytes", "bytecount", "size", "sizebytes", "length"),
            context,
        )
        hash_ok = find_contextual_value(
            document,
            digest,
            ("sha256", "hash", "digest"),
            context,
        )
        input_checks.extend((size_ok, hash_ok))
        if not size_ok:
            issues.append(f"summary lacks the independently measured {label} byte count")
        if not hash_ok:
            issues.append(f"summary lacks the pinned {label} SHA-256")
    flags["input_evidence"] = all(input_checks)

    flags["generator_hash"] = find_contextual_value(
        document,
        generator_sha256,
        ("sha256", "hash", "digest", "generatorsha256"),
        ("generator", "script", "tool"),
    )
    if not flags["generator_hash"]:
        issues.append("summary lacks the running generator file SHA-256")

    slots_row_ok = find_contextual_value(
        document,
        expected.slot_rows,
        ("rows", "rowcount", "datarows", "slots", "slotcount"),
        ("startupslots", "slots", "output"),
    )
    slots_hash_ok = find_contextual_value(
        document,
        candidate_slots_sha256,
        ("sha256", "hash", "digest"),
        ("startupslots", "slots", "output"),
    )
    flags["slots_evidence"] = slots_row_ok and slots_hash_ok
    if not slots_row_ok:
        issues.append("summary lacks the exact startup_slots.tsv data-row count")
    if not slots_hash_ok:
        issues.append("summary lacks the independently calculated hash of its startup_slots.tsv")

    expected_order = [table.table_id for table in expected.tables]
    flags["invocation_order"] = any(
        value == expected_order and path_has_any(path, ("invocation", "order", "tables"))
        for path, value in _semantic_containers(document)
    )
    if not flags["invocation_order"]:
        issues.append("summary lacks the exact initializer invocation order")

    table_failures: list[str] = []
    for model in expected.tables:
        candidates: list[dict[str, Any]] = []
        for path, obj in semantic_objects(document):
            identifies_table = any(value == model.table_id for _, value in semantic_leaves(obj))
            identifies_table = identifies_table or path_has_any(path, (model.table_id,))
            if identifies_table:
                candidates.append(obj)
        nonzero_count = len(model.raw_values) - len(model.null_indices)
        requirements = (
            (("id", "tableid", "name"), model.table_id),
            (("start", "startva", "begin", "beginva"), hex8(model.start_va)),
            (("end", "endva", "stop", "endexclusive"), hex8(model.end_va)),
            (("slots", "slotcount", "rows", "rowcount"), len(model.raw_values)),
            (("nulls", "null", "nullcount", "nullslots"), len(model.null_indices)),
            (
                ("nonzero", "nonzerocount", "nonzeroslots", "nonzerotargets"),
                nonzero_count,
            ),
            (
                (
                    "uniquenonzero",
                    "uniquenonzerocount",
                    "uniquenonzerotargets",
                    "uniquenonzeroslots",
                    "uniquenonzerovalues",
                    "nonzerounique",
                    "nonzerouniquecount",
                    "nonzerouniquetargets",
                    "nonzerouniqueslots",
                ),
                model.unique_nonzero_count,
            ),
            (
                (
                    "exact",
                    "exactjoin",
                    "exactjoins",
                    "exactjoincount",
                    "exactcanonicaljoins",
                    "exactcanonicaljoincount",
                ),
                model.exact_join_count,
            ),
            (
                ("unresolvedexact", "unresolvedexactcount", "unresolved"),
                nonzero_count - model.exact_join_count,
            ),
            (
                (
                    "nullindices",
                    "nullslotindices",
                    "nullindexes",
                    "nullslotindexes",
                ),
                list(model.null_indices),
            ),
            (("firstrawvalue", "firstvalue", "firstrav"), hex8(model.raw_values[0])),
            (("lastrawvalue", "lastvalue", "lastraw"), hex8(model.raw_values[-1])),
        )
        matched = False
        for candidate_obj in candidates:
            ordinary_ok = all(
                has_semantic_value(candidate_obj, aliases, wanted)
                for aliases, wanted in requirements
            )
            signature_ok = any(
                path
                and path[-1] in {"signature", "callsignature", "callcontract", "prototype"}
                and normalized_signature(value) == normalized_signature(model.signature)
                for path, value in semantic_leaves(candidate_obj)
            )
            if ordinary_ok and signature_ok:
                matched = True
                break
        if not matched:
            table_failures.append(model.table_id)
    flags["table_evidence"] = not table_failures
    if table_failures:
        issues.append("summary lacks complete table facts for: " + ", ".join(table_failures))

    total_slots = sum(len(table.raw_values) for table in expected.tables)
    total_nulls = sum(len(table.null_indices) for table in expected.tables)
    total_nonzero = total_slots - total_nulls
    total_exact = sum(table.exact_join_count for table in expected.tables)
    total_requirements = (
        (("slots", "slotcount", "totalslots"), total_slots),
        (("nulls", "null", "nullcount", "nullslots", "totalnulls"), total_nulls),
        (
            ("nonzero", "nonzerocount", "nonzeroslots", "nonzerotargets", "totalnonzero"),
            total_nonzero,
        ),
        (
            (
                "exact",
                "exactjoin",
                "exactjoins",
                "exactjoincount",
                "exactcanonicaljoins",
                "exactcanonicaljoincount",
            ),
            total_exact,
        ),
        (
            ("unresolvedexact", "unresolvedexactcount", "unresolved"),
            total_nonzero - total_exact,
        ),
    )
    totals_candidates = [
        obj
        for path, obj in semantic_objects(document)
        if path_has_any(path, ("total", "combined", "aggregate"))
    ]
    flags["combined_totals"] = any(
        all(has_semantic_value(obj, aliases, wanted) for aliases, wanted in total_requirements)
        for obj in totals_candidates
    )
    if not flags["combined_totals"]:
        issues.append("summary lacks the exact combined totals")

    evidence_issues: list[str] = []
    forbidden = re.compile(r"(?i)(?:\b(?:pure|portable|supported|safe)\b|executable[-_]on[-_]x64)")
    for location, value in walk_json(document):
        if isinstance(value, str):
            if looks_absolute(value):
                evidence_issues.append(f"{location} contains an absolute path")
            if forbidden.search(value):
                evidence_issues.append(f"{location} contains a forbidden classification label")
        key = location.rsplit(".", 1)[-1]
        if forbidden.search(key):
            evidence_issues.append(f"{location} is a forbidden classification field")
    flags["evidence_only"] = not evidence_issues
    issues.extend(evidence_issues)
    return flags, issues


def validate_slots_tsv(raw: bytes, expected: ExpectedEvidence) -> tuple[bool, bool, list[str]]:
    """Validate exact row semantics while leaving decimal index width unspecified."""
    issues: list[str] = []
    byte_exact = raw == expected.slots_bytes
    if raw.startswith(b"\xef\xbb\xbf"):
        issues.append("startup_slots.tsv has a UTF-8 BOM")
    if b"\r" in raw:
        issues.append("startup_slots.tsv does not use LF-only line endings")
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        issues.append("startup_slots.tsv must end with exactly one newline")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        issues.append(f"startup_slots.tsv is not UTF-8: {exc}")
        return False, byte_exact, issues

    actual_lines = text.splitlines()
    expected_lines = expected.slots_bytes.decode("utf-8").splitlines()
    if not actual_lines or actual_lines[0] != TSV_HEADER:
        issues.append("startup_slots.tsv header differs from the contract")
    if len(actual_lines) != len(expected_lines):
        issues.append(
            f"startup_slots.tsv has {max(0, len(actual_lines) - 1)} rows, "
            f"expected {expected.slot_rows}"
        )
        return False, byte_exact, issues

    mismatches = 0
    for row_index, (actual_line, expected_line) in enumerate(
        zip(actual_lines[1:], expected_lines[1:])
    ):
        actual_cells = actual_line.split("\t")
        expected_cells = expected_line.split("\t")
        row_ok = len(actual_cells) == len(expected_cells) == 11
        if row_ok:
            slot_index = actual_cells[1]
            row_ok = re.fullmatch(r"[0-9]+", slot_index) is not None
            row_ok = row_ok and int(slot_index, 10) == int(expected_cells[1], 10)
            row_ok = row_ok and all(
                actual_cells[index] == expected_cells[index]
                for index in range(11)
                if index != 1
            )
        if not row_ok:
            mismatches += 1
            if mismatches <= 5:
                issues.append(f"startup_slots.tsv row {row_index} differs from oracle semantics")
    if mismatches > 5:
        issues.append(f"startup_slots.tsv has {mismatches} mismatching rows in total")
    return not issues, byte_exact, issues


def sanitized_environment(temp_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    sensitive = re.compile(
        r"(?i)(?:api.?key|token|secret|password|passwd|credential|openrouter|openai)"
    )
    for key in list(environment):
        if sensitive.search(key) or key.upper() in {
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONINSPECT",
        }:
            environment.pop(key, None)
    temp_root.mkdir(parents=True, exist_ok=True)
    home = temp_root / "home"
    appdata = home / "AppData" / "Roaming"
    localappdata = home / "AppData" / "Local"
    for directory in (home, appdata, localappdata):
        directory.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TEMP": str(temp_root),
            "TMP": str(temp_root),
            "TMPDIR": str(temp_root),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(appdata),
            "LOCALAPPDATA": str(localappdata),
        }
    )
    return environment


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, 9)
        except (OSError, ProcessLookupError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run_child(
    command: Sequence[str],
    cwd: Path,
    temp_root: Path,
    timeout: float,
) -> ProcessResult:
    creationflags = 0
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(
        list(command),
        cwd=str(cwd),
        env=sanitized_environment(temp_root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        **popen_kwargs,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return ProcessResult(process.returncode, False, stdout, stderr)
    except subprocess.TimeoutExpired as exc:
        terminate_process_tree(process)
        try:
            stdout_tail, stderr_tail = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout_tail, stderr_tail = b"", b""
        stdout = (exc.output or b"") + (stdout_tail or b"")
        stderr = (exc.stderr or b"") + (stderr_tail or b"")
        return ProcessResult(process.returncode, True, stdout, stderr)


def regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def snapshot_tree(root: Path, with_hashes: bool) -> dict[str, tuple[Any, ...]]:
    snapshot: dict[str, tuple[Any, ...]] = {}
    if not root.exists():
        return snapshot
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort(key=str.casefold)
        files.sort(key=str.casefold)
        current_path = Path(current)
        relative_dir = current_path.relative_to(root).as_posix()
        if relative_dir != ".":
            stat = current_path.lstat()
            snapshot[relative_dir + "/"] = ("dir", stat.st_mtime_ns)
        for name in files:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                stat = path.lstat()
                if path.is_symlink():
                    snapshot[relative] = ("symlink", os.readlink(path), stat.st_mtime_ns)
                elif path.is_file():
                    digest = sha256_file(path) if with_hashes else None
                    snapshot[relative] = ("file", stat.st_size, stat.st_mtime_ns, digest)
                else:
                    snapshot[relative] = ("other", stat.st_size, stat.st_mtime_ns)
            except OSError as exc:
                snapshot[relative] = ("error", type(exc).__name__)
    return snapshot


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def snapshot_workspace(
    repository: Path,
    excluded: Sequence[Path],
) -> dict[str, tuple[Any, ...]]:
    excluded_names = [os.path.normcase(os.path.abspath(str(path))) for path in excluded]

    def lexically_excluded(path: Path) -> bool:
        candidate = os.path.normcase(os.path.abspath(str(path)))
        for excluded_name in excluded_names:
            try:
                if os.path.commonpath((candidate, excluded_name)) == excluded_name:
                    return True
            except ValueError:
                continue
        return False

    snapshot: dict[str, tuple[Any, ...]] = {}
    for current, directories, files in os.walk(repository, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            (
                name
                for name in directories
                if name != ".git"
                and not lexically_excluded(current_path / name)
            ),
            key=str.casefold,
        )
        files.sort(key=str.casefold)
        if current_path != repository:
            relative_dir = current_path.relative_to(repository).as_posix() + "/"
            try:
                stat = current_path.lstat()
                snapshot[relative_dir] = ("dir", stat.st_mtime_ns)
            except OSError as exc:
                snapshot[relative_dir] = ("error", type(exc).__name__)
        for name in files:
            path = current_path / name
            if lexically_excluded(path):
                continue
            relative = path.relative_to(repository).as_posix()
            try:
                stat = path.lstat()
                if path.is_symlink():
                    snapshot[relative] = ("symlink", os.readlink(path), stat.st_mtime_ns)
                else:
                    snapshot[relative] = ("file", stat.st_size, stat.st_mtime_ns)
            except OSError as exc:
                snapshot[relative] = ("error", type(exc).__name__)
    return snapshot


def diff_snapshots(
    before: Mapping[str, tuple[Any, ...]],
    after: Mapping[str, tuple[Any, ...]],
) -> dict[str, Any]:
    before_keys = set(before)
    after_keys = set(after)
    added = sorted(after_keys - before_keys)
    removed = sorted(before_keys - after_keys)
    modified = sorted(key for key in before_keys & after_keys if before[key] != after[key])
    all_changes = [f"added:{path}" for path in added]
    all_changes += [f"removed:{path}" for path in removed]
    all_changes += [f"modified:{path}" for path in modified]
    return {
        "change_count": len(all_changes),
        "changes": all_changes[:200],
        "changes_truncated": len(all_changes) > 200,
    }


def snapshot_output(root: Path) -> dict[str, tuple[Any, ...]]:
    """Snapshot only generator-owned files: bytes, size, type, and mtime."""
    result: dict[str, tuple[Any, ...]] = {}
    for name in OWNED_OUTPUTS:
        path = root / name
        if not path.exists() and not path.is_symlink():
            result[name] = ("missing",)
            continue
        stat = path.lstat()
        if path.is_symlink():
            result[name] = ("symlink", os.readlink(path), stat.st_mtime_ns)
        elif path.is_file():
            result[name] = ("file", stat.st_size, stat.st_mtime_ns, sha256_file(path))
        else:
            result[name] = ("other", stat.st_mtime_ns)
    return result


def process_record(result: ProcessResult, test_count: int | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "exit_code": result.returncode,
        "timed_out": result.timed_out,
    }
    if test_count is not None:
        record["tests_ran"] = test_count
    return record


def find_test_count(result: ProcessResult) -> int:
    combined = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")
    matches = re.findall(r"Ran\s+(\d+)\s+tests?\s+in\s+", combined)
    return int(matches[-1]) if matches else 0


def print_failure_tail(candidate: str, phase: str, result: ProcessResult) -> None:
    if not result.timed_out and result.returncode == 0:
        return
    combined = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")
    lines = [line for line in combined.replace("\r\n", "\n").split("\n") if line.strip()]
    print(
        f"[{candidate}] {phase} failed"
        f" (timeout={result.timed_out}, exit={result.returncode})",
        file=sys.stderr,
    )
    for line in lines[-8:]:
        print(f"[{candidate}]   {line[:500]}", file=sys.stderr)


def copy_owned_outputs(source: Path, destination: Path, omit: str | None = None) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for name in OWNED_OUTPUTS:
        if name != omit:
            shutil.copy2(source / name, destination / name)


def run_check_scenario(
    script: Path,
    candidate_dir: Path,
    dll_copy: Path,
    index_copy: Path,
    output_dir: Path,
    temp_root: Path,
    timeout: float,
    expect_success: bool,
) -> dict[str, Any]:
    before = snapshot_output(output_dir)
    result = run_child(
        (
            sys.executable,
            "-B",
            str(script),
            "--dll",
            str(dll_copy),
            "--function-index",
            str(index_copy),
            "--output-dir",
            str(output_dir),
            "--check",
        ),
        candidate_dir,
        temp_root,
        timeout,
    )
    after = snapshot_output(output_dir)
    accepted = not result.timed_out and result.returncode == 0
    return {
        "exit_code": result.returncode,
        "timed_out": result.timed_out,
        "expected_success": expect_success,
        "exit_behavior_ok": accepted == expect_success,
        "read_only": before == after,
    }


def test_source_markers(test_path: Path) -> dict[str, bool]:
    markers = {
        "real_corpus": False,
        "check_mode": False,
        "truncated_or_malformed": False,
        "wrong_machine": False,
        "wrong_magic": False,
        "duplicate_index": False,
        "output_mutation": False,
        "timestamp_preservation": False,
    }
    if not regular_file(test_path):
        return markers
    text = test_path.read_text(encoding="utf-8", errors="replace").lower()
    markers.update(
        {
            "real_corpus": "empire.retail.dll" in text and "canonical_function_index.tsv" in text,
            "check_mode": "--check" in text,
            "truncated_or_malformed": "trunc" in text or "malform" in text,
            "wrong_machine": "machine" in text or "014c" in text,
            "wrong_magic": "magic" in text or "010b" in text,
            "duplicate_index": "duplic" in text and "index" in text,
            "output_mutation": "mutat" in text,
            "timestamp_preservation": "mtime" in text or "timestamp" in text,
        }
    )
    return markers


def grade_candidate(
    candidate_dir: Path,
    repository: Path,
    results_dir: Path,
    dll_path: Path,
    index_path: Path,
    expected: ExpectedEvidence,
    timeout: float,
) -> dict[str, Any]:
    candidate = candidate_dir.name
    issues: list[str] = []
    record: dict[str, Any] = {"candidate": candidate}
    print(f"[{candidate}] grading")

    if not candidate_dir.is_dir() or candidate_dir.is_symlink():
        record.update(
            {
                "submission": {"exists": False, "files": []},
                "unit_tests": None,
                "generation": None,
                "outputs": None,
                "check_scenarios": None,
                "side_effects": None,
                "test_source_markers": {},
                "strict_oracle_pass": False,
                "issues": ["candidate directory is missing or is a symlink"],
            }
        )
        return record

    initial_entries = sorted(path.name for path in candidate_dir.iterdir())
    initial_submission_exact = initial_entries == sorted(SUBMISSION_FILES) and all(
        regular_file(candidate_dir / name) for name in SUBMISSION_FILES
    )
    if not initial_submission_exact:
        issues.append("submission does not initially contain exactly the three required regular files")
    source_hashes: dict[str, str | None] = {}
    for name in SUBMISSION_FILES:
        path = candidate_dir / name
        source_hashes[name] = sha256_file(path) if regular_file(path) else None
    record["submission"] = {
        "exists": True,
        "files_before": initial_entries,
        "exact_before": initial_submission_exact,
        "source_sha256_before": source_hashes,
    }
    test_path = candidate_dir / "test_gen_startup_audit.py"
    script_path = candidate_dir / "gen_startup_audit.py"
    record["test_source_markers"] = test_source_markers(test_path)

    own_before = snapshot_tree(candidate_dir, with_hashes=True)
    outside_before = snapshot_workspace(repository, (candidate_dir, results_dir))

    with tempfile.TemporaryDirectory(prefix=f"pi-startup-oracle-{candidate}-") as temporary:
        temp_root = Path(temporary)
        unit_temp = temp_root / "unit-temp"
        if regular_file(test_path):
            unit_result = run_child(
                (
                    sys.executable,
                    "-B",
                    "-m",
                    "unittest",
                    "-v",
                    "test_gen_startup_audit.py",
                ),
                candidate_dir,
                unit_temp,
                timeout,
            )
            test_count = find_test_count(unit_result)
            unit_ok = (
                not unit_result.timed_out and unit_result.returncode == 0 and test_count > 0
            )
            record["unit_tests"] = process_record(unit_result, test_count)
            record["unit_tests"]["ok"] = unit_ok
            if not unit_ok:
                issues.append("candidate unittest did not finish successfully with at least one test")
                print_failure_tail(candidate, "unittest", unit_result)
        else:
            unit_ok = False
            record["unit_tests"] = None
            issues.append("test_gen_startup_audit.py is missing or not a regular file")

        corpus = temp_root / "corpus"
        corpus.mkdir()
        dll_copy = corpus / "empire.retail.dll"
        index_copy = corpus / "canonical_function_index.tsv"
        shutil.copyfile(dll_path, dll_copy)
        shutil.copyfile(index_path, index_copy)
        generated = temp_root / "generated"
        generated.mkdir()
        generator_sha = sha256_file(script_path) if regular_file(script_path) else ""
        if regular_file(script_path):
            generation_result = run_child(
                (
                    sys.executable,
                    "-B",
                    str(script_path),
                    "--dll",
                    str(dll_copy),
                    "--function-index",
                    str(index_copy),
                    "--output-dir",
                    str(generated),
                ),
                candidate_dir,
                temp_root / "generation-temp",
                timeout,
            )
            generation_ok = (
                not generation_result.timed_out and generation_result.returncode == 0
            )
            record["generation"] = process_record(generation_result)
            record["generation"]["ok"] = generation_ok
            if not generation_ok:
                issues.append("real-corpus generation did not exit successfully")
                print_failure_tail(candidate, "generation", generation_result)
        else:
            generation_ok = False
            record["generation"] = None
            issues.append("gen_startup_audit.py is missing or not a regular file")

        output_entries = sorted(path.name for path in generated.iterdir()) if generated.is_dir() else []
        output_names_exact = output_entries == sorted(OWNED_OUTPUTS)
        output_regular = all(regular_file(generated / name) for name in OWNED_OUTPUTS)
        slots_exact = False
        slots_byte_exact = False
        summary_flags = {
            "json_parse": False,
            "canonical_format": False,
            "schema": False,
            "input_evidence": False,
            "generator_hash": False,
            "slots_evidence": False,
            "invocation_order": False,
            "table_evidence": False,
            "combined_totals": False,
            "evidence_only": False,
        }
        summary_issues: list[str] = []
        if output_regular:
            slots_raw = (generated / "startup_slots.tsv").read_bytes()
            slots_exact, slots_byte_exact, slots_issues = validate_slots_tsv(slots_raw, expected)
            issues.extend(slots_issues)
            if not slots_exact:
                issues.append("startup_slots.tsv differs semantically from the independent oracle")
            summary_raw = (generated / "startup_summary.json").read_bytes()
            summary_flags, summary_issues = validate_summary(
                summary_raw,
                expected,
                generator_sha,
                sha256_bytes(slots_raw),
            )
            issues.extend(summary_issues)
        else:
            issues.append("one or both owned outputs are missing, non-regular, or symlinks")
        summary_ok = all(summary_flags.values())
        record["outputs"] = {
            "files": output_entries,
            "names_exact": output_names_exact,
            "unrelated_entries": [name for name in output_entries if name not in OWNED_OUTPUTS],
            "regular_files": output_regular,
            "startup_slots_exact": slots_exact,
            "startup_slots_byte_exact": slots_byte_exact,
            "summary_checks": summary_flags,
            "summary_ok": summary_ok,
        }

        scenarios: dict[str, Any] = {}
        if output_regular and regular_file(script_path):
            scenarios["unchanged"] = run_check_scenario(
                script_path,
                candidate_dir,
                dll_copy,
                index_copy,
                generated,
                temp_root / "check-unchanged-temp",
                timeout,
                True,
            )

            mutation_dir = temp_root / "check-mutated"
            copy_owned_outputs(generated, mutation_dir)
            mutation_path = mutation_dir / "startup_slots.tsv"
            mutation = bytearray(mutation_path.read_bytes())
            if mutation:
                position = mutation.find(b"00000000", len(TSV_HEADER))
                if position < 0:
                    position = min(len(mutation) - 1, len(TSV_HEADER) + 1)
                mutation[position] = ord("1") if mutation[position] != ord("1") else ord("2")
                mutation_path.write_bytes(bytes(mutation))
                scenarios["mutated"] = run_check_scenario(
                    script_path,
                    candidate_dir,
                    dll_copy,
                    index_copy,
                    mutation_dir,
                    temp_root / "check-mutated-temp",
                    timeout,
                    False,
                )
            else:
                scenarios["mutated"] = {
                    "exit_code": None,
                    "timed_out": False,
                    "expected_success": False,
                    "exit_behavior_ok": False,
                    "read_only": True,
                }

            missing_dir = temp_root / "check-missing"
            copy_owned_outputs(generated, missing_dir, omit="startup_summary.json")
            scenarios["missing"] = run_check_scenario(
                script_path,
                candidate_dir,
                dll_copy,
                index_copy,
                missing_dir,
                temp_root / "check-missing-temp",
                timeout,
                False,
            )

            extra_dir = temp_root / "check-unrelated-extra"
            copy_owned_outputs(generated, extra_dir)
            (extra_dir / "startup_summary.json.oracle-extra").write_bytes(b"oracle extra\n")
            scenarios["unrelated_extra"] = run_check_scenario(
                script_path,
                candidate_dir,
                dll_copy,
                index_copy,
                extra_dir,
                temp_root / "check-extra-temp",
                timeout,
                True,
            )
        else:
            for name, expected_success in (
                ("unchanged", True),
                ("mutated", False),
                ("missing", False),
                ("unrelated_extra", True),
            ):
                scenarios[name] = {
                    "exit_code": None,
                    "timed_out": False,
                    "expected_success": expected_success,
                    "exit_behavior_ok": False,
                    "read_only": False,
                }
        for name, scenario in scenarios.items():
            if name != "unrelated_extra" and not scenario["exit_behavior_ok"]:
                issues.append(f"--check {name} scenario has incorrect exit behavior")
            if not scenario["read_only"]:
                issues.append(f"--check {name} scenario modified contents or timestamps")
        record["check_scenarios"] = scenarios

    own_after = snapshot_tree(candidate_dir, with_hashes=True)
    outside_after = snapshot_workspace(repository, (candidate_dir, results_dir))
    own_diff = diff_snapshots(own_before, own_after)
    outside_diff = diff_snapshots(outside_before, outside_after)
    if own_diff["change_count"]:
        issues.append("candidate execution modified its submission directory")
    if outside_diff["change_count"]:
        issues.append("workspace changes outside the candidate/temp directory were observed")
    record["side_effects"] = {
        "candidate_tree": own_diff,
        "workspace_outside_candidate": outside_diff,
    }

    final_entries = sorted(path.name for path in candidate_dir.iterdir())
    final_submission_exact = final_entries == sorted(SUBMISSION_FILES) and all(
        regular_file(candidate_dir / name) for name in SUBMISSION_FILES
    )
    record["submission"]["files_after"] = final_entries
    record["submission"]["exact_after"] = final_submission_exact
    record["submission"]["source_sha256_after"] = {
        name: sha256_file(candidate_dir / name) if regular_file(candidate_dir / name) else None
        for name in SUBMISSION_FILES
    }

    scenario_ok = all(
        record["check_scenarios"][name]["exit_behavior_ok"]
        and record["check_scenarios"][name]["read_only"]
        for name in ("unchanged", "mutated", "missing")
    ) and record["check_scenarios"]["unrelated_extra"]["read_only"]
    strict_pass = all(
        (
            initial_submission_exact,
            final_submission_exact,
            unit_ok,
            generation_ok,
            output_regular,
            slots_exact,
            summary_ok,
            scenario_ok,
            own_diff["change_count"] == 0,
            outside_diff["change_count"] == 0,
        )
    )
    record["strict_oracle_pass"] = strict_pass
    record["issues"] = sorted(set(issues))
    return record


def bool_cell(value: Any) -> str:
    if value is None:
        return "not_run"
    return "yes" if bool(value) else "no"


TSV_COLUMNS = (
    "candidate",
    "submission_exact_before",
    "submission_exact_after",
    "unit_tests_ok",
    "unit_tests_ran",
    "unit_tests_timed_out",
    "generation_ok",
    "generation_timed_out",
    "owned_outputs_present",
    "startup_slots_exact",
    "summary_json_valid",
    "summary_canonical",
    "summary_semantics_ok",
    "unchanged_check_ok",
    "unchanged_check_read_only",
    "mutation_rejected",
    "mutation_check_read_only",
    "missing_rejected",
    "missing_check_read_only",
    "unrelated_extra_accepted",
    "unrelated_extra_check_read_only",
    "candidate_tree_unchanged",
    "workspace_outside_unchanged",
    "strict_oracle_pass",
    "issue_count",
)


def record_to_tsv(record: Mapping[str, Any]) -> dict[str, str]:
    submission = record.get("submission") or {}
    unit = record.get("unit_tests") or {}
    generation = record.get("generation") or {}
    outputs = record.get("outputs") or {}
    summary_checks = outputs.get("summary_checks") or {}
    scenarios = record.get("check_scenarios") or {}
    unchanged = scenarios.get("unchanged") or {}
    mutated = scenarios.get("mutated") or {}
    missing = scenarios.get("missing") or {}
    extra = scenarios.get("unrelated_extra") or {}
    side_effects = record.get("side_effects") or {}
    own = side_effects.get("candidate_tree") or {}
    outside = side_effects.get("workspace_outside_candidate") or {}
    summary_semantics = all(
        bool(summary_checks.get(name))
        for name in (
            "schema",
            "input_evidence",
            "generator_hash",
            "slots_evidence",
            "invocation_order",
            "table_evidence",
            "combined_totals",
            "evidence_only",
        )
    )
    return {
        "candidate": str(record["candidate"]),
        "submission_exact_before": bool_cell(submission.get("exact_before")),
        "submission_exact_after": bool_cell(submission.get("exact_after")),
        "unit_tests_ok": bool_cell(unit.get("ok")),
        "unit_tests_ran": str(unit.get("tests_ran", 0)),
        "unit_tests_timed_out": bool_cell(unit.get("timed_out")),
        "generation_ok": bool_cell(generation.get("ok")),
        "generation_timed_out": bool_cell(generation.get("timed_out")),
        "owned_outputs_present": bool_cell(outputs.get("regular_files")),
        "startup_slots_exact": bool_cell(outputs.get("startup_slots_exact")),
        "summary_json_valid": bool_cell(summary_checks.get("json_parse")),
        "summary_canonical": bool_cell(summary_checks.get("canonical_format")),
        "summary_semantics_ok": bool_cell(summary_semantics),
        "unchanged_check_ok": bool_cell(unchanged.get("exit_behavior_ok")),
        "unchanged_check_read_only": bool_cell(unchanged.get("read_only")),
        "mutation_rejected": bool_cell(mutated.get("exit_behavior_ok")),
        "mutation_check_read_only": bool_cell(mutated.get("read_only")),
        "missing_rejected": bool_cell(missing.get("exit_behavior_ok")),
        "missing_check_read_only": bool_cell(missing.get("read_only")),
        "unrelated_extra_accepted": bool_cell(extra.get("exit_behavior_ok")),
        "unrelated_extra_check_read_only": bool_cell(extra.get("read_only")),
        "candidate_tree_unchanged": bool_cell(own.get("change_count") == 0),
        "workspace_outside_unchanged": bool_cell(outside.get("change_count") == 0),
        "strict_oracle_pass": bool_cell(record.get("strict_oracle_pass")),
        "issue_count": str(len(record.get("issues") or [])),
    }


def render_tsv(records: Sequence[Mapping[str, Any]]) -> bytes:
    import io

    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=TSV_COLUMNS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for record in records:
        writer.writerow(record_to_tsv(record))
    return stream.getvalue().encode("utf-8")


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def candidate_sort_key(path: Path) -> tuple[Any, ...]:
    pieces = re.split(r"(\d+)", path.name.casefold())
    return tuple(int(piece) if piece.isdigit() else piece for piece in pieces)


def discover_candidates(root: Path, requested: Sequence[str] | None) -> list[Path]:
    if requested:
        result: list[Path] = []
        for name in requested:
            if not name or Path(name).name != name or name in {".", ".."}:
                raise OracleError(f"invalid candidate name: {name!r}")
            result.append(root / name)
        return sorted(result, key=candidate_sort_key)
    if not root.is_dir():
        return []
    return sorted((path for path in root.iterdir() if path.is_dir()), key=candidate_sort_key)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    repository = Path(__file__).resolve().parent.parent
    bakeoff = repository / "out" / "pi-swarm" / "20260824-startup-code-bakeoff"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates-dir", type=Path, default=bakeoff / "candidates")
    parser.add_argument("--candidate", action="append", help="grade only this immediate child")
    parser.add_argument(
        "--dll",
        type=Path,
        default=repository / "Total War Rome II" / "empire.retail.dll",
    )
    parser.add_argument(
        "--function-index",
        type=Path,
        default=repository
        / "src_canonical_out"
        / "empire.retail.dll"
        / "canonical_function_index.tsv",
    )
    parser.add_argument("--results-dir", type=Path, default=bakeoff / "oracle-results")
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args(argv)
    if not args.timeout > 0:
        parser.error("--timeout must be positive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    candidates_root = args.candidates_dir.resolve()
    results_dir = args.results_dir.resolve()
    dll_path = args.dll.resolve()
    index_path = args.function_index.resolve()
    try:
        expected = build_expected(dll_path, index_path)
        candidates = discover_candidates(candidates_root, args.candidate)
    except (OSError, OracleError) as exc:
        print(f"oracle input failure: {exc}", file=sys.stderr)
        return 2

    records: list[dict[str, Any]] = []
    for candidate_dir in candidates:
        try:
            records.append(
                grade_candidate(
                    candidate_dir,
                    repository,
                    results_dir,
                    dll_path,
                    index_path,
                    expected,
                    args.timeout,
                )
            )
        except Exception as exc:  # A broken submission must not abort the cohort.
            print(f"[{candidate_dir.name}] oracle exception: {type(exc).__name__}: {exc}", file=sys.stderr)
            records.append(
                {
                    "candidate": candidate_dir.name,
                    "submission": {},
                    "unit_tests": None,
                    "generation": None,
                    "outputs": None,
                    "check_scenarios": None,
                    "side_effects": None,
                    "test_source_markers": {},
                    "strict_oracle_pass": False,
                    "issues": [f"oracle_exception:{type(exc).__name__}:{exc}"],
                }
            )

    total_slots = sum(len(table.raw_values) for table in expected.tables)
    total_nulls = sum(len(table.null_indices) for table in expected.tables)
    total_exact = sum(table.exact_join_count for table in expected.tables)
    report = {
        "schema": SCHEMA,
        "oracle_script_sha256": sha256_file(Path(__file__).resolve()),
        "inputs": {
            "dll": {"bytes": expected.dll_bytes, "sha256": expected.dll_sha256},
            "function_index": {
                "bytes": expected.index_bytes,
                "sha256": expected.index_sha256,
            },
        },
        "expected": {
            "invocation_order": [table.table_id for table in expected.tables],
            "startup_slots_rows": expected.slot_rows,
            "startup_slots_sha256": expected.slots_sha256,
            "totals": {
                "slots": total_slots,
                "nulls": total_nulls,
                "nonzero": total_slots - total_nulls,
                "exact_join": total_exact,
                "unresolved_exact": total_slots - total_nulls - total_exact,
            },
        },
        "timeout_seconds_per_process": args.timeout,
        "candidate_count": len(records),
        "strict_pass_count": sum(bool(record.get("strict_oracle_pass")) for record in records),
        "candidates": records,
        "limitations": [
            "Workspace side-effect attribution assumes no concurrent writer and uses final metadata snapshots outside each candidate.",
            "Writes outside the repository and redirected temp/home directories are not observable without an OS sandbox.",
            "Transient writes that restore the two owned files to identical bytes and mtimes may evade the final snapshot.",
            "Test coverage markers are lexical evidence only and are not included in strict pass/fail.",
        ],
    }
    json_bytes = (json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )
    tsv_bytes = render_tsv(records)
    try:
        write_atomic(results_dir / "startup_candidate_oracle.tsv", tsv_bytes)
        write_atomic(results_dir / "startup_candidate_oracle.json", json_bytes)
    except OSError as exc:
        print(f"cannot write oracle results: {exc}", file=sys.stderr)
        return 2
    print(
        f"graded {len(records)} candidates; strict passes: "
        f"{report['strict_pass_count']}; results: {results_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
