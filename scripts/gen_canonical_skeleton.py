#!/usr/bin/env python3
"""Validate and stage a canonical Ghidra decompilation snapshot.

This generator deliberately does not share code or output paths with the legacy
``gen_build_skeleton.py`` pipeline.  It consumes the schema emitted by
``ExportCanonicalDecompiled.java`` and publishes only source files that match
the snapshot's canonical identity and mapping fingerprint exactly.

Examples::

    python scripts/gen_canonical_skeleton.py `
        src_canonical_out/empire.retail.dll `
        --validate-only --allow-partial `
        --report-dir generated/canonical-reports/partial-scan

    python scripts/gen_canonical_skeleton.py `
        src_canonical_out/empire.retail.dll `
        --output-root generated/canonical

The emitted directory is ``<output-root>/<mapping-fingerprint>/``.  It is built
in a clean sibling temporary directory and renamed into place.  Existing
fingerprint directories are immutable and are never replaced.

First-version limits:

* Sources are validated and copied byte-for-byte; C types and bodies are not
  sanitized and no compile-ready compatibility headers are synthesized.
* References are lexical direct ``decomp_fn_*`` / ``decomp_g_*`` references.
  Calls through pointers, relocations, and legacy ``DAT_*`` symbols are not
  resolved here.
* The definition parser understands balanced C parentheses/braces and ignores
  comments, strings, and character literals.  It intentionally rejects exotic
  suffix declarators, K&R definitions, and multiple top-level definitions.
* ``--allow-partial`` tolerates missing indexed files only.  Other non-success
  states have separate explicit flags, and every tolerated inventory requires an
  atomic ``--report-dir``.  Staging always requires a complete corpus.
* The mapping fingerprint is reproduced exactly from the exporter.  The exporter
  currently omits the function ``kind`` column from that digest; full metadata
  file hashes are therefore recorded separately in each summary.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Sequence


FORMAT_MARKER = "canonical-address-v2"
SNAPSHOT_FILE = "canonical_snapshot.tsv"
FUNCTION_INDEX_FILE = "canonical_function_index.tsv"
DATA_INDEX_FILE = "canonical_data_index.tsv"
DEFAULT_DECOMP_DIR = "canonical_decomp"

SNAPSHOT_HEADER = (
    "format",
    "executable_sha256",
    "mapping_fingerprint",
    "functions",
    "data_symbols",
)
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

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
FUNCTION_NAME_RE = re.compile(r"decomp_fn_[a-z0-9_]+\Z")
DATA_NAME_RE = re.compile(r"decomp_g_[a-z0-9_]+\Z")
FUNCTION_REF_RE = re.compile(r"\bdecomp_fn_[a-z0-9_]+\b")
DATA_REF_RE = re.compile(r"\bdecomp_g_[a-z0-9_]+\b")


class ValidationError(RuntimeError):
    """A structural or publication invariant failed."""


@dataclass(frozen=True)
class Snapshot:
    format: str
    executable_sha256: str
    mapping_fingerprint: str
    functions: int
    data_symbols: int


@dataclass(frozen=True)
class FunctionRecord:
    entry: str
    canonical_name: str
    original_name: str
    original_qualified_name: str
    symbol_id: int
    namespace_id: int
    source_type: str
    signature: str
    size: int
    kind: str
    body_ranges: str
    direct_thunk_target: str
    resolved_thunk_target: str


@dataclass(frozen=True)
class DataRecord:
    address: str
    canonical_name: str
    original_name: str
    original_qualified_name: str
    symbol_id: int
    namespace_id: int
    source_type: str
    symbol_type: str
    data_type_path: str
    data_type_length: int
    code_unit_length: int


@dataclass(frozen=True)
class Definition:
    declaration: str
    start_char: int
    end_char: int
    start_line: int
    end_line: int
    name_start: int
    name_end: int
    function_refs: Counter[str]
    data_refs: Counter[str]


@dataclass(frozen=True)
class SourceResult:
    record: FunctionRecord
    path: Path
    status: str
    diagnostic: str = ""
    file_sha256: str = ""
    definition_sha256: str = ""
    definition: Definition | None = None


@dataclass(frozen=True)
class UnexpectedEntry:
    relative_path: str
    diagnostic: str


@dataclass
class Corpus:
    root: Path
    decomp_dir: Path
    snapshot: Snapshot
    functions: list[FunctionRecord]
    data: list[DataRecord]
    artifact_bytes: dict[str, bytes]
    artifact_sha256: dict[str, str]


@dataclass
class Inventory:
    corpus: Corpus
    sources: list[SourceResult]
    unexpected: list[UnexpectedEntry]
    executable_path: Path | None = None
    executable_verified: bool = False
    counts: Counter[str] = field(default_factory=Counter)

    @property
    def successes(self) -> list[SourceResult]:
        return [item for item in self.sources if item.status == "success"]

    @property
    def is_complete(self) -> bool:
        return (
            len(self.successes) == len(self.corpus.functions)
            and not self.unexpected
            and all(item.status == "success" for item in self.sources)
        )


@dataclass(frozen=True)
class ValidationPolicy:
    allow_missing: bool = False
    allow_stale: bool = False
    allow_invalid: bool = False
    allow_failed_export: bool = False
    allow_unexpected: bool = False

    @property
    def has_tolerances(self) -> bool:
        return any(
            (
                self.allow_missing,
                self.allow_stale,
                self.allow_invalid,
                self.allow_failed_export,
                self.allow_unexpected,
            )
        )


STRICT_POLICY = ValidationPolicy()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_field(digest, value: str) -> None:
    """Apply ExportCanonicalDecompiled.java's UTF-8/NUL field framing."""

    digest.update(value.encode("utf-8"))
    digest.update(b"\0")


def exporter_mapping_fingerprint(
    executable_sha256: str,
    functions: Sequence[FunctionRecord],
    data_records: Sequence[DataRecord],
) -> str:
    """Reproduce the canonical exporter's mapping-fingerprint algorithm."""

    digest = hashlib.sha256()
    digest_field(digest, FORMAT_MARKER)
    digest_field(digest, executable_sha256)
    for record in functions:
        for value in (
            "F",
            record.entry,
            record.canonical_name,
            str(record.symbol_id),
            str(record.namespace_id),
            record.source_type,
            record.original_name,
            record.original_qualified_name,
            record.signature,
            record.direct_thunk_target,
            record.resolved_thunk_target,
            str(record.size),
            record.body_ranges,
        ):
            digest_field(digest, value)
    for record in data_records:
        for value in (
            "D",
            record.address,
            record.canonical_name,
            str(record.symbol_id),
            str(record.namespace_id),
            record.source_type,
            record.original_name,
            record.original_qualified_name,
            record.symbol_type,
            record.data_type_path,
            str(record.data_type_length),
            str(record.code_unit_length),
        ):
            digest_field(digest, value)
    return digest.hexdigest()


def decode_utf8(path: Path, data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError(f"{path}: not valid UTF-8: {error}") from error


def read_exact_tsv(
    path: Path, expected_header: Sequence[str]
) -> tuple[bytes, list[dict[str, str]]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValidationError(f"cannot read required TSV {path}: {error}") from error
    text = decode_utf8(path, raw)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter="\t")
    try:
        actual_header = tuple(next(reader))
    except StopIteration as error:
        raise ValidationError(f"{path}: empty TSV") from error
    if actual_header != tuple(expected_header):
        raise ValidationError(
            f"{path}: schema mismatch; expected {tuple(expected_header)!r}, "
            f"got {actual_header!r}"
        )
    rows: list[dict[str, str]] = []
    for line_number, row in enumerate(reader, start=2):
        if not row:
            raise ValidationError(f"{path}:{line_number}: blank TSV row")
        if len(row) != len(expected_header):
            raise ValidationError(
                f"{path}:{line_number}: expected {len(expected_header)} fields, "
                f"got {len(row)}"
            )
        rows.append(dict(zip(expected_header, row, strict=True)))
    return raw, rows


def decimal_field(
    value: str, *, path: Path, line_number: int, field_name: str, minimum: int = 0
) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise ValidationError(
            f"{path}:{line_number}: {field_name} must be a decimal integer, got {value!r}"
        )
    result = int(value, 10)
    if result < minimum:
        raise ValidationError(
            f"{path}:{line_number}: {field_name} must be >= {minimum}, got {result}"
        )
    return result


def require_nonempty(
    value: str, *, path: Path, line_number: int, field_name: str
) -> str:
    if not value:
        raise ValidationError(f"{path}:{line_number}: {field_name} must not be empty")
    return value


def ensure_unique(
    values: Iterable[tuple[str, int]], *, path: Path, field_name: str
) -> None:
    seen: dict[str, int] = {}
    for value, line_number in values:
        previous = seen.get(value)
        if previous is not None:
            raise ValidationError(
                f"{path}:{line_number}: duplicate {field_name} {value!r}; "
                f"first seen on line {previous}"
            )
        seen[value] = line_number


def load_corpus(root: Path, decomp_dir: Path | None = None) -> Corpus:
    root = root.resolve()
    decomp_dir = (decomp_dir or (root / DEFAULT_DECOMP_DIR)).resolve()
    snapshot_path = root / SNAPSHOT_FILE
    function_path = root / FUNCTION_INDEX_FILE
    data_path = root / DATA_INDEX_FILE

    snapshot_raw, snapshot_rows = read_exact_tsv(snapshot_path, SNAPSHOT_HEADER)
    if len(snapshot_rows) != 1:
        raise ValidationError(
            f"{snapshot_path}: expected exactly one snapshot row, got {len(snapshot_rows)}"
        )
    snapshot_row = snapshot_rows[0]
    if snapshot_row["format"] != FORMAT_MARKER:
        raise ValidationError(
            f"{snapshot_path}: unsupported format {snapshot_row['format']!r}; "
            f"expected {FORMAT_MARKER!r}"
        )
    for field_name in ("executable_sha256", "mapping_fingerprint"):
        if not SHA256_RE.fullmatch(snapshot_row[field_name]):
            raise ValidationError(
                f"{snapshot_path}: {field_name} must be 64 lowercase hexadecimal characters"
            )
    snapshot = Snapshot(
        format=snapshot_row["format"],
        executable_sha256=snapshot_row["executable_sha256"],
        mapping_fingerprint=snapshot_row["mapping_fingerprint"],
        functions=decimal_field(
            snapshot_row["functions"],
            path=snapshot_path,
            line_number=2,
            field_name="functions",
        ),
        data_symbols=decimal_field(
            snapshot_row["data_symbols"],
            path=snapshot_path,
            line_number=2,
            field_name="data_symbols",
        ),
    )

    function_raw, function_rows = read_exact_tsv(function_path, FUNCTION_HEADER)
    functions: list[FunctionRecord] = []
    for line_number, row in enumerate(function_rows, start=2):
        entry = require_nonempty(
            row["entry"], path=function_path, line_number=line_number, field_name="entry"
        )
        canonical_name = row["canonical_name"]
        if not FUNCTION_NAME_RE.fullmatch(canonical_name):
            raise ValidationError(
                f"{function_path}:{line_number}: invalid canonical function name "
                f"{canonical_name!r}"
            )
        if re.fullmatch(r"[0-9a-fA-F]+", entry):
            expected_name = "decomp_fn_" + entry.lower()
            if canonical_name != expected_name:
                raise ValidationError(
                    f"{function_path}:{line_number}: entry {entry!r} requires canonical "
                    f"name {expected_name!r}, got {canonical_name!r}"
                )
        kind = row["kind"]
        if kind not in {"func", "thunk"}:
            raise ValidationError(
                f"{function_path}:{line_number}: kind must be 'func' or 'thunk', got {kind!r}"
            )
        functions.append(
            FunctionRecord(
                entry=entry,
                canonical_name=canonical_name,
                original_name=require_nonempty(
                    row["original_name"],
                    path=function_path,
                    line_number=line_number,
                    field_name="original_name",
                ),
                original_qualified_name=require_nonempty(
                    row["original_qualified_name"],
                    path=function_path,
                    line_number=line_number,
                    field_name="original_qualified_name",
                ),
                symbol_id=decimal_field(
                    row["symbol_id"],
                    path=function_path,
                    line_number=line_number,
                    field_name="symbol_id",
                ),
                namespace_id=decimal_field(
                    row["namespace_id"],
                    path=function_path,
                    line_number=line_number,
                    field_name="namespace_id",
                ),
                source_type=require_nonempty(
                    row["source_type"],
                    path=function_path,
                    line_number=line_number,
                    field_name="source_type",
                ),
                signature=require_nonempty(
                    row["signature"],
                    path=function_path,
                    line_number=line_number,
                    field_name="signature",
                ),
                size=decimal_field(
                    row["size"],
                    path=function_path,
                    line_number=line_number,
                    field_name="size",
                    minimum=1,
                ),
                kind=kind,
                body_ranges=require_nonempty(
                    row["body_ranges"],
                    path=function_path,
                    line_number=line_number,
                    field_name="body_ranges",
                ),
                direct_thunk_target=row["direct_thunk_target"],
                resolved_thunk_target=row["resolved_thunk_target"],
            )
        )
    ensure_unique(
        ((record.entry, line) for line, record in enumerate(functions, start=2)),
        path=function_path,
        field_name="entry",
    )
    ensure_unique(
        ((record.canonical_name, line) for line, record in enumerate(functions, start=2)),
        path=function_path,
        field_name="canonical_name",
    )
    ensure_unique(
        ((str(record.symbol_id), line) for line, record in enumerate(functions, start=2)),
        path=function_path,
        field_name="symbol_id",
    )

    data_raw, data_rows = read_exact_tsv(data_path, DATA_HEADER)
    data_records: list[DataRecord] = []
    for line_number, row in enumerate(data_rows, start=2):
        address = require_nonempty(
            row["address"], path=data_path, line_number=line_number, field_name="address"
        )
        canonical_name = row["canonical_name"]
        if not DATA_NAME_RE.fullmatch(canonical_name):
            raise ValidationError(
                f"{data_path}:{line_number}: invalid canonical data name {canonical_name!r}"
            )
        if re.fullmatch(r"[0-9a-fA-F]+", address):
            expected_name = "decomp_g_" + address.lower()
            if canonical_name != expected_name:
                raise ValidationError(
                    f"{data_path}:{line_number}: address {address!r} requires canonical "
                    f"name {expected_name!r}, got {canonical_name!r}"
                )
        data_records.append(
            DataRecord(
                address=address,
                canonical_name=canonical_name,
                original_name=require_nonempty(
                    row["original_name"],
                    path=data_path,
                    line_number=line_number,
                    field_name="original_name",
                ),
                original_qualified_name=require_nonempty(
                    row["original_qualified_name"],
                    path=data_path,
                    line_number=line_number,
                    field_name="original_qualified_name",
                ),
                symbol_id=decimal_field(
                    row["symbol_id"],
                    path=data_path,
                    line_number=line_number,
                    field_name="symbol_id",
                ),
                namespace_id=decimal_field(
                    row["namespace_id"],
                    path=data_path,
                    line_number=line_number,
                    field_name="namespace_id",
                ),
                source_type=require_nonempty(
                    row["source_type"],
                    path=data_path,
                    line_number=line_number,
                    field_name="source_type",
                ),
                symbol_type=require_nonempty(
                    row["symbol_type"],
                    path=data_path,
                    line_number=line_number,
                    field_name="symbol_type",
                ),
                data_type_path=row["data_type_path"],
                data_type_length=decimal_field(
                    row["data_type_length"],
                    path=data_path,
                    line_number=line_number,
                    field_name="data_type_length",
                ),
                code_unit_length=decimal_field(
                    row["code_unit_length"],
                    path=data_path,
                    line_number=line_number,
                    field_name="code_unit_length",
                ),
            )
        )
    ensure_unique(
        ((record.address, line) for line, record in enumerate(data_records, start=2)),
        path=data_path,
        field_name="address",
    )
    ensure_unique(
        ((record.canonical_name, line) for line, record in enumerate(data_records, start=2)),
        path=data_path,
        field_name="canonical_name",
    )
    ensure_unique(
        ((str(record.symbol_id), line) for line, record in enumerate(data_records, start=2)),
        path=data_path,
        field_name="symbol_id",
    )

    if len(functions) != snapshot.functions:
        raise ValidationError(
            f"{snapshot_path}: functions={snapshot.functions}, but {function_path} has "
            f"{len(functions)} rows"
        )
    if len(data_records) != snapshot.data_symbols:
        raise ValidationError(
            f"{snapshot_path}: data_symbols={snapshot.data_symbols}, but {data_path} has "
            f"{len(data_records)} rows"
        )

    computed_fingerprint = exporter_mapping_fingerprint(
        snapshot.executable_sha256, functions, data_records
    )
    if computed_fingerprint != snapshot.mapping_fingerprint:
        raise ValidationError(
            f"{snapshot_path}: mapping_fingerprint does not bind the loaded indexes; "
            f"snapshot={snapshot.mapping_fingerprint}, computed={computed_fingerprint}"
        )

    artifacts = {
        SNAPSHOT_FILE: snapshot_raw,
        FUNCTION_INDEX_FILE: function_raw,
        DATA_INDEX_FILE: data_raw,
    }
    return Corpus(
        root=root,
        decomp_dir=decomp_dir,
        snapshot=snapshot,
        functions=functions,
        data=data_records,
        artifact_bytes=artifacts,
        artifact_sha256={name: sha256_bytes(raw) for name, raw in artifacts.items()},
    )


def mask_c_comments_and_literals(text: str) -> str:
    """Return an equal-length view with comments/literals replaced by spaces."""

    output = list(text)
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if char == '"':
                output[index] = " "
                index += 1
                state = "string"
                continue
            if char == "'":
                output[index] = " "
                index += 1
                state = "char"
                continue
            index += 1
            continue
        if state == "line_comment":
            if char == "\r" and following == "\n":
                continued = index > 0 and text[index - 1] == "\\"
                index += 2
                if not continued:
                    state = "code"
            elif char == "\n":
                continued = index > 0 and text[index - 1] == "\\"
                index += 1
                if not continued:
                    state = "code"
            else:
                output[index] = " "
                index += 1
            continue
        if state == "block_comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
            else:
                if char not in "\r\n":
                    output[index] = " "
                index += 1
            continue
        if state in {"string", "char"}:
            terminator = '"' if state == "string" else "'"
            if char == "\\":
                output[index] = " "
                if index + 1 < len(text):
                    if text[index + 1] not in "\r\n":
                        output[index + 1] = " "
                    index += 2
                else:
                    index += 1
                continue
            if char == terminator:
                output[index] = " "
                index += 1
                state = "code"
                continue
            if char not in "\r\n":
                output[index] = " "
            index += 1
            continue
        raise AssertionError(f"unknown lexer state {state}")
    if state == "block_comment":
        raise ValidationError("unterminated block comment")
    if state in {"string", "char"}:
        raise ValidationError(f"unterminated {state} literal")
    return "".join(output)


def skip_space(masked: str, index: int) -> int:
    while index < len(masked) and masked[index].isspace():
        index += 1
    return index


def balanced_end(masked: str, start: int, opening: str, closing: str) -> int:
    if start >= len(masked) or masked[start] != opening:
        raise ValidationError(f"expected {opening!r} at character {start}")
    depth = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index + 1
            if depth < 0:
                break
    raise ValidationError(f"unbalanced {opening}{closing} starting at character {start}")


def definition_start(masked: str, name_start: int) -> int:
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    last_delimiter = -1
    for index, char in enumerate(masked[:name_start]):
        if char == "(":
            paren_depth += 1
        elif char == ")" and paren_depth:
            paren_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        elif char == "{":
            brace_depth += 1
        elif char == "}" and brace_depth:
            brace_depth -= 1
            if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                last_delimiter = index
        elif (
            char == ";"
            and paren_depth == 0
            and bracket_depth == 0
            and brace_depth == 0
        ):
            last_delimiter = index
    return skip_space(masked, last_delimiter + 1)


def parse_canonical_definition(text: str, expected_name: str) -> Definition:
    if not FUNCTION_NAME_RE.fullmatch(expected_name):
        raise ValidationError(f"invalid expected canonical name {expected_name!r}")
    masked = mask_c_comments_and_literals(text)
    if re.search(r"(?m)^[ \t]*#", masked):
        raise ValidationError(
            "preprocessor directives are not supported in canonical definition files"
        )
    pattern = re.compile(r"\b" + re.escape(expected_name) + r"\b")
    candidates: list[tuple[int, int, int, int, int]] = []
    for match in pattern.finditer(masked):
        open_paren = skip_space(masked, match.end())
        if open_paren >= len(masked) or masked[open_paren] != "(":
            continue
        close_paren = balanced_end(masked, open_paren, "(", ")")
        open_brace = skip_space(masked, close_paren)
        if open_brace < len(masked) and masked[open_brace] == "{":
            candidates.append(
                (match.start(), match.end(), open_paren, close_paren, open_brace)
            )
    if not candidates:
        raise ValidationError(
            f"no definition anchored on canonical identifier {expected_name!r}"
        )
    if len(candidates) != 1:
        raise ValidationError(
            f"found {len(candidates)} definitions anchored on {expected_name!r}; expected one"
        )
    name_start, name_end, _open_paren, _close_paren, open_brace = candidates[0]
    start = definition_start(masked, name_start)
    if masked[:start].strip():
        raise ValidationError("unexpected top-level code before canonical definition")
    body_end = balanced_end(masked, open_brace, "{", "}")
    if masked[body_end:].strip():
        raise ValidationError("unexpected top-level code after canonical definition")
    declaration = text[start:open_brace].strip()
    if not declaration or expected_name not in declaration:
        raise ValidationError("could not isolate the canonical declaration")
    definition_mask = masked[start:body_end]
    relative_name_start = name_start - start
    relative_name_end = name_end - start
    function_refs: Counter[str] = Counter()
    for match in FUNCTION_REF_RE.finditer(definition_mask):
        if (
            match.start() == relative_name_start
            and match.end() == relative_name_end
        ):
            continue
        function_refs[match.group(0)] += 1
    data_refs = Counter(match.group(0) for match in DATA_REF_RE.finditer(definition_mask))
    return Definition(
        declaration=" ".join(declaration.split()),
        start_char=start,
        end_char=body_end,
        start_line=text.count("\n", 0, start) + 1,
        end_line=text.count("\n", 0, body_end) + 1,
        name_start=name_start,
        name_end=name_end,
        function_refs=function_refs,
        data_refs=data_refs,
    )


def exact_single_line(lines: Sequence[str], expected: str, label: str) -> str | None:
    matches = [line for line in lines if line.startswith(label)]
    if matches != [expected]:
        return f"expected exactly {expected!r}; found {matches!r}"
    return None


def validate_source_file(
    record: FunctionRecord, path: Path, snapshot: Snapshot
) -> SourceResult:
    if not path.exists():
        return SourceResult(record=record, path=path, status="missing")
    if path.is_symlink():
        return SourceResult(
            record=record, path=path, status="invalid", diagnostic="source is a symlink"
        )
    if not path.is_file():
        return SourceResult(
            record=record,
            path=path,
            status="invalid",
            diagnostic="expected source path is not a regular file",
        )
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return SourceResult(
            record=record,
            path=path,
            status="invalid",
            diagnostic=f"cannot read UTF-8 source: {error}",
        )
    file_hash = sha256_bytes(raw)
    lines = text.splitlines()
    stale_reasons = [
        reason
        for reason in (
            exact_single_line(
                lines,
                f"// Export format: {snapshot.format}",
                "// Export format:",
            ),
            exact_single_line(
                lines,
                f"// Mapping fingerprint: {snapshot.mapping_fingerprint}",
                "// Mapping fingerprint:",
            ),
        )
        if reason
    ]
    if stale_reasons:
        return SourceResult(
            record=record,
            path=path,
            status="stale",
            diagnostic="; ".join(stale_reasons),
            file_sha256=file_hash,
        )
    expected_eof = (
        f"// Canonical export EOF: success {record.canonical_name} "
        f"{snapshot.mapping_fingerprint}"
    )
    identity_reasons = [
        reason
        for reason in (
            exact_single_line(
                lines,
                f"// Canonical function: {record.canonical_name}",
                "// Canonical function:",
            ),
            exact_single_line(lines, "// Export result: success", "// Export result:"),
            exact_single_line(
                lines,
                f"// Entry: 0x{record.entry}  Size: {record.size}",
                "// Entry:",
            ),
            exact_single_line(
                lines,
                f"// Original function: {record.original_qualified_name}",
                "// Original function:",
            ),
            exact_single_line(
                lines,
                f"// Original signature: {record.signature}",
                "// Original signature:",
            ),
        )
        if reason
    ]
    eof_matches = [
        line for line in lines if line.startswith("// Canonical export EOF:")
    ]
    if eof_matches != [expected_eof] or not lines or lines[-1] != expected_eof:
        identity_reasons.append(
            f"expected one exact final success EOF {expected_eof!r}; "
            f"found {eof_matches!r}"
        )
    if identity_reasons:
        result_lines = [line for line in lines if line.startswith("// Export result:")]
        status = "failed_export" if result_lines and result_lines != ["// Export result: success"] else "invalid"
        return SourceResult(
            record=record,
            path=path,
            status=status,
            diagnostic="; ".join(identity_reasons),
            file_sha256=file_hash,
        )
    try:
        definition = parse_canonical_definition(text, record.canonical_name)
    except ValidationError as error:
        return SourceResult(
            record=record,
            path=path,
            status="invalid",
            diagnostic=str(error),
            file_sha256=file_hash,
        )
    return SourceResult(
        record=record,
        path=path,
        status="success",
        file_sha256=file_hash,
        definition_sha256=sha256_bytes(
            text[definition.start_char : definition.end_char].encode("utf-8")
        ),
        definition=definition,
    )


def enumerate_actual_entries(decomp_dir: Path) -> list[Path]:
    if not decomp_dir.exists():
        raise ValidationError(f"decompilation directory does not exist: {decomp_dir}")
    if not decomp_dir.is_dir():
        raise ValidationError(f"decompilation path is not a directory: {decomp_dir}")
    try:
        return sorted(decomp_dir.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise ValidationError(f"cannot enumerate {decomp_dir}: {error}") from error


def unexpected_entries(
    entries: Sequence[Path], expected_names: set[str]
) -> list[UnexpectedEntry]:
    return [
        UnexpectedEntry(
            relative_path=entry.name,
            diagnostic=(
                "unexpected directory" if entry.is_dir() else "not indexed by canonical name"
            ),
        )
        for entry in entries
        if entry.name not in expected_names
    ]


def validate_corpus(
    corpus: Corpus, *, jobs: int = 1, executable_path: Path | None = None
) -> Inventory:
    expected_names = {record.canonical_name + ".c" for record in corpus.functions}
    actual_entries = enumerate_actual_entries(corpus.decomp_dir)
    actual_by_name = {entry.name: entry for entry in actual_entries}

    def inspect(record: FunctionRecord) -> SourceResult:
        return validate_source_file(
            record,
            actual_by_name.get(
                record.canonical_name + ".c",
                corpus.decomp_dir / (record.canonical_name + ".c"),
            ),
            corpus.snapshot,
        )

    if jobs <= 1:
        sources = [inspect(record) for record in corpus.functions]
    else:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            sources = list(executor.map(inspect, corpus.functions, chunksize=64))

    # The exporter publishes through a short-lived sibling temporary file. Use a
    # fresh directory view after the long scan so a temp entry that has already
    # been renamed does not become a false unexpected result.
    unexpected = unexpected_entries(
        enumerate_actual_entries(corpus.decomp_dir), expected_names
    )

    function_names = {record.canonical_name for record in corpus.functions}
    data_names = {record.canonical_name for record in corpus.data}
    checked_sources: list[SourceResult] = []
    for source in sources:
        if source.definition is None:
            checked_sources.append(source)
            continue
        unknown_functions = sorted(set(source.definition.function_refs) - function_names)
        unknown_data = sorted(set(source.definition.data_refs) - data_names)
        if unknown_functions or unknown_data:
            reasons = []
            if unknown_functions:
                reasons.append("unindexed function refs: " + ",".join(unknown_functions))
            if unknown_data:
                reasons.append("unindexed data refs: " + ",".join(unknown_data))
            checked_sources.append(
                replace(source, status="invalid", diagnostic="; ".join(reasons))
            )
        else:
            checked_sources.append(source)

    executable_verified = False
    resolved_executable: Path | None = None
    if executable_path is not None:
        resolved_executable = executable_path.resolve()
        if not resolved_executable.is_file():
            raise ValidationError(f"executable is not a regular file: {resolved_executable}")
        actual_sha = sha256_file(resolved_executable)
        if actual_sha != corpus.snapshot.executable_sha256:
            raise ValidationError(
                f"executable SHA-256 mismatch: snapshot={corpus.snapshot.executable_sha256}, "
                f"actual={actual_sha}, file={resolved_executable}"
            )
        executable_verified = True

    # Reject a mixed validation if a live writer replaced any metadata file while
    # source inspection was in progress. Source bytes are independently rehashed
    # again during publication.
    verify_input_artifacts_unchanged(corpus)

    counts = Counter(source.status for source in checked_sources)
    counts["unexpected"] = len(unexpected)
    return Inventory(
        corpus=corpus,
        sources=checked_sources,
        unexpected=unexpected,
        executable_path=resolved_executable,
        executable_verified=executable_verified,
        counts=counts,
    )


def partial_diagnostics(inventory: Inventory, limit: int = 12) -> list[str]:
    diagnostics: list[str] = []
    # Surface contamination before the (usually much larger) missing-file list.
    for status in ("stale", "invalid", "failed_export"):
        for source in inventory.sources:
            if source.status != status:
                continue
            detail = f": {source.diagnostic}" if source.diagnostic else ""
            diagnostics.append(
                f"{source.status}: {source.record.canonical_name}.c{detail}"
            )
            if len(diagnostics) >= limit:
                return diagnostics
    for entry in inventory.unexpected:
        diagnostics.append(
            f"unexpected: {entry.relative_path}: {entry.diagnostic}"
        )
        if len(diagnostics) >= limit:
            return diagnostics
    for source in inventory.sources:
        if source.status != "missing":
            continue
        diagnostics.append(
            f"missing: {source.record.canonical_name}.c"
        )
        if len(diagnostics) >= limit:
            break
    return diagnostics


STATUS_POLICY = (
    ("missing", "allow_missing", "--allow-partial"),
    ("stale", "allow_stale", "--allow-stale"),
    ("invalid", "allow_invalid", "--allow-invalid"),
    ("failed_export", "allow_failed_export", "--allow-failed-export"),
    ("unexpected", "allow_unexpected", "--allow-unexpected"),
)


def enforce_completeness(
    inventory: Inventory, policy: ValidationPolicy = STRICT_POLICY
) -> None:
    if inventory.is_complete:
        return
    counts = inventory.counts
    disallowed = [
        (status, flag)
        for status, attribute, flag in STATUS_POLICY
        if counts[status] and not getattr(policy, attribute)
    ]
    if not disallowed:
        return
    details = "; ".join(partial_diagnostics(inventory, limit=5))
    required_flags = ", ".join(
        f"{flag} ({counts[status]} {status})" for status, flag in disallowed
    )
    raise ValidationError(
        "canonical corpus is incomplete or contaminated: "
        f"success={counts['success']} missing={counts['missing']} "
        f"stale={counts['stale']} invalid={counts['invalid']} "
        f"failed_export={counts['failed_export']} unexpected={counts['unexpected']}. "
        f"Explicit tolerance required: {required_flags}. "
        f"Examples: {details}"
    )


MANIFEST_HEADER = (
    "record_type",
    "mapping_fingerprint",
    "address",
    "canonical_name",
    "source_file",
    "source_status",
    "parse_status",
    "file_sha256",
    "definition_sha256",
    "definition_start_line",
    "definition_end_line",
    "declaration",
    "outgoing_function_targets",
    "outgoing_function_occurrences",
    "outgoing_data_targets",
    "outgoing_data_occurrences",
    "incoming_reference_sources",
    "incoming_reference_occurrences",
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
    "symbol_type",
    "data_type_path",
    "data_type_length",
    "code_unit_length",
    "diagnostic",
)

REFERENCE_HEADER = (
    "source_canonical_name",
    "source_entry",
    "source_status",
    "target_kind",
    "target_canonical_name",
    "target_indexed",
    "target_address",
    "target_source_status",
    "occurrences",
)


def tsv_bytes(header: Sequence[str], rows: Iterable[Sequence[object]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow(["" if value is None else value for value in row])
    return output.getvalue().encode("utf-8")


def manifest_bytes(inventory: Inventory) -> bytes:
    source_by_name = {
        source.record.canonical_name: source for source in inventory.sources
    }
    incoming_sources: dict[str, set[str]] = defaultdict(set)
    incoming_occurrences: Counter[str] = Counter()
    for source in inventory.sources:
        if source.definition is None:
            continue
        for target, occurrences in (
            source.definition.function_refs + source.definition.data_refs
        ).items():
            incoming_sources[target].add(source.record.canonical_name)
            incoming_occurrences[target] += occurrences

    rows: list[list[object]] = []
    fingerprint = inventory.corpus.snapshot.mapping_fingerprint
    for record in inventory.corpus.functions:
        source = source_by_name[record.canonical_name]
        definition = source.definition
        rows.append(
            [
                "function",
                fingerprint,
                record.entry,
                record.canonical_name,
                record.canonical_name + ".c",
                source.status,
                "parsed" if definition else "not_parsed",
                source.file_sha256,
                source.definition_sha256,
                definition.start_line if definition else "",
                definition.end_line if definition else "",
                definition.declaration if definition else "",
                len(definition.function_refs) if definition else 0,
                sum(definition.function_refs.values()) if definition else 0,
                len(definition.data_refs) if definition else 0,
                sum(definition.data_refs.values()) if definition else 0,
                len(incoming_sources[record.canonical_name]),
                incoming_occurrences[record.canonical_name],
                record.original_name,
                record.original_qualified_name,
                record.symbol_id,
                record.namespace_id,
                record.source_type,
                record.signature,
                record.size,
                record.kind,
                record.body_ranges,
                record.direct_thunk_target,
                record.resolved_thunk_target,
                "",
                "",
                "",
                "",
                source.diagnostic,
            ]
        )
    for record in inventory.corpus.data:
        rows.append(
            [
                "data",
                fingerprint,
                record.address,
                record.canonical_name,
                "",
                "indexed",
                "not_applicable",
                "",
                "",
                "",
                "",
                "",
                0,
                0,
                0,
                0,
                len(incoming_sources[record.canonical_name]),
                incoming_occurrences[record.canonical_name],
                record.original_name,
                record.original_qualified_name,
                record.symbol_id,
                record.namespace_id,
                record.source_type,
                "",
                "",
                "",
                "",
                "",
                "",
                record.symbol_type,
                record.data_type_path,
                record.data_type_length,
                record.code_unit_length,
                "",
            ]
        )
    for entry in inventory.unexpected:
        rows.append(
            [
                "unexpected",
                fingerprint,
                "",
                "",
                entry.relative_path,
                "unexpected",
                "not_parsed",
                "",
                "",
                "",
                "",
                "",
                0,
                0,
                0,
                0,
                0,
                0,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                entry.diagnostic,
            ]
        )
    return tsv_bytes(MANIFEST_HEADER, rows)


def references_bytes(inventory: Inventory) -> bytes:
    function_by_name = {
        record.canonical_name: record for record in inventory.corpus.functions
    }
    data_by_name = {record.canonical_name: record for record in inventory.corpus.data}
    status_by_name = {
        source.record.canonical_name: source.status for source in inventory.sources
    }
    rows: list[list[object]] = []
    for source in inventory.sources:
        if source.definition is None:
            continue
        for target, occurrences in sorted(source.definition.function_refs.items()):
            target_record = function_by_name.get(target)
            rows.append(
                [
                    source.record.canonical_name,
                    source.record.entry,
                    source.status,
                    "function",
                    target,
                    "yes" if target_record else "no",
                    target_record.entry if target_record else "",
                    status_by_name[target] if target_record else "unindexed",
                    occurrences,
                ]
            )
        for target, occurrences in sorted(source.definition.data_refs.items()):
            target_record = data_by_name.get(target)
            rows.append(
                [
                    source.record.canonical_name,
                    source.record.entry,
                    source.status,
                    "data",
                    target,
                    "yes" if target_record else "no",
                    target_record.address if target_record else "",
                    "indexed" if target_record else "unindexed",
                    occurrences,
                ]
            )
    return tsv_bytes(REFERENCE_HEADER, rows)


def summary_dict(
    inventory: Inventory, policy: ValidationPolicy = STRICT_POLICY
) -> dict[str, object]:
    function_edges = 0
    function_occurrences = 0
    data_edges = 0
    data_occurrences = 0
    for source in inventory.sources:
        if source.definition is None:
            continue
        function_edges += len(source.definition.function_refs)
        function_occurrences += sum(source.definition.function_refs.values())
        data_edges += len(source.definition.data_refs)
        data_occurrences += sum(source.definition.data_refs.values())
    return {
        "format": inventory.corpus.snapshot.format,
        "mapping_fingerprint": inventory.corpus.snapshot.mapping_fingerprint,
        "executable_sha256": inventory.corpus.snapshot.executable_sha256,
        "executable_verified": inventory.executable_verified,
        "executable_verification": (
            "verified" if inventory.executable_verified else "not_requested"
        ),
        "expected_functions": len(inventory.corpus.functions),
        "indexed_data_symbols": len(inventory.corpus.data),
        "source_success": inventory.counts["success"],
        "source_missing": inventory.counts["missing"],
        "source_stale": inventory.counts["stale"],
        "source_invalid": inventory.counts["invalid"],
        "source_failed_export": inventory.counts["failed_export"],
        "unexpected_entries": inventory.counts["unexpected"],
        "parsed_definitions": sum(
            source.definition is not None for source in inventory.sources
        ),
        "function_reference_edges": function_edges,
        "function_reference_occurrences": function_occurrences,
        "data_reference_edges": data_edges,
        "data_reference_occurrences": data_occurrences,
        "complete": inventory.is_complete,
        "allow_partial": policy.allow_missing,
        "validation_policy": {
            "allow_missing": policy.allow_missing,
            "allow_stale": policy.allow_stale,
            "allow_invalid": policy.allow_invalid,
            "allow_failed_export": policy.allow_failed_export,
            "allow_unexpected": policy.allow_unexpected,
        },
        "metadata_sha256": dict(sorted(inventory.corpus.artifact_sha256.items())),
    }


LIMITS_TEXT = """Canonical skeleton staging limits (first version)

- Validated source files are copied byte-for-byte; no C/C++ body or type
  sanitization is performed.
- No compile-ready global declarations, compatibility layer, linker inputs, or
  ABI claims are generated.
- The mapping fingerprint exactly mirrors ExportCanonicalDecompiled.java. That
  exporter currently omits the function kind column; validation_summary.json
  separately records SHA-256 for all three complete metadata files.
- references.tsv recognizes direct lexical decomp_fn_* and decomp_g_* tokens
  outside comments and literals. It does not resolve pointer calls, relocations,
  macros, DAT_*/PTR_* symbols, or dynamic imports.
- Definition parsing supports ordinary balanced C declarators/bodies. Exotic
  suffix declarators, K&R definitions, preprocessor-dependent syntax, and files
  containing multiple top-level definitions are rejected rather than rewritten.
- Partial/contaminated inventories are validation-only and require an atomic
  manifest/summary report. Missing, stale, malformed, failed, and unexpected
  states each have explicit policy. A fingerprint-keyed source stage is emitted
  only for complete coverage with no non-success inputs.
- Batch-local canonical_export_status.tsv and canonical_rollback_status.tsv are
  not acceptance-gated by this first version. Verify the final wrapper result
  and fresh-process rollback separately before consuming a completed stage.
"""


def safe_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def verify_input_artifacts_unchanged(corpus: Corpus) -> None:
    for name, expected_hash in corpus.artifact_sha256.items():
        path = corpus.root / name
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            raise ValidationError(
                f"input metadata changed during validation: {path} "
                f"({expected_hash} -> {actual_hash})"
            )


def reject_protected_output(output_root: Path, corpus: Corpus) -> None:
    resolved = output_root.resolve()
    repository_root = Path(__file__).resolve().parent.parent
    protected = [
        (repository_root / "src").resolve(),
        (repository_root / "buildable").resolve(),
        corpus.root.resolve(),
        corpus.decomp_dir.resolve(),
    ]
    for protected_path in protected:
        if resolved == protected_path or protected_path in resolved.parents:
            raise ValidationError(
                f"refusing staging output inside protected live tree {protected_path}: "
                f"{resolved}"
            )


def emit_stage(
    inventory: Inventory, output_root: Path
) -> Path:
    if not inventory.is_complete:
        raise ValidationError(
            "refusing to publish an immutable fingerprint stage from a partial corpus; "
            "use --validate-only --allow-partial until coverage is complete"
        )
    corpus = inventory.corpus
    if output_root.is_symlink():
        raise ValidationError(f"output root must not be a symlink: {output_root}")
    output_root = output_root.resolve()
    reject_protected_output(output_root, corpus)
    output_root.mkdir(parents=True, exist_ok=True)
    if output_root.is_symlink() or not output_root.is_dir():
        raise ValidationError(f"output root must be a real directory: {output_root}")
    destination = output_root / corpus.snapshot.mapping_fingerprint
    if destination.exists() or destination.is_symlink():
        raise ValidationError(
            f"immutable fingerprint stage already exists; refusing replacement: {destination}"
        )

    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{corpus.snapshot.mapping_fingerprint}.", dir=output_root
        )
    )
    try:
        verify_input_artifacts_unchanged(corpus)
        (temporary / "sources").mkdir()
        for name, raw in corpus.artifact_bytes.items():
            safe_write(temporary / "metadata" / name, raw)
        safe_write(temporary / "joined_manifest.tsv", manifest_bytes(inventory))
        safe_write(temporary / "references.tsv", references_bytes(inventory))
        summary = json.dumps(
            summary_dict(inventory, STRICT_POLICY),
            indent=2,
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        safe_write(temporary / "validation_summary.json", summary)
        safe_write(temporary / "LIMITS.txt", LIMITS_TEXT.encode("utf-8"))
        for source in inventory.successes:
            raw = source.path.read_bytes()
            actual_hash = sha256_bytes(raw)
            if actual_hash != source.file_sha256:
                raise ValidationError(
                    f"source changed during staging: {source.path} "
                    f"({source.file_sha256} -> {actual_hash})"
                )
            safe_write(temporary / "sources" / source.path.name, raw)
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            resolved_temporary = temporary.resolve()
            if output_root not in resolved_temporary.parents:
                raise ValidationError(
                    f"refusing cleanup of unexpected temporary path {resolved_temporary}"
                )
            shutil.rmtree(temporary)
        raise
    return destination


def emit_validation_report(
    inventory: Inventory, report_dir: Path, policy: ValidationPolicy
) -> Path:
    """Atomically publish a manifest-only report for a validation inventory."""

    corpus = inventory.corpus
    if report_dir.is_symlink():
        raise ValidationError(f"report directory must not be a symlink: {report_dir}")
    destination = report_dir.resolve()
    reject_protected_output(destination, corpus)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise ValidationError(f"report parent must be a real directory: {parent}")
    if destination.exists() or destination.is_symlink():
        raise ValidationError(
            f"validation report already exists; refusing replacement: {destination}"
        )

    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    try:
        verify_input_artifacts_unchanged(corpus)
        safe_write(temporary / "joined_manifest.tsv", manifest_bytes(inventory))
        safe_write(temporary / "references.tsv", references_bytes(inventory))
        summary_record = summary_dict(inventory, policy)
        summary_record["artifact_type"] = "canonical_validation_report"
        summary = json.dumps(
            summary_record,
            indent=2,
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        safe_write(temporary / "validation_summary.json", summary)
        safe_write(temporary / "LIMITS.txt", LIMITS_TEXT.encode("utf-8"))
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            resolved_temporary = temporary.resolve()
            if parent not in resolved_temporary.parents:
                raise ValidationError(
                    f"refusing cleanup of unexpected temporary path {resolved_temporary}"
                )
            shutil.rmtree(temporary)
        raise
    return destination


def print_summary(
    inventory: Inventory, policy: ValidationPolicy = STRICT_POLICY
) -> None:
    summary = summary_dict(inventory, policy)
    print(
        f"snapshot format={summary['format']} "
        f"fingerprint={summary['mapping_fingerprint']}"
    )
    print(
        f"executable sha256={summary['executable_sha256']} "
        f"verification={summary['executable_verification']}"
    )
    print(
        f"index functions={summary['expected_functions']} "
        f"data_symbols={summary['indexed_data_symbols']}"
    )
    print(
        "sources "
        f"success={summary['source_success']} missing={summary['source_missing']} "
        f"stale={summary['source_stale']} invalid={summary['source_invalid']} "
        f"failed_export={summary['source_failed_export']} "
        f"unexpected={summary['unexpected_entries']}"
    )
    print(
        "refs "
        f"function_edges={summary['function_reference_edges']} "
        f"function_occurrences={summary['function_reference_occurrences']} "
        f"data_edges={summary['data_reference_edges']} "
        f"data_occurrences={summary['data_reference_occurrences']}"
    )
    if not inventory.is_complete:
        for diagnostic in partial_diagnostics(inventory):
            print(f"  {diagnostic}")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "canonical_root",
        type=Path,
        help=(
            "directory containing canonical_snapshot.tsv, canonical_function_index.tsv, "
            "canonical_data_index.tsv, and normally canonical_decomp/"
        ),
    )
    parser.add_argument(
        "--decomp-dir",
        type=Path,
        help="override the canonical source directory (relative paths use canonical_root)",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        help="publish a new immutable <output-root>/<fingerprint>/ staging tree",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate and report without writing a staging tree",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        help=(
            "atomically persist joined_manifest.tsv and validation_summary.json; "
            "required whenever a non-success state is explicitly tolerated"
        ),
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "tolerate missing indexed source files during validation only; does not "
            "tolerate stale, invalid, failed, or unexpected inputs"
        ),
    )
    parser.add_argument(
        "--allow-stale",
        action="store_true",
        help="explicitly tolerate stale-fingerprint source files in a saved report",
    )
    parser.add_argument(
        "--allow-invalid",
        action="store_true",
        help="explicitly tolerate malformed/identity-invalid sources in a saved report",
    )
    parser.add_argument(
        "--allow-failed-export",
        action="store_true",
        help="explicitly tolerate indexed failed/timeout exports in a saved report",
    )
    parser.add_argument(
        "--allow-unexpected",
        action="store_true",
        help="explicitly tolerate unindexed directory entries in a saved report",
    )
    parser.add_argument(
        "--executable",
        type=Path,
        help="optionally verify the snapshot executable_sha256 against this binary",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(8, os.cpu_count() or 1),
        help="parallel source-validation workers (default: %(default)s)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be >= 1")
    if args.validate_only and args.output_root is not None:
        parser.error("--validate-only and --output-root are mutually exclusive")
    if not args.validate_only and args.output_root is None:
        parser.error("choose --validate-only or provide --output-root")
    if args.report_dir is not None and not args.validate_only:
        parser.error("--report-dir is available only with --validate-only")
    policy = ValidationPolicy(
        allow_missing=args.allow_partial,
        allow_stale=args.allow_stale,
        allow_invalid=args.allow_invalid,
        allow_failed_export=args.allow_failed_export,
        allow_unexpected=args.allow_unexpected,
    )
    if policy.has_tolerances and not args.validate_only:
        parser.error("validation tolerance flags cannot publish a staging tree")
    if policy.has_tolerances and args.report_dir is None:
        parser.error(
            "validation tolerance flags require --report-dir so the full inventory "
            "is persisted"
        )

    root = args.canonical_root.resolve()
    decomp_dir = args.decomp_dir
    if decomp_dir is not None and not decomp_dir.is_absolute():
        decomp_dir = root / decomp_dir
    try:
        corpus = load_corpus(root, decomp_dir)
        inventory = validate_corpus(
            corpus, jobs=args.jobs, executable_path=args.executable
        )
        print_summary(inventory, policy)
        enforce_completeness(inventory, policy)
        if args.validate_only:
            if args.report_dir is not None:
                report = emit_validation_report(inventory, args.report_dir, policy)
                print(f"report={report}")
            if inventory.is_complete:
                print("validation=complete")
            else:
                print("validation=tolerated_nonpublishable")
        else:
            destination = emit_stage(inventory, args.output_root)
            print(f"staged={destination}")
        return 0
    except ValidationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
