#!/usr/bin/env python3
"""Build a strict, bounded compile island from an immutable canonical stage.

The generator consumes only ``joined_manifest.tsv``, ``references.tsv``, and
the staged ``sources`` directory.  It never consults the legacy global header
set.  Each selected translation unit receives a header containing its exact
direct-callee declarations from ``joined_manifest.tsv`` (with only a trailing
semicolon added).

Outputs are immutable and scoped by both the canonical mapping fingerprint and
a deterministic policy hash.  Only an island that passes the integrated x64
compiler gate is published in the verified namespace::

    <output>/<mapping-fingerprint>/<policy-sha256>/

If a selected source contains unresolved legacy storage, address-valued labels,
unsupported canonical data, unresolved declaration types, or a compiler error,
it is rejected from that namespace and an atomic review package is published as::

    <output>/<mapping-fingerprint>/_quarantine/<policy-sha256>/

Programmatic structural-only publication is kept separately below
``_structural`` and never receives ``COMPILE_VERIFIED``.  The CLI requires
``--compiler`` for a structurally clean publication; use ``--dry-run`` when a
compiler is unavailable.

No implicit declarations, old-style ``()`` compatibility prototypes, blanket
byte arrays, or pointer-sized integer substitutions are synthesized.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence


FORMAT = "canonical-compile-island-v1"
POLICY_REVISION = 3
SUMMARY_FILE = "validation_summary.json"
MANIFEST_FILE = "joined_manifest.tsv"
REFERENCES_FILE = "references.tsv"
SOURCES_DIR = "sources"

AUDITED_ROOTS = (
    "10161140",
    "101627c0",
    "101bd660",
    "101c9910",
    "101d7cb0",
    "102667a0",
    "102773a0",
    "10282130",
    "102d8900",
    "1032ce70",
    "103d76e0",
    "10450190",
    "104a1980",
    "10512450",
    "10679cf0",
    "10682fc0",
)

# Deterministically selected from the bounded policy documented in
# docs/compile_island.md.  Each root passed the integrated x64 MSVC gate with
# exact recovered direct-callee prototypes; none relies on a fallback signature.
DEFAULT_ROOTS = (
    "102df760",
    "10328370",
    "104c76c0",
    "1064d4e0",
    "10698600",
    "10802630",
    "108a8e80",
    "1093c450",
    "109555c0",
    "10981dd0",
    "109871d0",
    "10a132b0",
    "10c93ea0",
    "10f17100",
    "10f4f540",
    "10f537c0",
)

JOINED_HEADER = (
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

REFERENCES_HEADER = (
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

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS_RE = re.compile(r"[0-9a-f]{8,16}\Z")
MSVC_BANNER_RE = re.compile(
    r"^Microsoft \(R\) C/C\+\+ Optimizing Compiler Version "
    r"(?P<version>[0-9]+(?:\.[0-9]+){2,3}) for (?P<target>x64|x86|ARM64)$",
    re.MULTILINE,
)
FUNCTION_RE = re.compile(r"\bdecomp_fn_[0-9a-z_]+\b")
DATA_RE = re.compile(r"\bdecomp_g_[0-9a-z_]+\b")
LEGACY_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:_DAT_|DAT_|PTR_|UNK_)[A-Za-z0-9_$?@]+"
)
LABEL_RE = re.compile(r"\bLAB_[0-9A-Fa-f]+\b")
IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")

COMPILE_FLAGS = ("/nologo", "/TC", "/Zs", "/W3", "/we4013")
FORCED_SYSTEM_HEADERS = (
    "windows.h",
    "stdbool.h",
    "stdint.h",
    "stddef.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
    "time.h",
    "math.h",
    "errno.h",
)
POINTER_WIDTH_GATE = (
    "#pragma once\n"
    "/* A compile-verified island is host-x64 only. */\n"
    "typedef char compile_island_requires_64_bit_pointers"
    "[(sizeof(void *) == 8) ? 1 : -1];\n"
).encode("ascii")

# This is a storage-width registry, not a claim about host pointer semantics.
# Guest pointer cells remain explicit four-byte integers.  Any source that needs
# a host pointer must be deliberately ported; the generator never widens it.
FIXED_DATA_REGISTRY: Mapping[tuple[str, int, int], tuple[str, str]] = {
    ("/undefined1", 1, 1): ("uint8_t", "guest scalar, 8 bits"),
    ("/undefined2", 2, 2): ("uint16_t", "guest scalar, 16 bits"),
    ("/undefined4", 4, 4): ("uint32_t", "guest scalar, 32 bits"),
    ("/undefined8", 8, 8): ("uint64_t", "guest scalar, 64 bits"),
    ("/pointer", 4, 4): ("uint32_t", "guest pointer storage, 32 bits"),
    ("/void *32", 4, 4): ("uint32_t", "guest pointer storage, 32 bits"),
}

# Types supplied by the narrow base include set used by the compile audit.
# This list is intentionally small.  Unknown recovered types enter quarantine;
# they are never converted to opaque byte arrays or invented scalar aliases.
KNOWN_DECLARATION_TYPES = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "_Bool",
        "bool",
        "size_t",
        "ptrdiff_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "undefined1",
        "undefined2",
        "undefined3",
        "undefined4",
        "undefined5",
        "undefined6",
        "undefined7",
        "undefined8",
        "byte",
        "ubyte",
        "ushort",
        "uint",
        "longlong",
        "ulonglong",
        "float10",
        "HMODULE",
        "HANDLE",
        "HWND",
        "HRESULT",
        "DWORD",
        "WORD",
        "BYTE",
        "BOOL",
        "LPVOID",
        "LPCVOID",
        "LPSTR",
        "LPCSTR",
        "LPWSTR",
        "LPCWSTR",
        "GUID",
    }
)

DECLARATION_WORDS = frozenset(
    {
        "const",
        "volatile",
        "restrict",
        "static",
        "extern",
        "register",
        "inline",
        "struct",
        "union",
        "enum",
        "__cdecl",
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__vectorcall",
        "__declspec",
    }
)

NON_TYPE_STATEMENT_WORDS = frozenset(
    {
        "break",
        "case",
        "continue",
        "default",
        "do",
        "else",
        "for",
        "goto",
        "if",
        "return",
        "switch",
        "while",
    }
)


class IslandError(RuntimeError):
    """The staged input or publication contract is invalid."""


@dataclass(frozen=True)
class Finding:
    entry: str
    category: str
    symbol: str
    detail: str


@dataclass(frozen=True)
class InventoryItem:
    entry: str
    source_file: str
    category: str
    symbol: str
    occurrences: int
    lines: tuple[int, ...]


@dataclass
class TranslationUnit:
    entry: str
    canonical_name: str
    source_file: str
    source_bytes: bytes
    source_sha256: str
    declaration: str
    function_declarations: list[tuple[str, str]] = field(default_factory=list)
    data_declarations: list[tuple[str, str]] = field(default_factory=list)
    inventory: list[InventoryItem] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    deps_bytes: bytes = b""


@dataclass(frozen=True)
class CompileConfig:
    compiler_path: Path
    compiler_sha256: str
    compiler_version: str
    compiler_target: str
    compiler_version_text: str
    compiler_version_sha256: str
    base_compat_path: Path
    base_compat_sha256: str


@dataclass(frozen=True)
class CompileResult:
    entry: str
    response_file: str
    exit_code: int
    output: str

    @property
    def passed(self) -> bool:
        return self.exit_code == 0


@dataclass
class IslandPlan:
    stage: Path
    fingerprint: str
    roots: tuple[str, ...]
    policy: dict[str, object]
    policy_sha256: str
    manifest_sha256: str
    references_sha256: str
    units: list[TranslationUnit]
    findings: list[Finding]
    compile_config: CompileConfig | None = None

    @property
    def structurally_clean(self) -> bool:
        return not self.findings


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_msvc_banner(version_text: str) -> tuple[str, str]:
    match = MSVC_BANNER_RE.search(version_text)
    if match is None or "Compiler Passes:" not in version_text:
        raise IslandError("compiler /Bv output is not an MSVC compiler inventory")
    return match.group("version"), match.group("target")


def resolve_compile_config(compiler: str | Path, base_compat: Path) -> CompileConfig:
    requested = str(compiler)
    located = shutil.which(requested)
    compiler_path = Path(located if located is not None else requested).resolve()
    base_path = base_compat.resolve()
    if not compiler_path.is_file():
        raise IslandError(f"compiler is not an executable file: {compiler_path}")
    if not base_path.is_file():
        raise IslandError(f"base compatibility header is not a file: {base_path}")
    try:
        completed = subprocess.run(
            [str(compiler_path), "/Bv"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IslandError(f"cannot query compiler {compiler_path}: {exc}") from exc
    version_text = completed.stdout.replace("\r\n", "\n").replace("\r", "\n")
    if not version_text.strip():
        raise IslandError(f"compiler version query returned no output: {compiler_path}")
    compiler_version, compiler_target = parse_msvc_banner(version_text)
    # /Bv reports every compiler-pass path.  Normalize the shared binary
    # directory so the immutable artifact remains relocatable while the binary
    # content hash still pins the compiler itself.
    version_text = re.sub(
        re.escape(str(compiler_path.parent)),
        "<COMPILER_DIR>",
        version_text,
        flags=re.IGNORECASE,
    )
    return CompileConfig(
        compiler_path=compiler_path,
        compiler_sha256=sha256_file(compiler_path),
        compiler_version=compiler_version,
        compiler_target=compiler_target,
        compiler_version_text=version_text,
        compiler_version_sha256=sha256_bytes(version_text.encode("utf-8")),
        base_compat_path=base_path,
        base_compat_sha256=sha256_file(base_path),
    )


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def normalize_address(raw: str) -> str:
    value = raw.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    value = value.lstrip("0") or "0"
    if len(value) < 8:
        value = value.zfill(8)
    if not ADDRESS_RE.fullmatch(value):
        raise IslandError(f"invalid canonical address: {raw!r}")
    return value


def normalize_roots(values: Iterable[str]) -> tuple[str, ...]:
    roots = sorted({normalize_address(value) for value in values})
    if not roots:
        raise IslandError("at least one root address is required")
    return tuple(roots)


def read_address_file(path: Path) -> list[str]:
    values: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        fields = [part for part in re.split(r"[\s,]+", value) if part]
        try:
            values.extend(normalize_address(field) for field in fields)
        except IslandError as exc:
            raise IslandError(f"{path}:{number}: {exc}") from exc
    return values


def read_tsv(path: Path, expected_header: Sequence[str]) -> list[dict[str, str]]:
    try:
        stream = path.open("r", encoding="utf-8", newline="")
    except OSError as exc:
        raise IslandError(f"cannot open {path}: {exc}") from exc
    with stream:
        reader = csv.DictReader(stream, delimiter="\t")
        actual = tuple(reader.fieldnames or ())
        if actual != tuple(expected_header):
            raise IslandError(
                f"{path}: schema mismatch; expected {tuple(expected_header)!r}, got {actual!r}"
            )
        rows: list[dict[str, str]] = []
        for number, row in enumerate(reader, 2):
            if None in row:
                raise IslandError(f"{path}:{number}: excess TSV fields")
            if any(value is None for value in row.values()):
                raise IslandError(f"{path}:{number}: missing TSV fields")
            rows.append({key: value or "" for key, value in row.items()})
    return rows


def require_decimal(value: str, context: str, *, minimum: int = 0) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise IslandError(f"{context}: expected a decimal integer, got {value!r}")
    result = int(value)
    if result < minimum:
        raise IslandError(f"{context}: expected a value >= {minimum}, got {result}")
    return result


def mask_comments_and_literals(text: str) -> str:
    """Replace C comments/string/character contents while preserving positions."""

    chars = list(text)
    state = "code"
    index = 0
    while index < len(chars):
        ch = chars[index]
        nxt = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if ch == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if ch == '"':
                chars[index] = " "
                state = "string"
            elif ch == "'":
                chars[index] = " "
                state = "character"
        elif state == "line_comment":
            if ch in "\r\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                state = "code"
                index += 2
                continue
            if ch not in "\r\n":
                chars[index] = " "
        else:
            if ch == "\\":
                chars[index] = " "
                if index + 1 < len(chars):
                    if chars[index + 1] not in "\r\n":
                        chars[index + 1] = " "
                    index += 2
                    continue
            elif (state == "string" and ch == '"') or (
                state == "character" and ch == "'"
            ):
                chars[index] = " "
                state = "code"
            elif ch not in "\r\n":
                chars[index] = " "
        index += 1
    if state in {"block_comment", "string", "character"}:
        raise IslandError(f"unterminated C lexical construct ({state})")
    return "".join(chars)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def split_parameters(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, ch in enumerate(text):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                raise IslandError(f"unbalanced parameter declaration: {text!r}")
        elif ch == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    if depth != 0:
        raise IslandError(f"unbalanced parameter declaration: {text!r}")
    parts.append(text[start:])
    return parts


def declaration_type_findings(
    entry: str, canonical_name: str, declaration: str
) -> list[Finding]:
    findings: list[Finding] = []
    if not declaration or "\n" in declaration or "\r" in declaration:
        return [
            Finding(entry, "invalid_declaration", canonical_name, "missing or multiline declaration")
        ]
    if ";" in declaration:
        findings.append(
            Finding(
                entry,
                "invalid_declaration",
                canonical_name,
                "joined declaration already contains a semicolon",
            )
        )
    match = re.search(rf"\b{re.escape(canonical_name)}\b", declaration)
    if match is None:
        return findings + [
            Finding(
                entry,
                "invalid_declaration",
                canonical_name,
                "canonical identifier is absent from declaration",
            )
        ]
    open_index = declaration.find("(", match.end())
    if open_index < 0:
        return findings + [
            Finding(entry, "invalid_declaration", canonical_name, "parameter list is absent")
        ]
    depth = 0
    close_index = -1
    for index in range(open_index, len(declaration)):
        ch = declaration[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_index = index
                break
    if close_index < 0 or declaration[close_index + 1 :].strip():
        return findings + [
            Finding(entry, "invalid_declaration", canonical_name, "unsupported declarator suffix")
        ]

    prefix_tokens = IDENT_RE.findall(declaration[: match.start()])
    for token in prefix_tokens:
        if token not in KNOWN_DECLARATION_TYPES and token not in DECLARATION_WORDS:
            findings.append(
                Finding(entry, "unresolved_type", token, f"return type of {canonical_name}")
            )

    parameters = declaration[open_index + 1 : close_index]
    if not parameters.strip():
        findings.append(
            Finding(
                entry,
                "old_style_declaration",
                canonical_name,
                "empty () parameter list is ABI-unverified",
            )
        )
        return findings
    for parameter in split_parameters(parameters):
        stripped = parameter.strip()
        if not stripped or stripped == "...":
            continue
        tokens = list(IDENT_RE.finditer(stripped))
        if not tokens:
            findings.append(
                Finding(entry, "invalid_declaration", canonical_name, f"bad parameter {stripped!r}")
            )
            continue

        # A final non-keyword identifier is the parameter name when the segment
        # already contains a type token (or another identifier) before it.
        ignored_name: str | None = None
        last = tokens[-1]
        before_last = stripped[: last.start()]
        preceding = [item.group(0) for item in tokens[:-1]]
        preceding_has_type = any(
            item in KNOWN_DECLARATION_TYPES
            or item in {"struct", "union", "enum"}
            or item not in DECLARATION_WORDS
            for item in preceding
        )
        if preceding_has_type and not before_last.rstrip().endswith(("struct", "union", "enum")):
            ignored_name = last.group(0)

        for token_match in tokens:
            token = token_match.group(0)
            if token == ignored_name and token_match is last:
                continue
            if token in KNOWN_DECLARATION_TYPES or token in DECLARATION_WORDS:
                continue
            findings.append(
                Finding(
                    entry,
                    "unresolved_type",
                    token,
                    f"parameter type of {canonical_name}",
                )
            )
    return findings


def body_type_findings(entry: str, masked: str) -> list[Finding]:
    """Conservatively detect unresolved local, cast, and sizeof type tokens."""

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    local_re = re.compile(
        r"(?m)^[ \t]*(?:(?:const|volatile)\s+)*(?P<type>[A-Za-z_]\w*)"
        r"(?:\s+|\s*\*+\s*)(?P<name>[A-Za-z_]\w*)"
        r"\s*(?:\[[^\]\r\n]*\])?\s*(?:;|=)"
    )
    for match in local_re.finditer(masked):
        token = match.group("type")
        if (
            token in KNOWN_DECLARATION_TYPES
            or token in DECLARATION_WORDS
            or token in NON_TYPE_STATEMENT_WORDS
        ):
            continue
        key = ("local declaration", token)
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    entry,
                    "unresolved_type",
                    token,
                    f"local declaration at line {line_number(masked, match.start())}",
                )
            )

    cast_re = re.compile(
        r"\(\s*(?:(?:const|volatile)\s+)*(?:(?:struct|union|enum)\s+)?"
        r"(?P<type>[A-Za-z_]\w*)\s*(?P<stars>\*+)\s*\)"
    )
    for match in cast_re.finditer(masked):
        token = match.group("type")
        if token in KNOWN_DECLARATION_TYPES:
            continue
        key = ("cast", token)
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    entry,
                    "unresolved_type",
                    token,
                    f"pointer cast at line {line_number(masked, match.start())}",
                )
            )

    sizeof_re = re.compile(
        r"\bsizeof\s*\(\s*(?:(?:struct|union|enum)\s+)?(?P<type>[A-Za-z_]\w*)\s*\)"
    )
    for match in sizeof_re.finditer(masked):
        token = match.group("type")
        if token in KNOWN_DECLARATION_TYPES:
            continue
        key = ("sizeof", token)
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    entry,
                    "unresolved_type",
                    token,
                    f"sizeof requires a recovered layout at line {line_number(masked, match.start())}",
                )
            )
    return findings


def legacy_inventory(entry: str, source_file: str, masked: str) -> list[InventoryItem]:
    grouped: dict[tuple[str, str], list[int]] = defaultdict(list)
    for match in LEGACY_RE.finditer(masked):
        symbol = match.group(0)
        if symbol.startswith("_DAT_"):
            category = "legacy_data_alias"
        elif symbol.startswith("DAT_"):
            category = "legacy_data"
        elif symbol.startswith("PTR_"):
            category = "legacy_pointer"
        else:
            category = "legacy_unknown"
        grouped[(category, symbol)].append(line_number(masked, match.start()))

    for match in LABEL_RE.finditer(masked):
        line_start = masked.rfind("\n", 0, match.start()) + 1
        prefix = masked[line_start : match.start()]
        suffix = masked[match.end() :]
        if re.fullmatch(r"[ \t]*", prefix) and re.match(r"[ \t]*:", suffix):
            continue
        if re.search(r"\bgoto\s*$", prefix):
            continue
        grouped[("address_valued_label", match.group(0))].append(
            line_number(masked, match.start())
        )

    return [
        InventoryItem(
            entry=entry,
            source_file=source_file,
            category=category,
            symbol=symbol,
            occurrences=len(lines),
            lines=tuple(sorted(lines)),
        )
        for (category, symbol), lines in sorted(grouped.items())
    ]


def build_deps_header(unit: TranslationUnit, fingerprint: str, policy_sha256: str) -> bytes:
    lines = [
        "#pragma once",
        "/* Generated by canonical-compile-island-v1; do not edit. */",
        f"/* Mapping fingerprint: {fingerprint} */",
        f"/* Policy SHA-256: {policy_sha256} */",
        f"/* Translation unit: {unit.canonical_name} */",
        "",
    ]
    if unit.function_declarations:
        lines.append("/* Exact direct-callee declarations from joined_manifest.tsv. */")
        for _, declaration in sorted(unit.function_declarations):
            lines.append(declaration + ";")
        lines.append("")
    if unit.data_declarations:
        lines.append("/* Fixed-width guest storage declarations. */")
        for _, declaration in sorted(unit.data_declarations):
            lines.append(declaration)
        lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def load_plan(
    stage: Path,
    roots: Sequence[str],
    compile_config: CompileConfig | None = None,
) -> IslandPlan:
    stage = stage.resolve()
    summary_path = stage / SUMMARY_FILE
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IslandError(f"cannot read {summary_path}: {exc}") from exc
    fingerprint = summary.get("mapping_fingerprint")
    if not isinstance(fingerprint, str) or not SHA256_RE.fullmatch(fingerprint):
        raise IslandError(f"{summary_path}: invalid mapping_fingerprint")
    if summary.get("complete") is not True:
        raise IslandError(f"{summary_path}: canonical stage is not complete")
    if summary.get("source_success") != summary.get("expected_functions"):
        raise IslandError(f"{summary_path}: success count does not match expected functions")

    manifest_path = stage / MANIFEST_FILE
    references_path = stage / REFERENCES_FILE
    sources_dir = stage / SOURCES_DIR
    if not sources_dir.is_dir():
        raise IslandError(f"missing staged sources directory: {sources_dir}")
    manifest_rows = read_tsv(manifest_path, JOINED_HEADER)
    reference_rows = read_tsv(references_path, REFERENCES_HEADER)
    manifest_sha256 = sha256_file(manifest_path)
    references_sha256 = sha256_file(references_path)

    by_address: dict[str, dict[str, str]] = {}
    by_name: dict[str, dict[str, str]] = {}
    for number, row in enumerate(manifest_rows, 2):
        if row["mapping_fingerprint"] != fingerprint:
            raise IslandError(f"{manifest_path}:{number}: mapping fingerprint mismatch")
        address = normalize_address(row["address"])
        name = row["canonical_name"]
        if address in by_address:
            raise IslandError(f"{manifest_path}:{number}: duplicate address {address}")
        if name in by_name:
            raise IslandError(f"{manifest_path}:{number}: duplicate canonical name {name}")
        by_address[address] = row
        by_name[name] = row

    refs_by_source: dict[str, list[dict[str, str]]] = defaultdict(list)
    for number, row in enumerate(reference_rows, 2):
        source_entry = normalize_address(row["source_entry"])
        occurrences = require_decimal(
            row["occurrences"], f"{references_path}:{number}:occurrences", minimum=1
        )
        row["occurrences"] = str(occurrences)
        refs_by_source[source_entry].append(row)

    normalized_roots = normalize_roots(roots)
    policy: dict[str, object] = {
        "format": FORMAT,
        "policy_revision": POLICY_REVISION,
        "generator_sha256": sha256_file(Path(__file__).resolve()),
        "roots": list(normalized_roots),
        "inputs": {
            "joined_manifest_sha256": manifest_sha256,
            "references_sha256": references_sha256,
        },
        "rules": {
            "callee_declarations": "joined_manifest exact text plus semicolon",
            "canonical_reference_contract": "comment/string-aware lexical equality",
            "legacy_storage": "quarantine",
            "address_valued_labels": "quarantine",
            "unknown_declaration_types": "quarantine",
            "old_style_empty_parameter_lists": "quarantine",
            "implicit_declarations": "forbidden",
            "pointer_sized_integer_fallbacks": "forbidden",
            "compiler_gate": {
                "arguments": list(COMPILE_FLAGS),
                "forced_system_headers": list(FORCED_SYSTEM_HEADERS),
                "base_compat_sha256": (
                    compile_config.base_compat_sha256 if compile_config is not None else None
                ),
                "compiler_sha256": (
                    compile_config.compiler_sha256 if compile_config is not None else None
                ),
                "compiler_family": "msvc" if compile_config is not None else None,
                "compiler_version": (
                    compile_config.compiler_version if compile_config is not None else None
                ),
                "compiler_target": (
                    compile_config.compiler_target if compile_config is not None else None
                ),
                "compiler_version_sha256": (
                    compile_config.compiler_version_sha256
                    if compile_config is not None
                    else None
                ),
                "target_pointer_bits": 64,
                "pointer_width_gate_sha256": sha256_bytes(POINTER_WIDTH_GATE),
            },
            "data_registry": [
                {
                    "data_type_path": key[0],
                    "data_type_length": key[1],
                    "code_unit_length": key[2],
                    "c_storage_type": value[0],
                    "meaning": value[1],
                }
                for key, value in sorted(FIXED_DATA_REGISTRY.items())
            ],
        },
    }
    policy_sha256 = sha256_bytes(canonical_json_bytes(policy))

    units: list[TranslationUnit] = []
    all_findings: list[Finding] = []
    for entry in normalized_roots:
        record = by_address.get(entry)
        if record is None or record["record_type"] != "function":
            raise IslandError(f"selected root {entry} is not an indexed function")
        expected_name = f"decomp_fn_{entry}"
        if record["canonical_name"] != expected_name:
            raise IslandError(
                f"selected root {entry} has unexpected canonical name {record['canonical_name']!r}"
            )
        if record["source_status"] != "success" or record["parse_status"] != "parsed":
            raise IslandError(
                f"selected root {entry} is not a successful parsed source "
                f"({record['source_status']}/{record['parse_status']})"
            )
        source_file = record["source_file"]
        if source_file != f"{expected_name}.c" or Path(source_file).name != source_file:
            raise IslandError(f"selected root {entry} has unsafe source path {source_file!r}")
        expected_sha = record["file_sha256"]
        if not SHA256_RE.fullmatch(expected_sha):
            raise IslandError(f"selected root {entry} has invalid source SHA-256")
        source_path = sources_dir / source_file
        try:
            source_bytes = source_path.read_bytes()
        except OSError as exc:
            raise IslandError(f"cannot read {source_path}: {exc}") from exc
        actual_sha = sha256_bytes(source_bytes)
        if actual_sha != expected_sha:
            raise IslandError(
                f"selected root {entry} source hash mismatch: expected {expected_sha}, got {actual_sha}"
            )
        try:
            source_text = source_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IslandError(f"{source_path}: source is not UTF-8: {exc}") from exc
        try:
            masked = mask_comments_and_literals(source_text)
        except IslandError as exc:
            raise IslandError(f"{source_path}: {exc}") from exc

        unit = TranslationUnit(
            entry=entry,
            canonical_name=expected_name,
            source_file=source_file,
            source_bytes=source_bytes,
            source_sha256=actual_sha,
            declaration=record["declaration"],
        )
        unit.findings.extend(declaration_type_findings(entry, expected_name, record["declaration"]))
        unit.findings.extend(body_type_findings(entry, masked))
        unit.inventory.extend(legacy_inventory(entry, source_file, masked))
        for item in unit.inventory:
            unit.findings.append(
                Finding(
                    entry,
                    item.category,
                    item.symbol,
                    f"{item.occurrences} occurrence(s) at lines "
                    + ",".join(str(value) for value in item.lines),
                )
            )

        function_counts = Counter(FUNCTION_RE.findall(masked))
        if function_counts[expected_name] < 1:
            raise IslandError(f"{source_path}: canonical definition identifier is absent")
        function_counts[expected_name] -= 1
        if function_counts[expected_name] == 0:
            del function_counts[expected_name]
        data_counts = Counter(DATA_RE.findall(masked))

        expected_function_counts: Counter[str] = Counter()
        expected_data_counts: Counter[str] = Counter()
        seen_reference_targets: set[tuple[str, str]] = set()
        for row in refs_by_source.get(entry, []):
            if row["source_canonical_name"] != expected_name or row["source_status"] != "success":
                raise IslandError(f"reference source contract mismatch for {entry}")
            kind = row["target_kind"]
            name = row["target_canonical_name"]
            pair = (kind, name)
            if pair in seen_reference_targets:
                raise IslandError(f"duplicate reference row for {entry} -> {kind}:{name}")
            seen_reference_targets.add(pair)
            occurrences = int(row["occurrences"])
            if kind == "function":
                expected_function_counts[name] = occurrences
            elif kind == "data":
                expected_data_counts[name] = occurrences
            else:
                raise IslandError(f"unknown reference target kind {kind!r} for {entry}")

            target = by_name.get(name)
            if row["target_indexed"] != "yes" or target is None:
                unit.findings.append(
                    Finding(entry, "unindexed_canonical_target", name, f"{kind} target is not indexed")
                )
                continue
            if normalize_address(row["target_address"]) != normalize_address(target["address"]):
                raise IslandError(f"reference target address mismatch for {entry} -> {name}")
            if target["record_type"] != kind:
                raise IslandError(f"reference target kind mismatch for {entry} -> {name}")
            if kind == "function":
                if row["target_source_status"] != "success":
                    unit.findings.append(
                        Finding(entry, "unavailable_callee", name, "callee source is not successful")
                    )
                    continue
                declaration = target["declaration"]
                unit.function_declarations.append((name, declaration))
                unit.findings.extend(declaration_type_findings(entry, name, declaration))
            else:
                try:
                    data_length = require_decimal(
                        target["data_type_length"], f"data {name}:data_type_length", minimum=1
                    )
                    code_length = require_decimal(
                        target["code_unit_length"], f"data {name}:code_unit_length", minimum=1
                    )
                except IslandError as exc:
                    unit.findings.append(Finding(entry, "unresolved_data_type", name, str(exc)))
                    continue
                key = (target["data_type_path"], data_length, code_length)
                registry = FIXED_DATA_REGISTRY.get(key)
                if registry is None:
                    unit.findings.append(
                        Finding(
                            entry,
                            "unresolved_data_type",
                            name,
                            f"no fixed-width registry entry for {key!r}",
                        )
                    )
                    continue
                c_type, meaning = registry
                declaration = f"extern {c_type} {name}; /* {meaning} */"
                unit.data_declarations.append((name, declaration))

        if function_counts != expected_function_counts:
            unit.findings.append(
                Finding(
                    entry,
                    "function_reference_contract",
                    expected_name,
                    f"source={dict(sorted(function_counts.items()))!r}; "
                    f"references.tsv={dict(sorted(expected_function_counts.items()))!r}",
                )
            )
        if data_counts != expected_data_counts:
            unit.findings.append(
                Finding(
                    entry,
                    "data_reference_contract",
                    expected_name,
                    f"source={dict(sorted(data_counts.items()))!r}; "
                    f"references.tsv={dict(sorted(expected_data_counts.items()))!r}",
                )
            )

        unit.function_declarations.sort(key=lambda item: item[0])
        unit.data_declarations.sort(key=lambda item: item[0])
        unit.findings.sort(key=lambda item: (item.category, item.symbol, item.detail))
        units.append(unit)
        all_findings.extend(unit.findings)

    all_findings.sort(key=lambda item: (item.entry, item.category, item.symbol, item.detail))
    plan = IslandPlan(
        stage=stage,
        fingerprint=fingerprint,
        roots=normalized_roots,
        policy=policy,
        policy_sha256=policy_sha256,
        manifest_sha256=manifest_sha256,
        references_sha256=references_sha256,
        units=units,
        findings=all_findings,
        compile_config=compile_config,
    )
    for unit in units:
        unit.deps_bytes = build_deps_header(unit, fingerprint, policy_sha256)
    return plan


def write_tsv(path: Path, header: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda p: p.as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def response_file_bytes(unit: TranslationUnit, config: CompileConfig) -> bytes:
    arguments = list(COMPILE_FLAGS)
    arguments.extend(f"/FI{header}" for header in FORCED_SYSTEM_HEADERS)
    arguments.append('/FI"..\\include\\pointer_width_gate.h"')
    arguments.append('/FI"..\\include\\base_compat.h"')
    # MSVC resolves a forced include relative to the primary source directory,
    # not the response file or process working directory.
    arguments.append(f'/FI"..\\include\\{unit.canonical_name}.deps.h"')
    arguments.append(f'"sources\\{unit.source_file}"')
    return ("\n".join(arguments) + "\n").encode("utf-8")


def normalize_compile_output(output: str, island_root: Path) -> str:
    """Remove the random atomic staging prefix from compiler diagnostics."""

    normalized = output.replace("\r\n", "\n").replace("\r", "\n")
    resolved = island_root.resolve()
    prefixes = {str(resolved), resolved.as_posix()}
    for prefix in sorted(prefixes, key=len, reverse=True):
        normalized = re.sub(
            re.escape(prefix), "<ISLAND_ROOT>", normalized, flags=re.IGNORECASE
        )
    return normalized


def run_compile_gate(root: Path, plan: IslandPlan) -> list[CompileResult]:
    config = plan.compile_config
    if config is None:
        raise IslandError("compiler gate requested without a pinned compiler configuration")
    compile_dir = root / "compile"
    logs_dir = compile_dir / "logs"
    logs_dir.mkdir(parents=True)
    (compile_dir / "compiler_version.txt").write_text(
        config.compiler_version_text, encoding="utf-8", newline="\n"
    )

    command_rows: list[tuple[object, ...]] = []
    results: list[CompileResult] = []
    for unit in plan.units:
        response_name = f"{unit.canonical_name}.rsp"
        response_relative = f"compile/{response_name}"
        response_path = compile_dir / response_name
        response = response_file_bytes(unit, config)
        response_path.write_bytes(response)
        command_rows.append(
            (
                unit.entry,
                unit.canonical_name,
                "cl.exe",
                response_relative,
                sha256_bytes(response),
                f'cl.exe @"{response_relative}"',
            )
        )

    write_tsv(
        compile_dir / "compile_commands.tsv",
        (
            "entry",
            "canonical_name",
            "compiler",
            "response_file",
            "response_sha256",
            "command_from_island_root",
        ),
        command_rows,
    )

    for unit in plan.units:
        response_relative = f"compile/{unit.canonical_name}.rsp"
        try:
            completed = subprocess.run(
                [str(config.compiler_path), f"@{response_relative}"],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                text=True,
                errors="replace",
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IslandError(f"compiler invocation failed for {unit.entry}: {exc}") from exc
        output = normalize_compile_output(completed.stdout, root)
        (logs_dir / f"{unit.canonical_name}.log").write_text(
            output, encoding="utf-8", newline="\n"
        )
        results.append(
            CompileResult(
                entry=unit.entry,
                response_file=response_relative,
                exit_code=completed.returncode,
                output=output,
            )
        )

    write_tsv(
        compile_dir / "compile_results.tsv",
        ("entry", "response_file", "exit_code", "passed", "output_sha256", "log_file"),
        (
            (
                result.entry,
                result.response_file,
                result.exit_code,
                "yes" if result.passed else "no",
                sha256_bytes(result.output.encode("utf-8")),
                f"compile/logs/decomp_fn_{result.entry}.log",
            )
            for result in results
        ),
    )
    return results


def publish_plan(plan: IslandPlan, output_root: Path) -> Path:
    output_root = output_root.resolve()
    if is_within(output_root, plan.stage) or is_within(plan.stage, output_root):
        raise IslandError("output root must be disjoint from the immutable canonical stage")

    fingerprint_dir = output_root / plan.fingerprint
    fingerprint_dir.mkdir(parents=True, exist_ok=True)
    temp_path = Path(
        tempfile.mkdtemp(prefix=f".{plan.policy_sha256}.tmp-", dir=fingerprint_dir)
    )
    try:
        (temp_path / "sources").mkdir()
        (temp_path / "include").mkdir()
        if plan.compile_config is not None:
            base_bytes = plan.compile_config.base_compat_path.read_bytes()
            if sha256_bytes(base_bytes) != plan.compile_config.base_compat_sha256:
                raise IslandError("base compatibility header changed after policy construction")
            (temp_path / "include" / "base_compat.h").write_bytes(base_bytes)
            (temp_path / "include" / "pointer_width_gate.h").write_bytes(
                POINTER_WIDTH_GATE
            )
        for unit in plan.units:
            (temp_path / "sources" / unit.source_file).write_bytes(unit.source_bytes)
            (temp_path / "include" / f"{unit.canonical_name}.deps.h").write_bytes(
                unit.deps_bytes
            )

        write_tsv(
            temp_path / "island_manifest.tsv",
            (
                "entry",
                "canonical_name",
                "source_file",
                "source_sha256",
                "deps_file",
                "deps_sha256",
                "direct_callees",
                "canonical_data",
                "inventory_items",
                "structural_findings",
            ),
            (
                (
                    unit.entry,
                    unit.canonical_name,
                    unit.source_file,
                    unit.source_sha256,
                    f"include/{unit.canonical_name}.deps.h",
                    sha256_bytes(unit.deps_bytes),
                    len(unit.function_declarations),
                    len(unit.data_declarations),
                    len(unit.inventory),
                    len(unit.findings),
                )
                for unit in plan.units
            ),
        )
        write_tsv(
            temp_path / "legacy_inventory.tsv",
            ("entry", "source_file", "category", "symbol", "occurrences", "lines"),
            (
                (
                    item.entry,
                    item.source_file,
                    item.category,
                    item.symbol,
                    item.occurrences,
                    ",".join(str(value) for value in item.lines),
                )
                for unit in plan.units
                for item in unit.inventory
            ),
        )
        (temp_path / "policy.json").write_bytes(canonical_json_bytes(plan.policy))

        compile_results: list[CompileResult] = []
        effective_findings = list(plan.findings)
        if plan.structurally_clean and plan.compile_config is not None:
            compile_results = run_compile_gate(temp_path, plan)
            for result in compile_results:
                if not result.passed:
                    effective_findings.append(
                        Finding(
                            result.entry,
                            "compiler_gate",
                            f"decomp_fn_{result.entry}",
                            f"MSVC returned exit code {result.exit_code}; see "
                            f"compile/logs/decomp_fn_{result.entry}.log",
                        )
                    )
            if plan.compile_config.compiler_target != "x64":
                effective_findings.append(
                    Finding(
                        plan.roots[0],
                        "compiler_target",
                        plan.compile_config.compiler_target,
                        "COMPILE_VERIFIED requires the MSVC x64 target",
                    )
                )

        effective_findings.sort(
            key=lambda item: (item.entry, item.category, item.symbol, item.detail)
        )
        compile_verified = (
            plan.structurally_clean
            and plan.compile_config is not None
            and plan.compile_config.compiler_target == "x64"
            and len(compile_results) == len(plan.units)
            and bool(plan.units)
            and all(item.passed for item in compile_results)
        )
        if effective_findings:
            status = "quarantined"
            final_parent = fingerprint_dir / "_quarantine"
            marker_name = "QUARANTINED"
        elif compile_verified:
            status = "compile_verified"
            final_parent = fingerprint_dir
            marker_name = "COMPILE_VERIFIED"
        else:
            status = "structurally_validated"
            final_parent = fingerprint_dir / "_structural"
            marker_name = "STRUCTURALLY_VALIDATED"

        write_tsv(
            temp_path / "quarantine.tsv",
            ("entry", "category", "symbol", "detail"),
            ((item.entry, item.category, item.symbol, item.detail) for item in effective_findings),
        )
        summary = {
            "format": FORMAT,
            "status": status,
            "mapping_fingerprint": plan.fingerprint,
            "policy_sha256": plan.policy_sha256,
            "roots": list(plan.roots),
            "translation_units": len(plan.units),
            "direct_callee_declarations": sum(
                len(unit.function_declarations) for unit in plan.units
            ),
            "canonical_data_declarations": sum(
                len(unit.data_declarations) for unit in plan.units
            ),
            "legacy_inventory_items": sum(len(unit.inventory) for unit in plan.units),
            "structural_findings": len(plan.findings),
            "compiler_gate": {
                "configured": plan.compile_config is not None,
                "translation_units_run": len(compile_results),
                "passed": sum(result.passed for result in compile_results),
                "failed": sum(not result.passed for result in compile_results),
                "verified": compile_verified,
            },
            "quarantine_findings": len(effective_findings),
            "joined_manifest_sha256": plan.manifest_sha256,
            "references_sha256": plan.references_sha256,
        }
        (temp_path / "island_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (temp_path / marker_name).write_text(
            status + "\n", encoding="ascii", newline="\n"
        )

        final_parent.mkdir(parents=True, exist_ok=True)
        final_path = final_parent / plan.policy_sha256
        if final_path.exists():
            if not final_path.is_dir():
                raise IslandError(f"immutable output collision at {final_path}")
            if tree_digest(final_path) != tree_digest(temp_path):
                raise IslandError(f"immutable output differs at {final_path}")
            shutil.rmtree(temp_path)
            return final_path
        os.rename(temp_path, final_path)
        return final_path
    except Exception:
        if temp_path.exists() and is_within(temp_path.resolve(), fingerprint_dir.resolve()):
            shutil.rmtree(temp_path)
        raise


def describe_plan(plan: IslandPlan) -> str:
    categories = Counter(item.category for item in plan.findings)
    values = [
        f"structural_status={'clean' if plan.structurally_clean else 'quarantined'}",
        f"fingerprint={plan.fingerprint}",
        f"policy={plan.policy_sha256}",
        f"roots={len(plan.roots)}",
        f"callees={sum(len(unit.function_declarations) for unit in plan.units)}",
        f"data={sum(len(unit.data_declarations) for unit in plan.units)}",
        f"findings={len(plan.findings)}",
    ]
    if categories:
        values.append(
            "categories=" + ",".join(f"{key}:{categories[key]}" for key in sorted(categories))
        )
    return " ".join(values)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path, help="immutable canonical fingerprint directory")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("out/canonical-compile-islands"),
        help="publication root (default: out/canonical-compile-islands)",
    )
    parser.add_argument(
        "--address",
        action="append",
        default=[],
        help="root address; repeat for multiple roots (defaults to the verified 16-root island)",
    )
    parser.add_argument(
        "--addresses-file",
        action="append",
        type=Path,
        default=[],
        help="UTF-8 file containing whitespace/comma-separated root addresses",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and report without publishing any output",
    )
    parser.add_argument(
        "--compiler",
        help="MSVC cl.exe path/name; required for a COMPILE_VERIFIED publication",
    )
    parser.add_argument(
        "--base-compat",
        type=Path,
        default=Path("src/include/ghidra_compat.h"),
        help="narrow forced-include compatibility header",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        requested: list[str] = list(args.address)
        for path in args.addresses_file:
            requested.extend(read_address_file(path))
        roots = requested or list(DEFAULT_ROOTS)
        compile_config = (
            resolve_compile_config(args.compiler, args.base_compat) if args.compiler else None
        )
        plan = load_plan(args.stage, roots, compile_config)
        print(describe_plan(plan))
        if args.dry_run:
            for finding in plan.findings:
                print(
                    f"quarantine {finding.entry} {finding.category} "
                    f"{finding.symbol}: {finding.detail}",
                    file=sys.stderr,
                )
            return 0 if plan.structurally_clean else 2
        if plan.structurally_clean and compile_config is None:
            raise IslandError(
                "clean publication requires --compiler; use --dry-run for structural validation"
            )
        output = publish_plan(plan, args.output_root)
        print(f"output={output}")
        summary = json.loads((output / "island_summary.json").read_text(encoding="utf-8"))
        print(f"result={summary['status']}")
        return 0 if summary["status"] == "compile_verified" else 2
    except IslandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
