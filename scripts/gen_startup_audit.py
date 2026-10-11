#!/usr/bin/env python3
"""Startup initializer audit generator (evidence-only inventory).

Implements docs/startup_audit_spec.md (schema rome2-startup-audit-v1).

The audit inventories the two initializer pointer tables invoked by
FUN_11683f08 in empire.retail.dll. It never executes code, classifies
initializers, translates anything, or registers anything in an x64 CRT.

Exit codes: 0 success / check match; 1 validation or check failure;
2 command-line usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
from pathlib import Path

SCHEMA = "rome2-startup-audit-v1"

# Pinned production inputs (byte-for-byte SHA-256).
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
IMAGE_BASE = 0x10000000

SLOTS_NAME = "startup_slots.tsv"
SUMMARY_NAME = "startup_summary.json"
OWNED_NAMES = (SLOTS_NAME, SUMMARY_NAME)
LOCK_NAME = ".startup-audit.lock"
TRANSACTION_PREFIX = ".startup-audit-txn-"

ENTRY_RE = re.compile(r"^[0-9a-f]{8}$")
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Table IDs, ranges, signatures and acceptance facts from the specification.
TABLE_DEFS = [
    {
        "id": "initterm_e_int",
        "start": 0x11739430,
        "end": 0x11739450,
        "signature": "int __cdecl(void)",
        "expect": {
            "slots": 8,
            "null_indices": [0],
            "unique_nonzero": 7,
            "exact": 1,
            "unresolved": 6,
        },
    },
    {
        "id": "initterm_void",
        "start": 0x1172FA04,
        "end": 0x1173942C,
        "signature": "void __cdecl(void)",
        "expect": {
            "slots": 9866,
            "null_indices": [0],
            "unique_nonzero": 9865,
            "exact": 1110,
            "unresolved": 8755,
        },
    },
]

TSV_HEADER = (
    "table\tslot_index\tslot_va\traw_target_va\tis_null\ttarget_rva\t"
    "target_section\ttarget_executable\texact_canonical_entry\t"
    "exact_canonical_name\texact_join"
)


class AuditError(Exception):
    """Any hard validation failure; reported on stderr with exit 1."""


class RecoveryRequired(AuditError):
    """Publication rollback failed; transaction evidence was preserved."""


def hex8(value: int) -> str:
    return format(value, "08x")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# PE parsing (own implementation; no external dependencies)
# --------------------------------------------------------------------------

class PeInfo:
    __slots__ = (
        "data",
        "machine",
        "magic",
        "image_base",
        "size_of_image",
        "sections",
    )

    def __init__(self, data, machine, magic, image_base, size_of_image, sections):
        self.data = data
        self.machine = machine
        self.magic = magic
        self.image_base = image_base
        self.size_of_image = size_of_image
        self.sections = sections


class Section:
    __slots__ = ("name", "vsize", "vaddr", "rawptr", "rawsize", "chars")

    def __init__(self, name, vsize, vaddr, rawptr, rawsize, chars):
        self.name = name
        self.vsize = vsize
        self.vaddr = vaddr
        self.rawptr = rawptr
        self.rawsize = rawsize
        self.chars = chars

    @property
    def executable(self) -> bool:
        return bool(self.chars & IMAGE_SCN_MEM_EXECUTE)


def parse_pe(data: bytes) -> PeInfo:
    """Validate PE32 x86 structure and return section mappings.

    Hard-fails on malformed/truncated data, wrong machine/magic/base,
    overlapping or unmappable raw section ranges.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise AuditError("not a PE file: missing MZ signature")
    if len(data) < 0x3C + 4:
        raise AuditError("truncated PE: missing e_lfanew")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        raise AuditError("truncated PE: bad e_lfanew offset")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise AuditError("malformed PE: missing PE\\0\\0 signature")

    coff = e_lfanew + 4
    if coff + 20 > len(data):
        raise AuditError("truncated PE: COFF header incomplete")
    machine, num_sections, _ts, _sym, _nsyms, opt_size, _chars = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    if machine != 0x014C:
        raise AuditError(
            f"wrong PE machine 0x{machine:04X}: expected 0x014C (I386)"
        )

    opt = coff + 20
    if opt_size < 96 or opt + opt_size > len(data):
        raise AuditError("truncated PE: optional header incomplete")
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x010B:
        raise AuditError(
            f"wrong optional-header magic 0x{magic:04X}: expected 0x010B (PE32)"
        )
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    if image_base != IMAGE_BASE:
        raise AuditError(f"wrong image base 0x{image_base:08X}: expected 0x10000000")
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    if size_of_image == 0 or image_base + size_of_image > 0x100000000:
        raise AuditError(
            f"invalid SizeOfImage 0x{size_of_image:08X} for PE32 image base"
        )

    if not 1 <= num_sections <= 96:
        raise AuditError(f"invalid PE section count {num_sections}")

    sect_off = opt + opt_size
    if sect_off + num_sections * 40 > len(data):
        raise AuditError("truncated PE: section headers incomplete")

    sections = []
    for i in range(num_sections):
        s = sect_off + i * 40
        raw_name = data[s:s + 8].split(b"\x00", 1)[0]
        if not raw_name:
            raise AuditError(f"section {i}: empty name")
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            raise AuditError(f"section {i}: name is not ASCII") from None
        if any(character in name for character in "\t\r\n"):
            raise AuditError(f"section {i}: name contains a TSV delimiter")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        chars = struct.unpack_from("<I", data, s + 36)[0]
        sections.append(Section(name, vsize, vaddr, rawptr, rawsize, chars))

    # File and image mappings must be bounded and unambiguous.
    raw_ranges = []
    rva_ranges = []
    for sec in sections:
        if sec.rawsize:
            end = sec.rawptr + sec.rawsize
            if end > len(data):
                raise AuditError(
                    f"section {sec.name!r}: raw range extends past end of file "
                    f"(0x{sec.rawptr:X}+0x{sec.rawsize:X} > 0x{len(data):X})"
                )
            raw_ranges.append((sec.rawptr, end, sec.name))
        span = max(sec.vsize, sec.rawsize)
        if span:
            end_rva = sec.vaddr + span
            if end_rva > size_of_image or end_rva > 0x100000000:
                raise AuditError(
                    f"section {sec.name!r}: RVA range exceeds SizeOfImage"
                )
            rva_ranges.append((sec.vaddr, end_rva, sec.name))
    raw_ranges.sort()
    for prev, cur in zip(raw_ranges, raw_ranges[1:]):
        if cur[0] < prev[1]:
            raise AuditError(
                f"overlapping raw section ranges: {prev[2]!r} and {cur[2]!r}"
            )
    rva_ranges.sort()
    for prev, cur in zip(rva_ranges, rva_ranges[1:]):
        if cur[0] < prev[1]:
            raise AuditError(
                f"overlapping RVA section mappings: {prev[2]!r} and {cur[2]!r}"
            )
    return PeInfo(data, machine, magic, image_base, size_of_image, sections)


def map_va(pe: PeInfo, va: int, size: int):
    """Map a VA to (file_offset, section); fail on unmappable/raw-unbacked."""
    if size <= 0:
        raise AuditError(f"invalid mapping width {size}")
    rva = va - pe.image_base
    if rva < 0:
        raise AuditError(f"VA 0x{va:08X} is below the image base")
    if rva + size > pe.size_of_image:
        raise AuditError(
            f"VA range 0x{va:08X}+{size} exceeds SizeOfImage"
        )
    matches = []
    for sec in pe.sections:
        extent = max(sec.vsize, sec.rawsize)
        if sec.vaddr <= rva and rva + size <= sec.vaddr + extent:
            matches.append(sec)
    if len(matches) > 1:
        raise AuditError(f"VA 0x{va:08X} maps ambiguously to multiple sections")
    if matches:
        sec = matches[0]
        delta = rva - sec.vaddr
        if delta + size > sec.rawsize:
            raise AuditError(
                f"VA range 0x{va:08X}+{size} is not fully raw-backed "
                f"in section {sec.name!r}"
            )
        return sec.rawptr + delta, sec
    raise AuditError(f"VA 0x{va:08X} does not map into any section")


# --------------------------------------------------------------------------
# Function index parsing and exact-equality join
# --------------------------------------------------------------------------

def parse_index(index_bytes: bytes):
    """Parse canonical_function_index.tsv into entry->canonical_name dict.

    Requires header columns 'entry' and 'canonical_name'; entries must be
    unique, exactly eight lowercase hexadecimal digits.
    """
    try:
        text = index_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditError(f"function index is not valid UTF-8: {exc}")
    # The pinned index is CRLF-terminated.  Normalize only that conventional
    # form so a stray bare carriage return cannot hide inside a field.
    if "\r" in text.replace("\r\n", ""):
        raise AuditError("function index contains a bare carriage return")
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise AuditError("function index is empty")
    header = lines[0].split("\t")
    if len(set(header)) != len(header):
        raise AuditError("function index header contains duplicate columns")
    for required in ("entry", "canonical_name"):
        if required not in header:
            raise AuditError(f"function index header lacks column {required!r}")
    entry_col = header.index("entry")
    name_col = header.index("canonical_name")
    ncols = len(header)

    table = {}
    for lineno, line in enumerate(lines[1:], start=2):
        if line == "":
            raise AuditError(f"function index line {lineno}: blank row")
        fields = line.split("\t")
        if len(fields) != ncols:
            raise AuditError(
                f"function index line {lineno}: {len(fields)} fields, expected {ncols}"
            )
        entry = fields[entry_col]
        if not ENTRY_RE.match(entry):
            raise AuditError(
                f"function index line {lineno}: entry {entry!r} is not eight "
                "lowercase hexadecimal digits"
            )
        if entry in table:
            raise AuditError(f"function index line {lineno}: duplicate entry {entry}")
        name = fields[name_col]
        if not name:
            raise AuditError(f"function index line {lineno}: blank canonical_name")
        if any(character in name for character in "\t\r\n"):
            raise AuditError(
                f"function index line {lineno}: canonical_name contains a TSV delimiter"
            )
        table[entry] = name
    if not table:
        raise AuditError("function index contains no entries")
    return table


# --------------------------------------------------------------------------
# Table auditing
# --------------------------------------------------------------------------

def evaluate_table(pe: PeInfo, index: dict, tdef: dict):
    """Read one initializer table and produce slot rows plus facts.

    Structural checks always run. Acceptance facts (tdef['expect']) are
    enforced only when present, so synthetic fixtures can reuse this core
    without weakening the production pins.
    """
    tid = tdef["id"]
    span = tdef["end"] - tdef["start"]
    if span <= 0 or span % 4 != 0:
        raise AuditError(f"{tid}: invalid range 0x{tdef['start']:X}-0x{tdef['end']:X}")

    count = span // 4
    vals = []
    rows = []
    null_indices = []
    for i in range(count):
        va = tdef["start"] + 4 * i
        off, _sec = map_va(pe, va, 4)
        val = struct.unpack_from("<I", pe.data, off)[0]
        vals.append(val)
        if val == 0:
            null_indices.append(i)
            rows.append([tid, str(i), hex8(va), "00000000", "yes",
                         "", "", "no", "", "", "no"])
        else:
            _toff, tsec = map_va(pe, val, 1)
            if not tsec.executable:
                raise AuditError(
                    f"{tid} slot {i}: target VA 0x{val:08X} in non-executable "
                    f"section {tsec.name!r}"
                )
            entry_key = hex8(val)
            matched = entry_key in index
            rows.append([
                tid, str(i), hex8(va), entry_key, "no",
                hex8(val - pe.image_base), tsec.name,
                "yes",                      # executable status (validated above)
                entry_key if matched else "",
                index.get(entry_key, "") if matched else "",
                "yes" if matched else "no",
            ])

    nonzero = [v for v in vals if v != 0]
    exact = sum(1 for v in nonzero if hex8(v) in index)
    unresolved = len(nonzero) - exact
    info = {
        "id": tid,
        "start_va": hex8(tdef["start"]),
        "end_va": hex8(tdef["end"]),
        "signature": tdef["signature"],
        "slot_count": count,
        "null_count": len(null_indices),
        "nonzero_count": len(nonzero),
        "unique_nonzero_count": len(set(nonzero)),
        "exact_join_count": exact,
        "unresolved_exact_count": unresolved,
        "null_indices": list(null_indices),
        "first_raw_value": hex8(vals[0]),
        "last_raw_value": hex8(vals[-1]),
    }

    expect = tdef.get("expect")
    if expect is not None:
        checks = (
            ("slot count", count == expect["slots"],
             f"{count} != {expect['slots']}"),
            ("null slots", null_indices == expect["null_indices"],
             f"{null_indices} != {expect['null_indices']}"),
            ("unique nonzero", len(set(nonzero)) == expect["unique_nonzero"],
             f"{len(set(nonzero))} != {expect['unique_nonzero']}"),
            ("exact joins", exact == expect["exact"], f"{exact} != {expect['exact']}"),
            ("unresolved exact", unresolved == expect["unresolved"],
             f"{unresolved} != {expect['unresolved']}"),
            ("last slot nonzero", vals[-1] != 0, "last slot is zero"),
        )
        for label, ok, detail in checks:
            if not ok:
                raise AuditError(f"{tid}: acceptance fact mismatch ({label}): {detail}")
    return rows, info


# --------------------------------------------------------------------------
# Output rendering
# --------------------------------------------------------------------------

def render_tsv(rows) -> bytes:
    for row_number, row in enumerate(rows, start=1):
        if len(row) != 11:
            raise AuditError(
                f"startup TSV row {row_number}: {len(row)} cells, expected 11"
            )
        for column_number, cell in enumerate(row, start=1):
            if not isinstance(cell, str):
                raise AuditError(
                    f"startup TSV row {row_number}, column {column_number}: "
                    "cell is not text"
                )
            if any(delimiter in cell for delimiter in "\t\r\n"):
                raise AuditError(
                    f"startup TSV row {row_number}, column {column_number}: "
                    "cell contains a TSV delimiter"
                )
    lines = [TSV_HEADER]
    lines.extend("\t".join(row) for row in rows)
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_summary(
    tables,
    dll_bytes_len,
    index_bytes_len,
    generator_sha,
    tsv_bytes,
    tsv_rows,
) -> bytes:
    summary = {
        "generator": {"sha256": generator_sha},
        "inputs": {
            "dll": {"byte_count": dll_bytes_len, "sha256": DLL_SHA256},
            "function_index": {
                "byte_count": index_bytes_len,
                "sha256": INDEX_SHA256,
            },
        },
        "invocation_order": [t["id"] for t in tables],
        "schema": SCHEMA,
        "startup_slots": {
            "data_row_count": tsv_rows,
            "sha256": sha256_hex(tsv_bytes),
        },
        "tables": tables,
        "totals": {
            "exact_join_count": sum(t["exact_join_count"] for t in tables),
            "nonzero_count": sum(t["nonzero_count"] for t in tables),
            "null_count": sum(t["null_count"] for t in tables),
            "slot_count": sum(t["slot_count"] for t in tables),
            "unresolved_exact_count": sum(
                t["unresolved_exact_count"] for t in tables
            ),
        },
    }
    text = json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    return text.encode("utf-8")


def compute_streams(dll_bytes, index_bytes, generator_bytes):
    """Full validation pipeline; returns (expected_tsv, expected_summary)."""
    pe = parse_pe(dll_bytes)
    index = parse_index(index_bytes)
    all_rows = []
    tables = []
    for tdef in TABLE_DEFS:
        rows, info = evaluate_table(pe, index, tdef)
        all_rows.extend(rows)
        tables.append(info)
    tsv = render_tsv(all_rows)
    gen_sha = sha256_hex(generator_bytes)
    summary = render_summary(
        tables,
        len(dll_bytes),
        len(index_bytes),
        gen_sha,
        tsv,
        len(all_rows),
    )
    return tsv, summary


def verify_pin(data: bytes, expected: str, label: str) -> None:
    actual = sha256_hex(data)
    if actual != expected:
        raise AuditError(
            f"{label} is unpinned: SHA-256 {actual} != expected {expected}"
        )


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------

def _is_regular_file_without_symlink(path: Path) -> bool:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def _write_fsynced(path: Path, payload: bytes) -> None:
    with open(path, "xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_existing(path: Path) -> None:
    # On Windows, FlushFileBuffers (used by os.fsync) requires a handle opened
    # for writing; a Python ``rb`` descriptor fails with EBADF.
    with open(path, "r+b") as handle:
        os.fsync(handle.fileno())


def _reserved_entries(out_dir: Path) -> list[str]:
    if not out_dir.is_dir():
        return []
    return sorted(
        entry.name
        for entry in out_dir.iterdir()
        if entry.name == LOCK_NAME or entry.name.startswith(TRANSACTION_PREFIX)
    )


def _acquire_lock(out_dir: Path) -> Path:
    lock_path = out_dir / LOCK_NAME
    try:
        descriptor = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        raise AuditError(
            f"publication lock already exists: {lock_path}; recovery may be required"
        ) from None
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(f"schema={SCHEMA}\npid={os.getpid()}\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(lock_path)
        except OSError:
            pass
        raise
    return lock_path


def _backup_file(source: Path, backup: Path, expected: bytes) -> None:
    # Keep an independent, writable byte copy.  A hard link shares the Windows
    # read-only attribute with its source and can make transaction cleanup
    # impossible; copy2 has the same problem because it copies that mode.
    source_stat = source.stat()
    _write_fsynced(backup, expected)
    if backup.read_bytes() != expected:
        raise AuditError(f"backup verification failed for {source.name}")
    # Preserve ordinary file timestamps without copying a read-only mode/ACL.
    os.utime(
        backup,
        ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
    )
    _fsync_existing(backup)


def _cleanup_transaction(transaction_dir: Path, lock_path: Path) -> None:
    errors = []
    try:
        shutil.rmtree(transaction_dir)
    except FileNotFoundError:
        pass
    except OSError as exc:
        errors.append(f"cannot remove {transaction_dir}: {exc}")
    try:
        os.unlink(lock_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        errors.append(f"cannot remove {lock_path}: {exc}")
    if errors:
        raise AuditError("publication cleanup failed: " + "; ".join(errors))


def write_outputs(out_dir: Path, tsv: bytes, summary: bytes) -> None:
    """Publish both files with rollback for caught replacement failures.

    This is process-transactional, not power-loss/crash atomic. The summary is
    installed last and hashes the TSV, so a reader can reject any interrupted
    mixed pair with ``--check``.
    """
    payloads = ((SLOTS_NAME, tsv), (SUMMARY_NAME, summary))
    out_dir.mkdir(parents=True, exist_ok=True)
    if not out_dir.is_dir():
        raise AuditError(f"output path is not a directory: {out_dir}")
    reserved = _reserved_entries(out_dir)
    if reserved:
        raise AuditError(
            "reserved publication artifact(s) already exist: " + ", ".join(reserved)
        )
    for name, _payload in payloads:
        destination = out_dir / name
        if os.path.lexists(destination) and not _is_regular_file_without_symlink(
            destination
        ):
            raise AuditError(f"owned output is not a regular file: {destination}")

    lock_path = _acquire_lock(out_dir)
    try:
        transaction_dir = Path(
            tempfile.mkdtemp(prefix=TRANSACTION_PREFIX, dir=out_dir)
        )
    except BaseException:
        try:
            os.unlink(lock_path)
        except OSError:
            pass
        raise
    records = []
    preserve_for_recovery = False
    committed = False
    try:
        # Stage and verify every new payload and every old-file backup before
        # changing either final path.
        for order, (name, payload) in enumerate(payloads):
            destination = out_dir / name
            stage = transaction_dir / f"new-{order}-{name}"
            _write_fsynced(stage, payload)
            if stage.read_bytes() != payload:
                raise AuditError(f"staged payload verification failed for {name}")
            existed = os.path.lexists(destination)
            backup = None
            old_payload = None
            if existed:
                old_payload = destination.read_bytes()
                backup = transaction_dir / f"old-{order}-{name}"
                _backup_file(destination, backup, old_payload)
            records.append(
                {
                    "name": name,
                    "payload": payload,
                    "destination": destination,
                    "stage": stage,
                    "backup": backup,
                    "existed": existed,
                    "old_payload": old_payload,
                }
            )

        installed = []
        try:
            # Slots first, summary commit marker last.
            for record in records:
                os.replace(record["stage"], record["destination"])
                installed.append(record)
            for record in records:
                if not _is_regular_file_without_symlink(record["destination"]):
                    raise AuditError(
                        f"published output is not regular: {record['name']}"
                    )
                if record["destination"].read_bytes() != record["payload"]:
                    raise AuditError(
                        f"published output verification failed: {record['name']}"
                    )
                _fsync_existing(record["destination"])
            committed = True
        except BaseException as primary:
            rollback_errors = []
            for record in reversed(installed):
                try:
                    if record["existed"]:
                        os.replace(record["backup"], record["destination"])
                    else:
                        try:
                            os.unlink(record["destination"])
                        except FileNotFoundError:
                            pass
                except BaseException as exc:
                    rollback_errors.append(f"{record['name']}: {exc}")
            if rollback_errors:
                preserve_for_recovery = True
                raise RecoveryRequired(
                    f"publication failed ({primary}); rollback also failed "
                    f"({'; '.join(rollback_errors)}); preserved {transaction_dir}"
                ) from primary
            try:
                for record in records:
                    if record["existed"]:
                        if not _is_regular_file_without_symlink(
                            record["destination"]
                        ):
                            raise RecoveryRequired(
                                f"rollback verification failed for "
                                f"{record['name']}; preserved {transaction_dir}"
                            ) from primary
                        if (
                            record["destination"].read_bytes()
                            != record["old_payload"]
                        ):
                            raise RecoveryRequired(
                                f"rollback bytes differ for {record['name']}; "
                                f"preserved {transaction_dir}"
                            ) from primary
                    elif os.path.lexists(record["destination"]):
                        raise RecoveryRequired(
                            f"rollback left new output {record['name']}; "
                            f"preserved {transaction_dir}"
                        ) from primary
            except RecoveryRequired:
                raise
            except BaseException as verify_error:
                preserve_for_recovery = True
                raise RecoveryRequired(
                    f"publication failed ({primary}); rollback could not be "
                    f"verified ({verify_error}); preserved {transaction_dir}"
                ) from primary
            raise AuditError(
                f"publication failed and prior outputs were restored: {primary}"
            ) from primary
    except RecoveryRequired:
        preserve_for_recovery = True
        raise
    finally:
        if not preserve_for_recovery:
            active_error = sys.exc_info()[1]
            try:
                _cleanup_transaction(transaction_dir, lock_path)
            except AuditError as cleanup_error:
                if committed:
                    raise AuditError(
                        "publication committed and verified, but cleanup failed; "
                        f"the new output pair is installed: {cleanup_error}"
                    ) from cleanup_error
                if active_error is not None:
                    raise AuditError(
                        f"{active_error}; transaction cleanup also failed: "
                        f"{cleanup_error}"
                    ) from active_error
                raise


def run_generate(dll_path: Path, index_path: Path, out_dir: Path) -> int:
    dll_bytes = read_input(dll_path, "--dll")
    index_bytes = read_input(index_path, "--function-index")
    generator_path = Path(__file__).resolve()
    generator_bytes = read_input(generator_path, "generator")
    verify_pin(dll_bytes, DLL_SHA256, f"DLL {dll_path.name}")
    verify_pin(index_bytes, INDEX_SHA256, f"function index {index_path.name}")
    tsv, summary = compute_streams(dll_bytes, index_bytes, generator_bytes)
    if read_input(generator_path, "generator") != generator_bytes:
        raise AuditError("generator changed while the audit was running")
    write_outputs(out_dir, tsv, summary)
    try:
        print(f"wrote {SLOTS_NAME} and {SUMMARY_NAME} to {out_dir}")
    except (OSError, ValueError) as exc:
        # Publication is already committed.  A broken status stream must not
        # turn a successful transaction into an ambiguous nonzero result.
        try:
            print(
                "warning: publication committed and verified, but success "
                f"status could not be written: {exc}",
                file=sys.stderr,
            )
        except (OSError, ValueError):
            pass
    return 0


def read_input(path: Path, option: str) -> bytes:
    if not path.is_file():
        raise AuditError(f"{option} input not found: {path.name} ({path})")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AuditError(f"cannot read {option} input {path}: {exc}")


def run_check(dll_path: Path, index_path: Path, out_dir: Path) -> int:
    # Strictly read-only: recompute expected streams and compare bytes.
    dll_bytes = read_input(dll_path, "--dll")
    index_bytes = read_input(index_path, "--function-index")
    generator_path = Path(__file__).resolve()
    generator_bytes = read_input(generator_path, "generator")
    verify_pin(dll_bytes, DLL_SHA256, f"DLL {dll_path.name}")
    verify_pin(index_bytes, INDEX_SHA256, f"function index {index_path.name}")
    exp_tsv, exp_summary = compute_streams(dll_bytes, index_bytes, generator_bytes)
    if read_input(generator_path, "generator") != generator_bytes:
        raise AuditError("generator changed while the audit was running")

    problems = []
    if not out_dir.is_dir():
        problems.append(f"output directory missing: {out_dir}")
    else:
        reserved = _reserved_entries(out_dir)
        if reserved:
            problems.append(
                "reserved publication artifact(s) present: " + ", ".join(reserved)
            )
        for name, expected in ((SLOTS_NAME, exp_tsv), (SUMMARY_NAME, exp_summary)):
            path = out_dir / name
            if not _is_regular_file_without_symlink(path):
                problems.append(f"missing output: {name}")
            elif path.read_bytes() != expected:
                problems.append(f"changed output: {name} differs from recomputed bytes")
    if problems:
        raise AuditError("; ".join(problems))
    print("check OK: outputs match recomputed byte streams")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gen_startup_audit.py",
        description="Evidence-only inventory of ROME II startup initializer tables.",
        allow_abbrev=False,
    )
    parser.add_argument("--dll", required=True, help="path to empire.retail.dll")
    parser.add_argument("--function-index", required=True,
                        help="path to canonical_function_index.tsv")
    parser.add_argument("--output-dir", required=True,
                        help="directory owning startup_slots.tsv and startup_summary.json")
    parser.add_argument("--check", action="store_true",
                        help="read-only verification of existing outputs")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)  # usage errors exit 2 via SystemExit
    try:
        out_dir = Path(args.output_dir)
        if args.check:
            return run_check(Path(args.dll), Path(args.function_index), out_dir)
        return run_generate(Path(args.dll), Path(args.function_index), out_dir)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: OS failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if sys.version_info < (3, 10):
        print("error: Python 3.10 or newer required", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())
