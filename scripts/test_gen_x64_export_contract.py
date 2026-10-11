#!/usr/bin/env python3
"""Focused tests for gen_x64_export_contract.py (stdlib unittest only)."""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest

import gen_x64_export_contract as contract


IMAGE_BASE = 0x10000000
EXPORT_RVA = 0x2000
EXPORT_SIZE = 0x180


def _write_section_header(
    image: bytearray,
    offset: int,
    name: bytes,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> None:
    image[offset : offset + 8] = name.ljust(8, b"\0")
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        offset + 8,
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def make_pe(
    *,
    eat: tuple[int, ...] = (0x1000, 0x1000, 0x3000),
    names: tuple[str, ...] = ("AliasOne", "AliasTwo", "Datum"),
    name_ordinals: tuple[int, ...] = (0, 1, 2),
    forwarder_slot: int | None = None,
) -> bytes:
    """Build a minimal, structurally valid PE32 with controlled exports."""
    if len(names) != len(name_ordinals):
        raise AssertionError("test fixture names/ordinals mismatch")
    image = bytearray(0x800)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into(
        "<HHIIIHH", image, coff, contract.IMAGE_FILE_MACHINE_I386, 3, 0x12345678, 0, 0, 0xE0, 0x2102
    )
    optional = coff + 20
    struct.pack_into("<H", image, optional, contract.PE32_MAGIC)
    struct.pack_into("<I", image, optional + 28, IMAGE_BASE)
    struct.pack_into("<I", image, optional + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", image, optional + 36, 0x200)   # FileAlignment
    struct.pack_into("<I", image, optional + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", image, optional + 60, 0x200)   # SizeOfHeaders
    struct.pack_into("<I", image, optional + 92, 16)      # NumberOfRvaAndSizes
    struct.pack_into("<II", image, optional + 96, EXPORT_RVA, EXPORT_SIZE)

    section_table = optional + 0xE0
    _write_section_header(
        image, section_table, b".text", 0x200, 0x1000, 0x200, 0x200, 0x60000020
    )
    _write_section_header(
        image, section_table + 40, b".rdata", 0x200, 0x2000, 0x200, 0x400, 0x40000040
    )
    _write_section_header(
        image, section_table + 80, b".data", 0x200, 0x3000, 0x200, 0x600, 0xC0000040
    )

    rdata = 0x400
    dll_name_rva = 0x2030
    eat_rva = 0x2040
    names_rva = 0x2050
    ordinals_rva = 0x2060
    string_rva = 0x2080
    forwarder_rva = 0x2160
    mutable_eat = list(eat)
    if forwarder_slot is not None:
        mutable_eat[forwarder_slot] = forwarder_rva
    struct.pack_into(
        "<IIHHIIIIIII",
        image,
        rdata,
        0xAABBCCDD,
        0xFFFFFFFF,
        1,
        2,
        dll_name_rva,
        1,
        len(mutable_eat),
        len(names),
        eat_rva,
        names_rva,
        ordinals_rva,
    )
    image[rdata + 0x30 : rdata + 0x30 + len(b"synthetic.dll\0")] = b"synthetic.dll\0"
    struct.pack_into(f"<{len(mutable_eat)}I", image, rdata + 0x40, *mutable_eat)

    encoded_names = [name.encode("ascii") + b"\0" for name in names]
    name_rvas: list[int] = []
    cursor = string_rva
    for encoded in encoded_names:
        name_rvas.append(cursor)
        offset = rdata + cursor - EXPORT_RVA
        image[offset : offset + len(encoded)] = encoded
        cursor += len(encoded)
    if names:
        struct.pack_into(f"<{len(names)}I", image, rdata + 0x50, *name_rvas)
        struct.pack_into(f"<{len(names)}H", image, rdata + 0x60, *name_ordinals)
    forwarder = b"OTHERDLL.Target\0"
    forwarder_offset = rdata + forwarder_rva - EXPORT_RVA
    image[forwarder_offset : forwarder_offset + len(forwarder)] = forwarder
    return bytes(image)


def tsv_bytes(header: tuple[str, ...], rows: list[dict[str, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=header, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def function_row(address: int) -> dict[str, str]:
    text = f"{address:08x}"
    return {
        "entry": text,
        "canonical_name": f"decomp_fn_{text}",
        "original_name": f"FUN_{text}",
        "original_qualified_name": f"Synthetic::FUN_{text}",
        "symbol_id": str(address),
        "namespace_id": "7",
        "source_type": "ANALYSIS",
        "signature": f"undefined FUN_{text}(void)",
        "size": "1",
        "kind": "func",
        "body_ranges": f"{text}-{text}",
        "direct_thunk_target": "",
        "resolved_thunk_target": "",
    }


def data_row(address: int) -> dict[str, str]:
    text = f"{address:08x}"
    return {
        "address": text,
        "canonical_name": f"decomp_g_{text}",
        "original_name": f"DAT_{text}",
        "original_qualified_name": f"Synthetic::DAT_{text}",
        "symbol_id": str(address),
        "namespace_id": "7",
        "source_type": "ANALYSIS",
        "symbol_type": "Global Variable",
        "data_type_path": "/byte",
        "data_type_length": "1",
        "code_unit_length": "1",
    }


def make_inputs(*, include_data: bool = True) -> tuple[bytes, bytes, bytes, bytes, contract.InputPolicy]:
    dll = make_pe()
    functions = tsv_bytes(contract.FUNCTION_HEADER, [function_row(IMAGE_BASE + 0x1000)])
    data_rows = [data_row(IMAGE_BASE + 0x3000)] if include_data else []
    data = tsv_bytes(contract.DATA_HEADER, data_rows)
    fingerprint = "12" * 32
    snapshot = tsv_bytes(
        contract.SNAPSHOT_HEADER,
        [
            {
                "format": "canonical-address-v2",
                "executable_sha256": hashlib.sha256(dll).hexdigest(),
                "mapping_fingerprint": fingerprint,
                "functions": "1",
                "data_symbols": str(len(data_rows)),
            }
        ],
    )
    policy = contract.InputPolicy(
        dll_sha256=hashlib.sha256(dll).hexdigest(),
        function_index_sha256=hashlib.sha256(functions).hexdigest(),
        data_index_sha256=hashlib.sha256(data).hexdigest(),
        snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
        executable_sha256=hashlib.sha256(dll).hexdigest(),
        mapping_fingerprint=fingerprint,
        function_rows=1,
        data_rows=len(data_rows),
        export_rows=3,
        ordinal_base=1,
        dll_name="synthetic.dll",
    )
    return dll, functions, data, snapshot, policy


def build_synthetic(
    *,
    dll: bytes | None = None,
    functions: bytes | None = None,
    data: bytes | None = None,
    snapshot: bytes | None = None,
    policy: contract.InputPolicy | None = None,
) -> contract.ArtifactSet:
    defaults = make_inputs()
    return contract.build_artifacts(
        dll_bytes=dll if dll is not None else defaults[0],
        function_index_bytes=functions if functions is not None else defaults[1],
        data_index_bytes=data if data is not None else defaults[2],
        snapshot_bytes=snapshot if snapshot is not None else defaults[3],
        policy=policy if policy is not None else defaults[4],
        generator_sha256="ab" * 32,
        input_labels={
            "dll": "fixture/synthetic.dll",
            "function_index": "fixture/functions.tsv",
            "data_index": "fixture/data.tsv",
            "snapshot": "fixture/snapshot.tsv",
            "generator": "scripts/gen_x64_export_contract.py",
        },
    )


class ExportContractTests(unittest.TestCase):
    def test_duplicate_rva_aliases_data_and_golden_determinism(self) -> None:
        first = build_synthetic()
        second = build_synthetic()
        self.assertEqual(first.by_name(), second.by_name())
        self.assertEqual([row.ordinal for row in first.rows], [1, 2, 3])
        self.assertEqual(first.rows[0].target_symbol, first.rows[1].target_symbol)
        self.assertEqual(first.rows[0].target_kind, "code")
        self.assertEqual(first.rows[0].target_section_characteristics, 0x60000020)
        self.assertEqual(first.rows[2].target_kind, "data")
        self.assertEqual(first.rows[2].target_section_characteristics, 0xC0000040)
        self.assertIn(
            b"AliasOne=rome2_export_code_10001000 @1\n", first.def_blueprint
        )
        self.assertIn(
            b"AliasTwo=rome2_export_code_10001000 @2\n", first.def_blueprint
        )
        self.assertIn(
            b"Datum=rome2_export_data_10003000 @3 DATA\n", first.def_blueprint
        )
        # These hashes are the compact golden files for the complete fixture,
        # including sorted ordinals, raw name RVAs, aliases, DATA, and metadata.
        self.assertEqual(
            contract.sha256_bytes(first.manifest),
            "6da1870e3abfbb7531f707a83e380130f1691cee8a105b914e975b5a1d68f6a5",
        )
        self.assertEqual(
            contract.sha256_bytes(first.def_blueprint),
            "28cf4938336b2c697630e261031209f165277df6502ac648de6deb6d130ef389",
        )
        self.assertEqual(
            contract.sha256_bytes(first.metadata),
            "9f778f368cf214fb00afb43c44371a08e1ed0560bf8a575b6156ddd0c896ffee",
        )

    def test_rejects_hole(self) -> None:
        dll, functions, data, snapshot, policy = make_inputs()
        broken = make_pe(eat=(0x1000, 0, 0x3000))
        policy, snapshot = replace_dll(policy, broken)
        with self.assertRaisesRegex(contract.ContractError, "hole at export ordinal 2"):
            build_synthetic(
                dll=broken, functions=functions, data=data, snapshot=snapshot, policy=policy
            )

    def test_rejects_unnamed_export(self) -> None:
        dll, functions, data, snapshot, policy = make_inputs()
        broken = make_pe(names=("AliasOne", "AliasTwo"), name_ordinals=(0, 1))
        policy, snapshot = replace_dll(policy, broken)
        with self.assertRaisesRegex(contract.ContractError, "unnamed export ordinal 3"):
            build_synthetic(
                dll=broken, functions=functions, data=data, snapshot=snapshot, policy=policy
            )

    def test_rejects_forwarder(self) -> None:
        dll, functions, data, snapshot, policy = make_inputs()
        broken = make_pe(forwarder_slot=0)
        policy, snapshot = replace_dll(policy, broken)
        with self.assertRaisesRegex(contract.ContractError, "forwarder export.*ordinal 1"):
            build_synthetic(
                dll=broken, functions=functions, data=data, snapshot=snapshot, policy=policy
            )

    def test_rejects_truncated_pe(self) -> None:
        dll, functions, data, snapshot, policy = make_inputs()
        broken = dll[:0x450]
        policy, snapshot = replace_dll(policy, broken)
        with self.assertRaisesRegex(contract.ContractError, "truncated"):
            build_synthetic(
                dll=broken, functions=functions, data=data, snapshot=snapshot, policy=policy
            )

    def test_rejects_canonical_join_miss(self) -> None:
        dll, functions, _, _, _ = make_inputs()
        data = tsv_bytes(contract.DATA_HEADER, [])
        fingerprint = "12" * 32
        snapshot = tsv_bytes(
            contract.SNAPSHOT_HEADER,
            [
                {
                    "format": "canonical-address-v2",
                    "executable_sha256": hashlib.sha256(dll).hexdigest(),
                    "mapping_fingerprint": fingerprint,
                    "functions": "1",
                    "data_symbols": "0",
                }
            ],
        )
        policy = contract.InputPolicy(
            dll_sha256=hashlib.sha256(dll).hexdigest(),
            function_index_sha256=hashlib.sha256(functions).hexdigest(),
            data_index_sha256=hashlib.sha256(data).hexdigest(),
            snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
            executable_sha256=hashlib.sha256(dll).hexdigest(),
            mapping_fingerprint=fingerprint,
            function_rows=1,
            data_rows=0,
            export_rows=3,
        )
        with self.assertRaisesRegex(contract.ContractError, "canonical join miss/ambiguity"):
            build_synthetic(
                dll=dll, functions=functions, data=data, snapshot=snapshot, policy=policy
            )

    def test_rejects_source_hash_drift_before_parsing(self) -> None:
        dll, functions, data, snapshot, policy = make_inputs()
        with self.assertRaisesRegex(contract.ContractError, "function index source hash drift"):
            build_synthetic(
                dll=dll,
                functions=functions + b"\n",
                data=data,
                snapshot=snapshot,
                policy=policy,
            )

    def test_rejects_def_metacharacters(self) -> None:
        _, functions, data, _, policy = make_inputs()
        for metacharacter in (",", "#"):
            with self.subTest(metacharacter=metacharacter):
                broken = make_pe(
                    names=(f"Alias{metacharacter}One", "AliasTwo", "Datum")
                )
                updated_policy, snapshot = replace_dll(policy, broken)
                with self.assertRaisesRegex(
                    contract.ContractError, "unsupported DEF character"
                ):
                    build_synthetic(
                        dll=broken,
                        functions=functions,
                        data=data,
                        snapshot=snapshot,
                        policy=updated_policy,
                    )

    def test_byte_identity_checker(self) -> None:
        artifacts = build_synthetic().by_name()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in artifacts.items():
                (root / name).write_bytes(content)
            contract._check_outputs(root, artifacts)
            (root / contract.DEF_NAME).write_bytes(b"drift\n")
            with self.assertRaisesRegex(contract.ContractError, "byte-identity check failed"):
                contract._check_outputs(root, artifacts)


def replace_dll(
    policy: contract.InputPolicy, dll: bytes
) -> tuple[contract.InputPolicy, bytes]:
    """Update both the expected PE hash and its pinned synthetic snapshot."""
    digest = hashlib.sha256(dll).hexdigest()
    snapshot = tsv_bytes(
        contract.SNAPSHOT_HEADER,
        [
            {
                "format": "canonical-address-v2",
                "executable_sha256": digest,
                "mapping_fingerprint": policy.mapping_fingerprint,
                "functions": str(policy.function_rows),
                "data_symbols": str(policy.data_rows),
            }
        ],
    )
    updated = contract.InputPolicy(
        dll_sha256=digest,
        function_index_sha256=policy.function_index_sha256,
        data_index_sha256=policy.data_index_sha256,
        snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
        executable_sha256=digest,
        mapping_fingerprint=policy.mapping_fingerprint,
        function_rows=policy.function_rows,
        data_rows=policy.data_rows,
        export_rows=policy.export_rows,
        ordinal_base=policy.ordinal_base,
        dll_name=policy.dll_name,
        machine=policy.machine,
        optional_magic=policy.optional_magic,
    )
    return updated, snapshot


if __name__ == "__main__":
    unittest.main(verbosity=2)
