#!/usr/bin/env python3
"""Freeze inert evidence for the next 0x100edd70 entry-decision composition."""

from __future__ import annotations

import ast
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
IMAGE_BASE = 0x10000000
INDEX = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"
INDEX_SIZE = 8_344_450
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"

INTERVALS = {
    "pre_selector": (
        0x100EDD70,
        0x0ED170,
        348,
        None,
        "5c66148eb32e3f84f45c115d520fc4e02844ed4aa3e4441bae750b029a4a2f7b",
    ),
    "selector": (
        0x100EDECC,
        0x0ED2CC,
        57,
        bytes.fromhex(
            "8b7d108bcfb894f87311668b10663b11751e6685d27415668b5002663b5102"
            "750f83c00483c1046685d275de33c0eb051bc083c80185c0746e"
        ),
        "11bc65f6b73602d0b4a7c974728793ca5d817cc974a5c8ff91ab1e98b64e7ebc",
    ),
    "registration": (
        0x100EDF05,
        0x0ED305,
        27,
        bytes.fromhex(
            "68d0e50e10e83b9b590183c404c745e000000000c745fc00000000"
        ),
        "207f89cc1284f85df0955249dd435c83e869d52a33903b2cf25c3adf6ac677fb",
    ),
    "installed_tail": (
        0x100EDF41,
        0x0ED341,
        9,
        bytes.fromhex("c745fcffffffffeb4a"),
        "ebcf3ccb829383d74c54f505a857df1ea3fb5913165c50c70fecf6a987b67f02",
    ),
    "exception_gap": (
        0x100EDF4A,
        0x0ED34A,
        41,
        bytes.fromhex(
            "8b4dec8b018b008945dc894de08b45e050ff75dce86d02000083c408c3"
            "8b65e8c745fcffffffffeb21"
        ),
        "48fa1bded5911a24a9980288ef3a9470d56277c0a3636946cae77a4bb327ff77",
    ),
    "common_epilogue": (
        0x100EDF94,
        0x0ED394,
        28,
        bytes.fromhex(
            "ff1534f97211a044319f118b4df064890d000000005f5e5b8be55dc3"
        ),
        "490afcdfb5d7f9ee30342e409c8b657875d504f7fe6ce7c29822bcb204795f1c",
    ),
}

REGISTRATION_CALLEE = (
    0x11687A4A,
    0x01686E4A,
    bytes.fromhex(
        "8bff558bec568b35a4bd9e1157ff75088bfe333d245c1212e8b7fdffff59"
        "83e61fa3245c12128bced3cf8bc75f5e5dc3"
    ),
    "9e14f09ccd77390a9228d00b088fe5d948452a3e6dfb060aed8c6ae831b1c95a",
)
HANDLER_LEAF = (
    0x100EE5D0,
    0x0ED9D0,
    bytes.fromhex("6a006a006a0068050000c0ff1590f17211c3"),
    "c7e16cde3d599ee4de8d9da66aeffef459087ace2e703d07b9b735789727a73a",
)

CANONICAL = {
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100edd70.c": (
        3_717,
        "ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34",
    ),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11687a4a.c": (
        1_203,
        "3060518fa410cf645455e084277f873bfc07e2a0ccd789e6910f63575622fbdd",
    ),
}

ADMITTED_CHILDREN = {
    "port/x64_ported/ported_100edd70_policy.h": (
        1_268,
        "f7aeffb38483518de6aec83c299bca16b1c3edceb1c95f453044de0f4e57c8ca",
    ),
    "port/x64_ported/ported_100edd70_policy.c": (
        2_460,
        "690079cf131bcb1ecbe42ac723dd4732dac6465690af8ff1a2e596e68ad605d3",
    ),
    "port/x64_runtime/test_entry_policy.c": (
        19_733,
        "18684a7904046190dd6b0043cb8c9cf040578d9f0f84c2bc760d988837677701",
    ),
    "scripts/test_x64_entry_policy_provenance.py": (
        10_492,
        "80141a47d0dff17952df21a665b3084622f0da8a95b5021f6acf77f61bb928ae",
    ),
    "docs/x64_entry_policy_selector_spec.md": (
        5_665,
        "be40badf0320dace68ebdf56a72cce2d3bb6dc4be14d177006c03d26d3e48432",
    ),
    "port/x64_ported/ported_100edd70_caller_closure.h": (
        6_200,
        "5b5487efdeafeb2685c020853a12c90c438b776697baab752a5f06bcc5024490",
    ),
    "port/x64_ported/ported_100edd70_caller_closure.c": (
        24_737,
        "26f9c039697975a6a65924287a02126939479d2d3e77ae0758b948a804151340",
    ),
    "port/x64_runtime/test_startup_100edd70_caller_closure.c": (
        77_077,
        "846111a16d24999bf546dc289ef7a38e58fc1a6deda1b874eb5361c7a3c76191",
    ),
    "scripts/test_x64_startup_100edd70_caller_closure_provenance.py": (
        12_320,
        "6fe39f092aadcb49e50df0ed2eef8b587428b411b507de9f734ebd9610cf29a4",
    ),
    "docs/x64_startup_100edd70_caller_closure.md": (
        7_220,
        "b6d8ace9973b156a8cb0abe805a2b958fb0a9f1e64fb8659412144b60a698ab7",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} is outside the pinned input")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe, 24, "PE header")
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    require_range(data, optional, optional_size, "optional header")
    if (
        machine != 0x014C
        or not 1 <= section_count <= 96
        or optional_size < 112
        or struct.unpack_from("<H", data, optional)[0] != 0x010B
        or struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE
    ):
        raise ValueError("input is not the pinned PE32 shape")
    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        entry = table + index * 40
        name = data[entry:entry + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, entry + 8
        )
        characteristics = struct.unpack_from("<I", data, entry + 36)[0]
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append(
            (name, rva, virtual_size, raw_offset, raw_size, characteristics)
        )
    return optional, tuple(sections)


def read_rva(data: bytes, sections, rva: int, size: int):
    matches = []
    for section in sections:
        name, section_rva, _virtual_size, raw_offset, raw_size, flags = section
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta, flags))
    if len(matches) != 1:
        raise ValueError(f"RVA 0x{rva:08x} has {len(matches)} raw mappings")
    name, offset, flags = matches[0]
    require_range(data, offset, size, f"RVA 0x{rva:08x}")
    return data[offset:offset + size], name, offset, flags


def read_va(data: bytes, sections, va: int, size: int):
    if va < IMAGE_BASE:
        raise ValueError("VA precedes the image base")
    return read_rva(data, sections, va - IMAGE_BASE, size)


def read_c_string(data: bytes, sections, rva: int) -> str:
    _unit, _name, offset, _flags = read_rva(data, sections, rva, 1)
    end = data.find(b"\0", offset)
    if end < 0 or end - offset > 4096:
        raise ValueError(f"unterminated string at RVA 0x{rva:08x}")
    return data[offset:end].decode("ascii")


def imported_name_at_iat(data: bytes, optional: int, sections, iat_va: int):
    import_rva, import_size = struct.unpack_from("<II", data, optional + 104)
    if import_rva == 0 or import_size < 20:
        raise ValueError("import directory is absent")
    for descriptor_index in range(import_size // 20):
        descriptor, _name, _offset, _flags = read_rva(
            data, sections, import_rva + descriptor_index * 20, 20
        )
        values = struct.unpack("<IIIII", descriptor)
        if values == (0, 0, 0, 0, 0):
            break
        original_thunk, _stamp, _chain, name_rva, first_thunk = values
        module = read_c_string(data, sections, name_rva)
        lookup_rva = original_thunk or first_thunk
        for thunk_index in range(65536):
            thunk_bytes, _name, _offset, _flags = read_rva(
                data, sections, lookup_rva + thunk_index * 4, 4
            )
            thunk = struct.unpack("<I", thunk_bytes)[0]
            if thunk == 0:
                break
            if IMAGE_BASE + first_thunk + thunk_index * 4 != iat_va:
                continue
            if thunk & 0x80000000:
                return module, f"ordinal-{thunk & 0xffff}"
            return module, read_c_string(data, sections, thunk + 2)
    raise ValueError(f"IAT cell 0x{iat_va:08x} is absent")


def rel32_target(body: bytes, body_va: int, instruction_offset: int) -> int:
    if body[instruction_offset] != 0xE8:
        raise ValueError("instruction is not an E8 rel32 call")
    displacement = struct.unpack_from("<i", body, instruction_offset + 1)[0]
    return body_va + instruction_offset + 5 + displacement


def index_rows(index_data: bytes, entry: str):
    lines = index_data.decode("utf-8").splitlines()
    header = lines[0].split("\t")
    return [
        dict(zip(header, line.split("\t"), strict=True))
        for line in lines[1:]
        if line.split("\t", 1)[0] == entry
    ]


class Startup100edd70EntryDecisionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.optional, cls.sections = parse_pe32(cls.dll)
        cls.index = INDEX.read_bytes()
        if len(cls.index) != INDEX_SIZE or sha256(cls.index) != INDEX_SHA256:
            raise AssertionError("canonical function index differs")

    def test_all_mainline_and_excluded_intervals_are_exact(self) -> None:
        for role, (va, raw_offset, size, expected, expected_hash) in INTERVALS.items():
            with self.subTest(role=role):
                body, section, actual_offset, flags = read_va(
                    self.dll, self.sections, va, size
                )
                self.assertEqual(section, ".text")
                self.assertEqual(actual_offset, raw_offset)
                self.assertNotEqual(flags & 0x20000000, 0)
                self.assertEqual(len(body), size)
                if expected is not None:
                    self.assertEqual(body, expected)
                self.assertEqual(sha256(body), expected_hash)

    def test_selector_and_registration_control_flow_are_exact(self) -> None:
        selector = INTERVALS["selector"][3]
        registration = INTERVALS["registration"][3]
        assert selector is not None and registration is not None
        self.assertEqual(selector[:3], bytes.fromhex("8b7d10"))
        self.assertEqual(selector[-2:], bytes.fromhex("746e"))
        selector_target = 0x100EDECC + len(selector) + struct.unpack_from(
            "<b", selector, len(selector) - 1
        )[0]
        self.assertEqual(selector_target, 0x100EDF73)

        self.assertEqual(registration[:5], bytes.fromhex("68d0e50e10"))
        self.assertEqual(struct.unpack_from("<I", registration, 1)[0], 0x100EE5D0)
        self.assertEqual(rel32_target(registration, 0x100EDF05, 5), 0x11687A4A)
        self.assertEqual(registration[10:13], bytes.fromhex("83c404"))
        self.assertEqual(registration[13:20], bytes.fromhex("c745e000000000"))
        self.assertEqual(registration[20:27], bytes.fromhex("c745fc00000000"))
        self.assertEqual(0x100EDF05 + 13, 0x100EDF12)
        self.assertEqual(0x100EDF05 + 20, 0x100EDF19)

    def test_registration_callee_and_handler_identity_are_inert_and_exact(self) -> None:
        callee_va, callee_raw, expected, expected_hash = REGISTRATION_CALLEE
        body, section, offset, flags = read_va(
            self.dll, self.sections, callee_va, len(expected)
        )
        self.assertEqual((section, offset), (".text", callee_raw))
        self.assertNotEqual(flags & 0x20000000, 0)
        self.assertEqual(body, expected)
        self.assertEqual(sha256(body), expected_hash)
        self.assertEqual(body[-2:], bytes.fromhex("5dc3"))

        handler_va, handler_raw, expected, expected_hash = HANDLER_LEAF
        body, section, offset, flags = read_va(
            self.dll, self.sections, handler_va, len(expected)
        )
        self.assertEqual((section, offset), (".text", handler_raw))
        self.assertNotEqual(flags & 0x20000000, 0)
        self.assertEqual(body, expected)
        self.assertEqual(sha256(body), expected_hash)
        self.assertEqual(struct.unpack_from("<I", body, 7)[0], 0xC0000005)
        self.assertEqual(struct.unpack_from("<I", body, 13)[0], 0x1172F190)
        self.assertEqual(
            imported_name_at_iat(self.dll, self.optional, self.sections, 0x1172F190),
            ("KERNEL32.dll", "RaiseException"),
        )
        self.assertEqual(body[-1], 0xC3)

    def test_excluded_tails_converge_only_on_the_common_epilogue(self) -> None:
        installed = INTERVALS["installed_tail"][3]
        gap = INTERVALS["exception_gap"][3]
        epilogue = INTERVALS["common_epilogue"][3]
        assert installed is not None and gap is not None and epilogue is not None
        self.assertEqual(installed[:7], bytes.fromhex("c745fcffffffff"))
        self.assertEqual(
            0x100EDF48 + 2 + struct.unpack_from("<b", installed, 8)[0],
            0x100EDF94,
        )
        self.assertEqual(gap[-2:], bytes.fromhex("eb21"))
        self.assertEqual(
            0x100EDF71 + 2 + struct.unpack_from("<b", gap, len(gap) - 1)[0],
            0x100EDF94,
        )
        self.assertEqual(epilogue[:2], bytes.fromhex("ff15"))
        self.assertEqual(struct.unpack_from("<I", epilogue, 2)[0], 0x1172F934)
        self.assertEqual(
            imported_name_at_iat(self.dll, self.optional, self.sections, 0x1172F934),
            ("ole32.dll", "CoUninitialize"),
        )
        self.assertEqual(epilogue[6], 0xA0)
        self.assertEqual(struct.unpack_from("<I", epilogue, 7)[0], 0x119F3144)
        self.assertEqual(epilogue[14:21], bytes.fromhex("64890d00000000"))
        self.assertEqual(epilogue[-1], 0xC3)

    def test_canonical_identities_and_index_rows_are_exact(self) -> None:
        for relative, (expected_size, expected_hash) in CANONICAL.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)
        entry_rows = index_rows(self.index, "100edd70")
        self.assertEqual(len(entry_rows), 1)
        self.assertEqual(entry_rows[0]["canonical_name"], "decomp_fn_100edd70")
        self.assertEqual(entry_rows[0]["size"], "535")
        self.assertEqual(
            entry_rows[0]["body_ranges"],
            "100edd70-100edf49,100edf73-100edfaf",
        )
        callee_rows = index_rows(self.index, "11687a4a")
        self.assertEqual(len(callee_rows), 1)
        self.assertEqual(callee_rows[0]["canonical_name"], "decomp_fn_11687a4a")
        self.assertEqual(callee_rows[0]["original_name"], "__set_invalid_parameter_handler")
        self.assertEqual(callee_rows[0]["size"], "48")
        self.assertEqual(callee_rows[0]["body_ranges"], "11687a4a-11687a79")
        self.assertEqual(index_rows(self.index, "100ee5d0"), [])

    def test_admitted_selector_and_caller_snapshots_are_exact(self) -> None:
        for relative, (expected_size, expected_hash) in ADMITTED_CHILDREN.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

    def test_reciprocal_evidence_mutants_fail_and_oracle_is_read_only(self) -> None:
        for role, (_va, _raw, _size, expected, expected_hash) in INTERVALS.items():
            if expected is None:
                continue
            for offset in (0, len(expected) // 2, len(expected) - 1):
                mutant = bytearray(expected)
                mutant[offset] ^= 1
                self.assertNotEqual(sha256(bytes(mutant)), expected_hash, role)
        for _va, _raw, expected, expected_hash in (
            REGISTRATION_CALLEE,
            HANDLER_LEAF,
        ):
            mutant = bytearray(expected)
            mutant[len(mutant) // 2] ^= 1
            self.assertNotEqual(sha256(bytes(mutant)), expected_hash)

        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imports = set()
        forbidden = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {
                    "write_bytes", "write_text", "unlink", "rename", "replace",
                    "mkdir", "rmdir", "touch",
                }:
                    forbidden.add(node.func.attr)
        self.assertEqual(
            imports,
            {"__future__", "ast", "hashlib", "struct", "unittest", "pathlib"},
        )
        self.assertEqual(forbidden, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
