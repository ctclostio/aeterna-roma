#!/usr/bin/env python3
"""Authenticate the two exact 0x100edd70 caller-closure windows as data."""

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

WINDOWS = {
    "handler": {
        "start": 0x100EDF20,
        "body": bytes.fromhex(
            "ff752457ff750c56e893f4ffff6a01e89c5702006860650d10e8b271020083c418"
        ),
        "sha": "52227b99b8d956f8926eb0f02b0f3b8c62a229dee20653b5608dc81a96e41084",
        "parent_call": 0x100EDF28,
        "continuation": 0x100EDF2D,
        "byte_call": 0x100EDF2F,
        "dword_call": 0x100EDF39,
        "cleanup": 0x100EDF3E,
        "hard_stop": 0x100EDF41,
        "continuation_sha": "16059cc15e0932ce776ddaeb4f7e5e991eb8fe6776f279d8b3dacc4238826954",
    },
    "skip": {
        "start": 0x100EDF73,
        "body": bytes.fromhex(
            "ff752457ff750c56e840f4ffff6a01e8495702006860650d10e85f71020083c418"
        ),
        "sha": "76a454a3f06c1c8de33f0b3b0ab432e059de9abca52b342b8cac0e9f50198d6a",
        "parent_call": 0x100EDF7B,
        "continuation": 0x100EDF80,
        "byte_call": 0x100EDF82,
        "dword_call": 0x100EDF8C,
        "cleanup": 0x100EDF91,
        "hard_stop": 0x100EDF94,
        "continuation_sha": "2bb4e7d91eb623e2d1bb5e99c1c71431bd06fb60fb1ae5316da895dcdad3e7ba",
    },
}

KEEPERS = {
    0x101136D0: (
        bytes.fromhex("8a442404a28e3d9f11c3"),
        "22b0fe50342cb045ba9144d7d8060d9752e1f72b353436d7a43194e03c3c7bc0",
        0xA2,
        0x119F3D8E,
    ),
    0x101150F0: (
        bytes.fromhex("8b442404a35c3f9f11c3"),
        "a4e8fe0de027b3efd0a36a670c540ef75256b470d380c4b3124e91e5e61332c5",
        0xA3,
        0x119F3F5C,
    ),
}

EXCLUDED = {
    0x100EDF05: (
        bytes.fromhex(
            "68d0e50e10e83b9b590183c404c745e000000000c745fc00000000"
        ),
        "207f89cc1284f85df0955249dd435c83e869d52a33903b2cf25c3adf6ac677fb",
    ),
    0x100EDF41: (
        bytes.fromhex("c745fcffffffffeb4a"),
        "ebcf3ccb829383d74c54f505a857df1ea3fb5913165c50c70fecf6a987b67f02",
    ),
    0x100EDF94: (
        bytes.fromhex("ff1534f97211a044319f118b4df064890d000000005f5e5b8be55dc3"),
        "490afcdfb5d7f9ee30342e409c8b657875d504f7fe6ce7c29822bcb204795f1c",
    ),
    0x100D6560: (
        bytes.fromhex("c3"),
        "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e",
    ),
}

FROZEN_AUTHORITIES = {
    "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.h":
        (4_111, "3c517d37787001ea4838a00e413c8124e08e9fecae749c767d8395de76915791"),
    "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.c":
        (28_612, "7abf65d7c510d17c45a59213be0e9176e4db76947cef436cfd542b03e8777b4d"),
    "port/x64_runtime/test_startup_100ed3c0_nonempty_lifecycle.c":
        (60_045, "921681d86eec2285095c97603652c5f0486776290c580ed19c1251c4ae5efcaa"),
    "scripts/test_x64_startup_100ed3c0_nonempty_lifecycle_provenance.py":
        (8_308, "e8353d50bce692498e22cab73e25320b66565cc9775dc1fcab5eb83b65dd9eba"),
    "docs/x64_startup_100ed3c0_nonempty_lifecycle.md":
        (6_922, "1dd19766d03b4dad226007e75d42d9ea1b4f0a3a6ab52c92b37981f078c73eb6"),
    "port/x64_ported/ported_100edd70_policy.h":
        (1_268, "f7aeffb38483518de6aec83c299bca16b1c3edceb1c95f453044de0f4e57c8ca"),
    "port/x64_ported/ported_100edd70_policy.c":
        (2_460, "690079cf131bcb1ecbe42ac723dd4732dac6465690af8ff1a2e596e68ad605d3"),
    "scripts/test_x64_entry_policy_provenance.py":
        (10_492, "80141a47d0dff17952df21a665b3084622f0da8a95b5021f6acf77f61bb928ae"),
    "scripts/x64_startup_100ed3c0_abi_fixture.json":
        (11_506, "d1f129b03e19fded78c19d8211f3a943a68004d2ff8c12a1530ce1f276a6f8d0"),
    "scripts/test_x64_startup_100ed3c0_abi_provenance.py":
        (32_655, "6a375973206129208d0af00bf81cdd0063494fdedbc08df1110fa74152850372"),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100edd70.c":
        (3_717, "ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34"),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_101136d0.c":
        (558, "9582f5f7f22dc6891b025ff09935566ef2d88296edbdb1c87e6c0928cdbfd1d9"),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_101150f0.c":
        (647, "b7e4109ee9c74560b347cb40056e028d6e18b40034efd5cf791d619137aba582"),
}

NEW_ARTIFACTS = {
    "port/x64_ported/ported_100edd70_caller_closure.h":
        (6_200, "5b5487efdeafeb2685c020853a12c90c438b776697baab752a5f06bcc5024490"),
    "port/x64_ported/ported_100edd70_caller_closure.c":
        (24_737, "26f9c039697975a6a65924287a02126939479d2d3e77ae0758b948a804151340"),
    "port/x64_runtime/test_startup_100edd70_caller_closure.c":
        (77_077, "846111a16d24999bf546dc289ef7a38e58fc1a6deda1b874eb5361c7a3c76191"),
    "docs/x64_startup_100edd70_caller_closure.md":
        (7_220, "b6d8ace9973b156a8cb0abe805a2b958fb0a9f1e64fb8659412144b60a698ab7"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError("range is outside the pinned image")


def parse_pe32(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("missing MZ")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe, 24)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE")
    coff = pe + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if machine != 0x014C or struct.unpack_from("<H", data, optional)[0] != 0x010B:
        raise ValueError("image is not the expected PE32")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    table = optional + optional_size
    sections = []
    for index in range(section_count):
        entry = table + index * 40
        require_range(data, entry, 40)
        name = data[entry:entry + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, entry + 8
        )
        require_range(data, raw_offset, raw_size)
        sections.append((name, rva, virtual_size, raw_offset, raw_size))
    return image_base, tuple(sections)


def read_va(data: bytes, image_base: int, sections, va: int, size: int) -> bytes:
    rva = va - image_base
    matches = []
    for _name, section_rva, _virtual_size, raw_offset, raw_size in sections:
        delta = rva - section_rva
        if delta >= 0 and size <= raw_size - delta:
            matches.append(raw_offset + delta)
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    require_range(data, matches[0], size)
    return data[matches[0]:matches[0] + size]


class Startup100edd70CallerClosureProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.base, cls.sections = parse_pe32(cls.dll)
        if cls.base != 0x10000000:
            raise AssertionError("unexpected image base")

    def test_both_windows_calls_continuations_and_cleanup_are_exact(self) -> None:
        for name, facts in WINDOWS.items():
            with self.subTest(name=name):
                body = read_va(
                    self.dll, self.base, self.sections,
                    facts["start"], len(facts["body"])
                )
                self.assertEqual(body, facts["body"])
                self.assertEqual(sha256(body), facts["sha"])
                self.assertEqual(body[:8], bytes.fromhex("ff752457ff750c56"))
                parent_offset = facts["parent_call"] - facts["start"]
                self.assertEqual(body[parent_offset], 0xE8)
                parent_rel = struct.unpack_from("<i", body, parent_offset + 1)[0]
                self.assertEqual(facts["parent_call"] + 5 + parent_rel, 0x100ED3C0)
                continuation = body[facts["continuation"] - facts["start"]:]
                self.assertEqual(len(continuation), 20)
                self.assertEqual(sha256(continuation), facts["continuation_sha"])
                self.assertEqual(body[-3:], bytes.fromhex("83c418"))
                self.assertEqual(facts["cleanup"] + 3, facts["hard_stop"])

    def test_keeper_leaves_and_rel32_targets_are_exact(self) -> None:
        for va, (expected, expected_hash, store_opcode, destination) in KEEPERS.items():
            with self.subTest(va=f"0x{va:08x}"):
                body = read_va(self.dll, self.base, self.sections, va, len(expected))
                self.assertEqual(body, expected)
                self.assertEqual(sha256(body), expected_hash)
                self.assertEqual(body[4], store_opcode)
                self.assertEqual(struct.unpack_from("<I", body, 5)[0], destination)
                self.assertEqual(body[-1], 0xC3)
        for facts in WINDOWS.values():
            body = facts["body"]
            for call_va, target in (
                (facts["byte_call"], 0x101136D0),
                (facts["dword_call"], 0x101150F0),
            ):
                offset = call_va - facts["start"]
                self.assertEqual(body[offset], 0xE8)
                rel = struct.unpack_from("<i", body, offset + 1)[0]
                self.assertEqual(call_va + 5 + rel, target)

    def test_excluded_registration_epilogues_and_guard_node_are_pinned(self) -> None:
        for va, (expected, expected_hash) in EXCLUDED.items():
            with self.subTest(va=f"0x{va:08x}"):
                body = read_va(self.dll, self.base, self.sections, va, len(expected))
                self.assertEqual(body, expected)
                self.assertEqual(sha256(body), expected_hash)

    def test_frozen_children_and_new_artifacts_are_one_snapshot(self) -> None:
        for relative, (expected_size, expected_hash) in {
            **FROZEN_AUTHORITIES, **NEW_ARTIFACTS
        }.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

    def test_reciprocal_window_and_authority_mutants_fail(self) -> None:
        for facts in WINDOWS.values():
            body = facts["body"]
            for offset in (0, 8, 13, len(body) - 1):
                mutant = bytearray(body)
                mutant[offset] ^= 1
                self.assertNotEqual(sha256(bytes(mutant)), facts["sha"])
        for relative, (expected_size, expected_hash) in NEW_ARTIFACTS.items():
            data = bytearray((ROOT / relative).read_bytes())
            data[len(data) // 2] ^= 1
            self.assertTrue(
                len(data) != expected_size or sha256(bytes(data)) != expected_hash,
                relative,
            )

    def test_oracle_is_standard_library_only_and_read_only(self) -> None:
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
