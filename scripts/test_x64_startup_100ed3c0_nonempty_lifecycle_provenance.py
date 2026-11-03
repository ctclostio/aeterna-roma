#!/usr/bin/env python3
"""Authenticate the whole bounded nonempty lifecycle composition.

The original PE and canonical export are read only as inert data. The two
already admitted children are frozen authorities; no original address is
loaded or executed.
"""

from __future__ import annotations

import ast
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
CANONICAL = (
    ROOT / "src_canonical_out" / "empire.retail.dll" /
    "canonical_decomp" / "decomp_fn_100ed3c0.c"
)

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
PARENT_RAW_OFFSET = 0x000EC7C0
PARENT_SIZE = 400
PARENT_SHA256 = "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"
PRELOOP_SIZE = 177
PRELOOP_SHA256 = "b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626"
LIFECYCLE_SIZE = 223
LIFECYCLE_SHA256 = "0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9"

CHILD_AUTHORITIES = {
    "port/x64_ported/ported_100ed3c0_nonempty_preloop.h":
        (5_544, "6b36577a24aee25fe253afbf6fc3c8df66abc2b37d3df48b960cdf6e3a64a6f5"),
    "port/x64_ported/ported_100ed3c0_nonempty_preloop.c":
        (57_967, "17f8c4828490235d4734d734e3222be2c47ac9763bd69871b1e7cd2744fcae6f"),
    "port/x64_runtime/test_startup_100ed3c0_nonempty_preloop.c":
        (60_502, "3f79ef5062a2e89fe195588a7a067ace263a978d574da4664cc4687163b2a49a"),
    "scripts/test_x64_startup_100ed3c0_nonempty_preloop_provenance.py":
        (9_741, "905c2a110b37ad237bdbf6075defb0be012354b216a3cbda96dd1c52808bbdf2"),
    "docs/x64_startup_100ed3c0_nonempty_preloop.md":
        (6_884, "4c9ba359c3c71e8f390bd3d3bfaf99d6c7c96fe9090b5046fd570515348ff3e8"),
    "port/x64_ported/ported_100ed471_ordinary_lifecycle.h":
        (6_362, "c085cb6afe916a3c0399f63b971256ea5e7e01aeb6456bc7f5940115070aecba"),
    "port/x64_ported/ported_100ed471_ordinary_lifecycle.c":
        (21_022, "167942ade0a8fc003e9fa34d79da435c24e370a0acb7dfc722b18d80e78a0236"),
    "port/x64_runtime/test_startup_100ed471_ordinary_lifecycle.c":
        (52_053, "4a4d9b60861ab80df8a3da4a3b2718dd27d77a74bbbe0078c02a07c4d0043661"),
    "scripts/test_x64_startup_100ed471_ordinary_lifecycle_provenance.py":
        (43_449, "fc433827064f1d86d69c981eed50feb48160dddd01f65019a34ec6a746f476f5"),
    "docs/x64_startup_100ed471_ordinary_lifecycle.md":
        (7_910, "206313658b2160a439f160a86279ae58bffea1b4cbfe7908b744a4cf7f7f1a34"),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c":
        (2_522, "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8"),
}

NEW_ARTIFACTS = {
    "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.h":
        (4_111, "3c517d37787001ea4838a00e413c8124e08e9fecae749c767d8395de76915791"),
    "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.c":
        (28_612, "7abf65d7c510d17c45a59213be0e9176e4db76947cef436cfd542b03e8777b4d"),
    "port/x64_runtime/test_startup_100ed3c0_nonempty_lifecycle.c":
        (60_045, "921681d86eec2285095c97603652c5f0486776290c580ed19c1251c4ae5efcaa"),
    "docs/x64_startup_100ed3c0_nonempty_lifecycle.md":
        (6_922, "1dd19766d03b4dad226007e75d42d9ea1b4f0a3a6ab52c92b37981f078c73eb6"),
}

CANONICAL_ORDER = (
    "uVar5 = decomp_fn_100f1bb0(param_3);",
    "decomp_fn_100df270(&local_8d8,uVar5);",
    "decomp_fn_100f1cc0();",
    "do {",
    "iVar3 = decomp_fn_100ec5c0();",
    "decomp_fn_100f1cc0();",
    "return;",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_parent(data: bytes) -> None:
    if len(data) != PARENT_SIZE:
        raise ValueError("the complete parent boundary changed")
    if sha256(data) != PARENT_SHA256:
        raise ValueError("the authenticated complete parent bytes changed")
    if sha256(data[:PRELOOP_SIZE]) != PRELOOP_SHA256:
        raise ValueError("the authenticated preloop partition changed")
    if len(data[PRELOOP_SIZE:]) != LIFECYCLE_SIZE:
        raise ValueError("the lifecycle partition size changed")
    if sha256(data[PRELOOP_SIZE:]) != LIFECYCLE_SHA256:
        raise ValueError("the authenticated lifecycle partition changed")


class Startup100ed3c0NonemptyLifecycleProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dll = DLL.read_bytes()

    def test_original_dll_and_complete_parent_interval_are_exact(self) -> None:
        self.assertEqual(len(self.dll), DLL_SIZE)
        self.assertEqual(sha256(self.dll), DLL_SHA256)
        parent = self.dll[
            PARENT_RAW_OFFSET:PARENT_RAW_OFFSET + PARENT_SIZE
        ]
        validate_parent(parent)

    def test_canonical_parent_preserves_preloop_loop_cleanup_and_return_order(
        self,
    ) -> None:
        parent = CANONICAL.read_text(encoding="utf-8")
        cursor = 0
        for token in CANONICAL_ORDER:
            cursor = parent.index(token, cursor) + len(token)

    def test_admitted_children_are_frozen(self) -> None:
        for relative, (expected_size, expected_hash) in CHILD_AUTHORITIES.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

    def test_whole_composition_artifacts_are_one_coherent_snapshot(self) -> None:
        for relative, (expected_size, expected_hash) in NEW_ARTIFACTS.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

        source = (
            ROOT / "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.c"
        ).read_text(encoding="utf-8")
        preview = source.index("rome2_port_100ed471_run_ordinary_lifecycle(")
        preloop = source.index("rome2_port_100ed3c0_run_nonempty_preloop(")
        lifecycle = source.index(
            "rome2_port_100ed471_run_ordinary_lifecycle(", preview + 1
        )
        commit = source.index("*result_out = state.combined_result;")
        self.assertLess(preview, preloop)
        self.assertLess(preloop, lifecycle)
        self.assertLess(lifecycle, commit)

    def test_reciprocal_boundary_and_authority_mutants_fail(self) -> None:
        parent = self.dll[
            PARENT_RAW_OFFSET:PARENT_RAW_OFFSET + PARENT_SIZE
        ]
        for offset in (0, PRELOOP_SIZE - 1, PRELOOP_SIZE, PARENT_SIZE - 1):
            mutant = bytearray(parent)
            mutant[offset] ^= 1
            with self.assertRaises(ValueError):
                validate_parent(bytes(mutant))
        with self.assertRaises(ValueError):
            validate_parent(parent[:-1])
        with self.assertRaises(ValueError):
            validate_parent(parent + b"\xc3")

        for relative, (expected_size, expected_hash) in {
            **CHILD_AUTHORITIES, **NEW_ARTIFACTS
        }.items():
            data = bytearray((ROOT / relative).read_bytes())
            data[len(data) // 2] ^= 1
            self.assertTrue(
                len(data) != expected_size or
                sha256(bytes(data)) != expected_hash,
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
            {"__future__", "ast", "hashlib", "unittest", "pathlib"},
        )
        self.assertEqual(forbidden, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
