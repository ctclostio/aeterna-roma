#!/usr/bin/env python3
"""Authenticate the bounded nonempty composition of x86 0x100ed3c0.

The original PE and canonical export are read only as data.  Existing admitted
child ports are immutable authorities; no original address is executed.
"""

from __future__ import annotations

import ast
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
CANONICAL = ROOT / "src_canonical_out" / "empire.retail.dll"

DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
PRELOOP_RAW_OFFSET = 0x000EC7C0
PRELOOP_SIZE = 177
PRELOOP_SHA256 = "b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626"
PRELOOP_BYTES = bytes.fromhex(
    "81ec0c0900008d4c2404c605c8319f1101c605c5319f1101c7042400000000"
    "e82c4800008d4c2410e8234800008b8424100900008d4c243c8944241c"
    "894424348b0424894424388d44240450c644242400c744242800000000"
    "e8824600008d442410508d4c244ce8744600008b44241c8d4c2428"
    "ffb42418090000894424588a4424248844245c8b44242889442460"
    "c644246400e857470000508d442438508d4c246ce8081effff"
    "8d4c2428e84f480000"
)
EXCLUDED_RAW_OFFSET = PRELOOP_RAW_OFFSET + PRELOOP_SIZE
EXCLUDED_SIZE = 223
EXCLUDED_SHA256 = "0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9"

AUTHORITIES = {
    "src_canonical_out/empire.retail.dll/canonical_function_index.tsv":
        (8_344_450, "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ed3c0.c":
        (2_522, "6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8"),
    "src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100f2750.c":
        (1_287, "16c0b2bd1980f7c8870b9a74720c17df25b4f8a883e56f3ba2a4a5eff68f706b"),
    "scripts/test_x64_startup_100ed3c0_preloop_transcript_provenance.py":
        (51_944, "8daac04b62793018719e97ca0ee13b8599f7d39727251f536bc6938a928b40e3"),
    "port/x64_ported/ported_100ed3c0_empty_preloop.h":
        (6_783, "8e0b4f400cfd5318fe9b898e11eda878cd56890670d9bb68d81a846110cba6d2"),
    "port/x64_ported/ported_100ed3c0_empty_preloop.c":
        (35_142, "3fe47efd083eb28aa04b98f1307b25402f95361f5880c7079b9861184d7b617c"),
    "port/x64_ported/ported_100df270_suffix_transcript.h":
        (8_373, "c340cb925096a87be9ee0a7edba3ef86af80a669de5ed5335c39032a54d782ff"),
    "port/x64_ported/ported_100df270_suffix_transcript.c":
        (23_762, "ee40bb59780e2f9a5f88116472a406393017f7049766be34acb45c172bd929f1"),
    "scripts/test_x64_startup_100df270_suffix_transcript_provenance.py":
        (22_322, "917c38c1ea7ec9cc41c6d3b0689fdfcc099c8c1f1b52f0d78312fb02c3e29bcc"),
    "scripts/x64_startup_100df270_suffix_transcript_static_gate.py":
        (52_211, "503a226319800b32ab30cd50e3f7ecda4665fe7d492b7bf19994996494553043"),
    "port/x64_ported/ported_100f1bb0_owned_utf16.h":
        (6_420, "f884d1ac2917fa8d132b2db30f19f6508844fb196bcc1bf72f77e577554fc4c9"),
    "port/x64_ported/ported_100f1bb0_owned_utf16.c":
        (38_760, "9c6b6aa9eca21e8204834816ee0cb70e445d517f91f1819422cc70cc36f33bfa"),
    "scripts/test_x64_startup_100f1bb0_owned_utf16_provenance.py":
        (49_683, "797164ae31c0b3a6496810d70ba642b3e20025901f7bd813aa97c0c8b403d628"),
    "scripts/x64_startup_100f1bb0_owned_utf16_static_gate.py":
        (53_808, "27b67c184b494d8fe0de026343cf90b040766e6b2f6ab418206c708da2b7751d"),
    "port/x64_ported/ported_100f2750_first_use_owned.h":
        (4_603, "4e766b3bec926adadde9e60dfb04e4459cfa33d22be6ec9295b5b77fdabbf86d"),
    "port/x64_ported/ported_100f2750_first_use_owned.c":
        (56_125, "607fe4812f7dbd19196ed653be4d4a0fabe0e1740c8ad5d86fc6193a7b566b21"),
    "scripts/test_x64_startup_100f2750_sentinel_owned_provenance.py":
        (43_941, "595667f61b49688d49d8eb0bc2e47adf687959b5d74428630987ca0cc2b6497b"),
    "scripts/x64_startup_100f2750_sentinel_owned_static_gate.py":
        (66_662, "b8fea27012499024e5403f982875a0f0f7ce23136861cf6e26cbcd54993e3070"),
}

NEW_ARTIFACTS = {
    "port/x64_ported/ported_100ed3c0_nonempty_preloop.h":
        (5_544, "6b36577a24aee25fe253afbf6fc3c8df66abc2b37d3df48b960cdf6e3a64a6f5"),
    "port/x64_ported/ported_100ed3c0_nonempty_preloop.c":
        (57_967, "17f8c4828490235d4734d734e3222be2c47ac9763bd69871b1e7cd2744fcae6f"),
    "port/x64_runtime/test_startup_100ed3c0_nonempty_preloop.c":
        (60_502, "3f79ef5062a2e89fe195588a7a067ace263a978d574da4664cc4687163b2a49a"),
    "docs/x64_startup_100ed3c0_nonempty_preloop.md":
        (6_884, "4c9ba359c3c71e8f390bd3d3bfaf99d6c7c96fe9090b5046fd570515348ff3e8"),
    "docs/x64_startup_100ed3c0_nonempty_preloop_spec.md":
        (6_081, "58ed588b497ff0d6c1207e1f44da6d837f6a2b4d7e1298fc7852a35ecdbeb3a8"),
}

PARENT_CALL_ORDER = (
    "decomp_fn_100f1c10(0);",
    "decomp_fn_100f1c10();",
    "decomp_fn_100f1aa0(local_908);",
    "decomp_fn_100f1aa0(local_8fc);",
    "uVar5 = decomp_fn_100f1bb0(param_3);",
    "decomp_fn_100df270(&local_8d8,uVar5);",
    "decomp_fn_100f1cc0();",
    "do {",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_preloop(data: bytes) -> None:
    if len(data) != PRELOOP_SIZE:
        raise ValueError("the hard stop changed")
    if data != PRELOOP_BYTES or sha256(data) != PRELOOP_SHA256:
        raise ValueError("the authenticated preloop bytes changed")


class Startup100ed3c0NonemptyPreloopProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()

    def test_original_dll_interval_and_hard_stop_are_exact(self):
        self.assertEqual(len(self.dll), DLL_SIZE)
        self.assertEqual(sha256(self.dll), DLL_SHA256)
        preloop = self.dll[PRELOOP_RAW_OFFSET:PRELOOP_RAW_OFFSET + PRELOOP_SIZE]
        validate_preloop(preloop)
        excluded = self.dll[
            EXCLUDED_RAW_OFFSET:EXCLUDED_RAW_OFFSET + EXCLUDED_SIZE
        ]
        self.assertEqual(len(excluded), EXCLUDED_SIZE)
        self.assertEqual(sha256(excluded), EXCLUDED_SHA256)

    def test_canonical_parent_preserves_the_three_relevant_calls_in_order(self):
        parent = (
            CANONICAL / "canonical_decomp" / "decomp_fn_100ed3c0.c"
        ).read_text(encoding="utf-8")
        positions = [parent.index(token) for token in PARENT_CALL_ORDER]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(positions[-2], positions[-1])

    def test_all_admitted_child_authorities_are_frozen(self):
        for relative, (expected_size, expected_hash) in AUTHORITIES.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

    def test_new_composition_artifacts_are_one_coherent_snapshot(self):
        for relative, (expected_size, expected_hash) in NEW_ARTIFACTS.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

        source = (ROOT / next(
            key for key in NEW_ARTIFACTS if key.endswith("nonempty_preloop.c")
        )).read_text(encoding="utf-8")
        ordered = (
            "rome2_port_100f1bb0_build_owned_utf16(",
            "rome2_port_100df270_run_platform_prefix_transcript(",
            "rome2_port_100df270_project_headless_empty_state(",
            "rome2_port_100df270_run_suffix_transcript_delegated(",
            "rome2_port_100f1cc0_cleanup_owned_utf16(",
            "result_out->child_receiver",
        )
        positions = [source.rindex(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("rome2_port_100f2750_first_use_owned(", source)

    def test_reciprocal_boundary_and_authority_mutants_fail(self):
        for offset in (0, 1, 64, 128, PRELOOP_SIZE - 1):
            mutant = bytearray(PRELOOP_BYTES)
            mutant[offset] ^= 1
            with self.assertRaises(ValueError):
                validate_preloop(bytes(mutant))
        with self.assertRaises(ValueError):
            validate_preloop(PRELOOP_BYTES[:-1])
        with self.assertRaises(ValueError):
            validate_preloop(PRELOOP_BYTES + b"\x56")

        for relative, (expected_size, expected_hash) in {
            **AUTHORITIES, **NEW_ARTIFACTS
        }.items():
            data = bytearray((ROOT / relative).read_bytes())
            data[len(data) // 2] ^= 1
            self.assertTrue(
                len(data) != expected_size or sha256(bytes(data)) != expected_hash,
                relative,
            )

    def test_oracle_is_standard_library_only_and_read_only(self):
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
        self.assertEqual(imports, {"__future__", "ast", "hashlib", "unittest", "pathlib"})
        self.assertEqual(forbidden, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
