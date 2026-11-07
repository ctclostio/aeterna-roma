"""Prevent legacy generators from reintroducing fabricated ABI storage."""
import ast
import re
import unittest
from pathlib import Path

from prune_opaque import update_opaque_header
from filter_opaque import parse_opaque_header

ROOT = Path(__file__).resolve().parents[1]


class LegacyTypeStorageTests(unittest.TestCase):
    def test_pruner_preserves_typedef_names_and_private_tags(self):
        header = ["#pragma once", "typedef struct opaque_Alpha Alpha;",
                  "typedef struct opaque_Beta Beta;"]
        result = update_opaque_header(header, remove=["Beta"], add=["Gamma", "Alpha"])
        self.assertEqual(parse_opaque_header('\n'.join(result)), ["Alpha", "Gamma"])
        self.assertIn("typedef struct opaque_Gamma Gamma;", result)
        self.assertNotIn("typedef struct Gamma Gamma;", result)

    def test_bad_added_type_rejected(self):
        with self.assertRaises(ValueError):
            update_opaque_header(["#pragma once"], add=["X; struct Y { int z; }"])

    def test_compat_generator_and_header_have_exact_storage_widths(self):
        source = (ROOT / "scripts/gen_build_skeleton.py").read_text("utf-8")
        tree = ast.parse(source)
        generated = next(node.value.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and any(isinstance(target, ast.Name) and target.id == "compat"
                    for target in node.targets))
        header = (ROOT / "src/include/ghidra_compat.h").read_text("utf-8")
        for text in (generated, header):
            for name, size in (("undefined3", 3), ("undefined5", 5),
                               ("undefined6", 6), ("undefined7", 7), ("float10", 10)):
                pattern = (r"typedef struct\s*\{\s*uint8_t bytes\[" + str(size)
                           + r"\];\s*\}\s*" + name + r";")
                with self.subTest(name=name):
                    self.assertRegex(text, pattern)
            self.assertNotIn("typedef long double float10", text)


if __name__ == "__main__":
    unittest.main()
