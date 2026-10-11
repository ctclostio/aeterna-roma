"""Black-box regression tests: generate into temporary directories, never the corpus."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GENERATOR = Path(__file__).resolve().parents[1] / "scripts" / "gen_build_skeleton.py"


class GeneratorRegression(unittest.TestCase):
    def generate(self, inputs):
        temporary = tempfile.TemporaryDirectory(prefix="skeleton-regression-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "input"
        source.mkdir()
        for name, text in inputs.items():
            (source / name).write_text(text, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(GENERATOR), str(source), str(root / "src")],
            text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = {p.name: p.read_text(encoding="utf-8") for p in (root / "buildable").glob("*.c")}
        prototypes = (root / "src" / "include" / "functions.h").read_text(encoding="utf-8")
        return outputs, prototypes

    def test_distinct_inputs_preserve_filenames_and_contents(self):
        inputs = {
            "10000001_a.c": "int a(void)\n{\n  return 1;\n}\n",
            "10000002_b.c": "int b(void)\n{\n  return 2;\n}\n",
        }
        outputs, prototypes = self.generate(inputs)
        self.assertEqual(outputs, inputs)
        self.assertIn("int a(void);", prototypes)
        self.assertIn("int b(void);", prototypes)

    def test_collision_renames_follow_each_input(self):
        inputs = {
            "10000001_same.c": "int same(void)\n{\n  return 11;\n}\n",
            "10000002_same.c": "int same(void)\n{\n  return 22;\n}\n",
            "10000003_other.c": "int other(void)\n{\n  return 33;\n}\n",
        }
        outputs, prototypes = self.generate(inputs)
        expected = dict(inputs)
        for name in ("10000001_same.c", "10000002_same.c"):
            renamed = "same_" + name.split("_")[0]
            expected[name] = inputs[name].replace("same(", renamed + "(")
            self.assertIn("int " + renamed + "(void);", prototypes)
        self.assertEqual(outputs, expected)
        self.assertNotIn("int same(void);", prototypes)
        self.assertIn("int other(void);", prototypes)

    def test_empty_corpus(self):
        outputs, prototypes = self.generate({})
        self.assertEqual(outputs, {})
        self.assertNotIn("int ", prototypes)


if __name__ == "__main__":
    unittest.main()
