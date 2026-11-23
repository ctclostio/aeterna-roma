"""Differential regression: the regex-driven sanitize_c must equal the original scanner.

sanitize_c feeds every x64 static gate, so its output and findings are a
fail-closed contract. The character-at-a-time scanner it replaced is kept here
as the oracle.
"""
from __future__ import annotations

import itertools
import pathlib
import random
import unittest

from x64_entry_policy_static_gate import sanitize_c

ROOT = pathlib.Path(__file__).resolve().parents[1]


def reference_sanitize_c(text: str) -> tuple[str, list[str]]:
    output: list[str] = []
    findings: list[str] = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        following = text[index + 1] if index + 1 < length else ""
        if char == "/" and following == "/":
            output.extend("  ")
            index += 2
            while index < length and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and following == "*":
            output.extend("  ")
            index += 2
            closed = False
            while index < length:
                if index + 1 < length and text[index : index + 2] == "*/":
                    output.extend("  ")
                    index += 2
                    closed = True
                    break
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
            if not closed:
                findings.append("unterminated block comment")
            continue

        prefix_length = 0
        if text.startswith('u8"', index):
            prefix_length = 2
        elif char in "LuU" and following in "\"'":
            prefix_length = 1
            if char == "L":
                findings.append("native wide literal")

        quote_index = index + prefix_length
        if quote_index < length and text[quote_index] in "\"'":
            quote = text[quote_index]
            for _ in range(prefix_length + 1):
                output.append(" ")
            index = quote_index + 1
            escaped = False
            closed = False
            while index < length:
                literal_char = text[index]
                output.append("\n" if literal_char == "\n" else " ")
                index += 1
                if escaped:
                    escaped = False
                elif literal_char == "\\":
                    escaped = True
                elif literal_char == quote:
                    closed = True
                    break
            if not closed:
                findings.append("unterminated string or character literal")
            continue

        output.append(char)
        index += 1
    return "".join(output), findings


EDGE_CASES = [
    "", "/", "//", "/*", "/**/", "/*/", "// L\"x\"", "L", "aL", "L\n",
    "L\r", "u", "U", "u8", "u8'x'", 'u8"x"', "Lu8'x'", "u8L'x'",
    "'", '"', "'\\", '"\\', "L'", 'L"', "u'", 'u"', "U'", 'U"',
    "'x' L", '"L"', "'L'", "/* L", "// L", "/* L */ L", '"x"L',
    # A token that starts on the last character of a consumed comment.
    "/**//* wcscmp */", "/* a *///wcscmp\n", "/* a */* b",
    "/* outer /* inner */ wcscmp;", "// wchar_t\rwcscmp();",
    "// wchar_t\r\nwcscmp();", "// wchar_t\nwcscmp();",
    "/* wchar_t\r\nL\"x\" */ wcslen();", "/* unterminated\nwcscmp",
    '"escaped\\\"wcscmp" wchar_t;', "'\\\'' wcscmp();",
    '"line\nwcscmp" L\'x\';', '"line\r\nwcscmp"',
    '"\\\n" wcscmp', '"\\\r\n" wcscmp', "/*\x00λ\n*/ wchar_t;",
    "rome2_guest_add_checked(); /* wcscmp */", "(uint16_t *)value;",
]


class SanitizeDifferentialTests(unittest.TestCase):
    def compare(self, text: str) -> None:
        actual = sanitize_c(text)
        self.assertEqual(actual, reference_sanitize_c(text), repr(text[:300]))
        self.assertEqual(len(actual[0]), len(text))

    def test_edge_cases(self) -> None:
        for text in EDGE_CASES:
            with self.subTest(text=text):
                self.compare(text)

    def test_historical_prefix_semantics(self) -> None:
        self.assertEqual(sanitize_c("u8'x'"), ("u8   ", []))
        self.assertEqual(sanitize_c("L"), ("L", ["native wide literal"]))
        for text in ("L\n", "u", "U"):
            self.assertEqual(sanitize_c(text), (text, []))

    def test_exhaustive_short_inputs(self) -> None:
        alphabet = "/ *'\"Lu8\\\r\n"
        for length in range(5):
            for chars in itertools.product(alphabet, repeat=length):
                self.compare("".join(chars))

    def test_deterministic_fuzz(self) -> None:
        rng = random.Random(901)
        alphabet = "/ *'\"LuU8\\\r\nλ\x00wcscmp;"
        for _ in range(10000):
            self.compare("".join(rng.choices(alphabet, k=rng.randrange(300))))

    def test_long_comments_and_literals(self) -> None:
        for ending in ("\n", "\r", "\r\n"):
            self.compare(("// wcscmp L\"x\"" + ending) * 20000)
        self.compare('"' + "// /* L'x' \\" * 10000 + '"')
        self.compare("/*" + "// L'x'\n" * 10000 + "*/")

    def test_repository_inputs(self) -> None:
        paths = sorted((ROOT / "port").rglob("*.c")) + sorted((ROOT / "port").rglob("*.h"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.compare(path.read_bytes().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
