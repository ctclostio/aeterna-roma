from __future__ import annotations

import pathlib
import tempfile
import unittest

import x64_entry_policy_static_gate as static_candidate_gate


class StaticCandidateGateTests(unittest.TestCase):
    def inspect(self, source: str, *, policy: bool = False) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "candidate.c"
            path.write_text(source, encoding="utf-8", newline="\n")
            return static_candidate_gate.inspect_source(path, policy=policy)

    def test_comments_and_narrow_literals_do_not_trigger_wide_gate(self) -> None:
        findings = self.inspect(
            '/* wchar_t and wcscmp are forbidden. */\nconst char *s = "wchar_t";\n'
        )
        self.assertEqual(findings, [])

    def test_native_wide_identifier_and_literal_are_rejected(self) -> None:
        findings = self.inspect('wchar_t value = L\'x\';\n')
        self.assertTrue(any("wchar_t" in finding for finding in findings))
        self.assertIn("native wide literal", findings)

    def test_unaligned_native_unit_cast_is_rejected(self) -> None:
        findings = self.inspect(
            "uint16_t load(const uint8_t *p) { return *(const uint16_t *)p; }\n"
        )
        self.assertTrue(any("alignment" in finding for finding in findings))

    def test_policy_direct_guest_arithmetic_is_rejected(self) -> None:
        findings = self.inspect(
            "void f(void) { command_line.value += 2; "
            "rome2_guest_add_checked(); }\n",
            policy=True,
        )
        self.assertTrue(any("direct guest-address arithmetic" in finding
                            for finding in findings))

    def test_policy_without_checked_add_is_rejected(self) -> None:
        findings = self.inspect("int selector(void) { return 0; }\n", policy=True)
        self.assertIn("policy source never calls rome2_guest_add_checked", findings)

    def test_policy_header_rules_apply_without_requiring_an_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "candidate.h"
            path.write_text(
                "int inline_selector(void) { return memcmp(0, 0, 0); }\n",
                encoding="utf-8",
                newline="\n",
            )
            findings = static_candidate_gate.inspect_source(
                path,
                policy=True,
                require_checked_add=False,
            )
        self.assertTrue(any("memcmp" in finding for finding in findings))
        self.assertFalse(any("checked_add" in finding for finding in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)

