#!/usr/bin/env python3
"""Additive source-shape containment checks, NOT a C semantic proof/admission gate.

A small lexer preserves strings and token boundaries, removes comments, and
rejects unsupported lexical constructs. The API and executable body have a
closed token grammar; tables accept only literal/enum constant fields. This
intentionally requires review for harmless structural refactors too. It assumes
ordinary trusted C11 headers/compiler (no injected macros, forced includes or
interposed memcpy). Production scans are bounded lexical evidence, not resolved
CMake/link graphs or whole-program alias analysis. No native/DLL execution.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEM = "ported_100edd70_terminal_transcript"
FUNCTION = "rome2_port_100edd70_project_terminal_transcript"
P = "ROME2_100EDD70_TERMINAL_"
T = "rome2_100edd70_terminal_"
HEADER = ROOT / "port/x64_ported" / (STEM + ".h")
SOURCE = ROOT / "port/x64_ported" / (STEM + ".c")
UNBUILT_COMPOSITION_PATHS = (
    ROOT / "port/x64_ported/ported_100edd70_unified_entry.c",
    ROOT / "port/x64_ported/ported_100edd70_unified_entry.h",
)

# Ordered alternatives keep comment-looking text inside literals inert and
# distinguish && from & &, identifiers from adjacent identifiers, etc.
LEX = re.compile(
    r'(?P<space>\s+)|(?P<comment>/\*.*?\*/|//[^\n]*)|'
    r'(?P<string>"(?:[^"\\\n]|\\[^\n])*"|\'(?:[^\'\\\n]|\\[^\n])*\')|'
    r'(?P<word>[A-Za-z_][A-Za-z_0-9]*)|'
    r'(?P<number>0[xX][0-9a-fA-F]+[uUlL]*|[0-9]+[uUlL]*)|'
    r'(?P<punct>->|&&|\|\||==|!=|<=|>=|<<|>>|\+\+|--|'
    r'[{}\[\]();,.#*+/%&|^!~<>=?:-])', re.DOTALL)


def tokens(text: str) -> tuple[str, ...]:
    if "\\\n" in text or "\\\r\n" in text or "??" in text:
        raise ValueError("line splices/trigraphs are outside this source grammar")
    result = []
    pos = 0
    while pos < len(text):
        match = LEX.match(text, pos)
        if match is None:
            raise ValueError(f"unsupported C token at offset {pos}")
        if match.lastgroup not in {"space", "comment"}:
            result.append(match.group())
        pos = match.end()
    return tuple(result)


def enum(name: str, members: list[str], prefix: str = P) -> str:
    values = ",".join(f"{prefix}{member}={i}" for i, member in enumerate(members))
    return f"typedef enum {T}{name} {{{values}}} {T}{name};"


KINDS = ["UNUSED", "TAIL_FRAME_STORE", "BRANCH", "IMPORTED_CALL_SHAPE",
         "GLOBAL_BYTE_LOAD", "SEH_SLOT_LOAD", "FS_ZERO_STORE", "POP_EDI",
         "POP_ESI", "POP_EBX", "TEARDOWN_MOV_ESP_EBP", "TEARDOWN_POP_EBP", "RETURN"]
IDENTITIES = ["NONE", "AL", "ECX", "EDI", "ESI", "EBX", "ESP", "EBP",
              "FRAME_SLOT", "FS_ZERO", "STACK_TOP", "GLOBAL_BYTE", "IMMEDIATE"]
SIGNATURE = f"{T}status {FUNCTION}(uint32_t policy, {T}transcript_result *result_out)"
EXPECTED_HEADER = f"""
#ifndef ROME2_PORTED_100EDD70_TERMINAL_TRANSCRIPT_H
#define ROME2_PORTED_100EDD70_TERMINAL_TRANSCRIPT_H
#include <stdint.h>
#define {P}POLICY_INSTALL UINT32_C(0)
#define {P}POLICY_SKIP UINT32_C(1)
#define {P}TAIL_CAPACITY 2U
#define {P}EPILOGUE_CAPACITY 10U
{enum('status', ['OK', 'BAD_ARGUMENT'])}
{enum('step_kind', KINDS)}
{enum('identity', IDENTITIES, P + 'ID_')}
typedef struct {T}step {{
 {T}step_kind kind;
 uint32_t instruction_original_pc;
 uint32_t instruction_size_bytes;
 uint32_t target_original_pc;
 uint32_t source_original_address;
 {T}identity source_identity;
 {T}identity destination_identity;
 int32_t frame_displacement;
 uint32_t immediate;
 uint32_t width_or_cleanup_bytes;
}} {T}step;
typedef struct {T}transcript_result {{
 uint32_t policy;
 uint32_t tail_record_count;
 uint32_t epilogue_record_count;
 {T}step tail[{P}TAIL_CAPACITY];
 {T}step epilogue[{P}EPILOGUE_CAPACITY];
 uint32_t return_source_identity;
 uint32_t return_original_pc;
}} {T}transcript_result;
{SIGNATURE};
#endif
"""
# Deliberately closed executable shape: both rejection branches dominate all
# initialization/publication; only the final memcpy writes through result_out.
EXPECTED_FUNCTION = SIGNATURE + f""" {{
 {T}transcript_result result;
 uintptr_t address;
 if ((policy != {P}POLICY_INSTALL && policy != {P}POLICY_SKIP) || result_out == NULL) {{
   return {P}BAD_ARGUMENT;
 }}
 address = (uintptr_t)result_out;
 if (address % _Alignof({T}transcript_result) != 0U ||
     sizeof(*result_out) - 1U > UINTPTR_MAX - address) {{
   return {P}BAD_ARGUMENT;
 }}
 memset(&result, 0, sizeof(result));
 result.policy = policy;
 if (policy == {P}POLICY_INSTALL) {{
   result.tail_record_count = {P}TAIL_CAPACITY;
   memcpy(result.tail, installed_tail, sizeof(installed_tail));
 }}
 result.epilogue_record_count = {P}EPILOGUE_CAPACITY;
 memcpy(result.epilogue, common_epilogue, sizeof(common_epilogue));
 result.return_source_identity = UINT32_C(0x119f3144);
 result.return_original_pc = UINT32_C(0x100edfaf);
 memcpy(result_out, &result, sizeof(result));
 return {P}OK;
}}
"""


class Cursor:
    def __init__(self, values: tuple[str, ...]):
        self.values = values
        self.pos = 0

    def take(self, expected: str) -> None:
        want = tokens(expected)
        if self.values[self.pos:self.pos + len(want)] != want:
            raise ValueError(f"expected {expected!r} at token {self.pos}")
        self.pos += len(want)

    def atom(self) -> str:
        if self.pos == len(self.values):
            raise ValueError("unexpected end of input")
        value = self.values[self.pos]
        self.pos += 1
        return value


def literal(cursor: Cursor) -> None:
    value = cursor.atom()
    if value == "UINT32_C":
        cursor.take("(")
        value = cursor.atom()
        if not re.fullmatch(r"0x[0-9a-f]+|[0-9]+", value):
            raise ValueError("UINT32_C operand must be a numeric literal")
        cursor.take(")")
    elif value == "-":
        if not re.fullmatch(r"[0-9]+", cursor.atom()):
            raise ValueError("negative displacement must be a literal")
    elif not re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)U?", value):
        raise ValueError("table operand must be a constant literal")


def directive_lines(text: str) -> tuple[tuple[str, ...], ...]:
    # Keep directive boundaries: a removed newline after #define can change
    # C meaning without changing the flattened token sequence.
    return tuple(tokens(line) for line in text.splitlines()
                 if line.lstrip().startswith("#"))


def inspect_header(text: str) -> list[str]:
    try:
        if directive_lines(text) != directive_lines(EXPECTED_HEADER):
            return ["header preprocessor directive boundaries changed"]
        if tokens(text) != tokens(EXPECTED_HEADER):
            return ["closed typed-data API changed (no callbacks/value/context inputs)"]
        return []
    except ValueError as error:
        return [str(error)]


def inspect_source(text: str) -> list[str]:
    try:
        expected_directives = f'#include "{STEM}.h"\n#include <stddef.h>\n#include <string.h>'
        if directive_lines(text) != directive_lines(expected_directives):
            return ["source preprocessor directives/dependencies changed"]
        cursor = Cursor(tokens(text))
        cursor.take(f'#include "{STEM}.h" #include <stddef.h> #include <string.h>')
        for typename, size in (("step_kind", 4), ("identity", 4),
                               ("step", 40), ("transcript_result", 500)):
            cursor.take(f"_Static_assert(sizeof({T}{typename}) == {size}U,")
            if not cursor.atom().startswith('"'):
                raise ValueError("static assertion diagnostic must be a string")
            cursor.take(");")
        for table, count in (("installed_tail", 2), ("common_epilogue", 10)):
            cursor.take(f"static const {T}step {table}[{count}] = {{")
            for row in range(count):
                cursor.take("{")
                kind = cursor.atom()
                if kind not in {P + name for name in KINDS[1:]}:
                    raise ValueError("table kind must be a known enum constant")
                # Four numeric fields, two operand identities, three numbers.
                for _ in range(4):
                    cursor.take(",")
                    literal(cursor)
                for _ in range(2):
                    cursor.take(",")
                    if cursor.atom() not in {P + "ID_" + item for item in IDENTITIES}:
                        raise ValueError("table identity must be a known enum constant")
                for field in range(3):
                    cursor.take(",")
                    if field == 1 and kind != P + "TAIL_FRAME_STORE":
                        cursor.take("0U")  # no observed/supplied opaque value
                    else:
                        literal(cursor)
                cursor.take("}")
                if row != count - 1:
                    cursor.take(",")
            cursor.take("};")
        cursor.take(EXPECTED_FUNCTION)
        if cursor.pos != len(cursor.values):
            raise ValueError("extra declarations/executable content after projection")
        return []
    except ValueError as error:
        return [str(error)]


def inspect_production(text: str) -> list[str]:
    # Deliberately scan comments/strings as well: export/include names and build
    # source paths can live in strings. A documentation mention is a review flag.
    return (["candidate reference on production/build surface"]
            if re.search(r"100edd70[^\s\";()]*terminal_transcript|" + FUNCTION,
                         text, re.IGNORECASE) else [])


def inspect_cmake(text: str) -> list[str]:
    findings = inspect_production(text)
    for candidate in (
        "ported_100edd70_unified_entry",
        "ported_100edd70_full_entry",
    ):
        if candidate.lower() in text.lower():
            findings.append(f"unadmitted entry composition entered CMake: {candidate}")
    # Current root CMake enumerates sources. Any future glob warrants graph
    # review, even one that does not obviously spell this candidate's basename.
    if re.search(r"\bfile\s*\(\s*GLOB(?:_RECURSE)?\b", text, re.IGNORECASE):
        findings.append("source glob requires resolved build-graph review")
    return findings


def production_paths() -> list[Path]:
    # Inspect compiled/production port inputs. The two entry-composition drafts
    # consume this candidate, but are deliberately unbuilt and checked separately.
    paths = [ROOT / "docs/x64_export_contract.md"]
    for directory in (ROOT / "port", ROOT / "src/include"):
        paths.extend(path for path in directory.rglob("*")
                     if path.is_file() and path.suffix.lower() in
                     {".c", ".h", ".cpp", ".hpp", ".def", ".tsv"}
                     and not path.name.startswith("test_")
                     and not any("_locked" in part for part in path.parts)
                     and path not in {HEADER, SOURCE}
                     and path not in UNBUILT_COMPOSITION_PATHS)
    return sorted(paths)


class TerminalContainmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

    def reciprocal(self, inspector, payload: str, old: str, new: str) -> None:
        self.assertEqual(payload.count(old), 1, f"nonunique mutation anchor: {old}")
        self.assertEqual(inspector(payload), [])
        start = payload.index(old)
        mutant = payload[:start] + new + payload[start + len(old):]
        self.assertTrue(inspector(mutant), f"mutant escaped: {new}")
        restored = mutant[:start] + old + mutant[start + len(new):]
        self.assertEqual(restored, payload)
        self.assertEqual(inspector(restored), [])

    def test_live_closed_api(self) -> None:
        self.assertEqual(inspect_header(self.header), [])

    def test_live_constant_only_source_and_validation_before_publication(self) -> None:
        self.assertEqual(inspect_source(self.source), [])

    def test_api_rejects_supplied_return_values_callbacks_and_live_state(self) -> None:
        anchor = "uint32_t policy,"
        for extra in ("uint8_t return_value,", "uint8_t *return_global,",
                      "void (*emit)(void),", "void *host_context,",
                      "uint32_t frame_address,"):
            with self.subTest(extra=extra):
                self.reciprocal(inspect_header, self.header, anchor, anchor + extra)
        self.reciprocal(inspect_header, self.header,
                        "uint32_t return_source_identity;",
                        "uint8_t return_value; uint32_t return_source_identity;")

    def test_effect_and_recovered_call_mutants_rejected(self) -> None:
        anchor = "    uintptr_t address;"
        for effect in ("CoUninitialize();", "decomp_fn_100ee1d0();",
                       "rome2_port_100edd70_run_caller_closure();", "emit();",
                       "malloc(500);", "system(\"echo effect\");",
                       "__writefsdword(0, 1);", "__asm { nop }",
                       "*(volatile unsigned char *)0x119f3144 = 0;",
                       "result.policy = *(unsigned char *)0x119f3144;",
                       "((void (*)(void))0x1172f934)();"):
            with self.subTest(effect=effect):
                self.reciprocal(inspect_source, self.source, anchor,
                                anchor + "\n    " + effect)

    def test_projection_storage_and_dependency_mutants_rejected(self) -> None:
        for old, new in (
            (f"static const {T}step installed_tail", f"static {T}step installed_tail"),
            (f"static const {T}step common_epilogue", f"static volatile {T}step common_epilogue"),
            ("-4, UINT32_C(0xffffffff), 4U", "-4, read_global(), 4U"),
            ("memset(&result, 0, sizeof(result));", "memset(&result, 1, sizeof(result));"),
            ("memcpy(result.tail, installed_tail, sizeof(installed_tail));",
             "memcpy(installed_tail, result.tail, sizeof(installed_tail));"),
            ("#include <string.h>", "#include <string.h>\n#include <windows.h>"),
            ("#include <stddef.h>", "#include <stddef.h>\n#define memcpy host_copy"),
            ("uintptr_t address;", "uintptr_t address; static unsigned counter; ++counter;"),
        ):
            with self.subTest(new=new):
                self.reciprocal(inspect_source, self.source, old, new)
        self.assertTrue(inspect_source(self.source + "\nvoid extra(void) { CoUninitialize(); }"))

    def test_validation_and_publish_mutants_rejected(self) -> None:
        publish = "memcpy(result_out, &result, sizeof(result));"
        for old, new in (
            (f"policy != {P}POLICY_SKIP", f"policy == {P}POLICY_SKIP"),
            ("result_out == NULL", "result_out != NULL"),
            (f"address % _Alignof({T}transcript_result) != 0U", "0"),
            ("sizeof(*result_out) - 1U > UINTPTR_MAX - address", "0"),
            ("    uintptr_t address;", "    uintptr_t address;\n    " + publish),
            (publish, publish + "\n    result_out->policy = 9;"),
            (publish, "memcpy(result_out, &result, 1);"),
            (publish, "/* " + publish + " */"),
            ("result.policy = policy;", "result_out->policy = policy;"),
        ):
            with self.subTest(new=new):
                self.reciprocal(inspect_source, self.source, old, new)
        # Move (rather than duplicate) publication ahead of validation.
        moved = self.source.replace(publish, "").replace(
            "    uintptr_t address;", "    uintptr_t address;\n    " + publish)
        self.assertTrue(inspect_source(moved))

    def test_return_remains_identity_not_value(self) -> None:
        self.reciprocal(inspect_source, self.source,
                        P + "ID_AL, 0, 0U, 1U",
                        P + "ID_AL, 0, 7U, 1U")
        anchor = "result.return_source_identity = UINT32_C(0x119f3144);"
        for replacement in ("result.return_source_identity = 0;",
                            "result.return_source_identity = DAT_119f3144;",
                            "result.return_source_identity = supplied_return;"):
            self.reciprocal(inspect_source, self.source, anchor, replacement)

    def test_lexical_controls_ignore_comments_not_code_or_strings(self) -> None:
        for inspector, text in ((inspect_source, self.source), (inspect_header, self.header)):
            self.assertEqual(inspector("/* CoUninitialize(); DAT_119f3144 */\n" + text), [])
            self.assertEqual(inspector(text.replace("uint32_t policy", "uint32_t /* data */ policy")), [])
        self.reciprocal(inspect_header, self.header,
                        f"#define {P}POLICY_INSTALL UINT32_C(0)\n",
                        f"#define {P}POLICY_INSTALL UINT32_C(0) ")
        self.assertNotEqual(tokens("a && b"), tokens("a & & b"))
        self.assertEqual(tokens('"/* not comment */"'), ('"/* not comment */"',))
        for malformed in ("/* unterminated", '"unterminated', "x\\\ny", "??=define x 1"):
            self.assertTrue(inspect_source(malformed))
        self.reciprocal(inspect_source, self.source, "    uintptr_t address;",
                        '    uintptr_t address; const char *x = "/* harmless? */";')

    def test_live_cmake_and_production_exclude_candidate(self) -> None:
        self.assertEqual(inspect_cmake(self.cmake), [])
        paths = production_paths()
        self.assertGreater(len(paths), 40)  # empty/truncated discovery must fail
        self.assertIn(ROOT / "port/x64_headless/headless_main.c", paths)
        self.assertIn(ROOT / "port/x64_exports/export_manifest.tsv", paths)
        self.assertIn(ROOT / "port/x64_ported/ported_100edd70_entry_decision.c", paths)
        for path in UNBUILT_COMPOSITION_PATHS:
            with self.subTest(unbuilt_candidate=path.relative_to(ROOT)):
                self.assertTrue(path.is_file())
                self.assertNotIn(path, paths)
                self.assertIn("terminal_transcript", path.read_text(encoding="utf-8"))
                self.assertNotIn(path.name, self.cmake)
        for candidate in (
            "ported_100edd70_unified_entry",
            "ported_100edd70_full_entry",
        ):
            with self.subTest(unadmitted_candidate=candidate):
                self.assertTrue(
                    inspect_cmake(
                        self.cmake + f"\nadd_library(candidate {candidate}.c)\n"
                    )
                )
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertEqual(inspect_production(path.read_text(encoding="utf-8")), [])

    def test_production_and_cmake_integration_mutants_rejected(self) -> None:
        for addition in (f'\n#include "{STEM}.h"\n', f"\n{FUNCTION}(0, &r);\n",
                         f"\nEXPORTS\n{FUNCTION}\n"):
            self.reciprocal(inspect_production, "/* independent consumer */",
                            "/* independent consumer */", addition)
        for addition in (f'\nadd_library(candidate "port/x64_ported/{STEM}.c")\n',
                         '\nfile(GLOB sources "port/x64_ported/*.c")\n',
                         '\nfile(GLOB_RECURSE sources "port/*.c")\n'):
            self.assertTrue(inspect_cmake(self.cmake + addition))
            self.assertEqual(inspect_cmake((self.cmake + addition)[:-len(addition)]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
