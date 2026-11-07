#!/usr/bin/env python3
"""Focused tests for filter_opaque.py and the generated src/include/opaque_types.h.

Pure tests need only the standard library. MSVC tests capture the vcvars64
environment once per process and skip with a reason if the toolchain is
absent. They compile small TUs in a temporary directory and never touch the
game sources.
"""

from __future__ import annotations

import contextlib
import io
import random
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import filter_opaque as fo

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKED_IN_HEADER = REPO_ROOT / "src" / "include" / "opaque_types.h"

FORWARD_DECL_RE = re.compile(r"typedef struct opaque_(?P<name>[A-Za-z_][A-Za-z0-9_]*) (?P=name);")

LEGACY_HEADER = (
    "#pragma once\n"
    "/* Auto-generated opaque fwd decls (system-collision filtered).\n"
    "   Sized dummy bodies so BY-VALUE struct use compiles; real layouts come from RTTI recovery later. */\n"
    "typedef struct { unsigned char _pad_[64]; } FxActor;\n"
    "typedef struct { unsigned char _pad_[64]; } _CONTEXT;\n"
    "typedef struct { unsigned char _pad_[64]; } word;\n"
)

INVALID_NAMES = [
    "", " ", "1abc", "a b", "a-b", "a;b", "a\n", "\na", "a\x00", "a\t",
    "x; } evil; typedef struct { int a", "Foo*", "T[64]", "struct Foo", "*/", "a/*",
    "café",    # Python str.isidentifier() accepts this; C identifiers here must be ASCII
    "٣",       # Arabic-Indic digit: str.isalnum() is True (the legacy check passed it)
    "Ｆoo",     # fullwidth letter
    "a​",      # zero-width space
]
RESERVED_NAMES = ["int", "struct", "typedef", "_Bool", "bool", "typeof", "__int64",
                  "__cdecl", "_Pragma", "class", "wchar_t", "template"]


def declaration_lines(header_text: str) -> list[str]:
    body = fo._COMMENT_RE.sub("", header_text)
    return [line for line in body.splitlines() if line.strip() and line.strip() != "#pragma once"]


class ForwardDeclarationAssertions(unittest.TestCase):
    def assert_forward_declarations_only(self, header_text: str) -> list[str]:
        """Every non-comment line is `#pragma once` or `typedef struct opaque_N N;`."""
        self.assertTrue(header_text.startswith("#pragma once\n"))
        self.assertNotIn("_pad_", header_text)
        body = fo._COMMENT_RE.sub("", header_text)
        for ch in "{}[]":
            self.assertNotIn(ch, body, f"storage/body syntax {ch!r} outside comments")
        names = []
        for line in declaration_lines(header_text):
            m = FORWARD_DECL_RE.fullmatch(line)
            self.assertIsNotNone(m, f"not an incomplete forward declaration: {line!r}")
            names.append(m.group("name"))
        self.assertEqual(names, sorted(set(names)), "declarations must be sorted and unique")
        return names


class RenderTests(ForwardDeclarationAssertions):
    def test_emits_sorted_deduplicated_forward_declarations(self) -> None:
        text = fo.render_opaque_header(["b", "B", "_a", "b", "a", "B"])
        self.assertEqual(declaration_lines(text), [
            "typedef struct opaque_B B;",
            "typedef struct opaque__a _a;",
            "typedef struct opaque_a a;",
            "typedef struct opaque_b b;",
        ])

    def test_output_is_independent_of_input_order_and_container(self) -> None:
        names = [f"Fx{i}" for i in range(25)] + ["_CONTEXT", "HINSTANCE__", "word", "undefined"]
        expected = fo.render_opaque_header(names)
        rng = random.Random(20261103)
        for _ in range(10):
            shuffled = names * 2
            rng.shuffle(shuffled)
            self.assertEqual(fo.render_opaque_header(shuffled), expected)
        self.assertEqual(fo.render_opaque_header(set(names)), expected)
        self.assertEqual(fo.render_opaque_header(n for n in reversed(names)), expected)

    def test_no_invented_storage(self) -> None:
        names = ["FxActor", "_CONTEXT", "_iobuf", "HINSTANCE__", "uint3", "unkbyte10"]
        text = fo.render_opaque_header(names)
        self.assertEqual(self.assert_forward_declarations_only(text), sorted(names))
        self.assertNotRegex(text, r"\bunsigned char\b")

    def test_tag_namespace_never_reuses_the_type_name(self) -> None:
        # Bare `struct _CONTEXT` is a complete host x64 struct in windows.h.
        for name in ("_CONTEXT", "_LIST_ENTRY", "hostent", "FxActor"):
            self.assertEqual(fo.opaque_tag(name), "opaque_" + name)
            self.assertNotEqual(fo.opaque_tag(name), name)

    def test_empty_name_set_renders_preamble_only(self) -> None:
        text = fo.render_opaque_header([])
        self.assertEqual(declaration_lines(text), [])
        self.assertEqual(fo.parse_opaque_header(text), [])

    def test_preamble_documents_pointer_only_contract(self) -> None:
        text = fo.render_opaque_header(["FxActor"])
        self.assertEqual(text.count("/*"), 1)
        self.assertEqual(text.count("*/"), 1)
        for phrase in ("incomplete struct", "pointers", "sizeof", "field access", "by-value",
                       "recovered", "evidence-backed layout", "opaque_"):
            self.assertIn(phrase, text)
        self.assertTrue(text.isascii())


class IdentifierValidationTests(unittest.TestCase):
    def test_accepts_plain_ascii_c_identifiers(self) -> None:
        for name in ("a", "_", "A1", "_CONTEXT", "HINSTANCE__", "__acrt_ptd", "opaque_x", "x" * 300):
            with self.subTest(name=name):
                self.assertEqual(fo.validate_identifier(name), name)

    def test_rejects_malformed_and_injection_names(self) -> None:
        for name in INVALID_NAMES:
            with self.subTest(name=name):
                with self.assertRaises(fo.InvalidIdentifierError):
                    fo.validate_identifier(name)
                with self.assertRaises(ValueError):
                    fo.render_opaque_header(["Valid", name])

    def test_rejects_reserved_keywords(self) -> None:
        for name in RESERVED_NAMES:
            with self.subTest(name=name):
                with self.assertRaisesRegex(fo.InvalidIdentifierError, "reserved"):
                    fo.render_opaque_header([name])

    def test_rejects_non_strings(self) -> None:
        for value in (None, b"abc", 5, ["a"]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    fo.render_opaque_header([value])  # type: ignore[list-item]

    def test_candidate_classification_separates_invalid_and_reserved(self) -> None:
        cands = fo.parse_candidates(
            "# comment\n/* c */\n\nstruct Foo;\nBar\n__int64\nx}y\nFoo\ncafé\n")
        self.assertEqual(cands, ["Foo", "Bar", "__int64", "x}y", "Foo", "café"])
        valid, reserved, invalid = fo.classify_candidates(cands)
        self.assertEqual(valid, ["Bar", "Foo"])
        self.assertEqual(reserved, ["__int64"])
        self.assertEqual(invalid, ["café", "x}y"])


class ParseHeaderTests(ForwardDeclarationAssertions):
    def test_reads_legacy_placeholder_header(self) -> None:
        self.assertEqual(fo.parse_opaque_header(LEGACY_HEADER), ["FxActor", "_CONTEXT", "word"])

    def test_accepts_every_form_previously_emitted(self) -> None:
        text = ("#pragma once\n"
                "typedef struct { unsigned char _pad_[16]; } Legacy;\n"
                "typedef struct Pruned Pruned;\n"          # form appended by prune_opaque.py
                "typedef struct opaque_Current Current;\n"
                "typedef struct opaque_Current Current;\n")
        self.assertEqual(fo.parse_opaque_header(text), ["Current", "Legacy", "Pruned"])

    def test_rerender_of_legacy_header_removes_all_bodies(self) -> None:
        out = fo.rerender_header(LEGACY_HEADER)
        self.assertEqual(self.assert_forward_declarations_only(out), ["FxActor", "_CONTEXT", "word"])
        self.assertEqual(fo.rerender_header(out), out, "re-rendering must be a fixed point")

    def test_comment_text_is_not_parsed_as_declarations(self) -> None:
        text = ("#pragma once\n/* typedef struct opaque_Ghost Ghost;\n"
                "   typedef struct { unsigned char _pad_[64]; } Ghost2; */\n"
                "typedef struct opaque_Real Real;\n")
        self.assertEqual(fo.parse_opaque_header(text), ["Real"])

    def test_rejects_unrecognized_or_inconsistent_content(self) -> None:
        bad_lines = [
            "typedef struct { int a; } Foo;",                    # a real body: never dropped silently
            "struct Foo { int a; };",
            "#define Foo int",
            "typedef struct opaque_A B;",                        # tag does not match name
            "typedef struct { unsigned char _pad_[64]; } a-b;",
            "typedef struct { unsigned char _pad_[64]; } int;",  # reserved keyword
            "// typedef struct opaque_X X;",
            "*/",
        ]
        for line in bad_lines:
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    fo.parse_opaque_header("#pragma once\ntypedef struct opaque_Ok Ok;\n" + line + "\n")

    def test_error_reports_line_number(self) -> None:
        with self.assertRaisesRegex(ValueError, r"line 3\b"):
            fo.parse_opaque_header("#pragma once\n/* a\n*/ junk\n")

    def test_rejects_unterminated_comment(self) -> None:
        with self.assertRaisesRegex(ValueError, "unterminated"):
            fo.parse_opaque_header("#pragma once\n/* never closed\ntypedef struct opaque_A A;\n")


class ProbeWorkflowTests(ForwardDeclarationAssertions):
    def test_only_undefined_names_are_declared_and_each_name_probed_once(self) -> None:
        calls: list[str] = []
        system_types = {"DWORD", "HANDLE"}

        def is_defined(name: str) -> bool:
            calls.append(name)
            return name in system_types

        valid, _, _ = fo.classify_candidates(["FxActor", "DWORD", "_CONTEXT", "HANDLE", "FxActor"])
        for workers in (1, 4):
            calls.clear()
            undefined, defined = fo.filter_undefined(valid, is_defined, workers=workers)
            self.assertEqual(sorted(calls), ["DWORD", "FxActor", "HANDLE", "_CONTEXT"])
            self.assertEqual(undefined, ["FxActor", "_CONTEXT"])
            self.assertEqual(defined, ["DWORD", "HANDLE"])
            self.assertEqual(self.assert_forward_declarations_only(fo.render_opaque_header(undefined)),
                             ["FxActor", "_CONTEXT"])

    def test_invalid_name_is_rejected_before_any_probe(self) -> None:
        calls: list[str] = []
        with self.assertRaises(ValueError):
            fo.filter_undefined(["FxActor", "x}y"], lambda n: calls.append(n) or False)
        self.assertEqual(calls, [])


class CommandLineTests(ForwardDeclarationAssertions):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="test_filter_opaque_")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_main(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = fo.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_rerender_to_output_preserves_names_and_writes_lf(self) -> None:
        legacy = self.tmp / "legacy.h"
        legacy.write_text(LEGACY_HEADER, newline="\n")
        dest = self.tmp / "new.h"
        rc, _, _ = self.run_main("--rerender", str(legacy), "--output", str(dest))
        self.assertEqual(rc, 0)
        self.assertEqual(legacy.read_text(), LEGACY_HEADER, "source must not change with --output")
        self.assertNotIn(b"\r", dest.read_bytes())
        self.assertEqual(self.assert_forward_declarations_only(dest.read_text()),
                         fo.parse_opaque_header(LEGACY_HEADER))

    def test_rerender_in_place_then_check(self) -> None:
        header = self.tmp / "opaque_types.h"
        header.write_text(LEGACY_HEADER, newline="\n")
        self.assertEqual(self.run_main("--rerender", str(header), "--check")[0], 1)
        self.assertEqual(header.read_text(), LEGACY_HEADER, "--check must not write")
        self.assertEqual(self.run_main("--rerender", str(header))[0], 0)
        self.assertEqual(self.run_main("--rerender", str(header), "--check")[0], 0)

    def test_check_accepts_crlf_checkout(self) -> None:
        # core.autocrlf=true checks the header out with CRLF line endings.
        header = self.tmp / "opaque_types.h"
        header.write_bytes(fo.render_opaque_header(["FxActor"]).replace("\n", "\r\n").encode("ascii"))
        self.assertEqual(self.run_main("--rerender", str(header), "--check")[0], 0)

    def test_rerender_refuses_unrecognized_header_without_writing(self) -> None:
        header = self.tmp / "opaque_types.h"
        original = "#pragma once\ntypedef struct { int a; } Recovered;\n"
        header.write_text(original, newline="\n")
        rc, _, err = self.run_main("--rerender", str(header))
        self.assertEqual(rc, 2)
        self.assertIn("unrecognized content", err)
        self.assertEqual(header.read_text(), original)

    def test_probe_mode_rejects_invalid_candidates_before_compiling(self) -> None:
        cands = self.tmp / "candidates.txt"
        cands.write_text("FxActor\nx} evil; typedef struct {\n", encoding="utf-8")
        dest = self.tmp / "out.h"
        rc, _, err = self.run_main(str(cands), str(dest))
        self.assertEqual(rc, 2)
        self.assertIn("rejected", err)
        self.assertFalse(dest.exists())

    def test_argument_combinations(self) -> None:
        for argv in (["--check"], ["--rerender", "a.h", "--check", "--output", "b.h"],
                     ["--rerender", "a.h", "cands.txt"], ["only_one_positional.txt"]):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                    fo.main(argv)
                self.assertEqual(cm.exception.code, 2)


class CheckedInHeaderTests(ForwardDeclarationAssertions):
    def test_checked_in_header_is_canonical_forward_declarations(self) -> None:
        text = CHECKED_IN_HEADER.read_text(encoding="ascii")
        names = self.assert_forward_declarations_only(text)
        self.assertGreater(len(names), 0)
        self.assertEqual(fo.rerender_header(text), text,
                         "stale: run python scripts/filter_opaque.py --rerender src/include/opaque_types.h")


# ---------------------------------------------------------------------------
# MSVC compile tests
# ---------------------------------------------------------------------------

_MSVC_CACHE: tuple[dict[str, str], str] | str | None = None


def msvc_toolchain() -> tuple[dict[str, str], str]:
    """Run vcvars64 at most once per process. Raise SkipTest if unavailable."""
    global _MSVC_CACHE
    if _MSVC_CACHE is None:
        if not Path(fo.VCVARS).is_file():
            _MSVC_CACHE = f"MSVC vcvars64.bat not found at {fo.VCVARS}"
        else:
            try:
                env = fo.msvc_env()
                _MSVC_CACHE = (env, fo.find_cl(env))
            except (OSError, subprocess.CalledProcessError) as e:
                _MSVC_CACHE = f"MSVC environment unavailable: {e}"
    if isinstance(_MSVC_CACHE, str):
        raise unittest.SkipTest(_MSVC_CACHE)
    return _MSVC_CACHE


MARK = "/* EXPECT */"


class MsvcCompileCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.env, cls.cl = msvc_toolchain()
        cls._tmp = tempfile.TemporaryDirectory(prefix="test_filter_opaque_msvc_")
        cls.tmp = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def compile_c(self, label: str, header_text: str, body: str) -> tuple[int, str, set[tuple[int, str]]]:
        """Compile PROBE_PRELUDE + opaque header + body as C with /W4 /WX.

        Returns (rc, output, {(line, error_code)}) for diagnostics in the TU itself."""
        d = self.tmp / label
        d.mkdir()
        (d / "opaque_types.h").write_text(header_text, encoding="ascii", newline="\n")
        src = d / f"{label}.c"
        src.write_text(fo.PROBE_PRELUDE + '#include "opaque_types.h"\n' + body,
                       encoding="ascii", newline="\n")
        r = subprocess.run([self.cl, "/nologo", "/c", "/TC", "/W4", "/WX", "/diagnostics:classic",
                            src.name, f"/Fo{label}.obj"],
                           cwd=d, env=self.env, capture_output=True, text=True, errors="replace")
        output = r.stdout + r.stderr
        diag_re = re.compile(rf"^(?:.*[\\/])?{re.escape(src.name)}\((\d+)(?:,\d+)?\)\s*:\s*"
                             r"(?:fatal\s+)?error\s+(C\d{4})", re.M | re.I)
        errors = {(int(m.group(1)), m.group(2)) for m in diag_re.finditer(output)}
        return r.returncode, output, errors

    @staticmethod
    def marked_line(body: str) -> int:
        """Line number of the MARK-ed line within the compiled TU."""
        prefix_lines = (fo.PROBE_PRELUDE + '#include "opaque_types.h"\n').count("\n")
        lines = body.splitlines()
        hits = [i for i, line in enumerate(lines) if MARK in line]
        assert len(hits) == 1, body
        return prefix_lines + hits[0] + 1


FIXTURE_NAMES = ["FxActor", "_CONTEXT"]

POINTER_USES = """\
extern FxActor g_extern_actor;
FxActor *g_actor;
_CONTEXT *g_context;
typedef struct { FxActor *actor; _CONTEXT *context; } Holder;
void take(FxActor *p);
void proto_by_value(FxActor a);
FxActor proto_returns_by_value(void);
FxActor *pass_through(FxActor *p) { take(p); return p; }
int same(const FxActor *a, const FxActor *b) { return a == b; }
FxActor *address_of_extern(void) { return &g_extern_actor; }
void *erase(_CONTEXT *c) { return (void *)c; }
Holder *holder_of(Holder *h) { return h; }
"""

# (label, body with one MARK-ed line, expected MSVC error code on that line)
REJECTED_USES = [
    ("sizeof", "unsigned long long f(void) { return sizeof(FxActor); } " + MARK + "\n", "C2027"),
    ("local_object", "void f(void) { FxActor a; (void)&a; } " + MARK + "\n", "C2079"),
    ("file_scope_object", "FxActor g_actor_storage; " + MARK + "\n", "C2079"),
    ("static_object", "static FxActor s_actor; " + MARK + "\nvoid *f(void) { return &s_actor; }\n", "C2079"),
    ("array", "FxActor g_actors[2]; " + MARK + "\n", "C2079"),
    ("field_access", "void f(FxActor *p) { p->field = 0; } " + MARK + "\n", "C2037"),
    ("pointer_arithmetic", "FxActor *f(FxActor *p) { return p + 1; } " + MARK + "\n", "C2036"),
    ("by_value_parameter_definition", "void f(FxActor a) { (void)&a; } " + MARK + "\n", "C2027"),
    ("by_value_return_definition", "FxActor f(FxActor *p) { return *p; } " + MARK + "\n", "C2079"),
    # windows.h defines a complete host x64 `struct _CONTEXT`. The opaque
    # typedef must stay incomplete and must not alias that layout.
    ("host_tag_not_captured", "unsigned long long f(void) { return sizeof(_CONTEXT); } " + MARK + "\n",
     "C2027"),
]


class MsvcSemanticsTests(MsvcCompileCase):
    def test_pointer_uses_compile_cleanly_at_w4_wx(self) -> None:
        rc, output, _ = self.compile_c("pointer_uses", fo.render_opaque_header(FIXTURE_NAMES), POINTER_USES)
        self.assertEqual(rc, 0, output)

    def test_layout_dependent_uses_are_rejected(self) -> None:
        header = fo.render_opaque_header(FIXTURE_NAMES)
        for label, body, code in REJECTED_USES:
            with self.subTest(use=label):
                rc, output, errors = self.compile_c(label, header, body)
                self.assertNotEqual(rc, 0, f"{label} compiled but must be rejected\n{output}")
                self.assertIn((self.marked_line(body), code), errors, output)

    def test_host_struct_tag_is_left_untouched(self) -> None:
        # Shows the host tag exists and is complete, so the rejection in
        # host_tag_not_captured really comes from the opaque tag.
        rc, output, _ = self.compile_c(
            "host_tag_untouched", fo.render_opaque_header(FIXTURE_NAMES),
            "unsigned long long f(void) { return sizeof(struct _CONTEXT); }\n"
            "_CONTEXT *g(CONTEXT *host) { (void)host; return 0; }\n")
        self.assertEqual(rc, 0, output)

    def test_legacy_placeholder_silently_accepted_by_value_use(self) -> None:
        # Regression baseline: the old 64-byte body let sizeof compile with an
        # invented size. Re-rendering the same names must reject it.
        body = "unsigned long long f(void) { return sizeof(FxActor); } " + MARK + "\n"
        rc, output, _ = self.compile_c("legacy_sizeof", LEGACY_HEADER, body)
        self.assertEqual(rc, 0, output)
        rc, output, errors = self.compile_c("rerendered_sizeof", fo.rerender_header(LEGACY_HEADER), body)
        self.assertIn((self.marked_line(body), "C2027"), errors, output)

    def test_real_msvc_prober_drops_system_types_only(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.tmp) as workdir:
            undefined, defined = fo.filter_undefined(
                ["DWORD", "HANDLE", "FxActor", "_iobuf", "_CONTEXT"],
                fo.make_msvc_prober(self.env, self.cl, Path(workdir)), workers=4)
            leftovers = list(Path(workdir).iterdir())
        self.assertEqual(defined, ["DWORD", "HANDLE"])
        # _iobuf and _CONTEXT are only struct tags in the system headers.
        self.assertEqual(undefined, ["FxActor", "_CONTEXT", "_iobuf"])
        self.assertEqual(leftovers, [], "probe files must be cleaned up")


class MsvcCheckedInHeaderTests(MsvcCompileCase):
    BATCH = 40  # stay well below MSVC's 100-error cap (C1003) per TU

    def setUp(self) -> None:
        self.header_text = CHECKED_IN_HEADER.read_text(encoding="ascii")
        self.names = fo.parse_opaque_header(self.header_text)
        self.assertGreater(len(self.names), 0)

    def test_every_name_is_usable_through_pointers(self) -> None:
        body = "".join(f"{n} *opaque_ptr_{i};\n" for i, n in enumerate(self.names))
        rc, output, _ = self.compile_c("checked_in_pointers", self.header_text, body)
        self.assertEqual(rc, 0, output)

    def test_every_name_is_incomplete(self) -> None:
        prefix_lines = (fo.PROBE_PRELUDE + '#include "opaque_types.h"\n').count("\n")
        for start in range(0, len(self.names), self.BATCH):
            batch = self.names[start:start + self.BATCH]
            body = "".join(f"unsigned long long opaque_size_{i}(void) {{ return sizeof({n}); }}\n"
                           for i, n in enumerate(batch))
            rc, output, errors = self.compile_c(f"checked_in_sizeof_{start}", self.header_text, body)
            self.assertNotEqual(rc, 0, output)
            complete = [n for i, n in enumerate(batch) if (prefix_lines + i + 1, "C2027") not in errors]
            self.assertEqual(complete, [], f"sizeof accepted for these names\n{output[-4000:]}")


if __name__ == "__main__":
    unittest.main()
