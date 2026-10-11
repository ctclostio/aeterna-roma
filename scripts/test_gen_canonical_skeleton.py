#!/usr/bin/env python3
"""Focused tests for gen_canonical_skeleton.py."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import gen_canonical_skeleton as canonical


FINGERPRINT = "69d3666966b51e79fd21ce5f87e52b928ea92438b9eff55586e5c90adbdcc95c"
EXECUTABLE_SHA = "b" * 64


def write_tsv(path: Path, header: tuple[str, ...], rows: list[list[object]]) -> None:
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    path.write_text(output.getvalue(), encoding="utf-8", newline="")


def function_row(entry: str) -> list[object]:
    return [
        entry,
        f"decomp_fn_{entry}",
        f"FUN_{entry}",
        f"FUN_{entry}",
        str(int(entry, 16)),
        "0",
        "DEFAULT",
        f"undefined FUN_{entry}(void)",
        "16",
        "func",
        f"{entry}-{int(entry, 16) + 15:x}",
        "",
        "",
    ]


def data_row(address: str) -> list[object]:
    return [
        address,
        f"decomp_g_{address}",
        f"DAT_{address}",
        f"DAT_{address}",
        str(int(address, 16) + 100000),
        "0",
        "ANALYSIS",
        "Label",
        "/dword",
        "4",
        "4",
    ]


def canonical_source(entry: str, body: str = "  return;\n") -> str:
    name = f"decomp_fn_{entry}"
    return (
        "// fixture.dll\n"
        f"// Export format: {canonical.FORMAT_MARKER}\n"
        f"// Mapping fingerprint: {FINGERPRINT}\n"
        f"// Canonical function: {name}\n"
        f"// Original function: FUN_{entry}\n"
        f"// Entry: 0x{entry}  Size: 16\n"
        f"// Original signature: undefined FUN_{entry}(void)\n"
        "// Export result: success\n\n"
        f"void {name}(void)\n"
        "{\n"
        f"{body}"
        "}\n\n"
        f"// Canonical export EOF: success {name} {FINGERPRINT}\n"
    )


def make_fixture(
    root: Path, *, include_first: bool = True, include_second: bool = False
) -> Path:
    write_tsv(
        root / canonical.SNAPSHOT_FILE,
        canonical.SNAPSHOT_HEADER,
        [[canonical.FORMAT_MARKER, EXECUTABLE_SHA, FINGERPRINT, "2", "1"]],
    )
    write_tsv(
        root / canonical.FUNCTION_INDEX_FILE,
        canonical.FUNCTION_HEADER,
        [function_row("1000"), function_row("2000")],
    )
    write_tsv(
        root / canonical.DATA_INDEX_FILE,
        canonical.DATA_HEADER,
        [data_row("3000")],
    )
    decomp = root / canonical.DEFAULT_DECOMP_DIR
    decomp.mkdir()
    if include_first:
        (decomp / "decomp_fn_1000.c").write_text(
            canonical_source(
                "1000",
                "  /* decomp_fn_bad(decomp_g_bad); { } */\n"
                "  const char *text = \"decomp_fn_bad ) } decomp_g_bad\";\n"
                "  (void)text;\n"
                "  decomp_fn_2000(decomp_g_3000);\n",
            ),
            encoding="utf-8",
            newline="",
        )
    if include_second:
        (decomp / "decomp_fn_2000.c").write_text(
            canonical_source("2000"), encoding="utf-8", newline=""
        )
    return decomp


class DefinitionParserTests(unittest.TestCase):
    def test_balances_and_ignores_comments_and_literals(self) -> None:
        text = canonical_source(
            "1000",
            "  // decomp_fn_1000(fake) {\n"
            "  const char *value = \"}) decomp_g_dead\";\n"
            "  if (value[0]) { decomp_fn_2000(decomp_g_3000); }\n",
        )
        definition = canonical.parse_canonical_definition(text, "decomp_fn_1000")
        self.assertEqual(definition.declaration, "void decomp_fn_1000(void)")
        self.assertEqual(definition.function_refs, {"decomp_fn_2000": 1})
        self.assertEqual(definition.data_refs, {"decomp_g_3000": 1})
        isolated = text[definition.start_char : definition.end_char]
        self.assertTrue(isolated.endswith("}"))

    def test_rejects_wrong_definition_identity(self) -> None:
        with self.assertRaises(canonical.ValidationError):
            canonical.parse_canonical_definition(
                "void decomp_fn_2000(void) {}\n", "decomp_fn_1000"
            )

    def test_line_comment_splice_and_preprocessor_rejection(self) -> None:
        text = (
            "void decomp_fn_1000(void) {\n"
            "  // decomp_fn_dead \\\n"
            "  decomp_g_dead;\n"
            "  decomp_fn_2000();\n"
            "}\n"
        )
        definition = canonical.parse_canonical_definition(text, "decomp_fn_1000")
        self.assertEqual(definition.function_refs, {"decomp_fn_2000": 1})
        self.assertEqual(definition.data_refs, {})
        with self.assertRaisesRegex(canonical.ValidationError, "preprocessor"):
            canonical.parse_canonical_definition(
                "#define X 1\nvoid decomp_fn_1000(void) {}\n",
                "decomp_fn_1000",
            )


class CorpusTests(unittest.TestCase):
    def test_partial_inventory_and_reference_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_fixture(root)
            corpus = canonical.load_corpus(root)
            inventory = canonical.validate_corpus(corpus, jobs=2)
            self.assertEqual(inventory.counts["success"], 1)
            self.assertEqual(inventory.counts["missing"], 1)
            self.assertFalse(inventory.is_complete)
            with self.assertRaises(canonical.ValidationError):
                canonical.enforce_completeness(inventory)
            policy = canonical.ValidationPolicy(allow_missing=True)
            canonical.enforce_completeness(inventory, policy)
            refs = canonical.references_bytes(inventory).decode("utf-8")
            self.assertIn("decomp_fn_2000", refs)
            self.assertIn("decomp_g_3000", refs)

            with tempfile.TemporaryDirectory() as report_parent:
                report = canonical.emit_validation_report(
                    inventory, Path(report_parent) / "report", policy
                )
                self.assertTrue((report / "joined_manifest.tsv").is_file())
                report_summary = json.loads(
                    (report / "validation_summary.json").read_text(encoding="utf-8")
                )
                self.assertTrue(report_summary["validation_policy"]["allow_missing"])
                self.assertFalse(report_summary["complete"])

    def test_stale_and_unexpected_never_stage_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decomp = make_fixture(root)
            source = decomp / "decomp_fn_1000.c"
            source.write_text(
                source.read_text(encoding="utf-8").replace(FINGERPRINT, "c" * 64),
                encoding="utf-8",
                newline="",
            )
            (decomp / "legacy_name.c").write_text("void legacy(void) {}\n", encoding="utf-8")
            inventory = canonical.validate_corpus(canonical.load_corpus(root))
            self.assertEqual(inventory.counts["stale"], 1)
            self.assertEqual(inventory.counts["missing"], 1)
            self.assertEqual(inventory.counts["unexpected"], 1)
            self.assertEqual(inventory.successes, [])
            with self.assertRaisesRegex(canonical.ValidationError, "--allow-stale"):
                canonical.enforce_completeness(
                    inventory, canonical.ValidationPolicy(allow_missing=True)
                )
            canonical.enforce_completeness(
                inventory,
                canonical.ValidationPolicy(
                    allow_missing=True, allow_stale=True, allow_unexpected=True
                ),
            )

    def test_unindexed_canonical_reference_is_invalid_but_reportable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decomp = make_fixture(root)
            source = decomp / "decomp_fn_1000.c"
            source.write_text(
                canonical_source("1000", "  decomp_fn_dead(decomp_g_dead);\n"),
                encoding="utf-8",
                newline="",
            )
            inventory = canonical.validate_corpus(canonical.load_corpus(root))
            first = inventory.sources[0]
            self.assertEqual(first.status, "invalid")
            self.assertIn("unindexed function refs", first.diagnostic)
            self.assertIn("unindexed data refs", first.diagnostic)
            refs = canonical.references_bytes(inventory).decode("utf-8")
            self.assertIn("decomp_fn_dead\tno\t\tunindexed", refs)
            self.assertIn("decomp_g_dead\tno\t\tunindexed", refs)

    def test_duplicate_success_eof_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decomp = make_fixture(root)
            source = decomp / "decomp_fn_1000.c"
            eof = f"// Canonical export EOF: success decomp_fn_1000 {FINGERPRINT}"
            source.write_text(
                source.read_text(encoding="utf-8").replace(eof, eof + "\n" + eof),
                encoding="utf-8",
                newline="",
            )
            inventory = canonical.validate_corpus(canonical.load_corpus(root))
            self.assertEqual(inventory.sources[0].status, "invalid")
            self.assertIn("one exact final success EOF", inventory.sources[0].diagnostic)

    def test_missing_decompilation_directory_is_structural_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decomp = make_fixture(root, include_first=False)
            decomp.rmdir()
            with self.assertRaisesRegex(canonical.ValidationError, "does not exist"):
                canonical.validate_corpus(canonical.load_corpus(root))

    def test_atomic_stage_is_immutable_and_contains_only_successes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "input"
            root.mkdir()
            make_fixture(root, include_second=True)
            inventory = canonical.validate_corpus(canonical.load_corpus(root))
            output = base / "output"
            destination = canonical.emit_stage(inventory, output)
            self.assertTrue((destination / "sources" / "decomp_fn_1000.c").is_file())
            self.assertTrue((destination / "sources" / "decomp_fn_2000.c").is_file())
            self.assertTrue((destination / "joined_manifest.tsv").is_file())
            manifest_rows = list(
                csv.reader(
                    io.StringIO(
                        (destination / "joined_manifest.tsv").read_text(encoding="utf-8")
                    ),
                    delimiter="\t",
                )
            )
            self.assertEqual(len(manifest_rows), 4)  # header + two functions + data
            self.assertTrue(all(len(row) == len(canonical.MANIFEST_HEADER) for row in manifest_rows))
            summary = json.loads(
                (destination / "validation_summary.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary["allow_partial"])
            self.assertEqual(
                set(summary["metadata_sha256"]),
                {
                    canonical.SNAPSHOT_FILE,
                    canonical.FUNCTION_INDEX_FILE,
                    canonical.DATA_INDEX_FILE,
                },
            )
            with self.assertRaises(canonical.ValidationError):
                canonical.emit_stage(inventory, output)

    def test_partial_inventory_cannot_publish_fingerprint_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "input"
            root.mkdir()
            make_fixture(root)
            inventory = canonical.validate_corpus(canonical.load_corpus(root))
            with self.assertRaises(canonical.ValidationError):
                canonical.emit_stage(inventory, base / "output")

    def test_schema_count_mismatch_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_fixture(root)
            snapshot = root / canonical.SNAPSHOT_FILE
            snapshot.write_text(
                snapshot.read_text(encoding="utf-8").replace("\t2\t1\n", "\t3\t1\n"),
                encoding="utf-8",
                newline="",
            )
            with self.assertRaises(canonical.ValidationError):
                canonical.load_corpus(root)

    def test_snapshot_fingerprint_must_bind_both_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_fixture(root)
            function_index = root / canonical.FUNCTION_INDEX_FILE
            function_index.write_text(
                function_index.read_text(encoding="utf-8").replace(
                    "undefined FUN_1000(void)", "int FUN_1000(void)"
                ),
                encoding="utf-8",
                newline="",
            )
            with self.assertRaisesRegex(
                canonical.ValidationError, "mapping_fingerprint does not bind"
            ):
                canonical.load_corpus(root)


if __name__ == "__main__":
    unittest.main()
