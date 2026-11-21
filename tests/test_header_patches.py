import support  # noqa: F401  (isolates config, cache and state)
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zkit import build

HEADER = "#pragma once\nvoid f() {\n    while (a != b)\n        --b;\n}\n"
EDITED = HEADER.replace("while (a != b)", "while (b != a)")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule(text: str = HEADER, edits=None, patched: str | None = None, file: str = "vector") -> dict:
    edits = edits if edits is not None else [{"old": "    while (a != b)\n", "new": "    while (b != a)\n"}]
    return {"file": file, "patches": [{"sha256": sha(text), "patched_sha256": sha(patched or EDITED),
                                       "edits": edits}]}


def tree(temp: str, header: str = HEADER) -> Path:
    root = Path(temp)
    (root / "lib" / "include").mkdir(parents=True)
    (root / "lib" / "include" / "vector").write_bytes(header.encode("utf-8"))
    (root / "include").mkdir()
    (root / "clang++").write_bytes(b"clang")
    return root


def config(root: Path, rules: list[str]) -> dict:
    return {**build.settings({"platform": "switch", "build": {"compiler": str(root / "clang++")}}),
            "includes": ["lib/include", "include", "src"], "header_patches": rules, "extra_cflags": []}


class HeaderPatchesTest(unittest.TestCase):
    def test_units_read_the_edited_copy_first_and_every_other_header_as_before(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(build, "header_patches", return_value=rule()):
            root = tree(temp)
            found, notes = {}, []
            with mock.patch.object(build, "patched_headers", wraps=build.patched_headers) as patched:
                for unit in ("a.cpp", "b.cpp"):
                    step = build._compile(root, config(root, ["end-first"]), unit, build.Layout("build/t"), found,
                                          notes)
            patched.assert_called_once()  # once per build, not per unit
            self.assertEqual(notes, [])
            folder = "build/tools/header-patches/end_first"
            includes = [flag for flag in step["flags"] if flag.startswith("-I")]
            self.assertEqual(includes, [f"-I{folder}", "-Ilib/include", "-Iinclude", "-Isrc"])
            self.assertIn(f"-I{folder}", step["argv"])  # compile_commands.json and `zkit try` read it too
            self.assertEqual((root / folder / "vector").read_text(), EDITED)
            self.assertEqual((root / "lib" / "include" / "vector").read_text(), HEADER)  # the release's is kept

    def test_a_unit_without_the_rule_keeps_its_includes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = tree(temp)
            step = build._compile(root, config(root, []), "a.cpp", build.Layout("build/t"), {}, [])
            self.assertEqual([flag for flag in step["flags"] if flag.startswith("-I")],
                             ["-Ilib/include", "-Iinclude", "-Isrc"])
            self.assertFalse((root / "build").exists())

    def test_another_copy_of_the_header_builds_unedited_and_says_so_once(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(build, "header_patches", return_value=rule(text="another release\n")):
            root = tree(temp)
            found, notes = {}, []
            for unit in ("a.cpp", "b.cpp"):
                step = build._compile(root, config(root, ["end-first"]), unit, build.Layout("build/t"), found, notes)
            self.assertEqual(len(notes), 1)
            self.assertIn("zkit has no patch for lib/include/vector", notes[0])
            self.assertIn(sha(HEADER), notes[0])
            self.assertIn("build.header_patches (end-first)", notes[0])
            self.assertEqual([flag for flag in step["flags"] if flag.startswith("-I")],
                             ["-Ilib/include", "-Iinclude", "-Isrc"])

    def test_a_header_in_none_of_the_includes_is_said(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(build, "header_patches", return_value=rule(file="list")):
            root = tree(temp)
            folder, notes = build.patched_headers(root, ["lib/include", "include"], ["end-first"])
            self.assertIsNone(folder)
            self.assertIn("header list is in none of the includes", notes[0])

    def test_the_first_include_that_has_the_header_is_the_one_edited(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(build, "header_patches", return_value=rule()):
            root = tree(temp)
            (root / "include" / "vector").write_text("ours\n")
            folder, notes = build.patched_headers(root, ["lib/include", "include"], ["end-first"])
            self.assertEqual((folder / "vector").read_text(), EDITED)
            self.assertEqual(notes, [])

    def test_rules_on_one_header_apply_in_turn(self):
        second = {"file": "vector", "patches": [{"sha256": sha(EDITED), "patched_sha256": sha(EDITED + "// two\n"),
                                                 "edits": [{"old": "}\n", "new": "}\n// two\n"}]}]}
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(build, "header_patches", side_effect=[rule(), second]):
            root = tree(temp)
            folder, notes = build.patched_headers(root, ["lib/include"], ["one", "two"])
            self.assertEqual(folder.name, "one+two")
            self.assertEqual((folder / "vector").read_text(), EDITED + "// two\n")

    def test_the_edits_and_the_result_are_checked(self):
        cases = [("missing", rule(edits=[{"old": "while (c != d)", "new": "x"}]), "exactly once"),
                 ("twice", rule(edits=[{"old": "    ", "new": "  "}]), "exactly once"),
                 ("result", rule(patched="something else"), "gave SHA-256"),
                 ("include_next", rule(edits=[{"old": "#pragma once\n", "new": "#include_next <vector>\n"}],
                                       patched=HEADER.replace("#pragma once\n", "#include_next <vector>\n")),
                  "include_next")]
        for name, table, message in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as temp, \
                    mock.patch.object(build, "header_patches", return_value=table):
                root = tree(temp)
                with self.assertRaisesRegex(ValueError, f"build.header_patches: .*{message}"):
                    build.patched_headers(root, ["lib/include"], ["end-first"])

    def test_a_changed_copy_is_written_again(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(build, "header_patches", return_value=rule()):
            root = tree(temp)
            folder, _ = build.patched_headers(root, ["lib/include"], ["end-first"])
            (folder / "vector").write_text("changed\n")
            build.patched_headers(root, ["lib/include"], ["end-first"])
            self.assertEqual((folder / "vector").read_text(), EDITED)

    def test_zkits_rules_are_well_formed(self):
        with self.assertRaisesRegex(ValueError, "no rule 'nothing' .*vector-destruct-end-first"):
            build.header_patches("nothing")
        for path in sorted(build.HEADER_PATCHES.glob("*.json")):
            table = build.header_patches(path.stem.replace("_", "-"))
            with self.subTest(path.name):
                self.assertTrue(table["about"] and table["file"] and table["patches"])
                for patch in table["patches"]:
                    self.assertRegex(patch["sha256"], "^[0-9a-f]{64}$")
                    self.assertRegex(patch["patched_sha256"], "^[0-9a-f]{64}$")
                    self.assertTrue(patch["release"])
                    for edit in patch["edits"]:
                        self.assertNotEqual(edit["old"], edit["new"])

    def test_the_rule_is_a_unit_setting(self):
        self.assertIn("header_patches", build.UNIT_KEYS)


if __name__ == "__main__":
    unittest.main()
