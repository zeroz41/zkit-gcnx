import support  # noqa: F401  (isolates config, cache and state)
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from zkit import hygiene, progress, quality
from zkit.project import Project

IDENTITY = "Dev Person <dev@example.org>"


def git(root: Path, *args: str, author: str = IDENTITY) -> str:
    name, email = author.split(" <")
    env = dict(os.environ, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email.rstrip(">"),
               GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email.rstrip(">"))
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True,
                          env=env).stdout


def report(functions: list[tuple[str, str, int, int, float]], data: list[tuple[str, str, int, int, float]],
           linked: set[str] = frozenset()) -> dict:
    """functions: (unit, name, address, size, match); data: (unit, section, address, size, match)."""
    units: dict[str, dict] = {}
    for unit, name, address, size, match in functions:
        u = units.setdefault(unit, {"name": unit, "functions": [], "sections": [],
                                    "metadata": {"module_name": "main", "complete": unit in linked}})
        u["functions"].append({"name": name, "size": str(size), "fuzzy_match_percent": match,
                               "metadata": {"virtual_address": str(address)}})
    for unit, section, address, size, match in data:
        u = units.setdefault(unit, {"name": unit, "functions": [], "sections": [],
                                    "metadata": {"module_name": "main", "complete": unit in linked}})
        u["sections"].append({"name": section, "size": str(size), "fuzzy_match_percent": match,
                              "metadata": {"virtual_address": str(address)}})
    exact = sum(size for _, _, _, size, match in functions if match == 100)
    return {"version": 2, "units": list(units.values()), "categories": [],
            "measures": {"total_code": str(sum(f[3] for f in functions)), "matched_code": str(exact),
                         "total_functions": len(functions),
                         "matched_functions": sum(1 for f in functions if f[4] == 100),
                         "total_data": str(sum(d[3] for d in data)),
                         "matched_data": str(sum(d[3] for d in data if d[4] == 100))}}


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.before = report([("main/a", "f", 0x80001000, 0x20, 100.0), ("main/a", "g", 0x80001020, 0x10, 90.0)],
                             [("main/a", ".data", 0x80100000, 0x40, 100.0)], linked={"main/a"})

    def test_rename_and_fold_are_not_losses(self):
        after = report([("main/b", "TClass::f", 0x80001000, 0x20, 100.0), ("main/b", "g", 0x80001020, 0x10, 95.0)],
                       [("main/b", ".data", 0x80100000, 0x20, 100.0), ("main/c", ".data", 0x80100020, 0x20, 100.0)],
                       linked={"main/b", "main/c"})
        delta = progress.compare(self.before, after)
        self.assertTrue(delta["ok"], delta["failures"])
        self.assertEqual([r["after"] for r in delta["renamed"]], ["TClass::f"])
        self.assertEqual([r["address"] for r in delta["improved"]], ["0x80001020"])

    def test_a_unit_renamed_into_another_folder_stays_in_its_module(self):
        """objdiff's report drops the module the project gives, so a unit renamed from `game/x` to `lib/y` would
        seem to move its functions to another module; in a target with one module it does not."""
        def bare(text_unit):
            out = report([(text_unit, "f", 0x80001000, 0x20, 0.0)], [(text_unit, ".data", 0x80100000, 0x40, 0.0)])
            for unit in out["units"]:
                unit["metadata"].pop("module_name")
            return out
        before, after = bare("game/x"), bare("lib/y")
        self.assertFalse(progress.compare(before, after)["ok"])           # by folder: a function disappeared
        self.assertTrue(progress.compare(before, after, "main")["ok"], progress.compare(before, after, "main"))

    def test_losses_are_named(self):
        after = copy.deepcopy(self.before)
        after["units"][0]["functions"][0]["fuzzy_match_percent"] = 99.0
        after["units"][0]["sections"][0]["fuzzy_match_percent"] = 50.0
        after["units"][0]["metadata"]["complete"] = False
        delta = progress.compare(self.before, after)
        self.assertFalse(delta["ok"])
        self.assertEqual([r["address"] for r in delta["regressed"]], ["0x80001000"])
        self.assertEqual(delta["exact_data_lost"][0]["size"], 0x40)
        self.assertEqual(len(delta["unlinked"]), 2)

    def test_a_section_in_pieces_is_read_from_its_recorded_ranges(self):
        """objdiff gives a unit's section one address (its first piece's) and the object's size (every piece plus
        the padding between them). Cutting a unit's later piece off into a new unit then seems to drop the data
        after its first piece and changes total_data by the padding; the ranges the link records show nothing
        moved out of the report."""
        pieces = {"main/g": {".rodata": [(0x1000, 0x1009), (0x3000, 0x3010)]},
                  "main/b": {".rodata": [(0x0800, 0x0810), (0x1010, 0x1020)]}}
        after_pieces = {"main/g": {".rodata": [(0x1000, 0x1009)]}, "main/n": {".rodata": [(0x3000, 0x3010)]},
                        "main/b": pieces["main/b"]}
        before = report([], [("main/g", ".rodata", 0x1000, 0x9 + 3 + 0x10, 0.0),
                             ("main/b", ".rodata", 0x0800, 0x20, 0.0)])
        after = report([], [("main/g", ".rodata", 0x1000, 0x9, 0.0), ("main/n", ".rodata", 0x3000, 0x10, 0.0),
                            ("main/b", ".rodata", 0x0800, 0x20, 0.0)])
        delta = progress.compare(before, after)                       # objdiff's addresses alone: a false loss
        self.assertEqual(sum(r["size"] for r in delta["data_coverage_lost"]), 0x1C - 0x9)
        self.assertEqual(delta["metrics"]["total_data"]["delta"], -3)
        with tempfile.TemporaryDirectory() as tmp:
            for name, value, table in (("before", before, pieces), ("after", after, after_pieces)):
                path = Path(tmp) / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                self.assertTrue(progress.apply_link(path, [], {u.split("/", 1)[1]: t for u, t in table.items()}))
                if name == "before":
                    recorded_before = progress.load(path)
                    self.assertEqual(recorded_before["units"][0]["sections"][0]["metadata"]["ranges"],
                                     [[0x1000, 0x1009], [0x3000, 0x3010]])
                    self.assertFalse(progress.compare(recorded_before, after)["ok"])   # one side alone: as before
                else:
                    recorded_after = progress.load(path)
        delta = progress.compare(recorded_before, recorded_after)
        self.assertTrue(delta["ok"], delta["failures"])
        self.assertEqual(delta["metrics"]["original_data"]["delta"], 0)
        recorded_after["units"][2]["sections"][0]["metadata"]["ranges"] = [[0x0800, 0x0810]]   # b's piece dropped
        delta = progress.compare(recorded_before, recorded_after)
        self.assertEqual(delta["data_coverage_lost"], [{"module": "main", "section": ".rodata", "address": "0x00001010",
                                                        "size": 0x10}])
        self.assertIn("original_data changed by -16: the split or target changed; compare reports of the same "
                      "configuration", delta["failures"])

    def test_alignment_padding_moving_out_of_the_report_is_no_loss(self):
        """A split at an 8-aligned start leaves the zero word before it in no unit's object: it and total_data's
        change are padding, not lost data. A range a symbol starts in, or with a non-zero byte, is still a loss."""
        class Obj:
            def __init__(self, address):
                self.address = address

        class Original:
            objects, labels, functions = [Obj(0x80100000), Obj(0x80100008), Obj(0x80200000), Obj(0x80200008)], [], []

            def section_of(self, address):
                return ".data" if address < 0x80200000 else ".sbss2"

            def read(self, address, size):
                return bytes(size) if address != 0x80100030 else b"\\x01" * size

        padding = progress.alignment_padding(Original())
        before = report([], [("main/a", ".data", 0x80100000, 0x40, 100.0), ("main/b", ".sbss2", 0x80200000, 0x20, 0.0)],
                        linked={"main/a"})
        after = report([], [("main/a", ".data", 0x80100000, 0x4, 100.0), ("main/c", ".data", 0x80100008, 0x38, 100.0),
                            ("main/b", ".sbss2", 0x80200000, 0x4, 0.0), ("main/d", ".sbss2", 0x80200008, 0x18, 0.0)],
                       linked={"main/a", "main/c"})
        self.assertFalse(progress.compare(before, after)["ok"])           # without the original: a false loss
        delta = progress.compare(before, after, padding=padding)
        self.assertTrue(delta["ok"], delta["failures"])
        self.assertEqual([(r["address"], r["size"], r["moved"]) for r in delta["padding_moved"]],
                         [("0x80100004", 4, "left"), ("0x80200004", 4, "left")])
        named = report([], [("main/a", ".data", 0x80100000, 0x4, 100.0), ("main/c", ".data", 0x80100010, 0x30, 100.0),
                            ("main/b", ".sbss2", 0x80200000, 0x20, 0.0)], linked={"main/a", "main/c"})
        delta = progress.compare(before, named, padding=padding)         # 0x80100008 starts a symbol: data
        self.assertFalse(delta["ok"])
        self.assertEqual([r["address"] for r in delta["data_coverage_lost"]], ["0x80100004"])

    def test_summary_page_and_baselines(self):
        summary = progress.summary(self.before)
        self.assertEqual(summary["modules"][0]["measures"]["complete_units"], 1)
        page = progress.page([("T", self.before)], "Game <script>")
        self.assertIn("Game &lt;script&gt;", page)
        self.assertNotIn("</script><script>", page.split('id="data"')[1].split("</script>")[0])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build").mkdir()
            (root / "build/report.json").write_text(json.dumps(self.before), encoding="utf-8")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "prog", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}, "targets": {"t": {
                "repository": "decomp", "module": "main", "report": "build/report.json"}}}), encoding="utf-8")
            project = Project.load(manifest)
            first = progress.save_baseline(project, "t", "session:test")
            self.assertEqual(progress.save_baseline(project, "t", "again")["name"], first["name"])  # unchanged
            self.assertTrue(progress.since(project, "t")["ok"])
            index = progress.write_page(project, ["t"], root / "out")
            self.assertTrue(index.read_text(encoding="utf-8").startswith("<!doctype html>"))
            self.assertEqual(json.loads((root / "out/t.json").read_text(encoding="utf-8")), self.before)

    def test_matches_carried_from_another_target(self):
        """`zkit progress --carry OTHER`: each function OTHER matched exactly, by name, is exact here, compiled
        with a score band, in a unit with no source file yet, or absent; OTHER's placeholders count apart."""
        from zkit.cli import build_parser, run

        def unit(name, source, functions):
            return {"name": name, "metadata": {"source_path": source}, "measures": {},
                    "functions": [{"name": n, "size": "8", **({} if p is None else {"fuzzy_match_percent": p})}
                                  for n, p in functions]}
        there = {"units": [unit("a", "src/a.cpp", [("f", 100.0), ("g", 100.0), ("h", 100.0), ("i", 100.0),
                                                   ("j", 100.0), ("fn_7100001000", 100.0), ("k", 50.0)])]}
        here = {"units": [unit("a", "src/a.cpp", [("f", 100.0), ("g", 95.5), ("h", None)]),
                          unit("a_7100009000", "src/a_7100009000.cpp", [("i", None)])]}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build").mkdir()
            (root / "src").mkdir()
            (root / "src/a.cpp").write_text("", encoding="utf-8")
            (root / "build/one.json").write_text(json.dumps(there), encoding="utf-8")
            (root / "build/two.json").write_text(json.dumps(here), encoding="utf-8")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "prog", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}, "targets": {
                "one": {"repository": "decomp", "module": "main", "report": "build/one.json"},
                "two": {"repository": "decomp", "module": "main", "report": "build/two.json"}}}), encoding="utf-8")
            data, said = run(build_parser().parse_args(["--project", str(manifest), "--target", "two", "progress",
                                                        "--carry", "one"]))
        self.assertEqual(data["counts"], {"exact": 1, "compiled 90-99%": 1, "compiled 0%": 1, "no source": 1,
                                          "absent": 1, "unnamed there": 1})
        self.assertEqual(data["matched_there"], 6)
        self.assertEqual(data["units"]["a_7100009000"], {"no source": 1})
        self.assertEqual(data["units"]["a"], {"compiled 90-99%": 1, "compiled 0%": 1, "absent": 1, "unnamed there": 1})
        self.assertIn("one -> two: 1 of 6 exact functions carried", said)

    def test_treemap_beside_the_table_and_badges(self):
        """`zkit report` writes treemap.html beside index.html, each linking the other, and --badges the first
        target's shields.io endpoint badges."""
        from zkit.cli import build_parser, run
        counts = {"total_code": "1000", "matched_code": "1000", "complete_code": "900", "total_data": "400",
                  "matched_data": "300", "complete_data": "200", "total_functions": 4, "matched_functions": 1,
                  "total_units": 3, "complete_units": 0}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build").mkdir()
            (root / "build/report.json").write_text(json.dumps({**self.before, "measures": counts}), encoding="utf-8")
            (root / "build/other.json").write_text(json.dumps(self.before), encoding="utf-8")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "prog", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}, "targets": {
                "t": {"repository": "decomp", "module": "main", "report": "build/report.json"},
                "u": {"repository": "decomp", "module": "main", "report": "build/other.json"}}}), encoding="utf-8")
            data, said = run(build_parser().parse_args(["--project", str(manifest), "report", "--out",
                                                        str(root / "site"), "--badges", str(root / "site/badges")]))
            index, treemap = Path(data["index"]), Path(data["treemap"])
            self.assertEqual((index.parent, treemap.name), (root / "site", "treemap.html"))
            self.assertIn('<a href="treemap.html">', index.read_text(encoding="utf-8"))
            page = treemap.read_text(encoding="utf-8")
            self.assertTrue(page.startswith("<!doctype html>"))
            self.assertIn('<a href="index.html">', page)
            self.assertNotIn("<script src", page)   # self-contained, offline
            shown = json.loads(page.split('id="data">')[1].split("</script>")[0])
            self.assertEqual([r["label"] for r in shown["reports"]], ["t", "u"])   # every target, as the table
            self.assertEqual((data["badges"]["target"], said.count("badges of t")), ("t", 1))
            badges = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (root / "site/badges").iterdir()}
        self.assertEqual({name: (b["label"], b["message"], b["color"]) for name, b in badges.items()}, {
            "code": ("code matched", "100.00%", "brightgreen"), "code-linked": ("code linked", "90.00%", "green"),
            "data": ("data matched", "75.00%", "yellowgreen"), "data-linked": ("data linked", "50.00%", "yellow"),
            "functions": ("functions matched", "25.00% (1 of 4)", "orange"),
            "units-linked": ("units linked", "0.00% (0 of 3)", "red")})
        self.assertEqual({b["schemaVersion"] for b in badges.values()}, {1})
        self.assertEqual((progress.badge_color(99.999), progress.badge_color(24.99)), ("green", "red"))
        self.assertEqual(progress.badges({"units": []})["code"]["message"], "0.00%")   # nothing to count

    def test_treemap_tiles_of_a_small_report(self):
        """A tile per function and per data section, sized by its bytes, coloured by match state and naming, in
        its unit and that unit's folder below the module; the tiles add up to the report."""
        small = report([("main/game/obj/a", "f__1AFv", 0x80001000, 0x20, 100.0),
                        ("main/game/obj/a", "fn_80001020", 0x80001020, 0x10, 95.0),
                        ("main/game/b", "B__sub_80002000", 0x80002000, 0x30, 40.0),
                        ("main/c", "g", 0x80003000, 0x8, 0.0)],
                       [("main/game/obj/a", ".data", 0x80100000, 0x40, 100.0),
                        ("main/game/obj/a", ".text", 0x80001000, 0x30, 90.0),
                        ("main/game/b", ".bss", 0x80100040, 0x10, 0.0)], linked={"main/game/obj/a"})
        small["units"][0]["functions"][0]["metadata"]["demangled_name"] = "A::f()"
        small["measures"].update(complete_code="48", complete_data="64", total_units=3, complete_units=1,
                                 total_code="104", total_data="80")
        data = progress.treemap_data(small)
        self.assertEqual((data["warnings"], data["named"]), ([], 2))
        code, sections = data["layouts"]["code"], data["layouts"]["data"]
        tiles = {t[9]: (t[4], t[5], t[6], t[7], code["units"][t[8]], t[10], t[11]) for t in code["tiles"]}
        self.assertEqual(tiles, {
            "A::f()": (0, 0, 0x20, 0x80001000, "game/obj/a", 1, 100.0),             # linked
            "fn_80001020": (2, 2, 0x10, 0x80001020, "game/obj/a", 1, 95.0),        # 90% or more, placeholder
            "B__sub_80002000": (4, 1, 0x30, 0x80002000, "game/b", 0, 40.0),        # started, in a named class
            "g": (5, 0, 0x8, 0x80003000, "c", 0, 0.0)})                            # not started
        self.assertEqual(sorted((t[9], t[4], t[6]) for t in sections["tiles"]), [(".bss", 5, 0x10), (".data", 0, 0x40)])
        self.assertEqual([(a[0], a[5]["bytes"], a[5]["matched"], a[5]["linked"], a[5]["items"], a[5]["placeholders"])
                          for a in code["areas"]], [("game", 48, 0, 0, 1, 0), ("game/obj", 48, 32, 48, 2, 1),
                                                    ("main", 8, 0, 0, 1, 0)])   # by size, then name
        for t in code["tiles"] + sections["tiles"]:   # inside the canvas, with an area proportional to the bytes
            self.assertTrue(0 <= t[0] and 0 <= t[1] and t[0] + t[2] <= 1600.1 and t[1] + t[3] <= 1000.1, t)
        biggest = max(code["tiles"], key=lambda t: t[6])
        smallest = min(code["tiles"], key=lambda t: t[6])
        self.assertGreater(biggest[2] * biggest[3], smallest[2] * smallest[3])
        small["measures"]["matched_code"] = "0"
        self.assertEqual(progress.treemap_data(small)["warnings"], ["matched_code: report 0, tiles 32"])

    def test_treemap_areas_and_naming_on_both_platforms(self):
        """Folders at most two levels below the module, a folder alone in its parent not counting; several
        modules name theirs. Placeholders: CodeWarrior and Itanium, in a class or not."""
        self.assertEqual(progress.treemap_areas([
            ("main", "app/game/gf/menu/a"), ("main", "app/game/b"), ("main", "libs/l/src/c"), ("main", "libs/m/d"),
            ("main", "u")]), ["app/game/gf", "app/game", "libs/l", "libs/m", "main"])
        self.assertEqual(progress.treemap_areas([("main", "src/x/a"), ("main", "src/y/b")]), ["src/x", "src/y"])
        self.assertEqual(progress.treemap_areas([("main", "a/x"), ("rel", "b/y"), ("rel", "z")]),
                         ["main/a", "rel/b", "rel"])
        tiers = {("fn_80001000", None): 2, ("lbl_80001000", None): 2, ("@123", None): 2,
                 ("Class__sub_80001000", None): 1, ("update__7TObjectFv", "TObject::update()"): 0,
                 ("_Z13fn_7100001000v", "fn_7100001000()"): 2, ("_ZN1A13fn_7100001000Ev", "A::fn_7100001000()"): 1,
                 ("_ZN1A6updateEv", "A::update()"): 0, ("_GLOBAL__sub_I_a.cpp", None): 0}
        self.assertEqual({key: progress.naming_tier(*key) for key in tiers}, tiers)
        bare = report([("app/menu/a", "_ZN1A1fEv", 0x7100001000, 0x20, 100.0), ("unit_7100002000", "fn_7100002000",
                                                                             0x7100002000, 0x10, 0.0)], [])
        for unit in bare["units"]:   # a Switch report: no module in the units
            unit["metadata"].pop("module_name")
        layout = progress.treemap_data(bare, "main")["layouts"]["code"]
        self.assertEqual(([a[0] for a in layout["areas"]], layout["units"]),
                         (["app/menu", "main"], ["app/menu/a", "unit_7100002000"]))

    def test_treemap_escapes_names(self):
        """Names come from untrusted builds and the page is published: none can close the data's script."""
        hostile = "f</script><b>x</b><!--"
        evil = report([("main/</script><b>", hostile, 0x80001000, 0x20, 100.0)],
                      [("main/</script><b>", ".data</script>", 0x80100000, 0x8, 0.0)])
        page = progress.treemap_page([("T</script>", evil)], "Game </script><b>")
        self.assertIn("<title>Game &lt;/script&gt;&lt;b&gt; treemap</title>", page)
        body = page.split('id="data">')[1]
        self.assertEqual(body.count("</script>"), 2)   # the data's own end and the code's
        embedded = body.split("</script>")[0]
        self.assertNotIn("<", embedded)
        shown = json.loads(embedded)
        self.assertEqual((shown["title"], shown["reports"][0]["label"]), ("Game </script><b>", "T</script>"))
        layouts = shown["reports"][0]["layouts"]
        self.assertEqual((layouts["code"]["tiles"][0][9], layouts["code"]["units"], layouts["data"]["tiles"][0][9]),
                         (hostile, ["</script><b>"], ".data</script>"))
        self.assertNotIn("innerHTML", page)   # names reach the page only as text

    def test_page_shows_where_report_totals_differ_from_its_units(self):
        counts = {"total_code": "48", "matched_code": "32", "total_functions": 2, "matched_functions": 1}
        consistent = {"version": 2, "measures": dict(counts), "units": [
            {"name": "main/a", "metadata": {"module_name": "main"}, "measures": dict(counts), "sections": [],
             "functions": [{"name": "f", "size": "32", "fuzzy_match_percent": 100.0,
                            "metadata": {"virtual_address": "2147487744"}}]}]}
        changed = copy.deepcopy(consistent)
        changed["measures"]["total_code"] = "52"
        data = lambda report: json.loads(progress.page([("T", report)], "Game").split(
            'id="data" type="application/json">')[1].split("</script>")[0])["reports"][0]
        self.assertEqual((data(consistent)["differences"], data(consistent)["file"]), ({}, "T.json"))
        self.assertEqual(data(changed)["differences"], {"total_code": {"report": 52, "units": 48}})

    def test_a_one_module_page_is_browsed_by_folder(self):
        """A Switch `main`: objdiff's report drops the module, so units are grouped by their first folder as
        categories, and a placeholder unit outside any folder stays in the module instead of becoming one."""
        bare = report([("ns/menu", "f", 0x7100001000, 0x20, 100.0), ("ns/data", "g", 0x7100001020, 0x10, 0.0),
                       ("unit_7100002000", "h", 0x7100002000, 0x10, 0.0)], [])
        for unit in bare["units"]:
            unit["metadata"].pop("module_name")
            unit["measures"] = {"total_code": str(sum(int(f["size"]) for f in unit["functions"])),
                                "matched_code": "32" if unit["name"] == "ns/menu" else "0", "total_units": 1}
        data = lambda modules: json.loads(progress.page([("T", bare)], "Game", "", modules).split(
            'id="data" type="application/json">')[1].split("</script>")[0])["reports"][0]
        shown = data({"T": "main"})
        self.assertEqual({u["module"] for u in shown["units"]}, {"main"})
        self.assertEqual([(c["id"], c["measures"]["total_code"], c["measures"]["matched_code"],
                           c["measures"]["total_units"]) for c in shown["summary"]["categories"]], [("ns", 48, 32, 2)])
        self.assertEqual(sorted(u["module"] for u in data(None)["units"]), ["ns", "ns", "unit_7100002000"])

    def test_readme_progress_table_only_between_existing_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "build").mkdir()
            (root / "build/report.json").write_text(json.dumps(self.before), encoding="utf-8")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "readme", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}, "targets": {"t": {
                "repository": "decomp", "module": "main", "report": "build/report.json"}}}), encoding="utf-8")
            project = Project.load(manifest)
            readme = root / "README.md"
            badges = "# Game\n\n## Progress\n\n[![Code]][page]\n\n## Building\n"
            readme.write_text(badges, encoding="utf-8")
            self.assertEqual(progress.write_readme(project, ["t"], readme), "no-markers")   # badges only: untouched
            self.assertEqual(readme.read_text(encoding="utf-8"), badges)
            readme.write_text(f"# Game\n\n## Progress\n\n{progress.README_START}\n{progress.README_END}\n",
                              encoding="utf-8")
            self.assertEqual(progress.write_readme(project, ["t"], readme), "updated")
            text = readme.read_text(encoding="utf-8")
            self.assertIn("| Code |", text.split(progress.README_START)[1].split(progress.README_END)[0])
            self.assertEqual(progress.write_readme(project, ["t"], readme), "unchanged")
            self.assertEqual(text.count(progress.README_START), 1)

    def test_hygiene_forbids_progress_table(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            readme = root / "README.md"
            readme.write_text("# Game\n\n## Progress\n\n| | Matched | Linked |\n|:--|--:|--:|\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            manifest = root / "p.json"
            config = {"schema_version": 1, "id": "readme", "repositories": {"decomp": {
                "root": ".", "role": "decomp", "hygiene": {"progress_table": "forbid"}}}, "targets": {}}
            manifest.write_text(json.dumps(config), encoding="utf-8")
            found = hygiene.files(Project.load(manifest), "decomp")["findings"]
            self.assertEqual([(f["kind"], f["severity"]) for f in found if f["kind"] == "progress-table"],
                             [("progress-table", "error")])
            config["repositories"]["decomp"]["hygiene"] = {}
            manifest.write_text(json.dumps(config), encoding="utf-8")
            found = hygiene.files(Project.load(manifest), "decomp")["findings"]
            self.assertFalse([f for f in found if f["kind"] == "progress-table"])


class QualityTests(unittest.TestCase):
    def test_counts_patterns_and_compares_revisions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            dirty = ('extern "C" void update__6TEnemyFv(void *arg0) {\n'
                     '    s32 temp_r3 = *(s32 *)((u8 *)arg0 + 0x10); // M2C_FIELD in a comment is ignored\n'
                     '    fn_80012345(lbl_80450000, temp_r3);\n}\n')
            (root / "src/enemy.cpp").write_text(dirty, encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add enemy")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "q", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}}}), encoding="utf-8")
            project = Project.load(manifest)
            counts = {c["key"]: c["count"] for c in quality.audit(project, "decomp")["counts"]}
            for key in ("extern_c", "mangled_member", "raw_offset", "decomp_temp", "arg_name", "function_placeholder",
                        "data_label"):
                self.assertGreater(counts[key], 0, key)
            self.assertEqual(counts["m2c_macro"], 0)
            (root / "src/enemy.cpp").write_text(
                "void TEnemy::update() {\n    s32 hp = this->hit_points;\n    take_damage(hp);\n}\n", encoding="utf-8")
            delta = quality.compare(project, "decomp", "HEAD")
            self.assertLess(delta["total"]["delta"], 0)
            self.assertEqual(delta["worse"], [])
            self.assertEqual(quality.audit(project, "decomp", revision="HEAD")["total"],
                             quality.compare(project, "decomp", "HEAD")["total"]["before"])

    def project(self, root: Path) -> Project:
        manifest = root / "p.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "q", "repositories": {
            "decomp": {"root": ".", "role": "decomp"}}}), encoding="utf-8")
        (root / ".git/info/exclude").write_text("p.json\n", encoding="utf-8")
        return Project.load(manifest)

    def test_moved_code_is_neither_removed_nor_added(self):
        """A change is measured by what it removes and adds, matched by text, so code that only moves to another
        file counts as neither; the findings it adds are placed on its own lines."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src/a.cpp").write_text("void f() {\n    fn_80012345();\n}\n", encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add a")
            project = self.project(root)
            (root / "src/a.cpp").write_text("void k() {\n}\n", encoding="utf-8")
            (root / "src/b.cpp").write_text("void f() {\n    fn_80012345();\n}\nvoid g() {\n    fn_80099999();\n}\n",
                                            encoding="utf-8")   # untracked: measured whole
            delta = quality.compare(project, "decomp", "HEAD")
            row = next(r for r in delta["rows"] if r["key"] == "function_placeholder")
            self.assertEqual((row["before"], row["after"], row["removed"], row["added"]), (1, 2, 0, 1))
            self.assertEqual(delta["new"], [{"key": "function_placeholder", "path": "src/b.cpp", "line": 5,
                                             "text": "fn_80099999"}])
            self.assertEqual(delta["files_changed"], 2)
            self.assertEqual((delta["total"]["removed"], delta["total"]["added"]), (0, 1))
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Move f")
            committed = quality.compare(project, "decomp", "HEAD~1", "HEAD")
            self.assertEqual(committed["rows"], delta["rows"])
            self.assertEqual(committed["new"], delta["new"])
            self.assertRegex(committed["after_commit"], r"^[0-9a-f]{40}$")

    def test_members_in_the_wrong_class_are_counted_beside_the_total(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "include").mkdir()
            (root / "src").mkdir()
            (root / "include/obj.h").write_text(
                "class TBase { public: void g(); };\nclass TFoo : public TBase { public: void f(); };\n"
                "class TBar { public: void h(); };\ntypedef TBar TBarAlias;\n", encoding="utf-8")
            (root / "src/foo.cpp").write_text(
                '#include "obj.h"\n'
                "void TFoo::f() {\n"
                "    ((TBase *)this)->g();\n"            # a base: no finding
                "    ((TBar *)this)->h();\n"             # unrelated: this_cast
                "    ((TBarAlias *)this)->h();\n"        # unrelated through a typedef
                "    TFoo__f((u8 *)this + 0x10);\n"      # own member on a sub-object: subobject_call
                "    TFoo__f((u8 *)this + 0);\n"         # offset 0 is the object itself
                "}\n", encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add foo")
            audit = quality.audit(self.project(root), "decomp")
            owned = {r["key"]: r["count"] for r in audit["ownership"]}
            self.assertEqual(owned, {"this_cast": 2, "subobject_call": 1})
            self.assertEqual(audit["total"], sum(r["count"] for r in audit["counts"]))
            self.assertNotIn("this_cast", {r["key"] for r in audit["counts"]})

    def test_a_name_starting_in_is_no_ghidra_register_input(self):
        """Ghidra names a register's incoming value `in_x8`, `in_w1`, `in_lr`, `in_FPCR`, `in_stack_ffffffe8`; a
        member called `in_list` (an original's own name, from its assert) is none."""
        catalog = quality.patterns()
        debt = "int a = in_x8 + in_w1; f(in_lr, in_FPCR, in_stack_ffffffe8, in_r3);"
        self.assertEqual(quality.count(debt, catalog)["ghidra_temp"], 6)
        self.assertEqual(quality.count("bool in_list() const; MM_ASSERT(it.node()->in_list());", catalog)
                         ["ghidra_temp"], 0)

    def test_a_c_modules_header_may_declare_extern_c(self):
        catalog = quality.patterns()
        guarded = '#ifdef __cplusplus\nextern "C" {\n#endif\nvoid* memset(void*, int, unsigned long);\n'
        self.assertEqual(quality.count(guarded, catalog, header=True)["extern_c"], 0)
        self.assertEqual(quality.count(guarded, catalog)["extern_c"], 1)

    def test_extern_c_is_debt_only_at_a_call_site_or_on_a_cxx_name(self):
        owned = ('extern "C" const char* TQuestBgmCtrl__class_name;\n'
                 'extern "C" __declspec(section ".rodata") const char epi1[] = "epi1.adx";\n'
                 'extern "C" void* table[2] = {\n    (void*)epi1, 0,\n};\n'
                 'extern "C" {\nint counter;\nvoid OSReport(const char* format, ...) {\n    counter++;\n}\n'
                 'static int (*hook)(int);\n}\n'
                 'extern "C" int nnMain(void) { return 0; }\n'
                 'extern "C" void later(void);\n'
                 'void later(void) { }\n'
                 'extern "C" const char* TQuestBgmCtrl__class_name = epi1;\n'
                 '// extern "C" void commented(void);\nconst char* s = "extern \\"C\\" void quoted(void);";\n')
        self.assertEqual(quality.extern_c_debt(owned), [])
        borrowed = ('#include "x.h"\nextern "C" void OSReport(const char*, ...);\n'
                    'extern "C" {\nvoid* memcpy(void*, const void*, unsigned long);\nextern int g_frame;\n}\n'
                    'extern "C" int g_count;\n'
                    'extern "C" void update__6TEnemyFv(void* self) { }\n'
                    'extern "C" void _ZN6TEnemy4drawEv(void* self) { }\n')
        self.assertEqual(quality.extern_c_debt(borrowed), [
            (2, "OSReport"), (4, "memcpy"), (5, "g_frame"), (7, "g_count"), (8, "update__6TEnemyFv"),
            (9, "_ZN6TEnemy4drawEv")])
        catalog = quality.patterns()
        self.assertEqual(quality.count(owned, catalog)["extern_c"], 0)
        self.assertEqual(quality.count(borrowed, catalog)["extern_c"], 6)
        self.assertEqual([f["text"] for f in quality.findings('extern "C" void f(int);', catalog)
                          if f["key"] == "extern_c"], ['extern "C" f'])

    def test_an_assignment_in_a_one_line_body_defines_nothing(self):
        """`g_count = 1;` inside `void reset() { ... }` written on one line assigns a global the file declares
        `extern "C"`; it is no definition, so the declaration stays debt."""
        one_line = 'extern "C" int g_count;\nvoid reset() { g_count = 1; }\n'
        self.assertEqual(quality.extern_c_debt(one_line), [(1, "g_count")])
        self.assertEqual(quality.extern_c_debt('extern "C" int g_count;\nint g_count = 1;\n'), [])

    def test_flat_c_spellings_of_members(self):
        catalog = quality.patterns()
        flat = ("void TMainCursor__set_end_task(void *self, TObject *task);\n"
                "TLoadCtrl *p = TLoadCtrl__instance; f(TObjCity_Season_XmasTree__create(p), TUnk_8013F08C__clear(p));\n")
        self.assertEqual(quality.count(flat, catalog)["flat_name"], 4)   # address-named classes too
        counted_elsewhere = ("poll_default__9TLoadCtrlFv(); hook__Fv(); TMainCursor__sub_8013E1C0(p);\n"
                             "TEffect__data_80450000; TObj__vt12(p); __vt__9TLoadCtrl; Mtx__ident(m);\n")
        self.assertEqual(quality.count(counted_elsewhere, catalog)["flat_name"], 1)   # Mtx__ident
        self.assertEqual(quality.count("TAdPlayerLoadGC__load_state; TOVS2__class_name;", catalog)["flat_name"], 2)
        not_members = "MAX__ITEMS; my__thing; GX__INIT; TRK__write_aram(p); void TClass::method() {}\n"
        self.assertEqual(quality.count(not_members, catalog)["flat_name"], 0)   # MetroTRK's own C name

    def test_function_body_findings_skip_comments(self):
        catalog = quality.patterns()
        self.assertEqual(quality.findings("// raw *(u8 *)((u8 *)p + 0x10)\nreturn this->x;", catalog), [])
        self.assertTrue(quality.findings("return *(s32 *)((u8 *)p + 0x10);", catalog))

    def test_offsets_casts_and_offset_names(self):
        catalog = quality.patterns()
        layout = ("x = (u8 *)p + 0x30; y = ((char *)(self) + 8); v = (Vec *)(p + 0x178);\n"
                  "a[(u8 *)p + 4 ](); f(unk_30, m_c, field_96, obj->set_field_378, s.f3C);\n")
        found = quality.count(layout, catalog)
        self.assertEqual((found["raw_offset"], found["offset_cast"], found["offset_member"]), (3, 1, 5))
        words = "m_face; unk_dead; m_bad; field_bead; (Vec *)(p + count); *(Vec *)(p + 0x10);"
        found = quality.count(words, catalog)   # hex-spelled words are names; a deref is a punned_deref
        self.assertEqual((found["offset_member"], found["offset_cast"], found["punned_deref"]), (0, 0, 1))
        self.assertEqual([f["text"] for f in quality.findings('load((saddr)"file.gvm", (u32)"x");', catalog)
                          if f["key"] == "string_cast"], ['(saddr)"file.gvm"', '(u32)"x"'])
        self.assertEqual(quality.count('(const char *)"a"; f("(u32)") /* (int)"b" */', catalog)["string_cast"], 0)

    def test_prototypes_and_externs_in_source_files(self):
        """A source file's file-scope declaration of what another file defines belongs in that file's header; what
        the file defines, a static or inline helper, a macro invocation and `extern "C"` (judged as extern_c) are
        none."""
        text = ('#include "enemy.h"\nvoid heap_free(void *);\nextern int g_frame;\nint a, b;\n'
                'void local(int);\nvoid local(int x) { }\nstatic void helper(void);\n'
                'extern int g_owned;\nint g_owned = 1;\nDECLARE_THING(TEnemy);\nextern "C" void OSReport(const char*, ...);\n'
                'namespace ns {\nvoid hidden(int);\n}\nstruct S { void method(); };\n'
                'void use() { extern int g_inner; void inner(int); }\n')
        self.assertEqual(quality.local_decl_debt(text)[0], [(2, "void heap_free(void *)"), (3, "extern int g_frame"),
                                                            (13, "void hidden(int)")])
        catalog = quality.patterns()
        self.assertEqual(quality.count(text, catalog)["local_decl"], 3)
        self.assertEqual(quality.count(text, catalog, rel="include/enemy.h")["local_decl"], 0)   # a header's job
        self.assertEqual([f for f in quality.findings(text, catalog) if f["key"] == "local_decl"], [])

    def test_address_comments_need_the_image(self):
        image = (0x8000C000, 0x805E1224)
        text = ("// moved from 0x8043E828\nu32 mask = 0x80000000; // 0x80000000 is the sign bit\n"
                "/* OS global at 0x800000F8,\n   was 80123456 */\nint fn_80123456;\nconst char *s = \"0x80123456\";\n")
        self.assertEqual(quality.address_comments(text, image), [(1, "// moved from 0x8043E828"),
                                                                 (4, "/* OS global at 0x800000F8, was 80123456 */")])
        self.assertEqual(quality.address_comments(text, None), [])
        catalog = quality.patterns()
        self.assertEqual(quality.count(text, catalog, image=image)["address_comment"], 2)
        self.assertEqual(quality.count(text, catalog)["address_comment"], 0)

    def test_address_comments_name_placeholders_without_the_image(self):
        text = "// see fn_80123456\nint x; // 0x80123456 is a mask\n/* sub_8001A2B0 */\n"
        self.assertEqual(quality.address_comments(text, None), [(1, "// see fn_80123456"), (3, "/* sub_8001A2B0 */")])
        self.assertEqual(quality.count(text, quality.patterns())["address_comment"], 2)

    def test_slipped_decompiler_shapes(self):
        """Register-named variables (not inside asm), no-op statements, padding fields read or written and
        hand-written size asserts are debt; the same function written plainly has none."""
        catalog = quality.patterns()
        text = ("void TFoo::step(int count) {\n"
                "    s32 r31 = count;\n"
                "    f32 f30, f31;\n"
                "    count = count;\n"
                "    if (1) {\n        work(r31);\n    }\n"
                "    while (0) { }\n"
                "    this->pad_10[2] = 1;\n"
                "    asm { mr r3, r31 }\n"
                "}\n"
                "typedef char check_size[(sizeof(TFoo) == 0x40) ? 1 : -1];\n")
        found = quality.count(text, catalog, rel="src/foo.cpp")
        self.assertEqual((found["register_name"], found["no_op"], found["pad_access"], found["size_assert"]),
                         (3, 3, 1, 1))
        self.assertEqual([f for f in quality.parsed_findings(text, catalog, "src/foo.cpp") if f[1] == "no_op"],
                         [(4, "no_op", "count = count;"), (5, "no_op", "if (1)"), (8, "no_op", "while (0)")])
        plain = "void TFoo::step(int count) {\n    s32 total = count;\n    if (count) { work(total); }\n}\n"
        self.assertFalse(+quality.count(plain, catalog, rel="src/foo.cpp"))

    def test_register_names_are_locals_and_parameters(self):
        """A register name counts on a local or a parameter, never on a field (u16 f4; often names its offset) and
        never r0-r2 (scratch, the stack pointer and the SDA2 base under the EABI)."""
        catalog = quality.patterns()
        text = ("struct TBox {\n    u16 f4;\n    s32 r30;\n};\nvoid move(s32 r3);\n"
                "void TBox::step(f32 f1) {\n    s32 r0 = 1;\n    s32 r31 = r0;\n}\n")
        self.assertEqual([f for f in quality.parsed_findings(text, catalog, "src/box.cpp") if f[1] == "register_name"],
                         [(5, "register_name", "void move(s32 r3);"), (6, "register_name", "void TBox::step(f32 f1) {"),
                          (8, "register_name", "s32 r31 = r0;")])

    def test_this_aliases_and_self_receivers(self):
        """`T *self = this;` and a cast of this, also through `struct T *`, alias this (this_alias); a `self`
        parameter or a `self` set from anything else is a C-style receiver (self_param)."""
        catalog = quality.patterns()
        text = ("void TBox::a() {\n    TBox *self = this;\n}\nvoid TBox::b() {\n    TBox *o = (struct TBox *)this;\n}\n"
                "void box_c(TBox *self) {\n    TBox *cursor = this;\n}\nvoid box_d(void *arg) {\n"
                "    TBox *self = (TBox *)arg;\n}\n")
        found = quality.count(text, catalog, rel="src/box.cpp")
        self.assertEqual((found["this_alias"], found["self_param"]), (2, 2))

    def test_block_declarations_of_the_files_own_names(self):
        """A prototype or extern inside a function body counts only for a name the file does not define."""
        catalog = quality.patterns()
        text = ("static void helper(int);\nint g_count;\nvoid run() {\n    void helper(int);\n"
                "    extern int g_count;\n    extern int g_other;\n}\nstatic void helper(int n) { }\n")
        self.assertEqual([f for f in quality.parsed_findings(text, catalog, "src/run.cpp") if f[1] == "local_decl"],
                         [(6, "local_decl", "extern int g_other;")])

    def test_header_extern_c_reads_the_config(self):
        """A header's extern "C" on a function a C++ unit defines is read from config.yml's symbols.txt and
        splits.txt; a C unit's function keeps its C linkage, and so does a unit configure.py links as middleware."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {
                "config/G/config.yml": "symbols: config/G/symbols.txt\nsplits: config/G/splits.txt\n",
                "config/G/splits.txt": "src/unit.cpp:\n\t.text       start:0x80003100 end:0x80003200\n\n"
                                       "src/os.c:\n\t.text       start:0x80003200 end:0x80003300\n\n"
                                       "src/lib/codec.cpp:\n\t.text       start:0x80003300 end:0x80003400\n",
                "config/G/symbols.txt": "update_all = .text:0x80003100; // type:function size:0x10\n"
                                        "OSReport = .text:0x80003200; // type:function size:0x10\n"
                                        "codec_init = .text:0x80003300; // type:function size:0x10\n",
                "configure.py": "MIDDLEWARE: list[tuple[int, str]] = [\n    (0x80003300, 'codec'),\n]\n"
                                "MIDDLEWARE_END = 0x80003400\n",
                "include/unit.h": '#ifdef __cplusplus\nextern "C" {\n#endif\nvoid update_all(void);\n'
                                  "void OSReport(const char *, ...);\nvoid codec_init(void);\n"
                                  "#ifdef __cplusplus\n}\n#endif\n",
                "src/unit.cpp": '#include "unit.h"\nvoid update_all(void) { }\n',
            }
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add unit")
            project = self.project(root)
            for revision in (None, "HEAD"):
                audit = quality.audit(project, "decomp", revision=revision)
                counts = {r["key"]: r["count"] for r in audit["counts"]}
                self.assertEqual(counts["header_extern_c"], 1, revision)
                self.assertEqual(audit["total"], sum(counts.values()))
            (root / "include/unit.h").write_text(
                '#ifdef __cplusplus\nextern "C" {\n#endif\nvoid OSReport(const char *, ...);\nvoid codec_init(void);\n'
                "#ifdef __cplusplus\n}\n#endif\nvoid update_all(void);\n", encoding="utf-8")
            delta = quality.compare(project, "decomp", "HEAD")
            row = next(r for r in delta["rows"] if r["key"] == "header_extern_c")
            self.assertEqual((row["before"], row["after"], row["removed"], row["added"]), (1, 0, 1, 0))
            self.assertEqual(delta["new"], [])

    def test_parameter_names_pair_prototypes_with_definitions(self):
        """A prototype pairs with the one definition of its name and parameter count, also one under libs/ (read to
        pair, never counted). A placeholder on one side and a real name on the other is debt on the placeholder's
        line (param_name_split); two real names (a letter starting the other side's name is one) are not flagged. A
        change fixing either side removes the finding and adds none."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {
                "include/widget.h": "class TWidget {\npublic:\n    void set(int arg0,\n             int count);\n"
                                    "    void move(int x, int dx);\n    void scale(float arg0, float arg1);\n};\n"
                                    "void sdk_wait(int arg0);\nvoid sdk_tick(int ticks);\n",
                "src/widget.cpp": '#include "widget.h"\nvoid TWidget::set(int value, int arg1) { }\n'
                                  "void TWidget::move(int xPos, int step) { }\n"
                                  "void TWidget::scale(float a0, float a1) { }\n",
                "libs/sdk/wait.c": "void sdk_wait(int ticks) { }\nvoid sdk_tick(int arg0) { }\n",
            }
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add widget")
            project = self.project(root)
            audit = quality.audit(project, "decomp")
            counts = {r["key"]: r["count"] for r in audit["counts"]}
            self.assertEqual(counts["param_name_split"], 3)
            scans = {rel: quality._scan(rel, text, quality.patterns(), None) for rel, text in files.items()
                     if not rel.startswith("libs/")}
            library = {"libs/sdk/wait.c": quality.signatures(quality._Source(files["libs/sdk/wait.c"]))}
            found = quality._relations(scans, quality.TREE_CHECKS, [], None, library)
            self.assertEqual(sorted(found["include/widget.h"]), [
                (3, "param_name_split", "arg0 (value at widget.cpp:2)"),
                (8, "param_name_split", "arg0 (ticks at wait.c:1)")])
            self.assertEqual(found["src/widget.cpp"], [(2, "param_name_split", "arg1 (count at widget.h:4)")])
            (root / "include/widget.h").write_text(files["include/widget.h"].replace("int arg0,", "int value,"),
                                                   encoding="utf-8")
            (root / "src/widget.cpp").write_text(files["src/widget.cpp"].replace("int arg1", "int count"),
                                                 encoding="utf-8")
            delta = quality.compare(project, "decomp", "HEAD")
            row = next(r for r in delta["rows"] if r["key"] == "param_name_split")
            self.assertEqual((row["before"], row["after"], row["removed"], row["added"]), (3, 1, 2, 0))
            self.assertEqual(delta["new"], [])
            # Naming one side of a placeholder pair adds a finding on the other side's kept line, and lists it.
            (root / "src/widget.cpp").write_text(files["src/widget.cpp"].replace("int arg1", "int count")
                                                 .replace("float a0", "float factor"), encoding="utf-8")
            delta = quality.compare(project, "decomp", "HEAD")
            row = next(r for r in delta["rows"] if r["key"] == "param_name_split")
            self.assertEqual((row["before"], row["after"], row["removed"], row["added"]), (3, 2, 2, 1))
            self.assertEqual([f for f in delta["new"] if f["key"] == "param_name_split"], [
                {"key": "param_name_split", "path": "include/widget.h", "line": 6,
                 "text": "arg0 (factor at widget.cpp:4)"}])

    def test_a_rewritten_debt_line_is_neither_removed_nor_added(self):
        """A hunk that replaces lines nets each check within it: renaming a variable on a debt line adds and removes
        nothing, and replacing one debt line with two adds one."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            text = "void TFoo::f() {\n    u8 *p = (u8 *)this + 0x10;\n    g(p);\n}\n"
            (root / "src/a.cpp").write_text(text, encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add a")
            project = self.project(root)
            for edit, removed, added in (("    u8 *q = (u8 *)this + 0x10;\n    g(q);\n", 0, 0),
                                         (("    u8 *p = (u8 *)this + 0x10;\n    u8 *q = (u8 *)this + 0x14;\n"
                                           "    g(p);\n"), 0, 1)):
                (root / "src/a.cpp").write_text(text.replace("    u8 *p = (u8 *)this + 0x10;\n    g(p);\n", edit),
                                                encoding="utf-8")
                delta = quality.compare(project, "decomp", "HEAD")
                row = next(r for r in delta["rows"] if r["key"] == "raw_offset")
                self.assertEqual((row["removed"], row["added"]), (removed, added), edit)
                self.assertEqual(len(delta["new"]), added)

    def test_units_and_classes_outside_their_home(self):
        """A unit named after an address is a fragment not in its real unit, and so is a header named after one
        that no unit shares a name with (one rename fixes both); a class declared in a C++ source file is a stand-in
        or a layout kept out of its header; a class with a body in two files is a copy (the header's copy is the
        first). C files may keep their own structs, and a nested class is part of its outer one."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "include").mkdir()
            files = {
                "include/enemy.h": "class TEnemy {\npublic:\n    struct Part { int hp; };\n};\n",
                "src/enemy.cpp": '#include "enemy.h"\nclass TEnemy { };\nstruct EnemyView : TObject {\n    u8 pad_0[0x30];\n};\n'
                                 "typedef struct { int x; } Pair;\nenum class Mode { A };\n",
                "src/TEnemy_80123456.cpp": "struct Pair { int x; };\n",
                "include/TEnemy_80123456.h": "void enemy_fragment(void);\n",
                "include/TBoss_80124000.h": "void boss_fragment(void);\n",
                "src/grid.c": "struct Cell { int x; };\n",
                "src/grid2.c": "struct Cell { int y; };\n",
                "src/hud.cpp": "static struct { int x; } state;\n",
            }
            for rel, text in files.items():
                (root / rel).write_text(text, encoding="utf-8")
            git(root, "init", "-q")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "Add units")
            manifest = root / "p.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "q", "repositories": {
                "decomp": {"root": ".", "role": "decomp", "quality": {"image": ["0x8000C000", "0x805E1224"]}}}}),
                encoding="utf-8")
            project = Project.load(manifest)
            self.assertEqual(quality.image_range(project, "decomp"), (0x8000C000, 0x805E1224))
            data = quality.audit(project, "decomp", top=10)
            counts = {c["key"]: c["count"] for c in data["counts"]}
            # TEnemy, EnemyView, Pair (by its typedef) in enemy.cpp; Pair in the address unit
            self.assertEqual((counts["address_unit"], counts["local_class"], counts["duplicate_class"]), (2, 4, 2))
            listed = {row["path"] for row in data["worst_files"]}
            self.assertIn("include/TBoss_80124000.h", listed)
            self.assertNotIn("include/TEnemy_80123456.h", listed)                # src/TEnemy_80123456.cpp has its name
            worst = {row["path"]: dict(row["top"]) for row in data["worst_files"]}
            self.assertEqual(worst["src/enemy.cpp"]["duplicate_class"], 2)       # TEnemy (the header's is first), Pair (src/TEnemy_80123456.cpp sorts first)
            self.assertEqual(worst["src/enemy.cpp"]["local_class"], 3)
            self.assertNotIn("src/grid2.c", worst)                                # C files keep their own structs
            self.assertEqual(quality.parsed_findings(files["src/enemy.cpp"], quality.patterns(), "src/enemy.cpp"),
                             [(2, "local_class", "class TEnemy"), (3, "local_class", "struct EnemyView"),
                              (6, "local_class", "struct Pair")])


class HygieneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "README.md").write_text("# Game\n\nSee [docs/arch.md](docs/arch.md).\n", encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs/arch.md").write_text("Run tools/build.py.\n", encoding="utf-8")
        (self.root / "tools").mkdir()
        (self.root / "tools/build.py").write_text("print('build')\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Add the build")
        manifest = self.root / "p.json"
        manifest.write_text(json.dumps({"schema_version": 1, "id": "h", "repositories": {
            "game": {"root": ".", "role": "decomp", "hygiene": {"identity": IDENTITY}}}}), encoding="utf-8")
        (self.root / ".git/info/exclude").write_text("p.json\n", encoding="utf-8")
        self.project = Project.load(manifest)

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_repository(self):
        result = hygiene.audit(self.project, "game")
        self.assertTrue(result["ok"], result)

    def test_upward_links_and_a_target_s_own_files_are_not_orphans(self):
        (self.root / "docs/notes.md").write_text("Units: [notes](../NOTES.txt).\n", encoding="utf-8")
        (self.root / "NOTES.txt").write_text("linked from docs/notes.md\n", encoding="utf-8")
        (self.root / "README.md").write_text("# Game\n\n[arch](docs/arch.md), [notes](docs/notes.md)\n",
                                             encoding="utf-8")
        (self.root / "config").mkdir()
        (self.root / "config/splits.txt").write_text("game/a.cpp:\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Add notes and splits")
        manifest = json.loads((self.root / "p.json").read_text(encoding="utf-8"))
        manifest["targets"] = {"t": {"repository": "game", "module": "main", "splits": "config/splits.txt"}}
        (self.root / "p.json").write_text(json.dumps(manifest), encoding="utf-8")
        found = hygiene.files(Project.load(self.root / "p.json"), "game")["findings"]
        self.assertEqual([f["path"] for f in found if f["kind"] == "orphan-doc"], [])

    def test_finds_what_must_not_be_committed(self):
        (self.root / "AGENTS.md").write_text("agent rules\n", encoding="utf-8")
        (self.root / "docs/TU_RECOVERY_2026_10_09.md").write_text("Later on 2026-10-09 we did things.\n",
                                                                     encoding="utf-8")
        (self.root / "tools/wave7_probe.py").write_text("print(1)\n", encoding="utf-8")
        (self.root / "docs/arch.md").write_text("Run tools/build.py and tools/gone.py.\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "Cleanup cycle: lane: 5 TUs tidied: 0 banners, 3 includes, 2 joined, "
            "9 regrouped (26615 -> 26615 matched)\n\nLong body.\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
        git(self.root, "branch", "old-work")
        result = hygiene.audit(self.project, "game")
        kinds = {f["kind"] for f in result["files"]["findings"]}
        self.assertTrue({"agent-doc", "dated-doc", "unused-script", "stale-reference"} <= kinds, kinds)
        problems = " ".join(result["commits"]["problems"][0]["problems"])
        for text in ("trailer", "body", "characters", "tool summary"):
            self.assertIn(text, problems)
        self.assertTrue(any("old-work" in p for p in result["tree"]["problems"]))
        self.assertEqual(result["files"]["history"][0]["path"], "AGENTS.md")
        self.assertFalse(result["ok"])

    def test_any_identity_takes_other_people_s_commits_but_not_ai_ones(self):
        (self.root / "docs/arch.md").write_text("Run tools/build.py twice.\n", encoding="utf-8")
        git(self.root, "commit", "-q", "-am", "Explain the build", author="Other Person <other@example.org>")
        self.assertFalse(hygiene.commits(self.project, "game")["problems"] == [])
        manifest = json.loads((self.root / "p.json").read_text(encoding="utf-8"))
        manifest["repositories"]["game"]["hygiene"]["identity"] = "any"
        (self.root / "p.json").write_text(json.dumps(manifest), encoding="utf-8")
        project = Project.load(self.root / "p.json")
        result = hygiene.commits(project, "game")
        self.assertEqual((result["identity"], result["problems"]), ("any", []))
        (self.root / "docs/arch.md").write_text("Run tools/build.py once.\n", encoding="utf-8")
        git(self.root, "commit", "-q", "-am", "Explain the build again", author="Claude <noreply@anthropic.com>")
        problems = hygiene.commits(project, "game")["problems"]
        self.assertEqual(len(problems), 1)
        self.assertIn("AI identity", problems[0]["problems"][0])

    def test_commit_message_hook(self):
        good = hygiene.message(self.project, "game", "Match the enemy update\n# comment from git\n")
        bad = hygiene.message(self.project, "game", "Fix\n\nWhy it changed.\n\nCo-Authored-By: Codex <noreply@openai.com>\n")
        self.assertTrue(good["ok"], good)
        self.assertFalse(bad["ok"])


if __name__ == "__main__":
    unittest.main()
