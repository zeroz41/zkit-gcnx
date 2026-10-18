import support  # noqa: F401  (isolates config, cache and state)
import tempfile
import unittest
from pathlib import Path

from zkit import apply, delink

BLR = (0x4E800020).to_bytes(4, "big")


def unit(path: Path, names: list[str], with_note: bool, extra: bool = False) -> None:
    rows = [{"name": name, "section": ".text", "value": 4 * i, "size": 4, "kind": "func", "bind": "global",
             "address": 0x80010000 + 4 * i if with_note else 0} for i, name in enumerate(names)]
    if extra:
        rows.append({"name": "added", "section": ".text", "value": 4 * len(names), "size": 4, "kind": "func",
                     "bind": "global", "address": 0})
    delink.write_object(delink.PPC, [(".text", 1, BLR * (len(names) + extra), 4)], rows, {}, path)


class ApplyTests(unittest.TestCase):
    def test_renames_by_place(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unit(root / "target.o", ["fn_80010000", "update", "fn_80010008"], with_note=True)
            unit(root / "base.o", ["init__5ActorFv", "update", "fn_80010008"], with_note=False)
            rows, unsure = apply.unit_renames(root / "target.o", root / "base.o")
            self.assertEqual([(r["address"], r["old"], r["new"]) for r in rows],
                             [(0x80010000, "fn_80010000", "init__5ActorFv")])
            self.assertEqual(unsure, [])

    def test_different_layout_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unit(root / "target.o", ["fn_80010000", "update"], with_note=True)
            unit(root / "base.o", ["init__5ActorFv", "update"], with_note=False, extra=True)
            rows, unsure = apply.unit_renames(root / "target.o", root / "base.o")
            self.assertEqual((rows, unsure), ([], [".text"]))


if __name__ == "__main__":
    unittest.main()
