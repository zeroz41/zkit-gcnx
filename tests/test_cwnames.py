import support  # noqa: F401  (isolates config, cache and state)
import unittest

from zkit import cwnames

CASES = {
    "run_task__7TObjectFv": "TObject::run_task()",
    "__ct__15TWindowHelpItemFPvUs": "TWindowHelpItem::TWindowHelpItem(void *, unsigned short)",
    "__dt__10J3DMtxCalcFv": "J3DMtxCalc::~J3DMtxCalc()",
    "getWeight__22J3DMtxCalcBlendAnmBaseCFUc": "J3DMtxCalcBlendAnmBase::getWeight(unsigned char) const",
    "calc__Q26JStage7TObjectFPCfRA3_f": "JStage::TObject::calc(const float *, float (&)[3])",
    "set__4TMapFPFPvi_vPv": "TMap::set(void (*)(void *, int), void *)",
    "mix__4TMixFiiT1N21": "TMix::mix(int, int, int, int, int)",
    "OSReport__FPCce": "OSReport(const char *, ...)",
}


class CodeWarriorNameTests(unittest.TestCase):
    def test_demangle_and_mangle_back(self):
        for symbol, text in CASES.items():
            parsed = cwnames.parse(symbol)
            self.assertIsNotNone(parsed, symbol)
            self.assertEqual(str(parsed).replace("[3]", "[3]"), text, symbol)
            self.assertEqual(cwnames.mangle(parsed), symbol)

    def test_plain_names_are_not_members(self):
        for symbol in ("OSInit", "fn_80003020", "__init_registers", "lbl_80450000", "TPlayer__sub_80003010"):
            self.assertIsNone(cwnames.parse(symbol), symbol)

    def test_an_override_takes_its_base_signature(self):
        base = cwnames.parse("update__6TActorFPvi")
        self.assertEqual(cwnames.member("update", "TEnemy", base), "update__6TEnemyFPvi")


if __name__ == "__main__":
    unittest.main()
