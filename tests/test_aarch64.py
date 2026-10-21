"""AArch64 decoding: the registers instructions read and write, and the argument registers a function takes."""

import support  # noqa: F401  (isolates config, cache and state)
import unittest

from zkit import aarch64
from zkit.aarch64 import V


class RegisterUseTests(unittest.TestCase):
    def test_reads_and_writes_as_llvm_objdump_reads_them(self):
        cases = {
            0x4EA01C08: ({V}, {V + 8}),            # mov v8.16b, v0.16b
            0xAA0003F3: ({0}, {19}),               # mov x19, x0
            0xB9028A63: ({19, 3}, set()),          # str w3, [x19, #0x288]
            0x39066001: ({0, 1}, set()),           # strb w1, [x0, #0x198]
            0x9E380008: ({V}, {8}),                # fcvtzs x8, s0
            0x9E220000: ({0}, {V}),                # scvtf s0, x0
            0xBC470C41: ({2}, {V + 1, 2}),         # ldr s1, [x2, #0x70]!
            0x7294BC69: ({9}, {9}),                # movk w9, #0xa5e3
            0x1E2703E0: (set(), {V}),              # fmov s0, wzr
            0x1E212000: ({V, V + 1}, set()),       # fcmp s0, s1
            0x1A9F07E0: (set(), {0}),              # cset w0, ne
            0xA9017BFD: (set(), set()),            # stp x29, x30, [sp, #0x10]: neither is an argument
            0xD65F03C0: (set(), set()),            # ret (x30)
            0x1E220822: ({V + 1, V + 2}, {V + 2}),  # fmul s2, s1, s2
            0x2D400D02: ({8}, {V + 2, V + 3}),     # ldp s2, s3, [x8]
        }
        for word, (reads, writes) in cases.items():
            read, written = aarch64.register_use(word)
            self.assertEqual(({r for r in read if r != 30 and r != 29}, {w for w in written if w not in (29, 30)}),
                             (reads, writes), hex(word))
        self.assertEqual(set(aarch64.register_use(0x94000000)[1]), aarch64.CALL_CLOBBERED)   # bl

    def test_argument_reads_follow_every_path_and_stop_at_calls(self):
        # cbz x1, else; ldr w0, [x2]; ret; else: mov w0, wzr; ret
        self.assertEqual(aarch64.argument_reads([0xB4000061, 0xB9400040, 0xD65F03C0, 0x2A1F03E0, 0xD65F03C0], 0),
                         {1, 2})
        # bl; mov x0, x3; ret: what follows a call is the call's, not the caller's
        self.assertEqual(aarch64.argument_reads([0x94000000, 0xAA0303E0, 0xD65F03C0], 0), set())
        # mov v8.16b, v0.16b; ret: a float argument
        self.assertEqual(aarch64.argument_reads([0x4EA01C08, 0xD65F03C0], 0), {V})


class JoinTests(unittest.TestCase):
    # cbz w0, else; adrp x8, page; ldr s0, [x8, #0x10]; b end; else: strb w9, [x8]; nop; end: ret
    WORDS = [0x34000080, 0x90000028, 0xBD401100, 0x14000003, 0x39000109, 0xD503201F, 0xD65F03C0]

    def test_a_register_after_a_jump_holds_what_the_branches_to_it_hold(self):
        """The store is reached only from the cbz, before the adrp: x8 holds no page there, so it refers to
        nothing, though straight-line reading would take it for a store into the page."""
        self.assertEqual(sorted(aarch64.track_addresses(self.WORDS, 0x1000)), [0x1008])
        relocations, _ = aarch64.code_relocations(self.WORDS, 0x1000, {})
        self.assertEqual(sorted((r.offset, r.target) for r in relocations), [(0x1004, 0x5010), (0x1008, 0x5010)])
        self.assertEqual(aarch64.global_stores(self.WORDS, 0x1000), set())

if __name__ == "__main__":
    unittest.main()
