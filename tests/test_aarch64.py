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

    def test_atomics_read_their_operands_and_write_the_register_given_the_old_value(self):
        cases = {
            0xB8210040: ({1, 2}, {0}),             # ldadd w1, w0, [x2]
            0xF8E300A4: ({3, 5}, {4}),             # ldaddal x3, x4, [x5]
            0xB8268107: ({6, 8}, {7}),             # swp w6, w7, [x8]
            0xB8BFC149: ({10}, {9}),               # ldapr w9, [x10]
            0xB82B019F: ({11, 12}, set()),         # stadd w11, [x12]
            0x88AD7DEE: ({13, 14, 15}, {13}),      # cas w13, w14, [x15]
            0xC8F0FE51: ({16, 17, 18}, {16}),      # casal x16, x17, [x18]
            0x48207C82: ({0, 1, 2, 3, 4}, {0, 1}),  # casp x0, x1, x2, x3, [x4]
            0x88DFFCC5: ({6}, {5}),                # ldar w5, [x6]
            0x889FFD07: ({7, 8}, set()),           # stlr w7, [x8]
            0x885FFD49: ({10}, {9}),               # ldaxr w9, [x10]
            0x880BFDAC: ({12, 13}, {11}),          # stlxr w11, w12, [x13]
        }
        for word, (reads, writes) in cases.items():
            self.assertEqual(tuple(map(set, aarch64.register_use(word))), (reads, writes), hex(word))
            self.assertEqual(set(aarch64.written(word)) - {31}, writes, hex(word))

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

class IndirectCallTests(unittest.TestCase):
    def test_a_register_branch_is_a_call_unless_a_jump_table_formed_its_target(self):
        """`ldr x2, [x8, #0x10]; br x2` leaves the function (a tail call through a member or function pointer);
        `adr x9; ldrb w8, [x10, x0]; add x8, x9, x8, lsl #2; br x8` is a switch's jump table; blr always calls."""
        self.assertEqual(aarch64.indirect_calls([0xF9400902, 0xD61F0040]), 1)
        self.assertEqual(aarch64.indirect_calls([0x10000089, 0x38606948, 0x8B080928, 0xD61F0100]), 0)
        self.assertEqual(aarch64.indirect_calls([0xD63F0100, 0xD65F03C0]), 1)


class RelocationTests(unittest.TestCase):
    def test_an_add_into_the_page_register_ends_the_page(self):
        """`adrp x8, page; add x8, x8, #0x110` leaves x8 holding the whole address: a load through it after that
        reads at an offset from that address, not at an offset into the page, and relocates nothing. So does a
        load that overwrites another register holding a page."""
        # adrp x8, page; add x8, x8, #0x110; ldr s0, [x8, #0x48]; adrp x9, page; ldr x9, [x8]; ldr w1, [x9, #4]
        words = [0x90000028, 0x91044108, 0xBD404900, 0x90000009, 0xF9400109, 0xB9400521, 0xD65F03C0]
        relocations, _ = aarch64.code_relocations(words, 0x1000, {})
        self.assertEqual(sorted((r.offset, r.target) for r in relocations), [(0x1000, 0x5110), (0x1004, 0x5110),
                                                                            (0x100C, 0x1000)])
        self.assertEqual(sorted(aarch64.track_addresses(words, 0x1000).items()), [(0x1004, (0x5110, "addr"))])

    def test_a_floating_point_write_leaves_the_page_register(self):
        """`fmul s8, s1, s2` writes v8, not x8: an adrp x8 before it still pairs with the add after it. A
        conversion to an integer register (`fcvtzs w8, s0`, `fmov w8, s0`) does replace the page."""
        # adrp x8, page; fmul s8, s1, s2; scvtf s8, w0; add x8, x8, #0x10; ret
        words = [0x90000028, 0x1E220828, 0x1E220008, 0x91004108, 0xD65F03C0]
        relocations, _ = aarch64.code_relocations(words, 0x1000, {})
        self.assertEqual(sorted((r.offset, r.target) for r in relocations), [(0x1000, 0x5010), (0x100C, 0x5010)])
        for word in (0x1E380008, 0x1E260008, 0x0E0C3C08):            # fcvtzs w8, s0; fmov w8, s0; mov w8, v0.s[1]
            self.assertEqual(aarch64.written(word), (8,), hex(word))
        for word in (0x1E220828, 0x1E220008, 0x1E270008, 0x4EA01C08):  # fmul; scvtf; fmov s8, w0; mov v8.16b
            self.assertEqual(aarch64.written(word), (), hex(word))

    def test_a_got_load_reads_a_slot_of_the_got_not_any_relocated_pointer(self):
        """`ldr x, [page, #lo12]` of a relocated word is a GOT load (to the pointee) only when the word is a slot
        of `.got`: element 0 of a pointer table in `.data` is relocated too, yet its load is a plain LDST64 of the
        table, its adrp an ADR_PREL_PG_HI21. Without a known `.got` every relocated pointer counts as a slot."""
        # adrp x8, page; ldr x9, [x8, #0x10]; adrp x11, page; ldr x10, [x11, #0x20]; ret
        words = [0x90000028, 0xF9400909, 0x9000002B, 0xF940116A, 0xD65F03C0]
        pointers = {0x5010: 0x9000, 0x5020: 0x9100}   # a table's element (to a string), a GOT slot
        found, cleared = aarch64.code_relocations(words, 0x1000, pointers, got=(0x5020, 0x5030))
        self.assertEqual(sorted((r.offset, r.kind, r.target, r.got) for r in found), [
            (0x1000, aarch64.ADR_PREL_PG_HI21, 0x5010, False), (0x1004, aarch64.LDST64, 0x5010, False),
            (0x1008, aarch64.ADR_GOT_PAGE, 0x9100, True), (0x100C, aarch64.LD64_GOT_LO12_NC, 0x9100, True)])
        self.assertEqual(cleared[0x1004], 0xF9400109)
        found, _ = aarch64.code_relocations(words, 0x1000, pointers)
        self.assertEqual([r.kind for r in found], [aarch64.ADR_GOT_PAGE, aarch64.LD64_GOT_LO12_NC,
                                                   aarch64.ADR_GOT_PAGE, aarch64.LD64_GOT_LO12_NC])


class ObjectCodeTests(unittest.TestCase):
    def test_an_objects_relocations_are_named_as_linked_code_finds_them(self):
        """An object's `adrp` relocation without an overflow check is the page relocation linked code shows; a
        data relocation is never one `code_relocations` finds in code."""
        self.assertEqual(aarch64.object_kind(aarch64.ADR_PREL_PG_HI21_NC), aarch64.ADR_PREL_PG_HI21)
        self.assertEqual(aarch64.object_kind(aarch64.CALL26), aarch64.CALL26)
        self.assertEqual(aarch64.object_kind(aarch64.LD64_GOT_LO12_NC), aarch64.LD64_GOT_LO12_NC)
        self.assertIsNone(aarch64.object_kind(aarch64.ABS64))

    def test_what_an_assembler_resolved_is_what_a_linker_relocates(self):
        """An assembler resolves a call or an address within its own section and leaves the object no relocation
        for it: such a call, adrp, adr or literal load is still relocated in linked code, a branch only when it
        leaves the function."""
        cases = {0x94000003: aarch64.CALL26,               # bl +12
                 0x14000002: None,                         # b +8, inside the 16 bytes
                 0x14000010: aarch64.JUMP26,               # b +0x40, past the end
                 0x17FFFFFF: aarch64.JUMP26,               # b -4, before the start
                 0x90000000: aarch64.ADR_PREL_PG_HI21,     # adrp x0
                 0x10000001: aarch64.ADR_PREL_LO21,        # adr x1
                 0x58000002: aarch64.LD_PREL_LO19,         # ldr x2, literal
                 0x18000002: aarch64.LD_PREL_LO19,         # ldr w2, literal
                 0x91000000: None}                         # add x0, x0, #0
        for word, kind in cases.items():
            self.assertEqual(aarch64.assembled(word, 0, 16), kind, hex(word))

    def test_relaxed_address_pairs_take_one_form(self):
        """A GOT load of one register (`adrp x8` + `ldr x8, [x8]`) and a `nop` + `adr x3` (what lld makes of an
        `adrp` + `add` near its target) both read as `adrp` + `add`, as cleared; a GOT load into another register
        than its page's, or with an instruction between its two, is left alone."""
        nop = aarch64.NOP
        words = [0x90000008, 0xF9400108, nop, 0x10000003, 0x90000008, 0xF9400109, 0x90000008, nop, 0xF9400108]
        kinds = {0: aarch64.ADR_GOT_PAGE, 1: aarch64.LD64_GOT_LO12_NC, 3: aarch64.ADR_PREL_LO21,
                 4: aarch64.ADR_GOT_PAGE, 5: aarch64.LD64_GOT_LO12_NC, 6: aarch64.ADR_GOT_PAGE,
                 8: aarch64.LD64_GOT_LO12_NC}
        self.assertEqual(aarch64.unrelaxed(words, kinds), [0, 2])
        self.assertEqual(words, [0x90000008, 0x91000108, 0x90000003, 0x91000063, 0x90000008, 0xF9400109,
                                 0x90000008, nop, 0xF9400108])
        self.assertEqual(kinds, {0: aarch64.ADR_PREL_PG_HI21, 1: aarch64.ADD_ABS_LO12_NC,
                                 2: aarch64.ADR_PREL_PG_HI21, 3: aarch64.ADD_ABS_LO12_NC,
                                 4: aarch64.ADR_GOT_PAGE, 5: aarch64.LD64_GOT_LO12_NC, 6: aarch64.ADR_GOT_PAGE,
                                 8: aarch64.LD64_GOT_LO12_NC})


class RelaxerTests(unittest.TestCase):
    """lld's AArch64Relaxer (LLVM 23), rule for rule, on one input section's relocations."""
    GOT, LD64 = aarch64.ADR_GOT_PAGE, aarch64.LD64_GOT_LO12_NC
    PAGE, ADD = aarch64.ADR_PREL_PG_HI21, aarch64.ADD_ABS_LO12_NC
    WORDS = {0x00: 0x90000008, 0x04: 0xF9400108,                        # adrp x8 + ldr x8, [x8]: s1
             0x10: 0x90000009, 0x14: 0xD503201F, 0x18: 0xF9400129,      # s2's load, parted by a nop
             0x20: 0x90000009, 0x24: 0xF9400129,                        # s2 again, adjacent
             0x30: 0x9000000C, 0x34: 0xF940018C,                        # s3, an import
             0x40: 0x9000000A, 0x44: 0x9100014A,                        # adrp x10 + add x10, x10: s4
             0x50: 0x9000000B, 0x54: 0x9100216B}                        # s5 + 8

    def relocations(self, order):
        from zkit.elf import Relocation
        table = {0x00: (self.GOT, 1, 0), 0x04: (self.LD64, 1, 0), 0x10: (self.GOT, 2, 0), 0x18: (self.LD64, 2, 0),
                 0x20: (self.GOT, 2, 0), 0x24: (self.LD64, 2, 0), 0x30: (self.GOT, 3, 0), 0x34: (self.LD64, 3, 0),
                 0x40: (self.PAGE, 4, 0), 0x44: (self.ADD, 4, 0), 0x50: (self.PAGE, 5, 8), 0x54: (self.ADD, 5, 8)}
        return [Relocation(offset, *table[offset]) for offset in order]

    def pairs(self, relocations, near=None):
        return {relocations[i].offset: form for i, form in aarch64.relaxed_pairs(
            relocations, self.WORDS.__getitem__, lambda i: relocations[i].symbol != 3, near).items()}

    def test_a_symbol_s_got_loads_in_a_section_relax_all_or_none(self):
        """s1's adjacent GOT load becomes adrp + add, and nop + adr once its target is near; s2's adjacent load
        stays, as its other load in the section is parted (before it or after it); the import's load stays; an
        adrp + add with an addend is never relaxed."""
        order = sorted(self.WORDS.keys() - {0x14})
        self.assertEqual(self.pairs(self.relocations(order)), {0x00: "add"})
        self.assertEqual(self.pairs(self.relocations(order), lambda i: True), {0x00: "adr", 0x40: "adr"})
        self.assertEqual(self.pairs(self.relocations(order), lambda i: False), {0x00: "add"})
        swapped = [0x00, 0x04, 0x20, 0x24, 0x10, 0x18, 0x30, 0x34]
        self.assertEqual(self.pairs(self.relocations(swapped)), {0x00: "add"})
        self.assertEqual(self.pairs(self.relocations([0x20, 0x24])), {0x20: "add"})   # alone in its section

    def test_a_lone_load_or_a_narrow_load_keeps_the_symbol_s_got_loads(self):
        """lld reads bit 31 of the load (its "sf" check): a byte load fails it."""
        from zkit.elf import Relocation
        alone = self.relocations([0x00, 0x04]) + [Relocation(0x60, self.LD64, 1, 0)]
        self.assertEqual(self.pairs(alone), {})
        narrow = dict(self.WORDS)
        narrow[0x04] = 0x39400108                                       # ldrb w8, [x8]
        relocations = self.relocations([0x00, 0x04])
        self.assertEqual(aarch64.relaxed_pairs(relocations, narrow.__getitem__, lambda i: True), {})

    def test_a_nop_and_adr_out_of_the_function_reads_as_the_pair_it_was(self):
        """On a relaxing target `nop` + `adr x3, s` with s outside the function is the `adrp` + `add` lld made it
        from, as cleared; an adr into the function (a jump table's base) stays an adr, as does every adr when
        the target's linker did not relax."""
        nop = aarch64.NOP
        words = [nop, 0x10000803, nop, 0x10000024, 0xD65F03C0]        # adr x3, +0x100; adr x4, +4 (the ret)
        found, cleared = aarch64.code_relocations(words, 0x1000, {}, relaxed=True)
        self.assertEqual([(r.offset, r.kind, r.target) for r in found], [
            (0x1000, self.PAGE, 0x1104), (0x1004, self.ADD, 0x1104), (0x100C, aarch64.ADR_PREL_LO21, 0x1010)])
        self.assertEqual((cleared[0x1000], cleared[0x1004]), (0x90000003, 0x91000063))
        found, _ = aarch64.code_relocations(words, 0x1000, {})
        self.assertEqual([r.kind for r in found], [aarch64.ADR_PREL_LO21, aarch64.ADR_PREL_LO21])


if __name__ == "__main__":
    unittest.main()
