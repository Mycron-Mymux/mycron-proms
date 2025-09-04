#!/usr/bin/env python3
"""
This generates a commented disasembly file from the PROM chips of the Z-80 based DIM-1003.

It is work-in-progress, but this file can be examined to find some of the functionality
present in the PROMs and how it is implemented. This was useful for creating the emulator
and providing floppy disk support in the emulator. 
"""

import sys
from z80lib import Memory

prom0 = list(open(sys.argv[1], 'rb').read())
prom1 = list(open(sys.argv[2], 'rb').read())
# gap = bytes(0x800)
# adding jump table from the dump below
gap = [0] * 0x800
gap[0x7e0:0x7f0] = [0x00, 0x00, 0x00, 0x00, 0xC3, 0xAD, 0x03, 0xC3,
                    0x4C, 0x03, 0xC3, 0x31, 0x03, 0xC3, 0x41, 0x03]
assert len(gap) == 0x800, f"Gap should be len 0x800, is now {hex(len(gap))}"
pad = [0] * 0x100  # TODO: workaround for memdump error

# This data is set up after the prom boots.
# Need to add some of it into the gap memory
# Ah... mycrop init at 0x248 copies the table at 0x142 to 0xfe4!
prom1_fill="""
0F00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0F80: 00 00 00 00 00 00 00 00 00 00 00 00 50 03 80 0F
0F90: 89 03 91 0F 89 04 50 03 98 0F 83 05 84 FF 00 0F
0FA0: A2 02 FF 0F 00 00 99 02 A5 02 44 00 01 0F A2 10
0FB0: 00 0F 00 00 6E 05 00 0E A2 02 00 0F 00 00 63 01
0FC0: A5 02 00 00 00 00 00 00 00 F0 00 00 00 00 00 00
0FD0: B8 0F AA 0F 00 00 00 00 00 00 00 00 00 00 00 00
0FE0: 00 00 00 00 C3 AD 03 C3 4C 03 C3 31 03 C3 41 03
0FF0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
"""

rawmem = prom0 + gap + prom1 + pad
print(';', len(rawmem))
mem = Memory(rawmem)
# ------------------------ prom 0 --------------------------

with mem.section(0, 0x3f, "irq table") as m:
    m.comment("; Z80 starts executing at addr 0. This is also interrupt 0")
    m.comment("; Corresponds to table 4.1 on page 2-14 of DIM-1001 documentation")
    m.comment("; the nops are probably padding / unused since mycrop doesn't use all of the space")
    m.comment("; most irqs just re-route to a jump table that prints an error corresponding to the irq")
    m.parse_nbytes(0x00, 8, "jump to init / IRQ 0", symbol="irq0")
    m.parse_nbytes(0x08, 8, "interrupt 1", symbol="irq1")
    m.parse_nbytes(0x10, 8, "interrupt 2", symbol="irq2")
    m.parse_nbytes(0x18, 8, "interrupt 3", symbol="irq3")
    m.parse_nbytes(0x20, 8, "interrupt 4", symbol="irq4")
    m.parse_nbytes(0x28, 8, "interrupt 5", symbol="irq5")
    m.parse_nbytes(0x30, 8, "interrupt 6", symbol="irq6")
    m.parse_nbytes(0x38, 8, "interrupt 7", symbol="irq7")
    m.add_sym("ram_jtab_irq0", 0xbe8)
    m.add_sym("ram_jtab_irq1", 0xbeb)
    m.add_sym("ram_jtab_irq2", 0xbee)
    m.add_sym("ram_jtab_irq3", 0xbf1)
    m.add_sym("ram_jtab_irq4", 0xbf4)
    m.add_sym("ram_jtab_irq5", 0xbf7)
    m.add_sym("ram_jtab_irq6", 0xbfa)
    m.add_sym("ram_jtab_irq7", 0xbfd)

with mem.section(0x40, 0x6f, "monitor entry jump table") as m:
    m.parse_pos(0x40, "MON - monitor entry p10")
    m.parse_pos(0x43, "MONERR - print error p11")
    m.parse_pos(0x46, "MONCR  - return to monitor without print - p11")
    m.parse_pos(0x49, "CRLF   - prints CR,LF")
    m.parse_pos(0x4c, "TTCON  - output text - p12")
    m.parse_pos(0x4f, "TTCLF  - TTCON + CR,LF - p12")
    m.parse_pos(0x52, "TTI    - input char without echo - p12")
    m.parse_pos(0x55, "TTIO   - input char with echo - p13")
    m.parse_pos(0x58, "TTO    - output character - p13")
    m.parse_pos(0x5b, "DREG   - display reg content - p13")
    m.parse_pos(0x5e, "DMEM   - display mem contens - p14")
    m.parse_pos(0x61, "OUTHX  - output single byte number - 14")
    m.parse_pos(0x64, "OUTH2  - output double byte number")
    m.parse_pos(0x67, "INHEX  - input single byte hex - p15")
    m.parse_pos(0x6a, "INHX2  - input double byte hex ")
    m.parse_pos(0x6d, "LOAD   - load program from diskette")

with mem.section(0x70, 0x8f, "diskette service routines (5.17)") as m:
    m.comment("looks a bit like dim-1030 page 6-32, execpt 1030 has WAIT on offset 0x18.")
    m.comment("offset D would then be 0x70. Se comments above BDO for error codes.")
    m.parse_pos(0x70, "BDO - basic diskette open p18")
    m.parse_pos(0x73, "BRDR - Basic diskette read")
    m.parse_pos(0x76, "BWDR - basic diskette write")
    m.parse_pos(0x79, "BDDR - Basic diskette delete")
    m.parse_pos(0x7c, "BDC  - Basic diskette close")
    m.parse_pos(0x7f, "BDD  - Basic diskette head down")
    m.parse_pos(0x82, "BLDR - Basic diskette load")
    m.parse_pos(0x85, "BUDR - Basic diskette unload")
    m.parse_pos(0x88, "LINK - Load and Start program")
    m.parse_pos(0x8b, "NIBBLE - Test for Hexadecimal digit")

with mem.section(0x83, 0x100, "extra jump table / unknown") as m:
    m.parse_nbytes(0x8e, 3, "unknown jump entry")
    m.parse_nbytes(0x91, 3, "unknown jump entry")
    m.parse_nbytes(0x94, 3, "unknown jump entry")
    m.parse_nbytes(0x97, 3, "unknown jump entry")
    m.parse_nbytes(0x9a, 3, "unknown jump entry")
    m.parse_nbytes(0x9d, 3, "unknown jump entry")
    m.parse_nbytes(0xa0, 3, "unknown jump entry")
    m.parse_nbytes(0xa3, 3, "unknown jump entry")
    m.parse_nbytes(0xa6, 3, "unknown jump entry")
    m.parse_nbytes(0xa9, 3, "unknown jump entry")
    m.parse_nbytes(0xac, 3, "unknown jump entry")
    m.parse_nbytes(0xaf, 3, "unknown jump entry")
    m.parse_nbytes(0xb2, 3, "unknown jump entry")
    m.parse_nbytes(0xb5, 3, "unknown jump entry")
    m.parse_nbytes(0xb8, 3, "unknown jump entry")
    m.parse_nbytes(0xbb, 3, "unknown jump entry")
    m.parse_nbytes(0xbe, 3, "unknown jump entry")
    m.comment("might be a few open entries and a few more filled in")


with mem.section(0x100, 0x14f, "strings and maybe consts") as m:
    ...


with mem.section(0x140, 0x300, "MYCROP init at 0x14e") as m:
    m.comment("0x166 -> 0x177 - init of lvl 2 jump table for interrupts")
    m.parse(0x14e, 0x257, "MYCROP (int 0) init", {
        0x158 : "TODO: this is the mystery port that it reads from further down (send 1 to port $14)",
        0x166 : "lvl 2 irq jump table init loop setup - prints errors for irq  1..5 and 7",
        0x16b : "all entries point to this addr",
        0x177 : "back up to lvl2 irq jump table loop",
        0x17f : "not sure what is connected to this port",
        # 0FD0: D0 0F C2 0F FF FF FF FF FF FF 00 9B FF FF FF FF
        0x181 : "stores input value in $fdb (this is also used further down in init). memdump suggests it was 9b on one computer (verified with extra read later)",
        0x184 : "if bit $80 is set, store $ff. Else store 0 in fde.",
        0x194 : "sets interrupt mode to 2 - z80 mode",
        0x19a : "read back data received from port $14",
        0x1a2 : "checking the memory dump on the mycron: ff0 has 6, which matches (9b >> 2) & 0x7",
        0x1d2 : "read back data received from port $14",
        0x1e1 : "read back data received from port $14",
        0x1fc : "read back data received from port $14",
        0x20d : "write $80 (if $80 was set on data from $14) or $20 to port 2",
        0x248 : "copy jump table from prom to upper part of work section between the two proms",
        0x257 : "jumps inside the MON entry (after the two CALLs)",
    }, symbol="MYCROP_INIT")
    m.add_sym("_MYCROP_INIT_irq_setup", 0x166)
    m.add_sym("_MYCROP_INIT_irq_l1", 0x170)
    m.add_sym("_MYCROP_INIT_18b", 0x18b)
    m.add_sym("_MYCROP_INIT_console", 0x1cb)
    m.add_sym("_MYCROP_INIT_20b", 0x20b)
    m.add_sym("_MYCROP_INIT_20d", 0x20d)

    # - ld c, n    - 7 cycles
    # - nop        - 4 cycles,
    # - dec c      - 4 cycles
    # - jp nz, nn  - 10 cyccles
    # - dec b      - 4 cycles
    # - the dim1001 card had 8080 at 2MHz, not sure about z80
    # - so this is about half a milisecond worth of sleep.
    m.comment("This is probably 5.5.9 WAIT (from dim 1030)")
    m.comment("The WAIT routine may be used to delay program execution a specified number of")
    m.comment("milliseconds.")
    m.comment("B - number of milliseconds delay desired")
    m.parse(0x25a, 0x26d,   "'delay' call target, loops for 'b' X  (7 + 0x25d * 18=10897 cycles)",
            symbol="SOME_DELAY")
    m.add_sym("_SOME_DELAY_l1", 0x25b)
    m.add_sym("_SOME_DELAY_l2", 0x25d)

    m.parse(0x26e, 0x277,  "; --- gap between 26e and 277", symbol="q__prompt_or_ret_26e")
    m.add_sym("_q_prompt_or_ret_26e_t1", 0x272)

    m.parse(0x278, 0x286,   "- printerror called by monerr", {
        0x279 : "addr to ERROR string",
    }, symbol="print_error")
    
    m.parse(0x287, 0x289,   "- clear screen???  $19 is EM - end of medium in C0 control codes", {
    }, symbol="q_clear_screen")
    
    m.parse(0x28c, 0x290,   "- ??? - looks like it's ised in the irq2 entry table set up by MYCROP_INIT", {
    }, symbol="q_irq_printerr")
    

    m.parse(0x291, 0x295,   "MONERR (0x43) entry", {
        0x292 : "print error string",
    }, symbol="MONERR")
    m.add_sym("_MONERR_nopush_af", 0x292)

    # IRQ 6 (breakpoint) also jumps here.
    m.parse(0x296, 0x2c8, "MON entry (irq 6 should jump here)", {
        0x29c : "load addr to mycrop header text",
        0x2a2 : "entry when the mycrop header is not needed",
        0x2a5 : "print prompt (*)",
        0x2aa : "set monitor stack?",
        0x2b2 : "load constant (0x41 = 'A') from 2c9 and check that it's non-zero",
        0x2ba : "load (2ca = 0x33) to e",
        0x2ba : "load (2ca = 0x5) to d",
        0x2bf : "compare input char with the value from 2c9",
        0x2c0 : "try next entry",
        0x2c3 : "found matching. push return addr of 2a2 (above) onto stack and _jump_",
    }, symbol="MON")
    m.add_sym("_MON_print_mycrophdr", 0x29c)
    m.add_sym("_MON_CRLF_promptonly", 0x2a2)
    m.add_sym("_MON_promptonly", 0x2a5)
    m.add_sym("_MON_called_by_prompt_space", 0x2ae)
    m.add_sym("_MON_try_entry", 0x2b5)

    m.comment("0x2c9 and on are jump targets : char + addr")
    m.comment("   2c9 : 41='A', 0533") 
    m.comment("   2cc : 43='C', 05EB - compare memory areas and display the locations with different contents (from bo gøran kvamme's picture)") 
    m.comment("   2cf : 44='D', 0564 - doc: display memory contents") 
    m.comment("   2d2 : 45='E', 0644 - strange entry into L")
    m.comment("   2d5 : 46='F', 0629 - doc: fill memory with specific contents")
    m.comment("   2d8 : 47='G', 1000 - doc: start execution of program")
    m.comment("   2db : 49='I', 05DA - interrupt disable or enable (from bo gøran kvamme's picture) (use: IE or ID)") 
    m.comment("   2de : 4C='L', 0649 - doc: load program from diskette")  
    m.comment("   2e1 : 4D='M', 05AA - move memory area (from bo gøran kvamme's picture)")
    m.comment("   2e4 : 53='S', 079C - doc: display and alter memory contents") # not decoded
    m.comment("   2e7 : 55='U', 038E - toggles caps lock on input (from disasembly)")
    m.comment("   2ea : 75='u', 038E - toggles caps lock on input (from disasembly)")
    m.comment("   2ed : 58='X', 06FD - doc: display and alter register contents")
    m.comment("   2f0 : 20=' ', 02AE - ignore this and read next char")
    m.comment(r"   2f3 : 0D='\r', 02A2 - back to the prompt")
    m.comment("   2f6 : 1d= , 0287 - TODO: is this the clear screen/home?")
    m.add_jump_targs([0x533, 0x5eb, 0x564, 0x644, 0x629, 0x1000, 0x5da, 0x649, 0x5aa, 0x79c, 0x38e, 0x6fd, 0x2ae, 0x2a2, 0x287])
    

    m.parse(0x2fa, 0x30b, "TTI (0x52) entry", symbol="TTI")

with mem.section(0x300, 0x400, "Section 300 mycrop") as m:
    # ----- 300
    m.parse(0x30c, 0x32e, "??? jump target from TTI (0x2ff)", {
        0x32e : "jumping to TTI entry"
    })
    m.add_sym("_qt_30c_31d", 0x31d)

    m.parse(0x331, 0x340, "MONCR (0x46) monitor entry point (special)", {
        0x334 : "read status register for serial port",
        0x336 : "check input ready (bit 0)",
        0x339 : "read 7-bit char from input and check that it's not a zero (used by monitor menu including parameters)",
        0x33e : "subtract 1 from a and update flags",
    }, symbol="MONCR")

    m.parse(0x341, 0x348, "check if console write space??? call target used by TTO", {
        0x342 : "after the sub (A-A), write a 0 to the control port",
        0x344 : "check if output buf ready on serial port (0x4)",
        0x346 : "z and h (half carry) are influenced. - if 4, then H is set and Z is low",
    }, symbol="console_rdy")

    m.parse(0x349, 0x34a, "TTIO (0x55) entry", symbol="TTIO")

    m.parse(0x34c, 0x376, "TTO (0x58) entry", {
        0x36d : "recursive call to self?",
    }, symbol="TTO")
    m.add_sym("_TTO_rd1", 0x34d)
    m.add_sym("_TTO_t1", 0x368)
    m.add_sym("_TTO_t2", 0x36d)

    m.parse(0x377, 0x38d, "??? call target")
    m.add_sym("_qtarg_38b", 0x38b)

    m.parse(0x38e, 0x397, "toggle upper and lower case input", {
        0x38f: "just toggles 0fe3 betweeen ff (upper case) and 00 (lower case)"
    }, symbol="mycrop_menu_entry_U_helper")

    m.parse(0x398, 0x3ac, "possible sanity check if character input controlled by flag", {
        0x399: "checks if upper case input is set (see function above)",
        0x39e: "return as is if flag(?) stored in fe3 (mycrop init does this) != 0xff",
        0x3a2: "return as is if a < $61",
        0x3a8: "clear upper bits if a >= $7f (q: why not and with 7f?)",
        }, symbol="inchar_possible_uppercase")
    m.add_sym("_inchar_uppercase_t1", 0x3ab)

    m.parse(0x3ad, 0x3b6, "called by MON entry", {
    }, "q_input_with_echo")

    m.parse(0x3b7, 0x3b9, "not sure", {
    })

    m.parse(0x3ba, 0x3bf, "??? call target", {
        0x3bc: "ret if a not $7f",
        0x3bd: "jump to 2a2 in MON (where MON calls CRLF)",
    }, symbol="q_ret_or_mon_prompt")

    m.parse(0x3c0, 0x3d1, "print /, space, then backspace (clear char after / prompt)", {
        0x3c0: "prints '/'",
        0x3c5: "prints space",
        0x3cb: "backspace",
    }, symbol="print_slashprompt")
    m.add_sym("_print_slashprompt_clear_one", 0x3c5)
    m.add_sym("_print_slashprompt_backspace", 0x3ca)


    m.parse(0x3d2, 0x3d5, "??? call target (from DMEM)", symbol="print_space")
    
    m.parse(0x3d7, 0x3e3, "??? call target", symbol="q_maybe_read_4_hexdigits")
    m.add_sym("_q_maybe_read_h4_t1", 0x3de)

    m.parse(0x3e4, 0x3e5, "??? call target",
            symbol="q_maybe_hex_input")

    m.parse(0x3e7, 0x403, "NIBBLE (0x8b) entry", symbol="NIBBLE")
    m.add_sym("_NIBBLE_t1", 0x3fd)
    m.add_sym("_NIBBLE_t2", 0x401)

with mem.section(0x400, 0x500, "Section 400 mycrop") as m:
    # ----- 400
    m.parse(0x404, 0x40c, "??? call target")

    m.parse(0x40d, 0x414, "??? call target - rotates left 4 bits/positions, ands with 0xf0 and loads res to b", symbol="rleft_4")

    m.parse(0x415, 0x425, "INHEX (0x67) entry", {
    }, symbol="INHEX")
    m.add_sym("_INHEX_t1", 0x418)
    m.add_sym("_INHEX_t2", 0x424)

    m.parse(0x426, 0x430, "INHX2 (0x6d) entry", {
    }, symbol="INHX2")
    m.add_sym("_INHX2_t1", 0x429)

    m.parse(0x431, 0x441, "???? target from jump at 0xa9", {
    }, symbol="q_from_0xa9")
    m.add_sym("_q_431_440", 0x440)

    m.parse(0x442, 0x44c, "???? target from jump at 0xac", {
    }, symbol="q_from_0xac")

    m.parse(0x44d, 0x45d, "TTCON (0x4c) entry", {
    }, symbol="TTCON")
    m.add_sym("_TTCON_t1", 0x44f)
    m.add_sym("_TTCON_t2", 0x45b)

    m.parse(0x45e, 0x45f, "TTCLF (0x4f) entry", {
    }, symbol="TTCLF")

    m.parse(0x461, 0x46d, "CRLF (0x49) entry", {
        0x464 : "call TTO",
    }, symbol="CRLF")

    m.parse(0x46e, 0x477, "jump target from DREG and called by DMEM", {
        0x470: "nb: this _calls_ tto, the one on 475 _jumps_ to tto to re-use the return",
    }, symbol="crlf_v2")

    m.parse(0x478, 0x48b, "OUTHX (0x61) entry", {
        0x479: "set jump target after print_hex_digit to TTO",
        0x47c: "store current a(and f) before shift right of a for first digit",
        0x484: "restore a for second digit, and store af again",
    }, symbol="OUTHX")
    m.add_sym("_OUTHX_t1", 0x47c)

    m.parse(0x48c, 0x494, "call target from OUTHX - uses known trick to convert lower 4 bits to hex. Then jumps to (hl).", {
        0x490: "A register is BCD corrected (9 is 0x39 A is 0x40), so add 6 if larger than '9'",
        0x494: "OUTHX sets hl to 0x34c (TTO), so that's the jump target here",
    }, symbol="print_hex_digit")

    m.parse(0x495, 0x49f, "OUTH2 (0x64) entry", {
    }, symbol="OUTH2")

    m.parse(0x4a0, 0x4a6, "??? called by below jump target from DREG (and jump table 0xa3)", {
        0x4a1: "sets hl to jump table entry for TTO",
        0x4a4: "jumps inside OUTHX",
    }, symbol="out_hex_from_0xa3")

    m.parse(0x4a7, 0x4b1, "??? jump target from DREG (and jump table 0xa6)", {
    }, symbol="out_hex2_from_0xa6")

    m.parse(0x4b2, 0x4f7, "DREG (0x5b) entry", {
        0x4c5: "TODO: is this the table in the gap below?",
    }, symbol="DREG")
    m.add_sym("_DREG_t1", 0x4be)
    m.add_sym("_DREG_t2", 0x4f4)

with mem.section(0x500, 0x600, "Section 500 mycrop") as m:
    # ----- 500
    m.parse(0x50c, 0x516, "??? call entry - store regs to stack - (all?)", {
    }, symbol="store_regs_50c")

    m.comment("dump from a running myrop")
    m.comment("    :  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F")
    m.comment("0FD0: D0 0F C2 0F 00 00 00 00 00 00 00 00 00 00 00 00")
    m.comment("0FE0: 00 00 00 00 C3 AD 03 C3 4C 03 C3 31 03 C3 41 03")
    m.comment("0FF0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")

    m.parse(0x517, 0x52a, "??? called by MON og MYCROP_INIT", {
        0x517: "compare what is stored in fd4 with f7",
        0x51b: "stores sp + 2 to fd2",
        0x51e: "load (fd4) to hl, then (hl) to a and cmp with f7. fd4 is a pointer to a var but 0 above",
        0x524: "jump if not f7",
        0x527: "copy fd6 contents to (hl = what fd4 pointed to)",
    }, symbol="q_store_stack_and_more")

    m.parse(0x52b, 0x532, "part of 517. stores sp + 0x10 to 0xfd0 ", {
    }, symbol="q_store_sp_plus_10_fd0")

    m.parse(0x533, 0x54c, "called by mycrop menu entry A", {
        }, symbol="mycrop_menu_entry_A")
    m.add_sym("_mycrop_menu_a_t1", 0x55a)
    
    m.parse(0x54e, 0x563, "called by mycrop menu entry A", {
        0x55a: "compare with a CR?",
        0x55d: "compare with a comma?",
        }, symbol="mycrop_menu_entry_A_helper")
    
    m.parse(0x564, 0x56a, "called by mycrop menu entry D (display memory contents)", {
        }, symbol="mycrop_menu_entry_D_display_mem")
    
    m.parse(0x56b, 0x5a1, "DMEM (0x5e) entry", {
        0x57b: "3a is ':'",
    }, symbol="DMEM")
    m.add_sym("_DMEM_t1", 0x575)
    m.add_sym("_DMEM_t2", 0x580)
    m.add_sym("_DMEM_t3", 0x59c)


    m.parse(0x5a2, 0x5a9, "???? from DMEM", {
    })

    m.parse(0x5aa, 0x5ac, "???? ", {
    }, symbol="q_from_mycrop_m_helper")

    m.parse(0x5ad, 0x5bb, "???? from jump table 0x8e", {
    }, symbol="q_from_0x8e")

    m.parse(0x5bc, 0x5cb, "called by mycrop C helper", {
        0x5bf: "3e is '>'",
    } )

    m.parse(0x5cc, 0x5d9, "???? call target - looks like it reads two hex vals with a slash between (bc, hl)", {
    }, symbol="q_read_two_hex_addrs")

    m.parse(0x5da, 0x5ea, "called by mycrop I.  IE to enable, ID to disable", {
    }, symbol="q_from_mycrop_I_helper")
    m.add_sym("_q_mycrop_I_t1", 0x5e4)
    
    m.parse(0x5eb, 0x5ec, "from mycrop C command (continues to next instruction, it seems)", {
    }, symbol="mycrop_menu_entry_C_helper")
    
    m.parse(0x5ee, 0x628, "???? from jump table 0x91", {
    }, symbol="q_from_0x91")
    m.add_sym("_q_from_0x91_t1", 0x5f1)
    m.add_sym("_q_from_0x91_t2", 0x604)
    m.add_sym("_q_from_0x91_t3", 0x616)
    m.add_sym("_q_from_0x91_t4", 0x619)

with mem.section(0x600, 0x700, "Section 600 mycrop") as m:
    m.parse(0x629, 0x634, "???? ", {
    }, symbol="q_from_mycrop_F_helper")

    m.parse(0x635, 0x643, "???? from jump table 0x94", {
    }, symbol="q_from_0x94")
    m.add_sym("_q_from_0x94_t1", 0x639)

    m.parse(0x644, 0x648, "mycrop E menu helper", {
    }, symbol="mycrop_menu_entry_E_helper")

    m.parse(0x649, 0x6fc, "mycrop L menu helper", {
        0x64a: "continues here",
    }, symbol="mycrop_menu_entry_L_helper")
    m.add_sym("_mycrop_menu_l_t1", 0x64a)
    m.add_sym("_mycrop_menu_l_t2", 0x668)
    m.add_sym("_mycrop_menu_l_t3", 0x676)
    m.add_sym("_mycrop_menu_l_t4", 0x679)
    m.add_sym("_mycrop_menu_l_t5", 0x69e)
    m.add_sym("_mycrop_menu_l_t6", 0x6a0)
    m.add_sym("_mycrop_menu_l_t7", 0x6a7)
    m.add_sym("_mycrop_menu_l_t8", 0x6b8)
    m.add_sym("_mycrop_menu_l_t9", 0x6e6)
    m.add_sym("_mycrop_menu_l_ta", 0x6ee)

    m.parse(0x6fd, 0x756, "called by mycrop menu entry X", {
        }, symbol="mycrop_menu_entry_X")
    m.add_sym("_mycrop_menu_x_t1", 0x70c)
    m.add_sym("_mycrop_menu_x_t2", 0x730)
    

with mem.section(0x700, 0x7ff, "Section 700 mycrop") as m:
    m.comment("the table from 757 and up describes the registers. XA.. XX displays all. XIX and XIY shows the hidden regs")
    m.parse(0x763, 0x77c, "??? called by X helper", {
        0x768: "757 has the register name table",
    })

    m.parse(0x77d, 0x784, "??? ", {
    })
    
    m.parse(0x785, 0x79b, "??? called by X helper", {
    })
    m.add_sym("_q_785_t1", 0x799)
    
    m.parse(0x79c, 0x7c3, "called by mycrop menu entry S", {
        }, symbol="mycrop_menu_entry_S")
    
    m.add_sym("_mycrop_menu_S_t1", 0x7a2)
    m.add_sym("_mycrop_menu_S_t2", 0x7b6)
    m.add_sym("_mycrop_menu_S_t3", 0x7ba)
    m.add_sym("_mycrop_menu_S_t4", 0x7bf)
    

with mem.section(0xfe00, 0xfff, "Section fe00 mycrop - special section set up after boot") as m:
    m.parse(0xfe0, 0xfe3, "jump table set up by mycrop init, copied from 0x142", {
    })

    m.parse(0xfe4, 0xfe6, "fe4")
    m.parse(0xfe7, 0xfe9, "fe7", symbol="jtab_fe7_TTO")
    m.parse(0xfea, 0xfec, "fea")
    m.parse(0xfed, 0xfef, "fed")

# ------------------------ prom 1 --------------------------
with mem.section(0x1000, 0x1100, "Section 1000 mycrop") as m:
    m.parse(0x1000, 0x1038, "called from mycrop menu G", {
            # 0x1003: "probably never returns here",
        },
        symbol="mycrop_menu_entry_g")
    m.add_sym("_mycrop_menu_entry_g_t1", 0x1016)
    m.add_sym("_mycrop_menu_entry_g_t2", 0x1026)
    m.add_sym("_mycrop_menu_entry_g_t3", 0x1032)
    
    m.parse(0x1039, 0x1041, "???? jumptarget (from DREG, DMEM, ...)", {
        0xfe4 : "??? used by MON etc",
        0xfe7 : "jump to TTO",
        0xfea : "jump to MONCR",
        0xfed : "??? used by TTO",
    }, symbol="restore_regs")
    m.comment("dim-1030 (p 6-31) describes the diskette buffer's functionality")
    m.comment("byte 0 is # bytes read/written(up to 128, but only 0-128 are used)")
    m.comment("byte 1 and 2 are not used, so the actual data is at +3 and the buffer")
    m.comment("must be 3 bytes (hdr) larger than the desired content")
    m.comment("")
    m.comment("The disk data format is documented at the end of DIM-1030 (p 6-37++)")
    m.comment("")

    m.comment("mycrop p 15:")
    m.comment("A = unit number")
    m.comment("B = pointer to program name")
    m.comment("The program name consists of a 8 byte area (trailing blanks).")
    m.comment("When program is properly loaded, the flipflop CARRY = 0 upon")
    m.comment("return and the HL register will contain the first address of the first")
    m.comment("segment of the loaded program.")
    m.comment("NB/TODO: the hl = ff80 + sp is suspicious - sp in the prompt is 0fd0 = 0x10f50")
    m.comment("which would overflow... so it ends up at 0x0f50 ?. At least it will be enough for a sector before fd7")
    m.comment("NB/TODO: B cannot be a 16-bit pointer... is it BC? LINK doc says BC....")
    m.comment("retval a seems to be 'sector 7 ID mark = 0x50 not found' (the PROG marker)")
    m.comment("retval b seems to be 'file name not found'")
    m.comment("mycrop p 27 (8.1) also says something about diskette format which is not quite the same as dim-1030?")
    m.comment("looks like the mycrop doc corresponds better with the code!")
    m.comment("This means 19 * 8 (sect 8..26) = 152 file name entries, where max seg size = 255*128=32650 - not quite 32kb")
    m.parse(0x1042, 0x10e0, "LOAD load program from diskette", {
        0x1044: "Store a=drive number at 0xfd7",
        0x104d: "Sets hl and sp to ff80 + current sp (strange to modify both, but loaded prog might have new sp).",
        0x1050: "The first push would overwrite the first byte of the input ",
        0x1051: "buffer unless something is skipped",
        0x1052: "Copy new hl/sp to 0xfd8",
        0x1055: "Strange. are we sure bc is 0? (de is bad/alt track numbers). NB: alt tracks appears to be ignored!?",
        0x1056: "It stores a copy of bc in de though",
        0x1057: "read track 0 sector 7",
        0x1061: "first byte should be 0x50 = 80 - ah. 0x50 is P in PROG for sector 7",
        0x1065: "return 0xa if first byte not 0x50",
        0x1068: "restore hl to the buffer addr for the data sector",
        0x106b: "next sector",
        0x106d: "compare with sector number 0x1b=27 (there is a loop at 1093 up here to 1068)",
        0x106f: "set error code b (don't have a documentation for that)",
        0x1071: "bail out of we reached sector 1b=27",
        0x107b: "number of 16-byte file entries in a 128-byte data segment",
        0x1080: "chars + spaces in filename (max 8)",
        0x1089: "skips to next file name entry",
        0x108f: "more chars to check",
        0x109c: "track# of first sector",
        0x109e: "sector # of first sector",
        0x10a0: "high order byte of load addr (load 1)",
        0x10a2: "low  order byte of load addr (load 1)",
        0x10a4: "number of 128-byte sectors in load (load 1)",
        0x10a6: "TODO: check closer, but appears to store de and fetch info about load 2 (addr+len)",
        0x10b5: "Store away load 2 info, restore load 1",
        0x10bd: "Restore load 2",
        0x10ce: "drive number at 0xfd7",
        0x10d8: "restore call frame + stack for call to BDC?",
        0x10dd: "set carry, clear h+n",
    }, symbol="LOAD")
    m.add_sym("_load_ld_fname_sect", 0x1068)
    m.add_sym("_load_cmpname_sect", 0x107a)
    m.add_sym("_load_cmpname", 0x107d)
    m.add_sym("_load_cmpname_char", 0x1082)
    m.add_sym("_load_cmpname_nextchar", 0x1096)
    m.add_sym("_load_ret", 0x10cd)
    m.add_sym("_load_err_ret", 0x10d8)
    m.add_sym("_load_err_ret_dd", 0x10dd)

    m.comment("Used by LOAD to load one the two segments (load 1 and load 2)")
    m.parse(0x10e1, 0x10ff, "", {
        0x10e2: "return if nothing more to read",
        0x10e3: "number of bytes per segment",
        0x10ed: "return if error",
        0x10ef: "bump memory pointer by 0x80 bytes",
        0x10f0: "increase sector",
        0x10f7: "ran out of sectors, bump up to sector 1 next track",
        0x10ff: "all sectors loaded",
    }, symbol="_dsk_load_segment")
    m.add_sym("_dsk_load_seg_ld", 0x10e6)
    m.add_sym("_dsk_load_seg_next_seg", 0x10ef)
    m.add_sym("_dsk_load_seg_next_iter", 0x10fa)

with mem.section(0x1100, 0x1200, "Section 1100 mycrop") as m:
    m.parse(0x1100, 0x1108, "??? call target", {
    }, symbol="dsk_read_bldr_unit_at_fd7")

    m.parse(0x1109, 0x110d, "LINK - Load and Start program", {
    }, symbol="LINK")

    m.comment("return codes 5.17 in mycrop")
    m.comment("0 - operation properly")
    m.comment("1 - CRC error in data")
    m.comment("2 - unit not ready")
    m.comment("3 - deleted data read")
    m.comment("4 - invalid track number")
    m.comment("5 - invalid sector number")
    m.comment("6 - improper unit number")
    m.comment("7 - CRC error in header")
    m.comment("8 - Missing data address mark")

    m.comment("")
    m.comment("A = unit number (mycrop). A = drive number 0-7. Return: 0, 2, or 6 (dim-1030)")
    m.parse(0x110e, 0x1122, "BDO - basic diskette open", {
        0x1118: "disk at track zero",
    }, symbol="BDO")
    m.add_sym("_bdo_j1", 0x1116)

    m.comment("A = drive number 0-7.  Return 0 (dim-1030)")
    m.parse(0x1123, 0x113b, "BDD - basic diskette head down.", {
        0x112a: "$4x to 89 = LH to cw2",
    }, symbol="BDD")
    m.add_sym("_BDD_t1", 0x1139)

    m.parse(0x113c, 0x1148, "call target", {
    }, symbol="dsk_chk_ready")

    m.comment("A = drive number 0-7. Return 0 (dim-1030)")
    m.parse(0x1149, 0x1151, "BDC - basic diskette close (raise read/write head)", {
    }, symbol="BDC")

    m.comment("A = drive number")
    m.comment("B = track address")
    m.comment("C = sector address")
    m.comment("D = bad track number, replacement on track 74 (0 - no bad tracks)")
    m.comment("E = bad track number, replacement on track 75 (0 - no bad tracks)")
    m.comment("HL = address of input buffer")
    m.parse(0x1152, 0x115a, "BRDR - basic diskette read", {
    }, symbol="BRDR")

    m.comment("A, B, C, D, E - as for BRDR")
    m.comment("HL = addreess of output buffer")
    m.parse(0x115b, 0x1163, "BWDR - basic diskette write", {
    }, symbol="BWDR")

    m.comment("A, B, C, D, E - as for BRDR")
    m.comment("HL = addreess of memory area -- why does it need this?")
    m.parse(0x1164, 0x116a, "BDDR - basic diskette delete (writes zeros specified track/sector)", {
    }, symbol="BDDR")

    m.comment("dim-1030:")
    m.comment("The BLDR subroutine is similar to BRDR except that the buffer format described")
    m.comment("in section 2 is not used. The routine will read the full 128 byte contents of the")
    m.comment("specified sector into memory starting with the address given by HL registers.")
    m.comment("A, B, C, D, E - as for BRDR")
    m.comment("HL = addreess of memory area")
    m.parse(0x116b, 0x117a, "BLDR - basic diskette load", {
        0x116d: "how can the comparison above not be z = equal?",
        0x1175: "addr of the data read part of the load function",
        0x1178: "jumping into BUDR does not make sense as it's a write op... ?",
    }, symbol="BLDR")
    m.add_sym("_bldr_j1", 0x1174)

    m.comment("dim-1030:")
    m.comment("The BUDR subroutine is similar to BWDR except that the buffer format described")
    m.comment("in section 2 is not used. The routine will write the full 128 byte memory area")
    m.comment("starting with the address given by HL registers onto the specified sector of the")
    m.comment("diskette.")
    m.comment("A, B, C, D, E - as for BRDR")
    m.comment("HL = addreess of memory area")
    m.parse(0x117b, 0x117e, "BUDR - basic diskette unload", {
        0x117c: "this is likely the write part of the BUDR function",
    }, symbol="BUDR")

    m.parse(0x117f, 0x1215, "BUDR - basic diskette unload", {
        0x1181: "if drive# a >= 8, jump",
        0x1184: "create a 'call frame' with offsets 9,8=buffer addr, 7=b, 6=c, 5=a, 4=f, 3,2=hl, 1,0=de",
        0x1187: "no alternate tracks/sectors",
        0x1192: "fetch b=track, c=sector from 'call frame' to a, d",
        0x119a: "jump if wanted track=0",
        0x119d: "0x4d = 77 ... number of tracks",
        0x119f: "jump if >= 77",
        0x11a2: "0x28=40",
        0x11a4: "jump if track < 40",
        0x11a7: "modify drive number in params by adding 8 if track >= 40?",
        0x11ac: "check sector is 1..26 (inclusive)",
        0x11b6: "Could this be a counter of how many time to check for track/sect?",
        0x11bc: "CW1  41 = looks like READ attempt, but only one CR (CR0) is high.",
        0x11c0: "CW1  49 = cont READ? toggling the NC /RAM.",
        0x11c2: "read dsk STATUS.",
        0x11c4: "d=2 above, so checks for address mark.",
        0x11c8: "read dsk DATA.",
        0x11ca: "wait until address mark fe (1030 p 6-40). should skip sector 0",
        0x11cf: "track # => d (this should be the next byte after fe)",
        0x11d2: "should be 0",
        0x11d4: "reset call frame pointer to read parms",
        0x11d8: "sect  # => b",
        0x11de: "if track read (d) != wanted (a), jump",
        0x11e1: "should be 0",
        0x11e6: "if sect read (b=>a) != wanted (hl), jump",
        0x11e9: "CRC 1",
        0x11eb: "STATUS",
        0x11ee: "CRC 2",
        0x11f0: "First of 17 x 00?",
        0x11f3: "0x20 = CRC ok",
        0x11fa: "c was loaded at 11e1-3, should have been 0 but maybe doc format is wrong?",
        0x11fd: "when c was zero",
        0x1200: "jp m should be when sign is set",
        0x1214: "Jumps to the hl addr specified at the start. 1311 for write, 12a7 for read?"
    }, symbol="_budr_find_trk_sec")
    m.add_sym("_budr_chk_trk_parm__valid", 0x1192)
    m.add_sym("_budr_chk_sec_parm_valid", 0x11ac)
    m.add_sym("_budr_setup_read_sects", 0x11b6)
    m.add_sym("_budr_read_mark", 0x11b8)
    m.add_sym("_budr_wait_amark", 0x11c2)
    m.add_sym("_burd_read_trk_sec", 0x11cf)   # not a jump target, but marks section
    m.add_sym("_budr_jt_5", 0x1204)
    m.add_sym("_budr_jt_6", 0x1205)
    m.add_sym("_budr_exit_1215", 0x1215)

    m.parse(0x1216, 0x1219, "part of BUDR", {
    }, symbol="dsk_ret_06")

with mem.section(0x1200, 0x1300, "Section 1200 mycrop") as m:

    m.parse(0x121a, 0x121a, "jump target", {
    }, symbol="dsk_pop_bc_ret_02")

    m.parse(0x121c, 0x121e, "jump target", {
    }, symbol="dsk_pop_bc_ret_a")

    m.parse(0x121f, 0x1237, "jump target", {
    }, symbol="dsk_unit_notready_ret_2")
    m.add_sym("_dsk_invtrack_ret_4", 0x1224)
    m.add_sym("_dsk_invsec_ret_5", 0x1229)
    m.add_sym("_dsk_unk_ret_p1", 0x122b)
    m.add_sym("_dsk_unk_ret_p2", 0x1232)

    m.comment("if jumped to from budr, b should have wanted sector number")
    m.comment("first in here should be the 0 followed after reading sector number")
    m.comment("The strange thing here is that it doesn't try to move the head (if sect=0)")
    m.comment("Could this be a 'stabilize head' attempt before actually moving the head?")
    m.parse(0x1238, 0x124b, "jump target", {
        0x1238: "this should be the 0 following the sect #",
        0x123a: "compares b (sector number) with a=0",
        0x123c: "why back to read_mark if the track is incorrect?",
        0x1240: "should be first byte of CRC",
        0x1246: "check crc again",
    }, symbol="dsk_unk_wrong_track")

    m.parse(0x124c, 0x1260, "jump target", {
    }, symbol="dsk_unk_wrong_sect")
    m.add_sym("_dsk_unk_wrong_sect_ret_7_crcerr", 0x125c)

    m.comment("TODO: could d be the last read track number? that way we try to step in or out")
    m.comment("until d matches the target. Note that d is inc/dec depending on direction.")
    m.parse(0x1261, 0x1288, "jump target", {
        0x1275: "STATUS",
        0x1267: "could d be the last read track number?",
        0x1277: "10 = at track zero",
        0x1278: "a == d => jump",
    }, symbol="dsk_seek_track")
    m.add_sym("_dsk_seek_track_cmp", 0x1266)
    m.add_sym("_dsk_seek_track_inc", 0x126e)
    m.add_sym("_dsk_seek_track_dec", 0x1275)
    m.add_sym("_dsk_seek_track_done", 0x1283)

    m.comment("increase track number")
    m.parse(0x1289, 0x1297, "call target.  5x = LH DIR SEL", {
        0x128e: "7x = LH + S + DIR SEL",
        0x1293: "5x = LH +   + DIR SEL",
        0x1295: "exit below (send to disk + delay)"
    }, symbol="dsk_step_inc")

    m.comment("decrease track number")
    m.parse(0x1298, 0x12a1, "call target, 0x6x = LH + S", {
        0x129d: "0x4x = LH",
    }, symbol="dsk_step_dec")
    m.add_sym("_dsk_step_dec_exit", 0x129f)

    m.parse(0x12a2, 0x12a6, "call target -- parm to delay is 0xa", {
    }, symbol="dsk_step_delay")

    m.comment("looks like this was written by somebody else than the find track/sec part")
    m.comment("Tries to load 2 x c bytes to a buffer and then checks crc")
    m.comment("If a sector is 128 bytes, then c _should_ be 0x40=64. See the weird code around")
    m.comment("11fb for how it starts at $40 but may be doubled or quadrupled (to 0x100 in one byte?)")
    m.comment("If dim-1030 doc is correct, the format of each data track can be very different.")
    m.comment("But the data block _should_ be 1 byte mark + 128 byte content + 2 byte CRC")
    m.comment("Lots of typos in the spec though")
    m.comment("While dumping a test run, C is 0x40, corresponding to 0x80=128 bytes data")
    m.parse(0x12a7, 0x130b, "", {
        0x12a7: "deeper callframe compared to the previous phase. to find de addr",
        0x12b0: "set up small delay loop?",
        0x12ad: "why?",
        0x12b6: "starts the read sequence as in find_trk_sec",
        0x12c2: "should be the fb address mark, but the value is not checked",
        0x12c4: "STATUS",
        0x12c6: "h = 0x02, so addressmark",
        0x12c7: "if mark found, jump",
        0x12cb: "reads another byte, then status without checking it",
        0x12cd: "STATUS, but doesn't check this",
        0x12d2: "set error code to 8 (missing address mark)",
        0x12d7: "h = 0x02, so addressmark",
        0x12db: "ah... could be consuming the addressmark byte?",
        0x12de: "reads one byte and stores in target memory",
        0x12e2: "some form of loop unrolling?",
        0x12e6: "c is the byte counter",
        0x12ee: "check CRC ok",
        0x12f3: "CRC ok. Sets return value ... a bit strange way (h & 3) ^ 3. if h=0xfb mark, res is 0",
        0x12f4: "only examines the 2 lsb of whatever the byte read ad 12db was (in h)",
        0x12f6: "should be 0 if data block is ok (that is mark byte is fb)",
        0x1300: "retry reading sector hdr and data",
    }, symbol="dsk_read_sector_data")
    m.add_sym("_dsk_rsecd_delay1", 0x12b2)
    m.add_sym("_dsk_rsecd_mark", 0x12c2)
    m.add_sym("_dsk_rsecd_chkmark", 0x12d7)
    m.add_sym("_dsk_rsecd_mark_ok", 0x12db)
    m.add_sym("_dsk_rsecd_rd_2byte", 0x12de)
    m.add_sym("_dsk_rsecd_crc_fail", 0x12fb)
    m.add_sym("_dsk_rsecd_rett_err_01", 0x1307)


with mem.section(0x1300, 0x1400, "Section 1300 mycrop") as m:
    m.parse(0x130c, 0x1310, "looks like target set up in HL for BDDR (delete)",
            {
            })
    m.parse(0x1311, 0x1388, "???? addr used in entry of budr - may not be a correct entry", {
        0x1313: "read data",
        0x1317: "c9 -> CW1(88)    (wr LD RAM CR0)",
        0x1319: "set hl/offset to 5 (stack offset to the original A register / disk number)",
        0x131c: "reading but ignoring",
        0x131e: "base value for bit OR below",
        0x1320: "add stack pointer, so something in SP+5 (see call frame setup in BUDR)",
        0x1321: "SP + 5",
        0x1322: "c0 | (hl / sp+5) -> CW2(89)    (with test data I get c0 here for disk 0)",
        0x1324: "read data (9a)    (write data is 8a)",
        0x1326: "looks like some kind of delay trick",
        0x133c: "a1 -> CW1",
        0x133e: "NB: clears a, a=0",
        0x133f: "a=0 -> DATA",
        0x1341: "load buffer addr to DE (interlaved with zero writes to data port)",
        0x1346: "a=0 -> DATA",
        0x134a: "a=0 -> DATA",
        0x1354: "a8 -> CW1",
        0x1357: "r-b -> DATA",
        0x135b: "a9 -> CW1",
        0x135d: "write data from (de) 2 times c",
        0x136b: "strange pattern. Write a control to CW1 then to DATA",
        0x1373: "now to DATA a few times",
        0x137e: "CW1",
        0x1383: "CW2",
    }, symbol="dsk_write_sector_data")
    m.add_sym("_dsk_write_sdata_jt1", 0x1329)
    m.add_sym("_dsk_write_sdata_jt2", 0x132c)
    m.add_sym("_dsk_write_sdata_jt3", 0x132f)
    m.add_sym("_dsk_write_sdata_jt4", 0x1332)
    m.add_sym("_dsk_write_sdata_jt5", 0x1335)
    m.add_sym("_dsk_write_sdata_jt6", 0x1338)
    m.add_sym("_dsk_write_sdata_wd_loop", 0x135d)

    m.parse(0x1389, 0x139c, "???? call target - jump from call table 0xbe", {
    }, symbol="q_from_0xbe")
    m.add_sym("_q_1389_t1", 0x1391)

    m.parse(0x139d, 0x13ad, "???? call target", {
    })
    m.add_sym("_q_139d_t1", 0x13ac)
    
    m.parse(0x13ae, 0x13da, "???? call target - jump from call table 0xaf", {
    }, symbol="q_from_0xaf")
    m.add_sym("_q_13ae_t1", 0x13b5)
    m.add_sym("_q_13ae_t2", 0x13bb)
    m.add_sym("_q_13ae_t3", 0x13d2)
    m.add_sym("_q_13ae_t4", 0x13d8)

    m.parse(0x13db, 0x13f2, "???? call target - jump from call table 0xb2", {
    }, symbol="q_from_0xb2")
    m.add_sym("_q_13db_t1", 0x13e7)

    m.parse(0x13fb, 0x143c, "???? call target - jump from call table 0xb5", {
    }, symbol="q_from_0xb5")
    m.add_sym("_q_13fb_t1", 0x1407)
    m.add_sym("_q_13fb_t2", 0x1413)
    m.add_sym("_q_13fb_t3", 0x141b)
    m.add_sym("_q_13fb_t4", 0x1425)


with mem.section(0x1400, 0x1500, "Section 1400 mycrop") as m:
    m.parse(0x143d, 0x144b, "??? call target", {
    })
    m.add_sym("_q_143d_t1", 0x1447)
    
    m.parse(0x144c, 0x145a, "??? call target", {
    })
    m.add_sym("_q_144c_t1", 0x1474)
    
    m.parse(0x145b, 0x1475, "??? jump target", {
    })

    m.parse(0x1476, 0x1482, "??? jump target", {
    })
    
    m.parse(0x1483, 0x149f, "??? jump target", {
    })
    m.add_sym("_q_1483_t1", 0x1487)
    m.add_sym("_q_1483_t2", 0x149c)
    
    m.parse(0x14a0, 0x14ab, "??? jump target", {
    })
    
    m.parse(0x14ac, 0x14ca, "??? jump target", {
    })
    m.add_sym("_q_14ca_t1", 0x14b1)
    m.add_sym("_q_14ca_t2", 0x14c6)
    m.add_sym("_q_14ca_t3", 0x14c7)

    m.parse(0x14cb, 0x1511, "??? jump target", {
    })
    m.add_sym("_q_14cb_t1", 0x14e1)
    m.add_sym("_q_14cb_t2", 0x14f3)
    m.add_sym("_q_14cb_t3", 0x1503)

    
with mem.section(0x1500, 0x1600, "Section 1500 mycrop") as m:
    m.parse(0x1512, 0x1576, "??? jump target", {
    })
    m.add_sym("_q_1512_t1", 0x1528)
    m.add_sym("_q_1512_t2", 0x1531)
    m.add_sym("_q_1512_t3", 0x1540)
    m.add_sym("_q_1512_t4", 0x1561)
    m.add_sym("_q_1512_t5", 0x156d)
    m.add_sym("_q_1512_t6", 0x1573)
    m.add_sym("_q_1512_t7", 0x1575)
    
    m.parse(0x1577, 0x157f, "??? jump target", {
    })
    
    m.parse(0x1580, 0x158b, "??? jump target", {
    })
    
    m.parse(0x158c, 0x15b3, "??? jump target", {
    })
    m.add_sym("_q_158c_t1", 0x1591)
    m.add_sym("_q_158c_t2", 0x159e)
    m.add_sym("_q_158c_t3", 0x15a2)
    
    m.parse(0x15b4, 0x15eb, "??? jump target", {
    })
    m.add_sym("_q_15b4_t1", 0x15bc)
    m.add_sym("_q_15b4_t2", 0x15e2)
    
    m.parse(0x15ec, 0x1610, "??? jump target", {
    })
    m.add_sym("_q_15ec_t1", 0x1607)
    m.add_sym("_q_15ec_t2", 0x160b)
    m.add_sym("_q_15ec_t3", 0x160f)


with mem.section(0x1600, 0x1800, "Section 1600 mycrop") as m:
    ...


if __name__ == "__main__":
    mem.dump()
