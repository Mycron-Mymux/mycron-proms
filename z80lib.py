#!/usr/bin/env python3

from contextlib import contextmanager
import z80emu

def hexlist(vals):
    return [hex(v) for v in vals]


def parsehex(s):
    if s.startswith("$"):
        return int(s[1:], 16)
    return int(s, 16)


def printable_block(vals):
    """Converts a list of values to a printable block
    """
    out = "|"
    for v in vals:
        c = chr(v)
        if c.isprintable():
            out += c
        else:
            out += '.'
    return out + '|'


def chunk16(addrs):
    """Returns chunks of addresses, where a chunk is defined as any addresses where a/16 is the same."""
    lst = []
    for a in addrs:
        if a % 16 == 0:
            if len(lst) > 0:
                yield lst
            lst = []
        lst.append(a)
    if len(lst) > 0:
        yield lst


class ParsedInfo:
    def __init__(self, mem, addr, comment):
        self.mem = mem
        self.addr = addr
        self.comment = comment

    def dump(self, print_addr=True):
        if self.comment == "":
            print()
        elif self.addr is None:
            print(f"; --- {self.comment}")
        else:
            print(f"; --- {hex(self.addr) }--- {self.comment}")

    @property
    def addrs(self):
        if self.addr is None:
            return []
        return [self.addr]


class ParsedInstr(ParsedInfo):
    """Used to store a parsed instruction"""
    def __init__(self, mem, addr, pbytes, parsed, comment, jctarg=None, print_addr=True):
        super().__init__(mem, addr, comment)
        self.pbytes = pbytes
        self.parsed = parsed
        self.jctarg = jctarg

    @property
    def addrs(self):
        if self.addr is None:
            return []
        # addresses that this instruction spans
        return list(range(self.addr, self.addr + len(self.pbytes)))

    def dump(self, print_addr=True):
        # addr string
        if print_addr or True:
            astr = f"        {self.addr:04x} :"
        else:
            astr = " " * 12

        # TODO: look at symbol table if this is a jump or call
        ibytes = " ".join([f'{v:2x}' for v in self.pbytes])
        comment = self.comment
        if self.jctarg is not None:
            jctarg = self.mem.rsymbols.get(self.jctarg, self.jctarg)
            if isinstance(jctarg, int):
                jctarg = f"{jctarg:04x}"
            if self.parsed.lower().startswith("call"):
                comment = f"CALL={jctarg} -- {self.comment}"
            else:
                comment = f"JUMP={jctarg} -- {self.comment}"
        if self.addr in self.mem.rsymbols:
            print(f"{self.mem.rsymbols[self.addr]}:")
        print(f"{astr} {ibytes:10} {self.parsed:32}      ; {comment}")


class ParsedSpacer(ParsedInfo):
    """Just used to add a spacer in the output"""
    def dump(self, print_addr=True):
        print()


class ParsedData(ParsedInfo):
    """TODO - need byte strings and values"""


# New attempt: read the binfile instead. Less fuss.
class Memory:
    def __init__(self, bindump, curpos=0):
        self.rawmem = bindump
        self.mem = list(bindump)
        self.memb = bytes(self.mem)

        # TODO: This is perhaps a bit too complicated. Just add everything to a list (comments and parsed instructions).
        # Then, compute the touced bytes and gaps afterwards (for later dumping).
        # Alternatively, just require that segments are parsed in order and then just compute the gap between cur+prev when dumping? 
        # TODO: second pass would require all with mem.section and mem.parse
        # invocations to be stored for later printing.
        # Also: a failed decode requires a dump of the previous info for that section.
        
        self.touched = {}
        self.parsed_targets = {}
        self.called_targets = {}
        self.jump_targets = {}
        self.parsed_instrs = {}    # memory locations with parsed instructions
        self.instrs = []           # list of comments and instrs in the order they were inserted
        
        print("; LEN", len(self.mem))
        self.hvals = [f'{self[i]:02x}' for i in range(len(self))]
        self.curpos = curpos
        # default sym should be s_hxaddr if not defined
        # comment for jumpps and calls should be prepended as "TARG=s_hxaddr/sym"
        self.symbols = {}
        self.rsymbols = {}

    def __len__(self):
        return len(self.mem)

    # This should support slices
    def __getitem__(self, loc):
        return self.mem[loc]

    def __setitem__(self, loc, val):
        self.mem[loc] = val
        self.memb = bytes(self.mem)

    def add_sym(self, symbol, addr):
        assert (symbol not in self.symbols) or (self.symbols[symbol] == addr)
        self.symbols[symbol] = addr
        self.rsymbols[addr] = symbol

    def read_byte(self):
        self.touched[self.curpos] = True
        val = self[self.curpos]
        self.curpos += 1
        return val

    def read_bytes(self, n):
        return [self.read_byte() for i in range(n)]

    def peek(self, addr=None):
        if addr is None:
            return self[self.curpos]
        return self[addr]

    def add_called_targ(self, addr):
        self.called_targets[addr] = True
    
    def add_jump_targ(self, addr):
        self.jump_targets[addr] = True
        
    def add_jump_targs(self, addrs):
        for addr in addrs:
            self.add_jump_targ(addr)
    
    def parse_cur(self, comment="", print_addr=True):
        addr = self.curpos
        p_nbytes, parsed = z80emu.dis(self.memb, self.curpos)
        pbytes = self[self.curpos:self.curpos + p_nbytes]
        jctarg = None

        parts = parsed.replace(",", " ").split()
        if parsed.startswith("call"):
            jctarg = parsehex(parts[-1])
            self.add_called_targ(jctarg)
        if parsed.startswith("jp"):
            jaddr = parts[-1]
            if 'hl' in jaddr:
                print(f";WARNING (z80lib parse_cur): don't know what hl is for registering jp targets (at 0x{addr:x}")
            else:
                jctarg = parsehex(jaddr)
                self.add_jump_targ(jctarg)
        self.parsed_instrs[addr] = parsed
        self.curpos += p_nbytes
        instr = ParsedInstr(self, addr, pbytes, parsed, comment, jctarg=jctarg)
        self.__add_instrs(instr)
        return instr

    def parse_pos(self, addr, comment, print_addr=True):
        self.curpos = addr
        return self.parse_cur(comment, print_addr)

    def parse_nbytes(self, addr, nbytes, comment, extra_comments=None, symbol=None):
        if symbol is not None:
            self.add_sym(symbol, addr)
            # comment = f"{symbol} -- {comment}"
        
        if extra_comments is None:
            extra_comments = {}
        prev_pos = addr
        instrs = [self.parse_pos(addr, comment, print_addr=True)]
        while self.curpos < addr + nbytes and self.curpos != prev_pos:
            prev_pos = self.curpos
            comment = extra_comments.get(self.curpos, "")
            instrs.append(self.parse_cur(comment=comment, print_addr=False))
        return instrs

    def parse_target(self, addr, nbytes, comment, extra_comments=None, symbol=None):
        if symbol is not None:
            self.add_sym(symbol, addr)
        self.parsed_targets[addr] = True
        return self.parse_nbytes(addr, nbytes, comment, extra_comments=extra_comments)

    def parse(self, addr, stop, comment, extra_comments=None, symbol=None):
        self.__add_instrs(ParsedSpacer(self.mem, None, comment))
        if symbol is None:
            symbol = f"qtarg_{addr:04x}"
        nbytes = stop - addr + 1  # plus 1 as parse_nbytes runs up to but not including
        self.parsed_targets[addr] = True
        return self.parse_nbytes(addr, nbytes, comment, extra_comments=extra_comments, symbol=symbol)

    def __add_instrs(self, instrs):
        if isinstance(instrs, ParsedInfo):
            self.instrs.append(instrs)
        else:
            assert isinstance(instrs, list)
            self.instrs.extend(instrs)

    def comment(self, comment=""):
        self.__add_instrs(ParsedInfo(self.mem, None, comment))

    def dump_row(self, row_no):
        vals = [self[row_no * 16 + p] for p in range(16)]
        hvals = [f'{v:2x}' for v in vals]
        out = f"; {row_no * 16:04x} " + ' '.join(hvals) + '   ' + printable_block(vals)
        print(out)

    def dump_access(self):
        print("; TODO: this does not work at the moment (touched is not updated)")
        def crepr(count):
            if count == 0:
                return '-'
            if count == 16:
                return 'X'
            return f"{count:x}"[-1]

        pos = 0
        while pos < len(self):
            print(f"; {pos:4x} ", end="")
            for b1 in range(16):
                count = 0
                for b2 in range(16):
                    if pos in self.touched:
                        count += 1
                    pos += 1
                print(crepr(count), end="")
            print()

    def dump_region(self, a_from, a_to):
        row_start = a_from // 16
        row_end = (a_to + 15) // 16

        offsets = [f'{i:2x}' for i in range(16)]
        print(f"; rows {row_start} .. {row_end}")
        print(f";      {' '.join(offsets[:8])} {' '.join(offsets[8:])}")
        for row_no in range(row_start, row_end + 1):
            self.dump_row(row_no)

    def check_calls(self):
        """Checks that each called location is actually disasembled"""
        called_targets = set(self.called_targets.keys())
        jump_targets = set(self.jump_targets.keys())
        parsed_targets = set(self.parsed_targets.keys())
        instr_addrs = set(self.parsed_instrs.keys())
        sym_addrs = set(self.rsymbols.keys())
        print("; TODO: the following map does not appear to be working any more")
        print("; --- checking targets ---")
        print("; - Called, not parsed  :", hexlist(sorted(called_targets - instr_addrs)))
        print("; - Jumped, not parsed  :", hexlist(sorted(jump_targets - instr_addrs)))
        print("; - call/jmp, no symbol :", hexlist(sorted((called_targets | jump_targets) - sym_addrs)))
        print("; - Parsed, not call/jmp:", hexlist(sorted(parsed_targets - called_targets - jump_targets)))
        print("; - Parsed and called   :", hexlist(sorted(parsed_targets & called_targets)))

    def dump_gap(self, start, stop):
        """dumps memory start-stop inclusive"""
        offsets = [f'{i:2x}' for i in range(16)]
        print(f"; TODO: gap {start:04x} .. {stop:04x}")
        print(f";      {' '.join(offsets[:8])} {' '.join(offsets[8:])}    " + "".join([f'{v:x}' for v in range(16)]))
        addrs = list(range(start, stop + 1))
        for chunk in chunk16(addrs):
            rowaddr = 16 * (min(chunk) // 16)
            rvals = ["  "] * 16
            rsyms = [" "] * 16
            for addr in chunk:
                val = self.mem[addr]
                rpos = addr % 16
                rvals[rpos]  = f'{val:2x}'
                c = chr(val)
                rsyms[rpos] = c if c.isprintable() else "."
            print(f"; {rowaddr:04x} " + ' '.join(rvals) + '   |' + ''.join(rsyms) + '|')

        
    def dump(self):
        # TODO: if a gap is detected, the dump is added before the first instruction.
        #       Any comments relevant to the code is then added above the dump.
        #       The below code is a bit convoluted and doesn't quite solve the problem since
        #       some comments should be either above or below the dump. Now all comments come below.
        last = 0
        held = []
        
        for instr in self.instrs:
            addrs = instr.addrs
            if len(addrs) > 0:
                istart = min(addrs)
                if istart - last > 1:
                    self.dump_gap(last + 1, istart - 1)

            if isinstance(instr, ParsedInstr):
                if len(held) > 0:
                    for h in held:
                        h.dump()
                    held = []
                instr.dump()
            else:
                held.append(instr)
            last = max([last] + instr.addrs)
        if len(held) > 0:
            for h in held:
                h.dump()
        if len(self) - last > 1:
            self.dump_gap(last + 1, len(self) - 1)
            
        self.dump_access()
        self.check_calls()

    @contextmanager
    def section(self, start, stop, header):
        self.comment(f"--------- {header} ------------")
        try:
            yield self
        finally:
            ...
