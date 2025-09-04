#!/usr/bin/env python3

"""
This program tries to combine EPROM dumps to get the best possible combinations of the proms.
"""

from pathlib import Path


TARG_DIR = "gen"



def hexbytes(vals):
    return " ".join([f"{v:02x}" if v is not None else "__" for v in vals])


def padline(a0, a1, vals):
    """For a range of values that should be on the same hexline, pad beginning (if a0 % 0 > 0)
    or end (if (a1 + 1) %  != 0) with None for easier handling later"""
    ad0 = (a0 // 16) * 16
    ad1 = ad0 + 15
    if ad0 < a0:
        seq = [None] * (a0 - ad0) + vals
    else:
        seq = list(vals)
    if ad1 > a1:
        seq.extend([None] * (ad1 - a1))
    return seq


def compare_range(start, stop, *proms):
    def lower_addr(v):
        return (v // 16) * 16

    # just to have them align nicely
    longest_name = max(len(p.name) for p in proms)

    for r0 in range(start, stop + 1, 16):
        print("    ---")
        r1 = min(r0 + 15, stop)
        for p in proms:
            seq = padline(r0, r1, p.data[r0:r1 + 1])
            print(f"    {lower_addr(r0):04x} - {p.name:>{longest_name}}: ", hexbytes(seq))


class Prom:
    def __init__(self, name, data):
        self.name = name
        self.data = list(data)
        self.start_size = len(self.data)

    @classmethod
    def read_from(cls, name, fname):
        data = open(fname, 'rb').read()
        return Prom(name, data)

    def copy(self, newname=None):
        return Prom(newname if newname else self.name, self.data)

    def save_to(self, fname):
        assert len(self.data) == self.start_size
        print("Writing PROM dump to", fname)
        with open(fname, 'wb') as f:
            f.write(bytes(self.data))


def verify_same(rstart, rstop, *proms):
    print(f"  ----- verify-same {rstart:04x}..{rstop:04x} {tuple(p.name for p in proms)}")
    p0d = proms[0].data[rstart: rstop + 1]
    for p in proms[1:]:
        assert p0d == p.data[rstart: rstop + 1], f"failed verify range {hex(rstart)}-{hex(rstop)} at p0={proms[0].name} p={p.name}"


def create_prom_26z_0():
    """"PROM 0 from 5417 and 7058 are identical. The one from 5613 differs by one byte:
    0x20c is 04 while it is 80 in the other two. This is a value stored in register A and
    later written to port 02.
    5616 appears to suffer from bit rot, where bit 7 is often switched from a 1 to a 0.
    Therefore, this one simply reads one of the identical proms and returns that one.
    """
    print("======= trying to make/combine prom 0")
    ps = Prom.read_from("ps", "dim-1003/RCT_UV-EPROM_2716_V2.6Z_SN7058_00.bin")
    ps.save_to(Path(TARG_DIR, "prom-2.6z-0.bin"))


def create_prom_26z_1():
    print("======= trying to make/combine prom 1")
    # prom01 from p1 and p4 are identical.
    p1 = Prom.read_from("p1", "dim-1003/RCT_UV-EPROM_2716_V2.6Z_SN5616_01.bin")
    p2 = Prom.read_from("p2", "dim-1003/RCT_UV-EPROM_2716_V2.6Z_SN5613_01.bin")
    p3 = Prom.read_from("p3", "dim-1003/RCT_UV-EPROM_2716_V2.6Z_SN5417_01.bin")
    p4 = Prom.read_from("p4", "dim-1003/RCT_UV-EPROM_2716_V2.6Z_SN7058_01.bin")

    # The one from p2 seems to be the most complete, so start with that one.
    # All of the proms agree on:
    # 0000-058b
    print("  === basing result on p2")
    res = p2.copy("res")

    pall = [p1, p2, p3, p4]
    verify_same(0x000, 0x58b, *pall)

    print("  ====== First difference. Weird.  p1==p4 and p2==p3. Could somebody have put extra functions in here for balsfjordsystemet?")
    compare_range(0x58c, 0x58f, p1, p4, p2, p3)

    compare_range(0x590, 0x59f, p1, p4, p2, p3)
    compare_range(0x59b, 0x59d, p2, p3)
    compare_range(0x590, 0x59f, p1, p4)

    compare_range(0x5a0, 0x5cf, p1, p4, p2, p3)

    print("  ======= All identical here?")
    verify_same(0x5d0, 0x61f, *pall)

    print("  ======= p2 is the only difference here")
    compare_range(0x620, 0x64f, p1, p3, p4, p2)
    print("  ====== to the end")
    print("  P1 is 0x0 from 0x613-0x61e, and then 0xff to the end")
    print("  P3 is 0x0 from 0x613 and out")
    print("  P4 is 0x0 from 0x613-0x61e, and then 0xff to the end")
    verify_same(0x613, 0x61e, p1, p3, p4)
    verify_same(0x613, 0x7ff, p1, p4)
    verify_same(0x76a, 0x7ff, p1, p2, p4)
    print("  Does this mean that these are older/different proms that got partially overwritten?")

    res.save_to(Path(TARG_DIR, "prom-2.6z-1.bin"))

Path(TARG_DIR).mkdir(exist_ok=True)
create_prom_26z_0()
create_prom_26z_1()
