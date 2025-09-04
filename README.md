PROM dumps from Mycron cards
===========================

We currently have PROM dumps from three different card types: 

- DIM-1001 CPU card using the Intel 8080 processor. It looks like these should be
  correct and functional, but we have not examined them in any detail.
- DIM-1002 Communication Processor. These have not been examined. 
- DIM-1003 CPU card using the Z-80 processor. Most of the work has
  been focused around this card.
  

Tools
------

### combine_proms_z80.py 

Uses the known PROM dumps to create PROM 0 and 1 to use in the Mycro
emulator. There are some differences in the PROM contents, so this
tool tries to combine them to a set of PROMS that are hopefully close
enough to the original version. 

The output is stored in the "gen" subdirectory (automatically created
if not already present).


### examine_proms_z80.py and z80lib.py

This disassembles the PROM code, using a library from the Mycron
emulator, which is a separate project.

On Linux, I'm just symlinking the z80emu library to z80emu.so in this
directory to make it work. Another option is to just copy the
necessary file.

The provided Makefile runs examine_proms_z80 and dumps the commented
assembly code into the gen directory.

Note: I need to make some cleanups to the Mycro emulator before I can 
provide the z80emu library that this tool needs.


### notify-make.sh 

Just for convenience. This shell script in the background and re-runs
make every time I save a python file. It just speeds up my work a
little bit.


