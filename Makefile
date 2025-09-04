Z80_PTARGS = gen/prom-2.6z-0.bin gen/prom-2.6z-1.bin	
Z80_DASM = gen/z80_disasm.asm

all: $(Z80_PTARGS) $(Z80_DASM)

clean:
	rm -rf gen


$(Z80_PTARGS): combine_proms_z80.py dim-1003/*.bin
	python combine_proms_z80.py 


$(Z80_DASM): examine_proms_z80.py $(Z80_PTARGS)
	python3 examine_proms_z80.py gen/prom-2.6z-0.bin gen/prom-2.6z-1.bin > $@
