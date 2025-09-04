PROM dumps from DIM-1003 CPU cards that use the Z-80 processor. 

These use two 2KiB PROM chips, where the first is mapped in at address
0 and the second starting at address 4KiB. The 2KiB area between the
two PROM chips is used by the monitor functions in the PROM. 

The contents of some of these chips have suffered from bit
rot. Furthermore, it looks like some unrelated data has been added to
the second PROM in some of the chips. One guess is that this may have
been in the memory of the computer when the PROMs were burned and that
the actual content that was supposed to be burned was less than
2KiB. Or some old data on the PROMs.

To get a functional PROM out of these, it's necessary to find the
right combination of dumps. This is done in the makefile of the main
repository.

Note that the DIM-1003 card has functionality for turning off the PROM
chips by writing a specific value to an I/O port (more on this
later). This suggests that these cards may have been capable of
booting and running CP/M.

