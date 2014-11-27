pwntools-regression
===================

A series of contrived examples to test pwntools for functionality regressions.

Specifically, it consists of a small server written in C which allows us to have various primitives we might get from a normal vulnerability.  This is compiled into all of the various architectures supported by QEMU and pwntools.  Then a test harness runs through everything, and tests all of the functionality.
