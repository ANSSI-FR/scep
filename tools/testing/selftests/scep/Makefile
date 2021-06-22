# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -O2

TEST_GEN_PROGS := scep-tests

include ../lib.mk

$(OUTPUT)/%-tests: %-tests.c ../kselftest_harness.h
	$(LINK.c) $< $(LDLIBS) -o $@ -lcap 
