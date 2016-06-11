# Generated automatically from Makefile.in by configure.
#***********************************************************************
#
# Makefile
#
# Makefile for Roaring Penguin's Linux user-space PPPoE client.
#
# Copyright (C) 1999 Roaring Penguin Software Inc.
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
# $Id: Makefile.in,v 1.2 2000/01/10 22:34:26 dfs Exp $
#***********************************************************************

DEFINES= 
POSIX_DEFINE=-D_POSIX_SOURCE=1

CFLAGS= -Wall -pedantic -ansi -O2 $(DEFINES) $(POSIX_DEFINE)

# Version is set ONLY IN THE MAKEFILE!  Don't delete this!
VERSION= 1.0

pppoe: pppoe.o
	gcc -o pppoe pppoe.o $(LIBS)

pppoe.o: pppoe.c pppoe.h
	gcc $(CFLAGS) '-DVERSION="$(VERSION)"' -c -o pppoe.o pppoe.c

distro:
	rm -rf rp-pppoe-$(VERSION)
	mkdir rp-pppoe-$(VERSION)
	cp HOW-TO-CONNECT LICENSE Makefile.in configure.in config.h.in configure README firewall pap-secrets pppoe.8 pppoe.c pppoe.h adsl-connect adsl-state.pl rp-pppoe-$(VERSION)
	tar cvf rp-pppoe-$(VERSION).tar rp-pppoe-$(VERSION)/*
	gzip -v -9 rp-pppoe-$(VERSION).tar

clean:
	rm -f *.o pppoe core *~

distclean: clean
	rm -f Makefile config.h config.cache config.log config.status

.PHONY: clean

.PHONY: distclean
