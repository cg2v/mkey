# mkey - Kerberos master key manager
# Copyright (c) 2003 Carnegie Mellon University
# All Rights Reserved.
# 
# Permission to use, copy, modify and distribute this software and its
# documentation is hereby granted, provided that both the copyright
# notice and this permission notice appear in all copies of the
# software, derivative works or modified versions, and any portions
# thereof, and that both notices appear in supporting documentation.
#
# CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
# CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
# ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
#
# Carnegie Mellon requests users of this software to return to
#
#  Software Distribution Coordinator  or  Software_Distribution@CS.CMU.EDU
#  School of Computer Science
#  Carnegie Mellon University
#  Pittsburgh PA 15213-3890
#
# any improvements or extensions that they make and grant Carnegie Mellon
# the rights to redistribute these changes.
# 
# $Id$

SYS=$(shell cat /etc/mw/sysname)
DESTDIR=/dist/sw.mkey.${SYS}
CMNDEST=/dist/sw.mkey.common

CFLAGS = -I/usr/local/include -DUSE_DOORS
LDFLAGS = -L/usr/local/lib -R /usr/local/lib

V=0

PROGRAMS = mkeyd
LIBRARIES = libmkey.so.$V

all: ${PROGRAMS} ${LIBRARIES}

clean:
	-rm -f ${PROGRAMS} ${LIBRARIES} *.o mkey_err.c mkey_err.h

libmkey.so.$V: libmkey.o mkey_err.o
	${LD} ${LDFLAGS} -G -h $@ -o $@ $^ -ldoor -lcom_err

libmkey.o: libmkey.c libmkey.h mkey_err.h
	${CC} ${CFLAGS} -KPIC -c -o $@ $<

mkey_err.o: mkey_err.c mkey_err.h
	${CC} ${CFLAGS} -KPIC -c -o $@ $<

mkey_err.c mkey_err.h: mkey_err.et
	compile_et $<


mkeyd: mkeyd.o libmkey.so.$V
	${CC} -mt ${LDFLAGS} -o $@ $^ -ldoor -lpthread -lkrb5

mkeyd.o: mkeyd.c mkey.h mkey_err.h
	${CC} -mt ${CFLAGS} -c -o $@ $<
