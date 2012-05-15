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

SYS=$(shell cat /etc/mw/sysname)
DESTDIR=/dist/sw.mkey.${SYS}
CMNDEST=/dist/sw.mkey.common

DESLIB=-ldes

ifeq ($(SYS),sun4x_59)
CFLAGS = -I/usr/local/include -DUSE_DOORS ${DEBUG}
LDFLAGS = -L/usr/local/lib -R /usr/local/lib
SHLDFLAGS = ${LDFLAGS} -G
MTFLAGS = -mt
RPCLIBS = -ldoor
SOCKLIBS = -lsocket
PICFLAGS=-KPIC
endif

ifeq ($(SYS),i386_rh80)
CFLAGS = -I/usr/local/include ${DEBUG}
LDFLAGS = -L/usr/local/lib -Wl,-rpath,/usr/local/lib
SHLDFLAGS = -L/usr/local/lib -rpath /usr/local/lib -shared -x
PICFLAGS=-fPIC
endif

V=1

PROGRAMS = mkey mkrelay mkeyd
LIBRARIES = libmkey.so.$V
HEADERS = libmkey.h mkey_err.h

all: ${PROGRAMS} ${LIBRARIES} ${HEADERS}

clean:
	-rm -f ${PROGRAMS} ${LIBRARIES} *.o mkey_err.c mkey_err.h

install: ${DESTDIR}/usr/local/bin/mkey \
         ${DESTDIR}/usr/local/libexec/mkeyd \
         ${DESTDIR}/usr/local/lib/libmkey.so.$V \
         ${HEADERS:%=${CMNDEST}/usr/local/include/%}

CPRULE = test -d $(dir $@) || mkdir -p $(dir $@); cp $< $@
${DESTDIR}/usr/local/bin/mkey          : mkey          ; ${CPRULE}
${DESTDIR}/usr/local/bin/mkrelay       : mkrelay       ; ${CPRULE}
${DESTDIR}/usr/local/libexec/mkeyd     : mkeyd         ; ${CPRULE}
${DESTDIR}/usr/local/lib/libmkey.so.$V : libmkey.so.$V
	${CPRULE}
	-rm -f ${DESTDIR}/usr/local/lib/libmkey.so
	ln -s libmkey.so.$V ${DESTDIR}/usr/local/lib/libmkey.so

${CMNDEST}/usr/local/include/% : % ; ${CPRULE}


libmkey.so.$V: libmkey.o mkeycode.o mkey_err.o
	${LD} ${SHLDFLAGS} -h $@ -o $@ $^ ${RPCLIBS} -lcom_err ${SOCKLIBS}

libmkey.o: libmkey.c libmkey.h mkey_err.h mkey.h
	${CC} ${CFLAGS} ${PICFLAGS} -c -o $@ $<

mkeycode.o: mkeycode.c libmkey.h mkey_err.h mkey.h
	${CC} ${CFLAGS} ${PICFLAGS} -c -o $@ $<

mkey_err.o: mkey_err.c mkey_err.h
	${CC} ${CFLAGS} ${PICFLAGS} -c -o $@ $<

mkey_err.c mkey_err.h: mkey_err.et
	compile_et $<

mkey: mkey.o libmkey.so.$V
	${CC} ${LDFLAGS} ${DEBUG} -o $@ $^ -lkrb5 ${DESLIB} -lsl -lcom_err

mkey.o : mkey.c libmkey.h mkey_err.h

mkrelay: mkrelay.o libmkey.so.$V
	${CC} ${LDFLAGS} ${DEBUG} -o $@ $^ -lcom_err ${SOCKLIBS}

mkrelay.o : mkrelay.c libmkey.h mkey_err.h

mkeyd: mkeyd.o libmkey.so.$V
	${CC} ${MTFLAGS} ${LDFLAGS} ${DEBUG} -o $@ $^ ${RPCLIBS} -lpthread -lkrb5

mkeyd.o: mkeyd.c mkey.h libmkey.h mkey_err.h
	${CC} ${MTFLAGS} ${CFLAGS} -c -o $@ $<
