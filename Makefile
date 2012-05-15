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

uname := $(shell uname)
CPRULE = test -d $(dir $@) || mkdir -p $(dir $@); cp $< $@

DESLIB=-ldes

_lib = lib
OPTMZ = -g
CPPFLAGS ?= -I/usr/cs/include

ifeq ($(uname),SunOS)
override CPPFLAGS += -DUSE_DOORS
LDFLAGS = -L/usr/cs/${_lib} -R /usr/cs/${_lib} ${OPTMZ}
SHLDFLAGS = -L/usr/cs/${_lib} -R /usr/cs/${_lib} -G $(filter -g,$(OPTMZ))
MTFLAGS = -mt
RPCLIBS = -ldoor
SOCKLIBS = -lsocket
PICFLAGS=-KPIC
endif

ifeq ($(uname),Linux)
LDFLAGS = -L/usr/cs/${_lib} -Wl,-rpath,/usr/cs/${_lib} ${OPTMZ}
SHLDFLAGS = -L/usr/cs/${_lib} -rpath /usr/cs/${_lib} -shared -x ${OPTMZ}
PICFLAGS=-fPIC
ifeq ($(shell uname -p),x86_64)
_lib = lib64
endif
endif

override CFLAGS += ${OPTMZ}

V=1

PROGRAMS = mkey mkrelay mkeyd
LIBRARIES = libmkey.so.$V
HEADERS = libmkey.h mkey_err.h

all: ${PROGRAMS} ${LIBRARIES} ${HEADERS}

clean:
	-rm -f ${PROGRAMS} ${LIBRARIES} *.o mkey_err.c mkey_err.h

install: ${DESTDIR}/bin/mkey \
         ${DESTDIR}/libexec/mkeyd \
         ${DESTDIR}/${_lib}/libmkey.so.$V \
         ${HEADERS:%=${DESTDIR}/include/%}

${DESTDIR}/bin/mkey          : mkey          ; ${CPRULE}
${DESTDIR}/bin/mkrelay       : mkrelay       ; ${CPRULE}
${DESTDIR}/libexec/mkeyd     : mkeyd         ; ${CPRULE}
${DESTDIR}/${_lib}/libmkey.so.$V : libmkey.so.$V
	${CPRULE}
	-rm -f ${DESTDIR}/${_lib}/libmkey.so
	ln -s libmkey.so.$V ${DESTDIR}/${_lib}/libmkey.so

${DESTDIR}/include/% : % ; ${CPRULE}


libmkey.so.$V: libmkey.o mkeycode.o mkey_err.o
	${LD} ${SHLDFLAGS} -h $@ -o $@ $^ ${RPCLIBS} -lcom_err ${SOCKLIBS}

libmkey.o: libmkey.c
	${CC} ${CFLAGS} ${CPPFLAGS} ${PICFLAGS} -c -o $@ $<

mkeycode.o: mkeycode.c
	${CC} ${CFLAGS} ${CPPFLAGS} ${PICFLAGS} -c -o $@ $<

mkey_err.o: mkey_err.c
	${CC} ${CFLAGS} ${CPPFLAGS} ${PICFLAGS} -c -o $@ $<

mkey_err.c mkey_err.h: mkey_err.et
	compile_et $<

mkey: mkey.o libmkey.so.$V
	${CC} ${LDFLAGS} -o $@ $^ -lkrb5 ${DESLIB} -lsl -lcom_err

mkrelay: mkrelay.o libmkey.so.$V
	${CC} ${LDFLAGS} -o $@ $^ -lcom_err ${SOCKLIBS}

mkeyd: mkeyd.o libmkey.so.$V
	${CC} ${MTFLAGS} ${LDFLAGS} -o $@ $^ ${RPCLIBS} -lpthread -lkrb5

mkeyd.o: mkeyd.c
	${CC} ${MTFLAGS} ${CFLAGS} ${CPPFLAGS} -c -o $@ $<

%.o : %.c
	${CC} -c ${CFLAGS} ${CPPFLAGS} -o $@ $<

libmkey.o mkeycode.o mkeyd.o: mkey.h libmkey.h mkey_err.h
mkrelay.o mkey.o : libmkey.h mkey_err.h
mkey_err.o: mkey_err.h
