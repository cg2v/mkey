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

srcdir ?= .
VPATH=$(srcdir)

uname := $(shell uname)
empty :=
space := $(empty) $(empty)
comma := ,
addwl   = -Wl,$(subst $(space),$(comma),$(1))
stripwl = $(subst $(comma),$(space),$(patsubst -Wl$(comma)%,%,$(1)))
CPRULE = test -d $(dir $@) || mkdir -p $(dir $@); cp $< $@

_lib = lib
OPTMZ = -g
CPPFLAGS ?= -I/usr/cs/include
LDFLAGS ?= -L/usr/cs/${_lib} $(call addwl,$(call rpath,/usr/cs/${_lib}))
override LDFLAGS += $(filter -g,${OPTMZ})

ifeq ($(uname),SunOS)
override CPPFLAGS += -DUSE_DOORS
rpath = -rpath $(1)
SHCCFLAGS = -KPIC
SHLDFLAGS = -G -h ${SONAME} $(call stripwl,${LDFLAGS})
SHLD = ld
MTFLAGS = -mt
RPCLIBS = -ldoor
SOCKLIBS = -lsocket
WARNFLAGS = -fd -v -errtags=yes -errwarn=%all
endif

ifeq ($(uname),Linux)
rpath = -R$(1)
SHCCFLAGS = -fPIC
SHLDFLAGS = -shared -Wl,-soname,${SONAME} ${LDFLAGS}
SHLD = gcc
MTFLAGS = -pthread
WARNFLAGS = -ansi -std=c99 -pedantic -Wall -Werror -Wextra \
            -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition \
            -Wpointer-arith -Wredundant-decls  -Wstrict-prototypes \
            -Wshadow -Wundef -Wunreachable-code -Wno-unused-function
ifeq ($(shell uname -p),x86_64)
_lib = lib64
endif
endif

VERSION := $(shell (cd $(psrcdir); git describe --dirty || git describe --dirty --tags || git describe --dirty --all || cat .version || echo unknown) 2>/dev/null)

override CFLAGS += ${OPTMZ} ${WARNFLAGS}
override CPPFLAGS := -I. -I$(srcdir) ${CPPFLAGS}
override CPPFLAGS += -DMKEY_VERSION='"${VERSION}"'

SOVERS = 1
SOBASE = libmkey
SONAME = ${SOBASE}.so.${SOVERS}
SOOBJS = libmkey.o mkeycode.o mkey_err.o ui.o
SOLIBS = ${RPCLIBS} -lcom_err ${SOCKLIBS}

PROGRAMS = mkey mkrelay mkeyd update_meta unlock_kdb
HEADERS = libmkey.h mkey_err.h

all: ${PROGRAMS} ${SONAME} ${HEADERS}

mkey: mkey.o ${SONAME}
	${CC} ${LDFLAGS} -o $@ $^ -lkrb5 -lsl -lcom_err

mkrelay: mkrelay.o ${SONAME}
	${CC} ${LDFLAGS} -o $@ $^ -lcom_err ${SOCKLIBS}

mkeyd: mkeyd.o ${SONAME}
	${CC} ${MTFLAGS} ${LDFLAGS} -o $@ $^ ${RPCLIBS} -lpthread -lkrb5

update_meta: update_meta.o ${SONAME}
	${CC} ${LDFLAGS} -o $@ $^ -lcrypto -lcom_err

unlock_kdb: unlock_kdb.o ${SONAME}
	${CC} ${LDFLAGS} -o $@ $^ -lopensc -lcrypto -lcom_err -lp11

${SONAME}: ${SOOBJS}
	${SHLD} ${SHLDFLAGS} -o ${SONAME}.new ${SOOBJS} ${SOLIBS}
	-rm -f ${SONAME}
	mv ${SONAME}.new ${SONAME}
	-rm -f ${SOBASE}.so
	ln -sf ${SONAME} ${SOBASE}.so


clean:
	-rm -f ${PROGRAMS} ${SONAME} ${SOBASE}.so *.o mkey_err.c mkey_err.h


install: ${DESTDIR}/bin/mkey
install: ${DESTDIR}/libexec/mkeyd
install: ${DESTDIR}/${_lib}/${SONAME}
install: ${HEADERS:%=${DESTDIR}/include/%}

${DESTDIR}/bin/mkey          : mkey          ; ${CPRULE}
${DESTDIR}/bin/mkrelay       : mkrelay       ; ${CPRULE}
${DESTDIR}/libexec/mkeyd     : mkeyd         ; ${CPRULE}
${DESTDIR}/include/%         : %             ; ${CPRULE}

${DESTDIR}/${_lib}/${SONAME} : ${SONAME}
	${CPRULE}
	-rm -f ${DESTDIR}/${_lib}/${SOBASE}.so
	ln -s ${SONAME} ${DESTDIR}/${_lib}/${SOBASE}.so


mkey_err.c mkey_err.h: mkey_err.et
	compile_et $<

%.o : %.c
	${CC} -c ${CFLAGS} ${CPPFLAGS} -o $@ $<

${SOOBJS}: %.o : %.c
	${CC} -c ${MTFLAGS} ${SHCCFLAGS} ${CFLAGS} ${CPPFLAGS} -o $@ $<

mkeyd.o: mkeyd.c
	${CC} -c ${MTFLAGS} ${CFLAGS} ${CPPFLAGS} -o $@ $<

libmkey.o mkeycode.o mkeyd.o: mkey.h libmkey.h mkey_err.h
mkrelay.o mkey.o update_meta.o unlock_kdb.o : libmkey.h mkey_err.h
mkey_err.o: mkey_err.h
pkcs15-simple.o : pkcs15-simple.h
