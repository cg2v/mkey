
SYS=$(shell cat /etc/mw/sysname)
DESTDIR = /dist/sw.smartcard.${SYS}

CFLAGS = -I/usr/local/include ${DEBUG}
LDFLAGS = -L/usr/local/lib -R /usr/local/lib ${DEBUG}

PROGRAMS = setup_smartcard update_meta

all: ${PROGRAMS}

clean:
	-rm -f ${PROGRAMS} *.o

install: ${DESTDIR}/usr/local/bin/setup_smartcard \
         ${DESTDIR}/usr/local/sbin/update_meta \
         ${DESTDIR}/usr/local/share/opensc/mw.profile

CPRULE = test -d $(dir $@) || mkdir -p $(dir $@); cp $< $@
${DESTDIR}/usr/local/bin/setup_smartcard     : setup_smartcard ; ${CPRULE}
${DESTDIR}/usr/local/sbin/update_meta        : update_meta     ; ${CPRULE}
${DESTDIR}/usr/local/share/opensc/mw.profile : mw.profile      ; ${CPRULE}

update_meta: update_meta.o
	${CC} ${LDFLAGS} -o $@ $^ -lcrypto -lmkey -lcom_err -lsocket
