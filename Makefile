
SYS=$(shell cat /etc/mw/sysname)
PROGRAMS = setup_smartcard
DESTDIR = /dist/sw.smartcard.${SYS}


all: ${PROGRAMS}

install: ${PROGRAMS:%=${DESTDIR}/usr/local/bin/%} \
         ${DESTDIR}/usr/share/opensc/mw.profile

clean:
	-rm -f ${PROGRAMS} *.o

CPRULE = test -d $(dir $@) || mkdir -p $(dir $@); cp $< $@
${DESTDIR}/usr/local/bin/% : % ; ${CPRULE}
${DESTDIR}/usr/share/opensc/mw.profile : mw.profile ; ${CPRULE}
