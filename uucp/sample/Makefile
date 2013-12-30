# $FreeBSD$

FILES=	call.sample config.sample dial.sample dialcode.sample passwd.sample \
	port.sample sys1.sample sys2.sample

NOOBJ=	noobj

BINOWN=	$(uucpowner)
BINGRP=	$(uucpgroup)

all clean cleandir depend lint tags:

install:
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 440 ${FILES} \
		${DESTDIR}${PREFIX}/etc/uucp

.include <bsd.prog.mk>
