# $Id$

FILES=	call config dial dialcode passwd port sys1 sys2
NOOBJ=	noobj

BINOWN=	$(owner)
BINGRP=	$(group)

all clean cleandir depend lint tags:

install:
	install -c -o ${BINOWN} -g ${BINGRP} -m 440 ${FILES} \
		${DESTDIR}/etc/uucp

.include <bsd.prog.mk>
