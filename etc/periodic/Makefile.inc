#	$Id$

BINDIR=	/etc/periodic/${.CURDIR:T}
BINOWN=	root
BINGRP=	wheel
NOOBJ=

beforeinstall:
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 755 ${BIN} \
	    ${DESTDIR}${BINDIR} 
