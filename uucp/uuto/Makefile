# Makefile for uuto
# $Id$

BINDIR=		$(bindir)

PROG=		uuto
SRCS=
NOMAN=
STRIP=

uuto:	uuto.in
	sed -e "s|@BINDIR@|$(bindir)|g" -e "s|@SBINDIR@|$(sbindir)|g" \
		$(.CURDIR)/uuto.in > $(.TARGET)

depend:

.include <bsd.prog.mk>
