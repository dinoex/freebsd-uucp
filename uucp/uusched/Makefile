# Makefile for uusched
# $Id$

BINDIR=		$(bindir)

PROG=	uusched
SRCS=
NOMAN=
STRIP=

uusched:	uusched.in
	sed -e "s|@BINDIR@|$(bindir)|g" -e "s|@SBINDIR@|$(sbindir)|g" \
		$(.CURDIR)/uusched.in > $(.TARGET)

.include <bsd.prog.mk>
