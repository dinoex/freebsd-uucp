# Makefile for uusched
# $FreeBSD: src/gnu/libexec/uucp/uusched/Makefile,v 1.12.2.1 2001/04/25 12:03:23 ru Exp $

SCRIPTS=	uusched
MAN=		uusched.8
CLEANFILES+=	$(SCRIPTS)

BINDIR=		$(bindir)

uusched: uusched.in
	sed -e "s|@SBINDIR@|$(libxdir)|g" \
		$(.ALLSRC) > $(.TARGET)

.include <bsd.prog.mk>
