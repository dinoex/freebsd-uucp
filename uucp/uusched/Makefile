# Makefile for uusched
# $FreeBSD: src/gnu/libexec/uucp/uusched/Makefile,v 1.13 2001/03/27 14:58:34 ru Exp $

SCRIPTS=	uusched
MAN=		uusched.8
CLEANFILES+=	$(SCRIPTS)

BINDIR=		$(bindir)

uusched: uusched.in
	sed -e "s|@SBINDIR@|$(libxdir)|g" \
		$(.ALLSRC) > $(.TARGET)

.include <bsd.prog.mk>
