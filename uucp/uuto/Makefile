# Makefile for uuto
# $FreeBSD: src/gnu/libexec/uucp/uuto/Makefile,v 1.11 2001/03/27 14:58:35 ru Exp $

SCRIPTS=	uuto
MAN=		uuto.1
CLEANFILES+=	$(SCRIPTS)

BINDIR=		$(bindir)

uuto: uuto.in
	sed -e "s|@BINDIR@|$(bindir)|g" \
		$(.ALLSRC) > $(.TARGET)

.include <bsd.prog.mk>
