#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: src/libexec/uucpd/Makefile,v 1.9 1999/08/28 00:10:28 peter Exp $

PROG=	uucpd
MAN8=	uucpd.8
LDADD=  -lcrypt -lutil -lmd
DPADD=  ${LIBCRYPT} ${LIBUTIL} ${LIBMD}
.include <bsd.prog.mk>
