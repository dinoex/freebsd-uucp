#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: src/libexec/uucpd/Makefile,v 1.12 2001/03/20 18:10:11 ru Exp $

PROG=	uucpd
MAN=	uucpd.8
MAN8=	uucpd.8
BINDIR=	${PREFIX}/libexec
MANDIR=	${PREFIX}/man/man
LDADD=  -lcrypt -lutil
DPADD=  ${LIBCRYPT} ${LIBUTIL}
CFLAGS+= -DPREFIX=\"${PREFIX}\"

.if defined(WITH_PAM)
CFLAGS+= -DUSE_PAM
DPADD+= ${LIBPAM}
LDADD+= ${MINUSLPAM}
.endif

.include <bsd.prog.mk>
