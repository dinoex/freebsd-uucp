# Makefile for uucico
# $FreeBSD: src/gnu/libexec/uucp/uucico/Makefile,v 1.12 1999/08/27 23:33:47 peter Exp $

BINDIR=         $(libxdir)
BINOWN=		$(uucpowner)
BINGRP=         dialer
BINMODE=        6555

PROG=		uucico
SRCS=		uucico.c trans.c send.c rec.c xcmd.c prot.c protg.c protf.c \
		prott.c prote.c proti.c protj.c proty.c protz.c time.c log.c \
		chat.c conn.c util.c copy.c
LDADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
DPADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
CFLAGS+=	-I$(.CURDIR)/../common_sources\
		-DVERSION=\"$(VERSION)\" -DOWNER=\"$(uucpowner)\"

MAN=		uucico.8
MAN8=		uucico.8

.if defined(WITH_ENCRYPTED_PASSWORDS)
LDADD+=       -lcrypt
DPADD+=       ${LIBCRYPT}
.endif

.include <bsd.prog.mk>
.PATH: $(.CURDIR)/../common_sources
