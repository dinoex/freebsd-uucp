# Makefile for uuxqt
# $FreeBSD: src/gnu/libexec/uucp/uuxqt/Makefile,v 1.10 1999/08/27 23:34:07 peter Exp $

BINDIR=         $(libxdir)
BINOWN=		$(uucpowner)
BINGRP=         $(uucpgroup)
BINMODE=        6550

PROG=		uuxqt
SRCS=		uuxqt.c util.c log.c copy.c
LDADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
DPADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
CFLAGS+=	-I$(.CURDIR)/../common_sources\
		-DVERSION=\"$(VERSION)\" -DOWNER=\"$(uucpowner)\"

MAN=		uuxqt.8
MAN8=		uuxqt.8

.include <bsd.prog.mk>
.PATH: $(.CURDIR)/../common_sources
