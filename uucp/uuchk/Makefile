# Makefile for uuchk
# $FreeBSD: src/gnu/libexec/uucp/uuchk/Makefile,v 1.8 1999/08/27 23:33:45 peter Exp $

BINDIR=		$(sbindir)

PROG=		uuchk
MAN=		uuchk.8
MAN8=		uuchk.8
LDADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
DPADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
CFLAGS+=	-I$(.CURDIR)/../common_sources\
		-DVERSION=\"$(VERSION)\"

.include <bsd.prog.mk>
