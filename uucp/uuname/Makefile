# Makefile for uuname
# $FreeBSD$

BINDIR=		$(bindir)
BINOWN=		$(uucpowner)
BINMODE=	4555

PROG=		uuname
SRCS=		uuname.c log.c
LDADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
DPADD+=		$(LIBUNIX) $(LIBUUCONF) $(LIBUUCP)
CFLAGS+=	-I$(.CURDIR)/../common_sources\
		-DVERSION=\"$(VERSION)\"


.include <bsd.prog.mk>
.PATH: $(.CURDIR)/../common_sources
