# $FreeBSD: src/etc/periodic/weekly/Makefile,v 1.4.2.1 2000/08/08 18:05:38 brian Exp $

BIN=	120.clean-kvmdb \
	310.locate \
	320.whatis \
	330.catman \
	340.noid \
	400.status-pkg \
	999.local
.if !defined(NOUUCP)
BIN+=	300.uucp
.endif

.include <bsd.prog.mk>
