.if exists(${.OBJDIR}/../libunix)
LIBUNIX=	$(.OBJDIR)/../libunix/libunix.a
.else
LIBUNIX=	$(.CURDIR)/../libunix/libunix.a
.endif

.if exists(${.OBJDIR}/../libuuconf)
LIBUUCONF=	$(.OBJDIR)/../libuuconf/libuuconf.a
.else
LIBUUCONF=	$(.CURDIR)/../libuuconf/libuuconf.a
.endif

.if exists(${.OBJDIR}/../libuucp)
LIBUUCP=	$(.OBJDIR)/../libuucp/libuucp.a
.else
LIBUUCP=	$(.CURDIR)/../libuucp/libuucp.a
.endif

VERSION=        1.06.1.8
PREFIX?=	/usr/local
uucpowner=	uucp
uucpgroup=	uucp
bindir=		${PREFIX}/bin
sbindir=        ${PREFIX}/sbin
libxdir=        ${PREFIX}/libexec/uucp
MANDIR=		${PREFIX}/man/man
INFODIR=	${PREFIX}/info

# The directory to look in for new style configuration files (when
# using HAVE_TAYLOR_CONFIG).
newconfigdir=	${PREFIX}/etc/uucp

# The directory to look in for BNU (when using HAVE_BNU_CONFIG) or
# V2 (when using HAVE_V2_CONFIG) style configuration files.
oldconfigdir=	${PREFIX}/etc/uucp
