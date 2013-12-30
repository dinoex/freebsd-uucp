PREFIX?=	/usr/local

all:	uucp uucpd etc
	(cd uucp && ${MAKE} all)
	(cd uucpd && ${MAKE} all)
	(cd etc && ${MAKE} all)

install: uucp uucpd etc
	mtree -deU -f uucp.mtree -p ${DESTDIR}/var
	mtree -deU -f local.mtree -p ${DESTDIR}${PREFIX}
	(cd uucp && ${MAKE} install)
	(cd uucpd && ${MAKE} install)
	(cd etc && ${MAKE} install)

clean:	uucp uucpd etc
	(cd uucp && ${MAKE} clean)
	(cd uucpd && ${MAKE} clean)
	(cd etc && ${MAKE} clean)
	rm -f uucp/common_sources/config.cache \
		uucp/common_sources/config.log \
		uucp/common_sources/config.status \
		uucp/common_sources/stamp-h \
		uucp/common_sources/stamp-h1

extract: etc uucp uucpd

etc:
	cvs -d `pwd`/cvs get etc

uucp:
	cvs -d `pwd`/cvs get uucp

uucpd:
	cvs -d `pwd`/cvs get uucpd

distclean:
	rm -rf uucp uucpd etc

configure:
	cd uucp/common_sources && sh configure ${CONFIGURE_ARGS}

