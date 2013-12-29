PREFIX?=	/usr/local

all:	uucp uucpd etc
	cd uucp && make all
	cd uucpd && make all
	cd etc && make all

install: uucp uucpd etc
	mtree -deU -f uucp.mtree -p /var
	mtree -deU -f local.mtree -p ${PREFIX}
	cd uucp && make install
	cd uucpd && make install
	cd etc && make install

clean:	uucp uucpd etc
	cd uucp && make clean
	cd uucpd && make clean
	cd etc && make clean
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

