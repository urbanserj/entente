CC=gcc
CFLAGS=-Wall -Wextra -fno-strict-aliasing
LDFLAGS=-lev -lpam

all: asn1
	$(CC) -Iasn1/ $(CFLAGS) $(LDFLAGS) main.c asn1/*.c -o entente

.PHONY : clean debian 

asn1:
	mkdir asn1 && ( cd asn1; asn1c -pdu=auto -fcompound-names ../ldap.asn1; rm converter-sample.c )

clean:
	rm -rf entente asn1/

install:
	if [ -z "$(DESTDIR)" ]; then exit 1; fi
	mkdir -p $(DESTDIR)/usr/sbin
	cp entente $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/etc/init.d
	cp entente.init.d $(DESTDIR)/etc/init.d/entente
	mkdir -p $(DESTDIR)/etc/default
	cp entente.default $(DESTDIR)/etc/default/entente

debian:
	dpkg-buildpackage -rfakeroot
