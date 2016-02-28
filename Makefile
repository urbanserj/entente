TARGET=entente

CFLAGS += \
	-std=gnu11 \
	-Wall -Wextra -Wpedantic \
	-Wno-extended-offsetof \
	-Wno-unused-parameter \
	-Wstrict-overflow -fno-strict-aliasing \
	-Wno-missing-field-initializers \
	-DASN_PDU_COLLECTION -Iasn1/ -Ildap/

LDFLAGS += -lev -lpam
SOURCES= \
	$(wildcard asn1/*.c) \
	$(wildcard ldap/*.c) \
	$(wildcard src/*.c)
OBJS=${SOURCES:.c=.o}

all: compile

compile: $(TARGET)

$(TARGET): ${OBJS}
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) ${OBJS}

install:
	mkdir -p $(DESTDIR)/usr/sbin
	cp entente $(DESTDIR)/usr/sbin/

clean:
	rm -rf \
		$(TARGET) $(OBJS) \
		debian/*.debhelper.log debian/*.debhelper \
		debian/*.substvars debian/files \
		debian/entente

build-deb:
	dpkg-buildpackage -rfakeroot -D -us -uc

clang-format:
	find -name '*.[ch]' | xargs -n 1 clang-format -i

.SUFFIXES:
.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<
