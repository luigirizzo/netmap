# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen pkt-gen-b
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/pkt-gen

NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include -I $(SRCDIR)/libnetmap
CFLAGS += -Wextra -Wno-address-of-packed-member

LDFLAGS += -L $(BUILDDIR)/build-libnetmap
LDLIBS += -lpthread -lm -lnetmap
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

ifdef WITH_PCAP
LDLIBS += -lpcap
else
CFLAGS += -DNO_PCAP
endif

PREFIX ?= /usr/local
MAN_PREFIX = $(if $(filter-out /,$(PREFIX)),$(PREFIX),/usr)/share/man

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
	-install -D -m 644 $(SRCDIR)/apps/pkt-gen/pkt-gen.8 $(DESTDIR)/$(MAN_PREFIX)/man8/pkt-gen.8

pkt-gen-b: pkt-gen-b.o

pkt-gen-b.o: pkt-gen.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c $^ -o $@
