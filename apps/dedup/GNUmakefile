# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	dedup
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/dedup

NO_MAN=
CFLAGS = -O2 -pipe -g
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include
CFLAGS += -Wextra
#CFLAGS += -DDEDUP_HASH_STAT

LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local
MAN_PREFIX = $(if $(filter-out /,$(PREFIX)),$(PREFIX),/usr)/share/man

all: $(PROGS)

dedup: dedup.o dedup-main.o

dedup.o: dedup.h

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
	-install -D -m 644 $(SRCDIR)/apps/lb/lb.8 $(DESTDIR)/$(MAN_PREFIX)/man8/lb.8
