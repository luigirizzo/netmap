# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	nmreplay
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/nmreplay

NO_MAN=
CFLAGS = -O2 # -pipe -g
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include -I $(SRCDIR)/libnetmap
CFLAGS += -Wextra

LDFLAGS += -L $(BUILDDIR)/build-libnetmap
LDLIBS += -lnetmap -lpthread
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local
MAN_PREFIX = $(if $(filter-out /,$(PREFIX)),$(PREFIX),/usr)/share/man

all: $(PROGS)

testlock: testlock.c

nmreplay: LDLIBS += -lm

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install install-docs
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
	-install -D -m 644 $(SRCDIR)/apps/nmreplay/nmreplay.8 $(DESTDIR)/$(MAN_PREFIX)/man8/nmreplay.8
