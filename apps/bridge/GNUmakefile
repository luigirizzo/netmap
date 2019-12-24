# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	bridge bridge-b
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/bridge

NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include -I$(SRCDIR)/libnetmap
CFLAGS += -Wextra

LDFLAGS += -L $(BUILDDIR)/build-libnetmap
LDLIBS += -lnetmap
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
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
	-install -D -m 644 $(SRCDIR)/apps/bridge/bridge.8 $(DESTDIR)/$(MAN_PREFIX)/man8/bridge.8

bridge-b: bridge-b.o

bridge-b.o: bridge.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c $^ -o $@
