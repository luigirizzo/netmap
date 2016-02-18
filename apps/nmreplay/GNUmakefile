# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	nmreplay
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
#VPATH = $(SRCDIR)/examples

NO_MAN=
CFLAGS = -O2 -pipe -g
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys
CFLAGS += -Wextra

LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local

all: $(PROGS)

testlock: testlock.c

nmreplay: LDLIBS += -lm

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
