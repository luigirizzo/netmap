# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	vale-ctl
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/vale-ctl

NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include
CFLAGS += -Wextra

LDLIBS += -lpthread -lm
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

ifdef WITH_PCAP
LDLIBS += -lpcap
else
CFLAGS += -DNO_PCAP
endif

PREFIX ?= /usr/local

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
