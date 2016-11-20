# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	= test_select testmmap test_nm producer
X86PROGS = testlock testcsum
LIBNETMAP =

CLEANFILES = $(PROGS) $(X86PROGS) *.o

SRCDIR ?= ..
VPATH = $(SRCDIR)/utils

NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
ifdef WITH_PCAP
# do not use pcap by default, as it is not always available on linux
LDLIBS += -lpcap
else
CFLAGS += -DNO_PCAP
endif

LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt -lm	# on linux
endif
#SRCS = pkt-gen.c

PREFIX ?= /usr/local

all: $(PROGS)

all-x86: $(PROGS) $(X86PROGS)

kern_test: testmod/kern_test.c

test_nm: test_nm.o

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
