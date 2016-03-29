# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen pkt-gen-b bridge bridge-b vale-ctl
#PROGS += pingd
PROGS	+= test_select testmmap
X86PROG = testlock testcsum
LIBNETMAP =

CLEANFILES = $(PROGS) $(X86PROGS) *.o

SRCDIR ?= ..
VPATH = $(SRCDIR)/examples

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
	LDLIBS += -lrt	# on linux
endif
#SRCS = pkt-gen.c

PREFIX ?= /usr/local

all: $(PROGS)

all-x86: $(PROGS) $(X86PROGS)

kern_test: testmod/kern_test.c

pkt-gen: pkt-gen.o

pkt-gen-b: pkt-gen-b.o

%-b.o: %.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c $^ -o $@

bridge: bridge.o

bridge-b: bridge-b.o

vale-ctl: vale-ctl.o

%-pic.o: %.c
	$(CC) $(CFLAGS) -fpic -c $^ -o $@

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c

tlem: LDLIBS += -lm

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
