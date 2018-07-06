# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	  = test_select testmmap test_nm functional ctrl-api-test fd_server
PROGS    += get_tx_rings_avail_sends get_tx_rings_max_sends
X86PROGS  = testlock testcsum producer
LIBNETMAP =

CLEANFILES = $(PROGS) $(X86PROGS) *.o

SRCDIR ?= ..
VPATH   = $(SRCDIR)/utils

NO_MAN=
CFLAGS  = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
CFLAGS += $(SUBSYS_FLAGS)
ifdef WITH_PCAP
# do not use pcap by default, as it is not always available on linux
LDLIBS += -lpcap
else
CFLAGS += -DNO_PCAP
endif

LDLIBS += -lpthread -lm
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt 	# on linux
endif
#SRCS = pkt-gen.c

PREFIX ?= /usr/local

.PHONY: install clean all-x86 all inttest

all: $(PROGS)

inttest:
	$(shell if [ "$(shell uname)" = "Linux" ] ; then modprobe netmap ;fi)
	./randomized_tests

all-x86: $(PROGS) $(X86PROGS)

kern_test: testmod/kern_test.c

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c

install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
