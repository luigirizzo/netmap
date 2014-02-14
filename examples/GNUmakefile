# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen bridge vale-ctl
#PROGS += pingd
PROGS	+= testlock test_select testmmap vale-ctl
LIBNETMAP =

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
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

all: $(PROGS)

kern_test: testmod/kern_test.c

pkt-gen: pkt-gen.o

bridge: bridge.o

vale-ctl: vale-ctl.o

%-pic.o: %.c
	$(CC) $(CFLAGS) -fpic -c $^ -o $@

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c
