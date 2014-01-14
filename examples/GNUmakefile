# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen bridge testpcap libnetmap.so
#PROGS += pingd
PROGS	+= testlock testcsum test_select testmmap vale-ctl
LIBNETMAP = pcap-pic.o nm_util-pic.o

CLEANFILES = $(PROGS) pcap.o nm_util.o *.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
ifdef WITH_PCAP
# do not make pcap default, as it is not always available on linux
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

testpcap: LDLIBS += -lpcap
testpcap: CFLAGS += -DTEST
testpcap: pcap.c libnetmap.so nm_util.o

kern_test: testmod/kern_test.c

nm_util.o pkt-gen.o bridge.o libnetmap.so pcap.o: nm_util.h

pkt-gen: pkt-gen.o nm_util.o

bridge: bridge.o nm_util.o

vale-ctl: vale-ctl.o

%-pic.o: %.c
	$(CC) $(CFLAGS) -fpic -c $^ -o $@

libnetmap.so: $(LIBNETMAP)
	$(CC) -shared -o $@ $(LIBNETMAP)

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c
