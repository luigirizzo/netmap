# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen bridge vale-ctl
#PROGS += pingd
PROGS	+= testlock test_select testmmap
MORE_PROGS = kern_test

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
.ifdef WITH_PCAP
LDFLAGS += -lpcap
.else
CFLAGS += -DNO_PCAP
.endif

LDFLAGS += -lpthread
LDFLAGS += -lrt	# needed on linux, does not harm on BSD
#SRCS = pkt-gen.c

all: $(PROGS)

kern_test: testmod/kern_test.c

pkt-gen: pkt-gen.o
	$(CC) $(CFLAGS) -o pkt-gen pkt-gen.o $(LDFLAGS)

bridge: bridge.o
	$(CC) $(CFLAGS) -o bridge bridge.o

vale-ctl: vale-ctl.o
	$(CC) $(CFLAGS) -o vale-ctl vale-ctl.o

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c
	$(CC) $(CFLAGS) -o testlock testlock.c -lpthread $(LDFLAGS)
