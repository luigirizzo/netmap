# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	lb
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
#VPATH = $(SRCDIR)/examples

NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I ../../examples
CFLAGS += -Wextra

LDLIBS += -lpthread -lm
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local

all: $(PROGS)

lb: lb.o pkt_hash.o

clean:
	-@rm -rf $(CLEANFILES)
