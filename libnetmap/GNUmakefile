SRCDIR ?= ../
PREFIX ?= usr/local
CFLAGS=-O2 -pipe -Wall -Werror
CFLAGS +=-g
CFLAGS += -I $(SRCDIR)/sys
VPATH = $(SRCDIR)/libnetmap
SRCS=$(notdir $(wildcard $(SRCDIR)/libnetmap/*.c))
OBJS=$(SRCS:.c=.o)

all: libnetmap.a

$(OBJS): libnetmap.h

libnetmap.a: $(OBJS)
	$(AR) r $@ $^

.PHONY: clean distclean install
clean:
	rm -f *.o

distclean: clean
	rm -f libnetmap.a

install:
	install -D libnetmap.a $(DESTDIR)/$(PREFIX)/lib/libnetmap.a

+%:
	@echo $*=$($*)
