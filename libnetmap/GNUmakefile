CFLAGS=-O2 -pipe -Wall -Werror
CFLAGS=-g
CFLAGS += -I $(SRCDIR)/sys
VPATH = $(SRCDIR)/libnetmap
SRCS=$(notdir $(wildcard $(SRCDIR)/libnetmap/*.c))
OBJS=$(filter-out nmport.o,$(SRCS:.c=.o)) nmport2.o

all: libnetmap.a

$(OBJS): libnetmap.h

nmport2.o: nmport.o
	$(LD) -r -T $(VPATH)/npopts.lds nmport.o -o $@

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
