CFLAGS += -Werror -Wall -O2 -g
#LDFLAGS += -lpthread -lm -ldl -lrt # sqlite requires them
LDFLAGS += -lpthread -lm -lrt # sqlite requires them
#LDFLAGS += -lrt # for clock_gettime()
EXTRA_CFLAGS += -I/usr/local/include -I../libsqlite/include
#EXTRA_LDFLAGS += ../libsqlite/lib/libsqlite3.a -lrt
CFLAGS += $(EXTRA_CFLAGS)
#PROG = tinyhttpd-s test_nvdimm
PROG = tinyhttpd tinyhttpd-b tinyhttpd-k tinyhttpd-f
#OBJS = tinyhttpd-s.o test_nvdimm.o
OBJS = tinyhttpd-b.o tinyhttpd-k.o tinyhttpd-f.o bplus_support.o bplus_impl.o
#OPT = -DWITH_SQLITE
SOPT = -DWITH_EXTMEM
SPATH ?= -I../netmap/sys/ -I../netmap/apps/include -DNETMAP_WITH_LIBS
BOPT = -DWITH_BPLUS -I./
KOPT = -DWITH_KVS $(BOPT)
FOPT = -DWITH_NOFLUSH

all: $(PROG)

#test_nvdimm: test_nvdimm.o
#	$(CC) $(CFLAGS) -o test_nvdimm test_nvdimm.o $(LDFLAGS) $(EXTRA_LDFLAGS)
#test_nvdimm.o: test_nvdimm.c nmlib.h
#	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(SPATH) -c test_nvdimm.c -o test_nvdimm.o $(EXTRA_CFLAGS)
tinyhttpd: tinyhttpd.c nmlib.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(SPATH) tinyhttpd.c -o tinyhttpd $(EXTRA_CFLAGS) $(LDFLAGS)

tinyhttpd-f: tinyhttpd-f.o
	$(CC) $(CFLAGS) -o tinyhttpd-f tinyhttpd-f.o $(LDFLAGS) $(EXTRA_CFLAGS)
tinyhttpd-f.o: tinyhttpd.c nmlib.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(FOPT) $(SPATH) -c tinyhttpd.c -o tinyhttpd-f.o $(EXTRA_CFLAGS)
tinyhttpd-k: tinyhttpd-k.o bplus_support.o bplus_impl.o
	$(CC) $(CFLAGS) -o tinyhttpd-k tinyhttpd-k.o bplus_impl.o bplus_support.o $(LDFLAGS) $(EXTRA_CFLAGS)
tinyhttpd-k.o: tinyhttpd.c nmlib.h bplus_common.h bplus_support.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(BOPT) $(SPATH) $(KOPT) -c tinyhttpd.c -o tinyhttpd-k.o $(EXTRA_CFLAGS)

tinyhttpd-b: tinyhttpd-b.o bplus_support.o bplus_impl.o
	$(CC) $(CFLAGS) -o tinyhttpd-b tinyhttpd-b.o bplus_impl.o bplus_support.o $(LDFLAGS) $(EXTRA_CFLAGS)
tinyhttpd-b.o: tinyhttpd.c nmlib.h bplus_common.h bplus_support.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(BOPT) $(SPATH) -c tinyhttpd.c -o tinyhttpd-b.o $(EXTRA_CFLAGS)
bplus_impl.o: bplus_impl.c
	$(CC) $(CFLAGS) $(BOPT) -c bplus_impl.c
bplus_support.o: bplus_support.c
	$(CC) $(CFLAGS) $(BOPT) -c bplus_support.c
#tinyhttpd: tinyhttpd.o
#	$(CC) $(CFLAGS) -o tinyhttpd tinyhttpd.o $(LDFLAGS) $(EXTRA_LDFLAGS)
#tinyhttpd.o: tinyhttpd.c nmlib.h
#	$(CC) $(CFLAGS) $(OPT) -c tinyhttpd.c
clean:
	-@rm -f $(PROG) $(OBJS)
