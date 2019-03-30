CFLAGS += -Werror -Wall -O2 -I../sys -DLIB
PROG = libnetmap.a
all: $(PROG)
libnetmap.a: nmreq.o
	ar rcs $(PROG) nmreq.o
nmreq.o: nmreq.c
	$(CC) $(CFLAGS) -c nmreq.c
clean:
	-@rm -rf nmreq.o libnetmap.a


