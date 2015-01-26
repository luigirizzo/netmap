obj-m += v1000_net.o
v1000_net-objs := v1000.o net.o


KSRC=/lib/modules/$(shell uname -r)/build

all: module test tags

module:
	make -C $(KSRC) M=$(PWD) modules

install:
	make -C $(KSRC) INSTALL_MOD_DIR=extramodules M=$(PWD) modules_install

test: test.o tun_alloc.o buildpkt.o
	gcc -Wall -g -o test test.o tun_alloc.o buildpkt.o -lpthread

test.o: test.c v1000_user.h tun_alloc.h
	gcc -Wall -g -c test.c

tun_alloc.o: tun_alloc.c tun_alloc.h
	gcc -Wall -g -c tun_alloc.c

buildpkt.o:
	gcc -Wall -g -c buildpkt.c

clean:
	make -C $(KSRC) M=$(PWD) clean
	-rm test *.o tags cscope.out

tags: v1000.c v1000.h net.c test.c
	ctags -R
