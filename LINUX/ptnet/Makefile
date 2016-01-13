EXTRA_CFLAGS += -I$(PWD)/../../sys

obj-$(CONFIG_E1000) += ptnet.o

KDIR=/lib/modules/`uname -r`/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
