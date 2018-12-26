ifneq ($(KERNELRELEASE),)

# virtio_net_src.c is just a symbolic link to virtio_net.c
# This workaround is needed because when defining modulename-y
# it is not possible to have a source called "modulename.c".
# Note that this is a problem only when NETMAP_DRIVER_SUFFIX
# is empty.
obj-m := virtio_net$(NETMAP_DRIVER_SUFFIX).o
virtio_net$(NETMAP_DRIVER_SUFFIX)-y := virtio_net_src.o

else

KSRC ?= /lib/modules/$(shell uname -r)/build

all: virtio_net.c
	$(MAKE) -C "${KSRC}" M=$(shell pwd) modules

install:
	$(MAKE) -C "${KSRC}" M=$(shell pwd) modules_install

clean:
	$(MAKE) -C "${KSRC}" M=$(shell pwd) clean

endif
