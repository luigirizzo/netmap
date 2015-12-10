# -*- makefile -*-

-include dkms.conf

PWD = $(shell pwd)
KVER = $(shell uname -r)
KVER_SHORT = $(shell uname -r | sed -r 's/([0-9]+\.[0-9]+).*?/\1/')
LINUX_SOURCE = linux-source-$(KVER_SHORT)
LINUX_SOURCE_ARCHIVE = "/usr/src/$(LINUX_SOURCE).tar.xz"
LINUX_SOURCE_HEADERS = "/usr/src/linux-headers-$(KVER)"
DKMS_SOURCE_DIR = "/usr/src/$(PACKAGE_NAME)-$(PACKAGE_VERSION)"

build: $(LINUX_SOURCE)
	cd LINUX && ./configure --kernel-sources="$(PWD)/$(LINUX_SOURCE)"
	cd LINUX && $(MAKE)

$(LINUX_SOURCE):
	tar xf $(LINUX_SOURCE_ARCHIVE)
	cd $(LINUX_SOURCE) && $(MAKE) oldconfig && $(MAKE) prepare && $(MAKE) scripts
	cp $(LINUX_SOURCE_HEADERS)/Module.symvers $(LINUX_SOURCE)/

clean:
	rm -rf $(LINUX_SOURCE)
	if [ -L LINUX/netmap.mak ]; then cd .. && $(MAKE) distclean; fi

install-dkms:
	mkdir -p $(DKMS_SOURCE_DIR)
	cp -a ../../* $(DKMS_SOURCE_DIR)
	cp -a ./* $(DKMS_SOURCE_DIR)
	dkms add -m $(PACKAGE_NAME)/$(PACKAGE_VERSION)

.PHONY: build clean install-dkms
