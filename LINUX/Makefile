# To build external modules, you must have a prebuilt kernel available
# that contains the configuration and header files used in the build.
# go in the kernel directory and do a
#       make oldconfig; make scripts; make prepare
# or    make defconfig; make scripts; make prepare
#



# list of objects for this module
#
# objects whose source file is in ../sys/dev/netmap
remoteobjs := netmap.o netmap_mem2.o \
	netmap_generic.o netmap_mbq.o netmap_vale.o \
	netmap_offloadings.o netmap_pipe.o
# all objects
netmap_lin-objs := $(remoteobjs) netmap_linux.o

obj-$(CONFIG_NETMAP) = netmap_lin.o

ifndef NODRIVERS
# list of modules to be built (actually also forcedeth and r8169)
MOD_LIST:=	CONFIG_E1000=m CONFIG_E1000E=m	\
		CONFIG_IXGBE=m CONFIG_IGB=m	\
		CONFIG_BNX2X=m CONFIG_MLX4=m	\
		CONFIG_VIRTIO_NET=m
obj-m += $(O_DRIVERS)
GET_DRIVERS := get-drivers
else
MOD_LIST:=
endif

# DRIVER_SRCS names of the driver sources is only used to
# clean files that we copied.
DRIVER_SRCS = r8169.c forcedeth.c e1000/ e1000e/ ixgbe/ igb/
DRIVER_SRCS += bnx2x/ mellanox/ mlx4/ virtio_net.c

# _DRV_SUBDIRS contains the subdirs with driver sources.
# In old linuxes everything is under drivers/net, newer versions
# have them in source/drivers/net/ethernet/$(manufacturer)

_DRV_SUBDIRS= nvidia realtek intel broadcom . ..

# The following commands are needed to build the modules as out-of-tree,
# in fact the kernel sources path must be specified.

PWD ?= $(CURDIR)
M:=$(PWD)

# Additional compile flags (e.g. header location)
EXTRA_CFLAGS := -I$(M) -I$(M)/../sys -I$(M)/../sys/dev -DCONFIG_NETMAP
EXTRA_CFLAGS += -Wno-unused-but-set-variable

# We use KSRC for the kernel configuration and sources.
# If the sources are elsewhere, then use SRC to point to them.
KSRC ?= /lib/modules/$(shell uname -r)/build
SRC ?= $(KSRC)

# extract version number.
# version.h can be in two different places.
# NOTE- A.B.C translates to aXXYY where XXYY are hex
LIN_VER = $(shell V=linux/version.h; G=. ; \
	[ -f $(KSRC)/include/$${V} ] || G=generated/uapi ;\
	grep LINUX_VERSION_CODE $(KSRC)/include/$${G}/linux/version.h | \
	awk '{printf "%03x%02x", $$3/256, $$3%256} ')

# produce a list of applicable patches for this version
PATCHES := $(shell \
	    cd $(PWD)/patches; ls diff--* | awk -v v=$(LIN_VER) -F -- \
	    '{ if ((!$$3 || $$3 <= v) && (!$$4 || v < $$4)) print $$0; }')

# source drivers to copy. Names derived from the patches
S_DRIVERS := $(shell \
	    cd $(PWD)/patches; ls diff--* | awk -v v=$(LIN_VER) -F -- \
	    '{ if ((!$$3 || $$3 <= v) && (!$$4 || v < $$4)) print $$2 }' )

# actual drivers after copy and patch
DRIVERS = $(shell [ "$(PATCHES)" != "" ] && ls -dAp \
	`echo $(PATCHES:diff--%=%) | sed -r 's/--[0-9a-f-]+//g'` 2> /dev/null)

# Compile v1000 (vhost porting to e1000) only if
# the LIN_VER >= 3.8.0, because we don't want to deal
# with backporting problems for v1000.
ifeq ($(word 1, $(sort 30800 $(LIN_VER))), 30800)
CONFIG_V1000:=m
else
CONFIG_V1000:=n
endif

CONFIG_V1000:=n	# force disable by now

obj-$(CONFIG_V1000) += vhost-port/


all: build

build: $(GET_DRIVERS)
	$(MAKE) -C $(KSRC) M=$(PWD) CONFIG_NETMAP=m $(MOD_LIST) \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)'			\
		O_DRIVERS="$(DRIVERS:%.c=%.o)" modules
	@ls -l `find . -name \*.ko`


test:
	@echo "version $(LIN_VER)"
	@echo "patches $(PATCHES)"
	@echo "drivers $(DRIVERS)"

clean:
	-@ $(MAKE) -C $(KSRC) M=$(PWD) clean 2> /dev/null
	-@ (rm -rf $(DRIVER_SRCS) *.orig *.rej *.ko *.o .*.d \
		.tmp_versions *.mod.c modules.order	\
		Module.symvers .*.cmd get-drivers )

# the source is not here so we need to specify a dependency
define remote_template
$$(obj)/$(1): $$(M)/../sys/dev/netmap/$(1:.o=.c)
	$$(call cmd,cc_o_c)
	$$(call cmd,modversions)
endef
$(foreach o,$(remoteobjs),$(eval $(call remote_template,$(o))))

#-- copy and patch initial files
# The location changes depending on the OS version, so ...
get-drivers:
	-@(								\
	    if [ -d "$(DRIVER_SRC)" ] ; then				\
		cd "$(DRIVER_SRC)"; s=.; what="`ls -dp *`" ;		\
	    else							\
		cd $(SRC); [ -d source ] && cd source ;			\
		cd drivers/net; s=. ;					\
		[ -d ethernet ] && cd ethernet && s="$(_DRV_SUBDIRS)" ;	\
		what="$(S_DRIVERS)" ;					\
	    fi ;							\
	    echo "LIN_VER $(LIN_VER)" ;					\
	    [ "$${what}" = "" ] && echo "-- NO DRIVERS --" && return;	\
	    echo "---- Building from `pwd`";				\
	    echo "---- copying $${what} ---" ;				\
	    what="$${what} cnic_if.h";					\
	    for i in $$s; do (cd $$i ;					\
		echo "  From `pwd` :";					\
		ls -ldp $${what} 2> /dev/null | sed 's/^/    /' ;	\
	    	cp -Rp $${what} $(PWD) 2>/dev/null );			\
	    done ;							\
	    cd $(PWD) ;							\
	    for i in $(PATCHES) ;					\
		do echo "** patch with $$i";				\
		patch --posix --quiet --force -p1 < patches/$$i;	\
	    done ;							\
	    echo "Building the following drivers: $(S_DRIVERS)" )
	@touch get-drivers


test3:
	@echo "from $(PATCHES) -- to $(MYDRIVERS)"
	@echo "Drivers is $(DRIVERS)"
	@echo "Actually have `ls -d $(DRIVERS) 2> /dev/null`"

# compute the diffs for the original files
diffs:
	@for i in `find . -name \*.orig`; do 	\
		diff -urp $$i $${i%.orig} ;	\
	done

apps:
	(cd ../examples; $(MAKE))

+%:
	@echo $($*)
