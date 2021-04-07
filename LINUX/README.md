# Netmap for Linux

This file contains instructions on how to build, install and use Netmap
on Linux.
This directory contains Linux-specific code to let netmap work on
Linux.
Native support is available for r8169, ixgbe, igb, i40e, e1000, e1000e,
virtio-net, and forcedeth Linux drivers.

Netmap relies on a kernel module (`netmap.ko`) and modified
device drivers. Userspace programs can use the native API (documented
in `netmap.4`) or a libpcap emulation library.

Most of the codebase is shared between FreeBSD and Linux, and it
is located in `sys/` in the root directory of this repository.
For Linux we use some additional glue code, (`bsd_glue.h`, in this
directory).

Device drivers are taken directly from either the Linux distributions
or vendor-provided out-of-tree drivers, and patched using the files in
the patches/ directory.  Common driver modifications are in the .h
files in this directory. Note that the patches for e1000, forcedeth,
virtio-net have been prepared on the vanilla kernel: this is usually
sufficient for Debian/Ubuntu, but it often fails on Red Hat/CentOS.
The patches for igb, e1000e, ixgbe and i40e, instead, are against
a specific version of the out-of-tree Intel drivers, and should compile
without any problem on the same systems where the original drivers do.

## Linux distributions used and tested

Development:

* Ubuntu 16.04.1 LTS (tested on kernel `4.4.0-53-generic`)
* Archlinux (tested on the `4.8.x` vanilla kernel provided by Arch)

Supported for general compatibility:

* Ubuntu 16.10 (tested on kernel `4.8.0-30-generic`)
* CentOS 7     (tested on kernel `3.10.0-514.2.2.el7.x86_64`)

On Archlinux systems the netmap software is provided by the 'netmap'
AUR package (https://aur.archlinux.org/packages/netmap/).  In general,
you can build and install netmap on any distribution, by following the
instruction in reported in the following [section](#how-to-build-the-code).

## How to build the code

The netmap port for linux is built and installed using the standard
`./configure && make && sudo make install` workflow.

The main purpose of the configure script is to determine the features of
your kernel using simple compile tests, since just trusting the kernel
version number is unreliable. The outcomes of the tests are stored in
a set of macros in the generated `netmap_linux_config.h` file.

The configure script also controls the compilation of optional netmap
features, namely [netmap subsystems](#netmap-subsystems).

### Netmap subsystems

These are optional parts of netmap that can be compiled in with
`--enable-SUBSYSTEM` and ruled out with `--disable-SUBSYSTEM`.
The available subsystems the following (the starred ones are enabled
by default):

* **vale** (\*): the VALE L2 switch (a fast switch that uses the netmap API).
* **pipe** (\*): netmap pipes (pairs of netmap virtual ports connected back to back).
* **monitor** (\*): netmap monitors (can monitor other netmap ports in copy
and zero-copy modes, without stopping traffic).
* **generic** (\*): the generic (a.k.a. emulated) netmap adapter that is
used to access NICs without native netmap support (at reduced performance).
* **ptnetmap** (\*): netmap passthrough support for guests (including the ptnet
driver).
* **sink**: a dummy drop-everything device with native netmap support.
It can emulate a link with configurable packet rate.

### NIC drivers

The emulated (generic) adapter can be used to open in netmap mode any NIC
for which the host OS already supplies a driver. The optimal performance,
however, is only obtained with netmap-enabled NIC drivers.  The configure
script implements two methods to obtain the netmap-enabled drivers:

1. patching the native drivers that come with your kernel;
2. patching NIC-vendors out-of-tree drivers selected by us.

Both methods have advantages and drawbacks and none is perfect.
In method 1 the patches we supply may fail to apply (especially on
Red Hat based distributions), but compilation of successfully patched
drivers usually works. In method 2 the patches will be guaranteed to
apply, but compilation may fail since the out-of-tree drivers may
not support your kernel.

By default `e1000e`, `i40e`, `ixgbe`, `ixgbevf` and igb use method 2,
while `e1000`, `r8169.c`, `forcedeth.c`, `veth.c` and `virtio_net.c`
drivers use method 1\.
The list of supported drivers can be obtained by running configure
with the `--show-drivers` option, while `--show-ext-drivers` lists the
drivers that use method 2 by default. For the latter drivers you may
also choose to use method 1 using the `--no-ext-drivers` (use method
1 for everything) or `--no-ext-drivers=` followed by a comma separated
list of drivers.

For method 1 you need the driver sources for your kernel.

* If you have built your own kernel, you need to tell configure
where the kernel build directory is using the `--kernel-dir=`
option. The build directory must have been prepared for external
modules compilation.

* If you are using the kernel provided by your Linux distribution
you need to install the full kernel-sources package (how to do
so depends on the distribution).  Note that, even when you have
installed the sources, configure will automatically find them
only if they are pointed to by /lib/modules/$(uname -r)/build
or /lib/modules/$(uname -r)/build/sources. If the sources are
anywhere else, you need to tell configure where to find them
using the `--kernel-sources=` options. The `--kernel-dir=` option
must still point to a directory where all the information for
external module compilation is available and there is typically
no need to supply it, since configure is already able to find
it in the standard place.

The configure script selects the patch to apply based only on the
kernel version. Moreover, we only supply patches for the vanilla kernel
from the Torvalds repository (not even the stable kernels). If the
patch selected by configure for a driver fails to apply, the driver
is disabled and will not be built my make.

For method 2 you need an Internet connection, since the external drivers
are downloaded by configure from the vendor repository.  Otherwise,
follow the instructions printed by the script.  The configure script
will try to build the original external driver before applying the
netmap patches: if the clean build fails then the vendor driver does
not support your kernel (yet?) and the driver is disabled.

If you want support for additional drivers please have a look at
`ixgbe_netmap_linux.h` and the patches in patches/ The patch file are
named as `vanilla--DRIVER--LOW--HIGH` where DRIVER is the driver name
to patch, LOW and HIGH are the versions to which the patch applies
(LOW included, HIGH excluded, so `vanilla--r8169.c--20638--30300` applies
from 2.6.38 to 3.3.0 (excluded).

The patches for the external drivers are named VENDOR--DRIVER--VERSION,
where VENDOR is just intel as of now, and VERSION is the upstream driver
version number (assigned by the VENDOR). If you want to use a different
VERSION than the default, and the patches directory contains a patch
for the version you are interest in, you can use the `--select-version`
option of configure. E.g., to select the 5.2.4 version of the ixgbe
external driver, pass `--select-version=ixgbe:5.2.4` to configure.

## How to load netmap in your system

Unload any modules for the network cards you want to use, e.g.

	sudo rmmod ixgbe
	sudo rmmod e1000
	...

Load netmap and device driver module

	sudo insmod ./netmap.ko
	sudo insmod ./ixgbe/ixgbe.ko
	sudo insmod ./e1000/e1000.ko
	...

Turn the interface(s) up

	sudo ifconfig eth0 up # and same for others

Run test applications -- as an example, pkt-gen is a raw packet
sender/receiver which can do line rate on a 10G interface.

Send about 500 million packets of 60 bytes each.
wait 5s before starting, so the link can go up

	sudo pkt-gen -i eth0 -f tx -n 500111222 -l 60 -w 5

On the receiver, you should see about 14.88 Mpps

	sudo pkt-gen -i eth0 -f rx # act as a receiver


## Common problems

* switching in/out of netmap mode causes the link to go down and up.
  If your card is connected to a switch with spanning tree enabled,
  the switch will likely MUTE THE LINK FOR 10 SECONDS while it is
  detecting the new topology. Either disable the spanning tree on
  the switch or use long pauses before sending data;

* Not all cards can do line rate no matter how fast is your software or
  CPU. Several have hardware limitations that prevent reaching the peak
  speed, especially for small packet sizes. Examples:

  - ixgbe cannot receive at line rate with packet sizes that are
    not multiple of 64 (after CRC stripping).
    This is especially evident with minimum-sized frames (-l 60 )

  - some of the low-end 'e1000' cards can send 1.2 - 1.3Mpps instead
    of the theoretical maximum (1.488Mpps)

  - the 'realtek' cards seem unable to send more than 450-500Kpps
    even though they can receive at least 1.1Mpps

* if the link is not up when the packet generator starts, you will
  see frequent messages about a link reset. While we work on a fix,
  use the '-w' argument on the generator to specify a longer timeout

* the ixgbe driver (and perhaps others) is severely slowed down if the
  remote party is sending flow control frames to slow down traffic.
  If that happens try to use the ethtool command to disable flow control.

* netmap does not program the NICs to perform offloadings such as TSO,
  UFO, RX/TX checksum offloadings, etc. As a result, in order to let
  netmap applications correctly interact with the host rings, you need
  to disable these offloadings

      # ethtool -K eth0 tx off rx off gso off tso off gro off lro off

  If offloadings are not disabled, the network stack may try to send
  GSO packets (up to 64KB) that are dropped by netmap (as they are
  too big for the netmap buffers); or the network stack could send
  unchecksummed packets that end up in the host RX ring, and if
  transmitted by netmap on a NIC TX ring they will be dropped by the
  destination as the checksum is wrong.

* if you are using netmap to implement an L2 switch (e.g. using the
  bridge application), you must put the NIC in promiscuous mode,
  otherwise the NIC (usually) drops all the frames whose destination
  MAC is different from the MAC of the NIC.

      # ip link set eth0 promisc on

  Some drivers (e.g. the netmap-patched i40e) may disable promiscuous
  mode during the down/up cycle that happens when putting the NIC
  in netmap mode. This means that it may be necessary to enable
  promiscuous mode again after starting the netmap application.
  If the promiscuous mode was already enabled, you may need to
  disable it before enabling it again. For these drivers, start the
  application first, and then execute these commands:

      # ip link set eth0 promisc off
      # ip link set eth0 promisc on

  or incorporate equivalent operations in your application.

* if you are receiving VLAN-tagged packets, netmap applications (with
  patched drivers) may not see the VLAN tag because receive VLAN offloading
  is enabled (and so VLAN tags are stripped by the NIC). To disable it use

      # ethtool -K eth0 rxvlan off

  In emulated netmap mode (i.e. with unpatched drivers) VLAN tags are never
  visible by the netmap application.

* When opening a veth interface in native netmap mode, the peer veth interface
  must also be opened in native netmap mode, otherwise the traffic won't flow.
  In other words, one cannot use native netmap mode on a veth endpoint and
  use the kernel network stack on the other endpoint. This is not a missing
  feature, as the native veth datapath is implemented using netmap pipes, and
  it does not make sense (in terms of performance) for pipes to support
  conversion between netmap buffers and skbuffs.

* pkt-gen traffic does not flow across a Linux bridge.
  Check that source MAC is not 00:00:00:00:00:00 (pkt-gen default), nor
  ff:ff:ff:ff:ff:ff. See:
  https://elixir.bootlin.com/linux/latest/source/net/bridge/br_input.c#L281


## Additional information

* igb: on linux 3.2 and above the igb driver moved to split buffers,
  and netmap was not updated until end of june 2013.
  Symptoms were inability to receive short packets.

* there are reports of ixgbe and igb unable to read packets.
  We are unable to reproduce the problem.
  - Ubuntu 12.04 LTS 3.5.0-25-generic. igb read problems ?
  - 3.2.0-32-generic with 82598 not working

* e1000e uses regular descriptor up 3.1 at least
  3.2.32 is reported to use extended descriptors
	(in my repo updated at -r 11975)
