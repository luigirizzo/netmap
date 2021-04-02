# Netmap passthrough howto

## 1. Introduction

This document describes how to configure netmap passthrough, a technology
that enables very fast network I/O (up to 30 Mpps and more) for QEMU Virtual
Machines.
With netmap passthrough you can make an arbitrary netmap port (physical NIC,
VALE port, pipe endpoint, monitor, ...) available inside a VM. In this way
your (unmodified) netmap application can run isolated inside a VM, without
losing the performance advantages of netmap. In particular you will still
able to zerocopy across the passed-through netmap ports (a.k.a. ptnetmap
ports).
Netmap passthrough requires support in both host (hypervisor) and guest OS.
Host needs a ptnetmap-capable hypervisor like QEMU (Linux host with KVM
enabled) or bhyve (FreeBSD host). Guest OS requires some ptnetmap drivers that
are already included with netmap, although not enabled by default.
Guest OS ptnetmap drivers are available for both Linux and FreeBSD guests.

Netmap passthrough is an enabler technology for Network Function
Virtualization, as it can be used to build chains of VMs for high-rate
middlebox packet processing. Given the variety
of netmap ports you can decide to connect the VMs together through
zerocopy ports (i.e. netmap pipes), or with copy for untrusted VMs
(i.e. VALE ports). You can get NIC-independent NIC passthrough by
directly passing a dedicated physical netmap port to a VM.

More information about ptnetmap are available in these slides:

* https://github.com/vmaffione/netmap-tutorial/blob/master/virtualization.pdf

and in these papers

* http://info.iet.unipi.it/~luigi/papers/20160613-ptnet.pdf
* http://info.iet.unipi.it/~luigi/papers/20150315-netmap-passthrough.pdf (older)

and in section 7 of this document.

## 2. Configure Linux host and QEMU for ptnetmap

On the Linux host, configure, build and install netmap normally:

	git clone https://github.com/luigirizzo/netmap.git
	cd netmap
	./configure [options]
	make
	sudo make install

Download, build and install the ptnetmap-enabled QEMU:

	git clone https://github.com/netmap-unipi/qemu
	cd qemu
	./configure --target-list=x86_64-softmmu --enable-kvm --enable-vhost-net --disable-werror --enable-netmap
	make
	sudo make install

Load the netmap

	sudo modprobe netmap

Example to run a VM passing through a VALE port (vale1:10):

	sudo qemu-system-x86_64 img.qcow2 -enable-kvm -smp 2 -m 2G -vga std -device ptnet-pci,netdev=data10,mac=00:AA:BB:CC:0a:0a -netdev netmap,ifname=vale1:10,id=data10,passthrough=on

Example to run a VM passing though the "left" endpoints of two pipes endpoints
(the "right" endpoints can be connected to other VMs or netmap programs running
directly on the host.

	sudo qemu-system-x86_64 img.qcow2 -enable-kvm -smp 2 -m 2G -vga std -device ptnet-pci,netdev=data1,mac=00:AA:BB:CC:0b:01 -netdev netmap,ifname=netmap:pipe0{1,id=data1,passthrough=on -device ptnet-pci,netdev=data1,mac=00:AA:BB:CC:0b:02 -netdev netmap,ifname=netmap:pipe1{1,id=data1,passthrough=on


## 3. Configure FreeBSD host and bhyve for ptnetmap
TODO


## 4. Configure Linux guest for ptnetmap

In the Linux guest, compile, build and install netmap with ptnetmap support:

	git clone https://github.com/luigirizzo/netmap.git
	cd netmap
	./configure --enable-ptnetmap
	make
	sudo make install

Load netmap module

	sudo rmmod netmap  # Possibly remove a previous netmap module:
	sudo modprobe netmap

As the netmap module is loaded, a new network interface will show up for each
passed-through netmap port, (e.g. 'ens4'). You can check that an interface is
a netmap passthrough one checking the driver:

	ethtool -i ens4
	  driver: ptnetmap-guest-drivers
	  version:
	  [...]

A guest ptnetmap port behaves like any other netmap ports. You can use pkt-gen
to test transmission;

	sudo pkt-gen -i ens4 -f tx


## 5. Use ptnetmap with FreeBSD guests

Netmap passthrough guest drivers are already included with netmap from FreeBSD
12 versions. When running FreeBSD guest with ptnetmap ports (e.g. using QEMU as
described above), an interface called "ptnet$N" will show up for each passed
through port.
If you want to use ptnetmap with older FreeBSD guests you can just update your
FreeBSD source tree with the updated netmap code from github and rebuild your
kernel.


## 6. ptnetmap tunables

While ptnetmap is mainly designed for the VMs to run middleboxes applications
(e.g. firewall, DDoS prevention, load balancing, IDS, typically carried out
by network operators), it also offers good performance when VMs run TCP/UDP
user applications. To make this possible, virtualized offloadings are
supported using the virtio-net header defined by the VirtIO standard
(http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1680006).
When the header is enabled in the guest OS and supported by the VM network
backend (e.g. VALE port and TAP devices both support it), two VMs on the
same host (e.g. connected through a VALE switch) can exchange TSO packets
(up to 64KB each) without the need to perform any TCP segmentation or
computing TCP checksums.
This header is the key for very high TCP VM-to-VM throughput (20+ Gbps),
and it is stored before the ethernet header of each packet sent or received
by your VMs.
If you want to use ptnetmap mainly to run middleboxes application (which
is the common case), you should disable the virtio-net header in the guest
OS:

	# echo 0 > /sys/module/netmap/parameters/ptnet_vnet_hdr

This step is needed to avoid performance issues in case your datapath exits the
hypervisor host through a physical NIC or goes through netmap ports that don't
support the virtio-net header.


## 7. Some background about ptnetmap

Netmap is a framework for high performance network I/O. It exposes an
hardware-independent API which allows userspace application to directly interact
with NIC hardware rings, in order to receive and transmit Ethernet frames.
Rings are always accessed in the context of system calls and NIC interrupts
are used to notify applications about NIC processing completion.
The performance boost of netmap w.r.t. traditional socket API primarily comes
from: (i) batching, since it is possible to send/receive hundreds of packets
with a single system call, (ii) preallocation of packet buffers and memory
mapping of those in the application address space.

Several netmap extension have been developed to support virtualization.
Netmap support for various paravirtualized drivers - e.g. virtio-net, Xen
netfront/netback - allows netmap applications to run in the guest over fast
paravirtualized I/O devices.

The Virtual Ethernet (VALE) software switch, which supports scalable high
performance local communication (over 20 Mpps between two switch ports), can
then be used to connect together multiple VMs.

However, in a typical scenario with two communicating netmap applications
running in different VMs (on the same host) connected through a VALE switch,
the journey of a packet is still quite convoluted. As a matter of facts,
while netmap is fast on both the host (the VALE switch) and the guest
(interaction between application and the emulated device), each packet still
needs to be processed from the hypervisor, which needs to emulate the
device model used in the guest (e.g. e1000, virtio-net). The emulation
involves device-specific overhead - queue processing, format conversions,
packet copies, address translations, etc. As a consequence, the maximum
packet rate between the two VMs is often limited by 2-5 Mpps.

To overcome these limitations, ptnetmap has been introduced as a passthrough
technique to completely avoid hypervisor processing in the packet
datapath, unblocking the full potential of netmap also for virtual machine
environments.
With ptnetmap, a netmap port on the host can be exposed to the guest in a
protected way, so that netmap applications in the guest can directly access
the rings and packet buffers of the host port, avoiding all the extra overhead
involved in the emulation of network devices. System calls issued by guest
applications on ptnetmap ports are served by kernel threads (one
per ring) running in the netmap host.

Similarly to VirtIO paravirtualization, synchronization between
guest netmap (driver) and host netmap (kernel threads) happens through a
shared memory area called Communication Status Block (CSB), which is used
to store producer-consumer state and notification suppression flags.

Two notification mechanisms needs to be supported by the hypervisor to allow
guest and host netmap to wake up each other.
On QEMU/bhyve, notifications from guest to host are implemented with accesses
to I/O registers which cause a trap in the hypervisor. Notifications in the
other direction are implemented using KVM/bhyve interrupt injection mechanisms.
MSI-X interrupts are used since they have less overhead than traditional
PCI interrupts.

Since I/O register accesses and interrupts are very expensive in the common
case of hardware assisted virtualization, they are suppressed when not needed,
i.e. each time the host (or the guest) is actively polling the CSB to
check for more work. From an high-level perspective, the system tries to
dynamically switch between polling operation under high load, and
interrupt-based operation under lower loads.

The original ptnetmap implementation required ptnetmap-enabled virtio-net/e1000
drivers. Only the notification functionalities of those devices were reused,
while the datapath (e.g. e1000 rings or virtio-net Virtual Queues) was
completely bypassed.

The ptnet device has been introduced as a cleaner approach to ptnetmap that
also adds the ability to interact with the standard TCP/IP network stack
and supports multi-ring netmap ports. The introduction of a new device model
does not limit the adoption of this solution, since ptnet drivers are
distributed together with netmap, and hypervisor modifications are needed in
any case.

The ptnet device belongs to the classes of paravirtualized devices, like
virtio-net. Unlike virtio-net, however, ptnet does not define an interface
to exchange packets (datapath), but the existing netmap API is used instead.
However, a CSB - cleaned up and extended to support an arbitrary number of
rings - is still used for producer-consumer synchronization and notification
suppression.

A number of device registers are used for configuration (number of rings and
slots, device MAC address, supported features, ...) while "kick" registers
are used for guest-to-host notifications.
The ptnetmap kthread infrastructure, moreover, has been already extended to
support an arbitrary number of rings, where currently each ring is served
by a different kernel thread.
