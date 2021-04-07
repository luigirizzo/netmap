**************************************************************
DISCLAIMER: This documentation is currently outdated.
            It is going to be updated soon.
**************************************************************

This directory contains the Windows version of netmap, developed by
Alessio Faina as part of his MS thesis at the Universita` di Pisa.

This version is made of two kernel modules, that should be built
as indicated in the "BUILD INSTRUCTIONS" section below,
which also build the standard netmap test program, pkt-gen.

    netmap.sys
	implements the netmap API, VALE switch, netmap pipes, monitor
	ports.  Performance is similar to that on FreeBSD and Linux:
	20Mpps on switch ports, over 100 Mpps on pipes.

	To load the module, do the following (as administrator)

	    (cd Output-Win8.1Release/netmap-pkg; ./nm-loader l)

	To test the functionality you can run the following programs
	in two terminals

	    ../examples/pkt-gen -i vale1:a -f tx # sender

	    ../examples/pkt-gen -i vale1:b -f rx # receiver

	The module can be unloaded with

	    (cd WINDOWS/Output-Win8.1Release/netmap-pkg; ./nm-loader u)

    nm-ndis.sys
	implements access to the NIC and the host stack using native
	Windows NIC drivers. Though faster than sockets, speed is only
	1-2 Mpps, limited by the standard device drivers.

	The module must be installed as a network service (see
	"INSTALL NM-NDIS" below) after which you can send or receive
	packets using any netmap application and

		netmap:ethXX

	as the port name. XX is the Windows "interface index" that
	can be shown with the following command (or many other ways):

		netsh int ipv4 show interfaces

Note that on 64-bit platforms kernel modules should be signed.
The build script does a Test-sign of the modules, and to load them one
should run the Operating System in Test-mode.

-------------------- BUILD INSTRUCTIONS --------------------

To build the kernel modules and the sample programs you need to
install the following tools (in this order):

  - Visual Studio 2013 (the "express" version suffices)

	https://www.visualstudio.com/downloads/download-visual-studio-vs

    Note, the 2013 version is reachable from the 'Download older versions' link

  - Windows Driver Kit (WDK) version 8.1 update

	https://msdn.microsoft.com/en-us/windows/hardware/gg454513.aspx

  - Cygwin

	http://www.cygwin.com/

   with base packages, make, C compiler, possibly git and other utilities
   used to build the sample programs pkt-gen

There are two build methods:

a) Build with command line tools and MsBuild.exe

   We have a makefile which builds everything, just run

	make		# will build all projects and pkt-gen

	make clean	# will clean output directories

   The output will be found in the directory ./Output-<chosen build type>

   Please look at the makefile to select different configurations

b) Build with the Visual studio GUI

    - Open the <root directory>\WINDOWS\VsSolution\Netmap.sln solution
    - Select on the build type combobox the type of Operating System (Win7/8/8.1)
      and the type of build (Debug/Release)
    - Click on "Compile", then "Compile solution"
    - The output will be found under
	<root directory>\WINDOWS\Output-<chosen-build-type>\


------------------- INSTALL NETMAP.SYS -------------------

The easiest way to install the netmap core module NETMAP.SYS is to
use the nm-loader program that we build together with the programs:

    - Open a "cmd" window with administrative privileges
    - Change into the directory containing netmap.sys< typically
		WINDOWS/Output-Win8.1Release/netmap-pkg

    - To load the module, run
		../nm-loader l
      a message will report the success or failure of the operation

    - To unload the module run
		../nm-loader u

You can also install the module permanently, as follows:

    - Open the folder containing netmap.{sys|inf|cat} , same as above
    - Right click on the .inf file and select -INSTALL- from the
      context menu; after a reboot the module will be correctly loaded

------------------- INSTALL NM-NDIS -------------------

The nm-ndis.sys module implements a lightweight filter that runs
as a service on an adapter, and is used access the host stack and
the NIC from netmap. It can be installed as follows:

    - open the configuration panel for the network card in use
       " Control panel -> network and sharing center -> Change adapter settings "
    - right click on an adapter then click on " Properties "
    - click on " Install -> Service -> Add "
    - click on 'Driver Disk' and select the folder
		WINDOWS/Output-Win8.1Release/nm-ndis-pkg
    - select the service "Netmap NDIS LightWeight Filter"
    - click accept on the warnings for the installation of an unsigned
      or test-signed driver

If the netmap.sys module is not installed permanently, remember to
deinstall the nm-ndis.sys module before a shutdown/reboot and before
unloading netmap.sys

------------------- PERFORMANCE -------------------

The typical experiment involve one netmap sender and one netmap receiver

	pkt-gen-b -i <interface-name> -f tx ...
	pkt-gen-b -i <interface-name> -f rx ...

The above version of pkt-gen uses busy-wait. The interface name can
be a VALE port or a NIC or host port using the nm-ndis module
(emulating the netmap API, so not as fast as the drivers using
native netmap mode available on FreeBSD and Linux).

    VALE port:	20-30Mpps with broadcast frames

	pkt-gen-b -i vale0:a -f tx
	pkt-gen-b -i vale0:b -f rx

    NETMAP pipe	up to 180 Mpps

	pkt-gen-b -i vale0:a}1 -f tx
	pkt-gen-b -i vale0:a{1 -f rx

    NETMAP to HOST ring	about 2.3 Mpps if dropped, 1.8Mpps to windump
       (replace the '5' with the interface index from
		netsh int ipv4 show interfaces

	pkt-gen-b -i netmap:eth5^ -f tx	# on one vm

    NETMAP to NIC ring		about 1Mpps VM-to-VM

	pkt-gen-b -i netmap:eth5 -f tx	# on one vm
	pkt-gen-b -i netmap:eth5 -f rx	# on another vm


------------------- GENERAL TIPS -------------------

Performance testing requires a bit of attention to make sure that
processes do not move between different cores, that the CPU clock
speed does not change, and that the switch does not drop packets
because of unrecognised MAC addresses.

--- Configuration of the software switch (Hyper-V) ---
- Always specify the MAC address of the sender
- By default, Hyper-V drops packets with MAC addresses not associated
  to the given port. To allow any traffic,
	Go into the configuration of the VM
	under "setting->NIC->Advanced Features"
	enable "Mac Spoofing"

--- Pinning cores (Hyper-V) ---
	Go into the configuration of the VM
	under settings->Processor
		Virtual machine reserve (percentage)	100
		(not clear if there is a way to pin the thread)

------------------- CODE OVERVIEW -------------------

KERNEL CODE:
The core netmap kernel code in the sys/ directory is the same one
used also on FreeBSD and Linux. The WINDOWS/ directory contains
windows specific code, mostly to implement the I/O system calls and
mmap support, and remap FreeBSD or Linux kernel data structures and
functions into Windows equivalents.

Access to the host stack and to NICs is implemented through an ndis
filter module, which is in the WINDOWS/nm-ndis directory.
The code comes from the examples contained in the Windows DDK (see
the license.rtf file) with small modifications -- about 500 lines
of code overall -- to interface with the main netmap module.

We have an additional utility, nm-loader, to load and unload the
netmap kernel module from the command line (eventually we may
provide a similar one for the filter).

To build the kernel modules we use the compiler from Visual Studio.

For convenience, we have construted the "solution" file and the various
project files with VSC, and then manually cleaned up the .vcxprj files
to remove the infinite copies of the same set of options generated
by the GUI. The configurations include instructions to sign the drivers
in Test-sign mode.
We then have a simple Makefile that calls MSbuild with the correct
configuration options.

Eventually we plan to invoke the compiler and signing tools directly
from the makefile avoidin the vcxprj and .sln files.

USER APPLICATIONS:
Netmap user applications only use ioctl(), mmap() and poll() and do not
need any new system call. We compile them with gcc under Cygwin,
and eventually we expect the same source code to be compilable under
all platform that support netmap.

Unfortunately, on Windows, mmap and poll are not
supported so we emulate them through special ioctl's. The mmap()
emulation is relatively straightforward -- netmap_user.h redefines
it to the wrapper function. For poll() things are a bit more
difficult, as we have not yet modified the Cygwin wrapprers that
support poll. As a consequence, at the moment our poll() emulation
only handles a single file descriptor. This is enough for our pkt-gen
program, but netmap programs using multiple file descriptors need
manual changes.


The file netmap.sln contains the following projects:

netmap
    the core of the netmap kernel module, can be used by itself to
    create VALE ports and netmap pipes

netmap-pkg
    a Test signed version of netmap module to be used on a 64 bit version
    of Windows with Test Sign mode activated

nm-ndis
    a kernel module to attach the netmap core to a
    physical network devices through NDIS hooks

nm-ndis-pkg
    a Test signed version of the above, again for use on 64 bit versions
    of Windows with Test Sign mode activated

loader
    a userspace program to dynamically load and unload the Netmap kernel
    module without the need to install it and load it at OS startup.

Projects are visual studio files, .vcxprj . The format is defined in
http://blog.bfitz.us/?p=922
