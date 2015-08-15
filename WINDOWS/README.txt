This directory contains a port of netmap to Windows, developed by Alessio
Faina as part of his MS thesis at the Universita` di Pisa.

This port is made of two kernel modules, that you should build as indicated
in the "BUILD NETMAP MODULES" section below.

    netmap.sys
	implements the netmap API, VALE switch, netmap pipes, monitor ports.
	Performance is similar to that on FreeBSD and Linux: 20Mpps on switch
	ports, over 100 Mpps on pipes.

 	To load the module, do the following (as adminstrator)

		(cd Output-Win8.1Release/netmap-pkg; ./nm-loader l)

	To test the functionality you can run the following programs
	in two terminals

		../examples/pkt-gen -i vale1:a -f tx # sender

		../examples/pkt-gen -i vale1:b -f rx # receiver

	The module can be unloaded with

		(cd WINDOWS/Output-Win8.1Release/netmap-pkg; ./nm-loader u)

    nm-ndis.sys
	implements access to the NIC and the host stack using native Windows
	NIC drivers. Though faster than sockets, speed is limited by the device
	drivers, in the 1-2Mpps range.

	The module must be installed as a network service (see "INSTALL NM-NDIS" below)
	after which you can send or receive packets using any netmap application and

		netmap:ethXX

	as the port name. XX is the Windows "interface index" that can be
	shown with the followin command (or many other ways):

		netsh int ipv4 show interfaces

Note that on 64-bit platforms kernel modules should be signed.
The build script we supply do a Test-sign of the modules,
and to load them you should run the system in Test-mode.

------------ BUILD NETMAP MODULES ----------

To build the module you need to install (in this order):
  - Visual Studio 2013 (express is enough)
	https://www.visualstudio.com/downloads/download-visual-studio-vs
      Note, you can reach the 2013 version from the
	'Download older versions' link

  - Windows Driver Kit (WDK) version 8.1 update
	https://msdn.microsoft.com/en-us/windows/hardware/gg454513.aspx

 - Cygwin,
	http://www.cygwin.com/
   with base packages, make, C compiler, possibly git and other utilities
   used to build the userspace program pkt-gen

a) Build with command line tools and MsBuild.exe
   We have a makefile which builds everything, just run
	make		# will build all projects and pkt-gen
	make clean	# will clean output directories

   The output will be found in the directory ./Output-<choosen build type>

   Please look at the makefile to select different configurations

b) Build with the Visual studio GUI
    - Open the <root directory>\WINDOWS\VsSolution\Netmap.sln solution
    - Select on the build type combobox the type of Operating System (Win7/8/8.1)
      and the type of build (Debug/Release)
    - Click on "Compile", then "Compile solution"
    - The output will be found under
	<root directory>\WINDOWS\Output-<chosen-build-type>\



------------ INSTALL NETMAP.SYS ------------

The easiest way to install the netmap core is manually, using the nm-loader
program that we build.

    - Open a "cmd" window with administrative privileges
    - Change into the directory containing netmap.sys< typically
		WINDOWS/Output-Win8.1Release/netmap-pkg

    - To load the module, run
		../nm-loader l
      a message on the console window will report the success or failure of the operation

    - To unload the module run
		../nm-loader u

You can also install the module persistently, as follows:

    - Open the folder containing netmap.{sys|inf|cat} , same as above
    - Right click on the .inf file and select -INSTALL- from the
      context menu; after a reboot the module will be correctly loaded

------------ INSTALL NM-NDIS ------------
The nm-ndis module implements a lightweight filter that runs as a service
on an adapter, and is used access the host stack and the NIC from netmap.

netcfg
    - open the configuration panel for the network card in use
       " Control panel -> network and sharing center -> Change adapter settings "
    - right click on an adapter then click on " Properties "
    - click on " Install -> Service -> Add "
    - click on 'Driver Disk' and select the folder
		WINDOWS/Output-Win8.1Release/nm-ndis-pkg
    - select the service "Netmap NDIS LightWeight Filter"
    - click accept on the warnings for the installation of an unsigned
      or test-signed driver

If the netmap core module has been installed in a dynamic way,
remember to deinstall the nm-ndis module before a shutdown/reboot
and before unloading the netmap core module.



------------ GENERAL TIPS -----------------------------------
Performance testing requires a bit of attention to make sure
that processes do not move between different cores, that the
CPU clock speed does not change, and that the switch does not
drop packets because of unrecognised MAC addresses.

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

--- PERFORMANCE ---

The typical experiment involve one netmap sender and one netmap receiver

	pkt-gen-b -i <interface-name> -f tx ...
	pkt-gen-b -i <interface-name> -f rx ...

this version of pkt-gen uses busy-wait. The interface name can be a VALE port
or a NIC or host port using the nm-ndis module (emulating the netmap API,
so not as fast as the drivers using native netmap mode available on FreeBSD
and Linux).

VALE port:	30Mpps with broadcast frames

	pkt-gen-b -i vale0:a -f tx
	pkt-gen-b -i vale0:b -f rx

NETMAP pipe	up to 180 Mpps

	pkt-gen-b -i vale0:a}1 -f tx
	pkt-gen-b -i vale0:a{1 -f rx

NETMAP to HOST ring	about 2.3 Mpps if dropped, 1.8Mpps to windump
	pkt-gen-b -i netmap:1^ -f tx	# on one vm

NETMAP to NIC ring	about 1Mpps VM-to-VM
	pkt-gen-b -i netmap:1 -f tx	# on one vm
	pkt-gen-b -i netmap:1 -f rx	# on another vm

------------ BRIEF DESCRIPTION ----------

The solution Netmap.sln contains the following projects:

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

sysctl
    (not complete) a tool to manipulate the sysctl variables in the netmap module.

Projects are visual studio files, .vcxprj . The format is defined in

http://blog.bfitz.us/?p=922
