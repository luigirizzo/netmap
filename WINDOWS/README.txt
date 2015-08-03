This directory contains a port of netmap to Windows.

For installation instructions see below

When using netmap with Windows NICs, the name to be
specified for the interface is the 'interface index'
which is the first number visible with the "route print" command

------------ BRIEF DESCRIPTION ----------

The solution Netmap.sln contains 5 different projects:
Netmap
Netmap Package
NetmapNdis
NetmapNdis Package
NetmapLoader

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

Projects are visual studio files, .vcxprj . The format is defined

http://blog.bfitz.us/?p=922

The directory ../examples contains pkt-gen, a userspace program
used to test the speed of a link between two netmap interfaces.


------------ NETMAP INSTALL INSTRUCTIONS (core)------------
Netmap modules can be loaded dynamically, or installed as a service
and loaded at boot time.

a) DYNAMIC LOAD: 
    - Open a "cmd" window with administrative privileges
    - Change into the directory containing Netmap.sys and Netmaploader.exe
    - To load the module, run "NetmapLoader L"; a message on the console window will
      report the success or failure of the operation

    - To unload the module run "Netmaploader U"

b) PERSISTENT INSTALL MODULE
    - Open the folder containing Netmap.{sys|inf|cat}
    - Right click on the .inf file and select -INSTALL- from the
      context menu; after a reboot the module will be correctly loaded

------------ NETMAP INSTALL INSTRUCTIONS (NDIS module)------------
    - open the configuration panel for the network card in use
       " Control panel -> network and sharing center -> Change adapter settings "
    - right click on an adapter then click on " Properties "
    - click on " Install -> Service -> Add "
    - click on 'Driver Disk' and select 'nmNdis.inf' in this folder
    - select 'Netmap NDIS' which is the only service you should see
    - click accept on the warnings for the installation of an unsigned
      driver (roughly twice per existing network card)

If the Netmap kernel module has been installed in a dynamic way,
remember to deinstall the NDIS module before a shutdown/reboot
and before unloading the Netmap Core Module.

------------ NETMAP BUILD INSTRUCTIONS ----------
Requirements:
To build the module you need to install (in this order):
  - Visual Studio 2013 (express is enough)
	https://www.visualstudio.com/downloads/download-visual-studio-vs
      Note, you can reach the 2013 version from the
	'Download older versions' link

  - Windows Driver Kit (WDK) version 8.1 update
	https://msdn.microsoft.com/en-us/windows/hardware/gg454513.aspx

 - Cygwin,
	http://www.cygwin.com/
   with base packages, make, c compiler, eventually gdb
   used to build the userspace program pkt-gen


a) Build with the Visual studio GUI
    - Open the <root directory>\WINDOWS\VsSolution\Netmap.sln solution
    - Select on the build type combobox the type of Operating System (Win7/8/8.1)
      and the type of build (Debug/Release)
    - Click on "Compile", then "Compile solution"
    - The output will be found under
	<root directory>\WINDOWS\VsSolution\Output\<chosen-build-type>\

b) Build with command line tools and MsBuild.exe
    - Select one of these directories, depending on the architecture

	32-bit host, 32-bit tools	C:\Program Files\MSBuild\12.0\bin
	64-bit host, 32-bit tools	C:\Program Files (x86)\MSBuild\12.0\bin
	64-bit host, 64-bit tools	C:\Program Files (x86)\MSBuild\12.0\bin\amd64

      (you can add it to the path or prepend the path to the MSBuild command below)

    - In the WINDOWS/VsSolution directory run the command
	 " MsBuild Netmap.sln /t:Build /p:Configuration=Release;Platform=Win32 "
/cygdrive/c/Program\ Files\ \(x86\)/MSBuild/12.0/Bin/MSBuild.exe /t:Build /p:Configuration=Release;Platform=Win32
      where Configuration and Platform parameter depends on what kind of build is needed.

    - The output will be found in the directory ./Output/<choosen build type>

       Using as configuration the keywords Debug/Release will
       automatically switch the selected configuration to "Current
       OS"-Debug/Release.

	If a build for a certain OS is needed valid options are
    		- "Win7 Debug" or "Win7 Release"
    		- "Win8 Debug" or "Win8 Release"
    		- "Win8.1 Debug" or "Win8.1 Release"

------------ PKT-GEN example building INSTRUCTIONS ----------
To build the pkt-gen example the following steps are required:
    - Open an instance of Cygwin Terminal
    - Change into the directory <netmap root dir>/WINDOWS/VsSolution
    - Execute the command ./bpgen.bat
    - The output will be found under <netmap root dir>/examples
    (pkt-gen.exe and pkt-gen-b.exe)



------------ GENERAL TIPS -----------------------------------
To use pkt-gen under Hyper-V with a physical device (generic) two precautions are needed
- Always specify the MAC address of the sender
- Go into the configuration of the VM and under "setting->NIC->Advanced Features" enable "Mac Spoofing" or else the packets will be discarded by the 
     Hyper-V virtual switch
