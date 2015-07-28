This directory contains a port of netmap to Windows.

------------ BRIEF DESCRIPTION ----------

The solution Netmap.sln contains 5 different projects:
Netmap
Netmap Package
NetmapNdis
NetmapNdis Package
NetmapLoader

- Netmap: the core of Netmap, can be used by itself to create Vale ports and pipes between applications
- Netmap package: a Test signed version of Netmap to be used on a 64 bit version of Windows with Test Sign mode activated
- NetmapNdis: this is the Ndis module, used to attach the netmap core to a physical network device
- NetmapNdis Package:  a Test signed version of the NDIS driver to be used on a 64 bit version of Windows with Test Sign mode activated
- NetmapLoader: a userspace program to dynamically (un)load the Netmap kernel module without the need to install it and load it at OS startup.

Outside the Windows solution, under <root directory>\examples, is available pkt-gen, a userspace program used to test the speed of a 
link between two netmap interfaces.


------------ NETMAP INSTALL INSTRUCTIONS (core)------------
There are two methods available to install Netmap: the first one is dynamically, the second one is by installing it as a service and let it be 
loaded at boot time with other kernel modules.

a) DINAMICALLY LOAD: 
    - Open a CMD window with administrative privileges
    - Change into the directory containing Netmap.sys and Netmaploader.exe
    - Execute the command "NetmapLoader L"; if the module has been loaded a successful message will be written on the console window, 
	otherwise an error code will be written.
    - To dinamically unload the module just execute the command "Netmaploader U"

b) INSTALL MODULE
    - Open the folder containing Netmap.sys/.inf/.cat
    - Right click on the .inf file and select -INSTALL- from the context menu; after a reboot the module will be correctly loaded

------------ NETMAP INSTALL INSTRUCTIONS (NDIS module)------------
    - open the configuration panel for the network card in use (Control panel -> network and sharing center -> Change adapter settings)
    - right click on an adapter then click Properties
    - click on Install->Service->Add
    - click on 'Driver Disk' and select nmNdis.inf' in this folder
    - select 'Netmap NDIS' which is the only service you should see
    - click accept on the warnings for the installation of an unsigned
      	driver (roughly twice per existing network card)

If the Netmap kernel module has been installed in a dynamic way, remember to disinstall 
the NDIS module before an eventual shutdown/reboot and before unloading the Netmap Core Module.

------------ NETMAP BUILD INSTRUCTIONS ----------
Requirements:
    - Visual Studio 2013 (any version) [https://www.visualstudio.com/downloads/download-visual-studio-vs]
       used to build the kernelspace modules in conjunction with WDK8.1
       used to build the NetmapLoader userspace program
    - Windows Driver Kit (WDK) version 8.1 update [https://msdn.microsoft.com/en-us/windows/hardware/gg454513.aspx]
    - Cygwin, [http://www.cygwin.com/] with base packages, make, c compiler, eventually gdb
        used to build the userspace program pkt-gen


a) Build by using the Visual studio GUI
    - Open the <root directory>\WINDOWS\VsSolution\Netmap.sln solution
    - Select on the build type combobox the kind of operative system (Win7/8/8.1) and the kind of build needed (Debug/Release)
    - Click on "Compile", then "Compile solution"
    - The output will be found under <root directory>\WINDOWS\VsSolution\Output\<choosen build type>\

b) Build by using the command line and MsBuild.exe
    - Change into one of these directories
	On 32-bit machines they can be found in: C:\Program Files\MSBuild\12.0\bin
	On 64-bit machines the 32-bit tools will be under: C:\Program Files (x86)\MSBuild\12.0\bin
		and the 64-bit tools under: C:\Program Files (x86)\MSBuild\12.0\bin\amd64
    - Execute the command " MsBuild <netmap project dir>\WINDOWS\VsSolution\Netmap.sln /t:Build /p:Configuration=Release;Platform=Win32 "
      where Configuration and Platform parameter depends on what kind of build is needed.
    - The output will be found under <root directory>\WINDOWS\VsSolution\Output\<choosen build type>\

	Using as configuration the keywords Debug/Release will automatically switch the selected configuration to "Current OS"-Debug/Release.
	If a build for a certain OS is needed valid options are
    		- "Win7 Debug" or "Win7 Release"
    		- "Win8 Debug" or "Win8 Release"
    		- "Win8.1 Debug" or "Win8.1 Release"

------------ PKT-GEN example building INSTRUCTIONS ----------
To build the pkt-gen example the following steps are required:
    - Open an instance of Cygwin Terminal
    - Change into the directory <netmap root dir>/WINDOWS/VsSolution
    - Execute the command ./bpgen.bat
    - The output will be found under <netmap root dir>/examples (pkt-gen.exe and pkt-gen-b.exe)



------------ GENERAL TIPS -----------------------------------
To use pkt-gen under Hyper-V with a physical device (generic) two precautions are needed
- Always specify the MAC address of the sender
- Go into the configuration of the VM and under "setting->NIC->Advanced Features" enable "Mac Spoofing" or else the packets will be discarded by the 
     Hyper-V virtual switch
