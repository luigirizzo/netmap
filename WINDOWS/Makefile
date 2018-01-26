# Makefile for netmap on windows
#
# Compile netmap as a module, useful if you want a netmap bridge
# or loadable drivers.

#.include <bsd.own.mk> # FreeBSD 10 and earlier
# .include "${SYSDIR}/conf/kern.opts.mk"

.PATH: ${.CURDIR}/../sys/dev/netmap
.PATH.h: ${.CURDIR}/../sys/net

CC="C:/Program Files (x86)/Microsoft Visual Studio 12.0/VC/bin/x86_amd64/CL.exe"

#CFLAGS += -I${.CURDIR}/../../sys -include win_glue.h
#CFLAGS += -DAMD64=1

DDK_BASE = "C:\Program Files (x86)\Windows Kits\8.1"
DDK_INC = ${DDK_BASE}/Include"
DDK_LIB = ${DDK_BASE}/lib/winV6.3/KM/x64"

OUTDIR = "${.CURDIR}/VsSolution/Output/Intermediate/Win8.1Release-X64"
DSTDIR = "${.CURDIR}/VsSolution/Output/NetmapWin8.1Release"

CFLAGS += -Zi -nologo -W4 -Wx -O2 -Ob2 -Ot -Oy0
CFLAGS += -GL 
CFLAGS += -D_WIN64 -D_AMD64_ -DAMD64
CFLAGS += -D _WIN32_WINNT=0x0603 -D WINVER=0x0603 -D WINNT=1 -D NTDDI_VERSION=0x06030000
CFLAGS += -GF -GM- =Zp8 -GS -Gy
CFLAGS += -fp:precise -Zc:wchar_t- -Zc:forScope- -GR-
CFLAGS += -Gz
CFLAGS += -wd4603 -wd4627 -wd4986 -wd4987 -wd4996
CFLAGS += -FO"${DDK_INC}/Shared/warning.h"
CFLAGS += -errorReport:queue -kernel -cbstring -d2epilogunwind
CFLAGS += -d1nodatetime -d1import_no_registry -d2AllowCompatibleILVersions -d2Zi+

RC_CFLAGS = -D _WIN64 -D _AMD64_=1 -D AMD64
RC_CFLAGS += -D _WIN32_WINNT=0x0603 -D WINVER=0x0603 -D WINNT=1 -D NTDDI_VERSION=0x06030000
RC_CFLAGS += =D "SMP_ID=\\\"{dd38f7fc-d7bd-488b-9242-7d8754cde80d}\\\"" -l"0x0409"
RC_CFLAGS += -I${DDK_INC}/UM"
RC_CFLAGS += -I${OUTDIR}"
RC_CFLAGS += -nologo -fo"${OUTDIR}/netmap_windows.res"

LD = C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_amd64\link.exe

LD_FLAGS :=
LD_FLAGS += /ERRORREPORT:QUEUE /OUT:"${DSTDIR}/Netmap.sys"
LD_FLAGS += /VERSION:"6.3" /INCREMENTAL:NO /NOLOGO /WX /SECTION:"INIT,d"

LD_FLAGS += ${DDK_LIB}/BufferOverflowFastFailK.lib"
LD_FLAGS += ${DDK_LIB}/ntoskrnl.lib"
LD_FLAGS += ${DDK_LIB}/hal.lib"
LD_FLAGS += ${DDK_LIB}/wmilib.lib"
LD_FLAGS += /NODEFAULTLIB /MANIFEST:NO /DEBUG
LD_FLAGS += /PDB:"${DSTDIR}/Netmap.pdb"
LD_FLAGS += /SUBSYSTEM:NATIVE,"6.03" /Driver /OPT:REF /OPT:ICF /ENTRY:"GsDriverEntry" /RELEASE
LD_FLAGS += /IMPLIB:"${DSTDIR}/Netmap.lib"
LD_FLAGS += /MERGE:"_TEXT=.text;_PAGE=PAGE" /MACHINE:X64 /PROFILE /kernel
LD_FLAGS += /IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4218,4235
LD_FLAGS += /osversion:6.3 /pdbcompress /debugtype:pdata
LD_FLAGS += ${OUTDIR}/netmap_windows.res"



APP_CFLAGS = -I../sys -Iincludes -I../apps/include -DNO_PCAP
APP_CFLAGS += -g -O2 -Wall -Werror

KMOD	= netmap

HDRS	+=
HDRS	+= netmap_mem2.h
HDRS	+= netmap_mbq.h
HDRS	= device_if.h bus_if.h opt_netmap.h
HDRS	+= opt_inet.h opt_inet6.h
# netmap.h netmap_kern.h

SRCS	:=
SRCS	+= netmap.c
SRCS	+= netmap_generic.c
SRCS	+= netmap_mbq.c
SRCS	+= netmap_mem2.c
SRCS	+= netmap_monitor.c
SRCS	+= netmap_pipe.c
SRCS	+= netmap_vale.c
SRCS	+= netmap_legacy.c
SRCS	+= netmap_windows.c
SRCS	+= win_glue.c


MSBUILD	="/cygdrive/c/Program Files (x86)/MSBuild/12.0/Bin/MSBuild.exe"

all: _msbuild _apps

_msbuild:
	@echo "--- the makefile is not working yet, use msbuild ---"
	rm -rf Output*
	$(MSBUILD) netmap.sln /t:Build /p:Configuration="Win8.1 Release" -p:Platform=x64

_apps:
	gcc $(APP_CFLAGS) ../apps/pkt-gen/pkt-gen.c  -o ../apps/pkt-gen/pkt-gen.exe
	gcc $(APP_CFLAGS) ../apps/pkt-gen/pkt-gen.c -DBUSYWAIT -o ../apps/pkt-gen/pkt-gen-b.exe
	gcc $(APP_CFLAGS) ../apps/bridge/bridge.c -DBUSYWAIT -Wno-unused-function -o ../apps/bridge/bridge-b.exe
	gcc $(APP_CFLAGS) ../apps/vale-ctl/vale-ctl.c -Wno-unused-function -o ../apps/vale-ctl/vale-ctl.exe
	
clean:
	rm -rf Output*

_old_all: pre-build do-build


pre-build:
	-rm -rf win-build
	mkdir -p win-build
	cp -p ../sys/dev/netmap/*.[ch] win-build
	cp -p *.[ch] win-build
	cp -p Makefile win-build
	(cd win-build; touch opt_inet.h opt_inet6.h opt_netmap.h device_if.h bus_if.h)

_loader:
	$(MSBUILD) Loader/loader.vcxproj /t:Build /p:Configuration="Win8.1 Release" -p:Platform=x64

_netmap: clean
	$(MSBUILD) netmap.vcxproj -t:Build -p:Configuration="Win8.1 Release" -p:Platform=x64

_nm-ndis: clean
	$(MSBUILD) nm-ndis/nm-ndis.vcxproj -t:Build -p:Configuration="Win8.1 Release" -p:Platform=x64

do-build:
	cd win-build; make body

body:	$(SRCS)
	# clcompile
	$(CC) $(CFLAGS) $(SRCS)
	# resource compile
	$(CC) $(RC_CFLAGS) netmap_windows.rc

