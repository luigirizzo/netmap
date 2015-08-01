# Makefile for netmap on windows
#
# Compile netmap as a module, useful if you want a netmap bridge
# or loadable drivers.

#.include <bsd.own.mk> # FreeBSD 10 and earlier
# .include "${SYSDIR}/conf/kern.opts.mk"

.PATH: ${.CURDIR}/../sys/dev/netmap
.PATH.h: ${.CURDIR}/../sys/net

CFLAGS += -I${.CURDIR}/../../sys -include win_glue.h
CFLAGS += -DAMD64=1
DDK ?= c:/WinDDK/7600.16385.1

KMOD	= netmap
SRCS	= device_if.h bus_if.h opt_netmap.h
SRCS	+= netmap.c
# netmap.h netmap_kern.h
SRCS	+= netmap_mem2.c netmap_mem2.h
SRCS	+= netmap_generic.c
SRCS	+= netmap_mbq.c netmap_mbq.h
SRCS	+= netmap_vale.c
SRCS	+= netmap_freebsd.c
SRCS	+= netmap_offloadings.c
SRCS	+= netmap_pipe.c
SRCS	+= netmap_monitor.c
SRCS	+= opt_inet.h opt_inet6.h
MSBUILD	="/cygdrive/c/Program Files (x86)/MSBuild/12.0/Bin/MSBuild.exe"

_not_working:
	@echo "--- the makefile is not working yet, use msbuild ---"
	rm -rf VsSolution/Output
	(cd VsSolution; $(MSBUILD) /t:Build /p:Configuration="Win8.1 Release";Platform=x64 )

clean:
	rm -rf VsSolution/Output

all: pre-build do-build

pre-build:
	-rm -rf win-build
	mkdir -p win-build
	cp -p ../sys/dev/netmap/*.[ch] win-build
	cp -p *.[ch] win-build
	cp -p Makefile win-build
	(cd win-build; touch opt_inet.h opt_inet6.h opt_netmap.h device_if.h bus_if.h)

do-build:
	cd win-build; make $(KMOD)

$(KMOD):	$(SRCS)
