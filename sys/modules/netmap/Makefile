# $FreeBSD$
#
# Compile netmap as a module, useful if you want a netmap bridge
# or loadable drivers.

.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/netmap
.PATH.h: ${.CURDIR}/../../net
CFLAGS += -I${.CURDIR}/../../
KMOD	= netmap
SRCS	= device_if.h bus_if.h opt_netmap.h
SRCS	+= netmap.c netmap.h netmap_kern.h
SRCS	+= netmap_mem2.c netmap_mem2.h
SRCS	+= netmap_generic.c
SRCS	+= netmap_mbq.c netmap_mbq.h
SRCS	+= netmap_vale.c
SRCS	+= netmap_freebsd.c
SRCS	+= netmap_offloadings.c
SRCS	+= netmap_pipe.c
SRCS	+= netmap_monitor.c
SRCS	+= opt_inet.h opt_inet6.h

.if !defined(KERNBUILDDIR)
.if ${MK_INET_SUPPORT} != "no"
opt_inet.h:
	@echo "#define INET 1" > ${.TARGET}
.endif

.if ${MK_INET6_SUPPORT} != "no"
opt_inet6.h:
	@echo "#define INET6 1" > ${.TARGET}
.endif
.endif

.include <bsd.kmod.mk>
