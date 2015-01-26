/*
 * glue to compile netmap under FreeBSD
 *
 * Headers are in
 * /System/Library/Frameworks/Kernel.framework/Headers/
 */
#ifndef OSX_GLUE_H
#define OSX_GLUE_H
#define __FBSDID(x)
#include <sys/types.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#define TUNABLE_INT(name, ptr)

#include <kern/locks.h>		// lock
#include <IOKit/IOLocks.h>	// IOlock
#include <sys/select.h>		// struct selinfo
struct selinfo {		// private in the kernel
	char dummy[128];
};
#include <sys/socket.h>
#include <sys/mbuf.h>

/* XXX some types i don't find in OSX */
typedef	void *		vm_paddr_t;
struct mbuf;	// XXX
struct ifnet;


// #include <sys/kpi_mbuf.h>
#include <net/kpi_interface.h>
#include <net/if.h>
#include <net/bpf.h>            /* BIOCIMMEDIATE */
//#include <net/vnet.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
// #include <machine/bus.h>        /* bus_dmamap_* */


#endif /* OSX_GLUE_H */
