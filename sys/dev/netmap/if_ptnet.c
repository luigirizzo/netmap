/*-
 * Copyright (c) 2016, Vincenzo Maffione <v.maffione@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Driver for ptnet paravirtualized network device. */

#include <sys/cdefs.h>
//__FBSDID("$FreeBSD: releng/10.2/sys/dev/netmap/netmap_ptnet.c xxx $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <sys/sglist.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>
#include <sys/smp.h>
#include <machine/smp.h>

#include <vm/uma.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net/if_vlan_var.h>

#include <net/bpf.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/sctp.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/selinfo.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_virt.h>
#include <dev/netmap/netmap_mem2.h>

struct ptnet_softc {
    struct ifnet *ifp;
};

static int	ptnet_probe(device_t);
static int	ptnet_attach(device_t);
static int	ptnet_detach(device_t);
static int	ptnet_suspend(device_t);
static int	ptnet_resume(device_t);
static int	ptnet_shutdown(device_t);

static device_method_t ptnet_methods[] = {
	DEVMETHOD(device_probe,			ptnet_probe),
	DEVMETHOD(device_attach,		ptnet_attach),
	DEVMETHOD(device_detach,		ptnet_detach),
	DEVMETHOD(device_suspend,		ptnet_suspend),
	DEVMETHOD(device_resume,		ptnet_resume),
	DEVMETHOD(device_shutdown,		ptnet_shutdown),
	DEVMETHOD_END
};

static driver_t ptnet_driver = {
	"ptnet",
	ptnet_methods,
	sizeof(struct ptnet_softc)
};
static devclass_t ptnet_devclass;

DRIVER_MODULE(ptnet, pci, ptnet_driver, ptnet_devclass, 0, 0);
MODULE_VERSION(ptnet, 1);
MODULE_DEPEND(ptnet, netmap, 1, 1, 1);

static int
ptnet_probe(device_t dev)
{
	printf("%s\n", __func__);

	if (pci_get_vendor(dev) != PTNETMAP_PCI_VENDOR_ID ||
		pci_get_device(dev) != PTNETMAP_PCI_NETIF_ID) {
		return (ENXIO);
	}

	device_set_desc(dev, "ptnet network adapter");

	return (BUS_PROBE_DEFAULT);
}

static int
ptnet_attach(device_t dev)
{
	struct ptnet_softc *sc;

	printf("%s\n", __func__);

	sc = device_get_softc(dev);
	sc->ifp = NULL;

	return (0);
}

static int
ptnet_detach(device_t dev)
{
	printf("%s\n", __func__);

	return (0);
}

static int
ptnet_suspend(device_t dev)
{
	struct ptnet_softc *sc;

	sc = device_get_softc(dev);
	(void)sc;

	return (0);
}

static int
ptnet_resume(device_t dev)
{
	struct ptnet_softc *sc;

	sc = device_get_softc(dev);
	(void)sc;

	return (0);
}

static int
ptnet_shutdown(device_t dev)
{
	/*
	 * Suspend already does all of what we need to
	 * do here; we just never expect to be resumed.
	 */
	return (ptnet_suspend(dev));
}
