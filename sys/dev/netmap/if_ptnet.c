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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>
#include <sys/smp.h>
#include <machine/smp.h>

#include <vm/uma.h>
#include <vm/vm.h>
#include <vm/pmap.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net/if_vlan_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

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

#ifndef PTNET_CSB_ALLOC
#error "No support for on-device CSB"
#endif

struct ptnet_softc;

struct ptnet_queue {
	struct ptnet_softc	*sc;
	struct			resource *irq;
	void			*cookie;
	int			kring_id;
	struct ptnet_ring	*ptring;
	unsigned int		kick;
};

struct ptnet_softc {
	device_t dev;
	struct ifnet		*ifp;
	struct ifmedia		media;
	struct mtx		core_mtx;
	char			core_mtx_name[16];
	char			hwaddr[ETHER_ADDR_LEN];

	/* Mirror of PTFEAT register. */
	uint32_t		ptfeatures;

	/* PCI BARs support. */
	struct resource		*iomem;
	struct resource		*msix_mem;

	unsigned int		num_rings;
	struct ptnet_queue	*queues;
	struct ptnet_csb	*csb;

	struct netmap_pt_guest_adapter *ptna_nm;
};

#define PTNET_CORE_LOCK_INIT(_sc)	do {			\
		snprintf((_sc)->core_mtx_name, sizeof((_sc)->core_mtx_name),	\
			 "%s", device_get_nameunit(sc->dev));			\
		mtx_init(&(_sc)->core_mtx, (_sc)->core_mtx_name,		\
			 "ptnet core lock", MTX_DEF);				\
	} while (0)

#define PTNET_CORE_LOCK_FINI(_sc)	mtx_destroy(&(_sc)->core_mtx)

#define PTNET_CORE_LOCK(_sc)	mtx_lock(&(_sc)->core_mtx)
#define PTNET_CORE_UNLOCK(_sc)	mtx_unlock(&(_sc)->core_mtx)

static int	ptnet_probe(device_t);
static int	ptnet_attach(device_t);
static int	ptnet_detach(device_t);
static int	ptnet_suspend(device_t);
static int	ptnet_resume(device_t);
static int	ptnet_shutdown(device_t);

static void	ptnet_init(void *opaque);
static int	ptnet_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data);
static void	ptnet_init_locked(struct ptnet_softc *sc);
static void	ptnet_stop(struct ptnet_softc *sc);
static void	ptnet_start(struct ifnet *ifp);

static int	ptnet_media_change(struct ifnet *ifp);
static void	ptnet_media_status(struct ifnet *ifp, struct ifmediareq *ifmr);

static int	ptnet_irqs_init(struct ptnet_softc *sc);
static void	ptnet_irqs_fini(struct ptnet_softc *sc);

static uint32_t ptnet_nm_ptctl(struct ifnet *ifp, uint32_t cmd);
static int	ptnet_nm_config(struct netmap_adapter *na, unsigned *txr,
				unsigned *txd, unsigned *rxr, unsigned *rxd);

static void	ptnet_tx_intr(void *opaque);
static void	ptnet_rx_intr(void *opaque);

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
	device_printf(dev, "%s\n", __func__);

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
	uint32_t ptfeatures = NET_PTN_FEATURES_BASE;
	unsigned int num_rx_rings, num_tx_rings;
	struct netmap_adapter na_arg;
	unsigned int nifp_offset;
	struct ptnet_softc *sc;
	struct ifnet *ifp;
	uint32_t macreg;
	int err, rid;
	int i;

	device_printf(dev, "%s\n", __func__);

	sc = device_get_softc(dev);
	sc->dev = dev;

	/* Setup PCI resources. */
	pci_enable_busmaster(dev);

	rid = PCIR_BAR(PTNETMAP_IO_PCI_BAR);
	sc->iomem = bus_alloc_resource_any(dev, SYS_RES_IOPORT, &rid,
					   RF_ACTIVE);
	if (sc->iomem == NULL) {
		device_printf(dev, "Failed to map I/O BAR\n");
		return (ENXIO);
	}

	/* Check if we are supported by the hypervisor. If not,
	 * bail out immediately. */
	bus_write_4(sc->iomem, PTNET_IO_PTFEAT, ptfeatures); /* wanted */
	ptfeatures = bus_read_4(sc->iomem, PTNET_IO_PTFEAT); /* acked */
	if (!(ptfeatures & NET_PTN_FEATURES_BASE)) {
		device_printf(dev, "Hypervisor does not support netmap "
				   "passthorugh\n");
		err = ENXIO;
		goto err_path;
	}
	sc->ptfeatures = ptfeatures;

	/* Allocate CSB and carry out CSB allocation protocol (CSBBAH first,
	 * then CSBBAL). */
	sc->csb = malloc(sizeof(struct ptnet_csb), M_DEVBUF,
			 M_NOWAIT | M_ZERO);
	if (sc->csb == NULL) {
		device_printf(dev, "Failed to allocate CSB\n");
		err = ENOMEM;
		goto err_path;
	}

	{
		vm_paddr_t paddr = vtophys(sc->csb);

		bus_write_4(sc->iomem, PTNET_IO_CSBBAH,
			    (paddr >> 32) & 0xffffffff);
		bus_write_4(sc->iomem, PTNET_IO_CSBBAL, paddr & 0xffffffff);
	}

	num_tx_rings = bus_read_4(sc->iomem, PTNET_IO_NUM_TX_RINGS);
	num_rx_rings = bus_read_4(sc->iomem, PTNET_IO_NUM_RX_RINGS);
	sc->num_rings = num_tx_rings + num_rx_rings;

	/* Allocate and initialize per-queue data structures. */
	sc->queues = malloc(sizeof(struct ptnet_queue) * sc->num_rings,
			    M_DEVBUF, M_NOWAIT | M_ZERO);
	if (sc->queues == NULL) {
		err = ENOMEM;
		goto err_path;
	}

	for (i = 0; i < sc->num_rings; i++) {
		struct ptnet_queue *pq = sc->queues + i;

		pq->sc = sc;
		pq->kring_id = i;
		pq->kick = PTNET_IO_KICK_BASE + 4 * i;
		pq->ptring = sc->csb->rings + i;
		if (i >= num_tx_rings) {
			pq->kring_id -= num_tx_rings;
		}
	}

	err = ptnet_irqs_init(sc);
	if (err) {
		goto err_path;
	}

	/* Setup Ethernet interface. */
	sc->ifp = ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(dev, "Failed to allocate ifnet\n");
		err = ENOMEM;
		goto err_path;
	}

	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	if_initbaudrate(ifp, IF_Gbps(10));
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX;
	ifp->if_init = ptnet_init;
	ifp->if_ioctl = ptnet_ioctl;
	ifp->if_start = ptnet_start;

	IFQ_SET_MAXLEN(&ifp->if_snd, 255);
	ifp->if_snd.ifq_drv_maxlen = 255;
	IFQ_SET_READY(&ifp->if_snd);

	ifmedia_init(&sc->media, IFM_IMASK, ptnet_media_change,
		     ptnet_media_status);
	ifmedia_add(&sc->media, IFM_ETHER | IFM_10G_T | IFM_FDX, 0, NULL);
	ifmedia_set(&sc->media, IFM_ETHER | IFM_10G_T | IFM_FDX);

	macreg = bus_read_4(sc->iomem, PTNET_IO_MAC_HI);
	sc->hwaddr[0] = (macreg >> 8) & 0xff;
	sc->hwaddr[1] = macreg & 0xff;
	macreg = bus_read_4(sc->iomem, PTNET_IO_MAC_LO);
	sc->hwaddr[2] = (macreg >> 24) & 0xff;
	sc->hwaddr[3] = (macreg >> 16) & 0xff;
	sc->hwaddr[4] = (macreg >> 8) & 0xff;
	sc->hwaddr[5] = macreg & 0xff;

	ether_ifattach(ifp, sc->hwaddr);

	ifp->if_data.ifi_hdrlen = sizeof(struct ether_vlan_header);
	ifp->if_capabilities |= IFCAP_JUMBO_MTU | IFCAP_VLAN_MTU;

	ifp->if_capenable = ifp->if_capabilities;

	PTNET_CORE_LOCK_INIT(sc);

	/* Prepare a netmap_adapter struct instance to do netmap_attach(). */
	nifp_offset = bus_read_4(sc->iomem, PTNET_IO_NIFP_OFS);
	na_arg.ifp = ifp;
	na_arg.num_tx_desc = bus_read_4(sc->iomem, PTNET_IO_NUM_TX_SLOTS);
	na_arg.num_rx_desc = bus_read_4(sc->iomem, PTNET_IO_NUM_RX_SLOTS);
	na_arg.num_tx_rings = num_tx_rings;
	na_arg.num_rx_rings = num_rx_rings;
	na_arg.nm_config = ptnet_nm_config;

	netmap_pt_guest_attach(&na_arg, sc->csb, nifp_offset, ptnet_nm_ptctl);

	/* Now a netmap adapter for this ifp has been allocated, and it
	 * can be accessed through NA(ifp). We also have to initialize the CSB
	 * pointer. */
	sc->ptna_nm = (struct netmap_pt_guest_adapter *)NA(ifp);
	sc->ptna_nm->csb = sc->csb;

	return (0);

err_path:
	ptnet_detach(dev);
	return err;
}

static int
ptnet_detach(device_t dev)
{
	struct ptnet_softc *sc = device_get_softc(dev);

	device_printf(dev, "%s\n", __func__);

	if (sc->ifp) {
		ether_ifdetach(sc->ifp);

		netmap_detach(sc->ifp);

		ifmedia_removeall(&sc->media);
		if_free(sc->ifp);
		sc->ifp = NULL;
	}

	ptnet_irqs_fini(sc);

	if (sc->csb) {
		bus_write_4(sc->iomem, PTNET_IO_CSBBAH, 0);
		bus_write_4(sc->iomem, PTNET_IO_CSBBAL, 0);
		free(sc->csb, M_DEVBUF);
		sc->csb = NULL;
	}

	if (sc->queues) {
		free(sc->queues, M_DEVBUF);
		sc->queues = NULL;
	}

	if (sc->iomem) {
		bus_release_resource(dev, SYS_RES_IOPORT,
				     PCIR_BAR(PTNETMAP_IO_PCI_BAR), sc->iomem);
		sc->iomem = NULL;
	}

	PTNET_CORE_LOCK_FINI(sc);

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

static int
ptnet_irqs_init(struct ptnet_softc *sc)
{
	int rid = PCIR_BAR(PTNETMAP_MSIX_PCI_BAR);
	int nvecs = sc->num_rings;
	unsigned int num_tx_rings;
	device_t dev = sc->dev;
	int err = ENOSPC;
	int i;

	num_tx_rings = bus_read_4(sc->iomem, PTNET_IO_NUM_TX_RINGS);

	sc->msix_mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
					      &rid, RF_ACTIVE);
	if (sc->msix_mem == NULL) {
		device_printf(dev, "Failed to allocate MSIX PCI BAR\n");
		return (ENXIO);
	}

	if (pci_msix_count(dev) < nvecs) {
		device_printf(dev, "Not enough MSI-X vectors\n");
		goto err_path;
	}

	err = pci_alloc_msix(dev, &nvecs);
	if (err) {
		device_printf(dev, "Failed to allocate MSI-X vectors\n");
		goto err_path;
	}

	for (i = 0; i < nvecs; i++) {
		struct ptnet_queue *pq = sc->queues + i;
		void (*handler)(void *) = ptnet_tx_intr;
		int rid = i + i;

		if (i > num_tx_rings) {
			handler = ptnet_rx_intr;
		}
		pq->irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
						 RF_ACTIVE);
		if (pq->irq == NULL) {
			device_printf(dev, "Failed to allocate interrupt"
					   "for queue #%d\n", i);
			goto err_path;
		}

		err = bus_setup_intr(dev, pq->irq, INTR_TYPE_NET | INTR_MPSAFE,
				     NULL /* intr_filter */, handler,
				     pq, &pq->cookie);
		if (err) {
			device_printf(dev, "Failed to register intr handler "
					   "for queue #%d\n", i);
			goto err_path;
		}

		bus_describe_intr(dev, pq->irq, pq->cookie, "q%d", i);
		//bus_bind_intr(); /* bind intr to CPU */
	}

	device_printf(dev, "Allocated %d MSI-X vectors\n", nvecs);

	return 0;
err_path:
	ptnet_irqs_fini(sc);
	return err;
}

static void
ptnet_irqs_fini(struct ptnet_softc *sc)
{
	device_t dev = sc->dev;
	int i;

	for (i = 0; i < sc->num_rings; i++) {
		struct ptnet_queue *pq = sc->queues + i;

		if (pq->cookie) {
			bus_teardown_intr(dev, pq->irq, pq->cookie);
			pq->cookie = NULL;
		}

		if (pq->irq) {
			bus_release_resource(dev, SYS_RES_IRQ, i + i, pq->irq);
			pq->irq = NULL;
		}
	}

	if (sc->msix_mem) {
		pci_release_msi(dev);

		bus_release_resource(dev, SYS_RES_MEMORY,
				     PCIR_BAR(PTNETMAP_MSIX_PCI_BAR),
				     sc->msix_mem);
		sc->msix_mem = NULL;
	}
}

static void
ptnet_init(void *opaque)
{
	struct ptnet_softc *sc = opaque;

	PTNET_CORE_LOCK(sc);
	ptnet_init_locked(sc);
	PTNET_CORE_UNLOCK(sc);
}

static int
ptnet_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ptnet_softc *sc = ifp->if_softc;
	device_t dev = sc->dev;
	int err = 0;

	switch (cmd) {
		case SIOCSIFFLAGS:
			device_printf(dev, "SIOCSIFFLAGS %x\n", ifp->if_flags);
			PTNET_CORE_LOCK(sc);
			if (ifp->if_flags & IFF_UP) {
				/* Network stack wants the iff to be up. */
				ptnet_init_locked(sc);
			} else {
				/* Network stack wants the iff to be down. */
				ptnet_stop(sc);
			}
			PTNET_CORE_UNLOCK(sc);

		default:
			err = ether_ioctl(ifp, cmd, data);
	}

	return err;
}

static void
ptnet_init_locked(struct ptnet_softc *sc)
{
	struct ifnet *ifp = sc->ifp;

	device_printf(sc->dev, "%s\n", __func__);

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		return; /* nothing to do */
	}
}

/* To be called under core lock. */
static void
ptnet_stop(struct ptnet_softc *sc)
{
	struct ifnet *ifp = sc->ifp;

	device_printf(sc->dev, "%s\n", __func__);

	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		return; /* nothing to do */
	}
}

static void
ptnet_start(struct ifnet *ifp)
{
}

static int
ptnet_media_change(struct ifnet *ifp)
{
	struct ptnet_softc *sc = ifp->if_softc;
	struct ifmedia *ifm = &sc->media;

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER) {
		return (EINVAL);
	}

	return (0);
}


static void
ptnet_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (1) {
		ifmr->ifm_status |= IFM_ACTIVE;
		ifmr->ifm_active |= IFM_10G_T | IFM_FDX;
	} else {
		ifmr->ifm_active |= IFM_NONE;
	}
}

static uint32_t
ptnet_nm_ptctl(struct ifnet *ifp, uint32_t cmd)
{
	struct ptnet_softc *sc = ifp->if_softc;
	int ret;

	bus_write_4(sc->iomem, PTNET_IO_PTCTL, cmd);
	ret = bus_read_4(sc->iomem, PTNET_IO_PTSTS);
	device_printf(sc->dev, "PTCTL %u, ret %u\n", cmd, ret);

	return ret;
}

static int
ptnet_nm_config(struct netmap_adapter *na, unsigned *txr, unsigned *txd,
		unsigned *rxr, unsigned *rxd)
{
	struct ptnet_softc *sc = na->ifp->if_softc;

	*txr = bus_read_4(sc->iomem, PTNET_IO_NUM_TX_RINGS);
	*rxr = bus_read_4(sc->iomem, PTNET_IO_NUM_RX_RINGS);
	*txd = bus_read_4(sc->iomem, PTNET_IO_NUM_TX_SLOTS);
	*rxd = bus_read_4(sc->iomem, PTNET_IO_NUM_RX_SLOTS);

	device_printf(sc->dev, "txr %u, rxr %u, txd %u, rxd %u\n",
		      *txr, *rxr, *txd, *rxd);

	return 0;
}

static void
ptnet_tx_intr(void *opaque)
{
	struct ptnet_queue *pq = opaque;
	struct ptnet_softc *sc = pq->sc;

	device_printf(sc->dev, "Tx interrupt #%d", pq->kring_id);
}

static void
ptnet_rx_intr(void *opaque)
{
	struct ptnet_queue *pq = opaque;
	struct ptnet_softc *sc = pq->sc;

	device_printf(sc->dev, "Rx interrupt #%d", pq->kring_id);
}
