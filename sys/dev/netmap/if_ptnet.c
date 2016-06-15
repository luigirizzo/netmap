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

//#define DEBUG
#ifdef DEBUG
#define DBG(x) x
#else   /* !DEBUG */
#define DBG(x)
#endif  /* !DEBUG */

struct ptnet_softc;

struct ptnet_queue {
	struct ptnet_softc	*sc;
	struct			resource *irq;
	void			*cookie;
	int			kring_id;
	struct ptnet_ring	*ptring;
	unsigned int		kick;
	struct mtx		lock;
	char			lock_name[16];
};

#define PTNET_Q_LOCK(_pq)	mtx_lock(&(_pq)->lock)
#define PTNET_Q_UNLOCK(_pq)	mtx_unlock(&(_pq)->lock)

struct ptnet_softc {
	device_t		dev;
	struct ifnet		*ifp;
	struct ifmedia		media;
	struct mtx		lock;
	char			lock_name[16];
	char			hwaddr[ETHER_ADDR_LEN];

	/* Mirror of PTFEAT register. */
	uint32_t		ptfeatures;

	/* Reference counter used to track the regif operations on the
	 * passed-through netmap port. */
	int backend_regifs;

	/* PCI BARs support. */
	struct resource		*iomem;
	struct resource		*msix_mem;

	unsigned int		num_rings;
	struct ptnet_queue	*queues;
	struct ptnet_queue	*rxqueues;
	struct ptnet_csb	*csb;

	struct netmap_pt_guest_adapter *ptna_nm;
	struct netmap_pt_guest_adapter ptna_dr;
	/* XXX we should move ptna_dr and backend_regifs inside struct
	 * netmap_pt_guest_adapter and have just one instance of that. */
};

#define PTNET_CORE_LOCK(_sc)	mtx_lock(&(_sc)->lock)
#define PTNET_CORE_UNLOCK(_sc)	mtx_unlock(&(_sc)->lock)

static int	ptnet_probe(device_t);
static int	ptnet_attach(device_t);
static int	ptnet_detach(device_t);
static int	ptnet_suspend(device_t);
static int	ptnet_resume(device_t);
static int	ptnet_shutdown(device_t);

static void	ptnet_init(void *opaque);
static int	ptnet_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data);
static int	ptnet_init_locked(struct ptnet_softc *sc);
static int	ptnet_stop(struct ptnet_softc *sc);
static int	ptnet_transmit(struct ifnet *ifp, struct mbuf *m);
static void	ptnet_qflush(struct ifnet *ifp);

static int	ptnet_media_change(struct ifnet *ifp);
static void	ptnet_media_status(struct ifnet *ifp, struct ifmediareq *ifmr);

static int	ptnet_irqs_init(struct ptnet_softc *sc);
static void	ptnet_irqs_fini(struct ptnet_softc *sc);

static uint32_t ptnet_nm_ptctl(struct ifnet *ifp, uint32_t cmd);
static int	ptnet_nm_config(struct netmap_adapter *na, unsigned *txr,
				unsigned *txd, unsigned *rxr, unsigned *rxd);
static int	ptnet_nm_krings_create(struct netmap_adapter *na);
static void	ptnet_nm_krings_delete(struct netmap_adapter *na);
static void	ptnet_nm_dtor(struct netmap_adapter *na);
static int	ptnet_nm_register(struct netmap_adapter *na, int onoff);
static int	ptnet_nm_txsync(struct netmap_kring *kring, int flags);
static int	ptnet_nm_rxsync(struct netmap_kring *kring, int flags);

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
DRIVER_MODULE_ORDERED(ptnet, pci, ptnet_driver, ptnet_devclass,
		      NULL, NULL, SI_ORDER_MIDDLE + 1);

static int
ptnet_probe(device_t dev)
{
	if (pci_get_vendor(dev) != PTNETMAP_PCI_VENDOR_ID ||
		pci_get_device(dev) != PTNETMAP_PCI_NETIF_ID) {
		return (ENXIO);
	}

	device_set_desc(dev, "ptnet network adapter");

	return (BUS_PROBE_DEFAULT);
}

extern int netmap_initialized;

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

	if (!netmap_initialized) {
		device_printf(dev, "Netmap still not initialized\n");
		return (ENXIO);
	}

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
	sc->rxqueues = sc->queues + num_tx_rings;

	for (i = 0; i < sc->num_rings; i++) {
		struct ptnet_queue *pq = sc->queues + i;

		pq->sc = sc;
		pq->kring_id = i;
		pq->kick = PTNET_IO_KICK_BASE + 4 * i;
		pq->ptring = sc->csb->rings + i;
		if (i >= num_tx_rings) {
			pq->kring_id -= num_tx_rings;
		}
		snprintf(pq->lock_name, sizeof(pq->lock_name), "%s-%d",
			 device_get_nameunit(dev), i);
		mtx_init(&pq->lock, pq->lock_name, NULL, MTX_DEF);
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
	ifp->if_transmit = ptnet_transmit;
	ifp->if_qflush = ptnet_qflush;

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

	snprintf(sc->lock_name, sizeof(sc->lock_name),
		 "%s", device_get_nameunit(dev));
	mtx_init(&sc->lock, sc->lock_name, "ptnet core lock", MTX_DEF);

	sc->backend_regifs = 0;

	/* Prepare a netmap_adapter struct instance to do netmap_attach(). */
	nifp_offset = bus_read_4(sc->iomem, PTNET_IO_NIFP_OFS);
	memset(&na_arg, 0, sizeof(na_arg));
	na_arg.ifp = ifp;
	na_arg.num_tx_desc = bus_read_4(sc->iomem, PTNET_IO_NUM_TX_SLOTS);
	na_arg.num_rx_desc = bus_read_4(sc->iomem, PTNET_IO_NUM_RX_SLOTS);
	na_arg.num_tx_rings = num_tx_rings;
	na_arg.num_rx_rings = num_rx_rings;
	na_arg.nm_config = ptnet_nm_config;
	na_arg.nm_krings_create = ptnet_nm_krings_create;
	na_arg.nm_krings_delete = ptnet_nm_krings_delete;
	na_arg.nm_dtor = ptnet_nm_dtor;
	na_arg.nm_register = ptnet_nm_register;
	na_arg.nm_txsync = ptnet_nm_txsync;
	na_arg.nm_rxsync = ptnet_nm_rxsync;

	netmap_pt_guest_attach(&na_arg, sc->csb, nifp_offset, ptnet_nm_ptctl);

	/* Now a netmap adapter for this ifp has been allocated, and it
	 * can be accessed through NA(ifp). We also have to initialize the CSB
	 * pointer. */
	sc->ptna_nm = (struct netmap_pt_guest_adapter *)NA(ifp);
	sc->ptna_nm->csb = sc->csb;

	/* Initialize a separate pass-through netmap adapter that is going to
	 * be used by this driver only, and so never exposed to netmap. We
	 * only need a subset of the available fields. */
	memset(&sc->ptna_dr, 0, sizeof(sc->ptna_dr));
	sc->ptna_dr.hwup.up.ifp = ifp;
	sc->ptna_dr.hwup.up.nm_mem = sc->ptna_nm->hwup.up.nm_mem;
	netmap_mem_get(sc->ptna_dr.hwup.up.nm_mem);
	sc->ptna_dr.hwup.up.nm_config = ptnet_nm_config;
	sc->ptna_dr.csb = sc->csb;

	device_printf(dev, "%s() completed\n", __func__);

	return (0);

err_path:
	ptnet_detach(dev);
	return err;
}

static int
ptnet_detach(device_t dev)
{
	struct ptnet_softc *sc = device_get_softc(dev);

	if (sc->ifp) {
		ether_ifdetach(sc->ifp);

		/* Uninitialize netmap adapters for this device. */
		netmap_mem_put(sc->ptna_dr.hwup.up.nm_mem);
		memset(&sc->ptna_dr, 0, sizeof(sc->ptna_dr));
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

	mtx_destroy(&sc->lock);

	device_printf(dev, "%s() completed\n", __func__);

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

	if (pci_find_cap(dev, PCIY_MSIX, NULL) != 0)  {
		device_printf(dev, "Could not find MSI-X capability\n");
		return (ENXIO);
	}

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

		rid = i + 1;
		pq->irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
						 RF_ACTIVE);
		if (pq->irq == NULL) {
			device_printf(dev, "Failed to allocate interrupt "
					   "for queue #%d\n", i);
			err = ENOSPC;
			goto err_path;
		}
	}

	for (i = 0; i < nvecs; i++) {
		struct ptnet_queue *pq = sc->queues + i;
		void (*handler)(void *) = ptnet_tx_intr;

		if (i >= num_tx_rings) {
			handler = ptnet_rx_intr;
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

	/* Tell the hypervisor that we have allocated the MSI-X vectors,
	 * so that it can do its own setup. */
	bus_write_4(sc->iomem, PTNET_IO_CTRL, PTNET_CTRL_IRQINIT);

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

	/* Tell the hypervisor that we are going to deallocate the
	 * MSI-X vectors, so that it can do its own cleanup. */
	bus_write_4(sc->iomem, PTNET_IO_CTRL, PTNET_CTRL_IRQFINI);

	for (i = 0; i < sc->num_rings; i++) {
		struct ptnet_queue *pq = sc->queues + i;

		if (pq->cookie) {
			bus_teardown_intr(dev, pq->irq, pq->cookie);
			pq->cookie = NULL;
		}

		if (pq->irq) {
			bus_release_resource(dev, SYS_RES_IRQ, i + 1, pq->irq);
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
				err = ptnet_init_locked(sc);
			} else {
				/* Network stack wants the iff to be down. */
				err = ptnet_stop(sc);
			}
			PTNET_CORE_UNLOCK(sc);

		default:
			err = ether_ioctl(ifp, cmd, data);
	}

	return err;
}

static int
ptnet_init_locked(struct ptnet_softc *sc)
{
	struct ifnet *ifp = sc->ifp;
	struct netmap_adapter *na_dr = &sc->ptna_dr.hwup.up;
	int ret;

	device_printf(sc->dev, "%s\n", __func__);

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		return 0; /* nothing to do */
	}

	netmap_update_config(na_dr);

	ret = netmap_mem_finalize(na_dr->nm_mem, na_dr);
	if (ret) {
		device_printf(sc->dev, "netmap_mem_finalize() failed\n");
		return ret;
	}

	if (sc->backend_regifs == 0) {
		ret = ptnet_nm_krings_create(na_dr);
		if (ret) {
			device_printf(sc->dev, "ptnet_nm_krings_create() "
					       "failed\n");
			goto err_mem_finalize;
		}

		ret = netmap_mem_rings_create(na_dr);
		if (ret) {
			device_printf(sc->dev, "netmap_mem_rings_create() "
					       "failed\n");
			goto err_rings_create;
		}

		ret = netmap_mem_get_lut(na_dr->nm_mem, &na_dr->na_lut);
		if (ret) {
			device_printf(sc->dev, "netmap_mem_get_lut() "
					       "failed\n");
			goto err_get_lut;
		}
	}

	ret = ptnet_nm_register(na_dr, 1 /* on */);
	if (ret) {
		goto err_register;
	}

	ifp->if_drv_flags |= IFF_DRV_RUNNING;

	return 0;

err_register:
	memset(&na_dr->na_lut, 0, sizeof(na_dr->na_lut));
err_get_lut:
	netmap_mem_rings_delete(na_dr);
err_rings_create:
	ptnet_nm_krings_delete(na_dr);
err_mem_finalize:
	netmap_mem_deref(na_dr->nm_mem, na_dr);

	return ret;
}

/* To be called under core lock. */
static int
ptnet_stop(struct ptnet_softc *sc)
{
	struct ifnet *ifp = sc->ifp;
	struct netmap_adapter *na_dr = &sc->ptna_dr.hwup.up;

	device_printf(sc->dev, "%s\n", __func__);

	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		return 0; /* nothing to do */
	}

	ptnet_nm_register(na_dr, 0 /* off */);

	if (sc->backend_regifs == 0) {
		netmap_mem_rings_delete(na_dr);
		ptnet_nm_krings_delete(na_dr);
	}
	netmap_mem_deref(na_dr->nm_mem, na_dr);

	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;

	return 0;
}

static inline void
ptnet_sync_tail(struct ptnet_ring *ptring, struct netmap_kring *kring)
{
	struct netmap_ring *ring = kring->ring;

	/* Update hwcur and hwtail as known by the host. */
        ptnetmap_guest_read_kring_csb(ptring, kring);

	/* nm_sync_finalize */
	ring->tail = kring->rtail = kring->nr_hwtail;
}

static int
ptnet_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct ptnet_softc *sc = ifp->if_softc;
	struct netmap_adapter *na = &sc->ptna_dr.hwup.up;
	struct ptnet_ring *ptring;
	struct netmap_kring *kring;
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	struct ptnet_queue *pq;
	unsigned int head;
	unsigned int lim;
	struct mbuf *mf;
	int nmbuf_bytes;
	uint8_t *nmbuf;

	device_printf(sc->dev, "transmit %p\n", m);

	pq = sc->queues + 0;
	ptring = pq->ptring;
	kring = na->tx_rings + pq->kring_id;
	ring = kring->ring;
	lim = kring->nkr_num_slots - 1;

	PTNET_Q_LOCK(pq);

	/* Update hwcur and hwtail (completed TX slots) as known by the host,
	 * by reading from CSB. */
	ptnet_sync_tail(ptring, kring);

	PTNET_Q_UNLOCK(pq);

	head = ring->head;
	slot = ring->slot + head;
	nmbuf = NMB(na, slot);
	nmbuf_bytes = 0;

	for (mf = m; mf; mf = mf->m_next) {
		uint8_t *mdata = mf->m_data;
		int mlen = mf->m_len;

		for (;;) {
			int copy = NETMAP_BUF_SIZE(na) - nmbuf_bytes;

			if (mlen < copy) {
				copy = mlen;
			}
			memcpy(nmbuf, mdata, copy);

			mdata += copy;
			mlen -= copy;
			nmbuf += copy;
			nmbuf_bytes += copy;

			if (!mlen) {
				break;
			}

			slot->len = nmbuf_bytes;
			slot->flags = NS_MOREFRAG;
			head = nm_next(head, lim);
			slot = ring->slot + head;
			nmbuf = NMB(na, slot);
			nmbuf_bytes = 0;
		}
	}

	m_freem(m);

	/* Complete last slot and update head. */
	slot->len = nmbuf_bytes;
	slot->flags = 0;
	ring->head = ring->cur = nm_next(head, lim);

	/* nm_txsync_prologue */
	kring->rcur = kring->rhead = ring->head;

	/* Tell the host to process the new packets, updating cur and
	 * head in the CSB. */
	ptnetmap_guest_write_kring_csb(ptring, kring->rcur,
			kring->rhead);

        /* Ask for a kick from a guest to the host if needed. */
	if (NM_ACCESS_ONCE(ptring->host_need_kick)) {
		ptring->sync_flags = NAF_FORCE_RECLAIM;
		bus_write_4(sc->iomem, pq->kick, 0);
	}

	return 0;
}

static void
ptnet_qflush(struct ifnet *ifp)
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

/* XXX krings create/delete and register functions should be shared
 *     with the Linux driver. */
static int
ptnet_nm_krings_create(struct netmap_adapter *na)
{
	/* Here (na == &sc->ptna_nm->hwup.up || na == &sc->ptna_dr.hwup.up). */
	struct ptnet_softc *sc = na->ifp->if_softc;
	struct netmap_adapter *na_nm = &sc->ptna_nm->hwup.up;
	struct netmap_adapter *na_dr = &sc->ptna_dr.hwup.up;
	int ret;

	if (sc->backend_regifs) {
		return 0;
	}

	/* Create krings on the public netmap adapter. */
	ret = netmap_hw_krings_create(na_nm);
	if (ret) {
		return ret;
	}

	/* Copy krings into the netmap adapter private to the driver. */
	na_dr->tx_rings = na_nm->tx_rings;
	na_dr->rx_rings = na_nm->rx_rings;

	return 0;
}

static void
ptnet_nm_krings_delete(struct netmap_adapter *na)
{
	/* Here (na == &sc->ptna_nm->hwup.up || na == &sc->ptna_dr.hwup.up). */
	struct ptnet_softc *sc = na->ifp->if_softc;
	struct netmap_adapter *na_nm = &sc->ptna_nm->hwup.up;
	struct netmap_adapter *na_dr = &sc->ptna_dr.hwup.up;

	if (sc->backend_regifs) {
		return;
	}

	na_dr->tx_rings = NULL;
	na_dr->rx_rings = NULL;

	netmap_hw_krings_delete(na_nm);
}

static void
ptnet_nm_dtor(struct netmap_adapter *na)
{
	netmap_mem_pt_guest_ifp_del(na->nm_mem, na->ifp);
}

static void
ptnet_sync_from_csb(struct ptnet_softc *sc, struct netmap_adapter *na)
{
	int i;

	/* Sync krings from the host, reading from
	 * CSB. */
	for (i = 0; i < sc->num_rings; i++) {
		struct ptnet_ring *ptring = sc->queues[i].ptring;
		struct netmap_kring *kring;

		if (i < na->num_tx_rings) {
			kring = na->tx_rings + i;
		} else {
			kring = na->rx_rings + i - na->num_tx_rings;
		}
		kring->rhead = kring->ring->head = ptring->head;
		kring->rcur = kring->ring->cur = ptring->cur;
		kring->nr_hwcur = ptring->hwcur;
		kring->nr_hwtail = kring->rtail =
			kring->ring->tail = ptring->hwtail;

		ND("%d,%d: csb {hc %u h %u c %u ht %u}", t, i,
		   ptring->hwcur, ptring->head, ptring->cur,
		   ptring->hwtail);
		ND("%d,%d: kring {hc %u rh %u rc %u h %u c %u ht %u rt %u t %u}",
		   t, i, kring->nr_hwcur, kring->rhead, kring->rcur,
		   kring->ring->head, kring->ring->cur, kring->nr_hwtail,
		   kring->rtail, kring->ring->tail);
	}
}

#define csb_notification_enable_all(_x, _na, _t, _fld, _v)		\
	do {								\
		struct ptnet_queue *queues = (_x)->queues;		\
		int i;							\
		if (_t == NR_RX) queues = (_x)->rxqueues;		\
		for (i=0; i<nma_get_nrings(_na, _t); i++) {		\
			queues[i].ptring->_fld = _v;			\
		}							\
	} while (0)							\

static int
ptnet_nm_register(struct netmap_adapter *na, int onoff)
{
	/* device-specific */
	struct ifnet *ifp = na->ifp;
	struct ptnet_softc *sc = ifp->if_softc;
	int native = (na == &sc->ptna_nm->hwup.up);
	enum txrx t;
	int ret = 0;
	int i;

	if (!onoff) {
		sc->backend_regifs--;
	}

	/* If this is the last netmap client, guest interrupt enable flags may
	 * be in arbitrary state. Since these flags are going to be used also
	 * by the netdevice driver, we have to make sure to start with
	 * notifications enabled. Also, schedule NAPI to flush pending packets
	 * in the RX rings, since we will not receive further interrupts
	 * until these will be processed. */
	if (native && !onoff && na->active_fds == 0) {
		D("Exit netmap mode, re-enable interrupts");
		csb_notification_enable_all(sc, na, NR_TX, guest_need_kick, 1);
		csb_notification_enable_all(sc, na, NR_RX, guest_need_kick, 1);
	}

	if (onoff) {
		if (sc->backend_regifs == 0) {
			/* Initialize notification enable fields in the CSB. */
			csb_notification_enable_all(sc, na, NR_TX, host_need_kick, 1);
			csb_notification_enable_all(sc, na, NR_TX, guest_need_kick, 0);
			csb_notification_enable_all(sc, na, NR_RX, host_need_kick, 1);
			csb_notification_enable_all(sc, na, NR_RX, guest_need_kick, 1);

			/* Make sure the host adapter passed through is ready
			 * for txsync/rxsync. */
			ret = ptnet_nm_ptctl(ifp, NET_PARAVIRT_PTCTL_REGIF);
			if (ret) {
				return ret;
			}
		}

		/* Sync from CSB must be done after REGIF PTCTL. Skip this
		 * step only if this is a netmap client and it is not the
		 * first one. */
		if ((!native && sc->backend_regifs == 0) ||
				(native && na->active_fds == 0)) {
			ptnet_sync_from_csb(sc, na);
		}

		/* If not native, don't call nm_set_native_flags, since we don't want
		 * to replace ndo_start_xmit method, nor set NAF_NETMAP_ON */
		if (native) {
			for_rx_tx(t) {
				for (i=0; i<nma_get_nrings(na, t); i++) {
					struct netmap_kring *kring = &NMR(na, t)[i];

					if (nm_kring_pending_on(kring)) {
						kring->nr_mode = NKR_NETMAP_ON;
					}
				}
			}
			nm_set_native_flags(na);
		}

	} else {
		if (native) {
			nm_clear_native_flags(na);
			for_rx_tx(t) {
				for (i=0; i<nma_get_nrings(na, t); i++) {
					struct netmap_kring *kring = &NMR(na, t)[i];

					if (nm_kring_pending_off(kring)) {
						kring->nr_mode = NKR_NETMAP_OFF;
					}
				}
			}
		}

		/* Sync from CSB must be done before UNREGIF PTCTL, on the last
		 * netmap client. */
		if (native && na->active_fds == 0) {
			ptnet_sync_from_csb(sc, na);
		}

		if (sc->backend_regifs == 0) {
			ret = ptnet_nm_ptctl(ifp, NET_PARAVIRT_PTCTL_UNREGIF);
		}
	}

	if (onoff) {
		sc->backend_regifs++;
	}

	return ret;
}

static int
ptnet_nm_txsync(struct netmap_kring *kring, int flags)
{
	struct ptnet_softc *sc = kring->na->ifp->if_softc;
	struct ptnet_queue *pq = sc->queues + kring->ring_id;
	bool notify;

	notify = netmap_pt_guest_txsync(pq->ptring, kring, flags);
	if (notify) {
		bus_write_4(sc->iomem, pq->kick, 0);
	}

	return 0;
}

static int
ptnet_nm_rxsync(struct netmap_kring *kring, int flags)
{
	struct ptnet_softc *sc = kring->na->ifp->if_softc;
	struct ptnet_queue *pq = sc->rxqueues + kring->ring_id;
	bool notify;

	notify = netmap_pt_guest_rxsync(pq->ptring, kring, flags);
	if (notify) {
		bus_write_4(sc->iomem, pq->kick, 0);
	}

	return 0;
}

static void
ptnet_tx_intr(void *opaque)
{
	struct ptnet_queue *pq = opaque;
	struct ptnet_softc *sc = pq->sc;
	struct netmap_adapter *na_dr = &sc->ptna_dr.hwup.up;

	DBG(device_printf(sc->dev, "Tx interrupt #%d\n", pq->kring_id));

	if (!(sc->ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		return;
	}

	if (netmap_tx_irq(sc->ifp, pq->kring_id) != NM_IRQ_PASS) {
		return;
	}

	PTNET_Q_LOCK(pq);
	ptnet_sync_tail(pq->ptring, na_dr->tx_rings + pq->kring_id);
	PTNET_Q_UNLOCK(pq);
}

static void
ptnet_rx_intr(void *opaque)
{
	struct ptnet_queue *pq = opaque;
	struct ptnet_softc *sc = pq->sc;
	unsigned int unused;

	DBG(device_printf(sc->dev, "Rx interrupt #%d\n", pq->kring_id));

	if (!(sc->ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		return;
	}

	if (netmap_rx_irq(sc->ifp, pq->kring_id, &unused) != NM_IRQ_PASS) {
		return;
	}
}
