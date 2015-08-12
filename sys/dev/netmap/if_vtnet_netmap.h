/*
 * Copyright (C) 2014 Vincenzo Maffione, Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $FreeBSD: head/sys/dev/netmap/if_vtnet_netmap.h 270097 2014-08-17 10:25:27Z luigi $
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>
#ifdef WITH_PTNETMAP_GUEST
#include <dev/netmap/netmap_virt.h>
static int vtnet_ptnetmap_txsync(struct netmap_kring *kring, int flags);
#define VTNET_PTNETMAP_ON(_na) \
	((nm_netmap_on(_na)) && ((_na)->nm_txsync == vtnet_ptnetmap_txsync))
#else   /* !WITH_PTNETMAP_GUEST */
#define VTNET_PTNETMAP_ON(_na)        0
#endif  /* WITH_PTNETMAP_GUEST */


#define SOFTC_T	vtnet_softc

/* Free all the unused buffer in all the RX virtqueues.
 * This function is called when entering and exiting netmap mode.
 * - buffers queued by the virtio driver return skbuf/mbuf pointer
 *   and need to be freed;
 * - buffers queued by netmap return the txq/rxq, and do not need work
 */
static void
vtnet_netmap_free_bufs(struct SOFTC_T* sc)
{
	int i, nmb = 0, n = 0, last;

	for (i = 0; i < sc->vtnet_max_vq_pairs; i++) {
		struct vtnet_rxq *rxq = &sc->vtnet_rxqs[i];
		struct virtqueue *vq;
		struct mbuf *m;
		struct vtnet_txq *txq = &sc->vtnet_txqs[i];
                struct vtnet_tx_header *txhdr;

		last = 0;
		vq = rxq->vtnrx_vq;
		while ((m = virtqueue_drain(vq, &last)) != NULL) {
			n++;
			if (m != (void *)rxq)
				m_freem(m);
			else
				nmb++;
		}

		last = 0;
		vq = txq->vtntx_vq;
		while ((txhdr = virtqueue_drain(vq, &last)) != NULL) {
			n++;
			if (txhdr != (void *)txq) {
				m_freem(txhdr->vth_mbuf);
				uma_zfree(vtnet_tx_header_zone, txhdr);
			} else
				nmb++;
		}
	}
	D("freed %d mbufs, %d netmap bufs on %d queues",
		n - nmb, nmb, i);
}

/* Register and unregister. */
static int
vtnet_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = ifp->if_softc;

	VTNET_CORE_LOCK(sc);
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	/* drain queues so netmap and native drivers
	 * do not interfere with each other
	 */
	vtnet_netmap_free_bufs(sc);
        vtnet_init_locked(sc);       /* also enable intr */
        VTNET_CORE_UNLOCK(sc);
        return (ifp->if_drv_flags & IFF_DRV_RUNNING ? 0 : 1);
}


/* Reconcile kernel and user view of the transmit ring. */
static int
vtnet_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct SOFTC_T *sc = ifp->if_softc;
	struct vtnet_txq *txq = &sc->vtnet_txqs[ring_nr];
	struct virtqueue *vq = txq->vtntx_vq;

	/*
	 * First part: process new packets to send.
	 */
	rmb();
	
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		struct sglist *sg = txq->vtntx_sg;

		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			/* we use an empty header here */
			static struct virtio_net_hdr_mrg_rxbuf hdr;
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);
                        int err;

			NM_CHECK_ADDR_LEN(na, addr, len);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			/* Initialize the scatterlist, expose it to the hypervisor,
			 * and kick the hypervisor (if necessary).
			 */
			sglist_reset(sg); // cheap
			// if vtnet_hdr_size > 0 ...
			err = sglist_append(sg, &hdr, sc->vtnet_hdr_size);
			// XXX later, support multi segment
			err = sglist_append_phys(sg, paddr, len);
			/* use na as the cookie */
                        err = virtqueue_enqueue(vq, txq, sg, sg->sg_nseg, 0);
                        if (unlikely(err < 0)) {
                                D("virtqueue_enqueue failed");
                                break;
                        }

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = nm_i; /* note we migth break early */

		/* No more free TX slots? Ask the hypervisor for notifications,
		 * possibly only when a considerable amount of work has been
		 * done.
		 */
		ND(3,"sent %d packets, hwcur %d", n, nm_i);
		virtqueue_disable_intr(vq);
		virtqueue_notify(vq);
	} else {
		if (ring->head != ring->tail)
		    ND(5, "pure notify ? head %d tail %d nused %d %d",
			ring->head, ring->tail, virtqueue_nused(vq),
			(virtqueue_dump(vq), 1));
		virtqueue_notify(vq);
		virtqueue_enable_intr(vq); // like postpone with 0
	}

	
        /* Free used slots. We only consider our own used buffers, recognized
	 * by the token we passed to virtqueue_add_outbuf.
	 */
        n = 0;
        for (;;) {
                struct vtnet_tx_header *txhdr = virtqueue_dequeue(vq, NULL);
                if (txhdr == NULL)
                        break;
                if (likely(txhdr == (void *)txq)) {
                        n++;
			if (virtqueue_nused(vq) < 32) { // XXX slow release
				break;
			}
		} else { /* leftover from previous transmission */
			m_freem(txhdr->vth_mbuf);
			uma_zfree(vtnet_tx_header_zone, txhdr);
		}
        }
	if (n) {
		kring->nr_hwtail += n;
		if (kring->nr_hwtail > lim)
			kring->nr_hwtail -= lim + 1;
	}
	if (nm_i != kring->nr_hwtail /* && vtnet_txq_below_threshold(txq) == 0*/) {
		ND(3, "disable intr, hwcur %d", nm_i);
		virtqueue_disable_intr(vq);
	} else {
		ND(3, "enable intr, hwcur %d", nm_i);
		virtqueue_postpone_intr(vq, VQ_POSTPONE_SHORT);
	}

        return 0;
}

static int
vtnet_refill_rxq(struct netmap_kring *kring, u_int nm_i, u_int head)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int n;

	/* device-specific */
	struct SOFTC_T *sc = ifp->if_softc;
	struct vtnet_rxq *rxq = &sc->vtnet_rxqs[ring_nr];
	struct virtqueue *vq = rxq->vtnrx_vq;

	/* use a local sglist, default might be short */
	struct sglist_seg ss[2];
	struct sglist sg = { ss, 0, 0, 2 };

	for (n = 0; nm_i != head; n++) {
		static struct virtio_net_hdr_mrg_rxbuf hdr;
		struct netmap_slot *slot = &ring->slot[nm_i];
		uint64_t paddr;
		void *addr = PNMB(na, slot, &paddr);
		int err = 0;

		if (addr == NETMAP_BUF_BASE(na)) { /* bad buf */
			if (netmap_ring_reinit(kring))
				return -1;
		}

		slot->flags &= ~NS_BUF_CHANGED;
		sglist_reset(&sg); // cheap
		err = sglist_append(&sg, &hdr, sc->vtnet_hdr_size);
		err = sglist_append_phys(&sg, paddr, NETMAP_BUF_SIZE(na));
		/* writable for the host */
		err = virtqueue_enqueue(vq, rxq, &sg, 0, sg.sg_nseg);
		if (err < 0) {
			D("virtqueue_enqueue failed");
			break;
		}
		nm_i = nm_next(nm_i, lim);
	}
	return nm_i;
}

/* Reconcile kernel and user view of the receive ring. */
static int
vtnet_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	// u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct SOFTC_T *sc = ifp->if_softc;
	struct vtnet_rxq *rxq = &sc->vtnet_rxqs[ring_nr];
	struct virtqueue *vq = rxq->vtnrx_vq;

	/* XXX netif_carrier_ok ? */

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * First part: import newly received packets.
	 * Only accept our
	 * own buffers (matching the token). We should only get
	 * matching buffers, because of vtnet_netmap_free_rx_unused_bufs()
	 * and vtnet_netmap_init_buffers().
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;
                struct netmap_adapter *token;

                nm_i = kring->nr_hwtail;
                n = 0;
		for (;;) {
			int len;
                        token = virtqueue_dequeue(vq, &len);
                        if (token == NULL)
                                break;
                        if (likely(token == (void *)rxq)) {
                            ring->slot[nm_i].len = len;
                            ring->slot[nm_i].flags = slot_flags;
                            nm_i = nm_next(nm_i, lim);
                            n++;
                        } else {
			    D("This should not happen");
                        }
		}
		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
        ND("[B] h %d c %d hwcur %d hwtail %d",
		ring->head, ring->cur, kring->nr_hwcur,
			      kring->nr_hwtail);

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur; /* netmap ring index */
	if (nm_i != head) {
		int err = vtnet_refill_rxq(kring, nm_i, head);
		if (err < 0)
			return 1;
		kring->nr_hwcur = err;
		virtqueue_notify(vq);
		/* After draining the queue may need an intr from the hypervisor */
        	vtnet_rxq_enable_intr(rxq);
	}

        ND("[C] h %d c %d t %d hwcur %d hwtail %d",
		ring->head, ring->cur, ring->tail,
		kring->nr_hwcur, kring->nr_hwtail);

	return 0;
}


/* Make RX virtqueues buffers pointing to netmap buffers. */
static int
vtnet_netmap_init_rx_buffers(struct SOFTC_T *sc)
{
	struct ifnet *ifp = sc->vtnet_ifp;
	struct netmap_adapter* na = NA(ifp);
	unsigned int r;

	/* if ptnetmap is enabled we must not init netmap buffers */
	if (VTNET_PTNETMAP_ON(na))
		return 1;
	if (!nm_native_on(na))
		return 0;
	for (r = 0; r < na->num_rx_rings; r++) {
                struct netmap_kring *kring = &na->rx_rings[r];
		struct vtnet_rxq *rxq = &sc->vtnet_rxqs[r];
		struct virtqueue *vq = rxq->vtnrx_vq;
	        struct netmap_slot* slot;
		int err = 0;

		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("strange, null netmap ring %d", r);
			return 0;
		}
		/* Add up to na>-num_rx_desc-1 buffers to this RX virtqueue.
		 * It's important to leave one virtqueue slot free, otherwise
		 * we can run into ring->cur/ring->tail wraparounds.
		 */
		err = vtnet_refill_rxq(kring, 0, na->num_rx_desc-1);
		if (err < 0)
			return 0;
		virtqueue_notify(vq);
	}

	return 1;
}

/* Update the virtio-net device configurations. Number of queues can
 * change dinamically, by 'ethtool --set-channels $IFNAME combined $N'.
 * This is actually the only way virtio-net can currently enable
 * the multiqueue mode.
 * XXX note that we seem to lose packets if the netmap ring has more
 * slots than the queue
 */
static int
vtnet_netmap_config(struct netmap_adapter *na, u_int *txr, u_int *txd,
						u_int *rxr, u_int *rxd)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = ifp->if_softc;

	*txr = *rxr = sc->vtnet_max_vq_pairs;
	*rxd = 512; // sc->vtnet_rx_nmbufs;
	*txd = *rxd; // XXX
        D("vtnet config txq=%d, txd=%d rxq=%d, rxd=%d",
					*txr, *txd, *rxr, *rxd);

	return 0;
}

#ifdef WITH_PTNETMAP_GUEST
/*
 * ptnetmap support for: virtio-net (FreeBSD version)
 *
 * this part od this file is meant to be a reference on how to implement
 * ptnetmap support for a network driver.
 * this file contains code but only static or inline functions used
 * by a single driver.
 */

/*
 * virtio-specific macro and fucntions
 */
/* ptnetmap virtio register BASE */
#define PTNETMAP_VIRTIO_IO_BASE         sizeof(struct virtio_net_config)
#ifndef VIRTIO_NET_F_PTNETMAP
#define VIRTIO_NET_F_PTNETMAP   0x2000000  /* linux/qeum  25 */
#endif /* VIRTIO_NET_F_PTNETMAP */

static void inline
vtnet_ptnetmap_iowrite4(device_t dev, uint32_t addr, uint32_t val)
{
	int i;
	/*
	 * virtio_pci config_set use multiple iowrite8, we need to split the
	 * call and reverse the order
	 */
	for (i = 3; i >= 0; i--) {
		virtio_write_dev_config_1(dev, PTNETMAP_VIRTIO_IO_BASE + addr + i,
			*(((uint8_t *)&val) + i));
	}
}

static uint32_t inline
vtnet_ptnetmap_ioread4(device_t dev, uint32_t addr)
{
	uint32_t val;
	int i;

	for (i = 0; i <= 3; i++) {
		*(((uint8_t *)&val) + i) = virtio_read_dev_config_1(dev,
				PTNETMAP_VIRTIO_IO_BASE + addr + i);
	}
	return val;
}

/*
 * CSB (Communication Status Block) allocation.
 * CSB is the shared memory used by the netmap instance running in the guest
 * and the ptnetmap kthreads in the host.
 * The CSBBAH/CSBBAL registers must be added to the virtio-net device.
 *
 * Only called after netmap_pt_guest_attach().
 */
static int
vtnet_ptnetmap_alloc_csb(struct SOFTC_T *sc)
{
	device_t dev = sc->vtnet_dev;
	struct ifnet *ifp = sc->vtnet_ifp;
	struct netmap_pt_guest_adapter* ptna =
		(struct netmap_pt_guest_adapter *)NA(ifp);

	vm_paddr_t csb_phyaddr;

	if (ptna->csb)
		return 0;

	ptna->csb = contigmalloc(NET_PARAVIRT_CSB_SIZE, M_DEVBUF,
			M_NOWAIT | M_ZERO, (size_t)0, -1UL, PAGE_SIZE, 0);
	if (!ptna->csb) {
		D("Communication Status Block allocation failed!");
		return ENOMEM;
	}

	csb_phyaddr = vtophys(ptna->csb);

	ptna->csb->guest_csb_on = 1;

	/* Tell the device the CSB physical address. */
	vtnet_ptnetmap_iowrite4(dev, PTNETMAP_VIRTIO_IO_CSBBAH,
			(uint32_t)(csb_phyaddr >> 32));
	vtnet_ptnetmap_iowrite4(dev, PTNETMAP_VIRTIO_IO_CSBBAL,
			(uint32_t)(csb_phyaddr));

	return 0;
}

/*
 * CSB (Communication Status Block) deallocation.
 */
static void
vtnet_ptnetmap_free_csb(struct SOFTC_T *sc)
{
	device_t dev = sc->vtnet_dev;
	struct ifnet *ifp = sc->vtnet_ifp;
	struct netmap_pt_guest_adapter* ptna =
		(struct netmap_pt_guest_adapter *)NA(ifp);

	if (ptna->csb) {
		/* CSB deallocation protocol. */
		vtnet_ptnetmap_iowrite4(dev, PTNETMAP_VIRTIO_IO_CSBBAH, 0x0ULL);
		vtnet_ptnetmap_iowrite4(dev, PTNETMAP_VIRTIO_IO_CSBBAL, 0x0ULL);

		contigfree(ptna->csb, NET_PARAVIRT_CSB_SIZE, M_DEVBUF);
		ptna->csb = NULL;
	}
}

static uint32_t vtnet_ptnetmap_ptctl(struct ifnet *, uint32_t);

/*
 * Returns device configuration from the CSB, after sending the PTCTL_CONFIG
 * command to the host (hypervisor virtio fronted).
 * The host reads the configuration from the netmap port (opened in the host)
 * and it stores the values in the CSB.
 */
static int
vtnet_ptnetmap_config(struct netmap_adapter *na,
		u_int *txr, u_int *txd, u_int *rxr, u_int *rxd)
{
	struct netmap_pt_guest_adapter *ptna =
		(struct netmap_pt_guest_adapter *)na;
	struct paravirt_csb *csb = ptna->csb;
	int ret;

	if (csb == NULL)
		return EINVAL;

	ret = vtnet_ptnetmap_ptctl(na->ifp, NET_PARAVIRT_PTCTL_CONFIG);
	if (ret)
		return ret;

	*txr = 1; //*txr = csb->num_tx_rings;
	*rxr = 1; //*rxr = csb->num_rx_rings;
	*txd = csb->num_tx_slots;
	*rxd = csb->num_rx_slots;

	ND("txr %u rxr %u txd %u rxd %u",
			*txr, *rxr, *txd, *rxd);
	return 0;
}

/*
 * Reconcile host and guest view of the transmit ring.
 * Use generic netmap_pt_guest_txsync().
 * Only the notification to the host is device-specific.
 */
static int
vtnet_ptnetmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	u_int ring_nr = kring->ring_id;
	struct SOFTC_T *sc = ifp->if_softc;
	struct virtqueue *vq = sc->vtnet_txqs[ring_nr].vtntx_vq;
	int ret, notify = 0;

	ret = netmap_pt_guest_txsync(kring, flags, &notify);

	if (notify)
		virtqueue_notify(vq);

	ND("TX - vq_index: %d", vq->index);

	return ret;
}

/*
 * Reconcile host and guest view of the receive ring.
 * Use generic netmap_pt_guest_rxsync().
 * Only the notification to the host is device-specific.
 */
static int
vtnet_ptnetmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	u_int ring_nr = kring->ring_id;
	struct SOFTC_T *sc = ifp->if_softc;
	struct virtqueue *vq = sc->vtnet_rxqs[ring_nr].vtnrx_vq;
	int ret, notify = 0;

	ret = netmap_pt_guest_rxsync(kring, flags, &notify);

	if (notify)
		virtqueue_notify(vq);

	ND("RX - vq_index: %d", vq->index);

	return ret;
}

/*
 * Register/unregister. We are already under netmap lock.
 * Only called on the first register or the last unregister.
 */
static int
vtnet_ptnetmap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_pt_guest_adapter *ptna =
		(struct netmap_pt_guest_adapter *)na;

	/* device-specific */
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = ifp->if_softc;
	struct paravirt_csb *csb = ptna->csb;
	struct netmap_kring *kring;
	int ret = 0;

	if (na == NULL)
		return EINVAL;

	VTNET_CORE_LOCK(sc);
	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
	        int i;
		nm_set_native_flags(na);
                /* push fake-elem in the tx queues to enable interrupts */
                for (i = 0; i < sc->vtnet_max_vq_pairs; i++) {
			struct vtnet_txq *txq = &sc->vtnet_txqs[i];
			struct mbuf *m0;
			m0 = m_gethdr(M_NOWAIT, MT_DATA);
			m0->m_len = 64;

			if (m0) {
				ret = vtnet_txq_encap(txq, &m0);
			}
		}
		ret = vtnet_ptnetmap_ptctl(na->ifp, NET_PARAVIRT_PTCTL_REGIF);
		if (ret) {
			//na->na_flags &= ~NAF_NETMAP_ON;
			nm_clear_native_flags(na);
			goto out;
		}
		/*
		 * Init ring and kring pointers
		 * After PARAVIRT_PTCTL_REGIF, the csb contains a snapshot of a
		 * host kring pointers.
		 * XXX This initialization is required, because we don't close
		 * the host port on UNREGIF.
		 */
		// Init rx ring
		kring = na->rx_rings;
		kring->rhead = kring->ring->head = csb->rx_ring.head;
		kring->rcur = kring->ring->cur = csb->rx_ring.cur;
		kring->nr_hwcur = csb->rx_ring.hwcur;
		kring->nr_hwtail = kring->rtail = kring->ring->tail =
			csb->rx_ring.hwtail;

		// Init tx ring
		kring = na->tx_rings;
		kring->rhead = kring->ring->head = csb->tx_ring.head;
		kring->rcur = kring->ring->cur = csb->tx_ring.cur;
		kring->nr_hwcur = csb->tx_ring.hwcur;
		kring->nr_hwtail = kring->rtail = kring->ring->tail =
			csb->tx_ring.hwtail;
	} else {
		ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
		//na->na_flags &= ~NAF_NETMAP_ON;
		nm_clear_native_flags(na);
		ret = vtnet_ptnetmap_ptctl(na->ifp, NET_PARAVIRT_PTCTL_UNREGIF);
		vtnet_init_locked(sc);       /* also enable intr */
	}
out:
        VTNET_CORE_UNLOCK(sc);
        return (ifp->if_drv_flags & IFF_DRV_RUNNING ? ret : 1);
}

static int
vtnet_ptnetmap_bdg_attach(const char *bdg_name, struct netmap_adapter *na)
{
	return EOPNOTSUPP;
}

/*
 * Send command to the host (hypervisor virtio fronted) through PTCTL register.
 * The PTCTL register must be added to the virtio-net device.
 */
static uint32_t
vtnet_ptnetmap_ptctl(struct ifnet *ifp, uint32_t val)
{
	struct SOFTC_T *sc = ifp->if_softc;
	device_t dev = sc->vtnet_dev;
	uint32_t ret;

        D("PTCTL = %u", val);
	vtnet_ptnetmap_iowrite4(dev, PTNETMAP_VIRTIO_IO_PTCTL, val);
        ret = vtnet_ptnetmap_ioread4(dev, PTNETMAP_VIRTIO_IO_PTSTS);
	D("PTSTS = %u", ret);

	return ret;
}

/*
 * Features negotiation with the host (hypervisor virtio fronted) through PTFEAT
 * register.
 * The PTFEAT register must be added to the virtio-net device.
 */
static uint32_t
vtnet_ptnetmap_features(struct SOFTC_T *sc)
{
	device_t dev = sc->vtnet_dev;
	uint32_t features;
	/* tell the device the features we support */
	vtnet_ptnetmap_iowrite4(dev, PTNETMAP_VIRTIO_IO_PTFEAT,
			NET_PTN_FEATURES_BASE);
	/* get back the acknowledged features */
	features = vtnet_ptnetmap_ioread4(dev, PTNETMAP_VIRTIO_IO_PTFEAT);
	D("ptnetmap support: %s\n",
			(features & NET_PTN_FEATURES_BASE) ? "base" :
			"none");
	return features;
}

static void
vtnet_ptnetmap_dtor(struct netmap_adapter *na)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = ifp->if_softc;

        vtnet_ptnetmap_free_csb(sc);
}

static struct netmap_pt_guest_ops vtnet_ptnetmap_ops = {
    .nm_ptctl = vtnet_ptnetmap_ptctl,
};
#endif /* WITH_PTNETMAP_GUEST */

static void
vtnet_netmap_attach(struct SOFTC_T *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->vtnet_ifp;
	na.num_tx_desc =  1024;// sc->vtnet_rx_nmbufs;
	na.num_rx_desc =  1024; // sc->vtnet_rx_nmbufs;
	na.nm_register = vtnet_netmap_reg;
	na.nm_txsync = vtnet_netmap_txsync;
	na.nm_rxsync = vtnet_netmap_rxsync;
	na.nm_config = vtnet_netmap_config;
	na.num_tx_rings = na.num_rx_rings = sc->vtnet_max_vq_pairs;
	D("max rings %d", sc->vtnet_max_vq_pairs);
#ifdef WITH_PTNETMAP_GUEST
	/* check if virtio-net (guest and host) supports ptnetmap */
	if (virtio_with_feature(sc->vtnet_dev, VIRTIO_NET_F_PTNETMAP) &&
		(vtnet_ptnetmap_features(sc) & NET_PTN_FEATURES_BASE)) {
		D("ptnetmap supported");
		na.nm_config = vtnet_ptnetmap_config;
		na.nm_register = vtnet_ptnetmap_reg;
		na.nm_txsync = vtnet_ptnetmap_txsync;
		na.nm_rxsync = vtnet_ptnetmap_rxsync;
		na.nm_dtor = vtnet_ptnetmap_dtor;
		na.nm_bdg_attach = vtnet_ptnetmap_bdg_attach; /* XXX */
		netmap_pt_guest_attach(&na, &vtnet_ptnetmap_ops);
		vtnet_ptnetmap_alloc_csb(sc);
	} else
#endif /* WITH_PTNETMAP_GUEST */
	netmap_attach(&na);

        D("virtio attached txq=%d, txd=%d rxq=%d, rxd=%d",
			na.num_tx_rings, na.num_tx_desc,
			na.num_tx_rings, na.num_rx_desc);
}
/* end of file */
