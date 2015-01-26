/*-
 * (C) 2014 Luigi Rizzo - Universita` di Pisa
 *
 * BSD copyright
 *
 * $FreeBSD$
 *
 * netmap support for if_bge.c
 * see ixgbe_netmap.h for details on the structure of the
 * various functions.
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>


/*
 * support for netmap register/unregisted. We are already under core lock.
 * only called on the first register or the last unregister.
 */
static int
bge_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct bge_softc *adapter = ifp->if_softc;

	BGE_LOCK(adapter);
	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	bge_stop(adapter);

        if (onoff) {
		na_set_native_flags(na);
	} else {
		na_clear_native_flags(na);
	}
	bge_init_locked(adapter);	/* also enables intr */
	BGE_UNLOCK(adapter);
	return (ifp->if_drv_flags & IFF_DRV_RUNNING ? 0 : 1);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
bge_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct bge_softc *sc = ifp;
	struct netmap_ring *ring = kring->ring;
	int delta, j, k, l, lim = kring->nkr_num_slots - 1;
	u_int nm_i;
	u_int nic_i;
	u_int const head = kring->rhead;

	/* bge_tx_cons_idx is the equivalent of TDH on intel cards,
	 * i.e. the index of the tx frame most recently completed.
	 */
	l = sc->bge_ldata.bge_status_block->bge_idx[0].bge_tx_cons_idx;

	/* Sync the TX descriptor list */
	bus_dmamap_sync(sc->bge_cdata.bge_tx_ring_tag,
		sc->bge_cdata.bge_tx_ring_map, BUS_DMASYNC_POSTWRITE);

	/* record completed transmissions */
	delta = l - sc->bge_tx_saved_considx;
	if (delta < 0)	/* wrap around */
		delta += BGE_TX_RING_CNT;
	if (delta > 0) {	/* some tx completed */
		sc->bge_tx_saved_considx = l;
		sc->bge_txcnt -= delta;
		kring->nr_hwtail += delta;
		if (kring->nr_hwtail > lim)
			kring->nr_hwtail -= lim + 1;
	}

	/* update tail pointer */
	XXX ring->tail = ...

	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		bus_dmamap_t *txmap = sc->bge_cdata.bge_tx_dmamap;
		int n = 0;

		l = sc->bge_tx_prodidx;
		while (j != k) {
			struct netmap_slot *slot = &ring->slot[j];
			struct bge_tx_bd *d = &sc->bge_ldata.bge_tx_ring[l];
			void *addr = NMB(na, slot);
			int len = slot->len;

			NM_CHECK_ADDR_LEN(addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				uint64_t paddr = vtophys(addr);
				d->bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
				d->bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
				/* buffer has changed, unload and reload map */
				netmap_reload_map(sc->bge_cdata.bge_tx_mtag,
					txmap[l], addr, na->buff_size);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			slot->flags &= ~NS_REPORT;
			d->bge_len = len;
			d->bge_flags = BGE_TXBDFLAG_END;
			bus_dmamap_sync(sc->bge_cdata.bge_tx_mtag,
				txmap[l], BUS_DMASYNC_PREWRITE);
			j = nm_next(j, lim);
			l = nm_next(l, lim);
			n++;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		sc->bge_tx_prodidx = l;
		ring->tail = ...

		/* now repeat the last part of bge_start_locked() */
		bus_dmamap_sync(sc->bge_cdata.bge_tx_ring_tag,
                    sc->bge_cdata.bge_tx_ring_map, BUS_DMASYNC_PREWRITE);
                /* Transmit. */
                bge_writembx(sc, BGE_MBX_TX_HOST_PROD0_LO, l);
                /* 5700 b2 errata */
                if (sc->bge_chiprev == BGE_CHIPREV_5700_BX)
                        bge_writembx(sc, BGE_MBX_TX_HOST_PROD0_LO, l);
                sc->bge_timer = 5;
	}
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 * In bge, the rx ring is initialized by setting the ring size
 * bge_writembx(sc, BGE_MBX_RX_STD_PROD_LO, BGE_STD_RX_RING_CNT - 1);
 * and the receiver always starts from 0.
 *  sc->bge_rx_saved_considx starts from 0 and is the place from
 * which the driver reads incoming packets.
 * sc->bge_ldata.bge_status_block->bge_idx[0].bge_rx_prod_idx is the
 * next (free) receive buffer where the hardware will put incoming packets.
 *
 * sc->bge_rx_saved_considx is maintained in software and represents XXX
 *
 * After a successful rxeof we do
 *	sc->bge_rx_saved_considx = rx_cons;
 *	^---- effectively becomes rx_prod_idx
 *
 *	bge_writembx(sc, BGE_MBX_RX_CONS0_LO, sc->bge_rx_saved_considx);
 *	^--- we have freed some descriptors
 *
 *	bge_writembx(sc, BGE_MBX_RX_STD_PROD_LO, (sc->bge_std +
 *                  BGE_STD_RX_RING_CNT - 1) % BGE_STD_RX_RING_CNT);
 *	^---- we have freed some buffers
 */
static int
bge_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct bge_softc *sc = a;
	struct netmap_ring *ring = kring->ring;
	int j, k, n, lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	uint32_t end;

	/* XXX check sync modes */
        bus_dmamap_sync(sc->bge_cdata.bge_rx_return_ring_tag,
            sc->bge_cdata.bge_rx_return_ring_map, BUS_DMASYNC_POSTREAD);
        bus_dmamap_sync(sc->bge_cdata.bge_rx_std_ring_tag,
            sc->bge_cdata.bge_rx_std_ring_map, BUS_DMASYNC_POSTWRITE);

	l = sc->bge_rx_saved_considx;
	nm_i = kring->nkr_hwtail;
	nic_i = netmap_idx_k2n(kring, nm_i);
	/*
	 * First part: import newly received packets
	 *
	/* bge_rx_prod_idx is the same as RDH on intel cards -- the next
	 * (empty) buffer to be used for receptions.
	 * To decide when to stop we rely on bge_rx_prod_idx
	 * and not on the flags in the frame descriptors.
	 */
	end = sc->bge_ldata.bge_status_block->bge_idx[0].bge_rx_prod_idx;
	if (nic_i != end) {
		for (n = 0; nic_i != end; n++) {
			struct bge_rx_bd *cur_rx;
			uint32_t len;

			cur_rx = &sc->bge_ldata.bge_rx_return_ring[l];
			len = cur_rx->bge_len - ETHER_CRC_LEN;
			kring->ring->slot[nm_i].len = len;
			kring->ring->slot[nm_i].flags = kring->nkr_slot_flags;
			/*  sync was in bge_newbuf() */
			bus_dmamap_sync(sc->bge_cdata.bge_rx_mtag,
				sc->bge_cdata.bge_rx_std_dmamap[l],
				BUS_DMASYNC_POSTREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		sc->bge_rx_saved_considx = end;
		bge_writembx(sc, BGE_MBX_RX_CONS0_LO, end);
		sc->bge_ifp->if_ipackets += n;
		kring->nr_hwtail = nm_i;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		n = 0;
		nic_i = netmap_idx_k2n(kring, nm_i);
		while (nm_i != head) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			struct bge_rx_bd *r = &sc->bge_ldata.bge_rx_std_ring[nic_i];
			if (addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;

			r->bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
			r->bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
			if (slot->flags & NS_BUF_CHANGED) {
				netmap_reload_map(sc->bge_cdata.bge_rx_mtag,
					sc->bge_cdata.bge_rx_std_dmamap[nic_i],
					addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			r->bge_flags = BGE_RXBDFLAG_END;
			r->bge_len = na->buff_size;
			r->bge_idx = nic_i;
			bus_dmamap_sync(sc->bge_cdata.bge_rx_mtag,
				sc->bge_cdata.bge_rx_std_dmamap[nic_i],
				BUS_DMASYNC_PREREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
			n++;
		}
		kring->nr_hwcur = head;
		/* Flush the RX DMA ring */

		bus_dmamap_sync(sc->bge_cdata.bge_rx_return_ring_tag,
		    sc->bge_cdata.bge_rx_return_ring_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}
	// nm_rxsync_finalize(kring, resvd); XXX what is resvd?
	return 0;
}


static void
bge_netmap_tx_init(struct bge_softc *sc)
{
	struct bge_tx_bd *d = sc->bge_ldata.bge_tx_ring;
	int i;
	struct netmap_adapter *na = NA(sc->bge_ifp);
	struct netmap_slot *slot;

        slot = netmap_reset(na, NR_TX, 0, 0);
	/* slot is NULL if we are not in native netmap mode */
	if (!slot)
		return;
	/* in native netmap mode, overwrite addresses and maps */
	for (i = 0; i < BGE_TX_RING_CNT; i++) {
		/*
		 * the first time, ``slot`` points the first slot of
		 * the ring; the reset might have introduced some kind
		 * of offset between the kernel and userspace view of
		 * the ring; for these reasons, we use l to point
		 * to the slot linked to the i-th descriptor.
		 */
		void *addr;
		uint64_t paddr;
		struct netmap_kring *kring = &na->tx_rings[0];
		int l = i + kring->nkr_hwofs;
		if (l >= sc->rl_ldata.rl_tx_desc_cnt)
			l -= sc->rl_ldata.rl_tx_desc_cnt;

		addr = NMB(na, slot + l);
		paddr = vtophys(addr);
		d[i].bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
		d[i].bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
		netmap_load_map(na, sc->bge_cdata.bge_tx_mtag,
			sc->bge_cdata.bge_tx_dmamap[i],
			addr, na->buff_size);
	}
}


static void
bge_netmap_rx_init(struct bge_softc *sc)
{
	/* slot is NULL if we are not in netmap mode */
	struct netmap_adapter *na = NA(sc->bge_ifp);
	struct netmap_slot *slot;
	struct bge_rx_bd *r = sc->bge_ldata.bge_rx_std_ring;
	int i;

        slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return; // not in native mode

	for (i = 0; i < BGE_STD_RX_RING_CNT; i++) {
		/*
		 * the first time, ``slot`` points the first slot of
		 * the ring; the reset might have introduced some kind
		 * of offset between the kernel and userspace view of
		 * the ring; for these reasons, we use l to point
		 * to the slot linked to the i-th descriptor.
		 */
		void *addr;
		uint64_t paddr;
		struct netmap_kring *kring = &na->rx_rings[0];
		int l = i + kring->nkr_hwofs;
		if (l >= sc->rl_ldata.rl_rx_desc_cnt)
			l -= sc->rl_ldata.rl_rx_desc_cnt;

		addr = NMB(na, slot + l);
		paddr = vtophys(addr);
		r[i].bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
		r[i].bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
		r[i].bge_flags = BGE_RXBDFLAG_END;
		r[i].bge_len = na->buff_size;
		r[i].bge_idx = i;
		/*
		 * userspace knows that hwcur->hwtail slots were ready
		 * before the reset, so we need to leave some slots
		 * unavailable to the driver.
		 */
		D("incomplete driver: don't know how to reserve slots");

		netmap_reload_map(na, sc->bge_cdata.bge_rx_mtag,
			sc->bge_cdata.bge_rx_std_dmamap[i],
			addr, na->buff_size);
	}
}

static void
bge_netmap_attach(struct bge_softc *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->bge_ifp;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = BGE_TX_RING_CNT;
	na.num_rx_desc = BGE_STD_RX_RING_CNT;
	na.nm_txsync = bge_netmap_txsync;
	na.nm_rxsync = bge_netmap_rxsync;
	na.nm_register = bge_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}
/* end of file */
