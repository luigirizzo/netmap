/*
 * Copyright (C) 2012 Luigi Rizzo. All rights reserved.
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
 * $FreeBSD: head/sys/dev/netmap/ixgbe_netmap.h 232238 2012-02-27 19:05:01Z luigi $
 *
 * netmap modifications for sfxge

init:
interrupt:
	sfxge_ev: sfxge_ev_qpoll()
		in turn calls common/efx_ev.c efx_ev_qpoll()
		the queue contains handlers which are interleaved,
		The specific drivers are
			efx_ev_rx		0
				then call eec_rx() or sfxge_ev_rx
			efx_ev_tx		2
				then call eec_tx() or sfxge_ev_tx
		plus some generic events.
			efx_ev_driver		5
			efx_ev_global		6
			efx_ev_drv_gen		7
			efx_ev_mcdi		0xc

The receive ring seems to be circular, SFXGE_NDESCS in both rx and tx.
	struct sfxge_rxq *rxq;
	struct sfxge_rx_sw_desc *rx_desc;

	id = rxq->pending modulo SFXGE_NDESCS
	the descriptor is rxq->queue[id]

each slot has size efx_qword_t (8 bytes with all overlays)

The card is reset through sfxge_schedule_reset()

Global lock:
	sx_xlock(&sc->softc_lock);

 */

#include <net/netmap.h>
#include <sys/selinfo.h>
/*
 * Some drivers may need the following headers. Others
 * already include them by default

#include <vm/vm.h>
#include <vm/pmap.h>

 */
#include <dev/netmap/netmap_kern.h>

static void sfxge_stop(struct sfxge_softc *sc);
static int sfxge_start(struct sfxge_softc *sc);
void sfxge_tx_qlist_post(struct sfxge_txq *txq);


static int
sfxge_netmap_init_buffers(struct sfxge_softc *sc)
{
	struct netmap_adapter *na = NA(sc->ifnet);
	struct netmap_slot *slot;
	int i, l, n, max_avail;
	void *addr;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_TX, 0, 0);
	// tx rings, see
	//	sfxge_tx_qinit()
	return 0;
}


/*
 * Register/unregister. We are already under core lock.
 * Only called on the first register or the last unregister.
 */
static int
sfxge_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct sfxge_softc *sc = ifp->if_softc;
	int error = 0;

	if (na == NULL)
		return EINVAL; /* no netmap support here */

	sfxge_stop(sc);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;

		/* save if_transmit and replace with our routine */
		na->if_transmit = ifp->if_transmit;
		ifp->if_transmit = netmap_transmit;

		/*
		 * reinitialize the adapter, now with netmap flag set,
		 * so the rings will be set accordingly.
		 */
		sfxge_start(sc);
		if ((ifp->if_drv_flags & (IFF_DRV_RUNNING | IFF_DRV_OACTIVE)) == 0) {
			error = ENOMEM;
			goto fail;
		}
	} else { /* reset normal mode (explicit request or netmap failed) */
fail:
		/* restore if_transmit */
		ifp->if_transmit = na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		/* initialize the card, this time in standard mode */
		sfxge_start(sc);	/* also enables intr */
	}
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
sfxge_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct sfxge_softc *sc = ifp->if_softc;
	struct sfxge_txq *txr = sc->txq[ring_nr];

	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k = ring->cur, l, n = 0, lim = kring->nkr_num_slots - 1;

	if (k > lim)
		return netmap_ring_reinit(kring);

//	bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
//			BUS_DMASYNC_POSTREAD);

	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 * The two numbers differ because upon a *_init() we reset
	 * the NIC ring but leave the netmap ring unchanged.
	 * For the transmit ring, we have
	 *
	 *		j = kring->nr_hwcur
	 *		l = IXGBE_TDT (not tracked in the driver)
	 * and
	 * 		j == (l + kring->nkr_hwofs) % ring_size
	 *
	 * In this driver kring->nkr_hwofs >= 0, but for other
	 * drivers it might be negative as well.
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		l = netmap_idx_k2n(kring, j); /* NIC index */
		for (n = 0; j != k; n++) {
			/*
			 * Collect per-slot info.
			 * Note that txbuf and curr are indexed by l.
			 *
			 * In this driver we collect the buffer address
			 * (using the PNMB() macro) because we always
			 * need to rewrite it into the NIC ring.
			 * Many other drivers preserve the address, so
			 * we only need to access it if NS_BUF_CHANGED
			 * is set.
			 * XXX note, on this device the dmamap* calls are
			 * not necessary because tag is 0, however just accessing
			 * the per-packet tag kills 1Mpps at 900 MHz.
			 */
			struct netmap_slot *slot = &ring->slot[j];
			uint64_t paddr;
			u_int len = slot->len;
			efx_buffer_t *desc;
			void *addr = PNMB(slot, &paddr);

			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
ring_reset:

				return netmap_ring_reinit(kring);
			}

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				netmap_reload_map(txr->packet_dma_tag,
				    txr->stmp[l].map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			slot->flags &= ~NS_REPORT;
			/*
			 * Fill the slot in the NIC ring.
			 * In this driver we need to rewrite the buffer
			 * address in the NIC ring. Other drivers do not
			 * need this.
			 * Use legacy descriptor, it is faster.
			 */
			desc->eb_addr = paddr;
			desc->eb_size = len;
			desc->eb_eop = 1;
			txr->n_pend_desc = 1;
			sfxge_tx_qlist_post(txr);

			/* make sure changes to the buffer are synced */
			bus_dmamap_sync(txr->packet_dma_tag,
			    txr->stmp[l].map, BUS_DMASYNC_PREWRITE);
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		/* decrease avail by number of packets  sent */
		kring->nr_hwavail -= n;

		/* synchronize the NIC ring */
//		bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
//			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* (re)start the transmitter up to slot l (excluded) */
//		IXGBE_WRITE_REG(&adapter->hw, IXGBE_TDT(txr->me), l);
	}

	/*
	 * Reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM) {
		j = 1; /* forced reclaim, ignore interrupts */
	} else if (kring->nr_hwavail > 0) {
		j = 0; /* buffers still available: no reclaim, ignore intr. */
	} else {
		j = 1;
	}
	if (j) {
		// txeof body to reclaim buffers
		if (txr->pending != txr->completed) {
			n = (txr->pending > txr->completed) ?
				txr->pending - txr->completed :
				txr->pending - txr->completed + SFXGE_NDESCS;
			txr->completed = txr->pending;
			kring->nr_hwavail += n;
		}
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	if (kring->nr_hwavail > lim)
		return netmap_ring_reinit(kring);
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 * Same as for the txsync, this routine must be efficient and
 * avoid races in accessing the shared regions.
 *
 * When called, userspace has read data from slots kring->nr_hwcur
 * up to ring->cur (excluded).
 *
 * The last interrupt reported kring->nr_hwavail slots available
 * after kring->nr_hwcur.
 * We must subtract the newly consumed slots (cur - nr_hwcur)
 * from nr_hwavail, make the descriptors available for the next reads,
 * and set kring->nr_hwcur = ring->cur and ring->avail = kring->nr_hwavail.
 *
 */
static int
sfxge_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct sfxge_softc *sc = ifp->if_softc;
	struct sfxge_rxq *rxq = sc->rxq[ring_nr];
	struct sfxge_evq *evq = sc->evq[ring_nr];
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

	if (k > lim)
		return netmap_ring_reinit(kring);

	/* XXX check sync modes */
//	bus_dmamap_sync(rxq->rxdma.dma_tag, rxq->rxdma.dma_map,
//			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * First part, import newly received packets into the netmap ring.
	 *
	 * j is the index of the next free slot in the netmap ring,
	 * and l is the index of the next received packet in the NIC ring,
	 * and they may differ in case if_init() has been called while
	 * in netmap mode. For the receive ring we have
	 *
	 *	j = (kring->nr_hwcur + kring->nr_hwavail) % ring_size
	 *	l = rxr->next_to_check;
	 * and
	 *	j == (l + kring->nkr_hwofs) % ring_size
	 *
	 * rxr->next_to_check is set to 0 on a ring reinit
	 */
	l = rxq->completed;
	j = netmap_idx_n2k(kring, l);

	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		// see sfxge_rx_qcomplete()
	
		for (n = 0; l != rxq->pending ; n++) {
			struct sfxge_rx_sw_desc *rx_desc = &rxq->queue[l];
			ring->slot[j].len =
				rx_desc->size - sc->rx_prefix_size;
			ring->slot[j].flags = slot_flags;
//			bus_dmamap_sync(rxq->ptag,
//			    rxq->rx_buffers[l].pmap, BUS_DMASYNC_POSTREAD);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		if (n) { /* update the state variables */
//			rxq->next_to_check = l;
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Skip past packets that userspace has released
	 * (from kring->nr_hwcur to ring->cur - ring->reserved excluded),
	 * and make the buffers available for reception.
	 * As usual j is the index in the netmap ring, l is the index
	 * in the NIC ring, and j == (l + kring->nkr_hwofs) % ring_size
	 */
	j = kring->nr_hwcur;
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}
	if (j != k) { /* userspace has released some packets. */
		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* collect per-slot info, with similar validations
			 * and flag handling as in the txsync code.
			 *
			 * NOTE curr and rxbuf are indexed by l.
			 * Also, this driver needs to update the physical
			 * address in the NIC ring, but other drivers
			 * may not have this requirement.
			 */
			struct netmap_slot *slot = &ring->slot[j];
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				//netmap_reload_map(rxq->ptag, rxbuf->pmap, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
//			curr->wb.upper.status_error = 0;
//			curr->read.pkt_addr = htole64(paddr);
//			bus_dmamap_sync(rxq->ptag, rxbuf->pmap,
//			    BUS_DMASYNC_PREREAD);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
//		bus_dmamap_sync(rxq->rxdma.dma_tag, rxq->rxdma.dma_map,
//		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		l = (l == 0) ? lim : l - 1;
		//IXGBE_WRITE_REG(&adapter->hw, IXGBE_RDT(rxr->me), l);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/*
 * The attach routine, called near the end of ixgbe_attach(),
 * fills the parameters for netmap_attach() and calls it.
 * It cannot fail, in the worst case (such as no memory)
 * netmap mode will be disabled and the driver will only
 * operate in standard mode.
 */
static void
sfxge_netmap_attach(struct sfxge_softc *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->ifnet;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = SFXGE_NDESCS;
	na.num_rx_desc = SFXGE_NDESCS;
	na.nm_txsync = sfxge_netmap_txsync;
	na.nm_rxsync = sfxge_netmap_rxsync;
	na.nm_register = sfxge_netmap_reg;
	na.num_tx_rings = SFXGE_TXQ_NTYPES + SFXGE_RX_SCALE_MAX;
	na.num_rx_rings = SFXGE_RX_SCALE_MAX;
	netmap_attach(&na);
}	

/* end of file */
