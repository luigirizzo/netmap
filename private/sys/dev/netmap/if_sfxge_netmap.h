/*
 * Copyright (C) 2014 Luigi Rizzo. All rights reserved.
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

	slot = netmap_reset(na, NR_TX, 0, 0);
	if (!slot)
		return 0;
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

	SFXGE_LOCK(sc);
	sfxge_stop(sc);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	sfxge_start(sc);	/* also enables intr */
	SFXGE_UNLOCK(sc);
	return (ifp->if_drv_flags & IFF_DRV_RUNNING ? 0 : 1);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
sfxge_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int reclaim_tx;

	struct sfxge_softc *sc = ifp->if_softc;
	struct sfxge_txq *txr = sc->txq[kring->ring_id];

//	bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
//			BUS_DMASYNC_POSTREAD);

	/*
	 * First part: process new packets to send.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i); /* NIC index */
		for (n = 0; nm_i != head ; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			efx_buffer_t *desc;

			NM_CHECK_ADDR_LEN(addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				netmap_reload_map(txr->packet_dma_tag,
				    txr->stmp[nic_i].map, addr);
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
			    txr->stmp[nic_i].map, BUS_DMASYNC_PREWRITE);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);

		}
		kring->nr_hwcur = head;

		/* synchronize the NIC ring */
//		bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
//			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* (re)start the transmitter up to slot l (excluded) */
//		IXGBE_WRITE_REG(&adapter->hw, IXGBE_TDT(txr->me), l);
	}

	/*
	 * Reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		// XXX todo: add txeof body to reclaim buffers
		if (txr->pending != txr->completed) {
			n = (txr->pending > txr->completed) ?
				txr->pending - txr->completed :
				txr->pending - txr->completed + SFXGE_NDESCS;
			txr->completed = txr->pending;
			kring->nr_hwtail += n;
			if (kring->nr_hwtail > lim)
				kring->nr_hwtail -= lim + 1;
		}
	}


	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
sfxge_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct sfxge_softc *sc = ifp->if_softc;
	struct sfxge_rxq *rxq = sc->rxq[kring->ring_id];
	struct sfxge_evq *evq = sc->evq[kring->ring_id];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = nm_rx_prologue(kring, &resvd);

	if (k > lim)
		return netmap_ring_reinit(kring);

	/* XXX check sync modes */
//	bus_dmamap_sync(rxq->rxdma.dma_tag, rxq->rxdma.dma_map,
//			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * First part, import newly received packets into the netmap ring.
	 */
	nic_i = rxq->completed;
	nm_i = netmap_idx_n2k(kring, nic_i);

	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		// see sfxge_rx_qcomplete()

		for (n = 0; l != rxq->pending ; n++) {
			struct sfxge_rx_sw_desc *rx_desc = &rxq->queue[nic_i];
			ring->slot[nm_i].len =
				rx_desc->size - sc->rx_prefix_size;
			ring->slot[nm_i].flags = slot_flags;
//			bus_dmamap_sync(rxq->ptag,
//			    rxq->rx_buffers[nic_i].pmap, BUS_DMASYNC_POSTREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
//			rxq->completed = nic_i;
			kring->nr_hwtail = nm_i;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

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
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
//		bus_dmamap_sync(rxq->rxdma.dma_tag, rxq->rxdma.dma_map,
//		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		//IXGBE_WRITE_REG(&adapter->hw, IXGBE_RDT(rxr->me), nic_i);
	}

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
