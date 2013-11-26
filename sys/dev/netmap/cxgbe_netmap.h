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
 * $FreeBSD$
 *
 * netmap modifications for cxgbe

20120120
t4_sge seems to be the main file for processing.

the device has several queues
	iq	ingress queue (messages posted ?)
	fl	freelist queue

buffers are in sd->cl

interrupts are serviced by t4_intr*() which does a atomic_cmpset_int()
to run only one instance of the driver (service_iq()) and
then clears the flag at the end.
The dispatches in there makes a list (iql) of postponed work.

Handlers are cpl_handler[] per packet type.
	received packets are t4_eth_rx()

the main transmit routine is t4_main.c :: cxgbe_transmit()
	which ends into t4_sge.c :: t4_eth_tx()
	and eventually write_txpkt_wr()

refill_fl() is called under lock
X_RSPD_TYPE_FLBUF	is a data packet, perhaps
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
// #include <vm/vm.h>
// #include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>

static int	cxgbe_netmap_reg(struct ifnet *, int onoff);
static int	cxgbe_netmap_txsync(void *, u_int, int);
static int	cxgbe_netmap_rxsync(void *, u_int, int);
static void	cxgbe_netmap_lock_wrapper(void *, int, u_int);


SYSCTL_NODE(_dev, OID_AUTO, cxgbe, CTLFLAG_RW, 0, "cxgbe card");

static void
cxgbe_netmap_attach(struct port_info *pi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = pi->ifp;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = 0; // qsize pi->num_tx_desc;
	na.num_rx_desc = 0; // XXX qsize  pi->num_rx_desc;
	na.nm_txsync = cxgbe_netmap_txsync;
	na.nm_rxsync = cxgbe_netmap_rxsync;
	na.nm_register = cxgbe_netmap_reg;
	/*
	 * adapter->rx_mbuf_sz is set by SIOCSETMTU, but in netmap mode
	 * we allocate the buffers on the first register. So we must
	 * disallow a SIOCSETMTU when if_capenable & IFCAP_NETMAP is set.
	 */
	na.num_tx_rings = na->num_rx_rings = pi->ntxq;
	na.buff_size = NETMAP_BUF_SIZE;
	netmap_attach(&na);
}	


/*
 * support for netmap register/unregisted. We are already under core lock.
 * only called on the first init or the last unregister.
 */
static int
cxgbe_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	int error = 0;

	if (!na)
		return EINVAL;

#if 0
	ixgbe_disable_intr(adapter);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	if (onoff) {
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;

		/* save if_transmit to restore it later */
		na->if_transmit = ifp->if_transmit;
		ifp->if_transmit = netmap_transmit;

		ixgbe_init_locked(adapter);
		if ((ifp->if_drv_flags & (IFF_DRV_RUNNING | IFF_DRV_OACTIVE)) == 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
fail:
		/* restore if_transmit */
		ifp->if_transmit = na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		ixgbe_init_locked(adapter);	/* also enables intr */
	}
#endif
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 *
 * Userspace has filled tx slots up to cur (excluded).
 * The last unused slot previously known to the kernel was nr_hwcur,
 * and the last interrupt reported nr_hwavail slots available
 * (using the special value -1 to indicate idle transmit ring).
 * The function must first update avail to what the kernel
 * knows, subtract the newly used slots (cur - nr_hwcur)
 * from both avail and nr_hwavail, and set nr_hwcur = cur
 * issuing a dmamap_sync on all slots.
 *
 * Check parameters in the struct netmap_ring.
 * We don't use avail, only check for bogus values.
 * Make sure cur is valid, and same goes for buffer indexes and lengths.
 * To avoid races, read the values once, and never use those from
 * the ring afterwards.
 */
static int
cxgbe_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
#if 0
        struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp;
	struct tx_ring *txr = &adapter->tx_rings[ring_nr];
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int j, k, n = 0, lim = kring->nkr_num_slots - 1;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	k = ring->cur;	/* ring is not protected by any lock */
	if ( (kring->nr_kflags & NR_REINIT) || k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		IXGBE_TX_LOCK(txr);
	bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
			BUS_DMASYNC_POSTREAD);

	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		while (j != k) {
			struct netmap_slot *slot = &ring->slot[j];
			struct ixgbe_tx_buf *txbuf = &txr->tx_buffers[j];
			union ixgbe_adv_tx_desc *curr = &txr->tx_base[j];
			void *addr = NMB(slot);
			int flags = ((slot->flags & NS_REPORT) ||
				j == 0 || j == report_frequency) ?
					IXGBE_TXD_CMD_RS : 0;
			int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				if (do_lock)
					IXGBE_TX_UNLOCK(txr);
				return netmap_ring_reinit(kring);
			}

			slot->flags &= ~NS_REPORT;
			curr->read.buffer_addr = htole64(vtophys(addr));
			curr->read.olinfo_status = 0;
			curr->read.cmd_type_len =
			    htole32(txr->txd_cmd | len |
				(IXGBE_ADVTXD_DTYP_DATA |
				    IXGBE_ADVTXD_DCMD_IFCS |
				    IXGBE_TXD_CMD_EOP | flags) );
			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				netmap_reload_map(txr->txtag, txbuf->map,
					addr, na->buff_size);
				slot->flags &= ~NS_BUF_CHANGED;
			}

			bus_dmamap_sync(txr->txtag, txbuf->map,
				BUS_DMASYNC_PREWRITE);
			j = (j == lim) ? 0 : j + 1;
			n++;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		ring->avail -= n; // XXX see others
		kring->nr_hwavail = ring->avail;

		bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		IXGBE_WRITE_REG(&adapter->hw, IXGBE_TDT(txr->me), k);
	}

	if (n == 0 || kring->nr_hwavail < 1) {
		/* record completed transmissions. TODO
		 *
		 * The datasheet discourages the use of TDH to find out the
		 * number of sent packets; the right way to do so, is to check
		 * the DD bit inside the status of a packet descriptor.  On the
		 * other hand, we avoid to set the `report status' bit for
		 * *all* outgoing packets (kind of interrupt mitigation),
		 * consequently the DD bit is not guaranteed to be set for all
		 * the packets: thats way, for the moment we continue to use
		 * TDH.
		 */
		j = IXGBE_READ_REG(&adapter->hw, IXGBE_TDH(ring_nr));
		if (j >= kring->nkr_num_slots) { /* XXX can happen */
			D("TDH wrap %d", j);
			j -= kring->nkr_num_slots;
		}
		int delta = j - txr->next_to_clean;
		if (delta) {
			/* new transmissions were completed, increment
			   ring->nr_hwavail. */
			if (delta < 0)
				delta += kring->nkr_num_slots;
			txr->next_to_clean = j;
			kring->nr_hwavail += delta;
			ring->avail = kring->nr_hwavail;
		}
	}

	if (do_lock)
		IXGBE_TX_UNLOCK(txr);
#endif
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 *
 * Userspace has read rx slots up to cur (excluded).
 * The last unread slot previously known to the kernel was nr_hwcur,
 * and the last interrupt reported nr_hwavail slots available.
 * We must subtract the newly consumed slots (cur - nr_hwcur)
 * from nr_hwavail, clearing the descriptors for the next
 * read, tell the hardware that they are available,
 * and set nr_hwcur = cur and avail = nr_hwavail.
 * issuing a dmamap_sync on all slots.
 */
static int
cxgbe_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
#if 0
        struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp;
	struct rx_ring *rxr = &adapter->rx_rings[ring_nr];
	struct netmap_adapter *na = NA(adapter->ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int j, k, n, lim = kring->nkr_num_slots - 1;

	k = ring->cur;	/* ring is not protected by any lock */
	if ( (kring->nr_kflags & NR_REINIT) || k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		IXGBE_RX_LOCK(rxr);
	/* XXX check sync modes */
	bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	j = rxr->next_to_check;
	for (n = 0; ; n++) {
		union ixgbe_adv_rx_desc *curr = &rxr->rx_base[j];
		uint32_t staterr = le32toh(curr->wb.upper.status_error);

		if ((staterr & IXGBE_RXD_STAT_DD) == 0)
			break;
		ring->slot[j].len = le16toh(curr->wb.upper.length);
		ring->slot[j].flags = kring->nkr_slot_flags;
		bus_dmamap_sync(rxr->ptag,
			rxr->rx_buffers[j].pmap, BUS_DMASYNC_POSTREAD);
		j = (j == lim) ? 0 : j + 1;
	}
	if (n) {
		rxr->next_to_check = j;
		kring->nr_hwavail += n;
		if (kring->nr_hwavail >= lim - 10) {
			ND("rx ring %d almost full %d", ring_nr, kring->nr_hwavail);
		}
	}

	/* skip past packets that userspace has already processed,
	 * making them available for reception.
	 * advance nr_hwcur and issue a bus_dmamap_sync on the
	 * buffers so it is safe to write to them.
	 * Also increase nr_hwavail
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* userspace has read some packets. */
		n = 0;
		while (j != k) {
			struct netmap_slot *slot = ring->slot + j;
			union ixgbe_adv_rx_desc *curr = &rxr->rx_base[j];
			struct ixgbe_rx_buf *rxbuf = rxr->rx_buffers + j;
			void *addr = NMB(slot);

			if (addr == netmap_buffer_base) { /* bad buf */
				if (do_lock)
					IXGBE_RX_UNLOCK(rxr);
				return netmap_ring_reinit(kring);
			}

			curr->wb.upper.status_error = 0;
			curr->read.pkt_addr = htole64(vtophys(addr));
			if (slot->flags & NS_BUF_CHANGED) {
				netmap_reload_map(rxr->ptag, rxbuf->pmap,
					addr, na->buff_size);
				slot->flags &= ~NS_BUF_CHANGED;
			}

			bus_dmamap_sync(rxr->ptag, rxbuf->pmap,
				BUS_DMASYNC_PREREAD);

			j = (j == lim) ? 0 : j + 1;
			n++;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = ring->cur;
		bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* IMPORTANT: we must leave one free slot in the ring,
		 * so move j back by one unit
		 */
		j = (j == 0) ? lim : j - 1;
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_RDT(rxr->me), j);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail ;
	if (do_lock)
		IXGBE_RX_UNLOCK(rxr);
#endif
	return 0;
}
