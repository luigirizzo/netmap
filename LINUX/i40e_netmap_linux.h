/*
 * Copyright (C) 2015, Luigi Rizzo. All rights reserved.
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
 * netmap support for: i40e (LINUX version)
 *
 * derived from ixgbe
 * netmap support for a network driver.
 * This file contains code but only static or inline functions used
 * by a single driver. To avoid replication of code we just #include
 * it near the beginning of the standard driver.
 *
 * This is imported in two places, hence the conditional at the
 * beginning.
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>

int i40e_netmap_txsync(struct netmap_kring *kring, int flags);
int i40e_netmap_rxsync(struct netmap_kring *kring, int flags);

extern int ix_rx_miss, ix_rx_miss_bufs, ix_crcstrip;

#ifdef NETMAP_LINUX_I40E_PTR_ARRAY
#define NM_I40E_TX_RING(a, r)		((a)->tx_rings[(r)])
#define NM_I40E_RX_RING(a, r)		((a)->rx_rings[(r)])
#else
#define NM_I40E_TX_RING(a, r)		(&(a)->tx_rings[(r)])
#define NM_I40E_RX_RING(a, r)		(&(a)->rx_rings[(r)])
#endif

#ifdef NETMAP_I40E_MAIN
/*
 * device-specific sysctl variables:
 *
 * ix_crcstrip: 0: NIC keeps CRC in rx frames (default), 1: NIC strips it.
 *	During regular operations the CRC is stripped, but on some
 *	hardware reception of frames not multiple of 64 is slower,
 *	so using crcstrip=0 helps in benchmarks.
 *      The driver by default strips CRCs and we do not override it.
 *
 * ix_rx_miss, ix_rx_miss_bufs:
 *	count packets that might be missed due to lost interrupts.
 */
SYSCTL_DECL(_dev_netmap);
int ix_rx_miss = 0, ix_rx_miss_bufs = 0, ix_crcstrip = 1;
SYSCTL_INT(_dev_netmap, OID_AUTO, ix_crcstrip,
    CTLFLAG_RW, &ix_crcstrip, 1, "NIC strips CRC on rx frames");
SYSCTL_INT(_dev_netmap, OID_AUTO, ix_rx_miss,
    CTLFLAG_RW, &ix_rx_miss, 0, "potentially missed rx intr");
SYSCTL_INT(_dev_netmap, OID_AUTO, ix_rx_miss_bufs,
    CTLFLAG_RW, &ix_rx_miss_bufs, 0, "potentially missed rx intr bufs");

#if 0
static void
set_crcstrip(struct ixgbe_hw *hw, int onoff)
{
	/* crc stripping is set in two places:
	 * IXGBE_HLREG0 (modified on init_locked and hw reset)
	 * IXGBE_RDRXCTL (set by the original driver in
	 *	ixgbe_setup_hw_rsc() called in init_locked.
	 *	We disable the setting when netmap is compiled in).
	 * We update the values here, but also in ixgbe.c because
	 * init_locked sometimes is called outside our control.
	 */
	uint32_t hl, rxc;

	hl = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	rxc = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);
	if (netmap_verbose)
		D("%s read  HLREG 0x%x rxc 0x%x",
			onoff ? "enter" : "exit", hl, rxc);
	/* hw requirements ... */
	rxc &= ~IXGBE_RDRXCTL_RSCFRSTSIZE;
	rxc |= IXGBE_RDRXCTL_RSCACKC;
	if (onoff && !ix_crcstrip) {
		/* keep the crc. Fast rx */
		hl &= ~IXGBE_HLREG0_RXCRCSTRP;
		rxc &= ~IXGBE_RDRXCTL_CRCSTRIP;
	} else {
		/* reset default mode */
		hl |= IXGBE_HLREG0_RXCRCSTRP;
		rxc |= IXGBE_RDRXCTL_CRCSTRIP;
	}
	if (netmap_verbose)
		D("%s write HLREG 0x%x rxc 0x%x",
			onoff ? "enter" : "exit", hl, rxc);
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hl);
	IXGBE_WRITE_REG(hw, IXGBE_RDRXCTL, rxc);
}
#endif /* unused */

static void
i40e_netmap_configure_tx_ring(struct i40e_ring *ring)
{
	struct netmap_adapter *na;

	if (!ring->netdev) {
		// XXX it this possible?
		return;
	}

	na = NA(ring->netdev);
	netmap_reset(na, NR_TX, ring->queue_index, 0);
}

static int
i40e_netmap_configure_rx_ring(struct i40e_ring *ring)
{
	struct netmap_adapter *na;
	struct netmap_slot *slot;
	struct netmap_kring *kring;
	int lim, i, ring_nr;

	if (!ring->netdev) {
		// XXX it this possible?
		return 0;
	}

	na = NA(ring->netdev);
	ring_nr = ring->queue_index;
	kring = &na->rx_rings[ring_nr];

	slot = netmap_reset(na, NR_RX, ring_nr, 0);
	if (!slot)
		return 0;	// not in native netmap mode

	lim = na->num_rx_desc - 1 - nm_kr_rxspace(kring);

	for (i = 0; i < na->num_rx_desc; i++) {
		int si = netmap_idx_n2k(kring, i);
		uint64_t paddr;
		union i40e_rx_desc *rx = I40E_RX_DESC(ring, i);
		PNMB(na, slot + si, &paddr);

		rx->read.pkt_addr = htole64(paddr);
		rx->read.hdr_addr = 0;
	}
	ring->next_to_clean = netmap_idx_k2n(kring, 0);
	wmb();
	writel(lim, ring->tail);
	return 1;
}

/*
 * Register/unregister. We are already under netmap lock.
 * Only called on the first register or the last unregister.
 */
static int
i40e_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct i40e_netdev_priv *np = netdev_priv(ifp);
        struct i40e_vsi  *vsi = np->vsi;
        struct i40e_pf   *pf = (struct i40e_pf *)vsi->back;
	bool was_running;

	while (test_and_set_bit(__I40E_CONFIG_BUSY, &pf->state))
			usleep_range(1000, 2000);

	if ( (was_running = netif_running(vsi->netdev)) )
		i40e_down(vsi);

	//set_crcstrip(&adapter->hw, onoff);
	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	if (was_running) {
		i40e_up(vsi);
	}
	//set_crcstrip(&adapter->hw, onoff); // XXX why twice ?

	clear_bit(__I40E_CONFIG_BUSY, &pf->state);

	return 0;
}


/*
 * The attach routine, called near the end of i40e_attach(),
 * fills the parameters for netmap_attach() and calls it.
 * It cannot fail, in the worst case (such as no memory)
 * netmap mode will be disabled and the driver will only
 * operate in standard mode.
 */
static void
i40e_netmap_attach(struct i40e_vsi *vsi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = vsi->netdev;
	na.na_flags = NAF_BDG_MAYSLEEP;
	// XXX check that queues is set.
	na.num_tx_desc = NM_I40E_TX_RING(vsi, 0)->count;
	na.num_rx_desc = NM_I40E_RX_RING(vsi, 0)->count;
	na.nm_txsync = i40e_netmap_txsync;
	na.nm_rxsync = i40e_netmap_rxsync;
	na.nm_register = i40e_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = vsi->num_queue_pairs;
	netmap_attach(&na);
}

#else /* NETMAP_I40E_MAIN */


/*
 * Reconcile kernel and user view of the transmit ring.
 *
 * All information is in the kring.
 * Userspace wants to send packets up to the one before kring->rhead,
 * kernel knows kring->nr_hwcur is the first unsent packet.
 *
 * Here we push packets out (as many as possible), and possibly
 * reclaim buffers from previously completed transmission.
 *
 * The caller (netmap) guarantees that there is only one instance
 * running at any time. Any interference with other driver
 * methods should be handled by the individual drivers.
 */

static inline u_int
i40e_netmap_read_hwtail(void *base, int nslots)
{
	struct i40e_tx_desc *desc = base;
	return le32toh(*(volatile __le32 *)&desc[nslots]);
}

int
i40e_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	/*
	 * interrupts on every tx packet are expensive so request
	 * them every half ring, or where NS_REPORT is set
	 */
	u_int report_frequency = kring->nkr_num_slots >> 1;

	/* device-specific */
	struct i40e_netdev_priv *np = netdev_priv(ifp);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_ring *txr;

	if (!netif_running(ifp))
		return 0;

	txr = NM_I40E_TX_RING(vsi, kring->ring_id);
	if (!txr)
		return ENXIO;
	//bus_dmamap_sync(txr->dma.tag, txr->dma.map,
	//		BUS_DMASYNC_POSTREAD);

	/*
	 * First part: process new packets to send.
	 * nm_i is the current index in the netmap ring,
	 * nic_i is the corresponding index in the NIC ring.
	 * The two numbers differ because upon a *_init() we reset
	 * the NIC ring but leave the netmap ring unchanged.
	 * For the transmit ring, we have
	 *
	 *		nm_i = kring->nr_hwcur
	 *		nic_i = IXGBE_TDT (not tracked in the driver)
	 * and
	 * 		nm_i == (nic_i + kring->nkr_hwofs) % ring_size
	 *
	 * In this driver kring->nkr_hwofs >= 0, but for other
	 * drivers it might be negative as well.
	 */

	/*
	 * If we have packets to send (kring->nr_hwcur != kring->rhead)
	 * iterate over the netmap ring, fetch length and update
	 * the corresponding slot in the NIC ring. Some drivers also
	 * need to update the buffer's physical address in the NIC slot
	 * even NS_BUF_CHANGED is not set (PNMB computes the addresses).
	 *
	 * The netmap_reload_map() calls is especially expensive,
	 * even when (as in this case) the tag is 0, so do only
	 * when the buffer has actually changed.
	 *
	 * If possible do not set the report/intr bit on all slots,
	 * but only a few times per ring or when NS_REPORT is set.
	 *
	 * Finally, on 10G and faster drivers, it might be useful
	 * to prefetch the next slot and txr entry.
	 */

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);

		__builtin_prefetch(&ring->slot[nm_i]);
		__builtin_prefetch(I40E_TX_DESC(txr, nic_i));

		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			/* device-specific */
			struct i40e_tx_desc *curr = I40E_TX_DESC(txr, nic_i);
			u64 flags = (slot->flags & NS_REPORT ||
				nic_i == 0 || nic_i == report_frequency) ?
				((u64)I40E_TX_DESC_CMD_RS << I40E_TXD_QW1_CMD_SHIFT) : 0;

			/* prefetch for next round */
			__builtin_prefetch(&ring->slot[nm_i + 1]);
			__builtin_prefetch(I40E_TX_DESC(txr, nic_i));

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				//netmap_reload_map(na, txr->dma.tag, txbuf->map, addr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

			/* Fill the slot in the NIC ring. */
			/* Use legacy descriptor, they are faster? */
			curr->buffer_addr = htole64(paddr);
			curr->cmd_type_offset_bsz = htole64(
			    ((u64)len << I40E_TXD_QW1_TX_BUF_SZ_SHIFT) |
			    flags |
			    ((u64)(I40E_TX_DESC_CMD_ICRC | I40E_TX_DESC_CMD_EOP) << I40E_TXD_QW1_CMD_SHIFT)
			  ); // XXX more ?

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		/* synchronize the NIC ring */
		//bus_dmamap_sync(txr->dma.tag, txr->dma.map,
		//	BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		/* (re)start the tx unit up to slot nic_i (excluded) */
		wmb();
		writel(nic_i, txr->tail);
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	nic_i = i40e_netmap_read_hwtail(txr->desc, kring->nkr_num_slots);
	if (nic_i != txr->next_to_clean) {
		/* some tx completed, increment avail */
		txr->next_to_clean = nic_i;
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
	}

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 * Same as for the txsync, this routine must be efficient.
 * The caller guarantees a single invocations, but races against
 * the rest of the driver should be handled here.
 *
 * On call, kring->rhead is the first packet that userspace wants
 * to keep, and kring->rcur is the wakeup point.
 * The kernel has previously reported packets up to kring->rtail.
 *
 * If (flags & NAF_FORCE_READ) also check for incoming packets irrespective
 * of whether or not we received an interrupt.
 */
int
i40e_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct i40e_netdev_priv *np = netdev_priv(ifp);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_ring *rxr;

	if (!netif_running(ifp))
		return 0;
       
	rxr = NM_I40E_RX_RING(vsi, kring->ring_id);
	if (!rxr)
		return ENXIO;

	if (head > lim)
		return netmap_ring_reinit(kring);

	if (!rxr)
		return ENXIO;
	/* XXX check sync modes */
	//bus_dmamap_sync(rxr->dma.tag, rxr->dma.map,
	//		BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * First part: import newly received packets.
	 *
	 * nm_i is the index of the next free slot in the netmap ring,
	 * nic_i is the index of the next received packet in the NIC ring,
	 * and they may differ in case if_init() has been called while
	 * in netmap mode. For the receive ring we have
	 *
	 *	nic_i = rxr->next_check;
	 *	nm_i = kring->nr_hwtail (previous)
	 * and
	 *	nm_i == (nic_i + kring->nkr_hwofs) % ring_size
	 *
	 * rxr->next_check is set to 0 on a ring reinit
	 */
	if (netmap_no_pendintr || force_update) {
		int crclen = ix_crcstrip ? 0 : 4;
		uint16_t slot_flags = kring->nkr_slot_flags;

		nic_i = rxr->next_to_clean; // or also k2n(kring->nr_hwtail)
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			union i40e_rx_desc *curr = I40E_RX_DESC(rxr, nic_i);
			uint64_t qword = le64toh(curr->wb.qword1.status_error_len);
			uint32_t staterr = (qword & I40E_RXD_QW1_STATUS_MASK)
				 >> I40E_RXD_QW1_STATUS_SHIFT;

			if ((staterr & (1<<I40E_RX_DESC_STATUS_DD_SHIFT)) == 0) {
				break;
			}
			ring->slot[nm_i].len = ((qword & I40E_RXD_QW1_LENGTH_PBUF_MASK)
			    >> I40E_RXD_QW1_LENGTH_PBUF_SHIFT) - crclen;
			ring->slot[nm_i].flags = slot_flags;
			//bus_dmamap_sync(rxr->ptag,
			//    rxr->buffers[nic_i].pmap, BUS_DMASYNC_POSTREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			if (netmap_no_pendintr && !force_update) {
				/* diagnostics */
				ix_rx_miss ++;
				ix_rx_miss_bufs += n;
			}
			rxr->next_to_clean = nic_i;
			kring->nr_hwtail = nm_i;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 * (kring->nr_hwcur to kring->rhead excluded),
	 * and make the buffers available for reception.
	 * As usual nm_i is the index in the netmap ring,
	 * nic_i is the index in the NIC ring, and
	 * nm_i == (nic_i + kring->nkr_hwofs) % ring_size
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			union i40e_32byte_rx_desc *curr = I40E_RX_DESC(rxr, nic_i);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				//netmap_reload_map(na, rxr->ptag, rxbuf->pmap, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->read.pkt_addr = htole64(paddr);
			curr->read.hdr_addr = 0; // XXX needed
			//bus_dmamap_sync(rxr->ptag, rxbuf->pmap,
			//    BUS_DMASYNC_PREREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		//bus_dmamap_sync(rxr->dma.tag, rxr->dma.map,
		//    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		wmb();
		writel(nic_i, rxr->tail);
	}

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

#endif /* NETMAP_I40E_MAIN */

/* end of file */
