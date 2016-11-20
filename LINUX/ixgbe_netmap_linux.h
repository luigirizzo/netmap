/*
 * Copyright (C) 2012-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
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
 * $FreeBSD: head/sys/dev/netmap/ixgbe_netmap.h 230572 2012-01-26 09:55:16Z luigi $
 *
 * netmap support for: ixgbe (LINUX version)
 *
 * This file is meant to be a reference on how to implement
 * netmap support for a network driver.
 * This file contains code but only static or inline functions used
 * by a single driver. To avoid replication of code we just #include
 * it near the beginning of the standard driver.
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#ifndef NM_IXGBEVF
/***********************************************************************
 *                        ixgbe                                        *
 ***********************************************************************/
#define NM_IXGBE_TDT(ring_nr)		IXGBE_TDT(ring_nr)
#define NM_IXGBE_TDH(ring_nr)		IXGBE_TDH(ring_nr)
#define NM_IXGBE_RDT(ring_nr)		IXGBE_RDT(ring_nr)
#define NM_IXGBE_ADAPTER 		ixgbe_adapter
#define NM_IXGBE_RESETTING 		__IXGBE_RESETTING
#define NM_IXGBE_DOWN(adapter)		ixgbe_down(adapter)
#define NM_IXGBE_UP(adapter)		ixgbe_up(adapter)
#define NM_IXGBE_RING			ixgbe_ring

#define ixgbe_driver_name netmap_ixgbe_driver_name
char ixgbe_driver_name[] = "ixgbe" NETMAP_LINUX_DRIVER_SUFFIX;

/*
 * Adaptation to different versions of the driver.
 */
#ifndef NETMAP_LINUX_IXGBE_DESC
#error "unsupported ixgbe driver version"
#else
#if   NETMAP_LINUX_IXGBE_DESC == 1
#define NM_IXGBE_TX_DESC(_1, _2)	IXGBE_TX_DESC_ADV(*(_1), _2)
#define NM_IXGBE_RX_DESC(_1, _2)	IXGBE_RX_DESC_ADV(*(_1), _2)
#elif NETMAP_LINUX_IXGBE_DESC == 2
#define NM_IXGBE_TX_DESC(_1, _2)	IXGBE_TX_DESC_ADV(_1, _2)
#define NM_IXGBE_RX_DESC(_1, _2)	IXGBE_RX_DESC_ADV(_1, _2)
#elif NETMAP_LINUX_IXGBE_DESC == 3
#define NM_IXGBE_TX_DESC(_1, _2)	IXGBE_TX_DESC(_1, _2)
#define NM_IXGBE_RX_DESC(_1, _2)	IXGBE_RX_DESC(_1, _2)
#else
#error "netmap build error: unexpected NETMAP_LINUX_IXGBE_DESC == " #NETMAP_LINUX_IXGBE_DESC
#endif
#endif /* NETMAP_LINUX_IXGBE_DESC */

#ifdef NETMAP_LINUX_IXGBE_PTR_ARRAY
#define NM_IXGBE_TX_RING(a, r)		((a)->tx_ring[(r)])
#define NM_IXGBE_RX_RING(a, r)		((a)->rx_ring[(r)])
#else
#define NM_IXGBE_TX_RING(a, r)		(&(a)->tx_ring[(r)])
#define NM_IXGBE_RX_RING(a, r)		(&(a)->rx_ring[(r)])
#endif /* NETMAP_LINUX_IXGBE_PTR_ARRAY */

#ifdef NETMAP_LINUX_IXGBE_HAVE_DISABLE
static inline void ixgbe_irq_enable_queues(struct ixgbe_adapter *adapter,
						u64 qmask);
static inline void ixgbe_irq_disable_queues(struct ixgbe_adapter *adapter,
						u64 qmask);
static void
ixgbe_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct NM_IXGBE_ADAPTER *adapter = netdev_priv(ifp);

	if (onoff) {
		ixgbe_irq_enable_queues(adapter, ~0);
	} else {
		ixgbe_irq_disable_queues(adapter, ~0);
	}
}
#else
static void
ixgbe_netmap_intr(struct netmap_adapter *na, int onoff)
{
	RD(5, "per-queue irq disable not supported");
}
#endif /* NETMAP_LINUX_IXGBE_HAVE_DISABLE */

/*
 * In netmap mode, overwrite the srrctl register with netmap_buf_size
 * to properly configure the Receive Buffer Size
 */
static void
ixgbe_netmap_configure_srrctl(struct NM_IXGBE_ADAPTER *adapter, struct NM_IXGBE_RING *rx_ring)
{
	struct netmap_adapter *na = NA(adapter->netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	u32 srrctl;
	u8 reg_idx = rx_ring->reg_idx;

	if (hw->mac.type == ixgbe_mac_82598EB) {
		u16 mask = adapter->ring_feature[RING_F_RSS].mask;
		reg_idx &= mask;
	}
	srrctl = IXGBE_RX_HDR_SIZE << 2;
	srrctl |= NETMAP_BUF_SIZE(na) >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;
	D("bufsz: %d srrctl: %d", NETMAP_BUF_SIZE(na),
		NETMAP_BUF_SIZE(na) >> IXGBE_SRRCTL_BSIZEPKT_SHIFT);
	/*
	 * XXX
	 * With Advanced RX descriptor, the address needs to be rewritten,
	 * but with Legacy RX descriptor, it simply has to zero the status
	 * byte in the descriptor to make it ready for reuse by hardware.
	 * (ixgbe datasheet - Section 7.1.9)
	 */
	srrctl |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;
	IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(reg_idx), srrctl);
}

#else
/***********************************************************************
 *                        ixgbevf                                      *
 ***********************************************************************/
#define NM_IXGBE_TDT(ring_nr)		IXGBE_VFTDT(ring_nr)
#define NM_IXGBE_TDH(ring_nr)		IXGBE_VFTDH(ring_nr)
#define NM_IXGBE_RDT(ring_nr)		IXGBE_VFRDT(ring_nr)
#define NM_IXGBE_TX_DESC(_1, _2)	IXGBEVF_TX_DESC(_1, _2)
#define NM_IXGBE_RX_DESC(_1, _2)	IXGBEVF_RX_DESC(_1, _2)
#define NM_IXGBE_TX_RING(a, r)		((a)->tx_ring[(r)])
#define NM_IXGBE_RX_RING(a, r)		((a)->rx_ring[(r)])
#define NM_IXGBE_ADAPTER 		ixgbevf_adapter
#define NM_IXGBE_RESETTING 		__IXGBEVF_RESETTING
#define NM_IXGBE_DOWN(adapter)		ixgbevf_down(adapter)
#define NM_IXGBE_UP(adapter)		ixgbevf_up(adapter)
#define NM_IXGBE_RING			ixgbevf_ring

#define ixgbevf_driver_name netmap_ixgbevf_driver_name
char ixgbevf_driver_name[] = "ixgbevf" NETMAP_LINUX_DRIVER_SUFFIX;

static void
ixgbe_netmap_intr(struct netmap_adapter *na, int onoff)
{
	// TODO
	RD(5, "per-queue irq disable not supported");
}

static void
ixgbe_netmap_configure_srrctl(struct NM_IXGBE_ADAPTER *adapter, struct NM_IXGBE_RING *rx_ring)
{
	// TODO
	D("not supported");
}
#endif /* NM_IXGBE */
/**********************************************************************/

/*
 * Register/unregister. We are already under netmap lock.
 * Only called on the first register or the last unregister.
 */
static int
ixgbe_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct NM_IXGBE_ADAPTER *adapter = netdev_priv(ifp);

	// adapter->netdev->trans_start = jiffies; // disable watchdog ?
	/* protect against other reinit */
	while (test_and_set_bit(NM_IXGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev))
		NM_IXGBE_DOWN(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	/* XXX SRIOV migth need another 2sec wait */
	if (netif_running(adapter->netdev))
		NM_IXGBE_UP(adapter);	/* also enables intr */
	clear_bit(NM_IXGBE_RESETTING, &adapter->state);
	return (0);
}

/*
 * Reconcile kernel and user view of the transmit ring.
 *
 * Userspace wants to send packets up to the one before ring->head,
 * kernel knows kring->nr_hwcur is the first unsent packet.
 *
 * Here we push packets out (as many as possible), and possibly
 * reclaim buffers from previously completed transmission.
 *
 * ring->tail is updated on return.
 * ring->head is never used here.
 *
 * The caller (netmap) guarantees that there is only one instance
 * running at any time. Any interference with other driver
 * methods should be handled by the individual drivers.
 */
static int
ixgbe_netmap_txsync(struct netmap_kring *kring, int flags)
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
	/*
	 * interrupts on every tx packet are expensive so request
	 * them every half ring, or where NS_REPORT is set
	 */
	u_int report_frequency = kring->nkr_num_slots >> 1;

	/* device-specific */
	struct NM_IXGBE_ADAPTER *adapter = netdev_priv(ifp);
	struct NM_IXGBE_RING *txr = NM_IXGBE_TX_RING(adapter, ring_nr);
	int reclaim_tx;

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
	 * If we have packets to send (kring->nr_hwcur != ring->cur)
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

	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			/* device-specific */
			union ixgbe_adv_tx_desc *curr = NM_IXGBE_TX_DESC(txr, nic_i);
			int flags = (slot->flags & NS_REPORT ||
				nic_i == 0 || nic_i == report_frequency) ?
				IXGBE_TXD_CMD_RS : 0;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, addr);
			}
			if (!(slot->flags & NS_MOREFRAG))
				flags |= IXGBE_TXD_CMD_EOP;
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);

			/* Fill the slot in the NIC ring. */
			curr->read.buffer_addr = htole64(paddr);
			curr->read.olinfo_status = htole32(len << IXGBE_ADVTXD_PAYLEN_SHIFT);
			curr->read.cmd_type_len = htole32(len | flags |
				IXGBE_ADVTXD_DTYP_DATA | IXGBE_ADVTXD_DCMD_DEXT |
				IXGBE_ADVTXD_DCMD_IFCS);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */
		/* (re)start the tx unit up to slot nic_i (excluded) */
		IXGBE_WRITE_REG(&adapter->hw, NM_IXGBE_TDT(txr->reg_idx), nic_i);
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 * Because this is expensive (we read a NIC register etc.)
	 * we only do it in specific cases (see below).
	 */
	if (flags & NAF_FORCE_RECLAIM) {
		reclaim_tx = 1; /* forced reclaim */
	} else if (!nm_kr_txempty(kring)) {
		reclaim_tx = 0; /* have buffers, no reclaim */
	} else {
		/*
		 * No buffers available. Locate previous slot with
		 * REPORT_STATUS set.
		 * If the slot has DD set, we can reclaim space,
		 * otherwise wait for the next interrupt.
		 * This enables interrupt moderation on the tx
		 * side though it might reduce throughput.
		 */
		union ixgbe_adv_tx_desc *txd = NM_IXGBE_TX_DESC(txr, 0);

		nic_i = txr->next_to_clean + report_frequency;
		if (nic_i > lim)
			nic_i -= lim + 1;
		// round to the closest with dd set
		nic_i = (nic_i < kring->nkr_num_slots / 4 ||
			 nic_i >= kring->nkr_num_slots*3/4) ?
			0 : report_frequency;
		reclaim_tx = txd[nic_i].wb.status & IXGBE_TXD_STAT_DD;	// XXX cpu_to_le32 ?
	}
	if (reclaim_tx) {
		/*
		 * Record completed transmissions.
		 * We (re)use the driver's txr->next_to_clean to keep
		 * track of the most recently completed transmission.
		 *
		 * The datasheet discourages the use of TDH to find
		 * out the number of sent packets, but we only set
		 * REPORT STATUS in a few slots so TDH is the only
		 * good way.
		 */
		nic_i = IXGBE_READ_REG(&adapter->hw, NM_IXGBE_TDH(ring_nr));
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("TDH wrap %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		txr->next_to_clean = nic_i;
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
	}
out:

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 * Same as for the txsync, this routine must be efficient.
 * The caller guarantees a single invocations, but races against
 * the rest of the driver should be handled here.
 *
 * When called, userspace has released buffers up to ring->head
 * (last one excluded).
 *
 * If (flags & NAF_FORCE_READ) also check for incoming packets irrespective
 * of whether or not we received an interrupt.
 */
static int
ixgbe_netmap_rxsync(struct netmap_kring *kring, int flags)
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
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct NM_IXGBE_ADAPTER *adapter = netdev_priv(ifp);
	struct NM_IXGBE_RING *rxr = NM_IXGBE_RX_RING(adapter, ring_nr);

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();

	/*
	 * First part: import newly received packets.
	 *
	 * nm_i is the index of the next free slot in the netmap ring,
	 * nic_i is the index of the next received packet in the NIC ring,
	 * and they may differ in case if_init() has been called while
	 * in netmap mode. For the receive ring we have
	 *
	 *	nm_i = (kring->nr_hwtail)
	 *	nic_i = rxr->next_to_clean; // really next to check
	 * and
	 *	nm_i == (nic_i + kring->nkr_hwofs) % ring_size
	 *
	 * rxr->next_to_clean is set to 0 on a ring reinit
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		nic_i = rxr->next_to_clean;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			union ixgbe_adv_rx_desc *curr = NM_IXGBE_RX_DESC(rxr, nic_i);
			uint32_t staterr = le32toh(curr->wb.upper.status_error);

			if ((staterr & IXGBE_RXD_STAT_DD) == 0)
				break;
			ring->slot[nm_i].len = le16toh(curr->wb.upper.length);
			ring->slot[nm_i].flags = (!(staterr & IXGBE_RXD_STAT_EOP) ? NS_MOREFRAG |
										slot_flags:slot_flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = nic_i;
			kring->nr_hwtail = nm_i;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 * (kring->nr_hwcur to ring->head excluded),
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

			union ixgbe_adv_rx_desc *curr = NM_IXGBE_RX_DESC(rxr, nic_i);
			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->wb.upper.status_error = 0;
			curr->read.pkt_addr = htole64(paddr);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		rxr->next_to_use = nic_i; // XXX not really used
		wmb();
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		IXGBE_WRITE_REG(&adapter->hw, NM_IXGBE_RDT(rxr->reg_idx), nic_i);
	}


	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/*
 * if in netmap mode, attach the netmap buffers to the ring and return true.
 * Otherwise return false.
 */
static int
ixgbe_netmap_configure_tx_ring(struct NM_IXGBE_ADAPTER *adapter, int ring_nr)
{
	struct netmap_adapter *na = NA(adapter->netdev);
	struct netmap_slot *slot;
	//int j;

        slot = netmap_reset(na, NR_TX, ring_nr, 0);
	if (!slot)
		return 0;	// not in native netmap mode
#if 0
	/*
	 * on a generic card we should set the address in the slot.
	 * But on the ixgbe, the address needs to be rewritten
	 * after a transmission so there is nothing do to except
	 * loading the map.
	 */
	for (j = 0; j < na->num_tx_desc; j++) {
		int sj = netmap_idx_n2k(&na->tx_rings[ring_nr], j);
		uint64_t paddr;
		void *addr = PNMB(na, slot + sj, &paddr);
	}
#endif
	return 1;
}

static int
ixgbe_netmap_configure_rx_ring(struct NM_IXGBE_ADAPTER *adapter, int ring_nr)
{
	/*
	 * In netmap mode, we must preserve the buffers made
	 * available to userspace before the if_init()
	 * (this is true by default on the TX side, because
	 * init makes all buffers available to userspace).
	 *
	 * netmap_reset() and the device-specific routines
	 * (e.g. ixgbe_setup_receive_rings()) map these
	 * buffers at the end of the NIC ring, so here we
	 * must set the RDT (tail) register to make sure
	 * they are not overwritten.
	 *
	 * In this driver the NIC ring starts at RDH = 0,
	 * RDT points to the last slot available for reception (?),
	 * so RDT = num_rx_desc - 1 means the whole ring is available.
	 */
	struct netmap_adapter *na = NA(adapter->netdev);
	struct netmap_slot *slot;
	int lim, i;
	struct NM_IXGBE_RING *ring = NM_IXGBE_RX_RING(adapter, ring_nr);

        slot = netmap_reset(na, NR_RX, ring_nr, 0);
        /* same as in ixgbe_setup_transmit_ring() */
	if (!slot)
		return 0;	// not in native netmap mode
	// XXX can we move it later ?
	ixgbe_netmap_configure_srrctl(adapter, ring);

	lim = na->num_rx_desc - 1 - nm_kr_rxspace(&na->rx_rings[ring_nr]);

	for (i = 0; i < na->num_rx_desc; i++) {
		/*
		 * Fill the map and set the buffer address in the NIC ring,
		 * considering the offset between the netmap and NIC rings
		 * (see comment in ixgbe_setup_transmit_ring() ).
		 */
		int si = netmap_idx_n2k(&na->rx_rings[ring_nr], i);
		uint64_t paddr;
		PNMB(na, slot + si, &paddr);
		// netmap_load_map(rxr->ptag, rxbuf->pmap, addr);
		/* Update descriptor */
		NM_IXGBE_RX_DESC(ring, i)->read.pkt_addr = htole64(paddr);
	}
	IXGBE_WRITE_REG(&adapter->hw, NM_IXGBE_RDT(ring_nr), lim);
	return 1;
}


/*
 * The attach routine, called near the end of ixgbe_attach(),
 * fills the parameters for netmap_attach() and calls it.
 * It cannot fail, in the worst case (such as no memory)
 * netmap mode will be disabled and the driver will only
 * operate in standard mode.
 */
static void
ixgbe_netmap_attach(struct NM_IXGBE_ADAPTER *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.num_tx_desc = NM_IXGBE_TX_RING(adapter, 0)->count;
	na.num_rx_desc = NM_IXGBE_RX_RING(adapter, 0)->count;
	na.nm_txsync = ixgbe_netmap_txsync;
	na.nm_rxsync = ixgbe_netmap_rxsync;
	na.nm_register = ixgbe_netmap_reg;
	na.num_tx_rings = adapter->num_tx_queues;
	na.num_rx_rings = adapter->num_rx_queues;
	na.nm_intr = ixgbe_netmap_intr;
	netmap_attach(&na);
}

/* end of file */
