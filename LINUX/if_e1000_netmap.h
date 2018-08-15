/*
 * Copyright (C) 2012-2014 Gaetano Catalli, Luigi Rizzo. All rights reserved.
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
 * $Id: if_e1000_netmap.h 10878 2012-04-12 22:28:48Z luigi $
 *
 * netmap support for: e1000 (linux version)
 * For details on netmap support please see ixgbe_netmap.h
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T	e1000_adapter

#define e1000_driver_name netmap_e1000_driver_name
char netmap_e1000_driver_name[] = "e1000" NETMAP_LINUX_DRIVER_SUFFIX;

/*
 * Register/unregister. We are already under netmap lock.
 */
static int
e1000_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(__E1000_RESETTING, &adapter->flags))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev))
		e1000_down(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	if (netif_running(adapter->netdev))
		e1000_up(adapter);
	else
		e1000_reset(adapter);

	clear_bit(__E1000_RESETTING, &adapter->flags);
	return (0);
}

static void e1000_irq_enable(struct e1000_adapter *adapter);
static void e1000_irq_disable(struct e1000_adapter *adapter);
static void
e1000_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	if (onoff)
		e1000_irq_enable(adapter);
	else
		e1000_irq_disable(adapter);
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
e1000_netmap_txsync(struct netmap_kring *kring, int flags)
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
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_tx_ring* txr = &adapter->tx_ring[ring_nr];

	rmb();
	/*
	 * First part: process new packets to send.
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
			struct e1000_tx_desc *curr = E1000_TX_DESC(*txr, nic_i);
			int hw_flags = E1000_TXD_CMD_IFCS;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (!(slot->flags & NS_MOREFRAG)) {
				hw_flags |= adapter->txd_cmd;
				/* For now E1000_TXD_CMD_RS is always set.
				 * We may set it only if NS_REPORT is set or
				 * at least once every half ring. */
			}
			if (slot->flags & NS_BUF_CHANGED) {
				curr->buffer_addr = htole64(paddr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev, &paddr, len, NR_TX);

			/* Fill the slot in the NIC ring. */
			curr->upper.data = 0;
			curr->lower.data = htole32(len | hw_flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */
		txr->next_to_use = nic_i; /* XXX what for ? */
		/* (re)start the tx unit up to slot nic_i (excluded) */
		writel(nic_i, adapter->hw.hw_addr + txr->tdt);
		mmiowb(); // XXX where do we need this ?
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		u_int tosync;

		/* record completed transmissions using TDH */
		nic_i = readl(adapter->hw.hw_addr + txr->tdh);
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("TDH wrap %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		nm_i = netmap_idx_n2k(kring, nic_i);
		txr->next_to_clean = nic_i;
		tosync = nm_next(kring->nr_hwtail, lim);
		/* sync all buffers that we are returning to userspace */
		for ( ; tosync != nm_i; tosync = nm_next(tosync, lim)) {
			struct netmap_slot *slot = &ring->slot[tosync];
			uint64_t paddr;
			(void)PNMB(na, slot, &paddr);

			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
					&paddr, slot->len, NR_TX);
		}
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
	}
out:

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
e1000_netmap_rxsync(struct netmap_kring *kring, int flags)
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
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_rx_ring *rxr = &adapter->rx_ring[ring_nr];

	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		nic_i = rxr->next_to_clean;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, nic_i);
			uint32_t staterr = le32toh(curr->status);
			struct netmap_slot *slot;
			uint64_t paddr;

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			dma_rmb(); /* read descriptor after status DD */

			slot = ring->slot + nm_i;
			PNMB(na, slot, &paddr);
			slot->len = le16toh(curr->length) - 4;
			slot->flags = (!(staterr & E1000_RXD_STAT_EOP) ? NS_MOREFRAG : 0);
			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
					&paddr, slot->len, NR_RX);
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
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, nic_i);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;
			if (slot->flags & NS_BUF_CHANGED) {
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
					&paddr, NETMAP_BUF_SIZE(na), NR_RX);
			curr->status = 0;
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
		writel(nic_i, adapter->hw.hw_addr + rxr->rdt);
	}
out:

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int e1000_netmap_init_buffers(struct SOFTC_T *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct e1000_tx_ring* txr = &adapter->tx_ring[0];
	unsigned int i, r, si;
	uint64_t paddr;

	if (!nm_native_on(na))
		return 0;

	for (r = 0; r < na->num_rx_rings; r++) {
		struct e1000_rx_ring *rxr;
		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("Skipping RX ring %d, netmap mode not requested", r);
			continue;
		}
		rxr = &adapter->rx_ring[r];

		for (i = 0; i < rxr->count; i++) {
			si = netmap_idx_n2k(na->rx_rings[r], i);
			PNMB(na, slot + si, &paddr);
			E1000_RX_DESC(*rxr, i)->buffer_addr = htole64(paddr);
		}

		rxr->next_to_use = 0;
		/* preserve buffers already made available to clients */
		i = rxr->count - 1 - nm_kr_rxspace(na->rx_rings[0]);
		if (i < 0) // XXX something wrong here, can it really happen ?
			i += rxr->count;
		wmb(); /* Force memory writes to complete */
		writel(i, hw->hw_addr + rxr->rdt);
	}

	/* now initialize the tx ring(s) */
	for (r = 0; r < na->num_tx_rings; r++) {
		slot = netmap_reset(na, NR_TX, r, 0);
		if (!slot) {
			D("Skipping TX ring %d, netmap mode not requested", r);
			continue;
		}

		for (i = 0; i < na->num_tx_desc; i++) {
			si = netmap_idx_n2k(na->tx_rings[r], i);
			PNMB(na, slot + si, &paddr);
			E1000_TX_DESC(*txr, i)->buffer_addr = htole64(paddr);
		}
	}

	return 1;
}

static int
e1000_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	struct SOFTC_T *adapter = netdev_priv(na->ifp);
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = adapter->rx_buffer_len;

	return 0;
}

static void
e1000_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.na_flags = NAF_MOREFRAG;
	na.num_tx_desc = adapter->tx_ring[0].count;
	na.num_rx_desc = adapter->rx_ring[0].count;
	na.num_tx_rings = na.num_rx_rings = 1;
	na.rx_buf_maxsize = adapter->rx_buffer_len;
	na.nm_register = e1000_netmap_reg;
	na.nm_txsync = e1000_netmap_txsync;
	na.nm_rxsync = e1000_netmap_rxsync;
	na.nm_intr = e1000_netmap_intr;
	na.nm_config = e1000_netmap_config;

	netmap_attach(&na);
}

/* end of file */
