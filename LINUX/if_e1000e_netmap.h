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
 * $Id: if_e1000e_netmap.h 10670 2012-02-27 21:15:38Z luigi $
 *
 * netmap support for: e1000e (linux version)
 * For details on netmap support please see ixgbe_netmap.h
 * The driver supports 1 TX and 1 RX ring. Single lock.
 * tx buffer address only written on change.
 * Apparently the driver uses extended descriptors on rx from 3.2.32
 * Rx Crc stripping ?
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T	e1000_adapter

/*
 * Adaptation to different versions of the driver.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
#warning this driver uses extended descriptors
#define NM_E1K_RX_DESC_T	union e1000_rx_desc_extended
#define	NM_E1R_RX_STATUS	wb.upper.status_error
#define	NM_E1R_RX_LENGTH	wb.upper.length
#define	NM_E1R_RX_BUFADDR	read.buffer_addr
#else
#warning this driver uses regular descriptors
#define E1000_RX_DESC_EXT	E1000_RX_DESC	// XXX workaround
#define NM_E1K_RX_DESC_T	struct e1000_rx_desc
#define	NM_E1R_RX_STATUS	status
#define	NM_E1R_RX_BUFADDR	buffer_addr
#define	NM_E1R_RX_LENGTH	length
#endif /* up to 3.2.x */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
#define NM_WR_TX_TAIL(_x)	writel(_x, txr->tail)	// XXX tx_ring
#define	NM_WR_RX_TAIL(_x)	writel(_x, rxr->tail)	// XXX rx_ring
#define	NM_RD_TX_HEAD()		readl(txr->head)
#else
#define NM_WR_TX_TAIL(_x)	writel(_x, adapter->hw.hw_addr + txr->tail)
#define	NM_WR_RX_TAIL(_x)	writel(_x, adapter->hw.hw_addr + rxr->tail)
#define	NM_RD_TX_HEAD()		readl(adapter->hw.hw_addr + txr->head)
#endif /* < 3.4.0 */


/*
 * Register/unregister. We are already under netmap lock.
 */
static int
e1000_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	rtnl_lock();
	if (netif_running(adapter->netdev))
		e1000e_down(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

	if (netif_running(adapter->netdev))
		e1000e_up(adapter);
	else
		e1000e_reset(adapter);	// XXX is it needed ?

	rtnl_unlock();

	clear_bit(__E1000_RESETTING, &adapter->state);
	return (0);
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
	/* generate an interrupt approximately every half ring */
	u_int report_frequency = kring->nkr_num_slots >> 1;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_ring* txr = &adapter->tx_ring[ring_nr];

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
			void *addr = PNMB(slot, &paddr);

			/* device-specific */
			struct e1000_tx_desc *curr = E1000_TX_DESC(*txr, nic_i);
			int flags = (slot->flags & NS_REPORT ||
				nic_i == 0 || nic_i == report_frequency) ?
				E1000_TXD_CMD_RS : 0;

			NM_CHECK_ADDR_LEN(addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr)
				curr->buffer_addr = htole64(paddr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

			/* Fill the slot in the NIC ring. */
			curr->upper.data = 0;
			curr->lower.data = htole32(adapter->txd_cmd | len | flags |
				E1000_TXD_CMD_EOP);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */

		txr->next_to_use = nic_i;
		NM_WR_TX_TAIL(nic_i);
		mmiowb(); // XXX where do we need this ?
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		/* record completed transmissions using TDH */
		nic_i = NM_RD_TX_HEAD();	// XXX could scan descriptors ?
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("TDH wrap %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		txr->next_to_clean = nic_i;
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
	}
out:
	nm_txsync_finalize(kring);

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
	u_int const head = nm_rxsync_prologue(kring);
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_ring *rxr = &adapter->rx_ring[ring_nr];

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;
		int strip_crc = (adapter->flags2 & FLAG2_CRC_STRIPPING) ? 0 : 4;

		nic_i = rxr->next_to_clean;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			NM_E1K_RX_DESC_T *curr = E1000_RX_DESC_EXT(*rxr, nic_i);
			uint32_t staterr = le32toh(curr->NM_E1R_RX_STATUS);

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			ring->slot[nm_i].len = le16toh(curr->NM_E1R_RX_LENGTH) - strip_crc;
			ring->slot[nm_i].flags = slot_flags;
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
			void *addr = PNMB(slot, &paddr);
			NM_E1K_RX_DESC_T *curr = E1000_RX_DESC_EXT(*rxr, nic_i);

			if (addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;
			curr->NM_E1R_RX_BUFADDR = htole64(paddr); /* reload ext.desc. addr. */
			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr)
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->NM_E1R_RX_STATUS = 0;
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
		NM_WR_RX_TAIL(nic_i);
	}

	/* tell userspace that there might be new packets */
	nm_rxsync_finalize(kring);

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/* diagnostic routine to catch errors */
static void e1000e_no_rx_alloc(struct SOFTC_T *a, int n)
{
	D("e1000->alloc_rx_buf should not be called");
}


/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int e1000e_netmap_init_buffers(struct SOFTC_T *adapter)
{
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct e1000_ring *rxr = adapter->rx_ring;
	struct e1000_ring *txr = adapter->tx_ring;
	int i, si;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

	slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return 0;	// not in netmap mode XXX check is useless

	adapter->alloc_rx_buf = (void*)e1000e_no_rx_alloc;
	for (i = 0; i < rxr->count; i++) {
		// XXX the skb check and cleanup can go away
		struct e1000_buffer *bi = &rxr->buffer_info[i];
		si = netmap_idx_n2k(&na->rx_rings[0], i);
		PNMB(slot + si, &paddr);
		if (bi->skb)
			D("rx buf %d was set", i);
		bi->skb = NULL; // XXX leak if set
		// netmap_load_map(...)
		E1000_RX_DESC_EXT(*rxr, i)->NM_E1R_RX_BUFADDR = htole64(paddr);
	}
	rxr->next_to_use = 0;
	/* preserve buffers already made available to clients */
	i = rxr->count - 1 - nm_kr_rxspace(&na->rx_rings[0]);
	wmb();	/* Force memory writes to complete */
	NM_WR_RX_TAIL(i);

	/* now initialize the tx ring */
	slot = netmap_reset(na, NR_TX, 0, 0);
	for (i = 0; i < na->num_tx_desc; i++) {
		si = netmap_idx_n2k(&na->tx_rings[0], i);
		PNMB(slot + si, &paddr);
		// netmap_load_map(...)
		E1000_TX_DESC(*txr, i)->buffer_addr = htole64(paddr);
	}
	return 1;
}


static void
e1000_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.num_tx_desc = adapter->tx_ring->count;
	na.num_rx_desc = adapter->rx_ring->count;
	na.nm_register = e1000_netmap_reg;
	na.nm_txsync = e1000_netmap_txsync;
	na.nm_rxsync = e1000_netmap_rxsync;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
