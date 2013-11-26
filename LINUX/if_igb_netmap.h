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
 * $Id: if_igb_netmap.h 10878 2012-04-12 22:28:48Z luigi $
 *
 * netmap support for "igb" (untested)
 * For details on netmap support please see ixgbe_netmap.h
 * This supports multiple tx/rx rings, multiple locks ?
 * CRCstrip, address rewrite ?
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#define SOFTC_T	igb_adapter

/*
 * Adapt to different versions. E1000_TX_DESC_ADV etc. have
 * dropped the _ADV suffix in newer versions. Also the first
 * argument is now a pointer not the object.
 */
#ifndef E1000_TX_DESC_ADV
#define	E1000_TX_DESC_ADV(_r, _i)	IGB_TX_DESC(&(_r), _i)
#define	E1000_RX_DESC_ADV(_r, _i)	IGB_RX_DESC(&(_r), _i)
#define	READ_TDH(_txr)			({struct e1000_hw *hw = &adapter->hw;rd32(E1000_TDH((_txr)->reg_idx));} )
#else /* up to 3.2, approximately */
#define	igb_tx_buffer			igb_buffer
#define	tx_buffer_info			buffer_info
#define	igb_rx_buffer			igb_buffer
#define	rx_buffer_info			buffer_info
#define	READ_TDH(_txr)			readl((_txr)->head)
#endif
/*
 * Register/unregister, similar to e1000_reinit_safe()
 */
static int
igb_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter*)na;
	int error = 0;

	if (na == NULL)
		return EINVAL;

	rtnl_lock();

	while (test_and_set_bit(__IGB_RESETTING, &adapter->state))
		msleep(1);

	if (netif_running(adapter->netdev))
		igb_down(adapter);

	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &hwna->nm_ndo;
	} else {
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		ifp->netdev_ops = (void *)na->if_transmit;
	}

	if (netif_running(adapter->netdev))
		igb_up(adapter);
	else
		igb_reset(adapter);

	clear_bit(__IGB_RESETTING, &adapter->state);

	rtnl_unlock();

	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
igb_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct igb_ring* txr = adapter->tx_ring[ring_nr];
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n = 0, lim = kring->nkr_num_slots - 1;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	if (!netif_carrier_ok(ifp))
		return 0;

	/* take a copy of ring->cur now, and never read it again */
	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		uint32_t olinfo_status=0;
		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[j];
			/* curr is the current slot in the nic ring */
			union e1000_adv_tx_desc *curr =
			    E1000_TX_DESC_ADV(*txr, l);
			int flags =  ((slot->flags & NS_REPORT) ||
                                j == 0 || j == report_frequency) ?
                                        E1000_TXD_CMD_RS : 0;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			u_int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				return netmap_ring_reinit(kring);
			}

			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->read.buffer_addr = htole64(paddr);
			// XXX check olinfo and cmd_type_len
			curr->read.olinfo_status =
			    htole32(olinfo_status |
                                (len<< E1000_ADVTXD_PAYLEN_SHIFT));
			curr->read.cmd_type_len =
			    htole32(len | E1000_ADVTXD_DTYP_DATA |
				    E1000_ADVTXD_DCMD_IFCS |
				    E1000_ADVTXD_DCMD_DEXT |
				    E1000_TXD_CMD_EOP | flags);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		ND("ring %d sent %d", ring_nr, n);
		kring->nr_hwavail -= n;

		wmb(); /* synchronize writes to the NIC ring */

		txr->next_to_use = l;
		writel(l, txr->tail);
		mmiowb(); // XXX where do we need this ?
	}
	if (kring->nr_hwavail < 0 || kring->nr_hwavail > lim)
		D("ouch, hwavail %d", kring->nr_hwavail);

	if (n == 0 || kring->nr_hwavail < 1) {
		int delta;

		/* record completed transmissions using TDH */
		l = READ_TDH(txr);
		if (l >= kring->nkr_num_slots) { /* XXX can happen */
			D("TDH wrap %d", l);
			l -= kring->nkr_num_slots;
		}
		delta = l - txr->next_to_clean;
		ND("ring %d tdh %d delta %d", ring_nr, l, delta);
		if (delta) {
			/* some tx completed, increment hwavail. */
			if (delta < 0)
				delta += kring->nkr_num_slots;
			txr->next_to_clean = l;
			/* fool the timer so we don't get watchdog resets */
			txr->next_to_use = l;
			kring->nr_hwavail += delta;
		}
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
igb_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct igb_ring *rxr = adapter->rx_ring[ring_nr];
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

	if (!netif_carrier_ok(ifp))
		return 0;

	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring, l in the NIC ring.
	 */
	l = rxr->next_to_clean;
	j = netmap_idx_n2k(kring, l);
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		for (n = 0; ; n++) {
			union e1000_adv_rx_desc *curr =
					E1000_RX_DESC_ADV(*rxr, l);
			uint32_t staterr = le32toh(curr->wb.upper.status_error);
			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			ring->slot[j].len = le16toh(curr->wb.upper.length);
			ring->slot[j].flags = slot_flags;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = l;
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur; /* netmap ring index */
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}
	if (j != k) { /* userspace has released some packets. */
		l = netmap_idx_k2n(kring, j); /* NIC ring index */
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			union e1000_adv_rx_desc *curr = E1000_RX_DESC_ADV(*rxr, l);
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				return netmap_ring_reinit(kring);
			}
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_FROM_DEVICE, old_paddr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->read.pkt_addr = htole64(paddr);
			curr->read.hdr_addr = 0;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		wmb();
		rxr->next_to_use = l; // XXX not really used
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		l = (l == 0) ? lim : l - 1;
		writel(l, rxr->tail);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;

	return 0;
}


static int
igb_netmap_configure_tx_ring(struct SOFTC_T *adapter, int ring_nr)
{
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct igb_ring *txr = adapter->tx_ring[ring_nr];
	int i, si;
	void *addr;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_TX, ring_nr, 0);
	if (!slot)
		return 0;  // XXX this should never happen
	for (i = 0; i < na->num_tx_desc; i++) {
		union e1000_adv_tx_desc *tx_desc;
		si = netmap_idx_n2k(&na->tx_rings[ring_nr], i);
		addr = PNMB(slot + si, &paddr);
		tx_desc = E1000_TX_DESC_ADV(*txr, i);
		tx_desc->read.buffer_addr = htole64(paddr);
		/* actually we don't care to init the rings here */
	}
	return 1;	// success
}


static int
igb_netmap_configure_rx_ring(struct igb_ring *rxr)
{
	struct ifnet *ifp = rxr->netdev;
	struct netmap_adapter* na = NA(ifp);
	int reg_idx = rxr->reg_idx;
	struct netmap_slot* slot;
	u_int i;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

	/*
	 * XXX watch out, the main driver must not use
	 * split headers. The buffer len should be written
	 * into wr32(E1000_SRRCTL(reg_idx), srrctl) with options
	 * something like
	 *	srrctl = ALIGN(buffer_len, 1024) >>
	 *		E1000_SRRCTL_BSIZEPKT_SHIFT;
	 *	srrctl |= E1000_SRRCTL_DESCTYPE_ADV_ONEBUF;
	 *	srrctl |= E1000_SRRCTL_DROP_EN;
	 */
        slot = netmap_reset(na, NR_RX, reg_idx, 0);
	if (!slot)
		return 0;	// not in netmap mode

	for (i = 0; i < rxr->count; i++) {
		union e1000_adv_rx_desc *rx_desc;
		uint64_t paddr;
		int si = netmap_idx_n2k(&na->rx_rings[reg_idx], i);

#if 0
		// XXX the skb check can go away
		struct igb_rx_buffer *bi = &rxr->rx_buffer_info[i];
		if (bi->skb)
			D("rx buf %d was set", i);
		bi->skb = NULL; // XXX leak if set
#endif /* useless */

		PNMB(slot + si, &paddr);
		rx_desc = E1000_RX_DESC_ADV(*rxr, i);
		rx_desc->read.hdr_addr = 0;
		rx_desc->read.pkt_addr = htole64(paddr);
	}
	rxr->next_to_use = 0;
	/* preserve buffers already made available to clients */
	i = rxr->count - 1 - na->rx_rings[reg_idx].nr_hwavail;

	wmb();	/* Force memory writes to complete */
	ND("%s rxr%d.tail %d", ifp->if_xname, reg_idx, i);
	writel(i, rxr->tail);
	return 1;	// success
}


static void
igb_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.num_tx_desc = adapter->tx_ring_count;
	na.num_rx_desc = adapter->rx_ring_count;
	na.nm_register = igb_netmap_reg;
	na.nm_txsync = igb_netmap_txsync;
	na.nm_rxsync = igb_netmap_rxsync;
	na.num_tx_rings = adapter->num_tx_queues;
	na.num_rx_rings = adapter->num_rx_queues;
	netmap_attach(&na);
}
/* end of file */
