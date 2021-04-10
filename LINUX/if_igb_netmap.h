/*
 * Copyright (C) 2012-2014 Luigi Rizzo. All rights reserved.
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
 * netmap support for: igb (linux version)
 * For details on netmap support please see ixgbe_netmap.h
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T	igb_adapter

#define igb_driver_name netmap_igb_driver_name
char netmap_igb_driver_name[] = "igb" NETMAP_LINUX_DRIVER_SUFFIX;

/*
 * Adapt to different versions of the driver.
 * E1000_TX_DESC_ADV etc. have dropped the _ADV suffix at some point.
 * Also the first argument is now a pointer not the object.
 */
#ifdef NETMAP_LINUX_HAVE_IGB_RD32
#define READ_TDH(_adapter, _txr)	igb_rd32(&(_adapter)->hw, E1000_TDH((_txr)->reg_idx))
#define READ_RCTL(_adapter, _rxr)	igb_rd32(&(_adapter)->hw, E1000_RXDCTL((_rxr)->reg_idx))
#elif defined(E1000_READ_REG)
#define READ_TDH(_adapter, _txr)	E1000_READ_REG(&(_adapter)->hw, E1000_TDH((_txr)->reg_idx))
#define READ_RCTL(_adapter, _rxr)	E1000_READ_REG(&(_adapter)->hw, E1000_RXDCTL((_rxr)->reg_idx))
#elif defined rd32
static inline u32 READ_TDH(struct igb_adapter *adapter, struct igb_ring *txr)
{
	struct e1000_hw *hw = &adapter->hw;
	return rd32(E1000_TDH(txr->reg_idx));
}
static inline u32 READ_RCTL(struct igb_adapter *adapter, struct igb_ring *rxr)
{
	struct e1000_hw *hw = &adapter->hw;
	return rd32(E1000_RXDCTL(rxr->reg_idx));
}
#else
#define	READ_TDH(_adapter, _txr)	readl((_txr)->head)
#define	READ_RCTL(_adapter, _rxr)	readl(E1000_RXDCRL((_rxr)->reg_idx))
#endif
#ifdef E1000_WRITE_REG
#define NM_WRITE_RCTL(_adapter, _rxr, _rxdctl)	\
	E1000_WRITE_REG(&(_adapter)->hw, E1000_RXDCTL((_rxr)->reg_idx), (rxdctl))
#define NM_WRITE_SRRCTL(_adapter, _rxr, _srrctl)	\
	E1000_WRITE_REG(&(_adapter)->hw, E1000_SRRCTL((_rxr)->reg_idx), (srrctl))
#elif defined(wr32)
static inline void NM_WRITE_RCTL(struct igb_adapter *adapter, struct igb_ring *rxr,
	u32 rxdctl)
{
	struct e1000_hw *hw = &adapter->hw;
	wr32(E1000_RXDCTL(rxr->reg_idx), rxdctl);
}
static inline void NM_WRITE_SRRCTL(struct igb_adapter *adapter, struct igb_ring *rxr,
	u32 srrctl)
{
	struct e1000_hw *hw = &adapter->hw;
	wr32(E1000_TDH(rxr->reg_idx), srrctl);
}
#else
#define NM_WRITE_RCTL(_adapter, _rxr, _rxdctl)	\
	writel(E1000_RCTL((_rxr)->reg_idx, (_rxdctl))
#define NM_WRITE_SRRCTL(_adapter, _rxr, _srrctl)	\
	writel(E1000_SRRCTL((_rxr)->reg_idx, (_srrctl))
#endif

#ifndef E1000_TX_DESC_ADV
#define	E1000_TX_DESC_ADV(_r, _i)	IGB_TX_DESC(&(_r), _i)
#define	E1000_RX_DESC_ADV(_r, _i)	IGB_RX_DESC(&(_r), _i)
#else /* up to 3.2, approximately */
#define	igb_tx_buffer			igb_buffer
#define	tx_buffer_info			buffer_info
#define	igb_rx_buffer			igb_buffer
#define	rx_buffer_info			buffer_info
#endif


/*
 * Register/unregister. We are already under netmap lock.
 * Only called on the first register or the last unregister.
 */
static int
igb_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(__IGB_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev))
		igb_down(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	if (netif_running(adapter->netdev))
		igb_up(adapter);
	else
		igb_reset(adapter); // XXX is it needed ?

	clear_bit(__IGB_RESETTING, &adapter->state);
	return (0);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
igb_netmap_txsync(struct netmap_kring *kring, int flags)
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
	u_int report_frequency = kring->nkr_num_slots >> 1, report;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct igb_ring* txr = adapter->tx_ring[ring_nr];

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
			uint64_t offset = nm_get_offset(kring, slot);

			/* device-specific */
			union e1000_adv_tx_desc *curr =
			    E1000_TX_DESC_ADV(*txr, nic_i);
			int hw_flags = E1000_ADVTXD_DTYP_DATA |  E1000_ADVTXD_DCMD_DEXT |
				E1000_ADVTXD_DCMD_IFCS;
			u_int totlen = len;

			PNMB(na, slot, &paddr);
			NM_CHECK_ADDR_LEN_OFF(na, len, offset);

			report = slot->flags & NS_REPORT ||
				nic_i == 0 ||
				nic_i == report_frequency;
			if (slot->flags & NS_MOREFRAG) {
				/* There is some duplicated code here, but
				 * mixing everything up in the outer loop makes
				 * things less transparent, and it also adds
				 * unnecessary instructions in the fast path
				 */
				union e1000_adv_tx_desc *first = curr;

				first->read.buffer_addr = htole64(paddr + offset);
				first->read.cmd_type_len = htole32(len | hw_flags);
				netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
						&paddr, len, NR_TX);
				/* avoid setting the FCS flag in the
				 * descriptors after the first, for safety
				 */
				hw_flags &= ~E1000_ADVTXD_DCMD_IFCS;
				for (;;) {
					nm_i = nm_next(nm_i, lim);
					nic_i = nm_next(nic_i, lim);
					/* remember that we have to ask for a
					 * report each time we move past half a
					 * ring
					 */
					report |= nic_i == 0 ||
						nic_i == report_frequency;
					if (nm_i == head) {
						// XXX should we accept incomplete packets?
						return EINVAL;
					}
					slot = &ring->slot[nm_i];
					len = slot->len;
					addr = PNMB(na, slot, &paddr);
					PNMB(na, slot, &paddr);
					offset = nm_get_offset(kring, slot);
					NM_CHECK_ADDR_LEN_OFF(na, len, offset);
					curr = E1000_TX_DESC_ADV(*txr, nic_i);
					totlen += len;
					if (!(slot->flags & NS_MOREFRAG))
						break;
					curr->read.buffer_addr = htole64(paddr + offset);
					curr->read.olinfo_status = 0;
					curr->read.cmd_type_len = htole32(len | hw_flags);

					netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
							&paddr, len, NR_TX);
				}
				first->read.olinfo_status =
					htole32(totlen << E1000_ADVTXD_PAYLEN_SHIFT);
				totlen = 0;
			}
			/* curr now always points to the last descriptor of a packet
			 * (which is also the first for single-slot packets)
			 *
			 * EOP and RS must be set only in this descriptor.
			 */
			hw_flags |= E1000_TXD_CMD_EOP | (report ? E1000_TXD_CMD_RS : 0);
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);

			/* Fill the slot in the NIC ring. */
			curr->read.buffer_addr = htole64(paddr + offset);
			// XXX check olinfo and cmd_type_len
			curr->read.olinfo_status = htole32(totlen<< E1000_ADVTXD_PAYLEN_SHIFT);
			curr->read.cmd_type_len = htole32(len | hw_flags);
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev, &paddr, len, NR_TX);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */

		/* (re)start the tx unit up to slot nic_i (excluded) */
		writel(nic_i, txr->tail);
		wmb();
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		u_int tosync;

		/* record completed transmissions using TDH */
		nic_i = READ_TDH(adapter, txr);
		if (unlikely(nic_i >= kring->nkr_num_slots)) {
			nm_prerr("TDH wrap at idx %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		nm_i = netmap_idx_n2k(kring, nic_i);
		tosync = nm_next(kring->nr_hwtail, lim);
		/* sync all buffers that we are returning to userspace */
		for ( ; tosync != nm_i; tosync = nm_next(tosync, lim)) {
			struct netmap_slot *slot = &ring->slot[tosync];
			uint64_t paddr;
			(void)PNMB_O(kring, slot, &paddr);

			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
					&paddr, slot->len, NR_TX);
		}
		kring->nr_hwtail = nm_prev(nm_i, lim);
	}
out:

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
igb_netmap_rxsync(struct netmap_kring *kring, int flags)
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
	int complete; /* did we see a complete packet ? */

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct igb_ring *rxr = adapter->rx_ring[ring_nr];

	if (!netif_carrier_ok(ifp))
		return 0;

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
			union e1000_adv_rx_desc *curr =
					E1000_RX_DESC_ADV(*rxr, nic_i);
			uint32_t staterr = le32toh(curr->wb.upper.status_error);
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			dma_rmb(); /* read descriptor after status DD */
			PNMB_O(kring, slot, &paddr);
			slot->len = le16toh(curr->wb.upper.length);
			complete = (staterr & E1000_RXD_STAT_EOP);
			slot->flags = complete ? 0 : NS_MOREFRAG;
			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev, &paddr, slot->len, NR_RX);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = nic_i;
#ifdef NETMAP_LINUX_HAVE_IGB_NTA
			rxr->next_to_alloc = nic_i;
#endif /* NETMAP_LINUX_HAVE_IGB_NTA */
			if (complete)
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
			uint64_t offset = nm_get_offset(kring, slot);
			union e1000_adv_rx_desc *curr = E1000_RX_DESC_ADV(*rxr, nic_i);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				slot->flags &= ~NS_BUF_CHANGED;
			}
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
					&paddr, NETMAP_BUF_SIZE(na), NR_RX);
			curr->read.pkt_addr = htole64(paddr + offset);
			curr->read.hdr_addr = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		wmb();
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		writel(nic_i, rxr->tail);
	}


	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


static int
igb_netmap_configure_tx_ring(struct SOFTC_T *adapter, int ring_nr)
{
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;

	slot = netmap_reset(na, NR_TX, ring_nr, 0);
	if (!slot)
		return 0;  // not in netmap native mode

	/* no need to fill the tx rings, since txsync will
	 * always overwrite the tx slots
	 */

	return 1;	// success
}

static int
igb_netmap_bufcfg(struct netmap_kring *kring, uint64_t target)
{
	if (kring->tx == NR_TX) {
		kring->hwbuf_len = target;
		return 0;
	}

	target >>= 10;
	if (target >= 1 && target <= 16) {
		target <<= 10;
	} else {
		return EINVAL;
	}
	kring->hwbuf_len = target;
	kring->buf_align = 0; /* no alignment */
	nm_prinf("%s: hwbuf_len %llu", kring->name, kring->hwbuf_len);
	return 0;
}

static void
igb_netmap_configure_srrctl(struct igb_ring *rxr)
{
	struct ifnet *ifp = rxr->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct igb_adapter *adapter = netdev_priv(ifp);
	struct netmap_kring *kring = na->rx_rings[rxr->reg_idx];
	u32 srrctl;

	srrctl = kring->hwbuf_len >> E1000_SRRCTL_BSIZEPKT_SHIFT;
	srrctl |= E1000_SRRCTL_DESCTYPE_ADV_ONEBUF;
	srrctl |= E1000_SRRCTL_DROP_EN;
	NM_WRITE_SRRCTL(adapter, rxr, srrctl);
}


static int
igb_netmap_configure_rx_ring(struct igb_ring *rxr)
{
	struct ifnet *ifp = rxr->netdev;
	struct netmap_adapter* na = NA(ifp);
	int reg_idx = rxr->reg_idx;
	struct netmap_slot* slot;
	struct netmap_kring *kring;
	u_int i, n;

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
		return 0;	// not in native netmap mode

	igb_netmap_configure_srrctl(rxr);

	kring = na->rx_rings[reg_idx];
	/* preserve buffers already made available to clients */
	n = rxr->count - 1 - nm_kr_rxspace(na->rx_rings[reg_idx]);
	for (i = 0; i < n; i++) {
		union e1000_adv_rx_desc *rx_desc;
		uint64_t paddr;
		int si = netmap_idx_n2k(kring, i);

		PNMB_O(kring, slot + si, &paddr);
		rx_desc = E1000_RX_DESC_ADV(*rxr, i);
		rx_desc->read.hdr_addr = 0;
		rx_desc->read.pkt_addr = htole64(paddr);
	}

	wmb();	/* Force memory writes to complete */
	nm_prdis("%s rxr%d.tail %d", na->name, reg_idx, i);
	writel(n, rxr->tail);
	return 1;	// success
}

static int
igb_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = NETMAP_BUF_SIZE(na);

	return 0;
}


static void
igb_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.na_flags = NAF_MOREFRAG | NAF_OFFSETS;
	na.num_tx_desc = adapter->tx_ring_count;
	na.num_rx_desc = adapter->rx_ring_count;
	na.num_tx_rings = adapter->num_tx_queues;
	na.num_rx_rings = adapter->num_rx_queues;
	na.rx_buf_maxsize = 1500; /* will be overwritten by config */
	na.nm_register = igb_netmap_reg;
	na.nm_txsync = igb_netmap_txsync;
	na.nm_rxsync = igb_netmap_rxsync;
	na.nm_config = igb_netmap_config;
	na.nm_bufcfg = igb_netmap_bufcfg;
	netmap_attach(&na);
}

/* end of file */
