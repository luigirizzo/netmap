/*
 * Copyright (C) 2021 Savoir-faire Linux, Inc.
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
 * $Id: if_stmmac_netmap_linux.h 10679 2021-01-18 13:42:18E SFL $
 *
 * netmap support for: stmmac (re, linux version)
 * For details on netmap support please see ixgbe_netmap.h
 * 1 tx ring, 1 rx ring, 1 lock, crcstrip ? reinit tx addr,
 */

#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

static int stmmac_open(struct net_device *dev);
static int stmmac_release(struct net_device *dev);

#ifdef MODULENAME
#undef MODULENAME
#define MODULENAME "stmmac" NETMAP_LINUX_DRIVER_SUFFIX
#endif

/*
 * Register/unregister, mostly the reinit task
 */
static int stmmac_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	int error = 0;

	stmmac_release(ifp);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);

		if (stmmac_open(ifp) < 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
	fail:
		nm_clear_native_flags(na);
		error = stmmac_open(ifp) ? EINVAL : 0;
	}

	return (error);
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int stmmac_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i; /* index into the netmap ring */
	u_int nic_i; /* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct stmmac_priv *stmac_priv = netdev_priv(ifp);

	rmb();

	/*
	* First part: process new packets to send.
	*/
	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	nm_i = kring->nr_hwcur;
	/* we have new packets to send */
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);
			uint32_t etdes1 =
				(slot->len & ETDES1_BUFFER1_SIZE_MASK);
			uint32_t etdes0 = ETDES0_LAST_SEGMENT | ETDES0_OWN |
					  ETDES0_FIRST_SEGMENT;

			/* device-specific */
			struct dma_desc *pdam_desc = NULL;
			if (stmac_priv->extend_desc)
				pdam_desc =
					(struct dma_desc *)(stmac_priv->dma_etx +
							    nic_i);
			else
				pdam_desc = stmac_priv->dma_tx + nic_i;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (nic_i == lim) /* mark end of ring */
				etdes0 |= ETDES0_END_RING;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				pdam_desc->des2 = paddr;
			}

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			pdam_desc->des0 = etdes0;
			pdam_desc->des1 = etdes1;

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}

		kring->nr_hwcur = head;

		stmac_priv->cur_tx = nic_i;
		wmb(); /* synchronize writes to the NIC ring */
	}

	/*
	* Second part: reclaim buffers for completed transmissions.
	*/
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		for (n = 0, nic_i = stmac_priv->dirty_tx;
		     nic_i != stmac_priv->cur_tx; n++) {
			struct dma_desc *pdam_desc = NULL;
			if (stmac_priv->extend_desc)
				pdam_desc =
					(struct dma_desc *)(stmac_priv->dma_etx +
							    nic_i);
			else
				pdam_desc = stmac_priv->dma_tx + nic_i;

			/* check if DMA owned */
			if (pdam_desc->des0 & ETDES0_OWN)
				break;

			if (++nic_i == na->num_tx_desc)
				nic_i = 0;
		}

		if (n > 0) {
			stmac_priv->dirty_tx = nic_i;
			kring->nr_hwtail =
				nm_prev(netmap_idx_n2k(kring, nic_i), lim);
		}
	}
out:
	return 0;
}

/*
 * Reconcile kernel and user view of the receive ring.
 * static int stmmac_rx(struct stmmac_priv *priv, int limit)
 */
static int stmmac_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct stmmac_priv *stmac_priv = netdev_priv(ifp);
	struct netmap_ring *ring = kring->ring;
	unsigned int nm_i; /* index into the netmap ring */
	unsigned int entry; /* index into the NIC ring */
	unsigned int n;
	unsigned int const lim = kring->nkr_num_slots - 1;
	unsigned int const head = kring->rhead;

	int force_update =
		(flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();

	/*
	* First part: import newly received packets.
	*/
	if (netmap_no_pendintr || force_update) {
		uint32_t stop_i = nm_prev(kring->nr_hwcur, lim);
		int coe = stmac_priv->hw->rx_csum;
		uint32_t frame_len = 0x0;

		entry = stmac_priv->cur_rx; /* next pkt to check */
		nm_i = netmap_idx_n2k(kring, entry);

		while (nm_i != stop_i) {
			int status;
			struct dma_desc *pdam_desc;

			if (stmac_priv->extend_desc)
				pdam_desc =
					(struct dma_desc *)(stmac_priv->dma_erx +
							    entry);
			else
				pdam_desc = stmac_priv->dma_rx + entry;

			/* read the status of the incoming frame */
			status = stmac_priv->hw->desc->rx_status(
				&stmac_priv->dev->stats, &stmac_priv->xstats,
				pdam_desc);

			/* check if managed by the DMA otherwise go ahead */
			if (unlikely(status & dma_own))
				break;

			if ((stmac_priv->extend_desc) &&
			    (stmac_priv->hw->desc->rx_extended_status))
				stmac_priv->hw->desc->rx_extended_status(
					&stmac_priv->dev->stats,
					&stmac_priv->xstats,
					stmac_priv->dma_erx + entry);

			frame_len = stmac_priv->hw->desc->get_rx_frame_len(
				pdam_desc, coe);

			/* ACS is set; GMAC core strips PAD/FCS for IEEE 802.3
			 * Type frames (LLC/LLC-SNAP)
			 */
			if (unlikely(status != llc_snap))
				frame_len -= ETH_FCS_LEN;

			ring->slot[nm_i].len = frame_len;
			ring->slot[nm_i].flags = 0;

			nm_i = nm_next(nm_i, lim);
			entry = nm_next(entry, lim);
		}

		stmac_priv->cur_rx = entry;

		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	* Second part: skip past packets that userspace has released.
	*/
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		entry = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			uint32_t erdes1 = 0x0;

			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			struct dma_desc *pdam_desc;

			if (stmac_priv->extend_desc)
				pdam_desc =
					(struct dma_desc *)(stmac_priv->dma_erx +
							    entry);
			else
				pdam_desc = stmac_priv->dma_rx + entry;

			erdes1 = NETMAP_BUF_SIZE(na);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (entry == lim) /* mark end of ring */
				erdes1 |= ERDES1_END_RING;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				pdam_desc->des2 = paddr;
				slot->flags &= ~NS_BUF_CHANGED;
			}

			pdam_desc->des1 |= erdes1;

			nm_i = nm_next(nm_i, lim);
			entry = nm_next(entry, lim);
		}

		kring->nr_hwcur = head;
		wmb();
	}

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

/*
 * Make the Tx desc rings point to the netmap buffers.
 * static int init_dma_desc_rings(struct net_device *dev, gfp_t flags)
 */
static int stmmac_netmap_tx_init(struct stmmac_priv *stmac_priv)
{
	struct netmap_adapter *na = NA(stmac_priv->dev);
	struct netmap_slot *slot = NULL;
	int i, l;
	uint64_t paddr = 0x0;

	slot = netmap_reset(na, NR_TX, 0, 0);
	if (!slot)
		return 0;

	/* l points in the netmap ring, i points in the NIC ring */
	for (i = 0; i < na->num_tx_desc; i++) {
		uint32_t etdes0 = 0x0;
		struct dma_desc *pdam_desc = NULL;

		stmac_priv->tx_skbuff[i] = NULL;
		if (stmac_priv->extend_desc)
			pdam_desc = &((stmac_priv->dma_etx + i)->basic);

		else
			pdam_desc = stmac_priv->dma_tx + i;

		if (IS_ERR(pdam_desc))
			return 0;

		l = netmap_idx_n2k(na->tx_rings[0], i);
		PNMB(na, slot + l, &paddr);

		/* ETDES2 */
		pdam_desc->des2 = paddr;

		/* ETDES0 */
		if (i == na->num_tx_desc - 1)
			etdes0 |= ETDES0_END_RING;

		pdam_desc->des0 = etdes0;
	}

	return 1;
}

/*
 * Make the Rx desc rings point to the netmap buffers.
 * static int init_dma_desc_rings(struct net_device *dev, gfp_t flags)
 */
static int stmmac_netmap_rx_init(struct stmmac_priv *stmac_priv)
{
	struct netmap_adapter *na = NA(stmac_priv->dev);
	struct netmap_slot *slot = NULL;
	int i, lim, l;
	uint64_t paddr = 0x0;

	slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return 0;

	lim = na->num_rx_desc - nm_kr_rxspace(na->rx_rings[0]);
	for (i = 0; i < na->num_rx_desc; i++) {
		void *addr;
		uint32_t erdes1 = 0x0;
		struct dma_desc *pdam_desc = NULL;

		stmac_priv->rx_skbuff[i] = NULL;

		if (stmac_priv->extend_desc)
			pdam_desc = &((stmac_priv->dma_erx + i)->basic);
		else
			pdam_desc = stmac_priv->dma_rx + i;

		if (IS_ERR(pdam_desc))
			return 0;

		l = netmap_idx_n2k(na->rx_rings[0], i);
		addr = PNMB(na, slot + l, &paddr);

		/* NOTE:is not set: ERDES3 and erdes1 |= ((BUF_SIZE_8KiB - 1) << ERDES1_BUFFER2_SIZE_SHIFT) & ERDES1_BUFFER2_SIZE_MASK; */

		/* ERDES2 */
		pdam_desc->des2 = paddr;

		/* ERDES1 */
		erdes1 |=
			((NETMAP_BUF_SIZE(na) - 1) & ERDES1_BUFFER1_SIZE_MASK);

		/* operate in ring mode only, and set last ERDES accordingly*/
		if (i == na->num_rx_desc - 1) {
			erdes1 |= ERDES1_END_RING;
		}

		erdes1 |= ERDES1_DISABLE_IC;

		pdam_desc->des1 |= erdes1;

		/* ERDES0 */
		if (i < lim)
			pdam_desc->des0 |= RDES0_OWN;
	}

	return 1;
}

static int stmmac_netmap_bufcfg(struct netmap_kring *kring, uint64_t target)
{
	kring->hwbuf_len = BUF_SIZE_8KiB;
	kring->buf_align = 0; /* no alignment */

	return 0;
}

static int stmmac_netmap_config(struct netmap_adapter *na,
				struct nm_config_info *info)
{
	struct stmmac_priv *stmac_priv = netdev_priv(na->ifp);
	int ret = netmap_rings_config_get(na, info);

	if (ret)
		return ret;

	info->rx_buf_maxsize = stmac_priv->dma_buf_sz;

	return 0;
}

static void stmmac_netmap_attach(struct stmmac_priv *stmac_priv)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = stmac_priv->dev; /* struct net_device *dev; */
	na.pdev = &stmac_priv->device; /* struct device *device; */
	na.num_tx_desc = DMA_TX_SIZE;
	na.num_rx_desc = DMA_RX_SIZE;
	na.rx_buf_maxsize = BUF_SIZE_8KiB;
	na.num_tx_rings = na.num_rx_rings = 1;
	na.nm_txsync = stmmac_netmap_txsync;
	na.nm_rxsync = stmmac_netmap_rxsync;
	na.nm_register = stmmac_netmap_reg;
	na.nm_config = stmmac_netmap_config;
	na.nm_bufcfg = stmmac_netmap_bufcfg;
	netmap_attach(&na);
}

/* end of file */
