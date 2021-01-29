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
 * $Id: forcedeth_netmap.h 10670 2012-02-27 21:15:38Z luigi $
 *
 * netmap support for: forcedeth (nfe, linux)
 * For details on netmap support see ixgbe_netmap.h

The driver supports ORIGinal and EXtended descriptors through unions.
We remove the .orig and .ex suffix for brevity.

Pointers in the ring (N slots) are
	first_rx = 0, last_rx = N-1, get_rx = put_rx = 0 at init
Following init there is a call to nv_alloc_rx_optimized() which does
	less_rx = get_rx - 1
	for (put_rx = 0; put_rx != less_rx; put_rx++)
		put_rx.flags = LEN | NV_RX2_AVAIL;
so it leaves one free slot and put_rx pointing at the end.
Basically, get_rx is where new packets arrive, put_rx is where
new buffers are added.

The rx_intr aka nv_rx_process_optimized() scans
	while (get_rx != put_rx && !(get_rx.flags & NV_RX2_AVAIL)) {
		...
		get_rx++
	}
followed by a nv_alloc_rx_optimized().
This makes sure that there is always a free slot.

 */

#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#define SOFTC_T	fe_priv

#ifdef DRV_NAME
#undef DRV_NAME
#define DRV_NAME "forcedeth" NETMAP_LINUX_DRIVER_SUFFIX
#endif


/*
 * Register/unregister. We are already under netmap lock.
 * only called on the first register or the last unregister.
 * The "forcedeth" driver is poorly written, the reinit routine
 * is replicated multiple times and one way to achieve it is to
 * nv_change_mtu twice above ETH_DATA_LEN.
 */
static int
forcedeth_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *np = netdev_priv(ifp);
	u8 __iomem *base = get_hwbase(ifp);

	// first half of nv_change_mtu() - down
	nv_disable_irq(ifp);
	nv_napi_disable(ifp);
	netif_tx_lock_bh(ifp);
	netif_addr_lock(ifp);
	spin_lock(&np->lock);
	/* stop engines */
	nv_stop_rxtx(ifp);
	nv_txrx_reset(ifp);
	/* drain rx queue */
	nv_drain_rxtx(ifp);

	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	// second half of nv_change_mtu() -- up
	if (nv_init_ring(ifp)) {
		if (!np->in_shutdown)
			mod_timer(&np->oom_kick, jiffies + OOM_REFILL);
	}
	/* reinit nic view of the rx queue */
	writel(np->rx_buf_sz, base + NvRegOffloadConfig);
	setup_hw_rings(ifp, NV_SETUP_RX_RING | NV_SETUP_TX_RING);
	writel(((np->rx_ring_size-1) << NVREG_RINGSZ_RXSHIFT) + ((np->tx_ring_size-1) << NVREG_RINGSZ_TXSHIFT),
	base + NvRegRingSizes);
	pci_push(base);
	writel(NVREG_TXRXCTL_KICK|np->txrxctl_bits, get_hwbase(ifp) + NvRegTxRxControl);
	pci_push(base);
	/* restart rx engine */
	nv_start_rxtx(ifp);
	spin_unlock(&np->lock);
	netif_addr_unlock(ifp);
	netif_tx_unlock_bh(ifp);
	nv_napi_enable(ifp);
	nv_enable_irq(ifp);

	return (0);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
forcedeth_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct SOFTC_T *np = netdev_priv(ifp);
	struct ring_desc_ex *txr = np->tx_ring.ex;
	uint32_t lastpkt = (np->desc_ver == DESC_VER_1 ? NV_TX_LASTPACKET : NV_TX2_LASTPACKET);
	u_int k;

	/*
	 * First part: process new packets to send.
	 */

	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = np->put_tx.ex - txr; // NIC pointer
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			/* device-specific */
			struct ring_desc_ex *put_tx = txr + nic_i;
			// XXX check who needs lastpkt
			int cmd = (len - 1) | NV_TX2_VALID | lastpkt;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

			/* Fill the slot in the NIC ring. */
			put_tx->bufhigh = htole32(dma_high(paddr));
			put_tx->buflow = htole32(dma_low(paddr));
			put_tx->flaglen = htole32(cmd);
			put_tx->txvlan = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		np->put_tx.ex = txr + nic_i;
		kring->nr_hwcur = head;
		wmb();	/* synchronize writes to the NIC ring */
		/* restart tx unit where is the new index ? */
		writel(NVREG_TXRXCTL_KICK|np->txrxctl_bits,
			get_hwbase(ifp) + NvRegTxRxControl);
	}

	/*
	 * Second part: reclaim buffers for completed transmissions
	 */
	/* Sync the TX descriptor list */
	rmb();
	nic_i =  np->get_tx.ex - txr;
	k = np->put_tx.ex - txr;
	if (nic_i != k) {
		for (n = 0; nic_i != k; n++) {
			uint32_t cmdstat = le32toh(txr[nic_i].flaglen);
			if (cmdstat & NV_TX2_VALID)
				break;
			if (++nic_i == np->tx_ring_size)
				nic_i = 0;
		}
		if (n > 0) {
			np->get_tx.ex = txr + nic_i;
			kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
		}
	}

out:

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
forcedeth_netmap_rxsync(struct netmap_kring *kring, int flags)
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
	struct SOFTC_T *np = netdev_priv(ifp);
	struct ring_desc_ex *rxr = np->rx_ring.ex;
	u_int refill;	// refill position

	if (head > lim)
		return netmap_ring_reinit(kring);

	/*
	 * First part: import newly received packets.
	 */
	rmb();
	if (netmap_no_pendintr || force_update) {
		nic_i = np->get_rx.ex - rxr; /* next pkt to check */
		/* put_rx is the refill position, one before nr_hwcur.
		 * This slot is not available
		 */
		refill = np->put_rx.ex - rxr; /* refill position */
		nm_i = netmap_idx_n2k(kring, nic_i);

		while (nic_i != refill) {
			uint32_t statlen = le32toh(rxr[nic_i].flaglen);

			if (statlen & NV_RX2_AVAIL) /* still owned by the NIC */
				break;
			ring->slot[nm_i].len = statlen & LEN_MASK_V2; // XXX crc?
			ring->slot[nm_i].flags = 0;
			// ifp->stats.rx_packets++;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		np->get_rx.ex = rxr + nic_i;
		kring->nr_hwtail = nm_i;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur; // refill is one before nic_i
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		refill = np->put_rx.ex - rxr; /* refill position */

		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			struct ring_desc_ex *desc = rxr + nic_i;

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}

			desc->flaglen = htole32(NETMAP_BUF_SIZE(na));
			desc->bufhigh = htole32(dma_high(paddr));
			desc->buflow = htole32(dma_low(paddr));
			// enable the previous buffer
			rxr[refill].flaglen |= htole32(NV_RX2_AVAIL);
			refill = nm_next(refill, lim);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		np->put_rx.ex = rxr + refill;
		/* Flush the RX DMA ring */
		wmb();
	}


	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/*
 * Additional routines to init the tx and rx rings.
 * In other drivers we do that inline in the main code.
 */
static int
forcedeth_netmap_tx_init(struct SOFTC_T *np)
{
	struct netmap_adapter *na = NA(np->dev);
	struct netmap_slot *slot;

	slot = netmap_reset(na, NR_TX, 0, 0);
	/* slot is NULL if we are not in native netmap mode */
	if (!slot)
		return 0;

	/* no need to pre-fill the tx rings, since txsync
	 * will always overwrite the tx slots
	 */

	return 1;
}


static int
forcedeth_netmap_rx_init(struct SOFTC_T *np)
{
	struct netmap_adapter *na = NA(np->dev);
	struct netmap_slot *slot = netmap_reset(na, NR_RX, 0, 0);
	struct ring_desc_ex *desc = np->rx_ring.ex;
	uint32_t cmdstat;
	int i, lim;

	if (!slot)
		return 0;
	/*
	 * Do not release the slots owned by userspace,
	 * and also keep one empty.
	 */
	lim = np->rx_ring_size - 1 - nm_kr_rxspace(na->rx_rings[0]);
	for (i = 0; i < lim; i++) {
		void *addr;
		uint64_t paddr;
		int l = netmap_idx_n2k(na->rx_rings[0], i);

		addr = PNMB(na, slot + l, &paddr);
		//netmap_reload_map(np->rl_ldata.rl_rx_mtag,
		//    np->rl_ldata.rl_rx_desc[i].rx_dmamap, addr);
		desc[i].bufhigh = htole32(dma_high(paddr));
		desc[i].buflow = htole32(dma_low(paddr));
		cmdstat = NETMAP_BUF_SIZE(na);
		if (i < lim)
			cmdstat |= NV_RX2_AVAIL;
		desc[i].flaglen = htole32(cmdstat);
	}
	// XXX ring end anywhere ?
	np->get_rx.ex = desc;
	np->put_rx.ex = desc + lim;
	return 1;
}


static void
forcedeth_netmap_attach(struct SOFTC_T *np)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = np->dev;
	na.pdev = &np->pci_dev->dev;
	na.num_tx_desc = np->tx_ring_size;
	na.num_rx_desc = np->tx_ring_size;
	na.nm_txsync = forcedeth_netmap_txsync;
	na.nm_rxsync = forcedeth_netmap_rxsync;
	na.nm_register = forcedeth_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
