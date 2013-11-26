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
 * $Id: forcedeth_netmap.h 10670 2012-02-27 21:15:38Z luigi $
 *
 * netmap support for 'forcedeth' (nfe) driver
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


/*
 * support for netmap register/unregisted. We are already under core lock.
 * only called on the first register or the last unregister.
 * The "forcedeth" driver is poorly written, the reinit routine
 * is replicated multiple times and one way to achieve it is to
 * nv_change_mtu twice above ETH_DATA_LEN.
 */
static int
forcedeth_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter *)na;
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *np = netdev_priv(ifp);
	int error = 0;
	u8 __iomem *base = get_hwbase(ifp);

	if (na == NULL)
		return EINVAL;
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
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &hwna->nm_ndo;
	} else {
		/* restore if_transmit */
		ifp->netdev_ops = (void *)na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
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

	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
forcedeth_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *np = netdev_priv(ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n, lim = kring->nkr_num_slots - 1;
	struct ring_desc_ex *txr = np->tx_ring.ex;
	uint32_t lastpkt = (np->desc_ver == DESC_VER_1 ? NV_TX_LASTPACKET : NV_TX2_LASTPACKET);

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);


	/* Sync the TX descriptor list */
	rmb();
	/* XXX (move after tx) record completed transmissions */
	// l is the current pointer, k is the last pointer
	l =  np->get_tx.ex - txr;
	k = np->put_tx.ex - txr;
        for (n = 0; l != k; n++) {
		uint32_t cmdstat = le32toh(txr[l].flaglen);
		if (cmdstat & NV_TX2_VALID)
			break;
		if (++l == np->tx_ring_size)
			l = 0;
	}
	if (n > 0) {
		np->get_tx.ex = txr + l;
		kring->nr_hwavail += n;
	}

	/* now deal with new transmissions */
	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		l = np->put_tx.ex - txr; // NIC pointer
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			struct ring_desc_ex *put_tx = txr + l;
			int len = slot->len;
			int cmd = (len - 1) | NV_TX2_VALID | lastpkt;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				return netmap_ring_reinit(kring);
			}

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			slot->flags &= ~NS_REPORT;
			put_tx->bufhigh = htole32(dma_high(paddr));
			put_tx->buflow = htole32(dma_low(paddr));
			put_tx->flaglen = htole32(cmd);
			put_tx->txvlan = 0;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		np->put_tx.ex = txr + l;
		kring->nr_hwcur = k;
		/* decrease avail by number of sent packets */
		kring->nr_hwavail -= n;
		wmb();
		/* start ? */
		writel(NVREG_TXRXCTL_KICK|np->txrxctl_bits,
			get_hwbase(ifp) + NvRegTxRxControl);
	}
	/* update avail to what the hardware knows */
	ring->avail = kring->nr_hwavail;
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
forcedeth_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *np = netdev_priv(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n, lim = kring->nkr_num_slots - 1;
	struct ring_desc_ex *rxr = np->rx_ring.ex;
	u_int resvd, refill;	// refill position
	uint16_t slot_flags = kring->nkr_slot_flags;

	k = ring->cur;
	resvd = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	l = np->get_rx.ex - rxr; /* next pkt to check */
	/* put_rx is the refill position, one before nr_hwcur.
	 * This slot is not available
	 */
	refill = np->put_rx.ex - rxr; /* refill position */
	j = netmap_idx_n2k(kring, l);
	for (n = kring->nr_hwavail; l != refill ; n++) {
		uint32_t statlen = le32toh(rxr[l].flaglen);

		if (statlen & NV_RX2_AVAIL) /* still owned by the NIC */
			break;
		kring->ring->slot[j].len = statlen & LEN_MASK_V2; // XXX crc?
		kring->ring->slot[j].flags = slot_flags;
		j = (j == lim) ? 0 : j + 1;
		l = (l == lim) ? 0 : l + 1;
	}
	if (n != kring->nr_hwavail) { /* new received buffers */
		np->get_rx.ex = rxr + l;
		ifp->stats.rx_packets += n - kring->nr_hwavail;
		kring->nr_hwavail = n;
	}

	/* skip past packets that userspace has already processed, */
	j = kring->nr_hwcur; // refill is one before j
	if (resvd > 0) {
		if (resvd + ring->avail >= lim) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}
	if (j != k) {	/* userspace has returned some packets. */
		l = netmap_idx_k2n(kring, j); /* NIC ring index */
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = ring->slot + j;
			struct ring_desc_ex *desc = rxr + l;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				return netmap_ring_reinit(kring);
			}
			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			desc->flaglen = htole32(NETMAP_BUF_SIZE);
			desc->bufhigh = htole32(dma_high(paddr));
			desc->buflow = htole32(dma_low(paddr));
			// enable the previous buffer
			rxr[refill].flaglen |= htole32(NV_RX2_AVAIL);
			refill = (refill == lim) ? 0 : refill + 1;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		np->put_rx.ex = rxr + refill;
		/* Flush the RX DMA ring */
		wmb();
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;
	return 0;
}


/*
 * Additional routines to init the tx and rx rings.
 * In other drivers we do that inline in the main code.
 */
static int
forcedeth_netmap_tx_init(struct SOFTC_T *np)
{
	struct ring_desc_ex *desc;
	int i, n;
	struct netmap_adapter *na = NA(np->dev);
	struct netmap_slot *slot;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_TX, 0, 0);
	/* slot is NULL if we are not in netmap mode */
	if (!slot)
		return 0;
	/* in netmap mode, overwrite addresses and maps */
	//txd = np->rl_ldata.rl_tx_desc;
	desc = np->tx_ring.ex;
	n = np->tx_ring_size;

	/* l points in the netmap ring, i points in the NIC ring */
	for (i = 0; i < n; i++) {
		int l = netmap_idx_n2k(&na->tx_rings[0], i);
		uint64_t paddr;
		PNMB(slot + l, &paddr);
		desc[i].flaglen = 0;
		desc[i].bufhigh = htole32(dma_high(paddr));
		desc[i].buflow = htole32(dma_low(paddr));
	}
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
	 * userspace knows that hwavail packets were ready before the
	 * reset, so we need to tell the NIC that last hwavail
	 * descriptors of the ring are still owned by the driver.
	 */
	lim = np->rx_ring_size - 1 - na->rx_rings[0].nr_hwavail;
	for (i = 0; i < np->rx_ring_size; i++) {
		uint64_t paddr;
		int l = netmap_idx_n2k(&na->rx_rings[0], i);
		PNMB(slot + l, &paddr);
		netmap_reload_map(np->rl_ldata.rl_rx_mtag,
		    np->rl_ldata.rl_rx_desc[i].rx_dmamap, addr);
		desc[i].bufhigh = htole32(dma_high(paddr));
		desc[i].buflow = htole32(dma_low(paddr));
		cmdstat = NETMAP_BUF_SIZE;
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
	na.num_tx_desc = np->tx_ring_size;
	na.num_rx_desc = np->tx_ring_size;
	na.nm_txsync = forcedeth_netmap_txsync;
	na.nm_rxsync = forcedeth_netmap_rxsync;
	na.nm_register = forcedeth_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

