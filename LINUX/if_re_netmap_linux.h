/*
 * Copyright (C) 2011 Luigi Rizzo. All rights reserved.
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
 * $Id: if_re_netmap_linux.h 10679 2012-02-28 13:42:18Z luigi $
 *
 * netmap support for "r8169" (re) (UNTESTED)
 * For details on netmap support please see ixgbe_netmap.h
 * 1 tx ring, 1 rx ring, 1 lock, crcstrip ? reinit tx addr,
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>


static void rtl8169_wait_for_quiescence(struct ifnet *);
#define SOFTC_T	rtl8169_private


/*
 * Register/unregister, mostly the reinit task
 */
static int
re_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	int error = 0;
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter*)na;

	if (na == NULL)
		return EINVAL;
	rtnl_lock();
	rtl8169_wait_for_quiescence(ifp);
	rtl8169_close(ifp);

	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &hwna->nm_ndo;

		if (rtl8169_open(ifp) < 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
fail:
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		ifp->netdev_ops = (void *)na->if_transmit;
		error = rtl8169_open(ifp) ? EINVAL : 0;
	}
	rtnl_unlock();
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
re_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = netdev_priv(ifp);
	void __iomem *ioaddr = sc->mmio_addr;
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n = 0, lim = kring->nkr_num_slots - 1;
	int new_slots;

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 */
	j = kring->nr_hwcur;
	new_slots = k - j - kring->nr_hwreserved;
	if (new_slots < 0)
		new_slots += kring->nkr_num_slots;
	if (new_slots > kring->nr_hwavail) {
		RD(5, "=== j %d k %d d %d hwavail %d hwreserved %d",
			j, k, new_slots, kring->nr_hwavail, kring->nr_hwreserved);
		return netmap_ring_reinit(kring);
	}
	if (!netif_carrier_ok(ifp)) {
		/* All the new slots are now unavailable. */
		kring->nr_hwavail -= new_slots;
		goto out;
	}
	if (j != k) {	/* we have new packets to send */
		l = sc->cur_tx; // XXX use internal macro ?
		for (n = 0; j != k; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[j];
			/* curr is the current slot in the nic ring */
			struct TxDesc *curr = &sc->TxDescArray[l];
			uint32_t flags = slot->len | LastFrag | DescOwn | FirstFrag ;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				sc->cur_tx = l; // XXX fix
				return netmap_ring_reinit(kring);
			}

			if (l == lim)	/* mark end of ring */
				flags |= RingEnd;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				curr->addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			slot->flags &= ~NS_REPORT;
			curr->opts1 = htole32(flags);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		kring->nr_hwavail -= new_slots
;
		sc->cur_tx = l;
		wmb(); /* synchronize writes to the NIC ring */
		RTL_W8(TxPoll, NPQ);	/* start ? */
	}

	if (n == 0 || kring->nr_hwavail < 1) {
		/* record completed transmissions */
		for (n = 0, l = sc->dirty_tx; l != sc->cur_tx; n++) {
			if (le32toh(sc->TxDescArray[l].opts1) & DescOwn)
				break;
			if (++l == NUM_TX_DESC)
				l = 0;
		}
		if (n > 0) {
			sc->dirty_tx = l;
			kring->nr_hwavail += n;
		}
	}
out:
	/* recompute hwreserved */
	kring->nr_hwreserved = k - j;
	if (kring->nr_hwreserved < 0) {
		kring->nr_hwreserved += kring->nkr_num_slots;
	}

	/* update avail and reserved to what the kernel knows */
	ring->avail = kring->nr_hwavail;
	ring->reserved = kring->nr_hwreserved;

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
re_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = netdev_priv(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * The device uses all the buffers in the ring, so we need
	 * another termination condition in addition to DescOwn
	 * cleared (all buffers could have it cleared. The easiest one
	 * is to limit the amount of data reported up to 'lim'
	 */
	l = sc->cur_rx; /* next pkt to check */
	j = netmap_idx_n2k(kring, l);
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		for (n = kring->nr_hwavail; n < lim ; n++) {
			struct RxDesc *cur_rx = &sc->RxDescArray[l];
			uint32_t rxstat = le32toh(cur_rx->opts1);
			uint32_t total_len;

			if ((rxstat & DescOwn) != 0)
				break;
			total_len = rxstat & 0x00001FFF;
			/* XXX subtract crc */
			total_len = (total_len < 4) ? 0 : total_len - 4;
			kring->ring->slot[j].len = total_len;
			kring->ring->slot[j].flags = slot_flags;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		if (n != kring->nr_hwavail) {
			sc->cur_rx = l;
			ifp->stats.rx_packets += n - kring->nr_hwavail;
			kring->nr_hwavail = n;
		}
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
			struct netmap_slot *slot = ring->slot + j;
			struct RxDesc *curr = &sc->RxDescArray[l];
			uint32_t flags = NETMAP_BUF_SIZE | DescOwn;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				return netmap_ring_reinit(kring);
			}

			if (l == lim)	/* mark end of ring */
				flags |= RingEnd;

			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				curr->addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->opts1 = htole32(flags);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		wmb(); // XXX needed ?
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
re_netmap_tx_init(struct SOFTC_T *sc)
{
	struct netmap_adapter *na = NA(sc->dev);
	struct netmap_slot *slot;
	struct TxDesc *desc = sc->TxDescArray;
	int i, l;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_TX, 0, 0);
	/* slot is NULL if we are not in netmap mode XXX cannot happen */
	if (!slot)
		return 0;

	/* l points in the netmap ring, i points in the NIC ring */
	for (i = 0; i < na->num_tx_desc; i++) {
		l = netmap_idx_n2k(&na->tx_rings[0], i);
		PNMB(slot + l, &paddr);
		desc[i].addr = htole64(paddr);
	}
	return 1;
}


static int
re_netmap_rx_init(struct SOFTC_T *sc)
{
	struct netmap_adapter *na = NA(sc->dev);
	struct netmap_slot *slot;
	struct RxDesc *desc = sc->RxDescArray;
	uint32_t cmdstat;
	int i, lim, l;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return 0;  /* XXX cannot happen */
	/*
	 * userspace knows that hwavail packets were ready before
	 * the reset, so only indexes < lim are made available for rx.
	 * XXX we use all slots, so no '-1' here
	 */
	lim = na->num_rx_desc /* - 1 */ - na->rx_rings[0].nr_hwavail;
	for (i = 0; i < na->num_rx_desc; i++) {
		l = netmap_idx_n2k(&na->rx_rings[0], i);
		PNMB(slot + l, &paddr);
		cmdstat = NETMAP_BUF_SIZE;
		if (i == na->num_rx_desc - 1)
			cmdstat |= RingEnd;
		if (i < lim)
			cmdstat |= DescOwn;
		desc[i].opts1 = htole32(cmdstat);
		desc[i].addr = htole64(paddr);
	}
	return 1;
}


static void
re_netmap_attach(struct SOFTC_T *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->dev;
	na.num_tx_desc = NUM_TX_DESC;
	na.num_rx_desc = NUM_RX_DESC;
	na.nm_txsync = re_netmap_txsync;
	na.nm_rxsync = re_netmap_rxsync;
	na.nm_register = re_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}
/* end of file */
