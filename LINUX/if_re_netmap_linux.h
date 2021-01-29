/*
 * Copyright (C) 2011-2014 Luigi Rizzo. All rights reserved.
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
 * netmap support for: r8169 (re, linux version)
 * For details on netmap support please see ixgbe_netmap.h
 * 1 tx ring, 1 rx ring, 1 lock, crcstrip ? reinit tx addr,
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

static int NETMAP_LINUX_RTL_OPEN(struct ifnet *);
static int rtl8169_close(struct ifnet *);
#ifdef NETMAP_LINUX_HAVE_RTL_WFQ
static void rtl8169_wait_for_quiescence(struct ifnet *);
#define NETMAP_LINUX_RTL_WFQ(ifp) rtl8169_wait_for_quiescence(ifp)
#else
#define NETMAP_LINUX_RTL_WFQ(ifp) do { (void)(ifp); } while (0)
#endif
#define SOFTC_T	rtl8169_private

#ifdef MODULENAME
#undef MODULENAME
#define MODULENAME "r8169" NETMAP_LINUX_DRIVER_SUFFIX
#endif


/*
 * Register/unregister, mostly the reinit task
 */
static int
re_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	int error = 0;

	NETMAP_LINUX_RTL_WFQ(ifp);
	rtl8169_close(ifp);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);

		if (NETMAP_LINUX_RTL_OPEN(ifp) < 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
fail:
		nm_clear_native_flags(na);
		error = NETMAP_LINUX_RTL_OPEN(ifp) ? EINVAL : 0;
	}
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
re_netmap_txsync(struct netmap_kring *kring, int flags)
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
	struct SOFTC_T *sc = netdev_priv(ifp);
	void __iomem *ioaddr = sc->mmio_addr;

	rmb();

	/*
	 * First part: process new packets to send.
	 */
	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = sc->cur_tx; // XXX use internal macro ?
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			/* device-specific */
			struct TxDesc *curr = &sc->TxDescArray[nic_i];
			uint32_t flags = slot->len | LastFrag | DescOwn | FirstFrag ;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (nic_i == lim)	/* mark end of ring */
				flags |= RingEnd;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				curr->addr = htole64(paddr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			curr->opts1 = htole32(flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		sc->cur_tx = nic_i;
		wmb(); /* synchronize writes to the NIC ring */
		RTL_W8(TxPoll, NPQ);	/* start ? */
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		for (n = 0, nic_i = sc->dirty_tx; nic_i != sc->cur_tx; n++) {
			if (le32toh(sc->TxDescArray[nic_i].opts1) & DescOwn)
				break;
			if (++nic_i == NUM_TX_DESC)
				nic_i = 0;
		}
		if (n > 0) {
			sc->dirty_tx = nic_i;
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
re_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = netdev_priv(ifp);
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * First part: import newly received packets.
	 *
	 * NOTE: This device uses all the buffers in the ring, so we
	 * need another termination condition in addition to DescOwn
	 * cleared (all buffers could have it cleared. The easiest one
	 * is to stop right before nm_hwcur.
	 */
	if (netmap_no_pendintr || force_update) {
		uint32_t stop_i = nm_prev(kring->nr_hwcur, lim);

		nic_i = sc->cur_rx; /* next pkt to check */
		nm_i = netmap_idx_n2k(kring, nic_i);

		while (nm_i != stop_i) {
			struct RxDesc *cur_rx = &sc->RxDescArray[nic_i];
			uint32_t rxstat = le32toh(cur_rx->opts1);
			uint32_t total_len;

			if ((rxstat & DescOwn) != 0)
				break;
			total_len = rxstat & 0x00001FFF;
			/* XXX subtract crc */
			total_len = (total_len < 4) ? 0 : total_len - 4;
			ring->slot[nm_i].len = total_len;
			ring->slot[nm_i].flags = 0;
			// ifp->stats.rx_packets++;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		sc->cur_rx = nic_i;
		kring->nr_hwtail = nm_i;
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

			struct RxDesc *curr = &sc->RxDescArray[nic_i];
			uint32_t flags = NETMAP_BUF_SIZE(na) | DescOwn;

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (nic_i == lim)	/* mark end of ring */
				flags |= RingEnd;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				curr->addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->opts1 = htole32(flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		wmb(); // XXX needed ?
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
re_netmap_tx_init(struct SOFTC_T *sc)
{
	struct netmap_adapter *na = NA(sc->dev);
	struct netmap_slot *slot;
	struct TxDesc *desc = sc->TxDescArray;
	int i, l;
	uint64_t paddr;

	slot = netmap_reset(na, NR_TX, 0, 0);
	if (!slot)
		return 0;	// not in native netmap mode

	/* l points in the netmap ring, i points in the NIC ring */
	for (i = 0; i < na->num_tx_desc; i++) {
		l = netmap_idx_n2k(na->tx_rings[0], i);
		PNMB(na, slot + l, &paddr);
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

	slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return 0;  // not in native netmap mode
	/*
	 * Do not release the slots owned by userspace
	 * XXX we use all slots, so no '-1' here
	 * XXX do we need -1 instead ?
	 */
	lim = na->num_rx_desc /* - 1 */ - nm_kr_rxspace(&na->rx_rings[0]);
	for (i = 0; i < lim; i++) {
		l = netmap_idx_n2k(na->rx_rings[0], i);
		PNMB(na, slot + l, &paddr);
		cmdstat = NETMAP_BUF_SIZE(na);
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
	na.pdev = &sc->pci_dev->dev;
	na.num_tx_desc = NUM_TX_DESC;
	na.num_rx_desc = NUM_RX_DESC;
	na.nm_txsync = re_netmap_txsync;
	na.nm_rxsync = re_netmap_rxsync;
	na.nm_register = re_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
