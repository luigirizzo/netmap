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
 * $FreeBSD: head/sys/dev/netmap/if_em_netmap.h 231881 2012-02-17 14:09:04Z luigi $
 *
 * netmap support for: nfe XXX not yet tested.
 *
 * For more details on netmap support please see ixgbe_netmap.h
 */


#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/netmap/netmap_kern.h>


static int
nfe_netmap_init_buffers(struct nfe_softc *sc)
{
	struct netmap_adapter *na = NA(sc->nfe_ifp);
	struct netmap_slot *slot;
	int i, l, n, max_avail;
	struct nfe_desc32 *desc32 = NULL;
	struct nfe_desc64 *desc64 = NULL;
	void *addr;
	uint64_t paddr;

	if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
		return 0;
	}

	slot = netmap_reset(na, NR_TX, 0, 0);
	if (!slot)
		return 0; // XXX cannot happen
	// XXX init the tx ring
	n = NFE_TX_RING_COUNT;
	for (i = 0; i < n; i++) {
		l = netmap_idx_n2k(&na->tx_rings[0], i);
		addr = PNMB(slot + l, &paddr);
		netmap_reload_map(sc->txq.tx_data_tag,
		    sc->txq.data[l].tx_data_map, addr);
		slot[l].flags = 0;
		if (sc->nfe_flags & NFE_40BIT_ADDR) {
			desc64 = &sc->txq.desc64[l];
			desc64->physaddr[0] = htole32(NFE_ADDR_HI(paddr));
			desc64->physaddr[1] = htole32(NFE_ADDR_LO(paddr));
			desc64->vtag = 0;
			desc64->length = htole16(0);
			desc64->flags = htole16(0);
		} else {
			desc32 = &sc->txq.desc32[l];
			desc32->physaddr = htole32(NFE_ADDR_LO(paddr));
			desc32->length = htole16(0);
			desc32->flags = htole16(0);
		}
	}

	slot = netmap_reset(na, NR_RX, 0, 0);
	// XXX init the rx ring
	/*
	 * preserve buffers still owned by the driver (and keep one empty).
	 */
	n = NFE_RX_RING_COUNT;
	max_avail = n - 1 - nm_kr_rxspace(&na->rx_rings[0]);
	for (i = 0; i < n; i++) {
		uint16_t flags;
		l = netmap_idx_n2k(&na->rx_rings[0], i);
		addr = PNMB(slot + l, &paddr);
		flags = (i < max_avail) ? NFE_RX_READY : 0;
		if (sc->nfe_flags & NFE_40BIT_ADDR) {
			desc64 = &sc->rxq.desc64[l];
			desc64->physaddr[0] = htole32(NFE_ADDR_HI(paddr));
			desc64->physaddr[1] = htole32(NFE_ADDR_LO(paddr));
			desc64->vtag = 0;
			desc64->length = htole16(NETMAP_BUF_SIZE);
			desc64->flags = htole16(NFE_RX_READY);
		} else {
			desc32 = &sc->rxq.desc32[l];
			desc32->physaddr = htole32(NFE_ADDR_LO(paddr));
			desc32->length = htole16(NETMAP_BUF_SIZE);
			desc32->flags = htole16(NFE_RX_READY);
		}

		netmap_reload_map(sc->rxq.rx_data_tag,
		    sc->rxq.data[l].rx_data_map, addr);
		bus_dmamap_sync(sc->rxq.rx_data_tag,
		    sc->rxq.data[l].rx_data_map, BUS_DMASYNC_PREREAD);
	}

	return 1;
}


/*
 * Register/unregister. We are already under netmap lock.
 */
static int
nfe_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct nfe_softc *sc = ifp->if_softc;

	NFE_LOCK(sc);
	nfe_stop(ifp);	/* also clear IFF_DRV_RUNNING */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	nfe_init_locked(sc);	/* also enable intr */
	NFE_UNLOCK(sc);
	return (0);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
nfe_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	/* generate an interrupt approximately every half ring */
	u_int report_frequency = kring->nkr_num_slots >> 1;

	/* device-specific */
	struct nfe_softc *sc = ifp->if_softc;
	struct nfe_desc32 *desc32 = NULL;
	struct nfe_desc64 *desc64 = NULL;

	bus_dmamap_sync(sc->txq.tx_desc_tag, sc->txq.tx_desc_map,
			BUS_DMASYNC_POSTREAD);

	/*
	 * First part: process new packets to send.
	 */

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			NM_CHECK_ADDR_LEN(addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(sc->txq.tx_data_tag,
				    sc->txq.data[l].tx_data_map, addr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

			if (sc->nfe_flags & NFE_40BIT_ADDR) {
			    desc64 = &sc->txq.desc64[l];
			    desc64->physaddr[0] = htole32(NFE_ADDR_HI(paddr));
			    desc64->physaddr[1] = htole32(NFE_ADDR_LO(paddr));
			    desc64->vtag = 0;
			    desc64->length = htole16(len - 1);
			    desc64->flags =
				htole16(NFE_TX_VALID | NFE_TX_LASTFRAG_V2);
			} else {
			    desc32 = &sc->txq.desc32[l];
			    desc32->physaddr = htole32(NFE_ADDR_LO(paddr));
			    desc32->length = htole16(len - 1);
			    desc32->flags =
				htole16(NFE_TX_VALID | NFE_TX_LASTFRAG_V1);
			}

			bus_dmamap_sync(sc->txq.tx_data_tag,
			    sc->txq.data[l].tx_data_map, BUS_DMASYNC_PREWRITE);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		sc->txq.cur = nic_i;

		bus_dmamap_sync(sc->txq.tx_desc_tag, sc->txq.tx_desc_map,
			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		/* XXX something missing ? where is the last pkt marker ? */
		NFE_WRITE(sc, NFE_RXTX_CTL, NFE_RXTX_KICKTX | sc->rxtxctl);
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		u_int nic_cur = sc->txq.cur;
		nic_i = sc->txq.next;
		for (n = 0; nic_i != nic_cur; n++, NFE_INC(nic_i, NFE_TX_RING_COUNT)) {
			uint16_t flags;
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
				desc64 = &sc->txq.desc64[l];
				flags = le16toh(desc64->flags);
			} else {
				desc32 = &sc->txq.desc32[l];
				flags = le16toh(desc32->flags);
			}
			if (flags & NFE_TX_VALID)
				break;
		}
		if (n > 0) {
			sc->txq.next = nic_i;
			kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
		}
	}

	nm_txsync_finalize(kring);

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
nfe_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = nm_rxsync_prologue(kring);
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct nfe_softc *sc = ifp->if_softc;
	struct nfe_desc32 *desc32;
	struct nfe_desc64 *desc64;

	if (head > lim)
		return netmap_ring_reinit(kring);

	bus_dmamap_sync(sc->rxq.rx_desc_tag, sc->rxq.rx_desc_map,
			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t flags, len;
		uint16_t slot_flags = kring->nkr_slot_flags;

		nic_i = sc->rxq.cur;
		nm_i = netmap_idx_n2k(kring, nic_i);
		for (n = 0; ; n++) {
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
			    desc64 = &sc->rxq.desc64[sc->rxq.cur];
			    flags = le16toh(desc64->flags);
			    len = le16toh(desc64->length) & NFE_RX_LEN_MASK;
			} else {
			    desc32 = &sc->rxq.desc32[sc->rxq.cur];
			    flags = le16toh(desc32->flags);
			    len = le16toh(desc32->length) & NFE_RX_LEN_MASK;
			}

			if (flags & NFE_RX_READY)
				break;

			ring->slot[nm_i].len = len;
			ring->slot[nm_i].flags = slot_flags;
			bus_dmamap_sync(sc->rxq.rx_data_tag,
				sc->rxq.data[nic_i].rx_data_map,
				BUS_DMASYNC_POSTREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			sc->rxq.cur = nic_i;
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

			if (addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(sc->rxq.rx_data_tag,
				    sc->rxq.data[l].rx_data_map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
				desc64 = &sc->rxq.desc64[nic_i];
				desc64->physaddr[0] =
				    htole32(NFE_ADDR_HI(paddr));
				desc64->physaddr[1] =
				    htole32(NFE_ADDR_LO(paddr));
				desc64->length = htole16(NETMAP_BUF_SIZE);
				desc64->flags = htole16(NFE_RX_READY);
			} else {
				desc32 = &sc->rxq.desc32[nic_i];
				desc32->physaddr =
				    htole32(NFE_ADDR_LO(paddr));
				desc32->length = htole16(NETMAP_BUF_SIZE);
				desc32->flags = htole16(NFE_RX_READY);
			}

			bus_dmamap_sync(sc->rxq.rx_data_tag,
			    sc->rxq.data[nic_i].rx_data_map,
			    BUS_DMASYNC_PREREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		bus_dmamap_sync(sc->rxq.rx_desc_tag, sc->rxq.rx_desc_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}

	/* tell userspace that there might be new packets */
	nm_rxsync_finalize(kring);

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


static void
nfe_netmap_attach(struct nfe_softc *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->nfe_ifp;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = NFE_TX_RING_COUNT;
	na.num_rx_desc = NFE_RX_RING_COUNT;
	na.nm_txsync = nfe_netmap_txsync;
	na.nm_rxsync = nfe_netmap_rxsync;
	na.nm_register = nfe_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na, 1);
}

/* end of file */
