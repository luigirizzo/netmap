/*
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
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
 * netmap support for nfe. XXX not yet tested.
 *
 * For more details on netmap support please see ixgbe_netmap.h
 */


#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
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
         * Userspace owned hwavail packets before the reset,
         * so the NIC that last hwavail descriptors of the ring
         * are still owned by the driver (and keep one empty).
         */
	n = NFE_RX_RING_COUNT;
        max_avail = n - 1 - na->rx_rings[0].nr_hwavail;
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

static void
nfe_netmap_lock_wrapper(struct ifnet *ifp, int what, u_int queueid)
{
	struct nfe_softc *sc = ifp->if_softc;

	switch (what) {
	case NETMAP_CORE_LOCK:
		NFE_LOCK(sc);
		break;
	case NETMAP_CORE_UNLOCK:
		NFE_UNLOCK(sc);
		break;
	}
}


/*
 * Register/unregister routine
 */
static int
nfe_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct nfe_softc *sc = ifp->if_softc;

	if (na == NULL)
		return EINVAL;	/* no netmap support here */

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	if (onoff) {
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;

		na->if_transmit = ifp->if_transmit;
		ifp->if_transmit = netmap_transmit;

		nfe_init_locked(sc);
	} else {
		/* return to non-netmap mode */
		ifp->if_transmit = na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		nfe_init_locked(sc);	/* also enable intr */
	}
	return (0);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
nfe_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct nfe_softc *sc = ifp->if_softc;
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n = 0, lim = kring->nkr_num_slots - 1;
	struct nfe_desc32 *desc32 = NULL;
	struct nfe_desc64 *desc64 = NULL;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	bus_dmamap_sync(sc->txq.tx_desc_tag, sc->txq.tx_desc_map,
			BUS_DMASYNC_POSTREAD);

	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 */
	j = kring->nr_hwcur;
	ND("hwcur %d cur %d", j, k);
	na->tx_rings[0].nr_kflags &= ~NKR_PENDINTR;
	if (j != k) {	/* we have new packets to send */

		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[j];
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			u_int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				return netmap_ring_reinit(kring);
			}
			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(sc->txq.tx_data_tag,
				    sc->txq.data[l].tx_data_map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
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
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		kring->nr_hwavail -= n;
		sc->txq.cur = l;

		bus_dmamap_sync(sc->txq.tx_desc_tag, sc->txq.tx_desc_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		NFE_WRITE(sc, NFE_RXTX_CTL, NFE_RXTX_KICKTX | sc->rxtxctl);
	}

	ND("send %d avail %d reclaim next %d cur %d", n, kring->nr_hwavail,
		sc->txq.next, sc->txq.cur);
	if (n == 0 || kring->nr_hwavail < 1) {
		l = sc->txq.next;
		k = sc->txq.cur;
		for (n = 0; l != k; n++, NFE_INC(l, NFE_TX_RING_COUNT)) {
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
		ND("reclaimed %d next %d cur %d", n,
			sc->txq.next, sc->txq.cur);
		if (n > 0) {
			sc->txq.next = l;
			kring->nr_hwavail += n;
		}
		ND("reclaimed %d next %d cur %d", n,
			sc->txq.next, sc->txq.cur);
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
nfe_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct nfe_softc *sc = ifp->if_softc;
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;
	struct nfe_desc32 *desc32;
	struct nfe_desc64 *desc64;

	if (k > lim)
		return netmap_ring_reinit(kring);


	/* XXX check sync modes */
	bus_dmamap_sync(sc->rxq.rx_desc_tag, sc->rxq.rx_desc_map,
			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring, l in the NIC ring.
	 */
	l = sc->rxq.cur;
	j = netmap_idx_n2k(kring, l);
	if (netmap_no_pendintr || force_update) {
		uint16_t flags, len;
		uint16_t slot_flags = kring->nkr_slot_flags;

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

			ring->slot[j].len = len;
			ring->slot[j].flags = slot_flags;
			bus_dmamap_sync(sc->rxq.rx_data_tag,
				sc->rxq.data[l].rx_data_map,
				BUS_DMASYNC_POSTREAD);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		if (n) { /* update the state variables */
			sc->rxq.cur = l;
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur;	/* netmap ring index */
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
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				return netmap_ring_reinit(kring);
			}

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(sc->rxq.rx_data_tag,
				    sc->rxq.data[l].rx_data_map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
				desc64 = &sc->rxq.desc64[l];
				desc64->physaddr[0] =
				    htole32(NFE_ADDR_HI(paddr));
				desc64->physaddr[1] =
				    htole32(NFE_ADDR_LO(paddr));
				desc64->length = htole16(NETMAP_BUF_SIZE);
				desc64->flags = htole16(NFE_RX_READY);
			} else {
				desc32 = &sc->rxq.desc32[l];
				desc32->physaddr =
				    htole32(NFE_ADDR_LO(paddr));
				desc32->length = htole16(NETMAP_BUF_SIZE);
				desc32->flags = htole16(NFE_RX_READY);
			}

			bus_dmamap_sync(sc->rxq.rx_data_tag,
			    sc->rxq.data[l].rx_data_map,
			    BUS_DMASYNC_PREREAD);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		bus_dmamap_sync(sc->rxq.rx_desc_tag, sc->rxq.rx_desc_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;
	return 0;
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
