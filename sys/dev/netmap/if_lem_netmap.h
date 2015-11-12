/*
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
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
 * $FreeBSD: head/sys/dev/netmap/if_lem_netmap.h 271849 2014-09-19 03:51:26Z glebius $
 *
 * netmap support for: lem
 *
 * For details on netmap support please see ixgbe_netmap.h
 */


#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_virt.h>

extern int netmap_adaptive_io;

/*
 * Register/unregister. We are already under netmap lock.
 */
static int
lem_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;

	EM_CORE_LOCK(adapter);

	lem_disable_intr(adapter);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

#ifndef EM_LEGACY_IRQ // XXX do we need this ?
	taskqueue_block(adapter->tq);
	taskqueue_drain(adapter->tq, &adapter->rxtx_task);
	taskqueue_drain(adapter->tq, &adapter->link_task);
#endif /* !EM_LEGCY_IRQ */

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	lem_init_locked(adapter);	/* also enable intr */

#ifndef EM_LEGACY_IRQ
	taskqueue_unblock(adapter->tq); // XXX do we need this ?
#endif /* !EM_LEGCY_IRQ */

	EM_CORE_UNLOCK(adapter);

	return (ifp->if_drv_flags & IFF_DRV_RUNNING ? 0 : 1);
}

static void
lem_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;

	EM_CORE_LOCK(adapter);
	if (onoff) {
		lem_enable_intr(adapter);
	} else {
		lem_disable_intr(adapter);
	}
	EM_CORE_UNLOCK(adapter);
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
lem_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	/* generate an interrupt approximately every half ring */
	u_int report_frequency = kring->nkr_num_slots >> 1;

	/* device-specific */
	struct adapter *adapter = ifp->if_softc;
#ifdef NIC_PARAVIRT
	struct paravirt_csb *csb = adapter->csb;
	uint64_t *csbd = (uint64_t *)(csb + 1);
#endif /* NIC_PARAVIRT */

	bus_dmamap_sync(adapter->txdma.dma_tag, adapter->txdma.dma_map,
			BUS_DMASYNC_POSTREAD);

	/*
	 * First part: process new packets to send.
	 */

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
#ifdef NIC_PARAVIRT
		int do_kick = 0;
		uint64_t t = 0; // timestamp
		int n = head - nm_i;
		if (n < 0)
			n += lim + 1;
		if (csb) {
			t = rdtsc(); /* last timestamp */
			csbd[16] += t - csbd[0]; /* total Wg */
			csbd[17] += n;		/* Wg count */
			csbd[0] = t;
		}
#endif /* NIC_PARAVIRT */
		nic_i = netmap_idx_k2n(kring, nm_i);
		while (nm_i != head) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			/* device-specific */
			struct e1000_tx_desc *curr = &adapter->tx_desc_base[nic_i];
			struct em_buffer *txbuf = &adapter->tx_buffer_area[nic_i];
			int flags = (slot->flags & NS_REPORT ||
				nic_i == 0 || nic_i == report_frequency) ?
				E1000_TXD_CMD_RS : 0;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				curr->buffer_addr = htole64(paddr);
				netmap_reload_map(na, adapter->txtag, txbuf->map, addr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

			/* Fill the slot in the NIC ring. */
			curr->upper.data = 0;
			curr->lower.data = htole32(adapter->txd_cmd | len |
				(E1000_TXD_CMD_EOP | flags) );
			bus_dmamap_sync(adapter->txtag, txbuf->map,
				BUS_DMASYNC_PREWRITE);

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
			// XXX might try an early kick
		}
		kring->nr_hwcur = head;

		 /* synchronize the NIC ring */
		bus_dmamap_sync(adapter->txdma.dma_tag, adapter->txdma.dma_map,
			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

#ifdef NIC_PARAVIRT
		/* set unconditionally, then also kick if needed */
		if (csb) {
			t = rdtsc();
			if (csb->host_need_txkick == 2) {
				/* can compute an update of delta */
				int64_t delta = t - csbd[3];
				if (delta < 0)
					delta = -delta;
				if (csbd[8] == 0 || delta < csbd[8]) {
					csbd[8] = delta;
					csbd[9]++;
				}
				csbd[10]++;
			}
			csb->guest_tdt = nic_i;
			csbd[18] += t - csbd[0]; // total wp
			csbd[19] += n;
		}
		if (!csb || !csb->guest_csb_on || (csb->host_need_txkick & 1))
			do_kick = 1;
		if (do_kick)
#endif /* NIC_PARAVIRT */
		/* (re)start the tx unit up to slot nic_i (excluded) */
		E1000_WRITE_REG(&adapter->hw, E1000_TDT(0), nic_i);
#ifdef NIC_PARAVIRT
		if (do_kick) {
			uint64_t t1 = rdtsc();
			csbd[20] += t1 - t; // total Np
			csbd[21]++;
		}
#endif /* NIC_PARAVIRT */
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (ticks != kring->last_reclaim || flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		kring->last_reclaim = ticks;
		/* record completed transmissions using TDH */
#ifdef NIC_PARAVIRT
		/* host updates tdh unconditionally, and we have
		 * no side effects on reads, so we can read from there
		 * instead of exiting.
		 */
		if (csb) {
		    static int drain = 0, nodrain=0, good = 0, bad = 0, fail = 0;
		    u_int x = adapter->next_tx_to_clean;
		    csbd[19]++; // XXX count reclaims
		    nic_i = csb->host_tdh;
		    if (csb->guest_csb_on) {
			if (nic_i == x) {
			    bad++;
		    	    csbd[24]++; // failed reclaims
			    /* no progress, request kick and retry */
			    csb->guest_need_txkick = 1;
			    mb(); // XXX barrier
		    	    nic_i = csb->host_tdh;
			} else {
			    good++;
			}
			if (nic_i != x) {
			    csb->guest_need_txkick = 2;
			    if (nic_i == csb->guest_tdt)
				drain++;
			    else
				nodrain++;
#if 1
			if (netmap_adaptive_io) {
			    /* new mechanism: last half ring (or so)
			     * released one slot at a time.
			     * This effectively makes the system spin.
			     *
			     * Take next_to_clean + 1 as a reference.
			     * tdh must be ahead or equal
			     * On entry, the logical order is
			     *		x < tdh = nic_i
			     * We first push tdh up to avoid wraps.
			     * The limit is tdh-ll (half ring).
			     * if tdh-256 < x we report x;
			     * else we report tdh-256
			     */
			    u_int tdh = nic_i;
			    u_int ll = csbd[15];
			    u_int delta = lim/8;
			    if (netmap_adaptive_io == 2 || ll > delta)
				csbd[15] = ll = delta;
			    else if (netmap_adaptive_io == 1 && ll > 1) {
				csbd[15]--;
			    }

			    if (nic_i >= kring->nkr_num_slots) {
				RD(5, "bad nic_i %d on input", nic_i);
			    }
			    x = nm_next(x, lim);
			    if (tdh < x)
				tdh += lim + 1;
			    if (tdh <= x + ll) {
				nic_i = x;
				csbd[25]++; //report n + 1;
			    } else {
				tdh = nic_i;
				if (tdh < ll)
				    tdh += lim + 1;
				nic_i = tdh - ll;
				csbd[26]++; // report tdh - ll
			    }
			}
#endif
			} else {
			    /* we stop, count whether we are idle or not */
			    int bh_active = csb->host_need_txkick & 2 ? 4 : 0;
			    csbd[27+ csb->host_need_txkick]++;
			    if (netmap_adaptive_io == 1) {
				if (bh_active && csbd[15] > 1)
				    csbd[15]--;
				else if (!bh_active && csbd[15] < lim/2)
				    csbd[15]++;
			    }
			    bad--;
			    fail++;
			}
		    }
		    RD(1, "drain %d nodrain %d good %d retry %d fail %d",
			drain, nodrain, good, bad, fail);
		} else
#endif /* !NIC_PARAVIRT */
		nic_i = E1000_READ_REG(&adapter->hw, E1000_TDH(0));
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("TDH wrap %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		adapter->next_tx_to_clean = nic_i;
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
	}

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
lem_netmap_rxsync(struct netmap_kring *kring, int flags)
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
	struct adapter *adapter = ifp->if_softc;
#ifdef NIC_PARAVIRT
	struct paravirt_csb *csb = adapter->csb;
	uint32_t csb_mode = csb && csb->guest_csb_on;
	uint32_t do_host_rxkick = 0;
#endif /* NIC_PARAVIRT */

	if (head > lim)
		return netmap_ring_reinit(kring);

#ifdef NIC_PARAVIRT
	if (csb_mode) {
		force_update = 1;
		csb->guest_need_rxkick = 0;
	}
#endif /* NIC_PARAVIRT */
	/* XXX check sync modes */
	bus_dmamap_sync(adapter->rxdma.dma_tag, adapter->rxdma.dma_map,
			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		nic_i = adapter->next_rx_desc_to_check;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			struct e1000_rx_desc *curr = &adapter->rx_desc_base[nic_i];
			uint32_t staterr = le32toh(curr->status);
			int len;

#ifdef NIC_PARAVIRT
			if (csb_mode) {
			    if ((staterr & E1000_RXD_STAT_DD) == 0) {
				/* don't bother to retry if more than 1 pkt */
				if (n > 1)
				    break;
				csb->guest_need_rxkick = 1;
				wmb();
				staterr = le32toh(curr->status);
				if ((staterr & E1000_RXD_STAT_DD) == 0) {
				    break;
				} else { /* we are good */
				   csb->guest_need_rxkick = 0;
				}
			    }
			} else
#endif /* NIC_PARAVIRT */
			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			len = le16toh(curr->length) - 4; // CRC
			if (len < 0) {
				RD(5, "bogus pkt (%d) size %d nic idx %d", n, len, nic_i);
				len = 0;
			}
			ring->slot[nm_i].len = len;
			ring->slot[nm_i].flags = slot_flags;
			bus_dmamap_sync(adapter->rxtag,
				adapter->rx_buffer_area[nic_i].map,
				BUS_DMASYNC_POSTREAD);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
#ifdef NIC_PARAVIRT
			if (csb_mode) {
			    if (n > 1) {
				/* leave one spare buffer so we avoid rxkicks */
				nm_i = nm_prev(nm_i, lim);
				nic_i = nm_prev(nic_i, lim);
				n--;
			    } else {
				csb->guest_need_rxkick = 1;
			    }
			}
#endif /* NIC_PARAVIRT */
			ND("%d new packets at nic %d nm %d tail %d",
				n,
				adapter->next_rx_desc_to_check,
				netmap_idx_n2k(kring, adapter->next_rx_desc_to_check),
				kring->nr_hwtail);
			adapter->next_rx_desc_to_check = nic_i;
			// if_inc_counter(ifp, IFCOUNTER_IPACKETS, n);
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

			struct e1000_rx_desc *curr = &adapter->rx_desc_base[nic_i];
			struct em_buffer *rxbuf = &adapter->rx_buffer_area[nic_i];

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				curr->buffer_addr = htole64(paddr);
				netmap_reload_map(na, adapter->rxtag, rxbuf->map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->status = 0;
			bus_dmamap_sync(adapter->rxtag, rxbuf->map,
			    BUS_DMASYNC_PREREAD);
#ifdef NIC_PARAVIRT
			if (csb_mode && csb->host_rxkick_at == nic_i)
				do_host_rxkick = 1;
#endif /* NIC_PARAVIRT */
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		bus_dmamap_sync(adapter->rxdma.dma_tag, adapter->rxdma.dma_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
#ifdef NIC_PARAVIRT
		/* set unconditionally, then also kick if needed */
		if (csb)
			csb->guest_rdt = nic_i;
		if (!csb_mode || do_host_rxkick)
#endif /* NIC_PARAVIRT */
		E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), nic_i);
	}

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

#if defined (NIC_PTNETMAP) && defined (WITH_PTNETMAP_GUEST)
/*
 * ptnetmap support for: lem (FreeBSD version)
 *
 * For details on ptnetmap support please see if_vtnet_netmap.h
 */
static uint32_t lem_ptnetmap_ptctl(struct ifnet *, uint32_t);

/* Returns device configuration from the CSB */
static int
lem_ptnetmap_config(struct netmap_adapter *na,
		u_int *txr, u_int *txd, u_int *rxr, u_int *rxd)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	struct paravirt_csb *csb = adapter->csb;
	int ret;

	if (csb == NULL)
		return EINVAL;

	ret = lem_ptnetmap_ptctl(ifp, NET_PARAVIRT_PTCTL_CONFIG);
	if (ret)
		return ret;

	*txr = 1; //*txr = csb->num_tx_rings;
	*rxr = 1; //*rxr = csb->num_rx_rings;
	*txd = csb->num_tx_slots;
	*rxd = csb->num_rx_slots;

	D("txr %u rxr %u txd %u rxd %u",
			*txr, *rxr, *txd, *rxd);

	return 0;
}

/* Reconcile host and guest view of the transmit ring. */
static int
lem_ptnetmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	//u_int ring_nr = kring->ring_id;
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	int ret, notify = 0;

	ret = netmap_pt_guest_txsync(kring, flags, &notify);

	if (notify)
		E1000_WRITE_REG(&adapter->hw, E1000_TDT(0), 0);

	return ret;
}

/* Reconcile host and guest view of the receive ring. */
static int
lem_ptnetmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	//u_int ring_nr = kring->ring_id;
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	int ret, notify = 0;

	ret = netmap_pt_guest_rxsync(kring, flags, &notify);

	if (notify)
		E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), 0);

	return ret;
}

/* Register/unregister. We are already under netmap lock. */
static int
lem_ptnetmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	struct paravirt_csb *csb = adapter->csb;
	struct netmap_kring *kring;
	int ret;

	if (onoff) {
		ret = lem_ptnetmap_ptctl(ifp, NET_PARAVIRT_PTCTL_REGIF);
		if (ret)
			return ret;

		na->na_flags |= NAF_NETMAP_ON;
		adapter->ptnetmap_enabled = 1;
		/*
		 * Init ring and kring pointers
		 * After PARAVIRT_PTCTL_REGIF, the csb contains a snapshot of a
		 * host kring pointers.
		 * XXX This initialization is required, because we don't close
		 * the host port on UNREGIF.
		 */

		// Init rx ring
		kring = na->rx_rings;
		kring->rhead = kring->ring->head = csb->rx_ring.head;
		kring->rcur = kring->ring->cur = csb->rx_ring.cur;
		kring->nr_hwcur = csb->rx_ring.hwcur;
		kring->nr_hwtail = kring->rtail = kring->ring->tail =
			csb->rx_ring.hwtail;

		// Init tx ring
		kring = na->tx_rings;
		kring->rhead = kring->ring->head = csb->tx_ring.head;
		kring->rcur = kring->ring->cur = csb->tx_ring.cur;
		kring->nr_hwcur = csb->tx_ring.hwcur;
		kring->nr_hwtail = kring->rtail = kring->ring->tail =
			csb->tx_ring.hwtail;
	} else {
		na->na_flags &= ~NAF_NETMAP_ON;
		adapter->ptnetmap_enabled = 0;
		ret = lem_ptnetmap_ptctl(ifp, NET_PARAVIRT_PTCTL_UNREGIF);
	}

	return lem_netmap_reg(na, onoff);
}


static int
lem_ptnetmap_bdg_attach(const char *bdg_name, struct netmap_adapter *na)
{
	return EOPNOTSUPP;
}

/*
 * CSB (Communication Status Block) setup
 * CSB is already allocated in if_lem (paravirt).
 */
static void
lem_ptnetmap_setup_csb(struct adapter *adapter)
{
	struct ifnet *ifp = adapter->ifp;
	struct netmap_pt_guest_adapter* ptna =
		(struct netmap_pt_guest_adapter *)NA(ifp);

	ptna->csb = adapter->csb;
}

/* Send command to the host through PTCTL register. */
static uint32_t
lem_ptnetmap_ptctl(struct ifnet *ifp, uint32_t val)
{
	struct adapter *adapter = ifp->if_softc;
	uint32_t ret;

	E1000_WRITE_REG(&adapter->hw, E1000_PTCTL, val);
	ret = E1000_READ_REG(&adapter->hw, E1000_PTSTS);
	D("PTSTS = %u", ret);

	return ret;
}

/* Features negotiation with the host through PTFEAT */
static uint32_t
lem_ptnetmap_features(struct adapter *adapter)
{
	uint32_t features;
	/* tell the device the features we support */
	E1000_WRITE_REG(&adapter->hw, E1000_PTFEAT, NET_PTN_FEATURES_BASE);
	/* get back the acknowledged features */
	features = E1000_READ_REG(&adapter->hw, E1000_PTFEAT);
	device_printf(adapter->dev, "ptnetmap support: %s\n",
			(features & NET_PTN_FEATURES_BASE) ? "base" :
			"none");
	return features;
}

static struct netmap_pt_guest_ops lem_ptnetmap_ops = {
	.nm_ptctl = lem_ptnetmap_ptctl,
};
/* XXX: these warning affect the proper kernel compilation
#elif defined (NIC_PTNETMAP)
#warning "if_lem supports ptnetmap but netmap does not support it"
#warning "(configure netmap with ptnetmap support)"
#elif defined (WITH_PTNETMAP_GUEST)
#warning "netmap supports ptnetmap but e1000 does not support it"
#warning "(configure if_lem with ptnetmap support)"
*/
#endif /* NIC_PTNETMAP && WITH_PTNETMAP_GUEST */

static void
lem_netmap_attach(struct adapter *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->ifp;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = adapter->num_tx_desc;
	na.num_rx_desc = adapter->num_rx_desc;
	na.nm_txsync = lem_netmap_txsync;
	na.nm_rxsync = lem_netmap_rxsync;
	na.nm_register = lem_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	na.nm_intr = lem_netmap_intr;
#if defined (NIC_PTNETMAP) && defined (WITH_PTNETMAP_GUEST)
        /* XXX: check if the device support ptnetmap (now we use PARA_SUBDEV) */
	if ((adapter->hw.subsystem_device_id == E1000_PARA_SUBDEV) &&
		(lem_ptnetmap_features(adapter) & NET_PTN_FEATURES_BASE)) {
		na.nm_config = lem_ptnetmap_config;
		na.nm_register = lem_ptnetmap_reg;
		na.nm_txsync = lem_ptnetmap_txsync;
		na.nm_rxsync = lem_ptnetmap_rxsync;
		na.nm_bdg_attach = lem_ptnetmap_bdg_attach; /* XXX */
		netmap_pt_guest_attach(&na, &lem_ptnetmap_ops);
		lem_ptnetmap_setup_csb(adapter);
	} else
#endif /* NIC_PTNETMAP && defined WITH_PTNETMAP_GUEST */
		netmap_attach(&na);
}

/* end of file */
