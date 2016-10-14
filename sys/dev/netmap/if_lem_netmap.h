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
#include <net/netmap_virt.h>

extern int netmap_adaptive_io;

#ifdef NIC_PARAVIRT
/* Support for virtio-like communication between host (H) and guest (G) NICs.

 This is for legacy e1000-paravirt, it does not support multi-ring.

 The guest allocates the shared Communication Status Block (csb) and
 write its physical address at CSBAL and CSBAH (data is little endian).
 csb->csb_on enables the mode. If disabled, the device acts a regular one.

 Notifications for tx and rx are exchanged without vm exits
 if possible. In particular (only mentioning csb mode below),
 the following actions are performed. In the description below,
 "double check" means verifying again the condition that caused
 the previous action, and reverting the action if the condition has
 changed. The condition typically depends on a variable set by the
 other party, and the double check is done to avoid races. E.g.

	// start with A=0
    again:
	// do something
	if ( cond(C) ) { // C is written by the other side
	    A = 1;
	    // barrier
	    if ( !cond(C) ) {
		A = 0;
		goto again;
	    }
	}

 TX: start from idle:
    H starts with host_need_txkick=1 when the I/O thread bh is idle. Upon new
    transmissions, G always updates guest_tdt.  If host_need_txkick == 1,
    G also writes to the TDT, which acts as a kick to H (so pending
    writes are always dispatched to H as soon as possible.)

 TX: active state:
    On the kick (TDT write) H sets host_need_txkick == 0 (if not
    done already by G), and starts an I/O thread trying to consume
    packets from TDH to guest_tdt, periodically refreshing host_tdh
    and TDH.  When host_tdh == guest_tdt, H sets host_need_txkick=1,
    and then does the "double check" for race avoidance.

 TX: G runs out of buffers
    XXX there are two mechanisms, one boolean (using guest_need_txkick)
    and one with a threshold (using guest_txkick_at). They are mutually
    exclusive.
    BOOLEAN: when G has no space, it sets guest_need_txkick=1 and does
        the double check. If H finds guest_need_txkick== 1 on a write
        to TDH, it also generates an interrupt.
    THRESHOLD: G sets guest_txkick_at to the TDH value for which it
	wants to receive an interrupt. When H detects that TDH moves
	across guest_txkick_at, it generates an interrupt.
	This second mechanism reduces the number of interrupts and
	TDT writes on the transmit side when the host is too slow.

 RX: start from idle
    G starts with guest_need_rxkick = 1 when the receive ring is empty.
    As packets arrive, H updates host_rdh (and RDH) and also generates an
    interrupt when guest_need_rxkick == 1 (so incoming packets are
    always reported to G as soon as possible, apart from interrupt
    moderation delays). It also tracks guest_rdt for new buffers.

 RX: active state
    As the interrupt arrives, G sets guest_need_rxkick = 0 and starts
    draining packets from the receive ring, while updating guest_rdt
    When G runs out of packets it sets guest_need_rxkick=1 and does the
    double check.

 RX: H runs out of buffers
    XXX there are two mechanisms, one boolean (using host_need_rxkick)
    and one with a threshold (using host_xxkick_at). They are mutually
    exclusive.
    BOOLEAN: when H has no space, it sets host_need_rxkick=1 and does the
	double check. If G finds host_need_rxkick==1 on updating guest_rdt,
        it also writes to RDT causing a kick to H.
    THRESHOLD: H sets host_rxkick_at to the RDT value for which it wants
	to receive a kick. When G detects that guest_rdt moves across
	host_rxkick_at, it writes to RDT thus generates a kick.
	This second mechanism reduces the number of kicks and
        RDT writes on the receive side when the guest is too slow and
	would free only a few buffers at a time.
 */
struct paravirt_csb {
    /*
     * Usage is described as follows:
     * 	[GH][RW][+-0]	guest/host reads/writes frequently/rarely/almost never
     */
    /* these are (mostly) written by the guest */
    uint32_t guest_tdt;            /* GW+ HR+ pkt to transmit */
    uint32_t guest_need_txkick;    /* GW- HR+ G ran out of tx bufs, request kick */
    uint32_t guest_need_rxkick;    /* GW- HR+ G ran out of rx pkts, request kick  */
    uint32_t guest_csb_on;         /* GW- HR+ enable paravirtual mode */
    uint32_t guest_rdt;            /* GW+ HR+ rx buffers available */
    uint32_t guest_txkick_at;      /* GW- HR+ tx ring pos. where G expects an intr */
    uint32_t guest_use_msix;        /* GW0 HR0 guest uses MSI-X interrupts. */
    uint32_t pad[9];

    /* these are (mostly) written by the host */
    uint32_t host_tdh;             /* GR0 HW- shadow register, mostly unused */
    uint32_t host_need_txkick;     /* GR+ HW- start the iothread */
    uint32_t host_txcycles_lim;    /* GW- HR- how much to spin before  sleep.
				    * set by the guest */
    uint32_t host_txcycles;        /* GR0 HW- counter, but no need to be exported */
    uint32_t host_rdh;             /* GR0 HW- shadow register, mostly unused */
    uint32_t host_need_rxkick;     /* GR+ HW- flush rx queued packets */
    uint32_t host_isr;             /* GR* HW* shadow copy of ISR */
    uint32_t host_rxkick_at;       /* GR+ HW- rx ring pos where H expects a kick */
    uint32_t vnet_ring_high;	/* Vnet ring physical address high. */
    uint32_t vnet_ring_low;	/* Vnet ring physical address low. */

    /* ptnetmap configuration fields */
    uint32_t nifp_offset;          /* offset of the netmap_if in the shared memory */
    /* uint16_t host_mem_id; */
    uint16_t num_tx_rings;         /* number of TX rings in the ptnetmap host port */
    uint16_t num_rx_rings;         /* number of RX rings in the ptnetmap host port */
    uint16_t num_tx_slots;         /* number of slots in the TX ring */
    uint16_t num_rx_slots;         /* number of slots in the RX ring */

    /* ptnetmap ring fields */
    struct ptnet_ring tx_ring;       /* TX ring fields shared between guest and host */
    struct ptnet_ring rx_ring;       /* RX ring fields shared between guest and host */
};

#endif  /* NIC_PARAVIRT */

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
	netmap_attach(&na);
}

/* end of file */
