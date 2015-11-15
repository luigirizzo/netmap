/*
 * Copyright (C) 2012-2014 Gaetano Catalli, Luigi Rizzo. All rights reserved.
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
 * $Id: if_e1000_netmap.h 10878 2012-04-12 22:28:48Z luigi $
 *
 * netmap support for: e1000 (linux version)
 * For details on netmap support please see ixgbe_netmap.h
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#include <netmap/netmap_virt.h>

#define SOFTC_T	e1000_adapter

#define e1000_driver_name netmap_e1000_driver_name
char netmap_e1000_driver_name[] = "e1000" NETMAP_LINUX_DRIVER_SUFFIX;

/*
 * Register/unregister. We are already under netmap lock.
 */
static int
e1000_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(__E1000_RESETTING, &adapter->flags))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev))
		e1000_down(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	if (netif_running(adapter->netdev))
		e1000_up(adapter);
	else
		e1000_reset(adapter);

	clear_bit(__E1000_RESETTING, &adapter->flags);
	return (0);
}

static void e1000_irq_enable(struct e1000_adapter *adapter);
static void e1000_irq_disable(struct e1000_adapter *adapter);
static void
e1000_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	if (onoff)
		e1000_irq_enable(adapter);
	else
		e1000_irq_disable(adapter);
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
e1000_netmap_txsync(struct netmap_kring *kring, int flags)
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
	u_int report_frequency = kring->nkr_num_slots >> 1;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_tx_ring* txr = &adapter->tx_ring[ring_nr];

	rmb();
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

			/* device-specific */
			struct e1000_tx_desc *curr = E1000_TX_DESC(*txr, nic_i);
			int flags = (slot->flags & NS_REPORT ||
				nic_i == 0 || nic_i == report_frequency) ?
				E1000_TXD_CMD_RS : 0;

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, paddr);
				curr->buffer_addr = htole64(paddr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

			/* Fill the slot in the NIC ring. */
			curr->upper.data = 0;
			curr->lower.data = htole32(adapter->txd_cmd |
				len | flags |
				E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */
		txr->next_to_use = nic_i; /* XXX what for ? */
		/* (re)start the tx unit up to slot nic_i (excluded) */
		writel(nic_i, adapter->hw.hw_addr + txr->tdt);
		mmiowb(); // XXX where do we need this ?
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		/* record completed transmissions using TDH */
		nic_i = readl(adapter->hw.hw_addr + txr->tdh);
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("TDH wrap %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		txr->next_to_clean = nic_i;
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);
	}
out:

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
e1000_netmap_rxsync(struct netmap_kring *kring, int flags)
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

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_rx_ring *rxr = &adapter->rx_ring[ring_nr];

	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		nic_i = rxr->next_to_clean;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, nic_i);
			uint32_t staterr = le32toh(curr->status);

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			ring->slot[nm_i].len = le16toh(curr->length) - 4;
			ring->slot[nm_i].flags = slot_flags;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = nic_i;
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
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, nic_i);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(...)
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->status = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		rxr->next_to_use = nic_i; // XXX not really used
		wmb();
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		writel(nic_i, adapter->hw.hw_addr + rxr->rdt);
	}
out:

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/* diagnostic routine to catch errors */
static void e1000_no_rx_alloc(struct SOFTC_T *adapter,
	  struct e1000_rx_ring *rxr, int cleaned_count)
{
	D("e1000->alloc_rx_buf should not be called");
}


/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int e1000_netmap_init_buffers(struct SOFTC_T *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct e1000_tx_ring* txr = &adapter->tx_ring[0];
	unsigned int i, r, si;
	uint64_t paddr;

	if (!nm_native_on(na))
		return 0;
	adapter->alloc_rx_buf = e1000_no_rx_alloc;
	for (r = 0; r < na->num_rx_rings; r++) {
		struct e1000_rx_ring *rxr;
		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("strange, null netmap ring %d", r);
			return 0;
		}
		rxr = &adapter->rx_ring[r];

		for (i = 0; i < rxr->count; i++) {
			si = netmap_idx_n2k(&na->rx_rings[r], i);
			PNMB(na, slot + si, &paddr);
			// netmap_load_map(...)
			E1000_RX_DESC(*rxr, i)->buffer_addr = htole64(paddr);
		}

		rxr->next_to_use = 0;
		/* preserve buffers already made available to clients */
		i = rxr->count - 1 - nm_kr_rxspace(&na->rx_rings[0]);
		if (i < 0) // XXX something wrong here, can it really happen ?
			i += rxr->count;
		D("i now is %d", i);
		wmb(); /* Force memory writes to complete */
		writel(i, hw->hw_addr + rxr->rdt);
	}
	/* now initialize the tx ring(s) */
	slot = netmap_reset(na, NR_TX, 0, 0);
	for (i = 0; i < na->num_tx_desc; i++) {
		si = netmap_idx_n2k(&na->tx_rings[0], i);
		PNMB(na, slot + si, &paddr);
		// netmap_load_map(...)
		E1000_TX_DESC(*txr, i)->buffer_addr = htole64(paddr);
	}
	return 1;
}

#if defined (CONFIG_E1000_NETMAP_PT) && defined (WITH_PTNETMAP_GUEST)
/*
 * ptnetmap support for: e1000 (linux version)
 *
 * For details on ptnetmap support please see virtio_netmap.h
 */
static uint32_t e1000_ptnetmap_ptctl(struct net_device *, uint32_t);

/* Returns device configuration from the CSB */
static int
e1000_ptnetmap_config(struct netmap_adapter *na,
		u_int *txr, u_int *txd, u_int *rxr, u_int *rxd)
{
	struct e1000_adapter *adapter = netdev_priv(na->ifp);
	struct paravirt_csb *csb = adapter->csb;
	int ret;

	if (csb == NULL)
		return EINVAL;

	ret = e1000_ptnetmap_ptctl(na->ifp, NET_PARAVIRT_PTCTL_CONFIG);
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
e1000_ptnetmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	//u_int ring_nr = kring->ring_id;
	struct ifnet *ifp = na->ifp;
	struct e1000_adapter *adapter = netdev_priv(ifp);
	struct e1000_tx_ring* txr = &adapter->tx_ring[0];
	int ret, notify = 0;

        IFRATE(adapter->rate_ctx.new.tx_sync++);

	ret = netmap_pt_guest_txsync(kring, flags, &notify);

	if (notify)
		writel(0, adapter->hw.hw_addr + txr->tdt);

	return ret;
}

/* Reconcile host and guest view of the receive ring. */
static int
e1000_ptnetmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	//u_int ring_nr = kring->ring_id;
	struct ifnet *ifp = na->ifp;
	struct e1000_adapter *adapter = netdev_priv(ifp);
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_rx_ring *rxr = &adapter->rx_ring[0];
	int ret, notify = 0;

        IFRATE(adapter->rate_ctx.new.rx_sync++);

	ret = netmap_pt_guest_rxsync(kring, flags, &notify);

	if (notify)
		writel(0, hw->hw_addr + rxr->rdt);

	return ret;
}

/* Register/unregister. We are already under netmap lock. */
static int
e1000_ptnetmap_reg(struct netmap_adapter *na, int onoff)
{
	struct e1000_adapter *adapter = netdev_priv(na->ifp);
	struct paravirt_csb *csb = adapter->csb;
	struct netmap_kring *kring;
	int ret = 0;

	if (onoff) {
		ret = e1000_ptnetmap_ptctl(na->ifp, NET_PARAVIRT_PTCTL_REGIF);
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
		ret = e1000_ptnetmap_ptctl(na->ifp, NET_PARAVIRT_PTCTL_UNREGIF);
	}

	return ret;
}

static int
e1000_ptnetmap_bdg_attach(const char *bdg_name, struct netmap_adapter *na)
{
	return EOPNOTSUPP;
}

/*
 * CSB (Communication Status Block) setup
 * CSB is already allocated in e1000 (paravirt).
 */
static void
e1000_ptnetmap_setup_csb(struct SOFTC_T *adapter)
{
	struct ifnet *ifp = adapter->netdev;
	struct netmap_pt_guest_adapter* ptna =
		(struct netmap_pt_guest_adapter *)NA(ifp);

	ptna->csb = adapter->csb;
}

/* Send command to the host through PTCTL register. */
static uint32_t
e1000_ptnetmap_ptctl(struct net_device *netdev, uint32_t val)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	uint32_t ret;

	ew32(PTCTL, val);
	ret = er32(PTSTS);
	D("PTSTS = %u", ret);

	return ret;
}

/* Features negotiation with the host through PTFEAT */
static uint32_t
e1000_ptnetmap_features(struct SOFTC_T *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	uint32_t features;
	/* tell the device the features we support */
	ew32(PTFEAT, NET_PTN_FEATURES_BASE); /* we are cheating for now */
	/* get back the acknowledged features */
	features = er32(PTFEAT);
	pr_info("%s ptnetmap support: %s\n", netdev->name,
			(features & NET_PTN_FEATURES_BASE) ? "base" :
			"none");
	return features;
}

static struct netmap_pt_guest_ops e1000_ptnetmap_ops = {
	.nm_ptctl = e1000_ptnetmap_ptctl,
};
#elif defined (CONFIG_E1000_NETMAP_PT)
#warning "e1000 supports ptnetmap but netmap does not support it"
#warning "(configure netmap with ptnetmap support)"
#elif defined (WITH_PTNETMAP_GUEST)
#warning "netmap supports ptnetmap but e1000 does not support it"
#warning "(configure e1000 with ptnetmap support)"
#endif /* CONFIG_E1000_NETMAP_PT && WITH_PTNETMAP_GUEST */

static void
e1000_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.num_tx_desc = adapter->tx_ring[0].count;
	na.num_rx_desc = adapter->rx_ring[0].count;
	na.nm_register = e1000_netmap_reg;
	na.nm_txsync = e1000_netmap_txsync;
	na.nm_rxsync = e1000_netmap_rxsync;
	na.num_tx_rings = na.num_rx_rings = 1;
	na.nm_intr = e1000_netmap_intr;

#if defined (CONFIG_E1000_NETMAP_PT) && defined (WITH_PTNETMAP_GUEST)
        /* XXX:check device ptnetmap support (now we use PARAVIRT_SUBDEV) */
	if (paravirtual &&
		(adapter->pdev->subsystem_device == E1000_PARAVIRT_SUBDEV) &&
	        (e1000_ptnetmap_features(adapter) & NET_PTN_FEATURES_BASE)) {
		na.nm_config = e1000_ptnetmap_config;
		na.nm_register = e1000_ptnetmap_reg;
		na.nm_txsync = e1000_ptnetmap_txsync;
		na.nm_rxsync = e1000_ptnetmap_rxsync;
		na.nm_bdg_attach = e1000_ptnetmap_bdg_attach; /* XXX */
		netmap_pt_guest_attach(&na, &e1000_ptnetmap_ops);
		e1000_ptnetmap_setup_csb(adapter);
	} else
#endif /* CONFIG_E1000_NETMAP_PT && WITH_PTNETMAP_GUEST */
	netmap_attach(&na);
}

/* end of file */
