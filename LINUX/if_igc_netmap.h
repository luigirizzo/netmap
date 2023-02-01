/*
 * netmap support for: igc (linux version)
 * For details on netmap support please see ixgbe_netmap.h
 */

#ifndef _IF_IGC_NETMAP_H_
#define _IF_IGC_NETMAP_H_

#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T	igc_adapter

#define igc_driver_name netmap_igc_driver_name
char netmap_igc_driver_name[] = "igc" NETMAP_LINUX_DRIVER_SUFFIX;

/*
 * Register/unregister. We are already under netmap lock.
 * Only called on the first register or the last unregister.
 */
static int
igc_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(__IGC_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev))
		igc_down(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

	if (netif_running(adapter->netdev))
		igc_up(adapter);
	else
		igc_reset(adapter); // XXX is it needed ?

	clear_bit(__IGC_RESETTING, &adapter->state);
	return (0);
}

static inline void NM_WRITE_SRRCTL(struct igc_adapter *adapter,
	struct igc_ring *rxr, u32 srrctl)
{
	struct igc_hw *hw = &adapter->hw;
	wr32(IGC_SRRCTL(rxr->reg_idx), srrctl);
}

static void
igc_netmap_configure_srrctl(struct igc_ring *rxr)
{
	struct ifnet *ifp = rxr->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct igc_adapter *adapter = netdev_priv(ifp);
	u32 srrctl;

	/* set descriptor configuration not using spilit header */
	srrctl = ALIGN(NETMAP_BUF_SIZE(na), 1024) >> IGC_SRRCTL_BSIZEPKT_SHIFT;
	srrctl |= IGC_SRRCTL_DESCTYPE_ADV_ONEBUF;
	// XXX: DROP_ENABLE neither defined or enabled in the main driver
	NM_WRITE_SRRCTL(adapter, rxr, srrctl);
}

static int
igc_netmap_configure_rx_ring(struct igc_ring *rxr)
{
	struct ifnet *ifp = rxr->netdev;
	struct netmap_adapter* na = NA(ifp);
	int reg_idx = rxr->reg_idx;
	struct netmap_slot* slot;
	struct netmap_kring *kring;
	u_int i, n;

	slot = netmap_reset(na, NR_RX, reg_idx, 0);
	if (!slot)
		return 0;       // not in native netmap mode

	igc_netmap_configure_srrctl(rxr);

	kring = na->rx_rings[reg_idx];

	/* preserve buffers already made available to clients */
	n = rxr->count - 1 - nm_kr_rxspace(na->rx_rings[reg_idx]);
	for (i = 0; i < rxr->count; i++) {
		union igc_adv_rx_desc *rx_desc;
		uint64_t paddr;
		int si = netmap_idx_n2k(kring, i);
		PNMB(na, slot + si, &paddr);
		rx_desc = IGC_RX_DESC(rxr, i);
		rx_desc->read.hdr_addr = 0;
		rx_desc->read.pkt_addr = htole64(paddr);
	}

	wmb();  /* Force memory writes to complete */
	nm_prdis("%s rxr%d.tail %d", na->name, reg_idx, i);
	writel(n, rxr->tail);

	return 1;      // success
}

static int
igc_netmap_configure_tx_ring(struct SOFTC_T *adapter, int ring_nr)
{
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct igc_ring *txr = adapter->tx_ring[ring_nr];
	int i, si;
	void *addr;
	uint64_t paddr;

	slot = netmap_reset(na, NR_TX, ring_nr, 0);
	if (!slot)
		return 0;  // not in netmap native mode

	for (i = 0; i < na->num_tx_desc; i++) {
		union igc_adv_tx_desc *tx_desc;
		si = netmap_idx_n2k(na->tx_rings[ring_nr], i);
		addr = PNMB(na, slot + si, &paddr);
		tx_desc = IGC_TX_DESC(txr, i);
		tx_desc->read.buffer_addr = htole64(paddr);
		/* actually we don't care to init the rings here */
	}

	return 1;       // success
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
igc_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;     /* index into the netmap ring */
	u_int nic_i;    /* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	/* generate an interrupt approximately every half ring */
	u_int report_frequency = kring->nkr_num_slots >> 1, report;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
		struct igc_ring* txr = adapter->tx_ring[ring_nr];

		if (!netif_carrier_ok(ifp) || !netif_device_present(ifp)) {
			goto out;
		}

		/*
		 * First part: process new packets to send.
		 */
		nm_i = kring->nr_hwcur;
		if (nm_i != head) {     /* we have new packets to send */
			unsigned int total_packets = 0, total_bytes = 0;
			nic_i = netmap_idx_k2n(kring, nm_i);
			for (n = 0; nm_i != head; n++) {
				struct netmap_slot *slot = &ring->slot[nm_i];
				u_int len = slot->len;
				uint64_t paddr;
				__le32 cmd_type = 0;
				uint32_t olinfo_status=0;
				void *addr = PNMB(na, slot, &paddr);

				/* device-specific */
				union igc_adv_tx_desc *curr =
					IGC_TX_DESC(txr, nic_i);
				int hw_flags = IGC_ADVTXD_DTYP_DATA | IGC_ADVTXD_DCMD_DEXT |
						IGC_ADVTXD_DCMD_IFCS;
				u_int totlen = len;

				NM_CHECK_ADDR_LEN(na, addr, len);

				report = slot->flags & NS_REPORT ||
					nic_i == 0 ||
					nic_i == report_frequency;
				total_packets++;
				total_bytes += len;

				if (slot->flags & NS_MOREFRAG) {
					/* There is some duplicated code here, but
					 * mixing everything up in the outer loop makes
					 * things less transparent, and it also adds
					 * unnecessary instructions in the fast path
					 */
					union igc_adv_tx_desc *first = curr;
					first->read.buffer_addr = htole64(paddr);
					first->read.cmd_type_len = htole32(len | hw_flags);
					netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
							&paddr, len, NR_TX);
					/* avoid setting the FCS flag in the
					 * descriptors after the first, for safety
					 */
					hw_flags &= ~IGC_ADVTXD_DCMD_IFCS;
					for (;;) {
						nm_i = nm_next(nm_i, lim);
						nic_i = nm_next(nic_i, lim);
						/* remember that we have to ask for a
						 * report each time we move past half a
						 * ring
						 */
						report |= nic_i == 0 ||
							nic_i == report_frequency;
						if (nm_i == head) {
							// XXX should we accept incomplete packets?
							return EINVAL;
						}
						slot = &ring->slot[nm_i];
						len = slot->len;
						addr = PNMB(na, slot, &paddr);
						NM_CHECK_ADDR_LEN(na, addr, len);
						curr = IGC_TX_DESC(txr, nic_i);
						totlen += len;
						total_packets++;
						total_bytes += len;
						if (!(slot->flags & NS_MOREFRAG))
							break;
						curr->read.buffer_addr = htole64(paddr);
						curr->read.olinfo_status = 0;
						curr->read.cmd_type_len = htole32(len | hw_flags);
						netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
								&paddr, len, NR_TX);
					}
					first->read.olinfo_status =
							htole32(totlen << IGC_ADVTXD_PAYLEN_SHIFT);
					totlen = 0;
				}
				/* curr now always points to the last descriptor of a packet
				 * (which is also the first for single-slot packets)
				 *
				 * EOP and RS must be set only in this descriptor.
				 */
				hw_flags |= IGC_ADVTXD_DCMD_EOP | (report ? IGC_ADVTXD_DCMD_RS : 0);
				slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);

				/* Fill the slot in the NIC ring. */
				curr->read.buffer_addr = htole64(paddr);
				curr->read.olinfo_status = htole32(olinfo_status | (totlen << IGC_ADVTXD_PAYLEN_SHIFT));
				curr->read.cmd_type_len = cmd_type | htole32(len | hw_flags);
				netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev, &paddr, len, NR_TX);
				nm_i = nm_next(nm_i, lim);
				nic_i = nm_next(nic_i, lim);
			}
		kring->nr_hwcur = head;

		wmb();  /* synchronize writes to the NIC ring */

		/* (re)start the tx unit up to slot nic_i (excluded) */
		writel(nic_i, txr->tail);
		wmb();
		txr->tx_stats.bytes += total_bytes;
		txr->tx_stats.packets += total_packets;
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		u_int tosync;
		struct igc_hw *hw = &adapter->hw;

		/* record completed transmissions using TDH */
		nic_i = rd32(IGC_TDH(txr->reg_idx));
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			nm_prdis("TDH wrap %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		nm_i = netmap_idx_n2k(kring, nic_i);
		tosync = nm_next(kring->nr_hwtail, lim);
		/* sync all buffers that we are returning to userspace */
		for ( ; tosync != nm_i; tosync = nm_next(tosync, lim)) {
			struct netmap_slot *slot = &ring->slot[tosync];
			uint64_t paddr;
			(void)PNMB(na, slot, &paddr);

			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
					&paddr, slot->len, NR_TX);
		}
		kring->nr_hwtail = nm_prev(nm_i, lim);
	}
out:
	return 0;
}

/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
igc_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;     /* index into the netmap ring */
	u_int nic_i;    /* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct igc_ring *rxr = adapter->rx_ring[ring_nr];

	if (!netif_carrier_ok(ifp) || !netif_device_present(ifp))
		return 0;

	if (head > lim) {
		nm_prlim(10, " rxsync lim %d head %d kring %p", lim, head, kring);
		return netmap_ring_reinit(kring);
	}

	rmb();
	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		unsigned int total_packets = 0, total_bytes = 0;
		u_int new_hwtail = (u_int)-1;
		nic_i = rxr->next_to_clean;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			union igc_adv_rx_desc *curr =
				IGC_RX_DESC(rxr, nic_i);
			uint32_t size = le16_to_cpu(curr->wb.upper.length);
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			int complete;

			if (!size)
				break;

			dma_rmb();

			PNMB(na, slot, &paddr);
			slot->len = size;
			complete = igc_test_staterr(curr, IGC_RXD_STAT_EOP);
			slot->flags = complete ? 0 : NS_MOREFRAG;
			total_packets++;
			total_bytes += slot->len;
			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev, &paddr, slot->len, NR_RX);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);

			if (complete)
				new_hwtail = nm_i;
		}

		if (n) { /* update the state variables */
			rxr->next_to_clean = nic_i;
			rxr->next_to_alloc = nic_i;
			if (new_hwtail != (u_int)-1)
				kring->nr_hwtail = nm_i;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
		rxr->rx_stats.bytes += total_bytes;
		rxr->rx_stats.packets += total_packets;
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
			union igc_adv_rx_desc *curr = IGC_RX_DESC(rxr, nic_i);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				slot->flags &= ~NS_BUF_CHANGED;
			}
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
				&paddr, NETMAP_BUF_SIZE(na), NR_RX);
			curr->read.pkt_addr = htole64(paddr);
			curr->read.hdr_addr = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		wmb();
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		writel(nic_i, rxr->tail);
	}

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

static int
igc_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = NETMAP_BUF_SIZE(na);

	return 0;
}

static void
igc_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.na_flags = NAF_MOREFRAG;
	na.num_tx_desc = adapter->tx_ring_count;
	na.num_rx_desc = adapter->rx_ring_count;
	na.num_tx_rings = adapter->num_tx_queues;
	na.num_rx_rings = adapter->num_rx_queues;
	na.rx_buf_maxsize = 1500; /* will be overwritten by config */
	na.nm_register = igc_netmap_reg;
	na.nm_txsync = igc_netmap_txsync;
	na.nm_rxsync = igc_netmap_rxsync;
	na.nm_config = igc_netmap_config;
	netmap_attach(&na);
}

#endif // _IF_IGC_NETMAP_H_
