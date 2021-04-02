
#ifndef _IF_VMXNET3_NETMAP_H_
#define _IF_VMXNET3_NETMAP_H_

#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T vmxnet3_adapter

static int vmxnet3_rq_create_all(struct vmxnet3_adapter *adapter);

static int
vmxnet3_netmap_reg(struct netmap_adapter *na, int onoff)
{
	int err = 0;

	struct ifnet *ifp       = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(VMXNET3_STATE_BIT_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev)) {
		vmxnet3_quiesce_dev(adapter);
		vmxnet3_reset_dev(adapter);

		vmxnet3_rq_destroy_all(adapter);
	}

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

	err = vmxnet3_rq_create_all(adapter);
	if (err)
		goto out;

	if (netif_running(adapter->netdev)) {
		err = vmxnet3_activate_dev(adapter);
		if (err)
			goto out;
	} else {
		vmxnet3_reset_dev(adapter);
	}

out:
	clear_bit(VMXNET3_STATE_BIT_RESETTING, &adapter->state);

	if (err) {
		vmxnet3_force_close(adapter);
	}

	return 0;
}

static u_int
vmxnet3_netmap_tq_tx_complete(struct vmxnet3_tx_queue *tq, struct pci_dev *pdev)
{
	u_int completed = 0;
	union Vmxnet3_GenericDesc *gdesc;

	gdesc = tq->comp_ring.base + tq->comp_ring.next2proc;

	while (VMXNET3_TCD_GET_GEN(&gdesc->tcd) == tq->comp_ring.gen) {
		vmxnet3_cmd_ring_adv_next2comp(&tq->tx_ring);
		vmxnet3_comp_ring_adv_next2proc(&tq->comp_ring);

		gdesc = tq->comp_ring.base + tq->comp_ring.next2proc;

		completed++;
	}

	return completed;
}

static int
vmxnet3_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp         = na->ifp;
	struct netmap_ring *ring  = kring->ring;

	u_int n;
	u_int nm_i; // index into the netmap ring
	u_int completed;
	u_int transmitted = 0;
	u_int ring_nr     = kring->ring_id;

	u_int const lim  = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	struct SOFTC_T *adapter     = netdev_priv(ifp);
	struct vmxnet3_tx_queue *tq = &adapter->tx_queue[ring_nr];

	if (!netif_carrier_ok(ifp))
		return 0;

	//
	// Free up the comp_descriptors aggressively
	//

	completed = vmxnet3_netmap_tq_tx_complete(tq, adapter->pdev);

	//
	// Reclaim buffers for completed transmissions
	//

	kring->nr_hwtail =
	        nm_prev(tq->comp_ring.next2proc, tq->comp_ring.size - 1);

	//
	// Process new packets to send
	//

	nm_i = kring->nr_hwcur;

	if (nm_i != head) {
		for (n = 0; nm_i != head; n++) {
			int free_cmd_desc_count;
			unsigned long lock_flags;

			struct netmap_slot *slot = ring->slot + nm_i;
			u_int packet_len         = slot->len;
			struct vmxnet3_tx_buf_info *tbi;
			union Vmxnet3_GenericDesc *gdesc;
			uint64_t paddr;

			PNMB(na, slot, &paddr);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			netmap_sync_map_dev(na, (bus_dma_tag_t)na->pdev, &paddr,
			                    packet_len, NR_TX);

			spin_lock_irqsave(&tq->tx_lock, lock_flags);

			tbi   = tq->buf_info + tq->tx_ring.next2fill;
			gdesc = tq->tx_ring.base + tq->tx_ring.next2fill;

			free_cmd_desc_count =
			        vmxnet3_cmd_ring_desc_avail(&tq->tx_ring);

			if (free_cmd_desc_count < 1) {
				tq->stats.tx_ring_full++;
				spin_unlock_irqrestore(&tq->tx_lock,
				                       lock_flags);
				break;
			}

			BUG_ON(packet_len > VMXNET3_MAX_TX_BUF_SIZE);
			BUG_ON(gdesc->txd.addr != tbi->dma_addr);
			BUG_ON(gdesc->txd.gen == tq->tx_ring.gen);

			/*	comments in other driver implementations
			 *indicate a size of 0 denotes a packet of
			 *VMXNET3_MAX_TX_BUF_SIZE bytes */
			tbi->len = packet_len == VMXNET3_MAX_TX_BUF_SIZE
			                   ? 0
			                   : packet_len;

			gdesc->dword[3] =
			        cpu_to_le32(VMXNET3_TXD_CQ | VMXNET3_TXD_EOP);

			dma_wmb();

			// set the packet length and flip the GEN bit
			gdesc->dword[2] = cpu_to_le32(
			        tq->tx_ring.gen << VMXNET3_TXD_GEN_SHIFT |
			        packet_len);

			vmxnet3_cmd_ring_adv_next2fill(&tq->tx_ring);

			transmitted++;
			spin_unlock_irqrestore(&tq->tx_lock, lock_flags);

			//
			// go to the next netmap slot
			//
			nm_i = nm_next(nm_i, lim);
		}

		kring->nr_hwcur = head;
	}

	//
	// Notify vSwitch that packets are available.

	if (transmitted >= tq->shared->txThreshold) {
		tq->shared->txThreshold = 0;
		VMXNET3_WRITE_BAR0_REG(
		        adapter,
		        (VMXNET3_REG_TXPROD + tq->qid * VMXNET3_REG_ALIGN),
		        tq->tx_ring.next2fill);
	}

	return 0;
}

static int
vmxnet3_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	static const u32 rxprod_reg[] = {VMXNET3_REG_RXPROD,
	                                 VMXNET3_REG_RXPROD2};

	u_int nm_i;
	u_int nic_i;

	struct netmap_adapter *na  = kring->na;
	struct ifnet *ifp          = na->ifp;
	struct netmap_ring *nmring = kring->ring;

	u_int ring_nr    = kring->ring_id;
	u_int const lim  = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update =
	        (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	struct Vmxnet3_RxCompDesc *rcd;
	struct SOFTC_T *adapter     = netdev_priv(ifp);
	struct vmxnet3_rx_queue *rq = &adapter->rx_queue[ring_nr];
	struct vmxnet3_cmd_ring *cmd_ring = rq->rx_ring;

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	//
	// First part: import newly received packets.
	//

	if (netmap_no_pendintr || force_update) {
		nm_i   = kring->nr_hwtail;
		nic_i  = netmap_idx_k2n(kring, nm_i);
		for (;;) {
			struct netmap_slot *slot;
			u_int rx_idx;
			uint64_t paddr;

			vmxnet3_getRxComp(
			        rcd,
			        &rq->comp_ring.base[rq->comp_ring.next2proc]
			                 .rcd,
			        &rxComp);

			if (rcd->gen != rq->comp_ring.gen)
				break;

			dma_rmb();

			// data ring has been disabled on device init
			BUG_ON(rcd->rqID != rq->qid && rcd->rqID != rq->qid2);

			/*	RX queues were configured to not fragment
			 *packets, so we expect both the SOP and EOP flags to be
			 *set in the RX completion desc
			 */
			BUG_ON(!(rcd->sop && rcd->eop));
			BUG_ON(rcd->len > NETMAP_BUF_SIZE(na));
			BUG_ON(VMXNET3_GET_RING_IDX(adapter, rcd->rqID) != 0);

			rx_idx   = rcd->rxdIdx;

			/* device may have skipped some rx descs */
			while (unlikely(nic_i != rx_idx)) {
				nm_prinf("%u skipped! rx_idx %u", nic_i, rx_idx);
				/* the nic has skipped some slots because who
				 * knows why. To shelter the application from
				 * this we would need to rotate the
				 * kernel-owned segments of the netmap and nic
				 * rings.  For now, we just set len=0 in the
				 * skipped slots and hope that this never
				 * happens.
				 */

				nmring->slot[nm_i].len = 0;
				nm_i = nm_next(nm_i, lim);
				nic_i = nm_next(nic_i, lim);
			}

			slot = nmring->slot + nm_i;
			PNMB(na, slot, &paddr);

			slot->len   = rcd->len;
			slot->flags = 0;
			netmap_sync_map_cpu(na, (bus_dma_tag_t)na->pdev, &paddr,
			                    slot->len, NR_RX);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);

			/* XXX can this ever happen with all offloads disabled?
			 */
			if (rcd->err) {
				rq->stats.drop_total++;
				rq->stats.drop_err++;

				if (!rcd->fcs)
					rq->stats.drop_fcs++;
			}

			vmxnet3_comp_ring_adv_next2proc(&rq->comp_ring);
		}

		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	//
	// Second part: skip past packets that userspace has released.
	//

	nm_i = kring->nr_hwcur;

	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		while (nm_i != head) {
			struct netmap_slot *slot = &nmring->slot[nm_i];
			struct Vmxnet3_RxDesc *rxd;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			if (slot->flags & NS_BUF_CHANGED) {

				if (addr == NETMAP_BUF_BASE(na)) // bad buf
					goto ring_reset;

				vmxnet3_getRxDesc(
					rxd,
					&cmd_ring->base[nic_i].rxd,
					&rxCmdDesc);

				rxd->addr = paddr;
				slot->flags &= ~NS_BUF_CHANGED;
				/* Ensure that the writes to rxd->gen bits will be
				 * observed after all other writes to rxd objects.
				 */
				dma_wmb();
			}
			netmap_sync_map_dev(na,
					(bus_dma_tag_t)na->pdev, &paddr,
					    NETMAP_BUF_SIZE(na), NR_RX);

			vmxnet3_getRxDesc(
				rxd,
				&cmd_ring->base[cmd_ring->next2fill].rxd,
				&rxCmdDesc);
			rxd->gen = cmd_ring->gen;
			vmxnet3_cmd_ring_adv_next2fill(cmd_ring);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		/* if needed, update the register */
		if (unlikely(rq->shared->updateRxProd)) {
			VMXNET3_WRITE_BAR0_REG(
				adapter,
				rxprod_reg[kring->ring_id] +
					rq->qid * VMXNET3_REG_ALIGN,
				cmd_ring->next2fill);
		}
	}

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

static void
vmxnet3_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp       = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	if (onoff)
		vmxnet3_enable_all_intrs(adapter);
	else
		vmxnet3_disable_all_intrs(adapter);
}

/* configure RX queue buffers to point to Netmap buffers */
static int
vmxnet3_netmap_rq_config_rx_buf(struct vmxnet3_rx_queue *rq,
                                struct SOFTC_T *adapter)
{
	struct ifnet *ifp         = adapter->netdev;
	struct netmap_adapter *na = NA(ifp);

	u_int i;
	u_int nm_i;
	u_int ring_idx;
	u_int ring_nr            = rq - adapter->rx_queue;
	struct netmap_slot *slot = netmap_reset(na, NR_RX, ring_nr, 0);

	if (!slot) {
		return 0; // not in native netmap mode
	}

	nm_i = 0;
	/* use only the 0th ring of each RX queue as it appears that the 1st
	   ring can only be used for packet fragments (VMXNET3_RXD_BTYPE_BODY),
	   which this driver doesn't support */
	for (ring_idx = 0; ring_idx < 1; ring_idx++) {
		struct vmxnet3_cmd_ring *cmd_ring = rq->rx_ring + ring_idx;

		for (i = 0; i < cmd_ring->size; i++) {
			struct vmxnet3_rx_buf_info *rbi =
			        rq->buf_info[ring_idx] + i;
			union Vmxnet3_GenericDesc *gd = cmd_ring->base + i;
			uint64_t paddr;
			u_int si = netmap_idx_n2k(na->rx_rings[ring_nr], nm_i);

			PNMB(na, slot + si, &paddr);

			rbi->buf_type = VMXNET3_RX_BUF_NONE;
			rbi->len      = NETMAP_BUF_SIZE(na);
			rbi->dma_addr = (dma_addr_t)paddr;

			gd->rxd.addr = cpu_to_le64(rbi->dma_addr);
			gd->dword[2] = cpu_to_le32(
			        (!cmd_ring->gen << VMXNET3_RXD_GEN_SHIFT) |
			        (VMXNET3_RXD_BTYPE_HEAD
			         << VMXNET3_RXD_BTYPE_SHIFT) |
			        rbi->len);
			nm_i++;

			if (i == cmd_ring->size - 1)
				break;

			gd->dword[2] = cpu_to_le32(
			        gd->dword[2] |
			        (cmd_ring->gen << VMXNET3_RXD_GEN_SHIFT));
			vmxnet3_cmd_ring_adv_next2fill(cmd_ring);
		}
	}

	return 1;
}

/* configure TX queue buffers to point to Netmap buffers */
static int
vmxnet3_netmap_tq_config_tx_buf(struct vmxnet3_tx_queue *tq,
                                struct SOFTC_T *adapter)
{
	struct ifnet *ifp         = adapter->netdev;
	struct netmap_adapter *na = NA(ifp);

	u_int i;
	u_int ring_nr                     = tq - adapter->tx_queue;
	struct vmxnet3_cmd_ring *cmd_ring = &tq->tx_ring;
	struct netmap_slot *slot          = netmap_reset(na, NR_TX, ring_nr, 0);

	if (!slot) {
		return 0; // not in native netmap mode
	}

	for (i = 0; i < cmd_ring->size; i++) {
		struct vmxnet3_tx_buf_info *tbi = tq->buf_info + i;
		union Vmxnet3_GenericDesc *gd   = cmd_ring->base + i;
		uint64_t paddr;
		u_int si = netmap_idx_n2k(na->tx_rings[ring_nr], i);

		PNMB(na, slot + si, &paddr);

		tbi->map_type = VMXNET3_MAP_NONE;
		/*	the buffer length will get overridden by the actual
		   packet length on transmit */
		tbi->len      = NETMAP_BUF_SIZE(na);
		tbi->dma_addr = (dma_addr_t)paddr;
		tbi->sop_idx  = i;

		gd->txd.addr = cpu_to_le64(tbi->dma_addr);
		gd->dword[2] = 0;
		gd->dword[3] = 0;
	}

	return 1;
}

static void
vmxnet3_netmap_set_rxdataring_enabled(struct SOFTC_T *adapter)
{
	struct ifnet *ifp         = adapter->netdev;
	struct netmap_adapter *na = NA(ifp);

	adapter->rxdataring_enabled =
	        nm_native_on(na) ? 0 : VMXNET3_VERSION_GE_3(adapter);
}

static void
vmxnet3_netmap_init_buffers(struct SOFTC_T *adapter)
{
	struct ifnet *ifp         = adapter->netdev;
	struct netmap_adapter *na = NA(ifp);

	u_int r;

	if (!nm_native_on(na))
		return;

	for (r = 0; r < na->num_rx_rings; r++) {
		(void)netmap_reset(na, NR_RX, r, 0);
	}

	for (r = 0; r < na->num_tx_rings; r++) {
		(void)netmap_reset(na, NR_TX, r, 0);
	}

	return;
}

static int
vmxnet3_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);
	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = NETMAP_BUF_SIZE(na);

	return 0;
}

static void
vmxnet3_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp          = adapter->netdev;
	na.pdev         = &adapter->pdev->dev;
	na.num_tx_desc  = adapter->tx_ring_size;
	na.num_rx_desc  = adapter->rx_ring_size;
	na.nm_register  = vmxnet3_netmap_reg;
	na.nm_txsync    = vmxnet3_netmap_txsync;
	na.nm_rxsync    = vmxnet3_netmap_rxsync;
	na.num_tx_rings = adapter->num_tx_queues;
	na.num_rx_rings = adapter->num_rx_queues;
	na.nm_intr      = vmxnet3_netmap_intr;
	na.nm_config    = vmxnet3_netmap_config;

	netmap_attach(&na);
}

static void
vmxnet3_netmap_detach(struct net_device *device)
{
	netmap_detach(device);
}

#endif // _IF_VMXNET3_NETMAP_H_
