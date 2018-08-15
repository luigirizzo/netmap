
#ifndef _IF_VMXNET3_NETMAP_H_
#define _IF_VMXNET3_NETMAP_H_

#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T vmxnet3_adapter

static int vmxnet3_rq_create_all(struct vmxnet3_adapter *adapter);
static void vmxnet3_unmap_tx_buf(struct vmxnet3_tx_buf_info *tbi,
				 struct pci_dev *pdev);

static int vmxnet3_netmap_reg(struct netmap_adapter *na, int onoff)
{
	int err = 0;

	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(VMXNET3_STATE_BIT_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev)) {
		vmxnet3_quiesce_dev(adapter);
		vmxnet3_reset_dev(adapter);

		vmxnet3_rq_destroy_all(adapter);

		err = vmxnet3_rq_create_all(adapter);
		if (err)
			goto out;
	}

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

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

static int vmxnet3_netmap_unmap_pkt(u32 eop_idx, struct vmxnet3_tx_queue *tq,
				    struct pci_dev *pdev)
{
	int entries = 0;

	//
	// no out of order completion
	//

	BUG_ON(tq->buf_info[eop_idx].sop_idx != tq->tx_ring.next2comp);
	BUG_ON(VMXNET3_TXDESC_GET_EOP(&(tq->tx_ring.base[eop_idx].txd)) != 1);

	BUG_ON(tq->buf_info[eop_idx].skb != NULL);

	VMXNET3_INC_RING_IDX_ONLY(eop_idx, tq->tx_ring.size);

	while (tq->tx_ring.next2comp != eop_idx) {
		vmxnet3_unmap_tx_buf(tq->buf_info + tq->tx_ring.next2comp,
				     pdev);

		//
		// update next2comp w/o tx_lock. Since we are marking more,
		// instead of less, tx ring entries avail, the worst case is
		// that the tx routine incorrectly re-queues a pkt due to
		// insufficient tx ring entries.
		//

		vmxnet3_cmd_ring_adv_next2comp(&tq->tx_ring);
		entries++;
	}

	return entries;
}

static int vmxnet3_netmap_tq_tx_complete(struct vmxnet3_tx_queue *tq,
					 struct pci_dev *pdev)
{
	int completed = 0;
	union Vmxnet3_GenericDesc *gdesc;

	gdesc = tq->comp_ring.base + tq->comp_ring.next2proc;

	while (VMXNET3_TCD_GET_GEN(&gdesc->tcd) == tq->comp_ring.gen) {
		completed += vmxnet3_netmap_unmap_pkt(
			VMXNET3_TCD_GET_TXIDX(&gdesc->tcd), tq, pdev);

		vmxnet3_comp_ring_adv_next2proc(&tq->comp_ring);
		gdesc = tq->comp_ring.base + tq->comp_ring.next2proc;
	}

	return completed;
}

static int vmxnet3_netmap_txsync(struct netmap_kring *kring, int flags)
{
#define kUseTwoTxDescForPacket 0
#define kMinFreeTxDescForPacket (kUseTwoTxDescForPacket ? 2 : 1)

	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;

	u_int n;
	u_int nm_i; // index into the netmap ring
	int completed;
	u_int deferred = 0;
	u_int ring_nr = kring->ring_id;

	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	union Vmxnet3_GenericDesc *gdesc;
	struct SOFTC_T *adapter = netdev_priv(ifp);
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
			u32 copy_size = 0;
			int free_cmd_desc_count;
			unsigned long lock_flags;

			union Vmxnet3_GenericDesc *sop_txd;
			union Vmxnet3_GenericDesc *eop_txd;

			struct netmap_slot *slot = &ring->slot[nm_i];

			dma_addr_t dma_addr;
			u_int packet_len = slot->len;
			void *packet_addr = PNMB(na, slot, &dma_addr);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			netmap_sync_map_dev(na, (bus_dma_tag_t)na->pdev, &dma_addr,
					packet_len, NR_TX);

			spin_lock_irqsave(&tq->tx_lock, lock_flags);

			free_cmd_desc_count =
				vmxnet3_cmd_ring_desc_avail(&tq->tx_ring);

			if (free_cmd_desc_count < kMinFreeTxDescForPacket) {
				tq->stats.tx_ring_full++;
				spin_unlock_irqrestore(&tq->tx_lock,
						       lock_flags);
				break;
			}

			//
			// Copy header
			//

			if (kUseTwoTxDescForPacket) {
				struct Vmxnet3_TxDataDesc *tdd = tdd =
					tq->data_ring.base +
					tq->tx_ring.next2fill;

				copy_size = min((u_int)VMXNET3_HDR_COPY_SIZE,
						packet_len);
				memcpy(tdd->data, packet_addr, copy_size);
			}

			//
			// Map rest of data
			//

			{
				u32 dw2;
				u32 len;
				u32 buf_offset;
				union Vmxnet3_GenericDesc *gdesc;
				struct vmxnet3_tx_buf_info *tbi = NULL;

				//
				// use the previous gen bit for the SOP desc
				//

				dw2 = (tq->tx_ring.gen ^ 0x1)
				      << VMXNET3_TXD_GEN_SHIFT;

				sop_txd = tq->tx_ring.base +
					  tq->tx_ring.next2fill;
				gdesc = sop_txd;

				//
				// Setup TX descriptor for the header
				//

				if (copy_size) {
					sop_txd->txd.addr = cpu_to_le64(
						tq->data_ring.basePA +
						tq->tx_ring.next2fill *
							sizeof(struct
							       Vmxnet3_TxDataDesc));
					sop_txd->dword[2] =
						cpu_to_le32(dw2 | copy_size);
					sop_txd->dword[3] = 0;

					tbi = tq->buf_info +
					      tq->tx_ring.next2fill;
					tbi->map_type = VMXNET3_MAP_NONE;

					vmxnet3_cmd_ring_adv_next2fill(
						&tq->tx_ring);

					//
					// use the right gen for non-SOP desc
					//

					dw2 = tq->tx_ring.gen
					      << VMXNET3_TXD_GEN_SHIFT;
				}

				//
				// Handle linear part
				//

				len = packet_len - copy_size;
				buf_offset = copy_size;

				if (len) {
					u32 buf_size;

					BUG_ON(len > VMXNET3_MAX_TX_BUF_SIZE);
					buf_size = len;
					dw2 |= len;

					tbi = tq->buf_info +
					      tq->tx_ring.next2fill;
					tbi->map_type = VMXNET3_MAP_NONE;
					tbi->dma_addr = dma_addr + buf_offset;
					tbi->len = buf_size;

					gdesc = tq->tx_ring.base +
						tq->tx_ring.next2fill;
					BUG_ON(gdesc->txd.gen ==
					       tq->tx_ring.gen);

					gdesc->txd.addr =
						cpu_to_le64(tbi->dma_addr);
					gdesc->dword[2] = cpu_to_le32(dw2);
					gdesc->dword[3] = 0;

					vmxnet3_cmd_ring_adv_next2fill(
						&tq->tx_ring);
					dw2 = tq->tx_ring.gen
					      << VMXNET3_TXD_GEN_SHIFT;
				}

				eop_txd = gdesc;

				tbi->skb = NULL;
				tbi->sop_idx = sop_txd - tq->tx_ring.base;
			}

			//
			// setup the EOP desc
			//

			eop_txd->dword[3] =
				cpu_to_le32(VMXNET3_TXD_CQ | VMXNET3_TXD_EOP);

			//
			// setup the SOP desc
			//

			gdesc = sop_txd;

			gdesc->txd.om = 0;
			gdesc->txd.msscof = 0;

			//
			// finally flips the GEN bit of the SOP desc
			//

			gdesc->dword[2] = cpu_to_le32(
				le32_to_cpu(gdesc->dword[2]) ^ VMXNET3_TXD_GEN);

			deferred++;

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
	//

	if (deferred >= 1) {
		VMXNET3_WRITE_BAR0_REG(adapter, (VMXNET3_REG_TXPROD +
						 tq->qid * VMXNET3_REG_ALIGN),
				       tq->tx_ring.next2fill);
	}

	return 0;
}

static int vmxnet3_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	static const u32 rxprod_reg[] = { VMXNET3_REG_RXPROD,
					  VMXNET3_REG_RXPROD2 };

	u32 num_pkts = 0;
	u32 netmap_offset = 0;
	u_int nm_i = 0; // index into the netmap ring

	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *nmring = kring->ring;

	u_int ring_nr = kring->ring_id;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update =
		(flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	struct Vmxnet3_RxCompDesc *rcd;
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct vmxnet3_rx_queue *rq = &adapter->rx_queue[ring_nr];

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	//
	// First part: import newly received packets.
	//

	if (netmap_no_pendintr || force_update) {
		uint32_t hwtail_lim = nm_prev(kring->nr_hwcur, lim);

		nm_i = kring->nr_hwtail;

		vmxnet3_getRxComp(
			rcd, &rq->comp_ring.base[rq->comp_ring.next2proc].rcd,
			&rxComp);

		while (rcd->gen == rq->comp_ring.gen && nm_i != hwtail_lim) {
			u32 idx;
			u32 ring_idx;
			int num_to_alloc;
			void *packet_addr;
			void *packet_nic_addr;
			struct netmap_slot *slot;
			struct Vmxnet3_RxDesc *rxd;
			struct vmxnet3_rx_buf_info *rbi;
			struct vmxnet3_cmd_ring *ring = NULL;

			slot = nmring->slot + nm_i;
			packet_addr = NMB(na, slot);

			BUG_ON(rcd->rqID != rq->qid && rcd->rqID != rq->qid2);
			idx = rcd->rxdIdx;
			ring_idx = rcd->rqID < adapter->num_rx_queues ? 0 : 1;
			ring = rq->rx_ring + ring_idx;
			vmxnet3_getRxDesc(rxd,
					  &rq->rx_ring[ring_idx].base[idx].rxd,
					  &rxCmdDesc);
			rbi = rq->buf_info[ring_idx] + idx;
			BUG_ON(rxd->addr != rbi->dma_addr ||
			       rxd->len != rbi->len);

			if (rcd->eop && rcd->err) {
				rq->stats.drop_total++;
				rq->stats.drop_err++;

				if (!rcd->fcs)
					rq->stats.drop_fcs++;

				goto rcd_done;
			}

			if (rcd->sop) {
				BUG_ON(rxd->btype != VMXNET3_RXD_BTYPE_HEAD ||
				       rcd->rqID != rq->qid);
				BUG_ON(rbi->buf_type != VMXNET3_RX_BUF_SKB);

				if (rcd->len == 0) {
					BUG_ON(!(rcd->sop && rcd->eop));
					goto rcd_done;
				}

				packet_nic_addr = rbi->skb->data;
				memcpy(packet_addr, packet_nic_addr, rcd->len);

				netmap_offset = rcd->len;
			} else {
				// non SOP buffer must be type 1 in most cases
				BUG_ON(rbi->buf_type != VMXNET3_RX_BUF_PAGE);
				BUG_ON(rxd->btype != VMXNET3_RXD_BTYPE_BODY);

				packet_nic_addr = page_address(rbi->page);
				memcpy(packet_addr + netmap_offset,
				       packet_nic_addr, rcd->len);

				netmap_offset += rcd->len;
			}

			if (rcd->eop) {
				dma_addr_t dma_addr;

				slot->len = netmap_offset;
				slot->flags = 0;

				PNMB(na, slot, &dma_addr);
				netmap_sync_map_cpu(na, (bus_dma_tag_t)na->pdev,
						&dma_addr, slot->len, NR_RX);

				num_pkts++;
				nm_i = nm_next(nm_i, lim);
			}

		rcd_done:
			ring->next2comp = idx;

			num_to_alloc = vmxnet3_cmd_ring_desc_avail(ring);
			ring = rq->rx_ring + ring_idx;

			while (num_to_alloc) {
				vmxnet3_getRxDesc(
					rxd, &ring->base[ring->next2fill].rxd,
					&rxCmdDesc);
				BUG_ON(!rxd->addr);

				// Recv desc is ready to be used by the device
				rxd->gen = ring->gen;
				vmxnet3_cmd_ring_adv_next2fill(ring);
				num_to_alloc--;
			}

			// if needed, update the register
			if (unlikely(rq->shared->updateRxProd)) {
				VMXNET3_WRITE_BAR0_REG(
					adapter,
					rxprod_reg[ring_idx] +
						rq->qid * VMXNET3_REG_ALIGN,
					ring->next2fill);
			}

			vmxnet3_comp_ring_adv_next2proc(&rq->comp_ring);
			vmxnet3_getRxComp(
				rcd,
				&rq->comp_ring.base[rq->comp_ring.next2proc]
					 .rcd,
				&rxComp);
		}

		if (num_pkts) {
			kring->nr_hwtail = nm_i;
		}

		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	//
	// Second part: skip past packets that userspace has released.
	//

	nm_i = kring->nr_hwcur;

	if (nm_i != head) {
		int n;

		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &nmring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			if (addr == NETMAP_BUF_BASE(na)) // bad buf
				goto ring_reset;

			slot->flags &= ~NS_BUF_CHANGED;

			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
					&paddr, NETMAP_BUF_SIZE(na), NR_RX);

			nm_i = nm_next(nm_i, lim);
		}
		kring->nr_hwcur = head;
	}

	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

static void vmxnet3_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	if (onoff)
		vmxnet3_enable_all_intrs(adapter);
	else
		vmxnet3_disable_all_intrs(adapter);
}

static void vmxnet3_netmap_init_buffers(struct SOFTC_T *adapter)
{
	u32 r;
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter *na = NA(ifp);

	if (!nm_native_on(na))
		return;

	for (r = 0; r < na->num_rx_rings; r++) {
		(void)netmap_reset(na, NR_RX, r, 0);
	}

	for (r = 0; r < na->num_tx_rings; r++) {
		(void)netmap_reset(na, NR_TX, r, 0);
	}
}

static void vmxnet3_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.num_tx_desc = adapter->tx_ring_size;
	na.num_rx_desc = adapter->rx_ring_size;
	na.nm_register = vmxnet3_netmap_reg;
	na.nm_txsync = vmxnet3_netmap_txsync;
	na.nm_rxsync = vmxnet3_netmap_rxsync;
	na.num_tx_rings = adapter->num_tx_queues;
	na.num_rx_rings = adapter->num_rx_queues;
	na.nm_intr = vmxnet3_netmap_intr;

	netmap_attach(&na);
}

static void vmxnet3_netmap_detach(struct net_device *device)
{
	netmap_detach(device);
}

#endif // _IF_VMXNET3_NETMAP_H_
