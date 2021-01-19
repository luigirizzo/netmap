/*
 * Copyright (C) 2020 Semihalf
 * Author: Marek Maslanka <marek.maslanka@semihalf.com>
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


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T	mvneta_port

#define mvneta_driver_name netmap_mvneta_driver_name
char mvneta_driver_name[] = "mvneta" NETMAP_LINUX_DRIVER_SUFFIX;

#define MVNETA_TX_PKT_OFFSET_MASK(offset) (((offset) << 23) & 0x3F800000)

static u32 mvreg_read(struct mvneta_port *pp, u32 offset);
static void mvreg_write(struct mvneta_port *pp, u32 offset, u32 data);
static int mvneta_stop(struct net_device *dev);
static int mvneta_open(struct net_device *dev);
static void mvneta_rx_desc_fill(struct mvneta_rx_desc *rx_desc,
				u32 phys_addr, void *virt_addr,
				struct mvneta_rx_queue *rxq);
static int mvneta_rxq_busy_desc_num_get(struct mvneta_port *pp,
					struct mvneta_rx_queue *rxq);
static struct mvneta_rx_desc *
mvneta_rxq_next_desc_get(struct mvneta_rx_queue *rxq);
static struct mvneta_tx_desc *
mvneta_txq_next_desc_get(struct mvneta_tx_queue *txq);
static void mvneta_rxq_desc_num_update(struct mvneta_port *pp,
				       struct mvneta_rx_queue *rxq,
				       int rx_done, int rx_filled);
static void mvneta_rxq_non_occup_desc_add(struct mvneta_port *pp,
					  struct mvneta_rx_queue *rxq,
					  int ndescs);
static void mvneta_txq_inc_put(struct mvneta_tx_queue *txq);
static void mvneta_txq_pend_desc_add(struct mvneta_port *pp,
				     struct mvneta_tx_queue *txq,
				     int pend_desc);
static int mvneta_txq_sent_desc_proc(struct mvneta_port *pp,
				     struct mvneta_tx_queue *txq);
static void mvneta_rx_error(struct mvneta_port *pp,
			    struct mvneta_rx_desc *rx_desc);

static int mvneta_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct mvneta_port *pp = (struct mvneta_port *)netdev_priv(na->ifp);
	int error = 0;

	if (na == NULL)
		return -EINVAL;

	if (!netif_running(na->ifp))
		return -EINVAL;

	mvneta_stop(pp->dev);

	pp->netmap_mode = onoff;
	if (onoff) /* enable netmap mode */
		nm_set_native_flags(na);
	else
		nm_clear_native_flags(na);

	if (netif_running(pp->dev)) {
		mvneta_open(pp->dev);
		pr_debug("%s: starting interface\n", na->ifp->name);
	}
	return error;
}

static int mvneta_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	int cpu;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct mvneta_rx_queue *rxr = &adapter->rxqs[ring_nr];

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	cpu = get_cpu();

	rmb();

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		int rx_todo;

		nic_i = rxr->next_desc_to_proc;
		nm_i = netmap_idx_n2k(kring, nic_i); /* map NIC ring index to netmap ring index */

		rx_todo = mvneta_rxq_busy_desc_num_get(adapter, rxr);
		rx_todo = (rx_todo >= lim - rxr->desc_used) ? lim - rxr->desc_used - 1 : rx_todo;
		for (n = 0; n < rx_todo; n++) {
			struct mvneta_rx_desc *curr = mvneta_rxq_next_desc_get(rxr);
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			uint32_t rx_status = curr->status;

			if (rx_status & MVNETA_RXD_ERR_SUMMARY) {
				mvneta_rx_error(adapter, curr);
			} else {
				PNMB_O(kring, slot, &paddr);
				slot->len = curr->data_size;
				netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev, &paddr,
						    slot->len, NR_RX);
				if (rx_status & MVNETA_RXD_FIRST_DESC) {
					slot->len -= MVNETA_MH_SIZE + ETH_FCS_LEN;
					slot->data_offs = MVNETA_MH_SIZE;
				}
			}
			slot->flags = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			kring->nr_hwtail = nm_i;
			rxr->next_desc_to_proc = nic_i;
			rxr->desc_used += n;
			mvneta_rxq_desc_num_update(adapter, rxr, n, 0);
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

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				struct mvneta_rx_desc *rx_desc;
				rx_desc = (struct mvneta_rx_desc *)rxr->descs + nic_i;
				mvneta_rx_desc_fill(rx_desc, paddr, addr, rxr);
				slot->flags &= ~NS_BUF_CHANGED;
			} else {
				netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev, &paddr,
						    NETMAP_BUF_SIZE(na), NR_RX);
			}
			slot->len = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		wmb();
		mvneta_rxq_non_occup_desc_add(adapter, rxr, n);
		rxr->desc_used -= n;
	}

	put_cpu();
	return 0;

ring_reset:
	put_cpu();
	return netmap_ring_reinit(kring);
}

static int mvneta_netmap_txsync(struct netmap_kring *kring, int flags)
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

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct mvneta_tx_queue *txr = &adapter->txqs[ring_nr];
	struct mvneta_tx_desc *curr;

	rmb();
	/*
	 * First part: process new packets to send.
	 */

	if (!netif_carrier_ok(ifp)) {
		return 0;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			uint64_t offset = nm_get_offset(kring, slot);
			void *addr = PNMB(na, slot, &paddr);
			/* Get a descriptor for the first part of the packet */
			curr = mvneta_txq_next_desc_get(txr);

			NM_CHECK_ADDR_LEN(na, addr, len);
			NM_CHECK_ADDR_LEN_OFF(na, len, offset);

			if (slot->flags & NS_BUF_CHANGED) {
				curr->buf_phys_addr = paddr;
			}
			curr->data_size = len;
			curr->command = MVNETA_TX_L4_CSUM_NOT | MVNETA_TXD_FLZ_DESC |
					MVNETA_TX_PKT_OFFSET_MASK(offset + slot->data_offs);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);

			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev, &paddr, len, NR_TX);
			mvneta_txq_inc_put(txr);

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		mvneta_txq_pend_desc_add(adapter, txr, n);
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */
	}

	nm_i = kring->nr_hwtail;
	n = mvneta_txq_sent_desc_proc(adapter, txr);
	/* sync all buffers that we are returning to userspace */
	while (n) {
		struct netmap_slot *slot = &ring->slot[nm_i];
		uint64_t paddr;
		(void)PNMB_O(kring, slot, &paddr);

		netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
				    &paddr, slot->len, NR_TX);
		slot->len = 0;
		slot->data_offs = 0;
		nm_i = nm_next(nm_i, lim);
		n--;
	}
	kring->nr_hwtail = nm_i;

	if (adapter->neta_armada3700) {
		unsigned long flags;
		int mask;

		local_irq_save(flags);
		mask = mvreg_read(adapter, MVNETA_INTR_NEW_MASK);
		mask |= BIT(ring_nr) & MVNETA_TX_INTR_MASK_ALL;
		mvreg_write(adapter, MVNETA_INTR_NEW_MASK, mask);
		local_irq_restore(flags);
	} else {
		enable_percpu_irq(adapter->dev->irq, 0);
	}

	return 0;
}

/*
 * Make the rx ring point to the netmap buffers.
 */
static int mvneta_netmap_rxq_init_buffers(struct SOFTC_T *adapter,
					  struct mvneta_rx_queue *rxr,
					  int num)
{
	struct ifnet *ifp = adapter->dev;
	struct netmap_adapter *na = NA(ifp);
	struct netmap_slot *slot;
	struct mvneta_rx_desc *rx_desc;
	struct netmap_kring *kring;

	int i, si;
	uint64_t paddr;
	void *vaddr;

	if (!nm_native_on(na)) {
		nm_prinf("Interface not in native netmap mode");
		return 0;	/* nothing to reinitialize */
	}

	kring = na->rx_rings[rxr->id];
	mvneta_rxq_non_occup_desc_add(adapter, rxr, num);

	/* initialize the rx ring */
	slot = netmap_reset(na, NR_RX, rxr->id, 0);
	if (!slot) {
		nm_prerr("Error: RX slot is null");
		return 0;
	}

	for (i = 0; i < num; i++) {
		si = netmap_idx_n2k(na->rx_rings[rxr->id], i);
		vaddr = PNMB_O(kring, slot + si, &paddr);
		rx_desc = (struct mvneta_rx_desc *)rxr->descs + i;
		mvneta_rx_desc_fill(rx_desc, paddr, vaddr, rxr);
	}
	rxr->next_desc_to_proc = 0;
	rxr->desc_used = 0;
	/* Force memory writes to complete */
	wmb();
	return 1;
}

/*
 * Make the tx ring point to the netmap buffers.
 */
static int mvneta_netmap_txq_init_buffers(struct SOFTC_T *adapter)
{
	struct ifnet *ifp = adapter->dev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct mvneta_tx_desc *tx_desc;
	struct mvneta_tx_queue *txr;
	int i, t, si;
	uint64_t paddr;

	if (!nm_native_on(na))
		return 0;

	for (t = 0; t < na->num_tx_rings; t++) {
		txr = &adapter->txqs[t];
		slot = netmap_reset(na, NR_TX, t, 0);
		if (!slot) {
			nm_prinf("Skipping TX ring %d", t);
			continue;
		}
		/* initialize the tx ring for netmap mode */
		for (i = 0; i < na->num_tx_desc; i++) {
			si = netmap_idx_n2k(na->tx_rings[t], i);
			PNMB(na, slot + si, &paddr);
			tx_desc = (struct mvneta_tx_desc *)txr->descs + i;
			tx_desc->buf_phys_addr = paddr;
		}
	}
	return 0;
}

static void mvneta_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->dev;
	na.pdev = adapter->dev->dev.parent;
	na.na_flags = NAF_OFFSETS;
	na.num_tx_desc = adapter->tx_ring_size;
	na.num_rx_desc = adapter->rx_ring_size;
	na.nm_txsync = mvneta_netmap_txsync;
	na.nm_rxsync = mvneta_netmap_rxsync;
	na.nm_register = mvneta_netmap_reg;
	na.num_tx_rings = txq_number;
	na.num_rx_rings = rxq_number;
	na.rx_buf_maxsize = 1500;

	adapter->netmap_mode = false;

	netmap_attach(&na);
}

/* end of file */
