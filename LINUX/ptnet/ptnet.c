/*
 * Netmap passthrough interface driver for Linux
 * Copyright(c) 2015 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/virtio_net.h>

#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_virt.h>
#include <dev/netmap/netmap_mem2.h>


static bool ptnet_vnet_hdr = true;
module_param(ptnet_vnet_hdr, bool, 0444);
static bool ptnet_gso = true;
module_param(ptnet_gso, bool, 0444);

/* Enable to debug RX-side hangs */
//#define HANGCTRL

#if 0  /* Switch to 1 to enable per-packet logs. */
#define DBG D
#else
#define DBG ND
#endif

#define DRV_NAME "ptnet"
#define DRV_VERSION "0.1"

struct ptnet_info;

/* Per-ring data structure. */
struct ptnet_queue {
	struct ptnet_info *pi;
	struct ptnet_ring *ptring;
	int kring_id;
	u8* __iomem kick;

	/* MSI-X interrupt data structures. */
	char msix_name[64];
	cpumask_var_t msix_affinity_mask;
};

struct ptnet_rx_queue {
	struct ptnet_queue q;
	struct napi_struct napi;
	struct page *rx_pool;
	int rx_pool_num;
#ifdef HANGCTRL
#define HANG_INTVAL_MS		3000
	struct timer_list hang_timer;
#endif
};

/* Per-adapter data structure. */
struct ptnet_info {
	struct net_device *netdev;
	struct pci_dev *pdev;

	/* Reference counter to track users of backend netmap port: the
	 * network stack and netmap clients.
	 * Used to decide when we need (de)allocate krings/rings and
	 * start (stop) ptnetmap kthreads. */
	int backend_regifs;

	/* Mirrors PTFEAT register content. */
	uint32_t ptfeatures;

	/* Access to device memory. */
	int bars;
	u8* __iomem ioaddr;
#ifndef PTNET_CSB_ALLOC
	u8* __iomem csbaddr;
#endif  /* !PTNET_CSB_ALLOC */

	/* MSI-X interrupt data structures. */
	struct msix_entry *msix_entries;

	int num_rings;
	struct ptnet_queue **queues;
	struct ptnet_queue **rxqueues;

	/* CSB memory to be used for producer/consumer state
	 * synchronization. */
	struct ptnet_csb *csb;

	int min_tx_slots;

	/* Pass-through netmap adapter used by netmap. */
	struct netmap_pt_guest_adapter *ptna_nm;

	/* Pass-through netmap adapter used by this driver. */
	struct netmap_pt_guest_adapter ptna_dr;
};

#ifdef HANGCTRL
static void
hang_tmr_callback(unsigned long arg)
{
	struct ptnet_rx_queue *prq = (struct ptnet_rx_queue *)arg;
	struct ptnet_info *pi = prq->q.pi;
	struct netmap_adapter *na = &pi->ptna_dr.hwup.up;
	struct netmap_kring *kring = na->rx_rings + prq->q.kring_id;
	struct netmap_ring *ring = kring->ring;

	pr_info("HANG RX#%d: hwc %u h %u c %u hwt %u t %u rx.guest_need_kick %u\n",
		kring->ring_id, kring->nr_hwcur, ring->head, ring->cur,
		kring->nr_hwtail, ring->tail, prq->q.ptring->guest_need_kick);

	if (mod_timer(&prq->hang_timer,
		      jiffies + msecs_to_jiffies(HANG_INTVAL_MS))) {
		pr_err("%s: mod_timer() failed\n", __func__);
	}
}
#endif

static inline void
ptnet_sync_tail(struct ptnet_ring *ptring, struct netmap_kring *kring)
{
	struct netmap_ring *ring = kring->ring;

	/* Update hwcur and hwtail as known by the host. */
        ptnetmap_guest_read_kring_csb(ptring, kring);

	/* nm_sync_finalize */
	ring->tail = kring->rtail = kring->nr_hwtail;
}

static inline int
ptnet_tx_slots(struct netmap_ring *ring)
{
	int space = (int)ring->tail - ring->head;

	if (space < 0) {
		space += ring->num_slots;
	}

	return space;
}

struct xmit_copy_args {
	struct netmap_adapter *na;
	struct netmap_ring *ring;
	unsigned int head;
	unsigned int lim;
	struct netmap_slot *slot;
	void *nmbuf;
	int nmbuf_bytes;
};

static inline void
ptnet_copy_to_ring(struct xmit_copy_args *a,
		   void *skbdata, unsigned int skbdata_len)
{
	for (;;) {
		int copy = min(skbdata_len,
			       NETMAP_BUF_SIZE(a->na) - a->nmbuf_bytes);

		memcpy(a->nmbuf, skbdata, copy);
		skbdata += copy;
		skbdata_len -= copy;
		a->nmbuf += copy;
		a->nmbuf_bytes += copy;

		if (likely(!skbdata_len)) {
			break;
		}

		a->slot->len = a->nmbuf_bytes;
		a->slot->flags = NS_MOREFRAG;
		a->head = nm_next(a->head, a->lim);
		a->slot = &a->ring->slot[a->head];
		a->nmbuf = NMB(a->na, a->slot);
		a->nmbuf_bytes = 0;
	}
}

static netdev_tx_t
ptnet_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	int nfrags = skb_shinfo(skb)->nr_frags;
	int queue_idx = skb_get_queue_mapping(skb);
	struct ptnet_queue *pq = pi->queues[queue_idx];
	struct ptnet_ring *ptring = pq->ptring;
	struct netmap_kring *kring;
	struct xmit_copy_args a;
	int f;

	a.na = &pi->ptna_dr.hwup.up;
	kring = &a.na->tx_rings[queue_idx];
	a.ring = kring->ring;
	a.lim = kring->nkr_num_slots - 1;

	DBG("TX skb len=%d", skb->len);

	/* Update hwcur and hwtail (completed TX slots) as known by the host,
	 * by reading from CSB. */
	ptnet_sync_tail(ptring, kring);

	if (unlikely(ptnet_tx_slots(a.ring) < pi->min_tx_slots)) {
		ND(1, "TX ring unexpected overflow, requeuing");

		return NETDEV_TX_BUSY;
	}

	/* Grab the next available TX slot. */
	a.head = a.ring->head;
	a.slot = &a.ring->slot[a.head];
	a.nmbuf = NMB(a.na, a.slot);
	a.nmbuf_bytes = 0;

	/* First step: Setup the virtio-net header at the beginning of th
	 *  first slot. */
	if (pi->ptfeatures & NET_PTN_FEATURES_VNET_HDR) {
		struct virtio_net_hdr_v1 *vh = a.nmbuf;

		if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
			vh->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			vh->csum_start = skb_checksum_start_offset(skb);
			vh->csum_offset = skb->csum_offset;
		} else {
			vh->flags = 0;
			vh->csum_start = vh->csum_offset = 0;
		}

		if (skb_is_gso(skb)) {
			vh->hdr_len = skb_headlen(skb);
			vh->gso_size = skb_shinfo(skb)->gso_size;
			if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
				vh->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
			} else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP) {
				vh->gso_type = VIRTIO_NET_HDR_GSO_UDP;
			} else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6) {
				vh->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
			}

			if (skb_shinfo(skb)->gso_type & SKB_GSO_TCP_ECN) {
				vh->gso_type |= VIRTIO_NET_HDR_GSO_ECN;
			}

		} else {
			vh->hdr_len = vh->gso_size = 0;
			vh->gso_type = VIRTIO_NET_HDR_GSO_NONE;
		}

		vh->num_buffers = 0; /* unused */

		ND(1, "%s: vnet hdr: flags %x csum_start %u csum_ofs %u hdr_len = "
		      "%u gso_size %u gso_type %x", __func__, vh->flags,
		      vh->csum_start, vh->csum_offset, vh->hdr_len, vh->gso_size,
		      vh->gso_type);

		a.nmbuf += sizeof(*vh);
		a.nmbuf_bytes += sizeof(*vh);
	}

	/* Second step: Copy in the linear part of the sk_buff. */
	ptnet_copy_to_ring(&a, skb->data, skb_headlen(skb));

	/* Third step: Copy in the sk_buffs frags. */
	for (f = 0; f < nfrags; f++) {
		const struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		ptnet_copy_to_ring(&a, skb_frag_address(frag),
				   skb_frag_size(frag));
	}

	/* Prepare the last slot. */
	a.slot->len = a.nmbuf_bytes;
	a.slot->flags = 0;
	a.ring->head = a.ring->cur = nm_next(a.head, a.lim);

	if (skb_shinfo(skb)->nr_frags) {
		ND(1, "TX frags #%u lfsz %u tsz %d gso_segs %d gso_size %d", skb_shinfo(skb)->nr_frags,
		skb_frag_size(&skb_shinfo(skb)->frags[skb_shinfo(skb)->nr_frags-1]),
		(int)skb->len, skb_shinfo(skb)->gso_segs, skb_shinfo(skb)->gso_size);
	}

	BUG_ON(a.ring->slot[a.head].flags & NS_MOREFRAG);

	/* nm_txsync_prologue */
	kring->rcur = a.ring->cur;
	kring->rhead = a.ring->head;

	if (!skb->xmit_more) {
		/* Tell the host to process the new packets, updating cur and
		 * head in the CSB. */
		ptnetmap_guest_write_kring_csb(ptring, kring->rcur,
					       kring->rhead);
	}

        /* Ask for a kick from a guest to the host if needed. */
	if (NM_ACCESS_ONCE(ptring->host_need_kick)) {
		ptring->sync_flags = NAF_FORCE_RECLAIM;
		iowrite32(0, pq->kick);
	}

        /* No more TX slots for further transmissions. We have to stop the
	 * qdisc layer and enable notifications. */
	if (ptnet_tx_slots(a.ring) < pi->min_tx_slots) {
		netif_stop_subqueue(netdev, pq->kring_id);
		ptring->guest_need_kick = 1;

                /* Double check. */
		ptnet_sync_tail(ptring, kring);
		if (unlikely(ptnet_tx_slots(a.ring) >= pi->min_tx_slots)) {
			/* More TX space came in the meanwhile. */
			netif_start_subqueue(netdev, pq->kring_id);
			ptring->guest_need_kick = 0;
		}
	}

	pi->netdev->stats.tx_bytes += skb->len;
	pi->netdev->stats.tx_packets ++;

	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

/*
 * ptnet_get_stats - Get System Network Statistics
 *
 * Returns the address of the device statistics structure.
 */
static struct net_device_stats *
ptnet_get_stats(struct net_device *netdev)
{
	return &netdev->stats;
}

/*
 * ptnet_change_mtu - Change the Maximum Transfer Unit
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int
ptnet_change_mtu(struct net_device *netdev, int new_mtu)
{
	pr_info("%s changing MTU from %d to %d\n",
		netdev->name, netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	return 0;
}

/*
 * ptnet_tx_intr - Interrupt handler for TX queues
 * @data: pointer to a network interface device structure
 */
static irqreturn_t
ptnet_tx_intr(int irq, void *data)
{
	struct ptnet_queue *pq = data;
	struct net_device *netdev = pq->pi->netdev;

	if (netmap_tx_irq(netdev, pq->kring_id)) {
		return IRQ_HANDLED;
	}

	/* Just wake up the qdisc layer, it will flush pending transmissions,
	 * with the side effect of reclaiming completed TX slots. */
	netif_wake_subqueue(netdev, pq->kring_id);

	return IRQ_HANDLED;
}

static inline void
ptnet_napi_schedule(struct ptnet_queue *pq)
{
	struct ptnet_rx_queue *prq = (struct ptnet_rx_queue *)pq;

	/* Disable RX interrupts and schedule NAPI. */

	if (likely(napi_schedule_prep(&prq->napi))) {
		/* It's good thing to reset rx.guest_need_kick as soon as
		 * possible. */
		pq->ptring->guest_need_kick = 0;
		__napi_schedule(&prq->napi);
	} else {
		/* NAPI is already scheduled and we are ok with it. */
		pq->ptring->guest_need_kick = 1;
	}
}

/*
 * ptnet_rx_intr - Interrupt handler for RX queues
 * @data: pointer to a network interface device structure
 */
static irqreturn_t
ptnet_rx_intr(int irq, void *data)
{
	ptnet_napi_schedule((struct ptnet_queue *)data);

	return IRQ_HANDLED;
}

static struct page *
ptnet_alloc_page(struct ptnet_rx_queue *prq)
{
	struct page *p = prq->rx_pool;

	if (p) {
		prq->rx_pool = (struct page *)(p->private);
		prq->rx_pool_num--;
		p->private = (unsigned long)NULL;

		return p;
	}

	return alloc_page(GFP_ATOMIC);
}

static inline void
ptnet_rx_pool_refill(struct ptnet_rx_queue *prq)
{
	while (prq->rx_pool_num < 2 * MAX_SKB_FRAGS) {
		struct page *p = alloc_page(GFP_ATOMIC);

		if (!p) {
			break;
		}

		p->private = (unsigned long)(prq->rx_pool);
		prq->rx_pool = p;
		prq->rx_pool_num ++;
	}
}

/*
 * ptnet_rx_poll - NAPI RX polling callback
 */
static int
ptnet_rx_poll(struct napi_struct *napi, int budget)
{
	struct ptnet_rx_queue *prq = container_of(napi, struct ptnet_rx_queue,
					          napi);
	struct ptnet_queue *pq = (struct ptnet_queue *)prq;
	struct ptnet_ring *ptring = pq->ptring;
	struct ptnet_info *pi = pq->pi;
	struct netmap_adapter *na = &pi->ptna_dr.hwup.up;
	struct netmap_kring *kring = &na->rx_rings[pq->kring_id];
	struct netmap_ring *ring = kring->ring;
	unsigned int const lim = kring->nkr_num_slots - 1;
	bool have_vnet_hdr = pi->ptfeatures & NET_PTN_FEATURES_VNET_HDR;
	unsigned int head = ring->head;
	int work_done = 0;
	int nm_irq;

	nm_irq = netmap_rx_irq(pi->netdev, pq->kring_id, &work_done);
	if (nm_irq != NM_IRQ_PASS) {
		if (nm_irq == NM_IRQ_COMPLETED) {
			napi_complete(napi);
			return 1;
		} else {
			return budget;
		}
	}

#ifdef HANGCTRL
	del_timer(&prq->hang_timer);
#endif

	/* Update hwtail, rtail, tail and hwcur to what is known from the host,
	 * reading from CSB. */
	ptnet_sync_tail(ptring, kring);

	kring->nr_kflags &= ~NKR_PENDINTR;

	/* Import completed RX slots. */
	while (work_done < budget && head != ring->tail) {
		struct virtio_net_hdr_v1 *vh;
		struct netmap_slot *slot;
		struct sk_buff *skb;
		unsigned int first = head;
		struct page *skbpage = NULL;
		int skbdata_avail = 0;
		void *skbdata;
		int nmbuf_len;
		void *nmbuf;
		int copy;
		int nns = 0;

		slot = &ring->slot[head];
		nmbuf = NMB(na, slot);
		nmbuf_len = slot->len;

		vh = nmbuf;
		if (likely(have_vnet_hdr)) {
			ND(1, "%s: vnet hdr: flags %x csum_start %u "
			      "csum_ofs %u hdr_len = %u gso_size %u "
			      "gso_type %x", __func__, vh->flags,
			      vh->csum_start, vh->csum_offset, vh->hdr_len,
			      vh->gso_size, vh->gso_type);
			nmbuf += sizeof(*vh);
			nmbuf_len -= sizeof(*vh);
		}

		skb = napi_alloc_skb(napi, nmbuf_len);
		if (unlikely(!skb)) {
			pr_err("%s: napi_alloc_skb() failed\n",
			       __func__);
			break;
		}

		memcpy(skb_put(skb, nmbuf_len), nmbuf, nmbuf_len);

		while (slot->flags & NS_MOREFRAG) {
			head = nm_next(head, lim);
			nns++;
			if (unlikely(head == ring->tail)) {
				ND(1, "Warning: truncated packet, retrying");
				dev_kfree_skb_any(skb);
				work_done ++;
				pi->netdev->stats.rx_frame_errors ++;
				/* Reset head to the beginning of the
				 * current packet. */
				head = first;
				goto out_of_slots;
			}
			slot = &ring->slot[head];
			nmbuf = NMB(na, slot);
			nmbuf_len = slot->len;

			do {
				if (!skbdata_avail) {
					if (skbpage) {
						ND(1, "add f #%u fsz %lu tsz %d", skb_shinfo(skb)->nr_frags,
								PAGE_SIZE - skbdata_avail, (int)skb->len);
						skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
								skbpage, 0, PAGE_SIZE - skbdata_avail,
								PAGE_SIZE);
					}

					skbpage = ptnet_alloc_page(prq);
					if (unlikely(!skbpage)) {
						pr_err("%s: pntet_alloc_page() failed\n",
						       __func__);
						break;
					}
					skbdata = page_address(skbpage);
					skbdata_avail = PAGE_SIZE;
				}

				copy = min(nmbuf_len, skbdata_avail);
				memcpy(skbdata, nmbuf, copy);
				nmbuf += copy;
				nmbuf_len -= copy;
				skbdata += copy;
				skbdata_avail -= copy;
			} while (nmbuf_len);
		}

		nns++;
		if (skbpage) {
			skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
					skbpage, 0, PAGE_SIZE - skbdata_avail,
					PAGE_SIZE);
			ND(1, "RX frags #%u lfsz %lu tsz %d nns %d", skb_shinfo(skb)->nr_frags,
					PAGE_SIZE - skbdata_avail, (int)skb->len, nns);
		}

		head = nm_next(head, lim);

		DBG("RX SKB len=%d", skb->len);

		pi->netdev->stats.rx_bytes += skb->len;
		pi->netdev->stats.rx_packets ++;

		if (likely(have_vnet_hdr && (vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))) {
			if (unlikely(!skb_partial_csum_set(skb, vh->csum_start,
							   vh->csum_offset))) {
				dev_kfree_skb_any(skb);
				work_done ++;
				pi->netdev->stats.rx_frame_errors ++;
				continue;
			}

		} else if (have_vnet_hdr && (vh->flags & VIRTIO_NET_HDR_F_DATA_VALID)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}

		skb->protocol = eth_type_trans(skb, pi->netdev);

		if (likely(have_vnet_hdr && vh->gso_type != VIRTIO_NET_HDR_GSO_NONE)) {
			switch (vh->gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {

			case VIRTIO_NET_HDR_GSO_TCPV4:
				skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
				break;

			case VIRTIO_NET_HDR_GSO_UDP:
				skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
				break;

			case VIRTIO_NET_HDR_GSO_TCPV6:
				skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
				break;
			}

			if (vh->gso_type & VIRTIO_NET_HDR_GSO_ECN) {
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}

			skb_shinfo(skb)->gso_size = vh->gso_size;
			skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
			skb_shinfo(skb)->gso_segs = 0;
		}

		/*
		 * We should always use napi_gro_receive() in place of
		 * netif_receive_skb(). However, currently we have an
		 * issue (probably due this driver and/or netmap) such
		 * that when virtio-net header is not null using
		 * napi_gro_receive() causes sometimes reordering
		 * of two consecutive sk_buffs. This reordering usually
		 * causes the network stack to issue a TCP DUPACK, and
		 * so a retransmission on the sender side. This bug
		 * seems to disappear if we use netif_receive_skb(skb)
		 * here.
		 *
		 * I've also noticed that when the reordering happens,
		 * i.e.
		 *
		 *    skb1, skb2 --> napi_gro_receive() --> skb2, skb1
		 *
		 * then it is always true that
		 *
		 *    (skb1->len == MTU+14) && (skb2->len > skb1->len)
		 *    && skb_is_gso(skb1) == 0 && skb_is_gso(skb2) != 0
		 *
		 * where usually MTU == 1500.
		 */
		if (have_vnet_hdr && vh->flags) {
			netif_receive_skb(skb);
		} else {
			napi_gro_receive(napi, skb);
		}

		work_done ++;
	}

out_of_slots:
	if (work_done < budget) {
		/* Budget was not fully consumed, since we have no more
		 * completed RX slots. We can enable notifications and
		 * exit polling mode. */
                ptring->guest_need_kick = 1;
		napi_complete_done(napi, work_done);

                /* Double check for more completed RX slots. */
		ptnet_sync_tail(ptring, kring);
		if (head != ring->tail) {
			/* If there is more work to do, disable notifications
			 * and reschedule. */
			ptnet_napi_schedule(pq);
                }
#ifdef HANGCTRL
		if (mod_timer(&prq->hang_timer,
			      jiffies + msecs_to_jiffies(HANG_INTVAL_MS))) {
			pr_err("%s: mod_timer failed\n", __func__);
		}
#endif
	}

	if (work_done) {
		/* Tell the host (through the CSB) about the updated ring->cur and
		 * ring->head (RX buffer refill).
		 */
		ring->head = ring->cur = head;
		kring->rcur = ring->cur;
		kring->rhead = ring->head;
		ptnetmap_guest_write_kring_csb(ptring, kring->rcur,
					       kring->rhead);
		/* Kick the host if needed. */
		if (NM_ACCESS_ONCE(ptring->host_need_kick)) {
			ptring->sync_flags = NAF_FORCE_READ;
			iowrite32(0, pq->kick);
		}
	}

	ptnet_rx_pool_refill(prq);

	return work_done;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/* Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void
ptnet_netpoll(struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	struct netmap_adapter *na = &pi->ptna_dr.hwup.up;
	int i;

	for (i = 0; i < na->num_rx_rings; i++) {
		ptnet_napi_schedule(pi->rxqueues[i]);
	}
}
#endif

static int
ptnet_irqs_init(struct ptnet_info *pi)
{
	unsigned int num_tx_rings;
	int ret;
	int i;

	num_tx_rings = ioread32(pi->ioaddr + PTNET_IO_NUM_TX_RINGS);

	/* Allocate the MSI-X interrupt vectors we need. */
	pi->msix_entries = kzalloc(sizeof(*pi->msix_entries) * pi->num_rings,
				   GFP_KERNEL);
	if (!pi->msix_entries) {
		pr_err("Failed to allocate msix entires\n");
		return -ENOMEM;
	}

	for (i=0; i<pi->num_rings; i++) {
		struct ptnet_queue *pq = pi->queues[i];

		memset(&pq->msix_affinity_mask, 0, sizeof(pq->msix_affinity_mask));
		if (!alloc_cpumask_var(&pq->msix_affinity_mask, GFP_KERNEL)) {
			pr_err("Failed to alloc cpumask var\n");
			goto err_masks;
		}
		pi->msix_entries[i].entry = i;
	}

	ret = pci_enable_msix_exact(pi->pdev, pi->msix_entries,
				    pi->num_rings);
	if (ret) {
		pr_err("Failed to enable msix vectors (%d)\n", ret);
		goto err_masks;
	}

	for (i=0; i<pi->num_rings; i++) {
		struct ptnet_queue *pq = pi->queues[i];
		irq_handler_t handler = (i < num_tx_rings) ?
					ptnet_tx_intr : ptnet_rx_intr;

		snprintf(pq->msix_name, sizeof(pq->msix_name),
			 "ptnet-%d", i);
		ret = request_irq(pi->msix_entries[i].vector, handler,
				  0, pq->msix_name, pq);
		if (ret) {
			pr_err("Unable to allocate interrupt (%d)\n", ret);
			goto err_irqs;
		}
		pr_info("IRQ for ring #%d --> %u, handler %p\n", i,
			pi->msix_entries[i].vector, handler);
	}

	/* Tell the hypervisor that we have allocated the MSI-X vectors,
	 * so that it can do its own setup. */
	iowrite32(PTNET_CTRL_IRQINIT, pi->ioaddr + PTNET_IO_CTRL);

	return 0;

err_irqs:
	for (; i>=0; i--) {
		free_irq(pi->msix_entries[i].vector, pi->queues[i]);
	}
	i = pi->num_rings-1;
err_masks:
	for (; i>=0; i--) {
		free_cpumask_var(pi->queues[i]->msix_affinity_mask);
	}

	return ret;
}

static void
ptnet_irqs_fini(struct ptnet_info *pi)
{
	int i;

	/* Tell the hypervisor that we are going to deallocate the
	 * MSI-X vectors, so that it can do its own setup. */
	iowrite32(PTNET_CTRL_IRQFINI, pi->ioaddr + PTNET_IO_CTRL);

	for (i=0; i<pi->num_rings; i++) {
		struct ptnet_queue *pq = pi->queues[i];

		free_irq(pi->msix_entries[i].vector, pq);
		if (pq->msix_affinity_mask) {
			free_cpumask_var(pq->msix_affinity_mask);
		}
	}
	pci_disable_msix(pi->pdev);
	kfree(pi->msix_entries);
}

static int ptnet_nm_krings_create(struct netmap_adapter *na);
static void ptnet_nm_krings_delete(struct netmap_adapter *na);

static int ptnet_nm_register(struct netmap_adapter *na, int onoff);
/*
 * ptnet_open - Called when a network interface is made active
 *
 * Returns 0 on success, negative value on failure.
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). */
static int
ptnet_open(struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	struct netmap_adapter *na_dr = &pi->ptna_dr.hwup.up;
	int ret;
	int i;

	D("%s: netif_running %u", __func__, netif_running(netdev));

	netmap_update_config(na_dr);

	ret = netmap_mem_finalize(na_dr->nm_mem, na_dr);
	if (ret) {
		pr_err("netmap_mem_finalize() failed\n");
		goto err_mem_finalize;
	}

	if (pi->backend_regifs == 0) {
		ret = ptnet_nm_krings_create(na_dr);
		if (ret) {
			pr_err("ptnet_nm_krings_create() failed\n");
			goto err_mem_finalize;
		}

		ret = netmap_mem_rings_create(na_dr);
		if (ret) {
			pr_err("netmap_mem_rings_create() failed\n");
			goto err_rings_create;
		}

		ret = netmap_mem_get_lut(na_dr->nm_mem, &na_dr->na_lut);
		if (ret) {
			pr_err("netmap_mem_get_lut() failed\n");
			goto err_get_lut;
		}
	}

	ret = ptnet_nm_register(na_dr, 1 /* on */);
	if (ret) {
		goto err_register;
	}

	{
		unsigned int nm_buf_size = NETMAP_BUF_SIZE(na_dr);

		BUG_ON(nm_buf_size == 0);
		pi->min_tx_slots = 65536 / nm_buf_size + 2;
		pr_info("%s: min_tx_slots = %u\n", __func__, pi->min_tx_slots);
	}

	netif_tx_start_all_queues(netdev);

	pr_info("%s: %p\n", __func__, pi);

	for (i = 0; i < na_dr->num_rx_rings; i++){
		struct ptnet_rx_queue *prq = (struct ptnet_rx_queue *)
					pi->rxqueues[i];
#ifdef HANGCTRL
		setup_timer(&prq->hang_timer, &hang_tmr_callback,
			    (unsigned long)prq);
		if (mod_timer(&prq->hang_timer,
			      jiffies + msecs_to_jiffies(HANG_INTVAL_MS))) {
			pr_err("%s: mod_timer failed\n", __func__);
		}
#endif
		prq->rx_pool = NULL;
		prq->rx_pool_num = 0;
		napi_enable(&prq->napi);

		/* There may be pending packets received in netmap mode while
		 * the interface was down. Schedule NAPI to flush packets that
		 * are pending in the RX ring. We won't receive further
		 * interrupts until the pending ones will be processed. */
		D("Schedule NAPI to flush RX ring #%d", i);
		ptnet_napi_schedule(&prq->q);
	}

	return 0;

err_register:
	memset(&na_dr->na_lut, 0, sizeof(na_dr->na_lut));
err_get_lut:
	netmap_mem_rings_delete(na_dr);
err_rings_create:
	ptnet_nm_krings_delete(na_dr);
err_mem_finalize:
	return -ret;
}

/*
 * ptnet_close - Disables a network interface
 *
 * Returns 0, this is not allowed to fail.
 * The close entry point is called when an interface is de-activated
 * by the OS.
 */
static int
ptnet_close(struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	struct netmap_adapter *na_dr = &pi->ptna_dr.hwup.up;
	int i;

	D("%s: netif_running %u", __func__, netif_running(netdev));

	netif_tx_stop_all_queues(netdev);

	for (i = 0; i < na_dr->num_rx_rings; i++){
		struct ptnet_rx_queue *prq = (struct ptnet_rx_queue *)
					pi->rxqueues[i];
#ifdef HANGCTRL
		del_timer(&prq->hang_timer);
#endif
		/* Stop napi. */
		napi_disable(&prq->napi);

		/* Free RX pool. */
		while (prq->rx_pool) {
			struct page *p = prq->rx_pool;

			prq->rx_pool = (struct page *)(p->private);
			p->private = (unsigned long)NULL;
			put_page(p);
		}
		prq->rx_pool = NULL;
		prq->rx_pool_num = 0;
	}


	ptnet_nm_register(na_dr, 0 /* off */);

	if (pi->backend_regifs == 0) {
		netmap_mem_rings_delete(na_dr);
		ptnet_nm_krings_delete(na_dr);
	}
	netmap_mem_deref(na_dr->nm_mem, na_dr);

	pr_info("%s: %p\n", __func__, pi);

	return 0;
}

static const struct net_device_ops ptnet_netdev_ops = {
	.ndo_open		= ptnet_open,
	.ndo_stop		= ptnet_close,
	.ndo_start_xmit		= ptnet_start_xmit,
	.ndo_get_stats		= ptnet_get_stats,
	.ndo_change_mtu		= ptnet_change_mtu,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= ptnet_netpoll,
#endif
};


static int
ptnet_nm_krings_create(struct netmap_adapter *na)
{
	/* Here (na == &pi->ptna_nm->hwup.up || na == &pi->ptna_dr.hwup.up). */
	struct ptnet_info *pi = netdev_priv(na->ifp);
	struct netmap_adapter *na_nm = &pi->ptna_nm->hwup.up;
	struct netmap_adapter *na_dr = &pi->ptna_dr.hwup.up;
	int ret;

	if (pi->backend_regifs) {
		return 0;
	}

	/* Create krings on the public netmap adapter. */
	ret = netmap_hw_krings_create(na_nm);
	if (ret) {
		return ret;
	}

	/* Copy krings into the netmap adapter private to the driver. */
	na_dr->tx_rings = na_nm->tx_rings;
	na_dr->rx_rings = na_nm->rx_rings;

	return 0;
}

static void
ptnet_nm_krings_delete(struct netmap_adapter *na)
{
	/* Here (na == &pi->ptna_nm->hwup.up || na == &pi->ptna_dr.hwup.up). */
	struct ptnet_info *pi = netdev_priv(na->ifp);
	struct netmap_adapter *na_nm = &pi->ptna_nm->hwup.up;
	struct netmap_adapter *na_dr = &pi->ptna_dr.hwup.up;

	if (pi->backend_regifs) {
		return;
	}

	na_dr->tx_rings = NULL;
	na_dr->rx_rings = NULL;

	netmap_hw_krings_delete(na_nm);
}

static uint32_t
ptnet_nm_ptctl(struct net_device *netdev, uint32_t cmd)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	int ret;

	iowrite32(cmd, pi->ioaddr + PTNET_IO_PTCTL);
	ret = ioread32(pi->ioaddr + PTNET_IO_PTSTS);
	pr_info("PTCTL %u, ret %u\n", cmd, ret);

	return ret;
}

static void
ptnet_sync_from_csb(struct ptnet_info *pi, struct netmap_adapter *na)
{
	int i;

	/* Sync krings from the host, reading from
	 * CSB. */
	for (i = 0; i < pi->num_rings; i++) {
		struct ptnet_ring *ptring = pi->queues[i]->ptring;
		struct netmap_kring *kring;

		if (i < na->num_tx_rings) {
			kring = na->tx_rings + i;
		} else {
			kring = na->rx_rings + i - na->num_tx_rings;
		}
		kring->rhead = kring->ring->head = ptring->head;
		kring->rcur = kring->ring->cur = ptring->cur;
		kring->nr_hwcur = ptring->hwcur;
		kring->nr_hwtail = kring->rtail =
			kring->ring->tail = ptring->hwtail;

		ND("%d,%d: csb {hc %u h %u c %u ht %u}", t, i,
		   ptring->hwcur, ptring->head, ptring->cur,
		   ptring->hwtail);
		ND("%d,%d: kring {hc %u rh %u rc %u h %u c %u ht %u rt %u t %u}",
		   t, i, kring->nr_hwcur, kring->rhead, kring->rcur,
		   kring->ring->head, kring->ring->cur, kring->nr_hwtail,
		   kring->rtail, kring->ring->tail);
	}
}

#define csb_notification_enable_all(_pi, _na, _t, _fld, _v)		\
	do {								\
		struct ptnet_queue **queues = (_pi)->queues;		\
		int i;							\
		if (_t == NR_RX) queues = (_pi)->rxqueues;		\
		for (i=0; i<nma_get_nrings(_na, _t); i++) {		\
			queues[i]->ptring->_fld = _v;			\
		}							\
	} while (0)							\

static int
ptnet_nm_register(struct netmap_adapter *na, int onoff)
{
	/* device-specific */
	struct net_device *netdev = na->ifp;
	struct ptnet_info *pi = netdev_priv(netdev);
	int native = (na == &pi->ptna_nm->hwup.up);
	enum txrx t;
	int ret = 0;
	int i;

	BUG_ON(!(na == &pi->ptna_nm->hwup.up || na == &pi->ptna_dr.hwup.up));

	if (!onoff) {
		pi->backend_regifs--;
	}

	/* If this is the last netmap client, guest interrupt enable flags may
	 * be in arbitrary state. Since these flags are going to be used also
	 * by the netdevice driver, we have to make sure to start with
	 * notifications enabled. Also, schedule NAPI to flush pending packets
	 * in the RX rings, since we will not receive further interrupts
	 * until these will be processed. */
	if (native && !onoff && na->active_fds == 0) {
		D("Exit netmap mode, re-enable interrupts");
		csb_notification_enable_all(pi, na, NR_TX, guest_need_kick, 1);
		csb_notification_enable_all(pi, na, NR_RX, guest_need_kick, 1);
		if (netif_running(netdev)) {
			D("Exit netmap mode, schedule NAPI to flush RX ring");
			for (i = 0; i < na->num_rx_rings; i++){
				ptnet_napi_schedule(pi->rxqueues[i]);
			}

		}
	}

	if (onoff) {
		if (pi->backend_regifs == 0) {
			/* Initialize notification enable fields in the CSB. */
			csb_notification_enable_all(pi, na, NR_TX, host_need_kick, 1);
			csb_notification_enable_all(pi, na, NR_TX, guest_need_kick, 0);
			csb_notification_enable_all(pi, na, NR_RX, host_need_kick, 1);
			csb_notification_enable_all(pi, na, NR_RX, guest_need_kick, 1);

			/* Make sure the host adapter passed through is ready
			 * for txsync/rxsync. */
			ret = ptnet_nm_ptctl(netdev, NET_PARAVIRT_PTCTL_REGIF);
			if (ret) {
				return ret;
			}
		}

		/* Sync from CSB must be done after REGIF PTCTL. Skip this
		 * step only if this is a netmap client and it is not the
		 * first one. */
		if ((!native && pi->backend_regifs == 0) ||
				(native && na->active_fds == 0)) {
			ptnet_sync_from_csb(pi, na);
		}

		/* If not native, don't call nm_set_native_flags, since we don't want
		 * to replace ndo_start_xmit method, nor set NAF_NETMAP_ON */
		if (native) {
			for_rx_tx(t) {
				for (i=0; i<nma_get_nrings(na, t); i++) {
					struct netmap_kring *kring = &NMR(na, t)[i];

					if (nm_kring_pending_on(kring)) {
						kring->nr_mode = NKR_NETMAP_ON;
					}
				}
			}
			nm_set_native_flags(na);
		}

	} else {
		if (native) {
			nm_clear_native_flags(na);
			for_rx_tx(t) {
				for (i=0; i<nma_get_nrings(na, t); i++) {
					struct netmap_kring *kring = &NMR(na, t)[i];

					if (nm_kring_pending_off(kring)) {
						kring->nr_mode = NKR_NETMAP_OFF;
					}
				}
			}
		}

		/* Sync from CSB must be done before UNREGIF PTCTL, on the last
		 * netmap client. */
		if (native && na->active_fds == 0) {
			ptnet_sync_from_csb(pi, na);
		}

		if (pi->backend_regifs == 0) {
			ret = ptnet_nm_ptctl(netdev, NET_PARAVIRT_PTCTL_UNREGIF);
		}
	}

	if (onoff) {
		pi->backend_regifs++;
	}

	return ret;
}

static int
ptnet_nm_config(struct netmap_adapter *na, unsigned *txr, unsigned *txd,
		unsigned *rxr, unsigned *rxd)
{
	struct ptnet_info *pi = netdev_priv(na->ifp);

	*txr = ioread32(pi->ioaddr + PTNET_IO_NUM_TX_RINGS);
	*rxr = ioread32(pi->ioaddr + PTNET_IO_NUM_RX_RINGS);
	*txd = ioread32(pi->ioaddr + PTNET_IO_NUM_TX_SLOTS);
	*rxd = ioread32(pi->ioaddr + PTNET_IO_NUM_RX_SLOTS);

	pr_info("txr %u, rxr %u, txd %u, rxd %u\n",
		*txr, *rxr, *txd, *rxd);

	return 0;
}

static int
ptnet_nm_txsync(struct netmap_kring *kring, int flags)
{
	struct ptnet_info *pi = netdev_priv(kring->na->ifp);
	struct ptnet_queue *pq = pi->queues[kring->ring_id];
	bool notify;

	notify = netmap_pt_guest_txsync(pq->ptring, kring, flags);
	if (notify) {
		iowrite32(0, pq->kick);
	}

	return 0;
}

static int
ptnet_nm_rxsync(struct netmap_kring *kring, int flags)
{
	struct ptnet_info *pi = netdev_priv(kring->na->ifp);
	struct ptnet_queue *pq = pi->rxqueues[kring->ring_id];
	bool notify;

	notify = netmap_pt_guest_rxsync(pq->ptring, kring, flags);
	if (notify) {
		iowrite32(0, pq->kick);
	}

	return 0;
}

static void
ptnet_nm_dtor(struct netmap_adapter *na)
{
	netmap_mem_pt_guest_ifp_del(na->nm_mem, na->ifp);
}

static struct netmap_adapter ptnet_nm_ops = {
	.nm_register = ptnet_nm_register,
	.nm_config = ptnet_nm_config,
	.nm_txsync = ptnet_nm_txsync,
	.nm_rxsync = ptnet_nm_rxsync,
	.nm_krings_create = ptnet_nm_krings_create,
	.nm_krings_delete = ptnet_nm_krings_delete,
	.nm_dtor = ptnet_nm_dtor,
};

/*
 * ptnet_probe - Device Initialization Routine
 * @ent: entry in ptnet_pci_table
 *
 * Returns 0 on success, negative on failure
 *
 * ptnet_probe initializes a pi identified by a pci_dev structure.
 * The OS initialization and configuration of the pi private structure
 * occur.
 */
static int
ptnet_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	uint32_t ptfeatures = NET_PTN_FEATURES_BASE;
	unsigned int num_tx_rings, num_rx_rings;
	struct netmap_adapter na_arg;
	struct net_device *netdev;
	unsigned int nifp_offset;
	unsigned int queue_pairs;
	struct ptnet_info *pi;
	uint8_t macaddr[6];
	u8* __iomem ioaddr;
	uint32_t macreg;
	int bars;
	int err;
	int i;

	/* PCI I/O BAR initialization. */
	bars = pci_select_bars(pdev, IORESOURCE_MEM | IORESOURCE_IO);
	err = pci_enable_device(pdev);
	if (err) {
		return err;
	}

	err = pci_request_selected_regions(pdev, bars, DRV_NAME);
	if (err) {
		goto err_pci_reg;
	}

	pci_set_master(pdev);
	err = pci_save_state(pdev);
	if (err) {
		goto err_iomap;
	}

	err = -EIO;
	pr_info("IO BAR (registers): start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, PTNETMAP_IO_PCI_BAR),
		pci_resource_len(pdev, PTNETMAP_IO_PCI_BAR),
		pci_resource_flags(pdev, PTNETMAP_IO_PCI_BAR));

	ioaddr = pci_iomap(pdev, PTNETMAP_IO_PCI_BAR, 0);
	if (!ioaddr) {
		goto err_iomap;
	}

	/* Check if we are supported by the hypervisor. If not,
	 * bail out immediately. */
	if (ptnet_vnet_hdr) {
		ptfeatures |= NET_PTN_FEATURES_VNET_HDR;
	}
	iowrite32(ptfeatures, ioaddr + PTNET_IO_PTFEAT); /* wanted */
	ptfeatures = ioread32(ioaddr + PTNET_IO_PTFEAT); /* acked */
	if (!(ptfeatures & NET_PTN_FEATURES_BASE)) {
		pr_err("Hypervisor doesn't support netmap passthrough\n");
		goto err_ptfeat;
	}

	/* Allocate a multi-queue Ethernet device, with space for
	 * the adapter struct and per-ring structs. */
	err = -ENOMEM;
	num_tx_rings = ioread32(ioaddr + PTNET_IO_NUM_TX_RINGS);
	num_rx_rings = ioread32(ioaddr + PTNET_IO_NUM_RX_RINGS);
	queue_pairs = min(num_tx_rings, num_rx_rings);
	netdev = alloc_etherdev_mq(sizeof(*pi) +
				   (num_tx_rings + num_rx_rings) *
						sizeof(struct ptnet_queue *) +
				   num_tx_rings * sizeof(struct ptnet_queue) +
				   num_rx_rings * sizeof(struct ptnet_rx_queue),
				   queue_pairs);
	if (!netdev) {
		goto err_ptfeat;
	}

	/* Cross-link data structures. */
	SET_NETDEV_DEV(netdev, &pdev->dev);
	pci_set_drvdata(pdev, netdev);
	pi = netdev_priv(netdev);
	pi->netdev = netdev;
	pi->pdev = pdev;
	pi->bars = bars;
	pi->ioaddr = ioaddr;
	pi->ptfeatures = ptfeatures;
	pi->num_rings = num_tx_rings + num_rx_rings;

	/* Initialize the arrays of pointers with the per-ring structures. */
	pi->queues = (struct ptnet_queue **)(pi + 1);
	pi->rxqueues = pi->queues + num_tx_rings;
	{
		struct ptnet_queue *pq;
		struct ptnet_rx_queue *prq;

		/* TX queues first. */
		pq = (struct ptnet_queue *)(pi->queues + pi->num_rings);
		for (i = 0; i < num_tx_rings; i++) {
			pi->queues[i] = pq++;
		}
		/* Then RX queues. */
		prq = (struct ptnet_rx_queue *)pq;
		for (i = 0; i < num_rx_rings; i++, prq++) {
			pi->rxqueues[i] = (struct ptnet_queue *)prq;
		}
	}

#ifndef PTNET_CSB_ALLOC
	/* Map the CSB memory exposed by the device. We don't use
	 * pci_ioremap_bar(), since we want the ioremap_cache() function
	 * to be called internally, rather than ioremap_nocache(). */
	pr_info("MEMORY BAR (CSB): start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
		pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR),
		pci_resource_flags(pdev, PTNETMAP_MEM_PCI_BAR));
	pi->csbaddr = ioremap_cache(pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
				    pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR));
	if (!pi->csbaddr)
		goto err_csb;
	pi->csb = (struct ptnet_csb *)pi->csbaddr;

#else  /* PTNET_CSB_ALLOC */

	/* Alloc the CSB here and tell the hypervisor its physical address. */
	pi->csb = kzalloc(sizeof(struct ptnet_csb), GFP_KERNEL);
	if (!pi->csb) {
		goto err_csb;
	}

	{
		phys_addr_t paddr = virt_to_phys(pi->csb);

		/* CSB allocation protocol. Write CSBBAH first, then
		 * CSBBAL. */
		iowrite32((paddr >> 32) & 0xffffffff,
			  ioaddr + PTNET_IO_CSBBAH);
		iowrite32(paddr & 0xffffffff,
			  ioaddr + PTNET_IO_CSBBAL);
	}
#endif /* PTNET_CSB_ALLOC */

	/* Initialize common parts of all the queues (interrupt
	 * setup excluded). */
	for (i = 0; i < pi->num_rings; i++) {
		struct ptnet_queue *pq = pi->queues[i];
		pq->pi = pi;
		pq->kring_id = i;
		pq->kick = ioaddr + PTNET_IO_KICK_BASE + 4 * i;
		pq->ptring = pi->csb->rings + i;
		if (i >= num_tx_rings) {
			pq->kring_id -= num_tx_rings;
		}
	}

	netdev->netdev_ops = &ptnet_netdev_ops;

	for (i = 0; i < queue_pairs; i++) {
		struct ptnet_rx_queue *prq = (struct ptnet_rx_queue *)
					     pi->rxqueues[i];
		netif_napi_add(netdev, &prq->napi, ptnet_rx_poll, NAPI_POLL_WEIGHT);
	}

	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	/* Read MAC address from device and put it into the netdev struct. */
	macreg = ioread32(ioaddr + PTNET_IO_MAC_HI);
	macaddr[0] = (macreg >> 8) & 0xff;
	macaddr[1] = macreg & 0xff;
	macreg = ioread32(ioaddr + PTNET_IO_MAC_LO);
	macaddr[2] = (macreg >> 24) & 0xff;
	macaddr[3] = (macreg >> 16) & 0xff;
	macaddr[4] = (macreg >> 8) & 0xff;
	macaddr[5] = macreg & 0xff;
	memcpy(netdev->dev_addr, macaddr, netdev->addr_len);

	netdev->features = NETIF_F_HIGHDMA;

	if (pi->ptfeatures & NET_PTN_FEATURES_VNET_HDR) {
		netdev->hw_features |= NETIF_F_HW_CSUM
				       | NETIF_F_SG;
		if (ptnet_gso) {
			netdev->hw_features |= NETIF_F_TSO
					       | NETIF_F_UFO
				               | NETIF_F_TSO_ECN
				               | NETIF_F_TSO6;
		}
		netdev->features |= netdev->hw_features
				    | NETIF_F_RXCSUM;
		if (ptnet_gso) {
			netdev->features |= NETIF_F_GSO_ROBUST;
		}
	}

	device_set_wakeup_enable(&pi->pdev->dev, 0);

	err = ptnet_irqs_init(pi);
	if (err) {
		goto err_irqs;
	}

	strcpy(netdev->name, "eth%d");

	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	err = register_netdev(netdev);
	if (err)
		goto err_netreg;

	/* Read the nifp_offset for the passed-through interface. */
	nifp_offset = ioread32(ioaddr + PTNET_IO_NIFP_OFS);

	/* Attach a guest pass-through netmap adapter to this device. */
	ptnet_nm_ops.num_tx_desc = ioread32(ioaddr + PTNET_IO_NUM_TX_SLOTS);
	ptnet_nm_ops.num_rx_desc = ioread32(ioaddr + PTNET_IO_NUM_RX_SLOTS);
	ptnet_nm_ops.num_tx_rings = num_tx_rings;
	ptnet_nm_ops.num_rx_rings = num_rx_rings;
	na_arg = ptnet_nm_ops;
	na_arg.ifp = pi->netdev;
	netmap_pt_guest_attach(&na_arg, pi->csb, nifp_offset,
			       ptnet_nm_ptctl);
	/* Now a netmap adapter for this device has been allocated, and it
	 * can be accessed through NA(ifp). We have to initialize the CSB
	 * pointer. */
	pi->ptna_nm = (struct netmap_pt_guest_adapter *)NA(pi->netdev);
	pi->ptna_nm->csb = pi->csb;

	/* If virtio-net header was negotiated, set the virt_hdr_len field in
	 * the netmap adapter, to inform users that this netmap adapter requires
	 * the application to deal with the headers. */
	if (pi->ptfeatures & NET_PTN_FEATURES_VNET_HDR) {
		pi->ptna_nm->hwup.up.virt_hdr_len = sizeof(struct virtio_net_hdr_v1);
	}

	/* Initialize a separate pass-through netmap adapter that is going to
	 * be used by this driver only, and so never exposed to netmap. We
	 * only need a subset of the available fields. */
	memset(&pi->ptna_dr, 0, sizeof(pi->ptna_dr));
	pi->ptna_dr.hwup.up.ifp = pi->netdev;
	pi->ptna_dr.hwup.up.nm_mem = pi->ptna_nm->hwup.up.nm_mem;
	netmap_mem_get(pi->ptna_dr.hwup.up.nm_mem);
	pi->ptna_dr.hwup.up.nm_config = ptnet_nm_config;
	pi->ptna_dr.csb = pi->csb;

	pi->backend_regifs = 0;

	netif_carrier_on(netdev);

	pr_info("%s: %p\n", __func__, pi);

	return 0;

	pr_info("%s: failed\n", __func__);
err_netreg:
	ptnet_irqs_fini(pi);
err_irqs:
#ifdef PTNET_CSB_ALLOC
	kfree(pi->csb);
#endif /* PTNET_CSB_ALLOC */
err_csb:
#ifndef PTNET_CSB_ALLOC
	iounmap(pi->csbaddr);
#endif  /* !PTNET_CSB_ALLOC */
	free_netdev(netdev);
err_ptfeat:
	iounmap(ioaddr);
err_iomap:
	pci_release_selected_regions(pdev, bars);
err_pci_reg:
	pci_disable_device(pdev);
	return err;
}

/*
 * ptnet_remove - Device Removal Routine
 *
 * ptnet_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 */
static void
ptnet_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ptnet_info *pi = netdev_priv(netdev);
	int i;

	netif_carrier_off(netdev);

	/* When the netdev is unregistered, ptnet_close() is invoked
	 * for the device. Therefore, the uninitialization of the the
	 * two netmap adapter (ptna_dr, ptna_nm) must happen afterwards. */
	unregister_netdev(netdev);

	/* Uninitialize netmap adapters for this device. */
	netmap_mem_put(pi->ptna_dr.hwup.up.nm_mem);
	memset(&pi->ptna_dr, 0, sizeof(pi->ptna_dr));

	netmap_detach(netdev);

	for (i = 0; i < netdev->num_rx_queues; i++) {
		struct ptnet_rx_queue *prq = (struct ptnet_rx_queue *)
					     pi->rxqueues[i];
		netif_napi_del(&prq->napi);
	}

	ptnet_irqs_fini(pi);

	iounmap(pi->ioaddr);
#ifndef  PTNET_CSB_ALLOC
	iounmap(pi->csbaddr);
#else  /* !PTNET_CSB_ALLOC */
	iowrite32(0, pi->ioaddr + PTNET_IO_CSBBAH);
	iowrite32(0, pi->ioaddr + PTNET_IO_CSBBAL);
	kfree(pi->csb);
#endif /* !PTNET_CSB_ALLOC */
	pci_release_selected_regions(pdev, pi->bars);
	free_netdev(netdev);
	pci_disable_device(pdev);

	pr_info("%s: %p\n", __func__, pi);
}

static void
ptnet_shutdown(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		ptnet_close(netdev);
	}

	pci_disable_device(pdev);
}

/* PCI Device ID Table */
static const struct pci_device_id ptnet_pci_table[] = {
        {PCI_DEVICE(PTNETMAP_PCI_VENDOR_ID, PTNETMAP_PCI_NETIF_ID), 0, 0, 0},
	/* required last entry */
	{0,}
};

MODULE_DEVICE_TABLE(pci, ptnet_pci_table);

static struct pci_driver ptnet_driver = {
	.name     = DRV_NAME,
	.id_table = ptnet_pci_table,
	.probe    = ptnet_probe,
	.remove   = ptnet_remove,
	.shutdown = ptnet_shutdown,
};

int
ptnet_init(void)
{
	pr_info("%s - version %s\n", "Passthrough netmap interface driver",
		DRV_VERSION);

	return pci_register_driver(&ptnet_driver);
}

void
ptnet_fini(void)
{
	pci_unregister_driver(&ptnet_driver);
}
