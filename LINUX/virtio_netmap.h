/*
 * Copyright (C) 2014-2015 Vincenzo Maffione. All rights reserved.
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
#include <netmap/netmap_mem2.h>
#include <linux/virtio_ring.h>


static int virtnet_close(struct ifnet *ifp);
static int virtnet_open(struct ifnet *ifp);
static void free_receive_bufs(struct virtnet_info *vi);
static void free_unused_bufs(struct virtnet_info *vi);

#define DEV_NUM_TX_QUEUES(_netdev)	(_netdev)->num_tx_queues

#ifdef NETMAP_LINUX_VIRTIO_FUNCTIONS

#ifdef NETMAP_LINUX_VIRTIO_ADD_BUF
/* Some simple renaming due to virtio interface changes. */
#define virtqueue_add_inbuf(_vq, _sg, _num, _tok, _gfp)	\
		NETMAP_LINUX_VIRTIO_ADD_BUF(_vq, _sg, 0, _num, _tok, _gfp)
#define virtqueue_add_outbuf(_vq, _sg, _num, _tok, _gfp) \
		NETMAP_LINUX_VIRTIO_ADD_BUF(_vq, _sg, _num, 0, _tok, _gfp)
#endif /* VIRTIO_ADD_BUF */

#else  /* !VIRTIO_FUNCTIONS */

/* Before 2.6.35, the virtio interface was not exported with functions,
   but using virtqueue callbacks. */
#define virtqueue_detach_unused_buf(_vq) \
		(_vq)->vq_ops->detach_unused_buf(_vq)
#define virtqueue_get_buf(_vq, _lp) \
		(_vq)->vq_ops->get_buf(_vq, _lp)
#define virtqueue_add_inbuf(_vq, _sg, _num, _tok, _gfp) \
		(_vq)->vq_ops->add_buf(_vq, _sg, 0, _num, _tok)
#define virtqueue_add_outbuf(_vq, _sg, _num, _tok, _gfp) \
		(_vq)->vq_ops->add_buf(_vq, _sg, _num, 0, _tok)
#define virtqueue_kick(_vq) \
		(_vq)->vq_ops->kick(_vq)
#define virtqueue_enable_cb(_vq) \
		(_vq)->vq_ops->enable_cb(_vq)
#define virtqueue_disable_cb(_vq) \
		(_vq)->vq_ops->disable_cb(_vq)

#endif  /* !VIRTIO_FUNCTIONS */


#ifndef NETMAP_LINUX_VIRTIO_CB_DELAYED
/* The delayed optimization did not exists before version 3.0. */
#define virtqueue_enable_cb_delayed(_vq)	virtqueue_enable_cb(_vq)
#endif  /* !VIRTIO_CB_DELAYED */


#ifndef NETMAP_LINUX_VIRTIO_GET_VRSIZE
/* Not yet found a way to find out virtqueue length in these
   kernel series. Use the virtio default value. */
#define virtqueue_get_vring_size(_vq)	({ (void)(_vq); 256; })
#endif  /* !VIRTIO_GET_VRSIZE */


#ifndef NETMAP_LINUX_VIRTIO_FREE_PAGES
static struct page *get_a_page(struct virtnet_info *vi, gfp_t gfp_mask);

/* This function did not exists, there was just the code. */
static void
free_receive_bufs(struct virtnet_info *vi)
{
	while (vi->pages)
		__free_pages(get_a_page(vi, GFP_KERNEL), 0);
}
#endif /* !VIRTIO_FREE_PAGES */


#ifdef NETMAP_LINUX_VIRTIO_MULTI_QUEUE

#define GET_RX_VQ(_vi, _i)		(_vi)->rq[_i].vq
#define GET_TX_VQ(_vi, _i)		(_vi)->sq[_i].vq
#define VQ_FULL(_vq, _err)		({ (void)(_err); (_vq)->num_free == 0; })
#define GET_RX_SG(_vi, _i)		(_vi)->rq[_i].sg
#define GET_TX_SG(_vi, _i)		(_vi)->sq[_i].sg
#ifdef NETMAP_LINUX_VIRTIO_RQ_NUM
/* multi queue, num field exists */
#define RXNUM_DEC(_vi, _i)		--(_vi)->rq[_i].num
#define RXNUM_INC(_vi, _i)		++(_vi)->rq[_i].num
#else  /* !VIRTIO_RQ_NUM */
/* multi queue, but num field has been removed */
#define RXNUM_DEC(_vi, _i)		({ (void)(_vi); (void)(_i); })
#define RXNUM_INC(_vi, _i)		RXNUM_DEC(_vi, _i)
#endif /* !VIRTIO_RQ_NUM */

#else  /* !MULTI_QUEUE */

/* Before 3.8.0 virtio did not have multiple queues, and therefore
   it did not have per-queue data structures. We then abstract the
   way data structure are accessed, ignoring the queue indexes. */
#define GET_RX_VQ(_vi, _i)		({ (void)(_i); (_vi)->rvq; })
#define GET_TX_VQ(_vi, _i)		({ (void)(_i); (_vi)->svq; })
#define VQ_FULL(_vq, _err)		({ (void)(_vq); (_err) > 0; })
#define RXNUM_DEC(_vi, _i)		({ (void)(_i); --(_vi)->num; })
#define RXNUM_INC(_vi, _i)		({ (void)(_i); ++(_vi)->num; })

#ifdef NETMAP_LINUX_VIRTIO_SG
/* single queue, scatterlist in the vi */
#define GET_RX_SG(_vi, _i)		(_vi)->rx_sg
#define GET_TX_SG(_vi, _i)		(_vi)->tx_sg

#else  /* !MULTI_QUEUE && !SG */

/* Use the scatterlist struct defined in the current function (see below). */
#define GET_RX_SG(_vi, _i)	_compat_sg
#define GET_TX_SG(_vi, _i)	_compat_sg
#endif /* !MULTI_QUEUE && !SG */

#endif /* !MULTI_QUEUE */

#if defined(NETMAP_LINUX_VIRTIO_MULTI_QUEUE) || defined(NETMAP_LINUX_VIRTIO_SG)

/* The following macros are used only for kernels < 2.6.35, see below. */
#define COMPAT_DECL_SG
#define COMPAT_INIT_SG(_sgl)
static void
virtio_netmap_init_sgs(struct virtnet_info *vi)
{
	int i;

	for (i = 0; i < DEV_NUM_TX_QUEUES(vi->dev); i++)
		sg_init_table(GET_TX_SG(vi, i), 2);

	for (i = 0; i < DEV_NUM_RX_QUEUES(vi->dev); i++)
		sg_init_table(GET_RX_SG(vi, i), 2);
}

#else  /* !MULTI_QUEUE && !SG */

/* A scatterlist struct is needed by functions that invoke
   virtqueue_add_buf() methods, but before 2.6.35 these struct were
   not part of virtio-net data structures, but were defined in those
   function. This macro does this definition, which is not necessary
   for subsequent versions. */
#define COMPAT_DECL_SG		        struct scatterlist _compat_sg[2];
#define COMPAT_INIT_SG(_sgl)		sg_init_table(_sgl, 2)
#define virtio_netmap_init_sgs(_vi)

#endif /* !MULTI_QUEUE && !SG */


#ifndef NETMAP_LINUX_VIRTIO_NOTIFY
#define virtqueue_notify(_vq)		virtqueue_kick(_vq)
#endif /* VIRTIO_NOTIFY */


static void
virtio_netmap_clean_used_rings(struct virtnet_info *vi,
			       struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < DEV_NUM_TX_QUEUES(vi->dev); i++) {
		struct virtqueue *vq = GET_TX_VQ(vi, i);
		unsigned int wlen;
		void *token;
		int n = 0;

		while ((token = virtqueue_get_buf(vq, &wlen)) != NULL) {
			if (token != na) {
				/* Not ours, it's a sk_buff,
				 * let's free. */
				dev_kfree_skb(token);
			}
			n++;
		}
		D("got %d used bufs on queue tx-%d", n, i);
	}

	for (i = 0; i < DEV_NUM_RX_QUEUES(vi->dev); i++) {
		struct virtqueue *vq = GET_RX_VQ(vi, i);
		unsigned int wlen;
		void *token;
		int n = 0;

		while ((token = virtqueue_get_buf(vq, &wlen)) != NULL) {
			n++;
			RXNUM_DEC(vi, i);
		}
		D("got %d used bufs on queue rx-%d", n, i);
	}
}


static void
virtio_netmap_reclaim_unused(struct virtnet_info *vi)
{
	int i;

	/* Drain the RX/TX virtqueues, otherwise the driver will
	 * interpret the netmap buffers currently linked to the
	 * netmap ring as buffers allocated by the driver. This
	 * would break the driver (and kernel panic/ooops).
	 * We scan all the virtqueues, even those that have not been
	 * activated (by 'ethtool --set-channels eth0 combined $N').
	 */

	for (i = 0; i < DEV_NUM_TX_QUEUES(vi->dev); i++) {
		struct virtqueue *vq = GET_TX_VQ(vi, i);
		void *token;
		int n = 0;

		while ((token = virtqueue_detach_unused_buf(vq)) != NULL) {
			n++;
		}
		D("detached %d pending bufs on queue tx-%d", n, i);
	}

	for (i = 0; i < DEV_NUM_RX_QUEUES(vi->dev); i++) {
		struct virtqueue *vq = GET_RX_VQ(vi, i);
		void *token;
		int n = 0;

		while ((token = virtqueue_detach_unused_buf(vq)) != NULL) {
			RXNUM_DEC(vi, i);
			n++;
		}
		D("detached %d pending bufs on queue rx-%d", n, i);
	}
}

/* Set or clear nr_pending_mode and nr_mode for all the rings, independently
 * of the specific user request. This is necessary for now because the
 * virtio-net driver patches do not support single-queue mode (modifications
 * would be needed to free_unused_bufs() free_receive_bufs()).*/
static void
virtio_netmap_set_kring_mode(struct netmap_adapter *na, int mode)
{
	int i;

	for (i = 0; i < DEV_NUM_TX_QUEUES(na->ifp); i++) {
		struct netmap_kring *kring = &na->tx_rings[i];

		kring->nr_pending_mode = kring->nr_mode = mode;
	}

	for (i = 0; i < DEV_NUM_RX_QUEUES(na->ifp); i++) {
		struct netmap_kring *kring = &na->rx_rings[i];

		kring->nr_pending_mode = kring->nr_mode = mode;
	}

}

/* Register and unregister. */
static int
virtio_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct virtnet_info *vi = netdev_priv(ifp);
	bool was_up = false;
	int error = 0;

	if (na == NULL)
		return EINVAL;

	if (na->active_fds > 0) {
		/* virtio-net adapter currently does not support single-queue
		 * mode. As a consequence, register (unregister) operations
		 * only have effect with first (last) user.*/
		return 0;
	}

	/* It's important to make sure each virtnet_close() matches
	 * a virtnet_open(), otherwise a napi_disable() is not matched by
	 * a napi_enable(), which results in a deadlock. */
	if (netif_running(ifp)) {
		was_up = true;
		/* Down the interface. This also disables napi. */
		virtnet_close(ifp);
	}

	if (onoff) {
		/* Get and free any used buffers. This is necessary
		 * before calling free_unused_bufs(), that uses
		 * virtqueue_detach_unused_buf(). */
		virtio_netmap_clean_used_rings(vi, na);

		/* Initialize scatter-gather lists used to publish netmap
		 * buffers through virtio descriptors, in such a way that each
		 * each scatter-gather list contains exactly one descriptor
		 * (which can point to a netmap buffer). This initialization is
		 * necessary to prevent the virtio frontend (host) to think
		 * we are using multi-descriptors scatter-gather lists. */
		virtio_netmap_init_sgs(vi);

		/* We have to drain the RX virtqueues, otherwise the
		 * virtio_netmap_init_buffer() called by the subsequent
		 * virtnet_open() cannot link the netmap buffers to the
		 * virtio RX ring.
		 * The unused buffers point to memory allocated by
		 * the virtio-driver (e.g. sk_buffs). We need to free that
		 * memory, otherwise we have leakage.
		 */
		free_unused_bufs(vi);
		/* Also free the pages allocated by the driver. */
		free_receive_bufs(vi);

		/* enable netmap mode */
		virtio_netmap_set_kring_mode(na, NKR_NETMAP_ON);
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
		virtio_netmap_set_kring_mode(na, NKR_NETMAP_OFF);

		/* Get and free any used buffer. This is necessary
		 * before calling virtqueue_detach_unused_buf(). */
		virtio_netmap_clean_used_rings(vi, na);

		virtio_netmap_reclaim_unused(vi);
	}

	if (was_up) {
		/* Up the interface. This also enables the napi. */
		virtnet_open(ifp);
	}

	return (error);
}

static struct virtio_net_hdr_mrg_rxbuf shared_tx_vnet_hdr;
static struct virtio_net_hdr_mrg_rxbuf shared_rx_vnet_hdr;

/* Reconcile kernel and user view of the transmit ring. */
static int
virtio_netmap_txsync(struct netmap_kring *kring, int flags)
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
	COMPAT_DECL_SG
	struct virtnet_info *vi = netdev_priv(ifp);
	struct virtqueue *vq = GET_TX_VQ(vi, ring_nr);
	struct scatterlist *sg = GET_TX_SG(vi, ring_nr);
	size_t vnet_hdr_len = vi->mergeable_rx_bufs ?
				sizeof(shared_tx_vnet_hdr) :
				sizeof(shared_tx_vnet_hdr.hdr);
	struct netmap_adapter *token;

	virtqueue_disable_cb(vq);

	/* Free used slots. We only consider our own used buffers, recognized
	 * by the token we passed to virtqueue_add_outbuf.
	 */
	n = 0;
	for (;;) {
		token = virtqueue_get_buf(vq, &nic_i); /* dummy 2nd arg */
		if (token == NULL)
			break;
		if (likely(token == na))
			n++;
	}
	kring->nr_hwtail += n;
	if (kring->nr_hwtail > lim)
		kring->nr_hwtail -= lim + 1;

	/*
	 * First part: process new packets to send.
	 */
	rmb();

	if (!netif_running(ifp)) {
		/* All the new slots are now unavailable. */
		goto out;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		int nospace = 0;

		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			void *addr = NMB(na, slot);

			NM_CHECK_ADDR_LEN(na, addr, len);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			/* Initialize the scatterlist and expose it to
			 * the hypervisor. */
			COMPAT_INIT_SG(sg);
			sg_set_buf(sg, &shared_tx_vnet_hdr, vnet_hdr_len);
			sg_set_buf(sg + 1, addr, len);
			nospace = virtqueue_add_outbuf(vq, sg, 2, na, GFP_ATOMIC);
			if (nospace) {
				RD(3, "virtqueue_add_outbuf failed [err=%d]",
				   nospace);
				break;
			}

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}

		virtqueue_kick(vq);

		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = nm_i; /* note we migth break early */

		/* No more free virtio descriptors or netmap slots? Ask the
		 * hypervisor for notifications, possibly only when a
		 * considerable amount of work has been done.
		 */
		if (nospace || nm_kr_txempty(kring)) {
			virtqueue_enable_cb_delayed(vq);
		}
	}
out:

	return 0;
}


/* Reconcile kernel and user view of the receive ring. */
static int
virtio_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	// u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	COMPAT_DECL_SG
	struct virtnet_info *vi = netdev_priv(ifp);
	struct virtqueue *vq = GET_RX_VQ(vi, ring_nr);
	struct scatterlist *sg = GET_RX_SG(vi, ring_nr);
	size_t vnet_hdr_len = vi->mergeable_rx_bufs ?
				sizeof(shared_rx_vnet_hdr) :
				sizeof(shared_rx_vnet_hdr.hdr);

	/* XXX netif_carrier_ok ? */

	if (head > lim)
		return netmap_ring_reinit(kring);

	virtqueue_disable_cb(vq);

	rmb();
	/*
	 * First part: import newly received packets.
	 * Only accept our
	 * own buffers (matching the token). We should only get
	 * matching buffers, because of free_unused_bufs()
	 * and virtio_netmap_init_buffers().
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;
		struct netmap_adapter *token;

		nm_i = kring->nr_hwtail;
		n = 0;
		for (;;) {
			int len;
			token = virtqueue_get_buf(vq, &len);
			if (token == NULL)
				break;

			RXNUM_DEC(vi, ring_nr);

			if (unlikely(token != na)) {
				RD(5, "Received unexpected virtqueue token %p\n",
						token);
			} else {
				/* Skip the virtio-net header. */
				len -= vnet_hdr_len;
				if (unlikely(len < 0)) {
					RD(5, "Truncated virtio-net-header, missing %d"
							" bytes", -len);
					len = 0;
				}

				ring->slot[nm_i].len = len;
				ring->slot[nm_i].flags = slot_flags;
				nm_i = nm_next(nm_i, lim);
				n++;
			}
		}
		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
	ND("[B] h %d c %d hwcur %d hwtail %d",
			ring->head, ring->cur, kring->nr_hwcur,
			kring->nr_hwtail);

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur; /* netmap ring index */
	if (nm_i != head) {
		int nospace = 0;

		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			void *addr = NMB(na, slot);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				return netmap_ring_reinit(kring);

			slot->flags &= ~NS_BUF_CHANGED;

			/* Initialize the scatterlist and expose it to
			 * the hypervisor. */
			COMPAT_INIT_SG(sg);
			sg_set_buf(sg, &shared_rx_vnet_hdr, vnet_hdr_len);
			sg_set_buf(sg + 1, addr, NETMAP_BUF_SIZE(na));
			nospace = virtqueue_add_inbuf(vq, sg, 2, na, GFP_ATOMIC);
			if (nospace) {
				RD(3, "virtqueue_add_inbuf failed [err=%d]",
				   nospace);
				break;
			}
			RXNUM_INC(vi, ring_nr);
			nm_i = nm_next(nm_i, lim);
		}
		virtqueue_kick(vq);
		kring->nr_hwcur = head;
	}

	/* We have finished processing used RX buffers, so we have to tell
	 * the hypervisor to make a call when more used RX buffers will be
	 * ready.
	 */
	virtqueue_enable_cb(vq);


	ND("[C] h %d c %d t %d hwcur %d hwtail %d",
			ring->head, ring->cur, ring->tail,
			kring->nr_hwcur, kring->nr_hwtail);

	return 0;
}


/* Make RX virtqueues buffers pointing to netmap buffers. */
static int
virtio_netmap_init_buffers(struct virtnet_info *vi)
{
	struct ifnet *ifp = vi->dev;
	struct netmap_adapter* na = NA(ifp);
	size_t vnet_hdr_len = vi->mergeable_rx_bufs ?
				sizeof(shared_rx_vnet_hdr) :
				sizeof(shared_rx_vnet_hdr.hdr);
	unsigned int r;

	if (!nm_native_on(na))
		return 0;
	for (r = 0; r < na->num_rx_rings; r++) {
		COMPAT_DECL_SG
		struct netmap_ring *ring = na->rx_rings[r].ring;
		struct virtqueue *vq = GET_RX_VQ(vi, r);
		struct scatterlist *sg = GET_RX_SG(vi, r);
		struct netmap_slot* slot;
		unsigned int i;
		int err = 0;

		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("strange, null netmap ring %d", r);
			return 0;
		}

		/* Add up to na>-num_rx_desc-1 buffers to this RX virtqueue.
		 * It's important to leave one virtqueue slot free, otherwise
		 * we can run into ring->cur/ring->tail wraparounds.
		 */
		for (i = 0; i < na->num_rx_desc-1; i++) {
			void *addr;

			slot = &ring->slot[i];
			addr = NMB(na, slot);
			COMPAT_INIT_SG(sg);
			sg_set_buf(sg, &shared_rx_vnet_hdr, vnet_hdr_len);
			sg_set_buf(sg + 1, addr, NETMAP_BUF_SIZE(na));
			err = virtqueue_add_inbuf(vq, sg, 2, na, GFP_ATOMIC);
			if (err < 0) {
				D("virtqueue_add_inbuf failed");

				return 0;
			}
			RXNUM_INC(vi, r);

			if (VQ_FULL(vq, err))
				break;
		}
		D("added %d inbufs on queue %d", i, r);
		virtqueue_kick(vq);
	}

	return 1;
}

/* Update the virtio-net device configurations. Number of queues can
 * change dinamically, by 'ethtool --set-channels $IFNAME combined $N'.
 * This is actually the only way virtio-net can currently enable
 * the multiqueue mode.
 */
static int
virtio_netmap_config(struct netmap_adapter *na, u_int *txr, u_int *txd,
		     u_int *rxr, u_int *rxd)
{
	struct ifnet *ifp = na->ifp;
	struct virtnet_info *vi = netdev_priv(ifp);

	*txr = ifp->real_num_tx_queues;
	*txd = virtqueue_get_vring_size(GET_TX_VQ(vi, 0));
	*rxr = 1;
	*rxd = virtqueue_get_vring_size(GET_RX_VQ(vi, 0));
	D("virtio config txq=%d, txd=%d rxq=%d, rxd=%d",
			*txr, *txd, *rxr, *rxd);

	return 0;
}

static void
virtio_netmap_attach(struct virtnet_info *vi)
{
	struct netmap_adapter na; /* temporary container of methods */

	/* TX shared virtio-net header must be zeroed because its
	 * content is exposed to the host. RX shared virtio-net
	 * header is zeroed only for security reasons. */
	bzero(&shared_tx_vnet_hdr, sizeof(shared_tx_vnet_hdr));
	bzero(&shared_rx_vnet_hdr, sizeof(shared_rx_vnet_hdr));

	bzero(&na, sizeof(na));

	na.ifp = vi->dev;
	na.num_tx_desc = virtqueue_get_vring_size(GET_TX_VQ(vi, 0));
	na.num_rx_desc = virtqueue_get_vring_size(GET_RX_VQ(vi, 0));
	na.num_tx_rings = na.num_rx_rings = 1;
	na.nm_register = virtio_netmap_reg;
	na.nm_txsync = virtio_netmap_txsync;
	na.nm_rxsync = virtio_netmap_rxsync;
	na.nm_config = virtio_netmap_config;

	netmap_attach(&na);

	D("virtio attached txq=%d, txd=%d rxq=%d, rxd=%d",
			na.num_tx_rings, na.num_tx_desc,
			na.num_tx_rings, na.num_rx_desc);
}
/* end of file */
