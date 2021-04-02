/*
 * Copyright (C) 2018 Vincenzo Maffione. All rights reserved.
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

/* Netmap support for the virtio-net driver build from fixed "external"
 * sources (currently taken from Linux 4.9, and patched by
 * patches/custom--virtio_net.c--4.9). This driver should be preferred
 * to the one included with the running Linux version.
 */

/*************************************************************************/
/* COMPATIBILITY LAYER                                                   */
/*************************************************************************/

#ifndef VIRTIO_F_VERSION_1
#define VIRTIO_F_VERSION_1		32
#endif

#ifndef VIRTIO_F_ANY_LAYOUT
#define VIRTIO_F_ANY_LAYOUT		27
#endif

#ifndef NETMAP_LINUX_HAVE_ETHTOOL_VALIDATE
static inline int ethtool_validate_speed(__u32 speed)
{
	return speed <= INT_MAX || speed == SPEED_UNKNOWN;
}

static inline int ethtool_validate_duplex(__u8 duplex)
{
	switch (duplex) {
	case DUPLEX_HALF:
	case DUPLEX_FULL:
	case DUPLEX_UNKNOWN:
		return 1;
	}

	return 0;
}
#endif  /* NETMAP_LINUX_HAVE_ETHTOOL_VALIDATE */

#ifndef NETMAP_LINUX_HAVE_U64_STATS_INIT
#define u64_stats_init(x)
#endif  /* !NETMAP_LINUX_HAVE_U64_STATS_INIT */

#ifndef NETMAP_LINUX_HAVE_U64_STATS_IRQ
#define u64_stats_fetch_begin_irq	u64_stats_fetch_begin_bh
#define u64_stats_fetch_retry_irq	u64_stats_fetch_retry_bh
#endif  /* !NETMAP_LINUX_HAVE_U64_STATS_IRQ */

#ifdef NETMAP_LINUX_HAVE_SKB_COALESCE_RX_FRAG
#define WITH_MERGEABLE_RX_BUFS
#endif  /* !NETMAP_LINUX_HAVE_SKB_COALESCE_RX_FRAG */

#ifndef NETMAP_LINUX_HAVE_VIRTIO_BYTEORDER
#include <linux/types.h>

/*
 * __virtio{16,32,64} have the following meaning:
 * - __u{16,32,64} for virtio devices in legacy mode, accessed in native endian
 * - __le{16,32,64} for standard-compliant virtio devices
 */

typedef __u16 __bitwise__ __virtio16;
typedef __u32 __bitwise__ __virtio32;
typedef __u64 __bitwise__ __virtio64;

static inline u16 __virtio16_to_cpu(bool little_endian, __virtio16 val)
{
	if (little_endian)
		return le16_to_cpu((__force __le16)val);
	else
		return be16_to_cpu((__force __be16)val);
}

static inline __virtio16 __cpu_to_virtio16(bool little_endian, u16 val)
{
	if (little_endian)
		return (__force __virtio16)cpu_to_le16(val);
	else
		return (__force __virtio16)cpu_to_be16(val);
}

static inline u32 __virtio32_to_cpu(bool little_endian, __virtio32 val)
{
	if (little_endian)
		return le32_to_cpu((__force __le32)val);
	else
		return be32_to_cpu((__force __be32)val);
}

static inline __virtio32 __cpu_to_virtio32(bool little_endian, u32 val)
{
	if (little_endian)
		return (__force __virtio32)cpu_to_le32(val);
	else
		return (__force __virtio32)cpu_to_be32(val);
}

static inline u64 __virtio64_to_cpu(bool little_endian, __virtio64 val)
{
	if (little_endian)
		return le64_to_cpu((__force __le64)val);
	else
		return be64_to_cpu((__force __be64)val);
}

static inline __virtio64 __cpu_to_virtio64(bool little_endian, u64 val)
{
	if (little_endian)
		return (__force __virtio64)cpu_to_le64(val);
	else
		return (__force __virtio64)cpu_to_be64(val);
}
#endif  /* NETMAP_LINUX_HAVE_VIRTIO_BYTEORDER */

#ifndef NETMAP_LINUX_HAVE_VIRTIO_IS_LITTLE_ENDIAN
static inline bool virtio_legacy_is_little_endian(void)
{
#ifdef __LITTLE_ENDIAN
	return true;
#else
	return false;
#endif
}

static inline bool virtio_is_little_endian(struct virtio_device *vdev)
{
	return virtio_has_feature(vdev, VIRTIO_F_VERSION_1) ||
		virtio_legacy_is_little_endian();
}
#endif  /* NETMAP_LINUX_HAVE_VIRTIO_IS_LITTLE_ENDIAN */

#ifndef NETMAP_LINUX_HAVE_VIRTIO_MEMORY_ACCESSORS
static inline u16 virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val)
{
	return __virtio16_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio16 cpu_to_virtio16(struct virtio_device *vdev, u16 val)
{
	return __cpu_to_virtio16(virtio_is_little_endian(vdev), val);
}

static inline u32 virtio32_to_cpu(struct virtio_device *vdev, __virtio32 val)
{
	return __virtio32_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio32 cpu_to_virtio32(struct virtio_device *vdev, u32 val)
{
	return __cpu_to_virtio32(virtio_is_little_endian(vdev), val);
}

static inline u64 virtio64_to_cpu(struct virtio_device *vdev, __virtio64 val)
{
	return __virtio64_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio64 cpu_to_virtio64(struct virtio_device *vdev, u64 val)
{
	return __cpu_to_virtio64(virtio_is_little_endian(vdev), val);
}
#endif  /* NETMAP_LINUX_HAVE_VIRTIO_MEMORY_ACCESSORS */

#if !defined(NETMAP_LINUX_VIRTIO_NET_HDR_FROM_SKB_5ARGS) && !defined(NETMAP_LINUX_VIRTIO_NET_HDR_FROM_SKB_4ARGS) && !defined(NETMAP_LINUX_VIRTIO_NET_HDR_FROM_SKB_3ARGS)
static inline int virtio_net_hdr_to_skb(struct sk_buff *skb,
					const struct virtio_net_hdr *hdr,
					bool little_endian)
{
	unsigned short gso_type = 0;

	if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		switch (hdr->gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			gso_type = SKB_GSO_TCPV4;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			gso_type = SKB_GSO_TCPV6;
			break;
		case VIRTIO_NET_HDR_GSO_UDP:
			gso_type = SKB_GSO_UDP;
			break;
		default:
			return -EINVAL;
		}

		if (hdr->gso_type & VIRTIO_NET_HDR_GSO_ECN)
			gso_type |= SKB_GSO_TCP_ECN;

		if (hdr->gso_size == 0)
			return -EINVAL;
	}

	if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		u16 start = __virtio16_to_cpu(little_endian, hdr->csum_start);
		u16 off = __virtio16_to_cpu(little_endian, hdr->csum_offset);

		if (!skb_partial_csum_set(skb, start, off))
			return -EINVAL;
	}

	if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		u16 gso_size = __virtio16_to_cpu(little_endian, hdr->gso_size);

		skb_shinfo(skb)->gso_size = gso_size;
		skb_shinfo(skb)->gso_type = gso_type;

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	return 0;
}

static inline int virtio_net_hdr_from_skb(const struct sk_buff *skb,
					  struct virtio_net_hdr *hdr,
					  bool little_endian)
{
	memset(hdr, 0, sizeof(*hdr));

	if (skb_is_gso(skb)) {
		struct skb_shared_info *sinfo = skb_shinfo(skb);

		/* This is a hint as to how much should be linear. */
		hdr->hdr_len = __cpu_to_virtio16(little_endian,
						 skb_headlen(skb));
		hdr->gso_size = __cpu_to_virtio16(little_endian,
						  sinfo->gso_size);
		if (sinfo->gso_type & SKB_GSO_TCPV4)
			hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		else if (sinfo->gso_type & SKB_GSO_TCPV6)
			hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		else if (sinfo->gso_type & SKB_GSO_UDP)
			hdr->gso_type = VIRTIO_NET_HDR_GSO_UDP;
		else
			return -EINVAL;
		if (sinfo->gso_type & SKB_GSO_TCP_ECN)
			hdr->gso_type |= VIRTIO_NET_HDR_GSO_ECN;
	} else
		hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		if (skb->vlan_tci & VLAN_TAG_PRESENT)
			hdr->csum_start = __cpu_to_virtio16(little_endian,
				skb_checksum_start_offset(skb) + VLAN_HLEN);
		else
			hdr->csum_start = __cpu_to_virtio16(little_endian,
				skb_checksum_start_offset(skb));
		hdr->csum_offset = __cpu_to_virtio16(little_endian,
				skb->csum_offset);
	} /* else everything is zero */

	return 0;
}
#endif

#ifndef NETMAP_LINUX_VIRTIO_GET_VRSIZE
/* Not yet found a way to find out virtqueue length in these
   kernel series. Use the virtio default value. */
#define virtqueue_get_vring_size(_vq)	({ (void)(_vq); 256; })
#endif  /* !VIRTIO_GET_VRSIZE */

#ifndef NETMAP_LINUX_HAVE_VIRTIO_DEVICE_READY
static inline
void virtio_device_ready(struct virtio_device *dev)
{
	unsigned status = dev->config->get_status(dev);

	BUG_ON(status & VIRTIO_CONFIG_S_DRIVER_OK);
	dev->config->set_status(dev, status | VIRTIO_CONFIG_S_DRIVER_OK);
}
#endif  /* NETMAP_LINUX_HAVE_VIRTIO_DEVICE_READY */

#ifndef NETMAP_LINUX_HAVE_VIRTQUEUE_IS_BROKEN
#define virtqueue_is_broken(_x)	false
#endif  /* NETMAP_LINUX_HAVE_VIRTQUEUE_IS_BROKEN */

#ifndef NETMAP_LINUX_VIRTIO_CB_DELAYED
/* The delayed optimization did not exists before version 3.0. */
#define virtqueue_enable_cb_delayed(_vq)	virtqueue_enable_cb(_vq)
#endif  /* !VIRTIO_CB_DELAYED */

#ifndef NETMAP_LINUX_HAVE_VIRTIO_CONFIG_ACCESSORS
#define virtio_cread(vdev, structname, member, ptr)			\
	do {								\
		/* Must match the member's type, and be integer */	\
		if (!typecheck(typeof((((structname*)0)->member)), *(ptr))) \
			(*ptr) = 1;					\
									\
		switch (sizeof(*ptr)) {					\
		case 1:							\
			*(ptr) = virtio_cread8(vdev,			\
					       offsetof(structname, member)); \
			break;						\
		case 2:							\
			*(ptr) = virtio_cread16(vdev,			\
						offsetof(structname, member)); \
			break;						\
		case 4:							\
			*(ptr) = virtio_cread32(vdev,			\
						offsetof(structname, member)); \
			break;						\
		case 8:							\
			*(ptr) = virtio_cread64(vdev,			\
						offsetof(structname, member)); \
			break;						\
		default:						\
			BUG();						\
		}							\
	} while(0)

/* Config space accessors. */
#define virtio_cwrite(vdev, structname, member, ptr)			\
	do {								\
		/* Must match the member's type, and be integer */	\
		if (!typecheck(typeof((((structname*)0)->member)), *(ptr))) \
			BUG_ON((*ptr) == 1);				\
									\
		switch (sizeof(*ptr)) {					\
		case 1:							\
			virtio_cwrite8(vdev,				\
				       offsetof(structname, member),	\
				       *(ptr));				\
			break;						\
		case 2:							\
			virtio_cwrite16(vdev,				\
					offsetof(structname, member),	\
					*(ptr));			\
			break;						\
		case 4:							\
			virtio_cwrite32(vdev,				\
					offsetof(structname, member),	\
					*(ptr));			\
			break;						\
		case 8:							\
			virtio_cwrite64(vdev,				\
					offsetof(structname, member),	\
					*(ptr));			\
			break;						\
		default:						\
			BUG();						\
		}							\
	} while(0)

static inline u8 virtio_cread8(struct virtio_device *vdev, unsigned int offset)
{
	u8 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	return ret;
}

static inline void virtio_cread_bytes(struct virtio_device *vdev,
				      unsigned int offset,
				      void *buf, size_t len)
{
	vdev->config->get(vdev, offset, buf, len);
}

static inline void virtio_cwrite8(struct virtio_device *vdev,
				  unsigned int offset, u8 val)
{
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

static inline u16 virtio_cread16(struct virtio_device *vdev,
				 unsigned int offset)
{
	u16 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	return ret;
}

static inline void virtio_cwrite16(struct virtio_device *vdev,
				   unsigned int offset, u16 val)
{
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

static inline u32 virtio_cread32(struct virtio_device *vdev,
				 unsigned int offset)
{
	u32 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	return ret;
}

static inline void virtio_cwrite32(struct virtio_device *vdev,
				   unsigned int offset, u32 val)
{
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

static inline u64 virtio_cread64(struct virtio_device *vdev,
				 unsigned int offset)
{
	u64 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	return ret;
}

static inline void virtio_cwrite64(struct virtio_device *vdev,
				   unsigned int offset, u64 val)
{
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

/* Conditional config space accessors. */
#define virtio_cread_feature(vdev, fbit, structname, member, ptr)	\
	({								\
		int _r = 0;						\
		if (!virtio_has_feature(vdev, fbit))			\
			_r = -ENOENT;					\
		else							\
			virtio_cread((vdev), structname, member, ptr);	\
		_r;							\
	})
#endif  /* !NETMAP_LINUX_HAVE_VIRTIO_CONFIG_ACCESSORS */

/*************************************************************************/
/* NETMAP SUPPORT                                                        */
/*************************************************************************/

static int virtnet_open(struct net_device *dev);
static int virtnet_close(struct net_device *dev);

static void
virtio_net_netmap_free_os_buf(struct virtnet_info *vi, enum txrx t,
			      int idx, void *buf)
{
	if (t == NR_TX) {
		dev_kfree_skb(buf);
	} else {
		if (vi->mergeable_rx_bufs) {
			unsigned long ctx = (unsigned long)buf;
			void *base = mergeable_ctx_to_buf_address(ctx);
			put_page(virt_to_head_page(base));
		} else if (vi->big_packets) {
			give_pages(&vi->rq[idx], buf);
		} else {
			dev_kfree_skb(buf);
		}
	}
}

static void
virtio_net_netmap_detach_unused(struct virtnet_info *vi, bool onoff,
				enum txrx t, int idx)
{
	struct virtqueue* vq = (t == NR_RX) ? vi->rq[idx].vq : vi->sq[idx].vq;
	unsigned int n = 0;
	void *buf;

	while ((buf = virtqueue_detach_unused_buf(vq)) != NULL) {
		if (!onoff) {
			/* This is a netmap buffer, so there is
			 * nothing to do. */
		} else {
			virtio_net_netmap_free_os_buf(vi, t, idx, buf);
		}
		n++;
	}

	if (n)
		nm_prinf("%d sgs detached on %s-%d (onoff=%d)",
			 n, nm_txrx2str(t), idx, onoff);
}

static void
virtio_net_netmap_drain_used(struct virtnet_info *vi, bool onoff,
				enum txrx t, int idx)
{
	struct virtqueue* vq = (t == NR_RX) ? vi->rq[idx].vq : vi->sq[idx].vq;
	unsigned int len, n = 0;
	void *buf;

	while ((buf = virtqueue_get_buf(vq, &len)) != NULL) {
		if (!onoff) {
			/* This is a netmap buffer, so there is
			 * nothing to do. */
		} else {
			virtio_net_netmap_free_os_buf(vi, t, idx, buf);
		}
		n++;
	}

	if (n)
		nm_prinf("%d sgs drained on %s-%d (onoff=%d)",
			n, nm_txrx2str(t), idx, onoff);
}

/* Initialize scatter-gather lists used to publish netmap
 * buffers through virtio descriptors, in such a way that each
 * each scatter-gather list contains exactly two descriptors
 * (which can point to a netmap buffer). This initialization is
 * necessary to prevent the virtio frontend (host) to think
 * we are using multi-descriptors scatter-gather lists. */
static void
virtio_net_netmap_init_sgs(struct virtnet_info *vi)
{
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		sg_init_table(vi->sq[i].sg, 2);
		sg_init_table(vi->rq[i].sg, 2);
	}
}

/* Register and unregister. */
static int
virtio_net_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct virtnet_info *vi = netdev_priv(ifp);
	bool was_up = false;
	enum txrx t;
	int i;

	/* It's important to make sure each virtnet_close() matches
	 * a virtnet_open(), otherwise a napi_disable() is not matched by
	 * a napi_enable(), which results in a deadlock. */
	if (netif_running(ifp)) {
		was_up = true;
		/* Down the interface. This also disables napi. */
		virtnet_close(ifp);
	}

	if (onoff) {
		/* Enable netmap mode before draining and detaching OS
		 * buffers, to prevent the OS to transmit packets
		 * while we are doing that. */
		nm_set_native_flags(na);

		for_rx_tx(t) {
			/* Hardware rings. */
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (!nm_kring_pending_on(kring))
					continue;

				/* Get used OS buffers. */
				virtio_net_netmap_drain_used(vi, onoff, t, i);

				/* Detach and free any unused OS buffers. */
				virtio_net_netmap_detach_unused(vi, onoff, t, i);

				/* Initialize scatter-gater buffers for
				 * netmap mode. */
				virtio_net_netmap_init_sgs(vi);

				kring->nr_mode = NKR_NETMAP_ON;
			}

			/* Host rings. */
			for (i = 0; i < nma_get_host_nrings(na, t); i++) {
				struct netmap_kring *kring =
					NMR(na, t)[nma_get_nrings(na, t) + i];

				if (nm_kring_pending_on(kring)) {
					kring->nr_mode = NKR_NETMAP_ON;
				}
			}
		}
	} else {
		for_rx_tx(t) {
			/* Hardware rings. */
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (!nm_kring_pending_off(kring))
					continue;

				/* Get used netmap buffers. */
				virtio_net_netmap_drain_used(vi, onoff, t, i);

				/* Detach and free any unused netmap buffers. */
				virtio_net_netmap_detach_unused(vi, onoff, t, i);

				kring->nr_mode = NKR_NETMAP_OFF;
			}

			/* Host rings. */
			for (i = 0; i < nma_get_host_nrings(na, t); i++) {
				struct netmap_kring *kring =
					NMR(na, t)[nma_get_nrings(na, t) + i];

				if (nm_kring_pending_off(kring)) {
					kring->nr_mode = NKR_NETMAP_OFF;
				}
			}
		}

		/* Disable netmap mode after netmap buffers have been drained
		 * and detached, to prevent the OS to start transmitting while
		 * we are doing that. */
		nm_clear_native_flags(na);
	}

	if (was_up) {
		/* Up the interface. This also enables the napi. */
		virtnet_open(ifp);
	}

	return 0;
}

/* Prepare an RX virtqueue for netmap operation. Returns true if
 * the queue is ready for netmap and false if it is not going to
 * work in netmap mode. */
static bool
virtio_net_netmap_init_buffers(struct virtnet_info *vi, int r)
{
	size_t vnet_hdr_len = vi->mergeable_rx_bufs ?
				sizeof(vi->rq[r].shared_rxvhdr) :
				sizeof(vi->rq[r].shared_rxvhdr.hdr);
	struct netmap_adapter *na = NA(vi->dev);
	struct netmap_kring *kring;
	struct virtqueue *vq;
	int i;

	if (!nm_netmap_on(na)) {
		return false;
	}

	kring = na->rx_rings[r];
	if (kring->nr_mode != NKR_NETMAP_ON) {
		return false;
	}

	vq = vi->rq[r].vq;

	/*
	 * Add exactly na->num_rx_desc descriptor chains to this RX
	 * virtqueue, as virtio_netmap_rxsync() assumes the chains
	 * are returned in the same order by virtqueue_get_buf().
	 * It is technically possible that the hypervisor returns
	 * na->num_rx_desc chains before the user can consume them,
	 * so virtio_netmap_rxsync() must prevent ring->tail to
	 * wrap around ring->head.
	 */
	for (i = 0; i < na->num_rx_desc && vq->num_free > 0; i++) {
		struct netmap_ring *ring = kring->ring;
		struct scatterlist *sg = vi->rq[r].sg;
		struct netmap_slot *slot;
		void *addr;
		int err;

		slot = &ring->slot[i];
		addr = NMB(na, slot);
		sg_set_buf(sg, &vi->rq[r].shared_rxvhdr, vnet_hdr_len);
		sg_set_buf(sg + 1, addr, NETMAP_BUF_SIZE(na));
		err = virtqueue_add_inbuf(vq, sg, 2, na, GFP_ATOMIC);
		if (err < 0) {
			nm_prerr("virtqueue_add_inbuf() failed");
			return 0;
		}
	}
	nm_prinf("%s-rx-%d: %d netmap buffers published", na->name,
			r, i);

	return true;
}

/* Reconcile kernel and user view of the transmit ring. */
static int
virtio_net_netmap_txsync(struct netmap_kring *kring, int flags)
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
	struct virtnet_info *vi = netdev_priv(ifp);
	struct send_queue *sq = vi->sq + ring_nr;
	struct virtqueue *vq = sq->vq;
	struct scatterlist *sg = sq->sg;
	size_t vnet_hdr_len = vi->mergeable_rx_bufs ?
				sizeof(sq->shared_txvhdr) :
				sizeof(sq->shared_txvhdr.hdr);
	int interrupts = !(kring->nr_kflags & NKR_NOINTR);
	struct netmap_adapter *token;

	if (!netif_running(ifp)) {
		/* All the new slots are now unavailable. */
		goto out;
	}

	/*
	 * First part: process new packets to send.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			void *addr = NMB(na, slot);
			int nospace;

			NM_CHECK_ADDR_LEN(na, addr, len);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			/* Initialize the scatterlist and expose it to
			 * the hypervisor. */
			sg_set_buf(sg, &sq->shared_txvhdr, vnet_hdr_len);
			sg_set_buf(sg + 1, addr, len);
			nospace = virtqueue_add_outbuf(vq, sg, 2, na, GFP_ATOMIC);
			if (nospace) {
				nm_prerr("virtqueue_add_outbuf failed [err=%d]",
					nospace);
				break;
			}

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}

		virtqueue_kick(vq);

		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = nm_i; /* note we might break early */
	}
out:
	if (interrupts && vq->num_free < 32)
		virtqueue_enable_cb_delayed(vq);

	/* Free used slots. We only consider our own used buffers, recognized
	 * by the token we passed to virtqueue_add_outbuf.
	 */
	n = 0;
	for (;;) {
		token = virtqueue_get_buf(vq, &nic_i); /* dummy 2nd arg */
		if (token == NULL)
			break;
		if (unlikely(token != na))
			nm_prerr("BUG: token mismatch");
		else
			n++;
	}
	if (n > 0) {
		kring->nr_hwtail += n;
		if (kring->nr_hwtail > lim)
			kring->nr_hwtail -= lim + 1;
	}

	return 0;
}

/* Reconcile kernel and user view of the receive ring. */
static int
virtio_net_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) ||
				(kring->nr_kflags & NKR_PENDINTR);
	int interrupts = !(kring->nr_kflags & NKR_NOINTR);

	/* device-specific */
	struct virtnet_info *vi = netdev_priv(ifp);
	struct receive_queue *rq = vi->rq + ring_nr;
	struct virtqueue *vq = rq->vq;
	struct scatterlist *sg = rq->sg;
	size_t vnet_hdr_len = vi->mergeable_rx_bufs ?
				sizeof(rq->shared_rxvhdr) :
				sizeof(rq->shared_rxvhdr.hdr);

	virtqueue_disable_cb(vq);

	/*
	 * First part: import newly received packets.
	 * Only accept our own buffers (matching the token). We should only get
	 * matching buffers, because of virtio_net_netmap_detach_unused() and
	 * virtio_net_netmap_init_buffers(). We may need to stop early to avoid
	 * hwtail to overrun hwcur.
	 */
	if (netmap_no_pendintr || force_update) {
		uint32_t hwtail_lim = nm_prev(kring->nr_hwcur, lim);
		struct netmap_adapter *token;


		nm_i = kring->nr_hwtail;
		n = 0;
		while (nm_i != hwtail_lim) {
			int len;
			token = virtqueue_get_buf(vq, &len);
			if (token == NULL)
				break;

			if (unlikely(token != na)) {
				nm_prlim(5, "Received unexpected virtqueue token %p\n",
						token);
			} else {
				/* Skip the virtio-net header. */
				len -= vnet_hdr_len;
				if (unlikely(len < 0)) {
					nm_prlim(1, "Truncated virtio-net-header, missing %d"
							" bytes", -len);
					len = 0;
				}

				ring->slot[nm_i].len = len;
				ring->slot[nm_i].flags = 0;
				nm_i = nm_next(nm_i, lim);
				n++;
			}
		}
		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
	nm_prdis("[B] h %d c %d hwcur %d hwtail %d",
			ring->head, ring->cur, kring->nr_hwcur,
			kring->nr_hwtail);

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur; /* netmap ring index */
	if (nm_i != head) {
		int nospace = 0;

		for (; nm_i != head; nm_i = nm_next(nm_i, lim)) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			void *addr = NMB(na, slot);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				return netmap_ring_reinit(kring);

			slot->flags &= ~NS_BUF_CHANGED;

			/* Initialize the scatterlist and expose it to
			 * the hypervisor. */
			sg_set_buf(sg, &rq->shared_rxvhdr, vnet_hdr_len);
			sg_set_buf(sg + 1, addr, NETMAP_BUF_SIZE(na));
			nospace = virtqueue_add_inbuf(vq, sg, 2, na, GFP_ATOMIC);
			if (nospace) {
				nm_prlim(2, "virtqueue_add_inbuf failed [err=%d]",
				   nospace);
				break;
			}
		}
		virtqueue_kick(vq);
		kring->nr_hwcur = nm_i;
	}

	/* We have finished processing used RX buffers, so we have to tell
	 * the hypervisor to make a call when more used RX buffers will be
	 * ready.
	 */
	if (interrupts)
		virtqueue_enable_cb(vq);


	nm_prdis("[C] h %d c %d t %d hwcur %d hwtail %d",
			ring->head, ring->cur, ring->tail,
			kring->nr_hwcur, kring->nr_hwtail);

	return 0;
}

/* Enable/disable interrupts on all virtqueues. */
static void
virtio_net_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct virtnet_info *vi = netdev_priv(na->ifp);
	enum txrx t;
	int i;

	for_rx_tx(t) {
		for (i = 0; i < nma_get_nrings(na, t); i++) {
			struct virtqueue *vq;

			vq = t == NR_RX ? vi->rq[i].vq : vi->sq[i].vq;

			if (onoff)
				virtqueue_enable_cb(vq);
			else
				virtqueue_disable_cb(vq);
		}
	}
}

static void
virtio_net_netmap_attach(struct virtnet_info *vi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = vi->dev;
	na.na_flags = 0;
	na.num_tx_desc = virtqueue_get_vring_size(vi->sq[0].vq);
	na.num_rx_desc = virtqueue_get_vring_size(vi->rq[0].vq);
	na.num_tx_rings = na.num_rx_rings = vi->max_queue_pairs;
	na.rx_buf_maxsize = 0;
	na.nm_register = virtio_net_netmap_reg;
	na.nm_txsync = virtio_net_netmap_txsync;
	na.nm_rxsync = virtio_net_netmap_rxsync;
	na.nm_intr = virtio_net_netmap_intr;
	na.nm_config = NULL;

	netmap_attach(&na);
}

/* end of file */
