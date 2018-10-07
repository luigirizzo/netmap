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

/*************************************************************************/
/* COMPATIBILITY LAYER                                                   */
/*************************************************************************/

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

static inline bool virtio_legacy_is_little_endian(void)
{
#ifdef __LITTLE_ENDIAN
	return true;
#else
	return false;
#endif
}

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


/*************************************************************************/
/* NETMAP SUPPORT                                                        */
/*************************************************************************/

static void
virtio_net_netmap_attach(struct virtnet_info *vi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = vi->dev;
	na.na_flags = 0;
	na.num_tx_desc = 1;
	na.num_rx_desc = 1;
	na.num_tx_rings = na.num_rx_rings = 1;
	na.rx_buf_maxsize = 0;
	na.nm_register = NULL;
	na.nm_txsync = NULL;
	na.nm_rxsync = NULL;
	na.nm_intr = NULL;
	na.nm_config = NULL;

	netmap_attach(&na);
}

/* end of file */
