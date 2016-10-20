/*
 ** Copyright (c) 2015, Asim Jamshed, Robin Sommer, Seth Hall
 ** and the International Computer Science Institute. All rights reserved.
 **
 ** Redistribution and use in source and binary forms, with or without
 ** modification, are permitted provided that the following conditions are met:
 **
 ** (1) Redistributions of source code must retain the above copyright
 **     notice, this list of conditions and the following disclaimer.
 **
 ** (2) Redistributions in binary form must reproduce the above copyright
 **     notice, this list of conditions and the following disclaimer in the
 **     documentation and/or other materials provided with the distribution.
 **
 **
 ** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 ** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 ** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ** ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 ** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 ** CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 ** SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 ** INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 ** CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ** ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 ** POSSIBILITY OF SUCH DAMAGE.
 **/
/* for func prototypes */
#include "pkt_hash.h"

/* Make Linux headers choose BSD versions of some of the data structures */
#define __FAVOR_BSD

/* for types */
#include <sys/types.h>
/* for [n/h]to[h/n][ls] */
#include <netinet/in.h>
/* iphdr */
#include <netinet/ip.h>
/* ipv6hdr */
#include <netinet/ip6.h>
/* tcphdr */
#include <netinet/tcp.h>
/* udphdr */
#include <netinet/udp.h>
/* eth hdr */
#include <net/ethernet.h>
/* for memset */
#include <string.h>

//#include <libnet.h>
/*---------------------------------------------------------------------*/
/**
 *  * The cache table is used to pick a nice seed for the hash value. It is
 *   * built only once when sym_hash_fn is called for the very first time
 *    */
static void
build_sym_key_cache(uint32_t *cache, int cache_len)
{
	static const uint8_t key[] = {
		0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0xcb, 0x2b, 0x5a, 0x5a,
		0xb4, 0x30, 0x7b, 0xae,
                0xa3, 0x2d, 0xcb, 0x77,
                0x0c, 0xf2, 0x30, 0x80,
                0x3b, 0xb7, 0x42, 0x6a,
                0xfa, 0x01, 0xac, 0xbe};

        uint32_t result = (((uint32_t)key[0]) << 24) |
                (((uint32_t)key[1]) << 16) |
                (((uint32_t)key[2]) << 8)  |
                ((uint32_t)key[3]);

        uint32_t idx = 32;
        int i;

        for (i = 0; i < cache_len; i++, idx++) {
                uint8_t shift = (idx % (sizeof(uint8_t) * 8));
                uint32_t bit;

                cache[i] = result;
                bit = ((key[idx/(sizeof(uint8_t) * 8)] << shift)
		       & 0x80) ? 1 : 0;
                result = ((result << 1) | bit);
        }
}
/*---------------------------------------------------------------------*/
/**
 ** Computes symmetric hash based on the 4-tuple header data
 **/
static uint32_t
sym_hash_fn(uint32_t sip, uint32_t dip, uint16_t sp, uint32_t dp)
{
#define MSB32				0x80000000
#define MSB16				0x8000
#define KEY_CACHE_LEN			96

	uint32_t rc = 0;
	int i;
	static int first_time = 1;
	static uint32_t key_cache[KEY_CACHE_LEN] = {0};

	if (first_time) {
		build_sym_key_cache(key_cache, KEY_CACHE_LEN);
		first_time = 0;
	}

	for (i = 0; i < 32; i++) {
                if (sip & MSB32)
                        rc ^= key_cache[i];
                sip <<= 1;
        }
        for (i = 0; i < 32; i++) {
                if (dip & MSB32)
			rc ^= key_cache[32+i];
                dip <<= 1;
        }
        for (i = 0; i < 16; i++) {
		if (sp & MSB16)
                        rc ^= key_cache[64+i];
                sp <<= 1;
        }
        for (i = 0; i < 16; i++) {
                if (dp & MSB16)
                        rc ^= key_cache[80+i];
                dp <<= 1;
        }

	return rc;
}
/*---------------------------------------------------------------------*/
/**
 ** Parser + hash function for the IPv4 packet
 **/
static uint32_t
decode_ip_n_hash(struct ip *iph, uint8_t hash_split, uint8_t seed)
{
	uint32_t rc = 0;

	if (hash_split == 2) {
		rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
			ntohl(iph->ip_dst.s_addr),
			ntohs(0xFFFD) + seed,
			ntohs(0xFFFE) + seed);
	} else {
		struct tcphdr *tcph = NULL;
		struct udphdr *udph = NULL;

		switch (iph->ip_p) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)((uint8_t *)iph + (iph->ip_hl<<2));
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
					 ntohl(iph->ip_dst.s_addr),
					 ntohs(tcph->th_sport) + seed,
					 ntohs(tcph->th_dport) + seed);
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *)((uint8_t *)iph + (iph->ip_hl<<2));
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
					 ntohl(iph->ip_dst.s_addr),
					 ntohs(udph->uh_sport) + seed,
					 ntohs(udph->uh_dport) + seed);
			break;
		case IPPROTO_IPIP:
			/* tunneling */
			rc = decode_ip_n_hash((struct ip *)((uint8_t *)iph + (iph->ip_hl<<2)),
					      hash_split, seed);
			break;
		default:
			/*
			 ** the hash strength (although weaker but) should still hold
			 ** even with 2 fields
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
					 ntohl(iph->ip_dst.s_addr),
					 ntohs(0xFFFD) + seed,
					 ntohs(0xFFFE) + seed);
			 **/
			// We return 0 to indicate that the packet couldn't be balanced.
			return 0;
			break;
		}
	}
	return rc;
}
/*---------------------------------------------------------------------*/
/**
 ** Parser + hash function for the IPv6 packet
 **/
static uint32_t
decode_ipv6_n_hash(struct ip6_hdr *ipv6h, uint8_t hash_split, uint8_t seed)
{
	uint32_t saddr, daddr;
	uint32_t rc = 0;

	/* Get only the first 4 octets */
	saddr = ipv6h->ip6_src.s6_addr[0] |
		(ipv6h->ip6_src.s6_addr[1] << 8) |
		(ipv6h->ip6_src.s6_addr[2] << 16) |
		(ipv6h->ip6_src.s6_addr[3] << 24);
	daddr = ipv6h->ip6_dst.s6_addr[0] |
		(ipv6h->ip6_dst.s6_addr[1] << 8) |
		(ipv6h->ip6_dst.s6_addr[2] << 16) |
		(ipv6h->ip6_dst.s6_addr[3] << 24);

	if (hash_split == 2) {
		rc = sym_hash_fn(ntohl(saddr),
				 ntohl(daddr),
				 ntohs(0xFFFD) + seed,
				 ntohs(0xFFFE) + seed);
	} else {
		struct tcphdr *tcph = NULL;
		struct udphdr *udph = NULL;

		switch(ntohs(ipv6h->ip6_ctlun.ip6_un1.ip6_un1_nxt)) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(ipv6h + 1);
			rc = sym_hash_fn(ntohl(saddr),
					 ntohl(daddr),
					 ntohs(tcph->th_sport) + seed,
					 ntohs(tcph->th_dport) + seed);
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *)(ipv6h + 1);
			rc = sym_hash_fn(ntohl(saddr),
					 ntohl(daddr),
					 ntohs(udph->uh_sport) + seed,
					 ntohs(udph->uh_dport) + seed);
			break;
		case IPPROTO_IPIP:
			/* tunneling */
			rc = decode_ip_n_hash((struct ip *)(ipv6h + 1),
					      hash_split, seed);
			break;
		case IPPROTO_IPV6:
			/* tunneling */
			rc = decode_ipv6_n_hash((struct ip6_hdr *)(ipv6h + 1),
						hash_split, seed);
			break;
		case IPPROTO_ICMP:
		case IPPROTO_GRE:
		case IPPROTO_ESP:
		case IPPROTO_PIM:
		case IPPROTO_IGMP:
		default:
			/*
			 ** the hash strength (although weaker but) should still hold
			 ** even with 2 fields
			 **/
			rc = sym_hash_fn(ntohl(saddr),
					 ntohl(daddr),
					 ntohs(0xFFFD) + seed,
					 ntohs(0xFFFE) + seed);
		}
	}
	return rc;
}
/*---------------------------------------------------------------------*/
/**
 *  *  A temp solution while hash for other protocols are filled...
 *   * (See decode_vlan_n_hash & pkt_hdr_hash functions).
 *    */
static uint32_t
decode_others_n_hash(struct ether_header *ethh, uint8_t seed)
{
	uint32_t saddr, daddr, rc;

	saddr = ethh->ether_shost[5] |
		(ethh->ether_shost[4] << 8) |
		(ethh->ether_shost[3] << 16) |
		(ethh->ether_shost[2] << 24);
	daddr = ethh->ether_dhost[5] |
		(ethh->ether_dhost[4] << 8) |
		(ethh->ether_dhost[3] << 16) |
		(ethh->ether_dhost[2] << 24);

	rc = sym_hash_fn(ntohl(saddr),
			 ntohl(daddr),
			 ntohs(0xFFFD) + seed,
			 ntohs(0xFFFE) + seed);

	return rc;
}
/*---------------------------------------------------------------------*/
/**
 ** Parser + hash function for VLAN packet
 **/
static inline uint32_t
decode_vlan_n_hash(struct ether_header *ethh, uint8_t hash_split, uint8_t seed)
{
	uint32_t rc = 0;
	struct vlanhdr *vhdr = (struct vlanhdr *)(ethh + 1);

	switch (ntohs(vhdr->proto)) {
	case ETHERTYPE_IP:
		rc = decode_ip_n_hash((struct ip *)(vhdr + 1),
				      hash_split, seed);
		break;
	case ETHERTYPE_IPV6:
		rc = decode_ipv6_n_hash((struct ip6_hdr *)(vhdr + 1),
					hash_split, seed);
		break;
	case ETHERTYPE_ARP:
	default:
		/* others */
		rc = decode_others_n_hash(ethh, seed);
		break;
	}
	return rc;
}
/*---------------------------------------------------------------------*/
/**
 ** General parser + hash function...
 **/
uint32_t
pkt_hdr_hash(const unsigned char *buffer, uint8_t hash_split, uint8_t seed)
{
	int rc = 0;
	struct ether_header *ethh = (struct ether_header *)buffer;

	switch (ntohs(ethh->ether_type)) {
	case ETHERTYPE_IP:
		rc = decode_ip_n_hash((struct ip *)(ethh + 1),
				      hash_split, seed);
		break;
	case ETHERTYPE_IPV6:
		rc = decode_ipv6_n_hash((struct ip6_hdr *)(ethh + 1),
					hash_split, seed);
		break;
	case ETHERTYPE_VLAN:
		rc = decode_vlan_n_hash(ethh, hash_split, seed);
		break;
	case ETHERTYPE_ARP:
	default:
		/* others */
		rc = decode_others_n_hash(ethh, seed);
		break;
	}

	return rc;
}
/*---------------------------------------------------------------------*/

