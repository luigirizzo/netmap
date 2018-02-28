/*
 * A tool for functional testing netmap transmission and reception.
 *
 * Copyright (C) 2018 Vincenzo Maffione. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
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
#include <assert.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/netmap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#define ETH_ADDR_LEN 6

struct Event {
	unsigned evtype;
#define EVENT_TYPE_RX 0x1
#define EVENT_TYPE_TX 0x2
	unsigned pkt_len;
	char filler;
	unsigned num;
};

struct Global {
	struct nm_desc *nmd;
	const char *ifname;
	unsigned wait_link_secs;    /* wait for link */
	unsigned timeout_secs;      /* transmit/receive timeout */
	int ignore_if_not_matching; /* ignore certain received packets */
	int verbose;

#define MAX_PKT_SIZE 65536
	char pktm[MAX_PKT_SIZE]; /* packet model */
	unsigned pktm_len;       /* packet model length */
	char pktr[MAX_PKT_SIZE]; /* packet received */
	unsigned pktr_len;       /* length of received packet */
	unsigned max_frag_size;  /* max bytes per netmap TX slot */

	char src_mac[ETH_ADDR_LEN];
	char dst_mac[ETH_ADDR_LEN];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	char filler;

#define MAX_EVENTS 64
	unsigned num_events;
	struct Event events[MAX_EVENTS];
};

static void
fill_packet_field(struct Global *g, unsigned offset, const char *content,
		  unsigned content_len)
{
	if (offset + content_len > sizeof(g->pktm)) {
		printf("Packet layout overflow: %u + %u > %lu\n", offset,
		       content_len, sizeof(g->pktm));
		exit(EXIT_FAILURE);
	}

	memcpy(g->pktm + offset, content, content_len);
}

static void
fill_packet_8bit(struct Global *g, unsigned offset, uint8_t val)
{
	fill_packet_field(g, offset, (const char *)&val, sizeof(val));
}

static void
fill_packet_16bit(struct Global *g, unsigned offset, uint16_t val)
{
	val = htons(val);
	fill_packet_field(g, offset, (const char *)&val, sizeof(val));
}

static void
fill_packet_32bit(struct Global *g, unsigned offset, uint32_t val)
{
	val = htonl(val);
	fill_packet_field(g, offset, (const char *)&val, sizeof(val));
}

/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum /* host endianness */)
{
	const uint8_t *addr = data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

static uint16_t
wrapsum(uint32_t sum /* host endianness */)
{
	sum = ~sum & 0xFFFF;
	return sum; /* host endianness */
}

static void
build_packet(struct Global *g)
{
	unsigned ofs = 0;
	unsigned ethofs;
	unsigned ipofs;
	unsigned udpofs;
	unsigned pldofs;

	memset(g->pktm, 0, sizeof(g->pktm));
	if (g->verbose) {
		printf("%s: starting at ofs %u\n", __func__, ofs);
	}

	ethofs = ofs;
	(void)ethofs;
	/* Ethernet destination and source MAC address plus ethertype. */
	fill_packet_field(g, ofs, g->dst_mac, ETH_ADDR_LEN);
	ofs += ETH_ADDR_LEN;
	fill_packet_field(g, ofs, g->src_mac, ETH_ADDR_LEN);
	ofs += ETH_ADDR_LEN;
	fill_packet_16bit(g, ofs, ETHERTYPE_IP);
	ofs += 2;
	if (g->verbose) {
		printf("%s: eth done, ofs %u\n", __func__, ofs);
	}

	ipofs = ofs;
	/* First byte of IP header. */
	fill_packet_8bit(g, ofs,
			 (IPVERSION << 4) | ((sizeof(struct iphdr)) >> 2));
	ofs += 1;
	/* Skip QoS byte. */
	ofs += 1;
	/* Total length. */
	fill_packet_16bit(g, ofs, g->pktm_len - ipofs);
	ofs += 2;
	/* Skip identification field. */
	ofs += 2;
	/* Offset (and flags) field. */
	fill_packet_16bit(g, ofs, IP_DF);
	ofs += 2;
	/* TTL. */
	fill_packet_8bit(g, ofs, IPDEFTTL);
	ofs += 1;
	/* Protocol. */
	fill_packet_8bit(g, ofs, IPPROTO_UDP);
	ofs += 1;
	/* Skip checksum for now. */
	ofs += 2;
	/* Source IP address. */
	fill_packet_32bit(g, ofs, g->src_ip);
	ofs += 4;
	/* Dst IP address. */
	fill_packet_32bit(g, ofs, g->dst_ip);
	ofs += 4;
	/* Now put the checksum. */
	fill_packet_16bit(
		g, ipofs + 10,
		wrapsum(checksum(g->pktm + ipofs, sizeof(struct iphdr), 0)));
	if (g->verbose) {
		printf("%s: ip done, ofs %u\n", __func__, ofs);
	}

	udpofs = ofs;
	/* UDP source port. */
	fill_packet_16bit(g, ofs, g->src_port);
	ofs += 2;
	/* UDP source port. */
	fill_packet_16bit(g, ofs, g->dst_port);
	ofs += 2;
	/* UDP length (UDP header + data). */
	fill_packet_16bit(g, ofs, g->pktm_len - udpofs);
	ofs += 2;
	/* Skip the UDP checksum for now. */
	ofs += 2;
	if (g->verbose) {
		printf("%s: udp done, ofs %u\n", __func__, ofs);
	}

	/* Fill UDP payload. */
	pldofs = ofs;
	for (; ofs < g->pktm_len; ofs++) {
		fill_packet_8bit(g, ofs, g->filler);
	}
	if (g->verbose) {
		printf("%s: payload done, ofs %u\n", __func__, ofs);
	}

	/* Put the UDP checksum now.
	 * Magic: taken from sbin/dhclient/packet.c */
	fill_packet_16bit(
		g, udpofs + 6,
		wrapsum(checksum(
			/* udp header */ g->pktm + udpofs,
			sizeof(struct udphdr),
			checksum(/* udp payload */ g->pktm + pldofs,
				 g->pktm_len - pldofs,
				 checksum(/* pseudo header */ g->pktm + ipofs +
						  12,
					  2 * sizeof(g->src_ip),
					  IPPROTO_UDP + (uint32_t)(g->pktm_len -
								   udpofs))))));
}

static unsigned
tx_bytes_avail(struct netmap_ring *ring, unsigned max_frag_size)
{
	unsigned avail_per_slot = ring->nr_buf_size;

	if (max_frag_size < avail_per_slot) {
		avail_per_slot = max_frag_size;
	}

	return nm_ring_space(ring) * avail_per_slot;
}

/* Transmit a single packet using any TX ring. */
static int
tx_one(struct Global *g)
{
	struct nm_desc *nmd = g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	unsigned int i;

	for (;;) {
		for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
			struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);
			unsigned head		 = ring->head;
			unsigned frags		 = 0;
			unsigned ofs		 = 0;

			if (tx_bytes_avail(ring, g->max_frag_size) <
			    g->pktm_len) {
				continue;
			}

			for (;;) {
				struct netmap_slot *slot = &ring->slot[head];
				char *buf = NETMAP_BUF(ring, slot->buf_idx);
				unsigned copysize = g->pktm_len - ofs;

				if (copysize > ring->nr_buf_size) {
					copysize = ring->nr_buf_size;
				}
				if (copysize > g->max_frag_size) {
					copysize = g->max_frag_size;
				}

				memcpy(buf, g->pktm + ofs, copysize);
				ofs += copysize;
				slot->len   = copysize;
				slot->flags = NS_MOREFRAG;
				head	= nm_ring_next(ring, head);
				frags++;
				if (ofs >= g->pktm_len) {
					/* Last fragment. */
					assert(ofs == g->pktm_len);
					slot->flags = NS_REPORT;
					break;
				}
			}

			ring->head = ring->cur = head;
			ioctl(nmd->fd, NIOCTXSYNC, NULL);
			printf("packet (%u bytes, %u frags) transmitted to TX "
			       "ring #%d\n",
			       g->pktm_len, frags, i);
			return 0;
		}

		if (elapsed_ms > g->timeout_secs * 1000) {
			printf("%s: Timeout\n", __func__);
			return -1;
		}

		/* Retry after a short while. */
		usleep(wait_ms * 1000);
		elapsed_ms += wait_ms;
		ioctl(nmd->fd, NIOCTXSYNC, NULL);
	}

	/* never reached */
	return 0;
}

/* If -I option is specified, we want to ignore frames that don't match
 * our expected ethernet header.
 * This function currently assumes that Ethernet header starts from
 * the beginning of the packet buffers. */
static int
ignore_received_frame(struct Global *g)
{
	if (!g->ignore_if_not_matching) {
		return 0; /* don't ignore */
	}

	if (g->pktr_len < 14 || memcmp(g->pktm, g->pktr, 14) != 0) {
		return 1; /* ignore */
	}

	return 0; /* don't ignore */
}

/* Receive a single packet from any RX ring. */
static int
rx_one(struct Global *g)
{
	struct nm_desc *nmd = g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	unsigned int i;

	for (;;) {
	again:
		for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; i++) {
			struct netmap_ring *ring = NETMAP_RXRING(nmd->nifp, i);
			unsigned int head	= ring->head;
			unsigned int frags       = 0;

			if (nm_ring_empty(ring)) {
				continue;
			}

			g->pktr_len = 0;
			for (;;) {
				struct netmap_slot *slot = &ring->slot[head];
				char *buf = NETMAP_BUF(ring, slot->buf_idx);

				if (g->pktr_len + slot->len > sizeof(g->pktr)) {
					/* Sanity check. */
					printf("Error: received packet too "
					       "large "
					       "(>= %u bytes) ",
					       g->pktr_len + slot->len);
					exit(EXIT_FAILURE);
				}
				memcpy(g->pktr + g->pktr_len, buf, slot->len);
				g->pktr_len += slot->len;
				head = nm_ring_next(ring, head);
				frags++;
				if (!(slot->flags & NS_MOREFRAG)) {
					break;
				}
			}
			ring->head = ring->cur = head;
			ioctl(nmd->fd, NIOCRXSYNC, NULL);
			if (ignore_received_frame(g)) {
				if (g->verbose) {
					printf("(ignoring packet with %u bytes "
					       "and "
					       "%u frags received from RX ring "
					       "#%d)\n",
					       g->pktr_len, frags, i);
				}
				elapsed_ms = 0;
				goto again;
			}
			printf("packet (%u bytes, %u frags) received "
			       "from RX "
			       "ring #%d\n",
			       g->pktr_len, frags, i);
			return 0;
		}

		if (elapsed_ms > g->timeout_secs * 1000) {
			printf("%s: Timeout\n", __func__);
			return -1;
		}

		/* Retry after a short while. */
		usleep(wait_ms * 1000);
		elapsed_ms += wait_ms;
		ioctl(nmd->fd, NIOCRXSYNC, NULL);
	}

	return 0;
}

static int
rx_check(struct Global *g)
{
	unsigned i;

	if (g->pktr_len != g->pktm_len) {
		printf("Received packet length (%u) different from "
		       "expected (%u bytes)\n",
		       g->pktr_len, g->pktm_len);
		return -1;
	}

	for (i = 0; i < g->pktr_len; i++) {
		if (g->pktr[i] != g->pktm[i]) {
			printf("Received packet differs from model at "
			       "offset %u (0x%02x!=0x%02x)\n",
			       i, g->pktr[i], (uint8_t)g->pktm[i]);
			return -1;
		}
	}

	return 0;
}

static int
parse_event(const char *opt, unsigned event_type, struct Event *event)
{
	char *strbuf = strdup(opt);
	char *save   = strbuf;
	int more;
	char *c;

	if (!strbuf || strlen(strbuf) == 0) {
		goto err;
	}

	event->evtype = event_type;
	event->filler = 'a';
	event->num    = 1;

	for (c = strbuf; *c != '\0' && *c != ':'; c++) {
	}
	more	   = (*c == ':');
	*c	     = '\0';
	event->pkt_len = atoi(strbuf);
	if (more) {
		strbuf = c + 1;
		for (c = strbuf; *c != '\0' && *c != ':'; c++) {
		}
		more	  = (*c == ':');
		*c	    = '\0';
		event->filler = strbuf[0];
	}
	if (more) {
		strbuf = c + 1;
		for (c = strbuf; *c != '\0'; c++) {
		}
		event->num = atoi(strbuf);
	}
#if 0
	printf("parsed %u:%c:%u\n", event->pkt_len, event->filler, event->num);
#endif
	return 0;
err:
	free(save);
	return -1;
}

static struct Global _g;

static void
usage(void)
{
	printf("usage: ./functional [-h]\n"
	       "    -i NETMAP_PORT\n"
	       "    [-F MAX_FRAGMENT_SIZE (=inf)]\n"
	       "    [-T TIMEOUT_SECS (=5)]\n"
	       "    [-w WAIT_LINK_SECS (=0)]\n"
	       "    [-t LEN[:FILLCHAR[:NUM]] (trasmit NUM packets with size "
	       "LEN bytes)]\n"
	       "    [-r LEN[:FILLCHAR[:NUM]] (expect to receive NUM packets "
	       "with size LEN bytes)]\n"
	       "    [-I (ignore ethernet frames with unmatching Ethernet "
	       "header)]\n"
	       "    [-v (increment verbosity level)]\n"
	       "\nExample:\n"
	       "    $ ./functional -i netmap:lo -t 100 -r 100 -t 40:b:2 -r "
	       "40:b:2\n");
}

int
main(int argc, char **argv)
{
	struct Global *g = &_g;
	int opt;
	unsigned int i;

	g->ifname	 = NULL;
	g->nmd		  = NULL;
	g->timeout_secs   = 5;
	g->wait_link_secs = 0;
	g->pktm_len       = 60;
	g->max_frag_size  = ~0U; /* unlimited */
	for (i = 0; i < ETH_ADDR_LEN; i++)
		g->src_mac[i] = 0x00;
	for (i = 0; i < ETH_ADDR_LEN; i++)
		g->dst_mac[i] = 0xFF;
	g->src_ip		  = 0x0A000005; /* 10.0.0.5 */
	g->dst_ip		  = 0x0A000007; /* 10.0.0.7 */
	g->filler		  = 'a';
	g->num_events		  = 0;
	g->ignore_if_not_matching = /*false=*/0;
	g->verbose		  = 0;

	while ((opt = getopt(argc, argv, "hi:w:F:T:t:r:Iv")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;

		case 'i':
			g->ifname = optarg;
			break;

		case 'w':
			g->wait_link_secs = atoi(optarg);
			break;

		case 'F':
			g->max_frag_size = atoi(optarg);
			break;

		case 'T':
			g->timeout_secs = atoi(optarg);
			break;

		case 't':
		case 'r':
			if (g->num_events >= MAX_EVENTS) {
				printf("Too many events\n");
				return -1;
			}

			if (parse_event(optarg,
					(opt == 't') ? EVENT_TYPE_TX
						     : EVENT_TYPE_RX,
					g->events + g->num_events)) {
				printf("Invalid event syntax '%s'\n", optarg);
				usage();
				return -1;
			}
			g->num_events++;
			break;

		case 'I':
			g->ignore_if_not_matching = 1;
			break;

		case 'v':
			g->verbose++;
			break;

		default:
			printf("    Unrecognized option %c\n", opt);
			usage();
			return -1;
		}
	}

	if (!g->ifname) {
		printf("Missing ifname\n");
		usage();
		return -1;
	}

	if (g->num_events < 1) {
		printf("No transmit/receive events specified\n");
		usage();
		return -1;
	}

	g->nmd = nm_open(g->ifname, NULL, 0, NULL);
	if (g->nmd == NULL) {
		printf("Failed to nm_open(%s)\n", g->ifname);
		return -1;
	}
	if (g->wait_link_secs > 0) {
		sleep(g->wait_link_secs);
	}

	for (i = 0; i < g->num_events; i++) {
		const struct Event *e = g->events + i;
		unsigned j;

		g->filler   = e->filler;
		g->pktm_len = e->pkt_len;
		build_packet(g);

		for (j = 0; j < e->num; j++) {
			if (e->evtype == EVENT_TYPE_TX) {
				if (tx_one(g)) {
					return -1;
				}

			} else if (e->evtype == EVENT_TYPE_RX) {
				if (rx_one(g)) {
					return -1;
				}
				if (rx_check(g)) {
					return -1;
				}
			}
		}
	}

	nm_close(g->nmd);

	return 0;
}
