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
#include <sys/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <net/netmap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#define NETMAP_WITH_LIBS
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <net/netmap_user.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "fd_server.h"

#define ETH_ADDR_LEN 6

struct Event {
	unsigned evtype;
#define EVENT_TYPE_RX 0x1
#define EVENT_TYPE_TX 0x2
#define EVENT_TYPE_PAUSE 0x3
	unsigned num; /* > 1 if repeated event */

	/* Tx and Rx event. */
	unsigned pkt_len;
	char filler;

	/* Pause event. */
	unsigned long long usecs;
};

struct extra_buffer {
	uint32_t buf_idx;
	TAILQ_ENTRY(extra_buffer) list_entry;
};

;

struct Global {
	struct nm_desc *nmd;
	const char *ifname;
	unsigned wait_link_secs;    /* wait for link */
	unsigned timeout_secs;      /* transmit/receive timeout */
	int ignore_if_not_matching; /* ignore certain received packets */
	int success_if_no_receive;  /* exit status 0 if we receive no packets */
	int sequential_fill;        /* increment fill char for multi-packets
	                            operations */
	int request_from_fd_server; /* false --> directly open the interface */

#define LV_ERROR_MSG 1
#define LV_DEBUG_SEND_RECV 2
#define LV_DEBUG_EXTRA_BUF 3
#define LV_DEBUG_BUILD_PACKET 4
#define LV_DEBUG_PARSE_ARGS 5
	int verbosity_level;

	/* List of currently not in use normal buffers. */
	TAILQ_HEAD(extra_buf_head, extra_buffer) extra_buffers_head;
	unsigned extra_buffers_num; /* number of granted extra buffers */

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
	unsigned num_loops;
};

void release_if_fd(struct Global *, const char *);
void release_extra_buffers(struct Global *);

void
verbose_print(int current_verbosity, int required_verbosity, char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (current_verbosity >= required_verbosity) {
		vprintf(format, args);
	}

	va_end(args);
}

void
verbose_perror(int current_verbosity, int required_verbosity, char *str)
{
	if (current_verbosity >= required_verbosity) {
		perror(str);
	}
}

void
cleanup(struct Global *g)
{
	if (g->extra_buffers_num > 0) {
		release_extra_buffers(g);
	}

	if (g->request_from_fd_server) {
		release_if_fd(g, g->ifname);
	} else {
		nm_close(g->nmd);
	}
}

static void
fill_packet_field(struct Global *g, unsigned offset, const char *content,
                  unsigned content_len)
{
	if (offset + content_len > sizeof(g->pktm)) {
		verbose_print(g->verbosity_level, LV_ERROR_MSG,
		              "Packet layout overflow: %u + %u > %lu\n", offset,
		              content_len, sizeof(g->pktm));
		cleanup(g);
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
		if (sum > 0xFFFF) {
			sum -= 0xFFFF;
		}
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF) {
			sum -= 0xFFFF;
		}
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
	verbose_print(g->verbosity_level, LV_DEBUG_BUILD_PACKET,
	              "%s: starting at ofs %u\n", __func__, ofs);

	ethofs = ofs;
	(void)ethofs;
	/* Ethernet destination and source MAC address plus ethertype. */
	fill_packet_field(g, ofs, g->dst_mac, ETH_ADDR_LEN);
	ofs += ETH_ADDR_LEN;
	fill_packet_field(g, ofs, g->src_mac, ETH_ADDR_LEN);
	ofs += ETH_ADDR_LEN;
	fill_packet_16bit(g, ofs, ETHERTYPE_IP);
	ofs += 2;
	verbose_print(g->verbosity_level, LV_DEBUG_BUILD_PACKET,
	              "%s: eth done, ofs %u\n", __func__, ofs);

	ipofs = ofs;
	/* First byte of IP header. */
	fill_packet_8bit(g, ofs, (IPVERSION << 4) | ((sizeof(struct ip)) >> 2));
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
	        wrapsum(checksum(g->pktm + ipofs, sizeof(struct ip), 0)));
	verbose_print(g->verbosity_level, LV_DEBUG_BUILD_PACKET,
	              "%s: ip done, ofs %u\n", __func__, ofs);

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
	verbose_print(g->verbosity_level, LV_DEBUG_BUILD_PACKET,
	              "%s: udp done, ofs %u\n", __func__, ofs);

	/* Fill UDP payload. */
	pldofs = ofs;
	for (; ofs < g->pktm_len; ofs++) {
		fill_packet_8bit(g, ofs, g->filler);
	}
	verbose_print(g->verbosity_level, LV_DEBUG_BUILD_PACKET,
	              "%s: payload done, ofs %u\n", __func__, ofs);

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

// static unsigned
// tx_bytes_avail(struct netmap_ring *ring, unsigned max_frag_size)
// {
// 	unsigned avail_per_slot = ring->nr_buf_size;

// 	if (max_frag_size < avail_per_slot) {
// 		avail_per_slot = max_frag_size;
// 	}

// 	return nm_ring_space(ring) * avail_per_slot;
// }

static int
tx_flush(struct Global *g)
{
	struct nm_desc *nmd = g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	int i;

	for (;;) {
		int pending = 0;
		for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
			struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);

			pending += nm_tx_pending(ring);
		}

		if (!pending) {
			return 0;
		}

		if (elapsed_ms > g->timeout_secs * 1000) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "%s: Timeout\n", __func__);
			return -1;
		}

		usleep(wait_ms * 1000);
		elapsed_ms += wait_ms;

		ioctl(nmd->fd, NIOCTXSYNC, NULL);
	}
}

uint64_t
ring_avail_packets(struct netmap_ring *ring, unsigned pkt_len)
{
	uint64_t slot_per_packet;

	slot_per_packet = ceil((double)pkt_len / (double)ring->nr_buf_size);
	return nm_ring_space(ring) / slot_per_packet;
}

uint64_t
adapter_avail_sends(struct nm_desc *nmd, unsigned pkt_len)
{
	uint64_t sends_available = 0;
	unsigned int i;

	for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
		struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);

		sends_available += ring_avail_packets(ring, pkt_len);
	}

	return sends_available;
}

void
put_one_packet(struct Global *g, struct netmap_ring *ring)
{
	unsigned head  = ring->head;
	unsigned frags = 0;
	unsigned ofs   = 0;

	for (;;) {
		struct netmap_slot *slot = &ring->slot[head];
		char *buf                = NETMAP_BUF(ring, slot->buf_idx);
		unsigned copysize        = g->pktm_len - ofs;

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
		head        = nm_ring_next(ring, head);
		frags++;
		if (ofs >= g->pktm_len) {
			/* Last fragment. */
			assert(ofs == g->pktm_len);
			slot->flags = NS_REPORT;
			break;
		}
	}

	ring->head = ring->cur = head;
	verbose_print(g->verbosity_level, LV_DEBUG_SEND_RECV,
	              "packet (%u bytes, %u frags) placed to TX\n", g->pktm_len,
	              frags);
}

/* Used for multi-packets sequential send/receive actions */
char
next_fill(char cur_fill)
{
	if (cur_fill == 'z')
		return 'a';
	if (cur_fill == 'Z')
		return 'A';
	return ++cur_fill;
}

/* Transmit packets_num packets using any combination of TX rings. */
static int
tx(struct Global *g, unsigned packets_num)
{
	struct nm_desc *nmd = g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	unsigned int i;

	/* We cycle here until either we timeout or we find enough space. */
	for (;;) {
		if (adapter_avail_sends(nmd, g->pktm_len) >= packets_num) {
			break;
		}

		if (elapsed_ms > g->timeout_secs * 1000) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "%s: Timeout\n", __func__);
			return -1;
		}

		/* Retry after a short while. */
		usleep(wait_ms * 1000);
		elapsed_ms += wait_ms;
		ioctl(nmd->fd, NIOCTXSYNC, NULL);
	}

	/* Once we have enough space, we start filling slots. We might use
	 * multiple rings.
	 */
	for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
		struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);
		uint64_t ring_sends_num;

		for (ring_sends_num = ring_avail_packets(ring, g->pktm_len);
		     ring_sends_num > 0 && packets_num > 0;
		     --ring_sends_num, --packets_num) {
			put_one_packet(g, ring);

			if (g->sequential_fill == 1) {
				g->filler = next_fill(g->filler);
				build_packet(g);
			}
		}

		if (packets_num == 0) {
			break;
		}
	}

	assert(packets_num == 0);
	/* Once we're done we sync, sending all packets at once. */
	ioctl(nmd->fd, NIOCTXSYNC, NULL);
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

uint64_t
adapter_avail_receives(struct nm_desc *nmd, unsigned pkt_len)
{
	uint64_t receives_available = 0;
	unsigned int i;

	for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; i++) {
		struct netmap_ring *ring = NETMAP_RXRING(nmd->nifp, i);

		receives_available += ring_avail_packets(ring, pkt_len);
	}

	return receives_available;
}

static int
rx_check(struct Global *g)
{
	unsigned i;

	if (g->pktr_len != g->pktm_len) {
		verbose_print(g->verbosity_level, LV_ERROR_MSG,
		              "Received packet length (%u) different from "
		              "expected (%u bytes)\n",
		              g->pktr_len, g->pktm_len);
		return -1;
	}

	for (i = 0; i < g->pktr_len; i++) {
		if (g->pktr[i] != g->pktm[i]) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "Received packet differs from model at "
			              "offset %u (0x%02x!=0x%02x)\n",
			              i, g->pktr[i], (uint8_t)g->pktm[i]);
			return -1;
		}
	}

	return 0;
}

int
read_one_packet(struct Global *g, struct netmap_ring *ring)
{
	unsigned head = ring->head;
	int frags     = 0;

	g->pktr_len = 0;
	for (;;) {
		struct netmap_slot *slot = &ring->slot[head];
		char *buf                = NETMAP_BUF(ring, slot->buf_idx);

		if (g->pktr_len + slot->len > sizeof(g->pktr)) {
			/* Sanity check. */
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "Error: received packet too "
			              "large "
			              "(>= %u bytes) ",
			              g->pktr_len + slot->len);
			cleanup(g);
			exit(EXIT_FAILURE);
		}

		memcpy(g->pktr + g->pktr_len, buf, slot->len);
		g->pktr_len += slot->len;
		head = nm_ring_next(ring, head);
		frags++;
		if (!(slot->flags & NS_MOREFRAG)) {
			break;
		}

		if (head == ring->tail) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "warning: truncated packet "
			              "(len=%u)\n",
			              g->pktr_len);
			frags = -1;
			break;
		}
	}

	ring->head = ring->cur = head;
	verbose_print(g->verbosity_level, LV_DEBUG_SEND_RECV,
	              "packet (%u bytes, %d frags) received "
	              "from RX\n",
	              g->pktr_len, frags);
	return frags;
}

/* Receive packets_num packets from any combination of RX rings. */
static int
rx(struct Global *g, unsigned packets_num)
{
	struct nm_desc *nmd = g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	unsigned int i;

	/* We cycle here until either we timeout or we find enough space. */
	for (;;) {
	again:
		if (adapter_avail_receives(nmd, g->pktm_len) >= packets_num) {
			break;
		}

		if (elapsed_ms > g->timeout_secs * 1000) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "%s: Timeout\n", __func__);
			/* -n flag */
			return g->success_if_no_receive == 1 ? 0 : -1;
		}

		/* Retry after a short while. */
		usleep(wait_ms * 1000);
		elapsed_ms += wait_ms;
		ioctl(nmd->fd, NIOCRXSYNC, NULL);
	}

	/* Once we have enough space, we start reading packets. We might use
	 * multiple rings.
	 */
	for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; i++) {
		struct netmap_ring *ring = NETMAP_RXRING(nmd->nifp, i);
		uint64_t ring_receives_num;

		for (ring_receives_num = ring_avail_packets(ring, g->pktm_len);
		     ring_receives_num > 0 && packets_num > 0;
		     --ring_receives_num, --packets_num) {
			int frags = 0;

			frags = read_one_packet(g, ring);
			if (frags == -1) {
				break; /* Truncated packet, skip this ring. */
			}

			if (ignore_received_frame(g)) {
				verbose_print(g->verbosity_level,
				              LV_DEBUG_SEND_RECV,
				              "(ignoring packet with %u bytes "
				              "and "
				              "%d frags received from RX ring "
				              "#%d)\n",
				              g->pktr_len, frags, i);
				elapsed_ms = 0;
				/* We can go back there, because we're
				 * decrementing packets_num each time, therefore
				 * the we will wait only for the remaining
				 * packets.
				 */
				goto again;
			}

			/* As soon as we find a packet wich doesn't match our
			 * packet model we exit with status EXIT_FAILURE.
			 */
			if (rx_check(g)) {
				cleanup(g);
				exit(EXIT_FAILURE);
			}

			if (g->sequential_fill == 1) {
				g->filler = next_fill(g->filler);
				build_packet(g);
			}
		}

		if (packets_num == 0) {
			break;
		}
	}

	assert(packets_num == 0);
	/* Once we're done we sync, freeing all slots at once. */
	ioctl(nmd->fd, NIOCRXSYNC, NULL);
	return 0;
}

static int
parse_txrx_event(const char *opt, unsigned event_type, struct Event *event,
                 int verbosity_level)
{
	char *strbuf = strdup(opt);
	char *save   = strbuf;
	int more;
	char *c;
	int ret = -1;

	if (!strbuf || strlen(strbuf) == 0) {
		goto out;
	}

	event->evtype = event_type;
	event->filler = 'a';
	event->num    = 1;

	for (c = strbuf; *c != '\0' && *c != ':'; c++) {
	}
	more           = (*c == ':');
	*c             = '\0';
	event->pkt_len = atoi(strbuf);
	if (event->pkt_len == 0) {
		goto out;
	}
	if (more) {
		strbuf = c + 1;
		for (c = strbuf; *c != '\0' && *c != ':'; c++) {
		}
		more          = (*c == ':');
		*c            = '\0';
		event->filler = strbuf[0];
	}
	if (more) {
		strbuf = c + 1;
		for (c = strbuf; *c != '\0'; c++) {
		}
		event->num = atoi(strbuf);
		if (event->num == 0) {
			goto out;
		}
	}

	ret = 0;
	verbose_print(verbosity_level, LV_DEBUG_PARSE_ARGS, "parsed %u:%c:%u\n",
	              event->pkt_len, event->filler, event->num);
out:
	if (save) {
		free(save);
	}
	return ret;
}

static int
parse_pause_event(const char *opt, struct Event *event, int verbosity_level)
{
	char *strbuf = strdup(opt);
	char *save   = strbuf;
	unsigned mul = 1000000;
	int ret      = -1;

	while (*strbuf != '\0' && isdigit(*strbuf)) {
		strbuf++;
	}
	if (!strcmp(strbuf, "us")) {
		mul = 1;
	} else if (!strcmp(strbuf, "ms")) {
		mul = 1000;
	} else if (strcmp(strbuf, "s") && strcmp(strbuf, "")) {
		goto out;
	}

	event->evtype = EVENT_TYPE_PAUSE;
	event->usecs  = atoi(save);
	if (event->usecs == 0) {
		goto out;
	}

	event->usecs *= mul;
	event->num = 1;
	ret        = 0;
	verbose_print(verbosity_level, LV_DEBUG_PARSE_ARGS,
	              "parsed %llu usecs\n", event->usecs);
out:
	free(save);
	return ret;
}

static struct Global _g;

static void
usage(FILE *stream)
{
	fprintf(stream,
	        "usage: ./functional {-c | -o | -i | -I}\n"
	        "Required:\n"
	        "    -c (shuts down the fd server),\n"
	        "    -o (starts the fd server),\n"
	        "    -i NETMAP_PORT (requests the interface from the fd "
	        "server),\n"
	        "    -I NETMAP_PORT (directly opens the interface)\n"
	        "Optional:\n"
	        "    [-s SOURCE MAC ADDRESS (=0:0:0:0:0:0)]\n"
	        "    [-d DESTINATION MAC ADDRESS (=FF:FF:FF:FF:FF:FF)]\n"
	        "    [-F MAX_FRAGMENT_SIZE (=inf)]\n"
	        "    [-T TIMEOUT_SECS (=1)]\n"
	        "    [-w WAIT_FOR_LINK_SECS (=0)]\n"
	        "    [-t LEN[:FILLCHAR[:NUM]] (trasmit NUM packets with size "
	        "LEN bytes)]\n"
	        "    [-r LEN[:FILLCHAR[:NUM]] (expect to receive NUM packets "
	        "with size LEN bytes)]\n"
	        "    [-p NUM[us|ms|s]] (pause for NUM us/ms/s)]\n"
	        "    [-g (ignore ethernet frames with unmatching Ethernet "
	        "header)]\n"
	        "    [-n (exit status = 0 <==> no frames were received)]\n"
	        "    [-q (during multi-packets send/receive increments fill "
	        "character after each operation)]\n"
	        "    [-e NUM (use NUM extra buffers to send packets, "
	        "can only be used when with -I)]\n"
	        "    [-v (increment verbosity level)]\n"
	        "    [-C [NUM (=1)] (how many times to run the events)]\n"
	        "\nExample:\n"
	        "    $ ./functional -i netmap:lo -t 100 -r 100 -t 40:b:2 -r "
	        "40:b:2\n");
}

/* TODO: Move functions to communicate to the fd_server to another file */
/* Copied from nm_open() */
void
fill_nm_desc(struct nm_desc *des, struct nmreq *req, int fd)
{
	uint32_t nr_reg;

	memset(des, 0, sizeof(*des));
	des->self = des;
	des->fd   = fd;
	memcpy(&des->req, req, sizeof(des->req));
	nr_reg = req->nr_flags & NR_REG_MASK;

	if (nr_reg == NR_REG_SW) { /* host stack */
		des->first_tx_ring = des->last_tx_ring = des->req.nr_tx_rings;
		des->first_rx_ring = des->last_rx_ring = des->req.nr_rx_rings;
	} else if (nr_reg == NR_REG_ALL_NIC) { /* only nic */
		des->first_tx_ring = 0;
		des->first_rx_ring = 0;
		des->last_tx_ring  = des->req.nr_tx_rings - 1;
		des->last_rx_ring  = des->req.nr_rx_rings - 1;
	} else if (nr_reg == NR_REG_NIC_SW) {
		des->first_tx_ring = 0;
		des->first_rx_ring = 0;
		des->last_tx_ring  = des->req.nr_tx_rings;
		des->last_rx_ring  = des->req.nr_rx_rings;
	} else if (nr_reg == NR_REG_ONE_NIC) {
		/* XXX check validity */
		des->first_tx_ring = des->last_tx_ring = des->first_rx_ring =
		        des->last_rx_ring =
		                des->req.nr_ringid & NETMAP_RING_MASK;
	} else { /* pipes */
		des->first_tx_ring = des->last_tx_ring = 0;
		des->first_rx_ring = des->last_rx_ring = 0;
	}
}

int
connect_to_fd_server(struct Global *g)
{
	struct sockaddr_un name;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	int socket_fd;

	socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (socket_fd == -1) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "socket()");
		return -1;
	}

	memset(&name, 0, sizeof(name));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, SOCKET_NAME, sizeof(name.sun_path) - 1);
	name.sun_path[sizeof(name.sun_path) - 1] = '\0';
	while (connect(socket_fd, (const struct sockaddr *)&name,
	               sizeof(struct sockaddr_un)) == -1) {
		if (elapsed_ms > g->timeout_secs * 1000) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "%s: Timeout\n", __func__);
			return -1;
		}

		usleep(wait_ms * 1000);
		elapsed_ms += wait_ms;
	}

	return socket_fd;
}

void
start_fd_server(struct Global *g)
{
	int socket_fd;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "fork()");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		wait(NULL);
		return;
	}

	if (execl("fd_server", "fd_server", (char *)NULL)) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "exec()");
		exit(EXIT_FAILURE);
	}

	socket_fd = connect_to_fd_server(g);
	if (socket_fd == -1) {
		verbose_print(g->verbosity_level, LV_ERROR_MSG,
		              "Can't connect to fd_server\n");
		exit(EXIT_FAILURE);
	}
	close(socket_fd);
}

int
recv_fd(int socket, int *fd, void *buf, size_t buf_size)
{
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} ancillary;
	struct fd_response *res;
	struct cmsghdr *cmsg;
	struct iovec iov[1];
	struct msghdr msg;
	int amount;

	errno           = 0;
	iov[0].iov_base = buf;
	iov[0].iov_len  = buf_size;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = iov;
	msg.msg_iovlen = 1;
	memset(ancillary.buf, 0, sizeof(ancillary.buf));
	msg.msg_control    = ancillary.buf;
	msg.msg_controllen = sizeof(ancillary.buf);
	cmsg               = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level   = SOL_SOCKET;
	cmsg->cmsg_type    = SCM_RIGHTS;
	cmsg->cmsg_len     = CMSG_LEN(sizeof(int));
	amount             = recvmsg(socket, &msg, 0);
	if (amount == -1) {
		return -1;
	}

	res = iov[0].iov_base;
	if (res->result != 0) {
		errno = res->result;
		return -1;
	}

	/* If res->result == 0, we know for sure that a file descriptor has been
	 * sent through the ancillary data.
	 */
	cmsg = CMSG_FIRSTHDR(&msg);
	memcpy(fd, CMSG_DATA(cmsg), sizeof(int));

	return amount;
}

struct nm_desc *
get_if_fd(struct Global *g, const char *if_name)
{
	struct fd_response res;
	struct fd_request req;
	struct nm_desc *nmd;
	int socket_fd;
	int new_fd;
	int ret;

	socket_fd = connect_to_fd_server(g);
	if (socket_fd == -1) {
		exit(EXIT_FAILURE);
	}

	memset(&req, 0, sizeof(req));
	req.action = FD_GET;
	strncpy(req.if_name, if_name, sizeof(req.if_name));
	ret = send(socket_fd, &req, sizeof(req), 0);
	if (ret < 0) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "send()");
		return NULL;
	}

	memset(&res, 0, sizeof(res));
	ret = recv_fd(socket_fd, &new_fd, &res, sizeof(res));
	if (ret == -1) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "recv_fd()");
		return NULL;
	}
	close(socket_fd);

	nmd = malloc(sizeof(*nmd));
	if (nmd == NULL) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "malloc()");
		return NULL;
	}

	fill_nm_desc(nmd, &res.req, new_fd);
	if (nm_mmap(nmd, NULL) != 0) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "nm_mmap()");
		return NULL;
	}

	return nmd;
}

void
release_if_fd(struct Global *g, const char *if_name)
{
	struct fd_request req;
	int socket_fd;
	int ret;

	socket_fd = connect_to_fd_server(g);
	if (socket_fd == -1) {
		exit(EXIT_FAILURE);
	}

	memset(&req, 0, sizeof(req));
	req.action = FD_RELEASE;
	strncpy(req.if_name, if_name, sizeof(req.if_name));

	ret = send(socket_fd, &req, sizeof(req), 0);
	if (ret <= 0) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "send()");
	}

	close(socket_fd);
}

void
stop_fd_server(struct Global *g)
{
	struct fd_request req;
	int socket_fd;
	int ret;

	socket_fd = connect_to_fd_server(g);
	if (socket_fd == -1) {
		verbose_print(g->verbosity_level, LV_DEBUG_SEND_RECV,
		              "fd_server alredy down\n");
		return;
	}
	verbose_print(g->verbosity_level, LV_DEBUG_SEND_RECV,
	              "Shutting down fd_server\n");

	memset(&req, 0, sizeof(req));
	req.action = FD_STOP;
	ret        = send(socket_fd, &req, sizeof(req), 0);
	if (ret == -1) {
		verbose_perror(g->verbosity_level, LV_ERROR_MSG, "send()");
	}
	/* By calling recv() we synchronize with the fd_server closing the
	 * socket.
	 * This way we're sure that during the next call to ./functional
	 * the fd_server has alredy closed its end and we avoid a possible race
	 * condition. Otherwise the call to functional might connect to the
	 * previous fd_server backlog.
	 */
	recv(socket_fd, &req, sizeof(req), 0);
	close(socket_fd);
}

int
parse_mac_address(const char *opt, char *mac)
{
	if (6 == sscanf(opt, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
	                &mac[2], &mac[3], &mac[4], &mac[5])) {
		return 0;
	}
	return -1;
}

/* Uses the first adapter slot (any will do) to save the extra buffers indexes.
 */
int
parse_extra_buffers_indexes(struct Global *g)
{
	struct netmap_if *nifp   = g->nmd->nifp;
	struct netmap_ring *ring = NETMAP_TXRING(nifp, g->nmd->first_tx_ring);
	struct netmap_slot *slot = &ring->slot[ring->head];
	uint32_t extra_buf_index = nifp->ni_bufs_head;
	uint32_t real_index      = slot->buf_idx;
	struct extra_buffer *u_buf;
	unsigned i;

	verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "Parsing %u extra buffers:\n", g->extra_buffers_num);
	for (i = 0; i < g->extra_buffers_num; i++) {
		if (extra_buf_index == 0) {
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "   error, index = 0\n");
			return -1;
		}
		verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "   index = %u\n", extra_buf_index);

		u_buf = malloc(sizeof(*u_buf));
		if (u_buf == NULL) {
			verbose_perror(g->verbosity_level, LV_ERROR_MSG,
			               "malloc()");
			return -1;
		}
		u_buf->buf_idx = extra_buf_index;
		TAILQ_INSERT_HEAD(&g->extra_buffers_head, u_buf, list_entry);
		slot->buf_idx   = extra_buf_index;
		extra_buf_index = *(uint32_t *)NETMAP_BUF(ring, slot->buf_idx);
	}
	slot->buf_idx = real_index;

	return 0;
}

/* Loops through the adapter slots, swapping the default buffers with the
 * extra buffers. Keeps going until we run out of extra buffers, or adapter
 * slots.
 */
int
swap_in_extra_buffers(struct Global *g)
{
	unsigned extra_buffers_num = g->extra_buffers_num;
	unsigned int i;

	for (i = g->nmd->first_tx_ring; i <= g->nmd->last_tx_ring; i++) {
		struct netmap_ring *ring = NETMAP_TXRING(g->nmd->nifp, i);
		unsigned head;

		for (head = ring->head; head != ring->tail;
		     head = nm_ring_next(ring, head)) {
			struct extra_buffer *u_buf =
			        TAILQ_FIRST(&g->extra_buffers_head);
			struct netmap_slot *slot = &ring->slot[head];
			uint32_t real_index      = slot->buf_idx;

			if (u_buf == NULL) {
				/* We finished swapping in extra buffers */
				return 0;
			}

			slot->buf_idx = u_buf->buf_idx;
			slot->flags |= NS_BUF_CHANGED;
			u_buf->buf_idx = real_index;
			TAILQ_REMOVE(&g->extra_buffers_head, u_buf, list_entry);
			TAILQ_INSERT_TAIL(&g->extra_buffers_head, u_buf,
			                 list_entry);

			if (--extra_buffers_num == 0) {
				return 0;
			}
		}
	}

	/* This is reached if the adapter has less slots than the number of
	 * requested extra buffers. Nevertheless this is not a problem as the
	 * not in use extra buffers will will be released during cleanup().
	 */
	return 0;
}

/* We only re-build the extra buffers list, as requested from netmap. We don't
 * undo the swapping that we did at the start of the program to swap in the
 * extra buffer. This probably leaves the netmap adapter in an incosistent
 * state, that's why we only support this option for interfaces requested
 * directly.
 */
void
release_extra_buffers(struct Global *g)
{
	struct netmap_if *nifp   = g->nmd->nifp;
	struct netmap_ring *ring = NETMAP_TXRING(nifp, g->nmd->first_tx_ring);
	struct netmap_slot *slot = &ring->slot[ring->head];
	uint32_t real_index      = slot->buf_idx;
	struct extra_buffer *u_buf;
	uint32_t *next_extra_buffer;

	verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "Releasing %u extra buffers:\n", g->extra_buffers_num);
	if (TAILQ_EMPTY(&g->extra_buffers_head)) {
		return;
	}

	u_buf = TAILQ_FIRST(&g->extra_buffers_head);
	nifp->ni_bufs_head = u_buf->buf_idx;
	verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "   head index %u\n", nifp->ni_bufs_head);
	slot->buf_idx = u_buf->buf_idx;
	TAILQ_REMOVE(&g->extra_buffers_head, u_buf, list_entry);
	free(u_buf);

	while (!TAILQ_EMPTY(&g->extra_buffers_head)) {
		next_extra_buffer = (uint32_t *)NETMAP_BUF(ring, slot->buf_idx);
		u_buf = TAILQ_FIRST(&g->extra_buffers_head);
		verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "   index = %u\n", u_buf->buf_idx);
		*next_extra_buffer = u_buf->buf_idx;
		slot->buf_idx = u_buf->buf_idx;
		TAILQ_REMOVE(&g->extra_buffers_head, u_buf, list_entry);
		free(u_buf);
	}
	next_extra_buffer = (uint32_t *)NETMAP_BUF(ring, slot->buf_idx);
	*next_extra_buffer = 0;
	slot->buf_idx = real_index;
}

int
main(int argc, char **argv)
{
	struct Global *g = &_g;
	unsigned int i, c;
	int opt;
	int ret;

	g->nmd            = NULL;
	g->ifname         = NULL;
	g->wait_link_secs = 0;
	g->timeout_secs   = 1;
	g->pktm_len       = 60;
	g->max_frag_size  = ~0U; /* unlimited */
	for (i = 0; i < ETH_ADDR_LEN; i++) {
		g->src_mac[i] = 0x00;
	}
	for (i = 0; i < ETH_ADDR_LEN; i++) {
		g->dst_mac[i] = 0xFF;
	}
	g->src_ip                 = 0x0A000005; /* 10.0.0.5 */
	g->dst_ip                 = 0x0A000007; /* 10.0.0.7 */
	g->filler                 = 'a';
	g->num_events             = 0;
	g->ignore_if_not_matching = /*false=*/0;
	g->success_if_no_receive  = /*false=*/0;
	g->request_from_fd_server = /*true=*/1;
	g->sequential_fill        = /*false=*/0;
	g->extra_buffers_num      = 0;
	g->verbosity_level        = 0;
	g->num_loops              = 1;
	g->extra_buffers_num      = 0;
	TAILQ_INIT(&g->extra_buffers_head);

	while ((opt = getopt(argc, argv, "hconqe:s:d:i:I:w:F:T:t:r:gvp:C:")) !=
	       -1) {
		switch (opt) {
		case 'h':
			usage(stdout);
			return 0;

		/* TODO: move this option to fd_server */
		case 'c':
			stop_fd_server(g);
			return 0;

		/* TODO: move this option to fd_server */
		case 'o':
			start_fd_server(g);
			return 0;

		case 'n':
			g->success_if_no_receive = /*true=*/1;
			break;

		case 'q':
			g->sequential_fill = /*true=*/1;
			break;

		case 'e':
			g->extra_buffers_num = atoi(optarg);
			if (g->extra_buffers_num <= 0) {
				verbose_print(
				        g->verbosity_level, LV_ERROR_MSG,
				        "Invalid number of extra buffers\n");
				exit(EXIT_FAILURE);
			};
			verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "Requesting %u extra buffers\n", g->extra_buffers_num);
			break;

		case 's':
			ret = parse_mac_address(optarg, g->src_mac);
			if (ret == -1) {
				verbose_print(g->verbosity_level, LV_ERROR_MSG,
				              "Invalid source MAC address\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			ret = parse_mac_address(optarg, g->dst_mac);
			if (ret == -1) {
				verbose_print(
				        g->verbosity_level, LV_ERROR_MSG,
				        "Invalid destination MAC address\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'i':
			g->ifname = optarg;
			break;

		case 'I':
			g->ifname                 = optarg;
			g->request_from_fd_server = /*false=*/0;
			break;

		case 'F':
			g->max_frag_size = atoi(optarg);
			break;

		case 'w':
			g->wait_link_secs = atoi(optarg);
			break;

		case 'T':
			g->timeout_secs = atoi(optarg);
			break;

		case 't':
		case 'r':
		case 'p': {
			int ret = 0;

			if (g->num_events >= MAX_EVENTS) {
				verbose_print(g->verbosity_level, LV_ERROR_MSG,
				              "Too many events\n");
				exit(EXIT_FAILURE);
			}

			if (opt == 'p') {
				ret = parse_pause_event(
				        optarg, g->events + g->num_events,
				        g->verbosity_level);
			} else {
				ret = parse_txrx_event(
				        optarg,
				        (opt == 't') ? EVENT_TYPE_TX
				                     : EVENT_TYPE_RX,
				        g->events + g->num_events,
				        g->verbosity_level);
			}
			if (ret) {
				verbose_print(g->verbosity_level, LV_ERROR_MSG,
				              "Invalid event syntax '%s'\n",
				              optarg);
				usage(stderr);
				exit(EXIT_FAILURE);
			}
			g->num_events++;
			break;
		}

		case 'g':
			g->ignore_if_not_matching = 1;
			break;

		case 'v':
			g->verbosity_level++;
			break;

		case 'C':
			g->num_loops = atoi(optarg);
			if (g->num_loops == 0) {
				verbose_print(g->verbosity_level, LV_ERROR_MSG,
				              "Invalid -C option '%s'\n",
				              optarg);
				exit(EXIT_FAILURE);
			}
			break;

		default:
			verbose_print(g->verbosity_level, LV_ERROR_MSG,
			              "Unrecognized option %c\n", opt);
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (g->ifname == NULL) {
		verbose_print(g->verbosity_level, LV_ERROR_MSG,
		              "Missing ifname\n");
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	if (g->request_from_fd_server == 1 && g->extra_buffers_num > 0) {
		verbose_print(
		        g->verbosity_level, LV_ERROR_MSG,
		        "Extra buffers can only be used when requesting an "
		        "interface directly\n");
		exit(EXIT_FAILURE);
	}

	if (g->request_from_fd_server == 0) {
		/* We directly open the file descriptor. */
		if (g->extra_buffers_num > 0) {
			struct nmreq req;

			memset(&req, 0, sizeof(req));
			req.nr_arg3 = g->extra_buffers_num;
			g->nmd      = nm_open(g->ifname, &req, 0, NULL);
		} else {
			g->nmd = nm_open(g->ifname, NULL, 0, NULL);
		}
	} else {
		g->nmd = get_if_fd(g, g->ifname);
	}
	if (g->nmd == NULL) {
		verbose_print(g->verbosity_level, LV_ERROR_MSG,
		              "Failed to nm_open(%s)\n", g->ifname);
		exit(EXIT_FAILURE);
	}

	if (g->extra_buffers_num > 0) {
		/* Stores the real number of extra buffers. */
		g->extra_buffers_num = g->nmd->req.nr_arg3;
		verbose_print(g->verbosity_level, LV_DEBUG_EXTRA_BUF, "Received %u extra buffers\n", g->extra_buffers_num);
		ret = parse_extra_buffers_indexes(g);
		if (ret == -1) {
			cleanup(g);
			exit(EXIT_FAILURE);
		}

		swap_in_extra_buffers(g);
	}

	if (g->wait_link_secs > 0) {
		sleep(g->wait_link_secs);
	}

	for (c = 0; c < g->num_loops; c++) {
		for (i = 0; i < g->num_events; i++) {
			const struct Event *e = g->events + i;

			if (e->evtype == EVENT_TYPE_TX ||
			    e->evtype == EVENT_TYPE_RX) {
				g->filler   = e->filler;
				g->pktm_len = e->pkt_len;
				build_packet(g);
			}

			switch (e->evtype) {
			case EVENT_TYPE_TX:
				if (tx(g, e->num)) {
					cleanup(g);
					exit(EXIT_FAILURE);
				}
				break;

			case EVENT_TYPE_RX:
				if (rx(g, e->num)) {
					cleanup(g);
					exit(EXIT_FAILURE);
				}
				break;

			case EVENT_TYPE_PAUSE:
				usleep(e->usecs);
				break;
			}
		}
	}

	/* if we have sent something, wait for all tx to complete */
	tx_flush(g);
	cleanup(g);
	return 0;
}
