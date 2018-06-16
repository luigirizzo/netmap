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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
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

struct Global {
	struct nm_desc nmd;
	const char *ifname;
	unsigned wait_link_secs;    /* wait for link */
	unsigned timeout_secs;      /* transmit/receive timeout */
	int ignore_if_not_matching; /* ignore certain received packets */
	int success_if_no_receive;
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
	unsigned num_loops;
};

void release_if_fd(const char *);

void
clean_exit(struct Global *g)
{

	release_if_fd(g->ifname);
	exit(EXIT_FAILURE);
}

static void
fill_packet_field(struct Global *g, unsigned offset, const char *content,
		  unsigned content_len)
{
	if (offset + content_len > sizeof(g->pktm)) {
		printf("Packet layout overflow: %u + %u > %lu\n", offset,
		       content_len, sizeof(g->pktm));
		clean_exit(g);
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

static int
tx_flush(struct Global *g)
{
	struct nm_desc *nmd = &g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	int i;

	for (;;) {
		int pending = 0;
		for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
			struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);

			pending += nm_tx_pending(ring);
		}

		if (!pending)
			return 0;

		if (elapsed_ms > g->timeout_secs * 1000) {
			printf("%s: Timeout\n", __func__);
			return -1;
		}

		if (elapsed_ms > 0) {
			usleep(wait_ms * 1000);
			elapsed_ms += wait_ms;
		}

		ioctl(nmd->fd, NIOCTXSYNC, NULL);
	}
}

/* Transmit a single packet using any TX ring. */
static int
tx_one(struct Global *g)
{
	struct nm_desc *nmd = &g->nmd;
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
	struct nm_desc *nmd = &g->nmd;
	unsigned elapsed_ms = 0;
	unsigned wait_ms    = 100;
	unsigned int i;

	for (;;) {
	again:
		for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; i++) {
			struct netmap_ring *ring = NETMAP_RXRING(nmd->nifp, i);
			unsigned int head	= ring->head;
			unsigned int frags       = 0;
			int truncated		 = 0;

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
					clean_exit(g);
				}
				memcpy(g->pktr + g->pktr_len, buf, slot->len);
				g->pktr_len += slot->len;
				head = nm_ring_next(ring, head);
				frags++;
				if (!(slot->flags & NS_MOREFRAG)) {
					break;
				}
				if (head == ring->tail) {
					printf("warning: truncated packet "
					       "(len=%u)\n",
					       g->pktr_len);
					truncated = 1;
					break;
				}
			}
			if (truncated) {
				continue; /* skip this ring */
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
			return g->success_if_no_receive == 1 ? -1 : 0;
		}

		if (elapsed_ms > g->timeout_secs * 1000) {
			printf("%s: Timeout\n", __func__);
			return g->success_if_no_receive == 1 ? 0 : -1;
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
parse_txrx_event(const char *opt, unsigned event_type, struct Event *event)
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
	more	   = (*c == ':');
	*c	     = '\0';
	event->pkt_len = atoi(strbuf);
	if (event->pkt_len == 0) {
		goto out;
	}
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
		if (event->num == 0) {
			goto out;
		}
	}

	ret = 0;
#if 0
	printf("parsed %u:%c:%u\n", event->pkt_len, event->filler, event->num);
#endif
out:
	if (save) {
		free(save);
	}
	return ret;
}

static int
parse_pause_event(const char *opt, struct Event *event)
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
	ret	= 0;
out:
#if 0
	printf("parsed %llu usecs\n", event->usecs);
#endif
	free(save);
	return ret;
}

static struct Global _g;

static void
usage(void)
{
	printf("usage: ./functional [-h] "
	       "[-s (shuts down the file descriptor server)]\n"
	       "    -i NETMAP_PORT\n"
	       "    [-F MAX_FRAGMENT_SIZE (=inf)]\n"
	       "    [-T TIMEOUT_SECS (=5)]\n"
	       "    [-w WAIT_FOR_LINK_SECS (=0)]\n"
	       "    [-t LEN[:FILLCHAR[:NUM]] (trasmit NUM packets with size "
	       "LEN bytes)]\n"
	       "    [-r LEN[:FILLCHAR[:NUM]] (expect to receive NUM packets "
	       "with size LEN bytes)\n"
	       "    [-p NUM[us|ms|s]] (pause for NUM us/ms/s)]\n"
	       "    [-I (ignore ethernet frames with unmatching Ethernet "
	       "header)]\n"
	       "    [-v (increment verbosity level)]\n"
	       "    [-C [NUM (=1)] (how many times to run the events)]\n"
	       "\nExample:\n"
	       "    $ ./functional -i netmap:lo -t 100 -r 100 -t 40:b:2 -r "
	       "40:b:2\n");
}


/* Copied from nm_open() */
void
fill_nm_desc(struct nm_desc *des, struct nmreq *req, int fd)
{
	uint32_t nr_reg;

	memset(des, 0, sizeof(*des));
	des->self = des;
	des->fd = fd;
	memcpy(&des->req, req, sizeof(des->req));
	nr_reg = req->nr_flags & NR_REG_MASK;

	if (nr_reg == NR_REG_SW) { /* host stack */
		des->first_tx_ring = des->last_tx_ring = des->req.nr_tx_rings;
		des->first_rx_ring = des->last_rx_ring = des->req.nr_rx_rings;
	} else if (nr_reg ==  NR_REG_ALL_NIC) { /* only nic */
		des->first_tx_ring = 0;
		des->first_rx_ring = 0;
		des->last_tx_ring = des->req.nr_tx_rings - 1;
		des->last_rx_ring = des->req.nr_rx_rings - 1;
	} else if (nr_reg ==  NR_REG_NIC_SW) {
		des->first_tx_ring = 0;
		des->first_rx_ring = 0;
		des->last_tx_ring = des->req.nr_tx_rings;
		des->last_rx_ring = des->req.nr_rx_rings;
	} else if (nr_reg == NR_REG_ONE_NIC) {
		/* XXX check validity */
		des->first_tx_ring = des->last_tx_ring =
		des->first_rx_ring = des->last_rx_ring = des->req.nr_ringid & NETMAP_RING_MASK;
	} else { /* pipes */
		des->first_tx_ring = des->last_tx_ring = 0;
		des->first_rx_ring = des->last_rx_ring = 0;
	}
}

#define MS_WAIT 10

void
start_fd_server(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		/* The fd_server needs to create the unix socket. Sleeping does
		 * not guarantee a correct synchronization, but should be good
		 * enough.
		 */
		usleep(MS_WAIT * 1000);
		return;
	}

	execl("fd_server", "fd_server", (char *)NULL);
}

#define SOCKET_NAME "/tmp/my_unix_socket"

int
connect_to_fd_server(void)
{
	struct sockaddr_un name;
	int socket_fd;
	int ret;

	socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (socket_fd == -1) {
		perror("socket()");
		return -1;
	}

	memset(&name, 0, sizeof(struct sockaddr_un));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, SOCKET_NAME, sizeof(name.sun_path) - 1);
	name.sun_path[sizeof(name.sun_path) - 1] = '\0';
	ret = connect(socket_fd, (const struct sockaddr *)&name,
		sizeof(struct sockaddr_un));
	if (ret == 0) {
		return socket_fd;
	}

	printf("fd_server offline\n");
	return ret;
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

	errno = 0;

	iov[0].iov_base = buf;
	iov[0].iov_len = buf_size;

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	memset(ancillary.buf, 0, sizeof(ancillary.buf));
	msg.msg_control = ancillary.buf;
	msg.msg_controllen = sizeof(ancillary.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	amount = recvmsg(socket, &msg, 0);
	if (amount < 0) {
		return amount;
	}

	res = iov[0].iov_base;
	if (res->result != 0) {
		errno = res->result;
		return -1;
	}

	/* If res->result == 0, we know for sure that a file descriptor has been
	 * sent through the ancillary data.
	 */
	if (amount > 0) {
		cmsg = CMSG_FIRSTHDR(&msg);
		*fd = *(int *)CMSG_DATA(cmsg);
	}

	return amount;
}

int
get_if_fd(const char *if_name, struct nm_desc *nmd)
{
	struct fd_response res;
	struct fd_request req;
	int socket_fd;
	int new_fd;
	int ret;

	socket_fd = connect_to_fd_server();

	memset(&req, 0, sizeof(req));
	req.action = FD_GET;
	strncpy(req.if_name, if_name, sizeof(req.if_name));
	ret = send(socket_fd, &req, sizeof(struct fd_request), 0);
	if (ret < 0) {
		perror("send()");
		return -1;
	}

	memset(&res, 0, sizeof(res));
	ret = recv_fd(socket_fd, &new_fd, &res, sizeof(struct fd_response));
	if (ret < 0) {
		perror("recv_fd()");
		return -1;
	}

	fill_nm_desc(nmd, &res.req, new_fd);
	if (nm_mmap(nmd, NULL) != 0) {
		perror("nm_mmap()");
		return -1;
	}

	close(socket_fd);
	return 0;
}

void
release_if_fd(const char *if_name)
{
	struct fd_request req;
	int socket_fd;
	int ret;

	socket_fd = connect_to_fd_server();

	memset(&req, 0, sizeof(req));
	req.action = FD_RELEASE;
	strncpy(req.if_name, if_name, sizeof(req.if_name));

	ret = send(socket_fd, &req, sizeof(struct fd_request), 0);
	if (ret <= 0) {
		perror("send()");
	}

	close(socket_fd);
}

void
stop_fd_server(void)
{
	struct fd_request req;
	int socket_fd;
	int ret;

	socket_fd = connect_to_fd_server();
	if (socket_fd == -1) {
		printf("server alredy down\n");
		return;
	}
	printf("shutting down fd_server\n");

	memset(&req, 0, sizeof(req));
	req.action = FD_STOP;
	ret = send(socket_fd, &req, sizeof(struct fd_request), 0);
	if (ret <= 0) {
		perror("send()");
	}
	close(socket_fd);
}

int
parse_mac_address(const char *opt, char *mac)
{
	if (6 == sscanf(opt, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5])) {
		return 0;
	}
	return -1;
}

int
main(int argc, char **argv)
{
	struct Global *g = &_g;
	unsigned int i, c;
	int opt;
	int ret;

	g->ifname	 = NULL;
	g->wait_link_secs = 0;
	g->timeout_secs   = 5;
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
	g->success_if_no_receive  = /*false=*/0;
	g->verbose		  = 0;
	g->num_loops		  = 1;
	memset(&g->nmd, 0, sizeof(struct nm_desc));

	while ((opt = getopt(argc, argv, "hcons:d:i:w:F:T:t:r:Ivp:C:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;

		case 'c':
			stop_fd_server();
			return 0;

		case 'o':
			start_fd_server();
			return 0;

		case 'n':
			/* Not receiving means timing out */
			g->success_if_no_receive = 1;
			return 0;

		case 's':
			ret = parse_mac_address(optarg, g->src_mac);
			if (ret == -1) {
				printf("Invalid source MAC address\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			ret = parse_mac_address(optarg, g->dst_mac);
			if (ret == -1) {
				printf("Invalid destination MAC address\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'i':
			g->ifname = optarg;
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
				printf("Too many events\n");
				return -1;
			}

			if (opt == 'p') {
				ret = parse_pause_event(
					optarg, g->events + g->num_events);
			} else {
				ret = parse_txrx_event(
					optarg,
					(opt == 't') ? EVENT_TYPE_TX
						     : EVENT_TYPE_RX,
					g->events + g->num_events);
			}
			if (ret) {
				printf("Invalid event syntax '%s'\n", optarg);
				usage();
				return -1;
			}
			g->num_events++;
			break;
		}

		case 'I':
			g->ignore_if_not_matching = 1;
			break;

		case 'v':
			g->verbose++;
			break;

		case 'C':
			g->num_loops = atoi(optarg);
			if (g->num_loops == 0) {
				printf("Invalid -C option '%s'\n", optarg);
				return -1;
			}
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
		printf("No transmit/receive/pause events specified\n");
		usage();
		return -1;
	}

	if (get_if_fd(g->ifname, &g->nmd) < 0) {
		printf("Failed to nm_open(%s)\n", g->ifname);
		return -1;
	}

	if (g->wait_link_secs > 0) {
		sleep(g->wait_link_secs);
	}

	for (c = 0; c < g->num_loops; c++) {
		for (i = 0; i < g->num_events; i++) {
			const struct Event *e = g->events + i;
			unsigned j;

			if (e->evtype == EVENT_TYPE_TX ||
			    e->evtype == EVENT_TYPE_RX) {
				g->filler   = e->filler;
				g->pktm_len = e->pkt_len;
				build_packet(g);
			}

			for (j = 0; j < e->num; j++) {
				printf("%d: ", j);
				switch (e->evtype) {
				case EVENT_TYPE_TX:
					if (tx_one(g)) {
						clean_exit(g);
					}
					break;

				case EVENT_TYPE_RX:
					if (rx_one(g)) {
						clean_exit(g);
					}
					if (rx_check(g)) {
						clean_exit(g);
					}
					break;

				case EVENT_TYPE_PAUSE:
					usleep(e->usecs);
					break;
				}
			}
		}
	}

	/* if we have sent something, wait for all tx to complete */
	tx_flush(g);

	release_if_fd(g->ifname);

	return 0;
}
