/*
 * Copyright (C) 2016 Broala and Universita` di Pisa. All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <inttypes.h>
#include <syslog.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include <netinet/in.h>		/* htonl */

#include <pthread.h>

#include "pkt_hash.h"
#include "ctrs.h"


/*
 * use our version of header structs, rather than bringing in a ton
 * of platform specific ones
 */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct compact_eth_hdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	u_int16_t h_proto;
};

struct compact_ip_hdr {
	u_int8_t ihl:4, version:4;
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct compact_ipv6_hdr {
	u_int8_t priority:4, version:4;
	u_int8_t flow_lbl[3];
	u_int16_t payload_len;
	u_int8_t nexthdr;
	u_int8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

#define MAX_IFNAMELEN 	64
#define DEF_OUT_PIPES 	2
#define DEF_EXTRA_BUFS 	0
#define DEF_BATCH	2048
#define DEF_WAIT_LINK	2
#define DEF_SYSLOG_INT	600
#define BUF_REVOKE	100

struct {
	char ifname[MAX_IFNAMELEN];
	char base_name[MAX_IFNAMELEN];
	int netmap_fd;
	uint16_t output_rings;
	uint16_t num_groups;
	uint32_t extra_bufs;
	uint16_t batch;
	int syslog_interval;
	int wait_link;
} glob_arg;

/*
 * the overflow queue is a circular queue of buffers
 */
struct overflow_queue {
	char name[MAX_IFNAMELEN];
	struct netmap_slot *slots;
	uint32_t head;
	uint32_t tail;
	uint32_t n;
	uint32_t size;
};

struct overflow_queue *freeq;

static inline int
oq_full(struct overflow_queue *q)
{
	return q->n >= q->size;
}

static inline int
oq_empty(struct overflow_queue *q)
{
	return q->n <= 0;
}

static inline void
oq_enq(struct overflow_queue *q, const struct netmap_slot *s)
{
	if (unlikely(oq_full(q))) {
		D("%s: queue full!", q->name);
		abort();
	}
	q->slots[q->tail] = *s;
	q->n++;
	q->tail++;
	if (q->tail >= q->size)
		q->tail = 0;
}

static inline struct netmap_slot
oq_deq(struct overflow_queue *q)
{
	struct netmap_slot s = q->slots[q->head];
	if (unlikely(oq_empty(q))) {
		D("%s: queue empty!", q->name);
		abort();
	}
	q->n--;
	q->head++;
	if (q->head >= q->size)
		q->head = 0;
	return s;
}

static volatile int do_abort = 0;

uint64_t dropped = 0;
uint64_t forwarded = 0;
uint64_t non_ip = 0;

struct port_des {
	struct my_ctrs ctr;
	unsigned int last_sync;
	struct overflow_queue *oq;
	struct nm_desc *nmd;
	struct netmap_ring *ring;
	struct group_des *group;
};

struct port_des *ports;

/* each group of pipes receives all the packets */
struct group_des {
	char pipename[MAX_IFNAMELEN];
	struct port_des *ports;
	int first_id;
	int nports;
	int last;
	int custom_port;
};

struct group_des *groups;

static void *
print_stats(void *arg)
{
	int npipes = glob_arg.output_rings;
	int sys_int = 0;
	(void)arg;
	struct my_ctrs cur, prev;
	char b1[40], b2[40];
	struct my_ctrs *pipe_prev;

	pipe_prev = calloc(npipes, sizeof(struct my_ctrs));
	if (pipe_prev == NULL) {
		D("out of memory");
		exit(1);
	}

	memset(&prev, 0, sizeof(prev));
	gettimeofday(&prev.t, NULL);
	while (!do_abort) {
		int j, dosyslog = 0;
		uint64_t pps, dps, usec;
		struct my_ctrs x;

		memset(&cur, 0, sizeof(cur));
		usec = wait_for_next_report(&prev.t, &cur.t, 1000);

		if (++sys_int == glob_arg.syslog_interval) {
			dosyslog = 1;
			sys_int = 0;
		}

		for (j = 0; j < npipes; ++j) {
			struct port_des *p = &ports[j];

			cur.pkts += p->ctr.pkts;
			cur.drop += p->ctr.drop;

			x.pkts = p->ctr.pkts - pipe_prev[j].pkts;
			x.drop = p->ctr.drop - pipe_prev[j].drop;
			pps = (x.pkts*1000000 + usec/2) / usec;
			dps = (x.drop*1000000 + usec/2) / usec;
			printf("%s/%s|", norm(b1, pps), norm(b2, dps));
			pipe_prev[j] = p->ctr;

			if (dosyslog) {
				syslog(LOG_INFO,
					"{"
						"\"interface\":\"%s\","
						"\"output_ring\":%"PRIu16","
						"\"packets_forwarded\":%"PRIu64","
						"\"packets_dropped\":%"PRIu64
					"}", glob_arg.ifname, j, p->ctr.pkts, p->ctr.drop);
			}
		}
		printf("\n");
		if (dosyslog) {
			syslog(LOG_INFO,
				"{"
					"\"interface\":\"%s\","
					"\"output_ring\":null,"
					"\"packets_forwarded\":%"PRIu64","
					"\"packets_dropped\":%"PRIu64","
					"\"non_ip_packets\":%"PRIu64
				"}", glob_arg.ifname, forwarded, dropped, non_ip);
		}
		x.pkts = cur.pkts - prev.pkts;
		x.drop = cur.drop - prev.drop;
		pps = (x.pkts*1000000 + usec/2) / usec;
		dps = (x.drop*1000000 + usec/2) / usec;
		printf("===> aggregate %spps %sdps\n", norm(b1, pps), norm(b2, dps));
		prev = cur;
	}

	free(pipe_prev);

	return NULL;
}

static void
free_buffers(void)
{
	int i, tot = 0;
	struct port_des *rxport = &ports[glob_arg.output_rings];

	/* build a netmap free list with the buffers in all the overflow queues */
	for (i = 0; i < glob_arg.output_rings + 1; i++) {
		struct port_des *cp = &ports[i];
		struct overflow_queue *q = cp->oq;

		if (!q)
			continue;

		while (q->n) {
			struct netmap_slot s = oq_deq(q);
			uint32_t *b = (uint32_t *)NETMAP_BUF(cp->ring, s.buf_idx);

			*b = rxport->nmd->nifp->ni_bufs_head;
			rxport->nmd->nifp->ni_bufs_head = s.buf_idx;
			tot++;
		}
	}
	D("added %d buffers to netmap free list", tot);

	for (i = 0; i < glob_arg.output_rings + 1; ++i) {
		nm_close(ports[i].nmd);
	}
}


static void sigint_h(int sig)
{
	(void)sig;		/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

void usage()
{
	printf("usage: lb [options]\n");
	printf("where options are:\n");
	printf("  -i iface        	interface name (required)\n");
	printf("  -p [prefix:]npipes	add a new group of output pipes\n");
	printf("  -B nbufs        	number of extra buffers (default: %d)\n", DEF_EXTRA_BUFS);
	printf("  -b batch        	batch size (default: %d)\n", DEF_BATCH);
	printf("  -w seconds        	wait for link up (default: %d)\n", DEF_WAIT_LINK);
	printf("  -s seconds      	seconds between syslog messages (default: %d)\n",
			DEF_SYSLOG_INT);
	exit(0);
}

static int
parse_pipes(char *spec)
{
	char *end = index(spec, ':');
	static int max_groups = 0;
	struct group_des *g;
       
	ND("spec %s num_groups %d", spec, glob_arg.num_groups);
	if (max_groups < glob_arg.num_groups + 1) {
		size_t size = sizeof(*g) * (glob_arg.num_groups + 1);
		groups = realloc(groups, size);
		if (groups == NULL) {
			D("out of memory");
			return 1;
		}
	}
	g = &groups[glob_arg.num_groups];
	memset(g, 0, sizeof(*g));

	if (end != NULL) {
		if (end - spec > MAX_IFNAMELEN - 8) {
			D("name '%s' too long", spec);
			return 1;
		}
		if (end == spec) {
			D("missing prefix before ':' in '%s'", spec);
			return 1;
		}
		strncpy(g->pipename, spec, end - spec);
		g->custom_port = 1;
		end++;
	} else {
		/* no prefix, this group will use the
		 * name of the input port.
		 * This will be set in init_groups(),
		 * since here the input port may still
		 * be uninitialized
		 */
		end = spec;
	}
	if (*end == '\0') {
		g->nports = DEF_OUT_PIPES;
	} else {
		g->nports = atoi(end);
		if (g->nports < 1) {
			D("invalid number of pipes '%s' (must be at least 1)", end);
			return 1;
		}
	}
	glob_arg.output_rings += g->nports;
	glob_arg.num_groups++;
	return 0;
}

/* complete the initialization of the groups data structure */
void init_groups(void)
{
	int i, j, t = 0;
	struct group_des *g = NULL;
	for (i = 0; i < glob_arg.num_groups; i++) {
		g = &groups[i];
		g->ports = &ports[t];
		for (j = 0; j < g->nports; j++)
			g->ports[j].group = g;
		t += g->nports;
		if (!g->custom_port)
			strcpy(g->pipename, glob_arg.base_name);
		for (j = 0; j < i; j++) {
			struct group_des *h = &groups[j];
			if (!strcmp(h->pipename, g->pipename))
				g->first_id += h->nports;
		}
	}
	g->last = 1;
}

/* push the packet described by slot rs to the group g.
 * This may cause other buffers to be pushed down the
 * chain headed by g.
 * Return a free buffer.
 */
uint32_t forward_packet(struct group_des *g, struct netmap_slot *rs)
{
	uint32_t hash = rs->ptr;
	uint32_t output_port = hash % g->nports;
	struct port_des *port = &g->ports[output_port];
	struct netmap_ring *ring = port->ring;
	struct overflow_queue *q = port->oq;

	/* Move the packet to the output pipe, unless there is
	 * either no space left on the ring, or there is some
	 * packet still in the overflow queue (since those must
	 * take precedence over the new one)
	*/
	if (nm_ring_space(ring) && (q == NULL || oq_empty(q))) {
		struct netmap_slot *ts = &ring->slot[ring->cur];
		struct netmap_slot old_slot = *ts;
		uint32_t free_buf;

		ts->buf_idx = rs->buf_idx;
		ts->len = rs->len;
		ts->flags |= NS_BUF_CHANGED;
		ts->ptr = rs->ptr;
		ring->head = ring->cur = nm_ring_next(ring, ring->cur);
		port->ctr.pkts++;
		forwarded++;
		if (old_slot.ptr && !g->last) {
			/* old slot not empty and we are not the last group:
			 * push it further down the chain
			 */
			free_buf = forward_packet(g + 1, &old_slot);
		} else {
			/* just return the old slot buffer: it is
			 * either empty or already seen by everybody
			 */
			free_buf = old_slot.buf_idx;
		}

		return free_buf;
	}

	/* use the overflow queue, if available */
	if (q == NULL || oq_full(q)) {
		/* no space left on the ring and no overflow queue
		 * available: we are forced to drop the packet
		 */
		dropped++;
		port->ctr.drop++;
		return rs->buf_idx;
	}

	oq_enq(q, rs);

	/*
	 * we cannot continue down the chain and we need to
	 * return a free buffer now. We take it from the free queue.
	 */
	if (oq_empty(freeq)) {
		/* the free queue is empty. Revoke some buffers
		 * from the longest overflow queue
		 */
		uint32_t j;
		struct port_des *lp = &ports[0];
		uint32_t max = lp->oq->n;

		/* let lp point to the port with the longest queue */
		for (j = 1; j < glob_arg.output_rings; j++) {
			struct port_des *cp = &ports[j];
			if (cp->oq->n > max) {
				lp = cp;
				max = cp->oq->n;
			}
		}

		/* move the oldest BUF_REVOKE buffers from the
		 * lp queue to the free queue
		 */
		// XXX optimize this cycle
		for (j = 0; lp->oq->n && j < BUF_REVOKE; j++) {
			struct netmap_slot tmp = oq_deq(lp->oq);
			oq_enq(freeq, &tmp);
		}

		ND(1, "revoked %d buffers from %s", j, lq->name);
		lp->ctr.drop += j;
		dropped += j;
	}

	return oq_deq(freeq).buf_idx;
}

int main(int argc, char **argv)
{
	int ch;
	uint32_t i;
	int rv;
	unsigned int iter = 0;

	glob_arg.ifname[0] = '\0';
	glob_arg.output_rings = 0;
	glob_arg.batch = DEF_BATCH;
	glob_arg.wait_link = DEF_WAIT_LINK;
	glob_arg.syslog_interval = DEF_SYSLOG_INT;

	while ( (ch = getopt(argc, argv, "i:p:b:B:s:")) != -1) {
		switch (ch) {
		case 'i':
			D("interface is %s", optarg);
			if (strlen(optarg) > MAX_IFNAMELEN - 8) {
				D("ifname too long %s", optarg);
				return 1;
			}
			if (strncmp(optarg, "netmap:", 7) && strncmp(optarg, "vale", 4)) {
				sprintf(glob_arg.ifname, "netmap:%s", optarg);
			} else {
				strcpy(glob_arg.ifname, optarg);
			}
			break;

		case 'p':
			if (parse_pipes(optarg)) {
				usage();
				return 1;
			}
			break;

		case 'B':
			glob_arg.extra_bufs = atoi(optarg);
			D("requested %d extra buffers", glob_arg.extra_bufs);
			break;

		case 'b':
			glob_arg.batch = atoi(optarg);
			D("batch is %d", glob_arg.batch);
			break;

		case 's':
			glob_arg.syslog_interval = atoi(optarg);
			D("syslog interval is %d", glob_arg.syslog_interval);
			break;

		default:
			D("bad option %c %s", ch, optarg);
			usage();
			return 1;

		}
	}

	if (glob_arg.ifname[0] == '\0') {
		D("missing interface name");
		usage();
		return 1;
	}

	/* extract the base name */
	char *nscan = strncmp(glob_arg.ifname, "netmap:", 7) ?
			glob_arg.ifname : glob_arg.ifname + 7;
	strncpy(glob_arg.base_name, nscan, MAX_IFNAMELEN);
	for (nscan = glob_arg.base_name; *nscan && !index("-*^{}/@", *nscan); nscan++)
		;
	*nscan = '\0';	

	if (glob_arg.num_groups == 0)
		parse_pipes("");

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("lb", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	uint32_t npipes = glob_arg.output_rings;


	pthread_t stat_thread;

	ports = calloc(npipes + 1, sizeof(struct port_des));
	if (!ports) {
		D("failed to allocate the stats array");
		return 1;
	}
	struct port_des *rxport = &ports[npipes];
	init_groups();

	if (pthread_create(&stat_thread, NULL, print_stats, NULL) == -1) {
		D("unable to create the stats thread: %s", strerror(errno));
		return 1;
	}


	/* we need base_req to specify pipes and extra bufs */
	struct nmreq base_req;
	memset(&base_req, 0, sizeof(base_req));

	base_req.nr_arg1 = npipes;
	base_req.nr_arg3 = glob_arg.extra_bufs;

	rxport->nmd = nm_open(glob_arg.ifname, &base_req, 0, NULL);

	if (rxport->nmd == NULL) {
		D("cannot open %s", glob_arg.ifname);
		return (1);
	} else {
		D("successfully opened %s (tx rings: %u)", glob_arg.ifname,
		  rxport->nmd->req.nr_tx_slots);
	}

	uint32_t extra_bufs = rxport->nmd->req.nr_arg3;
	struct overflow_queue *oq = NULL;
	/* reference ring to access the buffers */
	rxport->ring = NETMAP_RXRING(rxport->nmd->nifp, 0);

	if (!glob_arg.extra_bufs)
		goto run;

	D("obtained %d extra buffers", extra_bufs);
	if (!extra_bufs)
		goto run;

	/* one overflow queue for each output pipe, plus one for the
	 * free extra buffers
	 */
	oq = calloc(npipes + 1, sizeof(struct overflow_queue));
	if (!oq) {
		D("failed to allocated overflow queues descriptors");
		goto run;
	}

	freeq = &oq[npipes];
	rxport->oq = freeq;

	freeq->slots = calloc(extra_bufs, sizeof(struct netmap_slot));
	if (!freeq->slots) {
		D("failed to allocate the free list");
	}
	freeq->size = extra_bufs;
	snprintf(freeq->name, MAX_IFNAMELEN, "free queue");

	/*
	 * the list of buffers uses the first uint32_t in each buffer
	 * as the index of the next buffer.
	 */
	uint32_t scan;
	for (scan = rxport->nmd->nifp->ni_bufs_head;
	     scan;
	     scan = *(uint32_t *)NETMAP_BUF(rxport->ring, scan))
	{
		struct netmap_slot s;
		s.len = s.flags = 0;
		s.ptr = 0;
		s.buf_idx = scan;
		ND("freeq <- %d", s.buf_idx);
		oq_enq(freeq, &s);
	}


	if (freeq->n != extra_bufs) {
		D("something went wrong: netmap reported %d extra_bufs, but the free list contained %d",
				extra_bufs, freeq->n);
		return 1;
	}
	rxport->nmd->nifp->ni_bufs_head = 0;

run:
	atexit(free_buffers);

	int j, t = 0;
	for (j = 0; j < glob_arg.num_groups; j++) {
		struct group_des *g = &groups[j];
		int k;
		for (k = 0; k < g->nports; ++k) {
			struct port_des *p = &g->ports[k];
			char interface[25];
			sprintf(interface, "netmap:%s{%d/xT@%d", g->pipename, g->first_id + k,
					rxport->nmd->req.nr_arg2);
			D("opening pipe named %s", interface);

			p->nmd = nm_open(interface, NULL, 0, rxport->nmd);

			if (p->nmd == NULL) {
				D("cannot open %s", interface);
				return (1);
			} else {
				D("successfully opened pipe #%d %s (tx slots: %d)",
				  k + 1, interface, p->nmd->req.nr_tx_slots);
				p->ring = NETMAP_TXRING(p->nmd->nifp, 0);
			}
			D("zerocopy %s",
			  (rxport->nmd->mem == p->nmd->mem) ? "enabled" : "disabled");

			if (extra_bufs) {
				struct overflow_queue *q = &oq[t + k];
				q->slots = calloc(extra_bufs, sizeof(struct netmap_slot));
				if (!q->slots) {
					D("failed to allocate overflow queue for pipe %d", k);
					/* make all overflow queue management fail */
					extra_bufs = 0;
				}
				q->size = extra_bufs;
				snprintf(q->name, MAX_IFNAMELEN, "oq %s{%d", g->pipename, k);
				p->oq = q;
			}
		}
		t += g->nports;
	}

	if (glob_arg.extra_bufs && !extra_bufs) {
		if (oq) {
			for (i = 0; i < npipes + 1; i++) {
				free(oq[i].slots);
				oq[i].slots = NULL;
			}
			free(oq);
			oq = NULL;
		}
		D("*** overflow queues disabled ***");
	}

	sleep(glob_arg.wait_link);

	struct pollfd pollfd[npipes + 1];
	memset(&pollfd, 0, sizeof(pollfd));
	signal(SIGINT, sigint_h);
	while (!do_abort) {
		u_int polli = 0;
		iter++;

		for (i = 0; i < npipes; ++i) {
			struct netmap_ring *ring = ports[i].ring;
			if (nm_ring_next(ring, ring->tail) == ring->cur) {
				/* no need to poll, there are no packets pending */
				continue;
			}
			pollfd[polli].fd = ports[i].nmd->fd;
			pollfd[polli].events = POLLOUT;
			pollfd[polli].revents = 0;
			++polli;
		}

		pollfd[polli].fd = rxport->nmd->fd;
		pollfd[polli].events = POLLIN;
		pollfd[polli].revents = 0;
		++polli;

		//RD(5, "polling %d file descriptors", polli+1);
		rv = poll(pollfd, polli, 10);
		if (rv <= 0) {
			if (rv < 0 && errno != EAGAIN && errno != EINTR)
				RD(1, "poll error %s", strerror(errno));
			continue;
		}

		if (oq) {
			/* try to push packets from the overflow queues
			 * to the corresponding pipes
			 */
			for (i = 0; i < npipes; i++) {
				struct port_des *p = &ports[i];
				struct overflow_queue *q = p->oq;
				struct group_des *g = p->group;
				uint32_t j, lim;
				struct netmap_ring *ring;
				struct netmap_slot *slot;

				if (oq_empty(q))
					continue;
				ring = p->ring;
				lim = nm_ring_space(ring);
				if (!lim)
					continue;
				if (q->n < lim)
					lim = q->n;
				for (j = 0; j < lim; j++) {
					struct netmap_slot s = oq_deq(q), tmp;
					tmp.ptr = 0;
					slot = &ring->slot[ring->cur];
					if (slot->ptr && !g->last) {
						tmp.buf_idx = forward_packet(g + 1, slot);
						/* the forwarding may have removed packets
						 * from the current queue
						 */
						if (q->n < lim)
							lim = q->n;
					} else {
						tmp.buf_idx = slot->buf_idx;
					}
					oq_enq(freeq, &tmp);
					*slot = s;
					slot->flags |= NS_BUF_CHANGED;
					ring->cur = nm_ring_next(ring, ring->cur);
				}
				ring->head = ring->cur;
				forwarded += lim;
				p->ctr.pkts += lim;
			}
		}

		int batch = 0;
		for (i = rxport->nmd->first_rx_ring; i <= rxport->nmd->last_rx_ring; i++) {
			struct netmap_ring *rxring = NETMAP_RXRING(rxport->nmd->nifp, i);

			//D("prepare to scan rings");
			int next_cur = rxring->cur;
			struct netmap_slot *next_slot = &rxring->slot[next_cur];
			const char *next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
			while (!nm_ring_empty(rxring)) {
				struct netmap_slot *rs = next_slot;
				struct group_des *g = &groups[0];

				// CHOOSE THE CORRECT OUTPUT PIPE
				uint32_t hash = pkt_hdr_hash((const unsigned char *)next_buf, 4, 'B');
				if (hash == 0) {
					non_ip++; // XXX ??
				}
				rs->ptr = hash | (1UL << 32);
				// prefetch the buffer for the next round
				next_cur = nm_ring_next(rxring, next_cur);
				next_slot = &rxring->slot[next_cur];
				next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
				__builtin_prefetch(next_buf);
				// 'B' is just a hashing seed
				rs->buf_idx = forward_packet(g, rs);
				rs->flags |= NS_BUF_CHANGED;
				rxring->head = rxring->cur = next_cur;

				batch++;
				if (unlikely(batch >= glob_arg.batch)) {
					ioctl(rxport->nmd->fd, NIOCRXSYNC, NULL);
					batch = 0;
				}
				ND(1,
				   "Forwarded Packets: %"PRIu64" Dropped packets: %"PRIu64"   Percent: %.2f",
				   forwarded, dropped,
				   ((float)dropped / (float)forwarded * 100));
			}

		}
	}

	pthread_join(stat_thread, NULL);

	printf("%"PRIu64" packets forwarded.  %"PRIu64" packets dropped. Total %"PRIu64"\n", forwarded,
	       dropped, forwarded + dropped);
	return 0;
}
