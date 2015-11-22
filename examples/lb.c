#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <inttypes.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>	/* the L2 protocols */

#include <pthread.h>

#include "lb.h"

#define MAX_IFNAMELEN 	64
#define DEF_OUT_PIPES 	2
#define DEF_EXTRA_BUFS 	0

struct {
	char ifname[MAX_IFNAMELEN];
	uint16_t output_rings;
	uint32_t extra_bufs;
} glob_arg;

struct overflow_queue {
	char name[MAX_IFNAMELEN];
	struct netmap_slot *slots;
	int head;
	int tail;
	int n;
	int size;
	struct netmap_ring *ring;
};

static inline void
oq_enq(struct overflow_queue *q, const struct netmap_slot *s)
{
	if (unlikely(q->n >= q->size)) {
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
	if (unlikely(q->n <= 0)) {
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

struct pipe_stat {
	uint64_t drop;
	uint64_t forward;
};

struct pipe_stat *pipe_stats;


static void *
print_stats(void *arg)
{
	int npipes = glob_arg.output_rings;
	(void)arg;

	while (!do_abort) {
		int j;
		struct timeval delta;
		uint64_t total_packets;

		delta.tv_sec = 1;
		delta.tv_usec = 0;
		select(0, NULL, NULL, NULL, &delta);

		for (j = 0; j < npipes; ++j) {
			struct pipe_stat *p = &pipe_stats[j];

			total_packets = p->drop + p->forward;
			D("Ring %u, Total Packets: %"PRIu64" Forwarded Packets: %"PRIu64" Dropped packets: %"PRIu64" Percent: %.2f",
			   j, total_packets, p->forward, p->drop, ((float)p->drop / (float)total_packets * 100));
		}
	}
	return NULL;
}

static void sigint_h(int sig)
{
	(void)sig;		/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

inline uint32_t ip_hasher(const char * buffer, const u_int16_t buffer_len)
{
	uint32_t l3_offset = sizeof(struct compact_eth_hdr);
	uint16_t eth_type;

	eth_type = (buffer[12] << 8) + buffer[13];

	while (eth_type == 0x8100 /* VLAN */ ) {
		l3_offset += 4;
		eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
	}

	switch (eth_type) {
	case 0x0800:
		{
			/* IPv4 */
			struct compact_ip_hdr *iph;

			if (unlikely
			    (buffer_len <
			     l3_offset + sizeof(struct compact_ip_hdr)))
				return 0;

			iph = (struct compact_ip_hdr *)&buffer[l3_offset];

			return ntohl(iph->saddr) + ntohl(iph->daddr);
		}
		break;
	case 0x86DD:
		{
			/* IPv6 */
			struct compact_ipv6_hdr *ipv6h;
			uint32_t *s, *d;

			if (unlikely
			    (buffer_len <
			     l3_offset + sizeof(struct compact_ipv6_hdr)))
				return 0;

			ipv6h = (struct compact_ipv6_hdr *)&buffer[l3_offset];
			s = (uint32_t *) & ipv6h->saddr;
			d = (uint32_t *) & ipv6h->daddr;

			return (s[0] + s[1] + s[2] + s[3] + d[0] + d[1] + d[2] +
				d[3]);
		}
		break;
	default:
		return 0;	/* Unknown protocol */
	}
}

void usage()
{
	printf("usage: lb [options]\n");
	printf("where options are:\n");
	printf("  -i iface        interface name (required)\n");
	printf("  -p npipes       number of output pipes (default: %d)\n", DEF_OUT_PIPES);
	printf("  -b nbufs        number of extra buffers (default: %d)\n", DEF_EXTRA_BUFS);
	exit(0);
}



int main(int argc, char **argv)
{
	int ch, i;

	glob_arg.ifname[0] = '\0';
	glob_arg.output_rings = DEF_OUT_PIPES;

	while ( (ch = getopt(argc, argv, "i:p:b:")) != -1) {
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
			glob_arg.output_rings = atoi(optarg);
			if (glob_arg.output_rings < 1) {
				D("you must output to at least one pipe");
				usage();
				return 1;
			}
			break;

		case 'b':
			glob_arg.extra_bufs = atoi(optarg);
			D("requested %d extra buffers", glob_arg.extra_bufs);
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

	int npipes = glob_arg.output_rings;
	struct nm_desc *rxnmd = NULL;
	struct nm_desc *txnmds[npipes];
	struct netmap_ring *txrings[npipes];

	struct overflow_queue *freeq = NULL;

	struct netmap_ring *rxring = NULL;
	pthread_t stat_thread;

	pipe_stats = calloc(sizeof(struct pipe_stat), npipes);
	if (!pipe_stats) {
		D("failed to allocate the stats array");
		return 1;
	}

	if (pthread_create(&stat_thread, NULL, print_stats, NULL) == -1) {
		D("unable to create the stats thread: %s", strerror(errno));
		return 1;
	}

	struct nmreq base_req;
	memset(&base_req, 0, sizeof(base_req));

	base_req.nr_arg1 = npipes;
	base_req.nr_arg3 = glob_arg.extra_bufs;

	rxnmd = nm_open(glob_arg.ifname, &base_req, 0, NULL);

	if (rxnmd == NULL) {
		D("cannot open %s", glob_arg.ifname);
		return (1);
	} else {
		D("successfully opened %s (tx rings: %u)", glob_arg.ifname,
		  rxnmd->req.nr_tx_slots);
	}
	rxring = NETMAP_RXRING(rxnmd->nifp, 0);

	int extra_bufs = rxnmd->req.nr_arg3;
	struct overflow_queue *oq = NULL;

	if (!glob_arg.extra_bufs)
		goto run;

	D("obtained %d extra buffers", extra_bufs);
	if (!extra_bufs)
		goto run;

	/* one overflow queue for each output pipe, plus one for the
	 * free extra buffers
	 */
	oq = calloc(sizeof(struct overflow_queue), npipes + 1);
	if (!oq) {
		D("failed to allocated overflow queues descriptors");
		goto run;
	}

	freeq = &oq[npipes];

	freeq->slots = calloc(sizeof(struct netmap_slot), extra_bufs);
	if (!freeq->slots) {
		D("failed to allocate the free list");
	}
	freeq->size = extra_bufs;
	freeq->ring = rxring;
	snprintf(freeq->name, MAX_IFNAMELEN, "free queue");

	uint32_t scan;
	for (scan = rxnmd->nifp->ni_bufs_head;
	     scan;
	     scan = *(uint32_t *)NETMAP_BUF(rxring, scan))
	{
		struct netmap_slot s;
		s.buf_idx = scan;
		ND("freeq <- %d", s.buf_idx);
		oq_enq(freeq, &s);
	}
	if (freeq->n != extra_bufs) {
		D("something went wrong: netmap reported %d extra_bufs, but the free list contained %d",
				extra_bufs, freeq->n);
		return 1;
	}
	rxnmd->nifp->ni_bufs_head = 0;

run:
	for (i = 0; i < npipes; ++i) {
		char interface[25];
		sprintf(interface, "%s{%d", glob_arg.ifname, i);
		D("opening pipe named %s", interface);

		//txnmds[i] = nm_open(interface, NULL, NM_OPEN_NO_MMAP | NM_OPEN_ARG3 | NM_OPEN_RING_CFG, rxnmd);
		txnmds[i] = nm_open(interface, NULL, 0, rxnmd);

		if (txnmds[i] == NULL) {
			D("cannot open %s", interface);
			return (1);
		} else {
			D("successfully opened pipe #%d %s (tx slots: %d)",
			  i + 1, interface, txnmds[i]->req.nr_tx_slots);
			// Is this right?  Do pipes only have one ring?
			txrings[i] = NETMAP_TXRING(txnmds[i]->nifp, 0);
		}
		D("zerocopy %s",
		  (rxnmd->mem == txnmds[i]->mem) ? "enabled" : "disabled");

		if (extra_bufs) {
			struct overflow_queue *q = &oq[i];
			q->slots = calloc(sizeof(struct netmap_slot), extra_bufs);
			if (!q->slots) {
				D("failed to allocate overflow queue for pipe %d", i);
				/* make all overflow queue management fail */
				extra_bufs = 0;
			}
			q->ring = txrings[i];
			q->size = extra_bufs;
			snprintf(q->name, MAX_IFNAMELEN, "oq %d", i);
		}
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

	sleep(2);

	struct pollfd pollfd[npipes + 1];
	memset(&pollfd, 0, sizeof(pollfd));

	signal(SIGINT, sigint_h);
	while (!do_abort) {
		u_int polli = 0;

		for (i = 0; i < npipes; ++i) {
			pollfd[polli].fd = txnmds[i]->fd;
			pollfd[polli].events = POLLOUT;
			pollfd[polli].revents = 0;
			++polli;
		}

		pollfd[polli].fd = rxnmd->fd;
		pollfd[polli].events = POLLIN;
		pollfd[polli].revents = 0;
		++polli;

		//RD(5, "polling %d file descriptors", polli+1);
		i = poll(pollfd, polli, 10);
		if (i <= 0) {
			RD(1, "poll error %s", errno ? strerror(errno) : "timeout");
			continue;
		} else {
			//RD(5, "Poll returned %d", i);
		}

		if (oq) {
			/* try to push packets from the overflow queues
			 * to the corresponding pipes
			 */
			for (i = 0; i < npipes; i++) {
				struct overflow_queue *q = &oq[i];
				int j, lim;
				struct netmap_ring *ring;
				struct netmap_slot *slot;
				struct pipe_stat *p = &pipe_stats[i];

				if (!q->n)
					continue;
				ring = q->ring;
				lim = nm_ring_space(ring);
				if (!lim)
					continue;
				if (q->n < lim)
					lim = q->n;
				for (j = 0; j < lim; j++) {
					struct netmap_slot s = oq_deq(q);
					slot = &ring->slot[ring->cur];
					oq_enq(freeq, slot);
					*slot = s;
					slot->flags |= NS_BUF_CHANGED;
					ring->cur = nm_ring_next(ring, ring->cur);
				}
				ring->head = ring->cur;
				forwarded += lim;
				p->forward++;
			}
		}

		for (i = rxnmd->first_rx_ring; i <= rxnmd->last_rx_ring; i++) {
			rxring = NETMAP_RXRING(rxnmd->nifp, i);

			//D("prepare to scan rings");
			int next_cur = rxring->cur;
			struct netmap_slot *next_slot = &rxring->slot[next_cur];
			const char *next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
			while (!nm_ring_empty(rxring)) {
				struct netmap_slot *rs = next_slot;
				next_cur = nm_ring_next(rxring, next_cur);
				next_slot = &rxring->slot[next_cur];

				// CHOOSE THE CORRECT OUTPUT PIPE
				const char *p = next_buf;
				next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
				__builtin_prefetch(next_buf);
				uint32_t output_port =
				    ip_hasher(p, rs->len) % npipes;
				struct netmap_ring *ring = txrings[output_port];
				uint32_t free_buf;
				struct pipe_stat *ps = &pipe_stats[output_port];

				// Move the packet to the output pipe.
				if (nm_ring_space(ring)) {
					struct netmap_slot *ts = &ring->slot[ring->cur];
					free_buf = ts->buf_idx;
					ts->buf_idx = rs->buf_idx;
					ts->len = rs->len;
					ts->flags |= NS_BUF_CHANGED;
					ring->head = ring->cur = nm_ring_next(ring, ring->cur);
					ps->forward++;
					forwarded++;
				} else if (oq) {
					/* out of ring space, use the overflow queue */

					struct overflow_queue *q = &oq[output_port];
					if (freeq->n) {
						free_buf = oq_deq(freeq).buf_idx;
						oq_enq(q, rs);
						ND(1, "overflow on pipe %d", output_port);
					} else {
						/* here we should remove one buffer from the longest
						 * overflow queue, unless that is our own.
						 * for now, we just drop
						 */
						dropped++;
						ps->drop++;
						goto next;
					}
				} else {
					dropped++;
					ps->drop++;
					goto next;
				}
				rs->buf_idx = free_buf;
				rs->flags |= NS_BUF_CHANGED;

			next:
				rxring->head = rxring->cur = next_cur;
				ND(1,
				   "Forwarded Packets: %"PRIu64" Dropped packets: %"PRIu64"   Percent: %.2f",
				   forwarded, dropped,
				   ((float)dropped / (float)forwarded * 100));
			}

		}
	}

	pthread_join(stat_thread, NULL);

	/* build a netmap free list with the buffers in all the overflow queues */
	if (oq) {
		int tot = 0;
		for (i = 0; i < npipes + 1; i++) {
			struct overflow_queue *q = &oq[i];

			while (q->n) {
				struct netmap_slot s = oq_deq(q);
				uint32_t *b = (uint32_t *)NETMAP_BUF(q->ring, s.buf_idx);

				*b = rxnmd->nifp->ni_bufs_head;
				rxnmd->nifp->ni_bufs_head = s.buf_idx;
				tot++;
			}

		}
		D("added %d buffers to netmap free list", tot);
	}

	nm_close(rxnmd);
	for (i = 0; i < npipes; ++i) {
		nm_close(txnmds[i]);
	}

	printf("%"PRIu64" packets forwarded.  %"PRIu64" packets dropped.\n", forwarded,
	       dropped);
	return 0;
}
