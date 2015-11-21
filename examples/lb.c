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

#include "lb.h"

#define MAX_IFNAMELEN 	64
#define DEF_OUT_PIPES 	2
#define DEF_EXTRA_BUFS 	0

struct {
	char ifname[MAX_IFNAMELEN];
	uint16_t output_rings;
	uint32_t extra_bufs;
} glob_arg;

static int do_abort = 0;

uint64_t dropped = 0;
uint64_t forwarded = 0;

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

static inline bool pkt_swap(struct netmap_slot * ts, struct netmap_ring * ring)
{
	struct netmap_slot *rs;
	rs = &ring->slot[ring->cur];

	if (nm_ring_space(ring) == 0) {
		//RD(5, "no room to transmit to %s (tx_slots %d - tx_slots_pending %d - nm_ring_space %d)!", 
		//  d->req.nr_name, d->req.nr_tx_slots, nm_tx_pending(ring), nm_ring_space(ring));
		++dropped;
		return false;
	} else {
		++forwarded;
	}

	rs->len = ts->len;
	uint32_t pkt = ts->buf_idx;
	ts->buf_idx = rs->buf_idx;
	rs->buf_idx = pkt;
	/* report the buffer change. */
	ts->flags |= NS_BUF_CHANGED;
	rs->flags |= NS_BUF_CHANGED;
	ring->head = ring->cur = nm_ring_next(ring, ring->cur);
	return true;
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
	int ch;

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

	struct nm_desc *rxnmd = NULL;
	struct nm_desc *txnmds[glob_arg.output_rings];
	struct netmap_ring *txrings[glob_arg.output_rings];

	struct netmap_ring *rxring = NULL;

	uint64_t ring_drops[glob_arg.output_rings];
	memset(&ring_drops, 0, sizeof(ring_drops));
	uint64_t ring_forward[glob_arg.output_rings];
	memset(&ring_forward, 0, sizeof(ring_forward));

	struct nmreq base_req;
	memset(&base_req, 0, sizeof(base_req));

	base_req.nr_arg1 = glob_arg.output_rings;
	base_req.nr_arg3 = glob_arg.extra_bufs;

	rxnmd = nm_open(glob_arg.ifname, &base_req, 0, NULL);

	if (rxnmd == NULL) {
		D("cannot open %s", glob_arg.ifname);
		return (1);
	} else {
		D("successfully opened %s (tx rings: %u)", glob_arg.ifname,
		  rxnmd->req.nr_tx_slots);
	}

	if (glob_arg.extra_bufs)
		D("obtained %d extra buffers", rxnmd->req.nr_arg3);

	int i;
	for (i = 0; i < glob_arg.output_rings; ++i) {
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
	}

	sleep(2);

	struct pollfd pollfd[glob_arg.output_rings + 1];
	memset(&pollfd, 0, sizeof(pollfd));

	signal(SIGINT, sigint_h);
	while (!do_abort) {
		u_int polli = 0;

		for (i = 0; i < glob_arg.output_rings; ++i) {
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
			D("poll error/timeout  %s", strerror(errno));
			continue;
		} else {
			//RD(5, "Poll returned %d", i);
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
				    ip_hasher(p, rs->len) % glob_arg.output_rings;

				// Move the packet to the output pipe.
				if (!pkt_swap(rs, txrings[output_port]))
					++ring_drops[output_port];
				else
					++ring_forward[output_port];

				rxring->head = rxring->cur = next_cur;
				ND(1,
				   "Forwarded Packets: %"PRIu64" Dropped packets: %"PRIu64"   Percent: %.2f",
				   forwarded, dropped,
				   ((float)dropped / (float)forwarded * 100));
			}

#if 0
			uint64_t total_packets;
			for (j = 0; j < glob_arg.output_rings; ++j) {
				total_packets = ring_drops[j] + ring_forward[j];
				RD(glob_arg.output_rings,
				   "Ring %u, Total Packets: %"PRIu64" Forwarded Packets: %"PRIu64" Dropped packets: %"PRIu64" Percent: %.2f",
				   j, total_packets, ring_forward[j],
				   ring_drops[j],
				   ((float)ring_drops[j] /
				    (float)total_packets * 100));
			}
			//RD(1, "\n");
#endif
		}
	}

	nm_close(rxnmd);
	for (i = 0; i < glob_arg.output_rings; ++i) {
		nm_close(txnmds[i]);
	}

	printf("%"PRIu64" packets forwarded.  %"PRIu64" packets dropped.\n", forwarded,
	       dropped);
	return 0;
}
