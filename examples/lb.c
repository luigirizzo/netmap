#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */

#include <lb.h>

char iface[25];
u_int OUTPUT_RINGS = 0;

static int do_abort = 0;

uint64_t dropped = 0;
uint64_t forwarded = 0;


static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

inline uint32_t ip_hasher(const u_char *buffer, const u_int16_t buffer_len)
	{
	uint32_t l3_offset = sizeof(struct compact_eth_hdr);
	uint16_t eth_type;

	eth_type = (buffer[12] << 8) + buffer[13];

	while (eth_type == 0x8100 /* VLAN */)
		{
		l3_offset += 4;
		eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
		}

	switch (eth_type)
		{
		case 0x0800:
			{
			/* IPv4 */
			struct compact_ip_hdr *iph;

			if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ip_hdr)))
				return 0;

			iph = (struct compact_ip_hdr *) &buffer[l3_offset];

			return ntohl(iph->saddr) + ntohl(iph->daddr);
			}
			break;
		case 0x86DD:
			{
			/* IPv6 */
			struct compact_ipv6_hdr *ipv6h;
			uint32_t *s, *d;

			if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ipv6_hdr)))
				return 0;

			ipv6h = (struct compact_ipv6_hdr *) &buffer[l3_offset];
			s = (uint32_t *) &ipv6h->saddr;
			d = (uint32_t *) &ipv6h->daddr;

			return(s[0] + s[1] + s[2] + s[3] + d[0] + d[1] + d[2] + d[3]);
			}
			break;
		default:
			return 0; /* Unknown protocol */
		}
	}

inline bool pkt_swap(struct netmap_slot *ts, struct netmap_ring *ring)
	{
	struct netmap_slot *rs;
	rs = &ring->slot[ring->cur];

	bool ret;
	if ( nm_ring_space(ring) == 0 ) 
		{
		//RD(5, "no room to transmit to %s (tx_slots %d - tx_slots_pending %d - nm_ring_space %d)!", 
		//  d->req.nr_name, d->req.nr_tx_slots, nm_tx_pending(ring), nm_ring_space(ring));
		++dropped;
		ret = false;
		}
	else
		{
		++forwarded;
		ret = true;
		}

	rs->len = ts->len;
	uint32_t pkt = ts->buf_idx;
	ts->buf_idx = rs->buf_idx;
	rs->buf_idx = pkt;
	/* report the buffer change. */
	ts->flags |= NS_BUF_CHANGED;
	rs->flags |= NS_BUF_CHANGED;
	ring->head = ring->cur = nm_ring_next(ring, ring->cur);
	return ret;
	}

void usage()
	{
	printf("usage: lb <iface> <balance-ports>\n");
	exit(0);
	}

int main(int argc, char **argv)
	{
	if ( argc != 3 )
		{
		usage();
		}
	else
		{
		char *ptr;
		OUTPUT_RINGS = strtoul(argv[2], &ptr, 10);
		sprintf(iface, "netmap:%s", argv[1]);
		}

	if ( OUTPUT_RINGS == 0 )
		{
		printf("You must output to more than 0 pipes\n");
		usage();
		}

	struct nm_desc *rxnmd = NULL;
	struct nm_desc *txnmds[OUTPUT_RINGS];
	struct netmap_ring *txrings[OUTPUT_RINGS];

	struct netmap_ring *rxring = NULL;
	struct netmap_ring *txring  = NULL;

	uint64_t ring_drops[OUTPUT_RINGS];
	memset(&ring_drops, 0, sizeof(ring_drops));
	uint64_t ring_forward[OUTPUT_RINGS];
	memset(&ring_forward, 0, sizeof(ring_forward));

	u_int received = 0;
	u_int cur, rx, n;
	int ret;

	struct nmreq base_req;
	memset(&base_req, 0, sizeof(base_req));

        struct nm_desc base_nmd;
        memset(&base_nmd, 0, sizeof(base_nmd));
        base_nmd.req.nr_arg1 = 65535;
        base_nmd.req.nr_arg3 = 65535;
        base_nmd.req.nr_tx_rings = 65535;
        base_nmd.req.nr_rx_rings = 65535;
        base_nmd.req.nr_rx_slots = 65535;
        base_nmd.req.nr_tx_slots = 65535;

        rxnmd = nm_open(iface, NULL, NM_OPEN_ARG1 | NM_OPEN_ARG3 | NM_OPEN_RING_CFG, &base_nmd);

	if (rxnmd == NULL)
		{
		D("cannot open %s", rxnmd);
		return (1);
		}
	else
		{
		D("successfully opened %s (tx rings: %llu)", rxnmd, rxnmd->req.nr_tx_slots);
		}

	int i, j;
	for (i=0; i<OUTPUT_RINGS; ++i)
		{
		char interface[25];
		sprintf(interface, "%s{%d", iface, i);
		D("opening pipe named %s", interface);

		//txnmds[i] = nm_open(interface, NULL, NM_OPEN_NO_MMAP | NM_OPEN_ARG3 | NM_OPEN_RING_CFG, rxnmd);
		uint64_t flags = NM_OPEN_NO_MMAP | NM_OPEN_ARG3 | NM_OPEN_RING_CFG;
		txnmds[i] = nm_open(interface, NULL, flags, rxnmd);

		if (txnmds[i] == NULL)
			{
			D("cannot open %s", txnmds[i]);
			return (1);
			}
		else
			{
			D("successfully opened pipe #%d %s (tx slots: %d)", i+1, interface, txnmds[i]->req.nr_tx_slots);
			// Is this right?  Do pipes only have one ring?
			txrings[i] = NETMAP_TXRING(txnmds[i]->nifp, 0);
			}
		D("zerocopy %s", (rxnmd->mem == txnmds[i]->mem) ? "enabled" : "disabled");
		}

	sleep(2);

	struct pollfd pollfd[OUTPUT_RINGS+1];
	memset(&pollfd, 0, sizeof(pollfd));

	signal(SIGINT, sigint_h);
	while ( !do_abort )
		{
		u_int m = 0;
		u_int polli = 0;

		for (i=0; i<OUTPUT_RINGS; ++i)
			{
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
		i = poll(pollfd, polli+1, 10);
		if ( i <= 0 )
			{
			D("poll error/timeout  %s", strerror(errno));
			continue;
			}
		else
			{
			//RD(5, "Poll returned %d", i);
			}
		
		for ( i = rxnmd->first_rx_ring; i <= rxnmd->last_rx_ring; i++ ) 
			{
			rxring = NETMAP_RXRING(rxnmd->nifp, i);

			//D("prepare to scan rings");
			while ( !nm_ring_empty(rxring) )
				{
				struct netmap_slot *rs = &rxring->slot[rxring->cur];

				// CHOOSE THE CORRECT OUTPUT PIPE
				const u_char *p = NETMAP_BUF(rxring, rs->buf_idx);
				//__builtin_prefetch(p);
				uint32_t output_port = ip_hasher(p, rs->len) % OUTPUT_RINGS;

				// Move the packet to the output pipe.
				if ( ! pkt_swap(rs, txrings[output_port]) )
					++ring_drops[output_port];
				else
					++ring_forward[output_port];

				rxring->head = rxring->cur = nm_ring_next(rxring, rxring->cur);
				RD(1, "Forwarded Packets: %llu Dropped packets: %llu   Percent: %.2f", forwarded, dropped, ((float)dropped/(float)forwarded*100));
				}

			uint64_t total_packets;
			for ( j=0; j<OUTPUT_RINGS; ++j )
				{
				total_packets = ring_drops[j]+ring_forward[j];
				RD(OUTPUT_RINGS, "Ring %d, Total Packets: %llu Forwarded Packets: %llu Dropped packets: %llu Percent: %.2f", j, total_packets, ring_forward[j], ring_drops[j], ((float)ring_drops[j]/(float)total_packets*100));
				}
			//RD(1, "\n");
			}
		}

	nm_close(rxnmd);
	for ( i=0; i<OUTPUT_RINGS; ++i )
		{
		nm_close(txnmds[i]);
		}

	printf("%llu packets forwarded.  %llu packets dropped.\n", forwarded, dropped);
	return 0;
	}

