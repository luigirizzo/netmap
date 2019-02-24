/* Given an interface name and a packet length (optional), prints to stdout
 * the maximum number of packets (each within that length) that fits in the
 * transmit rings, assuming they are all empty. If the packet length is not
 * specified, it is assumed that any packet to be transmitted fits within a
 * single netmap slot, hence printing the total number of TX slots.
 * On error, "-1" is printed.
 * Arguments:
 *    $1 -> interface name
 *    $2 -> packet length
 */
#include <inttypes.h>
#include <math.h>
#include <net/if.h>

#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

uint64_t
slots_per_packet(struct netmap_ring *ring, unsigned pkt_len)
{
	return (uint64_t)(ceil((double)pkt_len / (double)ring->nr_buf_size));
}

uint64_t
ring_max_tx_packets(struct netmap_ring *ring, unsigned pkt_len)
{
	if (pkt_len == 0) {
		return nm_ring_space(ring) - 1;
	}

	return (ring->num_slots - 1) / slots_per_packet(ring, pkt_len);
}

uint64_t
nmport_max_tx_packets(struct nm_desc *nmd, unsigned pkt_len)
{
	uint64_t total = 0;
	unsigned int i;

	for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
		struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);

		total += ring_max_tx_packets(ring, pkt_len);
	}

	return total;
}

int
main(int argc, char **argv)
{
	uint64_t max_tx_packets;
	struct nm_desc *nmd;
	const char *if_name;
	uint64_t pkt_len;

	if (argc == 2) {
		pkt_len = 0;
	} else if (argc == 3) {
		pkt_len = atoi(argv[2]);
		if (pkt_len == 0) {
			printf("-1");
			exit(EXIT_FAILURE);
		}
	} else {
		printf("-1");
		exit(EXIT_FAILURE);
	}

	fclose(stderr);
	if_name = argv[1];
	nmd     = nm_open(if_name, NULL, 0, NULL);
	if (nmd == NULL) {
		printf("-1");
		exit(EXIT_FAILURE);
	}

	max_tx_packets = nmport_max_tx_packets(nmd, pkt_len);
	printf("%" PRId64, max_tx_packets);

	return 0;
}
