/* Given an interface name and a packet length (optional), prints to stdout
 * the number of packets that can be send through the interface rings. If the
 * packet length is missing, the number of available slot is printed instead.
 * Prints "-1" if something went wrong.
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
slot_per_send(struct netmap_ring *ring, unsigned pkt_len)
{
	return (uint64_t)(ceil((double)pkt_len / (double)ring->nr_buf_size));
}

uint64_t
ring_avail_sends(struct netmap_ring *ring, unsigned pkt_len)
{
	if (pkt_len == 0) {
		return nm_ring_space(ring);
	}

	return nm_ring_space(ring) / slot_per_send(ring, pkt_len);
}

uint64_t
adapter_avail_sends(struct nm_desc *nmd, unsigned pkt_len)
{
	uint64_t sends_available = 0;
	unsigned int i;

	for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
		struct netmap_ring *ring = NETMAP_TXRING(nmd->nifp, i);

		sends_available += ring_avail_sends(ring, pkt_len);
	}

	return sends_available;
}

int
main(int argc, char **argv)
{
	uint64_t avail_sends;
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

	avail_sends = adapter_avail_sends(nmd, pkt_len);
	printf("%" PRId64, avail_sends);
	return 0;
}