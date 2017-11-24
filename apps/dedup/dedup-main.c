/*
 * (C) 2017	Giuseppe Lettieri
 *
 * BSD license
 *
 */

#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>
#include "dedup.h"

int verbose = 0;

static int do_abort = 0;
static int zerocopy = 1; /* enable zerocopy if possible */

static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}


static void
usage(void)
{
	fprintf(stderr,
		"dedup\n"
		);
	exit(1);
}

int
main(int argc, char **argv)
{
	struct pollfd pollfd[2];
	int ch;
	struct nm_desc *pa = NULL, *pb = NULL;
	char *ifa = NULL, *ifb = NULL;
	int wait_link = 2;
	int win_size_usec = 50;
	unsigned int fifo_size = 10;
	struct dedup dedup;
	int n;

	fprintf(stderr, "%s built %s %s\n\n", argv[0], __DATE__, __TIME__);

	while ((ch = getopt(argc, argv, "hci:vw:W:F:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			/* fallthrough */
		case 'h':
			usage();
			break;
		case 'i':	/* interface */
			if (ifa == NULL)
				ifa = optarg;
			else if (ifb == NULL)
				ifb = optarg;
			else
				D("%s ignored, already have 2 interfaces",
					optarg);
			break;
		case 'c':
			zerocopy = 0; /* do not zerocopy */
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			wait_link = atoi(optarg);
			break;
		case 'W':
			win_size_usec = atoi(optarg);
			break;
		case 'F':
			fifo_size = atoi(optarg);
			break;
		}

	}

	if (!ifa || !ifb) {
		D("missing interface");
		usage();
	}
	pa = nm_open(ifa, NULL, 0, NULL);
	if (pa == NULL) {
		D("cannot open %s", ifa);
		return (1);
	}
	if (pa->first_rx_ring != pa->last_rx_ring) {
		D("%s: too many RX rings (%d)", pa->req.nr_name,
				pa->last_rx_ring - pa->first_rx_ring + 1);
		return (1);
	}
	/* try to reuse the mmap() of the first interface, if possible */
	pb = nm_open(ifb, NULL, NM_OPEN_NO_MMAP, pa);
	if (pb == NULL) {
		D("cannot open %s", ifb);
		nm_close(pa);
		return (1);
	}
	if (pb->first_tx_ring != pb->last_tx_ring) {
		D("%s: too many TX rings (%d)", pb->req.nr_name,
				pb->last_rx_ring - pb->first_rx_ring + 1);
		nm_close(pa);
		return (1);
	}

	memset(&dedup, 0, sizeof(dedup));
	dedup.out_slot = dedup.out_ring->slot;
	if (dedup_init(&dedup, fifo_size, 
			NETMAP_RXRING(pa->nifp, pa->first_rx_ring),
			NETMAP_TXRING(pb->nifp, pb->first_tx_ring)) < 0) {
		D("failed to initialize dedup with fifo_size %u", fifo_size);
		return (1);
	}
	if (fifo_size >= dedup.out_ring->num_slots - 1) {
		D("fifo_size %u too large (max %u)", fifo_size, dedup.out_ring->num_slots - 1);
		return (1);
	}
	if (dedup_set_hold_packets(&dedup, 1) < 0) {
		D("failed to set 'hold packets' option");
		return (1);
	}
	dedup.in_memid = pa->req.nr_arg2;
	dedup.fifo_memid = dedup.out_memid = (zerocopy ? pb->req.nr_arg2 : -1 );
	dedup.win_size.tv_sec = win_size_usec / 1000000;
	dedup.win_size.tv_usec = win_size_usec % 1000000;
	D("win_size %lld+%lld", (long long) dedup.win_size.tv_sec,
			(long long) dedup.win_size.tv_usec);

	/* setup poll(2) array */
	memset(pollfd, 0, sizeof(pollfd));
	pollfd[0].fd = pa->fd;
	pollfd[1].fd = pb->fd;

	D("Wait %d secs for link to come up...", wait_link);
	sleep(wait_link);
	D("Ready to go, %s -> %s", pa->req.nr_name, pb->req.nr_name);

	/* main loop */
	signal(SIGINT, sigint_h);
	n = 0;
	while (!do_abort) {
		int ret;
		struct timeval now;

		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;
		if (!n)
			pollfd[0].events = POLLIN;
		else
			pollfd[1].events = POLLOUT;
		/* poll() also cause kernel to txsync/rxsync the NICs */
		ret = poll(pollfd, 2, 1000);
		gettimeofday(&now, NULL);
		if (ret <= 0 || verbose)
		    D("poll %s [0] ev %x %x"
			     " [1] ev %x %x",
				ret <= 0 ? "timeout" : "ok",
				pollfd[0].events,
				pollfd[0].revents,
				pollfd[1].events,
				pollfd[1].revents
			);
		n = dedup_push_in(&dedup, &now);
	}
	nm_close(pb);
	nm_close(pa);

	return (0);
}
