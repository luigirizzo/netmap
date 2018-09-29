#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <math.h>
#include <sys/time.h>

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

static int stop = 0;

static void
sigint_handler(int signum)
{
	(void)signum;
	ACCESS_ONCE(stop) = 1;
}

struct context {
	struct nm_desc *nmd;
	struct nm_csb_atok *atok_base;
	struct nm_csb_ktoa *ktoa_base;
	int verbose;
	int batch;
};

static void *
kloop_worker(void *opaque)
{
	struct context *ctx = opaque;
	struct nm_desc *nmd = ctx->nmd;
	struct nmreq_sync_kloop_start req;
	struct nmreq_header hdr;
	int ret;

	/* The ioctl() returns on failure or when some other thread
	 * stops the kernel loop. */
	memset(&hdr, 0, sizeof(hdr));
	hdr.nr_version = NETMAP_API;
	hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_START;
	hdr.nr_body    = (uintptr_t)&req;
	hdr.nr_options = (uintptr_t)NULL;
	memset(&req, 0, sizeof(req));
	req.csb_atok = (uintptr_t)ctx->atok_base;
	req.csb_ktoa = (uintptr_t)ctx->ktoa_base;
	ret          = ioctl(nmd->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_START)");
		exit(EXIT_FAILURE);
	}

	return NULL;
}

inline int
ringspace(struct netmap_ring *ring, uint32_t head)
{
	int space = ring->tail - head;

	if (space < 0) {
		space += ring->num_slots;
	}

	return space;
}

static void
usage(const char *progname)
{
	printf("%s\n"
	       "[-h (show this help and exit)]\n"
	       "[-f FUNCTION (rx,tx)]\n"
	       "[-v (be more verbose)]\n"
	       "[-R RATE_PPS (0 = infinite)]\n"
	       "[-b BATCH_SIZE (in packets)]\n"
	       "-i NETMAP_PORT\n",
	       progname);
}

typedef enum {
	F_TX = 0,
	F_RX,
} function_t;

int
main(int argc, char **argv)
{
	struct nm_csb_atok *atok_base = NULL;
	struct nm_csb_ktoa *ktoa_base = NULL;
	int num_entries, num_tx_entries;
	unsigned long long bytes = 0;
	unsigned long long pkts  = 0;
	const char *ifname       = NULL;
	void *csb                = NULL;
	uint16_t first_ring, last_ring;
	struct context ctx;
	struct nm_desc *nmd;

	double rate                = 1.0 /* pps */;
	unsigned int period_us     = 0;
	unsigned int period_budget = 0;
	struct timeval next_time;
	int packet_budget;

	function_t func;
	pthread_t th;
	int opt;
	int ret;

	/* Register a signal handler to stop the program on SIGINT. */
	{
		struct sigaction sa;

		sa.sa_handler = sigint_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		if (sigaction(SIGINT, &sa, NULL)) {
			perror("sigaction(SIGINT)");
			exit(EXIT_FAILURE);
		}
	}

	memset(&ctx, 0, sizeof(ctx));
	func        = F_RX;
	ctx.verbose = 0;
	ctx.batch   = 1;

	while ((opt = getopt(argc, argv, "hi:f:vR:b:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'i':
			ifname = optarg;
			break;

		case 'f':
			if (!strcmp(optarg, "tx")) {
				func = F_TX;
			} else if (!strcmp(optarg, "rx")) {
				func = F_RX;
			} else {
				printf("    Unknown function %s\n", optarg);
			}
			break;

		case 'v':
			ctx.verbose++;
			break;

		case 'R':
			rate = atof(optarg);
			if (rate < 0.0) {
				printf("    Invalid rate %s\n", optarg);
				return -1;
			}
			break;

		case 'b':
			ctx.batch = atoi(optarg);
			if (ctx.batch <= 0) {
				printf("    Invalid batch %s\n", optarg);
				return -1;
			}
			break;

		default:
			printf("    Unrecognized option %c\n", opt);
			usage(argv[0]);
			return -1;
		}
	}

	if (ifname == NULL) {
		printf("No netmap port specified\n");
		usage(argv[0]);
		return -1;
	}

	/* Open the netmap port. */
	ctx.nmd = nmd = nm_open(ifname, NULL, 0, NULL);
	if (!nmd) {
		printf("nm_open(%s) failed\n", ifname);
		return -1;
	}

	/* Allocate CSB entries. */
	{
		size_t csb_size;

		num_tx_entries = nmd->last_tx_ring - nmd->first_tx_ring + 1;
		num_entries    = num_tx_entries + nmd->last_rx_ring -
		              nmd->first_rx_ring + 1;
		printf("Number of CSB entries = %d\n", (int)num_entries);
		csb_size = (sizeof(struct nm_csb_atok) +
		            sizeof(struct nm_csb_ktoa)) *
		           num_entries;
		assert(csb_size > 0);
		ret = posix_memalign(&csb, sizeof(struct nm_csb_atok),
		                     csb_size);
		if (ret) {
			printf("Failed to allocate CSB memory\n");
			return -1;
		}
		memset(csb, 0, csb_size);

		atok_base = ctx.atok_base = (struct nm_csb_atok *)csb;
		ktoa_base                 = ctx.ktoa_base =
		        (struct nm_csb_ktoa *)(ctx.atok_base + num_entries);
	}

	/* Start the kernel worker thread. */
	ret = pthread_create(&th, NULL, kloop_worker, &ctx);
	if (ret) {
		printf("pthread_create() failed: %s\n", strerror(ret));
		nm_close(nmd);
		return -1;
	}

	/* Compute variables for rate limiting. */
	if (rate != 0.0) {
		double us = 1000000.0 / rate;
		double b  = 1.0;
		if (us < 50.0) {
			b = ceil(50.0 / us);
			us *= b;
		}
		period_us     = (unsigned int)us;
		period_budget = (unsigned int)b;
	}
#if 0
	printf("period us %u batch %u\n", period_us, period_budget);
#endif
	if (func == F_RX) {
		atok_base += num_tx_entries;
		ktoa_base += num_tx_entries;
		first_ring = nmd->first_rx_ring;
		last_ring  = nmd->last_rx_ring;
	} else {
		first_ring = nmd->first_tx_ring;
		last_ring  = nmd->last_tx_ring;
	}

	gettimeofday(&next_time, NULL);
	packet_budget = 0;

	/* Run the application loop. */
	while (!ACCESS_ONCE(stop)) {
		uint16_t r;

		if (period_us != 0) {
			struct timeval now, diff;

			next_time.tv_usec += period_us;
			if (next_time.tv_usec > 1000000) {
				next_time.tv_usec -= 1000000;
				next_time.tv_sec++;
			}
			packet_budget = period_budget;
			gettimeofday(&now, NULL);
			timersub(&next_time, &now, &diff);
			usleep(diff.tv_usec);
		} else {
			packet_budget = 0xfffffff; /* infinite */
		}

		for (r = first_ring; r <= last_ring; r++) {
			struct nm_csb_atok *atok = atok_base + r;
			struct nm_csb_ktoa *ktoa = ktoa_base + r;
			struct netmap_ring *ring;
			struct netmap_slot *slot;
			uint32_t head;
			int batch;

			if (func == F_TX) {
				ring = NETMAP_TXRING(nmd->nifp, r);
			} else {
				ring = NETMAP_RXRING(nmd->nifp, r);
			}

			head = atok->head;
			/* For convenience we reuse the netmap_ring
			 * header to store hwtail and hwcur, since the
			 * cur, head and tail fields are not used. */
			nm_sync_kloop_appl_read(ktoa,
			                        /*hwtail=*/&ring->tail,
			                        /*hwcur=*/&ring->cur);
			batch = ringspace(ring, head);
			if (batch > packet_budget) { /* rate limiting */
				batch = packet_budget;
			}
			if (batch == 0) {
				continue;
			}
			if (batch > ctx.batch) {
				batch = ctx.batch;
			}

			pkts += batch;
			packet_budget -= batch;
			while (--batch >= 0) {
				slot = ring->slot + head;
				if (func == F_TX) {
					slot->len   = 60;
					slot->flags = 0;
					{
						char *buf = NETMAP_BUF(
						        ring, slot->buf_idx);
						memset(buf, 0xFF, 6);
						memset(buf + 6, 0, 6);
						buf[12] = 0x08;
						buf[13] = 0x00;
						memset(buf + 14, 'x',
						       slot->len - 14);
					}
				} else {
					if (ctx.verbose) {
						char *buf = NETMAP_BUF(
						        ring, slot->buf_idx);
						int i;
						for (i = 0; i < slot->len;
						     i++) {
							printf(" %02x",
							       (unsigned char)
							               buf[i]);
						}
						printf("\n");
					}
				}
				bytes += slot->len;
				head = nm_ring_next(ring, head);
			}
			nm_sync_kloop_appl_write(atok, head, head);
			printf("ring #%u, hwcur %u, head %u, hwtail "
			       "%u\n",
			       (unsigned int)r, ring->cur, head, ring->tail);
		}
	}

	/* Stop the kernel worker thread. */
	{
		struct nmreq_header hdr;
		int ret;

		memset(&hdr, 0, sizeof(hdr));
		hdr.nr_version = NETMAP_API;
		hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_STOP;
		ret            = ioctl(nmd->fd, NIOCCTRL, &hdr);
		if (ret) {
			perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_STOP)");
		}
	}

	/* Release the allocated resources. */
	ret = pthread_join(th, NULL);
	if (ret) {
		printf("pthread_join() failed: %s\n", strerror(ret));
	}

	free(csb);

	nm_close(nmd);

	return 0;
}
