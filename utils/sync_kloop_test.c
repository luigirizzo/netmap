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
	const char *func;
	struct nm_csb_atok *atok_base;
	struct nm_csb_ktoa *ktoa_base;
	int verbose;
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

static void
usage(const char *progname)
{
	printf("%s\n"
	       "[-h (show this help and exit)]\n"
	       "[-f FUNCTION (rx,tx)]\n"
	       "[-v (be more verbose)]\n"
	       "-i NETMAP_PORT\n",
	       progname);
}

int
main(int argc, char **argv)
{
	int num_entries, num_tx_entries;
	unsigned long long bytes = 0;
	unsigned long long pkts = 0;
	const char *ifname = NULL;
	void *csb          = NULL;
	struct context ctx;
	struct nm_desc *nmd;
	pthread_t th;
	int opt;
	int ret;

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
	ctx.func = "rx";
	ctx.verbose = 0;

	while ((opt = getopt(argc, argv, "hi:f:v")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'i':
			ifname = optarg;
			break;

		case 'f':
			ctx.func = optarg;
			if (strcmp(optarg, "tx") && strcmp(optarg, "rx")) {
				printf("    Unknown function %s\n", optarg);
				return -1;
			}
			break;

		case 'v':
			ctx.verbose ++;
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
		num_entries = num_tx_entries +
				nmd->last_rx_ring - nmd->first_rx_ring + 1;
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

		ctx.atok_base = (struct nm_csb_atok *)csb;
		ctx.ktoa_base =
		        (struct nm_csb_ktoa *)(ctx.atok_base + num_entries);
	}

	/* Start the kernel worker thread. */
	ret = pthread_create(&th, NULL, kloop_worker, &ctx);
	if (ret) {
		printf("pthread_create() failed: %s\n", strerror(ret));
		nm_close(nmd);
		return -1;
	}

	/* Run the application loop. */
	if (!strcmp(ctx.func, "tx")) {
		while (!ACCESS_ONCE(stop)) {
			uint16_t r;

			for (r = nmd->first_tx_ring; r <= nmd->last_tx_ring;
			     r++) {
				struct netmap_ring *ring =
				        NETMAP_TXRING(nmd->nifp, r);
				struct nm_csb_atok *atok = ctx.atok_base + r;
				struct nm_csb_ktoa *ktoa = ctx.ktoa_base + r;
				struct netmap_slot *slot;
				uint32_t head;

				head = atok->head;
				/* For convenience we reuse the netmap_ring
				 * header to store hwtail and hwcur, since the
				 * cur, head and tail fields are not used. */
				nm_sync_kloop_appl_read(ktoa, /*hwtail=*/&ring->tail,
							/*hwcur=*/&ring->cur);

				if (head == ring->tail) {
					continue;
				}

				slot        = ring->slot + head;
				slot->len   = 60;
				slot->flags = 0;
				bytes += slot->len;
				pkts++;
				{
					char *buf =
					        NETMAP_BUF(ring, slot->buf_idx);
					memset(buf, 0xFF, 6);
					memset(buf + 6, 0, 6);
					buf[12] = 0x08;
					buf[13] = 0x00;
					memset(buf + 14, 'x', slot->len - 14);
				}
				head = nm_ring_next(ring, head);
				nm_sync_kloop_appl_write(atok, head, head);
				printf("ring #%u, hwcur %u, head %u, hwtail "
				       "%u\n",
				       (unsigned int)r, ring->cur, head, ring->tail);
			}
			usleep(1000000);
		}

	} else if (!strcmp(ctx.func, "rx")) {

		while (!ACCESS_ONCE(stop)) {
			uint16_t r;

			for (r = nmd->first_rx_ring; r <= nmd->last_rx_ring;
			     r++) {
				struct netmap_ring *ring =
				        NETMAP_RXRING(nmd->nifp, r);
				struct nm_csb_atok *atok = ctx.atok_base + num_tx_entries + r;
				struct nm_csb_ktoa *ktoa = ctx.ktoa_base + num_tx_entries + r;
				struct netmap_slot *slot;
				uint32_t head;

				head = atok->head;
				/* For convenience we reuse the netmap_ring
				 * header to store hwtail and hwcur, since the
				 * cur, head and tail fields are not used. */
				nm_sync_kloop_appl_read(ktoa, /*hwtail=*/&ring->tail,
							/*hwcur=*/&ring->cur);

				if (head == ring->tail) {
					continue;
				}

				slot        = ring->slot + head;
				bytes += slot->len;
				pkts++;
				if (ctx.verbose) {
					char *buf =
					        NETMAP_BUF(ring, slot->buf_idx);
					int i;
					for (i = 0; i < slot->len; i++) {
						printf(" %02x", (unsigned char)buf[i]);
					}
					printf("\n");
				}
				head = nm_ring_next(ring, head);
				nm_sync_kloop_appl_write(atok, head, head);
				printf("ring #%u, hwcur %u, head %u, hwtail "
				       "%u\n",
				       (unsigned int)r, ring->cur, head, ring->tail);
			}
			usleep(1000000);
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
