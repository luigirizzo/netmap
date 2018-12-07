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
#ifdef __linux__
#include <sys/eventfd.h>
#endif /* __linux__ */

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

static int stop = 0;

static void
sigint_handler(int signum)
{
	(void)signum;
	ACCESS_ONCE(stop) = 1;
}

struct eventfds {
	int ioeventfd;
	int irqfd;
};

struct context {
	int fd; /* netmap file descriptor */
	struct nm_csb_atok *atok_base;
	struct nm_csb_ktoa *ktoa_base;
	int sleep_us;
	int verbose;
	int batch;
	int num_entries;
	struct eventfds *eventfds;
};

static void *
kloop_worker(void *opaque)
{
	struct nmreq_opt_sync_kloop_eventfds *opt = NULL;
	struct context *ctx                       = opaque;
	struct nmreq_sync_kloop_start req;
	struct nmreq_header hdr;
	int ret;

	if (ctx->eventfds) {
		size_t opt_size = sizeof(*opt) +
		                  ctx->num_entries * sizeof(opt->eventfds[0]);
		int i;

		opt = malloc(opt_size);
		memset(opt, 0, opt_size);
		opt->nro_opt.nro_next    = 0;
		opt->nro_opt.nro_reqtype = NETMAP_REQ_OPT_SYNC_KLOOP_EVENTFDS;
		opt->nro_opt.nro_status  = 0;
		opt->nro_opt.nro_size    = opt_size;
		for (i = 0; i < ctx->num_entries; i++) {
			opt->eventfds[i].ioeventfd = ctx->eventfds[i].ioeventfd;
			opt->eventfds[i].irqfd     = ctx->eventfds[i].irqfd;
		}
	}

	/* The ioctl() returns on failure or when some other thread
	 * stops the kernel loop. */
	memset(&hdr, 0, sizeof(hdr));
	hdr.nr_version = NETMAP_API;
	hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_START;
	hdr.nr_body    = (uintptr_t)&req;
	hdr.nr_options = (uintptr_t)opt;
	memset(&req, 0, sizeof(req));
	req.sleep_us = (uint32_t)ctx->sleep_us;
	ret          = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_START)");
		exit(EXIT_FAILURE);
	}

	return NULL;
}

static inline int
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
	       "[-u KLOOP_SLEEP_US (in microseconds)]\n"
	       "[-k (use eventfd-based notifications)]\n"
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
	struct eventfds *eventfds_base = NULL;
	int num_tx_entries, num_rx_entries;
	unsigned long long bytes = 0;
	unsigned long long pkts  = 0;
	const char *ifname       = NULL;
	void *csb                = NULL;
	uint16_t first_ring, last_ring;
	struct netmap_if *nifp = NULL;
	struct context ctx;

	double target_rate         = 0.0 /* pps */;
	unsigned int period_us     = 0;
	unsigned int period_budget = 0;
	struct timeval next_time;
	int packet_budget;
	struct timeval loop_begin, loop_end;
	int use_eventfds = 0;

	int init_tx_payload = 1;
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
	func         = F_RX;
	ctx.verbose  = 0;
	ctx.batch    = 1;
	ctx.sleep_us = 100;

	while ((opt = getopt(argc, argv, "hi:f:vR:b:u:k")) != -1) {
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
			target_rate = atof(optarg);
			if (target_rate < 0.0) {
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

		case 'u':
			ctx.sleep_us = atoi(optarg);
			if (ctx.sleep_us < 0) {
				printf("    Invalid sleep_us %s\n", optarg);
				return -1;
			}
			break;

		case 'k':
			use_eventfds = 1;
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

	ctx.fd = open("/dev/netmap", O_RDWR);
	if (ctx.fd < 0) {
		perror("open(/dev/netmap)");
		return ctx.fd;
	}

	/* Get the number of TX and RX rings. */
	{
		struct nmreq_port_info_get req;
		struct nmreq_header hdr;

		memset(&hdr, 0, sizeof(hdr));
		hdr.nr_version = NETMAP_API;
		strncpy(hdr.nr_name, ifname, sizeof(hdr.nr_name) - 1);
		hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
		hdr.nr_body    = (uintptr_t)&req;
		memset(&req, 0, sizeof(req));
		ret = ioctl(ctx.fd, NIOCCTRL, &hdr);
		if (ret) {
			perror("ioctl(/dev/netmap, NIOCCTRL, PORT_INFO_GET)");
			return ret;
		}

		num_tx_entries = req.nr_tx_rings;
		num_rx_entries = req.nr_rx_rings;
		ctx.num_entries = num_tx_entries + num_rx_entries;
	}

	/* Allocate CSB entries. */
	{
		size_t csb_size;

		printf("Number of CSB entries = %d\n", (int)ctx.num_entries);
		csb_size = (sizeof(struct nm_csb_atok) +
		            sizeof(struct nm_csb_ktoa)) *
		           ctx.num_entries;
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
		        (struct nm_csb_ktoa *)(ctx.atok_base + ctx.num_entries);
	}

	{
		/* Open the netmap port with NR_EXCLUSIVE and with
		 * the CSB option. */
		struct nmreq_register req;
		struct nmreq_opt_csb opt;
		struct nmreq_header hdr;
		void *mem;

		memset(&opt, 0, sizeof(opt));
		opt.nro_opt.nro_reqtype = NETMAP_REQ_OPT_CSB;
		opt.csb_atok = (uintptr_t)atok_base;
		opt.csb_ktoa = (uintptr_t)ktoa_base;

		memset(&hdr, 0, sizeof(hdr));
		hdr.nr_version = NETMAP_API;
		strncpy(hdr.nr_name, ifname, sizeof(hdr.nr_name) - 1);
		hdr.nr_reqtype = NETMAP_REQ_REGISTER;
		hdr.nr_body    = (uintptr_t)&req;
		hdr.nr_options = (uintptr_t)&opt.nro_opt;
		memset(&req, 0, sizeof(req));
		req.nr_mode       = NR_REG_ALL_NIC;
		req.nr_flags      |= NR_EXCLUSIVE;
		ret               = ioctl(ctx.fd, NIOCCTRL, &hdr);
		if (ret) {
			perror("ioctl(/dev/netmap, NIOCCTRL, REGISTER)");
			return ret;
		}

		mem = mmap(0, req.nr_memsize, PROT_WRITE | PROT_READ,
				MAP_SHARED, ctx.fd, 0);
		if (mem == MAP_FAILED) {
			perror("mmap()");
			return -1;
		}
		nifp = NETMAP_IF(mem, req.nr_offset);
	}

	/* Allocate eventfds. */
	if (use_eventfds) {
#ifdef __linux__
		int i;

		ctx.eventfds =
		        malloc(ctx.num_entries * sizeof(ctx.eventfds[0]));
		for (i = 0; i < ctx.num_entries; i++) {
			int efd;

			efd = eventfd(0, 0);
			if (efd < 0) {
				perror("eventfd()");
			}
			ctx.eventfds[i].ioeventfd = efd;
			efd                       = eventfd(0, 0);
			if (efd < 0) {
				perror("eventfd()");
			}
			ctx.eventfds[i].irqfd = efd;
		}
#else  /* !__linux__ */
		printf("Eventfds not supported on this platform\n");
		return -1;
#endif /* !__linux__ */
	}

	/* Start the kernel worker thread. */
	ret = pthread_create(&th, NULL, kloop_worker, &ctx);
	if (ret) {
		printf("pthread_create() failed: %s\n", strerror(ret));
		return -1;
	}

	/* Compute variables for rate limiting. */
	if (target_rate != 0.0) {
		double us = 1000000.0 / target_rate;
		double b  = 1.0;
#define MIN_USLEEP 50.0
		if (us < MIN_USLEEP) {
			b = ceil(MIN_USLEEP / us);
			us *= b;
		}
		period_us     = (unsigned int)us;
		period_budget = (unsigned int)b;
#undef MIN_USLEEP
	}
#if 0
	printf("period us %u batch %u\n", period_us, period_budget);
#endif
	eventfds_base = ctx.eventfds;
	if (func == F_RX) {
		atok_base += num_tx_entries;
		ktoa_base += num_tx_entries;
		eventfds_base += num_tx_entries;
		first_ring = 0;
		last_ring  = num_tx_entries-1;
	} else {
		first_ring = 0;
		last_ring  = num_rx_entries-1;
	}

	gettimeofday(&next_time, NULL);
	loop_begin    = next_time;
	packet_budget = 0;

	/* Run the application loop. */
	while (!ACCESS_ONCE(stop)) {
		uint16_t r;

		if (period_us == 0) {
			packet_budget = 0xfffffff; /* infinite */
		} else {
			struct timeval now, diff;

			next_time.tv_usec += period_us;
			if (next_time.tv_usec > 1000000) {
				next_time.tv_usec -= 1000000;
				next_time.tv_sec++;
			}
			packet_budget = period_budget;
			if (period_budget > 1) {
				/* Busy wait. */
				for (;;) {
					gettimeofday(&now, NULL);
					/* if now >= next_time */
					if (!timercmp(&now, &next_time, <)) {
						break;
					}
				}
			} else {
				/* Sleep. */
				gettimeofday(&now, NULL);
				/* if now < next_time ... */
				if (timercmp(&now, &next_time, <)) {
					/* diff = next_time - now */
					timersub(&next_time, &now, &diff);
					usleep(diff.tv_usec);
				}
			}
		}

		for (r = first_ring; r <= last_ring; r++) {
			struct eventfds *evfds = ctx.eventfds ?
					(eventfds_base + r) : NULL;
			struct nm_csb_atok *atok = atok_base + r;
			struct nm_csb_ktoa *ktoa = ktoa_base + r;
			struct netmap_ring *ring;
			struct netmap_slot *slot;
			uint32_t head;
			int batch;

			if (func == F_TX) {
				ring = NETMAP_TXRING(nifp, r);
			} else {
				ring = NETMAP_RXRING(nifp, r);
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
					slot->len = 60;
					if ((slot->flags & NS_BUF_CHANGED) ||
					    init_tx_payload) {
						char *buf = NETMAP_BUF(
						        ring, slot->buf_idx);
						memset(buf, 0xFF, 6);
						memset(buf + 6, 0, 6);
						buf[12] = 0x08;
						buf[13] = 0x00;
						memset(buf + 14, 'x',
						       slot->len - 14);
						/* Drop the copy once we are
						 * confident that we have filled
						 * all the buffers in the TX
						 * ring. */
						if (pkts > 20000) {
							printf("Stop to init "
							       "packets\n");
							init_tx_payload = 0;
						}
					}
					slot->flags = 0;
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
			/* Write updated information for the kernel. */
			nm_sync_kloop_appl_write(atok, head, head);
			/* Notify the kernel if needed. */
			if (evfds && ACCESS_ONCE(ktoa->kern_need_kick)) {
				uint64_t x = 1;
				int n = write(evfds->ioeventfd, &x, sizeof(x));

				assert(n == sizeof(x));
				if (ctx.verbose) {
					printf("Kernel notified\n");
				}
			}
			if (ctx.verbose) {
				printf("ring #%u, hwcur %u, head %u, hwtail "
				       "%u\n",
				       (unsigned int)r, ring->cur, head,
				       ring->tail);
			}
		}
	}

	/* Measure average rate. */
	gettimeofday(&loop_end, NULL);
	{
		struct timeval duration;
		unsigned long udiff;
		double measured_rate;

		timersub(&loop_end, &loop_begin, &duration);
		udiff         = duration.tv_sec * 1000000 + duration.tv_usec;
		measured_rate = (double)pkts / (double)udiff;
		printf("Measured rate: %.6f Mpps\n", measured_rate);
	}

	/* Stop the kernel worker thread. */
	{
		struct nmreq_header hdr;
		int ret;

		memset(&hdr, 0, sizeof(hdr));
		hdr.nr_version = NETMAP_API;
		hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_STOP;
		ret            = ioctl(ctx.fd, NIOCCTRL, &hdr);
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

	return 0;
}
