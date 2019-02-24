#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <poll.h>
#include <net/if.h>
#include <stdint.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

static void usage()
{
	D("producer [-w WP_NANOSECONDS] [-i NETMAP_IFNAME]");
}

static int stop = 0;

static void
sigint_handler(int signum)
{
	(void)signum;
	stop = 1;
}

/* initialize to avoid a division by 0 */
static uint64_t ticks_per_second = 1000000000; /* set by calibrate_tsc */

static inline uint64_t
rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/*
 * do an idle loop to compute the clock speed. We expect
 * a constant TSC rate and locked on all CPUs.
 * Returns ticks per second
 */
static uint64_t
calibrate_tsc(void)
{
    struct timeval a, b;
    uint64_t ta_0, ta_1, tb_0, tb_1, dmax = ~0;
    uint64_t da, db, cy = 0;
    int i;
    for (i=0; i < 3; i++) {
	ta_0 = rdtsc();
	gettimeofday(&a, NULL);
	ta_1 = rdtsc();
	usleep(20000);
	tb_0 = rdtsc();
	gettimeofday(&b, NULL);
	tb_1 = rdtsc();
	da = ta_1 - ta_0;
	db = tb_1 - tb_0;
	if (da + db < dmax) {
	    cy = (b.tv_sec - a.tv_sec)*1000000 + b.tv_usec - a.tv_usec;
	    cy = (double)(tb_0 - ta_1)*1000000/(double)cy;
	    dmax = da + db;
	}
    }
    ticks_per_second = cy;
    return cy;
}

#define NS2TSC(x) ((x)*ticks_per_second/1000000000UL)
#define TSC2NS(x) ((x)*1000000000UL/ticks_per_second)

static inline void
tsc_sleep_till(uint64_t when)
{
#define barrier() asm volatile ("" ::: "memory")
    while (rdtsc() < when)
        barrier();
#undef barrier
}

int main(int argc, char **argv)
{
	const char *ifname = "netmap:nmsink0";
	unsigned int wp_ns = 150;
	struct netmap_ring *ring;
	unsigned int num_slots;
	unsigned long npkts = 0;
	struct timeval t1, t2;
	unsigned long udiff;
	struct sigaction sa;
	struct nm_desc *nmd;
	struct pollfd pfd;
	uint64_t wp_ticks;
	unsigned int i;
	double T_avg;
	int ret;
	int ch;

	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	ret = sigaction(SIGINT, &sa, NULL);
	if (ret) {
		perror("sigaction(SIGINT)");
		exit(EXIT_FAILURE);
	}

	while ( (ch = getopt(argc, argv, "w:i:") ) != -1) {
		switch(ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;

		case 'i':
			ifname = optarg;
			break;

		case 'w':
			wp_ns = strtoull(optarg, NULL, 10);
			break;
		}
	}

	calibrate_tsc();
	wp_ticks = NS2TSC(wp_ns);

	nmd = nm_open(ifname, NULL, 0, NULL);
	if (!nmd) {
		if (errno == 0) {
			errno = ENXIO;
		}
		D("Could not open %s [%s]", ifname, strerror(errno));
		return -1;
	}

	ring = NETMAP_TXRING(nmd->nifp, 0);
	num_slots = ring->num_slots;
	for (i = 0; i < num_slots; i++) {
		struct netmap_slot *slot;

		slot = ring->slot + i;
		slot->len = 64;
		memset(NETMAP_BUF(ring, slot->buf_idx), 0, slot->len);
	}

	pfd.fd = nmd->fd;
	pfd.events = POLLOUT;

	gettimeofday(&t1, NULL);
	while (!stop) {
		uint64_t now = rdtsc();
		unsigned int b = num_slots +
			ring->tail - ring->head;

		if (b >= num_slots) { /* wraparound */
			b -= num_slots;
		}
		if (b > num_slots >> 1) {
			b = num_slots >> 1;
		}
		npkts += b;
		ring->head += b;
		if (ring->head >= ring->num_slots) { /* wraparound */
			ring->head -= ring->num_slots;
		}
		ring->cur = ring->head;
		tsc_sleep_till(now + b * wp_ticks);
		poll(&pfd, 1, -1);
	}
	gettimeofday(&t2, NULL);
	udiff = (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
	T_avg = (double)udiff * 1000 / (double)npkts;

	nm_close(nmd);

	D("T_avg %f ns", T_avg);

	return 0;
}
