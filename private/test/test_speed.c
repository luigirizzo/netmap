#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h> /* ioctl */
#include <sys/queue.h> /* LIST_* */
#include <sys/time.h>
#include <sys/socket.h> /* sockaddr .. */

#include <net/if.h> /* IFNAMSIZ */
#include <net/netmap.h>
#include <net/netmap_user.h>

#include "testnetmap.h"
#include "test_speed.h"
#include "test_device.h"

#define ITERATIONS 100000


static struct timing_method t_methods[] = {
	{ "gettimeofday()", TIMING_GTD, 0 },
	/*{ "clock_gettime(CLOCK_REALTIME)", TIMING_CGT, CLOCK_REALTIME },*/
	/*{ "clock_gettime(CLOCK_REALTIME_PRECISE)", TIMING_CGT, CLOCK_REALTIME_PRECISE },*/
	/*{ "clock_gettime(CLOCK_REALTIME_FAST)", TIMING_CGT, CLOCK_REALTIME_FAST },*/
	/*{ "clock_gettime(CLOCK_MONOTONIC)", TIMING_CGT, CLOCK_MONOTONIC },*/
	/*{ "clock_gettime(CLOCK_MONOTONIC_PRECISE)", TIMING_CGT, CLOCK_MONOTONIC_PRECISE },*/
	/*{ "clock_gettime(CLOCK_MONOTONIC_FAST)", TIMING_CGT, CLOCK_MONOTONIC_FAST },*/
	{ "", 0, 0 }
};


static void
test_ioctl_speed(const char *ifname)
{
	int fd, i;
	double ravg = 0;
	struct nmreq req;
	struct netmap_if *nifp;
	void *tmp_addr;

	fd = netmap_open();
	tmp_addr = netmap_mmap(fd, 1024 /* XXX */);
	
	strcpy(req.nr_name, ifname);
	/* single queue sync. */
	req.nr_ringid = 0 | NETMAP_HW_RING;
	ASSERT(ioctl(fd, NIOCREGIF, &req) != -1);
	nifp = NETMAP_IF(tmp_addr, req.nr_offset);

	/* multi-queue sync: default configuration */
	i = 0;
	while (strcmp("", t_methods[i].label) != 0) {
		TIMEIT(t_methods[i].type, t_methods[i].clock_id,
		       ioctl(fd, NIOCRXSYNC, NULL), ravg, ITERATIONS);
		SUCCESSF(": NIOCRXSYNC: multi: %0.6f usec.\n", ravg);
		TIMEIT(t_methods[i].type, t_methods[i].clock_id,
		       ioctl(fd, NIOCTXSYNC, NULL), ravg, ITERATIONS);
		SUCCESSF(": NIOCTXSYNC: multi: %0.6f usec.\n", ravg);
		i++;
	}

	i = 0;
	while (strcmp("", t_methods[i].label) != 0) {
		TIMEIT(t_methods[i].type, t_methods[i].clock_id,
		       ioctl(fd, NIOCRXSYNC, NULL), ravg, ITERATIONS);
		SUCCESSF(": NIOCRXSYNC: single: %0.6f usec.\n", ravg);
		TIMEIT(t_methods[i].type, t_methods[i].clock_id,
		       ioctl(fd, NIOCTXSYNC, NULL), ravg, ITERATIONS);
		SUCCESSF(": NIOCTXSYNC: single: %0.6f usec.\n", ravg);
		i++;
	}

	ASSERT(ioctl(fd, NIOCUNREGIF, &req) != -1);

	netmap_close(fd);
}

void
test_speed(const char *ifname)
{
	test_ioctl_speed(ifname);
}
