#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strcmp */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */

#include <sys/mman.h> /* PROT_* */
#include <sys/ioctl.h> /* ioctl */
#include <sys/queue.h> /* LIST_* */
#include <machine/param.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h> /* sockaddr.. */

#include <net/bpf.h>
#include <net/if.h> /* ifreq */
#include <net/netmap.h>
#include <net/netmap_user.h>

#include "testnetmap.h"
#include "test_device.h"


#ifdef VERBOSE
#undef VERBOSE
#endif
#define VERBOSE 1



int
netmap_open(void)
{
	int fd;

	fd = open("/dev/netmap", O_RDWR);
	ASSERT(fd != -1);

	return (fd);
}


void
netmap_close(int fd)
{
	int ret;

	ret = close(fd);
	ASSERT(ret != -1);
}


void *
netmap_mmap(int fd, int l)
{
	void *tmp_addr;

	tmp_addr = mmap(0, l, PROT_WRITE | PROT_READ,
			MAP_SHARED, fd, 0);
	ASSERT(tmp_addr != MAP_FAILED);

	return (tmp_addr);
}


static void
test_netmap_open_close(void)
{
	int fd, fd1;
	
	fd = netmap_open();
	fd1 = netmap_open();

	netmap_close(fd1);
	netmap_close(fd);

	SUCCESS();
}


static void
test_netmap_ioctl(const char *ifname)
{
	int fd, fd1;
	struct nmreq ifreq;

	fd = netmap_open();
	fd1 = netmap_open();

	strcpy(ifreq.nr_name, "fu0");
	/* unable to register unexistent interface */
	ASSERT(ioctl(fd, NIOCREGIF, &ifreq) == -1);

	strcpy(ifreq.nr_name, ifname);
	ASSERT(ioctl(fd, NIOCREGIF, &ifreq) != -1);
	/* unable to register multiple interfaces */
	ASSERT(ioctl(fd, NIOCREGIF, &ifreq) == -1);
	/* register the same interface on different fds. */
	ASSERT(ioctl(fd1, NIOCREGIF, &ifreq) != -1);

	/* check if the driver support userspace synchronization. */
	ASSERT(ioctl(fd, NIOCTXSYNC, &ifreq) != -1);
	ASSERT(ioctl(fd, NIOCRXSYNC, &ifreq) != -1);

	ASSERT(ioctl(fd1, NIOCUNREGIF, &ifreq) != -1);
	ASSERT(ioctl(fd, NIOCUNREGIF, &ifreq) != -1);
	/* unable to unregister an interface twice */
	ASSERT(ioctl(fd, NIOCUNREGIF, &ifreq) == -1);

	netmap_close(fd1);
	netmap_close(fd);

	SUCCESS();
}


static void
test_netmap_mmap(const char *ifname)
{
	int fd;
	void *tmp_addr;
	struct nmreq ifreq;
	int l;

	fd = netmap_open();
	strcpy(ifreq.nr_name, ifname);
	ASSERT(ioctl(fd, NIOCREGIF, &ifreq) != -1);
	l = ifreq.nr_memsize;

	tmp_addr = netmap_mmap(fd, l);
	ASSERT(munmap(tmp_addr, 1024) != -1);

	ASSERT(ioctl(fd, NIOCUNREGIF, &ifreq) != -1);
	netmap_close(fd);
	
	SUCCESS();
}


static void
test_netmap_poll(const char *ifname)
{
	int fd, ret;
	struct ifreq ifreq;
	struct pollfd fds[1];

	fd = netmap_open();

	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;

	/* no registered interface: POLLERR */
	ASSERT(poll(fds, 1, INFTIM) == 1);
	ASSERT(fds[0].revents & POLLERR);

	strcpy(ifreq.ifr_name, ifname);
	ASSERT(ioctl(fd, NIOCREGIF, &ifreq) != -1);

	/* noone is sending packets, so we cannot read: timeout */
	fds[0].events = (POLLIN | POLLRDNORM);
	ASSERT((ret = poll(fds, 1, 1000)) != -1);
	if (ret > 0)
		ASSERT(fds[0].revents & POLLIN &&
		       fds[0].revents & POLLRDNORM);

	/* the ring is empty, if we want to write we can do it. */
	fds[0].events = (POLLOUT | POLLWRNORM);
	ASSERT((ret = poll(fds, 1, 1000)) != -1);
	if (ret > 0)
		ASSERT(fds[0].revents & POLLOUT &&
		       fds[0].revents & POLLWRNORM);

	ASSERT(ioctl(fd, NIOCUNREGIF, &ifreq) != -1);
	netmap_close(fd);
	
	SUCCESS();
}


void
test_device(const char *ifname)
{
	test_netmap_open_close();

	test_netmap_ioctl(ifname);

	test_netmap_mmap(ifname);

	test_netmap_poll(ifname);
}
