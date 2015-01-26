#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strcmp */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */
#include <signal.h> /* sigsuspend */

#include <sys/mman.h> /* PROT_* */
#include <sys/ioctl.h> /* ioctl */
#include <machine/param.h>
#include <sys/types.h>
#include <sys/socket.h> /* sockaddr.. */
#include <arpa/inet.h> /* ntohs */

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h> /* ifreq */
#include <net/netmap.h>
#include <net/netmap_user.h>

#include "testnetmap.h"
#include "test_device.h"
#include "test_userspace.h"


#ifdef VERBOSE
#undef VERBOSE
#endif
#define VERBOSE 1


void
test_userspace(const char *ifname)
{
	int fd;
	void *tmp_addr;
	struct nmreq ifreq;
	struct netmap_if *nifp;
	int l;

	fd = netmap_open();


	strcpy(ifreq.nr_name, ifname);
	ASSERT(ioctl(fd, NIOCREGIF, &ifreq) != -1);
	l = ifreq.nr_memsize;
	tmp_addr = netmap_mmap(fd, l);
	nifp = NETMAP_IF(tmp_addr, ifreq.nr_offset);

	PRINT_NIF(nifp);

	ASSERT(ioctl(fd, NIOCUNREGIF, &ifreq) != -1);
	ASSERT(munmap(tmp_addr, l) != -1);
	netmap_close(fd);

	SUCCESS();
}
