#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <net/netmap.h>

int
port_info_get(int fd, const char *ifname)
{
	struct nmreq_port_info_get req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.nr_hdr.nr_version = NETMAP_API;
	req.nr_hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
	strncpy(req.nr_hdr.nr_name, ifname, sizeof(req.nr_hdr.nr_name));
	ret = ioctl(fd, NIOCCTRL, &req);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL)");
	}
	printf("nr_offset %lu\n", req.nr_offset);
	printf("nr_memsize %lu\n", req.nr_memsize);
	printf("nr_tx_slots %u\n", req.nr_tx_slots);
	printf("nr_rx_slots %u\n", req.nr_rx_slots);
	printf("nr_tx_rings %u\n", req.nr_tx_rings);
	printf("nr_rx_rings %u\n", req.nr_rx_rings);
	printf("nr_mem_id %u\n", req.nr_mem_id);

	return ret;
}

static void
usage(const char *prog)
{
	printf("%s -i IFNAME\n", prog);
}

int main(int argc, char **argv)
{
	const char *ifname = "ens4";
	int opt;

	while ((opt = getopt(argc, argv, "hi:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'i':
			ifname = optarg;
			break;

		default:
			printf("    Unrecognized option %c\n", opt);
			usage(argv[0]);
			return -1;
		}
	}

	{
		int fd;
		int ret;
		fd = open("/dev/netmap", O_RDWR);
		if (fd < 0) {
			perror("open(/dev/netmap)");
			return fd;
		}
		ret = port_info_get(fd, ifname);
		return ret;
	}

	return 0;
}
